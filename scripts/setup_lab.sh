#!/usr/bin/env bash
# Build (or repair) the lab: namespaces, veths, routes, forwarding, the
# deliberately vulnerable firewall (rule-14), PostgreSQL in `db`, Flask in `app`.
# Idempotent: rerunning brings everything back to the baseline state.
# Touches only the lab's namespaces, its `inet lab` table and its own PostgreSQL cluster.
set -euo pipefail
# shellcheck source=scripts/lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

need_root
load_env
for cmd in ip nft conntrack curl pg_isready runuser setsid; do
  command -v "$cmd" >/dev/null || die "'$cmd' is not installed (run scripts/install.sh)"
done
[ -x "$VENV_PY" ] || die "$VENV_PY not found (run scripts/install.sh first)"

step "Network namespaces"
for ns in "${LAB_NAMESPACES[@]}"; do
  if ns_exists "$ns"; then info "$ns: exists"; else ip netns add "$ns"; info "$ns: created"; fi
  in_ns "$ns" ip link set lo up
done

step "veth links between router and employee / app / db"
# name inside the leaf namespace: lab0; name inside router: lab-<role>.
link_leaf() {
  local leaf_ns="$1" role="$2" leaf_ip="$3" gw_ip="$4" rname="lab-$2"
  if ! in_ns "$NS_ROUTER" ip link show "$rname" >/dev/null 2>&1; then
    # A half-built pair (leaf side left over) is removed first.
    in_ns "$leaf_ns" ip link del lab0 >/dev/null 2>&1 || true
    ip link add "$rname" netns "$NS_ROUTER" type veth peer name lab0 netns "$leaf_ns"
    info "$role: created $NS_ROUTER/$rname <-> $leaf_ns/lab0"
  else
    info "$role: $NS_ROUTER/$rname exists"
  fi
  in_ns "$NS_ROUTER" ip addr replace "$gw_ip/24" dev "$rname"
  in_ns "$NS_ROUTER" ip link set "$rname" up
  in_ns "$leaf_ns" ip addr replace "$leaf_ip/24" dev lab0
  in_ns "$leaf_ns" ip link set lab0 up
  in_ns "$leaf_ns" ip route replace default via "$gw_ip" dev lab0
}
link_leaf "$NS_EMPLOYEE" emp "$EMPLOYEE_IP" "$ROUTER_EMP_IP"
link_leaf "$NS_APP" app "$APP_IP" "$ROUTER_APP_IP"
link_leaf "$NS_DB" db "$DB_IP" "$ROUTER_DB_IP"

step "IP forwarding in $NS_ROUTER"
in_ns "$NS_ROUTER" sysctl -qw net.ipv4.ip_forward=1
info "net.ipv4.ip_forward=$(in_ns "$NS_ROUTER" sysctl -n net.ipv4.ip_forward)"

step "Firewall: load baseline (inet lab, rule-14 open)"
load_baseline
info "rendered ruleset: $RENDERED_NFT"
in_ns "$NS_ROUTER" nft list chain inet lab forward | sed 's/^/    /'

step "PostgreSQL lab cluster in $NS_DB"
PGBIN="$(pg_bin)"
info "server binaries: $PGBIN"
install -d -m 0755 "$STATE_DIR" "$LOG_DIR"
install -d -m 0755 -o postgres -g postgres "$SOCK_DIR"
touch "$PG_LOG"; chown postgres:postgres "$PG_LOG"
if [ ! -s "$PGDATA_DIR/PG_VERSION" ]; then
  rm -rf "$PGDATA_DIR"
  install -d -m 0700 -o postgres -g postgres "$PGDATA_DIR"
  (cd / && runuser -u postgres -- "$PGBIN/initdb" -D "$PGDATA_DIR" --auth-local=peer \
     --auth-host=scram-sha-256 --encoding=UTF8 --no-locale >/dev/null)
  cp "$PGDATA_DIR/pg_hba.conf" "$PGDATA_DIR/pg_hba.conf.orig"
  info "initialised $PGDATA_DIR"
else
  info "cluster exists: $PGDATA_DIR"
fi
# Regenerate pg_hba.conf from the pristine copy so the lab line is always current.
[ -f "$PGDATA_DIR/pg_hba.conf.orig" ] || cp "$PGDATA_DIR/pg_hba.conf" "$PGDATA_DIR/pg_hba.conf.orig"
{
  cat "$PGDATA_DIR/pg_hba.conf.orig"
  echo "# cybersec-lab: the company app's role, from the lab networks (the firewall decides who gets here)"
  echo "host ${DB_NAME} ${DB_USER} ${APP_IP%.*.*}.0.0/16 scram-sha-256"
} > "$PGDATA_DIR/pg_hba.conf.new"
chown postgres:postgres "$PGDATA_DIR/pg_hba.conf.new"
chmod 0600 "$PGDATA_DIR/pg_hba.conf.new"
mv -f "$PGDATA_DIR/pg_hba.conf.new" "$PGDATA_DIR/pg_hba.conf"

pg_opts="-c listen_addresses=${DB_IP} -c port=${DB_PORT} -c unix_socket_directories=${SOCK_DIR}"
if as_postgres_in_db "$PGBIN/pg_ctl" -D "$PGDATA_DIR" status >/dev/null 2>&1; then
  if in_ns "$NS_DB" pg_isready -q -h "$DB_IP" -p "$DB_PORT" -t 3; then
    as_postgres_in_db "$PGBIN/pg_ctl" -D "$PGDATA_DIR" reload >/dev/null
    info "already running on ${DB_IP}:${DB_PORT} (config reloaded)"
  else
    info "running but not reachable on ${DB_IP}:${DB_PORT}; restarting"
    as_postgres_in_db "$PGBIN/pg_ctl" -D "$PGDATA_DIR" stop -m fast -w >/dev/null || true
  fi
fi
if ! as_postgres_in_db "$PGBIN/pg_ctl" -D "$PGDATA_DIR" status >/dev/null 2>&1; then
  if ! as_postgres_in_db "$PGBIN/pg_ctl" -D "$PGDATA_DIR" -l "$PG_LOG" -w -t 30 -o "$pg_opts" start >/dev/null; then
    tail -n 20 "$PG_LOG" >&2 || true
    die "PostgreSQL did not start (log: $PG_LOG)"
  fi
  info "started on ${DB_IP}:${DB_PORT}"
fi

step "Seed database '$DB_NAME' and role '$DB_USER' (idempotent)"
# The password reaches psql through the environment (\getenv), never argv.
export DB_PASSWORD
as_postgres_in_db psql -X -q -h "$SOCK_DIR" -p "$DB_PORT" -d postgres -v ON_ERROR_STOP=1 \
  -v db_name="$DB_NAME" -v db_user="$DB_USER" -f - < "$REPO/lab/seed.sql"
count="$(as_postgres_in_db psql -X -At -h "$SOCK_DIR" -p "$DB_PORT" -d "$DB_NAME" -c 'SELECT count(*) FROM records')"
info "records table: $count rows"

step "Company app (Flask) in $NS_APP on ${APP_IP}:${APP_SERVICE_PORT}"
health_url="http://${APP_IP}:${APP_SERVICE_PORT}/health"
if flask_running && in_ns "$NS_APP" curl -fsS -m 3 -o /dev/null "$health_url"; then
  info "already running (pid $(cat "$FLASK_PID"))"
else
  if [ -f "$FLASK_PID" ]; then kill "$(cat "$FLASK_PID")" 2>/dev/null || true; rm -f "$FLASK_PID"; fi
  # Anything else still holding the app namespace (e.g. a Flask from a crashed run).
  for pid in $(ip netns pids "$NS_APP" 2>/dev/null); do kill "$pid" 2>/dev/null || true; done
  export APP_IP APP_SERVICE_PORT DB_IP DB_PORT DB_NAME DB_USER DB_PASSWORD
  export DB_HOST="$DB_IP"
  (cd "$REPO" && exec setsid ip netns exec "$NS_APP" "$VENV_PY" "$REPO/company_app/app.py" \
     >>"$FLASK_LOG" 2>&1 </dev/null) &
  echo $! > "$FLASK_PID"
  for _ in $(seq 1 50); do
    if in_ns "$NS_APP" curl -fsS -m 2 -o /dev/null "$health_url" 2>/dev/null; then break; fi
    flask_running || { tail -n 20 "$FLASK_LOG" >&2 || true; die "Flask exited during startup (log: $FLASK_LOG)"; }
    sleep 0.2
  done
  in_ns "$NS_APP" curl -fsS -m 3 -o /dev/null "$health_url" || die "Flask did not answer $health_url (log: $FLASK_LOG)"
  info "started (pid $(cat "$FLASK_PID"), log $FLASK_LOG)"
fi

step "Self-check (baseline: app works, attacker reaches the database)"
self_check yes
# The self-check's own connection counted on rule-14; reload so the lab starts at 0.
load_baseline
info "rule-14 counter reset to 0"
echo "Lab is up."
