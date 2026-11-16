# shellcheck shell=bash
# Shared helpers for the lab scripts. Sourced, never run directly.
#
# Provides: REPO, load_env, step, info, warn, die, need_root, lab_* helpers.
# Configuration: .env.example gives the defaults, .env overrides them, and a
# variable already set in the environment overrides both.

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export REPO

# Every key the scripts read. Values must be plain (no spaces, no quotes needed).
LAB_ENV_KEYS=(
  APP_HOST APP_PORT AI_MODE MOCK_AI_SCENARIO OLLAMA_URL OLLAMA_MODEL OLLAMA_TIMEOUT LAB_MODE
  NS_EMPLOYEE NS_APP NS_DB NS_ROUTER EMPLOYEE_IP EMPLOYEE_NET APP_IP APP_SERVICE_PORT DB_IP DB_PORT
  DB_NAME DB_USER DB_PASSWORD LAB_STATE_DIR POLL_INTERVAL_SECONDS MAX_ATTEMPTS LOG_LEVEL
)

STEP_NO=0
step() { STEP_NO=$((STEP_NO + 1)); echo "=== STEP ${STEP_NO}: $* [$(basename "$0")] ==="; }
info() { echo "    $*"; }
warn() { echo "WARNING: $*" >&2; }
die()  { echo "ERROR: $*" >&2; exit 1; }

need_root() {
  [ "$(id -u)" -eq 0 ] || die "$(basename "$0") must run as root (use: sudo $0)"
}

# Read KEY=value lines from a file into variables that are not already set.
_read_env_file() {
  local file="$1" line key value
  [ -f "$file" ] || return 0
  while IFS= read -r line || [ -n "$line" ]; do
    line="${line%$'\r'}"
    [[ "$line" =~ ^[[:space:]]*(#|$) ]] && continue
    [[ "$line" =~ ^[[:space:]]*(export[[:space:]]+)?([A-Za-z_][A-Za-z0-9_]*)=(.*)$ ]] || continue
    key="${BASH_REMATCH[2]}"
    value="${BASH_REMATCH[3]}"
    # Strip an inline " # comment" and surrounding whitespace / quotes.
    value="${value%%[[:space:]]#*}"
    value="${value#"${value%%[![:space:]]*}"}"
    value="${value%"${value##*[![:space:]]}"}"
    if [[ "$value" =~ ^\"(.*)\"$ ]] || [[ "$value" =~ ^\'(.*)\'$ ]]; then
      value="${BASH_REMATCH[1]}"
    fi
    if [ -z "${!key+x}" ]; then
      printf -v "$key" '%s' "$value"
      export "${key?}"
    fi
  done < "$file"
}

load_env() {
  _read_env_file "$REPO/.env"
  _read_env_file "$REPO/.env.example"
  local k
  for k in "${LAB_ENV_KEYS[@]}"; do
    [ -n "${!k:-}" ] || die "configuration key $k is missing (check .env / .env.example)"
  done
  # Derived values. Every lab subnet is a /24 and the router is .1 on it.
  ROUTER_EMP_IP="${EMPLOYEE_IP%.*}.1"
  ROUTER_APP_IP="${APP_IP%.*}.1"
  ROUTER_DB_IP="${DB_IP%.*}.1"
  STATE_DIR="$LAB_STATE_DIR"
  PGDATA_DIR="$STATE_DIR/pgdata"
  SOCK_DIR="$STATE_DIR/run"
  LOG_DIR="$STATE_DIR/logs"
  RENDERED_NFT="$STATE_DIR/baseline.rendered.nft"
  FLASK_PID="$STATE_DIR/flask.pid"
  FLASK_LOG="$LOG_DIR/flask.log"
  PG_LOG="$LOG_DIR/postgres.log"
  VENV_PY="$REPO/.venv/bin/python"
  LAB_NAMESPACES=("$NS_ROUTER" "$NS_EMPLOYEE" "$NS_APP" "$NS_DB")
  export ROUTER_EMP_IP ROUTER_APP_IP ROUTER_DB_IP STATE_DIR PGDATA_DIR SOCK_DIR LOG_DIR \
    RENDERED_NFT FLASK_PID FLASK_LOG PG_LOG VENV_PY
}

# Newest installed PostgreSQL server binaries, independent of version and CPU.
pg_bin() {
  local base=/usr/lib/postgresql ver
  ver="$(find "$base" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' 2>/dev/null | sort -V | tail -n 1)"
  if [ -z "$ver" ] || [ ! -x "$base/$ver/bin/pg_ctl" ]; then die "PostgreSQL server not found under $base (run scripts/install.sh)"; fi
  echo "$base/$ver/bin"
}

ns_exists() { [ -e "/run/netns/$1" ] || ip netns list 2>/dev/null | awk '{print $1}' | grep -qx "$1"; }
in_ns() { local ns="$1"; shift; ip netns exec "$ns" "$@"; }

# Run a command as the postgres user inside the db namespace, from a neutral cwd.
as_postgres_in_db() { (cd / && ip netns exec "$NS_DB" runuser -u postgres -- "$@"); }

# Render lab/baseline.nft with the configured addresses (only these five keys).
render_baseline() {
  sed -e "s|\${EMPLOYEE_NET}|${EMPLOYEE_NET}|g" \
      -e "s|\${APP_IP}|${APP_IP}|g" \
      -e "s|\${APP_SERVICE_PORT}|${APP_SERVICE_PORT}|g" \
      -e "s|\${DB_IP}|${DB_IP}|g" \
      -e "s|\${DB_PORT}|${DB_PORT}|g" \
      "$REPO/lab/baseline.nft"
}

load_baseline() {
  mkdir -p "$STATE_DIR"
  render_baseline > "$RENDERED_NFT"
  # shellcheck disable=SC2016
  if grep -q '\${' "$RENDERED_NFT"; then die "unrendered placeholder left in $RENDERED_NFT"; fi
  in_ns "$NS_ROUTER" nft -f "$RENDERED_NFT"
  # Fresh state: no tracked flows left over from before the reload.
  in_ns "$NS_ROUTER" conntrack -F >/dev/null 2>&1 || true
}

flask_running() {
  [ -f "$FLASK_PID" ] && kill -0 "$(cat "$FLASK_PID")" 2>/dev/null
}

# 0 when every lab piece is up (namespaces, firewall table, Flask, PostgreSQL).
lab_is_up() {
  local ns
  for ns in "${LAB_NAMESPACES[@]}"; do ns_exists "$ns" || return 1; done
  in_ns "$NS_ROUTER" nft list table inet lab >/dev/null 2>&1 || return 1
  flask_running || return 1
  in_ns "$NS_APP" curl -fsS -m 3 -o /dev/null "http://${APP_IP}:${APP_SERVICE_PORT}/health" || return 1
  in_ns "$NS_APP" pg_isready -q -h "$DB_IP" -p "$DB_PORT" -t 3 || return 1
}

# Self-check used by setup and reset. Prints yes/no lines; fails if either differs.
# want_attacker = yes (baseline, rule-14 open) or no.
self_check() {
  local want_attacker="${1:-yes}" app attacker body
  body="$(in_ns "$NS_EMPLOYEE" curl -s -m 5 -w '\n%{http_code}' "http://${APP_IP}:${APP_SERVICE_PORT}/api/records" || true)"
  if [ "$(tail -n 1 <<<"$body")" = "200" ] && grep -q '"records"' <<<"$body"; then app=yes; else app=no; fi
  if in_ns "$NS_EMPLOYEE" pg_isready -q -h "$DB_IP" -p "$DB_PORT" -t 3; then attacker=yes; else attacker=no; fi
  info "company app works from employee:       $app (want yes)"
  info "attacker (employee) reaches database:  $attacker (want $want_attacker)"
  [ "$app" = yes ] || die "self-check failed: the company app does not answer /api/records (see $FLASK_LOG)"
  [ "$attacker" = "$want_attacker" ] || die "self-check failed: attacker reachability is '$attacker', expected '$want_attacker'"
}
