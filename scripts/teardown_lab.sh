#!/usr/bin/env bash
# Stop the lab services and delete the lab namespaces (which removes the veths
# and the `inet lab` table with them). The PostgreSQL data directory is kept so
# the next setup is fast; pass --purge to delete it and all lab state too.
# Never touches the host's own networking, firewall or system PostgreSQL.
set -euo pipefail
# shellcheck source=scripts/lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

need_root
load_env
purge=no
case "${1:-}" in
  --purge) purge=yes ;;
  "") ;;
  *) die "usage: $0 [--purge]" ;;
esac

kill_ns_pids() {
  local ns="$1" pid
  ns_exists "$ns" || return 0
  for pid in $(ip netns pids "$ns" 2>/dev/null); do kill "$pid" 2>/dev/null || true; done
  for _ in $(seq 1 25); do
    [ -z "$(ip netns pids "$ns" 2>/dev/null)" ] && return 0
    sleep 0.2
  done
  for pid in $(ip netns pids "$ns" 2>/dev/null); do kill -9 "$pid" 2>/dev/null || true; done
}

step "Stop the company app (Flask)"
if flask_running; then kill "$(cat "$FLASK_PID")" 2>/dev/null || true; info "stopped pid $(cat "$FLASK_PID")"; else info "not running"; fi
rm -f "$FLASK_PID"
kill_ns_pids "$NS_APP"

step "Stop the lab PostgreSQL"
if [ -s "$PGDATA_DIR/PG_VERSION" ] && [ -d /usr/lib/postgresql ]; then
  PGBIN="$(pg_bin)"
  if (cd / && runuser -u postgres -- "$PGBIN/pg_ctl" -D "$PGDATA_DIR" status >/dev/null 2>&1); then
    (cd / && runuser -u postgres -- "$PGBIN/pg_ctl" -D "$PGDATA_DIR" stop -m fast -w -t 30 >/dev/null) || warn "pg_ctl stop failed"
    info "stopped"
  else
    info "not running"
  fi
else
  info "no lab cluster"
fi
kill_ns_pids "$NS_DB"
kill_ns_pids "$NS_EMPLOYEE"

step "Delete lab namespaces (veths and the inet lab table go with them)"
for ns in "${LAB_NAMESPACES[@]}"; do
  if ns_exists "$ns"; then ip netns del "$ns"; info "$ns: deleted"; else info "$ns: absent"; fi
done

if [ "$purge" = yes ]; then
  step "Purge lab state ($STATE_DIR)"
  case "$STATE_DIR" in
    /|/var|/var/lib|/home|/root|"") die "refusing to delete '$STATE_DIR'" ;;
  esac
  rm -rf "$STATE_DIR"
  info "deleted"
fi
echo "Lab torn down."
