#!/usr/bin/env bash
# The "hacked employee workstation" tries to open a PostgreSQL session on the
# company database. It has no password: a password prompt from the server
# already proves the database is reachable (that is the misconfiguration).
set -euo pipefail
# shellcheck source=scripts/lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

need_root
load_env
ns_exists "$NS_EMPLOYEE" || die "the lab is not running; start it with scripts/setup_lab.sh"

step "Attack: ${EMPLOYEE_IP} (${NS_EMPLOYEE}) -> ${DB_IP}:${DB_PORT} (PostgreSQL, no password)"
set +e
out="$(env -i PATH="$PATH" PGPASSFILE="$STATE_DIR/no-such-pgpass" PGCONNECT_TIMEOUT=3 \
  ip netns exec "$NS_EMPLOYEE" psql -X -w \
  "host=${DB_IP} port=${DB_PORT} dbname=${DB_NAME} user=${DB_USER} sslmode=disable gssencmode=disable" \
  -c 'SELECT 1' 2>&1)"
rc=$?
set -e
info "psql exit code $rc: ${out//$'\n'/ }"
if [ "$rc" -eq 0 ] || grep -qiE 'password|authentication|pg_hba' <<<"$out"; then
  echo "RESULT: REACHED - the database answered the attacker."
else
  echo "RESULT: BLOCKED - no answer from the database."
fi
