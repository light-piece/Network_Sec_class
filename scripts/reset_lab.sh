#!/usr/bin/env bash
# Put the lab back to its vulnerable baseline: rule-14 back, no temp-block,
# counter 0, no leftover tracked connections; clear the backend's incident
# state if the backend is running; rerun the self-check.
# Touches only the lab's own namespaces, table and cluster.
set -euo pipefail
# shellcheck source=scripts/lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

need_root
load_env

step "Check the lab is up"
lab_is_up || die "the lab is not running; start it with scripts/setup_lab.sh"
info "namespaces, firewall table, Flask and PostgreSQL are up"

step "Reload baseline firewall (rule-14 open, no temp-block)"
load_baseline
in_ns "$NS_ROUTER" nft list chain inet lab forward | sed 's/^/    /'

step "Self-check (baseline: app works, attacker reaches the database)"
self_check yes
load_baseline
info "rule-14 counter reset to 0"

step "Clear backend incident state (if the backend is running)"
url="http://127.0.0.1:${APP_PORT}/api/lab/reset"
if out="$(curl -sS -m 15 -X POST "$url" 2>&1)"; then
  info "POST $url -> $out"
else
  info "backend not reachable on port ${APP_PORT}; skipped"
fi
echo "Lab reset to baseline."
