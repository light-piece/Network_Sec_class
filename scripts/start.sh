#!/usr/bin/env bash
# Start the demo: bring the lab up if it is down, then run the FastAPI backend
# (API + dashboard) in the foreground.
set -euo pipefail
# shellcheck source=scripts/lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

need_root
load_env

step "Lab"
if lab_is_up; then
  info "already up"
else
  info "down or incomplete; running setup_lab.sh"
  "$REPO/scripts/setup_lab.sh"
fi

step "Backend on ${APP_HOST}:${APP_PORT}"
[ -x "$REPO/.venv/bin/uvicorn" ] || die "$REPO/.venv/bin/uvicorn not found (run scripts/install.sh)"
cd "$REPO"
exec "$REPO/.venv/bin/uvicorn" backend.main:app --host "$APP_HOST" --port "$APP_PORT"
