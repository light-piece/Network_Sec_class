#!/usr/bin/env bash
# One-time installer for the lab VM (Ubuntu 24.04, ARM64 or x86_64). Safe to rerun.
#   sudo ./scripts/install.sh          interactive machine (generates a DB password)
#   sudo CI=1 ./scripts/install.sh     non-interactive, uses .env.example defaults
# Installs system packages, creates .venv and installs requirements, creates
# .env, then builds the lab (PostgreSQL cluster, role, seed data, namespaces,
# firewall, company app) with setup_lab.sh.
set -euo pipefail
# shellcheck source=scripts/lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

export DEBIAN_FRONTEND=noninteractive
CI="${CI:-}"
PACKAGES=(git python3 python3-venv python3-pip nftables postgresql postgresql-client conntrack curl iproute2 procps)

step "Check system"
need_root
[ -r /etc/os-release ] || die "cannot read /etc/os-release; this installer is for Ubuntu 24.04"
# shellcheck disable=SC1091
. /etc/os-release
arch="$(uname -m)"
info "OS: ${PRETTY_NAME:-unknown}, architecture: $arch"
[ "${ID:-}" = ubuntu ] || die "this installer supports Ubuntu only (found ${ID:-unknown})"
[ "${VERSION_ID:-}" = "24.04" ] || warn "tested on Ubuntu 24.04; found ${VERSION_ID:-unknown}"
case "$arch" in
  aarch64|arm64) ;;
  x86_64) info "x86_64 is fine (the demo VM is ARM64; nothing here depends on the CPU)" ;;
  *) warn "untested architecture $arch" ;;
esac

step "System packages"
missing=()
for p in "${PACKAGES[@]}"; do
  dpkg-query -W -f='${Status}' "$p" 2>/dev/null | grep -q "install ok installed" || missing+=("$p")
done
if [ ${#missing[@]} -eq 0 ]; then
  info "all installed: ${PACKAGES[*]}"
else
  info "installing: ${missing[*]}"
  apt-get update -qq
  apt-get install -y -qq --no-install-recommends "${missing[@]}" >/dev/null
fi
pg_bin >/dev/null
info "PostgreSQL server: $(pg_bin)"
info "the system PostgreSQL service is left as it is; the lab runs its own cluster"

step "Configuration (.env)"
if [ -f "$REPO/.env" ]; then
  info ".env exists; keeping it"
else
  cp "$REPO/.env.example" "$REPO/.env"
  if [ -z "$CI" ]; then
    pw="$(od -An -N12 -tx1 /dev/urandom | tr -d ' \n')"
    sed -i "s|^DB_PASSWORD=.*|DB_PASSWORD=${pw}|" "$REPO/.env"
    info "created .env from .env.example with a random DB_PASSWORD"
  else
    info "created .env from .env.example (CI defaults)"
  fi
  chmod 0600 "$REPO/.env"
fi
load_env

step "Python virtual environment (.venv) and requirements"
if [ ! -x "$REPO/.venv/bin/python" ]; then
  rm -rf "$REPO/.venv"
  python3 -m venv "$REPO/.venv"
  info "created $REPO/.venv ($("$REPO/.venv/bin/python" --version))"
else
  info "exists ($("$REPO/.venv/bin/python" --version))"
fi
"$REPO/.venv/bin/python" -m pip install -q --disable-pip-version-check -r "$REPO/requirements.txt"
info "requirements installed"
# Leave files usable by the person who ran sudo.
if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != root ]; then
  chown -R "$SUDO_USER": "$REPO/.venv" "$REPO/.env"
fi

step "Build the lab (setup_lab.sh)"
"$REPO/scripts/setup_lab.sh"

step "Done"
cat <<EOT
    The lab is up. Next steps:
      1. Edit .env if needed (AI_MODE=ollama and OLLAMA_URL for the real model).
      2. sudo ./scripts/start.sh        # backend + dashboard on port ${APP_PORT}
      3. Open http://<VM IP>:${APP_PORT}  (ip -4 addr shows the VM IP)
    Other tools: scripts/attack.sh, scripts/reset_lab.sh, scripts/teardown_lab.sh
EOT
