#!/usr/bin/env bash
# Full removal of the NCP/AWG server deployment created by install.sh.
set -euo pipefail

DEPLOY_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DEPLOY_DIR"

log()  { printf '\033[1;32m[+]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*"; }

[ "$(id -u)" -eq 0 ] || { echo "Run as root" >&2; exit 1; }

if [ -f .env ]; then
    # shellcheck disable=SC1091
    set -a; . ./.env; set +a
fi

log "Stopping and removing containers"
docker compose --env-file .env -f docker-compose.yml down -v 2>/dev/null || true

log "Removing images"
docker rmi dynam-ncp:local dynam-amneziawg:local 2>/dev/null || true

# SPA ipset gate cleanup (best-effort).
if command -v ipset >/dev/null 2>&1; then
    ipset destroy ncp_spa_allow 2>/dev/null || true
fi
if command -v iptables >/dev/null 2>&1; then
    iptables -D INPUT -m set --match-set ncp_spa_allow src -j ACCEPT 2>/dev/null || true
fi

if command -v ufw >/dev/null 2>&1 && [ -f .env ]; then
    ufw delete allow "${AWG_PORT:-0}/udp" 2>/dev/null || true
    ufw delete allow "${SPA_PORT:-0}/udp" 2>/dev/null || true
    ufw delete allow "${REALITY_PORT:-0}/tcp" 2>/dev/null || true
    ufw delete allow "${PORTHOP_BASE_PORT:-0}:$((${PORTHOP_BASE_PORT:-0}+${PORTHOP_RANGE:-0}-1))/udp" 2>/dev/null || true
fi

log "Removing secrets, configs and client bundles"
rm -rf secrets client-configs .env awg/awg0.conf

log "Done. The awg0 interface dies with the container; SSH was never touched."
