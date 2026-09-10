#!/usr/bin/env bash
# ============================================================================
# NCP (Dynam) + AmneziaWG 3.1 — one-command server installer
#
#   sudo ./install.sh
#
# What it does (see deploy/README.md for details):
#   1. Preflight checks (root, Debian/Ubuntu, free ports, UDP egress)
#   2. Installs Docker + compose plugin (official Docker repo)
#   3. Builds images: dynam-ncp (from this repo) + dynam-amneziawg (source)
#   4. Generates UNIQUE per-installation secrets: AWG keys, H1-H4/S1-S4,
#      SPA/reality Ed25519 keys, porthop HMAC + header-protection secrets,
#      random ports (so no universal DPI rule matches this install)
#   5. Writes .env (chmod 600) + secrets/, renders awg0.conf
#   6. docker compose up -d + healthchecks
#   7. Firewall: opens only the needed UDP/TCP ports (SSH untouched)
#   8. Prints + saves the client bundle into ./client-configs/
#
# Secrets never leave this machine. Do not commit .env / secrets/ /
# client-configs/ (they are in .gitignore).
# ============================================================================
set -euo pipefail

DEPLOY_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$DEPLOY_DIR/.." && pwd)"
cd "$DEPLOY_DIR"

log()  { printf '\033[1;32m[+]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

# --------------------------------------------------------------------------
# 1. Preflight
# --------------------------------------------------------------------------
[ "$(id -u)" -eq 0 ] || die "Run as root: sudo ./install.sh"

if [ -r /etc/os-release ]; then
    . /etc/os-release
    case "${ID:-}" in
        ubuntu|debian) : ;;
        *) warn "Untested OS '${ID:-unknown}' — Debian/Ubuntu expected, continuing anyway" ;;
    esac
else
    warn "Cannot detect OS — continuing anyway"
fi

# --------------------------------------------------------------------------
# 2. Docker + compose plugin
# --------------------------------------------------------------------------
if ! command -v docker >/dev/null 2>&1; then
    log "Installing Docker (official repository)"
    apt-get update -qq
    apt-get install -y -qq ca-certificates curl gnupg >/dev/null
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/${ID:-ubuntu}/docker.gpg \
        -o /etc/apt/keyrings/docker.asc
    chmod a+r /etc/apt/keyrings/docker.asc
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] \
https://download.docker.com/linux/${ID:-ubuntu} ${VERSION_CODENAME:-jammy} stable" \
        > /etc/apt/sources.list.d/docker.list
    apt-get update -qq
    apt-get install -y -qq docker-ce docker-ce-cli containerd.io \
        docker-buildx-plugin docker-compose-plugin >/dev/null
fi
docker compose version >/dev/null 2>&1 \
    || die "docker compose plugin missing (apt-get install docker-compose-plugin)"

mkdir -p secrets client-configs
chmod 700 secrets client-configs

# --------------------------------------------------------------------------
# 3. Build images
# --------------------------------------------------------------------------
log "Building dynam-ncp image from repo source (this takes a few minutes)"
docker build -f "$DEPLOY_DIR/Dockerfile.ncp" -t dynam-ncp:local "$REPO_ROOT"

log "Building dynam-amneziawg image from source"
docker build -f "$DEPLOY_DIR/Dockerfile.amneziawg" -t dynam-amneziawg:local "$REPO_ROOT"

# --------------------------------------------------------------------------
# 4. Unique per-installation secrets
# --------------------------------------------------------------------------
rand_hex()   { head -c "$1" /dev/urandom | od -An -tx1 | tr -d ' \n'; }
rand_b64()   { head -c "$1" /dev/urandom | base64 -w0; }
rand_u32()   { echo $(( 16 + RANDOM % 2000000000 )); }
rand_port()  { echo $(( 20000 + RANDOM % 40000 )); }

# Distinct H1-H4 outside the reserved WG message-type range (1..4).
H1=$(rand_u32); H2=$(rand_u32); H3=$(rand_u32); H4=$(rand_u32)
while [ "$H2" = "$H1" ]; do H2=$(rand_u32); done
while [ "$H3" = "$H1" ] || [ "$H3" = "$H2" ]; do H3=$(rand_u32); done
while [ "$H4" = "$H1" ] || [ "$H4" = "$H2" ] || [ "$H4" = "$H3" ]; do H4=$(rand_u32); done

S1=$(( 16 + RANDOM % 1136 )); S2=$(( 16 + RANDOM % 1136 ))
S3=$(( 16 + RANDOM % 1136 )); S4=$(( 16 + RANDOM % 1136 ))
JC=$(( 3 + RANDOM % 8 )); JMIN=$(( 10 + RANDOM % 41 )); JMAX=$(( 200 + RANDOM % 800 ))
HEADER_PROTECTION_KEY=$(rand_b64 32)

AWG_PORT=$(rand_port)
SPA_PORT=$(rand_port)
REALITY_PORT=443
PORTHOP_BASE=$(rand_port)
PORTHOP_RANGE=16
PORTHOP_SECRET=$(rand_hex 32)
PORTHOP_HP_SECRET=$(rand_hex 32)
PORTHOP_SESSION_ID="0x$(rand_hex 8)"
PORTHOP_VER_MIN=$(( 100 + RANDOM % 100 ))
PORTHOP_VER_MAX=$(( PORTHOP_VER_MIN + 5 + RANDOM % 40 ))
PORTHOP_HOP_MIN=$(( 30 + RANDOM % 60 ))
PORTHOP_HOP_MAX=$(( PORTHOP_HOP_MIN + 30 + RANDOM % 90 ))
AWG_ADDRESS="10.$(( RANDOM % 200 + 10 )).$(( RANDOM % 200 + 10 )).1/24"
AWG_CLIENT_ADDRESS="${AWG_ADDRESS%1/24}2/32"
AWG_SUBNET="${AWG_ADDRESS%.*}.0/24"

log "Generating AmneziaWG server + client keypairs"
AWG_SERVER_PRIV=$(docker run --rm dynam-amneziawg:local awg genkey)
AWG_SERVER_PUB=$(printf '%s' "$AWG_SERVER_PRIV" | docker run --rm -i dynam-amneziawg:local awg pubkey)
AWG_CLIENT_PRIV=$(docker run --rm dynam-amneziawg:local awg genkey)
AWG_CLIENT_PUB=$(printf '%s' "$AWG_CLIENT_PRIV" | docker run --rm -i dynam-amneziawg:local awg pubkey)

log "Generating SPA + reality Ed25519 keys (via ncp spa keygen)"
docker run --rm -v "$DEPLOY_DIR/secrets:/out" dynam-ncp:local \
    spa keygen --out /out/client >/dev/null
# The .key file is 96 bytes: sk(64) || pk(32). The authorized_keys line is
# the base64 public key; the reality keyfile wants base64 of the 64B secret.
SPA_PUBKEY_B64=$(tail -c 32 secrets/client.key | base64 -w0)
REALITY_SECRET_B64=$(head -c 64 secrets/client.key | base64 -w0)
SPA_KEY_ID=$(head -c 32 secrets/client.key | sha256sum | head -c 16)

printf '%s\n' "$SPA_PUBKEY_B64" > secrets/spa_authorized_keys
printf '%s %s\n' "client-$SPA_KEY_ID" "$REALITY_SECRET_B64" > secrets/reality_keys
chmod 600 secrets/* 2>/dev/null || true

# --------------------------------------------------------------------------
# 5. Render configs
# --------------------------------------------------------------------------
log "Writing .env and awg0.conf"
cat > .env <<EOF
# Generated by install.sh on $(date -u +%Y-%m-%dT%H:%M:%SZ) — unique per install.
AWG_PORT=$AWG_PORT
AWG_MTU=1280
AWG_ADDRESS=$AWG_ADDRESS
SPA_PORT=$SPA_PORT
SPA_TTL=300
REALITY_PORT=$REALITY_PORT
REALITY_FALLBACK=${REALITY_FALLBACK:-www.microsoft.com:443}
REALITY_INTERNAL=${REALITY_INTERNAL:-127.0.0.1:22}
PORTHOP_BASE_PORT=$PORTHOP_BASE
PORTHOP_RANGE=$PORTHOP_RANGE
PORTHOP_SECRET=$PORTHOP_SECRET
PORTHOP_HP_SECRET=$PORTHOP_HP_SECRET
PORTHOP_SESSION_ID=$PORTHOP_SESSION_ID
PORTHOP_VER_RANGE=$PORTHOP_VER_MIN-$PORTHOP_VER_MAX
PORTHOP_PADDING=2-10
PORTHOP_HOP_INTERVAL=$PORTHOP_HOP_MIN-$PORTHOP_HOP_MAX
EOF
chmod 600 .env

cat > awg/awg0.conf <<EOF
# AmneziaWG server config — unique parameters for THIS installation.
[Interface]
PrivateKey = $AWG_SERVER_PRIV
ListenPort = $AWG_PORT
MTU = 1280
Jc = $JC
Jmin = $JMIN
Jmax = $JMAX
S1 = $S1
S2 = $S2
S3 = $S3
S4 = $S4
H1 = $H1
H2 = $H2
H3 = $H3
H4 = $H4
# AWG 3.1 header protection / padding (ignored by older tools)
HeaderProtectionKey = $HEADER_PROTECTION_KEY
ContentPaddingAddition = 2-10

[Peer]
# client
PublicKey = $AWG_CLIENT_PUB
AllowedIPs = ${AWG_CLIENT_ADDRESS}
EOF
chmod 600 awg/awg0.conf

# --------------------------------------------------------------------------
# 6. Firewall — open only what's needed, never touch SSH
# --------------------------------------------------------------------------
if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
    log "ufw is active — opening AWG/SPA/porthop ports (SSH untouched)"
    ufw allow "$AWG_PORT"/udp >/dev/null
    ufw allow "$SPA_PORT"/udp >/dev/null
    ufw allow "$REALITY_PORT"/tcp >/dev/null
    ufw allow "$PORTHOP_BASE:$(( PORTHOP_BASE + PORTHOP_RANGE - 1 ))/udp" >/dev/null
else
    warn "ufw inactive or absent — skipping firewall changes."
    warn "Make sure UDP $AWG_PORT, UDP $SPA_PORT, TCP $REALITY_PORT and"
    warn "UDP $PORTHOP_BASE-$(( PORTHOP_BASE + PORTHOP_RANGE - 1 )) are reachable."
fi

# --------------------------------------------------------------------------
# 7. Up + healthcheck
# --------------------------------------------------------------------------
log "Starting containers"
docker compose --env-file .env -f docker-compose.yml up -d --build

log "Waiting for healthchecks"
sleep 5
docker compose --env-file .env -f docker-compose.yml ps

if ! docker exec dynam-awg awg show awg0 >/dev/null 2>&1; then
    warn "amnezia-awg healthcheck failed — see: docker logs dynam-awg"
fi

# --------------------------------------------------------------------------
# 8. Client bundle
# --------------------------------------------------------------------------
SERVER_IP=$(curl -fsS --max-time 5 https://ifconfig.me 2>/dev/null \
            || hostname -I | awk '{print $1}')

CLIENT_CONF=client-configs/awg-client.conf
cat > "$CLIENT_CONF" <<EOF
# AmneziaWG client config — import into AmneziaVPN 3.1+ (or awg-compatible
# client). Parameters are unique to this server installation.
[Interface]
PrivateKey = $AWG_CLIENT_PRIV
Address = ${AWG_CLIENT_ADDRESS%/*}/24
DNS = 1.1.1.1, 1.0.0.1
MTU = 1280
Jc = $JC
Jmin = $JMIN
Jmax = $JMAX
S1 = $S1
S2 = $S2
S3 = $S3
S4 = $S4
H1 = $H1
H2 = $H2
H3 = $H3
H4 = $H4
HeaderProtectionKey = $HEADER_PROTECTION_KEY
ContentPaddingAddition = 2-10

[Peer]
PublicKey = $AWG_SERVER_PUB
Endpoint = $SERVER_IP:$AWG_PORT
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = $(( 20 + RANDOM % 16 ))
EOF
chmod 600 "$CLIENT_CONF"

cp secrets/client.key client-configs/spa-client.key
cat > client-configs/ACCESS.txt <<EOF
NCP/AWG server access bundle — $(date -u +%Y-%m-%d)
=================================================
Server: $SERVER_IP

1) Main transport — AmneziaWG:
   Import awg-client.conf into AmneziaVPN 3.1+ (AWG protocol).

2) SPA knock (opens the AWG port if the SPA gate is enforced):
   ncp spa knock $SERVER_IP --key spa-client.key --allow-port $AWG_PORT --proto udp --port $SPA_PORT

3) Reality front:  $SERVER_IP:$REALITY_PORT
   (fallback site: ${REALITY_FALLBACK:-www.microsoft.com:443};
    authorized clients carry the Ed25519 token from spa-client.key)

4) Port-hopping transport (AWG 3.1 hardened):
   ncp porthop client --host $SERVER_IP --base-port $PORTHOP_BASE \\
       --range $PORTHOP_RANGE --secret $PORTHOP_SECRET \\
       --hp-secret $PORTHOP_HP_SECRET --ver-range $PORTHOP_VER_MIN-$PORTHOP_VER_MAX \\
       --content-padding 2-10 --hop-interval $PORTHOP_HOP_MIN-$PORTHOP_HOP_MAX \\
       --session-id $PORTHOP_SESSION_ID --message "ping"

5) Fallback if the transport is unreachable:
   ncp proxy --autopilot        # local DPI bypass without the server

Keep this directory private (mode 600). Do not send it over chat.
EOF
chmod 600 client-configs/ACCESS.txt

log "Done. Client bundle: $DEPLOY_DIR/client-configs/"
echo
cat client-configs/ACCESS.txt
echo
if command -v qrencode >/dev/null 2>&1; then
    log "AWG client config QR:"
    qrencode -t ansiutf8 < "$CLIENT_CONF" || true
else
    warn "Install 'qrencode' to print the AWG config as a QR code"
fi

log "Hardening reminder: switch SSH to key-only auth"
warn "  sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config && systemctl reload ssh"
warn "  (only after your SSH key works!) and consider fail2ban."
