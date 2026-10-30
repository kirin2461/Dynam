#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════════════
# G5 TURN-over-UDP live interop harness.
#
#   * Starts pinned coturn (turnserver) with an isolated temporary config and
#     an ephemeral loopback port; generated independent credentials.
#   * Starts a loopback UDP echo peer.
#   * Builds and runs the ncp::turn::TurnClient interop driver (our client):
#     Allocate (401/nonce/MESSAGE-INTEGRITY), CreatePermission, Send/Data
#     bootstrap, ChannelBind + ChannelData application exchange, Refresh and
#     allocation delete.
#   * Runs the independent reference client turnutils_uclient as a control
#     (does NOT substitute for our client's interop result).
#
# Loopback only; no production services; no firewall changes. Everything lives
# in a mktemp dir removed on exit.
#
# Usage:
#   scripts/lab/turn_interop/run_turn_interop.sh [--skip-uclient] [--with-expiry]
#
# Env overrides:
#   TURN_SERVER_BIN (default: turnserver)
#   TURN_UCLIENT_BIN (default: turnutils_uclient)
# ══════════════════════════════════════════════════════════════════════════════
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
TURN_SERVER_BIN="${TURN_SERVER_BIN:-turnserver}"
TURN_UCLIENT_BIN="${TURN_UCLIENT_BIN:-turnutils_uclient}"
SKIP_UCLIENT=0
WITH_EXPIRY=0
for arg in "$@"; do
    case "$arg" in
        --skip-uclient) SKIP_UCLIENT=1 ;;
        --with-expiry) WITH_EXPIRY=1 ;;
        *) echo "unknown argument: $arg" >&2; exit 2 ;;
    esac
done

for b in "$TURN_SERVER_BIN" "$TURN_UCLIENT_BIN" python3 g++ openssl; do
    command -v "$b" >/dev/null || { echo "missing required tool: $b"; exit 2; }
done

SERVER_VER="$("$TURN_SERVER_BIN" --version 2>&1 | tail -1 || true)"
echo "== coturn version: ${SERVER_VER}"

# ── Isolated temp environment ────────────────────────────────────────────────
TMPD="$(mktemp -d /tmp/g5-turn-interop.XXXXXX)"
PIDS=()
cleanup() {
    for p in "${PIDS[@]:-}"; do
        [[ -n "$p" ]] && kill "$p" 2>/dev/null || true
    done
    sleep 0.3
    for p in "${PIDS[@]:-}"; do
        [[ -n "$p" ]] && kill -9 "$p" 2>/dev/null || true
    done
    rm -rf "$TMPD"
}
trap cleanup EXIT

# Ephemeral loopback ports.
TURN_PORT=$(( 21000 + RANDOM % 20000 ))
ECHO_PORT=$(( 21000 + RANDOM % 20000 ))
while [[ "$ECHO_PORT" == "$TURN_PORT" ]]; do ECHO_PORT=$(( 21000 + RANDOM % 20000 )); done

# Generated independent credentials (never derived from any project secret).
TURN_USER="g5u$(openssl rand -hex 4)"
TURN_PASS="g5p-$(openssl rand -hex 12)"
TURN_REALM="g5-lab-realm"

cat > "$TMPD/turnserver.conf" <<EOF
# G5 lab: isolated coturn config (loopback only, no TLS/DTLS, no CLI).
listening-ip=127.0.0.1
relay-ip=127.0.0.1
listening-port=$TURN_PORT
min-port=49300
max-port=49399
realm=$TURN_REALM
user=$TURN_USER:$TURN_PASS
lt-cred-mech
no-tls
no-dtls
no-cli
no-multicast-peers
allow-loopback-peers
pidfile=$TMPD/turnserver.pid
log-file=$TMPD/turnserver.log
verbose
EOF
if [[ "$WITH_EXPIRY" == "1" ]]; then
    # Bounds only the optional natural-expiry phase; the driver requests 1 s.
    echo "max-allocate-lifetime=3" >> "$TMPD/turnserver.conf"
fi

echo "== starting turnserver on 127.0.0.1:$TURN_PORT (config: $TMPD/turnserver.conf)"
"$TURN_SERVER_BIN" -c "$TMPD/turnserver.conf" &
PIDS+=($!)

# Wait until the TURN UDP port answers (or the process dies).
ready=0
for _ in $(seq 1 50); do
    if python3 - "$TURN_PORT" <<'PY' 2>/dev/null
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(0.2)
# Unauthenticated Allocate: a live RFC5766 server answers 401.
msg = bytes.fromhex("000300082112a442") + bytes(range(12)) + bytes.fromhex("0019000411000000")
s.sendto(msg, ("127.0.0.1", int(sys.argv[1])))
try:
    data, _ = s.recvfrom(2048)
    sys.exit(0 if len(data) >= 20 and data[0] & 0xC0 == 0 and data[4:8] == bytes.fromhex("2112a442") else 1)
except socket.timeout:
    sys.exit(1)
PY
    then ready=1; break; fi
    sleep 0.2
done
[[ "$ready" == "1" ]] || { echo "turnserver did not become ready"; cat "$TMPD/turnserver.log" 2>/dev/null || true; exit 1; }
echo "== turnserver ready"

echo "== starting UDP echo peer on 127.0.0.1:$ECHO_PORT"
python3 "$(dirname "${BASH_SOURCE[0]}")/udp_echo_peer.py" 127.0.0.1 "$ECHO_PORT" \
    > "$TMPD/echo.log" 2>&1 &
PIDS+=($!)
sleep 0.3

# ── Build the interop driver (our client, not the reference) ────────────────
echo "== building turn_client_driver"
g++ -std=c++17 -O1 -Wall \
    -I "$REPO_ROOT/src/core/include" \
    "$REPO_ROOT/scripts/lab/turn_interop/turn_client_driver.cpp" \
    "$REPO_ROOT/src/core/src/ncp_turn_client.cpp" \
    -lssl -lcrypto -o "$TMPD/turn_client_driver"

# ── Run OUR client interop (primary result) ──────────────────────────────────
echo "== running G5 TurnClient interop driver"
driver_rc=0
driver_args=(127.0.0.1 "$TURN_PORT" "$TURN_USER" "$TURN_PASS" 127.0.0.1 "$ECHO_PORT")
[[ "$WITH_EXPIRY" == "1" ]] && driver_args+=(--natural-expiry)
"$TMPD/turn_client_driver" "${driver_args[@]}" 2>&1 | tee "$TMPD/driver.log" || driver_rc=$?

# The natural-expiry phase needs a very short allocation ceiling.  That ceiling
# must not leak into the independent uclient control: its multi-second exchange
# would otherwise expire mid-test and produce a harness-induced 100% loss.
# Restart coturn with the same generated credentials but normal lifetimes.
if [[ "$WITH_EXPIRY" == "1" && "$SKIP_UCLIENT" == "0" ]]; then
    echo "== restarting coturn with normal allocation lifetime for uclient control"
    kill "${PIDS[0]}" 2>/dev/null || true
    wait "${PIDS[0]}" 2>/dev/null || true
    grep -v '^max-allocate-lifetime=' "$TMPD/turnserver.conf" \
        > "$TMPD/turnserver-control.conf"
    "$TURN_SERVER_BIN" -c "$TMPD/turnserver-control.conf" \
        > "$TMPD/turnserver-control-stdout.log" 2>&1 &
    PIDS+=($!)
    control_ready=0
    for _ in $(seq 1 50); do
        if python3 - "$TURN_PORT" <<'PY' 2>/dev/null
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(0.2)
msg = bytes.fromhex("000300082112a442") + bytes(range(12)) + bytes.fromhex("0019000411000000")
s.sendto(msg, ("127.0.0.1", int(sys.argv[1])))
try:
    data, _ = s.recvfrom(2048)
    sys.exit(0 if len(data) >= 20 and data[0] & 0xC0 == 0 and data[4:8] == bytes.fromhex("2112a442") else 1)
except socket.timeout:
    sys.exit(1)
PY
        then control_ready=1; break; fi
        sleep 0.2
    done
    [[ "$control_ready" == "1" ]] || { echo "control turnserver did not become ready"; exit 1; }
fi

# ── Independent reference client control (not a substitute) ──────────────────
uclient_rc=0
if [[ "$SKIP_UCLIENT" == "0" ]]; then
    echo "== running turnutils_uclient control (independent reference)"
    "$TURN_UCLIENT_BIN" -u "$TURN_USER" -w "$TURN_PASS" -p "$TURN_PORT" \
        -e 127.0.0.1 -r "$ECHO_PORT" -c \
        -n 3 -l 64 127.0.0.1 > "$TMPD/uclient.log" 2>&1 || uclient_rc=$?
    tail -5 "$TMPD/uclient.log" || true
fi

echo
expiry_ok=1
if [[ "$WITH_EXPIRY" == "1" ]] && ! grep -q "G5_NATURAL_EXPIRY PASS" "$TMPD/driver.log"; then
    expiry_ok=0
fi
if [[ "$driver_rc" == "0" ]] && [[ "$expiry_ok" == "1" ]] && grep -q "G5_INTEROP PASS" "$TMPD/driver.log"; then
    echo "G5_INTEROP RESULT: PASS (our ncp::turn::TurnClient vs coturn ${SERVER_VER})"
    [[ "$WITH_EXPIRY" == "1" ]] && echo "G5_NATURAL_EXPIRY RESULT: PASS (wall-clock expiry, not Refresh(0))"
else
    echo "G5_INTEROP RESULT: FAIL (driver_rc=$driver_rc)"
    echo "--- turnserver log tail ---"; tail -20 "$TMPD/turnserver.log" 2>/dev/null || true
    exit 1
fi
if [[ "$SKIP_UCLIENT" == "0" ]]; then
    if [[ "$uclient_rc" == "0" ]] && \
       grep -q "Total lost packets 0 (0.000000%)" "$TMPD/uclient.log"; then
        echo "G5_UCLIENT CONTROL: PASS (rc=0 and zero relayed-packet loss)"
    else
        echo "G5_UCLIENT CONTROL: FAIL (rc=$uclient_rc or nonzero/unreported loss) -- control only"
        exit 1
    fi
fi
