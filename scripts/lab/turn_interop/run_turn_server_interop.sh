#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════════════
# G5 TURN-server live interop harness (SERVER role under test).
#
#   * Builds and starts OUR ncp::turn::TurnServer (turn_server_driver) with
#     isolated ephemeral loopback ports and generated independent credentials.
#   * Starts a loopback UDP echo peer.
#   * Runs the existing turn_client_driver (OUR ncp::turn::TurnClient) against
#     OUR server: Allocate (401/nonce/MESSAGE-INTEGRITY), CreatePermission,
#     Send/Data bootstrap, ChannelBind + ChannelData exchange, Refresh and
#     delete. This is a self-consistency check ONLY — it is NOT independent
#     implementation interop.
#   * Runs the INDEPENDENT reference client turnutils_uclient (coturn) against
#     OUR server and requires zero relayed-packet loss. This is the independent
#     interop control for the server role.
#
# Loopback only; no production services; no firewall changes. Everything lives
# in a mktemp dir removed on exit. run_turn_interop.sh is untouched and still
# covers the client-role direction (our client vs coturn server).
#
# Usage:
#   scripts/lab/turn_interop/run_turn_server_interop.sh [--skip-uclient]
#
# Env overrides:
#   TURN_UCLIENT_BIN (default: turnutils_uclient)
# ══════════════════════════════════════════════════════════════════════════════
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
TURN_UCLIENT_BIN="${TURN_UCLIENT_BIN:-turnutils_uclient}"
CAPTURE="${CAPTURE:-0}"
EVIDENCE_DIR="${EVIDENCE_DIR:-}"
SKIP_UCLIENT=0
for arg in "$@"; do
    case "$arg" in
        --skip-uclient) SKIP_UCLIENT=1 ;;
        *) echo "unknown argument: $arg" >&2; exit 2 ;;
    esac
done

for b in g++ python3 openssl; do
    command -v "$b" >/dev/null || { echo "missing required tool: $b"; exit 2; }
done
if [[ "$SKIP_UCLIENT" == "0" ]]; then
    command -v "$TURN_UCLIENT_BIN" >/dev/null || \
        { echo "missing required tool: $TURN_UCLIENT_BIN"; exit 2; }
fi

# ── Isolated temp environment ────────────────────────────────────────────────
TMPD="$(mktemp -d /tmp/g5-turn-server-interop.XXXXXX)"
PIDS=()
CAPTURE_PID=""
stop_capture() {
    if [[ -n "$CAPTURE_PID" ]]; then
        kill -INT "$CAPTURE_PID" 2>/dev/null || true
        wait "$CAPTURE_PID" 2>/dev/null || true
        CAPTURE_PID=""
    fi
}
cleanup() {
    stop_capture
    for p in "${PIDS[@]:-}"; do
        [[ -n "$p" ]] && kill "$p" 2>/dev/null || true
    done
    sleep 0.3
    for p in "${PIDS[@]:-}"; do
        [[ -n "$p" ]] && kill -9 "$p" 2>/dev/null || true
    done
    if [[ -n "$EVIDENCE_DIR" ]]; then
        mkdir -p "$EVIDENCE_DIR"
        cp "$TMPD"/*.log "$TMPD"/*.pcap "$EVIDENCE_DIR"/ 2>/dev/null || true
    fi
    rm -rf "$TMPD"
}
trap cleanup EXIT

# Ephemeral loopback ports.
TURN_PORT=$(( 21000 + RANDOM % 20000 ))
ECHO_PORT=$(( 21000 + RANDOM % 20000 ))
while [[ "$ECHO_PORT" == "$TURN_PORT" ]]; do ECHO_PORT=$(( 21000 + RANDOM % 20000 )); done

# Generated independent credentials (never derived from any project secret).
TURN_USER="g5su$(openssl rand -hex 4)"
TURN_PASS="g5sp-$(openssl rand -hex 12)"
TURN_REALM="g5-server-lab-realm"

# ── Build OUR server driver and the existing client driver ───────────────────
echo "== building turn_server_driver (our ncp::turn::TurnServer)"
g++ -std=c++17 -O1 -Wall \
    -I "$REPO_ROOT/src/core/include" \
    "$REPO_ROOT/scripts/lab/turn_interop/turn_server_driver.cpp" \
    "$REPO_ROOT/src/core/src/ncp_turn_server.cpp" \
    "$REPO_ROOT/src/core/src/ncp_turn_client.cpp" \
    -lssl -lcrypto -o "$TMPD/turn_server_driver"

echo "== building turn_client_driver (our ncp::turn::TurnClient)"
g++ -std=c++17 -O1 -Wall \
    -I "$REPO_ROOT/src/core/include" \
    "$REPO_ROOT/scripts/lab/turn_interop/turn_client_driver.cpp" \
    "$REPO_ROOT/src/core/src/ncp_turn_client.cpp" \
    -lssl -lcrypto -o "$TMPD/turn_client_driver"

# ── Start OUR server ──────────────────────────────────────────────────────────
echo "== starting our TURN server on 127.0.0.1:$TURN_PORT (relay 127.0.0.1)"
"$TMPD/turn_server_driver" 127.0.0.1 "$TURN_PORT" 127.0.0.1 \
    "$TURN_REALM" "$TURN_USER" "$TURN_PASS" \
    > "$TMPD/server.log" 2> "$TMPD/server.err" &
PIDS+=($!)

# Wait until READY line (actual bound port) and the UDP socket answers a 401.
ready=0
for _ in $(seq 1 50); do
    if grep -q "READY $TURN_PORT" "$TMPD/server.log" 2>/dev/null && \
       python3 - "$TURN_PORT" <<'PY' 2>/dev/null
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
    kill -0 "${PIDS[0]}" 2>/dev/null || break
    sleep 0.2
done
if [[ "$ready" != "1" ]]; then
    echo "our TURN server did not become ready"
    cat "$TMPD/server.log" "$TMPD/server.err" 2>/dev/null || true
    exit 1
fi
echo "== our TURN server ready: $(head -1 "$TMPD/server.log")"

echo "== starting UDP echo peer on 127.0.0.1:$ECHO_PORT"
python3 "$(dirname "${BASH_SOURCE[0]}")/udp_echo_peer.py" 127.0.0.1 "$ECHO_PORT" \
    > "$TMPD/echo.log" 2>&1 &
PIDS+=($!)
sleep 0.3

if [[ "$CAPTURE" == "1" ]]; then
    command -v tcpdump >/dev/null || { echo 'CAPTURE=1 requires tcpdump'; exit 2; }
    # Only the client<->server TURN socket is classified here.  The separate
    # relay<->echo UDP flow is deliberately outside this STUN capture.
    tcpdump -i lo -nn -s0 -U --immediate-mode \
        -w "$TMPD/turn-server.pcap" "udp port $TURN_PORT" \
        > "$TMPD/tcpdump.log" 2>&1 &
    CAPTURE_PID=$!
    sleep 0.3
    kill -0 "$CAPTURE_PID" 2>/dev/null || {
        cat "$TMPD/tcpdump.log"; exit 1;
    }
fi

# ── OUR client <-> OUR server (self-consistency, NOT independent interop) ────
echo "== running existing turn_client_driver against OUR server (self-consistency)"
driver_rc=0
"$TMPD/turn_client_driver" 127.0.0.1 "$TURN_PORT" "$TURN_USER" "$TURN_PASS" \
    127.0.0.1 "$ECHO_PORT" 2>&1 | tee "$TMPD/driver.log" || driver_rc=$?

echo
if [[ "$driver_rc" == "0" ]] && grep -q "G5_INTEROP PASS" "$TMPD/driver.log"; then
    echo "G5_SERVER_INTEROP PASS (our ncp::turn::TurnClient <-> our ncp::turn::TurnServer; self-consistency only, NOT independent interop)"
else
    echo "G5_SERVER_INTEROP FAIL (driver_rc=$driver_rc)"
    echo "--- server stderr tail ---"; tail -20 "$TMPD/server.err" 2>/dev/null || true
    exit 1
fi

# ── Independent reference client control: turnutils_uclient <-> OUR server ───
uclient_rc=0
if [[ "$SKIP_UCLIENT" == "0" ]]; then
    echo "== running turnutils_uclient (independent reference) against OUR server"
    "$TURN_UCLIENT_BIN" -u "$TURN_USER" -w "$TURN_PASS" -p "$TURN_PORT" \
        -e 127.0.0.1 -r "$ECHO_PORT" -c \
        -n 3 -l 64 127.0.0.1 > "$TMPD/uclient.log" 2>&1 || uclient_rc=$?
    tail -5 "$TMPD/uclient.log" || true

    if [[ "$uclient_rc" == "0" ]] && \
       grep -q "Total lost packets 0 (0.000000%)" "$TMPD/uclient.log"; then
        echo "G5_SERVER_UCLIENT CONTROL PASS (independent turnutils_uclient <-> our server, zero relayed-packet loss)"
    else
        echo "G5_SERVER_UCLIENT CONTROL FAIL (rc=$uclient_rc or nonzero/unreported loss)"
        echo "--- server stderr tail ---"; tail -20 "$TMPD/server.err" 2>/dev/null || true
        exit 1
    fi
fi

if [[ "$CAPTURE" == "1" ]]; then
    sleep 0.3
    stop_capture
    [[ -s "$TMPD/turn-server.pcap" ]] || { echo 'TURN capture is empty'; exit 1; }
fi
