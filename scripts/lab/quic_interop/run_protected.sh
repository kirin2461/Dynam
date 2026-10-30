#!/usr/bin/env bash
# Local, same-implementation Dynam E2E-over-RealQuic proof run.
# This is not an independent implementation interop or external two-host gate.
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/../../.." && pwd)"
CLI="${1:-$REPO_ROOT/build-lab-quic/bin/ncp_quic_protected_cli}"
COUNT="${COUNT:-4}"
PORT="${PORT:-0}"
CAPTURE="${CAPTURE:-0}"
EVIDENCE_DIR="${EVIDENCE_DIR:-}"
WORK="$(mktemp -d /tmp/dynam_quic_protected_XXXXXX)"
SRV=""
TCPDUMP_PID=""

stop_capture() {
    if [ -n "$TCPDUMP_PID" ]; then
        kill -INT "$TCPDUMP_PID" 2>/dev/null || true
        wait "$TCPDUMP_PID" 2>/dev/null || true
        TCPDUMP_PID=""
    fi
}

cleanup() {
    [ -z "$SRV" ] || kill "$SRV" 2>/dev/null || true
    stop_capture
    if [ -n "$EVIDENCE_DIR" ]; then
        mkdir -p "$EVIDENCE_DIR"
        cp "$WORK"/*.log "$EVIDENCE_DIR"/ 2>/dev/null || true
        cp "$WORK"/*.pcap "$EVIDENCE_DIR"/ 2>/dev/null || true
    else
        rm -rf "$WORK"
    fi
}
trap cleanup EXIT

if [ ! -x "$CLI" ]; then
    echo "protected harness not built: $CLI" >&2
    exit 2
fi

CERT="$WORK/cert.pem"
KEY="$WORK/key.pem"
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$KEY" -out "$CERT" \
    -days 2 -subj '/CN=localhost' \
    -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1' \
    -addext 'basicConstraints=critical,CA:TRUE' >/dev/null 2>&1 || exit 2

wait_for_line() {
    for _ in $(seq 50); do
        grep -q "$2" "$1" 2>/dev/null && return 0
        sleep 0.1
    done
    return 1
}

port_from() {
    grep -oP 'LISTENING (\[?[^\]:]+\]?:)?\K\d+' "$1" | head -1
}

timeout 60 "$CLI" server --bind 127.0.0.1 --port "$PORT" \
    --cert "$CERT" --key "$KEY" --count "$COUNT" \
    >"$WORK/server.log" 2>&1 &
SRV=$!
if ! wait_for_line "$WORK/server.log" LISTENING; then
    echo "server did not start" >&2
    cat "$WORK/server.log" >&2
    exit 1
fi
PORT="$(port_from "$WORK/server.log")"
if [ -z "$PORT" ]; then
    echo "could not parse server port" >&2
    exit 1
fi

if [ "$CAPTURE" = "1" ]; then
    command -v tcpdump >/dev/null 2>&1 || {
        echo "CAPTURE=1 requires tcpdump" >&2
        exit 2
    }
    # Linux cooked-v2 (-i any) is not supported by the pinned nDPI 4.2 reader;
    # loopback EN10MB keeps this capture directly consumable by the gate.
    tcpdump -i lo -nn -s0 -U --immediate-mode -w "$WORK/protected.pcap" \
        "udp port $PORT" >"$WORK/tcpdump.log" 2>&1 &
    TCPDUMP_PID=$!
    sleep 0.2
    kill -0 "$TCPDUMP_PID" 2>/dev/null || {
        echo "tcpdump did not start" >&2
        cat "$WORK/tcpdump.log" >&2
        exit 1
    }
fi

timeout 60 "$CLI" client --host 127.0.0.1 --port "$PORT" \
    --ca "$CERT" --count "$COUNT" >"$WORK/client.log" 2>&1
CLIENT_RC=$?
wait "$SRV" 2>/dev/null
SERVER_RC=$?
SRV=""
[ "$CAPTURE" = "1" ] && sleep 0.5
stop_capture

cat "$WORK/client.log"
cat "$WORK/server.log"
echo "protected harness rc: client=$CLIENT_RC server=$SERVER_RC"

PASS=1
[ "$CLIENT_RC" -eq 0 ] && [ "$SERVER_RC" -eq 0 ] || PASS=0
grep -q '^DYNAM_QUIC_PROTECTED_OK ' "$WORK/client.log" || PASS=0
grep -q '^DYNAM_QUIC_PROTECTED_SERVER_OK ' "$WORK/server.log" || PASS=0
[ "$(grep -c '^PROTECTED_ECHO_OK ' "$WORK/client.log")" -eq "$COUNT" ] || PASS=0
[ "$(grep -c '^PROTECTED_ECHOED ' "$WORK/server.log")" -eq "$COUNT" ] || PASS=0
if grep -q 'DYNAM_QUIC_PROTECTED_FAIL\|plaintext_fallback=[^0]' \
    "$WORK/client.log" "$WORK/server.log"; then
    PASS=0
fi

if [ "$PASS" -eq 1 ]; then
    echo "DYNAM_QUIC_PROTECTED_MATRIX_PASS scope=local_same_implementation app_echoes=$COUNT"
    exit 0
fi
echo "DYNAM_QUIC_PROTECTED_MATRIX_FAIL" >&2
exit 1
