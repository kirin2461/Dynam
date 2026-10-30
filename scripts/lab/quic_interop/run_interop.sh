#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════
# G4 real-QUIC independent interop runner.
#
# Runs the ncp_quic_cli (MsQuic 2.6.3 wrapper) against INDEPENDENT QUIC
# stacks on UDP loopback, in both client and server roles:
#
#   1) ncp server  <-> aioquic 1.3.0 client   (full app-level echo)
#   2) aioquic 1.3.0 server <-> ncp client    (full app-level echo)
#   3) ncp server (h3 mode) <-> ngtcp2 gtlsclient   (app-level H3 GET/200)
#   4) ngtcp2 gtlsserver <-> ncp client (h3 mode)   (app-level H3 GET/200)
#   5) ncp server  <-> aioquic client         (RFC 9221 DATAGRAM echo)
#   6) aioquic server <-> ncp client          (RFC 9221 DATAGRAM echo)
#
# Cases 1-2 are full INTEROP_PASS/FAIL (echo byte-compare both roles).
# Cases 3-4 use ALPN "h3" with real HTTP/3 semantics against the ngtcp2
# example peers: an H3 GET request is parsed (QPACK static-table field
# section, :method GET verified) and a 200 response with a DATA body is
# returned/decoded. QUALIFICATION: our side never sends an H3 control
# stream/SETTINGS frame because RealQuicEndpoint cannot open unidirectional
# streams; the exchange relies on RFC 9114 default settings
# (QPACK_MAX_TABLE_CAPACITY=0). ngtcp2/nghttp3 fully decodes and validates
# both directions (it closes the HTTP stream with H3_NO_ERROR), so this is
# genuine application-level H3 interop with the stated caveat, NOT merely a
# handshake.
# Cases 5-6 are full RFC 9221 DATAGRAM INTEROP_PASS/FAIL: datagram support
# negotiation is verified (max_datagram_frame_size transport parameter) and
# every datagram echo is byte-compared, in both client/server roles.
#
# Usage: run_interop.sh [--selftest]
# Exit 0 if all runnable cases pass. Prints a summary matrix.
# ═══════════════════════════════════════════════════════════════════════════
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
CLI="$HERE/ncp_quic_cli"
AIOQUIC_PY="${AIOQUIC_PY:-python3}"
AIOQUIC="$AIOQUIC_PY $HERE/aioquic_echo.py"
WORK="$(mktemp -d /tmp/quic_interop_XXXXXX)"
# Set KEEP_LOGS=1 to preserve per-case logs under $WORK for evidence.
trap '[ -n "${KEEP_LOGS:-}" ] || rm -rf "$WORK"; kill $(jobs -p) 2>/dev/null' EXIT

CERT="$WORK/cert.pem"
KEY="$WORK/key.pem"
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$KEY" -out "$CERT" \
    -days 2 -subj '/CN=localhost' \
    -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1' \
    -addext 'basicConstraints=critical,CA:TRUE' >/dev/null 2>&1

if [ ! -x "$CLI" ]; then
    echo "building ncp_quic_cli..."
    bash "$HERE/build.sh" >/dev/null
fi

PASS=0; FAIL=0; SKIP=0
report() {  # report <case> <PASS|FAIL|SKIP> <detail>
    printf '%-42s %-6s %s\n' "$1" "$2" "$3"
    case "$2" in PASS) PASS=$((PASS+1));; FAIL) FAIL=$((FAIL+1));; *) SKIP=$((SKIP+1));; esac
}

wait_for_line() {  # wait_for_line <file> <pattern> <tries>
    for _ in $(seq "$3"); do
        grep -q "$2" "$1" 2>/dev/null && return 0
        sleep 0.2
    done
    return 1
}

port_from() { grep -oP 'LISTENING (\[?[^\]:]+\]?:)?\K\d+' "$1" | head -1; }

SELFTEST=${1:-}
if [ "$SELFTEST" = "--selftest" ]; then
    echo "== case 0: ncp server <-> ncp client (selftest) =="
    timeout 30 "$CLI" server --port 0 --cert "$CERT" --key "$KEY" \
        --max-messages 4 > "$WORK/s0.log" 2>&1 &
    SRV=$!
    wait_for_line "$WORK/s0.log" LISTENING 25
    PORT=$(port_from "$WORK/s0.log")
    timeout 30 "$CLI" client --host 127.0.0.1 --port "$PORT" --insecure \
        --count 4 > "$WORK/c0.log" 2>&1
    RC=$?
    wait $SRV 2>/dev/null
    if [ $RC -eq 0 ] && grep -q INTEROP_OK "$WORK/c0.log"; then
        report "ncp<->ncp selftest" PASS "4 messages echoed"
    else
        report "ncp<->ncp selftest" FAIL "rc=$RC"; cat "$WORK/c0.log"
    fi
fi

# ---------------------------------------------------------------- case 1
echo "== case 1: ncp server <-> aioquic client =="
if $AIOQUIC_PY -c "import aioquic" 2>/dev/null; then
    timeout 60 "$CLI" server --port 0 --cert "$CERT" --key "$KEY" \
        --max-messages 4 > "$WORK/s1.log" 2>&1 &
    SRV=$!
    if wait_for_line "$WORK/s1.log" LISTENING 25; then
        PORT=$(port_from "$WORK/s1.log")
        timeout 60 $AIOQUIC client --host 127.0.0.1 --port "$PORT" \
            --insecure --count 4 > "$WORK/c1.log" 2>&1
        RC=$?
        wait $SRV 2>/dev/null
        if [ $RC -eq 0 ] && grep -q INTEROP_OK "$WORK/c1.log" \
            && grep -q "SERVER_DONE handled=4" "$WORK/s1.log"; then
            report "aioquic client -> ncp server" PASS \
                "$(grep -c ECHO_OK "$WORK/c1.log") echoes"
        else
            report "aioquic client -> ncp server" FAIL "rc=$RC"
            tail -n 5 "$WORK/c1.log" "$WORK/s1.log"
        fi
    else
        report "aioquic client -> ncp server" FAIL "server no listen"
    fi
else
    report "aioquic client -> ncp server" SKIP "aioquic not installed"
fi

# ------------------------------------------------------------- case 1b
echo "== case 1b: ncp server <-> aioquic client (CA-verified TLS) =="
if $AIOQUIC_PY -c "import aioquic" 2>/dev/null; then
    timeout 60 "$CLI" server --port 0 --cert "$CERT" --key "$KEY" \
        --max-messages 2 > "$WORK/s1b.log" 2>&1 &
    SRV=$!
    if wait_for_line "$WORK/s1b.log" LISTENING 25; then
        PORT=$(port_from "$WORK/s1b.log")
        # aioquic verifies our self-signed (CA:TRUE) cert via --ca and the
        # IP SAN 127.0.0.1; no insecure flag here.
        timeout 60 $AIOQUIC client --host 127.0.0.1 --port "$PORT" \
            --ca "$CERT" --count 2 > "$WORK/c1b.log" 2>&1
        RC=$?
        wait $SRV 2>/dev/null
        if [ $RC -eq 0 ] && grep -q INTEROP_OK "$WORK/c1b.log"; then
            report "aioquic client (CA-verify) -> ncp server" PASS \
                "verified handshake + echoes"
        else
            report "aioquic client (CA-verify) -> ncp server" FAIL "rc=$RC"
            tail -n 5 "$WORK/c1b.log" "$WORK/s1b.log"
        fi
    else
        report "aioquic client (CA-verify) -> ncp server" FAIL "no listen"
    fi
else
    report "aioquic client (CA-verify) -> ncp server" SKIP "aioquic absent"
fi

# ---------------------------------------------------------------- case 2
echo "== case 2: aioquic server <-> ncp client =="
if $AIOQUIC_PY -c "import aioquic" 2>/dev/null; then
    timeout 60 $AIOQUIC server --port 0 --cert "$CERT" --key "$KEY" \
        > "$WORK/s2.log" 2>&1 &
    SRV=$!
    # aioquic serve() with port 0: read bound port from log line
    if wait_for_line "$WORK/s2.log" LISTENING 50; then
        PORT=$(port_from "$WORK/s2.log")
        timeout 60 "$CLI" client --host 127.0.0.1 --port "$PORT" \
            --insecure --count 4 > "$WORK/c2.log" 2>&1
        RC=$?
        kill $SRV 2>/dev/null; wait $SRV 2>/dev/null
        if [ $RC -eq 0 ] && grep -q INTEROP_OK "$WORK/c2.log" \
            && grep -q ECHOED "$WORK/s2.log"; then
            report "ncp client -> aioquic server" PASS \
                "$(grep -c ECHO_OK "$WORK/c2.log") echoes"
        else
            report "ncp client -> aioquic server" FAIL "rc=$RC"
            tail -n 5 "$WORK/c2.log" "$WORK/s2.log"
        fi
    else
        report "ncp client -> aioquic server" FAIL "server no listen"
        tail -n 5 "$WORK/s2.log"
    fi
else
    report "ncp client -> aioquic server" SKIP "aioquic not installed"
fi

# ---------------------------------------------------------------- case 3
echo "== case 3: ncp server (h3) <-> ngtcp2 gtlsclient (app-level H3) =="
if command -v gtlsclient >/dev/null 2>&1; then
    timeout 60 "$CLI" server --port 0 --cert "$CERT" --key "$KEY" \
        --alpn h3 --unidi 3 --h3 --max-messages 1 > "$WORK/s3.log" 2>&1 &
    SRV=$!
    if wait_for_line "$WORK/s3.log" LISTENING 25; then
        PORT=$(port_from "$WORK/s3.log")
        # No -q / --no-http-dump: ngtcp2's own HTTP/3 decoder must print the
        # response headers (:status: 200) and body for the PASS verdict.
        timeout 30 gtlsclient --exit-on-first-stream-close \
            127.0.0.1 "$PORT" "https://127.0.0.1:$PORT/index.html" \
            > "$WORK/c3.log" 2>&1
        RC=$?
        wait $SRV 2>/dev/null
        if [ $RC -eq 0 ] \
            && grep -q "H3_RESPONDED .*status=200" "$WORK/s3.log" \
            && grep -q ":status: 200" "$WORK/c3.log" \
            && grep -q "ncp-h3-echo" "$WORK/c3.log"; then
            report "ngtcp2 client -> ncp server (H3)" PASS \
                "H3 GET parsed, 200+body decoded by ngtcp2 (no SETTINGS sent)"
        else
            report "ngtcp2 client -> ncp server (H3)" FAIL "rc=$RC"
            tail -n 8 "$WORK/c3.log" "$WORK/s3.log"
        fi
    else
        report "ngtcp2 client -> ncp server (H3)" FAIL "server no listen"
    fi
else
    report "ngtcp2 client -> ncp server (H3)" SKIP "gtlsclient not installed"
fi

# ---------------------------------------------------------------- case 4
echo "== case 4: ngtcp2 gtlsserver <-> ncp client (h3) (app-level H3) =="
if command -v gtlsserver >/dev/null 2>&1; then
    mkdir -p "$WORK/htdocs"
    echo "hello from ngtcp2 h3" > "$WORK/htdocs/index.html"
    PORT=$(python3 - <<'EOF'
import socket
s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1",0))
print(s.getsockname()[1])
s.close()
EOF
)
    timeout 60 gtlsserver -q 127.0.0.1 $PORT "$KEY" "$CERT" \
        -d "$WORK/htdocs" > "$WORK/s4.log" 2>&1 &
    SRV=$!
    sleep 1
    timeout 30 "$CLI" client --host 127.0.0.1 --port $PORT --alpn h3 \
        --insecure --unidi 3 --h3 > "$WORK/c4.log" 2>&1
    RC=$?
    kill $SRV 2>/dev/null; wait $SRV 2>/dev/null
    if [ $RC -eq 0 ] && grep -q "INTEROP_OK h3=1" "$WORK/c4.log" \
        && grep -q "H3_RESPONSE .*status=200" "$WORK/c4.log"; then
        report "ncp client -> ngtcp2 server (H3)" PASS \
            "$(grep H3_RESPONSE "$WORK/c4.log" | head -1)"
    else
        report "ncp client -> ngtcp2 server (H3)" FAIL "rc=$RC"
        tail -n 5 "$WORK/c4.log" "$WORK/s4.log"
    fi
else
    report "ncp client -> ngtcp2 server (H3)" SKIP "gtlsserver not installed"
fi

# ---------------------------------------------------------------- case 5
echo "== case 5: ncp server <-> aioquic client (RFC 9221 DATAGRAM echo) =="
if $AIOQUIC_PY -c "import aioquic" 2>/dev/null; then
    timeout 60 "$CLI" server --port 0 --cert "$CERT" --key "$KEY" \
        --datagram --max-datagrams 4 > "$WORK/s5.log" 2>&1 &
    SRV=$!
    if wait_for_line "$WORK/s5.log" LISTENING 25; then
        PORT=$(port_from "$WORK/s5.log")
        # --count 0: pure datagram exchange, no stream messages.
        timeout 60 $AIOQUIC client --host 127.0.0.1 --port "$PORT" \
            --insecure --count 0 --datagram --dgram-count 4 \
            > "$WORK/c5.log" 2>&1
        RC=$?
        wait $SRV 2>/dev/null
        if [ $RC -eq 0 ] && grep -q INTEROP_OK "$WORK/c5.log" \
            && grep -q DGRAM_NEGOTIATED "$WORK/c5.log" \
            && [ "$(grep -c DGRAM_OK "$WORK/c5.log")" -eq 4 ] \
            && [ "$(grep -c ECHOED_DGRAM "$WORK/s5.log")" -eq 4 ] \
            && grep -q "SERVER_DONE handled=0 dgrams=4" "$WORK/s5.log"; then
            report "aioquic client -> ncp server (DATAGRAM)" PASS \
                "$(grep DGRAM_NEGOTIATED "$WORK/c5.log" | head -1), 4 datagrams echoed"
        else
            report "aioquic client -> ncp server (DATAGRAM)" FAIL "rc=$RC"
            tail -n 5 "$WORK/c5.log" "$WORK/s5.log"
        fi
    else
        report "aioquic client -> ncp server (DATAGRAM)" FAIL "no listen"
    fi
else
    report "aioquic client -> ncp server (DATAGRAM)" SKIP "aioquic absent"
fi

# ---------------------------------------------------------------- case 6
echo "== case 6: aioquic server <-> ncp client (streams + RFC 9221 DATAGRAM) =="
if $AIOQUIC_PY -c "import aioquic" 2>/dev/null; then
    timeout 60 $AIOQUIC server --port 0 --cert "$CERT" --key "$KEY" \
        --datagram > "$WORK/s6.log" 2>&1 &
    SRV=$!
    if wait_for_line "$WORK/s6.log" LISTENING 50; then
        PORT=$(port_from "$WORK/s6.log")
        # --count 2: stream echo and datagram echo on the same connection.
        timeout 60 "$CLI" client --host 127.0.0.1 --port "$PORT" \
            --insecure --count 2 --datagram --dgram-count 4 \
            > "$WORK/c6.log" 2>&1
        RC=$?
        kill $SRV 2>/dev/null; wait $SRV 2>/dev/null
        if [ $RC -eq 0 ] && grep -q INTEROP_OK "$WORK/c6.log" \
            && grep -q DGRAM_NEGOTIATED "$WORK/c6.log" \
            && [ "$(grep -c DGRAM_OK "$WORK/c6.log")" -eq 4 ] \
            && [ "$(grep -c ECHOED_DGRAM "$WORK/s6.log")" -eq 4 ]; then
            report "ncp client -> aioquic server (DATAGRAM)" PASS \
                "$(grep DGRAM_NEGOTIATED "$WORK/c6.log" | head -1), 4 datagrams echoed"
        else
            report "ncp client -> aioquic server (DATAGRAM)" FAIL "rc=$RC"
            tail -n 5 "$WORK/c6.log" "$WORK/s6.log"
        fi
    else
        report "ncp client -> aioquic server (DATAGRAM)" FAIL "no listen"
        tail -n 5 "$WORK/s6.log"
    fi
else
    report "ncp client -> aioquic server (DATAGRAM)" SKIP "aioquic absent"
fi

echo "──────────────────────────────────────────────────────────────"
echo "interop summary: PASS=$PASS FAIL=$FAIL SKIP=$SKIP"
[ $FAIL -eq 0 ]
