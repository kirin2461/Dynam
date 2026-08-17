#!/usr/bin/env bash
# suite3_compat.sh — Suite 3: protocol compatibility through the bypass.
#
# Cells: TLS1.2-only server, TLS1.3, HTTP/1.1, HTTP/2, QUIC/HTTP3.
# For each cell x ncp mode we run a request through the proxy, capture the
# traffic and assert the negotiated parameters with pcap_assert.
#
# Runs INSIDE the client container. The TLS1.2-only server is started on the
# dpi-server with openssl s_server; starting it is delegated to the
# DPI_EXEC hook (e.g. "ssh root@172.30.0.10"). If DPI_EXEC is empty the
# command is run locally (valid when the suite itself runs on dpi-server).
#
# Env switches:
#   MODES        ncp modes (default: "tspu chain")
#   DPI_EXEC     remote executor for dpi-server commands, e.g.
#                DPI_EXEC="ssh -o StrictHostKeyChecking=no root@172.30.0.10"
#                (default: empty = run locally)
#   TLS12_PORT   openssl s_server port (default: 8443)
#   CERT/KEY     testbed cert paths on dpi-server
#                 (default: /srv/certs/cert.pem, /srv/certs/key.pem)
#   SERVER_IP / BLOCKED_SNI / PROXY_PORT / CAP_IFACE / LAB_DIR — as suite1
set -u
set -o pipefail

MODES=${MODES:-"tspu chain"}
DPI_EXEC=${DPI_EXEC:-}
TLS12_PORT=${TLS12_PORT:-8443}
CERT=${CERT:-/srv/certs/cert.pem}
KEY=${KEY:-/srv/certs/key.pem}
SERVER_IP=${SERVER_IP:-172.30.0.10}
BLOCKED_SNI=${BLOCKED_SNI:-forbidden.example}
PROXY_PORT=${PROXY_PORT:-1080}
PROXY_SPEC=${PROXY_SPEC:-socks5h://127.0.0.1:${PROXY_PORT}}
CAP_IFACE=${CAP_IFACE:-eth0}
LAB_DIR=${LAB_DIR:-/tmp/lab}
MARKER=${MARKER:-DYNAM-TESTBED-OK}
CHAIN_ARGS=${CHAIN_ARGS:---filter-tcp=443 --dpi-desync=multisplit --dpi-desync-split-pos=1,midsld --dpi-desync-fooling=badseq}
PCAP_ASSERT=${PCAP_ASSERT:-/lab/pcap_assert.py}

PCAP_DIR="${LAB_DIR}/pcaps"
mkdir -p "${LAB_DIR}" "${PCAP_DIR}"
LOG="${LAB_DIR}/suite3.log"
SUMMARY="${LAB_DIR}/suite3_summary.txt"
: > "${LOG}"
: > "${SUMMARY}"

log() { echo "[suite3 $(date +%H:%M:%S)] $*" | tee -a "${LOG}"; }

FAILURES=0
note_result() {  # note_result <case> <PASS|FAIL|SKIP> <detail>
    echo "$1: $2 — $3" | tee -a "${SUMMARY}"
    [ "$2" = "FAIL" ] && FAILURES=$((FAILURES + 1))
    return 0
}

on_dpi() {  # run a command on the dpi-server (or locally without DPI_EXEC)
    if [ -n "${DPI_EXEC}" ]; then
        # shellcheck disable=SC2086
        ${DPI_EXEC} "$@"
    else
        bash -c "$*"
    fi
}

# kill_wait <pid> <sig> <timeout-sec>: signal a child, wait for it to die,
# escalate to SIGKILL on timeout (defends against stuck tcpdump/ncp).
kill_wait() {
    local pid=$1 sig=$2 t=${3:-5} i state
    kill -0 "${pid}" 2>/dev/null || return 0
    kill -"${sig}" "${pid}" 2>/dev/null || true
    for i in $(seq 1 $((t * 10))); do
        [ -d "/proc/${pid}" ] || break
        state=$(awk '{print $3}' "/proc/${pid}/stat" 2>/dev/null)
        [ "${state}" = "Z" ] && break
        sleep 0.1
    done
    if [ -d "/proc/${pid}" ]; then
        state=$(awk '{print $3}' "/proc/${pid}/stat" 2>/dev/null)
        [ "${state}" != "Z" ] && kill -KILL "${pid}" 2>/dev/null || true
    fi
    wait "${pid}" 2>/dev/null || true
}

NCP_PID=""
start_proxy() {
    local mode=$1
    stop_proxy
    case "${mode}" in
        tspu)  ncp proxy --preset tspu --port "${PROXY_PORT}" & NCP_PID=$! ;;
        auto)  ncp proxy --preset auto --port "${PROXY_PORT}" & NCP_PID=$! ;;
        chain) ncp proxy --chain "${CHAIN_ARGS}" --port "${PROXY_PORT}" & NCP_PID=$! ;;
        direct) NCP_PID="" ;;
        *) log "unknown mode ${mode}"; return 1 ;;
    esac
    if [ -n "${NCP_PID}" ]; then
        local i
        for i in $(seq 1 50); do
            (exec 3<>"/dev/tcp/127.0.0.1/${PROXY_PORT}") 2>/dev/null && {
                exec 3>&- 3<&-; break; }
            sleep 0.1
        done
        log "proxy started: mode=${mode} pid=${NCP_PID}"
    fi
}

stop_proxy() {
    [ -n "${NCP_PID}" ] && kill_wait "${NCP_PID}" TERM 5
    NCP_PID=""
}

TCPDUMP_PID=""
start_capture() {
    tcpdump -i "${CAP_IFACE}" -n -s 0 -w "$1" \
        "host ${SERVER_IP}" >/dev/null 2>&1 &
    TCPDUMP_PID=$!
    sleep 0.5
}

stop_capture() {
    # SIGINT first: tcpdump flushes the pcap writer on SIGINT.
    [ -n "${TCPDUMP_PID}" ] && kill_wait "${TCPDUMP_PID}" INT 5
    TCPDUMP_PID=""
}

stop_tls12_server() {
    on_dpi "pkill -f 'openssl s_server.*-accept ${TLS12_PORT}'" \
        >>"${LOG}" 2>&1 || true
}

trap 'stop_capture; stop_proxy; stop_tls12_server' EXIT

# cell <mode> <cell-name> <url> <curl-extra...> ; pcap asserts via PCAP_CHECKS
run_cell() {  # run_cell <mode> <cell> <url> [curl args...]
    local mode=$1 cell=$2 url=$3
    shift 3
    local pcap="${PCAP_DIR}/suite3_${cell}_${mode}.pcap"
    local report="${LAB_DIR}/suite3_${cell}_${mode}.json"

    start_proxy "${mode}" || { note_result "${cell}/${mode}" FAIL "proxy"; return 1; }
    start_capture "${pcap}"
    local args=(-sS -k --max-time 30 -o /dev/null -w '%{http_code}')
    [ "${mode}" != "direct" ] && args+=(-x "${PROXY_SPEC}")
    args+=("$@")
    local code
    code=$(curl "${args[@]}" "${url}" 2>>"${LOG}" || echo "000")
    sleep 0.5
    stop_capture
    log "cell ${cell}/${mode}: http=${code} url=${url}"

    # Any HTTP status (even 4xx from openssl s_server -WWW) means the TLS
    # transport completed; only a hard curl failure (000) is a cell failure.
    if [ "${code}" = "000" ]; then
        note_result "${cell}/${mode}" FAIL "curl failed (http=${code})"
        stop_proxy; return 1
    fi
    # shellcheck disable=SC2086
    if python3 "${PCAP_ASSERT}" "${pcap}" ${PCAP_CHECKS} --pretty \
            > "${report}" 2>>"${LOG}"; then
        note_result "${cell}/${mode}" PASS "http=${code} (${report})"
    else
        note_result "${cell}/${mode}" FAIL "pcap_assert (${report})"
    fi
    stop_proxy
}

log "=== suite3 compat: modes='${MODES}' ==="

# --- TLS1.2-only -------------------------------------------------------------
log "starting TLS1.2-only openssl s_server on dpi-server:${TLS12_PORT}"
stop_tls12_server
on_dpi "nohup openssl s_server -tls1_2 -cert ${CERT} -key ${KEY} \
    -accept ${TLS12_PORT} -WWW >/tmp/s_server_tls12.log 2>&1 &" \
    >>"${LOG}" 2>&1 || log "WARNING: cannot start s_server via DPI_EXEC"
sleep 1
for mode in ${MODES}; do
    PCAP_CHECKS="--check tls-version --expect-tls-version 1.2"
    run_cell "${mode}" tls12 "https://${BLOCKED_SNI}:${TLS12_PORT}/"
done
stop_tls12_server

# --- TLS1.3 ------------------------------------------------------------------
for mode in ${MODES}; do
    PCAP_CHECKS="--check tls-version --expect-tls-version 1.3"
    run_cell "${mode}" tls13 "https://${BLOCKED_SNI}/"
done

# --- HTTP/1.1 ----------------------------------------------------------------
for mode in ${MODES}; do
    PCAP_CHECKS="--check seq-ack"
    run_cell "${mode}" http11 "http://${BLOCKED_SNI}/" --http1.1
done

# --- HTTP/2 ------------------------------------------------------------------
if curl --version | grep -q HTTP2; then
    for mode in ${MODES}; do
        PCAP_CHECKS="--check alpn --expect-alpn h2 --check http2 --expect-http2 present"
        run_cell "${mode}" http2 "https://${BLOCKED_SNI}/" --http2
    done
else
    log "SKIP http2: curl built without nghttp2"
    for mode in ${MODES}; do
        note_result "http2/${mode}" SKIP "curl without HTTP2 support"
    done
fi

# --- QUIC / HTTP3 (best effort) ----------------------------------------------
if curl --version | grep -q HTTP3; then
    for mode in ${MODES}; do
        PCAP_CHECKS="--check quic --expect-quic present"
        run_cell "${mode}" quic "https://${BLOCKED_SNI}/" --http3-only
    done
else
    log "SKIP http3 client; best-effort UDP/443 smoke with fake QUIC Initial"
    for mode in ${MODES}; do
        # Craft a minimal QUIC Initial-like long-header datagram and send it
        # directly to udp/443; verifies UDP/443 path and gives pcap evidence.
        local_pcap="${PCAP_DIR}/suite3_quic_${mode}.pcap"
        start_capture "${local_pcap}"
        python3 - "$SERVER_IP" <<'EOF' >>"${LOG}" 2>&1
import socket, sys, os
dst = sys.argv[1]
# QUIC long header: form=1, type=Initial(0), version 1, dcid/scid 8B each.
pkt = bytes([0xC3]) + (1).to_bytes(4, "big") \
      + bytes([8]) + os.urandom(8) + bytes([8]) + os.urandom(8) \
      + b"\x00" + os.urandom(1200)          # token len 0 + padding
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.sendto(pkt, (dst, 443))
print("sent fake QUIC Initial (%d bytes) to %s:443" % (len(pkt), dst))
EOF
        sleep 0.5
        stop_capture
        if python3 "${PCAP_ASSERT}" "${local_pcap}" --check quic --pretty \
                > "${LAB_DIR}/suite3_quic_${mode}.json" 2>>"${LOG}"; then
            :
        fi
        udp=$(python3 -c "import json;print(json.load(open('${LAB_DIR}/suite3_quic_${mode}.json'))['checks']['quic']['details']['udp443_datagrams'])" 2>/dev/null || echo 0)
        if [ "${udp}" != "0" ]; then
            note_result "quic/${mode}" SKIP "no h3 client; UDP/443 smoke ok (datagrams=${udp})"
        else
            note_result "quic/${mode}" FAIL "no h3 client; UDP/443 smoke found no datagrams"
        fi
    done
fi

log "=== suite3 done: failures=${FAILURES}, summary=${SUMMARY} ==="
exit $((FAILURES > 0 ? 1 : 0))
