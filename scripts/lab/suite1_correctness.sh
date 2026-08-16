#!/usr/bin/env bash
# suite1_correctness.sh — Suite 1: correctness of desync packet formation.
#
# DPI is OFF (allow-all). For each ncp mode we start the proxy, capture the
# traffic of a blocked-domain request and verify with pcap_assert that the
# ClientHello is formed as expected (segmentation, sequence space, TLS
# version). This suite validates *formation*, not bypass.
#
# Runs INSIDE the client container (172.30.0.20). Requires: ncp, curl,
# tcpdump, python3 + /lab/pcap_assert.py (mounted lab tools).
#
# Env switches:
#   MODES        modes to test        (default: "tspu chain auto")
#   N_RUNS       curl runs per mode   (default: 1 — one capture is enough)
#   CLIENT_IP    this host            (default: 172.30.0.20)
#   SERVER_IP    dpi-server           (default: 172.30.0.10)
#   BLOCKED_SNI  blocked test domain  (default: forbidden.example)
#   ALLOWED_SNI  control domain       (default: allowed.example)
#   PROXY_PORT   ncp socks port       (default: 1080)
#   CAP_IFACE    capture interface    (default: eth0; client-side capture
#                shows the exact wire image the DPI receives in 2-node)
#   LAB_DIR      results dir          (default: /tmp/lab)
#   CHAIN_ARGS   inline chain string for mode "chain"
set -u
set -o pipefail

MODES=${MODES:-"tspu chain auto"}
N_RUNS=${N_RUNS:-1}
CLIENT_IP=${CLIENT_IP:-172.30.0.20}
SERVER_IP=${SERVER_IP:-172.30.0.10}
BLOCKED_SNI=${BLOCKED_SNI:-forbidden.example}
ALLOWED_SNI=${ALLOWED_SNI:-allowed.example}
PROXY_PORT=${PROXY_PORT:-1080}
PROXY_SPEC=${PROXY_SPEC:-socks5h://127.0.0.1:${PROXY_PORT}}
CAP_IFACE=${CAP_IFACE:-eth0}
LAB_DIR=${LAB_DIR:-/tmp/lab}
MARKER=${MARKER:-DYNAM-TESTBED-OK}
CHAIN_ARGS=${CHAIN_ARGS:---filter-tcp=443 --dpi-desync=multisplit --dpi-desync-split-pos=1,midsld --dpi-desync-fooling=badseq}
PCAP_ASSERT=${PCAP_ASSERT:-/lab/pcap_assert.py}

PCAP_DIR=${LAB_DIR}/pcaps
SUMMARY=${LAB_DIR}/suite1_summary.txt
mkdir -p "${LAB_DIR}" "${PCAP_DIR}"
: > "${SUMMARY}"

log() { echo "[suite1 $(date +%H:%M:%S)] $*" | tee -a "${LAB_DIR}/suite1.log"; }

FAILURES=0
note_result() {  # note_result <case> <PASS|FAIL|SKIP> <detail>
    echo "$1: $2 — $3" | tee -a "${SUMMARY}"
    [ "$2" = "FAIL" ] && FAILURES=$((FAILURES + 1))
    return 0
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
start_proxy() {  # start_proxy <mode>
    local mode=$1
    stop_proxy
    case "${mode}" in
        tspu)  ncp proxy --preset tspu --port "${PROXY_PORT}" &
               NCP_PID=$! ;;
        auto)  ncp proxy --preset auto --port "${PROXY_PORT}" &
               NCP_PID=$! ;;
        chain) ncp proxy --chain "${CHAIN_ARGS}" --port "${PROXY_PORT}" &
               NCP_PID=$! ;;
        direct) NCP_PID="" ;;
        *) log "unknown mode ${mode}"; return 1 ;;
    esac
    if [ -n "${NCP_PID}" ]; then
        # Wait for the listener to come up.
        local i
        for i in $(seq 1 50); do
            (exec 3<>"/dev/tcp/127.0.0.1/${PROXY_PORT}") 2>/dev/null && {
                exec 3>&- 3<&-; break; }
            sleep 0.1
        done
        log "proxy started: mode=${mode} pid=${NCP_PID} port=${PROXY_PORT}"
    fi
}

stop_proxy() {
    [ -n "${NCP_PID}" ] && kill_wait "${NCP_PID}" TERM 5
    NCP_PID=""
}

TCPDUMP_PID=""
start_capture() {  # start_capture <pcap-path>
    tcpdump -i "${CAP_IFACE}" -n -s 0 -w "$1" \
        "host ${SERVER_IP} and (tcp port 443 or tcp port 80 or udp port 443)" \
        >/dev/null 2>&1 &
    TCPDUMP_PID=$!
    sleep 0.5  # let tcpdump attach before traffic starts
}

stop_capture() {
    # SIGINT first: tcpdump flushes the pcap writer on SIGINT.
    [ -n "${TCPDUMP_PID}" ] && kill_wait "${TCPDUMP_PID}" INT 5
    TCPDUMP_PID=""
}

trap 'stop_capture; stop_proxy' EXIT

log "=== suite1 correctness: modes='${MODES}' dpi=ALLOW-ALL ==="

for mode in ${MODES}; do
    log "--- mode=${mode} ---"
    start_proxy "${mode}" || { note_result "${mode}" FAIL "proxy start"; continue; }

    PCAP="${PCAP_DIR}/suite1_${mode}.pcap"
    start_capture "${PCAP}"

    # Drive one request to the blocked domain (and a control request).
    CURL_ARGS=(-sS -k --max-time 30 -o /dev/null -w '%{http_code}')
    if [ "${mode}" != "direct" ]; then
        CURL_ARGS+=(-x "${PROXY_SPEC}")
    fi
    CODE_BLOCKED=$(curl "${CURL_ARGS[@]}" "https://${BLOCKED_SNI}/" 2>>"${LAB_DIR}/suite1.log" || echo "000")
    CODE_ALLOWED=$(curl "${CURL_ARGS[@]}" "https://${ALLOWED_SNI}/" 2>>"${LAB_DIR}/suite1.log" || echo "000")
    sleep 0.5
    stop_capture
    log "curl: blocked=${CODE_BLOCKED} allowed=${CODE_ALLOWED} pcap=${PCAP}"

    REPORT="${LAB_DIR}/suite1_${mode}.json"
    # split-positions: tspu/chain must split the SNI; auto — report only.
    SPLIT_ASSERTS=(--check split-positions --check seq-ack --check tls-version
                   --expect-tls-version 1.3)
    case "${mode}" in
        tspu|chain)
            SPLIT_ASSERTS+=(--expect-sni-split --expect-no-sni-single-frame) ;;
    esac
    if python3 "${PCAP_ASSERT}" "${PCAP}" "${SPLIT_ASSERTS[@]}" \
            --client "${CLIENT_IP}" --server "${SERVER_IP}" \
            --pretty > "${REPORT}" 2>>"${LAB_DIR}/suite1.log"; then
        note_result "${mode}" PASS "pcap_assert ok (report ${REPORT})"
    else
        note_result "${mode}" FAIL "pcap_assert failed (report ${REPORT})"
    fi
    stop_proxy
done

log "=== suite1 done: failures=${FAILURES}, summary=${SUMMARY} ==="
exit $((FAILURES > 0 ? 1 : 0))
