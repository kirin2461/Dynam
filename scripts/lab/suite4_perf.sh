#!/usr/bin/env bash
# suite4_perf.sh — Suite 4: performance per ncp mode.
#
# N_RUNS downloads of each test file per mode; metrics.py aggregates
# handshake/TTFB/total medians+p95, download speed, retransmits and the ncp
# process CPU (per-core busy% over the window + ncp_cpu_percent_total).
#
# NOTE (documented lab limitation): perf runs go against the kernel-level
# `string` DPI model or no DPI at all — the python/NFQUEUE `reassemble`
# model is a functional model, not load-capable.
#
# Runs INSIDE the client container.
#
# Env switches:
#   MODES      ncp modes (default: "direct tspu auto")
#   SIZES      test file paths on the server (default: "/5mb.bin /50mb.bin")
#   N_RUNS     repetitions per cell (default: 20)
#   IMPAIRMENT label of the current impairment profile (default: clean;
#              apply profiles with impairment.sh before running: suite4 is
#              intended for clean + wan)
#   CAPTURE    set to 1 to also capture pcaps per cell (default: 0)
#   SERVER_IP / BLOCKED_SNI / PROXY_PORT / LAB_DIR — as suite1
set -u
set -o pipefail

MODES=${MODES:-"direct tspu auto"}
SIZES=${SIZES:-"/5mb.bin /50mb.bin"}
N_RUNS=${N_RUNS:-20}
IMPAIRMENT=${IMPAIRMENT:-clean}
CAPTURE=${CAPTURE:-0}
SERVER_IP=${SERVER_IP:-172.30.0.10}
BLOCKED_SNI=${BLOCKED_SNI:-forbidden.example}
PROXY_PORT=${PROXY_PORT:-1080}
PROXY_SPEC=${PROXY_SPEC:-socks5h://127.0.0.1:${PROXY_PORT}}
CAP_IFACE=${CAP_IFACE:-eth0}
LAB_DIR=${LAB_DIR:-/tmp/lab}
MARKER=${MARKER:-DYNAM-TESTBED-OK}
CHAIN_ARGS=${CHAIN_ARGS:---filter-tcp=443 --dpi-desync=multisplit --dpi-desync-split-pos=1,midsld --dpi-desync-fooling=badseq}
METRICS=${METRICS:-/lab/metrics.py}

mkdir -p "${LAB_DIR}/suite4" "${LAB_DIR}/pcaps"
LOG="${LAB_DIR}/suite4.log"
: > "${LOG}"

log() { echo "[suite4 $(date +%H:%M:%S)] $*" | tee -a "${LOG}"; }

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
        "host ${SERVER_IP} and tcp port 443" >/dev/null 2>&1 &
    TCPDUMP_PID=$!
    sleep 0.5
}

stop_capture() {
    # SIGINT first: tcpdump flushes the pcap writer on SIGINT.
    [ -n "${TCPDUMP_PID}" ] && kill_wait "${TCPDUMP_PID}" INT 5
    TCPDUMP_PID=""
}

trap 'stop_capture; stop_proxy' EXIT

log "=== suite4 perf: modes='${MODES}' sizes='${SIZES}' n=${N_RUNS} impairment=${IMPAIRMENT} ==="

JSONS=""
for mode in ${MODES}; do
    start_proxy "${mode}" || continue
    for size in ${SIZES}; do
        size_label=$(basename "${size}" | tr -cd 'a-zA-Z0-9')
        case_name="suite4_${mode}_${size_label}_${IMPAIRMENT}"
        json_out="${LAB_DIR}/suite4/${case_name}.json"
        pcap="${LAB_DIR}/pcaps/${case_name}.pcap"

        margs=(--name "${case_name}"
               --url "https://${BLOCKED_SNI}${size}"
               --runs "${N_RUNS}"
               --insecure
               --expect-marker "${MARKER}"
               --timeout 300
               --json "${json_out}" --md "${json_out%.json}.md")
        if [ "${mode}" != "direct" ]; then
            margs+=(--proxy "${PROXY_SPEC}")
        fi
        if [ -n "${NCP_PID}" ]; then
            margs+=(--pid "${NCP_PID}")
        fi
        if [ "${CAPTURE}" = "1" ]; then
            start_capture "${pcap}"
            margs+=(--pcap "${pcap}")
        fi

        log "running ${case_name} ..."
        # Exit 1 (zero successes) is a legitimate measurement outcome.
        python3 "${METRICS}" run "${margs[@]}" >>"${LOG}" 2>&1 || true
        [ "${CAPTURE}" = "1" ] && stop_capture
        JSONS="${JSONS} ${json_out}"
        log "done ${case_name} -> ${json_out}"
    done
    stop_proxy
done

# Combined report across all cells.
if [ -n "${JSONS}" ]; then
    # shellcheck disable=SC2086
    python3 "${METRICS}" aggregate ${JSONS} \
        --md "${LAB_DIR}/suite4_report.md" >>"${LOG}" 2>&1 \
        && log "combined table: ${LAB_DIR}/suite4_report.md"
fi

log "=== suite4 done ==="
exit 0
