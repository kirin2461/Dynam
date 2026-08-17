#!/usr/bin/env bash
# suite2_dpi_models.sh — Suite 2: bypass success-rate matrix (mode x DPI model).
#
# For every DPI model x ncp mode cell we run N_RUNS requests to the blocked
# domain and measure the bypass success rate with metrics.py. A control run
# to the allowed domain must always succeed (sanity that DPI!=broken).
#
# Runs INSIDE the client container. The DPI model itself lives on the
# dpi-server; switching it is delegated to the DPI_SWITCH_CMD hook (the
# integrator sets it, e.g. an ssh command restarting dpi-emu with the given
# env). If DPI_SWITCH_CMD is empty the script assumes the model is switched
# externally between runs and only labels the results with DPI_MODEL.
#
# Env switches:
#   DPI_MODELS    models to iterate (default: "string reassemble:4096:strict
#                 reassemble:16384:permissive-first reassemble:16384:permissive-last")
#                 format: <model>[:<buffer_limit>:<ooo_policy>]
#   DPI_SWITCH_CMD  command template run as: eval with DPI_MODEL,
#                 BUFFER_LIMIT, OOO_POLICY exported (default: empty)
#   MODES         ncp modes (default: "direct tspu chain auto")
#   N_RUNS        repetitions per cell (default: 10)
#   IMPAIRMENT    label of the current impairment profile (default: clean)
#   BLOCKED_SNI / ALLOWED_SNI / SERVER_IP / PROXY_PORT / LAB_DIR — as suite1
set -u
set -o pipefail

DPI_MODELS=${DPI_MODELS:-"string reassemble:4096:strict reassemble:16384:permissive-first reassemble:16384:permissive-last"}
DPI_SWITCH_CMD=${DPI_SWITCH_CMD:-}
MODES=${MODES:-"direct tspu chain auto"}
N_RUNS=${N_RUNS:-10}
IMPAIRMENT=${IMPAIRMENT:-clean}
SERVER_IP=${SERVER_IP:-172.30.0.10}
BLOCKED_SNI=${BLOCKED_SNI:-forbidden.example}
ALLOWED_SNI=${ALLOWED_SNI:-allowed.example}
PROXY_PORT=${PROXY_PORT:-1080}
PROXY_SPEC=${PROXY_SPEC:-socks5h://127.0.0.1:${PROXY_PORT}}
LAB_DIR=${LAB_DIR:-/tmp/lab}
MARKER=${MARKER:-DYNAM-TESTBED-OK}
CHAIN_ARGS=${CHAIN_ARGS:---filter-tcp=443 --dpi-desync=multisplit --dpi-desync-split-pos=1,midsld --dpi-desync-fooling=badseq}
METRICS=${METRICS:-/lab/metrics.py}

mkdir -p "${LAB_DIR}/suite2"
LOG="${LAB_DIR}/suite2.log"
SUMMARY_MD="${LAB_DIR}/suite2_report.md"
SUMMARY_TXT="${LAB_DIR}/suite2_summary.txt"
: > "${LOG}"
: > "${SUMMARY_TXT}"

log() { echo "[suite2 $(date +%H:%M:%S)] $*" | tee -a "${LOG}"; }

# kill_wait <pid> <sig> <timeout-sec>: signal a child, wait for it to die,
# escalate to SIGKILL on timeout.
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

trap 'stop_proxy' EXIT

switch_dpi_model() {  # switch_dpi_model <model> <buffer_limit> <ooo_policy>
    export DPI_MODEL=$1 BUFFER_LIMIT=$2 OOO_POLICY=$3
    if [ -n "${DPI_SWITCH_CMD}" ]; then
        log "switching DPI model: ${DPI_MODEL} limit=${BUFFER_LIMIT} ooo=${OOO_POLICY}"
        if ! eval "${DPI_SWITCH_CMD}" >>"${LOG}" 2>&1; then
            log "ERROR: DPI_SWITCH_CMD failed for ${DPI_MODEL}"
            return 1
        fi
        sleep 2  # let the DPI come up / flush state
    else
        log "DPI_SWITCH_CMD unset — assuming model '${DPI_MODEL}' already active"
    fi
}

run_cell() {  # run_cell <model_label> <mode>
    local label=$1 mode=$2
    start_proxy "${mode}" || return 1

    # Control: the allowed domain must succeed regardless of the model.
    local ctl_args=(-sS -k --max-time 30 -o /dev/null -w '%{http_code}')
    local ctl_proxy=()
    [ "${mode}" != "direct" ] && ctl_proxy=(-x "${PROXY_SPEC}")
    local ctl_code
    ctl_code=$(curl "${ctl_args[@]}" "${ctl_proxy[@]}" \
        "https://${ALLOWED_SNI}/" 2>>"${LOG}" || echo "000")
    log "control allowed.example: http=${ctl_code}"
    if [ "${ctl_code}" != "200" ]; then
        log "WARNING: control request failed (http=${ctl_code}) — results suspect"
    fi

    local case_name="suite2_${label}_${mode}_${IMPAIRMENT}"
    local json_out="${LAB_DIR}/suite2/${case_name}.json"
    local margs=(--name "${case_name}"
                 --url "https://${BLOCKED_SNI}/"
                 --runs "${N_RUNS}"
                 --insecure
                 --expect-marker "${MARKER}"
                 --json "${json_out}" --md "${json_out%.json}.md")
    if [ "${mode}" != "direct" ]; then
        margs+=(--proxy "${PROXY_SPEC}")
    fi
    python3 "${METRICS}" run "${margs[@]}" >>"${LOG}" 2>&1
    # metrics.py exits 1 when nothing succeeded — that is a VALID result
    # for a blocked cell, so do not treat it as a script failure.
    local rate
    rate=$(python3 -c "import json;print(json.load(open('${json_out}'))['aggregate']['success_rate'])" 2>/dev/null || echo "?")
    log "cell ${label}/${mode}: bypass success_rate=${rate} (${json_out})"
    echo "${label} | ${mode} | ${IMPAIRMENT} | success_rate=${rate} | control_http=${ctl_code}" >> "${SUMMARY_TXT}"
    stop_proxy
}

log "=== suite2 dpi models: models='${DPI_MODELS}' modes='${MODES}' impairment=${IMPAIRMENT} ==="

for spec in ${DPI_MODELS}; do
    # spec = <model>[:<buffer_limit>[:<ooo_policy>]]
    model=""; limit=""; ooo=""
    IFS=':' read -r model limit ooo <<<"${spec}"
    [ -z "${limit}" ] && limit=16384
    [ -z "${ooo}" ] && ooo=strict
    label="${model}_${limit}_${ooo}"
    if [ "${model}" = "string" ]; then label="string"; fi

    switch_dpi_model "${model}" "${limit}" "${ooo}" || continue
    for mode in ${MODES}; do
        run_cell "${label}" "${mode}"
    done
done

# Combined markdown table over all cells.
JSONS=$(ls "${LAB_DIR}"/suite2/*.json 2>/dev/null || true)
if [ -n "${JSONS}" ]; then
    # shellcheck disable=SC2086
    python3 "${METRICS}" aggregate ${JSONS} --md "${SUMMARY_MD}" >>"${LOG}" 2>&1 \
        && log "combined table: ${SUMMARY_MD}"
fi

log "=== suite2 done: summary=${SUMMARY_TXT} ==="
exit 0
