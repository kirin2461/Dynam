#!/usr/bin/env bash
# zapret_blockcheck_evidence.sh — OPTIONAL availability evidence layer that
# wraps the ORIGINAL zapret blockcheck.sh (read-only checkout) inside a
# dedicated, wrapper-owned network namespace.
#
# This layer is strictly ADDITIONAL evidence. It never replaces Dynam's
# UDP/DPI tests (udp_dpi_gate.py, pcap_assert suites). It makes no claim of
# TSPU (or any DPI) invisibility; it only records what the upstream
# blockcheck tool observed inside an isolated lab namespace.
#
# Hard-fail by default: without explicit opt-in AND a dedicated isolated
# netns created/owned by this wrapper (or carrying its verifiable ownership
# marker), the script refuses to run (exit 2, verdict NOT-RUN). It never
# touches the host/VPS network namespace, host firewall (iptables/nft/
# ipfw/pf on the host), or any netns it did not create/own.
#
# Usage:
#   zapret_blockcheck_evidence.sh [--opt-in] [--self-test] [--netns NAME]
#
# Real (isolated) run — requires ALL of:
#   --opt-in                         (or DYNAM_ZAPRET_BLOCKCHECK_OPTIN=1)
#   root with CAP_SYS_ADMIN + CAP_NET_ADMIN
#   deps: iproute2, curl, iptables or nftables, realpath/readlink
#   zapret checkout with built binaries (nfqws/tpws/mdig)
#   The wrapper creates/owns netns "dynam-zapret-lab" (default) and runs the
#   original blockcheck.sh ONLY inside it via `ip netns exec`. It does NOT
#   set up NAT/veth or any host connectivity — if the lab ns has no uplink,
#   blockcheck simply reports UNAVAILABLE. Operators may pre-move a
#   dedicated lab interface into the owned ns; host firewall stays untouched.
#
# Self-test (mock) mode:
#   --self-test runs the full check/parse/cleanup pipeline against a mock
#   transcript. It NEVER invokes the real blockcheck, `ip netns`, or any
#   firewall command. Netns state is simulated via DYNAM_ZAPRET_ST_NS_STATE.
#
# Env:
#   ZAPRET_BLOCKCHECK              path to ORIGINAL blockcheck.sh
#                                  (default: /mnt/agents/work/zapret/blockcheck.sh)
#   DYNAM_ZAPRET_BLOCKCHECK_OPTIN  =1 required for any execution
#   DYNAM_ZAPRET_NETNS             netns name (default: dynam-zapret-lab;
#                                  must start with "dynam-zapret-")
#   DYNAM_ZAPRET_RUN_DIR           private state dir, chmod 700
#                                  (default: /run/dynam/zapret-blockcheck)
#   DYNAM_ZAPRET_REDACT            space-separated extra secrets to strip
#                                  from the sanitized log
#   LAB_DIR                        public results dir (default: /tmp/lab)
#   DYNAM_ZAPRET_ST_NS_STATE       self-test only:
#                                  missing|owned|foreign|production|create-fail
#   DYNAM_ZAPRET_MOCK_BLOCKCHECK   self-test only: executable mock that
#                                  prints a canned blockcheck transcript
#
# Outputs (LAB_DIR):
#   zapret_blockcheck_verdict.txt      verdict: PASS | FAIL | NOT-RUN + counts
#   zapret_blockcheck.sanitized.log    blockcheck output, IPs/secrets stripped
#   zapret_blockcheck_wrapper.log      wrapper operational log (no raw output)
# Raw blockcheck output lives only in RUN_DIR (mode 600) and is deleted by
# the cleanup trap together with the netns, in-ns nfqws/tpws/mdig processes
# and all in-ns firewall state (netns deletion destroys it atomically).
#
# Exit codes: 0 = PASS (blockcheck completed its SUMMARY inside the lab ns),
#             1 = FAIL (started but no complete SUMMARY),
#             2 = NOT-RUN (refusal or interruption; no evidence collected).
set -u
set -o pipefail

PROG=${0##*/}
ZAPRET_BLOCKCHECK_DEFAULT=/mnt/agents/work/zapret/blockcheck.sh
BLOCKCHECK_IN=${ZAPRET_BLOCKCHECK:-$ZAPRET_BLOCKCHECK_DEFAULT}
NS_PREFIX=dynam-zapret-
LAB_NS=${DYNAM_ZAPRET_NETNS:-dynam-zapret-lab}
LAB_DIR=${LAB_DIR:-/tmp/lab}
RUN_DIR=${DYNAM_ZAPRET_RUN_DIR:-/run/dynam/zapret-blockcheck}
OPT_IN=${DYNAM_ZAPRET_BLOCKCHECK_OPTIN:-0}
SELF_TEST=0
REDACT_TOKENS=${DYNAM_ZAPRET_REDACT:-}
ST_NS_STATE=${DYNAM_ZAPRET_ST_NS_STATE:-missing}
MOCK_BLOCKCHECK=${DYNAM_ZAPRET_MOCK_BLOCKCHECK:-}

VERDICT_FILE=${LAB_DIR}/zapret_blockcheck_verdict.txt
WLOG=${LAB_DIR}/zapret_blockcheck_wrapper.log
SLOG=${LAB_DIR}/zapret_blockcheck.sanitized.log
RAWLOG=${RUN_DIR}/blockcheck.raw.log
SEDSCRIPT=${RUN_DIR}/redact.sed
MARKER=${RUN_DIR}/${LAB_NS}.owned

BC_PID=
VERDICT_WRITTEN=0
NS_ACTIVE=0    # 1 = a wrapper-owned netns currently exists and must be torn down

EXIT_PASS=0
EXIT_FAIL=1
EXIT_NOTRUN=2

mkdir -p "${LAB_DIR}"
mkdir -p "${RUN_DIR}" && chmod 700 "${RUN_DIR}"

log() { echo "[zapret-evidence $(date +%H:%M:%S)] $*" | tee -a "${WLOG}"; }

usage() {
    sed -n '2,60p' "$0"
    exit ${EXIT_NOTRUN}
}

write_verdict() {  # write_verdict <PASS|FAIL|NOT-RUN> <reason>
    local verdict=$1 reason=$2 avail=0 unavail=0 summary=no
    if [ -f "${SLOG}" ]; then
        avail=$(grep -c '!!!!! AVAILABLE !!!!!' "${SLOG}" 2>/dev/null) || avail=0
        unavail=$(grep -c '^UNAVAILABLE' "${SLOG}" 2>/dev/null) || unavail=0
        grep -q '^\* SUMMARY$' "${SLOG}" 2>/dev/null && summary=yes
    fi
    {
        echo "verdict: ${verdict}"
        echo "reason: ${reason}"
        echo "summary_seen: ${summary}"
        echo "available_strategies: ${avail}"
        echo "unavailable_strategies: ${unavail}"
        echo "netns: ${LAB_NS}"
        echo "blockcheck: ${BLOCKCHECK_IN}"
        echo "scope: availability-evidence-only; NOT a replacement for Dynam UDP/DPI tests; no TSPU/DPI invisibility claim"
    } > "${VERDICT_FILE}"
    VERDICT_WRITTEN=1
    log "verdict: ${verdict} (${reason})"
}

die_notrun() {  # die_notrun <reason>
    log "NOT-RUN: $1"
    write_verdict NOT-RUN "$1"
    exit ${EXIT_NOTRUN}
}

# ---------------------------------------------------------------------------
# cleanup trap: kill blockcheck child, kill in-ns nfqws/tpws/mdig, delete the
# wrapper-owned netns (atomically destroys all in-ns firewall state), remove
# ownership marker, raw log and sed script. NEVER touches host firewall.
# ---------------------------------------------------------------------------
cleanup() {
    trap - EXIT INT TERM HUP
    log "cleanup: starting"
    if [ -n "${BC_PID}" ] && kill -0 "${BC_PID}" 2>/dev/null; then
        log "cleanup: terminating blockcheck child pid ${BC_PID}"
        kill "${BC_PID}" 2>/dev/null || true
    fi
    if [ "${SELF_TEST}" = 1 ]; then
        # Simulated teardown only: self-test never created a netns, never
        # started nfqws/tpws and never touched any firewall.
        log "cleanup: self-test — simulated netns/nfqws/tpws/firewall teardown (nothing real was created)"
        [ "${NS_ACTIVE}" = 1 ] && rm -f "${MARKER}"
    elif [ "${NS_ACTIVE}" = 1 ]; then
        # Kill leftover in-ns workers before removing the namespace.
        local pid comm
        for pid in $(ip netns pids "${LAB_NS}" 2>/dev/null); do
            comm=$(cat "/proc/${pid}/comm" 2>/dev/null || echo "")
            case "${comm}" in
                nfqws|tpws|mdig|dvtws|winws|curl)
                    log "cleanup: killing in-ns ${comm} (pid ${pid})"
                    kill "${pid}" 2>/dev/null || true
                    ;;
            esac
        done
        log "cleanup: deleting wrapper-owned netns ${LAB_NS} (drops ALL in-ns firewall state; host firewall untouched)"
        ip netns del "${LAB_NS}" 2>/dev/null || \
            log "cleanup: WARNING: ip netns del ${LAB_NS} failed"
        rm -f "${MARKER}"
    fi
    rm -f "${RAWLOG}" "${SEDSCRIPT}"
    if [ "${VERDICT_WRITTEN}" != 1 ]; then
        write_verdict NOT-RUN "interrupted before completion"
    fi
    log "cleanup: done"
}

on_signal() {  # on_signal <SIGNAME>
    log "received SIG$1 — aborting, evidence NOT-RUN"
    exit ${EXIT_NOTRUN}
}

# ---------------------------------------------------------------------------
# argument parsing
# ---------------------------------------------------------------------------
while [ $# -gt 0 ]; do
    case "$1" in
        --opt-in)    OPT_IN=1 ;;
        --self-test) SELF_TEST=1 ;;
        --netns)
            [ $# -ge 2 ] || { echo "${PROG}: --netns needs a value" >&2; exit ${EXIT_NOTRUN}; }
            LAB_NS=$2
            MARKER=${RUN_DIR}/${LAB_NS}.owned
            shift
            ;;
        --help|-h)   usage ;;
        *) echo "${PROG}: unknown argument: $1" >&2; usage ;;
    esac
    shift
done

trap cleanup EXIT
trap 'on_signal INT'  INT
trap 'on_signal TERM' TERM
trap 'on_signal HUP'  HUP

log "starting (mode=$([ "${SELF_TEST}" = 1 ] && echo self-test || echo real))"

# ---------------------------------------------------------------------------
# gate 1: explicit opt-in (required in BOTH modes — defense in depth)
# ---------------------------------------------------------------------------
case "${OPT_IN}" in
    1|true|yes) ;;
    *) die_notrun "missing explicit opt-in: re-run with --opt-in or DYNAM_ZAPRET_BLOCKCHECK_OPTIN=1" ;;
esac

# ---------------------------------------------------------------------------
# gate 2: dedicated lab namespace name (refuse production-looking names)
# ---------------------------------------------------------------------------
case "${LAB_NS}" in
    "${NS_PREFIX}"*[!a-z0-9-]*|"${NS_PREFIX}"|"")
        die_notrun "netns name '${LAB_NS}' must match ${NS_PREFIX}<a-z0-9-> (dedicated lab namespace)" ;;
    "${NS_PREFIX}"*) ;;
    *) die_notrun "netns name '${LAB_NS}' refused: must start with '${NS_PREFIX}' (dedicated lab namespace)" ;;
esac

# ---------------------------------------------------------------------------
# gate 3: blockcheck path safety (applies to BOTH modes so the WOULD-RUN
# line in self-test always reflects the validated real target)
# ---------------------------------------------------------------------------
resolve_path() {  # resolve_path <path> -> prints canonical path or fails
    if command -v realpath >/dev/null 2>&1; then
        realpath "$1" 2>/dev/null
    else
        (cd "$(dirname "$1")" 2>/dev/null && printf '%s/%s\n' "$(pwd -P)" "$(basename "$1")")
    fi
}

BLOCKCHECK_RESOLVED=$(resolve_path "${BLOCKCHECK_IN}")
[ -n "${BLOCKCHECK_RESOLVED}" ] && [ -f "${BLOCKCHECK_RESOLVED}" ] || \
    die_notrun "blockcheck path '${BLOCKCHECK_IN}' does not resolve to a regular file"
[ -r "${BLOCKCHECK_RESOLVED}" ] || \
    die_notrun "blockcheck path '${BLOCKCHECK_RESOLVED}' is not readable"
[ "$(basename "${BLOCKCHECK_RESOLVED}")" = "blockcheck.sh" ] || \
    die_notrun "path '${BLOCKCHECK_RESOLVED}' refused: basename must be blockcheck.sh (original zapret script)"
if [ -n "$(find "${BLOCKCHECK_RESOLVED}" -perm -0002 -print -quit 2>/dev/null)" ]; then
    die_notrun "path '${BLOCKCHECK_RESOLVED}' refused: world-writable target"
fi
log "blockcheck path validated: ${BLOCKCHECK_RESOLVED}"

# The exact command a real run executes INSIDE the lab netns (never host).
REAL_CMD=(ip netns exec "${LAB_NS}" env BATCH=1 "${BLOCKCHECK_RESOLVED}")
log "WOULD-RUN(in-netns-only): ${REAL_CMD[*]}"

# ---------------------------------------------------------------------------
# gate 4: isolation — dedicated netns created/owned by this wrapper (or with
# a verifiable ownership marker), demonstrably distinct from the production
# (pid 1) namespace. Self-test simulates the same state machine.
# ---------------------------------------------------------------------------
ns_setup_real() {
    [ "$(id -u)" = 0 ] || die_notrun "must run as root (CAP_SYS_ADMIN + CAP_NET_ADMIN required)"
    command -v ip >/dev/null 2>&1    || die_notrun "missing dependency: ip (iproute2)"
    command -v curl >/dev/null 2>&1  || die_notrun "missing dependency: curl (required by blockcheck)"
    if ! command -v iptables >/dev/null 2>&1 && ! command -v nft >/dev/null 2>&1; then
        die_notrun "missing dependency: iptables or nftables (required by blockcheck nfqws tests)"
    fi
    command -v sed >/dev/null 2>&1   || die_notrun "missing dependency: sed"
    command -v grep >/dev/null 2>&1  || die_notrun "missing dependency: grep"

    local inode
    if ip netns list 2>/dev/null | awk '{print $1}' | grep -qx "${LAB_NS}"; then
        # Namespace exists: adopt ONLY with a valid ownership marker.
        [ -f "${MARKER}" ] || die_notrun \
            "netns '${LAB_NS}' exists without a wrapper ownership marker — refusing to touch a foreign/production namespace"
        inode=$(ip netns exec "${LAB_NS}" readlink /proc/self/ns/net 2>/dev/null) || \
            die_notrun "cannot inspect netns '${LAB_NS}'"
        grep -qx "inode=${inode}" "${MARKER}" 2>/dev/null || die_notrun \
            "ownership marker for '${LAB_NS}' does not match the live netns inode — refusing"
        NS_ACTIVE=1
        log "adopted wrapper-owned netns '${LAB_NS}' (marker verified, inode ${inode})"
    else
        ip netns add "${LAB_NS}" 2>/dev/null || die_notrun \
            "cannot create netns '${LAB_NS}' (CAP_SYS_ADMIN/CAP_NET_ADMIN absent?)"
        NS_ACTIVE=1
        ip netns exec "${LAB_NS}" ip link set lo up 2>/dev/null || \
            die_notrun "cannot bring up loopback inside netns '${LAB_NS}'"
        inode=$(ip netns exec "${LAB_NS}" readlink /proc/self/ns/net 2>/dev/null) || \
            die_notrun "cannot inspect new netns '${LAB_NS}'"
        { echo "inode=${inode}"; echo "created_by=${PROG}"; } > "${MARKER}"
        chmod 600 "${MARKER}"
        log "created isolated lab netns '${LAB_NS}' (inode ${inode})"
    fi

    # Refuse if the lab namespace is not distinct from the production one.
    local init_inode
    init_inode=$(readlink /proc/1/ns/net 2>/dev/null) || init_inode=
    if [ -n "${init_inode}" ] && [ "${init_inode}" = "${inode}" ]; then
        die_notrun "netns '${LAB_NS}' IS the production (pid 1) network namespace — refusing"
    fi
    if [ "$(ip netns identify 1 2>/dev/null)" = "${LAB_NS}" ]; then
        die_notrun "pid 1 lives inside '${LAB_NS}' — that makes it the production namespace, refusing"
    fi
    log "isolation verified: '${LAB_NS}' is a dedicated lab netns, distinct from pid 1"
}

ns_setup_self_test() {
    case "${ST_NS_STATE}" in
        production)
            die_notrun "netns '${LAB_NS}' would BE the production namespace (simulated) — refusing" ;;
        foreign)
            die_notrun "netns '${LAB_NS}' exists without a wrapper ownership marker (simulated) — refusing" ;;
        create-fail)
            die_notrun "cannot create netns '${LAB_NS}': CAP_SYS_ADMIN/CAP_NET_ADMIN absent (simulated)" ;;
        owned)
            [ -f "${MARKER}" ] || die_notrun \
                "ownership marker for '${LAB_NS}' missing (simulated adopt) — refusing"
            NS_ACTIVE=1
            log "self-test: adopted simulated wrapper-owned netns '${LAB_NS}'" ;;
        missing)
            { echo "inode=net:[0]"; echo "created_by=${PROG} (self-test)"; } > "${MARKER}"
            chmod 600 "${MARKER}"
            NS_ACTIVE=1
            log "self-test: simulated creation of isolated lab netns '${LAB_NS}'" ;;
        *)
            die_notrun "unknown DYNAM_ZAPRET_ST_NS_STATE='${ST_NS_STATE}'" ;;
    esac
    log "self-test: isolation state machine verified (state=${ST_NS_STATE})"
}

if [ "${SELF_TEST}" = 1 ]; then
    ns_setup_self_test
else
    ns_setup_real
fi

# ---------------------------------------------------------------------------
# log sanitization: strip IPv4/IPv6 addresses and operator-supplied secrets
# ---------------------------------------------------------------------------
build_sed_script() {
    : > "${SEDSCRIPT}"
    chmod 600 "${SEDSCRIPT}"
    {
        echo 's/([0-9]{1,3}\.){3}[0-9]{1,3}/<redacted-ip>/g'
        echo 's/([0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(%[A-Za-z0-9_.-]+)?/<redacted-ip6>/g'
    } >> "${SEDSCRIPT}"
    local tok esc
    for tok in ${REDACT_TOKENS}; do
        esc=$(printf '%s' "${tok}" | sed 's/[][\.*^$/]/\\&/g')
        [ -n "${esc}" ] && echo "s/${esc}/<redacted-secret>/g" >> "${SEDSCRIPT}"
    done
}

sanitize_log() {  # sanitize_log <raw> <sanitized>
    build_sed_script
    sed -E -f "${SEDSCRIPT}" "$1" > "$2"
    rm -f "${SEDSCRIPT}"
}

# ---------------------------------------------------------------------------
# execution: real run happens ONLY inside the owned netns via ip netns exec;
# self-test runs a mock transcript and never touches netns/firewall.
# ---------------------------------------------------------------------------
CANNED_TRANSCRIPT='* blockcheck (mock) starting
http rutracker.org: connecting via 198.51.100.7
https tls1.2 rutracker.org --dpi-desync=fake
!!!!! AVAILABLE !!!!!
https tls1.3 rutracker.org --dpi-desync=multisplit
UNAVAILABLE code=1
* SUMMARY
mock summary: 1 available, 1 unavailable'

run_blockcheck() {
    : > "${RAWLOG}"
    chmod 600 "${RAWLOG}"
    if [ "${SELF_TEST}" = 1 ]; then
        # Mock path: NEVER invokes the real blockcheck, ip netns, or firewall.
        if [ -n "${MOCK_BLOCKCHECK}" ]; then
            [ -x "${MOCK_BLOCKCHECK}" ] || die_notrun "mock '${MOCK_BLOCKCHECK}' is not executable"
            log "self-test: running mock transcript from ${MOCK_BLOCKCHECK}"
            "${MOCK_BLOCKCHECK}" > "${RAWLOG}" 2>&1 &
        else
            log "self-test: using built-in canned transcript"
            printf '%s\n' "${CANNED_TRANSCRIPT}" > "${RAWLOG}" &
        fi
    else
        log "executing original blockcheck inside netns '${LAB_NS}': ${REAL_CMD[*]}"
        "${REAL_CMD[@]}" > "${RAWLOG}" 2>&1 &
    fi
    BC_PID=$!
    # `wait` keeps signal traps responsive; cleanup kills BC_PID on abort.
    wait "${BC_PID}" 2>/dev/null
    local rc=$?
    BC_PID=
    return ${rc}
}

run_blockcheck
BC_RC=$?
log "blockcheck run finished (exit ${BC_RC})"

sanitize_log "${RAWLOG}" "${SLOG}"
log "sanitized evidence log: ${SLOG}"

if grep -q '^\* SUMMARY$' "${SLOG}" 2>/dev/null; then
    write_verdict PASS "blockcheck completed its SUMMARY inside isolated netns '${LAB_NS}'"
    exit ${EXIT_PASS}
fi
write_verdict FAIL "blockcheck ran but produced no complete SUMMARY (exit ${BC_RC})"
exit ${EXIT_FAIL}
