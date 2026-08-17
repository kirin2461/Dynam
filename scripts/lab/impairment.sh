#!/usr/bin/env bash
# impairment.sh — network impairment profiles for the Dynam DPI lab.
#
# Applies/removes tc-netem qdiscs and MTU/MSS clamps on the client
# container interface (default eth0). Must run as root (NET_ADMIN).
#
# Usage:
#   impairment.sh <profile> [iface]
#   impairment.sh status [iface]
#
# Profiles:
#   clean     remove all impairments (netem off, MTU back to 1500,
#             MSS clamp removed)
#   delay50   netem delay 50ms
#   wan       netem delay 100ms +-20ms, loss 1%
#   loss5     netem loss 5%
#   reorder   netem delay 10ms with 25% reordering (50% correlation)
#   mtu1400   MTU 1400 + TCPMSS clamp to 1360
#   mtu576    MTU 576  + TCPMSS clamp to 536
#
# Env:
#   IFACE     default interface (default: eth0; CLI arg overrides)
#   BASE_MTU  MTU restored by "clean" (default: 1500)
#   LAB_DIR   log dir (default: /tmp/lab)
#
# Notes:
#   - IPv6 is out of scope here (handled by a separate compose override
#     with enable_ipv6 + fd00:30::/64); impairment profiles are v4-only.
#   - Suite 2 must run at least under clean/delay50/reorder/loss5;
#     suite 4 under clean + wan (driven by the integrator loop).
set -u

PROFILE=${1:-}
IFACE=${2:-${IFACE:-eth0}}
BASE_MTU=${BASE_MTU:-1500}
LAB_DIR=${LAB_DIR:-/tmp/lab}
mkdir -p "${LAB_DIR}"
LOG="${LAB_DIR}/impairment.log"

log() { echo "[impairment $(date +%H:%M:%S)] $*" | tee -a "${LOG}"; }

usage() {
    sed -n '2,30p' "$0"
    exit 2
}

[ -z "${PROFILE}" ] && usage

if [ "$(id -u)" != "0" ]; then
    log "ERROR: must run as root (NET_ADMIN required)"
    exit 2
fi
if ! command -v tc >/dev/null 2>&1; then
    log "ERROR: tc not found (install iproute2)"
    exit 2
fi

netem_off() {
    tc qdisc del dev "${IFACE}" root 2>/dev/null || true
}

mss_clamp_off() {
    # Remove any TCPMSS clamp rule we installed on this interface
    # (delete may fail if absent — fine; loop guards against duplicates).
    local rule spec
    while rule=$(iptables -t mangle -S POSTROUTING 2>/dev/null | \
            grep "TCPMSS" | grep -- "-o ${IFACE} " | head -1); do
        [ -n "${rule}" ] || break
        spec=${rule#-A POSTROUTING }
        # shellcheck disable=SC2086
        iptables -t mangle -D POSTROUTING ${spec} 2>/dev/null || break
    done
}

mss_clamp_on() {  # mss_clamp_on <mss>
    mss_clamp_off
    iptables -t mangle -A POSTROUTING -o "${IFACE}" -p tcp \
        --tcp-flags SYN,RST SYN -j TCPMSS --set-mss "$1"
}

apply_netem() {  # apply_netem <args...>
    netem_off
    tc qdisc add dev "${IFACE}" root netem "$@"
}

case "${PROFILE}" in
    clean)
        netem_off
        mss_clamp_off
        ip link set dev "${IFACE}" mtu "${BASE_MTU}"
        log "clean: netem off, mtu=${BASE_MTU}, clamp off (${IFACE})"
        ;;
    delay50)
        apply_netem delay 50ms
        log "delay50 applied on ${IFACE}"
        ;;
    wan)
        apply_netem delay 100ms 20ms loss 1%
        log "wan (100ms +-20ms, loss 1%) applied on ${IFACE}"
        ;;
    loss5)
        apply_netem loss 5%
        log "loss5 applied on ${IFACE}"
        ;;
    reorder)
        apply_netem delay 10ms reorder 25% 50%
        log "reorder (10ms, 25%/50%) applied on ${IFACE}"
        ;;
    mtu1400)
        ip link set dev "${IFACE}" mtu 1400
        mss_clamp_on 1360
        log "mtu1400 + MSS clamp 1360 applied on ${IFACE}"
        ;;
    mtu576)
        ip link set dev "${IFACE}" mtu 576
        mss_clamp_on 536
        log "mtu576 + MSS clamp 536 applied on ${IFACE}"
        ;;
    status)
        echo "== qdisc on ${IFACE} =="
        tc qdisc show dev "${IFACE}"
        echo "== link =="
        ip link show dev "${IFACE}"
        echo "== mangle POSTROUTING (TCPMSS) =="
        iptables -t mangle -S POSTROUTING 2>/dev/null | grep TCPMSS \
            || echo "(no MSS clamp)"
        exit 0
        ;;
    *)
        log "ERROR: unknown profile '${PROFILE}'"
        usage
        ;;
esac

# Post-state for the log.
tc qdisc show dev "${IFACE}" | tee -a "${LOG}"
exit 0
