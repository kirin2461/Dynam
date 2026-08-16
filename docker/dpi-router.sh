#!/bin/bash
# DPI midbox entrypoint (runs inside the isolated container only).
# A *router*, not a server: packets cross it via FORWARD, and any packet
# carrying a blocked SNI / HTTP Host is answered with a TCP RST — classic
# carrier-grade inline-DPI behavior. iptables -m string is PER-PACKET, so
# split-packet desync genuinely evades it while unsplit traffic dies.
set -u

BLOCKED_DOMAINS="${BLOCKED_DOMAINS:-forbidden.example,blocked.example}"

# Map interfaces to the two testbed subnets.
CLI_IF=""
SRV_IF=""
for iface in $(ls /sys/class/net | grep -v '^lo$'); do
    addr=$(ip -4 -o addr show dev "$iface" | awk '{print $4}')
    case "$addr" in
        172.30.1.*) CLI_IF=$iface ;;
        172.30.2.*) SRV_IF=$iface ;;
    esac
done
if [ -z "$CLI_IF" ] || [ -z "$SRV_IF" ]; then
    echo "[dpi][FATAL] cannot map interfaces to clientnet/servernet"
    ip -4 -o addr show
    exit 1
fi
echo "[dpi] client-facing: $CLI_IF   server-facing: $SRV_IF"

# GRO/TSO/GSO on veth pairs reassemble split segments BEFORE netfilter sees
# them, which would make split-based desync untestable. Disable offloads.
ethtool -K "$CLI_IF" tso off gso off gro off 2>/dev/null || true
ethtool -K "$SRV_IF" tso off gso off gro off 2>/dev/null || true

sysctl -w net.ipv4.ip_forward=1 >/dev/null

# No conntrack ESTABLISHED shortcut on purpose: the string match must see the
# ClientHello / HTTP request packets of EVERY connection.
iptables -F FORWARD
IFS=',' read -ra arr <<< "$BLOCKED_DOMAINS"
for d in "${arr[@]}"; do
    iptables -A FORWARD -p tcp --dport 443 -m string --string "$d" --algo bm \
        -j REJECT --reject-with tcp-reset
    iptables -A FORWARD -p tcp --dport 80 -m string --string "Host: $d" --algo bm \
        -j REJECT --reject-with tcp-reset
    echo "[dpi] midbox-blocking $d (SNI + Host, RST injection)"
done

# NAT so the target's replies find their way back regardless of its routing.
iptables -t nat -A POSTROUTING -o "$SRV_IF" -j MASQUERADE

# Optional link impairment.
if [ -n "${DPI_NETEM:-}" ]; then
    tc qdisc add dev "$SRV_IF" root netem $DPI_NETEM && echo "[dpi] netem: $DPI_NETEM"
fi

echo "[dpi] router up. blocked: ${BLOCKED_DOMAINS}"
sleep infinity &
wait $!
