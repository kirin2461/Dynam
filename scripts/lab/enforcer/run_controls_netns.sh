#!/usr/bin/env bash
# Docker-free equivalent of run_controls.sh for a disposable Linux host.
# The outer unshare creates a new network namespace. Sender and receiver are
# separate nested namespaces; nftables/Suricata run only in the middle one.
# No host interface, route, firewall, DNS, or published port is changed.
set -euo pipefail

if [[ "${NCP_ENFORCER_NETNS:-0}" != "1" ]]; then
    exec unshare -n env NCP_ENFORCER_NETNS=1 bash "$0" "$@"
fi

HERE="$(cd "$(dirname "$0")" && pwd)"
RESULTS="$HERE/results-netns"
mkdir -p "$RESULTS"
rm -f "$RESULTS"/*.json "$RESULTS"/*.jsonl "$RESULTS"/*.log \
      "$RESULTS"/*.txt "$RESULTS"/suricata.rules 2>/dev/null || true

for tool in ip nft nsenter suricata python3 sha256sum; do
    command -v "$tool" >/dev/null || { echo "missing required tool: $tool" >&2; exit 2; }
done

PIDS=()
SURICATA_PID=""
cleanup() {
    if [[ -n "$SURICATA_PID" ]]; then kill -TERM "$SURICATA_PID" 2>/dev/null || true; fi
    for pid in "${PIDS[@]:-}"; do
        [[ -n "$pid" ]] && kill "$pid" 2>/dev/null || true
    done
    sleep 0.2
    for pid in "${PIDS[@]:-}"; do
        [[ -n "$pid" ]] && kill -9 "$pid" 2>/dev/null || true
    done
    nft delete table ip ncp_enforcer 2>/dev/null || true
}
trap cleanup EXIT INT TERM

ip link set lo up
sysctl -q -w net.ipv4.ip_forward=1

# Namespace-holder processes. They have no external connectivity.
unshare -n --fork sleep 300 &
CLIENT_NS=$!
PIDS+=("$CLIENT_NS")
unshare -n --fork sleep 300 &
SERVER_NS=$!
PIDS+=("$SERVER_NS")

# Middle enforcer: 172.30.240.2 <-> sender and 172.30.241.2 <-> receiver.
ip link add ncp-c type veth peer name eth0 netns "$CLIENT_NS"
ip link add ncp-s type veth peer name eth0 netns "$SERVER_NS"
ip addr add 172.30.240.2/24 dev ncp-c
ip addr add 172.30.241.2/24 dev ncp-s
ip link set ncp-c up
ip link set ncp-s up

nsenter -n -t "$CLIENT_NS" ip link set lo up
nsenter -n -t "$CLIENT_NS" ip addr add 172.30.240.10/24 dev eth0
nsenter -n -t "$CLIENT_NS" ip link set eth0 up
nsenter -n -t "$CLIENT_NS" ip route add 172.30.241.0/24 via 172.30.240.2

nsenter -n -t "$SERVER_NS" ip link set lo up
nsenter -n -t "$SERVER_NS" ip addr add 172.30.241.10/24 dev eth0
nsenter -n -t "$SERVER_NS" ip link set eth0 up
nsenter -n -t "$SERVER_NS" ip route add 172.30.240.0/24 via 172.30.241.2

nsenter -n -t "$SERVER_NS" python3 "$HERE/udp_control.py" server \
    --output "$RESULTS/receiver.jsonl" > "$RESULTS/receiver-stdout.log" 2>&1 &
RECEIVER_PID=$!
PIDS+=("$RECEIVER_PID")
sleep 0.2

control() {
    local kind="$1" expect="$2" label="$3"
    nsenter -n -t "$CLIENT_NS" python3 "$HERE/udp_control.py" client \
        "$kind" "$expect" --output "$RESULTS/$label.json"
}

# Routing/reference baseline: all controls must work with enforcement disabled.
bash "$HERE/nftables.sh" off
control random pass baseline-random
control stun pass baseline-stun
control ph pass baseline-ph

# Independent Suricata IPS + nftables enforcement, still inside the middle
# network namespace only. No bypass flag: a missing IPS listener cannot fail open.
bash "$HERE/nftables.sh" quic-stun
suricata --build-info > "$RESULTS/suricata-build-info.txt"
nft list table ip ncp_enforcer > "$RESULTS/nftables-effective.txt"
cp "$HERE/suricata.rules" "$RESULTS/suricata.rules"
suricata -c /etc/suricata/suricata.yaml --nfq -q 0 \
    -S "$HERE/suricata.rules" \
    --set default-rule-path="$HERE" \
    --set nfq.fail-open=no \
    -l "$RESULTS" > "$RESULTS/suricata-stdout.log" 2>&1 &
SURICATA_PID=$!

ready=0
for _ in $(seq 1 60); do
    if ! kill -0 "$SURICATA_PID" 2>/dev/null; then
        cat "$RESULTS/suricata-stdout.log" >&2 || true
        exit 1
    fi
    if grep -q 'Engine started' "$RESULTS/suricata.log" 2>/dev/null; then
        ready=1
        break
    fi
    sleep 0.25
done
[[ "$ready" == "1" ]] || { echo 'Suricata did not become ready' >&2; exit 1; }

control stun pass enforced-stun
control ph block enforced-ph-blocked
control random block enforced-random-blocked

# A timeout alone is not enforcement evidence: prove that the independent IPS
# saw and denied both negative controls.
test -s "$RESULTS/fast.log"
test "$(grep -c 'NCP ENF default deny unclassified UDP' "$RESULTS/fast.log")" -ge 2
cp "$RESULTS/fast.log" "$RESULTS/suricata-fast.log"
sha256sum "$RESULTS/suricata.rules" "$RESULTS/suricata-fast.log" \
    > "$RESULTS/evidence.sha256"

python3 - "$RESULTS" <<'PY'
import json
from pathlib import Path
import sys
root = Path(sys.argv[1])
files = sorted(root.glob("*.json"))
records = [json.loads(p.read_text()) for p in files]
assert len(records) == 6, f"expected six controls, got {len(records)}"
assert all(r.get("passed") for r in records), records
summary = {"schema_version": 1, "passed": True,
           "isolation": "nested network namespaces",
           "enforcer": "Suricata NFQUEUE + nftables", "controls": records}
(root / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
print("G1_ENFORCER_CONTROLS_PASS")
PY
