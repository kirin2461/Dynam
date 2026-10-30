#!/usr/bin/env bash
# AF_PACKET userspace-IPS equivalent of run_controls_netns.sh for kernels
# without NFQUEUE support (custom 6.6.69-cube.pvm guest kernel returns
# ENOENT for nfqueue). Uses pure-Python rtnetlink (netns_setup.py) plus an
# AF_PACKET bump-in-the-wire IPS (afpacket_enforcer.py). All interfaces,
# addresses, and sockets live inside the outer unshare'd network namespace;
# nothing on the host changes.
set -euo pipefail

if [[ "${NCP_ENFORCER_NETNS:-0}" != "1" ]]; then
    exec unshare -n env NCP_ENFORCER_NETNS=1 bash "$0" "$@"
fi

HERE="$(cd "$(dirname "$0")" && pwd)"
RESULTS="$HERE/results-afpacket"
mkdir -p "$RESULTS"
rm -f "$RESULTS"/*.json "$RESULTS"/*.jsonl "$RESULTS"/*.log \
      "$RESULTS"/*.txt 2>/dev/null || true

for tool in unshare nsenter python3 sha256sum; do
    command -v "$tool" >/dev/null || { echo "missing required tool: $tool" >&2; exit 2; }
done

PIDS=()
ENFORCER_PID=""
cleanup() {
    if [[ -n "$ENFORCER_PID" ]]; then kill -TERM "$ENFORCER_PID" 2>/dev/null || true; fi
    for pid in "${PIDS[@]:-}"; do
        [[ -n "$pid" ]] && kill "$pid" 2>/dev/null || true
    done
    sleep 0.2
    for pid in "${PIDS[@]:-}"; do
        [[ -n "$pid" ]] && kill -9 "$pid" 2>/dev/null || true
    done
}
trap cleanup EXIT INT TERM

{
    uname -a
    python3 --version
    for t in suricata nft ip tc iptables; do
        if command -v "$t" >/dev/null; then echo "$t: $(command -v "$t")"; else echo "$t: ABSENT"; fi
    done
    echo "note: NFQUEUE path unavailable (nftables queue num 0 -> ENOENT on this kernel);"
    echo "enforcer is the independent Python AF_PACKET userspace IPS instead."
} > "$RESULTS/environment.txt"

python3 "$HERE/netns_setup.py" link-set lo up

# Namespace-holder processes. They have no external connectivity.
unshare -n --fork sleep 300 &
CLIENT_NS=$!
PIDS+=("$CLIENT_NS")
unshare -n --fork sleep 300 &
SERVER_NS=$!
PIDS+=("$SERVER_NS")
sleep 0.3

# Middle enforcer namespace: ncp-c <-> client eth0, ncp-s <-> server eth0.
# Pure L2: the middle namespace holds no IP addresses, so the AF_PACKET
# bridge process is the only path between client and server.
python3 "$HERE/netns_setup.py" add-veth ncp-c eth0 --peer-pid "$CLIENT_NS"
python3 "$HERE/netns_setup.py" add-veth ncp-s eth0 --peer-pid "$SERVER_NS"
python3 "$HERE/netns_setup.py" link-set ncp-c up
python3 "$HERE/netns_setup.py" link-set ncp-s up

# /8 prefixes make the two /24 control addresses on-link across the bridge,
# keeping the exact udp_control.py addressing (172.30.241.10 server).
python3 "$HERE/netns_setup.py" --netns-pid "$CLIENT_NS" link-set lo up
python3 "$HERE/netns_setup.py" --netns-pid "$CLIENT_NS" link-set eth0 up
python3 "$HERE/netns_setup.py" --netns-pid "$CLIENT_NS" addr-add eth0 172.30.240.10/8
python3 "$HERE/netns_setup.py" --netns-pid "$SERVER_NS" link-set lo up
python3 "$HERE/netns_setup.py" --netns-pid "$SERVER_NS" link-set eth0 up
python3 "$HERE/netns_setup.py" --netns-pid "$SERVER_NS" addr-add eth0 172.30.241.10/8

nsenter -n -t "$SERVER_NS" python3 "$HERE/udp_control.py" server \
    --output "$RESULTS/receiver.jsonl" > "$RESULTS/receiver-stdout.log" 2>&1 &
PIDS+=("$!")
sleep 0.2

control() {
    local kind="$1" expect="$2" label="$3"
    nsenter -n -t "$CLIENT_NS" python3 "$HERE/udp_control.py" client \
        "$kind" "$expect" --output "$RESULTS/$label.json"
}

start_enforcer() {  # policy verdict-log alert-log stdout-log
    python3 "$HERE/afpacket_enforcer.py" \
        --if-a ncp-c --if-b ncp-s --policy "$1" \
        --verdicts "$2" --alerts "$3" > "$4" 2>&1 &
    ENFORCER_PID=$!
    local ready=0 _
    for _ in $(seq 1 40); do
        if ! kill -0 "$ENFORCER_PID" 2>/dev/null; then
            cat "$4" >&2 || true
            exit 1
        fi
        if grep -q 'Engine started' "$4" 2>/dev/null; then ready=1; break; fi
        sleep 0.25
    done
    [[ "$ready" == "1" ]] || { echo 'AF_PACKET enforcer did not become ready' >&2; exit 1; }
}

stop_enforcer() {
    kill -TERM "$ENFORCER_PID" 2>/dev/null || true
    wait "$ENFORCER_PID" 2>/dev/null || true
    ENFORCER_PID=""
}

# Reference baseline: same in-path bridge, policy off (forward everything).
start_enforcer off "$RESULTS/baseline-verdicts.jsonl" \
    "$RESULTS/baseline-alerts.log" "$RESULTS/enforcer-baseline-stdout.log"
control random pass baseline-random
control stun pass baseline-stun
control ph pass baseline-ph
stop_enforcer
cp "$RESULTS/receiver.jsonl" "$RESULTS/receiver-baseline.jsonl"

# Enforcement phase: quic-stun policy, default-deny with independent alerts.
start_enforcer quic-stun "$RESULTS/enforced-verdicts.jsonl" \
    "$RESULTS/enforced-alerts.log" "$RESULTS/enforcer-enforced-stdout.log"
control stun pass enforced-stun
control ph block enforced-ph-blocked
control random block enforced-random-blocked
stop_enforcer

# A timeout alone is not enforcement evidence: prove the in-path IPS saw and
# actively dropped both negative controls.
test -s "$RESULTS/enforced-alerts.log"
test "$(grep -c 'NCP ENF default deny unclassified UDP' "$RESULTS/enforced-alerts.log")" -ge 2
test "$(grep -c '"verdict": "DROP"' "$RESULTS/enforced-verdicts.jsonl")" -ge 2

sha256sum "$HERE/afpacket_enforcer.py" "$HERE/udp_control.py" \
    "$RESULTS/enforced-alerts.log" "$RESULTS/enforced-verdicts.jsonl" \
    > "$RESULTS/evidence.sha256"

python3 - "$RESULTS" <<'PY'
import json
from pathlib import Path
import sys

root = Path(sys.argv[1])
files = sorted(p.name for p in root.glob("*.json") if p.name != "summary.json")
records = [json.loads((root / name).read_text()) for name in files]
assert len(records) == 6, f"expected six controls, got {len(records)}"
assert all(r.get("passed") for r in records), records

baseline_rx = [json.loads(l) for l in
               (root / "receiver-baseline.jsonl").read_text().splitlines() if l.strip()]
enforced_rx = [json.loads(l) for l in
               (root / "receiver.jsonl").read_text().splitlines() if l.strip()]
enforced_rx = enforced_rx[len(baseline_rx):]
assert len(baseline_rx) == 3, f"baseline receiver evidence incomplete: {baseline_rx}"
assert all(r["kind"] == "stun" for r in enforced_rx) and len(enforced_rx) == 1, \
    f"prohibited traffic reached receiver during enforcement: {enforced_rx}"

verdicts = [json.loads(l) for l in
            (root / "enforced-verdicts.jsonl").read_text().splitlines() if l.strip()]
drops = [v for v in verdicts if v["verdict"] == "DROP"]
assert len(drops) >= 2, f"expected DROP verdicts for ph and random: {verdicts}"
allows = [v for v in verdicts if v["verdict"] == "ALLOW" and v["kind"] == "stun"]
assert allows, "no STUN allow verdict recorded"

summary = {
    "schema_version": 1,
    "passed": True,
    "isolation": "nested network namespaces (unshare -n), no host changes",
    "enforcer": "Python AF_PACKET userspace IPS (L2 bump-in-the-wire), "
                "independent of nftables/NFQUEUE",
    "policy": "quic-stun: allow STUN binding, default-deny unclassified UDP",
    "controls": records,
    "enforced_receiver_evidence": enforced_rx,
    "drop_verdicts": drops,
}
(root / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
print("G1_ENFORCER_CONTROLS_PASS")
PY
