#!/usr/bin/env bash
# Real production Dynam Director-over-RealQuic through an independent
# AF_PACKET userspace IPS. All networking is inside nested namespaces.
set -euo pipefail

if [[ "${NCP_ENFORCER_NETNS:-0}" != "1" ]]; then
    exec unshare -n env NCP_ENFORCER_NETNS=1 bash "$0" "$@"
fi

HERE="$(cd "$(dirname "$0")" && pwd)"
BINARY="${1:-$HERE/../../../build-lab-quic/bin/ncp_quic_director_cli}"
RESULTS="${EVIDENCE_DIR:-$HERE/results-quic-director-afpacket}"
CAPTURE="${CAPTURE:-0}"
[[ -x "$BINARY" ]] || { echo "director CLI not executable: $BINARY" >&2; exit 2; }
mkdir -p "$RESULTS"
rm -f "$RESULTS"/*.json "$RESULTS"/*.jsonl "$RESULTS"/*.log \
      "$RESULTS"/*.txt "$RESULTS"/*.sha256 "$RESULTS"/*.pcap 2>/dev/null || true

for tool in unshare nsenter python3 sha256sum openssl timeout; do
    command -v "$tool" >/dev/null || { echo "missing required tool: $tool" >&2; exit 2; }
done

PIDS=()
ENFORCER_PID=""
RECEIVER_PID=""
CAPTURE_PID=""
CERTS="$RESULTS/test-certs"
rm -rf "$CERTS"
mkdir -p "$CERTS"
cleanup() {
    if [[ -n "$CAPTURE_PID" ]]; then kill -INT "$CAPTURE_PID" 2>/dev/null || true; fi
    if [[ -n "$ENFORCER_PID" ]]; then kill -TERM "$ENFORCER_PID" 2>/dev/null || true; fi
    if [[ -n "$RECEIVER_PID" ]]; then kill "$RECEIVER_PID" 2>/dev/null || true; fi
    for pid in "${PIDS[@]:-}"; do
        [[ -n "$pid" ]] && kill "$pid" 2>/dev/null || true
    done
    sleep 0.2
    for pid in "${PIDS[@]:-}"; do
        [[ -n "$pid" ]] && kill -9 "$pid" 2>/dev/null || true
    done
    rm -rf "$CERTS"
}
trap cleanup EXIT INT TERM

openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "$CERTS/key.pem" -out "$CERTS/cert.pem" -days 1 \
    -subj '/CN=lab.dynam.test' \
    -addext 'subjectAltName=DNS:lab.dynam.test' \
    -addext 'basicConstraints=critical,CA:TRUE' >/dev/null 2>&1

{
    uname -a
    python3 --version
    "$BINARY" --help 2>&1 || true
    echo "policy: structural QUIC v1 flow bootstrap, default-deny other UDP"
    echo "scope: production NcpQuicDirectorAdapter, same Dynam implementation"
} > "$RESULTS/environment.txt"

python3 "$HERE/netns_setup.py" link-set lo up
unshare -n --fork sleep 300 &
CLIENT_NS=$!
PIDS+=("$CLIENT_NS")
unshare -n --fork sleep 300 &
SERVER_NS=$!
PIDS+=("$SERVER_NS")
sleep 0.3
python3 "$HERE/netns_setup.py" add-veth ncp-c eth0 --peer-pid "$CLIENT_NS"
python3 "$HERE/netns_setup.py" add-veth ncp-s eth0 --peer-pid "$SERVER_NS"
python3 "$HERE/netns_setup.py" link-set ncp-c up
python3 "$HERE/netns_setup.py" link-set ncp-s up
python3 "$HERE/netns_setup.py" --netns-pid "$CLIENT_NS" link-set lo up
python3 "$HERE/netns_setup.py" --netns-pid "$CLIENT_NS" link-set eth0 up
python3 "$HERE/netns_setup.py" --netns-pid "$CLIENT_NS" addr-add eth0 172.30.240.10/8
python3 "$HERE/netns_setup.py" --netns-pid "$SERVER_NS" link-set lo up
python3 "$HERE/netns_setup.py" --netns-pid "$SERVER_NS" link-set eth0 up
python3 "$HERE/netns_setup.py" --netns-pid "$SERVER_NS" addr-add eth0 172.30.241.10/8

# AF_PACKET forwarding must operate on real wire-sized UDP datagrams.  MsQuic
# may use UDP GSO; reinjecting a coalesced super-packet into a 1500-byte veth
# fails with EMSGSIZE and is not an independent per-datagram policy decision.
for feature in tso gso gro; do
    python3 "$HERE/netns_setup.py" offload-set ncp-c "$feature" off
    python3 "$HERE/netns_setup.py" offload-set ncp-s "$feature" off
    python3 "$HERE/netns_setup.py" --netns-pid "$CLIENT_NS" offload-set eth0 "$feature" off
    python3 "$HERE/netns_setup.py" --netns-pid "$SERVER_NS" offload-set eth0 "$feature" off
done
# UDP_SEGMENT has a separate named feature on this kernel.  Disable and verify
# it explicitly instead of assuming that generic GSO=off is sufficient.
for pid in "$CLIENT_NS" "$SERVER_NS"; do
    python3 "$HERE/netns_setup.py" --netns-pid "$pid" feature-set \
        eth0 tx-udp-segmentation off
done

start_enforcer() {
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

start_capture() {
    [[ "$CAPTURE" == "1" ]] || return 0
    command -v tcpdump >/dev/null || { echo 'CAPTURE=1 requires tcpdump' >&2; exit 2; }
    # EN10MB on one middlebox veth is directly consumable by the pinned nDPI
    # reader. Capture only the enforced production session, before controls.
    tcpdump -i ncp-c -nn -s0 -U --immediate-mode \
        -w "$RESULTS/enforced-production.pcap" 'udp port 45000' \
        > "$RESULTS/enforced-tcpdump.log" 2>&1 &
    CAPTURE_PID=$!
    sleep 0.3
    kill -0 "$CAPTURE_PID" 2>/dev/null || {
        cat "$RESULTS/enforced-tcpdump.log" >&2
        exit 1
    }
}

stop_capture() {
    [[ -n "$CAPTURE_PID" ]] || return 0
    kill -INT "$CAPTURE_PID" 2>/dev/null || true
    wait "$CAPTURE_PID" 2>/dev/null || true
    CAPTURE_PID=""
    [[ -s "$RESULTS/enforced-production.pcap" ]] || {
        echo 'production capture is empty' >&2
        exit 1
    }
}

run_target() {
    local label="$1"
    nsenter -n -t "$SERVER_NS" "$BINARY" server \
        --bind 172.30.241.10 --port 45000 --count 4 \
        --cert "$CERTS/cert.pem" --key "$CERTS/key.pem" \
        > "$RESULTS/$label-server.log" 2>&1 &
    local server_pid=$!
    PIDS+=("$server_pid")
    sleep 0.4
    if ! timeout 45s nsenter -n -t "$CLIENT_NS" "$BINARY" client \
        --bind 172.30.240.10 --host 172.30.241.10 --port 45000 --count 4 \
        --sni lab.dynam.test --ca "$CERTS/cert.pem" \
        > "$RESULTS/$label-client.log" 2>&1; then
        cat "$RESULTS/$label-client.log" >&2 || true
        cat "$RESULTS/$label-server.log" >&2 || true
        return 1
    fi
    if ! timeout 10s tail --pid="$server_pid" -f /dev/null; then
        cat "$RESULTS/$label-server.log" >&2 || true
        return 1
    fi
    grep -q 'DYNAM_QUIC_DIRECTOR_OK' "$RESULTS/$label-client.log"
    grep -q 'DYNAM_QUIC_DIRECTOR_SERVER_OK' "$RESULTS/$label-server.log"
}

start_receiver() {
    local label="$1"
    nsenter -n -t "$SERVER_NS" python3 "$HERE/udp_control.py" server \
        --output "$RESULTS/$label-receiver.jsonl" \
        > "$RESULTS/$label-receiver.log" 2>&1 &
    RECEIVER_PID=$!
    sleep 0.2
}

stop_receiver() {
    kill "$RECEIVER_PID" 2>/dev/null || true
    wait "$RECEIVER_PID" 2>/dev/null || true
    RECEIVER_PID=""
}

control() {
    local kind="$1" expect="$2" label="$3"
    nsenter -n -t "$CLIENT_NS" python3 "$HERE/udp_control.py" client \
        "$kind" "$expect" --output "$RESULTS/$label.json"
}

# Positive target and negative controls must work without enforcement.
start_enforcer off "$RESULTS/baseline-verdicts.jsonl" \
    "$RESULTS/baseline-alerts.log" "$RESULTS/baseline-enforcer.log"
run_target baseline
start_receiver baseline
control ph pass baseline-ph
control random pass baseline-random
stop_receiver
stop_enforcer

# The actual protected director path must pass structural QUIC policy; legacy
# PH and random UDP must be actively dropped by the same middlebox.
start_enforcer quic-v1 "$RESULTS/enforced-verdicts.jsonl" \
    "$RESULTS/enforced-alerts.log" "$RESULTS/enforced-enforcer.log"
start_capture
run_target enforced
stop_capture
start_receiver enforced
control ph block enforced-ph-blocked
control random block enforced-random-blocked
stop_receiver
stop_enforcer

sha256sum "$HERE/afpacket_enforcer.py" \
    "$RESULTS"/baseline-client.log "$RESULTS"/baseline-server.log \
    "$RESULTS"/enforced-client.log "$RESULTS"/enforced-server.log \
    "$RESULTS"/enforced-alerts.log "$RESULTS"/enforced-verdicts.jsonl \
    > "$RESULTS/evidence.sha256"
if [[ "$CAPTURE" == "1" ]]; then
    sha256sum "$RESULTS/enforced-production.pcap" >> "$RESULTS/evidence.sha256"
fi

python3 - "$RESULTS" <<'PY'
import json
from pathlib import Path
import sys

root = Path(sys.argv[1])
controls = [json.loads((root / f"{name}.json").read_text()) for name in (
    "baseline-ph", "baseline-random", "enforced-ph-blocked",
    "enforced-random-blocked")]
assert all(r.get("passed") for r in controls), controls
verdicts = [json.loads(line) for line in
            (root / "enforced-verdicts.jsonl").read_text().splitlines() if line]
quic_allows = [v for v in verdicts if v["verdict"] == "ALLOW" and
               v["kind"] in ("quic-initial", "quic-established")]
drops = [v for v in verdicts if v["verdict"] == "DROP" and
         v["kind"] == "unclassified-udp"]
assert quic_allows, "no real QUIC allow verdicts"
assert len(drops) >= 2, f"negative controls were not actively dropped: {verdicts}"
assert all(v.get("checksum_finalized") for v in quic_allows + drops)
summary = {
    "schema_version": 1,
    "passed": True,
    "marker": "DYNAM_QUIC_ENFORCER_PASS",
    "scope": "production NcpQuicDirectorAdapter; same Dynam implementation",
    "isolation": "nested network namespaces; no host network changes",
    "enforcer": "independent Python AF_PACKET userspace IPS",
    "policy": "allow structural QUIC v1 bidirectional flow; default-deny other UDP",
    "baseline_target": "DYNAM_QUIC_DIRECTOR_OK + SERVER_OK",
    "enforced_target": "DYNAM_QUIC_DIRECTOR_OK + SERVER_OK",
    "negative_controls": controls,
    "quic_allow_verdicts": len(quic_allows),
    "drop_verdicts": drops,
    "not_claimed": ["independent Dynam implementation interop",
                    "cryptographic QUIC validation by enforcer",
                    "provider/ТСПУ bypass"],
}
(root / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
print("DYNAM_QUIC_ENFORCER_PASS scope=production_director_quic_v1")
PY
