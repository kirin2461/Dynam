#!/usr/bin/env bash
# Runs only disposable internal Compose networks; never changes host firewall.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE"
command -v docker >/dev/null || { echo "Docker is required" >&2; exit 2; }
mkdir -p results
rm -f results/*.json results/*.jsonl results/*.log results/*.txt results/suricata.rules 2>/dev/null || true

wait_healthy() {
  local service="$1" cid status
  for _ in $(seq 1 60); do
    cid="$(docker compose ps -q "$service")"
    status="$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$cid" 2>/dev/null || true)"
    [[ "$status" == "healthy" || "$status" == "running" ]] && return 0
    [[ "$status" == "unhealthy" || "$status" == "exited" || "$status" == "dead" ]] && break
    sleep 0.5
  done
  docker compose logs "$service" >&2 || true
  echo "$service did not become healthy" >&2
  return 1
}

export ENFORCER_MODE=off
docker compose up -d --build enforcer receiver
cleanup() { docker compose down --volumes --remove-orphans >/dev/null 2>&1 || true; }
trap cleanup EXIT INT TERM
wait_healthy enforcer
wait_healthy receiver

control() {
  local kind="$1" expect="$2" label="$3"
  docker compose --profile controls run --rm --no-deps \
    --entrypoint /bin/sh sender -ec \
    "ip route add 172.30.241.0/24 via 172.30.240.2; exec python3 /opt/udp_control.py client $kind $expect --output /results/$label.json"
}

# Routing/reference baseline: all controls must work with enforcement disabled.
control random pass baseline-random
control stun pass baseline-stun
control ph pass baseline-ph

export ENFORCER_MODE=quic-stun
docker compose up -d --force-recreate enforcer
wait_healthy enforcer
control stun pass enforced-stun
control ph block enforced-ph-blocked
control random block enforced-random-blocked

# A timeout alone is not enforcement evidence: prove the independent IPS saw
# and denied the two negative controls.
docker compose exec -T enforcer sh -ec '
  test -s /var/log/suricata/fast.log
  test "$(grep -c "NCP ENF default deny unclassified UDP" /var/log/suricata/fast.log)" -ge 2
'
docker compose exec -T enforcer sh -ec 'cat /var/log/suricata/fast.log' > results/suricata-fast.log
sha256sum results/suricata.rules results/suricata-fast.log > results/evidence.sha256

python3 - <<'PY'
import json
from pathlib import Path
root = Path("results")
files = sorted(root.glob("*.json"))
records = [json.loads(p.read_text()) for p in files]
assert len(records) == 6, f"expected six controls, got {len(records)}"
assert all(r.get("passed") for r in records), records
summary = {"schema_version": 1, "passed": True, "controls": records}
(root / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
print("G1_ENFORCER_CONTROLS_PASS")
PY
