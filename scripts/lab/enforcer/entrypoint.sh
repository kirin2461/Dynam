#!/usr/bin/env bash
# Runs only inside the disposable enforcer network namespace.
set -euo pipefail

MODE="${ENFORCER_MODE:-quic-stun}"
[[ "$MODE" == "off" || "$MODE" == "quic-stun" ]] || {
  echo "ENFORCER_MODE must be off or quic-stun" >&2
  exit 2
}

bash /usr/local/bin/ncp-enforcer-nftables "$MODE"
suricata --build-info > /results/suricata-build-info.txt
nft list table ip ncp_enforcer > /results/nftables-effective.txt
cp /etc/suricata/rules/ncp-enforcer.rules /results/suricata.rules

# The packaged configuration supplies decoder/app-layer defaults. Only the
# independent local ruleset is evaluated. fail-open is explicitly disabled.
suricata -c /etc/suricata/suricata.yaml --nfq -q 0 \
  -S /etc/suricata/rules/ncp-enforcer.rules \
  --set default-rule-path=/etc/suricata/rules \
  --set nfq.fail-open=no \
  > /results/suricata-stdout.log 2>&1 &
PID=$!
cleanup() {
  kill -TERM "$PID" 2>/dev/null || true
  wait "$PID" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# Readiness is checked through the container healthcheck; an early Suricata
# exit is propagated immediately instead of being hidden by a sleep.
wait "$PID"
