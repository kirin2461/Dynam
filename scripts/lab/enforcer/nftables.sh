#!/usr/bin/env bash
# Creates/deletes only this container's own table; host rules are untouched.
set -euo pipefail
MODE="${1:?mode required}"

nft delete table ip ncp_enforcer 2>/dev/null || true
nft add table ip ncp_enforcer

if [[ "$MODE" == "off" ]]; then
  nft 'add chain ip ncp_enforcer forward { type filter hook forward priority -100; policy accept; }'
else
  # No bypass flag: if Suricata is not listening, queued traffic cannot fail open.
  nft 'add chain ip ncp_enforcer forward { type filter hook forward priority -100; policy accept; }'
  nft add rule ip ncp_enforcer forward udp dport 45000 queue num 0
  nft add rule ip ncp_enforcer forward udp sport 45000 queue num 0
fi
