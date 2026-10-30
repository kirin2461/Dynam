# Independent G1 enforcer cell

This harness uses **Suricata IPS + nftables**, not nDPI, to evaluate a specific
in-path policy. It is an isolated control cell, not a provider/ТСПУ simulator
and not evidence of universal DPI bypass.

## Safety properties

- both Compose networks are `internal: true`;
- no host ports are published;
- no host firewall, DNS, routes, or production network namespace is changed;
- `NET_ADMIN`/`NET_RAW` are granted only to the disposable enforcer container;
- nftables modifies only table `ip ncp_enforcer` inside that container;
- the NFQUEUE rule has no `bypass` flag, so a missing IPS listener does not fail
  open;
- `docker compose down` is executed through an EXIT trap.

Run only in a disposable Docker environment:

```bash
bash scripts/lab/enforcer/run_controls.sh
```

On a disposable Linux host without Docker, an equivalent nested-network-
namespace runner is available. It requires root plus `iproute2`, `nftables`,
Suricata with NFQUEUE support, `nsenter`, and Python 3. The outer `unshare -n`
keeps every address, route, veth, and nftables change off the host namespace:

```bash
bash scripts/lab/enforcer/run_controls_netns.sh
```

Its artifacts are written to `results-netns/`; the Docker runner uses
`results/`. Both runners require the same six controls and independent IPS
alerts, and neither is a provider/ТСПУ simulator.

## Required controls

With enforcement disabled, random UDP, STUN, and legacy PH must all receive a
valid response. With the `quic-stun` policy enabled:

- a real STUN Binding Request/Success exchange must pass;
- legacy PH must time out;
- high-entropy Unknown UDP must time out;
- Suricata `fast.log` must contain the independent default-deny alert.

A timeout without an IPS alert is not enforcement evidence. The script also
writes effective nftables rules, Suricata build information, the exact ruleset,
and SHA-256 evidence hashes under `results/`. These results are local lab
artifacts and must be sanitized before publication.

## Scope limitation

The STUN control validates the policy engine and capture path. It does not yet
prove a QUIC control, Dynam Policy PASS, active-probe equivalence, or provider
DPI resistance. Those require their own independent reference and candidate
runs. Container image/package versions must be recorded with every actual run;
unexecuted configuration is never reported as PASS.
