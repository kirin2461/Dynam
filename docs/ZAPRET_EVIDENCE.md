# Zapret blockcheck availability evidence layer

`scripts/lab/zapret_blockcheck_evidence.sh` wraps the **original, unmodified**
zapret `blockcheck.sh` (default path
`/mnt/agents/work/zapret/blockcheck.sh`, overridable via the
`ZAPRET_BLOCKCHECK` environment variable) as an **optional, additional
availability evidence layer**.

It is **not** a replacement for Dynam's UDP/DPI evidence stack
(`udp_dpi_gate.py`, `pcap_assert`, suites 1–4): those remain the authoritative
tests for packet formation and protocol classification. This layer only
records what the upstream zapret tool observes when probing DPI bypass
strategies. It makes **no claim of TSPU (or any DPI) invisibility** — an
`!!!!! AVAILABLE !!!!!` line from blockcheck is upstream tool output recorded
as evidence, nothing more.

## Safety model

The wrapper **hard-fails by default**. A real run requires *all* of:

1. **Explicit opt-in**: `--opt-in` or `DYNAM_ZAPRET_BLOCKCHECK_OPTIN=1`.
2. **A dedicated isolated network namespace**, default `dynam-zapret-lab`
   (name must start with `dynam-zapret-`), that is either created by the
   wrapper or already carries its verifiable ownership marker
   (`$DYNAM_ZAPRET_RUN_DIR/<ns>.owned`, containing the live netns inode).
3. The lab netns must be **provably distinct from the production (pid 1)
   network namespace**; if it is the pid 1 namespace, the wrapper refuses.
4. Root with `CAP_SYS_ADMIN` + `CAP_NET_ADMIN`, plus dependencies (below).

Refusals exit `2` and write `verdict: NOT-RUN`. The wrapper:

- **never runs blockcheck in the host/production namespace** — execution is
  exclusively `ip netns exec <lab-ns> env BATCH=1 <blockcheck.sh>`;
- **never touches the host/VPS firewall** — it issues no host `iptables`,
  `nft`, `ipfw`, or `pf` commands, and configures no NAT/veth/uplink (if the
  lab netns has no connectivity, blockcheck simply reports `UNAVAILABLE`;
  operators may pre-move a dedicated lab interface into the owned netns);
- refuses foreign namespaces (existing netns without a valid ownership
  marker), foreign-looking names, and unsafe blockcheck paths (missing,
  non-regular, wrong basename, world-writable);
- cleans up via an `EXIT/INT/TERM/HUP` trap: kills the blockcheck child and
  any in-netns `nfqws`/`tpws`/`mdig`/`curl` workers, deletes the owned netns
  (which atomically destroys all in-netns firewall state), and removes the
  ownership marker, raw log, and redaction script.

## Dependencies (real mode)

- `bash`, `sed`, `grep`, `awk`, `find`, `realpath` (or `readlink` fallback)
- `iproute2` (`ip`) with network-namespace support
- `curl` (required by blockcheck itself, >= 7.49 for `--connect-to`)
- `iptables` **or** `nftables` (blockcheck nfqws strategy tests)
- a zapret checkout with **built** binaries (`nfqws`, `tpws`, `mdig`);
  see the zapret checkout's own `docs/` for building
- Linux; FreeBSD/OpenBSD/macOS blockcheck variants are out of scope here

## Usage

Isolated real run (lab host only, never a VPS or production host):

```sh
sudo DYNAM_ZAPRET_BLOCKCHECK_OPTIN=1 LAB_DIR=/tmp/lab \
    scripts/lab/zapret_blockcheck_evidence.sh --opt-in
```

Hermetic mock/self-test run (safe anywhere, never invokes the real
blockcheck, netns, or firewall):

```sh
scripts/lab/zapret_blockcheck_evidence.sh --opt-in --self-test
python3 scripts/lab/test_zapret_blockcheck_evidence.py
```

Useful environment variables:

| Variable | Meaning |
| --- | --- |
| `ZAPRET_BLOCKCHECK` | path to the original `blockcheck.sh` |
| `DYNAM_ZAPRET_BLOCKCHECK_OPTIN` | `=1` required for any execution |
| `DYNAM_ZAPRET_NETNS` | lab netns name (default `dynam-zapret-lab`) |
| `DYNAM_ZAPRET_RUN_DIR` | private state dir, chmod 700 (default `/run/dynam/zapret-blockcheck`) |
| `DYNAM_ZAPRET_REDACT` | extra space-separated secrets stripped from the sanitized log |
| `LAB_DIR` | results dir (default `/tmp/lab`) |
| `DYNAM_ZAPRET_ST_NS_STATE` | self-test only: `missing`/`owned`/`foreign`/`production`/`create-fail` |
| `DYNAM_ZAPRET_MOCK_BLOCKCHECK` | self-test only: executable printing a canned blockcheck transcript |

## Outputs and verdict semantics

Written to `LAB_DIR`:

- `zapret_blockcheck_verdict.txt` — `verdict: PASS | FAIL | NOT-RUN`,
  `summary_seen`, `available_strategies`, `unavailable_strategies`, and a
  `scope` line repeating that this is availability evidence only;
- `zapret_blockcheck.sanitized.log` — blockcheck stdout with all IPv4/IPv6
  addresses and any `DYNAM_ZAPRET_REDACT` secrets stripped;
- `zapret_blockcheck_wrapper.log` — wrapper operational log (never contains
  raw blockcheck output).

Raw blockcheck output exists only transiently in `DYNAM_ZAPRET_RUN_DIR`
(mode `600`) and is deleted by the cleanup trap.

Verdicts:

- **PASS** — blockcheck ran to completion (its `* SUMMARY` was produced)
  inside the isolated lab netns. PASS means "evidence collected", **not**
  "bypass works" and **not** "invisible to TSPU/DPI".
- **FAIL** — execution started but no complete `* SUMMARY` was produced.
- **NOT-RUN** — refusal (no opt-in, no isolation, missing dependencies,
  unsafe path) or interruption. No evidence was collected.

## Limitations

- The wrapper provides L3 isolation only; it deliberately does not provide
  connectivity. Without an operator-provisioned lab uplink inside the netns,
  blockcheck reports everything `UNAVAILABLE` — that is the expected safe
  outcome, not a failure of the layer.
- blockcheck results depend on the operator's network, DNS, and the tested
  domains; they are point-in-time availability observations and cannot
  establish DPI invisibility or future reachability.
