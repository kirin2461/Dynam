# Strategy synthesis: building a desync strategy per destination on live traffic

Supersedes the reorder-only fallback from `FIX-adaptive-reorder-fallback.md`
(`ClientHelloStrategyTracker` / `apply_in_order_fallback` are removed).

## Problem

No fixed preset fits this network: fakes and multi-split break youtube,
reordering breaks example.com / cloudflare, and the first connection to every
destination paid for finding that out. `enable_autoprobe` /
`autoprobe_max_strategies` existed in `DPIConfig` but nothing read them.

## Design

`src/core/include/ncp_strategy_synth.hpp`, `src/core/src/ncp_strategy_synth.cpp`.

* A strategy is three genes: **split** (sni / midsld / pos1 / multi),
  **order** (in-order / disorder / reverse), **fake** (none / badseq / badsum /
  low-ttl). `Keep` leaves the preset's knob. `apply_genes()` rewrites only the
  desync knobs of the per-packet `effective_cfg`.
* `synthesized_strategy_ladder()`: 12 candidates, least intrusive first. The
  order is a prior. Laplace-smoothed global win rates re-rank it at run time,
  so what works on the network is learnt once and tried first on new hosts.
* Every new ClientHello is a trial of its destination's current candidate. The
  destination is the SNI, or the IP when there is no SNI. Signals come from
  outbound packets only:
  * **success**: the client sends data past the end of the ClientHello record
    on the same flow, which only happens after a ServerHello. The candidate is
    locked for that destination.
  * **failure**: the ClientHello is retransmitted at the same seq (the
    retransmission already goes out with the next candidate), or a flow stays
    silent for longer than 3 s when the app opens a new connection (RST
    injection case).
* Only the candidate a flow was **opened** with gets a clean trial. After the
  DPI has seen one attempt the flow may be poisoned, so a failure on a
  retransmission does not count against the next candidate. That candidate
  gets its clean trial on the next connection. (Live regression from run21:
  without this, a destination got stuck on the preset forever.)
* A locked candidate is dropped after 2 clean failures. When every candidate
  has failed, a new round starts, logged once. Destinations expire after
  600 s. Capacity: 512 destinations, 1024 flows.
* Parallel flows of the same trial that fail together move the destination
  forward only once.

## Modes

* `ncp run --synth`: the full ladder, so the preset's desync knobs are ignored.
* Default (no flag): candidates `{preset, sni/in-order/no-fake}`. This keeps
  the old fallback behaviour but on the same machinery.
* `DPIBypass::set_strategy_synthesis()` / `strategy_report_json()`. The stats
  file gets a `"strategy"` section (mode, candidates with scores, wins,
  failures, switches) and `dpi.strategy_locked`. The shutdown summary prints
  `locked=`.

## Tests

`tests/test_strategy_synth.cpp`: 25 tests, which replace
`test_clienthello_strategy.cpp`. They cover the signals, seq wrap-around,
multi-segment ClientHello, locking, global ranking, parallel flows,
poisoned retransmissions, the new round after exhaustion, TTL, capacity and
the genes. Full suite: 1448 tests, 1440 passed, 8 skipped (I2P/SAM), 0 failed.

## Live verification (elevated, all modules on)

run22 (`driver_report22.txt`):

| mode | pass 1 (cold) | pass 2 |
|---|---|---|
| `runet-strong --synth` | 6/6 OK | 6/6 OK |
| `runet-soft --synth` | 6/6 OK | 6/6 OK |
| `runet-strong` (preset + fallback) | 5/6 (example.com FAIL) | 6/6 OK |

The 6 hosts are example.com, cloudflare, youtube, 1.1.1.1, discord and twitch.
Each one locked on attempt 1, because the global ranking had already found
`sni/in-order/no-fake`.

run23 (`driver_report23.txt`): 14 connections each to x.com and instagram.

* x.com: all 12 candidates failed cleanly, the log shows "every candidate
  failed, starting a new round". TCP connects, the ServerHello never arrives.
  This is consistent with IP/range blocking of 172.66.0.0/16 rather than SNI
  DPI.
* instagram (157.240.245.174) and telegram-web: the SYN is never answered,
  which is an IP block. No ClientHello is ever sent, so no TLS desync can
  help. These need a tunnel or proxy, not desync.

## Known limitations

* Only TLS ClientHello on 443/80 is synthesized. QUIC and HTTP are not.
* The verdict for a silent flow needs another connection to the same
  destination.
* Fails are counted per retransmission in `failures`. Only clean trials
  affect scores.
