# Fix: seconds-long TLS latency in driver mode (inline shaping delays)

**Date**: 2026-11-22
**Files changed**:
- `src/core/src/ncp_behavioral_cloak.cpp` — burst-end packet no longer sleeps the idle gap inline; result clamped to an inline budget
- `src/core/include/ncp_behavioral_cloak.hpp` — `BehavioralCloakConfig::max_inline_delay_us`
- `src/core/include/ncp_time_correlation_breaker.hpp` — `TimeCorrelationBreakerConfig::inline_packet_path()`
- `src/cli/main.cpp` — Time Correlation Breaker constructed with the packet-path profile
- `src/core/include/ncp_dpi.hpp` — `kMaxInlineSendDelayUs`, `clamp_inline_send_delay_us()`
- `src/core/src/ncp_dpi.cpp` — all three `get_send_delay_us` sites clamp before sleeping
- `tests/test_shaping_delay.cpp` (new, 15 tests), `tests/CMakeLists.txt`

**Status**: Fixed, rebuilt, full suite green (1423 tests: 1415 passed, 8 skipped for missing I2P SAM, 0 failed), verified live in elevated driver mode.

---

## Symptom

With every module enabled (`ncp run --auto`), HTTPS through the WinDivert pipeline
took seconds per handshake:

| Modules | `1.1.1.1` TLS |
|---|---|
| driver, all off | 0.06–0.20 s |
| driver, all on | **4.0–9.2 s**, occasional timeouts |
| driver, `--no-cloak` | 0.43–1.15 s |
| driver, `--no-time-break` | 0.41–4.8 s |
| no driver | 0.07–0.19 s |

Both shaping modules were suspect, but the dominant contributor was not the one
the numbers suggested.

## Root cause

`ModuleHooks::get_send_delay_us` is called **inline on the WinDivert capture
thread** for every real segment and slept on immediately. Everything queued
behind that packet waits for the whole sleep — it is a global stall, not a
per-connection delay. Two modules fed it values sized for something else:

1. **BehavioralCloak — burst boundary (dominant).** In `shape_packet()` the
   burst state machine sets `burst_state_ = IDLE` *inside* the same call, so
   the following `else` branch ran `compute_idle_delay_()` and slept the model's
   full idle gap — `2000–8000 ms` for `chrome_casual` — for the last packet of
   every burst (5–30 packets). A measurement on the code before the fix showed
   `shape_packet()` returning up to **8 034 253 µs**. Every ~20th intercepted
   packet froze the capture thread for up to 8 s, which is exactly the observed
   4–9 s handshake latency.
2. **BehavioralCloak — intra-burst.** `compute_burst_delay_()` returns
   `50–200 ms` per packet for `chrome_casual`, plus up to 100 ms of HIGH-threat
   noise and up to 100 ms of upload-ratio penalty. Those intervals describe
   *application think-time*, which the OS produces on its own; replaying them
   per segment multiplies it.
3. **TimeCorrelationBreaker.** Defaults are `10–500 ms` per call, scaled up to
   5× by CV auto-adjust and 2.5× at CRITICAL threat, i.e. up to 2.5 s per
   segment. Its own header documents the call as "before the next session or
   request".

## Fix

Three independent layers, so a future module cannot reintroduce the stall:

1. `shape_packet()` no longer applies the idle gap inline — the gap stays
   available to callers that can actually wait, via `get_idle_duration()`
   (unchanged, still 2–8 s). The combined result (burst + ratio penalty +
   threat noise) is clamped to `BehavioralCloakConfig::max_inline_delay_us`,
   default **2000 µs**, `0` disables inline shaping delays entirely.
2. New factory `TimeCorrelationBreakerConfig::inline_packet_path()`:
   `0.5–4 ms`, `auto_adjust = false` (per-packet CV scaling has no session-level
   signal to work with). The session-scale defaults are untouched — pinned by
   `TimeBreakerInlineProfile.DefaultConfigIsStillSessionScale`.
3. `clamp_inline_send_delay_us()` caps anything a hook returns at
   `kMaxInlineSendDelayUs` (**50 ms**) at all three capture-thread call sites
   (disorder, reverse-frag, normal). Previously the only cap was `< 10 s`, which
   silently accepted the 8 s value.

## Tests

`tests/test_shaping_delay.cpp` — 15 tests, written red first. Before the fix the
worst-case assertion failed with `actual: 8034253 vs 2000`. Coverage:

- every `shape_packet()` result stays within the budget, including at HIGH and
  CRITICAL threat (the noise branch) and with a custom budget;
- `max_inline_delay_us = 0` returns exactly `0`, not "a few µs";
- the burst-closing packet is inside the budget while `get_idle_duration()`
  still reports 2000–8000 ms afterwards;
- breaker jitter stays in `[500, 4000]` µs over 2000 calls and never increments
  `cv_adjustments`, even with a flat gap history (CV = 0);
- `clamp_inline_send_delay_us` for `0`, negatives, `INT64_MIN`, `INT64_MAX`,
  and just past the cap;
- worst case as wired in `main.cpp` (CRITICAL cloak + breaker) fits the cap.

## Live verification (elevated, `driver_report15.txt`)

All modules on, `--preset runet-soft` (in-order split), 2 passes:

```
baseline (no driver)   1.1.1.1 191/88   example.com 71/148   cloudflare 101/199   discord 61/55
driver, all modules    1.1.1.1  59/68   example.com 69/160   cloudflare  90/204   discord 72/201
```

`tcb.total_jitter_us` = 38 684 over 14 packets ≈ **2.8 ms/packet** — inside the
new profile as designed. Autopilot stayed at level 0 / `selecting` with
`switches_total: 0`.

## Separate finding (not fixed here): out-of-order segmentation is dropped on some paths

Under `AutoProbe` (`fake+reverse-frag`) `example.com` and `www.cloudflare.com`
still fail, while `1.1.1.1`, `8.8.8.8` and `discord.com` succeed. This is **not**
the shaping bug and **not** affected by this fix:

- `pktmon` capture: TCP connect succeeds, then ncp emits the ClientHello as
  `seq=132`, `seq=2`, `seq=1` (out of order, reverse-frag). The server sends
  **no ACK at all** — not even a duplicate ACK — and the flow dies on
  retransmission timeout.
- The identical pattern to `1.1.1.1` is ACKed (`ack=132`, `ack=443`) and the
  handshake completes.
- Strategy matrix: `RuNet-Soft` (in-order split) → all four destinations OK;
  `AutoProbe`, `RuNet-TSPU`, `RuNet-Strong` (all reorder) → exactly the two
  Cloudflare-hosted names fail, `1.1.1.1` and `discord.com` fine.

Same packets from the same sender, different only by destination, so the drop is
on the path, not in ncp. Until per-destination fallback exists, use
`ncp run --preset runet-soft` on paths that drop reordered segments.
