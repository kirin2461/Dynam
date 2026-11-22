# Fix: per-destination fallback from reordering strategies

## Problem

On the test ISP, the reordering presets (`autoprobe` / `Mobile-Universal`,
`runet-strong`) broke TLS to hosts that work fine without the driver
(`example.com` 8.6.112.0, `www.cloudflare.com` 104.16.124.96, `www.youtube.com`
64.233.162.198). The server never sent an ACK and the handshake died on timeout.
The same strategy worked towards `1.1.1.1`, `discord.com` and `www.twitch.tv`.
The reordering presets also did not unblock the hosts that really are blocked
(`x.com`, `instagram`, `web.telegram.org`), so on this path they only did harm.

Measured before the fix (`driver_report16.txt`): `runet-soft` reached every
reachable host; `autoprobe` broke `example.com` and `youtube`.

## Diagnosis

* The capture thread only sees outbound packets, so it never sees the missing
  ACK. But a ClientHello sent again at the same sequence number *is* that missing
  ACK: the OS would not retransmit if the first copy had got through.
* A capture (`cap2/yt1.pcapng`) showed that putting the segments back in order is
  not enough on its own. Fake packets keep the flow poisoned, and so does the
  1-byte + SNI + midsld multi-split, even with the segments in order. The host
  only recovered with a single in-order split and no fakes, which is the
  RuNet-Soft shape.

## Fix

* `ClientHelloStrategyTracker` (`ncp_dpi.hpp/.cpp`) tracks one entry per
  `dst_ip:port`. It records the last ClientHello seq and whether that attempt was
  reordered. If the same seq is retransmitted within 60 s after a reordered
  attempt, that destination switches to in-order. The switch is one-way: a
  destination never goes back to reordering. Entries last 600 s (TTL) and the
  table is capped at 256 with oldest-first eviction. It runs on the capture
  thread only.
* `apply_in_order_fallback(DPIConfig&)` turns off disorder, reverse-frag, fakes,
  autottl, `fake_repeats` and multi-layer split. It keeps `enable_tcp_split` on
  and leaves the split geometry unchanged.
* The pipeline calls it for every ClientHello after zapret chain matching. The
  tracker object lives in `Impl`, so it survives `update_config()` and AutoPilot
  preset swaps.
* New stat `strategy_fallbacks` appears in the stats JSON and in the shutdown
  summary, plus one log line per learned destination.

## Tests

`tests/test_clienthello_strategy.cpp` has 17 tests covering learning on
retransmission, stickiness, carry-over to new flows, per-destination and
per-port isolation, in-order attempts not being blamed, the retransmission
window, TTL re-probe, the capacity bound, and the contents of the fallback
profile.

Full suite: 1440 tests, 1432 passed, 8 skipped (I2P/SAM), 0 failed.

## Live verification (`driver_report20.txt`, elevated, all modules on)

| preset       | pass 1 (cold)                       | pass 2 (learnt)        | fallbacks |
|--------------|-------------------------------------|------------------------|-----------|
| runet-strong | example/cloudflare/youtube FAIL 9 s | all 6 OK, 95–148 ms    | 4         |
| autoprobe    | example/cloudflare/youtube FAIL 9 s | all 6 OK, 75–202 ms    | 3         |
| runet-soft   | all 6 OK                            | all 6 OK               | 0         |

Before the multi-split change, `autoprobe` pass 2 still failed on youtube
(`driver_report19.txt`).

## Known limitation

The first connection to a destination that does not tolerate reordering still
fails. That flow is already poisoned before its retransmission is seen, so it
cannot recover. Browsers retry, so this costs one slow first load per
destination, and it happens again after the 600 s TTL. A possible next step is to
switch the whole preset to in-order once several destinations have needed the
fallback.

On this ISP the recommended choice is still `ncp run --preset runet-soft`.
