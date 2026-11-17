# Fix: porthop client printed an empty host in its echo line

**Date**: 2026-11-16
**File changed**: `src/cli/main.cpp` (`handle_porthop`, one output line)
**Status**: Fixed, rebuilt, verified with a live loopback roundtrip. No test regressions.

---

## Summary

`ncp porthop client` printed the echo confirmation with a blank host field:

```
[*] Sent "hello-porthop" to 127.0.0.1:40002 (epoch 0)
[+] ACK seq=0
[+] Echo from :59327 — "hello-porthop"
              ^ no host, and the port shown is the local one
```

The line reads as though the peer's address failed to resolve. It did not — the
wrong field was being printed.

## Root cause

`PortHopReceived` carries three distinct pieces of addressing information:

```cpp
struct PortHopReceived {
    PortHopFrame frame;
    std::string from_ip;
    uint16_t from_port = 0;   // sender's source port
    uint16_t local_port = 0;  // which bound port received the datagram
};
```

All three are populated on the client path (`ncp_porthop.cpp:960-962`):

```cpp
rec.from_ip = addr_to_ip(from);
rec.from_port = ntohs(from.sin_port);
rec.local_port = local_port_;
```

The CLI printed only `local_port`, and printed it directly after a literal
`"Echo from :"` — so the colon was followed by a local ephemeral port with no
host in front of it. `59327` in the example above is the *local* source port,
not the peer's, so the message was also misleading about what the number meant.

Line 5639 in the same file already does this correctly for the SPA path
(`from " << r.from_ip << ":" << r.from_port`), so the correct pattern was
present — this one line just diverged from it.

## The change

```diff
-                    std::cout << "[+] Echo from :" << r.local_port << " — \"" << text << "\"\n";
+                    std::cout << "[+] Echo from " << r.from_ip << ":" << r.from_port
+                              << " (local port " << r.local_port << ") — \"" << text << "\"\n";
```

`from_ip`/`from_port` identify the peer; `local_port` is retained because it is
genuinely useful when diagnosing port-hop behaviour (it shows which port of the
hop range actually received the datagram), but it is now labelled so it cannot
be mistaken for the peer's port.

## Verification

Live loopback roundtrip — server on `--base-port 40000 --range 8`, client
sending one message:

Before:
```
[*] Sent "hello-porthop" to 127.0.0.1:40002 (epoch 0)
[+] ACK seq=0
[+] Echo from :59327 — "hello-porthop"
```

After:
```
[*] Sent "hello-porthop" to 127.0.0.1:40002 (epoch 0)
[+] ACK seq=0
[+] Echo from 127.0.0.1:40000 (local port 59652) — "hello-porthop"
```

The peer address is now present and correct (`127.0.0.1:40000` is the server's
base port, the expected source of the echo), and the local port is labelled.

The transport itself was working throughout — ACK received, echo payload
returned intact. This was a reporting defect, not a functional one.

### Test suite — no regressions

```
[==========] 1275 tests from 159 test suites ran. (52718 ms total)
[  PASSED  ] 1267 tests.
[  SKIPPED ] 8 tests.
```

Identical to baseline. The 8 skips are `I2PManagerTest.*` (no I2P SAM bridge on
`127.0.0.1:7656`), environmental.

## Why the test suite did not catch this

`PortHopReceived` field population is covered by the porthop tests, and those
pass — they assert that `from_ip`, `from_port` and `local_port` hold the right
values. The defect was purely in the CLI's `std::cout` formatting, one layer
above the tested code, which no test exercises.

This is the same structural gap as the other CLI fixes on this branch: argument
handling and output formatting in `main.cpp` are untested. A test asserting on
the rendered string would catch it; none exists.

## Severity

Cosmetic. No wrong behaviour, no data loss, no security impact — the transport
performed correctly and the payload was delivered. Recorded because the output
actively misleads: an operator debugging a port-hop session would reasonably
read `Echo from :59327` as a connection or address-resolution failure, and the
number shown was the local port rather than the peer's.
