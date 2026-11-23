# Method 3 — QUIC / UDP Initial Parser-Divergence Transport

> Engineering design note for the NCP C++ networking library. This describes a
> protocol-handling module and its testability surface at the level of packet
> formats and parser behavior. It makes **no claim** of defeating any specific
> real-world middlebox; all evaluation is confined to the project's own DPI Lab
> emulator and unit tests.

## 1. Technique name + idea

**QUIC Initial Parser-Divergence (QPD).** A QUIC/UDP sending primitive that emits
a *coalesced* UDP datagram containing a decoy long-header Initial packet followed
by the genuine Initial, such that a lightweight middlebox parser and a
RFC-9000-compliant endpoint resolve the "first" Initial differently. The decoy
carries a well-formed long header with a plausible version and CID lengths, a
valid-looking length varint, and a padded CRYPTO-shaped tail; the real Initial
follows at an offset the compliant server reaches by honoring the decoy's length
field, while a parser that stops at the first SNI-bearing CRYPTO frame latches
onto the decoy.

This generalizes the existing single fake-Initial injection into a **single
datagram** carrying both decoy and real data, removing the timing/ordering
dependence of sending two separate packets.

## 2. Wire-level behavior

A QUIC long header is `form(1) fixed(1) type(2) typebits(4) | version(32) |
dcid_len(8) dcid | scid_len(8) scid | token_len(varint) token |
length(varint) | pn + protected payload`.

QPD builds one UDP payload:

```
[ decoy Initial: valid long header, version=v1, dcid/scid 8–20B,
  token_len=0, length=L_decoy, body = PADDING-shaped random ]
[ real Initial:  the client's actual Initial (SNI inside CRYPTO) ]
```

- RFC 9000 §12.2 lets multiple QUIC packets be **coalesced** in one datagram; a
  compliant server parses the decoy, consumes exactly `L_decoy` bytes, fails to
  decrypt it (unknown keys / PADDING), discards it, and proceeds to the real
  Initial. Discarding an undecryptable coalesced packet is explicitly allowed.
- A middlebox that scans the datagram for the first long-header Initial and
  extracts the SNI from the first CRYPTO frame it can locate sees only the decoy,
  whose CRYPTO frames are absent/garbage — so no SNI is recovered from the
  datagram at the expected offset.

Because the decoy is syntactically valid (it reuses the same construction as
`build_fake_quic_initial`), a parser cannot cheaply reject it as malformed.

## 3. Difference from existing code

- `src/core/src/ncp_quic.cpp:7` `build_fake_quic_initial()` produces a **standalone**
  fake Initial. The WinDivert/proxy paths send these as *separate* decoy
  datagrams (README "fake QUIC Initials"). QPD instead **coalesces** a decoy and
  the real Initial into one datagram, so there is no second packet to drop or
  reorder and no inter-packet timing signal.
- `src/core/src/ncp_ipfrag.cpp:28` `build_ip_fragments()` provides IP-layer
  fragmentation of a QUIC Initial (`--quic-frag`). QPD operates at the **QUIC
  layer** (coalescing), orthogonal to and combinable with IP fragmentation.
- `src/core/src/ncp_real_quic.cpp` (`RealQuicEndpoint`) is the msquic-backed real
  transport; QPD is a *packet-shaping* primitive for the desync path, not a
  replacement for the real endpoint.

## 4. C++ reference sketch

Header-only shape, no new dependencies (reuses `randombytes_*` already used in
`ncp_quic.cpp`). Slots next to `build_fake_quic_initial`.

```cpp
// ncp_quic.hpp (additions)
namespace ncp {

// Build a decoy Initial sized `decoy_len` and coalesce the caller's real
// Initial after it. Returns total bytes written to `out`, or 0 on failure.
size_t build_coalesced_initial(uint8_t* out, size_t out_cap,
                               const uint8_t* real_initial, size_t real_len,
                               size_t decoy_len,
                               uint8_t dcid_len = 8, uint8_t scid_len = 8);

} // namespace ncp
```

```cpp
// ncp_quic.cpp (additions)
size_t build_coalesced_initial(uint8_t* out, size_t out_cap,
                               const uint8_t* real_initial, size_t real_len,
                               size_t decoy_len,
                               uint8_t dcid_len, uint8_t scid_len) {
    if (!out || !real_initial || real_len == 0) return 0;
    if (decoy_len < 64) decoy_len = 64;
    if (decoy_len + real_len > out_cap) return 0;

    // Reuse the vetted decoy builder for the leading packet: it emits a valid
    // long header with a self-consistent length varint and padded tail.
    const size_t n_decoy = build_fake_quic_initial(out, out_cap, decoy_len,
                                                   dcid_len, scid_len);
    if (n_decoy == 0 || n_decoy + real_len > out_cap) return 0;

    // Coalesce: real Initial immediately follows the decoy in the same datagram.
    std::memcpy(out + n_decoy, real_initial, real_len);
    return n_decoy + real_len;
}
```

`std::memcpy` requires `<cstring>` (already a common include in this TU set).

## 5. Integration points

- **WinDivert UDP path** in `src/core/src/ncp_dpi.cpp`: where a fake QUIC Initial
  is currently injected for UDP/443, call `build_coalesced_initial()` with the
  intercepted client Initial as `real_initial` and re-inject the single datagram
  instead of two.
- **Proxy UDP ASSOCIATE** path (`ncp_proxy.cpp`) for the no-admin route.
- Gate by the existing `--ipset` filter (QUIC has no visible SNI, README already
  routes QUIC desync through ipset).

## 6. Testability + caveats

- **Unit test** (`tests/`): assert the output parses as two long-header packets;
  assert `decoy.length` varint equals the decoy body size; assert bytes
  `[n_decoy, n_decoy+real_len)` are byte-identical to the input real Initial;
  fuzz `decoy_len`/`real_len` for bounds (no OOB, returns 0 when over capacity).
- **Lab test**: run through `docker/dpi-emu.py` QUIC path and the real msquic
  server to confirm the compliant server completes the handshake while the
  emulator's SNI extraction reads the decoy offset.
- **Caveats**: coalescing behavior varies by server stack; some may process
  packets in a datagram in an order that defeats the decoy. This is a parser
  *divergence* primitive validated only in-lab — not a guaranteed bypass and not
  attributable to any specific deployed device.
