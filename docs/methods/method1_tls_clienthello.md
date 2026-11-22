# Method 1 — TLS Record / ClientHello Manipulation

**Lane:** TLS record layer / ClientHello wire manipulation
**Author:** METHOD-AGENT 1 of 5 (Dynam / NCP C++, v1.7.6)
**Status:** Design + reference sketch only (no build in this environment)

---

## 1. Technique name + idea

**Technique: "Boundary-Straddle ClientHello" (BSCH) — split the SNI hostname
*inside a single TLS record* across two TLS records whose framing is
deliberately re-negotiated at the wire level.**

Instead of splitting the *TCP stream* at the SNI offset (what Dynam does today),
BSCH re-frames one `ClientHello` into **two legal TLS handshake records** where
the *first* record's declared length ends in the middle of the SNI hostname, and
the *second* record carries the remainder. TLS permits a handshake message to
span multiple records (RFC 8446 §5.1 — "Handshake messages MAY be coalesced …
[or] fragmented across several records"). A spec-compliant TLS stack at the
server reassembles the handshake message and reads one correct `ClientHello`. A
reassembling DPI that keys on *"find the SNI string in the first handshake
record"* — the common cheap path — sees a hostname that is cut at the record
boundary and never matches its blocklist. The trick is purely at the **TLS
record framing layer**: it does not touch TCP sequence numbers, IP TTLs, or
checksums, so it survives on-path TCP normalizers that would coalesce TCP
segments (and thus defeat today's TCP split).

---

## 2. What it does at the wire level, and why it defeats a reassembling DPI

### Input
A single, complete, single-record `ClientHello`:

```
0x16 03 01 | rec_len(2) | 01 | hs_len(3) | <ClientHello body ...>
^record hdr              ^handshake hdr
```

The body contains the `server_name` extension with the hostname bytes at some
offset `S` (located with the existing `ncp::parse_tls_client_hello` /
`find_sni_hostname_offset`).

### Output
Two back-to-back TLS **handshake** records on the same TCP stream:

```
Record A:  16 03 01 | lenA(2) | <first  part of the handshake message>
Record B:  16 03 01 | lenB(2) | <second part of the handshake message>
```

Key rules that make it work and keep it legal:

1. **One handshake message, two records.** The 4-byte handshake header
   (`01 | hs_len`) appears **only once**, at the start of Record A. `hs_len` is
   unchanged — it still describes the whole message. Record A's `lenA` covers
   *part* of that message; Record B's `lenB` covers the rest.
   `lenA + lenB == original_record_len` (the 5-byte record header is re-emitted
   once per record, so two headers appear on the wire instead of one).

2. **Cut point lands inside the SNI hostname.** We choose the record boundary at
   `cut = S + k`, where `S` is the first byte of the hostname and `1 <= k <
   host_len`. So the hostname string `www.exa | mple.com` is physically split by
   the TLS record boundary: `www.exa` ends Record A, `mple.com` begins the
   payload of Record B.

3. **Why a cheap reassembling DPI fails.**
   - A DPI that scans only the *first* TLS record for `server_name` sees a
     truncated hostname (`www.exa`) that matches nothing.
   - A DPI that does TCP reassembly but keeps **per-TLS-record** SNI parsing
     (i.e. it assumes a `ClientHello` is one record, as the vast majority of
     real traffic is) parses Record A as a malformed/short handshake and either
     bails or extracts the truncated name.
   - A DPI that *correctly* treats the handshake as a record-spanning message
     and re-concatenates record payloads **before** re-parsing will defeat BSCH
     — that is the honest threat-model caveat (§6). BSCH raises the DPI's
     required work from "memchr the SNI in record 0" to "stateful TLS record
     reassembly + handshake reassembly," which is the whole point.

4. **No TCP/IP tampering.** Both records are ordinary application bytes written
   to the connected socket. There is no TTL fake, no bad checksum, no sequence
   overlap. A downstream TCP normalizer that coalesces segments **cannot undo**
   the TLS record boundary, because the boundary is encoded in the *content*
   (the two 5-byte record headers), not in packetization. This is the core
   advantage over Dynam's current TCP-level SNI split.

### Optional hardening variants (same framing primitive)
- **BSCH-3**: three records, cut the hostname twice, so even a DPI that peeks at
  the first *two* records misses it.
- **BSCH-pad**: prepend a dummy, self-contained `handshake(0x16)` record of type
  `client_hello` with a decoy SNI *before* Record A, exploiting coalescing-vs-
  first-wins ambiguity. (Kept distinct from Dynam's decoy-SNI, which sends full
  separate fake ClientHellos — see §3.)

---

## 3. How it differs from existing Dynam techniques

| Existing Dynam technique | File:line | What it does | Why BSCH is different |
|---|---|---|---|
| TCP SNI split | `src/core/src/dpi_advanced.cpp:357` (`find_sni_split_points`), `:1002` (used in `process_outgoing`) | Returns byte offsets and splits the **TCP segment** at the SNI offset via `tcp_manip->split_segments`. | BSCH splits at the **TLS record** layer, not the TCP layer. A TCP coalescer re-joins Dynam's segments; it cannot re-join BSCH's record boundary. |
| Generic TLS record chunking | `src/core/src/dpi_advanced.cpp:371` (`split_tls_record`) | Cuts the raw byte buffer into `max_fragment_size` chunks with **no TLS re-framing** — it does not insert new record headers, so it only chunks the stream, not the records. | BSCH emits *valid, independently-framed* TLS handshake records (each with its own `16 03 01 len`), keeping `hs_len` intact. It is TLS-aware re-framing, not blind chunking. |
| RFC 7685 ClientHello padding | `src/core/src/dpi_advanced.cpp:384` (`add_tls_padding`) | Appends a zero `padding` extension and fixes the 3 length fields. Single record out. | BSCH changes *record framing*, not extension content. Complementary: you can pad first, then BSCH-split the padded record. |
| RFC 8446 inner-plaintext padding | `src/core/src/tls_record_padding.cpp:108` (`pad_plaintext`), `:181` (`pad_record`) | Grows record payloads with zero/CSPRNG bytes to normalize sizes. | Size shaping, not SNI concealment. Orthogonal. |
| ECH | `src/core/src/ncp_ech.cpp` (`apply_ech`), used at `src/core/src/dpi_advanced.cpp:943` | Encrypts the inner ClientHello/SNI via HPKE (ext `0xfe0d`). | ECH needs a valid `ECHConfigList` (from DNS HTTPS RR) and server support. BSCH needs **nothing from the server** — it is a unilateral framing trick for the no-ECH fallback path. BSCH is the degraded-mode cousin of ECH. |
| Decoy SNI | `src/core/src/dpi_advanced.cpp:974`–`984` (`create_fake_client_hello`) | Sends *entire separate* fake ClientHello records before the real one. | BSCH-pad's decoy (optional) is a decoy SNI **inside the same handshake-message framing window**, exploiting record-coalescing ambiguity, not a standalone prior ClientHello. |
| Desync confuse (overlap/TTL/OOB/badseq) | `src/core/src/ncp_desync_confuse.cpp:53`–`100` | Raw IPv4/TCP segment descriptors that poison the DPI's **TCP** state machine. | BSCH is 100% in-band TLS content with correct everything-below; it targets the DPI's **TLS record parser**, a different layer, and needs no raw socket. |

**Net gap filled:** Dynam currently has (a) TCP-layer SNI splitting and (b) full
ECH, but **no TLS-record-layer SNI concealment that works without server/ECH
support and survives TCP re-coalescing.** BSCH fills exactly that gap.

---

## 4. C++ reference sketch

Header-only, no new dependencies, uses the existing
`ncp::parse_tls_client_hello` from `ncp_tls_parse.hpp`. Drops into the desync
library next to `ncp_desync_confuse.hpp`.

```cpp
// src/core/include/ncp_tls_boundary_straddle.hpp
#pragma once
//
// Method 1: Boundary-Straddle ClientHello (BSCH).
// Re-frames a single-record TLS ClientHello into N handshake records whose
// record boundaries fall INSIDE the SNI hostname. The handshake header
// (msg_type + hs_len) is emitted once; only record headers multiply.
//
// Pure, allocation-only, no I/O. Output bytes are written to the socket in
// order, exactly like a normal ClientHello would be.

#include <cstdint>
#include <cstddef>
#include <vector>
#include "ncp_tls_parse.hpp"   // ncp::parse_tls_client_hello, is_tls_client_hello

namespace ncp {
namespace tlsframe {

struct BschConfig {
    // Number of TLS records to emit (>= 2). 2 = one cut, 3 = two cuts, ...
    uint8_t  record_count = 2;
    // Minimum bytes of hostname that must sit on EACH side of a cut, so we
    // never emit a zero-length record payload and always truly straddle.
    uint8_t  min_host_bytes_each_side = 1;
    // If true and no usable SNI is found, fall back to a middle-of-record cut
    // (still valid record-spanning framing, just not SNI-targeted).
    bool     fallback_mid_record = true;
};

// Result: ready-to-send wire bytes. On any failure/ineligibility the vector
// contains exactly the original input (never a corrupted record).
inline std::vector<uint8_t> straddle_client_hello(const uint8_t* data,
                                                  size_t len,
                                                  const BschConfig& cfg);

// ---------------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------------

namespace detail {

// Re-emit the single handshake message [hs_start, len) as `cuts.size()+1`
// TLS records. `cuts` are absolute offsets into the ORIGINAL buffer and must be
// strictly increasing, all within (hs_start, len). The 5-byte original record
// header at [0,5) is discarded; fresh record headers are written per fragment.
inline std::vector<uint8_t> reframe(const uint8_t* data, size_t len,
                                    size_t hs_start,
                                    const std::vector<size_t>& cuts) {
    std::vector<uint8_t> out;
    out.reserve(len + cuts.size() * 5);

    // Build fragment boundaries over the handshake-message byte range.
    // Fragment 0 starts at hs_start (so it carries the 4-byte handshake hdr).
    std::vector<size_t> bounds;
    bounds.push_back(hs_start);
    for (size_t c : cuts) bounds.push_back(c);
    bounds.push_back(len);

    const uint8_t ver_hi = data[1];   // reuse the record version bytes (03)
    const uint8_t ver_lo = data[2];   // (01 for TLS1.0-compat record layer)

    for (size_t i = 0; i + 1 < bounds.size(); ++i) {
        const size_t frag_off = bounds[i];
        const size_t frag_len = bounds[i + 1] - bounds[i];
        if (frag_len == 0 || frag_len > 0x4000) return {};  // keep <= 2^14
        out.push_back(0x16);                                 // handshake
        out.push_back(ver_hi);
        out.push_back(ver_lo);
        out.push_back(static_cast<uint8_t>((frag_len >> 8) & 0xFF));
        out.push_back(static_cast<uint8_t>(frag_len & 0xFF));
        out.insert(out.end(), data + frag_off, data + frag_off + frag_len);
    }
    return out;
}

} // namespace detail

inline std::vector<uint8_t> straddle_client_hello(const uint8_t* data,
                                                  size_t len,
                                                  const BschConfig& cfg) {
    std::vector<uint8_t> unchanged(data, data + (data ? len : 0));
    if (!data || len < 9 || cfg.record_count < 2) return unchanged;

    // Must be a single complete record whose length covers the whole buffer,
    // mirroring the strictness of add_tls_padding() (dpi_advanced.cpp:400).
    ncp::TlsClientHelloInfo info = ncp::parse_tls_client_hello(data, len);
    if (!info.valid || info.record_len != len) return unchanged;

    const size_t hs_start = 5;  // handshake header begins right after record hdr

    // Pick cut points inside the SNI hostname when available.
    std::vector<size_t> cuts;
    const uint8_t needed = cfg.record_count - 1;  // number of cuts
    const size_t pad = cfg.min_host_bytes_each_side;

    if (info.sni_value_len > static_cast<size_t>(needed) + 2 * pad) {
        const size_t host_beg = info.sni_value_offset + pad;
        const size_t host_end = info.sni_value_offset + info.sni_value_len - pad;
        const size_t span = host_end - host_beg;
        for (uint8_t i = 0; i < needed; ++i) {
            // Evenly spread the cuts through the hostname interior.
            size_t c = host_beg + (span * (i + 1)) / (needed + 1);
            if (!cuts.empty() && c <= cuts.back()) c = cuts.back() + 1;
            if (c <= hs_start || c >= len) return unchanged;
            cuts.push_back(c);
        }
    } else if (cfg.fallback_mid_record) {
        size_t c = hs_start + (len - hs_start) / 2;
        if (c <= hs_start || c >= len) return unchanged;
        cuts.push_back(c);                 // single mid-record cut, still legal
    } else {
        return unchanged;                  // no usable SNI, fallback disabled
    }

    std::vector<uint8_t> out = detail::reframe(data, len, hs_start, cuts);
    return out.empty() ? unchanged : out;
}

} // namespace tlsframe
} // namespace ncp
```

Notes on the sketch:
- It reuses the vetted, bounds-checked parser in `ncp_tls_parse.hpp` rather than
  re-implementing SNI location, matching the existing style
  (`dpi_advanced.cpp:360` also centralizes SNI offset discovery).
- It is *conservative*: on any ineligibility it returns the original bytes
  verbatim, exactly like `TLSManipulator::add_tls_padding`
  (`dpi_advanced.cpp:394`). It can never emit a corrupted record.
- Output is a single contiguous `std::vector<uint8_t>`: the two (or more) TLS
  records concatenated. The caller writes it with one or more `send()` calls —
  the record boundary is in the bytes, so even a single `send()` preserves it.

---

## 5. Integration points

1. **New technique enum.** Add `TLS_RECORD_STRADDLE` to `EvasionTechnique` in
   `src/core/include/ncp_dpi_advanced.hpp:29`–`34` (TLS-level block), next to
   `TLS_RECORD_SPLIT`.

2. **Pipeline hook.** In `AdvancedDPIBypass::process_outgoing`
   (`src/core/src/dpi_advanced.cpp:905`), add a stage **after** ECH/padding
   (`:972`) and **before** the TCP split stage (`:986`), gated the same way:
   ```cpp
   // === BSCH: TLS-record-layer SNI straddle (Method 1) ===
   if (!cfg.mimicry_managed_tls && cfg.enable_tls_straddle && is_client_hello) {
       auto reframed = ncp::tlsframe::straddle_client_hello(
           working_data.data(), working_data.size(), cfg.bsch);
       if (reframed.size() >= working_data.size()) {
           working_data = std::move(reframed);
           impl_->stats.tls_records_straddled.fetch_add(1,
               std::memory_order_relaxed);
       }
   }
   ```
   Place it before the splitting branch so BSCH and the existing TCP split can
   *compose* (TLS-record straddle, then optional TCP segmentation of the
   resulting multi-record buffer).

3. **Config.** Add `bool enable_tls_straddle` + `BschConfig bsch` to
   `AdvancedDPIConfig` (`ncp_dpi_advanced.hpp:96`), read under `config_mutex`
   into the `cfg` snapshot at `dpi_advanced.cpp:915`–`923` (the existing
   data-race-safe snapshot pattern).

4. **Stats.** Add `std::atomic<uint64_t> tls_records_straddled{0}` alongside
   `tls_records_split` (`ncp_dpi_advanced.hpp:143`) and wire it into the copy
   ctor / `reset()` like the sibling counters.

5. **Zapret-style config mapping (optional).** In `ncp_dpi.cpp` where zapret
   overrides map to advanced config (around `ncp_dpi.cpp:321`–`357`), map a new
   `--tls-straddle` override to `enable_tls_straddle`, so it lives alongside
   `enable_tcp_split` / `enable_multi_layer_split`.

6. **Build.** Header-only — add the `#include` where it is used in
   `dpi_advanced.cpp`; no new `.cpp`, no new dependency, no CMake target change.

---

## 6. Testability + threat-model caveats

### Unit tests (pure function, deterministic — ideal for the existing test style)
A test over `ncp::tlsframe::straddle_client_hello` would assert:

1. **Round-trip validity.** Concatenate the output records' payloads (stripping
   each 5-byte record header); the result must byte-for-byte equal the original
   handshake message (`data[5..len)`). Re-parsing the *reassembled* message with
   `parse_tls_client_hello` must yield the identical `sni`.
2. **True straddle.** For a hostname of length ≥ 4, assert the chosen cut offset
   satisfies `sni_value_offset < cut < sni_value_offset + sni_value_len`, i.e.
   the hostname really is split across the record boundary (no record payload
   contains the full hostname substring).
3. **Framing well-formedness.** Every emitted record starts with `16 03 xx`, its
   declared length equals its payload length, each payload ≤ `0x4000`, and the
   sum of payload lengths equals the original handshake-message length.
4. **Handshake header appears once.** Only the first record's payload begins with
   `01` + a 3-byte `hs_len` equal to the original; later records carry raw
   continuation bytes (no new `01` handshake header).
5. **Conservative fallback.** Non-ClientHello input, truncated/multi-record
   input, `record_len != len`, or hostname too short for `record_count` cuts →
   output is byte-identical to input (never corrupted).
6. **`record_count = 3`** produces 3 records with 2 interior cuts, both inside
   the hostname when it is long enough.

(A fuzz harness feeding random/truncated buffers should only ever yield either a
valid re-framing or the untouched input — never an out-of-bounds read; the
parser already enforces bounds.)

### Threat-model caveats (honest)
- **This is not a guaranteed real-world bypass.** A DPI that performs correct,
  stateful TLS *record reassembly* and then handshake reassembly before SNI
  extraction will see the true hostname and block it. BSCH defeats the common
  *cheap* path ("SNI lives in the first handshake record"), not a fully
  conformant reassembler.
- **Fingerprintability.** Real browsers almost never fragment a `ClientHello`
  mid-SNI across TLS records. A DPI could flag "handshake record boundary inside
  server_name" as anomalous and treat straddling itself as a signal. Use
  sparingly, and prefer ECH (`ncp_ech.cpp`) when an `ECHConfigList` is available;
  BSCH is the **degraded-mode fallback**, not a replacement for ECH.
- **Server tolerance.** Record-spanning handshake messages are legal
  (RFC 8446 §5.1) and widely accepted, but a rare, strict/embedded stack may
  reject them; keep it behind an opt-in config flag and a feature probe.
- **No lower-layer protection.** BSCH does nothing about TCP/IP-level
  fingerprints, timing, or JA3/JA4; it must be combined with the other four
  method-agents' layers for a defensible unified method. BSCH is intentionally
  narrow: one new trick at the TLS record layer.

---

### Summary
BSCH re-frames a ClientHello into multiple legal TLS handshake records whose
boundaries fall *inside* the SNI hostname — a pure TLS-record-layer trick that,
unlike Dynam's current TCP-level SNI split, cannot be undone by a TCP
re-coalescer and needs no server/ECH support, while honestly conceding it only
defeats cheap, non-reassembling SNI extraction.
