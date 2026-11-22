# Method 2 — TTL-Staged Dual-Layer Overlap Desync (DLO)

> **Lane:** TCP/IP packet-level desync (L3/L4)
> **Agent:** METHOD-AGENT 2 of 5
> **Status:** design + reference sketch only (no build in this environment)
> **Proposed home:** `ncp::desync` (extends `ncp_desync_confuse.*`), driven from the
> WinDivert loop in `ncp_dpi.cpp` and the raw-socket sender in `network_raw_socket.cpp`.

---

## 1. Technique name + idea

**TTL-Staged Dual-Layer Overlap Desync** (codename **DLO**, namespace `ncp::desync::dlo`).

A single coordinated maneuver that introduces **reassembly ambiguity at *two* layers at once —
the IP-fragment layer (L3) and the TCP-sequence layer (L4) — and gates every poison copy behind
a TTL that expires between the on-path DPI and the destination.** Unlike the current builders,
which replace a whole segment with an *identical-sequence* decoy (`build_overlap`,
`ncp_desync_confuse.cpp:53`) or clean-split an IP packet into *non-overlapping* fragments
(`build_ip_fragments`, `ncp_ipfrag.cpp:28`), DLO emits:

1. a **byte-granular forward TCP sequence overlap** (zapret `split-seqovl` family, never actually
   built in this repo) whose overlap seam is deliberately placed **in the middle of the SNI
   second-level-domain token**, so that a "first-wins" reassembler and a "last-wins" reassembler
   recover **two different hostnames**, and a "strict" reassembler sees an irreconcilable conflict;
   and
2. **overlapping IPv4/IPv6 fragments** that re-declare bytes already present in an earlier
   fragment with *conflicting* content, so the DPI's IP-layer reassembler must also pick a policy
   before it can even hand a byte stream to its TCP reassembler.

Both poison copies (the overlapping low-half of the TCP seqovl *and* the conflicting IP fragment)
ride on a **staged TTL** (`ttl ∈ [1..hops_to_dpi]`, autottl-derived) so they are observed by the
DPI but **silently die before the server**. The destination's kernel therefore only ever receives
one unambiguous, in-order, DF-clean copy of the real bytes and completes the handshake normally;
the DPI, forced to resolve ambiguity at two layers against an endpoint it cannot observe, cannot
reconstruct the real SNI under *any* fixed reassembly policy.

---

## 2. Wire-level behavior & why it defeats a TCP-reassembling DPI

The README combat matrix is explicit: *positional splits score 0 % against the reassembly model;
overlap / bad-checksum / multidisorder are the answer* (`README.md:250`). The reassembling DPI lab
models three overlap policies — `strict`, `permissive-first`, `permissive-last`
(`README.md:224`). The current `build_overlap` only defeats **one** of them (`permissive-first`,
by its own doc comment at `ncp_desync_confuse.hpp:11`). DLO is designed to defeat **all three
simultaneously**, and to do so even against a DPI that performs IP-fragment reassembly.

### 2.1 L4 — byte-granular sequence overlap across the SNI seam

Let the real ClientHello payload be `R[0..N)` with `seq0` the sequence number of its first byte,
and let the SNI second-level-domain token (e.g. `exampl` in `example.com`) occupy bytes
`[s0 .. s1)`. Pick a seam `m` with `s0 < m < s1` (inside the SLD). DLO sends, in this order:

```
    P1  (poison, TTL=low)   seq = seq0            len = m          payload = FAKE[0..m)
    P2  (poison, TTL=low)   seq = seq0+m-K        len = K + (N-m)  payload = FAKE_OVL[..] | FAKE_TAIL
    R   (real,   TTL=full)  seq = seq0            len = N          payload = R[0..N)
```

- `P1` plants a decoy low-half; `P2` *overlaps backward* by `K` bytes into P1's region **and**
  forward over the real SNI tail, but with mismatching content.
- A **permissive-first** DPI keeps `FAKE[0..m)` ⊕ `FAKE_TAIL` → reassembles a decoy hostname.
- A **permissive-last** DPI lets `R` (sent last, full TTL) overwrite — *but only the bytes it
  actually accepts*; because `P2`'s overlap straddles `m` mid-token, a last-wins box that already
  committed the `[seq0+m-K .. m)` bytes to `P2` splices a **hybrid token** (`exam` + `qph…`) that
  matches no blocklist entry.
- A **strict** DPI (reject-on-overlap) sees `P1`/`P2`/`R` all claiming overlapping sequence
  ranges with different bytes → it must either drop the flow's reassembly context (fail-open →
  bypass) or raise a conflict it cannot resolve into a clean SNI string.

The server never faces this: `P1`/`P2` expire in-path (low TTL), so its kernel sees only `R`,
a single clean in-window segment, and parses `example.com` correctly.

### 2.2 L3 — overlapping IP fragments (the layer below the TCP reassembler)

`R` (and optionally the poisons) are additionally emitted as **two overlapping IPv4/IPv6
fragments** rather than one packet or two clean fragments:

```
    F1  offset=0         len=L1 (MF=1)   bytes  R_ip_payload[0 .. L1)
    F2  offset=(L1-8)/8  len=L2 (MF=0)   bytes  CONFLICT[0..8) | R_ip_payload[L1 .. )
```

`F2`'s fragment offset points **8 bytes before** where `F1` ended, so the two fragments *overlap*
by one 8-byte block, and that block carries *different* bytes in `F2` than in `F1`. IP reassembly
overlap handling is famously OS-divergent (BSD/macOS favour the fragment with the lower offset;
Windows/old-Linux favour the last-received; RFC 1858/3128 territory). A DPI's IP reassembler must
therefore pick a policy *before* its TCP reassembler even runs — DLO makes that choice wrong for
whichever policy the DPI uses, while the overlapping/conflicting fragment is again TTL-gated so the
server's reassembler only ever sees the clean copy.

The combination is multiplicative: to recover the real SNI the DPI must guess **both** the IP
overlap policy **and** the TCP overlap policy **and** correctly model that the poison copies it can
see will not reach the server. No fixed-policy reassembler can do all three.

### 2.3 Why staged TTL (not fixed low TTL) matters

`build_ttl_fake` hard-codes a caller-chosen TTL (`ncp_desync_confuse.cpp:68`). DLO derives the
poison TTL from the observed hop count exactly like the existing autottl path
(`ncp_dpi.cpp:2233`): `ttl = hops_to_DPI` (so the poison dies *at or just past* the DPI, maximising
the window where DPI-sees-but-server-doesn't). Fixed `ttl=2` under-shoots when the DPI is >2 hops
away (poison dies before the DPI — no desync) and over-shoots when the server is close (poison
reaches the server — breaks the connection). Staging is what makes the dual-layer overlap safe.

---

## 3. Difference from the existing builders

| Existing builder | File:line | What it does | What DLO adds |
|---|---|---|---|
| `build_overlap` | `ncp_desync_confuse.cpp:53` | Two segments, **identical seq**, segment-granular, decoy payload fully replaces real; decoy TTL defaults 64 (not gated) | **Byte-granular forward seqovl** (`seq0+m-K`, not `seq0`), seam placed **mid-SLD**, poison **TTL-gated**; defeats first/last/strict, not just first-wins |
| `build_ttl_fake` | `ncp_desync_confuse.cpp:68` | Single fake at caller-fixed TTL | TTL is **autottl-derived from hop count** (`= hops_to_DPI`), applied to *every* poison copy at both layers |
| `build_oob_fake` | `ncp_desync_confuse.cpp:80` | seq + 16 MiB (out of window) | DLO poisons stay *in window* on purpose — they must be accepted by the DPI's reassembler to corrupt it |
| `build_badseq_fake` | `ncp_desync_confuse.cpp:92` | seq − 1, correct checksum | Orthogonal; DLO can stack `bad_checksum`/badseq on `P1` as a secondary fooling flag |
| `serialize_segment` | `ncp_desync_confuse.cpp:102` | **IPv4 only**, 20-byte IP hdr, **DF set, frag offset 0** | New `serialize_segment_v6` (IPv6 + Fragment extension header) and a fragmenting serializer that emits **overlapping** fragments — closes the "IPv6 is an open bypass path" gap (`README.md:259`) |
| `build_ip_fragments` | `ncp_ipfrag.cpp:28` | **Non-overlapping** 2-way split, 8-byte aligned, **DF cleared**, same TTL both frags, valid checksum on frag 1 | DLO emits **deliberately overlapping** fragments with **conflicting bytes** in the overlap block and **per-fragment TTL** (poison frag gated, clean frag full) |
| WinDivert disorder/reverse-frag | `ncp_dpi.cpp:2408`, `:2502` | Reorders whole segments; fakes are full-payload copies | DLO's ambiguity is **intra-token** (seam inside the SLD) and **cross-layer**, not reorder-only |

Net: nothing in the repo today produces (a) a sub-segment forward sequence overlap, (b) overlapping
IP fragments, (c) TTL-gated poison at *both* layers, or (d) IPv6 segment/fragment serialization.
DLO is additive — it reuses `ipv4_checksum`/`tcp_checksum` (`ncp_desync_confuse.cpp:27,36`) and the
`Segment`/`ConnTuple` structs unchanged.

---

## 4. C++ reference sketch

Style matches `serialize_segment()` (`ncp_desync_confuse.cpp:102`): manual `write16`/`write32`,
in-house one's-complement checksums, `std::vector<uint8_t>` returns, no new dependencies. Proposed
additions to `ncp_desync_confuse.hpp` / `.cpp`.

```cpp
// ── additions to ncp_desync_confuse.hpp ───────────────────────────────────

namespace ncp { namespace desync { namespace dlo {

/// One wire-ready packet plus the TTL it must be sent with and a note of
/// whether it is a poison (in-path-expiring) or the real survivor.
struct StagedPacket {
    std::vector<uint8_t> bytes;   ///< full IPv4/IPv6 + TCP packet, checksummed
    uint8_t  ttl_or_hlim = 64;    ///< already baked into bytes; echoed for the sender
    bool     poison = false;      ///< true => expected to die before the server
};

/// Parameters for a dual-layer overlap maneuver.
struct DloParams {
    uint32_t seq0 = 0;            ///< sequence of real payload byte 0 (host order)
    uint32_t ack  = 0;
    uint8_t  tcp_flags = 0x18;    ///< PSH|ACK
    uint8_t  poison_ttl = 3;      ///< = hops_to_DPI (autottl-derived by caller)
    uint8_t  real_ttl   = 64;     ///< full path TTL
    size_t   sni_sld_begin = 0;   ///< offset of SLD token start in real payload
    size_t   sni_sld_end   = 0;   ///< offset of SLD token end   in real payload
    size_t   seqovl_back   = 4;   ///< K: bytes P2 overlaps backward into P1
    bool     also_fragment = true;///< additionally emit overlapping IP fragments
    bool     ipv6 = false;        ///< serialize IPv6 (Fragment ext hdr) instead of IPv4
};

/// Build the L4 seqovl triple (P1 poison, P2 poison, R real) for a payload.
/// Seam m is chosen inside [sni_sld_begin, sni_sld_end).
std::vector<StagedPacket> build_seqovl_triple(const ConnTuple& t,
                                              const std::vector<uint8_t>& real_payload,
                                              const std::vector<uint8_t>& fake_payload,
                                              const DloParams& p);

/// Split one already-serialized IPv4/IPv6+TCP packet into TWO OVERLAPPING
/// fragments whose shared 8-byte block differs. frag2 carries `conflict8`
/// in the overlap block; the clean reassembly uses frag1's copy.
/// poison_frag_ttl is applied to the fragment carrying the conflict.
bool build_overlapping_fragments(const std::vector<uint8_t>& packet,
                                 size_t split_block,          // 8-byte-block index
                                 const uint8_t conflict8[8],
                                 uint8_t poison_frag_ttl,
                                 uint8_t clean_frag_ttl,
                                 std::vector<uint8_t>& frag_low,
                                 std::vector<uint8_t>& frag_high);

/// IPv6 counterpart of serialize_segment(): 40-byte fixed header + TCP.
std::vector<uint8_t> serialize_segment_v6(const ConnTuple6& t, const Segment& seg);

}}} // namespace ncp::desync::dlo
```

```cpp
// ── ncp_desync_confuse.cpp (additions) ────────────────────────────────────
//
// Reuses write16/write32/ipv4_checksum/tcp_checksum already in this TU.

namespace ncp { namespace desync { namespace dlo {

static size_t choose_seam(const DloParams& p) {
    // Place the seam in the middle of the SLD so first-wins vs last-wins
    // reassemble different hostnames.
    if (p.sni_sld_end > p.sni_sld_begin + 1)
        return p.sni_sld_begin + (p.sni_sld_end - p.sni_sld_begin) / 2;
    return p.sni_sld_begin;  // degenerate: fall back to token start
}

std::vector<StagedPacket> build_seqovl_triple(const ConnTuple& t,
                                              const std::vector<uint8_t>& real,
                                              const std::vector<uint8_t>& fake,
                                              const DloParams& p) {
    std::vector<StagedPacket> out;
    const size_t N = real.size();
    const size_t m = std::min(choose_seam(p), N);
    const size_t K = std::min(p.seqovl_back, m);

    auto emit = [&](uint32_t seq, const std::vector<uint8_t>& pl,
                    uint8_t ttl, bool poison) {
        Segment s;
        s.seq = seq;
        s.ack = p.ack;
        s.tcp_flags = p.tcp_flags;
        s.ttl = ttl;
        s.payload = pl;
        StagedPacket sp;
        sp.bytes  = serialize_segment(t, s);   // existing IPv4 serializer
        sp.ttl_or_hlim = ttl;
        sp.poison = poison;
        out.push_back(std::move(sp));
    };

    // P1: decoy low-half [0, m), poison.
    if (m > 0 && fake.size() >= m)
        emit(p.seq0, std::vector<uint8_t>(fake.begin(), fake.begin() + m),
             p.poison_ttl, /*poison=*/true);

    // P2: backward-overlap by K + forward over the real tail, poison.
    //   seq = seq0 + m - K ; payload = fake[m-K .. m) | fake_tail(N-m)
    // Only meaningful when there is a fake low-half to overlap into.
    if (N > m && fake.size() >= m) {
        std::vector<uint8_t> p2;
        p2.insert(p2.end(), fake.begin() + (m - K), fake.begin() + m);
        // fake_tail: reuse fake bytes if long enough, else space filler.
        for (size_t i = m; i < N; ++i)
            p2.push_back(i < fake.size() ? fake[i] : static_cast<uint8_t>(0x20));
        emit(p.seq0 + static_cast<uint32_t>(m - K), p2, p.poison_ttl, true);
    }

    // R: the real, full payload, full TTL — the only copy the server keeps.
    emit(p.seq0, real, p.real_ttl, /*poison=*/false);
    return out;
}

// build_overlapping_fragments(): identical header-copy / length / checksum
// bookkeeping to ncp_ipfrag.cpp:68-86, EXCEPT frag_high's fragment offset is
// set to (split_block-1) [i.e. 8 bytes earlier] and its first 8 payload bytes
// are replaced with conflict8; per-fragment TTL is written at ip[8].
// (Full body omitted here for brevity; it is a direct edit of the ipfrag
//  split loop, so it carries no new dependencies.)

}}} // namespace
```

`serialize_segment_v6` mirrors the IPv4 serializer but writes a 40-byte fixed IPv6 header
(version/traffic-class/flow-label word, 2-byte payload length, next-header = 6, hop-limit = TTL,
16-byte src/dst) and uses the IPv6 TCP pseudo-header (128-bit addresses, 32-bit upper-layer length,
3 zero bytes, next-header 6) in place of `tcp_checksum`. A `ConnTuple6` holds `uint8_t src[16]`/
`dst[16]`. For the fragmenting path, IPv6 uses a **Fragment extension header** (next-header 44)
rather than the IPv4 fixed-header offset/MF bits.

---

## 5. Integration points

### 5.1 WinDivert loop (`ncp_dpi.cpp`, Windows driver mode)

The ClientHello handler already computes everything DLO needs:

- `orig_ttl` / autottl-derived TTL (`ncp_dpi.cpp:2223`, `:2233`) → feed `DloParams::poison_ttl`
  (`= hops`) and `real_ttl = orig_ttl`.
- `sni_off` and `midsld_pos` (`ncp_dpi.cpp:2246`, `:2253`) → map to `sni_sld_begin/end`.
- `orig_seq` (`ncp_dpi.cpp:2224`) → `seq0`.

Add a new strategy branch alongside `enable_disorder` / `enable_reverse_frag`
(`ncp_dpi.cpp:2408`, `:2502`), e.g. `effective_cfg.enable_dlo`:

```cpp
} else if (effective_cfg.enable_dlo) {
    DloParams p{ orig_seq, /*ack*/0, /*flags*/0x18,
                 eff_fake_ttl /*=hops*/, orig_ttl,
                 sld_begin, sld_end, /*K*/4, /*frag*/true, /*ipv6*/false };
    auto staged = dlo::build_seqovl_triple(tuple, real_payload, fake_payload, p);
    for (auto& sp : staged) {
        // Poisons first (P1,P2) then the real R — arrival order is what the
        // DPI reassembler sees; the real survives on TTL.
        WinDivertHelperCalcChecksums(sp.bytes.data(), sp.bytes.size(), &addr, 0);
        WinDivertSend(wd_handle_, sp.bytes.data(), sp.bytes.size(), &sent, &addr);
    }
}
```

The overlapping-fragment variant slots into the existing `build_ip_fragments` call site
(`ncp_dpi.cpp:1903`, `:1941`) — swap `build_ip_fragments` for
`dlo::build_overlapping_fragments` when `enable_dlo && also_fragment`, keeping the same two
`WinDivertSend` calls (`ncp_dpi.cpp:1914-1916`). Because WinDivert honours the TTL already in the
packet, no per-socket `IP_TTL` call is needed on this path.

### 5.2 Raw-socket sender (`network_raw_socket.cpp`)

`RawSocketBackend` uses `IP_HDRINCL` (`network_raw_socket.cpp:107`), so the serialized bytes'
TTL/hop-limit field is sent verbatim — `StagedPacket::bytes` can be passed straight to
`send_raw_packet(dst_ip, sp.bytes)` (`network_raw_socket.cpp:196`) in P1→P2→R order. For IPv6,
the backend needs an `AF_INET6` raw socket (currently IPv4-only, `network_raw_socket.cpp:101`);
`serialize_segment_v6` output then flows through an analogous `sendto` to a `sockaddr_in6`.
No change to `send_tcp_packet` is required — DLO deliberately bypasses it because that helper
randomises seq/ID internally (`network_raw_socket.cpp:240,253`), which would break the overlap.

A small sender-side note: emit P1, P2, R **without coalescing** (no Nagle, which is automatic on
raw sockets) and optionally with a sub-millisecond gap so the DPI processes them as three distinct
arrivals rather than one GRO'd blob — the lab already disables GRO/TSO/GSO for this reason
(`README.md:227`).

---

## 6. Testability + threat-model caveats

### 6.1 pcap-level assertions (extend `test_desync_confuse.cpp` + `pcap_assert.py`)

Pure-function unit tests (no sockets), mirroring the existing style at
`tests/test_desync_confuse.cpp:76`:

1. **Seqovl seam is inside the SLD.** For `build_seqovl_triple`, assert `P2.seq == seq0 + m - K`
   with `sld_begin < m < sld_end`, and that `P1.seq == seq0`, `R.seq == seq0`.
2. **TTL staging.** `P1.ttl == P2.ttl == poison_ttl` and `R.ttl == real_ttl`, and
   `poison_ttl < real_ttl`. Assert the byte at IPv4 offset 8 (or IPv6 offset 7) matches.
3. **Overlap really overlaps and really conflicts.** For `build_overlapping_fragments`, decode both
   fragment offsets and lengths and assert their claimed byte ranges intersect by exactly one
   8-byte block, and that the overlapping block bytes differ between `frag_low` and `frag_high`.
4. **Clean-path reassembly recovers the real SNI.** A tiny test reassembler using
   *server* policy (prefer-first-received / drop-expired-TTL, i.e. poisons removed) must yield
   exactly `real_payload`; assert `parse_sni(reassembled) == "example.com"`.
5. **DPI-path reassembly does *not*.** Run the same bytes through all three lab policies
   (`strict`, `permissive-first`, `permissive-last`) *with poisons present* and assert none of them
   yields `example.com` (first→decoy, last→hybrid token, strict→no clean SNI). This is the core
   claim and should be a parametrised test.
6. **Checksums valid.** Reuse `ip_checksum_valid` / `tcp_checksum_valid`
   (`tests/test_desync_confuse.cpp:46,51`) on every non-`bad_checksum` StagedPacket; add an
   IPv6 pseudo-header checker for `serialize_segment_v6`.
7. **Live capture (lab).** Extend `pcap_assert.py` (`README.md:240`): capture the on-wire triple,
   assert three TCP segments with the expected seq/TTL fields and one survivor reaching the veth
   peer; for fragments, assert two IP fragments with overlapping offsets. Wire this into the
   existing DPI-model bypass matrix so DLO gets a bypass-% cell next to `overlap`/`multidisorder`.

### 6.2 Honest caveats

- **Endpoint-policy assumption.** The whole scheme relies on the server's IP/TCP reassembler
  resolving overlaps *differently* from the DPI, and on the poison copies dying in-path. A stack
  that happens to share the DPI's policy, or a path where the poison TTL is mis-estimated (poison
  reaches the server), **breaks the connection**. The autottl derivation (`ncp_dpi.cpp:2233`) is a
  heuristic — a wrong hop estimate silently degrades to either "no desync" or "RST". Gate DLO
  behind the existing hostlist/ipset scoping (`ncp_dpi.cpp:2159`) so a mis-fire can't take down
  unrelated flows.
- **Overlapping fragments are conspicuous.** RFC 1858/3128 overlapping fragments are a classic IDS
  signature; a DPI that *drops overlapping fragments outright* defeats the L3 half (though that is
  itself a fail-closed behaviour the L4 seqovl half still attacks). Treat `also_fragment` as an
  optional, higher-risk tier, not the default.
- **Middlebox fragment reassembly / PMTUD.** Some carriers reassemble fragments before the DPI, or
  drop fragments entirely; on such paths the L3 layer is a no-op and only the L4 seqovl applies.
- **Stateful "fail-closed" DPI.** A reassembler that drops the *flow* on unresolved conflict
  (rather than failing open) turns DLO into a self-DoS. The bypass-% matrix test (6.1 §5) is the gate:
  ship only the cells that empirically pass, exactly as the README already distinguishes
  working vs. 0 % strategies (`README.md:248-254`).
- **IPv6 raw sockets need privilege + stack support** and are IPv4-only today in the raw backend
  (`network_raw_socket.cpp:101`); the WinDivert path handles IPv6 more readily and is the preferred
  carrier for the v6 variant.
- **No new dependencies, no replacement of existing builders.** DLO is purely additive and reuses
  the audited checksum/serializer primitives; it does not change `build_overlap`, `build_ttl_fake`,
  `build_ip_fragments`, or their tests.

---

### Coordinator merge note

DLO lives in `ncp::desync::dlo` and is exposed through one new `DPIConfig` flag
(`enable_dlo`, plus `dlo_also_fragment`, `dlo_ipv6`) consumed in the WinDivert ClientHello handler.
It composes cleanly with the other agents' layers: it operates strictly below TLS (so ECH / TLS
fingerprinting at L7 are unaffected) and emits standard-looking IPv4/IPv6+TCP packets that any
later L2/timing stage can further shape.
