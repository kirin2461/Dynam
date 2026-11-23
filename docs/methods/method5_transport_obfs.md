# Method 5 — Adaptive Transport Selection with Decoy-Fronted Framing (ATS-DF)

> Engineering design note for the NCP C++ networking library. It describes a
> pluggable transport-selection module and a framing wrapper, at the level of
> interfaces, wire format, and testability. No claim is made about defeating a
> specific deployed system; evaluation is confined to the project's own lab and
> unit tests.

## 1. Technique name + idea

**Adaptive Transport Selection with Decoy-Fronted Framing (ATS-DF).** A policy
layer that unifies the existing per-protocol rotation and AS-aware routing into a
single feedback-driven selector, plus a thin framing wrapper that prepends an
already-protected (indistinguishable-from-random) header prefix to the first
bytes of any chosen transport. The selector consumes live success/failure signals
(the same signals the AutoPilot ML feature collects) to pick among
Reality / porthop / fog / WS-tunnel / QUIC, and demotes transports that show
probe-like failures. The framing wrapper ensures the *first flight* of every
transport shares one statistical shape, so a classifier cannot fingerprint the
transport from its opening bytes.

## 2. How it works

1. **Unified selection.** `ProtocolRotationSchedule` (time/threat-driven) and
   `ASAwareRouter` (ASN load-balancing) are combined behind one `choose()` that
   also factors a per-transport health score updated from connection outcomes.
2. **Decoy-fronted framing.** Before handing bytes to the transport, the first
   `N` bytes are a per-session HKDF-derived prefix produced by the existing
   `HeaderProtection` primitive, so all transports open with a keyed,
   signature-free prefix (no static magic to match).
3. **Feedback demotion.** On repeated open-failures or probe-shaped resets, the
   selector lowers that transport's score and rotates; recovery is rate-limited
   with exponential backoff (mirrors AutoPilot's janitor semantics).

## 3. Difference from existing code

- `src/core/src/ncp_transport_manager.cpp:183` `ProtocolRotationSchedule::should_rotate()`
  rotates on **time/threat only**; ATS-DF adds an outcome-driven health score.
- `src/core/src/ncp_transport_manager.cpp:510` `ASAwareRouter::is_balanced()` /
  `rebalance()` balance by **ASN load**, with no notion of transport health;
  ATS-DF composes both into one decision.
- `src/core/src/ncp_rotation_coordinator.cpp` coordinates rotation but does not
  consume live bypass-success feedback; ATS-DF closes that loop.
- `src/core/src/ncp_header_protection.cpp:103` `HeaderProtection::prefix()` already
  produces keyed per-session prefixes for porthop/fog/AEMM frames; ATS-DF
  **reuses** it as a universal front for *all* transports rather than only those
  three frame types.
- `src/core/src/ncp_protocol_morph.cpp:221` mutates ALPN/TLS profile per
  connection; ATS-DF is a level above (which transport), and composes with morph.

## 4. C++ reference sketch

No new dependencies; reuses `HeaderProtection` and the existing transport enums.

```cpp
// ncp_transport_manager.hpp (additions)
namespace ncp {

enum class TransportKind { Reality, Porthop, Fog, WsTunnel, Quic };

struct TransportHealth {
    double score = 1.0;        // 1.0 = healthy, decays on failure
    uint32_t consecutive_fail = 0;
    std::chrono::steady_clock::time_point cooldown_until{};
};

class AdaptiveTransportSelector {
public:
    void set_rotation(ProtocolRotationSchedule* r)  { rot_ = r; }
    void set_router(ASAwareRouter* a)               { router_ = a; }

    // Pick a transport given current ASN + threat; honors cooldowns.
    TransportKind choose(uint32_t asn, ThreatLevel threat);

    // Feedback from the connection director.
    void report_success(TransportKind k);
    void report_failure(TransportKind k, bool probe_like);

private:
    std::mutex mu_;
    std::map<TransportKind, TransportHealth> health_;
    ProtocolRotationSchedule* rot_ = nullptr;
    ASAwareRouter* router_ = nullptr;
};

} // namespace ncp
```

```cpp
// ncp_transport_manager.cpp (additions)
TransportKind AdaptiveTransportSelector::choose(uint32_t asn, ThreatLevel threat) {
    std::lock_guard<std::mutex> lk(mu_);
    const auto now = std::chrono::steady_clock::now();

    // Candidate order from the time/threat schedule, then re-ranked by health.
    std::vector<TransportKind> cand = rot_ ? rot_->ordered_candidates(threat)
                                           : default_order();
    std::stable_sort(cand.begin(), cand.end(),
        [&](TransportKind a, TransportKind b) {
            return health_[a].score > health_[b].score;
        });

    for (TransportKind k : cand) {
        auto& h = health_[k];
        if (now < h.cooldown_until) continue;   // skip cooling-down transports
        return k;
    }
    return cand.empty() ? TransportKind::Reality : cand.front();
}

void AdaptiveTransportSelector::report_failure(TransportKind k, bool probe_like) {
    std::lock_guard<std::mutex> lk(mu_);
    auto& h = health_[k];
    h.score = std::max(0.05, h.score * (probe_like ? 0.4 : 0.7));
    if (++h.consecutive_fail >= 3) {
        const auto backoff = std::chrono::seconds(30 * h.consecutive_fail);
        h.cooldown_until = std::chrono::steady_clock::now() + backoff;
    }
}

void AdaptiveTransportSelector::report_success(TransportKind k) {
    std::lock_guard<std::mutex> lk(mu_);
    auto& h = health_[k];
    h.consecutive_fail = 0;
    h.score = std::min(1.0, h.score + 0.1);
}
```

The decoy-fronted prefix is applied where each transport writes its first flight,
calling `HeaderProtection::prefix(tag, out, ...)` with a per-transport `tag`.

## 5. Integration points

- `src/core/src/ncp_connection_director.cpp`: call `choose()` on connect, and
  `report_success/report_failure` from the existing outcome callbacks.
- `src/core/src/ncp_rotation_coordinator.cpp`: delegate the "which transport"
  decision to `AdaptiveTransportSelector`, keeping its scheduling role.
- `src/core/src/ncp_header_protection.cpp`: reused unchanged for the front prefix.
- Feeds and is fed by the AutoPilot ML feature (Task 1): failure signals are the
  same features the learner records.

## 6. Testability + caveats

- **Unit tests** (`tests/`): deterministic selection given seeded health scores;
  cooldown is honored; 3-failure threshold triggers backoff; success restores
  score; probe-like failures decay faster. Prefix front: assert first `N` bytes
  match `HeaderProtection::matches()` and carry no static magic.
- **Lab**: run transport rotation under `docker-compose.lab.yml` and confirm a
  forced transport failure causes demotion and rotation without connection loss.
- **Caveats**: health scores are heuristic; an adversary that fails a transport
  *selectively* could bias selection — mitigated by backoff and periodic
  re-probing, but not eliminated. Review-only; not built or runtime-verified here.
