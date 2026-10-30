#include "ncp_mimicry_session.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <stdexcept>
#include <utility>

/**
 * @file ncp_mimicry_session.cpp
 * @brief Per-session adapter implementation. See the header for the contract.
 *
 * Adapter-level datagram kinds (first byte of every PortHop payload):
 *   'H' — raw E2E key-exchange blob
 *   'C' — serialized E2E EncryptedMessage of a tagged capabilities message
 *   'E' — outer-mimicked serialized E2E EncryptedMessage (control or data)
 *   'P' — insecure plaintext compatibility datagram (gated, pre-handshake)
 *
 * All E2ESession / TrafficMimicry calls are exception-guarded at the API
 * boundary: a crypto failure is a transport-level drop (inbound) or a
 * nullopt/empty queue (outbound), never a propagated exception.
 */

namespace ncp {

namespace {

constexpr uint8_t kKindHandshake = 'H';
constexpr uint8_t kKindCaps      = 'C';
constexpr uint8_t kKindE2E       = 'E';
/// Explicit insecure plaintext compatibility datagrams. Dropped unless
/// Config::allow_insecure_plaintext_legacy is set, and never accepted once
/// the E2E session is established.
constexpr uint8_t kKindPlaintext = 'P';

/// HKDF contexts for per-session derivation from the established E2E shared
/// secret. Both endpoints derive identical values independently.
constexpr const char* kSessionIdContext = "ncp-mimicry-session/pt-id-v1";
constexpr const char* kShaperSecretContext = "ncp-mimicry-session/shaper-v1";
constexpr const char* kMaskKeyContext = "ncp-mimicry-session/mask-v1";

/// Default mimicry wire version pinned when the caller left it at 0
/// (0 would randomize per instance and desynchronize the two peers).
constexpr uint8_t kDefaultMimicWireVersion = 3;

/// v2 transition-grace floor (MEDIUM-2): under the v2 C1 control-mask pin,
/// post-activation control retransmits are decodable ONLY via the old-grace
/// RX candidate, which lives until activation + grace_period_ms. With the
/// historical defaults (grace 1000 ms, retransmit 200 ms x 5 = 1000 ms) the
/// retransmit budget exactly consumes the grace window, so tail retransmits
/// at RTT >= ~100-200 ms would land after grace expiry and force an
/// uncertain divergence (unrepairable in-band by design). When v2 is
/// negotiated the effective grace is therefore raised to at least the full
/// retransmit budget plus a fixed margin of kV2GraceMarginIntervals
/// retransmit intervals. v1-negotiated sessions keep the configured grace
/// exactly (byte-identical v1 behavior).
constexpr uint32_t kV2GraceMarginIntervals = 2;

/// The v2 grace floor: retransmit_interval_ms * max_retransmit_attempts
/// (full budget) + kV2GraceMarginIntervals * retransmit_interval_ms
/// (margin). Overflow-saturated to uint32_t.
uint32_t v2_grace_floor_ms(const ProfileTransitionConfig& tc) {
    const uint64_t interval = tc.retransmit_interval_ms;
    const uint64_t budget = interval * tc.max_retransmit_attempts;
    const uint64_t floor = budget + interval * kV2GraceMarginIntervals;
    return static_cast<uint32_t>(
        floor > UINT32_MAX ? UINT32_MAX : floor);
}

/// Transition-target outer-mask gate. The outer mask swaps to the pending
/// profile SYNCHRONOUSLY at local activation (epoch observer). Under
/// transition protocol v1 the COMMIT/CONFIRM the activating side emits right
/// after the swap are already wrapped with the NEW mask while the peer still
/// decodes with the old + (grace) previous mask, so only the
/// length-prefix-compatible generic masks keep those datagrams decodable
/// across the switch; any other target (DNS_QUERY, TLS, ...) would make the
/// confirmation traffic undecodable and silently diverge the profile state
/// permanently. Under v2 the control mask is pinned to the
/// transition-stable mask (C1) and the pending mask is an RX candidate (C3),
/// which removes that coupling for ARBITRARY target masks.
///
/// v2_gate_open == the session negotiated profile_transition_v2 (both peers
/// advertised V1∧V2). With the gate closed the exact v1 refusal paths apply:
/// start_profile_transition -> INVALID_PROFILE (no state change, no control
/// traffic), and a PREPARE resolving to a non-generic mask is refused with
/// ABORT(UNKNOWN_PROFILE).
bool is_transition_target_mimic(TrafficMimicry::MimicProfile p,
                                bool v2_gate_open) {
    if (v2_gate_open) return true;
    return p == TrafficMimicry::MimicProfile::GENERIC_UDP ||
           p == TrafficMimicry::MimicProfile::GENERIC_TCP;
}

// ---- FSM-driven mask variants (step 6, design §3.4) ----
//
// Fixed built-in family variant maps — constant, not host-configurable in v2
// scope. Keyed by FSM state name; the reference models (§3.2) name states
// after the lifecycle phases. A stateful profile is one profile whose
// engaged FSM state selects among the family's mask variants per datagram.

/// The distinct masks of a family's variant map, in a FIXED order (RX
/// sibling-candidate order). Empty for families without a variant map;
/// emptiness is also the "no variants" test used by TX and RX.
std::vector<TrafficMimicry::MimicProfile>
family_variant_masks(ProtocolFamily fam) {
    using MP = TrafficMimicry::MimicProfile;
    switch (fam) {
        case ProtocolFamily::QUIC:
            return {MP::QUIC_INITIAL, MP::QUIC_SHORT_HEADER};
        case ProtocolFamily::WEBRTC:
            // SRTP_LIKE is deferred (needs ROC/SRC state); the data state
            // falls back to STUN_MESSAGE per design §3.4.
            return {MP::STUN_MESSAGE};
        default:
            return {};
    }
}

/// TX-side variant selection: the mask for the engaged FSM's current state,
/// or nullopt when the state is not in the family map (caller falls back to
/// the active mask). Pure function of (family, state name); the family comes
/// from the hash-bound active profile descriptor (I-V2-5).
std::optional<TrafficMimicry::MimicProfile>
variant_for_state(ProtocolFamily fam, const std::string& state) {
    using MP = TrafficMimicry::MimicProfile;
    switch (fam) {
        case ProtocolFamily::QUIC:
            if (state == "bootstrap" || state == "handshake")
                return MP::QUIC_INITIAL;
            if (state == "established" || state == "data")
                return MP::QUIC_SHORT_HEADER;
            return std::nullopt;
        case ProtocolFamily::WEBRTC:
            if (state == "handshake" || state == "established" ||
                state == "data")
                return MP::STUN_MESSAGE;
            return std::nullopt;
        default:
            return std::nullopt;
    }
}

/// Extract the peer's public key from a DH-style key-exchange blob:
/// [ver:1][proto:1][pk_len:2 BE][pk ...]. Returns false for malformed or
/// KEM-style (Kyber) blobs — peer-key extraction is only defined for the
/// stateless DH key exchanges this adapter supports.
bool extract_peer_public_key(const std::vector<uint8_t>& blob,
                             std::vector<uint8_t>& out) {
    if (blob.size() < 4) return false;
    const uint16_t pk_len = static_cast<uint16_t>(
        (static_cast<uint16_t>(blob[2]) << 8) | blob[3]);
    if (pk_len == 0 || blob.size() < 4u + pk_len) return false;
    out.assign(blob.begin() + 4, blob.begin() + 4 + pk_len);
    return true;
}

uint64_t round_up_worst(uint64_t n, uint32_t block) {
    if (block <= 1) return n;
    return ((n + block - 1) / block) * block;
}

bool valid_path_state(const PathState& p) {
    if (p.outer_transport == OuterTransportKind::TurnSendData &&
        !p.turn_send_data_bootstrap) return false;
    if (p.hop_policy == PathHopPolicy::Disabled &&
        p.porthop_padding_headroom != 0) return false;
    return true;
}

uint64_t outer_path_overhead(const PathState& p) {
    uint64_t n = kUdpHeaderBytes;
    n += p.ip_version == PathIpVersion::IPv4 ? 20 : 40;  // unknown => safe IPv6
    switch (p.outer_transport) {
        case OuterTransportKind::Direct: break;
        case OuterTransportKind::TurnChannelData:
            n += kTurnChannelDataHeaderBytes;
            if (p.turn_channeldata_padding) n += 3;
            break;
        case OuterTransportKind::TurnSendData:
            n += p.ip_version == PathIpVersion::IPv6 ? 48 : 36;
            break;
    }
    if (p.hop_policy == PathHopPolicy::LegacyPortHop)
        n += kPortHopHeaderBytes + p.porthop_padding_headroom;
    return n;
}

/// Exact worst-case encoded IP packet size for one application payload.
/// Returns nullopt for a mask without a declared bounded encoding.
std::optional<uint64_t> worst_packet_size(
    size_t payload_size, const NcpMimicrySession::Config& cfg,
    const ProfileLayoutParams& layout, TrafficMimicry::MimicProfile mimic,
    bool profile_capable, const PathState& path) {
    if (!valid_path_state(path) ||
        payload_size > MAX_PROFILE_DATA_PAYLOAD_BYTES) return std::nullopt;

    uint64_t plain = payload_size;
    if (profile_capable) {
        // PD body (magic/version/epoch/length[9] + payload) is padded first;
        // the NCP magic[3] + type[1] tag is then prepended WITHOUT padding.
        plain = round_up_worst(plain + 9, layout.padding_block_bytes) + 4;
    }
    if (cfg.e2e_config.enable_padding) {
        // ISO7816-4 always appends 0x80, then pads to a 128-byte block.
        plain = round_up_worst(plain + 1, 128);
    }

    // EncryptedMessage v3: fixed header 9 + six uint16 blob lengths 12 +
    // DH public 32 + outer nonce 24. The separate auth_tag and nested header
    // nonce/associated-data blobs are empty: the AEAD tag is already in the
    // ciphertext on this adapter's data path.
    uint64_t wire = plain + 93;
    uint64_t masked = 0;
    switch (mimic) {
        case TrafficMimicry::MimicProfile::GENERIC_UDP:
            masked = wire + 4;
            break;
        case TrafficMimicry::MimicProfile::GENERIC_TCP:
            masked = wire + 4;
            if (cfg.mimic_config.enable_size_mimicry)
                masked += static_cast<uint32_t>(
                    std::max(0, cfg.mimic_config.max_padding));
            break;
        case TrafficMimicry::MimicProfile::QUIC_SHORT_HEADER:
            masked = wire + 62;
            break;
        case TrafficMimicry::MimicProfile::STUN_MESSAGE:
            // STUN header 20 + payload attr header 4 + wire version/length 5
            // + MI attr 24, with the payload attribute aligned to 4 bytes.
            masked = 48 + round_up_worst(wire + 5, 4);
            break;
        case TrafficMimicry::MimicProfile::QUIC_INITIAL:
            masked = std::max<uint64_t>(
                wire + 79,
                static_cast<uint64_t>(cfg.mimic_config.quic_min_packet_size));
            break;
        default:
            return std::nullopt;
    }
    return masked + 1 /* adapter kind */ + outer_path_overhead(path);
}

} // namespace

struct NcpMimicrySession::Impl {
    Config cfg;

    // ---- crypto (owned per session) ----
    E2ESession e2e;
    KeyPair keys;
    bool handshake_started = false;

    // ---- profile transition context (created once the E2E session is
    // established; the transition session_id is derived from the shared
    // secret) ----
    std::unique_ptr<SessionProfileContext> ctx;
    std::optional<NCPCapabilities> peer_caps;

    // ---- outer mask (per-session; never global) ----
    TrafficMimicry outer;
    TrafficMimicry::MimicProfile active_mimic;
    ProfileLayoutParams active_layout;
    PathState current_path;
    std::optional<TrafficMimicry::MimicProfile> pending_mimic;
    std::optional<TrafficMimicry::MimicProfile> old_mimic;  // grace decoder

    // ---- transition protocol v2 (session-wide capability) ----
    // Set in handle_caps(): strict AND of both peers' V2 bits AND the
    // negotiated V1 bit (v2 ⇒ v1; fail-closed on a stripped bit). While
    // false, every v1 code path below is byte-identical to pre-v2 behavior.
    bool v2_negotiated = false;
    // Per-session mask binding key (HKDF from the E2E shared secret), set
    // into the TrafficMimicry config at finalize_handshake(). Only the
    // stateful v2 masks consume it; generic masks ignore it.
    std::array<uint8_t, 32> mask_key{};

    // ---- per-session shaper (catalog-derived; disengaged without catalog) --
    std::unique_ptr<MimicryShaper> shaper;
    std::array<uint8_t, SessionSecret::kSize> shaper_secret_snapshot{};
    uint64_t shaper_session_tag = 0;
    std::string shaper_profile_name;

    // ---- per-session FSM shape/timing source (catalog-derived; engaged only
    // while the active profile's descriptor carries fsm.enabled). When set,
    // data packets take pacing from the FSM instead of the shaper; control
    // packets never consume FSM data shapes. The FSM borrows the catalog
    // descriptor, so the (caller-owned) catalog must outlive this session —
    // the same lifetime rule the shaper re-derivation already relies on.
    std::unique_ptr<MimicryFsmSession> fsm;
    // Mask-variant family of the hash-bound active profile descriptor,
    // (re)bound together with the FSM (rebind_fsm). Set only while the FSM
    // is engaged AND the descriptor's family has a variant map; feeds the
    // TX variant selection (send_application) and the RX sibling candidate
    // (handle_e2e). Derived exclusively from the catalog descriptor — never
    // from runtime FSM state — so both endpoints agree on the variant set
    // (I-V2-5).
    std::optional<ProtocolFamily> variant_family;

    // ---- outbound reaction queue (poll-loop drained) ----
    // Structurally bounded (I-DRAIN-8): see queue_push(). The byte counter
    // tracks the sum of OutboundDatagram::bytes sizes currently queued.
    std::deque<OutboundDatagram> out_q;
    size_t out_q_bytes = 0;

    // ---- counters ----
    uint64_t mtu_budget_rejections = 0;
    uint64_t ingress_dropped = 0;
    uint64_t queue_dropped_packets = 0;  // refused by queue bounds (I-DRAIN-8)
    uint64_t queue_dropped_bytes = 0;
    // I-TXD-2: exact RX candidate work accounting. *_max are per-datagram
    // maxima, structurally <= kMaxRxCandidates (enforced in handle_e2e).
    uint64_t candidate_unwrap_attempts_total = 0;
    uint64_t candidate_aead_attempts_total = 0;
    uint32_t candidate_unwrap_attempts_max = 0;
    uint32_t candidate_aead_attempts_max = 0;

    explicit Impl(Config c)
        : cfg(std::move(c)), e2e(cfg.e2e_config),
          active_mimic(cfg.stable_mimic), active_layout(cfg.stable_layout) {
        if (cfg.hop_policy == PathHopPolicy::LegacyPortHop) {
            if (cfg.porthop_overhead_bytes <
                kPortHopHeaderBytes + cfg.porthop_padding_headroom_bytes) {
                throw std::invalid_argument(
                    "porthop_overhead_bytes under-reserves PH header/padding");
            }
        } else if (cfg.porthop_padding_headroom_bytes != 0) {
            // valid_path_state() rule, enforced at creation: padding
            // headroom only exists under the LegacyPortHop policy.
            throw std::invalid_argument(
                "porthop_padding_headroom_bytes requires "
                "PathHopPolicy::LegacyPortHop");
        }
        if (cfg.outer_transport == OuterTransportKind::TurnSendData) {
            // TurnSendData is a bootstrap-phase mode only (see
            // ncp_datagram_path.hpp); fail before any socket/session work.
            throw std::invalid_argument(
                "outer_transport TurnSendData is bootstrap-only");
        }
        current_path.effective_mtu = cfg.path_mtu_bytes;
        current_path.ip_version = PathIpVersion::IPv4;
        current_path.outer_transport = cfg.outer_transport;
        current_path.hop_policy = cfg.hop_policy;
        current_path.porthop_padding_headroom =
            cfg.hop_policy == PathHopPolicy::LegacyPortHop
                ? cfg.porthop_padding_headroom_bytes
                : 0;
        TrafficMimicry::MimicConfig mc = cfg.mimic_config;
        if (mc.wire_version == 0) mc.wire_version = kDefaultMimicWireVersion;
        mc.profile = active_mimic;
        // Direction-distinct STUN transaction-id streams (v2 mask): the
        // adapter knows its endpoint Role, standalone use keeps role 0.
        mc.endpoint_role = (cfg.role == Role::Server) ? 2 : 1;
        outer.set_config(mc);
        keys = e2e.generate_key_pair();
    }

    size_t datagram_budget() const {
        return cfg.path_mtu_bytes > cfg.porthop_overhead_bytes
                   ? cfg.path_mtu_bytes - cfg.porthop_overhead_bytes
                   : 0;
    }

    size_t max_application_datagram(const PathState& supplied) const {
        PathState path = supplied;
        if (path.effective_mtu == 0) path.effective_mtu = kUnknownPathMtuBasis;
        if (!valid_path_state(path)) return 0;
        const bool profile_capable = ctx
            ? ctx->manager().peer_capable()
            : cfg.advertise_profile_transition;

        std::vector<TrafficMimicry::MimicProfile> masks{active_mimic};
        if (v2_negotiated && !cfg.disable_mask_variants && fsm &&
            variant_family) {
            for (auto m : family_variant_masks(*variant_family))
                if (std::find(masks.begin(), masks.end(), m) == masks.end())
                    masks.push_back(m);
        }
        auto fits = [&](size_t n) {
            for (auto m : masks) {
                auto size = worst_packet_size(n, cfg, active_layout, m,
                                              profile_capable, path);
                if (!size || *size > path.effective_mtu) return false;
            }
            return true;
        };

        size_t lo = 0;
        size_t hi = std::min(cfg.max_application_payload,
                             MAX_PROFILE_DATA_PAYLOAD_BYTES);
        if (!fits(0)) return 0;
        // Invariant: lo fits, hi is only an upper bound (not assumed to fit).
        while (lo < hi) {
            const size_t mid = lo + (hi - lo + 1) / 2;
            if (fits(mid)) lo = mid;
            else hi = mid - 1;
        }
        return lo;
    }

    /// Mirror the authoritative, monotonic E2E crypto epoch into the
    /// transition context. Called at context creation, at every API entry
    /// point that can emit or process control, and after every successful
    /// decrypt/rekey, so outbound control always binds the current epoch.
    /// The adapter never invents an epoch counter of its own.
    void sync_crypto_epoch() {
        if (!ctx) return;
        try {
            ctx->set_crypto_epoch(e2e.get_crypto_epoch());
        } catch (...) {
        }
    }

    // ---- outer mask helpers (stateless profiles only) ----

    std::vector<uint8_t> outer_wrap(const std::vector<uint8_t>& in,
                                    TrafficMimicry::MimicProfile p) {
        try {
            return outer.wrap_payload(in, p);
        } catch (...) {
            return {};
        }
    }

    std::vector<uint8_t> outer_unwrap(const std::vector<uint8_t>& in,
                                      TrafficMimicry::MimicProfile p) {
        try {
            return outer.unwrap_payload(in, p);
        } catch (...) {
            return {};
        }
    }

    // ---- crypto hooks for SessionProfileContext (exception-guarded) ----

    SessionProfileContext::Crypto make_crypto() {
        SessionProfileContext::Crypto c;
        c.encrypt = [this](const std::vector<uint8_t>& pt)
            -> std::vector<uint8_t> {
            try {
                return E2EUtils::serialize_message(e2e.encrypt(pt));
            } catch (...) {
                return {};  // outbound handler drops empty wires
            }
        };
        c.decrypt = [this](const std::vector<uint8_t>& wire)
            -> std::optional<std::vector<uint8_t>> {
            try {
                auto m = E2EUtils::deserialize_message(wire);
                if (!m) return std::nullopt;
                auto pt = e2e.decrypt(*m);
                if (pt) sync_crypto_epoch();  // a successful decrypt may have
                                              // committed a DH ratchet step
                return pt;
            } catch (...) {
                return std::nullopt;
            }
        };
        c.decrypt_ex = [this](const std::vector<uint8_t>& wire)
            -> std::optional<std::pair<std::vector<uint8_t>, uint64_t>> {
            try {
                auto m = E2EUtils::deserialize_message(wire);
                if (!m) return std::nullopt;
                auto pt = e2e.decrypt(*m);
                if (!pt) return std::nullopt;
                sync_crypto_epoch();  // as above: follow post-rekey epoch
                return std::make_pair(std::move(*pt),
                                      static_cast<uint64_t>(
                                          m->header.message_number));
            } catch (...) {
                return std::nullopt;
            }
        };
        c.tx_crypto_counter = [this] {
            return static_cast<uint64_t>(e2e.get_sending_chain_length());
        };
        c.rx_crypto_counter = [this] {
            return static_cast<uint64_t>(e2e.get_receiving_chain_length());
        };
        return c;
    }

    /// (Re)build the per-session FSM shape source for a catalog descriptor.
    /// Engaged only when the descriptor carries an enabled, non-empty FSM
    /// model; otherwise any existing FSM is disengaged and the (always
    /// maintained) shaper stays the data-shape source. Deterministic: the
    /// FSM is derived from the same per-session secret material as the
    /// shaper, so both endpoints of the session build identical FSMs.
    /// Lifecycle mapping: the derivation secret only exists once the E2E
    /// handshake completed, so a fresh FSM traverses BOOTSTRAP and HANDSHAKE
    /// immediately at construction and is parked at ESTABLISHED; DATA is
    /// entered on the first application packet (see send_application).
    void rebind_fsm(const ProfileDescriptor* d) {
        variant_family.reset();
        if (!d || !d->fsm.enabled || d->fsm.states.empty()) {
            fsm.reset();
            return;
        }
        try {
            DerivedProfile dp = ReferenceProfileCatalog::derive_session(
                *d, SessionSecret::from_bytes(shaper_secret_snapshot));
            std::unique_ptr<MimicryFsmSession> next(
                new MimicryFsmSession(*d, dp));
            while (next->phase() < MimicryFsmPhase::ESTABLISHED)
                if (!next->advance_phase()) break;
            fsm = std::move(next);
            // Step 6: remember the variant family of the hash-bound active
            // profile descriptor (nullopt for families without a variant
            // map). Read at datagram time by both the TX variant selection
            // and the RX sibling-candidate path.
            if (!family_variant_masks(d->family).empty())
                variant_family = d->family;
        } catch (...) {
            fsm.reset();  // fall back to the shaper path
        }
    }

    /// Derive the per-session transition binding + shaper secret from the
    /// established shared secret, then build the SessionProfileContext and
    /// the catalog-derived shaper. Called exactly once per endpoint.
    bool finalize_handshake(const std::vector<uint8_t>& peer_public_key) {
        try {
            SecureMemory shared =
                e2e.compute_shared_secret(keys, peer_public_key);
            SecureMemory sid = e2e.derive_keys(shared, kSessionIdContext,
                                               PROFILE_SESSION_ID_SIZE);
            SecureMemory ssec = e2e.derive_keys(shared, kShaperSecretContext,
                                                SessionSecret::kSize);
            std::memcpy(shaper_secret_snapshot.data(), ssec.data(),
                        shaper_secret_snapshot.size());

            // Per-session mask binding key (v2 stateful masks). Both
            // endpoints derive the identical key from the shared secret;
            // the stateful masks (QUIC_SHORT_HEADER / STUN_MESSAGE) become
            // per-session authenticated, generic masks ignore it. Installed
            // WITHOUT touching the active profile/wire_version, and never
            // reset by a mask-only profile switch (I-V2-4).
            {
                SecureMemory mk = e2e.derive_keys(shared, kMaskKeyContext,
                                                  mask_key.size());
                std::memcpy(mask_key.data(), mk.data(), mask_key.size());
                TrafficMimicry::MimicConfig mc = outer.get_config();
                std::memcpy(mc.session_mask_key.data(), mask_key.data(),
                            mask_key.size());
                outer.set_config(mc);
            }

            ProfileTransitionConfig pcfg = cfg.transition_config;
            std::memcpy(pcfg.session_id.data(), sid.data(),
                        PROFILE_SESSION_ID_SIZE);
            if (pcfg.max_payload_bytes > cfg.max_application_payload)
                pcfg.max_payload_bytes = cfg.max_application_payload;

            ctx.reset(new SessionProfileContext(pcfg, cfg.stable_profile,
                                                cfg.stable_layout,
                                                make_crypto()));
            // Bind the authoritative E2E crypto epoch (0 for a freshly
            // established session) — never an invented value.
            sync_crypto_epoch();
            // Layout resolver for inbound PREPARE targets, with the
            // responder-side fail-fast gate folded in: the transition
            // manager turns a nullopt resolution into a clean
            // ABORT(UNKNOWN_PROFILE) refusal BEFORE entering READY. Under
            // v1 a target whose resolved outer mask is not
            // length-prefix-compatible (non-generic) is undecodable at the
            // synchronous mask switch — refusing prevents silent permanent
            // profile divergence. Under v2 (evaluated at call time: the
            // capability is only known after the caps exchange) the gate is
            // lifted and arbitrary resolved masks are accepted.
            // Without a catalog the base resolution is the default accept
            // (no padding), matching SessionProfileContext's fallback.
            {
                const auto base_resolver = cfg.catalog
                    ? make_catalog_layout_resolver(cfg.catalog)
                    : std::function<std::optional<ProfileLayoutParams>(
                          const ProfileRef&)>{};
                ctx->set_layout_resolver(
                    [this, base_resolver](const ProfileRef& ref)
                        -> std::optional<ProfileLayoutParams> {
                        std::optional<ProfileLayoutParams> layout;
                        if (base_resolver) layout = base_resolver(ref);
                        else layout = ProfileLayoutParams{};
                        if (!layout) return std::nullopt;
                        if (cfg.mimic_resolver) {
                            auto m = cfg.mimic_resolver(ref);
                            if (m && !is_transition_target_mimic(
                                         *m, v2_negotiated))
                                return std::nullopt;  // undecodable target
                        }
                        // Step 7 (design §3.3): a descriptor gating itself on
                        // the profile-transition-v2 capability is a v2-only
                        // transition target; refuse it under a v1 session
                        // (defense in depth on top of the wire gate — the
                        // responder-side refusal becomes ABORT(UNKNOWN_
                        // PROFILE) before READY). The catalog lookup is
                        // hash-bound: the base resolver above already
                        // verified ref.content_hash.
                        if (!v2_negotiated && cfg.catalog) {
                            const ProfileDescriptor* d = cfg.catalog->find(
                                ref.id, ref.revision);
                            if (d && descriptor_requires_profile_transition_v2(
                                         *d))
                                return std::nullopt;
                        }
                        return layout;
                    });
            }
            ctx->set_control_outbound_handler(
                [this](const std::vector<uint8_t>& wire) {
                    if (wire.empty()) return;  // guarded crypto failure
                    OutboundDatagram o;
                    o.bytes.push_back(kKindE2E);
                    // C1 (v2 control mask pin): while a transition is
                    // outstanding, every control datagram — including
                    // retransmissions and side-band ABORTs — is wrapped with
                    // the transition-stable mask: pre-activation that is the
                    // active mask, post-activation the old mask (kept as the
                    // grace decoder). With no transition outstanding (or a
                    // v1-negotiated session) control keeps the v1 behavior:
                    // wrapped with the active mask.
                    TrafficMimicry::MimicProfile ctl_mimic = active_mimic;
                    if (v2_negotiated && ctx &&
                        ctx->manager().has_outstanding() &&
                        ctx->manager().is_activated() && old_mimic) {
                        ctl_mimic = *old_mimic;
                    }
                    auto wrapped = outer_wrap(wire, ctl_mimic);
                    if (wrapped.empty()) return;
                    o.bytes.insert(o.bytes.end(), wrapped.begin(),
                                   wrapped.end());
                    o.profile_epoch = ctx ? ctx->tx_epoch() : 0;
                    o.pacing_delay = std::chrono::milliseconds(0);
                    o.is_control = true;  // never consumes a data shape
                    if (fsm) fsm->note_control_packet(o.bytes.size());
                    queue_push(std::move(o));
                });
            ctx->set_abort_handler([this](uint64_t, AbortReason) {
                // Pre-activation abort: cancel prepared shapes/timers and drop
                // the pending outer mask; the stable profile stays active.
                if (shaper) shaper->cancel_prepared_shape();
                if (fsm) fsm->cancel_prepared_shape();
                pending_mimic.reset();
            });
            ctx->add_epoch_observer([this](uint32_t, uint32_t) {
                on_profile_activation();
            });

            // Per-session polymorphic shaper from the catalog.
            if (cfg.catalog) {
                const ProfileDescriptor* d = cfg.catalog->find(
                    cfg.stable_profile.id, cfg.stable_profile.revision);
                if (d) {
                    DerivedProfile dp = ReferenceProfileCatalog::derive_session(
                        *d, SessionSecret::from_bytes(shaper_secret_snapshot));
                    shaper.reset(new MimicryShaper(dp.stat, dp.rng_seed));
                    shaper_session_tag = dp.session_tag;
                    shaper_profile_name = dp.stat.name;
                    // Engage the FSM shape source when the stable profile
                    // carries an FSM model (no-op otherwise).
                    rebind_fsm(d);
                }
            }
            return true;
        } catch (...) {
            ctx.reset();
            shaper.reset();
            fsm.reset();
            return false;
        }
    }

    /// Epoch observer target: local activation of a transition. Swaps the
    /// outer mask to the pending profile (keeping the old one as the grace
    /// decoder), cancels prepared shapes/timers bound to the superseded
    /// epoch and installs the catalog-derived profile for the new epoch.
    /// Never resets E2E ratchet state, TLS session state, keys or counters.
    void on_profile_activation() {
        old_mimic = active_mimic;
        if (ctx) {
            auto pending = ctx->pending_profile();
            if (pending) {
                if (cfg.catalog) {
                    const ProfileDescriptor* d = cfg.catalog->find(
                        pending->id, pending->revision);
                    if (d) active_layout = profile_layout_from_descriptor(*d);
                }
            }
        }
        if (pending_mimic) {
            active_mimic = *pending_mimic;
            TrafficMimicry::MimicConfig mc = outer.get_config();
            mc.profile = active_mimic;  // wire_version unchanged (pinned)
            outer.set_config(mc);       // mask-only switch: no TLS/key reset
        }
        if (shaper) {
            shaper->cancel_prepared_shape();
            bool rederived = false;
            if (ctx && cfg.catalog) {
                auto pending = ctx->pending_profile();
                if (pending) {
                    const ProfileDescriptor* d = cfg.catalog->find(
                        pending->id, pending->revision);
                    if (d) {
                        // Re-derive deterministically from the same per-session
                        // secret material used at handshake finalization.
                        try {
                            DerivedProfile dp =
                                ReferenceProfileCatalog::derive_session(
                                    *d, SessionSecret::from_bytes(
                                            shaper_secret_snapshot));
                            shaper->set_profile(std::move(dp.stat));
                            shaper_profile_name = shaper->profile().name;
                            rederived = true;
                        } catch (...) {
                            // fall through to epoch bump without re-derivation
                        }
                    }
                }
            }
            // No catalog descriptor for the target: keep the current model
            // but still bump the shaper epoch so stale shapes cannot leak.
            if (!rederived) shaper->set_profile(shaper->profile());
        }

        // Rebind the FSM shape source at the same epoch boundary. A fresh
        // FSM is built from the newly active profile's descriptor (fresh
        // state/profile epochs) and the OLD FSM object — including any
        // prepared shape bound to the superseded profile — is destroyed, so
        // no stale-epoch shape can leak across the boundary. A target with
        // no catalog descriptor or without fsm.enabled disengages the FSM
        // and the shaper path takes over again (rollback symmetry: the
        // pre-activation abort path above never rebuilt anything).
        {
            const ProfileDescriptor* nd = nullptr;
            if (ctx && cfg.catalog) {
                auto pending = ctx->pending_profile();
                if (pending)
                    nd = cfg.catalog->find(pending->id, pending->revision);
            }
            rebind_fsm(nd);
        }
    }

    /// Resolve the pending outer mask once the transition manager has a
    /// pending profile (responder learns it from PREPARE).
    void sync_pending_mimic() {
        if (!ctx || pending_mimic) return;
        auto pending = ctx->pending_profile();
        if (!pending || !cfg.mimic_resolver) return;
        auto m = cfg.mimic_resolver(*pending);
        if (m) pending_mimic = *m;
    }

    /// Grace-window cleanup: once the FSM is back to IDLE with nothing
    /// outstanding, the old outer decoder is removed.
    void cleanup_after_finalize() {
        if (!ctx) return;
        if (ctx->state() == ProfileTransitionState::IDLE &&
            !ctx->manager().has_outstanding()) {
            old_mimic.reset();
            if (!ctx->manager().is_activated()) pending_mimic.reset();
        }
    }

    /// Bounded enqueue for the outbound reaction queue (I-DRAIN-8).
    /// Refuse-new policy: when the datagram would push the queue past
    /// either configured bound, it is refused (counted, never queued) and
    /// existing queued datagrams are never evicted to make room.
    void queue_push(OutboundDatagram&& o) {
        const size_t n = o.bytes.size();
        const bool over_packets =
            out_q.size() >= cfg.max_outbound_queue_packets;
        const bool over_bytes =
            cfg.max_outbound_queue_bytes == 0 ||
            out_q_bytes + n > cfg.max_outbound_queue_bytes;
        if (over_packets || over_bytes) {
            ++queue_dropped_packets;
            queue_dropped_bytes += n;
            return;
        }
        out_q_bytes += n;
        out_q.push_back(std::move(o));
    }

    void queue_caps() {
        if (!ctx) return;
        try {
            NCPCapabilities caps;
            capabilities_set_profile_transition(
                caps, cfg.advertise_profile_transition);
            // Additive v2 feature bit (reserved[0] bit 0x02), advertised per
            // config. The v2 ⇒ v1 coupling is enforced on the RECEIVE side
            // (handle_caps): a v2 bit without v1 never counts as v2.
            capabilities_set_profile_transition_v2(
                caps, cfg.advertise_profile_transition_v2);
            auto wrapped = CapabilitiesExchange::wrap_capabilities(caps);
            auto wire = E2EUtils::serialize_message(e2e.encrypt(wrapped));
            OutboundDatagram o;
            o.bytes.push_back(kKindCaps);
            o.bytes.insert(o.bytes.end(), wire.begin(), wire.end());
            o.profile_epoch = ctx->tx_epoch();
            queue_push(std::move(o));
        } catch (...) {
            // capability advertisement failed; session stays legacy-safe
        }
    }

    IngressResult handle_caps(const uint8_t* body, size_t len) {
        try {
            auto m = E2EUtils::deserialize_message(
                std::vector<uint8_t>(body, body + len));
            if (!m) { ++ingress_dropped; return {IngressKind::Dropped, {}}; }
            auto pt = e2e.decrypt(*m);
            if (!pt) { ++ingress_dropped; return {IngressKind::Dropped, {}}; }
            auto caps = CapabilitiesExchange::parse_capabilities(*pt);
            if (!caps) { ++ingress_dropped; return {IngressKind::Dropped, {}}; }
            peer_caps = *caps;
            sync_crypto_epoch();  // successful decrypt: follow rekeys
            // Negotiation is a strict AND of both advertisements.
            const bool v1_negotiated =
                cfg.advertise_profile_transition &&
                capabilities_support_profile_transition(*caps);
            if (ctx) {
                ctx->set_peer_capable(v1_negotiated);
            }
            // v2: strict AND of the v2 bits AND negotiated v1 — a peer
            // advertising 0x02 without 0x01 is malformed and treated as
            // v1-only (fail-closed, exactly like a stripped bit).
            v2_negotiated = v1_negotiated &&
                            cfg.advertise_profile_transition_v2 &&
                            capabilities_support_profile_transition_v2(*caps);
            // MEDIUM-2: with v2 negotiated, clamp the effective transition
            // grace to at least the full retransmit budget plus margin so
            // post-activation control retransmits (decodable only via the
            // old-grace candidate under C1) cannot outlive the grace
            // window. Never lowers a larger configured grace; v1 sessions
            // keep the configured grace exactly.
            if (v2_negotiated && ctx)
                ctx->set_grace_floor_ms(
                    v2_grace_floor_ms(cfg.transition_config));
            return {IngressKind::Capabilities, {}};
        } catch (...) {
            ++ingress_dropped;
            return {IngressKind::Dropped, {}};
        }
    }

    /// Feed one E2E wire candidate through the profile context. Reports the
    /// app payload for data, and whether transition control was consumed.
    struct CtxFeedResult {
        bool consumed = false;  // AEAD-authenticated (data or control)
        bool is_data = false;
        std::optional<std::vector<uint8_t>> payload;
    };

    CtxFeedResult feed_ctx(const std::vector<uint8_t>& wire, uint64_t now_ms) {
        CtxFeedResult r;
        if (!ctx) return r;
        const auto before = ctx->counters();
        auto app = ctx->on_ciphertext(wire, now_ms);
        const auto after = ctx->counters();
        if (app) {
            r.consumed = true;
            r.is_data = true;
            r.payload = std::move(*app);
            return r;
        }
        const uint64_t ctl_before =
            before.control_rx + before.control_duplicates;
        const uint64_t ctl_after = after.control_rx + after.control_duplicates;
        r.consumed = ctl_after > ctl_before;
        return r;
    }

    IngressResult finish_feed(CtxFeedResult&& r) {
        sync_pending_mimic();
        cleanup_after_finalize();
        return r.is_data
                   ? IngressResult{IngressKind::Data, std::move(r.payload)}
                   : IngressResult{IngressKind::Control, {}};
    }

    IngressResult handle_e2e(const uint8_t* body, size_t len,
                             uint64_t now_ms) {
        if (!ctx) { ++ingress_dropped; return {IngressKind::Dropped, {}}; }
        std::vector<uint8_t> blob(body, body + len);

        // RX candidates (C3): ordered active → pending → old-grace →
        // sibling-variant (step 6, FSM-driven mask variants), first
        // AEAD-valid candidate wins, hard cap 4 (plain v2 uses at most 3; a
        // family variant map contributes at most one mask beyond
        // active/pending/old). Authentication happens strictly AFTER
        // unwrapping, inside the E2E AEAD + inner epoch checks; a failed
        // candidate never mutates ratchet/FSM/transition state
        // (verify-then-commit), so trying the next candidate is safe.
        //
        // I-TXD-2: exact per-datagram candidate work accounting, with the
        // cap ENFORCED in code (not just implied by the dedup sets): no
        // more than kMaxRxCandidates unwrap attempts — and therefore no
        // more AEAD attempts — are ever performed for one datagram, even
        // under a pathological mask configuration where the sibling set
        // would not collapse onto active/pending/old.
        uint32_t unwrap_attempts = 0;
        uint32_t aead_attempts = 0;  // candidates fed into the E2E decrypt
        CtxFeedResult r;
        bool consumed = false;
        auto try_candidate = [&](TrafficMimicry::MimicProfile m) {
            if (consumed) return;
            if (unwrap_attempts >= NcpMimicrySession::kMaxRxCandidates)
                return;  // hard structural cap (I-V2-3 / I-TXD-2)
            ++unwrap_attempts;
            auto inner = outer_unwrap(blob, m);
            if (inner.empty()) return;  // mask layer rejected: no AEAD work
            ++aead_attempts;
            r = feed_ctx(inner, now_ms);
            consumed = r.consumed;
        };
        //
        // Candidate 1: active outer profile.
        try_candidate(active_mimic);

        // Candidate 2 (v2 only): pending outer profile while a transition is
        // outstanding. Installed no later than the peer's first possible
        // new-mask transmission (initiator: start_profile_transition()
        // success; responder: PREPARE accept via sync_pending_mimic()), so
        // early new-mask data/control decodes with zero gap. Removed on
        // rollback/finalize. Deduplicated against the active mask (a
        // mask-preserving transition must not double-charge the AEAD layer).
        // v1 sessions never take this branch: the v1 path below stays
        // byte-identical.
        const bool pending_candidate =
            v2_negotiated && pending_mimic &&
            *pending_mimic != active_mimic &&
            ctx->manager().has_outstanding();
        if (pending_candidate) {
            try_candidate(*pending_mimic);
        }

        // Candidate 3: previous outer profile, only while the grace window
        // is open. A replayed/corrupted datagram fails AEAD here as well and
        // can never confirm a transition. Under v2 the old mask is
        // deduplicated against masks already tried (identical unwraps are
        // deterministic; re-feeding identical bytes would only double-count
        // inner rejections); under v1 the branch is exactly the historical
        // one.
        bool old_tried = false;
        if (v2_negotiated && old_mimic) {
            old_tried = (*old_mimic == active_mimic) ||
                        (pending_candidate && *pending_mimic == *old_mimic);
        }
        bool old_attempted = false;
        if (old_mimic && ctx->in_grace_period(now_ms) && !old_tried &&
            !consumed && unwrap_attempts < NcpMimicrySession::kMaxRxCandidates) {
            old_attempted = true;
            try_candidate(*old_mimic);
        }

        // Candidate 4 (v2 + FSM-driven mask variants only): the sibling
        // variant(s) of the active profile's family (step 6, design §3.4).
        // The acceptance set is a pure function of the hash-bound active
        // profile descriptor's family — NEVER of the receiver's own FSM
        // state (I-V2-5) — so endpoints cannot drift apart when their
        // independent FSM instances sit in different states. Gated exactly
        // like the TX side (v2 negotiated, variants enabled, FSM engaged on
        // a variant family), deduped against every mask already tried for
        // this datagram; the hard cap of 4 candidates stands.
        if (v2_negotiated && !cfg.disable_mask_variants && fsm &&
            variant_family) {
            for (auto sib : family_variant_masks(*variant_family)) {
                if (consumed ||
                    unwrap_attempts >= NcpMimicrySession::kMaxRxCandidates)
                    break;  // first AEAD-valid candidate wins; hard cap
                if (sib == active_mimic) continue;
                if (pending_candidate && sib == *pending_mimic) continue;
                if (old_mimic && sib == *old_mimic && (old_attempted || old_tried))
                    continue;  // identical unwrap already evaluated (or the
                               // mask was excluded as a duplicate of
                               // active/pending above)
                try_candidate(sib);
            }
        }

        // I-TXD-2: commit the per-datagram work into the session counters.
        candidate_unwrap_attempts_total += unwrap_attempts;
        candidate_aead_attempts_total += aead_attempts;
        if (unwrap_attempts > candidate_unwrap_attempts_max)
            candidate_unwrap_attempts_max = unwrap_attempts;
        if (aead_attempts > candidate_aead_attempts_max)
            candidate_aead_attempts_max = aead_attempts;

        if (consumed) return finish_feed(std::move(r));

        ++ingress_dropped;
        cleanup_after_finalize();
        return {IngressKind::Dropped, {}};
    }
};

// ==================== public API ====================

NcpMimicrySession::NcpMimicrySession(Config cfg)
    : impl_(new Impl(std::move(cfg))) {}

NcpMimicrySession::~NcpMimicrySession() { delete impl_; }

std::optional<NcpMimicrySession::OutboundDatagram>
NcpMimicrySession::start_handshake() {
    auto& im = *impl_;
    if (im.cfg.role != Role::Client || im.handshake_started) return std::nullopt;
    try {
        auto req = im.e2e.create_key_exchange_request(im.keys);
        im.handshake_started = true;
        OutboundDatagram o;
        o.bytes.push_back(kKindHandshake);
        o.bytes.insert(o.bytes.end(), req.begin(), req.end());
        return o;
    } catch (...) {
        return std::nullopt;
    }
}

bool NcpMimicrySession::is_established() const {
    try {
        return impl_->e2e.is_established() && impl_->ctx != nullptr;
    } catch (...) {
        return false;
    }
}

bool NcpMimicrySession::transition_capable() const {
    return impl_->peer_caps.has_value() &&
           impl_->cfg.advertise_profile_transition &&
           capabilities_support_profile_transition(*impl_->peer_caps);
}

bool NcpMimicrySession::rotate_e2e_keys() {
    auto& im = *impl_;
    if (!im.e2e.is_established()) return false;
    try {
        const uint64_t before = im.e2e.get_crypto_epoch();
        im.e2e.rotate_keys();  // no-ops when fenced (non-initiator, in-flight)
        im.sync_crypto_epoch();
        return im.e2e.get_crypto_epoch() > before;
    } catch (...) {
        return false;
    }
}

std::optional<NcpMimicrySession::OutboundDatagram>
NcpMimicrySession::send_application(const std::vector<uint8_t>& payload,
                                    uint64_t now_ms) {
    (void)now_ms;  // pacing is reported, scheduling is the poll loop's job
    auto& im = *impl_;
    if (!im.ctx || !im.e2e.is_established()) return std::nullopt;
    if (payload.size() > im.cfg.max_application_payload ||
        payload.size() > MAX_PROFILE_DATA_PAYLOAD_BYTES) {
        ++im.mtu_budget_rejections;
        return std::nullopt;
    }
    if (payload.size() > im.max_application_datagram(im.current_path)) {
        ++im.mtu_budget_rejections;
        return std::nullopt;
    }
    im.sync_crypto_epoch();
    try {
        // Data path only: consume one prepared shape for pacing. Control
        // packets never touch the shape source. When the active profile
        // carries an FSM model, the epoch-bound MimicryFsmSession is the
        // shape/timing source; otherwise the catalog-derived shaper is used
        // (unchanged legacy path).
        std::chrono::milliseconds pacing{0};
        if (im.fsm) {
            // First application packet: advance ESTABLISHED -> DATA.
            while (im.fsm->phase() < MimicryFsmPhase::DATA)
                if (!im.fsm->advance_phase()) break;
            im.fsm->prepare_data_shape();  // idempotent peek (descriptor MTU)
            MimicryFsmShape fs;
            if (im.fsm->take_data_shape(fs))
                pacing = std::chrono::milliseconds(
                    static_cast<long long>(fs.delay_ms));
        } else if (im.shaper) {
            im.shaper->prepare_data_shape(im.datagram_budget());
            PreparedShape ps;
            if (im.shaper->take_data_shape(ps))
                pacing = std::chrono::milliseconds(
                    static_cast<long long>(ps.delay_ms));
        }

        const uint32_t epoch = im.ctx->tx_epoch();
        auto wire = im.ctx->encode_data(payload);
        if (!wire || wire->empty()) return std::nullopt;

        // Step 6 (design §3.4): per-datagram FSM-driven mask variant. Only
        // when the session negotiated v2, the operator has not disabled
        // variants, the FSM shape source is engaged AND the active profile's
        // hash-bound descriptor family has a variant map. States outside the
        // map fall back to the active mask. active_mimic itself still flips
        // only at profile activation; control datagrams never take this path
        // (the control-outbound handler is untouched — C1).
        TrafficMimicry::MimicProfile data_mimic = im.active_mimic;
        if (im.v2_negotiated && !im.cfg.disable_mask_variants && im.fsm &&
            im.variant_family) {
            if (auto v = variant_for_state(*im.variant_family,
                                           im.fsm->current_state()))
                data_mimic = *v;
        }

        auto wrapped = im.outer_wrap(*wire, data_mimic);
        if (wrapped.empty()) return std::nullopt;

        OutboundDatagram o;
        o.bytes.push_back(kKindE2E);
        o.bytes.insert(o.bytes.end(), wrapped.begin(), wrapped.end());
        o.profile_epoch = epoch;
        o.pacing_delay = pacing;
        o.is_control = false;

        // Hard post-encode budget check: kind + outer + E2E + NCP + PD.
        if (o.bytes.size() > im.datagram_budget()) {
            ++im.mtu_budget_rejections;
            return std::nullopt;
        }
        return o;
    } catch (...) {
        return std::nullopt;
    }
}

NcpMimicrySession::IngressResult
NcpMimicrySession::on_datagram(const uint8_t* data, size_t len,
                               uint64_t now_ms) {
    auto& im = *impl_;
    if (!data || len < 1) {
        ++im.ingress_dropped;
        return {IngressKind::Dropped, {}};
    }
    im.sync_crypto_epoch();
    try {
        const uint8_t kind = data[0];
        const uint8_t* body = data + 1;
        const size_t blen = len - 1;
        switch (kind) {
            case kKindHandshake: {
                std::vector<uint8_t> blob(body, body + blen);
                if (im.cfg.role == Role::Server) {
                    if (im.ctx) {  // duplicate KX request: transport drop
                        ++im.ingress_dropped;
                        return {IngressKind::Dropped, {}};
                    }
                    auto resp = im.e2e.process_key_exchange_request(blob,
                                                                    im.keys);
                    std::vector<uint8_t> peer_pub;
                    if (!extract_peer_public_key(blob, peer_pub) ||
                        !im.finalize_handshake(peer_pub)) {
                        ++im.ingress_dropped;
                        return {IngressKind::Dropped, {}};
                    }
                    OutboundDatagram o;
                    o.bytes.push_back(kKindHandshake);
                    o.bytes.insert(o.bytes.end(), resp.begin(), resp.end());
                    im.queue_push(std::move(o));
                    im.queue_caps();
                    return {IngressKind::Handshake, {}};
                }
                // client: key-exchange response
                if (!im.handshake_started || im.ctx) {
                    ++im.ingress_dropped;
                    return {IngressKind::Dropped, {}};
                }
                if (!im.e2e.complete_key_exchange(blob, im.keys)) {
                    ++im.ingress_dropped;
                    return {IngressKind::Dropped, {}};
                }
                std::vector<uint8_t> peer_pub;
                if (!extract_peer_public_key(blob, peer_pub) ||
                    !im.finalize_handshake(peer_pub)) {
                    ++im.ingress_dropped;
                    return {IngressKind::Dropped, {}};
                }
                im.queue_caps();
                return {IngressKind::Handshake, {}};
            }
            case kKindCaps:
                return im.handle_caps(body, blen);
            case kKindE2E:
                return im.handle_e2e(body, blen, now_ms);
            case kKindPlaintext: {
                // Explicit insecure compatibility mode only; an established
                // E2E session is NEVER downgraded to plaintext.
                if (!im.cfg.allow_insecure_plaintext_legacy ||
                    im.e2e.is_established()) {
                    ++im.ingress_dropped;
                    return {IngressKind::Dropped, {}};
                }
                IngressResult r;
                r.kind = IngressKind::Data;
                r.app_payload = std::vector<uint8_t>(body, body + blen);
                r.insecure_plaintext = true;
                return r;
            }
            default:
                ++im.ingress_dropped;
                return {IngressKind::Dropped, {}};
        }
    } catch (...) {
        ++im.ingress_dropped;
        return {IngressKind::Dropped, {}};
    }
}

bool NcpMimicrySession::has_outbound() const { return !impl_->out_q.empty(); }

std::optional<NcpMimicrySession::OutboundDatagram>
NcpMimicrySession::next_outbound() {
    auto& im = *impl_;
    if (im.out_q.empty()) return std::nullopt;
    auto o = std::move(im.out_q.front());
    im.out_q.pop_front();
    // Keep the I-DRAIN-8 byte accounting in lockstep with the queue.
    im.out_q_bytes -= std::min(im.out_q_bytes, o.bytes.size());
    return o;
}

TransitionError NcpMimicrySession::start_profile_transition(
    const std::string& profile_id, uint32_t revision, uint64_t now_ms) {
    auto& im = *impl_;
    if (!im.ctx) return TransitionError::INVALID_STATE;
    if (!im.cfg.catalog) return TransitionError::INVALID_PROFILE;
    im.sync_crypto_epoch();
    try {
        const ProfileDescriptor* d = im.cfg.catalog->find(profile_id, revision);
        if (!d) return TransitionError::INVALID_PROFILE;
        // Step 7 (design §3.3): a descriptor requiring the
        // profile-transition-v2 capability is a v2-only transition target.
        // Refuse it under a v1-negotiated session — INVALID_PROFILE, no
        // state change, no control traffic (the responder side carries the
        // same gate in the layout resolver).
        if (!im.v2_negotiated &&
            descriptor_requires_profile_transition_v2(*d))
            return TransitionError::INVALID_PROFILE;
        ProfileRef ref = profile_ref_from_descriptor(*d);
        ProfileLayoutParams layout = profile_layout_from_descriptor(*d);
        std::optional<TrafficMimicry::MimicProfile> mimic;
        if (im.cfg.mimic_resolver) mimic = im.cfg.mimic_resolver(ref);
        // Fail-fast under v1: a non-generic target mask is undecodable at
        // the synchronous outer-mask switch (see is_transition_target_mimic).
        // The gate is lifted iff the session negotiated v2 (C1/C3 make
        // arbitrary targets decodable). Refusal: NO state change, NO control
        // traffic.
        if (mimic && !is_transition_target_mimic(*mimic, im.v2_negotiated))
            return TransitionError::INVALID_PROFILE;
        auto err = im.ctx->start_transition(ref, layout,
                                            TransitionDirection::BIDIRECTIONAL,
                                            /*reason=*/1, now_ms);
        if (err == TransitionError::NONE && mimic) im.pending_mimic = *mimic;
        return err;
    } catch (...) {
        return TransitionError::INVALID_STATE;
    }
}

TransitionError NcpMimicrySession::start_profile_transition(
    ProfileRef target, ProfileLayoutParams layout,
    TrafficMimicry::MimicProfile mimic, uint64_t now_ms) {
    auto& im = *impl_;
    if (!im.ctx) return TransitionError::INVALID_STATE;
    im.sync_crypto_epoch();
    try {
        // Fail-fast under v1: a non-generic target mask is undecodable at
        // the synchronous outer-mask switch (see is_transition_target_mimic).
        // The gate is lifted iff the session negotiated v2. Refusal: NO
        // state change, NO control traffic.
        if (!is_transition_target_mimic(mimic, im.v2_negotiated))
            return TransitionError::INVALID_PROFILE;
        auto err = im.ctx->start_transition(target, layout,
                                            TransitionDirection::BIDIRECTIONAL,
                                            /*reason=*/1, now_ms);
        if (err == TransitionError::NONE) im.pending_mimic = mimic;
        return err;
    } catch (...) {
        return TransitionError::INVALID_STATE;
    }
}

bool NcpMimicrySession::abort_transition(AbortReason reason, uint64_t now_ms) {
    auto& im = *impl_;
    if (!im.ctx) return false;
    im.sync_crypto_epoch();
    try {
        return im.ctx->abort_transition(reason, now_ms);
    } catch (...) {
        return false;
    }
}

void NcpMimicrySession::tick(uint64_t now_ms) {
    auto& im = *impl_;
    if (!im.ctx) return;
    im.sync_crypto_epoch();
    try {
        im.ctx->tick(now_ms);
    } catch (...) {
        // retransmission emission failed at the crypto boundary; retry next tick
    }
    im.sync_pending_mimic();
    im.cleanup_after_finalize();
}

uint32_t NcpMimicrySession::effective_transition_grace_ms() const {
    const auto& im = *impl_;
    if (!im.ctx) return im.cfg.transition_config.grace_period_ms;
    return im.ctx->configured_grace_period_ms();
}

NcpMimicrySession::Stats NcpMimicrySession::stats() const {
    Stats s;
    const auto& im = *impl_;
    try {
        s.established = im.e2e.is_established() && im.ctx != nullptr;
        s.transition_capable = transition_capable();
        s.transition_v2_capable = im.v2_negotiated;
        s.e2e_messages_sent = im.e2e.get_messages_sent();
        s.e2e_messages_received = im.e2e.get_messages_received();
        s.e2e_sending_chain_length = im.e2e.get_sending_chain_length();
        s.e2e_receiving_chain_length = im.e2e.get_receiving_chain_length();
        s.crypto_epoch = im.e2e.get_crypto_epoch();
    } catch (...) {
    }
    if (im.ctx) {
        s.transition_state = im.ctx->state();
        s.active_profile = im.ctx->tx_profile();
        s.pending_profile = im.ctx->pending_profile();
        // Effective epoch = what outbound data is stamped with right now
        // (the pending epoch once activated, before finalization).
        s.profile_epoch = im.ctx->tx_epoch();
        s.tx_epoch = im.ctx->tx_epoch();
        s.transition_counters = im.ctx->counters();
    } else {
        s.active_profile = im.cfg.stable_profile;
    }
    s.active_mimic = im.active_mimic;
    s.pending_mimic = im.pending_mimic;
    try {
        s.outer_stats = im.outer.get_stats();
    } catch (...) {
    }
    s.shaper_engaged = im.shaper != nullptr;
    s.shaper_epoch = im.shaper ? im.shaper->profile_epoch() : 0;
    s.fsm_engaged = im.fsm != nullptr;
    if (im.fsm) {
        s.fsm_state_epoch = im.fsm->state_epoch();
        s.fsm_profile_epoch = im.fsm->profile_epoch();
        s.fsm_phase = im.fsm->phase();
        s.fsm_state = im.fsm->current_state();
        s.fsm_control_packets = im.fsm->control_packets_observed();
    }
    s.mtu_budget_rejections = im.mtu_budget_rejections;
    s.ingress_dropped = im.ingress_dropped;
    s.outbound_queue_packets = im.out_q.size();
    s.outbound_queue_bytes = im.out_q_bytes;
    s.queue_dropped_packets = im.queue_dropped_packets;
    s.queue_dropped_bytes = im.queue_dropped_bytes;
    s.candidate_unwrap_attempts_total = im.candidate_unwrap_attempts_total;
    s.candidate_aead_attempts_total = im.candidate_aead_attempts_total;
    s.candidate_unwrap_attempts_max = im.candidate_unwrap_attempts_max;
    s.candidate_aead_attempts_max = im.candidate_aead_attempts_max;
    return s;
}

std::string NcpMimicrySession::e2e_session_id() const {
    try {
        return impl_->e2e.get_session_id();
    } catch (...) {
        return {};
    }
}

bool NcpMimicrySession::shaper_engaged() const {
    return impl_->shaper != nullptr;
}

uint64_t NcpMimicrySession::shaper_epoch() const {
    return impl_->shaper ? impl_->shaper->profile_epoch() : 0;
}

const char* NcpMimicrySession::shaper_profile_name() const {
    return impl_->shaper_profile_name.empty()
               ? ""
               : impl_->shaper_profile_name.c_str();
}

uint64_t NcpMimicrySession::shaper_session_tag() const {
    return impl_->shaper_session_tag;
}

bool NcpMimicrySession::shaper_has_prepared_shape() const {
    return impl_->shaper && impl_->shaper->has_prepared_shape();
}

bool NcpMimicrySession::shaper_peek_prepared(PreparedShape& out) {
    auto& im = *impl_;
    if (!im.shaper) return false;
    out = im.shaper->prepare_data_shape(im.datagram_budget());
    return true;
}

bool NcpMimicrySession::fsm_engaged() const {
    return impl_->fsm != nullptr;
}

MimicryFsmPhase NcpMimicrySession::fsm_phase() const {
    return impl_->fsm ? impl_->fsm->phase() : MimicryFsmPhase::BOOTSTRAP;
}

const char* NcpMimicrySession::fsm_state_name() const {
    return impl_->fsm ? impl_->fsm->current_state().c_str() : "";
}

uint64_t NcpMimicrySession::fsm_state_epoch() const {
    return impl_->fsm ? impl_->fsm->state_epoch() : 0;
}

uint64_t NcpMimicrySession::fsm_seed() const {
    return impl_->fsm ? impl_->fsm->seed() : 0;
}

bool NcpMimicrySession::fsm_peek_prepared(MimicryFsmShape& out) {
    auto& im = *impl_;
    if (!im.fsm) return false;
    out = im.fsm->prepare_data_shape();  // idempotent peek, no consumption
    return true;
}

size_t NcpMimicrySession::max_application_datagram(
    const PathState& path_state) const {
    return impl_->max_application_datagram(path_state);
}

bool NcpMimicrySession::update_path_state(const PathState& path_state) {
    if (!valid_path_state(path_state)) return false;
    if (path_state.hop_policy == PathHopPolicy::LegacyPortHop &&
        impl_->cfg.porthop_overhead_bytes <
            kPortHopHeaderBytes + path_state.porthop_padding_headroom)
        return false;
    impl_->current_path = path_state;
    return true;
}

bool NcpMimicrySession::apply_icmp_packet_too_big(
    uint32_t advertised_mtu) {
    if (advertised_mtu == 0) return false;
    PathState next = impl_->current_path;
    const uint32_t current = next.effective_mtu == 0
        ? kUnknownPathMtuBasis : next.effective_mtu;
    if (advertised_mtu >= current) return false;
    if (next.ip_version == PathIpVersion::IPv6 &&
        advertised_mtu < 1280) return false;
    next.effective_mtu = advertised_mtu;
    return update_path_state(next);
}

PathState NcpMimicrySession::path_state() const {
    return impl_->current_path;
}

size_t NcpMimicrySession::max_datagram_bytes() const {
    return impl_->datagram_budget();
}

} // namespace ncp
