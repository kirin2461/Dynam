#ifndef NCP_CAPABILITIES_HPP
#define NCP_CAPABILITIES_HPP

#include <cstdint>
#include <cstddef>
#include <vector>
#include <string>
#include <array>
#include <optional>
#include <map>
#include <cstring>
#include <algorithm>

namespace ncp {

// ======================================================================
//  E2E Message Type Discriminator
// ======================================================================
//  4-byte magic prefix: 'N','C','P', <type_byte>
//  Eliminates collision with legacy untagged E2E messages.
//  Old peers' data won't start with "NCP" — safe fallback to DATA.

enum class E2EMessageType : uint8_t {
    DATA             = 0x00,   // Application data (may be untagged from old peers)
    CAPABILITIES     = 0x01,   // Capabilities exchange message
    CAPS_CONFIRM     = 0x02,   // Confirmation HMAC of negotiated config
};

/// Magic prefix for capabilities-aware messages.
static constexpr uint8_t NCP_MSG_MAGIC[3] = {'N', 'C', 'P'};
static constexpr size_t  NCP_MSG_TAG_SIZE = 4;  // magic[3] + type[1]

// ======================================================================
//  Stage Flags — bitmap of pipeline stages
// ======================================================================
//  uint32_t — 32 bits, 11 used, 21 reserved for future stages.
//  Bit operations via free functions (enum class prevents implicit |&).

enum class StageFlag : uint32_t {
    NONE                 = 0,
    ADVERSARIAL_PADDING  = 1u << 0,
    FLOW_SHAPING         = 1u << 1,
    PROBE_RESIST         = 1u << 2,
    TRAFFIC_MIMICRY      = 1u << 3,
    TLS_FINGERPRINT      = 1u << 4,
    ADVANCED_DPI         = 1u << 5,
    ECH                  = 1u << 6,
    PROTOCOL_MORPH       = 1u << 7,
    BURST_MORPHER        = 1u << 8,
    GENEVA_GA            = 1u << 9,
    ENTROPY_MASKING      = 1u << 10,
    // Bits 11-31 reserved
};

inline StageFlag operator|(StageFlag a, StageFlag b) {
    return static_cast<StageFlag>(
        static_cast<uint32_t>(a) | static_cast<uint32_t>(b));
}
inline StageFlag operator&(StageFlag a, StageFlag b) {
    return static_cast<StageFlag>(
        static_cast<uint32_t>(a) & static_cast<uint32_t>(b));
}
inline StageFlag operator~(StageFlag a) {
    return static_cast<StageFlag>(~static_cast<uint32_t>(a));
}
inline StageFlag& operator|=(StageFlag& a, StageFlag b) {
    a = a | b; return a;
}
inline StageFlag& operator&=(StageFlag& a, StageFlag b) {
    a = a & b; return a;
}
inline bool has_flag(StageFlag set, StageFlag flag) {
    return (static_cast<uint32_t>(set) & static_cast<uint32_t>(flag)) != 0;
}

/// Portable popcount (Kernighan's bit trick). MSVC-safe.
inline uint32_t popcount32(uint32_t v) {
    uint32_t c = 0;
    while (v) { v &= v - 1; ++c; }
    return c;
}

/// Validate that a stage_id has exactly one bit set (single stage).
inline bool is_valid_stage_id(uint32_t sid) {
    return sid != 0 && popcount32(sid) == 1;
}

/// Iterate over all set bits, calling fn(StageFlag) for each.
template<typename Fn>
void for_each_stage(StageFlag set, Fn&& fn) {
    for (uint32_t bit = 0; bit < 32; ++bit) {
        auto flag = static_cast<StageFlag>(1u << bit);
        if (has_flag(set, flag)) {
            fn(flag);
        }
    }
}

/// Human-readable name for a stage flag (single bit).
inline const char* stage_flag_name(StageFlag flag) {
    switch (flag) {
        case StageFlag::ADVERSARIAL_PADDING: return "adversarial_padding";
        case StageFlag::FLOW_SHAPING:        return "flow_shaping";
        case StageFlag::PROBE_RESIST:        return "probe_resist";
        case StageFlag::TRAFFIC_MIMICRY:     return "traffic_mimicry";
        case StageFlag::TLS_FINGERPRINT:     return "tls_fingerprint";
        case StageFlag::ADVANCED_DPI:        return "advanced_dpi";
        case StageFlag::ECH:                 return "ech";
        case StageFlag::PROTOCOL_MORPH:      return "protocol_morph";
        case StageFlag::BURST_MORPHER:       return "burst_morpher";
        case StageFlag::GENEVA_GA:           return "geneva_ga";
        case StageFlag::ENTROPY_MASKING:     return "entropy_masking";
        default:                             return "unknown";
    }
}

// ======================================================================
//  Per-stage configuration entry (TLV)
// ======================================================================

/// Maximum size of a single stage config blob (prevents DoS).
static constexpr uint16_t MAX_STAGE_CONFIG_SIZE = 4096;

struct StageConfigEntry {
    StageFlag stage_id;
    std::vector<uint8_t> config_data;  // Opaque per-stage config blob
};

// ======================================================================
//  NCP Capabilities — exchanged between peers
// ======================================================================
//
//  Wire format (all big-endian):
//    [version:2][supported_stages:4][preferred_stages:4]
//    [morph_seed:32]
//    [tls_profile:1][burst_target:1][max_fragment_size:2]
//    [num_configs:1]
//    for each config:
//      [stage_id_bits:4][config_len:2][config_data:N]  (max N=4096)
//    [reserved:16]  — zero-filled, for future extensions

static constexpr uint16_t NCP_CAPS_VERSION = 1;
static constexpr size_t   NCP_MORPH_SEED_SIZE = 32;
static constexpr size_t   NCP_CAPS_RESERVED_SIZE = 16;

struct NCPCapabilities {
    uint16_t  version = NCP_CAPS_VERSION;
    StageFlag supported_stages = StageFlag::NONE;  // What I CAN do
    StageFlag preferred_stages = StageFlag::NONE;  // What I WANT to use

    // Protocol Morph synchronization seed (random per-session)
    std::array<uint8_t, NCP_MORPH_SEED_SIZE> morph_seed{};

    // Quick-access common parameters
    uint8_t  tls_profile = 0;        // BrowserType enum value
    uint8_t  burst_target = 0;       // TargetTrafficType enum value
    uint16_t max_fragment_size = 1400;

    // Per-stage config entries (optional, for stages needing parameters)
    std::vector<StageConfigEntry> stage_configs;

    // Reserved bytes for forward compatibility
    std::array<uint8_t, NCP_CAPS_RESERVED_SIZE> reserved{};

    // ---- Serialization ----

    std::vector<uint8_t> serialize() const {
        std::vector<uint8_t> out;
        out.reserve(128);

        // Version (2 bytes)
        out.push_back(static_cast<uint8_t>((version >> 8) & 0xFF));
        out.push_back(static_cast<uint8_t>(version & 0xFF));

        // Supported stages (4 bytes)
        uint32_t sup = static_cast<uint32_t>(supported_stages);
        out.push_back(static_cast<uint8_t>((sup >> 24) & 0xFF));
        out.push_back(static_cast<uint8_t>((sup >> 16) & 0xFF));
        out.push_back(static_cast<uint8_t>((sup >> 8) & 0xFF));
        out.push_back(static_cast<uint8_t>(sup & 0xFF));

        // Preferred stages (4 bytes)
        uint32_t pref = static_cast<uint32_t>(preferred_stages);
        out.push_back(static_cast<uint8_t>((pref >> 24) & 0xFF));
        out.push_back(static_cast<uint8_t>((pref >> 16) & 0xFF));
        out.push_back(static_cast<uint8_t>((pref >> 8) & 0xFF));
        out.push_back(static_cast<uint8_t>(pref & 0xFF));

        // Morph seed (32 bytes)
        out.insert(out.end(), morph_seed.begin(), morph_seed.end());

        // Quick params (4 bytes)
        out.push_back(tls_profile);
        out.push_back(burst_target);
        out.push_back(static_cast<uint8_t>((max_fragment_size >> 8) & 0xFF));
        out.push_back(static_cast<uint8_t>(max_fragment_size & 0xFF));

        // Stage configs (TLV array) — only valid single-bit stage IDs
        uint8_t num = 0;
        for (const auto& entry : stage_configs) {
            if (is_valid_stage_id(static_cast<uint32_t>(entry.stage_id))) ++num;
            if (num == 255) break;
        }
        out.push_back(num);

        uint8_t written = 0;
        for (const auto& entry : stage_configs) {
            if (written >= num) break;
            uint32_t sid = static_cast<uint32_t>(entry.stage_id);
            if (!is_valid_stage_id(sid)) continue;

            out.push_back(static_cast<uint8_t>((sid >> 24) & 0xFF));
            out.push_back(static_cast<uint8_t>((sid >> 16) & 0xFF));
            out.push_back(static_cast<uint8_t>((sid >> 8) & 0xFF));
            out.push_back(static_cast<uint8_t>(sid & 0xFF));

            uint16_t clen = static_cast<uint16_t>(
                std::min(entry.config_data.size(),
                         static_cast<size_t>(MAX_STAGE_CONFIG_SIZE)));
            out.push_back(static_cast<uint8_t>((clen >> 8) & 0xFF));
            out.push_back(static_cast<uint8_t>(clen & 0xFF));
            out.insert(out.end(),
                       entry.config_data.begin(),
                       entry.config_data.begin() + clen);
            ++written;
        }

        // Reserved (16 bytes)
        out.insert(out.end(), reserved.begin(), reserved.end());

        return out;
    }

    static std::optional<NCPCapabilities> deserialize(
        const uint8_t* data, size_t len) {

        // Minimum: 2+4+4+32+4+1+16 = 63 bytes
        if (!data || len < 63) return std::nullopt;

        NCPCapabilities caps;
        size_t pos = 0;

        // Version
        caps.version = static_cast<uint16_t>(
            (static_cast<uint16_t>(data[pos]) << 8) |
             static_cast<uint16_t>(data[pos + 1]));
        pos += 2;

        // For forward compat: accept version >= 1, parse what we know
        if (caps.version < 1) return std::nullopt;

        // Supported stages
        uint32_t sup = (static_cast<uint32_t>(data[pos]) << 24) |
                       (static_cast<uint32_t>(data[pos+1]) << 16) |
                       (static_cast<uint32_t>(data[pos+2]) << 8) |
                        static_cast<uint32_t>(data[pos+3]);
        caps.supported_stages = static_cast<StageFlag>(sup);
        pos += 4;

        // Preferred stages
        uint32_t pref = (static_cast<uint32_t>(data[pos]) << 24) |
                        (static_cast<uint32_t>(data[pos+1]) << 16) |
                        (static_cast<uint32_t>(data[pos+2]) << 8) |
                         static_cast<uint32_t>(data[pos+3]);
        caps.preferred_stages = static_cast<StageFlag>(pref);
        pos += 4;

        // Morph seed
        if (pos + NCP_MORPH_SEED_SIZE > len) return std::nullopt;
        std::memcpy(caps.morph_seed.data(), data + pos, NCP_MORPH_SEED_SIZE);
        pos += NCP_MORPH_SEED_SIZE;

        // Quick params
        if (pos + 4 > len) return std::nullopt;
        caps.tls_profile = data[pos++];
        caps.burst_target = data[pos++];
        caps.max_fragment_size = static_cast<uint16_t>(
            (static_cast<uint16_t>(data[pos]) << 8) |
             static_cast<uint16_t>(data[pos + 1]));
        pos += 2;

        // Stage configs
        if (pos + 1 > len) return std::nullopt;
        uint8_t num_configs = data[pos++];

        for (uint8_t i = 0; i < num_configs; ++i) {
            if (pos + 6 > len) break;  // Graceful: stop parsing, keep what we have

            uint32_t sid = (static_cast<uint32_t>(data[pos]) << 24) |
                           (static_cast<uint32_t>(data[pos+1]) << 16) |
                           (static_cast<uint32_t>(data[pos+2]) << 8) |
                            static_cast<uint32_t>(data[pos+3]);
            pos += 4;

            uint16_t clen = static_cast<uint16_t>(
                (static_cast<uint16_t>(data[pos]) << 8) |
                 static_cast<uint16_t>(data[pos + 1]));
            pos += 2;

            // FIX: Cap config size to prevent DoS
            if (clen > MAX_STAGE_CONFIG_SIZE) {
                // Skip oversized entry (advance pos but don't store)
                if (pos + clen > len) break;
                pos += clen;
                continue;
            }

            if (pos + clen > len) break;

            // FIX: Validate stage_id is single-bit (popcount == 1)
            if (!is_valid_stage_id(sid)) {
                // Skip invalid stage_id entry
                pos += clen;
                continue;
            }

            StageConfigEntry entry;
            entry.stage_id = static_cast<StageFlag>(sid);
            entry.config_data.assign(data + pos, data + pos + clen);
            pos += clen;

            caps.stage_configs.push_back(std::move(entry));
        }

        // Reserved (may be absent in truncated messages from old peers)
        if (pos + NCP_CAPS_RESERVED_SIZE <= len) {
            std::memcpy(caps.reserved.data(), data + pos, NCP_CAPS_RESERVED_SIZE);
        }

        return caps;
    }

    static std::optional<NCPCapabilities> deserialize(
        const std::vector<uint8_t>& data) {
        return deserialize(data.data(), data.size());
    }

    /// Get config entry for a specific stage (or nullptr)
    const StageConfigEntry* get_stage_config(StageFlag stage) const {
        for (const auto& entry : stage_configs) {
            if (entry.stage_id == stage) return &entry;
        }
        return nullptr;
    }
};

// ======================================================================
//  Negotiated Configuration — result of capabilities exchange
// ======================================================================

struct NegotiatedConfig {
    uint16_t version = NCP_CAPS_VERSION;           // FIX: Include in HMAC
    StageFlag active_stages = StageFlag::NONE;     // Intersection of both peers

    // Resolved parameters
    std::array<uint8_t, NCP_MORPH_SEED_SIZE> morph_seed{};  // HKDF-derived shared seed
    uint8_t  tls_profile = 0;
    uint8_t  burst_target = 0;
    uint16_t max_fragment_size = 1400;

    // Merged per-stage configs (intersection of supported stages only)
    std::map<uint32_t, std::vector<uint8_t>> stage_configs;

    bool is_stage_active(StageFlag flag) const {
        return has_flag(active_stages, flag);
    }

    /// Serialize for confirmation HMAC computation.
    /// Deterministic byte representation of the negotiated config.
    /// FIX: Now includes version to prevent cross-version HMAC collisions.
    std::vector<uint8_t> serialize_for_hmac() const {
        std::vector<uint8_t> out;

        // Version (2 bytes) — prevents cross-version HMAC match
        out.push_back(static_cast<uint8_t>((version >> 8) & 0xFF));
        out.push_back(static_cast<uint8_t>(version & 0xFF));

        uint32_t active = static_cast<uint32_t>(active_stages);
        out.push_back(static_cast<uint8_t>((active >> 24) & 0xFF));
        out.push_back(static_cast<uint8_t>((active >> 16) & 0xFF));
        out.push_back(static_cast<uint8_t>((active >> 8) & 0xFF));
        out.push_back(static_cast<uint8_t>(active & 0xFF));

        out.insert(out.end(), morph_seed.begin(), morph_seed.end());
        out.push_back(tls_profile);
        out.push_back(burst_target);
        out.push_back(static_cast<uint8_t>((max_fragment_size >> 8) & 0xFF));
        out.push_back(static_cast<uint8_t>(max_fragment_size & 0xFF));

        // Stage configs in deterministic order (sorted by key via std::map)
        for (const auto& [sid, data] : stage_configs) {
            out.push_back(static_cast<uint8_t>((sid >> 24) & 0xFF));
            out.push_back(static_cast<uint8_t>((sid >> 16) & 0xFF));
            out.push_back(static_cast<uint8_t>((sid >> 8) & 0xFF));
            out.push_back(static_cast<uint8_t>(sid & 0xFF));
            uint16_t clen = static_cast<uint16_t>(data.size());
            out.push_back(static_cast<uint8_t>((clen >> 8) & 0xFF));
            out.push_back(static_cast<uint8_t>(clen & 0xFF));
            out.insert(out.end(), data.begin(), data.end());
        }

        return out;
    }
};

// ======================================================================
//  Negotiation Logic
// ======================================================================

inline NegotiatedConfig negotiate(
    const NCPCapabilities& local,
    const NCPCapabilities& peer) {

    NegotiatedConfig result;
    result.version = std::min(local.version, peer.version);

    // Active = both support AND at least one prefers
    StageFlag both_support = local.supported_stages & peer.supported_stages;
    StageFlag either_wants = local.preferred_stages | peer.preferred_stages;
    result.active_stages = both_support & either_wants;

    // TLS profile: prefer peer's if non-zero (constrained peer drives)
    result.tls_profile = (peer.tls_profile != 0)
        ? peer.tls_profile : local.tls_profile;

    // Burst target: prefer peer's if non-zero
    result.burst_target = (peer.burst_target != 0)
        ? peer.burst_target : local.burst_target;

    // Fragment size: use minimum of both (safer)
    result.max_fragment_size = std::min(
        local.max_fragment_size, peer.max_fragment_size);

    // NOTE: morph_seed is NOT set here — it must be derived via HKDF
    // from shared_secret + both morph seeds by the caller.
    // Use derive_and_apply_morph_seed() helper below.

    // Merge per-stage configs for active stages only
    for_each_stage(result.active_stages, [&](StageFlag flag) {
        uint32_t sid = static_cast<uint32_t>(flag);

        // Prefer peer's config, fallback to local's
        const auto* peer_cfg = peer.get_stage_config(flag);
        const auto* local_cfg = local.get_stage_config(flag);

        if (peer_cfg && !peer_cfg->config_data.empty()) {
            result.stage_configs[sid] = peer_cfg->config_data;
        } else if (local_cfg && !local_cfg->config_data.empty()) {
            result.stage_configs[sid] = local_cfg->config_data;
        }
    });

    return result;
}

/// Create local-only config when peer doesn't respond (timeout fallback).
inline NegotiatedConfig negotiate_local_only(
    const NCPCapabilities& local) {

    NegotiatedConfig result;
    result.version = local.version;
    result.active_stages = local.supported_stages & local.preferred_stages;
    result.tls_profile = local.tls_profile;
    result.burst_target = local.burst_target;
    result.max_fragment_size = local.max_fragment_size;

    for (const auto& entry : local.stage_configs) {
        if (has_flag(result.active_stages, entry.stage_id)) {
            result.stage_configs[static_cast<uint32_t>(entry.stage_id)] =
                entry.config_data;
        }
    }

    return result;
}

// ======================================================================
//  Morph Seed Derivation
// ======================================================================

struct MorphSeedDerivation {
    /// Build the HKDF salt from both morph seeds in deterministic order.
    /// Initiator's seed always comes first.
    static std::vector<uint8_t> build_salt(
        const std::array<uint8_t, NCP_MORPH_SEED_SIZE>& local_seed,
        const std::array<uint8_t, NCP_MORPH_SEED_SIZE>& peer_seed,
        bool is_initiator) {

        std::vector<uint8_t> salt;
        salt.reserve(NCP_MORPH_SEED_SIZE * 2);

        if (is_initiator) {
            salt.insert(salt.end(), local_seed.begin(), local_seed.end());
            salt.insert(salt.end(), peer_seed.begin(), peer_seed.end());
        } else {
            salt.insert(salt.end(), peer_seed.begin(), peer_seed.end());
            salt.insert(salt.end(), local_seed.begin(), local_seed.end());
        }

        return salt;
    }

    /// HKDF info context string.
    static std::vector<uint8_t> info() {
        const char* ctx = "ncp-morph-seed-v1";
        return std::vector<uint8_t>(
            reinterpret_cast<const uint8_t*>(ctx),
            reinterpret_cast<const uint8_t*>(ctx) + std::strlen(ctx));
    }
};

// ======================================================================
//  Helper: derive_and_apply_morph_seed
// ======================================================================
//
//  Combines salt construction + HKDF derivation into a single call.
//  Prevents callers from forgetting the HKDF step after negotiate().
//
//  Usage:
//    auto negotiated = negotiate(local_caps, peer_caps);
//    derive_and_apply_morph_seed(
//        negotiated, shared_secret,
//        local_caps.morph_seed, peer_caps.morph_seed,
//        is_initiator,
//        hkdf_fn  // = E2EUtils::derive_key or equivalent
//    );
//    // negotiated.morph_seed is now set

using HkdfDeriveFn = std::function<std::vector<uint8_t>(
    const uint8_t* ikm, size_t ikm_len,
    const std::vector<uint8_t>& salt,
    const std::vector<uint8_t>& info,
    size_t output_len)>;

inline void derive_and_apply_morph_seed(
    NegotiatedConfig& config,
    const uint8_t* shared_secret, size_t shared_secret_len,
    const std::array<uint8_t, NCP_MORPH_SEED_SIZE>& local_seed,
    const std::array<uint8_t, NCP_MORPH_SEED_SIZE>& peer_seed,
    bool is_initiator,
    HkdfDeriveFn hkdf_fn) {

    auto salt = MorphSeedDerivation::build_salt(local_seed, peer_seed, is_initiator);
    auto info = MorphSeedDerivation::info();
    auto derived = hkdf_fn(shared_secret, shared_secret_len,
                           salt, info, NCP_MORPH_SEED_SIZE);

    size_t copy_len = std::min(derived.size(),
                               static_cast<size_t>(NCP_MORPH_SEED_SIZE));
    std::memcpy(config.morph_seed.data(), derived.data(), copy_len);
}

// ======================================================================
//  Capabilities Exchange Protocol
// ======================================================================
//
//  Sequence (2 RTT total):
//
//  1. Both peers reach SessionEstablished (after E2E key exchange)
//  2. Both peers immediately encrypt(serialize(local_caps))
//     with NCP magic + E2EMessageType::CAPABILITIES tag prepended
//  3. Both peers wait for peer capabilities (5s timeout)
//  4. negotiate(local_caps, peer_caps) → NegotiatedConfig
//  5. derive_and_apply_morph_seed(negotiated, ...)
//  6. Both peers send HMAC(session_key, serialize(negotiated))
//     with NCP magic + E2EMessageType::CAPS_CONFIRM tag
//  7. Both peers verify peer's HMAC matches their own
//  8. If HMAC mismatch → abort (MITM detected) or fallback
//  9. apply_negotiated_config(negotiated) → Orchestrator
//
//  If allow_in_band_negotiation = false (default):
//    Skip steps 2-8, use pre-shared OrchestratorConfig directly.

struct CapabilitiesExchange {

    // ---- Message wrapping with 4-byte magic tag ----

    /// Check if a decrypted message has the NCP magic prefix.
    /// Legacy messages from old peers won't have it → treated as DATA.
    static bool has_magic(const std::vector<uint8_t>& decrypted) {
        if (decrypted.size() < NCP_MSG_TAG_SIZE) return false;
        return decrypted[0] == NCP_MSG_MAGIC[0] &&
               decrypted[1] == NCP_MSG_MAGIC[1] &&
               decrypted[2] == NCP_MSG_MAGIC[2];
    }

    /// Wrap capabilities message with 4-byte tag: 'N','C','P', 0x01
    static std::vector<uint8_t> wrap_capabilities(
        const NCPCapabilities& caps) {

        auto serialized = caps.serialize();
        std::vector<uint8_t> msg;
        msg.reserve(NCP_MSG_TAG_SIZE + serialized.size());
        msg.push_back(NCP_MSG_MAGIC[0]);
        msg.push_back(NCP_MSG_MAGIC[1]);
        msg.push_back(NCP_MSG_MAGIC[2]);
        msg.push_back(static_cast<uint8_t>(E2EMessageType::CAPABILITIES));
        msg.insert(msg.end(), serialized.begin(), serialized.end());
        return msg;
    }

    /// Wrap confirmation HMAC with 4-byte tag: 'N','C','P', 0x02
    static std::vector<uint8_t> wrap_confirm(
        const std::vector<uint8_t>& hmac_bytes) {

        std::vector<uint8_t> msg;
        msg.reserve(NCP_MSG_TAG_SIZE + hmac_bytes.size());
        msg.push_back(NCP_MSG_MAGIC[0]);
        msg.push_back(NCP_MSG_MAGIC[1]);
        msg.push_back(NCP_MSG_MAGIC[2]);
        msg.push_back(static_cast<uint8_t>(E2EMessageType::CAPS_CONFIRM));
        msg.insert(msg.end(), hmac_bytes.begin(), hmac_bytes.end());
        return msg;
    }

    /// Wrap application data with 4-byte tag: 'N','C','P', 0x00
    /// Only call this when BOTH peers are capabilities-aware.
    /// For communication with old peers, send raw data without wrapping.
    static std::vector<uint8_t> wrap_data(
        const std::vector<uint8_t>& data) {

        std::vector<uint8_t> msg;
        msg.reserve(NCP_MSG_TAG_SIZE + data.size());
        msg.push_back(NCP_MSG_MAGIC[0]);
        msg.push_back(NCP_MSG_MAGIC[1]);
        msg.push_back(NCP_MSG_MAGIC[2]);
        msg.push_back(static_cast<uint8_t>(E2EMessageType::DATA));
        msg.insert(msg.end(), data.begin(), data.end());
        return msg;
    }

    /// Peek at message type. Returns DATA for legacy untagged messages.
    static E2EMessageType peek_type(const std::vector<uint8_t>& decrypted) {
        if (!has_magic(decrypted)) return E2EMessageType::DATA;
        return static_cast<E2EMessageType>(decrypted[3]);
    }

    /// Extract payload (strip 4-byte tag).
    /// For legacy untagged messages, returns the full message.
    static std::vector<uint8_t> unwrap(
        const std::vector<uint8_t>& decrypted) {

        if (!has_magic(decrypted)) {
            // Legacy message — no tag to strip
            return decrypted;
        }
        if (decrypted.size() <= NCP_MSG_TAG_SIZE) return {};
        return std::vector<uint8_t>(
            decrypted.begin() + NCP_MSG_TAG_SIZE, decrypted.end());
    }

    /// Parse capabilities from a tagged message.
    static std::optional<NCPCapabilities> parse_capabilities(
        const std::vector<uint8_t>& decrypted_message) {

        if (!has_magic(decrypted_message)) return std::nullopt;
        if (decrypted_message.size() < NCP_MSG_TAG_SIZE + 1) return std::nullopt;
        if (static_cast<E2EMessageType>(decrypted_message[3]) !=
            E2EMessageType::CAPABILITIES) {
            return std::nullopt;
        }
        return NCPCapabilities::deserialize(
            decrypted_message.data() + NCP_MSG_TAG_SIZE,
            decrypted_message.size() - NCP_MSG_TAG_SIZE);
    }

    /// Default timeout for capabilities exchange (milliseconds).
    static constexpr int EXCHANGE_TIMEOUT_MS = 5000;
};

} // namespace ncp

#endif // NCP_CAPABILITIES_HPP
