#pragma once

// ═══════════════════════════════════════════════════════════════════════════
// ncp_mimicry_cli.hpp — shared, testable helpers for the operator CLI surface
// of the mimicry subsystem (porthop secure mode + `ncp mimicry-catalog`).
//
// Everything here is a PURE adapter between argv tokens and the core
// mimicry building blocks (ReferenceProfileCatalog / MimicryCatalogIo /
// MimicryAutoPilot / NcpConnectionDirector). No sockets, no threads, no
// global state — main.cpp owns the I/O loops; these helpers only parse,
// validate, configure and format. The unit tests in
// tests/test_cli_mimicry_flags.cpp exercise this header directly.
//
// Security notes:
//   - SignaturePolicy defaults to ENFORCE and is only relaxed by the
//     explicit, dev-only --mimicry-allow-unsigned-dev escape hatch.
//   - The stats JSON contains NO secrets, NO key material and NO peer
//     addresses — profile ids/revisions, state names and counters only.
// ═══════════════════════════════════════════════════════════════════════════

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <functional>
#include <limits>
#include <memory>
#include <optional>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include "ncp_connection_director.hpp"
#include "ncp_mimicry_autopilot.hpp"
#include "ncp_mimicry_catalog_io.hpp"
#include "ncp_reference_profile_catalog.hpp"

namespace ncp {
namespace cli {

// ---- multi-packet load mode (--mimicry-load-*; client secure mode only) --

/// Load payload wire layout (exactly `size` bytes, size >= kLoadHeaderSize):
///   [0..3]   magic "PHL1"
///   [4..11]  uint64 sequence, little-endian
///   [12..)   deterministic seed-derived pattern (splitmix64 per word)
inline constexpr char kLoadMagic[4] = {'P', 'H', 'L', '1'};
inline constexpr size_t kLoadHeaderSize = 12;

/// Strict bounds for the load knobs. count is capped so every per-sequence
/// bookkeeping structure (bitset, timestamps, RTT samples) stays bounded;
/// size must hold the load header and fit the secure-mode datagram budget
/// (path_mtu 1500 - porthop overhead, mirroring the 1024 --message cap).
inline constexpr uint64_t kLoadCountMax = 100000;
inline constexpr uint64_t kLoadSizeMin = kLoadHeaderSize;
inline constexpr uint64_t kLoadSizeMax = 1024;
inline constexpr uint64_t kLoadRateMin = 1;
inline constexpr uint64_t kLoadRateMax = 100000;  ///< messages per second
inline constexpr uint64_t kLoadDurationMaxSec = 3600;

/// Parsed `--mimicry-load-*` bundle. Load mode is ENABLED by the presence
/// of ANY of these options (defaults below fill the rest). Client secure
/// mode only — handle_porthop rejects these for serve/raw operation.
struct MimicryLoadFlags {
    uint64_t count = 100;        ///< --mimicry-load-count N
    uint64_t size = 128;         ///< --mimicry-load-size N (bytes)
    uint64_t rate = 50;          ///< --mimicry-load-rate R (msg/s pacing)
    uint64_t duration_sec = 0;   ///< --mimicry-load-duration SEC (0 = none)
    uint64_t seed = 1;           ///< --mimicry-load-seed N
    std::string stats_json_path; ///< --mimicry-load-stats-json <path>

    bool count_set = false;
    bool size_set = false;
    bool rate_set = false;
    bool duration_set = false;
    bool seed_set = false;
    bool stats_set = false;

    bool any_set() const {
        return count_set || size_set || rate_set || duration_set ||
               seed_set || stats_set;
    }
    bool enabled() const { return any_set(); }
};

/// Parsed `--mimicry-*` option bundle for `ncp porthop` secure mode.
/// Defaults preserve the pre-existing behavior exactly: ENFORCE signature
/// policy, no allow-list, MANUAL control (only --mimicry-transition
/// requests), adapter default grace, stats printed to stdout.
struct MimicryFlags {
    std::string catalog_path;       ///< --mimicry-catalog <path>
    std::vector<std::string> allowed;  ///< --mimicry-allowed <csv> (parsed)
    bool require_signed = false;    ///< --mimicry-require-signed (explicit ENFORCE)
    bool allow_unsigned_dev = false;///< --mimicry-allow-unsigned-dev (DEV_ONLY)
    bool auto_mode = false;         ///< --mimicry-auto (attach AUTO autopilot)
    bool locked = false;            ///< --mimicry-locked (attach LOCKED autopilot)
    int64_t switch_cooldown_ms = -1;   ///< --mimicry-switch-cooldown <sec>
    int64_t min_dwell_ms = -1;         ///< --mimicry-min-dwell <sec>
    double hysteresis_pct = -1.0;      ///< --mimicry-hysteresis <pct>
    int64_t transition_grace_ms = -1;  ///< --mimicry-transition-grace <ms>
    std::string stats_json_path;    ///< --mimicry-stats-json <path> ("" = stdout)
    bool v2 = true;                 ///< --mimicry-v2 on|off (profile_transition_v2)
    bool v2_set = false;            ///< --mimicry-v2 present on the command line
    MimicryLoadFlags load;          ///< --mimicry-load-* (client secure mode)

    /// True when the operator supplied any --mimicry-* flag beyond
    /// --mimicry-profile/--mimicry-transition (used to reject these flags
    /// when secure mode itself is not enabled).
    bool any_extended_set() const {
        return !catalog_path.empty() || !allowed.empty() || require_signed ||
               allow_unsigned_dev || auto_mode || locked ||
               switch_cooldown_ms >= 0 || min_dwell_ms >= 0 ||
               hysteresis_pct >= 0.0 || transition_grace_ms >= 0 ||
               !stats_json_path.empty() || v2_set || load.any_set();
    }
};

// ---- tiny argv helpers (self-contained twins of the main.cpp statics) ----

inline bool flag_present(const std::vector<std::string>& args,
                         const std::string& flag) {
    for (const auto& a : args)
        if (a == flag) return true;
    return false;
}

inline std::string option_value(const std::vector<std::string>& args,
                                const std::string& option,
                                const std::string& default_val = "") {
    for (size_t i = 0; i + 1 < args.size(); ++i)
        if (args[i] == option) return args[i + 1];
    return default_val;
}

inline std::vector<std::string> split_csv(const std::string& csv) {
    std::vector<std::string> out;
    std::istringstream ss(csv);
    std::string tok;
    while (std::getline(ss, tok, ',')) {
        const size_t s = tok.find_first_not_of(" \t");
        const size_t e = tok.find_last_not_of(" \t");
        if (s != std::string::npos)
            out.push_back(tok.substr(s, e - s + 1));
    }
    return out;
}

/// Parse a non-negative decimal number; false on garbage/range violation.
inline bool parse_u64(const std::string& s, uint64_t lo, uint64_t hi,
                      uint64_t& out) {
    if (s.empty()) return false;
    try {
        size_t idx = 0;
        const uint64_t v = std::stoull(s, &idx, 10);
        if (idx != s.size() || v < lo || v > hi) return false;
        out = v;
        return true;
    } catch (...) {
        return false;
    }
}

inline bool parse_double_range(const std::string& s, double lo, double hi,
                               double& out) {
    if (s.empty()) return false;
    try {
        size_t idx = 0;
        const double v = std::stod(s, &idx);
        if (idx != s.size() || !(v >= lo && v <= hi)) return false;
        out = v;
        return true;
    } catch (...) {
        return false;
    }
}

/// Parse every --mimicry-* flag (except --mimicry-profile /
/// --mimicry-transition, owned by the caller) into `out`. On failure
/// returns false with a human-readable `err` naming the offending flag.
/// Cross-flag conflicts are hard errors; values are range-checked here.
inline bool parse_mimicry_flags(const std::vector<std::string>& args,
                                MimicryFlags& out, std::string& err) {
    out = MimicryFlags{};
    out.catalog_path = option_value(args, "--mimicry-catalog", "");
    const std::string allowed_csv = option_value(args, "--mimicry-allowed", "");
    if (!allowed_csv.empty()) {
        out.allowed = split_csv(allowed_csv);
        if (out.allowed.empty()) {
            err = "--mimicry-allowed: empty profile id list";
            return false;
        }
    }
    out.require_signed = flag_present(args, "--mimicry-require-signed");
    out.allow_unsigned_dev = flag_present(args, "--mimicry-allow-unsigned-dev");
    out.auto_mode = flag_present(args, "--mimicry-auto");
    out.locked = flag_present(args, "--mimicry-locked");
    out.stats_json_path = option_value(args, "--mimicry-stats-json", "");

    if (out.auto_mode && out.locked) {
        err = "--mimicry-auto and --mimicry-locked are mutually exclusive";
        return false;
    }
    if (out.require_signed && out.allow_unsigned_dev) {
        err = "--mimicry-require-signed and --mimicry-allow-unsigned-dev "
              "are mutually exclusive";
        return false;
    }

    uint64_t v = 0;
    const std::string cd = option_value(args, "--mimicry-switch-cooldown", "");
    if (!cd.empty()) {
        if (!parse_u64(cd, 0, 86400, v)) {
            err = "bad --mimicry-switch-cooldown (expected 0..86400 seconds): "
                  + cd;
            return false;
        }
        out.switch_cooldown_ms = static_cast<int64_t>(v) * 1000;
    }
    const std::string dw = option_value(args, "--mimicry-min-dwell", "");
    if (!dw.empty()) {
        if (!parse_u64(dw, 0, 86400, v)) {
            err = "bad --mimicry-min-dwell (expected 0..86400 seconds): " + dw;
            return false;
        }
        out.min_dwell_ms = static_cast<int64_t>(v) * 1000;
    }
    const std::string hy = option_value(args, "--mimicry-hysteresis", "");
    if (!hy.empty()) {
        double d = 0.0;
        if (!parse_double_range(hy, 0.0, 1000.0, d)) {
            err = "bad --mimicry-hysteresis (expected 0..1000 percent): " + hy;
            return false;
        }
        out.hysteresis_pct = d;
    }
    const std::string gr = option_value(args, "--mimicry-transition-grace", "");
    if (!gr.empty()) {
        if (!parse_u64(gr, 0, 600000, v)) {
            err = "bad --mimicry-transition-grace (expected 0..600000 ms): "
                  + gr;
            return false;
        }
        out.transition_grace_ms = static_cast<int64_t>(v);
    }
    // Operator kill-switch for profile_transition_v2: "off" clears
    // NcpMimicrySession::Config::advertise_profile_transition_v2 so the
    // session negotiates v1-only (arbitrary non-generic transition targets
    // and FSM-driven mask variants are then refused / not emitted).
    const std::string v2s = option_value(args, "--mimicry-v2", "");
    if (!v2s.empty()) {
        if (v2s == "on")       out.v2 = true;
        else if (v2s == "off") out.v2 = false;
        else {
            err = "bad --mimicry-v2 (expected on|off): " + v2s;
            return false;
        }
        out.v2_set = true;
    }

    // ---- multi-packet load mode (--mimicry-load-*) ----
    // Presence of any load option enables the mode; strict bounds above.
    {
        auto parse_load_opt = [&](const char* flag, uint64_t lo, uint64_t hi,
                                  uint64_t& dst, bool& seen) -> bool {
            if (!flag_present(args, flag)) return true;
            seen = true;
            const std::string s = option_value(args, flag, "");
            uint64_t x = 0;
            if (s.empty() || !parse_u64(s, lo, hi, x)) {
                err = "bad " + std::string(flag) + " (expected " +
                      std::to_string(lo) + ".." + std::to_string(hi) + "): " +
                      (s.empty() ? "<missing value>" : s);
                return false;
            }
            dst = x;
            return true;
        };
        if (!parse_load_opt("--mimicry-load-count", 1, kLoadCountMax,
                            out.load.count, out.load.count_set))
            return false;
        if (!parse_load_opt("--mimicry-load-size", kLoadSizeMin, kLoadSizeMax,
                            out.load.size, out.load.size_set))
            return false;
        if (!parse_load_opt("--mimicry-load-rate", kLoadRateMin, kLoadRateMax,
                            out.load.rate, out.load.rate_set))
            return false;
        if (!parse_load_opt("--mimicry-load-duration", 0, kLoadDurationMaxSec,
                            out.load.duration_sec, out.load.duration_set))
            return false;
        if (!parse_load_opt("--mimicry-load-seed", 0,
                            std::numeric_limits<uint64_t>::max(),
                            out.load.seed, out.load.seed_set))
            return false;
        if (flag_present(args, "--mimicry-load-stats-json")) {
            // Fail closed: a present flag with a missing/empty path is a
            // parse error, not a silent stdout fallback.
            const std::string p =
                option_value(args, "--mimicry-load-stats-json", "");
            if (p.empty()) {
                err = "bad --mimicry-load-stats-json (expected a file "
                      "path): <missing value>";
                return false;
            }
            out.load.stats_set = true;
            out.load.stats_json_path = p;
        }
    }

    // The autopilot knobs configure the decision loop; without an attached
    // autopilot they would silently do nothing — fail loudly instead.
    if (!out.auto_mode && !out.locked &&
        (out.switch_cooldown_ms >= 0 || out.min_dwell_ms >= 0 ||
         out.hysteresis_pct >= 0.0)) {
        err = "--mimicry-switch-cooldown/--mimicry-min-dwell/"
              "--mimicry-hysteresis require --mimicry-auto or "
              "--mimicry-locked";
        return false;
    }
    return true;
}

/// Allow-list membership (empty allow-list == everything allowed).
inline bool allowed_contains(const MimicryFlags& f,
                             const std::string& profile_id) {
    if (f.allowed.empty()) return true;
    for (const auto& id : f.allowed)
        if (id == profile_id) return true;
    return false;
}

/// Hard-error check for the operator kill-switch: --mimicry-v2 off cannot be
/// combined with a --mimicry-transition target descriptor that requires the
/// profile-transition-v2 capability (the adapter would refuse it at session
/// time anyway — fail at the CLI with a clear message instead). Returns true
/// and sets `err` on conflict.
inline bool v2_kill_switch_conflict(const MimicryFlags& f,
                                    const ProfileDescriptor* transition_desc,
                                    std::string& err) {
    if (f.v2 || !transition_desc) return false;
    if (!descriptor_requires_profile_transition_v2(*transition_desc))
        return false;
    err = "--mimicry-v2 off cannot be combined with the v2-only "
          "--mimicry-transition target '" + transition_desc->profile_id +
          "@" + std::to_string(transition_desc->revision) + "' (requires "
          "the '" + std::string(kCapabilityProfileTransitionV2) +
          "' capability)";
    return true;
}

/// Candidate restriction for an attached autopilot: every catalog profile
/// id NOT on the allow-list is excluded from auto-selection. Manual
/// transitions are validated separately at the CLI level.
inline std::vector<std::string> autopilot_excludes_for_allowed(
        const ReferenceProfileCatalog& catalog,
        const std::vector<std::string>& allowed) {
    std::vector<std::string> excl;
    if (allowed.empty()) return excl;
    auto is_allowed = [&](const std::string& id) {
        for (const auto& a : allowed)
            if (a == id) return true;
        return false;
    };
    for (const auto& canonical : catalog.list()) {  // "id@revision"
        const size_t at = canonical.find('@');
        const std::string id = canonical.substr(0, at);
        if (!is_allowed(id)) {
            bool dup = false;
            for (const auto& e : excl)
                if (e == id) { dup = true; break; }
            if (!dup) excl.push_back(id);
        }
    }
    return excl;
}

/// Build the catalog the CLI hands to the director: legacy built-ins first,
/// then the optional external file through the policy-checked
/// MimicryCatalogIo::load_file path. Returns nullptr on failure with `err`
/// set (container error + per-descriptor registration issues appended);
/// human-facing warnings (e.g. the dev-unsigned escape hatch, WARNED
/// records) are appended to `warnings`.
inline std::unique_ptr<ReferenceProfileCatalog> build_catalog(
        const MimicryFlags& flags, std::string& err,
        std::vector<std::string>& warnings) {
    ReferenceProfileCatalog::Options opts;
    // ENFORCE is the default; --mimicry-require-signed makes that explicit.
    opts.external_policy = flags.allow_unsigned_dev
        ? SignaturePolicy::DEV_UNSIGNED
        : SignaturePolicy::ENFORCE;
    auto catalog = std::unique_ptr<ReferenceProfileCatalog>(
        new ReferenceProfileCatalog(opts));
    catalog->register_legacy_builtins();
    catalog->register_reference_builtins();  // stateful v2 references (§3.2)

    if (flags.allow_unsigned_dev) {
        warnings.push_back(
            "WARNING: --mimicry-allow-unsigned-dev accepts UNSIGNED external "
            "mimicry profiles (SignaturePolicy::DEV_UNSIGNED). Development/"
            "lab use only — never run this against untrusted catalog files.");
    }
    if (flags.catalog_path.empty()) return catalog;

    std::vector<ReferenceProfileCatalog::RegisterOutcome> outcomes;
    MimicryCatalogIo::Error io_err;
    if (!MimicryCatalogIo::load_file(flags.catalog_path, *catalog, &outcomes,
                                     io_err)) {
        std::ostringstream e;
        e << "failed to load mimicry catalog '" << flags.catalog_path
          << "': [" << io_err.code << "] " << io_err.message;
        if (io_err.record != MimicryCatalogIo::kNoRecord)
            e << " (record " << io_err.record << ")";
        for (size_t i = 0; i < outcomes.size(); ++i) {
            const auto& oc = outcomes[i];
            if (oc.ok()) continue;
            e << "\n    descriptor "
              << (oc.canonical_id.empty()
                      ? ("#" + std::to_string(i))
                      : oc.canonical_id)
              << ":";
            for (const auto& is : oc.issues)
                e << " [" << is.code << "] " << is.message;
        }
        err = e.str();
        return nullptr;
    }
    for (const auto& oc : outcomes) {
        if (oc.status == ReferenceProfileCatalog::RegisterStatus::WARNED) {
            std::ostringstream w;
            w << "catalog record " << oc.canonical_id << " accepted with"
              << " warnings:";
            for (const auto& is : oc.issues)
                w << " [" << is.code << "] " << is.message;
            warnings.push_back(w.str());
        }
    }
    return catalog;
}

/// Autopilot configuration for --mimicry-auto / --mimicry-locked. The
/// caller owns the catalog and the request functor target (the director);
/// both must outlive the autopilot. `wire_version` must match the session
/// template's mimic wire version so candidate eligibility agrees with the
/// negotiated wire format.
inline MimicryAutoPilot::Config make_autopilot_config(
        const MimicryFlags& flags, const ReferenceProfileCatalog& catalog,
        std::function<MimicryAutoPilot::TransitionResult(const std::string&,
                                                         uint32_t)>
            request_transition,
        uint32_t wire_version) {
    MimicryAutoPilot::Config c;
    c.enabled = true;
    c.mode = flags.auto_mode ? MimicryAutoPilot::Mode::AUTO
                             : MimicryAutoPilot::Mode::LOCKED;
    c.catalog = &catalog;
    c.request_transition = std::move(request_transition);
    c.wire_version = wire_version;
    if (flags.switch_cooldown_ms >= 0) c.cooldown_ms = flags.switch_cooldown_ms;
    if (flags.min_dwell_ms >= 0) c.min_dwell_ms = flags.min_dwell_ms;
    if (flags.hysteresis_pct >= 0.0) c.hysteresis_pct = flags.hysteresis_pct;
    c.exclude_profile_ids =
        autopilot_excludes_for_allowed(catalog, flags.allowed);
    return c;
}

// ---- load message construction / verification (deterministic, pure) ----

/// Stateless deterministic pattern word (splitmix64 finalizer over a mixed
/// seed/sequence/word-index key). No generator state — the same (seed, seq,
/// idx) triple always yields the same word on every platform.
inline uint64_t load_pattern_word(uint64_t seed, uint64_t seq, uint64_t idx) {
    uint64_t z = seed + 0x9E3779B97F4A7C15ULL;
    z ^= seq * 0xBF58476D1CE4E5B9ULL + 0x2545F4914F6CDD1DULL;
    z ^= (idx + 1) * 0x94D049BB133111EBULL;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

/// Build the deterministic load message for (seed, seq) with exactly `size`
/// bytes (size >= kLoadHeaderSize). Never logged as payload.
inline void build_load_message(uint64_t seed, uint64_t seq, size_t size,
                               std::vector<uint8_t>& out) {
    out.resize(size);
    std::memcpy(out.data(), kLoadMagic, 4);
    for (int i = 0; i < 8; ++i)
        out[4 + i] = static_cast<uint8_t>((seq >> (8 * i)) & 0xFF);
    size_t pos = kLoadHeaderSize;
    uint64_t idx = 0;
    while (pos < size) {
        const uint64_t w = load_pattern_word(seed, seq, idx++);
        for (int i = 0; i < 8 && pos < size; ++i, ++pos)
            out[pos] = static_cast<uint8_t>((w >> (8 * i)) & 0xFF);
    }
}

/// Full structural + pattern verification of a received echo. Returns false
/// (corrupted) for a wrong size, bad magic or any payload mismatch; on
/// success extracts the little-endian sequence number.
inline bool verify_load_message(uint64_t seed, size_t expected_size,
                                const uint8_t* data, size_t len,
                                uint64_t& seq) {
    if (len != expected_size || len < kLoadHeaderSize) return false;
    if (std::memcmp(data, kLoadMagic, 4) != 0) return false;
    uint64_t s = 0;
    for (int i = 0; i < 8; ++i)
        s |= static_cast<uint64_t>(data[4 + i]) << (8 * i);
    std::vector<uint8_t> expected;
    build_load_message(seed, s, expected_size, expected);
    if (std::memcmp(data, expected.data(), len) != 0) return false;
    seq = s;
    return true;
}

// ---- self-contained streaming SHA-256 (FIPS 180-4) ----
// Header-local so the load verification stays hermetic and unit-testable
// without pulling libsodium internals into the CLI adapter. Used for the
// canonical sent / received-unique stream hashes.

class Sha256Stream {
public:
    Sha256Stream() { reset(); }

    void reset() {
        state_ = {0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
                  0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u};
        total_ = 0;
        buflen_ = 0;
    }

    void update(const uint8_t* data, size_t len) {
        total_ += len;
        while (len > 0) {
            const size_t take = std::min(len, 64 - buflen_);
            std::memcpy(buf_.data() + buflen_, data, take);
            buflen_ += take;
            data += take;
            len -= take;
            if (buflen_ == 64) {
                compress(buf_.data());
                buflen_ = 0;
            }
        }
    }

    void update(const std::vector<uint8_t>& v) {
        if (!v.empty()) update(v.data(), v.size());
    }

    /// Non-destructive: the stream stays usable after final().
    std::array<uint8_t, 32> final() const {
        Sha256Stream c = *this;
        const uint64_t bitlen = c.total_ * 8;
        const uint8_t one = 0x80;
        c.update(&one, 1);
        const uint8_t zero = 0;
        while (c.buflen_ != 56) c.update(&zero, 1);
        uint8_t lenbe[8];
        for (int i = 0; i < 8; ++i)
            lenbe[i] = static_cast<uint8_t>((bitlen >> (56 - 8 * i)) & 0xFF);
        c.update(lenbe, 8);
        std::array<uint8_t, 32> out{};
        for (int i = 0; i < 8; ++i)
            for (int b = 0; b < 4; ++b)
                out[i * 4 + b] =
                    static_cast<uint8_t>((c.state_[i] >> (24 - 8 * b)) & 0xFF);
        return out;
    }

    std::string hex() const {
        const auto d = final();
        char buf[65];
        for (int i = 0; i < 32; ++i)
            std::snprintf(buf + i * 2, 3, "%02x", d[i]);
        return std::string(buf, 64);
    }

private:
    void compress(const uint8_t* block) {
        static constexpr uint32_t k[64] = {
            0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
            0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
            0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
            0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
            0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
            0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
            0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
            0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
            0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
            0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
            0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
            0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
            0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
            0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
            0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
            0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u};
        uint32_t w[64];
        for (int i = 0; i < 16; ++i)
            w[i] = (uint32_t(block[i * 4]) << 24) |
                   (uint32_t(block[i * 4 + 1]) << 16) |
                   (uint32_t(block[i * 4 + 2]) << 8) |
                   uint32_t(block[i * 4 + 3]);
        for (int i = 16; i < 64; ++i) {
            const uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^
                                (w[i - 15] >> 3);
            const uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^
                                (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }
        uint32_t a = state_[0], b = state_[1], c = state_[2], d = state_[3],
                 e = state_[4], f = state_[5], g = state_[6], h = state_[7];
        for (int i = 0; i < 64; ++i) {
            const uint32_t s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
            const uint32_t ch = (e & f) ^ (~e & g);
            const uint32_t t1 = h + s1 + ch + k[i] + w[i];
            const uint32_t s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
            const uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            const uint32_t t2 = s0 + maj;
            h = g; g = f; f = e; e = d + t1;
            d = c; c = b; b = a; a = t1 + t2;
        }
        state_[0] += a; state_[1] += b; state_[2] += c; state_[3] += d;
        state_[4] += e; state_[5] += f; state_[6] += g; state_[7] += h;
    }

    static uint32_t rotr(uint32_t x, unsigned n) {
        return (x >> n) | (x << (32 - n));
    }

    std::array<uint32_t, 8> state_{};
    std::array<uint8_t, 64> buf_{};
    uint64_t total_ = 0;
    size_t buflen_ = 0;
};

// ---- load run metrics (bounded memory, reorder-tolerant canonical hash) --

struct MimicryLoadMetrics {
    uint64_t requested = 0;        ///< operator --mimicry-load-count
    uint64_t attempted = 0;        ///< sends attempted (duration may cut)
    uint64_t sent = 0;             ///< accepted by the director
    uint64_t send_errors = 0;
    uint64_t received_unique = 0;  ///< verified echoes, first copy only
    uint64_t duplicates = 0;
    uint64_t out_of_order = 0;
    uint64_t corrupted = 0;
    uint64_t missing = 0;          ///< sent but never verified
    uint64_t elapsed_ms = 0;
    double offered_goodput_bps = 0.0;   ///< sent payload bytes / elapsed
    double verified_goodput_bps = 0.0;  ///< verified echo bytes / elapsed
    bool has_rtt = false;
    double rtt_p50_ms = 0.0;
    double rtt_p95_ms = 0.0;
    double rtt_p99_ms = 0.0;
    std::string sha256_sent;            ///< canonical sent stream (seq order)
    std::string sha256_received_unique; ///< canonical unique echoes (seq order)
    bool passed = false;
};

/// Per-run load tracker. Bounded memory: a received-bitset and one send
/// timestamp per sequence (count is capped by kLoadCountMax) plus one RTT
/// sample per verified echo. The canonical received hash is computed at
/// finalize() in ascending sequence order, so transient UDP reordering
/// counts toward out_of_order but never falsely breaks the stream hash.
class MimicryLoadTracker {
public:
    MimicryLoadTracker(uint64_t seed, uint64_t size, uint64_t max_seq)
        : seed_(seed),
          size_(size),
          received_bits_(static_cast<size_t>((max_seq + 63) / 64), 0),
          send_ts_(static_cast<size_t>(max_seq), kNoTs) {}

    void note_sent(uint64_t seq, const std::vector<uint8_t>& bytes,
                   uint32_t t_rel_ms) {
        sha_sent_.update(bytes);
        if (seq < send_ts_.size()) send_ts_[static_cast<size_t>(seq)] = t_rel_ms;
        ++sent_;
    }
    void note_send_error() { ++send_errors_; }

    void note_received(const uint8_t* data, size_t len, uint32_t t_rel_ms) {
        uint64_t seq = 0;
        if (!verify_load_message(seed_, size_, data, len, seq) ||
            seq >= send_ts_.size() ||
            send_ts_[static_cast<size_t>(seq)] == kNoTs) {
            ++corrupted_;  // bad magic/size/pattern or never sent by us
            return;
        }
        const size_t word = static_cast<size_t>(seq >> 6);
        const uint64_t bit = 1ULL << (seq & 63);
        if (received_bits_[word] & bit) {
            ++duplicates_;
            return;
        }
        received_bits_[word] |= bit;
        ++received_unique_;
        if (seq < max_received_seq_) ++out_of_order_;
        else max_received_seq_ = seq;
        rtt_ms_.push_back(t_rel_ms - send_ts_[static_cast<size_t>(seq)]);
    }

    uint64_t sent() const { return sent_; }
    uint64_t received_unique() const { return received_unique_; }

    /// Matured quality sample for the live MimicryAutoPilot feed. Only sends
    /// older than settle_ms are counted, so recently-sent outstanding echoes
    /// are not misclassified as loss. Counters are cumulative over the matured
    /// prefix; repeated calls are idempotent and never consume tracker state.
    bool autopilot_metrics(uint32_t now_rel_ms, uint32_t settle_ms,
                           MimicryAutoPilot::UdpMetrics& out) const {
        if (now_rel_ms <= settle_ms) return false;
        const uint32_t cutoff = now_rel_ms - settle_ms;
        uint64_t matured = 0;
        uint64_t verified = 0;
        for (size_t seq = 0; seq < send_ts_.size(); ++seq) {
            const uint32_t sent_ts = send_ts_[seq];
            if (sent_ts == kNoTs || sent_ts > cutoff) continue;
            ++matured;
            const size_t word = seq >> 6;
            if (received_bits_[word] & (1ULL << (seq & 63))) ++verified;
        }
        if (matured == 0) return false;
        out = MimicryAutoPilot::UdpMetrics{};
        out.loss_ratio = static_cast<double>(matured - verified) /
                         static_cast<double>(matured);
        out.packets = matured;
        out.throughput_bps = static_cast<double>(verified) * size_ * 8.0 *
                             1000.0 / static_cast<double>(now_rel_ms);
        if (!rtt_ms_.empty()) {
            std::vector<uint32_t> sorted = rtt_ms_;
            std::sort(sorted.begin(), sorted.end());
            out.rtt_ms = percentile(sorted, 95.0);
        }
        return true;
    }

    MimicryLoadMetrics finalize(uint64_t requested, uint64_t attempted,
                                uint64_t elapsed_ms) const {
        MimicryLoadMetrics m;
        m.requested = requested;
        m.attempted = attempted;
        m.sent = sent_;
        m.send_errors = send_errors_;
        m.received_unique = received_unique_;
        m.duplicates = duplicates_;
        m.out_of_order = out_of_order_;
        m.corrupted = corrupted_;
        m.missing = sent_ - received_unique_;
        m.elapsed_ms = elapsed_ms;
        if (elapsed_ms > 0) {
            m.offered_goodput_bps =
                static_cast<double>(sent_) * size_ * 8.0 * 1000.0 /
                static_cast<double>(elapsed_ms);
            m.verified_goodput_bps =
                static_cast<double>(received_unique_) * size_ * 8.0 * 1000.0 /
                static_cast<double>(elapsed_ms);
        }
        if (!rtt_ms_.empty()) {
            std::vector<uint32_t> sorted = rtt_ms_;
            std::sort(sorted.begin(), sorted.end());
            m.has_rtt = true;
            m.rtt_p50_ms = percentile(sorted, 50.0);
            m.rtt_p95_ms = percentile(sorted, 95.0);
            m.rtt_p99_ms = percentile(sorted, 99.0);
        }
        // Canonical received-unique stream hash: ascending sequence order,
        // payload bytes re-derived (each was memcmp-verified at receive).
        Sha256Stream h;
        std::vector<uint8_t> buf;
        for (uint64_t seq = 0; seq < attempted; ++seq) {
            const size_t word = static_cast<size_t>(seq >> 6);
            if (!(received_bits_[word] & (1ULL << (seq & 63)))) continue;
            build_load_message(seed_, seq, size_, buf);
            h.update(buf);
        }
        m.sha256_received_unique = h.hex();
        m.sha256_sent = sha_sent_.hex();
        m.passed = send_errors_ == 0 && corrupted_ == 0 && m.missing == 0 &&
                   attempted > 0 && sent_ == attempted &&
                   received_unique_ == sent_ &&
                   m.sha256_sent == m.sha256_received_unique;
        return m;
    }

private:
    static constexpr uint32_t kNoTs = 0xFFFFFFFFu;

    static double percentile(const std::vector<uint32_t>& sorted, double p) {
        // nearest-rank
        size_t rank = static_cast<size_t>((p / 100.0) * sorted.size() + 0.5);
        if (rank == 0) rank = 1;
        if (rank > sorted.size()) rank = sorted.size();
        return static_cast<double>(sorted[rank - 1]);
    }

    uint64_t seed_;
    uint64_t size_;
    Sha256Stream sha_sent_;
    std::vector<uint64_t> received_bits_;
    std::vector<uint32_t> send_ts_;
    std::vector<uint32_t> rtt_ms_;
    uint64_t sent_ = 0;
    uint64_t send_errors_ = 0;
    uint64_t received_unique_ = 0;
    uint64_t duplicates_ = 0;
    uint64_t out_of_order_ = 0;
    uint64_t corrupted_ = 0;
    uint64_t max_received_seq_ = 0;
};

/// Load teardown report (schema_version=1): counters, goodput, RTT
/// percentiles and canonical stream hashes only — NO payload bytes, NO peer
/// addresses, NO secrets. The seed is a pattern seed, not key material.
inline std::string mimicry_load_stats_json(const MimicryLoadMetrics& m,
                                           const MimicryLoadFlags& cfg) {
    std::ostringstream j;
    j.setf(std::ios::fixed);
    j.precision(3);
    j << "{\"schema_version\":1,\"type\":\"porthop_mimicry_load\""
      << ",\"config\":{\"size\":" << cfg.size << ",\"seed\":" << cfg.seed
      << ",\"rate\":" << cfg.rate << ",\"duration_sec\":" << cfg.duration_sec
      << "}"
      << ",\"requested\":" << m.requested
      << ",\"attempted\":" << m.attempted
      << ",\"sent\":" << m.sent
      << ",\"send_errors\":" << m.send_errors
      << ",\"received_unique\":" << m.received_unique
      << ",\"duplicates\":" << m.duplicates
      << ",\"out_of_order\":" << m.out_of_order
      << ",\"corrupted\":" << m.corrupted
      << ",\"missing\":" << m.missing
      << ",\"elapsed_ms\":" << m.elapsed_ms
      << ",\"offered_goodput_bps\":" << m.offered_goodput_bps
      << ",\"verified_goodput_bps\":" << m.verified_goodput_bps
      << ",\"rtt_ms\":";
    if (m.has_rtt) {
        j << "{\"p50\":" << m.rtt_p50_ms << ",\"p95\":" << m.rtt_p95_ms
          << ",\"p99\":" << m.rtt_p99_ms << "}";
    } else {
        j << "null";
    }
    j << ",\"sha256_sent\":\"" << m.sha256_sent << "\""
      << ",\"sha256_received_unique\":\"" << m.sha256_received_unique << "\""
      << ",\"passed\":" << (m.passed ? "true" : "false") << "}";
    return j.str();
}

// ---- compact stats JSON (no secrets, no peer addresses) ----

inline std::string json_escape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 2);
    for (char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                    out += buf;
                } else {
                    out += c;
                }
        }
    }
    return out;
}

inline std::string profile_ref_json(const ProfileRef& r) {
    std::ostringstream j;
    j << "{\"id\":\"" << json_escape(r.id) << "\",\"revision\":" << r.revision
      << "}";
    return j.str();
}

/// Per-session adapter snapshot as a compact JSON object.
inline std::string session_stats_json(const NcpMimicrySession::Stats& s) {
    std::ostringstream j;
    j << "{\"established\":" << (s.established ? "true" : "false")
      << ",\"transition_capable\":" << (s.transition_capable ? "true" : "false")
      << ",\"profile\":" << profile_ref_json(s.active_profile)
      << ",\"pending_profile\":";
    if (s.pending_profile) j << profile_ref_json(*s.pending_profile);
    else                   j << "null";
    j << ",\"transition_state\":\""
      << ncp::to_string(s.transition_state) << "\""
      << ",\"crypto_epoch\":" << s.crypto_epoch
      << ",\"profile_epoch\":" << s.profile_epoch
      << ",\"mtu_budget_rejections\":" << s.mtu_budget_rejections
      << ",\"ingress_dropped\":" << s.ingress_dropped
      << ",\"transitions\":{"
      << "\"started\":" << s.transition_counters.transitions_started
      << ",\"committed\":" << s.transition_counters.transitions_committed
      << ",\"effective\":" << s.transition_counters.transitions_effective
      << ",\"aborted\":" << s.transition_counters.transitions_aborted
      << ",\"timed_out\":" << s.transition_counters.transitions_timed_out
      << ",\"uncertain\":" << s.transition_counters.transitions_uncertain
      << "}}";
    return j.str();
}

/// Director aggregate counters as a compact JSON object.
inline std::string director_stats_json(const NcpConnectionDirector::Stats& d) {
    std::ostringstream j;
    j << "{\"sessions_created\":" << d.sessions_created
      << ",\"sessions_removed\":" << d.sessions_removed
      << ",\"datagrams_in\":" << d.datagrams_in
      << ",\"datagrams_out\":" << d.datagrams_out
      << ",\"app_messages_in\":" << d.app_messages_in
      << ",\"app_messages_out\":" << d.app_messages_out
      << ",\"ingress_unknown_session\":" << d.ingress_unknown_session
      << ",\"requests_enqueued\":" << d.requests_enqueued
      << ",\"requests_applied\":" << d.requests_applied
      << ",\"requests_failed\":" << d.requests_failed
      << ",\"transition_commits_reported\":" << d.transition_commits_reported
      << ",\"transition_aborts_reported\":" << d.transition_aborts_reported
      << ",\"transition_feedback_timeouts\":"
      << d.transition_feedback_timeouts
      << "}";
    return j.str();
}

/// Full teardown report: role, per-session snapshots, director aggregates
/// and (when attached) the autopilot's own JSON block (embedded verbatim —
/// it is already guaranteed free of secrets/addresses).
inline std::string mimicry_stats_json(
        const char* role,
        const std::vector<std::pair<uint64_t, NcpMimicrySession::Stats>>&
            sessions,
        const NcpConnectionDirector::Stats& director,
        const std::string& autopilot_json = "") {
    std::ostringstream j;
    j << "{\"role\":\"" << role << "\",\"sessions\":[";
    bool first = true;
    for (const auto& kv : sessions) {
        if (!first) j << ",";
        first = false;
        j << "{\"session_id\":" << kv.first
          << ",\"stats\":" << session_stats_json(kv.second) << "}";
    }
    j << "],\"director\":" << director_stats_json(director);
    if (!autopilot_json.empty()) j << ",\"autopilot\":" << autopilot_json;
    j << "}";
    return j.str();
}

/// Write the teardown report to `path` (--mimicry-stats-json), using the
/// atomic tmp+rename pattern. Returns false with `err` set on write
/// failure. The stdout variant is handled by the caller (print when
/// MimicryFlags::stats_json_path is empty).
inline bool write_mimicry_stats_file(const std::string& path,
                                     const std::string& json,
                                     std::string& err) {
    const std::string tmp = path + ".tmp";
    {
        std::ofstream f(tmp, std::ios::trunc);
        if (!f) {
            err = "cannot open stats file for writing: " + tmp;
            return false;
        }
        f << json << "\n";
        if (!f) {
            err = "failed writing stats file: " + tmp;
            std::remove(tmp.c_str());
            return false;
        }
    }
    if (std::rename(tmp.c_str(), path.c_str()) != 0) {
        std::remove(path.c_str());
        if (std::rename(tmp.c_str(), path.c_str()) != 0) {
            std::remove(tmp.c_str());
            err = "cannot move stats file into place: " + path;
            return false;
        }
    }
    return true;
}

} // namespace cli
} // namespace ncp
