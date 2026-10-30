/**
 * @file ncp_mimicry_catalog_io.cpp
 * @brief Safe, versioned file IO for ReferenceProfileCatalog descriptors.
 *
 * Deterministic bounded binary container (see header for the format).
 * Crypto: libsodium only (BLAKE2b-256 via crypto_generichash for the
 * container checksum) — same hard dependency as the catalog itself.
 * No payload bytes, PCAP content, IP addresses or private keys are ever
 * written or read here; records carry only ProfileDescriptor metadata,
 * public artifact signatures and content hashes.
 */

#include "ncp_mimicry_catalog_io.hpp"

#ifndef HAVE_SODIUM
#error "libsodium is required for ncp_mimicry_catalog_io. Rebuild with -DHAVE_SODIUM=ON"
#endif

#include <sodium.h>

#include <algorithm>
#include <cstring>
#include <fstream>
#include <set>
#include <utility>

namespace ncp {

namespace {

void ensure_sodium() {
    static const int rc = sodium_init();
    (void)rc;
}

// ==================== Limits helpers ====================

uint32_t min_u32(uint32_t a, uint32_t b) { return a < b ? a : b; }

// ==================== Writer ====================

class IoWriter {
public:
    std::vector<uint8_t> out;

    void u8(uint8_t v) { out.push_back(v); }

    void u32(uint32_t v) {
        for (int i = 0; i < 4; ++i)
            out.push_back(static_cast<uint8_t>(v >> (8 * i)));
    }

    void u64(uint64_t v) {
        for (int i = 0; i < 8; ++i)
            out.push_back(static_cast<uint8_t>(v >> (8 * i)));
    }

    void f64(double v) {
        uint64_t bits;
        static_assert(sizeof(bits) == sizeof(v), "double must be 64-bit");
        std::memcpy(&bits, &v, sizeof(bits));
        u64(bits);
    }

    void boolean(bool v) { u8(v ? 1 : 0); }

    void str(const std::string& s) {
        u32(static_cast<uint32_t>(s.size()));
        out.insert(out.end(), s.begin(), s.end());
    }

    void bytes(const std::vector<uint8_t>& b) {
        u32(static_cast<uint32_t>(b.size()));
        out.insert(out.end(), b.begin(), b.end());
    }
};

void write_capture(IoWriter& w, const CaptureProvenance& c) {
    w.str(c.capture_id);
    w.str(c.capture_hash);
    w.str(c.environment);
    w.str(c.session_group);
    w.u64(c.captured_epoch);
    w.u32(c.duration_s);
    w.boolean(c.negative_control);
}

/// Encode one full descriptor record body (signature + content_hash
/// included). Capability and capture lists are order-normalised exactly
/// like canonical_serialize(); normalisation is hash-neutral because the
/// canonical form applies the same ordering.
void write_descriptor(IoWriter& w, const ProfileDescriptor& d) {
    // ---- identity / versioning ----
    w.u32(d.schema_version);
    w.str(d.profile_id);
    w.u32(d.revision);
    w.u32(static_cast<uint32_t>(d.family));
    w.u32(d.min_wire_version);
    w.u32(d.max_wire_version);

    // ---- capabilities: sorted + deduped (canonical order) ----
    {
        std::vector<std::string> caps = d.required_capabilities;
        std::sort(caps.begin(), caps.end());
        caps.erase(std::unique(caps.begin(), caps.end()), caps.end());
        w.u32(static_cast<uint32_t>(caps.size()));
        for (const auto& c : caps) w.str(c);
    }

    // ---- size model ----
    w.u32(static_cast<uint32_t>(d.sizes.kind));
    w.f64(d.sizes.mean);
    w.f64(d.sizes.stddev);
    w.u32(static_cast<uint32_t>(d.sizes.components.size()));
    for (const auto& c : d.sizes.components) {
        w.f64(c.weight);
        w.f64(c.mean);
        w.f64(c.stddev);
    }
    w.f64(d.sizes.clamp_min);
    w.f64(d.sizes.clamp_max);

    // ---- IAT model ----
    w.u32(static_cast<uint32_t>(d.iat.kind));
    w.f64(d.iat.mean_ms);
    w.f64(d.iat.stddev_ms);
    w.f64(d.iat.fixed_ms);

    // ---- joint size/IAT ----
    w.boolean(d.joint.has_value());
    if (d.joint) {
        w.f64(d.joint->correlation);
        w.u32(d.joint->lag_packets);
    }

    // ---- burst ----
    w.boolean(d.burst.enabled);
    w.f64(d.burst.mean_burst_packets);
    w.f64(d.burst.mean_burst_gap_ms);
    w.u32(static_cast<uint32_t>(d.burst.direction));

    // ---- FSM ----
    w.boolean(d.fsm.enabled);
    w.str(d.fsm.initial_state);
    w.u32(static_cast<uint32_t>(d.fsm.states.size()));
    for (const auto& s : d.fsm.states) {
        w.str(s.name);
        w.f64(s.dwell_mean_ms);
        w.f64(s.dwell_stddev_ms);
    }
    w.u32(static_cast<uint32_t>(d.fsm.transitions.size()));
    for (const auto& t : d.fsm.transitions) {
        w.str(t.from);
        w.str(t.to);
        w.f64(t.probability);
    }

    // ---- padding / header / MTU ----
    w.u32(d.padding_header.header_overhead_bytes);
    w.u32(d.padding_header.padding_block_bytes);
    w.u32(d.padding_header.padding_max_bytes);
    w.boolean(d.padding_header.pad_to_block);
    w.u32(d.mtu.path_mtu_bytes);
    w.u32(d.mtu.max_payload_bytes);

    // ---- provenance ----
    w.u64(d.provenance.sample_count);
    w.u64(d.provenance.window_count);
    {
        std::vector<CaptureProvenance> caps = d.provenance.captures;
        std::sort(caps.begin(), caps.end(),
                  [](const CaptureProvenance& a, const CaptureProvenance& b) {
                      return a.capture_id < b.capture_id;
                  });
        w.u32(static_cast<uint32_t>(caps.size()));
        for (const auto& c : caps) write_capture(w, c);
    }

    // ---- derivation bounds ----
    w.f64(d.derivation.size_mean_rel_jitter);
    w.f64(d.derivation.iat_mean_rel_jitter);
    w.f64(d.derivation.burst_rel_jitter);
    w.f64(d.derivation.fsm_dwell_rel_jitter);
    w.u32(d.derivation.padding_extra_max_bytes);
    w.u32(d.derivation.header_gap_shift_max_bytes);

    // ---- artifact signature ----
    w.boolean(d.signature.present);
    w.str(d.signature.scheme);
    w.str(d.signature.key_id);
    w.bytes(d.signature.signature);

    // ---- content hash ----
    w.str(d.content_hash);
}

// ==================== Reader ====================

class IoReader {
public:
    IoReader(const uint8_t* data, size_t size,
             const MimicryCatalogIo::Limits& lim,
             MimicryCatalogIo::Error& err, uint32_t record)
        : data_(data), size_(size), lim_(lim), err_(err), record_(record) {}

    bool ok() const { return err_.code.empty(); }
    size_t pos() const { return pos_; }
    size_t remaining() const { return size_ - pos_; }

    bool fail(const char* code, std::string msg) {
        if (err_.code.empty()) {
            err_.code = code;
            err_.message = std::move(msg);
            err_.byte_offset = pos_;
            err_.record = record_;
        }
        return false;
    }

    bool take(size_t n) {
        if (n > remaining()) {
            pos_ = size_;
            return fail("truncated", "unexpected end of container");
        }
        pos_ += n;
        return true;
    }

    bool u8(uint8_t& v) {
        if (!take(1)) return false;
        v = data_[pos_ - 1];
        return true;
    }

    bool u32(uint32_t& v) {
        if (!take(4)) return false;
        const uint8_t* p = data_ + (pos_ - 4);
        v = static_cast<uint32_t>(p[0]) |
            (static_cast<uint32_t>(p[1]) << 8) |
            (static_cast<uint32_t>(p[2]) << 16) |
            (static_cast<uint32_t>(p[3]) << 24);
        return true;
    }

    bool u64(uint64_t& v) {
        if (!take(8)) return false;
        const uint8_t* p = data_ + (pos_ - 8);
        v = 0;
        for (int i = 0; i < 8; ++i)
            v |= static_cast<uint64_t>(p[i]) << (8 * i);
        return true;
    }

    bool f64(double& v) {
        uint64_t bits;
        if (!u64(bits)) return false;
        static_assert(sizeof(bits) == sizeof(v), "double must be 64-bit");
        std::memcpy(&v, &bits, sizeof(v));
        return true;
    }

    /// Strict boolean: only 0x00 / 0x01 are well-formed.
    bool boolean(bool& v) {
        uint8_t b;
        if (!u8(b)) return false;
        if (b > 1)
            return fail("boolean_out_of_range", "boolean field is not 0 or 1");
        v = (b != 0);
        return true;
    }

    /// Length-prefixed string with a hard bound checked BEFORE allocation.
    bool str(std::string& s, uint32_t max_len) {
        uint32_t len;
        if (!u32(len)) return false;
        if (len > max_len)
            return fail("string_too_long", "string field exceeds bound");
        if (!take(len)) return false;
        s.assign(reinterpret_cast<const char*>(data_ + (pos_ - len)), len);
        return true;
    }

    /// Length-prefixed byte vector with a hard bound checked BEFORE
    /// allocation.
    bool bytes(std::vector<uint8_t>& v, uint32_t max_len) {
        uint32_t len;
        if (!u32(len)) return false;
        if (len > max_len)
            return fail("signature_too_large", "byte field exceeds bound");
        if (!take(len)) return false;
        v.assign(data_ + (pos_ - len), data_ + pos_);
        return true;
    }

    /// Bounded vector element count checked BEFORE allocation.
    bool count(uint32_t& n, uint32_t max_n, const char* what) {
        if (!u32(n)) return false;
        if (n > max_n)
            return fail("count_out_of_range",
                        std::string(what) + " count exceeds bound");
        return true;
    }

    template <typename E>
    bool enumeration(E& v, uint32_t max_value, const char* what) {
        uint32_t raw;
        if (!u32(raw)) return false;
        if (raw > max_value)
            return fail("enum_out_of_range",
                        std::string(what) + " value out of range");
        v = static_cast<E>(raw);
        return true;
    }

private:
    const uint8_t* data_;
    size_t size_;
    size_t pos_ = 0;
    const MimicryCatalogIo::Limits& lim_;
    MimicryCatalogIo::Error& err_;
    uint32_t record_;
};

bool read_capture(IoReader& r, CaptureProvenance& c,
                  const MimicryCatalogIo::Limits& lim) {
    return r.str(c.capture_id, lim.max_string_len) &&
           r.str(c.capture_hash, lim.max_string_len) &&
           r.str(c.environment, lim.max_string_len) &&
           r.str(c.session_group, lim.max_string_len) &&
           r.u64(c.captured_epoch) && r.u32(c.duration_s) &&
           r.boolean(c.negative_control);
}

/// Decode one full descriptor record body from `r`. On return with
/// r.ok(), every field of `d` is populated (signature + content_hash
/// included). Semantic validation is intentionally left to the catalog.
bool read_descriptor(IoReader& r, ProfileDescriptor& d,
                     const MimicryCatalogIo::Limits& lim) {
    // ---- identity / versioning ----
    if (!r.u32(d.schema_version)) return false;
    if (!r.str(d.profile_id, lim.max_string_len)) return false;
    if (!r.u32(d.revision)) return false;
    if (!r.enumeration(d.family, 10 /* ProtocolFamily::STUN */,
                       "protocol family"))
        return false;
    if (!r.u32(d.min_wire_version)) return false;
    if (!r.u32(d.max_wire_version)) return false;

    // ---- capabilities ----
    {
        uint32_t n;
        if (!r.count(n, lim.max_capabilities, "capability")) return false;
        d.required_capabilities.clear();
        d.required_capabilities.reserve(n);
        for (uint32_t i = 0; i < n; ++i) {
            std::string c;
            if (!r.str(c, lim.max_string_len)) return false;
            d.required_capabilities.push_back(std::move(c));
        }
    }

    // ---- size model ----
    if (!r.enumeration(d.sizes.kind, 2 /* DISCRETE_MIX */, "size dist kind"))
        return false;
    if (!r.f64(d.sizes.mean) || !r.f64(d.sizes.stddev)) return false;
    {
        uint32_t n;
        if (!r.count(n, lim.max_mix_components, "size mix component"))
            return false;
        d.sizes.components.clear();
        d.sizes.components.reserve(n);
        for (uint32_t i = 0; i < n; ++i) {
            SizeDistribution::Component c;
            if (!r.f64(c.weight) || !r.f64(c.mean) || !r.f64(c.stddev))
                return false;
            d.sizes.components.push_back(c);
        }
    }
    if (!r.f64(d.sizes.clamp_min) || !r.f64(d.sizes.clamp_max)) return false;

    // ---- IAT model ----
    if (!r.enumeration(d.iat.kind, 2 /* FIXED */, "interval kind"))
        return false;
    if (!r.f64(d.iat.mean_ms) || !r.f64(d.iat.stddev_ms) ||
        !r.f64(d.iat.fixed_ms))
        return false;

    // ---- joint size/IAT ----
    {
        bool present;
        if (!r.boolean(present)) return false;
        if (present) {
            ReferenceJointSizeIatModel j;
            if (!r.f64(j.correlation) || !r.u32(j.lag_packets)) return false;
            d.joint = j;
        } else {
            d.joint.reset();
        }
    }

    // ---- burst ----
    if (!r.boolean(d.burst.enabled)) return false;
    if (!r.f64(d.burst.mean_burst_packets) ||
        !r.f64(d.burst.mean_burst_gap_ms))
        return false;
    if (!r.enumeration(d.burst.direction, 3 /* SYMMETRIC */,
                       "direction model"))
        return false;

    // ---- FSM ----
    if (!r.boolean(d.fsm.enabled)) return false;
    if (!r.str(d.fsm.initial_state, lim.max_string_len)) return false;
    {
        uint32_t n;
        if (!r.count(n, lim.max_fsm_states, "FSM state")) return false;
        d.fsm.states.clear();
        d.fsm.states.reserve(n);
        for (uint32_t i = 0; i < n; ++i) {
            FsmState s;
            if (!r.str(s.name, lim.max_string_len) ||
                !r.f64(s.dwell_mean_ms) || !r.f64(s.dwell_stddev_ms))
                return false;
            d.fsm.states.push_back(std::move(s));
        }
    }
    {
        uint32_t n;
        if (!r.count(n, lim.max_fsm_transitions, "FSM transition"))
            return false;
        d.fsm.transitions.clear();
        d.fsm.transitions.reserve(n);
        for (uint32_t i = 0; i < n; ++i) {
            FsmTransition t;
            if (!r.str(t.from, lim.max_string_len) ||
                !r.str(t.to, lim.max_string_len) || !r.f64(t.probability))
                return false;
            d.fsm.transitions.push_back(std::move(t));
        }
    }

    // ---- padding / header / MTU ----
    if (!r.u32(d.padding_header.header_overhead_bytes) ||
        !r.u32(d.padding_header.padding_block_bytes) ||
        !r.u32(d.padding_header.padding_max_bytes))
        return false;
    if (!r.boolean(d.padding_header.pad_to_block)) return false;
    if (!r.u32(d.mtu.path_mtu_bytes) || !r.u32(d.mtu.max_payload_bytes))
        return false;

    // ---- provenance ----
    if (!r.u64(d.provenance.sample_count) ||
        !r.u64(d.provenance.window_count))
        return false;
    {
        uint32_t n;
        if (!r.count(n, lim.max_captures, "capture")) return false;
        d.provenance.captures.clear();
        d.provenance.captures.reserve(n);
        for (uint32_t i = 0; i < n; ++i) {
            CaptureProvenance c;
            if (!read_capture(r, c, lim)) return false;
            d.provenance.captures.push_back(std::move(c));
        }
    }

    // ---- derivation bounds ----
    if (!r.f64(d.derivation.size_mean_rel_jitter) ||
        !r.f64(d.derivation.iat_mean_rel_jitter) ||
        !r.f64(d.derivation.burst_rel_jitter) ||
        !r.f64(d.derivation.fsm_dwell_rel_jitter))
        return false;
    if (!r.u32(d.derivation.padding_extra_max_bytes) ||
        !r.u32(d.derivation.header_gap_shift_max_bytes))
        return false;

    // ---- artifact signature ----
    if (!r.boolean(d.signature.present)) return false;
    if (!r.str(d.signature.scheme, lim.max_string_len)) return false;
    if (!r.str(d.signature.key_id, lim.max_string_len)) return false;
    if (!r.bytes(d.signature.signature, lim.max_signature_bytes)) return false;

    // ---- content hash ----
    if (!r.str(d.content_hash, lim.max_string_len)) return false;

    return r.ok();
}

} // namespace

// ==================== Limits ====================

MimicryCatalogIo::Limits MimicryCatalogIo::Limits::from_catalog(
    const ReferenceProfileCatalog::Limits& cl) {
    Limits l;
    l.max_descriptors = static_cast<uint32_t>(
        min_u32(256u, static_cast<uint32_t>(
                          cl.max_profiles > 0xFFFFFFFFull ? 0xFFFFFFFFull
                                                          : cl.max_profiles)));
    l.max_string_len = static_cast<uint32_t>(
        min_u32(128u, static_cast<uint32_t>(
                          cl.max_string_len > 0xFFFFFFFFull
                              ? 0xFFFFFFFFull
                              : cl.max_string_len)));
    l.max_capabilities = static_cast<uint32_t>(cl.max_capabilities);
    l.max_mix_components = static_cast<uint32_t>(cl.max_mix_components);
    l.max_fsm_states = static_cast<uint32_t>(cl.max_fsm_states);
    l.max_fsm_transitions = static_cast<uint32_t>(cl.max_fsm_transitions);
    l.max_captures = static_cast<uint32_t>(cl.max_captures);
    return l;
}

// ==================== Parsing ====================

bool MimicryCatalogIo::parse_bytes(const std::vector<uint8_t>& bytes,
                                   ParsedFile& out, Error& err,
                                   const Limits& lim) {
    ensure_sodium();
    err = Error{};
    out = ParsedFile{};

    if (bytes.size() > lim.max_file_bytes) {
        err.code = "file_too_large";
        err.message = "container exceeds size bound";
        return false;
    }
    // header (20 bytes) + checksum (32 bytes) is the smallest container.
    if (bytes.size() < 20 + 32) {
        err.code = "truncated";
        err.message = "container smaller than header + checksum";
        err.byte_offset = bytes.size();
        return false;
    }

    // ---- checksum over everything before the final 32 bytes ----
    {
        std::array<uint8_t, 32> digest{};
        crypto_generichash(digest.data(), digest.size(), bytes.data(),
                           bytes.size() - 32, nullptr, 0);
        if (sodium_memcmp(digest.data(), bytes.data() + (bytes.size() - 32),
                          32) != 0) {
            err.code = "checksum_mismatch";
            err.message = "container checksum mismatch (corrupt or tampered)";
            err.byte_offset = bytes.size() - 32;
            return false;
        }
    }

    IoReader r(bytes.data(), bytes.size() - 32, lim, err, kNoRecord);

    // ---- magic ----
    if (!r.take(sizeof(kMagic))) return false;
    if (std::memcmp(bytes.data(), kMagic, sizeof(kMagic)) != 0) {
        err.code = "bad_magic";
        err.message = "not an NCP mimicry catalog container";
        err.byte_offset = 0;
        return false;
    }

    // ---- version / flags ----
    uint32_t version, flags, count;
    if (!r.u32(version)) return false;
    if (version != kContainerVersion) {
        err.code = "unsupported_container_version";
        err.message = "unsupported container version";
        err.byte_offset = 8;
        return false;
    }
    if (!r.u32(flags)) return false;
    if (flags != 0) {
        err.code = "unsupported_flags";
        err.message = "unsupported container flags set";
        err.byte_offset = 12;
        return false;
    }
    if (!r.u32(count)) return false;
    if (count > lim.max_descriptors) {
        err.code = "too_many_descriptors";
        err.message = "descriptor count exceeds bound";
        err.byte_offset = 16;
        return false;
    }

    out.container_version = version;
    out.descriptors.clear();
    out.descriptors.reserve(count);

    std::set<std::pair<std::string, uint32_t>> seen;

    for (uint32_t i = 0; i < count; ++i) {
        uint32_t record_len;
        if (!r.u32(record_len)) return false;
        if (record_len > lim.max_record_bytes) {
            err.code = "record_too_large";
            err.message = "descriptor record exceeds size bound";
            err.byte_offset = r.pos() - 4;
            err.record = i;
            return false;
        }
        if (record_len > r.remaining()) {
            err.code = "truncated";
            err.message = "descriptor record extends past container end";
            err.byte_offset = r.pos();
            err.record = i;
            return false;
        }

        ProfileDescriptor d;
        IoReader rec(bytes.data() + r.pos(), record_len, lim, err, i);
        if (!read_descriptor(rec, d, lim)) return false;
        if (rec.remaining() != 0) {
            err.code = "trailing_data";
            err.message = "descriptor record has trailing bytes";
            err.byte_offset = r.pos() + rec.pos();
            err.record = i;
            return false;
        }
        if (!r.take(record_len)) return false;  // cannot happen; defensive

        // duplicate (profile_id, revision) within the same file
        if (!seen.emplace(d.profile_id, d.revision).second) {
            err.code = "duplicate_profile_revision";
            err.message =
                "duplicate profile revision inside container: " + d.profile_id;
            err.byte_offset = r.pos();
            err.record = i;
            return false;
        }

        out.descriptors.push_back(std::move(d));
    }

    if (r.remaining() != 0) {
        err.code = "trailing_data";
        err.message = "unexpected bytes between records and checksum";
        err.byte_offset = r.pos();
        return false;
    }
    return true;
}

bool MimicryCatalogIo::parse_bytes(const std::vector<uint8_t>& bytes,
                                   ParsedFile& out, Error& err) {
    return parse_bytes(bytes, out, err, Limits{});
}

bool MimicryCatalogIo::parse_file(const std::string& path, ParsedFile& out,
                                  Error& err, const Limits& lim) {
    err = Error{};
    out = ParsedFile{};

    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f) {
        err.code = "io_open_failed";
        err.message = "cannot open catalog file";
        return false;
    }
    const std::streamoff end = f.tellg();
    if (end < 0) {
        err.code = "io_read_failed";
        err.message = "cannot determine catalog file size";
        return false;
    }
    if (static_cast<uint64_t>(end) > lim.max_file_bytes) {
        err.code = "file_too_large";
        err.message = "catalog file exceeds size bound";
        return false;
    }
    std::vector<uint8_t> bytes(static_cast<size_t>(end));
    f.seekg(0, std::ios::beg);
    if (!bytes.empty()) {
        f.read(reinterpret_cast<char*>(bytes.data()), end);
        if (!f) {
            err.code = "io_read_failed";
            err.message = "failed reading catalog file";
            return false;
        }
    }
    return parse_bytes(bytes, out, err, lim);
}

bool MimicryCatalogIo::parse_file(const std::string& path, ParsedFile& out,
                                  Error& err) {
    return parse_file(path, out, err, Limits{});
}

// ==================== Serialization ====================

std::vector<uint8_t> MimicryCatalogIo::serialize(
    const std::vector<ProfileDescriptor>& descriptors) {
    ensure_sodium();

    // deterministic record order: (profile_id, revision)
    std::vector<const ProfileDescriptor*> order;
    order.reserve(descriptors.size());
    for (const auto& d : descriptors) order.push_back(&d);
    std::stable_sort(order.begin(), order.end(),
                     [](const ProfileDescriptor* a, const ProfileDescriptor* b) {
                         if (a->profile_id != b->profile_id)
                             return a->profile_id < b->profile_id;
                         return a->revision < b->revision;
                     });

    IoWriter w;
    w.out.insert(w.out.end(), kMagic, kMagic + sizeof(kMagic));
    w.u32(kContainerVersion);
    w.u32(0);  // flags
    w.u32(static_cast<uint32_t>(order.size()));

    for (const ProfileDescriptor* d : order) {
        IoWriter rec;
        write_descriptor(rec, *d);
        w.u32(static_cast<uint32_t>(rec.out.size()));
        w.out.insert(w.out.end(), rec.out.begin(), rec.out.end());
    }

    std::array<uint8_t, 32> digest{};
    crypto_generichash(digest.data(), digest.size(), w.out.data(),
                       w.out.size(), nullptr, 0);
    w.out.insert(w.out.end(), digest.begin(), digest.end());
    return std::move(w.out);
}

bool MimicryCatalogIo::save_file(
    const std::string& path,
    const std::vector<ProfileDescriptor>& descriptors, Error& err) {
    err = Error{};
    const std::vector<uint8_t> bytes = serialize(descriptors);
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f) {
        err.code = "io_write_failed";
        err.message = "cannot open output file for writing";
        return false;
    }
    f.write(reinterpret_cast<const char*>(bytes.data()),
            static_cast<std::streamsize>(bytes.size()));
    f.flush();
    if (!f) {
        err.code = "io_write_failed";
        err.message = "failed writing catalog file";
        return false;
    }
    return true;
}

std::vector<uint8_t> MimicryCatalogIo::export_catalog_bytes(
    const ReferenceProfileCatalog& catalog) {
    std::vector<ProfileDescriptor> all;
    for (const auto& canonical_id : catalog.list()) {
        const auto at = canonical_id.find('@');
        if (at == std::string::npos) continue;
        const std::string id = canonical_id.substr(0, at);
        uint32_t revision = 0;
        try {
            revision = static_cast<uint32_t>(
                std::stoul(canonical_id.substr(at + 1)));
        } catch (...) {
            continue;  // defensive: list() always yields well-formed ids
        }
        if (const ProfileDescriptor* d = catalog.find(id, revision))
            all.push_back(*d);
    }
    return serialize(all);
}

bool MimicryCatalogIo::export_catalog(const ReferenceProfileCatalog& catalog,
                                      const std::string& path, Error& err) {
    std::vector<ProfileDescriptor> all;
    for (const auto& canonical_id : catalog.list()) {
        const auto at = canonical_id.find('@');
        if (at == std::string::npos) continue;
        const std::string id = canonical_id.substr(0, at);
        uint32_t revision = 0;
        try {
            revision = static_cast<uint32_t>(
                std::stoul(canonical_id.substr(at + 1)));
        } catch (...) {
            continue;
        }
        if (const ProfileDescriptor* d = catalog.find(id, revision))
            all.push_back(*d);
    }
    return save_file(path, all, err);
}

// ==================== Loading ====================

bool MimicryCatalogIo::load_file(
    const std::string& path, ReferenceProfileCatalog& catalog,
    std::vector<ReferenceProfileCatalog::RegisterOutcome>* outcomes,
    Error& err, const Limits& lim) {
    err = Error{};
    ParsedFile parsed;
    if (!parse_file(path, parsed, err, lim)) return false;

    for (size_t i = 0; i < parsed.descriptors.size(); ++i) {
        // EXTERNAL, policy-checked path only — ENFORCE is preserved and
        // the trusted built-in path is never used for file records.
        auto outcome = catalog.register_profile(parsed.descriptors[i]);
        if (outcomes) outcomes->push_back(outcome);
        if (!outcome.ok()) {
            std::string codes;
            for (const auto& iss : outcome.issues) {
                if (iss.severity != IssueSeverity::ERROR) continue;
                if (!codes.empty()) codes += ',';
                codes += iss.code;
            }
            err.code = "registration_failed";
            err.message = "descriptor rejected by catalog policy" +
                          (outcome.canonical_id.empty()
                               ? std::string()
                               : ": " + outcome.canonical_id) +
                          (codes.empty() ? std::string()
                                         : " [" + codes + "]");
            err.record = static_cast<uint32_t>(i);
            return false;
        }
    }
    return true;
}

bool MimicryCatalogIo::load_file(
    const std::string& path, ReferenceProfileCatalog& catalog,
    std::vector<ReferenceProfileCatalog::RegisterOutcome>* outcomes,
    Error& err) {
    return load_file(path, catalog, outcomes, err, Limits{});
}

// ==================== Validation ====================

bool MimicryCatalogIo::validate_file(
    const std::string& path, const ReferenceProfileCatalog& catalog,
    std::vector<std::pair<std::string, std::vector<ValidationIssue>>>&
        issues_out,
    Error& err, const Limits& lim) {
    err = Error{};
    issues_out.clear();
    ParsedFile parsed;
    if (!parse_file(path, parsed, err, lim)) return false;

    for (const auto& d : parsed.descriptors) {
        issues_out.emplace_back(
            d.profile_id + "@" + std::to_string(d.revision),
            catalog.validate_descriptor(d));
    }
    return true;
}

bool MimicryCatalogIo::validate_file(
    const std::string& path, const ReferenceProfileCatalog& catalog,
    std::vector<std::pair<std::string, std::vector<ValidationIssue>>>&
        issues_out,
    Error& err) {
    return validate_file(path, catalog, issues_out, err, Limits{});
}

} // namespace ncp
