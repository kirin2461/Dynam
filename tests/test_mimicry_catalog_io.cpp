// ══════════════════════════════════════════════════════════════════════════════
// tests/test_mimicry_catalog_io.cpp
// Tests for safe versioned file IO for ReferenceProfileCatalog
// (ncp_mimicry_catalog_io) — future --mimicry-catalog / validate-catalog
// persistence layer.
// ══════════════════════════════════════════════════════════════════════════════
#include <gtest/gtest.h>

#include <sodium.h>

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "ncp_mimicry_catalog_io.hpp"
#include "ncp_test_temp.hpp"

using namespace ncp;

namespace {

// ── Helpers ─────────────────────────────────────────────────────────────────

std::string hex64(char c) { return std::string(64, c); }

/// A fully valid external descriptor (unsigned until signed by the caller).
/// Mirrors the fixture in test_reference_profile_catalog.cpp.
ProfileDescriptor make_valid_external(const std::string& id = "test.webrtc_ref",
                                      uint32_t revision = 1) {
    ProfileDescriptor d;
    d.schema_version = ProfileDescriptor::kSchemaVersion;
    d.profile_id = id;
    d.revision = revision;
    d.family = ProtocolFamily::WEBRTC;
    d.min_wire_version = 1;
    d.max_wire_version = 3;
    d.required_capabilities = {"burst-shaping", "fsm-timing"};  // sorted

    d.sizes.kind = SizeDistKind::NORMAL;
    d.sizes.mean = 500.0;
    d.sizes.stddev = 50.0;
    d.sizes.clamp_min = 64.0;
    d.sizes.clamp_max = 1200.0;

    d.iat.kind = IntervalKind::NORMAL;
    d.iat.mean_ms = 20.0;
    d.iat.stddev_ms = 5.0;

    ReferenceJointSizeIatModel j;
    j.correlation = 0.3;
    j.lag_packets = 1;
    d.joint = j;

    d.burst.enabled = true;
    d.burst.mean_burst_packets = 4.0;
    d.burst.mean_burst_gap_ms = 100.0;
    d.burst.direction = DirectionModel::SERVER_DRIVEN;

    d.fsm.enabled = true;
    d.fsm.initial_state = "idle";
    d.fsm.states = {{"bulk", 500.0, 50.0}, {"idle", 2000.0, 200.0}};
    d.fsm.transitions = {{"idle", "bulk", 1.0}, {"bulk", "idle", 1.0}};

    d.padding_header.header_overhead_bytes = 60;
    d.padding_header.padding_block_bytes = 16;
    d.padding_header.padding_max_bytes = 256;
    d.padding_header.pad_to_block = true;

    d.mtu.path_mtu_bytes = 1500;
    d.mtu.max_payload_bytes = 1400;

    d.provenance.sample_count = 100000;
    d.provenance.window_count = 500;
    CaptureProvenance a;
    a.capture_id = "cap-a";
    a.capture_hash = hex64('a');
    a.environment = "lab";
    a.session_group = "sg-1";
    a.captured_epoch = 1700000000;
    a.duration_s = 3600;
    a.negative_control = false;
    CaptureProvenance b;
    b.capture_id = "cap-b";
    b.capture_hash = hex64('b');
    b.environment = "lab";
    b.session_group = "sg-2";
    b.captured_epoch = 1700001000;
    b.duration_s = 600;
    b.negative_control = true;
    d.provenance.captures = {a, b};  // sorted by capture_id

    d.derivation.size_mean_rel_jitter = 0.10;
    d.derivation.iat_mean_rel_jitter = 0.10;
    d.derivation.burst_rel_jitter = 0.10;
    d.derivation.fsm_dwell_rel_jitter = 0.10;
    d.derivation.padding_extra_max_bytes = 64;
    d.derivation.header_gap_shift_max_bytes = 8;

    ReferenceProfileCatalog::update_content_hash(d);
    return d;
}

/// Recompute the trailing BLAKE2b-256 checksum after tampering with the
/// container body (test-only helper; uses libsodium like the implementation).
void rewrite_checksum(std::vector<uint8_t>& bytes) {
    ASSERT_GE(bytes.size(), 32u);
    std::array<uint8_t, 32> digest{};
    crypto_generichash(digest.data(), digest.size(), bytes.data(),
                       bytes.size() - 32, nullptr, 0);
    std::memcpy(bytes.data() + (bytes.size() - 32), digest.data(), 32);
}

void write_bytes(const std::string& path, const std::vector<uint8_t>& bytes) {
    MimicryCatalogIo::Error err;
    // save via raw stream to allow arbitrary (tampered) bytes
    FILE* f = std::fopen(path.c_str(), "wb");
    ASSERT_NE(f, nullptr);
    ASSERT_EQ(std::fwrite(bytes.data(), 1, bytes.size(), f), bytes.size());
    ASSERT_EQ(std::fclose(f), 0);
}

bool issue_has(const std::vector<ValidationIssue>& issues,
               const std::string& code) {
    for (const auto& i : issues)
        if (i.code == code) return true;
    return false;
}

/// Offset of a field inside the first record of a serialized container.
/// Layout: header(20) | record_len(4) | schema_version(4) | id_len(4) | id.
size_t first_record_field_offset(const ProfileDescriptor& d,
                                 size_t after_id_fields) {
    return 20 + 4 + 4 + 4 + d.profile_id.size() + after_id_fields;
}

struct TempFile {
    std::string path;
    explicit TempFile(const std::string& name) : path(ncp_test::temp_path(name)) {}
    ~TempFile() { std::remove(path.c_str()); }
};

// ── Roundtrip / determinism ─────────────────────────────────────────────────

TEST(MimicryCatalogIo, RoundtripPreservesCompleteDescriptor) {
    auto kp = ReferenceProfileCatalog::generate_signing_keypair();
    ProfileDescriptor d = make_valid_external();
    ASSERT_TRUE(ReferenceProfileCatalog::sign_descriptor(d, "test-key",
                                                         kp.secret_key));

    const auto bytes = MimicryCatalogIo::serialize({d});
    MimicryCatalogIo::ParsedFile parsed;
    MimicryCatalogIo::Error err;
    ASSERT_TRUE(MimicryCatalogIo::parse_bytes(bytes, parsed, err))
        << err.code << ": " << err.message;
    ASSERT_EQ(parsed.container_version, MimicryCatalogIo::kContainerVersion);
    ASSERT_EQ(parsed.descriptors.size(), 1u);

    const ProfileDescriptor& r = parsed.descriptors[0];
    // complete record: signature + content_hash included
    EXPECT_EQ(r.profile_id, d.profile_id);
    EXPECT_EQ(r.revision, d.revision);
    EXPECT_EQ(r.family, d.family);
    EXPECT_EQ(r.content_hash, d.content_hash);
    ASSERT_TRUE(r.signature.present);
    EXPECT_EQ(r.signature.scheme, "ed25519");
    EXPECT_EQ(r.signature.key_id, "test-key");
    EXPECT_EQ(r.signature.signature, d.signature.signature);
    // every canonical field round-trips bit-exactly
    EXPECT_EQ(ReferenceProfileCatalog::canonical_serialize(r),
              ReferenceProfileCatalog::canonical_serialize(d));
    // sub-models preserved
    ASSERT_TRUE(r.joint.has_value());
    EXPECT_DOUBLE_EQ(r.joint->correlation, 0.3);
    EXPECT_EQ(r.joint->lag_packets, 1u);
    ASSERT_EQ(r.provenance.captures.size(), 2u);
    EXPECT_EQ(r.provenance.captures[1].capture_id, "cap-b");
    EXPECT_TRUE(r.provenance.captures[1].negative_control);
    ASSERT_EQ(r.fsm.states.size(), 2u);
    EXPECT_EQ(r.fsm.transitions[0].from, "idle");
    EXPECT_EQ(r.derivation.padding_extra_max_bytes, 64u);
}

TEST(MimicryCatalogIo, SerializationIsDeterministic) {
    ProfileDescriptor a = make_valid_external("alpha", 2);
    ProfileDescriptor b = make_valid_external("alpha", 1);
    ProfileDescriptor c = make_valid_external("beta", 1);

    const auto b1 = MimicryCatalogIo::serialize({a, b, c});
    const auto b2 = MimicryCatalogIo::serialize({c, b, a});  // different order
    const auto b3 = MimicryCatalogIo::serialize({a, b, c});
    EXPECT_EQ(b1, b2) << "record ordering must be canonicalised";
    EXPECT_EQ(b1, b3) << "repeated serialization must be byte-identical";

    // canonical record order: alpha@1, alpha@2, beta@1
    MimicryCatalogIo::ParsedFile parsed;
    MimicryCatalogIo::Error err;
    ASSERT_TRUE(MimicryCatalogIo::parse_bytes(b1, parsed, err));
    ASSERT_EQ(parsed.descriptors.size(), 3u);
    EXPECT_EQ(parsed.descriptors[0].profile_id, "alpha");
    EXPECT_EQ(parsed.descriptors[0].revision, 1u);
    EXPECT_EQ(parsed.descriptors[1].revision, 2u);
    EXPECT_EQ(parsed.descriptors[2].profile_id, "beta");
}

TEST(MimicryCatalogIo, SaveAndLoadFileRoundtrip) {
    TempFile tf("ncp_cat_io_roundtrip.bin");
    ProfileDescriptor d = make_valid_external();

    MimicryCatalogIo::Error err;
    ASSERT_TRUE(MimicryCatalogIo::save_file(tf.path, {d}, err))
        << err.code << ": " << err.message;

    MimicryCatalogIo::ParsedFile parsed;
    ASSERT_TRUE(MimicryCatalogIo::parse_file(tf.path, parsed, err))
        << err.code << ": " << err.message;
    ASSERT_EQ(parsed.descriptors.size(), 1u);
    EXPECT_EQ(parsed.descriptors[0].content_hash, d.content_hash);
    EXPECT_EQ(ReferenceProfileCatalog::canonical_serialize(parsed.descriptors[0]),
              ReferenceProfileCatalog::canonical_serialize(d));
}

// ── Policy: ENFORCE / WARN_ONLY / DEV_UNSIGNED via load_file ────────────────

TEST(MimicryCatalogIo, SignedDescriptorAcceptedUnderEnforce) {
    auto kp = ReferenceProfileCatalog::generate_signing_keypair();
    ProfileDescriptor d = make_valid_external();
    ASSERT_TRUE(ReferenceProfileCatalog::sign_descriptor(d, "signer-1",
                                                         kp.secret_key));

    TempFile tf("ncp_cat_io_enforce_ok.bin");
    MimicryCatalogIo::Error err;
    ASSERT_TRUE(MimicryCatalogIo::save_file(tf.path, {d}, err));

    ReferenceProfileCatalog cat;  // default: ENFORCE
    ASSERT_TRUE(cat.add_trusted_key("signer-1", kp.public_key));

    std::vector<ReferenceProfileCatalog::RegisterOutcome> outcomes;
    ASSERT_TRUE(MimicryCatalogIo::load_file(tf.path, cat, &outcomes, err))
        << err.code << ": " << err.message;
    ASSERT_EQ(outcomes.size(), 1u);
    EXPECT_EQ(outcomes[0].status, ReferenceProfileCatalog::RegisterStatus::OK);
    EXPECT_EQ(outcomes[0].canonical_id, "test.webrtc_ref@1");

    const ProfileDescriptor* loaded = cat.find("test.webrtc_ref", 1);
    ASSERT_NE(loaded, nullptr);
    EXPECT_EQ(loaded->content_hash, d.content_hash);
    EXPECT_TRUE(loaded->signature.present);
}

TEST(MimicryCatalogIo, UnsignedDescriptorRejectedUnderEnforce) {
    ProfileDescriptor d = make_valid_external();  // no signature

    TempFile tf("ncp_cat_io_enforce_reject.bin");
    MimicryCatalogIo::Error err;
    ASSERT_TRUE(MimicryCatalogIo::save_file(tf.path, {d}, err));

    ReferenceProfileCatalog cat;  // ENFORCE
    std::vector<ReferenceProfileCatalog::RegisterOutcome> outcomes;
    EXPECT_FALSE(MimicryCatalogIo::load_file(tf.path, cat, &outcomes, err));
    EXPECT_EQ(err.code, "registration_failed");
    EXPECT_NE(err.message.find("signature_required"), std::string::npos);
    ASSERT_EQ(outcomes.size(), 1u);
    EXPECT_EQ(outcomes[0].status,
              ReferenceProfileCatalog::RegisterStatus::REJECTED);
    EXPECT_TRUE(issue_has(outcomes[0].issues, "signature_required"));
    EXPECT_EQ(cat.size(), 0u);  // nothing snuck into the catalog
}

TEST(MimicryCatalogIo, UntrustedKeyRejectedUnderEnforce) {
    auto kp = ReferenceProfileCatalog::generate_signing_keypair();
    ProfileDescriptor d = make_valid_external();
    ASSERT_TRUE(ReferenceProfileCatalog::sign_descriptor(d, "rogue",
                                                         kp.secret_key));

    TempFile tf("ncp_cat_io_untrusted.bin");
    MimicryCatalogIo::Error err;
    ASSERT_TRUE(MimicryCatalogIo::save_file(tf.path, {d}, err));

    ReferenceProfileCatalog cat;  // ENFORCE, no keys registered
    EXPECT_FALSE(MimicryCatalogIo::load_file(tf.path, cat, nullptr, err));
    EXPECT_EQ(err.code, "registration_failed");
    EXPECT_NE(err.message.find("unknown_signing_key"), std::string::npos);
    EXPECT_EQ(cat.size(), 0u);
}

TEST(MimicryCatalogIo, WarnOnlyAcceptsUnsignedWithWarning) {
    ProfileDescriptor d = make_valid_external();

    TempFile tf("ncp_cat_io_warn.bin");
    MimicryCatalogIo::Error err;
    ASSERT_TRUE(MimicryCatalogIo::save_file(tf.path, {d}, err));

    ReferenceProfileCatalog::Options opts;
    opts.external_policy = SignaturePolicy::WARN_ONLY;
    ReferenceProfileCatalog cat(opts);

    std::vector<ReferenceProfileCatalog::RegisterOutcome> outcomes;
    ASSERT_TRUE(MimicryCatalogIo::load_file(tf.path, cat, &outcomes, err))
        << err.code << ": " << err.message;
    ASSERT_EQ(outcomes.size(), 1u);
    EXPECT_EQ(outcomes[0].status,
              ReferenceProfileCatalog::RegisterStatus::WARNED);
    EXPECT_TRUE(issue_has(outcomes[0].issues, "unsigned_profile"));
    EXPECT_EQ(cat.size(), 1u);
}

TEST(MimicryCatalogIo, DevUnsignedAcceptsAndRecordsPolicyWarning) {
    ProfileDescriptor d = make_valid_external();

    TempFile tf("ncp_cat_io_dev.bin");
    MimicryCatalogIo::Error err;
    ASSERT_TRUE(MimicryCatalogIo::save_file(tf.path, {d}, err));

    ReferenceProfileCatalog::Options opts;
    opts.external_policy = SignaturePolicy::DEV_UNSIGNED;
    ReferenceProfileCatalog cat(opts);

    std::vector<ReferenceProfileCatalog::RegisterOutcome> outcomes;
    ASSERT_TRUE(MimicryCatalogIo::load_file(tf.path, cat, &outcomes, err));
    ASSERT_EQ(outcomes.size(), 1u);
    EXPECT_EQ(outcomes[0].status,
              ReferenceProfileCatalog::RegisterStatus::WARNED);
    EXPECT_TRUE(issue_has(outcomes[0].issues, "dev_unsigned_policy"));
    EXPECT_EQ(cat.size(), 1u);
}

// ── Tampering / integrity ───────────────────────────────────────────────────

TEST(MimicryCatalogIo, SingleByteTamperRejectedByChecksum) {
    auto bytes = MimicryCatalogIo::serialize({make_valid_external()});
    ASSERT_GT(bytes.size(), 64u);
    bytes[30] ^= 0x01;  // inside first record, checksum now stale

    MimicryCatalogIo::ParsedFile parsed;
    MimicryCatalogIo::Error err;
    EXPECT_FALSE(MimicryCatalogIo::parse_bytes(bytes, parsed, err));
    EXPECT_EQ(err.code, "checksum_mismatch");
}

TEST(MimicryCatalogIo, CorruptedContentHashRejectedByCatalogValidation) {
    auto bytes = MimicryCatalogIo::serialize({make_valid_external()});
    // content_hash is the last field of the record body: a 32-bit length (64)
    // followed by 64 hex chars, immediately before the record end. Find it by
    // scanning backwards from the checksum.
    ASSERT_GT(bytes.size(), 32u + 4u + 64u);
    const size_t hash_off = bytes.size() - 32 - 64;
    // sanity: the preceding u32 length must be 64
    ASSERT_EQ(bytes[hash_off - 4], 64u);
    bytes[hash_off] = (bytes[hash_off] == 'a') ? 'b' : 'a';  // flip, stay hex
    rewrite_checksum(bytes);  // container integrity intact; CONTENT is wrong

    TempFile tf("ncp_cat_io_bad_hash.bin");
    write_bytes(tf.path, bytes);

    ReferenceProfileCatalog cat;  // ENFORCE
    MimicryCatalogIo::Error err;
    EXPECT_FALSE(MimicryCatalogIo::load_file(tf.path, cat, nullptr, err));
    EXPECT_EQ(err.code, "registration_failed");
    EXPECT_NE(err.message.find("hash_mismatch"), std::string::npos);
    EXPECT_EQ(cat.size(), 0u);
}

TEST(MimicryCatalogIo, CorruptedSignatureRejectedUnderEnforce) {
    auto kp = ReferenceProfileCatalog::generate_signing_keypair();
    ProfileDescriptor d = make_valid_external();
    ASSERT_TRUE(ReferenceProfileCatalog::sign_descriptor(d, "k", kp.secret_key));

    auto bytes = MimicryCatalogIo::serialize({d});
    // signature blob: located just before the trailing content_hash string.
    // content_hash string = u32 len(64) + 64 chars; before it: u32 sig_len(64)
    // + 64 sig bytes.
    const size_t hash_off = bytes.size() - 32 - 64;
    const size_t sig_off = hash_off - 4 - 64;
    ASSERT_EQ(bytes[sig_off - 4], 64u);
    bytes[sig_off] ^= 0xFF;  // corrupt one signature byte
    // content_hash excludes signature fields, so the hash is still valid —
    // only the Ed25519 verification can catch this.
    rewrite_checksum(bytes);

    TempFile tf("ncp_cat_io_bad_sig.bin");
    write_bytes(tf.path, bytes);

    ReferenceProfileCatalog cat;
    ASSERT_TRUE(cat.add_trusted_key("k", kp.public_key));
    MimicryCatalogIo::Error err;
    EXPECT_FALSE(MimicryCatalogIo::load_file(tf.path, cat, nullptr, err));
    EXPECT_EQ(err.code, "registration_failed");
    EXPECT_NE(err.message.find("invalid_signature"), std::string::npos);
    EXPECT_EQ(cat.size(), 0u);
}

TEST(MimicryCatalogIo, DuplicateIdRevisionInsideFileRejected) {
    ProfileDescriptor d = make_valid_external();
    // serialize() is a passive container writer; the duplicate guard lives in
    // the parser (and again in the catalog itself).
    const auto bytes = MimicryCatalogIo::serialize({d, d});

    MimicryCatalogIo::ParsedFile parsed;
    MimicryCatalogIo::Error err;
    EXPECT_FALSE(MimicryCatalogIo::parse_bytes(bytes, parsed, err));
    EXPECT_EQ(err.code, "duplicate_profile_revision");
    EXPECT_EQ(err.record, 1u);
}

TEST(MimicryCatalogIo, DuplicateAgainstCatalogRejectedOnLoad) {
    ProfileDescriptor d = make_valid_external();
    TempFile tf("ncp_cat_io_dup.bin");
    MimicryCatalogIo::Error err;
    ASSERT_TRUE(MimicryCatalogIo::save_file(tf.path, {d}, err));

    ReferenceProfileCatalog::Options opts;
    opts.external_policy = SignaturePolicy::DEV_UNSIGNED;
    ReferenceProfileCatalog cat(opts);
    ASSERT_TRUE(cat.register_profile(d).ok());  // pre-register same id@rev

    EXPECT_FALSE(MimicryCatalogIo::load_file(tf.path, cat, nullptr, err));
    EXPECT_EQ(err.code, "registration_failed");
    EXPECT_NE(err.message.find("duplicate_profile_revision"),
              std::string::npos);
}

// ── Malformed / truncated / trailing / oversized ────────────────────────────

TEST(MimicryCatalogIo, TruncatedContainerRejected) {
    const auto bytes = MimicryCatalogIo::serialize({make_valid_external()});
    for (size_t cut : {size_t(0), size_t(10), size_t(20), bytes.size() / 2,
                       bytes.size() - 1}) {
        std::vector<uint8_t> shorty(bytes.begin(), bytes.begin() + cut);
        MimicryCatalogIo::ParsedFile parsed;
        MimicryCatalogIo::Error err;
        EXPECT_FALSE(MimicryCatalogIo::parse_bytes(shorty, parsed, err))
            << "cut at " << cut;
        EXPECT_TRUE(err.code == "truncated" ||
                    err.code == "checksum_mismatch")
            << "cut at " << cut << " gave " << err.code;
    }
}

TEST(MimicryCatalogIo, TrailingDataRejected) {
    auto bytes = MimicryCatalogIo::serialize({make_valid_external()});
    // append a byte AFTER the checksum, then fix size bookkeeping by
    // re-checksumming: parser reads header+records, then expects exactly 32
    // checksum bytes at EOF — the stray byte shifts the checksum window.
    bytes.push_back(0x00);
    MimicryCatalogIo::ParsedFile parsed;
    MimicryCatalogIo::Error err;
    EXPECT_FALSE(MimicryCatalogIo::parse_bytes(bytes, parsed, err));
    // checksum window moved → mismatch (equally a hard rejection)
    EXPECT_EQ(err.code, "checksum_mismatch");

    // stricter case: well-formed checksum but garbage between records and
    // checksum → build by re-serialising with an injected record-length hack
    // is overkill; instead verify the explicit trailing-data path via a
    // hand-patched record that leaves bytes unconsumed inside the record.
    auto clean = MimicryCatalogIo::serialize({make_valid_external()});
    // shrink the declared first-record length by 1 → leftover byte inside
    // container → "trailing_data" (record 0 leaves one byte unconsumed).
    ASSERT_GT(clean.size(), 24u);
    uint32_t rec_len = static_cast<uint32_t>(clean[20]) |
                       (static_cast<uint32_t>(clean[21]) << 8);
    ASSERT_GT(rec_len, 1u);
    rec_len -= 1;
    clean[20] = static_cast<uint8_t>(rec_len & 0xFF);
    clean[21] = static_cast<uint8_t>((rec_len >> 8) & 0xFF);
    rewrite_checksum(clean);
    EXPECT_FALSE(MimicryCatalogIo::parse_bytes(clean, parsed, err));
    EXPECT_TRUE(err.code == "trailing_data" || err.code == "truncated")
        << err.code;
}

TEST(MimicryCatalogIo, OversizedFileRejectedBeforeRead) {
    TempFile tf("ncp_cat_io_oversize.bin");
    MimicryCatalogIo::Error err;
    ASSERT_TRUE(MimicryCatalogIo::save_file(tf.path, {make_valid_external()},
                                            err));

    MimicryCatalogIo::Limits lim;
    lim.max_file_bytes = 64;  // smaller than any real container
    MimicryCatalogIo::ParsedFile parsed;
    EXPECT_FALSE(MimicryCatalogIo::parse_file(tf.path, parsed, err, lim));
    EXPECT_EQ(err.code, "file_too_large");
}

TEST(MimicryCatalogIo, TooManyDescriptorsRejected) {
    auto bytes = MimicryCatalogIo::serialize({make_valid_external()});
    ASSERT_GT(bytes.size(), 20u);
    // descriptor_count at offset 16
    const uint32_t huge = 1000000u;
    for (int i = 0; i < 4; ++i)
        bytes[16 + i] = static_cast<uint8_t>(huge >> (8 * i));
    rewrite_checksum(bytes);

    MimicryCatalogIo::ParsedFile parsed;
    MimicryCatalogIo::Error err;
    EXPECT_FALSE(MimicryCatalogIo::parse_bytes(bytes, parsed, err));
    EXPECT_EQ(err.code, "too_many_descriptors");
}

TEST(MimicryCatalogIo, OversizedStringRejectedBeforeAllocation) {
    ProfileDescriptor d = make_valid_external();
    auto bytes = MimicryCatalogIo::serialize({d});
    // profile_id length field: header(20) + record_len(4) + schema_version(4)
    const size_t id_len_off = 20 + 4 + 4;
    ASSERT_GT(bytes.size(), id_len_off + 4);
    const uint32_t huge = 0x7FFFFFFFu;
    for (int i = 0; i < 4; ++i)
        bytes[id_len_off + i] = static_cast<uint8_t>(huge >> (8 * i));
    rewrite_checksum(bytes);

    MimicryCatalogIo::ParsedFile parsed;
    MimicryCatalogIo::Error err;
    EXPECT_FALSE(MimicryCatalogIo::parse_bytes(bytes, parsed, err));
    EXPECT_EQ(err.code, "string_too_long");
    EXPECT_EQ(err.record, 0u);
}

TEST(MimicryCatalogIo, EnumOutOfRangeRejected) {
    ProfileDescriptor d = make_valid_external();
    auto bytes = MimicryCatalogIo::serialize({d});
    // family field: after id (revision is 4 bytes after id)
    const size_t family_off = first_record_field_offset(d, 4);
    ASSERT_GT(bytes.size(), family_off + 4);
    const uint32_t bad = 99;
    for (int i = 0; i < 4; ++i)
        bytes[family_off + i] = static_cast<uint8_t>(bad >> (8 * i));
    rewrite_checksum(bytes);

    MimicryCatalogIo::ParsedFile parsed;
    MimicryCatalogIo::Error err;
    EXPECT_FALSE(MimicryCatalogIo::parse_bytes(bytes, parsed, err));
    EXPECT_EQ(err.code, "enum_out_of_range");
}

TEST(MimicryCatalogIo, BadMagicVersionFlagsRejected) {
    {
        auto bytes = MimicryCatalogIo::serialize({});
        bytes[0] = 'X';
        rewrite_checksum(bytes);
        MimicryCatalogIo::ParsedFile parsed;
        MimicryCatalogIo::Error err;
        EXPECT_FALSE(MimicryCatalogIo::parse_bytes(bytes, parsed, err));
        EXPECT_EQ(err.code, "bad_magic");
    }
    {
        auto bytes = MimicryCatalogIo::serialize({});
        bytes[8] = 0x7F;  // container_version low byte
        rewrite_checksum(bytes);
        MimicryCatalogIo::ParsedFile parsed;
        MimicryCatalogIo::Error err;
        EXPECT_FALSE(MimicryCatalogIo::parse_bytes(bytes, parsed, err));
        EXPECT_EQ(err.code, "unsupported_container_version");
    }
    {
        auto bytes = MimicryCatalogIo::serialize({});
        bytes[12] = 0x01;  // flags low byte
        rewrite_checksum(bytes);
        MimicryCatalogIo::ParsedFile parsed;
        MimicryCatalogIo::Error err;
        EXPECT_FALSE(MimicryCatalogIo::parse_bytes(bytes, parsed, err));
        EXPECT_EQ(err.code, "unsupported_flags");
    }
}

TEST(MimicryCatalogIo, MissingFileReportsStructuredError) {
    MimicryCatalogIo::ParsedFile parsed;
    MimicryCatalogIo::Error err;
    EXPECT_FALSE(MimicryCatalogIo::parse_file(
        ncp_test::temp_path("ncp_cat_io_definitely_missing.bin"), parsed,
        err));
    EXPECT_EQ(err.code, "io_open_failed");
    EXPECT_FALSE(err.message.empty());
    // non-sensitive: no file contents, no key material in the error
}

TEST(MimicryCatalogIo, CustomLimitsBoundDescriptorCount) {
    auto bytes = MimicryCatalogIo::serialize(
        {make_valid_external("a", 1), make_valid_external("b", 1)});

    MimicryCatalogIo::Limits lim;
    lim.max_descriptors = 1;
    MimicryCatalogIo::ParsedFile parsed;
    MimicryCatalogIo::Error err;
    EXPECT_FALSE(MimicryCatalogIo::parse_bytes(bytes, parsed, err, lim));
    EXPECT_EQ(err.code, "too_many_descriptors");

    // from_catalog mirrors the catalog's own validation limits
    ReferenceProfileCatalog::Limits cl;
    cl.max_profiles = 7;
    cl.max_string_len = 64;
    const auto derived = MimicryCatalogIo::Limits::from_catalog(cl);
    EXPECT_EQ(derived.max_descriptors, 7u);
    EXPECT_EQ(derived.max_string_len, 64u);
    EXPECT_EQ(derived.max_captures, cl.max_captures);
}

TEST(MimicryCatalogIo, EmptyContainerIsValid) {
    const auto bytes = MimicryCatalogIo::serialize({});
    MimicryCatalogIo::ParsedFile parsed;
    MimicryCatalogIo::Error err;
    ASSERT_TRUE(MimicryCatalogIo::parse_bytes(bytes, parsed, err))
        << err.code;
    EXPECT_TRUE(parsed.descriptors.empty());
}

// ── validate_file (validate-catalog support) ────────────────────────────────

TEST(MimicryCatalogIo, ValidateFileReportsIssuesWithoutRegistering) {
    // one clean descriptor + one whose content_hash was corrupted
    ProfileDescriptor good = make_valid_external("good", 1);
    ProfileDescriptor bad = make_valid_external("bad", 1);
    bad.provenance.sample_count = 424242;  // stale content_hash on purpose
    // (bad keeps its old content_hash → hash_mismatch at validation)

    TempFile tf("ncp_cat_io_validate.bin");
    MimicryCatalogIo::Error err;
    ASSERT_TRUE(MimicryCatalogIo::save_file(tf.path, {good, bad}, err));

    ReferenceProfileCatalog cat;
    std::vector<std::pair<std::string, std::vector<ValidationIssue>>> issues;
    ASSERT_TRUE(MimicryCatalogIo::validate_file(tf.path, cat, issues, err))
        << err.code << ": " << err.message;
    ASSERT_EQ(issues.size(), 2u);
    // deterministic order: bad@1 before good@1
    EXPECT_EQ(issues[0].first, "bad@1");
    EXPECT_TRUE(issue_has(issues[0].second, "hash_mismatch"));
    EXPECT_EQ(issues[1].first, "good@1");
    EXPECT_FALSE(issue_has(issues[1].second, "hash_mismatch"));
    // validate_file never registers anything
    EXPECT_EQ(cat.size(), 0u);
}

TEST(MimicryCatalogIo, ValidateFilePropagatesContainerErrors) {
    MimicryCatalogIo::Error err;
    std::vector<std::pair<std::string, std::vector<ValidationIssue>>> issues;
    ReferenceProfileCatalog cat;
    EXPECT_FALSE(MimicryCatalogIo::validate_file(
        ncp_test::temp_path("ncp_cat_io_missing_validate.bin"), cat, issues,
        err));
    EXPECT_EQ(err.code, "io_open_failed");
    EXPECT_TRUE(issues.empty());
}

// ── Legacy built-in export ──────────────────────────────────────────────────

TEST(MimicryCatalogIo, LegacyBuiltinExportRoundtripsDeterministically) {
    ReferenceProfileCatalog cat;
    cat.register_legacy_builtins();
    ASSERT_EQ(cat.size(), 4u);

    const auto b1 = MimicryCatalogIo::export_catalog_bytes(cat);
    const auto b2 = MimicryCatalogIo::export_catalog_bytes(cat);
    EXPECT_EQ(b1, b2) << "export must be byte-deterministic";

    MimicryCatalogIo::ParsedFile parsed;
    MimicryCatalogIo::Error err;
    ASSERT_TRUE(MimicryCatalogIo::parse_bytes(b1, parsed, err))
        << err.code << ": " << err.message;
    ASSERT_EQ(parsed.descriptors.size(), 4u);

    for (const auto& d : parsed.descriptors) {
        const ProfileDescriptor* orig =
            cat.find(d.profile_id, d.revision);
        ASSERT_NE(orig, nullptr) << d.profile_id;
        EXPECT_EQ(ReferenceProfileCatalog::canonical_serialize(d),
                  ReferenceProfileCatalog::canonical_serialize(*orig));
        EXPECT_EQ(d.content_hash, orig->content_hash);
        EXPECT_FALSE(d.signature.present);  // built-ins are unsigned
        // no payload/PCAP/IP material: provenance captures are empty and
        // every string is a short metadata label
        EXPECT_TRUE(d.provenance.captures.empty());
    }

    // exported built-ins re-import cleanly under DEV_UNSIGNED (unsigned)…
    TempFile tf("ncp_cat_io_builtins.bin");
    ASSERT_TRUE(MimicryCatalogIo::save_file(tf.path, parsed.descriptors, err));
    ReferenceProfileCatalog::Options dev;
    dev.external_policy = SignaturePolicy::DEV_UNSIGNED;
    ReferenceProfileCatalog dev_cat(dev);
    ASSERT_TRUE(MimicryCatalogIo::load_file(tf.path, dev_cat, nullptr, err))
        << err.code << ": " << err.message;
    EXPECT_EQ(dev_cat.size(), 4u);

    // …and are refused under ENFORCE (no trust bypass for file records)
    ReferenceProfileCatalog strict;
    EXPECT_FALSE(MimicryCatalogIo::load_file(tf.path, strict, nullptr, err));
    EXPECT_EQ(err.code, "registration_failed");
    EXPECT_EQ(strict.size(), 0u);
}

} // namespace
