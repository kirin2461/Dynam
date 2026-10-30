// ══════════════════════════════════════════════════════════════════════════════
// tests/test_reference_profile_catalog.cpp
// Tests for Этап 1A — ncp_reference_profile_catalog
// (versioned signed reference profile catalog + StatProfile adapter +
//  deterministic per-session derivation)
// ══════════════════════════════════════════════════════════════════════════════
#include <gtest/gtest.h>
#include "ncp_reference_profile_catalog.hpp"
#include "ncp_mimicry_session.hpp"

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <limits>
#include <random>
#include <string>
#include <vector>

using namespace ncp;

namespace {

// ── Helpers ─────────────────────────────────────────────────────────────────

std::string hex64(char c) { return std::string(64, c); }

/// A fully valid external descriptor (unsigned; call update_content_hash()
/// and optionally sign_descriptor() before registration).
ProfileDescriptor make_valid_external() {
    ProfileDescriptor d;
    d.schema_version = ProfileDescriptor::kSchemaVersion;
    d.profile_id = "test.webrtc_ref";
    d.revision = 1;
    d.family = ProtocolFamily::WEBRTC;
    d.min_wire_version = 1;
    d.max_wire_version = 3;
    d.required_capabilities = {"burst-shaping", "fsm-timing"};

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
    d.provenance.captures = {a, b};

    d.derivation.size_mean_rel_jitter = 0.10;
    d.derivation.iat_mean_rel_jitter = 0.10;
    d.derivation.burst_rel_jitter = 0.10;
    d.derivation.fsm_dwell_rel_jitter = 0.10;
    d.derivation.padding_extra_max_bytes = 64;
    d.derivation.header_gap_shift_max_bytes = 8;

    ReferenceProfileCatalog::update_content_hash(d);
    return d;
}

bool has_code(const std::vector<ValidationIssue>& issues, const std::string& code) {
    for (const auto& i : issues)
        if (i.code == code) return true;
    return false;
}

bool has_error(const std::vector<ValidationIssue>& issues, const std::string& code) {
    for (const auto& i : issues)
        if (i.code == code && i.severity == IssueSeverity::ERROR) return true;
    return false;
}

bool any_error(const std::vector<ValidationIssue>& issues) {
    for (const auto& i : issues)
        if (i.severity == IssueSeverity::ERROR) return true;
    return false;
}

SessionSecret fixed_secret(uint8_t fill) {
    std::array<uint8_t, SessionSecret::kSize> b{};
    b.fill(fill);
    return SessionSecret::from_bytes(b);
}

} // namespace

// ══════════════════════════════════════════════════════════════════════════════
// Canonical serialization & content hash
// ══════════════════════════════════════════════════════════════════════════════

TEST(ReferenceProfileCanonical, DeterministicForSameInput) {
    const auto d = make_valid_external();
    const auto c1 = ReferenceProfileCatalog::canonical_serialize(d);
    const auto c2 = ReferenceProfileCatalog::canonical_serialize(d);
    EXPECT_EQ(c1, c2);
    EXPECT_EQ(ReferenceProfileCatalog::compute_content_hash(d),
              ReferenceProfileCatalog::compute_content_hash(d));
}

TEST(ReferenceProfileCanonical, FieldChangeChangesHash) {
    auto d = make_valid_external();
    const std::string h1 = ReferenceProfileCatalog::compute_content_hash(d);
    d.revision = 2;
    EXPECT_NE(h1, ReferenceProfileCatalog::compute_content_hash(d));
    d.revision = 1;
    d.sizes.mean += 1.0;
    EXPECT_NE(h1, ReferenceProfileCatalog::compute_content_hash(d));
}

TEST(ReferenceProfileCanonical, CapabilityOrderIrrelevant) {
    auto d = make_valid_external();
    const std::string h1 = ReferenceProfileCatalog::compute_content_hash(d);
    std::reverse(d.required_capabilities.begin(), d.required_capabilities.end());
    EXPECT_EQ(h1, ReferenceProfileCatalog::compute_content_hash(d));
}

TEST(ReferenceProfileCanonical, CaptureOrderIrrelevant) {
    auto d = make_valid_external();
    const std::string h1 = ReferenceProfileCatalog::compute_content_hash(d);
    std::reverse(d.provenance.captures.begin(), d.provenance.captures.end());
    EXPECT_EQ(h1, ReferenceProfileCatalog::compute_content_hash(d));
}

TEST(ReferenceProfileCanonical, SignatureExcludedFromHash) {
    auto d = make_valid_external();
    const std::string h1 = ReferenceProfileCatalog::compute_content_hash(d);
    auto kp = ReferenceProfileCatalog::generate_signing_keypair();
    ASSERT_TRUE(ReferenceProfileCatalog::sign_descriptor(d, "key-1", kp.secret_key));
    EXPECT_TRUE(d.signature.present);
    EXPECT_EQ(h1, ReferenceProfileCatalog::compute_content_hash(d));
    EXPECT_EQ(h1, d.content_hash);
}

// ══════════════════════════════════════════════════════════════════════════════
// Validation
// ══════════════════════════════════════════════════════════════════════════════

class ReferenceProfileValidation : public ::testing::Test {
protected:
    ReferenceProfileCatalog cat;
    ProfileDescriptor d = make_valid_external();
};

TEST_F(ReferenceProfileValidation, ValidDescriptorPasses) {
    const auto issues = cat.validate_descriptor(d);
    for (const auto& i : issues)
        ADD_FAILURE() << "unexpected " << i.code << ": " << i.message;
    EXPECT_TRUE(issues.empty());
}

TEST_F(ReferenceProfileValidation, RejectsBadSchemaVersion) {
    d.schema_version = 99;
    ReferenceProfileCatalog::update_content_hash(d);
    EXPECT_TRUE(has_error(cat.validate_descriptor(d), "unsupported_schema_version"));
}

TEST_F(ReferenceProfileValidation, RejectsInvalidProfileId) {
    d.profile_id = "Bad ID!";
    ReferenceProfileCatalog::update_content_hash(d);
    EXPECT_TRUE(has_error(cat.validate_descriptor(d), "invalid_profile_id"));
    d.profile_id = "";
    ReferenceProfileCatalog::update_content_hash(d);
    EXPECT_TRUE(has_error(cat.validate_descriptor(d), "invalid_profile_id"));
}

TEST_F(ReferenceProfileValidation, RejectsZeroRevision) {
    d.revision = 0;
    ReferenceProfileCatalog::update_content_hash(d);
    EXPECT_TRUE(has_error(cat.validate_descriptor(d), "invalid_revision"));
}

TEST_F(ReferenceProfileValidation, RejectsWireVersionInversion) {
    d.min_wire_version = 5;
    d.max_wire_version = 2;
    ReferenceProfileCatalog::update_content_hash(d);
    EXPECT_TRUE(has_error(cat.validate_descriptor(d), "wire_version_range"));
}

TEST_F(ReferenceProfileValidation, RejectsUnknownCapability) {
    d.required_capabilities.push_back("does-not-exist");
    ReferenceProfileCatalog::update_content_hash(d);
    EXPECT_TRUE(has_error(cat.validate_descriptor(d), "unknown_capability"));
}

TEST_F(ReferenceProfileValidation, RejectsMixWeightSum) {
    d.sizes.kind = SizeDistKind::DISCRETE_MIX;
    d.sizes.components = {{0.7, 500.0, 50.0}, {0.2, 900.0, 80.0}};  // sums to 0.9
    ReferenceProfileCatalog::update_content_hash(d);
    EXPECT_TRUE(has_error(cat.validate_descriptor(d), "size_mix_weights_sum"));
}

TEST_F(ReferenceProfileValidation, RejectsEmptyMix) {
    d.sizes.kind = SizeDistKind::DISCRETE_MIX;
    d.sizes.components.clear();
    ReferenceProfileCatalog::update_content_hash(d);
    EXPECT_TRUE(has_error(cat.validate_descriptor(d), "size_mix_empty"));
}

TEST_F(ReferenceProfileValidation, RejectsNegativeSizeStddev) {
    d.sizes.stddev = -1.0;
    ReferenceProfileCatalog::update_content_hash(d);
    EXPECT_TRUE(has_error(cat.validate_descriptor(d), "size_stddev_negative"));
}

TEST_F(ReferenceProfileValidation, RejectsClampRange) {
    d.sizes.clamp_min = 2000.0;
    d.sizes.clamp_max = 100.0;
    ReferenceProfileCatalog::update_content_hash(d);
    EXPECT_TRUE(has_error(cat.validate_descriptor(d), "size_clamp_range"));
}

TEST_F(ReferenceProfileValidation, RejectsClampAbovePayloadBudget) {
    d.sizes.clamp_max = 5000.0;  // > mtu.max_payload_bytes (1400)
    ReferenceProfileCatalog::update_content_hash(d);
    EXPECT_TRUE(has_error(cat.validate_descriptor(d), "size_exceeds_payload_budget"));
}

TEST_F(ReferenceProfileValidation, RejectsBadExponentialIat) {
    d.iat.kind = IntervalKind::EXPONENTIAL;
    d.iat.mean_ms = 0.0;
    ReferenceProfileCatalog::update_content_hash(d);
    EXPECT_TRUE(has_error(cat.validate_descriptor(d), "iat_mean"));
}

TEST_F(ReferenceProfileValidation, RejectsNegativeFixedIat) {
    d.iat.kind = IntervalKind::FIXED;
    d.iat.fixed_ms = -5.0;
    ReferenceProfileCatalog::update_content_hash(d);
    EXPECT_TRUE(has_error(cat.validate_descriptor(d), "iat_fixed"));
}

TEST_F(ReferenceProfileValidation, RejectsJointCorrelationOutOfRange) {
    d.joint->correlation = 1.5;
    ReferenceProfileCatalog::update_content_hash(d);
    EXPECT_TRUE(has_error(cat.validate_descriptor(d), "joint_correlation_range"));
}

TEST_F(ReferenceProfileValidation, RejectsBurstPacketsBelowOne) {
    d.burst.mean_burst_packets = 0.5;
    ReferenceProfileCatalog::update_content_hash(d);
    EXPECT_TRUE(has_error(cat.validate_descriptor(d), "burst_packets"));
}

TEST_F(ReferenceProfileValidation, RejectsFsmDuplicateState) {
    d.fsm.states.push_back({"idle", 100.0, 10.0});
    ReferenceProfileCatalog::update_content_hash(d);
    EXPECT_TRUE(has_error(cat.validate_descriptor(d), "fsm_duplicate_state"));
}

TEST_F(ReferenceProfileValidation, RejectsFsmInitialMissing) {
    d.fsm.initial_state = "ghost";
    ReferenceProfileCatalog::update_content_hash(d);
    EXPECT_TRUE(has_error(cat.validate_descriptor(d), "fsm_initial_state"));
}

TEST_F(ReferenceProfileValidation, RejectsFsmTransitionRef) {
    d.fsm.transitions.push_back({"bulk", "ghost", 0.5});
    ReferenceProfileCatalog::update_content_hash(d);
    EXPECT_TRUE(has_error(cat.validate_descriptor(d), "fsm_transition_ref"));
}

TEST_F(ReferenceProfileValidation, RejectsFsmProbabilitySum) {
    d.fsm.transitions.push_back({"idle", "bulk", 0.5});  // idle now sums to 1.5
    ReferenceProfileCatalog::update_content_hash(d);
    EXPECT_TRUE(has_error(cat.validate_descriptor(d), "fsm_probability_sum"));
}

TEST_F(ReferenceProfileValidation, RejectsMtuBudgetExceeded) {
    d.mtu.max_payload_bytes = 1500;  // 60 header + 1500 > 1500 MTU
    d.sizes.clamp_max = 1500.0;      // keep within payload budget
    ReferenceProfileCatalog::update_content_hash(d);
    EXPECT_TRUE(has_error(cat.validate_descriptor(d), "mtu_budget_exceeded"));
}

TEST_F(ReferenceProfileValidation, RejectsDuplicateCaptureId) {
    d.provenance.captures.push_back(d.provenance.captures[0]);
    d.provenance.captures.back().capture_hash = hex64('c');  // distinct hash
    ReferenceProfileCatalog::update_content_hash(d);
    EXPECT_TRUE(has_error(cat.validate_descriptor(d), "duplicate_capture_id"));
}

TEST_F(ReferenceProfileValidation, RejectsDuplicateCaptureHash) {
    d.provenance.captures.push_back(d.provenance.captures[0]);
    d.provenance.captures.back().capture_id = "cap-c";  // distinct id
    ReferenceProfileCatalog::update_content_hash(d);
    EXPECT_TRUE(has_error(cat.validate_descriptor(d), "duplicate_capture_hash"));
}

TEST_F(ReferenceProfileValidation, RejectsBadCaptureHashFormat) {
    d.provenance.captures[0].capture_hash = "not-a-hash";
    ReferenceProfileCatalog::update_content_hash(d);
    EXPECT_TRUE(has_error(cat.validate_descriptor(d), "capture_hash_format"));
}

TEST_F(ReferenceProfileValidation, RejectsNegativeControlSessionOverlap) {
    // Negative control must be session-disjoint from primary captures.
    d.provenance.captures[1].session_group = "sg-1";  // same as primary cap-a
    ReferenceProfileCatalog::update_content_hash(d);
    EXPECT_TRUE(has_error(cat.validate_descriptor(d),
                          "session_overlap_negative_control"));
}

TEST_F(ReferenceProfileValidation, RejectsMissingContentHash) {
    d.content_hash.clear();
    EXPECT_TRUE(has_error(cat.validate_descriptor(d), "missing_content_hash"));
}

TEST_F(ReferenceProfileValidation, RejectsHashMismatch) {
    d.sizes.mean += 1.0;  // tamper without refreshing the hash
    EXPECT_TRUE(has_error(cat.validate_descriptor(d), "hash_mismatch"));
}

TEST_F(ReferenceProfileValidation, RejectsNegativeDerivationBounds) {
    d.derivation.iat_mean_rel_jitter = -0.1;
    ReferenceProfileCatalog::update_content_hash(d);
    EXPECT_TRUE(has_error(cat.validate_descriptor(d), "derivation_negative"));
}

// ══════════════════════════════════════════════════════════════════════════════
// Registration & signature policy
// ══════════════════════════════════════════════════════════════════════════════

TEST(ReferenceProfilePolicy, EnforceRejectsUnsigned) {
    ReferenceProfileCatalog cat;  // ENFORCE is the default
    const auto out = cat.register_profile(make_valid_external());
    EXPECT_EQ(out.status, ReferenceProfileCatalog::RegisterStatus::REJECTED);
    EXPECT_TRUE(has_error(out.issues, "signature_required"));
    EXPECT_EQ(cat.size(), 0u);
}

TEST(ReferenceProfilePolicy, EnforceAcceptsValidSignature) {
    ReferenceProfileCatalog cat;
    auto kp = ReferenceProfileCatalog::generate_signing_keypair();
    ASSERT_TRUE(cat.add_trusted_key("key-1", kp.public_key));
    EXPECT_TRUE(cat.has_trusted_key("key-1"));

    auto d = make_valid_external();
    ASSERT_TRUE(ReferenceProfileCatalog::sign_descriptor(d, "key-1", kp.secret_key));
    const auto out = cat.register_profile(d);
    EXPECT_TRUE(out.ok()) << (out.issues.empty() ? "" : out.issues[0].message);
    EXPECT_EQ(out.status, ReferenceProfileCatalog::RegisterStatus::OK);
    EXPECT_EQ(out.canonical_id, "test.webrtc_ref@1");
    EXPECT_EQ(cat.size(), 1u);
}

TEST(ReferenceProfilePolicy, EnforceRejectsUnknownSigningKey) {
    ReferenceProfileCatalog cat;
    auto kp = ReferenceProfileCatalog::generate_signing_keypair();
    auto d = make_valid_external();
    ASSERT_TRUE(ReferenceProfileCatalog::sign_descriptor(d, "key-1", kp.secret_key));
    const auto out = cat.register_profile(d);  // key never added to trust store
    EXPECT_EQ(out.status, ReferenceProfileCatalog::RegisterStatus::REJECTED);
    EXPECT_TRUE(has_error(out.issues, "unknown_signing_key"));
}

TEST(ReferenceProfilePolicy, EnforceRejectsCorruptedSignature) {
    ReferenceProfileCatalog cat;
    auto kp = ReferenceProfileCatalog::generate_signing_keypair();
    ASSERT_TRUE(cat.add_trusted_key("key-1", kp.public_key));
    auto d = make_valid_external();
    ASSERT_TRUE(ReferenceProfileCatalog::sign_descriptor(d, "key-1", kp.secret_key));
    d.signature.signature[10] ^= 0xFF;
    const auto out = cat.register_profile(d);
    EXPECT_EQ(out.status, ReferenceProfileCatalog::RegisterStatus::REJECTED);
    EXPECT_TRUE(has_error(out.issues, "invalid_signature"));
}

TEST(ReferenceProfilePolicy, EnforceRejectsPostSignTampering) {
    ReferenceProfileCatalog cat;
    auto kp = ReferenceProfileCatalog::generate_signing_keypair();
    ASSERT_TRUE(cat.add_trusted_key("key-1", kp.public_key));
    auto d = make_valid_external();
    ASSERT_TRUE(ReferenceProfileCatalog::sign_descriptor(d, "key-1", kp.secret_key));
    d.sizes.mean += 1.0;  // tamper: hash no longer matches, signature invalid
    const auto out = cat.register_profile(d);
    EXPECT_EQ(out.status, ReferenceProfileCatalog::RegisterStatus::REJECTED);
    EXPECT_TRUE(has_error(out.issues, "hash_mismatch"));
}

TEST(ReferenceProfilePolicy, DuplicateRevisionRejected) {
    ReferenceProfileCatalog cat;
    auto kp = ReferenceProfileCatalog::generate_signing_keypair();
    ASSERT_TRUE(cat.add_trusted_key("key-1", kp.public_key));
    auto d = make_valid_external();
    ASSERT_TRUE(ReferenceProfileCatalog::sign_descriptor(d, "key-1", kp.secret_key));
    ASSERT_TRUE(cat.register_profile(d).ok());
    const auto dup = cat.register_profile(d);
    EXPECT_EQ(dup.status, ReferenceProfileCatalog::RegisterStatus::REJECTED);
    EXPECT_TRUE(has_error(dup.issues, "duplicate_profile_revision"));
}

TEST(ReferenceProfilePolicy, MultipleRevisionsCoexistAndLatestWins) {
    ReferenceProfileCatalog cat;
    auto kp = ReferenceProfileCatalog::generate_signing_keypair();
    ASSERT_TRUE(cat.add_trusted_key("key-1", kp.public_key));

    auto d1 = make_valid_external();
    ASSERT_TRUE(ReferenceProfileCatalog::sign_descriptor(d1, "key-1", kp.secret_key));
    ASSERT_TRUE(cat.register_profile(d1).ok());

    auto d2 = make_valid_external();
    d2.revision = 2;
    d2.sizes.mean = 600.0;
    ASSERT_TRUE(ReferenceProfileCatalog::sign_descriptor(d2, "key-1", kp.secret_key));
    ASSERT_TRUE(cat.register_profile(d2).ok());

    EXPECT_EQ(cat.size(), 2u);
    ASSERT_NE(cat.find("test.webrtc_ref", 1), nullptr);
    const auto* latest = cat.find_latest("test.webrtc_ref");
    ASSERT_NE(latest, nullptr);
    EXPECT_EQ(latest->revision, 2u);
    EXPECT_DOUBLE_EQ(latest->sizes.mean, 600.0);
    EXPECT_EQ(cat.find_latest("nope"), nullptr);
    EXPECT_EQ(cat.find("test.webrtc_ref", 99), nullptr);
}

TEST(ReferenceProfilePolicy, WarnOnlyAcceptsUnsignedWithWarning) {
    ReferenceProfileCatalog::Options opts;
    opts.external_policy = SignaturePolicy::WARN_ONLY;
    ReferenceProfileCatalog cat(opts);
    const auto out = cat.register_profile(make_valid_external());
    EXPECT_TRUE(out.ok());
    EXPECT_EQ(out.status, ReferenceProfileCatalog::RegisterStatus::WARNED);
    EXPECT_TRUE(has_code(out.issues, "unsigned_profile"));
    EXPECT_EQ(cat.size(), 1u);
}

TEST(ReferenceProfilePolicy, DevUnsignedAcceptsWithWarning) {
    ReferenceProfileCatalog::Options opts;
    opts.external_policy = SignaturePolicy::DEV_UNSIGNED;
    ReferenceProfileCatalog cat(opts);
    const auto out = cat.register_profile(make_valid_external());
    EXPECT_TRUE(out.ok());
    EXPECT_EQ(out.status, ReferenceProfileCatalog::RegisterStatus::WARNED);
    EXPECT_TRUE(has_code(out.issues, "dev_unsigned_policy"));
}

TEST(ReferenceProfilePolicy, CatalogFullRejects) {
    ReferenceProfileCatalog::Options opts;
    opts.external_policy = SignaturePolicy::DEV_UNSIGNED;
    opts.limits.max_profiles = 1;
    ReferenceProfileCatalog cat(opts);
    auto d1 = make_valid_external();
    ASSERT_TRUE(cat.register_profile(d1).ok());
    auto d2 = make_valid_external();
    d2.profile_id = "test.other";
    ReferenceProfileCatalog::update_content_hash(d2);
    const auto out = cat.register_profile(d2);
    EXPECT_EQ(out.status, ReferenceProfileCatalog::RegisterStatus::REJECTED);
    EXPECT_TRUE(has_error(out.issues, "catalog_full"));
}

TEST(ReferenceProfilePolicy, RejectsInvalidKeySize) {
    ReferenceProfileCatalog cat;
    EXPECT_FALSE(cat.add_trusted_key("key-1", std::vector<uint8_t>(16, 0x42)));
    EXPECT_FALSE(cat.add_trusted_key("", std::vector<uint8_t>(32, 0x42)));
}

TEST(ReferenceProfilePolicy, BuiltinPathRespectsCatalogCapacity) {
    ReferenceProfileCatalog::Options opts;
    opts.limits.max_profiles = 1;
    ReferenceProfileCatalog cat(opts);
    ASSERT_TRUE(cat.register_builtin_stat_profile(StatProfile::voip_opus()).ok());
    const auto out = cat.register_builtin_stat_profile(StatProfile::zoom_call());
    EXPECT_EQ(out.status, ReferenceProfileCatalog::RegisterStatus::REJECTED);
    EXPECT_TRUE(has_error(out.issues, "catalog_full"));
    EXPECT_EQ(cat.size(), 1u);
}

// ══════════════════════════════════════════════════════════════════════════════
// Built-in StatProfile adapter (trusted path, backward compatibility)
// ══════════════════════════════════════════════════════════════════════════════

TEST(ReferenceProfileAdapter, RegisterLegacyBuiltins) {
    ReferenceProfileCatalog cat;  // ENFORCE default — builtins bypass via trust
    cat.register_legacy_builtins();
    EXPECT_EQ(cat.size(), 4u);
    // Legacy names must be preserved exactly.
    for (const char* name : {"webrtc_video", "zoom_call", "youtube_stream",
                             "voip_opus"}) {
        const auto* d = cat.find(name, 1);
        ASSERT_NE(d, nullptr) << name;
        EXPECT_EQ(d->profile_id, name);
        EXPECT_FALSE(d->signature.present);  // trusted path, no signature
        EXPECT_FALSE(d->content_hash.empty());
    }
    EXPECT_EQ(cat.find_latest("voip_opus")->revision, 1u);
}

TEST(ReferenceProfileAdapter, BuiltinRoundtripPreservesSamplingBehavior) {
    // from_stat_profile → to_stat_profile must preserve the exact sampling
    // behavior of the legacy profile (identical sequences on identical RNGs).
    for (const auto& legacy : {StatProfile::webrtc_video(), StatProfile::zoom_call(),
                               StatProfile::youtube_stream(), StatProfile::voip_opus()}) {
        const auto d = ReferenceProfileCatalog::from_stat_profile(legacy);
        const auto adapted = ReferenceProfileCatalog::to_stat_profile(d);
        EXPECT_EQ(adapted.name, legacy.name);

        std::mt19937_64 rng_a(12345), rng_b(12345);
        for (int i = 0; i < 200; ++i) {
            EXPECT_DOUBLE_EQ(legacy.sample_size(rng_a), adapted.sample_size(rng_b));
        }
        for (int i = 0; i < 200; ++i) {
            EXPECT_DOUBLE_EQ(legacy.sample_interval_ms(rng_a),
                             adapted.sample_interval_ms(rng_b));
        }
    }
}

TEST(ReferenceProfileAdapter, BuiltinDescriptorValidatesWithoutErrors) {
    ReferenceProfileCatalog cat;
    const auto d =
        ReferenceProfileCatalog::from_stat_profile(StatProfile::webrtc_video());
    const auto issues = cat.validate_descriptor(d);
    // Hand-tuned builtins honestly report missing capture provenance as
    // warnings, but must not produce validation errors.
    EXPECT_FALSE(any_error(issues));
    EXPECT_TRUE(has_code(issues, "insufficient_provenance"));
}

TEST(ReferenceProfileAdapter, BuiltinRegistrationIsTrustedPath) {
    ReferenceProfileCatalog cat;
    const auto out =
        cat.register_builtin_stat_profile(StatProfile::voip_opus());
    EXPECT_TRUE(out.ok());
    EXPECT_EQ(out.status, ReferenceProfileCatalog::RegisterStatus::WARNED);
    EXPECT_EQ(out.canonical_id, "voip_opus@1");
}

TEST(ReferenceProfileAdapter, OversizedClampIsContainedWithinWireBudget) {
    // A legacy profile clamping above the u16 wire budget must still adapt
    // into a valid descriptor (no mtu_range / budget validation errors).
    ReferenceProfileCatalog cat;
    StatProfile p = StatProfile::voip_opus();
    p.name = "oversized_custom";
    p.sizes.clamp_max = 200000.0;  // > 65535
    const auto d = ReferenceProfileCatalog::from_stat_profile(p);
    EXPECT_LE(d.sizes.clamp_max, 65435.0);
    EXPECT_LE(d.mtu.path_mtu_bytes, 65535u);
    const auto issues = cat.validate_descriptor(d);
    EXPECT_FALSE(has_code(issues, "mtu_range"));
    EXPECT_FALSE(has_code(issues, "mtu_budget_exceeded"));
    EXPECT_FALSE(has_code(issues, "size_exceeds_payload_budget"));
    EXPECT_FALSE(has_code(issues, "size_clamp_max_resource"));
    EXPECT_TRUE(cat.register_builtin(d).ok());
}

TEST(ReferenceProfileAdapter, JointSamplerSummarizedIntoDescriptor) {
    // A StatProfile carrying a sampler-side joint model gets a lag-0 Pearson
    // correlation summary in the descriptor's ReferenceJointSizeIatModel.
    StatProfile p = StatProfile::voip_opus();
    p.name = "joint_custom";
    JointSizeIatComponent c;
    c.weight = 1.0;
    c.mu_size_bytes = 200.0;
    c.mu_iat_ms = 20.0;
    c.l00 = 20.0;
    c.l10 = 3.0;
    c.l11 = 4.0;  // correlation = 3/5 = 0.6
    p.size_iat_joint.components = {c};
    ASSERT_TRUE(p.has_joint_size_iat());

    const auto d = ReferenceProfileCatalog::from_stat_profile(p);
    ASSERT_TRUE(d.joint.has_value());
    EXPECT_NEAR(d.joint->correlation, 0.6, 1e-9);
    EXPECT_EQ(d.joint->lag_packets, 0u);

    // The reverse direction preserves legacy marginal sampling (no GMM is
    // reconstructed from a correlation summary).
    const auto back = ReferenceProfileCatalog::to_stat_profile(d);
    EXPECT_FALSE(back.has_joint_size_iat());
}

TEST(ReferenceProfileAdapter, ProfileWithoutJointHasNoJointDescriptor) {
    const auto d =
        ReferenceProfileCatalog::from_stat_profile(StatProfile::voip_opus());
    EXPECT_FALSE(d.joint.has_value());
}

TEST(ReferenceProfileAdapter, DerivedStatWorksWithLegacyShaper) {
    ReferenceProfileCatalog cat;
    cat.register_legacy_builtins();
    const auto* d = cat.find("zoom_call", 1);
    ASSERT_NE(d, nullptr);
    const auto stat = ReferenceProfileCatalog::to_stat_profile(*d);
    MimicryShaper shaper(stat, 42);
    const auto plan = shaper.plan(100000);
    ASSERT_FALSE(plan.empty());
    size_t total = 0;
    for (const auto& c : plan) {
        EXPECT_GE(c.bytes, 1u);
        EXPECT_LE(static_cast<double>(c.bytes), d->sizes.clamp_max);
        total += c.bytes;
    }
    EXPECT_EQ(total, 100000u);
}

// ══════════════════════════════════════════════════════════════════════════════
// Lookup / listing / wire compatibility
// ══════════════════════════════════════════════════════════════════════════════

TEST(ReferenceProfileLookup, ListAndFamilyFilter) {
    ReferenceProfileCatalog cat;
    cat.register_legacy_builtins();
    const auto all = cat.list();
    ASSERT_EQ(all.size(), 4u);
    EXPECT_TRUE(std::is_sorted(all.begin(), all.end()));
    // All legacy builtins are adapted as GENERIC_UDP.
    const auto udp = cat.list_by_family(ProtocolFamily::GENERIC_UDP);
    EXPECT_EQ(udp.size(), 4u);
    EXPECT_TRUE(cat.list_by_family(ProtocolFamily::TLS).empty());
}

TEST(ReferenceProfileLookup, WireCompatibility) {
    const auto d = make_valid_external();  // wire range [1, 3]
    EXPECT_FALSE(d.is_wire_compatible(0));
    EXPECT_TRUE(d.is_wire_compatible(1));
    EXPECT_TRUE(d.is_wire_compatible(3));
    EXPECT_FALSE(d.is_wire_compatible(4));
}

// ══════════════════════════════════════════════════════════════════════════════
// Deterministic per-session derivation
// ══════════════════════════════════════════════════════════════════════════════

TEST(ReferenceProfileDerivation, DeterministicForSameSecret) {
    const auto d = make_valid_external();
    const auto s = fixed_secret(0x11);
    const auto a = ReferenceProfileCatalog::derive_session(d, s);
    const auto b = ReferenceProfileCatalog::derive_session(d, s);
    EXPECT_EQ(a.session_tag, b.session_tag);
    EXPECT_EQ(a.rng_seed, b.rng_seed);
    EXPECT_DOUBLE_EQ(a.stat.sizes.mean, b.stat.sizes.mean);
    EXPECT_DOUBLE_EQ(a.stat.intervals.mean_ms, b.stat.intervals.mean_ms);
    EXPECT_DOUBLE_EQ(a.burst_scale, b.burst_scale);
    EXPECT_DOUBLE_EQ(a.fsm_dwell_scale, b.fsm_dwell_scale);
    EXPECT_EQ(a.header_gap_shift_bytes, b.header_gap_shift_bytes);
    EXPECT_EQ(a.padding_extra_bytes, b.padding_extra_bytes);
    EXPECT_EQ(a.profile_id, d.profile_id);
    EXPECT_EQ(a.stat.name, d.profile_id);  // legacy name preserved
}

TEST(ReferenceProfileDerivation, DiffersAcrossSessions) {
    const auto d = make_valid_external();
    const auto a = ReferenceProfileCatalog::derive_session(d, fixed_secret(0x11));
    const auto b = ReferenceProfileCatalog::derive_session(d, fixed_secret(0x22));
    EXPECT_NE(a.session_tag, b.session_tag);
    EXPECT_NE(a.rng_seed, b.rng_seed);
    // Overwhelmingly probable: at least one jittered parameter differs.
    const bool params_differ =
        a.stat.sizes.mean != b.stat.sizes.mean ||
        a.stat.intervals.mean_ms != b.stat.intervals.mean_ms ||
        a.burst_scale != b.burst_scale ||
        a.padding_extra_bytes != b.padding_extra_bytes;
    EXPECT_TRUE(params_differ);
}

TEST(ReferenceProfileDerivation, ParametersStayWithinBounds) {
    auto d = make_valid_external();
    const double j_size = d.derivation.size_mean_rel_jitter;
    const double j_iat = d.derivation.iat_mean_rel_jitter;
    const double j_burst = d.derivation.burst_rel_jitter;

    for (uint32_t i = 0; i < 50; ++i) {
        const auto s = SessionSecret::generate();
        const auto dp = ReferenceProfileCatalog::derive_session(d, s);

        // size mean: within ±jitter of base AND within model clamps
        EXPECT_GE(dp.stat.sizes.mean, 500.0 * (1.0 - j_size) - 1e-9);
        EXPECT_LE(dp.stat.sizes.mean, 500.0 * (1.0 + j_size) + 1e-9);
        EXPECT_GE(dp.stat.sizes.mean, dp.stat.sizes.clamp_min);
        EXPECT_LE(dp.stat.sizes.mean, dp.stat.sizes.clamp_max);

        // iat mean: within ±jitter, non-negative
        EXPECT_GE(dp.stat.intervals.mean_ms, 20.0 * (1.0 - j_iat) - 1e-9);
        EXPECT_LE(dp.stat.intervals.mean_ms, 20.0 * (1.0 + j_iat) + 1e-9);
        EXPECT_GE(dp.stat.intervals.mean_ms, 0.0);

        // burst scale, FSM dwell scale, header shift and padding cap
        EXPECT_GE(dp.burst_scale, 1.0 - j_burst - 1e-9);
        EXPECT_LE(dp.burst_scale, 1.0 + j_burst + 1e-9);
        const double j_dwell = d.derivation.fsm_dwell_rel_jitter;
        EXPECT_GE(dp.fsm_dwell_scale, 1.0 - j_dwell - 1e-9);
        EXPECT_LE(dp.fsm_dwell_scale, 1.0 + j_dwell + 1e-9);
        EXPECT_LE(std::abs(dp.header_gap_shift_bytes),
                  static_cast<int>(d.derivation.header_gap_shift_max_bytes));
        EXPECT_LE(dp.padding_extra_bytes, d.derivation.padding_extra_max_bytes);
    }
}

TEST(ReferenceProfileDerivation, DiscreteMixComponentsJitteredAndClamped) {
    auto d = make_valid_external();
    d.sizes.kind = SizeDistKind::DISCRETE_MIX;
    d.sizes.components = {{0.5, 400.0, 40.0}, {0.5, 900.0, 60.0}};
    d.derivation.size_mean_rel_jitter = 0.5;  // large enough to hit clamps
    ReferenceProfileCatalog::update_content_hash(d);

    for (uint32_t i = 0; i < 20; ++i) {
        const auto dp =
            ReferenceProfileCatalog::derive_session(d, SessionSecret::generate());
        ASSERT_EQ(dp.stat.sizes.components.size(), 2u);
        for (const auto& c : dp.stat.sizes.components) {
            EXPECT_GE(c.mean, dp.stat.sizes.clamp_min);
            EXPECT_LE(c.mean, dp.stat.sizes.clamp_max);
        }
    }
}

TEST(ReferenceProfileDerivation, DerivedProfileFeedsLegacyShaper) {
    const auto d = make_valid_external();
    const auto dp = ReferenceProfileCatalog::derive_session(d, fixed_secret(0x77));
    MimicryShaper shaper(dp.stat, dp.rng_seed);
    const auto plan = shaper.plan(50000);
    ASSERT_FALSE(plan.empty());
    size_t total = 0;
    for (const auto& c : plan) {
        EXPECT_GE(c.bytes, 1u);
        EXPECT_LE(static_cast<double>(c.bytes), d.sizes.clamp_max);
        EXPECT_GE(c.delay_ms, 0.0);
        total += c.bytes;
    }
    EXPECT_EQ(total, 50000u);
}

TEST(ReferenceProfileDerivation, SessionSecretsAreDistinct) {
    const auto a = SessionSecret::generate();
    const auto b = SessionSecret::generate();
    EXPECT_NE(a.bytes(), b.bytes());
}

TEST(ReferenceProfileDerivation, ZeroJitterYieldsBaseParameters) {
    auto d = make_valid_external();
    d.derivation.size_mean_rel_jitter = 0.0;
    d.derivation.iat_mean_rel_jitter = 0.0;
    d.derivation.burst_rel_jitter = 0.0;
    d.derivation.fsm_dwell_rel_jitter = 0.0;
    d.derivation.padding_extra_max_bytes = 0;
    d.derivation.header_gap_shift_max_bytes = 0;
    ReferenceProfileCatalog::update_content_hash(d);
    const auto dp = ReferenceProfileCatalog::derive_session(d, fixed_secret(0x33));
    EXPECT_DOUBLE_EQ(dp.stat.sizes.mean, d.sizes.mean);
    EXPECT_DOUBLE_EQ(dp.stat.intervals.mean_ms, d.iat.mean_ms);
    EXPECT_DOUBLE_EQ(dp.burst_scale, 1.0);
    EXPECT_DOUBLE_EQ(dp.fsm_dwell_scale, 1.0);
    EXPECT_EQ(dp.header_gap_shift_bytes, 0);
    EXPECT_EQ(dp.padding_extra_bytes, 0u);
    // rng seed still derived (non-zero with overwhelming probability)
    EXPECT_NE(dp.rng_seed, 0u);
}

// ══════════════════════════════════════════════════════════════════════════════
// Reviewer-mandated hardening (M1/M2/L1/L2)
// ══════════════════════════════════════════════════════════════════════════════

TEST(ReferenceProfileCanonical, DerivationFieldsCoveredByHash) {
    auto d = make_valid_external();
    const std::string h1 = ReferenceProfileCatalog::compute_content_hash(d);
    d.derivation.fsm_dwell_rel_jitter += 0.01;
    EXPECT_NE(h1, ReferenceProfileCatalog::compute_content_hash(d));
    d.derivation.fsm_dwell_rel_jitter -= 0.01;
    d.derivation.header_gap_shift_max_bytes += 1;
    EXPECT_NE(h1, ReferenceProfileCatalog::compute_content_hash(d));
    // restoring the original value restores the original hash
    d.derivation.header_gap_shift_max_bytes -= 1;
    EXPECT_EQ(h1, ReferenceProfileCatalog::compute_content_hash(d));
}

TEST_F(ReferenceProfileValidation, RejectsNonFiniteSizeMean) {
    d.sizes.mean = std::numeric_limits<double>::quiet_NaN();
    ReferenceProfileCatalog::update_content_hash(d);
    EXPECT_TRUE(has_error(cat.validate_descriptor(d), "size_mean_not_finite"));

    d = make_valid_external();
    d.sizes.mean = std::numeric_limits<double>::infinity();
    ReferenceProfileCatalog::update_content_hash(d);
    EXPECT_TRUE(has_error(cat.validate_descriptor(d), "size_mean_not_finite"));
}

TEST_F(ReferenceProfileValidation, RejectsNonFiniteMixComponent) {
    d.sizes.kind = SizeDistKind::DISCRETE_MIX;
    d.sizes.components = {{0.5, std::numeric_limits<double>::quiet_NaN(), 10.0},
                          {0.5, 500.0, 50.0}};
    ReferenceProfileCatalog::update_content_hash(d);
    EXPECT_TRUE(has_error(cat.validate_descriptor(d), "size_mix_not_finite"));
}

TEST_F(ReferenceProfileValidation, RejectsNonFiniteIat) {
    d.iat.mean_ms = -std::numeric_limits<double>::infinity();
    ReferenceProfileCatalog::update_content_hash(d);
    EXPECT_TRUE(has_error(cat.validate_descriptor(d), "iat_not_finite"));
}

TEST_F(ReferenceProfileValidation, RejectsNegativeFsmDwellJitterBound) {
    d.derivation.fsm_dwell_rel_jitter = -0.01;
    ReferenceProfileCatalog::update_content_hash(d);
    EXPECT_TRUE(has_error(cat.validate_descriptor(d), "derivation_negative"));
}

TEST(ReferenceProfileAdapter, NonFiniteClampIsSanitised) {
    // inf/NaN clamp_max must not cause UB in ceil/cast; the adapter must
    // still produce a validatable descriptor.
    ReferenceProfileCatalog cat;
    for (double bad : {std::numeric_limits<double>::infinity(),
                       -std::numeric_limits<double>::infinity(),
                       std::numeric_limits<double>::quiet_NaN()}) {
        StatProfile p = StatProfile::voip_opus();
        p.name = "sanitised_custom";
        p.sizes.clamp_max = bad;
        const auto d = ReferenceProfileCatalog::from_stat_profile(p);
        EXPECT_TRUE(std::isfinite(d.sizes.clamp_max));
        EXPECT_LE(d.sizes.clamp_max, 65435.0);
        EXPECT_LE(d.mtu.path_mtu_bytes, 65535u);
        EXPECT_FALSE(has_code(cat.validate_descriptor(d), "mtu_range"));
        EXPECT_FALSE(has_code(cat.validate_descriptor(d), "size_clamp_not_finite"));
    }
}

TEST(ReferenceProfileDerivation, PaddingCapAtUint32MaxDoesNotOverflow) {
    auto d = make_valid_external();
    d.padding_header.padding_max_bytes = 0;  // no padding cap interference
    d.derivation.padding_extra_max_bytes = UINT32_MAX;
    ReferenceProfileCatalog::update_content_hash(d);
    for (uint32_t i = 0; i < 10; ++i) {
        const auto dp =
            ReferenceProfileCatalog::derive_session(d, SessionSecret::generate());
        EXPECT_LE(dp.padding_extra_bytes, UINT32_MAX);  // no wraparound garbage
    }
    // deterministic for a fixed secret even at the extreme cap
    const auto a = ReferenceProfileCatalog::derive_session(d, fixed_secret(0x42));
    const auto b = ReferenceProfileCatalog::derive_session(d, fixed_secret(0x42));
    EXPECT_EQ(a.padding_extra_bytes, b.padding_extra_bytes);
}

TEST(ReferenceProfileDerivation, FsmDwellAndHeaderShiftVaryAcrossSessions) {
    const auto d = make_valid_external();
    bool dwell_differs = false, shift_differs = false;
    const auto ref = ReferenceProfileCatalog::derive_session(d, fixed_secret(0x01));
    for (uint8_t i = 2; i < 12; ++i) {
        const auto dp = ReferenceProfileCatalog::derive_session(d, fixed_secret(i));
        if (dp.fsm_dwell_scale != ref.fsm_dwell_scale) dwell_differs = true;
        if (dp.header_gap_shift_bytes != ref.header_gap_shift_bytes)
            shift_differs = true;
    }
    EXPECT_TRUE(dwell_differs);
    EXPECT_TRUE(shift_differs);
}

// ══════════════════════════════════════════════════════════════════════════════
// Step 7 (design §3.2/§3.3): built-in stateful v2 reference descriptors.
//
//   * register_reference_builtins() registers ref.quic.v1 (family QUIC) and
//     ref.webrtc.v1 (family WEBRTC) through the trusted BUILTIN path
//   * both validate with zero ERRORs, carry the {stateful-mask,
//     profile-transition-v2} capability pair and the exact FsmModel dwell /
//     transition structure of design §3.2
//   * content hashes are stable across catalogs and registrations
//   * default_capabilities() gained the two new registry strings
//   * adapter: a descriptor requiring profile-transition-v2 is refused as a
//     transition target under a v1-negotiated session (INVALID_PROFILE, no
//     state change, no control traffic) and accepted under v2
// ══════════════════════════════════════════════════════════════════════════════

TEST(ReferenceProfileReferenceBuiltins, RegisterValidateAndListByFamily) {
    ReferenceProfileCatalog cat;
    cat.register_reference_builtins();

    const ProfileDescriptor* q = cat.find(kReferenceQuicProfileId, 1);
    const ProfileDescriptor* w = cat.find(kReferenceWebrtcProfileId, 1);
    ASSERT_NE(q, nullptr) << "ref.quic.v1 not registered";
    ASSERT_NE(w, nullptr) << "ref.webrtc.v1 not registered";

    for (const ProfileDescriptor* d : {q, w}) {
        const auto issues = cat.validate_descriptor(*d);
        for (const auto& is : issues)
            EXPECT_NE(is.severity, IssueSeverity::ERROR)
                << d->profile_id << " validation error: [" << is.code << "] "
                << is.message;
        // Capability pair present; helper agrees.
        EXPECT_TRUE(descriptor_requires_profile_transition_v2(*d));
        EXPECT_EQ(d->required_capabilities.size(), 2u);
        EXPECT_NE(std::find(d->required_capabilities.begin(),
                            d->required_capabilities.end(),
                            kCapabilityStatefulMask),
                  d->required_capabilities.end());
        EXPECT_NE(std::find(d->required_capabilities.begin(),
                            d->required_capabilities.end(),
                            kCapabilityProfileTransitionV2),
                  d->required_capabilities.end());
    }

    EXPECT_EQ(q->family, ProtocolFamily::QUIC);
    EXPECT_EQ(w->family, ProtocolFamily::WEBRTC);

    const auto quic = cat.list_by_family(ProtocolFamily::QUIC);
    EXPECT_NE(std::find(quic.begin(), quic.end(), "ref.quic.v1@1"),
              quic.end());
    const auto webrtc = cat.list_by_family(ProtocolFamily::WEBRTC);
    EXPECT_NE(std::find(webrtc.begin(), webrtc.end(), "ref.webrtc.v1@1"),
              webrtc.end());
}

TEST(ReferenceProfileReferenceBuiltins, HashStableAcrossCatalogs) {
    ReferenceProfileCatalog a;
    ReferenceProfileCatalog b;
    a.register_reference_builtins();
    b.register_reference_builtins();

    for (const char* id : {kReferenceQuicProfileId,
                           kReferenceWebrtcProfileId}) {
        const ProfileDescriptor* da = a.find(id, 1);
        const ProfileDescriptor* db = b.find(id, 1);
        ASSERT_NE(da, nullptr);
        ASSERT_NE(db, nullptr);
        EXPECT_EQ(da->content_hash, db->content_hash)
            << id << " content hash not reproducible";
        // The stored hash matches a fresh canonical recomputation.
        EXPECT_EQ(da->content_hash,
                  ReferenceProfileCatalog::compute_content_hash(*da));
        EXPECT_EQ(da->content_hash.size(), 64u);
    }
}

TEST(ReferenceProfileReferenceBuiltins, FsmModelsMatchDesign) {
    ReferenceProfileCatalog cat;
    cat.register_reference_builtins();
    const ProfileDescriptor* q = cat.find(kReferenceQuicProfileId, 1);
    const ProfileDescriptor* w = cat.find(kReferenceWebrtcProfileId, 1);
    ASSERT_NE(q, nullptr);
    ASSERT_NE(w, nullptr);

    // QUIC (§3.2): bootstrap dwell 0 → handshake N(250,80) → established
    // N(2000,800) → data terminal self-loop; dominant data-phase model
    // N(450,200) clamp [64,1280] @ iat N(25,15).
    ASSERT_TRUE(q->fsm.enabled);
    EXPECT_EQ(q->fsm.initial_state, "bootstrap");
    ASSERT_EQ(q->fsm.states.size(), 4u);
    EXPECT_EQ(q->fsm.states[0].name, "bootstrap");
    EXPECT_DOUBLE_EQ(q->fsm.states[0].dwell_mean_ms, 0.0);
    EXPECT_EQ(q->fsm.states[1].name, "handshake");
    EXPECT_DOUBLE_EQ(q->fsm.states[1].dwell_mean_ms, 250.0);
    EXPECT_DOUBLE_EQ(q->fsm.states[1].dwell_stddev_ms, 80.0);
    EXPECT_EQ(q->fsm.states[2].name, "established");
    EXPECT_DOUBLE_EQ(q->fsm.states[2].dwell_mean_ms, 2000.0);
    EXPECT_DOUBLE_EQ(q->fsm.states[2].dwell_stddev_ms, 800.0);
    EXPECT_EQ(q->fsm.states[3].name, "data");
    ASSERT_EQ(q->fsm.transitions.size(), 4u);
    EXPECT_EQ(q->fsm.transitions[0].from, "bootstrap");
    EXPECT_EQ(q->fsm.transitions[0].to, "handshake");
    EXPECT_EQ(q->fsm.transitions[3].from, "data");
    EXPECT_EQ(q->fsm.transitions[3].to, "data");  // terminal self-loop
    EXPECT_DOUBLE_EQ(q->sizes.mean, 450.0);
    EXPECT_DOUBLE_EQ(q->sizes.stddev, 200.0);
    EXPECT_DOUBLE_EQ(q->sizes.clamp_min, 64.0);
    EXPECT_DOUBLE_EQ(q->sizes.clamp_max, 1280.0);
    EXPECT_DOUBLE_EQ(q->iat.mean_ms, 25.0);
    EXPECT_DOUBLE_EQ(q->iat.stddev_ms, 15.0);
    EXPECT_GE(q->mtu.max_payload_bytes, 1350u);  // fits the Initial clamp

    // WEBRTC (§3.2): handshake N(1500,400) → established N(600,200) → data
    // terminal; burst model enabled (mean 3 packets, 33 ms gap).
    ASSERT_TRUE(w->fsm.enabled);
    EXPECT_EQ(w->fsm.initial_state, "handshake");
    ASSERT_EQ(w->fsm.states.size(), 3u);
    EXPECT_EQ(w->fsm.states[0].name, "handshake");
    EXPECT_DOUBLE_EQ(w->fsm.states[0].dwell_mean_ms, 1500.0);
    EXPECT_DOUBLE_EQ(w->fsm.states[0].dwell_stddev_ms, 400.0);
    EXPECT_EQ(w->fsm.states[1].name, "established");
    EXPECT_DOUBLE_EQ(w->fsm.states[1].dwell_mean_ms, 600.0);
    EXPECT_DOUBLE_EQ(w->fsm.states[1].dwell_stddev_ms, 200.0);
    EXPECT_EQ(w->fsm.states[2].name, "data");
    EXPECT_EQ(w->fsm.transitions.size(), 3u);
    EXPECT_TRUE(w->burst.enabled);
    EXPECT_DOUBLE_EQ(w->burst.mean_burst_packets, 3.0);
    EXPECT_DOUBLE_EQ(w->burst.mean_burst_gap_ms, 33.0);
    EXPECT_DOUBLE_EQ(w->sizes.mean, 220.0);   // audio data-phase dominant
    EXPECT_DOUBLE_EQ(w->iat.mean_ms, 20.0);   // 20 ms ptime
}

TEST(ReferenceProfileCapabilities, DefaultRegistryIncludesV2Strings) {
    const auto caps = ReferenceProfileCatalog::default_capabilities();
    EXPECT_NE(std::find(caps.begin(), caps.end(), kCapabilityStatefulMask),
              caps.end());
    EXPECT_NE(std::find(caps.begin(), caps.end(),
                        kCapabilityProfileTransitionV2),
              caps.end());
}

// ── Adapter integration: the profile-transition-v2 capability gate ──────────
//
// A descriptor carrying the "profile-transition-v2" capability is a v2-only
// transition target. Under a v1-negotiated session the adapter refuses it at
// the initiator with INVALID_PROFILE — no state change, no control traffic —
// and the same descriptor completes fine when v2 was negotiated.
namespace {

struct RefBuiltinPair {
    ReferenceProfileCatalog catalog;
    std::unique_ptr<NcpMimicrySession> cli;
    std::unique_ptr<NcpMimicrySession> srv;
    uint64_t now = 1'000'000;

    RefBuiltinPair() { catalog.register_reference_builtins(); }

    void init(bool cli_v2, bool srv_v2) {
        NcpMimicrySession::Config base;
        base.e2e_config.enable_padding = false;
        base.catalog = &catalog;
        base.stable_profile = profile_ref_from_descriptor(
            *catalog.find(kReferenceQuicProfileId, 1));
        base.stable_layout = profile_layout_from_descriptor(
            *catalog.find(kReferenceQuicProfileId, 1));
        base.stable_mimic = TrafficMimicry::MimicProfile::QUIC_SHORT_HEADER;
        base.mimic_config.profile = base.stable_mimic;
        base.mimic_config.wire_version = 3;
        base.mimic_config.enable_timing_mimicry = false;
        base.mimic_resolver = [](const ProfileRef& r)
            -> std::optional<TrafficMimicry::MimicProfile> {
            using MP = TrafficMimicry::MimicProfile;
            if (r.id == kReferenceQuicProfileId) return MP::QUIC_SHORT_HEADER;
            if (r.id == kReferenceWebrtcProfileId) return MP::STUN_MESSAGE;
            return std::nullopt;
        };
        base.transition_config.retransmit_interval_ms = 50;
        base.transition_config.max_retransmit_attempts = 6;
        base.transition_config.grace_period_ms = 1000;

        auto cc = base;
        cc.role = NcpMimicrySession::Role::Client;
        cc.advertise_profile_transition_v2 = cli_v2;
        cli.reset(new NcpMimicrySession(cc));
        auto sc = base;
        sc.role = NcpMimicrySession::Role::Server;
        sc.advertise_profile_transition_v2 = srv_v2;
        srv.reset(new NcpMimicrySession(sc));
    }

    void advance(uint64_t ms) {
        now += ms;
        cli->tick(now);
        srv->tick(now);
    }

    void pump() {
        for (int i = 0; i < 1000; ++i) {
            bool progress = false;
            while (auto o = cli->next_outbound()) {
                srv->on_datagram(o->bytes, now);
                progress = true;
            }
            while (auto o = srv->next_outbound()) {
                cli->on_datagram(o->bytes, now);
                progress = true;
            }
            if (!progress) break;
        }
    }

    bool established() {
        if (!cli->is_established()) {
            auto hs = cli->start_handshake();
            if (hs) srv->on_datagram(hs->bytes, now);
        }
        pump();
        return cli->is_established() && srv->is_established();
    }
};

} // namespace

TEST(ReferenceProfileReferenceBuiltins,
     V2CapabilityDescriptorRejectedAsTargetUnderV1Session) {
    // ── v1-negotiated session: local refusal, zero footprint ─────────────
    {
        RefBuiltinPair p;
        p.init(/*cli_v2=*/true, /*srv_v2=*/false);  // strict AND → v1 session
        ASSERT_TRUE(p.established());
        ASSERT_TRUE(p.cli->transition_capable());
        ASSERT_FALSE(p.cli->stats().transition_v2_capable);
        ASSERT_FALSE(p.srv->stats().transition_v2_capable);
        const auto c0 = p.cli->stats();
        const auto s0 = p.srv->stats();

        EXPECT_EQ(p.cli->start_profile_transition(kReferenceWebrtcProfileId, 1,
                                                  p.now),
                  TransitionError::INVALID_PROFILE)
            << "v2-capability descriptor accepted as target under v1";
        EXPECT_FALSE(p.cli->has_outbound())
            << "refusal emitted control traffic";
        p.pump();
        const auto c1 = p.cli->stats();
        const auto s1 = p.srv->stats();
        EXPECT_EQ(c1.transition_state, ProfileTransitionState::IDLE);
        EXPECT_EQ(c1.profile_epoch, 0u);
        EXPECT_EQ(c1.transition_counters.transitions_started,
                  c0.transition_counters.transitions_started);
        EXPECT_EQ(s1.transition_counters.control_rx,
                  s0.transition_counters.control_rx);
        EXPECT_EQ(c1.active_mimic,
                  TrafficMimicry::MimicProfile::QUIC_SHORT_HEADER);
    }

    // ── v2-negotiated session: the same descriptor is a valid target ──────
    {
        RefBuiltinPair p;
        p.init(true, true);
        ASSERT_TRUE(p.established());
        ASSERT_TRUE(p.cli->stats().transition_v2_capable);
        ASSERT_EQ(p.cli->start_profile_transition(kReferenceWebrtcProfileId, 1,
                                                  p.now),
                  TransitionError::NONE);
        p.pump();
        p.advance(2000);
        p.pump();
        EXPECT_EQ(p.cli->stats().transition_counters.transitions_effective, 1u);
        EXPECT_EQ(p.srv->stats().transition_counters.transitions_effective, 1u);
        EXPECT_EQ(p.cli->stats().active_mimic,
                  TrafficMimicry::MimicProfile::STUN_MESSAGE);
        EXPECT_EQ(p.cli->stats().active_profile.id, kReferenceWebrtcProfileId);
        // The target's FSM engages on both endpoints (state parked at the
        // model's initial state "handshake").
        EXPECT_TRUE(p.cli->stats().fsm_engaged);
        EXPECT_EQ(p.cli->stats().fsm_state, "handshake");
    }
}
