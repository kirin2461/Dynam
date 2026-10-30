// ══════════════════════════════════════════════════════════════════════════════
// tests/test_cli_mimicry_flags.cpp
// Tests for the operator CLI helpers of the mimicry subsystem
// (src/cli/ncp_mimicry_cli.hpp): --mimicry-* flag parsing/validation,
// catalog construction policy, allow-list candidate restriction, autopilot
// config plumbing and the teardown stats JSON.
// ══════════════════════════════════════════════════════════════════════════════
#include <gtest/gtest.h>

#include <cstdio>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include "ncp_mimicry_cli.hpp"
#include "ncp_test_temp.hpp"

using namespace ncp;

namespace {

/// A fully valid (unsigned) external descriptor; mirrors the fixture in
/// test_mimicry_catalog_io.cpp.
ProfileDescriptor make_valid_external(const std::string& id,
                                      uint32_t revision = 1) {
    ProfileDescriptor d;
    d.schema_version = ProfileDescriptor::kSchemaVersion;
    d.profile_id = id;
    d.revision = revision;
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

    d.mtu.path_mtu_bytes = 1500;
    d.mtu.max_payload_bytes = 1400;

    d.provenance.sample_count = 100000;
    d.provenance.window_count = 500;
    CaptureProvenance a;
    a.capture_id = "cap-a";
    a.capture_hash = std::string(64, 'a');
    a.environment = "lab";
    a.session_group = "sg-1";
    a.captured_epoch = 1700000000;
    a.duration_s = 3600;
    d.provenance.captures = {a};

    ReferenceProfileCatalog::update_content_hash(d);
    return d;
}

struct TempFile {
    std::string path;
    explicit TempFile(const std::string& n) : path(ncp_test::temp_path(n)) {}
    ~TempFile() { std::remove(path.c_str()); }
};

bool save_catalog(const std::string& path,
                  const std::vector<ProfileDescriptor>& ds) {
    MimicryCatalogIo::Error err;
    return MimicryCatalogIo::save_file(path, ds, err);
}

// ── flag parsing ────────────────────────────────────────────────────────────

TEST(CliMimicryFlags, DefaultsAreEmpty) {
    ncp::cli::MimicryFlags f;
    std::string err;
    ASSERT_TRUE(ncp::cli::parse_mimicry_flags({}, f, err));
    EXPECT_FALSE(f.any_extended_set());
    EXPECT_EQ(f.switch_cooldown_ms, -1);
    EXPECT_EQ(f.min_dwell_ms, -1);
    EXPECT_EQ(f.transition_grace_ms, -1);
    EXPECT_LT(f.hysteresis_pct, 0.0);
}

TEST(CliMimicryFlags, ParsesAllKnobs) {
    const std::vector<std::string> args = {
        "--mimicry-catalog", "/tmp/cat.bin",
        "--mimicry-allowed", "webrtc_video, voip_opus",
        "--mimicry-require-signed",
        "--mimicry-auto",
        "--mimicry-switch-cooldown", "30",
        "--mimicry-min-dwell", "45",
        "--mimicry-hysteresis", "12.5",
        "--mimicry-transition-grace", "750",
        "--mimicry-stats-json", "/tmp/stats.json",
    };
    ncp::cli::MimicryFlags f;
    std::string err;
    ASSERT_TRUE(ncp::cli::parse_mimicry_flags(args, f, err)) << err;
    EXPECT_EQ(f.catalog_path, "/tmp/cat.bin");
    ASSERT_EQ(f.allowed.size(), 2u);
    EXPECT_EQ(f.allowed[0], "webrtc_video");
    EXPECT_EQ(f.allowed[1], "voip_opus");
    EXPECT_TRUE(f.require_signed);
    EXPECT_TRUE(f.auto_mode);
    EXPECT_FALSE(f.locked);
    EXPECT_EQ(f.switch_cooldown_ms, 30000);
    EXPECT_EQ(f.min_dwell_ms, 45000);
    EXPECT_DOUBLE_EQ(f.hysteresis_pct, 12.5);
    EXPECT_EQ(f.transition_grace_ms, 750);
    EXPECT_EQ(f.stats_json_path, "/tmp/stats.json");
    EXPECT_TRUE(f.any_extended_set());
}

TEST(CliMimicryFlags, AutoAndLockedConflict) {
    ncp::cli::MimicryFlags f;
    std::string err;
    EXPECT_FALSE(ncp::cli::parse_mimicry_flags(
        {"--mimicry-auto", "--mimicry-locked"}, f, err));
    EXPECT_NE(err.find("mutually exclusive"), std::string::npos);
}

TEST(CliMimicryFlags, SignedPolicyConflict) {
    ncp::cli::MimicryFlags f;
    std::string err;
    EXPECT_FALSE(ncp::cli::parse_mimicry_flags(
        {"--mimicry-require-signed", "--mimicry-allow-unsigned-dev"}, f, err));
    EXPECT_NE(err.find("mutually exclusive"), std::string::npos);
}

TEST(CliMimicryFlags, AutopilotKnobsRequireAutopilot) {
    for (const char* knob : {"--mimicry-switch-cooldown",
                             "--mimicry-min-dwell", "--mimicry-hysteresis"}) {
        ncp::cli::MimicryFlags f;
        std::string err;
        EXPECT_FALSE(ncp::cli::parse_mimicry_flags({knob, "5"}, f, err))
            << knob;
        EXPECT_NE(err.find("--mimicry-auto"), std::string::npos) << knob;
    }
    // ...but they parse fine with an autopilot mode attached.
    ncp::cli::MimicryFlags f;
    std::string err;
    EXPECT_TRUE(ncp::cli::parse_mimicry_flags(
        {"--mimicry-locked", "--mimicry-switch-cooldown", "5"}, f, err))
        << err;
    EXPECT_EQ(f.switch_cooldown_ms, 5000);
}

TEST(CliMimicryFlags, BadValuesRejected) {
    struct { const char* flag; const char* val; } bad[] = {
        {"--mimicry-switch-cooldown", "abc"},
        {"--mimicry-switch-cooldown", "999999"},
        {"--mimicry-min-dwell", "-5"},
        {"--mimicry-hysteresis", "-1"},
        {"--mimicry-hysteresis", "1e99"},
        {"--mimicry-transition-grace", "700000"},
        {"--mimicry-transition-grace", "10ms"},
    };
    for (const auto& b : bad) {
        ncp::cli::MimicryFlags f;
        std::string err;
        // give the autopilot knobs a mode so only the value check can fail
        std::vector<std::string> args = {"--mimicry-auto", b.flag, b.val};
        EXPECT_FALSE(ncp::cli::parse_mimicry_flags(args, f, err))
            << b.flag << "=" << b.val;
        EXPECT_NE(err.find(b.flag), std::string::npos) << b.flag;
    }
}

TEST(CliMimicryFlags, EmptyAllowedListRejected) {
    ncp::cli::MimicryFlags f;
    std::string err;
    EXPECT_FALSE(ncp::cli::parse_mimicry_flags(
        {"--mimicry-allowed", " , ,"}, f, err));
}

// ── allow-list ──────────────────────────────────────────────────────────────

TEST(CliMimicryAllowed, EmptyListAllowsEverything) {
    ncp::cli::MimicryFlags f;
    EXPECT_TRUE(ncp::cli::allowed_contains(f, "anything"));
}

TEST(CliMimicryAllowed, Membership) {
    ncp::cli::MimicryFlags f;
    std::string err;
    ASSERT_TRUE(ncp::cli::parse_mimicry_flags(
        {"--mimicry-allowed", "a,b,c"}, f, err));
    EXPECT_TRUE(ncp::cli::allowed_contains(f, "b"));
    EXPECT_FALSE(ncp::cli::allowed_contains(f, "z"));
}

TEST(CliMimicryAllowed, AutopilotExcludesOffListProfiles) {
    ReferenceProfileCatalog catalog;
    catalog.register_legacy_builtins();  // 4 built-in profiles
    const auto excl = ncp::cli::autopilot_excludes_for_allowed(
        catalog, {"voip_opus"});
    // every built-in except voip_opus is excluded
    EXPECT_EQ(excl.size(), catalog.list().size() - 1);
    bool has_voip = false;
    for (const auto& e : excl)
        if (e == "voip_opus") has_voip = true;
    EXPECT_FALSE(has_voip);
    // no allow-list => no exclusions
    EXPECT_TRUE(ncp::cli::autopilot_excludes_for_allowed(catalog, {}).empty());
}

// ── catalog construction ────────────────────────────────────────────────────

TEST(CliMimicryCatalog, BuiltinsOnlyByDefault) {
    ncp::cli::MimicryFlags f;
    std::string err;
    std::vector<std::string> warnings;
    auto cat = ncp::cli::build_catalog(f, err, warnings);
    ASSERT_TRUE(cat != nullptr) << err;
    EXPECT_TRUE(warnings.empty());
    EXPECT_NE(cat->find_latest("voip_opus"), nullptr);
}

TEST(CliMimicryCatalog, MissingFileIsAClearError) {
    ncp::cli::MimicryFlags f;
    f.catalog_path = "/nonexistent/never-there.ncpmcat";
    std::string err;
    std::vector<std::string> warnings;
    auto cat = ncp::cli::build_catalog(f, err, warnings);
    EXPECT_FALSE(cat);
    EXPECT_NE(err.find("/nonexistent/never-there.ncpmcat"),
              std::string::npos);
}

TEST(CliMimicryCatalog, UnsignedExternalRejectedUnderEnforce) {
    TempFile tf("cli_flags_unsigned_enforce.ncpmcat");
    ASSERT_TRUE(save_catalog(tf.path, {make_valid_external("lab.custom")}));

    ncp::cli::MimicryFlags f;  // default: ENFORCE
    f.catalog_path = tf.path;
    std::string err;
    std::vector<std::string> warnings;
    auto cat = ncp::cli::build_catalog(f, err, warnings);
    EXPECT_FALSE(cat);
    EXPECT_NE(err.find(tf.path), std::string::npos);
}

TEST(CliMimicryCatalog, UnsignedExternalAcceptedUnderDevUnsigned) {
    TempFile tf("cli_flags_unsigned_dev.ncpmcat");
    ASSERT_TRUE(save_catalog(tf.path, {make_valid_external("lab.custom")}));

    ncp::cli::MimicryFlags f;
    f.catalog_path = tf.path;
    f.allow_unsigned_dev = true;
    std::string err;
    std::vector<std::string> warnings;
    auto cat = ncp::cli::build_catalog(f, err, warnings);
    ASSERT_TRUE(cat != nullptr) << err;
    EXPECT_NE(cat->find_latest("lab.custom"), nullptr);
    ASSERT_FALSE(warnings.empty());
    EXPECT_NE(warnings.front().find("DEV_UNSIGNED"), std::string::npos);
}

TEST(CliMimicryCatalog, SignedExternalRejectedWithoutTrustedKey) {
    auto kp = ReferenceProfileCatalog::generate_signing_keypair();
    auto d = make_valid_external("lab.signed");
    ASSERT_TRUE(ReferenceProfileCatalog::sign_descriptor(d, "lab-key",
                                                         kp.secret_key));
    TempFile tf("cli_flags_signed.ncpmcat");
    ASSERT_TRUE(save_catalog(tf.path, {d}));

    ncp::cli::MimicryFlags f;
    f.catalog_path = tf.path;
    f.require_signed = true;
    std::string err;
    std::vector<std::string> warnings;
    auto cat = ncp::cli::build_catalog(f, err, warnings);
    // ENFORCE rejects untrusted key ids — no trusted key was registered.
    EXPECT_FALSE(cat);

    // WARN-free acceptance requires the key in the trust store; build_catalog
    // does not expose trust provisioning (by design — CLI never takes keys
    // from argv), so only DEV_UNSIGNED can accept external files from the
    // CLI today. That path is covered above.
}

// ── autopilot config plumbing ───────────────────────────────────────────────

TEST(CliMimicryAutopilotConfig, ModeAndKnobs) {
    ReferenceProfileCatalog catalog;
    catalog.register_legacy_builtins();

    ncp::cli::MimicryFlags f;
    std::string err;
    ASSERT_TRUE(ncp::cli::parse_mimicry_flags(
        {"--mimicry-auto", "--mimicry-allowed", "voip_opus",
         "--mimicry-switch-cooldown", "30", "--mimicry-min-dwell", "45",
         "--mimicry-hysteresis", "25"},
        f, err));

    bool called = false;
    auto cfg = ncp::cli::make_autopilot_config(
        f, catalog,
        [&](const std::string&, uint32_t) {
            called = true;
            return MimicryAutoPilot::TransitionResult::ACCEPTED;
        },
        3);
    EXPECT_TRUE(cfg.enabled);
    EXPECT_EQ(cfg.mode, MimicryAutoPilot::Mode::AUTO);
    EXPECT_EQ(cfg.catalog, &catalog);
    EXPECT_TRUE(static_cast<bool>(cfg.request_transition));
    EXPECT_EQ(cfg.wire_version, 3u);
    EXPECT_EQ(cfg.cooldown_ms, 30000);
    EXPECT_EQ(cfg.min_dwell_ms, 45000);
    EXPECT_DOUBLE_EQ(cfg.hysteresis_pct, 25.0);
    EXPECT_EQ(cfg.exclude_profile_ids.size(), catalog.list().size() - 1);
    (void)called;

    // LOCKED maps without the AUTO flag.
    ncp::cli::MimicryFlags lf;
    ASSERT_TRUE(ncp::cli::parse_mimicry_flags({"--mimicry-locked"}, lf, err));
    auto lcfg = ncp::cli::make_autopilot_config(
        lf, catalog,
        [](const std::string&, uint32_t) {
            return MimicryAutoPilot::TransitionResult::ACCEPTED;
        },
        3);
    EXPECT_EQ(lcfg.mode, MimicryAutoPilot::Mode::LOCKED);
    EXPECT_TRUE(lcfg.exclude_profile_ids.empty());
}

// ── stats JSON ──────────────────────────────────────────────────────────────

TEST(CliMimicryStatsJson, ContainsRequiredFields) {
    NcpMimicrySession::Stats s;
    s.established = true;
    s.transition_capable = true;
    s.active_profile.id = "voip_opus";
    s.active_profile.revision = 1;
    s.crypto_epoch = 2;
    s.profile_epoch = 3;
    s.mtu_budget_rejections = 4;
    s.transition_counters.transitions_effective = 1;
    s.transition_counters.transitions_aborted = 2;
    s.transition_counters.transitions_timed_out = 3;

    NcpConnectionDirector::Stats d;
    d.sessions_created = 1;
    d.datagrams_in = 10;
    d.datagrams_out = 11;
    d.app_messages_in = 5;
    d.app_messages_out = 5;
    d.transition_commits_reported = 1;

    const std::string json = ncp::cli::mimicry_stats_json(
        "client", {{0x1122ULL, s}}, d);
    for (const char* key : {
            "\"role\":\"client\"", "\"profile\":{\"id\":\"voip_opus\"",
            "\"pending_profile\":null", "\"transition_state\":\"IDLE\"",
            "\"crypto_epoch\":2", "\"profile_epoch\":3",
            "\"mtu_budget_rejections\":4", "\"effective\":1", "\"aborted\":2",
            "\"timed_out\":3", "\"sessions_created\":1",
            "\"transition_commits_reported\":1"}) {
        EXPECT_NE(json.find(key), std::string::npos) << key;
    }
    EXPECT_EQ(json.front(), '{');
    EXPECT_EQ(json.back(), '}');
}

TEST(CliMimicryStatsJson, AutopilotBlockEmbedded) {
    NcpConnectionDirector::Stats d;
    const std::string json = ncp::cli::mimicry_stats_json(
        "client", {}, d, "{\"mode\":\"auto\"}");
    EXPECT_NE(json.find("\"autopilot\":{\"mode\":\"auto\"}"),
              std::string::npos);
}

TEST(CliMimicryStatsJson, FileWriteRoundtrip) {
    TempFile tf("cli_flags_stats.json");
    std::string err;
    ASSERT_TRUE(ncp::cli::write_mimicry_stats_file(tf.path, "{\"ok\":true}",
                                                   err))
        << err;
    std::ifstream in(tf.path);
    std::stringstream buf;
    buf << in.rdbuf();
    EXPECT_NE(buf.str().find("{\"ok\":true}"), std::string::npos);
}

TEST(CliMimicryStatsJson, FileWriteFailureIsAnError) {
    std::string err;
    EXPECT_FALSE(ncp::cli::write_mimicry_stats_file(
        "/nonexistent-dir-xyz/stats.json", "{}", err));
    EXPECT_FALSE(err.empty());
}

} // namespace

TEST(CliMimicryFlags, V2KillSwitchParsing) {
    // Default: v2 advertised, flag not considered "set".
    {
        ncp::cli::MimicryFlags f;
        std::string err;
        ASSERT_TRUE(ncp::cli::parse_mimicry_flags({}, f, err));
        EXPECT_TRUE(f.v2);
        EXPECT_FALSE(f.v2_set);
    }
    // Explicit off: kill-switch engaged, counts as an extended flag.
    {
        ncp::cli::MimicryFlags f;
        std::string err;
        ASSERT_TRUE(ncp::cli::parse_mimicry_flags(
            {"--mimicry-v2", "off"}, f, err))
            << err;
        EXPECT_FALSE(f.v2);
        EXPECT_TRUE(f.v2_set);
        EXPECT_TRUE(f.any_extended_set());
    }
    // Explicit on: accepted, marked set.
    {
        ncp::cli::MimicryFlags f;
        std::string err;
        ASSERT_TRUE(ncp::cli::parse_mimicry_flags(
            {"--mimicry-v2", "on"}, f, err))
            << err;
        EXPECT_TRUE(f.v2);
        EXPECT_TRUE(f.v2_set);
        EXPECT_TRUE(f.any_extended_set());
    }
    // Garbage value: hard parse error naming the flag.
    {
        ncp::cli::MimicryFlags f;
        std::string err;
        EXPECT_FALSE(ncp::cli::parse_mimicry_flags(
            {"--mimicry-v2", "maybe"}, f, err));
        EXPECT_NE(err.find("--mimicry-v2"), std::string::npos);
    }
}

TEST(CliMimicryFlags, V2KillSwitchConflictWithV2OnlyTransitionTarget) {
    ncp::cli::MimicryFlags f;
    std::string err;
    std::vector<std::string> warnings;
    auto cat = ncp::cli::build_catalog(f, err, warnings);
    ASSERT_TRUE(cat != nullptr) << err;

    // The stateful reference built-ins are registered by the CLI catalog.
    const auto* v2only = cat->find(ncp::kReferenceQuicProfileId, 1);
    ASSERT_NE(v2only, nullptr);
    ASSERT_TRUE(ncp::descriptor_requires_profile_transition_v2(*v2only));
    const auto* legacy = cat->find_latest("voip_opus");
    ASSERT_NE(legacy, nullptr);
    ASSERT_FALSE(ncp::descriptor_requires_profile_transition_v2(*legacy));

    // Kill-switch off + v2-only target → hard error naming both flags.
    {
        ncp::cli::MimicryFlags off;
        off.v2 = false;
        off.v2_set = true;
        std::string e;
        EXPECT_TRUE(ncp::cli::v2_kill_switch_conflict(off, v2only, e));
        EXPECT_NE(e.find("--mimicry-v2"), std::string::npos);
        EXPECT_NE(e.find("--mimicry-transition"), std::string::npos);
        EXPECT_NE(e.find(ncp::kReferenceQuicProfileId), std::string::npos);
    }
    // Kill-switch off + legacy (v1-capable) target → no conflict.
    {
        ncp::cli::MimicryFlags off;
        off.v2 = false;
        off.v2_set = true;
        std::string e;
        EXPECT_FALSE(ncp::cli::v2_kill_switch_conflict(off, legacy, e));
        EXPECT_TRUE(e.empty());
    }
    // Kill-switch on (default) + v2-only target → allowed.
    {
        ncp::cli::MimicryFlags on;
        std::string e;
        EXPECT_FALSE(ncp::cli::v2_kill_switch_conflict(on, v2only, e));
        EXPECT_TRUE(e.empty());
    }
    // No transition target at all → no conflict.
    {
        ncp::cli::MimicryFlags off;
        off.v2 = false;
        std::string e;
        EXPECT_FALSE(ncp::cli::v2_kill_switch_conflict(off, nullptr, e));
        EXPECT_TRUE(e.empty());
    }
}

// ── load mode flag parsing (--mimicry-load-*) ───────────────────────────────

TEST(CliMimicryLoadFlags, DefaultsWhenAbsent) {
    ncp::cli::MimicryFlags f;
    std::string err;
    ASSERT_TRUE(ncp::cli::parse_mimicry_flags({}, f, err));
    EXPECT_FALSE(f.load.any_set());
    EXPECT_FALSE(f.load.enabled());
    EXPECT_FALSE(f.any_extended_set());
    EXPECT_EQ(f.load.count, 100u);
    EXPECT_EQ(f.load.size, 128u);
    EXPECT_EQ(f.load.rate, 50u);
    EXPECT_EQ(f.load.duration_sec, 0u);
    EXPECT_EQ(f.load.seed, 1u);
    EXPECT_TRUE(f.load.stats_json_path.empty());
}

TEST(CliMimicryLoadFlags, ParsesAllOptions) {
    ncp::cli::MimicryFlags f;
    std::string err;
    ASSERT_TRUE(ncp::cli::parse_mimicry_flags(
        {"--mimicry-load-count", "500", "--mimicry-load-size", "256",
         "--mimicry-load-rate", "200", "--mimicry-load-duration", "30",
         "--mimicry-load-seed", "42",
         "--mimicry-load-stats-json", "/tmp/load.json"},
        f, err))
        << err;
    EXPECT_TRUE(f.load.enabled());
    EXPECT_TRUE(f.any_extended_set());
    EXPECT_EQ(f.load.count, 500u);
    EXPECT_EQ(f.load.size, 256u);
    EXPECT_EQ(f.load.rate, 200u);
    EXPECT_EQ(f.load.duration_sec, 30u);
    EXPECT_EQ(f.load.seed, 42u);
    EXPECT_EQ(f.load.stats_json_path, "/tmp/load.json");
}

TEST(CliMimicryLoadFlags, AnySingleOptionEnablesLoad) {
    const std::vector<std::vector<std::string>> cases = {
        {"--mimicry-load-count", "10"},
        {"--mimicry-load-size", "64"},
        {"--mimicry-load-rate", "5"},
        {"--mimicry-load-duration", "0"},
        {"--mimicry-load-seed", "0"},
        {"--mimicry-load-stats-json", "/tmp/x.json"},
    };
    for (const auto& args : cases) {
        ncp::cli::MimicryFlags f;
        std::string err;
        ASSERT_TRUE(ncp::cli::parse_mimicry_flags(args, f, err))
            << args[0] << ": " << err;
        EXPECT_TRUE(f.load.enabled()) << args[0];
        EXPECT_TRUE(f.any_extended_set()) << args[0];
    }
    // Untouched knobs keep their defaults.
    ncp::cli::MimicryFlags f;
    std::string err;
    ASSERT_TRUE(ncp::cli::parse_mimicry_flags(
        {"--mimicry-load-count", "7"}, f, err));
    EXPECT_EQ(f.load.size, 128u);
    EXPECT_EQ(f.load.rate, 50u);
    EXPECT_EQ(f.load.seed, 1u);
}

TEST(CliMimicryLoadFlags, BadValuesRejected) {
    const std::vector<std::pair<std::string, std::string>> bad = {
        {"--mimicry-load-count", "0"},          // below min
        {"--mimicry-load-count", "100001"},     // memory bound
        {"--mimicry-load-count", "abc"},
        {"--mimicry-load-size", "11"},          // smaller than the header
        {"--mimicry-load-size", "1025"},        // over the datagram budget
        {"--mimicry-load-size", "-1"},
        {"--mimicry-load-rate", "0"},
        {"--mimicry-load-rate", "100001"},
        {"--mimicry-load-duration", "3601"},
        {"--mimicry-load-duration", "10s"},
        {"--mimicry-load-seed", "xyz"},
        {"--mimicry-load-seed", ""},            // missing value
        {"--mimicry-load-stats-json", ""},      // missing path (fail closed)
    };
    for (const auto& b : bad) {
        ncp::cli::MimicryFlags f;
        std::string err;
        EXPECT_FALSE(ncp::cli::parse_mimicry_flags({b.first, b.second}, f, err))
            << b.first << "=" << b.second;
        EXPECT_NE(err.find(b.first), std::string::npos) << b.first;
    }
}

TEST(CliMimicryLoadFlags, BoundaryValuesAccepted) {
    ncp::cli::MimicryFlags f;
    std::string err;
    ASSERT_TRUE(ncp::cli::parse_mimicry_flags(
        {"--mimicry-load-count", "100000", "--mimicry-load-size", "12",
         "--mimicry-load-rate", "100000", "--mimicry-load-duration", "3600",
         "--mimicry-load-seed", "18446744073709551615"},
        f, err))
        << err;
    EXPECT_EQ(f.load.count, 100000u);
    EXPECT_EQ(f.load.size, 12u);
    EXPECT_EQ(f.load.rate, 100000u);
    EXPECT_EQ(f.load.duration_sec, 3600u);
    EXPECT_EQ(f.load.seed, 0xFFFFFFFFFFFFFFFFULL);
}

// ── load message build/verify ───────────────────────────────────────────────

TEST(CliMimicryLoadMsg, RoundtripAndDeterminism) {
    std::vector<uint8_t> a, b, c;
    ncp::cli::build_load_message(7, 42, 128, a);
    ncp::cli::build_load_message(7, 42, 128, b);
    ncp::cli::build_load_message(7, 43, 128, c);
    ASSERT_EQ(a.size(), 128u);
    EXPECT_EQ(a, b);              // fully deterministic
    EXPECT_NE(a, c);              // unique per sequence
    // magic + little-endian sequence header
    EXPECT_EQ(std::memcmp(a.data(), ncp::cli::kLoadMagic, 4), 0);
    uint64_t seq = 0;
    EXPECT_TRUE(ncp::cli::verify_load_message(7, 128, a.data(), a.size(), seq));
    EXPECT_EQ(seq, 42u);
}

TEST(CliMimicryLoadMsg, MinimumSizeIsHeaderOnly) {
    std::vector<uint8_t> m;
    ncp::cli::build_load_message(1, 0, ncp::cli::kLoadHeaderSize, m);
    ASSERT_EQ(m.size(), ncp::cli::kLoadHeaderSize);
    uint64_t seq = 999;
    EXPECT_TRUE(ncp::cli::verify_load_message(1, ncp::cli::kLoadHeaderSize,
                                              m.data(), m.size(), seq));
    EXPECT_EQ(seq, 0u);
}

TEST(CliMimicryLoadMsg, VerificationRejectsTampering) {
    std::vector<uint8_t> m;
    ncp::cli::build_load_message(5, 9, 128, m);
    uint64_t seq = 0;
    // wrong seed
    EXPECT_FALSE(ncp::cli::verify_load_message(6, 128, m.data(), m.size(), seq));
    // wrong expected size
    EXPECT_FALSE(ncp::cli::verify_load_message(5, 64, m.data(), m.size(), seq));
    // truncated
    EXPECT_FALSE(ncp::cli::verify_load_message(5, 128, m.data(), 100, seq));
    // flipped payload byte
    auto t = m;
    t[20] ^= 0x01;
    EXPECT_FALSE(ncp::cli::verify_load_message(5, 128, t.data(), t.size(), seq));
    // flipped magic
    t = m;
    t[0] ^= 0xFF;
    EXPECT_FALSE(ncp::cli::verify_load_message(5, 128, t.data(), t.size(), seq));
    // flipped sequence byte (pattern no longer matches the header seq)
    t = m;
    t[5] ^= 0x01;
    EXPECT_FALSE(ncp::cli::verify_load_message(5, 128, t.data(), t.size(), seq));
}

// ── streaming SHA-256 ───────────────────────────────────────────────────────

TEST(CliMimicryLoadSha256, KnownVectors) {
    ncp::cli::Sha256Stream empty;
    EXPECT_EQ(empty.hex(),
              "e3b0c44298fc1c149afbf4c8996fb924"
              "27ae41e4649b934ca495991b7852b855");
    ncp::cli::Sha256Stream abc;
    const std::string s = "abc";
    abc.update(reinterpret_cast<const uint8_t*>(s.data()), s.size());
    EXPECT_EQ(abc.hex(),
              "ba7816bf8f01cfea414140de5dae22"
              "23b00361a396177a9cb410ff61f20015ad");
    // Same result when fed byte-by-byte (streaming path) — 56-byte padding
    // edge included via a longer message.
    std::string long_msg(1000, 'x');
    ncp::cli::Sha256Stream one, two;
    one.update(reinterpret_cast<const uint8_t*>(long_msg.data()),
               long_msg.size());
    for (char ch : long_msg) {
        const uint8_t b = static_cast<uint8_t>(ch);
        two.update(&b, 1);
    }
    EXPECT_EQ(one.hex(), two.hex());
    // final() is non-destructive.
    EXPECT_EQ(abc.hex(),
              "ba7816bf8f01cfea414140de5dae22"
              "23b00361a396177a9cb410ff61f20015ad");
}

// ── load tracker metrics ────────────────────────────────────────────────────

namespace {

class LoadRun {
public:
    LoadRun(uint64_t seed, uint64_t size, uint64_t count)
        : tracker(seed, size, count), seed_(seed), size_(size) {}
    void send(uint64_t seq) {
        ncp::cli::build_load_message(seed_, seq, size_, msg_);
        tracker.note_sent(seq, msg_, seq * 10);  // 10 ms apart
    }
    void send_all(uint64_t n) { for (uint64_t i = 0; i < n; ++i) send(i); }
    void receive(uint64_t seq) {
        ncp::cli::build_load_message(seed_, seq, size_, msg_);
        tracker.note_received(msg_.data(), msg_.size(), seq * 10 + 3);
    }
    ncp::cli::MimicryLoadTracker tracker;
private:
    uint64_t seed_;
    uint64_t size_;
    std::vector<uint8_t> msg_;
};

} // namespace

TEST(CliMimicryLoadTracker, CleanRunPasses) {
    LoadRun r(1, 128, 10);
    r.send_all(10);
    for (uint64_t i = 0; i < 10; ++i) r.receive(i);
    const auto m = r.tracker.finalize(10, 10, 1000);
    EXPECT_TRUE(m.passed);
    EXPECT_EQ(m.sent, 10u);
    EXPECT_EQ(m.received_unique, 10u);
    EXPECT_EQ(m.missing, 0u);
    EXPECT_EQ(m.corrupted, 0u);
    EXPECT_EQ(m.sha256_sent, m.sha256_received_unique);
    ASSERT_TRUE(m.has_rtt);
    EXPECT_DOUBLE_EQ(m.rtt_p50_ms, 3.0);
    EXPECT_DOUBLE_EQ(m.offered_goodput_bps, 10 * 128 * 8.0);      // over 1 s
    EXPECT_DOUBLE_EQ(m.verified_goodput_bps, m.offered_goodput_bps);
}

TEST(CliMimicryLoadTracker, ReorderDoesNotBreakCanonicalHash) {
    LoadRun r(1, 128, 5);
    r.send_all(5);
    // receive fully reversed: 4,3,2,1,0 — every lower one is out-of-order
    for (uint64_t i = 0; i < 5; ++i) r.receive(4 - i);
    const auto m = r.tracker.finalize(5, 5, 100);
    EXPECT_EQ(m.out_of_order, 4u);
    EXPECT_EQ(m.duplicates, 0u);
    EXPECT_EQ(m.sha256_sent, m.sha256_received_unique);
    EXPECT_TRUE(m.passed);  // reorder alone must not fail the run
}

TEST(CliMimicryLoadTracker, DuplicatesCountedButPassedUnaffected) {
    LoadRun r(1, 128, 3);
    r.send_all(3);
    for (uint64_t i = 0; i < 3; ++i) r.receive(i);
    r.receive(1);  // duplicate echo
    const auto m = r.tracker.finalize(3, 3, 100);
    EXPECT_EQ(m.duplicates, 1u);
    EXPECT_EQ(m.received_unique, 3u);
    EXPECT_TRUE(m.passed);
}

TEST(CliMimicryLoadTracker, CorruptionFails) {
    LoadRun r(1, 128, 3);
    r.send_all(3);
    r.receive(0);
    r.receive(2);
    std::vector<uint8_t> bad;
    ncp::cli::build_load_message(1, 1, 128, bad);
    bad[20] ^= 0x80;  // tampered echo for seq 1
    r.tracker.note_received(bad.data(), bad.size(), 13);
    const auto m = r.tracker.finalize(3, 3, 100);
    EXPECT_EQ(m.corrupted, 1u);
    EXPECT_EQ(m.missing, 1u);  // seq 1 never verified
    EXPECT_FALSE(m.passed);
}

TEST(CliMimicryLoadTracker, MissingFailsAndHashDiffers) {
    LoadRun r(1, 128, 4);
    r.send_all(4);
    r.receive(0);
    r.receive(1);
    r.receive(3);  // seq 2 lost
    const auto m = r.tracker.finalize(4, 4, 100);
    EXPECT_EQ(m.missing, 1u);
    EXPECT_NE(m.sha256_sent, m.sha256_received_unique);
    EXPECT_FALSE(m.passed);
}

TEST(CliMimicryLoadTracker, SendErrorFails) {
    LoadRun r(1, 128, 3);
    r.send(0);
    r.tracker.note_send_error();  // seq 1 never accepted
    r.send(2);
    r.receive(0);
    r.receive(2);
    const auto m = r.tracker.finalize(3, 3, 100);
    EXPECT_EQ(m.send_errors, 1u);
    EXPECT_EQ(m.sent, 2u);
    EXPECT_FALSE(m.passed);  // sent != attempted
}

TEST(CliMimicryLoadTracker, DurationCutStillPasses) {
    // Operator asked for 100 but the duration cap stopped us at 3: that is
    // a complete, honest run of 3 messages.
    LoadRun r(1, 128, 100);
    r.send_all(3);
    for (uint64_t i = 0; i < 3; ++i) r.receive(i);
    const auto m = r.tracker.finalize(100, 3, 100);
    EXPECT_EQ(m.requested, 100u);
    EXPECT_EQ(m.attempted, 3u);
    EXPECT_TRUE(m.passed);
}

TEST(CliMimicryLoadTracker, NothingSentDoesNotPass) {
    LoadRun r(1, 128, 10);
    const auto m = r.tracker.finalize(10, 0, 5);
    EXPECT_EQ(m.attempted, 0u);
    EXPECT_FALSE(m.passed);  // vacuous run is not a PASS
}

TEST(CliMimicryLoadTracker, NeverSentSequenceIsCorrupted) {
    LoadRun r(1, 128, 3);
    r.send_all(2);
    r.receive(0);
    r.receive(1);
    r.receive(2);  // we never sent seq 2
    const auto m = r.tracker.finalize(3, 2, 100);
    EXPECT_EQ(m.corrupted, 1u);
    EXPECT_FALSE(m.passed);
}

TEST(CliMimicryLoadTracker, AutoPilotMetricsUseMaturedLossAndRtt) {
    LoadRun r(1, 128, 4);
    r.send_all(4);
    r.receive(0);
    r.receive(1);
    r.receive(3);  // seq 2 is genuinely missing after the settle window
    ncp::MimicryAutoPilot::UdpMetrics sample;
    ASSERT_TRUE(r.tracker.autopilot_metrics(1000, 750, sample));
    EXPECT_EQ(sample.packets, 4u);
    EXPECT_DOUBLE_EQ(sample.loss_ratio, 0.25);
    EXPECT_DOUBLE_EQ(sample.rtt_ms, 3.0);
    EXPECT_DOUBLE_EQ(sample.throughput_bps, 3 * 128 * 8.0);
    const auto first = sample;
    ASSERT_TRUE(r.tracker.autopilot_metrics(1000, 750, sample));
    EXPECT_EQ(sample.packets, first.packets);
    EXPECT_DOUBLE_EQ(sample.loss_ratio, first.loss_ratio);
}

TEST(CliMimicryLoadTracker, AutoPilotMetricsIgnoreRecentOutstandingSends) {
    ncp::cli::MimicryLoadTracker tracker(1, 128, 2);
    std::vector<uint8_t> msg;
    ncp::cli::build_load_message(1, 0, 128, msg);
    tracker.note_sent(0, msg, 900);
    ncp::cli::build_load_message(1, 1, 128, msg);
    tracker.note_sent(1, msg, 990);
    ncp::MimicryAutoPilot::UdpMetrics sample;
    EXPECT_FALSE(tracker.autopilot_metrics(1000, 750, sample));
    tracker.note_received(msg.data(), msg.size(), 1001);
    EXPECT_FALSE(tracker.autopilot_metrics(1001, 750, sample));
}

// ── load stats JSON ─────────────────────────────────────────────────────────

TEST(CliMimicryLoadStatsJson, SchemaAndFields) {
    LoadRun r(9, 128, 4);
    r.send_all(4);
    for (uint64_t i = 0; i < 4; ++i) r.receive(i);
    const auto m = r.tracker.finalize(4, 4, 200);
    ncp::cli::MimicryLoadFlags cfg;
    cfg.seed = 9;
    const std::string json = ncp::cli::mimicry_load_stats_json(m, cfg);
    for (const std::string& key : std::vector<std::string>{
            "\"schema_version\":1", "\"type\":\"porthop_mimicry_load\"",
            "\"seed\":9", "\"requested\":4", "\"attempted\":4", "\"sent\":4",
            "\"send_errors\":0", "\"received_unique\":4", "\"duplicates\":0",
            "\"out_of_order\":0", "\"corrupted\":0", "\"missing\":0",
            "\"elapsed_ms\":200", "\"offered_goodput_bps\":",
            "\"verified_goodput_bps\":", "\"rtt_ms\":{\"p50\":",
            "\"sha256_sent\":\"" + m.sha256_sent,
            "\"sha256_received_unique\":\"" + m.sha256_received_unique,
            "\"passed\":true"}) {
        EXPECT_NE(json.find(key), std::string::npos) << key;
    }
    EXPECT_EQ(json.front(), '{');
    EXPECT_EQ(json.back(), '}');
}

TEST(CliMimicryLoadStatsJson, NoRttSamplesIsNull) {
    LoadRun r(1, 128, 2);
    r.send_all(2);  // nothing received
    const auto m = r.tracker.finalize(2, 2, 100);
    ncp::cli::MimicryLoadFlags cfg;
    const std::string json = ncp::cli::mimicry_load_stats_json(m, cfg);
    EXPECT_NE(json.find("\"rtt_ms\":null"), std::string::npos);
    EXPECT_NE(json.find("\"passed\":false"), std::string::npos);
}

TEST(CliMimicryLoadStatsJson, AtomicFileWrite) {
    LoadRun r(1, 128, 2);
    r.send_all(2);
    r.receive(0);
    r.receive(1);
    const auto m = r.tracker.finalize(2, 2, 100);
    ncp::cli::MimicryLoadFlags cfg;
    const std::string json = ncp::cli::mimicry_load_stats_json(m, cfg);
    TempFile tf("cli_load_stats.json");
    std::string err;
    ASSERT_TRUE(ncp::cli::write_mimicry_stats_file(tf.path, json, err)) << err;
    std::ifstream in(tf.path);
    std::stringstream buf;
    buf << in.rdbuf();
    EXPECT_NE(buf.str().find("\"schema_version\":1"), std::string::npos);
    EXPECT_NE(buf.str().find("\"passed\":true"), std::string::npos);
}
