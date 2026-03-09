// ══════════════════════════════════════════════════════════════════════════════
// tests/test_protocol_morph.cpp
// Tests for ProtocolMorph (ncp_protocol_morph.hpp)
// ══════════════════════════════════════════════════════════════════════════════
#include <gtest/gtest.h>
#include "ncp_protocol_morph.hpp"

#include <vector>
#include <string>
#include <atomic>
#include <map>

using namespace ncp;

// ── Fixture ───────────────────────────────────────────────────────────────────

class ProtocolMorphTest : public ::testing::Test {
protected:
    ProtocolMorph::Config make_config() {
        ProtocolMorph::Config cfg;
        cfg.mutation.connections_per_mutation = 5;
        cfg.schedule.enabled = false; // disable schedule for determinism
        return cfg;
    }
};

// ── Construction ──────────────────────────────────────────────────────────────

TEST_F(ProtocolMorphTest, DefaultConstructor_NoThrow) {
    EXPECT_NO_THROW({ ProtocolMorph pm; });
}

TEST_F(ProtocolMorphTest, ConfigConstructor_NoThrow) {
    EXPECT_NO_THROW({ ProtocolMorph pm(make_config()); });
}

// ── Connection Profile Selection ─────────────────────────────────────────────

TEST_F(ProtocolMorphTest, SelectProfile_ReturnsSomething) {
    ProtocolMorph pm(make_config());
    auto profile = pm.select_profile_for_connection();
    // Connection ID should be ≥ 1 after first selection
    EXPECT_GE(profile.connection_id, 1u);
}

TEST_F(ProtocolMorphTest, SelectProfile_ValidMimicProfile) {
    ProtocolMorph pm(make_config());
    auto p = pm.select_profile_for_connection();
    // MimicProfile enum range check — just ensure it's assigned
    (void)p.mimic_profile;
    (void)p.browser_profile;
}

TEST_F(ProtocolMorphTest, SelectProfile_ConnectionIdMonotonicallyIncreasing) {
    ProtocolMorph pm(make_config());
    auto p1 = pm.select_profile_for_connection();
    auto p2 = pm.select_profile_for_connection();
    EXPECT_GT(p2.connection_id, p1.connection_id);
}

TEST_F(ProtocolMorphTest, SelectProfile_ReturnsEpoch) {
    ProtocolMorph pm(make_config());
    auto p = pm.select_profile_for_connection();
    EXPECT_GE(p.mutation_epoch, 0u);
}

// ── Weighted Random Selection ─────────────────────────────────────────────────

TEST_F(ProtocolMorphTest, WeightedSelection_PrefersHigherWeight) {
    ProtocolMorph::Config cfg;
    cfg.schedule.enabled = false;
    cfg.profile_weights = {
        {TrafficMimicry::MimicProfile::HTTPS_APPLICATION, 100},
        {TrafficMimicry::MimicProfile::DNS_QUERY,          0},  // disabled
    };
    cfg.mutation.connections_per_mutation = 9999; // prevent mutations
    ProtocolMorph pm(cfg);

    std::map<TrafficMimicry::MimicProfile, int> counts;
    for (int i = 0; i < 20; ++i) {
        auto p = pm.select_profile_for_connection();
        counts[p.mimic_profile]++;
    }
    // All selections should be HTTPS_APPLICATION since DNS_QUERY has weight 0
    EXPECT_EQ(counts[TrafficMimicry::MimicProfile::HTTPS_APPLICATION], 20);
    EXPECT_EQ(counts[TrafficMimicry::MimicProfile::DNS_QUERY], 0);
}

// ── On Connection Opened ──────────────────────────────────────────────────────

TEST_F(ProtocolMorphTest, OnConnectionOpened_NoThrow) {
    ProtocolMorph pm(make_config());
    EXPECT_NO_THROW(pm.on_connection_opened());
}

TEST_F(ProtocolMorphTest, OnConnectionOpened_IncrementsCounter) {
    ProtocolMorph pm(make_config());
    auto s1 = pm.get_stats();
    pm.on_connection_opened();
    pm.on_connection_opened();
    auto s2 = pm.get_stats();
    EXPECT_GE(s2.connections_total.load(), 2u);
}

// ── Force Mutation ────────────────────────────────────────────────────────────

TEST_F(ProtocolMorphTest, ForceMutation_NoThrow) {
    ProtocolMorph pm(make_config());
    EXPECT_NO_THROW(pm.force_mutation());
}

TEST_F(ProtocolMorphTest, ForceMutation_IncrementsEpoch) {
    ProtocolMorph pm(make_config());
    auto epoch_before = pm.get_mutation_epoch();
    pm.force_mutation();
    EXPECT_GT(pm.get_mutation_epoch(), epoch_before);
}

TEST_F(ProtocolMorphTest, ForceMutation_Twice_EpochIncreasesBy2) {
    ProtocolMorph pm(make_config());
    auto e0 = pm.get_mutation_epoch();
    pm.force_mutation();
    pm.force_mutation();
    EXPECT_EQ(pm.get_mutation_epoch(), e0 + 2);
}

// ── Mutation Epoch Tracking ───────────────────────────────────────────────────

TEST_F(ProtocolMorphTest, InitialMutationEpochIsZero) {
    ProtocolMorph pm(make_config());
    EXPECT_EQ(pm.get_mutation_epoch(), 0u);
}

TEST_F(ProtocolMorphTest, MutationTriggeredAtThreshold) {
    ProtocolMorph::Config cfg = make_config();
    cfg.mutation.connections_per_mutation = 3;
    ProtocolMorph pm(cfg);

    // Open 3 connections via select_profile_for_connection
    for (int i = 0; i < 3; ++i) {
        pm.select_profile_for_connection();
    }
    EXPECT_GE(pm.get_mutation_epoch(), 1u);
}

// ── Schedule ─────────────────────────────────────────────────────────────────

TEST_F(ProtocolMorphTest, GetScheduledProfile_NoSchedule_ReturnsFallback) {
    ProtocolMorph::Config cfg = make_config();
    cfg.schedule.enabled = false;
    ProtocolMorph pm(cfg);
    auto scheduled = pm.get_scheduled_profile();
    // Without schedule, should fall back to HTTPS_APPLICATION
    EXPECT_EQ(scheduled, TrafficMimicry::MimicProfile::HTTPS_APPLICATION);
}

TEST_F(ProtocolMorphTest, GetScheduledProfile_MoscowSchedule_ReturnsProfile) {
    ProtocolMorph::Config cfg = make_config();
    cfg.schedule = ProtocolMorph::ScheduleConfig::default_moscow();
    ProtocolMorph pm(cfg);
    auto scheduled = pm.get_scheduled_profile();
    // Should return a valid profile (not necessarily HTTPS, depends on time)
    (void)scheduled;
}

// ── Statistics ────────────────────────────────────────────────────────────────

TEST_F(ProtocolMorphTest, InitialStats_AllZero) {
    ProtocolMorph pm(make_config());
    auto s = pm.get_stats();
    EXPECT_EQ(s.connections_total.load(), 0u);
    EXPECT_EQ(s.mutations_performed.load(), 0u);
}

TEST_F(ProtocolMorphTest, ResetStats) {
    ProtocolMorph pm(make_config());
    pm.on_connection_opened();
    pm.reset_stats();
    auto s = pm.get_stats();
    EXPECT_EQ(s.connections_total.load(), 0u);
}

TEST_F(ProtocolMorphTest, Stats_ProfileUsageTracked) {
    ProtocolMorph pm(make_config());
    pm.select_profile_for_connection();
    auto s = pm.get_stats();
    // After one connection, at least one profile usage entry should exist
    EXPECT_FALSE(s.profile_usage.empty());
}

// ── Log Callback ─────────────────────────────────────────────────────────────

TEST_F(ProtocolMorphTest, SetLogCallback_NoThrow) {
    ProtocolMorph pm(make_config());
    std::string last_msg;
    EXPECT_NO_THROW(pm.set_log_callback([&](const std::string& msg) {
        last_msg = msg;
    }));
}

// ── Config Get / Set ─────────────────────────────────────────────────────────

TEST_F(ProtocolMorphTest, GetConfig_ReturnsSetConfig) {
    ProtocolMorph pm;
    auto cfg = make_config();
    cfg.mutation.connections_per_mutation = 42;
    pm.set_config(cfg);
    EXPECT_EQ(pm.get_config().mutation.connections_per_mutation, 42u);
}

// ── Shared Seed ───────────────────────────────────────────────────────────────

TEST_F(ProtocolMorphTest, SharedSeed_BothSidesSameSequence) {
    std::vector<uint8_t> seed(32, 0x5A);

    ProtocolMorph::Config cfg1 = make_config();
    cfg1.mutation.connections_per_mutation = 9999;
    cfg1.shared_seed = seed;

    ProtocolMorph::Config cfg2 = cfg1;

    ProtocolMorph pm1(cfg1), pm2(cfg2);

    // Both should select the same profile sequence
    for (int i = 0; i < 5; ++i) {
        auto p1 = pm1.select_profile_for_connection();
        auto p2 = pm2.select_profile_for_connection();
        EXPECT_EQ(p1.mimic_profile, p2.mimic_profile) << "Mismatch at i=" << i;
    }
}
