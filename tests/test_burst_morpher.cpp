// ══════════════════════════════════════════════════════════════════════════════
// tests/test_burst_morpher.cpp
// Tests for BurstMorpher, PerturbationCache, BurstTracker (ncp_burst_morpher.hpp)
// ══════════════════════════════════════════════════════════════════════════════
#include <gtest/gtest.h>
#include "ncp_burst_morpher.hpp"

#include <vector>
#include <cstring>
#include <numeric>
#include <thread>
#include <chrono>

using namespace ncp::DPI;

// ══════════════════════════════════════════════════════════════════════════════
// BurstProfile
// ══════════════════════════════════════════════════════════════════════════════

TEST(BurstProfileTest, ComputeHash_Deterministic) {
    BurstProfile p{};
    p.packet_count = 10;
    p.mean_size    = 512.0;
    p.mean_iat_us  = 1000.0;

    auto h1 = p.compute_hash();
    auto h2 = p.compute_hash();
    EXPECT_EQ(h1, h2);
}

TEST(BurstProfileTest, ComputeHash_DiffersForDifferentProfiles) {
    BurstProfile a{}, b{};
    a.packet_count = 5;  a.mean_size = 100.0;
    b.packet_count = 50; b.mean_size = 1200.0;
    EXPECT_NE(a.compute_hash(), b.compute_hash());
}

TEST(BurstProfileTest, Similarity_SelfIsPerfect) {
    BurstProfile p{};
    p.packet_count = 10;
    p.outbound_ratio = 0.7;
    p.mean_size  = 600.0;
    p.mean_iat_us = 500.0;

    double sim = p.similarity(p);
    EXPECT_NEAR(sim, 1.0, 0.001);
}

TEST(BurstProfileTest, Similarity_InRange) {
    BurstProfile a{}, b{};
    a.mean_size = 100; b.mean_size = 1400;
    a.outbound_ratio = 0.2; b.outbound_ratio = 0.9;
    double sim = a.similarity(b);
    EXPECT_GE(sim, 0.0);
    EXPECT_LE(sim, 1.0);
}

// ══════════════════════════════════════════════════════════════════════════════
// TargetProfile Presets
// ══════════════════════════════════════════════════════════════════════════════

TEST(TargetProfileTest, YouTube_FieldsPopulated) {
    auto p = TargetProfile::youtube();
    EXPECT_EQ(p.type, TargetTrafficType::YOUTUBE_STREAM);
    EXPECT_FALSE(p.name.empty());
    EXPECT_GT(p.target_entropy, 0.0);
}

TEST(TargetProfileTest, Netflix_FieldsPopulated) {
    auto p = TargetProfile::netflix();
    EXPECT_EQ(p.type, TargetTrafficType::NETFLIX_STREAM);
    EXPECT_FALSE(p.name.empty());
}

TEST(TargetProfileTest, Zoom_FieldsPopulated) {
    auto p = TargetProfile::zoom();
    EXPECT_EQ(p.type, TargetTrafficType::ZOOM_VIDEO);
    EXPECT_FALSE(p.name.empty());
}

TEST(TargetProfileTest, HttpBrowsing_FieldsPopulated) {
    auto p = TargetProfile::http_browsing();
    EXPECT_EQ(p.type, TargetTrafficType::HTTP_BROWSING);
}

TEST(TargetProfileTest, QuicWeb_FieldsPopulated) {
    auto p = TargetProfile::quic_web();
    EXPECT_EQ(p.type, TargetTrafficType::QUIC_WEB);
}

TEST(TargetProfileTest, TargetTypeToString_AllTypes) {
    EXPECT_STRNE(target_type_to_string(TargetTrafficType::YOUTUBE_STREAM), "");
    EXPECT_STRNE(target_type_to_string(TargetTrafficType::NETFLIX_STREAM), "");
    EXPECT_STRNE(target_type_to_string(TargetTrafficType::ZOOM_VIDEO),     "");
    EXPECT_STRNE(target_type_to_string(TargetTrafficType::HTTP_BROWSING),  "");
    EXPECT_STRNE(target_type_to_string(TargetTrafficType::QUIC_WEB),       "");
}

// ══════════════════════════════════════════════════════════════════════════════
// TargetProfileDB
// ══════════════════════════════════════════════════════════════════════════════

TEST(TargetProfileDBTest, LoadDefaults_ProvidesAllBuiltIns) {
    TargetProfileDB db;
    db.load_defaults();
    EXPECT_NE(db.get(TargetTrafficType::YOUTUBE_STREAM), nullptr);
    EXPECT_NE(db.get(TargetTrafficType::NETFLIX_STREAM), nullptr);
    EXPECT_NE(db.get(TargetTrafficType::ZOOM_VIDEO),     nullptr);
    EXPECT_NE(db.get(TargetTrafficType::HTTP_BROWSING),  nullptr);
    EXPECT_NE(db.get(TargetTrafficType::QUIC_WEB),       nullptr);
}

TEST(TargetProfileDBTest, AddCustomProfile) {
    TargetProfileDB db;
    TargetProfile p;
    p.type = TargetTrafficType::CUSTOM;
    p.name = "test_custom";
    db.add_profile(p);
    EXPECT_NE(db.get(TargetTrafficType::CUSTOM), nullptr);
}

TEST(TargetProfileDBTest, FindNearest_OnPopulatedDB) {
    TargetProfileDB db;
    db.load_defaults();

    BurstProfile burst{};
    burst.mean_size = 1400;
    burst.outbound_ratio = 0.05; // mostly downstream → streaming
    const TargetProfile* nearest = db.find_nearest(burst);
    EXPECT_NE(nearest, nullptr);
}

TEST(TargetProfileDBTest, FindNearest_EmptyDBReturnsNull) {
    TargetProfileDB db;
    BurstProfile burst{};
    EXPECT_EQ(db.find_nearest(burst), nullptr);
}

// ══════════════════════════════════════════════════════════════════════════════
// PerturbationCache
// ══════════════════════════════════════════════════════════════════════════════

TEST(PerturbationCacheTest, InsertAndLookup) {
    PerturbationCache cache(100);

    PerturbationEntry entry;
    entry.pre_padding = {0xDE, 0xAD, 0xBE, 0xEF};
    entry.evasion_score = 0.8;
    entry.target_type = TargetTrafficType::YOUTUBE_STREAM;

    cache.insert(0x12345678ABCDEF01ULL, TargetTrafficType::YOUTUBE_STREAM, entry);

    const auto* found = cache.lookup(0x12345678ABCDEF01ULL, TargetTrafficType::YOUTUBE_STREAM);
    ASSERT_NE(found, nullptr);
    EXPECT_EQ(found->pre_padding, entry.pre_padding);
}

TEST(PerturbationCacheTest, LookupMissReturnsNull) {
    PerturbationCache cache;
    EXPECT_EQ(cache.lookup(0xDEADBEEFULL, TargetTrafficType::NETFLIX_STREAM), nullptr);
}

TEST(PerturbationCacheTest, CacheSize) {
    PerturbationCache cache;
    EXPECT_EQ(cache.size(), 0u);
    PerturbationEntry e;
    cache.insert(1, TargetTrafficType::YOUTUBE_STREAM, e);
    EXPECT_EQ(cache.size(), 1u);
}

TEST(PerturbationCacheTest, Clear) {
    PerturbationCache cache;
    PerturbationEntry e;
    cache.insert(1, TargetTrafficType::YOUTUBE_STREAM, e);
    cache.clear();
    EXPECT_EQ(cache.size(), 0u);
}

TEST(PerturbationCacheTest, LRU_EvictsOldestOnOverflow) {
    PerturbationCache cache(3); // max 3 entries
    PerturbationEntry e;
    cache.insert(1, TargetTrafficType::YOUTUBE_STREAM, e);
    cache.insert(2, TargetTrafficType::NETFLIX_STREAM, e);
    cache.insert(3, TargetTrafficType::ZOOM_VIDEO,     e);
    cache.insert(4, TargetTrafficType::HTTP_BROWSING,  e); // evicts LRU
    EXPECT_EQ(cache.size(), 3u);
}

TEST(PerturbationCacheTest, SerializeDeserialize_Roundtrip) {
    PerturbationCache cache;
    PerturbationEntry e;
    e.pre_padding = {0xAA, 0xBB};
    e.evasion_score = 0.5;
    e.target_type = TargetTrafficType::YOUTUBE_STREAM;
    cache.insert(0xCAFEBABE, TargetTrafficType::YOUTUBE_STREAM, e);

    auto serialized = cache.serialize();
    EXPECT_FALSE(serialized.empty());

    PerturbationCache cache2;
    bool ok = cache2.load_from_buffer(serialized.data(), serialized.size());
    EXPECT_TRUE(ok);
    const auto* entry = cache2.lookup(0xCAFEBABE, TargetTrafficType::YOUTUBE_STREAM);
    ASSERT_NE(entry, nullptr);
    EXPECT_EQ(entry->pre_padding, e.pre_padding);
}

TEST(PerturbationCacheTest, Stats_HitRateUpdates) {
    PerturbationCache cache;
    PerturbationEntry e;
    cache.insert(42, TargetTrafficType::YOUTUBE_STREAM, e);
    cache.lookup(42, TargetTrafficType::YOUTUBE_STREAM);   // hit
    cache.lookup(99, TargetTrafficType::YOUTUBE_STREAM);   // miss

    auto stats = cache.get_stats();
    EXPECT_EQ(stats.hits.load(), 1u);
    EXPECT_EQ(stats.misses.load(), 1u);
    EXPECT_NEAR(stats.hit_rate(), 0.5, 0.001);
}

// ══════════════════════════════════════════════════════════════════════════════
// BurstTracker
// ══════════════════════════════════════════════════════════════════════════════

TEST(BurstTrackerTest, ObservePacket_SinglePacketNoBurstEnd) {
    BurstTracker tracker(100000.0); // 100ms gap
    auto result = tracker.observe_packet(512, PacketDirection::OUTBOUND);
    // Single packet → burst not complete yet
    EXPECT_FALSE(result.has_value());
}

TEST(BurstTrackerTest, Flush_ReturnsBurstIfPacketsObserved) {
    BurstTracker tracker(100000.0);
    tracker.observe_packet(512, PacketDirection::OUTBOUND);
    tracker.observe_packet(256, PacketDirection::INBOUND);
    auto result = tracker.flush();
    EXPECT_TRUE(result.has_value());
    if (result) {
        EXPECT_EQ(result->packet_count, 2u);
    }
}

TEST(BurstTrackerTest, Flush_EmptyTrackerReturnsNoValue) {
    BurstTracker tracker;
    auto result = tracker.flush();
    EXPECT_FALSE(result.has_value());
}

TEST(BurstTrackerTest, CurrentBurst_ReflectsObservations) {
    BurstTracker tracker;
    tracker.observe_packet(100, PacketDirection::OUTBOUND);
    tracker.observe_packet(200, PacketDirection::OUTBOUND);
    auto burst = tracker.current_burst();
    EXPECT_EQ(burst.packet_count, 2u);
}

TEST(BurstTrackerTest, GetSetGapThreshold) {
    BurstTracker tracker(50000.0);
    EXPECT_DOUBLE_EQ(tracker.get_gap_threshold(), 50000.0);
    tracker.set_gap_threshold(200000.0);
    EXPECT_DOUBLE_EQ(tracker.get_gap_threshold(), 200000.0);
}

// ══════════════════════════════════════════════════════════════════════════════
// BurstMorpher
// ══════════════════════════════════════════════════════════════════════════════

TEST(BurstMorpherTest, DefaultConstructor_NoThrow) {
    EXPECT_NO_THROW({ BurstMorpher bm; });
}

TEST(BurstMorpherTest, SelectPerturbation_ReturnsPadding) {
    BurstMorpher bm;
    BurstProfile burst{};
    burst.packet_count = 5;
    burst.mean_size = 512;

    auto result = bm.select_perturbation(512, burst);
    EXPECT_FALSE(result.pre_padding.empty());
    EXPECT_GE(result.evasion_score, 0.0);
    EXPECT_LE(result.evasion_score, 1.0);
}

TEST(BurstMorpherTest, SelectPerturbation_CacheHit_AfterInsert) {
    BurstMorpherConfig cfg;
    cfg.fallback_to_rule_based = false;
    BurstMorpher bm(cfg);

    BurstProfile burst{};
    burst.mean_size = 800;
    uint64_t h = burst.compute_hash();

    // Pre-populate cache
    PerturbationEntry e;
    e.pre_padding = {0xAA, 0xBB, 0xCC};
    e.evasion_score = 0.9;
    e.target_type = TargetTrafficType::YOUTUBE_STREAM;
    bm.cache().insert(h, TargetTrafficType::YOUTUBE_STREAM, e);

    BurstMorpherConfig cfg2;
    cfg2.default_target = TargetTrafficType::YOUTUBE_STREAM;
    cfg2.auto_select_target = false;
    bm.set_config(cfg2);

    auto result = bm.select_perturbation(512, burst, TargetTrafficType::YOUTUBE_STREAM);
    EXPECT_TRUE(result.from_cache);
}

TEST(BurstMorpherTest, ObservePacket_NoThrow) {
    BurstMorpher bm;
    EXPECT_NO_THROW(bm.observe_packet(512, PacketDirection::OUTBOUND));
}

TEST(BurstMorpherTest, GetStats_InitialZero) {
    BurstMorpher bm;
    auto s = bm.get_stats();
    EXPECT_EQ(s.bursts_observed.load(), 0u);
}

TEST(BurstMorpherTest, ResetStats) {
    BurstMorpher bm;
    BurstProfile b{};
    bm.select_perturbation(64, b);
    bm.reset_stats();
    EXPECT_EQ(bm.get_stats().perturbations_applied.load(), 0u);
}
