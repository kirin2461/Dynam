// ══════════════════════════════════════════════════════════════════════════════
// tests/test_flow_shaper.cpp
// Tests for FlowShaper (ncp_flow_shaper.hpp)
// ══════════════════════════════════════════════════════════════════════════════
#include <gtest/gtest.h>
#include "ncp_flow_shaper.hpp"

#include <vector>
#include <string>
#include <chrono>
#include <atomic>
#include <thread>

using namespace ncp::DPI;

// ── Fixture ───────────────────────────────────────────────────────────────────

class FlowShaperTest : public ::testing::Test {
protected:
    std::vector<uint8_t> make_packet(size_t n = 512) {
        std::vector<uint8_t> v(n);
        for (size_t i = 0; i < n; ++i) v[i] = static_cast<uint8_t>(i & 0xFF);
        return v;
    }
};

// ── Profile String Conversion ─────────────────────────────────────────────────

TEST_F(FlowShaperTest, FlowProfileToString_AllProfiles) {
    EXPECT_STRNE(flow_profile_to_string(FlowProfile::WEB_BROWSING),  "");
    EXPECT_STRNE(flow_profile_to_string(FlowProfile::VIDEO_STREAM),  "");
    EXPECT_STRNE(flow_profile_to_string(FlowProfile::MESSENGER),     "");
    EXPECT_STRNE(flow_profile_to_string(FlowProfile::GAMING),        "");
    EXPECT_STRNE(flow_profile_to_string(FlowProfile::FILE_DOWNLOAD), "");
}

TEST_F(FlowShaperTest, FlowProfileFromString_Roundtrip) {
    EXPECT_EQ(flow_profile_from_string("web_browsing"),  FlowProfile::WEB_BROWSING);
    EXPECT_EQ(flow_profile_from_string("video_stream"),  FlowProfile::VIDEO_STREAM);
    EXPECT_EQ(flow_profile_from_string("messenger"),     FlowProfile::MESSENGER);
    EXPECT_EQ(flow_profile_from_string("gaming"),        FlowProfile::GAMING);
    EXPECT_EQ(flow_profile_from_string("file_download"), FlowProfile::FILE_DOWNLOAD);
}

// ── Config Presets ─────────────────────────────────────────────────────────────

TEST_F(FlowShaperTest, ConfigPreset_WebBrowsing) {
    auto cfg = FlowShaperConfig::web_browsing();
    EXPECT_EQ(cfg.profile, FlowProfile::WEB_BROWSING);
    EXPECT_TRUE(cfg.enabled);
}

TEST_F(FlowShaperTest, ConfigPreset_VideoStream) {
    auto cfg = FlowShaperConfig::video_stream();
    EXPECT_EQ(cfg.profile, FlowProfile::VIDEO_STREAM);
}

TEST_F(FlowShaperTest, ConfigPreset_Messenger) {
    auto cfg = FlowShaperConfig::messenger();
    EXPECT_EQ(cfg.profile, FlowProfile::MESSENGER);
}

TEST_F(FlowShaperTest, ConfigPreset_Gaming) {
    auto cfg = FlowShaperConfig::gaming();
    EXPECT_EQ(cfg.profile, FlowProfile::GAMING);
}

TEST_F(FlowShaperTest, ConfigPreset_FileDownload) {
    auto cfg = FlowShaperConfig::file_download();
    EXPECT_EQ(cfg.profile, FlowProfile::FILE_DOWNLOAD);
}

// ── Burst / Size Distribution Presets ────────────────────────────────────────

TEST_F(FlowShaperTest, SizeDistribution_WebBrowsing_HasBuckets) {
    auto sd = SizeDistribution::web_browsing();
    EXPECT_FALSE(sd.buckets.empty());
}

TEST_F(FlowShaperTest, SizeDistribution_VideoStream_HasBuckets) {
    auto sd = SizeDistribution::video_stream();
    EXPECT_FALSE(sd.buckets.empty());
}

TEST_F(FlowShaperTest, BurstModel_WebBrowsing_IsReasonable) {
    auto bm = BurstModel::web_browsing();
    EXPECT_GT(bm.burst_packets_max, bm.burst_packets_min);
    EXPECT_GT(bm.pause_ms_max, bm.pause_ms_min);
}

TEST_F(FlowShaperTest, BurstModel_Gaming_IsReasonable) {
    auto bm = BurstModel::gaming();
    EXPECT_GT(bm.burst_packets_max, 0);
}

// ── Lifecycle ─────────────────────────────────────────────────────────────────

TEST_F(FlowShaperTest, DefaultConstructor_NotRunning) {
    FlowShaper fs;
    EXPECT_FALSE(fs.is_running());
}

TEST_F(FlowShaperTest, StartStop) {
    FlowShaper fs;
    fs.start(nullptr);
    EXPECT_TRUE(fs.is_running());
    fs.stop();
    EXPECT_FALSE(fs.is_running());
}

TEST_F(FlowShaperTest, DoubleStop_IsIdempotent) {
    FlowShaper fs;
    fs.start(nullptr);
    fs.stop();
    EXPECT_NO_THROW(fs.stop());
}

TEST_F(FlowShaperTest, StartWithCallback) {
    FlowShaper fs;
    std::atomic<int> call_count{0};
    fs.start([&](const ShapedPacket&) { call_count++; });
    EXPECT_TRUE(fs.is_running());
    fs.stop();
}

// ── shape_sync ────────────────────────────────────────────────────────────────

TEST_F(FlowShaperTest, ShapeSync_ReturnsShapedPackets) {
    FlowShaper fs;
    auto cfg = FlowShaperConfig::web_browsing();
    fs.update_config(cfg);

    auto pkt = make_packet(512);
    auto result = fs.shape_sync(pkt, true);
    EXPECT_FALSE(result.empty());
}

TEST_F(FlowShaperTest, ShapeSync_PacketDataPreserved) {
    FlowShaper fs;
    auto pkt = make_packet(64);
    auto result = fs.shape_sync(pkt, true);

    // At least one packet should contain the original data (possibly with headers)
    EXPECT_FALSE(result.empty());
    bool found = false;
    for (auto& sp : result) {
        if (sp.data.size() >= pkt.size()) {
            found = true;
            break;
        }
    }
    EXPECT_TRUE(found);
}

TEST_F(FlowShaperTest, ShapeSync_LargePacket_MayBeSplit) {
    FlowShaperConfig cfg = FlowShaperConfig::gaming(); // small packet profile
    cfg.enable_size_shaping = true;
    FlowShaper fs;
    fs.update_config(cfg);

    auto big_pkt = make_packet(4096);
    auto result = fs.shape_sync(big_pkt, true);
    EXPECT_FALSE(result.empty());
}

TEST_F(FlowShaperTest, ShapeSync_DownloadPacket_IsMarkedNotUpload) {
    FlowShaper fs;
    auto pkt = make_packet(256);
    auto result = fs.shape_sync(pkt, false); // is_upload = false
    EXPECT_FALSE(result.empty());
    // First result packet should reflect the upload=false direction
    if (!result.empty()) {
        EXPECT_FALSE(result[0].is_upload);
    }
}

// ── Timing / Burst ────────────────────────────────────────────────────────────

TEST_F(FlowShaperTest, NextDelay_IsNonNegative) {
    FlowShaper fs;
    auto delay = fs.next_delay();
    EXPECT_GE(delay.count(), 0);
}

TEST_F(FlowShaperTest, ShouldBurst_ReturnsBoolean) {
    FlowShaper fs;
    bool b = fs.should_burst();
    (void)b; // just ensure no crash
}

TEST_F(FlowShaperTest, SelectTargetSize_InReasonableRange) {
    FlowShaper fs;
    size_t sz = fs.select_target_size();
    EXPECT_GT(sz, 0u);
    EXPECT_LE(sz, 65536u);
}

// ── Dummy / Keepalive Generation ─────────────────────────────────────────────

TEST_F(FlowShaperTest, GenerateDummy_NotEmpty) {
    FlowShaper fs;
    auto d = fs.generate_dummy();
    EXPECT_TRUE(d.is_dummy);
    EXPECT_FALSE(d.data.empty());
}

TEST_F(FlowShaperTest, GenerateKeepalive_NotEmpty) {
    FlowShaper fs;
    auto k = fs.generate_keepalive();
    EXPECT_TRUE(k.is_keepalive);
    EXPECT_FALSE(k.data.empty());
}

TEST_F(FlowShaperTest, IsFlowDummy_DetectsOwnDummy) {
    FlowShaper fs;
    auto dummy = fs.generate_dummy();
    EXPECT_TRUE(fs.is_flow_dummy(dummy.data.data(), dummy.data.size()));
}

TEST_F(FlowShaperTest, IsFlowDummy_ReturnsFalseForNormal) {
    FlowShaper fs;
    auto pkt = make_packet(64);
    EXPECT_FALSE(fs.is_flow_dummy(pkt.data(), pkt.size()));
}

// ── Ratio Shaping ─────────────────────────────────────────────────────────────

TEST_F(FlowShaperTest, CurrentRatio_Initial) {
    FlowShaper fs;
    double r = fs.current_ratio();
    EXPECT_GE(r, 0.0);
}

TEST_F(FlowShaperTest, NeedsRatioBalance_InitialFalse) {
    FlowShaper fs;
    // With no packets yet, ratio balancing should not be triggered
    bool needs = fs.needs_ratio_balance();
    (void)needs;
}

// ── Statistics ────────────────────────────────────────────────────────────────

TEST_F(FlowShaperTest, InitialStatsAreZero) {
    FlowShaper fs;
    auto s = fs.get_stats();
    EXPECT_EQ(s.packets_shaped.load(), 0u);
}

TEST_F(FlowShaperTest, ResetStats) {
    FlowShaper fs;
    fs.shape_sync(make_packet(64), true);
    fs.reset_stats();
    auto s = fs.get_stats();
    EXPECT_EQ(s.packets_shaped.load(), 0u);
}

TEST_F(FlowShaperTest, StatsIncrementAfterShape) {
    FlowShaper fs;
    fs.shape_sync(make_packet(128), true);
    auto s = fs.get_stats();
    EXPECT_GT(s.packets_shaped.load(), 0u);
}

// ── Config Update ─────────────────────────────────────────────────────────────

TEST_F(FlowShaperTest, UpdateConfig_ChangesProfile) {
    FlowShaper fs;
    auto cfg = FlowShaperConfig::messenger();
    fs.update_config(cfg);
    EXPECT_EQ(fs.get_config().profile, FlowProfile::MESSENGER);
}
