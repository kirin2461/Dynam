// Tests for the inline (per-packet) delay budget of the timing-shaping modules.
//
// Context: BehavioralCloak and TimeCorrelationBreaker are wired into the
// WinDivert capture thread through ModuleHooks::get_send_delay_us, which is
// called for every intercepted real segment and slept on *inline*.  Both
// modules were written for session granularity (50-200 ms burst intervals,
// 10-500 ms jitter), so replaying their output per segment added seconds to a
// TLS handshake and stalled unrelated flows.  These tests pin the contract:
// nothing on the packet path may sleep for more than a small budget.

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <limits>

#include "ncp_behavioral_cloak.hpp"
#include "ncp_dpi.hpp"
#include "ncp_time_correlation_breaker.hpp"

using namespace ncp::DPI;

namespace {

// Runs shape_packet() enough times to walk through several burst/idle cycles
// and returns the largest delay seen, in microseconds.
int64_t max_cloak_delay_us(BehavioralCloak& cloak, int iterations) {
    int64_t worst = 0;
    for (int i = 0; i < iterations; ++i) {
        auto d = cloak.shape_packet(1400, true);
        worst = std::max(worst, static_cast<int64_t>(d.count()));
    }
    return worst;
}

} // namespace

// ===== BehavioralCloak: inline budget =====

TEST(BehavioralCloakInlineBudget, DefaultBudgetBoundsEveryPacket) {
    BehavioralCloakConfig cfg;
    cfg.active_model = "chrome_casual";
    BehavioralCloak cloak(cfg);

    const int64_t worst = max_cloak_delay_us(cloak, 2000);
    EXPECT_LE(worst, cfg.max_inline_delay_us)
        << "shape_packet() exceeded the inline budget: a caller on the capture "
           "thread would sleep " << worst << "us per segment";
}

TEST(BehavioralCloakInlineBudget, HighThreatNoiseIsAlsoBounded) {
    BehavioralCloakConfig cfg;
    BehavioralCloak cloak(cfg);
    cloak.set_threat_level(ThreatLevel::HIGH);

    // The HIGH-threat branch adds noise drawn from burst_interval_max_ms * 500,
    // i.e. up to 100 ms, on top of the burst delay.
    const int64_t worst = max_cloak_delay_us(cloak, 2000);
    EXPECT_LE(worst, cfg.max_inline_delay_us);
}

TEST(BehavioralCloakInlineBudget, CriticalThreatNoiseIsAlsoBounded) {
    BehavioralCloakConfig cfg;
    BehavioralCloak cloak(cfg);
    cloak.set_threat_level(ThreatLevel::CRITICAL);

    EXPECT_LE(max_cloak_delay_us(cloak, 1000), cfg.max_inline_delay_us);
}

TEST(BehavioralCloakInlineBudget, ZeroBudgetDisablesInlineDelay) {
    BehavioralCloakConfig cfg;
    cfg.max_inline_delay_us = 0;
    BehavioralCloak cloak(cfg);

    // count() must be 0, not "a few microseconds" -- the hook treats <= 0 as
    // "no sleep at all", so anything else would still call sleep_for().
    EXPECT_EQ(max_cloak_delay_us(cloak, 500), 0);
}

TEST(BehavioralCloakInlineBudget, CustomBudgetIsRespected) {
    BehavioralCloakConfig cfg;
    cfg.max_inline_delay_us = 250;
    BehavioralCloak cloak(cfg);

    const int64_t worst = max_cloak_delay_us(cloak, 1000);
    EXPECT_LE(worst, 250);
    EXPECT_GT(worst, 0) << "some shaping should still happen inside the budget";
}

TEST(BehavioralCloakInlineBudget, IdleGapIsReportedOutOfBandNotInline) {
    // The idle gap is the one part of the model that is *not* applied inline:
    // callers ask for it explicitly via get_idle_duration().  It must keep
    // reporting the model's real (seconds-scale) value.
    BehavioralCloakConfig cfg;
    BehavioralCloak cloak(cfg);

    // Walk until a burst ends, checking that every packet in it -- including
    // the one that closes the burst -- stays inside the inline budget.
    // (The fresh cloak starts in IDLE, so the idle gap is queryable up front and
    // drops to zero as soon as the first packet opens a burst.)
    int64_t worst = cloak.shape_packet(1400, true).count();
    int packets = 1;
    while (cloak.get_idle_duration().count() == 0 && packets < 200) {
        worst = std::max(worst, static_cast<int64_t>(cloak.shape_packet(1400, true).count()));
        ++packets;
    }
    ASSERT_LT(packets, 200) << "burst never ended; chrome_casual burst size is 5-30";
    EXPECT_LE(worst, cfg.max_inline_delay_us);

    const auto idle = cloak.get_idle_duration();
    EXPECT_GE(idle.count(), 2000);
    EXPECT_LE(idle.count(), 8000);
}

TEST(BehavioralCloakInlineBudget, DisabledCloakReturnsZero) {
    BehavioralCloakConfig cfg;
    cfg.enabled = false;
    BehavioralCloak cloak(cfg);
    EXPECT_EQ(max_cloak_delay_us(cloak, 100), 0);
}

// ===== TimeCorrelationBreaker: inline packet-path profile =====

TEST(TimeBreakerInlineProfile, JitterStaysWithinBounds) {
    TimeCorrelationBreaker breaker(TimeCorrelationBreakerConfig::inline_packet_path());

    for (int i = 0; i < 2000; ++i) {
        const int64_t jitter = breaker.compute_jitter().count();
        EXPECT_GE(jitter, 500);
        EXPECT_LE(jitter, 4000) << "per-segment jitter must stay in the sub-5ms range";
    }
}

TEST(TimeBreakerInlineProfile, NoAutoAdjustScaling) {
    TimeCorrelationBreaker breaker(TimeCorrelationBreakerConfig::inline_packet_path());

    // A flat gap history gives CV = 0; with auto_adjust the stock config would
    // scale jitter by up to 5x.  The packet path must not do that.
    for (int i = 0; i < 10; ++i) {
        breaker.record_gap(100.0);
    }
    for (int i = 0; i < 500; ++i) {
        EXPECT_LE(breaker.compute_jitter().count(), 4000);
    }
    EXPECT_EQ(breaker.get_stats().cv_adjustments.load(), 0u);
}

TEST(TimeBreakerInlineProfile, DefaultConfigIsStillSessionScale) {
    // Guard against "fixing" the packet path by silently changing the
    // session-level defaults that other callers rely on.
    const TimeCorrelationBreakerConfig def;
    EXPECT_DOUBLE_EQ(def.min_jitter_ms, 10.0);
    EXPECT_DOUBLE_EQ(def.max_jitter_ms, 500.0);
    EXPECT_TRUE(def.auto_adjust);
}

// ===== Capture-thread clamp =====

TEST(InlineSendDelayClamp, NonPositiveDelaysBecomeZero) {
    EXPECT_EQ(clamp_inline_send_delay_us(0), 0);
    EXPECT_EQ(clamp_inline_send_delay_us(-1), 0);
    EXPECT_EQ(clamp_inline_send_delay_us(std::numeric_limits<int64_t>::min()), 0);
}

TEST(InlineSendDelayClamp, SmallDelaysPassThrough) {
    EXPECT_EQ(clamp_inline_send_delay_us(1), 1);
    EXPECT_EQ(clamp_inline_send_delay_us(2000), 2000);
    EXPECT_EQ(clamp_inline_send_delay_us(kMaxInlineSendDelayUs), kMaxInlineSendDelayUs);
}

TEST(InlineSendDelayClamp, LargeDelaysAreTruncated) {
    EXPECT_EQ(clamp_inline_send_delay_us(kMaxInlineSendDelayUs + 1), kMaxInlineSendDelayUs);
    EXPECT_EQ(clamp_inline_send_delay_us(8000000), kMaxInlineSendDelayUs);
    EXPECT_EQ(clamp_inline_send_delay_us(std::numeric_limits<int64_t>::max()),
              kMaxInlineSendDelayUs);
}

TEST(InlineSendDelayClamp, CapIsSmallEnoughForTheCaptureThread) {
    // The hook blocks the WinDivert receive loop, so the cap must stay well
    // under a human-perceptible stall.
    EXPECT_GT(kMaxInlineSendDelayUs, 0);
    EXPECT_LE(kMaxInlineSendDelayUs, 100000);
}

TEST(InlineSendDelayClamp, CombinedModulesFitTheCaptureBudget) {
    // worst case as wired in main.cpp: cloak (budgeted) + breaker (bounded) on
    // a three-segment ClientHello.
    BehavioralCloakConfig cloak_cfg;
    BehavioralCloak cloak(cloak_cfg);
    cloak.set_threat_level(ThreatLevel::CRITICAL);
    TimeCorrelationBreaker breaker(TimeCorrelationBreakerConfig::inline_packet_path());

    for (int i = 0; i < 200; ++i) {
        int64_t total = cloak.shape_packet(1400, true).count() + breaker.compute_jitter().count();
        EXPECT_LE(clamp_inline_send_delay_us(total), kMaxInlineSendDelayUs);
    }
}
