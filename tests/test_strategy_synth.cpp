// Tests for StrategySynthesizer and the strategy genes: per-destination
// synthesis of DPI desync strategies, tuned on live outbound traffic.
//
// Signals available to the capture thread (outbound only):
//   success - client data past the end of its ClientHello on the same flow;
//   failure - the ClientHello retransmitted at the same seq, or a flow left
//             silent past the verdict timeout when a new one starts.

#include <gtest/gtest.h>

#include "ncp_strategy_synth.hpp"

using namespace ncp::DPI;

namespace {

using Clock = StrategySynthesizer::Clock;
using std::chrono::milliseconds;
using std::chrono::seconds;

constexpr uint32_t kIpA = 0x08067000;  // 8.6.112.0
constexpr uint32_t kIpB = 0x68107C60;  // 104.16.124.96
constexpr uint16_t kHttps = 443;
constexpr uint32_t kHelloLen = 517;

const Clock::time_point t0 = Clock::time_point(seconds(1000));

std::vector<StrategyGenes> two_candidates() {
    return {
        {SplitGene::Sni, OrderGene::InOrder, FakeGene::None},
        {SplitGene::Pos1, OrderGene::Disorder, FakeGene::Badseq},
    };
}

} // namespace

// ===== StrategySynthesizer =====

TEST(StrategySynthesizer, FirstClientHelloUsesFirstCandidate) {
    StrategySynthesizer s(two_candidates());
    const auto t = s.on_client_hello("example.com", kIpA, 50000, kHttps, 1000, kHelloLen, t0);
    EXPECT_EQ(t.candidate, 0);
    EXPECT_FALSE(t.retransmission);
    EXPECT_FALSE(t.switched);
    EXPECT_FALSE(t.exhausted);
    EXPECT_EQ(s.pending_flows(), 1u);
}

TEST(StrategySynthesizer, RetransmissionMovesToNextCandidate) {
    StrategySynthesizer s(two_candidates());
    s.on_client_hello("example.com", kIpA, 50000, kHttps, 1000, kHelloLen, t0);

    const auto r = s.on_client_hello("example.com", kIpA, 50000, kHttps, 1000, kHelloLen,
                                     t0 + milliseconds(300));
    EXPECT_TRUE(r.retransmission);
    EXPECT_TRUE(r.switched);
    EXPECT_EQ(r.candidate, 1) << "the retransmission itself must go out with the next candidate";
    EXPECT_EQ(s.failures(), 1u);
    EXPECT_EQ(s.switches(), 1u);
}

TEST(StrategySynthesizer, DataPastClientHelloLocksCandidate) {
    StrategySynthesizer s(two_candidates());
    s.on_client_hello("example.com", kIpA, 50000, kHttps, 1000, kHelloLen, t0);
    s.on_client_hello("example.com", kIpA, 50000, kHttps, 1000, kHelloLen, t0 + milliseconds(300));

    const auto v = s.on_data(kIpA, 50000, kHttps, 1000 + kHelloLen, t0 + milliseconds(400));
    EXPECT_TRUE(v.success);
    EXPECT_TRUE(v.newly_locked);
    EXPECT_EQ(v.candidate, 1);
    EXPECT_EQ(v.destination, "example.com");
    EXPECT_EQ(v.attempts, 2);
    EXPECT_EQ(s.locked_candidate("example.com"), 1);
    EXPECT_EQ(s.wins(), 1u);
    EXPECT_EQ(s.pending_flows(), 0u);
}

TEST(StrategySynthesizer, DataInsideClientHelloIsNotAVerdict) {
    StrategySynthesizer s(two_candidates());
    s.on_client_hello("example.com", kIpA, 50000, kHttps, 1000, 1800, t0);

    // Second segment of a multi-segment ClientHello.
    const auto v = s.on_data(kIpA, 50000, kHttps, 1000 + 1400, t0 + milliseconds(1));
    EXPECT_FALSE(v.success);
    EXPECT_EQ(s.pending_flows(), 1u);
}

TEST(StrategySynthesizer, SequenceWrapAroundIsHandled) {
    StrategySynthesizer s(two_candidates());
    const uint32_t seq = 0xFFFFFFF0u;
    s.on_client_hello("example.com", kIpA, 50000, kHttps, seq, 0x100, t0);
    const auto v = s.on_data(kIpA, 50000, kHttps, seq + 0x100u, t0 + milliseconds(50));
    EXPECT_TRUE(v.success);
}

TEST(StrategySynthesizer, LockedCandidateIsReusedForNewFlows) {
    StrategySynthesizer s(two_candidates());
    s.on_client_hello("example.com", kIpA, 50000, kHttps, 1000, kHelloLen, t0);
    s.on_client_hello("example.com", kIpA, 50000, kHttps, 1000, kHelloLen, t0 + milliseconds(300));
    s.on_data(kIpA, 50000, kHttps, 1000 + kHelloLen, t0 + milliseconds(400));

    const auto t = s.on_client_hello("example.com", kIpA, 50001, kHttps, 777777, kHelloLen,
                                     t0 + seconds(5));
    EXPECT_EQ(t.candidate, 1);
    EXPECT_FALSE(t.switched);
}

TEST(StrategySynthesizer, WhatWorkedIsTriedFirstOnNewDestinations) {
    StrategySynthesizer s(two_candidates());
    s.on_client_hello("example.com", kIpA, 50000, kHttps, 1000, kHelloLen, t0);
    s.on_client_hello("example.com", kIpA, 50000, kHttps, 1000, kHelloLen, t0 + milliseconds(300));
    s.on_data(kIpA, 50000, kHttps, 1000 + kHelloLen, t0 + milliseconds(400));

    EXPECT_GT(s.global_score(1), s.global_score(0));
    const auto t = s.on_client_hello("www.cloudflare.com", kIpB, 50002, kHttps, 5000, kHelloLen,
                                     t0 + seconds(1));
    EXPECT_EQ(t.candidate, 1);
}

TEST(StrategySynthesizer, SilentFlowFailsWhenANewConnectionStarts) {
    StrategySynthesizer s(two_candidates());
    s.on_client_hello("example.com", kIpA, 50000, kHttps, 1000, kHelloLen, t0);

    // No retransmission seen (e.g. RST injected), app opens a new connection.
    const auto t = s.on_client_hello("example.com", kIpA, 50001, kHttps, 9000, kHelloLen,
                                     t0 + seconds(4));
    EXPECT_EQ(s.failures(), 1u);
    EXPECT_EQ(t.candidate, 1);
    EXPECT_TRUE(t.switched);
}

TEST(StrategySynthesizer, ParallelFlowsAreNotFailedBeforeTheVerdictTimeout) {
    StrategySynthesizer s(two_candidates());
    s.on_client_hello("example.com", kIpA, 50000, kHttps, 1000, kHelloLen, t0);
    // Browsers open several connections at once; that is not a failure.
    const auto t = s.on_client_hello("example.com", kIpA, 50001, kHttps, 9000, kHelloLen,
                                     t0 + milliseconds(20));
    EXPECT_EQ(s.failures(), 0u);
    EXPECT_EQ(t.candidate, 0);
}

TEST(StrategySynthesizer, ParallelFailuresDoNotSkipAnUntriedCandidate) {
    std::vector<StrategyGenes> three = two_candidates();
    three.push_back({SplitGene::Midsld, OrderGene::InOrder, FakeGene::None});
    StrategySynthesizer s(three);

    s.on_client_hello("example.com", kIpA, 50000, kHttps, 1000, kHelloLen, t0);
    s.on_client_hello("example.com", kIpA, 50001, kHttps, 2000, kHelloLen, t0 + milliseconds(5));

    const auto r1 = s.on_client_hello("example.com", kIpA, 50000, kHttps, 1000, kHelloLen,
                                      t0 + milliseconds(300));
    const auto r2 = s.on_client_hello("example.com", kIpA, 50001, kHttps, 2000, kHelloLen,
                                      t0 + milliseconds(305));
    EXPECT_EQ(r1.candidate, 1);
    EXPECT_EQ(r2.candidate, 1) << "the second failure of candidate 0 must not burn candidate 1";
    EXPECT_EQ(s.switches(), 1u);
}

TEST(StrategySynthesizer, PoisonedRetransmissionDoesNotBurnTheNextCandidate) {
    StrategySynthesizer s(two_candidates());
    s.on_client_hello("example.com", kIpA, 50000, kHttps, 1000, kHelloLen, t0);
    ASSERT_EQ(s.on_client_hello("example.com", kIpA, 50000, kHttps, 1000, kHelloLen,
                                t0 + milliseconds(300)).candidate, 1);

    // Candidate 1 now fails too, but only on a flow the DPI already saw.
    const auto again = s.on_client_hello("example.com", kIpA, 50000, kHttps, 1000, kHelloLen,
                                         t0 + milliseconds(900));
    EXPECT_EQ(again.candidate, 1);
    EXPECT_FALSE(again.exhausted);
    EXPECT_DOUBLE_EQ(s.global_score(1), 0.5) << "not a clean trial, must not count globally";

    // The next connection gives candidate 1 its clean trial.
    const auto fresh = s.on_client_hello("example.com", kIpA, 50001, kHttps, 9000, kHelloLen,
                                         t0 + seconds(5));
    EXPECT_EQ(fresh.candidate, 1);
}

TEST(StrategySynthesizer, PresetThatPoisonsTheFlowStillLearnsTheFallback) {
    // Live regression: the preset's fakes poisoned the first flow, its
    // in-order retransmission failed as well, and the destination froze on the
    // preset for good.  The fallback must get a clean trial on the next flow.
    StrategySynthesizer s(preset_with_in_order_fallback());
    s.on_client_hello("example.com", kIpA, 50000, kHttps, 1000, kHelloLen, t0);
    s.on_client_hello("example.com", kIpA, 50000, kHttps, 1000, kHelloLen, t0 + milliseconds(300));
    s.on_client_hello("example.com", kIpA, 50000, kHttps, 1000, kHelloLen, t0 + milliseconds(900));
    s.on_client_hello("example.com", kIpA, 50000, kHttps, 1000, kHelloLen, t0 + milliseconds(2100));

    const auto next = s.on_client_hello("example.com", kIpA, 50001, kHttps, 9000, kHelloLen,
                                        t0 + seconds(12));
    EXPECT_EQ(next.candidate, 1);
    const auto v = s.on_data(kIpA, 50001, kHttps, 9000 + kHelloLen, t0 + seconds(12) + milliseconds(80));
    EXPECT_TRUE(v.success);
    EXPECT_EQ(s.locked_candidate("example.com"), 1);
}

TEST(StrategySynthesizer, ExhaustionStartsANewRound) {
    StrategySynthesizer s(two_candidates());
    // Clean failure of candidate 0, then of candidate 1, each on its own flow.
    s.on_client_hello("x.com", kIpA, 50000, kHttps, 1000, kHelloLen, t0);
    s.on_client_hello("x.com", kIpA, 50000, kHttps, 1000, kHelloLen, t0 + milliseconds(300));
    s.on_client_hello("x.com", kIpA, 50001, kHttps, 2000, kHelloLen, t0 + seconds(5));
    const auto r = s.on_client_hello("x.com", kIpA, 50001, kHttps, 2000, kHelloLen,
                                     t0 + seconds(5) + milliseconds(300));
    EXPECT_TRUE(r.exhausted);
    EXPECT_GE(r.candidate, 0);
    EXPECT_LT(r.candidate, 2);

    // Announced once per destination, not on every further round.
    bool announced_again = false;
    for (int i = 0; i < 6; ++i) {
        const uint16_t port = static_cast<uint16_t>(50010 + i);
        const auto t = t0 + seconds(10 + 5 * i);
        s.on_client_hello("x.com", kIpA, port, kHttps, 3000u + i, kHelloLen, t);
        announced_again |= s.on_client_hello("x.com", kIpA, port, kHttps, 3000u + i, kHelloLen,
                                             t + milliseconds(300)).exhausted;
    }
    EXPECT_FALSE(announced_again);
}

TEST(StrategySynthesizer, LockedCandidateSurvivesOneFailureButNotTwo) {
    StrategySynthesizer s(two_candidates());
    s.on_client_hello("example.com", kIpA, 50000, kHttps, 1000, kHelloLen, t0);
    s.on_data(kIpA, 50000, kHttps, 1000 + kHelloLen, t0 + milliseconds(100));
    ASSERT_EQ(s.locked_candidate("example.com"), 0);

    s.on_client_hello("example.com", kIpA, 50001, kHttps, 2000, kHelloLen, t0 + seconds(1));
    s.on_client_hello("example.com", kIpA, 50001, kHttps, 2000, kHelloLen, t0 + seconds(2));
    EXPECT_EQ(s.locked_candidate("example.com"), 0) << "one silent flow is not proof";

    s.on_client_hello("example.com", kIpA, 50002, kHttps, 3000, kHelloLen, t0 + seconds(3));
    const auto r = s.on_client_hello("example.com", kIpA, 50002, kHttps, 3000, kHelloLen,
                                     t0 + seconds(4));
    EXPECT_EQ(s.locked_candidate("example.com"), -1);
    EXPECT_EQ(r.candidate, 1);
}

TEST(StrategySynthesizer, DestinationsAreIndependent) {
    StrategySynthesizer s(two_candidates());
    s.on_client_hello("example.com", kIpA, 50000, kHttps, 1000, kHelloLen, t0);
    s.on_client_hello("example.com", kIpA, 50000, kHttps, 1000, kHelloLen, t0 + milliseconds(300));

    // Candidate 0 failed globally once, but nothing was proven elsewhere: a
    // new destination may start on any candidate; it must not be locked.
    s.on_client_hello("www.cloudflare.com", kIpB, 50010, kHttps, 7000, kHelloLen, t0 + seconds(1));
    EXPECT_EQ(s.locked_candidate("www.cloudflare.com"), -1);
    EXPECT_EQ(s.tracked_destinations(), 2u);
}

TEST(StrategySynthesizer, DestinationsExpireAndReprobe) {
    StrategySynthesizer s(two_candidates());
    s.set_destination_ttl(seconds(60));
    s.on_client_hello("example.com", kIpA, 50000, kHttps, 1000, kHelloLen, t0);
    s.on_data(kIpA, 50000, kHttps, 1000 + kHelloLen, t0 + milliseconds(100));
    ASSERT_EQ(s.locked_candidate("example.com"), 0);

    s.on_client_hello("other.org", kIpB, 50001, kHttps, 1, kHelloLen, t0 + seconds(120));
    EXPECT_EQ(s.locked_candidate("example.com"), -1);
}

TEST(StrategySynthesizer, CapacityIsBounded) {
    StrategySynthesizer s(two_candidates());
    s.set_max_destinations(4);
    s.set_max_flows(8);
    for (uint32_t i = 0; i < 64; ++i) {
        s.on_client_hello("host" + std::to_string(i), 0x0A000000u | i,
                          static_cast<uint16_t>(40000 + i), kHttps, 1000 + i, kHelloLen,
                          t0 + milliseconds(i));
    }
    EXPECT_LE(s.tracked_destinations(), 4u);
    EXPECT_LE(s.pending_flows(), 8u);
}

TEST(StrategySynthesizer, EmptyCandidateSetFallsBackToPreset) {
    StrategySynthesizer s(std::vector<StrategyGenes>{});
    ASSERT_EQ(s.candidates().size(), 1u);
    EXPECT_EQ(s.candidates()[0], StrategyGenes{});
}

TEST(StrategySynthesizer, ClearResetsEverything) {
    StrategySynthesizer s(two_candidates());
    s.on_client_hello("example.com", kIpA, 50000, kHttps, 1000, kHelloLen, t0);
    s.on_client_hello("example.com", kIpA, 50000, kHttps, 1000, kHelloLen, t0 + milliseconds(300));
    s.clear();
    EXPECT_EQ(s.failures(), 0u);
    EXPECT_EQ(s.switches(), 0u);
    EXPECT_EQ(s.tracked_destinations(), 0u);
    EXPECT_EQ(s.pending_flows(), 0u);
    EXPECT_DOUBLE_EQ(s.global_score(0), 0.5);
}

// ===== Genes =====

TEST(StrategyGenes, KeepGenesLeaveConfigUntouched) {
    DPIConfig cfg;
    apply_preset(DPIPreset::MOBILE_UNIVERSAL, cfg);
    const DPIConfig before = cfg;
    apply_genes(StrategyGenes{}, cfg);
    EXPECT_TRUE(cfg == before);
    EXPECT_EQ(StrategyGenes{}.name(), "preset");
}

TEST(StrategyGenes, InOrderNoFakeStripsAPreset) {
    DPIConfig cfg;
    apply_preset(DPIPreset::MOBILE_UNIVERSAL, cfg);
    apply_genes({SplitGene::Sni, OrderGene::InOrder, FakeGene::None}, cfg);
    EXPECT_TRUE(cfg.enable_tcp_split);
    EXPECT_TRUE(cfg.split_at_sni);
    EXPECT_FALSE(cfg.enable_multi_layer_split);
    EXPECT_FALSE(cfg.enable_disorder);
    EXPECT_FALSE(cfg.enable_reverse_frag);
    EXPECT_FALSE(cfg.enable_fake_packet);
    EXPECT_FALSE(cfg.enable_autottl);
}

TEST(StrategyGenes, ReverseTurnsDisorderOff) {
    DPIConfig cfg;
    cfg.enable_disorder = true;
    apply_genes({SplitGene::Keep, OrderGene::Reverse, FakeGene::Keep}, cfg);
    EXPECT_FALSE(cfg.enable_disorder) << "disorder would shadow reverse-frag in the send path";
    EXPECT_TRUE(cfg.enable_reverse_frag);
}

TEST(StrategyGenes, FakeGenesOwnTheTtl) {
    DPIConfig cfg;
    cfg.enable_autottl = true;
    cfg.randomize_fake_ttl = true;
    apply_genes({SplitGene::Keep, OrderGene::Keep, FakeGene::LowTtl}, cfg);
    EXPECT_TRUE(cfg.enable_fake_packet);
    EXPECT_FALSE(cfg.enable_autottl);
    EXPECT_FALSE(cfg.randomize_fake_ttl);
    EXPECT_EQ(cfg.fake_fooling, 0);
    EXPECT_GT(cfg.fake_ttl, 0);

    apply_genes({SplitGene::Keep, OrderGene::Keep, FakeGene::Badseq}, cfg);
    EXPECT_EQ(cfg.fake_fooling, 2);
    apply_genes({SplitGene::Keep, OrderGene::Keep, FakeGene::Badsum}, cfg);
    EXPECT_EQ(cfg.fake_fooling, 1);
}

TEST(StrategyGenes, LadderStartsConservativeAndIsUnique) {
    const auto ladder = synthesized_strategy_ladder();
    ASSERT_FALSE(ladder.empty());
    ASSERT_LE(ladder.size(), StrategySynthesizer::kMaxCandidates);
    EXPECT_EQ(ladder.front().order, OrderGene::InOrder);
    EXPECT_EQ(ladder.front().fake, FakeGene::None);
    for (size_t i = 0; i < ladder.size(); ++i)
        for (size_t j = i + 1; j < ladder.size(); ++j)
            EXPECT_NE(ladder[i], ladder[j]) << ladder[i].name();
}

TEST(StrategyGenes, PresetFallbackIsPresetThenInOrder) {
    const auto c = preset_with_in_order_fallback();
    ASSERT_EQ(c.size(), 2u);
    EXPECT_EQ(c[0], StrategyGenes{});
    EXPECT_EQ(c[1].order, OrderGene::InOrder);
    EXPECT_EQ(c[1].fake, FakeGene::None);
}
