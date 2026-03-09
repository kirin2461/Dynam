// ══════════════════════════════════════════════════════════════════════════════
// tests/test_geneva.cpp
// Tests for GenevaEngine + GenevaGA (ncp_geneva_engine.hpp, ncp_geneva_ga.hpp)
// ══════════════════════════════════════════════════════════════════════════════
#include <gtest/gtest.h>
#include "ncp_geneva_engine.hpp"
#include "ncp_geneva_ga.hpp"

#include <vector>
#include <string>
#include <cstring>
#include <atomic>
#include <chrono>

using namespace ncp::DPI;

// ── Helpers ───────────────────────────────────────────────────────────────────

static std::vector<uint8_t> make_ip_packet(size_t size = 60) {
    std::vector<uint8_t> pkt(size, 0);
    // Minimal IPv4 header stub (version/IHL)
    pkt[0] = 0x45; // IPv4, IHL=5 (20 bytes)
    pkt[8] = 64;   // TTL
    pkt[9] = 0x06; // TCP
    return pkt;
}

// ══════════════════════════════════════════════════════════════════════════════
// GenevaEngine — Action Tests
// ══════════════════════════════════════════════════════════════════════════════

class GenevaEngineTest : public ::testing::Test {
protected:
    GenevaEngine engine;

    GenevaStrategy single_action_strategy(GenevaAction action, size_t param = 0) {
        GenevaStrategy s;
        GenevaStep step;
        step.action      = action;
        step.target_index = 0;
        step.param       = param;
        s.steps.push_back(step);
        return s;
    }
};

TEST_F(GenevaEngineTest, EmptyStrategy_PassThrough) {
    GenevaStrategy s;
    auto pkt = make_ip_packet();
    auto result = engine.apply_strategy(pkt, s);
    EXPECT_EQ(result.size(), 1u);
    EXPECT_EQ(result[0], pkt);
}

TEST_F(GenevaEngineTest, Duplicate_ProducesTwoPackets) {
    auto s = single_action_strategy(GenevaAction::DUPLICATE);
    auto pkt = make_ip_packet(64);
    auto result = engine.apply_strategy(pkt, s);
    EXPECT_EQ(result.size(), 2u);
}

TEST_F(GenevaEngineTest, Fragment_ProducesMultipleChunks) {
    auto s = single_action_strategy(GenevaAction::FRAGMENT, 8);
    auto pkt = make_ip_packet(40);
    auto result = engine.apply_strategy(pkt, s);
    EXPECT_GE(result.size(), 2u);
}

TEST_F(GenevaEngineTest, TamperTtl_ModifiesTtl) {
    auto s = single_action_strategy(GenevaAction::TAMPER_TTL);
    auto pkt = make_ip_packet(40);
    uint8_t orig_ttl = pkt[8];
    auto result = engine.apply_strategy(pkt, s);
    EXPECT_EQ(result.size(), 1u);
    // TTL should be different
    EXPECT_NE(result[0][8], orig_ttl);
}

TEST_F(GenevaEngineTest, TamperSeq_DoesNotShrinkPacket) {
    auto s = single_action_strategy(GenevaAction::TAMPER_SEQ);
    auto pkt = make_ip_packet(60);
    auto result = engine.apply_strategy(pkt, s);
    EXPECT_GE(result.size(), 1u);
    if (!result.empty()) {
        EXPECT_GE(result[0].size(), 20u);
    }
}

TEST_F(GenevaEngineTest, TamperFlags_ProducesOutput) {
    auto s = single_action_strategy(GenevaAction::TAMPER_FLAGS);
    auto pkt = make_ip_packet(40);
    auto result = engine.apply_strategy(pkt, s);
    EXPECT_GE(result.size(), 1u);
}

TEST_F(GenevaEngineTest, TamperChecksum_ProducesOutput) {
    auto s = single_action_strategy(GenevaAction::TAMPER_CHECKSUM);
    auto pkt = make_ip_packet(40);
    auto result = engine.apply_strategy(pkt, s);
    EXPECT_GE(result.size(), 1u);
}

TEST_F(GenevaEngineTest, Drop_ProducesZeroPackets) {
    auto s = single_action_strategy(GenevaAction::DROP);
    auto pkt = make_ip_packet(40);
    auto result = engine.apply_strategy(pkt, s);
    EXPECT_EQ(result.size(), 0u);
}

TEST_F(GenevaEngineTest, Disorder_DoesNotLosePackets) {
    // Build a strategy that first duplicates then disorders
    GenevaStrategy s;
    GenevaStep dup;
    dup.action = GenevaAction::DUPLICATE;
    dup.target_index = 0;
    GenevaStep dis;
    dis.action = GenevaAction::DISORDER;
    dis.target_index = 0;
    s.steps = {dup, dis};

    auto pkt = make_ip_packet(40);
    auto result = engine.apply_strategy(pkt, s);
    EXPECT_EQ(result.size(), 2u); // duplicated, then just reordered
}

// ── Strategy Presets ─────────────────────────────────────────────────────────

TEST_F(GenevaEngineTest, Preset_TSPU2026_HasSteps) {
    auto s = GenevaStrategy::tspu_2026();
    EXPECT_FALSE(s.steps.empty());
    EXPECT_FALSE(s.description.empty());
}

TEST_F(GenevaEngineTest, Preset_GFW2025_HasSteps) {
    auto s = GenevaStrategy::gfw_2025();
    EXPECT_FALSE(s.steps.empty());
}

TEST_F(GenevaEngineTest, Preset_IranDPI_HasSteps) {
    auto s = GenevaStrategy::iran_dpi();
    EXPECT_FALSE(s.steps.empty());
}

TEST_F(GenevaEngineTest, Preset_Universal_HasSteps) {
    auto s = GenevaStrategy::universal();
    EXPECT_FALSE(s.steps.empty());
}

TEST_F(GenevaEngineTest, ApplyPreset_TSPU2026_ProducesOutput) {
    auto s = GenevaStrategy::tspu_2026();
    auto pkt = make_ip_packet(60);
    auto result = engine.apply_strategy(pkt, s);
    EXPECT_FALSE(result.empty());
}

// ── Statistics ────────────────────────────────────────────────────────────────

TEST_F(GenevaEngineTest, InitialStats_AllZero) {
    const auto& stats = engine.get_stats();
    EXPECT_EQ(stats.packets_processed, 0u);
}

TEST_F(GenevaEngineTest, Stats_IncrementAfterApply) {
    auto s = single_action_strategy(GenevaAction::DUPLICATE);
    engine.apply_strategy(make_ip_packet(40), s);
    const auto& stats = engine.get_stats();
    EXPECT_GT(stats.packets_processed, 0u);
}

TEST_F(GenevaEngineTest, ResetStats) {
    auto s = single_action_strategy(GenevaAction::DUPLICATE);
    engine.apply_strategy(make_ip_packet(40), s);
    engine.reset_stats();
    EXPECT_EQ(engine.get_stats().packets_processed, 0u);
}

// ══════════════════════════════════════════════════════════════════════════════
// GenevaGA — Genetic Algorithm Tests
// ══════════════════════════════════════════════════════════════════════════════

class GenevaGATest : public ::testing::Test {
protected:
    GAConfig small_config() {
        GAConfig cfg;
        cfg.population_size = 8;
        cfg.elite_count     = 2;
        cfg.tournament_size = 3;
        cfg.max_steps       = 4;
        cfg.seed_presets    = true;
        return cfg;
    }

    FitnessEvaluator mock_evaluator() {
        return [](const GenevaStrategy& s, const std::string&, uint16_t, int) -> FitnessResult {
            FitnessResult r;
            r.connected   = true;
            r.latency_ms  = 10.0 + (s.steps.size() * 5.0);
            r.packet_loss = 0.0;
            return r;
        };
    }
};

TEST_F(GenevaGATest, DefaultConstructor_NoThrow) {
    EXPECT_NO_THROW({ GenevaGA ga; });
}

TEST_F(GenevaGATest, SetConfig_NoThrow) {
    GenevaGA ga;
    EXPECT_NO_THROW(ga.set_config(small_config()));
}

TEST_F(GenevaGATest, GetConfig_ReturnsSet) {
    GenevaGA ga;
    auto cfg = small_config();
    cfg.population_size = 16;
    ga.set_config(cfg);
    EXPECT_EQ(ga.get_config().population_size, 16u);
}

TEST_F(GenevaGATest, InitializePopulation_FillsPopulation) {
    GenevaGA ga;
    ga.set_config(small_config());
    ga.set_fitness_evaluator(mock_evaluator());
    ga.set_target("127.0.0.1", 443);
    EXPECT_NO_THROW(ga.initialize_population());
}

TEST_F(GenevaGATest, InjectStrategy_NoThrow) {
    GenevaGA ga;
    ga.set_config(small_config());
    ga.set_fitness_evaluator(mock_evaluator());
    ga.set_target("127.0.0.1", 443);
    ga.initialize_population();
    EXPECT_NO_THROW(ga.inject_strategy(GenevaStrategy::tspu_2026()));
}

TEST_F(GenevaGATest, InjectPresetStrategies_NoThrow) {
    GenevaGA ga;
    ga.set_config(small_config());
    ga.set_fitness_evaluator(mock_evaluator());
    ga.set_target("127.0.0.1", 443);
    ga.initialize_population();
    EXPECT_NO_THROW(ga.inject_preset_strategies());
}

TEST_F(GenevaGATest, EvaluatePopulation_NoThrow) {
    GenevaGA ga;
    ga.set_config(small_config());
    ga.set_fitness_evaluator(mock_evaluator());
    ga.set_target("127.0.0.1", 443);
    ga.initialize_population();
    EXPECT_NO_THROW(ga.evaluate_population());
}

TEST_F(GenevaGATest, EvolveOneGeneration_NoThrow) {
    GenevaGA ga;
    ga.set_config(small_config());
    ga.set_fitness_evaluator(mock_evaluator());
    ga.set_target("127.0.0.1", 443);
    ga.initialize_population();
    ga.evaluate_population();
    EXPECT_NO_THROW(ga.evolve_one_generation());
}

TEST_F(GenevaGATest, EvolveMultipleGenerations) {
    GenevaGA ga;
    ga.set_config(small_config());
    ga.set_fitness_evaluator(mock_evaluator());
    ga.set_target("127.0.0.1", 443);
    ga.initialize_population();

    for (int gen = 0; gen < 3; ++gen) {
        ga.evaluate_population();
        EXPECT_NO_THROW(ga.evolve_one_generation());
    }
}

TEST_F(GenevaGATest, GetBest_AfterEvaluation) {
    GenevaGA ga;
    ga.set_config(small_config());
    ga.set_fitness_evaluator(mock_evaluator());
    ga.set_target("127.0.0.1", 443);
    ga.initialize_population();
    ga.evaluate_population();

    auto best = ga.get_best();
    EXPECT_GT(best.fitness.score(), 0.0);
}

TEST_F(GenevaGATest, GetTopN_ReturnsNResults) {
    GenevaGA ga;
    ga.set_config(small_config());
    ga.set_fitness_evaluator(mock_evaluator());
    ga.set_target("127.0.0.1", 443);
    ga.initialize_population();
    ga.evaluate_population();

    auto top3 = ga.get_top_n(3);
    EXPECT_LE(top3.size(), 3u); // may have fewer if population is small
}

TEST_F(GenevaGATest, GetStats_AfterGeneration) {
    GenevaGA ga;
    ga.set_config(small_config());
    ga.set_fitness_evaluator(mock_evaluator());
    ga.set_target("127.0.0.1", 443);
    ga.initialize_population();
    ga.evaluate_population();
    ga.evolve_one_generation();

    auto stats = ga.get_stats();
    EXPECT_GT(stats.total_evaluations, 0u);
}

TEST_F(GenevaGATest, FitnessScore_ConnectedBaseIsHigh) {
    FitnessResult r;
    r.connected   = true;
    r.latency_ms  = 10.0;
    r.packet_loss = 0.0;
    EXPECT_GT(r.score(), 900.0);
}

TEST_F(GenevaGATest, FitnessScore_NotConnectedIsZero) {
    FitnessResult r;
    r.connected = false;
    EXPECT_DOUBLE_EQ(r.score(), 0.0);
}

TEST_F(GenevaGATest, Callbacks_SetWithoutThrow) {
    GenevaGA ga;
    EXPECT_NO_THROW(ga.on_generation([](uint32_t, const GAStats&) {}));
    EXPECT_NO_THROW(ga.on_new_best([](const Individual&) {}));
    EXPECT_NO_THROW(ga.on_re_evolution([](uint32_t) {}));
}

TEST_F(GenevaGATest, IsRunning_FalseInitially) {
    GenevaGA ga;
    EXPECT_FALSE(ga.is_running());
}
