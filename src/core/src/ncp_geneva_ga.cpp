#include "ncp_geneva_ga.hpp"
#include <sodium.h>
#include <algorithm>
#include <numeric>
#include <cassert>

namespace ncp {
namespace DPI {

// ======================================================================
//  CSPRNG helpers (libsodium)
// ======================================================================

uint32_t GenevaGA::csprng_uniform(uint32_t upper_bound) {
    if (upper_bound <= 1) return 0;
    return randombytes_uniform(upper_bound);
}

double GenevaGA::csprng_double() {
    uint32_t val = randombytes_uniform(1000000);
    return static_cast<double>(val) / 1000000.0;
}

// ======================================================================
//  Construction / Destruction
// ======================================================================

GenevaGA::GenevaGA() = default;

GenevaGA::~GenevaGA() {
    stop();
}

// ======================================================================
//  Configuration
// ======================================================================

void GenevaGA::set_config(const GAConfig& config) {
    config_ = config;
}

GAConfig GenevaGA::get_config() const {
    return config_;
}

void GenevaGA::set_fitness_evaluator(FitnessEvaluator evaluator) {
    fitness_evaluator_ = std::move(evaluator);
}

void GenevaGA::set_target(const std::string& host, uint16_t port) {
    target_host_ = host;
    target_port_ = port;
}

// ======================================================================
//  Population management
// ======================================================================

uint64_t GenevaGA::next_id() {
    return id_counter_.fetch_add(1, std::memory_order_relaxed);
}

GenevaAction GenevaGA::random_action() const {
    constexpr int count = 8;  // Number of GenevaAction values
    return static_cast<GenevaAction>(csprng_uniform(count));
}

GenevaStep GenevaGA::random_step() const {
    GenevaStep step;
    step.action = random_action();
    step.target_index = csprng_uniform(4);  // Target packets 0-3

    switch (step.action) {
        case GenevaAction::FRAGMENT:
            step.param = config_.min_fragment_size +
                csprng_uniform(static_cast<uint32_t>(
                    config_.max_fragment_size - config_.min_fragment_size + 1));
            step.description = "fragment(" + std::to_string(step.param) + ")";
            break;
        case GenevaAction::TAMPER_TTL:
            step.param = config_.min_ttl +
                csprng_uniform(static_cast<uint32_t>(
                    config_.max_ttl - config_.min_ttl + 1));
            step.description = "tamper_ttl(" + std::to_string(step.param) + ")";
            break;
        case GenevaAction::DUPLICATE:
            step.param = 0;
            step.description = "duplicate";
            break;
        case GenevaAction::DROP:
            step.param = 0;
            step.description = "drop";
            break;
        case GenevaAction::DISORDER:
            step.param = 0;
            step.description = "disorder";
            break;
        case GenevaAction::TAMPER_SEQ:
            step.param = csprng_uniform(65536);
            step.description = "tamper_seq(" + std::to_string(step.param) + ")";
            break;
        case GenevaAction::TAMPER_FLAGS:
            step.param = csprng_uniform(256);
            step.description = "tamper_flags(0x" + std::to_string(step.param) + ")";
            break;
        case GenevaAction::TAMPER_CHECKSUM:
            step.param = 0;
            step.description = "tamper_checksum";
            break;
    }
    return step;
}

void GenevaGA::initialize_population() {
    std::lock_guard<std::mutex> lock(population_mutex_);
    population_.clear();
    population_.reserve(config_.population_size);

    // Inject preset strategies if configured
    if (config_.seed_presets) {
        auto presets = {
            GenevaStrategy::tspu_2026(),
            GenevaStrategy::gfw_2025(),
            GenevaStrategy::iran_dpi(),
            GenevaStrategy::universal()
        };
        for (const auto& preset : presets) {
            if (population_.size() >= config_.population_size) break;
            Individual ind;
            ind.strategy = preset;
            ind.id = next_id();
            population_.push_back(std::move(ind));
        }
    }

    // Fill rest with random strategies
    while (population_.size() < config_.population_size) {
        Individual ind;
        ind.id = next_id();

        // Random step count between min and max
        size_t step_count = config_.min_steps +
            csprng_uniform(static_cast<uint32_t>(
                config_.max_steps - config_.min_steps + 1));

        for (size_t i = 0; i < step_count; ++i) {
            ind.strategy.steps.push_back(random_step());
        }
        ind.strategy.description = "random_gen0_" + std::to_string(ind.id);
        population_.push_back(std::move(ind));
    }
}

void GenevaGA::inject_strategy(const GenevaStrategy& s) {
    std::lock_guard<std::mutex> lock(population_mutex_);
    Individual ind;
    ind.strategy = s;
    ind.id = next_id();
    population_.push_back(std::move(ind));
}

void GenevaGA::inject_preset_strategies() {
    inject_strategy(GenevaStrategy::tspu_2026());
    inject_strategy(GenevaStrategy::gfw_2025());
    inject_strategy(GenevaStrategy::iran_dpi());
    inject_strategy(GenevaStrategy::universal());
}

// ======================================================================
//  Fitness evaluation
// ======================================================================

FitnessResult GenevaGA::evaluate_individual(const Individual& ind) {
    if (!fitness_evaluator_) {
        FitnessResult fail;
        return fail;
    }

    // Run multiple probes and aggregate
    double total_latency = 0.0;
    double total_loss = 0.0;
    int successes = 0;
    int total_retries = 0;

    for (int probe = 0; probe < config_.fitness_probes; ++probe) {
        FitnessResult r = fitness_evaluator_(
            ind.strategy, target_host_, target_port_,
            config_.fitness_timeout_ms);

        if (r.connected) ++successes;
        total_latency += r.latency_ms;
        total_loss += r.packet_loss;
        total_retries += r.retry_count;
    }

    FitnessResult result;
    int probes = config_.fitness_probes;
    result.connected = (successes > 0);
    result.latency_ms = total_latency / probes;
    result.packet_loss = total_loss / probes;
    result.retry_count = total_retries;
    return result;
}

void GenevaGA::evaluate_population() {
    std::lock_guard<std::mutex> lock(population_mutex_);

    for (auto& ind : population_) {
        ind.fitness = evaluate_individual(ind);
    }

    // Update stats
    {
        std::lock_guard<std::mutex> slock(stats_mutex_);
        stats_.total_evaluations += population_.size();
    }
}

// ======================================================================
//  Selection
// ======================================================================

Individual GenevaGA::tournament_select() const {
    // population_mutex_ must be held by caller
    assert(!population_.empty());

    size_t best_idx = csprng_uniform(static_cast<uint32_t>(population_.size()));
    double best_score = population_[best_idx].fitness.score();

    for (size_t i = 1; i < config_.tournament_size; ++i) {
        size_t idx = csprng_uniform(static_cast<uint32_t>(population_.size()));
        double s = population_[idx].fitness.score();
        if (s > best_score) {
            best_score = s;
            best_idx = idx;
        }
    }
    return population_[best_idx];
}

// ======================================================================
//  Crossover — single-point over steps vector
// ======================================================================

Individual GenevaGA::crossover(const Individual& parent_a, const Individual& parent_b) {
    Individual child;
    child.id = next_id();

    const auto& steps_a = parent_a.strategy.steps;
    const auto& steps_b = parent_b.strategy.steps;

    if (steps_a.empty() && steps_b.empty()) {
        child.strategy.steps.push_back(random_step());
    } else if (steps_a.empty()) {
        child.strategy = parent_b.strategy;
    } else if (steps_b.empty()) {
        child.strategy = parent_a.strategy;
    } else {
        // Single-point crossover
        size_t cut_a = csprng_uniform(static_cast<uint32_t>(steps_a.size()));
        size_t cut_b = csprng_uniform(static_cast<uint32_t>(steps_b.size()));

        // First half from parent A, second half from parent B
        for (size_t i = 0; i <= cut_a && i < steps_a.size(); ++i) {
            child.strategy.steps.push_back(steps_a[i]);
        }
        for (size_t i = cut_b; i < steps_b.size(); ++i) {
            child.strategy.steps.push_back(steps_b[i]);
        }

        // Enforce max_steps
        while (child.strategy.steps.size() > config_.max_steps) {
            child.strategy.steps.pop_back();
        }
    }

    child.strategy.description =
        parent_a.strategy.description + " x " + parent_b.strategy.description;
    child.generation = std::max(parent_a.generation, parent_b.generation) + 1;

    return child;
}

// ======================================================================
//  Mutation operators
// ======================================================================

void GenevaGA::mutate(Individual& ind) {
    if (csprng_double() >= config_.mutation_rate) return;

    auto& s = ind.strategy;

    // Roll for each mutation type independently
    if (csprng_double() < config_.swap_actions_rate)
        mutate_swap_actions(s);

    if (csprng_double() < config_.change_fragment_rate)
        mutate_change_fragment_size(s);

    if (csprng_double() < config_.step_add_rate)
        mutate_add_step(s);

    if (csprng_double() < config_.step_remove_rate)
        mutate_remove_step(s);

    if (csprng_double() < config_.change_ttl_rate)
        mutate_change_ttl(s);

    if (csprng_double() < config_.change_target_rate)
        mutate_change_target_index(s);
}

void GenevaGA::mutate_swap_actions(GenevaStrategy& s) {
    if (s.steps.size() < 2) return;
    size_t i = csprng_uniform(static_cast<uint32_t>(s.steps.size()));
    size_t j = csprng_uniform(static_cast<uint32_t>(s.steps.size()));
    if (i != j) {
        std::swap(s.steps[i].action, s.steps[j].action);
        std::swap(s.steps[i].param, s.steps[j].param);
        std::swap(s.steps[i].description, s.steps[j].description);
    }
}

void GenevaGA::mutate_change_fragment_size(GenevaStrategy& s) {
    for (auto& step : s.steps) {
        if (step.action == GenevaAction::FRAGMENT) {
            // Perturb by ±20%
            int current = static_cast<int>(step.param);
            int delta_range = std::max(current / 5, 1);
            int delta = static_cast<int>(csprng_uniform(
                static_cast<uint32_t>(delta_range * 2 + 1))) - delta_range;
            int new_val = current + delta;

            new_val = std::max(new_val, static_cast<int>(config_.min_fragment_size));
            new_val = std::min(new_val, static_cast<int>(config_.max_fragment_size));
            step.param = static_cast<size_t>(new_val);
            step.description = "fragment(" + std::to_string(step.param) + ")";
            break;  // Mutate only first fragment step
        }
    }
}

void GenevaGA::mutate_add_step(GenevaStrategy& s) {
    if (s.steps.size() >= config_.max_steps) return;
    size_t pos = csprng_uniform(static_cast<uint32_t>(s.steps.size() + 1));
    s.steps.insert(s.steps.begin() + static_cast<ptrdiff_t>(pos), random_step());
}

void GenevaGA::mutate_remove_step(GenevaStrategy& s) {
    if (s.steps.size() <= config_.min_steps) return;
    size_t pos = csprng_uniform(static_cast<uint32_t>(s.steps.size()));
    s.steps.erase(s.steps.begin() + static_cast<ptrdiff_t>(pos));
}

void GenevaGA::mutate_change_ttl(GenevaStrategy& s) {
    for (auto& step : s.steps) {
        if (step.action == GenevaAction::TAMPER_TTL) {
            step.param = config_.min_ttl +
                csprng_uniform(static_cast<uint32_t>(
                    config_.max_ttl - config_.min_ttl + 1));
            step.description = "tamper_ttl(" + std::to_string(step.param) + ")";
            break;
        }
    }
}

void GenevaGA::mutate_change_target_index(GenevaStrategy& s) {
    if (s.steps.empty()) return;
    size_t idx = csprng_uniform(static_cast<uint32_t>(s.steps.size()));
    s.steps[idx].target_index = csprng_uniform(4);
}

// ======================================================================
//  Evolution (one generation)
// ======================================================================

void GenevaGA::sort_population() {
    // population_mutex_ must be held by caller
    std::sort(population_.begin(), population_.end(),
        [](const Individual& a, const Individual& b) {
            return a.fitness.score() > b.fitness.score();
        });
}

void GenevaGA::evolve_one_generation() {
    std::lock_guard<std::mutex> lock(population_mutex_);

    if (population_.empty()) return;

    sort_population();

    double old_best = population_.empty() ? 0.0 : population_[0].fitness.score();

    // New population starts with elites
    std::vector<Individual> new_pop;
    new_pop.reserve(config_.population_size);

    size_t elite = std::min(config_.elite_count, population_.size());
    for (size_t i = 0; i < elite; ++i) {
        new_pop.push_back(population_[i]);
    }

    // Fill rest via selection + crossover + mutation
    while (new_pop.size() < config_.population_size) {
        Individual parent_a = tournament_select();

        if (csprng_double() < config_.crossover_rate) {
            Individual parent_b = tournament_select();
            Individual child = crossover(parent_a, parent_b);
            mutate(child);
            new_pop.push_back(std::move(child));
        } else {
            // Clone with mutation
            parent_a.id = next_id();
            parent_a.generation += 1;
            mutate(parent_a);
            new_pop.push_back(std::move(parent_a));
        }
    }

    population_ = std::move(new_pop);

    // Evaluate the new population (without lock — we already hold it,
    // so we call evaluator inline)
    for (auto& ind : population_) {
        if (ind.fitness.score() == 0.0) {  // Only unevaluated
            ind.fitness = evaluate_individual(ind);
        }
    }

    sort_population();

    // Update stats
    {
        std::lock_guard<std::mutex> slock(stats_mutex_);
        stats_.current_generation++;
        stats_.population_size = population_.size();
        stats_.total_evaluations += population_.size();
        stats_.last_evolution = std::chrono::steady_clock::now();

        if (!population_.empty()) {
            stats_.best_fitness = population_[0].fitness.score();
            stats_.worst_fitness = population_.back().fitness.score();
            stats_.best_strategy_desc = population_[0].strategy.description;

            double sum = 0.0;
            for (const auto& ind : population_) {
                sum += ind.fitness.score();
            }
            stats_.avg_fitness = sum / static_cast<double>(population_.size());
        }
    }

    // Fire callbacks
    double new_best = population_.empty() ? 0.0 : population_[0].fitness.score();

    if (on_generation_) {
        std::lock_guard<std::mutex> slock(stats_mutex_);
        on_generation_(stats_.current_generation, stats_);
    }

    if (new_best > old_best && on_new_best_ && !population_.empty()) {
        on_new_best_(population_[0]);
    }
}

// ======================================================================
//  Adaptive health check
// ======================================================================

bool GenevaGA::check_best_health() {
    Individual best;
    {
        std::lock_guard<std::mutex> lock(population_mutex_);
        if (population_.empty()) return false;
        best = population_[0];
    }

    FitnessResult result = evaluate_individual(best);
    return result.connected;
}

// ======================================================================
//  Background threads
// ======================================================================

bool GenevaGA::start() {
    if (running_.load()) return false;
    if (!fitness_evaluator_) return false;

    running_.store(true);

    if (population_.empty()) {
        initialize_population();
    }

    // Evolution thread
    evolution_thread_ = std::thread([this]() {
        evolution_loop();
    });

    // Health check thread
    health_thread_ = std::thread([this]() {
        health_check_loop();
    });

    return true;
}

void GenevaGA::stop() {
    running_.store(false);
    if (evolution_thread_.joinable()) evolution_thread_.join();
    if (health_thread_.joinable()) health_thread_.join();
}

bool GenevaGA::is_running() const {
    return running_.load();
}

void GenevaGA::evolution_loop() {
    while (running_.load()) {
        evaluate_population();
        evolve_one_generation();

        // Check stop conditions
        {
            std::lock_guard<std::mutex> slock(stats_mutex_);
            if (stats_.current_generation >= config_.max_generations) {
                break;
            }
            if (stats_.best_fitness >= config_.target_fitness) {
                // Target reached — slow down evolution but keep running
                // for adaptive response to DPI changes
            }
        }

        // Sleep between generations
        for (int i = 0; i < config_.evolution_interval_sec && running_.load(); ++i) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }
}

void GenevaGA::health_check_loop() {
    while (running_.load()) {
        // Sleep first
        for (int i = 0; i < config_.health_check_interval_sec && running_.load(); ++i) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }

        if (!running_.load()) break;

        bool healthy = check_best_health();

        if (!healthy) {
            consecutive_health_fails_++;

            if (consecutive_health_fails_ >= config_.consecutive_failures) {
                // TSPU/DPI updated! Current strategy is dead.
                // Trigger re-evolution: reset population, keep elites,
                // inject fresh random individuals
                {
                    std::lock_guard<std::mutex> lock(population_mutex_);

                    // Keep top elites
                    sort_population();
                    size_t keep = std::min(config_.elite_count, population_.size());
                    std::vector<Individual> survivors(
                        population_.begin(),
                        population_.begin() + static_cast<ptrdiff_t>(keep));

                    population_ = std::move(survivors);

                    // Re-inject presets
                    if (config_.seed_presets) {
                        auto presets = {
                            GenevaStrategy::tspu_2026(),
                            GenevaStrategy::gfw_2025(),
                            GenevaStrategy::iran_dpi(),
                            GenevaStrategy::universal()
                        };
                        for (const auto& p : presets) {
                            if (population_.size() >= config_.population_size) break;
                            Individual ind;
                            ind.strategy = p;
                            ind.id = next_id();
                            population_.push_back(std::move(ind));
                        }
                    }

                    // Fill with fresh random
                    while (population_.size() < config_.population_size) {
                        Individual ind;
                        ind.id = next_id();
                        size_t step_count = config_.min_steps +
                            csprng_uniform(static_cast<uint32_t>(
                                config_.max_steps - config_.min_steps + 1));
                        for (size_t i = 0; i < step_count; ++i) {
                            ind.strategy.steps.push_back(random_step());
                        }
                        ind.strategy.description = "re_evo_" + std::to_string(ind.id);
                        population_.push_back(std::move(ind));
                    }
                }

                {
                    std::lock_guard<std::mutex> slock(stats_mutex_);
                    stats_.re_evolutions++;
                }

                if (on_re_evolution_) {
                    std::lock_guard<std::mutex> slock(stats_mutex_);
                    on_re_evolution_(stats_.re_evolutions);
                }

                consecutive_health_fails_ = 0;
            }
        } else {
            consecutive_health_fails_ = 0;
        }
    }
}

// ======================================================================
//  Results
// ======================================================================

Individual GenevaGA::get_best() const {
    std::lock_guard<std::mutex> lock(population_mutex_);
    if (population_.empty()) return Individual{};

    auto it = std::max_element(population_.begin(), population_.end(),
        [](const Individual& a, const Individual& b) {
            return a.fitness.score() < b.fitness.score();
        });
    return *it;
}

GenevaStrategy GenevaGA::get_best_strategy() const {
    return get_best().strategy;
}

std::vector<Individual> GenevaGA::get_top_n(size_t n) const {
    std::lock_guard<std::mutex> lock(population_mutex_);

    std::vector<Individual> sorted = population_;
    std::sort(sorted.begin(), sorted.end(),
        [](const Individual& a, const Individual& b) {
            return a.fitness.score() > b.fitness.score();
        });

    if (sorted.size() > n) sorted.resize(n);
    return sorted;
}

GAStats GenevaGA::get_stats() const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    return stats_;
}

// ======================================================================
//  Callbacks
// ======================================================================

void GenevaGA::on_generation(GenerationCallback cb) {
    on_generation_ = std::move(cb);
}

void GenevaGA::on_new_best(NewBestCallback cb) {
    on_new_best_ = std::move(cb);
}

void GenevaGA::on_re_evolution(ReEvolutionCallback cb) {
    on_re_evolution_ = std::move(cb);
}

} // namespace DPI
} // namespace ncp
