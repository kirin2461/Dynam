#ifndef NCP_GENEVA_GA_HPP
#define NCP_GENEVA_GA_HPP

#include "ncp_geneva_engine.hpp"
#include <cstdint>
#include <cstddef>
#include <vector>
#include <string>
#include <functional>
#include <mutex>
#include <atomic>
#include <thread>
#include <chrono>

namespace ncp {
namespace DPI {

// ======================================================================
//  Fitness result for a single strategy evaluation
// ======================================================================
struct FitnessResult {
    bool    connected      = false;   // Primary: did we get a response?
    double  latency_ms     = 9999.0;  // Secondary: round-trip time
    double  packet_loss    = 1.0;     // Secondary: 0.0 = no loss, 1.0 = total
    int     retry_count    = 0;       // How many retries were needed

    // Combined scalar fitness: higher = better
    // connected gives a massive bonus; latency and loss are penalties
    double score() const {
        if (!connected) return 0.0;
        // Base 1000 for successful connect
        // Subtract latency penalty (capped at 500)
        // Subtract loss penalty (up to 300)
        double s = 1000.0;
        s -= std::min(latency_ms * 0.5, 500.0);
        s -= packet_loss * 300.0;
        s -= retry_count * 50.0;
        return std::max(s, 1.0);  // Floor at 1.0 if connected
    }
};

// ======================================================================
//  Individual in the population
// ======================================================================
struct Individual {
    GenevaStrategy strategy;
    FitnessResult  fitness;
    uint32_t       generation = 0;
    uint64_t       id = 0;            // Unique ID for tracking
};

// ======================================================================
//  GA Configuration
// ======================================================================
struct GAConfig {
    // Population
    size_t population_size       = 64;       // 50-100 recommended
    size_t elite_count           = 4;        // Survivors per generation
    size_t tournament_size       = 5;        // Tournament selection k

    // Mutation rates (probabilities 0.0 - 1.0)
    double mutation_rate         = 0.3;      // Per-individual mutation chance
    double crossover_rate        = 0.7;      // Crossover vs clone
    double step_add_rate         = 0.15;     // Add a new random step
    double step_remove_rate      = 0.10;     // Remove a random step
    double swap_actions_rate     = 0.20;     // Swap two actions in steps
    double change_fragment_rate  = 0.20;     // Mutate fragment size param
    double change_ttl_rate       = 0.15;     // Mutate TTL value
    double change_target_rate    = 0.15;     // Mutate target_index

    // Strategy constraints
    size_t min_steps             = 1;
    size_t max_steps             = 12;       // Prevent bloat
    size_t max_fragment_size     = 1400;
    size_t min_fragment_size     = 8;
    uint8_t max_ttl              = 255;
    uint8_t min_ttl              = 1;

    // Evolution loop
    int    evolution_interval_sec = 300;     // Run GA every N seconds
    int    fitness_timeout_ms     = 5000;    // TCP connect timeout
    int    fitness_probes         = 3;       // Probes per evaluation
    size_t max_generations        = 1000;    // Stop condition
    double target_fitness         = 950.0;   // Stop if reached

    // Adaptive re-evolution
    int    health_check_interval_sec = 60;   // Check best strategy health
    int    consecutive_failures      = 3;    // Trigger re-evolution after N fails

    // Seed strategies (injected into initial population)
    bool   seed_presets          = true;     // Include tspu_2026, gfw_2025, etc.
};

// ======================================================================
//  GA Statistics
// ======================================================================
struct GAStats {
    uint32_t current_generation  = 0;
    size_t   population_size     = 0;
    double   best_fitness        = 0.0;
    double   avg_fitness         = 0.0;
    double   worst_fitness       = 0.0;
    uint64_t total_evaluations   = 0;
    uint32_t re_evolutions       = 0;        // Times adaptive loop triggered
    std::chrono::steady_clock::time_point last_evolution;
    std::string best_strategy_desc;
};

// ======================================================================
//  Fitness evaluator callback
// ======================================================================
// The user provides this: given a strategy and target, attempt a real
// TCP connection through the GenevaEngine and report results.
// This decouples the GA from network I/O implementation.
using FitnessEvaluator = std::function<FitnessResult(
    const GenevaStrategy& strategy,
    const std::string& target_host,
    uint16_t target_port,
    int timeout_ms
)>;

// ======================================================================
//  GenevaGA — Genetic Algorithm Engine
// ======================================================================
class GenevaGA {
public:
    GenevaGA();
    ~GenevaGA();

    // ---- Configuration ----
    void set_config(const GAConfig& config);
    GAConfig get_config() const;

    // ---- Fitness evaluator (MUST be set before start) ----
    void set_fitness_evaluator(FitnessEvaluator evaluator);

    // ---- Target endpoint for fitness probes ----
    void set_target(const std::string& host, uint16_t port);

    // ---- Population management ----
    void initialize_population();                  // Create initial pop
    void inject_strategy(const GenevaStrategy& s); // Add external strategy
    void inject_preset_strategies();               // Inject tspu/gfw/iran/universal

    // ---- Single-generation evolution (manual control) ----
    void evaluate_population();                    // Run fitness on all
    void evolve_one_generation();                  // Select + crossover + mutate

    // ---- Adaptive loop (background thread) ----
    bool start();                                  // Start background evolution
    void stop();                                   // Stop background thread
    bool is_running() const;

    // ---- Results ----
    Individual get_best() const;                   // Current best individual
    GenevaStrategy get_best_strategy() const;      // Convenience
    std::vector<Individual> get_top_n(size_t n) const;
    GAStats get_stats() const;

    // ---- Callbacks ----
    using GenerationCallback = std::function<void(uint32_t gen, const GAStats& stats)>;
    using NewBestCallback = std::function<void(const Individual& best)>;
    using ReEvolutionCallback = std::function<void(uint32_t trigger_count)>;

    void on_generation(GenerationCallback cb);
    void on_new_best(NewBestCallback cb);
    void on_re_evolution(ReEvolutionCallback cb);

private:
    // ---- Genetic operators ----
    Individual tournament_select() const;
    Individual crossover(const Individual& parent_a, const Individual& parent_b);
    void mutate(Individual& ind);

    // ---- Mutation operators ----
    void mutate_swap_actions(GenevaStrategy& s);
    void mutate_change_fragment_size(GenevaStrategy& s);
    void mutate_add_step(GenevaStrategy& s);
    void mutate_remove_step(GenevaStrategy& s);
    void mutate_change_ttl(GenevaStrategy& s);
    void mutate_change_target_index(GenevaStrategy& s);

    // ---- Helpers ----
    GenevaStep random_step() const;
    GenevaAction random_action() const;
    uint64_t next_id();
    void sort_population();                         // By fitness descending
    FitnessResult evaluate_individual(const Individual& ind);

    // ---- Adaptive health check ----
    bool check_best_health();

    // ---- Background thread ----
    void evolution_loop();
    void health_check_loop();

    // ---- CSPRNG ----
    static uint32_t csprng_uniform(uint32_t upper_bound);
    static double   csprng_double();               // [0.0, 1.0)

    // ---- State ----
    GAConfig config_;
    std::vector<Individual> population_;
    mutable std::mutex population_mutex_;

    FitnessEvaluator fitness_evaluator_;
    std::string target_host_;
    uint16_t target_port_ = 443;

    std::atomic<bool> running_{false};
    std::thread evolution_thread_;
    std::thread health_thread_;

    std::atomic<uint64_t> id_counter_{0};
    GAStats stats_;
    mutable std::mutex stats_mutex_;

    // Callbacks
    GenerationCallback   on_generation_;
    NewBestCallback      on_new_best_;
    ReEvolutionCallback  on_re_evolution_;

    int consecutive_health_fails_ = 0;
};

} // namespace DPI
} // namespace ncp

#endif // NCP_GENEVA_GA_HPP
