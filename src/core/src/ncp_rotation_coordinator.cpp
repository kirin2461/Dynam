/**
 * @file ncp_rotation_coordinator.cpp
 * @brief Coordinated identity rotation with anti-correlation engine
 *
 * Threading model:
 *   - mu protects ALL mutable state: config, ls[], stats, event_log, last_corr
 *   - Callbacks (rotation_cb, correlation_cb) are called WITH lock held for
 *     state snapshot consistency, but callbacks MUST NOT call back into
 *     RotationCoordinator (would deadlock). This is documented in the header.
 *   - Cascade (coordinated L7 rotations after L2) uses non-blocking scheduling:
 *     pending layers get their next_rotation set to now+stagger, and the
 *     scheduler picks them up naturally. No blocking sleep in cascade.
 *   - interruptible_sleep_ms() releases mu before sleeping.
 */

#include "ncp_rotation_coordinator.hpp"
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <condition_variable>
#include <deque>
#include <mutex>
#include <numeric>
#include <thread>
#include <sodium.h>

namespace ncp {
namespace DPI {

static uint32_t jittered_interval_ms(
    uint32_t base_sec, double jitter_factor, uint32_t min_sec)
{
    if (base_sec == 0) return min_sec * 1000;
    uint32_t base_ms = base_sec * 1000;
    uint32_t jr = static_cast<uint32_t>(base_ms * jitter_factor);
    uint32_t jitter = jr > 0 ? randombytes_uniform(2 * jr + 1) : 0;
    int64_t result = static_cast<int64_t>(base_ms) - jr + jitter;
    int64_t floor_ms = static_cast<int64_t>(min_sec) * 1000;
    if (result < floor_ms) result = floor_ms;
    return static_cast<uint32_t>(result);
}

static uint32_t random_stagger_ms(uint32_t lo, uint32_t hi) {
    if (hi <= lo) return lo;
    return lo + randombytes_uniform(hi - lo + 1);
}

static double pearson_r(const std::vector<double>& x, const std::vector<double>& y) {
    size_t n = std::min(x.size(), y.size());
    if (n < 3) return 0.0;
    double sx=0, sy=0, sxy=0, sx2=0, sy2=0;
    for (size_t i = 0; i < n; ++i) {
        sx += x[i]; sy += y[i];
        sxy += x[i]*y[i]; sx2 += x[i]*x[i]; sy2 += y[i]*y[i];
    }
    double d = std::sqrt((n*sx2-sx*sx)*(n*sy2-sy*sy));
    if (d < 1e-10) return 0.0;
    return (n*sxy - sx*sy) / d;
}

struct RotationCoordinator::Impl {
    RotationCoordinatorConfig config;
    RotationCallback rotation_cb;
    CorrelationCallback correlation_cb;
    std::atomic<bool> running{false};
    std::thread scheduler_thread;
    mutable std::mutex mu;
    std::condition_variable cv;

    struct LayerState {
        std::chrono::steady_clock::time_point next_rotation;
        std::deque<std::chrono::steady_clock::time_point> history;
        std::deque<double> intervals;
        uint64_t count = 0;
    };
    std::array<LayerState, ROTATION_LAYER_COUNT> ls;
    std::deque<RotationEvent> event_log;
    static constexpr size_t MAX_LOG = 200;
    std::vector<CorrelationResult> last_corr;
    RotationStats stats{};

    // --- All *_locked() methods require mu to be held by caller ---

    void schedule_next_locked(RotationLayer layer) {
        auto i = static_cast<size_t>(layer);
        const auto& lc = config.layers[i];
        uint32_t ms = jittered_interval_ms(
            lc.base_interval_sec, lc.jitter_factor, lc.min_interval_sec);
        ls[i].next_rotation =
            std::chrono::steady_clock::now() + std::chrono::milliseconds(ms);
    }

    void record_event_locked(RotationLayer layer) {
        auto i = static_cast<size_t>(layer);
        auto now = std::chrono::steady_clock::now();
        double interval_sec = 0;
        if (!ls[i].history.empty()) {
            interval_sec = std::chrono::duration<double>(
                now - ls[i].history.back()).count();
            ls[i].intervals.push_back(interval_sec);
            if (ls[i].intervals.size() > config.correlation_window)
                ls[i].intervals.pop_front();
        }
        ls[i].history.push_back(now);
        if (ls[i].history.size() > config.correlation_window + 1)
            ls[i].history.pop_front();
        ls[i].count++;
        stats.rotation_counts[i]++;

        // FIX: actual_interval_ms instead of truncated _sec
        uint32_t interval_ms = static_cast<uint32_t>(interval_sec * 1000.0);
        RotationEvent ev{layer, now, interval_ms};
        event_log.push_back(ev);
        if (event_log.size() > MAX_LOG) event_log.pop_front();
    }

    // Execute rotation for one layer. Caller MUST hold mu.
    // Records event under lock, then calls callback (still under lock —
    // callback must not re-enter RotationCoordinator).
    void exec_rotation_locked(RotationLayer layer) {
        record_event_locked(layer);
        if (rotation_cb) rotation_cb(layer);
    }

    // FIX HIGH: Coordinated rotation with proper locking.
    // FIX MEDIUM: No blocking sleep in cascade — schedule as timed events.
    //
    // Pattern: lock -> record trigger -> compute pending list ->
    //          schedule pending as near-future timed events -> unlock.
    // Scheduler loop naturally picks up pending layers on next iteration.
    void exec_coordinated_locked(RotationLayer trigger) {
        // 1. Rotate the trigger layer immediately
        exec_rotation_locked(trigger);

        if (trigger != RotationLayer::L2_IDENTITY) return;
        stats.coordinated_rotations++;

        // 2. Schedule L7 layers as near-future timed events with stagger
        auto now = std::chrono::steady_clock::now();

        auto schedule_if = [&](bool flag, RotationLayer rl) {
            auto idx = static_cast<size_t>(rl);
            if (flag && config.layers[idx].enabled) {
                uint32_t stagger = random_stagger_ms(
                    config.stagger_min_ms, config.stagger_max_ms);
                ls[idx].next_rotation =
                    now + std::chrono::milliseconds(stagger);
            }
        };

        schedule_if(config.coordinate_tls_with_l2,    RotationLayer::L7_TLS);
        schedule_if(config.coordinate_timing_with_l2, RotationLayer::L7_TIMING);
        schedule_if(config.coordinate_dummy_with_l2,  RotationLayer::L7_DUMMY);
        schedule_if(config.coordinate_geneva_with_l2, RotationLayer::L7_GENEVA);

        // 3. Wake scheduler so it picks up the near-future events
        cv.notify_all();
    }

    // FIX MEDIUM: check_correlation now returns per-layer delays.
    // Returns array of delays per layer (0 = no delay needed).
    std::array<uint32_t, ROTATION_LAYER_COUNT> check_correlation_locked() {
        last_corr.clear();
        std::array<uint32_t, ROTATION_LAYER_COUNT> per_layer_delay{};

        for (size_t i = 0; i < ROTATION_LAYER_COUNT; ++i) {
            for (size_t j = i + 1; j < ROTATION_LAYER_COUNT; ++j) {
                if (ls[i].intervals.size() < 3 ||
                    ls[j].intervals.size() < 3) continue;

                size_t n = std::min(ls[i].intervals.size(),
                                    ls[j].intervals.size());
                std::vector<double> vi(ls[i].intervals.end() - n,
                                       ls[i].intervals.end());
                std::vector<double> vj(ls[j].intervals.end() - n,
                                       ls[j].intervals.end());
                double r = pearson_r(vi, vj);

                CorrelationResult cr;
                cr.layer_a = static_cast<RotationLayer>(i);
                cr.layer_b = static_cast<RotationLayer>(j);
                cr.pearson_r = r;
                cr.is_correlated = std::fabs(r) > config.correlation_threshold;
                cr.injected_delay_ms = 0;

                if (cr.is_correlated) {
                    uint32_t d = randombytes_uniform(
                        config.decorrelation_max_delay_sec * 1000 + 1);
                    cr.injected_delay_ms = d;

                    // FIX: Apply delay only to the layers in this pair
                    per_layer_delay[i] = std::max(per_layer_delay[i], d);
                    per_layer_delay[j] = std::max(per_layer_delay[j], d);

                    stats.correlation_detections++;
                    stats.total_decorrelation_delay_ms += d;
                    if (correlation_cb) correlation_cb(cr);
                }
                last_corr.push_back(cr);
            }
        }
        return per_layer_delay;
    }

    // Interruptible sleep that releases mu.
    // Caller must NOT hold mu when calling this.
    void interruptible_sleep_ms(uint32_t ms) {
        auto deadline = std::chrono::steady_clock::now() +
                        std::chrono::milliseconds(ms);
        while (std::chrono::steady_clock::now() < deadline && running.load()) {
            std::unique_lock<std::mutex> lk(mu);
            cv.wait_until(lk, std::min(deadline,
                std::chrono::steady_clock::now() +
                std::chrono::milliseconds(200)),
                [this]{ return !running.load(); });
        }
    }

    // --- Scheduler loop ---
    // FIX: check_correlation once per tick, per-layer delays,
    //      all state access under mu.
    void scheduler_loop() {
        while (running.load()) {
            std::unique_lock<std::mutex> lock(mu);

            // Find earliest due rotation
            auto earliest = std::chrono::steady_clock::time_point::max();
            for (size_t i = 0; i < ROTATION_LAYER_COUNT; ++i) {
                if (!config.layers[i].enabled) continue;
                if (ls[i].next_rotation < earliest)
                    earliest = ls[i].next_rotation;
            }

            cv.wait_until(lock, earliest, [this]{ return !running.load(); });
            if (!running.load()) break;

            auto now = std::chrono::steady_clock::now();

            // Collect which layers are due
            std::vector<size_t> due_layers;
            for (size_t i = 0; i < ROTATION_LAYER_COUNT; ++i) {
                if (!config.layers[i].enabled) continue;
                if (ls[i].next_rotation <= now)
                    due_layers.push_back(i);
            }

            if (due_layers.empty()) continue;

            // FIX: Single correlation check per tick
            auto per_layer_delay = check_correlation_locked();

            // Apply per-layer decorrelation delays to due layers
            // by pushing their next_rotation forward
            bool any_delayed = false;
            for (size_t i : due_layers) {
                if (per_layer_delay[i] > 0) {
                    ls[i].next_rotation =
                        now + std::chrono::milliseconds(per_layer_delay[i]);
                    any_delayed = true;
                }
            }

            // If any layers were delayed, re-loop to pick up new times
            if (any_delayed) continue;

            // Fire all non-delayed due layers
            for (size_t i : due_layers) {
                auto layer = static_cast<RotationLayer>(i);
                exec_coordinated_locked(layer);
                schedule_next_locked(layer);
            }
        }
    }
};

// ---- Public API ----

RotationCoordinator::RotationCoordinator() : impl_(std::make_unique<Impl>()) {}
RotationCoordinator::~RotationCoordinator() {
    if (impl_ && impl_->running.load()) stop();
}
RotationCoordinator::RotationCoordinator(RotationCoordinator&&) noexcept = default;
RotationCoordinator& RotationCoordinator::operator=(RotationCoordinator&&) noexcept = default;

void RotationCoordinator::set_config(const RotationCoordinatorConfig& c) {
    std::lock_guard<std::mutex> lk(impl_->mu); impl_->config = c;
}
RotationCoordinatorConfig RotationCoordinator::get_config() const {
    std::lock_guard<std::mutex> lk(impl_->mu); return impl_->config;
}
void RotationCoordinator::set_rotation_callback(RotationCallback cb) {
    std::lock_guard<std::mutex> lk(impl_->mu); impl_->rotation_cb = std::move(cb);
}
void RotationCoordinator::set_correlation_callback(CorrelationCallback cb) {
    std::lock_guard<std::mutex> lk(impl_->mu); impl_->correlation_cb = std::move(cb);
}

void RotationCoordinator::start() {
    if (impl_->running.load()) return;
    impl_->running = true;
    {
        std::lock_guard<std::mutex> lk(impl_->mu);
        for (size_t i = 0; i < ROTATION_LAYER_COUNT; ++i)
            if (impl_->config.layers[i].enabled)
                impl_->schedule_next_locked(static_cast<RotationLayer>(i));
    }
    impl_->scheduler_thread = std::thread(&Impl::scheduler_loop, impl_.get());
}

void RotationCoordinator::stop() {
    impl_->running = false;
    impl_->cv.notify_all();
    if (impl_->scheduler_thread.joinable()) impl_->scheduler_thread.join();
}

bool RotationCoordinator::is_running() const { return impl_->running.load(); }

// FIX HIGH: rotate_now() now holds lock for all state access.
void RotationCoordinator::rotate_now(RotationLayer layer) {
    if (!impl_->running.load()) return;
    {
        std::lock_guard<std::mutex> lk(impl_->mu);
        impl_->exec_coordinated_locked(layer);
        impl_->schedule_next_locked(layer);
    }
    impl_->cv.notify_all();
}

// FIX LOW: rotate_all() now uses stagger to avoid perfect correlation.
void RotationCoordinator::rotate_all() {
    if (!impl_->running.load()) return;
    std::lock_guard<std::mutex> lk(impl_->mu);
    auto now = std::chrono::steady_clock::now();
    bool first = true;
    for (size_t i = 0; i < ROTATION_LAYER_COUNT; ++i) {
        if (!impl_->config.layers[i].enabled) continue;
        auto layer = static_cast<RotationLayer>(i);
        if (first) {
            // First layer fires immediately
            impl_->exec_rotation_locked(layer);
            impl_->schedule_next_locked(layer);
            first = false;
        } else {
            // Subsequent layers get staggered scheduling
            uint32_t stagger = random_stagger_ms(
                impl_->config.stagger_min_ms, impl_->config.stagger_max_ms);
            impl_->ls[i].next_rotation =
                now + std::chrono::milliseconds(stagger);
        }
    }
    impl_->cv.notify_all();
}

std::chrono::milliseconds RotationCoordinator::time_until_next(
    RotationLayer layer) const
{
    std::lock_guard<std::mutex> lk(impl_->mu);
    auto now = std::chrono::steady_clock::now();
    auto& nr = impl_->ls[static_cast<size_t>(layer)].next_rotation;
    if (nr <= now) return std::chrono::milliseconds(0);
    return std::chrono::duration_cast<std::chrono::milliseconds>(nr - now);
}

std::vector<RotationEvent> RotationCoordinator::get_recent_events(
    size_t max_count) const
{
    std::lock_guard<std::mutex> lk(impl_->mu);
    size_t n = std::min(max_count, impl_->event_log.size());
    return {impl_->event_log.end() - n, impl_->event_log.end()};
}

std::vector<CorrelationResult>
RotationCoordinator::get_correlation_results() const {
    std::lock_guard<std::mutex> lk(impl_->mu); return impl_->last_corr;
}

RotationStats RotationCoordinator::get_stats() const {
    std::lock_guard<std::mutex> lk(impl_->mu); return impl_->stats;
}
void RotationCoordinator::reset_stats() {
    std::lock_guard<std::mutex> lk(impl_->mu); impl_->stats = RotationStats{};
}

} // namespace DPI
} // namespace ncp
