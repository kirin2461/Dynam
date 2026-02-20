/**
 * @file ncp_rotation_coordinator.cpp
 * @brief Coordinated identity rotation with anti-correlation engine
 *
 * Three pillars:
 * 1. Coordinated rotation: L2 identity change triggers staggered L7 changes
 * 2. Anti-correlation: Pearson r detects periodic patterns across layers
 * 3. CSPRNG jitter: randombytes_uniform() on all intervals, no periodicity
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

    void schedule_next(RotationLayer layer) {
        auto i = static_cast<size_t>(layer);
        const auto& lc = config.layers[i];
        uint32_t ms = jittered_interval_ms(lc.base_interval_sec, lc.jitter_factor, lc.min_interval_sec);
        ls[i].next_rotation = std::chrono::steady_clock::now() + std::chrono::milliseconds(ms);
    }

    void record_event(RotationLayer layer) {
        auto i = static_cast<size_t>(layer);
        auto now = std::chrono::steady_clock::now();
        double interval_sec = 0;
        if (!ls[i].history.empty()) {
            interval_sec = std::chrono::duration<double>(now - ls[i].history.back()).count();
            ls[i].intervals.push_back(interval_sec);
            if (ls[i].intervals.size() > config.correlation_window)
                ls[i].intervals.pop_front();
        }
        ls[i].history.push_back(now);
        if (ls[i].history.size() > config.correlation_window + 1)
            ls[i].history.pop_front();
        ls[i].count++;
        stats.rotation_counts[i]++;
        RotationEvent ev{layer, now, static_cast<uint32_t>(interval_sec)};
        event_log.push_back(ev);
        if (event_log.size() > MAX_LOG) event_log.pop_front();
    }

    void exec_rotation(RotationLayer layer) {
        record_event(layer);
        if (rotation_cb) rotation_cb(layer);
    }

    void exec_coordinated(RotationLayer trigger) {
        exec_rotation(trigger);
        if (trigger != RotationLayer::L2_IDENTITY) return;
        stats.coordinated_rotations++;

        struct Pending { RotationLayer l; uint32_t delay; };
        std::vector<Pending> pend;
        auto maybe = [&](bool flag, RotationLayer rl) {
            auto idx = static_cast<size_t>(rl);
            if (flag && config.layers[idx].enabled)
                pend.push_back({rl, random_stagger_ms(config.stagger_min_ms, config.stagger_max_ms)});
        };
        maybe(config.coordinate_tls_with_l2, RotationLayer::L7_TLS);
        maybe(config.coordinate_timing_with_l2, RotationLayer::L7_TIMING);
        maybe(config.coordinate_dummy_with_l2, RotationLayer::L7_DUMMY);
        maybe(config.coordinate_geneva_with_l2, RotationLayer::L7_GENEVA);

        std::sort(pend.begin(), pend.end(), [](auto& a, auto& b){ return a.delay < b.delay; });
        uint32_t elapsed = 0;
        for (auto& p : pend) {
            if (!running.load()) break;
            uint32_t wait = p.delay > elapsed ? p.delay - elapsed : 0;
            if (wait > 0) {
                std::this_thread::sleep_for(std::chrono::milliseconds(wait));
                elapsed += wait;
            }
            exec_rotation(p.l);
            schedule_next(p.l);
        }
    }

    uint32_t check_correlation() {
        last_corr.clear();
        uint32_t max_delay = 0;
        for (size_t i = 0; i < ROTATION_LAYER_COUNT; ++i) {
            for (size_t j = i+1; j < ROTATION_LAYER_COUNT; ++j) {
                if (ls[i].intervals.size() < 3 || ls[j].intervals.size() < 3) continue;
                size_t n = std::min(ls[i].intervals.size(), ls[j].intervals.size());
                std::vector<double> vi(ls[i].intervals.end()-n, ls[i].intervals.end());
                std::vector<double> vj(ls[j].intervals.end()-n, ls[j].intervals.end());
                double r = pearson_r(vi, vj);
                CorrelationResult cr;
                cr.layer_a = static_cast<RotationLayer>(i);
                cr.layer_b = static_cast<RotationLayer>(j);
                cr.pearson_r = r;
                cr.is_correlated = std::fabs(r) > config.correlation_threshold;
                cr.injected_delay_ms = 0;
                if (cr.is_correlated) {
                    uint32_t d = randombytes_uniform(config.decorrelation_max_delay_sec * 1000 + 1);
                    cr.injected_delay_ms = d;
                    max_delay = std::max(max_delay, d);
                    stats.correlation_detections++;
                    stats.total_decorrelation_delay_ms += d;
                    if (correlation_cb) correlation_cb(cr);
                }
                last_corr.push_back(cr);
            }
        }
        return max_delay;
    }

    void interruptible_sleep_ms(uint32_t ms) {
        auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(ms);
        while (std::chrono::steady_clock::now() < deadline && running.load()) {
            std::unique_lock<std::mutex> lk(mu);
            cv.wait_until(lk, std::min(deadline,
                std::chrono::steady_clock::now() + std::chrono::milliseconds(200)),
                [this]{ return !running.load(); });
        }
    }

    void scheduler_loop() {
        while (running.load()) {
            std::unique_lock<std::mutex> lock(mu);
            auto earliest = std::chrono::steady_clock::time_point::max();
            for (size_t i = 0; i < ROTATION_LAYER_COUNT; ++i) {
                if (!config.layers[i].enabled) continue;
                if (ls[i].next_rotation < earliest)
                    earliest = ls[i].next_rotation;
            }
            cv.wait_until(lock, earliest, [this]{ return !running.load(); });
            if (!running.load()) break;
            auto now = std::chrono::steady_clock::now();
            for (size_t i = 0; i < ROTATION_LAYER_COUNT; ++i) {
                if (!config.layers[i].enabled) continue;
                if (ls[i].next_rotation > now) continue;
                auto layer = static_cast<RotationLayer>(i);
                uint32_t decorr = check_correlation();
                if (decorr > 0) {
                    lock.unlock();
                    interruptible_sleep_ms(decorr);
                    if (!running.load()) return;
                    lock.lock();
                }
                lock.unlock();
                exec_coordinated(layer);
                lock.lock();
                schedule_next(layer);
            }
        }
    }
};

RotationCoordinator::RotationCoordinator() : impl_(std::make_unique<Impl>()) {}
RotationCoordinator::~RotationCoordinator() { if (impl_ && impl_->running.load()) stop(); }
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
                impl_->schedule_next(static_cast<RotationLayer>(i));
    }
    impl_->scheduler_thread = std::thread(&Impl::scheduler_loop, impl_.get());
}

void RotationCoordinator::stop() {
    impl_->running = false;
    impl_->cv.notify_all();
    if (impl_->scheduler_thread.joinable()) impl_->scheduler_thread.join();
}

bool RotationCoordinator::is_running() const { return impl_->running.load(); }

void RotationCoordinator::rotate_now(RotationLayer layer) {
    if (!impl_->running.load()) return;
    impl_->exec_coordinated(layer);
    std::lock_guard<std::mutex> lk(impl_->mu);
    impl_->schedule_next(layer);
    impl_->cv.notify_all();
}

void RotationCoordinator::rotate_all() {
    if (!impl_->running.load()) return;
    std::lock_guard<std::mutex> lk(impl_->mu);
    for (size_t i = 0; i < ROTATION_LAYER_COUNT; ++i) {
        if (!impl_->config.layers[i].enabled) continue;
        auto layer = static_cast<RotationLayer>(i);
        impl_->exec_rotation(layer);
        impl_->schedule_next(layer);
    }
    impl_->cv.notify_all();
}

std::chrono::milliseconds RotationCoordinator::time_until_next(RotationLayer layer) const {
    std::lock_guard<std::mutex> lk(impl_->mu);
    auto now = std::chrono::steady_clock::now();
    auto& nr = impl_->ls[static_cast<size_t>(layer)].next_rotation;
    if (nr <= now) return std::chrono::milliseconds(0);
    return std::chrono::duration_cast<std::chrono::milliseconds>(nr - now);
}

std::vector<RotationEvent> RotationCoordinator::get_recent_events(size_t max_count) const {
    std::lock_guard<std::mutex> lk(impl_->mu);
    size_t n = std::min(max_count, impl_->event_log.size());
    return {impl_->event_log.end() - n, impl_->event_log.end()};
}

std::vector<CorrelationResult> RotationCoordinator::get_correlation_results() const {
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
