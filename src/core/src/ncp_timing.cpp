#define _USE_MATH_DEFINES
#include <cmath>
#include "ncp_timing.hpp"
#include "ncp_csprng.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <queue>
#include <thread>

namespace ncp {
namespace DPI {

// --- TimingProfile factory methods --------------------------------------------

TimingProfile TimingProfile::low() {
    TimingProfile p;
    p.min_delay_ms = 1.0;
    p.max_delay_ms = 10.0;
    p.jitter_factor = 0.1;
    p.burst_mode    = true;
    p.burst_prob    = 0.3;
    p.burst_size    = 5;
    return p;
}

TimingProfile TimingProfile::moderate() {
    TimingProfile p;
    p.min_delay_ms = 10.0;
    p.max_delay_ms = 100.0;
    p.jitter_factor = 0.3;
    p.burst_mode    = true;
    p.burst_prob    = 0.15;
    p.burst_size    = 3;
    return p;
}

TimingProfile TimingProfile::high() {
    TimingProfile p;
    p.min_delay_ms = 50.0;
    p.max_delay_ms = 500.0;
    p.jitter_factor = 0.5;
    p.burst_mode    = true;
    p.burst_prob    = 0.05;
    p.burst_size    = 2;
    return p;
}

TimingProfile TimingProfile::paranoid() {
    TimingProfile p;
    p.min_delay_ms = 200.0;
    p.max_delay_ms = 1000.0;
    p.jitter_factor = 0.8;
    p.burst_mode    = false;
    p.burst_prob    = 0.0;
    p.burst_size    = 0;
    return p;
}

// --- TimingObfuscator::Impl ---------------------------------------------------

struct TimingObfuscator::Impl {
    // Pending packet: data + send callback
    struct PendingPacket {
        std::vector<uint8_t>            data;
        PacketSendCallback              send_cb;
    };

    std::atomic<bool>                           running{false};
    std::chrono::steady_clock::time_point       last_tx_time;
    std::mutex                                  profile_mutex;
    std::mutex                                  queue_mutex;
    std::condition_variable                     queue_cv;
    std::thread                                 worker_thread;
    TimingProfile                               profile;
    std::queue<PendingPacket>                   packet_queue;
    TimingStats                                 stats;

    Impl() : last_tx_time(std::chrono::steady_clock::now()) {}

    double calculate_next_delay() {
        std::lock_guard<std::mutex> lock(profile_mutex);
        // Base delay from profile
        double base = profile.min_delay_ms +
            (ncp::csprng_double() * (profile.max_delay_ms - profile.min_delay_ms));
        // Add jitter
        double jitter = base * profile.jitter_factor *
            (ncp::csprng_double() - 0.5);
        double total = base + jitter;
        // Burst logic
        if (profile.burst_mode && ncp::csprng_double() < profile.burst_prob) {
            if (profile.burst_size > 0)
                total /= static_cast<double>(profile.burst_size);
        }
        return (total < 0.0) ? 0.1 : total;
    }

    void worker_loop() {
        while (running.load()) {
            PendingPacket packet;
            {
                std::unique_lock<std::mutex> lock(queue_mutex);
                queue_cv.wait(lock, [this] {
                    return !packet_queue.empty() || !running.load();
                });
                if (!running.load() && packet_queue.empty()) break;
                packet = std::move(packet_queue.front());
                packet_queue.pop();
            }

            // Calculate delay and wait
            double delay_ms = calculate_next_delay();
            auto target_time = last_tx_time +
                std::chrono::microseconds(
                    static_cast<long long>(delay_ms * 1000.0));
            std::this_thread::sleep_until(target_time);

            // Send the packet
            if (packet.send_cb) {
                packet.send_cb(packet.data);
            }
            last_tx_time = std::chrono::steady_clock::now();

            // Update stats
            stats.packets_delayed++;
            stats.total_delay_ms += static_cast<uint64_t>(delay_ms);
            if (stats.packets_delayed > 0) {
                stats.avg_delay_ms =
                    static_cast<double>(stats.total_delay_ms) /
                    static_cast<double>(stats.packets_delayed);
            }
        }
    }
};

// --- TimingObfuscator implementation ------------------------------------------

TimingObfuscator::TimingObfuscator()
    : impl_(std::make_unique<Impl>())
{}

TimingObfuscator::~TimingObfuscator() {
    stop();
}

TimingObfuscator::TimingObfuscator(TimingObfuscator&&) noexcept = default;
TimingObfuscator& TimingObfuscator::operator=(TimingObfuscator&&) noexcept = default;

void TimingObfuscator::start(const TimingProfile& profile,
                              PacketSendCallback callback) {
    if (impl_->running.load()) return;
    {
        std::lock_guard<std::mutex> lock(impl_->profile_mutex);
        impl_->profile = profile;
    }
    // Store callback via a wrapper that bundles it per enqueue call;
    // save as default callback for enqueue() overloads
    impl_->running.store(true);
    impl_->worker_thread = std::thread([this, cb = std::move(callback)]() mutable {
        // Wrap: each queued packet uses the shared callback
        // We run the raw loop but inject the callback into each packet
        // Actually packets are enqueued with their own callbacks;
        // if none, use the session callback.
        // Re-use worker_loop but first set a session-level callback.
        // To support the public API (single callback for all packets),
        // we need to store the session callback in Impl.
        // Quick fix: wrap worker_loop with callback injection.
        while (impl_->running.load()) {
            Impl::PendingPacket packet;
            {
                std::unique_lock<std::mutex> lock(impl_->queue_mutex);
                impl_->queue_cv.wait(lock, [this] {
                    return !impl_->packet_queue.empty() || !impl_->running.load();
                });
                if (!impl_->running.load() && impl_->packet_queue.empty()) break;
                packet = std::move(impl_->packet_queue.front());
                impl_->packet_queue.pop();
            }
            double delay_ms = impl_->calculate_next_delay();
            auto target_time = impl_->last_tx_time +
                std::chrono::microseconds(
                    static_cast<long long>(delay_ms * 1000.0));
            std::this_thread::sleep_until(target_time);
            // Use packet-specific callback if set, else use session callback
            if (packet.send_cb) {
                packet.send_cb(packet.data);
            } else if (cb) {
                cb(packet.data);
            }
            impl_->last_tx_time = std::chrono::steady_clock::now();
            impl_->stats.packets_delayed++;
            impl_->stats.total_delay_ms += static_cast<uint64_t>(delay_ms);
            if (impl_->stats.packets_delayed > 0) {
                impl_->stats.avg_delay_ms =
                    static_cast<double>(impl_->stats.total_delay_ms) /
                    static_cast<double>(impl_->stats.packets_delayed);
            }
        }
    });
}

void TimingObfuscator::stop() {
    {
        std::lock_guard<std::mutex> lock(impl_->queue_mutex);
        impl_->running.store(false);
        impl_->queue_cv.notify_all();
    }
    if (impl_->worker_thread.joinable()) {
        impl_->worker_thread.join();
    }
}

bool TimingObfuscator::is_running() const {
    return impl_->running.load();
}

void TimingObfuscator::enqueue(const std::vector<uint8_t>& packet) {
    std::lock_guard<std::mutex> lock(impl_->queue_mutex);
    impl_->packet_queue.push({packet, nullptr});
    impl_->queue_cv.notify_one();
}

void TimingObfuscator::enqueue_batch(
    const std::vector<std::vector<uint8_t>>& packets) {
    std::lock_guard<std::mutex> lock(impl_->queue_mutex);
    for (const auto& p : packets) {
        impl_->packet_queue.push({p, nullptr});
    }
    impl_->queue_cv.notify_all();
}

void TimingObfuscator::set_profile(const TimingProfile& profile) {
    std::lock_guard<std::mutex> lock(impl_->profile_mutex);
    impl_->profile = profile;
}

size_t TimingObfuscator::queue_size() const {
    std::lock_guard<std::mutex> lock(impl_->queue_mutex);
    return impl_->packet_queue.size();
}

TimingStats TimingObfuscator::get_stats() const {
    return impl_->stats;
}

void TimingObfuscator::reset_stats() {
    impl_->stats = TimingStats{};
}

} // namespace DPI
} // namespace ncp
