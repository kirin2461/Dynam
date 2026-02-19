/**
 * @file ncp_timing.cpp
 * @brief TimingObfuscator implementation - Phase 6
 *
 * Background thread-based packet timing obfuscation.
 * Adds jitter and random delays between packet transmissions
 * to defeat timing-based DPI/traffic analysis.
 *
 * Phase 0.11: Replaced std::mt19937 with ncp::CSPRNG (libsodium).
 */

#include "ncp_timing.hpp"
#include "ncp_csprng.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cmath>
#include <mutex>
#include <queue>
#include <thread>

namespace ncp {
namespace DPI {

// ─── TimingProfile factory methods ────────────────────────────────────────────

TimingProfile TimingProfile::low() {
    TimingProfile p;
    p.min_delay_ms  = 1.0;
    p.max_delay_ms  = 10.0;
    p.jitter_factor = 0.1;
    p.burst_mode    = true;
    p.burst_prob    = 0.3;
    p.burst_size    = 5;
    return p;
}

TimingProfile TimingProfile::moderate() {
    TimingProfile p;
    p.min_delay_ms  = 10.0;
    p.max_delay_ms  = 100.0;
    p.jitter_factor = 0.3;
    p.burst_mode    = true;
    p.burst_prob    = 0.15;
    p.burst_size    = 3;
    return p;
}

TimingProfile TimingProfile::high() {
    TimingProfile p;
    p.min_delay_ms  = 50.0;
    p.max_delay_ms  = 500.0;
    p.jitter_factor = 0.5;
    p.burst_mode    = true;
    p.burst_prob    = 0.05;
    p.burst_size    = 2;
    return p;
}

TimingProfile TimingProfile::paranoid() {
    TimingProfile p;
    p.min_delay_ms  = 200.0;
    p.max_delay_ms  = 2000.0;
    p.jitter_factor = 0.8;
    p.burst_mode    = false;
    p.burst_prob    = 0.0;
    p.burst_size    = 1;
    return p;
}

// ─── Impl ─────────────────────────────────────────────────────────────────────

struct TimingObfuscator::Impl {
    TimingProfile                          profile;
    PacketSendCallback                     callback;
    TimingStats                            stats{};

    std::queue<std::vector<uint8_t>>       packet_queue;
    mutable std::mutex                     mu;
    std::condition_variable                cv;

    std::atomic<bool>                      running{false};
    std::thread                            worker;

    Impl() {}

    // ── Compute a single delay with jitter ──────────────────────────────────
    double compute_delay() {
        // Uniform base delay via CSPRNG
        double base_delay = ncp::CSPRNG::uniform_double(
            profile.min_delay_ms, profile.max_delay_ms
        );

        // Apply jitter: approximate Gaussian via Box-Muller with CSPRNG
        double stddev = base_delay * profile.jitter_factor;
        double u1 = ncp::CSPRNG::uniform_double(1e-10, 1.0);
        double u2 = ncp::CSPRNG::uniform_double(0.0, 1.0);
        double z  = std::sqrt(-2.0 * std::log(u1)) * std::cos(2.0 * M_PI * u2);
        double jitter = z * stddev;

        double delay = base_delay + jitter;

        // Clamp to valid range
        delay = std::max(0.5, delay);  // at least 0.5ms
        delay = std::min(delay, profile.max_delay_ms * 2.0);

        return delay;
    }

    // ── Worker thread loop ──────────────────────────────────────────────────
    void worker_loop() {
        while (running.load(std::memory_order_relaxed)) {
            std::vector<uint8_t> packet;
            {
                std::unique_lock<std::mutex> lock(mu);
                cv.wait_for(lock, std::chrono::milliseconds(100), [this] {
                    return !packet_queue.empty() || !running.load(std::memory_order_relaxed);
                });

                if (!running.load(std::memory_order_relaxed) && packet_queue.empty()) {
                    break;
                }

                if (packet_queue.empty()) {
                    continue;
                }

                packet = std::move(packet_queue.front());
                packet_queue.pop();
            }

            // Check for burst mode
            if (profile.burst_mode) {
                double roll = ncp::CSPRNG::uniform_double(0.0, 1.0);
                if (roll < profile.burst_prob) {
                    // Burst: send multiple packets with minimal delay
                    send_packet(packet, 0.5);  // minimal delay for first

                    size_t burst_remaining = profile.burst_size - 1;
                    while (burst_remaining > 0 && running.load(std::memory_order_relaxed)) {
                        std::vector<uint8_t> burst_pkt;
                        {
                            std::lock_guard<std::mutex> lock(mu);
                            if (packet_queue.empty()) break;
                            burst_pkt = std::move(packet_queue.front());
                            packet_queue.pop();
                        }
                        send_packet(burst_pkt, 1.0);  // very short delay within burst
                        --burst_remaining;

                        std::lock_guard<std::mutex> slock(mu);
                        stats.packets_in_bursts++;
                    }

                    {
                        std::lock_guard<std::mutex> slock(mu);
                        stats.bursts_triggered++;
                        stats.packets_in_bursts++;  // count the first packet too
                    }
                    continue;
                }
            }

            // Normal path: compute delay and send
            double delay = compute_delay();
            send_packet(packet, delay);
        }

        // Flush remaining packets on shutdown
        flush_remaining();
    }

    // ── Send a single packet with delay ─────────────────────────────────────
    void send_packet(const std::vector<uint8_t>& packet, double delay_ms) {
        if (delay_ms > 0.5) {
            auto delay_us = static_cast<int64_t>(delay_ms * 1000.0);
            std::this_thread::sleep_for(std::chrono::microseconds(delay_us));
        }

        if (callback) {
            callback(packet);
        }

        {
            std::lock_guard<std::mutex> lock(mu);
            stats.packets_delayed++;
            stats.total_delay_ms += static_cast<uint64_t>(delay_ms);
            if (stats.packets_delayed > 0) {
                stats.avg_delay_ms =
                    static_cast<double>(stats.total_delay_ms) /
                    static_cast<double>(stats.packets_delayed);
            }
        }
    }

    // ── Flush remaining queued packets ──────────────────────────────────────
    void flush_remaining() {
        std::lock_guard<std::mutex> lock(mu);
        while (!packet_queue.empty()) {
            auto& pkt = packet_queue.front();
            if (callback) {
                callback(pkt);
            }
            stats.packets_delayed++;
            packet_queue.pop();
        }
    }
};

// ─── Constructor / Destructor ─────────────────────────────────────────────────

TimingObfuscator::TimingObfuscator()
    : impl_(std::make_unique<Impl>())
{}

TimingObfuscator::~TimingObfuscator() {
    if (impl_ && impl_->running.load()) {
        stop();
    }
}

TimingObfuscator::TimingObfuscator(TimingObfuscator&&) noexcept = default;
TimingObfuscator& TimingObfuscator::operator=(TimingObfuscator&&) noexcept = default;

// ─── start() ──────────────────────────────────────────────────────────────────

void TimingObfuscator::start(const TimingProfile& profile, PacketSendCallback callback) {
    if (impl_->running.load()) {
        stop();
    }

    impl_->profile  = profile;
    impl_->callback = std::move(callback);
    impl_->running.store(true, std::memory_order_release);

    impl_->worker = std::thread([this] {
        impl_->worker_loop();
    });
}

// ─── stop() ───────────────────────────────────────────────────────────────────

void TimingObfuscator::stop() {
    impl_->running.store(false, std::memory_order_release);
    impl_->cv.notify_all();

    if (impl_->worker.joinable()) {
        impl_->worker.join();
    }
}

// ─── is_running() ─────────────────────────────────────────────────────────────

bool TimingObfuscator::is_running() const {
    return impl_->running.load(std::memory_order_acquire);
}

// ─── enqueue() ────────────────────────────────────────────────────────────────

void TimingObfuscator::enqueue(const std::vector<uint8_t>& packet) {
    {
        std::lock_guard<std::mutex> lock(impl_->mu);
        impl_->packet_queue.push(packet);
    }
    impl_->cv.notify_one();
}

// ─── enqueue_batch() ──────────────────────────────────────────────────────────

void TimingObfuscator::enqueue_batch(
    const std::vector<std::vector<uint8_t>>& packets)
{
    {
        std::lock_guard<std::mutex> lock(impl_->mu);
        for (const auto& pkt : packets) {
            impl_->packet_queue.push(pkt);
        }
    }
    impl_->cv.notify_one();
}

// ─── set_profile() ────────────────────────────────────────────────────────────

void TimingObfuscator::set_profile(const TimingProfile& profile) {
    std::lock_guard<std::mutex> lock(impl_->mu);
    impl_->profile = profile;
}

// ─── queue_size() ─────────────────────────────────────────────────────────────

size_t TimingObfuscator::queue_size() const {
    std::lock_guard<std::mutex> lock(impl_->mu);
    return impl_->packet_queue.size();
}

// ─── Stats ────────────────────────────────────────────────────────────────────

TimingStats TimingObfuscator::get_stats() const {
    std::lock_guard<std::mutex> lock(impl_->mu);
    return impl_->stats;
}

void TimingObfuscator::reset_stats() {
    std::lock_guard<std::mutex> lock(impl_->mu);
    impl_->stats = TimingStats{};
}

} // namespace DPI
} // namespace ncp
