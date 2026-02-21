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

// --- TimingObfuscator implementation ------------------------------------------

TimingObfuscator::TimingObfuscator() 
    : running_(false)
    , last_tx_time_(std::chrono::steady_clock::now())
{}

TimingObfuscator::~TimingObfuscator() {
    stop();
}

bool TimingObfuscator::initialize(const TimingProfile& profile) {
    std::lock_guard<std::mutex> lock(profile_mutex_);
    profile_ = profile;
    return true;
}

bool TimingObfuscator::start() {
    if (running_) return true;
    
    running_ = true;
    worker_thread_ = std::thread(&TimingObfuscator::worker_loop, this);
    return true;
}

void TimingObfuscator::stop() {
    {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        running_ = false;
        queue_cv_.notify_all();
    }
    
    if (worker_thread_.joinable()) {
        worker_thread_.join();
    }
}

void TimingObfuscator::enqueue_packet(const std::vector<uint8_t>& data, 
                                    std::function<void(const std::vector<uint8_t>&)> send_cb) {
    std::lock_guard<std::mutex> lock(queue_mutex_);
    packet_queue_.push({data, send_cb});
    queue_cv_.notify_one();
}

void TimingObfuscator::worker_loop() {
    while (running_) {
        PendingPacket packet;
        {
            std::unique_lock<std::mutex> lock(queue_mutex_);
            queue_cv_.wait(lock, [this] { return !packet_queue_.empty() || !running_; });
            
            if (!running_ && packet_queue_.empty()) break;
            
            packet = packet_queue_.front();
            packet_queue_.pop();
        }
        
        // Calculate delay
        double delay_ms = calculate_next_delay();
        
        // Wait until it's time to send
        auto target_time = last_tx_time_ + std::chrono::microseconds(static_cast<long long>(delay_ms * 1000));
        std::this_thread::sleep_until(target_time);
fix(timing): add _USE_MATH_DEFINES for M_PI on Windows        // Send
        packet.send_cb(packet.data);
        last_tx_time_ = std::chrono::steady_clock::now();
    }
}

double TimingObfuscator::calculate_next_delay() {
    std::lock_guard<std::mutex> lock(profile_mutex_);
    
    // Base delay from profile
    double base = profile_.min_delay_ms + 
                 (ncp::CSPRNG::get_instance().random_float() * (profile_.max_delay_ms - profile_.min_delay_ms));
    
    // Add jitter (Gaussian-like)
    double jitter = base * profile_.jitter_factor * (ncp::CSPRNG::get_instance().random_float() - 0.5);
    
    double total = base + jitter;
    
    // Burst logic
    if (profile_.burst_mode) {
        if (ncp::CSPRNG::get_instance().random_float() < profile_.burst_prob) {
            // Significant reduction in delay for burst
            total /= profile_.burst_size;
        }
    }
    
    return (total < 0) ? 0.1 : total;
}

} // namespace DPI
} // namespace ncp
