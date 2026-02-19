/**
 * @file security.cpp
 * @brief Implementation of security enhancement features
 */

#include "../include/ncp_security.hpp"
#include <algorithm>
#include <numeric>
#include <cmath>
#include <iomanip>
#include <sstream>
#include <deque>
#include <unordered_map>

namespace ncp {

// ==================== CertificatePinner ====================

struct CertificatePinner::Impl {
    // Use unordered_map for O(1) hostname lookup instead of linear search
    std::unordered_map<std::string, std::vector<PinnedCert>> pin_index_;
    mutable std::mutex mutex_;
};

CertificatePinner::CertificatePinner() : impl_(std::make_unique<Impl>()) {}

CertificatePinner::~CertificatePinner() = default;

void CertificatePinner::add_pin(const std::string& hostname, const std::string& sha256_hash, bool is_backup) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    PinnedCert cert{hostname, sha256_hash, is_backup};
    impl_->pin_index_[hostname].push_back(cert);
}

void CertificatePinner::add_pins(const std::vector<PinnedCert>& pins) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    for (const auto& pin : pins) {
        impl_->pin_index_[pin.hostname].push_back(pin);
    }
}

void CertificatePinner::load_default_pins() {
    // Default pins for major DoH providers (SPKI SHA256 hashes)
    // Cloudflare DNS - https://cloudflare-dns.com/
    add_pin("cloudflare-dns.com", "GP8Knf7qBae+aIfythytMbYnL+yowaWVeD6MoLHkVRg=");
    add_pin("cloudflare-dns.com", "RQeZkB42znUfsDIIFWIRiYEcKl7nHwNFwWCrnMMJbVc=", true); // backup
    
    // Google DNS - https://dns.google/
    add_pin("dns.google", "WoiWRyIOVNa9ihaBciRSC7XHjliYS9VwUGOIud4PB18=");
    add_pin("dns.google", "lCppFqbkrlJ3EcVFAkeip0+44VaoJUymbnOaEUk7tEU=", true); // backup
    
    // Quad9 DNS - https://www.quad9.net/
    add_pin("dns9.quad9.net", "yioEpqeR4WtDwE9YxNVnCEkTxIjx6EEIwFSQW+lJsbc=");
    add_pin("dns9.quad9.net", "Wg+cUJTh+h6OwLd0NWW7R7IlMBuEMkzh/x2IG0S/VLg=", true); // backup
}

bool CertificatePinner::verify_certificate(const std::string& hostname, const std::string& cert_hash) const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    auto it = impl_->pin_index_.find(hostname);
    if (it == impl_->pin_index_.end()) {
        return false;
    }
    for (const auto& pin : it->second) {
        if (pin.sha256_hash == cert_hash) {
            return true;
        }
    }
    return false;
}

std::vector<CertificatePinner::PinnedCert> CertificatePinner::get_pins(const std::string& hostname) const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    auto it = impl_->pin_index_.find(hostname);
    if (it != impl_->pin_index_.end()) {
        return it->second;
    }
    return {};
}

void CertificatePinner::clear_pins() {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    impl_->pin_index_.clear();
}

// ==================== LatencyMonitor ====================

struct LatencyMonitor::Impl {
    uint32_t threshold_ms_;
    std::function<void(const LatencyAlert&)> alert_callback_;
    std::unordered_map<std::string, std::deque<uint32_t>> latency_history_;
    mutable std::mutex mutex_;

    explicit Impl(uint32_t threshold) : threshold_ms_(threshold) {}
};

LatencyMonitor::LatencyMonitor(uint32_t threshold_ms) 
    : impl_(std::make_unique<Impl>(threshold_ms)) {}

LatencyMonitor::~LatencyMonitor() = default;

void LatencyMonitor::record_latency(const std::string& provider, uint32_t latency_ms) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    impl_->latency_history_[provider].push_back(latency_ms);
    
    // Keep only last 100 measurements (use deque for efficient pop_front)
    if (impl_->latency_history_[provider].size() > 100) {
        impl_->latency_history_[provider].pop_front();
    }
    
    // Check for alert
    if (impl_->alert_callback_ && latency_ms > impl_->threshold_ms_) {
        LatencyAlert alert;
        alert.provider = provider;
        alert.latency_ms = latency_ms;
        alert.threshold_ms = impl_->threshold_ms_;
        alert.timestamp = std::chrono::system_clock::now();
        alert.message = "Latency exceeded threshold";
        impl_->alert_callback_(alert);
    }
}

LatencyMonitor::LatencyStats LatencyMonitor::get_latency_stats(const std::string& provider) const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    LatencyStats stats;
    
    auto it = impl_->latency_history_.find(provider);
    if (it == impl_->latency_history_.end() || it->second.empty()) {
        return stats;
    }
    
    const auto& history = it->second;
    stats.sample_count = static_cast<uint32_t>(history.size());
    
    // Calculate average
    stats.avg_ms = static_cast<uint32_t>(
        std::accumulate(history.begin(), history.end(), 0ULL) / history.size()
    );
    
    // Min and max
    stats.min_ms = *std::min_element(history.begin(), history.end());
    stats.max_ms = *std::max_element(history.begin(), history.end());
    
    // Standard deviation
    double variance = 0.0;
    for (auto val : history) {
        double diff = static_cast<double>(val) - stats.avg_ms;
        variance += diff * diff;
    }
    variance /= history.size();
    stats.std_dev_ms = static_cast<uint32_t>(std::sqrt(variance));
    
    // Percentiles with bounds checking
    std::vector<uint32_t> sorted(history.begin(), history.end());
    std::sort(sorted.begin(), sorted.end());
    
    if (!sorted.empty()) {
        size_t p50_idx = std::min(sorted.size() * 50 / 100, sorted.size() - 1);
        size_t p95_idx = std::min(sorted.size() * 95 / 100, sorted.size() - 1);
        size_t p99_idx = std::min(sorted.size() * 99 / 100, sorted.size() - 1);
        
        stats.p50_ms = sorted[p50_idx];
        stats.p95_ms = sorted[p95_idx];
        stats.p99_ms = sorted[p99_idx];
    }
    
    return stats;
}

void LatencyMonitor::set_alert_callback(std::function<void(const LatencyAlert&)> callback) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    impl_->alert_callback_ = std::move(callback);
}

void LatencyMonitor::clear_history() {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    impl_->latency_history_.clear();
}

std::vector<std::string> LatencyMonitor::get_monitored_providers() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    std::vector<std::string> providers;
    for (const auto& pair : impl_->latency_history_) {
        providers.push_back(pair.first);
    }
    return providers;
}

// ==================== ConnectionMonitor ====================

struct ConnectionMonitor::Impl {
    std::deque<ConnectionInfo> connection_history_;
    std::unordered_map<std::string, HostStats> connection_stats_;
    mutable std::mutex mutex_;
};

ConnectionMonitor::ConnectionMonitor() : impl_(std::make_unique<Impl>()) {}

ConnectionMonitor::~ConnectionMonitor() = default;

void ConnectionMonitor::record_connection(
    const std::string& host,
    uint16_t port,
    bool successful,
    uint32_t duration_ms
) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    
    ConnectionInfo info;
    info.host = host;
    info.port = port;
    info.timestamp = std::chrono::system_clock::now();
    info.successful = successful;
    info.duration_ms = duration_ms;
    
    impl_->connection_history_.push_back(info);
    
    // Keep last 1000 connections (use deque for efficient pop_front)
    if (impl_->connection_history_.size() > 1000) {
        impl_->connection_history_.pop_front();
    }
    
    // Update stats
    auto& host_stats = impl_->connection_stats_[host];
    host_stats.total_attempts++;
    if (successful) {
        host_stats.successful_attempts++;
    } else {
        host_stats.failed_attempts++;
    }
    host_stats.total_duration_ms += duration_ms;
    host_stats.last_attempt = info.timestamp;
}

ConnectionMonitor::HostStats ConnectionMonitor::get_host_stats(const std::string& host) const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    auto it = impl_->connection_stats_.find(host);
    if (it != impl_->connection_stats_.end()) {
        return it->second;
    }
    return HostStats{};
}

std::vector<ConnectionMonitor::ConnectionInfo> ConnectionMonitor::get_recent_connections(
    size_t count
) const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    if (count >= impl_->connection_history_.size()) {
        return std::vector<ConnectionInfo>(impl_->connection_history_.begin(), 
                                           impl_->connection_history_.end());
    }
    auto start_it = impl_->connection_history_.end() - count;
    return std::vector<ConnectionInfo>(start_it, impl_->connection_history_.end());
}

void ConnectionMonitor::clear_history() {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    impl_->connection_history_.clear();
    impl_->connection_stats_.clear();
}

} // namespace ncp
