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

namespace ncp {

// ==================== CertificatePinner ====================

CertificatePinner::CertificatePinner() {}

CertificatePinner::~CertificatePinner() {}

void CertificatePinner::add_pin(const std::string& hostname, const std::string& sha256_hash, bool is_backup) {
    std::lock_guard<std::mutex> lock(mutex_);
    pins_.push_back({hostname, sha256_hash, is_backup});
}

void CertificatePinner::add_pins(const std::vector<PinnedCert>& pins) {
    std::lock_guard<std::mutex> lock(mutex_);
    pins_.insert(pins_.end(), pins.begin(), pins.end());
}

void CertificatePinner::load_default_pins() {
        // Default pins for major DoH providers (SPKI SHA256 hashes)
    // Mode: Paranoid (all verifications active)
    add_pin("cloudflare-dns.com", "GP8Knf7qBae+aIfythytMbYnL+yowaWVeD6MoLHkVRg=");
    add_pin("cloudflare-dns.com", "RQeZkB42znUfsDIIFWIRiYEcKl7nHwNFwWCrnMMJbVc=", true); // backup
    
    // Google DNS - https://dns.google/
    add_pin("dns.google", "WoiWRyIOVNa9ihaBciRSC7XHjliYS9VwUGOIud4PB18=");
    add_pin("dns.google", "lCppFqbkrlJ3EcVFAkeip0+44VaoJUymbnOaEUk7tEU=", true); // backup
    
    // Quad9 DNS - https://www.quad9.net/
    add_pin("dns9.quad9.net", "yioEpqeR4WtDwE9YxNVnCEkTxIjx6EEIwFSQW+lJsbc=");
    add_pin("dns9.quad9.net", "Wg+cUJTh+h6OwLd0NWW7R7IlMBuEMkzh/x2IG0S/VLg=", true); // backup
    
    // Extra security: force pinning for all system updates
    add_pin("replit.com", "base64_sha256_hash_here");
}

bool CertificatePinner::verify_certificate(const std::string& hostname, const std::string& cert_hash) const {
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto& pin : pins_) {
        if (pin.hostname == hostname && pin.sha256_hash == cert_hash) {
            return true;
        }
    }
    return false;
}

std::vector<CertificatePinner::PinnedCert> CertificatePinner::get_pins(const std::string& hostname) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<PinnedCert> result;
    for (const auto& pin : pins_) {
        if (pin.hostname == hostname) {
            result.push_back(pin);
        }
    }
    return result;
}

void CertificatePinner::clear_pins() {
    std::lock_guard<std::mutex> lock(mutex_);
    pins_.clear();
}

// ==================== LatencyMonitor ====================

LatencyMonitor::LatencyMonitor(uint32_t threshold_ms) : threshold_ms_(threshold_ms) {}

LatencyMonitor::~LatencyMonitor() {}

void LatencyMonitor::record_latency(const std::string& provider, uint32_t latency_ms) {
    std::lock_guard<std::mutex> lock(mutex_);
    latency_history_[provider].push_back(latency_ms);
    
    // Keep only last 100 measurements
    if (latency_history_[provider].size() > 100) {
        latency_history_[provider].erase(latency_history_[provider].begin());
    }
    
    // Check for alert
    if (alert_callback_ && latency_ms > threshold_ms_) {
        LatencyAlert alert;
        alert.provider = provider;
        alert.latency_ms = latency_ms;
        alert.threshold_ms = threshold_ms_;
        alert.timestamp = std::chrono::system_clock::now();
        alert.message = "Latency exceeded threshold";
        alert_callback_(alert);
    }
}

LatencyMonitor::LatencyStats LatencyMonitor::get_stats(const std::string& provider) const {
    std::lock_guard<std::mutex> lock(mutex_);
    LatencyStats stats{};
    
    auto it = latency_history_.find(provider);
    if (it == latency_history_.end() || it->second.empty()) {
        return stats;
    }
    
    const auto& history = it->second;
    stats.sample_count = static_cast<uint32_t>(history.size());
    stats.min_ms = *std::min_element(history.begin(), history.end());
    stats.max_ms = *std::max_element(history.begin(), history.end());
    stats.avg_ms = std::accumulate(history.begin(), history.end(), 0ULL) / history.size();
    
    // Calculate standard deviation
    double sum_sq_diff = 0.0;
    for (uint32_t val : history) {
        double diff = val - stats.avg_ms;
        sum_sq_diff += diff * diff;
    }
    stats.stddev_ms = static_cast<uint32_t>(std::sqrt(sum_sq_diff / history.size()));
    stats.last_update = std::chrono::system_clock::now();
    
    return stats;
}

void LatencyMonitor::set_threshold(uint32_t threshold_ms) {
    std::lock_guard<std::mutex> lock(mutex_);
    threshold_ms_ = threshold_ms;
}

uint32_t LatencyMonitor::get_threshold() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return threshold_ms_;
}

void LatencyMonitor::set_alert_callback(AlertCallback callback) {
    std::lock_guard<std::mutex> lock(mutex_);
    alert_callback_ = callback;
}

bool LatencyMonitor::is_anomalous(const std::string& provider, uint32_t latency_ms) const {
    auto stats = get_stats(provider);
    if (stats.sample_count < 10) return false; // Need more data
    
    // Anomalous if > mean + 2*stddev
    return latency_ms > (stats.avg_ms + 2 * stats.stddev_ms);
}

void LatencyMonitor::reset_stats() {
    std::lock_guard<std::mutex> lock(mutex_);
    latency_history_.clear();
}

// ==================== TrafficPadder ====================

TrafficPadder::TrafficPadder(uint32_t min_size, uint32_t max_size) 
    : min_size_(min_size), max_size_(max_size), rng_(std::random_device{}()) {}

TrafficPadder::~TrafficPadder() {}

std::vector<uint8_t> TrafficPadder::add_padding(const std::vector<uint8_t>& data) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::uniform_int_distribution<uint32_t> dist(min_size_, max_size_);
    uint32_t padding_size = dist(rng_);
    uint32_t original_size = static_cast<uint32_t>(data.size());
    
    std::vector<uint8_t> result;
    result.reserve(4 + original_size + padding_size);
    
    // Size header FIRST (big-endian)
    result.push_back((original_size >> 24) & 0xFF);
    result.push_back((original_size >> 16) & 0xFF);
    result.push_back((original_size >> 8) & 0xFF);
    result.push_back(original_size & 0xFF);
    
    // Original data
    result.insert(result.end(), data.begin(), data.end());
    
    // Random padding
    std::uniform_int_distribution<unsigned int> byte_dist(0, 255);
    for (uint32_t i = 0; i < padding_size; ++i) {
                    result.push_back(static_cast<uint8_t>(byte_dist(rng_)));
    }
    
    return result;
}

std::vector<uint8_t> TrafficPadder::remove_padding(const std::vector<uint8_t>& data) {
    // Minimum: 4 bytes for size header
    if (data.size() < 4) {
        throw std::runtime_error("Data too small to contain padding header");
    }
    
    // Read size from the FIRST 4 bytes (big-endian)
    uint32_t original_size = (static_cast<uint32_t>(data[0]) << 24) |
                             (static_cast<uint32_t>(data[1]) << 16) |
                             (static_cast<uint32_t>(data[2]) << 8) |
                              static_cast<uint32_t>(data[3]);
    
    // Validate size
    if (original_size > data.size() - 4) {
        throw std::runtime_error("Invalid padding: claimed size exceeds data");
    }
    
    // Return original data (skip the 4-byte size header)
    return std::vector<uint8_t>(data.begin() + 4, data.begin() + 4 + original_size);
}

void TrafficPadder::set_padding_range(uint32_t min_size, uint32_t max_size) {
    std::lock_guard<std::mutex> lock(mutex_);
    min_size_ = min_size;
    max_size_ = max_size;
}

// ==================== ForensicLogger ====================

ForensicLogger::ForensicLogger() : enabled_(false) {}

ForensicLogger::ForensicLogger(const std::string& log_path) : log_path_(log_path), enabled_(true) {
    log_file_.open(log_path_, std::ios::app);
    if (!log_file_.is_open()) {
        enabled_ = false;
    }
}

ForensicLogger::~ForensicLogger() {
    flush();
    if (log_file_.is_open()) {
        log_file_.close();
    }
}

void ForensicLogger::log(EventType type, const std::string& source, 
                         const std::string& message,
                         const std::map<std::string, std::string>& metadata) {
    if (!enabled_) return;
    
    std::lock_guard<std::mutex> lock(mutex_);
    
    LogEntry entry;
    entry.timestamp = std::chrono::system_clock::now();
    entry.type = type;
    entry.source = source;
    entry.message = message;
    entry.metadata = metadata;
    
    entries_.push_back(entry);
    write_entry(entry);
    
    // Keep only last 1000 entries in memory
    if (entries_.size() > 1000) {
        entries_.erase(entries_.begin());
    }
}

std::string ForensicLogger::event_type_to_string(EventType type) const {
    switch (type) {
        case EventType::DNS_QUERY: return "DNS_QUERY";
        case EventType::DNS_RESPONSE: return "DNS_RESPONSE";
        case EventType::CERTIFICATE_VERIFICATION: return "CERT_VERIFY";
        case EventType::LATENCY_ALERT: return "LATENCY_ALERT";
        case EventType::ROUTE_SWITCH: return "ROUTE_SWITCH";
        case EventType::CANARY_TRIGGERED: return "CANARY";
        case EventType::ERROR: return "ERROR";
        case EventType::WARNING: return "WARNING";
        case EventType::INFO: return "INFO";
        default: return "UNKNOWN";
    }
}

void ForensicLogger::write_entry(const LogEntry& entry) {
    if (!log_file_.is_open()) return;
    
    // Format timestamp as ISO 8601
    auto time_t = std::chrono::system_clock::to_time_t(entry.timestamp);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        entry.timestamp.time_since_epoch()) % 1000;
    
    std::ostringstream oss;
    #ifdef _WIN32
    std::tm tm_buf;
    gmtime_s(&tm_buf, &time_t);
    oss << std::put_time(&tm_buf, "%Y-%m-%dT%H:%M:%S");
#else
    oss << std::put_time(std::gmtime(&time_t), "%Y-%m-%dT%H:%M:%S");
#endif
    oss << '.' << std::setfill('0') << std::setw(3) << ms.count() << "Z";
    
    // Write JSON-like format
    log_file_ << "{\"timestamp\":\"" << oss.str() << "\","
              << "\"type\":\"" << event_type_to_string(entry.type) << "\","
              << "\"source\":\"" << entry.source << "\","
              << "\"message\":\"" << entry.message << "\"";
    
    // Add metadata if present
    if (!entry.metadata.empty()) {
        log_file_ << ",\"metadata\":{";
        bool first = true;
        for (const auto& [key, value] : entry.metadata) {
            if (!first) log_file_ << ",";
            log_file_ << "\"" << key << "\":\"" << value << "\"";
            first = false;
        }
        log_file_ << "}";
    }
    
    log_file_ << "}\n";
}

void ForensicLogger::flush() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (log_file_.is_open()) {
        log_file_.flush();
    }
}

void ForensicLogger::set_log_path(const std::string& path) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (log_file_.is_open()) {
        log_file_.close();
    }
    log_path_ = path;
    log_file_.open(log_path_, std::ios::app);
    enabled_ = log_file_.is_open();
}

void ForensicLogger::set_enabled(bool enabled) {
    std::lock_guard<std::mutex> lock(mutex_);
    enabled_ = enabled;
}

std::vector<ForensicLogger::LogEntry> ForensicLogger::get_recent_entries(size_t count) const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (count >= entries_.size()) {
        return entries_;
    }
    return std::vector<LogEntry>(entries_.end() - count, entries_.end());
}

void ForensicLogger::log_dns_query(const std::string& hostname, const std::string& provider) {
    log(EventType::DNS_QUERY, "DNSResolver", "DNS query for " + hostname,
        {{"hostname", hostname}, {"provider", provider}});
}

void ForensicLogger::log_dns_response(const std::string& hostname, uint32_t latency_ms, bool success) {
    log(EventType::DNS_RESPONSE, "DNSResolver", 
        success ? "DNS response received" : "DNS query failed",
        {{"hostname", hostname}, {"latency_ms", std::to_string(latency_ms)}, 
         {"success", success ? "true" : "false"}});
}

void ForensicLogger::log_cert_verification(const std::string& hostname, bool valid) {
    log(EventType::CERTIFICATE_VERIFICATION, "CertPinner",
        valid ? "Certificate verified" : "Certificate verification failed",
        {{"hostname", hostname}, {"valid", valid ? "true" : "false"}});
}

void ForensicLogger::log_latency_alert(const std::string& provider, uint32_t latency_ms) {
    log(EventType::LATENCY_ALERT, "LatencyMonitor", "High latency detected",
        {{"provider", provider}, {"latency_ms", std::to_string(latency_ms)}});
}

void ForensicLogger::log_route_switch(const std::string& from_provider, 
                                       const std::string& to_provider, 
                                       const std::string& reason) {
    log(EventType::ROUTE_SWITCH, "AutoRouteSwitch", "Route switched",
        {{"from", from_provider}, {"to", to_provider}, {"reason", reason}});
}

void ForensicLogger::log_canary_triggered(const std::string& domain, const std::string& details) {
    log(EventType::CANARY_TRIGGERED, "CanaryTokens", "Canary triggered - possible interception",
        {{"domain", domain}, {"details", details}});
}

void ForensicLogger::log_error(const std::string& source, const std::string& message) {
    log(EventType::ERROR, source, message, {});
}

void ForensicLogger::log_warning(const std::string& source, const std::string& message) {
    log(EventType::WARNING, source, message, {});
}

void ForensicLogger::log_info(const std::string& source, const std::string& message) {
    log(EventType::INFO, source, message, {});
}

// ==================== AutoRouteSwitch ====================

AutoRouteSwitch::AutoRouteSwitch(uint32_t failure_threshold) 
    : failure_threshold_(failure_threshold) {}

AutoRouteSwitch::~AutoRouteSwitch() {}

void AutoRouteSwitch::register_provider(const std::string& name, int priority) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Add to providers list sorted by priority (higher first)
    auto it = std::find_if(providers_.begin(), providers_.end(),
        [&name](const auto& p) { return p.first == name; });
    
    if (it == providers_.end()) {
        providers_.push_back({name, priority});
        std::sort(providers_.begin(), providers_.end(),
            [](const auto& a, const auto& b) { return a.second > b.second; });
        
        // Initialize status
        ProviderStatus status;
        status.name = name;
        status.consecutive_failures = 0;
        status.total_failures = 0;
        status.total_successes = 0;
        status.is_active = (active_provider_.empty());
        status_.insert_or_assign(name, status);
        
        // Set first provider as active
        if (active_provider_.empty()) {
            active_provider_ = name;
        }
    }
}

void AutoRouteSwitch::record_success(const std::string& provider) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = status_.find(provider);
    if (it != status_.end()) {
        it->second.consecutive_failures = 0;
        it->second.total_successes++;
        it->second.last_success = std::chrono::system_clock::now();
    }
}

void AutoRouteSwitch::record_failure(const std::string& provider) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = status_.find(provider);
    if (it != status_.end()) {
        it->second.consecutive_failures++;
        it->second.total_failures++;
        it->second.last_failure = std::chrono::system_clock::now();
        
        // Check if we need to switch
        if (it->second.consecutive_failures >= failure_threshold_ && 
            provider == active_provider_) {
            check_and_switch(provider);
        }
    }
}

void AutoRouteSwitch::check_and_switch(const std::string& failed_provider) {
    // Find next available provider
    std::string next_provider;
    
    for (const auto& [name, priority] : providers_) {
        if (name != failed_provider) {
            auto it = status_.find(name);
            if (it != status_.end() && it->second.consecutive_failures < failure_threshold_) {
                next_provider = name;
                break;
            }
        }
    }
    
    if (!next_provider.empty() && next_provider != active_provider_) {
        std::string old_provider = active_provider_;
        
        // Update status
        if (auto it = status_.find(active_provider_); it != status_.end()) {
            it->second.is_active = false;
        }
        
        active_provider_ = next_provider;
        
        if (auto it = status_.find(active_provider_); it != status_.end()) {
            it->second.is_active = true;
        }
        
        // Notify callback
        if (switch_callback_) {
            switch_callback_(old_provider, next_provider, "Consecutive failures exceeded threshold");
        }
    }
}

std::string AutoRouteSwitch::get_active_provider() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return active_provider_;
}

std::string AutoRouteSwitch::get_next_provider() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    for (const auto& [name, priority] : providers_) {
        if (name != active_provider_) {
            auto it = status_.find(name);
            if (it != status_.end() && it->second.consecutive_failures < failure_threshold_) {
                return name;
            }
        }
    }
    return "";
}

AutoRouteSwitch::ProviderStatus AutoRouteSwitch::get_provider_status(const std::string& provider) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = status_.find(provider);
    if (it != status_.end()) {
        return it->second;
    }
    return {};
}

std::vector<AutoRouteSwitch::ProviderStatus> AutoRouteSwitch::get_all_provider_status() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<ProviderStatus> result;
    for (const auto& [name, status] : status_) {
        result.push_back(status);
    }
    return result;
}

void AutoRouteSwitch::set_failure_threshold(uint32_t threshold) {
    std::lock_guard<std::mutex> lock(mutex_);
    failure_threshold_ = threshold;
}

void AutoRouteSwitch::set_switch_callback(SwitchCallback callback) {
    std::lock_guard<std::mutex> lock(mutex_);
    switch_callback_ = callback;
}

void AutoRouteSwitch::reset_provider(const std::string& provider) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = status_.find(provider);
    if (it != status_.end()) {
        it->second.consecutive_failures = 0;
        it->second.total_failures = 0;
        it->second.total_successes = 0;
    }
}

void AutoRouteSwitch::reset_all() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    for (auto& [name, status] : status_) {
        status.consecutive_failures = 0;
        status.total_failures = 0;
        status.total_successes = 0;
    }
    
    // Reset to first provider
    if (!providers_.empty()) {
        if (auto it = status_.find(active_provider_); it != status_.end()) {
            it->second.is_active = false;
        }
        active_provider_ = providers_.front().first;
        if (auto it = status_.find(active_provider_); it != status_.end()) {
            it->second.is_active = true;
        }
    }
}

// ==================== CanaryTokens ====================

CanaryTokens::CanaryTokens() {}

CanaryTokens::~CanaryTokens() {}

void CanaryTokens::add_canary(const std::string& domain, const std::string& expected_response) {
    std::lock_guard<std::mutex> lock(mutex_);
    canaries_[domain] = expected_response;
}

void CanaryTokens::remove_canary(const std::string& domain) {
    std::lock_guard<std::mutex> lock(mutex_);
    canaries_.erase(domain);
}

CanaryTokens::CanaryResult CanaryTokens::check_canary(const std::string& domain, 
                                                       const std::string& actual_response) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    CanaryResult result;
    result.domain = domain;
    result.check_time = std::chrono::system_clock::now();
    result.actual_response = actual_response;
    
    auto it = canaries_.find(domain);
    if (it != canaries_.end()) {
        result.expected_response = it->second;
        result.triggered = (actual_response != it->second);
        
        if (result.triggered) {
            result.details = "Response mismatch: expected '" + it->second + 
                           "', got '" + actual_response + "'";
            
            // Notify callback
            if (trigger_callback_) {
                trigger_callback_(result);
            }
        } else {
            result.details = "Response matches expected value";
        }
    } else {
        result.triggered = false;
        result.details = "Unknown canary domain";
    }
    
    return result;
}

std::vector<CanaryTokens::CanaryResult> CanaryTokens::check_all_canaries(
    std::function<std::string(const std::string&)> resolver) {
    
    std::vector<CanaryResult> results;
    
    // Copy canaries to avoid holding lock during resolution
    std::map<std::string, std::string> canaries_copy;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        canaries_copy = canaries_;
    }
    
    for (const auto& [domain, expected] : canaries_copy) {
        std::string actual;
        try {
            actual = resolver(domain);
        } catch (...) {
            actual = "RESOLUTION_FAILED";
        }
        
        auto result = check_canary(domain, actual);
        results.push_back(result);
    }
    
    return results;
}

void CanaryTokens::set_trigger_callback(TriggerCallback callback) {
    std::lock_guard<std::mutex> lock(mutex_);
    trigger_callback_ = callback;
}

std::vector<std::string> CanaryTokens::get_canary_domains() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<std::string> domains;
    for (const auto& [domain, _] : canaries_) {
        domains.push_back(domain);
    }
    return domains;
}

void CanaryTokens::clear_canaries() {
    std::lock_guard<std::mutex> lock(mutex_);
    canaries_.clear();
}

// Helper function to validate SecurityManager configuration
void validate_security_config(const SecurityManager::Config& config) {
    // Latency threshold validation
    if (config.latency_threshold_ms == 0) {
        throw std::invalid_argument("latency_threshold_ms must be greater than 0");
    }
    if (config.latency_threshold_ms > 30000) {
        throw std::invalid_argument("latency_threshold_ms exceeds maximum (30000ms)");
    }
    
    // Padding size validation
    if (config.min_padding_size > config.max_padding_size) {
        throw std::invalid_argument("min_padding_size cannot exceed max_padding_size");
    }
    if (config.max_padding_size > 65536) {
        throw std::invalid_argument("max_padding_size exceeds maximum (65536 bytes)");
    }
    
    // Route switch threshold validation
    if (config.enable_auto_route_switch && config.route_switch_threshold == 0) {
        throw std::invalid_argument("route_switch_threshold must be greater than 0");
    }
}


// ==================== SecurityManager ====================

SecurityManager::SecurityManager() {}

SecurityManager::SecurityManager(const Config& config) : config_(config) {
    validate_security_config(config);  // Validate before use
    // Initialize components based on config
    if (config_.enable_latency_monitoring) {
        latency_monitor_.set_threshold(config_.latency_threshold_ms);

        
    }
    
    if (config_.enable_traffic_padding) {
        traffic_padder_.set_padding_range(config_.min_padding_size, config_.max_padding_size);
    }
    
    if (config_.enable_forensic_logging && !config_.forensic_log_path.empty()) {
        forensic_logger_.set_log_path(config_.forensic_log_path);
        forensic_logger_.set_enabled(true);
    }
    
    if (config_.enable_auto_route_switch) {
        auto_route_switch_.set_failure_threshold(config_.route_switch_threshold);
    }
}

SecurityManager::~SecurityManager() {}

void SecurityManager::configure(const Config& config) {
    validate_security_config(config);  // Validate before use
    config_ = config;
    
    // Reconfigure components
    latency_monitor_.set_threshold(config_.latency_threshold_ms);
traffic_padder_.set_padding_range(config_.min_padding_size, config_.max_padding_size);
    
    if (config_.enable_forensic_logging && !config_.forensic_log_path.empty()) {
        forensic_logger_.set_log_path(config_.forensic_log_path);
    }
    forensic_logger_.set_enabled(config_.enable_forensic_logging);
    
    auto_route_switch_.set_failure_threshold(config_.route_switch_threshold);
}

SecurityManager::Config SecurityManager::get_config() const {
    return config_;
}

} // namespace ncp
