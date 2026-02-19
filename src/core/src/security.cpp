/**
 * @file security.cpp
 * @brief Implementation of security enhancement features
 *
 * All classes use direct member fields as declared in ncp_security.hpp.
 * No pimpl idiom — the header exposes members directly.
 */

#include "../include/ncp_security.hpp"
#include <algorithm>
#include <numeric>
#include <cmath>
#include <iomanip>
#include <sstream>
#include <cstring>
#include <ctime>

#ifdef _WIN32
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  include <windows.h>
#  include <io.h>
// windows.h defines ERROR macro which conflicts with EventType::ERROR
#  ifdef ERROR
#    undef ERROR
#  endif
// Also kill min/max macros if NOMINMAX didn't work (e.g. included transitively)
#  ifdef min
#    undef min
#  endif
#  ifdef max
#    undef max
#  endif
#else
#  include <unistd.h>
#  include <sys/mman.h>
#  include <sys/prctl.h>
#  include <sys/resource.h>
#  include <signal.h>
#  include <dirent.h>
#  include <fstream>
#endif

namespace ncp {

// ==================== CertificatePinner ====================

CertificatePinner::CertificatePinner() {}

CertificatePinner::~CertificatePinner() = default;

void CertificatePinner::add_pin(const std::string& hostname, const std::string& sha256_hash, bool is_backup) {
    std::lock_guard<std::mutex> lock(mutex_);
    PinnedCert cert{hostname, sha256_hash, is_backup};
    pins_.push_back(cert);
}

void CertificatePinner::add_pins(const std::vector<PinnedCert>& pins) {
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto& pin : pins) {
        pins_.push_back(pin);
    }
}

void CertificatePinner::load_default_pins() {
    // Cloudflare DNS
    add_pin("cloudflare-dns.com", "GP8Knf7qBae+aIfythytMbYnL+yowaWVeD6MoLHkVRg=");
    add_pin("cloudflare-dns.com", "RQeZkB42znUfsDIIFWIRiYEcKl7nHwNFwWCrnMMJbVc=", true);
    // Google DNS
    add_pin("dns.google", "WoiWRyIOVNa9ihaBciRSC7XHjliYS9VwUGOIud4PB18=");
    add_pin("dns.google", "lCppFqbkrlJ3EcVFAkeip0+44VaoJUymbnOaEUk7tEU=", true);
    // Quad9 DNS
    add_pin("dns9.quad9.net", "yioEpqeR4WtDwE9YxNVnCEkTxIjx6EEIwFSQW+lJsbc=");
    add_pin("dns9.quad9.net", "Wg+cUJTh+h6OwLd0NWW7R7IlMBuEMkzh/x2IG0S/VLg=", true);
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

LatencyMonitor::LatencyMonitor(uint32_t threshold_ms)
    : threshold_ms_(threshold_ms)
{}

LatencyMonitor::~LatencyMonitor() = default;

void LatencyMonitor::record_latency(const std::string& provider, uint32_t latency_ms) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto& history = latency_history_[provider];
    history.push_back(latency_ms);

    // Keep only last 100 measurements
    if (history.size() > 100) {
        history.erase(history.begin());
    }

    // Fire alert if threshold exceeded
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

LatencyMonitor::LatencyStats LatencyMonitor::get_latency_stats(const std::string& provider) const {
    std::lock_guard<std::mutex> lock(mutex_);
    LatencyStats stats{};

    auto it = latency_history_.find(provider);
    if (it == latency_history_.end() || it->second.empty()) {
        return stats;
    }

    const auto& history = it->second;
    stats.sample_count = static_cast<uint64_t>(history.size());
    stats.last_update = std::chrono::system_clock::now();

    // Average
    uint64_t sum = 0;
    for (auto val : history) sum += val;
    stats.avg_ms = static_cast<uint32_t>(sum / history.size());

    // Min / Max
    stats.min_ms = *std::min_element(history.begin(), history.end());
    stats.max_ms = *std::max_element(history.begin(), history.end());

    // Standard deviation
    double variance = 0.0;
    for (auto val : history) {
        double diff = static_cast<double>(val) - static_cast<double>(stats.avg_ms);
        variance += diff * diff;
    }
    variance /= static_cast<double>(history.size());
    stats.std_dev_ms = static_cast<uint32_t>(std::sqrt(variance));

    // Percentiles
    std::vector<uint32_t> sorted(history.begin(), history.end());
    std::sort(sorted.begin(), sorted.end());

    if (!sorted.empty()) {
        size_t n = sorted.size();
        stats.p50_ms = sorted[(std::min)(n * 50 / 100, n - 1)];
        stats.p95_ms = sorted[(std::min)(n * 95 / 100, n - 1)];
        stats.p99_ms = sorted[(std::min)(n * 99 / 100, n - 1)];
    }

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
    alert_callback_ = std::move(callback);
}

bool LatencyMonitor::is_anomalous(const std::string& provider, uint32_t latency_ms) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = latency_history_.find(provider);
    if (it == latency_history_.end() || it->second.size() < 5) {
        // Not enough data — compare against absolute threshold
        return latency_ms > threshold_ms_;
    }

    const auto& history = it->second;
    uint64_t sum = 0;
    for (auto val : history) sum += val;
    double avg = static_cast<double>(sum) / static_cast<double>(history.size());

    double variance = 0.0;
    for (auto val : history) {
        double diff = static_cast<double>(val) - avg;
        variance += diff * diff;
    }
    double std_dev = std::sqrt(variance / static_cast<double>(history.size()));

    // Anomalous if > 3 standard deviations from mean
    return static_cast<double>(latency_ms) > (avg + 3.0 * std_dev);
}

void LatencyMonitor::clear_history() {
    std::lock_guard<std::mutex> lock(mutex_);
    latency_history_.clear();
}

std::vector<std::string> LatencyMonitor::get_monitored_providers() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::string> providers;
    for (const auto& pair : latency_history_) {
        providers.push_back(pair.first);
    }
    return providers;
}

// ==================== ConnectionMonitor ====================

ConnectionMonitor::ConnectionMonitor() {}

ConnectionMonitor::~ConnectionMonitor() = default;

void ConnectionMonitor::record_connection(
    const std::string& host,
    uint16_t port,
    bool successful,
    uint32_t duration_ms)
{
    std::lock_guard<std::mutex> lock(mutex_);

    ConnectionInfo info;
    info.host = host;
    info.port = port;
    info.timestamp = std::chrono::system_clock::now();
    info.successful = successful;
    info.duration_ms = duration_ms;

    connection_history_.push_back(info);

    // Keep last 1000
    if (connection_history_.size() > 1000) {
        connection_history_.erase(connection_history_.begin());
    }

    // Update per-host stats
    auto& hs = connection_stats_[host];
    hs.total_attempts++;
    if (successful) {
        hs.successful_attempts++;
    } else {
        hs.failed_attempts++;
    }
    hs.total_duration_ms += duration_ms;
    hs.last_attempt = info.timestamp;
}

ConnectionMonitor::HostStats ConnectionMonitor::get_host_stats(const std::string& host) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = connection_stats_.find(host);
    if (it != connection_stats_.end()) {
        return it->second;
    }
    return HostStats{};
}

std::vector<ConnectionMonitor::ConnectionInfo> ConnectionMonitor::get_recent_connections(
    size_t count) const
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (count >= connection_history_.size()) {
        return connection_history_;
    }
    auto start_it = connection_history_.end() - static_cast<ptrdiff_t>(count);
    return std::vector<ConnectionInfo>(start_it, connection_history_.end());
}

void ConnectionMonitor::clear_history() {
    std::lock_guard<std::mutex> lock(mutex_);
    connection_history_.clear();
    connection_stats_.clear();
}

// ==================== TrafficPadder ====================

TrafficPadder::TrafficPadder(uint32_t min_size, uint32_t max_size)
    : min_size_(min_size), max_size_(max_size)
{
    // Phase 0: CSPRNG init (idempotent)
    ncp::csprng_init();
}

TrafficPadder::~TrafficPadder() = default;

std::vector<uint8_t> TrafficPadder::add_padding(const std::vector<uint8_t>& data) {
    std::lock_guard<std::mutex> lock(mutex_);

    // Determine target size
    uint32_t target = (std::max)(min_size_, static_cast<uint32_t>(data.size()));
    if (target < max_size_) {
        target = static_cast<uint32_t>(ncp::csprng_range(
            static_cast<int>(target), static_cast<int>(max_size_)));
    }

    // Format: [4-byte original length (big-endian)] [original data] [random padding]
    std::vector<uint8_t> result;
    result.reserve(4 + target);

    uint32_t orig_len = static_cast<uint32_t>(data.size());
    result.push_back(static_cast<uint8_t>((orig_len >> 24) & 0xFF));
    result.push_back(static_cast<uint8_t>((orig_len >> 16) & 0xFF));
    result.push_back(static_cast<uint8_t>((orig_len >> 8) & 0xFF));
    result.push_back(static_cast<uint8_t>(orig_len & 0xFF));

    result.insert(result.end(), data.begin(), data.end());

    // Fill remainder with CSPRNG bytes
    size_t pad_needed = static_cast<size_t>(4 + target) - result.size();
    if (pad_needed > 0) {
        size_t old_size = result.size();
        result.resize(old_size + pad_needed);
        ncp::csprng_fill(result.data() + old_size, pad_needed);
    }

    return result;
}

std::vector<uint8_t> TrafficPadder::remove_padding(const std::vector<uint8_t>& data) {
    if (data.size() < 4) return data;

    uint32_t orig_len = (static_cast<uint32_t>(data[0]) << 24)
                      | (static_cast<uint32_t>(data[1]) << 16)
                      | (static_cast<uint32_t>(data[2]) << 8)
                      | static_cast<uint32_t>(data[3]);

    if (orig_len > data.size() - 4) {
        return data;  // Corrupted — return as-is
    }

    return std::vector<uint8_t>(data.begin() + 4, data.begin() + 4 + orig_len);
}

void TrafficPadder::set_padding_range(uint32_t min_size, uint32_t max_size) {
    std::lock_guard<std::mutex> lock(mutex_);
    min_size_ = min_size;
    max_size_ = max_size;
}

// ==================== ForensicLogger ====================

ForensicLogger::ForensicLogger() : enabled_(false) {}

ForensicLogger::ForensicLogger(const std::string& log_path)
    : log_path_(log_path), enabled_(true)
{
    if (!log_path_.empty()) {
        log_file_.open(log_path_, std::ios::app);
    }
}

ForensicLogger::~ForensicLogger() {
    if (log_file_.is_open()) {
        log_file_.flush();
        log_file_.close();
    }
}

std::string ForensicLogger::event_type_to_string(EventType type) const {
    switch (type) {
        case EventType::DNS_QUERY:                return "DNS_QUERY";
        case EventType::DNS_RESPONSE:             return "DNS_RESPONSE";
        case EventType::CERTIFICATE_VERIFICATION: return "CERT_VERIFY";
        case EventType::LATENCY_ALERT:            return "LATENCY_ALERT";
        case EventType::ROUTE_SWITCH:             return "ROUTE_SWITCH";
        case EventType::CANARY_TRIGGERED:         return "CANARY_TRIGGERED";
        case EventType::ERROR:                    return "ERROR";
        case EventType::WARNING:                  return "WARNING";
        case EventType::INFO:                     return "INFO";
    }
    return "UNKNOWN";
}

void ForensicLogger::write_entry(const LogEntry& entry) {
    if (!log_file_.is_open()) return;

    auto time_t_val = std::chrono::system_clock::to_time_t(entry.timestamp);
    struct tm tm_buf{};
#ifdef _WIN32
    gmtime_s(&tm_buf, &time_t_val);
#else
    gmtime_r(&time_t_val, &tm_buf);
#endif

    log_file_ << std::put_time(&tm_buf, "%Y-%m-%dT%H:%M:%SZ")
              << " [" << event_type_to_string(entry.type) << "]"
              << " src=" << entry.source
              << " msg=" << entry.message;

    for (const auto& kv : entry.metadata) {
        log_file_ << " " << kv.first << "=" << kv.second;
    }
    log_file_ << "\n";
}

void ForensicLogger::log(EventType type, const std::string& source,
                         const std::string& message,
                         const std::map<std::string, std::string>& metadata)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (!enabled_) return;

    LogEntry entry;
    entry.timestamp = std::chrono::system_clock::now();
    entry.type = type;
    entry.source = source;
    entry.message = message;
    entry.metadata = metadata;

    entries_.push_back(entry);
    if (entries_.size() > 10000) {
        entries_.erase(entries_.begin());
    }

    write_entry(entry);
}

void ForensicLogger::log_dns_query(const std::string& hostname, const std::string& provider) {
    log(EventType::DNS_QUERY, "dns", hostname, {{"provider", provider}});
}

void ForensicLogger::log_dns_response(const std::string& hostname, uint32_t latency_ms, bool success) {
    log(EventType::DNS_RESPONSE, "dns", hostname,
        {{"latency_ms", std::to_string(latency_ms)}, {"success", success ? "true" : "false"}});
}

void ForensicLogger::log_cert_verification(const std::string& hostname, bool valid) {
    log(EventType::CERTIFICATE_VERIFICATION, "tls", hostname,
        {{"valid", valid ? "true" : "false"}});
}

void ForensicLogger::log_latency_alert(const std::string& provider, uint32_t latency_ms) {
    log(EventType::LATENCY_ALERT, "latency", provider,
        {{"latency_ms", std::to_string(latency_ms)}});
}

void ForensicLogger::log_route_switch(const std::string& from, const std::string& to, const std::string& reason) {
    log(EventType::ROUTE_SWITCH, "routing", "switch",
        {{"from", from}, {"to", to}, {"reason", reason}});
}

void ForensicLogger::log_canary_triggered(const std::string& domain, const std::string& details) {
    log(EventType::CANARY_TRIGGERED, "canary", domain, {{"details", details}});
}

void ForensicLogger::log_error(const std::string& source, const std::string& message) {
    log(EventType::ERROR, source, message);
}

void ForensicLogger::log_warning(const std::string& source, const std::string& message) {
    log(EventType::WARNING, source, message);
}

void ForensicLogger::log_info(const std::string& source, const std::string& message) {
    log(EventType::INFO, source, message);
}

void ForensicLogger::set_log_path(const std::string& path) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (log_file_.is_open()) {
        log_file_.flush();
        log_file_.close();
    }
    log_path_ = path;
    if (!path.empty()) {
        log_file_.open(path, std::ios::app);
    }
}

void ForensicLogger::set_enabled(bool enabled) {
    std::lock_guard<std::mutex> lock(mutex_);
    enabled_ = enabled;
}

void ForensicLogger::flush() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (log_file_.is_open()) {
        log_file_.flush();
    }
}

std::vector<ForensicLogger::LogEntry> ForensicLogger::get_recent_entries(size_t count) const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (count >= entries_.size()) {
        return entries_;
    }
    auto start_it = entries_.end() - static_cast<ptrdiff_t>(count);
    return std::vector<LogEntry>(start_it, entries_.end());
}

// ==================== AutoRouteSwitch ====================

AutoRouteSwitch::AutoRouteSwitch(uint32_t failure_threshold)
    : failure_threshold_(failure_threshold)
{}

AutoRouteSwitch::~AutoRouteSwitch() = default;

void AutoRouteSwitch::register_provider(const std::string& name, int priority) {
    std::lock_guard<std::mutex> lock(mutex_);
    providers_.push_back({name, priority});
    // Sort by priority (higher = better)
    std::sort(providers_.begin(), providers_.end(),
              [](const auto& a, const auto& b) { return a.second > b.second; });

    ProviderStatus ps;
    ps.name = name;
    ps.consecutive_failures = 0;
    ps.total_failures = 0;
    ps.total_successes = 0;
    ps.is_active = active_provider_.empty();
    ps.last_failure = {};
    ps.last_success = {};
    status_[name] = ps;

    if (active_provider_.empty()) {
        active_provider_ = name;
    }
}

void AutoRouteSwitch::record_success(const std::string& provider) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = status_.find(provider);
    if (it == status_.end()) return;

    it->second.consecutive_failures = 0;
    it->second.total_successes++;
    it->second.last_success = std::chrono::system_clock::now();
}

void AutoRouteSwitch::record_failure(const std::string& provider) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = status_.find(provider);
    if (it == status_.end()) return;

    it->second.consecutive_failures++;
    it->second.total_failures++;
    it->second.last_failure = std::chrono::system_clock::now();

    if (it->second.consecutive_failures >= failure_threshold_ && provider == active_provider_) {
        check_and_switch(provider);
    }
}

void AutoRouteSwitch::check_and_switch(const std::string& failed_provider) {
    // Already under lock from caller
    std::string next;
    for (const auto& p : providers_) {
        if (p.first != failed_provider) {
            auto sit = status_.find(p.first);
            if (sit != status_.end() && sit->second.consecutive_failures < failure_threshold_) {
                next = p.first;
                break;
            }
        }
    }

    if (!next.empty()) {
        std::string old_active = active_provider_;
        if (status_.count(old_active)) status_[old_active].is_active = false;
        active_provider_ = next;
        status_[next].is_active = true;

        if (switch_callback_) {
            switch_callback_(old_active, next, "consecutive failures >= " + std::to_string(failure_threshold_));
        }
    }
}

std::string AutoRouteSwitch::get_active_provider() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return active_provider_;
}

std::string AutoRouteSwitch::get_next_provider() const {
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto& p : providers_) {
        if (p.first != active_provider_) {
            return p.first;
        }
    }
    return active_provider_;
}

AutoRouteSwitch::ProviderStatus AutoRouteSwitch::get_provider_status(const std::string& provider) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = status_.find(provider);
    if (it != status_.end()) return it->second;
    return ProviderStatus{};
}

std::vector<AutoRouteSwitch::ProviderStatus> AutoRouteSwitch::get_all_provider_status() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<ProviderStatus> result;
    for (const auto& pair : status_) {
        result.push_back(pair.second);
    }
    return result;
}

void AutoRouteSwitch::set_failure_threshold(uint32_t threshold) {
    std::lock_guard<std::mutex> lock(mutex_);
    failure_threshold_ = threshold;
}

void AutoRouteSwitch::set_switch_callback(SwitchCallback callback) {
    std::lock_guard<std::mutex> lock(mutex_);
    switch_callback_ = std::move(callback);
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
    for (auto& pair : status_) {
        pair.second.consecutive_failures = 0;
        pair.second.total_failures = 0;
        pair.second.total_successes = 0;
    }
}

// ==================== CanaryTokens ====================

CanaryTokens::CanaryTokens() {}

CanaryTokens::~CanaryTokens() = default;

void CanaryTokens::add_canary(const std::string& domain, const std::string& expected_response) {
    std::lock_guard<std::mutex> lock(mutex_);
    canaries_[domain] = expected_response;
}

void CanaryTokens::remove_canary(const std::string& domain) {
    std::lock_guard<std::mutex> lock(mutex_);
    canaries_.erase(domain);
}

CanaryTokens::CanaryResult CanaryTokens::check_canary(
    const std::string& domain, const std::string& actual_response)
{
    std::lock_guard<std::mutex> lock(mutex_);
    CanaryResult result;
    result.domain = domain;
    result.check_time = std::chrono::system_clock::now();
    result.actual_response = actual_response;

    auto it = canaries_.find(domain);
    if (it == canaries_.end()) {
        result.triggered = false;
        result.details = "Unknown canary domain";
        return result;
    }

    result.expected_response = it->second;
    result.triggered = (actual_response != it->second);
    result.details = result.triggered
        ? "INTERCEPTED: expected [" + it->second + "] got [" + actual_response + "]"
        : "OK";

    if (result.triggered && trigger_callback_) {
        trigger_callback_(result);
    }

    return result;
}

std::vector<CanaryTokens::CanaryResult> CanaryTokens::check_all_canaries(
    std::function<std::string(const std::string&)> resolver)
{
    // Copy canaries under lock, then resolve outside
    std::map<std::string, std::string> canaries_copy;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        canaries_copy = canaries_;
    }

    std::vector<CanaryResult> results;
    for (const auto& pair : canaries_copy) {
        std::string actual = resolver(pair.first);
        results.push_back(check_canary(pair.first, actual));
    }
    return results;
}

void CanaryTokens::set_trigger_callback(TriggerCallback callback) {
    std::lock_guard<std::mutex> lock(mutex_);
    trigger_callback_ = std::move(callback);
}

std::vector<std::string> CanaryTokens::get_canary_domains() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::string> domains;
    for (const auto& pair : canaries_) {
        domains.push_back(pair.first);
    }
    return domains;
}

void CanaryTokens::clear_canaries() {
    std::lock_guard<std::mutex> lock(mutex_);
    canaries_.clear();
}

// ==================== SecurityManager ====================

SecurityManager::SecurityManager()
    : latency_monitor_(500)
{}

SecurityManager::SecurityManager(const Config& config)
    : config_(config),
      latency_monitor_(config.latency_threshold_ms),
      traffic_padder_(config.min_padding_size, config.max_padding_size),
      forensic_logger_(config.forensic_log_path),
      auto_route_switch_(config.route_switch_threshold)
{
    if (config.enable_certificate_pinning) {
        cert_pinner_.load_default_pins();
    }
    forensic_logger_.set_enabled(config.enable_forensic_logging);
}

SecurityManager::~SecurityManager() = default;

void SecurityManager::configure(const Config& config) {
    config_ = config;
    latency_monitor_.set_threshold(config.latency_threshold_ms);
    traffic_padder_.set_padding_range(config.min_padding_size, config.max_padding_size);
    auto_route_switch_.set_failure_threshold(config.route_switch_threshold);
    forensic_logger_.set_enabled(config.enable_forensic_logging);
    if (!config.forensic_log_path.empty()) {
        forensic_logger_.set_log_path(config.forensic_log_path);
    }
}

SecurityManager::Config SecurityManager::get_config() const {
    return config_;
}

// ==================== AntiForensics ====================

AntiForensics::AntiForensics() {}

AntiForensics::AntiForensics(const Config& config) : config_(config) {}

bool AntiForensics::secure_delete_file(const std::string& path) {
#ifdef _WIN32
    HANDLE hFile = CreateFileA(path.c_str(), GENERIC_WRITE, 0, nullptr,
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return false;

    LARGE_INTEGER file_size;
    GetFileSizeEx(hFile, &file_size);
    auto size = static_cast<size_t>(file_size.QuadPart);

    size_t buf_size = size < 65536 ? size : 65536;
    std::vector<uint8_t> buf(buf_size);
    for (int pass = 0; pass < config_.overwrite_passes; ++pass) {
        SetFilePointer(hFile, 0, nullptr, FILE_BEGIN);
        uint8_t fill = (pass % 3 == 0) ? 0x00 : (pass % 3 == 1) ? 0xFF : 0x55;
        std::memset(buf.data(), fill, buf.size());
        size_t remaining = size;
        while (remaining > 0) {
            DWORD to_write = static_cast<DWORD>(remaining < buf.size() ? remaining : buf.size());
            DWORD written = 0;
            WriteFile(hFile, buf.data(), to_write, &written, nullptr);
            remaining -= written;
        }
        FlushFileBuffers(hFile);
    }
    CloseHandle(hFile);
    return DeleteFileA(path.c_str()) != 0;
#else
    std::fstream file(path, std::ios::in | std::ios::out | std::ios::binary);
    if (!file.is_open()) return false;

    file.seekg(0, std::ios::end);
    auto size = static_cast<size_t>(file.tellg());

    size_t buf_size = size < 65536 ? size : 65536;
    std::vector<uint8_t> buf(buf_size);
    for (int pass = 0; pass < config_.overwrite_passes; ++pass) {
        file.seekp(0, std::ios::beg);
        uint8_t fill = (pass % 3 == 0) ? 0x00 : (pass % 3 == 1) ? 0xFF : 0x55;
        std::memset(buf.data(), fill, buf.size());
        size_t remaining = size;
        while (remaining > 0) {
            size_t chunk = remaining < buf.size() ? remaining : buf.size();
            file.write(reinterpret_cast<char*>(buf.data()), static_cast<std::streamsize>(chunk));
            remaining -= chunk;
        }
        file.flush();
    }
    file.close();
    return (unlink(path.c_str()) == 0);
#endif
}

bool AntiForensics::secure_delete_directory(const std::string& path) {
    (void)path;
    return false;
}

bool AntiForensics::lock_memory(void* ptr, size_t size) {
#ifdef _WIN32
    return VirtualLock(ptr, size) != 0;
#else
    return mlock(ptr, size) == 0;
#endif
}

bool AntiForensics::unlock_memory(void* ptr, size_t size) {
#ifdef _WIN32
    return VirtualUnlock(ptr, size) != 0;
#else
    return munlock(ptr, size) == 0;
#endif
}

bool AntiForensics::secure_zero_memory(void* ptr, size_t size) {
    if (!ptr || size == 0) return false;
#ifdef _WIN32
    SecureZeroMemory(ptr, size);
#else
    volatile unsigned char* p = static_cast<volatile unsigned char*>(ptr);
    for (size_t i = 0; i < size; ++i) p[i] = 0;
#endif
    return true;
}

bool AntiForensics::disable_ptrace() {
#ifdef _WIN32
    return false;
#else
    return prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) == 0;
#endif
}

bool AntiForensics::enable_aslr() {
    return true;
}

bool AntiForensics::set_process_dumpable(bool dumpable) {
#ifdef _WIN32
    (void)dumpable;
    return false;
#else
    return prctl(PR_SET_DUMPABLE, dumpable ? 1 : 0, 0, 0, 0) == 0;
#endif
}

bool AntiForensics::clear_bash_history() {
#ifdef _WIN32
    return false;
#else
    const char* home = getenv("HOME");
    if (!home) return false;
    std::string hist_path = std::string(home) + "/.bash_history";
    return secure_delete_file(hist_path);
#endif
}

bool AntiForensics::clear_system_logs() {
    return false;
}

bool AntiForensics::clear_browser_cache() {
    return false;
}

// ==================== MonitoringDetector ====================

MonitoringDetector::MonitoringDetector() {}

bool MonitoringDetector::is_debugger_present() {
#ifdef _WIN32
    return IsDebuggerPresent() != 0;
#else
    return check_debugger_linux();
#endif
}

bool MonitoringDetector::check_debugger_linux() {
#ifdef _WIN32
    return false;
#else
    std::ifstream status_file("/proc/self/status");
    std::string line;
    while (std::getline(status_file, line)) {
        if (line.find("TracerPid:") != std::string::npos) {
            auto pos = line.find(':');
            if (pos != std::string::npos) {
                int pid = std::stoi(line.substr(pos + 1));
                return pid != 0;
            }
        }
    }
    return false;
#endif
}

bool MonitoringDetector::is_running_in_vm() {
    return check_vm_artifacts();
}

bool MonitoringDetector::check_vm_artifacts() {
#ifdef _WIN32
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\VBoxGuest",
                      0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return true;
    }
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\VMware, Inc.\\VMware Tools",
                      0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return true;
    }
    return false;
#else
    std::ifstream vendor("/sys/class/dmi/id/sys_vendor");
    if (vendor.is_open()) {
        std::string v;
        std::getline(vendor, v);
        if (v.find("QEMU") != std::string::npos ||
            v.find("VMware") != std::string::npos ||
            v.find("VirtualBox") != std::string::npos ||
            v.find("Xen") != std::string::npos) {
            return true;
        }
    }
    return false;
#endif
}

bool MonitoringDetector::is_running_in_sandbox() {
#ifdef _WIN32
    if (GetModuleHandleA("SbieDll.dll")) return true;
    return false;
#else
    std::ifstream cgroup("/proc/1/cgroup");
    if (cgroup.is_open()) {
        std::string line;
        while (std::getline(cgroup, line)) {
            if (line.find("docker") != std::string::npos ||
                line.find("lxc") != std::string::npos) {
                return true;
            }
        }
    }
    return false;
#endif
}

bool MonitoringDetector::is_network_monitored() {
    return detect_wireshark();
}

bool MonitoringDetector::detect_wireshark() {
#ifdef _WIN32
    HWND hwnd = FindWindowA(nullptr, "The Wireshark Network Analyzer");
    return hwnd != nullptr;
#else
    DIR* proc_dir = opendir("/proc");
    if (!proc_dir) return false;

    struct dirent* entry;
    while ((entry = readdir(proc_dir)) != nullptr) {
        if (entry->d_name[0] < '0' || entry->d_name[0] > '9') continue;

        std::string cmdline_path = std::string("/proc/") + entry->d_name + "/comm";
        std::ifstream comm(cmdline_path);
        if (comm.is_open()) {
            std::string name;
            std::getline(comm, name);
            if (name == "wireshark" || name == "tshark" ||
                name == "tcpdump" || name == "dumpcap") {
                closedir(proc_dir);
                return true;
            }
        }
    }
    closedir(proc_dir);
    return false;
#endif
}

MonitoringDetector::ThreatInfo MonitoringDetector::scan_threats() {
    ThreatInfo info;
    info.debugger_detected = is_debugger_present();
    info.vm_detected = is_running_in_vm();
    info.sandbox_detected = is_running_in_sandbox();
    info.wireshark_detected = detect_wireshark();
    return info;
}

bool MonitoringDetector::evade_debugger() {
#ifdef _WIN32
    if (IsDebuggerPresent()) {
        return false;
    }
    return true;
#else
    return prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) == 0;
#endif
}

bool MonitoringDetector::break_on_debug() {
#ifdef _WIN32
    if (IsDebuggerPresent()) {
        DebugBreak();
        return true;
    }
    return false;
#else
    if (check_debugger_linux()) {
        raise(SIGTRAP);
        return true;
    }
    return false;
#endif
}

// ==================== ProcessStealth ====================

ProcessStealth::ProcessStealth() {}

bool ProcessStealth::hide_process() {
#ifdef _WIN32
    return false;
#else
    return prctl(PR_SET_NAME, config_.fake_name.c_str(), 0, 0, 0) == 0;
#endif
}

bool ProcessStealth::unhide_process() {
#ifdef _WIN32
    return false;
#else
    if (original_name_.empty()) return false;
    return prctl(PR_SET_NAME, original_name_.c_str(), 0, 0, 0) == 0;
#endif
}

bool ProcessStealth::hide_network_connections() {
    return false;
}

bool ProcessStealth::set_fake_process_name(const std::string& name) {
#ifdef _WIN32
    (void)name;
    return false;
#else
    if (original_name_.empty()) {
        char buf[16]{};
        prctl(PR_GET_NAME, buf, 0, 0, 0);
        original_name_ = buf;
    }
    config_.fake_name = name;
    return prctl(PR_SET_NAME, name.c_str(), 0, 0, 0) == 0;
#endif
}

} // namespace ncp
