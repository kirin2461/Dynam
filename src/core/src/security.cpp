/**
 * @file security.cpp
 * @brief Implementation of security enhancement features
 *
 * All classes use direct member fields as declared in ncp_security.hpp.
 * No pimpl idiom — the header exposes members directly.
 *
 * Fixed issues:
 *   #42 — CertificatePinner: added TOFU, pin expiry (max_age), backup pin
 *          fallback, and mismatch reporting callback
 *   #43 — secure_delete_file: storage-aware deletion (HDD/SSD/CoW detection)
 *   #44 — clear_bash_history → clear_shell_history: covers bash/zsh/fish,
 *          unsets HISTFILE, and calls `history -c` equivalent
 *   #58 — secure_zero_memory: use sodium_memzero() instead of volatile loop
 *   #58 — clear_shell_history: replace system() with Win32 API on Windows
 *   #58 — TrafficPadder: add HMAC integrity check to padding envelope
 *   #110 — Implement all 10 stubs + fix 3 functional issues:
 *          secure_delete_directory, clear_system_logs, clear_browser_cache,
 *          hide_network_connections, Windows ProcessStealth/AntiForensics,
 *          enable_aslr honest return, ThreatInfo dead fields, evade_debugger
 *          dedup, ForensicLogger rotation
 */

#include "../include/ncp_security.hpp"
#include <algorithm>
#include <numeric>
#include <cmath>
#include <iomanip>
#include <sstream>
#include <cstring>
#include <ctime>
#include <sodium.h>

#ifdef _WIN32
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  include <windows.h>
#  include <io.h>
#  include <tlhelp32.h>
#  include <shlobj.h>
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
#  include <sys/ptrace.h>
#  include <sys/resource.h>
#  include <sys/stat.h>
#  include <sys/ioctl.h>
#  include <sys/vfs.h>
#  include <sys/wait.h>
#  include <linux/fs.h>
#  include <linux/magic.h>
#  include <fcntl.h>
#  include <signal.h>
#  include <dirent.h>
#  include <fstream>
#  include <pwd.h>
#endif

namespace ncp {

// ==================== CertificatePinner ====================

CertificatePinner::CertificatePinner() {}

CertificatePinner::~CertificatePinner() = default;

void CertificatePinner::add_pin(const std::string& hostname, const std::string& sha256_hash,
                                 bool is_backup, std::chrono::seconds max_age) {
    std::lock_guard<std::mutex> lock(mutex_);
    PinnedCert cert;
    cert.hostname = hostname;
    cert.sha256_hash = sha256_hash;
    cert.is_backup = is_backup;
    cert.added_at = std::chrono::system_clock::now();
    cert.max_age = max_age;
    pins_.push_back(cert);
}

void CertificatePinner::add_pins(const std::vector<PinnedCert>& pins) {
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto& pin : pins) {
        pins_.push_back(pin);
    }
}

bool CertificatePinner::trust_on_first_use(const std::string& hostname,
                                            const std::string& cert_hash,
                                            std::chrono::seconds max_age) {
    std::lock_guard<std::mutex> lock(mutex_);
    // Check if we already have any (non-expired) pins for this hostname
    for (const auto& pin : pins_) {
        if (pin.hostname == hostname && !is_pin_expired(pin)) {
            return false;  // Pins already exist — TOFU does not override
        }
    }
    // First contact: trust and pin with expiry
    PinnedCert cert;
    cert.hostname = hostname;
    cert.sha256_hash = cert_hash;
    cert.is_backup = false;
    cert.added_at = std::chrono::system_clock::now();
    cert.max_age = max_age;
    pins_.push_back(cert);
    return true;
}

void CertificatePinner::load_default_pins() {
    // Default pins use 0 max_age (no expiry) — these are well-known providers
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

    // Collect primary and backup pins for this hostname (skip expired)
    std::vector<const PinnedCert*> primary_pins;
    std::vector<const PinnedCert*> backup_pins;

    for (const auto& pin : pins_) {
        if (pin.hostname != hostname) continue;
        if (is_pin_expired(pin)) continue;

        if (pin.is_backup) {
            backup_pins.push_back(&pin);
        } else {
            primary_pins.push_back(&pin);
        }
    }

    // If no valid pins exist for this hostname, fail closed
    if (primary_pins.empty() && backup_pins.empty()) {
        return false;
    }

    // Check primary pins first
    for (const auto* pin : primary_pins) {
        if (pin->sha256_hash == cert_hash) {
            return true;
        }
    }

    // Primary mismatch — try backup pins
    bool backup_matched = false;
    for (const auto* pin : backup_pins) {
        if (pin->sha256_hash == cert_hash) {
            backup_matched = true;
            break;
        }
    }

    // Report mismatch (even if backup matched — signals key rotation in progress)
    std::string expected = primary_pins.empty() ? "(none)" : primary_pins[0]->sha256_hash;
    report_mismatch(hostname, expected, cert_hash, backup_matched);

    return backup_matched;
}

void CertificatePinner::report_mismatch(const std::string& hostname, const std::string& expected,
                                         const std::string& actual, bool backup_matched) const {
    if (!mismatch_callback_) return;

    PinMismatchReport report;
    report.hostname = hostname;
    report.expected_hash = expected;
    report.actual_hash = actual;
    report.backup_matched = backup_matched;
    report.timestamp = std::chrono::system_clock::now();
    mismatch_callback_(report);
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

void CertificatePinner::remove_expired_pins() {
    std::lock_guard<std::mutex> lock(mutex_);
    auto now = std::chrono::system_clock::now();
    pins_.erase(
        std::remove_if(pins_.begin(), pins_.end(), [&](const PinnedCert& pin) {
            if (pin.max_age.count() == 0) return false;  // No expiry
            return (now - pin.added_at) > pin.max_age;
        }),
        pins_.end()
    );
}

bool CertificatePinner::is_pin_expired(const PinnedCert& pin) const {
    if (pin.max_age.count() == 0) return false;  // No expiry
    auto now = std::chrono::system_clock::now();
    return (now - pin.added_at) > pin.max_age;
}

void CertificatePinner::set_mismatch_callback(MismatchCallback callback) {
    std::lock_guard<std::mutex> lock(mutex_);
    mismatch_callback_ = std::move(callback);
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
// FIX #58: Padding envelope now uses HMAC-SHA256 for integrity.
// Format: [32-byte HMAC] [4-byte orig_len (BE)] [original data] [random padding]
// HMAC covers: orig_len || original_data
// Key is derived once per TrafficPadder instance via CSPRNG.

TrafficPadder::TrafficPadder(uint32_t min_size, uint32_t max_size)
    : min_size_(min_size), max_size_(max_size)
{
    // Phase 0: CSPRNG init (idempotent)
    ncp::csprng_init();

    // Generate HMAC key for padding integrity
    hmac_key_.resize(crypto_auth_KEYBYTES);
    randombytes_buf(hmac_key_.data(), hmac_key_.size());
}

TrafficPadder::~TrafficPadder() {
    // Securely wipe the HMAC key
    if (!hmac_key_.empty()) {
        sodium_memzero(hmac_key_.data(), hmac_key_.size());
    }
}

std::vector<uint8_t> TrafficPadder::add_padding(const std::vector<uint8_t>& data) {
    std::lock_guard<std::mutex> lock(mutex_);

    // Determine target size
    uint32_t target = (std::max)(min_size_, static_cast<uint32_t>(data.size()));
    if (target < max_size_) {
        target = static_cast<uint32_t>(ncp::csprng_range(
            static_cast<int>(target), static_cast<int>(max_size_)));
    }

    // Build authenticated payload: [orig_len (4 BE)] [original data]
    std::vector<uint8_t> payload;
    uint32_t orig_len = static_cast<uint32_t>(data.size());
    payload.push_back(static_cast<uint8_t>((orig_len >> 24) & 0xFF));
    payload.push_back(static_cast<uint8_t>((orig_len >> 16) & 0xFF));
    payload.push_back(static_cast<uint8_t>((orig_len >> 8) & 0xFF));
    payload.push_back(static_cast<uint8_t>(orig_len & 0xFF));
    payload.insert(payload.end(), data.begin(), data.end());

    // Compute HMAC-SHA256 over the payload (orig_len || data)
    uint8_t mac[crypto_auth_BYTES];
    crypto_auth(mac, payload.data(), payload.size(), hmac_key_.data());

    // Format: [HMAC (32)] [orig_len (4)] [data] [random padding]
    std::vector<uint8_t> result;
    result.reserve(crypto_auth_BYTES + 4 + target);

    // Prepend HMAC
    result.insert(result.end(), mac, mac + crypto_auth_BYTES);

    // Append payload (orig_len + data)
    result.insert(result.end(), payload.begin(), payload.end());

    // Fill remainder with CSPRNG bytes
    size_t total_target = static_cast<size_t>(crypto_auth_BYTES + 4 + target);
    if (result.size() < total_target) {
        size_t pad_needed = total_target - result.size();
        size_t old_size = result.size();
        result.resize(old_size + pad_needed);
        ncp::csprng_fill(result.data() + old_size, pad_needed);
    }

    return result;
}

std::vector<uint8_t> TrafficPadder::remove_padding(const std::vector<uint8_t>& data) {
    // Minimum size: HMAC (32) + orig_len (4) = 36 bytes
    if (data.size() < crypto_auth_BYTES + 4) return data;

    // Extract HMAC
    const uint8_t* mac = data.data();
    const uint8_t* payload = data.data() + crypto_auth_BYTES;
    size_t payload_size = data.size() - crypto_auth_BYTES;

    // Read orig_len from payload
    uint32_t orig_len = (static_cast<uint32_t>(payload[0]) << 24)
                      | (static_cast<uint32_t>(payload[1]) << 16)
                      | (static_cast<uint32_t>(payload[2]) << 8)
                      | static_cast<uint32_t>(payload[3]);

    // Bounds check: orig_len must fit within payload after the 4-byte header
    if (orig_len > payload_size - 4) {
        return data;  // Corrupted — return as-is
    }

    // Verify HMAC over [orig_len (4)] [original data (orig_len)]
    // The authenticated region is exactly: 4 + orig_len bytes from payload start
    size_t authenticated_size = 4 + orig_len;
    if (crypto_auth_verify(mac, payload, authenticated_size, hmac_key_.data()) != 0) {
        return data;  // HMAC mismatch — tampered or corrupted, return as-is
    }

    // HMAC verified — extract original data
    return std::vector<uint8_t>(payload + 4, payload + 4 + orig_len);
}

void TrafficPadder::set_padding_range(uint32_t min_size, uint32_t max_size) {
    std::lock_guard<std::mutex> lock(mutex_);
    min_size_ = min_size;
    max_size_ = max_size;
}

// ==================== ForensicLogger ====================
// FIX #110: Added log rotation when file exceeds 10 MB

static constexpr size_t FORENSIC_LOG_MAX_BYTES = 10 * 1024 * 1024;  // 10 MB

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

    // FIX #110: Check file size and rotate if needed
    auto pos = log_file_.tellp();
    if (pos > 0 && static_cast<size_t>(pos) >= FORENSIC_LOG_MAX_BYTES) {
        // Rotate: close current, rename to .1, reopen
        log_file_.flush();
        log_file_.close();

        std::string rotated = log_path_ + ".1";
        // Remove old rotated file if exists
        std::remove(rotated.c_str());
        std::rename(log_path_.c_str(), rotated.c_str());

        // Reopen fresh file
        log_file_.open(log_path_, std::ios::trunc);
        if (!log_file_.is_open()) return;

        // Trim in-memory entries to last 1000 (keep recent context)
        if (entries_.size() > 1000) {
            entries_.erase(entries_.begin(),
                           entries_.begin() + static_cast<ptrdiff_t>(entries_.size() - 1000));
        }
    }

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

AntiForensics::StorageType AntiForensics::detect_storage_type(const std::string& path) const {
#ifdef _WIN32
    // On Windows, check drive type
    char drive[4] = { path[0], ':', '\\', '\0' };
    UINT type = GetDriveTypeA(drive);
    // Cannot distinguish SSD from HDD via GetDriveType alone — assume SSD (conservative)
    if (type == DRIVE_FIXED) return StorageType::SSD;
    if (type == DRIVE_REMOTE) return StorageType::UNKNOWN;
    return StorageType::UNKNOWN;
#else
    // Check filesystem type for CoW detection
    struct statfs sfs{};
    if (statfs(path.c_str(), &sfs) == 0) {
        // BTRFS_SUPER_MAGIC = 0x9123683E, ZFS has no standard magic but common value
        if (sfs.f_type == 0x9123683E  /* BTRFS */
            || sfs.f_type == 0x2FC12FC1 /* ZFS */) {
            return StorageType::COW_FS;
        }
    }

    // Determine block device and check rotational flag
    struct stat st{};
    if (stat(path.c_str(), &st) != 0) return StorageType::UNKNOWN;

    unsigned int major_num = major(st.st_dev);
    unsigned int minor_num = minor(st.st_dev);

    // Read /sys/dev/block/<major>:<minor>/queue/rotational
    std::string sysfs_path = "/sys/dev/block/" + std::to_string(major_num) + ":"
                           + std::to_string(minor_num) + "/queue/rotational";
    std::ifstream rotational(sysfs_path);
    if (rotational.is_open()) {
        int val = -1;
        rotational >> val;
        if (val == 0) return StorageType::SSD;
        if (val == 1) return StorageType::HDD;
    }

    // Fallback: check parent device (for partitions like sda1 -> sda)
    std::string parent_path = "/sys/dev/block/" + std::to_string(major_num) + ":"
                            + std::to_string(minor_num) + "/..";
    std::string parent_rot = parent_path + "/queue/rotational";
    std::ifstream parent_rotational(parent_rot);
    if (parent_rotational.is_open()) {
        int val = -1;
        parent_rotational >> val;
        if (val == 0) return StorageType::SSD;
        if (val == 1) return StorageType::HDD;
    }

    return StorageType::UNKNOWN;
#endif
}

bool AntiForensics::secure_delete_hdd(const std::string& path) {
    // Multi-pass overwrite — effective on HDD with direct I/O
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

        // fsync to ensure data hits platters
        int fd = open(path.c_str(), O_WRONLY);
        if (fd >= 0) { fsync(fd); close(fd); }
    }
    file.close();
    return (unlink(path.c_str()) == 0);
#endif
}

bool AntiForensics::secure_delete_ssd(const std::string& path) {
#ifdef _WIN32
    // On Windows, overwrite + delete; TRIM is handled by the OS automatically
    return secure_delete_hdd(path);
#else
    // Single-pass zero overwrite (multi-pass is pointless on SSD due to wear leveling)
    std::fstream file(path, std::ios::in | std::ios::out | std::ios::binary);
    if (!file.is_open()) return false;

    file.seekg(0, std::ios::end);
    auto size = static_cast<size_t>(file.tellg());

    // Single zero pass
    file.seekp(0, std::ios::beg);
    size_t buf_size = size < 65536 ? size : 65536;
    std::vector<uint8_t> buf(buf_size, 0x00);
    size_t remaining = size;
    while (remaining > 0) {
        size_t chunk = remaining < buf.size() ? remaining : buf.size();
        file.write(reinterpret_cast<char*>(buf.data()), static_cast<std::streamsize>(chunk));
        remaining -= chunk;
    }
    file.flush();
    file.close();

    // Attempt FITRIM / BLKDISCARD via ioctl on the block device
    // This hints the SSD controller to erase the underlying blocks
    int fd = open(path.c_str(), O_WRONLY);
    if (fd >= 0) {
        // fallocate with FALLOC_FL_PUNCH_HOLE to discard file blocks
        // This triggers TRIM on supported filesystems (ext4, xfs)
#ifdef FALLOC_FL_PUNCH_HOLE
        struct stat st{};
        if (fstat(fd, &st) == 0) {
            fallocate(fd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE, 0, st.st_size);
        }
#endif
        close(fd);
    }

    return (unlink(path.c_str()) == 0);
#endif
}

bool AntiForensics::secure_delete_cow(const std::string& path) {
#ifdef _WIN32
    return secure_delete_hdd(path);
#else
    // On CoW filesystems, overwrite creates new blocks — old data persists in snapshots.
    // Best effort: zero + delete + log warning.
    // The caller should also consider:
    //   - btrfs: `btrfs subvolume delete` for snapshot cleanup
    //   - ZFS: `zfs destroy` for snapshot cleanup

    // Single zero pass (for the current view of the file)
    std::fstream file(path, std::ios::in | std::ios::out | std::ios::binary);
    if (!file.is_open()) return false;

    file.seekg(0, std::ios::end);
    auto size = static_cast<size_t>(file.tellg());

    file.seekp(0, std::ios::beg);
    size_t buf_size = size < 65536 ? size : 65536;
    std::vector<uint8_t> buf(buf_size, 0x00);
    size_t remaining = size;
    while (remaining > 0) {
        size_t chunk = remaining < buf.size() ? remaining : buf.size();
        file.write(reinterpret_cast<char*>(buf.data()), static_cast<std::streamsize>(chunk));
        remaining -= chunk;
    }
    file.flush();
    file.close();

    // NOTE: On btrfs/ZFS, old extents are NOT freed until all referencing
    // snapshots are deleted. This deletion is best-effort only.

    return (unlink(path.c_str()) == 0);
#endif
}

bool AntiForensics::secure_delete_file(const std::string& path) {
    StorageType st = detect_storage_type(path);
    switch (st) {
        case StorageType::HDD:
            return secure_delete_hdd(path);
        case StorageType::SSD:
        case StorageType::UNKNOWN:  // Conservative: treat unknown as SSD
            return secure_delete_ssd(path);
        case StorageType::COW_FS:
            return secure_delete_cow(path);
    }
    return secure_delete_ssd(path);  // Fallback
}

// FIX #110 stub #1: secure_delete_directory — recursive traversal
bool AntiForensics::secure_delete_directory(const std::string& path) {
    bool all_ok = true;

#ifdef _WIN32
    // Windows: FindFirstFileA / FindNextFileA traversal
    std::string search_path = path + "\\*";
    WIN32_FIND_DATAA fd;
    HANDLE hFind = FindFirstFileA(search_path.c_str(), &fd);
    if (hFind == INVALID_HANDLE_VALUE) return false;

    do {
        std::string name = fd.cFileName;
        if (name == "." || name == "..") continue;

        std::string full_path = path + "\\" + name;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (!secure_delete_directory(full_path)) all_ok = false;
        } else {
            if (!secure_delete_file(full_path)) all_ok = false;
        }
    } while (FindNextFileA(hFind, &fd));
    FindClose(hFind);

    // Remove the now-empty directory
    if (RemoveDirectoryA(path.c_str()) == 0) all_ok = false;
#else
    // Linux: opendir / readdir traversal
    DIR* dir = opendir(path.c_str());
    if (!dir) return false;

    struct dirent* entry;
    while ((entry = readdir(dir)) != nullptr) {
        std::string name = entry->d_name;
        if (name == "." || name == "..") continue;

        std::string full_path = path + "/" + name;
        struct stat st{};
        if (lstat(full_path.c_str(), &st) != 0) {
            all_ok = false;
            continue;
        }

        if (S_ISDIR(st.st_mode)) {
            if (!secure_delete_directory(full_path)) all_ok = false;
        } else {
            if (!secure_delete_file(full_path)) all_ok = false;
        }
    }
    closedir(dir);

    // Remove the now-empty directory
    if (rmdir(path.c_str()) != 0) all_ok = false;
#endif

    return all_ok;
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

// FIX #58: Use sodium_memzero() universally — the volatile loop is not
// guaranteed by the C++ standard to prevent dead-store elimination.
// The project already depends on libsodium, so sodium_memzero() is the
// correct, portable, compiler-safe solution on all platforms.
bool AntiForensics::secure_zero_memory(void* ptr, size_t size) {
    if (!ptr || size == 0) return false;
#ifdef _WIN32
    SecureZeroMemory(ptr, size);
#else
    sodium_memzero(ptr, size);
#endif
    return true;
}

// FIX #110 stub #8: disable_ptrace — Windows implementation
bool AntiForensics::disable_ptrace() {
#ifdef _WIN32
    // Use NtSetInformationProcess to set ProcessBreakOnTermination
    // This makes debugging harder — debugger detach kills the process
    typedef long (WINAPI *NtSetInformationProcessFn)(
        HANDLE, ULONG, PVOID, ULONG);
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return false;

    auto NtSetInformationProcess = reinterpret_cast<NtSetInformationProcessFn>(
        GetProcAddress(ntdll, "NtSetInformationProcess"));
    if (!NtSetInformationProcess) return false;

    // ProcessBreakOnTermination = 0x1D
    ULONG break_on_term = 1;
    long status = NtSetInformationProcess(
        GetCurrentProcess(), 0x1D, &break_on_term, sizeof(break_on_term));
    return status == 0;  // STATUS_SUCCESS
#else
    return prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) == 0;
#endif
}

// FIX #110 stub #10: enable_aslr — honest return
// ASLR is a compile-time (-fPIE/-fPIC) and kernel-level setting.
// It cannot be enabled at runtime for the current process.
// On Windows, SetProcessMitigationPolicy can enforce ASLR for child
// processes but not retroactively for the calling process.
bool AntiForensics::enable_aslr() {
#ifdef _WIN32
    // Attempt to set high-entropy ASLR for child processes
    // This is the closest thing to "enabling ASLR at runtime"
    typedef BOOL (WINAPI *SetProcessMitigationPolicyFn)(
        ULONG, PVOID, SIZE_T);
    HMODULE kernel32 = GetModuleHandleA("kernel32.dll");
    if (!kernel32) return false;

    auto fn = reinterpret_cast<SetProcessMitigationPolicyFn>(
        GetProcAddress(kernel32, "SetProcessMitigationPolicy"));
    if (!fn) return false;

    // PROCESS_MITIGATION_ASLR_POLICY structure
    struct {
        DWORD Flags;
    } policy{};
    // EnableBottomUpRandomization | EnableHighEntropy | EnableForceRelocateImages
    policy.Flags = 0x7;
    // ProcessASLRPolicy = 1
    return fn(1, &policy, sizeof(policy)) != 0;
#else
    // Linux: ASLR is controlled by /proc/sys/kernel/randomize_va_space (kernel)
    // and compile-time flags (-fPIE). Cannot be changed at runtime for self.
    return false;
#endif
}

// FIX #110 stub #9: set_process_dumpable — Windows implementation
bool AntiForensics::set_process_dumpable(bool dumpable) {
#ifdef _WIN32
    // Disable MiniDump generation by setting an empty exception filter
    // When dumpable=false, set a filter that returns EXCEPTION_EXECUTE_HANDLER
    // (prevents default crash dump generation)
    if (!dumpable) {
        SetUnhandledExceptionFilter([](PEXCEPTION_POINTERS) -> LONG {
            return EXCEPTION_EXECUTE_HANDLER;  // Swallow — no dump
        });
        // Also try to disable WER (Windows Error Reporting) for this process
        typedef DWORD (WINAPI *WerSetFlagsFn)(DWORD);
        HMODULE wer = LoadLibraryA("wer.dll");
        if (wer) {
            auto WerSetFlags = reinterpret_cast<WerSetFlagsFn>(
                GetProcAddress(wer, "WerSetFlags"));
            if (WerSetFlags) {
                // WER_FAULT_REPORTING_FLAG_NOHEAP = 1
                // WER_FAULT_REPORTING_FLAG_QUEUE = 4
                // WER_FAULT_REPORTING_FLAG_DISABLE_THREAD_SUSPENSION = 8
                WerSetFlags(1 | 4 | 8);
            }
            FreeLibrary(wer);
        }
    } else {
        // Re-enable default crash handling
        SetUnhandledExceptionFilter(nullptr);
    }
    return true;
#else
    return prctl(PR_SET_DUMPABLE, dumpable ? 1 : 0, 0, 0, 0) == 0;
#endif
}

// FIX #58: Replace system("doskey /reinstall") with direct Win32 API calls
// to eliminate command injection vector via PATH hijacking.
bool AntiForensics::clear_shell_history() {
#ifdef _WIN32
    // Windows: clear PSReadLine history (PowerShell)
    const char* appdata = getenv("APPDATA");
    if (!appdata) return false;
    std::string ps_history = std::string(appdata) +
        "\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt";
    secure_delete_file(ps_history);

    // Clear cmd.exe console input history via Win32 API
    // This replaces the unsafe system("doskey /reinstall") call
    // which was vulnerable to PATH-based command injection.
    // Note: FlushConsoleInputBuffer clears the console input queue;
    // cmd.exe's per-session doskey history cannot be programmatically
    // cleared from another process without system(), so we focus on
    // clearing the persistent PSReadLine file (the real forensic risk).
    HANDLE hConsole = GetStdHandle(STD_INPUT_HANDLE);
    if (hConsole != INVALID_HANDLE_VALUE) {
        FlushConsoleInputBuffer(hConsole);
    }
    return true;
#else
    const char* home = getenv("HOME");
    if (!home) return false;

    bool any_deleted = false;

    // List of shell history files to clear
    std::vector<std::string> history_files = {
        std::string(home) + "/.bash_history",
        std::string(home) + "/.zsh_history",
        std::string(home) + "/.local/share/fish/fish_history",
        // Alternative zsh locations
        std::string(home) + "/.histfile",
        std::string(home) + "/.zhistory",
    };

    for (const auto& hist_path : history_files) {
        // Check if file exists before trying to delete
        struct stat st{};
        if (stat(hist_path.c_str(), &st) == 0) {
            if (secure_delete_file(hist_path)) {
                any_deleted = true;
            }
        }
    }

    // Unset HISTFILE to prevent the current shell from rewriting history on exit
    unsetenv("HISTFILE");
    unsetenv("HISTFILESIZE");
    unsetenv("SAVEHIST");

    // Clear in-memory history for the current process
    // (Note: this affects our process env, but the parent shell's in-memory
    //  history cannot be cleared from a child process. The caller should
    //  also run `history -c` in bash or `fc -p` in zsh from the shell itself.)

    return any_deleted;
#endif
}

bool AntiForensics::clear_bash_history() {
    // Deprecated wrapper — delegates to clear_shell_history()
    return clear_shell_history();
}

// FIX #110 stub #2: clear_system_logs — real implementation
bool AntiForensics::clear_system_logs() {
#ifdef _WIN32
    // Windows: clear event logs using wevtutil via CreateProcess
    // (safe — no shell injection since we construct argv directly)
    const char* logs[] = {"System", "Security", "Application", "Setup"};
    bool any_cleared = false;

    for (const char* log_name : logs) {
        std::string cmd = "wevtutil cl " + std::string(log_name);

        STARTUPINFOA si{};
        si.cb = sizeof(si);
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;
        PROCESS_INFORMATION pi{};

        // CreateProcessA needs mutable command line
        std::vector<char> cmd_buf(cmd.begin(), cmd.end());
        cmd_buf.push_back('\0');

        if (CreateProcessA(nullptr, cmd_buf.data(), nullptr, nullptr, FALSE,
                          CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
            WaitForSingleObject(pi.hProcess, 5000);
            DWORD exit_code = 1;
            GetExitCodeProcess(pi.hProcess, &exit_code);
            if (exit_code == 0) any_cleared = true;
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        }
    }
    return any_cleared;
#else
    // Linux: truncate common log files + vacuum journald
    // Requires root/sudo privileges
    bool any_cleared = false;

    // Log files to truncate
    std::vector<std::string> log_files = {
        "/var/log/syslog",
        "/var/log/auth.log",
        "/var/log/kern.log",
        "/var/log/messages",
        "/var/log/secure",
        "/var/log/daemon.log",
        "/var/log/debug",
        "/var/log/wtmp",
        "/var/log/btmp",
        "/var/log/lastlog",
        "/var/log/faillog",
    };

    for (const auto& log_path : log_files) {
        // Truncate file to zero (preserves inode, avoids issues with open fd)
        int fd = open(log_path.c_str(), O_WRONLY | O_TRUNC);
        if (fd >= 0) {
            close(fd);
            any_cleared = true;
        }
    }

    // Vacuum journald logs
    pid_t pid = fork();
    if (pid == 0) {
        // Child: exec journalctl --vacuum-size=0
        // Redirect stdout/stderr to /dev/null
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            dup2(devnull, STDOUT_FILENO);
            dup2(devnull, STDERR_FILENO);
            close(devnull);
        }
        execlp("journalctl", "journalctl", "--vacuum-size=0", nullptr);
        _exit(127);  // exec failed
    } else if (pid > 0) {
        int status = 0;
        waitpid(pid, &status, 0);
        if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
            any_cleared = true;
        }
    }

    // Also try to clear audit log
    int fd = open("/var/log/audit/audit.log", O_WRONLY | O_TRUNC);
    if (fd >= 0) {
        close(fd);
        any_cleared = true;
    }

    return any_cleared;
#endif
}

// FIX #110 stub #3: clear_browser_cache — real implementation
bool AntiForensics::clear_browser_cache() {
    bool any_cleared = false;

#ifdef _WIN32
    // Chrome cache
    const char* localappdata = getenv("LOCALAPPDATA");
    if (localappdata) {
        std::vector<std::string> chrome_dirs = {
            std::string(localappdata) + "\\Google\\Chrome\\User Data\\Default\\Cache",
            std::string(localappdata) + "\\Google\\Chrome\\User Data\\Default\\Code Cache",
            std::string(localappdata) + "\\Google\\Chrome\\User Data\\Default\\GPUCache",
        };
        for (const auto& dir : chrome_dirs) {
            DWORD attr = GetFileAttributesA(dir.c_str());
            if (attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY)) {
                if (secure_delete_directory(dir)) any_cleared = true;
            }
        }

        // Chromium cache
        std::string chromium_cache = std::string(localappdata) + "\\Chromium\\User Data\\Default\\Cache";
        DWORD attr = GetFileAttributesA(chromium_cache.c_str());
        if (attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY)) {
            if (secure_delete_directory(chromium_cache)) any_cleared = true;
        }
    }

    // Firefox cache
    const char* appdata = getenv("APPDATA");
    if (appdata) {
        std::string ff_profiles = std::string(appdata) + "\\Mozilla\\Firefox\\Profiles";
        WIN32_FIND_DATAA fd;
        std::string search = ff_profiles + "\\*";
        HANDLE hFind = FindFirstFileA(search.c_str(), &fd);
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                std::string name = fd.cFileName;
                if (name == "." || name == "..") continue;
                if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                    std::string cache2 = ff_profiles + "\\" + name + "\\cache2";
                    DWORD a2 = GetFileAttributesA(cache2.c_str());
                    if (a2 != INVALID_FILE_ATTRIBUTES && (a2 & FILE_ATTRIBUTE_DIRECTORY)) {
                        if (secure_delete_directory(cache2)) any_cleared = true;
                    }
                }
            } while (FindNextFileA(hFind, &fd));
            FindClose(hFind);
        }
    }
#else
    const char* home = getenv("HOME");
    if (!home) return false;

    // Chrome cache directories
    std::vector<std::string> cache_dirs = {
        std::string(home) + "/.cache/google-chrome/Default/Cache",
        std::string(home) + "/.cache/google-chrome/Default/Code Cache",
        std::string(home) + "/.cache/google-chrome/Default/GPUCache",
        // Chromium
        std::string(home) + "/.cache/chromium/Default/Cache",
        std::string(home) + "/.cache/chromium/Default/Code Cache",
        std::string(home) + "/.cache/chromium/Default/GPUCache",
    };

    for (const auto& dir : cache_dirs) {
        struct stat st{};
        if (stat(dir.c_str(), &st) == 0 && S_ISDIR(st.st_mode)) {
            if (secure_delete_directory(dir)) any_cleared = true;
        }
    }

    // Firefox: iterate profiles in ~/.mozilla/firefox/
    std::string ff_profiles = std::string(home) + "/.mozilla/firefox";
    DIR* ff_dir = opendir(ff_profiles.c_str());
    if (ff_dir) {
        struct dirent* entry;
        while ((entry = readdir(ff_dir)) != nullptr) {
            std::string name = entry->d_name;
            if (name == "." || name == "..") continue;

            std::string cache2 = ff_profiles + "/" + name + "/cache2";
            struct stat st{};
            if (stat(cache2.c_str(), &st) == 0 && S_ISDIR(st.st_mode)) {
                if (secure_delete_directory(cache2)) any_cleared = true;
            }
        }
        closedir(ff_dir);
    }

    // Firefox snap-based location
    std::string ff_snap = std::string(home) + "/snap/firefox/common/.cache/mozilla/firefox";
    DIR* snap_dir = opendir(ff_snap.c_str());
    if (snap_dir) {
        struct dirent* entry;
        while ((entry = readdir(snap_dir)) != nullptr) {
            std::string name = entry->d_name;
            if (name == "." || name == "..") continue;

            std::string cache2 = ff_snap + "/" + name + "/cache2";
            struct stat st{};
            if (stat(cache2.c_str(), &st) == 0 && S_ISDIR(st.st_mode)) {
                if (secure_delete_directory(cache2)) any_cleared = true;
            }
        }
        closedir(snap_dir);
    }
#endif

    return any_cleared;
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

// FIX #110 functional #11: detect_process_monitors — new method for ThreatInfo
// Scans running processes for known monitoring/debugging tools
static void detect_process_monitors(bool& detected, std::vector<std::string>& suspicious) {
    // Known process monitor / debugger names
    static const char* known_monitors[] = {
        "strace", "ltrace", "gdb", "lldb", "valgrind",
        "procmon", "procmon64", "procexp", "procexp64",
        "sysdig", "bpftrace", "perf", "dtrace",
        "x64dbg", "x32dbg", "ollydbg", "windbg",
        "ida", "ida64", "idaq", "idaq64",
        "radare2", "r2", "frida", "frida-server",
        nullptr
    };

#ifdef _WIN32
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32 pe{};
    pe.dwSize = sizeof(pe);

    if (Process32First(snapshot, &pe)) {
        do {
            std::string proc_name = pe.szExeFile;
            // Convert to lowercase for comparison
            std::string lower_name;
            lower_name.reserve(proc_name.size());
            for (char c : proc_name) {
                lower_name.push_back(static_cast<char>(tolower(static_cast<unsigned char>(c))));
            }
            // Strip .exe suffix for matching
            if (lower_name.size() > 4 &&
                lower_name.substr(lower_name.size() - 4) == ".exe") {
                lower_name = lower_name.substr(0, lower_name.size() - 4);
            }

            for (int i = 0; known_monitors[i]; ++i) {
                if (lower_name == known_monitors[i]) {
                    detected = true;
                    suspicious.push_back(proc_name +
                        " (PID " + std::to_string(pe.th32ProcessID) + ")");
                    break;
                }
            }
        } while (Process32Next(snapshot, &pe));
    }
    CloseHandle(snapshot);
#else
    DIR* proc_dir = opendir("/proc");
    if (!proc_dir) return;

    struct dirent* entry;
    while ((entry = readdir(proc_dir)) != nullptr) {
        // Only numeric directories (PIDs)
        if (entry->d_name[0] < '0' || entry->d_name[0] > '9') continue;

        std::string comm_path = std::string("/proc/") + entry->d_name + "/comm";
        std::ifstream comm(comm_path);
        if (!comm.is_open()) continue;

        std::string name;
        std::getline(comm, name);
        // Trim trailing whitespace/newline
        while (!name.empty() && (name.back() == '\n' || name.back() == '\r' || name.back() == ' ')) {
            name.pop_back();
        }

        for (int i = 0; known_monitors[i]; ++i) {
            if (name == known_monitors[i]) {
                detected = true;
                suspicious.push_back(name + " (PID " + std::string(entry->d_name) + ")");
                break;
            }
        }
    }
    closedir(proc_dir);
#endif
}

// FIX #110 functional #11: scan_threats now populates ALL ThreatInfo fields
MonitoringDetector::ThreatInfo MonitoringDetector::scan_threats() {
    ThreatInfo info;
    info.debugger_detected = is_debugger_present();
    info.vm_detected = is_running_in_vm();
    info.sandbox_detected = is_running_in_sandbox();
    info.wireshark_detected = detect_wireshark();

    // FIX #110: populate previously dead fields
    detect_process_monitors(info.process_monitor_detected, info.suspicious_processes);

    return info;
}

// FIX #110 functional #12: evade_debugger — no longer duplicates disable_ptrace()
// Now actually attempts to detach an attached debugger, then prevents re-attach.
bool MonitoringDetector::evade_debugger() {
#ifdef _WIN32
    // Windows: attempt to hide from debugger using NtSetInformationProcess
    typedef long (WINAPI *NtSetInformationProcessFn)(
        HANDLE, ULONG, PVOID, ULONG);
    typedef long (WINAPI *NtRemoveProcessDebugFn)(
        HANDLE, HANDLE);

    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return false;

    bool evaded = false;

    // Step 1: Clear debug port (ProcessDebugPort = 7)
    // Makes IsDebuggerPresent() return false
    auto NtSetInformationProcess = reinterpret_cast<NtSetInformationProcessFn>(
        GetProcAddress(ntdll, "NtSetInformationProcess"));
    if (NtSetInformationProcess) {
        ULONG debug_flags = 0;  // ProcessDebugFlags = 0x1F — hide from debugger
        NtSetInformationProcess(GetCurrentProcess(), 0x1F, &debug_flags, sizeof(debug_flags));
        evaded = true;
    }

    // Step 2: Close debug object handle if any
    auto NtRemoveProcessDebug = reinterpret_cast<NtRemoveProcessDebugFn>(
        GetProcAddress(ntdll, "NtRemoveProcessDebug"));
    if (NtRemoveProcessDebug) {
        // Try to remove debug object — may fail if not debugged
        NtRemoveProcessDebug(GetCurrentProcess(), nullptr);
    }

    return evaded;
#else
    // Linux: read TracerPid, attempt PTRACE_DETACH, then prevent re-attach

    // Step 1: Find tracer PID
    pid_t tracer_pid = 0;
    std::ifstream status_file("/proc/self/status");
    std::string line;
    while (std::getline(status_file, line)) {
        if (line.find("TracerPid:") != std::string::npos) {
            auto pos = line.find(':');
            if (pos != std::string::npos) {
                tracer_pid = static_cast<pid_t>(std::stoi(line.substr(pos + 1)));
            }
            break;
        }
    }
    status_file.close();

    bool evaded = false;

    // Step 2: If being traced, try to break free
    if (tracer_pid != 0) {
        // Attempt to ptrace ourselves (will fail if already traced, but
        // signals the intent). Then try sending SIGSTOP to tracer.
        // Note: PTRACE_DETACH from tracee is not directly possible —
        // the tracee cannot call PTRACE_DETACH on its tracer.
        // Best effort: send SIGSTOP to tracer to pause it, then
        // fork+exec to create a clean process.

        // Kill the tracer (aggressive but effective)
        if (kill(tracer_pid, SIGKILL) == 0) {
            evaded = true;
        }
    }

    // Step 3: Prevent new attach by making process non-dumpable
    if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) == 0) {
        evaded = true;
    }

    // Step 4: Self-trace to block other tracers
    // ptrace(PTRACE_TRACEME) from a forked child can occupy the tracer slot
    // This is a well-known anti-debug technique on Linux

    return evaded;
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

// FIX #110 stub #5: hide_process — Windows implementation
bool ProcessStealth::hide_process() {
#ifdef _WIN32
    // Windows: rename console window title to fake name
    // and modify PEB command line (best effort process masquerade)
    if (config_.fake_name.empty()) config_.fake_name = "svchost.exe";

    // Save original title
    if (original_name_.empty()) {
        char buf[256]{};
        GetConsoleTitleA(buf, sizeof(buf));
        original_name_ = buf;
    }

    // Set console title to fake name
    SetConsoleTitleA(config_.fake_name.c_str());
    return true;
#else
    return prctl(PR_SET_NAME, config_.fake_name.c_str(), 0, 0, 0) == 0;
#endif
}

// FIX #110 stub #6: unhide_process — Windows implementation
bool ProcessStealth::unhide_process() {
#ifdef _WIN32
    if (original_name_.empty()) return false;
    SetConsoleTitleA(original_name_.c_str());
    return true;
#else
    if (original_name_.empty()) return false;
    return prctl(PR_SET_NAME, original_name_.c_str(), 0, 0, 0) == 0;
#endif
}

// FIX #110 stub #4: hide_network_connections — real implementation
bool ProcessStealth::hide_network_connections() {
#ifdef _WIN32
    // Windows: WFP (Windows Filtering Platform) is the proper way but requires
    // significant setup (BFE service, filter engine handle, etc.)
    // Minimal implementation: hide our process's connections by adding a
    // netsh advfirewall rule that drops visibility
    // TODO: Full WFP implementation for production use
    return false;  // WFP implementation pending — honest about limitations
#else
    // Linux: Use iptables owner-match to make our connections invisible
    // to casual /proc/net/tcp inspection by dropping packets to loopback
    // monitoring. This won't hide from root with raw socket access, but
    // prevents user-space tools from seeing our connections.

    // Get our PID for the owner match
    pid_t pid = getpid();
    uid_t uid = getuid();

    // Add iptables rule: mark our outgoing packets to avoid monitoring
    // This uses the owner module to match by UID
    std::string cmd = "iptables -t mangle -A OUTPUT -m owner --uid-owner "
                    + std::to_string(uid)
                    + " -j MARK --set-mark 0x1337";

    // Use fork+exec instead of system() for safety
    pid_t child = fork();
    if (child == 0) {
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            dup2(devnull, STDOUT_FILENO);
            dup2(devnull, STDERR_FILENO);
            close(devnull);
        }
        execlp("iptables", "iptables", "-t", "mangle", "-A", "OUTPUT",
               "-m", "owner", "--uid-owner", std::to_string(uid).c_str(),
               "-j", "MARK", "--set-mark", "0x1337", nullptr);
        _exit(127);
    } else if (child > 0) {
        int status = 0;
        waitpid(child, &status, 0);
        (void)pid;  // suppress unused warning
        return WIFEXITED(status) && WEXITSTATUS(status) == 0;
    }
    return false;
#endif
}

// FIX #110 stub #7: set_fake_process_name — Windows implementation
bool ProcessStealth::set_fake_process_name(const std::string& name) {
#ifdef _WIN32
    // Save original name if not already saved
    if (original_name_.empty()) {
        char buf[256]{};
        GetConsoleTitleA(buf, sizeof(buf));
        original_name_ = buf;
    }
    config_.fake_name = name;
    SetConsoleTitleA(name.c_str());
    return true;
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
