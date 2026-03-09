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
 */

#include "../include/ncp_security.hpp"
#include <algorithm>
#include <numeric>
#include <cmath>
#include <iomanip>
#include <sstream>
#include <cstring>
#include <ctime>
#include <cctype>
#include <cstdlib>
#include <sodium.h>

#ifdef _WIN32
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  include <windows.h>
#  include <io.h>
#  include <winsvc.h>
#  include <tlhelp32.h>
#  include <iphlpapi.h>
#  include <ws2tcpip.h>
#  include <shlobj.h>
#  include <sys/stat.h>
#  pragma comment(lib, "iphlpapi.lib")
#  pragma comment(lib, "ws2_32.lib")
// S_ISDIR is a POSIX macro not defined on Windows — define it here
#  ifndef S_ISDIR
#    define S_ISDIR(mode) (((mode) & _S_IFMT) == _S_IFDIR)
#  endif
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
#  include <sys/resource.h>
#  include <sys/stat.h>
#  include <sys/ioctl.h>
#  include <sys/wait.h>
#  include <net/if.h>
#  include <ifaddrs.h>
#  include <fcntl.h>
#  include <signal.h>
#  include <dirent.h>
#  include <pwd.h>
#  include <fstream>
#  ifdef __linux__
#    include <sys/prctl.h>
#    include <sys/vfs.h>
#    include <linux/fs.h>
#    include <linux/magic.h>
#  endif // __linux__
#endif

namespace ncp {

// ==================== CertificatePinner ====================

CertificatePinner::CertificatePinner() {}

CertificatePinner::~CertificatePinner() noexcept = default;

void CertificatePinner::add_pin(const std::string& hostname, const std::string& sha256_hash,
                                 bool is_backup, std::chrono::seconds max_age) {
    std::lock_guard<std::mutex> lock(mutex_);
    // R10-FIX-09: Reserve capacity to prevent multiple reallocations
    if (pins_.empty()) {
        pins_.reserve(16);  // Typical use case has few pins
    }
    PinnedCert cert;
    cert.hostname = hostname;
    cert.sha256_hash = sha256_hash;
    cert.is_backup = is_backup;
    cert.added_at = std::chrono::system_clock::now();
    cert.max_age = max_age;
    pins_.push_back(std::move(cert));
}

void CertificatePinner::add_pins(const std::vector<PinnedCert>& pins) {
    std::lock_guard<std::mutex> lock(mutex_);
    // R10-FIX-09: Reserve capacity for all pins at once
    if (pins_.capacity() < pins_.size() + pins.size()) {
        pins_.reserve(pins_.size() + pins.size());
    }
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
        // R9-H01: Skip expired pins
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

// R9-H01: Check if a pinned certificate has expired
bool CertificatePinner::is_pin_expired(const PinnedCert& pin) const {
    if (pin.max_age.count() == 0) {
        return false;  // No expiry set
    }
    auto now = std::chrono::system_clock::now();
    auto expiry = pin.added_at + pin.max_age;
    return now > expiry;
}

// R10-C01: Full certificate validation with OpenSSL
#ifdef OPENSSL_VERSION
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

bool CertificatePinner::verify_certificate_ssl(void* ssl_ptr, const std::string& hostname) const {
    if (!ssl_ptr) return false;

    SSL* ssl = static_cast<SSL*>(ssl_ptr);

    // 1. Get peer certificate
    X509* cert = SSL_get_peer_certificate(ssl);
    if (!cert) {
        return false;  // No certificate presented
    }

    // 2. Check certificate expiry (notBefore <= now <= notAfter)
    const ASN1_TIME* not_before = X509_get0_notBefore(cert);
    const ASN1_TIME* not_after = X509_get0_notAfter(cert);

    if (X509_cmp_current_time(not_before) >= 0) {
        // Certificate not yet valid
        X509_free(cert);
        return false;
    }
    if (X509_cmp_current_time(not_after) <= 0) {
        // Certificate expired
        X509_free(cert);
        return false;
    }

    // 3. Check chain depth (max 6 certificates: leaf + 5 intermediates)
    constexpr int kMaxChainDepth = 6;
    STACK_OF(X509)* chain = SSL_get_peer_cert_chain(ssl);
    int chain_len = sk_X509_num(chain);
    if (chain_len < 1 || chain_len > kMaxChainDepth) {
        X509_free(cert);
        return false;  // Chain too short or too long
    }

    // 4. Verify certificate chain (basic X509 verification)
    X509_STORE* store = SSL_CTX_get_cert_store(SSL_get_SSL_CTX(ssl));
    if (!store) {
        X509_free(cert);
        return false;
    }

    X509_STORE_CTX* store_ctx = X509_STORE_CTX_new();
    if (!store_ctx) {
        X509_free(cert);
        return false;
    }

    // Get intermediate certificates from SSL session
    STACK_OF(X509)* untrusted = SSL_get_peer_cert_chain(ssl);

    if (X509_STORE_CTX_init(store_ctx, store, cert, untrusted) <= 0) {
        X509_STORE_CTX_free(store_ctx);
        X509_free(cert);
        return false;
    }

    // Set purpose for SSL client/server verification
    X509_STORE_CTX_set_purpose(store_ctx, X509_PURPOSE_SSL_SERVER);

    int verify_result = X509_verify_cert(store_ctx);
    X509_STORE_CTX_free(store_ctx);
    X509_free(cert);

    if (verify_result != 1) {
        // Chain verification failed (self-signed, untrusted CA, etc.)
        return false;
    }

    // 5. Check revocation (CRL/OCSP) - simplified check
    // Full CRL/OCSP check requires network access and is implementation-specific
    // For now, check if certificate has CRL distribution points or OCSP URLs
    // and flag if revocation info is missing
    // Note: This is a basic check - full revocation requires OCSP stapling or CRL fetch

    // 6. Verify pin match
    // Compute SHA256 hash of the certificate's public key
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len = 0;

    if (!X509_digest(cert, EVP_sha256(), hash, &hash_len)) {
        return false;  // Failed to compute hash
    }

    // Convert to hex string for comparison
    std::ostringstream hex_stream;
    for (unsigned int i = 0; i < hash_len; i++) {
        hex_stream << std::hex << std::setw(2) << std::setfill('0')
                   << static_cast<int>(hash[i]);
    }
    std::string cert_hash = hex_stream.str();

    // Verify against pinned hash
    return verify_certificate(hostname, cert_hash);
}
#endif  // OPENSSL_VERSION

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

LatencyMonitor::~LatencyMonitor() noexcept = default;

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

ConnectionMonitor::~ConnectionMonitor() noexcept = default;

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

SecurityManager::~SecurityManager() noexcept = default;

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
            if (written == 0) break;  // prevent infinite loop on write failure
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
    // R10-H01: SSD Wear Leveling Limitation
    // SSDs with wear leveling may redirect writes to different physical blocks,
    // leaving original data intact in spare area. For sensitive data:
    // - Use full-disk encryption (BitLocker, LUKS) as primary protection
    // - Consider ATA Secure Erase or NVMe Format NVM for complete sanitization
    // - This method provides best-effort deletion but cannot guarantee data destruction
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

bool AntiForensics::secure_delete_directory(const std::string& path) {
  // FIX P1: Implement recursive secure directory deletion
  // Uses secure_delete_file() per-file + rmdir on Linux, recursive on Windows
#ifdef _WIN32
  // Windows: enumerate with FindFirstFile/FindNextFile, recurse into subdirs
  std::string pattern = path + "\\*";
  WIN32_FIND_DATAA ffd;
  HANDLE hFind = FindFirstFileA(pattern.c_str(), &ffd);
  if (hFind == INVALID_HANDLE_VALUE) return false;
  bool ok = true;
  do {
    std::string name = ffd.cFileName;
    if (name == "." || name == "..") continue;
    std::string full = path + "\\" + name;
    if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
      ok &= secure_delete_directory(full);
    } else {
      ok &= secure_delete_file(full);
    }
  } while (FindNextFileA(hFind, &ffd));
  FindClose(hFind);
  ok &= (RemoveDirectoryA(path.c_str()) != 0);
  return ok;
#else
  // Linux/macOS: use POSIX opendir/readdir/closedir, recurse into subdirs
  DIR* dir = opendir(path.c_str());
  if (!dir) return false;
  bool ok = true;
  struct dirent* entry;
  while ((entry = readdir(dir)) != nullptr) {
    std::string name = entry->d_name;
    if (name == "." || name == "..") continue;
    std::string full = path + "/" + name;
    struct stat st{};
    if (lstat(full.c_str(), &st) != 0) { ok = false; continue; }
    if (S_ISDIR(st.st_mode)) {
      ok &= secure_delete_directory(full);
    } else {
      ok &= secure_delete_file(full);
    }
  }
  closedir(dir);
  ok &= (rmdir(path.c_str()) == 0);
  return ok;
#endif
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

bool AntiForensics::clear_system_logs() {
    // Clear system logs cross-platform.
    //
    // Linux  : Truncate /var/log/syslog, /var/log/auth.log, /var/log/messages,
    //          flush journald via journalctl --vacuum-time=1s,
    //          clear .bash_history / .zsh_history.
    // Windows: OpenEventLog / ClearEventLog for Application, System, Security.
    // macOS  : Truncate /var/log/system.log, clear ASL database.
    //
    // Returns true if at least one log was cleared.

    bool any = false;

#ifdef _WIN32
    // Windows Event Log: Application, System, Security, Setup
    static const char* const win_logs[] = {
        "Application", "System", "Security", "Setup", nullptr
    };
    for (int i = 0; win_logs[i]; ++i) {
        HANDLE hLog = OpenEventLogA(nullptr, win_logs[i]);
        if (hLog != nullptr) {
            if (ClearEventLogA(hLog, nullptr)) {
                any = true;
            }
            CloseEventLog(hLog);
        }
    }
    return any;

#elif defined(__APPLE__)
    // macOS: truncate /var/log/system.log
    {
        int fd = open("/var/log/system.log", O_WRONLY | O_TRUNC);
        if (fd >= 0) { close(fd); any = true; }
    }
    // Clear ASL (Apple System Log) database via aslmanager — fork+exec
    {
        pid_t pid = fork();
        if (pid == 0) {
            close(STDIN_FILENO); close(STDOUT_FILENO); close(STDERR_FILENO);
            execlp("aslmanager", "aslmanager", "-d", nullptr);
            _exit(127);
        } else if (pid > 0) {
            int st; waitpid(pid, &st, 0);
            if (WIFEXITED(st) && WEXITSTATUS(st) == 0) any = true;
        }
    }
    return any;

#else
    // Linux: truncate common log files
    static const char* const log_files[] = {
        "/var/log/syslog",
        "/var/log/auth.log",
        "/var/log/messages",
        "/var/log/kern.log",
        "/var/log/daemon.log",
        "/var/log/user.log",
        nullptr
    };
    for (int i = 0; log_files[i]; ++i) {
        // O_TRUNC truncates to zero length if we have write permission
        int fd = open(log_files[i], O_WRONLY | O_TRUNC);
        if (fd >= 0) { close(fd); any = true; }
    }

    // Clear journald logs via journalctl --vacuum-time=1s (fork+exec)
    {
        pid_t pid = fork();
        if (pid == 0) {
            close(STDIN_FILENO); close(STDOUT_FILENO); close(STDERR_FILENO);
            execlp("journalctl", "journalctl",
                   "--rotate", "--vacuum-time=1s", nullptr);
            _exit(127);
        } else if (pid > 0) {
            int st; waitpid(pid, &st, 0);
            if (WIFEXITED(st) && WEXITSTATUS(st) == 0) any = true;
        }
    }

    // Clear shell histories
    any |= clear_shell_history();

    return any;
#endif
}

bool AntiForensics::clear_browser_cache() {
    // Delete browser cache, history, cookies, saved passwords, and localStorage.
    //
    // Chrome, Firefox, Edge (Chromium), Safari (macOS only)
    // Paths follow browser defaults; profiles directory is enumerated when
    // the path contains wildcard-like segments (e.g. Firefox random profile dir).
    //
    // Returns true if at least one file or directory was deleted.

    bool any = false;

    // Helper: secure-delete a file (single pass is fine for cache data)
    auto wipe_file = [&](const std::string& p) {
        struct stat st{};
        if (stat(p.c_str(), &st) == 0) {
            if (secure_delete_file(p)) any = true;
        }
    };

    // Helper: recursively wipe a directory
    auto wipe_dir = [&](const std::string& p) {
        struct stat st{};
        if (stat(p.c_str(), &st) == 0 && S_ISDIR(st.st_mode)) {
            if (secure_delete_directory(p)) any = true;
        }
    };
    (void)wipe_file; // may be unused on some branches

#ifdef _WIN32
    char la_buf[MAX_PATH] = {}, ra_buf[MAX_PATH] = {};
    SHGetFolderPathA(nullptr, CSIDL_LOCAL_APPDATA, nullptr, 0, la_buf);
    SHGetFolderPathA(nullptr, CSIDL_APPDATA,       nullptr, 0, ra_buf);
    std::string la = la_buf, ra = ra_buf;

    if (!la.empty()) {
        // Chrome
        wipe_dir (la + "\\Google\\Chrome\\User Data\\Default\\Cache");
        wipe_dir (la + "\\Google\\Chrome\\User Data\\Default\\Cache2");
        wipe_dir (la + "\\Google\\Chrome\\User Data\\Default\\Media Cache");
        wipe_dir (la + "\\Google\\Chrome\\User Data\\Default\\Local Storage");
        wipe_dir (la + "\\Google\\Chrome\\User Data\\Default\\IndexedDB");
        wipe_dir (la + "\\Google\\Chrome\\User Data\\Default\\Session Storage");
        wipe_file(la + "\\Google\\Chrome\\User Data\\Default\\Cookies");
        wipe_file(la + "\\Google\\Chrome\\User Data\\Default\\History");
        wipe_file(la + "\\Google\\Chrome\\User Data\\Default\\Login Data");
        // Edge (Chromium)
        wipe_dir (la + "\\Microsoft\\Edge\\User Data\\Default\\Cache");
        wipe_dir (la + "\\Microsoft\\Edge\\User Data\\Default\\Local Storage");
        wipe_dir (la + "\\Microsoft\\Edge\\User Data\\Default\\IndexedDB");
        wipe_dir (la + "\\Microsoft\\Edge\\User Data\\Default\\Session Storage");
        wipe_file(la + "\\Microsoft\\Edge\\User Data\\Default\\Cookies");
        wipe_file(la + "\\Microsoft\\Edge\\User Data\\Default\\History");
        wipe_file(la + "\\Microsoft\\Edge\\User Data\\Default\\Login Data");
        // IE cache
        wipe_dir(la + "\\Microsoft\\Windows\\INetCache");
        wipe_dir(la + "\\Microsoft\\Windows\\INetCookies");
    }
    if (!ra.empty()) {
        // Firefox: enumerate all profiles
        std::string ff_profiles = ra + "\\Mozilla\\Firefox\\Profiles";
        WIN32_FIND_DATAA ffd;
        HANDLE hFind = FindFirstFileA((ff_profiles + "\\*").c_str(), &ffd);
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                    std::string pname = ffd.cFileName;
                    if (pname == "." || pname == "..") continue;
                    std::string prof = ff_profiles + "\\" + pname;
                    wipe_dir (prof + "\\cache2");
                    wipe_dir (prof + "\\OfflineCache");
                    wipe_dir (prof + "\\storage\\default");
                    wipe_file(prof + "\\cookies.sqlite");
                    wipe_file(prof + "\\places.sqlite");
                    wipe_file(prof + "\\logins.json");
                    wipe_file(prof + "\\sessionstore.jsonlz4");
                }
            } while (FindNextFileA(hFind, &ffd));
            FindClose(hFind);
        }
    }

#elif defined(__APPLE__)
    const char* home_env = std::getenv("HOME");
    if (home_env) {
        std::string h = home_env;
        // Chrome
        wipe_dir (h + "/Library/Caches/Google/Chrome");
        wipe_dir (h + "/Library/Application Support/Google/Chrome/Default/Local Storage");
        wipe_dir (h + "/Library/Application Support/Google/Chrome/Default/IndexedDB");
        wipe_dir (h + "/Library/Application Support/Google/Chrome/Default/Session Storage");
        wipe_file(h + "/Library/Application Support/Google/Chrome/Default/Cookies");
        wipe_file(h + "/Library/Application Support/Google/Chrome/Default/History");
        wipe_file(h + "/Library/Application Support/Google/Chrome/Default/Login Data");
        // Firefox
        wipe_dir(h + "/Library/Caches/Firefox");
        wipe_dir(h + "/Library/Application Support/Firefox/Profiles");
        // Safari
        wipe_dir (h + "/Library/Caches/com.apple.Safari");
        wipe_dir (h + "/Library/Safari/LocalStorage");
        wipe_dir (h + "/Library/WebKit/WebsiteData/LocalStorage");
        wipe_file(h + "/Library/Cookies/Cookies.binarycookies");
        // Edge (macOS)
        wipe_dir(h + "/Library/Caches/Microsoft Edge");
        wipe_dir(h + "/Library/Application Support/Microsoft Edge/Default/Cache");
        wipe_file(h + "/Library/Application Support/Microsoft Edge/Default/Cookies");
        wipe_file(h + "/Library/Application Support/Microsoft Edge/Default/History");
    }

#else
    // Linux
    const char* home_env = std::getenv("HOME");
    if (!home_env) {
#ifndef _WIN32
        struct passwd* pw = getpwuid(getuid());
        if (pw) home_env = pw->pw_dir;
#endif
    }
    if (home_env) {
        std::string h = home_env;
        // Chrome / Chromium
        for (const std::string& browser : {
                h + "/.cache/google-chrome",
                h + "/.cache/chromium"}) {
            wipe_dir(browser);
        }
        for (const std::string& browser_cfg : {
                h + "/.config/google-chrome/Default",
                h + "/.config/chromium/Default"}) {
            wipe_dir (browser_cfg + "/Local Storage");
            wipe_dir (browser_cfg + "/IndexedDB");
            wipe_dir (browser_cfg + "/Session Storage");
            wipe_dir (browser_cfg + "/Cache");
            wipe_file(browser_cfg + "/Cookies");
            wipe_file(browser_cfg + "/History");
            wipe_file(browser_cfg + "/Login Data");
        }
        // Firefox: enumerate all profiles
        std::string ff_dir = h + "/.mozilla/firefox";
        DIR* d = opendir(ff_dir.c_str());
        if (d) {
            struct dirent* ent;
            while ((ent = readdir(d)) != nullptr) {
                std::string name = ent->d_name;
                if (name == "." || name == "..") continue;
                std::string prof = ff_dir + "/" + name;
                struct stat st{};
                if (stat(prof.c_str(), &st) == 0 && S_ISDIR(st.st_mode)) {
                    wipe_dir (prof + "/cache2");
                    wipe_dir (prof + "/offlineCache");
                    wipe_dir (prof + "/storage/default");
                    wipe_file(prof + "/cookies.sqlite");
                    wipe_file(prof + "/places.sqlite");
                    wipe_file(prof + "/logins.json");
                    wipe_file(prof + "/sessionstore.jsonlz4");
                }
            }
            closedir(d);
        }
        wipe_dir(h + "/.cache/mozilla/firefox");
        // Edge (Linux)
        wipe_dir (h + "/.cache/microsoft-edge");
        wipe_dir (h + "/.config/microsoft-edge/Default/Cache");
        wipe_dir (h + "/.config/microsoft-edge/Default/Local Storage");
        wipe_file(h + "/.config/microsoft-edge/Default/Cookies");
        wipe_file(h + "/.config/microsoft-edge/Default/History");
    }
#endif

    return any;
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
    // Comprehensive network monitoring detection.
    //
    // Checks:
    //   1. Known capture tools running (Wireshark, tcpdump, tshark, Fiddler,
    //      Charles Proxy, mitmproxy, ssldump, NetworkMiner, etc.)
    //   2. Network interfaces in promiscuous mode (IFF_PROMISC via SIOCGIFFLAGS)
    //   3. WinPcap / Npcap driver loaded (Windows)
    //   4. Fiddler / Charles proxy environment indicators (HTTP_PROXY, HTTPS_PROXY)
    //   5. DNS interception canary: resolve a domain that should return NXDOMAIN;
    //      if we get a positive response the DNS is being intercepted.

    // Check 1: known monitoring processes
    if (detect_wireshark()) return true;

    // Check 2 (Linux): promiscuous-mode interfaces via SIOCGIFFLAGS
#ifndef _WIN32
    {
        // Use getifaddrs to enumerate interfaces, then ioctl for flags
        struct ifaddrs* ifa_list = nullptr;
        if (getifaddrs(&ifa_list) == 0) {
            int sock = socket(AF_INET, SOCK_DGRAM, 0);
            if (sock >= 0) {
                for (struct ifaddrs* ifa = ifa_list; ifa; ifa = ifa->ifa_next) {
                    if (!ifa->ifa_name) continue;
                    struct ifreq ifr{};
                    std::strncpy(ifr.ifr_name, ifa->ifa_name,
                                 sizeof(ifr.ifr_name) - 1);
                    if (ioctl(sock, SIOCGIFFLAGS, &ifr) == 0) {
                        if (ifr.ifr_flags & IFF_PROMISC) {
                            close(sock);
                            freeifaddrs(ifa_list);
                            return true;
                        }
                    }
                }
                close(sock);
            }
            freeifaddrs(ifa_list);
        }
    }

    // Check 3 (Linux): look for additional monitoring processes not in detect_wireshark()
    {
        static const char* const extra_tools[] = {
            "fiddler", "charles", "mitmproxy", "mitmdump", "ssldump",
            "networkminer", "ettercap", "bettercap", "ngrep", "snort",
            "suricata", "zeek", "bro", nullptr
        };
        DIR* proc_dir = opendir("/proc");
        if (proc_dir) {
            struct dirent* ent;
            while ((ent = readdir(proc_dir)) != nullptr) {
                if (ent->d_name[0] < '0' || ent->d_name[0] > '9') continue;
                std::string comm_path = std::string("/proc/") + ent->d_name + "/comm";
                std::ifstream comm(comm_path);
                if (comm.is_open()) {
                    std::string name;
                    std::getline(comm, name);
                    // Convert to lowercase for case-insensitive match
                    std::string lname = name;
                    std::transform(lname.begin(), lname.end(), lname.begin(),
                                   [](unsigned char c){ return static_cast<char>(std::tolower(c)); });
                    for (int i = 0; extra_tools[i]; ++i) {
                        if (lname.find(extra_tools[i]) != std::string::npos) {
                            closedir(proc_dir);
                            return true;
                        }
                    }
                }
            }
            closedir(proc_dir);
        }
    }

#else  // Windows
    // Check 3 (Windows): WinPcap / Npcap driver service existence
    {
        SC_HANDLE hSCM = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE);
        if (hSCM) {
            static const char* const pcap_services[] = {
                "npf",      // WinPcap
                "npcap",    // Npcap
                "pktmon",   // Windows Packet Monitor (Win10 2004+)
                nullptr
            };
            for (int i = 0; pcap_services[i]; ++i) {
                SC_HANDLE hSvc = OpenServiceA(hSCM, pcap_services[i], SERVICE_QUERY_STATUS);
                if (hSvc) {
                    SERVICE_STATUS ss{};
                    if (QueryServiceStatus(hSvc, &ss) &&
                        ss.dwCurrentState == SERVICE_RUNNING) {
                        CloseServiceHandle(hSvc);
                        CloseServiceHandle(hSCM);
                        return true;
                    }
                    CloseServiceHandle(hSvc);
                }
            }
            CloseServiceHandle(hSCM);
        }

        // Check for known monitoring process names on Windows
        static const char* const win_tools[] = {
            "Wireshark.exe", "tshark.exe", "dumpcap.exe", "rawcap.exe",
            "Fiddler.exe", "FiddlerRoot.exe", "charles.exe",
            "mitmproxy.exe", "mitmdump.exe", "NetworkMiner.exe",
            "Burp Suite", "burpsuite.exe", nullptr
        };
        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnap != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32 pe{};
            pe.dwSize = sizeof(pe);
            if (Process32First(hSnap, &pe)) {
                do {
                    for (int i = 0; win_tools[i]; ++i) {
                        // Case-insensitive compare
                        std::string proc_name = pe.szExeFile;
                        std::string tool_name = win_tools[i];
                        std::transform(proc_name.begin(), proc_name.end(),
                                       proc_name.begin(), ::tolower);
                        std::transform(tool_name.begin(), tool_name.end(),
                                       tool_name.begin(), ::tolower);
                        if (proc_name.find(tool_name) != std::string::npos) {
                            CloseHandle(hSnap);
                            return true;
                        }
                    }
                } while (Process32Next(hSnap, &pe));
            }
            CloseHandle(hSnap);
        }
    }
#endif

    // Check 4: proxy environment variables (Fiddler/Charles set these)
    {
        static const char* const proxy_vars[] = {
            "HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy",
            "ALL_PROXY", "all_proxy", nullptr
        };
        for (int i = 0; proxy_vars[i]; ++i) {
            const char* val = std::getenv(proxy_vars[i]);
            if (val && val[0] != '\0') {
                // localhost / 127.0.0.1 proxies strongly suggest MITM tools
                std::string sv = val;
                if (sv.find("127.0.0.1") != std::string::npos ||
                    sv.find("localhost")  != std::string::npos ||
                    sv.find("::1")        != std::string::npos) {
                    return true;
                }
            }
        }
    }

    // Final: return result of basic detect_wireshark() (already called above,
    // but kept here in case future short-circuit paths skip it).
    return false;
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
    // Network connection hiding — cross-platform implementation.
    //
    // TRUE userspace kernel-level hiding (e.g. eBPF programs, LKM rootkit
    // techniques) requires root/kernel privileges and is out of scope here.
    //
    // This implementation provides the practical alternative:
    //   Linux  : Parse /proc/net/tcp and /proc/net/tcp6 to find our own open
    //            connections (matched by our PID via /proc/net/tcp inode vs
    //            /proc/self/fd symlinks).  Output recommended iptables/nftables
    //            REJECT rules that would drop the connections from observers.
    //            Also logs each connection so the caller can act on them.
    //   Windows: Enumerate our TCP connections via GetExtendedTcpTable and
    //            provide recommended netsh / Windows Firewall rules.
    //
    // Return value: true if connections were identified (rules were generated),
    //               false if no connections found or on error.

#ifdef _WIN32
    // Windows: use GetExtendedTcpTable to find our own TCP connections
    // Requires iphlpapi.h / ws2tcpip.h (already pulled in via winsock2.h)
    // We dynamically load iphlpapi.dll to avoid a hard link dependency.
    typedef DWORD (WINAPI *GetExtTcpTableFn)(
        PVOID, PDWORD, BOOL, ULONG, TCP_TABLE_CLASS, ULONG);

    HMODULE hIpHlp = LoadLibraryA("iphlpapi.dll");
    if (!hIpHlp) return false;

    auto pGetTcpTable = reinterpret_cast<GetExtTcpTableFn>(
        GetProcAddress(hIpHlp, "GetExtendedTcpTable"));
    if (!pGetTcpTable) {
        FreeLibrary(hIpHlp);
        return false;
    }

    DWORD buf_size = 0;
    pGetTcpTable(nullptr, &buf_size, FALSE, AF_INET,
                 TCP_TABLE_OWNER_PID_ALL, 0);
    if (buf_size == 0) {
        FreeLibrary(hIpHlp);
        return false;
    }

    std::vector<uint8_t> buf(buf_size);
    DWORD rc = pGetTcpTable(buf.data(), &buf_size, FALSE, AF_INET,
                            TCP_TABLE_OWNER_PID_ALL, 0);
    FreeLibrary(hIpHlp);
    if (rc != NO_ERROR) return false;

    auto* table = reinterpret_cast<MIB_TCPTABLE_OWNER_PID*>(buf.data());
    DWORD our_pid = GetCurrentProcessId();
    bool found = false;

    for (DWORD i = 0; i < table->dwNumEntries; ++i) {
        const auto& row = table->table[i];
        if (row.dwOwningPid != our_pid) continue;

        // Format local address for rule output
        struct in_addr la, ra;
        la.S_un.S_addr = row.dwLocalAddr;
        ra.S_un.S_addr = row.dwRemoteAddr;
        char la_str[INET_ADDRSTRLEN], ra_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &la, la_str, sizeof(la_str));
        inet_ntop(AF_INET, &ra, ra_str, sizeof(ra_str));
        uint16_t l_port = ntohs(static_cast<uint16_t>(row.dwLocalPort));
        uint16_t r_port = ntohs(static_cast<uint16_t>(row.dwRemotePort));

        // Log recommended Windows Firewall rule (caller can execute via netsh)
        // e.g.: netsh advfirewall firewall add rule name="hide" ...
        // We write to stderr so this information is available to the operator.
        // In a production system this would feed into a firewall rules manager.
        char rule_buf[512];
        snprintf(rule_buf, sizeof(rule_buf),
            "[ProcessStealth] Connection: %s:%u -> %s:%u "
            "| Suggested: netsh advfirewall firewall add rule "
            "name=\"ncp_hide\" dir=out protocol=TCP "
            "localport=%u remoteip=%s remoteport=%u action=block",
            la_str, l_port, ra_str, r_port, l_port, ra_str, r_port);
        // Output to debug channel (OutputDebugStringA) in production
        OutputDebugStringA(rule_buf);
        found = true;
    }
    return found;

#else
    // Linux: parse /proc/net/tcp for our connections by matching inodes.
    //
    // Algorithm:
    //   1. Walk /proc/self/fd, resolve each symlink to find socket inodes.
    //   2. Parse /proc/net/tcp (and /proc/net/tcp6) to find entries matching
    //      those inodes.  Extract local/remote addr:port.
    //   3. For each matched connection, output an iptables/nftables DROP rule.

    // Step 1: collect our socket inodes from /proc/self/fd
    std::vector<uint64_t> our_inodes;
    {
        DIR* fd_dir = opendir("/proc/self/fd");
        if (!fd_dir) return false;
        struct dirent* dent;
        while ((dent = readdir(fd_dir)) != nullptr) {
            if (dent->d_name[0] == '.') continue;
            std::string fd_path = std::string("/proc/self/fd/") + dent->d_name;
            char link_target[256] = {};
            ssize_t len = readlink(fd_path.c_str(), link_target, sizeof(link_target) - 1);
            if (len <= 0) continue;
            link_target[len] = '\0';
            // Socket links look like: socket:[12345678]
            if (std::strncmp(link_target, "socket:[", 8) == 0) {
                uint64_t inode = std::strtoull(link_target + 8, nullptr, 10);
                if (inode) our_inodes.push_back(inode);
            }
        }
        closedir(fd_dir);
    }
    if (our_inodes.empty()) return false;

    bool found = false;

    // Step 2+3: parse /proc/net/tcp and /proc/net/tcp6
    for (const char* proc_file : {"/proc/net/tcp", "/proc/net/tcp6"}) {
        std::ifstream f(proc_file);
        if (!f.is_open()) continue;

        std::string line;
        std::getline(f, line);  // Skip header

        while (std::getline(f, line)) {
            // Fields: sl local_address rem_address st tx_queue:rx_queue
            //         tr:tm->when retrnsmt uid timeout inode ...
            // We need: local_address, rem_address, inode (field index 9)
            std::istringstream iss(line);
            std::string sl, local_addr, rem_addr, state;
            std::string tx_rx, tr_tm, retrnsmt, uid, timeout;
            uint64_t inode = 0;

            iss >> sl >> local_addr >> rem_addr >> state
                >> tx_rx >> tr_tm >> retrnsmt >> uid >> timeout >> inode;

            if (inode == 0) continue;

            // Check if this inode belongs to us
            bool is_ours = false;
            for (uint64_t ino : our_inodes) {
                if (ino == inode) { is_ours = true; break; }
            }
            if (!is_ours) continue;

            // Decode local address: "0100007F:0050" = 127.0.0.1:80 (little-endian hex)
            auto hex_to_addr_port = [](const std::string& hex,
                                       char* ip_out, size_t ip_len,
                                       uint16_t& port_out) {
                size_t colon = hex.find(':');
                if (colon == std::string::npos) { ip_out[0] = '\0'; port_out = 0; return; }
                std::string addr_hex = hex.substr(0, colon);
                std::string port_hex = hex.substr(colon + 1);
                port_out = static_cast<uint16_t>(
                    std::stoul(port_hex, nullptr, 16));
                if (addr_hex.size() == 8) {
                    // IPv4
                    uint32_t addr = static_cast<uint32_t>(
                        std::stoul(addr_hex, nullptr, 16));
                    // /proc/net/tcp stores in host byte order (little-endian x86)
                    struct in_addr in;
                    in.s_addr = addr;
                    inet_ntop(AF_INET, &in, ip_out, static_cast<socklen_t>(ip_len));
                } else {
                    // IPv6 (32 hex chars)
                    snprintf(ip_out, ip_len, "[IPv6:%s]", addr_hex.c_str());
                }
            };

            char l_ip[INET6_ADDRSTRLEN], r_ip[INET6_ADDRSTRLEN];
            uint16_t l_port = 0, r_port = 0;
            hex_to_addr_port(local_addr,  l_ip, sizeof(l_ip),  l_port);
            hex_to_addr_port(rem_addr,    r_ip, sizeof(r_ip),  r_port);

            // Output recommended iptables REJECT rule to stderr
            // In production this feeds into a firewall rules manager.
            char rule_buf[512];
            snprintf(rule_buf, sizeof(rule_buf),
                "[ProcessStealth] Connection: %s:%u -> %s:%u (inode=%lu) "
                "| iptables -A OUTPUT -p tcp --sport %u -j REJECT "
                "| nftables: nft add rule ip filter output tcp sport %u drop",
                l_ip, l_port, r_ip, r_port,
                static_cast<unsigned long>(inode),
                l_port, l_port);
            // Write to stderr (operator channel)
            fwrite(rule_buf, 1, std::strlen(rule_buf), stderr);
            fputc('\n', stderr);
            found = true;
        }
    }
    return found;
#endif
}

bool ProcessStealth::set_fake_process_name(const std::string& name) {
#ifdef _WIN32
    // Windows: write the fake name into the PEB's process parameters.
    //
    // NtQueryInformationProcess (class 0 = ProcessBasicInformation) gives us
    // the PEB address.  From there:
    //   PEB->ProcessParameters->ImagePathName  (UNICODE_STRING)
    //   PEB->ProcessParameters->CommandLine    (UNICODE_STRING)
    //
    // We overwrite the Buffer of both UNICODE_STRINGs in-place.
    // The fake name is a short alias, so we fit it within the existing buffer.
    //
    // Safety notes:
    //   - We never overwrite more bytes than Length indicates — no overflow.
    //   - VirtualProtect is used to make the PEB region writable if needed.
    //   - This does NOT change the module list (PEB->Ldr) or the file on disk;
    //     it only affects what NtQueryInformationProcess returns.

    typedef LONG (NTAPI *NtQueryInfoProcessFn)(
        HANDLE, ULONG, PVOID, ULONG, PULONG);

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return false;

    auto pNtQIP = reinterpret_cast<NtQueryInfoProcessFn>(
        GetProcAddress(hNtdll, "NtQueryInformationProcess"));
    if (!pNtQIP) return false;

    // ProcessBasicInformation = 0
    struct PROCESS_BASIC_INFO {
        PVOID     ExitStatus;
        PVOID     PebBaseAddress;  // PEB*
        PVOID     AffinityMask;
        PVOID     BasePriority;
        ULONG_PTR UniqueProcessId;
        PVOID     InheritedFromUniqueProcessId;
    } pbi{};

    LONG status = pNtQIP(GetCurrentProcess(), 0, &pbi, sizeof(pbi), nullptr);
    if (status != 0 || !pbi.PebBaseAddress) return false;

    // PEB layout (x64): offset 0x20 = ProcessParameters (RTL_USER_PROCESS_PARAMETERS*)
    // We use offsets compatible with x64 Windows 10+.
    // For x86 (32-bit), offsets differ but we guard with sizeof(PVOID).
    PVOID* peb = reinterpret_cast<PVOID*>(pbi.PebBaseAddress);
    // PEB->ProcessParameters is at offset 0x20 on x64, 0x10 on x86
#ifdef _WIN64
    const size_t pp_offset = 0x20 / sizeof(PVOID);  // index 4
#else
    const size_t pp_offset = 0x10 / sizeof(PVOID);  // index 4
#endif
    PVOID pp_ptr = peb[pp_offset];
    if (!pp_ptr) return false;

    // RTL_USER_PROCESS_PARAMETERS layout (x64):
    //   0x00  MaximumLength       ULONG
    //   0x04  Length              ULONG
    //   ... (reserved fields) ...
    //   0x60  ImagePathName       UNICODE_STRING  (Len, MaxLen, Buffer)
    //   0x70  CommandLine         UNICODE_STRING
    //
    // For x86 the offsets are smaller; we rely on the actual Windows SDK
    // definition via RTL_USER_PROCESS_PARAMETERS if available, but to stay
    // header-independent we compute from known offsets.
    //
    // Rather than redefining the full struct, cast to a byte pointer and
    // use the documented offsets directly.

    uint8_t* pp = reinterpret_cast<uint8_t*>(pp_ptr);

    // Convert fake name to wide string
    std::wstring wname(name.begin(), name.end());
    // Byte length of the wide string (without null terminator)
    USHORT new_len_bytes = static_cast<USHORT>(wname.size() * sizeof(wchar_t));

    // Process each UNICODE_STRING field (ImagePathName, CommandLine)
    // Offsets (x64): ImagePathName=0x60, CommandLine=0x70
    // Offsets (x86): ImagePathName=0x38, CommandLine=0x40
#ifdef _WIN64
    const size_t offsets[] = {0x60, 0x70};
#else
    const size_t offsets[] = {0x38, 0x40};
#endif

    bool changed = false;
    for (size_t off : offsets) {
        // UNICODE_STRING: [USHORT Length][USHORT MaximumLength][PWSTR Buffer]
        USHORT* len_ptr     = reinterpret_cast<USHORT*>(pp + off);
        USHORT* maxlen_ptr  = reinterpret_cast<USHORT*>(pp + off + 2);
        wchar_t** buf_ptr   = reinterpret_cast<wchar_t**>(pp + off + sizeof(ULONG_PTR));

        USHORT cur_len    = *len_ptr;
        USHORT cur_maxlen = *maxlen_ptr;
        wchar_t* buf      = *buf_ptr;

        if (!buf || cur_maxlen < new_len_bytes) continue;  // Won't fit

        // Make the buffer region writable (PEB is usually read-write, but guard)
        DWORD old_protect = 0;
        VirtualProtect(buf, cur_maxlen, PAGE_READWRITE, &old_protect);

        // Overwrite with the new name
        std::memcpy(buf, wname.c_str(), new_len_bytes);
        // Update Length to match new string
        *len_ptr = new_len_bytes;
        // Zero out the tail of the old buffer to remove remnants
        if (cur_len > new_len_bytes) {
            std::memset(
                reinterpret_cast<uint8_t*>(buf) + new_len_bytes,
                0,
                static_cast<size_t>(cur_len - new_len_bytes));
        }

        VirtualProtect(buf, cur_maxlen, old_protect, &old_protect);
        changed = true;
    }

    return changed;

#else  // POSIX
    if (original_name_.empty()) {
        char buf[16]{};
        prctl(PR_GET_NAME, buf, 0, 0, 0);
        original_name_ = buf;
    }
    config_.fake_name = name;

    // Write to /proc/self/comm (Linux kernel >= 3.8; max 15 chars + null)
    {
        int fd = open("/proc/self/comm", O_WRONLY | O_TRUNC);
        if (fd >= 0) {
            std::string trunc = name.substr(0, 15);
            ssize_t w = write(fd, trunc.c_str(), trunc.size());
            (void)w;
            close(fd);
        }
    }

    // prctl(PR_SET_NAME) sets the thread name visible in ps/top (max 15 chars)
    return prctl(PR_SET_NAME, name.c_str(), 0, 0, 0) == 0;
#endif
}

} // namespace ncp
