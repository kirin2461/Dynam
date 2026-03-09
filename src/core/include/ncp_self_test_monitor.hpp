#pragma once
/**
 * @file ncp_self_test_monitor.hpp
 * @brief Background self-attack / self-test monitor with auto-countermeasures
 *
 * Runs 5 categories of self-tests in a background thread to detect
 * whether the local traffic could be identified by an adversary:
 *
 *   1. ENTROPY_CHECK       — Shannon entropy of recent packet data
 *   2. TIMING_ANALYSIS     — Coefficient of variation of inter-arrival times
 *   3. SIZE_DISTRIBUTION   — Packet size bimodal profile (ACK + data)
 *   4. FINGERPRINT_CHECK   — TLS fingerprint consistency (placeholder)
 *   5. DNS_LEAK_CHECK       — DNS traffic routing check (placeholder)
 *
 * When a test fails (score < fail_threshold) and auto_countermeasure is
 * enabled, the monitor logs and applies recommended countermeasures.
 *
 * At HIGH threat the test interval is automatically reduced to 60 s.
 */

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <functional>
#include <mutex>
#include <atomic>
#include <thread>
#include <chrono>

#include "ncp_orchestrator.hpp"   // ncp::DPI::ThreatLevel

namespace ncp {

// =====================================================================
// Test type
// =====================================================================

enum class SelfTestType {
    ENTROPY_CHECK,       ///< Entropy of recent packet payloads
    TIMING_ANALYSIS,     ///< Inter-arrival time coefficient of variation
    SIZE_DISTRIBUTION,   ///< Packet size distribution profile
    FINGERPRINT_CHECK,   ///< TLS fingerprint consistency
    DNS_LEAK_CHECK       ///< DNS leak detection
};

// =====================================================================
// Result
// =====================================================================

struct SelfTestResult {
    SelfTestType  type       = SelfTestType::ENTROPY_CHECK;
    bool          passed     = true;
    std::string   test_name;
    std::string   detail;
    double        score      = 1.0;  ///< 1.0 = perfect, 0.0 = fully detectable
    std::chrono::steady_clock::time_point timestamp;

    /// Recommended countermeasure string if the test failed.
    std::string countermeasure;
};

// =====================================================================
// Configuration
// =====================================================================

struct SelfTestMonitorConfig {
    bool enabled = true;
    std::chrono::seconds test_interval{300};  ///< Run tests every 5 minutes
    double fail_threshold     = 0.6;          ///< Score below this = fail
    bool   auto_countermeasure = true;        ///< Automatically apply fixes
    bool   notify_on_fail     = true;         ///< Call failure_callback_ on fail
};

// =====================================================================
// Statistics
// =====================================================================

struct SelfTestMonitorStats {
    std::atomic<uint64_t> tests_run{0};
    std::atomic<uint64_t> tests_passed{0};
    std::atomic<uint64_t> tests_failed{0};
    std::atomic<uint64_t> countermeasures_applied{0};
    std::atomic<uint64_t> consecutive_failures{0};

    void reset() noexcept;

    SelfTestMonitorStats() = default;
    SelfTestMonitorStats(const SelfTestMonitorStats& o) noexcept
        : tests_run(o.tests_run.load())
        , tests_passed(o.tests_passed.load())
        , tests_failed(o.tests_failed.load())
        , countermeasures_applied(o.countermeasures_applied.load())
        , consecutive_failures(o.consecutive_failures.load())
    {}
    SelfTestMonitorStats& operator=(const SelfTestMonitorStats& o) noexcept {
        if (this != &o) {
            tests_run.store(o.tests_run.load());
            tests_passed.store(o.tests_passed.load());
            tests_failed.store(o.tests_failed.load());
            countermeasures_applied.store(o.countermeasures_applied.load());
            consecutive_failures.store(o.consecutive_failures.load());
        }
        return *this;
    }
};

// =====================================================================
// Main class
// =====================================================================

class SelfTestMonitor {
public:
    SelfTestMonitor();
    explicit SelfTestMonitor(const SelfTestMonitorConfig& cfg);
    ~SelfTestMonitor();

    SelfTestMonitor(const SelfTestMonitor&) = delete;
    SelfTestMonitor& operator=(const SelfTestMonitor&) = delete;

    // -----------------------------------------------------------------
    // Test execution
    // -----------------------------------------------------------------

    /// Run all 5 tests synchronously and return results.
    std::vector<SelfTestResult> run_all_tests();

    /// Run a single test type synchronously.
    SelfTestResult run_test(SelfTestType type);

    // -----------------------------------------------------------------
    // Background monitor
    // -----------------------------------------------------------------

    /// Start the background monitoring thread.
    void start();

    /// Stop the background monitoring thread (blocks until thread exits).
    void stop();

    /// Returns true if the background thread is running.
    bool is_running() const;

    // -----------------------------------------------------------------
    // Callbacks and countermeasures
    // -----------------------------------------------------------------

    using FailureCallback = std::function<void(const SelfTestResult&)>;

    /// Register a callback invoked for every failed test.
    void set_failure_callback(FailureCallback cb);

    /**
     * @brief Apply the recommended countermeasure for a failed test.
     *
     * Currently logs the action; integration points for future
     * automatic remediation are stubbed.
     */
    void apply_countermeasure(const SelfTestResult& result);

    // -----------------------------------------------------------------
    // Results
    // -----------------------------------------------------------------

    /// Return the results from the most recent run_all_tests() call.
    std::vector<SelfTestResult> get_last_results() const;

    // -----------------------------------------------------------------
    // Sample feeding
    // -----------------------------------------------------------------

    /**
     * @brief Feed a packet sample into the rolling statistics buffers.
     *
     * Called by external components for each observed packet so that
     * test_entropy_(), test_timing_(), and test_size_distribution_()
     * have data to analyse.
     *
     * @param data             Raw packet bytes.
     * @param inter_arrival_ms Time in ms since the previous packet.
     */
    void feed_packet(const std::vector<uint8_t>& data, double inter_arrival_ms);

    // -----------------------------------------------------------------
    // Accessors
    // -----------------------------------------------------------------

    void                    set_config(const SelfTestMonitorConfig& cfg);
    SelfTestMonitorConfig   get_config() const;
    SelfTestMonitorStats    get_stats()  const;
    void                    reset_stats();
    void                    set_threat_level(ncp::DPI::ThreatLevel level);

private:
    SelfTestMonitorConfig   config_;
    SelfTestMonitorStats    stats_;
    mutable std::mutex      mutex_;
    ncp::DPI::ThreatLevel   threat_level_ = ncp::DPI::ThreatLevel::NONE;

    std::thread             monitor_thread_;
    std::atomic<bool>       running_{false};
    FailureCallback         failure_callback_;
    std::vector<SelfTestResult> last_results_;   ///< Protected by mutex_

    // Rolling sample buffers (protected by mutex_)
    std::vector<double> recent_packet_entropies_;   ///< Per-packet Shannon entropy
    std::vector<double> recent_inter_arrival_ms_;   ///< Inter-arrival times
    std::vector<size_t> recent_packet_sizes_;        ///< Packet byte sizes
    static constexpr size_t MAX_SAMPLES = 1000;

    // -----------------------------------------------------------------
    // Individual test implementations
    // -----------------------------------------------------------------

    /// Check Shannon entropy of recent packets (expected 7.5 – 8.0 for encrypted).
    SelfTestResult test_entropy_();

    /// Check coefficient of variation of inter-arrival times.
    SelfTestResult test_timing_();

    /// Check whether packet sizes match the HTTPS bimodal profile.
    SelfTestResult test_size_distribution_();

    /// TLS fingerprint consistency check (placeholder — always passes).
    SelfTestResult test_fingerprint_();

    /// DNS leak detection (placeholder — checks DoH assumption).
    SelfTestResult test_dns_leak_();

    // -----------------------------------------------------------------
    // Background loop
    // -----------------------------------------------------------------

    void monitor_loop_();

    // -----------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------

    /// Compute Shannon entropy of byte data (result in bits, 0–8).
    static double compute_entropy_(const std::vector<uint8_t>& data);

    /// Compute mean of a sample vector.
    static double mean_(const std::vector<double>& v);

    /// Compute standard deviation of a sample vector.
    static double stddev_(const std::vector<double>& v, double mean);

    /// Effective test interval (reduced at HIGH threat).
    std::chrono::seconds effective_interval_() const;
};

} // namespace ncp
