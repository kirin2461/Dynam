#pragma once

#include <string>
#include <vector>
#include <memory>
#include <atomic>
#include <functional>
#include <cstdint>

namespace NCP {
namespace DPI {

/**
 * @brief DPI Bypass operation mode
 */
enum class DPIMode {
    DRIVER,      // nfqueue (Linux) / WinDivert (Windows) - packet modification
    PROXY,       // Transparent proxy mode
    PASSIVE      // Just detect, don't modify
};

/**
 * @brief Predefined DPI tuning profiles
 *
 * These presets are primarily tuned for common Russian DPI patterns
 * and are exposed via CLI/GUI for quick selection.
 */
enum class DPIPreset {
    NONE,        // No preset, use raw config
    RUNET_SOFT,  // Mild fragmentation + SNI tricks
    RUNET_STRONG // Aggressive fragmentation + disorder
};

/**
 * @brief DPI Bypass configuration
 */
struct DPIConfig {
    DPIMode mode = DPIMode::DRIVER;
    
    // TCP fragmentation settings
    bool enable_tcp_split = true;       // Split TCP packets
    int split_position = 2;             // Position to split (bytes from start)
    bool split_at_sni = true;           // Split at SNI hostname
    
    // TTL manipulation
    bool enable_fake_packet = true;     // Send fake packets with low TTL
    int fake_ttl = 1;                   // TTL for fake packets (dies at first hop)
    
    // Disorder techniques  
    bool enable_disorder = true;        // Send packets with timing/reordering tricks
    bool enable_oob_data = false;       // Use TCP out-of-band data
    int disorder_delay_ms = 15;         // Delay between fragments when disorder is enabled
    
    // Network settings
    uint16_t listen_port = 8080;        // For proxy mode
    std::string target_host;            // Target host (proxy mode)
    uint16_t target_port = 443;         // Target port
    
    // nfqueue settings (Linux)
    int nfqueue_num = 0;                // NFQUEUE number
    
    // Advanced
    int fragment_size = 2;              // Fragment size in bytes
    int fragment_offset = 2;            // Offset for fragmentation
};

/**
 * @brief Apply a predefined preset to an existing configuration.
 *
 * Network-related fields (listen_port, target_host/port, nfqueue_num)
 * are preserved so that callers can configure the destination first
 * and then overlay RuNet-oriented tuning.
 */
void apply_preset(DPIPreset preset, DPIConfig& config);

/**
 * @brief Convert a human-readable preset name to enum.
 *
 * Supports case-insensitive names like:
 * - "runet-soft"
 * - "runet_strong"
 * - "runet-strong"
 */
DPIPreset preset_from_string(const std::string& name);

/**
 * @brief Convert preset enum to human-readable name.
 */
const char* preset_to_string(DPIPreset preset);

/**
 * @brief DPI Bypass statistics
 */
struct DPIStats {
    uint64_t packets_total = 0;
    uint64_t packets_modified = 0;
    uint64_t packets_fragmented = 0;
    uint64_t fake_packets_sent = 0;
    uint64_t bytes_sent = 0;
    uint64_t bytes_received = 0;
    uint64_t connections_handled = 0;
};

/**
 * @brief Main DPI Bypass class
 * 
 * Supports multiple bypass techniques:
 * - TCP fragmentation (splits TLS ClientHello)
 * - Fake packets (low TTL packets to confuse DPI)
 * - Packet disorder (out-of-order delivery)
 * - SNI splitting (split specifically at SNI field)
 */
class DPIBypass {
public:
    DPIBypass();
    ~DPIBypass();
    
    // Non-copyable
    DPIBypass(const DPIBypass&) = delete;
    DPIBypass& operator=(const DPIBypass&) = delete;
    
    /**
     * @brief Initialize DPI bypass with configuration
     * @param config DPI bypass configuration
     * @return true if initialized successfully
     */
    bool initialize(const DPIConfig& config);
    
    /**
     * @brief Start DPI bypass (driver or proxy mode)
     * @return true if started successfully
     */
    bool start();
    
    /**
     * @brief Stop DPI bypass
     */
    void stop();
    
    /**
     * @brief Shutdown and cleanup
     */
    void shutdown();
    
    /**
     * @brief Check if bypass is running
     */
    bool is_running() const;
    
    /**
     * @brief Get statistics
     */
    DPIStats get_stats() const;
    
    /**
     * @brief Set log callback
     */
    void set_log_callback(std::function<void(const std::string&)> callback);

private:
    class Impl;
    std::unique_ptr<Impl> impl;
};

} // namespace DPI
} // namespace NCP
