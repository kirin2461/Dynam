#ifndef NCP_L3_STEALTH_HPP
#define NCP_L3_STEALTH_HPP

#include <cstdint>
#include <string>
#include <vector>
#include <atomic>
#include <mutex>
#include <functional>
#include <chrono>

namespace ncp {

/**
 * @brief L3 Anti-Fingerprint Stealth Engine (Phase 1)
 *
 * Normalizes IP/TCP header fields that ISPs and DPI systems use
 * for traffic correlation and OS fingerprinting.
 *
 * Works entirely at L3 via AF_INET + SOCK_RAW (IP_HDRINCL).
 * No Npcap, no AF_PACKET, no special drivers required.
 *
 * Covers:
 *  - IPID randomization (anti-correlation)
 *  - TTL normalization (anti-hop-count detection)
 *  - IPv6 Flow Label randomization (anti-fingerprint)
 *  - MSS clamping (hide VPN/tunnel MTU)
 *  - IP fragmentation enforcement (force MTU=1500 output)
 *  - TCP timestamp normalization (anti-uptime fingerprint)
 */
class L3Stealth {
public:
    // ==================== OS Profiles ====================
    enum class OSProfile {
        AUTO,           // Detect current OS and use native values
        WINDOWS_10,     // TTL=128, window=65535, DF=1
        WINDOWS_11,     // TTL=128, window=65535, DF=1
        LINUX_5X,       // TTL=64, window=65535, DF=1
        LINUX_6X,       // TTL=64, window=65535, DF=1
        MACOS_14,       // TTL=64, window=65535, DF=1
        FREEBSD_14,     // TTL=64, window=65535, DF=1
        ANDROID_14,     // TTL=64, window=65535, DF=1
        IOS_17,         // TTL=64, window=65535, DF=1
        CUSTOM          // User-defined values
    };

    // ==================== IPID Strategy ====================
    enum class IPIDStrategy {
        CSPRNG,             // Fully random via libsodium randombytes
        INCREMENTAL_RANDOM, // Increment by random 1-64 (mimics Windows)
        ZERO,               // Always 0 (mimics Linux DF=1 packets)
        PER_DESTINATION,    // Per-dest counter with random start (mimics modern Linux)
        GLOBAL_COUNTER      // Single global counter with random start (mimics older OS)
    };

    // ==================== Configuration ====================
    struct Config {
        // --- IPID Randomization ---
        bool enable_ipid_randomization = true;
        IPIDStrategy ipid_strategy = IPIDStrategy::CSPRNG;

        // --- TTL Normalization ---
        bool enable_ttl_normalization = true;
        OSProfile ttl_profile = OSProfile::AUTO;
        uint8_t custom_ttl = 128;               // Used when ttl_profile == CUSTOM
        bool randomize_ttl_jitter = false;       // Add +-1 jitter to TTL

        // --- IPv6 Flow Label ---
        bool enable_flow_label_randomization = true;
        bool per_flow_label = true;              // Same label per 5-tuple, random per new flow
        uint32_t custom_flow_label = 0;          // 0 = auto-random, nonzero = fixed

        // --- MSS Clamping ---
        bool enable_mss_clamping = true;
        uint16_t target_mss = 1460;              // Standard Ethernet MSS (MTU 1500 - 40)
        bool clamp_only_syn = true;              // Only modify MSS in SYN/SYN-ACK packets

        // --- IP Fragmentation Enforcement ---
        bool enable_fragment_normalization = false;
        uint16_t enforce_mtu = 1500;             // Force all outgoing packets to this MTU
        bool clear_df_for_tunneled = false;       // Clear DF bit on tunneled packets

        // --- TCP Timestamp Normalization ---
        bool enable_tcp_timestamp_normalization = true;
        bool randomize_timestamp_offset = true;   // Random base offset for TSval
        uint32_t timestamp_hz = 1000;             // Timestamp tick rate (Win=10ms, Linux=1ms)

        // --- DF Bit Control ---
        bool enable_df_normalization = true;
        bool force_df = true;                     // true=set DF (Win10/Linux default)

        // --- General ---
        OSProfile os_profile = OSProfile::AUTO;   // Master profile for all defaults
        bool enable_logging = false;
    };

    // ==================== Statistics ====================
    struct Stats {
        std::atomic<uint64_t> packets_processed{0};
        std::atomic<uint64_t> ipid_rewritten{0};
        std::atomic<uint64_t> ttl_normalized{0};
        std::atomic<uint64_t> flow_labels_randomized{0};
        std::atomic<uint64_t> mss_clamped{0};
        std::atomic<uint64_t> packets_fragmented{0};
        std::atomic<uint64_t> timestamps_normalized{0};
        std::atomic<uint64_t> df_bits_modified{0};

        Stats() = default;
        Stats(const Stats& o)
            : packets_processed(o.packets_processed.load())
            , ipid_rewritten(o.ipid_rewritten.load())
            , ttl_normalized(o.ttl_normalized.load())
            , flow_labels_randomized(o.flow_labels_randomized.load())
            , mss_clamped(o.mss_clamped.load())
            , packets_fragmented(o.packets_fragmented.load())
            , timestamps_normalized(o.timestamps_normalized.load())
            , df_bits_modified(o.df_bits_modified.load()) {}

        void reset() {
            packets_processed.store(0);
            ipid_rewritten.store(0);
            ttl_normalized.store(0);
            flow_labels_randomized.store(0);
            mss_clamped.store(0);
            packets_fragmented.store(0);
            timestamps_normalized.store(0);
            df_bits_modified.store(0);
        }
    };

    // ==================== Lifecycle ====================
    L3Stealth();
    ~L3Stealth();

    L3Stealth(const L3Stealth&) = delete;
    L3Stealth& operator=(const L3Stealth&) = delete;

    /**
     * @brief Initialize with config. Must be called before process_*.
     * @return true if libsodium initialized and config valid
     */
    bool initialize(const Config& config = Config{});

    /**
     * @brief Update config at runtime (thread-safe)
     */
    bool update_config(const Config& config);

    /**
     * @brief Get current config (thread-safe)
     */
    Config get_config() const;

    // ==================== Packet Processing ====================

    /**
     * @brief Process an outgoing IPv4 packet in-place.
     *
     * Rewrites IPID, TTL, DF, MSS, TCP timestamps.
     * The packet must start with an IP header (as with IP_HDRINCL).
     *
     * @param packet Mutable packet buffer (IP header + payload)
     * @return true if packet was modified
     */
    bool process_ipv4_packet(std::vector<uint8_t>& packet);

    /**
     * @brief Process an outgoing IPv6 packet in-place.
     *
     * Rewrites Flow Label, Hop Limit, MSS, TCP timestamps.
     *
     * @param packet Mutable packet buffer (IPv6 header + payload)
     * @return true if packet was modified
     */
    bool process_ipv6_packet(std::vector<uint8_t>& packet);

    /**
     * @brief Fragment an IPv4 packet to enforce MTU.
     *
     * @param packet Original packet
     * @param mtu Target MTU (default: config enforce_mtu)
     * @return Vector of fragment packets, or single-element if no fragmentation needed
     */
    std::vector<std::vector<uint8_t>> fragment_ipv4(
        const std::vector<uint8_t>& packet,
        uint16_t mtu = 0
    );

    // ==================== IPID Generation ====================

    /**
     * @brief Generate next IPID value based on configured strategy.
     * @param dest_ip Destination IP (used for PER_DESTINATION strategy)
     */
    uint16_t generate_ipid(uint32_t dest_ip = 0);

    // ==================== Flow Label Generation ====================

    /**
     * @brief Generate IPv6 flow label for a given 5-tuple hash.
     * @param flow_hash Hash of (src_ip, dst_ip, src_port, dst_port, protocol)
     */
    uint32_t generate_flow_label(uint64_t flow_hash = 0);

    // ==================== TTL ====================

    /**
     * @brief Get the TTL value for current OS profile.
     */
    uint8_t get_profile_ttl() const;

    /**
     * @brief Get the MSS value for current config.
     */
    uint16_t get_target_mss() const;

    // ==================== Stats ====================
    Stats get_stats() const;
    void reset_stats();

    // ==================== Logging ====================
    using LogCallback = std::function<void(const std::string&)>;
    void set_log_callback(LogCallback cb);

    // ==================== Static Helpers ====================

    /**
     * @brief Detect current OS and return matching profile.
     */
    static OSProfile detect_os_profile();

    /**
     * @brief Get default TTL for a given OS profile.
     */
    static uint8_t default_ttl_for_profile(OSProfile profile);

    /**
     * @brief Get default MSS for standard Ethernet.
     */
    static uint16_t default_mss() { return 1460; }

private:
    // --- Internal packet manipulation ---
    bool rewrite_ipid(uint8_t* ip_header, size_t len);
    bool normalize_ttl(uint8_t* ip_header, size_t len);
    bool normalize_df(uint8_t* ip_header, size_t len);
    bool clamp_mss_ipv4(uint8_t* tcp_header, size_t tcp_len);
    bool clamp_mss_ipv6(uint8_t* tcp_header, size_t tcp_len);
    bool normalize_tcp_timestamps(uint8_t* tcp_header, size_t tcp_len);
    bool rewrite_ipv6_flow_label(uint8_t* ipv6_header, size_t len, uint64_t flow_hash);
    bool normalize_hop_limit(uint8_t* ipv6_header, size_t len);

    // --- Checksum recalculation ---
    static uint16_t calculate_checksum(const void* data, int len);
    static void recalculate_ip_checksum(uint8_t* ip_header);
    static void recalculate_tcp_checksum_ipv4(uint8_t* ip_header, uint8_t* tcp_header, size_t tcp_total_len);
    static void recalculate_tcp_checksum_ipv6(uint8_t* ipv6_header, uint8_t* tcp_header, size_t tcp_total_len);

    // --- TCP options parsing ---
    static int find_mss_option_offset(const uint8_t* tcp_header, size_t tcp_header_len);
    static int find_timestamp_option_offset(const uint8_t* tcp_header, size_t tcp_header_len);

    // --- Per-destination IPID tracking ---
    struct DestIPIDState {
        uint16_t current_id;
        std::chrono::steady_clock::time_point last_used;
    };
    mutable std::mutex dest_ipid_mutex_;
    std::unordered_map<uint32_t, DestIPIDState> dest_ipid_map_;
    uint16_t global_ipid_counter_ = 0;

    // --- Flow label cache ---
    mutable std::mutex flow_label_mutex_;
    std::unordered_map<uint64_t, uint32_t> flow_label_cache_;

    // --- Timestamp state ---
    uint32_t timestamp_offset_ = 0;
    std::chrono::steady_clock::time_point timestamp_epoch_;

    // --- Config & state ---
    mutable std::mutex config_mutex_;
    Config config_;
    bool initialized_ = false;
    Stats stats_;
    LogCallback log_cb_;

    void log(const std::string& msg);
};

} // namespace ncp

#endif // NCP_L3_STEALTH_HPP
