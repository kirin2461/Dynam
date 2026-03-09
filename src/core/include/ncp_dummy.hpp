#ifndef NCP_DUMMY_HPP
#define NCP_DUMMY_HPP

#include <cstdint>
#include <cstddef>
#include <vector>
#include <memory>
#include <string>

namespace ncp {
namespace DPI {

/**
 * @brief Dummy packet injection profile
 */
struct DummyProfile {
    double injection_ratio = 0.5;    // 0.0-1.0, dummy-to-real ratio
    size_t min_size = 64;            // Min dummy packet size
    size_t max_size = 1400;          // Max dummy packet size
    bool mimic_real_distribution = true; // Match real packet size distribution

    /// Low stealth - few dummies
    static DummyProfile low()      { return {0.3, 64, 800, false}; }
    /// Moderate stealth
    static DummyProfile moderate() { return {0.5, 64, 1200, true}; }
    /// High stealth - 1:1 dummy:real
    static DummyProfile high()     { return {1.0, 64, 1400, true}; }
};

/**
 * @brief Statistics for dummy injection / filtering
 */
struct DummyStats {
    uint64_t real_packets = 0;
    uint64_t dummy_packets = 0;
    uint64_t total_dummy_bytes = 0;
};

/**
 * @brief Injects dummy (decoy) packets into an outgoing stream and
 *        filters them out on the receiving side.
 *
 * Dummy packets carry a 12-byte HMAC-based marker:
 *   [8-byte random nonce][4-byte HMAC-SHA256 tag]
 *
 * The tag is computed as HMAC-SHA256(session_key, nonce) truncated
 * to 4 bytes. Each dummy gets a unique nonce so there is no repeated
 * byte pattern for DPI to match. Both the injecting and filtering
 * sides must share the same session key (set via set_session_key()).
 *
 * If no session key is explicitly set, a random key is generated at
 * construction time. This works when the same DummyPacketInjector
 * instance handles both inject() and filter().
 *
 * Payload composition: 70% ASCII printable (0x20-0x7E), 30% random.
 */
class DummyPacketInjector {
public:
    DummyPacketInjector();
    ~DummyPacketInjector();

    // Non-copyable
    DummyPacketInjector(const DummyPacketInjector&) = delete;
    DummyPacketInjector& operator=(const DummyPacketInjector&) = delete;

    // Move semantics
    DummyPacketInjector(DummyPacketInjector&&) noexcept;
    DummyPacketInjector& operator=(DummyPacketInjector&&) noexcept;

    /**
     * @brief Set the session key used for HMAC-based dummy markers.
     *
     * Both the sending and receiving sides must call this with the
     * same key before inject() / filter(). The key should be at
     * least 16 bytes; it will be used as-is for HMAC-SHA256.
     *
     * If never called, a random 32-byte key is generated at construction.
     */
    void set_session_key(const std::vector<uint8_t>& key);
    void set_session_key(const uint8_t* key, size_t len);

    /**
     * @brief Inject dummy packets among real packets.
     * @param real_packets  The original outgoing packets.
     * @param profile       Injection profile (ratio, sizes).
     * @return Mixed vector of real + dummy packets, interleaved.
     */
    std::vector<std::vector<uint8_t>> inject(
        const std::vector<std::vector<uint8_t>>& real_packets,
        const DummyProfile& profile = DummyProfile::moderate()
    );

    /**
     * @brief Filter out dummy packets from a mixed stream.
     * @param mixed_packets  Mixed real + dummy packets.
     * @return Only the real packets (dummies removed).
     */
    std::vector<std::vector<uint8_t>> filter(
        const std::vector<std::vector<uint8_t>>& mixed_packets
    );

    /**
     * @brief Check if a single packet is a dummy (instance method).
     *
     * Uses the current session key for HMAC verification.
     */
    bool is_dummy_packet(const std::vector<uint8_t>& packet) const;

    /**
     * @brief Legacy static check - DEPRECATED.
     *
     * Cannot verify HMAC without session key. Always returns false.
     * Use is_dummy_packet() instance method instead.
     */
    [[deprecated("Use is_dummy_packet() instance method with session key")]]
    static bool is_dummy(const std::vector<uint8_t>& packet);

    DummyStats get_stats() const;
    void reset_stats();

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace DPI
} // namespace ncp

#endif // NCP_DUMMY_HPP
