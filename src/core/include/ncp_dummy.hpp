#ifndef NCP_DUMMY_HPP
#define NCP_DUMMY_HPP

#include <cstdint>
#include <cstddef>
#include <vector>
#include <memory>

namespace ncp {
namespace DPI {

/// Dummy packet marker (encrypted per-session, checked on filter)
static constexpr uint32_t DUMMY_MARKER = 0xDEADBEEF;

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
 * Dummy packets carry a 4-byte encrypted marker (DUMMY_MARKER)
 * followed by a mix of ASCII-printable bytes (~70 %) and random
 * bytes (~30 %) so that they look like realistic traffic to a DPI
 * system.  The marker is XOR-encrypted with a per-session key so
 * that a passive observer cannot trivially identify dummies.
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
     * @brief Check if a single packet is a dummy.
     */
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
