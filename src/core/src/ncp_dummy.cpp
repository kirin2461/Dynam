/**
 * @file ncp_dummy.cpp
 * @brief DummyPacketInjector implementation - Phase 5
 *
 * Injects dummy (decoy) packets into real traffic to confuse DPI analysis.
 * Uses encrypted 0xDEADBEEF marker for dummy identification.
 * Composition: 70% ASCII printable (0x20-0x7E), 30% random bytes.
 */

#include "ncp_dummy.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <cstring>
#include <mutex>
#include <numeric>
#include <random>
#include <vector>

namespace ncp {
namespace DPI {

// --- Encrypted marker constants ----------------------------------------------
static constexpr uint32_t DUMMY_MARKER_RAW  = 0xDEADBEEF;
static constexpr uint8_t  MARKER_XOR_KEY    = 0x5A;

// Marker bytes XOR-encrypted with key
static constexpr std::array<uint8_t, 4> ENCRYPTED_MARKER = {
    static_cast<uint8_t>((DUMMY_MARKER_RAW >> 24) ^ MARKER_XOR_KEY),
    static_cast<uint8_t>((DUMMY_MARKER_RAW >> 16) ^ MARKER_XOR_KEY),
    static_cast<uint8_t>((DUMMY_MARKER_RAW >>  8) ^ MARKER_XOR_KEY),
    static_cast<uint8_t>((DUMMY_MARKER_RAW >>  0) ^ MARKER_XOR_KEY)
};

// Marker is placed at offset 0 of each dummy packet (first 4 bytes)
static constexpr size_t MARKER_OFFSET = 0;
static constexpr size_t MARKER_SIZE   = ENCRYPTED_MARKER.size();

// --- DummyProfile factory methods --------------------------------------------

DummyProfile DummyProfile::low() {
    return {0.3, 64, 800, false};
}

DummyProfile DummyProfile::moderate() {
    return {0.5, 64, 1200, true};
}

DummyProfile DummyProfile::high() {
    return {1.0, 64, 1400, true};
}

// --- Impl --------------------------------------------------------------------

struct DummyPacketInjector::Impl {
    DummyProfile              profile;
    DummyStats                stats{};
    mutable std::mutex        mu;
    std::mt19937              rng;

    explicit Impl(const DummyProfile& prof)
        : profile(prof)
        , rng(std::random_device{}())
    {}

    // -- Generate a single dummy packet ---------------------------------------
    std::vector<uint8_t> generate_dummy() {
        std::uniform_int_distribution<size_t> size_dist(
            std::max(profile.min_size, MARKER_SIZE),
            std::max(profile.max_size, MARKER_SIZE + 1)
        );
        const size_t pkt_size = size_dist(rng);
        std::vector<uint8_t> pkt(pkt_size);

        // Write encrypted marker at offset 0
        std::copy(ENCRYPTED_MARKER.begin(), ENCRYPTED_MARKER.end(),
                  pkt.begin() + MARKER_OFFSET);

        // Fill payload: 70% ASCII printable, 30% random
        const size_t payload_start = MARKER_OFFSET + MARKER_SIZE;
        const size_t payload_len   = pkt_size - payload_start;
        const size_t ascii_count   = static_cast<size_t>(payload_len * 0.7);

        std::uniform_int_distribution<int> ascii_dist(0x20, 0x7E);
        std::uniform_int_distribution<int> byte_dist(0x00, 0xFF);

        for (size_t i = 0; i < payload_len; ++i) {
            if (i < ascii_count) {
                pkt[payload_start + i] = static_cast<uint8_t>(ascii_dist(rng));
            } else {
                pkt[payload_start + i] = static_cast<uint8_t>(byte_dist(rng));
            }
        }

        // Shuffle payload bytes to avoid obvious boundary between ASCII/random
        std::shuffle(pkt.begin() + payload_start, pkt.end(), rng);
        return pkt;
    }

    // -- Check if a packet contains the encrypted dummy marker ----------------
    static bool check_dummy(const std::vector<uint8_t>& packet) {
        if (packet.size() < MARKER_OFFSET + MARKER_SIZE) {
            return false;
        }
        return std::equal(
            ENCRYPTED_MARKER.begin(), ENCRYPTED_MARKER.end(),
            packet.begin() + MARKER_OFFSET
        );
    }
};

// --- Constructor / Destructor ------------------------------------------------

DummyPacketInjector::DummyPacketInjector()
    : impl_(std::make_unique<Impl>(DummyProfile::moderate()))
{}

DummyPacketInjector::~DummyPacketInjector() = default;

DummyPacketInjector::DummyPacketInjector(DummyPacketInjector&&) noexcept = default;
DummyPacketInjector& DummyPacketInjector::operator=(DummyPacketInjector&&) noexcept = default;

// --- inject() ----------------------------------------------------------------

std::vector<std::vector<uint8_t>>
DummyPacketInjector::inject(
    const std::vector<std::vector<uint8_t>>& real_packets,
    const DummyProfile& profile)
{
    std::lock_guard<std::mutex> lock(impl_->mu);
    impl_->profile = profile;

    if (real_packets.empty()) {
        return {};
    }

    // Calculate number of dummy packets to inject
    const size_t real_count  = real_packets.size();
    const size_t dummy_count = static_cast<size_t>(
        std::ceil(real_count * profile.injection_ratio)
    );

    // Build mixed output: real packets + dummy packets
    std::vector<std::vector<uint8_t>> mixed;
    mixed.reserve(real_count + dummy_count);

    // Copy real packets
    for (const auto& pkt : real_packets) {
        mixed.push_back(pkt);
    }

    // Generate and append dummy packets
    uint64_t injected_bytes = 0;
    for (size_t i = 0; i < dummy_count; ++i) {
        auto dummy = impl_->generate_dummy();
        injected_bytes += dummy.size();
        mixed.push_back(std::move(dummy));
    }

    // Interleave: shuffle the combined vector so dummies are spread out
    std::shuffle(mixed.begin(), mixed.end(), impl_->rng);

    // Update stats
    impl_->stats.real_packets  += real_count;
    impl_->stats.dummy_packets += dummy_count;
    impl_->stats.total_dummy_bytes += injected_bytes;

    return mixed;
}

// --- filter() ----------------------------------------------------------------

std::vector<std::vector<uint8_t>>
DummyPacketInjector::filter(
    const std::vector<std::vector<uint8_t>>& mixed_packets)
{
    std::lock_guard<std::mutex> lock(impl_->mu);

    std::vector<std::vector<uint8_t>> real;
    real.reserve(mixed_packets.size());

    for (const auto& pkt : mixed_packets) {
        if (Impl::check_dummy(pkt)) {
            impl_->stats.dummy_packets++;
            impl_->stats.total_dummy_bytes += pkt.size();
        } else {
            real.push_back(pkt);
            impl_->stats.real_packets++;
        }
    }

    return real;
}

// --- is_dummy() --------------------------------------------------------------

bool DummyPacketInjector::is_dummy(const std::vector<uint8_t>& packet) {
    return Impl::check_dummy(packet);
}

// --- Stats -------------------------------------------------------------------

DummyStats DummyPacketInjector::get_stats() const {
    std::lock_guard<std::mutex> lock(impl_->mu);
    return impl_->stats;
}

void DummyPacketInjector::reset_stats() {
    std::lock_guard<std::mutex> lock(impl_->mu);
    impl_->stats = DummyStats{};
}

} // namespace DPI
} // namespace ncp
