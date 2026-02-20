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
#include <vector>
#include <sodium.h>

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

// --- CSPRNG helpers ----------------------------------------------------------

static uint32_t csprng_uniform(uint32_t upper_bound) {
    if (upper_bound <= 1) return 0;
    return randombytes_uniform(upper_bound);
}

static void fisher_yates_shuffle(std::vector<uint8_t>::iterator begin,
                                  std::vector<uint8_t>::iterator end) {
    const size_t n = static_cast<size_t>(end - begin);
    if (n <= 1) return;
    for (size_t i = n - 1; i > 0; --i) {
        size_t j = csprng_uniform(static_cast<uint32_t>(i + 1));
        std::swap(*(begin + i), *(begin + j));
    }
}

template<typename T>
static void fisher_yates_shuffle_vec(std::vector<T>& vec) {
    const size_t n = vec.size();
    if (n <= 1) return;
    for (size_t i = n - 1; i > 0; --i) {
        size_t j = csprng_uniform(static_cast<uint32_t>(i + 1));
        std::swap(vec[i], vec[j]);
    }
}

// --- Impl --------------------------------------------------------------------

struct DummyPacketInjector::Impl {
    DummyProfile              profile;
    DummyStats                stats{};
    mutable std::mutex        mu;

    explicit Impl(const DummyProfile& prof)
        : profile(prof)
    {}

    // -- Generate a single dummy packet ---------------------------------------
    std::vector<uint8_t> generate_dummy() {
        // SECURITY FIX: Use unbiased randombytes_uniform() instead of std::uniform_int_distribution with mt19937
        const size_t min_sz = std::max(profile.min_size, MARKER_SIZE);
        const size_t max_sz = std::max(profile.max_size, MARKER_SIZE + 1);
        const size_t range = max_sz - min_sz;
        const size_t pkt_size = (range > 0)
            ? min_sz + csprng_uniform(static_cast<uint32_t>(range))
            : min_sz;

        std::vector<uint8_t> pkt(pkt_size);

        // Write encrypted marker at offset 0
        std::copy(ENCRYPTED_MARKER.begin(), ENCRYPTED_MARKER.end(),
                  pkt.begin() + MARKER_OFFSET);

        // Fill payload: 70% ASCII printable, 30% random
        const size_t payload_start = MARKER_OFFSET + MARKER_SIZE;
        const size_t payload_len   = pkt_size - payload_start;
        const size_t ascii_count   = static_cast<size_t>(payload_len * 0.7);

        for (size_t i = 0; i < payload_len; ++i) {
            if (i < ascii_count) {
                // ASCII range: 0x20 to 0x7E (95 characters)
                pkt[payload_start + i] = static_cast<uint8_t>(
                    0x20 + csprng_uniform(0x7E - 0x20 + 1)
                );
            } else {
                pkt[payload_start + i] = static_cast<uint8_t>(csprng_uniform(256));
            }
        }

        // Shuffle payload bytes to avoid obvious boundary between ASCII/random
        // SECURITY FIX: Use Fisher-Yates with unbiased randombytes_uniform()
        fisher_yates_shuffle(pkt.begin() + payload_start, pkt.end());
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
    // SECURITY FIX: Use Fisher-Yates with unbiased randombytes_uniform()
    fisher_yates_shuffle_vec(mixed);

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
