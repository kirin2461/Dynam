/**
 * @file ncp_dummy.cpp
 * @brief DummyPacketInjector implementation - Phase 5
 *
 * Injects dummy (decoy) packets into real traffic to confuse DPI analysis.
 * Uses HMAC-SHA256 based marker with per-session key for dummy identification.
 * Marker: [8-byte nonce][4-byte HMAC tag] — unique per packet, no static pattern.
 * Payload composition: 70% ASCII printable (0x20-0x7E), 30% random bytes.
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

// --- Marker layout -----------------------------------------------------------
// Each dummy packet starts with:
//   [NONCE: 8 bytes][TAG: 4 bytes] = 12 bytes total
// TAG = HMAC-SHA256(session_key, nonce) truncated to first 4 bytes.
// Every dummy gets a fresh random nonce, so no two dummies share a byte pattern.

static constexpr size_t MARKER_NONCE_SIZE = 8;
static constexpr size_t MARKER_TAG_SIZE   = 4;
static constexpr size_t MARKER_TOTAL_SIZE = MARKER_NONCE_SIZE + MARKER_TAG_SIZE;
static constexpr size_t MARKER_OFFSET     = 0;

static constexpr size_t SESSION_KEY_SIZE  = 32; // crypto_auth_hmacsha256_KEYBYTES

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

// --- HMAC marker helpers -----------------------------------------------------

/// Compute HMAC-SHA256(key, nonce) and write truncated 4-byte tag to `tag_out`.
static void compute_marker_tag(
    const uint8_t* key, size_t key_len,
    const uint8_t* nonce, size_t nonce_len,
    uint8_t tag_out[MARKER_TAG_SIZE])
{
    uint8_t full_mac[crypto_auth_hmacsha256_BYTES];
    crypto_auth_hmacsha256_state state;
    crypto_auth_hmacsha256_init(&state, key, key_len);
    crypto_auth_hmacsha256_update(&state, nonce, nonce_len);
    crypto_auth_hmacsha256_final(&state, full_mac);
    std::memcpy(tag_out, full_mac, MARKER_TAG_SIZE);
    sodium_memzero(full_mac, sizeof(full_mac));
}

/// Verify that the first MARKER_TOTAL_SIZE bytes of `packet` contain a valid
/// HMAC marker for the given session key.
static bool verify_marker(
    const uint8_t* key, size_t key_len,
    const uint8_t* data, size_t data_len)
{
    if (data_len < MARKER_OFFSET + MARKER_TOTAL_SIZE) return false;

    const uint8_t* nonce = data + MARKER_OFFSET;
    const uint8_t* tag   = data + MARKER_OFFSET + MARKER_NONCE_SIZE;

    uint8_t expected_tag[MARKER_TAG_SIZE];
    compute_marker_tag(key, key_len, nonce, MARKER_NONCE_SIZE, expected_tag);

    // Constant-time comparison to prevent timing side-channel
    bool match = (sodium_memcmp(tag, expected_tag, MARKER_TAG_SIZE) == 0);
    sodium_memzero(expected_tag, sizeof(expected_tag));
    return match;
}

// --- Impl --------------------------------------------------------------------

struct DummyPacketInjector::Impl {
    DummyProfile              profile;
    DummyStats                stats{};
    mutable std::mutex        mu;
    std::vector<uint8_t>      session_key;

    explicit Impl(const DummyProfile& prof)
        : profile(prof)
    {
        // Generate random session key at construction
        session_key.resize(SESSION_KEY_SIZE);
        randombytes_buf(session_key.data(), SESSION_KEY_SIZE);
    }

    ~Impl() {
        // Secure wipe of key material
        if (!session_key.empty()) {
            sodium_memzero(session_key.data(), session_key.size());
        }
    }

    // -- Generate a single dummy packet ---------------------------------------
    std::vector<uint8_t> generate_dummy() {
        const size_t min_sz = std::max(profile.min_size, MARKER_TOTAL_SIZE);
        const size_t max_sz = std::max(profile.max_size, MARKER_TOTAL_SIZE + 1);
        const size_t range = max_sz - min_sz;
        const size_t pkt_size = (range > 0)
            ? min_sz + csprng_uniform(static_cast<uint32_t>(range))
            : min_sz;

        std::vector<uint8_t> pkt(pkt_size);

        // Generate random nonce and compute HMAC tag
        uint8_t nonce[MARKER_NONCE_SIZE];
        randombytes_buf(nonce, MARKER_NONCE_SIZE);

        uint8_t tag[MARKER_TAG_SIZE];
        compute_marker_tag(
            session_key.data(), session_key.size(),
            nonce, MARKER_NONCE_SIZE,
            tag);

        // Write marker: [nonce][tag]
        std::memcpy(pkt.data() + MARKER_OFFSET, nonce, MARKER_NONCE_SIZE);
        std::memcpy(pkt.data() + MARKER_OFFSET + MARKER_NONCE_SIZE,
                    tag, MARKER_TAG_SIZE);

        sodium_memzero(tag, sizeof(tag));

        // Fill payload: 70% ASCII printable, 30% random
        const size_t payload_start = MARKER_OFFSET + MARKER_TOTAL_SIZE;
        const size_t payload_len   = pkt_size - payload_start;
        const size_t ascii_count   = static_cast<size_t>(payload_len * 0.7);

        for (size_t i = 0; i < payload_len; ++i) {
            if (i < ascii_count) {
                pkt[payload_start + i] = static_cast<uint8_t>(
                    0x20 + csprng_uniform(0x7E - 0x20 + 1)
                );
            } else {
                pkt[payload_start + i] = static_cast<uint8_t>(csprng_uniform(256));
            }
        }

        // Shuffle payload bytes (not the marker!) to mix ASCII/random
        fisher_yates_shuffle(pkt.begin() + payload_start, pkt.end());
        return pkt;
    }

    // -- Check if a packet contains a valid HMAC dummy marker -----------------
    bool check_dummy(const std::vector<uint8_t>& packet) const {
        return verify_marker(
            session_key.data(), session_key.size(),
            packet.data(), packet.size());
    }
};

// --- Constructor / Destructor ------------------------------------------------

DummyPacketInjector::DummyPacketInjector()
    : impl_(std::make_unique<Impl>(DummyProfile::moderate()))
{}

DummyPacketInjector::~DummyPacketInjector() = default;

DummyPacketInjector::DummyPacketInjector(DummyPacketInjector&&) noexcept = default;
DummyPacketInjector& DummyPacketInjector::operator=(DummyPacketInjector&&) noexcept = default;

// --- Session key management --------------------------------------------------

void DummyPacketInjector::set_session_key(const std::vector<uint8_t>& key) {
    set_session_key(key.data(), key.size());
}

void DummyPacketInjector::set_session_key(const uint8_t* key, size_t len) {
    std::lock_guard<std::mutex> lock(impl_->mu);
    // Wipe old key
    if (!impl_->session_key.empty()) {
        sodium_memzero(impl_->session_key.data(), impl_->session_key.size());
    }
    impl_->session_key.assign(key, key + len);
}

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
        if (impl_->check_dummy(pkt)) {
            impl_->stats.dummy_packets++;
            impl_->stats.total_dummy_bytes += pkt.size();
        } else {
            real.push_back(pkt);
            impl_->stats.real_packets++;
        }
    }

    return real;
}

// --- is_dummy_packet() (instance) --------------------------------------------

bool DummyPacketInjector::is_dummy_packet(const std::vector<uint8_t>& packet) const {
    std::lock_guard<std::mutex> lock(impl_->mu);
    return impl_->check_dummy(packet);
}

// --- is_dummy() (static, deprecated) -----------------------------------------

bool DummyPacketInjector::is_dummy(const std::vector<uint8_t>& /*packet*/) {
    // Cannot verify HMAC without session key. Always returns false.
    // Callers should migrate to is_dummy_packet() instance method.
    return false;
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
