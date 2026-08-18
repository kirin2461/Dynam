#pragma once

/**
 * @file ncp_aemm.hpp
 * @brief M9: Reed-Solomon erasure coding core (K of N) for the AEMM
 *        transport layer.
 *
 * Splits a stream into N shards; any K of them recover the original data,
 * so a session survives full blocking of N-K routes.
 *
 * - GF(2^8) with the classical RS polynomial 0x11D. Log/exp tables plus a
 *   full 256x256 multiply table are built once at static-init (function-local
 *   static => thread-safe since C++11).
 * - Systematic Cauchy encoding matrix: data shards pass through untouched,
 *   parity shards are Cauchy rows. Cauchy matrices are totally invertible,
 *   so EVERY k-of-n subset yields an invertible decoding submatrix.
 * - decode() inverts the k×k submatrix over GF(2^8) with Gauss-Jordan.
 * - Inner XOR-accumulate loop has an AVX2 path (classic 4-bit nibble /
 *   vpshufb table technique, guarded by __AVX2__) with a table-based scalar
 *   fallback. Both paths are covered by the tests; correctness first.
 * - Wire shard header (21 bytes):
 *     magic(2)="RS" | k(1) | n(1) | shard_idx(1) | block_id(4,BE) |
 *     orig_len(4,BE) | blake2b-8(payload) | payload
 *
 * Self-contained: no project deps; BLAKE2b via libsodium crypto_generichash.
 */

#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

namespace ncp {
namespace aemm {

/// Wire shard header size: 2 + 1 + 1 + 1 + 4 + 4 + 8.
constexpr size_t kShardHeaderSize = 21;

/// View of one present shard for decode(): idx in [0, n), ptr to shard_len
/// bytes of shard content (data or parity).
struct ShardView {
    uint32_t idx = 0;
    const uint8_t* ptr = nullptr;
};

/// Result of unpack_shard(): header fields plus verified payload.
struct UnpackedShard {
    uint8_t  k = 0;
    uint8_t  n = 0;
    uint8_t  shard_idx = 0;
    uint32_t block_id = 0;
    uint32_t orig_len = 0;
    std::vector<uint8_t> payload;
};

// GF(2^8) primitives (poly 0x11D), exposed for tests and advanced use.
uint8_t gf_mul(uint8_t a, uint8_t b);
uint8_t gf_inv(uint8_t a);

class ErasureCoder {
public:
    /// k data shards, n total shards. Valid for 1 <= k <= n <= 255.
    ErasureCoder(uint32_t k, uint32_t n);

    bool valid() const noexcept { return valid_; }
    uint32_t k() const noexcept { return k_; }
    uint32_t n() const noexcept { return n_; }

    /// Bytes per shard when splitting data_len bytes into k data shards
    /// (last data shard is zero-padded up to this length).
    size_t shard_len(size_t data_len) const;

    /// Systematic encode.
    /// @param data       k pointers to len-byte data shards (read-only).
    /// @param out_parity (n-k) pointers to len-byte buffers (write-only).
    void encode(const uint8_t* const* data,
                uint8_t* const* out_parity,
                size_t len) const;

    /// Decode from exactly k present shards (any k-of-n subset).
    /// @param present  k ShardViews (idx < n). Data shards pass through.
    /// @param out_data k pointers to len-byte buffers receiving data shards
    ///                 0..k-1 in order.
    /// @return false on bad arguments or a singular submatrix (should not
    ///         happen with the Cauchy construction).
    bool decode(const std::vector<ShardView>& present,
                uint8_t* const* out_data,
                size_t len) const;

    /// Convenience: split + encode + pack_shard() a whole block.
    /// Returns n wire shards (empty vector on invalid input).
    std::vector<std::vector<uint8_t>> encode_block(const uint8_t* data,
                                                   size_t len,
                                                   uint32_t block_id) const;

    /// Convenience: unpack + verify + decode a block from any subset of
    /// wire shards (>= k valid shards required; checksum failures are
    /// skipped). Returns the original block bytes or nullopt.
    std::optional<std::vector<uint8_t>> recover_block(
        const std::vector<std::vector<uint8_t>>& wire_shards) const;

private:
    uint32_t k_ = 0;
    uint32_t n_ = 0;
    bool valid_ = false;
    /// Encoding matrix, n rows x k columns, row-major. Rows 0..k-1 are the
    /// identity (systematic), rows k..n-1 are Cauchy: a_ij = 1/(x_i + y_j)
    /// with x_i = i, y_j = n + j (all sums non-zero, pairwise distinct).
    std::vector<uint8_t> matrix_;
};

// ---------------------------------------------------------------------------
// Wire shard helpers
// ---------------------------------------------------------------------------

/// Pack one shard with header + blake2b-8 payload checksum.
std::vector<uint8_t> pack_shard(uint8_t k, uint8_t n, uint8_t shard_idx,
                                uint32_t block_id,
                                const uint8_t* payload, size_t payload_len,
                                uint32_t orig_len);

/// Parse and checksum-verify a wire shard. nullopt on any mismatch/truncation.
std::optional<UnpackedShard> unpack_shard(const uint8_t* buf, size_t len);
std::optional<UnpackedShard> unpack_shard(const std::vector<uint8_t>& buf);

} // namespace aemm
} // namespace ncp
