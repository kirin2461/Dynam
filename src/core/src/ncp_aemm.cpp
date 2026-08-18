#include "ncp_aemm.hpp"

#include <cstring>

#include <sodium.h>

#if defined(__AVX2__)
#include <immintrin.h>
#endif

namespace ncp {
namespace aemm {

namespace {

// ---------------------------------------------------------------------------
// GF(2^8) tables, poly 0x11D, generator 2. Function-local static => the
// tables are initialised exactly once, thread-safe (C++11 magic statics).
// ---------------------------------------------------------------------------
struct GfTables {
    uint8_t exp[512];   // exp[i] = 2^i; duplicated to avoid the mod-255 step
    uint8_t log[256];   // log[x] = i such that 2^i = x (log[0] unused)
    uint8_t mul[256][256];  // full multiply table (64 KiB) for the hot loop

    GfTables() {
        uint16_t x = 1;
        for (int i = 0; i < 255; ++i) {
            exp[i] = static_cast<uint8_t>(x);
            log[x] = static_cast<uint8_t>(i);
            x <<= 1;
            if (x & 0x100) x ^= 0x11D;
        }
        for (int i = 255; i < 512; ++i) exp[i] = exp[i - 255];
        log[0] = 0;  // undefined, guarded by the a&&b checks below
        for (int a = 0; a < 256; ++a) {
            for (int b = 0; b < 256; ++b) {
                mul[a][b] = (a && b)
                    ? exp[log[a] + log[b]]
                    : static_cast<uint8_t>(0);
            }
        }
    }
};

const GfTables& gf() {
    static const GfTables tables;
    return tables;
}

// ---------------------------------------------------------------------------
// out[i] ^= coef * in[i] over GF(2^8).
// AVX2 path: classic 4-bit nibble technique — split each input byte into
// lo/hi nibbles and look up coef*nibble in two 16-entry tables with
// vpshufb (the technique used by ISA-L / Backblaze; a straight per-byte
// GF multiply in AVX2 is NOT correct, so we do not attempt one).
// Scalar fallback: one table lookup per byte via the 256x256 mul table.
// ---------------------------------------------------------------------------
void gf_mul_add(uint8_t* out, const uint8_t* in, uint8_t coef, size_t len) {
    if (coef == 0) return;
    if (coef == 1) {
        size_t i = 0;
        for (; i + 8 <= len; i += 8) {  // 8-way unrolled XOR
            out[i+0] ^= in[i+0]; out[i+1] ^= in[i+1];
            out[i+2] ^= in[i+2]; out[i+3] ^= in[i+3];
            out[i+4] ^= in[i+4]; out[i+5] ^= in[i+5];
            out[i+6] ^= in[i+6]; out[i+7] ^= in[i+7];
        }
        for (; i < len; ++i) out[i] ^= in[i];
        return;
    }

#if defined(__AVX2__)
    {
        const auto& t = gf();
        uint8_t lo[16], hi[16];
        for (int i = 0; i < 16; ++i) {
            lo[i] = t.mul[coef][i];
            hi[i] = t.mul[coef][static_cast<uint8_t>(i << 4)];
        }
        const __m256i tbl_lo = _mm256_broadcastsi128_si256(
            _mm_loadu_si128(reinterpret_cast<const __m128i*>(lo)));
        const __m256i tbl_hi = _mm256_broadcastsi128_si256(
            _mm_loadu_si128(reinterpret_cast<const __m128i*>(hi)));
        const __m256i mask = _mm256_set1_epi8(0x0F);

        size_t i = 0;
        for (; i + 32 <= len; i += 32) {
            const __m256i v = _mm256_loadu_si256(
                reinterpret_cast<const __m256i*>(in + i));
            const __m256i vlo = _mm256_and_si256(v, mask);
            const __m256i vhi = _mm256_and_si256(_mm256_srli_epi16(v, 4), mask);
            const __m256i r = _mm256_xor_si256(
                _mm256_shuffle_epi8(tbl_lo, vlo),
                _mm256_shuffle_epi8(tbl_hi, vhi));
            const __m256i o = _mm256_loadu_si256(
                reinterpret_cast<const __m256i*>(out + i));
            _mm256_storeu_si256(reinterpret_cast<__m256i*>(out + i),
                                _mm256_xor_si256(o, r));
        }
        const uint8_t* row = t.mul[coef];
        for (; i < len; ++i) out[i] ^= row[in[i]];
        return;
    }
#else
    const uint8_t* row = gf().mul[coef];
    size_t i = 0;
    for (; i + 4 <= len; i += 4) {  // 4-way unrolled table multiply
        out[i+0] ^= row[in[i+0]]; out[i+1] ^= row[in[i+1]];
        out[i+2] ^= row[in[i+2]]; out[i+3] ^= row[in[i+3]];
    }
    for (; i < len; ++i) out[i] ^= row[in[i]];
#endif
}

// Invert a k×k matrix (row-major) over GF(2^8) via Gauss-Jordan.
// Returns false if singular.
bool gf_invert(std::vector<uint8_t>& m, uint32_t k) {
    std::vector<uint8_t> inv(static_cast<size_t>(k) * k, 0);
    for (uint32_t i = 0; i < k; ++i) inv[i * k + i] = 1;

    for (uint32_t col = 0; col < k; ++col) {
        // Find pivot.
        uint32_t pivot = col;
        while (pivot < k && m[pivot * k + col] == 0) ++pivot;
        if (pivot == k) return false;  // singular
        if (pivot != col) {
            for (uint32_t j = 0; j < k; ++j) {
                std::swap(m[col * k + j], m[pivot * k + j]);
                std::swap(inv[col * k + j], inv[pivot * k + j]);
            }
        }
        // Scale pivot row so m[col][col] == 1.
        const uint8_t p = m[col * k + col];
        if (p != 1) {
            const uint8_t pinv = gf_inv(p);
            for (uint32_t j = 0; j < k; ++j) {
                m[col * k + j] = gf_mul(m[col * k + j], pinv);
                inv[col * k + j] = gf_mul(inv[col * k + j], pinv);
            }
        }
        // Eliminate the column from all other rows.
        for (uint32_t r = 0; r < k; ++r) {
            if (r == col) continue;
            const uint8_t f = m[r * k + col];
            if (f == 0) continue;
            for (uint32_t j = 0; j < k; ++j) {
                m[r * k + j] ^= gf_mul(m[col * k + j], f);
                inv[r * k + j] ^= gf_mul(inv[col * k + j], f);
            }
        }
    }
    m = std::move(inv);
    return true;
}

void write32be(uint8_t* p, uint32_t v) {
    p[0] = static_cast<uint8_t>(v >> 24);
    p[1] = static_cast<uint8_t>((v >> 16) & 0xFF);
    p[2] = static_cast<uint8_t>((v >> 8) & 0xFF);
    p[3] = static_cast<uint8_t>(v & 0xFF);
}

uint32_t read32be(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 24) |
           (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8) |
           static_cast<uint32_t>(p[3]);
}

void ensure_sodium() {
    static const int rc = sodium_init();
    (void)rc;
}

} // namespace

uint8_t gf_mul(uint8_t a, uint8_t b) {
    return gf().mul[a][b];
}

uint8_t gf_inv(uint8_t a) {
    if (a == 0) return 0;  // undefined; 0 is a safe sentinel
    const auto& t = gf();
    return t.exp[255 - t.log[a]];
}

ErasureCoder::ErasureCoder(uint32_t k, uint32_t n) : k_(k), n_(n) {
    if (k_ < 1 || n_ < k_ || n_ > 255) return;
    valid_ = true;
    matrix_.assign(static_cast<size_t>(n_) * k_, 0);
    for (uint32_t i = 0; i < n_; ++i) {
        for (uint32_t j = 0; j < k_; ++j) {
            if (i < k_) {
                matrix_[i * k_ + j] = (i == j) ? 1 : 0;  // systematic rows
            } else {
                // Cauchy row: 1 / (x_i + y_j), x_i = i, y_j = n + j.
                // x_i in [k, n), y_j in [n, n+k) => always distinct, XOR != 0.
                const uint8_t xi = static_cast<uint8_t>(i);
                const uint8_t yj = static_cast<uint8_t>(n_ + j);
                matrix_[i * k_ + j] = gf_inv(static_cast<uint8_t>(xi ^ yj));
            }
        }
    }
}

size_t ErasureCoder::shard_len(size_t data_len) const {
    if (!valid_ || data_len == 0) return 0;
    return (data_len + k_ - 1) / k_;
}

void ErasureCoder::encode(const uint8_t* const* data,
                          uint8_t* const* out_parity,
                          size_t len) const {
    if (!valid_ || !data || !out_parity) return;
    const uint32_t parity = n_ - k_;
    for (uint32_t p = 0; p < parity; ++p) {
        uint8_t* dst = out_parity[p];
        if (!dst) continue;
        std::memset(dst, 0, len);
        const uint8_t* row = &matrix_[(k_ + p) * k_];
        for (uint32_t j = 0; j < k_; ++j) {
            if (data[j]) gf_mul_add(dst, data[j], row[j], len);
        }
    }
}

bool ErasureCoder::decode(const std::vector<ShardView>& present,
                          uint8_t* const* out_data,
                          size_t len) const {
    if (!valid_ || !out_data) return false;
    if (present.size() != k_) return false;
    for (const auto& sv : present) {
        if (sv.idx >= n_ || (!sv.ptr && len > 0)) return false;
    }

    // Build the k×k decoding submatrix from the present rows.
    std::vector<uint8_t> sub(static_cast<size_t>(k_) * k_);
    for (uint32_t r = 0; r < k_; ++r) {
        std::memcpy(&sub[r * k_], &matrix_[present[r].idx * k_], k_);
    }
    if (!gf_invert(sub, k_)) return false;

    // data[j] = sum_i inv[j][i] * present[i]
    for (uint32_t j = 0; j < k_; ++j) {
        uint8_t* dst = out_data[j];
        if (!dst) return false;
        std::memset(dst, 0, len);
        for (uint32_t i = 0; i < k_; ++i) {
            gf_mul_add(dst, present[i].ptr, sub[j * k_ + i], len);
        }
    }
    return true;
}

std::vector<std::vector<uint8_t>> ErasureCoder::encode_block(
        const uint8_t* data, size_t len, uint32_t block_id) const {
    if (!valid_ || (!data && len > 0) || len == 0) return {};
    const size_t slen = shard_len(len);

    std::vector<std::vector<uint8_t>> data_shards(k_, std::vector<uint8_t>(slen, 0));
    for (uint32_t j = 0; j < k_; ++j) {
        const size_t off = static_cast<size_t>(j) * slen;
        const size_t take = (off < len) ? std::min(slen, len - off) : 0;
        if (take) std::memcpy(data_shards[j].data(), data + off, take);
    }
    const uint32_t parity = n_ - k_;
    std::vector<std::vector<uint8_t>> parity_shards(parity, std::vector<uint8_t>(slen, 0));

    std::vector<const uint8_t*> dptr(k_);
    std::vector<uint8_t*> pptr(parity);
    for (uint32_t j = 0; j < k_; ++j) dptr[j] = data_shards[j].data();
    for (uint32_t p = 0; p < parity; ++p) pptr[p] = parity_shards[p].data();
    encode(dptr.data(), pptr.data(), slen);

    std::vector<std::vector<uint8_t>> out;
    out.reserve(n_);
    for (uint32_t i = 0; i < n_; ++i) {
        const auto& buf = (i < k_) ? data_shards[i] : parity_shards[i - k_];
        out.push_back(pack_shard(static_cast<uint8_t>(k_),
                                 static_cast<uint8_t>(n_),
                                 static_cast<uint8_t>(i),
                                 block_id, buf.data(), buf.size(),
                                 static_cast<uint32_t>(len)));
    }
    return out;
}

std::optional<std::vector<uint8_t>> ErasureCoder::recover_block(
        const std::vector<std::vector<uint8_t>>& wire_shards) const {
    if (!valid_) return std::nullopt;

    std::vector<UnpackedShard> good;
    std::vector<bool> seen(n_, false);
    for (const auto& w : wire_shards) {
        auto s = unpack_shard(w);
        if (!s) continue;                       // checksum/format failure
        if (s->k != k_ || s->n != n_) continue; // wrong coder parameters
        if (s->shard_idx >= n_ || seen[s->shard_idx]) continue;  // dup/bad idx
        seen[s->shard_idx] = true;
        good.push_back(std::move(*s));
        if (good.size() == k_) break;
    }
    if (good.size() < k_) return std::nullopt;

    const size_t slen = good[0].payload.size();
    const uint32_t orig_len = good[0].orig_len;
    for (const auto& s : good) {
        if (s.payload.size() != slen || s.orig_len != orig_len)
            return std::nullopt;  // inconsistent block
    }

    std::vector<std::vector<uint8_t>> data(k_, std::vector<uint8_t>(slen, 0));
    std::vector<ShardView> present(k_);
    std::vector<uint8_t*> dptr(k_);
    for (uint32_t i = 0; i < k_; ++i) {
        present[i] = ShardView{good[i].shard_idx, good[i].payload.data()};
        dptr[i] = data[i].data();
    }
    if (!decode(present, dptr.data(), slen)) return std::nullopt;

    std::vector<uint8_t> out;
    out.reserve(static_cast<size_t>(k_) * slen);
    for (uint32_t j = 0; j < k_; ++j)
        out.insert(out.end(), data[j].begin(), data[j].end());
    if (orig_len > out.size()) return std::nullopt;
    out.resize(orig_len);
    return out;
}

std::vector<uint8_t> pack_shard(uint8_t k, uint8_t n, uint8_t shard_idx,
                                uint32_t block_id,
                                const uint8_t* payload, size_t payload_len,
                                uint32_t orig_len) {
    ensure_sodium();
    std::vector<uint8_t> out(kShardHeaderSize + payload_len, 0);
    out[0] = 'R';
    out[1] = 'S';
    out[2] = k;
    out[3] = n;
    out[4] = shard_idx;
    write32be(&out[5], block_id);
    write32be(&out[9], orig_len);
    if (payload_len > 0)
        std::memcpy(&out[kShardHeaderSize], payload, payload_len);
    crypto_generichash(&out[13], 8,
                       payload_len ? payload : nullptr, payload_len,
                       nullptr, 0);
    return out;
}

std::optional<UnpackedShard> unpack_shard(const uint8_t* buf, size_t len) {
    if (!buf || len < kShardHeaderSize) return std::nullopt;
    if (buf[0] != 'R' || buf[1] != 'S') return std::nullopt;

    UnpackedShard s;
    s.k = buf[2];
    s.n = buf[3];
    s.shard_idx = buf[4];
    s.block_id = read32be(&buf[5]);
    s.orig_len = read32be(&buf[9]);
    if (s.k < 1 || s.n < s.k) return std::nullopt;

    const uint8_t* payload = &buf[kShardHeaderSize];
    const size_t payload_len = len - kShardHeaderSize;

    ensure_sodium();
    uint8_t check[8];
    crypto_generichash(check, sizeof(check),
                       payload_len ? payload : nullptr, payload_len,
                       nullptr, 0);
    if (sodium_memcmp(check, &buf[13], 8) != 0) return std::nullopt;

    s.payload.assign(payload, payload + payload_len);
    return s;
}

std::optional<UnpackedShard> unpack_shard(const std::vector<uint8_t>& buf) {
    return unpack_shard(buf.data(), buf.size());
}

} // namespace aemm
} // namespace ncp
