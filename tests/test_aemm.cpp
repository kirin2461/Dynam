// M9: tests for ncp_aemm — Reed-Solomon erasure coding core (K of N).
#include "ncp_aemm.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <numeric>
#include <random>
#include <vector>

using ncp::aemm::ErasureCoder;
using ncp::aemm::ShardView;

namespace {

std::vector<uint8_t> random_bytes(size_t n, std::mt19937& rng) {
    std::vector<uint8_t> v(n);
    std::uniform_int_distribution<int> d(0, 255);
    for (auto& b : v) b = static_cast<uint8_t>(d(rng));
    return v;
}

// Encode k data shards of len bytes, return data + parity shards (n total).
struct Encoded {
    std::vector<std::vector<uint8_t>> shards;  // 0..k-1 data, k..n-1 parity
    size_t len;
};

Encoded encode_shards(const ErasureCoder& ec,
                      const std::vector<std::vector<uint8_t>>& data) {
    Encoded e;
    e.len = data[0].size();
    e.shards = data;
    const uint32_t parity = ec.n() - ec.k();
    for (uint32_t p = 0; p < parity; ++p)
        e.shards.emplace_back(e.len, 0);

    std::vector<const uint8_t*> dptr(ec.k());
    std::vector<uint8_t*> pptr(parity);
    for (uint32_t j = 0; j < ec.k(); ++j) dptr[j] = data[j].data();
    for (uint32_t p = 0; p < parity; ++p) pptr[p] = e.shards[ec.k() + p].data();
    ec.encode(dptr.data(), pptr.data(), e.len);
    return e;
}

// Decode from the given shard indices; returns recovered data shards.
bool decode_subset(const ErasureCoder& ec, const Encoded& e,
                   const std::vector<uint32_t>& idx,
                   std::vector<std::vector<uint8_t>>& out_data) {
    std::vector<ShardView> present;
    for (uint32_t i : idx) present.push_back(ShardView{i, e.shards[i].data()});
    out_data.assign(ec.k(), std::vector<uint8_t>(e.len, 0));
    std::vector<uint8_t*> optr(ec.k());
    for (uint32_t j = 0; j < ec.k(); ++j) optr[j] = out_data[j].data();
    return ec.decode(present, optr.data(), e.len);
}

} // namespace

// --- GF(2^8) primitive sanity ---
TEST(AemmGf, MulInvIdentities) {
    EXPECT_EQ(ncp::aemm::gf_mul(0, 0), 0);
    EXPECT_EQ(ncp::aemm::gf_mul(0, 53), 0);
    EXPECT_EQ(ncp::aemm::gf_mul(1, 200), 200);
    // 2 * 0x80 must reduce by the 0x11D polynomial -> 0x1D.
    EXPECT_EQ(ncp::aemm::gf_mul(2, 0x80), 0x1D);
    for (int a = 1; a < 256; ++a) {
        const uint8_t inv = ncp::aemm::gf_inv(static_cast<uint8_t>(a));
        EXPECT_EQ(ncp::aemm::gf_mul(static_cast<uint8_t>(a), inv), 1)
            << "a=" << a;
    }
    // Commutativity spot-check.
    std::mt19937 rng(7);
    for (int i = 0; i < 1000; ++i) {
        uint8_t a = static_cast<uint8_t>(rng());
        uint8_t b = static_cast<uint8_t>(rng());
        EXPECT_EQ(ncp::aemm::gf_mul(a, b), ncp::aemm::gf_mul(b, a));
    }
}

// --- (k=3, n=5): recover with EVERY possible 3-of-5 subset (10 combos) ---
TEST(AemmErasure, K3N5AllTenSubsets) {
    ErasureCoder ec(3, 5);
    ASSERT_TRUE(ec.valid());
    std::mt19937 rng(42);
    const size_t len = 1024;

    std::vector<std::vector<uint8_t>> data;
    for (uint32_t j = 0; j < 3; ++j) data.push_back(random_bytes(len, rng));
    Encoded e = encode_shards(ec, data);

    int combos = 0;
    for (uint32_t a = 0; a < 5; ++a)
        for (uint32_t b = a + 1; b < 5; ++b)
            for (uint32_t c = b + 1; c < 5; ++c) {
                ++combos;
                std::vector<std::vector<uint8_t>> recovered;
                ASSERT_TRUE(decode_subset(ec, e, {a, b, c}, recovered))
                    << "subset " << a << "," << b << "," << c;
                for (uint32_t j = 0; j < 3; ++j)
                    EXPECT_EQ(recovered[j], data[j])
                        << "subset " << a << "," << b << "," << c
                        << " shard " << j;
            }
    EXPECT_EQ(combos, 10);
}

// --- (k=4, n=6): 200 random 4-of-6 subsets ---
TEST(AemmErasure, K4N6RandomSubsetsX200) {
    ErasureCoder ec(4, 6);
    ASSERT_TRUE(ec.valid());
    std::mt19937 rng(1234);
    const size_t len = 4096;

    std::vector<std::vector<uint8_t>> data;
    for (uint32_t j = 0; j < 4; ++j) data.push_back(random_bytes(len, rng));
    Encoded e = encode_shards(ec, data);

    for (int iter = 0; iter < 200; ++iter) {
        std::vector<uint32_t> idx(6);
        std::iota(idx.begin(), idx.end(), 0u);
        std::shuffle(idx.begin(), idx.end(), rng);
        idx.resize(4);
        std::vector<std::vector<uint8_t>> recovered;
        ASSERT_TRUE(decode_subset(ec, e, idx, recovered)) << "iter " << iter;
        for (uint32_t j = 0; j < 4; ++j)
            ASSERT_EQ(recovered[j], data[j]) << "iter " << iter << " shard " << j;
    }
}

// --- Odd shard lengths (scalar remainder path in gf_mul_add) ---
TEST(AemmErasure, OddLengths) {
    ErasureCoder ec(3, 5);
    ASSERT_TRUE(ec.valid());
    std::mt19937 rng(99);
    for (size_t len : {1u, 7u, 31u, 33u, 100u, 1023u}) {
        std::vector<std::vector<uint8_t>> data;
        for (uint32_t j = 0; j < 3; ++j) data.push_back(random_bytes(len, rng));
        Encoded e = encode_shards(ec, data);
        std::vector<std::vector<uint8_t>> recovered;
        // Lose both parity shards: pure data passthrough.
        ASSERT_TRUE(decode_subset(ec, e, {0, 1, 2}, recovered));
        for (uint32_t j = 0; j < 3; ++j) EXPECT_EQ(recovered[j], data[j]);
        // Lose two data shards: real reconstruction.
        ASSERT_TRUE(decode_subset(ec, e, {0, 3, 4}, recovered));
        for (uint32_t j = 0; j < 3; ++j)
            EXPECT_EQ(recovered[j], data[j]) << "len=" << len;
    }
}

// --- Wire shard pack/unpack roundtrip + tamper detection ---
TEST(AemmShard, PackUnpackRoundtripAndTamper) {
    std::mt19937 rng(5);
    auto payload = random_bytes(500, rng);
    auto wire = ncp::aemm::pack_shard(3, 5, 4, 0xB10C1234, payload.data(),
                                      payload.size(),
                                      static_cast<uint32_t>(payload.size()));
    ASSERT_EQ(wire.size(), ncp::aemm::kShardHeaderSize + payload.size());
    EXPECT_EQ(wire[0], 'R');
    EXPECT_EQ(wire[1], 'S');

    auto parsed = ncp::aemm::unpack_shard(wire);
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->k, 3);
    EXPECT_EQ(parsed->n, 5);
    EXPECT_EQ(parsed->shard_idx, 4);
    EXPECT_EQ(parsed->block_id, 0xB10C1234u);
    EXPECT_EQ(parsed->orig_len, payload.size());
    EXPECT_EQ(parsed->payload, payload);

    // Tamper with a payload byte -> checksum must reject it.
    auto tampered = wire;
    tampered.back() ^= 0xFF;
    EXPECT_FALSE(ncp::aemm::unpack_shard(tampered).has_value());

    // Tamper with header fields -> rejected too.
    auto bad_magic = wire;
    bad_magic[0] = 'X';
    EXPECT_FALSE(ncp::aemm::unpack_shard(bad_magic).has_value());

    // Truncated -> rejected.
    EXPECT_FALSE(ncp::aemm::unpack_shard(wire.data(), 10).has_value());
}

// --- Full block roundtrip over 1 MiB of random data, losing N-K shards ---
TEST(AemmBlock, OneMiBRoundtrip) {
    ErasureCoder ec(4, 6);
    ASSERT_TRUE(ec.valid());
    std::mt19937 rng(2024);
    auto block = random_bytes(1024 * 1024, rng);

    auto wire = ec.encode_block(block.data(), block.size(), 77);
    ASSERT_EQ(wire.size(), 6u);

    // Verify all shards parse cleanly first.
    for (const auto& w : wire)
        ASSERT_TRUE(ncp::aemm::unpack_shard(w).has_value());

    // Drop shards 1 and 4 (one data, one parity) -> still recoverable.
    std::vector<std::vector<uint8_t>> subset = {wire[0], wire[2], wire[3], wire[5]};
    auto recovered = ec.recover_block(subset);
    ASSERT_TRUE(recovered.has_value());
    EXPECT_EQ(*recovered, block);

    // Only k-1 = 3 shards -> must fail.
    std::vector<std::vector<uint8_t>> too_few = {wire[0], wire[1], wire[2]};
    EXPECT_FALSE(ec.recover_block(too_few).has_value());

    // One tampered shard in the subset: skipped, still recovers from 4 valid.
    auto tampered_set = subset;
    tampered_set.push_back(wire[4]);
    tampered_set[0].back() ^= 0x01;  // shard 0 now has a bad checksum
    auto rec2 = ec.recover_block(tampered_set);
    ASSERT_TRUE(rec2.has_value());
    EXPECT_EQ(*rec2, block);
}

// --- Throughput smoke: log the number, don't fail hard on slow CI ---
TEST(AemmThroughput, ScalarSmoke) {
    ErasureCoder ec(4, 6);
    ASSERT_TRUE(ec.valid());
    std::mt19937 rng(31337);
    const size_t block = 4 * 1024 * 1024;  // 4 MiB
    auto data = random_bytes(block, rng);

    // Warm-up.
    (void)ec.encode_block(data.data(), data.size(), 1);

    const int iters = 8;
    auto t0 = std::chrono::steady_clock::now();
    size_t total = 0;
    for (int i = 0; i < iters; ++i) {
        auto wire = ec.encode_block(data.data(), data.size(),
                                    static_cast<uint32_t>(i));
        total += block;
        // Include a decode pass in the measured loop too.
        std::vector<std::vector<uint8_t>> subset = {wire[0], wire[2], wire[3], wire[5]};
        auto rec = ec.recover_block(subset);
        ASSERT_TRUE(rec.has_value());
    }
    auto t1 = std::chrono::steady_clock::now();
    const double sec = std::chrono::duration<double>(t1 - t0).count();
    const double mbps = (static_cast<double>(total) / (1024.0 * 1024.0)) / sec;

    // SPEC target: >= 50 MB/s scalar. Log the number; do NOT hard-fail.
    std::cout << "[AemmThroughput] RS encode+decode (k=4,n=6, 4 MiB x "
              << iters << "): " << mbps << " MB/s (SPEC target >= 50 MB/s)"
              << std::endl;
    SUCCEED();
}
