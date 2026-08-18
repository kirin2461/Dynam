#pragma once

/**
 * @file ncp_semfluid.hpp
 * @brief Semantic Fluid Transport (M8) — HTTP semantic wrapper.
 *
 * Payload rides inside syntactically AND semantically valid HTTP
 * requests (plausible headers, plausible cookie values), not random
 * noise.
 *
 * Embedding:
 *   blob  = len(4,BE) || payload
 *   chunk = data(43) || BLAKE2b-4(data)               // 47 bytes
 *   field = base62_bigint(chunk), left-padded to 64 chars
 * Chunks travel in Cookie values (MSFPC=..., _uetsid=..., ...) in a
 * fixed order. Every cookie chunk is exactly 64 chars, so chunk size
 * leaks nothing.
 *
 * Determinism: given the same seed, wrap() produces byte-identical
 * requests (stable header order).
 *
 * No exceptions cross the public API.
 */

#include <cstdint>
#include <cstddef>
#include <vector>
#include <string>
#include <utility>
#include <optional>
#include <random>

namespace ncp {

struct HttpRequest {
    std::string method;
    std::string path;
    // Ordered headers (order is part of the fingerprint, so it is stable).
    std::vector<std::pair<std::string, std::string>> headers;
    std::vector<uint8_t> body;

    std::optional<std::string> header(const std::string& name) const;
    std::string serialize() const; // full HTTP/1.1 request bytes
};

class SemanticWrapper {
public:
    static constexpr int    kTemplateCount   = 5;
    static constexpr size_t kMaxPayload      = 1u << 20; // 1 MiB sanity cap
    static constexpr size_t kChunkDataBytes  = 43;
    static constexpr size_t kChunkFieldChars = 64;

    /**
     * Wrap `payload` into a realistic HTTP request.
     * @param payload     bytes to embed
     * @param template_id 0..kTemplateCount-1, or nullopt to pick via rng
     * @param rng         caller-seeded RNG (determinism is the caller's job)
     */
    static HttpRequest wrap(const std::vector<uint8_t>& payload,
                            std::optional<int> template_id,
                            std::mt19937_64& rng);

    /**
     * Extract and checksum-verify the embedded payload.
     * Returns nullopt on any inconsistency (missing chunks, bad base62,
     * checksum mismatch, length mismatch).
     */
    static std::optional<std::vector<uint8_t>> unwrap(const HttpRequest& req);

    /**
     * Minimal HTTP/1.1 request parser for the shapes we generate.
     * Returns nullopt on malformed input.
     */
    static std::optional<HttpRequest> parse_request(const uint8_t* bytes,
                                                    size_t len);
    static std::optional<HttpRequest> parse_request(const std::string& s);

    // ----- exposed for tests / linting -----
    static std::string base62_encode_block(const uint8_t* data, size_t len,
                                           size_t width);
    static bool        base62_decode_block(const std::string& s,
                                           uint8_t* out, size_t out_len);
    static const char* template_name(int template_id);
};

} // namespace ncp
