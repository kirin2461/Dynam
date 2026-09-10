/**
 * @file ncp_header_protection.cpp
 * @brief AWG 3.1-inspired header protection (see ncp_header_protection.hpp)
 */

#include "ncp_header_protection.hpp"

#include <cstring>
#include <sodium.h>

namespace ncp {

namespace {
constexpr char kHpSalt[] = "ncp-hp-v1";
constexpr size_t kHashLen = 32;  // SHA-256 output

void store_u64_be_hp(uint8_t* p, uint64_t v) {
    for (int i = 0; i < 8; ++i)
        p[i] = static_cast<uint8_t>(v >> ((7 - i) * 8));
}

bool hmac_sha256(const uint8_t* key, size_t key_len,
                 const uint8_t* data, size_t data_len,
                 uint8_t* out) {
    crypto_auth_hmacsha256_state st;
    if (crypto_auth_hmacsha256_init(&st, key, key_len) != 0)
        return false;
    crypto_auth_hmacsha256_update(&st, data, data_len);
    crypto_auth_hmacsha256_final(&st, out);
    return true;
}
} // namespace

// ==================== HKDF-SHA256 ====================

bool hkdf_sha256(const uint8_t* ikm, size_t ikm_len,
                 const uint8_t* salt, size_t salt_len,
                 const uint8_t* info, size_t info_len,
                 uint8_t* out, size_t out_len) {
    if (!ikm || ikm_len == 0 || !out || out_len == 0 ||
        out_len > 255 * kHashLen)
        return false;

    // Extract: PRK = HMAC-Hash(salt, IKM). Zero salt when absent (RFC 5869).
    uint8_t zero_salt[kHashLen] = {0};
    if (!salt || salt_len == 0) {
        salt = zero_salt;
        salt_len = kHashLen;
    }
    uint8_t prk[kHashLen];
    if (!hmac_sha256(salt, salt_len, ikm, ikm_len, prk))
        return false;

    // Expand: T(i) = HMAC(PRK, T(i-1) || info || i)
    uint8_t t[kHashLen];
    size_t t_len = 0;
    size_t produced = 0;
    uint8_t counter = 1;
    while (produced < out_len) {
        crypto_auth_hmacsha256_state st;
        if (crypto_auth_hmacsha256_init(&st, prk, sizeof(prk)) != 0) {
            sodium_memzero(prk, sizeof(prk));
            return false;
        }
        if (t_len > 0)
            crypto_auth_hmacsha256_update(&st, t, t_len);
        if (info && info_len > 0)
            crypto_auth_hmacsha256_update(&st, info, info_len);
        crypto_auth_hmacsha256_update(&st, &counter, 1);
        crypto_auth_hmacsha256_final(&st, t);
        t_len = kHashLen;

        const size_t take = (out_len - produced < kHashLen)
                                ? (out_len - produced) : kHashLen;
        std::memcpy(out + produced, t, take);
        produced += take;
        ++counter;
    }
    sodium_memzero(prk, sizeof(prk));
    sodium_memzero(t, sizeof(t));
    return true;
}

// ==================== HeaderProtection ====================

HeaderProtection::HeaderProtection(std::vector<uint8_t> secret,
                                   std::string context)
    : context_(std::move(context)) {
    if (secret.empty())
        return;
    prk_.resize(kHashLen);
    if (!hkdf_sha256(secret.data(), secret.size(),
                     reinterpret_cast<const uint8_t*>(kHpSalt),
                     sizeof(kHpSalt) - 1,
                     nullptr, 0, prk_.data(), prk_.size())) {
        prk_.clear();
        return;
    }
    sodium_memzero(secret.data(), secret.size());
    enabled_ = true;
}

void HeaderProtection::prefix(uint64_t tag, uint8_t* out,
                              size_t out_len) const {
    if (!enabled_ || !out || out_len == 0 || out_len > kHashLen)
        return;
    // Single-block HKDF-Expand: T(1) = HMAC(PRK, info || 0x01),
    // info = context || tag_u64_BE.
    crypto_auth_hmacsha256_state st;
    if (crypto_auth_hmacsha256_init(&st, prk_.data(), prk_.size()) != 0)
        return;
    if (!context_.empty())
        crypto_auth_hmacsha256_update(
            &st, reinterpret_cast<const uint8_t*>(context_.data()),
            context_.size());
    uint8_t tag_be[8];
    store_u64_be_hp(tag_be, tag);
    crypto_auth_hmacsha256_update(&st, tag_be, sizeof(tag_be));
    const uint8_t one = 1;
    crypto_auth_hmacsha256_update(&st, &one, 1);
    uint8_t full[kHashLen];
    crypto_auth_hmacsha256_final(&st, full);
    std::memcpy(out, full, out_len);
    sodium_memzero(full, sizeof(full));
}

bool HeaderProtection::matches(uint64_t tag, const uint8_t* data,
                               size_t len) const {
    if (!enabled_ || !data || len == 0 || len > kHashLen)
        return false;
    uint8_t expected[kHashLen];
    prefix(tag, expected, len);
    return sodium_memcmp(expected, data, len) == 0;
}

void HeaderProtection::set_version_range(uint8_t min_v, uint8_t max_v) {
    if (min_v == 0) min_v = 1;
    if (max_v < min_v) max_v = min_v;
    ver_min_ = min_v;
    ver_max_ = max_v;
}

uint8_t HeaderProtection::random_version() const {
    if (ver_max_ <= ver_min_)
        return ver_min_;
    const uint32_t span = static_cast<uint32_t>(ver_max_) - ver_min_ + 1;
    return static_cast<uint8_t>(ver_min_ + randombytes_uniform(span));
}

std::optional<std::pair<uint8_t, uint8_t>>
HeaderProtection::parse_version_range(const std::string& spec) {
    if (spec.empty())
        return std::nullopt;
    const size_t dash = spec.find('-');
    try {
        if (dash == std::string::npos) {
            const int v = std::stoi(spec);
            if (v < 1 || v > 255) return std::nullopt;
            return std::make_pair(static_cast<uint8_t>(v),
                                  static_cast<uint8_t>(v));
        }
        const int lo = std::stoi(spec.substr(0, dash));
        const int hi = std::stoi(spec.substr(dash + 1));
        if (lo < 1 || hi > 255 || hi < lo) return std::nullopt;
        return std::make_pair(static_cast<uint8_t>(lo),
                              static_cast<uint8_t>(hi));
    } catch (...) {
        return std::nullopt;
    }
}

// ==================== Content padding ====================

std::optional<ContentPaddingConfig>
ContentPaddingConfig::parse(const std::string& spec) {
    if (spec.empty())
        return std::nullopt;
    constexpr int kCap = 1400;  // keep padded datagrams inside typical MTU
    const size_t dash = spec.find('-');
    try {
        ContentPaddingConfig cfg;
        if (dash == std::string::npos) {
            const int v = std::stoi(spec);
            if (v < 0) return std::nullopt;
            cfg.min_pad = cfg.max_pad =
                static_cast<uint16_t>(v > kCap ? kCap : v);
        } else {
            const int lo = std::stoi(spec.substr(0, dash));
            const int hi = std::stoi(spec.substr(dash + 1));
            if (lo < 0 || hi < lo) return std::nullopt;
            cfg.min_pad = static_cast<uint16_t>(lo > kCap ? kCap : lo);
            cfg.max_pad = static_cast<uint16_t>(hi > kCap ? kCap : hi);
        }
        return cfg;
    } catch (...) {
        return std::nullopt;
    }
}

uint16_t ContentPaddingConfig::sample() const {
    if (!enabled())
        return 0;
    if (max_pad <= min_pad)
        return min_pad;
    const uint32_t span = static_cast<uint32_t>(max_pad) - min_pad + 1;
    return static_cast<uint16_t>(min_pad + randombytes_uniform(span));
}

uint16_t content_pad_append(std::vector<uint8_t>& buf,
                            const ContentPaddingConfig& cfg,
                            size_t max_size) {
    if (!cfg.enabled())
        return 0;
    uint16_t pad_len = cfg.sample();
    if (pad_len > 255)
        pad_len = 255;  // length is stored in a single trailing byte
    // Need pad_len payload bytes + 1 length byte.
    while (pad_len > 0 && buf.size() + pad_len + 1 > max_size)
        --pad_len;
    if (pad_len == 0 && buf.size() + 1 > max_size)
        return 0;  // cannot even fit the length byte; leave unpadded
    if (pad_len > 0) {
        const size_t old = buf.size();
        buf.resize(old + pad_len);
        randombytes_buf(buf.data() + old, pad_len);
    }
    buf.push_back(static_cast<uint8_t>(pad_len));
    return pad_len;
}

std::optional<size_t> content_pad_strip(const uint8_t* buf, size_t buf_size) {
    if (!buf || buf_size < 1)
        return std::nullopt;
    const uint8_t pad_len = buf[buf_size - 1];
    if (static_cast<size_t>(pad_len) + 1 > buf_size)
        return std::nullopt;
    return buf_size - pad_len - 1;
}

} // namespace ncp
