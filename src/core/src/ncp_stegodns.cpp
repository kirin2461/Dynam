#include "ncp_stegodns.hpp"

#include <cstring>
#include <mutex>
#include <vector>

#include <sodium.h>

namespace ncp {

namespace {

// ===== One-time libsodium init =====
void ensure_sodium() {
    static std::once_flag flag;
    std::call_once(flag, [] { const int rc = sodium_init(); (void)rc; });
}

// ===== Constants =====
constexpr uint8_t kMagic0 = 'N';
constexpr uint8_t kMagic1 = 'D';
constexpr uint8_t kVersion = 1;
constexpr size_t  kPayloadLen = 2 + 1 + 4 + 2 + 32 + 4;  // 43 bytes

constexpr size_t kSigLen   = crypto_sign_BYTES;                       // 64
constexpr size_t kNonceLen = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;  // 24
constexpr size_t kCtLen = kPayloadLen +
                          crypto_aead_xchacha20poly1305_ietf_ABYTES;  // 59
constexpr size_t kBlobLen = kSigLen + kNonceLen + kCtLen;             // 147

constexpr char kSpfPrefix[]   = "v=spf1 ip4:";
constexpr char kSpfInfix[]    = " include:";
constexpr char kSpfNcpLabel[] = "._ncp.";
constexpr char kSpfSuffix[]   = " ~all";

// ===== base32 (RFC4648, lowercase, padding stripped) =====
constexpr char kB32Alphabet[] = "abcdefghijklmnopqrstuvwxyz234567";

std::string b32_encode(const uint8_t* data, size_t len) {
    std::string out;
    out.reserve((len * 8 + 4) / 5);
    uint32_t acc = 0;
    int bits = 0;
    for (size_t i = 0; i < len; ++i) {
        acc = (acc << 8) | data[i];
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            out.push_back(kB32Alphabet[(acc >> bits) & 31u]);
        }
    }
    if (bits > 0) {
        out.push_back(kB32Alphabet[(acc << (5 - bits)) & 31u]);
    }
    return out;
}

int b32_value(char c) {
    if (c >= 'a' && c <= 'z') return c - 'a';
    if (c >= '2' && c <= '7') return c - '2' + 26;
    return -1;
}

bool b32_decode(std::string_view s, std::vector<uint8_t>& out) {
    out.clear();
    out.reserve(s.size() * 5 / 8);
    uint32_t acc = 0;
    int bits = 0;
    for (char c : s) {
        const int v = b32_value(c);
        if (v < 0) return false;
        acc = (acc << 5) | static_cast<uint32_t>(v);
        bits += 5;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<uint8_t>((acc >> bits) & 0xFF));
        }
    }
    return true;
}

// ===== Key derivation: BLAKE2b(passphrase, 32), unkeyed =====
std::array<uint8_t, 32> derive_key(const std::string& passphrase) {
    ensure_sodium();
    std::array<uint8_t, 32> key{};
    crypto_generichash(key.data(), key.size(),
                       reinterpret_cast<const uint8_t*>(passphrase.data()),
                       passphrase.size(), nullptr, 0);
    return key;
}

// ===== Payload (de)serialization =====
std::array<uint8_t, kPayloadLen> serialize_payload(const NodeParams& p) {
    std::array<uint8_t, kPayloadLen> out{};
    size_t o = 0;
    out[o++] = kMagic0;
    out[o++] = kMagic1;
    out[o++] = kVersion;
    std::memcpy(out.data() + o, p.ipv4.data(), 4);
    o += 4;
    out[o++] = static_cast<uint8_t>((p.port >> 8) & 0xFF);
    out[o++] = static_cast<uint8_t>(p.port & 0xFF);
    std::memcpy(out.data() + o, p.spa_pubkey.data(), 32);
    o += 32;
    for (int i = 3; i >= 0; --i) {
        out[o++] = static_cast<uint8_t>((p.expires_unix >> (i * 8)) & 0xFF);
    }
    return out;
}

bool deserialize_payload(const uint8_t* d, size_t len, NodeParams& out) {
    if (len != kPayloadLen) return false;
    if (d[0] != kMagic0 || d[1] != kMagic1) return false;
    if (d[2] != kVersion) return false;
    size_t o = 3;
    std::memcpy(out.ipv4.data(), d + o, 4);
    o += 4;
    out.port = static_cast<uint16_t>((d[o] << 8) | d[o + 1]);
    o += 2;
    std::memcpy(out.spa_pubkey.data(), d + o, 32);
    o += 32;
    out.expires_unix = (static_cast<uint32_t>(d[o]) << 24) |
                       (static_cast<uint32_t>(d[o + 1]) << 16) |
                       (static_cast<uint32_t>(d[o + 2]) << 8) |
                       static_cast<uint32_t>(d[o + 3]);
    return true;
}

} // anonymous namespace

// ===== StegoDnsEncoder =====

StegoDnsEncoder::StegoDnsEncoder(
    const std::string& master_passphrase,
    const std::array<uint8_t, 64>& signing_secret_key)
    : enc_key_(derive_key(master_passphrase)), sign_sk_(signing_secret_key) {
    ensure_sodium();
}

std::string StegoDnsEncoder::encode_txt(const NodeParams& params,
                                        const std::string& domain) const {
    std::array<uint8_t, kNonceLen> nonce{};
    randombytes_buf(nonce.data(), nonce.size());
    return encode_txt(params, domain, nonce);
}

std::string StegoDnsEncoder::encode_txt(
    const NodeParams& params,
    const std::string& domain,
    const std::array<uint8_t, 24>& fixed_nonce) const {
    ensure_sodium();

    // 1. Encrypt payload.
    const auto payload = serialize_payload(params);
    std::array<uint8_t, kCtLen> ct{};
    unsigned long long ct_len = 0;
    crypto_aead_xchacha20poly1305_ietf_encrypt(
        ct.data(), &ct_len, payload.data(), payload.size(),
        nullptr, 0, nullptr, fixed_nonce.data(), enc_key_.data());

    // 2. Sign nonce || ciphertext.
    std::array<uint8_t, kNonceLen + kCtLen> signed_msg{};
    std::memcpy(signed_msg.data(), fixed_nonce.data(), kNonceLen);
    std::memcpy(signed_msg.data() + kNonceLen, ct.data(), kCtLen);
    std::array<uint8_t, kSigLen> sig{};
    crypto_sign_detached(sig.data(), nullptr, signed_msg.data(),
                         signed_msg.size(), sign_sk_.data());

    // 3. blob = sig || nonce || ciphertext.
    std::array<uint8_t, kBlobLen> blob{};
    std::memcpy(blob.data(), sig.data(), kSigLen);
    std::memcpy(blob.data() + kSigLen, fixed_nonce.data(), kNonceLen);
    std::memcpy(blob.data() + kSigLen + kNonceLen, ct.data(), kCtLen);

    // 4. base32 and split 60/40 across the two SPF slots.
    const std::string b32 = b32_encode(blob.data(), blob.size());
    const size_t part1_len = (b32.size() * 3) / 5;
    const std::string part1 = b32.substr(0, part1_len);
    const std::string part2 = b32.substr(part1_len);

    std::string out;
    out.reserve(sizeof(kSpfPrefix) + part1.size() + sizeof(kSpfInfix) +
                part2.size() + sizeof(kSpfNcpLabel) + domain.size() +
                sizeof(kSpfSuffix));
    out += kSpfPrefix;
    out += part1;
    out += kSpfInfix;
    out += part2;
    out += kSpfNcpLabel;
    out += domain;
    out += kSpfSuffix;
    return out;
}

// ===== StegoDnsDecoder =====

StegoDnsDecoder::StegoDnsDecoder(
    const std::string& master_passphrase,
    const std::array<uint8_t, 32>& verify_pubkey)
    : enc_key_(derive_key(master_passphrase)), verify_pk_(verify_pubkey) {
    ensure_sodium();
}

std::optional<NodeParams> StegoDnsDecoder::decode_txt(std::string_view txt,
                                                      uint64_t now) const {
    ensure_sodium();

    // 1. Validate the SPF envelope shape.
    constexpr size_t kPrefixLen = sizeof(kSpfPrefix) - 1;
    constexpr size_t kInfixLen = sizeof(kSpfInfix) - 1;
    constexpr size_t kNcpLen = sizeof(kSpfNcpLabel) - 1;
    constexpr size_t kSuffixLen = sizeof(kSpfSuffix) - 1;

    if (txt.size() <= kPrefixLen + kSuffixLen) return std::nullopt;
    if (txt.compare(0, kPrefixLen, kSpfPrefix) != 0) return std::nullopt;
    if (txt.compare(txt.size() - kSuffixLen, kSuffixLen, kSpfSuffix) != 0) {
        return std::nullopt;
    }

    const size_t part1_begin = kPrefixLen;
    const size_t infix_pos = txt.find(kSpfInfix, part1_begin);
    if (infix_pos == std::string_view::npos) return std::nullopt;
    const std::string_view part1 =
        txt.substr(part1_begin, infix_pos - part1_begin);
    if (part1.empty()) return std::nullopt;

    const size_t part2_begin = infix_pos + kInfixLen;
    const size_t ncp_pos = txt.find(kSpfNcpLabel, part2_begin);
    if (ncp_pos == std::string_view::npos || ncp_pos == part2_begin) {
        return std::nullopt;
    }
    const std::string_view part2 =
        txt.substr(part2_begin, ncp_pos - part2_begin);
    const std::string_view domain =
        txt.substr(ncp_pos + kNcpLen, txt.size() - kSuffixLen -
                                          (ncp_pos + kNcpLen));
    if (domain.empty()) return std::nullopt;

    // Both slots and the domain must use their allowed character sets.
    for (char c : part1) {
        if (b32_value(c) < 0) return std::nullopt;
    }
    for (char c : part2) {
        if (b32_value(c) < 0) return std::nullopt;
    }
    for (char c : domain) {
        const bool ok = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
                        c == '.' || c == '-';
        if (!ok) return std::nullopt;
    }

    // 2. Reassemble and decode the blob.
    std::string b32;
    b32.reserve(part1.size() + part2.size());
    b32.append(part1);
    b32.append(part2);
    std::vector<uint8_t> blob;
    if (!b32_decode(b32, blob)) return std::nullopt;
    if (blob.size() != kBlobLen) return std::nullopt;

    const uint8_t* sig = blob.data();
    const uint8_t* nonce = blob.data() + kSigLen;
    const uint8_t* ct = blob.data() + kSigLen + kNonceLen;

    // 3. Verify the publisher signature over nonce || ciphertext.
    if (crypto_sign_verify_detached(sig, nonce, kNonceLen + kCtLen,
                                    verify_pk_.data()) != 0) {
        return std::nullopt;
    }

    // 4. Decrypt.
    std::array<uint8_t, kPayloadLen> payload{};
    unsigned long long payload_len = 0;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            payload.data(), &payload_len, nullptr, ct, kCtLen, nullptr, 0,
            nonce, enc_key_.data()) != 0) {
        return std::nullopt;
    }
    if (payload_len != kPayloadLen) return std::nullopt;

    // 5. Parse and check expiry (0 = never expires).
    NodeParams params;
    if (!deserialize_payload(payload.data(), payload.size(), params)) {
        return std::nullopt;
    }
    if (params.expires_unix != 0 &&
        static_cast<uint64_t>(params.expires_unix) <= now) {
        return std::nullopt;
    }
    return params;
}

} // namespace ncp
