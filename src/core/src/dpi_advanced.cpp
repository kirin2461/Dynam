#include "../include/ncp_dpi_advanced.hpp"
#include "../include/ncp_dpi.hpp"
#include "../include/ncp_ech.hpp"
#include "../include/ncp_tls_fingerprint.hpp"
#include "../include/ncp_csprng.hpp"
#include <sodium.h>
#include <thread>
#include <mutex>
#include <atomic>
#include <algorithm>
#include <cstring>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <set>
#include <chrono>

namespace ncp {
namespace DPI {

// ==================== Helper Functions ====================

namespace {

inline uint32_t secure_random(uint32_t max) {
    return randombytes_uniform(max);
}

inline std::vector<uint8_t> random_bytes(size_t count) {
    std::vector<uint8_t> result(count);
    randombytes_buf(result.data(), count);
    return result;
}

static const std::vector<uint16_t> GREASE_VALUES = {
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a,
    0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
    0xcaca, 0xdada, 0xeaea, 0xfafa
};

inline uint16_t get_random_grease() {
    return GREASE_VALUES[secure_random(static_cast<uint32_t>(GREASE_VALUES.size()))];
}

} // anonymous namespace

// ==================== TCPManipulator Implementation ====================

struct TCPManipulator::Impl {
};

TCPManipulator::TCPManipulator() : impl_(std::make_unique<Impl>()) {}
TCPManipulator::~TCPManipulator() = default;

std::vector<std::vector<uint8_t>> TCPManipulator::split_segments(
    const uint8_t* data, size_t len, const std::vector<size_t>& split_points) {
    std::vector<std::vector<uint8_t>> segments;
    if (!data || len == 0) return segments;
    std::vector<size_t> valid_points;
    for (auto pt : split_points) {
        if (pt > 0 && pt < len) valid_points.push_back(pt);
    }
    std::sort(valid_points.begin(), valid_points.end());
    valid_points.erase(std::unique(valid_points.begin(), valid_points.end()), valid_points.end());
    size_t prev = 0;
    for (size_t pt : valid_points) {
        segments.emplace_back(data + prev, data + pt);
        prev = pt;
    }
    if (prev < len) segments.emplace_back(data + prev, data + len);
    return segments;
}

std::vector<std::vector<uint8_t>> TCPManipulator::create_overlap(
    const uint8_t* data, size_t len, size_t overlap_size) {
    std::vector<std::vector<uint8_t>> segments;
    if (!data || len == 0 || overlap_size == 0) {
        if (data && len > 0) segments.emplace_back(data, data + len);
        return segments;
    }
    size_t segment_size = std::max<size_t>(overlap_size * 2, 16);
    size_t offset = 0;
    while (offset < len) {
        size_t end = std::min(offset + segment_size, len);
        segments.emplace_back(data + offset, data + end);
        if (end < len) {
            size_t overlap_start = end - std::min(overlap_size, end - offset);
            segments.emplace_back(data + overlap_start, data + end);
        }
        offset = end;
    }
    return segments;
}

std::vector<uint8_t> TCPManipulator::add_oob_marker(
    const uint8_t* data, size_t len, size_t urgent_position) {
    std::vector<uint8_t> result(data, data + len);
    if (urgent_position < len) result.insert(result.begin() + urgent_position, 0x00);
    return result;
}

void TCPManipulator::shuffle_segments(
    std::vector<std::vector<uint8_t>>& segments, void*) {
    if (segments.size() <= 1) return;
    for (size_t i = segments.size() - 1; i > 0; --i) {
        uint32_t j = secure_random(static_cast<uint32_t>(i + 1));
        std::swap(segments[i], segments[j]);
    }
}

// ==================== TLSManipulator Implementation ====================

struct TLSManipulator::Impl {
    // Internal default fingerprint (used when no external fp is set)
    ncp::TLSFingerprint tls_fp_;
    // External fingerprint pointer (not owned, caller keeps alive)
    ncp::TLSFingerprint* external_fp_ = nullptr;

    Impl() : tls_fp_(ncp::BrowserType::CHROME) {}

    // Returns the active fingerprint: external if set, otherwise internal
    ncp::TLSFingerprint& active_fp() {
        return external_fp_ ? *external_fp_ : tls_fp_;
    }

    static int find_sni_offset(const uint8_t* data, size_t len);
};

TLSManipulator::TLSManipulator() : impl_(std::make_unique<Impl>()) {}
TLSManipulator::~TLSManipulator() = default;

void TLSManipulator::set_tls_fingerprint(ncp::TLSFingerprint* fp) {
    impl_->external_fp_ = fp;
}

std::vector<uint8_t> TLSManipulator::create_fingerprinted_client_hello(
    const std::string& sni) {
    // Use external fingerprint's current profile (don't randomize — caller controls profile)
    auto& fp = impl_->active_fp();
    fp.set_sni(sni);

    auto ciphers     = fp.get_cipher_suites();
    auto extensions  = fp.get_extensions();
    auto alpn_protos = fp.get_alpn();

    std::vector<uint8_t> hello;
    hello.reserve(512);

    // === TLS Record Header ===
    hello.push_back(0x16);
    hello.push_back(0x03); hello.push_back(0x01);
    size_t rec_len_pos = hello.size();
    hello.push_back(0x00); hello.push_back(0x00);

    // === Handshake Header ===
    hello.push_back(0x01);
    size_t hs_len_pos = hello.size();
    hello.push_back(0x00); hello.push_back(0x00); hello.push_back(0x00);

    // === ClientHello Body ===
    hello.push_back(0x03); hello.push_back(0x03);

    auto rnd = ncp::csprng_bytes(32);
    hello.insert(hello.end(), rnd.begin(), rnd.end());

    hello.push_back(32);
    auto sid = ncp::csprng_bytes(32);
    hello.insert(hello.end(), sid.begin(), sid.end());

    // === Cipher Suites ===
    uint16_t cs_len = static_cast<uint16_t>(ciphers.size() * 2);
    hello.push_back(static_cast<uint8_t>((cs_len >> 8) & 0xFF));
    hello.push_back(static_cast<uint8_t>(cs_len & 0xFF));
    for (uint16_t cs : ciphers) {
        hello.push_back(static_cast<uint8_t>((cs >> 8) & 0xFF));
        hello.push_back(static_cast<uint8_t>(cs & 0xFF));
    }

    // === Compression Methods ===
    hello.push_back(0x01); hello.push_back(0x00);

    // === Extensions ===
    size_t ext_len_pos = hello.size();
    hello.push_back(0x00); hello.push_back(0x00);

    auto append_ext = [&](uint16_t type, const std::vector<uint8_t>& d) {
        hello.push_back(static_cast<uint8_t>((type >> 8) & 0xFF));
        hello.push_back(static_cast<uint8_t>(type & 0xFF));
        uint16_t l = static_cast<uint16_t>(d.size());
        hello.push_back(static_cast<uint8_t>((l >> 8) & 0xFF));
        hello.push_back(static_cast<uint8_t>(l & 0xFF));
        hello.insert(hello.end(), d.begin(), d.end());
    };

    for (uint16_t ext_id : extensions) {
        switch (ext_id) {
        case 0: { // server_name
            std::vector<uint8_t> sni_data;
            uint16_t list_l = static_cast<uint16_t>(sni.size() + 3);
            sni_data.push_back(static_cast<uint8_t>((list_l >> 8) & 0xFF));
            sni_data.push_back(static_cast<uint8_t>(list_l & 0xFF));
            sni_data.push_back(0x00);
            uint16_t nm_l = static_cast<uint16_t>(sni.size());
            sni_data.push_back(static_cast<uint8_t>((nm_l >> 8) & 0xFF));
            sni_data.push_back(static_cast<uint8_t>(nm_l & 0xFF));
            sni_data.insert(sni_data.end(), sni.begin(), sni.end());
            append_ext(0, sni_data);
            break;
        }
        case 10: { // supported_groups
            auto ja3 = fp.generate_ja3();
            auto& curves = ja3.elliptic_curves;
            std::vector<uint8_t> gd;
            uint16_t gl = static_cast<uint16_t>(curves.size() * 2);
            gd.push_back(static_cast<uint8_t>((gl >> 8) & 0xFF));
            gd.push_back(static_cast<uint8_t>(gl & 0xFF));
            for (uint16_t g : curves) {
                gd.push_back(static_cast<uint8_t>((g >> 8) & 0xFF));
                gd.push_back(static_cast<uint8_t>(g & 0xFF));
            }
            append_ext(10, gd);
            break;
        }
        case 11: append_ext(11, {0x01, 0x00}); break;
        case 13: {
            std::vector<uint16_t> sa = {
                0x0403, 0x0503, 0x0603, 0x0807, 0x0808,
                0x0809, 0x080A, 0x080B, 0x0401, 0x0501, 0x0601, 0x0203, 0x0201
            };
            std::vector<uint8_t> sd;
            uint16_t sl = static_cast<uint16_t>(sa.size() * 2);
            sd.push_back(static_cast<uint8_t>((sl >> 8) & 0xFF));
            sd.push_back(static_cast<uint8_t>(sl & 0xFF));
            for (uint16_t s : sa) {
                sd.push_back(static_cast<uint8_t>((s >> 8) & 0xFF));
                sd.push_back(static_cast<uint8_t>(s & 0xFF));
            }
            append_ext(13, sd);
            break;
        }
        case 16: {
            std::vector<uint8_t> al;
            std::vector<uint8_t> alist;
            for (const auto& p : alpn_protos) {
                alist.push_back(static_cast<uint8_t>(p.size()));
                alist.insert(alist.end(), p.begin(), p.end());
            }
            uint16_t all = static_cast<uint16_t>(alist.size());
            al.push_back(static_cast<uint8_t>((all >> 8) & 0xFF));
            al.push_back(static_cast<uint8_t>(all & 0xFF));
            al.insert(al.end(), alist.begin(), alist.end());
            append_ext(16, al);
            break;
        }
        case 43: {
            std::vector<uint8_t> sv;
            sv.push_back(0x04);
            sv.push_back(0x03); sv.push_back(0x04);
            sv.push_back(0x03); sv.push_back(0x03);
            append_ext(43, sv);
            break;
        }
        case 45: append_ext(45, {0x01, 0x01}); break;
        case 51: {
            uint8_t pk[32], sk[32];
            crypto_box_keypair(pk, sk);
            sodium_memzero(sk, sizeof(sk));
            std::vector<uint8_t> ks;
            uint16_t ksl = 2 + 2 + 32;
            ks.push_back(static_cast<uint8_t>((ksl >> 8) & 0xFF));
            ks.push_back(static_cast<uint8_t>(ksl & 0xFF));
            ks.push_back(0x00); ks.push_back(0x1D);
            ks.push_back(0x00); ks.push_back(0x20);
            ks.insert(ks.end(), pk, pk + 32);
            append_ext(51, ks);
            break;
        }
        default:
            if ((ext_id & 0x0F0F) == 0x0A0A) {
                append_ext(ext_id, {static_cast<uint8_t>(ncp::csprng_uniform(256))});
            } else {
                append_ext(ext_id, {});
            }
            break;
        }
    }

    // === Fill lengths ===
    uint16_t el = static_cast<uint16_t>(hello.size() - ext_len_pos - 2);
    hello[ext_len_pos]     = static_cast<uint8_t>((el >> 8) & 0xFF);
    hello[ext_len_pos + 1] = static_cast<uint8_t>(el & 0xFF);

    uint32_t hl = static_cast<uint32_t>(hello.size() - hs_len_pos - 3);
    hello[hs_len_pos]     = static_cast<uint8_t>((hl >> 16) & 0xFF);
    hello[hs_len_pos + 1] = static_cast<uint8_t>((hl >> 8) & 0xFF);
    hello[hs_len_pos + 2] = static_cast<uint8_t>(hl & 0xFF);

    uint16_t rl = static_cast<uint16_t>(hello.size() - 5);
    hello[rec_len_pos]     = static_cast<uint8_t>((rl >> 8) & 0xFF);
    hello[rec_len_pos + 1] = static_cast<uint8_t>(rl & 0xFF);

    return hello;
}

int TLSManipulator::Impl::find_sni_offset(const uint8_t* data, size_t len) {
    if (!data || len < 5 + 4) return -1;
    if (data[0] != 0x16 || data[1] != 0x03) return -1;
    size_t pos = 5;
    if (pos + 4 > len) return -1;
    if (data[pos] != 0x01) return -1;
    pos += 4;
    if (pos + 2 + 32 + 1 > len) return -1;
    pos += 2 + 32;
    uint8_t session_id_len = data[pos++];
    if (pos + session_id_len > len) return -1;
    pos += session_id_len;
    if (pos + 2 > len) return -1;
    uint16_t cipher_suites_len = (data[pos] << 8) | data[pos + 1];
    pos += 2;
    if (pos + cipher_suites_len > len) return -1;
    pos += cipher_suites_len;
    if (pos + 1 > len) return -1;
    uint8_t compression_len = data[pos++];
    if (pos + compression_len > len) return -1;
    pos += compression_len;
    if (pos + 2 > len) return -1;
    uint16_t extensions_len = (data[pos] << 8) | data[pos + 1];
    pos += 2;
    size_t exts_end = std::min(pos + extensions_len, len);
    while (pos + 4 <= exts_end) {
        uint16_t ext_type = (data[pos] << 8) | data[pos + 1];
        uint16_t ext_len = (data[pos + 2] << 8) | data[pos + 3];
        pos += 4;
        if (pos + ext_len > exts_end) break;
        if (ext_type == 0x0000) {
            if (pos + 2 > exts_end) return -1;
            uint16_t list_len = (data[pos] << 8) | data[pos + 1];
            pos += 2;
            if (pos + list_len > exts_end || list_len < 3) return -1;
            pos += 1;
            if (pos + 2 > exts_end) return -1;
            uint16_t hostname_len = (data[pos] << 8) | data[pos + 1];
            pos += 2;
            if (pos + hostname_len > exts_end) return -1;
            return static_cast<int>(pos);
        }
        pos += ext_len;
    }
    return -1;
}

std::vector<size_t> TLSManipulator::find_sni_split_points(
    const uint8_t* data, size_t len) {
    std::vector<size_t> split_points;
    int sni_offset = Impl::find_sni_offset(data, len);
    if (sni_offset > 0) {
        size_t sni_pos = static_cast<size_t>(sni_offset);
        split_points.push_back(sni_pos);
        if (sni_pos + 4 < len) split_points.push_back(sni_pos + 2);
    } else {
        if (len > 40) split_points.push_back(40);
    }
    return split_points;
}

std::vector<std::vector<uint8_t>> TLSManipulator::split_tls_record(
    const uint8_t* data, size_t len, size_t max_fragment_size) {
    std::vector<std::vector<uint8_t>> fragments;
    if (!data || len == 0) return fragments;
    size_t offset = 0;
    while (offset < len) {
        size_t chunk_size = std::min(max_fragment_size, len - offset);
        fragments.emplace_back(data + offset, data + offset + chunk_size);
        offset += chunk_size;
    }
    return fragments;
}

std::vector<uint8_t> TLSManipulator::add_tls_padding(
    const uint8_t* data, size_t len, size_t padding_size) {
    if (!data || len == 0) return {};
    std::vector<uint8_t> result(data, data + len);
    auto padding = random_bytes(padding_size);
    result.insert(result.end(), padding.begin(), padding.end());
    return result;
}

std::vector<uint8_t> TLSManipulator::inject_grease(
    const uint8_t* data, size_t len) {
    if (!data || len < 10) return std::vector<uint8_t>(data, data + len);
    std::vector<uint8_t> result(data, data + len);
    size_t inject_pos = 5 + secure_random(std::min(static_cast<uint32_t>(20), static_cast<uint32_t>(len - 5)));
    if (inject_pos + 2 < result.size()) {
        uint16_t grease = get_random_grease();
        result[inject_pos] = (grease >> 8) & 0xFF;
        result[inject_pos + 1] = grease & 0xFF;
    }
    return result;
}

// =====================================================================
// Phase 2: TLSFingerprint-driven ClientHello generation
// create_fake_client_hello — randomizes browser profile per call (decoy)
// create_fingerprinted_client_hello — uses caller-controlled profile
// =====================================================================

std::vector<uint8_t> TLSManipulator::create_fake_client_hello(
    const std::string& fake_sni) {

    auto& fp = impl_->active_fp();

    // For decoy hellos: randomize profile to avoid fingerprint correlation
    // (only when using internal fp — external fp is caller-controlled)
    if (!impl_->external_fp_) {
        static const ncp::BrowserType profiles[] = {
            ncp::BrowserType::CHROME, ncp::BrowserType::FIREFOX,
            ncp::BrowserType::SAFARI, ncp::BrowserType::EDGE
        };
        fp.set_profile(profiles[ncp::csprng_uniform(4)]);
    }
    fp.set_sni(fake_sni);

    auto ciphers    = fp.get_cipher_suites();
    auto extensions = fp.get_extensions();
    auto alpn_protos = fp.get_alpn();

    std::vector<uint8_t> hello;
    hello.reserve(512);

    // === TLS Record Header ===
    hello.push_back(0x16);
    hello.push_back(0x03); hello.push_back(0x01);
    size_t rec_len_pos = hello.size();
    hello.push_back(0x00); hello.push_back(0x00);

    // === Handshake Header ===
    hello.push_back(0x01);
    size_t hs_len_pos = hello.size();
    hello.push_back(0x00); hello.push_back(0x00); hello.push_back(0x00);

    // === ClientHello Body ===
    hello.push_back(0x03); hello.push_back(0x03);

    auto rnd = ncp::csprng_bytes(32);
    hello.insert(hello.end(), rnd.begin(), rnd.end());

    // Session ID (32 bytes — TLS 1.3 middlebox compat)
    hello.push_back(32);
    auto sid = ncp::csprng_bytes(32);
    hello.insert(hello.end(), sid.begin(), sid.end());

    // === Cipher Suites ===
    uint16_t cs_len = static_cast<uint16_t>(ciphers.size() * 2);
    hello.push_back(static_cast<uint8_t>((cs_len >> 8) & 0xFF));
    hello.push_back(static_cast<uint8_t>(cs_len & 0xFF));
    for (uint16_t cs : ciphers) {
        hello.push_back(static_cast<uint8_t>((cs >> 8) & 0xFF));
        hello.push_back(static_cast<uint8_t>(cs & 0xFF));
    }

    // === Compression Methods ===
    hello.push_back(0x01); hello.push_back(0x00);

    // === Extensions ===
    size_t ext_len_pos = hello.size();
    hello.push_back(0x00); hello.push_back(0x00);

    auto append_ext = [&](uint16_t type, const std::vector<uint8_t>& d) {
        hello.push_back(static_cast<uint8_t>((type >> 8) & 0xFF));
        hello.push_back(static_cast<uint8_t>(type & 0xFF));
        uint16_t l = static_cast<uint16_t>(d.size());
        hello.push_back(static_cast<uint8_t>((l >> 8) & 0xFF));
        hello.push_back(static_cast<uint8_t>(l & 0xFF));
        hello.insert(hello.end(), d.begin(), d.end());
    };

    for (uint16_t ext_id : extensions) {
        switch (ext_id) {
        case 0: {
            std::vector<uint8_t> sni;
            uint16_t list_l = static_cast<uint16_t>(fake_sni.size() + 3);
            sni.push_back(static_cast<uint8_t>((list_l >> 8) & 0xFF));
            sni.push_back(static_cast<uint8_t>(list_l & 0xFF));
            sni.push_back(0x00);
            uint16_t nm_l = static_cast<uint16_t>(fake_sni.size());
            sni.push_back(static_cast<uint8_t>((nm_l >> 8) & 0xFF));
            sni.push_back(static_cast<uint8_t>(nm_l & 0xFF));
            sni.insert(sni.end(), fake_sni.begin(), fake_sni.end());
            append_ext(0, sni);
            break;
        }
        case 10: {
            auto ja3 = fp.generate_ja3();
            auto& curves = ja3.elliptic_curves;
            std::vector<uint8_t> gd;
            uint16_t gl = static_cast<uint16_t>(curves.size() * 2);
            gd.push_back(static_cast<uint8_t>((gl >> 8) & 0xFF));
            gd.push_back(static_cast<uint8_t>(gl & 0xFF));
            for (uint16_t g : curves) {
                gd.push_back(static_cast<uint8_t>((g >> 8) & 0xFF));
                gd.push_back(static_cast<uint8_t>(g & 0xFF));
            }
            append_ext(10, gd);
            break;
        }
        case 11: append_ext(11, {0x01, 0x00}); break;
        case 13: {
            std::vector<uint16_t> sa = {
                0x0403, 0x0503, 0x0603, 0x0807, 0x0808,
                0x0809, 0x080A, 0x080B, 0x0401, 0x0501, 0x0601, 0x0203, 0x0201
            };
            std::vector<uint8_t> sd;
            uint16_t sl = static_cast<uint16_t>(sa.size() * 2);
            sd.push_back(static_cast<uint8_t>((sl >> 8) & 0xFF));
            sd.push_back(static_cast<uint8_t>(sl & 0xFF));
            for (uint16_t s : sa) {
                sd.push_back(static_cast<uint8_t>((s >> 8) & 0xFF));
                sd.push_back(static_cast<uint8_t>(s & 0xFF));
            }
            append_ext(13, sd);
            break;
        }
        case 16: {
            std::vector<uint8_t> al;
            std::vector<uint8_t> alist;
            for (const auto& p : alpn_protos) {
                alist.push_back(static_cast<uint8_t>(p.size()));
                alist.insert(alist.end(), p.begin(), p.end());
            }
            uint16_t all = static_cast<uint16_t>(alist.size());
            al.push_back(static_cast<uint8_t>((all >> 8) & 0xFF));
            al.push_back(static_cast<uint8_t>(al all & 0xFF));
            al.insert(al.end(), alist.begin(), alist.end());
            append_ext(16, al);
            break;
        }
        case 43: {
            std::vector<uint8_t> sv;
            sv.push_back(0x04);
            sv.push_back(0x03); sv.push_back(0x04);
            sv.push_back(0x03); sv.push_back(0x03);
            append_ext(43, sv);
            break;
        }
        case 45: append_ext(45, {0x01, 0x01}); break;
        case 51: {
            uint8_t pk[32], sk[32];
            crypto_box_keypair(pk, sk);
            sodium_memzero(sk, sizeof(sk));
            std::vector<uint8_t> ks;
            uint16_t ksl = 2 + 2 + 32;
            ks.push_back(static_cast<uint8_t>((ksl >> 8) & 0xFF));
            ks.push_back(static_cast<uint8_t>(ksl & 0xFF));
            ks.push_back(0x00); ks.push_back(0x1D);
            ks.push_back(0x00); ks.push_back(0x20);
            ks.insert(ks.end(), pk, pk + 32);
            append_ext(51, ks);
            break;
        }
        default:
            if ((ext_id & 0x0F0F) == 0x0A0A) {
                append_ext(ext_id, {static_cast<uint8_t>(ncp::csprng_uniform(256))});
            } else {
                append_ext(ext_id, {});
            }
            break;
        }
    }

    // === Fill lengths ===
    uint16_t el = static_cast<uint16_t>(hello.size() - ext_len_pos - 2);
    hello[ext_len_pos]     = static_cast<uint8_t>((el >> 8) & 0xFF);
    hello[ext_len_pos + 1] = static_cast<uint8_t>(el & 0xFF);

    uint32_t hl = static_cast<uint32_t>(hello.size() - hs_len_pos - 3);
    hello[hs_len_pos]     = static_cast<uint8_t>((hl >> 16) & 0xFF);
    hello[hs_len_pos + 1] = static_cast<uint8_t>((hl >> 8) & 0xFF);
    hello[hs_len_pos + 2] = static_cast<uint8_t>(hl & 0xFF);

    uint16_t rl = static_cast<uint16_t>(hello.size() - 5);
    hello[rec_len_pos]     = static_cast<uint8_t>((rl >> 8) & 0xFF);
    hello[rec_len_pos + 1] = static_cast<uint8_t>(rl & 0xFF);

    return hello;
}

// ==================== TrafficObfuscator Implementation ====================

struct TrafficObfuscator::Impl {
    ObfuscationMode mode;
    std::vector<uint8_t> key;
    size_t xor_offset = 0;
    Impl(ObfuscationMode m, const std::vector<uint8_t>& k) : mode(m), key(k) {
        if (key.empty()) {
            key.resize(crypto_stream_chacha20_KEYBYTES);
            randombytes_buf(key.data(), key.size());
        }
    }
};

TrafficObfuscator::TrafficObfuscator(ObfuscationMode mode, const std::vector<uint8_t>& key)
    : impl_(std::make_unique<Impl>(mode, key)) {}
TrafficObfuscator::~TrafficObfuscator() = default;

std::vector<uint8_t> TrafficObfuscator::obfuscate(const uint8_t* data, size_t len) {
    if (!data || len == 0) return {};
    std::vector<uint8_t> result;
    switch (impl_->mode) {
    case ObfuscationMode::XOR_SIMPLE: {
        result.resize(len);
        for (size_t i = 0; i < len; ++i)
            result[i] = data[i] ^ impl_->key[i % impl_->key.size()];
        break;
    }
    case ObfuscationMode::XOR_ROLLING: {
        result.resize(len);
        for (size_t i = 0; i < len; ++i) {
            size_t ki = (impl_->xor_offset + i) % impl_->key.size();
            result[i] = data[i] ^ impl_->key[ki];
        }
        impl_->xor_offset = (impl_->xor_offset + len) % impl_->key.size();
        break;
    }
    case ObfuscationMode::CHACHA20: {
        if (impl_->key.size() >= crypto_stream_chacha20_KEYBYTES) {
            uint8_t nonce[crypto_stream_chacha20_NONCEBYTES];
            randombytes_buf(nonce, sizeof(nonce));
            result.resize(sizeof(nonce) + len);
            std::copy(nonce, nonce + sizeof(nonce), result.begin());
            crypto_stream_chacha20_xor(result.data() + sizeof(nonce), data, len, nonce, impl_->key.data());
        } else {
            result.assign(data, data + len);
        }
        break;
    }
    case ObfuscationMode::HTTP_CAMOUFLAGE: {
        std::string hdr = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: "
                          + std::to_string(len) + "\r\n\r\n";
        result.reserve(hdr.size() + len);
        result.insert(result.end(), hdr.begin(), hdr.end());
        result.insert(result.end(), data, data + len);
        break;
    }
    default: result.assign(data, data + len); break;
    }
    return result;
}

std::vector<uint8_t> TrafficObfuscator::deobfuscate(const uint8_t* data, size_t len) {
    if (!data || len == 0) return {};
    switch (impl_->mode) {
    case ObfuscationMode::CHACHA20: {
        if (impl_->key.size() >= crypto_stream_chacha20_KEYBYTES && len > crypto_stream_chacha20_NONCEBYTES) {
            const uint8_t* nonce = data;
            const uint8_t* ct = data + crypto_stream_chacha20_NONCEBYTES;
            size_t ct_len = len - crypto_stream_chacha20_NONCEBYTES;
            std::vector<uint8_t> result(ct_len);
            crypto_stream_chacha20_xor(result.data(), ct, ct_len, nonce, impl_->key.data());
            return result;
        }
        return std::vector<uint8_t>(data, data + len);
    }
    case ObfuscationMode::HTTP_CAMOUFLAGE: {
        const char* he = "\r\n\r\n";
        auto it = std::search(data, data + len, he, he + 4);
        if (it != data + len) {
            size_t off = (it - data) + 4;
            return std::vector<uint8_t>(data + off, data + len);
        }
        return std::vector<uint8_t>(data, data + len);
    }
    default: return obfuscate(data, len);
    }
}

ObfuscationMode TrafficObfuscator::get_mode() const { return impl_->mode; }
void TrafficObfuscator::rotate_key() {
    randombytes_buf(impl_->key.data(), impl_->key.size());
    impl_->xor_offset = 0;
}

// ==================== AdvancedDPIBypass Implementation ====================

struct AdvancedDPIBypass::Impl {
    std::atomic<bool> running{false};
    AdvancedDPIConfig config;
    AdvancedDPIStats stats;
    std::unique_ptr<DPIBypass> base_bypass;
    std::unique_ptr<TCPManipulator> tcp_manip;
    std::unique_ptr<TLSManipulator> tls_manip;
    std::unique_ptr<TrafficObfuscator> obfuscator;
    std::function<void(const std::string&)> log_callback;
    mutable std::mutex stats_mutex;
    std::atomic<int> detection_counter{0};
    std::atomic<int> current_strategy{0};

    // Phase 3C: External TLS fingerprint (forwarded to tls_manip)
    ncp::TLSFingerprint* external_fp_ = nullptr;

    // Phase 3D: ECH config (parsed from ech_config_list in AdvancedDPIConfig)
    ECH::ECHConfig ech_config_;
    bool ech_config_valid_ = false;

    void log(const std::string& msg) { if (log_callback) log_callback(msg); }
};

AdvancedDPIBypass::AdvancedDPIBypass() : impl_(std::make_unique<Impl>()) {}
AdvancedDPIBypass::~AdvancedDPIBypass() { stop(); }

bool AdvancedDPIBypass::initialize(const AdvancedDPIConfig& config) {
    impl_->config = config;
    impl_->base_bypass = std::make_unique<DPIBypass>();
    if (!impl_->base_bypass->initialize(config.base_config)) {
        impl_->log("Failed to initialize base DPI bypass"); return false;
    }
    impl_->tcp_manip = std::make_unique<TCPManipulator>();
    impl_->tls_manip = std::make_unique<TLSManipulator>();

    // Forward external fingerprint to TLSManipulator if already set
    if (impl_->external_fp_) {
        impl_->tls_manip->set_tls_fingerprint(impl_->external_fp_);
    }

    // Phase 3D: Parse ECH config from config.ech_config_list
    if (config.enable_ech && !config.ech_config_list.empty()) {
        if (ECH::parse_ech_config(config.ech_config_list, impl_->ech_config_)) {
            impl_->ech_config_valid_ = true;
            impl_->log("ECH config loaded and validated");
        } else {
            impl_->log("Failed to parse ECH config from ech_config_list");
        }
    }

    if (config.obfuscation != ObfuscationMode::NONE) {
        impl_->obfuscator = std::make_unique<TrafficObfuscator>(config.obfuscation, config.obfuscation_key);
    }
    impl_->log("Advanced DPI bypass initialized with " + std::to_string(config.techniques.size()) + " techniques");
    return true;
}

void AdvancedDPIBypass::set_tls_fingerprint(ncp::TLSFingerprint* fp) {
    impl_->external_fp_ = fp;
    // Forward to TLSManipulator if already created
    if (impl_->tls_manip) {
        impl_->tls_manip->set_tls_fingerprint(fp);
    }
    impl_->log("TLS fingerprint " + std::string(fp ? "set" : "cleared") +
               " on advanced bypass pipeline");
}

void AdvancedDPIBypass::set_ech_config(const std::vector<uint8_t>& config_list) {
    if (ECH::parse_ech_config(config_list, impl_->ech_config_)) {
        impl_->ech_config_valid_ = true;
        impl_->config.enable_ech = true;
        impl_->log("ECH config updated and validated");
    } else {
        impl_->ech_config_valid_ = false;
        impl_->log("Failed to parse ECH config in set_ech_config()");
    }
}

bool AdvancedDPIBypass::start() {
    if (!impl_->base_bypass) { impl_->log("Base bypass not initialized"); return false; }
    impl_->running = true;
    if (!impl_->base_bypass->start()) { impl_->log("Failed to start base DPI bypass"); impl_->running = false; return false; }
    impl_->log("Advanced DPI bypass started"); return true;
}

void AdvancedDPIBypass::stop() {
    impl_->running = false;
    if (impl_->base_bypass) impl_->base_bypass->stop();
    impl_->log("Advanced DPI bypass stopped");
}

bool AdvancedDPIBypass::is_running() const { return impl_->running; }

AdvancedDPIStats AdvancedDPIBypass::get_stats() const {
    std::lock_guard<std::mutex> lock(impl_->stats_mutex);
    AdvancedDPIStats stats = impl_->stats;
    if (impl_->base_bypass) stats.base_stats = impl_->base_bypass->get_stats();
    return stats;
}

std::vector<std::vector<uint8_t>> AdvancedDPIBypass::process_outgoing(
    const uint8_t* data, size_t len) {
    if (!data || len == 0) return {};
    std::vector<std::vector<uint8_t>> result;
    std::vector<uint8_t> working_data(data, data + len);
    const auto& cfg = impl_->config;
    bool is_client_hello = (len > 5 && data[0] == 0x16 && data[1] == 0x03 && data[5] == 0x01);

    // === Phase 2.2: GREASE injection (before ECH, before splits) ===
    if (cfg.base_config.enable_pattern_obfuscation && is_client_hello) {
        working_data = impl_->tls_manip->inject_grease(working_data.data(), working_data.size());
        std::lock_guard<std::mutex> lock(impl_->stats_mutex);
        impl_->stats.grease_injected++;
    }

    // === Phase 3D: ECH application (after GREASE, before splits) ===
    if (cfg.enable_ech && is_client_hello && impl_->ech_config_valid_) {
        auto ech_hello = ECH::apply_ech(working_data, impl_->ech_config_);
        if (ech_hello.size() > working_data.size()) {
            // ECH extension was added — update working_data
            working_data = std::move(ech_hello);
            std::lock_guard<std::mutex> lock(impl_->stats_mutex);
            impl_->stats.ech_applied++;
            impl_->log("ECH applied to ClientHello");
        }
    }

    // === Phase 2: Decoy SNI (uses fingerprinted ClientHello) ===
    if (cfg.base_config.enable_decoy_sni && is_client_hello && !cfg.base_config.decoy_sni_domains.empty()) {
        for (const auto& decoy_domain : cfg.base_config.decoy_sni_domains) {
            auto fake_hello = impl_->tls_manip->create_fake_client_hello(decoy_domain);
            result.push_back(std::move(fake_hello));
            std::lock_guard<std::mutex> lock(impl_->stats_mutex);
            impl_->stats.fake_packets_injected++;
        }
    }

    // === Splitting logic (SNI split or multi-layer split) ===
    if (cfg.base_config.enable_multi_layer_split && is_client_hello && !cfg.base_config.split_positions.empty()) {
        std::vector<size_t> sp;
        sp.reserve(cfg.base_config.split_positions.size());
        for (int pos : cfg.base_config.split_positions) { if (pos >= 0) sp.push_back(static_cast<size_t>(pos)); }
        auto segments = impl_->tcp_manip->split_segments(working_data.data(), working_data.size(), sp);
        result.insert(result.end(), segments.begin(), segments.end());
        std::lock_guard<std::mutex> lock(impl_->stats_mutex);
        impl_->stats.tcp_segments_split += segments.size();
    } else if (is_client_hello) {
        auto split_points = impl_->tls_manip->find_sni_split_points(working_data.data(), working_data.size());
        if (!split_points.empty()) {
            if (cfg.base_config.randomize_split_position) {
                int jitter = static_cast<int>(secure_random(static_cast<uint32_t>(
                    cfg.base_config.split_position_max - cfg.base_config.split_position_min + 1)));
                jitter += cfg.base_config.split_position_min;
                for (auto& pt : split_points)
                    pt = std::min(pt + static_cast<size_t>(jitter), working_data.size() - 1);
            }
            auto segments = impl_->tcp_manip->split_segments(working_data.data(), working_data.size(), split_points);
            result.insert(result.end(), segments.begin(), segments.end());
            std::lock_guard<std::mutex> lock(impl_->stats_mutex);
            impl_->stats.tls_records_split++;
        } else {
            result.push_back(working_data);
        }
    } else {
        result.push_back(working_data);
    }

    // === Padding ===
    if (cfg.padding.enabled && cfg.padding.max_padding > 0) {
        for (auto& segment : result) {
            size_t ps = cfg.padding.random_padding
                ? secure_random(static_cast<uint32_t>(cfg.padding.max_padding - cfg.padding.min_padding + 1)) + cfg.padding.min_padding
                : cfg.padding.max_padding;
            segment = impl_->tls_manip->add_tls_padding(segment.data(), segment.size(), ps);
            std::lock_guard<std::mutex> lock(impl_->stats_mutex);
            impl_->stats.packets_padded++;
            impl_->stats.bytes_padding += ps;
        }
    }

    // === Obfuscation ===
    if (impl_->obfuscator) {
        for (auto& segment : result) {
            segment = impl_->obfuscator->obfuscate(segment.data(), segment.size());
            std::lock_guard<std::mutex> lock(impl_->stats_mutex);
            impl_->stats.bytes_obfuscated += segment.size();
        }
    }

    if (cfg.base_config.enable_timing_jitter && result.size() > 1) {
        std::lock_guard<std::mutex> lock(impl_->stats_mutex);
        impl_->stats.timing_delays_applied += result.size() - 1;
    }
    return result;
}

std::vector<uint8_t> AdvancedDPIBypass::process_incoming(const uint8_t* data, size_t len) {
    if (!data || len == 0) return {};
    if (impl_->obfuscator) {
        auto result = impl_->obfuscator->deobfuscate(data, len);
        std::lock_guard<std::mutex> lock(impl_->stats_mutex);
        impl_->stats.bytes_deobfuscated += result.size();
        return result;
    }
    return std::vector<uint8_t>(data, data + len);
}

void AdvancedDPIBypass::set_log_callback(std::function<void(const std::string&)> callback) {
    impl_->log_callback = std::move(callback);
}

void AdvancedDPIBypass::set_technique_enabled(EvasionTechnique technique, bool enabled) {
    auto& techniques = impl_->config.techniques;
    auto it = std::find(techniques.begin(), techniques.end(), technique);
    if (enabled && it == techniques.end()) techniques.push_back(technique);
    else if (!enabled && it != techniques.end()) techniques.erase(it);
}

std::vector<EvasionTechnique> AdvancedDPIBypass::get_active_techniques() const {
    return impl_->config.techniques;
}

void AdvancedDPIBypass::apply_preset(BypassPreset preset) {
    auto& cfg = impl_->config.base_config;
    auto& techniques = impl_->config.techniques;
    techniques.clear();
    switch (preset) {
    case BypassPreset::MINIMAL:
        cfg.enable_tcp_split = true; cfg.split_at_sni = true;
        cfg.enable_noise = false; cfg.enable_fake_packet = false;
        techniques.push_back(EvasionTechnique::SNI_SPLIT);
        break;
    case BypassPreset::MODERATE:
        cfg.enable_tcp_split = true; cfg.split_at_sni = true;
        cfg.enable_noise = true; cfg.enable_fake_packet = true;
        cfg.enable_pattern_obfuscation = true;
        techniques.push_back(EvasionTechnique::SNI_SPLIT);
        techniques.push_back(EvasionTechnique::TLS_GREASE);
        techniques.push_back(EvasionTechnique::IP_TTL_TRICKS);
        break;
    case BypassPreset::AGGRESSIVE:
        cfg.enable_tcp_split = true; cfg.split_at_sni = true;
        cfg.enable_noise = true; cfg.enable_fake_packet = true;
        cfg.enable_pattern_obfuscation = true; cfg.randomize_split_position = true;
        cfg.randomize_fake_ttl = true; cfg.enable_timing_jitter = true;
        cfg.enable_decoy_sni = true; cfg.enable_multi_layer_split = true;
        techniques.push_back(EvasionTechnique::SNI_SPLIT);
        techniques.push_back(EvasionTechnique::TLS_GREASE);
        techniques.push_back(EvasionTechnique::IP_TTL_TRICKS);
        techniques.push_back(EvasionTechnique::TIMING_JITTER);
        techniques.push_back(EvasionTechnique::FAKE_SNI);
        techniques.push_back(EvasionTechnique::TCP_SEGMENTATION);
        break;
    case BypassPreset::STEALTH:
        cfg.enable_tcp_split = true; cfg.split_at_sni = true;
        cfg.enable_noise = false; cfg.enable_fake_packet = false;
        cfg.enable_pattern_obfuscation = true; cfg.enable_timing_jitter = true;
        cfg.timing_jitter_min_us = 50; cfg.timing_jitter_max_us = 200;
        techniques.push_back(EvasionTechnique::SNI_SPLIT);
        techniques.push_back(EvasionTechnique::TIMING_JITTER);
        impl_->config.obfuscation = ObfuscationMode::HTTP_CAMOUFLAGE;
        break;
    }
    impl_->log("Applied preset: " + std::to_string(static_cast<int>(preset)));
}

// ==================== ECH Integration ====================

std::vector<uint8_t> DPIEvasion::apply_ech(
    const std::vector<uint8_t>& client_hello,
    const std::vector<uint8_t>& ech_config_data) {
    ECH::ECHConfig config;
    if (!ECH::parse_ech_config(ech_config_data, config)) return client_hello;
    return ECH::apply_ech(client_hello, config);
}

std::vector<uint8_t> DPIEvasion::apply_domain_fronting(
    const std::vector<uint8_t>& data,
    const std::string& front_domain,
    const std::string& real_domain) {
    std::vector<uint8_t> result = data;
    auto pos = std::search(result.begin(), result.end(), real_domain.begin(), real_domain.end());
    if (pos != result.end() && front_domain.size() == real_domain.size())
        std::copy(front_domain.begin(), front_domain.end(), pos);
    return result;
}

// ==================== Preset Configurations ====================

namespace Presets {

AdvancedDPIConfig create_tspu_preset() {
    AdvancedDPIConfig config;
    config.base_config.mode = DPIMode::PROXY;
    config.base_config.enable_tcp_split = true; config.base_config.split_at_sni = true;
    config.base_config.split_position = 1; config.base_config.fragment_size = 1;
    config.base_config.enable_fake_packet = true; config.base_config.fake_ttl = 2;
    config.base_config.enable_disorder = true; config.base_config.disorder_delay_ms = 10;
    config.base_config.enable_noise = true; config.base_config.noise_size = 128;
    config.base_config.randomize_split_position = true;
    config.base_config.split_position_min = 1; config.base_config.split_position_max = 5;
    config.base_config.enable_pattern_obfuscation = true;
    config.base_config.randomize_fake_ttl = true;
    config.base_config.enable_timing_jitter = true;
    config.base_config.timing_jitter_min_us = 100; config.base_config.timing_jitter_max_us = 500;
    config.base_config.enable_decoy_sni = true;
    config.base_config.decoy_sni_domains = {"google.com", "cloudflare.com"};
    config.techniques = { EvasionTechnique::SNI_SPLIT, EvasionTechnique::TCP_SEGMENTATION,
        EvasionTechnique::IP_TTL_TRICKS, EvasionTechnique::TIMING_JITTER,
        EvasionTechnique::TLS_GREASE, EvasionTechnique::FAKE_SNI };
    config.tspu_bypass = true;
    return config;
}

AdvancedDPIConfig create_gfw_preset() {
    AdvancedDPIConfig config;
    config.base_config.mode = DPIMode::PROXY;
    config.base_config.enable_tcp_split = true; config.base_config.split_at_sni = true;
    config.base_config.fragment_size = 2; config.base_config.enable_fake_packet = true;
    config.base_config.enable_disorder = true; config.base_config.enable_pattern_obfuscation = true;
    config.base_config.enable_multi_layer_split = true;
    config.base_config.split_positions = {2, 40, 120};
    config.techniques = { EvasionTechnique::SNI_SPLIT, EvasionTechnique::TCP_SEGMENTATION,
        EvasionTechnique::TCP_DISORDER, EvasionTechnique::TLS_GREASE };
    config.china_gfw_bypass = true; config.obfuscation = ObfuscationMode::XOR_ROLLING;
    return config;
}

AdvancedDPIConfig create_iran_preset() {
    AdvancedDPIConfig config;
    config.base_config.mode = DPIMode::PROXY;
    config.base_config.enable_tcp_split = true; config.base_config.split_at_sni = true;
    config.base_config.enable_fake_packet = true; config.base_config.enable_pattern_obfuscation = true;
    config.techniques = { EvasionTechnique::SNI_SPLIT, EvasionTechnique::TLS_GREASE, EvasionTechnique::HTTP_HEADER_SPLIT };
    config.obfuscation = ObfuscationMode::HTTP_CAMOUFLAGE;
    return config;
}

AdvancedDPIConfig create_aggressive_preset() {
    AdvancedDPIConfig config;
    config.base_config.mode = DPIMode::PROXY;
    config.base_config.enable_tcp_split = true; config.base_config.split_at_sni = true;
    config.base_config.split_position = 1; config.base_config.fragment_size = 1;
    config.base_config.enable_fake_packet = true; config.base_config.fake_ttl = 1;
    config.base_config.enable_disorder = true; config.base_config.enable_noise = true;
    config.base_config.noise_size = 256; config.base_config.randomize_split_position = true;
    config.base_config.enable_pattern_obfuscation = true; config.base_config.randomize_fake_ttl = true;
    config.base_config.enable_tcp_options_randomization = true;
    config.base_config.enable_timing_jitter = true; config.base_config.enable_multi_layer_split = true;
    config.base_config.enable_decoy_sni = true; config.base_config.enable_adaptive_fragmentation = true;
    config.techniques = { EvasionTechnique::SNI_SPLIT, EvasionTechnique::TCP_SEGMENTATION,
        EvasionTechnique::TCP_DISORDER, EvasionTechnique::TCP_OVERLAP,
        EvasionTechnique::IP_TTL_TRICKS, EvasionTechnique::TLS_GREASE,
        EvasionTechnique::FAKE_SNI, EvasionTechnique::TIMING_JITTER };
    config.obfuscation = ObfuscationMode::CHACHA20;
    config.padding.enabled = true; config.padding.max_padding = 128;
    return config;
}

AdvancedDPIConfig create_stealth_preset() {
    AdvancedDPIConfig config;
    config.base_config.mode = DPIMode::PROXY;
    config.base_config.enable_tcp_split = true; config.base_config.split_at_sni = true;
    config.base_config.fragment_size = 4; config.base_config.enable_pattern_obfuscation = true;
    config.base_config.enable_timing_jitter = true;
    config.base_config.timing_jitter_min_us = 50; config.base_config.timing_jitter_max_us = 150;
    config.techniques = { EvasionTechnique::SNI_SPLIT, EvasionTechnique::TIMING_JITTER };
    config.obfuscation = ObfuscationMode::HTTP_CAMOUFLAGE;
    return config;
}

AdvancedDPIConfig create_compatible_preset() {
    AdvancedDPIConfig config;
    config.base_config.mode = DPIMode::PROXY;
    config.base_config.enable_tcp_split = true; config.base_config.split_at_sni = true;
    config.base_config.split_position = 2; config.base_config.fragment_size = 8;
    config.techniques = { EvasionTechnique::SNI_SPLIT };
    return config;
}

} // namespace Presets
} // namespace DPI
} // namespace ncp
