/**
 * @file ncp_ech_fetch.cpp
 * @brief ECHConfig fetching via DNS-over-HTTPS
 *
 * Fetches ECH configurations from DNS using:
 * 1. HTTPS RR (type 65) — primary, per RFC 9460
 * 2. TXT records — fallback, looks for "ech=<base64>" entries
 */

#include "../include/ncp_ech_fetch.hpp"
#include "../include/ncp_doh.hpp"  // Existing DoH implementation
#include <algorithm>
#include <sstream>
#include <cstring>

namespace ncp {
namespace DPI {
namespace ECH {

// ---------------------------------------------------------------------------
// HTTPS RR record type (RFC 9460) — not in DoHClient::RecordType enum,
// but DoHClient::resolve() accepts any RecordType value cast to the enum.
// Type 65 = HTTPS Service Binding record.
// ---------------------------------------------------------------------------
static constexpr uint16_t DNS_TYPE_HTTPS = 65;

// SVCB/HTTPS SvcParamKey for ECH (RFC 9460 §14.3.2)
static constexpr uint16_t SVCPARAM_ECH = 5;

// ECHConfig version from draft-ietf-tls-esni-18
static constexpr uint16_t ECH_CONFIG_VERSION = 0xfe0d;

// ---------------------------------------------------------------------------
// Base64 decoder (standard alphabet, handles padding)
// ---------------------------------------------------------------------------
static std::vector<uint8_t> base64_decode(const std::string& input) {
    static constexpr int8_t TABLE[256] = {
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
        52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,
        -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
        15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
        -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
        41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    };

    std::vector<uint8_t> out;
    out.reserve(input.size() * 3 / 4);

    uint32_t accum = 0;
    int bits = 0;
    for (unsigned char c : input) {
        if (c == '=' || c == '\n' || c == '\r' || c == ' ') continue;
        int8_t val = TABLE[c];
        if (val < 0) continue;  // skip invalid chars
        accum = (accum << 6) | static_cast<uint32_t>(val);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<uint8_t>((accum >> bits) & 0xFF));
        }
    }
    return out;
}

// ---------------------------------------------------------------------------
// Parse a single ECHConfig from wire format (draft-ietf-tls-esni)
//
// Wire format:
//   uint16 version (0xfe0d)
//   uint16 length
//   uint8  config_id
//   uint16 kem_id
//   uint16 public_key_length
//   opaque public_key[public_key_length]
//   uint16 cipher_suites_length
//   HPKESymmetricCipherSuite cipher_suites[cipher_suites_length/4]
//   uint16 maximum_name_length
//   uint8  public_name_length
//   opaque public_name[public_name_length]
//   uint16 extensions_length
//   opaque extensions[extensions_length]
// ---------------------------------------------------------------------------
static bool parse_single_ech_config(const uint8_t* data, size_t data_len,
                                     ECHConfig& config, size_t& bytes_consumed)
{
    bytes_consumed = 0;
    if (data_len < 4) return false;

    size_t off = 0;

    // version
    uint16_t version = (static_cast<uint16_t>(data[off]) << 8) | data[off + 1];
    off += 2;

    // length of the rest of this ECHConfig entry
    uint16_t config_len = (static_cast<uint16_t>(data[off]) << 8) | data[off + 1];
    off += 2;

    if (off + config_len > data_len) return false;

    // Save raw_config (version + length + contents)
    config.raw_config.assign(data, data + off + config_len);
    config.version = version;

    // For unknown versions, skip the config body
    if (version != ECH_CONFIG_VERSION) {
        bytes_consumed = off + config_len;
        return false;
    }

    size_t end = off + config_len;

    // config_id
    if (off >= end) return false;
    config.config_id = data[off++];

    // kem_id
    if (off + 2 > end) return false;
    uint16_t kem_id = (static_cast<uint16_t>(data[off]) << 8) | data[off + 1];
    off += 2;

    // public_key
    if (off + 2 > end) return false;
    uint16_t pk_len = (static_cast<uint16_t>(data[off]) << 8) | data[off + 1];
    off += 2;
    if (off + pk_len > end) return false;
    config.public_key.assign(data + off, data + off + pk_len);
    off += pk_len;

    // cipher_suites
    if (off + 2 > end) return false;
    uint16_t cs_len = (static_cast<uint16_t>(data[off]) << 8) | data[off + 1];
    off += 2;
    if (off + cs_len > end || cs_len % 4 != 0) return false;

    config.cipher_suites.clear();
    for (size_t i = 0; i < cs_len; i += 4) {
        uint16_t kdf_id = (static_cast<uint16_t>(data[off + i]) << 8) | data[off + i + 1];
        uint16_t aead_id = (static_cast<uint16_t>(data[off + i + 2]) << 8) | data[off + i + 3];
        config.cipher_suites.push_back(HPKECipherSuite(
            static_cast<HPKEKem>(kem_id),
            static_cast<HPKEKDF>(kdf_id),
            static_cast<HPKEAEAD>(aead_id)
        ));
    }
    off += cs_len;

    // maximum_name_length
    if (off + 2 > end) return false;
    config.maximum_name_length = (static_cast<uint16_t>(data[off]) << 8) | data[off + 1];
    off += 2;

    // public_name (length-prefixed, 1 byte length)
    if (off >= end) return false;
    uint8_t name_len = data[off++];
    if (off + name_len > end) return false;
    config.public_name.assign(reinterpret_cast<const char*>(data + off), name_len);
    off += name_len;

    // extensions (skip)
    if (off + 2 > end) return false;
    uint16_t ext_len = (static_cast<uint16_t>(data[off]) << 8) | data[off + 1];
    off += 2;
    if (off + ext_len > end) return false;
    off += ext_len;

    bytes_consumed = off;
    return true;
}

// ---------------------------------------------------------------------------
// Parse ECHConfigList wire format
//
// Wire format:
//   uint16 total_length
//   ECHConfig configs[...]
// ---------------------------------------------------------------------------
static std::vector<ECHConfig> parse_ech_config_list(const uint8_t* data, size_t data_len)
{
    std::vector<ECHConfig> configs;
    if (data_len < 2) return configs;

    uint16_t list_len = (static_cast<uint16_t>(data[0]) << 8) | data[1];
    size_t off = 2;

    if (off + list_len > data_len) return configs;

    size_t list_end = off + list_len;
    while (off < list_end) {
        ECHConfig config;
        size_t consumed = 0;
        if (parse_single_ech_config(data + off, list_end - off, config, consumed)) {
            configs.push_back(std::move(config));
        }
        if (consumed == 0) break;  // prevent infinite loop
        off += consumed;
    }

    return configs;
}

// ---------------------------------------------------------------------------
// Parse HTTPS RR (type 65) RDATA wire format (RFC 9460)
//
// Wire format:
//   uint16 SvcPriority
//   domain-name TargetName (wire format, compressed or uncompressed)
//   SvcParams (sequence of key-value pairs until end of RDATA)
//
// Each SvcParam:
//   uint16 SvcParamKey
//   uint16 SvcParamLength
//   opaque SvcParamValue[SvcParamLength]
//
// We look for SvcParamKey=5 (ech) which contains an ECHConfigList.
// ---------------------------------------------------------------------------
static std::vector<ECHConfig> parse_https_rr_rdata(
    const uint8_t* rdata, size_t rdata_len)
{
    std::vector<ECHConfig> configs;
    if (rdata_len < 4) return configs;  // at minimum: priority(2) + root name(1) + something

    size_t off = 0;

    // SvcPriority (skip)
    off += 2;

    // TargetName — skip domain name in wire format
    // Wire-format names end with a 0 byte (root) or a compression pointer (0xC0..)
    while (off < rdata_len) {
        uint8_t label_len = rdata[off];
        if (label_len == 0) {
            off++;  // root terminator
            break;
        }
        if ((label_len & 0xC0) == 0xC0) {
            off += 2;  // compression pointer (2 bytes)
            break;
        }
        off += 1 + label_len;
    }

    // Parse SvcParams looking for ech (key=5)
    while (off + 4 <= rdata_len) {
        uint16_t param_key = (static_cast<uint16_t>(rdata[off]) << 8) | rdata[off + 1];
        off += 2;
        uint16_t param_len = (static_cast<uint16_t>(rdata[off]) << 8) | rdata[off + 1];
        off += 2;

        if (off + param_len > rdata_len) break;

        if (param_key == SVCPARAM_ECH) {
            // SvcParamValue is an ECHConfigList
            auto parsed = parse_ech_config_list(rdata + off, param_len);
            configs.insert(configs.end(),
                           std::make_move_iterator(parsed.begin()),
                           std::make_move_iterator(parsed.end()));
        }

        off += param_len;
    }

    return configs;
}

// ---------------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------------

struct ECHConfigFetcher::Impl {
    DoHConfig doh_config;
    std::string last_error;
    std::unique_ptr<ncp::DoHClient> resolver;

    Impl() {
        resolver = std::make_unique<ncp::DoHClient>();
    }

    // Try to extract ECH configs from TXT records (fallback)
    // Looks for entries prefixed with "ech=" followed by base64
    std::vector<ECHConfig> try_parse_txt_records(const std::vector<std::string>& records) {
        std::vector<ECHConfig> configs;

        for (const auto& txt : records) {
            // Look for "ech=<base64>" pattern
            std::string trimmed = txt;
            // Strip surrounding quotes if present (common in TXT records)
            if (trimmed.size() >= 2 && trimmed.front() == '"' && trimmed.back() == '"') {
                trimmed = trimmed.substr(1, trimmed.size() - 2);
            }

            // Check for ech= prefix (case-insensitive)
            std::string lower = trimmed;
            std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

            std::string b64_data;
            if (lower.rfind("ech=", 0) == 0) {
                b64_data = trimmed.substr(4);
            } else if (lower.rfind("echconfig=", 0) == 0) {
                b64_data = trimmed.substr(10);
            } else {
                // Try decoding the entire record as base64 — some deployments
                // put raw base64 ECHConfigList in a dedicated _ech TXT record
                // Only if it looks like valid base64 (alphanumeric + /+ =)
                bool looks_b64 = !trimmed.empty() && trimmed.size() > 20;
                for (char c : trimmed) {
                    if (!std::isalnum(c) && c != '+' && c != '/' && c != '=') {
                        looks_b64 = false;
                        break;
                    }
                }
                if (looks_b64) {
                    b64_data = trimmed;
                } else {
                    continue;
                }
            }

            if (b64_data.empty()) continue;

            // Decode base64
            auto decoded = base64_decode(b64_data);
            if (decoded.size() < 6) continue;  // too short for any ECHConfig

            // Try parsing as ECHConfigList first
            auto parsed = parse_ech_config_list(decoded.data(), decoded.size());
            if (!parsed.empty()) {
                configs.insert(configs.end(),
                               std::make_move_iterator(parsed.begin()),
                               std::make_move_iterator(parsed.end()));
                continue;
            }

            // Try parsing as a single ECHConfig (no list wrapper)
            ECHConfig single;
            size_t consumed = 0;
            if (parse_single_ech_config(decoded.data(), decoded.size(), single, consumed)) {
                configs.push_back(std::move(single));
            }
        }

        return configs;
    }
};

ECHConfigFetcher::ECHConfigFetcher() : impl_(std::make_unique<Impl>()) {}
ECHConfigFetcher::~ECHConfigFetcher() = default;

void ECHConfigFetcher::set_doh_config(const DoHConfig& config) {
    impl_->doh_config = config;

    // Configure existing DoH resolver
    ncp::DoHClient::Config resolver_config;
    resolver_config.custom_server_url = config.server_url;
    resolver_config.timeout_ms = config.timeout_ms;
    resolver_config.verify_tls = config.verify_ssl;
    resolver_config.provider = ncp::DoHClient::Provider::CUSTOM;

    impl_->resolver->set_config(resolver_config);
}

bool ECHConfigFetcher::fetch_ech_config(const std::string& domain, ECHConfig& config) {
    auto configs = fetch_all_configs(domain);

    if (configs.empty()) {
        impl_->last_error = "No ECHConfig found for domain";
        return false;
    }

    // Return first config (highest priority from HTTPS RR, or first from TXT)
    config = configs[0];
    return true;
}

std::vector<ECHConfig> ECHConfigFetcher::fetch_all_configs(const std::string& domain) {
    std::vector<ECHConfig> configs;
    impl_->last_error.clear();

    try {
        // === Strategy 1: HTTPS RR (type 65) — preferred ===
        // Cast DNS_TYPE_HTTPS to RecordType. DoHClient builds the query
        // with whatever type value we pass; parse_dns_response will
        // return RDATA in addresses[] as hex or raw depending on type.
        //
        // NOTE: Our DoH parser currently only extracts A/AAAA/CNAME from
        // responses. For HTTPS RR we'd need raw RDATA. Until DoHClient
        // supports returning raw RDATA for unknown types, we attempt
        // the query but may get empty results. The TXT fallback below
        // covers this case.
        {
            auto response = impl_->resolver->resolve(
                domain, static_cast<ncp::DoHClient::RecordType>(DNS_TYPE_HTTPS));

            // If the resolver returned addresses (some DoH implementations
            // encode unknown RDATA as hex strings), try to parse them
            for (const auto& addr : response.addresses) {
                // Try interpreting as hex-encoded RDATA
                std::vector<uint8_t> rdata;
                rdata.reserve(addr.size() / 2);
                bool valid_hex = (addr.size() % 2 == 0) && !addr.empty();
                for (size_t i = 0; valid_hex && i + 1 < addr.size(); i += 2) {
                    char hi = addr[i], lo = addr[i + 1];
                    auto hex_val = [](char c) -> int {
                        if (c >= '0' && c <= '9') return c - '0';
                        if (c >= 'a' && c <= 'f') return 10 + c - 'a';
                        if (c >= 'A' && c <= 'F') return 10 + c - 'A';
                        return -1;
                    };
                    int h = hex_val(hi), l = hex_val(lo);
                    if (h < 0 || l < 0) { valid_hex = false; break; }
                    rdata.push_back(static_cast<uint8_t>((h << 4) | l));
                }
                if (valid_hex && rdata.size() >= 4) {
                    auto parsed = parse_https_rr_rdata(rdata.data(), rdata.size());
                    configs.insert(configs.end(),
                                   std::make_move_iterator(parsed.begin()),
                                   std::make_move_iterator(parsed.end()));
                }
            }
        }

        // === Strategy 2: TXT record fallback ===
        // Some CDNs (e.g., early Cloudflare deployments) published ECH
        // configs in TXT records at _ech.<domain> or as "ech=<base64>"
        // in the domain's TXT records.
        if (configs.empty()) {
            // Try _ech.<domain> first (dedicated ECH TXT record)
            std::string ech_domain = "_ech." + domain;
            auto txt_response = impl_->resolver->resolve(
                ech_domain, ncp::DoHClient::RecordType::TXT);

            auto txt_configs = impl_->try_parse_txt_records(txt_response.addresses);
            configs.insert(configs.end(),
                           std::make_move_iterator(txt_configs.begin()),
                           std::make_move_iterator(txt_configs.end()));

            // If still empty, try TXT on the bare domain
            if (configs.empty()) {
                auto bare_response = impl_->resolver->resolve(
                    domain, ncp::DoHClient::RecordType::TXT);
                txt_configs = impl_->try_parse_txt_records(bare_response.addresses);
                configs.insert(configs.end(),
                               std::make_move_iterator(txt_configs.begin()),
                               std::make_move_iterator(txt_configs.end()));
            }
        }

        if (configs.empty()) {
            impl_->last_error = "No valid ECHConfig in DNS records";
        }

    } catch (const std::exception& e) {
        impl_->last_error = std::string("Exception: ") + e.what();
    }

    return configs;
}

std::string ECHConfigFetcher::get_last_error() const {
    return impl_->last_error;
}

// Convenience function
std::optional<ECHConfig> fetch_ech_config_simple(const std::string& domain) {
    ECHConfigFetcher fetcher;
    ECHConfig config;

    if (fetcher.fetch_ech_config(domain, config)) {
        return config;
    }

    return std::nullopt;
}

} // namespace ECH
} // namespace DPI
} // namespace ncp
