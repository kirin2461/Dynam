/**
 * @file ncp_ech_fetch.cpp
 * @brief ECHConfig fetching via DNS-over-HTTPS
 */

#include "../include/ncp_ech_fetch.hpp"
#include "../include/ncp_doh.hpp"  // Existing DoH implementation
#include <algorithm>
#include <sstream>

namespace ncp {
namespace DPI {
namespace ECH {

struct ECHConfigFetcher::Impl {
    DoHConfig doh_config;
    std::string last_error;
    std::unique_ptr<DoHResolver> resolver;

    Impl() {
        resolver = std::make_unique<DoHResolver>();
    }
};

ECHConfigFetcher::ECHConfigFetcher() : impl_(std::make_unique<Impl>()) {}
ECHConfigFetcher::~ECHConfigFetcher() = default;

void ECHConfigFetcher::set_doh_config(const DoHConfig& config) {
    impl_->doh_config = config;
    
    // Configure existing DoH resolver
    DoHResolver::Config resolver_config;
    resolver_config.server_url = config.server_url;
    resolver_config.timeout_ms = config.timeout_ms;
    resolver_config.verify_ssl = config.verify_ssl;
    
    impl_->resolver->configure(resolver_config);
}

bool ECHConfigFetcher::fetch_ech_config(const std::string& domain, ECHConfig& config) {
    auto configs = fetch_all_configs(domain);
    
    if (configs.empty()) {
        impl_->last_error = "No ECHConfig found for domain";
        return false;
    }
    
    // Return first config
    config = configs[0];
    return true;
}

std::vector<ECHConfig> ECHConfigFetcher::fetch_all_configs(const std::string& domain) {
    std::vector<ECHConfig> configs;
    impl_->last_error.clear();

    try {
        // Query HTTPS record type (type 65)
        auto response = impl_->resolver->resolve(domain, 65);  // HTTPS RR type
        
        if (response.answers.empty()) {
            impl_->last_error = "No HTTPS records found";
            return configs;
        }

        // Parse HTTPS records for ECH parameter
        for (const auto& answer : response.answers) {
            if (answer.type != 65) continue;  // HTTPS RR

            // HTTPS record format:
            // Priority (2 bytes) + Target (domain name) + SvcParams
            const auto& rdata = answer.rdata;
            if (rdata.size() < 2) continue;

            size_t pos = 2;  // Skip priority

            // Skip target domain name
            while (pos < rdata.size() && rdata[pos] != 0) {
                uint8_t label_len = rdata[pos];
                pos += 1 + label_len;
            }
            pos++;  // Skip null terminator

            // Parse SvcParams
            while (pos + 4 <= rdata.size()) {
                uint16_t param_key = (rdata[pos] << 8) | rdata[pos + 1];
                uint16_t param_len = (rdata[pos + 2] << 8) | rdata[pos + 3];
                pos += 4;

                if (pos + param_len > rdata.size()) break;

                // ECH parameter key is 5
                if (param_key == 5) {
                    // Parse ECHConfigList
                    std::vector<uint8_t> ech_config_list(
                        rdata.begin() + pos,
                        rdata.begin() + pos + param_len
                    );

                    // ECHConfigList format: length (2 bytes) + ECHConfigs
                    if (ech_config_list.size() >= 2) {
                        uint16_t list_len = (ech_config_list[0] << 8) | ech_config_list[1];
                        
                        if (list_len + 2 == ech_config_list.size()) {
                            // Parse individual ECHConfig entries
                            size_t cfg_pos = 2;
                            while (cfg_pos + 4 <= ech_config_list.size()) {
                                uint16_t cfg_len = (ech_config_list[cfg_pos] << 8) | 
                                                   ech_config_list[cfg_pos + 1];
                                cfg_pos += 2;

                                if (cfg_pos + cfg_len > ech_config_list.size()) break;

                                std::vector<uint8_t> cfg_data(
                                    ech_config_list.begin() + cfg_pos,
                                    ech_config_list.begin() + cfg_pos + cfg_len
                                );

                                ECHConfig config;
                                if (parse_ech_config(cfg_data, config)) {
                                    configs.push_back(config);
                                }

                                cfg_pos += cfg_len;
                            }
                        }
                    }
                }

                pos += param_len;
            }
        }

        if (configs.empty()) {
            impl_->last_error = "No valid ECHConfig in HTTPS records";
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
