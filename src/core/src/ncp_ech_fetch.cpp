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
    std::unique_ptr<ncp::DoHClient> resolver;

    Impl() {
        resolver = std::make_unique<ncp::DoHClient>();
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
    
    // Return first config
    config = configs[0];
    return true;
}

std::vector<ECHConfig> ECHConfigFetcher::fetch_all_configs(const std::string& domain) {
    std::vector<ECHConfig> configs;
    impl_->last_error.clear();

    try {
        // Query HTTPS record type (type 65) - use TXT as closest available
        // DoHClient doesn't directly support type 65 (HTTPS RR),
        // so we resolve TXT and look for ECH configs
        auto response = impl_->resolver->resolve(domain, ncp::DoHClient::RecordType::TXT);
        
        if (response.status_code != 200 && !response.error_message.empty()) {
            impl_->last_error = "DoH query failed: " + response.error_message;
            return configs;
        }

        // For a real implementation, we'd need HTTPS RR (type 65) support.
        // This is a placeholder that processes any returned data.
        if (!response.addresses.empty()) {
            // Try to parse ECH configs from TXT records
            for (const auto& txt : response.addresses) {
                // Look for base64-encoded ECH config in TXT records
                // Real implementation would use SVCB/HTTPS records
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
