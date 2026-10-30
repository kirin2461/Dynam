#include "ncp_transport_config.hpp"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <string>
#include <vector>

namespace {

void require(bool condition) {
    if (!condition) std::abort();
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Keep pathological inputs bounded even when the runner omits -max_len.
    if (size > 65536) return 0;
    const std::string text(reinterpret_cast<const char*>(data), size);
    std::string error;
    const auto cfg = ncp::parse_transport_config(text, error);
    if (!cfg) return 0;

    // A successful parse is always validated and must bind with the correct
    // runtime-secret domain. No sockets or live sessions are created here.
    require(ncp::validate_transport_config(*cfg, error));
    const bool legacy = cfg->wire_transport == ncp::WireTransport::LegacyPortHop;
    const std::vector<uint8_t> secret(32, 0x42);
    const auto bound = ncp::bind_transport_config(
        *cfg, legacy ? secret : std::vector<uint8_t>{}, error);
    require(bound.has_value());
    require(bound->hop_schedule.has_value() == legacy);
    require(bound->hop_policy == (legacy ? ncp::PathHopPolicy::LegacyPortHop
                                         : ncp::PathHopPolicy::Disabled));

    ncp::NcpMimicrySession::Config session_cfg;
    ncp::apply_transport_config(*bound, session_cfg);
    require(session_cfg.hop_policy == bound->hop_policy);
    require(session_cfg.outer_transport == bound->outer_transport);
    if (!legacy) require(session_cfg.porthop_overhead_bytes == 0);
    return 0;
}
