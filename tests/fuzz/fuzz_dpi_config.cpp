#include "ncp_dpi.hpp"
#include <cstdint>
#include <cstddef>
#include <string>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 4) return 0;

    // Fuzz DPIConfig deserialization
    std::string serialized(reinterpret_cast<const char*>(data), size);
    auto config = ncp::DPI::DPIConfig::deserialize(serialized);

    // If deserialization succeeded, test validation
    if (config.has_value()) {
        config->validate();
        config->is_valid();
        config->to_string();
        config->serialize();
    }

    // Fuzz DPIConfig with random field values
    if (size >= sizeof(ncp::DPI::DPIConfig)) {
        ncp::DPI::DPIConfig cfg;
        cfg.fragment_size = static_cast<int>(data[0]) | (static_cast<int>(data[1]) << 8);
        cfg.fragment_offset = static_cast<int>(data[2]);
        cfg.split_position = static_cast<int>(data[3]);
        if (size > 4) cfg.noise_size = static_cast<int>(data[4]) | (static_cast<int>(data[size > 5 ? 5 : 4]) << 8);
        if (size > 6) cfg.fake_ttl = static_cast<int>(data[6]);
        cfg.validate();
    }

    return 0;
}
