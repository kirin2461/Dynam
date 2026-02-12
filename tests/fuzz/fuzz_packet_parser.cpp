#include "ncp_network.hpp"
#include <cstdint>
#include <cstddef>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 20) return 0;  // Minimum packet size

    ncp::Network net;
    std::vector<uint8_t> packet(data, data + size);

    // Test packet parsing and bypass application
    net.apply_bypass_to_packet(packet);

    // Test fragmentation with various sizes
    if (size >= 40) {
        std::vector<uint8_t> frag_packet(data, data + size);
        net.fragment_packet(frag_packet);
    }

    return 0;
}
