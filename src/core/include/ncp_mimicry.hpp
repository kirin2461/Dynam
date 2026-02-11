#ifndef NCP_TRAFFIC_MIMICRY_HPP
#define NCP_TRAFFIC_MIMICRY_HPP

#include <vector>
#include <string>
#include <cstdint>
#include <random>

namespace NCP {

/**
 * @brief Traffic Mimicry to disguise specialized traffic as common protocols
 */
class TrafficMimicry {
public:
    enum class MimicProfile {
        HTTP_GET,
        HTTPS_CLIENT_HELLO,
        DNS_QUERY,
        GENERIC_TCP
    };

    TrafficMimicry();
    ~TrafficMimicry();

    // Transform data to look like a specific protocol
    std::vector<uint8_t> wrap_payload(const std::vector<uint8_t>& payload, MimicProfile profile);
    
    // Extract original data from a mimicked packet
    std::vector<uint8_t> unwrap_payload(const std::vector<uint8_t>& mimicked_data, MimicProfile profile);

private:
    std::vector<uint8_t> create_http_get_wrapper(const std::vector<uint8_t>& payload);
    std::vector<uint8_t> create_https_hello_wrapper(const std::vector<uint8_t>& payload);
    
    std::mt19937 rng_;
};

} // namespace NCP

#endif // NCP_TRAFFIC_MIMICRY_HPP
