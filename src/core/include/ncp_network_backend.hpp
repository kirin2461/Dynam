#ifndef NCP_NETWORK_BACKEND_HPP
#define NCP_NETWORK_BACKEND_HPP

#include <vector>
#include <string>
#include <cstdint>
#include <functional>
#include <memory>
#include <atomic>
#include <thread>

namespace ncp {

/**
 * @brief Network backend types for hybrid architecture
 * Allows runtime selection of capture/injection method
 */
enum class NetworkBackendType {
    AUTO,           // Auto-detect best available backend
    RAW_SOCKETS,    // Cross-platform raw sockets (requires admin/root)
    ETW_CAPTURE,    // Windows ETW packet capture (no driver needed)
    PROXY_ONLY,     // Application-level proxy (no admin needed)
    NFQUEUE         // Linux netfilter_queue (requires root)
};

/**
 * @brief Packet capture callback
 * @param data Raw packet bytes
 * @param timestamp Capture timestamp
 */
using CaptureCallback = std::function<void(const std::vector<uint8_t>&, time_t)>;

/**
 * @brief Abstract interface for network backends
 * Replaces direct Npcap/libpcap dependency with pluggable architecture
 */
class INetworkBackend {
public:
    virtual ~INetworkBackend() = default;

    // Lifecycle
    virtual bool initialize(const std::string& interface_name = "") = 0;
    virtual void shutdown() = 0;
    virtual bool is_initialized() const = 0;

    // Packet capture
    virtual bool start_capture(CaptureCallback callback) = 0;
    virtual void stop_capture() = 0;
    virtual bool is_capturing() const = 0;

    // Packet injection
    virtual bool send_raw_packet(
        const std::string& dest_ip,
        const std::vector<uint8_t>& data
    ) = 0;

    virtual bool send_tcp_packet(
        const std::string& src_ip,
        const std::string& dst_ip,
        uint16_t src_port,
        uint16_t dst_port,
        const std::vector<uint8_t>& payload,
        uint8_t tcp_flags = 0x02,
        uint8_t ttl = 64
    ) = 0;

    // Diagnostics
    virtual std::string get_backend_name() const = 0;
    virtual std::string get_last_error() const = 0;
    virtual bool requires_admin() const = 0;
};

/**
 * @brief Factory for creating network backends
 * Selects the best available backend for the current platform and privileges
 */
class NetworkBackendFactory {
public:
    /**
     * @brief Create a network backend instance
     * @param type Desired backend type (AUTO = best available)
     * @return Unique pointer to backend, or nullptr if unavailable
     */
    static std::unique_ptr<INetworkBackend> create(
        NetworkBackendType type = NetworkBackendType::AUTO
    );

    /**
     * @brief Check if running with elevated privileges
     */
    static bool is_elevated();

    /**
     * @brief List available backends on current platform
     */
    static std::vector<NetworkBackendType> available_backends();
};

} // namespace ncp

#endif // NCP_NETWORK_BACKEND_HPP
