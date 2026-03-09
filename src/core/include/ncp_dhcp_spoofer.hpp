#ifndef NCP_DHCP_SPOOFER_HPP
#define NCP_DHCP_SPOOFER_HPP

#include <string>
#include <vector>
#include <cstdint>
#include <functional>
#include <atomic>

namespace ncp {

/**
 * @brief DHCP Client ID (Option 61) Spoofer
 * Works locally without remote server:
 *   Windows: Registry DhcpClientIdentifier + service restart
 *   Linux:   dhclient.conf modification + DHCP renew
 */
class DHCPSpoofer {
public:
    struct Config {
        std::string interface_name;
        std::string custom_client_id;  // Empty = generate from spoofed MAC
        bool auto_renew = true;        // Restart DHCP after change
    };

    DHCPSpoofer() = default;
    ~DHCPSpoofer();

    bool apply(const Config& config);
    bool restore();
    bool is_applied() const { return applied_; }

    std::string get_current_client_id() const { return current_id_; }
    std::string get_last_error() const { return last_error_; }

    static std::string generate_from_mac(const std::string& mac);
    static std::string generate_random();

private:
    bool apply_windows(const Config& config);
    bool apply_linux(const Config& config);
    bool restore_windows();
    bool restore_linux();
    std::string find_interface_guid(const std::string& name);

    std::atomic<bool> applied_{false};
    std::string current_id_;
    std::string original_id_;
    std::string interface_name_;
    std::string last_error_;
};

} // namespace ncp

#endif // NCP_DHCP_SPOOFER_HPP
