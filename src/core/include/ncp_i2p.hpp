#ifndef NCP_I2P_HPP
#define NCP_I2P_HPP

#include <string>
#include <vector>
#include <cstdint>

namespace NCP {

/**
 * @brief I2P Network Integration Manager
 */
class I2PManager {
public:
    struct Config {
        bool enabled = false;
        std::string sam_host = "127.0.0.1";
        uint16_t sam_port = 7656;
        std::string proxy_host = "127.0.0.1";
        uint16_t proxy_port = 4444;
        bool use_http_proxy = true;
    };

    I2PManager();
    ~I2PManager();

    bool initialize(const Config& config);
    bool is_active() const;
    void set_enabled(bool enabled);

    // Get current I2P destination (b32 address)
    std::string get_destination() const;
    
    // Connect through I2P tunnel
    bool create_tunnel(const std::string& name, uint16_t local_port, const std::string& remote_dest);

private:
    Config config_;
    bool is_initialized_;
    std::string current_dest_;
};

} // namespace NCP

#endif // NCP_I2P_HPP
