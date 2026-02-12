#include "../include/ncp_i2p.hpp"
#include <iostream>

namespace ncp {

I2PManager::I2PManager() : is_initialized_(false) {}
I2PManager::~I2PManager() {}

bool I2PManager::initialize(const Config& config) {
    config_ = config;
    is_initialized_ = true;
    // In a real implementation, this would connect to I2P SAM bridge
    current_dest_ = "ncp_client.b32.i2p"; 
    return true;
}

bool I2PManager::is_active() const {
    return config_.enabled && is_initialized_;
}

void I2PManager::set_enabled(bool enabled) {
    config_.enabled = enabled;
}

std::string I2PManager::get_destination() const {
    return current_dest_;
}

bool I2PManager::create_tunnel(const std::string& name, uint16_t local_port, const std::string& remote_dest) {
    if (!is_active()) return false;
    // Placeholder for tunnel creation via SAM
    return true;
}

} // namespace ncp
