#ifndef NCP_INTERFACE_SELECTOR_HPP
#define NCP_INTERFACE_SELECTOR_HPP

#include <string>
#include <vector>
#include <memory>
#include <functional>
#include "NetworkManager.hpp"

namespace ncp {

struct InterfaceInfo {
    std::string name;
    std::string display_name;
    std::string description;
    std::string mac_address;
    std::string ip_address;
    std::string subnet_mask;
    std::string gateway;
    bool is_wireless = false;
    bool is_up = false;
    bool is_loopback = false;
    int speed_mbps = 0;      // Link speed
    int signal_strength = 0; // For wireless (0-100)
};

class InterfaceSelector {
public:
    InterfaceSelector();
    ~InterfaceSelector();
    
    // Interface enumeration
    std::vector<InterfaceInfo> get_available_interfaces() const;
    void refresh_interfaces();
    
    // Selection
    bool select_interface(const std::string& name);
    bool select_best_interface();
    InterfaceInfo get_selected_interface() const { return selected_; }
    std::string get_selected_name() const { return selected_.name; }
    
    // Filtering
    std::vector<InterfaceInfo> get_active_interfaces() const;
    std::vector<InterfaceInfo> get_wireless_interfaces() const;
    std::vector<InterfaceInfo> get_wired_interfaces() const;
    
    // Callbacks
    using SelectionCallback = std::function<void(const InterfaceInfo&)>;
    void set_selection_callback(SelectionCallback callback) { selection_callback_ = callback; }
    
private:
    std::vector<InterfaceInfo> interfaces_;
    InterfaceInfo selected_;
    SelectionCallback selection_callback_;
    
    void enumerate_interfaces();
};

} // namespace ncp

#endif // NCP_INTERFACE_SELECTOR_HPP
