#include "ncp_crypto.hpp"
#include "ncp_license.hpp"
#include "ncp_network.hpp"
#include "ncp_spoofer.hpp"
#include "ncp_dpi.hpp"
#include "ncp_i2p.hpp"
#include "ncp_paranoid.hpp"
#include "ncp_mimicry.hpp"

#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <functional>
#include <memory>
#include <csignal>
#include <atomic>
#include <thread>
#include <chrono>

using namespace ncp;

// ============================================================================
// Global instances (RAII via unique_ptr)
// ============================================================================

std::unique_ptr<NetworkSpoofer> g_spoofer;
std::unique_ptr<DPI::DPIBypass> g_dpi_bypass;
std::unique_ptr<ParanoidMode> g_paranoid;

std::atomic<bool> g_running(false);

// ============================================================================
// Signal handler
// ============================================================================

void signal_handler(int signal) {
    if (signal == SIGINT || signal == SIGTERM) {
        std::cout << "\n[!] Shutdown signal received...\n";
        g_running = false;  // Only set flag, cleanup happens in main()
    }
}

// ============================================================================
// ArgumentParser
// ============================================================================

class ArgumentParser {
public:
    struct Command {
        std::string name;
        std::string description;
        std::function<void(const std::vector<std::string>&)> handler;
        std::vector<std::string> args_help;
    };

    ArgumentParser(const std::string& prog_name, const std::string& version)
        : prog_name_(prog_name), version_(version) {}

    void add_command(
        const std::string& name,
        const std::string& description,
        std::function<void(const std::vector<std::string>&)> handler,
        const std::vector<std::string>& args_help = {}
    ) {
        commands_[name] = {name, description, handler, args_help};
    }

    void parse_and_execute(int argc, char* argv[]) {
        if (argc < 2) {
            print_usage();
            return;
        }

        std::string cmd = argv[1];
        if (cmd == "help" || cmd == "--help" || cmd == "-h") {
            print_usage();
            return;
        }
        if (cmd == "version" || cmd == "--version" || cmd == "-v") {
            std::cout << prog_name_ << " " << version_ << std::endl;
            return;
        }

        auto it = commands_.find(cmd);
        if (it == commands_.end()) {
            std::cerr << "Unknown command: " << cmd << "\n";
            print_usage();
            return;
        }

        std::vector<std::string> args(argv + 2, argv + argc);
        it->second.handler(args);
    }

private:
    void print_usage() const {
        std::cout << prog_name_ << " " << version_ << " - Network Control Protocol\n";
        std::cout << "\nUsage: " << prog_name_ << " <command> [options]\n\n";
        std::cout << "Commands:\n";
        for (const auto& [name, cmd] : commands_) {
            std::cout << "  " << cmd.name;
            for (const auto& arg : cmd.args_help)
                std::cout << " " << arg;
            std::cout << "\n    " << cmd.description << "\n\n";
        }
        std::cout << "  help\n    Show this help message\n\n";
        std::cout << "  version\n    Show version information\n";
    }

    std::string prog_name_;
    std::string version_;
    std::map<std::string, Command> commands_;
};

// ============================================================================
// Utility functions
// ============================================================================

static std::string get_arg(const std::vector<std::string>& args, size_t index, const std::string& default_val = "") {
    return index < args.size() ? args[index] : default_val;
}

static bool has_flag(const std::vector<std::string>& args, const std::string& flag) {
    return std::find(args.begin(), args.end(), flag) != args.end();
}

static std::string get_option(const std::vector<std::string>& args, const std::string& option, const std::string& default_val = "") {
    auto it = std::find(args.begin(), args.end(), option);
    if (it != args.end() && ++it != args.end()) return *it;
    return default_val;
}

static int get_option_int(const std::vector<std::string>& args, const std::string& option, int default_val = 0) {
    std::string val = get_option(args, option);
    if (val.empty()) return default_val;
    try {
        return std::stoi(val);
    } catch (...) {
        return default_val;
    }
}

// ============================================================================
// Forward declarations
// ============================================================================

void handle_run(const std::vector<std::string>& args);
void handle_stop(const std::vector<std::string>& args);
void handle_status(const std::vector<std::string>& args);
void handle_rotate(const std::vector<std::string>& args);
void handle_crypto(const std::vector<std::string>& args);
void handle_network(const std::vector<std::string>& args);
void handle_license(const std::vector<std::string>& args);
void handle_dpi(const std::vector<std::string>& args);
void handle_i2p(const std::vector<std::string>& args);
void handle_mimic(const std::vector<std::string>& args);

// ============================================================================
// main()
// ============================================================================

int main(int argc, char* argv[]) {
    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);

    ArgumentParser parser("ncp", "v1.1.0");

    parser.add_command("run", "Start PARANOID mode (all protection layers)", handle_run, {"[<interface>]"});
    parser.add_command("stop", "Stop spoofing and restore original settings", handle_stop);
    parser.add_command("status", "Show current spoof status", handle_status);
    parser.add_command("rotate", "Rotate all identities", handle_rotate);
    parser.add_command("crypto", "Cryptographic operations", handle_crypto, {"<action>", "[args]"});
    parser.add_command("network", "Network operations", handle_network, {"<action>"});
    parser.add_command("license", "License management", handle_license, {"<action>"});
    parser.add_command("dpi", "DPI bypass proxy", handle_dpi, {"[options]"});
    parser.add_command("i2p", "I2P proxy configuration", handle_i2p, {"<action>"});
    parser.add_command("mimic", "Set traffic mimicry mode", handle_mimic, {"<type>"});

    parser.parse_and_execute(argc, argv);

    return 0;
}

// ============================================================================
// Handler implementations
// ============================================================================

void handle_run(const std::vector<std::string>& args) {
    try {
        std::cout << "[*] Starting PARANOID mode...\n";
        
        std::string interface = get_arg(args, 0);
        
        // Initialize globals
        g_spoofer = std::make_unique<NetworkSpoofer>();
        g_dpi_bypass = std::make_unique<DPI::DPIBypass>();
        g_paranoid = std::make_unique<ParanoidMode>();
        
        // 1. Configure and enable NetworkSpoofer
        NetworkSpoofer::SpoofConfig spoof_cfg;
        spoof_cfg.spoof_ipv4 = true;
        spoof_cfg.spoof_ipv6 = true;
        spoof_cfg.spoof_mac = true;
        spoof_cfg.spoof_dns = true;
        spoof_cfg.coordinated_rotation = true;
        
        if (!g_spoofer->enable(interface.empty() ? "eth0" : interface, spoof_cfg)) {
            std::cerr << "[!] Failed to enable spoofing\n";
            return;
        }
        std::cout << "[+] Spoofing enabled on " << (interface.empty() ? "eth0" : interface) << "\n";
        
        // 2. Configure and start DPI bypass with RUNET_STRONG preset
        DPI::DPIConfig dpi_cfg;
        DPI::apply_preset(DPI::DPIPreset::RUNET_STRONG, dpi_cfg);
        
        if (!g_dpi_bypass->initialize(dpi_cfg) || !g_dpi_bypass->start()) {
            std::cerr << "[!] Failed to start DPI bypass\n";
            return;
        }
        std::cout << "[+] DPI bypass active (RuNet-Strong preset)\n";
        
        // 3. Activate ParanoidMode with TINFOIL_HAT threat level
        g_paranoid->set_threat_level(ParanoidMode::ThreatLevel::TINFOIL_HAT);
        if (!g_paranoid->activate()) {
            std::cerr << "[!] Failed to activate ParanoidMode\n";
            return;
        }
        std::cout << "[+] ParanoidMode activated (TINFOIL_HAT level)\n";
        
        std::cout << "[+] All protection layers running. Press Ctrl+C to stop.\n";
        
        g_running = true;
        
        // Wait loop
        while (g_running) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
        
        // Cleanup after loop exit (RAII compliance)
        std::cout << "\n[*] Shutting down services...\n";
        
        if (g_paranoid && g_paranoid->is_active()) {
            g_paranoid->deactivate();
            std::cout << "[+] ParanoidMode deactivated\n";
        }
        g_paranoid.reset();
        
        if (g_dpi_bypass && g_dpi_bypass->is_running()) {
            g_dpi_bypass->stop();
            std::cout << "[+] DPI bypass stopped\n";
        }
        g_dpi_bypass.reset();
        
        if (g_spoofer && g_spoofer->is_enabled()) {
            g_spoofer->disable();
            std::cout << "[+] Spoofing disabled, settings restored\n";
        }
        g_spoofer.reset();
        
        std::cout << "[+] Shutdown complete\n";
        
    } catch (const std::exception& e) {
        std::cerr << "[!] Exception in handle_run: " << e.what() << "\n";
    }
}

void handle_stop(const std::vector<std::string>& args) {
    std::cout << "[*] Stopping all services and restoring settings...\n";
    
    g_running = false;
    
    if (g_paranoid && g_paranoid->is_active()) {
        g_paranoid->deactivate();
        std::cout << "[+] ParanoidMode deactivated\n";
    }
    g_paranoid.reset();
    
    if (g_dpi_bypass && g_dpi_bypass->is_running()) {
        g_dpi_bypass->stop();
        std::cout << "[+] DPI bypass stopped\n";
    }
    g_dpi_bypass.reset();
    
    if (g_spoofer && g_spoofer->is_enabled()) {
        g_spoofer->disable();
        std::cout << "[+] Spoofing disabled, original settings restored\n";
    }
    g_spoofer.reset();
    
    std::cout << "[+] All services stopped\n";
}

void handle_status(const std::vector<std::string>& args) {
    std::cout << "=== NCP Status ===\n\n";
    
    // Spoofing status
    if (g_spoofer && g_spoofer->is_enabled()) {
        auto status = g_spoofer->get_status();
        std::cout << "[Spoofing]\n";
        std::cout << "  IPv4: " << (status.ipv4_spoofed ? status.current_ipv4 : "Not spoofed") << "\n";
        std::cout << "  IPv6: " << (status.ipv6_spoofed ? status.current_ipv6 : "Not spoofed") << "\n";
        std::cout << "  MAC: " << (status.mac_spoofed ? status.current_mac : "Not spoofed") << "\n";
        std::cout << "  Hostname: " << (status.hostname_spoofed ? status.current_hostname : "Not spoofed") << "\n";
    } else {
        std::cout << "[Spoofing] Inactive\n";
    }
    
    // DPI bypass status
    if (g_dpi_bypass && g_dpi_bypass->is_running()) {
        auto stats = g_dpi_bypass->get_stats();
        std::cout << "\n[DPI Bypass]\n";
        std::cout << "  Packets processed: " << stats.packets_total.load() << "\n";
        std::cout << "  Packets modified: " << stats.packets_modified.load() << "\n";
        std::cout << "  Fake packets sent: " << stats.fake_packets_sent.load() << "\n";
    } else {
        std::cout << "\n[DPI Bypass] Inactive\n";
    }
    
    // ParanoidMode status
    if (g_paranoid && g_paranoid->is_active()) {
        auto pstats = g_paranoid->get_statistics();
        std::cout << "\n[ParanoidMode]\n";
        
        // Show threat level
        std::cout << "  Threat level: ";
        auto level = g_paranoid->get_threat_level();
        switch(level) {
            case ParanoidMode::ThreatLevel::MODERATE: std::cout << "MODERATE"; break;
            case ParanoidMode::ThreatLevel::EXTREME: std::cout << "EXTREME"; break;
            case ParanoidMode::ThreatLevel::HIGH: std::cout << "HIGH"; break;
            case ParanoidMode::ThreatLevel::TINFOIL_HAT: std::cout << "TINFOIL_HAT"; break;
            default: std::cout << "UNKNOWN"; break;
        }
        std::cout << "\n";
        
        std::cout << "  Active circuits: " << pstats.circuits_created << "\n";
        std::cout << "  Cover traffic sent: " << pstats.cover_traffic_sent << " bytes\n";
        std::cout << "  Anonymity set size: " << pstats.anonymity_set_size << "\n";
    } else {
        std::cout << "\n[ParanoidMode] Inactive\n";
    }
}

void handle_rotate(const std::vector<std::string>& args) {
    if (!g_spoofer || !g_spoofer->is_enabled()) {
        std::cerr << "[!] Spoofing not active\n";
        return;
    }
    
    std::cout << "[*] Rotating all identities...\n";
    
    if (g_spoofer->rotate_all()) {
        auto status = g_spoofer->get_status();
        std::cout << "[+] Identity rotation complete:\n";
        std::cout << "  New IPv4: " << status.current_ipv4 << "\n";
        std::cout << "  New IPv6: " << status.current_ipv6 << "\n";
        std::cout << "  New MAC: " << status.current_mac << "\n";
    } else {
        std::cerr << "[!] Rotation failed\n";
    }
    
    // Rotate paranoid circuits if active
    if (g_paranoid && g_paranoid->is_active()) {
        g_paranoid->rotate_all_circuits();
        std::cout << "[+] Paranoid circuits rotated\n";
    }
}

void handle_crypto(const std::vector<std::string>& args) {
    std::string action = get_arg(args, 0);
    
    if (action.empty()) {
        std::cerr << "Usage: ncp crypto <action> [args]\n";
        std::cerr << "Actions: keygen, random, hash, sign, verify\n";
        return;
    }
    
    Crypto crypto;
    
    if (action == "keygen") {
        auto keypair = crypto.generate_keypair();
        std::cout << "[+] Keypair generated (Ed25519)\n";
        std::cout << "Public key: " << Crypto::bytes_to_hex(keypair.public_key) << "\n";
        std::cout << "Secret key: [REDACTED - store securely]\n";
    }
    else if (action == "random") {
        size_t size = static_cast<size_t>(get_option_int(args, "-n", 32));
        auto random_bytes = crypto.generate_random(size);
        std::cout << "Random bytes (" << size << "): " << Crypto::bytes_to_hex(random_bytes) << "\n";
    }
    else if (action == "hash") {
        std::string algo = get_arg(args, 1, "sha256");
        std::string data = get_arg(args, 2);
        
        if (data.empty()) {
            std::cerr << "[!] No data provided\n";
            return;
        }
        
        SecureMemory msg(reinterpret_cast<const uint8_t*>(data.data()), data.size());
        SecureMemory hash;
        
        if (algo == "sha256")
            hash = crypto.hash_sha256(msg);
        else if (algo == "sha512")
            hash = crypto.hash_sha512(msg);
        else if (algo == "blake2b")
            hash = crypto.hash_blake2b(msg);
        else {
            std::cerr << "[!] Unknown hash algorithm: " << algo << "\n";
            return;
        }
        
        std::cout << "Hash (" << algo << "): " << Crypto::bytes_to_hex(hash) << "\n";
    }
    else if (action == "sign" || action == "verify") {
        std::cerr << "[!] " << action << " not yet implemented\n";
    }
    else {
        std::cerr << "[!] Unknown crypto action: " << action << "\n";
    }
}

void handle_network(const std::vector<std::string>& args) {
    std::string action = get_arg(args, 0);
    
    if (action.empty()) {
        std::cerr << "Usage: ncp network <action>\n";
        std::cerr << "Actions: interfaces, stats\n";
        return;
    }
    
    Network net;
    
    if (action == "interfaces") {
        auto ifaces = net.get_interfaces();
        std::cout << "Available network interfaces:\n";
        for (const auto& iface : ifaces) {
            std::cout << "  " << iface.name << " (" << iface.ip_address << ")";
            if (iface.is_up) std::cout << " [UP]";
            std::cout << "\n";
        }
    }
    else if (action == "stats") {
        auto stats = net.get_stats();
        std::cout << "Network Statistics:\n";
        std::cout << "  Packets sent: " << stats.packets_sent << "\n";
        std::cout << "  Packets received: " << stats.packets_received << "\n";
        std::cout << "  Bytes sent: " << stats.bytes_sent << "\n";
        std::cout << "  Bytes received: " << stats.bytes_received << "\n";
    }
    else {
        std::cerr << "[!] Unknown network action: " << action << "\n";
    }
}

void handle_license(const std::vector<std::string>& args) {
    std::string action = get_arg(args, 0);
    
    if (action.empty()) {
        std::cerr << "Usage: ncp license <action>\n";
        std::cerr << "Actions: hwid, info, validate, activate\n";
        return;
    }
    
    License lic;
    
    if (action == "hwid") {
        std::string hwid = lic.get_hwid();
        std::cout << "Hardware ID: " << hwid << "\n";
    }
    else if (action == "info") {
        std::string license_file = get_arg(args, 1, "license.key");
        auto info = lic.get_license_info(license_file);
        if (info.is_valid) {
            std::cout << "License Information:\n";
            std::cout << "  Type: " << static_cast<int>(info.type) << "\n";
            std::cout << "  Days remaining: " << info.days_remaining << "\n";
            std::cout << "  Valid: " << (info.is_valid ? "Yes" : "No") << "\n";
        } else {
            std::cerr << "[!] License file not found or invalid\n";
        }
    }
    else if (action == "validate") {
        std::string hwid = lic.get_hwid();
        std::string license_file = get_arg(args, 1, "license.key");
        auto result = lic.validate_offline(hwid, license_file);
        std::cout << "Validation result: ";
        if (result == License::ValidationResult::VALID) {
            std::cout << "VALID\n";
        } else {
            std::cout << "INVALID\n";
        }
    }
    else if (action == "activate") {
        std::cerr << "[!] License activation not yet implemented\n";
    }
    else {
        std::cerr << "[!] Unknown license action: " << action << "\n";
    }
}

void handle_dpi(const std::vector<std::string>& args) {
    std::cout << "[*] Configuring DPI bypass...\n";
    
    DPI::DPIConfig config;
    
    // Parse options
    config.mode = DPI::DPIMode::PROXY;
    config.listen_port = get_option_int(args, "--port", 8080);
    config.target_host = get_option(args, "--target", "example.com");
    config.target_port = get_option_int(args, "--target-port", 443);
    config.enable_tcp_split = !has_flag(args, "--no-split");
    config.split_position = get_option_int(args, "--split-pos", 2);
    config.enable_noise = !has_flag(args, "--no-noise");
    config.noise_size = get_option_int(args, "--noise-size", 64);
    config.enable_fake_packet = !has_flag(args, "--no-fake");
    config.fake_ttl = get_option_int(args, "--fake-ttl", 1);
    config.enable_disorder = !has_flag(args, "--no-disorder");
    
    std::string preset = get_option(args, "--preset");
    if (!preset.empty()) {
        DPI::DPIPreset p = DPI::preset_from_string(preset);
        DPI::apply_preset(p, config);
        std::cout << "[+] Applied preset: " << preset << "\n";
    }
    
    if (!config.is_valid()) {
        std::cerr << "[!] Invalid DPI configuration\n";
        return;
    }
    
    auto dpi = std::make_unique<DPI::DPIBypass>();
    if (!dpi->initialize(config)) {
        std::cerr << "[!] Failed to initialize DPI bypass\n";
        return;
    }
    
    if (!dpi->start()) {
        std::cerr << "[!] Failed to start DPI bypass\n";
        return;
    }
    
    std::cout << "[+] DPI bypass started on port " << config.listen_port << "\n";
    std::cout << "[+] Target: " << config.target_host << ":" << config.target_port << "\n";
    std::cout << "[+] TCP split: " << (config.enable_tcp_split ? "enabled" : "disabled") << "\n";
    std::cout << "[+] Noise injection: " << (config.enable_noise ? "enabled" : "disabled") << "\n";
    std::cout << "[+] Packet disorder: " << (config.enable_disorder ? "enabled" : "disabled") << "\n";
    
    g_dpi_bypass = std::move(dpi);
    g_running = true;
    
    std::cout << "\nPress Ctrl+C to stop\n";
    
    while (g_running) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}

void handle_i2p(const std::vector<std::string>& args) {
    std::string action = get_arg(args, 0);
    
    if (action.empty()) {
        std::cerr << "Usage: ncp i2p <action>\n";
        std::cerr << "Actions: start, stop, status\n";
        return;
    }
    
    static std::unique_ptr<I2PManager> i2p_mgr;
    
    if (action == "start") {
        std::cout << "[*] Starting I2P manager...\n";
        i2p_mgr = std::make_unique<I2PManager>();
        
        I2PManager::Config cfg;
        cfg.enabled = true;
        cfg.sam_host = get_option(args, "--sam-host", "127.0.0.1");
        cfg.sam_port = get_option_int(args, "--sam-port", 7656);
        cfg.enable_garlic_routing = true;
        cfg.tunnel_length = get_option_int(args, "--tunnel-length", 3);
        cfg.random_tunnel_selection = true;
        cfg.enable_encrypted_leaseset = true;
        
        if (!i2p_mgr->initialize(cfg)) {
            std::cerr << "[!] Failed to initialize I2P manager\n";
            return;
        }
        
        std::cout << "[+] I2P manager initialized\n";
        std::cout << "[+] SAM bridge: " << cfg.sam_host << ":" << cfg.sam_port << "\n";
        std::cout << "[+] Tunnel length: " << cfg.tunnel_length << " hops\n";
        std::cout << "[+] Garlic routing: enabled\n";
    }
    else if (action == "stop") {
        if (i2p_mgr) {
            i2p_mgr.reset();
            std::cout << "[+] I2P manager stopped\n";
        } else {
            std::cerr << "[!] I2P manager not running\n";
        }
    }
    else if (action == "status") {
        if (!i2p_mgr || !i2p_mgr->is_active()) {
            std::cout << "[I2P] Inactive\n";
            return;
        }
        
        auto stats = i2p_mgr->get_statistics();
        std::cout << "[I2P Status]\n";
        std::cout << "  Active tunnels: " << stats.active_tunnels << "\n";
        std::cout << "  Known routers: " << stats.known_routers << "\n";
        std::cout << "  Total sent: " << stats.total_sent << " bytes\n";
        std::cout << "  Total received: " << stats.total_received << " bytes\n";
        std::cout << "  Tunnel success rate: " << (stats.tunnel_success_rate * 100) << "%\n";
    }
    else {
        std::cerr << "[!] Unknown I2P action: " << action << "\n";
    }
}

void handle_mimic(const std::vector<std::string>& args) {
    std::string type = get_arg(args, 0);
    
    if (type.empty()) {
        std::cerr << "Usage: ncp mimic <type>\n";
        std::cerr << "Types: http, https, dns, quic, websocket, bittorrent, skype, zoom\n";
        return;
    }
    
    TrafficMimicry::MimicProfile profile;
    
    if (type == "http")
        profile = TrafficMimicry::MimicProfile::HTTP_GET;
    else if (type == "https")
        profile = TrafficMimicry::MimicProfile::HTTPS_APPLICATION;
    else if (type == "dns")
        profile = TrafficMimicry::MimicProfile::DNS_QUERY;
    else if (type == "quic")
        profile = TrafficMimicry::MimicProfile::QUIC_INITIAL;
    else if (type == "websocket")
        profile = TrafficMimicry::MimicProfile::WEBSOCKET;
    else if (type == "bittorrent")
        profile = TrafficMimicry::MimicProfile::BITTORRENT;
    else if (type == "skype")
        profile = TrafficMimicry::MimicProfile::SKYPE;
    else if (type == "zoom")
        profile = TrafficMimicry::MimicProfile::ZOOM;
    else {
        std::cerr << "[!] Unknown mimicry type: " << type << "\n";
        return;
    }
    
    TrafficMimicry::MimicConfig config;
    config.profile = profile;
    config.enable_timing_mimicry = true;
    config.enable_size_mimicry = true;
    config.enable_pattern_mimicry = true;
    config.randomize_fields = true;
    
    TrafficMimicry mimicry(config);
    
    std::cout << "[+] Traffic mimicry configured: " << type << "\n";
    std::cout << "[+] Timing mimicry: enabled\n";
    std::cout << "[+] Size mimicry: enabled\n";
    std::cout << "[+] Pattern mimicry: enabled\n";
    std::cout << "\nTraffic will be disguised as " << type << " protocol\n";
}
