#include <iostream>
#include <string>
#include <vector>
#include <csignal>
#include <atomic>
#include <thread>
#include <chrono>
#include "ncp_crypto.hpp"
#include "ncp_license.hpp"
#include "ncp_network.hpp"
#include "ncp_db.hpp"
#include "ncp_spoofer.hpp"
#include "ncp_dpi.hpp"
#include "ncp_i2p.hpp"

using namespace NCP;

// Global spoofer instance for signal handling
std::atomic<bool> g_running(false);
NetworkSpoofer* g_spoofer = nullptr;
DPI::DPIBypass* g_dpi_bypass = nullptr;

void signal_handler(int signal) {
    if (signal == SIGINT || signal == SIGTERM) {
        std::cout << "\n\n[!] Shutdown signal received. Restoring...\n";
        g_running = false;
    }
}

void print_usage() {
    std::cout << "NCP CLI v1.0.0 - Network Control Protocol\n"
              << "Usage: ncp <command> [options]\n\n"
              << "Commands:\n"
              << "  run <iface>    - Start full spoofing + DPI bypass\n"
              << "  stop           - Stop spoofing and restore\n"
              << "  status         - Show current spoof status\n"
              << "  rotate         - Rotate all identities\n"
              << "  crypto         - Cryptographic operations\n"
              << "  license        - License management\n"
              << "  network        - Network operations\n"
              << "  dpi            - DPI bypass proxy\n"
              << "  tor            - Configure Tor proxy (bridges/hops)\n"
              << "  i2p            - Configure I2P proxy\n"
              << "  mimic <type>   - Set traffic mimicry (http|tls|none)\n"
              << "  obfuscate      - Toggle advanced traffic mimicry\n"
              << "  dns-secure     - Toggle DNS leak protection\n"
              << "  help           - Show this help\n";
}

void handle_run(const std::vector<std::string>& args) {
    
    Network network;
    auto interfaces = network.get_interfaces();
    
    std::cout << "\nAvailable network interfaces:\n";
    for (size_t i = 0; i < interfaces.size(); ++i) {
        std::cout << "  [" << i << "] " << interfaces[i] << "\n";
    }
    
    std::string iface;
    if (args.size() >= 3) {
        iface = args[2];
    } else if (!interfaces.empty()) {
        std::cout << "\nSelect interface (0-" << interfaces.size()-1 << "): ";
        int idx;
        std::cin >> idx;
        if (idx >= 0 && idx < (int)interfaces.size()) {
            iface = interfaces[idx];
        } else {
            std::cout << "Invalid selection\n";
            return;
        }
    } else {
        std::cout << "No interfaces found\n";
        return;
    }
    
    // Setup signal handler
    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);
    
    NetworkSpoofer spoofer;
    g_spoofer = &spoofer;
    
    // Configure spoofing
    NetworkSpoofer::SpoofConfig config;
    config.spoof_ipv4 = true;
    config.spoof_ipv6 = true;
    config.spoof_mac = true;
    config.spoof_dns = true;
    
    std::cout << "\n==========================================\n";
    std::cout << "   NCP Network Spoofer - STARTING        \n";
    std::cout << "==========================================\n\n";
    
    std::cout << "[*] Enabling spoofing on: " << iface << "\n";
    
    if (!spoofer.enable(iface, config)) {
        std::cerr << "[-] Failed to enable spoofing!\n";
        return;
    }
    
    auto status = spoofer.get_status();
    std::cout << "\n[+] Spoofing ACTIVE:\n";
    std::cout << "  IPv4: " << (status.ipv4_spoofed ? status.current_ipv4 : "unchanged") << "\n";
    std::cout << "  IPv6: " << (status.ipv6_spoofed ? status.current_ipv6 : "unchanged") << "\n";
    std::cout << "  MAC:  " << (status.mac_spoofed ? status.current_mac : "unchanged") << "\n";
    std::cout << "  DNS:  " << (status.dns_spoofed ? "spoofed" : "unchanged") << "\n";
    
    std::cout << "\n==========================================\n";
    std::cout << "   Press Ctrl+C to stop and restore      \n";
    std::cout << "==========================================\n\n";

        // Start DPI bypass
    DPI::DPIConfig dpi_config;
    dpi_config.listen_port = 8080;
    dpi_config.fragment_size = 2;
    dpi_config.enable_fake_packet = true;
    dpi_config.enable_disorder = true;
    
    static DPI::DPIBypass dpi_bypass;
    g_dpi_bypass = &dpi_bypass;
    
    if (dpi_bypass.initialize(dpi_config) && dpi_bypass.start()) {
        std::cout << "    DPI: ACTIVE on port " << dpi_config.listen_port << "\n";
    } else {
        std::cout << "    DPI: FAILED\n";
    }
    
    g_running = true;
    int counter = 0;
    while (g_running) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        counter++;
        if (counter % 30 == 0) {
            std::cout << "[*] Running for " << counter << " seconds...\n";
        }
    }
    
// Stop DPI bypass
    if (g_dpi_bypass) {
        g_dpi_bypass->shutdown();
        std::cout << "[+] DPI Bypass stopped\n";
        g_dpi_bypass = nullptr;
    }


    std::cout << "\n[*] Disabling spoofing and restoring...\n";
    spoofer.disable();
    std::cout << "[+] Original settings restored!\n";
    g_spoofer = nullptr;
}
    

void handle_status() {
    if (g_spoofer && g_spoofer->is_enabled()) {
        auto status = g_spoofer->get_status();
        std::cout << "Spoofing: ACTIVE\n";
        std::cout << "  IPv4: " << status.current_ipv4 << "\n";
        std::cout << "  IPv6: " << status.current_ipv6 << "\n";
        std::cout << "  MAC:  " << status.current_mac << "\n";
    } else {
        std::cout << "Spoofing: INACTIVE\n";
    }
}

void handle_rotate() {
    if (g_spoofer && g_spoofer->is_enabled()) {
        std::cout << "[*] Rotating all identities...\n";
        if (g_spoofer->rotate_all()) {
            auto status = g_spoofer->get_status();
            std::cout << "[+] New identities:\n";
            std::cout << "  IPv4: " << status.current_ipv4 << "\n";
            std::cout << "  MAC:  " << status.current_mac << "\n";
        } else {
            std::cout << "[-] Rotation failed\n";
        }
    } else {
        std::cout << "Spoofing not active. Use 'ncp run' first.\n";
    }
}

void handle_stop() {
    if (g_spoofer && g_spoofer->is_enabled()) {
        std::cout << "[*] Stopping and restoring...\n";
        g_spoofer->disable();
        std::cout << "[+] Original settings restored!\n";
    } else {
        std::cout << "Spoofing not active.\n";
    }
}

void handle_crypto(const std::vector<std::string>& args) {
    Crypto crypto;
    if (args.size() < 3) {
        std::cout << "Usage: ncp crypto <keygen|random <size>>\n";
        return;
    }
    if (args[2] == "keygen") {
        auto kp = crypto.generate_keypair();
        std::cout << "Public: " << Crypto::bytes_to_hex(kp.public_key) << "\n";
        std::cout << "Secret: " << Crypto::bytes_to_hex(kp.secret_key) << "\n";
    } else if (args[2] == "random" && args.size() >= 4) {
        auto r = crypto.generate_random(std::stoi(args[3]));
        std::cout << Crypto::bytes_to_hex(r) << "\n";
    }
}

void handle_network(const std::vector<std::string>& args) {
    Network network;
    if (args.size() < 3) {
        std::cout << "Usage: ncp network <interfaces|stats>\n";
        return;
    }
    if (args[2] == "interfaces") {
        auto ifaces = network.get_interfaces();
        for (size_t i = 0; i < ifaces.size(); ++i)
            std::cout << "[" << i << "] " << ifaces[i] << "\n";
    } else if (args[2] == "stats") {
        auto s = network.get_stats();
        std::cout << "Sent: " << s.bytes_sent << " Recv: " << s.bytes_received << "\n";
    }
}

void handle_license(const std::vector<std::string>& args) {
    License license;
    if (args.size() < 3) {
        std::cout << "Usage: ncp license <hwid|info>\n";
        return;
    }
    if (args[2] == "hwid") {
        std::cout << "HWID: " << license.get_hwid() << "\n";
    } else if (args[2] == "info") {
        std::cout << "License: " << (license.get_license_info("license.dat").is_valid ? "Valid" : "Invalid") << "\n";
    }
}

void handle_dpi(const std::vector<std::string>& args) {
    DPI::DPIConfig config;
    config.mode = DPI::DPIMode::PROXY;
    config.listen_port = 8080;
    config.target_host = "";
    config.target_port = 443;
    config.fragment_size = 2;
    config.fragment_offset = 2;
    config.enable_fake_packet = true;
    config.enable_disorder = true;
    
    // Parse arguments
    for (size_t i = 2; i < args.size(); i++) {
        if (args[i] == "--port" && i + 1 < args.size()) {
            config.listen_port = std::stoi(args[++i]);
        } else if (args[i] == "--target" && i + 1 < args.size()) {
            config.target_host = args[++i];
        } else if (args[i] == "--target-port" && i + 1 < args.size()) {
            config.target_port = std::stoi(args[++i]);
        } else if (args[i] == "--fragment" && i + 1 < args.size()) {
            config.fragment_size = std::stoi(args[++i]);
        } else if (args[i] == "--mode" && i + 1 < args.size()) {
            std::string mode = args[++i];
            if (mode == "proxy") {
                config.mode = DPI::DPIMode::PROXY;
            } else if (mode == "passive") {
                config.mode = DPI::DPIMode::PASSIVE;
            } else {
                config.mode = DPI::DPIMode::DRIVER;
            }
        } else if ((args[i] == "--preset" || args[i] == "--profile") && i + 1 < args.size()) {
            auto preset = DPI::preset_from_string(args[++i]);
            if (preset != DPI::DPIPreset::NONE) {
                DPI::apply_preset(preset, config);
            }
        } else if (args[i] == "--split-position" && i + 1 < args.size()) {
            config.split_position = std::stoi(args[++i]);
        } else if (args[i] == "--split-at-sni") {
            config.split_at_sni = true;
        } else if (args[i] == "--no-split-at-sni") {
            config.split_at_sni = false;
        } else if (args[i] == "--fragment-size" && i + 1 < args.size()) {
            config.fragment_size = std::stoi(args[++i]);
        } else if (args[i] == "--enable-fake") {
            config.enable_fake_packet = true;
        } else if (args[i] == "--disable-fake" || args[i] == "--no-fake") {
            config.enable_fake_packet = false;
        } else if (args[i] == "--enable-disorder") {
            config.enable_disorder = true;
        } else if (args[i] == "--disable-disorder" || args[i] == "--no-disorder") {
            config.enable_disorder = false;
        }
    }
    
    std::cout << "\n==========================================\n";
    std::cout << "   NCP DPI Bypass Proxy - STARTING        \n";
    std::cout << "==========================================\n\n";
    std::cout << "[*] Configuration:\n";
    std::cout << "  Mode:         "
              << (config.mode == DPI::DPIMode::DRIVER ? "driver" :
                  config.mode == DPI::DPIMode::PROXY  ? "proxy"  : "passive")
              << "\n";
    std::cout << "  Listen port:  " << config.listen_port << "\n";
    std::cout << "  Target host:  "
              << (config.target_host.empty() ? "<required in proxy mode>" : config.target_host)
              << "\n";
    std::cout << "  Target port:  " << config.target_port << "\n";
    std::cout << "  Fragment:     " << config.fragment_size << " bytes\n";
    std::cout << "  Split at SNI: " << (config.split_at_sni ? "yes" : "no") << "\n";
    std::cout << "  Fake packets: " << (config.enable_fake_packet ? "enabled" : "disabled") << "\n";
    std::cout << "  Disorder:     " << (config.enable_disorder ? "enabled" : "disabled") << "\n\n";
    
    DPI::DPIBypass bypass;
    bypass.set_log_callback([](DPI::LogLevel /*level*/, const std::string& msg) {
        std::cout << "[DPI] " << msg << "\n";
    });
    if (!bypass.initialize(config)) {
        std::cerr << "[-] Failed to initialize DPI bypass!\n";
        return;
    }
    
    if (!bypass.start()) {
        std::cerr << "[-] Failed to start DPI bypass!\n";
        return;
    }
    
    std::cout << "[+] DPI Bypass proxy started on port " << config.listen_port << "\n";
    std::cout << "[*] DPI bypass running in driver mode (nfqueue)\n";
    std::cout << "[*] Press Ctrl+C to stop\n\n";    
    g_running = true;
    while (g_running) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    
    bypass.shutdown();
    std::cout << "[+] DPI Bypass stopped\n";
}

void handle_i2p(const std::vector<std::string>& args) {
    I2PManager i2p;
    I2PManager::Config config;
    
    if (args.size() < 3) {
        std::cout << "Usage: ncp i2p <status|enable|disable|tunnel>\n";
        return;
    }

    if (args[2] == "enable") {
        config.enabled = true;
        i2p.initialize(config);
        std::cout << "[+] I2P Integration enabled. Destination: " << i2p.get_destination() << "\n";
    } else if (args[2] == "disable") {
        i2p.set_enabled(false);
        std::cout << "[+] I2P Integration disabled\n";
    } else if (args[2] == "status") {
        std::cout << "I2P Status: " << (i2p.is_active() ? "ACTIVE" : "INACTIVE") << "\n";
        if (i2p.is_active()) {
            std::cout << "Destination: " << i2p.get_destination() << "\n";
        }
    }
}

int main(int argc, char* argv[]) {
    std::vector<std::string> args(argv, argv + argc);
    
    if (argc < 2) {
        print_usage();
        return 0;
    }
    
    std::string cmd = args[1];
    
    if (cmd == "help" || cmd == "-h") print_usage();
    else if (cmd == "run") handle_run(args);
    else if (cmd == "stop") handle_stop();
    else if (cmd == "status") handle_status();
    else if (cmd == "rotate") handle_rotate();
    else if (cmd == "crypto") handle_crypto(args);
    else if (cmd == "network") handle_network(args);
    else if (cmd == "license") handle_license(args);
    else if (cmd == "dpi") handle_dpi(args);
    else if (cmd == "i2p") handle_i2p(args);
    else if (cmd == "mimic") {
        if (args.size() < 3) {
            std::cout << "Usage: ncp mimic <http|tls|none>\n";
        } else {
            Network network;
            if (args[2] == "http") {
                network.enable_bypass(BypassTechnique::HTTP_MIMICRY);
                std::cout << "[+] HTTP Mimicry enabled\n";
            } else if (args[2] == "tls") {
                network.enable_bypass(BypassTechnique::TLS_MIMICRY);
                std::cout << "[+] TLS Mimicry enabled\n";
            } else {
                network.disable_bypass();
                std::cout << "[+] Mimicry disabled\n";
            }
        }
    }
    else {
        std::cout << "Unknown: " << cmd << ". Use 'ncp help'\n";
        return 1;
    }
    return 0;
}
