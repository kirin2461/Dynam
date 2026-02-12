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
#include "ncp_paranoid.hpp"
#include "ncp_security.hpp"
#include "ncp_tls_fingerprint.hpp"
#include "ncp_secure_memory.hpp"

using namespace ncp;

// Global spoofer instance for signal handling
std::atomic<bool> g_running(false);
NetworkSpoofer* g_spoofer = nullptr;
DPI::DPIBypass* g_dpi_bypass = nullptr;
ParanoidMode* g_paranoid = nullptr;

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
              << "  run <iface>    - Start PARANOID mode (all protection layers)\n"
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

        // === PARANOID MODE: Enable all protection layers ===
    static ParanoidMode paranoid;
    g_paranoid = &paranoid;

    // Set maximum threat level (TINFOIL_HAT = all features enabled)
    paranoid.set_threat_level(ParanoidMode::ThreatLevel::TINFOIL_HAT);

    // Layer 1-2: Entry obfuscation + Multiple anonymization networks
    ParanoidMode::LayeredConfig layered;
    layered.use_bridge_nodes = true;
    layered.rotate_entry_guards = true;
    layered.entry_guard_lifetime_hours = 6;
    layered.enable_tor_over_i2p = true;
    layered.enable_vpn_chain = true;
    layered.vpn_chain_count = 2;
    // Layer 3: Traffic obfuscation
    layered.enable_constant_rate_traffic = true;
    layered.cover_traffic_rate_kbps = 128;
    layered.enable_traffic_morphing = true;
    layered.randomize_packet_sizes = true;
    // Layer 4: Timing attacks prevention
    layered.enable_random_delays = true;
    layered.min_delay_ms = 50;
    layered.max_delay_ms = 500;
    layered.enable_batching = true;
    layered.batch_size = 10;
    // Layer 5: Metadata stripping
    layered.strip_all_metadata = true;
    layered.sanitize_headers = true;
    layered.remove_fingerprints = true;
    // Layer 6: Advanced crypto
    layered.enable_post_quantum_crypto = true;
    layered.enable_forward_secrecy = true;
    layered.enable_deniable_encryption = true;
    layered.rekeying_interval_minutes = 15;
    // Layer 7: Anti-correlation
    layered.enable_traffic_splitting = true;
    layered.use_multiple_circuits = true;
    layered.simultaneous_circuits = 3;
    layered.disable_circuit_reuse = true;
    // Layer 8: System-level protection
    layered.enable_memory_wiping = true;
    layered.disable_disk_cache = true;
    layered.disable_swap = true;
    layered.enable_secure_delete = true;
    paranoid.set_layered_config(layered);

    // Network isolation (prevent all leaks)
    ParanoidMode::NetworkIsolation net_iso;
    net_iso.block_ipv6 = true;
    net_iso.block_webrtc = true;
    net_iso.block_local_connections = true;
    net_iso.force_dns_over_anonymizer = true;
    net_iso.isolate_per_domain = true;
    net_iso.isolate_per_tab = true;
    net_iso.prevent_cross_origin_leaks = true;
    net_iso.enable_kill_switch = true;
    net_iso.block_on_vpn_drop = true;
    net_iso.block_on_tor_drop = true;
    paranoid.set_network_isolation(net_iso);

    // Forensic resistance
    ParanoidMode::ForensicResistance forensic;
    forensic.encrypt_memory = true;
    forensic.clear_memory_on_exit = true;
    forensic.prevent_memory_dumps = true;
    forensic.encrypt_temp_files = true;
    forensic.secure_delete_on_exit = true;
    forensic.overwrite_passes = 7;
    forensic.disable_all_logging = true;
    forensic.encrypt_logs = true;
    forensic.disable_crash_dumps = true;
    paranoid.set_forensic_resistance(forensic);

    // Traffic analysis resistance
    ParanoidMode::TrafficAnalysisResistance tar;
    tar.enable_packet_padding = true;
    tar.pad_to_fixed_size = true;
    tar.fixed_packet_size = 1500;
    tar.enable_constant_rate = true;
    tar.enable_burst_suppression = true;
    tar.enable_traffic_shaping = true;
    tar.inject_dummy_packets = true;
    tar.randomize_order = true;
    tar.split_across_circuits = true;
    tar.enable_wfp_defense = true;
    paranoid.set_traffic_analysis_resistance(tar);

    // Advanced features
    ParanoidMode::AdvancedFeatures adv;
    adv.use_obfs4 = true;
    adv.use_meek = true;
    adv.use_snowflake = true;
    paranoid.set_advanced_features(adv);

    // Activate paranoid mode
    if (paranoid.activate()) {
        std::cout << "\n[+] PARANOID MODE: ACTIVE (TINFOIL_HAT)\n";
        std::cout << "    Layer 1: Entry obfuscation (bridge nodes + guard rotation)\n";
        std::cout << "    Layer 2: Multi-anonymization (VPN -> Tor -> I2P)\n";
        std::cout << "    Layer 3: Traffic obfuscation (constant rate + morphing)\n";
        std::cout << "    Layer 4: Timing protection (random delays + batching)\n";
        std::cout << "    Layer 5: Metadata stripping (headers + fingerprints)\n";
        std::cout << "    Layer 6: Advanced crypto (post-quantum + forward secrecy)\n";
        std::cout << "    Layer 7: Anti-correlation (traffic splitting + multi-circuit)\n";
        std::cout << "    Layer 8: System protection (memory wipe + secure delete)\n";
        std::cout << "    Network isolation: kill switch + leak prevention\n";
        std::cout << "    Forensic resistance: encrypted memory + no logs\n";
        std::cout << "    Traffic analysis resistance: padding + WFP defense\n";
    } else {
        std::cout << "\n[!] PARANOID MODE: FAILED to activate (some layers may be unavailable)\n";
    }

    // Start cover traffic and monitoring
    paranoid.start_cover_traffic();
    paranoid.enable_constant_rate_shaping(128);
    
    g_running = true;
    int counter = 0;
    while (g_running) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        counter++;
        if (counter % 30 == 0) {
            std::cout << "[*] Running for " << counter << " seconds...\n";
        }
    }

        // Stop paranoid mode
    if (g_paranoid) {
        g_paranoid->stop_cover_traffic();
        g_paranoid->clear_all_traces();
        g_paranoid->deactivate();
        std::cout << "[+] Paranoid mode deactivated, all traces cleared\n";
        g_paranoid = nullptr;
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
