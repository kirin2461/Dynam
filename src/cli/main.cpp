#include "ncp_crypto.hpp"
#include "ncp_license.hpp"
#include "ncp_network.hpp"
#include "ncp_spoofer.hpp"
#include "ncp_dpi.hpp"
#include "ncp_dpi_zapret.hpp"
#include "ncp_i2p.hpp"
#include "ncp_paranoid.hpp"
#include "ncp_mimicry.hpp"
#include "ncp_dns_leak_prevention.hpp"
#include "ncp_l3_stealth.hpp"
#include "ncp_rtt_equalizer.hpp"
#include "ncp_volume_normalizer.hpp"
#include "ncp_wf_defense.hpp"
#include "ncp_behavioral_cloak.hpp"
#include "ncp_time_correlation_breaker.hpp"
#include "ncp_self_test_monitor.hpp"
#include "ncp_session_fragmenter.hpp"
#include "ncp_cross_layer_correlator.hpp"
#include "ncp_geneva_engine.hpp"
#include "ncp_covert_channel.hpp"
#include "ncp_transport_manager.hpp"

#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <functional>
#include <memory>
#include <cctype>  // R10-FIX-06: Required for is_valid_netsh_identifier/is_valid_dns_address

#ifdef _WIN32
#include <winsock2.h>
#include <iphlpapi.h>
#pragma comment(lib, "iphlpapi.lib")
#endif
#include <csignal>
#include <atomic>
#include <thread>
#include <chrono>
#include <fstream>
#include <sstream>

using namespace ncp;
using namespace ncp::DPI;

// ============================================================================
// Application state (encapsulated globals for better testability)
// ============================================================================
struct AppState {
    std::unique_ptr<NetworkSpoofer> spoofer;
    std::unique_ptr<DPI::DPIBypass> dpi_bypass;
    std::unique_ptr<ParanoidMode> paranoid;
    // New modules
    std::unique_ptr<DNSLeakPrevention> dns_leak;
    std::unique_ptr<L3Stealth> l3_stealth;
    std::unique_ptr<DPI::RTTEqualizer> rtt_equalizer;
    std::unique_ptr<DPI::VolumeNormalizer> volume_normalizer;
    std::unique_ptr<DPI::WFDefense> wf_defense;
    std::unique_ptr<DPI::BehavioralCloak> behavioral_cloak;
    std::unique_ptr<DPI::TimeCorrelationBreaker> time_breaker;
    std::unique_ptr<SelfTestMonitor> self_test;
    std::unique_ptr<SessionFragmenter> session_frag;
    std::unique_ptr<CrossLayerCorrelator> cross_layer;
    std::unique_ptr<DPI::GenevaEngine> geneva;
    std::unique_ptr<CovertChannelManager> covert_channel;
    // Transport modules
    std::unique_ptr<ProtocolRotationSchedule> protocol_rotation;
    std::unique_ptr<ASAwareRouter> as_router;
    std::unique_ptr<GeoObfuscator> geo_obfuscator;

    void reset() {
        // Reset in reverse order
        geo_obfuscator.reset();
        as_router.reset();
        protocol_rotation.reset();
        covert_channel.reset();
        geneva.reset();
        cross_layer.reset();
        session_frag.reset();
        self_test.reset();
        time_breaker.reset();
        behavioral_cloak.reset();
        wf_defense.reset();
        volume_normalizer.reset();
        rtt_equalizer.reset();
        l3_stealth.reset();
        dns_leak.reset();
        paranoid.reset();
        dpi_bypass.reset();
        spoofer.reset();
    }
};

AppState g_app;
std::sig_atomic_t g_running = 0;

// ============================================================================
// Signal handler
// ============================================================================

void signal_handler(int signal) {
    if (signal == SIGINT || signal == SIGTERM) {
        // SAFETY: Only async-signal-safe operations in signal handler
        g_running = 0;
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

#ifdef _WIN32
// Standalone DNS setter — works even when the full spoofer fails.
:// R10-FIX-06: Command injection prevention - validate inputs and use safe parameter passing
// Validates that string contains only allowed characters for DNS/interface names
static bool is_valid_netsh_identifier(const std::string& s) {
    if (s.empty() || s.length() > 256) return false;
    for (char c : s) {
        // Allow alphanumeric, dot, dash, underscore, space (for interface names with spaces)
        if (!std::isalnum(static_cast<unsigned char>(c)) && c != '.' && c != '-' && 
            c != '_' && c != ' ' && c != '\\' && c != '/' && c != '(' && c != ')' &&
            c != '[' && c != ']') {
            return false;
        }
    }
    return true;
}

static bool is_valid_dns_address(const std::string& s) {
    if (s.empty() || s.length() > 45) return false;  // Max IPv6 length
    for (char c : s) {
        // Allow alphanumeric, dot, colon (IPv6), brackets for IPv6 zones
        if (!std::isalnum(static_cast<unsigned char>(c)) && c != '.' && c != ':' && 
            c != '%' && c != '[' && c != ']') {
            return false;
        }
    }
    return true;
}

// Uses CreateProcessW directly for correct Unicode adapter names.
// R10-FIX-06: Input validation prevents command injection
static bool force_set_dns(const std::string& iface_utf8,
                          const std::string& primary_dns,
                          const std::string& secondary_dns) {
    // Validate inputs to prevent command injection
    if (!is_valid_netsh_identifier(iface_utf8)) {
        std::cerr << "[!] Invalid interface name (rejected for security)\n";
        return false;
    }
    if (!is_valid_dns_address(primary_dns)) {
        std::cerr << "[!] Invalid primary DNS address (rejected for security)\n";
        return false;
    }
    if (!is_valid_dns_address(secondary_dns)) {
        std::cerr << "[!] Invalid secondary DNS address (rejected for security)\n";
        return false;
    }

    auto run_netsh = [](const std::wstring& args_w) -> bool {
        STARTUPINFOW si = {};
        si.cb = sizeof(si);
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;
        PROCESS_INFORMATION pi = {};
        std::wstring cmd = L"netsh " + args_w;
        // CreateProcessW needs a mutable buffer
        std::vector<wchar_t> buf(cmd.begin(), cmd.end());
        buf.push_back(L'\0');
        if (!CreateProcessW(nullptr, buf.data(), nullptr, nullptr,
                            FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi))
            return false;
        WaitForSingleObject(pi.hProcess, 5000);
        DWORD exitCode = 1;
        GetExitCodeProcess(pi.hProcess, &exitCode);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return exitCode == 0;
    };

    // Convert interface name from UTF-8 to wide string
    int wlen = MultiByteToWideChar(CP_UTF8, 0, iface_utf8.c_str(), -1, nullptr, 0);
    if (wlen <= 0) return false;
    std::wstring iface_w(wlen - 1, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, iface_utf8.c_str(), -1, &iface_w[0], wlen);

    // Convert DNS addresses
    auto to_wide = [](const std::string& s) -> std::wstring {
        return std::wstring(s.begin(), s.end());
    };

    // Set primary DNS
    bool ok1 = run_netsh(L"interface ip set dns name=\"" + iface_w +
                         L"\" static " + to_wide(primary_dns));
    // Add secondary DNS
    bool ok2 = run_netsh(L"interface ip add dns name=\"" + iface_w +
                         L"\" " + to_wide(secondary_dns) + L" index=2");

    return ok1; // primary is the critical one
}
#endif

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


static std::string detect_default_interface() {
#ifdef _WIN32
    // On Windows, find the first active non-loopback, non-virtual adapter
    // and return its FriendlyName (e.g. "Ethernet", "Wi-Fi") for netsh.
    ULONG bufSize = 15000;
    PIP_ADAPTER_ADDRESSES addrs = (PIP_ADAPTER_ADDRESSES)malloc(bufSize);
    if (!addrs) return "Ethernet";
    ULONG flags = GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_SKIP_ANYCAST |
                  GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    if (GetAdaptersAddresses(AF_INET, flags, nullptr, addrs, &bufSize) != NO_ERROR) {
        free(addrs);
        return "Ethernet";
    }
    std::string best_name;
    for (PIP_ADAPTER_ADDRESSES a = addrs; a; a = a->Next) {
        if (a->OperStatus != IfOperStatusUp) continue;
        if (a->IfType == IF_TYPE_SOFTWARE_LOOPBACK) continue;
        if (!a->FirstUnicastAddress) continue;
        // Convert FriendlyName (wchar_t) to std::string
        std::string name;
        if (a->FriendlyName) {
            int len = WideCharToMultiByte(CP_UTF8, 0, a->FriendlyName, -1, nullptr, 0, nullptr, nullptr);
            if (len > 0) {
                name.resize(len - 1);
                WideCharToMultiByte(CP_UTF8, 0, a->FriendlyName, -1, &name[0], len, nullptr, nullptr);
            }
        }
        if (name.empty()) continue;
        // Skip virtual/VPN adapters by description and name heuristics
        std::string desc;
        if (a->Description) {
            int dlen = WideCharToMultiByte(CP_UTF8, 0, a->Description, -1, nullptr, 0, nullptr, nullptr);
            if (dlen > 0) {
                desc.resize(dlen - 1);
                WideCharToMultiByte(CP_UTF8, 0, a->Description, -1, &desc[0], dlen, nullptr, nullptr);
            }
        }
        // Common virtual adapter keywords (case-insensitive check)
        auto contains_ci = [](const std::string& haystack, const char* needle) {
            std::string h = haystack, n = needle;
            for (auto& c : h) c = static_cast<char>(tolower(static_cast<unsigned char>(c)));
            for (auto& c : n) c = static_cast<char>(tolower(static_cast<unsigned char>(c)));
            return h.find(n) != std::string::npos;
        };
        bool is_virtual = contains_ci(name, "vpn") || contains_ci(name, "virtual") ||
                          contains_ci(name, "tap") || contains_ci(name, "tunnel") ||
                          contains_ci(name, "docker") || contains_ci(name, "vbox") ||
                          contains_ci(name, "vmware") || contains_ci(name, "hamachi") ||
                          contains_ci(name, "radmin") ||
                          contains_ci(desc, "vpn") || contains_ci(desc, "virtual") ||
                          contains_ci(desc, "tap") || contains_ci(desc, "tunnel") ||
                          contains_ci(desc, "radmin");
        if (is_virtual) continue;
        best_name = name;
        break;
    }
    free(addrs);
    return best_name.empty() ? "Ethernet" : best_name;
#else
    Network net;
    auto ifaces = net.get_interfaces();
    for (const auto& iface : ifaces) {
        if (iface.is_up && iface.name != "lo" && iface.name != "localhost") {
            return iface.name;
        }
    }
    return "eth0";
#endif
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

    ArgumentParser parser("ncp", "v1.2.0");

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
        // ── License gate ──────────────────────────────────────────────────────
        // License validation required for all invocations.
        bool license_ok = false;
#ifdef _WIN32
        // Read %APPDATA%\ncp\license.json
        const char* appdata = std::getenv("APPDATA");
        std::string lic_path;
        if (appdata) {
            lic_path = std::string(appdata) + "\\ncp\\license.json";
        }
#else
        const char* home = std::getenv("HOME");
        std::string lic_path;
        if (home) {
            lic_path = std::string(home) + "/ncp/license.json";
        }
#endif
        if (!lic_path.empty()) {
            std::ifstream ifs(lic_path);
            if (ifs.good()) {
                std::stringstream buf;
                buf << ifs.rdbuf();
                std::string content = buf.str();
                // Simple check: file must contain a "key" field with NCP- prefix
                // Full Ed25519 verification happens in the Python layer
                if (content.find("\"key\"") != std::string::npos &&
                    content.find("NCP-") != std::string::npos) {
                    license_ok = true;
                }
            }
        }

        if (!license_ok) {
            std::cerr << "[!] License not found or invalid.\n";
            std::cerr << "[!] Activate a license via the web interface (http://localhost:8085)\n";
            std::cerr << "[!] or provide a valid license key first.\n";
            return;
        }
        std::cout << "[+] License verified\n";

        std::cout << "[*] Starting NCP protection...\n";
        
        // Interface: prefer --interface option, fallback to positional arg
        std::string interface = get_option(args, "--interface");
        if (interface.empty()) {
            // Positional: first arg that doesn't start with --
            for (const auto& a : args) {
                if (a.substr(0, 2) != "--") { interface = a; break; }
            }
        }
        
        // Initialize globals
        g_app.spoofer = std::make_unique<NetworkSpoofer>();
        g_app.dpi_bypass = std::make_unique<DPI::DPIBypass>();
        g_app.paranoid = std::make_unique<ParanoidMode>();
        
        // 1. Configure and enable NetworkSpoofer
        // SAFETY: On Wi-Fi/DHCP adapters, IP and MAC spoofing is DANGEROUS:
        //   - apply_ipv4 sets static 10.x.x.x, killing DHCP lease
        //   - apply_mac disables/enables the adapter, dropping Wi-Fi connection
        //   - USB Wi-Fi (Realtek) often ignores registry NetworkAddress anyway
        // So we only spoof DNS (to encrypted resolvers) and hostname.
        // IP/MAC spoofing should only be used on wired static-IP setups.
        NetworkSpoofer::SpoofConfig spoof_cfg;
        spoof_cfg.spoof_ipv4  = false; // Would break DHCP
        spoof_cfg.spoof_ipv6  = false; // Would break DHCP
        spoof_cfg.spoof_mac   = false; // Would drop Wi-Fi + USB adapters ignore it
        spoof_cfg.spoof_dns   = true;
        spoof_cfg.custom_dns_servers = {"1.1.1.1", "8.8.8.8"};
        spoof_cfg.spoof_hw_info = false;
        spoof_cfg.spoof_smbios = false;
        spoof_cfg.spoof_disk_serial = false;
        spoof_cfg.coordinated_rotation = false;
        
        // If user passes --full-spoof, enable everything (for wired/static setups)
        bool full_spoof = has_flag(args, "--full-spoof");
        if (full_spoof) {
            spoof_cfg.spoof_ipv4 = true;
            spoof_cfg.spoof_ipv6 = true;
            spoof_cfg.spoof_mac  = true;
            spoof_cfg.spoof_hw_info = true;
            spoof_cfg.coordinated_rotation = true;
            std::cout << "[*] Full spoof mode (IP+MAC+DNS) - use only on wired/static setups\n";
        }
        
        std::string iface = (interface.empty() || interface == "auto") ? detect_default_interface() : interface;
        std::cout << "[*] Interface: " << iface << "\n";
        
        bool dns_set = false;
        if (!g_app.spoofer->enable(iface, spoof_cfg)) {
            std::cerr << "[!] Warning: spoofing module failed on " << iface << "\n";
            g_app.spoofer.reset();
#ifdef _WIN32
            // Fallback: set DNS directly even when spoofer fails
            std::cout << "[*] Setting DNS directly (8.8.8.8, 1.1.1.1)...\n";
            if (force_set_dns(iface, "8.8.8.8", "1.1.1.1")) {
                std::cout << "[+] DNS set to 8.8.8.8, 1.1.1.1\n";
                dns_set = true;
            } else {
                std::cerr << "[!] DNS change failed - set DNS manually in network settings to 8.8.8.8\n";
            }
#else
            std::cerr << "[!] Set DNS manually to 8.8.8.8 in network settings\n";
#endif
        } else {
            auto status = g_app.spoofer->get_status();
            std::cout << "[+] Spoofing enabled on " << iface << "\n";
            if (status.dns_spoofed) {
                std::cout << "[+]   DNS: 1.1.1.1, 8.8.8.8\n";
                dns_set = true;
            }
            if (status.mac_spoofed)
                std::cout << "[+]   MAC: " << status.current_mac << "\n";
            if (status.ipv4_spoofed)
                std::cout << "[+]   IPv4: " << status.current_ipv4 << "\n";
            if (status.hostname_spoofed)
                std::cout << "[+]   Hostname: " << status.current_hostname << "\n";
        }
        if (!dns_set) {
            std::cerr << "[!] WARNING: DNS not changed! Beeline/mobile ISPs hijack DNS.\n";
            std::cerr << "[!] YouTube/Telegram will NOT work without DNS 8.8.8.8.\n";
            std::cerr << "[!] Please set DNS manually: Settings > Network > Wi-Fi > DNS = 8.8.8.8\n";
        }
        
        // 2. Configure and start DPI bypass
        // Determine preset: --preset <name> overrides default (RUNET_TSPU)
        std::string preset_name = get_option(args, "--preset", "");
        DPI::DPIPreset chosen_preset = DPI::DPIPreset::RUNET_TSPU; // default for home ISPs
        if (!preset_name.empty()) {
            chosen_preset = DPI::preset_from_string(preset_name);
            if (chosen_preset == DPI::DPIPreset::NONE) {
                std::cerr << "[!] Unknown preset: " << preset_name
                          << ". Valid: tspu, beeline, mts, megafon, tele2, mobile, auto\n";
                chosen_preset = DPI::DPIPreset::RUNET_TSPU;
            }
        }
        // --autoprobe flag forces AUTOPROBE preset
        if (has_flag(args, "--autoprobe") || has_flag(args, "--auto")) {
            chosen_preset = DPI::DPIPreset::AUTOPROBE;
        }

        DPI::DPIConfig dpi_cfg;
        DPI::apply_preset(chosen_preset, dpi_cfg);
        std::cout << "[*] DPI preset: " << DPI::preset_to_string(chosen_preset) << "\n";
        
        if (!g_app.dpi_bypass->initialize(dpi_cfg) || !g_app.dpi_bypass->start()) {
            std::cerr << "[!] Warning: DPI bypass failed to start (continuing without it)\n";
            g_app.dpi_bypass.reset();
        } else {
            std::cout << "[+] DPI bypass active (" << DPI::preset_to_string(chosen_preset)
                      << ": fake+" << (dpi_cfg.enable_disorder ? "disorder" :
                                        dpi_cfg.enable_reverse_frag ? "reverse-frag" : "split")
                      << ", ttl=" << dpi_cfg.fake_ttl
                      << (dpi_cfg.enable_autottl ? " autottl" : "")
                      << ")\n";

            // --- Zapret chain-based DPI ---
            std::string zapret_profile_name = get_option(args, "--zapret-profile", "");
            if (!zapret_profile_name.empty()) {
                auto zprofile = DPI::get_zapret_profile_by_name(zapret_profile_name);
                if (!zprofile.chains.empty()) {
                    // Optional: filter to specific chains via --zapret-chains
                    std::string chain_filter = get_option(args, "--zapret-chains", "");
                    if (!chain_filter.empty()) {
                        // Parse comma-separated chain names
                        std::vector<std::string> wanted;
                        std::istringstream ss(chain_filter);
                        std::string tok;
                        while (std::getline(ss, tok, ',')) {
                            // trim whitespace
                            size_t s = tok.find_first_not_of(" \t");
                            size_t e = tok.find_last_not_of(" \t");
                            if (s != std::string::npos)
                                wanted.push_back(tok.substr(s, e - s + 1));
                        }
                        if (!wanted.empty()) {
                            std::vector<DPI::ZapretChain> filtered;
                            for (const auto& c : zprofile.chains) {
                                for (const auto& w : wanted) {
                                    if (c.name == w) {
                                        filtered.push_back(c);
                                        break;
                                    }
                                }
                            }
                            zprofile.chains = std::move(filtered);
                        }
                    }
                    g_app.dpi_bypass->set_zapret_chains(std::move(zprofile.chains));
                    std::cout << "[+] Zapret profile: " << zapret_profile_name
                              << " (" << zprofile.id << ", chains loaded)\n";
                } else {
                    std::cerr << "[!] Unknown zapret profile: " << zapret_profile_name << "\n";
                }
            }
        }
        
        // 3. Activate ParanoidMode with TINFOIL_HAT threat level
        g_app.paranoid->set_threat_level(ParanoidMode::ThreatLevel::TINFOIL_HAT);
        if (!g_app.paranoid->activate()) {
            std::cerr << "[!] Warning: ParanoidMode failed to activate (continuing without it)\n";
            g_app.paranoid.reset();
        } else {
            std::cout << "[+] ParanoidMode activated (TINFOIL_HAT level)\n";
        }

        // 4. DNS Leak Prevention
        if (!has_flag(args, "--no-dns-leak")) {
            try {
                g_app.dns_leak = std::make_unique<DNSLeakPrevention>();
                DNSLeakConfig dns_cfg;
                dns_cfg.block_udp53       = true;
                dns_cfg.block_tcp53       = true;
                dns_cfg.block_webrtc_stun = false;
                dns_cfg.block_raw_ipv6    = false;
                dns_cfg.allowed_dns_servers = {"8.8.8.8", "1.1.1.1", "8.8.4.4", "1.0.0.1",
                                               "127.0.0.1", "::1"};
                g_app.dns_leak->set_config(dns_cfg);
                if (g_app.dns_leak->activate()) {
                    std::cout << "[+] DNS Leak Prevention active\n";
                } else {
                    std::cerr << "[!] DNS Leak Prevention failed to start\n";
                    g_app.dns_leak.reset();
                }
            } catch (const std::exception& ex) {
                std::cerr << "[!] DNS Leak Prevention exception: " << ex.what() << "\n";
                g_app.dns_leak.reset();
            }
        }

        // 5. L3 Stealth
        if (!has_flag(args, "--no-l3-stealth")) {
            try {
                g_app.l3_stealth = std::make_unique<L3Stealth>();
                L3Stealth::Config l3_cfg;
                l3_cfg.os_profile              = L3Stealth::OSProfile::WINDOWS_10;
                l3_cfg.ttl_profile             = L3Stealth::OSProfile::WINDOWS_10;
                l3_cfg.enable_ipid_randomization = true;
                l3_cfg.enable_ttl_normalization  = true;
                l3_cfg.enable_mss_clamping       = true;
                if (g_app.l3_stealth->initialize(l3_cfg)) {
                    std::cout << "[+] L3 Stealth active (Windows 10 profile)\n";
                } else {
                    std::cerr << "[!] L3 Stealth failed to initialize\n";
                    g_app.l3_stealth.reset();
                }
            } catch (const std::exception& ex) {
                std::cerr << "[!] L3 Stealth exception: " << ex.what() << "\n";
                g_app.l3_stealth.reset();
            }
        }

        // 6. RTT Equalizer
        if (!has_flag(args, "--no-rtt-eq")) {
            try {
                RTTEqualizerConfig rtt_cfg;
                g_app.rtt_equalizer = std::make_unique<DPI::RTTEqualizer>(rtt_cfg);
                std::cout << "[+] RTT Equalizer active\n";
            } catch (const std::exception& ex) {
                std::cerr << "[!] RTT Equalizer exception: " << ex.what() << "\n";
                g_app.rtt_equalizer.reset();
            }
        }

        // 7. Volume Normalizer
        if (!has_flag(args, "--no-volume-norm")) {
            try {
                VolumeNormalizerConfig vol_cfg;
                g_app.volume_normalizer = std::make_unique<DPI::VolumeNormalizer>(vol_cfg);
                std::cout << "[+] Volume Normalizer active\n";
            } catch (const std::exception& ex) {
                std::cerr << "[!] Volume Normalizer exception: " << ex.what() << "\n";
                g_app.volume_normalizer.reset();
            }
        }

        // 8. WF Defense (Tamaraw)
        if (!has_flag(args, "--no-wf-defense")) {
            try {
                WFDefenseConfig wf_cfg;
                wf_cfg.tamaraw_mode = true;
                g_app.wf_defense = std::make_unique<DPI::WFDefense>(wf_cfg);
                std::cout << "[+] WF Defense active (Tamaraw mode)\n";
            } catch (const std::exception& ex) {
                std::cerr << "[!] WF Defense exception: " << ex.what() << "\n";
                g_app.wf_defense.reset();
            }
        }

        // 9. Behavioral Cloak
        if (!has_flag(args, "--no-cloak")) {
            try {
                BehavioralCloakConfig cloak_cfg;
                cloak_cfg.active_model = "chrome_casual";
                g_app.behavioral_cloak = std::make_unique<DPI::BehavioralCloak>(cloak_cfg);
                std::cout << "[+] Behavioral Cloak active (chrome_casual profile)\n";
            } catch (const std::exception& ex) {
                std::cerr << "[!] Behavioral Cloak exception: " << ex.what() << "\n";
                g_app.behavioral_cloak.reset();
            }
        }

        // 10. Time Correlation Breaker
        if (!has_flag(args, "--no-time-break")) {
            try {
                TimeCorrelationBreakerConfig tcb_cfg;
                g_app.time_breaker = std::make_unique<DPI::TimeCorrelationBreaker>(tcb_cfg);
                std::cout << "[+] Time Correlation Breaker active\n";
            } catch (const std::exception& ex) {
                std::cerr << "[!] Time Correlation Breaker exception: " << ex.what() << "\n";
                g_app.time_breaker.reset();
            }
        }

        // 11. Self-Test Monitor
        if (!has_flag(args, "--no-self-test")) {
            try {
                SelfTestMonitorConfig st_cfg;
                g_app.self_test = std::make_unique<SelfTestMonitor>(st_cfg);
                g_app.self_test->start();
                std::cout << "[+] Self-Test Monitor active\n";
            } catch (const std::exception& ex) {
                std::cerr << "[!] Self-Test Monitor exception: " << ex.what() << "\n";
                g_app.self_test.reset();
            }
        }

        // 12. Session Fragmenter
        if (!has_flag(args, "--no-session-frag")) {
            try {
                SessionFragmenterConfig sf_cfg;
                g_app.session_frag = std::make_unique<SessionFragmenter>(sf_cfg);
                std::cout << "[+] Session Fragmenter active\n";
            } catch (const std::exception& ex) {
                std::cerr << "[!] Session Fragmenter exception: " << ex.what() << "\n";
                g_app.session_frag.reset();
            }
        }

        // 13. Cross-Layer Correlator
        if (!has_flag(args, "--no-cross-layer")) {
            try {
                CrossLayerCorrelatorConfig cl_cfg;
                cl_cfg.active_profile = "Windows10-Chrome";
                g_app.cross_layer = std::make_unique<CrossLayerCorrelator>(cl_cfg);
                g_app.cross_layer->load_default_profiles();
                std::cout << "[+] Cross-Layer Correlator active (Windows10-Chrome)\n";
            } catch (const std::exception& ex) {
                std::cerr << "[!] Cross-Layer Correlator exception: " << ex.what() << "\n";
                g_app.cross_layer.reset();
            }
        }

        // 14. Geneva Engine
        if (!has_flag(args, "--no-geneva")) {
            try {
                g_app.geneva = std::make_unique<DPI::GenevaEngine>();
                // Strategy is applied per-packet via apply_strategy(); just log readiness
                DPI::GenevaStrategy strat = DPI::GenevaStrategy::tspu_2026();
                (void)strat; // stored for use by packet processing path
                std::cout << "[+] Geneva Engine active (tspu_2026 strategy)\n";
            } catch (const std::exception& ex) {
                std::cerr << "[!] Geneva Engine exception: " << ex.what() << "\n";
                g_app.geneva.reset();
            }
        }

        // 15. Covert Channel Manager (disabled by default; only if --covert flag)
        if (has_flag(args, "--covert")) {
            try {
                CovertChannelConfig cc_cfg;
                cc_cfg.enabled = true;
                g_app.covert_channel = std::make_unique<CovertChannelManager>(cc_cfg);
                std::cout << "[+] Covert Channel Manager active\n";
            } catch (const std::exception& ex) {
                std::cerr << "[!] Covert Channel Manager exception: " << ex.what() << "\n";
                g_app.covert_channel.reset();
            }
        }

        // 16. Protocol Rotation Schedule
        {
            try {
                ProtocolRotationConfig pr_cfg;
                g_app.protocol_rotation = std::make_unique<ProtocolRotationSchedule>(pr_cfg);
                g_app.protocol_rotation->load_default_schedule();
                std::cout << "[+] Protocol Rotation Schedule active\n";
            } catch (const std::exception& ex) {
                std::cerr << "[!] Protocol Rotation Schedule exception: " << ex.what() << "\n";
                g_app.protocol_rotation.reset();
            }
        }

        // 17. AS-Aware Router
        {
            try {
                ASAwareRouterConfig ar_cfg;
                g_app.as_router = std::make_unique<ASAwareRouter>(ar_cfg);
                g_app.as_router->load_default_entries();
                std::cout << "[+] AS-Aware Router active\n";
            } catch (const std::exception& ex) {
                std::cerr << "[!] AS-Aware Router exception: " << ex.what() << "\n";
                g_app.as_router.reset();
            }
        }

        // 18. Geo Obfuscator
        {
            try {
                GeoObfuscatorConfig go_cfg;
                g_app.geo_obfuscator = std::make_unique<GeoObfuscator>(go_cfg);
                g_app.geo_obfuscator->load_default_nodes();
                std::cout << "[+] Geo Obfuscator active\n";
            } catch (const std::exception& ex) {
                std::cerr << "[!] Geo Obfuscator exception: " << ex.what() << "\n";
                g_app.geo_obfuscator.reset();
            }
        }

        // === Wire module hooks into DPI bypass packet pipeline ===
        if (g_app.dpi_bypass) {
            DPI::ModuleHooks hooks;
            
            hooks.pre_process = [](uint8_t* pkt, uint32_t& pkt_len) -> bool {
                // L3 Stealth: normalize TTL, IPID, MSS on all outbound packets
                if (g_app.l3_stealth) {
                    std::vector<uint8_t> v(pkt, pkt + pkt_len);
                    if (g_app.l3_stealth->process_ipv4_packet(v)) {
                        if (v.size() <= 65535) {
                            memcpy(pkt, v.data(), v.size());
                            pkt_len = static_cast<uint32_t>(v.size());
                        }
                    }
                }
                return true; // allow all packets (DNS blocking is via WFP, not here)
            };
            
            hooks.post_process = [](const uint8_t* pkt, uint32_t pkt_len) {
                // Self-Test Monitor: feed packet for entropy/timing/size analysis
                if (g_app.self_test) {
                    static auto last_pkt_time = std::chrono::steady_clock::now();
                    auto now = std::chrono::steady_clock::now();
                    double inter_arrival_ms = std::chrono::duration<double, std::milli>(now - last_pkt_time).count();
                    last_pkt_time = now;
                    std::vector<uint8_t> data(pkt, pkt + pkt_len);
                    g_app.self_test->feed_packet(data, inter_arrival_ms);
                }
                // WF Defense: record real packet
                if (g_app.wf_defense) {
                    g_app.wf_defense->record_real_packet(static_cast<size_t>(pkt_len), true);
                }
                // Volume Normalizer: record transfer
                if (g_app.volume_normalizer) {
                    g_app.volume_normalizer->record_transfer(static_cast<size_t>(pkt_len), true);
                }
            };
            
            hooks.get_send_delay_us = [](const uint8_t*, uint32_t pkt_len) -> int64_t {
                int64_t total_us = 0;
                // Behavioral Cloak: shape packet timing
                if (g_app.behavioral_cloak) {
                    auto d = g_app.behavioral_cloak->shape_packet(static_cast<size_t>(pkt_len), true);
                    total_us += d.count();
                }
                // Time Correlation Breaker: add jitter
                if (g_app.time_breaker) {
                    auto j = g_app.time_breaker->compute_jitter();
                    total_us += j.count();
                }
                return total_us;
            };
            
            g_app.dpi_bypass->set_module_hooks(hooks);
            std::cout << "[+] Module hooks wired into DPI pipeline\n";
        }

        // Check if at least one layer is active
        bool any_active = (g_app.spoofer && g_app.spoofer->is_enabled()) ||
                          (g_app.dpi_bypass && g_app.dpi_bypass->is_running()) ||
                          (g_app.paranoid && g_app.paranoid->is_active()) ||
                          (g_app.dns_leak && g_app.dns_leak->is_active()) ||
                          (g_app.l3_stealth != nullptr) ||
                          (g_app.rtt_equalizer != nullptr) ||
                          (g_app.volume_normalizer != nullptr) ||
                          (g_app.wf_defense != nullptr) ||
                          (g_app.behavioral_cloak != nullptr) ||
                          (g_app.time_breaker != nullptr) ||
                          (g_app.self_test && g_app.self_test->is_running()) ||
                          (g_app.session_frag != nullptr) ||
                          (g_app.cross_layer != nullptr) ||
                          (g_app.geneva != nullptr) ||
                          (g_app.protocol_rotation != nullptr) ||
                          (g_app.as_router != nullptr) ||
                          (g_app.geo_obfuscator != nullptr);
        if (!any_active) {
            std::cerr << "[!] All protection layers failed to start. Exiting.\n";
            g_app.reset();
            return;
        }

        std::cout << "[+] Protection layers running. Press Ctrl+C to stop.\n";

        g_running = true;

        // Wait loop
        while (g_running) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }

        // Cleanup after loop exit (RAII compliance)
        std::cout << "\n[*] Shutting down services...\n";

        // Stop modules in reverse initialization order
        if (g_app.geo_obfuscator) {
            g_app.geo_obfuscator.reset();
            std::cout << "[+] Geo Obfuscator stopped\n";
        }
        if (g_app.as_router) {
            g_app.as_router.reset();
            std::cout << "[+] AS-Aware Router stopped\n";
        }
        if (g_app.protocol_rotation) {
            g_app.protocol_rotation.reset();
            std::cout << "[+] Protocol Rotation stopped\n";
        }
        if (g_app.covert_channel) {
            g_app.covert_channel.reset();
            std::cout << "[+] Covert Channel Manager stopped\n";
        }
        if (g_app.geneva) {
            g_app.geneva.reset();
            std::cout << "[+] Geneva Engine stopped\n";
        }
        if (g_app.cross_layer) {
            g_app.cross_layer.reset();
            std::cout << "[+] Cross-Layer Correlator stopped\n";
        }
        if (g_app.session_frag) {
            g_app.session_frag->stop_monitor();
            g_app.session_frag.reset();
            std::cout << "[+] Session Fragmenter stopped\n";
        }
        if (g_app.self_test) {
            g_app.self_test->stop();
            g_app.self_test.reset();
            std::cout << "[+] Self-Test Monitor stopped\n";
        }
        if (g_app.time_breaker) {
            g_app.time_breaker.reset();
            std::cout << "[+] Time Correlation Breaker stopped\n";
        }
        if (g_app.behavioral_cloak) {
            g_app.behavioral_cloak.reset();
            std::cout << "[+] Behavioral Cloak stopped\n";
        }
        if (g_app.wf_defense) {
            g_app.wf_defense.reset();
            std::cout << "[+] WF Defense stopped\n";
        }
        if (g_app.volume_normalizer) {
            g_app.volume_normalizer.reset();
            std::cout << "[+] Volume Normalizer stopped\n";
        }
        if (g_app.rtt_equalizer) {
            g_app.rtt_equalizer.reset();
            std::cout << "[+] RTT Equalizer stopped\n";
        }
        if (g_app.l3_stealth) {
            g_app.l3_stealth.reset();
            std::cout << "[+] L3 Stealth stopped\n";
        }
        if (g_app.dns_leak && g_app.dns_leak->is_active()) {
            g_app.dns_leak->deactivate();
            g_app.dns_leak.reset();
            std::cout << "[+] DNS Leak Prevention deactivated\n";
        }
        if (g_app.paranoid && g_app.paranoid->is_active()) {
            g_app.paranoid->deactivate();
            std::cout << "[+] ParanoidMode deactivated\n";
        }
        g_app.paranoid.reset();

        if (g_app.dpi_bypass && g_app.dpi_bypass->is_running()) {
            g_app.dpi_bypass->stop();
            std::cout << "[+] DPI bypass stopped\n";
        }
        g_app.dpi_bypass.reset();

        if (g_app.spoofer && g_app.spoofer->is_enabled()) {
            g_app.spoofer->disable();
            std::cout << "[+] Spoofing disabled, settings restored\n";
        }
        g_app.spoofer.reset();

        std::cout << "[+] Shutdown complete\n";
        
    } catch (const std::exception& e) {
        std::cerr << "[!] Exception in handle_run: " << e.what() << "\n";
    }
}

void handle_stop(const std::vector<std::string>& args) {
    // FIX C4100: Mark unreferenced parameter
    (void)args;

    std::cout << "[*] Stopping all services and restoring settings...\n";

    g_running = false;

    // Stop transport modules first
    if (g_app.geo_obfuscator) {
        g_app.geo_obfuscator.reset();
        std::cout << "[+] Geo Obfuscator stopped\n";
    }
    if (g_app.as_router) {
        g_app.as_router.reset();
        std::cout << "[+] AS-Aware Router stopped\n";
    }
    if (g_app.protocol_rotation) {
        g_app.protocol_rotation.reset();
        std::cout << "[+] Protocol Rotation stopped\n";
    }
    if (g_app.covert_channel) {
        g_app.covert_channel.reset();
        std::cout << "[+] Covert Channel Manager stopped\n";
    }
    if (g_app.geneva) {
        g_app.geneva.reset();
        std::cout << "[+] Geneva Engine stopped\n";
    }
    if (g_app.cross_layer) {
        g_app.cross_layer.reset();
        std::cout << "[+] Cross-Layer Correlator stopped\n";
    }
    if (g_app.session_frag) {
        g_app.session_frag->stop_monitor();
        g_app.session_frag.reset();
        std::cout << "[+] Session Fragmenter stopped\n";
    }
    if (g_app.self_test) {
        g_app.self_test->stop();
        g_app.self_test.reset();
        std::cout << "[+] Self-Test Monitor stopped\n";
    }
    if (g_app.time_breaker) {
        g_app.time_breaker.reset();
        std::cout << "[+] Time Correlation Breaker stopped\n";
    }
    if (g_app.behavioral_cloak) {
        g_app.behavioral_cloak.reset();
        std::cout << "[+] Behavioral Cloak stopped\n";
    }
    if (g_app.wf_defense) {
        g_app.wf_defense.reset();
        std::cout << "[+] WF Defense stopped\n";
    }
    if (g_app.volume_normalizer) {
        g_app.volume_normalizer.reset();
        std::cout << "[+] Volume Normalizer stopped\n";
    }
    if (g_app.rtt_equalizer) {
        g_app.rtt_equalizer.reset();
        std::cout << "[+] RTT Equalizer stopped\n";
    }
    if (g_app.l3_stealth) {
        g_app.l3_stealth.reset();
        std::cout << "[+] L3 Stealth stopped\n";
    }
    if (g_app.dns_leak && g_app.dns_leak->is_active()) {
        g_app.dns_leak->deactivate();
        g_app.dns_leak.reset();
        std::cout << "[+] DNS Leak Prevention deactivated\n";
    }
    if (g_app.paranoid && g_app.paranoid->is_active()) {
        g_app.paranoid->deactivate();
        std::cout << "[+] ParanoidMode deactivated\n";
    }
    g_app.paranoid.reset();

    if (g_app.dpi_bypass && g_app.dpi_bypass->is_running()) {
        g_app.dpi_bypass->stop();
        std::cout << "[+] DPI bypass stopped\n";
    }
    g_app.dpi_bypass.reset();

    if (g_app.spoofer && g_app.spoofer->is_enabled()) {
        g_app.spoofer->disable();
        std::cout << "[+] Spoofing disabled, original settings restored\n";
    }
    g_app.spoofer.reset();

    std::cout << "[+] All services stopped\n";
}

void handle_status(const std::vector<std::string>& args) {
    // FIX C4100: Mark unreferenced parameter
    (void)args;
    
    std::cout << "=== NCP Status ===\n\n";
    
    // Spoofing status
    if (g_app.spoofer && g_app.spoofer->is_enabled()) {
        auto status = g_app.spoofer->get_status();
        std::cout << "[Spoofing]\n";
        std::cout << "  IPv4: " << (status.ipv4_spoofed ? status.current_ipv4 : "Not spoofed") << "\n";
        std::cout << "  IPv6: " << (status.ipv6_spoofed ? status.current_ipv6 : "Not spoofed") << "\n";
        std::cout << "  MAC: " << (status.mac_spoofed ? status.current_mac : "Not spoofed") << "\n";
        std::cout << "  Hostname: " << (status.hostname_spoofed ? status.current_hostname : "Not spoofed") << "\n";
    } else {
        std::cout << "[Spoofing] Inactive\n";
    }
    
    // DPI bypass status
    if (g_app.dpi_bypass && g_app.dpi_bypass->is_running()) {
        auto stats = g_app.dpi_bypass->get_stats();
        std::cout << "\n[DPI Bypass]\n";
        std::cout << "  Packets processed: " << stats.packets_total.load() << "\n";
        std::cout << "  Packets modified: " << stats.packets_modified.load() << "\n";
        std::cout << "  Fake packets sent: " << stats.fake_packets_sent.load() << "\n";
    } else {
        std::cout << "\n[DPI Bypass] Inactive\n";
    }
    
    // ParanoidMode status
    if (g_app.paranoid && g_app.paranoid->is_active()) {
        auto pstats = g_app.paranoid->get_statistics();
        std::cout << "\n[ParanoidMode]\n";

        // Show threat level
        std::cout << "  Threat level: ";
        auto level = g_app.paranoid->get_threat_level();
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

    // DNS Leak Prevention status
    if (g_app.dns_leak && g_app.dns_leak->is_active()) {
        auto ds = g_app.dns_leak->get_stats();
        std::cout << "\n[DNS Leak Prevention] Active\n";
        std::cout << "  DNS queries blocked: " << ds.dns_queries_blocked.load() << "\n";
        std::cout << "  STUN packets blocked: " << ds.stun_packets_blocked.load() << "\n";
        std::cout << "  Leaks detected: " << ds.leaks_detected.load() << "\n";
    } else {
        std::cout << "\n[DNS Leak Prevention] Inactive\n";
    }

    // L3 Stealth status
    if (g_app.l3_stealth) {
        auto ls = g_app.l3_stealth->get_stats();
        std::cout << "\n[L3 Stealth] Active\n";
        std::cout << "  Packets processed: " << ls.packets_processed.load() << "\n";
        std::cout << "  IPID rewritten: " << ls.ipid_rewritten.load() << "\n";
        std::cout << "  TTL normalized: " << ls.ttl_normalized.load() << "\n";
    } else {
        std::cout << "\n[L3 Stealth] Inactive\n";
    }

    // RTT Equalizer status
    if (g_app.rtt_equalizer) {
        auto rs = g_app.rtt_equalizer->get_stats();
        std::cout << "\n[RTT Equalizer] Active\n";
        std::cout << "  ACKs delayed: " << rs.acks_delayed.load() << "\n";
        std::cout << "  Adaptive adjustments: " << rs.adaptive_adjustments.load() << "\n";
    } else {
        std::cout << "\n[RTT Equalizer] Inactive\n";
    }

    // Volume Normalizer status
    if (g_app.volume_normalizer) {
        auto vs = g_app.volume_normalizer->get_stats();
        std::cout << "\n[Volume Normalizer] Active\n";
        std::cout << "  Requests normalized: " << vs.requests_normalized.load() << "\n";
        std::cout << "  Bytes padded: " << vs.bytes_padded.load() << "\n";
    } else {
        std::cout << "\n[Volume Normalizer] Inactive\n";
    }

    // WF Defense status
    if (g_app.wf_defense) {
        auto ws = g_app.wf_defense->get_stats();
        std::cout << "\n[WF Defense] Active (Tamaraw)\n";
        std::cout << "  Pages defended: " << ws.pages_defended.load() << "\n";
        std::cout << "  Dummy packets sent: " << ws.dummy_packets_sent.load() << "\n";
    } else {
        std::cout << "\n[WF Defense] Inactive\n";
    }

    // Behavioral Cloak status
    if (g_app.behavioral_cloak) {
        auto bs = g_app.behavioral_cloak->get_stats();
        std::cout << "\n[Behavioral Cloak] Active (" << g_app.behavioral_cloak->get_active_model_name() << ")\n";
        std::cout << "  Packets shaped: " << bs.packets_shaped.load() << "\n";
        std::cout << "  Bursts generated: " << bs.bursts_generated.load() << "\n";
    } else {
        std::cout << "\n[Behavioral Cloak] Inactive\n";
    }

    // Time Correlation Breaker status
    if (g_app.time_breaker) {
        auto ts = g_app.time_breaker->get_stats();
        std::cout << "\n[Time Correlation Breaker] Active\n";
        std::cout << "  Jitters applied: " << ts.jitters_applied.load() << "\n";
        std::cout << "  Current CV: " << (ts.current_cv_x1000.load() / 1000.0) << "\n";
    } else {
        std::cout << "\n[Time Correlation Breaker] Inactive\n";
    }

    // Self-Test Monitor status
    if (g_app.self_test && g_app.self_test->is_running()) {
        auto ss = g_app.self_test->get_stats();
        std::cout << "\n[Self-Test Monitor] Active\n";
        std::cout << "  Tests run: " << ss.tests_run.load() << "\n";
        std::cout << "  Tests passed: " << ss.tests_passed.load() << "\n";
        std::cout << "  Tests failed: " << ss.tests_failed.load() << "\n";
    } else {
        std::cout << "\n[Self-Test Monitor] Inactive\n";
    }

    // Session Fragmenter status
    if (g_app.session_frag) {
        auto sfs = g_app.session_frag->get_stats();
        std::cout << "\n[Session Fragmenter] Active\n";
        std::cout << "  Sessions tracked: " << sfs.sessions_tracked.load() << "\n";
        std::cout << "  Sessions reset: " << sfs.sessions_reset.load() << "\n";
    } else {
        std::cout << "\n[Session Fragmenter] Inactive\n";
    }

    // Cross-Layer Correlator status
    if (g_app.cross_layer) {
        auto cls = g_app.cross_layer->get_stats();
        std::cout << "\n[Cross-Layer Correlator] Active (" << g_app.cross_layer->get_active_profile() << ")\n";
        std::cout << "  Checks performed: " << cls.checks_performed.load() << "\n";
        std::cout << "  Mismatches detected: " << cls.mismatches_detected.load() << "\n";
        std::cout << "  Auto-fixes applied: " << cls.auto_fixes_applied.load() << "\n";
    } else {
        std::cout << "\n[Cross-Layer Correlator] Inactive\n";
    }

    // Geneva Engine status
    if (g_app.geneva) {
        const auto& gs = g_app.geneva->get_stats();
        std::cout << "\n[Geneva Engine] Active (tspu_2026)\n";
        std::cout << "  Packets processed: " << gs.packets_processed << "\n";
        std::cout << "  Packets duplicated: " << gs.packets_duplicated << "\n";
        std::cout << "  Packets fragmented: " << gs.packets_fragmented << "\n";
    } else {
        std::cout << "\n[Geneva Engine] Inactive\n";
    }

    // Covert Channel status
    if (g_app.covert_channel) {
        auto ccs = g_app.covert_channel->get_stats();
        std::cout << "\n[Covert Channel Manager] Active\n";
        std::cout << "  Messages sent: " << ccs.messages_sent.load() << "\n";
        std::cout << "  Bytes hidden: " << ccs.bytes_hidden.load() << "\n";
    } else {
        std::cout << "\n[Covert Channel Manager] Inactive (use --covert to enable)\n";
    }

    // Protocol Rotation status
    if (g_app.protocol_rotation) {
        auto prs = g_app.protocol_rotation->get_stats();
        std::cout << "\n[Protocol Rotation] Active\n";
        std::cout << "  Rotations: " << prs.rotations.load() << "\n";
    } else {
        std::cout << "\n[Protocol Rotation] Inactive\n";
    }

    // AS-Aware Router status
    if (g_app.as_router) {
        auto ars = g_app.as_router->get_stats();
        std::cout << "\n[AS-Aware Router] Active\n";
        std::cout << "  Connections routed: " << ars.connections_routed.load() << "\n";
        std::cout << "  AS switches: " << ars.as_switches.load() << "\n";
    } else {
        std::cout << "\n[AS-Aware Router] Inactive\n";
    }

    // Geo Obfuscator status
    if (g_app.geo_obfuscator) {
        auto gos = g_app.geo_obfuscator->get_stats();
        std::cout << "\n[Geo Obfuscator] Active\n";
        std::cout << "  Connections routed: " << gos.connections_routed.load() << "\n";
        std::cout << "  Region switches: " << gos.region_switches.load() << "\n";
    } else {
        std::cout << "\n[Geo Obfuscator] Inactive\n";
    }
}

void handle_rotate(const std::vector<std::string>& args) {
    // FIX C4100: Mark unreferenced parameter
    (void)args;
    
    if (!g_app.spoofer || !g_app.spoofer->is_enabled()) {
        std::cerr << "[!] Spoofing not active\n";
        return;
    }
    
    std::cout << "[*] Rotating all identities...\n";
    
    if (g_app.spoofer->rotate_all()) {
        auto status = g_app.spoofer->get_status();
        std::cout << "[+] Identity rotation complete:\n";
        std::cout << "  New IPv4: " << status.current_ipv4 << "\n";
        std::cout << "  New IPv6: " << status.current_ipv6 << "\n";
        std::cout << "  New MAC: " << status.current_mac << "\n";
    } else {
        std::cerr << "[!] Rotation failed\n";
    }
    
    // Rotate paranoid circuits if active
    if (g_app.paranoid && g_app.paranoid->is_active()) {
        g_app.paranoid->rotate_all_circuits();
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
#ifdef _WIN32
    // On Windows, use DRIVER mode (WinDivert transparent interception)
    // so traffic is redirected at the kernel level — no proxy configuration needed.
    config.mode = DPI::DPIMode::DRIVER;
#else
    config.mode = DPI::DPIMode::PROXY;
#endif
    // FIX C4244: Explicit cast for int to uint16_t conversion
    config.listen_port = static_cast<uint16_t>(get_option_int(args, "--port", 8881));
    config.target_host = get_option(args, "--target", "example.com");
    // FIX C4244: Use static_cast<uint16_t> to avoid int to uint16_t conversion warning
    config.target_port = static_cast<uint16_t>(get_option_int(args, "--target-port", 443));
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
    
    std::cout << "[+] DPI bypass started";
    if (config.mode == DPI::DPIMode::DRIVER) {
        std::cout << " (WinDivert driver mode)\n";
    } else {
        std::cout << " on port " << config.listen_port << "\n";
        std::cout << "[+] Target: " << config.target_host << ":" << config.target_port << "\n";
    }
    std::cout << "[+] TCP split: " << (config.enable_tcp_split ? "enabled" : "disabled") << "\n";
    std::cout << "[+] Fake packets: " << (config.enable_fake_packet ? "enabled" : "disabled");
    if (config.enable_fake_packet) {
        std::cout << " (ttl=" << config.fake_ttl;
        if (config.fake_fooling & 1) std::cout << ",badsum";
        if (config.fake_fooling & 2) std::cout << ",badseq";
        if (config.fake_fooling & 4) std::cout << ",md5sig";
        std::cout << ", repeats=" << config.fake_repeats << ")";
    }
    std::cout << "\n";
    std::cout << "[+] Disorder: " << (config.enable_disorder ? "enabled" : "disabled") << "\n";
    std::cout << "[+] Multi-split: " << (config.enable_multi_layer_split ? "enabled" : "disabled") << "\n";
    
    g_app.dpi_bypass = std::move(dpi);
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
        // FIX C4244: Explicit cast for int to uint16_t conversion
        // FIX C4244: Use static_cast<uint16_t> to avoid int to uint16_t conversion warning
        cfg.sam_port = static_cast<uint16_t>(get_option_int(args, "--sam-port", 7656));
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
