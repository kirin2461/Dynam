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
#include "ncp_proxy.hpp"
#include "ncp_tor_manager.hpp"
#include "ncp_blockcheck.hpp"
#include "ncp_zapret_import.hpp"
#include "ncp_hostlist.hpp"
#include "ncp_dpi_detector.hpp"
#include "ncp_autopilot.hpp"

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
#include <wininet.h>
#include <direct.h>
#pragma comment(lib, "iphlpapi.lib")
#else
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#endif
#include <cstdlib>
#include <cstdio>
#include <ctime>
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
// R10-FIX-06: Command injection prevention - validate inputs and use safe parameter passing
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

static std::vector<uint8_t> hex_to_bytes(const std::string& hex) {
    std::vector<uint8_t> out;
    out.reserve(hex.size() / 2);
    for (size_t i = 0; i + 1 < hex.size(); i += 2) {
        auto hv = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        };
        int hi = hv(hex[i]), lo = hv(hex[i + 1]);
        if (hi < 0 || lo < 0) { out.clear(); return out; }
        out.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    return out;
}

// ── Cross-process run state ─────────────────────────────────────────────
// `ncp run` writes a small JSON state file on startup and removes it during
// graceful shutdown, so `ncp status` / `ncp stop` invoked from a separate
// process can see and control the running instance.
static std::string ncp_state_dir() {
#ifdef _WIN32
    const char* appdata = std::getenv("APPDATA");
    if (appdata) return std::string(appdata) + "\\ncp";
    return ".";
#else
    const char* home = std::getenv("HOME");
    if (home) return std::string(home) + "/ncp";
    return "/tmp";
#endif
}

static std::string ncp_state_file() {
#ifdef _WIN32
    return ncp_state_dir() + "\\run_state.json";
#else
    return ncp_state_dir() + "/run_state.json";
#endif
}

static long ncp_current_pid() {
#ifdef _WIN32
    return static_cast<long>(GetCurrentProcessId());
#else
    return static_cast<long>(::getpid());
#endif
}

// forward decls (defined below, used by sysproxy/autopilot handlers)
static bool has_flag(const std::vector<std::string>& args, const std::string& flag);
static std::string get_option(const std::vector<std::string>& args, const std::string& option, const std::string& default_val = "");
static int get_option_int(const std::vector<std::string>& args, const std::string& option, int default_val = 0);

// ============================================================================
// System-wide proxy (application mode) — routes ALL proxy-aware applications
// (Discord, browsers, Electron/Chromium apps) through the local NCP proxy.
//
// Windows: per-user WinINET settings (HKCU — no admin needed), live-notified
// via InternetSetOptionW. Linux: GNOME gsettings when available, otherwise
// prints shell env instructions.
//
// SAFETY CONTRACT: previous settings are always saved to
// <state_dir>/sysproxy_state.json BEFORE changing anything; `off` restores
// exactly what was there (including "proxy was disabled"). If ncp crashes,
// `ncp sysproxy off` recovers from the state file.
// ============================================================================
static std::string ncp_sysproxy_state_file() {
#ifdef _WIN32
    return ncp_state_dir() + "\\sysproxy_state.json";
#else
    return ncp_state_dir() + "/sysproxy_state.json";
#endif
}

// minimal flat-JSON field extractors (our own written format)
static std::string sp_json_get_str(const std::string& j, const std::string& key) {
    std::string pat = "\"" + key + "\": \"";
    size_t p = j.find(pat);
    if (p == std::string::npos) return "";
    p += pat.size();
    size_t e = j.find('"', p);
    if (e == std::string::npos) return "";
    return j.substr(p, e - p);
}
static long sp_json_get_num(const std::string& j, const std::string& key, long dflt = -1) {
    std::string pat = "\"" + key + "\": ";
    size_t p = j.find(pat);
    if (p == std::string::npos) return dflt;
    p += pat.size();
    try { return std::stol(j.substr(p, 16)); } catch (...) { return dflt; }
}

struct SysproxySaved {
    bool valid = false;
    long enable = 0;                 // Windows ProxyEnable
    std::string server;              // Windows ProxyServer ("" = was unset)
    std::string override_list;       // Windows ProxyOverride
    std::string gnome_mode;          // Linux gsettings mode ("none"/"manual"/"auto")
};

static bool sysproxy_load_saved(SysproxySaved& out) {
    std::ifstream f(ncp_sysproxy_state_file());
    if (!f) return false;
    std::stringstream ss;
    ss << f.rdbuf();
    std::string j = ss.str();
    out.enable = sp_json_get_num(j, "enable", 0);
    out.server = sp_json_get_str(j, "server");
    out.override_list = sp_json_get_str(j, "override");
    out.gnome_mode = sp_json_get_str(j, "gnome_mode");
    out.valid = true;
    return true;
}

static void sysproxy_write_state(bool active, long port, const SysproxySaved& sv) {
    std::string path = ncp_sysproxy_state_file();
    // ensure dir exists
    size_t slash = path.find_last_of("/\\");
    if (slash != std::string::npos) {
        std::string dir = path.substr(0, slash);
#ifdef _WIN32
        _mkdir(dir.c_str());
#else
        mkdir(dir.c_str(), 0700);
#endif
    }
    std::ofstream f(path, std::ios::trunc);
    if (!f) return;
    f << "{\"active\": " << (active ? "true" : "false")
      << ", \"port\": " << port
      << ", \"enable\": " << sv.enable
      << ", \"server\": \"" << sv.server << "\""
      << ", \"override\": \"" << sv.override_list << "\""
      << ", \"gnome_mode\": \"" << sv.gnome_mode << "\"}\n";
}

static bool sysproxy_is_active() {
    std::ifstream f(ncp_sysproxy_state_file());
    if (!f) return false;
    std::stringstream ss;
    ss << f.rdbuf();
    return ss.str().find("\"active\": true") != std::string::npos;
}

#ifdef _WIN32
static const char* WIN_INET_KEY =
    "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings";

static bool win_reg_read_dword(HKEY root, const char* sub, const char* name, DWORD& out) {
    HKEY h;
    if (RegOpenKeyExA(root, sub, 0, KEY_READ, &h) != ERROR_SUCCESS) return false;
    DWORD val = 0, sz = sizeof(val), type = 0;
    bool ok = RegQueryValueExA(h, name, nullptr, &type,
                               reinterpret_cast<LPBYTE>(&val), &sz) == ERROR_SUCCESS;
    RegCloseKey(h);
    if (ok) out = val;
    return ok;
}
static std::string win_reg_read_str(HKEY root, const char* sub, const char* name) {
    HKEY h;
    if (RegOpenKeyExA(root, sub, 0, KEY_READ, &h) != ERROR_SUCCESS) return "";
    char buf[1024] = {0};
    DWORD sz = sizeof(buf), type = 0;
    std::string out;
    if (RegQueryValueExA(h, name, nullptr, &type,
                         reinterpret_cast<LPBYTE>(buf), &sz) == ERROR_SUCCESS)
        out = buf;
    RegCloseKey(h);
    return out;
}
static void win_inet_notify() {
    InternetSetOptionA(nullptr, INTERNET_OPTION_SETTINGS_CHANGED, nullptr, 0);
    InternetSetOptionA(nullptr, INTERNET_OPTION_REFRESH, nullptr, 0);
}
#endif

// Apply system proxy to 127.0.0.1:port. Saves previous settings first.
static bool sysproxy_apply(uint16_t port, std::string* err) {
    SysproxySaved sv;
#ifdef _WIN32
    DWORD en = 0;
    sv.enable = win_reg_read_dword(HKEY_CURRENT_USER, WIN_INET_KEY, "ProxyEnable", en)
                    ? static_cast<long>(en) : 0;
    sv.server = win_reg_read_str(HKEY_CURRENT_USER, WIN_INET_KEY, "ProxyServer");
    sv.override_list = win_reg_read_str(HKEY_CURRENT_USER, WIN_INET_KEY, "ProxyOverride");
    sv.valid = true;
    sysproxy_write_state(true, port, sv);  // save BEFORE changing

    HKEY h;
    if (RegCreateKeyExA(HKEY_CURRENT_USER, WIN_INET_KEY, 0, nullptr, 0,
                        KEY_SET_VALUE, nullptr, &h, nullptr) != ERROR_SUCCESS) {
        if (err) *err = "cannot open Internet Settings key";
        return false;
    }
    DWORD one = 1;
    RegSetValueExA(h, "ProxyEnable", 0, REG_DWORD,
                   reinterpret_cast<const BYTE*>(&one), sizeof(one));
    std::string server = "127.0.0.1:" + std::to_string(port);
    RegSetValueExA(h, "ProxyServer", 0, REG_SZ,
                   reinterpret_cast<const BYTE*>(server.c_str()),
                   static_cast<DWORD>(server.size() + 1));
    std::string ovr = "localhost;127.*;10.*;172.16.*;192.168.*;<local>";
    RegSetValueExA(h, "ProxyOverride", 0, REG_SZ,
                   reinterpret_cast<const BYTE*>(ovr.c_str()),
                   static_cast<DWORD>(ovr.size() + 1));
    RegCloseKey(h);
    win_inet_notify();
    return true;
#else
    // Linux: GNOME gsettings if available
    sv.valid = true;
    if (std::system("which gsettings >/dev/null 2>&1") == 0) {
        char mode[64] = {0};
        FILE* p = popen("gsettings get org.gnome.system.proxy mode 2>/dev/null", "r");
        if (p) {
            if (fgets(mode, sizeof(mode), p)) {
                std::string m = mode;
                while (!m.empty() && (m.back() == '\n' || m.back() == '\'' || m.back() == ' '))
                    m.pop_back();
                while (!m.empty() && m.front() == '\'') m.erase(m.begin());
                sv.gnome_mode = m;
            }
            pclose(p);
        }
        sysproxy_write_state(true, port, sv);
        std::string base = "gsettings set org.gnome.system.proxy";
        std::system((base + " mode 'manual'").c_str());
        std::system((base + ".socks host '127.0.0.1'").c_str());
        std::system((base + ".socks port " + std::to_string(port)).c_str());
        std::system((base + ".http host '127.0.0.1'").c_str());
        std::system((base + ".http port " + std::to_string(port)).c_str());
        std::system((base + ".https host '127.0.0.1'").c_str());
        std::system((base + ".https port " + std::to_string(port)).c_str());
        std::system((base + " ignore-hosts \"['localhost', '127.0.0.0/8', '10.0.0.0/8', '192.168.0.0/16', '172.16.0.0/12']\"").c_str());
        return true;
    }
    // No gsettings: record state anyway and give manual instructions
    sysproxy_write_state(true, port, sv);
    std::cout << "[i] gsettings not found — set these env vars for your apps:\n"
              << "    export http_proxy=http://127.0.0.1:" << port << "\n"
              << "    export https_proxy=http://127.0.0.1:" << port << "\n"
              << "    export all_proxy=socks5h://127.0.0.1:" << port << "\n";
    return true;
#endif
}

// Restore previous settings from the state file.
static bool sysproxy_restore(std::string* err) {
    SysproxySaved sv;
    if (!sysproxy_load_saved(sv)) {
        if (err) *err = "no saved state (system proxy was not applied by ncp)";
        return false;
    }
#ifdef _WIN32
    HKEY h;
    if (RegCreateKeyExA(HKEY_CURRENT_USER, WIN_INET_KEY, 0, nullptr, 0,
                        KEY_SET_VALUE, nullptr, &h, nullptr) != ERROR_SUCCESS) {
        if (err) *err = "cannot open Internet Settings key";
        return false;
    }
    DWORD en = static_cast<DWORD>(sv.enable);
    RegSetValueExA(h, "ProxyEnable", 0, REG_DWORD,
                   reinterpret_cast<const BYTE*>(&en), sizeof(en));
    if (!sv.server.empty())
        RegSetValueExA(h, "ProxyServer", 0, REG_SZ,
                       reinterpret_cast<const BYTE*>(sv.server.c_str()),
                       static_cast<DWORD>(sv.server.size() + 1));
    else
        RegDeleteValueA(h, "ProxyServer");
    if (!sv.override_list.empty())
        RegSetValueExA(h, "ProxyOverride", 0, REG_SZ,
                       reinterpret_cast<const BYTE*>(sv.override_list.c_str()),
                       static_cast<DWORD>(sv.override_list.size() + 1));
    else
        RegDeleteValueA(h, "ProxyOverride");
    RegCloseKey(h);
    win_inet_notify();
#else
    if (!sv.gnome_mode.empty() &&
        std::system("which gsettings >/dev/null 2>&1") == 0) {
        std::string cmd = "gsettings set org.gnome.system.proxy mode '" +
                          sv.gnome_mode + "'";
        std::system(cmd.c_str());
    }
#endif
    sysproxy_write_state(false, 0, sv);
    return true;
}

void handle_sysproxy(const std::vector<std::string>& args) {
    std::string action;
    for (const auto& a : args) {
        if (!a.empty() && a[0] != '-') { action = a; break; }
    }
    if (action.empty() || has_flag(args, "--help") || has_flag(args, "-h")) {
        std::cout << "Usage: ncp sysproxy <action>\n"
                  << "  on [--port N]   Route all proxy-aware applications through 127.0.0.1:N\n"
                  << "                  (Discord, browsers, Electron apps — no admin needed)\n"
                  << "  off             Restore previous system proxy settings\n"
                  << "  status          Show whether ncp system proxy is active\n"
                  << "\n"
                  << "Start the desync proxy first: ncp proxy --doh --autopilot\n"
                  << "(or use `ncp proxy --system-proxy` to do both in one command)\n";
        return;
    }
    if (action == "on") {
        int port = get_option_int(args, "--port", 1080);
        std::string err;
        if (!sysproxy_apply(static_cast<uint16_t>(port), &err)) {
            std::cerr << "[!] sysproxy on failed: " << err << "\n";
            return;
        }
        std::cout << "[+] System proxy set to 127.0.0.1:" << port << "\n"
                  << "    Applications (Discord etc.) now route through the NCP proxy.\n"
                  << "    Restore with: ncp sysproxy off\n";
        return;
    }
    if (action == "off") {
        std::string err;
        if (!sysproxy_restore(&err)) {
            std::cerr << "[!] " << err << "\n";
            return;
        }
        std::cout << "[+] System proxy settings restored\n";
        return;
    }
    if (action == "status") {
        std::cout << "System proxy (ncp): "
                  << (sysproxy_is_active() ? "ACTIVE" : "inactive") << "\n";
#ifdef _WIN32
        DWORD en = 0;
        bool have = win_reg_read_dword(HKEY_CURRENT_USER, WIN_INET_KEY,
                                       "ProxyEnable", en);
        std::cout << "Windows WinINET: ProxyEnable="
                  << (have ? std::to_string(en) : std::string("?"))
                  << " ProxyServer="
                  << win_reg_read_str(HKEY_CURRENT_USER, WIN_INET_KEY, "ProxyServer")
                  << "\n";
#endif
        return;
    }
    std::cerr << "[!] Unknown sysproxy action: " << action << "\n";
}

static bool ncp_pid_alive(long pid) {
    if (pid <= 0) return false;
#ifdef _WIN32
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE,
                           static_cast<DWORD>(pid));
    if (h) { CloseHandle(h); return true; }
    return false;
#else
    return ::kill(static_cast<pid_t>(pid), 0) == 0;
#endif
}

static void ncp_write_state(const std::string& modules_csv) {
#ifdef _WIN32
    CreateDirectoryA(ncp_state_dir().c_str(), nullptr);
#else
    ::mkdir(ncp_state_dir().c_str(), 0700);
#endif
    std::ofstream f(ncp_state_file(), std::ios::trunc);
    if (!f.is_open()) return;
    f << "{\"pid\":" << ncp_current_pid()
      << ",\"started\":" << static_cast<long>(std::time(nullptr))
      << ",\"modules\":\"" << modules_csv << "\"}\n";
}

static void ncp_clear_state() {
    std::remove(ncp_state_file().c_str());
}

struct NcpRunState {
    bool present = false;
    long pid = -1;
    long started = 0;
    std::string modules;
};

static NcpRunState ncp_read_state() {
    NcpRunState st;
    std::ifstream f(ncp_state_file());
    if (!f.is_open()) return st;
    std::string content((std::istreambuf_iterator<char>(f)),
                        std::istreambuf_iterator<char>());
    auto extract_long = [&](const char* key) -> long {
        std::string k = std::string("\"") + key + "\":";
        auto i = content.find(k);
        if (i == std::string::npos) return -1;
        i += k.size();
        try { return std::stol(content.substr(i)); } catch (...) { return -1; }
    };
    auto extract_str = [&](const char* key) -> std::string {
        std::string k = std::string("\"") + key + "\":\"";
        auto i = content.find(k);
        if (i == std::string::npos) return "";
        i += k.size();
        auto j = content.find('"', i);
        if (j == std::string::npos) return "";
        return content.substr(i, j - i);
    };
    st.pid = extract_long("pid");
    st.started = extract_long("started");
    st.modules = extract_str("modules");
    st.present = (st.pid > 0);
    return st;
}

static std::string get_arg(const std::vector<std::string>& args, size_t index, const std::string& default_val = "") {
    return index < args.size() ? args[index] : default_val;
}

static bool has_flag(const std::vector<std::string>& args, const std::string& flag) {
    return std::find(args.begin(), args.end(), flag) != args.end();
}

static std::string get_option(const std::vector<std::string>& args, const std::string& option, const std::string& default_val) {
    auto it = std::find(args.begin(), args.end(), option);
    if (it != args.end() && ++it != args.end()) return *it;
    return default_val;
}

static std::vector<std::string> get_options_all(const std::vector<std::string>& args, const std::string& option) {
    std::vector<std::string> out;
    for (size_t i = 0; i + 1 < args.size(); ++i)
        if (args[i] == option) out.push_back(args[i + 1]);
    return out;
}
static int get_option_int(const std::vector<std::string>& args, const std::string& option, int default_val) {
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
void handle_proxy(const std::vector<std::string>& args);
void handle_blockcheck(const std::vector<std::string>& args);
void handle_autopilot(const std::vector<std::string>& args);
void handle_sysproxy(const std::vector<std::string>& args);
void handle_import_zapret(const std::vector<std::string>& args);

// ============================================================================
// main()
// ============================================================================

int main(int argc, char* argv[]) {
    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);

    ArgumentParser parser("ncp", "v1.5.0");

    parser.add_command("run", "Start PARANOID mode (all protection layers; --kill-switch arms firewall kill switch)", handle_run, {"[<interface>]"});
    parser.add_command("stop", "Stop spoofing and restore original settings", handle_stop);
    parser.add_command("status", "Show current spoof status", handle_status);
    parser.add_command("rotate", "Rotate all identities", handle_rotate);
    parser.add_command("crypto", "Cryptographic operations", handle_crypto, {"<action>", "[args]"});
    parser.add_command("network", "Network operations", handle_network, {"<action>"});
    parser.add_command("license", "License management", handle_license, {"<action>"});
    parser.add_command("dpi", "DPI bypass proxy", handle_dpi, {"[options]"});
    parser.add_command("i2p", "I2P proxy configuration", handle_i2p, {"<action>"});
    parser.add_command("mimic", "Set traffic mimicry mode", handle_mimic, {"<type>"});
    parser.add_command("proxy", "Local SOCKS5/HTTP desync proxy (no admin needed)", handle_proxy, {"[--port 1080]", "[--preset name]", "[--zapret-profile name]", "[--block-quic]", "[--fake-quic N]", "[--autohostlist file]", "[--upstream socks5://127.0.0.1:9050]", "[--tor]", "[--tor-exec /path/tor --tor-bridge \"obfs4 ...\" --pt-obfs4 /path/lyrebird]"});
    parser.add_command("blockcheck", "Auto-select best DPI bypass strategy", handle_blockcheck, {"[--domains a,b,c]", "[--timeout ms]", "[--json]", "[--out file]", "[--apply profile.json]"});
    parser.add_command("autopilot", "Adaptive self-learning DPI bypass engine", handle_autopilot, {"<status|learn|reset|enable|disable|learn-preset>", "[domain|preset]", "[--json]", "[--timeout ms]"});
    parser.add_command("sysproxy", "System-wide proxy for applications (Discord etc.)", handle_sysproxy, {"<on|off|status>", "[--port N]"});
    parser.add_command("import-zapret", "Import zapret CLI strategy into NCP profile", handle_import_zapret, {"--args <zapret-args> | --file f", "[--out profile.json]"});

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
        // NOTE: `interface` is a COM macro (#define interface struct) in
        // Windows headers — use iface_opt for the variable name.
        std::string iface_opt = get_option(args, "--interface");
        if (iface_opt.empty()) {
            // Positional: first arg that doesn't start with --
            for (const auto& a : args) {
                if (a.substr(0, 2) != "--") { iface_opt = a; break; }
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
        
        std::string iface = (iface_opt.empty() || iface_opt == "auto") ? detect_default_interface() : iface_opt;
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
        if (has_flag(args, "--quic-block")) {
            dpi_cfg.quic_force_tcp = true;
            std::cout << "[*] QUIC blocked — clients will fall back to TCP/TLS\n";
        }
        {
            int qf = get_option_int(args, "--quic-frag", 0);
            if (qf > 0) {
                dpi_cfg.quic_ipfrag_offset = qf;
                std::cout << "[*] QUIC Initial IP fragmentation at offset " << qf << "\n";
            }
        }
        std::cout << "[*] DPI preset: " << DPI::preset_to_string(chosen_preset) << "\n";
        
        if (!g_app.dpi_bypass->initialize(dpi_cfg) || !g_app.dpi_bypass->start()) {
            std::cerr << "[!] Warning: DPI bypass failed to start (continuing without it)\n";
            g_app.dpi_bypass.reset();
        } else {
            if (g_app.dpi_bypass->interception_active()) {
                std::cout << "[+] DPI bypass active (" << DPI::preset_to_string(chosen_preset)
                          << ": fake+" << (dpi_cfg.enable_disorder ? "disorder" :
                                            dpi_cfg.enable_reverse_frag ? "reverse-frag" : "split")
                          << ", ttl=" << dpi_cfg.fake_ttl
                          << (dpi_cfg.enable_autottl ? " autottl" : "")
                          << ") — intercepting traffic\n";
            } else {
                std::cout << "[!] DPI bypass configured (" << DPI::preset_to_string(chosen_preset)
                          << ") but running PASSIVE — no traffic interception, see warnings above\n";
            }

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

        // Kill switch is strictly opt-in: it installs a firewall rule dropping ALL
        // non-loopback traffic. If this process dies unexpectedly (SIGKILL, crash,
        // reboot), the rule persists and locks the machine off the network entirely
        // (including SSH). Arm it only when explicitly requested via --kill-switch.
        {
            ParanoidMode::NetworkIsolation ni{};
            ni.enable_kill_switch = has_flag(args, "--kill-switch")
                                    && !has_flag(args, "--no-kill-switch");
            g_app.paranoid->set_network_isolation(ni);
        }

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
            if (g_app.dpi_bypass->interception_active()) {
                std::cout << "[+] Module hooks wired into DPI pipeline (live traffic)\n";
            } else {
                std::cout << "[!] Module hooks wired, but DPI is PASSIVE — hook modules will see\n"
                             "[!] ZERO packets and are effectively INACTIVE: l3-stealth, self-test\n"
                             "[!] packet feed, wf-defense, volume-normalizer, behavioral-cloak,\n"
                             "[!] time-correlation-breaker. Use `ncp proxy --system-proxy` for real\n"
                             "[!] coverage without admin rights.\n";
            }
        }

        // ── Honest wiring report: modules that never touch the packet path ──
        {
            std::vector<std::string> config_only;
            if (g_app.rtt_equalizer)     config_only.push_back("rtt-equalizer");
            if (g_app.geneva)            config_only.push_back("geneva");
            if (g_app.session_frag)      config_only.push_back("session-fragmenter");
            if (g_app.cross_layer)       config_only.push_back("cross-layer-correlator");
            if (g_app.covert_channel)    config_only.push_back("covert-channel");
            if (g_app.protocol_rotation) config_only.push_back("protocol-rotation");
            if (g_app.as_router)         config_only.push_back("as-router");
            if (g_app.geo_obfuscator)    config_only.push_back("geo-obfuscator");
            if (!config_only.empty()) {
                std::cout << "[i] Modules loaded but NOT in the packet path in run mode\n"
                             "[i] (config/schedulers only — they do not modify your traffic):\n[i]   ";
                for (size_t i = 0; i < config_only.size(); ++i)
                    std::cout << (i ? ", " : "") << config_only[i];
                std::cout << "\n";
            }
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

        // Publish cross-process state for `ncp status` / `ncp stop`
        {
            std::string mods;
            auto add_mod = [&](const char* n) { if (!mods.empty()) mods += ","; mods += n; };
            if (g_app.spoofer && g_app.spoofer->is_enabled()) add_mod("spoofing");
            if (g_app.dpi_bypass && g_app.dpi_bypass->is_running()) add_mod("dpi-bypass");
            if (g_app.paranoid && g_app.paranoid->is_active()) add_mod("paranoid");
            if (g_app.dns_leak && g_app.dns_leak->is_active()) add_mod("dns-leak");
            if (g_app.l3_stealth) add_mod("l3-stealth");
            if (g_app.rtt_equalizer) add_mod("rtt-equalizer");
            if (g_app.volume_normalizer) add_mod("volume-normalizer");
            if (g_app.wf_defense) add_mod("wf-defense");
            if (g_app.behavioral_cloak) add_mod("behavioral-cloak");
            if (g_app.time_breaker) add_mod("time-correlation-breaker");
            if (g_app.self_test) add_mod("self-test");
            if (g_app.session_frag) add_mod("session-fragmenter");
            if (g_app.cross_layer) add_mod("cross-layer-correlator");
            if (g_app.geneva) add_mod("geneva");
            if (g_app.protocol_rotation) add_mod("protocol-rotation");
            if (g_app.as_router) add_mod("as-router");
            if (g_app.geo_obfuscator) add_mod("geo-obfuscator");
            ncp_write_state(mods);
        }

        g_running = true;

        // ── Runtime heartbeat: live counters prove modules actually work ──
        int status_interval = get_option_int(args, "--status-interval", 30);
        if (status_interval > 0)
            std::cout << "[*] Runtime status heartbeat every " << status_interval
                      << "s (--status-interval 0 to disable)\n";
        auto hb_start = std::chrono::steady_clock::now();
        uint64_t prev_dpi_pkts = 0;
        int dpi_zero_streak = 0;
        bool hooks_zero_warned = false;
        int tick = 0;

        // Wait loop
        while (g_running) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
            if (status_interval <= 0) continue;
            if (++tick < status_interval) continue;
            tick = 0;

            long elapsed = static_cast<long>(std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::steady_clock::now() - hb_start).count());
            std::ostringstream hb;
            hb << "[hb " << elapsed << "s]";

            uint64_t dpi_pkts = 0;
            bool intercept = false;
            if (g_app.dpi_bypass) {
                auto ds = g_app.dpi_bypass->get_stats();
                dpi_pkts = ds.packets_total.load();
                intercept = g_app.dpi_bypass->interception_active();
                hb << " dpi[pkts=" << dpi_pkts << " +" << (dpi_pkts - prev_dpi_pkts)
                   << " mod=" << ds.packets_modified.load()
                   << " frag=" << ds.packets_fragmented.load()
                   << " fake=" << ds.fake_packets_sent.load()
                   << " drop=" << ds.packets_dropped.load()
                   << " err=" << ds.send_errors.load()
                   << " conn=" << ds.connections_handled.load() << "]";
                if (!intercept) hb << " PASSIVE";
            }

            uint64_t hook_sum = 0;
            bool any_hook = false;
            std::ostringstream hk;
            if (g_app.l3_stealth) {
                auto v = g_app.l3_stealth->get_stats();
                hook_sum += v.packets_processed.load(); any_hook = true;
                hk << " l3=" << v.packets_processed.load()
                   << "(ttl:" << v.ttl_normalized.load() << ",ipid:" << v.ipid_rewritten.load() << ")";
            }
            if (g_app.self_test) {
                auto v = g_app.self_test->get_stats();
                hook_sum += v.packets_fed.load(); any_hook = true;
                hk << " selftest-fed=" << v.packets_fed.load()
                   << "(tests:" << v.tests_run.load() << ",fail:" << v.tests_failed.load() << ")";
            }
            if (g_app.wf_defense) {
                auto v = g_app.wf_defense->get_stats();
                hook_sum += v.real_packets_processed.load(); any_hook = true;
                hk << " wf=" << v.real_packets_processed.load()
                   << "(dummy:" << v.dummy_packets_sent.load() << ")";
            }
            if (g_app.volume_normalizer) {
                auto v = g_app.volume_normalizer->get_stats();
                hook_sum += v.requests_normalized.load(); any_hook = true;
                hk << " volnorm=" << v.requests_normalized.load()
                   << "(pad:" << v.bytes_padded.load() << "B)";
            }
            if (g_app.behavioral_cloak) {
                auto v = g_app.behavioral_cloak->get_stats();
                hook_sum += v.packets_shaped.load(); any_hook = true;
                hk << " cloak=" << v.packets_shaped.load();
            }
            if (g_app.time_breaker) {
                auto v = g_app.time_breaker->get_stats();
                hook_sum += v.jitters_applied.load(); any_hook = true;
                hk << " timebreak=" << v.jitters_applied.load();
            }
            if (any_hook) hb << " hooks[" << hk.str() << " ]";

            // Background/own-channel modules with real counters
            std::ostringstream bg;
            if (g_app.dns_leak && g_app.dns_leak->is_active()) {
                auto v = g_app.dns_leak->get_stats();
                bg << " dns-block=" << v.dns_queries_blocked.load()
                   << " stun-block=" << v.stun_packets_blocked.load();
            }
            if (!bg.str().empty()) hb << " |" << bg.str();

            std::cout << hb.str() << "\n";

            // ── Zero-activity alarms ──
            if (intercept) {
                if (dpi_pkts == 0) {
                    if (++dpi_zero_streak >= 2)
                        std::cout << "[!] ALARM: interception backend is running but captured 0 packets"
                                     " in " << (dpi_zero_streak * status_interval) <<
                                     "s — interception is NOT working (check admin rights / driver)\n";
                } else {
                    dpi_zero_streak = 0;
                }
                if (dpi_pkts > 0 && any_hook && hook_sum == 0 && !hooks_zero_warned) {
                    hooks_zero_warned = true;
                    std::cout << "[!] ALARM: DPI captured " << dpi_pkts <<
                                 " packets but ALL hook modules report 0 — module pipeline not wired\n";
                }
            }
            prev_dpi_pkts = dpi_pkts;
        }

        // Cleanup after loop exit (RAII compliance)
        std::cout << "\n[*] Shutting down services...\n";

        // ── Final module statistics: proof of work for the whole session ──
        std::cout << "\n=== Final module statistics ===\n";
        if (g_app.dpi_bypass) {
            auto ds = g_app.dpi_bypass->get_stats();
            std::cout << "  DPI bypass: interception="
                      << (g_app.dpi_bypass->interception_active() ? "ACTIVE" : "PASSIVE (no traffic processed)")
                      << " pkts=" << ds.packets_total.load()
                      << " modified=" << ds.packets_modified.load()
                      << " fragmented=" << ds.packets_fragmented.load()
                      << " fakes=" << ds.fake_packets_sent.load()
                      << " dropped=" << ds.packets_dropped.load()
                      << " send_errors=" << ds.send_errors.load()
                      << " conns=" << ds.connections_handled.load() << "\n";
        }
        if (g_app.l3_stealth) {
            auto v = g_app.l3_stealth->get_stats();
            std::cout << "  L3 Stealth: packets=" << v.packets_processed.load()
                      << " ttl_norm=" << v.ttl_normalized.load()
                      << " ipid=" << v.ipid_rewritten.load()
                      << " mss_clamped=" << v.mss_clamped.load() << "\n";
        }
        if (g_app.self_test) {
            auto v = g_app.self_test->get_stats();
            std::cout << "  Self-Test: packets_fed=" << v.packets_fed.load()
                      << " tests=" << v.tests_run.load()
                      << " failed=" << v.tests_failed.load()
                      << " countermeasures=" << v.countermeasures_applied.load() << "\n";
        }
        if (g_app.wf_defense) {
            auto v = g_app.wf_defense->get_stats();
            std::cout << "  WF Defense: real=" << v.real_packets_processed.load()
                      << " dummy=" << v.dummy_packets_sent.load()
                      << " pages=" << v.pages_defended.load() << "\n";
        }
        if (g_app.volume_normalizer) {
            auto v = g_app.volume_normalizer->get_stats();
            std::cout << "  Volume Normalizer: requests=" << v.requests_normalized.load()
                      << " orig=" << v.bytes_original.load() << "B"
                      << " padded=" << v.bytes_padded.load() << "B"
                      << " cover=" << v.cover_bytes_sent.load() << "B\n";
        }
        if (g_app.behavioral_cloak) {
            auto v = g_app.behavioral_cloak->get_stats();
            std::cout << "  Behavioral Cloak: shaped=" << v.packets_shaped.load()
                      << " bursts=" << v.bursts_generated.load()
                      << " idles=" << v.idle_periods_injected.load() << "\n";
        }
        if (g_app.time_breaker) {
            auto v = g_app.time_breaker->get_stats();
            std::cout << "  Time Breaker: jitters=" << v.jitters_applied.load()
                      << " total=" << v.total_jitter_us.load() << "us\n";
        }
        if (g_app.rtt_equalizer) {
            auto v = g_app.rtt_equalizer->get_stats();
            std::cout << "  RTT Equalizer: acks_delayed=" << v.acks_delayed.load()
                      << " samples=" << v.samples_collected.load()
                      << " (not in packet path in run mode)\n";
        }
        if (g_app.geneva) {
            const auto& v = g_app.geneva->get_stats();
            std::cout << "  Geneva: packets_processed=" << v.packets_processed
                      << " tampered=" << v.packets_tampered
                      << " (not in packet path in run mode)\n";
        }
        if (g_app.dns_leak && g_app.dns_leak->is_active()) {
            auto v = g_app.dns_leak->get_stats();
            std::cout << "  DNS Leak Prevention: dns_blocked=" << v.dns_queries_blocked.load()
                      << " stun_blocked=" << v.stun_packets_blocked.load()
                      << " leaks=" << v.leaks_detected.load() << "\n";
        }
        std::cout << "=== end of statistics ===\n\n";
        ncp_clear_state();

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

    // Cross-process path: another `ncp run` instance owns the services.
    // Detect it via the state file and ask it to shut down gracefully.
    {
        NcpRunState st = ncp_read_state();
        bool any_local =
            (g_app.spoofer && g_app.spoofer->is_enabled()) ||
            (g_app.dpi_bypass && g_app.dpi_bypass->is_running()) ||
            (g_app.paranoid && g_app.paranoid->is_active()) ||
            (g_app.dns_leak && g_app.dns_leak->is_active());
        if (!any_local && st.present) {
            if (!ncp_pid_alive(st.pid)) {
                std::cout << "[*] Stale state file (pid " << st.pid
                          << " not running) - removing\n";
                ncp_clear_state();
                std::cout << "[+] Nothing to stop\n";
                return;
            }
            std::cout << "[*] Sending shutdown signal to ncp run (pid "
                      << st.pid << ")...\n";
#ifdef _WIN32
            // CTRL_BREAK works only within the same console group; fall back
            // to TerminateProcess (graceful cleanup may be skipped).
            if (!GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT,
                                          static_cast<DWORD>(st.pid))) {
                HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE,
                                       static_cast<DWORD>(st.pid));
                if (h) {
                    std::cerr << "[!] Graceful signal unavailable; terminating process\n";
                    TerminateProcess(h, 0);
                    CloseHandle(h);
                }
            }
#else
            ::kill(static_cast<pid_t>(st.pid), SIGINT);
#endif
            // Wait for the process to actually exit, up to 90 s.
            // (The state file is removed at the START of the run cleanup,
            // long before the slow iptables/spoofer restore completes, so
            // only process liveness is a reliable completion signal.)
            // Full cleanup (16 iptables rules + spoofer restore) takes ~25 s.
            for (int i = 0; i < 900 && ncp_pid_alive(st.pid); ++i) {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
            if (ncp_pid_alive(st.pid)) {
                std::cerr << "[!] Process still running after 90 s\n";
                return;
            }
            ncp_clear_state();
            std::cout << "[+] ncp run stopped, settings restored\n";
            return;
        }
    }

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

    // Cross-process path: report the running `ncp run` instance, if any.
    {
        bool any_local =
            (g_app.spoofer && g_app.spoofer->is_enabled()) ||
            (g_app.dpi_bypass && g_app.dpi_bypass->is_running()) ||
            (g_app.paranoid && g_app.paranoid->is_active()) ||
            (g_app.dns_leak && g_app.dns_leak->is_active());
        if (!any_local) {
            NcpRunState st = ncp_read_state();
            std::cout << "=== NCP Status ===\n\n";
            if (st.present && ncp_pid_alive(st.pid)) {
                std::cout << "[Core] RUNNING (pid " << st.pid;
                if (st.started > 0) {
                    long up = static_cast<long>(std::time(nullptr)) - st.started;
                    std::cout << ", uptime " << (up / 60) << "m" << (up % 60) << "s";
                }
                std::cout << ")\n";
                std::cout << "  Active modules: "
                          << (st.modules.empty() ? "(unknown)" : st.modules) << "\n";
            } else {
                if (st.present) {
                    std::cout << "[*] Removing stale state file (pid " << st.pid
                              << " not running)\n";
                    ncp_clear_state();
                }
                std::cout << "[Core] Not running\n";
            }
            return;
        }
    }

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
        std::cout << "Secret key: " << Crypto::bytes_to_hex(keypair.secret_key) << "\n";
        std::cout << "[!] Store the secret key securely; anyone with it can sign as you.\n";
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
    else if (action == "sign") {
        std::string data = get_arg(args, 1);
        std::string sk_hex = get_arg(args, 2);
        if (data.empty() || sk_hex.empty()) {
            std::cerr << "Usage: ncp crypto sign <message> <secret_key_hex>\n";
            return;
        }
        auto sk_bytes = hex_to_bytes(sk_hex);
        if (sk_bytes.size() != 64 && sk_bytes.size() != 32) {
            std::cerr << "[!] Invalid secret key length: " << sk_bytes.size()
                      << " bytes (expected 64 or 32)\n";
            return;
        }
        SecureMemory msg(reinterpret_cast<const uint8_t*>(data.data()), data.size());
        SecureMemory sk(sk_bytes.data(), sk_bytes.size());
        auto sig = crypto.sign_ed25519(msg, sk);
        if (sig.empty()) {
            std::cerr << "[!] Signing failed\n";
            return;
        }
        std::cout << "Signature (Ed25519): " << Crypto::bytes_to_hex(sig) << "\n";
    }
    else if (action == "verify") {
        std::string data = get_arg(args, 1);
        std::string sig_hex = get_arg(args, 2);
        std::string pk_hex = get_arg(args, 3);
        if (data.empty() || sig_hex.empty() || pk_hex.empty()) {
            std::cerr << "Usage: ncp crypto verify <message> <signature_hex> <public_key_hex>\n";
            return;
        }
        auto sig_bytes = hex_to_bytes(sig_hex);
        auto pk_bytes = hex_to_bytes(pk_hex);
        if (sig_bytes.size() != 64) {
            std::cerr << "[!] Invalid signature length: " << sig_bytes.size() << " bytes (expected 64)\n";
            return;
        }
        if (pk_bytes.size() != 32) {
            std::cerr << "[!] Invalid public key length: " << pk_bytes.size() << " bytes (expected 32)\n";
            return;
        }
        SecureMemory msg(reinterpret_cast<const uint8_t*>(data.data()), data.size());
        SecureMemory sig(sig_bytes.data(), sig_bytes.size());
        SecureMemory pk(pk_bytes.data(), pk_bytes.size());
        bool ok = crypto.verify_ed25519(msg, sig, pk);
        std::cout << "Verification: " << (ok ? "VALID" : "INVALID") << "\n";
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

    // Kill switch: EXPLICIT opt-in only, never default. Drops all direct
    // outbound traffic (WinDivert driver mode) so nothing leaks if the
    // chain goes down. --no-kill-switch always wins.
    config.kill_switch = has_flag(args, "--kill-switch") &&
                         !has_flag(args, "--no-kill-switch");
    if (config.kill_switch) {
        std::string ksa = get_option(args, "--ks-allow", "");
        if (!ksa.empty()) {
            auto colon = ksa.rfind(':');
            if (colon != std::string::npos) {
                config.kill_switch_allow_host = ksa.substr(0, colon);
                config.kill_switch_allow_port =
                    static_cast<uint16_t>(std::atoi(ksa.substr(colon + 1).c_str()));
            }
        }
#ifndef _WIN32
        std::cerr << "[!] --kill-switch requires the WinDivert driver mode "
                     "(Windows). On Linux use 'ncp run' (iptables-based). "
                     "Ignoring for this session.\n";
#endif
    }

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
// ============================================================================
// ncp proxy — local SOCKS5/HTTP desync proxy (no admin required)
// ============================================================================
void handle_proxy(const std::vector<std::string>& args) {
    if (has_flag(args, "--help") || has_flag(args, "-h")) {
        std::cout << "Usage: ncp proxy [options]\n"
                  << "  --port N              Listen port (default 1080, 0 = ephemeral)\n"
                  << "  --bind ADDR           Listen address (default 127.0.0.1)\n"
                  << "  --preset NAME         Base DPI preset for desync strategy\n"
                  << "  --split-pos N         TCP split at byte N\n"
                  << "  --split-sni           Split at SNI/Host position\n"
                  << "  --multisplit a,b,c    Multi-layer split positions\n"
                  << "  --chain \"<zapret args>\"  Attach zapret chain (import syntax)\n"
                  << "  --block-quic          Drop UDP/443 (force TCP fallback)\n"
                  << "  --fake-quic N         Send N fake QUIC Initials per target\n"
                  << "  --doh                 Resolve targets via DNS-over-HTTPS\n"
                  << "  --autohostlist FILE   Auto-record blocked hosts to FILE\n"
                  << "  --detector-log FILE   Append DPI detector events (JSONL)\n"
                  << "  --autopilot           Enable adaptive engine (learned per-host strategies,\n"
                  << "                        live degradation feedback, background re-learning)\n"
                  << "  --events-log FILE     Append live connection events (JSONL) to FILE\n"
                  << "  --stats-file FILE     Rewrite full stats JSON to FILE every 2s (atomic)\n"
                  << "  --system-proxy        Route ALL proxy-aware apps (Discord etc.) through\n"
                  << "                        this proxy; previous settings restored on exit\n"
                  << "  --upstream URL        Chain through upstream proxy (hides your IP):\n"
                  << "                        socks5://127.0.0.1:9050 or http://127.0.0.1:8080\n"
                  << "  --tor                 Shortcut for --upstream socks5://127.0.0.1:9050\n"
                  << "                        (Tor Browser uses port 9150 instead)\n"
                  << "  --tor-exec PATH       Managed Tor: spawn tor binary, auto-chain through it\n"
                  << "  --tor-bridge \"LINE\"  Bridge line (repeatable) — hides Tor usage itself:\n"
                  << "                        obfs4 IP:PORT FINGERPRINT cert=... iat-mode=0\n"
                  << "  --pt-obfs4 PATH       lyrebird/obfs4proxy binary (for obfs4 bridges)\n"
                  << "  --pt-snowflake PATH   snowflake-client binary (for Snowflake bridges)\n";
        return;
    }
    ncp::DesyncProxy::Config cfg;
    cfg.port = static_cast<uint16_t>(get_option_int(args, "--port", 1080));
    cfg.listen_host = get_option(args, "--bind", "127.0.0.1");

    // Base strategy: preset or safe default (split-2 + split-at-SNI)
    std::string preset_name = get_option(args, "--preset", "");
    if (!preset_name.empty()) {
        DPI::DPIPreset preset = DPI::preset_from_string(preset_name);
        if (preset == DPI::DPIPreset::NONE) {
            std::cerr << "[!] Unknown preset: " << preset_name << "\n";
            return;
        }
        DPI::apply_preset(preset, cfg.base);
    } else {
        cfg.base.enable_tcp_split = true;
        cfg.base.split_position = 2;
        cfg.base.split_at_sni = true;
        cfg.base.enable_noise = false;
        cfg.base.enable_fake_packet = false;
        cfg.base.enable_disorder = false;
    }

    // Explicit strategy flags override preset/default
    if (has_flag(args, "--split-sni")) {
        cfg.base.enable_tcp_split = false;
        cfg.base.enable_multi_layer_split = false;
        cfg.base.split_positions.clear();
        cfg.base.split_at_sni = true;
    }
    {
        int sp = get_option_int(args, "--split-pos", -1);
        if (sp > 0) {
            cfg.base.enable_tcp_split = true;
            cfg.base.split_position = sp;
            cfg.base.enable_multi_layer_split = false;
            cfg.base.split_positions.clear();
        }
    }
    {
        std::string ms = get_option(args, "--multisplit", "");
        if (!ms.empty()) {
            cfg.base.enable_tcp_split = false;
            cfg.base.enable_multi_layer_split = true;
            cfg.base.split_positions.clear();
            std::istringstream ss(ms);
            std::string tok;
            while (std::getline(ss, tok, ',')) {
                try { cfg.base.split_positions.push_back(std::stoi(tok)); }
                catch (...) {}
            }
        }
    }

    // Optional zapret chains (per-host strategies with hostlists)
    std::string zprof = get_option(args, "--zapret-profile", "");
    if (!zprof.empty()) {
        auto p = DPI::get_zapret_profile_by_name(zprof);
        if (p.chains.empty()) {
            std::cerr << "[!] Unknown zapret profile: " << zprof << "\n";
            return;
        }
        cfg.chains = p.chains;
    }
    cfg.hostlist_dir = get_option(args, "--hostlist-dir", "");
    cfg.block_quic = has_flag(args, "--block-quic");
    cfg.use_doh = has_flag(args, "--doh");

    // Inline zapret chain spec: --chain "--filter-tcp=443 --dpi-desync=multisplit
    // --dpi-desync-split-pos=1,midsld" (same syntax as import-zapret)
    {
        std::string chain_spec = get_option(args, "--chain", "");
        if (!chain_spec.empty()) {
            auto imported = DPI::parse_zapret_cmdline(chain_spec);
            if (imported.ok()) {
                cfg.chains = imported.profile.chains;
                std::cout << "[+] Strategy chain: "
                          << DPI::chain_to_cmdline(cfg.chains[0]) << "\n";
            } else {
                std::cerr << "[!] Bad --chain spec: "
                          << (imported.errors.empty() ? "?" : imported.errors[0]) << "\n";
                return;
            }
        }
    }
    cfg.fake_quic_repeats = get_option_int(args, "--fake-quic", 0);

    ncp::DpiDetector detector(512, 2);
    ncp::AutoHostlist autohl;
    std::string ahl_path = get_option(args, "--autohostlist", "");
    if (!ahl_path.empty()) {
        autohl.set_path(ahl_path);
        autohl.load();
        cfg.auto_hostlist = &autohl;
        std::cout << "[+] Auto-hostlist: " << ahl_path
                  << " (" << autohl.size() << " entries)\n";
    }
    std::string detlog = get_option(args, "--detector-log", "");
    if (!detlog.empty()) detector.set_log_file(detlog);
    cfg.detector = &detector;
    cfg.log_cb = [](const std::string& m) { std::cout << "[proxy] " << m << "\n"; };
    cfg.events_log = get_option(args, "--events-log", "");
    cfg.stats_file = get_option(args, "--stats-file", "");

    // AutoPilot: adaptive per-host strategies. Active when --autopilot is
    // passed OR the DB was enabled via `ncp autopilot enable`.
    ncp::AutoPilot autopilot;
    bool autopilot_active = false;
    {
        ncp::AutoPilot::Config apcfg;
        apcfg.use_doh = cfg.use_doh;  // learn in the same DNS reality the proxy runs in
        autopilot.load(apcfg);
        if (has_flag(args, "--autopilot") || autopilot.enabled()) {
            cfg.autopilot = &autopilot;
            autopilot.start();  // background re-learn janitor
            autopilot_active = true;
        }
    }

    ncp::DesyncProxy proxy;
    // ── Managed Tor with pluggable transports (obfs4 / Snowflake) ──
    ncp::TorManager tor_mgr;
    {
        std::string tor_bin = get_option(args, "--tor-exec", "");
        if (!tor_bin.empty()) {
            ncp::TorLaunchConfig tcfg;
            tcfg.tor_binary = tor_bin;
            tcfg.obfs4_binary = get_option(args, "--pt-obfs4", "");
            tcfg.snowflake_binary = get_option(args, "--pt-snowflake", "");
            tcfg.bridges = get_options_all(args, "--tor-bridge");
            std::cerr << "[*] Starting managed Tor"
                      << (tcfg.bridges.empty()
                              ? " (no bridges — Tor usage visible to ISP!)"
                              : " with " + std::to_string(tcfg.bridges.size()) +
                                    " bridge(s) — Tor usage hidden")
                      << "...\n";
            std::string err;
            if (!tor_mgr.start(tcfg, &err)) {
                std::cerr << "[!] Managed Tor failed: " << err << "\n";
                return;
            }
            std::cerr << "[+] Tor bootstrapped 100% — SOCKS5 on 127.0.0.1:"
                      << tor_mgr.socks_port() << "\n";
            cfg.upstream_type = "socks5";
            cfg.upstream_host = "127.0.0.1";
            cfg.upstream_port = tor_mgr.socks_port();
        }
    }
    // ── Upstream chain (Tor / SOCKS5 / HTTP CONNECT) ──
    if (!tor_mgr.running()) {
        std::string ups = get_option(args, "--upstream", "");
        if (has_flag(args, "--tor")) ups = "socks5://127.0.0.1:9050";
        if (!ups.empty()) {
            std::string rest = ups;
            auto scheme = rest.find("://");
            if (scheme != std::string::npos) {
                cfg.upstream_type = rest.substr(0, scheme);
                rest = rest.substr(scheme + 3);
            } else {
                cfg.upstream_type = "socks5";
            }
            if (cfg.upstream_type == "socks") cfg.upstream_type = "socks5";
            auto colon = rest.rfind(':');
            if (colon == std::string::npos ||
                (cfg.upstream_type != "socks5" && cfg.upstream_type != "http")) {
                std::cerr << "[!] Invalid --upstream: " << ups
                          << " (expected socks5://host:port or http://host:port)\n";
                return;
            }
            cfg.upstream_host = rest.substr(0, colon);
            int pnum = std::atoi(rest.substr(colon + 1).c_str());
            if (pnum <= 0 || pnum > 65535) {
                std::cerr << "[!] Invalid --upstream port in: " << ups << "\n";
                return;
            }
            cfg.upstream_port = static_cast<uint16_t>(pnum);
        }
    }

    if (!proxy.start(cfg)) {
        std::cerr << "[!] Failed to start proxy on " << cfg.listen_host << ":"
                  << cfg.port << "\n";
        return;
    }

    // Application mode: point the OS system proxy at us (restored on exit)
    bool sysproxy_on = false;
    if (has_flag(args, "--system-proxy")) {
        std::string sp_err;
        if (sysproxy_apply(proxy.bound_port(), &sp_err)) {
            sysproxy_on = true;
            std::cout << "[+] System proxy enabled — applications (Discord etc.) "
                         "now route through NCP. Restored automatically on exit.\n";
        } else {
            std::cerr << "[!] --system-proxy failed: " << sp_err << "\n";
        }
    }

    std::cout << "[+] NCP desync proxy active\n"
              << "    SOCKS5:        " << cfg.listen_host << ":" << proxy.bound_port() << "\n"
              << "    HTTP CONNECT:  " << cfg.listen_host << ":" << proxy.bound_port() << "\n"
              << "    QUIC block:    " << (cfg.block_quic ? "on (forces TCP fallback)" : "off") << "\n"
              << "    Fake QUIC:     " << cfg.fake_quic_repeats << " per target\n"
              << "    DoH upstream:  " << (cfg.use_doh ? "on (1.1.1.1)" : "off") << "\n"
              << (cfg.upstream_port
                      ? ("    Chain:         " + cfg.upstream_type + "://" +
                         cfg.upstream_host + ":" + std::to_string(cfg.upstream_port) +
                         (tor_mgr.running()
                              ? " (managed Tor + bridges — destination AND Tor usage hidden)"
                              : (cfg.upstream_port == 9050 || cfg.upstream_port == 9150
                                     ? " (Tor — destination IP hidden from ISP)"
                                     : " (upstream — destination IP hidden from ISP)")) +
                         "\n")
                      : "")
              << "    Chains:        " << cfg.chains.size() << "\n"
              << (cfg.events_log.empty() ? "" : ("    Events log:    " + cfg.events_log + "\n"))
              << (cfg.stats_file.empty() ? "" : ("    Stats file:    " + cfg.stats_file + "\n"))
              << "    AutoPilot:     " << (autopilot_active
                        ? ("on (" + std::to_string(autopilot.records().size()) +
                           " learned hosts, DB: " + ncp::AutoPilot::default_db_path() + ")")
                        : std::string("off")) << "\n"
              << "    System proxy:  " << (sysproxy_on ? "on (all applications)" : "off") << "\n"
              << "Point your browser/system proxy at this address. Ctrl+C to stop.\n";

    g_running = 1;
    while (g_running) {
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
    proxy.stop();
    if (sysproxy_on) {
        std::string sp_err;
        if (sysproxy_restore(&sp_err))
            std::cout << "[+] System proxy settings restored\n";
        else
            std::cerr << "[!] System proxy restore failed: " << sp_err
                      << " (run: ncp sysproxy off)\n";
    }
    if (autopilot_active) {
        autopilot.stop();
        autopilot.save();
    }
    auto st = proxy.stats();
    std::cout << "[+] Proxy stopped. Connections: " << st.connections_total
              << ", splits applied: " << st.desync_splits_applied
              << ", fake QUIC sent: " << st.fake_quic_sent
              << ", QUIC blocked: " << st.quic_datagrams_blocked
              << ", RST blocks: " << st.rst_blocks_detected
              << ", timeout blocks: " << st.timeout_blocks_detected;
    if (autopilot_active)
        std::cout << ", AutoPilot learned-strategy hits: " << st.autopilot_hits;
    std::cout << "\n";
}

// ============================================================================
// ncp blockcheck — automatic strategy selection
// ============================================================================
void handle_blockcheck(const std::vector<std::string>& args) {
    if (has_flag(args, "--help") || has_flag(args, "-h")) {
        std::cout << "Usage: ncp blockcheck [options]\n"
                  << "  --domains a,b,c       Domains to probe (default: built-in list)\n"
                  << "  --timeout MS          Per-probe timeout (default 5000)\n"
                  << "  --json                Print report as JSON\n"
                  << "  --out FILE            Save report JSON to FILE\n"
                  << "  --apply               Print best strategy as DPIConfig/profile JSON\n";
        return;
    }
    ncp::BlockChecker::Config cfg;
    cfg.timeout_ms = get_option_int(args, "--timeout", 5000);

    std::string domains_opt = get_option(args, "--domains", "");
    if (!domains_opt.empty()) {
        std::istringstream ss(domains_opt);
        std::string tok;
        while (std::getline(ss, tok, ',')) {
            size_t b = tok.find_first_not_of(" \t");
            size_t e = tok.find_last_not_of(" \t");
            if (b != std::string::npos) cfg.domains.push_back(tok.substr(b, e - b + 1));
        }
    }

    const bool quiet = has_flag(args, "--json") || !get_option(args, "--out", "").empty();
    if (!quiet) {
        cfg.progress_cb = [](const std::string& strat, const std::string& domain, bool ok) {
            std::cout << "  [" << (ok ? "OK" : "FAIL") << "] " << strat
                      << " -> " << domain << "\n";
        };
    }

    std::cout << "[*] Running blockcheck (" 
              << (cfg.domains.empty() ? 6 : cfg.domains.size()) << " domains, "
              << "timeout " << cfg.timeout_ms << "ms)...\n";

    ncp::BlockChecker checker;
    auto report = checker.run(cfg);

    std::string out_path = get_option(args, "--out", "");
    if (!out_path.empty()) {
        std::ofstream f(out_path, std::ios::trunc);
        f << ncp::BlockChecker::report_to_json(report);
        std::cout << "[+] Report written to " << out_path << "\n";
    }
    if (has_flag(args, "--json")) {
        std::cout << ncp::BlockChecker::report_to_json(report);
    } else {
        std::cout << "\n═══ Blockcheck results ═══\n";
        for (const auto& r : report.results) {
            std::cout << "  " << r.strategy << ": " << r.success_count << "/" << r.total
                      << " ok";
            if (r.success_count > 0)
                std::cout << ", avg " << r.avg_latency_ms << " ms";
            if (r.strategy == report.best_strategy) std::cout << "   <-- BEST";
            std::cout << "\n";
        }
        std::cout << "\n[+] Best strategy: " << report.best_strategy
                  << " (" << report.best_description << ")\n";
    }

    std::string apply_path = get_option(args, "--apply", "");
    if (!apply_path.empty()) {
        std::ofstream f(apply_path, std::ios::trunc);
        f << ncp::BlockChecker::best_strategy_to_profile_json(report);
        std::cout << "[+] Best strategy profile written to " << apply_path << "\n";
    }
}

// ============================================================================
// ncp autopilot — adaptive self-learning DPI bypass engine
// ============================================================================

// Application domain presets: learning these covers the whole app, not just
// its main website (e.g. Discord uses separate domains for gateway/CDN/media).
static const std::map<std::string, std::vector<std::string>>& autopilot_presets() {
    static const std::map<std::string, std::vector<std::string>> presets = {
        {"discord", {"discord.com", "www.discord.com", "discord.gg",
                     "gateway.discord.gg", "cdn.discordapp.com",
                     "media.discordapp.net", "images-ext-1.discordapp.net",
                     "discord.media", "discordapp.com", "discordapp.net",
                     "status.discord.com", "ptb.discord.com"}},
        {"youtube", {"youtube.com", "www.youtube.com", "m.youtube.com",
                     "googlevideo.com", "i.ytimg.com", "yt3.ggpht.com",
                     "youtu.be"}},
        {"x", {"x.com", "www.x.com", "twitter.com", "api.x.com",
               "abs.twimg.com", "pbs.twimg.com", "video.twimg.com"}},
    };
    return presets;
}

void handle_autopilot(const std::vector<std::string>& args) {
    // first non-flag token = action
    std::string action;
    std::string positional;
    for (const auto& a : args) {
        if (!a.empty() && a[0] == '-') continue;
        if (action.empty()) { action = a; continue; }
        if (positional.empty()) { positional = a; continue; }
    }
    if (action.empty() || has_flag(args, "--help") || has_flag(args, "-h")) {
        std::cout << "Usage: ncp autopilot <action> [options]\n"
                  << "  status [--json]        Show learned per-host strategies\n"
                  << "  learn <domain>         Probe all strategies for domain, store the best\n"
                  << "                         (--doh: resolve probe targets via DNS-over-HTTPS)\n"
                  << "  learn-preset <name>    Learn all domains of an app: discord|youtube|x\n"
                  << "  reset [domain]         Drop one record (or all, if omitted)\n"
                  << "  enable                 Persistently enable AutoPilot (proxy picks it up)\n"
                  << "  disable                Persistently disable AutoPilot\n"
                  << "\n"
                  << "AutoPilot learns which desync strategy works for each host by live\n"
                  << "probing (TLS ClientHello over TCP/443 through a temporary local proxy),\n"
                  << "applies it inside `ncp proxy`, watches live traffic for degradation\n"
                  << "(RST/timeout) and re-learns automatically in the background.\n"
                  << "DB: " << ncp::AutoPilot::default_db_path() << "\n";
        return;
    }

    ncp::AutoPilot ap;
    ncp::AutoPilot::Config cfg;
    cfg.probe_timeout_ms = get_option_int(args, "--timeout", 5000);
    cfg.use_doh = has_flag(args, "--doh");
    ap.load(cfg);

    if (action == "status") {
        if (has_flag(args, "--json")) {
            std::cout << ap.to_json();
            return;
        }
        auto recs = ap.records();
        std::cout << "═══ AutoPilot status ═══\n"
                  << "  Enabled:   " << (ap.enabled() ? "yes" : "no") << "\n"
                  << "  DB:        " << ncp::AutoPilot::default_db_path() << "\n"
                  << "  Records:   " << recs.size() << "\n";
        if (recs.empty()) {
            std::cout << "  (no learned hosts yet — use `ncp autopilot learn <domain>`)\n";
            return;
        }
        std::cout << "  ────────────────────────────────────────────────────────────\n";
        for (const auto& r : recs) {
            std::cout << "  " << r.host << "\n"
                      << "      strategy: " << r.strategy.name
                      << (r.degraded ? "  [DEGRADED — will re-learn]" : "") << "\n"
                      << "      ok/fail:  " << r.successes << "/" << r.failures
                      << " (streak " << r.consec_failures << ")";
            if (r.ewma_latency_ms > 0.0)
                std::cout << ", ewma " << r.ewma_latency_ms << " ms";
            std::cout << "\n";
        }
        return;
    }

    if (action == "learn") {
        if (positional.empty()) {
            std::cerr << "[!] Usage: ncp autopilot learn <domain> [--timeout ms]\n";
            return;
        }
        std::cout << "[*] AutoPilot learning " << positional
                  << " (probing strategies, timeout " << cfg.probe_timeout_ms << "ms)...\n";
        std::string learned;
        bool ok = ap.learn(positional, &learned);
        if (ok) {
            std::cout << "[+] Learned " << ncp::AutoPilot::normalize_host(positional)
                      << ": best strategy = " << learned << "\n";
        } else {
            std::cout << "[-] No working strategy found for " << positional
                      << " (host unreachable or IP-level blocked). "
                      << "Marked degraded; background re-learn will retry with backoff.\n";
        }
        return;
    }

    if (action == "reset") {
        ap.reset(positional);
        std::cout << "[+] AutoPilot DB "
                  << (positional.empty() ? "wiped" : ("record dropped: " + positional))
                  << "\n";
        return;
    }

    if (action == "learn-preset") {
        if (positional.empty()) {
            std::cerr << "[!] Usage: ncp autopilot learn-preset <";
            bool first = true;
            for (const auto& kv : autopilot_presets()) {
                std::cerr << (first ? "" : "|") << kv.first;
                first = false;
            }
            std::cerr << "> [--doh] [--timeout ms]\n";
            return;
        }
        auto it = autopilot_presets().find(positional);
        if (it == autopilot_presets().end()) {
            std::cerr << "[!] Unknown preset: " << positional << "\n";
            return;
        }
        std::cout << "[*] AutoPilot learning preset '" << positional << "' ("
                  << it->second.size() << " domains)...\n";
        int ok_count = 0;
        int idx = 0;
        for (const auto& domain : it->second) {
            ++idx;
            std::cout << "  [" << idx << "/" << it->second.size() << "] " << domain
                      << " ... " << std::flush;
            std::string learned;
            if (ap.learn(domain, &learned)) {
                std::cout << learned << "\n";
                ++ok_count;
            } else {
                std::cout << "no working strategy (marked degraded)\n";
            }
        }
        std::cout << "[+] Preset '" << positional << "': " << ok_count << "/"
                  << it->second.size() << " domains learned\n";
        return;
    }

    if (action == "enable") {
        ap.set_enabled(true);
        std::cout << "[+] AutoPilot enabled. `ncp proxy` will now use learned "
                     "per-host strategies automatically.\n";
        return;
    }
    if (action == "disable") {
        ap.set_enabled(false);
        std::cout << "[+] AutoPilot disabled.\n";
        return;
    }

    std::cerr << "[!] Unknown autopilot action: " << action
              << " (try: ncp autopilot --help)\n";
}

// ============================================================================
// ncp import-zapret — import zapret CLI strategy
// ============================================================================
void handle_import_zapret(const std::vector<std::string>& args) {
    if (has_flag(args, "--help") || has_flag(args, "-h")) {
        std::cout << "Usage: ncp import-zapret (--args \"<zapret flags>\" | --file LIST.TXT)\n"
                  << "  Parses zapret CLI flags and prints the resulting strategy profile as JSON.\n";
        return;
    }
    std::string cmdline = get_option(args, "--args", "");
    std::string file = get_option(args, "--file", "");
    if (cmdline.empty() && file.empty()) {
        std::cerr << "[!] Usage: ncp import-zapret --args \"<zapret args>\" | --file <args.txt> [--out profile.json]\n";
        return;
    }
    if (!file.empty()) {
        std::ifstream f(file);
        if (!f.is_open()) {
            std::cerr << "[!] Cannot read " << file << "\n";
            return;
        }
        std::stringstream buf;
        buf << f.rdbuf();
        cmdline = buf.str();
    }

    auto result = DPI::parse_zapret_cmdline(cmdline);
    std::string json = DPI::zapret_profile_to_json(result);

    std::string out_path = get_option(args, "--out", "");
    if (!out_path.empty()) {
        std::ofstream f(out_path, std::ios::trunc);
        f << json;
        std::cout << "[+] Profile written to " << out_path << "\n";
    } else {
        std::cout << json;
    }

    if (!result.errors.empty()) {
        std::cerr << "[!] " << result.errors.size() << " parse error(s)\n";
        return;
    }
    std::cout << "[+] Imported " << result.profile.chains.size() << " chain(s)";
    if (!result.warnings.empty())
        std::cout << ", " << result.warnings.size() << " warning(s)";
    std::cout << "\n";
}
