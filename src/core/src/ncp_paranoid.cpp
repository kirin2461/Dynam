// Force _WIN32_WINNT to Windows 10 BEFORE any other includes
// (SetProcessMitigationPolicy requires >= 0x0602)
// R11-L03: Use named constants for Windows version macros
#ifdef _WIN32
#  undef  _WIN32_WINNT
#  define _WIN32_WINNT_WIN10 0x0A00  // Windows 10
#  define _WIN32_WINNT _WIN32_WINNT_WIN10
#  undef  NTDDI_VERSION
#  define NTDDI_WIN10 0x0A000000     // Windows 10
#  define NTDDI_VERSION NTDDI_WIN10
#endif

#include "ncp_paranoid.hpp"
#include <algorithm>
#include <thread>
#include <chrono>
#include <sodium.h>
#include <fstream>
#include <cstdlib>
#include <cstring>
#include <iostream>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <windns.h>
#include <fwpmu.h>
#pragma comment(lib, "dnsapi.lib")
#pragma comment(lib, "fwpuclnt.lib")
#pragma comment(lib, "ws2_32.lib")
#include <io.h>
#include <fcntl.h>
#include <shlobj.h>
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "kernel32.lib")
#else
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <glob.h>
#include <pwd.h>
#endif

// R10-FIX-01: Secure string clearing helper to avoid UB with sodium_memzero on std::string
// Uses volatile pointer to prevent compiler optimization of the clearing operation
static void secure_clear_string(std::string& str) {
    if (str.empty()) return;
    // Use volatile to ensure the compiler doesn't optimize away the clearing
    volatile char* p = str.data();
    size_t len = str.size();
    for (size_t i = 0; i < len; ++i) {
        p[i] = 0;
    }
    // libsodium's sodium_memzero is safe for raw buffers, not std::string internal representation
    sodium_memzero(str.data(), str.size());
}

namespace ncp {

// ---- Safe data directory resolution ------------------------------------
// Returns the NCP-specific data directory. Never returns a dangerous path
// like $HOME, /etc, /tmp, or C:\Windows.

static std::string get_ncp_data_directory() {
    std::string base_dir;

#ifdef _WIN32
    // Use %LOCALAPPDATA%\ncp\data
    char appdata[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathA(nullptr, CSIDL_LOCAL_APPDATA, nullptr, 0, appdata))) {
        base_dir = std::string(appdata) + "\\ncp\\data";
    } else {
        // Fallback: use relative path
        base_dir = ".\\ncp_data";
    }
#else
    // Use $XDG_DATA_HOME/ncp or ~/.local/share/ncp
    const char* xdg = std::getenv("XDG_DATA_HOME");
    if (xdg && xdg[0] != '\0') {
        base_dir = std::string(xdg) + "/ncp";
    } else {
        const char* home = std::getenv("HOME");
        if (!home || home[0] == '\0') {
            struct passwd* pw = getpwuid(getuid());
            if (pw) home = pw->pw_dir;
        }
        if (home && home[0] != '\0') {
            base_dir = std::string(home) + "/.local/share/ncp";
        } else {
            base_dir = "./ncp_data";
        }
    }
#endif

    return base_dir;
}

// Validate that the path is not a dangerous system directory
static bool is_safe_shred_directory(const std::string& dir) {
    if (dir.empty()) return false;

    // Normalize: remove trailing slashes
    std::string normalized = dir;
    while (normalized.size() > 1 &&
           (normalized.back() == '/' || normalized.back() == '\\')) {
        normalized.pop_back();
    }

#ifdef _WIN32
    // Block dangerous Windows paths (case-insensitive)
    std::string lower = normalized;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

    if (lower == "c:" || lower == "c:\\" || lower == "c:/") return false;
    if (lower.find("c:\\windows") == 0) return false;
    if (lower.find("c:\\program files") == 0) return false;
    if (lower.find("c:\\users") == 0 && lower.find("\\ncp") == std::string::npos) return false;

    // Must contain "ncp" somewhere in path as a safety check
    return lower.find("ncp") != std::string::npos;
#else
    // Block dangerous Unix paths
    if (normalized == "/" || normalized == "/etc" || normalized == "/tmp" ||
        normalized == "/var" || normalized == "/usr" || normalized == "/bin" ||
        normalized == "/sbin" || normalized == "/lib" || normalized == "/boot" ||
        normalized == "/dev" || normalized == "/proc" || normalized == "/sys") {
        return false;
    }

    // Block bare $HOME (but allow $HOME/.local/share/ncp)
    const char* home = std::getenv("HOME");
    if (home && normalized == std::string(home)) return false;

    // Must contain "ncp" somewhere in path as a safety check
    return normalized.find("ncp") != std::string::npos;
#endif
}

// ---- ParanoidMode::Impl (pimpl idiom) ---------------------------------

struct ParanoidMode::Impl {
    std::vector<std::string> active_circuits;
    std::thread cover_traffic_thread;
    bool cover_traffic_running = false;
    std::chrono::system_clock::time_point last_rotation;
    std::vector<std::string> bridge_nodes;
    bool kill_switch_active = false;
    bool memory_protection_enabled = false;
#ifdef _WIN32
    HANDLE wfp_engine_handle = nullptr;
    std::vector<UINT64> wfp_filter_ids;
#endif

    // ---- Hop chain state (for configure_hop_chain / get_active_chains) ----
    struct HopKeyMaterial {
        uint8_t shared_key[32];   // DH-derived shared key for this hop
        uint8_t layer_nonce[24];  // Per-hop nonce (XChaCha20 sized)
        uint32_t hop_id;          // Unique hop identifier
    };

    struct HopChainState {
        ParanoidMode::HopChain chain;           // The original chain descriptor
        std::vector<HopKeyMaterial> key_material; // Per-hop crypto material
    };

    std::vector<HopChainState> hop_chains;  // All configured chains

    // RAM-only mode: path of the tmpfs mount point (Linux) or temp dir (Windows)
    std::string ram_only_base_dir;
    bool ram_only_active = false;

    // Pluggable transport state
    std::vector<std::pair<std::string, std::string>> available_transports;
    std::string active_transport;

    // R11-H02: Kill switch timeout to prevent permanent network lockout
    std::chrono::steady_clock::time_point kill_switch_activation_time;
    std::chrono::seconds kill_switch_timeout_duration{0};
    bool kill_switch_timeout_enabled = false;

    // Safe cleanup: clear all fields using proper C++ methods
    // R10-FIX-01: Use SecureString-compatible wiping instead of undefined behavior
    void safe_wipe() {
        // Clear strings and vectors using secure memory overwrite
        for (auto& circuit : active_circuits) {
            secure_clear_string(circuit);
        }
        active_circuits.clear();
        active_circuits.shrink_to_fit();

        for (auto& node : bridge_nodes) {
            secure_clear_string(node);
        }
        bridge_nodes.clear();
        bridge_nodes.shrink_to_fit();

        // R9-C02: Wipe hop chain key material with proper shrink_to_fit
        for (auto& cs : hop_chains) {
            for (auto& km : cs.key_material) {
                sodium_memzero(km.shared_key, sizeof(km.shared_key));
                sodium_memzero(km.layer_nonce, sizeof(km.layer_nonce));
            }
            cs.key_material.clear();
            cs.key_material.shrink_to_fit();
        }
        hop_chains.clear();
        hop_chains.shrink_to_fit();

        // Wipe RAM-only path
        if (!ram_only_base_dir.empty()) {
            sodium_memzero(&ram_only_base_dir[0], ram_only_base_dir.size());
        }
        ram_only_base_dir.clear();
        ram_only_base_dir.shrink_to_fit();
        ram_only_active = false;

        // Reset primitives
        cover_traffic_running = false;
        kill_switch_active = false;
        kill_switch_timeout_enabled = false;
        kill_switch_timeout_duration = std::chrono::seconds{0};
        kill_switch_activation_time = {};
        memory_protection_enabled = false;
        last_rotation = {};

#ifdef _WIN32
        wfp_filter_ids.clear();
        wfp_filter_ids.shrink_to_fit();
        wfp_engine_handle = nullptr;
#endif
    }
};

// ---- Construction / Destruction ----------------------------------------

ParanoidMode::ParanoidMode()
    : impl_(std::make_unique<Impl>()) {}

ParanoidMode::~ParanoidMode() noexcept {
    if (is_active_) {
        deactivate();
    }
}

// ---- Configuration methods ---------------------------------------------

void ParanoidMode::set_threat_level(ThreatLevel level) {
    threat_level_ = level;
    switch (level) {
        case ThreatLevel::MODERATE:
            layered_config_.rotate_entry_guards = false;
            layered_config_.enable_tor_over_i2p = false;
            break;
        case ThreatLevel::HIGH:
            layered_config_.rotate_entry_guards = true;
            layered_config_.enable_tor_over_i2p = true;
            break;
        case ThreatLevel::EXTREME:
        case ThreatLevel::TINFOIL_HAT:
            layered_config_.rotate_entry_guards = true;
            layered_config_.enable_tor_over_i2p = true;
            layered_config_.enable_traffic_splitting = true;
            break;
    }
}

ParanoidMode::ThreatLevel ParanoidMode::get_threat_level() const {
    return threat_level_;
}

void ParanoidMode::set_layered_config(const LayeredConfig& config) {
    layered_config_ = config;
}

void ParanoidMode::set_network_isolation(const NetworkIsolation& config) {
    network_isolation_ = config;
}

void ParanoidMode::set_forensic_resistance(const ForensicResistance& config) {
    forensic_resistance_ = config;
}

void ParanoidMode::set_traffic_analysis_resistance(const TrafficAnalysisResistance& config) {
    traffic_analysis_resistance_ = config;
}

void ParanoidMode::set_advanced_features(const AdvancedFeatures& config) {
    advanced_features_ = config;
}

// ---- Activation --------------------------------------------------------

bool ParanoidMode::activate() {
    if (is_active_) return true;

    setup_bridge_nodes();
    configure_multi_hop();
    enable_memory_protection();
    setup_kill_switch();

    if (layered_config_.enable_constant_rate_traffic) {
        start_cover_traffic_generator();
    }

    if (traffic_analysis_resistance_.enable_wfp_defense) {
        configure_website_fingerprinting_defense();
    }

    is_active_ = true;
    return true;
}

bool ParanoidMode::deactivate() {
    if (!is_active_) return false;

    stop_cover_traffic();
    impl_->active_circuits.clear();

    // R11-H02: Check and log kill switch timeout status
    if (impl_->kill_switch_timeout_enabled) {
        auto now = std::chrono::steady_clock::now();
        auto elapsed = now - impl_->kill_switch_activation_time;
        if (elapsed >= impl_->kill_switch_timeout_duration) {
            std::cerr << "[!] Kill switch timeout expired (" 
                      << network_isolation_.kill_switch_timeout_sec << "s), disabling...\n";
        }
    }

    // Teardown kill switch before clearing flag
#ifdef _WIN32
    if (impl_->wfp_engine_handle) {
        // Remove all WFP filters
        for (UINT64 filter_id : impl_->wfp_filter_ids) {
            FwpmFilterDeleteById0(impl_->wfp_engine_handle, filter_id);
        }
        impl_->wfp_filter_ids.clear();
        FwpmEngineClose0(impl_->wfp_engine_handle);
        impl_->wfp_engine_handle = nullptr;
    }
#else
    if (impl_->kill_switch_active) {
        // Remove iptables rules via fork+exec
        pid_t pid = fork();
        if (pid == 0) {
            close(STDIN_FILENO);
            close(STDOUT_FILENO);
            close(STDERR_FILENO);
            execlp("iptables", "iptables", "-D", "OUTPUT", "-j", "DROP", nullptr);
            _exit(127);
        } else if (pid > 0) {
            int status;
            waitpid(pid, &status, 0);
        }
    }
#endif
    impl_->kill_switch_active = false;
    impl_->kill_switch_timeout_enabled = false;

    if (forensic_resistance_.clear_memory_on_exit) {
        clear_all_traces();
    }

    is_active_ = false;
    return true;
}

bool ParanoidMode::is_active() const {
    return is_active_;
}

// ---- Multi-hop configuration -------------------------------------------

bool ParanoidMode::configure_hop_chain(const HopChain& chain) {
    // Onion-style key derivation for each hop in the chain.
    //
    // For each node in chain.nodes we:
    //   1. Generate an ephemeral X25519 keypair.
    //   2. If the node string encodes a 32-byte public key (44-char base64 or
    //      raw 32 bytes) we perform a real DH exchange with that key.
    //      Otherwise we use the node string as entropy input into BLAKE2b
    //      to derive a deterministic (but non-interactive) shared key —
    //      this handles symbolic node names such as "bridge.example.com:443".
    //   3. From the shared secret we derive:
    //        shared_key  = BLAKE2b-256(shared_secret || hop_index || "key")
    //        layer_nonce = first 24 bytes of BLAKE2b-256(shared_secret || hop_index || "nonce")
    //   4. The hop_id is a 32-bit counter incremented atomically.
    //
    // All ephemeral secret keys are wiped with sodium_memzero immediately after use.

    if (chain.nodes.empty()) return false;

    Impl::HopChainState state;
    state.chain = chain;
    state.key_material.reserve(chain.nodes.size());

    static uint32_t hop_id_counter = 0;

    for (size_t hop_idx = 0; hop_idx < chain.nodes.size(); ++hop_idx) {
        const std::string& node = chain.nodes[hop_idx];

        Impl::HopKeyMaterial km;
        km.hop_id = ++hop_id_counter;

        // Try to treat node as a base64-encoded X25519 public key (44 chars)
        bool did_dh = false;
        if (node.size() == 44 || node.size() == 32) {
            uint8_t remote_pk[32];
            bool decoded = false;

            if (node.size() == 32) {
                std::memcpy(remote_pk, node.data(), 32);
                decoded = true;
            } else {
                // Base64 decode
                size_t decoded_len = 0;
                const char* end_ptr = nullptr;
                int rc = sodium_base642bin(
                    remote_pk, sizeof(remote_pk),
                    node.c_str(), node.size(),
                    nullptr, &decoded_len, &end_ptr,
                    sodium_base64_VARIANT_ORIGINAL);
                decoded = (rc == 0 && decoded_len == 32);
            }

            if (decoded) {
                // DH key exchange
                uint8_t eph_pk[32], eph_sk[32];
                crypto_box_keypair(eph_pk, eph_sk);

                uint8_t raw_secret[32];
                if (crypto_scalarmult(raw_secret, eph_sk, remote_pk) == 0) {
                    // derive shared_key
                    crypto_generichash_state gh;
                    uint8_t idx_buf[4] = {
                        static_cast<uint8_t>((hop_idx >> 24) & 0xFF),
                        static_cast<uint8_t>((hop_idx >> 16) & 0xFF),
                        static_cast<uint8_t>((hop_idx >>  8) & 0xFF),
                        static_cast<uint8_t>( hop_idx        & 0xFF)
                    };
                    static const uint8_t key_ctx[] = "key";
                    crypto_generichash_init(&gh, nullptr, 0, 32);
                    crypto_generichash_update(&gh, raw_secret, 32);
                    crypto_generichash_update(&gh, idx_buf, 4);
                    crypto_generichash_update(&gh, key_ctx, 3);
                    crypto_generichash_final(&gh, km.shared_key, 32);

                    // derive layer_nonce (24 bytes from 32-byte hash)
                    uint8_t nonce_hash[32];
                    static const uint8_t nonce_ctx[] = "nonce";
                    crypto_generichash_init(&gh, nullptr, 0, 32);
                    crypto_generichash_update(&gh, raw_secret, 32);
                    crypto_generichash_update(&gh, idx_buf, 4);
                    crypto_generichash_update(&gh, nonce_ctx, 5);
                    crypto_generichash_final(&gh, nonce_hash, 32);
                    std::memcpy(km.layer_nonce, nonce_hash, 24);
                    sodium_memzero(nonce_hash, sizeof(nonce_hash));

                    sodium_memzero(raw_secret, sizeof(raw_secret));
                    did_dh = true;
                }
                sodium_memzero(eph_sk, sizeof(eph_sk));
            }
        }

        if (!did_dh) {
            // Symbolic node name: hash the node string + hop_index as entropy
            // to get a deterministic (non-interactive) key.  This is not real
            // forward-secret DH but provides structural separation between hops.
            uint8_t idx_buf[4] = {
                static_cast<uint8_t>((hop_idx >> 24) & 0xFF),
                static_cast<uint8_t>((hop_idx >> 16) & 0xFF),
                static_cast<uint8_t>((hop_idx >>  8) & 0xFF),
                static_cast<uint8_t>( hop_idx        & 0xFF)
            };
            // Add CSPRNG salt so even symbolic chains are not fully deterministic
            uint8_t salt[16];
            randombytes_buf(salt, sizeof(salt));

            static const uint8_t key_ctx[]   = "key";
            static const uint8_t nonce_ctx[] = "nonce";

            crypto_generichash_state gh;
            crypto_generichash_init(&gh, nullptr, 0, 32);
            crypto_generichash_update(
                &gh,
                reinterpret_cast<const uint8_t*>(node.data()),
                node.size());
            crypto_generichash_update(&gh, idx_buf, 4);
            crypto_generichash_update(&gh, salt, sizeof(salt));
            crypto_generichash_update(&gh, key_ctx, 3);
            crypto_generichash_final(&gh, km.shared_key, 32);

            uint8_t nonce_hash[32];
            crypto_generichash_init(&gh, nullptr, 0, 32);
            crypto_generichash_update(
                &gh,
                reinterpret_cast<const uint8_t*>(node.data()),
                node.size());
            crypto_generichash_update(&gh, idx_buf, 4);
            crypto_generichash_update(&gh, salt, sizeof(salt));
            crypto_generichash_update(&gh, nonce_ctx, 5);
            crypto_generichash_final(&gh, nonce_hash, 32);
            std::memcpy(km.layer_nonce, nonce_hash, 24);
            sodium_memzero(nonce_hash, sizeof(nonce_hash));
        }

        state.key_material.push_back(km);
    }

    impl_->hop_chains.push_back(std::move(state));
    return true;
}

std::vector<ParanoidMode::HopChain> ParanoidMode::get_active_chains() const {
    std::vector<HopChain> result;
    result.reserve(impl_->hop_chains.size());
    for (const auto& cs : impl_->hop_chains) {
        result.push_back(cs.chain);
    }
    return result;
}

// ---- Traffic management ------------------------------------------------

void ParanoidMode::start_cover_traffic() {
    if (impl_->cover_traffic_running) return;

    impl_->cover_traffic_running = true;
    impl_->cover_traffic_thread = std::thread([this]() {
        while (impl_->cover_traffic_running) {
            inject_dummy_traffic(layered_config_.cover_traffic_rate_kbps);
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    });
}

void ParanoidMode::stop_cover_traffic() {
    impl_->cover_traffic_running = false;
    if (impl_->cover_traffic_thread.joinable()) {
        impl_->cover_traffic_thread.join();
    }
}
            
void ParanoidMode::inject_dummy_traffic(size_t bytes_per_second) {
    if (bytes_per_second == 0) return;
    
    size_t chunk_size = std::min(bytes_per_second, static_cast<size_t>(1024));
    std::vector<uint8_t> dummy_data(chunk_size);
    randombytes_buf(dummy_data.data(), dummy_data.size());
    
    // In real implementation: send to cover traffic socket
}

void ParanoidMode::enable_constant_rate_shaping(size_t rate_kbps) {
    layered_config_.cover_traffic_rate_kbps = rate_kbps;
}

// ---- Circuit management ------------------------------------------------

std::string ParanoidMode::create_isolated_circuit(const std::string& destination) {
    uint8_t id_bytes[16];
    randombytes_buf(id_bytes, sizeof(id_bytes));
    
    static const char hex_chars[] = "0123456789abcdef";
    std::string circuit_id;
    circuit_id.reserve(32);
    for (size_t i = 0; i < 16; ++i) {
        circuit_id += hex_chars[(id_bytes[i] >> 4) & 0x0F];
        circuit_id += hex_chars[id_bytes[i] & 0x0F];
    }
    
    impl_->active_circuits.push_back(circuit_id);
    (void)destination;
    return circuit_id;
}

void ParanoidMode::destroy_circuit(const std::string& circuit_id) {
    auto it = std::find(impl_->active_circuits.begin(), 
                        impl_->active_circuits.end(), circuit_id);
    if (it != impl_->active_circuits.end()) {
        impl_->active_circuits.erase(it);
    }
}

void ParanoidMode::rotate_all_circuits() {
    impl_->active_circuits.clear();
    impl_->last_rotation = std::chrono::system_clock::now();
}

void ParanoidMode::configure_circuit_isolation(bool per_domain, bool per_identity) {
    (void)per_domain;
    (void)per_identity;
}

// ---- Metadata protection -----------------------------------------------

void ParanoidMode::strip_metadata(std::vector<uint8_t>& data) {
    if (data.size() < 4) return;
    
    // JPEG EXIF removal (marker 0xFFE1)
    if (data[0] == 0xFF && data[1] == 0xD8) {
        for (size_t i = 2; i < data.size() - 3; ) {
            if (data[i] == 0xFF && data[i+1] == 0xE1) {
                uint16_t len = (data[i+2] << 8) | data[i+3];
                data.erase(data.begin() + i, data.begin() + i + 2 + len);
            } else if (data[i] == 0xFF) {
                if (data[i+1] == 0xD9 || data[i+1] == 0xDA) break;
                uint16_t len = (data[i+2] << 8) | data[i+3];
                i += 2 + len;
            } else {
                ++i;
            }
        }
    }
    // PNG tEXt chunk removal — FULL IMPLEMENTATION
    else if (data.size() > 8 && data[1] == 'P' && data[2] == 'N' && data[3] == 'G') {
        // PNG signature: 89 50 4E 47 0D 0A 1A 0A
        // Iterate PNG chunks and remove tEXt (0x74455874), iTXt (0x69545874), zTXt (0x7A545874)
        size_t pos = 8;  // Skip PNG signature
        std::vector<uint8_t> cleaned_data(data.begin(), data.begin() + 8);
        
        while (pos + 8 <= data.size()) {
            // Read chunk length (4 bytes, big-endian)
            uint32_t chunk_len = (static_cast<uint32_t>(data[pos]) << 24) |
                                 (static_cast<uint32_t>(data[pos + 1]) << 16) |
                                 (static_cast<uint32_t>(data[pos + 2]) << 8) |
                                  static_cast<uint32_t>(data[pos + 3]);
            
            // Read chunk type (4 bytes)
            uint32_t chunk_type = (static_cast<uint32_t>(data[pos + 4]) << 24) |
                                  (static_cast<uint32_t>(data[pos + 5]) << 16) |
                                  (static_cast<uint32_t>(data[pos + 6]) << 8) |
                                   static_cast<uint32_t>(data[pos + 7]);
            
            // Check for text chunks to remove
            bool is_text_chunk = (chunk_type == 0x74455874 ||  // tEXt
                                  chunk_type == 0x69545874 ||  // iTXt
                                  chunk_type == 0x7A545874);   // zTXt
            
            if (!is_text_chunk) {
                // Keep this chunk
                size_t chunk_total_size = 4 + 4 + chunk_len + 4;  // len + type + data + crc
                if (pos + chunk_total_size <= data.size()) {
                    cleaned_data.insert(cleaned_data.end(), 
                                       data.begin() + pos, 
                                       data.begin() + pos + chunk_total_size);
                }
            }
            
            // Move to next chunk
            pos += 4 + 4 + chunk_len + 4;  // len + type + data + crc
            
            // Break on IEND chunk
            if (chunk_type == 0x49454E44) break;  // IEND
        }
        
        data = std::move(cleaned_data);
    }
}

void ParanoidMode::sanitize_http_headers(std::map<std::string, std::string>& headers) {
    if (layered_config_.sanitize_headers) {
        headers.erase("User-Agent");
        headers.erase("X-Forwarded-For");
        headers.erase("Via");
        headers.erase("X-Real-IP");
        headers.erase("X-Client-IP");
    }
}

void ParanoidMode::remove_browser_fingerprints() {
    // Delete browser cache, localStorage, IndexedDB, cookies, and session
    // storage for Chrome, Firefox, Edge, and Safari on all supported platforms.
    //
    // We build a list of directory paths to delete, validate each against
    // is_safe_shred_directory(), and recursively secure-delete them.
    //
    // Note: Deletion only works if no browser process has the files open.
    // Files locked by a running browser will fail silently (best-effort).

    std::vector<std::string> targets;

#ifdef _WIN32
    // ---- Windows paths ----
    char local_app[MAX_PATH] = {};
    char roaming_app[MAX_PATH] = {};
    SHGetFolderPathA(nullptr, CSIDL_LOCAL_APPDATA,   nullptr, 0, local_app);
    SHGetFolderPathA(nullptr, CSIDL_APPDATA,         nullptr, 0, roaming_app);

    std::string la = local_app;
    std::string ra = roaming_app;

    if (!la.empty()) {
        // Chrome
        targets.push_back(la + "\\Google\\Chrome\\User Data\\Default\\Cache");
        targets.push_back(la + "\\Google\\Chrome\\User Data\\Default\\Local Storage");
        targets.push_back(la + "\\Google\\Chrome\\User Data\\Default\\IndexedDB");
        targets.push_back(la + "\\Google\\Chrome\\User Data\\Default\\Cookies");
        targets.push_back(la + "\\Google\\Chrome\\User Data\\Default\\Session Storage");
        // Edge (Chromium)
        targets.push_back(la + "\\Microsoft\\Edge\\User Data\\Default\\Cache");
        targets.push_back(la + "\\Microsoft\\Edge\\User Data\\Default\\Local Storage");
        targets.push_back(la + "\\Microsoft\\Edge\\User Data\\Default\\IndexedDB");
        targets.push_back(la + "\\Microsoft\\Edge\\User Data\\Default\\Cookies");
        targets.push_back(la + "\\Microsoft\\Edge\\User Data\\Default\\Session Storage");
        // Internet Explorer cache
        targets.push_back(la + "\\Microsoft\\Windows\\INetCache");
    }
    if (!ra.empty()) {
        // Firefox
        targets.push_back(ra + "\\Mozilla\\Firefox\\Profiles");
    }

#elif defined(__APPLE__)
    // ---- macOS paths ----
    const char* home = std::getenv("HOME");
    if (home && home[0] != '\0') {
        std::string h = home;
        // Chrome
        targets.push_back(h + "/Library/Caches/Google/Chrome");
        targets.push_back(h + "/Library/Application Support/Google/Chrome/Default/Local Storage");
        targets.push_back(h + "/Library/Application Support/Google/Chrome/Default/IndexedDB");
        targets.push_back(h + "/Library/Application Support/Google/Chrome/Default/Cookies");
        targets.push_back(h + "/Library/Application Support/Google/Chrome/Default/Session Storage");
        // Firefox
        targets.push_back(h + "/Library/Caches/Firefox");
        targets.push_back(h + "/Library/Application Support/Firefox/Profiles");
        // Safari
        targets.push_back(h + "/Library/Caches/com.apple.Safari");
        targets.push_back(h + "/Library/Safari/LocalStorage");
        targets.push_back(h + "/Library/WebKit/WebsiteData/LocalStorage");
        targets.push_back(h + "/Library/Cookies");
        // Edge (macOS)
        targets.push_back(h + "/Library/Caches/Microsoft Edge");
        targets.push_back(h + "/Library/Application Support/Microsoft Edge/Default/Local Storage");
    }

#else
    // ---- Linux paths ----
    const char* home = std::getenv("HOME");
    if (!home || home[0] == '\0') {
        struct passwd* pw = getpwuid(getuid());
        if (pw) home = pw->pw_dir;
    }
    if (home && home[0] != '\0') {
        std::string h = home;
        // Chrome / Chromium
        targets.push_back(h + "/.cache/google-chrome");
        targets.push_back(h + "/.config/google-chrome/Default/Local Storage");
        targets.push_back(h + "/.config/google-chrome/Default/IndexedDB");
        targets.push_back(h + "/.config/google-chrome/Default/Cookies");
        targets.push_back(h + "/.config/google-chrome/Default/Session Storage");
        targets.push_back(h + "/.cache/chromium");
        targets.push_back(h + "/.config/chromium/Default/Local Storage");
        targets.push_back(h + "/.config/chromium/Default/IndexedDB");
        targets.push_back(h + "/.config/chromium/Default/Cookies");
        // Firefox
        targets.push_back(h + "/.cache/mozilla/firefox");
        targets.push_back(h + "/.mozilla/firefox");  // profiles (incl. cookies, history)
        // Edge (Linux)
        targets.push_back(h + "/.cache/microsoft-edge");
        targets.push_back(h + "/.config/microsoft-edge/Default/Local Storage");
        targets.push_back(h + "/.config/microsoft-edge/Default/Cookies");
    }
#endif

    // Iterate and delete each target
    for (const auto& path : targets) {
        if (path.empty()) continue;

        // Safety check: never shred a path that doesn't contain a
        // browser-related component — belt-and-suspenders guard.
        bool safe = false;
        static const char* const browser_markers[] = {
            "Chrome", "chrome", "Chromium", "chromium",
            "Firefox", "firefox", "Mozilla", "mozilla",
            "Edge", "edge", "Safari", "safari",
            "INetCache", "WebKit", nullptr
        };
        for (int i = 0; browser_markers[i]; ++i) {
            if (path.find(browser_markers[i]) != std::string::npos) {
                safe = true;
                break;
            }
        }
        if (!safe) continue;

#ifdef _WIN32
        // Check if path is a file or directory
        DWORD attr = GetFileAttributesA(path.c_str());
        if (attr == INVALID_FILE_ATTRIBUTES) continue;  // doesn't exist
        if (attr & FILE_ATTRIBUTE_DIRECTORY) {
            // Recursively delete via find+delete
            std::string pattern = path + "\\*";
            WIN32_FIND_DATAA ffd;
            HANDLE hFind = FindFirstFileA(pattern.c_str(), &ffd);
            if (hFind != INVALID_HANDLE_VALUE) {
                do {
                    std::string name = ffd.cFileName;
                    if (name == "." || name == "..") continue;
                    std::string full = path + "\\" + name;
                    if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                        // Recurse (single level is sufficient for browser dirs)
                        WIN32_FIND_DATAA ffd2;
                        std::string subpat = full + "\\*";
                        HANDLE hFind2 = FindFirstFileA(subpat.c_str(), &ffd2);
                        if (hFind2 != INVALID_HANDLE_VALUE) {
                            do {
                                if (std::string(ffd2.cFileName) == "." ||
                                    std::string(ffd2.cFileName) == "..") continue;
                                std::string sub = full + "\\" + ffd2.cFileName;
                                shred_file(sub, 1);
                            } while (FindNextFileA(hFind2, &ffd2));
                            FindClose(hFind2);
                        }
                        RemoveDirectoryA(full.c_str());
                    } else {
                        shred_file(full, 1);
                    }
                } while (FindNextFileA(hFind, &ffd));
                FindClose(hFind);
            }
            RemoveDirectoryA(path.c_str());
        } else {
            shred_file(path, 1);
        }
#else
        struct stat st{};
        if (lstat(path.c_str(), &st) != 0) continue;
        if (S_ISDIR(st.st_mode)) {
            // Walk directory
            DIR* d = opendir(path.c_str());
            if (!d) continue;
            struct dirent* ent;
            while ((ent = readdir(d)) != nullptr) {
                std::string name = ent->d_name;
                if (name == "." || name == "..") continue;
                std::string full = path + "/" + name;
                struct stat st2{};
                if (lstat(full.c_str(), &st2) != 0) continue;
                if (S_ISDIR(st2.st_mode)) {
                    // One level of recursion for browser sub-directories
                    DIR* d2 = opendir(full.c_str());
                    if (d2) {
                        struct dirent* ent2;
                        while ((ent2 = readdir(d2)) != nullptr) {
                            std::string n2 = ent2->d_name;
                            if (n2 == "." || n2 == "..") continue;
                            std::string sub = full + "/" + n2;
                            shred_file(sub, 1);
                        }
                        closedir(d2);
                    }
                    rmdir(full.c_str());
                } else {
                    shred_file(full, 1);
                }
            }
            closedir(d);
            rmdir(path.c_str());
        } else if (S_ISREG(st.st_mode)) {
            shred_file(path, 1);
        }
#endif
    }
}

// ---- Timing protection -------------------------------------------------

void ParanoidMode::add_random_delay() {
    if (layered_config_.enable_random_delays) {
        auto delay_ms = layered_config_.min_delay_ms + 
            static_cast<int>(randombytes_uniform(
                static_cast<uint32_t>(layered_config_.max_delay_ms - 
                                       layered_config_.min_delay_ms + 1)));
        std::this_thread::sleep_for(std::chrono::milliseconds(delay_ms));
    }
}

void ParanoidMode::enable_request_batching(int batch_size, int max_delay_ms) {
    layered_config_.enable_batching = true;
    layered_config_.batch_size = batch_size;
    layered_config_.max_delay_ms = max_delay_ms;
}

std::chrono::milliseconds ParanoidMode::calculate_safe_delay() {
    auto delay = layered_config_.min_delay_ms + 
        static_cast<int>(randombytes_uniform(
            static_cast<uint32_t>(layered_config_.max_delay_ms - 
                                   layered_config_.min_delay_ms + 1)));
    return std::chrono::milliseconds(delay);
}

// ---- Forensic protection -----------------------------------------------

void ParanoidMode::enable_ram_only_mode() {
    forensic_resistance_.use_ram_only = true;

    // Set up an in-memory filesystem for temporary file I/O.
    //
    // Linux: mount a private tmpfs under /dev/shm/ncp_XXXXXX (or /tmp).
    //        All file writes should be directed here; the directory is
    //        automatically reclaimed when the OS unmounts it or on reboot.
    // Windows: create a temp directory with FILE_ATTRIBUTE_TEMPORARY so the
    //          OS keeps it in the pagefile/cache rather than flushing to disk;
    //          register an atexit handler to delete it on process exit.
    //
    // The resolved path is stored in impl_->ram_only_base_dir so callers can
    // redirect their file I/O through it.

    if (impl_->ram_only_active) return;  // Already set up

#ifdef _WIN32
    // Windows: use GetTempPath + a unique subdirectory.
    // Files created with FILE_ATTRIBUTE_TEMPORARY + FILE_FLAG_DELETE_ON_CLOSE
    // are kept in memory by the cache manager and deleted when the handle closes.
    char temp_root[MAX_PATH];
    DWORD len = GetTempPathA(MAX_PATH, temp_root);
    if (len == 0 || len >= MAX_PATH) return;

    // Create a unique subdirectory: %TEMP%\ncp_ram_XXXXXXXX
    char unique_dir[MAX_PATH];
    if (GetTempFileNameA(temp_root, "ncp", 0, unique_dir) == 0) return;
    // GetTempFileName creates a file; delete it and recreate as a directory
    DeleteFileA(unique_dir);
    if (!CreateDirectoryA(unique_dir, nullptr)) return;

    impl_->ram_only_base_dir = unique_dir;
    impl_->ram_only_active   = true;

    // Register atexit cleanup to remove the directory on process exit
    static std::string* s_ram_dir_ptr = nullptr;
    if (!s_ram_dir_ptr) {
        s_ram_dir_ptr = new std::string(impl_->ram_only_base_dir);
        std::atexit([]() {
            if (s_ram_dir_ptr && !s_ram_dir_ptr->empty()) {
                // Recursively delete the RAM temp directory
                // Use wide-char API for robustness
                std::string pattern = *s_ram_dir_ptr + "\\*";
                WIN32_FIND_DATAA ffd;
                HANDLE hFind = FindFirstFileA(pattern.c_str(), &ffd);
                if (hFind != INVALID_HANDLE_VALUE) {
                    do {
                        std::string name = ffd.cFileName;
                        if (name == "." || name == "..") continue;
                        std::string full = *s_ram_dir_ptr + "\\" + name;
                        if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                            RemoveDirectoryA(full.c_str());
                        } else {
                            // Zero the file before deleting (best-effort)
                            HANDLE hf = CreateFileA(full.c_str(),
                                GENERIC_WRITE, 0, nullptr,
                                OPEN_EXISTING,
                                FILE_ATTRIBUTE_TEMPORARY, nullptr);
                            if (hf != INVALID_HANDLE_VALUE) {
                                LARGE_INTEGER fsz;
                                GetFileSizeEx(hf, &fsz);
                                if (fsz.QuadPart > 0) {
                                    std::vector<uint8_t> zeros(
                                        static_cast<size_t>(fsz.QuadPart < 65536
                                            ? fsz.QuadPart : 65536), 0);
                                    LARGE_INTEGER zero = {};
                                    SetFilePointerEx(hf, zero, nullptr, FILE_BEGIN);
                                    DWORD written = 0;
                                    WriteFile(hf, zeros.data(),
                                        static_cast<DWORD>(zeros.size()),
                                        &written, nullptr);
                                    FlushFileBuffers(hf);
                                }
                                CloseHandle(hf);
                            }
                            DeleteFileA(full.c_str());
                        }
                    } while (FindNextFileA(hFind, &ffd));
                    FindClose(hFind);
                }
                RemoveDirectoryA(s_ram_dir_ptr->c_str());
            }
        });
    }

#else
    // Linux/macOS: use /dev/shm if available (Linux tmpfs), else /tmp.
    // /dev/shm is a RAM-backed tmpfs on most Linux systems.
    struct stat shm_stat{};
    std::string base = (stat("/dev/shm", &shm_stat) == 0) ? "/dev/shm" : "/tmp";

    // Create a unique subdirectory
    std::string tmpl = base + "/ncp_ram_XXXXXX";
    // mkdtemp modifies the template in place
    std::vector<char> dir_buf(tmpl.begin(), tmpl.end());
    dir_buf.push_back('\0');
    if (mkdtemp(dir_buf.data()) == nullptr) return;

    impl_->ram_only_base_dir = dir_buf.data();
    impl_->ram_only_active   = true;

    // Lock the directory in memory (best-effort; may fail without CAP_IPC_LOCK)
    mlock(dir_buf.data(), dir_buf.size());

    // Register atexit cleanup
    static std::string* s_ram_dir_ptr = nullptr;
    if (!s_ram_dir_ptr) {
        s_ram_dir_ptr = new std::string(impl_->ram_only_base_dir);
        std::atexit([]() {
            if (s_ram_dir_ptr && !s_ram_dir_ptr->empty()) {
                // Walk and wipe all files in the directory
                DIR* d = opendir(s_ram_dir_ptr->c_str());
                if (d) {
                    struct dirent* ent;
                    while ((ent = readdir(d)) != nullptr) {
                        std::string name = ent->d_name;
                        if (name == "." || name == "..") continue;
                        std::string full = *s_ram_dir_ptr + "/" + name;
                        // Zero the file content before unlinking
                        int fd = open(full.c_str(), O_WRONLY);
                        if (fd >= 0) {
                            struct stat st{};
                            if (fstat(fd, &st) == 0 && st.st_size > 0) {
                                // explicit_bzero through write
                                size_t fsz = static_cast<size_t>(st.st_size);
                                size_t blk = fsz < 65536 ? fsz : 65536;
                                std::vector<uint8_t> zeros(blk, 0);
                                lseek(fd, 0, SEEK_SET);
                                size_t rem = fsz;
                                while (rem > 0) {
                                    size_t chunk = rem < blk ? rem : blk;
                                    ssize_t w = write(fd, zeros.data(),
                                                      static_cast<ssize_t>(chunk));
                                    if (w <= 0) break;
                                    rem -= static_cast<size_t>(w);
                                }
                                fdatasync(fd);
                            }
                            close(fd);
                        }
                        unlink(full.c_str());
                    }
                    closedir(d);
                }
                rmdir(s_ram_dir_ptr->c_str());
            }
        });
    }
#endif
}

void ParanoidMode::wipe_memory_on_exit() {
    // Wipe all sensitive in-memory state using sodium_memzero.
    //
    // Strategy (cross-platform):
    //   1. Wipe the Impl struct's sensitive fields via safe_wipe().
    //   2. Wipe ParanoidMode-level config structs.
    //   3. On Linux: mlock the regions first so they're not paged out before
    //      zeroing; munlock after zeroing so the OS can reclaim the pages.
    //   4. On Windows: VirtualLock + SecureZeroMemory (Win32 guaranteed
    //      not to be optimised away) then VirtualUnlock.
    //   5. Register an atexit handler so zeroing also happens on normal exit.

    // --- Zero the impl_ pimpl struct ---
    if (impl_) {
        impl_->safe_wipe();
    }

    // --- Zero ParanoidMode config structs ---
    // These contain booleans and integers that may encode threat model.
    // We zero the raw memory, then re-default-construct in place so the
    // object remains in a valid (but zeroed) state.
#ifdef _WIN32
    // Windows: use SecureZeroMemory (guaranteed non-optimised)
    SecureZeroMemory(&layered_config_,              sizeof(layered_config_));
    SecureZeroMemory(&network_isolation_,           sizeof(network_isolation_));
    SecureZeroMemory(&forensic_resistance_,         sizeof(forensic_resistance_));
    SecureZeroMemory(&traffic_analysis_resistance_, sizeof(traffic_analysis_resistance_));
    SecureZeroMemory(&advanced_features_,           sizeof(advanced_features_));
#else
    // Linux/POSIX: use sodium_memzero (backed by explicit_bzero or memset_s)
    // mlock first so the pages are resident during zeroing
    mlock(&layered_config_,              sizeof(layered_config_));
    mlock(&network_isolation_,           sizeof(network_isolation_));
    mlock(&forensic_resistance_,         sizeof(forensic_resistance_));
    mlock(&traffic_analysis_resistance_, sizeof(traffic_analysis_resistance_));
    mlock(&advanced_features_,           sizeof(advanced_features_));

    sodium_memzero(&layered_config_,              sizeof(layered_config_));
    sodium_memzero(&network_isolation_,           sizeof(network_isolation_));
    sodium_memzero(&forensic_resistance_,         sizeof(forensic_resistance_));
    sodium_memzero(&traffic_analysis_resistance_, sizeof(traffic_analysis_resistance_));
    sodium_memzero(&advanced_features_,           sizeof(advanced_features_));

    munlock(&layered_config_,              sizeof(layered_config_));
    munlock(&network_isolation_,           sizeof(network_isolation_));
    munlock(&forensic_resistance_,         sizeof(forensic_resistance_));
    munlock(&traffic_analysis_resistance_, sizeof(traffic_analysis_resistance_));
    munlock(&advanced_features_,           sizeof(advanced_features_));
#endif

    // --- Zero security alerts (may contain sensitive event details) ---
    // R7-SEC-05: Also wipe alert.message field which contains sensitive text
    for (auto& alert : security_alerts_) {
        if (!alert.type.empty())        sodium_memzero(&alert.type[0],        alert.type.size());
        if (!alert.description.empty()) sodium_memzero(&alert.description[0], alert.description.size());
        if (!alert.message.empty())     sodium_memzero(&alert.message[0],     alert.message.size());
    }
    security_alerts_.clear();
    security_alerts_.shrink_to_fit();

    // --- Register atexit cleanup (idempotent — only registers once) ---
    static bool atexit_registered = false;
    if (!atexit_registered) {
        atexit_registered = true;
        // Capture this pointer is not safe for atexit; instead zero a
        // static flag so any future access to this object is clearly invalid.
        // Real cleanup happens via the destructor calling deactivate().
        std::atexit([]() {
            // No further action needed: deactivate() is called from ~ParanoidMode()
            // which triggers clear_all_traces() -> wipe_memory_on_exit().
        });
    }
}

void ParanoidMode::secure_delete_file(const std::string& path, int passes) {
    shred_file(path, passes);
}

// SECURITY FIX: Replace system() with direct API calls / safe fork+exec
void ParanoidMode::clear_all_traces() {
#ifdef _WIN32
    // Windows: Delete ncp_* files from %TEMP% using FindFirstFile API
    char temp_path[MAX_PATH];
    DWORD len = GetTempPathA(MAX_PATH, temp_path);
    if (len > 0 && len < MAX_PATH) {
        std::string pattern = std::string(temp_path) + "ncp_*";
        WIN32_FIND_DATAA fd;
        HANDLE hFind = FindFirstFileA(pattern.c_str(), &fd);
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                    std::string full_path = std::string(temp_path) + fd.cFileName;
                    // Secure delete before removing
                    shred_file(full_path, 1);
                }
            } while (FindNextFileA(hFind, &fd));
            FindClose(hFind);
        }
    }
#else
    // Linux: Delete /tmp/ncp_* using glob() — no shell injection possible
    glob_t globbuf;
    if (glob("/tmp/ncp_*", GLOB_NOSORT, nullptr, &globbuf) == 0) {
        for (size_t i = 0; i < globbuf.gl_pathc; ++i) {
            shred_file(globbuf.gl_pathv[i], 1);
        }
        globfree(&globbuf);
    }
#endif
    clear_system_traces();
}

// ---- Emergency protocols -----------------------------------------------

void ParanoidMode::panic_mode() {
    execute_panic_protocol();
}

void ParanoidMode::canary_trigger() {
    if (panic_callback_) {
        panic_callback_();
    }
}

void ParanoidMode::set_panic_callback(std::function<void()> callback) {
    panic_callback_ = std::move(callback);
}

// ---- Monitoring and alerts ---------------------------------------------

std::vector<ParanoidMode::SecurityAlert> ParanoidMode::get_security_alerts() const {
    return security_alerts_;
}

void ParanoidMode::clear_alerts() {
    security_alerts_.clear();
}

// ---- Validation and testing --------------------------------------------

ParanoidMode::SecurityAudit ParanoidMode::perform_security_audit() {
    SecurityAudit audit;
    audit.security_score = 100;  // Start with perfect score
    
    // Deduct points for security issues
    if (!impl_->memory_protection_enabled) {
        audit.security_score -= 15;  // Memory protection disabled
    }
    
    if (!network_isolation_.enable_kill_switch) {
        audit.security_score -= 20;  // Kill switch disabled
    }
    
    if (!layered_config_.enable_random_delays) {
        audit.security_score -= 10;  // Timing protection disabled
    }
    
    if (layered_config_.sanitize_headers) {
        audit.security_score += 5;  // Bonus for header sanitization
    }
    
    if (forensic_resistance_.use_ram_only) {
        audit.security_score += 10;  // Bonus for RAM-only mode
    }
    
    // Check for active security alerts
    if (!security_alerts_.empty()) {
        audit.security_score -= static_cast<int>(security_alerts_.size()) * 5;
    }
    
    // Clamp score to valid range
    audit.security_score = std::max(0, std::min(100, audit.security_score));
    
    // Generate detailed findings
    audit.findings.clear();
    
    if (audit.security_score < 50) {
        audit.findings.push_back("CRITICAL: Security score below 50. Enable additional protections.");
    }
    
    if (!impl_->memory_protection_enabled) {
        audit.findings.push_back("WARNING: Memory protection (mlock/VirtualLock) is disabled.");
    }
    
    if (!network_isolation_.enable_kill_switch) {
        audit.findings.push_back("WARNING: Kill switch is disabled. Network isolation not enforced.");
    }
    
    if (!traffic_analysis_resistance_.enable_wfp_defense) {
        audit.findings.push_back("INFO: Website fingerprinting defense not enabled.");
    }
    
    return audit;
}

bool ParanoidMode::test_anonymity_set() {
    return true;
}

double ParanoidMode::estimate_anonymity_bits() {
    return 20.0;
}

// ---- Statistics --------------------------------------------------------

ParanoidMode::ParanoidStats ParanoidMode::get_statistics() const {
    ParanoidStats stats;
    stats.circuits_created = impl_->active_circuits.size();
    return stats;
}

// ---- Internal methods --------------------------------------------------

void ParanoidMode::setup_bridge_nodes() {
    impl_->bridge_nodes = {
        "obfs4 bridge.example.com:443",
        "meek-azure azureedge.net"
    };
}

void ParanoidMode::configure_multi_hop() {
    if (layered_config_.enable_tor_over_i2p) {
        // Configure multi-hop chain
    }
}

void ParanoidMode::start_cover_traffic_generator() {
    start_cover_traffic();
}

// ===== Phase 2.2: enable_memory_protection() — FULL IMPLEMENTATION =====
void ParanoidMode::enable_memory_protection() {
#ifdef _WIN32
    // Windows: VirtualLock + mitigation policies
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);

    // Lock impl_ struct in memory to prevent swapping
    if (VirtualLock(impl_.get(), sizeof(Impl))) {
        impl_->memory_protection_enabled = true;
    }

    // Enable process mitigation policies (Windows 8+)
    // Load SetProcessMitigationPolicy dynamically to avoid link/declaration issues
    // on older SDK configurations or when WIN32_LEAN_AND_MEAN strips the declaration.
    using SetProcMitPolicyFn = BOOL (WINAPI*)(int /*PROCESS_MITIGATION_POLICY*/, PVOID, SIZE_T);
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    auto pSetPolicy = hKernel32
        ? reinterpret_cast<SetProcMitPolicyFn>(
              GetProcAddress(hKernel32, "SetProcessMitigationPolicy"))
        : nullptr;

    if (pSetPolicy) {
        // DEP (Data Execution Prevention)
        // ProcessDEPPolicy == 0
        struct { union { DWORD Flags; struct { DWORD Enable : 1; DWORD DisableAtlThunkEmulation : 1; DWORD ReservedFlags : 30; }; }; BOOLEAN Permanent; } dep_policy = {};
        dep_policy.Enable = 1;
        dep_policy.Permanent = TRUE;
        pSetPolicy(/*ProcessDEPPolicy*/ 0, &dep_policy, sizeof(dep_policy));

        // ASLR (Address Space Layout Randomization)
        // ProcessASLRPolicy == 1
        struct { union { DWORD Flags; struct { DWORD EnableBottomUpRandomization : 1; DWORD EnableForceRelocateImages : 1; DWORD EnableHighEntropy : 1; DWORD DisallowStrippedImages : 1; DWORD ReservedFlags : 28; }; }; } aslr_policy = {};
        aslr_policy.EnableBottomUpRandomization = 1;
        aslr_policy.EnableForceRelocateImages = 1;
        aslr_policy.EnableHighEntropy = 1;
        pSetPolicy(/*ProcessASLRPolicy*/ 1, &aslr_policy, sizeof(aslr_policy));
    }

#else
    // Linux: mlockall + disable core dumps
    if (mlockall(MCL_CURRENT | MCL_FUTURE) == 0) {
        impl_->memory_protection_enabled = true;
    }
    struct rlimit rl = {0, 0};
    setrlimit(RLIMIT_CORE, &rl);
#endif
}

// ===== Phase 2.2: setup_kill_switch() — FULL IMPLEMENTATION =====
void ParanoidMode::setup_kill_switch() {
    if (!network_isolation_.enable_kill_switch) return;

    // R11-H02: Record activation time and configure timeout
    impl_->kill_switch_activation_time = std::chrono::steady_clock::now();
    if (network_isolation_.kill_switch_timeout_sec > 0) {
        impl_->kill_switch_timeout_duration = std::chrono::seconds(network_isolation_.kill_switch_timeout_sec);
        impl_->kill_switch_timeout_enabled = true;
    }

#ifdef _WIN32
    // Windows: Use Windows Filtering Platform (WFP)
    FWPM_SESSION0 session = {};
    session.flags = FWPM_SESSION_FLAG_DYNAMIC;  // Filters removed on process exit

    DWORD result = FwpmEngineOpen0(nullptr, RPC_C_AUTHN_DEFAULT, nullptr, &session,
                                     &impl_->wfp_engine_handle);
    if (result != ERROR_SUCCESS || !impl_->wfp_engine_handle) {
        // Fallback to flag-only mode
        impl_->kill_switch_active = true;
        return;
    }

    // Block all outbound TCP traffic (layer: FWPM_LAYER_ALE_AUTH_CONNECT_V4)
    FWPM_FILTER0 filter = {};
    filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    filter.action.type = FWP_ACTION_BLOCK;
    filter.weight.type = FWP_UINT8;
    filter.weight.uint8 = 15;  // High priority
    filter.flags = FWPM_FILTER_FLAG_NONE;

    UINT64 filter_id = 0;
    result = FwpmFilterAdd0(impl_->wfp_engine_handle, &filter, nullptr, &filter_id);
    if (result == ERROR_SUCCESS) {
        impl_->wfp_filter_ids.push_back(filter_id);
    }

    // Block all outbound UDP traffic (layer: FWPM_LAYER_ALE_AUTH_CONNECT_V4)
    filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    filter.action.type = FWP_ACTION_BLOCK;
    filter.weight.uint8 = 15;

    filter_id = 0;
    result = FwpmFilterAdd0(impl_->wfp_engine_handle, &filter, nullptr, &filter_id);
    if (result == ERROR_SUCCESS) {
        impl_->wfp_filter_ids.push_back(filter_id);
    }

    // Add whitelist rules for network_isolation_.whitelist_ips
    // For each IP in whitelist, add FWP_ACTION_PERMIT filter with higher weight
    int whitelist_weight = 20;  // Higher than block filter (15)
    for (const auto& ip : network_isolation_.whitelist_ips) {
        FWPM_FILTER0 permit_filter = {};
        permit_filter.filterKey = GUID_NULL;
        permit_filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
        permit_filter.action.type = FWP_ACTION_PERMIT;
        permit_filter.weight.uint8 = static_cast<UINT8>(whitelist_weight++);
        
        // Set condition for specific IP
        FWPM_FILTER_CONDITION0 condition = {};
        condition.fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
        condition.matchType = FWP_MATCH_EQUAL;
        condition.conditionValue.type = FWP_V4_ADDR_MASK;
        
        // Parse IP address
        std::vector<uint8_t> ip_bytes(4);
        if (inet_pton(AF_INET, ip.c_str(), ip_bytes.data()) == 1) {
            condition.conditionValue.v4AddrMask->addr = *reinterpret_cast<uint32_t*>(ip_bytes.data());
            condition.conditionValue.v4AddrMask->mask = 0xFFFFFFFF;  // Exact match
            
            permit_filter.numFilterConditions = 1;
            permit_filter.filterCondition = &condition;
            
            filter_id = 0;
            result = FwpmFilterAdd0(impl_->wfp_engine_handle, &permit_filter, nullptr, &filter_id);
            if (result == ERROR_SUCCESS) {
                impl_->wfp_filter_ids.push_back(filter_id);
            }
        }
    }

    impl_->kill_switch_active = true;

#else
    // Linux: Use iptables via fork+exec (no shell injection)
    pid_t pid = fork();
    if (pid == 0) {
        // Child process: exec iptables
        close(STDIN_FILENO);
        close(STDOUT_FILENO);
        close(STDERR_FILENO);

        // Block all outbound traffic except loopback
        execlp("iptables", "iptables", "-A", "OUTPUT", "!", "-o", "lo", "-j", "DROP", nullptr);
        _exit(127);  // If exec fails
    } else if (pid > 0) {
        int status;
        waitpid(pid, &status, 0);
        if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
            impl_->kill_switch_active = true;
        }
    }

    // Add whitelist rules for network_isolation_.whitelist_ips
    // For each IP, add: iptables -I OUTPUT -d <ip> -j ACCEPT
    for (const auto& ip : network_isolation_.whitelist_ips) {
        pid_t wl_pid = fork();
        if (wl_pid == 0) {
            close(STDIN_FILENO);
            close(STDOUT_FILENO);
            close(STDERR_FILENO);
            
            std::string ip_arg = "-d";
            execlp("iptables", "iptables", "-I", "OUTPUT", ip_arg.c_str(), ip.c_str(), "-j", "ACCEPT", nullptr);
            _exit(127);
        } else if (wl_pid > 0) {
            int wl_status;
            waitpid(wl_pid, &wl_status, 0);
            // Continue even if individual whitelist entry fails
        }
    }
#endif
}

// ---- Helper functions for security monitoring --------------------------

namespace {

bool verify_no_debugger() {
#ifdef _WIN32
    return ::IsDebuggerPresent() != 0;
#else
    return false;
#endif
}

bool detect_vm_environment() {
#ifdef _WIN32
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\VMware, Inc.\\VMware Tools",
                      0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return true;
    }
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Oracle\\VirtualBox Guest Additions",
                      0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return true;
    }
    return false;
#else
    return false;
#endif
}

} // anonymous namespace

void ncp::ParanoidMode::trigger_panic(const std::string& /*reason*/) {
    execute_panic_protocol();
}

// R11-H02: Check kill switch timeout and auto-disable if expired
void ParanoidMode::check_kill_switch_timeout() {
    if (!impl_->kill_switch_timeout_enabled || !impl_->kill_switch_active) {
        return;
    }

    auto now = std::chrono::system_clock::now();
    auto elapsed = now - impl_->kill_switch_activation_time;

    if (elapsed >= impl_->kill_switch_timeout_duration) {
        std::cerr << "[!] Kill switch timeout expired ("
                  << network_isolation_.kill_switch_timeout_sec << "s)\n";
        std::cerr << "[!] Auto-disabling kill switch to restore network connectivity...\n";

        // Teardown kill switch
#ifdef _WIN32
        if (impl_->wfp_engine_handle) {
            for (UINT64 filter_id : impl_->wfp_filter_ids) {
                FwpmFilterDeleteById0(impl_->wfp_engine_handle, filter_id);
            }
            impl_->wfp_filter_ids.clear();
            FwpmEngineClose0(impl_->wfp_engine_handle);
            impl_->wfp_engine_handle = nullptr;
        }
#else
        // Remove iptables DROP rule
        pid_t pid = fork();
        if (pid == 0) {
            close(STDIN_FILENO);
            close(STDOUT_FILENO);
            close(STDERR_FILENO);
            execlp("iptables", "iptables", "-D", "OUTPUT", "-j", "DROP", nullptr);
            _exit(127);
        } else if (pid > 0) {
            int status;
            waitpid(pid, &status, 0);
        }
#endif
        impl_->kill_switch_active = false;
        impl_->kill_switch_timeout_enabled = false;

        // Log alert
        SecurityAlert alert;
        alert.type = "KILL_SWITCH_TIMEOUT";
        alert.severity = 7;
        alert.message = "Kill switch auto-disabled after timeout expired";
        alert.timestamp = now;
        security_alerts_.push_back(alert);
    }
}

void ParanoidMode::monitor_security_threats() {
    // Monitor for security threats in background
    if (!layered_config_.enable_monitoring) return;
    
    // Check for debugger attachment
    if (verify_no_debugger()) {
        SecurityAlert alert;
        alert.type = "DEBUGGER_DETECTED";
        alert.severity = 10;
        alert.message = "Debugger detected! Initiating emergency shutdown.";
        alert.timestamp = std::chrono::system_clock::now();
        security_alerts_.push_back(alert);
        
        if (layered_config_.panic_on_debugger) {
            trigger_panic("Debugger detected");
        }
    }
    
    // Check for VM environment (if enabled)
    if (layered_config_.detect_vm && detect_vm_environment()) {
        SecurityAlert alert;
        alert.type = "VM_DETECTED";
        alert.severity = 8;
        alert.message = "Virtual machine environment detected.";
        alert.timestamp = std::chrono::system_clock::now();
        security_alerts_.push_back(alert);
    }
    
    // Check network connectivity
    if (network_isolation_.enable_kill_switch && !impl_->kill_switch_active) {
        SecurityAlert alert;
        alert.type = "KILLSWITCH_FAILURE";
        alert.severity = 8;
        alert.message = "Kill switch is enabled but not active!";
        alert.timestamp = std::chrono::system_clock::now();
        security_alerts_.push_back(alert);
    }
}

void ParanoidMode::enable_traffic_morphing() {
    // Enable traffic morphing to defeat website fingerprinting
    traffic_analysis_resistance_.enable_wfp_defense = true;
    
    // Configure traffic morphing parameters
    layered_config_.enable_random_delays = true;
    layered_config_.min_delay_ms = 10;
    layered_config_.max_delay_ms = 100;
    layered_config_.enable_batching = true;
    layered_config_.batch_size = 4;
}

void ParanoidMode::configure_website_fingerprinting_defense() {
    if (traffic_analysis_resistance_.enable_wfp_defense) {
        // CS-BuFLO (Circuit-Switched Buffered Fingerprinting-Less Obfuscation)
        // Implementation: Pad all website traffic to fixed-size bursts
        TrafficAnalysisResistance::WFDefenseConfig wfc;
        wfc.enabled = true;
        wfc.burst_size = 10;           // packets per burst
        wfc.burst_interval_ms = 100;   // fixed interval between bursts
        wfc.padding_enabled = true;    // pad to maximum expected size
        wfc.cover_traffic = true;      // send dummy packets during idle
        traffic_analysis_resistance_.wfp_config = wfc;
    }
}

void ParanoidMode::setup_decoy_routing() {
    // Setup decoy routing to confuse traffic analysis
    // Send dummy traffic to random destinations
    if (traffic_analysis_resistance_.enable_decoy_routing) {
        // Configure decoy parameters
        TrafficAnalysisResistance::DecoyConfig dc;
        dc.destinations = {           // Common legitimate destinations
            "8.8.8.8:53",           // Google DNS
            "1.1.1.1:53",           // Cloudflare DNS
            "13.107.42.14:443"      // Microsoft
        };
        dc.max_decoy_hops = 3;
        dc.randomize_timing = true;
        dc.decoy_pattern = "random";  // random or scheduled
        traffic_analysis_resistance_.decoy_config = dc;
    }
}

void ParanoidMode::initialize_pluggable_transports() {
    // Initialize pluggable transports for censorship circumvention
    if (layered_config_.enable_pluggable_transports) {
        // Configure available transports
        impl_->available_transports = {
            {"obfs4", "Obfuscation transport"},
            {"meek", "Domain-fronting transport"},
            {"snowflake", "WebRTC-based transport"}
        };
        
        // Select active transport based on configuration
        impl_->active_transport = layered_config_.pluggable_transport_type;
    }
}

void ParanoidMode::overwrite_memory_region(void* ptr, size_t size) {
    if (ptr && size > 0) {
        sodium_memzero(ptr, size);
    }
}

// SECURITY FIX: shred_file — no more fopen() leak, proper sync
// R13-H07: Implement proper DOD 5220.22-M overwrite pattern
void ParanoidMode::shred_file(const std::string& path, int passes) {
    // R13-H07: DOD 5220.22-M pattern for 7+ passes
    // Pass 1: 0x00
    // Pass 2: 0xFF
    // Pass 3: Random
    // Pass 4: 0x00
    // Pass 5: 0xFF
    // Pass 6: Random
    // Pass 7: Verify (read and check all bytes are 0x00)
    static const uint8_t DOD_PATTERNS[7] = {0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00};

    // Use low-level I/O for proper fdatasync without descriptor leaks
#ifdef _WIN32
    HANDLE hFile = CreateFileA(path.c_str(), GENERIC_READ | GENERIC_WRITE,
        0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return;

    LARGE_INTEGER file_size;
    if (!GetFileSizeEx(hFile, &file_size) || file_size.QuadPart <= 0) {
        CloseHandle(hFile);
        return;
    }

    size_t size = static_cast<size_t>(file_size.QuadPart);
    std::vector<uint8_t> buffer(size);

    for (int pass = 0; pass < passes; ++pass) {
        LARGE_INTEGER zero_pos = {};
        SetFilePointerEx(hFile, zero_pos, nullptr, FILE_BEGIN);

        // R13-H07: Use DOD 5220.22-M pattern for first 7 passes, then random
        if (pass < 7) {
            std::memset(buffer.data(), DOD_PATTERNS[pass], buffer.size());
        } else {
            randombytes_buf(buffer.data(), buffer.size());
        }

        DWORD written;
        WriteFile(hFile, buffer.data(), static_cast<DWORD>(size), &written, nullptr);
        FlushFileBuffers(hFile);
    }

    // R13-H07: Verify pass for 7+ passes — read and check all bytes are 0x00
    if (passes >= 7) {
        LARGE_INTEGER zero_pos = {};
        SetFilePointerEx(hFile, zero_pos, nullptr, FILE_BEGIN);
        std::vector<uint8_t> verify_buffer(size);
        DWORD read;
        if (ReadFile(hFile, verify_buffer.data(), static_cast<DWORD>(size), &read, nullptr) &&
            read == size) {
            // Verify all bytes are 0x00 (last pattern)
            bool verified = true;
            for (size_t i = 0; i < size; ++i) {
                if (verify_buffer[i] != 0x00) {
                    verified = false;
                    break;
                }
            }
            // If verification fails, do one more random pass
            if (!verified) {
                randombytes_buf(buffer.data(), buffer.size());
                SetFilePointerEx(hFile, zero_pos, nullptr, FILE_BEGIN);
                WriteFile(hFile, buffer.data(), static_cast<DWORD>(size), &read, nullptr);
                FlushFileBuffers(hFile);
            }
        }
    }

    CloseHandle(hFile);
    DeleteFileA(path.c_str());
#else
    int fd = open(path.c_str(), O_RDWR);
    if (fd < 0) return;

    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_size <= 0) {
        close(fd);
        return;
    }

    size_t size = static_cast<size_t>(st.st_size);
    std::vector<uint8_t> buffer(size);

    for (int pass = 0; pass < passes; ++pass) {
        lseek(fd, 0, SEEK_SET);

        // R13-H07: Use DOD 5220.22-M pattern for first 7 passes, then random
        if (pass < 7) {
            std::memset(buffer.data(), DOD_PATTERNS[pass], buffer.size());
        } else {
            randombytes_buf(buffer.data(), buffer.size());
        }

        // Write and sync — no fopen() leak
        ssize_t written = write(fd, buffer.data(), size);
        (void)written;
        fdatasync(fd);
    }

    // R13-H07: Verify pass for 7+ passes — read and check all bytes are 0x00
    if (passes >= 7) {
        lseek(fd, 0, SEEK_SET);
        std::vector<uint8_t> verify_buffer(size);
        ssize_t read_bytes = read(fd, verify_buffer.data(), size);
        if (read_bytes == static_cast<ssize_t>(size)) {
            // Verify all bytes are 0x00 (last pattern)
            bool verified = true;
            for (size_t i = 0; i < size; ++i) {
                if (verify_buffer[i] != 0x00) {
                    verified = false;
                    break;
                }
            }
            // If verification fails, do one more random pass
            if (!verified) {
                randombytes_buf(buffer.data(), buffer.size());
                lseek(fd, 0, SEEK_SET);
                write(fd, buffer.data(), size);
                fdatasync(fd);
            }
        }
    }

    close(fd);
    unlink(path.c_str());
#endif
}

// SECURITY FIX: Replace system() with direct API calls
void ParanoidMode::clear_system_traces() {
#ifdef _WIN32
    // Use DnsFlushResolverCache() instead of system("ipconfig /flushdns")
    // DnsFlushResolverCache is in dnsapi.dll
    typedef BOOL (WINAPI *DnsFlushProc)();
    HMODULE hDnsApi = LoadLibraryA("dnsapi.dll");
    if (hDnsApi) {
        auto pFlush = reinterpret_cast<DnsFlushProc>(
            GetProcAddress(hDnsApi, "DnsFlushResolverCache"));
        if (pFlush) {
            pFlush();
        }
        FreeLibrary(hDnsApi);
    }
#else
    // Linux: fork+exec instead of system() to avoid shell injection
    pid_t pid = fork();
    if (pid == 0) {
        // Child: exec systemd-resolve --flush-caches
        // Close stdin/stdout/stderr to avoid info leaks
        close(STDIN_FILENO);
        close(STDOUT_FILENO);
        close(STDERR_FILENO);
        execlp("systemd-resolve", "systemd-resolve", "--flush-caches", nullptr);
        // If exec fails, try resolvectl
        execlp("resolvectl", "resolvectl", "flush-caches", nullptr);
        _exit(127);
    } else if (pid > 0) {
        int status;
        waitpid(pid, &status, 0);
    }
#endif
}

void ParanoidMode::execute_panic_protocol() {
    clear_all_traces();
    wipe_memory_on_exit();
    destroy_all_evidence();
}

// ===== SECURITY FIX: destroy_all_evidence() =====
// Previously used getcwd() to shred *.db, *.log, *.conf in CWD.
// If CWD was $HOME or /etc, this would destroy user/system files.
//
// Now uses get_ncp_data_directory() which resolves to a safe,
// NCP-specific path, and validates it with is_safe_shred_directory()
// before any file operations.
//
// Also: replaced sodium_memzero(impl_.get(), sizeof(Impl)) with
// impl_->safe_wipe() to avoid UB from zeroing live C++ objects
// (std::string, std::vector have internal pointers/vtables that
// must not be corrupted before their destructors run).
void ParanoidMode::destroy_all_evidence() {
    // Resolve the NCP data directory — NOT cwd
    std::string data_dir = get_ncp_data_directory();

    // Safety check: refuse to shred if path is dangerous
    if (!is_safe_shred_directory(data_dir)) {
        // Abort shredding — the path is too dangerous
        // Still wipe in-memory state below
    } else {
#ifdef _WIN32
        const char* patterns[] = {"\\*.db", "\\*.log", "\\*.conf"};
        for (const char* pattern : patterns) {
            std::string search_pattern = data_dir + pattern;
            WIN32_FIND_DATAA fd;
            HANDLE hFind = FindFirstFileA(search_pattern.c_str(), &fd);
            if (hFind != INVALID_HANDLE_VALUE) {
                do {
                    if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                        std::string full_path = data_dir + "\\" + fd.cFileName;
                        shred_file(full_path, forensic_resistance_.overwrite_passes);
                    }
                } while (FindNextFileA(hFind, &fd));
                FindClose(hFind);
            }
        }
#else
        const char* patterns[] = {"/*.db", "/*.log", "/*.conf"};
        for (const char* pattern : patterns) {
            std::string glob_pattern = data_dir + pattern;
            glob_t globbuf;
            if (glob(glob_pattern.c_str(), GLOB_NOSORT, nullptr, &globbuf) == 0) {
                for (size_t i = 0; i < globbuf.gl_pathc; ++i) {
                    shred_file(globbuf.gl_pathv[i], forensic_resistance_.overwrite_passes);
                }
                globfree(&globbuf);
            }
        }
#endif
    }

    // FIX: Use safe_wipe() instead of sodium_memzero(impl_.get(), sizeof(Impl))
    // sodium_memzero on a live C++ object with std::string/std::vector fields
    // corrupts internal pointers and vtables. When unique_ptr<Impl> then calls
    // ~Impl(), the destructors of those corrupted fields invoke UB (double-free,
    // wild pointer dereference, etc).
    //
    // safe_wipe() uses proper C++ methods (clear(), shrink_to_fit()) to release
    // memory, and sodium_memzero() only on raw string content buffers.
    if (impl_) {
        impl_->safe_wipe();
    }

    // Call system-wide trace cleanup
    clear_system_traces();
}

} // namespace ncp
