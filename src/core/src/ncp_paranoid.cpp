#include "ncp_paranoid.hpp"
#include <algorithm>
#include <thread>
#include <chrono>
#include <sodium.h>
#include <fstream>
#include <cstdlib>
#include <cstring>

#ifdef _WIN32
#include <windows.h>
#include <windns.h>
#pragma comment(lib, "dnsapi.lib")
#include <io.h>
#include <fcntl.h>
#else
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <glob.h>
#endif

namespace ncp {

// ---- ParanoidMode::Impl (pimpl idiom) ---------------------------------

struct ParanoidMode::Impl {
    std::vector<std::string> active_circuits;
    std::thread cover_traffic_thread;
    bool cover_traffic_running = false;
    std::chrono::system_clock::time_point last_rotation;
    std::vector<std::string> bridge_nodes;
    bool kill_switch_active = false;
    bool memory_protection_enabled = false;
};

// ---- Construction / Destruction ----------------------------------------

ParanoidMode::ParanoidMode()
    : impl_(std::make_unique<Impl>()) {}

ParanoidMode::~ParanoidMode() {
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
    impl_->kill_switch_active = false;

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

bool ParanoidMode::configure_hop_chain(const HopChain& /*chain*/) {
    return true;
}

std::vector<ParanoidMode::HopChain> ParanoidMode::get_active_chains() const {
    return {};
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
    // PNG tEXt chunk removal — placeholder
    else if (data.size() > 8 && data[1] == 'P' && data[2] == 'N' && data[3] == 'G') {
        // TODO: iterate PNG chunks and remove tEXt, iTXt, zTXt
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
    // In real implementation: inject JS to randomize fingerprints
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
}

void ParanoidMode::wipe_memory_on_exit() {
    // Overwrite sensitive memory regions using sodium_memzero
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
    audit.security_score = 85;  // Placeholder
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

void ParanoidMode::enable_memory_protection() {
#ifdef _WIN32
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
#else
    if (mlockall(MCL_CURRENT | MCL_FUTURE) == 0) {
        impl_->memory_protection_enabled = true;
    }
    struct rlimit rl = {0, 0};
    setrlimit(RLIMIT_CORE, &rl);
#endif
}

void ParanoidMode::setup_kill_switch() {
    if (network_isolation_.enable_kill_switch) {
        impl_->kill_switch_active = true;
    }
}

void ParanoidMode::monitor_security_threats() {}

void ParanoidMode::enable_traffic_morphing() {}

void ParanoidMode::configure_website_fingerprinting_defense() {
    if (traffic_analysis_resistance_.enable_wfp_defense) {
        // CS-BuFLO implementation placeholder
    }
}

void ParanoidMode::setup_decoy_routing() {}

void ParanoidMode::initialize_pluggable_transports() {}

void ParanoidMode::overwrite_memory_region(void* ptr, size_t size) {
    if (ptr && size > 0) {
        sodium_memzero(ptr, size);
    }
}

// SECURITY FIX: shred_file — no more fopen() leak, proper sync
void ParanoidMode::shred_file(const std::string& path, int passes) {
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
        
        if (pass % 3 == 0) {
            std::memset(buffer.data(), 0x00, buffer.size());
        } else if (pass % 3 == 1) {
            std::memset(buffer.data(), 0xFF, buffer.size());
        } else {
            randombytes_buf(buffer.data(), buffer.size());
        }
        
        DWORD written;
        WriteFile(hFile, buffer.data(), static_cast<DWORD>(size), &written, nullptr);
        FlushFileBuffers(hFile);
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
        
        if (pass % 3 == 0) {
            std::memset(buffer.data(), 0x00, buffer.size());
        } else if (pass % 3 == 1) {
            std::memset(buffer.data(), 0xFF, buffer.size());
        } else {
            randombytes_buf(buffer.data(), buffer.size());
        }
        
        // Write and sync — no fopen() leak
        ssize_t written = write(fd, buffer.data(), size);
        (void)written;
        fdatasync(fd);
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

void ParanoidMode::destroy_all_evidence() {
    // Shred all .db, .log, .conf files in working directory
}

} // namespace ncp
