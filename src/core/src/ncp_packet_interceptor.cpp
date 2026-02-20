#include "../include/ncp_packet_interceptor.hpp"
#include "../include/ncp_l3_stealth.hpp"
#include <cstring>
#include <algorithm>
#include <iostream>
#include <sodium.h>

#ifdef __linux__
#ifdef HAVE_NFQUEUE
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/netfilter.h>
#endif
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#elif defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <fwpmu.h>
#ifdef HAVE_WINDIVERT
#include <windivert.h>
#endif
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "fwpuclnt.lib")
#ifdef HAVE_WINDIVERT
#pragma comment(lib, "WinDivert.lib")
#endif
#endif

namespace ncp {

// ==================== IP/UDP/GRE Header Structs ====================

#pragma pack(push, 1)
struct IPv4Header {
    uint8_t  ihl_ver;
    uint8_t  tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t check;
    uint32_t saddr;
    uint32_t daddr;
};

struct UDPHeader {
    uint16_t source;
    uint16_t dest;
    uint16_t len;
    uint16_t check;
};

struct GREHeader {
    uint16_t flags_ver;     // flags (4 bits) + version (4 bits) + protocol type
    uint16_t protocol;      // Encapsulated protocol (0x0800 = IPv4)
    uint32_t key;           // Optional: GRE key (if K bit set in flags)
};

// FIX #31: VXLANHeader corrected to 8 bytes (was 12 due to erroneous reserved2[4])
// VXLAN header per RFC 7348: flags(1) + reserved(3) + VNI(3) + reserved(1) = 8 bytes
struct VXLANHeader {
    uint8_t  flags;         // 0x08 = VNI present
    uint8_t  reserved1[3];
    uint8_t  vni[3];        // VNI (24 bits), stored as 3 bytes
    uint8_t  reserved2;     // 1 byte reserved (was erroneously uint8_t reserved2[4])
};
#pragma pack(pop)

static_assert(sizeof(VXLANHeader) == 8, "VXLANHeader must be exactly 8 bytes per RFC 7348");

static constexpr uint8_t IPPROTO_GRE = 47;
static constexpr uint8_t IPPROTO_IPIP = 4;
static constexpr uint16_t VXLAN_PORT = 4789;
static constexpr uint16_t GRE_PROTO_IPV4 = 0x0800;

// Forward declaration
static std::vector<uint8_t> encapsulate_packet(const std::vector<uint8_t>& packet,
                                               const PacketInterceptor::Config& cfg);

// ==================== Iptables RAII Helper (FIX #33) ====================

#ifdef __linux__
// Safe iptables execution via execvp (no shell, no injection risk)
static bool iptables_exec(const char* action, int queue_num) {
    std::string queue_str = std::to_string(queue_num);
    pid_t pid = fork();
    if (pid < 0) return false;
    if (pid == 0) {
        // Child — exec iptables directly, no shell involved
        const char* argv[] = {
            "iptables", action, "OUTPUT",
            "-j", "NFQUEUE",
            "--queue-num", queue_str.c_str(),
            nullptr
        };
        execvp("iptables", const_cast<char* const*>(argv));
        _exit(127); // exec failed
    }
    // Parent — wait for child
    int status = 0;
    waitpid(pid, &status, 0);
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}
#endif

// ==================== FIX #32: Resolve local source IP ====================

#ifdef __linux__
// Determine local source IP for a given destination via a connected UDP socket
static uint32_t resolve_local_saddr(const char* remote_ip) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return 0;

    struct sockaddr_in remote{};
    remote.sin_family = AF_INET;
    remote.sin_port = htons(80); // arbitrary port
    inet_pton(AF_INET, remote_ip, &remote.sin_addr);

    // connect() on UDP doesn't send anything, just binds to a local route
    if (connect(sock, reinterpret_cast<struct sockaddr*>(&remote), sizeof(remote)) < 0) {
        close(sock);
        return 0;
    }

    struct sockaddr_in local{};
    socklen_t len = sizeof(local);
    if (getsockname(sock, reinterpret_cast<struct sockaddr*>(&local), &len) < 0) {
        close(sock);
        return 0;
    }
    close(sock);
    return local.sin_addr.s_addr; // already in network byte order
}
#endif

// ==================== FIX #29: ChaCha20 stream cipher obfuscation ====================

// Applies ChaCha20 stream cipher instead of single-byte XOR.
// Uses a per-packet random nonce prepended to the payload for decryption.
// The key is derived from cfg.obfuscation_key (32 bytes) via crypto_generichash if needed.
static void apply_stream_obfuscation(std::vector<uint8_t>& result, size_t payload_offset,
                                     const uint8_t* key_material, size_t key_len) {
    if (payload_offset >= result.size()) return;

    // Derive a 32-byte key from whatever key material we have
    uint8_t derived_key[crypto_stream_chacha20_KEYBYTES]; // 32
    crypto_generichash(derived_key, sizeof(derived_key),
                       key_material, key_len,
                       nullptr, 0);

    // Generate a random nonce per packet
    uint8_t nonce[crypto_stream_chacha20_NONCEBYTES]; // 8
    randombytes_buf(nonce, sizeof(nonce));

    size_t payload_len = result.size() - payload_offset;

    // XOR payload with ChaCha20 keystream (in-place)
    crypto_stream_chacha20_xor(
        result.data() + payload_offset,   // output (in-place)
        result.data() + payload_offset,   // input
        payload_len,
        nonce,
        derived_key);

    // Prepend nonce so the receiver can decrypt
    // Insert nonce bytes at payload_offset
    result.insert(result.begin() + payload_offset, nonce, nonce + sizeof(nonce));

    // Wipe derived key
    sodium_memzero(derived_key, sizeof(derived_key));
}

// ==================== Platform-Specific Implementation ====================

class PacketInterceptor::Impl {
public:
    virtual ~Impl() = default;
    virtual bool initialize(const Config& cfg) = 0;
    virtual bool start() = 0;
    virtual void stop() = 0;
    virtual bool is_running() const = 0;

    PacketInterceptor* parent = nullptr;
};

#if defined(__linux__) && defined(HAVE_NFQUEUE)
// ==================== NFQUEUE Backend (Linux) ====================

class NFQUEUEBackend : public PacketInterceptor::Impl {
public:
    NFQUEUEBackend() = default;
    ~NFQUEUEBackend() override { stop(); }

    bool initialize(const Config& cfg) override {
        config_ = cfg;

        // Open netfilter_queue
        nfq_handle_ = nfq_open();
        if (!nfq_handle_) {
            parent->log("[NFQUEUE] nfq_open() failed");
            return false;
        }

        // Unbind existing handler (if any)
        nfq_unbind_pf(nfq_handle_, AF_INET);

        // Bind to AF_INET
        if (nfq_bind_pf(nfq_handle_, AF_INET) < 0) {
            parent->log("[NFQUEUE] nfq_bind_pf() failed");
            nfq_close(nfq_handle_);
            nfq_handle_ = nullptr;
            return false;
        }

        // Create queue
        nfq_queue_ = nfq_create_queue(nfq_handle_, cfg.nfqueue_num,
                                      &NFQUEUEBackend::packet_callback_static,
                                      this);
        if (!nfq_queue_) {
            parent->log("[NFQUEUE] nfq_create_queue() failed (queue=" +
                       std::to_string(cfg.nfqueue_num) + ")");
            nfq_close(nfq_handle_);
            nfq_handle_ = nullptr;
            return false;
        }

        // Set queue length
        nfq_set_queue_maxlen(nfq_queue_, cfg.nfqueue_max_len);

        // Set copy mode (packet payload)
        nfq_set_mode(nfq_queue_, NFQNL_COPY_PACKET, 0xFFFF);

        fd_ = nfq_fd(nfq_handle_);
        if (fd_ < 0) {
            parent->log("[NFQUEUE] nfq_fd() failed");
            nfq_destroy_queue(nfq_queue_);
            nfq_close(nfq_handle_);
            nfq_handle_ = nullptr;
            nfq_queue_ = nullptr;
            return false;
        }

        // FIX #33: Use execvp-based iptables invocation (no shell injection risk)
        if (!iptables_exec("-A", cfg.nfqueue_num)) {
            parent->log("[NFQUEUE] Warning: Failed to add iptables rule. "
                        "Run manually: iptables -A OUTPUT -j NFQUEUE --queue-num " +
                        std::to_string(cfg.nfqueue_num));
        } else {
            iptables_rule_added_ = true;
        }

        parent->log("[NFQUEUE] Initialized on queue " + std::to_string(cfg.nfqueue_num));
        return true;
    }

    bool start() override {
        if (running_) return true;
        running_ = true;

        worker_thread_ = std::thread([this]() {
            char buf[4096];
            int rv;
            parent->log("[NFQUEUE] Worker thread started");
            while (running_) {
                rv = recv(fd_, buf, sizeof(buf), 0);
                if (rv >= 0) {
                    nfq_handle_packet(nfq_handle_, buf, rv);
                } else {
                    if (errno == EINTR) continue;
                    break;
                }
            }
            parent->log("[NFQUEUE] Worker thread stopped");
        });
        return true;
    }

    void stop() override {
        if (!running_) return;
        running_ = false;

        if (worker_thread_.joinable()) {
            // Interrupt recv() by closing socket
            if (fd_ >= 0) {
                shutdown(fd_, SHUT_RDWR);
            }
            worker_thread_.join();
        }

        if (nfq_queue_) {
            nfq_destroy_queue(nfq_queue_);
            nfq_queue_ = nullptr;
        }
        if (nfq_handle_) {
            nfq_close(nfq_handle_);
            nfq_handle_ = nullptr;
        }

        // FIX #33: Remove iptables rule safely via execvp
        if (iptables_rule_added_) {
            iptables_exec("-D", config_.nfqueue_num);
            iptables_rule_added_ = false;
        }
    }

    bool is_running() const override { return running_; }

private:
    static int packet_callback_static(struct nfq_q_handle* qh, struct nfgenmsg* nfmsg,
                                      struct nfq_data* nfa, void* data)
    {
        auto* self = static_cast<NFQUEUEBackend*>(data);
        return self->packet_callback(qh, nfmsg, nfa);
    }

    int packet_callback(struct nfq_q_handle* qh, struct nfgenmsg* nfmsg,
                        struct nfq_data* nfa)
    {
        struct nfqnl_msg_packet_hdr* ph = nfq_get_msg_packet_hdr(nfa);
        if (!ph) return nfq_set_verdict(qh, 0, NF_ACCEPT, 0, nullptr);

        uint32_t id = ntohl(ph->packet_id);
        unsigned char* payload_data;
        int payload_len = nfq_get_payload(nfa, &payload_data);
        if (payload_len < 0) return nfq_set_verdict(qh, id, NF_ACCEPT, 0, nullptr);

        // Copy to vector for processing
        std::vector<uint8_t> packet(payload_data, payload_data + payload_len);

        parent->stats_.packets_intercepted++;
        parent->stats_.bytes_processed += packet.size();

        // Call packet handler
        PacketInterceptor::Verdict verdict;
        if (parent->packet_handler_) {
            verdict = parent->packet_handler_(packet, true);
        } else {
            verdict = parent->default_packet_handler(packet, true);
        }

        // Apply verdict
        uint32_t nf_verdict;
        switch (verdict) {
            case PacketInterceptor::Verdict::ACCEPT:
                nf_verdict = NF_ACCEPT;
                break;
            case PacketInterceptor::Verdict::DROP:
                nf_verdict = NF_DROP;
                parent->stats_.packets_dropped++;
                break;
            case PacketInterceptor::Verdict::MODIFIED:
                nf_verdict = NF_ACCEPT;
                parent->stats_.packets_modified++;
                return nfq_set_verdict(qh, id, nf_verdict,
                                       packet.size(),
                                       packet.data());
            case PacketInterceptor::Verdict::QUEUE:
                return nfq_set_verdict(qh, id, NF_REPEAT, 0, nullptr);
        }

        return nfq_set_verdict(qh, id, nf_verdict, 0, nullptr);
    }

    struct nfq_handle* nfq_handle_ = nullptr;
    struct nfq_q_handle* nfq_queue_ = nullptr;
    int fd_ = -1;
    std::atomic<bool> running_{false};
    std::thread worker_thread_;
    bool iptables_rule_added_ = false;
    Config config_;
};
#endif // __linux__ && HAVE_NFQUEUE

// ==================== FIX #83: WinDivert Backend (Windows) ====================
//
// Replaces the WFP placeholder with a functional WinDivert-based backend.
// WinDivert provides userspace packet interception on Windows without
// requiring a custom kernel-mode driver.
//
// Architecture mirrors NFQUEUEBackend:
//   initialize() -> open WinDivert handle
//   start()      -> spawn worker thread calling WinDivertRecv() in a loop
//   packet_callback() -> call parent->packet_handler_ or default_packet_handler()
//   stop()       -> close handle, join worker thread

#if defined(_WIN32) && defined(HAVE_WINDIVERT)
class WinDivertBackend : public PacketInterceptor::Impl {
public:
    WinDivertBackend() = default;
    ~WinDivertBackend() override { stop(); }

    bool initialize(const Config& cfg) override {
        config_ = cfg;

        // Open WinDivert handle with the configured filter
        handle_ = WinDivertOpen(
            cfg.windivert_filter.c_str(),
            WINDIVERT_LAYER_NETWORK,    // Intercept at network (IP) layer
            cfg.windivert_priority,
            cfg.windivert_flags
        );

        if (handle_ == INVALID_HANDLE_VALUE) {
            DWORD err = GetLastError();
            parent->log("[WinDivert] WinDivertOpen failed, error=" + std::to_string(err));
            if (err == ERROR_FILE_NOT_FOUND) {
                parent->log("[WinDivert] WinDivert driver not found. "
                           "Ensure WinDivert.sys and WinDivert.dll are in PATH or application directory.");
            } else if (err == ERROR_ACCESS_DENIED) {
                parent->log("[WinDivert] Access denied. Run as Administrator.");
            }
            return false;
        }

        // Set queue parameters for high throughput
        WinDivertSetParam(handle_, WINDIVERT_PARAM_QUEUE_LENGTH, 8192);
        WinDivertSetParam(handle_, WINDIVERT_PARAM_QUEUE_TIME, 1024);   // ms
        WinDivertSetParam(handle_, WINDIVERT_PARAM_QUEUE_SIZE, 4194304); // 4MB

        parent->log("[WinDivert] Initialized with filter: " + cfg.windivert_filter);
        return true;
    }

    bool start() override {
        if (running_) return true;
        running_ = true;

        worker_thread_ = std::thread([this]() {
            // Buffer for received packets (max jumbo frame)
            std::vector<uint8_t> recv_buf(65535 + 40); // max IP packet + WINDIVERT_ADDRESS
            WINDIVERT_ADDRESS addr;
            UINT recv_len = 0;

            parent->log("[WinDivert] Worker thread started");

            while (running_) {
                // Blocking receive — returns when a packet matches the filter
                if (!WinDivertRecv(handle_, recv_buf.data(),
                                   static_cast<UINT>(recv_buf.size()),
                                   &recv_len, &addr))
                {
                    DWORD err = GetLastError();
                    if (!running_) break; // Graceful shutdown
                    if (err == ERROR_NO_DATA || err == ERROR_INSUFFICIENT_BUFFER) continue;
                    parent->log("[WinDivert] WinDivertRecv failed, error=" + std::to_string(err));
                    break;
                }

                // Copy packet data into a vector for processing
                std::vector<uint8_t> packet(recv_buf.begin(), recv_buf.begin() + recv_len);
                bool is_outbound = (addr.Outbound != 0);

                parent->stats_.packets_intercepted++;
                parent->stats_.bytes_processed += packet.size();

                // Call packet handler (same pattern as NFQUEUEBackend)
                PacketInterceptor::Verdict verdict;
                if (parent->packet_handler_) {
                    verdict = parent->packet_handler_(packet, is_outbound);
                } else {
                    verdict = parent->default_packet_handler(packet, is_outbound);
                }

                // Apply verdict
                switch (verdict) {
                    case PacketInterceptor::Verdict::ACCEPT:
                        // Re-inject original packet
                        WinDivertSend(handle_, recv_buf.data(), recv_len, nullptr, &addr);
                        break;

                    case PacketInterceptor::Verdict::DROP:
                        // Don't re-inject — packet is silently dropped
                        parent->stats_.packets_dropped++;
                        break;

                    case PacketInterceptor::Verdict::MODIFIED:
                        // Re-inject modified packet; recalculate checksums
                        WinDivertHelperCalcChecksums(packet.data(),
                                                     static_cast<UINT>(packet.size()),
                                                     &addr, 0);
                        WinDivertSend(handle_, packet.data(),
                                      static_cast<UINT>(packet.size()),
                                      nullptr, &addr);
                        parent->stats_.packets_modified++;
                        break;

                    case PacketInterceptor::Verdict::QUEUE:
                        // Re-inject and let the system re-process
                        WinDivertSend(handle_, recv_buf.data(), recv_len, nullptr, &addr);
                        break;
                }
            }

            parent->log("[WinDivert] Worker thread stopped");
        });

        parent->log("[WinDivert] Started");
        return true;
    }

    void stop() override {
        if (!running_) return;
        running_ = false;

        // Close handle — this unblocks WinDivertRecv() in the worker thread
        if (handle_ != INVALID_HANDLE_VALUE) {
            WinDivertClose(handle_);
            handle_ = INVALID_HANDLE_VALUE;
        }

        if (worker_thread_.joinable()) {
            worker_thread_.join();
        }
    }

    bool is_running() const override { return running_; }

private:
    HANDLE handle_ = INVALID_HANDLE_VALUE;
    std::atomic<bool> running_{false};
    std::thread worker_thread_;
    Config config_;
};
#endif // _WIN32 && HAVE_WINDIVERT

#ifdef _WIN32
// ==================== WFP Backend (Windows, legacy placeholder) ====================
// Kept for backward compatibility. Prefer WinDivertBackend for actual packet interception.

class WFPBackend : public PacketInterceptor::Impl {
public:
    WFPBackend() = default;
    ~WFPBackend() override { stop(); }

    bool initialize(const Config& cfg) override {
        config_ = cfg;

        // Open WFP engine
        FWPM_SESSION0 session = {0};
        session.flags = 0;
        DWORD result = FwpmEngineOpen0(nullptr, RPC_C_AUTHN_WINNT, nullptr, &session, &engine_handle_);
        if (result != ERROR_SUCCESS) {
            parent->log("[WFP] FwpmEngineOpen0 failed: " + std::to_string(result));
            return false;
        }

        // Note: Full WFP callout driver requires kernel-mode driver.
        // For userspace, we can only register filters, not callouts.
        // This is a placeholder showing the structure.
        // Real implementation needs a signed kernel driver.

        parent->log("[WFP] Initialized (legacy placeholder — use WINDIVERT backend for packet interception)");
        return true;
    }

    bool start() override {
        if (running_) return true;
        running_ = true;
        parent->log("[WFP] Started (WARNING: WFP backend is a placeholder, "
                    "packet interception is NOT functional. "
                    "Use Backend::WINDIVERT or Backend::AUTO for actual packet processing)");
        return true;
    }

    void stop() override {
        if (!running_) return;
        running_ = false;

        if (engine_handle_) {
            FwpmEngineClose0(engine_handle_);
            engine_handle_ = nullptr;
        }
    }

    bool is_running() const override { return running_; }

private:
    HANDLE engine_handle_ = nullptr;
    std::atomic<bool> running_{false};
    Config config_;
};
#endif // _WIN32

// ==================== PacketInterceptor Implementation ====================

PacketInterceptor::PacketInterceptor() = default;
PacketInterceptor::~PacketInterceptor() { stop(); }

bool PacketInterceptor::initialize(const Config& config) {
    if (initialized_) return false;

    std::lock_guard<std::mutex> lock(config_mutex_);
    config_ = config;
    config_version_++;  // FIX #30: bump version on init

    Backend backend = config.backend;
    if (backend == Backend::AUTO) {
        backend = detect_backend();
    }

    if (backend == Backend::NONE) {
        initialized_ = true;
        log("[PacketInterceptor] Backend=NONE, interception disabled");
        return true;
    }

#if defined(__linux__) && defined(HAVE_NFQUEUE)
    if (backend == Backend::NFQUEUE) {
        impl_ = std::make_unique<NFQUEUEBackend>();
        impl_->parent = this;
        if (!impl_->initialize(config)) {
            impl_.reset();
            return false;
        }
        initialized_ = true;
        return true;
    }
#endif

#if defined(_WIN32) && defined(HAVE_WINDIVERT)
    // FIX #83: Prefer WinDivert for actual packet interception on Windows
    if (backend == Backend::WINDIVERT || backend == Backend::AUTO) {
        impl_ = std::make_unique<WinDivertBackend>();
        impl_->parent = this;
        if (!impl_->initialize(config)) {
            impl_.reset();
            // Fall through to WFP if WinDivert fails
            if (backend == Backend::AUTO) {
                log("[PacketInterceptor] WinDivert failed, falling back to WFP (limited)");
            } else {
                return false;
            }
        } else {
            initialized_ = true;
            return true;
        }
    }
#endif

#ifdef _WIN32
    if (backend == Backend::WFP) {
        impl_ = std::make_unique<WFPBackend>();
        impl_->parent = this;
        if (!impl_->initialize(config)) {
            impl_.reset();
            return false;
        }
        initialized_ = true;
        return true;
    }
#endif

    log("[PacketInterceptor] Backend not available on this platform");
    return false;
}

bool PacketInterceptor::start() {
    if (!initialized_) return false;
    if (running_) return true;

    if (impl_) {
        if (!impl_->start()) return false;
    }

    running_ = true;
    log("[PacketInterceptor] Started");
    return true;
}

void PacketInterceptor::stop() {
    if (!running_) return;
    running_ = false;

    if (impl_) {
        impl_->stop();
    }

    log("[PacketInterceptor] Stopped");
}

bool PacketInterceptor::is_running() const {
    return running_.load();
}

bool PacketInterceptor::update_config(const Config& config) {
    std::lock_guard<std::mutex> lock(config_mutex_);
    config_ = config;
    config_version_++;  // FIX #30: bump version so L3Stealth re-initializes
    return true;
}

PacketInterceptor::Config PacketInterceptor::get_config() const {
    std::lock_guard<std::mutex> lock(config_mutex_);
    return config_;
}

void PacketInterceptor::set_packet_handler(PacketHandler handler) {
    packet_handler_ = handler;
}

PacketInterceptor::Stats PacketInterceptor::get_stats() const {
    return Stats(stats_);
}

void PacketInterceptor::reset_stats() {
    stats_.reset();
}

void PacketInterceptor::set_log_callback(LogCallback cb) {
    log_cb_ = cb;
}

void PacketInterceptor::log(const std::string& msg) {
    Config cfg;
    {
        std::lock_guard<std::mutex> lock(config_mutex_);
        cfg = config_;
    }
    if (cfg.enable_logging && log_cb_) {
        log_cb_(msg);
    }
}

// ==================== FIX #84: Shared L3Stealth initialization ====================
//
// Replaces the per-thread `static thread_local L3Stealth` with a single
// shared instance. L3Stealth already uses internal mutexes for thread safety
// (dest_ipid_mutex_, flow_label_mutex_, config_mutex_, atomic global_ipid_counter_),
// so a shared instance is safe and ensures consistent state:
//   - Per-destination IPID cache shared across threads (no IPID collisions)
//   - Global IPID counter monotonicity preserved
//   - IPv6 flow labels consistent per 5-tuple (RFC 6437)
//   - TCP timestamp epoch/offset consistent across connections
//   - Statistics aggregated in one place

void PacketInterceptor::ensure_l3stealth_initialized(const Config& cfg, uint64_t current_version) {
    std::lock_guard<std::mutex> lock(l3stealth_mutex_);
    if (!l3stealth_ || l3stealth_config_version_ != current_version) {
        if (!l3stealth_) {
            l3stealth_ = std::make_unique<L3Stealth>();
        }
        L3Stealth::Config l3cfg;
        l3cfg.enable_ipid_randomization = true;
        l3cfg.enable_ttl_normalization = true;
        l3cfg.enable_mss_clamping = true;
        l3cfg.enable_tcp_timestamp_normalization = true;
        l3stealth_->initialize(l3cfg);
        l3stealth_config_version_ = current_version;
    }
}

// ==================== Default Packet Handler ====================

PacketInterceptor::Verdict PacketInterceptor::default_packet_handler(
    std::vector<uint8_t>& packet, bool is_outbound)
{
    if (!is_outbound) return Verdict::ACCEPT; // Only process outbound

    Config cfg;
    uint64_t current_version;
    {
        std::lock_guard<std::mutex> lock(config_mutex_);
        cfg = config_;
        current_version = config_version_;
    }

    bool modified = false;

    // 1. L3Stealth integration
    // FIX #84: Use shared L3Stealth instance instead of thread_local.
    // This ensures all threads share the same IPID cache, flow label cache,
    // timestamp epoch, and statistics — preventing DPI-detectable inconsistencies.
    if (cfg.integrate_l3_stealth) {
        ensure_l3stealth_initialized(cfg, current_version);

        if (packet.size() >= 20 && l3stealth_) {
            uint8_t ver = (packet[0] >> 4) & 0x0F;
            if (ver == 4) {
                if (l3stealth_->process_ipv4_packet(packet)) {
                    modified = true;
                }
            } else if (ver == 6) {
                if (l3stealth_->process_ipv6_packet(packet)) {
                    modified = true;
                }
            }
        }
    }

    // 2. Post-tunnel TTL rewrite
    if (cfg.enable_post_tunnel_ttl_rewrite && packet.size() >= 20) {
        auto* ip = reinterpret_cast<IPv4Header*>(packet.data());
        if ((ip->ihl_ver >> 4) == 4) {
            if (ip->ttl != cfg.target_ttl) {
                ip->ttl = cfg.target_ttl;
                // Recalculate IP checksum
                ip->check = 0;
                uint32_t sum = 0;
                uint16_t* buf = reinterpret_cast<uint16_t*>(packet.data());
                int len = (ip->ihl_ver & 0x0F) * 4;
                for (int i = 0; i < len / 2; i++) {
                    sum += ntohs(buf[i]);
                }
                sum = (sum >> 16) + (sum & 0xFFFF);
                sum += (sum >> 16);
                ip->check = htons(static_cast<uint16_t>(~sum));
                modified = true;
                stats_.ttl_rewrites++;
            }
        }
    }

    // 3. MTU enforcement (fragment if needed)
    if (cfg.enable_mtu_enforcement && packet.size() > cfg.enforce_mtu) {
        // For simplicity, just accept large packets here.
        // Real fragmentation should be done via L3Stealth::fragment_ipv4()
        // or by setting DF=0 and letting kernel fragment.
        log("[PacketInterceptor] Packet size " + std::to_string(packet.size()) +
            " exceeds MTU " + std::to_string(cfg.enforce_mtu) + " (fragmentation needed)");
    }

    // 4. Tunneling (GRE/IPIP/VXLAN)
    if (cfg.enable_tunneling && cfg.tunnel_protocol != TunnelProtocol::NONE) {
        // Encapsulate packet
        std::vector<uint8_t> encapsulated = encapsulate_packet(packet, cfg);
        if (!encapsulated.empty()) {
            packet = std::move(encapsulated);
            modified = true;
            stats_.packets_tunneled++;
        }
    }

    return modified ? Verdict::MODIFIED : Verdict::ACCEPT;
}

// ==================== Tunneling Helpers ====================

static std::vector<uint8_t> encapsulate_packet(const std::vector<uint8_t>& packet,
                                               const PacketInterceptor::Config& cfg)
{
    if (cfg.tunnel_remote_ip.empty()) return {};

    std::vector<uint8_t> result;

    // Outer IP header
    size_t outer_ip_len = 20;
    size_t tunnel_hdr_len = 0;

    switch (cfg.tunnel_protocol) {
        case PacketInterceptor::TunnelProtocol::GRE:
            tunnel_hdr_len = 8; // GRE header with key
            break;
        case PacketInterceptor::TunnelProtocol::IPIP:
            tunnel_hdr_len = 0; // IPIP is just IP-in-IP, no extra header
            break;
        case PacketInterceptor::TunnelProtocol::VXLAN:
            // FIX #31: UDP(8) + VXLAN(8) = 16 total, VXLAN struct is now correctly 8 bytes
            tunnel_hdr_len = 8 + 8; // UDP + VXLAN (both 8 bytes each)
            break;
        case PacketInterceptor::TunnelProtocol::GRE_OBFUSCATED:
            tunnel_hdr_len = 8 + 8; // UDP + GRE (obfuscated)
            break;
        default:
            return {};
    }

    size_t total_len = outer_ip_len + tunnel_hdr_len + packet.size();
    result.resize(total_len);

    // Build outer IP header
    auto* outer_ip = reinterpret_cast<IPv4Header*>(result.data());
    outer_ip->ihl_ver = 0x45;
    outer_ip->tos = 0;
    outer_ip->tot_len = htons(static_cast<uint16_t>(total_len));
    outer_ip->id = htons(static_cast<uint16_t>(randombytes_uniform(65536)));
    outer_ip->frag_off = htons(0x4000); // DF
    outer_ip->ttl = 64;

    if (cfg.tunnel_protocol == PacketInterceptor::TunnelProtocol::GRE ||
        cfg.tunnel_protocol == PacketInterceptor::TunnelProtocol::GRE_OBFUSCATED) {
        outer_ip->protocol = (cfg.tunnel_protocol == PacketInterceptor::TunnelProtocol::GRE_OBFUSCATED)
                             ? 17 /* UDP */ : 47 /* GRE */;
    } else if (cfg.tunnel_protocol == PacketInterceptor::TunnelProtocol::IPIP) {
        outer_ip->protocol = 4; // IPIP
    } else if (cfg.tunnel_protocol == PacketInterceptor::TunnelProtocol::VXLAN) {
        outer_ip->protocol = 17; // UDP
    }

    // Parse remote IP
    inet_pton(AF_INET, cfg.tunnel_remote_ip.c_str(), &outer_ip->daddr);

    // FIX #32: Resolve local source address via routing table lookup
    // instead of relying on kernel to fill saddr=0 (not portable to BSD)
#ifdef __linux__
    outer_ip->saddr = resolve_local_saddr(cfg.tunnel_remote_ip.c_str());
#else
    outer_ip->saddr = 0; // Fallback: on Windows with WFP, kernel fills this
#endif

    outer_ip->check = 0; // Kernel will recalculate with IP_HDRINCL

    // Build tunnel header
    size_t tunnel_offset = outer_ip_len;

    if (cfg.tunnel_protocol == PacketInterceptor::TunnelProtocol::GRE ||
        cfg.tunnel_protocol == PacketInterceptor::TunnelProtocol::GRE_OBFUSCATED) {
        if (cfg.tunnel_protocol == PacketInterceptor::TunnelProtocol::GRE_OBFUSCATED) {
            // Fake UDP header
            auto* udp = reinterpret_cast<UDPHeader*>(result.data() + tunnel_offset);
            udp->source = htons(cfg.fake_udp_src_port);
            udp->dest = htons(cfg.fake_udp_dst_port);
            udp->len = htons(static_cast<uint16_t>(8 + 8 + packet.size()));
            udp->check = 0;
            tunnel_offset += 8;
        }

        auto* gre = reinterpret_cast<GREHeader*>(result.data() + tunnel_offset);
        gre->flags_ver = htons(0x2000); // K bit set (key present)
        gre->protocol = htons(GRE_PROTO_IPV4);
        gre->key = htonl(cfg.tunnel_id);
        tunnel_offset += 8;
    } else if (cfg.tunnel_protocol == PacketInterceptor::TunnelProtocol::VXLAN) {
        auto* udp = reinterpret_cast<UDPHeader*>(result.data() + tunnel_offset);
        udp->source = htons(cfg.fake_udp_src_port);
        udp->dest = htons(VXLAN_PORT);
        udp->len = htons(static_cast<uint16_t>(8 + sizeof(VXLANHeader) + packet.size()));
        udp->check = 0;
        tunnel_offset += 8;

        // FIX #31: Write exactly 8 bytes for VXLAN header (struct is now correct)
        auto* vxlan = reinterpret_cast<VXLANHeader*>(result.data() + tunnel_offset);
        std::memset(vxlan, 0, sizeof(VXLANHeader));
        vxlan->flags = 0x08; // VNI present
        // VNI is 24 bits stored in 3 bytes (big-endian)
        uint32_t vni_val = cfg.tunnel_id & 0x00FFFFFF;
        vxlan->vni[0] = static_cast<uint8_t>((vni_val >> 16) & 0xFF);
        vxlan->vni[1] = static_cast<uint8_t>((vni_val >> 8) & 0xFF);
        vxlan->vni[2] = static_cast<uint8_t>(vni_val & 0xFF);
        tunnel_offset += sizeof(VXLANHeader); // exactly 8
    }

    // Copy inner packet
    std::memcpy(result.data() + tunnel_offset, packet.data(), packet.size());

    // FIX #29: Replace single-byte XOR with ChaCha20 stream cipher
    if (cfg.enable_protocol_obfuscation) {
        if (!cfg.obfuscation_key.empty()) {
            // Use provided key material for ChaCha20
            apply_stream_obfuscation(result, tunnel_offset,
                                     cfg.obfuscation_key.data(),
                                     cfg.obfuscation_key.size());
            // Update outer IP total length (nonce was prepended)
            auto* ip = reinterpret_cast<IPv4Header*>(result.data());
            ip->tot_len = htons(static_cast<uint16_t>(result.size()));
        } else if (cfg.xor_key != 0) {
            // Legacy fallback: single-byte XOR (deprecated, warn)
            // Kept for backward compat but should be migrated
            for (size_t i = tunnel_offset; i < result.size(); i++) {
                result[i] ^= cfg.xor_key;
            }
        }
    }

    return result;
}

// ==================== Static Helpers ====================

bool PacketInterceptor::is_elevated() {
#ifdef __linux__
    return geteuid() == 0;
#elif defined(_WIN32)
    BOOL elevated = FALSE;
    HANDLE token = nullptr;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        TOKEN_ELEVATION te;
        DWORD size = sizeof(te);
        if (GetTokenInformation(token, TokenElevation, &te, sizeof(te), &size)) {
            elevated = te.TokenIsElevated;
        }
        CloseHandle(token);
    }
    return elevated != FALSE;
#else
    return false;
#endif
}

bool PacketInterceptor::is_nfqueue_available() {
#if defined(__linux__) && defined(HAVE_NFQUEUE)
    // Check if libnetfilter_queue is available
    struct nfq_handle* h = nfq_open();
    if (h) {
        nfq_close(h);
        return true;
    }
    return false;
#else
    return false;
#endif
}

// FIX #83: WinDivert availability check
bool PacketInterceptor::is_windivert_available() {
#if defined(_WIN32) && defined(HAVE_WINDIVERT)
    // Try opening a WinDivert handle with a minimal filter to check availability
    HANDLE h = WinDivertOpen("false", WINDIVERT_LAYER_NETWORK, 0, WINDIVERT_FLAG_SNIFF);
    if (h != INVALID_HANDLE_VALUE) {
        WinDivertClose(h);
        return true;
    }
    return false;
#else
    return false;
#endif
}

bool PacketInterceptor::is_wfp_available() {
#ifdef _WIN32
    HANDLE engine;
    FWPM_SESSION0 session = {0};
    DWORD result = FwpmEngineOpen0(nullptr, RPC_C_AUTHN_WINNT, nullptr, &session, &engine);
    if (result == ERROR_SUCCESS) {
        FwpmEngineClose0(engine);
        return true;
    }
    return false;
#else
    return false;
#endif
}

PacketInterceptor::Backend PacketInterceptor::detect_backend() {
#if defined(__linux__) && defined(HAVE_NFQUEUE)
    if (is_nfqueue_available()) return Backend::NFQUEUE;
#elif defined(_WIN32)
    // FIX #83: Prefer WinDivert over WFP on Windows
#ifdef HAVE_WINDIVERT
    if (is_windivert_available()) return Backend::WINDIVERT;
#endif
    if (is_wfp_available()) return Backend::WFP;
#endif
    return Backend::NONE;
}

} // namespace ncp
