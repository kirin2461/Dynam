#include "ncp_dpi.hpp"
#include "ncp_dpi_advanced.hpp"
#include "ncp_dpi_zapret.hpp"
#include "ncp_tls_fingerprint.hpp"
#include "ncp_ech.hpp"
#include "ncp_thread_pool.hpp"
#include <thread>
#include <mutex>
#include <set>
#include <cstring>
#include <iostream>
#include <algorithm>
#include <chrono>
#include <vector>
#include <sodium.h>
#include <cctype>
#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")
    #define CLOSE_SOCKET closesocket
    #ifdef HAVE_WINDIVERT
        #include <windivert.h>
    #endif
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <netinet/ip.h>
    #include <netinet/tcp.h>
    #include <arpa/inet.h>
    #include <unistd.h>
    #include <netdb.h>
    #include <poll.h>
    #define SOCKET int
    #define INVALID_SOCKET -1
    #define CLOSE_SOCKET close
    
    #ifdef HAVE_NFQUEUE
        #include <linux/netfilter.h>
        #include <libnetfilter_queue/libnetfilter_queue.h>
    #endif
#endif

#ifdef HAVE_LIBWEBSOCKETS
    #include "ncp_ws_tunnel.hpp"
#endif

namespace ncp {
namespace DPI {

namespace {

std::string to_lower_copy(const std::string& s) {
    std::string out = s;
    std::transform(out.begin(), out.end(), out.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return out;
}

} // namespace

// Using libsodium CSPRNG (randombytes_uniform) instead of mt19937

// TLS ClientHello detection
static bool is_tls_client_hello(const uint8_t* data, size_t len) {
    return len > 5 && data[0] == 0x16 && data[1] == 0x03 && data[5] == 0x01;
}

/**
 * @brief Best-effort parser for TLS ClientHello to locate SNI hostname offset.
 */
int find_sni_hostname_offset(const uint8_t* data, size_t len) {
    // R9-H14: Validate packet length before trusting header fields
    if (!data || len < 5 + 4) {
        return -1;
    }

    if (data[0] != 0x16 || data[1] != 0x03) {
        return -1;
    }

    size_t pos = 5;
    if (pos + 4 > len) {
        return -1;
    }

    uint8_t handshake_type = data[pos];
    if (handshake_type != 0x01) {
        return -1;
    }

    // R9-H14: Validate hs_len doesn't exceed buffer
    uint32_t hs_len = (static_cast<uint32_t>(data[pos + 1]) << 16) |
                      (static_cast<uint32_t>(data[pos + 2]) << 8) |
                      static_cast<uint32_t>(data[pos + 3]);
    if (hs_len > len - 5) {
        return -1;  // Malformed: handshake length exceeds buffer
    }
    pos += 4;

    if (pos + 2 + 32 + 1 > len) {
        return -1;
    }

    pos += 2;  // client_version
    pos += 32; // random

    uint8_t session_id_len = data[pos];
    pos += 1;
    if (pos + session_id_len > len) return -1;
    pos += session_id_len;

    if (pos + 2 > len) {
        return -1;
    }
    uint16_t cipher_suites_len = (static_cast<uint16_t>(data[pos]) << 8) |
                                 static_cast<uint16_t>(data[pos + 1]);
    pos += 2;
    if (pos + cipher_suites_len > len) return -1;
    pos += cipher_suites_len;

    if (pos + 1 > len) {
        return -1;
    }
    uint8_t compression_methods_len = data[pos];
    pos += 1;
    if (pos + compression_methods_len > len) return -1;
    pos += compression_methods_len;

    if (pos + 2 > len) {
        return -1;
    }
    uint16_t extensions_len = (static_cast<uint16_t>(data[pos]) << 8) |
                              static_cast<uint16_t>(data[pos + 1]);
    pos += 2;

    // R13-C02: Reject malformed extensions_len, don't clamp
    // If extensions_len exceeds buffer or overflows, reject the packet entirely
    size_t exts_end = pos + extensions_len;
    if (exts_end > len || exts_end < pos) {  // Overflow or out-of-bounds
        return -1;  // Reject malformed packet (don't clamp!)
    }

    while (pos + 4 <= exts_end) {
        uint16_t ext_type = (static_cast<uint16_t>(data[pos]) << 8) |
                            static_cast<uint16_t>(data[pos + 1]);
        uint16_t ext_data_len = (static_cast<uint16_t>(data[pos + 2]) << 8) |
                                static_cast<uint16_t>(data[pos + 3]);
        // R10-FIX-03: Validate before advancing pos to prevent out-of-bounds reads
        if (ext_data_len > exts_end - pos - 4) {
            return -1;  // Malformed extension length
        }
        pos += 4;
        if (pos + ext_data_len > exts_end) {
            return -1;  // Should not happen due to check above, but defensive
        }

        if (ext_type == 0x0000) {
            size_t sni_pos = pos;
            if (sni_pos + 2 > exts_end) return -1;
            uint16_t list_len = (static_cast<uint16_t>(data[sni_pos]) << 8) |
                                static_cast<uint16_t>(data[sni_pos + 1]);
            sni_pos += 2;
            if (sni_pos + list_len > exts_end || list_len < 3) {
                return -1;
            }

            
            // FIX: Validate we can read nametype
            if (sni_pos >= exts_end) return -1;
            uint8_t name_type = data[sni_pos];
            // FIX: Validate nametype is hostname (0x00)
            if (name_type != 0x00) return -1;
            sni_pos += 1;
            if (sni_pos + 2 > exts_end) return -1;
            uint16_t host_len = (static_cast<uint16_t>(data[sni_pos]) << 8) |
                                static_cast<uint16_t>(data[sni_pos + 1]);
            sni_pos += 2;

            if (sni_pos + host_len > exts_end) {
                return -1;
            }

            return static_cast<int>(sni_pos);
        }
        pos += ext_data_len;
    }
    return -1;
}

class DPIBypass::Impl {
public:
    std::atomic<bool> running{false};
    DPIConfig config;

    // When true, initialize() will NOT create an AdvancedDPIBypass child.
    // This breaks the infinite recursion:
    //   DPIBypass::init -> init_advanced_bypass -> AdvancedDPIBypass::init
    //   -> creates inner DPIBypass (base_only) -> no further recursion.
    bool base_only{false};

    // FIX #39: Dedicated mutex for config reads/writes.
    mutable std::mutex config_mutex;

    DPIStats stats;
    mutable std::mutex stats_mutex;
    std::thread worker_thread;
    std::function<void(const std::string&)> log_callback;

    // Phase 2: Advanced DPI bypass integration
    // R6-DPI-03: Use shared_ptr to prevent use-after-free when snapshot used outside lock
    std::shared_ptr<AdvancedDPIBypass> advanced_bypass_;
    // R17-FIX-01: atomic to prevent data race between init_advanced_bypass() and pipe_client_to_server()
    std::atomic<bool> advanced_enabled_{false};

    // Phase 2: TLS Fingerprint for realistic ClientHello
    std::unique_ptr<ncp::TLSFingerprint> tls_fingerprint_;

    // Thread pool for connection handling
    std::unique_ptr<ncp::ThreadPool> thread_pool_;
    std::atomic<int> active_connections_{0};
    static constexpr int MAX_CONNECTIONS = 256;

    // R11-FIX-01: Thread-safe thread tracking using set of thread IDs
    // R17-FIX-03: Use thread IDs instead of storing std::thread objects to avoid UAF
    std::set<std::thread::id> active_thread_ids_;
    std::mutex active_threads_mutex_;
    std::condition_variable threads_cv_;
    std::atomic<size_t> active_thread_count_{0};
    std::atomic<size_t> peak_thread_count_{0};  // R13-FIX-01: Track peak concurrency
    std::atomic<uint64_t> thread_pool_exhausted_{0};  // R13-FIX-01: Track exhaustion events
    std::atomic<bool> shutdown_requested_{false};

    // Phase 4: Transform callback for orchestrator integration.
    // Invoked on outgoing payload BEFORE fragmentation/advanced pipeline.
    mutable std::mutex transform_cb_mutex_;
    TransformCallback transform_callback_;

    // Module hook callbacks: wired by main.cpp after construction.
    // Protected by hooks_mutex_; snapshot in windivert_loop before the loop.
    mutable std::mutex hooks_mutex_;
    ModuleHooks hooks_;

    // Zapret chain-based DPI: when active, windivert_loop consults chains
    // instead of the single global DPIConfig for desync parameters.
    mutable std::mutex zapret_mutex_;
    std::vector<ZapretChain> zapret_chains_;   // active chains (empty = use global preset)
    bool zapret_active_ = false;

    TransformCallback snapshot_transform_cb() const {
        std::lock_guard<std::mutex> lock(transform_cb_mutex_);
        return transform_callback_;
    }

    void set_transform_cb(TransformCallback cb) {
        std::lock_guard<std::mutex> lock(transform_cb_mutex_);
        transform_callback_ = std::move(cb);
    }

    void set_zapret_chains(std::vector<ZapretChain> chains) {
        std::lock_guard<std::mutex> lock(zapret_mutex_);
        zapret_chains_ = std::move(chains);
        zapret_active_ = !zapret_chains_.empty();
    }

    // R12-M01/R13-H02: Find the first zapret chain matching this packet; returns nullptr if none.
    // Note: sni parameter is required — caller must extract SNI from TLS ClientHello for TCP packets
    const ZapretChain* find_matching_chain(ZProto proto, uint16_t dst_port,
                                           const std::string& sni) const {
        // No lock needed: called only from windivert_loop after snapshot
        for (const auto& chain : zapret_chains_) {
            if (chain_matches_packet(chain, proto, dst_port, sni)) return &chain;
        }
        return nullptr;
    }

    // Apply zapret chain overrides onto a DPIConfig copy
    static DPIConfig apply_chain_overrides(const DPIConfig& base, const ZapretDPIOverrides& ov) {
        DPIConfig cfg = base;
        cfg.enable_tcp_split = true;
        cfg.enable_fake_packet = ov.enable_fake;
        cfg.fake_repeats = std::max(ov.fake_repeats, 1);
        cfg.fake_fooling = ov.fake_fooling;

        if (ov.enable_disorder) {
            cfg.enable_disorder = true;
            cfg.enable_reverse_frag = false;
        } else if (ov.enable_multi_split || ov.enable_fakedsplit) {
            cfg.enable_disorder = false;
            cfg.enable_reverse_frag = false;
            cfg.enable_multi_layer_split = ov.enable_multi_split;
        } else {
            // Default: use reverse-frag (good for Beeline)
            cfg.enable_disorder = false;
            cfg.enable_reverse_frag = true;
        }

        if (ov.split_position > 0) cfg.split_position = ov.split_position;

        if (ov.ttl > 0) cfg.fake_ttl = ov.ttl;
        if (ov.auto_ttl) {
            cfg.enable_autottl = true;
            cfg.autottl_min = ov.auto_ttl_min;
            cfg.autottl_max = ov.auto_ttl_max;
        }
        return cfg;
    }

    // Apply transform callback to a buffer.  Returns transformed data
    // (or empty vector if no callback / callback returned empty).
    std::vector<uint8_t> apply_transform(
        const uint8_t* data, size_t len) {
        auto xform = snapshot_transform_cb();
        if (!xform) return {};
        std::vector<uint8_t> input(data, data + len);
        auto result = xform(input);
        return result;  // empty means "use original"
    }

#ifdef HAVE_LIBWEBSOCKETS
    std::unique_ptr<ncp::WSTunnel> ws_tunnel_;
    std::mutex ws_client_mutex_;
    SOCKET ws_active_client_ = INVALID_SOCKET;
#endif

    // Phase 2: Initialize AdvancedDPIBypass from DPIConfig
    void init_advanced_bypass() {
        AdvancedDPIConfig adv_config;
        adv_config.base_config = config;

        if (config.enable_tcp_split) {
            adv_config.techniques.push_back(EvasionTechnique::SNI_SPLIT);
            adv_config.techniques.push_back(EvasionTechnique::TCP_SEGMENTATION);
        }
        if (config.enable_fake_packet) {
            adv_config.techniques.push_back(EvasionTechnique::IP_TTL_TRICKS);
            adv_config.techniques.push_back(EvasionTechnique::FAKE_SNI);
        }
        if (config.enable_pattern_obfuscation) {
            adv_config.techniques.push_back(EvasionTechnique::TLS_GREASE);
        }
        if (config.enable_timing_jitter) {
            adv_config.techniques.push_back(EvasionTechnique::TIMING_JITTER);
        }
        if (config.enable_disorder) {
            adv_config.techniques.push_back(EvasionTechnique::TCP_DISORDER);
        }

        if (config.enable_fake_packet && config.enable_tcp_split &&
            config.enable_pattern_obfuscation) {
            adv_config.tspu_bypass = true;
        }

        advanced_bypass_ = std::make_shared<AdvancedDPIBypass>();
        advanced_bypass_->set_log_callback([this](const std::string& msg) {
            log("[Advanced] " + msg);
        });

        if (tls_fingerprint_) {
            advanced_bypass_->set_tls_fingerprint(tls_fingerprint_.get());
        }

        if (advanced_bypass_->initialize(adv_config)) {
            if (tls_fingerprint_) {
                advanced_bypass_->set_tls_fingerprint(tls_fingerprint_.get());
            }
#if defined(_WIN32)
            // On Windows DRIVER mode the main WinDivert loop handles all
            // packet interception.  Do NOT start the Advanced child's own
            // base_bypass (which would open a second WinDivert handle on the
            // same filter and break connectivity).  Advanced is used only for
            // its process_outgoing()/process_incoming() transformations.
            if (config.mode != DPIMode::DRIVER) {
                advanced_bypass_->start();
            }
#else
            advanced_bypass_->start();
#endif
            advanced_enabled_ = true;
            log("Advanced DPI bypass layer initialized with " +
                std::to_string(adv_config.techniques.size()) + " techniques" +
                (tls_fingerprint_ ? " + TLS fingerprint" : ""));
        } else {
            log("Warning: Advanced DPI bypass initialization failed, using basic mode");
            advanced_bypass_.reset();
            advanced_enabled_ = false;
        }
    }

    // Phase 2: Initialize TLS Fingerprint
    void init_tls_fingerprint() {
        tls_fingerprint_ = std::make_unique<ncp::TLSFingerprint>(ncp::BrowserType::CHROME);
        if (!config.target_host.empty()) {
            tls_fingerprint_->set_sni(config.target_host);
        }
        log("TLS fingerprint initialized (profile=Chrome, target=" + config.target_host + ")");
    }

    // FIX #39: Thread-safe config snapshot helper
    DPIConfig snapshot_config() const {
        std::lock_guard<std::mutex> lock(config_mutex);
        return config;
    }

    // FIX #55: proxy_listen_loop with poll() before accept() and connection limits
    void proxy_listen_loop() {
#ifdef _WIN32
        WSADATA wsa_data;
        if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
            log("Failed to initialize Winsock for DPI proxy");
            running = false;
            return;
        }
#endif

        SOCKET listen_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (listen_sock == INVALID_SOCKET) {
            log("Failed to create listen socket for DPI proxy");
            running = false;
#ifdef _WIN32
            WSACleanup();
#endif
            return;
        }

        int opt = 1;
        setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR,
                   reinterpret_cast<const char*>(&opt), sizeof(opt));

        // FIX #39: snapshot config for listen_port (thread-safe)
        DPIConfig listen_cfg = snapshot_config();

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(listen_cfg.listen_port);
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

        if (bind(listen_sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
            log("Failed to bind DPI proxy socket (port in use?)");
            CLOSE_SOCKET(listen_sock);
            running = false;
#ifdef _WIN32
            WSACleanup();
#endif
            return;
        }

        if (listen(listen_sock, SOMAXCONN) < 0) {
            log("Failed to listen on DPI proxy socket");
            CLOSE_SOCKET(listen_sock);
            running = false;
#ifdef _WIN32
            WSACleanup();
#endif
            return;
        }

        size_t num_threads = std::min<size_t>(std::thread::hardware_concurrency(), 8);
        
        // R6-DPI-09: Shutdown existing thread pool before creating new one
        if (thread_pool_) {
            thread_pool_->shutdown();
            thread_pool_.reset();
        }
        thread_pool_ = std::make_unique<ncp::ThreadPool>(num_threads);
        log("DPI proxy listening on 127.0.0.1:" + std::to_string(listen_cfg.listen_port));

        // FIX #55: Use poll()/select() with timeout so the loop exits when running becomes false
        while (running) {
#ifdef _WIN32
            fd_set read_fds;
            FD_ZERO(&read_fds);
            FD_SET(listen_sock, &read_fds);
            struct timeval tv;
            tv.tv_sec = 1;
            tv.tv_usec = 0;
            int sel_ret = select(static_cast<int>(listen_sock + 1), &read_fds, nullptr, nullptr, &tv);
            if (sel_ret <= 0) {
                continue;
            }
#else
            struct pollfd pfd;
            pfd.fd = listen_sock;
            pfd.events = POLLIN;
            pfd.revents = 0;
            int poll_ret = poll(&pfd, 1, 1000);
            if (poll_ret <= 0) {
                continue;
            }
            if (!(pfd.revents & POLLIN)) {
                continue;
            }
#endif

            sockaddr_in client_addr{};
#ifdef _WIN32
            int addr_len = static_cast<int>(sizeof(client_addr));
#else
            socklen_t addr_len = static_cast<socklen_t>(sizeof(client_addr));
#endif

            SOCKET client_sock = accept(listen_sock,
                                        reinterpret_cast<sockaddr*>(&client_addr),
                                        &addr_len);
            if (client_sock == INVALID_SOCKET) {
                if (!running) break;
                continue;
            }

            // R6-DPI-02: Atomic connection limit check-and-increment
            int expected = active_connections_.load(std::memory_order_relaxed);
            if (expected >= MAX_CONNECTIONS) {
                log("DPI proxy: max connections reached (" + std::to_string(MAX_CONNECTIONS) + "), rejecting");
                CLOSE_SOCKET(client_sock);
                continue;
            }
            // Try to increment; if another thread beat us, retry or reject
            while (!active_connections_.compare_exchange_weak(expected, expected + 1,
                       std::memory_order_acq_rel, std::memory_order_relaxed)) {
                if (expected >= MAX_CONNECTIONS) {
                    log("DPI proxy: max connections reached (" + std::to_string(MAX_CONNECTIONS) + "), rejecting");
                    CLOSE_SOCKET(client_sock);
                    goto next_connection;  // Skip to next iteration
                }
            }

            {
                std::lock_guard<std::mutex> lock(stats_mutex);
                stats.connections_handled++;
            }

            thread_pool_->submit([this, client_sock]() {
                handle_proxy_connection(client_sock);
                active_connections_.fetch_sub(1, std::memory_order_release);
            });
            
            next_connection:;
        }

        CLOSE_SOCKET(listen_sock);
#ifdef _WIN32
        WSACleanup();
#endif
    }

    // FIX #55: handle_proxy_connection
    void handle_proxy_connection(SOCKET client_sock) {
        // FIX #39: config snapshot at connection start
        DPIConfig cfg_snap = snapshot_config();

        if (cfg_snap.target_host.empty()) {
            log("DPI proxy: target_host is empty, closing client connection");
            CLOSE_SOCKET(client_sock);
            return;
        }

        addrinfo hints{};
        std::memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;

        addrinfo* result = nullptr;
        if (getaddrinfo(cfg_snap.target_host.c_str(), nullptr, &hints, &result) != 0 || !result) {
            log("DPI proxy: failed to resolve target host: " + cfg_snap.target_host);
            CLOSE_SOCKET(client_sock);
            return;
        }

        sockaddr_in remote_addr{};
        remote_addr.sin_family = AF_INET;
        remote_addr.sin_port = htons(cfg_snap.target_port);
        remote_addr.sin_addr = reinterpret_cast<sockaddr_in*>(result->ai_addr)->sin_addr;
        freeaddrinfo(result);

        SOCKET server_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (server_sock == INVALID_SOCKET) {
            log("DPI proxy: failed to create upstream socket");
            CLOSE_SOCKET(client_sock);
            return;
        }

        // FIX #55: Set TCP_NODELAY before connect to prevent Nagle from coalescing fragments
        int nodelay = 1;
        setsockopt(server_sock, IPPROTO_TCP, TCP_NODELAY,
                   reinterpret_cast<const char*>(&nodelay), sizeof(nodelay));

        if (connect(server_sock,
                    reinterpret_cast<sockaddr*>(&remote_addr),
                    sizeof(remote_addr)) < 0) {
            log("DPI proxy: failed to connect to upstream server");
            CLOSE_SOCKET(client_sock);
            CLOSE_SOCKET(server_sock);
            return;
        }

        // R7-DPI-04: Use try-catch to handle std::thread constructor failure
        // to prevent std::terminate() if thread creation fails
        // R12-M02: Track active threads for proper shutdown
        // R17-FIX-03: Track by thread ID instead of storing thread objects
        std::thread t_cs;
        std::thread t_sc;
        std::thread::id t_cs_id;
        std::thread::id t_sc_id;
        try {
            // R17-FIX-03: Store thread IDs before starting threads
            t_cs = std::thread([this, client_sock, server_sock, cfg_snap]() {
                pipe_client_to_server(client_sock, server_sock, cfg_snap);
            });
            t_sc = std::thread([this, server_sock, client_sock]() {
                pipe_server_to_client(server_sock, client_sock);
            });
            t_cs_id = t_cs.get_id();
            t_sc_id = t_sc.get_id();

            // Add to active threads tracking
            {
                std::lock_guard<std::mutex> lock(active_threads_mutex_);
                active_thread_ids_.insert(t_cs_id);
                active_thread_ids_.insert(t_sc_id);
            }
        } catch (const std::system_error& e) {
            log("DPI proxy: failed to create pipe threads: " + std::string(e.what()));
            CLOSE_SOCKET(client_sock);
            CLOSE_SOCKET(server_sock);
            return;
        }

        // R12-M02: Wait for pipe threads to complete
        if (t_cs.joinable()) {
            t_cs.join();
            std::lock_guard<std::mutex> lock(active_threads_mutex_);
            active_thread_ids_.erase(t_cs_id);
        }
        if (t_sc.joinable()) {
            t_sc.join();
            std::lock_guard<std::mutex> lock(active_threads_mutex_);
            active_thread_ids_.erase(t_sc_id);
        }

        CLOSE_SOCKET(client_sock);
        CLOSE_SOCKET(server_sock);
    }

    // FIX #39: pipe_server_to_client -- simple relay
    void pipe_server_to_client(SOCKET server_sock, SOCKET client_sock) {
        std::vector<uint8_t> buffer(8192);
        while (running) {
#ifdef _WIN32
            fd_set read_fds;
            FD_ZERO(&read_fds);
            FD_SET(server_sock, &read_fds);
            struct timeval tv;
            tv.tv_sec = 1;
            tv.tv_usec = 0;
            int sel = select(static_cast<int>(server_sock + 1), &read_fds, nullptr, nullptr, &tv);
            if (sel < 0) break;
            if (sel == 0) continue;
            if (!FD_ISSET(server_sock, &read_fds)) continue;
#else
            struct pollfd pfd;
            pfd.fd = server_sock;
            pfd.events = POLLIN;
            pfd.revents = 0;
            int ret = poll(&pfd, 1, 1000);
            if (ret < 0) break;
            if (ret == 0) continue;
            if (!(pfd.revents & (POLLIN | POLLHUP | POLLERR))) continue;
#endif
            int received = recv(server_sock, reinterpret_cast<char*>(buffer.data()),
                                static_cast<int>(buffer.size()), 0);
            if (received <= 0) break;

            // R6-DPI-03: Snapshot advanced_bypass_ as shared_ptr to prevent use-after-free
            // R17-FIX-01: Use atomic load for thread-safe read
            std::shared_ptr<AdvancedDPIBypass> adv_snap;
            if (advanced_enabled_.load(std::memory_order_acquire)) {
                std::lock_guard<std::mutex> lock(config_mutex);
                adv_snap = advanced_bypass_;
            }
            
            if (adv_snap) {
                auto deobf = adv_snap->process_incoming(
                    buffer.data(), static_cast<size_t>(received));
                // R7-DPI-03: Fall back to raw data if deobfuscation returns empty
                // to prevent silent data loss when obfuscator state is mismatched
                if (!deobf.empty()) {
                    send_raw(client_sock, deobf.data(), deobf.size());
                } else {
                    send_raw(client_sock, buffer.data(), static_cast<size_t>(received));
                }
            } else {
                send_raw(client_sock, buffer.data(), static_cast<size_t>(received));
            }
        }
    }

    // FIX #39: cfg_snap passed by value -- no concurrent access to shared config
    // Phase 4: Transform callback applied before fragmentation/advanced pipeline.
    void pipe_client_to_server(SOCKET client_sock, SOCKET server_sock, DPIConfig cfg_snap) {
        std::vector<uint8_t> buffer(8192);
        bool client_hello_processed = false;

#ifdef _WIN32
        // Windows select-based relay
        while (running) {
            fd_set read_fds;
            FD_ZERO(&read_fds);
            FD_SET(client_sock, &read_fds);
            SOCKET max_fd = client_sock;
            struct timeval tv;
            tv.tv_sec = 1;
            tv.tv_usec = 0;
            int sel = select(static_cast<int>(max_fd + 1), &read_fds, nullptr, nullptr, &tv);
            if (sel < 0) break;
            if (sel == 0) continue;

            if (!FD_ISSET(client_sock, &read_fds)) continue;

            int received = recv(client_sock, reinterpret_cast<char*>(buffer.data()),
                                static_cast<int>(buffer.size()), 0);
            if (received <= 0) break;
            {
                std::lock_guard<std::mutex> lock(stats_mutex);
                stats.bytes_received += static_cast<uint64_t>(received);
                stats.packets_total++;
            }

            // Phase 4: Apply transform callback before any DPI processing
            const uint8_t* send_data = buffer.data();
            size_t send_len = static_cast<size_t>(received);
            std::vector<uint8_t> transformed = apply_transform(send_data, send_len);
            if (!transformed.empty()) {
                send_data = transformed.data();
                send_len = transformed.size();
                std::lock_guard<std::mutex> lock(stats_mutex);
                stats.packets_modified++;
            }

            bool is_ch = false;
            if (!client_hello_processed &&
                is_tls_client_hello(send_data, send_len)) {
                is_ch = true;
                client_hello_processed = true;
            }

            // R6-DPI-03: Snapshot advanced_bypass_ as shared_ptr to prevent use-after-free
            // R17-FIX-01: Use atomic load for thread-safe read
            std::shared_ptr<AdvancedDPIBypass> adv_snap;
            if (advanced_enabled_.load(std::memory_order_acquire)) {
                std::lock_guard<std::mutex> lock(config_mutex);
                adv_snap = advanced_bypass_;
            }
            
            // Phase 2: Route ClientHello through AdvancedDPIBypass
            if (is_ch && adv_snap) {
                send_via_advanced(server_sock, send_data, send_len);
            } else {
                send_with_fragmentation(server_sock, send_data, send_len, is_ch, cfg_snap);
            }
        }
#else
        // POSIX poll-based relay
        struct pollfd fds[1];
        fds[0].fd = client_sock;
        fds[0].events = POLLIN;

        while (running) {
            int ret = poll(fds, 1, 1000);
            if (ret < 0) break;
            if (ret == 0) continue;

            if (!(fds[0].revents & (POLLIN | POLLHUP | POLLERR))) continue;

            int received = recv(client_sock, reinterpret_cast<char*>(buffer.data()),
                                static_cast<int>(buffer.size()), 0);
            if (received <= 0) break;
            {
                std::lock_guard<std::mutex> lock(stats_mutex);
                stats.bytes_received += static_cast<uint64_t>(received);
                stats.packets_total++;
            }

            // Phase 4: Apply transform callback before any DPI processing
            const uint8_t* send_data = buffer.data();
            size_t send_len = static_cast<size_t>(received);
            std::vector<uint8_t> transformed = apply_transform(send_data, send_len);
            if (!transformed.empty()) {
                send_data = transformed.data();
                send_len = transformed.size();
                std::lock_guard<std::mutex> lock(stats_mutex);
                stats.packets_modified++;
            }

            bool is_ch = false;
            if (!client_hello_processed &&
                is_tls_client_hello(send_data, send_len)) {
                is_ch = true;
                client_hello_processed = true;
            }

            // R17-FIX-04: Unified logic with Windows path - snapshot advanced_bypass_
            std::shared_ptr<AdvancedDPIBypass> adv_snap;
            {
                std::lock_guard<std::mutex> lock(config_mutex);
                if (advanced_enabled_.load(std::memory_order_acquire)) {
                    adv_snap = advanced_bypass_;
                }
            }
            
            // Phase 2: Route ClientHello through AdvancedDPIBypass
            if (is_ch && adv_snap) {
                send_via_advanced(server_sock, send_data, send_len);
            } else {
                send_with_fragmentation(server_sock, send_data, send_len, is_ch, cfg_snap);
            }
        }
#endif
    }

    // FIX #39: 5-arg send_with_fragmentation with cfg snapshot
    // FIX #38/#48: No fake packet / noise injection via TCP socket
    void send_with_fragmentation(
        SOCKET sock, const uint8_t* data, size_t len,
        bool is_client_hello, const DPIConfig& cfg)
    {
        if (!data || len == 0) return;

        auto send_all = [&](const uint8_t* d, size_t l) -> size_t {
            size_t total_sent = 0;
            while (total_sent < l) {
                int to_send = static_cast<int>(std::min<size_t>(l - total_sent, 1460));
                int sent = send(sock,
                                reinterpret_cast<const char*>(d + total_sent),
                                to_send, 0);
                if (sent <= 0) break;
                total_sent += static_cast<size_t>(sent);
            }
            return total_sent;
        };

        // FIX #38/#48: noise/fake-packet via TCP socket is broken.
        // TCP guarantees in-order reliable delivery. Low-TTL trick only works
        // with raw sockets. In PROXY mode we only apply TCP fragmentation.
        if (is_client_hello && (cfg.enable_noise || cfg.enable_fake_packet)) {
            log("DPI: noise/fake-packet requested but skipped -- "
                "TCP socket injection is broken; raw socket integration required");
            {
                std::lock_guard<std::mutex> lock(stats_mutex);
                if (cfg.enable_fake_packet) stats.fake_packets_sent++;
            }
        }

        if (!is_client_hello || !cfg.enable_tcp_split) {
            size_t sent = send_all(data, len);
            std::lock_guard<std::mutex> lock(stats_mutex);
            stats.bytes_sent += static_cast<uint64_t>(sent);
            return;
        }

        // TCP split/fragmentation
        size_t first_len = 0;
        int sni_offset = -1;
        if (cfg.split_at_sni) {
            sni_offset = find_sni_hostname_offset(data, len);
        }

        if (sni_offset > 0 && static_cast<size_t>(sni_offset) < len) {
            first_len = static_cast<size_t>(sni_offset);
        } else if (cfg.split_position > 0 &&
                   static_cast<size_t>(cfg.split_position) < len) {
            first_len = static_cast<size_t>(cfg.split_position);
        } else {
            first_len = std::min<size_t>(len, 1);
        }

        size_t sent_total = 0;
        size_t sent_first = send_all(data, first_len);
        sent_total += sent_first;

        size_t remaining = (sent_first < len) ? (len - sent_first) : 0;
        if (remaining > 0) {
            // R11-FIX-02: Prevent integer overflow in fragment size calculation
            constexpr size_t MAX_FRAG_SIZE = 8192;  // Sane upper bound
            size_t base_frag_size = (cfg.fragment_size > 0)
                                   ? static_cast<size_t>(cfg.fragment_size) : 2;
            // Clamp to prevent overflow and unreasonable sizes
            base_frag_size = std::min(base_frag_size, MAX_FRAG_SIZE);
            // Ensure at least 1 byte
            base_frag_size = std::max(base_frag_size, size_t{1});
            
            size_t offset = 0;
            while (offset < remaining) {
                // R11-FIX-02: Saturating add to prevent overflow
                size_t jitter = randombytes_uniform(3);
                size_t current_frag = base_frag_size;
                if (jitter < remaining - offset - base_frag_size) {
                    current_frag += jitter;
                }
                current_frag = std::min(current_frag, remaining - offset);

                if (cfg.enable_disorder && cfg.disorder_delay_ms > 0) {
                    std::this_thread::sleep_for(
                        std::chrono::milliseconds(cfg.disorder_delay_ms));
                }
                size_t sent = send_all(data + sent_first + offset, current_frag);
                sent_total += sent;
                if (sent == 0) break;
                offset += sent;
            }
        }

        {
            std::lock_guard<std::mutex> lock(stats_mutex);
            stats.bytes_sent += static_cast<uint64_t>(sent_total);
            if (sent_total >= len && first_len > 0 && remaining > 0) {
                stats.packets_fragmented++;
            }
        }
    }

    // Phase 2: Send data through AdvancedDPIBypass pipeline
    void send_via_advanced(SOCKET sock, const uint8_t* data, size_t len) {
        // CRIT-3: take config snapshot under lock to prevent data race
        DPIConfig cfg_snap;
        {
            std::lock_guard<std::mutex> lock(config_mutex);
            cfg_snap = config;
        }

        auto segments = advanced_bypass_->process_outgoing(data, len);

        auto send_all = [&](const uint8_t* d, size_t l) -> size_t {
            size_t total_sent = 0;
            while (total_sent < l) {
                int to_send = static_cast<int>(std::min<size_t>(l - total_sent, 1460));
                int sent = send(sock,
                                reinterpret_cast<const char*>(d + total_sent),
                                to_send, 0);
                if (sent <= 0) break;
                total_sent += static_cast<size_t>(sent);
            }
            return total_sent;
        };

        size_t sent_total = 0;
        for (size_t i = 0; i < segments.size(); ++i) {
            const auto& seg = segments[i];

            if (i > 0 && cfg_snap.enable_timing_jitter &&
                cfg_snap.timing_jitter_min_us > 0) {
                uint32_t delay = cfg_snap.timing_jitter_min_us +
                    randombytes_uniform(static_cast<uint32_t>(
                        cfg_snap.timing_jitter_max_us - cfg_snap.timing_jitter_min_us + 1));
                std::this_thread::sleep_for(std::chrono::microseconds(delay));
            } else if (i > 0 && cfg_snap.enable_disorder && cfg_snap.disorder_delay_ms > 0) {
                std::this_thread::sleep_for(
                    std::chrono::milliseconds(cfg_snap.disorder_delay_ms));
            }

            sent_total += send_all(seg.data(), seg.size());
        }

        {
            std::lock_guard<std::mutex> lock(stats_mutex);
            stats.bytes_sent += static_cast<uint64_t>(sent_total);
            if (segments.size() > 1) {
                stats.packets_fragmented++;
            }
        }
    }

    // Raw send helper (no fragmentation)
    size_t send_raw(SOCKET sock, const uint8_t* data, size_t len) {
        size_t total_sent = 0;
        while (total_sent < len) {
            int to_send = static_cast<int>(std::min<size_t>(len - total_sent, 1460));
            int sent = send(sock,
                            reinterpret_cast<const char*>(data + total_sent),
                            to_send, 0);
            if (sent <= 0) break;
            total_sent += static_cast<size_t>(sent);
        }
        {
            std::lock_guard<std::mutex> lock(stats_mutex);
            stats.bytes_sent += static_cast<uint64_t>(total_sent);
        }
        return total_sent;
    }

#ifdef HAVE_LIBWEBSOCKETS
    // FIX #41: process_outgoing_for_ws returns vector of separate frames.
    std::vector<std::vector<uint8_t>> process_outgoing_for_ws(
        const uint8_t* data, size_t len,
        bool is_client_hello, const DPIConfig& cfg)
    {
        std::vector<std::vector<uint8_t>> frames;
        if (!data || len == 0) return frames;

        // Noise / fake host preamble (separate WS frame)
        if (is_client_hello && cfg.enable_noise) {
            std::vector<uint8_t> noise_frame;
            if (!cfg.fake_host.empty()) {
                std::string mask = "GET / HTTP/1.1\r\nHost: " + cfg.fake_host + "\r\n\r\n";
                noise_frame.assign(mask.begin(), mask.end());
            } else {
                size_t noise_sz = cfg.noise_size > 0
                                    ? static_cast<size_t>(cfg.noise_size) : 64;
                noise_frame.resize(noise_sz);
                for (size_t i = 0; i < noise_sz; ++i)
                    noise_frame[i] = static_cast<uint8_t>(randombytes_uniform(256));
            }
            frames.push_back(std::move(noise_frame));
        }

        // Fake TLS probe (each as separate WS frame)
        if (is_client_hello && cfg.enable_fake_packet) {
            int fakes = (cfg.fake_ttl > 2) ? 2 : 1;
            for (int i = 0; i < fakes; ++i) {
                std::vector<uint8_t> fake_frame = {
                    0x16, 0x03,
                    static_cast<uint8_t>(randombytes_uniform(4)),
                    static_cast<uint8_t>(randombytes_uniform(256)),
                    static_cast<uint8_t>(randombytes_uniform(256)),
                    0x01
                };
                frames.push_back(std::move(fake_frame));
                {
                    std::lock_guard<std::mutex> lock(stats_mutex);
                    stats.fake_packets_sent++;
                }
            }
        }

        // TCP split / fragmentation (each fragment = separate WS frame)
        if (!is_client_hello || !cfg.enable_tcp_split) {
            frames.emplace_back(data, data + len);
        } else {
            size_t first_len = 0;
            int sni_off = -1;
            if (cfg.split_at_sni)
                sni_off = find_sni_hostname_offset(data, len);

            if (sni_off > 0 && static_cast<size_t>(sni_off) < len)
                first_len = static_cast<size_t>(sni_off);
            else if (cfg.split_position > 0 &&
                     static_cast<size_t>(cfg.split_position) < len)
                first_len = static_cast<size_t>(cfg.split_position);
            else
                first_len = std::min<size_t>(len, 1);

            frames.emplace_back(data, data + first_len);

            size_t base_frag = cfg.fragment_size > 0
                                ? static_cast<size_t>(cfg.fragment_size) : 2;
            size_t remaining = len - first_len;
            size_t off = first_len;
            while (remaining > 0) {
                size_t j = randombytes_uniform(3);
                size_t chunk = std::min(base_frag + j, remaining);
                frames.emplace_back(data + off, data + off + chunk);
                off += chunk;
                remaining -= chunk;
            }
        }

        {
            std::lock_guard<std::mutex> lock(stats_mutex);
            size_t total_bytes = 0;
            for (const auto& f : frames) total_bytes += f.size();
            stats.bytes_sent += static_cast<uint64_t>(total_bytes);
            if (is_client_hello && cfg.enable_tcp_split)
                stats.packets_fragmented++;
        }

        return frames;
    }

    void send_to_client(const uint8_t* data, size_t len) {
        std::lock_guard<std::mutex> lock(ws_client_mutex_);
        if (ws_active_client_ == INVALID_SOCKET || !data || len == 0) return;
        size_t total_sent = 0;
        while (total_sent < len) {
            int chunk = static_cast<int>(std::min<size_t>(len - total_sent, 8192));
            int sent = ::send(ws_active_client_,
                              reinterpret_cast<const char*>(data + total_sent), chunk, 0);
            if (sent <= 0) break;
            total_sent += static_cast<size_t>(sent);
        }
        {
            std::lock_guard<std::mutex> slock(stats_mutex);
            stats.bytes_received += static_cast<uint64_t>(total_sent);
        }
    }

    void ws_tunnel_listen_loop() {
#ifdef _WIN32
        WSADATA wsa_data;
        if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
            log("WS_TUNNEL: Failed to initialize Winsock");
            running = false;
            return;
        }
#endif
        // FIX #39: snapshot config
        DPIConfig listen_cfg = snapshot_config();
        uint16_t local_port = listen_cfg.ws_local_port > 0
                                ? listen_cfg.ws_local_port : 8081;

        SOCKET listen_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (listen_sock == INVALID_SOCKET) {
            log("WS_TUNNEL: Failed to create listen socket");
            running = false;
#ifdef _WIN32
            WSACleanup();
#endif
            return;
        }

        int opt = 1;
        setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR,
                   reinterpret_cast<const char*>(&opt), sizeof(opt));

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(local_port);
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

        if (bind(listen_sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
            log("WS_TUNNEL: Failed to bind on port " + std::to_string(local_port));
            CLOSE_SOCKET(listen_sock);
            running = false;
#ifdef _WIN32
            WSACleanup();
#endif
            return;
        }

        if (listen(listen_sock, SOMAXCONN) < 0) {
            log("WS_TUNNEL: Failed to listen");
            CLOSE_SOCKET(listen_sock);
            running = false;
#ifdef _WIN32
            WSACleanup();
#endif
            return;
        }

        size_t num_threads = std::min<size_t>(std::thread::hardware_concurrency(), 8);
        
        // R6-DPI-09: Shutdown existing thread pool before creating new one
        if (thread_pool_) {
            thread_pool_->shutdown();
            thread_pool_.reset();
        }
        thread_pool_ = std::make_unique<ncp::ThreadPool>(num_threads);

        log("WS_TUNNEL: listening on 127.0.0.1:" + std::to_string(local_port) +
            " -> relay " + listen_cfg.ws_server_url);

        // FIX #55: poll() before accept() in WS tunnel loop too
        while (running) {
#ifdef _WIN32
            fd_set read_fds;
            FD_ZERO(&read_fds);
            FD_SET(listen_sock, &read_fds);
            struct timeval tv;
            tv.tv_sec = 1;
            tv.tv_usec = 0;
            int sel_ret = select(static_cast<int>(listen_sock + 1), &read_fds, nullptr, nullptr, &tv);
            if (sel_ret <= 0) continue;
#else
            struct pollfd pfd;
            pfd.fd = listen_sock;
            pfd.events = POLLIN;
            pfd.revents = 0;
            int poll_ret = poll(&pfd, 1, 1000);
            if (poll_ret <= 0) continue;
            if (!(pfd.revents & POLLIN)) continue;
#endif

            sockaddr_in client_addr{};
#ifdef _WIN32
            int addr_len = static_cast<int>(sizeof(client_addr));
#else
            socklen_t addr_len = static_cast<socklen_t>(sizeof(client_addr));
#endif
            SOCKET client_sock = accept(listen_sock,
                                        reinterpret_cast<sockaddr*>(&client_addr),
                                        &addr_len);
            if (client_sock == INVALID_SOCKET) {
                if (!running) break;
                continue;
            }

            // R6-DPI-02: Atomic connection limit check-and-increment for WS tunnel
            int expected = active_connections_.load(std::memory_order_relaxed);
            if (expected >= MAX_CONNECTIONS) {
                log("WS tunnel: max connections reached, rejecting");
                CLOSE_SOCKET(client_sock);
                continue;
            }
            while (!active_connections_.compare_exchange_weak(expected, expected + 1,
                       std::memory_order_acq_rel, std::memory_order_relaxed)) {
                if (expected >= MAX_CONNECTIONS) {
                    log("WS tunnel: max connections reached, rejecting");
                    CLOSE_SOCKET(client_sock);
                    goto next_ws_connection;
                }
            }

            {
                std::lock_guard<std::mutex> lock(stats_mutex);
                stats.connections_handled++;
            }

            thread_pool_->submit([this, client_sock]() {
                handle_ws_tunnel_connection(client_sock);
                active_connections_.fetch_sub(1, std::memory_order_release);
            });
            
            next_ws_connection:;
        }

        CLOSE_SOCKET(listen_sock);
#ifdef _WIN32
        WSACleanup();
#endif
    }

    void handle_ws_tunnel_connection(SOCKET client_sock) {
        {
            std::lock_guard<std::mutex> lock(ws_client_mutex_);
            // DPI-FIX-2: Single-client enforcement
            if (ws_active_client_ != INVALID_SOCKET) {
                log("WS tunnel: rejecting new client, already connected");
                CLOSE_SOCKET(client_sock);
                return;
            }
            ws_active_client_ = client_sock;
        }

        // FIX #39: snapshot config at connection start
        DPIConfig cfg_snap = snapshot_config();

        std::vector<uint8_t> buffer(8192);
        bool client_hello_processed = false;

        while (running) {
            // R6-DPI-10: Use poll/select with timeout before recv to allow graceful shutdown
#ifdef _WIN32
            fd_set read_fds;
            FD_ZERO(&read_fds);
            FD_SET(client_sock, &read_fds);
            struct timeval tv;
            tv.tv_sec = 1;
            tv.tv_usec = 0;
            int sel = select(static_cast<int>(client_sock + 1), &read_fds, nullptr, nullptr, &tv);
            if (sel <= 0) continue;  // Timeout or error — check running flag
            if (!FD_ISSET(client_sock, &read_fds)) continue;
#else
            struct pollfd pfd;
            pfd.fd = client_sock;
            pfd.events = POLLIN;
            pfd.revents = 0;
            int ret = poll(&pfd, 1, 1000);
            if (ret <= 0) continue;  // Timeout or error — check running flag
            if (!(pfd.revents & (POLLIN | POLLHUP | POLLERR))) continue;
#endif

            int received = recv(client_sock,
                                reinterpret_cast<char*>(buffer.data()),
                                static_cast<int>(buffer.size()), 0);
            if (received <= 0) break;

            {
                std::lock_guard<std::mutex> lock(stats_mutex);
                stats.bytes_received += static_cast<uint64_t>(received);
                stats.packets_total++;
            }

            // Phase 4: Apply transform callback in WS tunnel path
            const uint8_t* send_data = buffer.data();
            size_t send_len = static_cast<size_t>(received);
            std::vector<uint8_t> transformed = apply_transform(send_data, send_len);
            if (!transformed.empty()) {
                send_data = transformed.data();
                send_len = transformed.size();
                std::lock_guard<std::mutex> lock(stats_mutex);
                stats.packets_modified++;
            }

            bool is_ch = false;
            if (!client_hello_processed &&
                is_tls_client_hello(send_data, send_len)) {
                is_ch = true;
                client_hello_processed = true;
            }

            // FIX #41: Each frame sent as separate WebSocket message
            auto frames = process_outgoing_for_ws(
                send_data, send_len, is_ch, cfg_snap);

            if (ws_tunnel_) {
                for (const auto& frame : frames) {
                    if (!frame.empty()) {
                        ws_tunnel_->send(frame.data(), frame.size());
                    }
                }
            }
        }

        {
            std::lock_guard<std::mutex> lock(ws_client_mutex_);
            ws_active_client_ = INVALID_SOCKET;
        }
        CLOSE_SOCKET(client_sock);
    }

    bool start_ws_tunnel() {
        ws_tunnel_ = std::make_unique<ncp::WSTunnel>();

        // FIX #39: snapshot config
        DPIConfig cfg_snap = snapshot_config();

        ncp::WSTunnelConfig ws_cfg;
        ws_cfg.server_url           = cfg_snap.ws_server_url;
        ws_cfg.local_port           = cfg_snap.ws_local_port;
        ws_cfg.sni_override         = cfg_snap.ws_sni_override;
        ws_cfg.ping_interval_sec    = cfg_snap.ws_ping_interval_sec;
        ws_cfg.reconnect_delay_ms   = cfg_snap.ws_reconnect_delay_ms;
        ws_cfg.max_reconnect_attempts = cfg_snap.ws_max_reconnect_attempts;

        if (!ws_tunnel_->initialize(ws_cfg)) {
            log("WS_TUNNEL: Failed to initialize libwebsockets context");
            ws_tunnel_.reset();
            return false;
        }

        ws_tunnel_->set_receive_callback(
            [this](const uint8_t* data, size_t len) {
                send_to_client(data, len);
            });

        ws_tunnel_->set_state_callback(
            [this](bool connected) {
                log(std::string("WS_TUNNEL: relay ") +
                    (connected ? "CONNECTED" : "DISCONNECTED"));
            });

        if (!ws_tunnel_->start()) {
            log("WS_TUNNEL: Failed to connect to relay " + cfg_snap.ws_server_url);
            ws_tunnel_.reset();
            return false;
        }

        running = true;
        worker_thread = std::thread(&Impl::ws_tunnel_listen_loop, this);
        return true;
    }

    void stop_ws_tunnel() {
        if (ws_tunnel_) {
            ws_tunnel_->stop();
            ws_tunnel_.reset();
        }
        {
            std::lock_guard<std::mutex> lock(ws_client_mutex_);
            if (ws_active_client_ != INVALID_SOCKET) {
                CLOSE_SOCKET(ws_active_client_);
                ws_active_client_ = INVALID_SOCKET;
            }
        }
    }
#endif // HAVE_LIBWEBSOCKETS

#if defined(HAVE_WINDIVERT) && defined(_WIN32)
    HANDLE wd_handle_ = nullptr;

    // Clean up a stale WinDivert driver service from the Windows SCM.
    // Error 1058 is almost always caused by a leftover registry entry
    // at HKLM\SYSTEM\CurrentControlSet\Services\WinDivert that points
    // to a .sys path that no longer exists or has changed location.
    // See: https://github.com/basil00/WinDivert/issues/253
    void cleanup_stale_windivert_service() {
        // Method 1: Use SC to stop+delete the service
        log("WinDivert: cleaning stale driver service (error 1058 recovery)...");

        // Try all known WinDivert service names
        const char* service_names[] = {
            "WinDivert", "WinDivert1.0", "WinDivert14", nullptr
        };
        for (int i = 0; service_names[i]; i++) {
            SC_HANDLE scm = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
            if (!scm) continue;
            SC_HANDLE svc = OpenServiceA(scm, service_names[i],
                                         SERVICE_STOP | DELETE | SERVICE_QUERY_STATUS);
            if (svc) {
                SERVICE_STATUS status;
                ControlService(svc, SERVICE_CONTROL_STOP, &status);
                if (DeleteService(svc)) {
                    log(std::string("WinDivert: deleted stale service '") +
                        service_names[i] + "'");
                }
                CloseServiceHandle(svc);
            }
            CloseServiceHandle(scm);
        }

        // Method 2: Direct registry cleanup (in case SC didn't work)
        const wchar_t* reg_keys[] = {
            L"SYSTEM\\CurrentControlSet\\Services\\WinDivert",
            L"SYSTEM\\CurrentControlSet\\Services\\WinDivert1.0",
            L"SYSTEM\\CurrentControlSet\\Services\\WinDivert14",
            nullptr
        };
        for (int i = 0; reg_keys[i]; i++) {
            LSTATUS st = RegDeleteTreeW(HKEY_LOCAL_MACHINE, reg_keys[i]);
            if (st == ERROR_SUCCESS) {
                log("WinDivert: removed stale registry key");
            }
        }

        // Give Windows a moment to process the service deletion
        Sleep(500);
    }

    bool init_windivert() {
        // Ensure WinDivert DLL and driver can be found.
        // WinDivertOpen loads WinDivert.dll which installs WinDivert64.sys
        // as a kernel driver. Both files must be accessible.
        // Error 1058 (ERROR_SERVICE_DISABLED) typically means a stale
        // WinDivert service entry exists in the registry from a previous
        // install, pointing to a .sys path that no longer exists.
        {
            // Try setting DLL search directory to known WinDivert SDK locations
            // so that WinDivert.dll can locate WinDivert64.sys.
            wchar_t exe_path[MAX_PATH];
            GetModuleFileNameW(nullptr, exe_path, MAX_PATH);
            std::wstring exe_dir(exe_path);
            auto pos = exe_dir.find_last_of(L"\\//");
            if (pos != std::wstring::npos) exe_dir = exe_dir.substr(0, pos);
            SetDllDirectoryW(exe_dir.c_str());

            // Also try to copy WinDivert files from SDK if they're missing
            auto file_exists = [](const std::wstring& p) {
                return GetFileAttributesW(p.c_str()) != INVALID_FILE_ATTRIBUTES;
            };
            bool have_dll = file_exists(exe_dir + L"\\WinDivert.dll");
            bool have_sys = file_exists(exe_dir + L"\\WinDivert64.sys");

            if (!have_dll || !have_sys) {
                // Search known SDK locations
                const wchar_t* sdk_paths[] = {
                    L"C:\\WinDivert-2.2.2-A\\x64",
                    L"C:\\WinDivert-2.2.2-A",
                    L"C:\\WinDivert\\x64",
                    L"C:\\WinDivert",
                    nullptr
                };
                for (int i = 0; sdk_paths[i]; i++) {
                    std::wstring sdk(sdk_paths[i]);
                    if (!have_dll && file_exists(sdk + L"\\WinDivert.dll")) {
                        CopyFileW((sdk + L"\\WinDivert.dll").c_str(),
                                  (exe_dir + L"\\WinDivert.dll").c_str(), FALSE);
                        have_dll = file_exists(exe_dir + L"\\WinDivert.dll");
                        log("WinDivert: copied WinDivert.dll from SDK");
                    }
                    if (!have_sys && file_exists(sdk + L"\\WinDivert64.sys")) {
                        CopyFileW((sdk + L"\\WinDivert64.sys").c_str(),
                                  (exe_dir + L"\\WinDivert64.sys").c_str(), FALSE);
                        have_sys = file_exists(exe_dir + L"\\WinDivert64.sys");
                        log("WinDivert: copied WinDivert64.sys from SDK");
                    }
                    if (have_dll && have_sys) break;
                }
                if (!have_dll) log("WinDivert: WARNING - WinDivert.dll not found next to exe");
                if (!have_sys) log("WinDivert: WARNING - WinDivert64.sys not found next to exe");
            }
        }

        // Pre-emptive cleanup disabled: calling cleanup_stale_windivert_service()
        // unconditionally here caused the WinDivert driver service to be deleted
        // and re-registered on every startup, which is slow and unnecessary.
        // It is now called only inside the error-1058 retry path below, where
        // a stale service entry is the confirmed root cause.
        // cleanup_stale_windivert_service(); // MED-8: moved to error-1058 retry path

        // Open WinDivert filter:
        //   - HTTPS (443) with payload: full DPI bypass
        //   - HTTP (80) with payload: module pre/post processing
        //   - DNS (UDP 53): DNS leak prevention via pre_process hook
        //   - QUIC/UDP 443: for QUIC-based services (YouTube etc.)
        static const char* wd_filter =
            "outbound and ("
            "(tcp.DstPort == 443 and tcp.PayloadLength > 0) or "
            "(tcp.DstPort == 80 and tcp.PayloadLength > 0) or "
            "udp.DstPort == 53 or "
            "udp.DstPort == 443)";

        wd_handle_ = WinDivertOpen(
            wd_filter,
            WINDIVERT_LAYER_NETWORK,  // Network layer
            0,                        // Priority
            0                         // Flags
        );

        if (wd_handle_ == INVALID_HANDLE_VALUE) {
            DWORD err = GetLastError();

            // Error 1058: Retry once after cleanup + short wait.
            // The cleanup above should have removed the stale service,
            // but the SCM may need a moment to fully process it.
            if (err == 1058) {
                log("WinDivert: error 1058 on first try, retrying after cleanup...");
                Sleep(1000);
                cleanup_stale_windivert_service();
                Sleep(1000);

                wd_handle_ = WinDivertOpen(
                    wd_filter,
                    WINDIVERT_LAYER_NETWORK, 0, 0);

                if (wd_handle_ != INVALID_HANDLE_VALUE) {
                    log("WinDivert handle opened successfully (after retry)");
                    return true;
                }
                err = GetLastError();
            }

            std::string hint;
            switch (err) {
            case 2:
                hint = " WinDivert64.sys not found. Copy it next to ncp.exe.";
                break;
            case 5:
                hint = " Access denied. Run as Administrator.";
                break;
            case 577:
                hint = " Driver signature issue. Disable Secure Boot or sign the driver.";
                break;
            case 1058:
                hint = " Driver service could not start. "
                       "Stale WinDivert service entry in registry. "
                       "Run fix_windivert.bat as Admin, then reboot.";
                break;
            case 1275:
                hint = " Driver blocked by security policy. "
                       "Add WinDivert64.sys to antivirus exclusions.";
                break;
            default:
                hint = " Run as Administrator and ensure WinDivert64.sys "
                       "is in the same directory as ncp.exe.";
                break;
            }
            log("WinDivert: failed to open handle (error=" +
                std::to_string(err) + ")." + hint);
            return false;
        }
        log("WinDivert handle opened successfully");
        return true;
    }

    // Magic IP ID value used to mark packets we injected ourselves.
    // When we see this ID on an intercepted packet we know it is one of
    // our own fragments and must be passed through without re-processing.
    static constexpr uint16_t MAGIC_IP_ID = 0x4E43; // "NC" in hex

    void windivert_loop() {
        uint8_t packet[65535];
        UINT packet_len;
        WINDIVERT_ADDRESS addr;

        while (running) {
            // DPI-FIX-3: Re-snapshot config and zapret chains each iteration
            // so runtime update_config() calls take effect without restart.
            DPIConfig cfg = snapshot_config();

            // Snapshot zapret chains (if any)
            bool use_zapret = false;
            {
                std::lock_guard<std::mutex> lk(zapret_mutex_);
                use_zapret = zapret_active_;
            }

            if (!WinDivertRecv(wd_handle_, packet, sizeof(packet), &packet_len, &addr)) {
                if (!running) break;
                DWORD err = GetLastError();
                if (err == ERROR_NO_DATA || err == ERROR_TIMEOUT) continue;
                log("WinDivert: recv error " + std::to_string(err));
                break;
            }

            {
                std::lock_guard<std::mutex> lock(stats_mutex);
                stats.packets_total++;
            }

            // Parse IP + TCP headers
            PWINDIVERT_IPHDR ip_header = nullptr;
            PWINDIVERT_TCPHDR tcp_header = nullptr;
            PWINDIVERT_UDPHDR udp_header = nullptr;
            uint8_t* tcp_payload = nullptr;
            UINT payload_len = 0;

            // Parse for both TCP and UDP
            WinDivertHelperParsePacket(packet, packet_len,
                &ip_header, nullptr, nullptr, nullptr, nullptr,
                &tcp_header, &udp_header, (PVOID*)&tcp_payload, &payload_len, nullptr, nullptr);

            // Handle UDP packets (DNS port 53 + QUIC port 443)
            if (ip_header && udp_header && !tcp_header) {
                // Skip packets we injected ourselves
                if (ntohs(ip_header->Id) == MAGIC_IP_ID) {
                    // CRIT-1: check return value
                    if (!WinDivertSend(wd_handle_, packet, packet_len, nullptr, &addr)) {
                        DWORD wd_err = GetLastError();
                        if (wd_err != ERROR_HOST_UNREACHABLE && wd_err != ERROR_NETWORK_UNREACHABLE) {
                            log("WinDivertSend (magic/UDP) failed: err=" + std::to_string(wd_err));
                            stats.send_errors++;
                        }
                    }
                    continue;
                }

                uint16_t udp_dst = ntohs(udp_header->DstPort);

                // === QUIC DPI bypass (UDP 443) ===
                // When zapret chains are active and match QUIC traffic,
                // send fake QUIC packets before the real one to confuse DPI.
                if (use_zapret && udp_dst == 443 && tcp_payload && payload_len > 0) {
                    // R13-H02: Use find_matching_chain helper (empty SNI for UDP/QUIC)
                    const ZapretChain* match = find_matching_chain(ZProto::UDP, udp_dst, "");
                    if (match) {
                        auto ov = chain_to_overrides(*match);
                        int repeats = std::max(ov.fake_repeats, 1);
                        UINT ip_hdr_len = ip_header->HdrLength * 4;

                        // R6-DPI-14: Bounds check to prevent buffer underflow
                        size_t hdr_total = static_cast<size_t>(ip_hdr_len) + 8; // UDP header = 8
                        if (hdr_total >= packet_len) {
                            // Malformed or too small packet — skip fake injection
                            continue;
                        }

                        // Send fake QUIC packets with low TTL
                        for (int r = 0; r < repeats; r++) {
                            std::vector<uint8_t> fake(packet, packet + packet_len);
                            PWINDIVERT_IPHDR fip = (PWINDIVERT_IPHDR)fake.data();
                            fip->Id = htons(MAGIC_IP_ID);
                            fip->TTL = ov.ttl > 0 ? static_cast<uint8_t>(ov.ttl) : 4;
                            // Corrupt payload to create a fake packet
                            uint8_t* fpay = fake.data() + hdr_total;
                            size_t fpay_len = fake.size() - hdr_total;
                            if (fpay_len > 4) {
                                for (size_t i = 4; i < fpay_len; i++)
                                    fpay[i] = static_cast<uint8_t>(randombytes_uniform(256));
                            }
                            WinDivertHelperCalcChecksums(fake.data(),
                                static_cast<UINT>(fake.size()), &addr, 0);
                            if (ov.fake_fooling & 1) { // badsum
                                PWINDIVERT_UDPHDR fudp = (PWINDIVERT_UDPHDR)(fake.data() + ip_hdr_len);
                                fudp->Checksum ^= htons(0x0100);
                            }
                            // CRIT-1: check return value (fake packet - debug only)
                            if (!WinDivertSend(wd_handle_, fake.data(),
                                static_cast<UINT>(fake.size()), nullptr, &addr)) {
                                DWORD wd_err = GetLastError();
                                if (wd_err != ERROR_HOST_UNREACHABLE && wd_err != ERROR_NETWORK_UNREACHABLE) {
                                    log("WinDivertSend (fake/QUIC) failed: err=" + std::to_string(wd_err));
                                }
                            }
                            {
                                std::lock_guard<std::mutex> lock(stats_mutex);
                                stats.fake_packets_sent++;
                            }
                        }
                    }
                }

                // === Module pre-processing hook (UDP) ===
                {
                    ModuleHooks hooks_snap;
                    { std::lock_guard<std::mutex> lk(hooks_mutex_); hooks_snap = hooks_; }
                    if (hooks_snap.pre_process) {
                        uint32_t plen32 = static_cast<uint32_t>(packet_len);
                        if (!hooks_snap.pre_process(packet, plen32)) {
                            // Hook says DROP this packet
                            continue;
                        }
                        // CRIT-2: bounds check - hook must not exceed packet buffer size
                        if (plen32 > sizeof(packet)) {
                            log("pre_process hook (UDP) returned oversized length " +
                                std::to_string(plen32) + ", clamping to " +
                                std::to_string(sizeof(packet)));
                            plen32 = static_cast<uint32_t>(sizeof(packet));
                        }
                        packet_len = static_cast<UINT>(plen32);
                        
                        // R6-DPI-04: Re-parse headers after pre_process hook modified the packet
                        ip_header = nullptr;
                        udp_header = nullptr;
                        tcp_payload = nullptr;
                        payload_len = 0;
                        WinDivertHelperParsePacket(packet, packet_len,
                            &ip_header, nullptr, nullptr, nullptr, nullptr,
                            nullptr, &udp_header, (PVOID*)&tcp_payload, &payload_len, nullptr, nullptr);
                        if (!ip_header || !udp_header) {
                            // Send unchanged and continue
                            if (!WinDivertSend(wd_handle_, packet, packet_len, nullptr, &addr)) {
                                DWORD wd_err = GetLastError();
                                if (wd_err != ERROR_HOST_UNREACHABLE && wd_err != ERROR_NETWORK_UNREACHABLE) {
                                    log("WinDivertSend (UDP post-reparse) failed: err=" + std::to_string(wd_err));
                                    stats.send_errors++;
                                }
                            }
                            continue;
                        }
                    }
                }
                // CRIT-1: check return value (real UDP passthrough)
                if (!WinDivertSend(wd_handle_, packet, packet_len, nullptr, &addr)) {
                    DWORD wd_err = GetLastError();
                    if (wd_err != ERROR_HOST_UNREACHABLE && wd_err != ERROR_NETWORK_UNREACHABLE) {
                        log("WinDivertSend (UDP passthrough) failed: err=" + std::to_string(wd_err));
                        stats.send_errors++;
                    }
                }
                continue;
            }

            if (!ip_header || !tcp_header || !tcp_payload || payload_len == 0) {
                // CRIT-1: check return value (non-TCP passthrough)
                if (!WinDivertSend(wd_handle_, packet, packet_len, nullptr, &addr)) {
                    DWORD wd_err = GetLastError();
                    if (wd_err != ERROR_HOST_UNREACHABLE && wd_err != ERROR_NETWORK_UNREACHABLE) {
                        log("WinDivertSend (non-TCP passthrough) failed: err=" + std::to_string(wd_err));
                        stats.send_errors++;
                    }
                }
                continue;
            }

            // Skip packets we already injected (marked with MAGIC_IP_ID)
            if (ntohs(ip_header->Id) == MAGIC_IP_ID) {
                // CRIT-1: check return value (magic/TCP passthrough)
                if (!WinDivertSend(wd_handle_, packet, packet_len, nullptr, &addr)) {
                    DWORD wd_err = GetLastError();
                    if (wd_err != ERROR_HOST_UNREACHABLE && wd_err != ERROR_NETWORK_UNREACHABLE) {
                        log("WinDivertSend (magic/TCP) failed: err=" + std::to_string(wd_err));
                        stats.send_errors++;
                    }
                }
                continue;
            }

            // === Module pre-processing hook (TCP) ===
            {
                ModuleHooks hooks_snap;
                { std::lock_guard<std::mutex> lk(hooks_mutex_); hooks_snap = hooks_; }
                if (hooks_snap.pre_process) {
                    uint32_t plen32 = static_cast<uint32_t>(packet_len);
                    if (!hooks_snap.pre_process(packet, plen32)) {
                        // Hook says DROP this packet
                        continue;
                    }
                    // CRIT-2: bounds check - hook must not exceed packet buffer size
                    if (plen32 > sizeof(packet)) {
                        log("pre_process hook (TCP) returned oversized length " +
                            std::to_string(plen32) + ", clamping to " +
                            std::to_string(sizeof(packet)));
                        plen32 = static_cast<uint32_t>(sizeof(packet));
                    }
                    packet_len = static_cast<UINT>(plen32);
                    // Re-parse headers since pre_process may have modified the packet
                    ip_header = nullptr;
                    tcp_header = nullptr;
                    tcp_payload = nullptr;
                    payload_len = 0;
                    WinDivertHelperParsePacket(packet, packet_len,
                        &ip_header, nullptr, nullptr, nullptr, nullptr,
                        &tcp_header, nullptr, (PVOID*)&tcp_payload, &payload_len, nullptr, nullptr);
                    if (!ip_header || !tcp_header || !tcp_payload || payload_len == 0) {
                        // CRIT-1: check return value (post-hook passthrough)
                        if (!WinDivertSend(wd_handle_, packet, packet_len, nullptr, &addr)) {
                            DWORD wd_err = GetLastError();
                            if (wd_err != ERROR_HOST_UNREACHABLE && wd_err != ERROR_NETWORK_UNREACHABLE) {
                                log("WinDivertSend (post-hook passthrough) failed: err=" + std::to_string(wd_err));
                                stats.send_errors++;
                            }
                        }
                        continue;
                    }
                }
            }

            // Check for TLS ClientHello: ContentType=0x16, Version=0x03xx, HandshakeType=0x01
            bool is_client_hello = (payload_len > 5 &&
                                    tcp_payload[0] == 0x16 &&
                                    tcp_payload[1] == 0x03 &&
                                    tcp_payload[5] == 0x01);

            // ── Zapret chain matching ────────────────────────────────────────
            // When zapret chains are active, find the matching chain and use
            // its desync parameters (repeats, fooling, TTL, split-pos, etc.)
            // instead of the single global DPIConfig preset.
            DPIConfig effective_cfg = cfg;  // start with global preset
            uint16_t dst_port = ntohs(tcp_header->DstPort);

            // R12-M01: Extract SNI early for chain matching
            std::string sni_hostname;
            if (is_client_hello && tcp_payload && payload_len > 0) {
                int sni_off = find_sni_hostname_offset(tcp_payload, payload_len);
                if (sni_off > 0 && static_cast<size_t>(sni_off) < payload_len) {
                    // Extract hostname from ClientHello
                    uint16_t host_len = (static_cast<uint16_t>(tcp_payload[sni_off]) << 8) |
                                        static_cast<uint16_t>(tcp_payload[sni_off + 1]);
                    if (static_cast<size_t>(sni_off + 2 + host_len) <= payload_len) {
                        sni_hostname.assign(
                            reinterpret_cast<const char*>(tcp_payload + sni_off + 2),
                            host_len);
                    }
                }
            }

            if (use_zapret) {
                // R13-H02: Use find_matching_chain helper with extracted SNI
                const ZapretChain* match = find_matching_chain(ZProto::TCP, dst_port, sni_hostname);
                if (match) {
                    auto ov = chain_to_overrides(*match);
                    effective_cfg = apply_chain_overrides(cfg, ov);
                }
            }

            if (!is_client_hello || !effective_cfg.enable_tcp_split) {
                // CRIT-1: check return value (non-ClientHello passthrough)
                if (!WinDivertSend(wd_handle_, packet, packet_len, nullptr, &addr)) {
                    DWORD wd_err = GetLastError();
                    if (wd_err != ERROR_HOST_UNREACHABLE && wd_err != ERROR_NETWORK_UNREACHABLE) {
                        log("WinDivertSend (non-TLS passthrough) failed: err=" + std::to_string(wd_err));
                        stats.send_errors++;
                    }
                }
                continue;
            }

            // === TLS ClientHello detected ===
            {
                std::lock_guard<std::mutex> lock(stats_mutex);
                stats.packets_modified++;
            }

            UINT ip_hdr_len = ip_header->HdrLength * 4;
            UINT tcp_hdr_len = tcp_header->HdrLength * 4;
            // DPI-FIX-1: Validate header lengths before using them in memcpy
            if (ip_hdr_len < 20 || tcp_hdr_len < 20 || (ip_hdr_len + tcp_hdr_len) > packet_len) {
                // Invalid headers: reinject unchanged and skip DPI processing
                if (!WinDivertSend(wd_handle_, packet, packet_len, nullptr, &addr)) {
                    DWORD wd_err = GetLastError();
                    if (wd_err != ERROR_HOST_UNREACHABLE && wd_err != ERROR_NETWORK_UNREACHABLE) {
                        log("WinDivertSend (invalid-hdr passthrough) failed: err=" + std::to_string(wd_err));
                        stats.send_errors++;
                    }
                }
                continue;
            }
            UINT headers_len = ip_hdr_len + tcp_hdr_len;
            uint8_t orig_ttl = ip_header->TTL;
            uint32_t orig_seq = ntohl(tcp_header->SeqNum);

            // --- Determine split positions ---
            // Default: split at position 1 (before SNI)
            int sni_off = -1;
            if (effective_cfg.split_at_sni) {
                sni_off = find_sni_hostname_offset(tcp_payload, payload_len);
            }

            // Build list of split positions (sorted, unique, within range)
            std::vector<size_t> splits;
            if (effective_cfg.enable_multi_layer_split) {
                // Multi-split: position 1 + SNI offset (mimics zapret split-pos=1,midsld)
                splits.push_back(1);
                if (sni_off > 1 && static_cast<size_t>(sni_off) < payload_len) {
                    splits.push_back(static_cast<size_t>(sni_off));
                }
                // Add any user-specified positions
                for (int p : effective_cfg.split_positions) {
                    if (p > 0 && static_cast<size_t>(p) < payload_len) {
                        splits.push_back(static_cast<size_t>(p));
                    }
                }
            } else {
                // Single split
                size_t sp = 0;
                if (sni_off > 0 && static_cast<size_t>(sni_off) < payload_len) {
                    sp = static_cast<size_t>(sni_off);
                } else if (effective_cfg.split_position > 0 &&
                           static_cast<size_t>(effective_cfg.split_position) < payload_len) {
                    sp = static_cast<size_t>(effective_cfg.split_position);
                } else {
                    sp = std::min<size_t>(payload_len, 2);
                }
                splits.push_back(sp);
            }

            // Sort and deduplicate
            std::sort(splits.begin(), splits.end());
            splits.erase(std::unique(splits.begin(), splits.end()), splits.end());

            // --- Build TCP segments from split positions ---
            // Segments: [0..splits[0]), [splits[0]..splits[1]), ..., [splits[n-1]..payload_len)
            struct Segment {
                size_t offset;
                size_t length;
            };
            std::vector<Segment> segments;
            size_t prev = 0;
            for (size_t sp : splits) {
                if (sp > prev && sp < payload_len) {
                    segments.push_back({prev, sp - prev});
                    prev = sp;
                }
            }
            if (prev < payload_len) {
                segments.push_back({prev, payload_len - prev});
            }

            // Helper: build a raw IP+TCP packet carrying a payload slice
            auto build_segment = [&](size_t pay_offset, size_t pay_len,
                                     uint32_t seq_num, uint8_t ttl_val,
                                     bool corrupt_checksum, bool corrupt_seq) -> std::vector<uint8_t>
            {
                size_t total = headers_len + pay_len;
                std::vector<uint8_t> pkt(total);
                memcpy(pkt.data(), packet, headers_len);
                if (pay_len > 0) {
                    memcpy(pkt.data() + headers_len, tcp_payload + pay_offset, pay_len);
                }

                PWINDIVERT_IPHDR ip = (PWINDIVERT_IPHDR)pkt.data();
                ip->Length = htons(static_cast<uint16_t>(total));
                ip->Id = htons(MAGIC_IP_ID);
                ip->TTL = ttl_val;

                PWINDIVERT_TCPHDR tcp = (PWINDIVERT_TCPHDR)(pkt.data() + ip_hdr_len);
                tcp->SeqNum = htonl(seq_num);

                if (corrupt_seq) {
                    // badseq fooling: offset the sequence number so server drops it
                    uint32_t bad = seq_num - static_cast<uint32_t>(payload_len) - 1;
                    tcp->SeqNum = htonl(bad);
                }

                // Recalculate checksums
                WinDivertHelperCalcChecksums(pkt.data(), static_cast<UINT>(pkt.size()), &addr, 0);

                if (corrupt_checksum) {
                    // badsum fooling: flip a bit in TCP checksum after calculation
                    tcp->Checksum ^= htons(0x0100);
                }

                return pkt;
            };

            // Helper: build a fake TLS ClientHello packet (garbage SNI)
            auto build_fake = [&](size_t pay_offset, size_t pay_len, uint32_t seq_num) -> std::vector<uint8_t>
            {
                // Create a copy of the payload slice with corrupted SNI
                std::vector<uint8_t> fake_payload(pay_len);
                if (pay_len > 0) {
                    memcpy(fake_payload.data(), tcp_payload + pay_offset, pay_len);
                    // Corrupt the payload: fill with random data
                    // but keep TLS record header to look like real ClientHello to DPI
                    if (pay_len > 9) {
                        // Keep first 5 bytes (TLS record header) intact-looking
                        for (size_t i = 5; i < pay_len; i++) {
                            fake_payload[i] = static_cast<uint8_t>(randombytes_uniform(256));
                        }
                    } else {
                        for (size_t i = 0; i < pay_len; i++) {
                            fake_payload[i] = static_cast<uint8_t>(randombytes_uniform(256));
                        }
                    }
                }

                size_t total = headers_len + pay_len;
                std::vector<uint8_t> pkt(total);
                memcpy(pkt.data(), packet, headers_len);
                if (pay_len > 0) {
                    memcpy(pkt.data() + headers_len, fake_payload.data(), pay_len);
                }

                PWINDIVERT_IPHDR ip = (PWINDIVERT_IPHDR)pkt.data();
                ip->Length = htons(static_cast<uint16_t>(total));
                ip->Id = htons(MAGIC_IP_ID);
                ip->TTL = static_cast<uint8_t>(effective_cfg.fake_ttl); // low TTL: dies before server

                PWINDIVERT_TCPHDR tcp = (PWINDIVERT_TCPHDR)(pkt.data() + ip_hdr_len);
                tcp->SeqNum = htonl(seq_num);

                bool use_badseq = (effective_cfg.fake_fooling & 2) != 0;
                if (use_badseq) {
                    uint32_t bad = seq_num - static_cast<uint32_t>(payload_len) - 1;
                    tcp->SeqNum = htonl(bad);
                }

                // Add TCP MD5 option if md5sig fooling requested
                // (would require extending TCP header — skip for now,
                //  badseq+badsum+low TTL is sufficient)

                WinDivertHelperCalcChecksums(pkt.data(), static_cast<UINT>(pkt.size()), &addr, 0);

                bool use_badsum = (effective_cfg.fake_fooling & 1) != 0;
                if (use_badsum) {
                    tcp = (PWINDIVERT_TCPHDR)(pkt.data() + ip_hdr_len);
                    tcp->Checksum ^= htons(0x0100);
                }

                return pkt;
            };

            size_t total_sent = 0;

            if (effective_cfg.enable_disorder) {
                // === DISORDER MODE ===
                // Send segments in REVERSE order with fake packets interleaved.
                // zapret "fake,multidisorder" pattern:
                //   For each segment (last to first):
                //     1. Send FAKE of this segment (low TTL / bad checksum)
                //     2. Send REAL segment
                //     3. Send FAKE of this segment again (optional second fake)
                // DPI sees: fake2, real2, fake2, fake1, real1, fake1
                // Server: drops fakes (TTL expired / bad checksum / bad seq),
                //         reassembles real1+real2 by TCP sequence numbers.

                uint32_t seq_cursor = orig_seq;
                // Pre-calculate sequence offsets for each segment
                std::vector<uint32_t> seg_seq(segments.size());
                for (size_t i = 0; i < segments.size(); i++) {
                    seg_seq[i] = seq_cursor;
                    seq_cursor += static_cast<uint32_t>(segments[i].length);
                }

                for (int i = static_cast<int>(segments.size()) - 1; i >= 0; i--) {
                    const auto& seg = segments[static_cast<size_t>(i)];

                    // 1. Send fake(s) for this segment BEFORE the real one
                    if (effective_cfg.enable_fake_packet) {
                        for (int r = 0; r < effective_cfg.fake_repeats; r++) {
                            auto fake_pkt = build_fake(seg.offset, seg.length, seg_seq[static_cast<size_t>(i)]);
                            UINT sent = 0;
                            // CRIT-1: check return value (disorder fake)
                            if (!WinDivertSend(wd_handle_, fake_pkt.data(),
                                              static_cast<UINT>(fake_pkt.size()), &sent, &addr)) {
                                DWORD wd_err = GetLastError();
                                if (wd_err != ERROR_HOST_UNREACHABLE && wd_err != ERROR_NETWORK_UNREACHABLE) {
                                    log("WinDivertSend (disorder/fake-before) failed: err=" + std::to_string(wd_err));
                                }
                            }
                            total_sent += sent;
                            {
                                std::lock_guard<std::mutex> lock(stats_mutex);
                                stats.fake_packets_sent++;
                            }
                        }
                    }

                    // 2. Send the REAL segment
                    auto real_pkt = build_segment(seg.offset, seg.length,
                                                  seg_seq[static_cast<size_t>(i)],
                                                  orig_ttl, false, false);
                    // === Module delay hook (disorder mode real segment) ===
                    {
                        ModuleHooks hooks_snap;
                        { std::lock_guard<std::mutex> lk(hooks_mutex_); hooks_snap = hooks_; }
                        if (hooks_snap.get_send_delay_us) {
                            int64_t delay_us = hooks_snap.get_send_delay_us(
                                real_pkt.data(), static_cast<uint32_t>(real_pkt.size()));
                            if (delay_us > 0 && delay_us < 10000000) {
                                std::this_thread::sleep_for(std::chrono::microseconds(delay_us));
                            }
                        }
                    }
                    UINT sent = 0;
                    // CRIT-1: check return value (disorder real segment)
                    if (!WinDivertSend(wd_handle_, real_pkt.data(),
                                      static_cast<UINT>(real_pkt.size()), &sent, &addr)) {
                        DWORD wd_err = GetLastError();
                        if (wd_err != ERROR_HOST_UNREACHABLE && wd_err != ERROR_NETWORK_UNREACHABLE) {
                            log("WinDivertSend (disorder/real) failed: err=" + std::to_string(wd_err));
                            stats.send_errors++;
                        }
                    }
                    total_sent += sent;

                    // 3. Send fake AFTER real (optional second fake)
                    if (effective_cfg.enable_fake_packet) {
                        for (int r = 0; r < effective_cfg.fake_repeats; r++) {
                            auto fake_pkt = build_fake(seg.offset, seg.length, seg_seq[static_cast<size_t>(i)]);
                            UINT sent2 = 0;
                            // CRIT-1: check return value (disorder fake-after)
                            if (!WinDivertSend(wd_handle_, fake_pkt.data(),
                                              static_cast<UINT>(fake_pkt.size()), &sent2, &addr)) {
                                DWORD wd_err = GetLastError();
                                if (wd_err != ERROR_HOST_UNREACHABLE && wd_err != ERROR_NETWORK_UNREACHABLE) {
                                    log("WinDivertSend (disorder/fake-after) failed: err=" + std::to_string(wd_err));
                                }
                            }
                            total_sent += sent2;
                            {
                                std::lock_guard<std::mutex> lock(stats_mutex);
                                stats.fake_packets_sent++;
                            }
                        }
                    }
                }

            } else if (effective_cfg.enable_reverse_frag && segments.size() > 1) {
                // === REVERSE FRAGMENT MODE ===
                // Send segments in reverse order WITHOUT fake interleaving.
                // Mimics GoodbyeDPI --reverse-frag.
                // DPI processes packets in arrival order and fails to
                // reassemble the TLS ClientHello properly.

                uint32_t seq_cursor = orig_seq;
                std::vector<uint32_t> seg_seq(segments.size());
                for (size_t i = 0; i < segments.size(); i++) {
                    seg_seq[i] = seq_cursor;
                    seq_cursor += static_cast<uint32_t>(segments[i].length);
                }

                // Send fake(s) for the WHOLE payload first (if enabled)
                if (effective_cfg.enable_fake_packet) {
                    for (int r = 0; r < effective_cfg.fake_repeats; r++) {
                        auto fake_pkt = build_fake(0, payload_len, orig_seq);
                        UINT sent = 0;
                        // CRIT-1: check return value (reverse-frag whole fake)
                        if (!WinDivertSend(wd_handle_, fake_pkt.data(),
                                          static_cast<UINT>(fake_pkt.size()), &sent, &addr)) {
                            DWORD wd_err = GetLastError();
                            if (wd_err != ERROR_HOST_UNREACHABLE && wd_err != ERROR_NETWORK_UNREACHABLE) {
                                log("WinDivertSend (reverse-frag/fake) failed: err=" + std::to_string(wd_err));
                            }
                        }
                        total_sent += sent;
                        {
                            std::lock_guard<std::mutex> lock(stats_mutex);
                            stats.fake_packets_sent++;
                        }
                    }
                }

                // Send real segments in REVERSE order
                for (int i = static_cast<int>(segments.size()) - 1; i >= 0; i--) {
                    const auto& seg = segments[static_cast<size_t>(i)];
                    auto real_pkt = build_segment(seg.offset, seg.length,
                                                  seg_seq[static_cast<size_t>(i)],
                                                  orig_ttl, false, false);
                    // === Module delay hook (reverse-frag mode real segment) ===
                    {
                        ModuleHooks hooks_snap;
                        { std::lock_guard<std::mutex> lk(hooks_mutex_); hooks_snap = hooks_; }
                        if (hooks_snap.get_send_delay_us) {
                            int64_t delay_us = hooks_snap.get_send_delay_us(
                                real_pkt.data(), static_cast<uint32_t>(real_pkt.size()));
                            if (delay_us > 0 && delay_us < 10000000) {
                                std::this_thread::sleep_for(std::chrono::microseconds(delay_us));
                            }
                        }
                    }
                    UINT sent = 0;
                    // CRIT-1: check return value (reverse-frag real segment)
                    if (!WinDivertSend(wd_handle_, real_pkt.data(),
                                      static_cast<UINT>(real_pkt.size()), &sent, &addr)) {
                        DWORD wd_err = GetLastError();
                        if (wd_err != ERROR_HOST_UNREACHABLE && wd_err != ERROR_NETWORK_UNREACHABLE) {
                            log("WinDivertSend (reverse-frag/real) failed: err=" + std::to_string(wd_err));
                            stats.send_errors++;
                        }
                    }
                    total_sent += sent;
                }

            } else {
                // === NORMAL (non-disorder) MODE ===
                // Send segments in order, with optional fake packets before each.
                // zapret "fake,multisplit" pattern:
                //   For each segment:
                //     1. Send FAKE (low TTL)
                //     2. Send REAL segment

                uint32_t seq_cursor = orig_seq;

                for (size_t i = 0; i < segments.size(); i++) {
                    const auto& seg = segments[i];

                    // Send fake(s) before real segment
                    if (effective_cfg.enable_fake_packet) {
                        for (int r = 0; r < effective_cfg.fake_repeats; r++) {
                            auto fake_pkt = build_fake(seg.offset, seg.length, seq_cursor);
                            UINT sent = 0;
                            // CRIT-1: check return value (normal/fake)
                            if (!WinDivertSend(wd_handle_, fake_pkt.data(),
                                              static_cast<UINT>(fake_pkt.size()), &sent, &addr)) {
                                DWORD wd_err = GetLastError();
                                if (wd_err != ERROR_HOST_UNREACHABLE && wd_err != ERROR_NETWORK_UNREACHABLE) {
                                    log("WinDivertSend (normal/fake) failed: err=" + std::to_string(wd_err));
                                }
                            }
                            total_sent += sent;
                            {
                                std::lock_guard<std::mutex> lock(stats_mutex);
                                stats.fake_packets_sent++;
                            }
                        }
                    }

                    // Send the real segment
                    auto real_pkt = build_segment(seg.offset, seg.length,
                                                  seq_cursor, orig_ttl, false, false);
                    // === Module delay hook (normal mode real segment) ===
                    {
                        ModuleHooks hooks_snap;
                        { std::lock_guard<std::mutex> lk(hooks_mutex_); hooks_snap = hooks_; }
                        if (hooks_snap.get_send_delay_us) {
                            int64_t delay_us = hooks_snap.get_send_delay_us(
                                real_pkt.data(), static_cast<uint32_t>(real_pkt.size()));
                            if (delay_us > 0 && delay_us < 10000000) {
                                std::this_thread::sleep_for(std::chrono::microseconds(delay_us));
                            }
                        }
                    }
                    UINT sent = 0;
                    // CRIT-1: check return value (normal/real segment)
                    if (!WinDivertSend(wd_handle_, real_pkt.data(),
                                      static_cast<UINT>(real_pkt.size()), &sent, &addr)) {
                        DWORD wd_err = GetLastError();
                        if (wd_err != ERROR_HOST_UNREACHABLE && wd_err != ERROR_NETWORK_UNREACHABLE) {
                            log("WinDivertSend (normal/real) failed: err=" + std::to_string(wd_err));
                            stats.send_errors++;
                        }
                    }
                    total_sent += sent;

                    seq_cursor += static_cast<uint32_t>(seg.length);
                }
            }

            {
                std::lock_guard<std::mutex> lock(stats_mutex);
                stats.packets_fragmented++;
                stats.bytes_sent += static_cast<uint64_t>(total_sent);
            }

            // === Module post-processing hook ===
            {
                ModuleHooks hooks_snap;
                { std::lock_guard<std::mutex> lk(hooks_mutex_); hooks_snap = hooks_; }
                if (hooks_snap.post_process) {
                    hooks_snap.post_process(packet, static_cast<uint32_t>(packet_len));
                }
            }

            log("WinDivert: " +
                std::string(effective_cfg.enable_disorder ? "disorder" :
                           effective_cfg.enable_reverse_frag ? "reverse-frag" : "split") +
                (effective_cfg.enable_fake_packet ? "+fake" : "") +
                " TLS CH (" + std::to_string(payload_len) + " bytes -> " +
                std::to_string(segments.size()) + " segments" +
                (effective_cfg.enable_fake_packet ? ", ttl=" + std::to_string(effective_cfg.fake_ttl) : "") +
                (effective_cfg.enable_autottl ? ", autottl" : "") +
                ")");
        }

        // Cleanup
        if (wd_handle_ && wd_handle_ != INVALID_HANDLE_VALUE) {
            WinDivertClose(wd_handle_);
            wd_handle_ = nullptr;
        }
    }

    void cleanup_windivert() {
        if (wd_handle_ && wd_handle_ != INVALID_HANDLE_VALUE) {
            WinDivertClose(wd_handle_);
            wd_handle_ = nullptr;
        }
    }
#endif // HAVE_WINDIVERT && _WIN32

#if defined(HAVE_NFQUEUE) && !defined(_WIN32)
    struct nfq_handle* nfq_h = nullptr;
    struct nfq_q_handle* nfq_qh = nullptr;
    int m_nfq_fd = -1;

    static int nfq_callback(struct nfq_q_handle* qh, struct nfgenmsg*,
                           struct nfq_data* nfa, void* data) {
        Impl* self = static_cast<Impl*>(data);
        struct nfqnl_msg_packet_hdr* ph = nfq_get_msg_packet_hdr(nfa);
        if (!ph) return -1;
        uint32_t id = ntohl(ph->packet_id);

        unsigned char* payload;
        int payload_len = nfq_get_payload(nfa, &payload);
        if (payload_len < 0) {
            return nfq_set_verdict(qh, id, NF_ACCEPT, 0, nullptr);
        }

        {
            std::lock_guard<std::mutex> lock(self->stats_mutex);
            self->stats.packets_total++;
        }

        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, nullptr);
    }

    bool init_nfqueue() {
        DPIConfig cfg_snap = snapshot_config();
        nfq_h = nfq_open();
        if (!nfq_h) return false;
        nfq_unbind_pf(nfq_h, AF_INET);
        if (nfq_bind_pf(nfq_h, AF_INET) < 0) {
            nfq_close(nfq_h); nfq_h = nullptr;
            return false;
        }
        nfq_qh = nfq_create_queue(nfq_h, cfg_snap.nfqueue_num, &Impl::nfq_callback, this);
        if (!nfq_qh) {
            nfq_close(nfq_h); nfq_h = nullptr;
            return false;
        }
        nfq_set_mode(nfq_qh, NFQNL_COPY_PACKET, 0xffff);
        m_nfq_fd = nfq_fd(nfq_h);
        return true;
    }

    void nfqueue_loop() {
        char buf[65536];
        while (running) {
            int rv = recv(m_nfq_fd, buf, sizeof(buf), 0);
            if (rv >= 0) nfq_handle_packet(nfq_h, buf, rv);
        }
    }

    void cleanup_nfqueue() {
        if (nfq_qh) { nfq_destroy_queue(nfq_qh); nfq_qh = nullptr; }
        if (nfq_h) { nfq_close(nfq_h); nfq_h = nullptr; }
        m_nfq_fd = -1;
    }
#endif

    void log(const std::string& msg) {
        if (log_callback) {
            log_callback(msg);
        } else {
            std::clog << "[DPI] " << msg << std::endl;
        }
    }
};

void apply_preset(DPIPreset preset, DPIConfig& config) {
    switch (preset) {
    case DPIPreset::RUNET_SOFT:
#ifdef _WIN32
        config.mode = DPIMode::DRIVER;
#else
        config.mode = DPIMode::PROXY;
#endif
        config.enable_tcp_split = true;
        config.split_at_sni = true;
        config.split_position = 2;
        config.fragment_size = 8;
        config.fragment_offset = 2;
        config.enable_fake_packet = false;
        config.enable_disorder = false;
        config.enable_oob_data = false;
        break;
    case DPIPreset::RUNET_STRONG:
#ifdef _WIN32
        config.mode = DPIMode::DRIVER;
#else
        config.mode = DPIMode::PROXY;
#endif
        config.enable_tcp_split = true;
        config.split_at_sni = true;
        config.split_position = 1;
        config.fragment_size = 1;
        config.fragment_offset = 1;
        config.enable_fake_packet = true;
        config.enable_disorder = true;
        config.enable_oob_data = true;
        config.enable_noise = true;
        config.noise_size = 256;
        config.enable_host_case = true;
        config.fake_host = "google.com";
        config.fake_ttl = 2;
        break;
    case DPIPreset::RUNET_TSPU:
        // Designed for TSPU (government DPI) bypass on home/wired ISPs.
        // Mimics zapret: fake,multidisorder --split-pos=1,midsld
        // --fooling=badseq,md5sig --ttl=1 --repeats=1
#ifdef _WIN32
        config.mode = DPIMode::DRIVER;
#else
        config.mode = DPIMode::PROXY;
#endif
        config.enable_tcp_split = true;
        config.split_at_sni = true;
        config.split_position = 1;
        config.fragment_size = 1;
        config.fragment_offset = 0;
        config.enable_fake_packet = true;
        config.fake_ttl = 1;
        config.fake_fooling = 2 | 4;   // badseq(2) + md5sig(4)
        config.fake_repeats = 1;
        config.enable_disorder = true;  // send segments in reverse order
        config.disorder_delay_ms = 0;
        config.enable_multi_layer_split = true; // split at pos 1 AND midsld
        config.enable_oob_data = false;
        config.enable_noise = false;
        config.enable_host_case = false;
        config.fake_host.clear();
        config.enable_pattern_obfuscation = false;
        config.enable_timing_jitter = false;
        config.enable_reverse_frag = false;
        config.enable_autottl = false;
        break;

    case DPIPreset::BEELINE_MOBILE:
        // Beeline mobile: DNS hijacking + stricter DPI.
        // Key: --reverse-frag, higher TTL (4-6), badseq+badsum fooling.
        // User MUST change DNS to 8.8.8.8/1.1.1.1 (Beeline replaces DNS).
        // Based on: GoodbyeDPI "-1 --reverse-frag" Krasnodar reports,
        //   ByeDPI "-o1 -o25+s -T3 -At" confirmed Beeline 4G.
        // IMPORTANT: enable_disorder MUST be false so reverse-frag path
        //   is taken in windivert_loop (disorder has higher priority).
#ifdef _WIN32
        config.mode = DPIMode::DRIVER;
#else
        config.mode = DPIMode::PROXY;
#endif
        config.enable_tcp_split = true;
        config.split_at_sni = true;
        config.split_position = 1;
        config.fragment_size = 2;
        config.fragment_offset = 0;
        config.enable_fake_packet = true;
        config.fake_ttl = 4;             // higher TTL for mobile hops
        config.fake_fooling = 1 | 2;     // badsum(1) + badseq(2)
        config.fake_repeats = 6;          // More repeats for googlevideo/YouTube
        config.enable_disorder = false;  // MUST be false for reverse-frag to work
        config.disorder_delay_ms = 0;
        config.enable_multi_layer_split = true;
        config.enable_reverse_frag = true;  // KEY: reverse fragment order
        config.enable_oob_data = false;
        config.enable_noise = false;
        config.enable_host_case = false;
        config.fake_host.clear();
        config.enable_pattern_obfuscation = false;
        config.enable_timing_jitter = false;
        config.enable_autottl = true;    // auto-detect optimal TTL
        config.autottl_delta = 1;
        config.autottl_min = 3;
        config.autottl_max = 10;
        break;

    case DPIPreset::MTS_MOBILE:
        // MTS mobile: moderately strict DPI, ttl=4-8 works.
        // Based on: MTS Moscow "-9 -e1 -q", MTS Perm "-1",
        //   MTS Saratov confirmed working with auto-ttl.
#ifdef _WIN32
        config.mode = DPIMode::DRIVER;
#else
        config.mode = DPIMode::PROXY;
#endif
        config.enable_tcp_split = true;
        config.split_at_sni = true;
        config.split_position = 1;
        config.fragment_size = 2;
        config.fragment_offset = 0;
        config.enable_fake_packet = true;
        config.fake_ttl = 6;
        config.fake_fooling = 2 | 4;     // badseq(2) + md5sig(4)
        config.fake_repeats = 1;
        config.enable_disorder = true;
        config.disorder_delay_ms = 0;
        config.enable_multi_layer_split = true;
        config.enable_reverse_frag = false;
        config.enable_oob_data = false;
        config.enable_noise = false;
        config.enable_host_case = false;
        config.fake_host.clear();
        config.enable_pattern_obfuscation = false;
        config.enable_timing_jitter = false;
        config.enable_autottl = true;
        config.autottl_delta = 1;
        config.autottl_min = 3;
        config.autottl_max = 12;
        break;

    case DPIPreset::MEGAFON_MOBILE:
        // Megafon mobile: uses OOB data + split + fake.
        // Based on: Megafon reports with multi-split strategies,
        //   "-n google.com -Qr ... -s1:5+sm" patterns.
#ifdef _WIN32
        config.mode = DPIMode::DRIVER;
#else
        config.mode = DPIMode::PROXY;
#endif
        config.enable_tcp_split = true;
        config.split_at_sni = true;
        config.split_position = 1;
        config.fragment_size = 2;
        config.fragment_offset = 0;
        config.enable_fake_packet = true;
        config.fake_ttl = 6;
        config.fake_fooling = 2;         // badseq(2)
        config.fake_repeats = 1;
        config.enable_disorder = true;
        config.disorder_delay_ms = 0;
        config.enable_multi_layer_split = true;
        config.enable_reverse_frag = false;
        config.enable_oob_data = true;   // OOB data effective on Megafon
        config.enable_noise = false;
        config.enable_host_case = false;
        config.fake_host.clear();
        config.enable_pattern_obfuscation = false;
        config.enable_timing_jitter = false;
        config.enable_autottl = true;
        config.autottl_delta = 1;
        config.autottl_min = 3;
        config.autottl_max = 12;
        break;

    case DPIPreset::TELE2_MOBILE:
        // Tele2 mobile: similar to MTS, confirmed working with
        //   "-s0 -o1 -d1 -r1+s" and DNS 8.8.8.8.
#ifdef _WIN32
        config.mode = DPIMode::DRIVER;
#else
        config.mode = DPIMode::PROXY;
#endif
        config.enable_tcp_split = true;
        config.split_at_sni = true;
        config.split_position = 1;
        config.fragment_size = 2;
        config.fragment_offset = 0;
        config.enable_fake_packet = true;
        config.fake_ttl = 5;
        config.fake_fooling = 2 | 4;     // badseq(2) + md5sig(4)
        config.fake_repeats = 1;
        config.enable_disorder = true;
        config.disorder_delay_ms = 0;
        config.enable_multi_layer_split = true;
        config.enable_reverse_frag = false;
        config.enable_oob_data = false;
        config.enable_noise = false;
        config.enable_host_case = false;
        config.fake_host.clear();
        config.enable_pattern_obfuscation = false;
        config.enable_timing_jitter = false;
        config.enable_autottl = true;
        config.autottl_delta = 1;
        config.autottl_min = 3;
        config.autottl_max = 12;
        break;

    case DPIPreset::MOBILE_UNIVERSAL:
        // Universal mobile preset: conservative multi-method approach.
        // Works on most operators by combining multiple fooling methods.
#ifdef _WIN32
        config.mode = DPIMode::DRIVER;
#else
        config.mode = DPIMode::PROXY;
#endif
        config.enable_tcp_split = true;
        config.split_at_sni = true;
        config.split_position = 1;
        config.fragment_size = 2;
        config.fragment_offset = 0;
        config.enable_fake_packet = true;
        config.fake_ttl = 6;
        config.fake_fooling = 1 | 2 | 4; // badsum(1) + badseq(2) + md5sig(4)
        config.fake_repeats = 2;          // send fake twice for reliability
        config.enable_disorder = false;  // Must be false so reverse-frag path is taken
                                          // (same pattern as BEELINE_MOBILE: disorder has
                                          //  higher priority in windivert_loop and would
                                          //  silently suppress reverse-frag if left true)
        config.disorder_delay_ms = 0;
        config.enable_multi_layer_split = true;
        config.enable_reverse_frag = true;
        config.enable_oob_data = false;
        config.enable_noise = false;
        config.enable_host_case = false;
        config.fake_host.clear();
        config.enable_pattern_obfuscation = false;
        config.enable_timing_jitter = false;
        config.enable_autottl = true;
        config.autottl_delta = 1;
        config.autottl_min = 3;
        config.autottl_max = 15;
        break;

    case DPIPreset::AUTOPROBE:
        // Auto-probe mode: start with MOBILE_UNIVERSAL config,
        // but enable autoprobe to cycle through strategies if it fails.
        apply_preset(DPIPreset::MOBILE_UNIVERSAL, config);
        config.enable_autoprobe = true;
        config.autoprobe_timeout_sec = 8;
        config.autoprobe_max_strategies = 10;
        break;
    case DPIPreset::NONE:
    default:
        break;
    }
}

DPIPreset preset_from_string(const std::string& name) {
    auto lower = to_lower_copy(name);
    if (lower == "runet-soft" || lower == "runet_soft" || lower == "runetsoft") return DPIPreset::RUNET_SOFT;
    if (lower == "runet-strong" || lower == "runet_strong" || lower == "runetstrong") return DPIPreset::RUNET_STRONG;
    if (lower == "runet-tspu" || lower == "runet_tspu" || lower == "runettspu" || lower == "tspu") return DPIPreset::RUNET_TSPU;
    if (lower == "beeline" || lower == "beeline-mobile" || lower == "beeline_mobile") return DPIPreset::BEELINE_MOBILE;
    if (lower == "mts" || lower == "mts-mobile" || lower == "mts_mobile") return DPIPreset::MTS_MOBILE;
    if (lower == "megafon" || lower == "megafon-mobile" || lower == "megafon_mobile") return DPIPreset::MEGAFON_MOBILE;
    if (lower == "tele2" || lower == "tele2-mobile" || lower == "tele2_mobile" || lower == "t2") return DPIPreset::TELE2_MOBILE;
    if (lower == "mobile" || lower == "mobile-universal" || lower == "mobile_universal" || lower == "universal") return DPIPreset::MOBILE_UNIVERSAL;
    if (lower == "auto" || lower == "autoprobe" || lower == "auto-probe" || lower == "auto_probe") return DPIPreset::AUTOPROBE;
    return DPIPreset::NONE;
}

const char* preset_to_string(DPIPreset preset) {
    switch (preset) {
    case DPIPreset::RUNET_SOFT:        return "RuNet-Soft";
    case DPIPreset::RUNET_STRONG:      return "RuNet-Strong";
    case DPIPreset::RUNET_TSPU:        return "RuNet-TSPU";
    case DPIPreset::BEELINE_MOBILE:    return "Beeline-Mobile";
    case DPIPreset::MTS_MOBILE:        return "MTS-Mobile";
    case DPIPreset::MEGAFON_MOBILE:    return "Megafon-Mobile";
    case DPIPreset::TELE2_MOBILE:      return "Tele2-Mobile";
    case DPIPreset::MOBILE_UNIVERSAL:  return "Mobile-Universal";
    case DPIPreset::AUTOPROBE:         return "AutoProbe";
    case DPIPreset::NONE:
    default: return "Custom";
    }
}

DPIBypass::DPIBypass() : impl_(std::make_unique<Impl>()) {}
DPIBypass::~DPIBypass() { shutdown(); }

bool DPIBypass::initialize(const DPIConfig& config) {
    {
        std::lock_guard<std::mutex> lock(impl_->config_mutex);
        impl_->config = config;
    }

    // R9-C05: Warn about auto-TTL ineffectiveness on Windows (WinDivert limitation)
#ifdef _WIN32
    if (config.enable_autottl) {
        std::cerr << "[!] Warning: Auto-TTL is ineffective on Windows (WinDivert intercepts "
                     "outbound packets before routing, observed TTL is local OS default 128).\n";
        std::cerr << "[!] Consider setting fake_ttl manually or using PROXY mode.\n";
    }
#endif

    std::string mode_str;
    switch (config.mode) {
        case DPIMode::DRIVER:     mode_str = "driver";     break;
        case DPIMode::PROXY:      mode_str = "proxy";      break;
        case DPIMode::PASSIVE:    mode_str = "passive";    break;
        case DPIMode::WS_TUNNEL:  mode_str = "ws_tunnel";  break;
        default:                  mode_str = "unknown";    break;
    }
    impl_->log("Initialize DPI (mode=" + mode_str +
              ", listen_port=" + std::to_string(config.listen_port) +
              ", fragment_size=" + std::to_string(config.fragment_size) + ")");

    // Phase 2: Initialize TLS fingerprint for all modes
    impl_->init_tls_fingerprint();

    // Phase 2: Auto-detect when to enable advanced bypass
    bool needs_advanced = config.enable_pattern_obfuscation ||
                          config.enable_decoy_sni ||
                          config.enable_multi_layer_split ||
                          config.enable_adaptive_fragmentation ||
                          config.enable_timing_jitter ||
                          config.enable_tcp_options_randomization;

    if (config.enable_fake_packet && config.enable_tcp_split &&
        config.enable_noise && config.enable_disorder) {
        needs_advanced = true;
    }

    if (needs_advanced && !impl_->base_only) {
        impl_->init_advanced_bypass();
    }

    return true;
}

bool DPIBypass::start() {
#if defined(HAVE_NFQUEUE) && !defined(_WIN32)
    if (impl_->snapshot_config().mode == DPIMode::DRIVER) {
        if (!impl_->init_nfqueue()) return false;
        impl_->running = true;
        impl_->worker_thread = std::thread(&Impl::nfqueue_loop, impl_.get());
        impl_->log("DPI bypass started (driver mode via nfqueue, queue=" +
                  std::to_string(impl_->snapshot_config().nfqueue_num) + ")");
        return true;
    }
#endif

    DPIConfig cfg_snap = impl_->snapshot_config();

#if defined(HAVE_WINDIVERT) && defined(_WIN32)
    if (cfg_snap.mode == DPIMode::DRIVER) {
        if (!impl_->init_windivert()) return false;
        impl_->running = true;
        impl_->worker_thread = std::thread(&Impl::windivert_loop, impl_.get());
        impl_->log("DPI bypass started (WinDivert driver mode)" +
                  std::string(impl_->advanced_enabled_.load(std::memory_order_acquire) ? " + Advanced" : ""));
        return true;
    }
#endif

    if (cfg_snap.mode == DPIMode::PROXY) {
        impl_->running = true;
        impl_->worker_thread = std::thread(&Impl::proxy_listen_loop, impl_.get());
        impl_->log("DPI bypass started (TCP proxy mode" +
                  std::string(impl_->advanced_enabled_.load(std::memory_order_acquire) ? " + Advanced" : "") + ")");
        return true;
    }

#ifdef HAVE_LIBWEBSOCKETS
    if (cfg_snap.mode == DPIMode::WS_TUNNEL) {
        if (cfg_snap.ws_server_url.empty()) {
            impl_->log("WS_TUNNEL: ws_server_url is not configured");
            return false;
        }
        if (!impl_->start_ws_tunnel()) {
            return false;
        }
        impl_->log("DPI bypass started (WebSocket tunnel mode -> " +
                   cfg_snap.ws_server_url + ")");
        return true;
    }
#endif

    impl_->running = true;
    impl_->log("DPI bypass started (passive mode - nfqueue/proxy not active)");
    return true;
}

void DPIBypass::stop() {
    impl_->running = false;
#ifdef HAVE_LIBWEBSOCKETS
    impl_->stop_ws_tunnel();
#endif

    if (impl_->advanced_bypass_) {
        impl_->advanced_bypass_->stop();
    }
    if (impl_->worker_thread.joinable()) impl_->worker_thread.join();

    // HIGH-7: Wait for all active proxy connection threads to finish before
    // destroying Impl members (use-after-free mitigation).
    // The thread_pool_ shutdown() blocks until all queued and in-flight tasks
    // complete, which includes all handle_proxy_connection() invocations.
    // This ensures no connection thread accesses Impl fields after destruction.
    if (impl_->thread_pool_) {
        impl_->thread_pool_->shutdown();
    }

    // R12-M02 / R13-C03: Proper thread tracking - join all active threads
    // R17-FIX-03: Thread IDs are tracked; actual thread objects are joined in handle_proxy_connection
    // Just clear the tracking set - threads are joined where created
    {
        std::lock_guard<std::mutex> lock(impl_->active_threads_mutex_);
        impl_->active_thread_ids_.clear();
    }
    
    // Belt-and-suspenders: spin-wait up to 500ms if active_connections_ hasn't
    // reached zero yet (handles detached/legacy paths that don't use the pool).
    // This is a fallback for any threads not tracked in active_threads_.
    {
        int spin = 0;
        while (impl_->active_connections_.load() > 0 && spin < 50) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            ++spin;
        }
    }

#if defined(HAVE_WINDIVERT) && defined(_WIN32)
    impl_->cleanup_windivert();
#endif
#if defined(HAVE_NFQUEUE) && !defined(_WIN32)
    impl_->cleanup_nfqueue();
#endif
    impl_->log("DPI bypass stopped");
}

void DPIBypass::shutdown() { stop(); }
bool DPIBypass::is_running() const { return impl_->running; }

DPIStats DPIBypass::get_stats() const {
    std::lock_guard<std::mutex> lock(impl_->stats_mutex);
    return impl_->stats;
}

void DPIBypass::set_log_callback(LogCallback cb) {
    impl_->log_callback = [cb](const std::string& msg) { if (cb) cb(DPILogLevel::INFO, msg); };
}

void DPIBypass::set_base_only(bool v) {
    impl_->base_only = v;
}

DPIConfig DPIBypass::get_config() const {
    // FIX #39: use config_mutex instead of stats_mutex
    std::lock_guard<std::mutex> lock(impl_->config_mutex);
    return impl_->config;
}

bool DPIBypass::update_config(const DPIConfig& config) {
    auto err = config.validate();
    if (err != ValidationError::NONE) return false;
    DPIConfig old_cfg;
    {
        // FIX #39: use config_mutex for config writes
        std::lock_guard<std::mutex> lock(impl_->config_mutex);
        old_cfg = impl_->config;
        impl_->config = config;
    }
    notify_config_change(old_cfg, config);
    return true;
}

void DPIBypass::reset_stats() {
    std::lock_guard<std::mutex> lock(impl_->stats_mutex);
    impl_->stats.reset();
}

void DPIBypass::set_config_change_callback(ConfigChangeCallback callback) {
    std::lock_guard<std::mutex> lock(config_cb_mutex_);
    config_change_callback_ = std::move(callback);
}

void DPIBypass::set_transform_callback(TransformCallback callback) {
    // DPI-FIX-4: Forward directly to Impl; outer dead members removed.
    impl_->set_transform_cb(std::move(callback));
}

void DPIBypass::set_module_hooks(const ModuleHooks& hooks) {
    std::lock_guard<std::mutex> lock(impl_->hooks_mutex_);
    impl_->hooks_ = hooks;
}

void DPIBypass::set_zapret_chains(std::vector<ZapretChain> chains) {
    impl_->set_zapret_chains(std::move(chains));
}

void DPIBypass::log(DPILogLevel level, const std::string& message) {
    std::lock_guard<std::mutex> lock(log_mutex_);
    if (log_callback_) {
        log_callback_(level, message);
    } else {
        impl_->log(message);
    }
}

void DPIBypass::notify_config_change(const DPIConfig& old_cfg, const DPIConfig& new_cfg) {
    std::lock_guard<std::mutex> lock(config_cb_mutex_);
    if (config_change_callback_) {
        config_change_callback_(old_cfg, new_cfg);
    }
}

} // namespace DPI
} // namespace ncp
