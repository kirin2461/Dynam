#include "ncp_dpi.hpp"
#include "ncp_dpi_advanced.hpp"
#include "ncp_tls_fingerprint.hpp"
#include "ncp_ech.hpp"
#include "ncp_thread_pool.hpp"
#include <thread>
#include <mutex>
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
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <netinet/ip.h>
    #include <netinet/tcp.h>
    #include <arpa/inet.h>
    #include <unistd.h>
    #include <netdb.h>
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
    if (!data || len < 5 + 4) return -1;
    if (data[0] != 0x16 || data[1] != 0x03) return -1;

    size_t pos = 5;
    if (pos + 4 > len) return -1;

    uint8_t handshake_type = data[pos];
    if (handshake_type != 0x01) return -1;

    uint32_t hs_len = (static_cast<uint32_t>(data[pos + 1]) << 16) |
                      (static_cast<uint32_t>(data[pos + 2]) << 8) |
                      static_cast<uint32_t>(data[pos + 3]);
    (void)hs_len;
    pos += 4;

    if (pos + 2 + 32 + 1 > len) return -1;
    pos += 2; // client_version
    pos += 32; // random

    uint8_t session_id_len = data[pos];
    pos += 1;
    if (pos + session_id_len > len) return -1;
    pos += session_id_len;

    if (pos + 2 > len) return -1;
    uint16_t cipher_suites_len = (static_cast<uint16_t>(data[pos]) << 8) |
                                 static_cast<uint16_t>(data[pos + 1]);
    pos += 2;
    if (pos + cipher_suites_len > len) return -1;
    pos += cipher_suites_len;

    if (pos + 1 > len) return -1;
    uint8_t compression_methods_len = data[pos];
    pos += 1;
    if (pos + compression_methods_len > len) return -1;
    pos += compression_methods_len;

    if (pos + 2 > len) return -1;
    uint16_t extensions_len = (static_cast<uint16_t>(data[pos]) << 8) |
                              static_cast<uint16_t>(data[pos + 1]);
    pos += 2;

    size_t exts_end = pos + extensions_len;
    if (exts_end > len) exts_end = len;

    while (pos + 4 <= exts_end) {
        uint16_t ext_type = (static_cast<uint16_t>(data[pos]) << 8) |
                            static_cast<uint16_t>(data[pos + 1]);
        uint16_t ext_data_len = (static_cast<uint16_t>(data[pos + 2]) << 8) |
                                static_cast<uint16_t>(data[pos + 3]);
        pos += 4;
        if (pos + ext_data_len > exts_end) break;

        if (ext_type == 0x0000) {
            size_t sni_pos = pos;
            if (sni_pos + 2 > exts_end) return -1;
            uint16_t list_len = (static_cast<uint16_t>(data[sni_pos]) << 8) |
                                static_cast<uint16_t>(data[sni_pos + 1]);
            sni_pos += 2;
            if (sni_pos + list_len > exts_end || list_len < 3) return -1;
            uint8_t name_type = data[sni_pos];
            (void)name_type;
            sni_pos += 1;
            if (sni_pos + 2 > exts_end) return -1;
            uint16_t host_len = (static_cast<uint16_t>(data[sni_pos]) << 8) |
                                static_cast<uint16_t>(data[sni_pos + 1]);
            sni_pos += 2;
            if (sni_pos + host_len > exts_end) return -1;
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

    DPIStats stats;
    mutable std::mutex stats_mutex;
    std::thread worker_thread;
    std::function<void(const std::string&)> log_callback;

    // === Phase 2: Advanced DPI bypass integration ===
    std::unique_ptr<AdvancedDPIBypass> advanced_bypass_;
    bool advanced_enabled_ = false;

    // === Phase 2: TLS Fingerprint for realistic ClientHello ===
    std::unique_ptr<ncp::TLSFingerprint> tls_fingerprint_;

    // === Thread pool for connection handling ===
    std::unique_ptr<ncp::ThreadPool> thread_pool_;
    std::atomic<int> active_connections_{0};
    static constexpr int MAX_CONNECTIONS = 256;

    // === WebSocket Tunnel state (Phase 3) ===
#ifdef HAVE_LIBWEBSOCKETS
    std::unique_ptr<ncp::WSTunnel> ws_tunnel_;
    // Active client socket for WS tunnel mode (single-client for now)
    // Protected by ws_client_mutex_
    std::mutex ws_client_mutex_;
    SOCKET ws_active_client_ = INVALID_SOCKET;
#endif
    // =========================================================
    // Phase 2: Initialize AdvancedDPIBypass from DPIConfig
    // Phase 3C: Forward TLSFingerprint to advanced bypass
    // =========================================================
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

        advanced_bypass_ = std::make_unique<AdvancedDPIBypass>();
        advanced_bypass_->set_log_callback([this](const std::string& msg) {
            log("[Advanced] " + msg);
        });

        // Phase 3C: Set TLS fingerprint BEFORE initialize so it's available
        // during initialization, and again after in case initialize() recreates
        // internal TLSManipulator
        if (tls_fingerprint_) {
            advanced_bypass_->set_tls_fingerprint(tls_fingerprint_.get());
        }

        if (advanced_bypass_->initialize(adv_config)) {
            // Forward fingerprint again after initialize() creates TLSManipulator
            if (tls_fingerprint_) {
                advanced_bypass_->set_tls_fingerprint(tls_fingerprint_.get());
            }
            advanced_bypass_->start();
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

    // =========================================================
    // Phase 2: Initialize TLS Fingerprint
    // =========================================================
    void init_tls_fingerprint() {
        tls_fingerprint_ = std::make_unique<ncp::TLSFingerprint>(ncp::BrowserType::CHROME);
        if (!config.target_host.empty()) {
            tls_fingerprint_->set_sni(config.target_host);
        }
        log("TLS fingerprint initialized (profile=Chrome, target=" + config.target_host + ")");
    }

    // === Proxy mode state ===
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

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(config.listen_port);
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
        thread_pool_ = std::make_unique<ncp::ThreadPool>(num_threads);
        log("DPI proxy listening on 127.0.0.1:" + std::to_string(config.listen_port));

        while (running) {
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

            {
                std::lock_guard<std::mutex> lock(stats_mutex);
                stats.connections_handled++;
            }

            thread_pool_->submit([this, client_sock]() { handle_proxy_connection(client_sock); });
        }

        CLOSE_SOCKET(listen_sock);

#ifdef _WIN32
        WSACleanup();
#endif
    }

    void handle_proxy_connection(SOCKET client_sock) {
        if (config.target_host.empty()) {
            log("DPI proxy: target_host is empty, closing client connection");
            CLOSE_SOCKET(client_sock);
            return;
        }

        addrinfo hints{};
        std::memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;

        addrinfo* result = nullptr;
        if (getaddrinfo(config.target_host.c_str(), nullptr, &hints, &result) != 0 || !result) {
            log("DPI proxy: failed to resolve target host: " + config.target_host);
            CLOSE_SOCKET(client_sock);
            return;
        }

        sockaddr_in remote_addr{};
        remote_addr.sin_family = AF_INET;
        remote_addr.sin_port = htons(config.target_port);
        remote_addr.sin_addr = reinterpret_cast<sockaddr_in*>(result->ai_addr)->sin_addr;

        freeaddrinfo(result);

        SOCKET server_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (server_sock == INVALID_SOCKET) {
            log("DPI proxy: failed to create upstream socket");
            CLOSE_SOCKET(client_sock);
            return;
        }

        // Phase 2: Set TCP_NODELAY to prevent Nagle from coalescing fragments
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

        std::thread t_cs(&Impl::pipe_client_to_server, this, client_sock, server_sock);
        std::thread t_sc(&Impl::pipe_server_to_client, this, server_sock, client_sock);

        t_cs.join();
        t_sc.join();

        CLOSE_SOCKET(client_sock);
        CLOSE_SOCKET(server_sock);
    }

    void pipe_client_to_server(SOCKET client_sock, SOCKET server_sock) {
        std::vector<uint8_t> buffer(8192);
        bool client_hello_processed = false;

        while (running) {
            int received = recv(client_sock,
                                reinterpret_cast<char*>(buffer.data()),
                                static_cast<int>(buffer.size()), 0);
            if (received <= 0) break;

            {
                std::lock_guard<std::mutex> lock(stats_mutex);
                stats.bytes_received += static_cast<uint64_t>(received);
                stats.packets_total++;
            }

            bool is_ch = false;
            if (!client_hello_processed &&
                is_tls_client_hello(buffer.data(), static_cast<size_t>(received))) {
                is_ch = true;
                client_hello_processed = true;
            }

            // Phase 2: Route ClientHello through AdvancedDPIBypass
            if (is_ch && advanced_enabled_ && advanced_bypass_) {
                send_via_advanced(server_sock, buffer.data(),
                                 static_cast<size_t>(received));
            } else {
                send_with_fragmentation(server_sock, buffer.data(),
                                        static_cast<size_t>(received), is_ch);
            }
        }
    }

    void pipe_server_to_client(SOCKET server_sock, SOCKET client_sock) {
        std::vector<uint8_t> buffer(8192);

        while (running) {
            int received = recv(server_sock,
                                reinterpret_cast<char*>(buffer.data()),
                                static_cast<int>(buffer.size()), 0);
            if (received <= 0) break;

            {
                std::lock_guard<std::mutex> lock(stats_mutex);
                stats.bytes_received += static_cast<uint64_t>(received);
                stats.packets_total++;
            }

            // Phase 2: Incoming data through advanced deobfuscation if active
            if (advanced_enabled_ && advanced_bypass_) {
                auto deobf = advanced_bypass_->process_incoming(
                    buffer.data(), static_cast<size_t>(received));
                if (!deobf.empty()) {
                    send_raw(client_sock, deobf.data(), deobf.size());
                }
            } else {
                send_with_fragmentation(client_sock, buffer.data(),
                                        static_cast<size_t>(received), false);
            }
        }
    }

    // =========================================================
    // Phase 2: Send data through AdvancedDPIBypass pipeline
    // =========================================================
    void send_via_advanced(SOCKET sock, const uint8_t* data, size_t len) {
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

            if (i > 0 && config.enable_timing_jitter &&
                config.timing_jitter_min_us > 0) {
                uint32_t delay = config.timing_jitter_min_us +
                    randombytes_uniform(static_cast<uint32_t>(
                        config.timing_jitter_max_us - config.timing_jitter_min_us + 1));
                std::this_thread::sleep_for(std::chrono::microseconds(delay));
            } else if (i > 0 && config.enable_disorder && config.disorder_delay_ms > 0) {
                std::this_thread::sleep_for(
                    std::chrono::milliseconds(config.disorder_delay_ms));
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

    // =========================================================
    // Raw send helper (no fragmentation)
    // =========================================================
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

    void send_with_fragmentation(
        SOCKET sock,
        const uint8_t* data,
        size_t len,
        bool is_client_hello
    ) {
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

        // Noise/Junk before ClientHello
        if (is_client_hello && config.enable_noise) {
            std::vector<uint8_t> junk;
            if (!config.fake_host.empty()) {
                std::string mask = "GET / HTTP/1.1\r\nHost: " + config.fake_host + "\r\n\r\n";
                junk.assign(mask.begin(), mask.end());
            } else {
                junk.resize(config.noise_size > 0 ? config.noise_size : 64);
                for(auto& b : junk) b = static_cast<uint8_t>(randombytes_uniform(256));
            }
#ifdef IP_TTL
            int original_ttl = 64;
            socklen_t optlen = sizeof(original_ttl);
            getsockopt(sock, IPPROTO_IP, IP_TTL, reinterpret_cast<char*>(&original_ttl), &optlen);
            int low_ttl = 2;
            setsockopt(sock, IPPROTO_IP, IP_TTL, reinterpret_cast<const char*>(&low_ttl), sizeof(low_ttl));
            send_all(junk.data(), junk.size());
            setsockopt(sock, IPPROTO_IP, IP_TTL, reinterpret_cast<const char*>(&original_ttl), sizeof(original_ttl));
#else
            send_all(junk.data(), junk.size());
#endif
        }

        // Fake low-TTL probe before main ClientHello
        if (is_client_hello && config.enable_fake_packet) {
            for (int i = 0; i < (config.fake_ttl > 2 ? 2 : 1); ++i) {
                std::vector<uint8_t> fake_data = {
                    0x16, 0x03, static_cast<uint8_t>(randombytes_uniform(256) % 4),
                    static_cast<uint8_t>(randombytes_uniform(256)), static_cast<uint8_t>(randombytes_uniform(256)),
                    0x01
                };
#ifdef IP_TTL
                int original_ttl = 0;
                socklen_t optlen = static_cast<socklen_t>(sizeof(original_ttl));
                bool ttl_changed = false;
                if (getsockopt(sock, IPPROTO_IP, IP_TTL,
                               reinterpret_cast<char*>(&original_ttl), &optlen) == 0) {
                    int ttl = (config.fake_ttl > 0) ? (config.fake_ttl + i) : 2;
                    if (setsockopt(sock, IPPROTO_IP, IP_TTL,
                                   reinterpret_cast<const char*>(&ttl), sizeof(ttl)) == 0) {
                        ttl_changed = true;
                    }
                }
#endif
                send_all(fake_data.data(), fake_data.size());
                {
                    std::lock_guard<std::mutex> lock(stats_mutex);
                    stats.fake_packets_sent++;
                }
#ifdef IP_TTL
                if (ttl_changed) {
                    setsockopt(sock, IPPROTO_IP, IP_TTL,
                               reinterpret_cast<const char*>(&original_ttl), sizeof(original_ttl));
                }
#endif
                if (config.disorder_delay_ms > 0) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(config.disorder_delay_ms / 2));
                }
            }
        }

        if (!is_client_hello || !config.enable_tcp_split) {
            size_t sent = send_all(data, len);
            std::lock_guard<std::mutex> lock(stats_mutex);
            stats.bytes_sent += static_cast<uint64_t>(sent);
            return;
        }

        size_t first_len = 0;
        int sni_offset = -1;

        if (config.split_at_sni) {
            sni_offset = find_sni_hostname_offset(data, len);
        }

        if (sni_offset > 0 && static_cast<size_t>(sni_offset) < len) {
            first_len = static_cast<size_t>(sni_offset);
        } else if (config.split_position > 0 &&
                   static_cast<size_t>(config.split_position) < len) {
            first_len = static_cast<size_t>(config.split_position);
        } else {
            first_len = std::min<size_t>(len, 1);
        }

        size_t sent_total = 0;
        size_t sent_first = send_all(data, first_len);
        sent_total += sent_first;

        size_t remaining = (sent_first < len) ? (len - sent_first) : 0;

        if (remaining > 0) {
            size_t base_frag_size = (config.fragment_size > 0)
                                   ? static_cast<size_t>(config.fragment_size)
                                   : 2;
            size_t offset = 0;
            while (offset < remaining) {
                size_t jitter = randombytes_uniform(3);
                size_t current_frag = std::min(base_frag_size + jitter, remaining - offset);
                if (config.enable_disorder && config.disorder_delay_ms > 0) {
                    std::this_thread::sleep_for(
                        std::chrono::milliseconds(config.disorder_delay_ms));
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

    // =========================================================================
    // WebSocket Tunnel mode (Phase 3.4)
    // =========================================================================
#ifdef HAVE_LIBWEBSOCKETS

    /**
     * @brief Apply DPI fragmentation/obfuscation to outgoing data and return
     *        the processed buffer ready for WS tunnel transmission.
     *
     * This mirrors the logic of send_with_fragmentation() but instead of
     * sending over a TCP socket, it collects the processed segments into a
     * flat byte vector that will be pushed through WSTunnel::send().
     */
    std::vector<uint8_t> process_outgoing_for_ws(const uint8_t* data, size_t len,
                                                  bool is_client_hello) {
        std::vector<uint8_t> out;
        if (!data || len == 0) return out;

        // --- Noise / fake host preamble ---
        if (is_client_hello && config.enable_noise) {
            if (!config.fake_host.empty()) {
                std::string mask = "GET / HTTP/1.1\r\nHost: " + config.fake_host + "\r\n\r\n";
                out.insert(out.end(), mask.begin(), mask.end());
            } else {
                size_t noise_sz = config.noise_size > 0
                                    ? static_cast<size_t>(config.noise_size) : 64;
                size_t off = out.size();
                out.resize(out.size() + noise_sz);
                for (size_t i = 0; i < noise_sz; ++i)
                    out[off + i] = static_cast<uint8_t>(randombytes_uniform(256));
            }
        }

        // --- Fake TLS probe ---
        if (is_client_hello && config.enable_fake_packet) {
            int fakes = (config.fake_ttl > 2) ? 2 : 1;
            for (int i = 0; i < fakes; ++i) {
                uint8_t fake[] = {
                    0x16, 0x03,
                    static_cast<uint8_t>(randombytes_uniform(4)),
                    static_cast<uint8_t>(randombytes_uniform(256)),
                    static_cast<uint8_t>(randombytes_uniform(256)),
                    0x01
                };
                out.insert(out.end(), fake, fake + sizeof(fake));
                {
                    std::lock_guard<std::mutex> lock(stats_mutex);
                    stats.fake_packets_sent++;
                }
            }
        }

        // --- TCP split / fragmentation ---
        if (!is_client_hello || !config.enable_tcp_split) {
            out.insert(out.end(), data, data + len);
        } else {
            size_t first_len = 0;
            int sni_off = -1;
            if (config.split_at_sni)
                sni_off = find_sni_hostname_offset(data, len);

            if (sni_off > 0 && static_cast<size_t>(sni_off) < len)
                first_len = static_cast<size_t>(sni_off);
            else if (config.split_position > 0 &&
                     static_cast<size_t>(config.split_position) < len)
                first_len = static_cast<size_t>(config.split_position);
            else
                first_len = std::min<size_t>(len, 1);

            // First fragment
            out.insert(out.end(), data, data + first_len);

            // Remaining fragments with jitter-sized chunks
            size_t base_frag = config.fragment_size > 0
                                ? static_cast<size_t>(config.fragment_size) : 2;
            size_t remaining = len - first_len;
            size_t off = first_len;
            while (remaining > 0) {
                size_t j = randombytes_uniform(3);
                size_t chunk = std::min(base_frag + j, remaining);
                out.insert(out.end(), data + off, data + off + chunk);
                off += chunk;
                remaining -= chunk;
            }
        }

        {
            std::lock_guard<std::mutex> lock(stats_mutex);
            stats.bytes_sent += static_cast<uint64_t>(out.size());
            if (is_client_hello && config.enable_tcp_split)
                stats.packets_fragmented++;
        }

        return out;
    }

    /**
     * @brief Send raw data back to the currently connected client socket.
     *        Called from WSTunnel receive callback (relay → client).
     */
    void send_to_client(const uint8_t* data, size_t len) {
        std::lock_guard<std::mutex> lock(ws_client_mutex_);
        if (ws_active_client_ == INVALID_SOCKET || !data || len == 0)
            return;

        size_t total_sent = 0;
        while (total_sent < len) {
            int chunk = static_cast<int>(std::min<size_t>(len - total_sent, 8192));
            int sent = ::send(ws_active_client_,
                              reinterpret_cast<const char*>(data + total_sent),
                              chunk, 0);
            if (sent <= 0) break;
            total_sent += static_cast<size_t>(sent);
        }

        {
            std::lock_guard<std::mutex> slock(stats_mutex);
            stats.bytes_received += static_cast<uint64_t>(total_sent);
        }
    }

    /**
     * @brief WS tunnel accept loop.
     *
     * Listens on ws_local_port, accepts one client at a time, reads data,
     * applies DPI processing (fragmentation / obfuscation), then pushes
     * the result through WSTunnel::send().  Data received from the relay
     * is forwarded back to the client via the receive callback registered
     * in start_ws_tunnel().
     */
    void ws_tunnel_listen_loop() {
#ifdef _WIN32
        WSADATA wsa_data;
        if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
            log("WS_TUNNEL: Failed to initialize Winsock");
            running = false;
            return;
        }
#endif
        uint16_t local_port = config.ws_local_port > 0
                                ? config.ws_local_port : 8081;

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

        // Thread pool for concurrent client handling
        size_t num_threads = std::min<size_t>(std::thread::hardware_concurrency(), 8);
        thread_pool_ = std::make_unique<ncp::ThreadPool>(num_threads);

        log("WS_TUNNEL: listening on 127.0.0.1:" + std::to_string(local_port) +
            " → relay " + config.ws_server_url);

        while (running) {
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

            {
                std::lock_guard<std::mutex> lock(stats_mutex);
                stats.connections_handled++;
            }

            thread_pool_->submit([this, client_sock]() {
                handle_ws_tunnel_connection(client_sock);
            });
        }

        CLOSE_SOCKET(listen_sock);
#ifdef _WIN32
        WSACleanup();
#endif
    }

    /**
     * @brief Handle a single client connection in WS_TUNNEL mode.
     *
     * Reads from client → process_outgoing_for_ws() → WSTunnel::send()
     * The reverse path (relay → client) is handled by the WSTunnel
     * receive callback which calls send_to_client().
     */
    void handle_ws_tunnel_connection(SOCKET client_sock) {
        // Register this client for the receive callback path
        {
            std::lock_guard<std::mutex> lock(ws_client_mutex_);
            ws_active_client_ = client_sock;
        }

        std::vector<uint8_t> buffer(8192);
        bool client_hello_processed = false;

        while (running) {
            int received = recv(client_sock,
                                reinterpret_cast<char*>(buffer.data()),
                                static_cast<int>(buffer.size()), 0);
            if (received <= 0) break;

            {
                std::lock_guard<std::mutex> lock(stats_mutex);
                stats.bytes_received += static_cast<uint64_t>(received);
                stats.packets_total++;
            }

            bool is_ch = false;
            if (!client_hello_processed &&
                is_tls_client_hello(buffer.data(),
                                    static_cast<size_t>(received))) {
                is_ch = true;
                client_hello_processed = true;
            }

            // Apply DPI obfuscation pipeline then send via WS tunnel
            auto processed = process_outgoing_for_ws(
                buffer.data(), static_cast<size_t>(received), is_ch);

            if (!processed.empty() && ws_tunnel_) {
                ws_tunnel_->send(processed.data(), processed.size());
            }
        }

        // Unregister client
        {
            std::lock_guard<std::mutex> lock(ws_client_mutex_);
            ws_active_client_ = INVALID_SOCKET;
        }
        CLOSE_SOCKET(client_sock);
    }

    /**
     * @brief Initialize and start the WSTunnel, then enter accept loop.
     */
    bool start_ws_tunnel() {
        ws_tunnel_ = std::make_unique<ncp::WSTunnel>();

        ncp::WSTunnelConfig ws_cfg;
        ws_cfg.server_url           = config.ws_server_url;
        ws_cfg.local_port           = config.ws_local_port;
        ws_cfg.sni_override         = config.ws_sni_override;
        ws_cfg.ping_interval_sec    = config.ws_ping_interval_sec;
        ws_cfg.reconnect_delay_ms   = config.ws_reconnect_delay_ms;
        ws_cfg.max_reconnect_attempts = config.ws_max_reconnect_attempts;

        if (!ws_tunnel_->initialize(ws_cfg)) {
            log("WS_TUNNEL: Failed to initialize libwebsockets context");
            ws_tunnel_.reset();
            return false;
        }

        // Register receive callback: relay → client socket
        ws_tunnel_->set_receive_callback(
            [this](const uint8_t* data, size_t len) {
                send_to_client(data, len);
            });

        // Log connection state changes
        ws_tunnel_->set_state_callback(
            [this](bool connected) {
                log(std::string("WS_TUNNEL: relay ") +
                    (connected ? "CONNECTED" : "DISCONNECTED"));
            });

        if (!ws_tunnel_->start()) {
            log("WS_TUNNEL: Failed to connect to relay " + config.ws_server_url);
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
        // Close any active client
        {
            std::lock_guard<std::mutex> lock(ws_client_mutex_);
            if (ws_active_client_ != INVALID_SOCKET) {
                CLOSE_SOCKET(ws_active_client_);
                ws_active_client_ = INVALID_SOCKET;
            }
        }
    }
#endif // HAVE_LIBWEBSOCKETS

    // =========================================================================
    // NFQUEUE (driver mode)
    // =========================================================================
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
        nfq_h = nfq_open();
        if (!nfq_h) return false;
        nfq_unbind_pf(nfq_h, AF_INET);
        if (nfq_bind_pf(nfq_h, AF_INET) < 0) {
            nfq_close(nfq_h); nfq_h = nullptr;
            return false;
        }
        nfq_qh = nfq_create_queue(nfq_h, config.nfqueue_num, &Impl::nfq_callback, this);
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
        config.mode = DPIMode::PROXY;
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
        config.mode = DPIMode::PROXY;
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
    case DPIPreset::NONE:
    default:
        break;
    }
}

DPIPreset preset_from_string(const std::string& name) {
    auto lower = to_lower_copy(name);
    if (lower == "runet-soft" || lower == "runet_soft" || lower == "runetsoft") {
        return DPIPreset::RUNET_SOFT;
    }
    if (lower == "runet-strong" || lower == "runet_strong" || lower == "runetstrong") {
        return DPIPreset::RUNET_STRONG;
    }
    return DPIPreset::NONE;
}

const char* preset_to_string(DPIPreset preset) {
    switch (preset) {
    case DPIPreset::RUNET_SOFT:   return "RuNet-Soft";
    case DPIPreset::RUNET_STRONG: return "RuNet-Strong";
    case DPIPreset::NONE:
    default:
        return "Custom";
    }
}

DPIBypass::DPIBypass() : impl_(std::make_unique<Impl>()) {}
DPIBypass::~DPIBypass() { shutdown(); }

bool DPIBypass::initialize(const DPIConfig& config) {
    impl_->config = config;

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

    if (needs_advanced) {
        impl_->init_advanced_bypass();
    }

    return true;
}

bool DPIBypass::start() {
#if defined(HAVE_NFQUEUE) && !defined(_WIN32)
    if (impl_->config.mode == DPIMode::DRIVER) {
        if (!impl_->init_nfqueue()) return false;
        impl_->running = true;
        impl_->worker_thread = std::thread(&Impl::nfqueue_loop, impl_.get());
        impl_->log("DPI bypass started (driver mode via nfqueue, queue=" +
                  std::to_string(impl_->config.nfqueue_num) + ")");
        return true;
    }
#endif

    if (impl_->config.mode == DPIMode::PROXY) {
        impl_->running = true;
        impl_->worker_thread = std::thread(&Impl::proxy_listen_loop, impl_.get());
        impl_->log("DPI bypass started (TCP proxy mode" +
                  std::string(impl_->advanced_enabled_ ? " + Advanced" : "") + ")");
        return true;
    }

    // WebSocket Tunnel mode (Phase 3)
#ifdef HAVE_LIBWEBSOCKETS
    if (impl_->config.mode == DPIMode::WS_TUNNEL) {
        if (impl_->config.ws_server_url.empty()) {
            impl_->log("WS_TUNNEL: ws_server_url is not configured");
            return false;
        }
        if (!impl_->start_ws_tunnel()) {
            return false;
        }
        impl_->log("DPI bypass started (WebSocket tunnel mode → " +
                   impl_->config.ws_server_url + ")");
        return true;
    }
#endif

    // Passive fallback mode (no packet/stream modification)
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
    impl_->log_callback = [cb](const std::string& msg) { if (cb) cb(LogLevel::INFO, msg); };
}

DPIConfig DPIBypass::get_config() const {
    std::lock_guard<std::mutex> lock(impl_->stats_mutex);
    return impl_->config;
}

bool DPIBypass::update_config(const DPIConfig& config) {
    auto err = config.validate();
    if (err != ValidationError::NONE) return false;
    DPIConfig old_cfg;
    {
        std::lock_guard<std::mutex> lock(impl_->stats_mutex);
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

void DPIBypass::log(LogLevel level, const std::string& message) {
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
