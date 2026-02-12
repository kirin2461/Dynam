#include "ncp_dpi.hpp"
#include <thread>
#include <mutex>
#include <cstring>
#include <iostream>
#include <algorithm>
#include <chrono>
#include <vector>
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

// TLS ClientHello detection
static bool is_tls_client_hello(const uint8_t* data, size_t len) {
    return len > 5 && data[0] == 0x16 && data[1] == 0x03 && data[5] == 0x01;
}

/**
 * @brief Best-effort parser for TLS ClientHello to locate SNI hostname offset.
 *
 * Returns offset (in bytes from start of record) where the SNI hostname bytes begin,
 * or -1 if SNI cannot be found / parsed.
 *
 * Exposed with external linkage so unit tests can validate parsing robustness.
 */
int find_sni_hostname_offset(const uint8_t* data, size_t len) {
    // Basic TLS record header (5 bytes) + minimum handshake header
    if (!data || len < 5 + 4) {
        return -1;
    }

    // TLS record type 0x16 (handshake) and version 0x03,xx already checked by is_tls_client_hello.
    if (data[0] != 0x16 || data[1] != 0x03) {
        return -1;
    }

    size_t pos = 5; // Start of Handshake message
    if (pos + 4 > len) {
        return -1;
    }

    uint8_t handshake_type = data[pos];
    if (handshake_type != 0x01) { // ClientHello
        return -1;
    }

    // Handshake length (3 bytes) - we mostly rely on outer bounds
    uint32_t hs_len = (static_cast<uint32_t>(data[pos + 1]) << 16) |
                      (static_cast<uint32_t>(data[pos + 2]) << 8) |
                      static_cast<uint32_t>(data[pos + 3]);
    (void)hs_len;
    pos += 4;

    // ClientHello structure (RFC 5246 / 8446-style, simplified)
    if (pos + 2 + 32 + 1 > len) {
        return -1;
    }

    // client_version (2) + random (32)
    pos += 2;
    pos += 32;

    // session_id
    uint8_t session_id_len = data[pos];
    pos += 1;
    if (pos + session_id_len > len) {
        return -1;
    }
    pos += session_id_len;

    // cipher_suites
    if (pos + 2 > len) {
        return -1;
    }
    uint16_t cipher_suites_len = (static_cast<uint16_t>(data[pos]) << 8) |
                                 static_cast<uint16_t>(data[pos + 1]);
    pos += 2;
    if (pos + cipher_suites_len > len) {
        return -1;
    }
    pos += cipher_suites_len;

    // compression_methods
    if (pos + 1 > len) {
        return -1;
    }
    uint8_t compression_methods_len = data[pos];
    pos += 1;
    if (pos + compression_methods_len > len) {
        return -1;
    }
    pos += compression_methods_len;

    // extensions length
    if (pos + 2 > len) {
        return -1;
    }
    uint16_t extensions_len = (static_cast<uint16_t>(data[pos]) << 8) |
                              static_cast<uint16_t>(data[pos + 1]);
    pos += 2;

    size_t exts_end = pos + extensions_len;
    if (exts_end > len) {
        exts_end = len;
    }

    // Walk over extensions
    while (pos + 4 <= exts_end) {
        uint16_t ext_type = (static_cast<uint16_t>(data[pos]) << 8) |
                            static_cast<uint16_t>(data[pos + 1]);
        uint16_t ext_data_len = (static_cast<uint16_t>(data[pos + 2]) << 8) |
                                static_cast<uint16_t>(data[pos + 3]);
        pos += 4;

        if (pos + ext_data_len > exts_end) {
            break;
        }

        if (ext_type == 0x0000) { // server_name extension
            size_t sni_pos = pos;
            if (sni_pos + 2 > exts_end) {
                return -1;
            }

            uint16_t list_len = (static_cast<uint16_t>(data[sni_pos]) << 8) |
                                static_cast<uint16_t>(data[sni_pos + 1]);
            sni_pos += 2;
            if (sni_pos + list_len > exts_end || list_len < 3) {
                return -1;
            }

            // We only look at the first name in the list
            uint8_t name_type = data[sni_pos];
            (void)name_type; // Typically 0x00 (host_name)
            sni_pos += 1;
            if (sni_pos + 2 > exts_end) {
                return -1;
            }

            uint16_t host_len = (static_cast<uint16_t>(data[sni_pos]) << 8) |
                                static_cast<uint16_t>(data[sni_pos + 1]);
            sni_pos += 2;

            if (sni_pos + host_len > exts_end) {
                return -1;
            }

            // sni_pos now points at the first byte of the SNI hostname
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
    
    // === Proxy mode state ===
    void proxy_listen_loop() {
#ifdef _WIN32
        // Ensure Winsock is initialized for standalone DPI usage
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
        // Bind to localhost for home-user proxy usage
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

            std::thread(&Impl::handle_proxy_connection, this, client_sock).detach();
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

        // Resolve target host
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

        if (connect(server_sock,
                    reinterpret_cast<sockaddr*>(&remote_addr),
                    sizeof(remote_addr)) < 0) {
            log("DPI proxy: failed to connect to upstream server");
            CLOSE_SOCKET(client_sock);
            CLOSE_SOCKET(server_sock);
            return;
        }

        // Bidirectional piping: client -> server (with fragmentation/SNI-split)
        // and server -> client (plain forward).
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
                                static_cast<int>(buffer.size()),
                                0);
            if (received <= 0) {
                break;
            }

            {
                std::lock_guard<std::mutex> lock(stats_mutex);
                stats.bytes_received += static_cast<uint64_t>(received);
                stats.packets_total++;
            }

            bool is_client_hello = false;
            if (!client_hello_processed &&
                is_tls_client_hello(buffer.data(),
                                    static_cast<size_t>(received))) {
                is_client_hello = true;
                client_hello_processed = true;
            }

            send_with_fragmentation(
                server_sock,
                buffer.data(),
                static_cast<size_t>(received),
                is_client_hello
            );
        }
    }

    void pipe_server_to_client(SOCKET server_sock, SOCKET client_sock) {
        std::vector<uint8_t> buffer(8192);

        while (running) {
            int received = recv(server_sock,
                                reinterpret_cast<char*>(buffer.data()),
                                static_cast<int>(buffer.size()),
                                0);
            if (received <= 0) {
                break;
            }

            {
                std::lock_guard<std::mutex> lock(stats_mutex);
                stats.bytes_received += static_cast<uint64_t>(received);
                stats.packets_total++;
            }

            // No fragmentation for server->client path
            send_with_fragmentation(
                client_sock,
                buffer.data(),
                static_cast<size_t>(received),
                false
            );
        }
    }

    void send_with_fragmentation(
        SOCKET sock,
        const uint8_t* data,
        size_t len,
        bool is_client_hello
    ) {
        if (!data || len == 0) {
            return;
        }

        auto send_all = [&](const uint8_t* d, size_t l) -> size_t {
            size_t total_sent = 0;
            while (total_sent < l) {
                int to_send = static_cast<int>(std::min<size_t>(l - total_sent, 1460));
                int sent = send(sock,
                                reinterpret_cast<const char*>(d + total_sent),
                                to_send,
                                0);
                if (sent <= 0) {
                    break;
                }
                total_sent += static_cast<size_t>(sent);
            }
            return total_sent;
        };

        // Add Noise/Junk data before the actual ClientHello
        if (is_client_hello && config.enable_noise) {
            std::vector<uint8_t> junk;
            if (!config.fake_host.empty()) {
                // Use fake host as noise to mislead DPI
                std::string mask = "GET / HTTP/1.1\r\nHost: " + config.fake_host + "\r\n\r\n";
                junk.assign(mask.begin(), mask.end());
            } else {
                junk.resize(config.noise_size > 0 ? config.noise_size : 64);
                for(auto& b : junk) b = static_cast<uint8_t>(rand() % 256);
            }
            
            // Send junk with low TTL if fake_packet is enabled, otherwise just as noise
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

        // Optional fake low‑TTL probe before main ClientHello
        if (is_client_hello && config.enable_fake_packet) {
            std::vector<uint8_t> fake_data = {0x16, 0x03, 0x01, 0x00, 0x01, 0x01}; // Minimum TLS-like record
            
            // Send multiple fake packets with different characteristics
            for (int i = 0; i < (config.fake_ttl > 2 ? 2 : 1); ++i) {
#ifdef IP_TTL
                int original_ttl = 0;
                socklen_t optlen = static_cast<socklen_t>(sizeof(original_ttl));
                bool ttl_changed = false;
                if (getsockopt(sock, IPPROTO_IP, IP_TTL,
                               reinterpret_cast<char*>(&original_ttl),
                               &optlen) == 0) {
                    int ttl = (config.fake_ttl > 0) ? (config.fake_ttl + i) : 2;
                    if (setsockopt(sock, IPPROTO_IP, IP_TTL,
                                   reinterpret_cast<const char*>(&ttl),
                                   sizeof(ttl)) == 0) {
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
                               reinterpret_cast<const char*>(&original_ttl),
                               sizeof(original_ttl));
                }
#endif
                if (config.disorder_delay_ms > 0) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(config.disorder_delay_ms / 2));
                }
            }
        }

        // If this is not a ClientHello or TCP splitting is disabled,
        // just send as-is (potentially chunked by MTU size).
        if (!is_client_hello || !config.enable_tcp_split) {
            size_t sent = send_all(data, len);
            std::lock_guard<std::mutex> lock(stats_mutex);
            stats.bytes_sent += static_cast<uint64_t>(sent);
            return;
        }

        // Determine split point: SNI-based if requested and available,
        // otherwise based on split_position, with a safe minimum.
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
            // Advanced fragmentation with randomness
            size_t base_frag_size = (config.fragment_size > 0)
                                   ? static_cast<size_t>(config.fragment_size)
                                   : 2;
            
            size_t offset = 0;
            while (offset < remaining) {
                // Randomize fragment size slightly for evasion
                size_t jitter = (rand() % 3); 
                size_t current_frag = std::min(base_frag_size + jitter, remaining - offset);

                if (config.enable_disorder && config.disorder_delay_ms > 0) {
                    std::this_thread::sleep_for(
                        std::chrono::milliseconds(config.disorder_delay_ms));
                }

                size_t sent = send_all(data + sent_first + offset, current_frag);
                sent_total += sent;
                if (sent == 0) {
                    break;
                }
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
    
#if defined(HAVE_NFQUEUE) && !defined(_WIN32)
    struct nfq_handle* nfq_h = nullptr;
    struct nfq_q_handle* nfq_qh = nullptr;
    int nfq_fd = -1;
    
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
        nfq_fd = nfq_fd(nfq_h);
        return true;
    }
    
    void nfqueue_loop() {
        char buf[65536];
        while (running) {
            int rv = recv(nfq_fd, buf, sizeof(buf), 0);
            if (rv >= 0) nfq_handle_packet(nfq_h, buf, rv);
        }
    }
    
    void cleanup_nfqueue() {
        if (nfq_qh) { nfq_destroy_queue(nfq_qh); nfq_qh = nullptr; }
        if (nfq_h) { nfq_close(nfq_h); nfq_h = nullptr; }
        nfq_fd = -1;
    }
#endif

    void log(const std::string& msg) {
        if (log_callback) {
            log_callback(msg);
        } else {
            // Fallback when no callback is installed (e.g. tests)
            std::clog << "[DPI] " << msg << std::endl;
        }
    }
};

void apply_preset(DPIPreset preset, DPIConfig& config) {
    switch (preset) {
    case DPIPreset::RUNET_SOFT:
        // Mild settings targeting common Russian DPI deployments
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
        // Aggressive profile for heavily filtered networks (modernized for TSPU)
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
        config.fake_ttl = 2; // Paranoid level
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
    impl_->log("Initialize DPI (mode=" +
              std::string(config.mode == DPIMode::DRIVER ? "driver" :
                          config.mode == DPIMode::PROXY ? "proxy" : "passive") +
              ", listen_port=" + std::to_string(config.listen_port) +
              ", fragment_size=" + std::to_string(config.fragment_size) + ")");
    return true;
}

bool DPIBypass::start() {
#if defined(HAVE_NFQUEUE) && !defined(_WIN32)
    if (impl_->config.mode == DPIMode::DRIVER) {
        if (!impl_->init_nfqueue()) return false;
        impl_->running = true;
        impl_->worker_thread = std::thread(&Impl::nfqueue_loop, impl.get());
        impl_->log("DPI bypass started (driver mode via nfqueue, queue=" +
                  std::to_string(impl_->config.nfqueue_num) + ")");
        return true;
    }
#endif
    if (impl_->config.mode == DPIMode::PROXY) {
        impl_->running = true;
        impl_->worker_thread = std::thread(&Impl::proxy_listen_loop, impl.get());
        impl_->log("DPI bypass started (TCP proxy mode)");
        return true;
    }

    // Passive fallback mode (no packet/stream modification)
    impl_->running = true;
    impl_->log("DPI bypass started (passive mode - nfqueue/proxy not active)");
    return true;
}

void DPIBypass::stop() {
    impl_->running = false;
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

} // namespace DPI
} // namespace ncp
