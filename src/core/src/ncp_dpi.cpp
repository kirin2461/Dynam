#include "ncp_dpi.hpp"
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

// TLS ClientHello detection
static bool is_tls_client_hello(const uint8_t* data, size_t len) {
    return len > 5 && data[0] == 0x16 && data[1] == 0x03 && data[5] == 0x01;
}

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

    std::unique_ptr<ncp::ThreadPool> thread_pool_;
    std::atomic<int> active_connections_{0};
    static constexpr int MAX_CONNECTIONS = 256;

#ifdef HAVE_LIBWEBSOCKETS
    std::unique_ptr<ncp::WSTunnel> ws_tunnel_;
    std::mutex ws_client_mutex_;
    SOCKET ws_active_client_ = INVALID_SOCKET;
#endif

    // =========================================================================
    // FIX #55: proxy_listen_loop with poll() before accept() and connection limits
    // =========================================================================
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

        // FIX #55: Use poll() with timeout so the loop exits when running becomes false
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
                continue; // timeout or error — re-check running flag
            }
#else
            struct pollfd pfd;
            pfd.fd = listen_sock;
            pfd.events = POLLIN;
            pfd.revents = 0;
            int poll_ret = poll(&pfd, 1, 1000); // 1 second timeout
            if (poll_ret <= 0) {
                continue; // timeout or error — re-check running flag
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

            // FIX #55: Enforce MAX_CONNECTIONS limit
            int current = active_connections_.load();
            if (current >= MAX_CONNECTIONS) {
                log("DPI proxy: max connections reached (" + std::to_string(MAX_CONNECTIONS) + "), rejecting");
                CLOSE_SOCKET(client_sock);
                continue;
            }

            {
                std::lock_guard<std::mutex> lock(stats_mutex);
                stats.connections_handled++;
            }

            active_connections_++;
            thread_pool_->submit([this, client_sock]() {
                handle_proxy_connection(client_sock);
                active_connections_--;
            });
        }

        CLOSE_SOCKET(listen_sock);
#ifdef _WIN32
        WSACleanup();
#endif
    }

    // =========================================================================
    // FIX #55: handle_proxy_connection — poll-based relay, NO sub-threads
    // =========================================================================
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

        if (connect(server_sock,
                    reinterpret_cast<sockaddr*>(&remote_addr),
                    sizeof(remote_addr)) < 0) {
            log("DPI proxy: failed to connect to upstream server");
            CLOSE_SOCKET(client_sock);
            CLOSE_SOCKET(server_sock);
            return;
        }

        // FIX #55: Single-thread poll-based bidirectional relay
        // Instead of spawning 2 additional threads per connection (which
        // defeats the purpose of a thread pool), use poll() to multiplex.
        std::vector<uint8_t> buffer(8192);
        bool client_hello_processed = false;

#ifdef _WIN32
        // Windows select-based relay
        while (running) {
            fd_set read_fds;
            FD_ZERO(&read_fds);
            FD_SET(client_sock, &read_fds);
            FD_SET(server_sock, &read_fds);
            SOCKET max_fd = std::max(client_sock, server_sock);
            struct timeval tv;
            tv.tv_sec = 1;
            tv.tv_usec = 0;
            int sel = select(static_cast<int>(max_fd + 1), &read_fds, nullptr, nullptr, &tv);
            if (sel < 0) break;
            if (sel == 0) continue;

            // client -> server
            if (FD_ISSET(client_sock, &read_fds)) {
                int received = recv(client_sock, reinterpret_cast<char*>(buffer.data()),
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
                send_with_fragmentation(server_sock, buffer.data(),
                                        static_cast<size_t>(received), is_ch);
            }

            // server -> client
            if (FD_ISSET(server_sock, &read_fds)) {
                int received = recv(server_sock, reinterpret_cast<char*>(buffer.data()),
                                    static_cast<int>(buffer.size()), 0);
                if (received <= 0) break;
                {
                    std::lock_guard<std::mutex> lock(stats_mutex);
                    stats.bytes_received += static_cast<uint64_t>(received);
                    stats.packets_total++;
                }
                send_with_fragmentation(client_sock, buffer.data(),
                                        static_cast<size_t>(received), false);
            }
        }
#else
        // POSIX poll-based relay
        struct pollfd fds[2];
        fds[0].fd = client_sock;
        fds[0].events = POLLIN;
        fds[1].fd = server_sock;
        fds[1].events = POLLIN;

        while (running) {
            int ret = poll(fds, 2, 1000);
            if (ret < 0) break;
            if (ret == 0) continue;

            // client -> server
            if (fds[0].revents & (POLLIN | POLLHUP | POLLERR)) {
                int received = recv(client_sock, reinterpret_cast<char*>(buffer.data()),
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
                send_with_fragmentation(server_sock, buffer.data(),
                                        static_cast<size_t>(received), is_ch);
            }

            // server -> client
            if (fds[1].revents & (POLLIN | POLLHUP | POLLERR)) {
                int received = recv(server_sock, reinterpret_cast<char*>(buffer.data()),
                                    static_cast<int>(buffer.size()), 0);
                if (received <= 0) break;
                {
                    std::lock_guard<std::mutex> lock(stats_mutex);
                    stats.bytes_received += static_cast<uint64_t>(received);
                    stats.packets_total++;
                }
                send_with_fragmentation(client_sock, buffer.data(),
                                        static_cast<size_t>(received), false);
            }
        }
#endif

        CLOSE_SOCKET(client_sock);
        CLOSE_SOCKET(server_sock);
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

        // =====================================================================
        // FIX #48: Fake packet via TCP socket fundamentally does not work.
        //
        // TCP guarantees in-order reliable delivery. Setting a low TTL via
        // setsockopt(IP_TTL) does NOT prevent the TCP stack from retransmitting
        // the data — the fake bytes WILL reach the server and corrupt the TLS
        // handshake. The low-TTL trick only works with raw sockets where you
        // craft IP packets directly.
        //
        // In PROXY mode we only apply TCP fragmentation/splitting strategies
        // (which DO work over TCP sockets) and skip fake packet injection.
        //
        // Noise (fake host preamble) is also disabled in PROXY mode for the same
        // reason — injecting extra bytes into a TCP stream corrupts the protocol.
        //
        // For real fake-packet DPI evasion, use DRIVER mode (nfqueue/raw sockets).
        // =====================================================================

        if (is_client_hello && config.enable_noise && config.mode != DPIMode::PROXY) {
            // Noise only works in non-proxy modes (raw socket / nfqueue)
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

        if (is_client_hello && config.enable_fake_packet && config.mode != DPIMode::PROXY) {
            // Fake packets only work via raw sockets / nfqueue, not TCP proxy
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

        // TCP split/fragmentation — this DOES work correctly over TCP sockets
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
                                   ? static_cast<size_t>(config.fragment_size) : 2;
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

#ifdef HAVE_LIBWEBSOCKETS
    std::vector<uint8_t> process_outgoing_for_ws(const uint8_t* data, size_t len,
                                                  bool is_client_hello) {
        std::vector<uint8_t> out;
        if (!data || len == 0) return out;

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

        if (!is_client_hello || !config.enable_tcp_split) {
            out.insert(out.end(), data, data + len);
        } else {
            size_t first_len = 0;
            int sni_off = -1;
            if (config.split_at_sni) sni_off = find_sni_hostname_offset(data, len);
            if (sni_off > 0 && static_cast<size_t>(sni_off) < len)
                first_len = static_cast<size_t>(sni_off);
            else if (config.split_position > 0 &&
                     static_cast<size_t>(config.split_position) < len)
                first_len = static_cast<size_t>(config.split_position);
            else
                first_len = std::min<size_t>(len, 1);

            out.insert(out.end(), data, data + first_len);
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
        uint16_t local_port = config.ws_local_port > 0 ? config.ws_local_port : 8081;

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
        thread_pool_ = std::make_unique<ncp::ThreadPool>(num_threads);

        log("WS_TUNNEL: listening on 127.0.0.1:" + std::to_string(local_port) +
            " -> relay " + config.ws_server_url);

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

    void handle_ws_tunnel_connection(SOCKET client_sock) {
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
                is_tls_client_hello(buffer.data(), static_cast<size_t>(received))) {
                is_ch = true;
                client_hello_processed = true;
            }

            auto processed = process_outgoing_for_ws(
                buffer.data(), static_cast<size_t>(received), is_ch);
            if (!processed.empty() && ws_tunnel_) {
                ws_tunnel_->send(processed.data(), processed.size());
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

        ws_tunnel_->set_receive_callback(
            [this](const uint8_t* data, size_t len) { send_to_client(data, len); });
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
        {
            std::lock_guard<std::mutex> lock(ws_client_mutex_);
            if (ws_active_client_ != INVALID_SOCKET) {
                CLOSE_SOCKET(ws_active_client_);
                ws_active_client_ = INVALID_SOCKET;
            }
        }
    }
#endif // HAVE_LIBWEBSOCKETS

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
    if (lower == "runet-soft" || lower == "runet_soft" || lower == "runetsoft") return DPIPreset::RUNET_SOFT;
    if (lower == "runet-strong" || lower == "runet_strong" || lower == "runetstrong") return DPIPreset::RUNET_STRONG;
    return DPIPreset::NONE;
}

const char* preset_to_string(DPIPreset preset) {
    switch (preset) {
    case DPIPreset::RUNET_SOFT:   return "RuNet-Soft";
    case DPIPreset::RUNET_STRONG: return "RuNet-Strong";
    case DPIPreset::NONE:
    default: return "Custom";
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
        impl_->log("DPI bypass started (TCP proxy mode)");
        return true;
    }

#ifdef HAVE_LIBWEBSOCKETS
    if (impl_->config.mode == DPIMode::WS_TUNNEL) {
        if (impl_->config.ws_server_url.empty()) {
            impl_->log("WS_TUNNEL: ws_server_url is not configured");
            return false;
        }
        if (!impl_->start_ws_tunnel()) return false;
        impl_->log("DPI bypass started (WebSocket tunnel mode -> " +
                   impl_->config.ws_server_url + ")");
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
