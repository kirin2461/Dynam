#include "ConnectionMonitor.hpp"
#include <chrono>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#else
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

namespace ncp {

ConnectionMonitor::ConnectionMonitor() {
#ifdef _WIN32
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif
}

ConnectionMonitor::~ConnectionMonitor() {
    stop();
#ifdef _WIN32
    WSACleanup();
#endif
}

void ConnectionMonitor::start(int interval_ms) {
    // thread_mutex_ closes the TOCTOU race: two concurrent start() calls
    // could both pass the `running_` check and the second assignment to a
    // joinable monitor_thread_ would call std::terminate.
    std::lock_guard<std::mutex> lock(thread_mutex_);
    if (running_) return;
    if (monitor_thread_.joinable()) {
        // Defensive: a leftover joinable thread object (e.g. after a
        // stop()/start() race) must be joined before being overwritten.
        monitor_thread_.join();
    }

    interval_ms_ = interval_ms;
    running_ = true;
    monitor_thread_ = std::thread(&ConnectionMonitor::monitor_thread_func, this);
}

void ConnectionMonitor::stop() {
    // Join under thread_mutex_: if we released the lock before joining, a
    // concurrent start() could set running_=true and spawn a new thread
    // while the old one is still in its loop — the old thread would then
    // observe running_==true and never exit (two monitor threads).
    std::lock_guard<std::mutex> lock(thread_mutex_);
    running_ = false;
    if (monitor_thread_.joinable()) {
        monitor_thread_.join();
    }
}

bool ConnectionMonitor::check_internet() {
#ifdef _WIN32
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) return false;
    
    sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(53);
    inet_pton(AF_INET, "8.8.8.8", &addr.sin_addr);
    
    u_long mode = 1;
    ioctlsocket(sock, FIONBIO, &mode);
    
    connect(sock, (sockaddr*)&addr, sizeof(addr));
    
    fd_set writefds;
    FD_ZERO(&writefds);
    FD_SET(sock, &writefds);
    
    timeval tv;
    tv.tv_sec = 3;
    tv.tv_usec = 0;
    
    int result = select(0, nullptr, &writefds, nullptr, &tv);
    if (result <= 0) {
        closesocket(sock);
        return false;
    }
    // Writable is not connected: ECONNREFUSED also reports writable.
    int so_error = 0;
    int opt_len = sizeof(so_error);
    if (getsockopt(sock, SOL_SOCKET, SO_ERROR,
                   reinterpret_cast<char*>(&so_error), &opt_len) != 0 ||
        so_error != 0) {
        closesocket(sock);
        return false;
    }
    closesocket(sock);
    return true;
#else
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return false;
    
    sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(53);
    inet_pton(AF_INET, "8.8.8.8", &addr.sin_addr);
    
    struct timeval tv;
    tv.tv_sec = 3;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    
    int result = connect(sock, (sockaddr*)&addr, sizeof(addr));
    close(sock);
    
    return result == 0;
#endif
}

int ConnectionMonitor::measure_latency(const std::string& host) {
    auto start = std::chrono::high_resolution_clock::now();
    
#ifdef _WIN32
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) return -1;
    
    sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(53);
    inet_pton(AF_INET, host.c_str(), &addr.sin_addr);
    
    int result = connect(sock, (sockaddr*)&addr, sizeof(addr));
    closesocket(sock);
    
    if (result != 0 && WSAGetLastError() != WSAEWOULDBLOCK) return -1;
#else
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -1;
    
    sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(53);
    inet_pton(AF_INET, host.c_str(), &addr.sin_addr);
    
    int result = connect(sock, (sockaddr*)&addr, sizeof(addr));
    close(sock);
    
    if (result != 0) return -1;
#endif
    
    auto end = std::chrono::high_resolution_clock::now();
        return static_cast<int>(std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count());
}

void ConnectionMonitor::monitor_thread_func() {
    while (running_.load()) {
        update_info();
        std::this_thread::sleep_for(std::chrono::milliseconds(interval_ms_.load()));
    }
}

void ConnectionMonitor::update_info() {
    // Probe outside any lock (network I/O can take seconds).
    const bool internet = check_internet();
    const int latency = measure_latency();

    ConnectionInfo info_copy;
    ConnectionState old_state;
    StateCallback state_cb;
    InfoCallback info_cb;
    {
        std::lock_guard<std::mutex> lock(info_mutex_);
        old_state = info_.state;
        info_.internet_available = internet;
        info_.latency_ms = latency;
        info_.state = internet ? ConnectionState::Connected
                               : ConnectionState::Disconnected;
        info_copy = info_;
    }
    {
        std::lock_guard<std::mutex> lock(cb_mutex_);
        state_cb = state_callback_;
        info_cb = info_callback_;
    }

    // Invoke callbacks without holding info_mutex_: a callback that calls
    // get_info()/get_state() would otherwise deadlock (non-recursive mutex).
    if (old_state != info_copy.state && state_cb) {
        state_cb(old_state, info_copy.state);
    }
    if (info_cb) {
        info_cb(info_copy);
    }
}

} // namespace ncp
