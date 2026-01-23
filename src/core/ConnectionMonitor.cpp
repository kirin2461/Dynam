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
    if (running_) return;
    
    interval_ms_ = interval_ms;
    running_ = true;
    monitor_thread_ = std::thread(&ConnectionMonitor::monitor_thread_func, this);
}

void ConnectionMonitor::stop() {
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
    closesocket(sock);
    
    return result > 0;
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
    return std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
}

void ConnectionMonitor::monitor_thread_func() {
    while (running_) {
        update_info();
        std::this_thread::sleep_for(std::chrono::milliseconds(interval_ms_));
    }
}

void ConnectionMonitor::update_info() {
    auto old_state = info_.state;
    
    info_.internet_available = check_internet();
    info_.latency_ms = measure_latency();
    
    if (info_.internet_available) {
        info_.state = ConnectionState::Connected;
    } else {
        info_.state = ConnectionState::Disconnected;
    }
    
    if (old_state != info_.state && state_callback_) {
        state_callback_(old_state, info_.state);
    }
    
    if (info_callback_) {
        info_callback_(info_);
    }
}

} // namespace ncp
