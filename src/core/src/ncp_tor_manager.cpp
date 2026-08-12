#include "ncp_tor_manager.hpp"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <sstream>
#include <thread>

#ifdef _WIN32
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
#  include <winsock2.h>
#  include <ws2tcpip.h>
#else
#  include <arpa/inet.h>
#  include <csignal>
#  include <netinet/in.h>
#  include <sys/socket.h>
#  include <sys/types.h>
#  include <sys/wait.h>
#  include <unistd.h>
#endif

namespace ncp {

struct TorManager::Impl {
    std::atomic<bool> running{false};
    std::atomic<int> bootstrap{0};
    std::mutex log_mtx;
    std::string last_line;
    std::thread reader;
#ifdef _WIN32
    HANDLE proc = nullptr;
    HANDLE read_pipe = nullptr;
#else
    pid_t pid = -1;
    int read_fd = -1;
#endif
};

// ── helpers ──────────────────────────────────────────────────────────

static std::string torrc_escape(std::string p) {
#ifdef _WIN32
    // Tor config parser treats backslash as escape inside quotes — use
    // forward slashes, which Win32 APIs accept everywhere.
    for (auto& c : p) if (c == '\\') c = '/';
#endif
    return p;
}

uint16_t TorManager::pick_free_port() {
#ifdef _WIN32
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return 0;
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = 0;
    if (bind(s, reinterpret_cast<sockaddr*>(&a), sizeof(a)) != 0) {
        closesocket(s);
        return 0;
    }
    int len = sizeof(a);
    getsockname(s, reinterpret_cast<sockaddr*>(&a), &len);
    closesocket(s);
    return ntohs(a.sin_port);
#else
    int s = ::socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) return 0;
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = 0;
    if (::bind(s, reinterpret_cast<sockaddr*>(&a), sizeof(a)) != 0) {
        ::close(s);
        return 0;
    }
    socklen_t len = sizeof(a);
    ::getsockname(s, reinterpret_cast<sockaddr*>(&a), &len);
    ::close(s);
    return ntohs(a.sin_port);
#endif
}

std::string TorManager::build_torrc(const TorLaunchConfig& cfg,
                                    uint16_t socks_port,
                                    const std::string& data_dir) {
    std::ostringstream o;
    o << "DataDirectory \"" << torrc_escape(data_dir) << "\"\n";
    o << "SocksPort 127.0.0.1:" << socks_port << "\n";
    o << "AvoidDiskWrites 1\n";
    o << "Log notice stdout\n";
    if (!cfg.bridges.empty()) {
        o << "UseBridges 1\n";
        if (!cfg.obfs4_binary.empty())
            o << "ClientTransportPlugin obfs4 exec \""
              << torrc_escape(cfg.obfs4_binary) << "\"\n";
        if (!cfg.snowflake_binary.empty())
            o << "ClientTransportPlugin snowflake exec \""
              << torrc_escape(cfg.snowflake_binary) << "\"\n";
        for (const auto& b : cfg.bridges)
            o << "Bridge " << b << "\n";
    }
    return o.str();
}

int TorManager::parse_bootstrap_percent(const std::string& line) {
    // e.g. "[notice] Bootstrapped 100% (done): Done"
    auto pos = line.find("Bootstrapped ");
    if (pos == std::string::npos) return -1;
    pos += sizeof("Bootstrapped ") - 1;
    int pct = -1;
    if (std::sscanf(line.c_str() + pos, "%d%%", &pct) == 1)
        return (pct >= 0 && pct <= 100) ? pct : -1;
    return -1;
}

// ── lifecycle ────────────────────────────────────────────────────────

TorManager::TorManager() : impl_(std::make_unique<Impl>()) {}
TorManager::~TorManager() { stop(); }

bool TorManager::running() const { return impl_->running.load(); }
int TorManager::bootstrap_percent() const { return impl_->bootstrap.load(); }
std::string TorManager::last_log_line() const {
    std::lock_guard<std::mutex> lk(impl_->log_mtx);
    return impl_->last_line;
}

bool TorManager::start(const TorLaunchConfig& cfg, std::string* err) {
    if (impl_->running.load()) {
        if (err) *err = "already running";
        return false;
    }
    if (cfg.tor_binary.empty()) {
        if (err) *err = "tor_binary is empty (--tor-exec)";
        return false;
    }

    uint16_t port = cfg.socks_port ? cfg.socks_port : pick_free_port();
    if (port == 0) {
        if (err) *err = "could not allocate a free SOCKS port";
        return false;
    }

    std::string data_dir = cfg.data_dir;
    if (data_dir.empty()) {
        data_dir = (std::filesystem::temp_directory_path() /
                    ("ncp-tor-" + std::to_string(
#ifdef _WIN32
                        GetCurrentProcessId()
#else
                        ::getpid()
#endif
                    ))).string();
    }
    std::error_code ec;
    std::filesystem::create_directories(data_dir, ec);

    const std::string torrc_path =
        (std::filesystem::path(data_dir) / "ncp-torrc").string();
    {
        std::ofstream f(torrc_path, std::ios::trunc);
        if (!f) {
            if (err) *err = "cannot write torrc: " + torrc_path;
            return false;
        }
        f << build_torrc(cfg, port, data_dir);
    }

#ifdef _WIN32
    // ── spawn with stdout pipe (Windows) ──
    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    HANDLE rd = nullptr, wr = nullptr;
    if (!CreatePipe(&rd, &wr, &sa, 0)) {
        if (err) *err = "CreatePipe failed";
        return false;
    }
    SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOA si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdOutput = wr;
    si.hStdError = wr;

    std::string cmd = "\"" + cfg.tor_binary + "\" -f \"" + torrc_path + "\"";
    std::vector<char> cmdbuf(cmd.begin(), cmd.end());
    cmdbuf.push_back('\0');

    PROCESS_INFORMATION pi{};
    BOOL ok = CreateProcessA(nullptr, cmdbuf.data(), nullptr, nullptr, TRUE,
                             CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
    CloseHandle(wr);  // child holds its own copy
    if (!ok) {
        CloseHandle(rd);
        if (err) *err = "failed to start tor (error " +
                        std::to_string(GetLastError()) + "): " + cfg.tor_binary;
        return false;
    }
    CloseHandle(pi.hThread);
    impl_->proc = pi.hProcess;
    impl_->read_pipe = rd;
#else
    // ── spawn with stdout pipe (POSIX) ──
    int fds[2];
    if (::pipe(fds) != 0) {
        if (err) *err = "pipe() failed";
        return false;
    }
    pid_t pid = ::fork();
    if (pid == 0) {
        ::dup2(fds[1], STDOUT_FILENO);
        ::dup2(fds[1], STDERR_FILENO);
        ::close(fds[0]);
        ::close(fds[1]);
        ::execl(cfg.tor_binary.c_str(), "tor", "-f", torrc_path.c_str(),
                static_cast<char*>(nullptr));
        _exit(127);
    }
    ::close(fds[1]);
    if (pid < 0) {
        ::close(fds[0]);
        if (err) *err = "fork() failed";
        return false;
    }
    impl_->pid = pid;
    impl_->read_fd = fds[0];
#endif

    impl_->running.store(true);
    socks_port_ = port;

    // reader thread: parse bootstrap progress + last line
    auto* impl = impl_.get();
    impl_->reader = std::thread([impl]() {
        std::string pending;
        char buf[512];
        while (impl->running.load()) {
#ifdef _WIN32
            DWORD got = 0;
            BOOL ok = ReadFile(impl->read_pipe, buf, sizeof(buf), &got, nullptr);
            if (!ok || got == 0) break;
#else
            ssize_t got = ::read(impl->read_fd, buf, sizeof(buf));
            if (got <= 0) break;
#endif
            pending.append(buf, got);
            size_t nl;
            while ((nl = pending.find('\n')) != std::string::npos) {
                std::string line = pending.substr(0, nl);
                pending.erase(0, nl + 1);
                if (!line.empty() && line.back() == '\r') line.pop_back();
                int pct = parse_bootstrap_percent(line);
                if (pct >= 0) impl->bootstrap.store(pct);
                std::lock_guard<std::mutex> lk(impl->log_mtx);
                impl->last_line = line;
            }
        }
    });

    // wait for bootstrap 100% (or early process exit)
    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::seconds(cfg.bootstrap_timeout_sec);
    while (std::chrono::steady_clock::now() < deadline) {
        if (impl_->bootstrap.load() >= 100) return true;
#ifdef _WIN32
        if (WaitForSingleObject(impl_->proc, 0) == WAIT_OBJECT_0) break;
#else
        int status = 0;
        if (::waitpid(impl_->pid, &status, WNOHANG) == impl_->pid) break;
#endif
        std::this_thread::sleep_for(std::chrono::milliseconds(150));
    }

    std::string why = "bootstrap timeout";
    if (impl_->bootstrap.load() < 100) {
        std::lock_guard<std::mutex> lk(impl_->log_mtx);
        if (!impl_->last_line.empty()) why = impl_->last_line;
    }
    stop();
    if (err) *err = why;
    return false;
}

void TorManager::stop() {
    if (!impl_->running.exchange(false)) return;
#ifdef _WIN32
    if (impl_->proc) {
        TerminateProcess(impl_->proc, 0);
        WaitForSingleObject(impl_->proc, 3000);
        CloseHandle(impl_->proc);
        impl_->proc = nullptr;
    }
    if (impl_->read_pipe) {
        CloseHandle(impl_->read_pipe);
        impl_->read_pipe = nullptr;
    }
#else
    if (impl_->pid > 0) {
        ::kill(impl_->pid, SIGTERM);
        int status = 0;
        for (int i = 0; i < 20 && ::waitpid(impl_->pid, &status, WNOHANG) == 0; ++i)
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        ::kill(impl_->pid, SIGKILL);
        ::waitpid(impl_->pid, &status, 0);
        impl_->pid = -1;
    }
    if (impl_->read_fd >= 0) {
        ::close(impl_->read_fd);
        impl_->read_fd = -1;
    }
#endif
    if (impl_->reader.joinable()) impl_->reader.join();
    impl_->bootstrap.store(0);
}

} // namespace ncp
