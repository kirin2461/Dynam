#pragma once

// Managed Tor launcher with pluggable transports (obfs4 / Snowflake).
//
// Rationale: chaining to a plain Tor SOCKS5 (127.0.0.1:9050) hides the
// destination from the ISP, but the ISP still SEES that you use Tor
// (public guard lists, characteristic handshakes) and can block it.
// With bridges + pluggable transports the first hop looks like random
// noise (obfs4) or a WebRTC call (Snowflake), so Tor usage itself is
// hidden and circumvents Tor blocking.
//
// Design: NCP generates a torrc (UseBridges + ClientTransportPlugin),
// spawns the tor binary and waits for "Bootstrapped 100%". tor itself
// manages the PT binaries — NCP only needs the resulting local SOCKS5
// port, which becomes the desync proxy upstream.

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace ncp {

struct TorLaunchConfig {
    std::string tor_binary;              // path to tor / tor.exe (required)
    std::vector<std::string> bridges;    // full Bridge lines, e.g.
                                         // "obfs4 1.2.3.4:443 FINGERPRINT cert=... iat-mode=0"
    std::string obfs4_binary;            // lyrebird/obfs4proxy (optional)
    std::string snowflake_binary;        // snowflake-client (optional)
    uint16_t socks_port = 0;             // 0 = auto-pick a free port
    std::string data_dir;                // empty = %TEMP%/ncp-tor-<pid>
    int bootstrap_timeout_sec = 120;     // how long to wait for 100%
};

class TorManager {
public:
    TorManager();
    ~TorManager();                       // stop() if running

    // Spawns tor, waits for bootstrap. On success socks_port() is valid.
    bool start(const TorLaunchConfig& cfg, std::string* err);
    void stop();
    bool running() const;

    uint16_t socks_port() const { return socks_port_; }
    int bootstrap_percent() const;       // 0..100, last seen progress
    std::string last_log_line() const;   // for diagnostics / GUI

    // ── testable helpers (no process spawning) ──────────────────────
    // Builds the torrc text. Static so unit tests can verify generation.
    static std::string build_torrc(const TorLaunchConfig& cfg,
                                   uint16_t socks_port,
                                   const std::string& data_dir);
    // Extracts bootstrap percentage from a tor log line, or -1.
    static int parse_bootstrap_percent(const std::string& line);
    // Picks a currently-free TCP port on 127.0.0.1.
    static uint16_t pick_free_port();

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
    uint16_t socks_port_ = 0;
};

} // namespace ncp
