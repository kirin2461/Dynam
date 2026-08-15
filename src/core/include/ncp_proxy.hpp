#pragma once

// ═══════════════════════════════════════════════════════════════════════════
// NCP Desync Proxy — local SOCKS5 / HTTP CONNECT proxy with DPI desync.
//
// No admin/root required: works purely at the application level.
//
// Supported desync techniques at this level:
//   - multisplit of the first client payload (TLS ClientHello / HTTP request)
//     at zapret split markers: numeric, method, host, endhost, sld+N, endsld,
//     midsld, sniext
//   - Host header case randomization (HTTP)
//   - fake QUIC Initial injection before the first real QUIC datagram
//     (SOCKS5 UDP ASSOCIATE, UDP/443)
//   - QUIC block (drop UDP/443) to force browsers onto TCP/TLS
//
// Fake TCP segments (bad TTL / bad checksum) are NOT possible via regular
// sockets — those require the packet-level backend (WinDivert/NFQUEUE).
//
// Per-host strategies: zapret chains with hostlists are honored — the first
// chain whose port/proto/hostlist matches the target is used; otherwise the
// base DPIConfig strategy applies.
// ═══════════════════════════════════════════════════════════════════════════

#include "ncp_dpi.hpp"
#include "ncp_dpi_zapret.hpp"

#include <string>
#include <vector>
#include <memory>
#include <atomic>
#include <functional>
#include <cstdint>

namespace ncp {

class DpiDetector;
class AutoHostlist;
class AutoPilot;

struct ProxyStats {
    uint64_t connections_total = 0;
    uint64_t connections_active = 0;
    uint64_t bytes_client_to_server = 0;
    uint64_t bytes_server_to_client = 0;
    uint64_t desync_splits_applied = 0;
    uint64_t fake_quic_sent = 0;
    uint64_t quic_datagrams_blocked = 0;
    uint64_t rst_blocks_detected = 0;
    uint64_t timeout_blocks_detected = 0;
    uint64_t udp_sessions = 0;
    uint64_t autopilot_hits = 0;        // connections served by a learned strategy
};

class DesyncProxy {
public:
    struct Config {
        std::string listen_host = "127.0.0.1";
        uint16_t port = 1080;               // 0 = ephemeral

        // Fallback strategy (when no chain matches)
        DPI::DPIConfig base;

        // Per-host zapret chains (hostlist files resolved from hostlist_dir)
        std::vector<DPI::ZapretChain> chains;
        std::string hostlist_dir;           // base dir for chain hostlist files

        bool block_quic = false;            // drop UDP/443 → force TCP fallback
        int fake_quic_repeats = 0;          // fake Initials per new QUIC target

        // Resolve target domains via DNS-over-HTTPS (bypasses DNS-level blocks)
        bool use_doh = false;

        // TCP Fast Open on upstream connects (Linux 4.11+, opt-in).
        // First client payload travels in the SYN (data-in-SYN); the kernel
        // falls back to a normal handshake when TFO is unsupported.
        bool tfo = false;

        // Clamp upstream TCP MSS via TCP_MAXSEG (0 = kernel default).
        // Affects the proxy upstream leg only; the client-facing leg is
        // negotiated independently.
        int upstream_mss = 0;

        // ── Upstream proxy chain (Tor / any SOCKS5 / HTTP CONNECT) ──
        // When upstream_port != 0, every target connection is established
        // through the upstream proxy instead of a direct connect:
        //   client -> ncp (desync) -> upstream (e.g. Tor :9050) -> target.
        // The upstream resolves the target host itself (no local DNS at all),
        // hiding both the destination IP and DNS queries from the ISP.
        // Desync techniques still apply to the first payload sent upstream
        // (e.g. fragments Tor's TLS ClientHello to the guard).
        std::string upstream_type;      // "" (off) | "socks5" | "http"
        std::string upstream_host;      // e.g. "127.0.0.1"
        uint16_t upstream_port = 0;     // e.g. 9050 (Tor service) / 9150 (Tor Browser)

        int connect_timeout_ms = 8000;
        int hello_timeout_ms = 10000;       // first server byte after CH

        // Optional sinks
        DpiDetector* detector = nullptr;
        AutoHostlist* auto_hostlist = nullptr;
        // Adaptive engine: when set, learned per-host strategies take
        // precedence over chains/base and live outcomes are reported back.
        AutoPilot* autopilot = nullptr;
        std::function<void(const std::string&)> log_cb;

        // Live monitoring (file-based IPC for the GUI):
        //   events_log — JSONL stream, one event per line:
        //     {"ts":N,"ev":"connect","host":"...","port":443,"strategy":"autopilot:split-2"}
        //     {"ts":N,"ev":"outcome","host":"...","result":"ok|rst|timeout|connect_fail"}
        //     {"ts":N,"ev":"close","host":"...","c2s":N,"s2c":N,"ms":N}
        //   stats_file — full stats JSON, atomically rewritten every 2s.
        std::string events_log;
        std::string stats_file;
    };

    DesyncProxy();
    ~DesyncProxy();

    DesyncProxy(const DesyncProxy&) = delete;
    DesyncProxy& operator=(const DesyncProxy&) = delete;

    bool start(const Config& cfg);
    void stop();
    bool running() const;
    uint16_t bound_port() const;   // actual bound port (valid after start)
    ProxyStats stats() const;

    // ── Static helpers (pure, unit-testable) ──

    // Resolve zapret split positions to absolute byte offsets within payload.
    // tls/http context extracted automatically; unknown markers fall back.
    static std::vector<size_t> resolve_split_positions(
        const std::vector<DPI::ZSplitPos>& positions,
        const uint8_t* payload, size_t payload_len);

    // Build the segment list (offsets) from a base DPIConfig.
    static std::vector<size_t> split_offsets_from_config(
        const DPI::DPIConfig& cfg, const uint8_t* payload, size_t payload_len);

    // Pick the first chain matching (proto, dst_port, host).
    // hostlist patterns are expected pre-loaded in chain_hostlists (parallel
    // vectors: chain_hostlists[i] = patterns for chains[i].hostlist file).
    static const DPI::ZapretChain* select_chain(
        const std::vector<DPI::ZapretChain>& chains,
        const std::vector<std::vector<std::string>>& chain_hostlist_patterns,
        DPI::ZProto proto, uint16_t dst_port, const std::string& host);

private:
    class Impl;
    std::shared_ptr<Impl> impl_;
};

} // namespace ncp
