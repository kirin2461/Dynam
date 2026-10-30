#pragma once

// ═══════════════════════════════════════════════════════════════════════════
// NCP Blockcheck — automatic DPI-bypass strategy selection (zapret blockcheck
// equivalent).
//
// For each candidate strategy a temporary local SOCKS5 desync proxy is
// started (no admin needed), and each test domain is probed with a real TLS
// ClientHello through it. The strategy with the most successful probes
// (tie-break: lowest latency) wins.
//
// Output is a JSON report for CLI/GUI consumption.
// ═══════════════════════════════════════════════════════════════════════════

#include "ncp_dpi.hpp"
#include "ncp_dpi_zapret.hpp"

#include <string>
#include <vector>
#include <functional>
#include <cstdint>

namespace ncp {

struct BlockcheckStrategy {
    std::string name;
    std::string description;
    DPI::DPIConfig config;        // base config strategy
    DPI::ZapretChain chain;       // chain strategy (markers: midsld, sniext...)
    bool use_chain = false;
    bool is_direct = false;       // baseline probe without proxy
};

struct BlockcheckProbe {
    std::string domain;
    bool ok = false;
    // "rst" | "timeout" | "dns" | "connect" | "proxy" | "tls" | "unstable"
    std::string fail_reason;
    int latency_ms = 0;
    int round = 0;                // 0 = discovery, >0 = confirmation round
};

struct BlockcheckStrategyResult {
    std::string strategy;
    std::string description;
    std::vector<BlockcheckProbe> probes;
    std::vector<BlockcheckProbe> validation_probes;
    int success_count = 0;
    int total = 0;
    double avg_latency_ms = 0.0;
    long score = 0;
    bool validation_attempted = false;
    bool validated = false;       // at least one domain stable in every round
};

struct BlockcheckReport {
    std::vector<BlockcheckStrategyResult> results;
    std::string best_strategy;
    std::string best_description;
    DPI::DPIConfig best_config;
    DPI::ZapretChain best_chain;
    bool best_uses_chain = false;
    bool best_validated = false;
    bool early_exit_taken = false;
    size_t parallel_probes = 1;
    uint32_t validation_rounds = 0;
    int duration_ms = 0;
};

class BlockChecker {
public:
    struct Config {
        std::vector<std::string> domains;
        std::vector<BlockcheckStrategy> strategies;  // empty → default_strategies()
        int timeout_ms = 5000;                 // clamped to 1..120000 ms per I/O wait
        // Domains are checked concurrently inside one strategy. Strategies
        // remain sequential so their temporary proxies cannot interfere.
        size_t max_parallel_probes = 4;       // clamped to 1..32
        // Additional confirmation rounds for the best initial candidates.
        // A domain counts only when it succeeds in discovery and every round.
        uint32_t validation_rounds = 1;       // clamped to 0..8; 0 = single-pass
        size_t max_validation_candidates = 3; // bounds worst-case extra work
        // Stop after the first non-direct strategy that succeeds for every
        // domain in discovery and all confirmation rounds.
        bool early_exit = true;
        // Resolve probe targets via DNS-over-HTTPS inside the temporary
        // probing proxies (needed on networks with poisoned/filtered DNS).
        bool use_doh = false;
        // progress(strategy_name, domain, ok) — serialized across workers.
        std::function<void(const std::string&, const std::string&, bool)> progress_cb;
        // cancel check — return true to abort; may be called concurrently by
        // workers, so the callback itself must be thread-safe.
        std::function<bool()> cancel_cb;
        // Deterministic test hook. When set, no sockets or proxies are used.
        std::function<BlockcheckProbe(const BlockcheckStrategy&,
                                      const std::string&, int)> probe_fn;
    };

    BlockcheckReport run(const Config& cfg);

    static std::vector<BlockcheckStrategy> default_strategies();
    static std::vector<std::string> default_domains();

    static std::string report_to_json(const BlockcheckReport& r);

    // ── Probing primitives (exposed for tests / GUI) ──

    // Minimal TLS ClientHello carrying the given SNI.
    static std::vector<uint8_t> build_client_hello(const std::string& sni);

    // TLS-probe domain:443 through SOCKS5 proxy at 127.0.0.1:proxy_port.
    static BlockcheckProbe probe_via_socks5(uint16_t proxy_port,
                                            const std::string& domain,
                                            int timeout_ms);
    // Direct TLS-probe (no proxy) — baseline.
    static BlockcheckProbe probe_direct(const std::string& domain, int timeout_ms);

    // Serialize the winning strategy into a JSON profile fragment
    // (consumed by `ncp run --profile` and the GUI).
    static std::string best_strategy_to_profile_json(const BlockcheckReport& r);
};

} // namespace ncp
