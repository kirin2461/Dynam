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
    std::string fail_reason;      // "rst" | "timeout" | "connect" | "proxy"
    int latency_ms = 0;
};

struct BlockcheckStrategyResult {
    std::string strategy;
    std::string description;
    std::vector<BlockcheckProbe> probes;
    int success_count = 0;
    int total = 0;
    double avg_latency_ms = 0.0;
    long score = 0;
};

struct BlockcheckReport {
    std::vector<BlockcheckStrategyResult> results;
    std::string best_strategy;
    std::string best_description;
    DPI::DPIConfig best_config;
    DPI::ZapretChain best_chain;
    bool best_uses_chain = false;
    int duration_ms = 0;
};

class BlockChecker {
public:
    struct Config {
        std::vector<std::string> domains;
        std::vector<BlockcheckStrategy> strategies;  // empty → default_strategies()
        int timeout_ms = 5000;
        // progress(strategy_name, domain, ok) — called after each probe
        std::function<void(const std::string&, const std::string&, bool)> progress_cb;
        // cancel check — return true to abort
        std::function<bool()> cancel_cb;
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
