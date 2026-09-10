#pragma once

/**
 * @file ncp_cps.hpp
 * @brief CPS chains (AWG 3.1 I1-I5 analogue) — pre-handshake fake packet
 *        sequences against active probing.
 *
 * AmneziaWG 3.1 sends fake "signature" packets (DNS/QUIC-like) before the
 * real handshake, so a DPI system that replays or fingerprints the first
 * bytes of a flow sees plausible benign protocols instead of a fixed
 * handshake. This module implements the same concept for NCP as a small
 * chain-description language:
 *
 *   chain spec: steps separated by ';', each step one of:
 *     dns:<domain>   — fake DNS A-query for <domain> (random txid)
 *     quic[:<sni>]   — fake QUIC Initial (long header, random conn ids)
 *     tls:<domain>   — fake TLS 1.2/1.3 ClientHello with SNI <domain>
 *     hex:<hexbytes> — literal bytes
 *     wait:<ms>      — pause before the next step (may be a range "a-b")
 *
 * Example: "dns:yandex.ru;wait:20-80;quic;tls:mail.ru"
 *
 * Chains are executed over UDP (the transport used by port-hopping) via
 * execute_chain_udp(); a TCP variant is provided for TLS-looking steps.
 *
 * No exceptions cross the API; builders return empty vectors on bad input.
 */

#include <cstdint>
#include <cstddef>
#include <optional>
#include <string>
#include <vector>

namespace ncp {
namespace cps {

enum class StepKind : uint8_t {
    DNS_QUERY,
    QUIC_INITIAL,
    TLS_CLIENT_HELLO,
    RAW_BYTES,
    WAIT
};

struct CpsStep {
    StepKind kind = StepKind::RAW_BYTES;
    std::string arg;                    // domain / hex string / empty
    uint32_t wait_min_ms = 0;           // WAIT step: fixed or range start
    uint32_t wait_max_ms = 0;           // WAIT step: range end (0 = fixed)
};

struct CpsChain {
    std::vector<CpsStep> steps;

    /// Parse a chain spec (see file docstring). nullopt on syntax error.
    static std::optional<CpsChain> parse(const std::string& spec);

    /// Back to canonical text form (for logs/config round-trips).
    std::string to_string() const;
};

/// Build the wire bytes for one packet step (CSPRNG-driven fields).
/// Returns an empty vector for WAIT steps or invalid args.
std::vector<uint8_t> build_packet(const CpsStep& step);

/// Build a fake DNS A-query wire packet for `domain`.
std::vector<uint8_t> build_dns_query(const std::string& domain);

/// Build a fake QUIC Initial (>= 1200 bytes, random conn ids/payload).
std::vector<uint8_t> build_quic_initial(const std::string& sni);

/// Build a fake TLS ClientHello record with SNI `domain`.
std::vector<uint8_t> build_tls_client_hello(const std::string& domain);

/// Decode a hex string (case-insensitive, optional spaces). Empty on error.
std::vector<uint8_t> hex_decode(const std::string& hex);

/// Execute the chain over UDP to host:port (each packet step = 1 datagram,
/// WAIT steps sleep). Returns false on socket/send errors; err is set.
bool execute_chain_udp(const CpsChain& chain,
                       const std::string& host, uint16_t port,
                       std::string* err = nullptr);

/// Execute the chain over a connected TCP stream to host:port.
bool execute_chain_tcp(const CpsChain& chain,
                       const std::string& host, uint16_t port,
                       std::string* err = nullptr);

} // namespace cps
} // namespace ncp
