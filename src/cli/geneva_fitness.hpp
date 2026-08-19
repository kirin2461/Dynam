#pragma once

// ═══════════════════════════════════════════════════════════════════════════
// Geneva GA fitness evaluator — REAL network probes (CLI side).
//
// Lives in src/cli (not src/core) on purpose: the core library exposes the
// FitnessEvaluator hook and stays I/O-free; the CLI provides the probing
// implementation so `ncp run --geneva-evolve` actually measures strategies.
//
// The evaluator opens a real TCP connection to the probe target, sends a
// TLS ClientHello transformed by the candidate strategy (via a PRIVATE
// GenevaEngine instance — thread-safe, no shared stats), and waits for a
// ServerHello. Works on POSIX (poll/fcntl) and Windows (WSAPoll/ioctlsocket).
// ═══════════════════════════════════════════════════════════════════════════

#include "ncp_geneva_ga.hpp"

#include <cstdint>
#include <string>

namespace ncp {
namespace cli {

/// Real network fitness probe for the Geneva genetic algorithm.
///
/// 1. Builds a well-formed TLS 1.2/1.3 ClientHello with SNI = target host
///    (SNI omitted for IP literals).
/// 2. Applies `strategy` through a private DPI::GenevaEngine, producing the
///    packet sequence the live DPI path would emit.
/// 3. Opens a non-blocking TCP connection to (target_host, target_port)
///    within timeout_ms and sends the produced packets in order. When the
///    strategy contains a TAMPER_TTL step, the FIRST produced packet is sent
///    with a low IP_TTL (the Geneva "fake that poisons DPI but dies before
///    the server" pattern); the rest go out with normal TTL.
/// 4. Waits up to the remaining timeout for any response bytes.
///
/// Never throws: any failure (resolve/connect/RST/timeout/exception) returns
/// connected=false so a bad probe can never crash `ncp run`.
DPI::FitnessResult geneva_probe_fitness(const DPI::GenevaStrategy& strategy,
                                        const std::string& target_host,
                                        uint16_t target_port,
                                        int timeout_ms) noexcept;

} // namespace cli
} // namespace ncp
