#pragma once

/**
 * @file ncp_quic_director_adapter.hpp
 * @brief Production poll-loop binding between RealQuicEndpoint and
 *        NcpConnectionDirector.
 *
 * RealQuicEndpoint exposes one complete message per reliable bidirectional
 * stream. Independent QUIC streams do not preserve ordering, so Dynam
 * datagrams are carried in bounded, length-prefixed bundles. Each direction
 * has at most one request stream in flight per connection; every request is
 * answered on that same stream with the peer's next bundle (possibly empty).
 * Consequently H/C/E datagrams from one director are applied on the peer in
 * exactly the order emitted by NcpConnectionDirector::poll().
 *
 * The adapter owns neither endpoint nor director and creates no threads.
 * All calls must run on the owner's single I/O thread. The endpoint must be
 * started and connected by the caller. Malformed bundles, queue overflow and
 * transport failures are sticky fatal adapter errors: no partial bundle is
 * delivered and there is no plaintext or alternate-transport fallback.
 */

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "ncp_connection_director.hpp"
#include "ncp_real_quic.hpp"

namespace ncp {

class NcpQuicDirectorAdapter {
public:
    using SessionId = NcpConnectionDirector::SessionId;
    using Error = NcpConnectionDirector::Error;

    struct Config {
        /// Director registry key for the single client-side QUIC connection.
        SessionId client_session_id = 1;
        /// Bounds are per connection for pending egress and per wire bundle.
        size_t max_pending_egress = 256;
        size_t max_bundle_datagrams = 64;
        size_t max_bundle_bytes = 256 * 1024;
    };

    struct Stats {
        uint64_t bundles_sent = 0;
        uint64_t bundles_received = 0;
        uint64_t requests_sent = 0;
        uint64_t responses_sent = 0;
        uint64_t empty_bundles_sent = 0;
        uint64_t datagrams_sent = 0;
        uint64_t datagrams_received = 0;
        uint64_t transport_errors = 0;
        uint64_t decode_errors = 0;
        uint64_t pending_overflow = 0;
    };

    NcpQuicDirectorAdapter(RealQuicEndpoint& endpoint,
                           NcpConnectionDirector& director);
    NcpQuicDirectorAdapter(RealQuicEndpoint& endpoint,
                           NcpConnectionDirector& director,
                           Config cfg);
    ~NcpQuicDirectorAdapter();

    NcpQuicDirectorAdapter(const NcpQuicDirectorAdapter&) = delete;
    NcpQuicDirectorAdapter& operator=(const NcpQuicDirectorAdapter&) = delete;

    bool is_valid() const;
    const std::string& config_error() const;

    /// Client only. Creates client_session_id when needed and schedules H.
    Error start_handshake(uint64_t now_ms);

    /// Client passes client_session_id; server passes accepted connection_id.
    Error send_application(SessionId id, const std::vector<uint8_t>& payload,
                           uint64_t now_ms);

    /// Poll director, send at most one new request and process at most one
    /// inbound QUIC message. A receive timeout is normal and returns true.
    /// False is a sticky fatal error; inspect last_error() and close the
    /// endpoint rather than retrying on another transport.
    bool pump(uint64_t now_ms, uint32_t recv_timeout_ms);

    std::optional<NcpConnectionDirector::AppData> next_application_data();

    bool has_inflight(SessionId id) const;
    size_t pending_egress(SessionId id) const;
    const std::string& last_error() const;
    Stats stats() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace ncp
