#include "ncp_quic_director_adapter.hpp"

#include <algorithm>
#include <cstring>
#include <deque>
#include <limits>
#include <unordered_map>
#include <utility>

namespace ncp {

namespace {

void put_u32(std::vector<uint8_t>& out, uint32_t value) {
    out.push_back(static_cast<uint8_t>(value & 0xffu));
    out.push_back(static_cast<uint8_t>((value >> 8u) & 0xffu));
    out.push_back(static_cast<uint8_t>((value >> 16u) & 0xffu));
    out.push_back(static_cast<uint8_t>((value >> 24u) & 0xffu));
}

uint32_t get_u32(const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) |
           (static_cast<uint32_t>(p[1]) << 8u) |
           (static_cast<uint32_t>(p[2]) << 16u) |
           (static_cast<uint32_t>(p[3]) << 24u);
}

} // namespace

struct NcpQuicDirectorAdapter::Impl {
    struct ConnectionState {
        std::deque<NcpConnectionDirector::Egress> pending;
        bool inflight = false;
        uint64_t response_stream_id = 0;
        // R17-03: server-side per-connection failure. A failed connection is
        // isolated (its director session removed, its egress discarded)
        // without affecting any other connection.
        bool failed = false;
        std::string error;
    };

    Impl(RealQuicEndpoint& e, NcpConnectionDirector& d, Config c)
        : endpoint(e), director(d), cfg(std::move(c)) {}

    RealQuicEndpoint& endpoint;
    NcpConnectionDirector& director;
    Config cfg;
    bool valid = false;
    std::string config_error;
    std::string last_error;
    Stats st;
    std::unordered_map<SessionId, ConnectionState> connections;

    bool client() const {
        return endpoint.role() == RealQuicEndpoint::Role::Client;
    }

    /// Adapter-wide sticky failure (client role, or endpoint-level faults).
    bool fail(const std::string& message, uint64_t Stats::* counter) {
        if (last_error.empty()) last_error = message;
        ++(st.*counter);
        return false;
    }

    /// Failure attributable to one connection. On the client (a single
    /// connection) this is the adapter-wide sticky failure. On the server
    /// only that connection is failed; returns true so pump() keeps serving
    /// every other connection.
    bool fail_connection(SessionId id, ConnectionState& state,
                         const std::string& message,
                         uint64_t Stats::* counter) {
        if (client()) return fail(message, counter);
        ++(st.*counter);
        if (!state.failed) {
            state.failed = true;
            state.error = message;
            state.pending.clear();
            state.inflight = false;
            state.response_stream_id = 0;
            ++st.connections_failed;
            if (director.has_session(id)) director.remove_session(id);
        }
        return true;
    }

    std::string transport_detail(const std::string& operation) const {
        const std::string detail = endpoint.last_error();
        return operation + (detail.empty() ? "" : ": " + detail);
    }

    bool transport_fail(const std::string& operation) {
        return fail(transport_detail(operation), &Stats::transport_errors);
    }

    /// Move every polled egress item into its connection queue. An overflow
    /// fails only the overflowing connection; items for other connections
    /// that director.poll() already removed are never discarded.
    bool collect(uint64_t now_ms) {
        auto egress = director.poll(now_ms);
        bool ok = true;
        for (auto& item : egress) {
            const SessionId id = item.session_id;
            auto& state = connections[id];
            if (state.failed) continue;
            if (state.pending.size() >= cfg.max_pending_egress) {
                if (!fail_connection(id, state,
                                     "QUIC director pending egress bound exceeded",
                                     &Stats::pending_overflow))
                    ok = false;
                continue;
            }
            state.pending.push_back(std::move(item));
        }
        return ok;
    }

    /// Returns false with `why` set when the queued egress cannot be encoded.
    bool encode_next(ConnectionState& state, std::vector<uint8_t>& wire,
                     size_t& count, std::string& why) {
        count = 0;
        wire.clear();
        wire.reserve(std::min<size_t>(cfg.max_bundle_bytes, 4096));
        put_u32(wire, 0); // patched after the count is known
        for (const auto& item : state.pending) {
            if (count >= cfg.max_bundle_datagrams) break;
            if (item.bytes.empty() ||
                item.bytes.size() > std::numeric_limits<uint32_t>::max()) {
                why = "QUIC director produced an invalid empty/oversized datagram";
                return false;
            }
            const size_t extra = 4 + item.bytes.size();
            if (extra > cfg.max_bundle_bytes ||
                wire.size() > cfg.max_bundle_bytes - extra) {
                break;
            }
            put_u32(wire, static_cast<uint32_t>(item.bytes.size()));
            wire.insert(wire.end(), item.bytes.begin(), item.bytes.end());
            ++count;
        }
        if (count == 0 && !state.pending.empty()) {
            why = "QUIC director datagram does not fit bundle budget";
            return false;
        }
        const uint32_t n = static_cast<uint32_t>(count);
        wire[0] = static_cast<uint8_t>(n & 0xffu);
        wire[1] = static_cast<uint8_t>((n >> 8u) & 0xffu);
        wire[2] = static_cast<uint8_t>((n >> 16u) & 0xffu);
        wire[3] = static_cast<uint8_t>((n >> 24u) & 0xffu);
        return true;
    }

    /// Returns false with `why` set for a malformed bundle; nothing from a
    /// malformed bundle is delivered (atomic).
    bool decode(const std::vector<uint8_t>& wire,
                std::vector<std::vector<uint8_t>>& datagrams,
                std::string& why) {
        datagrams.clear();
        if (wire.size() > cfg.max_bundle_bytes || wire.size() < 4) {
            why = "QUIC director bundle has invalid size";
            return false;
        }
        const uint32_t count = get_u32(wire.data());
        if (count > cfg.max_bundle_datagrams) {
            why = "QUIC director bundle exceeds datagram bound";
            return false;
        }
        size_t offset = 4;
        datagrams.reserve(count);
        for (uint32_t i = 0; i < count; ++i) {
            if (offset > wire.size() || wire.size() - offset < 4) {
                why = "QUIC director bundle has truncated length";
                datagrams.clear();
                return false;
            }
            const uint32_t len = get_u32(wire.data() + offset);
            offset += 4;
            if (len == 0 || len > wire.size() - offset) {
                why = "QUIC director bundle has invalid datagram length";
                datagrams.clear();
                return false;
            }
            datagrams.emplace_back(wire.begin() + static_cast<ptrdiff_t>(offset),
                                   wire.begin() + static_cast<ptrdiff_t>(offset + len));
            offset += len;
        }
        if (offset != wire.size()) {
            why = "QUIC director bundle has trailing bytes";
            datagrams.clear();
            return false;
        }
        return true;
    }

    void account_sent(size_t count, bool response) {
        ++st.bundles_sent;
        if (response)
            ++st.responses_sent;
        else
            ++st.requests_sent;
        if (count == 0) ++st.empty_bundles_sent;
        st.datagrams_sent += count;
    }

    bool send_pending(SessionId id, ConnectionState& state, uint64_t now_ms) {
        (void)now_ms;
        if (state.failed || state.inflight || state.pending.empty()) return true;
        std::vector<uint8_t> wire;
        size_t count = 0;
        std::string why;
        if (!encode_next(state, wire, count, why))
            return fail_connection(id, state, why, &Stats::transport_errors);
        uint64_t stream_id = 0;
        const uint64_t connection_id = client() ? 0 : id;
        if (!endpoint.send_message(wire, &stream_id, connection_id))
            return fail_connection(
                id, state, transport_detail("QUIC director request send failed"),
                &Stats::transport_errors);
        state.pending.erase(state.pending.begin(),
                            state.pending.begin() + static_cast<ptrdiff_t>(count));
        state.inflight = true;
        state.response_stream_id = stream_id;
        account_sent(count, false);
        return true;
    }

    bool respond(SessionId id, ConnectionState& state,
                 const RealQuicEndpoint::Message& message) {
        if (state.failed) return true;
        std::vector<uint8_t> wire;
        size_t count = 0;
        std::string why;
        if (!encode_next(state, wire, count, why))
            return fail_connection(id, state, why, &Stats::transport_errors);
        if (!endpoint.respond(message.connection_id, message.stream_id, wire))
            return fail_connection(
                id, state, transport_detail("QUIC director response send failed"),
                &Stats::transport_errors);
        state.pending.erase(state.pending.begin(),
                            state.pending.begin() + static_cast<ptrdiff_t>(count));
        account_sent(count, true);
        return true;
    }
};

NcpQuicDirectorAdapter::NcpQuicDirectorAdapter(
    RealQuicEndpoint& endpoint, NcpConnectionDirector& director)
    : NcpQuicDirectorAdapter(endpoint, director, Config{}) {}

NcpQuicDirectorAdapter::NcpQuicDirectorAdapter(
    RealQuicEndpoint& endpoint, NcpConnectionDirector& director, Config cfg)
    : impl_(std::make_unique<Impl>(endpoint, director, std::move(cfg))) {
    auto fail = [&](const std::string& message) {
        impl_->valid = false;
        impl_->config_error = message;
    };
    if (!director.is_valid()) {
        fail("QUIC director adapter: director is invalid: " +
             director.config_error());
    } else if ((endpoint.role() == RealQuicEndpoint::Role::Client) !=
               (director.role() == NcpMimicrySession::Role::Client)) {
        fail("QUIC director adapter: endpoint/director roles differ");
    } else if (impl_->cfg.client_session_id == 0) {
        fail("QUIC director adapter: client_session_id must be non-zero");
    } else if (impl_->cfg.max_pending_egress == 0) {
        fail("QUIC director adapter: max_pending_egress must be >= 1");
    } else if (impl_->cfg.max_bundle_datagrams == 0 ||
               impl_->cfg.max_bundle_datagrams >
                   std::numeric_limits<uint32_t>::max()) {
        fail("QUIC director adapter: invalid max_bundle_datagrams");
    } else if (impl_->cfg.max_bundle_bytes < 8 ||
               impl_->cfg.max_bundle_bytes >
                   std::numeric_limits<uint32_t>::max()) {
        fail("QUIC director adapter: invalid max_bundle_bytes");
    } else {
        impl_->valid = true;
    }
}

NcpQuicDirectorAdapter::~NcpQuicDirectorAdapter() = default;

bool NcpQuicDirectorAdapter::is_valid() const { return impl_->valid; }

const std::string& NcpQuicDirectorAdapter::config_error() const {
    return impl_->config_error;
}

NcpQuicDirectorAdapter::Error NcpQuicDirectorAdapter::start_handshake(
    uint64_t now_ms) {
    if (!impl_->valid || !impl_->last_error.empty()) return Error::INVALID_STATE;
    if (!impl_->client()) return Error::INVALID_STATE;
    const SessionId id = impl_->cfg.client_session_id;
    if (!impl_->director.has_session(id)) {
        const Error err = impl_->director.add_session(id);
        if (err != Error::NONE) return err;
    }
    return impl_->director.start_handshake(id, now_ms);
}

NcpQuicDirectorAdapter::Error NcpQuicDirectorAdapter::send_application(
    SessionId id, const std::vector<uint8_t>& payload, uint64_t now_ms) {
    if (!impl_->valid || !impl_->last_error.empty()) return Error::INVALID_STATE;
    if (id == 0 || (impl_->client() && id != impl_->cfg.client_session_id))
        return Error::NO_SUCH_SESSION;
    const auto it = impl_->connections.find(id);
    if (it != impl_->connections.end() && it->second.failed)
        return Error::INVALID_STATE;
    return impl_->director.send_application(id, payload, now_ms);
}

bool NcpQuicDirectorAdapter::pump(uint64_t now_ms, uint32_t recv_timeout_ms) {
    if (!impl_->valid || !impl_->last_error.empty()) return false;
    if (!impl_->endpoint.is_running())
        return impl_->transport_fail("QUIC director endpoint is not running");
    if (!impl_->collect(now_ms)) return false;
    for (auto& kv : impl_->connections)
        if (!impl_->send_pending(kv.first, kv.second, now_ms)) return false;

    RealQuicEndpoint::Message message;
    if (!impl_->endpoint.recv_message(message, recv_timeout_ms)) return true;
    const SessionId id = impl_->client() ? impl_->cfg.client_session_id
                                         : message.connection_id;
    if (id == 0) {
        // Endpoint-level fault on the client; on the server a bogus id is
        // just dropped (no connection to attribute it to).
        if (impl_->client())
            return impl_->fail("QUIC director received invalid connection id",
                               &Stats::decode_errors);
        ++impl_->st.decode_errors;
        return true;
    }
    auto& state = impl_->connections[id];
    if (state.failed) {
        // R17-03: a failed connection's traffic is ignored; others proceed.
        ++impl_->st.messages_ignored_failed;
        return true;
    }
    const bool is_response = state.inflight &&
                             message.stream_id == state.response_stream_id;

    std::vector<std::vector<uint8_t>> datagrams;
    std::string why;
    if (!impl_->decode(message.payload, datagrams, why))
        return impl_->fail_connection(id, state, why, &Stats::decode_errors);
    if (is_response) {
        state.inflight = false;
        state.response_stream_id = 0;
    }
    for (const auto& bytes : datagrams)
        impl_->director.on_datagram(id, bytes, now_ms);
    ++impl_->st.bundles_received;
    impl_->st.datagrams_received += datagrams.size();

    if (!impl_->collect(now_ms)) return false;
    if (!is_response && !impl_->respond(id, state, message)) return false;
    return true;
}

std::optional<std::string> NcpQuicDirectorAdapter::connection_error(
    SessionId id) const {
    const auto it = impl_->connections.find(id);
    if (it == impl_->connections.end() || !it->second.failed)
        return std::nullopt;
    return it->second.error;
}

std::optional<NcpConnectionDirector::AppData>
NcpQuicDirectorAdapter::next_application_data() {
    return impl_->director.next_application_data();
}

bool NcpQuicDirectorAdapter::has_inflight(SessionId id) const {
    const auto it = impl_->connections.find(id);
    return it != impl_->connections.end() && it->second.inflight;
}

size_t NcpQuicDirectorAdapter::pending_egress(SessionId id) const {
    const auto it = impl_->connections.find(id);
    return it == impl_->connections.end() ? 0 : it->second.pending.size();
}

const std::string& NcpQuicDirectorAdapter::last_error() const {
    return impl_->last_error;
}

NcpQuicDirectorAdapter::Stats NcpQuicDirectorAdapter::stats() const {
    return impl_->st;
}

} // namespace ncp
