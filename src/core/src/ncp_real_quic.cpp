// ═══════════════════════════════════════════════════════════════════════════
// NCP REAL QUIC transport (G4) — implementation over the MsQuic C API.
// See ncp_real_quic.hpp for the contract. No global state; every instance
// owns its MsQuic handles and shuts them down in strict reverse order:
//   connections (shutdown -> SHUTDOWN_COMPLETE -> close)
//   listener stop/close, configuration close, registration close, MsQuicClose.
// ═══════════════════════════════════════════════════════════════════════════

#include "ncp_real_quic.hpp"

#include <atomic>
#include <condition_variable>
#include <cstdio>
#include <cstring>
#include <deque>
#include <map>
#include <mutex>
#include <unordered_map>

#include <arpa/inet.h>

// Pinned MsQuic 2.6.3 headers (third_party/msquic/include).
#include "msquic.h"

namespace ncp {

namespace {

std::string quic_addr_to_string(const QUIC_ADDR& a) {
    char ip[INET6_ADDRSTRLEN] = {0};
    uint16_t port = 0;
    if (a.Ip.sa_family == QUIC_ADDRESS_FAMILY_INET) {
        inet_ntop(AF_INET, &a.Ipv4.sin_addr, ip, sizeof(ip));
        port = ntohs(a.Ipv4.sin_port);
    } else if (a.Ip.sa_family == QUIC_ADDRESS_FAMILY_INET6) {
        inet_ntop(AF_INET6, &a.Ipv6.sin6_addr, ip, sizeof(ip));
        port = ntohs(a.Ipv6.sin6_port);
    } else {
        return "<unspec>";
    }
    char out[INET6_ADDRSTRLEN + 8];
    std::snprintf(out, sizeof(out), "%s:%u", ip, static_cast<unsigned>(port));
    return out;
}

} // namespace

// ---------------------------------------------------------------------------
// Per-stream state. Heap allocated, owned by the endpoint's stream map.
// The QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE event is the last callback a
// stream ever delivers; we close the handle and free the state there, which
// guarantees no callback can ever reference freed memory.
// ---------------------------------------------------------------------------
struct RealQuicEndpoint::Impl {
    struct StreamState {
        Impl* ep = nullptr;
        HQUIC stream = nullptr;
        uint64_t conn_id = 0;
        std::atomic<uint64_t> id{UINT64_MAX};  // QUIC stream id (once known)
        std::vector<uint8_t> rx;       // receive accumulation buffer
        bool fin_seen = false;
    };

    Config cfg;

    const QUIC_API_TABLE* api = nullptr;
    HQUIC registration = nullptr;
    HQUIC configuration = nullptr;
    HQUIC listener = nullptr;          // server
    HQUIC connection = nullptr;        // client (single fixed connection)

    // Keeps ALPN / credential string storage stable for MsQuic.
    QUIC_BUFFER alpn{};
    QUIC_CERTIFICATE_FILE cert_files{};

    mutable std::mutex mu;
    std::condition_variable cv;

    bool running = false;
    bool stopping = false;
    bool connected = false;            // client handshake done (or server: >=1 client)
    bool handshake_failed = false;
    std::string last_error;

    // Client shutdown synchronization.
    bool client_shutdown_complete = false;

    // Server: accepted connections.
    uint64_t next_conn_id = 0;
    std::unordered_map<uint64_t, HQUIC> server_conns;
    std::deque<uint64_t> connected_queue;   // handshaken server conn ids

    // All live streams, keyed by (conn_id, stream_id).
    std::map<std::pair<uint64_t, uint64_t>, StreamState*> streams;

    // Bounded inbound queues.
    std::deque<Message> inbound_messages;
    std::deque<Datagram> inbound_datagrams;

    Stats st;
    uint16_t datagram_max_send = 0;
    uint16_t bound_port = 0;
    std::string bound_local_str;
    std::string peer_str;

    explicit Impl(Config c) : cfg(std::move(c)) {}

    // ------------------------------------------------------------------
    // Error recording (callable from any MsQuic callback thread).
    // ------------------------------------------------------------------
    void set_error_locked(const char* what, QUIC_STATUS status) {
        char buf[160];
        std::snprintf(buf, sizeof(buf), "%s (QUIC_STATUS=0x%x)", what,
                      static_cast<unsigned>(status));
        last_error = buf;
    }
    void set_error(const char* what, QUIC_STATUS status) {
        std::lock_guard<std::mutex> lk(mu);
        set_error_locked(what, status);
    }

    // ------------------------------------------------------------------
    // Send helpers. Every send copies the payload into a heap buffer that is
    // freed exactly once: either on immediate send failure, or in the
    // completion event (SEND_COMPLETE / final DATAGRAM_SEND_STATE_CHANGED).
    // ------------------------------------------------------------------
    // MsQuic does NOT copy the QUIC_BUFFER array or the payload at
    // StreamSend/DatagramSend time: both must stay valid until the
    // completion event. This heap block owns both and is freed exactly once
    // in the completion callback (or on synchronous send failure).
    struct SendCtx {
        QUIC_BUFFER qbuf;
        uint8_t data[1];  // flexible tail: payload bytes
    };
    static SendCtx* make_send_ctx(const uint8_t* data, size_t len) {
        auto* raw = new (std::nothrow) uint8_t[sizeof(SendCtx) + (len ? len : 1)];
        if (!raw) return nullptr;
        auto* ctx = reinterpret_cast<SendCtx*>(raw);
        if (len) std::memcpy(ctx->data, data, len);
        ctx->qbuf.Buffer = ctx->data;
        ctx->qbuf.Length = static_cast<uint32_t>(len);
        return ctx;
    }
    static void free_send_ctx(void* p) { delete[] reinterpret_cast<uint8_t*>(p); }

    // Does not lock mu and does not touch last_error: safe to call with mu
    // held (StreamSend only queues an operation; it never blocks).
    bool do_stream_send(HQUIC stream, const uint8_t* data, size_t len,
                        bool fin, uint64_t* bytes_out, QUIC_STATUS* err_out) {
        SendCtx* ctx = make_send_ctx(data, len);
        if (!ctx) return false;
        QUIC_STATUS s = api->StreamSend(stream, &ctx->qbuf, 1,
                                        fin ? QUIC_SEND_FLAG_FIN : QUIC_SEND_FLAG_NONE,
                                        ctx);
        if (QUIC_FAILED(s)) {
            free_send_ctx(ctx);
            if (err_out) *err_out = s;
            return false;
        }
        if (bytes_out) *bytes_out = len;
        return true;
    }

    bool open_stream_and_send(HQUIC conn, uint64_t conn_id,
                              const std::vector<uint8_t>& payload,
                              uint64_t* stream_id_out) {
        auto* ss = new (std::nothrow) StreamState();
        if (!ss) return false;
        ss->ep = this;
        ss->conn_id = conn_id;

        HQUIC stream = nullptr;
        QUIC_STATUS s = api->StreamOpen(conn, QUIC_STREAM_OPEN_FLAG_NONE,
                                        &Impl::stream_cb, ss, &stream);
        if (QUIC_FAILED(s)) {
            delete ss;
            set_error("StreamOpen failed", s);
            return false;
        }
        ss->stream = stream;

        s = api->StreamStart(stream, QUIC_STREAM_START_FLAG_NONE);
        if (QUIC_FAILED(s)) {
            // Synchronous failure: no operation was queued, so no stream
            // callback will ever fire for ss. Safe to close + free here.
            api->StreamClose(stream);
            delete ss;
            set_error("StreamStart failed", s);
            return false;
        }

        uint64_t sent = 0;
        QUIC_STATUS send_err = QUIC_STATUS_SUCCESS;
        if (!do_stream_send(stream, payload.data(), payload.size(),
                            /*fin=*/true, &sent, &send_err)) {
            // StreamStart succeeded, so a START_COMPLETE callback may
            // already be in flight on a worker thread and references ss.
            // Abort the stream and let the guaranteed SHUTDOWN_COMPLETE
            // event close the handle and free ss exactly once.
            api->StreamShutdown(stream, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 0);
            set_error("StreamSend failed", send_err);
            return false;
        }
        // The stream is registered in the map when START_COMPLETE delivers
        // the QUIC stream id. send_message() waits for that id below.
        if (stream_id_out) {
            // Wait briefly for START_COMPLETE (fires on MsQuic worker thread).
            std::unique_lock<std::mutex> lk(mu);
            cv.wait_for(lk, std::chrono::milliseconds(5000),
                        [&] { return ss->id != UINT64_MAX || stopping; });
            *stream_id_out = ss->id;
        }
        std::lock_guard<std::mutex> lk(mu);
        st.bytes_sent += sent;
        return true;
    }

    void register_stream(StreamState* ss) {
        std::lock_guard<std::mutex> lk(mu);
        streams[{ss->conn_id, ss->id}] = ss;
        cv.notify_all();
    }

    void unregister_and_free_stream(StreamState* ss) {
        {
            std::lock_guard<std::mutex> lk(mu);
            if (ss->id != UINT64_MAX) {
                streams.erase({ss->conn_id, ss->id});
            }
        }
        api->StreamClose(ss->stream);
        delete ss;
    }

    void push_message(uint64_t conn_id, uint64_t stream_id,
                      std::vector<uint8_t>&& payload) {
        std::lock_guard<std::mutex> lk(mu);
        if (inbound_messages.size() >= cfg.max_inbound_messages) {
            ++st.messages_dropped_queue_full;
            return;
        }
        Message m;
        m.connection_id = conn_id;
        m.stream_id = stream_id;
        m.payload = std::move(payload);
        st.bytes_received += m.payload.size();
        ++st.messages_received;
        inbound_messages.push_back(std::move(m));
        cv.notify_all();
    }

    void push_datagram(uint64_t conn_id, const QUIC_BUFFER* b) {
        std::lock_guard<std::mutex> lk(mu);
        if (inbound_datagrams.size() >= cfg.max_inbound_datagrams) {
            ++st.datagrams_dropped_queue_full;
            return;
        }
        Datagram d;
        d.connection_id = conn_id;
        d.payload.assign(b->Buffer, b->Buffer + b->Length);
        ++st.datagrams_received;
        inbound_datagrams.push_back(std::move(d));
        cv.notify_all();
    }

    HQUIC find_connection(uint64_t conn_id) {
        // Client: the single fixed connection. Server: accepted conn map.
        if (cfg.role == Role::Client) return connection;
        std::lock_guard<std::mutex> lk(mu);
        auto it = server_conns.find(conn_id);
        return it == server_conns.end() ? nullptr : it->second;
    }

    // ------------------------------------------------------------------
    // MsQuic callbacks (static thunks; run on MsQuic worker threads).
    // ------------------------------------------------------------------
    static QUIC_STATUS QUIC_API stream_cb(HQUIC stream, void* ctx,
                                          QUIC_STREAM_EVENT* event) {
        auto* ss = static_cast<StreamState*>(ctx);
        Impl* ep = ss->ep;
        switch (event->Type) {
        case QUIC_STREAM_EVENT_START_COMPLETE:
            if (QUIC_SUCCEEDED(event->START_COMPLETE.Status)) {
                ss->id = event->START_COMPLETE.ID;
                ep->register_stream(ss);
            } else {
                ep->set_error("stream start rejected",
                              event->START_COMPLETE.Status);
            }
            break;

        case QUIC_STREAM_EVENT_RECEIVE: {
            const auto& r = event->RECEIVE;
            uint64_t total = 0;
            for (uint32_t i = 0; i < r.BufferCount; ++i) total += r.Buffers[i].Length;
            if (ep->cfg.max_message_size &&
                ss->rx.size() + total > ep->cfg.max_message_size) {
                // Oversized message: abort rather than buffer unboundedly.
                ep->api->StreamShutdown(stream, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 0);
                event->RECEIVE.TotalBufferLength = total;  // drain
                break;
            }
            for (uint32_t i = 0; i < r.BufferCount; ++i) {
                ss->rx.insert(ss->rx.end(), r.Buffers[i].Buffer,
                              r.Buffers[i].Buffer + r.Buffers[i].Length);
            }
            event->RECEIVE.TotalBufferLength = total;
            if (r.Flags & QUIC_RECEIVE_FLAG_FIN) {
                ss->fin_seen = true;
                // Resolve stream id for peer-started streams lazily.
                if (ss->id == UINT64_MAX) {
                    QUIC_UINT62 id = 0;
                    uint32_t sz = sizeof(id);
                    if (QUIC_SUCCEEDED(ep->api->GetParam(
                            stream, QUIC_PARAM_STREAM_ID, &sz, &id))) {
                        ss->id = id;
                        ep->register_stream(ss);
                    }
                }
                ep->push_message(ss->conn_id, ss->id, std::move(ss->rx));
                ss->rx.clear();
            }
            break;
        }

        case QUIC_STREAM_EVENT_SEND_COMPLETE:
            free_send_ctx(event->SEND_COMPLETE.ClientContext);
            break;

        case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
        case QUIC_STREAM_EVENT_PEER_RECEIVE_ABORTED:
        case QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE:
        case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
        case QUIC_STREAM_EVENT_PEER_ACCEPTED:
            break;

        case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
            // Final event for this stream: safe to close + free here.
            ep->unregister_and_free_stream(ss);
            break;

        default:
            break;
        }
        return QUIC_STATUS_SUCCESS;
    }

    static QUIC_STATUS QUIC_API connection_cb(HQUIC conn, void* ctx,
                                              QUIC_CONNECTION_EVENT* event) {
        auto* ep = static_cast<Impl*>(ctx);
        switch (event->Type) {
        case QUIC_CONNECTION_EVENT_CONNECTED: {
            std::lock_guard<std::mutex> lk(ep->mu);
            ep->connected = true;
            if (ep->cfg.role == Role::Server) {
                // Resolve this accepted connection's id and queue it.
                for (const auto& kv : ep->server_conns) {
                    if (kv.second == conn) {
                        ep->connected_queue.push_back(kv.first);
                        break;
                    }
                }
            }
            ep->cv.notify_all();
            break;
        }

        case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT: {
            std::lock_guard<std::mutex> lk(ep->mu);
            if (!ep->connected) ep->handshake_failed = true;
            ep->set_error_locked(
                "transport shutdown (TLS/QUIC layer rejected the peer; this "
                "is the expected path for plaintext garbage or bad certs)",
                event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status);
            ep->cv.notify_all();
            break;
        }

        case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER: {
            std::lock_guard<std::mutex> lk(ep->mu);
            char buf[96];
            std::snprintf(buf, sizeof(buf), "peer closed connection (0x%llx)",
                          static_cast<unsigned long long>(
                              event->SHUTDOWN_INITIATED_BY_PEER.ErrorCode));
            ep->last_error = buf;
            ep->cv.notify_all();
            break;
        }

        case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE: {
            // Final event for this connection. For accepted (server-side)
            // connections we close the handle right here — the documented
            // MsQuic pattern — so handles never leak and RegistrationClose
            // cannot hang. mu is held so shutdown() cannot race a
            // ConnectionShutdown against this close.
            HQUIC dead = nullptr;
            {
                std::lock_guard<std::mutex> lk(ep->mu);
                if (!event->SHUTDOWN_COMPLETE.HandshakeCompleted &&
                    !ep->connected) {
                    ep->handshake_failed = true;
                }
                if (ep->cfg.role == Role::Client) {
                    ep->connected = false;
                    ep->client_shutdown_complete = true;
                } else {
                    for (auto it = ep->server_conns.begin();
                         it != ep->server_conns.end(); ++it) {
                        if (it->second == conn) {
                            dead = it->second;
                            ep->server_conns.erase(it);
                            break;
                        }
                    }
                    ep->connected = !ep->server_conns.empty();
                }
                ep->cv.notify_all();
                if (dead) ep->api->ConnectionClose(dead);
            }
            break;
        }

        case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED: {
            auto* ss = new (std::nothrow) StreamState();
            if (!ss) {
                return QUIC_STATUS_OUT_OF_MEMORY;
            }
            ss->ep = ep;
            ss->stream = event->PEER_STREAM_STARTED.Stream;
            if (ep->cfg.role == Role::Server) {
                std::lock_guard<std::mutex> lk(ep->mu);
                for (const auto& kv : ep->server_conns) {
                    if (kv.second == conn) { ss->conn_id = kv.first; break; }
                }
            }
            ep->api->SetCallbackHandler(event->PEER_STREAM_STARTED.Stream,
                                        reinterpret_cast<void*>(&Impl::stream_cb),
                                        ss);
            break;
        }

        case QUIC_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED:
            ep->datagram_max_send =
                event->DATAGRAM_STATE_CHANGED.SendEnabled
                    ? event->DATAGRAM_STATE_CHANGED.MaxSendLength
                    : 0;
            break;

        case QUIC_CONNECTION_EVENT_DATAGRAM_RECEIVED: {
            uint64_t cid = 0;
            if (ep->cfg.role == Role::Server) {
                std::lock_guard<std::mutex> lk(ep->mu);
                for (const auto& kv : ep->server_conns) {
                    if (kv.second == conn) { cid = kv.first; break; }
                }
            }
            ep->push_datagram(cid, event->DATAGRAM_RECEIVED.Buffer);
            break;
        }

        case QUIC_CONNECTION_EVENT_DATAGRAM_SEND_STATE_CHANGED:
            if (QUIC_DATAGRAM_SEND_STATE_IS_FINAL(
                    event->DATAGRAM_SEND_STATE_CHANGED.State)) {
                free_send_ctx(event->DATAGRAM_SEND_STATE_CHANGED.ClientContext);
            }
            break;

        default:
            break;
        }
        return QUIC_STATUS_SUCCESS;
    }

    static QUIC_STATUS QUIC_API listener_cb(HQUIC /*listener*/, void* ctx,
                                            QUIC_LISTENER_EVENT* event) {
        auto* ep = static_cast<Impl*>(ctx);
        if (event->Type == QUIC_LISTENER_EVENT_NEW_CONNECTION) {
            HQUIC conn = event->NEW_CONNECTION.Connection;
            ep->api->SetCallbackHandler(
                conn, reinterpret_cast<void*>(&Impl::connection_cb), ep);
            QUIC_STATUS s =
                ep->api->ConnectionSetConfiguration(conn, ep->configuration);
            if (QUIC_FAILED(s)) {
                ep->set_error("ConnectionSetConfiguration failed", s);
                return s;  // rejects the connection
            }
            std::lock_guard<std::mutex> lk(ep->mu);
            const uint64_t id = ++ep->next_conn_id;
            ep->server_conns[id] = conn;
            return QUIC_STATUS_SUCCESS;
        }
        return QUIC_STATUS_SUCCESS;
    }

    // ------------------------------------------------------------------
    // Lifecycle.
    // ------------------------------------------------------------------
    bool build_configuration() {
        QUIC_SETTINGS settings{};
        settings.IsSet.IdleTimeoutMs = TRUE;
        settings.IdleTimeoutMs = cfg.idle_timeout_ms;
        settings.IsSet.PeerBidiStreamCount = TRUE;
        settings.PeerBidiStreamCount = cfg.peer_bidi_stream_count;
        settings.IsSet.PeerUnidiStreamCount = TRUE;
        settings.PeerUnidiStreamCount = cfg.peer_unidi_stream_count;
        // Fixed path: disable QUIC connection migration. The 4-tuple never
        // changes for the lifetime of this endpoint.
        settings.IsSet.MigrationEnabled = TRUE;
        settings.MigrationEnabled = FALSE;
        if (cfg.enable_datagrams) {
            settings.IsSet.DatagramReceiveEnabled = TRUE;
            settings.DatagramReceiveEnabled = TRUE;
        }

        QUIC_STATUS s = api->ConfigurationOpen(
            registration, &alpn, 1, &settings, sizeof(settings), nullptr,
            &configuration);
        if (QUIC_FAILED(s)) {
            set_error("ConfigurationOpen failed", s);
            return false;
        }

        QUIC_CREDENTIAL_CONFIG cred{};
        QUIC_CERTIFICATE_FILE cert_file{};
        if (cfg.role == Role::Server) {
            cert_file.CertificateFile = cfg.certificate_file.c_str();
            cert_file.PrivateKeyFile = cfg.private_key_file.c_str();
            cert_files = cert_file;
            cred.Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE;
            cred.Flags = QUIC_CREDENTIAL_FLAG_NONE;
            cred.CertificateFile = &cert_files;
        } else {
            cred.Type = QUIC_CREDENTIAL_TYPE_NONE;
            cred.Flags = QUIC_CREDENTIAL_FLAG_CLIENT;
            if (cfg.insecure_skip_verify) {
                // TEST ONLY. Certificate chain validation disabled.
                cred.Flags |= QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION;
            } else if (!cfg.ca_file.empty()) {
                // Pin an explicit CA bundle (OpenSSL backend).
                cred.Flags |= QUIC_CREDENTIAL_FLAG_SET_CA_CERTIFICATE_FILE;
                cred.CaCertificateFile = cfg.ca_file.c_str();
            }
        }

        s = api->ConfigurationLoadCredential(configuration, &cred);
        if (QUIC_FAILED(s)) {
            set_error("ConfigurationLoadCredential failed", s);
            return false;
        }
        return true;
    }

    bool start_client() {
        QUIC_STATUS s =
            api->ConnectionOpen(registration,
                                &Impl::connection_cb,
                                this, &connection);
        if (QUIC_FAILED(s)) {
            set_error("ConnectionOpen failed", s);
            return false;
        }

        // Pin the fixed local UDP path before starting (if configured).
        if (!cfg.local_address.empty() || cfg.local_port != 0) {
            QUIC_ADDR local{};
            if (!cfg.local_address.empty()) {
                if (!QuicAddrFromString(cfg.local_address.c_str(),
                                        cfg.local_port, &local)) {
                    set_error("bad local_address", QUIC_STATUS_INVALID_PARAMETER);
                    return false;
                }
            } else {
                QuicAddrSetFamily(&local, QUIC_ADDRESS_FAMILY_INET);
                QuicAddrSetPort(&local, cfg.local_port);
            }
            s = api->SetParam(connection, QUIC_PARAM_CONN_LOCAL_ADDRESS,
                              sizeof(local), &local);
            if (QUIC_FAILED(s)) {
                set_error("SetParam(CONN_LOCAL_ADDRESS) failed", s);
                return false;
            }
        }

        const std::string& sni =
            cfg.server_name.empty() ? cfg.remote_address : cfg.server_name;
        QUIC_ADDRESS_FAMILY af = QUIC_ADDRESS_FAMILY_UNSPEC;
        // Resolve the address family up front for literal IPs (no DNS path).
        QUIC_ADDR probe{};
        if (CxPlatIsIpLiteral(cfg.remote_address.c_str()) &&
            QuicAddrFromString(cfg.remote_address.c_str(), cfg.remote_port,
                               &probe)) {
            af = probe.Ip.sa_family;
            // ConnectionStart otherwise resolves serverName (TLS SNI) and can
            // silently ignore the configured fixed remote IP when the two
            // differ. Pin the literal path explicitly; SNI remains solely a
            // TLS certificate-verification hostname.
            s = api->SetParam(connection, QUIC_PARAM_CONN_REMOTE_ADDRESS,
                              sizeof(probe), &probe);
            if (QUIC_FAILED(s)) {
                set_error("SetParam(CONN_REMOTE_ADDRESS) failed", s);
                return false;
            }
        }
        s = api->ConnectionStart(connection, configuration, af, sni.c_str(),
                                 cfg.remote_port);
        if (QUIC_FAILED(s)) {
            set_error("ConnectionStart failed", s);
            return false;
        }
        running = true;
        return true;
    }

    bool start_server() {
        QUIC_STATUS s =
            api->ListenerOpen(registration,
                              &Impl::listener_cb,
                              this, &listener);
        if (QUIC_FAILED(s)) {
            set_error("ListenerOpen failed", s);
            return false;
        }
        QUIC_ADDR local{};
        if (!cfg.local_address.empty()) {
            if (!QuicAddrFromString(cfg.local_address.c_str(), cfg.local_port,
                                    &local)) {
                set_error("bad local_address", QUIC_STATUS_INVALID_PARAMETER);
                return false;
            }
        } else {
            QuicAddrSetFamily(&local, QUIC_ADDRESS_FAMILY_INET);
            QuicAddrSetPort(&local, cfg.local_port);
        }

        s = api->ListenerStart(listener, &alpn, 1, &local);
        if (QUIC_FAILED(s)) {
            set_error("ListenerStart failed", s);
            return false;
        }
        // Learn the actual bound fixed path.
        QUIC_ADDR bound{};
        uint32_t sz = sizeof(bound);
        if (QUIC_SUCCEEDED(api->GetParam(listener, QUIC_PARAM_LISTENER_LOCAL_ADDRESS,
                                         &sz, &bound))) {
            bound_port = QuicAddrGetPort(&bound);
            bound_local_str = quic_addr_to_string(bound);
        }
        running = true;
        return true;
    }

    bool start() {
        if (running) return true;
        if (cfg.role == Role::Server &&
            (cfg.certificate_file.empty() || cfg.private_key_file.empty())) {
            last_error = "server role requires certificate_file and private_key_file";
            return false;
        }
        if (cfg.role == Role::Client &&
            (cfg.remote_address.empty() || cfg.remote_port == 0)) {
            last_error = "client role requires remote_address and remote_port";
            return false;
        }

        QUIC_STATUS s = MsQuicOpen2(&api);
        if (QUIC_FAILED(s)) {
            set_error("MsQuicOpen2 failed (is libmsquic installed?)", s);
            return false;
        }
        QUIC_REGISTRATION_CONFIG reg_cfg{cfg.app_name.c_str(),
                                         QUIC_EXECUTION_PROFILE_LOW_LATENCY};
        s = api->RegistrationOpen(&reg_cfg, &registration);
        if (QUIC_FAILED(s)) {
            set_error("RegistrationOpen failed", s);
            MsQuicClose(api);
            api = nullptr;
            return false;
        }
        alpn.Buffer = reinterpret_cast<uint8_t*>(cfg.alpn.data());
        alpn.Length = static_cast<uint32_t>(cfg.alpn.size());

        if (!build_configuration()) return false;
        return cfg.role == Role::Client ? start_client() : start_server();
    }

    static bool trace_enabled() {
        static const bool on = std::getenv("NCP_RQ_TRACE") != nullptr;
        return on;
    }
#define NCP_RQ_TRACE(...) do { if (trace_enabled()) {         std::fprintf(stderr, "[ncp_rq] " __VA_ARGS__); } } while (0)

    void shutdown() {
        NCP_RQ_TRACE("shutdown: enter\n");
        // Phase 1: stop initiating/accepting new work.
        {
            std::lock_guard<std::mutex> lk(mu);
            if (stopping) return;
            stopping = true;
        }
        if (listener) {
            NCP_RQ_TRACE("shutdown: ListenerStop\n");
            api->ListenerStop(listener);
        }

        // Phase 2: gracefully shut down connections, wait for completion.
        if (cfg.role == Role::Client) {
            if (connection) {
                NCP_RQ_TRACE("shutdown: client graceful ConnectionShutdown\n");
                api->ConnectionShutdown(connection,
                                        QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);
                std::unique_lock<std::mutex> lk(mu);
                if (!cv.wait_for(lk, std::chrono::milliseconds(3000), [&] {
                        return client_shutdown_complete;
                    })) {
                    lk.unlock();
                    api->ConnectionShutdown(
                        connection, QUIC_CONNECTION_SHUTDOWN_FLAG_SILENT, 0);
                    lk.lock();
                    cv.wait_for(lk, std::chrono::milliseconds(2000), [&] {
                        return client_shutdown_complete;
                    });
                }
            }
        } else {
            {
                std::lock_guard<std::mutex> lk(mu);
                for (const auto& kv : server_conns) {
                    NCP_RQ_TRACE("shutdown: server silent ConnectionShutdown\n");
                    api->ConnectionShutdown(kv.second,
                                            QUIC_CONNECTION_SHUTDOWN_FLAG_SILENT,
                                            0);
                }
            }
            std::unique_lock<std::mutex> lk(mu);
            cv.wait_for(lk, std::chrono::milliseconds(3000),
                        [&] { return server_conns.empty(); });
        }

        NCP_RQ_TRACE("shutdown: connection waits done\n");
        // Phase 3: close handles in reverse order. By the time a connection
        // reaches SHUTDOWN_COMPLETE every stream has already delivered its
        // final SHUTDOWN_COMPLETE and been closed+freed in stream_cb.
        if (listener) { NCP_RQ_TRACE("shutdown: ListenerClose\n"); api->ListenerClose(listener); listener = nullptr; }
        if (connection) { NCP_RQ_TRACE("shutdown: ConnectionClose(client)\n"); api->ConnectionClose(connection); connection = nullptr; }
        // Close any accepted connections left over after the bounded wait.
        // Handle closes block until in-flight callbacks drain, and callbacks
        // acquire mu: therefore NEVER close a handle while holding mu.
        std::vector<HQUIC> leftover_conns;
        std::vector<StreamState*> leftover_streams;
        {
            std::lock_guard<std::mutex> lk(mu);
            for (auto& kv : server_conns) leftover_conns.push_back(kv.second);
            server_conns.clear();
            for (auto& kv : streams) leftover_streams.push_back(kv.second);
            streams.clear();
        }
        for (HQUIC c : leftover_conns) { NCP_RQ_TRACE("shutdown: ConnectionClose(server)\n"); api->ConnectionClose(c); }
        for (StreamState* ss : leftover_streams) {
            api->StreamClose(ss->stream);
            delete ss;
        }
        NCP_RQ_TRACE("shutdown: ConfigurationClose\n");
        if (configuration) { api->ConfigurationClose(configuration); configuration = nullptr; }
        NCP_RQ_TRACE("shutdown: RegistrationClose\n");
        if (registration) { api->RegistrationClose(registration); registration = nullptr; }
        NCP_RQ_TRACE("shutdown: MsQuicClose\n");
        if (api) { MsQuicClose(api); api = nullptr; }
        NCP_RQ_TRACE("shutdown: done\n");

        std::lock_guard<std::mutex> lk(mu);
        running = false;
        connected = false;
        cv.notify_all();
    }
};

// ---------------------------------------------------------------------------
// Public API.
// ---------------------------------------------------------------------------

RealQuicEndpoint::RealQuicEndpoint(Config cfg)
    : impl_(new Impl(std::move(cfg))) {}

RealQuicEndpoint::~RealQuicEndpoint() { impl_->shutdown(); }

bool RealQuicEndpoint::start() { return impl_->start(); }

void RealQuicEndpoint::shutdown() { impl_->shutdown(); }

bool RealQuicEndpoint::wait_connected(uint32_t timeout_ms) {
    std::unique_lock<std::mutex> lk(impl_->mu);
    return impl_->cv.wait_for(lk, std::chrono::milliseconds(timeout_ms), [&] {
        return impl_->connected || impl_->handshake_failed || impl_->stopping;
    }) && impl_->connected;
}

uint64_t RealQuicEndpoint::wait_connection(uint32_t timeout_ms) {
    std::unique_lock<std::mutex> lk(impl_->mu);
    impl_->cv.wait_for(lk, std::chrono::milliseconds(timeout_ms), [&] {
        return !impl_->connected_queue.empty() || impl_->stopping;
    });
    if (impl_->connected_queue.empty()) return 0;
    const uint64_t id = impl_->connected_queue.front();
    impl_->connected_queue.pop_front();
    return id;
}

bool RealQuicEndpoint::send_message(const std::vector<uint8_t>& payload,
                                    uint64_t* stream_id_out,
                                    uint64_t connection_id) {
    if (payload.size() > impl_->cfg.max_message_size) {
        impl_->last_error = "payload exceeds max_message_size";
        return false;
    }
    HQUIC conn = impl_->find_connection(connection_id);
    if (!conn || !impl_->connected) {
        impl_->last_error = "not connected";
        return false;
    }
    return impl_->open_stream_and_send(conn, connection_id, payload,
                                       stream_id_out);
}

bool RealQuicEndpoint::recv_message(Message& out, uint32_t timeout_ms) {
    std::unique_lock<std::mutex> lk(impl_->mu);
    if (!impl_->cv.wait_for(lk, std::chrono::milliseconds(timeout_ms), [&] {
            return !impl_->inbound_messages.empty() || impl_->stopping;
        })) {
        return false;
    }
    if (impl_->inbound_messages.empty()) return false;
    out = std::move(impl_->inbound_messages.front());
    impl_->inbound_messages.pop_front();
    return true;
}

bool RealQuicEndpoint::respond(uint64_t connection_id, uint64_t stream_id,
                               const std::vector<uint8_t>& payload) {
    std::lock_guard<std::mutex> lk(impl_->mu);
    auto it = impl_->streams.find({connection_id, stream_id});
    if (it == impl_->streams.end()) return false;
    Impl::StreamState* ss = it->second;
    uint64_t sent = 0;
    QUIC_STATUS send_err = QUIC_STATUS_SUCCESS;
    if (!impl_->do_stream_send(ss->stream, payload.data(), payload.size(),
                               /*fin=*/true, &sent, &send_err)) {
        impl_->set_error_locked("StreamSend(respond) failed", send_err);
        return false;
    }
    impl_->st.bytes_sent += sent;
    return true;
}

bool RealQuicEndpoint::send_datagram(const std::vector<uint8_t>& payload,
                                     uint64_t connection_id) {
    if (!impl_->cfg.enable_datagrams) {
        impl_->last_error = "datagrams not enabled in Config";
        return false;
    }
    HQUIC conn = impl_->find_connection(connection_id);
    if (!conn || !impl_->connected) {
        impl_->last_error = "not connected";
        return false;
    }
    if (impl_->datagram_max_send &&
        payload.size() > impl_->datagram_max_send) {
        impl_->last_error = "datagram exceeds negotiated max send length";
        return false;
    }
    Impl::SendCtx* ctx = Impl::make_send_ctx(payload.data(), payload.size());
    if (!ctx) return false;
    QUIC_STATUS s = impl_->api->DatagramSend(conn, &ctx->qbuf, 1,
                                             QUIC_SEND_FLAG_NONE, ctx);
    if (QUIC_FAILED(s)) {
        Impl::free_send_ctx(ctx);
        impl_->set_error("DatagramSend failed", s);
        return false;
    }
    std::lock_guard<std::mutex> lk(impl_->mu);
    impl_->st.bytes_sent += payload.size();
    return true;
}

bool RealQuicEndpoint::recv_datagram(Datagram& out, uint32_t timeout_ms) {
    std::unique_lock<std::mutex> lk(impl_->mu);
    if (!impl_->cv.wait_for(lk, std::chrono::milliseconds(timeout_ms), [&] {
            return !impl_->inbound_datagrams.empty() || impl_->stopping;
        })) {
        return false;
    }
    if (impl_->inbound_datagrams.empty()) return false;
    out = std::move(impl_->inbound_datagrams.front());
    impl_->inbound_datagrams.pop_front();
    return true;
}

uint16_t RealQuicEndpoint::datagram_max_send_length() const {
    return impl_->datagram_max_send;
}

RealQuicEndpoint::Role RealQuicEndpoint::role() const noexcept {
    return impl_->cfg.role;
}

bool RealQuicEndpoint::is_running() const { return impl_->running; }
bool RealQuicEndpoint::is_connected() const {
    std::lock_guard<std::mutex> lk(impl_->mu);
    return impl_->connected;
}

std::string RealQuicEndpoint::last_error() const {
    std::lock_guard<std::mutex> lk(impl_->mu);
    return impl_->last_error;
}

RealQuicEndpoint::Stats RealQuicEndpoint::stats() const {
    std::lock_guard<std::mutex> lk(impl_->mu);
    return impl_->st;
}

uint16_t RealQuicEndpoint::bound_local_port() const { return impl_->bound_port; }

std::string RealQuicEndpoint::local_address_str() const {
    if (impl_->cfg.role == Role::Server) return impl_->bound_local_str;
    if (!impl_->connection || !impl_->api) return {};
    QUIC_ADDR a{};
    uint32_t sz = sizeof(a);
    if (QUIC_FAILED(impl_->api->GetParam(impl_->connection,
                                         QUIC_PARAM_CONN_LOCAL_ADDRESS, &sz, &a))) {
        return {};
    }
    return quic_addr_to_string(a);
}

std::string RealQuicEndpoint::remote_address_str() const {
    if (!impl_->connection || !impl_->api) return {};
    QUIC_ADDR a{};
    uint32_t sz = sizeof(a);
    if (QUIC_FAILED(impl_->api->GetParam(impl_->connection,
                                         QUIC_PARAM_CONN_REMOTE_ADDRESS, &sz, &a))) {
        return {};
    }
    return quic_addr_to_string(a);
}

} // namespace ncp
