// Lab-only proof harness: real NcpMimicrySession E2E/capabilities/application
// datagrams carried inside real MsQuic reliable bidirectional streams.
//
// This is deliberately NOT a production integration and NOT an independent
// implementation interop test. Both processes use the same Dynam session
// implementation. The independent ncp_quic_cli echo matrix is a separate gate.
//
// Ordering contract: the client has only one application exchange in flight.
// The server answers on the request stream. During handshake the server's
// queued capabilities answer the client's capabilities stream, so capabilities
// cannot overtake the key-exchange response on another QUIC stream.

#include "ncp_real_quic.hpp"
#include "ncp_transport_config.hpp"

#include <array>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

namespace {

using ncp::NcpMimicrySession;
using ncp::RealQuicEndpoint;

uint64_t now_ms() {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
}

const char* arg_value(int argc, char** argv, const char* name,
                      const char* def = nullptr) {
    for (int i = 1; i + 1 < argc; ++i) {
        if (std::strcmp(argv[i], name) == 0) return argv[i + 1];
    }
    return def;
}

bool has_flag(int argc, char** argv, const char* name) {
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], name) == 0) return true;
    }
    return false;
}

void require(bool condition, const std::string& message) {
    if (!condition) throw std::runtime_error(message);
}

struct WireAudit {
    std::array<uint64_t, 256> rx{};
    std::array<uint64_t, 256> tx{};

    uint8_t inspect_rx(const std::vector<uint8_t>& bytes) {
        require(!bytes.empty(), "empty Dynam datagram received");
        const uint8_t kind = bytes[0];
        require(kind != 'P', "insecure plaintext Dynam datagram received");
        require(kind == 'H' || kind == 'C' || kind == 'E',
                "unknown Dynam datagram kind received");
        ++rx[kind];
        return kind;
    }

    uint8_t inspect_tx(const std::vector<uint8_t>& bytes) {
        require(!bytes.empty(), "empty Dynam datagram prepared");
        const uint8_t kind = bytes[0];
        require(kind != 'P', "insecure plaintext Dynam datagram prepared");
        require(kind == 'H' || kind == 'C' || kind == 'E',
                "unknown Dynam datagram kind prepared");
        ++tx[kind];
        return kind;
    }
};

std::unique_ptr<NcpMimicrySession> make_session(
    NcpMimicrySession::Role role, const std::string& remote) {
    NcpMimicrySession::Config cfg;
    cfg.role = role;
    cfg.e2e_config.enable_padding = false;
    cfg.mimic_config.wire_version = 3;
    cfg.mimic_config.enable_size_mimicry = false;
    cfg.path_mtu_bytes = 1500;
    cfg.porthop_overhead_bytes = 20;
    cfg.max_application_payload = 4096;
    cfg.allow_insecure_plaintext_legacy = false;

    // Exercise the real schema-2 creation-time binder rather than manually
    // asserting fixed-path fields in the harness.
    ncp::TransportConfig transport;
    transport.schema_version = ncp::TransportConfig::kSchemaTransport;
    transport.wire_transport = ncp::WireTransport::Quic;
    transport.quic.hop_policy = "disabled";
    transport.quic.alpn = "ncp-dynam-e2e";
    transport.quic.remote = remote.empty() ? "127.0.0.1:1" : remote;
    std::string error;
    auto bound = ncp::bind_transport_config(transport, {}, error);
    require(bound.has_value(), "QUIC transport bind failed: " + error);
    require(!bound->hop_schedule.has_value(),
            "fixed-path QUIC unexpectedly created a PortHop schedule");
    ncp::apply_transport_config(*bound, cfg);
    require(cfg.hop_policy == ncp::PathHopPolicy::Disabled,
            "QUIC session did not bind PathHopPolicy::Disabled");
    require(cfg.porthop_overhead_bytes == 0 &&
                cfg.porthop_padding_headroom_bytes == 0,
            "QUIC session retained PortHop overhead");
    return std::make_unique<NcpMimicrySession>(cfg);
}

void validate_final(const char* role, NcpMimicrySession& session,
                    const WireAudit& wire, size_t application_count,
                    const ncp::PathState& initial_path) {
    const auto stats = session.stats();
    require(stats.established && session.is_established(),
            std::string(role) + ": E2E session is not established");
    require(stats.transition_capable && stats.transition_v2_capable,
            std::string(role) + ": protected capabilities were not negotiated");
    require(stats.ingress_dropped == 0,
            std::string(role) + ": authenticated ingress datagrams were dropped");
    require(stats.queue_dropped_packets == 0 && stats.queue_dropped_bytes == 0,
            std::string(role) + ": outbound reaction queue dropped datagrams");
    require(stats.outbound_queue_packets == 0 && stats.outbound_queue_bytes == 0,
            std::string(role) + ": outbound reaction queue was not drained");
    require(stats.mtu_budget_rejections == 0,
            std::string(role) + ": protected datagram exceeded path budget");
    require(stats.e2e_messages_sent >= application_count + 1 &&
                stats.e2e_messages_received >= application_count + 1,
            std::string(role) + ": E2E message counters are incomplete");

    const auto path = session.path_state();
    require(path.hop_policy == ncp::PathHopPolicy::Disabled,
            std::string(role) + ": PortHop policy changed on fixed QUIC path");
    require(path.outer_transport == ncp::OuterTransportKind::Direct &&
                path.porthop_padding_headroom == 0,
            std::string(role) + ": invalid outer path state");
    require(path.effective_mtu == initial_path.effective_mtu &&
                path.ip_version == initial_path.ip_version &&
                path.outer_transport == initial_path.outer_transport &&
                path.hop_policy == initial_path.hop_policy &&
                path.porthop_padding_headroom == initial_path.porthop_padding_headroom &&
                path.turn_channeldata_padding == initial_path.turn_channeldata_padding &&
                path.turn_send_data_bootstrap == initial_path.turn_send_data_bootstrap,
            std::string(role) + ": Dynam path state changed during QUIC exchange");

    require(wire.tx['H'] == 1 && wire.rx['H'] == 1 &&
                wire.tx['C'] == 1 && wire.rx['C'] == 1,
            std::string(role) + ": H/C exchange was not exactly once in each direction");
    require(wire.tx['E'] == application_count &&
                wire.rx['E'] == application_count,
            std::string(role) + ": protected application E count mismatch");
    require(wire.tx['P'] == 0 && wire.rx['P'] == 0,
            std::string(role) + ": plaintext fallback observed");
}

std::vector<uint8_t> make_payload(size_t size, uint8_t seed) {
    std::vector<uint8_t> payload(size);
    for (size_t i = 0; i < size; ++i) {
        payload[i] = static_cast<uint8_t>(seed + (i * 131u) % 251u);
    }
    return payload;
}

int run_client(int argc, char** argv) {
    RealQuicEndpoint::Config cfg;
    cfg.role = RealQuicEndpoint::Role::Client;
    cfg.local_address = arg_value(argc, argv, "--bind", "127.0.0.1");
    cfg.remote_address = arg_value(argc, argv, "--host", "127.0.0.1");
    cfg.remote_port = static_cast<uint16_t>(
        std::stoi(arg_value(argc, argv, "--port", "0")));
    cfg.alpn = "ncp-dynam-e2e";
    const char* ca = arg_value(argc, argv, "--ca", nullptr);
    if (ca) cfg.ca_file = ca;
    else if (has_flag(argc, argv, "--insecure")) cfg.insecure_skip_verify = true;
    const char* sni = arg_value(argc, argv, "--sni", nullptr);
    if (sni) cfg.server_name = sni;
    const size_t count = static_cast<size_t>(
        std::stoul(arg_value(argc, argv, "--count", "4")));
    require(count > 0 && count <= 32, "client --count must be in 1..32");

    RealQuicEndpoint transport(cfg);
    require(transport.start(), "client QUIC start: " + transport.last_error());
    require(transport.wait_connected(10000),
            "client QUIC handshake: " + transport.last_error());
    const std::string initial_local = transport.local_address_str();
    const std::string initial_remote = transport.remote_address_str();
    std::printf("CONNECTED local=%s remote=%s\n",
                initial_local.c_str(), initial_remote.c_str());
    std::fflush(stdout);

    auto session = make_session(NcpMimicrySession::Role::Client,
                                initial_remote);
    const auto initial_path = session->path_state();
    WireAudit wire;

    auto exchange = [&](const std::vector<uint8_t>& outbound,
                        NcpMimicrySession::IngressResult& ingress) {
        wire.inspect_tx(outbound);
        uint64_t stream_id = UINT64_MAX;
        require(transport.send_message(outbound, &stream_id),
                "client protected send: " + transport.last_error());
        RealQuicEndpoint::Message response;
        require(transport.recv_message(response, 15000),
                "client protected response timeout");
        require(response.stream_id == stream_id,
                "client response arrived on an unexpected QUIC stream");
        const uint8_t response_kind = wire.inspect_rx(response.payload);
        ingress = session->on_datagram(response.payload, now_ms());
        require(ingress.kind != NcpMimicrySession::IngressKind::Dropped,
                "client dropped authenticated Dynam response");
        require(!ingress.insecure_plaintext,
                "client accepted insecure plaintext after establishment");
        return response_kind;
    };

    auto handshake = session->start_handshake();
    require(handshake.has_value(), "client did not create E2E handshake");
    NcpMimicrySession::IngressResult ingress;
    require(exchange(handshake->bytes, ingress) == 'H' &&
                ingress.kind == NcpMimicrySession::IngressKind::Handshake,
            "client E2E handshake response mismatch");
    require(session->is_established(), "client E2E handshake did not complete");

    // Drain exactly the reaction generated by the handshake. The server's
    // capabilities arrive as the response on this same new request stream.
    auto caps = session->next_outbound();
    require(caps.has_value() && caps->bytes[0] == 'C',
            "client did not queue protected capabilities");
    require(exchange(caps->bytes, ingress) == 'C' &&
                ingress.kind == NcpMimicrySession::IngressKind::Capabilities,
            "client protected capabilities exchange failed");
    require(!session->has_outbound(), "unexpected client handshake reactions");
    std::printf("E2E_READY role=client capabilities=v2 path=fixed\n");
    std::fflush(stdout);

    for (size_t i = 0; i < count; ++i) {
        const size_t size = 32 + i * 257;
        const auto payload = make_payload(size, static_cast<uint8_t>(i * 17));
        auto protected_data = session->send_application(payload, now_ms());
        require(protected_data.has_value() && protected_data->bytes[0] == 'E',
                "client failed to protect application payload");
        require(exchange(protected_data->bytes, ingress) == 'E' &&
                    ingress.kind == NcpMimicrySession::IngressKind::Data &&
                    ingress.app_payload && *ingress.app_payload == payload,
                "client protected application echo mismatch");
        std::printf("PROTECTED_ECHO_OK index=%zu plaintext_bytes=%zu wire_bytes=%zu\n",
                    i, payload.size(), protected_data->bytes.size());
        std::fflush(stdout);
    }

    require(!session->has_outbound(), "client application reactions remained queued");
    validate_final("client", *session, wire, count, initial_path);
    require(transport.local_address_str() == initial_local &&
                transport.remote_address_str() == initial_remote,
            "client QUIC UDP path changed during exchange");
    const auto qs = transport.stats();
    require(qs.messages_dropped_queue_full == 0,
            "client QUIC transport dropped inbound messages");
    std::printf("DYNAM_QUIC_PROTECTED_OK role=client e2e=1 capabilities=v2 "
                "app_echoes=%zu plaintext_fallback=0 path_hop=disabled "
                "quic_local_unchanged=1 quic_remote_unchanged=1\n", count);
    return 0;
}

int run_server(int argc, char** argv) {
    RealQuicEndpoint::Config cfg;
    cfg.role = RealQuicEndpoint::Role::Server;
    cfg.local_address = arg_value(argc, argv, "--bind", "127.0.0.1");
    cfg.local_port = static_cast<uint16_t>(
        std::stoi(arg_value(argc, argv, "--port", "0")));
    cfg.certificate_file = arg_value(argc, argv, "--cert", "");
    cfg.private_key_file = arg_value(argc, argv, "--key", "");
    cfg.alpn = "ncp-dynam-e2e";
    const size_t count = static_cast<size_t>(
        std::stoul(arg_value(argc, argv, "--count", "4")));
    require(count > 0 && count <= 32, "server --count must be in 1..32");

    RealQuicEndpoint transport(cfg);
    require(transport.start(), "server QUIC start: " + transport.last_error());
    const std::string initial_local = transport.local_address_str();
    std::printf("LISTENING %s\n", initial_local.c_str());
    std::fflush(stdout);
    require(transport.wait_connected(10000),
            "server QUIC handshake: " + transport.last_error());

    auto session = make_session(NcpMimicrySession::Role::Server, "");
    const auto initial_path = session->path_state();
    WireAudit wire;
    size_t echoes = 0;
    bool saw_client_caps = false;

    while (echoes < count) {
        RealQuicEndpoint::Message request;
        require(transport.recv_message(request, 15000),
                "server protected request timeout");
        const uint8_t kind = wire.inspect_rx(request.payload);
        auto ingress = session->on_datagram(request.payload, now_ms());
        require(ingress.kind != NcpMimicrySession::IngressKind::Dropped,
                "server dropped authenticated Dynam request");
        require(!ingress.insecure_plaintext,
                "server accepted insecure plaintext after establishment");

        if (kind == 'E' && echoes < count &&
            ingress.kind == NcpMimicrySession::IngressKind::Data) {
            require(session->is_established() && saw_client_caps,
                    "server received application data before protected bring-up");
            require(ingress.app_payload.has_value(),
                    "server protected data has no application payload");
            auto echo = session->send_application(*ingress.app_payload, now_ms());
            require(echo.has_value() && echo->bytes[0] == 'E',
                    "server failed to protect application echo");
            wire.inspect_tx(echo->bytes);
            require(transport.respond(request.connection_id, request.stream_id,
                                      echo->bytes),
                    "server protected echo: " + transport.last_error());
            ++echoes;
            std::printf("PROTECTED_ECHOED index=%zu plaintext_bytes=%zu wire_bytes=%zu\n",
                        echoes - 1, ingress.app_payload->size(), echo->bytes.size());
            std::fflush(stdout);
            continue;
        }

        if (kind == 'H') {
            require(ingress.kind == NcpMimicrySession::IngressKind::Handshake,
                    "server E2E handshake request mismatch");
        } else if (kind == 'C') {
            require(ingress.kind == NcpMimicrySession::IngressKind::Capabilities,
                    "server protected capabilities mismatch");
            saw_client_caps = true;
        } else {
            throw std::runtime_error("server received unexpected Dynam control/data sequence");
        }

        // H yields H+C. Answer H now; retain C until the client's C request,
        // which proves that the client has already processed the H response.
        auto reaction = session->next_outbound();
        require(reaction.has_value(), "server missing protected reaction");
        wire.inspect_tx(reaction->bytes);
        require(transport.respond(request.connection_id, request.stream_id,
                                  reaction->bytes),
                "server protected reaction: " + transport.last_error());
    }

    require(session->is_established() && saw_client_caps,
            "server protected bring-up did not complete");
    std::printf("E2E_READY role=server capabilities=v2 path=fixed\n");
    validate_final("server", *session, wire, count, initial_path);
    require(transport.local_address_str() == initial_local,
            "server QUIC UDP path changed during exchange");
    const auto qs = transport.stats();
    require(qs.messages_dropped_queue_full == 0,
            "server QUIC transport dropped inbound messages");
    std::printf("DYNAM_QUIC_PROTECTED_SERVER_OK role=server e2e=1 capabilities=v2 "
                "app_echoes=%zu plaintext_fallback=0 path_hop=disabled "
                "quic_local_unchanged=1\n", count);
    std::fflush(stdout);
    // Allow the final queued QUIC response to flush before endpoint teardown.
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    return 0;
}

} // namespace

int main(int argc, char** argv) {
    try {
        require(argc >= 2, "usage: ncp_quic_protected_cli server|client ...");
        if (std::strcmp(argv[1], "server") == 0) return run_server(argc, argv);
        if (std::strcmp(argv[1], "client") == 0) return run_client(argc, argv);
        throw std::runtime_error("unknown mode");
    } catch (const std::exception& e) {
        std::fprintf(stderr, "DYNAM_QUIC_PROTECTED_FAIL %s\n", e.what());
        return 1;
    }
}
