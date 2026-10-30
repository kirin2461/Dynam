// Lab driver for the PRODUCTION NcpQuicDirectorAdapter path. Unlike the
// original protected proof harness, this program does not own a direct
// NcpMimicrySession and does not implement a separate wire state machine.

#include "ncp_quic_director_adapter.hpp"
#include "ncp_transport_config.hpp"

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

namespace {

using ncp::NcpConnectionDirector;
using ncp::NcpMimicrySession;
using ncp::NcpQuicDirectorAdapter;
using ncp::RealQuicEndpoint;

uint64_t now_ms() {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
}

const char* arg_value(int argc, char** argv, const char* name,
                      const char* fallback = nullptr) {
    for (int i = 1; i + 1 < argc; ++i)
        if (std::strcmp(argv[i], name) == 0) return argv[i + 1];
    return fallback;
}

bool has_flag(int argc, char** argv, const char* name) {
    for (int i = 1; i < argc; ++i)
        if (std::strcmp(argv[i], name) == 0) return true;
    return false;
}

void require(bool condition, const std::string& message) {
    if (!condition) throw std::runtime_error(message);
}

NcpConnectionDirector::Config make_director(NcpMimicrySession::Role role,
                                            const std::string& remote) {
    NcpMimicrySession::Config session;
    session.role = role;
    session.e2e_config.enable_padding = false;
    session.mimic_config.wire_version = 3;
    session.mimic_config.enable_size_mimicry = false;
    session.path_mtu_bytes = 1500;
    session.max_application_payload = 4096;
    session.allow_insecure_plaintext_legacy = false;
    session.stable_profile.id = "generic.udp";
    session.stable_profile.revision = 1;

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
    ncp::apply_transport_config(*bound, session);
    require(session.hop_policy == ncp::PathHopPolicy::Disabled &&
                session.porthop_overhead_bytes == 0 &&
                session.porthop_padding_headroom_bytes == 0,
            "QUIC director retained PortHop state or overhead");

    NcpConnectionDirector::Config director;
    director.session_template = std::move(session);
    return director;
}

std::vector<uint8_t> make_payload(size_t size, uint8_t seed) {
    std::vector<uint8_t> out(size);
    for (size_t i = 0; i < size; ++i)
        out[i] = static_cast<uint8_t>(seed + (i * 131u) % 251u);
    return out;
}

size_t argument_count(int argc, char** argv) {
    const size_t count = static_cast<size_t>(
        std::stoul(arg_value(argc, argv, "--count", "4")));
    require(count > 0 && count <= 32, "--count must be in 1..32");
    return count;
}

void validate_session(const char* role, const NcpMimicrySession::Stats& stats,
                      size_t application_count) {
    require(stats.established, std::string(role) + ": E2E not established");
    require(stats.transition_capable && stats.transition_v2_capable,
            std::string(role) + ": protected capabilities not negotiated");
    require(stats.ingress_dropped == 0,
            std::string(role) + ": authenticated ingress dropped");
    require(stats.queue_dropped_packets == 0 && stats.queue_dropped_bytes == 0,
            std::string(role) + ": session reaction queue dropped data");
    require(stats.outbound_queue_packets == 0 && stats.outbound_queue_bytes == 0,
            std::string(role) + ": session reaction queue not drained");
    require(stats.mtu_budget_rejections == 0,
            std::string(role) + ": path budget rejection");
    require(stats.e2e_messages_sent >= application_count + 1 &&
                stats.e2e_messages_received >= application_count + 1,
            std::string(role) + ": incomplete E2E message counters");
}

void validate_adapter(const char* role, const NcpQuicDirectorAdapter& adapter) {
    const auto stats = adapter.stats();
    require(stats.decode_errors == 0 && stats.transport_errors == 0 &&
                stats.pending_overflow == 0,
            std::string(role) + ": production adapter errors are non-zero");
    require(stats.bundles_sent > 0 && stats.bundles_received > 0 &&
                stats.datagrams_sent > 0 && stats.datagrams_received > 0,
            std::string(role) +": production adapter did not carry Dynam data");
}

int run_client(int argc, char** argv) {
    RealQuicEndpoint::Config cfg;
    cfg.role = RealQuicEndpoint::Role::Client;
    cfg.local_address = arg_value(argc, argv, "--bind", "127.0.0.1");
    cfg.remote_address = arg_value(argc, argv, "--host", "127.0.0.1");
    cfg.remote_port = static_cast<uint16_t>(
        std::stoi(arg_value(argc, argv, "--port", "0")));
    cfg.alpn = "ncp-dynam-e2e";
    if (const char* ca = arg_value(argc, argv, "--ca", nullptr)) cfg.ca_file = ca;
    else if (has_flag(argc, argv, "--insecure")) cfg.insecure_skip_verify = true;
    if (const char* sni = arg_value(argc, argv, "--sni", nullptr))
        cfg.server_name = sni;
    const size_t count = argument_count(argc, argv);

    RealQuicEndpoint endpoint(cfg);
    require(endpoint.start(), "client QUIC start: " + endpoint.last_error());
    require(endpoint.wait_connected(10000),
            "client QUIC handshake: " + endpoint.last_error());
    const std::string initial_local = endpoint.local_address_str();
    const std::string initial_remote = endpoint.remote_address_str();
    std::printf("CONNECTED local=%s remote=%s production_adapter=1\n",
                initial_local.c_str(), initial_remote.c_str());
    std::fflush(stdout);

    NcpConnectionDirector director(
        make_director(NcpMimicrySession::Role::Client, initial_remote));
    NcpQuicDirectorAdapter adapter(endpoint, director);
    require(adapter.is_valid(), adapter.config_error());
    require(adapter.start_handshake(now_ms()) == NcpConnectionDirector::Error::NONE,
            "client director failed to schedule handshake");

    size_t next_send = 0;
    size_t echoes = 0;
    std::vector<uint8_t> expected;
    bool announced_ready = false;
    for (int iteration = 0; iteration < 30000 && echoes < count; ++iteration) {
        const uint64_t now = now_ms();
        require(adapter.pump(now, 10), "client adapter: " + adapter.last_error());
        while (auto app = adapter.next_application_data()) {
            require(app->session_id == 1, "client received unexpected session id");
            require(!expected.empty() && app->payload == expected,
                    "client protected application echo mismatch");
            std::printf("PROTECTED_DIRECTOR_ECHO_OK index=%zu plaintext_bytes=%zu\n",
                        echoes, app->payload.size());
            std::fflush(stdout);
            ++echoes;
        }
        const auto stats = director.session_stats(1);
        if (stats && stats->established && stats->transition_v2_capable) {
            if (!announced_ready) {
                std::printf("E2E_READY role=client capabilities=v2 "
                            "path=fixed production_adapter=1\n");
                std::fflush(stdout);
                announced_ready = true;
            }
            if (next_send < count && next_send == echoes) {
                expected = make_payload(32 + next_send * 257,
                                        static_cast<uint8_t>(next_send * 17));
                require(adapter.send_application(1, expected, now) ==
                            NcpConnectionDirector::Error::NONE,
                        "client director rejected application payload");
                ++next_send;
            }
        }
    }
    require(echoes == count, "client production director exchange timed out");
    for (int i = 0; i < 100 && (adapter.has_inflight(1) ||
                               adapter.pending_egress(1) != 0); ++i)
        require(adapter.pump(now_ms(), 10),
                "client adapter drain: " + adapter.last_error());
    require(!adapter.has_inflight(1) && adapter.pending_egress(1) == 0,
            "client production adapter did not drain");

    const auto stats = director.session_stats(1);
    require(stats.has_value(), "client director session disappeared");
    validate_session("client", *stats, count);
    validate_adapter("client", adapter);
    require(director.stats().inbox_dropped == 0,
            "client director inbox dropped application data");
    require(endpoint.stats().messages_dropped_queue_full == 0,
            "client QUIC transport dropped messages");
    require(endpoint.local_address_str() == initial_local &&
                endpoint.remote_address_str() == initial_remote,
            "client QUIC UDP path changed");
    std::printf("DYNAM_QUIC_DIRECTOR_OK role=client e2e=1 capabilities=v2 "
                "app_echoes=%zu plaintext_fallback=0 path_hop=disabled "
                "production_adapter=1 quic_local_unchanged=1 "
                "quic_remote_unchanged=1\n", count);
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
    const size_t count = argument_count(argc, argv);

    RealQuicEndpoint endpoint(cfg);
    require(endpoint.start(), "server QUIC start: " + endpoint.last_error());
    const std::string initial_local = endpoint.local_address_str();
    std::printf("LISTENING %s production_adapter=1\n", initial_local.c_str());
    std::fflush(stdout);
    const uint64_t connection_id = endpoint.wait_connection(15000);
    require(connection_id != 0,
            "server QUIC handshake: " + endpoint.last_error());

    NcpConnectionDirector director(
        make_director(NcpMimicrySession::Role::Server, ""));
    NcpQuicDirectorAdapter adapter(endpoint, director);
    require(adapter.is_valid(), adapter.config_error());

    size_t echoes = 0;
    bool announced_ready = false;
    bool pumped_after_last_echo = false;
    for (int iteration = 0; iteration < 30000; ++iteration) {
        const uint64_t now = now_ms();
        require(adapter.pump(now, 10), "server adapter: " + adapter.last_error());
        if (echoes == count) pumped_after_last_echo = true;
        while (auto app = adapter.next_application_data()) {
            require(app->session_id == connection_id,
                    "server application session id mismatch");
            require(adapter.send_application(connection_id, app->payload, now) ==
                        NcpConnectionDirector::Error::NONE,
                    "server director rejected echo payload");
            std::printf("PROTECTED_DIRECTOR_ECHOED index=%zu plaintext_bytes=%zu\n",
                        echoes, app->payload.size());
            std::fflush(stdout);
            ++echoes;
            if (echoes == count) pumped_after_last_echo = false;
        }
        const auto stats = director.session_stats(connection_id);
        if (!announced_ready && stats && stats->established &&
            stats->transition_v2_capable) {
            std::printf("E2E_READY role=server capabilities=v2 "
                        "path=fixed production_adapter=1\n");
            std::fflush(stdout);
            announced_ready = true;
        }
        if (echoes == count && pumped_after_last_echo &&
            !adapter.has_inflight(connection_id) &&
            adapter.pending_egress(connection_id) == 0)
            break;
        require(iteration < 29999, "server production director exchange timed out");
    }

    const auto stats = director.session_stats(connection_id);
    require(stats.has_value(), "server director session disappeared");
    validate_session("server", *stats, count);
    validate_adapter("server", adapter);
    require(director.stats().inbox_dropped == 0,
            "server director inbox dropped application data");
    require(endpoint.stats().messages_dropped_queue_full == 0,
            "server QUIC transport dropped messages");
    require(endpoint.local_address_str() == initial_local,
            "server QUIC UDP path changed");
    std::printf("DYNAM_QUIC_DIRECTOR_SERVER_OK role=server e2e=1 capabilities=v2 "
                "app_echoes=%zu plaintext_fallback=0 path_hop=disabled "
                "production_adapter=1 quic_local_unchanged=1\n", count);
    std::fflush(stdout);
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    return 0;
}

} // namespace

int main(int argc, char** argv) {
    try {
        ncp::init_library();
        require(argc >= 2, "usage: ncp_quic_director_cli server|client ...");
        if (std::strcmp(argv[1], "server") == 0) return run_server(argc, argv);
        if (std::strcmp(argv[1], "client") == 0) return run_client(argc, argv);
        throw std::runtime_error("unknown mode");
    } catch (const std::exception& e) {
        std::fprintf(stderr, "DYNAM_QUIC_DIRECTOR_FAIL %s\n", e.what());
        return 1;
    }
}
