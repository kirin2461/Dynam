// Real MsQuic integration tests for the production Director adapter.
// Runtime certificates are test-only and are never committed.

#include <gtest/gtest.h>

#include "ncp_quic_director_adapter.hpp"
#include "ncp_transport_config.hpp"

#include <chrono>
#include <cstdlib>
#include <string>
#include <thread>
#include <vector>

#include <unistd.h>

namespace {

using ncp::NcpConnectionDirector;
using ncp::NcpMimicrySession;
using ncp::NcpQuicDirectorAdapter;
using ncp::RealQuicEndpoint;

struct TestCerts {
    std::string dir;
    std::string cert;
    std::string key;
    bool ok = false;
};

TestCerts generate_certs() {
    TestCerts tc;
    char path[] = "/tmp/ncp_quic_director_test_XXXXXX";
    if (!mkdtemp(path)) return tc;
    tc.dir = path;
    tc.cert = tc.dir + "/cert.pem";
    tc.key = tc.dir + "/key.pem";
    const std::string command =
        "openssl req -x509 -newkey rsa:2048 -nodes -keyout '" + tc.key +
        "' -out '" + tc.cert + "' -days 2 -subj '/CN=localhost'"
        " -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1'"
        " -addext 'basicConstraints=critical,CA:TRUE' >/dev/null 2>&1";
    tc.ok = std::system(command.c_str()) == 0 &&
            access(tc.cert.c_str(), R_OK) == 0 &&
            access(tc.key.c_str(), R_OK) == 0;
    return tc;
}

uint64_t now_ms() {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
}

NcpConnectionDirector::Config director_config(NcpMimicrySession::Role role) {
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
    transport.quic.remote = "127.0.0.1:1";
    std::string error;
    auto bound = ncp::bind_transport_config(transport, {}, error);
    EXPECT_TRUE(bound.has_value()) << error;
    EXPECT_FALSE(bound->hop_schedule.has_value());
    ncp::apply_transport_config(*bound, session);

    NcpConnectionDirector::Config director;
    director.session_template = std::move(session);
    return director;
}

RealQuicEndpoint::Config server_config(const TestCerts& certs) {
    RealQuicEndpoint::Config cfg;
    cfg.role = RealQuicEndpoint::Role::Server;
    cfg.local_address = "127.0.0.1";
    cfg.certificate_file = certs.cert;
    cfg.private_key_file = certs.key;
    cfg.alpn = "ncp-dynam-e2e";
    return cfg;
}

RealQuicEndpoint::Config client_config(const TestCerts& certs, uint16_t port) {
    RealQuicEndpoint::Config cfg;
    cfg.role = RealQuicEndpoint::Role::Client;
    cfg.local_address = "127.0.0.1";
    cfg.remote_address = "127.0.0.1";
    cfg.remote_port = port;
    cfg.server_name = "localhost";
    cfg.ca_file = certs.cert;
    cfg.alpn = "ncp-dynam-e2e";
    return cfg;
}

std::vector<uint8_t> payload(size_t size, uint8_t seed) {
    std::vector<uint8_t> out(size);
    for (size_t i = 0; i < size; ++i)
        out[i] = static_cast<uint8_t>(seed + (i * 131u) % 251u);
    return out;
}

class QuicDirectorAdapterTest : public ::testing::Test {
protected:
    static void SetUpTestSuite() {
        ncp::init_library();
        certs_ = generate_certs();
    }
    static TestCerts certs_;
};
TestCerts QuicDirectorAdapterTest::certs_;

TEST_F(QuicDirectorAdapterTest, ProtectedDirectorExchangeBothRoles) {
    ASSERT_TRUE(certs_.ok);
    RealQuicEndpoint server(server_config(certs_));
    ASSERT_TRUE(server.start()) << server.last_error();
    RealQuicEndpoint client(client_config(certs_, server.bound_local_port()));
    ASSERT_TRUE(client.start()) << client.last_error();
    ASSERT_TRUE(client.wait_connected(8000)) << client.last_error();
    const uint64_t connection_id = server.wait_connection(8000);
    ASSERT_NE(connection_id, 0u);

    NcpConnectionDirector client_director(
        director_config(NcpMimicrySession::Role::Client));
    NcpConnectionDirector server_director(
        director_config(NcpMimicrySession::Role::Server));
    NcpQuicDirectorAdapter client_adapter(client, client_director);
    NcpQuicDirectorAdapter server_adapter(server, server_director);
    ASSERT_TRUE(client_adapter.is_valid()) << client_adapter.config_error();
    ASSERT_TRUE(server_adapter.is_valid()) << server_adapter.config_error();

    const std::string client_local = client.local_address_str();
    const std::string client_remote = client.remote_address_str();
    const std::string server_local = server.local_address_str();
    ASSERT_EQ(client_adapter.start_handshake(now_ms()),
              NcpConnectionDirector::Error::NONE);

    const std::vector<std::vector<uint8_t>> expected = {
        payload(32, 1), payload(289, 2), payload(546, 3), payload(803, 4)};
    std::vector<std::vector<uint8_t>> received;
    bool applications_sent = false;
    bool complete = false;
    for (int iteration = 0; iteration < 10000; ++iteration) {
        const uint64_t now = now_ms();
        ASSERT_TRUE(client_adapter.pump(now, 0)) << client_adapter.last_error();
        ASSERT_TRUE(server_adapter.pump(now, 0)) << server_adapter.last_error();

        while (auto app = server_adapter.next_application_data()) {
            ASSERT_EQ(app->session_id, connection_id);
            ASSERT_EQ(server_adapter.send_application(app->session_id,
                                                      app->payload, now),
                      NcpConnectionDirector::Error::NONE);
        }
        while (auto app = client_adapter.next_application_data()) {
            EXPECT_EQ(app->session_id, 1u);
            received.push_back(std::move(app->payload));
        }

        const auto cs = client_director.session_stats(1);
        const auto ss = server_director.session_stats(connection_id);
        if (!applications_sent && cs && ss && cs->established && ss->established &&
            cs->transition_v2_capable && ss->transition_v2_capable) {
            for (const auto& item : expected)
                ASSERT_EQ(client_adapter.send_application(1, item, now),
                          NcpConnectionDirector::Error::NONE);
            applications_sent = true;
        }
        if (applications_sent && received.size() == expected.size() &&
            !client_adapter.has_inflight(1) &&
            !server_adapter.has_inflight(connection_id) &&
            client_adapter.pending_egress(1) == 0 &&
            server_adapter.pending_egress(connection_id) == 0) {
            complete = true;
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    ASSERT_TRUE(complete) << "protected director exchange timed out";
    EXPECT_EQ(received, expected);

    const auto cs = client_director.session_stats(1);
    const auto ss = server_director.session_stats(connection_id);
    ASSERT_TRUE(cs && ss);
    EXPECT_TRUE(cs->transition_capable && ss->transition_capable);
    EXPECT_TRUE(cs->transition_v2_capable && ss->transition_v2_capable);
    EXPECT_EQ(cs->ingress_dropped, 0u);
    EXPECT_EQ(ss->ingress_dropped, 0u);
    EXPECT_EQ(cs->mtu_budget_rejections, 0u);
    EXPECT_EQ(ss->mtu_budget_rejections, 0u);
    EXPECT_EQ(client_director.stats().inbox_dropped, 0u);
    EXPECT_EQ(server_director.stats().inbox_dropped, 0u);
    EXPECT_EQ(client_adapter.stats().decode_errors, 0u);
    EXPECT_EQ(server_adapter.stats().decode_errors, 0u);
    EXPECT_EQ(client.local_address_str(), client_local);
    EXPECT_EQ(client.remote_address_str(), client_remote);
    EXPECT_EQ(server.local_address_str(), server_local);
}

TEST_F(QuicDirectorAdapterTest, MalformedBundleIsAtomicAndFatal) {
    ASSERT_TRUE(certs_.ok);
    RealQuicEndpoint server(server_config(certs_));
    ASSERT_TRUE(server.start()) << server.last_error();
    RealQuicEndpoint client(client_config(certs_, server.bound_local_port()));
    ASSERT_TRUE(client.start()) << client.last_error();
    ASSERT_TRUE(client.wait_connected(8000)) << client.last_error();
    ASSERT_NE(server.wait_connection(8000), 0u);

    NcpConnectionDirector director(
        director_config(NcpMimicrySession::Role::Server));
    NcpQuicDirectorAdapter adapter(server, director);
    ASSERT_TRUE(adapter.is_valid()) << adapter.config_error();

    // Declares one datagram but contains no length or payload.
    ASSERT_TRUE(client.send_message({1, 0, 0, 0}));
    bool failed = false;
    for (int i = 0; i < 100 && !failed; ++i) {
        failed = !adapter.pump(now_ms(), 10);
        if (!failed) std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    ASSERT_TRUE(failed);
    EXPECT_EQ(adapter.stats().decode_errors, 1u);
    EXPECT_EQ(director.stats().datagrams_in, 0u);
    EXPECT_EQ(director.session_count(), 0u);
    EXPECT_FALSE(adapter.pump(now_ms(), 0)); // sticky failure, no fallback
}

TEST_F(QuicDirectorAdapterTest, PendingOverflowFailsClosed) {
    ASSERT_TRUE(certs_.ok);
    RealQuicEndpoint server(server_config(certs_));
    ASSERT_TRUE(server.start()) << server.last_error();
    RealQuicEndpoint client(client_config(certs_, server.bound_local_port()));
    ASSERT_TRUE(client.start()) << client.last_error();
    ASSERT_TRUE(client.wait_connected(8000)) << client.last_error();
    ASSERT_NE(server.wait_connection(8000), 0u);

    NcpConnectionDirector client_director(
        director_config(NcpMimicrySession::Role::Client));
    NcpConnectionDirector server_director(
        director_config(NcpMimicrySession::Role::Server));
    NcpQuicDirectorAdapter client_adapter(client, client_director);
    NcpQuicDirectorAdapter::Config bounded;
    bounded.max_pending_egress = 1; // H produces H+C atomically on the server.
    NcpQuicDirectorAdapter server_adapter(server, server_director, bounded);
    ASSERT_EQ(client_adapter.start_handshake(now_ms()),
              NcpConnectionDirector::Error::NONE);

    bool overflow = false;
    for (int i = 0; i < 1000 && !overflow; ++i) {
        const uint64_t now = now_ms();
        ASSERT_TRUE(client_adapter.pump(now, 0)) << client_adapter.last_error();
        if (!server_adapter.pump(now, 0)) {
            overflow = true;
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    ASSERT_TRUE(overflow);
    EXPECT_EQ(server_adapter.stats().pending_overflow, 1u);
    EXPECT_EQ(server_director.stats().app_messages_in, 0u);
    EXPECT_FALSE(server_adapter.pump(now_ms(), 0));
}

TEST_F(QuicDirectorAdapterTest, RoleAndBoundsValidation) {
    RealQuicEndpoint client(client_config(certs_, 443));
    NcpConnectionDirector server_director(
        director_config(NcpMimicrySession::Role::Server));
    NcpQuicDirectorAdapter mismatch(client, server_director);
    EXPECT_FALSE(mismatch.is_valid());
    EXPECT_NE(mismatch.config_error().find("roles differ"), std::string::npos);

    NcpConnectionDirector client_director(
        director_config(NcpMimicrySession::Role::Client));
    NcpQuicDirectorAdapter::Config invalid;
    invalid.max_bundle_bytes = 7;
    NcpQuicDirectorAdapter bad_bounds(client, client_director, invalid);
    EXPECT_FALSE(bad_bounds.is_valid());
    EXPECT_NE(bad_bounds.config_error().find("max_bundle_bytes"),
              std::string::npos);
}

} // namespace
