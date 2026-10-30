// ══════════════════════════════════════════════════════════════════════════════
// tests/test_turn_server.cpp
// G5: unit tests for the REAL TURN-over-UDP/IPv4 server (ncp_turn_server.hpp).
//
// Hermetic: a TurnServer instance runs its single poll loop on a background
// thread bound to loopback ephemeral ports; raw client/peer UDP sockets and
// the shared STUN codec (ncp_turn_client.hpp) drive the wire protocol.
//
// Coverage:
//   * 401 long-term credential challenge (REALM/NONCE), wrong password /
//     bad nonce / stale nonce (438) all fail closed.
//   * Allocate success (XOR-RELAYED/XOR-MAPPED/LIFETIME), 437 on second
//     Allocate, 442 on non-UDP REQUESTED-TRANSPORT.
//   * Refresh extend + delete (lifetime=0), 437 after delete, natural expiry.
//   * CreatePermission + Send/Data bootstrap echo, ChannelBind + ChannelData
//     echo in both directions.
//   * Fail-closed drops: malformed datagrams, peer traffic without permission,
//     ChannelData from an unknown 5-tuple.
//   * Transaction-id replay response cache (retransmitted request gets the
//     cached response verbatim).
// ══════════════════════════════════════════════════════════════════════════════
#include <gtest/gtest.h>
#include "ncp_turn_server.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

using namespace ncp::turn;

namespace {

constexpr const char* kUser = "alice";
constexpr const char* kPass = "s3cret-independent";
constexpr const char* kRealm = "g5-test-realm";

// ── Server runner: owns the single poll loop on a background thread ─────────

struct ServerRunner {
    TurnServer server;
    std::thread th;
    std::atomic<bool> stop{false};

    explicit ServerRunner(TurnServerConfig cfg) : server(std::move(cfg)) {}

    bool start() {
        std::string err;
        if (!server.open(&err)) return false;
        th = std::thread([this] {
            while (!stop.load()) {
                std::string perr;
                server.poll(2, &perr);
            }
        });
        return true;
    }
    ~ServerRunner() {
        stop.store(true);
        if (th.joinable()) th.join();
    }
};

TurnServerConfig base_cfg() {
    TurnServerConfig cfg;
    cfg.bind_ip = "127.0.0.1";
    cfg.bind_port = 0;  // ephemeral
    cfg.relay_ip = "127.0.0.1";
    cfg.realm = kRealm;
    cfg.users = {{kUser, kPass}};  // independently supplied credentials
    return cfg;
}

// ── Raw UDP socket helper ────────────────────────────────────────────────────

struct UdpSocket {
    int fd = -1;
    uint16_t port = 0;

    UdpSocket() {
        fd = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        sockaddr_in sa{};
        sa.sin_family = AF_INET;
        sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        sa.sin_port = htons(0);
        ::bind(fd, reinterpret_cast<sockaddr*>(&sa), sizeof(sa));
        sockaddr_in actual{};
        socklen_t alen = sizeof(actual);
        ::getsockname(fd, reinterpret_cast<sockaddr*>(&actual), &alen);
        port = ntohs(actual.sin_port);
    }
    ~UdpSocket() { if (fd >= 0) ::close(fd); }

    bool send_to(uint16_t dst_port, const std::vector<uint8_t>& bytes) {
        sockaddr_in dst{};
        dst.sin_family = AF_INET;
        dst.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        dst.sin_port = htons(dst_port);
        return ::sendto(fd, reinterpret_cast<const char*>(bytes.data()),
                        bytes.size(), 0,
                        reinterpret_cast<sockaddr*>(&dst), sizeof(dst)) ==
               (ssize_t)bytes.size();
    }

    // Returns false on timeout. Fills addr/port of sender.
    bool recv(int timeout_ms, std::vector<uint8_t>& out,
              uint32_t* addr_be = nullptr, uint16_t* port_out = nullptr) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(fd, &rfds);
        timeval tv{timeout_ms / 1000, (timeout_ms % 1000) * 1000};
        int r = ::select(fd + 1, &rfds, nullptr, nullptr, &tv);
        if (r <= 0) return false;
        uint8_t buf[65536];
        sockaddr_in from{};
        socklen_t fromlen = sizeof(from);
        ssize_t n = ::recvfrom(fd, buf, sizeof(buf), 0,
                               reinterpret_cast<sockaddr*>(&from), &fromlen);
        if (n <= 0) return false;
        out.assign(buf, buf + n);
        if (addr_be) *addr_be = from.sin_addr.s_addr;
        if (port_out) *port_out = ntohs(from.sin_port);
        return true;
    }
};

// ── STUN transaction helper against the test server ──────────────────────────

struct TestClient {
    UdpSocket sock;
    uint16_t server_port = 0;
    std::string nonce;  // acquired from a 401/438 challenge

    bool transact(StunMessage& req, StunMessage& resp,
                  const uint8_t* mi_key, int timeout_ms = 3000) {
        req.txn_id = {};
        for (size_t i = 0; i < req.txn_id.size(); ++i)
            req.txn_id[i] = static_cast<uint8_t>(rand());
        std::vector<uint8_t> bytes =
            stun_encode(req, mi_key, mi_key ? 16 : 0, true);
        if (!sock.send_to(server_port, bytes)) return false;
        auto deadline = std::chrono::steady_clock::now() +
                        std::chrono::milliseconds(timeout_ms);
        while (std::chrono::steady_clock::now() < deadline) {
            std::vector<uint8_t> raw;
            if (!sock.recv(200, raw)) continue;
            StunMessage m;
            std::string derr;
            if (!stun_decode(raw.data(), raw.size(), m, derr)) continue;
            if (m.txn_id == req.txn_id) { resp = std::move(m); return true; }
        }
        return false;
    }

    // Unauthenticated Allocate to harvest realm+nonce from the 401.
    bool get_nonce() {
        StunMessage req;
        req.method = kMethodAllocate;
        req.cls = StunClass::Request;
        req.attributes.push_back({kAttrRequestedTransport, {17, 0, 0, 0}});
        StunMessage resp;
        if (!transact(req, resp, nullptr)) return false;
        uint32_t code = 0;
        if (!error_code(resp, code) || code != kErrorUnauthorized) return false;
        if (resp.find_string(kAttrRealm) != kRealm) return false;
        nonce = resp.find_string(kAttrNonce);
        return !nonce.empty();
    }

    void add_auth(StunMessage& req) {
        req.attributes.push_back({kAttrUsername, {kUser, kUser + strlen(kUser)}});
        req.attributes.push_back({kAttrRealm, {kRealm, kRealm + strlen(kRealm)}});
        req.attributes.push_back({kAttrNonce, {nonce.begin(), nonce.end()}});
    }

    static bool error_code(const StunMessage& m, uint32_t& code) {
        const StunAttribute* a = m.find(kAttrErrorCode);
        if (!a || a->value.size() < 4) return false;
        code = (uint32_t)(a->value[2] & 0x07) * 100 + a->value[3];
        return true;
    }

    std::array<uint8_t, 16> key(const std::string& pass) {
        return long_term_key(kUser, kRealm, pass);
    }
};

StunMessage make_allocate() {
    StunMessage req;
    req.method = kMethodAllocate;
    req.cls = StunClass::Request;
    req.attributes.push_back({kAttrRequestedTransport, {17, 0, 0, 0}});
    return req;
}

// Simple loopback echo peer for relay tests.
struct EchoPeer {
    UdpSocket sock;
    std::thread th;
    std::atomic<bool> stop{false};
    void start() {
        th = std::thread([this] {
            while (!stop.load()) {
                std::vector<uint8_t> data;
                uint32_t addr; uint16_t port;
                if (!sock.recv(50, data, &addr, &port)) continue;
                sockaddr_in dst{};
                dst.sin_family = AF_INET;
                dst.sin_addr.s_addr = addr;
                dst.sin_port = htons(port);
                ::sendto(sock.fd, reinterpret_cast<const char*>(data.data()),
                         data.size(), 0,
                         reinterpret_cast<sockaddr*>(&dst), sizeof(dst));
            }
        });
    }
    ~EchoPeer() { stop.store(true); if (th.joinable()) th.join(); }
};

} // namespace

// ── Authentication ───────────────────────────────────────────────────────────

TEST(TurnServer, UnauthenticatedAllocateChallenged401) {
    ServerRunner srv(base_cfg());
    ASSERT_TRUE(srv.start());
    TestClient c;
    c.server_port = srv.server.bound_port();

    StunMessage req = make_allocate();
    StunMessage resp;
    ASSERT_TRUE(c.transact(req, resp, nullptr));
    ASSERT_EQ(resp.cls, StunClass::ErrorResponse);
    uint32_t code = 0;
    ASSERT_TRUE(TestClient::error_code(resp, code));
    EXPECT_EQ(code, kErrorUnauthorized);
    EXPECT_EQ(resp.find_string(kAttrRealm), kRealm);
    EXPECT_FALSE(resp.find_string(kAttrNonce).empty());
    EXPECT_GE(srv.server.stats().auth_challenges_401, 1u);
    EXPECT_EQ(srv.server.stats().allocations_active, 0u);
}

TEST(TurnServer, BadNonceFailsClosed401) {
    ServerRunner srv(base_cfg());
    ASSERT_TRUE(srv.start());
    TestClient c;
    c.server_port = srv.server.bound_port();
    auto k = c.key(kPass);

    StunMessage req = make_allocate();
    req.attributes.push_back({kAttrUsername, {kUser, kUser + strlen(kUser)}});
    req.attributes.push_back({kAttrRealm, {kRealm, kRealm + strlen(kRealm)}});
    const std::string bogus = "not-a-valid-nonce";
    req.attributes.push_back({kAttrNonce, {bogus.begin(), bogus.end()}});
    StunMessage resp;
    ASSERT_TRUE(c.transact(req, resp, k.data()));
    uint32_t code = 0;
    ASSERT_TRUE(TestClient::error_code(resp, code));
    EXPECT_EQ(code, kErrorUnauthorized);
    EXPECT_EQ(srv.server.stats().bad_nonce_rejected, 1u);
    EXPECT_EQ(srv.server.stats().allocations_active, 0u);
}

TEST(TurnServer, WrongPasswordFailsClosed401) {
    ServerRunner srv(base_cfg());
    ASSERT_TRUE(srv.start());
    TestClient c;
    c.server_port = srv.server.bound_port();
    ASSERT_TRUE(c.get_nonce());

    StunMessage req = make_allocate();
    c.add_auth(req);
    auto bad_key = c.key("wrong-password");
    StunMessage resp;
    ASSERT_TRUE(c.transact(req, resp, bad_key.data()));
    uint32_t code = 0;
    ASSERT_TRUE(TestClient::error_code(resp, code));
    EXPECT_EQ(code, kErrorUnauthorized);
    EXPECT_EQ(srv.server.stats().bad_integrity_rejected, 1u);
    EXPECT_EQ(srv.server.stats().allocations_active, 0u);
}

TEST(TurnServer, UnknownUserFailsClosed401) {
    ServerRunner srv(base_cfg());
    ASSERT_TRUE(srv.start());
    TestClient c;
    c.server_port = srv.server.bound_port();
    ASSERT_TRUE(c.get_nonce());

    StunMessage req = make_allocate();
    const std::string mallory = "mallory";
    req.attributes.push_back({kAttrUsername, {mallory.begin(), mallory.end()}});
    req.attributes.push_back({kAttrRealm, {kRealm, kRealm + strlen(kRealm)}});
    req.attributes.push_back({kAttrNonce, {c.nonce.begin(), c.nonce.end()}});
    auto k = long_term_key(mallory, kRealm, "whatever");
    StunMessage resp;
    ASSERT_TRUE(c.transact(req, resp, k.data()));
    uint32_t code = 0;
    ASSERT_TRUE(TestClient::error_code(resp, code));
    EXPECT_EQ(code, kErrorUnauthorized);
    EXPECT_EQ(srv.server.stats().unknown_user_rejected, 1u);
}

TEST(TurnServer, StaleNonceFailsClosed438ThenRecovers) {
    TurnServerConfig cfg = base_cfg();
    cfg.nonce_lifetime = 1;  // seconds
    ServerRunner srv(cfg);
    ASSERT_TRUE(srv.start());
    TestClient c;
    c.server_port = srv.server.bound_port();
    ASSERT_TRUE(c.get_nonce());
    std::this_thread::sleep_for(std::chrono::milliseconds(2100));

    StunMessage req = make_allocate();
    c.add_auth(req);
    auto k = c.key(kPass);
    StunMessage resp;
    ASSERT_TRUE(c.transact(req, resp, k.data()));
    uint32_t code = 0;
    ASSERT_TRUE(TestClient::error_code(resp, code));
    EXPECT_EQ(code, kErrorStaleNonce);
    EXPECT_EQ(srv.server.stats().stale_nonce_438, 1u);
    EXPECT_EQ(srv.server.stats().allocations_active, 0u);

    // The fresh nonce carried by the 438 must work.
    c.nonce = resp.find_string(kAttrNonce);
    ASSERT_FALSE(c.nonce.empty());
    StunMessage req2 = make_allocate();
    c.add_auth(req2);
    StunMessage resp2;
    ASSERT_TRUE(c.transact(req2, resp2, k.data()));
    EXPECT_EQ(resp2.cls, StunClass::SuccessResponse);
}

// ── Allocate / Refresh ───────────────────────────────────────────────────────

TEST(TurnServer, AllocateSuccessAttributes) {
    ServerRunner srv(base_cfg());
    ASSERT_TRUE(srv.start());
    TestClient c;
    c.server_port = srv.server.bound_port();
    ASSERT_TRUE(c.get_nonce());
    auto k = c.key(kPass);

    StunMessage req = make_allocate();
    c.add_auth(req);
    StunMessage resp;
    ASSERT_TRUE(c.transact(req, resp, k.data()));
    ASSERT_EQ(resp.cls, StunClass::SuccessResponse);

    const StunAttribute* rel = resp.find(kAttrXorRelayedAddress);
    ASSERT_NE(rel, nullptr);
    uint32_t addr = 0; uint16_t port = 0;
    ASSERT_TRUE(decode_xor_address_ipv4(*rel, resp.txn_id, addr, port));
    EXPECT_EQ(addr, htonl(INADDR_LOOPBACK));
    EXPECT_NE(port, 0u);
    EXPECT_NE(port, c.server_port);

    const StunAttribute* mapped = resp.find(kAttrXorMappedAddress);
    ASSERT_NE(mapped, nullptr);
    ASSERT_TRUE(decode_xor_address_ipv4(*mapped, resp.txn_id, addr, port));
    EXPECT_EQ(addr, htonl(INADDR_LOOPBACK));
    EXPECT_EQ(port, c.sock.port);

    const StunAttribute* lt = resp.find(kAttrLifetime);
    ASSERT_NE(lt, nullptr);
    ASSERT_EQ(lt->value.size(), 4u);
    EXPECT_EQ(srv.server.stats().allocations_active, 1u);
    EXPECT_EQ(srv.server.stats().allocations_total, 1u);
    // Success responses to authenticated requests carry MESSAGE-INTEGRITY.
    EXPECT_TRUE(resp.has_message_integrity);
    EXPECT_TRUE(stun_verify_integrity(resp, k.data(), k.size()));
    EXPECT_TRUE(resp.has_fingerprint);
    EXPECT_TRUE(stun_verify_fingerprint(resp));
}

TEST(TurnServer, EvenPortHonoredAndAddressFamilyRejected) {
    ServerRunner srv(base_cfg());
    ASSERT_TRUE(srv.start());
    TestClient c;
    c.server_port = srv.server.bound_port();
    ASSERT_TRUE(c.get_nonce());
    auto k = c.key(kPass);

    // EVEN-PORT with R bit set: relayed port must be even.
    StunMessage req = make_allocate();
    req.attributes.push_back({kAttrEvenPort, {0x80}});
    c.add_auth(req);
    StunMessage resp;
    ASSERT_TRUE(c.transact(req, resp, k.data()));
    ASSERT_EQ(resp.cls, StunClass::SuccessResponse);
    uint32_t raddr = 0; uint16_t rport = 0;
    ASSERT_TRUE(decode_xor_address_ipv4(*resp.find(kAttrXorRelayedAddress),
                                        resp.txn_id, raddr, rport));
    EXPECT_EQ(rport & 1u, 0u);

    // REQUESTED-ADDRESS-FAMILY IPv6 on an IPv4-only server: 440.
    UdpSocket other;
    TestClient c2;
    c2.sock = std::move(other);  // fresh 5-tuple
    c2.server_port = c.server_port;
    ASSERT_TRUE(c2.get_nonce());
    StunMessage req2 = make_allocate();
    req2.attributes.push_back({kAttrRequestedAddressFamily, {0x02, 0, 0, 0}});
    c2.add_auth(req2);
    StunMessage resp2;
    ASSERT_TRUE(c2.transact(req2, resp2, k.data()));
    uint32_t code = 0;
    ASSERT_TRUE(TestClient::error_code(resp2, code));
    EXPECT_EQ(code, 440u);
}

TEST(TurnServer, SecondAllocateFromSame5Tuple437) {
    ServerRunner srv(base_cfg());
    ASSERT_TRUE(srv.start());
    TestClient c;
    c.server_port = srv.server.bound_port();
    ASSERT_TRUE(c.get_nonce());
    auto k = c.key(kPass);

    StunMessage req = make_allocate();
    c.add_auth(req);
    StunMessage resp;
    ASSERT_TRUE(c.transact(req, resp, k.data()));
    ASSERT_EQ(resp.cls, StunClass::SuccessResponse);

    StunMessage req2 = make_allocate();
    c.add_auth(req2);
    StunMessage resp2;
    ASSERT_TRUE(c.transact(req2, resp2, k.data()));
    uint32_t code = 0;
    ASSERT_TRUE(TestClient::error_code(resp2, code));
    EXPECT_EQ(code, 437u);
}

TEST(TurnServer, NonUdpRequestedTransport442) {
    ServerRunner srv(base_cfg());
    ASSERT_TRUE(srv.start());
    TestClient c;
    c.server_port = srv.server.bound_port();
    ASSERT_TRUE(c.get_nonce());
    auto k = c.key(kPass);

    StunMessage req;
    req.method = kMethodAllocate;
    req.cls = StunClass::Request;
    req.attributes.push_back({kAttrRequestedTransport, {6, 0, 0, 0}});  // TCP
    c.add_auth(req);
    StunMessage resp;
    ASSERT_TRUE(c.transact(req, resp, k.data()));
    uint32_t code = 0;
    ASSERT_TRUE(TestClient::error_code(resp, code));
    EXPECT_EQ(code, 442u);
    EXPECT_EQ(srv.server.stats().unsupported_transport_442, 1u);
}

TEST(TurnServer, RefreshExtendThenDelete) {
    ServerRunner srv(base_cfg());
    ASSERT_TRUE(srv.start());
    TestClient c;
    c.server_port = srv.server.bound_port();
    ASSERT_TRUE(c.get_nonce());
    auto k = c.key(kPass);

    StunMessage alloc = make_allocate();
    c.add_auth(alloc);
    StunMessage aresp;
    ASSERT_TRUE(c.transact(alloc, aresp, k.data()));
    ASSERT_EQ(aresp.cls, StunClass::SuccessResponse);

    // Extend.
    StunMessage ref;
    ref.method = kMethodRefresh;
    ref.cls = StunClass::Request;
    ref.attributes.push_back({kAttrLifetime, {0, 0, 1, 44}});  // 300 s
    c.add_auth(ref);
    StunMessage rresp;
    ASSERT_TRUE(c.transact(ref, rresp, k.data()));
    ASSERT_EQ(rresp.cls, StunClass::SuccessResponse);
    const StunAttribute* lt = rresp.find(kAttrLifetime);
    ASSERT_NE(lt, nullptr);
    ASSERT_EQ(lt->value.size(), 4u);
    EXPECT_EQ(lt->value[3], 300 & 0xFF);

    // Delete (lifetime=0).
    StunMessage del;
    del.method = kMethodRefresh;
    del.cls = StunClass::Request;
    del.attributes.push_back({kAttrLifetime, {0, 0, 0, 0}});
    c.add_auth(del);
    StunMessage dresp;
    ASSERT_TRUE(c.transact(del, dresp, k.data()));
    ASSERT_EQ(dresp.cls, StunClass::SuccessResponse);
    EXPECT_EQ(srv.server.stats().deleted_via_refresh, 1u);
    EXPECT_EQ(srv.server.stats().allocations_active, 0u);

    // Further Refresh without an allocation: 437.
    StunMessage ref2;
    ref2.method = kMethodRefresh;
    ref2.cls = StunClass::Request;
    c.add_auth(ref2);
    StunMessage r2;
    ASSERT_TRUE(c.transact(ref2, r2, k.data()));
    uint32_t code = 0;
    ASSERT_TRUE(TestClient::error_code(r2, code));
    EXPECT_EQ(code, 437u);
}

TEST(TurnServer, NaturalExpiryRemovesAllocation) {
    TurnServerConfig cfg = base_cfg();
    cfg.default_lifetime = 1;
    cfg.max_lifetime = 1;
    ServerRunner srv(cfg);
    ASSERT_TRUE(srv.start());
    TestClient c;
    c.server_port = srv.server.bound_port();
    ASSERT_TRUE(c.get_nonce());
    auto k = c.key(kPass);

    StunMessage alloc = make_allocate();
    c.add_auth(alloc);
    StunMessage aresp;
    ASSERT_TRUE(c.transact(alloc, aresp, k.data()));
    ASSERT_EQ(aresp.cls, StunClass::SuccessResponse);

    // Wait past the granted lifetime; the poll loop sweeps natural expiry.
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (srv.server.stats().expired_allocations == 0 &&
           std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    EXPECT_EQ(srv.server.stats().expired_allocations, 1u);
    EXPECT_EQ(srv.server.stats().allocations_active, 0u);

    // Refresh after natural expiry: 437 Allocation Mismatch.
    StunMessage ref;
    ref.method = kMethodRefresh;
    ref.cls = StunClass::Request;
    c.add_auth(ref);
    StunMessage rresp;
    ASSERT_TRUE(c.transact(ref, rresp, k.data()));
    uint32_t code = 0;
    ASSERT_TRUE(TestClient::error_code(rresp, code));
    EXPECT_EQ(code, 437u);
}

// ── Data plane ───────────────────────────────────────────────────────────────

TEST(TurnServer, FullRelayPathIndicationsAndChannelData) {
    ServerRunner srv(base_cfg());
    ASSERT_TRUE(srv.start());
    EchoPeer echo;
    echo.start();
    TestClient c;
    c.server_port = srv.server.bound_port();
    ASSERT_TRUE(c.get_nonce());
    auto k = c.key(kPass);

    StunMessage alloc = make_allocate();
    c.add_auth(alloc);
    StunMessage aresp;
    ASSERT_TRUE(c.transact(alloc, aresp, k.data()));
    ASSERT_EQ(aresp.cls, StunClass::SuccessResponse);

    // CreatePermission for the echo peer.
    StunMessage perm;
    perm.method = kMethodCreatePermission;
    perm.cls = StunClass::Request;
    perm.attributes.push_back({kAttrXorPeerAddress,
        encode_xor_address_ipv4(htonl(INADDR_LOOPBACK), echo.sock.port, {})});
    c.add_auth(perm);
    StunMessage presp;
    ASSERT_TRUE(c.transact(perm, presp, k.data()));
    ASSERT_EQ(presp.cls, StunClass::SuccessResponse);

    // Send indication -> relayed to peer -> echo returns as Data indication.
    const std::string ping = "g5-server-bootstrap-ping";
    StunMessage send;
    send.method = kMethodSend;
    send.cls = StunClass::Indication;
    send.txn_id = {};
    send.attributes.push_back({kAttrXorPeerAddress,
        encode_xor_address_ipv4(htonl(INADDR_LOOPBACK), echo.sock.port, {})});
    send.attributes.push_back({kAttrData, {ping.begin(), ping.end()}});
    ASSERT_TRUE(c.sock.send_to(c.server_port, stun_encode(send, nullptr, 0, true)));

    std::vector<uint8_t> raw;
    StunMessage data_ind;
    bool got = false;
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
    while (std::chrono::steady_clock::now() < deadline) {
        if (!c.sock.recv(200, raw)) continue;
        std::string derr;
        if (!stun_decode(raw.data(), raw.size(), data_ind, derr)) continue;
        if (data_ind.cls == StunClass::Indication &&
            data_ind.method == kMethodData) { got = true; break; }
    }
    ASSERT_TRUE(got);
    const StunAttribute* peer = data_ind.find(kAttrXorPeerAddress);
    const StunAttribute* payload = data_ind.find(kAttrData);
    ASSERT_NE(peer, nullptr);
    ASSERT_NE(payload, nullptr);
    uint32_t paddr = 0; uint16_t pport = 0;
    ASSERT_TRUE(decode_xor_address_ipv4(*peer, data_ind.txn_id, paddr, pport));
    EXPECT_EQ(paddr, htonl(INADDR_LOOPBACK));
    EXPECT_EQ(pport, echo.sock.port);
    EXPECT_EQ(std::string(payload->value.begin(), payload->value.end()), ping);

    // ChannelBind + ChannelData both directions.
    const uint16_t channel = 0x4001;
    StunMessage bind;
    bind.method = kMethodChannelBind;
    bind.cls = StunClass::Request;
    bind.attributes.push_back({kAttrChannelNumber,
        {0x40, 0x01, 0, 0}});
    bind.attributes.push_back({kAttrXorPeerAddress,
        encode_xor_address_ipv4(htonl(INADDR_LOOPBACK), echo.sock.port, {})});
    c.add_auth(bind);
    StunMessage bresp;
    ASSERT_TRUE(c.transact(bind, bresp, k.data()));
    ASSERT_EQ(bresp.cls, StunClass::SuccessResponse);

    const std::string pong = "g5-server-channeldata-pong";
    ASSERT_TRUE(c.sock.send_to(c.server_port,
        channel_data_encode(channel,
            reinterpret_cast<const uint8_t*>(pong.data()), pong.size())));
    got = false;
    deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
    uint16_t got_ch = 0;
    std::string got_payload;
    while (std::chrono::steady_clock::now() < deadline) {
        if (!c.sock.recv(200, raw)) continue;
        const uint8_t* pl = nullptr;
        size_t pl_len = 0;
        if (!channel_data_decode(raw.data(), raw.size(), got_ch, pl, pl_len))
            continue;
        got = true;
        got_payload.assign(reinterpret_cast<const char*>(pl), pl_len);
        break;
    }
    ASSERT_TRUE(got);
    EXPECT_EQ(got_ch, channel);
    EXPECT_EQ(got_payload, pong);

    const auto& st = srv.server.stats();
    EXPECT_GE(st.send_indications_relayed, 1u);
    EXPECT_GE(st.data_indications_sent, 1u);
    EXPECT_GE(st.channel_data_to_peer, 1u);
    EXPECT_GE(st.channel_data_to_client, 1u);
}

TEST(TurnServer, PeerTrafficWithoutPermissionDropped) {
    ServerRunner srv(base_cfg());
    ASSERT_TRUE(srv.start());
    TestClient c;
    c.server_port = srv.server.bound_port();
    ASSERT_TRUE(c.get_nonce());
    auto k = c.key(kPass);

    StunMessage alloc = make_allocate();
    c.add_auth(alloc);
    StunMessage aresp;
    ASSERT_TRUE(c.transact(alloc, aresp, k.data()));
    ASSERT_EQ(aresp.cls, StunClass::SuccessResponse);
    uint32_t raddr = 0; uint16_t rport = 0;
    ASSERT_TRUE(decode_xor_address_ipv4(*aresp.find(kAttrXorRelayedAddress),
                                        aresp.txn_id, raddr, rport));

    // A peer datagram straight to the relay port, with NO permission
    // installed: must be dropped fail-closed (no Data indication).
    UdpSocket peer;
    const std::string sneaky = "no-permission-payload";
    ASSERT_TRUE(peer.send_to(rport, {sneaky.begin(), sneaky.end()}));
    std::vector<uint8_t> raw;
    EXPECT_FALSE(c.sock.recv(500, raw));
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    while (srv.server.stats().permission_denied_dropped == 0 &&
           std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    EXPECT_EQ(srv.server.stats().permission_denied_dropped, 1u);
}

TEST(TurnServer, MalformedAndUnauthenticatedDataPlaneDropped) {
    ServerRunner srv(base_cfg());
    ASSERT_TRUE(srv.start());
    UdpSocket c;
    // Garbage datagram: not STUN, not ChannelData.
    std::vector<uint8_t> junk = {0xDE, 0xAD, 0xBE, 0xEF};
    ASSERT_TRUE(c.send_to(srv.server.bound_port(), junk));
    // ChannelData framing from a 5-tuple with no allocation.
    const std::string p = "x";
    ASSERT_TRUE(c.send_to(srv.server.bound_port(),
        channel_data_encode(0x4001,
            reinterpret_cast<const uint8_t*>(p.data()), p.size())));
    std::vector<uint8_t> raw;
    EXPECT_FALSE(c.recv(500, raw));  // fail closed: no response to either
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    while ((srv.server.stats().malformed_dropped == 0 ||
            srv.server.stats().no_allocation_dropped == 0) &&
           std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    EXPECT_GE(srv.server.stats().malformed_dropped, 1u);
    EXPECT_GE(srv.server.stats().no_allocation_dropped, 1u);
}

TEST(TurnServer, TransactionReplayCacheResendsCachedResponse) {
    ServerRunner srv(base_cfg());
    ASSERT_TRUE(srv.start());
    TestClient c;
    c.server_port = srv.server.bound_port();
    ASSERT_TRUE(c.get_nonce());
    auto k = c.key(kPass);

    StunMessage req = make_allocate();
    c.add_auth(req);
    req.txn_id = {};
    for (size_t i = 0; i < 12; ++i) req.txn_id[i] = (uint8_t)(0xA0 + i);
    std::vector<uint8_t> bytes = stun_encode(req, k.data(), k.size(), true);

    // Send the identical request bytes twice (UDP retransmission).
    ASSERT_TRUE(c.sock.send_to(c.server_port, bytes));
    ASSERT_TRUE(c.sock.send_to(c.server_port, bytes));

    std::vector<std::vector<uint8_t>> responses;
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
    while (responses.size() < 2 &&
           std::chrono::steady_clock::now() < deadline) {
        std::vector<uint8_t> raw;
        if (!c.sock.recv(200, raw)) continue;
        responses.push_back(raw);
    }
    ASSERT_EQ(responses.size(), 2u);
    // The retransmission is answered from the replay cache: byte-identical,
    // and NOT processed again (a second Allocate would have been 437).
    EXPECT_EQ(responses[0], responses[1]);
    StunMessage m;
    std::string derr;
    ASSERT_TRUE(stun_decode(responses[1].data(), responses[1].size(), m, derr));
    EXPECT_EQ(m.cls, StunClass::SuccessResponse);
    auto deadline2 = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    while (srv.server.stats().replay_cache_hits == 0 &&
           std::chrono::steady_clock::now() < deadline2) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    EXPECT_EQ(srv.server.stats().replay_cache_hits, 1u);
    EXPECT_EQ(srv.server.stats().allocations_active, 1u);
}
