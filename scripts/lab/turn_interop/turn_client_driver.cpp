// ══════════════════════════════════════════════════════════════════════════════
// scripts/lab/turn_interop/turn_client_driver.cpp
//
// G5 live-interop driver: exercises ncp::turn::TurnClient against a REAL TURN
// server (pinned coturn) over loopback UDP.
//
// Flow:
//   1. open + Allocate (long-term credentials, 401/nonce/MESSAGE-INTEGRITY)
//   2. CreatePermission to the UDP echo peer
//   3. Bootstrap: Send indication -> Data indication echo
//   4. ChannelBind -> ChannelData echo (application exchange)
//   5. Refresh (extend lifetime), Refresh(0) (delete allocation)
//
// Usage: turn_client_driver <server_ip> <server_port> <user> <pass>
//                             <echo_ip> <echo_port> [--natural-expiry]
// Exit 0 and prints "G5_INTEROP PASS" on success; exit 1 with FAIL otherwise.
//
// Credentials come from the command line (generated independently by the
// harness script); nothing is derived from HopSecret/E2E/mask material.
// ══════════════════════════════════════════════════════════════════════════════

#include "ncp_turn_client.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

using ncp::turn::TurnClient;
using ncp::turn::TurnConfig;
using ncp::turn::TurnReceivedData;
using ncp::turn::TurnState;

namespace {

int g_failures = 0;

#define CHECK(cond, step)                                              \
    do {                                                               \
        if (!(cond)) {                                                 \
            std::printf("G5_INTEROP FAIL step=%s err=%s\n", step, err.c_str()); \
            ++g_failures;                                              \
            return 1;                                                  \
        }                                                              \
        std::printf("G5_INTEROP ok: %s\n", step);                      \
    } while (0)

std::string ip_to_str(uint32_t addr_be) {
    in_addr a{addr_be};
    char buf[INET_ADDRSTRLEN] = {0};
    inet_ntop(AF_INET, &a, buf, sizeof(buf));
    return buf;
}

bool wait_payload(TurnClient& c, bool via_channel,
                  const std::string& expect, int timeout_ms,
                  TurnReceivedData& got, std::string& err) {
    auto deadline = std::chrono::steady_clock::now() +
                    std::chrono::milliseconds(timeout_ms);
    while (std::chrono::steady_clock::now() < deadline) {
        std::vector<TurnReceivedData> rx;
        if (!c.poll(200, &rx, &err)) return false;
        for (auto& r : rx) {
            if (r.via_channel != via_channel) continue;
            std::string s(reinterpret_cast<const char*>(r.payload.data()),
                          r.payload.size());
            if (s == expect) { got = std::move(r); return true; }
        }
    }
    err = "timeout waiting for relayed payload";
    return false;
}

} // namespace

int main(int argc, char** argv) {
    if (argc < 7 || argc > 8 ||
        (argc == 8 && std::string(argv[7]) != "--natural-expiry")) {
        std::fprintf(stderr,
            "usage: %s <server_ip> <server_port> <user> <pass> <echo_ip> <echo_port> [--natural-expiry]\n",
            argv[0]);
        return 2;
    }
    const bool test_natural_expiry = argc == 8;
    const std::string server_ip = argv[1];
    const uint16_t server_port = static_cast<uint16_t>(std::atoi(argv[2]));
    const std::string user = argv[3];
    const std::string pass = argv[4];
    const std::string echo_ip = argv[5];
    const uint16_t echo_port = static_cast<uint16_t>(std::atoi(argv[6]));

    TurnConfig cfg;
    cfg.server_address = server_ip;
    cfg.server_port = server_port;
    cfg.username = user;          // independently supplied credentials
    cfg.password = pass;
    cfg.requested_lifetime = 600;
    cfg.rto_ms = 300;
    cfg.max_retransmits = 7;

    std::string err;
    TurnClient c(cfg);

    CHECK(c.open(&err), "open");
    CHECK(c.allocate(&err), "allocate");
    std::printf("G5_INTEROP relayed=%s:%u lifetime=%u realm=%s\n",
                ip_to_str(c.relayed_addr_be()).c_str(), c.relayed_port(),
                c.granted_lifetime(), c.realm().c_str());
    CHECK(c.state() == TurnState::Allocated, "state_allocated");
    CHECK(c.lifetime_remaining() > 0, "lifetime_positive");

    CHECK(c.create_permission(echo_ip, echo_port, &err), "create_permission");

    // Bootstrap path: Send indication -> Data indication.
    const std::string boot = "g5-bootstrap-send-indication";
    CHECK(c.send_indication(echo_ip, echo_port,
          reinterpret_cast<const uint8_t*>(boot.data()), boot.size(), &err),
          "send_indication");
    TurnReceivedData rx;
    CHECK(wait_payload(c, /*via_channel=*/false, boot, 5000, rx, err),
          "data_indication_echo");
    std::printf("G5_INTEROP data_indication_from=%s:%u bytes=%zu\n",
                ip_to_str(rx.peer_addr_be).c_str(), rx.peer_port,
                rx.payload.size());

    // ChannelData application flow.
    const uint16_t channel = 0x4011;
    CHECK(c.channel_bind(echo_ip, echo_port, channel, &err), "channel_bind");
    CHECK(c.state() == TurnState::Bound, "state_bound");
    CHECK(!c.send_indication(echo_ip, echo_port,
          reinterpret_cast<const uint8_t*>(boot.data()), boot.size(), &err),
          "send_indication_rejected_after_bind");
    const std::string ping = "g5-channeldata-application-exchange";
    CHECK(c.send_channel_data(reinterpret_cast<const uint8_t*>(ping.data()),
                              ping.size(), &err), "send_channel_data");
    CHECK(wait_payload(c, /*via_channel=*/true, ping, 5000, rx, err),
          "channeldata_echo");
    CHECK(rx.channel == channel, "channel_number_match");
    std::printf("G5_INTEROP channel=0x%04x echo_bytes=%zu\n",
                rx.channel, rx.payload.size());

    // Refresh: extend, then delete (lifetime=0).
    CHECK(c.refresh(600, &err), "refresh_extend");
    CHECK(c.granted_lifetime() > 0, "refresh_lifetime");
    CHECK(c.refresh(0, &err), "refresh_delete");
    CHECK(c.state() == TurnState::Closed, "state_closed_after_delete");

    const auto& st = c.stats();
    std::printf("G5_INTEROP stats retransmits=%llu timeouts=%llu "
                "unknown_txn=%llu replayed_txn=%llu bad_integrity=%llu "
                "channel_rx=%llu data_ind_rx=%llu\n",
                (unsigned long long)st.retransmits,
                (unsigned long long)st.timeouts,
                (unsigned long long)st.unknown_txn_dropped,
                (unsigned long long)st.replayed_txn_dropped,
                (unsigned long long)st.bad_integrity_dropped,
                (unsigned long long)st.channel_data_rx,
                (unsigned long long)st.data_indication_rx);

    c.close();

    if (test_natural_expiry) {
        // Refresh(0) above is explicit deletion, not natural expiry. Use a new
        // short-lived allocation and prove that coturn rejects a new operation
        // only after its granted wall-clock lifetime has actually elapsed.
        cfg.requested_lifetime = 1;
        TurnClient expiring(cfg);
        CHECK(expiring.open(&err), "expiry_open");
        CHECK(expiring.allocate(&err), "expiry_allocate");
        const uint32_t granted = expiring.granted_lifetime();
        CHECK(granted > 0 && granted <= 10, "expiry_short_lifetime_granted");
        CHECK(expiring.create_permission(echo_ip, echo_port, &err),
              "expiry_create_permission_while_active");
        CHECK(expiring.channel_bind(echo_ip, echo_port, 0x4022, &err),
              "expiry_channel_bind_while_active");
        std::printf("G5_NATURAL_EXPIRY waiting=%u seconds\n", granted + 2);
        std::this_thread::sleep_for(std::chrono::seconds(granted + 2));
        CHECK(expiring.lifetime_remaining() == 0, "expiry_local_clock_elapsed");

        // The decisive data-plane gate: a previously valid bound channel must
        // no longer relay application data after natural allocation expiry.
        const std::string after_expiry = "must-not-be-relayed-after-expiry";
        CHECK(expiring.send_channel_data(
              reinterpret_cast<const uint8_t*>(after_expiry.data()),
              after_expiry.size(), &err), "expiry_channeldata_send_attempt");
        CHECK(!wait_payload(expiring, /*via_channel=*/true, after_expiry,
                            1500, rx, err),
              "expiry_channeldata_not_relayed");
        std::printf("G5_NATURAL_EXPIRY no_channeldata_echo=1\n");
        expiring.close();
        std::printf("G5_NATURAL_EXPIRY PASS\n");
    }

    std::printf("G5_INTEROP PASS\n");
    return 0;
}
