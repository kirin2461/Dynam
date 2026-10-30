// ══════════════════════════════════════════════════════════════════════════════
// scripts/lab/turn_interop/turn_server_driver.cpp
//
// G5 live-interop driver: standalone ncp::turn::TurnServer CLI for interop
// harnesses (loopback lab use). Prints "READY <actual_port>" once listening,
// then runs the single owner poll loop until SIGTERM/SIGINT.
//
// Usage:
//   turn_server_driver <bind_ip> <bind_port> <relay_ip> <realm> <user> <pass>
//
// bind_port 0 picks an ephemeral port (reported via READY). Credentials come
// from the command line (generated independently by the harness script);
// nothing is derived from HopSecret/E2E/mask material.
// ══════════════════════════════════════════════════════════════════════════════

#include "ncp_turn_server.hpp"

#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <string>

namespace {
volatile std::sig_atomic_t g_stop = 0;
void on_signal(int) { g_stop = 1; }
} // namespace

int main(int argc, char** argv) {
    if (argc != 7) {
        std::fprintf(stderr,
            "usage: %s <bind_ip> <bind_port> <relay_ip> <realm> <user> <pass>\n",
            argv[0]);
        return 2;
    }
    ncp::turn::TurnServerConfig cfg;
    cfg.bind_ip = argv[1];
    cfg.bind_port = static_cast<uint16_t>(std::atoi(argv[2]));
    cfg.relay_ip = argv[3];
    cfg.realm = argv[4];
    cfg.users = {{argv[5], argv[6]}};  // independently supplied credentials

    ncp::turn::TurnServer server(cfg);
    std::string err;
    if (!server.open(&err)) {
        std::fprintf(stderr, "turn_server_driver: open failed: %s\n",
                     err.c_str());
        return 1;
    }

    std::signal(SIGTERM, on_signal);
    std::signal(SIGINT, on_signal);

    std::printf("READY %u\n", server.bound_port());
    std::fflush(stdout);

    while (!g_stop) {
        if (server.poll(50, &err) < 0) {
            std::fprintf(stderr, "turn_server_driver: poll failed: %s\n",
                         err.c_str());
            return 1;
        }
    }

    const auto& st = server.stats();
    std::fprintf(stderr,
        "turn_server_driver: stopped; allocations_total=%llu "
        "auth401=%llu stale438=%llu bad_integrity=%llu malformed=%llu "
        "perm_denied=%llu replay_hits=%llu ch_to_peer=%llu ch_to_client=%llu "
        "data_ind=%llu send_ind=%llu\n",
        (unsigned long long)st.allocations_total,
        (unsigned long long)st.auth_challenges_401,
        (unsigned long long)st.stale_nonce_438,
        (unsigned long long)st.bad_integrity_rejected,
        (unsigned long long)st.malformed_dropped,
        (unsigned long long)st.permission_denied_dropped,
        (unsigned long long)st.replay_cache_hits,
        (unsigned long long)st.channel_data_to_peer,
        (unsigned long long)st.channel_data_to_client,
        (unsigned long long)st.data_indications_sent,
        (unsigned long long)st.send_indications_relayed);
    server.close();
    return 0;
}
