// Deterministic no-network tests for parallel blockcheck, winner validation,
// and bounded concurrent AutoPilot learning.
#include <gtest/gtest.h>

#include "ncp_autopilot.hpp"
#include "ncp_blockcheck.hpp"
#include "ncp_test_temp.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <future>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#ifndef _WIN32
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace {

using ncp::AutoPilot;
using ncp::AutoPilotStrategy;
using ncp::BlockChecker;
using ncp::BlockcheckProbe;
using ncp::BlockcheckReport;
using ncp::BlockcheckStrategy;
using ncp::BlockcheckStrategyResult;

BlockcheckStrategy split_strategy(const std::string& name, int position) {
    BlockcheckStrategy s;
    s.name = name;
    s.description = name + " test strategy";
    s.config.enable_tcp_split = true;
    s.config.split_position = position;
    return s;
}

BlockcheckProbe probe(const std::string& domain, bool ok, int latency = 10) {
    BlockcheckProbe p;
    p.domain = domain;
    p.ok = ok;
    p.latency_ms = ok ? latency : 0;
    if (!ok) p.fail_reason = "timeout";
    return p;
}

BlockcheckReport learned_report(const std::string& host) {
    BlockcheckReport rep;
    rep.best_strategy = "split-2";
    rep.best_description = "test split";
    rep.best_config.enable_tcp_split = true;
    rep.best_config.split_position = 2;
    BlockcheckStrategyResult sr;
    sr.strategy = rep.best_strategy;
    sr.success_count = 1;
    sr.total = 1;
    sr.score = 99990;
    sr.probes.push_back(probe(host, true));
    rep.results.push_back(sr);
    return rep;
}

TEST(BlockcheckParallel, UsesBoundedWorkersAndPreservesDomainOrder) {
    const std::vector<std::string> domains = {
        "a.test", "b.test", "c.test", "d.test", "e.test", "f.test"};
    std::atomic<int> active{0};
    std::atomic<int> max_active{0};

    BlockChecker::Config cfg;
    cfg.domains = domains;
    cfg.strategies = {split_strategy("split-2", 2)};
    cfg.max_parallel_probes = 3;
    cfg.validation_rounds = 0;
    cfg.probe_fn = [&](const BlockcheckStrategy&, const std::string& domain, int) {
        const int now = active.fetch_add(1) + 1;
        int expected = max_active.load();
        while (now > expected && !max_active.compare_exchange_weak(expected, now)) {}
        std::this_thread::sleep_for(std::chrono::milliseconds(30));
        active.fetch_sub(1);
        return probe(domain, true);
    };

    BlockChecker checker;
    auto rep = checker.run(cfg);
    ASSERT_EQ(rep.results.size(), 1u);
    ASSERT_EQ(rep.results[0].probes.size(), domains.size());
    EXPECT_EQ(rep.results[0].success_count, 6);
    EXPECT_EQ(rep.best_strategy, "split-2");
    EXPECT_FALSE(rep.best_validated);
    EXPECT_EQ(rep.parallel_probes, 3u);
    EXPECT_GT(max_active.load(), 1);
    EXPECT_LE(max_active.load(), 3);
    for (size_t i = 0; i < domains.size(); ++i)
        EXPECT_EQ(rep.results[0].probes[i].domain, domains[i]);
}

TEST(BlockcheckParallel, ReducesWallTimeForIndependentDomains) {
    BlockChecker::Config cfg;
    cfg.domains = {"a.test", "b.test", "c.test", "d.test"};
    cfg.strategies = {split_strategy("split-2", 2)};
    cfg.validation_rounds = 0;
    cfg.probe_fn = [&](const BlockcheckStrategy&, const std::string& domain, int) {
        std::this_thread::sleep_for(std::chrono::milliseconds(80));
        return probe(domain, true);
    };

    BlockChecker checker;
    cfg.max_parallel_probes = 1;
    auto sequential = checker.run(cfg);
    cfg.max_parallel_probes = 4;
    auto parallel = checker.run(cfg);

    ASSERT_EQ(sequential.results.size(), 1u);
    ASSERT_EQ(parallel.results.size(), 1u);
    EXPECT_EQ(sequential.results[0].success_count, 4);
    EXPECT_EQ(parallel.results[0].success_count, 4);
    EXPECT_GE(sequential.duration_ms, 300);
    EXPECT_LT(parallel.duration_ms, sequential.duration_ms / 2);
}

TEST(BlockcheckParallel, ClampsValidationAndTimeoutBudget) {
    std::atomic<int> calls{0};
    std::atomic<int> observed_timeout{0};
    BlockChecker::Config cfg;
    cfg.domains = {"a.test"};
    cfg.strategies = {split_strategy("split-1", 1)};
    cfg.timeout_ms = -1;
    cfg.validation_rounds = 1000;
    cfg.probe_fn = [&](const BlockcheckStrategy&, const std::string& domain, int timeout) {
        observed_timeout.store(timeout);
        ++calls;
        return probe(domain, true);
    };

    BlockChecker checker;
    auto rep = checker.run(cfg);
    EXPECT_EQ(rep.validation_rounds, 8u);
    EXPECT_EQ(observed_timeout.load(), 1);
    EXPECT_EQ(calls.load(), 9);  // discovery + eight bounded confirmations
    EXPECT_TRUE(rep.best_validated);
}

#ifndef _WIN32
TEST(BlockcheckNetwork, AcceptsFragmentedSocks5AndTlsHeaders) {
    const int listener = ::socket(AF_INET, SOCK_STREAM, 0);
    ASSERT_GE(listener, 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    ASSERT_EQ(::bind(listener, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)), 0);
    ASSERT_EQ(::listen(listener, 1), 0);
    socklen_t addr_len = sizeof(addr);
    ASSERT_EQ(::getsockname(listener, reinterpret_cast<sockaddr*>(&addr), &addr_len), 0);
    const uint16_t port = ntohs(addr.sin_port);
    std::atomic<bool> server_ok{true};

    std::thread server([&] {
        const int client = ::accept(listener, nullptr, nullptr);
        if (client < 0) { server_ok.store(false); return; }
        auto read_full = [&](void* data, size_t size) {
            auto* out = static_cast<uint8_t*>(data);
            size_t done = 0;
            while (done < size) {
                const ssize_t n = ::recv(client, out + done, size - done, 0);
                if (n <= 0) return false;
                done += static_cast<size_t>(n);
            }
            return true;
        };
        auto send_fragments = [&](const uint8_t* data, size_t size) {
            for (size_t i = 0; i < size; ++i) {
                if (::send(client, data + i, 1, 0) != 1) return false;
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
            return true;
        };

        uint8_t greeting[3];
        const uint8_t greeting_reply[2] = {0x05, 0x00};
        if (!read_full(greeting, sizeof(greeting)) ||
            !send_fragments(greeting_reply, sizeof(greeting_reply))) {
            server_ok.store(false); ::close(client); return;
        }
        uint8_t request[4];
        if (!read_full(request, sizeof(request))) {
            server_ok.store(false); ::close(client); return;
        }
        size_t tail_len = 0;
        uint8_t domain_len = 0;
        if (request[3] == 0x03) {
            if (!read_full(&domain_len, 1)) { server_ok.store(false); ::close(client); return; }
            tail_len = static_cast<size_t>(domain_len) + 2;
        } else if (request[3] == 0x01) tail_len = 6;
        else if (request[3] == 0x04) tail_len = 18;
        uint8_t request_tail[257];
        if (tail_len == 0 || !read_full(request_tail, tail_len)) {
            server_ok.store(false); ::close(client); return;
        }
        const uint8_t connect_reply[10] = {0x05, 0x00, 0x00, 0x01,
                                           127, 0, 0, 1, 0x01, 0xBB};
        if (!send_fragments(connect_reply, sizeof(connect_reply))) {
            server_ok.store(false); ::close(client); return;
        }
        uint8_t hello_prefix[5];
        if (!read_full(hello_prefix, sizeof(hello_prefix))) {
            server_ok.store(false); ::close(client); return;
        }
        const size_t hello_body_len =
            (static_cast<size_t>(hello_prefix[3]) << 8) | hello_prefix[4];
        std::vector<uint8_t> hello_body(hello_body_len);
        if (!read_full(hello_body.data(), hello_body.size())) {
            server_ok.store(false); ::close(client); return;
        }
        const uint8_t server_hello_prefix[6] = {0x16, 0x03, 0x03, 0x00, 0x00, 0x02};
        if (!send_fragments(server_hello_prefix, sizeof(server_hello_prefix))) {
            server_ok.store(false); ::close(client); return;
        }
        // Let the probe close first; closing a TCP socket with unread client
        // data can otherwise RST and discard the fragmented test response.
        uint8_t eof;
        (void)::recv(client, &eof, 1, 0);
        ::close(client);
    });

    auto result = BlockChecker::probe_via_socks5(port, "a.test", 1000);
    server.join();
    ::close(listener);
    EXPECT_TRUE(server_ok.load());
    EXPECT_TRUE(result.ok);
    EXPECT_EQ(result.fail_reason, "");
}
#endif

TEST(BlockcheckValidation, RejectsFlakyLeaderAndSelectsStableCandidate) {
    std::mutex mu;
    std::map<std::pair<std::string, std::string>, int> calls;
    BlockChecker::Config cfg;
    cfg.domains = {"a.test", "b.test"};
    cfg.strategies = {split_strategy("split-1", 1), split_strategy("split-2", 2)};
    cfg.max_parallel_probes = 2;
    cfg.validation_rounds = 1;
    cfg.max_validation_candidates = 2;
    cfg.probe_fn = [&](const BlockcheckStrategy& s, const std::string& domain, int) {
        int call;
        {
            std::lock_guard<std::mutex> lk(mu);
            call = ++calls[{s.name, domain}];
        }
        if (s.name == "split-1" && call > 1) return probe(domain, false);
        return probe(domain, true, s.name == "split-1" ? 1 : 10);
    };

    BlockChecker checker;
    auto rep = checker.run(cfg);
    EXPECT_EQ(rep.best_strategy, "split-2");
    EXPECT_TRUE(rep.best_validated);
    ASSERT_EQ(rep.results.size(), 2u);
    EXPECT_TRUE(rep.results[0].validation_attempted);
    EXPECT_FALSE(rep.results[0].validated);
    EXPECT_EQ(rep.results[0].success_count, 0);
    EXPECT_EQ(rep.results[0].validation_probes.size(), 2u);
    for (const auto& p : rep.results[0].probes) {
        EXPECT_FALSE(p.ok);
        EXPECT_EQ(p.fail_reason, "unstable");
    }
    EXPECT_TRUE(rep.results[1].validated);
    EXPECT_EQ(rep.results[1].success_count, 2);
}

TEST(BlockcheckValidation, DoesNotApplyUnstableWinner) {
    std::atomic<int> calls{0};
    BlockChecker::Config cfg;
    cfg.domains = {"a.test"};
    cfg.strategies = {split_strategy("split-1", 1)};
    cfg.validation_rounds = 1;
    cfg.probe_fn = [&](const BlockcheckStrategy&, const std::string& domain, int) {
        return probe(domain, calls.fetch_add(1) == 0);
    };

    BlockChecker checker;
    auto rep = checker.run(cfg);
    EXPECT_TRUE(rep.best_strategy.empty());
    EXPECT_FALSE(rep.best_validated);
    EXPECT_EQ(BlockChecker::best_strategy_to_profile_json(rep), "{}\n");
    const std::string json = BlockChecker::report_to_json(rep);
    EXPECT_NE(json.find("\"best_validated\": false"), std::string::npos);
    EXPECT_NE(json.find("\"fail\": \"unstable\""), std::string::npos);
    EXPECT_NE(json.find("\"validation_probes\""), std::string::npos);
}

TEST(BlockcheckValidation, EarlyExitSkipsRemainingStrategiesOnlyAfterConfirmation) {
    std::mutex mu;
    std::map<std::string, int> calls;
    BlockChecker::Config cfg;
    cfg.domains = {"a.test", "b.test"};
    cfg.strategies = {split_strategy("split-1", 1), split_strategy("split-2", 2),
                      split_strategy("split-3", 3)};
    cfg.max_parallel_probes = 2;
    cfg.validation_rounds = 1;
    cfg.early_exit = true;
    cfg.probe_fn = [&](const BlockcheckStrategy& s, const std::string& domain, int) {
        {
            std::lock_guard<std::mutex> lk(mu);
            ++calls[s.name];
        }
        return probe(domain, true);
    };

    BlockChecker checker;
    auto rep = checker.run(cfg);
    EXPECT_EQ(rep.best_strategy, "split-1");
    EXPECT_TRUE(rep.best_validated);
    EXPECT_TRUE(rep.early_exit_taken);
    ASSERT_EQ(rep.results.size(), 1u);
    EXPECT_EQ(rep.results[0].validation_probes.size(), 2u);
    EXPECT_EQ(calls["split-1"], 4);  // discovery + one confirmation, two domains
    EXPECT_EQ(calls["split-2"], 0);
    EXPECT_EQ(calls["split-3"], 0);
}

TEST(BlockcheckValidation, FullSweepChecksStrategiesAfterValidatedWinner) {
    std::mutex mu;
    std::map<std::string, int> calls;
    BlockChecker::Config cfg;
    cfg.domains = {"a.test"};
    cfg.strategies = {split_strategy("split-1", 1), split_strategy("split-2", 2),
                      split_strategy("split-3", 3)};
    cfg.validation_rounds = 1;
    cfg.early_exit = false;
    cfg.probe_fn = [&](const BlockcheckStrategy& s, const std::string& domain, int) {
        {
            std::lock_guard<std::mutex> lk(mu);
            ++calls[s.name];
        }
        return probe(domain, true);
    };

    BlockChecker checker;
    auto rep = checker.run(cfg);
    EXPECT_EQ(rep.results.size(), 3u);
    EXPECT_EQ(rep.best_strategy, "split-1");
    EXPECT_TRUE(rep.best_validated);
    EXPECT_FALSE(rep.early_exit_taken);
    EXPECT_EQ(calls["split-1"], 2);
    EXPECT_EQ(calls["split-2"], 2);
    EXPECT_EQ(calls["split-3"], 2);
}

TEST(AutoPilotParallel, LearnsIndependentHostsConcurrentlyAndPersistsBoth) {
    const std::string db = ncp_test::temp_path("ncp_test_autopilot_parallel.json");
    std::remove(db.c_str());
    std::atomic<int> active{0};
    std::atomic<int> max_active{0};

    AutoPilot::Config cfg;
    cfg.db_path = db;
    cfg.max_parallel_learns = 2;
    cfg.background_relearn = false;
    cfg.report_fn = [&](const std::string& host, int) {
        const int now = active.fetch_add(1) + 1;
        int expected = max_active.load();
        while (now > expected && !max_active.compare_exchange_weak(expected, now)) {}
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        active.fetch_sub(1);
        return learned_report(host);
    };

    AutoPilot ap;
    ASSERT_TRUE(ap.load(cfg));
    auto first = std::async(std::launch::async, [&] { return ap.learn("a.test"); });
    auto second = std::async(std::launch::async, [&] { return ap.learn("b.test"); });
    EXPECT_TRUE(first.get());
    EXPECT_TRUE(second.get());
    EXPECT_EQ(max_active.load(), 2);
    EXPECT_EQ(ap.records().size(), 2u);
    AutoPilotStrategy st;
    ASSERT_TRUE(ap.lookup("a.test", &st));
    EXPECT_EQ(st.name, "split-2");
    ASSERT_TRUE(ap.lookup("b.test", &st));
    EXPECT_EQ(st.name, "split-2");

    AutoPilot reloaded;
    AutoPilot::Config reload_cfg;
    reload_cfg.db_path = db;
    reload_cfg.background_relearn = false;
    ASSERT_TRUE(reloaded.load(reload_cfg));
    EXPECT_EQ(reloaded.records().size(), 2u);
    std::remove(db.c_str());
}

TEST(AutoPilotParallel, RejectsDuplicateInflightLearnOfSameHost) {
    const std::string db = ncp_test::temp_path("ncp_test_autopilot_same_host.json");
    std::remove(db.c_str());
    std::atomic<bool> entered{false};
    AutoPilot::Config cfg;
    cfg.db_path = db;
    cfg.max_parallel_learns = 2;
    cfg.background_relearn = false;
    cfg.report_fn = [&](const std::string& host, int) {
        entered.store(true);
        std::this_thread::sleep_for(std::chrono::milliseconds(80));
        return learned_report(host);
    };

    AutoPilot ap;
    ASSERT_TRUE(ap.load(cfg));
    auto first = std::async(std::launch::async, [&] { return ap.learn("a.test"); });
    while (!entered.load()) std::this_thread::sleep_for(std::chrono::milliseconds(2));
    EXPECT_FALSE(ap.learn("A.TEST."));
    EXPECT_TRUE(first.get());
    EXPECT_EQ(ap.records().size(), 1u);
    std::remove(db.c_str());
}

TEST(AutoPilotParallel, EnforcesLearnLimit) {
    const std::string db = ncp_test::temp_path("ncp_test_autopilot_limit.json");
    std::remove(db.c_str());
    std::atomic<bool> entered{false};
    AutoPilot::Config cfg;
    cfg.db_path = db;
    cfg.max_parallel_learns = 1;
    cfg.background_relearn = false;
    cfg.report_fn = [&](const std::string& host, int) {
        entered.store(true);
        std::this_thread::sleep_for(std::chrono::milliseconds(80));
        return learned_report(host);
    };

    AutoPilot ap;
    ASSERT_TRUE(ap.load(cfg));
    auto first = std::async(std::launch::async, [&] { return ap.learn("a.test"); });
    while (!entered.load()) std::this_thread::sleep_for(std::chrono::milliseconds(2));
    EXPECT_FALSE(ap.learn("b.test"));
    EXPECT_TRUE(first.get());
    EXPECT_EQ(ap.records().size(), 1u);
    std::remove(db.c_str());
}

} // namespace
