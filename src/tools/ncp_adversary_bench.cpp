/**
 * @file ncp_adversary_bench.cpp
 * @brief Strategy benchmark bridge for the web UI (/api/stealth/benchmark).
 *
 * Runs AdversaryTester::run_strategy_benchmark() over adversarial padding
 * strategies and prints a single JSON document on stdout:
 *
 *   {"strategies":[{"strategy":"ADAPTIVE","avg_stealth":0.81,
 *                   "min_stealth":0.77,"max_stealth":0.85,
 *                   "detection_rate":0.0,"runs":8}, ...],
 *    "best_strategy":"ADAPTIVE","best_stealth":0.81}
 *
 * Usage:
 *   ncp-adversary-bench [--strategy NAME|all] [--samples N] [--runs N]
 *
 * NAME (case-insensitive): RANDOM | HTTP_MIMIC | TLS_MIMIC | QUIC_MIMIC |
 *                          DNS_MIMIC | ADAPTIVE
 */

#include "ncp_adversary_tester.hpp"
#include "ncp_adversarial.hpp"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

using ncp::DPI::AdversaryTester;
using ncp::DPI::AdversarialConfig;
using ncp::DPI::AdversarialPadding;
using ncp::DPI::strategy_from_string;
using ncp::DPI::strategy_to_string;
using ncp::DPI::AdversarialStrategy;
using ncp::DPI::TestReport;

static const char* kStrategies[] = {
    "RANDOM", "HTTP_MIMIC", "TLS_MIMIC", "QUIC_MIMIC", "DNS_MIMIC", "ADAPTIVE"};

int main(int argc, char** argv) {
    std::string strategy = "all";
    size_t samples = 200;
    size_t runs = 8;

    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--strategy" && i + 1 < argc) {
            strategy = argv[++i];
        } else if (a == "--samples" && i + 1 < argc) {
            samples = static_cast<size_t>(std::atoi(argv[++i]));
        } else if (a == "--runs" && i + 1 < argc) {
            runs = static_cast<size_t>(std::atoi(argv[++i]));
        } else if (a == "--help" || a == "-h") {
            std::printf("usage: ncp-adversary-bench [--strategy NAME|all] "
                        "[--samples N] [--runs N]\n");
            return 0;
        } else {
            std::fprintf(stderr, "unknown argument: %s\n", a.c_str());
            return 2;
        }
    }

    samples = std::max<size_t>(10, std::min<size_t>(samples, 5000));
    runs = std::max<size_t>(1, std::min<size_t>(runs, 100));

    std::vector<std::string> list;
    if (strategy == "all" || strategy.empty()) {
        for (const char* s : kStrategies) list.push_back(s);
    } else {
        AdversarialStrategy s = strategy_from_string(strategy);
        if (s == AdversarialStrategy::CUSTOM) {
            std::fprintf(stderr, "CUSTOM strategy is not benchmarkable\n");
            return 2;
        }
        list.push_back(strategy_to_string(s));
    }

    std::string best_name;
    double best_stealth = -1.0;
    bool first = true;

    std::printf("{\"strategies\":[");
    for (const auto& name : list) {
        AdversarialStrategy s = strategy_from_string(name);

        // Configure the padder for THIS strategy — run_strategy_benchmark()
        // feeds payloads through padder.pad(), so the strategy must live in
        // the padder config.
        AdversarialConfig cfg;
        cfg.enabled = true;
        cfg.strategy = s;
        AdversarialPadding padder(cfg);
        AdversaryTester tester;

        std::vector<double> stealths;
        size_t detected = 0;
        for (size_t r = 0; r < runs; ++r) {
            TestReport rep = tester.run_strategy_benchmark(s, padder, samples);
            double st = rep.scores.aggregate_stealth();
            stealths.push_back(st);
            if (rep.detected) ++detected;
        }

        double sum = 0.0, mn = 1e9, mx = -1e9;
        for (double v : stealths) {
            sum += v;
            mn = std::min(mn, v);
            mx = std::max(mx, v);
        }
        double avg = sum / static_cast<double>(stealths.size());
        double det_rate =
            static_cast<double>(detected) / static_cast<double>(stealths.size());

        if (avg > best_stealth) {
            best_stealth = avg;
            best_name = name;
        }

        if (!first) std::printf(",");
        first = false;
        std::printf(
            "{\"strategy\":\"%s\",\"runs\":%zu,\"samples_per_run\":%zu,"
            "\"avg_stealth\":%.6f,\"min_stealth\":%.6f,\"max_stealth\":%.6f,"
            "\"detection_rate\":%.6f}",
            name.c_str(), runs, samples, avg, mn, mx, det_rate);
        std::fflush(stdout);
    }
    std::printf("],\"best_strategy\":\"%s\",\"best_stealth\":%.6f}\n",
                best_name.c_str(), best_stealth < 0 ? 0.0 : best_stealth);
    return 0;
}
