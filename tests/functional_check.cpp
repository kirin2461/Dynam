// NCP C++ functional check — exercises the core library end-to-end.
// Compiled against libncp_core.a on the target server.
#include "ncp_crypto.hpp"
#include "ncp_e2e.hpp"
#include "ncp_doh.hpp"
#include "ncp_quic.hpp"
#include "ncp_ipfrag.hpp"
#include "ncp_hostlist.hpp"
#include "ncp_zapret_import.hpp"
#include "ncp_dpi.hpp"
#include "ncp_dpi_detector.hpp"
#include "ncp_blockcheck.hpp"
#include "ncp_autopilot.hpp"
#include "ncp_proxy.hpp"
#include "ncp_tls_parse.hpp"
#include "ncp_license.hpp"
#include "ncp_network.hpp"
#include "ncp_mimicry.hpp"

#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

static int g_pass = 0, g_fail = 0;
#define CHECK(name, cond) do { \
    if (cond) { ++g_pass; std::cout << "[PASS] " << name << "\n"; } \
    else { ++g_fail; std::cout << "[FAIL] " << name << "\n"; } \
} while (0)

using namespace ncp;

static void test_crypto() {
    std::cout << "\n== Crypto ==\n";
    Crypto c;

    // ChaCha20-Poly1305 roundtrip
    SecureMemory key = c.generate_random(32);
    const char* msg = "secret payload for functional check";
    SecureMemory plain(reinterpret_cast<const uint8_t*>(msg), strlen(msg));
    SecureMemory enc = c.encrypt_chacha20(plain, key);
    CHECK("chacha20 encrypt produces output", !enc.empty() && enc.size() > plain.size());
    SecureMemory dec = c.decrypt_chacha20(enc, key);
    CHECK("chacha20 roundtrip", dec.size() == plain.size() &&
          memcmp(dec.data(), plain.data(), plain.size()) == 0);

    // Tamper detection (decrypt throws on authentication failure)
    if (enc.size() > 20) {
        std::vector<uint8_t> bad(enc.data(), enc.data() + enc.size());
        bad[15] ^= 0xFF;
        SecureMemory badmem(bad.data(), bad.size());
        bool rejected = false;
        try {
            SecureMemory dec2 = c.decrypt_chacha20(badmem, key);
            rejected = dec2.empty() ||
                !(dec2.size() == plain.size() && memcmp(dec2.data(), plain.data(), plain.size()) == 0);
        } catch (const std::exception&) {
            rejected = true;
        }
        CHECK("chacha20 tamper rejected", rejected);
    }

    // SHA-256 known vector: sha256("abc")
    const char* abc = "abc";
    SecureMemory abc_mem(reinterpret_cast<const uint8_t*>(abc), 3);
    SecureMemory h = c.hash_sha256(abc_mem);
    CHECK("sha256 known vector", Crypto::bytes_to_hex(h) ==
          "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

    // Ed25519 sign/verify
    auto kp = c.generate_keypair();
    auto sig = c.sign_ed25519(plain, kp.secret_key);
    CHECK("ed25519 sign", sig.size() == 64);
    CHECK("ed25519 verify ok", c.verify_ed25519(plain, sig, kp.public_key));
    const char* other = "different message";
    SecureMemory other_mem(reinterpret_cast<const uint8_t*>(other), strlen(other));
    CHECK("ed25519 wrong msg rejected", !c.verify_ed25519(other_mem, sig, kp.public_key));

    // Random uniqueness
    auto r1 = c.generate_random(32), r2 = c.generate_random(32);
    CHECK("csprng uniqueness", memcmp(r1.data(), r2.data(), 32) != 0);
}

static void test_e2e() {
    std::cout << "\n== E2E (X25519 + KEM + keys) ==\n";
    E2ESession alice, bob;

    auto alice_keys = alice.generate_key_pair();
    auto bob_keys = bob.generate_key_pair();
    CHECK("e2e keygen", !alice_keys.public_key.empty() && !bob_keys.public_key.empty());

    // Full key exchange: request -> response -> complete
    auto req = alice.create_key_exchange_request(alice_keys);
    CHECK("e2e kex request", !req.empty());
    auto resp = bob.process_key_exchange_request(req, bob_keys);
    CHECK("e2e kex response", !resp.empty());
    CHECK("e2e kex complete", alice.complete_key_exchange(resp, alice_keys));

    // Shared secret equality (X25519)
    std::vector<uint8_t> bob_pub(bob_keys.public_key.data(),
                                 bob_keys.public_key.data() + bob_keys.public_key.size());
    std::vector<uint8_t> alice_pub(alice_keys.public_key.data(),
                                   alice_keys.public_key.data() + alice_keys.public_key.size());
    auto sec_a = alice.compute_shared_secret(alice_keys, bob_pub);
    auto sec_b = bob.compute_shared_secret(bob_keys, alice_pub);
    CHECK("e2e shared secret equal",
          sec_a.size() == sec_b.size() && sec_a.size() > 0 &&
          memcmp(sec_a.data(), sec_b.data(), sec_a.size()) == 0);

    // Key derivation
    auto dk = alice.derive_keys(sec_a, "functional-check", 32);
    CHECK("e2e derive_keys", dk.size() == 32);

    // Low-level encrypt/decrypt with derived key
    const char* payload = "e2e encrypted message";
    std::vector<uint8_t> pt(payload, payload + strlen(payload));
    auto em = alice.encrypt_message(pt, dk);
    auto dt = bob.decrypt_message(em, dk);
    CHECK("e2e encrypt/decrypt roundtrip",
          dt.size() == pt.size() && memcmp(dt.data(), pt.data(), pt.size()) == 0);

    // Post-quantum KEM (Kyber1024) — requires optional liboqs dependency
    try {
        auto kem_keys = alice.generate_key_pair();
        std::vector<uint8_t> ct;
        std::vector<uint8_t> kem_pub(kem_keys.public_key.data(),
                                     kem_keys.public_key.data() + kem_keys.public_key.size());
        auto ss1 = E2ESession::encapsulate(kem_pub, ct);
        auto ss2 = E2ESession::decapsulate(kem_keys, ct);
        CHECK("e2e KEM encapsulate/decapsulate",
              !ss1.empty() && ss1.size() == ss2.size() &&
              memcmp(ss1.data(), ss2.data(), ss1.size()) == 0);
    } catch (const std::exception& e) {
        std::cout << "[SKIP] e2e KEM (Kyber1024): " << e.what()
                  << " (optional ENABLE_LIBOQS build flag)\n";
    }
}

static void test_doh() {
    std::cout << "\n== DoH (live, bypasses DNS block) ==\n";
    DoHClient::Config cfg;
    cfg.provider = DoHClient::Provider::CLOUDFLARE_PRIMARY;
    DoHClient client(cfg);
    auto ok = [](const DoHClient::DNSResult& r) {
        return !r.addresses.empty() && r.error_message.empty();
    };
    auto res = client.resolve_ipv4("www.youtube.com");
    CHECK("doh resolve youtube.com (DNS-blocked directly)", ok(res));
    if (ok(res))
        std::cout << "       youtube.com -> " << res.addresses[0] << "\n";
    else
        std::cout << "       error: " << res.error_message << "\n";
    auto res2 = client.resolve_ipv4("example.com");
    CHECK("doh resolve example.com", ok(res2));
}

static void test_quic_ipfrag() {
    std::cout << "\n== QUIC / IP fragmentation ==\n";
    std::vector<uint8_t> fake = build_fake_quic_initial(1200);
    CHECK("fake quic initial built", fake.size() >= 1200);
    CHECK("fake quic initial recognized", is_quic_initial(fake.data(), fake.size()));
    const uint8_t garbage[4] = {0x16, 0x03, 0x01, 0x00};
    CHECK("non-quic rejected", !is_quic_initial(garbage, sizeof(garbage)));

    // IPv4 UDP packet -> fragment -> reassemble
    // Build minimal IPv4+UDP packet: 20B IP + 8B UDP + 100B payload
    std::vector<uint8_t> pkt(20 + 8 + 100, 0);
    pkt[0] = 0x45;                       // IPv4, IHL 5
    uint16_t total = static_cast<uint16_t>(pkt.size());
    pkt[2] = total >> 8; pkt[3] = total & 0xFF;
    pkt[6] = 0x40; pkt[7] = 0x00;        // DF set
    pkt[8] = 64; pkt[9] = 17;            // TTL, UDP
    for (int i = 0; i < 100; ++i) pkt[28 + i] = static_cast<uint8_t>(i);
    std::vector<uint8_t> f1, f2;
    CHECK("ipfrag split", build_ip_fragments(pkt.data(), pkt.size(), 40, f1, f2));
    CHECK("ipfrag sizes", f1.size() == 68 && f2.size() == 80);  // split at UDP-hdr(8)+40
    // Reassemble payload manually
    std::vector<uint8_t> reasm;
    reasm.insert(reasm.end(), f1.begin() + 20, f1.end());
    reasm.insert(reasm.end(), f2.begin() + 20, f2.end());
    CHECK("ipfrag reassembly identical",
          reasm.size() == 108 && memcmp(reasm.data(), pkt.data() + 20, 108) == 0);
}

static void test_hostlist() {
    std::cout << "\n== Hostlists ==\n";
    HostlistMatcher m;
    m.add("youtube.com");
    m.add("*.discord.gg");
    CHECK("hostlist exact", m.contains("youtube.com"));
    CHECK("hostlist subdomain suffix", m.contains("www.youtube.com"));
    CHECK("hostlist wildcard", m.contains("media.discord.gg"));
    CHECK("hostlist negative", !m.contains("google.com"));
    CHECK("hostlist no partial", !m.contains("notyoutube.com"));
    m.add("com");
    CHECK("bare TLD does not match everything", !m.contains("example.org"));
}

static void test_zapret_import() {
    std::cout << "\n== zapret import ==\n";
    auto r = DPI::parse_zapret_cmdline(
        "--filter-tcp=443 --dpi-desync=fake,multisplit --dpi-desync-split-pos=midsld "
        "--dpi-desync-fooling=badsum --dpi-desync-ttl=3 --new "
        "--filter-udp=443 --dpi-desync=fake --dpi-desync-fake-quic=0x16030100");
    CHECK("zapret parse ok", r.ok() && r.profile.chains.size() == 2);
    if (r.profile.chains.size() == 2) {
        CHECK("chain1 tcp/443", r.profile.chains[0].proto == DPI::ZProto::TCP);
        CHECK("chain1 midsld marker", !r.profile.chains[0].split_positions.empty());
        CHECK("chain2 udp", r.profile.chains[1].proto == DPI::ZProto::UDP);
    }
    auto j = DPI::zapret_profile_to_json(r);
    CHECK("zapret json", j.find("\"chains\"") != std::string::npos);
}

static void test_dpi_presets() {
    std::cout << "\n== DPI presets ==\n";
    const char* names[] = {"tspu", "beeline", "mts", "megafon", "tele2", "mobile", "auto"};
    int ok = 0;
    for (auto n : names) {
        DPI::DPIPreset p = DPI::preset_from_string(n);
        DPI::DPIConfig cfg;
        DPI::apply_preset(p, cfg);
        cfg.listen_port = 8881;             // caller-provided (see handle_dpi)
        cfg.target_host = "example.com";    // caller-provided
        if (cfg.is_valid()) ++ok;
        else std::cout << "       [dbg] invalid preset: " << n
                       << " err=" << static_cast<int>(cfg.validate()) << "\n";
    }
    CHECK("all 7 presets valid", ok == 7);
    // zapret profiles
    const char* zn[] = {"zapret_full", "zapret_general", "zapret_discord", "zapret_google", "zapret_quic", "zapret_tcp", "zapret_youtube", "zapret_rublock"};
    bool zok = false;
    for (auto n : zn) {
        auto zp = DPI::get_zapret_profile_by_name(n);
        if (!zp.chains.empty()) { zok = true; std::cout << "       [dbg] zapret profile found: " << n << "\n"; break; }
    }
    CHECK("zapret profile lookup (any builtin)", zok);
}

static void test_detector() {
    std::cout << "\n== DPI detector ==\n";
    DpiDetector det;
    det.on_reset_after_hello("youtube.com");
    det.on_connect_reset("youtube.com");
    det.on_timeout("instagram.com");
    det.on_timeout("instagram.com");
    det.on_success("google.com");
    CHECK("detector events counted", det.total_events() == 3);  // on_success adds no event
    CHECK("detector rst kind", det.events_of_kind(DpiDetector::EventKind::RST_INJECTION) >= 1);
    auto blocked = det.blocked_hosts();
    CHECK("detector blocked hosts", !blocked.empty());
}

static void test_blockcheck_statics() {
    std::cout << "\n== Blockcheck (statics, live probe) ==\n";
    auto hello = BlockChecker::build_client_hello("www.youtube.com");
    CHECK("client hello built", hello.size() > 100);
    auto info = parse_tls_client_hello(hello.data(), hello.size());
    CHECK("client hello parses back", info.valid && info.sni == "www.youtube.com");
    CHECK("client hello sni offsets", info.sni_value_offset > 0 && info.sni_value_len == 15);

    auto strategies = BlockChecker::default_strategies();
    CHECK("default strategies >= 10", strategies.size() >= 10);

    // Live direct probe of DNS-blocked domain should fail with dns error
    auto p = BlockChecker::probe_direct("www.youtube.com", 4000);
    CHECK("direct probe youtube fails (DNS blocked here)", !p.ok);
    if (!p.ok) std::cout << "       fail reason: " << p.fail_reason << "\n";
    // Live direct probe of reachable domain should succeed
    auto p2 = BlockChecker::probe_direct("example.com", 4000);
    CHECK("direct probe example.com ok", p2.ok);
}

static void test_license_network() {
    std::cout << "\n== License / Network ==\n";
    License lic;
    CHECK("hwid stable non-empty", lic.get_hwid().size() >= 32);
    CHECK("hwid deterministic", lic.get_hwid() == lic.get_hwid());

    Network net;
    auto ifaces = net.get_interfaces();
    bool any_up = false, names_ok = true;
    for (auto& i : ifaces) {
        if (i.is_up) any_up = true;
        if (i.name.empty()) names_ok = false;
    }
    CHECK("interfaces listed", !ifaces.empty());
    CHECK("interface names populated", names_ok);
    CHECK("at least one UP interface", any_up);
    auto st = net.get_stats();
    CHECK("network stats non-zero", st.bytes_received > 0 || st.bytes_sent > 0);
}

static void test_mimicry() {
    std::cout << "\n== Traffic mimicry ==\n";
    using MP = TrafficMimicry::MimicProfile;
    MP profiles[] = {MP::HTTP_GET, MP::HTTPS_APPLICATION, MP::DNS_QUERY, MP::QUIC_INITIAL,
                     MP::WEBSOCKET, MP::BITTORRENT, MP::SKYPE, MP::ZOOM};
    int ok = 0;
    for (auto p : profiles) {
        TrafficMimicry::MimicConfig cfg;
        cfg.profile = p;
        TrafficMimicry m(cfg);
        (void)m;
        ++ok;
    }
    CHECK("all 8 mimic profiles construct", ok == 8);
}

static void test_autopilot() {
    std::cout << "\n== AutoPilot (adaptive engine) ==\n";
    const std::string db = "/tmp/ncp_autopilot_test.json";
    std::remove(db.c_str());

    CHECK("normalize_host lowercase+dot",
          AutoPilot::normalize_host("WWW.YouTube.COM.") == "www.youtube.com");

    AutoPilot ap;
    AutoPilot::Config cfg;
    cfg.db_path = db;
    cfg.max_records = 4;
    ap.load(cfg);

    // Seed a record directly through learn-independent path: report_failure
    // on unknown host -> pending -> placeholder at threshold
    ap.report_failure("youtube.com", "rst");
    ap.report_failure("youtube.com", "rst");
    AutoPilotStrategy st;
    CHECK("lookup empty before threshold", !ap.lookup("youtube.com", &st));
    ap.report_failure("youtube.com", "rst");
    CHECK("placeholder record after threshold", ap.records().size() == 1);
    CHECK("placeholder not served by lookup", !ap.lookup("youtube.com", &st));
    CHECK("placeholder is degraded", ap.records()[0].degraded);

    // Unknown-host success is a no-op (keeps DB clean)
    ap.report_success("never-seen.example", 10.0);
    bool found_unseen = false;
    for (const auto& r : ap.records())
        if (r.host == "never-seen.example") found_unseen = true;
    CHECK("unknown-host success no-op", !found_unseen);

    // Simulate a learned record: craft via JSON roundtrip
    ap.reset("");
    {
        std::ofstream f(db, std::ios::trunc);
        f << "{\"version\":1,\"enabled\":true,\"records\":{\"youtube.com\":{"
             "\"strategy\":\"multisplit-1-midsld\","
             "\"positions\":[{\"type\":0,\"offset\":1},{\"type\":6,\"offset\":0}],"
             "\"host_case\":false,\"successes\":3,\"failures\":0,"
             "\"consec_failures\":0,\"ewma_latency_ms\":120.5,"
             "\"last_learned\":1723300000,\"last_outcome\":1723300100,"
             "\"cooldown\":120.0,\"degraded\":false}}}\n";
    }
    AutoPilot ap2;
    AutoPilot::Config cfg2;
    cfg2.db_path = db;
    ap2.load(cfg2);
    CHECK("db load: enabled persisted", ap2.enabled());
    CHECK("db load: record parsed", ap2.records().size() == 1);
    CHECK("lookup exact", ap2.lookup("youtube.com", &st) &&
          st.name == "multisplit-1-midsld" && st.positions.size() == 2);
    CHECK("lookup longest-suffix (www.youtube.com)",
          ap2.lookup("www.youtube.com", &st));
    CHECK("lookup position types preserved",
          st.positions[0].type == DPI::ZSplitPosType::NUMERIC &&
          st.positions[1].type == DPI::ZSplitPosType::MIDSLD);
    CHECK("lookup miss for other host", !ap2.lookup("google.com", &st));

    // Degradation: 3 consecutive failures -> degraded -> lookup skips
    ap2.report_failure("youtube.com", "rst");
    ap2.report_failure("youtube.com", "rst");
    CHECK("not degraded before threshold", ap2.lookup("youtube.com", &st));
    ap2.report_failure("youtube.com", "timeout");
    auto recs = ap2.records();
    bool degr = !recs.empty() && recs[0].degraded && recs[0].consec_failures == 3;
    CHECK("degraded at threshold", degr);
    CHECK("lookup skips degraded", !ap2.lookup("youtube.com", &st));

    // Degradation persisted to disk
    AutoPilot ap3;
    AutoPilot::Config cfg3;
    cfg3.db_path = db;
    ap3.load(cfg3);
    auto recs3 = ap3.records();
    CHECK("degradation persisted", !recs3.empty() && recs3[0].degraded);

    // LRU eviction
    AutoPilot ap4;
    AutoPilot::Config cfg4;
    cfg4.db_path = "/tmp/ncp_autopilot_lru.json";
    cfg4.max_records = 3;
    cfg4.degrade_threshold = 1;  // immediate placeholder
    ap4.load(cfg4);
    std::remove("/tmp/ncp_autopilot_lru.json");
    ap4.report_failure("a.example", "rst");
    ap4.report_failure("b.example", "rst");
    ap4.report_failure("c.example", "rst");
    ap4.report_failure("d.example", "rst");
    CHECK("LRU cap enforced", ap4.records().size() == 3);

    CHECK("to_json contains records", ap2.to_json().find("\"records\"") != std::string::npos);

    // LIVE: learn a strategy for a real domain through temp proxies.
    // On this filtered server youtube.com needs desync; on open networks
    // "direct" wins — either way learn() must succeed and store a record.
    AutoPilot ap5;
    AutoPilot::Config cfg5;
    cfg5.db_path = "/tmp/ncp_autopilot_live.json";
    cfg5.probe_timeout_ms = 6000;
    cfg5.use_doh = true;  // this server has poisoned DNS; harmless elsewhere
    ap5.load(cfg5);
    std::string learned;
    bool lok = ap5.learn("www.youtube.com", &learned);
    CHECK("live learn youtube.com", lok);
    if (lok) {
        std::cout << "       learned strategy: " << learned << "\n";
        CHECK("live learned record servable", ap5.lookup("www.youtube.com", &st));
    }
}

int main() {
    std::cout << "=== NCP C++ FUNCTIONAL CHECK ===\n";
    test_crypto();
    test_e2e();
    test_doh();
    test_quic_ipfrag();
    test_hostlist();
    test_zapret_import();
    test_dpi_presets();
    test_detector();
    test_blockcheck_statics();
    test_license_network();
    test_mimicry();
    test_autopilot();
    std::cout << "\n=== RESULT: " << g_pass << " passed, " << g_fail << " failed ===\n";
    return g_fail == 0 ? 0 : 1;
}
