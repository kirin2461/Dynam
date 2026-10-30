// ══════════════════════════════════════════════════════════════════════════════
// tests/test_transport_config.cpp
//
// G2.2 executable evidence for docs/MIMICRY_CONFIG_MIGRATION.md: the
// versioned transport-config loader/validator/binder
// (src/core/include/ncp_transport_config.hpp) bound to REAL session creation
// (HopSchedule + NcpMimicrySession::Config consumed by the adapter and
// NcpConnectionDirector session templates).
//
// Evidence covered:
//   * schema-1 / empty configurations parse to the documented legacy
//     defaults (§2);
//   * legacy configurations bind a HopSchedule BYTE-IDENTICAL to one
//     constructed directly from the same parameters (§1 principle 1:
//     unchanged wire format / hop schedule);
//   * legacy-bound session templates create NcpMimicrySession adapters that
//     keep PathHopPolicy::LegacyPortHop and interoperate (real E2E
//     handshake + data) with adapters built from the raw legacy Config;
//   * fixed-path QUIC/TURN configurations bind NO HopSchedule, set
//     PathHopPolicy::Disabled, never reserve PH overhead, and never reuse
//     the PH hop secret (§3.2/§3.3);
//   * invalid legacy/new combinations and unknown fields fail at parse /
//     bind time — before any socket creation (§1 principle 4, §8 gate);
//   * misconfigured session templates are rejected by the adapter
//     constructor (fail before socket creation).
// ══════════════════════════════════════════════════════════════════════════════
#include <gtest/gtest.h>

#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

#include "ncp_transport_config.hpp"

namespace ncp {
namespace {

const std::vector<uint8_t> kHopSecret{'h', 'o', 'p', '-', 's', 'e', 'c', 'r',
                                      'e', 't'};

/// The doc §2 example, verbatim (inline comments included).
const char* kDocExample = R"(
schema_version: 2
wire_transport: legacy-porthop  # legacy-porthop | quic | turn
legacy_porthop:
  base_port: 45000
  range: 8
  hop_interval_ms: 60000
quic:
  hop_policy: disabled          # initial and only accepted QUIC value
  alpn: ncp/1
turn:
  transport: udp                # initial and only accepted TURN value
  data_mode: channel-data       # established application flow
  credential_ref: turn/production/client-a
)";

// ── Parse / defaults ────────────────────────────────────────────────────────

TEST(TransportConfig, EmptyTextIsSchema1LegacyDefaults) {
    std::string err;
    auto cfg = parse_transport_config("", err);
    ASSERT_TRUE(cfg) << err;
    EXPECT_EQ(cfg->schema_version, TransportConfig::kSchemaLegacy);
    EXPECT_EQ(cfg->wire_transport, WireTransport::LegacyPortHop);
    EXPECT_EQ(cfg->legacy_porthop.base_port, 45000u);
    EXPECT_EQ(cfg->legacy_porthop.range, 8u);
    EXPECT_EQ(cfg->legacy_porthop.hop_interval_ms, 60000u);
    EXPECT_FALSE(cfg->legacy_section_present);
}

TEST(TransportConfig, CommentsAndBlankLinesOnlyIsLegacyDefaults) {
    std::string err;
    auto cfg = parse_transport_config("# nothing here\n\n   # more\n", err);
    ASSERT_TRUE(cfg) << err;
    EXPECT_EQ(cfg->schema_version, 1u);
    EXPECT_EQ(cfg->wire_transport, WireTransport::LegacyPortHop);
}

// The doc example carries quic/turn sections alongside a legacy selection,
// which §3.1 rejects — the example illustrates the FIELD SET, not a valid
// combined config. The parts must parse/reject exactly as specified.
TEST(TransportConfig, DocExampleLegacyPartParses) {
    std::string err;
    auto cfg = parse_transport_config(
        "schema_version: 2\n"
        "wire_transport: legacy-porthop\n"
        "legacy_porthop:\n"
        "  base_port: 45000\n"
        "  range: 8\n"
        "  hop_interval_ms: 60000\n",
        err);
    ASSERT_TRUE(cfg) << err;
    EXPECT_EQ(cfg->schema_version, 2u);
    EXPECT_EQ(cfg->wire_transport, WireTransport::LegacyPortHop);
    EXPECT_TRUE(cfg->legacy_section_present);
    EXPECT_EQ(cfg->legacy_porthop.base_port, 45000u);
    EXPECT_EQ(cfg->legacy_porthop.range, 8u);
    EXPECT_EQ(cfg->legacy_porthop.hop_interval_ms, 60000u);
}

TEST(TransportConfig, DocExampleCombinationRejectedPerSection3) {
    // §3.1: QUIC- and TURN-only fields are rejected under legacy-porthop.
    std::string err;
    EXPECT_FALSE(parse_transport_config(kDocExample, err));
    EXPECT_FALSE(err.empty());
}

// ── Legacy binding: byte-identical hop schedule ─────────────────────────────

TEST(TransportConfig, LegacyBindsByteIdenticalHopSchedule) {
    std::string err;
    auto cfg = parse_transport_config(
        "schema_version: 2\n"
        "wire_transport: legacy-porthop\n"
        "legacy_porthop:\n"
        "  base_port: 45000\n"
        "  range: 8\n"
        "  hop_interval_ms: 60000\n",
        err);
    ASSERT_TRUE(cfg) << err;

    auto bound = bind_transport_config(*cfg, kHopSecret, err);
    ASSERT_TRUE(bound) << err;
    ASSERT_TRUE(bound->hop_schedule.has_value());
    EXPECT_EQ(bound->hop_policy, PathHopPolicy::LegacyPortHop);
    EXPECT_EQ(bound->outer_transport, OuterTransportKind::Direct);

    // The schedule a legacy deployment builds directly from the same
    // parameters (the pre-migration creation path, cf. CLI handle_porthop).
    HopSchedule direct(kHopSecret, 45000, 8, 60);
    EXPECT_EQ(bound->hop_schedule->base_port(), direct.base_port());
    EXPECT_EQ(bound->hop_schedule->port_range(), direct.port_range());
    EXPECT_EQ(bound->hop_schedule->interval_sec(), direct.interval_sec());
    for (uint32_t epoch = 0; epoch < 64; ++epoch)
        EXPECT_EQ(bound->hop_schedule->port_for_epoch(epoch),
                  direct.port_for_epoch(epoch))
            << "epoch " << epoch;
}

TEST(TransportConfig, Schema1DefaultsBindByteIdenticalHopSchedule) {
    std::string err;
    auto cfg = parse_transport_config("", err);
    ASSERT_TRUE(cfg) << err;
    auto bound = bind_transport_config(*cfg, kHopSecret, err);
    ASSERT_TRUE(bound) << err;
    ASSERT_TRUE(bound->hop_schedule.has_value());
    HopSchedule direct(kHopSecret, 45000, 8, 60);  // §2 legacy defaults
    for (uint32_t epoch = 0; epoch < 16; ++epoch)
        EXPECT_EQ(bound->hop_schedule->port_for_epoch(epoch),
                  direct.port_for_epoch(epoch));
}

// ── Real session creation from bound configurations ─────────────────────────

/// Minimal hermetic session pair (same pattern as
/// tests/test_datagram_path_budget.cpp): real E2E handshake over in-memory
/// datagrams, no sockets.
struct SessionPair {
    std::unique_ptr<NcpMimicrySession> cli;
    std::unique_ptr<NcpMimicrySession> srv;
    uint64_t now = 1000;

    SessionPair(const NcpMimicrySession::Config& client_cfg,
                const NcpMimicrySession::Config& server_cfg) {
        cli = std::make_unique<NcpMimicrySession>(client_cfg);
        srv = std::make_unique<NcpMimicrySession>(server_cfg);
        auto hs = cli->start_handshake();
        if (!hs) throw std::runtime_error("handshake did not start");
        (void)srv->on_datagram(hs->bytes, now);
        pump();
        if (!cli->is_established() || !srv->is_established())
            throw std::runtime_error("handshake did not complete");
    }

    void pump() {
        for (int i = 0; i < 32; ++i) {
            bool progress = false;
            while (auto o = srv->next_outbound()) {
                (void)cli->on_datagram(o->bytes, now);
                progress = true;
            }
            while (auto o = cli->next_outbound()) {
                (void)srv->on_datagram(o->bytes, now);
                progress = true;
            }
            if (!progress) return;
        }
        ADD_FAILURE() << "session pump did not quiesce";
    }
};

NcpMimicrySession::Config base_session_config(NcpMimicrySession::Role role) {
    NcpMimicrySession::Config c;
    c.role = role;
    c.e2e_config.enable_padding = false;
    c.mimic_config.wire_version = 3;
    c.mimic_config.enable_size_mimicry = false;
    c.path_mtu_bytes = 1500;
    c.porthop_overhead_bytes = 20;
    c.max_application_payload = 4096;  // don't clamp the budget comparison
    return c;
}

TEST(TransportConfig, LegacyBoundSessionsKeepLegacyPortHopPathAndInterop) {
    std::string err;
    auto cfg = parse_transport_config("", err);  // schema 1: unversioned
    ASSERT_TRUE(cfg) << err;
    auto bound = bind_transport_config(*cfg, kHopSecret, err);
    ASSERT_TRUE(bound) << err;

    // Session template patched ONLY through the binder.
    auto cc = base_session_config(NcpMimicrySession::Role::Client);
    auto sc = base_session_config(NcpMimicrySession::Role::Server);
    apply_transport_config(*bound, cc);
    apply_transport_config(*bound, sc);
    EXPECT_EQ(cc.hop_policy, PathHopPolicy::LegacyPortHop);
    EXPECT_EQ(cc.outer_transport, OuterTransportKind::Direct);
    EXPECT_GE(cc.porthop_overhead_bytes, 20u);

    SessionPair bound_pair(cc, sc);
    EXPECT_EQ(bound_pair.cli->path_state().hop_policy,
              PathHopPolicy::LegacyPortHop);
    EXPECT_EQ(bound_pair.srv->path_state().hop_policy,
              PathHopPolicy::LegacyPortHop);

    // Interop with sessions created from the RAW legacy Config (no
    // transport-config involvement): the pre-migration creation path.
    // Bound client <-> raw server and raw client <-> bound server.
    const std::vector<uint8_t> app{'m', 'i', 'g', 'r', 'a', 't', 'e'};
    for (int dir = 0; dir < 2; ++dir) {
        auto mcli = base_session_config(NcpMimicrySession::Role::Client);
        auto msrv = base_session_config(NcpMimicrySession::Role::Server);
        apply_transport_config(*bound, dir == 0 ? mcli : msrv);
        SessionPair mixed(mcli, msrv);
        ASSERT_TRUE(mixed.cli->is_established());
        ASSERT_TRUE(mixed.srv->is_established());
        auto out = mixed.cli->send_application(app, mixed.now);
        ASSERT_TRUE(out);
        auto r = mixed.srv->on_datagram(out->bytes, mixed.now);
        EXPECT_EQ(r.kind, NcpMimicrySession::IngressKind::Data);
        ASSERT_TRUE(r.app_payload);
        EXPECT_EQ(*r.app_payload, app);
        auto back = mixed.srv->send_application(app, mixed.now);
        ASSERT_TRUE(back);
        auto rr = mixed.cli->on_datagram(back->bytes, mixed.now);
        EXPECT_EQ(rr.kind, NcpMimicrySession::IngressKind::Data);
    }

    // Same path budget as the pre-migration default (20-byte PH reserve).
    SessionPair raw(base_session_config(NcpMimicrySession::Role::Client),
                    base_session_config(NcpMimicrySession::Role::Server));
    EXPECT_EQ(bound_pair.cli->max_application_datagram(
                  bound_pair.cli->path_state()),
              raw.cli->max_application_datagram(raw.cli->path_state()));
}

TEST(TransportConfig, LoadingSchema2DoesNotRewriteLiveLegacySession) {
    // A running legacy session and a newly loaded fixed-path configuration
    // coexist. Binding applies only to a NEW session template; it cannot
    // mutate the already-created adapter or its established E2E state.
    SessionPair live(base_session_config(NcpMimicrySession::Role::Client),
                     base_session_config(NcpMimicrySession::Role::Server));
    const auto before = live.cli->path_state();
    const auto before_budget = live.cli->max_application_datagram(before);

    std::string err;
    auto quic = parse_transport_config(
        "schema_version: 2\nwire_transport: quic\n"
        "quic:\n  hop_policy: disabled\n  remote: 127.0.0.1:4433\n", err);
    ASSERT_TRUE(quic) << err;
    auto bound = bind_transport_config(*quic, {}, err);
    ASSERT_TRUE(bound) << err;
    auto new_session_template =
        base_session_config(NcpMimicrySession::Role::Client);
    apply_transport_config(*bound, new_session_template);
    ASSERT_EQ(new_session_template.hop_policy, PathHopPolicy::Disabled);

    const auto after = live.cli->path_state();
    EXPECT_EQ(after.ip_version, before.ip_version);
    EXPECT_EQ(after.outer_transport, before.outer_transport);
    EXPECT_EQ(after.hop_policy, before.hop_policy);
    EXPECT_EQ(after.effective_mtu, before.effective_mtu);
    EXPECT_EQ(after.porthop_padding_headroom, before.porthop_padding_headroom);
    EXPECT_EQ(live.cli->max_application_datagram(after), before_budget);

    // The established legacy E2E session still exchanges protected data after
    // the new configuration is loaded and bound for future sessions.
    const std::vector<uint8_t> app{'l', 'i', 'v', 'e', '-', 'l', 'e', 'g', 'a', 'c', 'y'};
    auto out = live.cli->send_application(app, live.now);
    ASSERT_TRUE(out);
    auto received = live.srv->on_datagram(out->bytes, live.now);
    EXPECT_EQ(received.kind, NcpMimicrySession::IngressKind::Data);
    ASSERT_TRUE(received.app_payload);
    EXPECT_EQ(*received.app_payload, app);
}

TEST(TransportConfig, QuicFixedPathBindsNoPortHopAndNoMigration) {
    std::string err;
    auto cfg = parse_transport_config(
        "schema_version: 2\n"
        "wire_transport: quic\n"
        "quic:\n"
        "  hop_policy: disabled\n"
        "  alpn: ncp/1\n"
        "  remote: 203.0.113.7:4433\n",
        err);
    ASSERT_TRUE(cfg) << err;

    auto bound = bind_transport_config(*cfg, {}, err);
    ASSERT_TRUE(bound) << err;
    // Fixed path: NO hop schedule is ever created for QUIC (no accidental
    // PortHop), and the session path policy is Disabled.
    EXPECT_FALSE(bound->hop_schedule.has_value());
    EXPECT_EQ(bound->hop_policy, PathHopPolicy::Disabled);
    EXPECT_EQ(bound->outer_transport, OuterTransportKind::Direct);

    auto cc = base_session_config(NcpMimicrySession::Role::Client);
    auto sc = base_session_config(NcpMimicrySession::Role::Server);
    apply_transport_config(*bound, cc);
    apply_transport_config(*bound, sc);
    EXPECT_EQ(cc.porthop_overhead_bytes, 0u);
    EXPECT_EQ(cc.porthop_padding_headroom_bytes, 0u);

    SessionPair pair(cc, sc);  // real handshake on the fixed path
    EXPECT_EQ(pair.cli->path_state().hop_policy, PathHopPolicy::Disabled);
    EXPECT_EQ(pair.srv->path_state().hop_policy, PathHopPolicy::Disabled);
    EXPECT_EQ(pair.cli->path_state().porthop_padding_headroom, 0u);
    // No PortHop reservation: the fixed path admits strictly larger
    // application datagrams than the legacy path at the same MTU.
    SessionPair legacy(base_session_config(NcpMimicrySession::Role::Client),
                       base_session_config(NcpMimicrySession::Role::Server));
    EXPECT_GT(pair.cli->max_application_datagram(pair.cli->path_state()),
              legacy.cli->max_application_datagram(legacy.cli->path_state()));
    // Data still flows on the fixed path.
    const std::vector<uint8_t> app{'q', 'u', 'i', 'c'};
    auto out = pair.cli->send_application(app, pair.now);
    ASSERT_TRUE(out);
    auto r = pair.srv->on_datagram(out->bytes, pair.now);
    EXPECT_EQ(r.kind, NcpMimicrySession::IngressKind::Data);
    ASSERT_TRUE(r.app_payload);
    EXPECT_EQ(*r.app_payload, app);
}

TEST(TransportConfig, TurnFixedPathBindsChannelDataNoPortHop) {
    std::string err;
    auto cfg = parse_transport_config(
        "schema_version: 2\n"
        "wire_transport: turn\n"
        "turn:\n"
        "  transport: udp\n"
        "  data_mode: channel-data\n"
        "  credential_ref: turn/production/client-a\n",
        err);
    ASSERT_TRUE(cfg) << err;

    auto bound = bind_transport_config(*cfg, {}, err);
    ASSERT_TRUE(bound) << err;
    EXPECT_FALSE(bound->hop_schedule.has_value());
    EXPECT_EQ(bound->hop_policy, PathHopPolicy::Disabled);
    EXPECT_EQ(bound->outer_transport, OuterTransportKind::TurnChannelData);

    auto cc = base_session_config(NcpMimicrySession::Role::Client);
    apply_transport_config(*bound, cc);
    auto sc = base_session_config(NcpMimicrySession::Role::Server);
    apply_transport_config(*bound, sc);
    SessionPair pair(cc, sc);
    EXPECT_EQ(pair.cli->path_state().outer_transport,
              OuterTransportKind::TurnChannelData);
    EXPECT_EQ(pair.cli->path_state().hop_policy, PathHopPolicy::Disabled);
}

TEST(TransportConfig, FixedPathRejectsPortHopSecretReuse) {
    // §3.2: the PH hop secret is never reused as a QUIC/TLS credential.
    std::string err;
    TransportConfig cfg;  // programmatic schema-2 quic
    cfg.schema_version = TransportConfig::kSchemaTransport;
    cfg.wire_transport = WireTransport::Quic;
    cfg.quic.remote = "198.51.100.1:443";
    auto bound = bind_transport_config(cfg, kHopSecret, err);
    EXPECT_FALSE(bound);
    EXPECT_NE(err.find("secret"), std::string::npos);

    // And legacy REQUIRES the secret (no silent empty-secret schedule).
    cfg = TransportConfig{};
    EXPECT_FALSE(bind_transport_config(cfg, {}, err));
}

// ── Hard validation errors (§1 principle 4, §8: fail before sockets) ────────

TEST(TransportConfig, UnknownAndMisplacedFieldsAreHardErrors) {
    std::string err;
    EXPECT_FALSE(parse_transport_config("schema_version: 2\nbogus_key: 1\n", err));
    EXPECT_FALSE(parse_transport_config(
        "schema_version: 2\nlegacy_porthop:\n  bogus: 1\n", err));
    EXPECT_FALSE(parse_transport_config(
        "schema_version: 2\nlegacy_porthop:\n  base_port: 45000\n"
        "  base_port: 45001\n",
        err));  // duplicate key
    EXPECT_FALSE(parse_transport_config(
        "schema_version: 2\n  base_port: 45000\n", err));  // no section
    EXPECT_FALSE(parse_transport_config("schema_version: 3\n", err));
    EXPECT_FALSE(parse_transport_config(
        "wire_transport: quic\nquic:\n  remote: h:1\n", err))
        << "transport fields without explicit schema_version: 2 must fail";
}

TEST(TransportConfig, InvalidCombinationsFailBeforeSessionCreation) {
    std::string err;
    // QUIC with outer PortHop scheduling requested (§3.2 rejection).
    EXPECT_FALSE(parse_transport_config(
        "schema_version: 2\nwire_transport: quic\n"
        "legacy_porthop:\n  range: 8\n"
        "quic:\n  remote: h:1\n",
        err));
    // QUIC hop_policy other than disabled.
    EXPECT_FALSE(parse_transport_config(
        "schema_version: 2\nwire_transport: quic\n"
        "quic:\n  hop_policy: scheduled\n  remote: h:1\n",
        err));
    // QUIC without an explicit remote path.
    EXPECT_FALSE(parse_transport_config(
        "schema_version: 2\nwire_transport: quic\nquic:\n  alpn: ncp/1\n",
        err));
    // TURN over TCP (§3.3 rejection).
    EXPECT_FALSE(parse_transport_config(
        "schema_version: 2\nwire_transport: turn\n"
        "turn:\n  transport: tcp\n  credential_ref: a/b/c\n",
        err));
    // TURN without independent credentials reference.
    EXPECT_FALSE(parse_transport_config(
        "schema_version: 2\nwire_transport: turn\nturn:\n  transport: udp\n",
        err));
    // Legacy port range overflowing the UDP port space.
    EXPECT_FALSE(parse_transport_config(
        "schema_version: 2\nlegacy_porthop:\n  base_port: 65535\n  range: 2\n",
        err));
    // Sub-second hop interval cannot map to the second-granular schedule —
    // hard error, never silent truncation.
    EXPECT_FALSE(parse_transport_config(
        "schema_version: 2\nlegacy_porthop:\n  hop_interval_ms: 1500\n", err));
    // range: 0 must not silently become 1 (HopSchedule maps 0->1; the
    // config layer refuses it instead).
    EXPECT_FALSE(parse_transport_config(
        "schema_version: 2\nlegacy_porthop:\n  range: 0\n", err));
}

// ── Adapter construction guards for the new template fields ─────────────────

TEST(TransportConfig, SessionTemplateRejectsInconsistentFixedPath) {
    NcpMimicrySession::Config c;
    c.hop_policy = PathHopPolicy::Disabled;
    c.porthop_overhead_bytes = 0;
    c.porthop_padding_headroom_bytes = 1;  // padding without PortHop
    EXPECT_THROW(NcpMimicrySession{c}, std::invalid_argument);

    NcpMimicrySession::Config b;
    b.outer_transport = OuterTransportKind::TurnSendData;  // bootstrap-only
    EXPECT_THROW(NcpMimicrySession{b}, std::invalid_argument);

    // Defaults remain legacy and constructible (unchanged behavior).
    NcpMimicrySession::Config legacy;
    EXPECT_NO_THROW(NcpMimicrySession{legacy});
    NcpMimicrySession s{legacy};
    EXPECT_EQ(s.path_state().hop_policy, PathHopPolicy::LegacyPortHop);
    EXPECT_EQ(s.path_state().outer_transport, OuterTransportKind::Direct);
}

} // namespace
} // namespace ncp
