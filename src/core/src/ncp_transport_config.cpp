/**
 * @file ncp_transport_config.cpp
 * @brief Loader/validator/binder for the versioned wire-transport
 *        configuration (see ncp_transport_config.hpp and
 *        docs/MIMICRY_CONFIG_MIGRATION.md).
 *
 * The parser intentionally accepts ONLY the §2 subset: strict, small and
 * fail-closed. It is not a general YAML parser and must not grow into one.
 */

#include "ncp_transport_config.hpp"

#include <fstream>
#include <sstream>

namespace ncp {

const char* to_string(WireTransport t) noexcept {
    switch (t) {
        case WireTransport::LegacyPortHop: return "legacy-porthop";
        case WireTransport::Quic: return "quic";
        case WireTransport::Turn: return "turn";
    }
    return "unknown";
}

namespace {

struct Parser {
    TransportConfig cfg;
    std::string error;
    bool schema_version_seen = false;
    bool wire_transport_seen = false;
    // Duplicate-key tracking (sections tracked via cfg.*_section_present).
    bool seen_base_port = false, seen_range = false, seen_interval = false;
    bool seen_hop_policy = false, seen_alpn = false, seen_remote = false;
    bool seen_turn_transport = false, seen_data_mode = false,
         seen_credential_ref = false;

    bool fail(size_t line, const std::string& msg) {
        if (error.empty())
            error = "line " + std::to_string(line) + ": " + msg;
        return false;
    }

    static bool parse_u32(const std::string& s, uint32_t max, uint32_t& out) {
        if (s.empty() || s.size() > 10) return false;
        uint64_t v = 0;
        for (char c : s) {
            if (c < '0' || c > '9') return false;
            v = v * 10 + static_cast<uint64_t>(c - '0');
            if (v > max) return false;
        }
        out = static_cast<uint32_t>(v);
        return true;
    }

    bool set_once(bool& seen, size_t line, const char* key) {
        if (seen) return fail(line, std::string("duplicate key '") + key + "'");
        seen = true;
        return true;
    }

    bool top_level(size_t line, const std::string& key,
                   const std::string& value, bool& section_open) {
        if (key == "schema_version") {
            if (schema_version_seen) return fail(line, "duplicate 'schema_version'");
            schema_version_seen = true;
            uint32_t v = 0;
            if (!parse_u32(value, 1000000, v))
                return fail(line, "bad schema_version '" + value + "'");
            cfg.schema_version = v;
        } else if (key == "wire_transport") {
            if (wire_transport_seen) return fail(line, "duplicate 'wire_transport'");
            wire_transport_seen = true;
            if (value == "legacy-porthop")
                cfg.wire_transport = WireTransport::LegacyPortHop;
            else if (value == "quic")
                cfg.wire_transport = WireTransport::Quic;
            else if (value == "turn")
                cfg.wire_transport = WireTransport::Turn;
            else
                return fail(line, "unknown wire_transport '" + value + "'");
        } else if (key == "legacy_porthop" || key == "quic" || key == "turn") {
            if (!value.empty())
                return fail(line, "section '" + key + "' takes no inline value");
            bool& present = key == "legacy_porthop" ? cfg.legacy_section_present
                          : key == "quic"           ? cfg.quic_section_present
                                                    : cfg.turn_section_present;
            if (present) return fail(line, "duplicate section '" + key + "'");
            present = true;
            section_open = true;
            return true;
        } else {
            return fail(line, "unknown key '" + key + "'");
        }
        section_open = false;
        return true;
    }

    bool section_field(size_t line, const std::string& section,
                       const std::string& key, const std::string& value) {
        if (section == "legacy_porthop") {
            uint32_t v = 0;
            if (key == "base_port") {
                if (!set_once(seen_base_port, line, key.c_str())) return false;
                if (!parse_u32(value, 65535, v) || v == 0)
                    return fail(line, "bad base_port '" + value + "'");
                cfg.legacy_porthop.base_port = static_cast<uint16_t>(v);
            } else if (key == "range") {
                if (!set_once(seen_range, line, key.c_str())) return false;
                if (!parse_u32(value, 65535, v) || v == 0)
                    return fail(line, "bad range '" + value + "'");
                cfg.legacy_porthop.range = static_cast<uint16_t>(v);
            } else if (key == "hop_interval_ms") {
                if (!set_once(seen_interval, line, key.c_str())) return false;
                if (!parse_u32(value, 86400000, v) || v == 0)
                    return fail(line, "bad hop_interval_ms '" + value + "'");
                cfg.legacy_porthop.hop_interval_ms = v;
            } else {
                return fail(line, "unknown legacy_porthop key '" + key + "'");
            }
            return true;
        }
        if (section == "quic") {
            if (key == "hop_policy") {
                if (!set_once(seen_hop_policy, line, key.c_str())) return false;
                cfg.quic.hop_policy = value;
            } else if (key == "alpn") {
                if (!set_once(seen_alpn, line, key.c_str())) return false;
                cfg.quic.alpn = value;
            } else if (key == "remote") {
                if (!set_once(seen_remote, line, key.c_str())) return false;
                cfg.quic.remote = value;
            } else {
                return fail(line, "unknown quic key '" + key + "'");
            }
            return true;
        }
        if (section == "turn") {
            if (key == "transport") {
                if (!set_once(seen_turn_transport, line, key.c_str())) return false;
                cfg.turn.transport = value;
            } else if (key == "data_mode") {
                if (!set_once(seen_data_mode, line, key.c_str())) return false;
                cfg.turn.data_mode = value;
            } else if (key == "credential_ref") {
                if (!set_once(seen_credential_ref, line, key.c_str())) return false;
                cfg.turn.credential_ref = value;
            } else {
                return fail(line, "unknown turn key '" + key + "'");
            }
            return true;
        }
        return fail(line, "internal parser state error");
    }

    bool run(const std::string& text) {
        // Which section is currently open (empty = none).
        std::string section;
        std::istringstream in(text);
        std::string raw;
        size_t line_no = 0;
        while (std::getline(in, raw)) {
            ++line_no;
            if (raw.size() > 512)
                return fail(line_no, "line too long");
            // Strip comments (full-line and trailing, per the §2 example).
            const size_t hash = raw.find('#');
            std::string line = raw.substr(0, hash);
            // Trim right.
            const size_t last = line.find_last_not_of(" \t\r");
            if (last == std::string::npos) continue;  // blank
            line.erase(last + 1);
            const bool indented = line[0] == ' ' || line[0] == '\t';
            if (line.find('\t') != std::string::npos)
                return fail(line_no, "tabs are not accepted; use spaces");
            // Trim left.
            const size_t first = line.find_first_not_of(' ');
            line.erase(0, first);
            const size_t colon = line.find(':');
            if (colon == std::string::npos)
                return fail(line_no, "expected 'key: value'");
            std::string key = line.substr(0, colon);
            std::string value = line.substr(colon + 1);
            const size_t vf = value.find_first_not_of(' ');
            value = vf == std::string::npos ? "" : value.substr(vf);
            if (key.empty())
                return fail(line_no, "empty key");
            if (indented) {
                if (section.empty())
                    return fail(line_no, "indented field outside any section");
                if (!section_field(line_no, section, key, value)) return false;
            } else {
                bool opened = false;
                if (!top_level(line_no, key, value, opened)) return false;
                section = opened ? key : "";
            }
        }
        // §2: the transport extension is introduced as schema_version 2; any
        // transport field requires it explicitly.
        if ((wire_transport_seen || cfg.legacy_section_present ||
             cfg.quic_section_present || cfg.turn_section_present) &&
            (!schema_version_seen || cfg.schema_version != TransportConfig::kSchemaTransport))
            return fail(0, "transport fields require an explicit 'schema_version: 2'");
        if (schema_version_seen &&
            cfg.schema_version != TransportConfig::kSchemaLegacy &&
            cfg.schema_version != TransportConfig::kSchemaTransport)
            return fail(0, "unsupported schema_version " +
                               std::to_string(cfg.schema_version));
        return true;
    }
};

} // namespace

std::optional<TransportConfig> parse_transport_config(const std::string& text,
                                                      std::string& error) {
    Parser p;
    if (!p.run(text)) {
        error = p.error;
        return std::nullopt;
    }
    if (!validate_transport_config(p.cfg, error)) return std::nullopt;
    return p.cfg;
}

std::optional<TransportConfig> load_transport_config_file(
    const std::string& path, std::string& error) {
    std::ifstream f(path, std::ios::binary);
    if (!f.is_open()) {
        error = "cannot open '" + path + "'";
        return std::nullopt;
    }
    std::ostringstream ss;
    ss << f.rdbuf();
    return parse_transport_config(ss.str(), error);
}

bool validate_transport_config(const TransportConfig& cfg, std::string& error) {
    auto fail = [&error](const std::string& msg) {
        error = msg;
        return false;
    };
    if (cfg.schema_version != TransportConfig::kSchemaLegacy &&
        cfg.schema_version != TransportConfig::kSchemaTransport)
        return fail("unsupported schema_version " +
                    std::to_string(cfg.schema_version));

    switch (cfg.wire_transport) {
        case WireTransport::LegacyPortHop: {
            // §3.1: QUIC- and TURN-only fields are rejected.
            if (cfg.quic_section_present)
                return fail("legacy-porthop configuration carries a 'quic' "
                            "section (QUIC-only fields are rejected)");
            if (cfg.turn_section_present)
                return fail("legacy-porthop configuration carries a 'turn' "
                            "section (TURN-only fields are rejected)");
            const uint32_t base = cfg.legacy_porthop.base_port;
            const uint32_t range = cfg.legacy_porthop.range;
            if (base == 0) return fail("legacy_porthop.base_port must be > 0");
            if (range == 0) return fail("legacy_porthop.range must be >= 1");
            if (base + range - 1 > 65535)
                return fail("legacy_porthop base_port+range-1 exceeds 65535");
            const uint32_t ms = cfg.legacy_porthop.hop_interval_ms;
            if (ms == 0 || ms % 1000 != 0)
                return fail("legacy_porthop.hop_interval_ms must be a "
                            "positive whole-second value (HopSchedule "
                            "granularity); got " + std::to_string(ms));
            return true;
        }
        case WireTransport::Quic: {
            // §3.2: fixed-path only; no outer hopping, no TURN fields.
            if (cfg.legacy_section_present)
                return fail("quic configuration carries a 'legacy_porthop' "
                            "section (outer PortHop scheduling is rejected)");
            if (cfg.turn_section_present)
                return fail("quic configuration carries a 'turn' section");
            if (cfg.quic.hop_policy != "disabled")
                return fail("quic.hop_policy must be 'disabled' (the only "
                            "accepted value); got '" + cfg.quic.hop_policy + "'");
            if (cfg.quic.alpn.empty())
                return fail("quic.alpn must not be empty");
            if (cfg.quic.remote.empty())
                return fail("quic.remote must name a single explicit remote "
                            "path");
            return true;
        }
        case WireTransport::Turn: {
            // §3.3: UDP only, ChannelData for the established flow,
            // independent credentials via an external reference.
            if (cfg.legacy_section_present)
                return fail("turn configuration carries a 'legacy_porthop' "
                            "section (outer PortHop scheduling is rejected)");
            if (cfg.quic_section_present)
                return fail("turn configuration carries a 'quic' section");
            if (cfg.turn.transport != "udp")
                return fail("turn.transport must be 'udp' (TURN over "
                            "TCP/TLS/DTLS is rejected); got '" +
                            cfg.turn.transport + "'");
            if (cfg.turn.data_mode != "channel-data")
                return fail("turn.data_mode must be 'channel-data' for the "
                            "established flow; got '" + cfg.turn.data_mode + "'");
            if (cfg.turn.credential_ref.empty())
                return fail("turn.credential_ref must name an external "
                            "secret-store entry (independent long-term "
                            "credentials)");
            return true;
        }
    }
    return fail("unknown wire_transport value");
}

std::optional<BoundTransportConfig> bind_transport_config(
    const TransportConfig& cfg,
    const std::vector<uint8_t>& porthop_secret,
    std::string& error) {
    if (!validate_transport_config(cfg, error)) return std::nullopt;

    BoundTransportConfig out;
    out.config = cfg;

    if (cfg.wire_transport == WireTransport::LegacyPortHop) {
        if (porthop_secret.empty()) {
            error = "legacy-porthop binding requires the runtime PortHop "
                    "hop secret";
            return std::nullopt;
        }
        out.hop_schedule.emplace(
            porthop_secret, cfg.legacy_porthop.base_port,
            cfg.legacy_porthop.range,
            cfg.legacy_porthop.hop_interval_ms / 1000);
        out.hop_policy = PathHopPolicy::LegacyPortHop;
        out.outer_transport = OuterTransportKind::Direct;
        return out;
    }

    // Fixed-path QUIC/TURN: the PH hop secret is never reused as a QUIC/TLS
    // or TURN credential (§3.2/§3.3) — passing one is a hard error.
    if (!porthop_secret.empty()) {
        error = std::string("wire_transport '") + to_string(cfg.wire_transport) +
                "' must not be given the PortHop hop secret (secrets are "
                "never reused across transports)";
        return std::nullopt;
    }
    out.hop_schedule = std::nullopt;  // fixed path: NO hop schedule
    out.hop_policy = PathHopPolicy::Disabled;
    out.outer_transport = cfg.wire_transport == WireTransport::Turn
                              ? OuterTransportKind::TurnChannelData
                              : OuterTransportKind::Direct;
    return out;
}

void apply_transport_config(const BoundTransportConfig& bound,
                            NcpMimicrySession::Config& session_cfg) {
    session_cfg.hop_policy = bound.hop_policy;
    session_cfg.outer_transport = bound.outer_transport;
    if (bound.hop_policy == PathHopPolicy::LegacyPortHop) {
        const uint32_t floor =
            kPortHopHeaderBytes + session_cfg.porthop_padding_headroom_bytes;
        if (session_cfg.porthop_overhead_bytes < floor)
            session_cfg.porthop_overhead_bytes = floor;
    } else {
        session_cfg.porthop_overhead_bytes = 0;
        session_cfg.porthop_padding_headroom_bytes = 0;
    }
}

} // namespace ncp
