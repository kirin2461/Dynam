#include "ncp_zapret_import.hpp"

#include <algorithm>
#include <cctype>
#include <sstream>

namespace ncp {
namespace DPI {

// ─────────────────────────────────────────────────────────────────────────────
// Tokenizer (shell-style)
// ─────────────────────────────────────────────────────────────────────────────
std::vector<std::string> zapret_tokenize(const std::string& cmdline) {
    std::vector<std::string> out;
    std::string cur;
    bool in_s = false, in_d = false, esc = false;
    auto flush = [&]() {
        if (!cur.empty()) { out.push_back(cur); cur.clear(); }
    };
    for (char c : cmdline) {
        if (esc) { cur.push_back(c); esc = false; continue; }
        if (c == '\\' && !in_s) { esc = true; continue; }
        if (c == '\'' && !in_d) { in_s = !in_s; continue; }
        if (c == '"' && !in_s) { in_d = !in_d; continue; }
        if (std::isspace(static_cast<unsigned char>(c)) && !in_s && !in_d) {
            flush();
            continue;
        }
        cur.push_back(c);
    }
    flush();
    return out;
}

// ─────────────────────────────────────────────────────────────────────────────
// Small helpers
// ─────────────────────────────────────────────────────────────────────────────
namespace {

std::string to_lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

std::vector<std::string> split_commas(const std::string& s) {
    std::vector<std::string> out;
    std::string cur;
    for (char c : s) {
        if (c == ',') { out.push_back(cur); cur.clear(); }
        else cur.push_back(c);
    }
    if (!cur.empty()) out.push_back(cur);
    return out;
}

bool parse_int(const std::string& s, int& out) {
    if (s.empty()) return false;
    try {
        size_t pos = 0;
        int v = std::stoi(s, &pos);
        if (pos != s.size()) return false;
        out = v;
        return true;
    } catch (...) { return false; }
}

ZSplitPos parse_split_pos(const std::string& tok) {
    ZSplitPos sp;
    int v = 0;
    if (parse_int(tok, v)) {
        sp.type = ZSplitPosType::NUMERIC;
        sp.offset = v;
        return sp;
    }
    const std::string t = to_lower(tok);
    if (t == "method")  { sp.type = ZSplitPosType::METHOD;  return sp; }
    if (t == "host")    { sp.type = ZSplitPosType::HOST;    return sp; }
    if (t == "endhost") { sp.type = ZSplitPosType::ENDHOST; return sp; }
    if (t == "endsld")  { sp.type = ZSplitPosType::ENDSLD;  return sp; }
    if (t == "midsld")  { sp.type = ZSplitPosType::MIDSLD;  return sp; }
    if (t == "sniext")  { sp.type = ZSplitPosType::SNIEXT;  return sp; }
    if (t.rfind("sld+", 0) == 0) {
        sp.type = ZSplitPosType::SLD;
        parse_int(t.substr(4), sp.offset);
        return sp;
    }
    if (t.rfind("sld", 0) == 0) {
        sp.type = ZSplitPosType::SLD;
        sp.offset = 0;
        return sp;
    }
    // unknown marker — keep numeric 0 but flag via type NUMERIC
    sp.type = ZSplitPosType::NUMERIC;
    sp.offset = 0;
    return sp;
}

uint16_t parse_fooling(const std::string& val, std::vector<std::string>& warnings) {
    uint16_t flags = ZFOOL_NONE;
    for (const auto& tok_raw : split_commas(val)) {
        const std::string t = to_lower(tok_raw);
        if (t == "ts")            flags |= ZFOOL_TS;
        else if (t == "badseq")   flags |= ZFOOL_BADSEQ;
        else if (t == "badsum")   flags |= ZFOOL_BADSUM;
        else if (t == "md5sig")   flags |= ZFOOL_MD5SIG;
        else if (t == "datanoack")flags |= ZFOOL_DATANOACK;
        else if (t == "hopbyhop") flags |= ZFOOL_HOPBYHOP;
        else if (t == "hopbyhop2")flags |= ZFOOL_HOPBYHOP2;
        else if (!t.empty()) warnings.push_back("unknown fooling method: " + t);
    }
    return flags;
}

void parse_desync_modes(const std::string& val, ZapretChain& c,
                        std::vector<std::string>& warnings) {
    // zapret: <phase0>,<phase1>,<phase2> — order-independent by name class
    for (const auto& tok_raw : split_commas(val)) {
        const std::string t = to_lower(tok_raw);
        if (t.empty() || t == "none") continue;
        // phase 0
        if (t == "synack")       { c.phase0 = ZDesyncPhase0::SYNACK;  continue; }
        if (t == "syndata")      { c.phase0 = ZDesyncPhase0::SYNDATA; continue; }
        // phase 1
        if (t == "fake")         { c.phase1 = ZDesyncPhase1::FAKE;      continue; }
        if (t == "fakeknown")    { c.phase1 = ZDesyncPhase1::FAKEKNOWN; continue; }
        if (t == "rst")          { c.phase1 = ZDesyncPhase1::RST;       continue; }
        if (t == "rstack")       { c.phase1 = ZDesyncPhase1::RSTACK;    continue; }
        if (t == "hopbyhop")     { c.phase1 = ZDesyncPhase1::HOPBYHOP;  continue; }
        if (t == "destopt")      { c.phase1 = ZDesyncPhase1::DESTOPT;   continue; }
        if (t == "ipfrag1")      { c.phase1 = ZDesyncPhase1::IPFRAG1;   continue; }
        // phase 2
        if (t == "multisplit")     { c.phase2 = ZDesyncPhase2::MULTISPLIT;     continue; }
        if (t == "multidisorder")  { c.phase2 = ZDesyncPhase2::MULTIDISORDER;  continue; }
        if (t == "fakedsplit")     { c.phase2 = ZDesyncPhase2::FAKEDSPLIT;     continue; }
        if (t == "fakeddisorder")  { c.phase2 = ZDesyncPhase2::FAKEDDISORDER;  continue; }
        if (t == "hostfakesplit")  { c.phase2 = ZDesyncPhase2::HOSTFAKESPLIT;  continue; }
        if (t == "ipfrag2")        { c.phase2 = ZDesyncPhase2::IPFRAG2;        continue; }
        if (t == "udplen")         { c.phase2 = ZDesyncPhase2::UDPLEN;         continue; }
        if (t == "tamper")         { c.phase2 = ZDesyncPhase2::TAMPER;         continue; }
        // legacy single names used by older zapret configs
        if (t == "split")          { c.phase2 = ZDesyncPhase2::MULTISPLIT;     continue; }
        if (t == "split2")         { c.phase2 = ZDesyncPhase2::MULTISPLIT;
                                     c.split_positions.push_back(ZSplitPos{ZSplitPosType::NUMERIC, 2});
                                     continue; }
        if (t == "disorder")       { c.phase2 = ZDesyncPhase2::MULTIDISORDER;  continue; }
        if (t == "disorder2")      { c.phase2 = ZDesyncPhase2::MULTIDISORDER;  continue; }
        warnings.push_back("unknown desync mode: " + t);
    }
}

void parse_port_filter(const std::string& val, ZapretChain& c, ZProto proto,
                       std::vector<std::string>& errors) {
    c.proto = proto;
    c.ports.clear();
    for (const auto& tok : split_commas(val)) {
        // forms: "443", "80,443", "1000-2000", or with '~' exclusion — we keep it simple
        const size_t dash = tok.find('-');
        if (dash != std::string::npos) {
            int a = 0, b = 0;
            if (!parse_int(tok.substr(0, dash), a) || !parse_int(tok.substr(dash + 1), b)) {
                errors.push_back("bad port range: " + tok);
                continue;
            }
            c.ports.emplace_back(static_cast<uint16_t>(a), static_cast<uint16_t>(b));
        } else {
            int p = 0;
            if (!parse_int(tok, p)) {
                errors.push_back("bad port: " + tok);
                continue;
            }
            c.ports.emplace_back(static_cast<uint16_t>(p), static_cast<uint16_t>(p));
        }
    }
}

ZCondition parse_condition(const std::string& val) {
    ZCondition cond;
    if (val.size() >= 2) {
        const char kind = static_cast<char>(std::tolower(static_cast<unsigned char>(val[0])));
        int v = 0;
        if (parse_int(val.substr(1), v)) {
            cond.value = v;
            if (kind == 'n') cond.type = ZCondType::N;
            else if (kind == 'd') cond.type = ZCondType::D;
            else if (kind == 's') cond.type = ZCondType::S;
        }
    }
    return cond;
}

std::string json_escape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 8);
    for (char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    char buf[8];
                    snprintf(buf, sizeof(buf), "\\u%04x", c);
                    out += buf;
                } else out.push_back(c);
        }
    }
    return out;
}

} // namespace

// ─────────────────────────────────────────────────────────────────────────────
// Main parser
// ─────────────────────────────────────────────────────────────────────────────
ZapretImportResult parse_zapret_argv(const std::vector<std::string>& args) {
    ZapretImportResult res;
    res.profile.id = "imported";
    res.profile.label = "Imported zapret strategy";

    ZapretChain current;
    int chain_no = 0;
    current.name = "chain-1";
    bool current_has_content = false;

    auto flush_chain = [&]() {
        if (!current_has_content) return;
        // default ports if none given
        if (current.ports.empty()) {
            if (current.proto == ZProto::TCP) current.ports.emplace_back(443, 443);
            else current.ports.emplace_back(443, 443);
        }
        res.profile.chains.push_back(current);
        current = ZapretChain{};
        current_has_content = false;
        current.name = "chain-" + std::to_string(++chain_no + 1);
    };

    for (size_t i = 0; i < args.size(); ++i) {
        std::string a = args[i];
        if (a.empty()) continue;

        // normalize "--flag value" into "--flag=value" handled below via peek
        std::string flag = a, value;
        const size_t eq = a.find('=');
        if (eq != std::string::npos) {
            flag = a.substr(0, eq);
            value = a.substr(eq + 1);
        }
        auto need_value = [&](const std::string& f) -> bool {
            if (eq != std::string::npos) return true;
            if (i + 1 < args.size() && args[i + 1].rfind("--", 0) != 0) {
                value = args[++i];
                return true;
            }
            res.errors.push_back("missing value for " + f);
            return false;
        };

        if (flag == "--new") {
            flush_chain();
            continue;
        }
        if (flag == "--filter-tcp") {
            if (!need_value(flag)) continue;
            parse_port_filter(value, current, ZProto::TCP, res.errors);
            current_has_content = true;
            continue;
        }
        if (flag == "--filter-udp") {
            if (!need_value(flag)) continue;
            parse_port_filter(value, current, ZProto::UDP, res.errors);
            current_has_content = true;
            continue;
        }
        if (flag == "--filter-l3") {
            if (!need_value(flag)) continue;
            const std::string v = to_lower(value);
            if (v == "ipv4") current.l3_filter = ZL3Filter::IPV4;
            else if (v == "ipv6") current.l3_filter = ZL3Filter::IPV6;
            else res.warnings.push_back("unknown --filter-l3: " + value);
            continue;
        }
        if (flag == "--filter-l7") {
            if (!need_value(flag)) continue;
            uint32_t f = ZL7_NONE;
            for (const auto& t0 : split_commas(to_lower(value))) {
                if (t0 == "tls") f |= ZL7_TLS;
                else if (t0 == "http") f |= ZL7_HTTP;
                else if (t0 == "quic") f |= ZL7_QUIC;
                else if (t0 == "wireguard") f |= ZL7_WIREGUARD;
                else if (t0 == "dht") f |= ZL7_DHT;
                else if (t0 == "discord") f |= ZL7_DISCORD;
                else if (t0 == "stun") f |= ZL7_STUN;
                else if (t0 == "unknown") f |= ZL7_UNKNOWN;
                else res.warnings.push_back("unknown l7 filter: " + t0);
            }
            current.l7_filter = f;
            continue;
        }
        if (flag == "--dpi-desync") {
            if (!need_value(flag)) continue;
            parse_desync_modes(value, current, res.warnings);
            current_has_content = true;
            continue;
        }
        if (flag == "--dpi-desync-split-pos") {
            if (!need_value(flag)) continue;
            for (const auto& t : split_commas(value))
                current.split_positions.push_back(parse_split_pos(t));
            continue;
        }
        if (flag == "--dpi-desync-split-seqovl") {
            if (!need_value(flag)) continue;
            parse_int(value, current.split_seqovl);
            continue;
        }
        if (flag == "--dpi-desync-fooling") {
            if (!need_value(flag)) continue;
            current.fooling = parse_fooling(value, res.warnings);
            continue;
        }
        if (flag == "--dpi-desync-repeats") {
            if (!need_value(flag)) continue;
            if (!parse_int(value, current.desync_repeats))
                res.errors.push_back("bad --dpi-desync-repeats: " + value);
            continue;
        }
        if (flag == "--dpi-desync-ttl") {
            if (!need_value(flag)) continue;
            if (!parse_int(value, current.orig_ttl.ttl))
                res.errors.push_back("bad --dpi-desync-ttl: " + value);
            continue;
        }
        if (flag == "--dpi-desync-autottl") {
            if (!need_value(flag)) continue;
            current.orig_ttl.auto_ttl = true;
            const size_t dash = value.find('-');
            if (dash != std::string::npos) {
                parse_int(value.substr(0, dash), current.orig_ttl.auto_ttl_min);
                parse_int(value.substr(dash + 1), current.orig_ttl.auto_ttl_max);
            } else {
                parse_int(value, current.orig_ttl.auto_ttl_min);
            }
            continue;
        }
        if (flag == "--dpi-desync-any-protocol") {
            current.any_protocol = true;
            continue;
        }
        if (flag == "--dpi-desync-fake-tls") {
            current.fake_type = ZFakeType::TLS;
            if (eq != std::string::npos && !value.empty() && value != "0" && value != "1")
                res.warnings.push_back("fake-tls payload file ignored: " + value);
            continue;
        }
        if (flag == "--dpi-desync-fake-http") {
            current.fake_type = ZFakeType::HTTP;
            continue;
        }
        if (flag == "--dpi-desync-fake-quic") {
            current.fake_type = ZFakeType::QUIC;
            if (eq != std::string::npos && !value.empty() && value != "0" && value != "1")
                res.warnings.push_back("fake-quic payload file ignored: " + value);
            continue;
        }
        if (flag == "--dpi-desync-fake-wireguard") { current.fake_type = ZFakeType::WIREGUARD; continue; }
        if (flag == "--dpi-desync-fake-dht")       { current.fake_type = ZFakeType::DHT;       continue; }
        if (flag == "--dpi-desync-fake-discord")   { current.fake_type = ZFakeType::DISCORD;   continue; }
        if (flag == "--dpi-desync-fake-stun")      { current.fake_type = ZFakeType::STUN;      continue; }
        if (flag == "--dpi-desync-fake-unknown")   { current.fake_type = ZFakeType::UNKNOWN;   continue; }
        if (flag == "--dpi-desync-fake-unknown-udp") { current.fake_type = ZFakeType::UNKNOWN_UDP; continue; }
        if (flag == "--dpi-desync-fake-syndata")   { current.fake_type = ZFakeType::SYNDATA;   continue; }
        if (flag == "--dpi-desync-fake-hex") {
            if (!need_value(flag)) continue;
            current.fake_type = ZFakeType::CUSTOM;
            current.fake_custom_hex = value;
            continue;
        }
        if (flag == "--dpi-desync-fake-tls-mod") {
            if (!need_value(flag)) continue;
            for (const auto& t0 : split_commas(to_lower(value))) {
                if (t0 == "rnd") current.fake_tls_mod = ZFakeTlsMod::RND;
                else if (t0 == "rndsni") current.fake_tls_mod = ZFakeTlsMod::RNDSNI;
                else if (t0 == "dupsid") current.fake_tls_mod = ZFakeTlsMod::DUPSID;
                else if (t0 == "padencap") current.fake_tls_mod = ZFakeTlsMod::PADENCAP;
                else if (t0.rfind("sni=", 0) == 0) {
                    current.fake_tls_mod = ZFakeTlsMod::SNI_SET;
                    current.fake_tls_sni = value.substr(value.find("sni=") + 4);
                } else res.warnings.push_back("unknown fake-tls-mod: " + t0);
            }
            continue;
        }
        if (flag == "--dpi-desync-fake-offset") {
            if (!need_value(flag)) continue;
            parse_int(value, current.fake_offset);
            continue;
        }
        if (flag == "--dpi-desync-ipfrag-pos-tcp" || flag == "--dpi-desync-ipfrag-pos-udp") {
            if (!need_value(flag)) continue;
            parse_int(value, current.ipfrag_offset);
            continue;
        }
        if (flag == "--dpi-desync-ipid") {
            if (!need_value(flag)) continue;
            const std::string v = to_lower(value);
            if (v == "zero") current.ipid_mode = ZIpIdMode::ZERO;
            else if (v == "seq") current.ipid_mode = ZIpIdMode::SEQ;
            else if (v == "seqgroup") current.ipid_mode = ZIpIdMode::SEQGROUP;
            else if (v == "rnd") current.ipid_mode = ZIpIdMode::RND;
            else current.ipid_mode = ZIpIdMode::DEFAULT;
            continue;
        }
        if (flag == "--dpi-desync-dup") {
            if (!need_value(flag)) continue;
            parse_int(value, current.dup.count);
            continue;
        }
        if (flag == "--dpi-desync-dup-replace") { current.dup.replace = true; continue; }
        if (flag == "--dpi-desync-dup-ttl") {
            if (!need_value(flag)) continue;
            parse_int(value, current.dup.ttl);
            continue;
        }
        if (flag == "--dpi-desync-dup-fooling") {
            if (!need_value(flag)) continue;
            current.dup.fooling = parse_fooling(value, res.warnings);
            continue;
        }
        if (flag == "--dpi-desync-fakedsplit-altorder") { current.fakedsplit_altorder = true; continue; }
        if (flag == "--dpi-desync-hostfakesplit-midhost") {
            if (!need_value(flag)) continue;
            parse_int(value, current.hostfakesplit_midhost);
            continue;
        }
        if (flag == "--dpi-desync-udplen-increment") {
            if (!need_value(flag)) continue;
            parse_int(value, current.udplen_increment);
            continue;
        }
        if (flag == "--dpi-desync-udplen-pattern") {
            if (!need_value(flag)) continue;
            parse_int(value, current.udplen_pattern);
            continue;
        }
        if (flag == "--dpi-desync-tcp-flags") {
            if (!need_value(flag)) continue;
            current.orig_tcp_flags = value;
            continue;
        }
        if (flag == "--dpi-desync-start") {
            if (!need_value(flag)) continue;
            current.start = parse_condition(value);
            continue;
        }
        if (flag == "--dpi-desync-cutoff") {
            if (!need_value(flag)) continue;
            current.cutoff = parse_condition(value);
            continue;
        }
        if (flag == "--hostlist") {
            if (!need_value(flag)) continue;
            current.hostlist = value;
            current_has_content = true;
            continue;
        }
        if (flag == "--hostlist-exclude") {
            if (!need_value(flag)) continue;
            current.hostlist_exclude = value;
            continue;
        }
        if (flag == "--hostlist-auto") {
            if (!need_value(flag)) continue;
            current.hostlist_auto = value;
            continue;
        }
        if (flag == "--hostlist-domains") {
            if (!need_value(flag)) continue;
            current.host_domain = value;
            current_has_content = true;
            continue;
        }
        if (flag == "--ipset") {
            if (!need_value(flag)) continue;
            current.ipset = value;
            continue;
        }
        if (flag == "--ipset-exclude") {
            if (!need_value(flag)) continue;
            current.ipset_exclude = value;
            continue;
        }
        if (flag == "--wssize") {
            if (!need_value(flag)) continue;
            parse_int(value, current.wssize.value);
            continue;
        }
        if (flag == "--wssize-scale") {
            if (!need_value(flag)) continue;
            parse_int(value, current.wssize.scale);
            continue;
        }
        if (flag == "--wf-tcp") { if (need_value(flag)) current.wf_tcp = value; continue; }
        if (flag == "--wf-udp") { if (need_value(flag)) current.wf_udp = value; continue; }
        if (flag == "--wf-raw") { if (need_value(flag)) current.wf_raw = value; continue; }
        if (flag == "--ssid-filter") {
            if (need_value(flag)) current.ssid_filter = value;
            continue;
        }
        // zapret daemon / logging options — irrelevant to strategy
        if (flag == "--daemon" || flag == "--pidfile" || flag == "--user" ||
            flag == "--debug" || flag == "--log" || flag == "--hostcase" ||
            flag == "--hostspell" || flag == "--hostnospace" || flag == "--domcase") {
            if (flag == "--pidfile" || flag == "--user" || flag == "--debug" || flag == "--log") {
                // these take values
                if (eq == std::string::npos && i + 1 < args.size() &&
                    args[i + 1].rfind("--", 0) != 0) ++i;
            }
            res.warnings.push_back("option ignored (daemon/logging): " + flag);
            continue;
        }
        if (flag.rfind("--", 0) == 0) {
            res.warnings.push_back("unsupported option: " + flag);
            continue;
        }
        // bare token (e.g. stray domain) — ignore with warning
        res.warnings.push_back("stray argument ignored: " + a);
    }
    flush_chain();

    if (res.profile.chains.empty() && res.errors.empty()) {
        res.errors.push_back("no desync chains found in arguments");
    }
    return res;
}

ZapretImportResult parse_zapret_cmdline(const std::string& cmdline) {
    return parse_zapret_argv(zapret_tokenize(cmdline));
}

// ─────────────────────────────────────────────────────────────────────────────
// JSON serialization (manual, no dependency)
// ─────────────────────────────────────────────────────────────────────────────
std::string zapret_profile_to_json(const ZapretImportResult& result) {
    std::ostringstream j;
    j << "{\n  \"id\": \"" << json_escape(result.profile.id) << "\",\n";
    j << "  \"label\": \"" << json_escape(result.profile.label) << "\",\n";
    j << "  \"ok\": " << (result.ok() ? "true" : "false") << ",\n";

    j << "  \"chains\": [\n";
    for (size_t ci = 0; ci < result.profile.chains.size(); ++ci) {
        const ZapretChain& c = result.profile.chains[ci];
        j << "    {\n";
        j << "      \"name\": \"" << json_escape(c.name) << "\",\n";
        j << "      \"proto\": \"" << (c.proto == ZProto::TCP ? "tcp" : "udp") << "\",\n";
        j << "      \"ports\": [";
        for (size_t pi = 0; pi < c.ports.size(); ++pi) {
            j << (pi ? ", " : "") << "[" << c.ports[pi].first << "," << c.ports[pi].second << "]";
        }
        j << "],\n";
        j << "      \"desync\": \"" << json_escape(
            (c.phase0 != ZDesyncPhase0::NONE ? desync_phase0_to_string(c.phase0) + "," : "") +
            (c.phase1 != ZDesyncPhase1::NONE ? desync_phase1_to_string(c.phase1) : "") +
            (c.phase2 != ZDesyncPhase2::NONE
                 ? std::string(c.phase1 != ZDesyncPhase1::NONE ? "," : "") +
                       desync_phase2_to_string(c.phase2)
                 : "")) << "\",\n";
        j << "      \"split_positions\": [";
        for (size_t si = 0; si < c.split_positions.size(); ++si) {
            j << (si ? ", " : "") << "\"" << json_escape(split_pos_to_string(c.split_positions[si])) << "\"";
        }
        j << "],\n";
        j << "      \"fooling\": \"" << json_escape(fooling_flags_to_string(c.fooling)) << "\",\n";
        j << "      \"repeats\": " << c.desync_repeats << ",\n";
        j << "      \"ttl\": " << c.orig_ttl.ttl << ",\n";
        j << "      \"autottl\": " << (c.orig_ttl.auto_ttl ? "true" : "false") << ",\n";
        j << "      \"fake_type\": \"" << json_escape(fake_type_to_string(c.fake_type)) << "\",\n";
        if (!c.hostlist.empty())
            j << "      \"hostlist\": \"" << json_escape(c.hostlist) << "\",\n";
        if (!c.hostlist_auto.empty())
            j << "      \"hostlist_auto\": \"" << json_escape(c.hostlist_auto) << "\",\n";
        if (!c.hostlist_exclude.empty())
            j << "      \"hostlist_exclude\": \"" << json_escape(c.hostlist_exclude) << "\",\n";
        if (!c.ipset.empty())
            j << "      \"ipset\": \"" << json_escape(c.ipset) << "\",\n";
        j << "      \"cmdline\": \"" << json_escape(chain_to_cmdline(c)) << "\"\n";
        j << "    }" << (ci + 1 < result.profile.chains.size() ? "," : "") << "\n";
    }
    j << "  ],\n";

    auto dump_list = [&](const char* key, const std::vector<std::string>& v, bool last) {
        j << "  \"" << key << "\": [";
        for (size_t i = 0; i < v.size(); ++i)
            j << (i ? ", " : "") << "\"" << json_escape(v[i]) << "\"";
        j << "]" << (last ? "\n" : ",\n");
    };
    dump_list("warnings", result.warnings, false);
    dump_list("errors", result.errors, true);
    j << "}\n";
    return j.str();
}

} // namespace DPI
} // namespace ncp
