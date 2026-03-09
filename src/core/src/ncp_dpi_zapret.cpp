#include "ncp_dpi_zapret.hpp"
#include <algorithm>
#include <cctype>
#include <sstream>

namespace ncp {
namespace DPI {

// ═══════════════════════════════════════════════════════════════════════════════
// String conversion helpers
// ═══════════════════════════════════════════════════════════════════════════════

namespace {

std::string to_lower(const std::string& s) {
    std::string out = s;
    std::transform(out.begin(), out.end(), out.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return out;
}

} // anonymous namespace

std::string desync_phase0_to_string(ZDesyncPhase0 p) {
    switch (p) {
    case ZDesyncPhase0::SYNACK:  return "synack";
    case ZDesyncPhase0::SYNDATA: return "syndata";
    default:                     return "";
    }
}

std::string desync_phase1_to_string(ZDesyncPhase1 p) {
    switch (p) {
    case ZDesyncPhase1::FAKE:      return "fake";
    case ZDesyncPhase1::FAKEKNOWN: return "fakeknown";
    case ZDesyncPhase1::RST:       return "rst";
    case ZDesyncPhase1::RSTACK:    return "rstack";
    case ZDesyncPhase1::HOPBYHOP:  return "hopbyhop";
    case ZDesyncPhase1::DESTOPT:   return "destopt";
    case ZDesyncPhase1::IPFRAG1:   return "ipfrag1";
    default:                       return "";
    }
}

std::string desync_phase2_to_string(ZDesyncPhase2 p) {
    switch (p) {
    case ZDesyncPhase2::MULTISPLIT:     return "multisplit";
    case ZDesyncPhase2::MULTIDISORDER:  return "multidisorder";
    case ZDesyncPhase2::FAKEDSPLIT:     return "fakedsplit";
    case ZDesyncPhase2::FAKEDDISORDER:  return "fakeddisorder";
    case ZDesyncPhase2::HOSTFAKESPLIT:  return "hostfakesplit";
    case ZDesyncPhase2::IPFRAG2:        return "ipfrag2";
    case ZDesyncPhase2::UDPLEN:         return "udplen";
    case ZDesyncPhase2::TAMPER:         return "tamper";
    default:                            return "";
    }
}

std::string fooling_flags_to_string(uint16_t flags) {
    std::vector<std::string> parts;
    if (flags & ZFOOL_TS)        parts.push_back("ts");
    if (flags & ZFOOL_BADSEQ)    parts.push_back("badseq");
    if (flags & ZFOOL_BADSUM)    parts.push_back("badsum");
    if (flags & ZFOOL_MD5SIG)    parts.push_back("md5sig");
    if (flags & ZFOOL_DATANOACK) parts.push_back("datanoack");
    if (flags & ZFOOL_HOPBYHOP)  parts.push_back("hopbyhop");
    if (flags & ZFOOL_HOPBYHOP2) parts.push_back("hopbyhop2");
    std::string result;
    for (size_t i = 0; i < parts.size(); ++i) {
        if (i > 0) result += ",";
        result += parts[i];
    }
    return result;
}

std::string fake_type_to_string(ZFakeType ft) {
    switch (ft) {
    case ZFakeType::TLS:         return "tls";
    case ZFakeType::HTTP:        return "http";
    case ZFakeType::QUIC:        return "quic";
    case ZFakeType::WIREGUARD:   return "wireguard";
    case ZFakeType::DHT:         return "dht";
    case ZFakeType::DISCORD:     return "discord";
    case ZFakeType::STUN:        return "stun";
    case ZFakeType::SYNDATA:     return "syndata";
    case ZFakeType::UNKNOWN:     return "unknown";
    case ZFakeType::UNKNOWN_UDP: return "unknown-udp";
    case ZFakeType::CUSTOM:      return "custom";
    default:                     return "none";
    }
}

std::string split_pos_to_string(const ZSplitPos& sp) {
    switch (sp.type) {
    case ZSplitPosType::METHOD:  return "method";
    case ZSplitPosType::HOST:    return "host";
    case ZSplitPosType::ENDHOST: return "endhost";
    case ZSplitPosType::SLD:     return "sld+" + std::to_string(sp.offset);
    case ZSplitPosType::ENDSLD:  return "endsld";
    case ZSplitPosType::MIDSLD:  return "midsld";
    case ZSplitPosType::SNIEXT:  return "sniext";
    case ZSplitPosType::NUMERIC:
    default:                     return std::to_string(sp.offset);
    }
}

std::string ipid_mode_to_string(ZIpIdMode m) {
    switch (m) {
    case ZIpIdMode::ZERO:     return "0";
    case ZIpIdMode::SEQ:      return "seq";
    case ZIpIdMode::SEQGROUP: return "seqgroup";
    case ZIpIdMode::RND:      return "rnd";
    default:                  return "";
    }
}

std::string condition_to_string(const ZCondition& c) {
    switch (c.type) {
    case ZCondType::N: return "n" + std::to_string(c.value);
    case ZCondType::D: return "d" + std::to_string(c.value);
    case ZCondType::S: return "s" + std::to_string(c.value);
    default:           return "";
    }
}

// Build a full command-line representation for a chain (debugging/logging)
std::string chain_to_cmdline(const ZapretChain& chain) {
    std::ostringstream cmd;
    cmd << "--new";

    // Protocol & port filters
    if (chain.proto == ZProto::TCP) {
        if (!chain.wf_tcp.empty()) cmd << " --wf-tcp=" << chain.wf_tcp;
    } else {
        if (!chain.wf_udp.empty()) cmd << " --wf-udp=" << chain.wf_udp;
    }
    if (!chain.wf_raw.empty()) cmd << " --wf-raw=" << chain.wf_raw;

    // L3 filter
    if (chain.l3_filter == ZL3Filter::IPV4) cmd << " --filter-l3=ipv4";
    else if (chain.l3_filter == ZL3Filter::IPV6) cmd << " --filter-l3=ipv6";

    // L7 filter
    {
        std::vector<std::string> l7parts;
        if (chain.l7_filter & ZL7_TLS)       l7parts.push_back("tls");
        if (chain.l7_filter & ZL7_HTTP)      l7parts.push_back("http");
        if (chain.l7_filter & ZL7_QUIC)      l7parts.push_back("quic");
        if (chain.l7_filter & ZL7_WIREGUARD) l7parts.push_back("wireguard");
        if (chain.l7_filter & ZL7_DHT)       l7parts.push_back("dht");
        if (chain.l7_filter & ZL7_DISCORD)   l7parts.push_back("discord");
        if (chain.l7_filter & ZL7_STUN)      l7parts.push_back("stun");
        if (chain.l7_filter & ZL7_UNKNOWN)   l7parts.push_back("unknown");
        if (!l7parts.empty()) {
            cmd << " --filter-l7=";
            for (size_t i = 0; i < l7parts.size(); ++i) {
                if (i) cmd << ",";
                cmd << l7parts[i];
            }
        }
    }

    // Host/IP lists
    if (!chain.hostlist.empty())         cmd << " --hostlist=" << chain.hostlist;
    if (!chain.hostlist_exclude.empty()) cmd << " --hostlist-exclude=" << chain.hostlist_exclude;
    if (!chain.hostlist_auto.empty())    cmd << " --hostlist-auto=" << chain.hostlist_auto;
    if (!chain.ipset.empty())            cmd << " --ipset=" << chain.ipset;
    if (!chain.ipset_exclude.empty())    cmd << " --ipset-exclude=" << chain.ipset_exclude;
    if (!chain.ssid_filter.empty())      cmd << " --ssid-filter=" << chain.ssid_filter;

    // Desync mode
    {
        std::vector<std::string> modes;
        auto s0 = desync_phase0_to_string(chain.phase0);
        auto s1 = desync_phase1_to_string(chain.phase1);
        auto s2 = desync_phase2_to_string(chain.phase2);
        if (!s0.empty()) modes.push_back(s0);
        if (!s1.empty()) modes.push_back(s1);
        if (!s2.empty()) modes.push_back(s2);
        if (!modes.empty()) {
            cmd << " --dpi-desync=";
            for (size_t i = 0; i < modes.size(); ++i) {
                if (i) cmd << ",";
                cmd << modes[i];
            }
        }
    }

    // Repeats
    if (chain.desync_repeats > 1) cmd << " --dpi-desync-repeats=" << chain.desync_repeats;

    // Fooling
    if (chain.fooling != ZFOOL_NONE) {
        cmd << " --dpi-desync-fooling=" << fooling_flags_to_string(chain.fooling);
    }

    // Split positions
    if (!chain.split_positions.empty()) {
        cmd << " --dpi-desync-split-pos=";
        for (size_t i = 0; i < chain.split_positions.size(); ++i) {
            if (i) cmd << ",";
            cmd << split_pos_to_string(chain.split_positions[i]);
        }
    }

    // Seqovl
    if (chain.split_seqovl > 0) cmd << " --dpi-desync-split-seqovl=" << chain.split_seqovl;

    // Fake type
    if (chain.fake_type != ZFakeType::TLS && chain.fake_type != ZFakeType::NONE) {
        cmd << " --dpi-desync-fake-" << fake_type_to_string(chain.fake_type);
    }

    // Fake TLS mod
    if (chain.fake_tls_mod != ZFakeTlsMod::NONE) {
        cmd << " --dpi-desync-fake-tls-mod=";
        switch (chain.fake_tls_mod) {
        case ZFakeTlsMod::RND:      cmd << "rnd"; break;
        case ZFakeTlsMod::RNDSNI:   cmd << "rndsni"; break;
        case ZFakeTlsMod::DUPSID:   cmd << "dupsid"; break;
        case ZFakeTlsMod::SNI_SET:  cmd << "sni=" << chain.fake_tls_sni; break;
        case ZFakeTlsMod::PADENCAP: cmd << "padencap"; break;
        default: break;
        }
    }

    // Fake custom hex
    if (chain.fake_type == ZFakeType::CUSTOM && !chain.fake_custom_hex.empty()) {
        cmd << " --dpi-desync-fake-hex=" << chain.fake_custom_hex;
    }

    // TTL
    if (chain.orig_ttl.auto_ttl) {
        cmd << " --dpi-desync-autottl";
        if (chain.orig_ttl.auto_ttl_min > 1 || chain.orig_ttl.auto_ttl_max > 0) {
            cmd << "=" << chain.orig_ttl.auto_ttl_min << "-" << chain.orig_ttl.auto_ttl_max;
        }
    } else if (chain.orig_ttl.ttl > 0) {
        cmd << " --dpi-desync-ttl=" << chain.orig_ttl.ttl;
    }

    // TCP flags
    if (!chain.orig_tcp_flags.empty()) {
        cmd << " --dpi-desync-tcp-flags=" << chain.orig_tcp_flags;
    }

    // IP-ID
    if (chain.ipid_mode != ZIpIdMode::DEFAULT) {
        cmd << " --dpi-desync-ipid=" << ipid_mode_to_string(chain.ipid_mode);
    }

    // Dup system
    if (chain.dup.count > 0) {
        cmd << " --dpi-desync-dup=" << chain.dup.count;
        if (chain.dup.replace) cmd << " --dpi-desync-dup-replace";
        if (chain.dup.ttl > 0) cmd << " --dpi-desync-dup-ttl=" << chain.dup.ttl;
        if (chain.dup.fooling != ZFOOL_NONE)
            cmd << " --dpi-desync-dup-fooling=" << fooling_flags_to_string(chain.dup.fooling);
    }

    // Fakedsplit extras
    if (chain.fakedsplit_altorder) cmd << " --dpi-desync-fakedsplit-altorder";
    if (chain.hostfakesplit_midhost > 0)
        cmd << " --dpi-desync-hostfakesplit-midhost=" << chain.hostfakesplit_midhost;

    // UDP extras
    if (chain.udplen_increment != 0) cmd << " --dpi-desync-udplen-increment=" << chain.udplen_increment;

    // IP fragmentation
    if (chain.ipfrag_offset > 0) cmd << " --dpi-desync-ipfrag-pos-tcp=" << chain.ipfrag_offset;

    // Window size
    if (chain.wssize.value > 0) {
        cmd << " --wssize=" << chain.wssize.value;
        if (chain.wssize.scale >= 0) cmd << ":" << chain.wssize.scale;
    }

    // Any protocol
    if (chain.any_protocol) cmd << " --dpi-desync-any-protocol";

    // Start / cutoff conditions
    if (chain.start.type != ZCondType::NONE) cmd << " --dpi-desync-start=" << condition_to_string(chain.start);
    if (chain.cutoff.type != ZCondType::NONE) cmd << " --dpi-desync-cutoff=" << condition_to_string(chain.cutoff);

    return cmd.str();
}


// ═══════════════════════════════════════════════════════════════════════════════
// Chain definitions — based on zapret v72.x recommended configs for Russia
// ═══════════════════════════════════════════════════════════════════════════════

namespace {

// Helper: create a split-pos with numeric offset
ZSplitPos sp_num(int n) {
    ZSplitPos sp;
    sp.type = ZSplitPosType::NUMERIC;
    sp.offset = n;
    return sp;
}

ZSplitPos sp_marker(ZSplitPosType t, int offset = 0) {
    ZSplitPos sp;
    sp.type = t;
    sp.offset = offset;
    return sp;
}

std::vector<ZapretChain> build_all_chains() {
    std::vector<ZapretChain> chains;

    // Chain 1: QUIC General (hostlist) — UDP 443
    // --new --filter-udp=443 --hostlist=list-general.txt
    // --dpi-desync=fake --dpi-desync-repeats=11 --dpi-desync-fake-quic
    // --dpi-desync-cutoff=n4
    {
        ZapretChain c;
        c.name = "QUIC General";
        c.proto = ZProto::UDP;
        c.ports = {{443, 443}};
        c.hostlist = "list-general.txt";
        c.phase0 = ZDesyncPhase0::NONE;
        c.phase1 = ZDesyncPhase1::FAKE;
        c.phase2 = ZDesyncPhase2::NONE;
        c.desync_repeats = 11;
        c.fake_type = ZFakeType::QUIC;
        c.cutoff = {ZCondType::N, 4};
        c.wf_udp = "443";
        chains.push_back(c);
    }

    // Chain 2: Discord STUN — UDP 19294-19344,50000-50100
    // --new --filter-udp=19294-19344,50000-50100 --filter-l7=discord,stun
    // --dpi-desync=fake --dpi-desync-repeats=6
    // --dpi-desync-fake-discord --dpi-desync-cutoff=n4
    {
        ZapretChain c;
        c.name = "Discord STUN";
        c.proto = ZProto::UDP;
        c.ports = {{19294, 19344}, {50000, 50100}};
        c.l7_filter = ZL7_DISCORD | ZL7_STUN;
        c.phase1 = ZDesyncPhase1::FAKE;
        c.desync_repeats = 6;
        c.fake_type = ZFakeType::DISCORD;
        c.cutoff = {ZCondType::N, 4};
        chains.push_back(c);
    }

    // Chain 3: Discord Media — TCP 2053,2083,2087,2096,8443
    // --new --filter-tcp=2053,2083,2087,2096,8443
    // --dpi-desync=fake,multisplit --dpi-desync-split-seqovl=681
    // --dpi-desync-split-pos=1 --dpi-desync-fooling=ts,badseq
    // --dpi-desync-repeats=8 --dpi-desync-fake-tls
    {
        ZapretChain c;
        c.name = "Discord Media";
        c.proto = ZProto::TCP;
        c.ports = {{2053, 2053}, {2083, 2083}, {2087, 2087}, {2096, 2096}, {8443, 8443}};
        c.host_domain = "discord.media";
        c.phase1 = ZDesyncPhase1::FAKE;
        c.phase2 = ZDesyncPhase2::MULTISPLIT;
        c.split_seqovl = 681;
        c.split_positions = {sp_num(1)};
        c.fooling = ZFOOL_TS | ZFOOL_BADSEQ;
        c.desync_repeats = 8;
        c.fake_type = ZFakeType::TLS;
        c.wf_tcp = "2053,2083,2087,2096,8443";
        chains.push_back(c);
    }

    // Chain 4: Google TLS — TCP 443 (Google-specific)
    // --new --filter-tcp=443 --hostlist=list-google.txt
    // --dpi-desync-ipid=0 --dpi-desync=fake,multisplit
    // --dpi-desync-split-seqovl=681 --dpi-desync-split-pos=1
    // --dpi-desync-fooling=ts,badseq --dpi-desync-repeats=8
    {
        ZapretChain c;
        c.name = "Google TLS";
        c.proto = ZProto::TCP;
        c.ports = {{443, 443}};
        c.hostlist = "list-google.txt";
        c.ipid_mode = ZIpIdMode::ZERO;
        c.phase1 = ZDesyncPhase1::FAKE;
        c.phase2 = ZDesyncPhase2::MULTISPLIT;
        c.split_seqovl = 681;
        c.split_positions = {sp_num(1)};
        c.fooling = ZFOOL_TS | ZFOOL_BADSEQ;
        c.desync_repeats = 8;
        c.fake_type = ZFakeType::TLS;
        c.wf_tcp = "443";
        chains.push_back(c);
    }

    // Chain 5: General Hostlist — TCP 80,443
    // --new --filter-tcp=80,443 --hostlist=list-general.txt
    // --dpi-desync=fake,multisplit --dpi-desync-split-seqovl=664
    // --dpi-desync-split-pos=1 --dpi-desync-fooling=ts,badseq
    // --dpi-desync-repeats=8
    {
        ZapretChain c;
        c.name = "General Hostlist";
        c.proto = ZProto::TCP;
        c.ports = {{80, 80}, {443, 443}};
        c.hostlist = "list-general.txt";
        c.phase1 = ZDesyncPhase1::FAKE;
        c.phase2 = ZDesyncPhase2::MULTISPLIT;
        c.split_seqovl = 664;
        c.split_positions = {sp_num(1)};
        c.fooling = ZFOOL_TS | ZFOOL_BADSEQ;
        c.desync_repeats = 8;
        c.fake_type = ZFakeType::TLS;
        c.wf_tcp = "80,443";
        chains.push_back(c);
    }

    // Chain 6: QUIC ipset-all — UDP 443
    // --new --filter-udp=443 --ipset=ipset-all.txt
    // --dpi-desync=fake --dpi-desync-repeats=11 --dpi-desync-fake-quic
    // --dpi-desync-cutoff=n4
    {
        ZapretChain c;
        c.name = "QUIC ipset-all";
        c.proto = ZProto::UDP;
        c.ports = {{443, 443}};
        c.ipset = "ipset-all.txt";
        c.phase1 = ZDesyncPhase1::FAKE;
        c.desync_repeats = 11;
        c.fake_type = ZFakeType::QUIC;
        c.cutoff = {ZCondType::N, 4};
        c.wf_udp = "443";
        chains.push_back(c);
    }

    // Chain 7: TCP ipset-all — TCP 80,443,12
    // --new --filter-tcp=80,443,12 --ipset=ipset-all.txt
    // --dpi-desync=fake,multisplit --dpi-desync-split-seqovl=664
    // --dpi-desync-split-pos=1 --dpi-desync-fooling=ts,badseq
    // --dpi-desync-repeats=8
    {
        ZapretChain c;
        c.name = "TCP ipset-all";
        c.proto = ZProto::TCP;
        c.ports = {{80, 80}, {443, 443}, {12, 12}};
        c.ipset = "ipset-all.txt";
        c.phase1 = ZDesyncPhase1::FAKE;
        c.phase2 = ZDesyncPhase2::MULTISPLIT;
        c.split_seqovl = 664;
        c.split_positions = {sp_num(1)};
        c.fooling = ZFOOL_TS | ZFOOL_BADSEQ;
        c.desync_repeats = 8;
        c.fake_type = ZFakeType::TLS;
        c.wf_tcp = "80,443,12";
        chains.push_back(c);
    }

    // Chain 8: UDP Unknown — UDP 12 (for any-protocol bypass)
    // --new --filter-udp=12 --ipset=ipset-all.txt
    // --dpi-desync=fake --dpi-desync-repeats=10
    // --dpi-desync-any-protocol --dpi-desync-fake-unknown-udp
    // --dpi-desync-cutoff=n4
    {
        ZapretChain c;
        c.name = "UDP Unknown";
        c.proto = ZProto::UDP;
        c.ports = {{12, 12}};
        c.ipset = "ipset-all.txt";
        c.phase1 = ZDesyncPhase1::FAKE;
        c.desync_repeats = 10;
        c.any_protocol = true;
        c.fake_type = ZFakeType::UNKNOWN_UDP;
        c.cutoff = {ZCondType::N, 4};
        chains.push_back(c);
    }

    // Chain 9: YouTube QUIC Aggressive — UDP 443
    // Optimized for YouTube with fakedsplit and higher repeats
    // --new --filter-udp=443 --hostlist=list-youtube.txt
    // --dpi-desync=fake --dpi-desync-repeats=14
    // --dpi-desync-fake-quic --dpi-desync-cutoff=n6
    // --dpi-desync-fooling=badsum,datanoack
    {
        ZapretChain c;
        c.name = "YouTube QUIC";
        c.proto = ZProto::UDP;
        c.ports = {{443, 443}};
        c.hostlist = "list-youtube.txt";
        c.phase1 = ZDesyncPhase1::FAKE;
        c.desync_repeats = 14;
        c.fake_type = ZFakeType::QUIC;
        c.fooling = ZFOOL_BADSUM | ZFOOL_DATANOACK;
        c.cutoff = {ZCondType::N, 6};
        c.wf_udp = "443";
        chains.push_back(c);
    }

    // Chain 10: YouTube TLS — TCP 443
    // --new --filter-tcp=443 --hostlist=list-youtube.txt
    // --dpi-desync=fake,fakedsplit --dpi-desync-split-pos=sniext
    // --dpi-desync-split-seqovl=681 --dpi-desync-fooling=ts,badseq,md5sig
    // --dpi-desync-repeats=10 --dpi-desync-autottl=1-4
    // --dpi-desync-fakedsplit-altorder
    {
        ZapretChain c;
        c.name = "YouTube TLS";
        c.proto = ZProto::TCP;
        c.ports = {{443, 443}};
        c.hostlist = "list-youtube.txt";
        c.phase1 = ZDesyncPhase1::FAKE;
        c.phase2 = ZDesyncPhase2::FAKEDSPLIT;
        c.split_positions = {sp_marker(ZSplitPosType::SNIEXT)};
        c.split_seqovl = 681;
        c.fooling = ZFOOL_TS | ZFOOL_BADSEQ | ZFOOL_MD5SIG;
        c.desync_repeats = 10;
        c.orig_ttl.auto_ttl = true;
        c.orig_ttl.auto_ttl_min = 1;
        c.orig_ttl.auto_ttl_max = 4;
        c.fakedsplit_altorder = true;
        c.fake_type = ZFakeType::TLS;
        c.fake_tls_mod = ZFakeTlsMod::RNDSNI;
        c.wf_tcp = "443";
        chains.push_back(c);
    }

    // Chain 11: RuBlock TLS — TCP 80,443 with advanced desync for heavily blocked sites
    // --new --filter-tcp=80,443 --hostlist=list-rublock.txt
    // --dpi-desync=syndata,fake,multidisorder
    // --dpi-desync-split-pos=1,midsld --dpi-desync-split-seqovl=664
    // --dpi-desync-fooling=ts,badseq,md5sig,datanoack
    // --dpi-desync-repeats=12 --dpi-desync-ttl=6
    // --dpi-desync-fake-tls-mod=rndsni
    {
        ZapretChain c;
        c.name = "RuBlock TLS";
        c.proto = ZProto::TCP;
        c.ports = {{80, 80}, {443, 443}};
        c.hostlist = "list-rublock.txt";
        c.phase0 = ZDesyncPhase0::SYNDATA;
        c.phase1 = ZDesyncPhase1::FAKE;
        c.phase2 = ZDesyncPhase2::MULTIDISORDER;
        c.split_positions = {sp_num(1), sp_marker(ZSplitPosType::MIDSLD)};
        c.split_seqovl = 664;
        c.fooling = ZFOOL_TS | ZFOOL_BADSEQ | ZFOOL_MD5SIG | ZFOOL_DATANOACK;
        c.desync_repeats = 12;
        c.orig_ttl.ttl = 6;
        c.fake_type = ZFakeType::TLS;
        c.fake_tls_mod = ZFakeTlsMod::RNDSNI;
        c.wf_tcp = "80,443";
        chains.push_back(c);
    }

    // Chain 12: Hostfakesplit General — TCP 443
    // Uses hostfakesplit mode for TSPU-specific bypass
    // --new --filter-tcp=443 --hostlist=list-general.txt
    // --dpi-desync=fake,hostfakesplit --dpi-desync-split-pos=host
    // --dpi-desync-fooling=ts,badseq --dpi-desync-repeats=6
    // --dpi-desync-hostfakesplit-midhost=2
    {
        ZapretChain c;
        c.name = "Hostfakesplit General";
        c.proto = ZProto::TCP;
        c.ports = {{443, 443}};
        c.hostlist = "list-general.txt";
        c.phase1 = ZDesyncPhase1::FAKE;
        c.phase2 = ZDesyncPhase2::HOSTFAKESPLIT;
        c.split_positions = {sp_marker(ZSplitPosType::HOST)};
        c.fooling = ZFOOL_TS | ZFOOL_BADSEQ;
        c.desync_repeats = 6;
        c.hostfakesplit_midhost = 2;
        c.fake_type = ZFakeType::TLS;
        c.wf_tcp = "443";
        chains.push_back(c);
    }

    // Chain 13: WireGuard UDP — UDP 51820
    // --new --filter-udp=51820 --filter-l7=wireguard
    // --dpi-desync=fake --dpi-desync-repeats=8
    // --dpi-desync-fake-wireguard --dpi-desync-cutoff=n3
    {
        ZapretChain c;
        c.name = "WireGuard UDP";
        c.proto = ZProto::UDP;
        c.ports = {{51820, 51820}};
        c.l7_filter = ZL7_WIREGUARD;
        c.phase1 = ZDesyncPhase1::FAKE;
        c.desync_repeats = 8;
        c.fake_type = ZFakeType::WIREGUARD;
        c.cutoff = {ZCondType::N, 3};
        chains.push_back(c);
    }

    return chains;
}

} // anonymous namespace


// ═══════════════════════════════════════════════════════════════════════════════
// Profile management
// ═══════════════════════════════════════════════════════════════════════════════

ZapretProfile get_zapret_profile(ZapretProfileId id) {
    auto all = build_all_chains();
    ZapretProfile p;

    switch (id) {
    case ZapretProfileId::ZAPRET_FULL:
        p.id = "zapret_full";
        p.label = "Zapret Full";
        p.description = "All 13 chains: QUIC, Discord, Google, General, ipset, YouTube, RuBlock, WireGuard";
        p.chains = all;
        break;

    case ZapretProfileId::ZAPRET_GENERAL:
        p.id = "zapret_general";
        p.label = "Zapret General";
        p.description = "General hostlist TCP + TCP ipset (chains 5+7)";
        p.chains = {all[4], all[6]};
        break;

    case ZapretProfileId::ZAPRET_DISCORD:
        p.id = "zapret_discord";
        p.label = "Zapret Discord";
        p.description = "Discord STUN + Discord Media (chains 2+3)";
        p.chains = {all[1], all[2]};
        break;

    case ZapretProfileId::ZAPRET_GOOGLE:
        p.id = "zapret_google";
        p.label = "Zapret Google";
        p.description = "Google TLS with ip-id=zero (chain 4)";
        p.chains = {all[3]};
        break;

    case ZapretProfileId::ZAPRET_QUIC_ONLY:
        p.id = "zapret_quic";
        p.label = "Zapret QUIC";
        p.description = "QUIC general + QUIC ipset-all + YouTube QUIC (chains 1+6+9)";
        p.chains = {all[0], all[5], all[8]};
        break;

    case ZapretProfileId::ZAPRET_TCP_ONLY:
        p.id = "zapret_tcp";
        p.label = "Zapret TCP";
        p.description = "Discord Media + Google + General + TCP ipset + Hostfakesplit (chains 3-5,7,12)";
        p.chains = {all[2], all[3], all[4], all[6], all[11]};
        break;

    case ZapretProfileId::ZAPRET_YOUTUBE:
        p.id = "zapret_youtube";
        p.label = "Zapret YouTube";
        p.description = "YouTube QUIC + YouTube TLS + Google TLS (chains 9+10+4)";
        p.chains = {all[8], all[9], all[3]};
        break;

    case ZapretProfileId::ZAPRET_RUBLOCK:
        p.id = "zapret_rublock";
        p.label = "Zapret RuBlock";
        p.description = "RuBlock TLS + General + Hostfakesplit + QUIC (chains 11+5+12+1)";
        p.chains = {all[10], all[4], all[11], all[0]};
        break;

    case ZapretProfileId::ZAPRET_CUSTOM:
    case ZapretProfileId::NONE:
    default:
        p.id = "zapret_none";
        p.label = "None";
        p.description = "Zapret chains disabled";
        break;
    }

    return p;
}

ZapretProfile get_zapret_profile_by_name(const std::string& name) {
    auto lower = to_lower(name);
    if (lower == "zapret_full"    || lower == "full"    || lower == "all")     return get_zapret_profile(ZapretProfileId::ZAPRET_FULL);
    if (lower == "zapret_general" || lower == "general")                       return get_zapret_profile(ZapretProfileId::ZAPRET_GENERAL);
    if (lower == "zapret_discord" || lower == "discord")                       return get_zapret_profile(ZapretProfileId::ZAPRET_DISCORD);
    if (lower == "zapret_google"  || lower == "google")                        return get_zapret_profile(ZapretProfileId::ZAPRET_GOOGLE);
    if (lower == "zapret_quic"    || lower == "quic")                          return get_zapret_profile(ZapretProfileId::ZAPRET_QUIC_ONLY);
    if (lower == "zapret_tcp"     || lower == "tcp")                           return get_zapret_profile(ZapretProfileId::ZAPRET_TCP_ONLY);
    if (lower == "zapret_youtube" || lower == "youtube")                       return get_zapret_profile(ZapretProfileId::ZAPRET_YOUTUBE);
    if (lower == "zapret_rublock" || lower == "rublock")                       return get_zapret_profile(ZapretProfileId::ZAPRET_RUBLOCK);
    return get_zapret_profile(ZapretProfileId::NONE);
}

std::vector<std::string> list_zapret_profiles() {
    return {"zapret_full", "zapret_general", "zapret_discord",
            "zapret_google", "zapret_quic", "zapret_tcp",
            "zapret_youtube", "zapret_rublock"};
}


// ═══════════════════════════════════════════════════════════════════════════════
// Packet matching
// ═══════════════════════════════════════════════════════════════════════════════

namespace {

// R12-M01: Check if SNI matches a hostlist pattern (supports wildcard *.domain.com)
bool match_hostname(const std::string& sni, const std::string& pattern) {
    if (pattern.empty()) return true;  // Empty pattern matches everything
    if (sni.empty()) return false;
    
    std::string sni_lower = to_lower(sni);
    std::string pattern_lower = to_lower(pattern);
    
    // Exact match
    if (sni_lower == pattern_lower) return true;
    
    // Wildcard match: *.example.com matches foo.example.com but not example.com
    if (pattern_lower.size() > 2 && pattern_lower[0] == '*' && pattern_lower[1] == '.') {
        std::string suffix = pattern_lower.substr(1);  // ".example.com"
        if (sni_lower.size() > suffix.size() &&
            sni_lower.compare(sni_lower.size() - suffix.size(), std::string::npos, suffix) == 0) {
            return true;
        }
    }
    
    return false;
}

// R12-M01: Load hostlist from file (one hostname per line)
std::vector<std::string> load_hostlist(const std::string& filepath) {
    std::vector<std::string> hosts;
    if (filepath.empty()) return hosts;
    
    // TODO(R13): Implement file loading for hostlist
    // For now, hostlist is expected to be pre-loaded into ZapretChain
    return hosts;
}

} // anonymous namespace

bool chain_matches_packet(const ZapretChain& chain, ZProto proto, uint16_t dst_port,
                          const std::string& sni) {
    // R12-M01: Check protocol
    if (chain.proto != proto) return false;
    
    // R12-M01: Check port range
    bool port_match = false;
    for (const auto& range : chain.ports) {
        if (dst_port >= range.first && dst_port <= range.second) {
            port_match = true;
            break;
        }
    }
    if (!port_match) return false;
    
    // R12-M01: Check SNI against host_domain (exact match)
    if (!chain.host_domain.empty() && !sni.empty()) {
        if (!match_hostname(sni, chain.host_domain)) {
            return false;
        }
    }
    
    // R12-M01: Check SNI against hostlist patterns (wildcard support)
    // Note: hostlist is expected to be pre-parsed into a vector of patterns
    // TODO(R13): Add hostlist_patterns field to ZapretChain for efficiency
    if (!chain.hostlist.empty() && !sni.empty()) {
        // For now, treat hostlist as a single pattern or comma-separated list
        std::istringstream ss(chain.hostlist);
        std::string pattern;
        bool hostlist_match = false;
        while (std::getline(ss, pattern, ',')) {
            // Trim whitespace
            size_t start = pattern.find_first_not_of(" \t\r\n");
            size_t end = pattern.find_last_not_of(" \t\r\n");
            if (start != std::string::npos && end != std::string::npos) {
                pattern = pattern.substr(start, end - start + 1);
            }
            if (match_hostname(sni, pattern)) {
                hostlist_match = true;
                break;
            }
        }
        if (!hostlist_match) {
            return false;
        }
    }
    
    // R12-M01: Check hostlist_exclude (negative match)
    if (!chain.hostlist_exclude.empty() && !sni.empty()) {
        std::istringstream ss(chain.hostlist_exclude);
        std::string pattern;
        while (std::getline(ss, pattern, ',')) {
            size_t start = pattern.find_first_not_of(" \t\r\n");
            size_t end = pattern.find_last_not_of(" \t\r\n");
            if (start != std::string::npos && end != std::string::npos) {
                pattern = pattern.substr(start, end - start + 1);
            }
            if (match_hostname(sni, pattern)) {
                // Excluded host matches — reject this chain
                return false;
            }
        }
    }
    
    return true;
}


// ═══════════════════════════════════════════════════════════════════════════════
// DPI override mapping
// ═══════════════════════════════════════════════════════════════════════════════

ZapretDPIOverrides chain_to_overrides(const ZapretChain& chain) {
    ZapretDPIOverrides ov;

    // Phase 0
    ov.synack  = (chain.phase0 == ZDesyncPhase0::SYNACK);
    ov.syndata = (chain.phase0 == ZDesyncPhase0::SYNDATA);

    // Phase 1 -> enable_fake
    ov.enable_fake = (chain.phase1 != ZDesyncPhase1::NONE);
    ov.fake_repeats = chain.desync_repeats;

    // Phase 2
    switch (chain.phase2) {
    case ZDesyncPhase2::MULTISPLIT:
        ov.enable_multi_split = true;
        break;
    case ZDesyncPhase2::MULTIDISORDER:
        ov.enable_disorder = true;
        ov.enable_multi_split = true;
        break;
    case ZDesyncPhase2::FAKEDSPLIT:
        ov.enable_fakedsplit = true;
        break;
    case ZDesyncPhase2::FAKEDDISORDER:
        ov.enable_fakeddisorder = true;
        break;
    case ZDesyncPhase2::HOSTFAKESPLIT:
        ov.enable_hostfakesplit = true;
        break;
    case ZDesyncPhase2::TAMPER:
        ov.enable_tamper = true;
        break;
    default:
        break;
    }

    // Split position (use first numeric position)
    if (!chain.split_positions.empty()) {
        const auto& sp = chain.split_positions[0];
        if (sp.type == ZSplitPosType::NUMERIC && sp.offset > 0) {
            ov.split_position = sp.offset;
        } else {
            ov.split_position = 1; // named markers default to 1 for the override
        }
    } else {
        ov.split_position = 1;
    }

    ov.seqovl = chain.split_seqovl;

    // Fake type mapping
    switch (chain.fake_type) {
    case ZFakeType::QUIC:        ov.use_quic_fake = true; break;
    case ZFakeType::HTTP:        ov.use_http_fake = true; break;
    case ZFakeType::WIREGUARD:   ov.use_wireguard_fake = true; break;
    case ZFakeType::DISCORD:     ov.use_discord_fake = true; break;
    case ZFakeType::STUN:        ov.use_stun_fake = true; break;
    case ZFakeType::UNKNOWN:
    case ZFakeType::UNKNOWN_UDP: ov.use_unknown_fake = true; break;
    default: break;
    }

    // IP-ID
    ov.ip_id_mode = chain.ipid_mode;

    // TTL
    ov.ttl = chain.orig_ttl.ttl;
    ov.auto_ttl = chain.orig_ttl.auto_ttl;
    ov.auto_ttl_min = chain.orig_ttl.auto_ttl_min;
    ov.auto_ttl_max = chain.orig_ttl.auto_ttl_max;

    // TCP flags
    ov.tcp_flags = chain.orig_tcp_flags;

    // Dup
    ov.dup_count = chain.dup.count;
    ov.dup_replace = chain.dup.replace;

    // UDP len
    ov.udplen_increment = chain.udplen_increment;

    // Window size
    ov.wssize = chain.wssize.value;

    // Fooling flags mapping -> DPIConfig fake_fooling bitfield
    // DPIConfig mapping: 1=badsum, 2=badseq, 4=md5sig, 8=datanoack, 16=hopbyhop
    if (chain.fooling & ZFOOL_TS)        ov.fake_fooling |= 2;  // ts -> badseq equivalent
    if (chain.fooling & ZFOOL_BADSEQ)    ov.fake_fooling |= 2;
    if (chain.fooling & ZFOOL_BADSUM)    ov.fake_fooling |= 1;
    if (chain.fooling & ZFOOL_MD5SIG)    ov.fake_fooling |= 4;
    if (chain.fooling & ZFOOL_DATANOACK) ov.fake_fooling |= 8;
    if (chain.fooling & ZFOOL_HOPBYHOP)  ov.fake_fooling |= 16;
    if (chain.fooling & ZFOOL_HOPBYHOP2) ov.fake_fooling |= 16;

    return ov;
}

} // namespace DPI
} // namespace ncp
