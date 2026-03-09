#pragma once
#include <string>
#include <vector>
#include <cstdint>
#include <unordered_map>

namespace ncp {
namespace DPI {

// ═══════════════════════════════════════════════════════════════════════════════
// Zapret v72.x — Full Feature Set
// ═══════════════════════════════════════════════════════════════════════════════

// ---------------------------------------------------------------------------
// Desync mode (--dpi-desync)
// Zapret uses multi-phase mode combos: <phase0>,<phase1>,<phase2>
// Phase 0 (SYN stage):  synack, syndata
// Phase 1 (first data): fake, fakeknown, rst, rstack, hopbyhop, destopt, ipfrag1
// Phase 2 (payload):    multisplit, multidisorder, fakedsplit, fakeddisorder,
//                        hostfakesplit, ipfrag2, udplen, tamper
// ---------------------------------------------------------------------------
enum class ZDesyncPhase0 : uint8_t {
    NONE      = 0,
    SYNACK    = 1,  // --dpi-desync synack          (send SYN+ACK to confuse DPI)
    SYNDATA   = 2,  // --dpi-desync syndata          (SYN with payload data)
};

enum class ZDesyncPhase1 : uint8_t {
    NONE      = 0,
    FAKE      = 1,  // --dpi-desync fake             (fake packet with wrong payload)
    FAKEKNOWN = 2,  // --dpi-desync fakeknown        (fake only for known protocols)
    RST       = 3,  // --dpi-desync rst              (RST packet)
    RSTACK    = 4,  // --dpi-desync rstack           (RST+ACK packet)
    HOPBYHOP  = 5,  // --dpi-desync hopbyhop         (IPv6 hop-by-hop options)
    DESTOPT   = 6,  // --dpi-desync destopt          (IPv6 destination options)
    IPFRAG1   = 7,  // --dpi-desync ipfrag1          (IP fragmentation phase 1)
};

enum class ZDesyncPhase2 : uint8_t {
    NONE           = 0,
    MULTISPLIT     = 1,  // --dpi-desync multisplit        (split into N segments)
    MULTIDISORDER  = 2,  // --dpi-desync multidisorder     (disorder segments)
    FAKEDSPLIT     = 3,  // --dpi-desync fakedsplit        (split with fake between)
    FAKEDDISORDER  = 4,  // --dpi-desync fakeddisorder     (disorder with fake between)
    HOSTFAKESPLIT  = 5,  // --dpi-desync hostfakesplit     (split at host boundary + fake)
    IPFRAG2        = 6,  // --dpi-desync ipfrag2           (IP fragmentation phase 2)
    UDPLEN         = 7,  // --dpi-desync udplen            (manipulate UDP length)
    TAMPER         = 8,  // --dpi-desync tamper            (modify packet in-place)
};

// ---------------------------------------------------------------------------
// Fooling method (--dpi-desync-fooling) — bitmask, comma-separated in zapret
// ---------------------------------------------------------------------------
enum ZFoolingFlags : uint16_t {
    ZFOOL_NONE       = 0,
    ZFOOL_TS         = 1 << 0,  // ts          (TCP timestamp manipulation)
    ZFOOL_BADSEQ     = 1 << 1,  // badseq      (invalid TCP sequence number)
    ZFOOL_BADSUM     = 1 << 2,  // badsum      (invalid TCP checksum)
    ZFOOL_MD5SIG     = 1 << 3,  // md5sig      (TCP MD5 signature option)
    ZFOOL_DATANOACK  = 1 << 4,  // datanoack   (send data before ACK)
    ZFOOL_HOPBYHOP   = 1 << 5,  // hopbyhop    (IPv6 hop-by-hop extension header)
    ZFOOL_HOPBYHOP2  = 1 << 6,  // hopbyhop2   (double hop-by-hop)
};

// ---------------------------------------------------------------------------
// Fake packet type (--dpi-desync-fake-*)
// ---------------------------------------------------------------------------
enum class ZFakeType : uint8_t {
    NONE         = 0,
    TLS          = 1,   // --dpi-desync-fake-tls        (fake TLS ClientHello)
    HTTP         = 2,   // --dpi-desync-fake-http        (fake HTTP request)
    QUIC         = 3,   // --dpi-desync-fake-quic        (fake QUIC Initial)
    WIREGUARD    = 4,   // --dpi-desync-fake-wireguard   (fake WireGuard handshake)
    DHT          = 5,   // --dpi-desync-fake-dht         (fake DHT packet)
    DISCORD      = 6,   // --dpi-desync-fake-discord      (fake Discord packet)
    STUN         = 7,   // --dpi-desync-fake-stun         (fake STUN binding)
    SYNDATA      = 8,   // --dpi-desync-fake-syndata      (SYN with fake data)
    UNKNOWN      = 9,   // --dpi-desync-fake-unknown      (unknown TCP protocol)
    UNKNOWN_UDP  = 10,  // --dpi-desync-fake-unknown-udp  (unknown UDP protocol)
    CUSTOM       = 11,  // --dpi-desync-fake-hex=<hex>    (custom hex payload)
};

// ---------------------------------------------------------------------------
// Fake TLS modification (--dpi-desync-fake-tls-mod)
// ---------------------------------------------------------------------------
enum class ZFakeTlsMod : uint8_t {
    NONE     = 0,
    RND      = 1,  // rnd       (randomize fake TLS payload)
    RNDSNI   = 2,  // rndsni    (random SNI in fake)
    DUPSID   = 3,  // dupsid    (duplicate session ID)
    SNI_SET  = 4,  // sni=<val> (set specific SNI in fake)
    PADENCAP = 5,  // padencap  (padding encapsulation)
};

// ---------------------------------------------------------------------------
// Split-position marker (--dpi-desync-split-pos)
// Zapret supports numeric + named markers:
//   N, method, host, endhost, sld+N, endsld, midsld, sniext
// ---------------------------------------------------------------------------
enum class ZSplitPosType : uint8_t {
    NUMERIC   = 0,  // Plain numeric offset
    METHOD    = 1,  // "method"   — at HTTP method boundary
    HOST      = 2,  // "host"     — at Host: header start
    ENDHOST   = 3,  // "endhost"  — at Host: header end
    SLD       = 4,  // "sld+N"    — at second-level domain offset
    ENDSLD    = 5,  // "endsld"   — at end of SLD
    MIDSLD    = 6,  // "midsld"   — at middle of SLD
    SNIEXT    = 7,  // "sniext"   — at TLS SNI extension boundary
};

struct ZSplitPos {
    ZSplitPosType type = ZSplitPosType::NUMERIC;
    int offset = 0;  // numeric value or offset for sld+N
};

// ---------------------------------------------------------------------------
// IP-ID mode (--dpi-desync-ipid)
// ---------------------------------------------------------------------------
enum class ZIpIdMode : uint8_t {
    DEFAULT   = 0,  // OS default
    ZERO      = 1,  // ipid=0
    SEQ       = 2,  // ipid=seq       (sequential per connection)
    SEQGROUP  = 3,  // ipid=seqgroup  (sequential per group)
    RND       = 4,  // ipid=rnd       (random)
};

// ---------------------------------------------------------------------------
// L7 protocol filter (--filter-l7)
// ---------------------------------------------------------------------------
enum ZL7Filter : uint32_t {
    ZL7_NONE      = 0,
    ZL7_TLS       = 1 << 0,
    ZL7_HTTP      = 1 << 1,
    ZL7_QUIC      = 1 << 2,
    ZL7_WIREGUARD = 1 << 3,
    ZL7_DHT       = 1 << 4,
    ZL7_DISCORD   = 1 << 5,
    ZL7_STUN      = 1 << 6,
    ZL7_UNKNOWN   = 1 << 7,
};

// ---------------------------------------------------------------------------
// L3 protocol filter (--filter-l3)
// ---------------------------------------------------------------------------
enum class ZL3Filter : uint8_t {
    ANY  = 0,
    IPV4 = 1,
    IPV6 = 2,
};

// ---------------------------------------------------------------------------
// Start/cutoff condition types
// ---------------------------------------------------------------------------
enum class ZCondType : uint8_t {
    NONE = 0,
    N    = 1,   // nN  — after N-th packet
    D    = 2,   // dN  — after N seconds
    S    = 3,   // sN  — after N bytes
};

struct ZCondition {
    ZCondType type = ZCondType::NONE;
    int value = 0;
};

// ---------------------------------------------------------------------------
// Protocol filter
// ---------------------------------------------------------------------------
enum class ZProto : uint8_t {
    TCP = 0,
    UDP = 1,
};

// ---------------------------------------------------------------------------
// Originator packet TTL system
// ---------------------------------------------------------------------------
struct ZOrigTtl {
    int ttl = 0;              // --dpi-desync-ttl (0 = disabled)
    bool auto_ttl = false;    // --dpi-desync-autottl
    int auto_ttl_min = 1;     // --dpi-desync-autottl=M-N  (min)
    int auto_ttl_max = 0;     // --dpi-desync-autottl=M-N  (max, 0=auto)
    int auto_ttl_cutoff = 0;  // --dpi-desync-fooling-autottl-cutoff
};

// ---------------------------------------------------------------------------
// Duplicate packet system (--dpi-desync-dup)
// ---------------------------------------------------------------------------
struct ZDup {
    int count = 0;            // --dpi-desync-dup=N  (0 = disabled)
    bool replace = false;     // --dpi-desync-dup-replace
    int ttl = 0;              // --dpi-desync-dup-ttl
    uint16_t fooling = 0;     // --dpi-desync-dup-fooling (ZFoolingFlags bitmask)
};

// ---------------------------------------------------------------------------
// Window size override
// ---------------------------------------------------------------------------
struct ZWsSize {
    int value = 0;            // --wssize (0 = disabled)
    int scale = -1;           // --wssize-scale (-1 = auto)
};

// ---------------------------------------------------------------------------
// A single zapret chain (one --new block in zapret args)
// Contains ALL v72.x parameters for a single desync strategy
// ---------------------------------------------------------------------------
struct ZapretChain {
    std::string name;                   // human-readable chain name

    // ─── Protocol & Port filters ───
    ZProto proto = ZProto::TCP;
    std::vector<std::pair<uint16_t, uint16_t>> ports;  // (min,max) pairs
    ZL3Filter l3_filter = ZL3Filter::ANY;              // --filter-l3
    uint32_t l7_filter = ZL7_NONE;                     // --filter-l7 (bitmask)

    // ─── Host/IP matching ───
    std::string hostlist;               // --hostlist <file>
    std::string hostlist_exclude;       // --hostlist-exclude <file>
    std::string hostlist_auto;          // --hostlist-auto <file> (auto-add blocked hosts)
    std::string ipset;                  // --ipset <file>
    std::string ipset_exclude;          // --ipset-exclude <file>
    std::string host_domain;            // exact domain match
    std::string ssid_filter;            // --ssid-filter (WiFi SSID match)

    // ─── Desync mode (3-phase) ───
    ZDesyncPhase0 phase0 = ZDesyncPhase0::NONE;
    ZDesyncPhase1 phase1 = ZDesyncPhase1::FAKE;
    ZDesyncPhase2 phase2 = ZDesyncPhase2::NONE;

    // ─── Desync general settings ───
    int desync_repeats = 1;             // --dpi-desync-repeats
    uint16_t fooling = ZFOOL_NONE;      // --dpi-desync-fooling (bitmask)
    bool any_protocol = false;          // --dpi-desync-any-protocol

    // ─── Split positions (supports multiple via multisplit) ───
    std::vector<ZSplitPos> split_positions;  // --dpi-desync-split-pos (list)
    int split_seqovl = 0;                   // --dpi-desync-split-seqovl

    // ─── Fake packet settings ───
    ZFakeType fake_type = ZFakeType::TLS;   // primary fake packet type
    ZFakeTlsMod fake_tls_mod = ZFakeTlsMod::NONE;  // --dpi-desync-fake-tls-mod
    std::string fake_tls_sni;                // for fake-tls-mod=sni=<value>
    std::string fake_custom_hex;             // for --dpi-desync-fake-hex
    int fake_offset = 0;                     // --dpi-desync-fake-offset

    // ─── TTL / originator system ───
    ZOrigTtl orig_ttl;                  // --dpi-desync-ttl / autottl
    std::string orig_tcp_flags;         // --dpi-desync-tcp-flags (e.g. "SAP")

    // ─── Duplicate system ───
    ZDup dup;

    // ─── IP-ID mode ───
    ZIpIdMode ipid_mode = ZIpIdMode::DEFAULT;  // --dpi-desync-ipid

    // ─── Fakedsplit/fakeddisorder extras ───
    bool fakedsplit_altorder = false;   // --dpi-desync-fakedsplit-altorder
    int hostfakesplit_midhost = 0;      // --dpi-desync-hostfakesplit-midhost (offset)

    // ─── UDP specific ───
    int udplen_increment = 0;           // --dpi-desync-udplen-increment
    int udplen_pattern = 0;             // --dpi-desync-udplen-pattern

    // ─── IP fragmentation ───
    int ipfrag_offset = 0;             // --dpi-desync-ipfrag-pos-tcp / udp

    // ─── Window size ───
    ZWsSize wssize;

    // ─── Start/Cutoff conditions ───
    ZCondition start;                   // --dpi-desync-start
    ZCondition cutoff;                  // --dpi-desync-cutoff

    // ─── WinFilter overrides ───
    std::string wf_tcp;                 // --wf-tcp
    std::string wf_udp;                 // --wf-udp
    std::string wf_raw;                 // --wf-raw
};

// ---------------------------------------------------------------------------
// A complete zapret profile = collection of chains
// ---------------------------------------------------------------------------
struct ZapretProfile {
    std::string id;
    std::string label;
    std::string description;
    std::vector<ZapretChain> chains;
};

// ---------------------------------------------------------------------------
// Predefined zapret profiles
// ---------------------------------------------------------------------------
enum class ZapretProfileId {
    NONE = 0,
    ZAPRET_FULL,       // All chains active
    ZAPRET_GENERAL,    // General hostlist chains
    ZAPRET_DISCORD,    // Discord-focused
    ZAPRET_GOOGLE,     // Google TLS
    ZAPRET_QUIC_ONLY,  // QUIC chains only
    ZAPRET_TCP_ONLY,   // TCP chains only
    ZAPRET_YOUTUBE,    // YouTube-optimized
    ZAPRET_RUBLOCK,    // Russia-specific blocked sites
    ZAPRET_CUSTOM      // User-defined combination
};

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

// Get a predefined profile
ZapretProfile get_zapret_profile(ZapretProfileId id);

// Get profile by string id
ZapretProfile get_zapret_profile_by_name(const std::string& name);

// List all available profile names
std::vector<std::string> list_zapret_profiles();

// R12-M01/R13-H02: Check if a packet matches a chain's filter (by proto, port, L3, SNI)
// Note: sni parameter is required — caller must extract SNI from TLS ClientHello
bool chain_matches_packet(const ZapretChain& chain, ZProto proto, uint16_t dst_port,
                          const std::string& sni);

// ---------------------------------------------------------------------------
// DPI override mapping — converts ZapretChain to our internal DPIConfig
// ---------------------------------------------------------------------------
struct ZapretDPIOverrides {
    // Phase 1
    bool enable_fake = false;
    int fake_repeats = 1;
    int fake_fooling = 0;          // maps to DPIConfig::fake_fooling bitfield

    // Phase 2
    bool enable_multi_split = false;
    bool enable_disorder = false;
    bool enable_fakedsplit = false;
    bool enable_fakeddisorder = false;
    bool enable_hostfakesplit = false;
    bool enable_tamper = false;

    // Split
    int split_position = 1;
    int seqovl = 0;

    // Fake type
    bool use_quic_fake = false;
    bool use_http_fake = false;
    bool use_wireguard_fake = false;
    bool use_discord_fake = false;
    bool use_stun_fake = false;
    bool use_unknown_fake = false;

    // TTL/IP
    ZIpIdMode ip_id_mode = ZIpIdMode::DEFAULT;
    int ttl = 0;
    bool auto_ttl = false;
    int auto_ttl_min = 1;
    int auto_ttl_max = 0;

    // Dup
    int dup_count = 0;
    bool dup_replace = false;

    // UDP
    int udplen_increment = 0;

    // Window size
    int wssize = 0;

    // TCP flags override
    std::string tcp_flags;

    // Phase 0
    bool synack = false;
    bool syndata = false;
};

ZapretDPIOverrides chain_to_overrides(const ZapretChain& chain);

// ---------------------------------------------------------------------------
// Serialization helpers (for config/CLI)
// ---------------------------------------------------------------------------
std::string desync_phase0_to_string(ZDesyncPhase0 p);
std::string desync_phase1_to_string(ZDesyncPhase1 p);
std::string desync_phase2_to_string(ZDesyncPhase2 p);
std::string fooling_flags_to_string(uint16_t flags);
std::string fake_type_to_string(ZFakeType ft);
std::string split_pos_to_string(const ZSplitPos& sp);
std::string ipid_mode_to_string(ZIpIdMode m);
std::string condition_to_string(const ZCondition& c);
std::string chain_to_cmdline(const ZapretChain& chain);

} // namespace DPI
} // namespace ncp
