// ══════════════════════════════════════════════════════════════════════════════
// ncp_turn_client.cpp
//
// G5: REAL TURN-over-UDP client (RFC 5766 / RFC 5769 / RFC 5389), native C++17.
// UDP only — no TCP/TLS fallback. Long-term credentials are supplied
// independently by the caller; they are never derived from HopSecret / E2E /
// mask material.
// ══════════════════════════════════════════════════════════════════════════════

#include "ncp_turn_client.hpp"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <thread>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#ifdef _WIN32
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <winsock2.h>
#  include <ws2tcpip.h>
using ncp_socket_t = SOCKET;
static constexpr ncp_socket_t kInvalidSocket = INVALID_SOCKET;
#else
#  include <arpa/inet.h>
#  include <netdb.h>
#  include <netinet/in.h>
#  include <sys/select.h>
#  include <sys/socket.h>
#  include <unistd.h>
using ncp_socket_t = int;
static constexpr ncp_socket_t kInvalidSocket = -1;
#endif

namespace ncp {
namespace turn {

namespace {

// ── CRC32 (ISO 3309 / ITU-T V.42) for FINGERPRINT ────────────────────────────

const uint32_t* crc32_table() {
    static uint32_t table[256];
    static bool init = false;
    if (!init) {
        for (uint32_t i = 0; i < 256; ++i) {
            uint32_t c = i;
            for (int k = 0; k < 8; ++k)
                c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
            table[i] = c;
        }
        init = true;
    }
    return table;
}

void put_u16(std::vector<uint8_t>& v, uint16_t x) {
    v.push_back(static_cast<uint8_t>(x >> 8));
    v.push_back(static_cast<uint8_t>(x & 0xFF));
}
void put_u32(std::vector<uint8_t>& v, uint32_t x) {
    v.push_back(static_cast<uint8_t>(x >> 24));
    v.push_back(static_cast<uint8_t>((x >> 16) & 0xFF));
    v.push_back(static_cast<uint8_t>((x >> 8) & 0xFF));
    v.push_back(static_cast<uint8_t>(x & 0xFF));
}
uint16_t get_u16(const uint8_t* p) {
    return static_cast<uint16_t>((p[0] << 8) | p[1]);
}
uint32_t get_u32(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 24) |
           (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8)  |
           (static_cast<uint32_t>(p[3]));
}

void pad4(std::vector<uint8_t>& v, size_t value_len) {
    size_t pad = (4 - (value_len % 4)) % 4;
    for (size_t i = 0; i < pad; ++i) v.push_back(0);
}

// HMAC-SHA1 one-shot via OpenSSL.
bool hmac_sha1(const uint8_t* key, size_t key_len,
               const uint8_t* data, size_t data_len,
               uint8_t out[20]) {
    unsigned int out_len = 0;
    const unsigned char* r = HMAC(EVP_sha1(),
                                  key, static_cast<int>(key_len),
                                  data, data_len,
                                  out, &out_len);
    return r != nullptr && out_len == 20;
}

// Constant-time compare.
bool ct_equal(const uint8_t* a, const uint8_t* b, size_t n) {
    uint8_t d = 0;
    for (size_t i = 0; i < n; ++i) d |= static_cast<uint8_t>(a[i] ^ b[i]);
    return d == 0;
}

} // anonymous namespace

uint32_t stun_crc32(const uint8_t* data, size_t len) {
    const uint32_t* t = crc32_table();
    uint32_t c = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; ++i)
        c = t[(c ^ data[i]) & 0xFF] ^ (c >> 8);
    return c ^ 0xFFFFFFFFu;
}

std::array<uint8_t, 16> long_term_key(const std::string& username,
                                      const std::string& realm,
                                      const std::string& password) {
    // key = MD5(username ":" realm ":" SASLprep(password)); SASLprep is the
    // caller's responsibility here (documented in the header).
    std::array<uint8_t, 16> out{};
    std::string src = username + ":" + realm + ":" + password;

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return out;
    unsigned int dlen = 0;
    if (EVP_DigestInit_ex(ctx, EVP_md5(), nullptr) == 1 &&
        EVP_DigestUpdate(ctx, src.data(), src.size()) == 1 &&
        EVP_DigestFinal_ex(ctx, out.data(), &dlen) == 1 && dlen == 16) {
        // ok
    } else {
        out.fill(0);
    }
    EVP_MD_CTX_free(ctx);
    return out;
}

const StunAttribute* StunMessage::find(uint16_t type) const {
    for (const auto& a : attributes)
        if (a.type == type) return &a;
    return nullptr;
}

std::string StunMessage::find_string(uint16_t type) const {
    const StunAttribute* a = find(type);
    if (!a) return {};
    return std::string(reinterpret_cast<const char*>(a->value.data()),
                       a->value.size());
}

// ── Encoding ─────────────────────────────────────────────────────────────────

static uint16_t encode_msg_type(uint16_t method, StunClass cls) {
    // RFC 5389 §6: method bits M11..M0 interleaved around class bits C0/C1.
    uint16_t type = static_cast<uint16_t>((method & 0x000F) |
                    ((method & 0x0070) << 1) |
                    ((method & 0x0F80) << 2));
    uint8_t c = static_cast<uint8_t>(cls);
    type |= static_cast<uint16_t>(((c & 0x1) << 4) | ((c & 0x2) << 7));
    return type;
}

static bool decode_msg_type(uint16_t type, uint16_t& method, StunClass& cls) {
    method = static_cast<uint16_t>((type & 0x000F) |
             ((type & 0x00E0) >> 1) |
             ((type & 0x3E00) >> 2));
    uint8_t c = static_cast<uint8_t>(((type >> 4) & 0x1) | ((type >> 7) & 0x2));
    if (c > 3) return false;
    cls = static_cast<StunClass>(c);
    return true;
}

std::vector<uint8_t> stun_encode(const StunMessage& msg,
                                 const uint8_t* mi_key, size_t mi_key_len,
                                 bool add_fingerprint) {
    std::vector<uint8_t> out;
    out.reserve(20 + 256);

    // Placeholder header; length patched as attributes are appended.
    put_u16(out, encode_msg_type(msg.method, msg.cls));
    put_u16(out, 0);
    put_u32(out, kStunMagicCookie);
    out.insert(out.end(), msg.txn_id.begin(), msg.txn_id.end());

    size_t attrs_len = 0;
    for (const auto& a : msg.attributes) {
        put_u16(out, a.type);
        put_u16(out, static_cast<uint16_t>(a.value.size()));
        out.insert(out.end(), a.value.begin(), a.value.end());
        pad4(out, a.value.size());
        attrs_len += 4 + ((a.value.size() + 3) & ~size_t(3));
    }

    if (mi_key && mi_key_len > 0) {
        // MESSAGE-INTEGRITY (RFC 5389 §15.4): the HMAC input is the message up
        // to and including the attribute PRECEDING MESSAGE-INTEGRITY (i.e. the
        // MI attribute header itself is excluded), with the length field
        // adjusted to cover the 24-byte MI attribute (but not FINGERPRINT).
        uint16_t len_with_mi = static_cast<uint16_t>(attrs_len + 24);
        out[2] = static_cast<uint8_t>(len_with_mi >> 8);
        out[3] = static_cast<uint8_t>(len_with_mi & 0xFF);
        uint8_t mac[20];
        if (!hmac_sha1(mi_key, mi_key_len, out.data(), out.size(), mac)) {
            return {};
        }
        put_u16(out, kAttrMessageIntegrity);
        put_u16(out, 20);
        out.insert(out.end(), mac, mac + 20);
        attrs_len += 24;
    } else {
        out[2] = static_cast<uint8_t>(attrs_len >> 8);
        out[3] = static_cast<uint8_t>(attrs_len & 0xFF);
    }

    if (add_fingerprint) {
        uint16_t len_with_fp = static_cast<uint16_t>(attrs_len + 8);
        out[2] = static_cast<uint8_t>(len_with_fp >> 8);
        out[3] = static_cast<uint8_t>(len_with_fp & 0xFF);
        uint32_t crc = stun_crc32(out.data(), out.size()) ^ 0x5354554Eu;
        put_u16(out, kAttrFingerprint);
        put_u16(out, 4);
        put_u32(out, crc);
    }
    return out;
}

bool stun_decode(const uint8_t* data, size_t len,
                 StunMessage& out, std::string& err) {
    if (!data || len < kStunHeaderSize) {
        err = "STUN message shorter than 20-byte header";
        return false;
    }
    if ((data[0] & 0xC0) != 0) {
        err = "not a STUN message (top bits set)";
        return false;
    }
    uint16_t type = get_u16(data);
    uint16_t msg_len = get_u16(data + 2);
    if (get_u32(data + 4) != kStunMagicCookie) {
        err = "bad magic cookie";
        return false;
    }
    if ((msg_len % 4) != 0) {
        err = "message length not multiple of 4";
        return false;
    }
    if (len != kStunHeaderSize + msg_len) {
        err = "datagram length does not match STUN length field";
        return false;
    }
    if (!decode_msg_type(type, out.method, out.cls)) {
        err = "bad message class bits";
        return false;
    }
    std::copy(data + 8, data + 20, out.txn_id.begin());
    out.raw.assign(data, data + len);
    out.attributes.clear();
    out.has_message_integrity = false;
    out.has_fingerprint = false;
    out.integrity_attr_offset = 0;

    size_t off = kStunHeaderSize;
    const size_t end = kStunHeaderSize + msg_len;
    while (off < end) {
        if (end - off < 4) {
            err = "truncated attribute header";
            return false;
        }
        uint16_t atype = get_u16(data + off);
        uint16_t alen = get_u16(data + off + 2);
        size_t padded = (static_cast<size_t>(alen) + 3) & ~size_t(3);
        if (off + 4 + padded > end) {
            err = "attribute overruns message";
            return false;
        }
        if (atype == kAttrMessageIntegrity) {
            out.has_message_integrity = (alen == 20);
            out.integrity_attr_offset = off;
        } else if (atype == kAttrFingerprint) {
            out.has_fingerprint = (alen == 4);
            // FINGERPRINT must be the final attribute (RFC 5389 §15.5).
            if (off + 4 + padded != end) {
                err = "FINGERPRINT not the last attribute";
                return false;
            }
        }
        StunAttribute a;
        a.type = atype;
        a.value.assign(data + off + 4, data + off + 4 + alen);
        out.attributes.push_back(std::move(a));
        off += 4 + padded;
    }
    return true;
}

bool stun_verify_integrity(const StunMessage& msg,
                           const uint8_t* key, size_t key_len) {
    if (!msg.has_message_integrity || msg.raw.empty() || !key || key_len == 0)
        return false;
    const size_t mi_off = msg.integrity_attr_offset;
    if (mi_off < kStunHeaderSize || mi_off + 24 > msg.raw.size())
        return false;
    // Reconstruct the message exactly as HMAC'd by the sender (RFC 5389
    // §15.4): header with the length field adjusted to cover attributes up to
    // and including the 24-byte MI attribute, followed by the attributes
    // PRECEDING MESSAGE-INTEGRITY (MI's own attribute header is excluded).
    std::vector<uint8_t> buf(msg.raw.begin(), msg.raw.begin() + mi_off);
    uint16_t mi_len = static_cast<uint16_t>((mi_off - kStunHeaderSize) + 24);
    buf[2] = static_cast<uint8_t>(mi_len >> 8);
    buf[3] = static_cast<uint8_t>(mi_len & 0xFF);
    uint8_t mac[20];
    if (!hmac_sha1(key, key_len, buf.data(), buf.size(), mac))
        return false;
    const uint8_t* got = msg.raw.data() + mi_off + 4;
    return ct_equal(mac, got, 20);
}

bool stun_verify_fingerprint(const StunMessage& msg) {
    if (!msg.has_fingerprint || msg.raw.size() < 8) return false;
    // Decode guarantees FINGERPRINT is last; its header starts at size-8.
    const size_t fp_off = msg.raw.size() - 8;
    if (get_u16(msg.raw.data() + fp_off) != kAttrFingerprint) return false;
    uint32_t expect = get_u32(msg.raw.data() + fp_off + 4);
    uint32_t actual = stun_crc32(msg.raw.data(), fp_off) ^ 0x5354554Eu;
    return expect == actual;
}

// ── ChannelData framing (RFC 5766 §11.4) ─────────────────────────────────────

bool is_channel_data(const uint8_t* data, size_t len) {
    // STUN messages start with two zero bits; ChannelData starts with 01.
    return len >= 1 && (data[0] & 0xC0) == 0x40;
}

std::vector<uint8_t> channel_data_encode(uint16_t channel,
                                         const uint8_t* payload, size_t len) {
    if (channel < kChannelNumberMin || channel > kChannelNumberMax ||
        len > 0xFFFF || (!payload && len != 0)) {
        return {};
    }
    std::vector<uint8_t> out;
    out.reserve(kChannelDataHeaderSize + len + 3);
    put_u16(out, channel);
    put_u16(out, static_cast<uint16_t>(len));
    if (payload && len) out.insert(out.end(), payload, payload + len);
    // Padding to a multiple of 4 is optional over UDP but legal; include it
    // for uniformity with TCP framing rules (RFC 5766 §11.4).
    pad4(out, len);
    return out;
}

bool channel_data_decode(const uint8_t* data, size_t len,
                         uint16_t& channel_out,
                         const uint8_t*& payload_out, size_t& payload_len_out) {
    if (!data || len < kChannelDataHeaderSize) return false;
    if ((data[0] & 0xC0) != 0x40) return false;
    channel_out = get_u16(data);
    if (channel_out < kChannelNumberMin || channel_out > kChannelNumberMax)
        return false;
    uint16_t plen = get_u16(data + 2);
    if (kChannelDataHeaderSize + plen > len) return false;  // truncated
    payload_out = data + kChannelDataHeaderSize;
    payload_len_out = plen;
    return true;  // trailing bytes beyond plen are padding (ignored)
}

// ── XOR-address helpers ──────────────────────────────────────────────────────

std::vector<uint8_t> encode_xor_address_ipv4(uint32_t addr_be, uint16_t port,
                                             const std::array<uint8_t, 12>& /*txn_id*/) {
    std::vector<uint8_t> v;
    v.reserve(8);
    v.push_back(0);
    v.push_back(0x01);  // IPv4 family
    uint16_t xport = static_cast<uint16_t>(port ^ (kStunMagicCookie >> 16));
    // XOR the address (host-order integer) with the cookie, store big-endian.
    uint32_t xaddr = ntohl(addr_be) ^ kStunMagicCookie;
    put_u16(v, xport);
    put_u32(v, xaddr);
    return v;
}

bool decode_xor_address_ipv4(const StunAttribute& attr,
                             const std::array<uint8_t, 12>& /*txn_id*/,
                             uint32_t& addr_be_out, uint16_t& port_out) {
    if (attr.value.size() < 8 || attr.value[1] != 0x01) return false;
    uint16_t xport = get_u16(attr.value.data() + 2);
    uint32_t xaddr = get_u32(attr.value.data() + 4);
    port_out = static_cast<uint16_t>(xport ^ (kStunMagicCookie >> 16));
    addr_be_out = htonl(xaddr ^ kStunMagicCookie);
    return true;
}

// ── TurnClient ───────────────────────────────────────────────────────────────

TurnClient::TurnClient(TurnConfig cfg) : cfg_(std::move(cfg)) {}

TurnClient::~TurnClient() {
    close();
}

void TurnClient::set_failed(const std::string& err) {
    last_error_ = err;
    state_ = TurnState::Failed;
}

bool TurnClient::parse_ipv4(const std::string& ip, uint32_t& addr_be) {
    in_addr a{};
    if (inet_pton(AF_INET, ip.c_str(), &a) != 1) return false;
    addr_be = a.s_addr;  // already network byte order
    return true;
}

std::array<uint8_t, 12> TurnClient::make_txn_id() {
    std::array<uint8_t, 12> id{};
    if (RAND_bytes(id.data(), static_cast<int>(id.size())) != 1) {
        // Fallback: xorshift from time + local state (never silently reuse ids).
        if (rng_state_ == 0) {
            rng_state_ = static_cast<uint64_t>(
                std::chrono::high_resolution_clock::now()
                    .time_since_epoch().count()) | 1u;
        }
        uint64_t x = rng_state_;
        for (size_t i = 0; i < id.size(); i += 8) {
            x ^= x << 13; x ^= x >> 7; x ^= x << 17;
            for (size_t k = 0; k < 8 && i + k < id.size(); ++k)
                id[i + k] = static_cast<uint8_t>(x >> (8 * k));
        }
        rng_state_ = x;
    }
    return id;
}

bool TurnClient::open(std::string* err) {
    if (sock_ != kInvalidSocket) return true;

#ifdef _WIN32
    WSADATA wsa{};
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        if (err) *err = "WSAStartup failed";
        return false;
    }
#endif

    // Resolve server address (IPv4 only for this UDP client).
    in_addr server{};
    if (inet_pton(AF_INET, cfg_.server_address.c_str(), &server) == 1) {
        server_addr_be_ = server.s_addr;
    } else {
        addrinfo hints{};
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_DGRAM;
        addrinfo* res = nullptr;
        if (getaddrinfo(cfg_.server_address.c_str(), nullptr, &hints, &res) != 0 || !res) {
            if (err) *err = "cannot resolve TURN server: " + cfg_.server_address;
            return false;
        }
        server_addr_be_ = reinterpret_cast<sockaddr_in*>(res->ai_addr)->sin_addr.s_addr;
        freeaddrinfo(res);
    }
    server_port_ = cfg_.server_port;

    sock_ = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock_ == kInvalidSocket) {
        if (err) *err = "socket() failed";
        return false;
    }
    // UDP only by construction: SOCK_DGRAM/IPPROTO_UDP. No TCP/TLS fallback.
    return true;
}

void TurnClient::close() {
    if (sock_ != kInvalidSocket) {
        // Best-effort: delete the allocation if one is active.
        if (state_ == TurnState::Allocated || state_ == TurnState::Bound) {
            std::string ignored;
            refresh(0, &ignored);
        }
#ifdef _WIN32
        closesocket(sock_);
#else
        ::close(sock_);
#endif
        sock_ = kInvalidSocket;
    }
    if (state_ != TurnState::Failed) state_ = TurnState::Closed;
    channel_bound_ = false;
    relayed_addr_be_ = 0;
    relayed_port_ = 0;
    granted_lifetime_ = 0;
    have_key_ = false;
    key_.fill(0);
}

bool TurnClient::ensure_open(std::string& err) {
    if (sock_ == kInvalidSocket) {
        err = "socket not open (call open())";
        return false;
    }
    return true;
}

bool TurnClient::ensure_allocated(std::string& err) {
    if (!ensure_open(err)) return false;
    if (state_ != TurnState::Allocated && state_ != TurnState::Bound) {
        err = "no active allocation";
        return false;
    }
    return true;
}

uint32_t TurnClient::lifetime_remaining() const {
    if (granted_lifetime_ == 0) return 0;
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::steady_clock::now() - lifetime_granted_at_).count();
    if (elapsed < 0 || static_cast<uint32_t>(elapsed) >= granted_lifetime_) return 0;
    return granted_lifetime_ - static_cast<uint32_t>(elapsed);
}

bool TurnClient::apply_auth_attributes(StunMessage& req) {
    if (!have_key_) return false;
    req.attributes.push_back({kAttrUsername,
        {cfg_.username.begin(), cfg_.username.end()}});
    req.attributes.push_back({kAttrRealm, {realm_.begin(), realm_.end()}});
    req.attributes.push_back({kAttrNonce, {nonce_.begin(), nonce_.end()}});
    return true;
}

bool TurnClient::parse_error_code(const StunMessage& msg, uint32_t& code_out) const {
    const StunAttribute* a = msg.find(kAttrErrorCode);
    if (!a || a->value.size() < 4) return false;
    uint8_t cls = static_cast<uint8_t>(a->value[2] & 0x07);
    uint8_t num = a->value[3];
    code_out = static_cast<uint32_t>(cls) * 100 + num;
    return true;
}

bool TurnClient::send_request(StunMessage& req, std::string& err) {
    std::vector<uint8_t> bytes = stun_encode(
        req, have_key_ ? key_.data() : nullptr,
        have_key_ ? key_.size() : 0, /*add_fingerprint=*/true);
    if (bytes.empty()) {
        err = "failed to encode STUN request";
        return false;
    }
    sockaddr_in dst{};
    dst.sin_family = AF_INET;
    dst.sin_port = htons(server_port_);
    dst.sin_addr.s_addr = server_addr_be_;
    int n = ::sendto(sock_,
                     reinterpret_cast<const char*>(bytes.data()),
                     static_cast<int>(bytes.size()), 0,
                     reinterpret_cast<sockaddr*>(&dst), sizeof(dst));
    if (n != static_cast<int>(bytes.size())) {
        err = "sendto() failed";
        return false;
    }
    return true;
}

void TurnClient::enqueue_received(TurnReceivedData&& rx) {
    if (pending_rx_.size() >= cfg_.max_pending_rx) {
        ++stats_.pending_rx_dropped_queue_full;
        return;
    }
    pending_rx_.push_back(std::move(rx));
}

bool TurnClient::handle_datagram(const uint8_t* data, size_t len,
                                 const std::array<uint8_t, 12>* awaited_txn,
                                 StunMessage& resp, bool& matched) {
    matched = false;

    // ChannelData: 4-byte framing, first two bits 01.
    if (is_channel_data(data, len)) {
        uint16_t channel = 0;
        const uint8_t* payload = nullptr;
        size_t payload_len = 0;
        if (!channel_data_decode(data, len, channel, payload, payload_len))
            return true;  // malformed ChannelData: drop silently
        if (channel_bound_ && channel == channel_number_) {
            TurnReceivedData rx;
            rx.via_channel = true;
            rx.channel = channel;
            rx.payload.assign(payload, payload + payload_len);
            enqueue_received(std::move(rx));
            stats_.channel_data_rx++;
        }
        // ChannelData for unknown channels: drop silently (RFC 5766 §11.4).
        return true;
    }

    StunMessage msg;
    std::string derr;
    if (!stun_decode(data, len, msg, derr))
        return true;  // malformed STUN: drop silently

    // Data indication from a permitted peer (bootstrap path).
    if (msg.cls == StunClass::Indication) {
        if (msg.method == kMethodData) {
            const StunAttribute* peer = msg.find(kAttrXorPeerAddress);
            const StunAttribute* payload = msg.find(kAttrData);
            if (peer && payload) {
                TurnReceivedData rx;
                rx.via_channel = false;
                if (decode_xor_address_ipv4(*peer, msg.txn_id,
                                            rx.peer_addr_be, rx.peer_port)) {
                    rx.payload = payload->value;
                    enqueue_received(std::move(rx));
                    stats_.data_indication_rx++;
                }
            }
        }
        return true;  // other indications are not expected; ignore
    }

    // Responses: match by transaction id.
    if (awaited_txn && msg.txn_id == *awaited_txn) {
        resp = std::move(msg);
        matched = true;
        return true;
    }
    if (recent_txn_ids_.count(msg.txn_id)) {
        // Re-delivered response to an already-completed transaction (UDP
        // duplicate / replay): drop silently (RFC 5389 §7.3.1 guidance).
        stats_.replayed_txn_dropped++;
    } else {
        stats_.unknown_txn_dropped++;
    }
    return true;
}

bool TurnClient::wait_response(const std::array<uint8_t, 12>& txn_id,
                               int timeout_ms, StunMessage& resp,
                               bool& got_response, std::string& err) {
    got_response = false;
    auto deadline = std::chrono::steady_clock::now() +
                    std::chrono::milliseconds(timeout_ms);

    for (;;) {
        auto now = std::chrono::steady_clock::now();
        if (now >= deadline) return true;  // window expired, no response
        int remaining_ms = static_cast<int>(
            std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count());
        if (remaining_ms < 1) remaining_ms = 1;

        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(sock_, &rfds);
        timeval tv{};
        tv.tv_sec = remaining_ms / 1000;
        tv.tv_usec = (remaining_ms % 1000) * 1000;
        int r = ::select(static_cast<int>(sock_) + 1, &rfds, nullptr, nullptr, &tv);
        if (r < 0) {
            err = "select() failed";
            return false;
        }
        if (r == 0) return true;  // timeout

        uint8_t buf[2048];
        sockaddr_in from{};
#ifdef _WIN32
        int fromlen = sizeof(from);
#else
        socklen_t fromlen = sizeof(from);
#endif
        int n = ::recvfrom(sock_, reinterpret_cast<char*>(buf), sizeof(buf), 0,
                           reinterpret_cast<sockaddr*>(&from), &fromlen);
        if (n <= 0) continue;
        // Only accept datagrams from the configured TURN server endpoint.
        if (from.sin_addr.s_addr != server_addr_be_ ||
            ntohs(from.sin_port) != server_port_) {
            continue;
        }
        bool matched = false;
        if (!handle_datagram(buf, static_cast<size_t>(n), &txn_id, resp, matched)) {
            err = "datagram handling error";
            return false;
        }
        if (matched) {
            got_response = true;
            return true;
        }
    }
}

bool TurnClient::transact(StunMessage& req, StunMessage& resp,
                          bool allow_auth_retry, std::string& err) {
    if (!ensure_open(err)) return false;

    int auth_retries = 0;
    for (;;) {
        // (Re)build auth attributes on every attempt: nonce may have changed.
        if (have_key_) {
            // Strip any stale auth attrs from a previous attempt.
            auto& a = req.attributes;
            a.erase(std::remove_if(a.begin(), a.end(), [](const StunAttribute& x) {
                return x.type == kAttrUsername || x.type == kAttrRealm ||
                       x.type == kAttrNonce;
            }), a.end());
            apply_auth_attributes(req);
        }
        req.txn_id = make_txn_id();

        bool got = false;
        for (int attempt = 0; attempt < cfg_.max_retransmits; ++attempt) {
            if (attempt > 0) stats_.retransmits++;
            if (!send_request(req, err)) return false;

            // RFC 5389 §7.2.1: wait RTO after the first send, doubling after
            // each retransmission; cap the interval at Rm*RTO. After the
            // final send, wait only 1.6*RTO before declaring failure.
            int64_t wait_ms;
            if (attempt == cfg_.max_retransmits - 1) {
                wait_ms = (cfg_.rto_ms * 16) / 10;
            } else {
                int64_t w = static_cast<int64_t>(cfg_.rto_ms) << attempt;
                int64_t cap = static_cast<int64_t>(cfg_.rto_ms) * cfg_.rto_cap_multiplier;
                wait_ms = (w > cap) ? cap : w;
            }

            StunMessage r;
            if (!wait_response(req.txn_id, static_cast<int>(wait_ms), r, got, err))
                return false;
            if (got) {
                resp = std::move(r);
                break;
            }
        }

        if (!got) {
            stats_.timeouts++;
            err = "transaction timed out after " +
                  std::to_string(cfg_.max_retransmits) + " transmissions";
            return false;
        }

        // Register the completed transaction id in the replay window.
        recent_txn_ids_.insert(resp.txn_id);
        recent_txn_order_.push_back(resp.txn_id);
        if (recent_txn_order_.size() > kRecentTxnWindow) {
            recent_txn_ids_.erase(recent_txn_order_.front());
            recent_txn_order_.pop_front();
        }

        // Response method must match the request method.
        if (resp.method != req.method) {
            err = "response method mismatch";
            return false;
        }

        if (resp.cls == StunClass::ErrorResponse) {
            uint32_t code = 0;
            parse_error_code(resp, code);
            if ((code == kErrorUnauthorized || code == kErrorStaleNonce) &&
                allow_auth_retry && auth_retries < 2) {
                // RFC 5389 §10 / RFC 5766 §3: acquire realm+nonce (401) or
                // refresh a stale nonce (438), then retry with credentials.
                const StunAttribute* realm_a = resp.find(kAttrRealm);
                const StunAttribute* nonce_a = resp.find(kAttrNonce);
                if (!nonce_a) {
                    err = "401/438 without NONCE attribute";
                    return false;
                }
                if (realm_a)
                    realm_ = std::string(reinterpret_cast<const char*>(
                        realm_a->value.data()), realm_a->value.size());
                nonce_ = std::string(reinterpret_cast<const char*>(
                    nonce_a->value.data()), nonce_a->value.size());
                if (code == kErrorUnauthorized || !have_key_) {
                    key_ = long_term_key(cfg_.username, realm_, cfg_.password);
                }
                have_key_ = true;
                ++auth_retries;
                continue;  // retry with MESSAGE-INTEGRITY
            }
            err = "TURN error response code " + std::to_string(code);
            return false;
        }

        if (resp.cls != StunClass::SuccessResponse) {
            err = "unexpected response class";
            return false;
        }

        // Success responses to authenticated requests carry MESSAGE-INTEGRITY;
        // verify when present (or require when we hold a key and the server
        // included the attribute — absence is tolerated for interop with
        // servers that omit it on success).
        if (have_key_ && resp.has_message_integrity) {
            if (!stun_verify_integrity(resp, key_.data(), key_.size())) {
                stats_.bad_integrity_dropped++;
                err = "MESSAGE-INTEGRITY verification failed on response";
                return false;
            }
        }
        if (resp.has_fingerprint && !stun_verify_fingerprint(resp)) {
            err = "FINGERPRINT verification failed on response";
            return false;
        }
        return true;
    }
}

bool TurnClient::allocate(std::string* err) {
    std::string local_err;
    std::string& e = err ? *err : local_err;
    if (!ensure_open(e)) return false;
    if (cfg_.username.empty() || cfg_.password.empty()) {
        e = "username/password must be supplied (independent credentials)";
        return false;
    }

    state_ = TurnState::Allocating;

    StunMessage req;
    req.method = kMethodAllocate;
    req.cls = StunClass::Request;
    // REQUESTED-TRANSPORT: UDP (17) in the top byte (RFC 5766 §6.1).
    req.attributes.push_back({kAttrRequestedTransport,
        {17, 0, 0, 0}});

    StunMessage resp;
    if (!transact(req, resp, /*allow_auth_retry=*/true, e)) {
        set_failed(e);
        return false;
    }

    const StunAttribute* relayed = resp.find(kAttrXorRelayedAddress);
    if (!relayed || !decode_xor_address_ipv4(*relayed, resp.txn_id,
                                             relayed_addr_be_, relayed_port_)) {
        e = "Allocate success without valid XOR-RELAYED-ADDRESS";
        set_failed(e);
        return false;
    }
    const StunAttribute* lifetime = resp.find(kAttrLifetime);
    granted_lifetime_ = lifetime && lifetime->value.size() == 4
        ? get_u32(lifetime->value.data())
        : cfg_.requested_lifetime;
    lifetime_granted_at_ = std::chrono::steady_clock::now();

    state_ = TurnState::Allocated;
    return true;
}

bool TurnClient::create_permission(uint32_t peer_addr_be, uint16_t peer_port,
                                   std::string* err) {
    std::string local_err;
    std::string& e = err ? *err : local_err;
    if (!ensure_allocated(e)) return false;

    StunMessage req;
    req.method = kMethodCreatePermission;
    req.cls = StunClass::Request;
    // Transaction id is only used for the XOR mask; it is fixed in
    // transact() after encoding, so encode with a zero id here is wrong —
    // XOR-PEER-ADDRESS for IPv4 uses only the magic cookie (port) and cookie
    // (address), NOT the transaction id (RFC 5389 §15.2: IPv4 XOR uses the
    // cookie alone). Safe to encode before the txn id is known.
    req.attributes.push_back({kAttrXorPeerAddress,
        encode_xor_address_ipv4(peer_addr_be, peer_port, {})});

    StunMessage resp;
    if (!transact(req, resp, /*allow_auth_retry=*/true, e)) return false;
    return true;
}

bool TurnClient::create_permission(const std::string& peer_ip, uint16_t peer_port,
                                   std::string* err) {
    uint32_t a = 0;
    if (!parse_ipv4(peer_ip, a)) {
        if (err) *err = "bad peer IPv4 address: " + peer_ip;
        return false;
    }
    return create_permission(a, peer_port, err);
}

bool TurnClient::channel_bind(uint32_t peer_addr_be, uint16_t peer_port,
                              uint16_t channel, std::string* err) {
    std::string local_err;
    std::string& e = err ? *err : local_err;
    if (!ensure_allocated(e)) return false;

    uint16_t ch = channel;
    if (ch == 0) ch = cfg_.requested_channel;
    if (ch == 0) ch = kChannelNumberMin + 1;  // auto-pick
    if (ch < kChannelNumberMin || ch > kChannelNumberMax) {
        e = "channel number out of range 0x4000-0x7FFF";
        return false;
    }

    StunMessage req;
    req.method = kMethodChannelBind;
    req.cls = StunClass::Request;
    // CHANNEL-NUMBER: 2-byte channel + 2-byte RFFU (RFC 5766 §11.2).
    req.attributes.push_back({kAttrChannelNumber,
        {static_cast<uint8_t>(ch >> 8), static_cast<uint8_t>(ch & 0xFF), 0, 0}});
    req.attributes.push_back({kAttrXorPeerAddress,
        encode_xor_address_ipv4(peer_addr_be, peer_port, {})});

    StunMessage resp;
    if (!transact(req, resp, /*allow_auth_retry=*/true, e)) return false;

    channel_bound_ = true;
    channel_number_ = ch;
    peer_addr_be_ = peer_addr_be;
    peer_port_ = peer_port;
    state_ = TurnState::Bound;
    return true;
}

bool TurnClient::channel_bind(const std::string& peer_ip, uint16_t peer_port,
                              uint16_t channel, std::string* err) {
    uint32_t a = 0;
    if (!parse_ipv4(peer_ip, a)) {
        if (err) *err = "bad peer IPv4 address: " + peer_ip;
        return false;
    }
    return channel_bind(a, peer_port, channel, err);
}

bool TurnClient::refresh(uint32_t lifetime, std::string* err) {
    std::string local_err;
    std::string& e = err ? *err : local_err;
    if (!ensure_open(e)) return false;
    if (state_ != TurnState::Allocated && state_ != TurnState::Bound) {
        e = "no active allocation to refresh";
        return false;
    }

    StunMessage req;
    req.method = kMethodRefresh;
    req.cls = StunClass::Request;
    std::vector<uint8_t> lt;
    put_u32(lt, lifetime);
    req.attributes.push_back({kAttrLifetime, std::move(lt)});

    StunMessage resp;
    if (!transact(req, resp, /*allow_auth_retry=*/true, e)) return false;

    if (lifetime == 0) {
        // Allocation deleted (RFC 5766 §7: zero-lifetime refresh).
        granted_lifetime_ = 0;
        channel_bound_ = false;
        state_ = TurnState::Closed;
        return true;
    }
    const StunAttribute* lt_resp = resp.find(kAttrLifetime);
    granted_lifetime_ = lt_resp && lt_resp->value.size() == 4
        ? get_u32(lt_resp->value.data())
        : lifetime;
    lifetime_granted_at_ = std::chrono::steady_clock::now();
    return true;
}

bool TurnClient::send_indication(uint32_t peer_addr_be, uint16_t peer_port,
                                 const uint8_t* data, size_t len,
                                 std::string* err) {
    std::string local_err;
    std::string& e = err ? *err : local_err;
    if (!ensure_allocated(e)) return false;
    if (channel_bound_) {
        e = "Send indication is bootstrap-only; use ChannelData after ChannelBind";
        return false;
    }
    if (!data && len != 0) {
        e = "null Send indication payload with nonzero length";
        return false;
    }
    if (len > 0xFFFF) {
        e = "Send indication payload exceeds 65535 bytes";
        return false;
    }

    StunMessage ind;
    ind.method = kMethodSend;
    ind.cls = StunClass::Indication;
    ind.txn_id = make_txn_id();
    ind.attributes.push_back({kAttrXorPeerAddress,
        encode_xor_address_ipv4(peer_addr_be, peer_port, {})});
    ind.attributes.push_back({kAttrData,
        std::vector<uint8_t>(data, data + len)});

    // Indications are never authenticated (RFC 5389 §4.1/§10: no response
    // exists to challenge); encode without MESSAGE-INTEGRITY.
    std::vector<uint8_t> bytes = stun_encode(ind, nullptr, 0, true);
    sockaddr_in dst{};
    dst.sin_family = AF_INET;
    dst.sin_port = htons(server_port_);
    dst.sin_addr.s_addr = server_addr_be_;
    int n = ::sendto(sock_, reinterpret_cast<const char*>(bytes.data()),
                     static_cast<int>(bytes.size()), 0,
                     reinterpret_cast<sockaddr*>(&dst), sizeof(dst));
    if (n != static_cast<int>(bytes.size())) {
        e = "sendto(Send indication) failed";
        return false;
    }
    return true;
}

bool TurnClient::send_indication(const std::string& peer_ip, uint16_t peer_port,
                                 const uint8_t* data, size_t len,
                                 std::string* err) {
    uint32_t a = 0;
    if (!parse_ipv4(peer_ip, a)) {
        if (err) *err = "bad peer IPv4 address: " + peer_ip;
        return false;
    }
    return send_indication(a, peer_port, data, len, err);
}

bool TurnClient::send_channel_data(const uint8_t* data, size_t len,
                                   std::string* err) {
    std::string local_err;
    std::string& e = err ? *err : local_err;
    if (!ensure_open(e)) return false;
    if (!channel_bound_) {
        e = "no channel bound (call channel_bind first)";
        return false;
    }
    if (!data && len != 0) {
        e = "null ChannelData payload with nonzero length";
        return false;
    }
    if (len > 0xFFFF) {
        e = "ChannelData payload exceeds 65535 bytes";
        return false;
    }
    std::vector<uint8_t> bytes = channel_data_encode(channel_number_, data, len);
    sockaddr_in dst{};
    dst.sin_family = AF_INET;
    dst.sin_port = htons(server_port_);
    dst.sin_addr.s_addr = server_addr_be_;
    int n = ::sendto(sock_, reinterpret_cast<const char*>(bytes.data()),
                     static_cast<int>(bytes.size()), 0,
                     reinterpret_cast<sockaddr*>(&dst), sizeof(dst));
    if (n != static_cast<int>(bytes.size())) {
        e = "sendto(ChannelData) failed";
        return false;
    }
    return true;
}

bool TurnClient::poll(int timeout_ms, std::vector<TurnReceivedData>* out,
                      std::string* err) {
    std::string local_err;
    std::string& e = err ? *err : local_err;
    if (!ensure_open(e)) return false;

    const bool infinite = timeout_ms < 0;
    auto deadline = std::chrono::steady_clock::now() +
                    std::chrono::milliseconds(infinite ? 0 : timeout_ms);

    for (;;) {
        // Drain anything already queued by the transaction layer.
        if (out && !pending_rx_.empty()) {
            out->insert(out->end(),
                        std::make_move_iterator(pending_rx_.begin()),
                        std::make_move_iterator(pending_rx_.end()));
            pending_rx_.clear();
            return true;
        }

        int wait_ms = 0;
        if (infinite) {
            wait_ms = -1;
        } else {
            auto now = std::chrono::steady_clock::now();
            if (now >= deadline) return true;
            wait_ms = static_cast<int>(
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    deadline - now).count());
            if (wait_ms < 1) wait_ms = 1;
        }

        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(sock_, &rfds);
        timeval* tvp = nullptr;
        timeval tv{};
        if (wait_ms >= 0) {
            tv.tv_sec = wait_ms / 1000;
            tv.tv_usec = (wait_ms % 1000) * 1000;
            tvp = &tv;
        }
        int r = ::select(static_cast<int>(sock_) + 1, &rfds, nullptr, nullptr, tvp);
        if (r < 0) {
            e = "select() failed";
            return false;
        }
        if (r == 0) return true;  // timeout, nothing received

        uint8_t buf[2048];
        sockaddr_in from{};
#ifdef _WIN32
        int fromlen = sizeof(from);
#else
        socklen_t fromlen = sizeof(from);
#endif
        int n = ::recvfrom(sock_, reinterpret_cast<char*>(buf), sizeof(buf), 0,
                           reinterpret_cast<sockaddr*>(&from), &fromlen);
        if (n <= 0) continue;
        if (from.sin_addr.s_addr != server_addr_be_ ||
            ntohs(from.sin_port) != server_port_) {
            continue;  // not from the TURN server
        }
        // No awaited transaction: responses arriving here are unknown/replayed.
        StunMessage sink;
        bool matched = false;
        handle_datagram(buf, static_cast<size_t>(n), nullptr, sink, matched);
        // Loop back to drain pending_rx_ / wait for more until deadline.
    }
}

} // namespace turn
} // namespace ncp
