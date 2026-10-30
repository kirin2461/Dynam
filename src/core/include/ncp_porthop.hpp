#pragma once

/**
 * @file ncp_porthop.hpp
 * @brief M2 — QUIC/UDP Port-Hopping transport
 *
 * Defeats UDP shaping by rotating the destination/source UDP port
 * mid-session on a schedule derived from a shared secret, without
 * breaking the logical session.
 *
 * Hop schedule:
 *   port(epoch) = base + (HMAC-SHA256(secret, epoch_u64_BE)[0..2] % range)
 * The epoch advances every `hop_interval_sec` or on demand (loss-triggered).
 *
 * Wire frame format (20-byte header):
 *   magic(2) = "PH" | ver(1) = 1 | session_id(8) | epoch(4, BE) |
 *   seq(4, BE) | flags(1) | payload...
 *
 * AWG 3.1-style hardening (optional, per-session):
 *   - Header protection (1.1): magic bytes are replaced by
 *     HKDF-SHA256(secret, "ncp-ph" || epoch_BE)[0..2), verified in
 *     constant time. The epoch field sits at a fixed offset, so the
 *     receiver re-derives the expected prefix after parsing.
 *   - Version-range randomisation (1.2): the ver byte is drawn at random
 *     from a per-installation range; the receiver accepts the whole range.
 *   - Content padding (1.3): PH_FLAG_CONTENT_PADDING appends random
 *     bytes + 1 length byte after the payload.
 *   - Hop-interval ranges (1.4): the hop interval may be a [min,max]
 *     range sampled per epoch.
 *
 * flags bits:
 *   bit0 (0x01) ACK_REQUEST — receiver should echo seq in an ACK frame
 *   bit1 (0x02) ACK         — seq field echoes the acknowledged seq
 *   bit2 (0x04) HOP_NOTIFY  — payload = next epoch u32 BE
 *   bit3 (0x08) CONTENT_PADDING — payload followed by pad bytes + len byte
 *
 * Server binds every port in [base, base+range) via SO_REUSEPORT sockets
 * (range is capped at 64 for tests) and demultiplexes by session_id.
 * The client address is learned per session from any port, so the scheme
 * is roaming-safe.
 *
 * Security notes:
 *   - HMAC-SHA256 via libsodium (crypto_auth_hmacsha256)
 *   - No exceptions cross the public API — bool/std::optional returns
 *   - Session state is protected by std::mutex
 *   - I-EPOCH-6: decode() enforces a monotonic replay fence on the header
 *     epoch (bounded window, clamped, no disable switch); HOP_NOTIFY
 *     forward jumps are capped at PortHopSession::kMaxHopNotifyForwardJump
 *     (excessive jumps reject the whole frame without state mutation);
 *     hop() saturates at UINT32_MAX instead of wrapping to 0.
 *   - I-EPOCH-6 exhaustion (G2.1): UINT32_MAX is a TERMINAL epoch. At
 *     saturation hop() is an observable no-op (returns false, counted via
 *     saturated_hop_attempts()) and performs NO timer/unacked reset, so a
 *     dead-end session cannot fake liveness by silently re-arming itself.
 *     should_hop() reports false once epoch_exhausted() is true. Recovery
 *     requires a NEW session (new session_id + handshake); the epoch is
 *     NEVER renegotiated or reset in-session.
 */

#include <cstdint>
#include <cstddef>
#include <array>
#include <chrono>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "ncp_winsock_init.hpp"
#include "ncp_header_protection.hpp"

namespace ncp {

// ===== Frame flags =====

enum PortHopFlags : uint8_t {
    PH_FLAG_NONE        = 0x00,
    PH_FLAG_ACK_REQUEST = 0x01,  // bit0: receiver must ACK this seq
    PH_FLAG_ACK         = 0x02,  // bit1: seq echoes the acknowledged seq
    PH_FLAG_HOP_NOTIFY  = 0x04,  // bit2: payload = next epoch (u32 BE)
    PH_FLAG_CONTENT_PADDING = 0x08,  // bit3: payload || pad || padlen(1)
};

// ===== Decoded frame =====

struct PortHopFrame {
    uint64_t session_id = 0;
    uint32_t epoch = 0;
    uint32_t seq = 0;
    uint8_t flags = 0;
    std::vector<uint8_t> payload;
};

// ===== Hop schedule =====

class HopSchedule {
public:
    HopSchedule(std::vector<uint8_t> secret,
                uint16_t base_port,
                uint16_t port_range,
                uint32_t interval_sec);

    /// Deterministic port for an epoch. Always in [base, base+range).
    uint16_t port_for_epoch(uint32_t epoch) const;

    uint16_t base_port() const noexcept { return base_port_; }
    uint16_t port_range() const noexcept { return port_range_; }
    uint32_t interval_sec() const noexcept { return interval_sec_; }

    /// Timer-as-range (1.4): hop interval becomes [min_s, max_s], sampled
    /// per epoch by the session. set_interval_range(m, 0) restores fixed.
    void set_interval_range(uint32_t min_sec, uint32_t max_sec);
    /// Random interval from the configured range (CSPRNG).
    uint32_t sample_interval_sec() const;

private:
    std::vector<uint8_t> secret_;
    uint16_t base_port_;
    uint16_t port_range_;
    uint32_t interval_sec_;
    uint32_t interval_max_sec_ = 0;  // 0 = fixed interval_sec_ (legacy)
};

// ===== Shared session logic (used by both client and server side) =====

class PortHopSession {
public:
    PortHopSession(uint64_t session_id, HopSchedule schedule);

    PortHopSession(const PortHopSession&) = delete;
    PortHopSession& operator=(const PortHopSession&) = delete;

    /// Encode a frame: stamps current epoch, next seq, flags.
    /// If PH_FLAG_ACK_REQUEST is set, the packet is tracked as unacked.
    std::vector<uint8_t> encode(const uint8_t* payload, size_t payload_len,
                                uint8_t flags = PH_FLAG_NONE);

    /// Validate + decode an incoming frame.
    /// Checks magic/version/session_id. Tracks ACK frames (bit1) and
    /// applies HOP_NOTIFY (bit2) epochs. Returns nullopt on any mismatch.
    ///
    /// I-EPOCH-6 replay fence (fail-closed, monotonic): ONLY a frame whose
    /// header epoch is below `min_accepted_epoch()` — the session's current
    /// epoch minus the bounded replay window (saturating at 0) — is
    /// rejected, BEFORE any ACK/HOP_NOTIFY state mutation, so a replayed
    /// old-epoch frame cannot clear ACKs or steer the epoch. Frames whose
    /// header epoch is at/above `min_accepted_epoch()` (including in-window
    /// OLDER epochs) still decode and may still process ACK bits and apply
    /// a monotonic in-window HOP_NOTIFY — the fence is a lower bound, not a
    /// full replay detector. Frames at a FUTURE epoch are accepted
    /// unchanged (the peer may hop first).
    ///
    /// HOP_NOTIFY hardening (I-EPOCH-6): the announced epoch is applied
    /// only when it advances the epoch by at most
    /// `kMaxHopNotifyForwardJump` (overflow-safe comparison). A notify that
    /// announces a larger forward jump — e.g. a forged 0xffffffff that
    /// would wrap the epoch/fence arithmetic — rejects the WHOLE frame
    /// without any state mutation (no epoch/ACK/timer change), because a
    /// legitimate peer hops one epoch at a time. A notify that does not
    /// advance the epoch is simply not applied (monotonic rule); the frame
    /// itself still decodes. Once the epoch is exhausted (UINT32_MAX) no
    /// HOP_NOTIFY can advance it — there is no u32 above UINT32_MAX — so
    /// the notify path is NOT an escape hatch from the terminal state:
    /// recovery requires a new session, never epoch renegotiation/reset.
    ///
    /// Authentication caveat: legacy "PH" frames carry NO authentication,
    /// and with header protection enabled the per-epoch prefix is only a
    /// 16-bit tag (brute-forcible, not a cryptographic MAC over the
    /// frame). The fence/jump-limit checks are therefore the primary
    /// anti-replay/anti-steering layers, not the prefix.
    std::optional<PortHopFrame> decode(const uint8_t* data, size_t len);

    /// Bounded replay window (in epochs) for the decode() epoch fence.
    /// Frames with header epoch >= current_epoch - window (saturating)
    /// are admissible; older frames are rejected. The default
    /// (kDefaultEpochReplayWindow) tolerates in-flight frames across a few
    /// hops; 0 means "current epoch or newer only" (strict mode). Values
    /// above kMaxEpochReplayWindow are CLAMPED to kMaxEpochReplayWindow, so
    /// a bogus huge window (e.g. UINT32_MAX) cannot silently disable the
    /// fence. There is no disable switch: the fence is always enforced
    /// (fail-closed).
    static constexpr uint32_t kDefaultEpochReplayWindow = 4;
    static constexpr uint32_t kMaxEpochReplayWindow = 64;
    void set_epoch_replay_window(uint32_t window_epochs);
    uint32_t epoch_replay_window() const;
    /// Observability for tests/stats: lowest header epoch decode() accepts.
    uint32_t min_accepted_epoch() const;
    /// Observability for tests/stats: number of frames decode() has
    /// rejected specifically via the epoch replay fence (below
    /// min_accepted_epoch). Distinct from malformed/session-mismatch drops.
    uint64_t epoch_fence_dropped() const;

    /// Maximum forward jump a HOP_NOTIFY may announce (I-EPOCH-6).
    ///
    /// Normative justification for the value 4:
    ///   - A legitimate peer advances its epoch exactly +1 per hop (timer-
    ///     or loss-driven) and announces each hop with its own HOP_NOTIFY,
    ///     so in-order delivery only ever requires a jump of 1.
    ///   - The bound of 4 exists solely to tolerate LOSS/COALESCING on the
    ///     notification path itself: up to four consecutive HOP_NOTIFYs may
    ///     be dropped, reordered past a later one, or coalesced by a sender
    ///     that batched several rapid hops, and the receiver still catches
    ///     up with a single frame. It deliberately does not exceed the
    ///     default replay window (kDefaultEpochReplayWindow = 4), so a
    ///     maximally-stale legitimate notify still passes the fence.
    ///   - The bound is NOT evidence for, or an allowance of, relay
    ///     multi-hop forwarding: there is no relay path in this protocol
    ///     that legitimately produces epoch jumps, so any larger jump is
    ///     treated as forged/garbage.
    ///   - The value is a protocol constant and is INTENTIONALLY NOT
    ///     configurable: enlarging it weakens the anti-steering bound that
    ///     keeps a forged 0xffffffff notify from driving the epoch (and
    ///     the replay-fence arithmetic) to the u32 wrap point, and shrinking
    ///     it to 0 would break legitimate catch-up after notification loss.
    /// A notify that jumps further than this bound rejects the whole frame
    /// without state mutation.
    static constexpr uint32_t kMaxHopNotifyForwardJump = 4;

    /// Overflow-safe epoch increment used by hop(): saturates at
    /// UINT32_MAX instead of wrapping to 0 (which would reopen the replay
    /// fence and reset monotonicity). Exposed statically so the saturation
    /// rule itself is directly testable.
    static constexpr uint32_t saturating_next_epoch(uint32_t e) noexcept {
        return e == UINT32_MAX ? e : e + 1;
    }

    /// Overflow-safe HOP_NOTIFY admission rule used by decode(): true iff
    /// `announced` advances `current` by at most kMaxHopNotifyForwardJump.
    /// The `announced > current` guard is evaluated first, so the
    /// subtraction can never wrap.
    static constexpr bool hop_notify_jump_allowed(uint32_t current,
                                                  uint32_t announced) noexcept {
        return announced > current &&
               announced - current <= kMaxHopNotifyForwardJump;
    }

    /// Session-independent frame parser: validates magic/version only.
    static std::optional<PortHopFrame> decode_raw(const uint8_t* data, size_t len);

    /// Session-independent field parser WITHOUT magic/version checks.
    /// Used when header protection is enabled: the prefix can only be
    /// verified after the epoch field has been read.
    static std::optional<PortHopFrame> parse_fields(const uint8_t* data, size_t len);

    /// Enable AWG-style header protection (1.1) and version range (1.2).
    void set_header_protection(const HeaderProtection& hp);
    bool header_protection_enabled() const;

    /// Content padding config (1.3); disabled by default.
    void set_content_padding(const ContentPaddingConfig& cfg);

    /// Hop decision: more than 3 unacked packets or epoch expired.
    /// Returns false once the epoch is exhausted (epoch_exhausted() ==
    /// true): the terminal state is reported via epoch_exhausted() instead
    /// of an ever-true hop signal that would only churn no-op hops. A
    /// caller that observes epoch_exhausted() MUST fail closed and
    /// establish a NEW session (new session_id + handshake) — the epoch is
    /// never renegotiated or reset in-session.
    bool should_hop(std::chrono::steady_clock::time_point now) const;

    /// Advance to the next epoch (resets epoch timer and unacked set).
    /// Returns true iff the epoch actually advanced.
    ///
    /// Saturation/exhaustion (I-EPOCH-6, G2.1): the epoch saturates at
    /// UINT32_MAX — it never wraps back to 0 (a wrap would reopen the
    /// replay fence and break monotonicity), and UINT32_MAX is a TERMINAL
    /// epoch. Calling hop() at the terminal epoch is an explicit,
    /// observable no-op: it returns false, increments
    /// saturated_hop_attempts(), and performs NO epoch-timer or unacked
    /// reset, so an exhausted session cannot silently fake liveness by
    /// re-arming its hop timer over and over. Recovery requires a new
    /// session; there is intentionally no in-session epoch reset API.
    bool hop();

    /// Terminal-state query (I-EPOCH-6 exhaustion): true iff the epoch has
    /// reached UINT32_MAX and can never advance again for this session.
    /// Callers should treat this as fail-closed: stop using the session
    /// for new traffic and re-establish with a fresh session_id/handshake.
    bool epoch_exhausted() const;

    /// Number of hop() calls refused at the terminal epoch (observability
    /// for operators/tests: churn at the ceiling is a liveness symptom,
    /// not a recovery mechanism).
    uint64_t saturated_hop_attempts() const;

    /// Test/audit helper: construct a session already parked at
    /// `start_epoch` (e.g. UINT32_MAX) so saturation behaviour is testable
    /// without performing 2^32 hops. The injected epoch is only a starting
    /// value — all monotonicity, fence, and exhaustion rules apply from
    /// there unchanged. NOT a reset mechanism for live sessions: it
    /// creates a fresh, independent session object (returned by pointer
    /// because PortHopSession is non-copyable/non-movable).
    static std::unique_ptr<PortHopSession>
    at_epoch_for_test(uint64_t session_id, HopSchedule schedule,
                      uint32_t start_epoch);

    uint64_t session_id() const noexcept { return session_id_; }
    uint32_t current_epoch() const;
    uint32_t next_seq() const;
    uint32_t last_ack_seq() const;
    size_t unacked_count() const;
    uint16_t current_port() const;   // schedule port for current epoch

    static constexpr size_t HEADER_SIZE = 20;  // 2+1+8+4+4+1

private:
    /// Lowest header epoch decode() accepts; saturating at 0. Caller must
    /// hold mutex_.
    uint32_t min_accepted_epoch_locked() const noexcept {
        return epoch_ > epoch_replay_window_ ? epoch_ - epoch_replay_window_
                                             : 0;
    }

    uint64_t session_id_;
    HopSchedule schedule_;
    HeaderProtection hp_;            // disabled => legacy "PH" framing
    ContentPaddingConfig padding_;   // disabled by default
    uint32_t epoch_replay_window_ = kDefaultEpochReplayWindow;  // I-EPOCH-6
    uint64_t epoch_fence_dropped_ = 0;  // frames dropped by the epoch fence
    uint32_t epoch_ = 0;
    uint32_t next_seq_ = 0;
    uint32_t last_ack_seq_ = 0;
    uint32_t cur_interval_sec_ = 0;  // sampled per epoch (timer range)
    uint64_t saturated_hop_attempts_ = 0;  // hop() calls at terminal epoch
    std::vector<uint32_t> unacked_;  // seqs sent with ACK_REQUEST, awaiting ACK
    std::chrono::steady_clock::time_point epoch_start_;
    mutable std::mutex mutex_;
};

// ===== Received frame with transport metadata =====

struct PortHopReceived {
    PortHopFrame frame;
    std::string from_ip;
    uint16_t from_port = 0;   // sender's source port
    uint16_t local_port = 0;  // which bound port received the datagram
};

// ===== Server =====
//
// Known limitation (documented, I-EPOCH-6): the server never originates
// hops — poll() has no interval/loss-driven epoch driver, so a server-side
// session's epoch advances ONLY via the peer's (bounded, monotonic)
// HOP_NOTIFY. If the client stops notifying, server and client epochs can
// drift apart within the replay window and the server's hop schedule is
// effectively client-led. This is a liveness/Scheduling limitation, not a
// fence bypass: the fence and the forward-jump bound still apply.
// Epoch exhaustion (terminal UINT32_MAX) is observable server-side via
// session_epoch_exhausted(); recovery is always a new session, never an
// in-session epoch reset.

class PortHopServer {
public:
    /// range > kMaxRange is clamped to kMaxRange (cap for tests).
    static constexpr uint16_t kMaxRange = 64;

    explicit PortHopServer(HopSchedule schedule);
    ~PortHopServer();

    PortHopServer(const PortHopServer&) = delete;
    PortHopServer& operator=(const PortHopServer&) = delete;

    /// Bind one UDP socket (SO_REUSEPORT) per port in [base, base+range).
    /// Returns false if any socket fails.
    bool bind_all();
    void close();
    bool is_bound() const;

    /// Whitelist a session_id. Datagrams from unknown sessions are dropped.
    void register_session(uint64_t session_id);
    void remove_session(uint64_t session_id);
    bool has_session(uint64_t session_id) const;

    /// Enable AWG-style header protection for all (current and future)
    /// sessions. When enabled, the fixed "PH" magic is replaced by
    /// HKDF-derived per-epoch prefixes and poll() uses the
    /// parse-then-verify path.
    void set_header_protection(const HeaderProtection& hp);
    bool header_protection_enabled() const;

    /// Content padding applied to frames sent via send_to_session().
    void set_content_padding(const ContentPaddingConfig& cfg);

    /// Non-blocking-ish receive pump: waits up to timeout_ms, drains all
    /// pending datagrams, returns frames from registered sessions.
    std::vector<PortHopReceived> poll(int timeout_ms = 0);

    /// Send a frame back to the learned client address of a session.
    bool send_to_session(uint64_t session_id,
                         const uint8_t* payload, size_t payload_len,
                         uint8_t flags = PH_FLAG_NONE);

    /// Convenience: ACK the given seq back to the session's client.
    bool send_ack(uint64_t session_id, uint32_t acked_seq);

    // Counters
    uint64_t frames_received() const;
    uint64_t frames_rejected_unknown_session() const;
    uint64_t frames_malformed() const;
    /// Frames dropped by a session's I-EPOCH-6 epoch replay fence in poll()
    /// (kept separate from frames_malformed(): these were well-formed
    /// frames for a known session, rejected only for being too old).
    uint64_t frames_rejected_epoch_fence() const;
    /// Number of frames associated with a session (0 if unknown).
    uint64_t session_frame_count(uint64_t session_id) const;

    /// I-EPOCH-6 exhaustion observability: nullopt if the session is
    /// unknown, otherwise whether the session's epoch is exhausted
    /// (terminal UINT32_MAX). An exhausted session is a dead end: remove
    /// it and require the peer to re-establish with a new session_id +
    /// handshake; never attempt in-session epoch recovery.
    std::optional<bool> session_epoch_exhausted(uint64_t session_id) const;

private:
    struct SessionState {
        PortHopSession session;
        std::array<uint8_t, 128> peer_addr{};  // opaque; holds sockaddr_storage
        uint32_t peer_addr_len = 0;
        bool peer_known = false;
        uint64_t frames = 0;
        SessionState(uint64_t sid, const HopSchedule& sched)
            : session(sid, sched) {}
        SessionState(const SessionState&) = delete;
        SessionState& operator=(const SessionState&) = delete;
    };

    HopSchedule schedule_;
    HeaderProtection hp_;            // applied to sessions + poll path
    ContentPaddingConfig padding_;   // applied to sessions
    std::vector<socket_t> sockets_;      // one socket per bound port
    std::vector<uint16_t> bound_ports_;  // parallel to sockets_
    std::unordered_map<uint64_t, SessionState> sessions_;
    mutable std::mutex mutex_;
    uint64_t rejected_unknown_ = 0;
    uint64_t malformed_ = 0;
    uint64_t epoch_fence_dropped_ = 0;  // I-EPOCH-6 fence drops in poll()
    bool bound_ = false;
};

// ===== Client =====

class PortHopClient {
public:
    PortHopClient(std::string server_ip,
                  HopSchedule schedule,
                  uint64_t session_id);
    ~PortHopClient();

    PortHopClient(const PortHopClient&) = delete;
    PortHopClient& operator=(const PortHopClient&) = delete;

    bool open();
    void close();
    bool is_open() const;

    /// Send payload to the currently scheduled server port.
    bool send(const uint8_t* payload, size_t payload_len,
              uint8_t flags = PH_FLAG_NONE);
    bool send(const std::vector<uint8_t>& payload,
              uint8_t flags = PH_FLAG_NONE);

    /// Receive replies (ACKs / server frames).
    std::vector<PortHopReceived> poll(int timeout_ms = 0);

    /// Advance epoch; next send() targets the new scheduled port. Returns
    /// false at the terminal epoch without resetting timer/unacked state.
    /// Callers MUST stop their retry loop and re-establish a new session
    /// (new session_id + handshake) instead of treating the no-op as progress.
    bool hop();

    uint16_t current_target_port() const;
    uint32_t current_epoch() const;
    uint16_t local_port() const;  // ephemeral source port
    PortHopSession& session() noexcept { return session_; }

private:
    std::string server_ip_;
    HopSchedule schedule_;
    uint64_t session_id_;
    PortHopSession session_;
    socket_t socket_ = kInvalidSocket;
    uint16_t local_port_ = 0;
};

} // namespace ncp
