// ══════════════════════════════════════════════════════════════════════════════
// tests/test_porthop.cpp
// Tests for M2 — ncp_porthop (UDP port-hopping transport)
// Uses in-process UDP loopback on 127.0.0.1, ports 45300+.
// ══════════════════════════════════════════════════════════════════════════════
#include <gtest/gtest.h>
#include "ncp_porthop.hpp"

#include <chrono>
#include <cstring>
#include <set>
#include <string>
#include <vector>

using namespace ncp;

namespace {

constexpr uint16_t kBasePort = 45300;
constexpr uint16_t kRange = 32;
constexpr uint32_t kIntervalSec = 60;
constexpr uint64_t kSessionId = 0x1122334455667788ULL;

std::vector<uint8_t> test_secret() {
    std::vector<uint8_t> s(32);
    for (size_t i = 0; i < s.size(); ++i)
        s[i] = static_cast<uint8_t>(i * 7 + 1);
    return s;
}

HopSchedule make_schedule() {
    return HopSchedule(test_secret(), kBasePort, kRange, kIntervalSec);
}

} // namespace

// ── Schedule ──────────────────────────────────────────────────────────────────

TEST(HopScheduleTest, Deterministic) {
    HopSchedule a = make_schedule();
    HopSchedule b = make_schedule();
    for (uint32_t e = 0; e < 64; ++e)
        EXPECT_EQ(a.port_for_epoch(e), b.port_for_epoch(e)) << "epoch " << e;
}

TEST(HopScheduleTest, StaysInRange) {
    HopSchedule s = make_schedule();
    for (uint32_t e = 0; e < 256; ++e) {
        uint16_t p = s.port_for_epoch(e);
        EXPECT_GE(p, kBasePort);
        EXPECT_LT(p, kBasePort + kRange);
    }
}

TEST(HopScheduleTest, DiffersAcrossEpochs) {
    HopSchedule s = make_schedule();
    std::set<uint16_t> ports;
    for (uint32_t e = 0; e < 64; ++e)
        ports.insert(s.port_for_epoch(e));
    // With a 32-port range and HMAC-derived ports, collisions happen,
    // but a single fixed port for all epochs is a broken schedule.
    EXPECT_GT(ports.size(), 1u);
}

TEST(HopScheduleTest, DiffersAcrossSecrets) {
    HopSchedule a = make_schedule();
    auto secret2 = test_secret();
    secret2[0] ^= 0xFF;
    HopSchedule b(secret2, kBasePort, kRange, kIntervalSec);
    bool any_diff = false;
    for (uint32_t e = 0; e < 64; ++e)
        if (a.port_for_epoch(e) != b.port_for_epoch(e)) any_diff = true;
    EXPECT_TRUE(any_diff);
}

// ── Frame encode/decode ───────────────────────────────────────────────────────

TEST(PortHopFrameTest, EncodeDecodeRoundtrip) {
    PortHopSession s(kSessionId, make_schedule());
    const char* msg = "hello port hopping";
    auto wire = s.encode(reinterpret_cast<const uint8_t*>(msg),
                         std::strlen(msg), PH_FLAG_ACK_REQUEST);

    ASSERT_EQ(wire.size(), PortHopSession::HEADER_SIZE + std::strlen(msg));
    EXPECT_EQ(wire[0], 'P');
    EXPECT_EQ(wire[1], 'H');
    EXPECT_EQ(wire[2], 1);

    PortHopSession peer(kSessionId, make_schedule());
    auto frame = peer.decode(wire.data(), wire.size());
    ASSERT_TRUE(frame.has_value());
    EXPECT_EQ(frame->session_id, kSessionId);
    EXPECT_EQ(frame->epoch, 0u);
    EXPECT_EQ(frame->seq, 0u);
    EXPECT_EQ(frame->flags, PH_FLAG_ACK_REQUEST);
    std::string text(frame->payload.begin(), frame->payload.end());
    EXPECT_EQ(text, msg);
}

TEST(PortHopFrameTest, SeqIncrements) {
    PortHopSession s(kSessionId, make_schedule());
    uint8_t b = 0x42;
    auto w0 = s.encode(&b, 1);
    auto w1 = s.encode(&b, 1);
    auto f0 = PortHopSession::decode_raw(w0.data(), w0.size());
    auto f1 = PortHopSession::decode_raw(w1.data(), w1.size());
    ASSERT_TRUE(f0 && f1);
    EXPECT_EQ(f0->seq, 0u);
    EXPECT_EQ(f1->seq, 1u);
}

TEST(PortHopFrameTest, RejectsBadMagicAndWrongSession) {
    PortHopSession s(kSessionId, make_schedule());
    uint8_t b = 1;
    auto wire = s.encode(&b, 1);

    auto bad_magic = wire;
    bad_magic[0] = 'X';
    EXPECT_FALSE(PortHopSession::decode_raw(bad_magic.data(), bad_magic.size()));

    PortHopSession other(kSessionId + 1, make_schedule());
    EXPECT_FALSE(other.decode(wire.data(), wire.size()));

    // Truncated frame.
    EXPECT_FALSE(PortHopSession::decode_raw(wire.data(), 5));
}

TEST(PortHopFrameTest, HopNotifyAdvancesEpoch) {
    PortHopSession a(kSessionId, make_schedule());
    PortHopSession b(kSessionId, make_schedule());
    // a hops to epoch 4 and notifies b. 4 == kMaxHopNotifyForwardJump is
    // the largest forward jump a single HOP_NOTIFY may announce (I-EPOCH-6
    // hardening); larger jumps reject the whole frame (tested below).
    for (int i = 0; i < 4; ++i) a.hop();
    uint8_t payload[4] = {0, 0, 0, 4};
    auto wire = a.encode(payload, 4, PH_FLAG_HOP_NOTIFY);
    auto frame = b.decode(wire.data(), wire.size());
    ASSERT_TRUE(frame.has_value());
    EXPECT_EQ(b.current_epoch(), 4u);
}

// ── should_hop ────────────────────────────────────────────────────────────────

TEST(PortHopSessionTest, ShouldHopOnSimulatedLoss) {
    PortHopSession s(kSessionId, make_schedule());
    auto now = std::chrono::steady_clock::now();
    EXPECT_FALSE(s.should_hop(now));

    // Simulate 4 packets sent with ACK requested and dropped (no ACK back).
    uint8_t b = 0;
    for (int i = 0; i < 4; ++i)
        s.encode(&b, 1, PH_FLAG_ACK_REQUEST);

    EXPECT_EQ(s.unacked_count(), 4u);
    EXPECT_TRUE(s.should_hop(now));  // unacked > 3
}

TEST(PortHopSessionTest, AckClearsUnacked) {
    PortHopSession sender(kSessionId, make_schedule());
    PortHopSession receiver(kSessionId, make_schedule());
    uint8_t b = 0;
    for (int i = 0; i < 4; ++i)
        sender.encode(&b, 1, PH_FLAG_ACK_REQUEST);
    EXPECT_EQ(sender.unacked_count(), 4u);

    // Receiver ACKs seq 3 (echoes in seq field).
    auto ack = receiver.encode(nullptr, 0, PH_FLAG_ACK);
    ack[15] = 0; ack[16] = 0; ack[17] = 0; ack[18] = 3;
    auto frame = sender.decode(ack.data(), ack.size());
    ASSERT_TRUE(frame.has_value());
    EXPECT_EQ(sender.unacked_count(), 0u);
    EXPECT_EQ(sender.last_ack_seq(), 3u);
    EXPECT_FALSE(sender.should_hop(std::chrono::steady_clock::now()));
}

TEST(PortHopSessionTest, ShouldHopOnIntervalExpiry) {
    HopSchedule sched(test_secret(), kBasePort, kRange, /*interval_sec=*/1);
    PortHopSession s(kSessionId, sched);
    auto now = std::chrono::steady_clock::now();
    EXPECT_FALSE(s.should_hop(now));
    EXPECT_TRUE(s.should_hop(now + std::chrono::seconds(2)));
}

TEST(PortHopSessionTest, HopResetsState) {
    PortHopSession s(kSessionId, make_schedule());
    uint8_t b = 0;
    for (int i = 0; i < 4; ++i)
        s.encode(&b, 1, PH_FLAG_ACK_REQUEST);
    s.hop();
    EXPECT_EQ(s.current_epoch(), 1u);
    EXPECT_EQ(s.unacked_count(), 0u);
    EXPECT_FALSE(s.should_hop(std::chrono::steady_clock::now()));
}

// ── I-EPOCH-6 epoch replay fence ─────────────────────────────────────────────
// decode() rejects frames whose header epoch is below
// current_epoch - epoch_replay_window (saturating at 0) before any
// ACK/HOP_NOTIFY state mutation. Current and future epochs, in-window
// reordering, and HOP_NOTIFY monotonicity are unchanged.

TEST(PortHopEpochFenceTest, OldEpochFrameOutsideWindowDropped) {
    PortHopSession sender(kSessionId, make_schedule());
    PortHopSession receiver(kSessionId, make_schedule());
    uint8_t b = 0x42;

    // Replay candidate: a frame stamped at epoch 0.
    auto old_wire = sender.encode(&b, 1);
    ASSERT_TRUE(old_wire.size() >= PortHopSession::HEADER_SIZE);

    // In-order delivery at epoch 0 is unaffected (no regression).
    ASSERT_TRUE(receiver.decode(old_wire.data(), old_wire.size()));

    // Receiver advances 5 epochs — past the default window (4).
    for (int i = 0; i < 5; ++i) receiver.hop();
    EXPECT_EQ(receiver.current_epoch(), 5u);
    EXPECT_EQ(receiver.epoch_replay_window(),
              PortHopSession::kDefaultEpochReplayWindow);
    EXPECT_EQ(receiver.min_accepted_epoch(), 1u);

    // The replayed epoch-0 frame is now dropped by the fence.
    EXPECT_FALSE(receiver.decode(old_wire.data(), old_wire.size()));
}

TEST(PortHopEpochFenceTest, WindowBoundaryFrameAcceptedOlderDropped) {
    PortHopSession sender(kSessionId, make_schedule());
    PortHopSession receiver(kSessionId, make_schedule());
    receiver.set_epoch_replay_window(2);
    uint8_t b = 0x42;

    // Sender stamps frames at epoch 1 and epoch 2.
    sender.hop();
    auto at_min = sender.encode(&b, 1);       // epoch 1
    sender.hop();
    auto inside_window = sender.encode(&b, 1);  // epoch 2

    // Receiver at epoch 3: min_accepted = 3 - 2 = 1.
    for (int i = 0; i < 3; ++i) receiver.hop();
    EXPECT_EQ(receiver.current_epoch(), 3u);
    EXPECT_EQ(receiver.min_accepted_epoch(), 1u);

    // epoch 1 == min_accepted: accepted (window is inclusive).
    auto f = receiver.decode(at_min.data(), at_min.size());
    ASSERT_TRUE(f.has_value());
    EXPECT_EQ(f->epoch, 1u);

    // epoch 2 is inside the window as well.
    f = receiver.decode(inside_window.data(), inside_window.size());
    ASSERT_TRUE(f.has_value());
    EXPECT_EQ(f->epoch, 2u);

    // A frame from epoch 0 (below min_accepted) is dropped.
    PortHopSession stale(kSessionId, make_schedule());
    auto too_old = stale.encode(&b, 1);
    EXPECT_FALSE(receiver.decode(too_old.data(), too_old.size()));
}

TEST(PortHopEpochFenceTest, InWindowReorderAcrossHopAccepted) {
    PortHopSession sender(kSessionId, make_schedule());
    PortHopSession receiver(kSessionId, make_schedule());
    receiver.set_epoch_replay_window(2);
    uint8_t b = 0x5A;

    // Sender stamps frames at epochs 2, 3, 4.
    sender.hop(); sender.hop();
    auto f2 = sender.encode(&b, 1);
    sender.hop();
    auto f3 = sender.encode(&b, 1);
    sender.hop();
    auto f4 = sender.encode(&b, 1);

    // Receiver already at epoch 4 (min_accepted 2): deliver out of order —
    // a network reorder across hops inside the window keeps working.
    for (int i = 0; i < 4; ++i) receiver.hop();
    EXPECT_EQ(receiver.min_accepted_epoch(), 2u);
    auto r4 = receiver.decode(f4.data(), f4.size());
    auto r2 = receiver.decode(f2.data(), f2.size());
    auto r3 = receiver.decode(f3.data(), f3.size());
    ASSERT_TRUE(r4.has_value());
    ASSERT_TRUE(r2.has_value());
    ASSERT_TRUE(r3.has_value());
    EXPECT_EQ(r4->epoch, 4u);
    EXPECT_EQ(r2->epoch, 2u);
    EXPECT_EQ(r3->epoch, 3u);
}

TEST(PortHopEpochFenceTest, FutureEpochAcceptedPerProtocol) {
    PortHopSession sender(kSessionId, make_schedule());
    PortHopSession receiver(kSessionId, make_schedule());
    receiver.set_epoch_replay_window(0);  // strictest fence
    uint8_t b = 0x7E;

    // Peer hopped first: frame stamped at epoch 3, receiver still at 0.
    // The fence is a lower bound only — future epochs are accepted as
    // before, and the local epoch does NOT move without HOP_NOTIFY.
    sender.hop(); sender.hop(); sender.hop();
    auto wire = sender.encode(&b, 1);
    auto frame = receiver.decode(wire.data(), wire.size());
    ASSERT_TRUE(frame.has_value());
    EXPECT_EQ(frame->epoch, 3u);
    EXPECT_EQ(receiver.current_epoch(), 0u);
}

TEST(PortHopEpochFenceTest, HopNotifyNeverRegressesEpoch) {
    PortHopSession a(kSessionId, make_schedule());
    PortHopSession b(kSessionId, make_schedule());

    // a walks b to epoch 5 with two bounded notifies (0→4, then 4→5);
    // a single 0→5 notify would exceed kMaxHopNotifyForwardJump and be
    // rejected (see HopNotifyExcessiveForwardJumpRejectedNoMutation).
    for (int i = 0; i < 4; ++i) a.hop();
    uint8_t up4[4] = {0, 0, 0, 4};
    auto wire4 = a.encode(up4, 4, PH_FLAG_HOP_NOTIFY);
    ASSERT_TRUE(b.decode(wire4.data(), wire4.size()));
    ASSERT_EQ(b.current_epoch(), 4u);
    a.hop();
    uint8_t up[4] = {0, 0, 0, 5};
    auto wire = a.encode(up, 4, PH_FLAG_HOP_NOTIFY);
    ASSERT_TRUE(b.decode(wire.data(), wire.size()));
    ASSERT_EQ(b.current_epoch(), 5u);

    // A HOP_NOTIFY from an in-window older epoch (3 >= 5-4) still decodes,
    // but must not regress the epoch (pre-existing monotonic rule).
    PortHopSession c(kSessionId, make_schedule());
    c.hop(); c.hop(); c.hop();
    uint8_t down[4] = {0, 0, 0, 3};
    auto stale_notify = c.encode(down, 4, PH_FLAG_HOP_NOTIFY);
    ASSERT_TRUE(b.decode(stale_notify.data(), stale_notify.size()));
    EXPECT_EQ(b.current_epoch(), 5u);

    // A HOP_NOTIFY replay from OUTSIDE the window is fenced entirely:
    // neither decoded nor applied.
    PortHopSession d(kSessionId, make_schedule());
    uint8_t zero[4] = {0, 0, 0, 0};
    auto fenced = d.encode(zero, 4, PH_FLAG_HOP_NOTIFY);  // epoch 0
    EXPECT_FALSE(b.decode(fenced.data(), fenced.size()));
    EXPECT_EQ(b.current_epoch(), 5u);
}

TEST(PortHopEpochFenceTest, FencedReplayCannotMutateAckState) {
    PortHopSession sender(kSessionId, make_schedule());
    PortHopSession acker(kSessionId, make_schedule());
    uint8_t b = 0;

    // Capture an old-epoch ACK frame (epoch 0) echoing seq 1.
    auto old_ack = acker.encode(nullptr, 0, PH_FLAG_ACK);
    old_ack[15] = 0; old_ack[16] = 0; old_ack[17] = 0; old_ack[18] = 1;

    // Sender advances to epoch 6 (min_accepted 2) and sends with ACK_REQUEST.
    for (int i = 0; i < 6; ++i) sender.hop();
    sender.encode(&b, 1, PH_FLAG_ACK_REQUEST);
    sender.encode(&b, 1, PH_FLAG_ACK_REQUEST);
    ASSERT_EQ(sender.unacked_count(), 2u);

    // Replaying the epoch-0 ACK is fenced BEFORE ACK processing:
    // unacked set and last_ack_seq are untouched.
    EXPECT_FALSE(sender.decode(old_ack.data(), old_ack.size()));
    EXPECT_EQ(sender.unacked_count(), 2u);
    EXPECT_EQ(sender.last_ack_seq(), 0u);

    // A current-epoch ACK still works (no regression of the ACK path).
    for (int i = 0; i < 6; ++i) acker.hop();
    auto ack = acker.encode(nullptr, 0, PH_FLAG_ACK);
    ack[15] = 0; ack[16] = 0; ack[17] = 0; ack[18] = 1;
    ASSERT_TRUE(sender.decode(ack.data(), ack.size()));
    EXPECT_EQ(sender.unacked_count(), 0u);
    EXPECT_EQ(sender.last_ack_seq(), 1u);
}

TEST(PortHopEpochFenceTest, StrictZeroWindowAcceptsOnlyCurrentAndFuture) {
    PortHopSession sender(kSessionId, make_schedule());
    PortHopSession receiver(kSessionId, make_schedule());
    receiver.set_epoch_replay_window(0);
    uint8_t b = 0x11;

    sender.hop();                       // sender epoch 1
    auto previous = sender.encode(&b, 1);
    sender.hop();                       // sender epoch 2
    auto current = sender.encode(&b, 1);

    receiver.hop(); receiver.hop();     // receiver epoch 2, min_accepted 2
    EXPECT_EQ(receiver.min_accepted_epoch(), 2u);

    // One epoch behind is already too old with window 0.
    EXPECT_FALSE(receiver.decode(previous.data(), previous.size()));
    // Current epoch still decodes.
    auto f = receiver.decode(current.data(), current.size());
    ASSERT_TRUE(f.has_value());
    EXPECT_EQ(f->epoch, 2u);
}

TEST(PortHopEpochFenceTest, HeaderProtectedOldEpochReplayDropped) {
    HeaderProtection hp(test_secret(), "ncp-ph");
    PortHopSession sender(kSessionId, make_schedule());
    PortHopSession receiver(kSessionId, make_schedule());
    sender.set_header_protection(hp);
    receiver.set_header_protection(hp);
    uint8_t b = 0x33;

    // Epoch-0 frame with a cryptographically VALID epoch-0 HP prefix.
    auto old_wire = sender.encode(&b, 1);
    ASSERT_TRUE(receiver.decode(old_wire.data(), old_wire.size()));

    // After the receiver advances past the window, the prefix still
    // verifies (HP derives it from the frame's own epoch) — the epoch
    // fence is the layer that drops the replay.
    for (int i = 0; i < 5; ++i) receiver.hop();
    EXPECT_EQ(receiver.min_accepted_epoch(), 1u);
    EXPECT_FALSE(receiver.decode(old_wire.data(), old_wire.size()));

    // Sanity: a fresh frame at the receiver's current epoch still decodes.
    for (int i = 0; i < 5; ++i) sender.hop();
    auto fresh = sender.encode(&b, 1);
    auto f = receiver.decode(fresh.data(), fresh.size());
    ASSERT_TRUE(f.has_value());
    EXPECT_EQ(f->epoch, 5u);
}

// ── I-EPOCH-6 hardening: forward-jump bound, wrap safety, window clamp ────────

TEST(PortHopEpochFenceTest, HopNotifyUint32MaxRejectedNoWrap) {
    // Regression probe: HOP_NOTIFY(0xffffffff) used to set epoch_ =
    // UINT32_MAX, after which the next hop() wrapped epoch_ to 0 and reset
    // the replay fence. The forward-jump bound must reject it with NO
    // state mutation, and hop() afterwards must behave normally.
    PortHopSession sender(kSessionId, make_schedule());
    PortHopSession receiver(kSessionId, make_schedule());

    uint8_t max_epoch[4] = {0xFF, 0xFF, 0xFF, 0xFF};
    auto wire = sender.encode(max_epoch, 4, PH_FLAG_HOP_NOTIFY);
    EXPECT_FALSE(receiver.decode(wire.data(), wire.size()));
    EXPECT_EQ(receiver.current_epoch(), 0u);
    EXPECT_EQ(receiver.min_accepted_epoch(), 0u);
    EXPECT_EQ(receiver.epoch_fence_dropped(), 0u);  // not a fence drop

    // hop() from epoch 0 must still advance normally (no wrap artifacts).
    receiver.hop();
    EXPECT_EQ(receiver.current_epoch(), 1u);
}

TEST(PortHopEpochFenceTest, HopNotifyExcessiveForwardJumpRejectedNoMutation) {
    PortHopSession acker(kSessionId, make_schedule());
    PortHopSession receiver(kSessionId, make_schedule());
    uint8_t b = 0;

    // Give the receiver mutable state: two unacked sends.
    receiver.encode(&b, 1, PH_FLAG_ACK_REQUEST);
    receiver.encode(&b, 1, PH_FLAG_ACK_REQUEST);
    ASSERT_EQ(receiver.unacked_count(), 2u);

    // Combined ACK|HOP_NOTIFY at a fence-passing epoch whose announced
    // epoch 5 exceeds the max forward jump (0→5 > 4). The WHOLE frame is
    // rejected before any mutation: no epoch change, no ACK processing.
    uint8_t five[4] = {0, 0, 0, 5};
    auto wire = acker.encode(five, 4,
        static_cast<uint8_t>(PH_FLAG_ACK | PH_FLAG_HOP_NOTIFY));
    wire[15] = 0; wire[16] = 0; wire[17] = 0; wire[18] = 1;  // ACK seq 1
    EXPECT_FALSE(receiver.decode(wire.data(), wire.size()));
    EXPECT_EQ(receiver.current_epoch(), 0u);
    EXPECT_EQ(receiver.unacked_count(), 2u);
    EXPECT_EQ(receiver.last_ack_seq(), 0u);

    // Boundary: exactly kMaxHopNotifyForwardJump (0→4) is still accepted.
    uint8_t four[4] = {0, 0, 0, 4};
    auto ok = acker.encode(four, 4, PH_FLAG_HOP_NOTIFY);
    ASSERT_TRUE(receiver.decode(ok.data(), ok.size()));
    EXPECT_EQ(receiver.current_epoch(), 4u);

    // From epoch 4: 4→9 rejected without mutation (jump 5 > 4), then the
    // boundary 4→8 accepted. (Order matters: after accepting 8, a notify
    // of 9 would be a legal +1 jump.)
    uint8_t nine[4] = {0, 0, 0, 9};
    uint8_t eight[4] = {0, 0, 0, 8};
    acker.hop(); acker.hop(); acker.hop(); acker.hop();  // header epoch 4
    auto bad = acker.encode(nine, 4, PH_FLAG_HOP_NOTIFY);
    EXPECT_FALSE(receiver.decode(bad.data(), bad.size()));
    EXPECT_EQ(receiver.current_epoch(), 4u);
    auto ok2 = acker.encode(eight, 4, PH_FLAG_HOP_NOTIFY);
    ASSERT_TRUE(receiver.decode(ok2.data(), ok2.size()));
    EXPECT_EQ(receiver.current_epoch(), 8u);
}

TEST(PortHopEpochFenceTest, HopNotifyJumpRuleOverflowSafeBoundaries) {
    using S = PortHopSession;
    EXPECT_EQ(S::kMaxHopNotifyForwardJump, 4u);
    // Exact-boundary acceptance / rejection.
    EXPECT_TRUE(S::hop_notify_jump_allowed(0u, 4u));
    EXPECT_FALSE(S::hop_notify_jump_allowed(0u, 5u));
    EXPECT_TRUE(S::hop_notify_jump_allowed(100u, 104u));
    EXPECT_FALSE(S::hop_notify_jump_allowed(100u, 105u));
    // Non-advancing announces are outside the rule (handled monotonically).
    EXPECT_FALSE(S::hop_notify_jump_allowed(5u, 5u));
    EXPECT_FALSE(S::hop_notify_jump_allowed(5u, 4u));
    // Near-wrap values: the comparison must not wrap. A +1 step at the top
    // of the range is allowed; anything larger or "forward" via wrap is not.
    EXPECT_TRUE(S::hop_notify_jump_allowed(UINT32_MAX - 1, UINT32_MAX));
    EXPECT_TRUE(S::hop_notify_jump_allowed(UINT32_MAX - 4, UINT32_MAX));
    EXPECT_FALSE(S::hop_notify_jump_allowed(UINT32_MAX - 5, UINT32_MAX));
    EXPECT_FALSE(S::hop_notify_jump_allowed(UINT32_MAX, 0u));
    EXPECT_FALSE(S::hop_notify_jump_allowed(0u, UINT32_MAX));
}

TEST(PortHopEpochFenceTest, HopSaturatesAtUint32MaxNoWrap) {
    // hop() must never wrap the epoch back to 0 (a wrap would reopen the
    // replay fence and break monotonicity). The saturating increment used
    // by hop() is directly testable at the boundary.
    EXPECT_EQ(PortHopSession::saturating_next_epoch(UINT32_MAX), UINT32_MAX);
    EXPECT_EQ(PortHopSession::saturating_next_epoch(UINT32_MAX - 1),
              UINT32_MAX);
    EXPECT_EQ(PortHopSession::saturating_next_epoch(0u), 1u);

    // Normal hop() behaviour is unchanged (still +1 with housekeeping).
    PortHopSession s(kSessionId, make_schedule());
    uint8_t b = 0;
    s.encode(&b, 1, PH_FLAG_ACK_REQUEST);
    s.hop();
    EXPECT_EQ(s.current_epoch(), 1u);
    EXPECT_EQ(s.unacked_count(), 0u);
}

TEST(PortHopEpochFenceTest, EpochReplayWindowClampedToMax) {
    PortHopSession s(kSessionId, make_schedule());
    // A bogus UINT32_MAX window must NOT disable the fence: it clamps.
    s.set_epoch_replay_window(UINT32_MAX);
    EXPECT_EQ(s.epoch_replay_window(), PortHopSession::kMaxEpochReplayWindow);

    // With the clamped window the fence still rejects old frames.
    PortHopSession sender(kSessionId, make_schedule());
    uint8_t b = 0x42;
    auto old_wire = sender.encode(&b, 1);  // epoch 0
    for (int i = 0; i < 70; ++i) s.hop();  // epoch 70, min_accepted 70-64=6
    EXPECT_EQ(s.current_epoch(), 70u);
    EXPECT_EQ(s.min_accepted_epoch(),
              70u - PortHopSession::kMaxEpochReplayWindow);
    EXPECT_FALSE(s.decode(old_wire.data(), old_wire.size()));
    EXPECT_EQ(s.epoch_fence_dropped(), 1u);

    // Strict mode (0) still means "current epoch or newer only".
    s.set_epoch_replay_window(0);
    EXPECT_EQ(s.epoch_replay_window(), 0u);
    EXPECT_EQ(s.min_accepted_epoch(), 70u);

    // Values at/below the max pass through unclamped.
    s.set_epoch_replay_window(PortHopSession::kMaxEpochReplayWindow + 100);
    EXPECT_EQ(s.epoch_replay_window(), PortHopSession::kMaxEpochReplayWindow);
    s.set_epoch_replay_window(7);
    EXPECT_EQ(s.epoch_replay_window(), 7u);
}

TEST(PortHopEpochFenceTest, CombinedAckAndHopNotifyFencedFrameNoMutation) {
    PortHopSession sender(kSessionId, make_schedule());
    PortHopSession acker(kSessionId, make_schedule());
    uint8_t b = 0;

    // Old-epoch (0) combined ACK|HOP_NOTIFY: echoes seq 1 and announces an
    // otherwise-legal in-window jump to epoch 3.
    uint8_t three[4] = {0, 0, 0, 3};
    auto old_combo = acker.encode(three, 4,
        static_cast<uint8_t>(PH_FLAG_ACK | PH_FLAG_HOP_NOTIFY));
    old_combo[15] = 0; old_combo[16] = 0; old_combo[17] = 0; old_combo[18] = 1;

    // Sender advances to epoch 6 (min_accepted 2) with two unacked sends.
    for (int i = 0; i < 6; ++i) sender.hop();
    sender.encode(&b, 1, PH_FLAG_ACK_REQUEST);
    sender.encode(&b, 1, PH_FLAG_ACK_REQUEST);
    ASSERT_EQ(sender.unacked_count(), 2u);

    // The combined replay is fenced BEFORE either bit is processed:
    // no ACK state change, no epoch steering, and it is counted as an
    // epoch-fence drop (not malformed).
    EXPECT_FALSE(sender.decode(old_combo.data(), old_combo.size()));
    EXPECT_EQ(sender.unacked_count(), 2u);
    EXPECT_EQ(sender.last_ack_seq(), 0u);
    EXPECT_EQ(sender.current_epoch(), 6u);
    EXPECT_EQ(sender.epoch_fence_dropped(), 1u);
}

// ── I-EPOCH-6 exhaustion (G2.1): UINT32_MAX is a terminal epoch ───────────────
// Saturation is reached via the at_epoch_for_test() helper (no 2^32 hop
// iteration). At the terminal epoch hop() is an observable no-op (no silent
// timer/unacked reset), should_hop() stops signalling, and recovery is
// out-of-band only: a new session (new session_id + handshake).

TEST(PortHopEpochExhaustionTest, FinalHopIntoSaturationAdvancesOnce) {
    auto s = PortHopSession::at_epoch_for_test(kSessionId, make_schedule(),
                                               UINT32_MAX - 1);
    uint8_t b = 0;
    s->encode(&b, 1, PH_FLAG_ACK_REQUEST);
    ASSERT_EQ(s->unacked_count(), 1u);
    EXPECT_FALSE(s->epoch_exhausted());

    // The last real hop advances to the terminal epoch and still performs
    // normal per-hop housekeeping (timer + unacked reset).
    EXPECT_TRUE(s->hop());
    EXPECT_EQ(s->current_epoch(), UINT32_MAX);
    EXPECT_TRUE(s->epoch_exhausted());
    EXPECT_EQ(s->unacked_count(), 0u);
    EXPECT_EQ(s->saturated_hop_attempts(), 0u);
}

TEST(PortHopEpochExhaustionTest, HopAtTerminalEpochIsObservableNoOp) {
    auto s = PortHopSession::at_epoch_for_test(kSessionId, make_schedule(),
                                               UINT32_MAX);
    ASSERT_TRUE(s->epoch_exhausted());

    // Mutable state that a legacy saturating hop() would have silently
    // reset: four unacked sends and a long-expired epoch timer.
    uint8_t b = 0;
    for (int i = 0; i < 4; ++i)
        s->encode(&b, 1, PH_FLAG_ACK_REQUEST);
    ASSERT_EQ(s->unacked_count(), 4u);

    // Terminal state supersedes every hop trigger: no loss/timer signal.
    EXPECT_FALSE(s->should_hop(std::chrono::steady_clock::now()));
    EXPECT_FALSE(s->should_hop(std::chrono::steady_clock::now() +
                               std::chrono::hours(24)));

    // hop() at the ceiling: returns false, NO timer/unacked reset, no
    // epoch movement — and every refused attempt is counted.
    for (int i = 1; i <= 3; ++i) {
        EXPECT_FALSE(s->hop());
        EXPECT_EQ(s->current_epoch(), UINT32_MAX);
        EXPECT_EQ(s->unacked_count(), 4u);  // NOT silently cleared
        EXPECT_EQ(s->saturated_hop_attempts(), static_cast<uint64_t>(i));
    }

    // The fence arithmetic does not wrap at the terminal epoch.
    EXPECT_EQ(s->min_accepted_epoch(),
              UINT32_MAX - PortHopSession::kDefaultEpochReplayWindow);
}

TEST(PortHopEpochExhaustionTest, HopNotifyIntoSaturationIsLegitimateFinalHop) {
    // Receiver parked at UINT32_MAX-2; peer at UINT32_MAX-1 announces the
    // final hop to UINT32_MAX (jump 2 <= kMaxHopNotifyForwardJump, header
    // epoch inside the replay window).
    auto receiver = PortHopSession::at_epoch_for_test(
        kSessionId, make_schedule(), UINT32_MAX - 2);
    auto sender = PortHopSession::at_epoch_for_test(
        kSessionId, make_schedule(), UINT32_MAX - 1);
    uint8_t top[4] = {0xFF, 0xFF, 0xFF, 0xFF};
    auto wire = sender->encode(top, 4, PH_FLAG_HOP_NOTIFY);

    ASSERT_TRUE(receiver->decode(wire.data(), wire.size()));
    EXPECT_EQ(receiver->current_epoch(), UINT32_MAX);
    EXPECT_TRUE(receiver->epoch_exhausted());

    // The terminal epoch is a dead end for the notify path too: nothing
    // exists above UINT32_MAX, so no notify can advance (or regress) it.
    auto replay = sender->encode(top, 4, PH_FLAG_HOP_NOTIFY);
    ASSERT_TRUE(receiver->decode(replay.data(), replay.size()));
    EXPECT_EQ(receiver->current_epoch(), UINT32_MAX);
    // hop() afterwards is the observable terminal no-op.
    EXPECT_FALSE(receiver->hop());
    EXPECT_EQ(receiver->current_epoch(), UINT32_MAX);
    EXPECT_EQ(receiver->saturated_hop_attempts(), 1u);
}

TEST(PortHopEpochExhaustionTest, NoInSessionEscapeFromTerminalEpoch) {
    auto s = PortHopSession::at_epoch_for_test(kSessionId, make_schedule(),
                                               UINT32_MAX);
    auto peer = PortHopSession::at_epoch_for_test(kSessionId, make_schedule(),
                                                  UINT32_MAX);
    uint8_t b = 0x42;

    // Ordinary data frames at the terminal epoch still decode (fail-closed
    // is the CALLER's decision via epoch_exhausted(); decode() itself
    // keeps serving in-window traffic), without moving the epoch.
    auto data = peer->encode(&b, 1);
    ASSERT_TRUE(s->decode(data.data(), data.size()));
    EXPECT_EQ(s->current_epoch(), UINT32_MAX);

    // No HOP_NOTIFY admission rule can fire at the ceiling.
    EXPECT_FALSE(PortHopSession::hop_notify_jump_allowed(UINT32_MAX, 0u));
    EXPECT_FALSE(
        PortHopSession::hop_notify_jump_allowed(UINT32_MAX, UINT32_MAX));

    // Exhaustion is sticky across decode/hop cycles: the epoch never
    // wraps, never regresses, never resets.
    for (int i = 0; i < 8; ++i) {
        ASSERT_TRUE(s->decode(data.data(), data.size()));
        EXPECT_FALSE(s->hop());
        EXPECT_EQ(s->current_epoch(), UINT32_MAX);
        EXPECT_TRUE(s->epoch_exhausted());
    }
    EXPECT_EQ(s->saturated_hop_attempts(), 8u);
}

TEST(PortHopEpochExhaustionTest, FenceStillRejectsOldFramesAtTerminalEpoch) {
    auto s = PortHopSession::at_epoch_for_test(kSessionId, make_schedule(),
                                               UINT32_MAX);
    PortHopSession stale(kSessionId, make_schedule());
    uint8_t b = 0x42;
    auto old_wire = stale.encode(&b, 1);  // epoch 0

    // min_accepted = UINT32_MAX - 4: epoch 0 is far below the fence and is
    // dropped (counted), with no wrap in the fence arithmetic.
    EXPECT_FALSE(s->decode(old_wire.data(), old_wire.size()));
    EXPECT_EQ(s->epoch_fence_dropped(), 1u);
    EXPECT_EQ(s->current_epoch(), UINT32_MAX);
}

// ── Server / client over UDP loopback ─────────────────────────────────────────

class PortHopLoopbackTest : public ::testing::Test {
protected:
    void SetUp() override {
        server_ = std::make_unique<PortHopServer>(make_schedule());
        ASSERT_TRUE(server_->bind_all());
        server_->register_session(kSessionId);

        client_ = std::make_unique<PortHopClient>("127.0.0.1", make_schedule(),
                                                  kSessionId);
        ASSERT_TRUE(client_->open());
    }
    void TearDown() override {
        client_.reset();
        server_.reset();
    }
    std::unique_ptr<PortHopServer> server_;
    std::unique_ptr<PortHopClient> client_;
};

TEST_F(PortHopLoopbackTest, BindsAllPorts) {
    EXPECT_TRUE(server_->is_bound());
    // Spot-check the schedule port is actually bound: send and receive.
    std::vector<uint8_t> payload = {1, 2, 3};
    ASSERT_TRUE(client_->send(payload));
    auto recvd = server_->poll(500);
    ASSERT_EQ(recvd.size(), 1u);
    EXPECT_EQ(recvd[0].frame.session_id, kSessionId);
    EXPECT_EQ(recvd[0].frame.payload, payload);
    EXPECT_EQ(recvd[0].local_port,
              server_->has_session(kSessionId)
                  ? HopSchedule(test_secret(), kBasePort, kRange, kIntervalSec)
                        .port_for_epoch(0)
                  : 0);
    EXPECT_EQ(recvd[0].from_ip, "127.0.0.1");
    EXPECT_EQ(recvd[0].from_port, client_->local_port());
}

TEST_F(PortHopLoopbackTest, RejectsUnknownSession) {
    const uint64_t kUnknown = 0xDEADBEEFCAFEF00DULL;
    PortHopClient stranger("127.0.0.1", make_schedule(), kUnknown);
    ASSERT_TRUE(stranger.open());
    std::vector<uint8_t> payload = {9, 9, 9};
    ASSERT_TRUE(stranger.send(payload));

    auto recvd = server_->poll(300);
    EXPECT_TRUE(recvd.empty());
    EXPECT_EQ(server_->frames_rejected_unknown_session(), 1u);
    EXPECT_EQ(server_->session_frame_count(kUnknown), 0u);
    EXPECT_FALSE(server_->has_session(kUnknown));
}

TEST_F(PortHopLoopbackTest, AckRoundtripClearsUnacked) {
    std::vector<uint8_t> payload = {7};
    ASSERT_TRUE(client_->send(payload, PH_FLAG_ACK_REQUEST));

    auto recvd = server_->poll(500);
    ASSERT_EQ(recvd.size(), 1u);
    EXPECT_EQ(recvd[0].frame.flags & PH_FLAG_ACK_REQUEST, PH_FLAG_ACK_REQUEST);
    EXPECT_EQ(client_->session().unacked_count(), 1u);

    ASSERT_TRUE(server_->send_ack(kSessionId, recvd[0].frame.seq));
    auto replies = client_->poll(500);
    ASSERT_EQ(replies.size(), 1u);
    EXPECT_EQ(replies[0].frame.flags & PH_FLAG_ACK, PH_FLAG_ACK);
    EXPECT_EQ(client_->session().unacked_count(), 0u);
    EXPECT_EQ(client_->session().last_ack_seq(), recvd[0].frame.seq);
}

TEST_F(PortHopLoopbackTest, SessionSurvivesHopAcrossPorts) {
    std::vector<uint8_t> p0 = {0xA0};
    ASSERT_TRUE(client_->send(p0));

    // Hop: epoch++ → next send targets the newly scheduled port.
    uint16_t port_before = client_->current_target_port();
    client_->hop();
    uint16_t port_after = client_->current_target_port();
    EXPECT_EQ(client_->current_epoch(), 1u);
    EXPECT_EQ(port_after, make_schedule().port_for_epoch(1));
    (void)port_before;  // ports may coincide; association must not depend on it

    std::vector<uint8_t> p1 = {0xB1};
    ASSERT_TRUE(client_->send(p1));

    // Drain both datagrams.
    std::vector<PortHopReceived> all;
    for (int i = 0; i < 4 && all.size() < 2; ++i) {
        auto batch = server_->poll(300);
        all.insert(all.end(), batch.begin(), batch.end());
    }
    ASSERT_EQ(all.size(), 2u);

    // Both frames associate with the same session despite the hop.
    EXPECT_EQ(server_->session_frame_count(kSessionId), 2u);
    std::set<uint32_t> epochs;
    std::set<uint16_t> local_ports;
    for (const auto& r : all) {
        EXPECT_EQ(r.frame.session_id, kSessionId);
        epochs.insert(r.frame.epoch);
        local_ports.insert(r.local_port);
        // Source (client) identity is stable across hops.
        EXPECT_EQ(r.from_port, client_->local_port());
    }
    EXPECT_EQ(epochs.count(0u), 1u);
    EXPECT_EQ(epochs.count(1u), 1u);
    // Every received port must be a schedule-valid port for its epoch.
    auto sched = make_schedule();
    for (const auto& r : all)
        EXPECT_EQ(r.local_port, sched.port_for_epoch(r.frame.epoch));
}

TEST_F(PortHopLoopbackTest, EpochFenceDropCountedSeparatelyFromMalformed) {
    // Walk the server-side session to epoch 5 with two bounded notifies
    // (0→4 then 4→5; a single 0→5 notify exceeds kMaxHopNotifyForwardJump).
    // Each notify is confirmed delivered before the next is sent: the two
    // datagrams arrive on different ports/sockets, and cross-socket drain
    // order is not guaranteed — processing notify(5) before notify(4)
    // would legitimately reject it as an excessive 0→5 jump.
    auto recv_n = [&](size_t want) {
        size_t got = 0;
        for (int i = 0; i < 10 && got < want; ++i)
            got += server_->poll(300).size();
        return got;
    };
    uint8_t b4[4] = {0, 0, 0, 4};
    uint8_t b5[4] = {0, 0, 0, 5};
    for (int i = 0; i < 4; ++i) client_->hop();
    ASSERT_TRUE(client_->send(std::vector<uint8_t>(b4, b4 + 4),
                              PH_FLAG_HOP_NOTIFY));
    ASSERT_EQ(recv_n(1), 1u);
    client_->hop();
    ASSERT_TRUE(client_->send(std::vector<uint8_t>(b5, b5 + 4),
                              PH_FLAG_HOP_NOTIFY));
    ASSERT_EQ(recv_n(1), 1u);

    // A stale client (same session_id, still at epoch 0) sends a frame.
    // Server session is at epoch 5, min_accepted 1: epoch 0 is fenced.
    PortHopClient stale("127.0.0.1", make_schedule(), kSessionId);
    ASSERT_TRUE(stale.open());
    std::vector<uint8_t> payload = {0xEE};
    ASSERT_TRUE(stale.send(payload));

    const uint64_t malformed_before = server_->frames_malformed();
    auto recvd = server_->poll(500);
    EXPECT_TRUE(recvd.empty());
    EXPECT_EQ(server_->frames_rejected_epoch_fence(), 1u);
    EXPECT_EQ(server_->frames_malformed(), malformed_before);  // unchanged
    EXPECT_EQ(server_->frames_received(), 2u);  // only the two notifies

    // A current-epoch frame from the live client is still delivered.
    std::vector<uint8_t> live = {0x11};
    ASSERT_TRUE(client_->send(live));
    recvd = server_->poll(500);
    ASSERT_EQ(recvd.size(), 1u);
    EXPECT_EQ(recvd[0].frame.epoch, 5u);
    EXPECT_EQ(recvd[0].frame.payload, live);
}

TEST_F(PortHopLoopbackTest, SessionEpochExhaustedQueryableFailClosed) {
    // Unknown session: nullopt (distinguishable from "not exhausted", so a
    // fail-closed caller cannot confuse the two).
    EXPECT_FALSE(server_->session_epoch_exhausted(0xDEADBEEFCAFEF00DULL)
                     .has_value());
    // Registered session at epoch 0: present and not exhausted.
    auto exhausted = server_->session_epoch_exhausted(kSessionId);
    ASSERT_TRUE(exhausted.has_value());
    EXPECT_FALSE(*exhausted);
    // Session-level terminal behaviour itself is covered by
    // PortHopEpochExhaustionTest (server-side epochs advance only via the
    // peer's bounded HOP_NOTIFY, so reaching UINT32_MAX over the wire
    // would need the same helper-based injection).
}

TEST_F(PortHopLoopbackTest, LossTriggersShouldHopThenHopRecovers) {
    // Drop 4 packets (server receives them but never ACKs).
    std::vector<uint8_t> payload = {5};
    for (int i = 0; i < 4; ++i)
        ASSERT_TRUE(client_->send(payload, PH_FLAG_ACK_REQUEST));

    // PortHopServer::poll() performs a single select() and drains only the
    // sockets ready at that instant. On loaded CI runners the loopback
    // datagrams may not all be queued when the first select() fires, so a
    // single poll can return a partial batch (observed as an instant
    // failure on ubuntu/macOS Release). Accumulate across polls with an
    // overall deadline — the assertions on the *content* stay unchanged.
    auto recv_all = [&](size_t want, std::chrono::milliseconds budget) {
        std::vector<PortHopReceived> all;
        auto deadline = std::chrono::steady_clock::now() + budget;
        while (all.size() < want && std::chrono::steady_clock::now() < deadline) {
            auto batch = server_->poll(200);
            all.insert(all.end(), batch.begin(), batch.end());
        }
        return all;
    };

    auto recvd = recv_all(4, std::chrono::milliseconds(2000));
    EXPECT_EQ(recvd.size(), 4u);
    EXPECT_EQ(client_->session().unacked_count(), 4u);
    EXPECT_TRUE(client_->session().should_hop(std::chrono::steady_clock::now()));

    // Hop and keep talking on the same session.
    client_->hop();
    ASSERT_TRUE(client_->send(payload));
    auto after = recv_all(1, std::chrono::milliseconds(2000));
    ASSERT_EQ(after.size(), 1u);
    EXPECT_EQ(after[0].frame.epoch, 1u);
    EXPECT_EQ(server_->session_frame_count(kSessionId), 5u);
}
