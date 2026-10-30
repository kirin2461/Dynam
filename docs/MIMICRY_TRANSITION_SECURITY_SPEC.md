# Mimicry Transition Security Specification (G0)

Normative specification of the security invariants for profile/mask
transitions in the mimicry stack. Each requirement carries a status that was
verified against the code on the date below — statuses are **not aspirational**:

- **[IMPL]** — implemented and covered by at least one named acceptance test.
- **[IMPL-NC]** — implemented in code, but not (yet) covered by a dedicated
  acceptance test.
- **[PARTIAL]** — implemented in a weaker form than this specification
  requires; the gap is stated explicitly.
- **[TODO]** — normative requirement with no current implementation.

Verified against (this revision):

- `src/core/include/ncp_profile_transition.hpp`,
  `src/core/src/ncp_profile_transition.cpp` (transition FSM, codec,
  `SessionProfileContext` data plane)
- `src/core/include/ncp_mimicry_session.hpp`,
  `src/core/src/ncp_mimicry_session.cpp` (session adapter, RX candidates)
- `src/core/include/ncp_porthop.hpp`,
  `src/core/src/ncp_porthop.cpp` (PortHop epoch/transport)
- `src/core/include/ncp_e2e.hpp`, `src/core/src/e2e.cpp` (crypto epoch,
  ratchet counters, verify-then-commit decrypt)
- Design background: `docs/MIMICRY_QUIC_RTC_DESIGN.md` (invariants I-V2-1..6,
  §3.4 mask variants)

---

## 1. Epochs and counters: definitions

Four independent monotonic sequences exist. No transition may reset, reuse,
or cross-bind any of them.

| Sequence | Owner | Advances on | Never advances/resets on |
|---|---|---|---|
| `crypto_epoch` (`E2ESession::get_crypto_epoch()`) | E2E layer | committed DH ratchet step / key rotation | failed or forged decrypts; mask/profile transitions |
| Ratchet chain counters (`get_sending_chain_length()`, `get_receiving_chain_length()`), nonce/tag per message | E2E layer | every AEAD message | mask/profile transitions |
| `profile_epoch` (PD data-framing epoch) | `ProfileTransitionManager` / `SessionProfileContext` | local activation of a committed profile transition (`pending_epoch = stable_epoch + 1` enforced via `STALE_EPOCH`) | retransmits, duplicates, aborts, PortHop hops |
| PortHop `epoch_` (`PortHopSession`) | PortHop transport | `hop()` (+1, saturating at `UINT32_MAX`) or `HOP_NOTIFY` with `next_epoch > epoch_` and `next_epoch - epoch_ <= kMaxHopNotifyForwardJump`; HOP_NOTIFY is NOT cryptographically authenticated (legacy framing is unauthenticated; the optional HP prefix is only a 16-bit tag) — monotonicity, the forward-jump bound, and the replay fence are the anti-steering layers | profile transitions, crypto rotation |

**I-EPOCH-1 (no reset on mask/profile transition) [IMPL].** A mask-only or
profile switch never resets the crypto session, double-ratchet state, replay
windows, message counters, TLS state, or mimicry session state. Stated
normatively in `ncp_profile_transition.hpp` (file banner) and
`ncp_mimicry_session.hpp`; enforced by construction (transition code holds no
mutator into `E2ESession` ratchet state). The session mask key
(`Impl::mask_key`, HKDF from the E2E shared secret) is likewise never re-
derived on a profile switch (design invariant I-V2-4).
*Acceptance:* `ProfileTransition.RatchetReplayAndCountersSurviveTransition`,
`UdpProfileTransition.RepeatedTransitionsMonotonicEpochs`.

**I-EPOCH-2 (crypto epoch monotonic, verify-then-commit) [IMPL].**
`crypto_epoch` is incremented ONLY when new DH root/chain material is
committed; failed/forged decrypts never advance it
(`ncp_e2e.hpp` banner on `get_crypto_epoch()`; staged skipped keys in
`e2e.cpp` are merged only after AEAD verification). Mask/profile transitions
never change it; the adapter mirrors it into the transition context
(`NcpMimicrySession::Impl::sync_crypto_epoch`) at context creation, at every
control-emitting entry point, and after every successful decrypt/rekey.
*Acceptance:* `MimicrySession.LayoutTransitionPreservesCryptoEpochAndCounterContinuity`
verifies that a layout-only transition leaves `crypto_epoch` and the E2E
session ID unchanged while sending/receiving chain counters continue to grow
through control and subsequent application data.

**I-EPOCH-3 (crypto-epoch fencing is peer-epoch-relative) [IMPL].** Inbound
`crypto_epoch` claims are fenced only against epochs previously observed
*from that peer* (`peer_bound_crypto_epoch`, `last_completed_peer_crypto_epoch`
in `ncp_profile_transition.cpp`); the local epoch never fences peer messages,
because E2E crypto epochs are permanently asymmetric between endpoints
(rotation initiator gains +2 per completed DH cycle, responder +1).
*Acceptance:* `ProfileTransition.EpochFencingRejectsStaleAndFuture`,
`.MidTransitionPeerRekeyAccepted`, `.OlderGenerationReplayRejected`,
`.EpochGapTransitionCompletes`, `.ResponderLedAfterInitiatorLedEpochGap`.

**I-EPOCH-4 (effective_counter is a crypto-stream position) [IMPL].**
`ControlMessage::effective_counter` is the sender's effective crypto packet
counter for the transition direction (sending/receiving chain length),
sampled fresh on every (re)build and upper-bound-validated against the
crypto stream on receipt (`validate_peer_claim`: for TX/BIDIRECTIONAL the
claim must not exceed the carrying packet's own crypto counter when known;
for RX_ONLY it must not exceed our TX chain length). It is NOT a transition
sequence number and is never deduped on. `SwitchEvent::effective_counter`
records the local claim at activation.
*Acceptance:* `ProfileTransition.PrepareLossRetransmitFreshCryptoCounter`.

**I-EPOCH-5 (profile_epoch is generic and independent) [IMPL].** The
transition layer's `profile_epoch` is independent of both the crypto epoch
and the PortHop epoch; a PortHop hop does not touch it and vice versa.
Target epoch must be exactly `stable_epoch + 1` (`TransitionError::STALE_EPOCH`
otherwise).

**I-EPOCH-6 (PortHop epoch monotonicity) [IMPL].** The PortHop epoch
advances via `hop()` (+1, resets the epoch timer and the unacked set;
**saturating at `UINT32_MAX`** — it never wraps back to 0, which would
reopen the replay fence) or via `HOP_NOTIFY`, which is applied only when
`next_epoch > epoch_` **and the forward jump is at most
`kMaxHopNotifyForwardJump = 4`** (overflow-safe comparison). A notify
announcing a larger forward jump — e.g. a forged `0xffffffff` that would
drive the epoch (and the fence arithmetic) to the u32 wrap point — rejects
the WHOLE frame BEFORE any ACK/HOP_NOTIFY state mutation. Regression
through the notify path is rejected (monotonic rule; the frame itself
still decodes). `PortHopSession::decode()` additionally enforces a
fail-closed monotonic replay fence on the *frame header* epoch: ONLY a
frame whose header epoch is below `min_accepted_epoch()` = current epoch −
`epoch_replay_window` (saturating at 0; default
`kDefaultEpochReplayWindow = 4`, per-session via
`set_epoch_replay_window()`, **clamped to `kMaxEpochReplayWindow = 64` so a
bogus huge window cannot silently disable the fence**, 0 = strict
"current-or-newer" mode, no disable switch) is rejected BEFORE any
ACK/HOP_NOTIFY state mutation, so a replayed old-epoch frame cannot clear
the unacked set, move `last_ack_seq_`, or steer the epoch. The fence is a
lower bound only, NOT a full replay detector: frames at/above
`min_accepted_epoch()` — including IN-WINDOW older epochs — still decode
and may still process ACK bits and apply a monotonic bounded HOP_NOTIFY;
current/future epochs are accepted unchanged (the peer may hop first) and
in-window reordering/loss across a hop keeps working. Authentication
caveat: legacy "PH" frames carry NO authentication, and with header
protection the per-epoch prefix is only a 16-bit tag (brute-forcible, not
a cryptographic MAC) — the fence and the forward-jump bound are the
anti-replay/anti-steering layers, not the prefix; HP derives the prefix
from the frame's own epoch, so an old-epoch replay with a valid old prefix
passes the prefix check and is dropped by the fence. Server-side
limitation (documented, not a fence bypass): `PortHopServer` never
originates hops — a server-side session's epoch advances ONLY via the
peer's bounded monotonic HOP_NOTIFY (poll() has no interval/loss-driven
epoch driver), so the hop schedule is effectively client-led.
**Epoch exhaustion is an explicit terminal state (G2.1).** `UINT32_MAX` is
a TERMINAL epoch: once reached, the epoch can never advance, regress, or
wrap for this session — `hop()` at the ceiling returns false, increments
`saturated_hop_attempts()`, and deliberately performs NO epoch-timer or
unacked reset, so a dead-end session cannot fake liveness by silently
re-arming its hop timer on every call; `should_hop()` stops signalling
(returns false) once `epoch_exhausted()` is true, superseding both the
loss and timer triggers. No HOP_NOTIFY can escape the terminal epoch
either (there is no u32 above `UINT32_MAX`, so the admission rule can
never fire). **Recovery from exhaustion requires a NEW session — new
`session_id` plus a fresh handshake; the epoch is NEVER renegotiated,
reset, or wrapped in-session**, and there is intentionally no API that
permits it. Callers MUST treat `PortHopSession::epoch_exhausted()` /
`PortHopServer::session_epoch_exhausted()` (nullopt for unknown sessions,
so fail-closed callers cannot confuse "unknown" with "not exhausted") as a
fail-closed liveness signal and re-establish out-of-band. The value
`kMaxHopNotifyForwardJump = 4` is normative: a legitimate peer hops
exactly +1 per hop and announces each hop with its own HOP_NOTIFY, so the
bound exists solely to tolerate up to four missed, reordered, or
coalesced notifications (it does not exceed the default replay window, so
a maximally-stale legitimate notify still passes the fence); it is NOT
relay multi-hop evidence — no protocol path legitimately produces larger
jumps — and it is deliberately NOT configurable, since enlarging it would
weaken the anti-steering bound near the u32 wrap point and shrinking it
to 0 would break legitimate catch-up after notification loss.
Fence drops are observable via `PortHopSession::epoch_fence_dropped()` and
`PortHopServer::frames_rejected_epoch_fence()` (kept distinct from
`frames_malformed()`).
*Acceptance:* `PortHopEpochFenceTest.OldEpochFrameOutsideWindowDropped`,
`.WindowBoundaryFrameAcceptedOlderDropped`,
`.InWindowReorderAcrossHopAccepted`, `.FutureEpochAcceptedPerProtocol`,
`.HopNotifyNeverRegressesEpoch`, `.FencedReplayCannotMutateAckState`,
`.StrictZeroWindowAcceptsOnlyCurrentAndFuture`,
`.HeaderProtectedOldEpochReplayDropped`,
`.HopNotifyUint32MaxRejectedNoWrap`,
`.HopNotifyExcessiveForwardJumpRejectedNoMutation`,
`.HopNotifyJumpRuleOverflowSafeBoundaries`,
`.HopSaturatesAtUint32MaxNoWrap`, `.EpochReplayWindowClampedToMax`,
`.CombinedAckAndHopNotifyFencedFrameNoMutation`,
`PortHopEpochExhaustionTest.FinalHopIntoSaturationAdvancesOnce`,
`.HopAtTerminalEpochIsObservableNoOp`,
`.HopNotifyIntoSaturationIsLegitimateFinalHop`,
`.NoInSessionEscapeFromTerminalEpoch`,
`.FenceStillRejectsOldFramesAtTerminalEpoch`,
`PortHopLoopbackTest.EpochFenceDropCountedSeparatelyFromMalformed`,
`.SessionEpochExhaustedQueryableFailClosed`.

## 2. Authenticated context

**I-AUTH-1 (control rides inside AEAD) [IMPL].** All transition control
messages are plaintext bodies passed to `hooks.emit_control`, which
NCP-tags them (`E2EMessageType::PROFILE_TRANSITION`) and encrypts them
*fresh on every call* through the established E2E AEAD channel
(`SessionProfileContext::Impl` ctor, `ncp_profile_transition.cpp:964-976`).
Ciphertext is never cached or reused; a logical retransmit keeps the same
`transition_id` but gets a fresh ratchet counter/nonce/tag.
*Acceptance:* `ProfileTransition.PrepareLossRetransmitFreshCryptoCounter`.

**I-AUTH-2 (context binding) [IMPL].** Every control body binds:
`session_id` (16 bytes, derived from the established session), `transition_id`,
target profile `id/revision/content_hash`, `direction`, `effective_counter`,
target `profile_epoch`, sender `crypto_epoch`, `grace_ms`. All fields are
verified against the `SessionProfileContext` state; the codec
(`ProfileTransitionCodec`) is strictly bounded (`MAX_CONTROL_BODY_BYTES = 256`,
exact length, bounded id `MAX_PROFILE_ID_LEN = 64`, identity-free fixed form
for ABORT) and produces no partial state.
*Acceptance:* `ProfileTransitionCodec.RoundtripAllTypes`,
`ProfileTransitionCodec.RejectsMalformed`,
`ProfileTransition.CorruptControlNoStateCorruption`.

**I-AUTH-3 (capability gate, fail-closed) [IMPL].** `profile_transition_v1`
(NCPCapabilities reserved bit 0x01) must be negotiated; otherwise
`start_transition()` returns `NOT_SUPPORTED`, no outbound control is emitted,
and inbound control is rejected without reply. v2 (`profile_transition_v2`)
is negotiated as strict AND of both peers' V1∧V2 bits (fail-closed on a
stripped bit; invariant I-V2-6). The adapter never silently downgrades an
established E2E session to plaintext; pre-handshake plaintext (`kind 'P'`)
is a separate explicit compatibility mode, OFF by default
(`Config::allow_insecure_plaintext_legacy`).
*Acceptance:* `ProfileTransition.LegacyPeerNoWire`,
`UdpProfileTransition.UnsupportedPeerNoWireChange`,
`UdpProfileTransitionV2.LegacyPeerRefusalZeroControlTraffic`,
`MimicrySessionV2.GateMatrix`, `MimicrySessionV2.V1NegotiatedSessionUnchanged`.

**I-AUTH-4 (outer mask is unauthenticated) [IMPL].** The outer mimicry layer
is a mask, not an authentication layer. Authentication happens strictly after
unwrapping, inside E2E AEAD + replay checks and the inner PD profile-epoch
check. Corrupted or replayed bytes therefore can never confirm a transition.
The v2 stateful masks add mask-level authentication (STUN HMAC / QUIC AEAD /
DCID check bound to the per-session `mask_key`) that fails closed for
wrong-session datagrams before E2E AEAD (invariant I-V2-4).

## 3. Transactional candidate decrypt

**I-TXD-1 (verify-then-commit) [IMPL].** Every RX candidate evaluation is
transactional: unwrap candidate → E2E AEAD decrypt → only on success any
state effect. A failed candidate never mutates ratchet, FSM, or transition
state, so trying the next candidate is safe. At the E2E layer this is
enforced by staged skipped keys (`stage_skipped_keys` /
`commit_staged_skipped` in `e2e.cpp`: keys are staged without mutating
`ratchet.skipped_keys` and merged only after the AEAD tag verifies; forged
packets cannot destroy skipped-key state), and by `crypto_epoch` never
advancing on failed decrypts (I-EPOCH-2). AEAD/replay failures are treated
as transport drops; the transition layer keeps its own dedup by
`(transition_id, state)`, never by crypto counter.
*Acceptance:* `ProfileTransition.LogicalDuplicatesAndReplayDoNotConfirm`,
`UdpProfileTransition.DuplicateReplayAndCorruptNewDatagrams`,
`MimicrySessionV2.CandidateOrderAndGarbageBound`.

**I-TXD-2 (bounded crypto work per datagram) [IMPL].** The RX path tries
at most 4 ordered candidates per datagram (see §4); each candidate costs one
mask unwrap plus at most one E2E AEAD attempt, and the first AEAD-valid
candidate wins (I-V2-3). The structural cap is enforced before each unwrap.
`candidate_unwrap_attempts_total`, `candidate_aead_attempts_total`,
`candidate_unwrap_attempts_max`, and `candidate_aead_attempts_max` expose exact
cumulative and per-datagram work for DoS accounting. Unwrap false-positive
amplification on a garbage flood remains bounded; mask-level authentication
on stateful masks reduces unnecessary AEAD work and is mandatory for stateful
targets.
*Acceptance:* `MimicrySessionV2.CandidateAttemptCountersExact`,
`MimicrySessionFsmVariants.CandidateAttemptCountersBoundedAtCap`, and
`MimicrySessionFsmVariants.CandidateCapRespectedUnderHostileFlood`.

## 4. RX candidate ordering, dedup, cap

**I-CAND-1 (ordered candidates) [IMPL].** Inbound datagrams are evaluated
against an ordered candidate list (`NcpMimicrySession::Impl::handle_e2e`,
`ncp_mimicry_session.cpp:687-780`):

1. **active** outer profile — always;
2. **pending** outer profile — v2 only, while a transition is outstanding,
   installed no later than the peer's first possible new-mask transmission
   (initiator: `start_profile_transition()` success; responder: PREPARE
   accept via `sync_pending_mimic()`), invariant I-V2-2 (zero decode gap);
3. **old-grace** outer profile — only while `ctx->in_grace_period(now_ms)`;
4. **sibling** variant mask(s) — v2 + FSM-driven mask variants only (§5).

**I-CAND-2 (dedup) [IMPL].** Candidates that unwrap identically are tried
once: pending is skipped when equal to active; old is skipped when equal to
active or to an already-tried pending; siblings are skipped when equal to
any mask already tried for this datagram. This prevents double-charging the
AEAD layer on mask-preserving transitions.

**I-CAND-3 (hard cap 4) [IMPL].** At most 4 candidates per datagram: plain
v2 uses at most 3; a family variant map contributes at most one mask beyond
active/pending/old (the active mask of a variant family is always one of the
family's variants, so dedup absorbs the rest). Under v1 the list is exactly
{active, old-grace} and byte-identical to pre-v2 behavior.
*Acceptance:* `MimicrySessionV2.CandidateOrderAndGarbageBound`,
`MimicrySessionV2.GraceExpiryDropsOldAndPendingCandidates`,
`MimicrySessionV2.ControlMaskPinnedThroughRetransmits` (control pinned to the
transition-stable mask, I-V2-1).

## 5. Sibling definition

**I-SIB-1 (normative).** A *sibling* of the active profile is exactly a mask
belonging to the **variant group of the same hash-bound descriptor
`(id, revision, content_hash)`** — i.e. the acceptance set must be a pure
function of the descriptor identity carried on the wire and verified against
the catalog, never of receiver-local runtime state.

**Status: [IMPL].** For catalog schema 1, the hash-bound
**`ProtocolFamily family` field IS the closed built-in variant group**; there
is deliberately no separate per-descriptor variant-group field. The verified
descriptor identity `(id, revision, content_hash)` therefore selects the
reviewed built-in map `family_variant_masks()` deterministically on both
endpoints: QUIC → {QUIC_INITIAL, QUIC_SHORT_HEADER}; WEBRTC → {STUN_MESSAGE};
other families → no siblings. Because `family` is covered by `content_hash`,
a stale hash after family mutation is rejected. Timing/statistics revisions
cannot silently change wire parsers; introducing a new variant group requires
reviewed code/a protocol-family map change rather than arbitrary signed
catalog data.
*Acceptance:* `MimicrySiblingBinding.SameFamilyRevisionTransitionRetainsSiblingSet`,
`.FamilyMutationChangesHashAndStaleHashRejected`, and
`.FamilyTransitionSwapsSiblingSetOnBothEndpoints`. These cover same-family
revision transitions with different hashes, stale-hash rejection at catalog
and live PREPARE boundaries, and deterministic candidate replacement on both
endpoints after a QUIC→WEBRTC transition and grace expiry.

**I-SIB-2 (TX/RX symmetry gate) [IMPL].** Variant wrapping applies to data
only, never to control (C1 pinning unchanged). `Config::disable_mask_variants`
(default false) disables both the TX variant selection and the RX sibling
candidate; it MUST be configured symmetrically on both peers (asymmetric use
causes one-way loss — documented WARNING in `ncp_mimicry_session.hpp`).
*Acceptance:* `tests/test_mimicry_session_fsm.cpp` variant tests (design
step 6).

## 6. DRAIN and grace

FSM: `IDLE → PREPARE → READY → COMMIT → DRAIN → IDLE`.

**I-DRAIN-1 (grace deadline) [IMPL].** Local activation (`activate()`) sets
`grace_deadline = now + grace_ms` and enters COMMIT. On confirmation
(CONFIRM or first valid new-layout data — `become_effective`) or on a
post-activation timeout (`become_uncertain`) the state becomes DRAIN,
retransmissions stop (`attempts = 0`), and the tick deadline becomes the
grace deadline. DRAIN finalizes (`finalize()`: pending becomes stable) when
`tick(now)` observes `now >= grace_deadline`.
*Acceptance:* `ProfileTransition.OldDataInGraceAcceptedAfterGraceRejected`,
`UdpProfileTransition.OldInFlightGraceAndDecoderRemoval`.

**I-DRAIN-2 (effective grace upper bound) [IMPL].** The responder clamps a
peer-proposed grace to `min(proposed, configured)`; READY/COMMIT re-clamp to
the running minimum (`ncp_profile_transition.cpp:658-660, 689-690, 714-715`).
The configured ceiling is `ProfileTransitionConfig::grace_period_ms`,
optionally *raised* (never lowered) by `set_grace_floor_ms()` — used by the
adapter once v2 is negotiated to the retransmit budget plus margin
(`v2_grace_floor_ms = retransmit_interval_ms * max_retransmit_attempts +
2 * retransmit_interval_ms`, `ncp_mimicry_session.cpp:60`), so
post-activation control retransmits — decodable under the v2 C1 control-mask
pin only via the old-grace candidate — cannot outlive the grace window. The
effective grace therefore satisfies:
`retransmit budget + margin ≤ effective_grace ≤ configured_grace_ceiling`
under v2, and `effective_grace ≤ grace_period_ms` under v1.
`effective_transition_grace_ms()` surfaces the value. A grace already bound
to an in-flight transition is never retroactively changed.

**I-DRAIN-3 (retransmission bounds) [IMPL].** Each control step is (re)sent
at most `max_retransmit_attempts` times (including the first send) at
`retransmit_interval_ms` spacing; the body is rebuilt on every retransmit
(fresh effective counter, fresh AEAD). Pre-activation exhaustion → ABORT +
clean rollback; post-activation exhaustion (COMMIT) → `become_uncertain`
(no silent rollback; `SwitchEvent.confirmed == false`).
*Acceptance:* `ProfileTransition.PreActivationTimeoutCleanAbort`,
`.TimeoutAsymmetricNoSilentRollback`,
`UdpProfileTransition.PrepareLossFreshRetransmission`,
`.ReadyLossRecoveredByPrepareRetransmit`, `.CommitAndConfirmLossRecovered`,
`.ConfirmLossRecoveredByRetransmit`,
`UdpProfileTransitionV2.ControlLossParity20Percent`.

**I-DRAIN-4 (courtesy CONFIRM, bounded) [IMPL].** A duplicate CONFIRM
received in DRAIN that carries a *fresh* effective counter observed on the
live crypto stream (`packet_crypto_counter` present) is a retransmission
from a peer still in COMMIT; it is re-acked with an idempotent CONFIRM —
no state change, no new timers — bounded per transition by
`drain_confirm_replies < max_retransmit_attempts`, so two DRAIN peers cannot
echo CONFIRM back and forth past the retransmission budget. A duplicate
re-carrying the previously recorded counter, or one fed without crypto
provenance, is only counted (`control_duplicates`) and generates no traffic.

**I-DRAIN-5 (no extension by duplicates) [IMPL].** Duplicate READY/COMMIT/
CONFIRM in any post-activation state are deduped (`control_duplicates++`)
and answered idempotently; they never re-arm timers, never re-activate, and
never move the grace deadline. Duplicate PREPARE after READY is answered by
READY retransmit without new timers.
*Acceptance:* `ProfileTransition.ReadyLossDuplicatePrepareNoNewTimers`,
`.CommitLossRecoveredByReadyRetransmit`.

**I-DRAIN-6 (monotonic cleanup without traffic) [IMPL].** All cleanup is
driven by the local monotonic clock via `tick()`: DRAIN → IDLE finalize at
the grace deadline, `SessionProfileContext::on_finalize_side_effects()`
(stable layout adoption), and adapter-side `cleanup_after_finalize()` /
`sync_pending_mimic()` (old/pending mask decoder removal). No inbound
traffic is required for state to converge; the grace window closes on the
deadline alone.
*Acceptance:* `MimicrySessionV2.GraceExpiryDropsOldAndPendingCandidates`.

**I-DRAIN-7 (post-activation abort refused) [IMPL].** ABORT/TIMEOUT are safe
only before activation. A post-activation ABORT is counted
(`aborts_ignored_post_activation`) and ignored — no rollback; the way back
is a NEW transition.
*Acceptance:* `ProfileTransition.PreActivationAbortCleanRollback`,
`.PostActivationAbortIgnoredNoRollback`,
`MimicrySessionV2.AbortPreActivationLocalAndEngaged`,
`MimicrySessionV2.AbortPostActivationRefused`.

**I-DRAIN-8 (outbound queue byte/packet bounds) [IMPL].** The adapter's
outbound reaction queue has independent structural packet and byte limits:
`max_outbound_queue_packets` (default 64) and
`max_outbound_queue_bytes` (default 256 KiB). The policy is refuse-new, never
drop-oldest: already queued control is not evicted, and a zero byte budget
disables queueing. Rejected datagrams are counted in
`queue_dropped_packets` and `queue_dropped_bytes`; dequeue maintains exact
byte occupancy. Producers remain separately rate-limited by the transition
retransmission budget and bounded courtesy CONFIRMs.
*Acceptance:* `MimicrySessionV2.OutboundQueuePacketBoundFloodNoDrain`,
`.OutboundQueueByteBoundRefusesAndCounts`, and
`.OutboundQueueExactFillBoundary`.

**I-DRAIN-9 (no distributed atomicity promised) [IMPL — documented].** After
a post-activation timeout the endpoints may transiently disagree (one
committed, one aborted). The committed side keeps the new profile (no silent
rollback); the mismatch is surfaced via counters and
`SwitchEvent.confirmed == false`. Recovery evidence:
`UdpProfileTransitionV2.CommitStormUncertainDivergenceRecovery`.

## 7. Data-plane epoch routing (inner PD layer)

**I-DATA-1.** Data messages carry the PD header with the sender's profile
epoch (`frame_data_body`); TX uses the new epoch/layout from local
activation when direction ≠ RX_ONLY (`tx_uses_new`), RX accepts the new
epoch post-activation when direction ≠ TX_ONLY (`rx_accepts_new`), and
accepts the stable epoch under the old layout only inside the grace window.
Reject classes are counted separately: `rx_rejected_early_new` (pending
epoch before COMMIT — never activates, never confirms),
`rx_rejected_old_expired` (superseded epoch after the grace deadline),
`rx_rejected_unknown_epoch`, `rx_rejected_malformed`.
*Acceptance:* `ProfileTransition.EarlyNewDataDoesNotActivateOrConfirm`,
`.OldDataInGraceAcceptedAfterGraceRejected`,
`.TxOnlyDirectionKeepsRxOnStable`,
`ProfileTransition.HappyPathContinuousDataAndCounters`.

**I-DATA-2 (confirmation by data).** Valid new-layout data confirms the
transition only in COMMIT (`note_new_layout_data`); early data never
confirms.
*Acceptance:* `ProfileTransition.ConfirmViaNewLayoutData`.

**I-DATA-3 (documented transient).** TX_ONLY transitions intentionally
transient: both endpoints activate with `tx_uses_new=true,
rx_accepts_new=false`, so new-epoch data is rejected by the peer
(`rx_rejected_unknown_epoch`) until it finalizes. Intended and documented in
`ncp_profile_transition.cpp:1018-1026`; not a security property.

## 8. Consolidated acceptance-test matrix

| Invariant | Test(s) | Status |
|---|---|---|
| I-EPOCH-1 no reset | `ProfileTransition.RatchetReplayAndCountersSurviveTransition`; `UdpProfileTransition.RepeatedTransitionsMonotonicEpochs` | IMPL |
| I-EPOCH-2 crypto epoch monotonic | `MimicrySession.LayoutTransitionPreservesCryptoEpochAndCounterContinuity`; ratchet/replay tests above | IMPL |
| I-EPOCH-3 peer-relative fencing | `EpochFencingRejectsStaleAndFuture`; `MidTransitionPeerRekeyAccepted`; `OlderGenerationReplayRejected`; `EpochGapTransitionCompletes`; `ResponderLedAfterInitiatorLedEpochGap` | IMPL |
| I-EPOCH-4 effective counter | `PrepareLossRetransmitFreshCryptoCounter` | IMPL |
| I-EPOCH-6 PortHop epoch fence | `PortHopEpochFenceTest.OldEpochFrameOutsideWindowDropped`; `.WindowBoundaryFrameAcceptedOlderDropped`; `.InWindowReorderAcrossHopAccepted`; `.FutureEpochAcceptedPerProtocol`; `.HopNotifyNeverRegressesEpoch`; `.FencedReplayCannotMutateAckState`; `.StrictZeroWindowAcceptsOnlyCurrentAndFuture`; `.HeaderProtectedOldEpochReplayDropped`; `.HopNotifyUint32MaxRejectedNoWrap`; `.HopNotifyExcessiveForwardJumpRejectedNoMutation`; `.HopNotifyJumpRuleOverflowSafeBoundaries`; `.HopSaturatesAtUint32MaxNoWrap`; `.EpochReplayWindowClampedToMax`; `.CombinedAckAndHopNotifyFencedFrameNoMutation`; `PortHopEpochExhaustionTest.FinalHopIntoSaturationAdvancesOnce`; `.HopAtTerminalEpochIsObservableNoOp`; `.HopNotifyIntoSaturationIsLegitimateFinalHop`; `.NoInSessionEscapeFromTerminalEpoch`; `.FenceStillRejectsOldFramesAtTerminalEpoch`; `PortHopLoopbackTest.EpochFenceDropCountedSeparatelyFromMalformed`; `.SessionEpochExhaustedQueryableFailClosed` | IMPL |
| I-AUTH-1/2/3 | codec roundtrip/reject tests; `LegacyPeerNoWire`; `UnsupportedPeerNoWireChange`; `LegacyPeerRefusalZeroControlTraffic`; `GateMatrix` | IMPL |
| I-TXD-1 verify-then-commit | `LogicalDuplicatesAndReplayDoNotConfirm`; `DuplicateReplayAndCorruptNewDatagrams`; `CandidateOrderAndGarbageBound` | IMPL |
| I-TXD-2 bounded crypto work | `MimicrySessionV2.CandidateAttemptCountersExact`; `MimicrySessionFsmVariants.CandidateAttemptCountersBoundedAtCap`; `CandidateCapRespectedUnderHostileFlood` | IMPL |
| I-CAND-1..3 order/dedup/cap | `CandidateOrderAndGarbageBound`; `GraceExpiryDropsOldAndPendingCandidates`; `ControlMaskPinnedThroughRetransmits` | IMPL |
| I-SIB-1 sibling = variant group of hash-bound descriptor | `MimicrySiblingBinding.SameFamilyRevisionTransitionRetainsSiblingSet`; `.FamilyMutationChangesHashAndStaleHashRejected`; `.FamilyTransitionSwapsSiblingSetOnBothEndpoints` | IMPL |
| I-SIB-2 symmetric variant gate | `tests/test_mimicry_session_fsm.cpp` variant selection tests | IMPL |
| I-DRAIN-1/2/6 grace & cleanup | `OldDataInGraceAcceptedAfterGraceRejected`; `OldInFlightGraceAndDecoderRemoval`; `GraceExpiryDropsOldAndPendingCandidates` | IMPL |
| I-DRAIN-3 retransmit bounds | `PrepareLossFreshRetransmission`; `ReadyLossRecoveredByPrepareRetransmit`; `CommitAndConfirmLossRecovered`; `ConfirmLossRecoveredByRetransmit`; `ControlLossParity20Percent`; `PreActivationTimeoutCleanAbort`; `TimeoutAsymmetricNoSilentRollback` | IMPL |
| I-DRAIN-4/5 bounded courtesy, no extension | `ReadyLossDuplicatePrepareNoNewTimers`; `CommitLossRecoveredByReadyRetransmit`; `LogicalDuplicatesAndReplayDoNotConfirm` | IMPL |
| I-DRAIN-7 post-activation abort | `PostActivationAbortIgnoredNoRollback`; `AbortPostActivationRefused` | IMPL |
| I-DRAIN-8 queue bounds | `MimicrySessionV2.OutboundQueuePacketBoundFloodNoDrain`; `.OutboundQueueByteBoundRefusesAndCounts`; `.OutboundQueueExactFillBoundary` | IMPL |
| I-DRAIN-9 divergence recovery | `CommitStormUncertainDivergenceRecovery` | IMPL |
| I-DATA-1/2 epoch routing | `EarlyNewDataDoesNotActivateOrConfirm`; `ConfirmViaNewLayoutData`; `TxOnlyDirectionKeepsRxOnStable`; `HappyPathContinuousDataAndCounters` | IMPL |
| End-to-end wire evidence | `UdpProfileTransition.ActiveStreamSwitchWithWireLayoutEvidence`; `IdleSwitchOverRealUdp`; `MimicrySessionV2.FullTransitionGenericToQuicShortHeader` | IMPL |

## 9. Closure summary and residual limitations

1. **I-EPOCH-6 [IMPL]** — resolved: `PortHopSession::decode()` enforces a
   bounded old-epoch replay fence (`min_accepted_epoch()`, default window 4,
   clamped to `kMaxEpochReplayWindow = 64`) before any ACK/HOP_NOTIFY state
   mutation; HOP_NOTIFY is additionally bounded to a forward jump of at most
   `kMaxHopNotifyForwardJump = 4` (excessive jumps reject the whole frame
   without mutation) and `hop()` saturates at `UINT32_MAX` (no u32 wrap), so
   a forged `HOP_NOTIFY(0xffffffff)` can no longer steer the epoch to the
   wrap point and reset the fence. Fence drops get dedicated counters
   (`epoch_fence_dropped()`, `frames_rejected_epoch_fence()`). HOP_NOTIFY
   monotonicity and in-window loss/reorder semantics are unchanged; the
   fence remains a lower bound only (in-window old frames may still
   ACK/notify), and HOP_NOTIFY is not cryptographically authenticated
   (legacy framing unauthenticated; HP prefix is a 16-bit tag). Epoch
   exhaustion (G2.1) is hardened into an explicit terminal state: at
   `UINT32_MAX` `hop()` is a counted observable no-op with no silent
   timer/unacked reset, `should_hop()` stops signalling, and
   `epoch_exhausted()` / `session_epoch_exhausted()` /
   `saturated_hop_attempts()` let callers fail closed; recovery is only a
   new session (new `session_id` + handshake), never in-session epoch
   renegotiation/reset, and the notify path cannot escape the terminal
   epoch. `kMaxHopNotifyForwardJump = 4` is fixed normatively (peer hops
   +1; bound tolerates ≤4 missed/coalesced notifications; not relay
   multi-hop evidence) and is not configurable. Remaining documented
   limitation: the server never originates hops — server-side epochs
   advance only via the peer's bounded HOP_NOTIFY (see §1); exhaustion
   state is exposed but the fail-closed reaction (tearing down and
   re-establishing the session) is the caller's responsibility, and
   `decode()` still serves in-window traffic at the terminal epoch so
   in-flight data is not black-holed before the caller acts.
2. **I-TXD-2 [IMPL]** — resolved: candidate crypto work is structurally
   capped at 4 and accounted by exact cumulative/per-datagram unwrap and AEAD
   counters, with adversarial flood and exact-work acceptance tests.
3. **I-SIB-1 [IMPL]** — resolved by the normative schema-1 declaration that
   the hash-bound `ProtocolFamily` IS the closed built-in variant group.
   Same-family revision continuity, stale-hash rejection, and cross-family
   candidate replacement are covered on both endpoints.
4. **I-DRAIN-8 [IMPL]** — resolved: the adapter outbound reaction queue has
   structural packet/byte caps, refuse-new accounting, exact occupancy, and
   flood/boundary tests.
5. **I-EPOCH-2 [IMPL]** — resolved: the dedicated layout-transition test
   verifies unchanged `crypto_epoch` and E2E session identity together with
   strictly continuing sending/receiving chain counters through control and
   application data.
