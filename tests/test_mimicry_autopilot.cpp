// ══════════════════════════════════════════════════════════════════════════════
// tests/test_mimicry_autopilot.cpp
// Tests for MimicryAutoPilot / ConnectionDirector — deterministic UDP
// reference-profile selection loop (no network, fake clock, scripted
// transition results).
// ══════════════════════════════════════════════════════════════════════════════
#include <gtest/gtest.h>
#include "ncp_mimicry_autopilot.hpp"

#include <map>
#include <string>
#include <utility>
#include <vector>

using namespace ncp;

namespace {

using AP = MimicryAutoPilot;
using TR = MimicryAutoPilot::TransitionResult;
using Mode = MimicryAutoPilot::Mode;
using State = MimicryAutoPilot::State;

const char* kVoip = "voip_opus";
const char* kWebrtc = "webrtc_video";
const char* kYoutube = "youtube_stream";
const char* kZoom = "zoom_call";

std::string canon(const std::string& id, uint32_t rev) {
    return id + "@" + std::to_string(rev);
}

struct Harness {
    ReferenceProfileCatalog catalog;  // declared first: must outlive `ap`
    int64_t now = 0;

    std::vector<std::pair<std::string, uint32_t>> requests;
    std::vector<std::pair<std::string, uint32_t>> cancels;
    std::vector<TR> scripted;  // consumed FIFO; empty => default_result
    TR default_result = TR::ACCEPTED;
    std::map<std::string, double> scores;  // key: "id@rev" or "id"
    std::map<std::string, AP::CandidateEvidence> evidence;  // key: profile_id
    bool evidence_enabled = false;

    std::unique_ptr<AP> ap;

    Harness() {
        // Deterministic base scores: voip > webrtc > youtube > zoom.
        scores[kVoip] = 4.0;
        scores[kWebrtc] = 3.0;
        scores[kYoutube] = 2.0;
        scores[kZoom] = 1.0;
    }

    void register_defaults() {
        ASSERT_TRUE(
            catalog.register_builtin_stat_profile(StatProfile::voip_opus()).ok());
        ASSERT_TRUE(
            catalog.register_builtin_stat_profile(StatProfile::webrtc_video()).ok());
        ASSERT_TRUE(
            catalog.register_builtin_stat_profile(StatProfile::youtube_stream()).ok());
        ASSERT_TRUE(
            catalog.register_builtin_stat_profile(StatProfile::zoom_call()).ok());
    }

    AP::Config base_config() {
        AP::Config cfg;
        cfg.enabled = true;
        cfg.catalog = &catalog;
        cfg.now_fn = [this] { return now; };
        cfg.request_transition = [this](const std::string& id, uint32_t rev) {
            requests.emplace_back(id, rev);
            if (!scripted.empty()) {
                TR r = scripted.front();
                scripted.erase(scripted.begin());
                return r;
            }
            return default_result;
        };
        cfg.cancel_transition = [this](const std::string& id, uint32_t rev) {
            cancels.emplace_back(id, rev);
        };
        cfg.candidate_score_fn = [this](const ProfileDescriptor& d) {
            auto it = scores.find(canon(d.profile_id, d.revision));
            if (it != scores.end()) return it->second;
            auto it2 = scores.find(d.profile_id);
            return it2 != scores.end() ? it2->second : 1.0;
        };
        cfg.candidate_evidence_fn = [this](const ProfileDescriptor& d,
                                           AP::CandidateEvidence& out) {
            if (!evidence_enabled) return true;
            auto it = evidence.find(d.profile_id);
            if (it != evidence.end()) out = it->second;
            return true;
        };
        cfg.cooldown_ms = 100;
        cfg.min_dwell_ms = 50;
        cfg.min_request_interval_ms = 10;
        cfg.failure_threshold = 3;
        cfg.transition_timeout_ms = 1000;
        cfg.busy_retry_ms = 20;
        cfg.hysteresis_pct = 10.0;
        return cfg;
    }

    void make() { make_with(base_config()); }
    void make_with(AP::Config cfg) { ap.reset(new AP(std::move(cfg))); }

    void advance(int64_t ms) { now += ms; }
    void tick(int n = 1) {
        for (int i = 0; i < n; ++i) ap->evaluate();
    }
    void degrade(int n = 3) {
        for (int i = 0; i < n; ++i) ap->report_degradation();
    }

    // Drive the initial selection: one request, committed immediately.
    std::pair<std::string, uint32_t> drive_initial() {
        tick();
        if (requests.empty()) return {"", 0};
        auto r = requests.back();
        EXPECT_TRUE(ap->commit_transition(r.first, r.second));
        return r;
    }

    bool stats_has(const std::string& frag) {
        return ap->to_stats_json().find(frag) != std::string::npos;
    }
};

// ══════════════════════════════════════════════════════════════════════════════
// Selection basics
// ══════════════════════════════════════════════════════════════════════════════

TEST(MimicryAutoPilot, InitialSelectionPicksBestInjectedScore) {
    Harness h;
    h.register_defaults();
    h.make();
    auto sel = h.drive_initial();
    ASSERT_EQ(sel.first, kVoip);  // highest injected score wins
    EXPECT_EQ(h.ap->active_profile_id(), kVoip);
    EXPECT_EQ(h.ap->active_profile_revision(), 1u);
    EXPECT_EQ(h.ap->state(), State::MONITORING);
    auto hist = h.ap->switch_history();
    ASSERT_EQ(hist.size(), 1u);
    EXPECT_EQ(hist[0].reason, "initial");
    EXPECT_TRUE(hist[0].from.empty());
    EXPECT_EQ(hist[0].to, canon(kVoip, 1));
}

TEST(MimicryAutoPilot, HysteresisBlocksMarginalChallenger) {
    Harness h;
    h.register_defaults();
    h.scores[kVoip] = 1.0;
    h.scores[kWebrtc] = 0.5;
    h.scores[kYoutube] = 0.5;
    h.scores[kZoom] = 0.5;
    h.make();
    ASSERT_EQ(h.drive_initial().first, kVoip);

    // Hysteresis is an IMPROVEMENT gate on a HEALTHY current: a marginal
    // challenger below the 10% margin must not displace it.
    // (A DEAD current instead falls back regardless of hysteresis — see
    // AdoptedActiveEqualScoresDegradationFallsBack.)
    h.advance(200);  // cooldown(100) + dwell(50) elapsed
    h.scores[kWebrtc] = 1.05;  // below 10% hysteresis margin vs 1.0
    h.tick(3);
    EXPECT_EQ(h.requests.size(), 1u);  // no new request
    EXPECT_EQ(h.ap->active_profile_id(), kVoip);
    EXPECT_EQ(h.ap->state(), State::MONITORING);

    h.scores[kWebrtc] = 1.2;  // clears the margin
    h.tick();
    ASSERT_EQ(h.requests.size(), 2u);
    EXPECT_EQ(h.requests.back().first, kWebrtc);
}

TEST(MimicryAutoPilot, CooldownGatesSwitch) {
    Harness h;
    h.register_defaults();
    auto cfg = h.base_config();
    cfg.cooldown_ms = 5000;
    cfg.min_dwell_ms = 10;
    h.make_with(cfg);
    ASSERT_EQ(h.drive_initial().first, kVoip);

    h.degrade();
    h.scores[kWebrtc] = 10.0;
    h.advance(4000);
    h.tick();
    EXPECT_EQ(h.requests.size(), 1u);  // cooldown blocks
    h.advance(1001);                   // now - last_switch = 5001 > 5000
    h.tick();
    ASSERT_EQ(h.requests.size(), 2u);
    EXPECT_EQ(h.requests.back().first, kWebrtc);
}

TEST(MimicryAutoPilot, DwellGatesHealthyImprovement) {
    Harness h;
    h.register_defaults();
    auto cfg = h.base_config();
    cfg.cooldown_ms = 10;
    cfg.min_dwell_ms = 5000;
    h.make_with(cfg);
    ASSERT_EQ(h.drive_initial().first, kVoip);

    h.scores[kWebrtc] = 10.0;  // much better, but we are healthy
    h.advance(1000);
    h.tick();
    EXPECT_EQ(h.requests.size(), 1u);  // dwell blocks healthy improvement
    EXPECT_EQ(h.ap->state(), State::MONITORING);
    h.advance(4001);  // dwell elapsed
    h.tick();
    ASSERT_EQ(h.requests.size(), 2u);
    EXPECT_TRUE(h.ap->commit_transition(h.requests.back().first,
                                        h.requests.back().second));
    EXPECT_TRUE(h.stats_has("\"last_reason\":\"improvement\""));
}

TEST(MimicryAutoPilot, DeadCurrentBypassesDwellButNotAntiStorm) {
    Harness h;
    h.register_defaults();
    auto cfg = h.base_config();
    cfg.cooldown_ms = 10;
    cfg.min_dwell_ms = 100000;  // huge: only a dead current may bypass it
    cfg.min_request_interval_ms = 5000;
    h.make_with(cfg);
    ASSERT_EQ(h.drive_initial().first, kVoip);  // request at t=0

    h.degrade();
    h.scores[kWebrtc] = 10.0;
    h.advance(1000);
    h.tick();
    EXPECT_EQ(h.requests.size(), 1u);  // anti-storm floor blocks (never bypassed)
    EXPECT_EQ(h.ap->state(), State::SELECTING);

    h.advance(4001);  // floor elapsed; dwell still NOT elapsed but current is dead
    h.tick();
    ASSERT_EQ(h.requests.size(), 2u);  // dwell bypassed for dead current
    EXPECT_EQ(h.requests.back().first, kWebrtc);
}

// ══════════════════════════════════════════════════════════════════════════════
// Transition protocol
// ══════════════════════════════════════════════════════════════════════════════

TEST(MimicryAutoPilot, BusyRetryKeepsActiveProfile) {
    Harness h;
    h.register_defaults();
    h.make();
    ASSERT_EQ(h.drive_initial().first, kVoip);

    h.degrade();
    h.scores[kWebrtc] = 10.0;
    h.scripted.push_back(TR::BUSY);
    h.advance(200);
    h.tick();
    ASSERT_EQ(h.requests.size(), 2u);  // asked, got BUSY
    EXPECT_EQ(h.ap->active_profile_id(), kVoip);  // active unchanged
    EXPECT_FALSE(h.ap->has_outstanding_request());
    EXPECT_TRUE(h.stats_has("\"busy\":1"));
    EXPECT_EQ(h.ap->switch_history().size(), 1u);  // no fake switch event

    h.advance(30);  // busy_retry(20) + floor(10) elapsed
    h.tick();
    ASSERT_EQ(h.requests.size(), 3u);  // retried
    EXPECT_TRUE(h.ap->commit_transition(h.requests.back().first,
                                        h.requests.back().second));
    EXPECT_EQ(h.ap->active_profile_id(), kWebrtc);
}

TEST(MimicryAutoPilot, CommitAndAbortSemantics) {
    Harness h;
    h.register_defaults();
    h.make();
    h.tick();
    ASSERT_EQ(h.requests.size(), 1u);
    const auto req = h.requests.back();

    // Mismatched commit/abort are refused; active untouched.
    EXPECT_FALSE(h.ap->commit_transition(req.first, req.second + 1));
    EXPECT_FALSE(h.ap->abort_transition("nonexistent", 1));

    EXPECT_TRUE(h.ap->abort_transition(req.first, req.second));
    EXPECT_FALSE(h.ap->has_active_profile());
    EXPECT_TRUE(h.ap->switch_history().empty());  // failed apply != switch
    EXPECT_TRUE(h.stats_has("\"aborts\":1"));
    EXPECT_FALSE(h.stats_has("\"failed_transitions\":0"));

    // After abort the loop re-selects and a real commit establishes active.
    h.advance(50);
    h.tick();
    ASSERT_EQ(h.requests.size(), 2u);
    EXPECT_TRUE(h.ap->commit_transition(h.requests.back().first,
                                        h.requests.back().second));
    EXPECT_EQ(h.ap->active_profile_id(), kVoip);
    EXPECT_EQ(h.ap->switch_history().size(), 1u);
}

TEST(MimicryAutoPilot, SingleOutstandingAndTimeoutCancel) {
    Harness h;
    h.register_defaults();
    h.make();
    h.tick();
    ASSERT_EQ(h.requests.size(), 1u);
    EXPECT_TRUE(h.ap->has_outstanding_request());
    EXPECT_EQ(h.ap->state(), State::WAITING_TRANSITION);

    h.tick(5);  // never a second outstanding request
    EXPECT_EQ(h.requests.size(), 1u);

    h.advance(1001);  // transition_timeout_ms elapsed
    h.tick();
    ASSERT_EQ(h.cancels.size(), 1u);  // timed-out request cancelled via hook
    EXPECT_EQ(h.cancels[0], h.requests[0]);
    EXPECT_TRUE(h.stats_has("\"timeouts\":1"));
    EXPECT_EQ(h.requests.size(), 2u);  // re-selection allowed afterwards
}

TEST(MimicryAutoPilot, DisabledAndLegacyPeerIssueNoCallbacks) {
    Harness h;
    h.register_defaults();
    auto cfg = h.base_config();
    cfg.enabled = false;
    h.make_with(cfg);
    h.tick(5);
    EXPECT_TRUE(h.requests.empty());
    EXPECT_EQ(h.ap->state(), State::DISABLED);

    h.ap->set_enabled(true);
    h.advance(50);  // anti-storm floor after the first request
    h.tick();
    ASSERT_EQ(h.requests.size(), 1u);
    EXPECT_TRUE(h.ap->has_outstanding_request());

    h.ap->set_enabled(false);  // outstanding request must be cancelled
    ASSERT_EQ(h.cancels.size(), 1u);
    EXPECT_EQ(h.cancels[0], h.requests[0]);
    EXPECT_FALSE(h.ap->has_outstanding_request());
    EXPECT_EQ(h.ap->state(), State::DISABLED);

    // Legacy peer: no requests at all, and outstanding cancelled.
    h.ap->set_enabled(true);
    h.advance(50);
    h.tick();
    ASSERT_EQ(h.requests.size(), 2u);
    h.ap->notify_legacy_peer(true);
    ASSERT_EQ(h.cancels.size(), 2u);
    EXPECT_EQ(h.ap->state(), State::DISABLED);
    h.advance(50);
    h.tick(5);
    EXPECT_EQ(h.requests.size(), 2u);  // nothing while legacy
    h.ap->notify_legacy_peer(false);
    h.tick();
    EXPECT_EQ(h.requests.size(), 3u);  // resumes after capability signal
}

TEST(MimicryAutoPilot, DisabledResultBacksOffWithoutSwitch) {
    Harness h;
    h.register_defaults();
    h.make();
    h.scripted.push_back(TR::DISABLED);
    h.tick();
    ASSERT_EQ(h.requests.size(), 1u);
    EXPECT_FALSE(h.ap->has_active_profile());
    EXPECT_TRUE(h.ap->switch_history().empty());
    EXPECT_TRUE(h.stats_has("\"disabled_results\":1"));
    h.advance(50);  // within backoff (cooldown 100)
    h.tick();
    EXPECT_EQ(h.requests.size(), 1u);
}

TEST(MimicryAutoPilot, RevisionPinning) {
    Harness h;
    h.register_defaults();
    // Second revision of voip_opus in the same catalog.
    auto d = ReferenceProfileCatalog::from_stat_profile(StatProfile::voip_opus());
    d.revision = 2;
    ReferenceProfileCatalog::update_content_hash(d);
    ASSERT_TRUE(h.catalog.register_builtin(d).ok());

    h.scores[canon(kVoip, 1)] = 5.0;
    h.scores[canon(kVoip, 2)] = 4.0;  // rev 1 wins
    h.make();
    h.tick();
    ASSERT_EQ(h.requests.size(), 1u);
    EXPECT_EQ(h.requests[0], std::make_pair(std::string(kVoip), 1u));

    // The request is pinned: committing a different revision is refused.
    EXPECT_FALSE(h.ap->commit_transition(kVoip, 2));
    EXPECT_TRUE(h.ap->commit_transition(kVoip, 1));
    EXPECT_EQ(h.ap->active_profile_revision(), 1u);
}

TEST(MimicryAutoPilot, EmptyCatalogSelectsNothing) {
    Harness h;  // no profiles registered
    h.make();
    h.tick(3);
    EXPECT_TRUE(h.requests.empty());
    EXPECT_FALSE(h.ap->has_active_profile());
    EXPECT_EQ(h.ap->state(), State::DEGRADED);
    EXPECT_TRUE(h.stats_has("\"candidates_considered\":0"));
}

TEST(MimicryAutoPilot, MalformedAndNonFiniteMetricsRejected) {
    Harness h;
    h.register_defaults();
    h.make();

    AP::UdpMetrics empty;  // everything absent
    EXPECT_FALSE(h.ap->ingest_metrics(empty));

    AP::UdpMetrics bad_loss;
    bad_loss.loss_ratio = 1.5;
    EXPECT_FALSE(h.ap->ingest_metrics(bad_loss));

    AP::UdpMetrics neg_rtt;
    neg_rtt.rtt_ms = -5.0;
    EXPECT_FALSE(h.ap->ingest_metrics(neg_rtt));

    AP::UdpMetrics inf_jitter;
    inf_jitter.jitter_ms = std::numeric_limits<double>::infinity();
    EXPECT_FALSE(h.ap->ingest_metrics(inf_jitter));

    AP::UdpMetrics ok;
    ok.rtt_ms = 50.0;
    ok.loss_ratio = 0.1;
    EXPECT_TRUE(h.ap->ingest_metrics(ok));

    EXPECT_TRUE(h.stats_has("\"malformed_metrics\":4"));
    EXPECT_TRUE(h.stats_has("\"samples\":1"));
}

TEST(MimicryAutoPilot, LossDegradationTriggersFallback) {
    Harness h;
    h.register_defaults();
    auto cfg = h.base_config();
    cfg.mode = Mode::FALLBACK_ONLY;  // isolate the degradation path
    h.make_with(cfg);
    ASSERT_EQ(h.drive_initial().first, kVoip);

    h.scores[kWebrtc] = 10.0;
    AP::UdpMetrics m;
    m.loss_ratio = 0.9;  // sample health = 1 - 0.5*0.9 = 0.55 < 0.6 floor
    h.ap->ingest_metrics(m);
    h.ap->ingest_metrics(m);
    h.advance(200);
    h.tick();
    EXPECT_EQ(h.requests.size(), 1u);  // below failure_threshold (3)
    h.ap->ingest_metrics(m);
    h.tick();
    ASSERT_EQ(h.requests.size(), 2u);
    EXPECT_EQ(h.requests.back().first, kWebrtc);
    EXPECT_TRUE(h.ap->commit_transition(kWebrtc, 1));
    EXPECT_TRUE(h.stats_has("\"last_reason\":\"degradation\""));
}

// ══════════════════════════════════════════════════════════════════════════════
// Modes / operator policy
// ══════════════════════════════════════════════════════════════════════════════

TEST(MimicryAutoPilot, LockedModeNeverTransitions) {
    Harness h;
    h.register_defaults();
    auto cfg = h.base_config();
    cfg.mode = Mode::LOCKED;
    h.make_with(cfg);
    h.tick(3);
    EXPECT_TRUE(h.requests.empty());  // not even an initial selection

    ASSERT_TRUE(h.ap->adopt_active_profile(kVoip, 1));
    h.degrade(5);
    h.scores[kWebrtc] = 100.0;
    h.advance(1000);
    h.tick(3);
    EXPECT_TRUE(h.requests.empty());
    EXPECT_EQ(h.ap->active_profile_id(), kVoip);
    EXPECT_FALSE(h.ap->set_manual_profile(kWebrtc, 1));  // refused while locked
    EXPECT_FALSE(h.ap->request_rollback());
}

TEST(MimicryAutoPilot, FallbackOnlyIgnoresHealthyImprovement) {
    Harness h;
    h.register_defaults();
    auto cfg = h.base_config();
    cfg.mode = Mode::FALLBACK_ONLY;
    h.make_with(cfg);
    ASSERT_EQ(h.drive_initial().first, kVoip);  // initial selection still happens

    h.scores[kWebrtc] = 100.0;  // huge improvement available
    h.advance(1000);
    h.tick(3);
    EXPECT_EQ(h.requests.size(), 1u);  // healthy: no switch in fallback-only
    EXPECT_EQ(h.ap->state(), State::MONITORING);

    h.degrade();
    h.tick();
    ASSERT_EQ(h.requests.size(), 2u);  // degradation: fallback allowed
    EXPECT_EQ(h.requests.back().first, kWebrtc);
}

TEST(MimicryAutoPilot, ManualModeAndProfileLock) {
    Harness h;
    h.register_defaults();
    auto cfg = h.base_config();
    cfg.mode = Mode::MANUAL;
    h.make_with(cfg);
    h.tick(3);
    EXPECT_TRUE(h.requests.empty());  // no auto-selection in manual mode

    EXPECT_FALSE(h.ap->set_manual_profile("nonexistent", 1));  // catalog check
    EXPECT_TRUE(h.ap->set_manual_profile(kZoom, 1));
    EXPECT_TRUE(h.ap->has_manual_profile());
    h.tick();
    ASSERT_EQ(h.requests.size(), 1u);
    EXPECT_EQ(h.requests[0], std::make_pair(std::string(kZoom), 1u));
    ASSERT_TRUE(h.ap->commit_transition(kZoom, 1));
    EXPECT_EQ(h.ap->active_profile_id(), kZoom);
    EXPECT_TRUE(h.stats_has("\"last_reason\":\"manual\""));
    EXPECT_TRUE(h.stats_has("\"manual_profile\":\"zoom_call@1\""));

    // Auto-selection stays suppressed after the manual commit.
    h.degrade(5);
    h.advance(1000);
    h.tick(3);
    EXPECT_EQ(h.requests.size(), 1u);

    h.ap->clear_manual_profile();
    EXPECT_FALSE(h.ap->has_manual_profile());
}

TEST(MimicryAutoPilot, AdoptActiveProfileEstablishesBaseline) {
    Harness h;
    h.register_defaults();
    auto cfg = h.base_config();
    cfg.cooldown_ms = 10;
    cfg.min_dwell_ms = 5000;
    h.make_with(cfg);

    EXPECT_FALSE(h.ap->adopt_active_profile("nonexistent", 1));  // bounded check
    ASSERT_TRUE(h.ap->adopt_active_profile(kVoip, 1));
    EXPECT_EQ(h.ap->active_profile_id(), kVoip);
    EXPECT_EQ(h.ap->state(), State::MONITORING);
    EXPECT_TRUE(h.ap->switch_history().empty());  // adoption is not a switch
    h.tick();
    EXPECT_TRUE(h.requests.empty());  // baseline adopted: no initial selection

    // Dwell baseline applies from adoption time.
    h.scores[kWebrtc] = 10.0;
    h.advance(1000);
    h.tick();
    EXPECT_TRUE(h.requests.empty());  // dwell blocks improvement
    h.advance(4001);
    h.tick();
    ASSERT_EQ(h.requests.size(), 1u);
    EXPECT_EQ(h.requests.back().first, kWebrtc);
}

TEST(MimicryAutoPilot, RollbackUsesNewTransitionToPreviousStable) {
    Harness h;
    h.register_defaults();
    auto cfg = h.base_config();
    cfg.cooldown_ms = 10;
    cfg.min_dwell_ms = 10;
    h.make_with(cfg);
    ASSERT_EQ(h.drive_initial().first, kVoip);
    EXPECT_FALSE(h.ap->request_rollback());  // no previous stable yet

    h.degrade();
    h.scores[kWebrtc] = 10.0;
    h.advance(200);
    h.tick();
    ASSERT_EQ(h.requests.size(), 2u);
    ASSERT_TRUE(h.ap->commit_transition(kWebrtc, 1));
    ASSERT_TRUE(h.ap->has_previous_stable());

    ASSERT_TRUE(h.ap->request_rollback());
    EXPECT_EQ(h.ap->active_profile_id(), kWebrtc);  // NOT an instant local apply
    h.advance(20);
    h.tick();
    ASSERT_EQ(h.requests.size(), 3u);  // rollback goes through a real request
    EXPECT_EQ(h.requests.back(), std::make_pair(std::string(kVoip), 1u));
    ASSERT_TRUE(h.ap->commit_transition(kVoip, 1));
    EXPECT_EQ(h.ap->active_profile_id(), kVoip);
    EXPECT_TRUE(h.stats_has("\"rollbacks\":1"));
    auto hist = h.ap->switch_history();
    ASSERT_EQ(hist.size(), 3u);
    EXPECT_EQ(hist.back().reason, "rollback");
    EXPECT_EQ(hist.back().to, canon(kVoip, 1));
}

// ══════════════════════════════════════════════════════════════════════════════
// Evidence inputs
// ══════════════════════════════════════════════════════════════════════════════

TEST(MimicryAutoPilot, OneBlockedHostIsNotDeadNetwork) {
    Harness h;
    h.register_defaults();
    auto cfg = h.base_config();
    cfg.mode = Mode::FALLBACK_ONLY;  // isolate the degradation path
    h.make_with(cfg);
    ASSERT_EQ(h.drive_initial().first, kVoip);
    h.scores[kWebrtc] = 10.0;
    h.advance(200);

    // 2 of 3 reference hosts reachable: aggregate healthy, no fallback.
    for (int i = 0; i < 5; ++i)
        EXPECT_TRUE(h.ap->ingest_reference_availability(2, 3));
    h.tick(3);
    EXPECT_EQ(h.requests.size(), 1u);
    EXPECT_EQ(h.ap->state(), State::MONITORING);

    // Malformed availability input rejected.
    EXPECT_FALSE(h.ap->ingest_reference_availability(4, 3));
    EXPECT_FALSE(h.ap->ingest_reference_availability(0, 0));

    // 0 of 3 reachable, repeatedly: degradation aggregate.
    EXPECT_TRUE(h.ap->ingest_reference_availability(0, 3));
    EXPECT_TRUE(h.ap->ingest_reference_availability(0, 3));
    EXPECT_TRUE(h.ap->ingest_reference_availability(0, 3));
    h.tick();
    ASSERT_EQ(h.requests.size(), 2u);
    EXPECT_EQ(h.requests.back().first, kWebrtc);
}

TEST(MimicryAutoPilot, OfflineDpiEvidenceIsNotLiveHealth) {
    Harness h;
    h.register_defaults();
    h.make();
    ASSERT_EQ(h.drive_initial().first, kVoip);
    h.scores[kWebrtc] = 10.0;
    h.advance(200);

    AP::OfflineDpiEvidence ev;
    ev.blocked = true;
    ev.observed_epoch = 1700000000;
    ev.source = "lab-offline-v1";
    h.ap->ingest_offline_dpi_evidence(ev);
    h.ap->ingest_offline_dpi_evidence(ev);
    EXPECT_EQ(h.requests.size(), 1u);  // below failure_threshold
    // Live health EWMA untouched by offline evidence.
    EXPECT_TRUE(h.stats_has("\"ewma_health\":1.000000"));
    EXPECT_TRUE(h.stats_has("\"evidence_blocked_streak\":2"));
    EXPECT_TRUE(h.stats_has("\"offline\":true"));
    EXPECT_TRUE(h.stats_has("lab-offline-v1"));

    h.ap->ingest_offline_dpi_evidence(ev);  // streak reaches threshold
    h.tick();
    ASSERT_EQ(h.requests.size(), 2u);  // offline verdict triggered fallback
    EXPECT_EQ(h.requests.back().first, kWebrtc);

    // A clear verdict resets the streak.
    ev.blocked = false;
    h.ap->ingest_offline_dpi_evidence(ev);
    EXPECT_TRUE(h.stats_has("\"evidence_blocked_streak\":0"));
}

TEST(MimicryAutoPilot, CandidateEvidenceHardGatesAndScoreTerms) {
    Harness h;
    h.register_defaults();
    h.evidence_enabled = true;
    // Hard gate: zoom is MTU-incompatible despite the... (lowest) score anyway;
    // gate the TOP scorer instead: voip fails the rehearsal gate.
    AP::CandidateEvidence bad;
    bad.rehearsal_passed = false;
    h.evidence[kVoip] = bad;
    h.make();
    h.tick();
    ASSERT_EQ(h.requests.size(), 1u);
    EXPECT_EQ(h.requests[0].first, kWebrtc);  // voip gated out
    EXPECT_TRUE(h.ap->abort_transition(h.requests[0].first, 1));
}

TEST(MimicryAutoPilot, GoodputScoreTermCanFlipSelection) {
    Harness h;
    h.register_defaults();
    h.evidence_enabled = true;
    auto cfg = h.base_config();
    cfg.w_goodput = 10.0;
    cfg.goodput_ref_bps = 1e6;
    h.evidence[kWebrtc].goodput_bps = 200000.0;  // +2.0 => 5.0 > voip's 4.0
    h.make_with(cfg);
    h.tick();
    ASSERT_EQ(h.requests.size(), 1u);
    EXPECT_EQ(h.requests[0].first, kWebrtc);  // goodput term flips the winner
    EXPECT_TRUE(h.stats_has("\"candidate_scores\":["));
}

// ══════════════════════════════════════════════════════════════════════════════
// Stats
// ══════════════════════════════════════════════════════════════════════════════

TEST(MimicryAutoPilot, StatsJsonContents) {
    Harness h;
    h.register_defaults();
    h.make();
    ASSERT_EQ(h.drive_initial().first, kVoip);
    const std::string j = h.ap->to_stats_json();
    const char* must[] = {
        "\"enabled\":true",
        "\"mode\":\"auto\"",
        "\"legacy_peer\":false",
        "\"state\":\"monitoring\"",
        "\"active_profile\":\"voip_opus@1\"",
        "\"pending_request\":null",
        "\"previous_stable\":null",
        "\"manual_profile\":null",
        "\"last_reason\":\"initial\"",
        "\"ewma_health\":",
        "\"candidates_considered\":4",
        "\"anti_storm_remaining_ms\":",
        "\"cooldown_remaining_ms\":",
        "\"dwell_remaining_ms\":",
        "\"candidate_scores\":[",
        "\"recent_switches\":[",
        "\"last_offline_dpi_evidence\":null",
        "\"reference_availability\":null",
        "\"switches\":1",
        "\"rollbacks\":0",
        "\"failed_transitions\":0",
    };
    for (const char* frag : must)
        EXPECT_TRUE(j.find(frag) != std::string::npos) << "missing: " << frag;
    // Recent switch recorded with pinned revision.
    EXPECT_NE(j.find("\"to\":\"voip_opus@1\""), std::string::npos);
}

// ══════════════════════════════════════════════════════════════════════════════
// Instance isolation (regression): two independent MimicryAutoPilot instances
// must not cross feedback, cooldown or history state.
// ══════════════════════════════════════════════════════════════════════════════

TEST(MimicryAutoPilot, InstancesDoNotShareFeedbackCooldownOrHistory) {
    Harness h1;
    Harness h2;  // own catalog, own fake clock, own hooks
    h1.register_defaults();
    h2.register_defaults();
    h1.make();
    h2.make();

    // Instance 1: full lifecycle — initial selection, degradation-driven
    // switch, live metrics feedback, and a far-advanced clock.
    ASSERT_EQ(h1.drive_initial().first, kVoip);
    h1.degrade();
    h1.scores[kWebrtc] = 10.0;
    h1.advance(200);  // h1 cooldown + dwell elapsed
    h1.tick();
    ASSERT_EQ(h1.requests.size(), 2u);
    ASSERT_TRUE(h1.ap->commit_transition(kWebrtc, 1));
    ASSERT_EQ(h1.ap->switch_history().size(), 2u);
    AP::UdpMetrics loss;
    loss.loss_ratio = 0.9;
    ASSERT_TRUE(h1.ap->ingest_metrics(loss));
    ASSERT_TRUE(h1.ap->ingest_metrics(loss));  // below failure_threshold (3)
    h1.advance(100000);  // h1's clock far ahead of h2's

    // Instance 2 has seen NONE of that: its own clock is still at 0 and it
    // only performed its own initial selection.
    h2.tick();
    ASSERT_EQ(h2.requests.size(), 1u);
    ASSERT_TRUE(h2.ap->commit_transition(h2.requests[0].first,
                                         h2.requests[0].second));
    EXPECT_EQ(h2.ap->active_profile_id(), kVoip)  // h1's switch didn't leak
        << "h1 switched to webrtc; h2 must keep its own selection";
    auto h2_hist = h2.ap->switch_history();
    ASSERT_EQ(h2_hist.size(), 1u);  // own initial selection only
    EXPECT_EQ(h2_hist[0].reason, "initial");
    EXPECT_TRUE(h2.stats_has("\"samples\":0"))       // no crossed feedback
        << "h1's ingested metrics must not appear in h2";
    EXPECT_TRUE(h2.stats_has("\"ewma_health\":1.000000"));
    EXPECT_EQ(h2.ap->state(), State::MONITORING)     // h1's degradation streak
        << "h1's degradation reports must not degrade h2";

    // h2's cooldown is its own: degradation right after its initial switch
    // (t=0) is gated even though h1's clock is far past every cooldown.
    h2.degrade();
    h2.scores[kZoom] = 10.0;
    h2.tick(3);
    EXPECT_EQ(h2.requests.size(), 1u) << "h2 must honor its own cooldown";
    h2.advance(200);  // h2's own cooldown/dwell elapse
    h2.tick();
    ASSERT_EQ(h2.requests.size(), 2u);
    EXPECT_EQ(h2.requests.back().first, kZoom);

    // And h1 was undisturbed by h2's activity throughout.
    EXPECT_EQ(h1.requests.size(), 2u);
    EXPECT_EQ(h1.ap->switch_history().size(), 2u);
    EXPECT_TRUE(h1.stats_has("\"samples\":2"));
    EXPECT_EQ(h1.ap->active_profile_id(), kWebrtc);
}

// ══════════════════════════════════════════════════════════════════════════════
// Degradation/recovery soak (regression): repeated degrade→switch→recover
// cycles over a fake clock must produce BOUNDED switching — exactly one
// fallback switch per degradation episode and zero switches from healthy
// score noise (no flapping).
// ══════════════════════════════════════════════════════════════════════════════

TEST(MimicryAutoPilot, DegradationRecoverySoakBoundedSwitching) {
    Harness h;
    h.register_defaults();
    auto cfg = h.base_config();
    cfg.mode = Mode::FALLBACK_ONLY;  // switches only on real degradation
    h.make_with(cfg);
    ASSERT_EQ(h.drive_initial().first, kVoip);
    ASSERT_EQ(h.ap->switch_history().size(), 1u);

    const char* order[] = {kWebrtc, kVoip};
    constexpr int kCycles = 12;
    for (int c = 0; c < kCycles; ++c) {
        const std::string cur = h.ap->active_profile_id();
        const char* nxt = order[c % 2];

        // "Recovery" phase: the alternative becomes attractive again while
        // the current profile is HEALTHY — no switch may happen, even with
        // cooldown and dwell fully elapsed.
        h.scores[nxt] = 10.0;
        h.scores[cur] = 1.0;
        h.advance(200);  // cooldown(100) + dwell(50) since the last switch
        h.tick(3);
        EXPECT_EQ(h.requests.size(), 1u + c)
            << "healthy score noise must not switch in cycle " << c;

        // Degradation phase: exactly one fallback switch to the alternative.
        h.degrade();
        h.tick();
        ASSERT_EQ(h.requests.size(), 2u + c) << "cycle " << c;
        EXPECT_EQ(h.requests.back().first, nxt);
        ASSERT_TRUE(h.ap->commit_transition(h.requests.back().first,
                                            h.requests.back().second));
        EXPECT_EQ(h.ap->active_profile_id(), nxt);

        // No new evidence and no elapsed time: repeated ticks must not flap.
        h.tick(5);
        EXPECT_EQ(h.requests.size(), 2u + c)
            << "post-switch ticks must not flap in cycle " << c;
    }

    const auto hist = h.ap->switch_history();
    ASSERT_EQ(hist.size(), 1u + kCycles)  // initial + exactly one per cycle
        << "switching is not bounded: " << hist.size() << " events in "
        << kCycles << " cycles";
    EXPECT_EQ(hist.front().reason, "initial");
    for (size_t i = 1; i < hist.size(); ++i)
        EXPECT_EQ(hist[i].reason, "degradation");
    EXPECT_TRUE(
        h.stats_has("\"switches\":" + std::to_string(1 + kCycles)));
}

// ══════════════════════════════════════════════════════════════════════════════
// Regression (production loopback): with an ADOPTED active profile and
// neutral/equal candidate scores, a degradation streak must still fall back
// to a DIFFERENT eligible profile — hysteresis is an improvement gate, not a
// reason to camp on a dead profile, and the active profile must not be its
// own fallback. Cooldown and the anti-storm floor must still apply.
// ══════════════════════════════════════════════════════════════════════════════

TEST(MimicryAutoPilot, AdoptedActiveEqualScoresDegradationFallsBack) {
    Harness h;
    h.register_defaults();
    for (auto& kv : h.scores) kv.second = 1.0;  // neutral, all equal
    h.make();

    ASSERT_TRUE(h.ap->adopt_active_profile(kVoip, 1));
    EXPECT_TRUE(h.ap->switch_history().empty());  // adoption is not a switch
    h.tick(3);
    EXPECT_TRUE(h.requests.empty());  // adopted baseline: no initial selection

    h.degrade();  // failure_threshold(3) reached → current is dead
    h.tick();
    EXPECT_TRUE(h.requests.empty())
        << "cooldown since adoption must still gate a dead-current fallback";

    h.advance(100);  // cooldown(100) + floor(10) elapsed; dwell bypassed (dead)
    h.tick();
    ASSERT_EQ(h.requests.size(), 1u)
        << "dead current with equal scores must still fall back";
    const auto fb = h.requests.back();
    EXPECT_NE(fb.first, kVoip)
        << "active profile must not be selected as its own fallback";
    EXPECT_TRUE(fb.first == kWebrtc || fb.first == kYoutube ||
                fb.first == kZoom)
        << "fallback target must be an eligible catalog profile";
    EXPECT_EQ(fb.second, 1u);
    EXPECT_EQ(h.ap->active_profile_id(), kVoip);  // requested, not applied yet

    // Anti-storm: an outstanding request means no second request.
    h.tick(3);
    EXPECT_EQ(h.requests.size(), 1u);

    ASSERT_TRUE(h.ap->commit_transition(fb.first, fb.second));
    EXPECT_EQ(h.ap->active_profile_id(), fb.first);
    auto hist = h.ap->switch_history();
    ASSERT_EQ(hist.size(), 1u);
    EXPECT_EQ(hist[0].reason, "degradation");
    EXPECT_EQ(hist[0].from, canon(kVoip, 1));

    // Repeated degradation inside the anti-storm/cooldown window: no flap.
    h.degrade();
    h.tick(3);
    EXPECT_EQ(h.requests.size(), 1u)
        << "anti-storm floor must block an instant re-request";
    h.advance(100);  // floor(10) + cooldown(100) since the committed switch
    h.tick();
    ASSERT_EQ(h.requests.size(), 2u);
    EXPECT_NE(h.requests.back().first, fb.first)
        << "the newly dead profile must fall back to yet another profile";
}

} // namespace
