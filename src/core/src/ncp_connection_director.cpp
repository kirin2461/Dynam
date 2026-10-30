#include "ncp_connection_director.hpp"

/**
 * @file ncp_connection_director.cpp
 * @brief ConnectionDirector implementation. See the header for the full
 *        threading/ownership contract. Internals:
 *
 *  - sessions_ / due queue / control FIFO / inbox: poll-loop thread only.
 *  - requests_ + gates_: guarded by req_mutex_, the ONLY state touched by
 *    foreign threads (RotationCoordinator / MimicryAutoPilot callbacks).
 *  - Cross-thread enqueue pre-checks read a Gate snapshot maintained by the
 *    poll loop; a request can therefore be refused fast (legacy peer, queue
 *    full) without ever touching an adapter off-thread. The poll loop
 *    re-validates at apply time — a stale gate can only turn an ACCEPTED
 *    request into an abort feedback, never into a wrong wire action.
 *  - Read-only telemetry (mimicry_provider()): a SnapshotProvider owning its
 *    own mutex + flattened MimicrySessionView map. The poll loop republishes
 *    the full map (<= max_sessions entries) after each poll() and on session
 *    create/remove. Provider reads copy out under the provider's mutex and
 *    never touch the adapters, so they are safe from ANY thread and remain
 *    valid (reporting the last published snapshot) even while the poll loop
 *    is mid-iteration. The provider owns no reference back to the director,
 *    so director destruction while an observer holds a locked shared_ptr is
 *    safe.
 *  - Stats counters mutated from foreign threads are std::atomic; all other
 *    counters are poll-thread only.
 */

#include <algorithm>
#include <atomic>
#include <utility>

namespace ncp {

const char* NcpConnectionDirector::to_string(Error e) noexcept {
    switch (e) {
        case Error::NONE:              return "none";
        case Error::INVALID_STATE:     return "invalid_state";
        case Error::SESSION_EXISTS:    return "session_exists";
        case Error::NO_SUCH_SESSION:   return "no_such_session";
        case Error::TOO_MANY_SESSIONS: return "too_many_sessions";
        case Error::NOT_ESTABLISHED:   return "not_established";
        case Error::REJECTED:          return "rejected";
    }
    return "unknown";
}

// ============================================================================
// Read-only telemetry provider (published snapshot; see file header)
// ============================================================================

namespace {

/// Flatten one adapter stats snapshot into the public telemetry view.
MimicrySessionView make_view(NcpConnectionDirector::SessionId id,
                             const NcpMimicrySession::Stats& st) {
    MimicrySessionView v;
    v.session_id = id;
    v.established = st.established;
    v.transition_capable = st.transition_capable;
    v.transition_state = st.transition_state;
    v.active_profile_id = st.active_profile.id;
    v.active_profile_revision = st.active_profile.revision;
    v.has_pending_profile = st.pending_profile.has_value();
    if (st.pending_profile) {
        v.pending_profile_id = st.pending_profile->id;
        v.pending_profile_revision = st.pending_profile->revision;
    }
    v.profile_epoch = st.profile_epoch;
    v.crypto_epoch = st.crypto_epoch;
    v.transitions_effective = st.transition_counters.transitions_effective;
    v.transitions_aborted = st.transition_counters.transitions_aborted;
    v.transitions_timed_out = st.transition_counters.transitions_timed_out;
    v.e2e_messages_sent = st.e2e_messages_sent;
    v.e2e_messages_received = st.e2e_messages_received;
    v.mtu_budget_rejections = st.mtu_budget_rejections;
    v.ingress_dropped = st.ingress_dropped;
    return v;
}

/// Self-contained snapshot store implementing IMimicrySessionProvider.
/// Owns its own mutex + map and holds NO reference back to the director, so
/// it stays valid for observers that outlive the director via shared_ptr.
class SnapshotProvider final : public IMimicrySessionProvider {
public:
    /// Poll thread: republish the complete view set (<= max_sessions).
    void publish(std::unordered_map<uint64_t, MimicrySessionView> views) {
        std::lock_guard<std::mutex> lk(mutex_);
        views_ = std::move(views);
    }

    std::vector<MimicrySessionView> list_sessions() const override {
        std::lock_guard<std::mutex> lk(mutex_);
        std::vector<MimicrySessionView> out;
        out.reserve(views_.size());
        for (const auto& kv : views_) out.push_back(kv.second);
        return out;
    }

    std::optional<MimicrySessionView> session(
        uint64_t session_id) const override {
        std::lock_guard<std::mutex> lk(mutex_);
        const auto it = views_.find(session_id);
        if (it == views_.end()) return std::nullopt;
        return it->second;
    }

private:
    mutable std::mutex mutex_;
    std::unordered_map<uint64_t, MimicrySessionView> views_;
};

} // namespace

// ============================================================================
// Impl
// ============================================================================

struct NcpConnectionDirector::Impl {
    struct Request {
        enum class Kind : uint8_t { ProfileTransition, KeyRotation };
        Kind kind = Kind::ProfileTransition;
        SessionId session_id = 0;
        std::string profile_id;
        uint32_t revision = 0;
        DPI::RotationLayer layer = DPI::RotationLayer::L7_TIMING;
    };

    /// Cross-thread visibility snapshot; the ONLY session state readable
    /// from foreign threads (under req_mutex_). Poll-loop maintained.
    struct Gate {
        bool exists = false;
        bool established = false;
        bool transition_capable = false;
        bool feedback_pending = false;  ///< director-requested transition open
    };

    struct SessionEntry {
        std::unique_ptr<NcpMimicrySession> adapter;
        // Director-requested transition tracking (poll thread only).
        bool fb_pending = false;
        std::string fb_profile_id;
        uint32_t fb_revision = 0;
        uint64_t fb_base_effective = 0;
        uint64_t fb_base_aborted = 0;
        uint64_t fb_base_timeouts = 0;
        uint64_t fb_deadline_ms = 0;
    };

    struct DueItem {
        uint64_t due_ms = 0;
        uint64_t seq = 0;
        Egress egress;
    };
    struct DueLater {
        bool operator()(const DueItem& a, const DueItem& b) const {
            if (a.due_ms != b.due_ms) return a.due_ms > b.due_ms;
            return a.seq > b.seq;  // FIFO within the same due time
        }
    };

    explicit Impl(Config c) : cfg(std::move(c)) {}

    Config cfg;
    bool valid = false;
    std::string config_error;

    // ---- poll-thread state ----
    std::unordered_map<SessionId, SessionEntry> sessions;
    std::priority_queue<DueItem, std::vector<DueItem>, DueLater> due_q;
    std::deque<Egress> control_q;
    std::deque<AppData> inbox;
    uint64_t due_seq = 0;
    TransitionCommittedCb committed_cb;
    TransitionAbortedCb aborted_cb;

    // ---- cross-thread state (req_mutex_) ----
    std::mutex req_mutex;
    std::deque<Request> requests;  // bounded by cfg.max_pending_requests
    std::unordered_map<SessionId, Gate> gates;

    // ---- read-only telemetry (own mutex; any-thread readers) ----
    std::shared_ptr<SnapshotProvider> provider =
        std::make_shared<SnapshotProvider>();

    // ---- counters: poll-thread only ----
    uint64_t sessions_created = 0;
    uint64_t sessions_removed = 0;
    uint64_t session_create_rejected = 0;
    uint64_t requests_applied = 0;
    uint64_t requests_failed = 0;
    uint64_t rotations_applied = 0;
    uint64_t datagrams_in = 0;
    uint64_t datagrams_out = 0;
    uint64_t app_messages_in = 0;
    uint64_t app_messages_out = 0;
    uint64_t inbox_dropped = 0;
    uint64_t due_dropped_overflow = 0;
    uint64_t control_dropped_overflow = 0;
    uint64_t ingress_unknown_session = 0;
    uint64_t transition_commits_reported = 0;
    uint64_t transition_aborts_reported = 0;
    uint64_t transition_feedback_timeouts = 0;
    // ---- counters: mutated from foreign threads ----
    std::atomic<uint64_t> requests_enqueued{0};
    std::atomic<uint64_t> requests_dropped_full{0};
    std::atomic<uint64_t> rotations_enqueued{0};
    std::atomic<uint64_t> l2_rotations_ignored{0};

    bool server_role() const {
        return cfg.session_template.role == NcpMimicrySession::Role::Server;
    }

    SessionEntry* find(SessionId id) {
        auto it = sessions.find(id);
        return it == sessions.end() ? nullptr : &it->second;
    }
    const SessionEntry* find(SessionId id) const {
        auto it = sessions.find(id);
        return it == sessions.end() ? nullptr : &it->second;
    }

    // ---- gate snapshot maintenance (poll thread; takes req_mutex_) ----

    void gate_insert(SessionId id) {
        std::lock_guard<std::mutex> lk(req_mutex);
        gates[id] = Gate{true, false, false, false};
    }

    void gate_erase(SessionId id) {
        std::lock_guard<std::mutex> lk(req_mutex);
        gates.erase(id);
    }

    void gate_clear_feedback(SessionId id) {
        std::lock_guard<std::mutex> lk(req_mutex);
        auto it = gates.find(id);
        if (it != gates.end()) it->second.feedback_pending = false;
    }

    /// Refresh exists/established/transition_capable for every live session.
    /// feedback_pending is owned by the request path and left untouched.
    void refresh_gates() {
        std::lock_guard<std::mutex> lk(req_mutex);
        for (auto& kv : sessions) {
            Gate& g = gates[kv.first];
            g.exists = true;
            g.established = kv.second.adapter->is_established();
            g.transition_capable = kv.second.adapter->transition_capable();
        }
    }

    /// Poll thread: republish the complete flattened telemetry snapshot
    /// (<= max_sessions entries; trivial cost). Runs after each poll() and
    /// on session create/remove so observers never see a stale registry.
    void publish_views() {
        std::unordered_map<SessionId, MimicrySessionView> views;
        views.reserve(sessions.size());
        for (const auto& kv : sessions)
            views.emplace(kv.first, make_view(kv.first, kv.second.adapter->stats()));
        provider->publish(std::move(views));
    }

    // ---- outbound scheduling (poll thread) ----

    /// Control is prioritized and never paced; data honors pacing_delay via
    /// the bounded due queue. Overflow is counted, never silent.
    void schedule(SessionId id, NcpMimicrySession::OutboundDatagram o,
                  uint64_t now_ms) {
        Egress e;
        e.session_id = id;
        e.bytes = std::move(o.bytes);
        e.is_control = o.is_control;
        e.profile_epoch = o.profile_epoch;
        if (e.is_control) {
            if (control_q.size() >= cfg.max_control_queue) {
                ++control_dropped_overflow;
                return;
            }
            control_q.push_back(std::move(e));
            return;
        }
        if (due_q.size() >= cfg.max_due_datagrams) {
            ++due_dropped_overflow;
            return;
        }
        const int64_t d = o.pacing_delay.count();
        const uint64_t delay = d > 0 ? static_cast<uint64_t>(d) : 0;
        due_q.push(DueItem{now_ms + delay, due_seq++, std::move(e)});
    }

    void drain_adapter_outbound(SessionId id, SessionEntry& se,
                                uint64_t now_ms) {
        while (auto o = se.adapter->next_outbound())
            schedule(id, std::move(*o), now_ms);
    }

    // ---- feedback (poll thread) ----

    void fire_committed(SessionId id, const std::string& pid, uint32_t rev) {
        ++transition_commits_reported;
        if (committed_cb) committed_cb(id, pid, rev);
    }

    void fire_aborted(SessionId id, const std::string& pid, uint32_t rev,
                      AbortReason reason) {
        ++transition_aborts_reported;
        if (aborted_cb) aborted_cb(id, pid, rev, reason);
    }

    /// Resolve an open director-requested transition: commit feedback once
    /// the adapter reports it effective, abort feedback on adapter
    /// abort/timeout or on the director-level backstop deadline.
    void check_feedback(uint64_t now_ms) {
        for (auto& kv : sessions) {
            SessionEntry& se = kv.second;
            if (!se.fb_pending) continue;
            const auto st = se.adapter->stats();
            if (st.transition_counters.transitions_effective >
                se.fb_base_effective) {
                se.fb_pending = false;
                gate_clear_feedback(kv.first);
                fire_committed(kv.first, se.fb_profile_id, se.fb_revision);
                continue;
            }
            if (st.transition_counters.transitions_aborted >
                    se.fb_base_aborted ||
                st.transition_counters.transitions_timed_out >
                    se.fb_base_timeouts) {
                se.fb_pending = false;
                gate_clear_feedback(kv.first);
                fire_aborted(kv.first, se.fb_profile_id, se.fb_revision,
                             AbortReason::TIMEOUT);
                continue;
            }
            if (now_ms >= se.fb_deadline_ms) {
                // Backstop: the adapter FSM did not resolve in time. Abort
                // locally (safe pre-activation) and report.
                se.adapter->abort_transition(AbortReason::TIMEOUT, now_ms);
                se.fb_pending = false;
                gate_clear_feedback(kv.first);
                ++transition_feedback_timeouts;
                fire_aborted(kv.first, se.fb_profile_id, se.fb_revision,
                             AbortReason::TIMEOUT);
            }
        }
    }

    // ---- request drain (poll thread) ----

    void apply_transition(SessionId id, const std::string& pid, uint32_t rev,
                          uint64_t now_ms) {
        SessionEntry* se = find(id);
        if (!se) {
            ++requests_failed;
            fire_aborted(id, pid, rev, AbortReason::PROTOCOL_ERROR);
            return;
        }
        const TransitionError err =
            se->adapter->start_profile_transition(pid, rev, now_ms);
        if (err == TransitionError::NONE) {
            ++requests_applied;
            const auto st = se->adapter->stats();
            se->fb_pending = true;
            se->fb_profile_id = pid;
            se->fb_revision = rev;
            se->fb_base_effective = st.transition_counters.transitions_effective;
            se->fb_base_aborted = st.transition_counters.transitions_aborted;
            se->fb_base_timeouts = st.transition_counters.transitions_timed_out;
            se->fb_deadline_ms = now_ms + cfg.transition_feedback_timeout_ms;
            drain_adapter_outbound(id, *se, now_ms);
            return;
        }
        ++requests_failed;
        // An ACCEPTED request must still resolve so the requester (e.g.
        // MimicryAutoPilot) is never left with a dangling outstanding.
        AbortReason reason = AbortReason::PROTOCOL_ERROR;
        if (err == TransitionError::BUSY) reason = AbortReason::PEER_BUSY;
        else if (err == TransitionError::INVALID_PROFILE)
            reason = AbortReason::UNKNOWN_PROFILE;
        gate_clear_feedback(id);
        fire_aborted(id, pid, rev, reason);
    }

    /// L7 rotation: per-session E2E key rotation on established sessions.
    /// The crypto epoch bump is per-session; the PortHop L2 hop epoch is
    /// never touched here.
    void apply_rotation() {
        for (auto& kv : sessions) {
            if (kv.second.adapter->is_established() &&
                kv.second.adapter->rotate_e2e_keys()) {
                ++rotations_applied;
            }
        }
    }

    void drain_requests(uint64_t now_ms) {
        std::deque<Request> pending;
        {
            std::lock_guard<std::mutex> lk(req_mutex);
            pending.swap(requests);
        }
        for (const Request& r : pending) {
            if (r.kind == Request::Kind::ProfileTransition)
                apply_transition(r.session_id, r.profile_id, r.revision,
                                 now_ms);
            else
                apply_rotation();
        }
    }
};

// ============================================================================
// Construction / validation
// ============================================================================

NcpConnectionDirector::NcpConnectionDirector(Config cfg)
    : impl_(new Impl(std::move(cfg))) {
    auto fail = [&](const char* msg) {
        impl_->valid = false;
        impl_->config_error = msg;
    };
    if (impl_->cfg.max_sessions == 0) {
        fail("NcpConnectionDirector: max_sessions must be >= 1");
    } else if (impl_->cfg.max_pending_requests == 0) {
        fail("NcpConnectionDirector: max_pending_requests must be >= 1");
    } else if (impl_->cfg.max_due_datagrams == 0) {
        fail("NcpConnectionDirector: max_due_datagrams must be >= 1");
    } else if (impl_->cfg.max_control_queue == 0) {
        fail("NcpConnectionDirector: max_control_queue must be >= 1");
    } else if (impl_->cfg.max_inbox == 0) {
        fail("NcpConnectionDirector: max_inbox must be >= 1");
    } else if (impl_->cfg.transition_feedback_timeout_ms == 0) {
        fail("NcpConnectionDirector: transition_feedback_timeout_ms must be > 0");
    } else if (!impl_->cfg.session_template.stable_profile.valid()) {
        fail("NcpConnectionDirector: session_template.stable_profile is invalid "
             "(empty or oversized profile id)");
    } else {
        impl_->valid = true;
    }
}

NcpConnectionDirector::~NcpConnectionDirector() { delete impl_; }

bool NcpConnectionDirector::is_valid() const { return impl_->valid; }

const std::string& NcpConnectionDirector::config_error() const {
    return impl_->config_error;
}

NcpMimicrySession::Role NcpConnectionDirector::role() const {
    return impl_->cfg.session_template.role;
}

// ============================================================================
// Registry (poll thread)
// ============================================================================

NcpConnectionDirector::Error NcpConnectionDirector::add_session(SessionId id) {
    if (!impl_->valid) return Error::INVALID_STATE;
    if (impl_->sessions.count(id) != 0) return Error::SESSION_EXISTS;
    if (impl_->sessions.size() >= impl_->cfg.max_sessions) {
        ++impl_->session_create_rejected;
        return Error::TOO_MANY_SESSIONS;
    }
    NcpMimicrySession::Config scfg = impl_->cfg.session_template;  // copy
    std::unique_ptr<NcpMimicrySession> adapter;
    try {
        adapter.reset(new NcpMimicrySession(std::move(scfg)));
    } catch (...) {
        ++impl_->session_create_rejected;
        return Error::REJECTED;
    }
    Impl::SessionEntry se;
    se.adapter = std::move(adapter);
    impl_->sessions.emplace(id, std::move(se));
    impl_->gate_insert(id);
    ++impl_->sessions_created;
    impl_->publish_views();
    return Error::NONE;
}

NcpConnectionDirector::Error NcpConnectionDirector::remove_session(
    SessionId id) {
    if (!impl_->valid) return Error::INVALID_STATE;
    auto it = impl_->sessions.find(id);
    if (it == impl_->sessions.end()) return Error::NO_SUCH_SESSION;
    impl_->sessions.erase(it);
    impl_->gate_erase(id);
    ++impl_->sessions_removed;
    impl_->publish_views();
    return Error::NONE;
}

bool NcpConnectionDirector::has_session(SessionId id) const {
    return impl_->sessions.count(id) != 0;
}

size_t NcpConnectionDirector::session_count() const {
    return impl_->sessions.size();
}

std::vector<NcpConnectionDirector::SessionId>
NcpConnectionDirector::session_ids() const {
    std::vector<SessionId> out;
    out.reserve(impl_->sessions.size());
    for (const auto& kv : impl_->sessions) out.push_back(kv.first);
    std::sort(out.begin(), out.end());
    return out;
}

// ============================================================================
// Data plane (poll thread)
// ============================================================================

NcpConnectionDirector::Error NcpConnectionDirector::start_handshake(
    SessionId id, uint64_t now_ms) {
    if (!impl_->valid) return Error::INVALID_STATE;
    auto* se = impl_->find(id);
    if (!se) return Error::NO_SUCH_SESSION;
    auto o = se->adapter->start_handshake();
    if (!o) return Error::INVALID_STATE;  // server role or already initiated
    // The handshake datagram is a priority control-style emission.
    o->is_control = true;
    impl_->schedule(id, std::move(*o), now_ms);
    return Error::NONE;
}

bool NcpConnectionDirector::is_established(SessionId id) const {
    const auto* se = impl_->find(id);
    return se && se->adapter->is_established();
}

void NcpConnectionDirector::on_datagram(SessionId id, const uint8_t* data,
                                        size_t len, uint64_t now_ms) {
    if (!impl_->valid || !data || len == 0) return;
    Impl::SessionEntry* se = impl_->find(id);
    if (!se) {
        // Server role auto-accepts new sessions on first ingress (bounded);
        // the transport (PortHopServer) already whitelisted the session id.
        if (!impl_->server_role() || !impl_->cfg.auto_accept_sessions ||
            add_session(id) != Error::NONE) {
            ++impl_->ingress_unknown_session;
            return;
        }
        se = impl_->find(id);
    }
    ++impl_->datagrams_in;
    const auto r = se->adapter->on_datagram(data, len, now_ms);
    if (r.kind == NcpMimicrySession::IngressKind::Data && r.app_payload &&
        !r.insecure_plaintext) {
        // Protected application data only; pre-handshake plaintext compat
        // datagrams are never surfaced to the application inbox.
        ++impl_->app_messages_in;
        if (impl_->inbox.size() >= impl_->cfg.max_inbox) {
            ++impl_->inbox_dropped;
        } else {
            AppData a;
            a.session_id = id;
            a.payload = std::move(*r.app_payload);
            impl_->inbox.push_back(std::move(a));
        }
    }
    impl_->drain_adapter_outbound(id, *se, now_ms);
}

NcpConnectionDirector::Error NcpConnectionDirector::send_application(
    SessionId id, const std::vector<uint8_t>& payload, uint64_t now_ms) {
    if (!impl_->valid) return Error::INVALID_STATE;
    auto* se = impl_->find(id);
    if (!se) return Error::NO_SUCH_SESSION;
    if (!se->adapter->is_established()) return Error::NOT_ESTABLISHED;
    auto o = se->adapter->send_application(payload, now_ms);
    if (!o) return Error::REJECTED;  // budget violation counted by adapter
    impl_->schedule(id, std::move(*o), now_ms);
    ++impl_->app_messages_out;
    return Error::NONE;
}

std::vector<NcpConnectionDirector::Egress> NcpConnectionDirector::poll(
    uint64_t now_ms) {
    std::vector<Egress> out;
    if (!impl_->valid) return out;

    // 1. Apply cross-thread requests (bounded by the queue size).
    impl_->drain_requests(now_ms);

    // 2. Tick every adapter (retransmissions / grace windows / FSM
    //    finalization) and collect queued reactions.
    for (auto& kv : impl_->sessions) {
        kv.second.adapter->tick(now_ms);
        impl_->drain_adapter_outbound(kv.first, kv.second, now_ms);
    }

    // 3. Resolve commit/rollback feedback for requested transitions.
    impl_->check_feedback(now_ms);

    // 4. Publish the cross-thread gate snapshot + the read-only telemetry
    //    snapshot (session views for mimicry_provider() observers).
    impl_->refresh_gates();
    impl_->publish_views();

    // 5. Emit: control first (prioritized, never paced), then paced data
    //    that is due.
    out.reserve(impl_->control_q.size());
    while (!impl_->control_q.empty()) {
        out.push_back(std::move(impl_->control_q.front()));
        impl_->control_q.pop_front();
    }
    while (!impl_->due_q.empty() && impl_->due_q.top().due_ms <= now_ms) {
        out.push_back(std::move(impl_->due_q.top().egress));
        impl_->due_q.pop();
    }
    impl_->datagrams_out += out.size();
    return out;
}

std::optional<NcpConnectionDirector::AppData>
NcpConnectionDirector::next_application_data() {
    if (impl_->inbox.empty()) return std::nullopt;
    AppData a = std::move(impl_->inbox.front());
    impl_->inbox.pop_front();
    return a;
}

std::optional<NcpMimicrySession::Stats> NcpConnectionDirector::session_stats(
    SessionId id) const {
    const auto* se = impl_->find(id);
    if (!se) return std::nullopt;
    return se->adapter->stats();
}

std::shared_ptr<const IMimicrySessionProvider>
NcpConnectionDirector::mimicry_provider() const {
    return impl_->provider;
}

std::string NcpConnectionDirector::session_e2e_id(SessionId id) const {
    const auto* se = impl_->find(id);
    if (!se) return {};
    return se->adapter->e2e_session_id();
}

NcpConnectionDirector::Stats NcpConnectionDirector::stats() const {
    Stats s;
    s.sessions_created = impl_->sessions_created;
    s.sessions_removed = impl_->sessions_removed;
    s.session_create_rejected = impl_->session_create_rejected;
    s.requests_enqueued = impl_->requests_enqueued.load();
    s.requests_dropped_full = impl_->requests_dropped_full.load();
    s.requests_applied = impl_->requests_applied;
    s.requests_failed = impl_->requests_failed;
    s.rotations_enqueued = impl_->rotations_enqueued.load();
    s.rotations_applied = impl_->rotations_applied;
    s.l2_rotations_ignored = impl_->l2_rotations_ignored.load();
    s.datagrams_in = impl_->datagrams_in;
    s.datagrams_out = impl_->datagrams_out;
    s.app_messages_in = impl_->app_messages_in;
    s.app_messages_out = impl_->app_messages_out;
    s.inbox_dropped = impl_->inbox_dropped;
    s.due_dropped_overflow = impl_->due_dropped_overflow;
    s.control_dropped_overflow = impl_->control_dropped_overflow;
    s.ingress_unknown_session = impl_->ingress_unknown_session;
    s.transition_commits_reported = impl_->transition_commits_reported;
    s.transition_aborts_reported = impl_->transition_aborts_reported;
    s.transition_feedback_timeouts = impl_->transition_feedback_timeouts;
    return s;
}

// ============================================================================
// Cross-thread request API (any thread; enqueue only — see header)
// ============================================================================

MimicryAutoPilot::TransitionResult
NcpConnectionDirector::enqueue_profile_transition(
    SessionId id, const std::string& profile_id, uint32_t revision) {
    using TR = MimicryAutoPilot::TransitionResult;
    if (!impl_->valid) return TR::DISABLED;

    // Resolve the target against the READ-ONLY catalog (catalog must not be
    // mutated while requests may be enqueued — see header contract).
    uint32_t rev = revision;
    const auto* catalog = impl_->cfg.session_template.catalog;
    if (catalog) {
        const ProfileDescriptor* d =
            rev == 0 ? catalog->find_latest(profile_id)
                     : catalog->find(profile_id, rev);
        if (!d) return TR::INVALID_PROFILE;
        rev = d->revision;
    }

    std::lock_guard<std::mutex> lk(impl_->req_mutex);
    const auto git = impl_->gates.find(id);
    if (git == impl_->gates.end() || !git->second.exists)
        return TR::BUSY;  // may appear later; retryable
    if (!git->second.established)
        return TR::BUSY;  // handshake in flight; retryable
    if (!git->second.transition_capable)
        return TR::NOT_SUPPORTED;  // legacy peer: never emit control
    if (git->second.feedback_pending)
        return TR::BUSY;  // one outstanding director-requested transition
    if (impl_->requests.size() >= impl_->cfg.max_pending_requests) {
        ++impl_->requests_dropped_full;
        return TR::BUSY;
    }
    Impl::Request r;
    r.kind = Impl::Request::Kind::ProfileTransition;
    r.session_id = id;
    r.profile_id = profile_id;
    r.revision = rev;
    impl_->requests.push_back(std::move(r));
    // Reserve the slot immediately so concurrent enqueues see the
    // outstanding transition before the poll loop applies it.
    impl_->gates[id].feedback_pending = true;
    ++impl_->requests_enqueued;
    return TR::ACCEPTED;
}

bool NcpConnectionDirector::enqueue_key_rotation(DPI::RotationLayer layer) {
    if (!impl_->valid) return false;
    if (layer == DPI::RotationLayer::L2_IDENTITY) {
        // PortHop owns the L2 hop epoch; acknowledged and ignored by design.
        ++impl_->l2_rotations_ignored;
        return true;
    }
    std::lock_guard<std::mutex> lk(impl_->req_mutex);
    if (impl_->requests.size() >= impl_->cfg.max_pending_requests) {
        ++impl_->requests_dropped_full;
        return false;
    }
    Impl::Request r;
    r.kind = Impl::Request::Kind::KeyRotation;
    r.layer = layer;
    impl_->requests.push_back(std::move(r));
    ++impl_->rotations_enqueued;
    return true;
}

std::function<MimicryAutoPilot::TransitionResult(const std::string&, uint32_t)>
NcpConnectionDirector::transition_request_handler(SessionId id) {
    return [this, id](const std::string& profile_id, uint32_t revision) {
        return this->enqueue_profile_transition(id, profile_id, revision);
    };
}

DPI::RotationCallback NcpConnectionDirector::rotation_callback() {
    return [this](DPI::RotationLayer layer) {
        this->enqueue_key_rotation(layer);
    };
}

void NcpConnectionDirector::set_transition_feedback(
    TransitionCommittedCb committed, TransitionAbortedCb aborted) {
    impl_->committed_cb = std::move(committed);
    impl_->aborted_cb = std::move(aborted);
}

} // namespace ncp
