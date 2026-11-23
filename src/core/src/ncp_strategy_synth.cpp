#include "ncp_strategy_synth.hpp"

#include <algorithm>
#include <numeric>

namespace ncp {
namespace DPI {

namespace {

// TTL for fakes that must reach the DPI box; the server drops them anyway
// because of the fooling (bad seq / bad checksum).
constexpr int kFoolingFakeTtl = 8;
// TTL for fakes that must expire before the server, with no other fooling.
constexpr int kLowFakeTtl = 3;

// Wrap-around-safe "a >= b" for TCP sequence numbers.
bool seq_at_or_after(uint32_t a, uint32_t b) noexcept {
    return static_cast<int32_t>(a - b) >= 0;
}

const char* split_name(SplitGene g) {
    switch (g) {
        case SplitGene::Keep:   return "keep";
        case SplitGene::Sni:    return "sni";
        case SplitGene::Midsld: return "midsld";
        case SplitGene::Pos1:   return "pos1";
        case SplitGene::Multi:  return "multi";
    }
    return "?";
}

const char* order_name(OrderGene g) {
    switch (g) {
        case OrderGene::Keep:     return "keep";
        case OrderGene::InOrder:  return "in-order";
        case OrderGene::Disorder: return "disorder";
        case OrderGene::Reverse:  return "reverse";
    }
    return "?";
}

const char* fake_name(FakeGene g) {
    switch (g) {
        case FakeGene::Keep:   return "keep";
        case FakeGene::None:   return "no-fake";
        case FakeGene::Badseq: return "fake-badseq";
        case FakeGene::Badsum: return "fake-badsum";
        case FakeGene::LowTtl: return "fake-lowttl";
    }
    return "?";
}

} // namespace

std::string StrategyGenes::name() const {
    if (split == SplitGene::Keep && order == OrderGene::Keep && fake == FakeGene::Keep) {
        return "preset";
    }
    return std::string(split_name(split)) + "/" + order_name(order) + "/" + fake_name(fake);
}

void apply_genes(const StrategyGenes& genes, DPIConfig& cfg) {
    switch (genes.split) {
        case SplitGene::Keep:
            break;
        case SplitGene::Sni:
            cfg.enable_tcp_split = true;
            cfg.split_at_sni = true;
            cfg.split_at_midsld = false;
            cfg.enable_multi_layer_split = false;
            cfg.split_positions.clear();
            break;
        case SplitGene::Midsld:
            cfg.enable_tcp_split = true;
            cfg.split_at_sni = true;  // midsld is located relative to the SNI
            cfg.split_at_midsld = true;
            cfg.enable_multi_layer_split = false;
            cfg.split_positions.clear();
            break;
        case SplitGene::Pos1:
            cfg.enable_tcp_split = true;
            cfg.split_at_sni = false;
            cfg.split_at_midsld = false;
            cfg.split_position = 1;
            cfg.enable_multi_layer_split = false;
            cfg.split_positions.clear();
            break;
        case SplitGene::Multi:
            cfg.enable_tcp_split = true;
            cfg.split_at_sni = true;
            cfg.split_at_midsld = true;
            cfg.enable_multi_layer_split = true;
            cfg.split_positions.clear();
            break;
    }

    switch (genes.order) {
        case OrderGene::Keep:
            break;
        case OrderGene::InOrder:
            cfg.enable_disorder = false;
            cfg.enable_reverse_frag = false;
            break;
        case OrderGene::Disorder:
            cfg.enable_disorder = true;
            cfg.enable_reverse_frag = false;
            break;
        case OrderGene::Reverse:
            // disorder takes precedence in the send path, so it must be off
            cfg.enable_disorder = false;
            cfg.enable_reverse_frag = true;
            break;
    }

    if (genes.fake != FakeGene::Keep) {
        // An explicit fake gene owns the TTL: auto-derivation would override it.
        cfg.enable_autottl = false;
        cfg.randomize_fake_ttl = false;
        cfg.fake_repeats = 1;
    }
    switch (genes.fake) {
        case FakeGene::Keep:
            break;
        case FakeGene::None:
            cfg.enable_fake_packet = false;
            cfg.fake_fooling = 0;
            break;
        case FakeGene::Badseq:
            cfg.enable_fake_packet = true;
            cfg.fake_fooling = 2;
            cfg.fake_ttl = kFoolingFakeTtl;
            break;
        case FakeGene::Badsum:
            cfg.enable_fake_packet = true;
            cfg.fake_fooling = 1;
            cfg.fake_ttl = kFoolingFakeTtl;
            break;
        case FakeGene::LowTtl:
            cfg.enable_fake_packet = true;
            cfg.fake_fooling = 0;
            cfg.fake_ttl = kLowFakeTtl;
            break;
    }
}

std::vector<StrategyGenes> synthesized_strategy_ladder() {
    using S = SplitGene;
    using O = OrderGene;
    using F = FakeGene;
    return {
        {S::Sni,    O::InOrder,  F::None},
        {S::Midsld, O::InOrder,  F::None},
        {S::Pos1,   O::InOrder,  F::None},
        {S::Sni,    O::InOrder,  F::Badseq},
        {S::Sni,    O::Disorder, F::None},
        {S::Multi,  O::InOrder,  F::None},
        {S::Midsld, O::InOrder,  F::Badseq},
        {S::Sni,    O::Disorder, F::Badseq},
        {S::Pos1,   O::Disorder, F::LowTtl},
        {S::Multi,  O::Reverse,  F::Badseq},
        {S::Sni,    O::InOrder,  F::Badsum},
        {S::Multi,  O::Disorder, F::Badsum},
    };
}

std::vector<StrategyGenes> preset_with_in_order_fallback() {
    return {
        {SplitGene::Keep, OrderGene::Keep, FakeGene::Keep},
        {SplitGene::Sni, OrderGene::InOrder, FakeGene::None},
    };
}

// ===== StrategySynthesizer =====

StrategySynthesizer::StrategySynthesizer(std::vector<StrategyGenes> candidates) {
    set_candidates(std::move(candidates));
}

void StrategySynthesizer::set_candidates(std::vector<StrategyGenes> candidates) {
    if (candidates.size() > kMaxCandidates) candidates.resize(kMaxCandidates);
    if (candidates.empty()) candidates.push_back(StrategyGenes{});
    candidates_ = std::move(candidates);
    clear();
}

void StrategySynthesizer::clear() {
    stats_.assign(candidates_.size(), CandidateStats{});
    dests_.clear();
    flows_.clear();
    switches_ = 0;
    wins_ = 0;
    failures_ = 0;
}

double StrategySynthesizer::global_score(int candidate) const {
    if (candidate < 0 || static_cast<size_t>(candidate) >= stats_.size()) return 0.0;
    const auto& s = stats_[static_cast<size_t>(candidate)];
    return (static_cast<double>(s.wins) + 1.0) /
           (static_cast<double>(s.wins + s.fails) + 2.0);
}

std::vector<int> StrategySynthesizer::ranking_() const {
    std::vector<int> order(candidates_.size());
    std::iota(order.begin(), order.end(), 0);
    // Stable: equal scores keep the prior (ladder) order.
    std::stable_sort(order.begin(), order.end(), [this](int a, int b) {
        return global_score(a) > global_score(b);
    });
    return order;
}

int StrategySynthesizer::locked_candidate(const std::string& destination) const {
    auto it = dests_.find(destination);
    return it == dests_.end() ? -1 : it->second.locked;
}

void StrategySynthesizer::expire_(Clock::time_point now) {
    for (auto it = flows_.begin(); it != flows_.end();) {
        if (now - it->second.last_sent > kFlowLifetime) it = flows_.erase(it);
        else ++it;
    }
    if (dest_ttl_.count() > 0) {
        for (auto it = dests_.begin(); it != dests_.end();) {
            if (now - it->second.seen > dest_ttl_) it = dests_.erase(it);
            else ++it;
        }
    }
}

StrategySynthesizer::Dest& StrategySynthesizer::dest_for_(const std::string& destination,
                                                          Clock::time_point now) {
    auto it = dests_.find(destination);
    if (it == dests_.end()) {
        if (dests_.size() >= max_dests_) {
            auto oldest = dests_.begin();
            for (auto j = dests_.begin(); j != dests_.end(); ++j) {
                if (j->second.seen < oldest->second.seen) oldest = j;
            }
            dests_.erase(oldest);
        }
        it = dests_.emplace(destination, Dest{}).first;
    }
    it->second.seen = now;
    return it->second;
}

int StrategySynthesizer::pick_(Dest& d, bool& switched, bool& exhausted) {
    if (d.locked >= 0) return d.locked;
    if (d.current >= 0) return d.current;

    const std::vector<int> order = ranking_();
    auto next_untried = [&]() -> int {
        for (int idx : order) {
            if (!((d.tried >> idx) & 1u)) return idx;
        }
        return -1;
    };

    int idx = next_untried();
    if (idx < 0) {
        // Every candidate failed here.  Start another round instead of
        // freezing on one: paths change, and a candidate may have failed only
        // because of what an earlier attempt did to the DPI's state.
        if (!d.exhausted) exhausted = true;
        d.exhausted = true;
        d.tried = 0;
        idx = next_untried();
    }

    switched = d.attempts > 0;
    if (switched) ++switches_;
    d.current = idx;
    ++d.attempts;
    return idx;
}

void StrategySynthesizer::fail_(const Flow& f) {
    ++failures_;
    // Only the candidate a flow was opened with had a clean trial; later ones
    // ran on retransmissions after the DPI had already seen the flow.
    const bool clean = f.candidate == f.first_candidate;
    if (clean && static_cast<size_t>(f.candidate) < stats_.size()) {
        ++stats_[static_cast<size_t>(f.candidate)].fails;
    }

    auto it = dests_.find(f.dest);
    if (it == dests_.end() || !clean) return;
    Dest& d = it->second;

    if (d.locked == f.candidate) {
        // A proven candidate gets a second chance: one silent flow can be the
        // application's doing, two in a row are the network's.
        if (++d.locked_failures >= kLockedFailuresToUnlock) {
            d.locked = -1;
            d.locked_failures = 0;
            d.current = -1;
            d.tried |= (uint64_t{1} << f.candidate);
        }
        return;
    }
    // Parallel flows of the same trial fail together: only the first one moves
    // the destination on, the rest must not skip the next candidate untried.
    if (d.current == f.candidate) {
        d.tried |= (uint64_t{1} << f.candidate);
        d.current = -1;
    }
}

void StrategySynthesizer::judge_stale_flows_(const std::string& destination,
                                             Clock::time_point now) {
    for (auto it = flows_.begin(); it != flows_.end();) {
        if (it->second.dest == destination && now - it->second.last_sent >= kVerdictTimeout) {
            fail_(it->second);
            it = flows_.erase(it);
        } else {
            ++it;
        }
    }
}

StrategySynthesizer::Trial StrategySynthesizer::on_client_hello(
    const std::string& destination, uint32_t dst_ipv4, uint16_t src_port,
    uint16_t dst_port, uint32_t seq, uint32_t payload_len, Clock::time_point now) {
    expire_(now);
    Trial trial;
    const uint64_t key = flow_key(dst_ipv4, src_port, dst_port);

    auto fit = flows_.find(key);
    if (fit != flows_.end() && fit->second.seq == seq) {
        // Retransmission: the previous attempt was never ACKed.
        trial.retransmission = true;
        fail_(fit->second);
        Dest& d = dest_for_(fit->second.dest, now);
        trial.candidate = pick_(d, trial.switched, trial.exhausted);
        fit->second.candidate = trial.candidate;
        fit->second.last_sent = now;
        return trial;
    }
    if (fit != flows_.end()) flows_.erase(fit);  // port reused by a new connection

    judge_stale_flows_(destination, now);

    Dest& d = dest_for_(destination, now);
    trial.candidate = pick_(d, trial.switched, trial.exhausted);

    if (flows_.size() >= max_flows_) {
        auto oldest = flows_.begin();
        for (auto j = flows_.begin(); j != flows_.end(); ++j) {
            if (j->second.last_sent < oldest->second.last_sent) oldest = j;
        }
        flows_.erase(oldest);
    }
    Flow f;
    f.dest = destination;
    f.seq = seq;
    f.end = seq + payload_len;
    f.candidate = trial.candidate;
    f.first_candidate = trial.candidate;
    f.last_sent = now;
    flows_.emplace(key, std::move(f));
    return trial;
}

StrategySynthesizer::Verdict StrategySynthesizer::on_data(
    uint32_t dst_ipv4, uint16_t src_port, uint16_t dst_port, uint32_t seq,
    Clock::time_point now) {
    Verdict v;
    auto fit = flows_.find(flow_key(dst_ipv4, src_port, dst_port));
    if (fit == flows_.end() || !seq_at_or_after(seq, fit->second.end)) return v;

    const Flow f = std::move(fit->second);
    flows_.erase(fit);

    ++wins_;
    if (static_cast<size_t>(f.candidate) < stats_.size()) {
        ++stats_[static_cast<size_t>(f.candidate)].wins;
    }

    v.success = true;
    v.destination = f.dest;
    v.candidate = f.candidate;

    Dest& d = dest_for_(f.dest, now);
    v.newly_locked = d.locked != f.candidate;
    d.locked = f.candidate;
    d.locked_failures = 0;
    d.current = f.candidate;
    d.exhausted = false;
    v.attempts = d.attempts;
    return v;
}

} // namespace DPI
} // namespace ncp
