#pragma once

// StrategySynthesizer — builds DPI desync strategies and tunes them on the
// live traffic, per destination, until one gets through.
//
// No fixed preset fits every path: the same ISP can need a plain in-order
// split towards one host and fakes towards another, while reordering breaks a
// third.  Instead of picking a preset up front, a strategy is composed from
// independent genes (where to split, in which order to send, which fakes to
// inject) and every new ClientHello to a destination is a trial of the current
// candidate.
//
// The capture thread only sees outbound packets, which is still enough to
// score a trial:
//   * success - the client sends payload past the end of its ClientHello on
//     the same flow.  It only does that after the ServerHello arrived.
//   * failure - the ClientHello is retransmitted at the same sequence number
//     (nothing was ACKed), or a flow stays silent past the verdict timeout and
//     the application opens another connection to the same destination
//     (typical after an injected RST).
//
// On failure the destination moves to the next untried candidate, the
// retransmission itself already goes out with it.  Only a flow's first
// candidate gets a clean trial, though: once the DPI has seen one attempt the
// flow may be poisoned, so a later candidate failing on a retransmission of
// that flow is not held against it - it is kept and gets a clean trial on the
// destination's next connection.  When every candidate has failed cleanly the
// destination starts another round, best global candidates first.
//
// On success the candidate is
// locked for that destination and credited globally; the global win rate
// orders the candidates tried first on destinations seen later, so what works
// on this network is learnt once and reused.
//
// Not thread-safe: call it from the packet capture thread only.

#include "ncp_dpi.hpp"

#include <chrono>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

namespace ncp {
namespace DPI {

enum class SplitGene : uint8_t {
    Keep,    ///< Leave the base config's split as is
    Sni,     ///< One split at the start of the SNI hostname
    Midsld,  ///< One split in the middle of the second-level domain
    Pos1,    ///< One split after the first byte
    Multi,   ///< Split at 1, SNI and midsld
};

enum class OrderGene : uint8_t {
    Keep,      ///< Leave the base config's ordering as is
    InOrder,   ///< Segments sent in order
    Disorder,  ///< Later segment first
    Reverse,   ///< All segments in reverse order
};

enum class FakeGene : uint8_t {
    Keep,    ///< Leave the base config's fakes as is
    None,    ///< No fake packets
    Badseq,  ///< Fake with a wrong sequence number (server discards it)
    Badsum,  ///< Fake with a broken TCP checksum (server discards it)
    LowTtl,  ///< Fake that expires before reaching the server
};

struct StrategyGenes {
    SplitGene split = SplitGene::Keep;
    OrderGene order = OrderGene::Keep;
    FakeGene fake = FakeGene::Keep;

    /// Human-readable form, e.g. "sni/in-order/no-fake".
    std::string name() const;

    bool operator==(const StrategyGenes& o) const noexcept {
        return split == o.split && order == o.order && fake == o.fake;
    }
    bool operator!=(const StrategyGenes& o) const noexcept { return !(*this == o); }
};

/// Overwrite the desync knobs of `cfg` selected by `genes`; `Keep` genes and
/// every other field (mode, ports, filters, ...) are left untouched.
void apply_genes(const StrategyGenes& genes, DPIConfig& cfg);

/// Candidates for synthesis, cheapest and least intrusive first.  The order is
/// only a prior: measured win rates reorder it at run time.
std::vector<StrategyGenes> synthesized_strategy_ladder();

/// Candidates for a fixed preset: the preset itself, then a single in-order
/// split without fakes for destinations that do not tolerate the preset.
std::vector<StrategyGenes> preset_with_in_order_fallback();

class StrategySynthesizer {
public:
    using Clock = std::chrono::steady_clock;

    struct Trial {
        int candidate = 0;           ///< Index into candidates() for this packet
        bool retransmission = false; ///< Same flow, same seq as the last ClientHello
        bool switched = false;       ///< Destination moved to a new candidate
        bool exhausted = false;      ///< Every candidate failed; a new round starts
    };

    struct Verdict {
        bool success = false;        ///< This packet proved the flow's trial worked
        bool newly_locked = false;   ///< Destination had no working candidate before
        std::string destination;
        int candidate = -1;
        int attempts = 0;            ///< Candidates tried for the destination so far
    };

    /// A silent flow is judged failed once this long has passed since its last
    /// ClientHello and another connection to the same destination starts.
    static constexpr std::chrono::milliseconds kVerdictTimeout{3000};
    /// A flow with no verdict is forgotten after this long.
    static constexpr std::chrono::seconds kFlowLifetime{30};
    /// Failures of a locked candidate needed before it is abandoned.
    static constexpr int kLockedFailuresToUnlock = 2;
    /// Hard cap on the number of candidates (they are tracked in a bitmask).
    static constexpr size_t kMaxCandidates = 64;

    explicit StrategySynthesizer(
        std::vector<StrategyGenes> candidates = synthesized_strategy_ladder());

    /// Replace the candidate set; drops everything learnt so far.  Truncated to
    /// kMaxCandidates; an empty set falls back to {Keep, Keep, Keep}.
    void set_candidates(std::vector<StrategyGenes> candidates);
    const std::vector<StrategyGenes>& candidates() const noexcept { return candidates_; }

    /// Called for every outbound ClientHello.
    /// @param destination SNI hostname, or the destination address if absent.
    Trial on_client_hello(const std::string& destination, uint32_t dst_ipv4,
                          uint16_t src_port, uint16_t dst_port, uint32_t seq,
                          uint32_t payload_len, Clock::time_point now = Clock::now());

    /// Called for every other outbound TCP payload packet.
    Verdict on_data(uint32_t dst_ipv4, uint16_t src_port, uint16_t dst_port,
                    uint32_t seq, Clock::time_point now = Clock::now());

    /// Locked (proven) candidate for `destination`, or -1.
    int locked_candidate(const std::string& destination) const;
    /// Laplace-smoothed global win rate of a candidate, in (0, 1).
    double global_score(int candidate) const;

    uint64_t switches() const noexcept { return switches_; }
    uint64_t wins() const noexcept { return wins_; }
    uint64_t failures() const noexcept { return failures_; }
    size_t tracked_destinations() const noexcept { return dests_.size(); }
    size_t pending_flows() const noexcept { return flows_.size(); }

    void clear();

    // Tuning knobs (exposed for tests).
    /// @note ttl of zero or less keeps destinations forever.
    void set_destination_ttl(std::chrono::seconds ttl) noexcept { dest_ttl_ = ttl; }
    void set_max_destinations(size_t n) noexcept { max_dests_ = n ? n : 1; }
    void set_max_flows(size_t n) noexcept { max_flows_ = n ? n : 1; }

private:
    struct Dest {
        int current = -1;         ///< Candidate under trial, -1 = pick next
        int locked = -1;          ///< Proven candidate, -1 = none
        int locked_failures = 0;
        uint64_t tried = 0;       ///< Bitmask of candidates that failed here
        int attempts = 0;
        bool exhausted = false;   ///< Announced "all failed"; cleared on success
        Clock::time_point seen{};
    };

    struct Flow {
        std::string dest;
        uint32_t seq = 0;
        uint32_t end = 0;         ///< seq + ClientHello length
        int candidate = 0;        ///< Candidate of the latest (re)transmission
        int first_candidate = 0;  ///< Candidate the flow was opened with
        Clock::time_point last_sent{};
    };

    struct CandidateStats {
        uint64_t wins = 0;
        uint64_t fails = 0;
    };

    static uint64_t flow_key(uint32_t dst_ipv4, uint16_t src_port, uint16_t dst_port) noexcept {
        return (static_cast<uint64_t>(dst_ipv4) << 32) |
               (static_cast<uint64_t>(src_port) << 16) | dst_port;
    }

    Dest& dest_for_(const std::string& destination, Clock::time_point now);
    int pick_(Dest& d, bool& switched, bool& exhausted);
    void fail_(const Flow& f);
    void judge_stale_flows_(const std::string& destination, Clock::time_point now);
    void expire_(Clock::time_point now);
    std::vector<int> ranking_() const;

    std::vector<StrategyGenes> candidates_;
    std::vector<CandidateStats> stats_;
    std::unordered_map<std::string, Dest> dests_;
    std::unordered_map<uint64_t, Flow> flows_;

    std::chrono::seconds dest_ttl_{600};
    size_t max_dests_ = 512;
    size_t max_flows_ = 1024;

    uint64_t switches_ = 0;
    uint64_t wins_ = 0;
    uint64_t failures_ = 0;
};

} // namespace DPI
} // namespace ncp
