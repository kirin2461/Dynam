#pragma once
/**
 * @file ncp_packet_pipeline.hpp
 * @brief Unified Packet Processing Pipeline — Dynam/NCP Anti-TSPU
 *
 * Coordinates all obfuscation modules into a single ordered pipeline
 * for outgoing and incoming packets. Each stage wraps an existing module
 * through a callback-based GenericStage so PacketPipeline does not own
 * the module instances (they live in ProtocolOrchestrator or elsewhere).
 *
 * Outgoing order (9 stages):
 *   1. E2E Encrypt         (E2ESession::encrypt)
 *   2. Protocol Morph      (ProtocolMorpher::wrap / select_profile_for_connection)
 *   3. Adversarial Pad     (AdversarialPadding::pad)
 *   4. Burst Morph         (BurstMorpher::select_perturbation + apply pre/post padding)
 *   5. Flow Shape          (FlowShaper::shape_sync — may produce multiple output packets)
 *   6. TLS Record Padding  (TLSRecordPadding::pad_record)
 *   7. Entropy Masking     (EntropyController::mask_entropy)
 *   8. L3 Stealth          (L3Stealth::process_ipv4_packet / process_ipv6_packet)
 *   9. L2 Stealth          (L2Stealth — optional, requires Npcap/pcap)
 *
 * Incoming order (4 stages):
 *   1. L3 Stealth uncloak
 *   2. Entropy Unmask      (EntropyController::unmask_entropy)
 *   3. Protocol Unmorph    (ProtocolMorpher::unwrap equivalent)
 *   4. E2E Decrypt         (E2ESession::decrypt)
 *
 * Thread-safety: all public methods are guarded by mutex_ except
 * get_stats() / reset_stats() which use atomic counters directly.
 */

#include <cstdint>
#include <vector>
#include <memory>
#include <functional>
#include <mutex>
#include <atomic>
#include <chrono>
#include <string>
#include <optional>

#include "ncp_orchestrator.hpp" // for ncp::DPI::ThreatLevel

namespace ncp {

// ============================================================
// PipelinePacket — packet + metadata travelling through stages
// ============================================================

struct PipelinePacket {
    std::vector<uint8_t> data;

    // Network metadata (optional, used by L3/L2 stages when available)
    std::string src_ip;
    std::string dst_ip;
    uint16_t    src_port  = 0;
    uint16_t    dst_port  = 0;

    enum class Direction { OUTBOUND, INBOUND } direction = Direction::OUTBOUND;

    std::chrono::steady_clock::time_point timestamp = std::chrono::steady_clock::now();

    // Stage-written metadata flags
    bool encrypted = false;  ///< Set by E2E stage
    bool morphed   = false;  ///< Set by Protocol Morph stage
    bool padded    = false;  ///< Set by Adversarial/Burst Pad stages

    /// Cumulative delay requested by FlowShaper
    std::chrono::microseconds added_delay{0};
};

// ============================================================
// PipelineStageResult
// ============================================================

struct PipelineStageResult {
    bool success = true;
    std::string error;

    /// Normally contains a single packet; FlowShaper may split into N packets.
    std::vector<PipelinePacket> output_packets;
};

// ============================================================
// PipelineConfig — per-stage enable switches + performance knobs
// ============================================================

struct PipelineConfig {
    bool enabled = true;

    // Per-stage enables (all on by default)
    bool enable_e2e              = true;
    bool enable_protocol_morph   = true;
    bool enable_adversarial      = true;
    bool enable_burst_morph      = true;
    bool enable_flow_shaping     = true;
    bool enable_tls_padding      = true;
    bool enable_entropy_masking  = true;
    bool enable_l3_stealth       = true;
    bool enable_l2_stealth       = false; ///< Requires Npcap/libpcap — disabled by default

    // Performance
    size_t max_packet_size              = 65535;
    bool   parallel_independent_stages  = false; ///< Future: run independent stages in parallel
};

// ============================================================
// PipelineStats — atomic counters, copyable
// ============================================================

struct PipelineStats {
    std::atomic<uint64_t> outbound_packets{0};
    std::atomic<uint64_t> inbound_packets{0};
    std::atomic<uint64_t> bytes_in{0};
    std::atomic<uint64_t> bytes_out{0};
    std::atomic<uint64_t> stage_errors{0};
    std::atomic<uint64_t> packets_dropped{0};

    /// Accumulated microseconds per outbound stage (index 0 = stage 1, etc.)
    std::atomic<uint64_t> stage_time_us[9]{};

    /// Accumulated microseconds per inbound stage (index 0 = IN.1, etc.)
    std::atomic<uint64_t> instage_time_us[4]{};

    void reset();

    PipelineStats() = default;

    /// Copy constructor — copies atomic loads
    PipelineStats(const PipelineStats& o);

    /// Copy assignment
    PipelineStats& operator=(const PipelineStats& o);
};

// ============================================================
// IPipelineStage — pure interface for all stages
// ============================================================

class IPipelineStage {
public:
    virtual ~IPipelineStage() = default;

    /// Human-readable stage name (e.g. "E2EEncrypt", "FlowShape")
    virtual std::string name() const = 0;

    /// Process one packet. May modify packet.data in-place or replace it.
    /// May return multiple output packets (e.g. FlowShaper splitting).
    virtual PipelineStageResult process(PipelinePacket& packet) = 0;

    virtual bool is_enabled() const = 0;
    virtual void set_enabled(bool e) = 0;
};

// ============================================================
// GenericStage — callback-based concrete stage
//
// Enables callers to register any lambda/function as a stage without
// subclassing. PacketPipeline uses this internally in setup_default_stages().
// External code can also construct GenericStages to attach real module
// instances via capturing lambdas.
// ============================================================

class GenericStage final : public IPipelineStage {
public:
    using StageCallback = std::function<PipelineStageResult(PipelinePacket&)>;

    GenericStage(std::string name, StageCallback cb, bool enabled = true);

    std::string          name()       const override { return name_; }
    bool                 is_enabled() const override { return enabled_; }
    void                 set_enabled(bool e) override { enabled_ = e; }
    PipelineStageResult  process(PipelinePacket& packet) override;

private:
    std::string    name_;
    StageCallback  cb_;
    bool           enabled_ = true;
};

// ============================================================
// PacketPipeline — main orchestrator
// ============================================================

class PacketPipeline {
public:
    PacketPipeline();
    explicit PacketPipeline(const PipelineConfig& config);
    ~PacketPipeline() = default;

    PacketPipeline(const PacketPipeline&)            = delete;
    PacketPipeline& operator=(const PacketPipeline&) = delete;

    // ----- Main processing API -----

    /// Run packet through all enabled outbound stages in order.
    PipelineStageResult process_outbound(PipelinePacket& packet);

    /// Run packet through all enabled inbound stages in order.
    PipelineStageResult process_inbound(PipelinePacket& packet);

    /// Convenience: wrap raw bytes into PipelinePacket (OUTBOUND) and process.
    PipelineStageResult process_outbound(const std::vector<uint8_t>& data);

    /// Convenience: wrap raw bytes into PipelinePacket (INBOUND) and process.
    PipelineStageResult process_inbound(const std::vector<uint8_t>& data);

    // ----- Stage management -----

    /// Append a stage to the end of the outbound pipeline.
    void add_outbound_stage(std::unique_ptr<IPipelineStage> stage);

    /// Append a stage to the end of the inbound pipeline.
    void add_inbound_stage(std::unique_ptr<IPipelineStage> stage);

    /// Remove all outbound and inbound stages.
    void clear_stages();

    /// Populate default stub stages for all 9 outbound + 4 inbound slots.
    /// Each stub logs its name and passes data through unchanged.
    /// Real module integration is done by replacing stubs via add_outbound_stage()
    /// after constructing PacketPipeline, or by using GenericStage with a capturing
    /// lambda that holds a pointer to the real module.
    void setup_default_stages();

    // ----- Configuration -----

    void           set_config(const PipelineConfig& config);
    PipelineConfig get_config() const;

    // ----- Stats -----

    PipelineStats get_stats()  const;
    void          reset_stats();

    // ----- Threat-level integration -----

    /// Adjust per-stage aggressiveness based on threat level.
    void               set_threat_level(DPI::ThreatLevel level);
    DPI::ThreatLevel   get_threat_level() const;

private:
    // ----- Internal helpers -----

    /// Run a single linear stage list over one packet.
    /// @param stages     Stage list to iterate.
    /// @param packet     Packet to process (modified in place for first output).
    /// @param time_accum Per-stage time accumulator array (may be nullptr).
    /// @param n_stages   Length of time_accum array (only used when non-null).
    PipelineStageResult run_stages_(
        std::vector<std::unique_ptr<IPipelineStage>>& stages,
        PipelinePacket& packet,
        std::atomic<uint64_t>* time_accum,
        size_t n_stages
    );

    // ----- State -----

    PipelineConfig   config_;
    PipelineStats    stats_;
    DPI::ThreatLevel threat_level_ = DPI::ThreatLevel::NONE;
    mutable std::mutex mutex_;

    std::vector<std::unique_ptr<IPipelineStage>> outbound_stages_;
    std::vector<std::unique_ptr<IPipelineStage>> inbound_stages_;
};

} // namespace ncp
