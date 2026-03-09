/**
 * @file ncp_packet_pipeline.cpp
 * @brief Unified Packet Processing Pipeline — implementation
 *
 * This translation unit provides:
 *   - PipelineStats copy semantics
 *   - GenericStage implementation
 *   - PacketPipeline full implementation with:
 *       * process_outbound / process_inbound (with per-stage timing)
 *       * setup_default_stages() — stub stages that log and pass through
 *       * set_threat_level() — adjusts stage enabled flags dynamically
 *
 * HOW TO WIRE REAL MODULES:
 *
 *   Option A (recommended): Replace individual stubs via add_outbound_stage()
 *   before the pipeline processes any packet:
 *
 *     pipeline.clear_stages();
 *     pipeline.setup_default_stages();   // populate stubs first
 *     // then override stage 0 (E2E) with a real lambda:
 *     pipeline.add_outbound_stage(std::make_unique<ncp::GenericStage>(
 *         "E2EEncrypt",
 *         [&e2e_session](ncp::PipelinePacket& pkt) -> ncp::PipelineStageResult {
 *             auto enc = e2e_session.encrypt(pkt.data, {});
 *             ncp::PipelineStageResult r;
 *             if (enc.ciphertext.empty()) {
 *                 r.success = false;
 *                 r.error   = "E2E encrypt failed";
 *                 return r;
 *             }
 *             pkt.data      = std::move(enc.ciphertext);
 *             pkt.encrypted = true;
 *             r.output_packets.push_back(pkt);
 *             return r;
 *         }
 *     ));
 *
 *   Option B: Construct PacketPipeline without default stages and push
 *   fully-configured GenericStage instances for each module you want active.
 */

#include "ncp_packet_pipeline.hpp"
#include "ncp_logger.hpp"

#include <cassert>
#include <sstream>

namespace ncp {

// ============================================================
// PipelineStats — copy semantics
// ============================================================

PipelineStats::PipelineStats(const PipelineStats& o)
    : outbound_packets (o.outbound_packets.load())
    , inbound_packets  (o.inbound_packets.load())
    , bytes_in         (o.bytes_in.load())
    , bytes_out        (o.bytes_out.load())
    , stage_errors     (o.stage_errors.load())
    , packets_dropped  (o.packets_dropped.load())
{
    for (size_t i = 0; i < 9; ++i)
        stage_time_us[i].store(o.stage_time_us[i].load());
    for (size_t i = 0; i < 4; ++i)
        instage_time_us[i].store(o.instage_time_us[i].load());
}

PipelineStats& PipelineStats::operator=(const PipelineStats& o)
{
    if (this == &o) return *this;
    outbound_packets.store(o.outbound_packets.load());
    inbound_packets.store(o.inbound_packets.load());
    bytes_in.store(o.bytes_in.load());
    bytes_out.store(o.bytes_out.load());
    stage_errors.store(o.stage_errors.load());
    packets_dropped.store(o.packets_dropped.load());
    for (size_t i = 0; i < 9; ++i)
        stage_time_us[i].store(o.stage_time_us[i].load());
    for (size_t i = 0; i < 4; ++i)
        instage_time_us[i].store(o.instage_time_us[i].load());
    return *this;
}

void PipelineStats::reset()
{
    outbound_packets.store(0);
    inbound_packets.store(0);
    bytes_in.store(0);
    bytes_out.store(0);
    stage_errors.store(0);
    packets_dropped.store(0);
    for (auto& t : stage_time_us)  t.store(0);
    for (auto& t : instage_time_us) t.store(0);
}

// ============================================================
// GenericStage
// ============================================================

GenericStage::GenericStage(std::string name, StageCallback cb, bool enabled)
    : name_(std::move(name))
    , cb_(std::move(cb))
    , enabled_(enabled)
{}

PipelineStageResult GenericStage::process(PipelinePacket& packet)
{
    if (!enabled_) {
        // Pass through without touching data
        PipelineStageResult r;
        r.output_packets.push_back(packet);
        return r;
    }
    return cb_(packet);
}

// ============================================================
// PacketPipeline — constructors
// ============================================================

PacketPipeline::PacketPipeline()
    : config_()
    , threat_level_(DPI::ThreatLevel::NONE)
{
    setup_default_stages();
    NCP_LOG_INFO("[PacketPipeline] Initialized with default stages.");
}

PacketPipeline::PacketPipeline(const PipelineConfig& config)
    : config_(config)
    , threat_level_(DPI::ThreatLevel::NONE)
{
    setup_default_stages();
    NCP_LOG_INFO("[PacketPipeline] Initialized with custom config.");
}

// ============================================================
// setup_default_stages
// ============================================================

void PacketPipeline::setup_default_stages()
{
    std::lock_guard<std::mutex> lk(mutex_);
    outbound_stages_.clear();
    inbound_stages_.clear();

    // Helper: create a passthrough stub that logs its name once per packet
    auto make_stub = [](const std::string& stage_name, bool enabled) {
        return std::make_unique<GenericStage>(
            stage_name,
            [stage_name](PipelinePacket& pkt) -> PipelineStageResult {
                NCP_LOG_DEBUG("[PacketPipeline] Stub stage '" + stage_name + "' applied.");
                PipelineStageResult r;
                r.output_packets.push_back(pkt);
                return r;
            },
            enabled
        );
    };

    // ---------- Outbound stages (9) ----------
    // Stage 1 — E2E Encrypt
    outbound_stages_.push_back(make_stub("E2EEncrypt",        config_.enable_e2e));
    // Stage 2 — Protocol Morph
    outbound_stages_.push_back(make_stub("ProtocolMorph",     config_.enable_protocol_morph));
    // Stage 3 — Adversarial Padding
    outbound_stages_.push_back(make_stub("AdversarialPad",    config_.enable_adversarial));
    // Stage 4 — Burst Morph
    outbound_stages_.push_back(make_stub("BurstMorph",        config_.enable_burst_morph));
    // Stage 5 — Flow Shape
    outbound_stages_.push_back(make_stub("FlowShape",         config_.enable_flow_shaping));
    // Stage 6 — TLS Record Padding
    outbound_stages_.push_back(make_stub("TLSRecordPad",      config_.enable_tls_padding));
    // Stage 7 — Entropy Masking
    outbound_stages_.push_back(make_stub("EntropyMask",       config_.enable_entropy_masking));
    // Stage 8 — L3 Stealth
    outbound_stages_.push_back(make_stub("L3Stealth",         config_.enable_l3_stealth));
    // Stage 9 — L2 Stealth (Npcap-dependent)
    outbound_stages_.push_back(make_stub("L2Stealth",         config_.enable_l2_stealth));

    // ---------- Inbound stages (4) ----------
    // IN.1 — L3 Stealth verify/uncloak
    inbound_stages_.push_back(make_stub("IN.L3Stealth",       config_.enable_l3_stealth));
    // IN.2 — Entropy Unmask
    inbound_stages_.push_back(make_stub("IN.EntropyUnmask",   config_.enable_entropy_masking));
    // IN.3 — Protocol Unmorph
    inbound_stages_.push_back(make_stub("IN.ProtocolUnmorph", config_.enable_protocol_morph));
    // IN.4 — E2E Decrypt
    inbound_stages_.push_back(make_stub("IN.E2EDecrypt",      config_.enable_e2e));

    NCP_LOG_DEBUG("[PacketPipeline] Default stages registered: "
                  + std::to_string(outbound_stages_.size()) + " outbound, "
                  + std::to_string(inbound_stages_.size())  + " inbound.");
}

// ============================================================
// run_stages_ — internal stage runner
// ============================================================

PipelineStageResult PacketPipeline::run_stages_(
    std::vector<std::unique_ptr<IPipelineStage>>& stages,
    PipelinePacket& packet,
    std::atomic<uint64_t>* time_accum,
    size_t n_stages)
{
    // We maintain a working list of packets.
    // Stages that split (e.g. FlowShaper) may produce N > 1 packets;
    // subsequent stages are applied to each.
    std::vector<PipelinePacket> current;
    current.push_back(packet);

    for (size_t si = 0; si < stages.size(); ++si) {
        auto& stage = stages[si];
        if (!stage->is_enabled()) continue;

        auto t_start = std::chrono::steady_clock::now();

        std::vector<PipelinePacket> next;
        bool had_error = false;
        std::string last_error;

        for (auto& pkt : current) {
            auto result = stage->process(pkt);
            if (!result.success) {
                NCP_LOG_ERROR("[PacketPipeline] Stage '" + stage->name()
                              + "' failed: " + result.error);
                stats_.stage_errors.fetch_add(1, std::memory_order_relaxed);
                had_error  = true;
                last_error = result.error;
                // Drop this packet; continue with others
                stats_.packets_dropped.fetch_add(1, std::memory_order_relaxed);
            } else {
                for (auto& op : result.output_packets)
                    next.push_back(std::move(op));
            }
        }

        auto t_end = std::chrono::steady_clock::now();
        auto us    = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::microseconds>(t_end - t_start).count());

        if (time_accum && si < n_stages)
            time_accum[si].fetch_add(us, std::memory_order_relaxed);

        if (next.empty()) {
            // All packets dropped — bail out
            PipelineStageResult r;
            r.success = false;
            r.error   = "Stage '" + stage->name() + "' dropped all packets";
            return r;
        }
        current = std::move(next);
        (void)had_error;
        (void)last_error;
    }

    PipelineStageResult final_result;
    final_result.output_packets = std::move(current);
    return final_result;
}

// ============================================================
// process_outbound
// ============================================================

PipelineStageResult PacketPipeline::process_outbound(PipelinePacket& packet)
{
    std::lock_guard<std::mutex> lk(mutex_);

    if (!config_.enabled) {
        PipelineStageResult r;
        r.output_packets.push_back(packet);
        return r;
    }

    const size_t orig_size = packet.data.size();
    stats_.outbound_packets.fetch_add(1, std::memory_order_relaxed);
    stats_.bytes_out.fetch_add(orig_size, std::memory_order_relaxed);

    packet.direction = PipelinePacket::Direction::OUTBOUND;
    packet.timestamp = std::chrono::steady_clock::now();

    auto result = run_stages_(outbound_stages_, packet,
                               stats_.stage_time_us, 9);

    if (!result.success) {
        NCP_LOG_ERROR("[PacketPipeline] Outbound pipeline failed: " + result.error);
    } else {
        NCP_LOG_DEBUG("[PacketPipeline] Outbound: " + std::to_string(orig_size)
                      + "B -> " + std::to_string(result.output_packets.size())
                      + " packet(s).");
    }
    return result;
}

PipelineStageResult PacketPipeline::process_outbound(const std::vector<uint8_t>& data)
{
    PipelinePacket pkt;
    pkt.data      = data;
    pkt.direction = PipelinePacket::Direction::OUTBOUND;
    return process_outbound(pkt);
}

// ============================================================
// process_inbound
// ============================================================

PipelineStageResult PacketPipeline::process_inbound(PipelinePacket& packet)
{
    std::lock_guard<std::mutex> lk(mutex_);

    if (!config_.enabled) {
        PipelineStageResult r;
        r.output_packets.push_back(packet);
        return r;
    }

    const size_t orig_size = packet.data.size();
    stats_.inbound_packets.fetch_add(1, std::memory_order_relaxed);
    stats_.bytes_in.fetch_add(orig_size, std::memory_order_relaxed);

    packet.direction = PipelinePacket::Direction::INBOUND;
    packet.timestamp = std::chrono::steady_clock::now();

    auto result = run_stages_(inbound_stages_, packet,
                               stats_.instage_time_us, 4);

    if (!result.success) {
        NCP_LOG_ERROR("[PacketPipeline] Inbound pipeline failed: " + result.error);
    } else {
        NCP_LOG_DEBUG("[PacketPipeline] Inbound: " + std::to_string(orig_size)
                      + "B -> " + std::to_string(result.output_packets.size())
                      + " packet(s).");
    }
    return result;
}

PipelineStageResult PacketPipeline::process_inbound(const std::vector<uint8_t>& data)
{
    PipelinePacket pkt;
    pkt.data      = data;
    pkt.direction = PipelinePacket::Direction::INBOUND;
    return process_inbound(pkt);
}

// ============================================================
// Stage management
// ============================================================

void PacketPipeline::add_outbound_stage(std::unique_ptr<IPipelineStage> stage)
{
    std::lock_guard<std::mutex> lk(mutex_);
    NCP_LOG_INFO("[PacketPipeline] add_outbound_stage: " + stage->name());
    outbound_stages_.push_back(std::move(stage));
}

void PacketPipeline::add_inbound_stage(std::unique_ptr<IPipelineStage> stage)
{
    std::lock_guard<std::mutex> lk(mutex_);
    NCP_LOG_INFO("[PacketPipeline] add_inbound_stage: " + stage->name());
    inbound_stages_.push_back(std::move(stage));
}

void PacketPipeline::clear_stages()
{
    std::lock_guard<std::mutex> lk(mutex_);
    outbound_stages_.clear();
    inbound_stages_.clear();
    NCP_LOG_DEBUG("[PacketPipeline] All stages cleared.");
}

// ============================================================
// Configuration
// ============================================================

void PacketPipeline::set_config(const PipelineConfig& config)
{
    std::lock_guard<std::mutex> lk(mutex_);
    config_ = config;

    // Re-sync per-stage enabled flags with the existing stage list.
    // Stages are in a fixed order as set up by setup_default_stages().
    auto sync_enabled = [](std::vector<std::unique_ptr<IPipelineStage>>& stages,
                            size_t idx, bool enabled)
    {
        if (idx < stages.size())
            stages[idx]->set_enabled(enabled);
    };

    sync_enabled(outbound_stages_, 0, config.enable_e2e);
    sync_enabled(outbound_stages_, 1, config.enable_protocol_morph);
    sync_enabled(outbound_stages_, 2, config.enable_adversarial);
    sync_enabled(outbound_stages_, 3, config.enable_burst_morph);
    sync_enabled(outbound_stages_, 4, config.enable_flow_shaping);
    sync_enabled(outbound_stages_, 5, config.enable_tls_padding);
    sync_enabled(outbound_stages_, 6, config.enable_entropy_masking);
    sync_enabled(outbound_stages_, 7, config.enable_l3_stealth);
    sync_enabled(outbound_stages_, 8, config.enable_l2_stealth);

    sync_enabled(inbound_stages_,  0, config.enable_l3_stealth);
    sync_enabled(inbound_stages_,  1, config.enable_entropy_masking);
    sync_enabled(inbound_stages_,  2, config.enable_protocol_morph);
    sync_enabled(inbound_stages_,  3, config.enable_e2e);

    NCP_LOG_INFO("[PacketPipeline] Config updated.");
}

PipelineConfig PacketPipeline::get_config() const
{
    std::lock_guard<std::mutex> lk(mutex_);
    return config_;
}

// ============================================================
// Stats
// ============================================================

PipelineStats PacketPipeline::get_stats() const
{
    // No mutex needed — PipelineStats uses atomics
    return PipelineStats(stats_);
}

void PacketPipeline::reset_stats()
{
    stats_.reset();
    NCP_LOG_DEBUG("[PacketPipeline] Stats reset.");
}

// ============================================================
// Threat level integration
// ============================================================

void PacketPipeline::set_threat_level(DPI::ThreatLevel level)
{
    std::lock_guard<std::mutex> lk(mutex_);
    threat_level_ = level;

    // Under HIGH / CRITICAL threat, force-enable all protection stages.
    // Under NONE / LOW, respect the original config.
    bool max_protection = (level == DPI::ThreatLevel::HIGH ||
                           level == DPI::ThreatLevel::CRITICAL);

    if (max_protection) {
        NCP_LOG_INFO("[PacketPipeline] ThreatLevel "
                     + std::string(level == DPI::ThreatLevel::CRITICAL ? "CRITICAL" : "HIGH")
                     + " — enabling all protection stages.");
        for (auto& s : outbound_stages_) s->set_enabled(true);
        for (auto& s : inbound_stages_)  s->set_enabled(true);
    } else {
        NCP_LOG_INFO("[PacketPipeline] ThreatLevel lowered — restoring config-based enables.");
        // Restore from current config
        PipelineConfig cfg = config_; // already under lock
        auto sync = [](std::vector<std::unique_ptr<IPipelineStage>>& stages,
                       size_t idx, bool enabled)
        {
            if (idx < stages.size()) stages[idx]->set_enabled(enabled);
        };
        sync(outbound_stages_, 0, cfg.enable_e2e);
        sync(outbound_stages_, 1, cfg.enable_protocol_morph);
        sync(outbound_stages_, 2, cfg.enable_adversarial);
        sync(outbound_stages_, 3, cfg.enable_burst_morph);
        sync(outbound_stages_, 4, cfg.enable_flow_shaping);
        sync(outbound_stages_, 5, cfg.enable_tls_padding);
        sync(outbound_stages_, 6, cfg.enable_entropy_masking);
        sync(outbound_stages_, 7, cfg.enable_l3_stealth);
        sync(outbound_stages_, 8, cfg.enable_l2_stealth);
        sync(inbound_stages_,  0, cfg.enable_l3_stealth);
        sync(inbound_stages_,  1, cfg.enable_entropy_masking);
        sync(inbound_stages_,  2, cfg.enable_protocol_morph);
        sync(inbound_stages_,  3, cfg.enable_e2e);
    }
}

DPI::ThreatLevel PacketPipeline::get_threat_level() const
{
    std::lock_guard<std::mutex> lk(mutex_);
    return threat_level_;
}

} // namespace ncp
