#include "ncp_orchestrator.hpp"

#include <algorithm>
#include <cstring>

namespace ncp {
namespace DPI {

// ===== String conversions =====

const char* threat_level_to_string(ThreatLevel t) noexcept {
    switch (t) {
        case ThreatLevel::NONE:     return "NONE";
        case ThreatLevel::LOW:      return "LOW";
        case ThreatLevel::MEDIUM:   return "MEDIUM";
        case ThreatLevel::HIGH:     return "HIGH";
        case ThreatLevel::CRITICAL: return "CRITICAL";
        default: return "UNKNOWN";
    }
}

ThreatLevel threat_level_from_int(int level) noexcept {
    if (level <= 0) return ThreatLevel::NONE;
    if (level == 1) return ThreatLevel::LOW;
    if (level == 2) return ThreatLevel::MEDIUM;
    if (level == 3) return ThreatLevel::HIGH;
    return ThreatLevel::CRITICAL;
}

// ===== Helper: detect TLS ClientHello =====

namespace {

bool looks_like_client_hello(const uint8_t* data, size_t len) {
    return len > 5 && data[0] == 0x16 && data[1] == 0x03 && data[5] == 0x01;
}

} // anonymous namespace

// ===== Strategy Presets =====

OrchestratorStrategy OrchestratorStrategy::stealth() {
    OrchestratorStrategy s;
    s.name = "stealth";
    s.min_threat = ThreatLevel::HIGH;

    s.enable_adversarial = true;
    s.adversarial_config = AdversarialConfig::aggressive();

    s.enable_flow_shaping = true;
    s.flow_config = FlowShaperConfig::web_browsing();
    s.flow_config.enable_flow_dummy = true;
    s.flow_config.dummy_ratio = 0.10;

    s.enable_probe_resist = true;
    s.probe_config = ProbeResistConfig::strict();

    s.enable_mimicry = true;
    s.mimic_profile = TrafficMimicry::MimicProfile::HTTPS_APPLICATION;

    // Step 2A/2B: Advanced DPI — STEALTH preset with fingerprint rotation
    s.enable_advanced_dpi = true;
    s.advanced_dpi_preset = AdvancedDPIBypass::BypassPreset::STEALTH;
    s.extra_techniques = {
        EvasionTechnique::TCP_DISORDER,
        EvasionTechnique::TLS_PADDING
    };

    s.enable_tls_fingerprint = true;
    s.tls_browser_profile = ncp::BrowserType::RANDOM;

    return s;
}

OrchestratorStrategy OrchestratorStrategy::balanced() {
    OrchestratorStrategy s;
    s.name = "balanced";
    s.min_threat = ThreatLevel::MEDIUM;

    s.enable_adversarial = true;
    s.adversarial_config = AdversarialConfig::balanced();

    s.enable_flow_shaping = true;
    s.flow_config = FlowShaperConfig::web_browsing();

    s.enable_probe_resist = true;
    s.probe_config = ProbeResistConfig::balanced();

    s.enable_mimicry = true;
    s.mimic_profile = TrafficMimicry::MimicProfile::HTTPS_APPLICATION;

    // Step 2A/2B: Advanced DPI — MODERATE preset
    s.enable_advanced_dpi = true;
    s.advanced_dpi_preset = AdvancedDPIBypass::BypassPreset::MODERATE;

    s.enable_tls_fingerprint = true;
    s.tls_browser_profile = ncp::BrowserType::CHROME;

    return s;
}

OrchestratorStrategy OrchestratorStrategy::performance() {
    OrchestratorStrategy s;
    s.name = "performance";
    s.min_threat = ThreatLevel::LOW;

    s.enable_adversarial = true;
    s.adversarial_config = AdversarialConfig::minimal();

    s.enable_flow_shaping = false;  // no flow shaping — min latency

    s.enable_probe_resist = true;
    s.probe_config = ProbeResistConfig::permissive();

    s.enable_mimicry = true;
    s.mimic_profile = TrafficMimicry::MimicProfile::HTTPS_APPLICATION;

    // Step 2A/2B: Advanced DPI — MINIMAL preset, no TLS fingerprint
    s.enable_advanced_dpi = true;
    s.advanced_dpi_preset = AdvancedDPIBypass::BypassPreset::MINIMAL;

    s.enable_tls_fingerprint = false;

    return s;
}

OrchestratorStrategy OrchestratorStrategy::max_compat() {
    OrchestratorStrategy s;
    s.name = "max_compat";
    s.min_threat = ThreatLevel::NONE;

    s.enable_adversarial = false;
    s.enable_flow_shaping = false;

    s.enable_probe_resist = true;
    s.probe_config = ProbeResistConfig::permissive();

    s.enable_mimicry = true;
    s.mimic_profile = TrafficMimicry::MimicProfile::HTTPS_APPLICATION;

    // Step 2A/2B: No advanced DPI, no TLS fingerprint
    s.enable_advanced_dpi = false;
    s.enable_tls_fingerprint = false;

    return s;
}

// ===== OrchestratorConfig Presets =====

OrchestratorConfig OrchestratorConfig::client_default() {
    OrchestratorConfig c;
    c.is_server = false;
    c.adaptive = true;
    c.strategy = OrchestratorStrategy::balanced();
    c.tls_browser_profile = ncp::BrowserType::CHROME;
    return c;
}

OrchestratorConfig OrchestratorConfig::server_default() {
    OrchestratorConfig c;
    c.is_server = true;
    c.adaptive = false;
    c.strategy = OrchestratorStrategy::balanced();
    // Servers don't need TLS fingerprint or advanced DPI (they receive)
    c.strategy.enable_advanced_dpi = false;
    c.strategy.enable_tls_fingerprint = false;
    return c;
}

// ===== Constructor / Destructor =====

ProtocolOrchestrator::ProtocolOrchestrator()
    : ProtocolOrchestrator(OrchestratorConfig::client_default()) {}

ProtocolOrchestrator::ProtocolOrchestrator(const OrchestratorConfig& config)
    : config_(config),
      current_strategy_(config.strategy),
      threat_level_(ThreatLevel::NONE),
      consecutive_failures_(0),
      consecutive_successes_(0) {

    // Initialize shared secret
    if (!config_.shared_secret.empty()) {
        current_strategy_.probe_config.shared_secret = config_.shared_secret;
    }

    apply_strategy(current_strategy_);
    last_escalation_ = std::chrono::steady_clock::now();
    stats_.current_strategy_name = current_strategy_.name;
    stats_.current_threat = threat_level_;
}

ProtocolOrchestrator::~ProtocolOrchestrator() {
    stop();
}

// ===== Lifecycle =====

void ProtocolOrchestrator::start(OrchestratorSendCallback send_cb) {
    if (running_.load()) return;
    send_callback_ = send_cb;
    running_.store(true);

    // Start flow shaper if enabled
    if (current_strategy_.enable_flow_shaping) {
        flow_shaper_.start([this](const ShapedPacket& sp) {
            if (send_callback_) {
                OrchestratedPacket op;
                op.data = sp.data;
                op.delay = sp.delay_before_send;
                op.is_dummy = sp.is_dummy;
                send_callback_(op);
            }
        });
    }

    // Start health monitor
    if (config_.health_check_interval_sec > 0) {
        health_thread_ = std::thread(&ProtocolOrchestrator::health_monitor_func, this);
    }
}

void ProtocolOrchestrator::stop() {
    running_.store(false);
    flow_shaper_.stop();

    // Step 2B: Stop advanced DPI if running
    if (advanced_dpi_ && advanced_dpi_->is_running()) {
        advanced_dpi_->stop();
    }

    if (health_thread_.joinable()) {
        health_thread_.join();
    }
}

bool ProtocolOrchestrator::is_running() const {
    return running_.load();
}

// ===== Step 2B: init_advanced_dpi =====

void ProtocolOrchestrator::init_advanced_dpi() {
    // Stop existing instance if any
    if (advanced_dpi_ && advanced_dpi_->is_running()) {
        advanced_dpi_->stop();
    }

    advanced_dpi_ = std::make_unique<AdvancedDPIBypass>();

    // Check if caller provided a full custom config
    bool has_custom = !config_.advanced_dpi_config.techniques.empty() ||
                      config_.advanced_dpi_config.obfuscation != ObfuscationMode::NONE;

    if (has_custom) {
        // Use full custom config from OrchestratorConfig
        advanced_dpi_->initialize(config_.advanced_dpi_config);
    } else {
        // Use preset from strategy, then apply extra techniques
        AdvancedDPIConfig adv_cfg;
        adv_cfg.base_config = config_.advanced_dpi_config.base_config;
        advanced_dpi_->initialize(adv_cfg);
        advanced_dpi_->apply_preset(current_strategy_.advanced_dpi_preset);
    }

    // Add per-strategy extra techniques on top
    for (auto t : current_strategy_.extra_techniques) {
        advanced_dpi_->set_technique_enabled(t, true);
    }

    // Start the advanced bypass (this wires its process_outgoing
    // as TransformCallback on the internal DPIBypass via Step 1F)
    advanced_dpi_->start();
}

// ===== Step 2B: apply_tls_profile =====

void ProtocolOrchestrator::apply_tls_profile(ncp::BrowserType profile) {
    if (!tls_fingerprint_) {
        tls_fingerprint_ = std::make_unique<ncp::TLSFingerprint>(profile);
    } else {
        tls_fingerprint_->set_profile(profile);
    }
}

// ===== Client Pipeline: send =====

std::vector<OrchestratedPacket> ProtocolOrchestrator::send(
    const std::vector<uint8_t>& payload) {

    if (!config_.enabled || payload.empty()) {
        OrchestratedPacket op;
        op.data = payload;
        return {op};
    }

    stats_.packets_sent.fetch_add(1);
    stats_.bytes_original.fetch_add(payload.size());

    std::vector<uint8_t> data = payload;

    // ------------------------------------------------------------------
    // Step 0a (2B): TLS Fingerprint — randomize ClientHello fingerprint
    // ------------------------------------------------------------------
    bool is_ch = looks_like_client_hello(data.data(), data.size());

    if (is_ch && current_strategy_.enable_tls_fingerprint && tls_fingerprint_) {
        tls_fingerprint_->randomize_all();
        // Note: actual ClientHello bytes are modified by the TLS stack;
        // here we ensure the fingerprint state is ready for the next
        // handshake.  If the payload IS a raw ClientHello being proxied,
        // advanced DPI's process_outgoing handles splitting/mutation.
    }

    // ------------------------------------------------------------------
    // Step 0b (2B): Advanced DPI — technique-driven evasion pipeline
    // ------------------------------------------------------------------
    if (current_strategy_.enable_advanced_dpi &&
        advanced_dpi_ && advanced_dpi_->is_running()) {

        auto segments = advanced_dpi_->process_outgoing(data.data(), data.size());

        // If advanced DPI produced multiple segments, each one becomes
        // an independent packet through the rest of the pipeline.
        if (segments.size() > 1) {
            std::vector<OrchestratedPacket> all_results;

            for (auto& seg : segments) {
                std::vector<uint8_t> seg_data = std::move(seg);

                // Step 1: Adversarial Padding
                if (current_strategy_.enable_adversarial) {
                    seg_data = adversarial_.pad(seg_data);
                }
                // Step 2: Protocol Mimicry
                if (current_strategy_.enable_mimicry) {
                    seg_data = mimicry_.wrap_payload(seg_data, current_strategy_.mimic_profile);
                }
                // Step 3: Auth token
                if (current_strategy_.enable_probe_resist && !config_.is_server) {
                    auto token = probe_resist_.generate_client_auth();
                    seg_data.insert(seg_data.begin(), token.begin(), token.end());
                }
                // Step 4: Flow Shaping
                if (current_strategy_.enable_flow_shaping) {
                    auto shaped = flow_shaper_.shape_sync(seg_data, true);
                    for (auto& sp : shaped) {
                        OrchestratedPacket op;
                        op.data = std::move(sp.data);
                        op.delay = sp.delay_before_send;
                        op.is_dummy = sp.is_dummy;
                        stats_.bytes_on_wire.fetch_add(op.data.size());
                        all_results.push_back(std::move(op));
                    }
                } else {
                    OrchestratedPacket op;
                    stats_.bytes_on_wire.fetch_add(seg_data.size());
                    op.data = std::move(seg_data);
                    all_results.push_back(std::move(op));
                }
            }

            update_overhead_stats();
            return all_results;
        }

        // Single segment — replace data and continue normal path
        if (!segments.empty()) {
            data = std::move(segments[0]);
        }
    }

    // Step 1: Adversarial Padding (Phase 1)
    if (current_strategy_.enable_adversarial) {
        data = adversarial_.pad(data);
    }

    // Step 2: Protocol Mimicry (wrap in HTTPS/DNS/QUIC)
    if (current_strategy_.enable_mimicry) {
        data = mimicry_.wrap_payload(data, current_strategy_.mimic_profile);
    }

    // Step 3: Prepend auth token (Phase 3 client-side)
    if (current_strategy_.enable_probe_resist && !config_.is_server) {
        auto token = probe_resist_.generate_client_auth();
        data.insert(data.begin(), token.begin(), token.end());
    }

    // Step 4: Flow Shaping (Phase 2)
    if (current_strategy_.enable_flow_shaping) {
        auto shaped = flow_shaper_.shape_sync(data, true);
        std::vector<OrchestratedPacket> result;
        for (auto& sp : shaped) {
            OrchestratedPacket op;
            op.data = std::move(sp.data);
            op.delay = sp.delay_before_send;
            op.is_dummy = sp.is_dummy;
            stats_.bytes_on_wire.fetch_add(op.data.size());
            result.push_back(std::move(op));
        }
        update_overhead_stats();
        return result;
    }

    // No flow shaping — return single packet
    OrchestratedPacket op;
    op.data = std::move(data);
    stats_.bytes_on_wire.fetch_add(op.data.size());
    update_overhead_stats();
    return {op};
}

void ProtocolOrchestrator::send_async(const std::vector<uint8_t>& payload) {
    if (!config_.enabled || payload.empty()) return;

    stats_.packets_sent.fetch_add(1);
    stats_.bytes_original.fetch_add(payload.size());

    std::vector<uint8_t> data = payload;

    // Step 0a (2B): TLS Fingerprint
    bool is_ch = looks_like_client_hello(data.data(), data.size());
    if (is_ch && current_strategy_.enable_tls_fingerprint && tls_fingerprint_) {
        tls_fingerprint_->randomize_all();
    }

    // Step 0b (2B): Advanced DPI
    if (current_strategy_.enable_advanced_dpi &&
        advanced_dpi_ && advanced_dpi_->is_running()) {

        auto segments = advanced_dpi_->process_outgoing(data.data(), data.size());

        if (segments.size() > 1) {
            // Multi-segment: process each through rest of pipeline and send
            for (auto& seg : segments) {
                std::vector<uint8_t> seg_data = std::move(seg);

                if (current_strategy_.enable_adversarial) {
                    seg_data = adversarial_.pad(seg_data);
                }
                if (current_strategy_.enable_mimicry) {
                    seg_data = mimicry_.wrap_payload(seg_data, current_strategy_.mimic_profile);
                }
                if (current_strategy_.enable_probe_resist && !config_.is_server) {
                    auto token = probe_resist_.generate_client_auth();
                    seg_data.insert(seg_data.begin(), token.begin(), token.end());
                }

                if (current_strategy_.enable_flow_shaping && flow_shaper_.is_running()) {
                    flow_shaper_.enqueue(seg_data, true);
                } else if (send_callback_) {
                    OrchestratedPacket op;
                    op.data = std::move(seg_data);
                    send_callback_(op);
                }
            }
            return;
        }

        if (!segments.empty()) {
            data = std::move(segments[0]);
        }
    }

    // Steps 1-3 synchronous
    if (current_strategy_.enable_adversarial) {
        data = adversarial_.pad(data);
    }
    if (current_strategy_.enable_mimicry) {
        data = mimicry_.wrap_payload(data, current_strategy_.mimic_profile);
    }
    if (current_strategy_.enable_probe_resist && !config_.is_server) {
        auto token = probe_resist_.generate_client_auth();
        data.insert(data.begin(), token.begin(), token.end());
    }

    // Step 4: Enqueue for async flow shaping
    if (current_strategy_.enable_flow_shaping && flow_shaper_.is_running()) {
        flow_shaper_.enqueue(data, true);
    } else if (send_callback_) {
        OrchestratedPacket op;
        op.data = std::move(data);
        send_callback_(op);
    }
}

// ===== Server Pipeline: receive =====

std::vector<uint8_t> ProtocolOrchestrator::receive(
    const std::vector<uint8_t>& wire_data,
    const std::string& source_ip,
    uint16_t source_port,
    const std::string& ja3,
    AuthResult* auth_result) {

    if (!config_.enabled || wire_data.empty()) {
        if (auth_result) *auth_result = AuthResult::AUTHENTICATED;
        return wire_data;
    }

    stats_.packets_received.fetch_add(1);

    std::vector<uint8_t> data = wire_data;

    // Step 1: Auth check (Phase 3 server-side)
    if (current_strategy_.enable_probe_resist && config_.is_server) {
        AuthResult result = probe_resist_.process_connection(
            source_ip, source_port, data.data(), data.size(), ja3);

        if (auth_result) *auth_result = result;

        if (result != AuthResult::AUTHENTICATED) {
            return {};  // Caller should send cover response
        }

        // Strip auth token from data
        size_t auth_len = probe_resist_.get_config().nonce_length + 4 +
                          probe_resist_.get_config().auth_length;
        if (data.size() > auth_len) {
            data.erase(data.begin(), data.begin() + auth_len);
        }
    } else {
        if (auth_result) *auth_result = AuthResult::AUTHENTICATED;
    }

    // Step 2: Discard flow dummies
    if (current_strategy_.enable_flow_shaping) {
        if (FlowShaper::is_flow_dummy(data.data(), data.size())) {
            return {};  // dummy packet, discard
        }
    }

    // Step 3: Discard adversarial dummies
    if (current_strategy_.enable_adversarial) {
        if (AdversarialPadding::is_dummy(data.data(), data.size())) {
            return {};  // dummy packet, discard
        }
    }

    // Step 4: Protocol unwrap (mimicry)
    if (current_strategy_.enable_mimicry) {
        data = mimicry_.unwrap_payload(data);
    }

    // Step 5: Adversarial unpad
    if (current_strategy_.enable_adversarial) {
        data = adversarial_.unpad(data);
    }

    // Step 6 (2B): Reverse advanced DPI obfuscation (if applicable)
    if (current_strategy_.enable_advanced_dpi &&
        advanced_dpi_ && advanced_dpi_->is_running()) {
        data = advanced_dpi_->process_incoming(data.data(), data.size());
    }

    return data;
}

std::vector<uint8_t> ProtocolOrchestrator::generate_cover_response() {
    return probe_resist_.generate_cover_response();
}

// ===== Adaptive Control =====

void ProtocolOrchestrator::report_detection(const DetectionEvent& event) {
    stats_.detection_events.fetch_add(1);

    if (!config_.adaptive) return;

    std::lock_guard<std::mutex> lock(strategy_mutex_);

    switch (event.type) {
        case DetectionEvent::Type::SUCCESS:
            report_success();
            return;

        case DetectionEvent::Type::CONNECTION_RESET:
        case DetectionEvent::Type::TLS_ALERT:
            consecutive_failures_ += 2;  // strong signal
            consecutive_successes_ = 0;
            break;

        case DetectionEvent::Type::CONNECTION_TIMEOUT:
        case DetectionEvent::Type::THROTTLED:
            consecutive_failures_ += 1;
            consecutive_successes_ = 0;
            break;

        case DetectionEvent::Type::PROBE_RECEIVED:
        case DetectionEvent::Type::IP_BLOCKED:
            consecutive_failures_ += 3;  // critical signal
            consecutive_successes_ = 0;
            break;

        case DetectionEvent::Type::DNS_POISONED:
            consecutive_failures_ += 1;
            consecutive_successes_ = 0;
            break;
    }

    if (consecutive_failures_ >= config_.escalation_threshold) {
        escalate("Detection events: " + std::string(
            event.type == DetectionEvent::Type::CONNECTION_RESET ? "RST" :
            event.type == DetectionEvent::Type::PROBE_RECEIVED ? "PROBE" :
            event.type == DetectionEvent::Type::IP_BLOCKED ? "BLOCKED" :
            "DETECTION"));
    }
}

void ProtocolOrchestrator::report_success() {
    stats_.successful_sends.fetch_add(1);

    if (!config_.adaptive) return;

    std::lock_guard<std::mutex> lock(strategy_mutex_);

    consecutive_successes_++;
    consecutive_failures_ = (std::max)(0, consecutive_failures_ - 1);

    // Check cooldown
    auto now = std::chrono::steady_clock::now();
    auto since_escalation = std::chrono::duration_cast<std::chrono::seconds>(
        now - last_escalation_).count();

    if (consecutive_successes_ >= config_.deescalation_threshold &&
        since_escalation >= config_.deescalation_cooldown_sec &&
        threat_level_ > ThreatLevel::NONE) {
        deescalate("Stable connection: " +
            std::to_string(consecutive_successes_) + " successes");
    }
}

void ProtocolOrchestrator::escalate(const std::string& reason) {
    if (threat_level_ >= ThreatLevel::CRITICAL) return;

    ThreatLevel old_level = threat_level_;
    threat_level_ = threat_level_from_int(static_cast<int>(threat_level_) + 1);
    stats_.escalations.fetch_add(1);
    stats_.current_threat = threat_level_;

    consecutive_failures_ = 0;
    last_escalation_ = std::chrono::steady_clock::now();

    // Apply new strategy for this threat level
    auto new_strategy = strategy_for_threat(threat_level_);
    apply_strategy(new_strategy);

    if (config_.on_strategy_change) {
        config_.on_strategy_change(old_level, threat_level_, reason);
    }
}

void ProtocolOrchestrator::deescalate(const std::string& reason) {
    if (threat_level_ <= ThreatLevel::NONE) return;

    ThreatLevel old_level = threat_level_;
    threat_level_ = threat_level_from_int(static_cast<int>(threat_level_) - 1);
    stats_.deescalations.fetch_add(1);
    stats_.current_threat = threat_level_;

    consecutive_successes_ = 0;

    auto new_strategy = strategy_for_threat(threat_level_);
    apply_strategy(new_strategy);

    if (config_.on_strategy_change) {
        config_.on_strategy_change(old_level, threat_level_, reason);
    }
}

OrchestratorStrategy ProtocolOrchestrator::strategy_for_threat(ThreatLevel level) {
    switch (level) {
        case ThreatLevel::NONE:
            return OrchestratorStrategy::max_compat();
        case ThreatLevel::LOW:
            return OrchestratorStrategy::performance();
        case ThreatLevel::MEDIUM:
            return OrchestratorStrategy::balanced();
        case ThreatLevel::HIGH:
        case ThreatLevel::CRITICAL:
            return OrchestratorStrategy::stealth();
        default:
            return OrchestratorStrategy::balanced();
    }
}

ThreatLevel ProtocolOrchestrator::get_threat_level() const {
    return threat_level_;
}

void ProtocolOrchestrator::set_threat_level(ThreatLevel level) {
    std::lock_guard<std::mutex> lock(strategy_mutex_);
    ThreatLevel old = threat_level_;
    threat_level_ = level;
    stats_.current_threat = level;
    auto new_strategy = strategy_for_threat(level);
    apply_strategy(new_strategy);
    if (config_.on_strategy_change && old != level) {
        config_.on_strategy_change(old, level, "Manual override");
    }
}

// ===== Strategy Management =====

void ProtocolOrchestrator::apply_strategy(const OrchestratorStrategy& strategy) {
    current_strategy_ = strategy;
    stats_.current_strategy_name = strategy.name;

    // Propagate shared secret
    if (!config_.shared_secret.empty()) {
        current_strategy_.probe_config.shared_secret = config_.shared_secret;
    }

    // Apply to core components
    if (strategy.enable_adversarial) {
        adversarial_.set_config(strategy.adversarial_config);
    }
    if (strategy.enable_flow_shaping) {
        flow_shaper_.set_config(strategy.flow_config);
    }
    if (strategy.enable_probe_resist) {
        probe_resist_.set_config(strategy.probe_config);
    }
    if (strategy.enable_mimicry) {
        TrafficMimicry::MimicConfig mc;
        mc.profile = strategy.mimic_profile;
        mimicry_.set_config(mc);
    }

    // Step 2B: Advanced DPI component
    if (strategy.enable_advanced_dpi) {
        init_advanced_dpi();
    } else {
        // Disable: stop and release
        if (advanced_dpi_ && advanced_dpi_->is_running()) {
            advanced_dpi_->stop();
        }
        advanced_dpi_.reset();
    }

    // Step 2B: TLS Fingerprint component
    if (strategy.enable_tls_fingerprint) {
        apply_tls_profile(strategy.tls_browser_profile);
    } else {
        tls_fingerprint_.reset();
    }
}

void ProtocolOrchestrator::set_strategy(const OrchestratorStrategy& strategy) {
    std::lock_guard<std::mutex> lock(strategy_mutex_);
    apply_strategy(strategy);
}

OrchestratorStrategy ProtocolOrchestrator::get_strategy() const {
    return current_strategy_;
}

void ProtocolOrchestrator::apply_preset(const std::string& name) {
    std::lock_guard<std::mutex> lock(strategy_mutex_);
    if (name == "stealth")      apply_strategy(OrchestratorStrategy::stealth());
    else if (name == "balanced") apply_strategy(OrchestratorStrategy::balanced());
    else if (name == "performance") apply_strategy(OrchestratorStrategy::performance());
    else if (name == "max_compat") apply_strategy(OrchestratorStrategy::max_compat());
}

// ===== Component Access =====

AdversarialPadding& ProtocolOrchestrator::adversarial() { return adversarial_; }
FlowShaper& ProtocolOrchestrator::flow_shaper() { return flow_shaper_; }
ProbeResist& ProtocolOrchestrator::probe_resist() { return probe_resist_; }
TrafficMimicry& ProtocolOrchestrator::mimicry() { return mimicry_; }

const AdversarialPadding& ProtocolOrchestrator::adversarial() const { return adversarial_; }
const FlowShaper& ProtocolOrchestrator::flow_shaper() const { return flow_shaper_; }
const ProbeResist& ProtocolOrchestrator::probe_resist() const { return probe_resist_; }
const TrafficMimicry& ProtocolOrchestrator::mimicry() const { return mimicry_; }

// Step 2B: New component accessors
AdvancedDPIBypass* ProtocolOrchestrator::advanced_dpi() {
    return advanced_dpi_.get();
}
const AdvancedDPIBypass* ProtocolOrchestrator::advanced_dpi() const {
    return advanced_dpi_.get();
}

ncp::TLSFingerprint* ProtocolOrchestrator::tls_fingerprint() {
    return tls_fingerprint_.get();
}
const ncp::TLSFingerprint* ProtocolOrchestrator::tls_fingerprint() const {
    return tls_fingerprint_.get();
}

// ===== Config & Stats =====

void ProtocolOrchestrator::set_config(const OrchestratorConfig& config) {
    config_ = config;
    if (!config_.shared_secret.empty()) {
        current_strategy_.probe_config.shared_secret = config_.shared_secret;
        probe_resist_.set_config(current_strategy_.probe_config);
    }
}

OrchestratorConfig ProtocolOrchestrator::get_config() const {
    return config_;
}

OrchestratorStats ProtocolOrchestrator::get_stats() const {
    return OrchestratorStats(stats_);
}

void ProtocolOrchestrator::reset_stats() {
    stats_.reset();
    adversarial_.reset_stats();
    flow_shaper_.reset_stats();
    probe_resist_.reset_stats();
    mimicry_.reset_stats();
    // Step 2B: reset advanced DPI stats via get_stats (no dedicated reset)
    // AdvancedDPIBypass doesn't have reset_stats() — stats are in Impl
}

void ProtocolOrchestrator::update_overhead_stats() {
    uint64_t orig = stats_.bytes_original.load();
    uint64_t wire = stats_.bytes_on_wire.load();
    if (orig > 0) {
        stats_.total_overhead_pct = (static_cast<double>(wire) / orig - 1.0) * 100.0;
    }
}

// ===== Health Monitor =====

void ProtocolOrchestrator::health_monitor_func() {
    while (running_.load()) {
        std::this_thread::sleep_for(
            std::chrono::seconds(config_.health_check_interval_sec));

        if (!running_.load()) break;

        // Periodic cleanup
        if (current_strategy_.enable_probe_resist) {
            probe_resist_.cleanup_stale_data();
        }

        // Update overhead stats
        update_overhead_stats();
    }
}

} // namespace DPI
} // namespace ncp
