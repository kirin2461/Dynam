#include "ncp_orchestrator.hpp"
#include "ncp_ech.hpp"

#include <algorithm>
#include <cstring>
#include <sodium.h>

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

    s.enable_tls_fingerprint = true;
    s.tls_browser_profile = ncp::BrowserType::CHROME;
    s.tls_rotate_per_connection = true;
    s.enable_advanced_dpi = true;
    s.dpi_preset = AdvancedDPIBypass::BypassPreset::STEALTH;

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

    s.enable_tls_fingerprint = true;
    s.tls_browser_profile = ncp::BrowserType::CHROME;
    s.tls_rotate_per_connection = false;
    s.enable_advanced_dpi = true;
    s.dpi_preset = AdvancedDPIBypass::BypassPreset::MODERATE;

    return s;
}

OrchestratorStrategy OrchestratorStrategy::performance() {
    OrchestratorStrategy s;
    s.name = "performance";
    s.min_threat = ThreatLevel::LOW;

    s.enable_adversarial = true;
    s.adversarial_config = AdversarialConfig::minimal();

    s.enable_flow_shaping = false;

    s.enable_probe_resist = true;
    s.probe_config = ProbeResistConfig::permissive();

    s.enable_mimicry = true;
    s.mimic_profile = TrafficMimicry::MimicProfile::HTTPS_APPLICATION;

    s.enable_tls_fingerprint = true;
    s.tls_browser_profile = ncp::BrowserType::CHROME;
    s.enable_advanced_dpi = false;

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

    s.enable_tls_fingerprint = true;
    s.tls_browser_profile = ncp::BrowserType::CHROME;
    s.enable_advanced_dpi = false;

    return s;
}

// ===== OrchestratorConfig Presets =====

OrchestratorConfig OrchestratorConfig::client_default() {
    OrchestratorConfig c;
    c.is_server = false;
    c.adaptive = true;
    c.strategy = OrchestratorStrategy::balanced();
    return c;
}

OrchestratorConfig OrchestratorConfig::server_default() {
    OrchestratorConfig c;
    c.is_server = true;
    c.adaptive = false;
    c.strategy = OrchestratorStrategy::balanced();
    return c;
}

// ===== Constructor / Destructor =====

ProtocolOrchestrator::ProtocolOrchestrator()
    : ProtocolOrchestrator(OrchestratorConfig::client_default()) {}

ProtocolOrchestrator::ProtocolOrchestrator(const OrchestratorConfig& config)
    : config_(config),
      current_strategy_(config.strategy),
      threat_level_(ThreatLevel::NONE),
      tls_fingerprint_(config.strategy.tls_browser_profile),
      ech_initialized_(false),
      consecutive_failures_(0),
      consecutive_successes_(0) {

    if (!config_.shared_secret.empty()) {
        current_strategy_.probe_config.shared_secret = config_.shared_secret;
    }

    if (config_.ech_enabled) {
        if (!config_.ech_config_data.empty()) {
            if (ECH::parse_ech_config(config_.ech_config_data, ech_config_)) {
                ech_initialized_ = true;
            } else {
                std::string public_name = (current_strategy_.tls_browser_profile == ncp::BrowserType::SAFARI)
                                          ? "apple.com" : "cloudflare.com";
                ech_config_ = ECH::create_test_ech_config(
                    public_name,
                    ECH::HPKECipherSuite(),
                    ech_private_key_
                );
                ech_initialized_ = true;
            }
        } else {
            std::string public_name = (current_strategy_.tls_browser_profile == ncp::BrowserType::SAFARI)
                                      ? "apple.com" : "cloudflare.com";
            ech_config_ = ECH::create_test_ech_config(
                public_name,
                ECH::HPKECipherSuite(),
                ech_private_key_
            );
            ech_initialized_ = true;
        }
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

    if (config_.health_check_interval_sec > 0) {
        health_thread_ = std::thread(&ProtocolOrchestrator::health_monitor_func, this);
    }
}

void ProtocolOrchestrator::stop() {
    running_.store(false);
    flow_shaper_.stop();
    if (advanced_dpi_) {
        advanced_dpi_->stop();
    }
    if (health_thread_.joinable()) {
        health_thread_.join();
    }
}

bool ProtocolOrchestrator::is_running() const {
    return running_.load();
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

    bool is_client_hello = (!data.empty() && data.size() > 5 &&
                           data[0] == 0x16 && data[1] == 0x03 && data[5] == 0x01);

    if (current_strategy_.enable_tls_fingerprint && is_client_hello) {
        if (current_strategy_.tls_rotate_per_connection) {
            static const ncp::BrowserType profiles[] = {
                ncp::BrowserType::CHROME, ncp::BrowserType::FIREFOX,
                ncp::BrowserType::SAFARI, ncp::BrowserType::EDGE
            };
            tls_fingerprint_.set_profile(profiles[randombytes_uniform(4)]);
        }
        stats_.tls_fingerprints_applied.fetch_add(1);
    }

    if (is_client_hello && current_strategy_.enable_advanced_dpi && advanced_dpi_) {
        auto segments = advanced_dpi_->process_outgoing(data.data(), data.size());
        stats_.advanced_dpi_segments.fetch_add(segments.size());

        std::vector<OrchestratedPacket> result;
        for (size_t i = 0; i < segments.size(); ++i) {
            auto packets = process_single_segment_(
                std::move(segments[i]), (i == 0));
            for (auto& pkt : packets) {
                result.push_back(std::move(pkt));
            }
        }
        update_overhead_stats();
        return result;
    }

    if (config_.ech_enabled && ech_initialized_ && is_client_hello &&
        !current_strategy_.enable_advanced_dpi) {
        auto ech_result = ECH::apply_ech(data, ech_config_);
        if (!ech_result.empty() && ech_result.size() > data.size()) {
            data = std::move(ech_result);
            stats_.ech_encryptions.fetch_add(1);
        }
    }

    return process_single_segment_(std::move(data), true);
}

std::vector<OrchestratedPacket> ProtocolOrchestrator::process_single_segment_(
    std::vector<uint8_t> data, bool is_first_segment) {

    if (current_strategy_.enable_adversarial) {
        data = adversarial_.pad(data);
    }

    if (current_strategy_.enable_mimicry) {
        data = mimicry_.wrap_payload(data, current_strategy_.mimic_profile);
    }

    if (current_strategy_.enable_probe_resist && !config_.is_server && is_first_segment) {
        auto token = probe_resist_.generate_client_auth();
        data.insert(data.begin(), token.begin(), token.end());
    }

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
        return result;
    }

    OrchestratedPacket op;
    stats_.bytes_on_wire.fetch_add(data.size());
    op.data = std::move(data);
    return {op};
}

void ProtocolOrchestrator::send_async(const std::vector<uint8_t>& payload) {
    if (!config_.enabled || payload.empty()) return;

    stats_.packets_sent.fetch_add(1);
    stats_.bytes_original.fetch_add(payload.size());

    std::vector<uint8_t> data = payload;

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

    if (current_strategy_.enable_flow_shaping && flow_shaper_.is_running()) {
        flow_shaper_.enqueue(data, true);
    } else if (send_callback_) {
        OrchestratedPacket op;
        op.data = std::move(data);
        send_callback_(op);
    }
}

// ===== Server Pipeline: receive =====
// FIX: Reordered receive pipeline so that:
//   1. Probe auth token is stripped first (always outermost)
//   2. Flow dummy check (flow shaper inserts dummies after mimicry wrapping)
//   3. Mimicry unwrap (removes protocol disguise)
//   4. Adversarial dummy check + unpad (adversarial is innermost layer)
//
// Previously: adversarial dummy check ran before mimicry unwrap,
// which meant the check was scanning mimicry-wrapped data and could
// never match the adversarial dummy pattern inside.

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

    // Step 1: Probe authentication (outermost layer — prepended token)
    if (current_strategy_.enable_probe_resist && config_.is_server) {
        AuthResult result = probe_resist_.process_connection(
            source_ip, source_port, data.data(), data.size(), ja3);

        if (auth_result) *auth_result = result;

        if (result != AuthResult::AUTHENTICATED) {
            return {};
        }

        size_t auth_len = probe_resist_.get_config().nonce_length + 4 +
                          probe_resist_.get_config().auth_length;
        if (data.size() > auth_len) {
            data.erase(data.begin(), data.begin() + auth_len);
        }
    } else {
        if (auth_result) *auth_result = AuthResult::AUTHENTICATED;
    }

    // Step 2: Flow shaper dummy check (dummies are injected post-mimicry)
    if (current_strategy_.enable_flow_shaping) {
        if (FlowShaper::is_flow_dummy(data.data(), data.size())) {
            return {};
        }
    }

    // Step 3: Protocol mimicry unwrap (removes HTTP/TLS/DNS/etc. wrapper)
    if (current_strategy_.enable_mimicry) {
        data = mimicry_.unwrap_payload(data);
    }

    // Step 4: Adversarial dummy check (after mimicry unwrap, before unpad)
    if (current_strategy_.enable_adversarial) {
        if (AdversarialPadding::is_dummy(data.data(), data.size())) {
            return {};
        }
    }

    // Step 5: Adversarial unpad (innermost layer)
    if (current_strategy_.enable_adversarial) {
        data = adversarial_.unpad(data);
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
            report_success_locked_();
            return;

        case DetectionEvent::Type::CONNECTION_RESET:
        case DetectionEvent::Type::TLS_ALERT:
            consecutive_failures_ += 2;
            consecutive_successes_ = 0;
            break;

        case DetectionEvent::Type::CONNECTION_TIMEOUT:
        case DetectionEvent::Type::THROTTLED:
            consecutive_failures_ += 1;
            consecutive_successes_ = 0;
            break;

        case DetectionEvent::Type::PROBE_RECEIVED:
        case DetectionEvent::Type::IP_BLOCKED:
            consecutive_failures_ += 3;
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
    report_success_locked_();
}

void ProtocolOrchestrator::report_success_locked_() {
    stats_.successful_sends.fetch_add(1);

    consecutive_successes_++;
    consecutive_failures_ = (std::max)(0, consecutive_failures_ - 1);

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

    if (!config_.shared_secret.empty()) {
        current_strategy_.probe_config.shared_secret = config_.shared_secret;
    }

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

    if (strategy.enable_tls_fingerprint) {
        tls_fingerprint_.set_profile(strategy.tls_browser_profile);
    }

    rebuild_advanced_dpi_();
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

// ===== Phase 4A: AdvancedDPIBypass management =====

void ProtocolOrchestrator::init_advanced_dpi_() {
    if (!current_strategy_.enable_advanced_dpi) {
        advanced_dpi_.reset();
        return;
    }

    advanced_dpi_ = std::make_unique<AdvancedDPIBypass>();

    AdvancedDPIConfig adv_cfg;
    adv_cfg.base_config.target_host = "";
    adv_cfg.tspu_bypass = (current_strategy_.dpi_preset == AdvancedDPIBypass::BypassPreset::STEALTH);

    switch (current_strategy_.dpi_preset) {
        case AdvancedDPIBypass::BypassPreset::STEALTH:
            adv_cfg.techniques = {
                EvasionTechnique::SNI_SPLIT,
                EvasionTechnique::TCP_SEGMENTATION,
                EvasionTechnique::IP_TTL_TRICKS,
                EvasionTechnique::FAKE_SNI,
                EvasionTechnique::TLS_GREASE,
                EvasionTechnique::TIMING_JITTER,
                EvasionTechnique::TCP_DISORDER
            };
            adv_cfg.enable_ech = (config_.ech_enabled && ech_initialized_);
            break;
        case AdvancedDPIBypass::BypassPreset::MODERATE:
            adv_cfg.techniques = {
                EvasionTechnique::SNI_SPLIT,
                EvasionTechnique::TCP_SEGMENTATION,
                EvasionTechnique::TLS_GREASE
            };
            adv_cfg.enable_ech = (config_.ech_enabled && ech_initialized_);
            break;
        case AdvancedDPIBypass::BypassPreset::MINIMAL:
        default:
            adv_cfg.techniques = {
                EvasionTechnique::SNI_SPLIT
            };
            break;
    }

    if (adv_cfg.enable_ech && ech_initialized_) {
        adv_cfg.ech_config_list = config_.ech_config_data;
    }

    advanced_dpi_->set_tls_fingerprint(&tls_fingerprint_);

    if (advanced_dpi_->initialize(adv_cfg)) {
        advanced_dpi_->set_tls_fingerprint(&tls_fingerprint_);
        if (ech_initialized_) {
            advanced_dpi_->set_ech_config(config_.ech_config_data);
        }
        advanced_dpi_->start();
    } else {
        advanced_dpi_.reset();
    }
}

void ProtocolOrchestrator::rebuild_advanced_dpi_() {
    if (current_strategy_.enable_advanced_dpi) {
        if (advanced_dpi_) {
            advanced_dpi_->stop();
        }
        init_advanced_dpi_();
    } else {
        if (advanced_dpi_) {
            advanced_dpi_->stop();
            advanced_dpi_.reset();
        }
    }
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

ncp::TLSFingerprint& ProtocolOrchestrator::tls_fingerprint() { return tls_fingerprint_; }
const ncp::TLSFingerprint& ProtocolOrchestrator::tls_fingerprint() const { return tls_fingerprint_; }

AdvancedDPIBypass* ProtocolOrchestrator::advanced_dpi() { return advanced_dpi_.get(); }
const AdvancedDPIBypass* ProtocolOrchestrator::advanced_dpi() const { return advanced_dpi_.get(); }

const ECH::ECHConfig& ProtocolOrchestrator::ech_config() const { return ech_config_; }
bool ProtocolOrchestrator::is_ech_initialized() const { return ech_initialized_; }

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

        if (current_strategy_.enable_probe_resist) {
            probe_resist_.cleanup_stale_data();
        }

        update_overhead_stats();
    }
}

} // namespace DPI
} // namespace ncp
