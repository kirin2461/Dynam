#include "ncp_orchestrator.hpp"
#include "ncp_ech.hpp"

#include <algorithm>
#include <cstring>
#include <sodium.h>

// FIX #72: Magic bytes for auth header validation
static constexpr uint8_t NCP_AUTH_MAGIC[2] = { 0x4E, 0x43 };  // "NC"
static constexpr uint8_t NCP_AUTH_VERSION = 0x01;
static constexpr size_t  NCP_AUTH_HEADER_SIZE = 3;  // 2 magic + 1 version

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

// FIX #75: Dedicated CRITICAL preset with maximum protection
OrchestratorStrategy OrchestratorStrategy::paranoid() {
    OrchestratorStrategy s;
    s.name = "paranoid";
    s.min_threat = ThreatLevel::CRITICAL;

    s.enable_adversarial = true;
    s.adversarial_config = AdversarialConfig::aggressive();
    s.adversarial_config.min_pad_bytes = 64;
    s.adversarial_config.max_pad_bytes = 256;
    s.adversarial_config.dummy_probability = 0.15;

    s.enable_flow_shaping = true;
    s.flow_config = FlowShaperConfig::web_browsing();
    s.flow_config.enable_flow_dummy = true;
    s.flow_config.dummy_ratio = 0.20;
    s.flow_config.enable_constant_rate = true;

    s.enable_probe_resist = true;
    s.probe_config = ProbeResistConfig::strict();

    s.enable_mimicry = true;
    s.mimic_profile = TrafficMimicry::MimicProfile::HTTPS_APPLICATION;

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
        // Derive adversarial dummy key from shared secret so both peers match
        derive_dummy_key_from_secret_(config_.shared_secret);
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

// ===== Dummy Key Derivation =====

void ProtocolOrchestrator::derive_dummy_key_from_secret_(
    const std::vector<uint8_t>& secret) {
    // HKDF-SHA256(ikm=secret, salt="NCP-ADV-DUMMY-KEY-v1", info="NCP-ADV-DUMMY", len=32)
    static const std::string salt_str = "NCP-ADV-DUMMY-KEY-v1";
    std::vector<uint8_t> salt(salt_str.begin(), salt_str.end());

    // Extract: PRK = HMAC-SHA256(salt, IKM)
    uint8_t prk[crypto_auth_hmacsha256_BYTES];
    crypto_auth_hmacsha256_state st;
    crypto_auth_hmacsha256_init(&st, salt.data(), salt.size());
    crypto_auth_hmacsha256_update(&st, secret.data(), secret.size());
    crypto_auth_hmacsha256_final(&st, prk);

    // Expand: OKM = HMAC-SHA256(PRK, info || 0x01)
    static const std::string info_str = "NCP-ADV-DUMMY";
    uint8_t expand_input[64];
    std::memcpy(expand_input, info_str.data(), info_str.size());
    expand_input[info_str.size()] = 0x01;

    uint8_t okm[crypto_auth_hmacsha256_BYTES];  // 32 bytes
    crypto_auth_hmacsha256_state st2;
    crypto_auth_hmacsha256_init(&st2, prk, sizeof(prk));
    crypto_auth_hmacsha256_update(&st2, expand_input, info_str.size() + 1);
    crypto_auth_hmacsha256_final(&st2, okm);

    // Set the derived key on the adversarial padding instance
    adversarial_.set_session_dummy_key(okm, 32);

    // Wipe intermediates
    sodium_memzero(prk, sizeof(prk));
    sodium_memzero(okm, sizeof(okm));
    sodium_memzero(expand_input, sizeof(expand_input));
}

void ProtocolOrchestrator::synchronize_dummy_key(
    const std::vector<uint8_t>& shared_secret) {
    std::lock_guard<std::mutex> lock(strategy_mutex_);
    if (!shared_secret.empty()) {
        derive_dummy_key_from_secret_(shared_secret);
    }
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

    // Issue #57: reset TLS session so next start() re-emits handshake
    mimicry_.reset_tls_session();
}

bool ProtocolOrchestrator::is_running() const {
    return running_.load();
}

// ===== Helper: is current profile HTTPS-based? =====

static bool is_https_profile(TrafficMimicry::MimicProfile p) {
    return p == TrafficMimicry::MimicProfile::HTTPS_APPLICATION ||
           p == TrafficMimicry::MimicProfile::HTTPS_CLIENT_HELLO;
}

// =============================================================================
// FIX #73: Extract common send pipeline into private method to eliminate
// duplication between send() and send_async(). Snapshot strategy under lock
// so mid-pipeline strategy changes don't cause inconsistency.
// =============================================================================

std::vector<uint8_t> ProtocolOrchestrator::prepare_payload(
    const std::vector<uint8_t>& payload,
    OrchestratorStrategy& snapshot) {

    // Snapshot strategy under lock to prevent mid-pipeline changes
    {
        std::lock_guard<std::mutex> lock(strategy_mutex_);
        snapshot = current_strategy_;
    }

    std::vector<uint8_t> data = payload;

    // Step 1: Adversarial Padding (Phase 1)
    if (snapshot.enable_adversarial) {
        data = adversarial_.pad(data);
    }

    // Step 2: Protocol Mimicry (wrap in HTTPS/DNS/QUIC)
    if (snapshot.enable_mimicry) {
        data = mimicry_.wrap_payload(data, snapshot.mimic_profile);
    }

    // Step 3: Prepend auth token with magic header (Phase 3 client-side)
    if (snapshot.enable_probe_resist && !config_.is_server) {
        auto token = probe_resist_.generate_client_auth();
        std::vector<uint8_t> header;
        header.reserve(NCP_AUTH_HEADER_SIZE + token.size());
        header.push_back(NCP_AUTH_MAGIC[0]);
        header.push_back(NCP_AUTH_MAGIC[1]);
        header.push_back(NCP_AUTH_VERSION);
        header.insert(header.end(), token.begin(), token.end());
        data.insert(data.begin(), header.begin(), header.end());
    }

    return data;
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

    OrchestratorStrategy snapshot;
    std::vector<uint8_t> data = prepare_payload(payload, snapshot);

    // Step 4: Flow Shaping (Phase 2)
    if (snapshot.enable_flow_shaping) {
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

    OrchestratedPacket op;
    stats_.bytes_on_wire.fetch_add(data.size());
    op.data = std::move(data);
    update_overhead_stats();
    return {op};
}

void ProtocolOrchestrator::send_async(const std::vector<uint8_t>& payload) {
    if (!config_.enabled || payload.empty()) return;

    stats_.packets_sent.fetch_add(1);
    stats_.bytes_original.fetch_add(payload.size());

    OrchestratorStrategy snapshot;
    std::vector<uint8_t> data = prepare_payload(payload, snapshot);

    if (snapshot.enable_flow_shaping && flow_shaper_.is_running()) {
        flow_shaper_.enqueue(data, true);
    } else if (send_callback_) {
        OrchestratedPacket op;
        op.data = std::move(data);
        send_callback_(op);
    }
}

// ===== Server Pipeline: receive =====
// FIX #72/#73: Reordered receive pipeline:
//   1. Probe auth token stripped first (outermost, with magic header validation)
//   2. Flow dummy check
//   3. Adversarial dummy check (now uses instance method with HMAC marker)
//   4. Mimicry unwrap
//   5. Adversarial unpad (innermost layer)

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

    OrchestratorStrategy snapshot;
    {
        std::lock_guard<std::mutex> lock(strategy_mutex_);
        snapshot = current_strategy_;
    }

    std::vector<uint8_t> data = wire_data;

    // Step 1: Auth check (Phase 3 server-side)
    if (snapshot.enable_probe_resist && config_.is_server) {
        size_t auth_token_len = probe_resist_.get_config().nonce_length + 4 +
                                probe_resist_.get_config().auth_length;
        size_t total_auth_len = NCP_AUTH_HEADER_SIZE + auth_token_len;

        bool has_auth_header = (data.size() >= total_auth_len &&
                                data[0] == NCP_AUTH_MAGIC[0] &&
                                data[1] == NCP_AUTH_MAGIC[1] &&
                                data[2] == NCP_AUTH_VERSION);

        if (has_auth_header) {
            std::vector<uint8_t> auth_data(data.begin() + NCP_AUTH_HEADER_SIZE, data.end());

            AuthResult result = probe_resist_.process_connection(
                source_ip, source_port, auth_data.data(), auth_data.size(), ja3);

            if (auth_result) *auth_result = result;

            if (result != AuthResult::AUTHENTICATED) {
                return {};
            }

            if (auth_data.size() > auth_token_len) {
                data.assign(auth_data.begin() + auth_token_len, auth_data.end());
            } else {
                return {};
            }
        } else {
            AuthResult result = probe_resist_.process_connection(
                source_ip, source_port, data.data(), data.size(), ja3);

            if (auth_result) *auth_result = result;

            if (result != AuthResult::AUTHENTICATED) {
                return {};
            }
        }
    } else {
        if (auth_result) *auth_result = AuthResult::AUTHENTICATED;
    }

    // Step 2: Discard flow dummies
    if (snapshot.enable_flow_shaping) {
        if (FlowShaper::is_flow_dummy(data.data(), data.size())) {
            return {};
        }
    }

    // Step 3: Discard adversarial dummies
    // Uses instance method with HMAC-derived session marker + legacy fallback
    if (snapshot.enable_adversarial) {
        if (adversarial_.is_dummy_packet(data.data(), data.size())) {
            return {};
        }
    }

    // Step 4: Protocol unwrap (mimicry)
    if (snapshot.enable_mimicry) {
        data = mimicry_.unwrap_payload(data);
    }

    // Step 5: Adversarial unpad
    if (snapshot.enable_adversarial) {
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
            report_success_locked();
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
        escalate(std::string("Detection events: ") + (
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
    report_success_locked();
}

void ProtocolOrchestrator::report_success_locked() {
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

    mimicry_.reset_tls_session();

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

    mimicry_.reset_tls_session();

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
            return OrchestratorStrategy::stealth();
        case ThreatLevel::CRITICAL:
            return OrchestratorStrategy::paranoid();
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
    mimicry_.reset_tls_session();
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
    mimicry_.reset_tls_session();
}

OrchestratorStrategy ProtocolOrchestrator::get_strategy() const {
    return current_strategy_;
}

void ProtocolOrchestrator::apply_preset(const std::string& name) {
    std::lock_guard<std::mutex> lock(strategy_mutex_);
    if (name == "stealth")      apply_strategy(OrchestratorStrategy::stealth());
    else if (name == "paranoid") apply_strategy(OrchestratorStrategy::paranoid());
    else if (name == "balanced") apply_strategy(OrchestratorStrategy::balanced());
    else if (name == "performance") apply_strategy(OrchestratorStrategy::performance());
    else if (name == "max_compat") apply_strategy(OrchestratorStrategy::max_compat());
    mimicry_.reset_tls_session();
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
    std::lock_guard<std::mutex> lock(strategy_mutex_);
    config_ = config;
    if (!config_.shared_secret.empty()) {
        current_strategy_.probe_config.shared_secret = config_.shared_secret;
        probe_resist_.set_config(current_strategy_.probe_config);
        // Re-derive adversarial dummy key when shared_secret changes
        derive_dummy_key_from_secret_(config_.shared_secret);
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

        {
            std::lock_guard<std::mutex> lock(strategy_mutex_);
            if (current_strategy_.enable_probe_resist) {
                probe_resist_.cleanup_stale_data();
            }
        }

        update_overhead_stats();
    }
}

} // namespace DPI
} // namespace ncp
