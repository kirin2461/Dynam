#include "ncp_flow_shaper.hpp"
#include <algorithm>
#include <cstring>
#define _USE_MATH_DEFINES
#include <cmath>
#include <cassert>
#include <condition_variable>
#include <sodium.h>
#include <shared_mutex>

namespace ncp {
namespace DPI {

// ===== String conversions =====
const char* flow_profile_to_string(FlowProfile p) noexcept {
    switch (p) {
        case FlowProfile::WEB_BROWSING:  return "WEB_BROWSING";
        case FlowProfile::VIDEO_STREAM: return "VIDEO_STREAM";
        case FlowProfile::MESSENGER:    return "MESSENGER";
        case FlowProfile::GAMING:       return "GAMING";
        case FlowProfile::FILE_DOWNLOAD: return "FILE_DOWNLOAD";
        case FlowProfile::CUSTOM:       return "CUSTOM";
        default:                        return "UNKNOWN";
    }
}

FlowProfile flow_profile_from_string(const std::string& name) noexcept {
    if (name == "WEB_BROWSING")   return FlowProfile::WEB_BROWSING;
    if (name == "VIDEO_STREAM")  return FlowProfile::VIDEO_STREAM;
    if (name == "MESSENGER")     return FlowProfile::MESSENGER;
    if (name == "GAMING")        return FlowProfile::GAMING;
    if (name == "FILE_DOWNLOAD") return FlowProfile::FILE_DOWNLOAD;
    if (name == "CUSTOM")        return FlowProfile::CUSTOM;
    return FlowProfile::WEB_BROWSING;
}

// ===== SizeDistribution presets =====
SizeDistribution SizeDistribution::web_browsing() {
    return {{ {52, 0.30}, {150, 0.15}, {350, 0.10}, {580, 0.08}, {1200, 0.12}, {1460, 0.25} }};
}
SizeDistribution SizeDistribution::video_stream() {
    return {{ {52, 0.20}, {200, 0.05}, {1200, 0.15}, {1460, 0.60} }};
}
SizeDistribution SizeDistribution::messenger() {
    return {{ {52, 0.25}, {80, 0.20}, {150, 0.25}, {300, 0.15}, {600, 0.10}, {1200, 0.05} }};
}
SizeDistribution SizeDistribution::gaming() {
    return {{ {52, 0.10}, {64, 0.25}, {80, 0.25}, {100, 0.20}, {150, 0.15}, {300, 0.05} }};
}
SizeDistribution SizeDistribution::file_download() {
    return {{ {52, 0.15}, {1460, 0.85} }};
}

// ===== BurstModel presets =====
BurstModel BurstModel::web_browsing() {
    BurstModel m;
    m.burst_packets_min = 8; m.burst_packets_max = 35;
    m.burst_inter_ms_min = 0.5; m.burst_inter_ms_max = 15.0;
    m.pause_ms_min = 1500.0; m.pause_ms_max = 8000.0;
    m.timing_distribution = Distribution::PARETO; m.pareto_alpha = 1.5;
    return m;
}
BurstModel BurstModel::video_stream() {
    BurstModel m;
    m.burst_packets_min = 50; m.burst_packets_max = 200;
    m.burst_inter_ms_min = 0.1; m.burst_inter_ms_max = 5.0;
    m.pause_ms_min = 10.0; m.pause_ms_max = 50.0;
    m.timing_distribution = Distribution::GAUSSIAN; m.pareto_alpha = 2.0;
    return m;
}
BurstModel BurstModel::messenger() {
    BurstModel m;
    m.burst_packets_min = 2; m.burst_packets_max = 8;
    m.burst_inter_ms_min = 5.0; m.burst_inter_ms_max = 50.0;
    m.pause_ms_min = 3000.0; m.pause_ms_max = 30000.0;
    m.timing_distribution = Distribution::EXPONENTIAL; m.pareto_alpha = 1.2;
    return m;
}
BurstModel BurstModel::gaming() {
    BurstModel m;
    m.burst_packets_min = 100; m.burst_packets_max = 1000;
    m.burst_inter_ms_min = 15.0; m.burst_inter_ms_max = 50.0;
    m.pause_ms_min = 0.0; m.pause_ms_max = 100.0;
    m.timing_distribution = Distribution::GAUSSIAN; m.pareto_alpha = 3.0;
    return m;
}
BurstModel BurstModel::file_download() {
    BurstModel m;
    m.burst_packets_min = 100; m.burst_packets_max = 500;
    m.burst_inter_ms_min = 0.05; m.burst_inter_ms_max = 2.0;
    m.pause_ms_min = 5.0; m.pause_ms_max = 50.0;
    m.timing_distribution = Distribution::GAUSSIAN; m.pareto_alpha = 2.5;
    return m;
}

// ===== FlowShaperConfig presets =====
FlowShaperConfig FlowShaperConfig::web_browsing() {
    FlowShaperConfig c; c.profile = FlowProfile::WEB_BROWSING;
    c.size_dist = SizeDistribution::web_browsing(); c.burst_model = BurstModel::web_browsing();
    return c;
}
FlowShaperConfig FlowShaperConfig::video_stream() {
    FlowShaperConfig c; c.profile = FlowProfile::VIDEO_STREAM;
    c.size_dist = SizeDistribution::video_stream(); c.burst_model = BurstModel::video_stream();
    return c;
}
FlowShaperConfig FlowShaperConfig::messenger() {
    FlowShaperConfig c; c.profile = FlowProfile::MESSENGER;
    c.size_dist = SizeDistribution::messenger(); c.burst_model = BurstModel::messenger();
    return c;
}
FlowShaperConfig FlowShaperConfig::gaming() {
    FlowShaperConfig c; c.profile = FlowProfile::GAMING;
    c.size_dist = SizeDistribution::gaming(); c.burst_model = BurstModel::gaming();
    return c;
}
FlowShaperConfig FlowShaperConfig::file_download() {
    FlowShaperConfig c; c.profile = FlowProfile::FILE_DOWNLOAD;
    c.size_dist = SizeDistribution::file_download(); c.burst_model = BurstModel::file_download();
    return c;
}

// ===== Impl Structure =====
struct FlowShaper::Impl {
    enum class BurstState { IDLE, BURSTING, PAUSING };

    FlowShaperConfig config;
    mutable std::shared_mutex config_mutex;

    BurstState burst_state = BurstState::IDLE;
    uint32_t packets_in_current_burst = 0;
    uint32_t current_burst_target = 0;
    std::chrono::steady_clock::time_point last_packet_time;
    std::chrono::steady_clock::time_point pause_end_time;

    std::atomic<uint64_t> upload_bytes{0};
    std::atomic<uint64_t> download_bytes{0};

    struct QueueEntry { std::vector<uint8_t> data; bool is_upload; };
    std::queue<QueueEntry> packet_queue;
    std::mutex queue_mutex;
    std::condition_variable_any queue_cv;

    std::atomic<bool> running{false};
    std::thread worker_thread;
    FlowSendCallback send_callback;

    std::vector<double> cumulative_weights;
    std::array<uint8_t, 4> dummy_marker;
    std::array<uint8_t, 32> session_key;
    FlowShaperStats stats;

    Impl() {
        last_packet_time = std::chrono::steady_clock::now();
        randombytes_buf(session_key.data(), session_key.size());
        derive_dummy_marker();
    }

    void derive_dummy_marker() {
        static const uint8_t context[] = "ncp.flow.dummy.marker";
        crypto_generichash(dummy_marker.data(), dummy_marker.size(),
                           context, sizeof(context) - 1,
                           session_key.data(), session_key.size());
    }

    void apply_profile_defaults() {
        if (config.size_dist.buckets.empty()) {
            switch (config.profile) {
                case FlowProfile::VIDEO_STREAM: config.size_dist = SizeDistribution::video_stream(); break;
                case FlowProfile::MESSENGER:    config.size_dist = SizeDistribution::messenger(); break;
                case FlowProfile::GAMING:       config.size_dist = SizeDistribution::gaming(); break;
                case FlowProfile::FILE_DOWNLOAD: config.size_dist = SizeDistribution::file_download(); break;
                default:                        config.size_dist = SizeDistribution::web_browsing(); break;
            }
        }
        precompute_weights();
    }

    void precompute_weights() {
        cumulative_weights.clear();
        double sum = 0.0;
        for (const auto& b : config.size_dist.buckets) { sum += b.weight; cumulative_weights.push_back(sum); }
        if (sum > 0.0) for (auto& w : cumulative_weights) w /= sum;
    }
};

// ===== FlowShaper implementation =====
FlowShaper::FlowShaper() : impl_(std::make_unique<Impl>()) {
    ncp::csprng_init();
    impl_->config = FlowShaperConfig::web_browsing();
    impl_->apply_profile_defaults();
}

FlowShaper::~FlowShaper() {
    stop();
    sodium_memzero(impl_->session_key.data(), impl_->session_key.size());
}

FlowShaper::FlowShaper(FlowShaper&&) noexcept = default;
FlowShaper& FlowShaper::operator=(FlowShaper&&) noexcept = default;

void FlowShaper::start(FlowSendCallback callback) {
    if (impl_->running.load()) return;
    impl_->send_callback = std::move(callback);
    impl_->running.store(true);
    impl_->worker_thread = std::thread([this]() {
        while (impl_->running.load()) {
            Impl::QueueEntry entry;
            bool has_entry = false;
            {
                std::unique_lock<std::mutex> lock(impl_->queue_mutex);
                if (!impl_->packet_queue.empty()) { entry = std::move(impl_->packet_queue.front()); impl_->packet_queue.pop(); has_entry = true; }
            }
            if (has_entry) {
                auto shaped = shape_sync(entry.data, entry.is_upload);
                for (auto& sp : shaped) {
                    if (sp.delay_before_send.count() > 0) std::this_thread::sleep_for(sp.delay_before_send);
                    if (impl_->send_callback) impl_->send_callback(sp);
                }
            } else {
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
        }
    });
}

void FlowShaper::stop() {
    impl_->running.store(false);
    if (impl_->worker_thread.joinable()) impl_->worker_thread.join();
}

bool FlowShaper::is_running() const { return impl_->running.load(); }

void FlowShaper::enqueue(const std::vector<uint8_t>& packet, bool is_upload) {
    std::lock_guard<std::mutex> lock(impl_->queue_mutex);
    impl_->packet_queue.push({packet, is_upload});
}

void FlowShaper::enqueue_batch(const std::vector<std::vector<uint8_t>>& packets, bool is_upload) {
    std::lock_guard<std::mutex> lock(impl_->queue_mutex);
    for (const auto& p : packets) impl_->packet_queue.push({p, is_upload});
}

std::vector<ShapedPacket> FlowShaper::shape_sync(const std::vector<uint8_t>& packet, bool is_upload) {
    FlowShaperConfig cfg;
    { std::shared_lock<std::shared_mutex> lock(impl_->config_mutex); cfg = impl_->config; }

    if (!cfg.enabled || packet.empty()) {
        ShapedPacket sp; sp.data = packet; sp.is_upload = is_upload; return {sp};
    }

    impl_->stats.packets_original.fetch_add(1);
    impl_->stats.bytes_original.fetch_add(packet.size());

    std::vector<ShapedPacket> result;
    auto sized = reshape_size(packet);
    for (auto& pkt : sized) {
        ShapedPacket sp;
        sp.data = std::move(pkt);
        sp.is_upload = is_upload;
        if (cfg.enable_timing_shaping) sp.delay_before_send = next_delay();
        impl_->stats.packets_shaped.fetch_add(1);
        impl_->stats.bytes_shaped.fetch_add(sp.data.size());
        result.push_back(std::move(sp));
    }
    return result;
}

std::vector<std::vector<uint8_t>> FlowShaper::reshape_size(const std::vector<uint8_t>& packet) {
    size_t target = select_target_size();
    if (packet.size() <= target) {
        std::vector<uint8_t> padded = packet;
        padded.resize(target);
        if (target > packet.size()) ncp::csprng_fill(padded.data() + packet.size(), target - packet.size());
        return { padded };
    }
    // Simple split for now
    std::vector<std::vector<uint8_t>> chunks;
    for (size_t i = 0; i < packet.size(); i += target) {
        size_t sz = std::min(target, packet.size() - i);
        chunks.emplace_back(packet.begin() + i, packet.begin() + i + sz);
    }
    return chunks;
}

size_t FlowShaper::select_target_size() {
    std::shared_lock<std::shared_mutex> lock(impl_->config_mutex);
    if (impl_->cumulative_weights.empty()) return 1460;
    double r = ncp::csprng_double();
    for (size_t i = 0; i < impl_->cumulative_weights.size(); ++i) {
        if (r <= impl_->cumulative_weights[i]) return impl_->config.size_dist.buckets[i].size;
    }
    return impl_->config.size_dist.buckets.back().size;
}

std::chrono::microseconds FlowShaper::next_delay() {
    std::shared_lock<std::shared_mutex> lock(impl_->config_mutex);
    double delay_ms = ncp::csprng_double_range(impl_->config.burst_model.burst_inter_ms_min, impl_->config.burst_model.burst_inter_ms_max);
    return std::chrono::microseconds(static_cast<long long>(delay_ms * 1000.0));
}

bool FlowShaper::should_burst() const { return impl_->burst_state == Impl::BurstState::BURSTING; }

ShapedPacket FlowShaper::generate_dummy() {
    ShapedPacket sp;
    size_t sz = select_target_size();
    sp.data.resize(4 + sz);
    std::memcpy(sp.data.data(), impl_->dummy_marker.data(), 4);
    ncp::csprng_fill(sp.data.data() + 4, sz);
    sp.is_dummy = true;
    sp.is_upload = true;
    return sp;
}

ShapedPacket FlowShaper::generate_keepalive() {
    ShapedPacket sp = generate_dummy();
    sp.is_keepalive = true;
    return sp;
}

bool FlowShaper::is_flow_dummy(const uint8_t* data, size_t len) const {
    if (len < 4) return false;
    return std::memcmp(data, impl_->dummy_marker.data(), 4) == 0;
}

double FlowShaper::current_ratio() const {
    uint64_t up = impl_->upload_bytes.load();
    uint64_t down = impl_->download_bytes.load();
    return (up + down == 0) ? 0.5 : static_cast<double>(up) / (up + down);
}

bool FlowShaper::needs_ratio_balance() const {
    double r = current_ratio();
    std::shared_lock<std::shared_mutex> lock(impl_->config_mutex);
    return std::abs(r - impl_->config.target_upload_ratio) > impl_->config.ratio_tolerance;
}

void FlowShaper::update_config(const FlowShaperConfig& cfg) {
    std::unique_lock<std::shared_mutex> lock(impl_->config_mutex);
    impl_->config = cfg;
    impl_->apply_profile_defaults();
}

FlowShaperConfig FlowShaper::get_config() const {
    std::shared_lock<std::shared_mutex> lock(impl_->config_mutex);
    return impl_->config;
}

FlowShaperStats FlowShaper::get_stats() const { return impl_->stats; }

void FlowShaper::reset_stats() { impl_->stats.reset(); impl_->upload_bytes = 0; impl_->download_bytes = 0; }

} // namespace DPI
} // namespace ncp
