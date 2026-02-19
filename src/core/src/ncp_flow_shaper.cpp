#include "ncp_flow_shaper.hpp"

#include <algorithm>
#include <cstring>
#include <cmath>
#include <cassert>
#include <condition_variable>

#ifdef _WIN32
#  define NOMINMAX
#  include <windows.h>
#  include <bcrypt.h>
#  undef min
#  undef max
#  undef ERROR
#else
#  include <fcntl.h>
#  include <unistd.h>
#endif

namespace ncp {
namespace DPI {

// ===== String conversions =====

const char* flow_profile_to_string(FlowProfile p) noexcept {
    switch (p) {
        case FlowProfile::WEB_BROWSING:  return "WEB_BROWSING";
        case FlowProfile::VIDEO_STREAM:  return "VIDEO_STREAM";
        case FlowProfile::MESSENGER:     return "MESSENGER";
        case FlowProfile::GAMING:        return "GAMING";
        case FlowProfile::FILE_DOWNLOAD: return "FILE_DOWNLOAD";
        case FlowProfile::CUSTOM:        return "CUSTOM";
        default: return "UNKNOWN";
    }
}

FlowProfile flow_profile_from_string(const std::string& name) noexcept {
    if (name == "WEB_BROWSING")  return FlowProfile::WEB_BROWSING;
    if (name == "VIDEO_STREAM")  return FlowProfile::VIDEO_STREAM;
    if (name == "MESSENGER")     return FlowProfile::MESSENGER;
    if (name == "GAMING")        return FlowProfile::GAMING;
    if (name == "FILE_DOWNLOAD") return FlowProfile::FILE_DOWNLOAD;
    if (name == "CUSTOM")        return FlowProfile::CUSTOM;
    return FlowProfile::WEB_BROWSING;
}

// ===== SizeDistribution presets =====

SizeDistribution SizeDistribution::web_browsing() {
    // Real HTTPS browsing: many small ACKs, some medium, few large
    return {{
        {52, 0.30},     // TCP ACK (no payload)
        {150, 0.15},    // small HTTP responses / headers
        {350, 0.10},    // medium fragments
        {580, 0.08},    // medium-large
        {1200, 0.12},   // large content chunks
        {1460, 0.25},   // MTU-sized segments
    }};
}

SizeDistribution SizeDistribution::video_stream() {
    // Video: mostly large downstream, small ACKs upstream
    return {{
        {52, 0.20},     // ACKs
        {200, 0.05},    // control messages
        {1200, 0.15},   // medium video chunks
        {1460, 0.60},   // MTU-sized video frames
    }};
}

SizeDistribution SizeDistribution::messenger() {
    // Chat: mostly small packets
    return {{
        {52, 0.25},     // ACKs
        {80, 0.20},     // typing indicator
        {150, 0.25},    // short messages
        {300, 0.15},    // medium messages
        {600, 0.10},    // long messages
        {1200, 0.05},   // images/stickers (chunked)
    }};
}

SizeDistribution SizeDistribution::gaming() {
    // Gaming: small uniform packets at high frequency
    return {{
        {52, 0.10},     // ACKs
        {64, 0.25},     // game state updates
        {80, 0.25},     // input packets
        {100, 0.20},    // slightly larger updates
        {150, 0.15},    // position sync
        {300, 0.05},    // occasional larger
    }};
}

SizeDistribution SizeDistribution::file_download() {
    // Download: huge downstream, tiny upstream
    return {{
        {52, 0.15},     // ACKs (upstream)
        {1460, 0.85},   // MTU-sized data (downstream)
    }};
}

// ===== BurstModel presets =====

BurstModel BurstModel::web_browsing() {
    BurstModel m;
    m.burst_packets_min = 8;
    m.burst_packets_max = 35;
    m.burst_inter_ms_min = 0.5;
    m.burst_inter_ms_max = 15.0;
    m.pause_ms_min = 1500.0;
    m.pause_ms_max = 8000.0;
    m.timing_distribution = Distribution::PARETO;
    m.pareto_alpha = 1.5;
    return m;
}

BurstModel BurstModel::video_stream() {
    BurstModel m;
    m.burst_packets_min = 50;
    m.burst_packets_max = 200;
    m.burst_inter_ms_min = 0.1;
    m.burst_inter_ms_max = 5.0;
    m.pause_ms_min = 10.0;
    m.pause_ms_max = 50.0;   // almost no pauses
    m.timing_distribution = Distribution::GAUSSIAN;
    m.pareto_alpha = 2.0;
    return m;
}

BurstModel BurstModel::messenger() {
    BurstModel m;
    m.burst_packets_min = 2;
    m.burst_packets_max = 8;
    m.burst_inter_ms_min = 5.0;
    m.burst_inter_ms_max = 50.0;
    m.pause_ms_min = 3000.0;
    m.pause_ms_max = 30000.0;  // long idle between messages
    m.timing_distribution = Distribution::EXPONENTIAL;
    m.pareto_alpha = 1.2;
    return m;
}

BurstModel BurstModel::gaming() {
    BurstModel m;
    m.burst_packets_min = 100;
    m.burst_packets_max = 1000;
    m.burst_inter_ms_min = 15.0;   // ~60Hz
    m.burst_inter_ms_max = 50.0;   // ~20Hz
    m.pause_ms_min = 0.0;
    m.pause_ms_max = 100.0;  // basically continuous
    m.timing_distribution = Distribution::UNIFORM;
    m.pareto_alpha = 3.0;
    return m;
}

BurstModel BurstModel::file_download() {
    BurstModel m;
    m.burst_packets_min = 100;
    m.burst_packets_max = 500;
    m.burst_inter_ms_min = 0.05;
    m.burst_inter_ms_max = 2.0;
    m.pause_ms_min = 5.0;
    m.pause_ms_max = 50.0;
    m.timing_distribution = Distribution::GAUSSIAN;
    m.pareto_alpha = 2.5;
    return m;
}

// ===== FlowShaperConfig presets =====

FlowShaperConfig FlowShaperConfig::web_browsing() {
    FlowShaperConfig c;
    c.profile = FlowProfile::WEB_BROWSING;
    c.size_dist = SizeDistribution::web_browsing();
    c.burst_model = BurstModel::web_browsing();
    c.target_upload_ratio = 0.15;
    c.keepalive_interval_ms = 5000.0;
    c.keepalive_size = 52;
    c.dummy_ratio = 0.05;
    return c;
}

FlowShaperConfig FlowShaperConfig::video_stream() {
    FlowShaperConfig c;
    c.profile = FlowProfile::VIDEO_STREAM;
    c.size_dist = SizeDistribution::video_stream();
    c.burst_model = BurstModel::video_stream();
    c.target_upload_ratio = 0.05;
    c.keepalive_interval_ms = 1000.0;
    c.keepalive_size = 52;
    c.dummy_ratio = 0.02;
    return c;
}

FlowShaperConfig FlowShaperConfig::messenger() {
    FlowShaperConfig c;
    c.profile = FlowProfile::MESSENGER;
    c.size_dist = SizeDistribution::messenger();
    c.burst_model = BurstModel::messenger();
    c.target_upload_ratio = 0.40;
    c.keepalive_interval_ms = 15000.0;
    c.keepalive_size = 52;
    c.dummy_ratio = 0.08;
    return c;
}

FlowShaperConfig FlowShaperConfig::gaming() {
    FlowShaperConfig c;
    c.profile = FlowProfile::GAMING;
    c.size_dist = SizeDistribution::gaming();
    c.burst_model = BurstModel::gaming();
    c.target_upload_ratio = 0.45;
    c.keepalive_interval_ms = 2000.0;
    c.keepalive_size = 64;
    c.dummy_ratio = 0.03;
    return c;
}

FlowShaperConfig FlowShaperConfig::file_download() {
    FlowShaperConfig c;
    c.profile = FlowProfile::FILE_DOWNLOAD;
    c.size_dist = SizeDistribution::file_download();
    c.burst_model = BurstModel::file_download();
    c.target_upload_ratio = 0.03;
    c.keepalive_interval_ms = 3000.0;
    c.keepalive_size = 52;
    c.dummy_ratio = 0.01;
    return c;
}

// ===== CSPRNG helper =====

static void csprng_fill(uint8_t* buf, size_t len) {
#ifdef _WIN32
    BCryptGenRandom(nullptr, buf, static_cast<ULONG>(len), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
#else
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd >= 0) {
        size_t off = 0;
        while (off < len) {
            ssize_t r = read(fd, buf + off, len - off);
            if (r <= 0) break;
            off += static_cast<size_t>(r);
        }
        close(fd);
    }
#endif
}

// ===== Constructor / Destructor =====

FlowShaper::FlowShaper()
    : FlowShaper(FlowShaperConfig::web_browsing()) {}

FlowShaper::FlowShaper(const FlowShaperConfig& config)
    : config_(config),
      burst_state_(BurstState::IDLE),
      packets_in_current_burst_(0),
      current_burst_target_(0),
      upload_bytes_(0),
      download_bytes_(0) {
    uint32_t seed;
    csprng_fill(reinterpret_cast<uint8_t*>(&seed), sizeof(seed));
    rng_.seed(seed);
    last_packet_time_ = std::chrono::steady_clock::now();
    apply_profile_defaults();
    precompute_weights();
}

FlowShaper::~FlowShaper() {
    stop();
}

FlowShaper::FlowShaper(FlowShaper&&) noexcept = default;
FlowShaper& FlowShaper::operator=(FlowShaper&&) noexcept = default;

void FlowShaper::apply_profile_defaults() {
    if (config_.size_dist.buckets.empty()) {
        switch (config_.profile) {
            case FlowProfile::WEB_BROWSING:  config_.size_dist = SizeDistribution::web_browsing(); break;
            case FlowProfile::VIDEO_STREAM:  config_.size_dist = SizeDistribution::video_stream(); break;
            case FlowProfile::MESSENGER:     config_.size_dist = SizeDistribution::messenger(); break;
            case FlowProfile::GAMING:        config_.size_dist = SizeDistribution::gaming(); break;
            case FlowProfile::FILE_DOWNLOAD: config_.size_dist = SizeDistribution::file_download(); break;
            default: config_.size_dist = SizeDistribution::web_browsing(); break;
        }
    }
    // Burst model defaults based on profile if not set
    if (config_.burst_model.burst_packets_min == 5 &&
        config_.burst_model.burst_packets_max == 30 &&
        config_.profile != FlowProfile::WEB_BROWSING &&
        config_.profile != FlowProfile::CUSTOM) {
        switch (config_.profile) {
            case FlowProfile::VIDEO_STREAM:  config_.burst_model = BurstModel::video_stream(); break;
            case FlowProfile::MESSENGER:     config_.burst_model = BurstModel::messenger(); break;
            case FlowProfile::GAMING:        config_.burst_model = BurstModel::gaming(); break;
            case FlowProfile::FILE_DOWNLOAD: config_.burst_model = BurstModel::file_download(); break;
            default: break;
        }
    }
}

void FlowShaper::precompute_weights() {
    cumulative_weights_.clear();
    if (config_.size_dist.buckets.empty()) return;
    double sum = 0.0;
    for (const auto& b : config_.size_dist.buckets) {
        sum += b.weight;
        cumulative_weights_.push_back(sum);
    }
    // Normalize
    if (sum > 0.0) {
        for (auto& w : cumulative_weights_) w /= sum;
    }
}

// ===== Lifecycle =====

void FlowShaper::start(FlowSendCallback callback) {
    if (running_.load()) return;
    send_callback_ = callback;
    running_.store(true);
    worker_thread_ = std::thread(&FlowShaper::worker_thread_func, this);
}

void FlowShaper::stop() {
    running_.store(false);
    if (worker_thread_.joinable()) {
        worker_thread_.join();
    }
}

bool FlowShaper::is_running() const {
    return running_.load();
}

// ===== Worker Thread =====

void FlowShaper::worker_thread_func() {
    auto last_keepalive = std::chrono::steady_clock::now();

    while (running_.load()) {
        QueueEntry entry;
        bool has_entry = false;

        {
            std::lock_guard<std::mutex> lock(queue_mutex_);
            if (!packet_queue_.empty()) {
                entry = std::move(packet_queue_.front());
                packet_queue_.pop();
                has_entry = true;
            }
        }

        if (has_entry) {
            auto shaped = shape_sync(entry.data, entry.is_upload);
            for (auto& sp : shaped) {
                if (sp.delay_before_send.count() > 0) {
                    std::this_thread::sleep_for(sp.delay_before_send);
                }
                if (send_callback_) {
                    send_callback_(sp);
                }
            }
        } else {
            // No packets — check idle keepalive
            auto now = std::chrono::steady_clock::now();
            double ms_since_keepalive = std::chrono::duration<double, std::milli>(
                now - last_keepalive).count();

            if (config_.enable_idle_keepalive &&
                ms_since_keepalive >= config_.keepalive_interval_ms) {
                auto ka = generate_keepalive();
                if (send_callback_) {
                    send_callback_(ka);
                }
                last_keepalive = now;
            }

            // Sleep briefly to avoid busy-waiting
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    }

    // Flush remaining
    std::lock_guard<std::mutex> lock(queue_mutex_);
    while (!packet_queue_.empty()) {
        auto& e = packet_queue_.front();
        auto shaped = shape_sync(e.data, e.is_upload);
        for (auto& sp : shaped) {
            if (send_callback_) send_callback_(sp);
        }
        packet_queue_.pop();
    }
}

// ===== Enqueue =====

void FlowShaper::enqueue(const std::vector<uint8_t>& packet, bool is_upload) {
    std::lock_guard<std::mutex> lock(queue_mutex_);
    if (packet_queue_.size() < config_.max_queue_depth) {
        packet_queue_.push({packet, is_upload});
    }
}

void FlowShaper::enqueue_batch(const std::vector<std::vector<uint8_t>>& packets, bool is_upload) {
    std::lock_guard<std::mutex> lock(queue_mutex_);
    for (const auto& p : packets) {
        if (packet_queue_.size() >= config_.max_queue_depth) break;
        packet_queue_.push({p, is_upload});
    }
}

// ===== Core: shape_sync =====

std::vector<ShapedPacket> FlowShaper::shape_sync(
    const std::vector<uint8_t>& packet, bool is_upload) {

    if (!config_.enabled || packet.empty()) {
        ShapedPacket sp;
        sp.data = packet;
        sp.is_upload = is_upload;
        return {sp};
    }

    stats_.packets_original.fetch_add(1);
    stats_.bytes_original.fetch_add(packet.size());
    track_bytes(packet.size(), is_upload);

    std::vector<ShapedPacket> result;

    // Step 1: Size shaping — split/pad to match distribution
    std::vector<std::vector<uint8_t>> sized;
    if (config_.enable_size_shaping) {
        sized = reshape_size(packet);
    } else {
        sized.push_back(packet);
    }

    // Step 2: Apply timing to each output packet
    for (auto& pkt : sized) {
        ShapedPacket sp;
        sp.data = std::move(pkt);
        sp.is_upload = is_upload;
        sp.is_dummy = false;
        sp.is_keepalive = false;

        if (config_.enable_timing_shaping) {
            sp.delay_before_send = next_delay();
        }

        stats_.packets_shaped.fetch_add(1);
        stats_.bytes_shaped.fetch_add(sp.data.size());
        result.push_back(std::move(sp));
    }

    // Step 3: Maybe inject dummy packet
    if (config_.enable_flow_dummy) {
        std::uniform_real_distribution<double> coin(0.0, 1.0);
        if (coin(rng_) < config_.dummy_ratio) {
            result.push_back(generate_dummy());
        }
    }

    // Step 4: Ratio balancing
    if (config_.enable_ratio_shaping && needs_ratio_balance()) {
        result.push_back(generate_ratio_balance_packet());
    }

    // Update overhead
    uint64_t orig = stats_.bytes_original.load();
    uint64_t shaped = stats_.bytes_shaped.load();
    if (orig > 0) {
        stats_.overhead_percent = (static_cast<double>(shaped) / orig - 1.0) * 100.0;
    }

    return result;
}

// ===== Size Shaping =====

std::vector<std::vector<uint8_t>> FlowShaper::reshape_size(
    const std::vector<uint8_t>& packet) {

    size_t target = select_target_size();

    if (packet.size() <= target) {
        // Pad up
        return { pad_to_size(packet, target) };
    } else {
        // Split into chunks matching distribution sizes
        return split_packet(packet, target);
    }
}

size_t FlowShaper::select_target_size() {
    if (cumulative_weights_.empty()) return 1460;

    std::uniform_real_distribution<double> dist(0.0, 1.0);
    double r = dist(rng_);

    for (size_t i = 0; i < cumulative_weights_.size(); ++i) {
        if (r <= cumulative_weights_[i]) {
            size_t base = config_.size_dist.buckets[i].size;
            // Add small jitter (±10%) to avoid exact pattern
            std::uniform_int_distribution<int> jitter(
                -static_cast<int>(base / 10),
                 static_cast<int>(base / 10));
            int result = static_cast<int>(base) + jitter(rng_);
            if (result < 20) result = 20;
            return static_cast<size_t>(result);
        }
    }
    return config_.size_dist.buckets.back().size;
}

std::vector<uint8_t> FlowShaper::pad_to_size(
    const std::vector<uint8_t>& data, size_t target) {
    if (data.size() >= target) return data;

    std::vector<uint8_t> result = data;
    size_t pad_needed = target - data.size();

    // Fill with pseudo-random bytes
    size_t old_size = result.size();
    result.resize(target);
    csprng_fill(result.data() + old_size, pad_needed);

    return result;
}

std::vector<std::vector<uint8_t>> FlowShaper::split_packet(
    const std::vector<uint8_t>& data, size_t max_size) {

    std::vector<std::vector<uint8_t>> chunks;
    size_t offset = 0;

    while (offset < data.size()) {
        // Each chunk gets a target size from distribution
        size_t chunk_target = (offset == 0) ? max_size : select_target_size();
        // Reserve 4 bytes for length header
        size_t data_space = (chunk_target > 4) ? chunk_target - 4 : chunk_target;
        size_t remaining = data.size() - offset;
        size_t take = (std::min)(data_space, remaining);

        std::vector<uint8_t> chunk;
        // 4-byte header: [total_packets:8][chunk_index:8][original_len:16]
        // Simplified: just [original_total_len:16][chunk_offset:16]
        uint16_t total_len = static_cast<uint16_t>(data.size() & 0xFFFF);
        uint16_t chunk_off = static_cast<uint16_t>(offset & 0xFFFF);
        chunk.push_back(static_cast<uint8_t>((total_len >> 8) & 0xFF));
        chunk.push_back(static_cast<uint8_t>(total_len & 0xFF));
        chunk.push_back(static_cast<uint8_t>((chunk_off >> 8) & 0xFF));
        chunk.push_back(static_cast<uint8_t>(chunk_off & 0xFF));

        chunk.insert(chunk.end(), data.begin() + offset, data.begin() + offset + take);

        // Pad chunk to target size
        if (chunk.size() < chunk_target) {
            size_t pad = chunk_target - chunk.size();
            size_t old_sz = chunk.size();
            chunk.resize(chunk_target);
            csprng_fill(chunk.data() + old_sz, pad);
        }

        chunks.push_back(std::move(chunk));
        offset += take;
        stats_.packets_split.fetch_add(1);
    }
    return chunks;
}

// ===== Timing =====

std::chrono::microseconds FlowShaper::next_delay() {
    advance_burst_state();

    if (burst_state_ == BurstState::PAUSING) {
        auto now = std::chrono::steady_clock::now();
        if (now < pause_end_time_) {
            auto remaining = std::chrono::duration_cast<std::chrono::microseconds>(
                pause_end_time_ - now);
            stats_.pauses_injected.fetch_add(1);
            return remaining;
        }
        // Pause over, start new burst
        burst_state_ = BurstState::BURSTING;
        std::uniform_int_distribution<int> bd(
            config_.burst_model.burst_packets_min,
            config_.burst_model.burst_packets_max);
        current_burst_target_ = bd(rng_);
        packets_in_current_burst_ = 0;
        stats_.bursts_generated.fetch_add(1);
    }

    return sample_delay();
}

bool FlowShaper::should_burst() const {
    return burst_state_ == BurstState::BURSTING;
}

void FlowShaper::advance_burst_state() {
    if (burst_state_ == BurstState::IDLE) {
        // Start first burst
        burst_state_ = BurstState::BURSTING;
        std::uniform_int_distribution<int> bd(
            config_.burst_model.burst_packets_min,
            config_.burst_model.burst_packets_max);
        current_burst_target_ = bd(rng_);
        packets_in_current_burst_ = 0;
        stats_.bursts_generated.fetch_add(1);
        return;
    }

    if (burst_state_ == BurstState::BURSTING) {
        packets_in_current_burst_++;
        if (packets_in_current_burst_ >= current_burst_target_) {
            // Burst complete — enter pause
            burst_state_ = BurstState::PAUSING;
            double pause_ms;
            std::uniform_real_distribution<double> pd(
                config_.burst_model.pause_ms_min,
                config_.burst_model.pause_ms_max);
            pause_ms = pd(rng_);
            pause_end_time_ = std::chrono::steady_clock::now() +
                std::chrono::microseconds(static_cast<int64_t>(pause_ms * 1000.0));
        }
    }
}

std::chrono::microseconds FlowShaper::sample_delay() {
    double delay_ms;
    const auto& bm = config_.burst_model;

    switch (bm.timing_distribution) {
        case BurstModel::Distribution::PARETO:
            delay_ms = sample_pareto(bm.pareto_alpha, bm.burst_inter_ms_min);
            delay_ms = (std::min)(delay_ms, bm.burst_inter_ms_max * 3.0); // cap outliers
            break;
        case BurstModel::Distribution::EXPONENTIAL: {
            double mean = (bm.burst_inter_ms_min + bm.burst_inter_ms_max) / 2.0;
            delay_ms = sample_exponential(1.0 / mean);
            break;
        }
        case BurstModel::Distribution::GAUSSIAN: {
            double mean = (bm.burst_inter_ms_min + bm.burst_inter_ms_max) / 2.0;
            double stddev = (bm.burst_inter_ms_max - bm.burst_inter_ms_min) / 4.0;
            std::normal_distribution<double> nd(mean, stddev);
            delay_ms = nd(rng_);
            break;
        }
        case BurstModel::Distribution::UNIFORM:
        default: {
            std::uniform_real_distribution<double> ud(
                bm.burst_inter_ms_min, bm.burst_inter_ms_max);
            delay_ms = ud(rng_);
            break;
        }
    }

    // Clamp
    if (delay_ms < 0.0) delay_ms = 0.0;
    if (delay_ms > bm.pause_ms_max) delay_ms = bm.pause_ms_max;

    return std::chrono::microseconds(static_cast<int64_t>(delay_ms * 1000.0));
}

double FlowShaper::sample_pareto(double alpha, double xm) {
    // Pareto distribution: X = xm / U^(1/alpha)
    std::uniform_real_distribution<double> u(0.0001, 1.0);
    return xm / std::pow(u(rng_), 1.0 / alpha);
}

double FlowShaper::sample_exponential(double lambda) {
    std::exponential_distribution<double> ed(lambda);
    return ed(rng_);
}

// ===== Dummy / Keepalive =====

ShapedPacket FlowShaper::generate_dummy() {
    ShapedPacket sp;
    size_t sz = select_target_size();
    sp.data.resize(4 + sz);
    sp.data[0] = FLOW_DUMMY_MAGIC_0;
    sp.data[1] = FLOW_DUMMY_MAGIC_1;
    sp.data[2] = FLOW_DUMMY_MAGIC_2;
    sp.data[3] = FLOW_DUMMY_MAGIC_3;
    if (sz > 0) {
        csprng_fill(sp.data.data() + 4, sz);
    }
    sp.is_dummy = true;
    sp.is_upload = true;
    sp.delay_before_send = sample_delay();
    stats_.dummy_packets.fetch_add(1);
    return sp;
}

ShapedPacket FlowShaper::generate_keepalive() {
    ShapedPacket sp;
    sp.data.resize(config_.keepalive_size, 0);
    // Minimal content — looks like TCP ACK
    if (sp.data.size() >= 4) {
        sp.data[0] = FLOW_DUMMY_MAGIC_0;
        sp.data[1] = FLOW_DUMMY_MAGIC_1;
        sp.data[2] = FLOW_DUMMY_MAGIC_2;
        sp.data[3] = FLOW_DUMMY_MAGIC_3;
    }
    sp.is_keepalive = true;
    sp.is_dummy = true;
    sp.is_upload = true;
    sp.delay_before_send = std::chrono::microseconds(0);
    stats_.keepalives_sent.fetch_add(1);
    return sp;
}

bool FlowShaper::is_flow_dummy(const uint8_t* data, size_t len) {
    if (len < 4) return false;
    return data[0] == FLOW_DUMMY_MAGIC_0 &&
           data[1] == FLOW_DUMMY_MAGIC_1 &&
           data[2] == FLOW_DUMMY_MAGIC_2 &&
           data[3] == FLOW_DUMMY_MAGIC_3;
}

// ===== Ratio Shaping =====

void FlowShaper::track_bytes(size_t bytes, bool is_upload) {
    if (is_upload) {
        upload_bytes_ += bytes;
    } else {
        download_bytes_ += bytes;
    }
}

double FlowShaper::current_ratio() const {
    uint64_t total = upload_bytes_ + download_bytes_;
    if (total == 0) return 0.5;
    return static_cast<double>(upload_bytes_) / total;
}

bool FlowShaper::needs_ratio_balance() const {
    double ratio = current_ratio();
    double target = config_.target_upload_ratio;
    return std::abs(ratio - target) > config_.ratio_tolerance;
}

ShapedPacket FlowShaper::generate_ratio_balance_packet() {
    ShapedPacket sp;
    double ratio = current_ratio();
    bool need_upload = (ratio < config_.target_upload_ratio);

    size_t sz = select_target_size();
    sp.data.resize(4 + sz);
    sp.data[0] = FLOW_DUMMY_MAGIC_0;
    sp.data[1] = FLOW_DUMMY_MAGIC_1;
    sp.data[2] = FLOW_DUMMY_MAGIC_2;
    sp.data[3] = FLOW_DUMMY_MAGIC_3;
    if (sz > 0) {
        csprng_fill(sp.data.data() + 4, sz);
    }
    sp.is_dummy = true;
    sp.is_upload = need_upload;
    sp.delay_before_send = std::chrono::microseconds(0);

    track_bytes(sp.data.size(), need_upload);
    stats_.dummy_packets.fetch_add(1);
    return sp;
}

// ===== Config & Stats =====

void FlowShaper::set_config(const FlowShaperConfig& config) {
    config_ = config;
    apply_profile_defaults();
    precompute_weights();
}

FlowShaperConfig FlowShaper::get_config() const {
    return config_;
}

void FlowShaper::set_profile(FlowProfile profile) {
    switch (profile) {
        case FlowProfile::WEB_BROWSING:  config_ = FlowShaperConfig::web_browsing(); break;
        case FlowProfile::VIDEO_STREAM:  config_ = FlowShaperConfig::video_stream(); break;
        case FlowProfile::MESSENGER:     config_ = FlowShaperConfig::messenger(); break;
        case FlowProfile::GAMING:        config_ = FlowShaperConfig::gaming(); break;
        case FlowProfile::FILE_DOWNLOAD: config_ = FlowShaperConfig::file_download(); break;
        default: break;
    }
    apply_profile_defaults();
    precompute_weights();
}

FlowShaperStats FlowShaper::get_stats() const {
    return FlowShaperStats(stats_);
}

void FlowShaper::reset_stats() {
    stats_.reset();
    upload_bytes_ = 0;
    download_bytes_ = 0;
}

} // namespace DPI
} // namespace ncp
