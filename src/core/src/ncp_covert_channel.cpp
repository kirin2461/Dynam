/**
 * @file ncp_covert_channel.cpp
 * @brief CovertChannelManager — multiplexer with centralized encryption
 *
 * Encryption architecture:
 *   Manager.send(plaintext)
 *     → crypto_.encrypt_aead(plaintext, session_key_, channel_id_as_aad)
 *     → active_channel_->send(ciphertext)
 *
 *   Manager.receive()
 *     → active_channel_->receive() → ciphertext
 *     → crypto_.decrypt_aead(ciphertext, session_key_, channel_id_as_aad)
 *     → plaintext
 *
 * This ensures:
 *   - Channels stay thin (embed + transport only, no crypto)
 *   - No crypto code duplication across channels (DRY)
 *   - ProtocolOrchestrator manages keys centrally (HKDF from shared_secret)
 *   - channel_id as AAD authenticates which channel produced the ciphertext
 */

#include "include/ncp_covert_channel.hpp"
#include "include/ncp_crypto.hpp"
#include "include/ncp_secure_memory.hpp"
#include "include/ncp_logger.hpp"

#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <mutex>
#include <thread>
#include <unordered_map>
#include <vector>

namespace ncp {
namespace covert {

// ===== channel_state_to_string =====

const char* channel_state_to_string(ChannelState s) noexcept {
    switch (s) {
        case ChannelState::CLOSED:   return "CLOSED";
        case ChannelState::OPENING:  return "OPENING";
        case ChannelState::OPEN:     return "OPEN";
        case ChannelState::DEGRADED: return "DEGRADED";
        case ChannelState::CLOSING:  return "CLOSING";
        case ChannelState::ERROR:    return "ERROR";
    }
    return "UNKNOWN";
}

// ===== CovertChannelManager::Impl =====

struct CovertChannelManager::Impl {
    Config config;
    std::shared_ptr<ncp::Crypto> crypto;

    // Session key for encrypt_aead / decrypt_aead
    std::vector<uint8_t> session_key; // 32 bytes for XChaCha20-Poly1305
    mutable std::mutex key_mutex;

    // Registered channels
    std::vector<std::shared_ptr<ICovertChannel>> channels;
    mutable std::mutex channels_mutex;

    // Active channel (best stealth score + open)
    std::shared_ptr<ICovertChannel> active_channel;

    // Health check thread
    std::thread health_thread;
    std::atomic<bool> running{false};
    std::condition_variable health_cv;
    std::mutex health_mutex;

    // Escalation callback
    std::function<void(const std::string&, const CovertDetectionEvent&)> escalation_cb;
    std::mutex escalation_mutex;

    // --- Encryption helpers ---

    SecureMemory to_secure(const uint8_t* data, size_t len) const {
        SecureMemory mem(len);
        if (len > 0 && data) {
            std::memcpy(mem.data(), data, len);
        }
        return mem;
    }

    SecureMemory session_key_secure() const {
        std::lock_guard<std::mutex> lock(key_mutex);
        return to_secure(session_key.data(), session_key.size());
    }

    SecureMemory channel_aad(const std::string& channel_type) const {
        return to_secure(
            reinterpret_cast<const uint8_t*>(channel_type.data()),
            channel_type.size());
    }

    // Encrypt plaintext for sending through a specific channel
    std::vector<uint8_t> encrypt_for_channel(
        const uint8_t* data, size_t len,
        const std::string& channel_type) {

        if (!crypto || session_key.empty()) {
            // No crypto configured — pass through raw
            return {data, data + len};
        }

        auto pt = to_secure(data, len);
        auto key = session_key_secure();
        auto aad = channel_aad(channel_type);

        auto ct = crypto->encrypt_aead(pt, key, aad);

        if (ct.empty()) {
            NCP_LOG_ERROR("CovertChannelManager: encrypt_aead failed");
            return {};
        }

        return {ct.data(), ct.data() + ct.size()};
    }

    // Decrypt ciphertext received from a specific channel
    std::vector<uint8_t> decrypt_from_channel(
        const uint8_t* data, size_t len,
        const std::string& channel_type) {

        if (!crypto || session_key.empty()) {
            return {data, data + len};
        }

        auto ct = to_secure(data, len);
        auto key = session_key_secure();
        auto aad = channel_aad(channel_type);

        auto pt = crypto->decrypt_aead(ct, key, aad);

        if (pt.empty()) {
            NCP_LOG_WARN("CovertChannelManager: decrypt_aead failed (tampered or wrong key)");
            return {};
        }

        return {pt.data(), pt.data() + pt.size()};
    }

    // --- Channel selection ---

    std::shared_ptr<ICovertChannel> select_best_channel() {
        std::lock_guard<std::mutex> lock(channels_mutex);
        std::shared_ptr<ICovertChannel> best;
        double best_score = -1.0;

        for (auto& ch : channels) {
            if (!ch->is_open()) continue;
            auto stats = ch->get_stats();
            if (stats.stealthiness_score > best_score) {
                best_score = stats.stealthiness_score;
                best = ch;
            }
        }

        return best;
    }

    // --- Health check ---

    void health_check_loop() {
        while (running.load()) {
            {
                std::unique_lock<std::mutex> lock(health_mutex);
                health_cv.wait_for(lock,
                    std::chrono::milliseconds(config.health_check_interval_ms),
                    [this] { return !running.load(); });
            }
            if (!running.load()) break;

            // Re-evaluate active channel
            auto best = select_best_channel();
            if (best && best != active_channel) {
                NCP_LOG_INFO("CovertChannelManager: switching to channel '" +
                             best->channel_type() + "'");
                active_channel = best;
            }

            // Check for degraded channels
            std::lock_guard<std::mutex> lock(channels_mutex);
            for (auto& ch : channels) {
                if (ch->state() == ChannelState::DEGRADED) {
                    auto stats = ch->get_stats();
                    if (stats.stealthiness_score < config.detection_threshold) {
                        NCP_LOG_WARN("CovertChannelManager: channel '" +
                                     ch->channel_type() + "' below threshold");

                        if (config.enable_failover) {
                            // Notify escalation
                            std::lock_guard<std::mutex> elock(escalation_mutex);
                            if (escalation_cb) {
                                CovertDetectionEvent event;
                                event.type = CovertDetectionEvent::Type::STATISTICAL_ANOMALY;
                                event.confidence = 1.0 - stats.stealthiness_score;
                                event.details = "stealth score below threshold";
                                escalation_cb(ch->channel_type(), event);
                            }
                        }
                    }
                }
            }
        }
    }
};

// ===== CovertChannelManager public methods =====

CovertChannelManager::CovertChannelManager()
    : CovertChannelManager(Config{}) {}

CovertChannelManager::CovertChannelManager(const Config& config)
    : impl_(std::make_unique<Impl>()) {
    impl_->config = config;
}

CovertChannelManager::CovertChannelManager(
    const Config& config, std::shared_ptr<ncp::Crypto> crypto)
    : impl_(std::make_unique<Impl>()) {
    impl_->config = config;
    impl_->crypto = std::move(crypto);
}

CovertChannelManager::~CovertChannelManager() {
    stop();
}

void CovertChannelManager::add_channel(std::shared_ptr<ICovertChannel> channel) {
    std::lock_guard<std::mutex> lock(impl_->channels_mutex);
    impl_->channels.push_back(std::move(channel));
}

void CovertChannelManager::remove_channel(const std::string& channel_type) {
    std::lock_guard<std::mutex> lock(impl_->channels_mutex);
    impl_->channels.erase(
        std::remove_if(impl_->channels.begin(), impl_->channels.end(),
            [&](const auto& ch) { return ch->channel_type() == channel_type; }),
        impl_->channels.end());

    if (impl_->active_channel &&
        impl_->active_channel->channel_type() == channel_type) {
        impl_->active_channel = impl_->select_best_channel();
    }
}

std::vector<std::string> CovertChannelManager::active_channels() const {
    std::lock_guard<std::mutex> lock(impl_->channels_mutex);
    std::vector<std::string> result;
    for (const auto& ch : impl_->channels) {
        if (ch->is_open()) {
            result.push_back(ch->channel_type());
        }
    }
    return result;
}

size_t CovertChannelManager::send(const uint8_t* data, size_t len) {
    auto channel = impl_->active_channel;
    if (!channel || !channel->is_open()) {
        channel = impl_->select_best_channel();
        if (!channel) {
            NCP_LOG_ERROR("CovertChannelManager: no active channel");
            return 0;
        }
        impl_->active_channel = channel;
    }

    // Encrypt: encrypt_aead(plaintext, session_key, channel_id_as_aad)
    auto ct = impl_->encrypt_for_channel(data, len, channel->channel_type());
    if (ct.empty() && len > 0) return 0;

    // Channel only transports raw (encrypted) bytes
    return channel->send(ct.data(), ct.size());
}

size_t CovertChannelManager::receive(uint8_t* buf, size_t max_len) {
    auto channel = impl_->active_channel;
    if (!channel || !channel->is_open()) {
        channel = impl_->select_best_channel();
        if (!channel) return 0;
        impl_->active_channel = channel;
    }

    // Receive ciphertext from channel
    std::vector<uint8_t> ct_buf(max_len + 64); // room for nonce + tag
    size_t ct_len = channel->receive(ct_buf.data(), ct_buf.size());
    if (ct_len == 0) return 0;

    // Decrypt: decrypt_aead(ciphertext, session_key, channel_id_as_aad)
    auto pt = impl_->decrypt_from_channel(
        ct_buf.data(), ct_len, channel->channel_type());
    if (pt.empty()) return 0;

    size_t to_copy = std::min(max_len, pt.size());
    std::memcpy(buf, pt.data(), to_copy);
    return to_copy;
}

void CovertChannelManager::set_session_key(const std::vector<uint8_t>& key) {
    std::lock_guard<std::mutex> lock(impl_->key_mutex);
    impl_->session_key = key;
    NCP_LOG_INFO("CovertChannelManager: session key set (" +
                 std::to_string(key.size()) + " bytes)");
}

bool CovertChannelManager::has_session_key() const {
    std::lock_guard<std::mutex> lock(impl_->key_mutex);
    return !impl_->session_key.empty();
}

void CovertChannelManager::start() {
    if (impl_->running.load()) return;

    // Open all registered channels
    {
        std::lock_guard<std::mutex> lock(impl_->channels_mutex);
        for (auto& ch : impl_->channels) {
            if (!ch->is_open()) {
                ch->open();
            }
        }
    }

    impl_->active_channel = impl_->select_best_channel();
    impl_->running.store(true);
    impl_->health_thread = std::thread([this] { impl_->health_check_loop(); });

    NCP_LOG_INFO("CovertChannelManager started");
}

void CovertChannelManager::stop() {
    if (!impl_->running.load()) return;
    impl_->running.store(false);
    impl_->health_cv.notify_all();

    if (impl_->health_thread.joinable()) {
        impl_->health_thread.join();
    }

    // Close all channels
    {
        std::lock_guard<std::mutex> lock(impl_->channels_mutex);
        for (auto& ch : impl_->channels) {
            ch->close();
        }
    }

    impl_->active_channel.reset();
    NCP_LOG_INFO("CovertChannelManager stopped");
}

bool CovertChannelManager::is_running() const {
    return impl_->running.load();
}

ChannelStats CovertChannelManager::aggregate_stats() const {
    ChannelStats agg;
    std::lock_guard<std::mutex> lock(impl_->channels_mutex);
    for (const auto& ch : impl_->channels) {
        auto s = ch->get_stats();
        agg.bytes_sent += s.bytes_sent;
        agg.bytes_received += s.bytes_received;
        agg.messages_sent += s.messages_sent;
        agg.messages_received += s.messages_received;
        agg.errors += s.errors;
        agg.retries += s.retries;
        // Weighted average of stealth scores
        if (ch->is_open()) {
            agg.stealthiness_score = std::min(agg.stealthiness_score == 0.0
                ? s.stealthiness_score : agg.stealthiness_score,
                s.stealthiness_score);
        }
    }
    return agg;
}

void CovertChannelManager::set_escalation_callback(
    std::function<void(const std::string&, const CovertDetectionEvent&)> cb) {
    std::lock_guard<std::mutex> lock(impl_->escalation_mutex);
    impl_->escalation_cb = std::move(cb);
}

} // namespace covert
} // namespace ncp
