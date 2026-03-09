/**
 * @file tls_record_padding.cpp
 * @brief TLS Record Padding implementation (Channel #4)
 *
 * Minimal code: delegates randomness to TrafficPadder / CSPRNG.
 * Only adds the padding-size computation and TLS record framing logic.
 *
 * FIX review findings:
 *   - pad_record() now documents CSPRNG-fill as post-encryption padding
 *   - set_config() / get_config() / get_stats() / reset_stats() thread-safe via mutex_
 *   - pad_record() validates no trailing data beyond declared payload
 *   - compute_padded_size() has default: branch for future enum safety
 */

#include "../include/ncp_tls_record_padding.hpp"
#include "../include/ncp_csprng.hpp"
#include <algorithm>
#include <cstring>

namespace ncp {

// ── helpers ──────────────────────────────────────────────────

static size_t next_power_of_two(size_t v) {
    if (v == 0) return 1;
    v--;
    v |= v >> 1;
    v |= v >> 2;
    v |= v >> 4;
    v |= v >> 8;
    v |= v >> 16;
    if constexpr (sizeof(size_t) > 4) v |= v >> 32;
    return v + 1;
}

static size_t align_up(size_t v, size_t block) {
    if (block == 0) return v;
    return ((v + block - 1) / block) * block;
}

// ── TLSRecordPadding ─────────────────────────────────────────

TLSRecordPadding::TLSRecordPadding(
    const TLSRecordPaddingConfig& config,
    TrafficPadder* external_padder)
    : config_(config)
    , padder_(external_padder)
{
    if (!padder_) {
        owned_padder_ = std::make_unique<TrafficPadder>(
            config_.min_padding,
            config_.max_padding);
        padder_ = owned_padder_.get();
    }
}

void TLSRecordPadding::set_config(const TLSRecordPaddingConfig& config) {
    std::lock_guard<std::mutex> lock(mutex_);
    config_ = config;
    if (owned_padder_) {
        owned_padder_->set_padding_range(config_.min_padding, config_.max_padding);
    }
}

TLSRecordPaddingConfig TLSRecordPadding::get_config() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return config_;
}

TLSRecordPaddingStats TLSRecordPadding::get_stats() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return stats_;
}

void TLSRecordPadding::reset_stats() {
    std::lock_guard<std::mutex> lock(mutex_);
    stats_ = {};
}

size_t TLSRecordPadding::compute_padded_size(size_t original) const {
    // Note: caller must hold mutex_
    const size_t max_sz = static_cast<size_t>(config_.max_record_size);

    switch (config_.strategy) {
    case TLSPaddingStrategy::BUCKET_POW2: {
        size_t bucket = next_power_of_two(original);
        return std::min(bucket, max_sz);
    }
    case TLSPaddingStrategy::FIXED_BLOCK: {
        size_t aligned = align_up(original, config_.fixed_block_size);
        return std::min(aligned, max_sz);
    }
    case TLSPaddingStrategy::RANDOM_RANGE: {
        uint32_t extra = (config_.min_padding == config_.max_padding)
            ? config_.min_padding
            : static_cast<uint32_t>(ncp::csprng_range(
                  config_.min_padding, config_.max_padding));
        size_t target = original + extra;
        return std::min(target, max_sz);
    }
    case TLSPaddingStrategy::CONSTANT_LENGTH:
        return max_sz;
    default:
        return original;
    }
}

std::vector<uint8_t> TLSRecordPadding::pad_plaintext(
    const std::vector<uint8_t>& plaintext,
    uint8_t content_type)
{
    std::lock_guard<std::mutex> lock(mutex_);

    stats_.records_processed++;

    if (!config_.enabled) {
        stats_.records_skipped++;
        return plaintext;
    }

    if (config_.pad_only_app_data && content_type != 0x17) {
        stats_.records_skipped++;
        return plaintext;
    }

    // RFC 8446 §5.4 inner plaintext: content + type + zeros
    // Format: [original content] [content_type byte] [zero padding...]
    // The receiver scans backwards past zeros to find the type byte.

    size_t target = compute_padded_size(plaintext.size() + 1); // +1 for type byte
    if (target <= plaintext.size() + 1) {
        // No room for padding, just append type byte
        std::vector<uint8_t> result;
        result.reserve(plaintext.size() + 1);
        result.insert(result.end(), plaintext.begin(), plaintext.end());
        result.push_back(content_type);
        stats_.records_padded++;
        return result;
    }

    size_t pad_len = target - plaintext.size() - 1;

    std::vector<uint8_t> result;
    result.reserve(target);
    result.insert(result.end(), plaintext.begin(), plaintext.end());
    result.push_back(content_type);
    result.resize(result.size() + pad_len, 0x00); // zero-fill per RFC 8446

    stats_.records_padded++;
    stats_.total_padding_bytes += pad_len;

    return result;
}

std::vector<uint8_t> TLSRecordPadding::unpad_plaintext(
    const std::vector<uint8_t>& padded,
    uint8_t& content_type)
{
    if (padded.empty()) {
        content_type = 0;
        return {};
    }

    // Scan backwards past zero bytes to find the real content type
    size_t i = padded.size();
    while (i > 0 && padded[i - 1] == 0x00) {
        i--;
    }

    if (i == 0) {
        // All zeros — malformed
        content_type = 0;
        return {};
    }

    // padded[i-1] is the content type byte
    content_type = padded[i - 1];
    return std::vector<uint8_t>(padded.begin(), padded.begin() + static_cast<ptrdiff_t>(i - 1));
}

bool TLSRecordPadding::pad_record(std::vector<uint8_t>& record) {
    std::lock_guard<std::mutex> lock(mutex_);

    stats_.records_processed++;

    // TLS record header: [type(1)] [version(2)] [length(2)] [payload...]
    if (record.size() < 5) {
        stats_.records_skipped++;
        return false;
    }

    uint8_t rec_type = record[0];
    uint16_t payload_len = (static_cast<uint16_t>(record[3]) << 8)
                         | static_cast<uint16_t>(record[4]);

    if (record.size() < 5u + payload_len) {
        stats_.records_skipped++;
        return false;
    }

    // FIX: Reject records with trailing data beyond declared payload.
    // This ensures padding is appended directly after the payload,
    // not after unexpected trailing bytes.
    if (record.size() != 5u + payload_len) {
        stats_.records_skipped++;
        return false;
    }

    if (!config_.enabled) {
        stats_.records_skipped++;
        return false;
    }

    if (config_.pad_only_app_data && rec_type != 0x17) {
        stats_.records_skipped++;
        return false;
    }

    size_t target_payload = compute_padded_size(payload_len);
    if (target_payload <= payload_len || target_payload > 16384) {
        stats_.records_skipped++;
        return false;
    }

    size_t pad_needed = target_payload - payload_len;

    // Post-encryption API: extend with CSPRNG-filled bytes.
    // Random fill is correct here — this operates on ciphertext,
    // where CSPRNG bytes are indistinguishable from encrypted data.
    // The receiver strips padding by peer-agreed target size or
    // by the original ciphertext length communicated out-of-band.
    size_t old_size = record.size();
    record.resize(old_size + pad_needed);
    ncp::csprng_fill(record.data() + old_size, pad_needed);

    // Update length field in header
    uint16_t new_len = static_cast<uint16_t>(target_payload);
    record[3] = static_cast<uint8_t>((new_len >> 8) & 0xFF);
    record[4] = static_cast<uint8_t>(new_len & 0xFF);

    stats_.records_padded++;
    stats_.total_padding_bytes += pad_needed;

    return true;
}

} // namespace ncp
