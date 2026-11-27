#pragma once

/**
 * @file ncp_onnx_integration.hpp
 * @brief Integration layer between OnnxShadowClassifier and AdversaryTester.
 *
 * This file provides:
 *   1. OnnxShadowFeatures::from_flow_data() — extract 10 model features
 *      from the data AdversaryTester already collects (FlowSnapshot + extras)
 *   2. Integration instructions for AdversaryTester modifications
 *
 * Feature contract (must match shadow_flow_classifier.onnx):
 *   [0] size_mean     — mean packet payload size (bytes)
 *   [1] size_cv       — stddev(size) / mean(size)
 *   [2] frac_small    — fraction of packets <= 128 bytes
 *   [3] frac_large    — fraction of packets >= 1200 bytes
 *   [4] error_rate    — connection errors / (packets + errors)
 *   [5] timing_cov    — stddev(IAT) / mean(IAT)
 *   [6] burst_anomaly — burst pattern anomaly score [0,1]
 *   [7] ks_distance   — KS distance vs reference browsing profile
 *   [8] upload_ratio  — upload bytes / total bytes
 *   [9] burst_rate    — detected bursts / flow duration
 *
 * NOTE: SizeErrorFeatures has only 8 fields. Fields [8] upload_ratio and
 * [9] burst_rate must come from FlowShaperStats / FlowSnapshot extras.
 */

#include "ncp_onnx_classifier.hpp"

#include <cmath>
#include <chrono>
#include <numeric>
#include <vector>
#include <algorithm>

namespace ncp {
namespace DPI {

/// Extract OnnxShadowFeatures from raw packet data that AdversaryTester
/// already collects in its FlowSnapshot window.
///
/// @param packet_sizes   Payload sizes of packets in the window.
/// @param iats_us        Inter-arrival times in microseconds (size = packet_sizes.size() - 1).
/// @param upload_bytes   Total upload bytes in the window.
/// @param download_bytes Total download bytes in the window.
/// @param error_count    Connection errors observed.
/// @param ref_sizes      Reference size distribution for KS test (e.g., web browsing).
/// @return OnnxShadowFeatures ready for model input.
inline OnnxShadowFeatures extract_onnx_features(
        const std::vector<size_t>& packet_sizes,
        const std::vector<std::chrono::microseconds>& iats_us,
        uint64_t upload_bytes,
        uint64_t download_bytes,
        size_t error_count,
        const std::vector<double>& ref_sizes = {})
{
    OnnxShadowFeatures f;
    const size_t n = packet_sizes.size();
    if (n == 0) return f;

    // [0] size_mean
    double sum = 0;
    size_t small = 0, large = 0;
    for (size_t s : packet_sizes) {
        sum += static_cast<double>(s);
        if (s <= 128) ++small;
        if (s >= 1200) ++large;
    }
    f.size_mean = static_cast<float>(sum / n);

    // [1] size_cv
    double var = 0;
    for (size_t s : packet_sizes) {
        double d = static_cast<double>(s) - sum / n;
        var += d * d;
    }
    var /= n;
    double mean = sum / n;
    f.size_cv = (mean > 0) ? static_cast<float>(std::sqrt(var) / mean) : 0.0f;

    // [2] frac_small
    f.frac_small = static_cast<float>(static_cast<double>(small) / n);

    // [3] frac_large
    f.frac_large = static_cast<float>(static_cast<double>(large) / n);

    // [4] error_rate
    double total = static_cast<double>(n + error_count);
    f.error_rate = (total > 0)
        ? static_cast<float>(static_cast<double>(error_count) / total)
        : 0.0f;

    // [5] timing_cov
    if (iats_us.size() > 1) {
        double iat_sum = 0;
        for (auto& iat : iats_us) iat_sum += iat.count();
        double iat_mean = iat_sum / iats_us.size();
        double iat_var = 0;
        for (auto& iat : iats_us) {
            double d = iat.count() - iat_mean;
            iat_var += d * d;
        }
        iat_var /= iats_us.size();
        f.timing_cov = (iat_mean > 0)
            ? static_cast<float>(std::sqrt(iat_var) / iat_mean)
            : 0.0f;
    }

    // [6] burst_anomaly: simple heuristic — ratio of very short IATs to total
    if (!iats_us.empty()) {
        size_t micro_burstes = 0;
        for (auto& iat : iats_us) {
            if (iat.count() < 1000) ++micro_burstes;  // < 1ms = micro-burst
        }
        f.burst_anomaly = static_cast<float>(
            static_cast<double>(micro_burstes) / iats_us.size());
    }

    // [7] ks_distance vs reference (if provided)
    if (!ref_sizes.empty() && n > 1) {
        // Simplified KS: sort both, compare CDFs at each step
        std::vector<double> sorted_obs(packet_sizes.begin(), packet_sizes.end());
        std::sort(sorted_obs.begin(), sorted_obs.end());
        std::vector<double> sorted_ref = ref_sizes;
        std::sort(sorted_ref.begin(), sorted_ref.end());

        double max_diff = 0;
        size_t i = 0, j = 0;
        while (i < sorted_obs.size() && j < sorted_ref.size()) {
            double cdf_obs = static_cast<double>(i + 1) / sorted_obs.size();
            double cdf_ref = static_cast<double>(j + 1) / sorted_ref.size();
            max_diff = std::max(max_diff, std::abs(cdf_obs - cdf_ref));
            if (sorted_obs[i] < sorted_ref[j]) ++i;
            else ++j;
        }
        f.ks_distance = static_cast<float>(max_diff);
    }

    // [8] upload_ratio
    uint64_t total_bytes = upload_bytes + download_bytes;
    f.upload_ratio = (total_bytes > 0)
        ? static_cast<float>(static_cast<double>(upload_bytes) / total_bytes)
        : 0.0f;

    // [9] burst_rate: count distinct bursts / flow duration
    // A burst = consecutive packets with IAT < 50ms
    if (iats_us.size() > 1) {
        size_t bursts = 0;
        bool in_burst = false;
        auto total_duration_us = std::chrono::microseconds(0);
        for (auto& iat : iats_us) total_duration_us += iat;
        double duration_s = total_duration_us.count() / 1e6;

        for (auto& iat : iats_us) {
            if (iat.count() < 50000) {  // < 50ms = within burst
                if (!in_burst) { ++bursts; in_burst = true; }
            } else {
                in_burst = false;
            }
        }
        f.burst_rate = (duration_s > 0)
            ? static_cast<float>(static_cast<double>(bursts) / duration_s)
            : 0.0f;
    }

    return f;
}

/// Helper to convert OnnxShadowFeatures to the vector<float> expected
/// by OnnxShadowClassifier::predict().
inline std::vector<float> to_predict_input(const OnnxShadowFeatures& f) {
    auto arr = f.to_array();
    return std::vector<float>(arr.begin(), arr.end());
}

} // namespace DPI
} // namespace ncp

// =====================================================================
// INTEGRATION GUIDE for AdversaryTester
// =====================================================================
//
// In ncp_adversary_tester.hpp, add to AdversaryTester class:
//
//   #include "ncp_onnx_classifier.hpp"
//   #include "ncp_onnx_integration.hpp"
//
//   // New member:
//   std::shared_ptr<OnnxShadowClassifier> onnx_classifier_;
//
//   // New method:
//   void set_onnx_classifier(std::shared_ptr<OnnxShadowClassifier> clf) {
//       std::lock_guard<std::mutex> lock(mutex_);
//       onnx_classifier_ = std::move(clf);
//   }
//
// In evaluate() method, after computing HeuristicScores:
//
//   double stealth = scores.aggregate_stealth();
//
//   // NEW: combine with ONNX if available
//   if (onnx_classifier_ && onnx_classifier_->is_loaded()) {
//       auto onnx_feats = extract_onnx_features(
//           snapshot_.packet_sizes, snapshot_.inter_arrival_times,
//           upload_bytes_, download_bytes_, snapshot_.error_count,
//           ref_profile_.size_buckets);  // or precomputed reference
//       auto input = to_predict_input(onnx_feats);
//       auto onnx_pred = onnx_classifier_->predict(input);
//       stealth = onnx_classifier_->combined_stealth(stealth, onnx_pred);
//   }
//
//   // Then create DetectionFeedback as before, using combined stealth.
//
// In main.cpp or wherever AdversaryTester is constructed:
//
//   auto onnx = std::make_shared<OnnxShadowClassifier>(onnx_config);
//   onnx->load();
//   tester.set_onnx_classifier(onnx);
//
