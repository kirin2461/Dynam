#pragma once

/**
 * @file ncp_onnx_classifier.hpp
 * @brief ONNX Runtime Shadow Classifier — Phase 3 Anti-ML Pipeline
 *
 * Loads a pre-trained ONNX model and runs inference to detect
 * NCP-obfuscated traffic. Feeds DetectionFeedback back into
 * AdversarialPadding::report_feedback() to close the adaptive loop.
 *
 * ONNX Runtime is a REQUIRED dependency. The project does not compile
 * without it — there are no stubs or no-op fallbacks.
 *
 * Thread safety: predict() is safe to call from multiple threads
 * simultaneously (Ort::Session is thread-safe for inference).
 */

#include <onnxruntime_cxx_api.h>

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <array>
#include <mutex>
#include <memory>
#include <atomic>

namespace ncp {
namespace DPI {

// =====================================================================
// Configuration
// =====================================================================

struct OnnxClassifierConfig {
    bool enabled = false;
    std::string model_path;           ///< Path to .onnx file

    /// Weight of ONNX score in combined stealth calculation.
    /// 0.0 = use heuristic only, 1.0 = use ONNX only.
    double weight = 0.6;

    /// Run inference every N packets (0 = every evaluate() call).
    /// Higher values reduce CPU at the cost of detection latency.
    size_t inference_interval = 1;

    /// Classification threshold. If P(NCP_obfuscated) > threshold,
    /// the traffic is considered "detected".
    double detection_threshold = 0.5;
};

// =====================================================================
// Statistics
// =====================================================================

struct OnnxClassifierStats {
    std::atomic<uint64_t> inferences_run{0};
    std::atomic<uint64_t> detections{0};
    std::atomic<uint64_t> load_failures{0};
    std::atomic<uint64_t> total_latency_us{0};

    /// Average inference latency in microseconds.
    double avg_latency_us() const {
        uint64_t runs = inferences_run.load();
        if (runs == 0) return 0.0;
        return static_cast<double>(total_latency_us.load()) / runs;
    }

    /// Detection rate (0.0 - 1.0).
    double detection_rate() const {
        uint64_t runs = inferences_run.load();
        if (runs == 0) return 0.0;
        return static_cast<double>(detections.load()) / runs;
    }

    void reset() {
        inferences_run.store(0);
        detections.store(0);
        load_failures.store(0);
        total_latency_us.store(0);
    }

    OnnxClassifierStats() = default;
    OnnxClassifierStats(const OnnxClassifierStats& o)
        : inferences_run(o.inferences_run.load())
        , detections(o.detections.load())
        , load_failures(o.load_failures.load())
        , total_latency_us(o.total_latency_us.load()) {}

    OnnxClassifierStats& operator=(const OnnxClassifierStats& o) {
        if (this != &o) {
            inferences_run.store(o.inferences_run.load());
            detections.store(o.detections.load());
            load_failures.store(o.load_failures.load());
            total_latency_us.store(o.total_latency_us.load());
        }
        return *this;
    }
};

// =====================================================================
// Prediction Result
// =====================================================================

struct OnnxPrediction {
    bool detected = false;              ///< P(NCP) > threshold
    double p_ncp_obfuscated = 0.0;     ///< Probability of NCP-obfuscated [0,1]
    double p_normal = 1.0;             ///< Probability of normal traffic [0,1]
    double stealth_score = 1.0;        ///< 1.0 - p_ncp (higher = stealthier)
    uint64_t inference_time_us = 0;    ///< Wall-clock inference time
    bool valid = false;                ///< True if prediction was computed
};

// =====================================================================
// Feature vector for ONNX classifier (must match trained model input)
// =====================================================================

/// 10 features expected by shadow_flow_classifier.onnx.
struct OnnxShadowFeatures {
    float size_mean      = 0.0f;   ///< Mean packet size (bytes)
    float size_cv        = 0.0f;   ///< Coefficient of variation (std/mean)
    float frac_small     = 0.0f;   ///< Fraction of packets <= 128 bytes
    float frac_large     = 0.0f;   ///< Fraction of packets >= 1200 bytes
    float error_rate     = 0.0f;   ///< Connection errors / total attempts
    float timing_cov     = 0.0f;   ///< CoV of inter-arrival times
    float burst_anomaly  = 0.0f;   ///< Burst pattern anomaly score [0,1]
    float ks_distance    = 0.0f;   ///< KS distance vs reference profile
    float upload_ratio   = 0.0f;   ///< Upload bytes / total bytes
    float burst_rate     = 0.0f;   ///< Bursts per second

    static constexpr size_t DIM = 10;

    /// Convert to flat float array for model input.
    std::array<float, DIM> to_array() const noexcept {
        return {{size_mean, size_cv, frac_small, frac_large,
                 error_rate, timing_cov, burst_anomaly, ks_distance,
                 upload_ratio, burst_rate}};
    }

    /// Expand tilde in path to home directory. Cross-platform.
    static std::string expand_tilde(const std::string& path);
};

// =====================================================================
// Main Class
// =====================================================================

class OnnxShadowClassifier {
public:
    OnnxShadowClassifier();
    explicit OnnxShadowClassifier(const OnnxClassifierConfig& config);
    ~OnnxShadowClassifier();

    // Non-copyable. Move is implemented manually (mutex is not movable).
    OnnxShadowClassifier(const OnnxShadowClassifier&) = delete;
    OnnxShadowClassifier& operator=(const OnnxShadowClassifier&) = delete;
    OnnxShadowClassifier(OnnxShadowClassifier&& other) noexcept;
    OnnxShadowClassifier& operator=(OnnxShadowClassifier&& other) noexcept;

    // ===== Lifecycle =====

    /**
     * @brief Load the ONNX model from config.model_path.
     * @return true on success, false if load failed.
     * @throws Ort::Exception on ONNX Runtime errors.
     */
    bool load();

    /**
     * @brief Load a specific model file (overrides config.model_path).
     */
    bool load(const std::string& model_path);

    /**
     * @brief Unload the model and free memory.
     */
    void unload();

    /**
     * @brief Whether a model is loaded and ready for inference.
     */
    bool is_loaded() const;

    // ===== Inference =====

    /**
     * @brief Run inference on a feature vector.
     * @param features Array of float features (must match model input size).
     * @param n_features Number of features (must match model input dimension).
     * @return Prediction result. valid=false if model not loaded.
     *
     * Thread-safe: may be called concurrently from multiple threads.
     */
    OnnxPrediction predict(const float* features, size_t n_features);

    /**
     * @brief Convenience overload for std::vector input.
     */
    OnnxPrediction predict(const std::vector<float>& features);

    /**
     * @brief Run inference and return full probability vector.
     * @param features Input features.
     * @return Raw model output probabilities (empty if not loaded).
     */
    std::vector<float> predict_proba(const std::vector<float>& features);

    // ===== Config / Stats =====

    void set_config(const OnnxClassifierConfig& config);
    OnnxClassifierConfig get_config() const;
    OnnxClassifierStats get_stats() const;
    void reset_stats();

    // ===== Integration helpers =====

    /**
     * @brief Compute combined stealth score from heuristic and ONNX scores.
     *
     * combined = (1 - weight) * heuristic_stealth + weight * onnx_stealth
     *
     * where onnx_stealth = 1.0 - p_ncp_obfuscated.
     *
     * If model not loaded or prediction invalid, returns heuristic_stealth.
     */
    double combined_stealth(double heuristic_stealth,
                            const OnnxPrediction& onnx_pred) const;

    /**
     * @brief Get the expected input feature count from the loaded model.
     * @return Number of input features, or 0 if not loaded.
     */
    size_t input_feature_count() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
    OnnxClassifierConfig config_;
    OnnxClassifierStats stats_;
    mutable std::mutex config_mutex_;
};

} // namespace DPI
} // namespace ncp
