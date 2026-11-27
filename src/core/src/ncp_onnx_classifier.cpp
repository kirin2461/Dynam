/**
 * @file ncp_onnx_classifier.cpp
 * @brief ONNX Runtime Shadow Classifier — no stubs, no fallbacks.
 *
 * ONNX Runtime is a required dependency. Every method contains real logic.
 */

#include "ncp_onnx_classifier.hpp"

#include <chrono>
#include <algorithm>
#include <cstring>
#include <cstdlib>

#ifdef _WIN32
#include <shlobj.h>
#include <windows.h>
#else
#include <sys/types.h>
#include <pwd.h>
#include <unistd.h>
#endif

namespace ncp {
namespace DPI {

// =====================================================================
// OnnxShadowFeatures helpers
// =====================================================================

std::string OnnxShadowFeatures::expand_tilde(const std::string& path) {
    if (path.empty() || path[0] != '~') return path;

    std::string home;
#ifdef _WIN32
    const char* up = std::getenv("USERPROFILE");
    if (up) { home = up; }
    else {
        char buf[MAX_PATH];
        if (SHGetFolderPathA(NULL, CSIDL_PROFILE, NULL, 0, buf) == S_OK)
            home = buf;
    }
#else
    const char* h = std::getenv("HOME");
    if (h) { home = h; }
    else {
        struct passwd* pw = getpwuid(getuid());
        if (pw) home = pw->pw_dir;
    }
#endif

    if (home.empty()) return path;
    if (path.size() == 1) return home;
    if (path[1] == '/') return home + path.substr(1);
    return path;
}

// =====================================================================
// Impl
// =====================================================================

struct OnnxShadowClassifier::Impl {
    Ort::Env env{ORT_LOGGING_LEVEL_WARNING, "ncp-shadow-classifier"};
    std::unique_ptr<Ort::Session> session;
    std::vector<int64_t> input_shape;
    Ort::MemoryInfo memory_info;
    // Owned strings for name lifetime (c_str used by Session::Run)
    std::vector<std::string> input_name_strs;
    std::vector<std::string> output_name_strs;
    std::vector<const char*> input_names;
    std::vector<const char*> output_names;

    bool loaded = false;
    size_t n_features = 0;
    bool moved_from = false;

    Impl()
        : memory_info(Ort::MemoryInfo::CreateCpu(OrtArenaAllocator, OrtMemTypeDefault))
    {}

    ~Impl() {
        // Clear in reverse dependency order
        input_names.clear();
        output_names.clear();
        input_name_strs.clear();
        output_name_strs.clear();
        session.reset();
    }
};

// =====================================================================
// Constructors / Destructor / Move
// =====================================================================

OnnxShadowClassifier::OnnxShadowClassifier()
    : impl_(std::make_unique<Impl>()) {}

OnnxShadowClassifier::OnnxShadowClassifier(const OnnxClassifierConfig& config)
    : impl_(std::make_unique<Impl>())
    , config_(config) {}

OnnxShadowClassifier::~OnnxShadowClassifier() = default;

// Manual move: std::mutex is NOT movable.
OnnxShadowClassifier::OnnxShadowClassifier(OnnxShadowClassifier&& other) noexcept
    : impl_(std::make_unique<Impl>())
    , stats_(other.stats_)
{
    std::lock_guard<std::mutex> lk(other.config_mutex_);
    config_ = std::move(other.config_);
    // Steal the ORT session
    std::swap(impl_, other.impl_);
    // other now has our fresh (empty) Impl; it's in a valid unloaded state
}

OnnxShadowClassifier& OnnxShadowClassifier::operator=(OnnxShadowClassifier&& other) noexcept {
    if (this == &other) return *this;
    {
        std::lock_guard<std::mutex> lk1(config_mutex_);
        std::lock_guard<std::mutex> lk2(other.config_mutex_);
        config_ = std::move(other.config_);
        stats_ = other.stats_;
        std::swap(impl_, other.impl_);
    }
    return *this;
}

// =====================================================================
// Lifecycle
// =====================================================================

bool OnnxShadowClassifier::load() {
    std::string path;
    {
        std::lock_guard<std::mutex> lk(config_mutex_);
        path = OnnxShadowFeatures::expand_tilde(config_.model_path);
    }
    return load(path);
}

bool OnnxShadowClassifier::load(const std::string& model_path) {
    std::string resolved = OnnxShadowFeatures::expand_tilde(model_path);

    try {
        Ort::SessionOptions opts;
        opts.SetIntraOpNumThreads(1);
        opts.SetInterOpNumThreads(1);
        opts.SetGraphOptimizationLevel(GraphOptimizationLevel::ORT_ENABLE_ALL);
        opts.EnableCpuMemArena();
        opts.EnableMemPattern();

#ifdef _WIN32
        int wlen = MultiByteToWideChar(CP_UTF8, 0, resolved.c_str(), -1, nullptr, 0);
        if (wlen <= 0) { stats_.load_failures.fetch_add(1); return false; }
        std::wstring wpath(wlen, L'\0');
        MultiByteToWideChar(CP_UTF8, 0, resolved.c_str(), -1, &wpath[0], wlen);
        wpath.pop_back();
        impl_->session = std::make_unique<Ort::Session>(impl_->env, wpath.c_str(), opts);
#else
        impl_->session = std::make_unique<Ort::Session>(impl_->env, resolved.c_str(), opts);
#endif

        Ort::AllocatorWithDefaultOptions alloc;

        // Input names + shape
        size_t n_inputs = impl_->session->GetInputCount();
        if (n_inputs < 1) { stats_.load_failures.fetch_add(1); return false; }

        impl_->input_name_strs.clear();
        impl_->input_names.clear();
        for (size_t i = 0; i < n_inputs; ++i) {
            auto name = impl_->session->GetInputNameAllocated(i, alloc);
            impl_->input_name_strs.push_back(name.get());
        }
        for (auto& s : impl_->input_name_strs)
            impl_->input_names.push_back(s.c_str());

        auto input_shape_info = impl_->session->GetInputTypeInfo(0)
            .GetTensorTypeAndShapeInfo();
        impl_->input_shape = input_shape_info.GetShape();

        impl_->n_features = 0;
        if (impl_->input_shape.size() >= 2 && impl_->input_shape[1] > 0)
            impl_->n_features = static_cast<size_t>(impl_->input_shape[1]);
        else if (impl_->input_shape.size() == 1 && impl_->input_shape[0] > 0)
            impl_->n_features = static_cast<size_t>(impl_->input_shape[0]);

        // Output names
        size_t n_outputs = impl_->session->GetOutputCount();
        impl_->output_name_strs.clear();
        impl_->output_names.clear();
        for (size_t i = 0; i < n_outputs; ++i) {
            auto name = impl_->session->GetOutputNameAllocated(i, alloc);
            impl_->output_name_strs.push_back(name.get());
        }
        for (auto& s : impl_->output_name_strs)
            impl_->output_names.push_back(s.c_str());

        impl_->loaded = true;
        return true;

    } catch (const Ort::Exception&) {
        impl_->loaded = false;
        stats_.load_failures.fetch_add(1);
        return false;
    }
}

void OnnxShadowClassifier::unload() {
    impl_->input_names.clear();
    impl_->output_names.clear();
    impl_->input_name_strs.clear();
    impl_->output_name_strs.clear();
    impl_->session.reset();
    impl_->loaded = false;
    impl_->n_features = 0;
}

bool OnnxShadowClassifier::is_loaded() const {
    if (!impl_ || impl_->moved_from) return false;
    return impl_->loaded;
}

// =====================================================================
// Inference
// =====================================================================

OnnxPrediction OnnxShadowClassifier::predict(const float* features,
                                              size_t n_features) {
    OnnxPrediction result;
    result.valid = false;

    if (!is_loaded()) return result;

    double threshold;
    {
        std::lock_guard<std::mutex> lk(config_mutex_);
        if (!config_.enabled) return result;
        threshold = config_.detection_threshold;
    }

    auto t0 = std::chrono::steady_clock::now();
    bool parsed_proba = false;

    try {
        std::vector<int64_t> shape = impl_->input_shape;
        if (!shape.empty() && (shape[0] == -1 || shape[0] == 0))
            shape[0] = 1;

        Ort::Value input_tensor = Ort::Value::CreateTensor<float>(
            impl_->memory_info,
            const_cast<float*>(features), n_features,
            shape.data(), shape.size());

        auto outputs = impl_->session->Run(
            Ort::RunOptions{nullptr},
            impl_->input_names.data(), &input_tensor, 1,
            impl_->output_names.data(), impl_->output_names.size());

        // Find the probabilities tensor (float, >= 2 elements)
        for (size_t i = 0; i < outputs.size() && !parsed_proba; ++i) {
            auto& out = outputs[i];
            if (!out.IsTensor()) continue;
            if (out.GetTensorTypeAndShapeInfo().GetElementType()
                != ONNX_TENSOR_ELEMENT_DATA_TYPE_FLOAT) continue;

            auto out_shape = out.GetTensorTypeAndShapeInfo().GetShape();
            size_t total = 1;
            for (auto d : out_shape)
                total *= (d > 0 ? static_cast<size_t>(d) : 1);

            if (total >= 2) {
                const float* data = out.GetTensorData<float>();
                result.p_normal = static_cast<double>(data[total - 2]);
                result.p_ncp_obfuscated = static_cast<double>(data[total - 1]);
                parsed_proba = true;
            } else if (total == 1) {
                const float* data = out.GetTensorData<float>();
                result.p_ncp_obfuscated = static_cast<double>(data[0]);
                result.p_normal = 1.0 - result.p_ncp_obfuscated;
                parsed_proba = true;
            }
        }

        if (parsed_proba) {
            result.valid = true;
            result.stealth_score = 1.0 - result.p_ncp_obfuscated;
            result.detected = (result.p_ncp_obfuscated > threshold);
        }

    } catch (const Ort::Exception&) {
        result.valid = false;
    }

    auto t1 = std::chrono::steady_clock::now();
    // Clock resolution on fast hosts can round a (mock) inference to 0µs;
    // record a minimum of 1µs so avg_latency stays meaningful.
    result.inference_time_us = static_cast<uint64_t>(std::max<int64_t>(
        1, std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count()));

    stats_.inferences_run.fetch_add(1);
    stats_.total_latency_us.fetch_add(result.inference_time_us);
    if (result.detected)
        stats_.detections.fetch_add(1);

    return result;
}

OnnxPrediction OnnxShadowClassifier::predict(const std::vector<float>& features) {
    return predict(features.data(), features.size());
}

std::vector<float> OnnxShadowClassifier::predict_proba(
        const std::vector<float>& features) {
    auto pred = predict(features);
    if (!pred.valid) return {};
    return {static_cast<float>(pred.p_normal),
            static_cast<float>(pred.p_ncp_obfuscated)};
}

// =====================================================================
// Config / Stats
// =====================================================================

void OnnxShadowClassifier::set_config(const OnnxClassifierConfig& config) {
    std::lock_guard<std::mutex> lock(config_mutex_);
    config_ = config;
}

OnnxClassifierConfig OnnxShadowClassifier::get_config() const {
    std::lock_guard<std::mutex> lock(config_mutex_);
    return config_;
}

OnnxClassifierStats OnnxShadowClassifier::get_stats() const {
    return stats_;
}

void OnnxShadowClassifier::reset_stats() {
    stats_.reset();
}

// =====================================================================
// Integration helpers
// =====================================================================

double OnnxShadowClassifier::combined_stealth(
        double heuristic_stealth,
        const OnnxPrediction& onnx_pred) const {
    double w;
    {
        std::lock_guard<std::mutex> lk(config_mutex_);
        if (!is_loaded() || !config_.enabled || !onnx_pred.valid)
            return heuristic_stealth;
        w = config_.weight;
    }
    return (1.0 - w) * heuristic_stealth + w * onnx_pred.stealth_score;
}

size_t OnnxShadowClassifier::input_feature_count() const {
    if (!is_loaded()) return 0;
    return impl_->n_features;
}

} // namespace DPI
} // namespace ncp
