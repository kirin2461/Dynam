/**
 * @file onnxruntime_cxx_api.h
 * @brief Minimal ONNX Runtime C++ API mock for testing.
 *
 * Simulates the ORT API surface used by ncp_onnx_classifier.cpp.
 * Mock Session performs logistic regression to produce realistic outputs.
 */
#pragma once

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <cmath>
#include <string>
#include <vector>
#include <stdexcept>
#include <memory>

// ── Enums ──
enum OrtLoggingLevel { ORT_LOGGING_LEVEL_WARNING = 2 };
enum GraphOptimizationLevel {
    ORT_DISABLE_ALL = 0, ORT_ENABLE_ALL = 99
};
enum OrtAllocatorType { OrtArenaAllocator = 0 };
enum OrtMemType { OrtMemTypeDefault = 0 };
enum ONNXTensorElementDataType {
    ONNX_TENSOR_ELEMENT_DATA_TYPE_FLOAT = 1,
    ONNX_TENSOR_ELEMENT_DATA_TYPE_INT64 = 7,
};

namespace Ort {

class Exception : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

class AllocatorWithDefaultOptions {
public:
    AllocatorWithDefaultOptions() = default;
};

class MemoryInfo {
public:
    static MemoryInfo CreateCpu(OrtAllocatorType, OrtMemType) { return {}; }
};

class AllocatedString {
    std::string s_;
public:
    AllocatedString(const char* p) : s_(p ? p : "") {}
    const char* get() const { return s_.c_str(); }
};

struct TensorInfo {
    std::vector<int64_t> shape;
    ONNXTensorElementDataType elem_type = ONNX_TENSOR_ELEMENT_DATA_TYPE_FLOAT;
    std::vector<int64_t> GetShape() const { return shape; }
    ONNXTensorElementDataType GetElementType() const { return elem_type; }
};

struct TypeInfo {
    TensorInfo tensor_info;
    TensorInfo GetTensorTypeAndShapeInfo() const { return tensor_info; }
};

class Value {
    std::vector<uint8_t> storage_;
    std::vector<int64_t> shape_;
    ONNXTensorElementDataType elem_type_ = ONNX_TENSOR_ELEMENT_DATA_TYPE_FLOAT;
    const float* float_ptr_ = nullptr;
    size_t float_count_ = 0;

public:
    Value() = default;

    // Template factory matching ORT API: CreateTensor<float>(mem, data, len, shape, shape_len)
    template <typename T>
    static Value CreateTensor(const MemoryInfo&, T* data, size_t len,
                              const int64_t* shape, size_t shape_len) {
        Value v;
        // Copy data into owned storage
        size_t bytes = len * sizeof(T);
        v.storage_.resize(bytes);
        std::memcpy(v.storage_.data(), data, bytes);
        v.shape_.assign(shape, shape + shape_len);
        v.float_ptr_ = reinterpret_cast<const float*>(v.storage_.data());
        v.float_count_ = len;
        return v;
    }

    bool IsTensor() const { return true; }

    TensorInfo GetTensorTypeAndShapeInfo() const {
        TensorInfo ti;
        ti.shape = shape_;
        ti.elem_type = elem_type_;
        return ti;
    }

    template <typename T>
    const T* GetTensorData() const {
        return reinterpret_cast<const T*>(storage_.data());
    }

    // For mock: set output
    void set_float_output(std::vector<float> data, std::vector<int64_t> shape) {
        elem_type_ = ONNX_TENSOR_ELEMENT_DATA_TYPE_FLOAT;
        shape_ = std::move(shape);
        storage_.resize(data.size() * sizeof(float));
        std::memcpy(storage_.data(), data.data(), storage_.size());
    }
    void set_int64_output(int64_t val, std::vector<int64_t> shape) {
        elem_type_ = ONNX_TENSOR_ELEMENT_DATA_TYPE_INT64;
        shape_ = std::move(shape);
        storage_.resize(sizeof(int64_t));
        std::memcpy(storage_.data(), &val, sizeof(int64_t));
    }
};

struct RunOptions {
    RunOptions(std::nullptr_t) {}
};

class SessionOptions {
public:
    void SetIntraOpNumThreads(int) {}
    void SetInterOpNumThreads(int) {}
    void SetGraphOptimizationLevel(GraphOptimizationLevel) {}
    void EnableCpuMemArena() {}
    void EnableMemPattern() {}
};

// Env MUST be defined before Session (Session references it)
class Env {
public:
    Env(OrtLoggingLevel, const char*) {}
};

// Mock inference: logistic model calibrated so that
//   OBFUSCATED [500,0.45,0.38,0.25,0.05,1.2,0.4,0.04,0.22,0.8] → p_ncp ≈ 0.79
//   NORMAL     [600,0.80,0.30,0.30,0.02,2.0,0.2,0.08,0.15,0.5] → p_ncp ≈ 0.01
inline std::vector<float> mock_infer(const float* input, size_t n) {
    float z = -1.5f;
    if (n >= 10) {
        z += -5.0f * (input[1] - 0.6f);   // size_cv: low → obfuscated
        z += -3.0f * (input[5] - 1.5f);    // timing_cov: low → obfuscated
        z +=  4.0f * (input[8] - 0.15f);   // upload_ratio: high → obfuscated
        z += -2.0f * (input[0] - 550.0f) / 200.0f;  // size_mean
        z +=  2.0f * (input[9] - 0.6f);    // burst_rate: regular → obfuscated
    }
    float p_ncp = 1.0f / (1.0f + std::exp(-z));
    return {1.0f - p_ncp, p_ncp};
}

class Session {
    bool loaded_ = false;
public:
    Session(const Env&, const char* path, const SessionOptions&) {
        std::string p(path ? path : "");
        if (p.find(".onnx") == std::string::npos)
            throw Exception("Not a model file: " + p);
        if (p.find("/nonexistent") != std::string::npos)
            throw Exception("File not found: " + p);
        loaded_ = true;
    }
    Session(const Env&, const wchar_t* path, const SessionOptions&) {
        std::string p;
        if (path) { while (*path) { p += static_cast<char>(*path); ++path; } }
        if (p.find(".onnx") == std::string::npos)
            throw Exception("Not a model file");
        if (p.find("nonexistent") != std::string::npos)
            throw Exception("File not found");
        loaded_ = true;
    }

    size_t GetInputCount() const { return 1; }
    size_t GetOutputCount() const { return 2; }

    AllocatedString GetInputNameAllocated(size_t, const AllocatorWithDefaultOptions&) const {
        return AllocatedString("float_input");
    }
    AllocatedString GetOutputNameAllocated(size_t idx, const AllocatorWithDefaultOptions&) const {
        return AllocatedString(idx == 0 ? "label" : "probabilities");
    }
    TypeInfo GetInputTypeInfo(size_t) const {
        TypeInfo ti;
        ti.tensor_info.shape = {-1, 10};
        ti.tensor_info.elem_type = ONNX_TENSOR_ELEMENT_DATA_TYPE_FLOAT;
        return ti;
    }
    TypeInfo GetOutputTypeInfo(size_t idx) const {
        TypeInfo ti;
        if (idx == 0) {
            ti.tensor_info.shape = {-1};
            ti.tensor_info.elem_type = ONNX_TENSOR_ELEMENT_DATA_TYPE_INT64;
        } else {
            ti.tensor_info.shape = {-1, 2};
            ti.tensor_info.elem_type = ONNX_TENSOR_ELEMENT_DATA_TYPE_FLOAT;
        }
        return ti;
    }

    std::vector<Value> Run(const RunOptions&,
                           const char* const*, const Value* inputs, size_t,
                           const char* const* output_names, size_t n_out) {
        if (!loaded_) throw Exception("Not loaded");

        auto input_shape = inputs[0].GetTensorTypeAndShapeInfo().GetShape();
        size_t n = 1;
        for (auto d : input_shape) if (d > 0) n *= d;
        const float* data = inputs[0].GetTensorData<float>();
        auto probs = mock_infer(data, n);

        std::vector<Value> results(n_out);
        for (size_t i = 0; i < n_out; ++i) {
            std::string name = output_names[i];
            if (name == "label") {
                results[i].set_int64_output(probs[1] > 0.5f ? 1 : 0, {1});
            } else {
                results[i].set_float_output(probs, {1, 2});
            }
        }
        return results;
    }
};

} // namespace Ort
