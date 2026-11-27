/**
 * @file test_onnx_classifier.cpp
 * @brief GoogleTest tests for OnnxShadowClassifier.
 *
 * ONNX Runtime is required. All tests run real inference.
 * Set NCP_TEST_MODEL environment variable to the .onnx file path.
 *
 * Compile:
 *   g++ -std=c++17 -I src tests/test_onnx_classifier.cpp \
 *       src/ncp_onnx_classifier.cpp \
 *       -lonnxruntime -lgtest -lgtest_main -lpthread \
 *       -o test_onnx_classifier
 */

#include "ncp_onnx_classifier.hpp"

#include <gtest/gtest.h>
#include <cmath>
#include <cstdlib>

using namespace ncp::DPI;

// =====================================================================
// Lifecycle tests
// =====================================================================

TEST(OnnxShadowClassifier, DefaultConstruction) {
    OnnxShadowClassifier clf;
    EXPECT_FALSE(clf.is_loaded());
    EXPECT_EQ(clf.input_feature_count(), 0u);
}

TEST(OnnxShadowClassifier, ConfigConstruction) {
    OnnxClassifierConfig cfg;
    cfg.enabled = true;
    cfg.weight = 0.7;
    cfg.detection_threshold = 0.6;

    OnnxShadowClassifier clf(cfg);
    auto got = clf.get_config();
    EXPECT_TRUE(got.enabled);
    EXPECT_NEAR(got.weight, 0.7, 0.001);
    EXPECT_NEAR(got.detection_threshold, 0.6, 0.001);
}

TEST(OnnxShadowClassifier, PredictWithoutLoadReturnsInvalid) {
    OnnxShadowClassifier clf;
    std::vector<float> features(10, 0.5f);
    auto pred = clf.predict(features);
    EXPECT_FALSE(pred.valid);
    EXPECT_FALSE(pred.detected);
}

TEST(OnnxShadowClassifier, PredictProbaWithoutLoadReturnsEmpty) {
    OnnxShadowClassifier clf;
    std::vector<float> features(10, 0.5f);
    auto proba = clf.predict_proba(features);
    EXPECT_TRUE(proba.empty());
}

TEST(OnnxShadowClassifier, CombinedStealthWithoutModelReturnsHeuristic) {
    OnnxShadowClassifier clf;
    OnnxPrediction invalid_pred;
    double result = clf.combined_stealth(0.8, invalid_pred);
    EXPECT_NEAR(result, 0.8, 0.001);
}

TEST(OnnxShadowClassifier, StatsInitiallyZero) {
    OnnxShadowClassifier clf;
    auto stats = clf.get_stats();
    EXPECT_EQ(stats.inferences_run.load(), 0u);
    EXPECT_EQ(stats.detections.load(), 0u);
    EXPECT_EQ(stats.load_failures.load(), 0u);
    EXPECT_NEAR(stats.avg_latency_us(), 0.0, 0.001);
}

TEST(OnnxShadowClassifier, UnloadIsIdempotent) {
    OnnxShadowClassifier clf;
    clf.unload();
    EXPECT_FALSE(clf.is_loaded());
    clf.unload();  // second call must not crash
    EXPECT_FALSE(clf.is_loaded());
}

TEST(OnnxShadowClassifier, MoveConstruction) {
    OnnxShadowClassifier clf1;
    OnnxShadowClassifier clf2(std::move(clf1));
    EXPECT_FALSE(clf2.is_loaded());
    EXPECT_FALSE(clf1.is_loaded());  // source is safe, not UB
}

TEST(OnnxShadowClassifier, MoveAssignment) {
    OnnxShadowClassifier clf1;
    OnnxShadowClassifier clf2;
    clf2 = std::move(clf1);
    EXPECT_FALSE(clf2.is_loaded());
    EXPECT_FALSE(clf1.is_loaded());
}

TEST(OnnxShadowClassifier, LoadFailsWithBadPath) {
    OnnxClassifierConfig cfg;
    cfg.model_path = "/nonexistent/model.onnx";
    cfg.enabled = true;
    OnnxShadowClassifier clf(cfg);
    EXPECT_FALSE(clf.load());
    EXPECT_GE(clf.get_stats().load_failures.load(), 1u);
}

// =====================================================================
// expand_tilde
// =====================================================================

TEST(OnnxShadowFeatures, ExpandTildeAbsolute) {
    EXPECT_EQ(OnnxShadowFeatures::expand_tilde("/absolute/path"),
              "/absolute/path");
}

TEST(OnnxShadowFeatures, ExpandTildeRelative) {
    EXPECT_EQ(OnnxShadowFeatures::expand_tilde("relative/path"),
              "relative/path");
}

TEST(OnnxShadowFeatures, ExpandTildeEmpty) {
    EXPECT_EQ(OnnxShadowFeatures::expand_tilde(""), "");
}

TEST(OnnxShadowFeatures, ExpandTildeHome) {
    std::string result = OnnxShadowFeatures::expand_tilde("~/model.onnx");
    const char* home = std::getenv("HOME");
#ifdef _WIN32
    if (!home) home = std::getenv("USERPROFILE");
#endif
    if (home) {
        EXPECT_NE(result[0], '~');
        EXPECT_NE(result.find("model.onnx"), std::string::npos);
    }
}

TEST(OnnxShadowFeatures, ToArray) {
    OnnxShadowFeatures f;
    f.size_mean = 500.0f;
    f.timing_cov = 1.2f;
    auto arr = f.to_array();
    EXPECT_EQ(arr.size(), 10u);
    EXPECT_FLOAT_EQ(arr[0], 500.0f);
    EXPECT_FLOAT_EQ(arr[5], 1.2f);
}

// =====================================================================
// Real inference tests (require NCP_TEST_MODEL)
// =====================================================================

class OnnxInferenceTest : public ::testing::Test {
protected:
    void SetUp() override {
        const char* path = std::getenv("NCP_TEST_MODEL");
        if (!path) GTEST_SKIP() << "Set NCP_TEST_MODEL to .onnx path";
        model_path_ = path;
    }
    std::string model_path_;
};

TEST_F(OnnxInferenceTest, LoadModel) {
    OnnxClassifierConfig cfg;
    cfg.model_path = model_path_;
    cfg.enabled = true;

    OnnxShadowClassifier clf(cfg);
    ASSERT_TRUE(clf.load()) << "Failed to load: " << model_path_;
    EXPECT_TRUE(clf.is_loaded());
    EXPECT_EQ(clf.input_feature_count(), 10u);
}

TEST_F(OnnxInferenceTest, PredictNormalTraffic) {
    OnnxClassifierConfig cfg;
    cfg.model_path = model_path_;
    cfg.enabled = true;
    cfg.detection_threshold = 0.5;

    OnnxShadowClassifier clf(cfg);
    ASSERT_TRUE(clf.load());

    std::vector<float> features = {
        600.0f, 0.8f, 0.30f, 0.30f, 0.02f, 2.0f, 0.2f, 0.08f, 0.15f, 0.5f};

    auto pred = clf.predict(features);
    ASSERT_TRUE(pred.valid) << "Inference produced no valid output";
    EXPECT_FALSE(pred.detected) << "Normal traffic should not be detected";
    EXPECT_GT(pred.p_normal, pred.p_ncp_obfuscated);
}

TEST_F(OnnxInferenceTest, PredictObfuscatedTraffic) {
    OnnxClassifierConfig cfg;
    cfg.model_path = model_path_;
    cfg.enabled = true;
    cfg.detection_threshold = 0.5;

    OnnxShadowClassifier clf(cfg);
    ASSERT_TRUE(clf.load());

    std::vector<float> features = {
        500.0f, 0.45f, 0.38f, 0.25f, 0.05f, 1.2f, 0.4f, 0.04f, 0.22f, 0.8f};

    auto pred = clf.predict(features);
    ASSERT_TRUE(pred.valid) << "Inference produced no valid output";
    EXPECT_TRUE(pred.detected) << "Obfuscated traffic should be detected";
    EXPECT_GT(pred.p_ncp_obfuscated, pred.p_normal);
}

TEST_F(OnnxInferenceTest, CombinedStealthReducesScore) {
    OnnxClassifierConfig cfg;
    cfg.model_path = model_path_;
    cfg.enabled = true;
    cfg.weight = 0.6;

    OnnxShadowClassifier clf(cfg);
    clf.load();

    std::vector<float> features = {
        500, 0.45f, 0.38f, 0.25f, 0.05f, 1.2f, 0.4f, 0.04f, 0.22f, 0.8f};
    auto pred = clf.predict(features);
    ASSERT_TRUE(pred.valid);

    double heuristic = 0.8;
    double combined = clf.combined_stealth(heuristic, pred);
    // ONNX detects obfuscated → combined < heuristic
    EXPECT_LT(combined, heuristic);
    double expected = 0.4 * heuristic + 0.6 * pred.stealth_score;
    EXPECT_NEAR(combined, expected, 0.01);
}

TEST_F(OnnxInferenceTest, StatsTracking) {
    OnnxClassifierConfig cfg;
    cfg.model_path = model_path_;
    cfg.enabled = true;
    cfg.detection_threshold = 0.5;

    OnnxShadowClassifier clf(cfg);
    clf.load();
    clf.reset_stats();

    std::vector<float> normal = {
        600, 0.8f, 0.3f, 0.3f, 0.02f, 2.0f, 0.2f, 0.08f, 0.15f, 0.5f};
    std::vector<float> obfuscated = {
        500, 0.45f, 0.38f, 0.25f, 0.05f, 1.2f, 0.4f, 0.04f, 0.22f, 0.8f};

    clf.predict(normal);
    clf.predict(obfuscated);
    clf.predict(obfuscated);

    auto stats = clf.get_stats();
    EXPECT_EQ(stats.inferences_run.load(), 3u);
    EXPECT_EQ(stats.detections.load(), 2u);
    EXPECT_NEAR(stats.detection_rate(), 2.0 / 3.0, 0.01);
}

TEST_F(OnnxInferenceTest, InferenceLatencyUnder1ms) {
    OnnxClassifierConfig cfg;
    cfg.model_path = model_path_;
    cfg.enabled = true;

    OnnxShadowClassifier clf(cfg);
    clf.load();

    std::vector<float> features(10, 0.5f);
    // Warmup
    for (int i = 0; i < 10; ++i) clf.predict(features);
    // Measure
    clf.reset_stats();
    for (int i = 0; i < 100; ++i) clf.predict(features);

    double avg_us = clf.get_stats().avg_latency_us();
    EXPECT_LT(avg_us, 1000.0) << "Avg inference > 1ms: " << avg_us << " μs";
}

TEST_F(OnnxInferenceTest, DisabledConfigReturnsInvalid) {
    OnnxClassifierConfig cfg;
    cfg.model_path = model_path_;
    cfg.enabled = false;  // disabled

    OnnxShadowClassifier clf(cfg);
    clf.load();  // loads model

    std::vector<float> features = {
        500, 0.45f, 0.38f, 0.25f, 0.05f, 1.2f, 0.4f, 0.04f, 0.22f, 0.8f};
    auto pred = clf.predict(features);
    // Model is loaded but config says disabled → should not run inference
    EXPECT_FALSE(pred.valid);
}
