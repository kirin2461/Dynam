#!/usr/bin/env python3
"""
Validate ONNX model inference: verify the ONNX model produces correct outputs.
This simulates what the C++ OnnxShadowClassifier will do.

Usage:
    python validate_onnx.py [--model models/shadow_flow_classifier.onnx]
"""

import argparse
import numpy as np
import onnxruntime as ort
import json
import os
import time


def load_model(model_path: str):
    """Load ONNX model and print info."""
    print(f"Loading model: {model_path}")
    
    sess_opts = ort.SessionOptions()
    sess_opts.intra_op_num_threads = 1
    sess_opts.inter_op_num_threads = 1
    sess_opts.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
    
    session = ort.InferenceSession(model_path, sess_opts)
    
    print(f"\nModel info:")
    print(f"  Inputs:")
    for inp in session.get_inputs():
        print(f"    {inp.name}: shape={inp.shape}, type={inp.type}")
    print(f"  Outputs:")
    for out in session.get_outputs():
        print(f"    {out.name}: shape={out.shape}, type={out.type}")
    
    return session


def generate_test_samples(n: int = 10):
    """Generate test feature vectors for validation."""
    rng = np.random.default_rng(123)
    
    # Mix of normal and obfuscated
    samples = []
    
    # Normal traffic (should be classified as class 0)
    for _ in range(n // 2):
        features = np.array([
            rng.normal(600, 200),    # size_mean
            rng.normal(0.8, 0.3),    # size_cv
            rng.normal(0.30, 0.10),  # frac_small
            rng.normal(0.30, 0.12),  # frac_large
            rng.exponential(0.02),   # error_rate
            rng.normal(2.0, 0.8),    # timing_cov
            rng.beta(2, 5),          # burst_anomaly
            rng.exponential(0.08),   # ks_distance
            rng.normal(0.15, 0.05),  # upload_ratio
            rng.exponential(0.5),    # burst_rate
        ], dtype=np.float32).clip(0, 10000)
        samples.append(('normal', features))
    
    # NCP-obfuscated (should be classified as class 1)
    for _ in range(n // 2):
        features = np.array([
            rng.normal(500, 120),    # size_mean
            rng.normal(0.45, 0.15),  # size_cv
            rng.normal(0.38, 0.08),  # frac_small
            rng.normal(0.25, 0.08),  # frac_large
            rng.exponential(0.05),   # error_rate
            rng.normal(1.2, 0.5),    # timing_cov
            rng.beta(3, 4),          # burst_anomaly
            rng.exponential(0.04),   # ks_distance
            rng.normal(0.22, 0.08),  # upload_ratio
            rng.normal(0.8, 0.2),    # burst_rate
        ], dtype=np.float32).clip(0, 10000)
        samples.append(('obfuscated', features))
    
    return samples


def benchmark_inference(session, features: np.ndarray, n_runs: int = 1000):
    """Benchmark inference latency."""
    input_name = session.get_inputs()[0].name
    
    # Warmup
    for _ in range(10):
        session.run(None, {input_name: features.reshape(1, -1)})
    
    # Benchmark
    times = []
    for _ in range(n_runs):
        t0 = time.perf_counter()
        session.run(None, {input_name: features.reshape(1, -1)})
        t1 = time.perf_counter()
        times.append((t1 - t0) * 1e6)  # microseconds
    
    return np.array(times)


def main():
    parser = argparse.ArgumentParser(description="Validate ONNX shadow classifier")
    parser.add_argument('--model', default='models/shadow_flow_classifier.onnx')
    parser.add_argument('--benchmark-runs', type=int, default=1000)
    args = parser.parse_args()
    
    if not os.path.exists(args.model):
        print(f"ERROR: Model not found: {args.model}")
        print("Run train_shadow_classifier.py first.")
        return 1
    
    # Load model
    session = load_model(args.model)
    
    # Get input/output names (same as C++ code will use)
    input_name = session.get_inputs()[0].name
    output_names = [out.name for out in session.get_outputs()]
    
    print(f"\nInput name: '{input_name}'")
    print(f"Output names: {output_names}")
    
    # Load metadata
    meta_path = args.model.replace('.onnx', '_metadata.json')
    if os.path.exists(meta_path):
        with open(meta_path) as f:
            meta = json.load(f)
        print(f"\nFeature names: {meta.get('features', 'unknown')}")
        print(f"Expected features: {meta.get('n_features', 'unknown')}")
    
    # Test samples
    print(f"\n{'='*60}")
    print("CLASSIFICATION TESTS")
    print(f"{'='*60}")
    
    samples = generate_test_samples(10)
    correct = 0
    
    for expected_label, features in samples:
        input_data = features.reshape(1, -1).astype(np.float32)
        outputs = session.run(output_names, {input_name: input_data})
        
        # Find probabilities output
        proba = None
        label = None
        for i, out in enumerate(outputs):
            if isinstance(out, np.ndarray):
                if out.dtype in (np.float32, np.float64) and out.size >= 2:
                    proba = out.flatten()[-2:]  # Last 2 values
                elif out.dtype in (np.int64, np.int32):
                    label = out.flatten()[0]
        
        if proba is not None:
            p_normal = proba[0]
            p_ncp = proba[1]
            predicted = 'normal' if p_normal > p_ncp else 'obfuscated'
            is_correct = (predicted == expected_label)
            if is_correct:
                correct += 1
            status = "✓" if is_correct else "✗"
            print(f"  {status} Expected: {expected_label:12s} | "
                  f"Predicted: {predicted:12s} | "
                  f"P(normal)={p_normal:.4f}, P(ncp)={p_ncp:.4f}")
        else:
            print(f"  ? Expected: {expected_label:12s} | Could not parse output")
    
    accuracy = correct / len(samples) * 100
    print(f"\nAccuracy: {correct}/{len(samples)} ({accuracy:.0f}%)")
    
    # Benchmark
    print(f"\n{'='*60}")
    print(f"BENCHMARK ({args.benchmark_runs} runs)")
    print(f"{'='*60}")
    
    sample_features = samples[0][1]
    times = benchmark_inference(session, sample_features, args.benchmark_runs)
    
    print(f"  Mean:   {times.mean():.1f} μs")
    print(f"  Median: {np.median(times):.1f} μs")
    print(f"  P95:    {np.percentile(times, 95):.1f} μs")
    print(f"  P99:    {np.percentile(times, 99):.1f} μs")
    print(f"  Min:    {times.min():.1f} μs")
    print(f"  Max:    {times.max():.1f} μs")
    
    # C++ compatibility check
    print(f"\n{'='*60}")
    print("C++ COMPATIBILITY CHECK")
    print(f"{'='*60}")
    
    # Verify the output format matches what C++ expects
    test_input = np.array([
        500.0, 0.5, 0.35, 0.28, 0.03, 1.2, 0.4, 0.05, 0.20, 0.7
    ], dtype=np.float32).reshape(1, -1)
    
    outputs = session.run(output_names, {input_name: test_input})
    
    print(f"  Input shape: {test_input.shape}")
    print(f"  Input dtype: {test_input.dtype}")
    print(f"  Number of outputs: {len(outputs)}")
    
    for i, out in enumerate(outputs):
        print(f"  Output[{i}] ('{output_names[i]}'):")
        print(f"    shape: {out.shape}, dtype: {out.dtype}, values: {out.flatten()[:5]}")
    
    print(f"\n  C++ code expects:")
    print(f"    - Float tensor with >= 2 elements")
    print(f"    - data[0] = P(normal), data[1] = P(NCP-obfuscated)")
    
    # Find the probability output
    for i, out in enumerate(outputs):
        if out.dtype in (np.float32, np.float64) and out.size >= 2:
            flat = out.flatten()
            print(f"\n  ✓ Output[{i}] ('{output_names[i]}') matches expected format")
            print(f"    P(normal) = {flat[-2]:.6f}")
            print(f"    P(ncp)    = {flat[-1]:.6f}")
            break
    
    # Model size
    model_size = os.path.getsize(args.model)
    print(f"\n  Model file size: {model_size / 1024:.1f} KB")
    
    print(f"\n{'='*60}")
    if accuracy >= 80:
        print("VALIDATION PASSED ✓")
    else:
        print("VALIDATION FAILED ✗")
    print(f"{'='*60}")
    
    return 0 if accuracy >= 80 else 1


if __name__ == '__main__':
    exit(main())
