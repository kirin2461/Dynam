#!/usr/bin/env python3
"""
Phase 3a (final): Train and export shadow classifier.

Strategy: Use multiple models, pick the best one that exports cleanly to ONNX
with regular tensor outputs (not seq(map)).

Models tried:
  1. LogisticRegression — clean tensor output, ~0.93 AUC
  2. RandomForest — clean tensor output, ~0.96 AUC  
  3. LightGBM — seq(map) output (harder for C++), ~0.99 AUC
"""

import os
import sys
import numpy as np
import json
import time
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, roc_auc_score, f1_score
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
import onnx
import onnxruntime as ort

sys.path.insert(0, os.path.dirname(__file__))
from train_shadow_classifier import (
    generate_dataset, FEATURE_NAMES,
    generate_normal_traffic, generate_ncp_obfuscated_traffic
)


def try_export(model, model_name, X_test, y_test):
    """Try to export model to ONNX and return (onnx_model, y_prob) or None."""
    from skl2onnx import convert_sklearn
    from skl2onnx.common.data_types import FloatTensorType
    
    try:
        initial_type = [('float_input', FloatTensorType([None, 10]))]
        onnx_model = convert_sklearn(
            model, initial_types=initial_type, target_opset=12,
            options={id(model): {'zipmap': False}}  # tensor output, not seq(map)
        )
        
        # Check output types — we want tensor, not seq(map)
        has_bad_output = False
        for out in onnx_model.graph.output:
            if out.type.HasField('sequence_type'):
                has_bad_output = True
                break
        
        if has_bad_output:
            print(f"  {model_name}: ✗ seq(map) output (not suitable)")
            return None
        
        # Verify tensor outputs
        tensor_outputs = []
        for out in onnx_model.graph.output:
            if out.type.HasField('tensor_type'):
                tensor_outputs.append(out.name)
        
        print(f"  {model_name}: ✓ clean tensor outputs: {tensor_outputs}")
        
        # Evaluate
        y_prob = model.predict_proba(X_test)[:, 1]
        y_pred = model.predict(X_test)
        auc = roc_auc_score(y_test, y_prob)
        f1 = f1_score(y_test, y_pred)
        print(f"  ROC-AUC: {auc:.4f}, F1: {f1:.4f}")
        
        return onnx_model, y_prob, auc, f1
    except Exception as e:
        print(f"  {model_name}: ✗ export failed: {e}")
        return None


def main():
    output_path = 'models/shadow_flow_classifier.onnx'
    n_samples = 10000
    seed = 42
    n_per_class = n_samples // 2
    
    print("=" * 60)
    print("PHASE 3a: Shadow Classifier (Final)")
    print("=" * 60)
    
    # Generate dataset
    X, y = generate_dataset(n_per_class, n_per_class, seed=seed)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=seed, stratify=y)
    
    print(f"Dataset: {X.shape[0]} samples, {X.shape[1]} features")
    print(f"Train: {len(X_train)}, Test: {len(X_test)}")
    
    # Try models
    print(f"\n{'='*60}")
    print("MODEL SELECTION")
    print(f"{'='*60}")
    
    models = {}
    
    # 1. LogisticRegression
    lr = LogisticRegression(max_iter=1000, C=1.0, random_state=seed)
    lr.fit(X_train, y_train)
    result = try_export(lr, "LogisticRegression", X_test, y_test)
    if result:
        models['LogisticRegression'] = (lr, result)
    
    # 2. RandomForest
    rf = RandomForestClassifier(n_estimators=50, max_depth=10, random_state=seed, n_jobs=-1)
    rf.fit(X_train, y_train)
    result = try_export(rf, "RandomForest", X_test, y_test)
    if result:
        models['RandomForest'] = (rf, result)
    
    # Select best
    if not models:
        print("\nERROR: No models exported successfully")
        return 1
    
    best_name = max(models.keys(), key=lambda k: models[k][1][2])  # by AUC (result is (model, (onnx, yprob, auc, f1)))
    best_model, (_, _, best_auc, best_f1) = models[best_name]
    print(f"\nSelected: {best_name} (AUC={best_auc:.4f}, F1={best_f1:.4f})")
    
    # Export best model
    from skl2onnx import convert_sklearn
    from skl2onnx.common.data_types import FloatTensorType
    
    initial_type = [('float_input', FloatTensorType([None, 10]))]
    onnx_model = convert_sklearn(
        best_model, initial_types=initial_type, target_opset=12,
        options={id(best_model): {'zipmap': False}}
    )
    
    os.makedirs(os.path.dirname(output_path) or '.', exist_ok=True)
    with open(output_path, 'wb') as f:
        f.write(onnx_model.SerializeToString())
    onnx.checker.check_model(onnx.load(output_path))
    
    size_kb = os.path.getsize(output_path) / 1024
    print(f"\nModel saved: {output_path} ({size_kb:.1f} KB)")
    
    # Metadata
    meta = {
        'features': FEATURE_NAMES,
        'n_features': 10,
        'model_type': best_name.lower(),
        'input_shape': [None, 10],
        'input_dtype': 'float32',
        'classes': [0, 1],
        'class_names': ['normal', 'ncp_obfuscated'],
        'auc': best_auc,
        'f1': best_f1,
    }
    meta_path = output_path.replace('.onnx', '_metadata.json')
    with open(meta_path, 'w') as f:
        json.dump(meta, f, indent=2)
    
    # ===== Verification =====
    print(f"\n{'='*60}")
    print("VERIFICATION (ONNX Runtime)")
    print(f"{'='*60}")
    
    sess_opts = ort.SessionOptions()
    sess_opts.intra_op_num_threads = 1
    sess = ort.InferenceSession(output_path, sess_opts)
    
    print(f"\nModel info:")
    for inp in sess.get_inputs():
        print(f"  Input: {inp.name}, shape={inp.shape}, type={inp.type}")
    for out in sess.get_outputs():
        print(f"  Output: {out.name}, shape={out.shape}, type={out.type}")
    
    rng = np.random.default_rng(999)
    
    # Test classification
    print(f"\nClassification tests:")
    correct = 0
    total = 0
    
    for label, gen_fn in [("normal", generate_normal_traffic),
                          ("obfuscated", generate_ncp_obfuscated_traffic)]:
        for _ in range(10):
            sample = gen_fn(1, rng).astype(np.float32)
            outputs = sess.run(None, {'float_input': sample})
            
            # Find probability output
            proba = None
            for out in outputs:
                if isinstance(out, np.ndarray) and out.dtype in (np.float32, np.float64):
                    if out.size >= 2:
                        proba = out.flatten()
                        break
                    elif out.size == 1:
                        proba = np.array([1.0 - out[0], out[0]])
                        break
            
            if proba is not None:
                p_normal, p_ncp = proba[0], proba[1] if len(proba) > 1 else proba[0]
                if len(proba) > 1:
                    p_normal, p_ncp = proba[-2], proba[-1]
                predicted = "normal" if p_normal > p_ncp else "obfuscated"
                is_correct = (predicted == label)
                if is_correct:
                    correct += 1
                total += 1
                status = "✓" if is_correct else "✗"
                print(f"  {status} {label:12s} → {predicted:12s} "
                      f"P(n)={p_normal:.4f} P(o)={p_ncp:.4f}")
    
    print(f"\n  Accuracy: {correct}/{total} ({100*correct/total:.0f}%)")
    
    # Benchmark
    sample = generate_normal_traffic(1, rng).astype(np.float32)
    times = []
    for _ in range(1000):
        t0 = time.perf_counter()
        sess.run(None, {'float_input': sample})
        t1 = time.perf_counter()
        times.append((t1 - t0) * 1e6)
    times = np.array(times)
    
    print(f"\nBenchmark (1000 inferences):")
    print(f"  Mean:   {times.mean():.1f} μs")
    print(f"  Median: {np.median(times):.1f} μs")
    print(f"  P95:    {np.percentile(times, 95):.1f} μs")
    print(f"  Min:    {times.min():.1f} μs")
    
    # C++ compatibility
    print(f"\n{'='*60}")
    print("C++ COMPATIBILITY")
    print(f"{'='*60}")
    
    test_input = np.array([500.0, 0.5, 0.35, 0.28, 0.03, 1.2, 0.4, 0.05, 0.20, 0.7],
                          dtype=np.float32).reshape(1, -1)
    outputs = sess.run(None, {'float_input': test_input})
    
    print(f"\nTest input: {test_input.flatten()}")
    for i, out in enumerate(outputs):
        name = sess.get_outputs()[i].name
        if isinstance(out, np.ndarray):
            print(f"  Output '{name}': dtype={out.dtype}, shape={out.shape}, values={out.flatten()}")
        else:
            print(f"  Output '{name}': type={type(out)}")
    
    # Find the probability tensor
    for i, out in enumerate(outputs):
        if isinstance(out, np.ndarray) and out.dtype in (np.float32, np.float64) and out.size >= 2:
            flat = out.flatten()
            print(f"\n  ✓ C++ code reads: data[{flat.size-2}]={flat[-2]:.6f} (P_normal)")
            print(f"                     data[{flat.size-1}]={flat[-1]:.6f} (P_ncp)")
            break
    
    print(f"\n{'='*60}")
    print("DONE ✓")
    print(f"{'='*60}")
    return 0


if __name__ == '__main__':
    exit(main())
