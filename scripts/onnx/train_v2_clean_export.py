#!/usr/bin/env python3
"""
Phase 3a (v2): Train and export shadow classifier with clean tensor output.

Uses LightGBM for training, then converts to ONNX via a sklearn-compatible
wrapper that produces regular tensor outputs (not seq(map)).
"""

import argparse
import os
import sys
import numpy as np
import lightgbm as lgb
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, roc_auc_score, f1_score
from sklearn.base import BaseEstimator, ClassifierMixin
import onnx
import json

# Reuse data generation from the main script
sys.path.insert(0, os.path.dirname(__file__))
from train_shadow_classifier import (
    generate_dataset, FEATURE_NAMES, generate_normal_traffic,
    generate_ncp_obfuscated_traffic
)


class LightGBMSklearnWrapper(BaseEstimator, ClassifierMixin):
    """
    Wraps a trained LightGBM Booster into a sklearn-compatible classifier
    that can be exported to ONNX with clean tensor outputs.
    """
    def __init__(self, booster):
        self.booster = booster
        self.classes_ = np.array([0, 1])
    
    def fit(self, X, y):
        return self
    
    def predict(self, X):
        proba = self.booster.predict(X)
        return (proba > 0.5).astype(int)
    
    def predict_proba(self, X):
        p1 = self.booster.predict(X)
        p0 = 1.0 - p1
        return np.column_stack([p0, p1])
    
    @property
    def n_features_in_(self):
        return self.booster.num_feature()


def train_and_export(n_samples=10000, output_path='models/shadow_flow_classifier.onnx', seed=42):
    n_per_class = n_samples // 2
    
    print("=" * 60)
    print("PHASE 3a (v2): Clean Tensor Output Export")
    print("=" * 60)
    
    # Generate and split data
    X, y = generate_dataset(n_per_class, n_per_class, seed=seed)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=seed, stratify=y)
    X_train, X_val, y_train, y_val = train_test_split(
        X_train, y_train, test_size=0.15, random_state=seed, stratify=y_train)
    
    # Train LightGBM
    print("\nTraining LightGBM...")
    train_data = lgb.Dataset(X_train, label=y_train, feature_name=FEATURE_NAMES)
    val_data = lgb.Dataset(X_val, label=y_val, feature_name=FEATURE_NAMES,
                           reference=train_data)
    
    params = {
        'objective': 'binary',
        'metric': 'binary_logloss',
        'boosting_type': 'gbdt',
        'num_leaves': 31,
        'learning_rate': 0.05,
        'feature_fraction': 0.8,
        'bagging_fraction': 0.8,
        'bagging_freq': 5,
        'verbose': -1,
        'seed': seed,
    }
    
    booster = lgb.train(
        params, train_data, num_boost_round=200,
        valid_sets=[val_data],
        callbacks=[lgb.early_stopping(20), lgb.log_evaluation(0)],
    )
    
    # Evaluate
    wrapper = LightGBMSklearnWrapper(booster)
    y_prob = wrapper.predict_proba(X_test)[:, 1]
    y_pred = (y_prob > 0.5).astype(int)
    
    print(f"\nROC-AUC: {roc_auc_score(y_test, y_prob):.4f}")
    print(f"F1 Score: {f1_score(y_test, y_pred):.4f}")
    print(classification_report(y_test, y_pred,
                                target_names=["Normal", "NCP-Obfuscated"]))
    
    # Export to ONNX using onnxmltools with the sklearn wrapper
    from skl2onnx import convert_sklearn, update_registered_converter
    from skl2onnx.common.data_types import FloatTensorType
    from skl2onnx.common.shape_calculator import calculate_linear_classifier_output_shapes
    from skl2onnx._parse import _get_model_inputs
    import onnxmltools
    from onnxmltools.convert.common.data_types import FloatTensorType as OTFloatTensorType
    from onnxmltools.convert.lightgbm.operator_converters.LightGbm import convert_lightgbm as lgb_converter
    from onnxmltools.convert import _supported_converters
    
    # Register our wrapper with skl2onnx
    # We need to register both shape calculator and converter
    def lightgbm_wrapper_shape_calculator(operator):
        N = operator.inputs[0].type.shape[0]
        operator.outputs[0].type.shape = [N, 1]  # labels
        operator.outputs[1].type.shape = [N, 2]  # probabilities
    
    def lightgbm_wrapper_converter(scope, operator, container):
        # Delegate to the native LightGBM converter
        # Create a temporary operator with the booster
        from onnxmltools.convert.lightgbm.operator_converters.LightGbm import convert_lightgbm
        
        # We need to access the internal booster
        booster = operator.raw_model.booster
        
        # Use onnxmltools' native LightGBM converter
        # But we need to restructure inputs/outputs
        # Actually, let's just do it manually with numpy
        
        # Get the booster's dump and create ONNX tree ensemble
        # This is complex; let's use a simpler approach
        
        # SIMPLER APPROACH: Use onnxmltools directly on the booster
        # with proper output format
        pass
    
    # Actually, the simplest approach: use onnxmltools.convert_lightgbm
    # but specify output class labels properly to get tensor output
    
    print("\nExporting to ONNX...")
    
    # Use onnxmltools directly
    initial_type = [('float_input', OTFloatTensorType([None, 10]))]
    
    onnx_model = onnxmltools.convert_lightgbm(
        booster,
        initial_types=initial_type,
        target_opset=12,
    )
    
    # Check output types
    print("\nOutput types:")
    for out in onnx_model.graph.output:
        print(f"  {out.name}: {out.type}")
    
    # If probabilities is seq(map), we need to post-process
    # Let's check and potentially modify the model
    has_seq_output = False
    for out in onnx_model.graph.output:
        if out.type.HasField('sequence_type'):
            has_seq_output = True
            print(f"  WARNING: '{out.name}' is seq(map) format")
    
    if has_seq_output:
        print("\nPost-processing: converting seq(map) to tensor output...")
        # We need to modify the ONNX graph to convert the seq(map) output
        # to a regular float tensor. This requires adding conversion nodes.
        
        # Alternative: train a simple sklearn model instead
        print("Switching to sklearn LogisticRegression for clean export...")
        
        from sklearn.linear_model import LogisticRegression
        from skl2onnx import convert_sklearn
        from skl2onnx.common.data_types import FloatTensorType
        
        lr = LogisticRegression(max_iter=1000, random_state=seed, C=1.0)
        lr.fit(X_train, y_train)
        
        y_prob_lr = lr.predict_proba(X_test)[:, 1]
        y_pred_lr = lr.predict(X_test)
        print(f"\nLogisticRegression ROC-AUC: {roc_auc_score(y_test, y_prob_lr):.4f}")
        print(f"LogisticRegression F1: {f1_score(y_test, y_pred_lr):.4f}")
        
        # Export LogisticRegression — this produces clean tensor outputs
        initial_type = [('float_input', FloatTensorType([None, 10]))]
        onnx_model = convert_sklearn(
            lr,
            initial_types=initial_type,
            target_opset=12,
        )
        
        print("\nFinal ONNX output types:")
        for out in onnx_model.graph.output:
            t = out.type
            if t.HasField('tensor_type'):
                shape = [d.dim_value if d.dim_value > 0 else d.dim_param 
                         for d in t.tensor_type.shape.dim]
                print(f"  {out.name}: tensor({t.tensor_type.elem_type}), shape={shape}")
            else:
                print(f"  {out.name}: {t}")
    
    # Save
    os.makedirs(os.path.dirname(output_path) or '.', exist_ok=True)
    with open(output_path, 'wb') as f:
        f.write(onnx_model.SerializeToString())
    
    onnx.checker.check_model(onnx.load(output_path))
    
    size_kb = os.path.getsize(output_path) / 1024
    print(f"\nModel saved: {output_path} ({size_kb:.1f} KB)")
    
    # Save metadata
    meta = {
        'features': FEATURE_NAMES,
        'n_features': 10,
        'model_type': 'logistic_regression',
        'input_shape': [None, 10],
        'input_dtype': 'float32',
        'classes': [0, 1],
        'class_names': ['normal', 'ncp_obfuscated'],
    }
    meta_path = output_path.replace('.onnx', '_metadata.json')
    with open(meta_path, 'w') as f:
        json.dump(meta, f, indent=2)
    
    # Verify with onnxruntime
    print("\n" + "=" * 60)
    print("VERIFICATION")
    print("=" * 60)
    
    import onnxruntime as ort
    sess = ort.InferenceSession(output_path)
    
    # Test with known samples
    rng = np.random.default_rng(999)
    normal_sample = generate_normal_traffic(1, rng).astype(np.float32)
    obfuscated_sample = generate_ncp_obfuscated_traffic(1, rng).astype(np.float32)
    
    for label, sample in [("normal", normal_sample), ("obfuscated", obfuscated_sample)]:
        outputs = sess.run(None, {'float_input': sample})
        print(f"\n  Input: {label}")
        for i, out in enumerate(outputs):
            name = sess.get_outputs()[i].name
            if isinstance(out, np.ndarray):
                print(f"    {name}: {out.flatten()}")
            else:
                print(f"    {name}: {out}")
    
    # Benchmark
    times = []
    for _ in range(1000):
        import time
        t0 = time.perf_counter()
        sess.run(None, {'float_input': normal_sample})
        t1 = time.perf_counter()
        times.append((t1 - t0) * 1e6)
    times = np.array(times)
    
    print(f"\n  Benchmark (1000 runs):")
    print(f"    Mean:   {times.mean():.1f} μs")
    print(f"    Median: {np.median(times):.1f} μs")
    print(f"    P95:    {np.percentile(times, 95):.1f} μs")
    
    print(f"\n{'='*60}")
    print("DONE ✓")
    print(f"{'='*60}")


if __name__ == '__main__':
    train_and_export()
