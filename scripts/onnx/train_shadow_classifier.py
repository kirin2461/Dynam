#!/usr/bin/env python3
"""
Phase 3a: Train LightGBM shadow classifier for Dynam/NCP AdversaryTester.

Generates a synthetic dataset mimicking normal vs NCP-obfuscated traffic,
trains a binary LightGBM classifier, and exports to ONNX format.

Usage:
    python train_shadow_classifier.py [--output models/shadow_flow_classifier.onnx]

Features (10 metadata, zero-payload):
    0: size_mean       — mean packet size (bytes)
    1: size_cv         — coefficient of variation (std/mean)
    2: frac_small      — fraction of packets <= 128 bytes
    3: frac_large      — fraction of packets >= 1200 bytes
    4: error_rate      — connection errors / total attempts
    5: timing_cov      — coefficient of variation of inter-arrival times
    6: burst_anomaly   — burst pattern anomaly score [0,1]
    7: ks_distance     — KS distance vs reference browsing profile
    8: upload_ratio    — upload bytes / total bytes
    9: burst_rate      — bursts per second
"""

import argparse
import os
import sys
import numpy as np
import lightgbm as lgb
from skl2onnx import convert_sklearn
from skl2onnx.common.data_types import FloatTensorType
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, roc_auc_score, f1_score
import onnx
import json


# =============================================================================
# Synthetic Dataset Generation
# =============================================================================

def generate_normal_traffic(n_samples: int, rng: np.random.Generator) -> np.ndarray:
    """
    Generate features for normal (Chrome-like) browsing traffic.
    Based on typical Chrome HTTPS browsing patterns.
    """
    data = np.zeros((n_samples, 10), dtype=np.float32)
    
    # size_mean: normal browsing has varied sizes, mean ~400-800 bytes
    data[:, 0] = rng.normal(600, 200, n_samples).clip(100, 1460)
    
    # size_cv: high variance in normal traffic (ACKs + content)
    data[:, 1] = rng.normal(0.8, 0.3, n_samples).clip(0.1, 3.0)
    
    # frac_small: ~30% small packets (ACKs, small requests)
    data[:, 2] = rng.normal(0.30, 0.10, n_samples).clip(0.05, 0.70)
    
    # frac_large: ~30% large packets (content)
    data[:, 3] = rng.normal(0.30, 0.12, n_samples).clip(0.05, 0.70)
    
    # error_rate: low for normal traffic
    data[:, 4] = rng.exponential(0.02, n_samples).clip(0.0, 0.15)
    
    # timing_cov: high (bursty human browsing)
    data[:, 5] = rng.normal(2.0, 0.8, n_samples).clip(0.3, 5.0)
    
    # burst_anomaly: low for normal
    data[:, 6] = rng.beta(2, 5, n_samples).clip(0.0, 1.0)
    
    # ks_distance: low (matches reference profile)
    data[:, 7] = rng.exponential(0.08, n_samples).clip(0.0, 0.5)
    
    # upload_ratio: ~15% for browsing
    data[:, 8] = rng.normal(0.15, 0.05, n_samples).clip(0.02, 0.40)
    
    # burst_rate: ~0.5 bursts/sec for casual browsing
    data[:, 9] = rng.exponential(0.5, n_samples).clip(0.05, 3.0)
    
    return data


def generate_ncp_obfuscated_traffic(n_samples: int, rng: np.random.Generator) -> np.ndarray:
    """
    Generate features for NCP-obfuscated traffic.
    
    NCP applies:
    - Adversarial padding (changes size distribution)
    - Flow shaping (normalizes sizes to reference profile)
    - Behavioral cloak (adds artificial timing)
    - Mimicry (wraps in TLS/HTTP patterns)
    
    Key differences from normal:
    - Size distribution is more uniform (quantile shaping)
    - Timing is more regular (flow shaping reduces CoV)
    - KS distance is lower (by design — it targets reference profile)
    - Upload ratio may be shifted (dummy packet injection)
    - Burst patterns are synthetic (state machine, not human)
    """
    data = np.zeros((n_samples, 10), dtype=np.float32)
    
    # size_mean: NCP normalizes to target sizes (64,128,256,512,1024,1460)
    # Mean tends toward 400-600 but with LESS variance
    data[:, 0] = rng.normal(500, 120, n_samples).clip(64, 1460)
    
    # size_cv: LOWER than normal (quantile shaping reduces variance)
    data[:, 1] = rng.normal(0.45, 0.15, n_samples).clip(0.1, 1.5)
    
    # frac_small: higher (padding adds small packets to hit target sizes)
    data[:, 2] = rng.normal(0.38, 0.08, n_samples).clip(0.10, 0.65)
    
    # frac_large: similar but slightly lower (more uniform distribution)
    data[:, 3] = rng.normal(0.25, 0.08, n_samples).clip(0.05, 0.55)
    
    # error_rate: slightly higher (some strategies fail, retransmits)
    data[:, 4] = rng.exponential(0.05, n_samples).clip(0.0, 0.25)
    
    # timing_cov: LOWER (flow shaping regularizes timing)
    # This is a KEY discriminator — normal traffic has CoV~2, NCP has CoV~1
    data[:, 5] = rng.normal(1.2, 0.5, n_samples).clip(0.2, 3.5)
    
    # burst_anomaly: slightly higher (synthetic bursts differ from human)
    data[:, 6] = rng.beta(3, 4, n_samples).clip(0.0, 1.0)
    
    # ks_distance: very low (NCP targets KS=0 via quantile shaping)
    # But the W1 distance may be non-zero — KS is "too perfect"
    data[:, 7] = rng.exponential(0.04, n_samples).clip(0.0, 0.25)
    
    # upload_ratio: shifted higher (dummy packets, adversarial padding)
    data[:, 8] = rng.normal(0.22, 0.08, n_samples).clip(0.05, 0.50)
    
    # burst_rate: more regular (state machine, not human randomness)
    data[:, 9] = rng.normal(0.8, 0.2, n_samples).clip(0.1, 2.5)
    
    return data


def generate_dataset(n_normal: int = 5000, n_obfuscated: int = 5000,
                     seed: int = 42):
    """Generate full training dataset."""
    rng = np.random.default_rng(seed)
    
    normal = generate_normal_traffic(n_normal, rng)
    obfuscated = generate_ncp_obfuscated_traffic(n_obfuscated, rng)
    
    X = np.vstack([normal, obfuscated])
    y = np.concatenate([np.zeros(n_normal, dtype=np.float32),
                        np.ones(n_obfuscated, dtype=np.float32)])
    
    # Shuffle
    perm = rng.permutation(len(y))
    return X[perm], y[perm]


# =============================================================================
# Training
# =============================================================================

FEATURE_NAMES = [
    "size_mean", "size_cv", "frac_small", "frac_large",
    "error_rate", "timing_cov", "burst_anomaly", "ks_distance",
    "upload_ratio", "burst_rate"
]


def train_model(X_train, y_train, X_val, y_val):
    """Train LightGBM binary classifier."""
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
        'n_jobs': -1,
        'seed': 42,
    }
    
    model = lgb.train(
        params,
        train_data,
        num_boost_round=200,
        valid_sets=[val_data],
        callbacks=[lgb.early_stopping(20), lgb.log_evaluation(50)],
    )
    
    return model


def evaluate_model(model, X_test, y_test):
    """Evaluate model and print metrics."""
    y_prob = model.predict(X_test)
    y_pred = (y_prob > 0.5).astype(int)
    
    print("\n" + "=" * 60)
    print("MODEL EVALUATION")
    print("=" * 60)
    print(f"ROC-AUC: {roc_auc_score(y_test, y_prob):.4f}")
    print(f"F1 Score: {f1_score(y_test, y_pred):.4f}")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred,
                                target_names=["Normal", "NCP-Obfuscated"]))
    
    # Feature importance
    importance = model.feature_importance(importance_type='gain')
    print("\nFeature Importance (gain):")
    for name, imp in sorted(zip(FEATURE_NAMES, importance),
                            key=lambda x: -x[1]):
        print(f"  {name:20s}: {imp:.1f}")
    
    return y_pred, y_prob


# =============================================================================
# ONNX Export
# =============================================================================

def export_to_onnx(model, output_path: str):
    """
    Export LightGBM model to ONNX format.
    
    Uses onnxmltools which natively supports LightGBM.
    """
    import onnxmltools
    from onnxmltools.convert import convert_lightgbm
    from onnxmltools.convert.common.data_types import FloatTensorType as LGFMFloatTensorType
    
    # Define input type (10 float features, dynamic batch size)
    initial_type = [('float_input', LGFMFloatTensorType([None, 10]))]
    
    # Convert directly using onnxmltools (native LightGBM support)
    onnx_model = convert_lightgbm(
        model,
        initial_types=initial_type,
        target_opset=12,
    )
    
    # Save
    os.makedirs(os.path.dirname(output_path) or '.', exist_ok=True)
    with open(output_path, 'wb') as f:
        f.write(onnx_model.SerializeToString())
    
    # Verify
    model_proto = onnx.load(output_path)
    onnx.checker.check_model(model_proto)
    
    model_size_kb = os.path.getsize(output_path) / 1024
    print(f"\nONNX model saved: {output_path}")
    print(f"Model size: {model_size_kb:.1f} KB")
    print(f"Inputs: {[inp.name for inp in model_proto.graph.input]}")
    print(f"Outputs: {[out.name for out in model_proto.graph.output]}")
    
    return output_path


# =============================================================================
# Main
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Train shadow classifier for Dynam/NCP AdversaryTester")
    parser.add_argument('--output', default='models/shadow_flow_classifier.onnx',
                        help='Output ONNX model path')
    parser.add_argument('--n-samples', type=int, default=10000,
                        help='Total samples (50/50 normal/obfuscated)')
    parser.add_argument('--seed', type=int, default=42,
                        help='Random seed')
    args = parser.parse_args()
    
    n_per_class = args.n_samples // 2
    
    print("=" * 60)
    print("PHASE 3a: Shadow Classifier Training Pipeline")
    print("=" * 60)
    print(f"Samples: {args.n_samples} ({n_per_class} normal + {n_per_class} obfuscated)")
    print(f"Features: {len(FEATURE_NAMES)}")
    print(f"Output: {args.output}")
    
    # Generate dataset
    print("\nGenerating synthetic dataset...")
    X, y = generate_dataset(n_per_class, n_per_class, seed=args.seed)
    print(f"Dataset shape: {X.shape}")
    print(f"Class distribution: normal={int((y==0).sum())}, "
          f"obfuscated={int((y==1).sum())}")
    
    # Split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=args.seed, stratify=y)
    X_train, X_val, y_train, y_val = train_test_split(
        X_train, y_train, test_size=0.15, random_state=args.seed, stratify=y_train)
    
    print(f"Train: {len(X_train)}, Val: {len(X_val)}, Test: {len(X_test)}")
    
    # Train
    print("\nTraining LightGBM...")
    model = train_model(X_train, y_train, X_val, y_val)
    
    # Evaluate
    evaluate_model(model, X_test, y_test)
    
    # Export to ONNX
    export_to_onnx(model, args.output)
    
    # Save dataset metadata
    metadata = {
        'features': FEATURE_NAMES,
        'n_features': len(FEATURE_NAMES),
        'n_train': len(X_train),
        'n_val': len(X_val),
        'n_test': len(X_test),
        'model_type': 'lightgbm_binary',
        'description': 'Normal vs NCP-obfuscated traffic classifier',
        'input_shape': [None, 10],
        'input_dtype': 'float32',
    }
    meta_path = args.output.replace('.onnx', '_metadata.json')
    with open(meta_path, 'w') as f:
        json.dump(metadata, f, indent=2)
    print(f"\nMetadata saved: {meta_path}")
    
    print("\n" + "=" * 60)
    print("DONE")
    print("=" * 60)


if __name__ == '__main__':
    main()
