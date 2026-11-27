"""
C++ Math Backend — Python wrapper for C++ math modules via ctypes.

This module provides high-performance C++ implementations of all 9 mathematical
modules, exposed through ctypes for use by the Python orchestration layer.

Usage:
    from src.math.cpp_backend import CppMathBackend
    
    backend = CppMathBackend("libncp_math.so")
    result = backend.fractal_generate(1000, hurst=0.75)
"""

import ctypes
import numpy as np
from pathlib import Path
from typing import Optional, List, Tuple, Dict, Any


class CppMathBackend:
    """
    Python wrapper for C++ math modules.
    
    All functions call compiled C++ code through ctypes for maximum performance.
    """
    
    def __init__(self, lib_path: Optional[str] = None):
        """
        Initialize the C++ backend.
        
        Args:
            lib_path: Path to libncp_math.so. If None, searches standard locations.
        """
        if lib_path is None:
            # Search in common locations
            search_paths = [
                Path(__file__).parent / "libncp_math.so",
                Path(__file__).parent.parent.parent / "dynam-src/src/core/libncp_math.so",
                Path("/home/user/dynam-src/src/core/libncp_math.so"),
            ]
            for p in search_paths:
                if p.exists():
                    lib_path = str(p)
                    break
        
        if lib_path is None:
            raise FileNotFoundError(
                "libncp_math.so not found. Compile it first:\n"
                "  cd dynam-src/src/core && g++ -std=c++17 -O2 -fPIC -shared "
                "-I include -o libncp_math.so src/ncp_math_c_api.cpp -lm"
            )
        
        self.lib = ctypes.CDLL(lib_path)
        self._setup_signatures()
    
    def _setup_signatures(self):
        """Set up ctypes function signatures for type safety."""
        
        # ─── FRACTAL ──────────────────────────────────────────────
        self.lib.ncp_fractal_generate.restype = ctypes.c_int
        self.lib.ncp_fractal_generate.argtypes = [
            ctypes.POINTER(ctypes.c_double),  # output
            ctypes.c_int,                      # length
            ctypes.c_double,                   # hurst
            ctypes.c_uint32,                   # seed
        ]
        
        self.lib.ncp_fractal_compute_hurst.restype = ctypes.c_double
        self.lib.ncp_fractal_compute_hurst.argtypes = [
            ctypes.POINTER(ctypes.c_double),  # data
            ctypes.c_int,                      # length
        ]
        
        self.lib.ncp_fractal_transform.restype = ctypes.c_int
        self.lib.ncp_fractal_transform.argtypes = [
            ctypes.POINTER(ctypes.c_double),  # input
            ctypes.POINTER(ctypes.c_double),  # output
            ctypes.c_int,                      # length
            ctypes.c_double,                   # target_hurst
        ]
        
        # ─── CHAOTIC ──────────────────────────────────────────────
        self.lib.ncp_chaotic_transform.restype = ctypes.c_int
        self.lib.ncp_chaotic_transform.argtypes = [
            ctypes.POINTER(ctypes.c_double),  # input
            ctypes.POINTER(ctypes.c_double),  # output
            ctypes.c_int,                      # length
            ctypes.c_double,                   # epsilon
        ]
        
        self.lib.ncp_chaotic_trajectory.restype = ctypes.c_int
        self.lib.ncp_chaotic_trajectory.argtypes = [
            ctypes.POINTER(ctypes.c_double),  # output_x
            ctypes.POINTER(ctypes.c_double),  # output_y
            ctypes.POINTER(ctypes.c_double),  # output_z
            ctypes.c_int,                      # length
            ctypes.c_double,                   # sigma
            ctypes.c_double,                   # rho
            ctypes.c_double,                   # beta
        ]
        
        self.lib.ncp_chaotic_lyapunov.restype = ctypes.c_double
        self.lib.ncp_chaotic_lyapunov.argtypes = [
            ctypes.POINTER(ctypes.c_double),  # data
            ctypes.c_int,                      # length
        ]
        
        # ─── ERGODIC ──────────────────────────────────────────────
        self.lib.ncp_ergodic_arnold.restype = ctypes.c_int
        self.lib.ncp_ergodic_arnold.argtypes = [
            ctypes.POINTER(ctypes.c_double), ctypes.POINTER(ctypes.c_double),
            ctypes.c_int, ctypes.c_int,
        ]
        
        self.lib.ncp_ergodic_convergence.restype = ctypes.c_double
        self.lib.ncp_ergodic_convergence.argtypes = [
            ctypes.POINTER(ctypes.c_double), ctypes.c_int,
        ]
        
        self.lib.ncp_ergodic_guarantee.restype = ctypes.c_double
        self.lib.ncp_ergodic_guarantee.argtypes = [
            ctypes.POINTER(ctypes.c_double), ctypes.c_int,
        ]
        
        # ─── TOPOLOGICAL ──────────────────────────────────────────
        self.lib.ncp_topo_persistence.restype = ctypes.c_int
        self.lib.ncp_topo_persistence.argtypes = [
            ctypes.POINTER(ctypes.c_double),  # data
            ctypes.c_int,                      # length
            ctypes.POINTER(ctypes.c_double),  # births
            ctypes.POINTER(ctypes.c_double),  # deaths
            ctypes.c_int,                      # max_pairs
        ]
        
        self.lib.ncp_topo_wasserstein.restype = ctypes.c_double
        self.lib.ncp_topo_wasserstein.argtypes = [
            ctypes.POINTER(ctypes.c_double), ctypes.POINTER(ctypes.c_double), ctypes.c_int,
            ctypes.POINTER(ctypes.c_double), ctypes.POINTER(ctypes.c_double), ctypes.c_int,
        ]
        
        # ─── TROPICAL ─────────────────────────────────────────────
        self.lib.ncp_tropical_add.restype = ctypes.c_double
        self.lib.ncp_tropical_add.argtypes = [ctypes.c_double, ctypes.c_double]
        
        self.lib.ncp_tropical_multiply.restype = ctypes.c_double
        self.lib.ncp_tropical_multiply.argtypes = [ctypes.c_double, ctypes.c_double]
        
        # ─── P-ADIC ──────────────────────────────────────────────
        self.lib.ncp_padic_valuation.restype = ctypes.c_int
        self.lib.ncp_padic_valuation.argtypes = [ctypes.c_longlong, ctypes.c_int]
        
        self.lib.ncp_padic_distance.restype = ctypes.c_double
        self.lib.ncp_padic_distance.argtypes = [ctypes.c_longlong, ctypes.c_longlong, ctypes.c_int]
        
        self.lib.ncp_padic_cluster.restype = ctypes.c_int
        self.lib.ncp_padic_cluster.argtypes = [
            ctypes.POINTER(ctypes.c_double), ctypes.c_int,
            ctypes.POINTER(ctypes.c_int), ctypes.c_double, ctypes.c_int,
        ]
        
        # ─── MIRROR ───────────────────────────────────────────────
        self.lib.ncp_mirror_morph.restype = ctypes.c_int
        self.lib.ncp_mirror_morph.argtypes = [
            ctypes.POINTER(ctypes.c_double), ctypes.POINTER(ctypes.c_double), ctypes.c_int,
        ]
        
        self.lib.ncp_mirror_stability.restype = ctypes.c_int
        self.lib.ncp_mirror_stability.argtypes = [
            ctypes.c_double, ctypes.c_double, ctypes.c_double,
        ]
        
        # ─── SELF-TEST ────────────────────────────────────────────
        self.lib.ncp_math_self_test.restype = ctypes.c_int
    
    # ═══════════════════════════════════════════════════════════════
    # HIGH-LEVEL API
    # ═══════════════════════════════════════════════════════════════
    
    def self_test(self) -> bool:
        """Run C++ self-test for all modules."""
        return bool(self.lib.ncp_math_self_test())
    
    # ─── Fractal ──────────────────────────────────────────────────
    
    def fractal_generate(self, length: int, hurst: float = 0.75, seed: int = 0) -> np.ndarray:
        """Generate fractional Gaussian noise (C++ accelerated)."""
        output = np.zeros(length, dtype=np.float64)
        ret = self.lib.ncp_fractal_generate(
            output.ctypes.data_as(ctypes.POINTER(ctypes.c_double)),
            length, hurst, seed
        )
        if ret != 0:
            raise RuntimeError(f"Fractal generation failed (code {ret})")
        return output
    
    def fractal_hurst(self, data: np.ndarray) -> float:
        """Compute Hurst exponent (C++ accelerated)."""
        data = np.ascontiguousarray(data, dtype=np.float64)
        return self.lib.ncp_fractal_compute_hurst(
            data.ctypes.data_as(ctypes.POINTER(ctypes.c_double)),
            len(data)
        )
    
    def fractal_transform(self, data: np.ndarray, target_hurst: float = 0.75) -> np.ndarray:
        """Apply fractal transformation (C++ accelerated)."""
        data = np.ascontiguousarray(data, dtype=np.float64)
        output = np.zeros_like(data)
        ret = self.lib.ncp_fractal_transform(
            data.ctypes.data_as(ctypes.POINTER(ctypes.c_double)),
            output.ctypes.data_as(ctypes.POINTER(ctypes.c_double)),
            len(data), target_hurst
        )
        if ret != 0:
            raise RuntimeError(f"Fractal transform failed (code {ret})")
        return output
    
    # ─── Chaotic ──────────────────────────────────────────────────
    
    def chaotic_transform(self, data: np.ndarray, epsilon: float = 0.01) -> np.ndarray:
        """Apply chaotic embedding (C++ accelerated)."""
        data = np.ascontiguousarray(data, dtype=np.float64)
        output = np.zeros_like(data)
        ret = self.lib.ncp_chaotic_transform(
            data.ctypes.data_as(ctypes.POINTER(ctypes.c_double)),
            output.ctypes.data_as(ctypes.POINTER(ctypes.c_double)),
            len(data), epsilon
        )
        if ret != 0:
            raise RuntimeError(f"Chaotic transform failed (code {ret})")
        return output
    
    def chaotic_lyapunov(self, data: np.ndarray) -> float:
        """Compute largest Lyapunov exponent (C++ accelerated)."""
        data = np.ascontiguousarray(data, dtype=np.float64)
        return self.lib.ncp_chaotic_lyapunov(
            data.ctypes.data_as(ctypes.POINTER(ctypes.c_double)),
            len(data)
        )
    
    # ─── Ergodic ──────────────────────────────────────────────────
    
    def ergodic_arnold(self, data: np.ndarray, iterations: int = 100) -> np.ndarray:
        """Apply Arnold cat map (C++ accelerated)."""
        data = np.ascontiguousarray(data, dtype=np.float64)
        output = np.zeros_like(data)
        self.lib.ncp_ergodic_arnold(
            data.ctypes.data_as(ctypes.POINTER(ctypes.c_double)),
            output.ctypes.data_as(ctypes.POINTER(ctypes.c_double)),
            len(data), iterations
        )
        return output
    
    def ergodic_guarantee(self, data: np.ndarray) -> float:
        """Compute ergodic stealth guarantee (C++ accelerated)."""
        data = np.ascontiguousarray(data, dtype=np.float64)
        return self.lib.ncp_ergodic_guarantee(
            data.ctypes.data_as(ctypes.POINTER(ctypes.c_double)),
            len(data)
        )
    
    # ─── Topological ──────────────────────────────────────────────
    
    def topo_persistence(self, data: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """Compute persistence diagram (C++ accelerated)."""
        data = np.ascontiguousarray(data, dtype=np.float64)
        n = len(data)
        births = np.zeros(n, dtype=np.float64)
        deaths = np.zeros(n, dtype=np.float64)
        
        num_pairs = self.lib.ncp_topo_persistence(
            data.ctypes.data_as(ctypes.POINTER(ctypes.c_double)),
            n,
            births.ctypes.data_as(ctypes.POINTER(ctypes.c_double)),
            deaths.ctypes.data_as(ctypes.POINTER(ctypes.c_double)),
            n
        )
        return births[:num_pairs], deaths[:num_pairs]
    
    def topo_wasserstein(self, births1: np.ndarray, deaths1: np.ndarray,
                          births2: np.ndarray, deaths2: np.ndarray) -> float:
        """Compute Wasserstein distance (C++ accelerated)."""
        return self.lib.ncp_topo_wasserstein(
            np.ascontiguousarray(births1, dtype=np.float64).ctypes.data_as(ctypes.POINTER(ctypes.c_double)),
            np.ascontiguousarray(deaths1, dtype=np.float64).ctypes.data_as(ctypes.POINTER(ctypes.c_double)),
            len(births1),
            np.ascontiguousarray(births2, dtype=np.float64).ctypes.data_as(ctypes.POINTER(ctypes.c_double)),
            np.ascontiguousarray(deaths2, dtype=np.float64).ctypes.data_as(ctypes.POINTER(ctypes.c_double)),
            len(births2),
        )
    
    # ─── Tropical ─────────────────────────────────────────────────
    
    def tropical_add(self, a: float, b: float) -> float:
        """Tropical addition: min(a, b)."""
        return self.lib.ncp_tropical_add(a, b)
    
    def tropical_multiply(self, a: float, b: float) -> float:
        """Tropical multiplication: a + b."""
        return self.lib.ncp_tropical_multiply(a, b)
    
    # ─── P-adic ───────────────────────────────────────────────────
    
    def padic_valuation(self, x: int, p: int = 2) -> int:
        """Compute p-adic valuation."""
        return self.lib.ncp_padic_valuation(x, p)
    
    def padic_distance(self, x: int, y: int, p: int = 2) -> float:
        """Compute p-adic distance."""
        return self.lib.ncp_padic_distance(x, y, p)
    
    def padic_cluster(self, data: np.ndarray, threshold: float = 0.5, p: int = 2) -> np.ndarray:
        """Ultrametric clustering (C++ accelerated)."""
        data = np.ascontiguousarray(data, dtype=np.float64)
        labels = np.zeros(len(data), dtype=np.int32)
        num_clusters = self.lib.ncp_padic_cluster(
            data.ctypes.data_as(ctypes.POINTER(ctypes.c_double)),
            len(data),
            labels.ctypes.data_as(ctypes.POINTER(ctypes.c_int)),
            threshold, p
        )
        return labels
    
    # ─── Mirror ───────────────────────────────────────────────────
    
    def mirror_morph(self, data: np.ndarray) -> np.ndarray:
        """Apply mirror morph A-side → B-side (C++ accelerated)."""
        data = np.ascontiguousarray(data, dtype=np.float64)
        output = np.zeros_like(data)
        self.lib.ncp_mirror_morph(
            data.ctypes.data_as(ctypes.POINTER(ctypes.c_double)),
            output.ctypes.data_as(ctypes.POINTER(ctypes.c_double)),
            len(data)
        )
        return output
    
    def mirror_stability(self, packet_size: float, arrival_rate: float, entropy: float) -> int:
        """Analyze traffic stability (C++ accelerated)."""
        return self.lib.ncp_mirror_stability(packet_size, arrival_rate, entropy)


# ─── Convenience singleton ──────────────────────────────────────────────

_backend: Optional[CppMathBackend] = None

def get_backend() -> CppMathBackend:
    """Get or create the C++ backend singleton."""
    global _backend
    if _backend is None:
        _backend = CppMathBackend()
    return _backend
