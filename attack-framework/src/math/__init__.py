"""
Mathematical Core — высшая математика для сетевого трафика.

Модули:
- fractal: Фрактальная генерация трафика (Hurst exponent, fGn)
- chaotic: Хаотический embedding (Lorenz, CSS)
- ergodic: Эргодический shaping (Birkhoff theorem)
- topological: Топологический морфинг (TDA, Wasserstein)
- tropical: Tropical geometry (piecewise-linear)
- padic: p-adic analysis (ultrametric)
- cluster: Cluster algebras (mutations)
- mirror: Mirror symmetry (wall-crossing)
- anabelian: Anabelian reconstruction (π₁)
"""

from .base import MathTransform, MathContext
from .fractal import FractalTrafficGenerator
from .chaotic import ChaoticEmbedder
from .ergodic import ErgodicShaper
from .topological import TopologicalMorpher
from .tropical import TropicalGeometry
from .padic import PadicAnalysis
from .cluster import ClusterAlgebra
from .mirror import MirrorSymmetry
from .anabelian import AnabelianReconstruction

__all__ = [
    "MathTransform",
    "MathContext",
    "FractalTrafficGenerator",
    "ChaoticEmbedder",
    "ErgodicShaper",
    "TopologicalMorpher",
    "TropicalGeometry",
    "PadicAnalysis",
    "ClusterAlgebra",
    "MirrorSymmetry",
    "AnabelianReconstruction",
]
