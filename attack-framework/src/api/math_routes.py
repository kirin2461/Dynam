"""
Math API routes — REST API для математических модулей.

Endpoints для всех 9 математических модулей:
- Fractal Traffic Generation
- Chaotic Embedding
- Ergodic Shaping
- Topological Morphing
- Tropical Geometry
- p-adic Analysis
- Cluster Algebra
- Mirror Symmetry
- Anabelian Reconstruction

Плюс Math Director и Pipeline management.
"""

from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field
from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
import numpy as np

from ..math.fractal import FractalTrafficGenerator, FractalConfig
from ..math.chaotic import ChaoticEmbedder, ChaoticConfig
from ..math.ergodic import ErgodicShaper, ErgodicConfig
from ..math.topological import TopologicalMorpher, TopologicalConfig
from ..math.tropical import TropicalGeometry, TropicalConfig
from ..math.padic import PadicAnalysis, PadicConfig
from ..math.cluster import ClusterAlgebra, ClusterAlgebraConfig
from ..math.mirror import MirrorSymmetry, MirrorConfig
from ..math.anabelian import AnabelianReconstruction, AnabelianConfig
from ..math.base import MathContext
from ..math.orchestration.math_director import MathDirector, DirectorConfig
from ..math.orchestration.pipeline import PipelineManager, MathPipeline


# ─── Pydantic Models ────────────────────────────────────────────────────

class TransformRequest(BaseModel):
    data: List[float] = Field(..., description="Input data as list of floats")
    parameters: Dict[str, Any] = Field(default_factory=dict, description="Transform parameters")
    context: Dict[str, Any] = Field(default_factory=dict, description="Math context")


class PipelineRequest(BaseModel):
    name: str
    description: str = ""
    steps: List[Dict[str, Any]] = Field(default_factory=list)


class DirectorRequest(BaseModel):
    data: List[float]
    dpi_fingerprint: Dict[str, Any] = Field(default_factory=dict)
    strategy: Optional[str] = None
    custom_transforms: Optional[List[str]] = None


# ─── Route Registration ─────────────────────────────────────────────────

def register_math_routes(app: FastAPI):
    """Register all math module routes."""
    
    # Инициализация трансформаций
    transforms = {
        "fractal": FractalTrafficGenerator(),
        "chaotic": ChaoticEmbedder(),
        "ergodic": ErgodicShaper(),
        "topological": TopologicalMorpher(),
        "tropical": TropicalGeometry(),
        "padic": PadicAnalysis(),
        "cluster": ClusterAlgebra(),
        "mirror": MirrorSymmetry(),
        "anabelian": AnabelianReconstruction(),
    }
    
    math_director = MathDirector()
    pipeline_manager = PipelineManager()
    
    # ═══════════════════════════════════════════════════════════════
    # FRACTAL TRAFFIC GENERATION
    # ═══════════════════════════════════════════════════════════════
    
    @app.post("/api/math/fractal/transform")
    async def fractal_transform(request: TransformRequest):
        """Применить фрактальную трансформацию."""
        data = np.array(request.data, dtype=np.float32)
        context = MathContext(target="api", parameters=request.parameters)
        
        result = transforms["fractal"].transform(data, context)
        metrics = transforms["fractal"].compute_metrics(data, result)
        
        return {
            "result": result.tolist(),
            "metrics": metrics,
        }
    
    @app.post("/api/math/fractal/generate")
    async def fractal_generate(length: int = 1000, hurst: float = 0.75):
        """Сгенерировать фрактальный трафик."""
        generator = FractalTrafficGenerator(FractalConfig(hurst_target=hurst))
        result = generator.match_distribution(hurst, length)
        
        return {
            "generated_data": result["generated_data"].tolist(),
            "hurst_target": result["target_hurst"],
            "hurst_actual": result["actual_hurst"],
            "hurst_error": result["hurst_error"],
            "multifractal_width": result["multifractal_width"],
        }
    
    @app.get("/api/math/fractal/hurst")
    async def compute_hurst(data: str):
        """Вычислить Hurst exponent."""
        data_array = np.array([float(x) for x in data.split(",")])
        hurst = transforms["fractal"].compute_hurst(data_array)
        
        return {"hurst_exponent": hurst}
    
    # ═══════════════════════════════════════════════════════════════
    # CHAOTIC EMBEDDING
    # ═══════════════════════════════════════════════════════════════
    
    @app.post("/api/math/chaotic/transform")
    async def chaotic_transform(request: TransformRequest):
        """Применить хаотическую трансформацию."""
        data = np.array(request.data, dtype=np.float32)
        context = MathContext(target="api", parameters=request.parameters)
        
        result = transforms["chaotic"].transform(data, context)
        metrics = transforms["chaotic"].compute_metrics(data, result)
        
        return {
            "result": result.tolist(),
            "metrics": metrics,
        }
    
    @app.post("/api/math/chaotic/embed")
    async def chaotic_embed(data: List[int]):
        """Встроить данные в хаотическую последовательность."""
        data_array = np.array(data, dtype=np.uint8)
        context = MathContext(target="api")
        
        embedded = transforms["chaotic"].transform(data_array, context)
        
        return {"embedded_data": embedded.tolist()}
    
    @app.get("/api/math/chaotic/lyapunov")
    async def compute_lyapunov(data: str):
        """Вычислить показатели Ляпунова."""
        data_array = np.array([float(x) for x in data.split(",")])
        lyap = transforms["chaotic"].lyapunov_exponents(data_array)
        
        return {"lyapunov_exponents": lyap.tolist()}
    
    # ═══════════════════════════════════════════════════════════════
    # ERGODIC SHAPING
    # ═══════════════════════════════════════════════════════════════
    
    @app.post("/api/math/ergodic/transform")
    async def ergodic_transform(request: TransformRequest):
        """Применить эргодическую трансформацию."""
        data = np.array(request.data, dtype=np.float32)
        context = MathContext(target="api", parameters=request.parameters)
        
        result = transforms["ergodic"].transform(data, context)
        metrics = transforms["ergodic"].compute_metrics(data, result)
        
        return {
            "result": result.tolist(),
            "metrics": metrics,
        }
    
    @app.get("/api/math/ergodic/convergence")
    async def ergodic_convergence(data: str):
        """Вычислить скорость сходимости."""
        data_array = np.array([float(x) for x in data.split(",")])
        convergence = transforms["ergodic"].birkhoff_convergence(data_array)
        
        return {"convergence_rate": convergence}
    
    @app.get("/api/math/ergodic/guarantee")
    async def ergodic_guarantee(data: str):
        """Вычислить stealth guarantee."""
        data_array = np.array([float(x) for x in data.split(",")])
        guarantee = transforms["ergodic"].ergodic_guarantee(data_array)
        
        return {"stealth_guarantee": guarantee}
    
    # ═══════════════════════════════════════════════════════════════
    # TOPOLOGICAL MORPHING
    # ═══════════════════════════════════════════════════════════════
    
    @app.post("/api/math/topological/transform")
    async def topological_transform(request: TransformRequest):
        """Применить топологическую трансформацию."""
        data = np.array(request.data, dtype=np.float32)
        context = MathContext(target="api", parameters=request.parameters)
        
        result = transforms["topological"].transform(data, context)
        metrics = transforms["topological"].compute_metrics(data, result)
        
        return {
            "result": result.tolist(),
            "metrics": metrics,
        }
    
    @app.get("/api/math/topological/diagram")
    async def topological_diagram(data: str):
        """Вычислить persistence diagram."""
        data_array = np.array([float(x) for x in data.split(",")])
        diagram = transforms["topological"].persistence_diagram(data_array)
        
        return {"persistence_diagram": diagram}
    
    @app.get("/api/math/topological/wasserstein")
    async def topological_wasserstein(data1: str, data2: str):
        """Вычислить Wasserstein distance между diagrams."""
        data1_array = np.array([float(x) for x in data1.split(",")])
        data2_array = np.array([float(x) for x in data2.split(",")])
        
        diagram1 = transforms["topological"].persistence_diagram(data1_array)
        diagram2 = transforms["topological"].persistence_diagram(data2_array)
        
        distance = transforms["topological"].wasserstein_distance(diagram1, diagram2)
        
        return {"wasserstein_distance": distance}
    
    # ═══════════════════════════════════════════════════════════════
    # TROPICAL GEOMETRY
    # ═══════════════════════════════════════════════════════════════
    
    @app.post("/api/math/tropical/transform")
    async def tropical_transform(request: TransformRequest):
        """Применить тропическую трансформацию."""
        data = np.array(request.data, dtype=np.float32)
        context = MathContext(target="api", parameters=request.parameters)
        
        result = transforms["tropical"].transform(data, context)
        metrics = transforms["tropical"].compute_metrics(data, result)
        
        return {
            "result": result.tolist(),
            "metrics": metrics,
        }
    
    @app.post("/api/math/tropical/optimize")
    async def tropical_optimize(c: List[float], A: List[List[float]], b: List[float]):
        """Решить тропическую задачу линейного программирования."""
        c_array = np.array(c, dtype=np.float32)
        A_array = np.array(A, dtype=np.float32)
        b_array = np.array(b, dtype=np.float32)
        
        result = transforms["tropical"].tropical_linear_program(c_array, A_array, b_array)
        
        return result
    
    # ═══════════════════════════════════════════════════════════════
    # P-ADIC ANALYSIS
    # ═══════════════════════════════════════════════════════════════
    
    @app.post("/api/math/padic/transform")
    async def padic_transform(request: TransformRequest):
        """Применить p-адическую трансформацию."""
        data = np.array(request.data, dtype=np.float32)
        context = MathContext(target="api", parameters=request.parameters)
        
        result = transforms["padic"].transform(data, context)
        metrics = transforms["padic"].compute_metrics(data, result)
        
        return {
            "result": result.tolist(),
            "metrics": metrics,
        }
    
    @app.get("/api/math/padic/expansion")
    async def padic_expansion(x: float, p: int = 2):
        """Вычислить p-адическое разложение."""
        expansion = transforms["padic"].padic_expansion(x, p)
        
        return {"padic_expansion": expansion}
    
    @app.get("/api/math/padic/clustering")
    async def padic_clustering(data: str, threshold: float = 0.5):
        """Выполнить ультраметрическую кластеризацию."""
        data_array = np.array([float(x) for x in data.split(",")])
        clusters = transforms["padic"].ultrametric_clustering(data_array, threshold)
        
        return {"clusters": clusters}
    
    # ═══════════════════════════════════════════════════════════════
    # CLUSTER ALGEBRA
    # ═══════════════════════════════════════════════════════════════
    
    @app.post("/api/math/cluster/transform")
    async def cluster_transform(request: TransformRequest):
        """Применить cluster mutation."""
        data = np.array(request.data, dtype=np.float32)
        context = MathContext(target="api", parameters=request.parameters)
        
        result = transforms["cluster"].transform(data, context)
        metrics = transforms["cluster"].compute_metrics(data, result)
        
        return {
            "result": result.tolist(),
            "metrics": metrics,
        }
    
    @app.post("/api/math/cluster/mutate")
    async def cluster_mutate(protocol_features: Dict[str, float], target_protocol: str):
        """Выполнить протокольную мутацию."""
        result = transforms["cluster"].protocol_mutation(protocol_features, target_protocol)
        
        return {"mutated_features": result}
    
    @app.get("/api/math/cluster/classification")
    async def cluster_classification():
        """Классификация конечного типа."""
        dynkin_type = transforms["cluster"].finite_type_classification()
        
        return {"dynkin_type": dynkin_type}
    
    # ═══════════════════════════════════════════════════════════════
    # MIRROR SYMMETRY
    # ═══════════════════════════════════════════════════════════════
    
    @app.post("/api/math/mirror/transform")
    async def mirror_transform(request: TransformRequest):
        """Применить mirror трансформацию."""
        data = np.array(request.data, dtype=np.float32)
        context = MathContext(target="api", parameters=request.parameters)
        
        result = transforms["mirror"].transform(data, context)
        metrics = transforms["mirror"].compute_metrics(data, result)
        
        return {
            "result": result.tolist(),
            "metrics": metrics,
        }
    
    @app.post("/api/math/mirror/wall_crossing")
    async def mirror_wall_crossing(data: List[float], target_stability: str):
        """Переход через wall."""
        data_array = np.array(data, dtype=np.float32)
        
        from ..math.mirror import StabilityCondition
        target = StabilityCondition(target_stability)
        
        result = transforms["mirror"].cross_wall(data_array, target)
        
        return {"result": result.tolist()}
    
    @app.post("/api/math/mirror/stability")
    async def mirror_stability(traffic_features: Dict[str, float]):
        """Анализ stability traffic features."""
        result = transforms["mirror"].traffic_stability(traffic_features)
        
        return result
    
    # ═══════════════════════════════════════════════════════════════
    # ANABELIAN RECONSTRUCTION
    # ═══════════════════════════════════════════════════════════════
    
    @app.post("/api/math/anabelian/transform")
    async def anabelian_transform(request: TransformRequest):
        """Применить anabelian трансформацию."""
        data = np.array(request.data, dtype=np.float32)
        context = MathContext(target="api", parameters=request.parameters)
        
        result = transforms["anabelian"].transform(data, context)
        metrics = transforms["anabelian"].compute_metrics(data, result)
        
        return {
            "result": result.tolist(),
            "metrics": metrics,
        }
    
    @app.post("/api/math/anabelian/reconstruct")
    async def anabelian_reconstruct(traffic_samples: List[List[float]]):
        """Реконструкция network topology из трафика."""
        samples = [np.array(s, dtype=np.float32) for s in traffic_samples]
        
        topology = transforms["anabelian"].reconstruct_from_traffic(samples)
        
        return {
            "num_nodes": len(topology.nodes),
            "num_edges": len(topology.edges),
        }
    
    @app.post("/api/math/anabelian/stealth")
    async def anabelian_stealth(data: List[float]):
        """Анализ topology-based stealth."""
        data_array = np.array(data, dtype=np.float32)
        
        result = transforms["anabelian"].topology_stealth(data_array)
        
        return result
    
    # ═══════════════════════════════════════════════════════════════
    # MATH DIRECTOR
    # ═══════════════════════════════════════════════════════════════
    
    @app.post("/api/math/director/apply")
    async def director_apply(request: DirectorRequest):
        """Применить математические трансформации через Math Director."""
        data = np.array(request.data, dtype=np.float32)
        context = MathContext(target="api")
        
        # Выбираем стратегию
        if request.dpi_fingerprint:
            strategy = math_director.select_strategy(request.dpi_fingerprint)
        else:
            from ..math.orchestration.math_director import MathStrategy
            strategy = MathStrategy[request.strategy.upper()] if request.strategy else MathStrategy.STANDARD
        
        # Применяем трансформации
        result = await math_director.apply_transforms(
            data,
            context,
            strategy=strategy,
            custom_transforms=request.custom_transforms
        )
        
        # Проверяем stealth
        stealth_verification = math_director.verify_stealth(data, result)
        
        return {
            "result": result.tolist(),
            "strategy": strategy.value,
            "stealth_verification": stealth_verification,
            "stats": math_director.get_stats(),
        }
    
    @app.get("/api/math/director/strategy")
    async def director_strategy(dpi_fingerprint: str):
        """Выбор стратегии на основе DPI fingerprint."""
        import json
        fingerprint = json.loads(dpi_fingerprint)
        
        strategy = math_director.select_strategy(fingerprint)
        
        return {"selected_strategy": strategy.value}
    
    # ═══════════════════════════════════════════════════════════════
    # PIPELINE MANAGEMENT
    # ═══════════════════════════════════════════════════════════════
    
    @app.post("/api/math/pipeline/create")
    async def pipeline_create(request: PipelineRequest):
        """Создать новый пайплайн."""
        pipeline = pipeline_manager.create_pipeline(request.name, request.description)
        
        for step in request.steps:
            pipeline.add_step(
                step["transform_name"],
                step.get("parameters", {}),
                step.get("enabled", True)
            )
        
        return pipeline.to_dict()
    
    @app.post("/api/math/pipeline/execute")
    async def pipeline_execute(pipeline_name: str, data: List[float]):
        """Выполнить пайплайн."""
        data_array = np.array(data, dtype=np.float32)
        context = MathContext(target="api")
        
        result = pipeline_manager.execute_pipeline(
            pipeline_name,
            data_array,
            transforms,
            context
        )
        
        return {"result": result.tolist()}
    
    @app.get("/api/math/pipeline/list")
    async def pipeline_list():
        """Список всех пайплайнов."""
        return pipeline_manager.list_pipelines()
    
    @app.get("/api/math/pipeline/{name}")
    async def pipeline_get(name: str):
        """Получить пайплайн по имени."""
        pipeline = pipeline_manager.get_pipeline(name)
        if not pipeline:
            raise HTTPException(status_code=404, detail="Pipeline not found")
        return pipeline.to_dict()
    
    @app.delete("/api/math/pipeline/{name}")
    async def pipeline_delete(name: str):
        """Удалить пайплайн."""
        success = pipeline_manager.delete_pipeline(name)
        if not success:
            raise HTTPException(status_code=404, detail="Pipeline not found")
        return {"status": "deleted"}
    
    @app.post("/api/math/pipeline/{name}/export")
    async def pipeline_export(name: str):
        """Экспорт пайплайна в JSON."""
        try:
            json_str = pipeline_manager.export_pipeline(name)
            return {"pipeline_json": json_str}
        except ValueError as e:
            raise HTTPException(status_code=404, detail=str(e))
    
    @app.post("/api/math/pipeline/import")
    async def pipeline_import(json_str: str):
        """Импорт пайплайна из JSON."""
        try:
            pipeline = pipeline_manager.import_pipeline(json_str)
            return pipeline.to_dict()
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e))
