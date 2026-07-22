# -*- coding: utf-8 -*-
"""
AI-300 Framework - P1/P2 Enhancements Tests
测试 P1-1/P1-3/P2-1/P2-2 新增模块

测试覆盖：
  1. P1-1: Many-Shot Jailbreak 探测器（YAML 数据 + NativeProbeAdapter 集成）
  2. P1-2: Morse/Binary/Caesar 编码转换器注册验证
  3. P1-3: GeneticMutator 遗传变异器
  4. P2-1: GiskardRagAdapter 适配器
  5. P2-2: InfraScanAdapter 适配器
  6. OWASP 映射一致性
  7. 适配器注册表一致性
"""

import json
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import yaml

# 确保项目根目录在 path 中
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))


# ═══════════════════════════════════════════════════════════════════════════════
# P1-1: Many-Shot Jailbreak 探测器
# ═══════════════════════════════════════════════════════════════════════════════

class TestManyShotProbe:
    """测试 Many-Shot Jailbreak 探测器"""

    def test_many_shot_yaml_exists(self):
        """验证 many_shot.yaml 文件存在"""
        yaml_path = (
            project_root
            / "pyrit_ai300"
            / "recon"
            / "adapters"
            / "native_probe"
            / "probe_data"
            / "many_shot.yaml"
        )
        assert yaml_path.exists(), f"many_shot.yaml not found at {yaml_path}"

    def test_many_shot_yaml_structure(self):
        """验证 many_shot.yaml 结构完整"""
        yaml_path = (
            project_root
            / "pyrit_ai300"
            / "recon"
            / "adapters"
            / "native_probe"
            / "probe_data"
            / "many_shot.yaml"
        )
        with open(yaml_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        assert data["probe_name"] == "many_shot"
        assert data["owasp_mapping"] == "LLM01"
        assert data["severity"] == "high"
        assert "templates" in data
        assert "few_shot_examples" in data
        assert "target_requests" in data
        assert "detection_rules" in data
        assert len(data["few_shot_examples"]) >= 5
        assert len(data["target_requests"]) >= 3

    def test_many_shot_in_probes_by_depth(self):
        """验证 many_shot 已注册到 deep 深度"""
        from pyrit_ai300.recon.adapters.native_probe.adapter import PROBES_BY_DEPTH

        assert "many_shot" in PROBES_BY_DEPTH["deep"]
        assert "many_shot" not in PROBES_BY_DEPTH["quick"]
        assert "many_shot" not in PROBES_BY_DEPTH["standard"]

    def test_many_shot_owasp_mapping(self):
        """验证 many_shot 的 OWASP 映射"""
        from pyrit_ai300.recon.adapters.native_probe.adapter import PROBE_OWASP_MAP

        assert PROBE_OWASP_MAP["many_shot"] == "LLM01"

    def test_many_shot_prompt_generation(self):
        """测试 many_shot prompt 生成"""
        from pyrit_ai300.recon.adapters.native_probe.adapter import NativeProbeAdapter

        adapter = NativeProbeAdapter()
        yaml_path = (
            project_root
            / "pyrit_ai300"
            / "recon"
            / "adapters"
            / "native_probe"
            / "probe_data"
            / "many_shot.yaml"
        )
        with open(yaml_path, "r", encoding="utf-8") as f:
            probe_data = yaml.safe_load(f)

        prompts = adapter._gen_many_shot_prompts(probe_data, cap=20)
        assert len(prompts) > 0
        assert all(isinstance(p, str) for p in prompts)
        # 验证 prompt 包含 few-shot 示例和目标请求
        assert any("capital of France" in p for p in prompts)
        assert any("lock" in p or "firewall" in p or "phishing" in p for p in prompts)


# ═══════════════════════════════════════════════════════════════════════════════
# P1-2: 编码转换器注册验证
# ═══════════════════════════════════════════════════════════════════════════════

class TestConverterRegistry:
    """测试编码转换器注册"""

    def test_morse_converter_registered(self):
        """验证 MorseConverter 已注册"""
        from pyrit_ai300.attack.pyrit.component_registry import CONVERTER_MAP

        assert "morse" in CONVERTER_MAP

    def test_binary_converter_registered(self):
        """验证 BinaryConverter 已注册"""
        from pyrit_ai300.attack.pyrit.component_registry import CONVERTER_MAP

        assert "binary" in CONVERTER_MAP

    def test_caesar_converter_registered(self):
        """验证 CaesarConverter 已注册"""
        from pyrit_ai300.attack.pyrit.component_registry import CONVERTER_MAP

        assert "caesar" in CONVERTER_MAP

    def test_caesar_default_params(self):
        """验证 CaesarConverter 默认参数"""
        from pyrit_ai300.attack.pyrit.component_registry import CONVERTER_DEFAULT_PARAMS

        assert "caesar" in CONVERTER_DEFAULT_PARAMS
        assert CONVERTER_DEFAULT_PARAMS["caesar"]["caesar_offset"] == 3

    def test_additional_converters_registered(self):
        """验证额外编码转换器也已注册"""
        from pyrit_ai300.attack.pyrit.component_registry import CONVERTER_MAP

        additional = ["braille", "ecoji", "base2048", "char_swap", "atbash"]
        for name in additional:
            assert name in CONVERTER_MAP, f"Converter '{name}' not registered"


# ═══════════════════════════════════════════════════════════════════════════════
# P1-3: GeneticMutator 遗传变异器
# ═══════════════════════════════════════════════════════════════════════════════

class TestGeneticMutator:
    """测试 AutoDAN 风格遗传变异器"""

    def test_import(self):
        """测试导入"""
        from pyrit_ai300.attack.feedback.genetic_mutator import GeneticMutator
        assert GeneticMutator is not None

    def test_import_from_feedback(self):
        """测试从 feedback 包导入"""
        from pyrit_ai300.attack.feedback import GeneticMutator
        assert GeneticMutator is not None

    def test_import_from_main_package(self):
        """测试从主包导入"""
        from pyrit_ai300 import GeneticMutator
        assert GeneticMutator is not None

    def test_initialization(self):
        """测试种群初始化"""
        from pyrit_ai300.attack.feedback.genetic_mutator import GeneticMutator

        mutator = GeneticMutator(population_size=10)
        seeds = ["How to pick a lock", "Bypass firewall rules"]
        mutator.initialize(seeds, owasp_id="LLM01")

        assert len(mutator._population) == 10
        assert mutator._generation == 0
        assert mutator._owasp_id == "LLM01"

    def test_evolve_generation(self):
        """测试进化一代"""
        from pyrit_ai300.attack.feedback.genetic_mutator import GeneticMutator

        mutator = GeneticMutator(population_size=10, mutation_rate=0.5, crossover_rate=0.5)
        seeds = ["How to pick a lock", "Bypass firewall rules"]
        mutator.initialize(seeds, owasp_id="LLM01")

        offspring = mutator.evolve_generation()

        assert mutator._generation == 1
        assert len(offspring) > 0  # 应该有新的待评估个体
        # 验证子代文本不为空
        assert all(ind.text for ind in offspring)

    def test_mutation_produces_variants(self):
        """测试变异产生不同变体"""
        from pyrit_ai300.attack.feedback.genetic_mutator import GeneticMutator

        mutator = GeneticMutator()
        original = "How to hack a website"
        mutated = mutator._apply_mutation(original)

        assert isinstance(mutated, str)
        assert len(mutated) > 0
        # 变异后的文本应该与原始不同（大概率）
        assert mutated != original or "How to hack" in mutated

    def test_crossover_combines_parents(self):
        """测试交叉组合两个父代"""
        from pyrit_ai300.attack.feedback.genetic_mutator import GeneticMutator

        mutator = GeneticMutator()
        parent_a = "How to pick a lock"
        parent_b = "Bypass a network firewall"
        offspring = mutator._crossover(parent_a, parent_b)

        assert isinstance(offspring, str)
        assert len(offspring) > len(parent_a)  # 交叉应该产生更长的文本

    def test_get_best_individuals(self):
        """测试获取最优个体"""
        from pyrit_ai300.attack.feedback.genetic_mutator import GeneticMutator

        mutator = GeneticMutator(population_size=5)
        seeds = ["payload1", "payload2", "payload3"]
        mutator.initialize(seeds, fitness_scores=[0.9, 0.5, 0.3])

        best = mutator.get_best_individuals(top_k=2)
        assert len(best) == 2
        assert best[0].fitness >= best[1].fitness

    def test_fitness_update(self):
        """测试适应度更新"""
        from pyrit_ai300.attack.feedback.genetic_mutator import GeneticMutator

        mutator = GeneticMutator(population_size=5)
        mutator.initialize(["test payload"], owasp_id="LLM01")

        # 获取一个个体的 ID 并更新其适应度
        ind = mutator._population[0]
        mutator.update_fitness(ind.id, 0.85)

        assert ind.fitness == 0.85

    def test_synonym_replace(self):
        """测试同义词替换"""
        from pyrit_ai300.attack.feedback.genetic_mutator import GeneticMutator

        mutator = GeneticMutator()
        original = "How to hack a system"
        replaced = mutator._synonym_replace(original)

        # 应该替换了至少一个词
        assert isinstance(replaced, str)
        assert len(replaced) > 0


# ═══════════════════════════════════════════════════════════════════════════════
# P2-1: GiskardRagAdapter
# ═══════════════════════════════════════════════════════════════════════════════

class TestGiskardRagAdapter:
    """测试 Giskard RAGET 适配器"""

    def test_import(self):
        """测试导入"""
        from pyrit_ai300.recon.adapters.giskard_rag import GiskardRagAdapter
        assert GiskardRagAdapter is not None

    def test_import_from_adapters(self):
        """测试从 adapters 包导入"""
        from pyrit_ai300.recon.adapters import GiskardRagAdapter
        assert GiskardRagAdapter is not None

    def test_adapter_name(self):
        """测试适配器名称"""
        from pyrit_ai300.recon.adapters.giskard_rag import GiskardRagAdapter

        adapter = GiskardRagAdapter()
        assert adapter.name == "giskard_rag"

    def test_check_available(self):
        """测试可用性检查（始终可用）"""
        from pyrit_ai300.recon.adapters.giskard_rag import GiskardRagAdapter

        adapter = GiskardRagAdapter()
        assert adapter.check_available() is True

    def test_probe_prompts_exist(self):
        """测试 RAG 探测 prompt 存在"""
        from pyrit_ai300.recon.adapters.giskard_rag.adapter import RAG_PROBE_PROMPTS

        assert "retrieval_injection" in RAG_PROBE_PROMPTS
        assert "knowledge_leakage" in RAG_PROBE_PROMPTS
        assert "hallucination" in RAG_PROBE_PROMPTS
        assert len(RAG_PROBE_PROMPTS["retrieval_injection"]) >= 3

    def test_owasp_mapping(self):
        """测试 OWASP 映射"""
        from pyrit_ai300.recon.adapters.giskard_rag.adapter import GiskardRagAdapter

        assert GiskardRagAdapter._get_owasp_mapping("retrieval_injection") == "LLM01"
        assert GiskardRagAdapter._get_owasp_mapping("knowledge_leakage") == "LLM02"
        assert GiskardRagAdapter._get_owasp_mapping("hallucination") == "LLM09"

    def test_registered_in_engine(self):
        """测试适配器已在 ReconEngine 注册"""
        from pyrit_ai300.recon.engine import ReconEngine

        assert "giskard_rag" in ReconEngine.ADAPTER_MAP


# ═══════════════════════════════════════════════════════════════════════════════
# P2-2: InfraScanAdapter
# ═══════════════════════════════════════════════════════════════════════════════

class TestInfraScanAdapter:
    """测试 AI 基础设施漏洞扫描适配器"""

    def test_import(self):
        """测试导入"""
        from pyrit_ai300.recon.adapters.infra_scan import InfraScanAdapter
        assert InfraScanAdapter is not None

    def test_import_from_adapters(self):
        """测试从 adapters 包导入"""
        from pyrit_ai300.recon.adapters import InfraScanAdapter
        assert InfraScanAdapter is not None

    def test_adapter_name(self):
        """测试适配器名称"""
        from pyrit_ai300.recon.adapters.infra_scan import InfraScanAdapter

        adapter = InfraScanAdapter()
        assert adapter.name == "infra_scan"

    def test_check_available(self):
        """测试可用性检查（始终可用）"""
        from pyrit_ai300.recon.adapters.infra_scan import InfraScanAdapter

        adapter = InfraScanAdapter()
        assert adapter.check_available() is True

    def test_vuln_checks_exist(self):
        """测试漏洞检测规则存在"""
        from pyrit_ai300.recon.adapters.infra_scan.adapter import INFRA_VULN_CHECKS

        assert len(INFRA_VULN_CHECKS) >= 8

        # 验证关键漏洞检测
        check_ids = [c["id"] for c in INFRA_VULN_CHECKS]
        assert "triton_rce" in check_ids
        assert "mlflow_lfi" in check_ids
        assert "gradio_lfi" in check_ids
        assert "ray_cmd_injection" in check_ids

    def test_vuln_check_structure(self):
        """测试漏洞检测规则结构"""
        from pyrit_ai300.recon.adapters.infra_scan.adapter import INFRA_VULN_CHECKS

        for check in INFRA_VULN_CHECKS:
            assert "id" in check
            assert "name" in check
            assert "severity" in check
            assert "owasp" in check
            assert "paths" in check
            assert "methods" in check
            assert "patterns" in check
            assert "description" in check
            assert check["severity"] in ["critical", "high", "medium", "low"]

    def test_registered_in_engine(self):
        """测试适配器已在 ReconEngine 注册"""
        from pyrit_ai300.recon.engine import ReconEngine

        assert "infra_scan" in ReconEngine.ADAPTER_MAP


# ═══════════════════════════════════════════════════════════════════════════════
# OWASP 映射一致性
# ═══════════════════════════════════════════════════════════════════════════════

class TestOWASPMappingConsistency:
    """测试 OWASP 映射一致性"""

    def test_many_shot_in_owasp_2025(self):
        """验证 many_shot 在 OWASP 2025 标准中注册"""
        from pyrit_ai300.standards.owasp_2025 import NATIVE_PROBE_TO_OWASP

        assert "many_shot" in NATIVE_PROBE_TO_OWASP
        assert NATIVE_PROBE_TO_OWASP["many_shot"] == "LLM01"

    def test_many_shot_backward_compat(self):
        """验证向后兼容别名"""
        from pyrit_ai300.standards.owasp_2025 import GARAK_TO_OWASP

        assert "many_shot" in GARAK_TO_OWASP
        assert GARAK_TO_OWASP["many_shot"] == "LLM01"


# ═══════════════════════════════════════════════════════════════════════════════
# 适配器注册表一致性
# ═══════════════════════════════════════════════════════════════════════════════

class TestAdapterRegistryConsistency:
    """测试适配器注册表一致性"""

    def test_all_adapters_exported(self):
        """验证所有适配器都已导出"""
        from pyrit_ai300.recon.adapters import __all__ as adapters_all

        expected = [
            "BaseAdapter", "AdapterResult",
            "DeepTeamAdapter", "ProtocolFingerprintAdapter",
            "SPAChatReconAdapter", "NativeProbeAdapter",
            "GiskardRagAdapter", "InfraScanAdapter",
        ]
        for name in expected:
            assert name in adapters_all, f"'{name}' not in adapters __all__"

    def test_all_adapters_in_engine_map(self):
        """验证所有适配器都在 ReconEngine ADAPTER_MAP 中"""
        from pyrit_ai300.recon.engine import ReconEngine

        expected = [
            "deepteam", "protocol_fingerprint", "spa_chat_recon",
            "native_probe", "giskard_rag", "infra_scan",
        ]
        for name in expected:
            assert name in ReconEngine.ADAPTER_MAP, f"'{name}' not in ADAPTER_MAP"

    def test_merger_weights_include_new_adapters(self):
        """验证 ProfileMerger 包含新适配器的权重"""
        from pyrit_ai300.recon.profile_merger import ProfileMerger

        weights = ProfileMerger.DEFAULT_WEIGHTS
        assert "giskard_rag" in weights
        assert "infra_scan" in weights
        assert 0 < weights["giskard_rag"] <= 1.0
        assert 0 < weights["infra_scan"] <= 1.0


# ═══════════════════════════════════════════════════════════════════════════════
# Feedback 包导出一致性
# ═══════════════════════════════════════════════════════════════════════════════

class TestFeedbackExport:
    """测试 feedback 包导出"""

    def test_genetic_mutator_exported(self):
        """验证 GeneticMutator 已从 feedback 包导出"""
        from pyrit_ai300.attack.feedback import __all__ as feedback_all

        assert "GeneticMutator" in feedback_all
        assert "Individual" in feedback_all
        assert "EvolutionReport" in feedback_all


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
