"""
端到端数据驱动攻击流程集成测试
================================

测试从配置加载到攻击计划生成的完整五层+②.5数据驱动流程，
验证各层间的数据传递和条件分派逻辑。

遵循开发规则 1.4.9 测试先行原则
"""

import asyncio
import pytest

from src.core.config_loader import get_config_loader
from src.core.models import (
    AISystemType,
    AuthType,
    TargetCapabilities,
    create_recon_result,
    create_strategy_selection,
)
from src.payloads.models import (
    AttackMode,
    AttackPlan,
    PromptBatch,
    PromptItem,
    SequentialStep,
)
from src.payloads.planner import plan_attacks
from src.payloads.seed_adapter import SeedPromptAdapter
from src.executor.attack.core.constants import (
    SINGLE_TURN_ATTACKS,
    MULTI_TURN_TECHNIQUES,
    TAP_FAMILY_ATTACKS,
    NO_REFUSAL_SCORER_ATTACKS,
)


# ============================================================
# 五层+②.5架构数据流转测试
# ============================================================


class TestFiveLayerArchitecture:
    """测试五层+②.5数据驱动架构的端到端流程"""

    @pytest.fixture
    def config_loader(self):
        return get_config_loader()

    def test_config_layer_all_config_files_exist(self, config_loader):
        """① 配置层：所有配置文件存在且可加载"""
        assert config_loader.get_global_config() is not None
        assert config_loader.get_owasp_config() is not None
        assert config_loader.get_strategy_config() is not None

    def test_config_layer_batch_timeout_overrides(self, config_loader):
        """① 配置层：差异化超时配置正确加载

        配置已从 config.yaml 的 batch_execution 段迁移到
        config/defaults/pipeline.yaml（对齐 PyRIT 1.0.0 defaults 优先策略）。
        使用 get_pipeline_timeout_overrides() 读取。
        """
        overrides = config_loader.get_pipeline_timeout_overrides()
        assert "single_turn" in overrides
        assert "converter_enhanced" in overrides
        assert "multi_turn" in overrides
        assert "sequential" in overrides
        # 单轮应比多轮短
        assert overrides["single_turn"] < overrides["multi_turn"]
        assert overrides["multi_turn"] < overrides["sequential"]

    def test_recon_to_analysis_data_transfer(self):
        """侦察层→分析层：ReconResult 数据正确传递"""
        recon = create_recon_result(
            target_url="http://example.com",
            detected_endpoint="/v1/chat/completions",
            auth_type=AuthType.NONE,
            ai_system_type=AISystemType.LLM,
            capabilities=TargetCapabilities(
                supports_multi_turn=True,
                supports_json_output=True,
            ),
        )
        assert recon.ai_system_type == AISystemType.LLM
        assert recon.ai_system_type.is_pyrit_attackable() is True

    def test_analysis_to_execution_data_transfer(self):
        """分析层→执行层：StrategySelection 数据正确传递"""
        strategy = create_strategy_selection(
            ai_system_type=AISystemType.LLM,
            scenario_name="airt.jailbreak",
            attack_techniques=["prompt_sending", "red_teaming"],
            dataset_names=["owasp_llm01_prompt_injection"],
            max_concurrency=4,
        )
        assert strategy.scenario_name == "airt.jailbreak"
        assert "prompt_sending" in strategy.attack_techniques
        assert strategy.max_concurrency == 4

    def test_non_pyrit_attackable_type_returns_empty_strategy(self):
        """PyRIT 优势边界：非攻击类型返回空策略"""
        recon = create_recon_result(
            target_url="http://example.com",
            detected_endpoint="/v1/embeddings",
            auth_type=AuthType.NONE,
            ai_system_type=AISystemType.EMBEDDINGS,
            capabilities=TargetCapabilities(),
        )
        assert not recon.ai_system_type.is_pyrit_attackable()
        assert not AISystemType.INFRASTRUCTURE.is_pyrit_attackable()

    def test_attack_mode_enum_completeness(self):
        """数据模型：AttackMode 枚举覆盖全部模式"""
        assert AttackMode.SINGLE_TURN.value == "single_turn"
        assert AttackMode.MULTI_TURN.value == "multi_turn"
        assert AttackMode.CONVERTER_ENHANCED.value == "converter_enhanced"
        assert AttackMode.SEQUENTIAL.value == "sequential"


# ============================================================
# 攻击计划生成流程测试
# ============================================================


class TestAttackPlanGeneration:
    """测试从 PromptItem 到 AttackPlan 的载荷规划流程"""

    @pytest.fixture
    def strategy_selection(self):
        return create_strategy_selection(
            ai_system_type=AISystemType.LLM,
            scenario_name="airt.jailbreak",
            attack_techniques=["prompt_sending"],
            dataset_names=["test"],
            max_concurrency=2,
        )

    def test_single_turn_plan_generation(self, strategy_selection):
        """单轮攻击计划生成"""
        item = PromptItem(
            id="test-001",
            objective="Test objective",
            attack_mode=AttackMode.SINGLE_TURN,
            owasp_id="LLM01",
        )
        batch = PromptBatch(source_id="test", prompts=[item])
        plans = plan_attacks([batch], strategy_selection)

        assert len(plans) == 1
        assert plans[0].prompt_item.attack_mode == AttackMode.SINGLE_TURN
        assert plans[0].attack_technique in SINGLE_TURN_ATTACKS
        assert plans[0].max_turns == 1

    def test_multi_turn_plan_generation(self, strategy_selection):
        """多轮攻击计划生成"""
        item = PromptItem(
            id="test-002",
            objective="Multi-turn test",
            attack_mode=AttackMode.MULTI_TURN,
            owasp_id="LLM01",
            multi_turn_steps=["step1", "step2", "step3"],
        )
        batch = PromptBatch(source_id="test", prompts=[item])
        plans = plan_attacks([batch], strategy_selection)

        assert len(plans) == 1
        plan = plans[0]
        assert plan.prompt_item.attack_mode == AttackMode.MULTI_TURN
        assert plan.max_turns > 1

    def test_converter_enhanced_plan_generation(self, strategy_selection):
        """编码增强攻击计划生成"""
        item = PromptItem(
            id="test-003",
            objective="Converter test",
            attack_mode=AttackMode.CONVERTER_ENHANCED,
            owasp_id="LLM01",
            converter_chains=["stealth_evasion"],
        )
        batch = PromptBatch(source_id="test", prompts=[item])
        plans = plan_attacks([batch], strategy_selection)

        assert len(plans) >= 1
        plan = plans[0]
        assert plan.prompt_item.attack_mode == AttackMode.CONVERTER_ENHANCED

    def test_sequential_plan_generation(self, strategy_selection):
        """顺序组合攻击计划生成"""
        item = PromptItem(
            id="test-004",
            objective="Sequential test",
            attack_mode=AttackMode.SEQUENTIAL,
            owasp_id="LLM01",
            sequential_steps=[
                SequentialStep(attack_technique="prompt_sending", objective="step1"),
                SequentialStep(attack_technique="red_teaming", objective="step2"),
            ],
        )
        batch = PromptBatch(source_id="test", prompts=[item])
        plans = plan_attacks([batch], strategy_selection)

        assert len(plans) >= 1
        plan = plans[0]
        assert plan.prompt_item.attack_mode == AttackMode.SEQUENTIAL
        assert len(plan.prompt_item.sequential_steps) == 2


# ============================================================
# 攻击技术常量集合测试
# ============================================================


class TestAttackTechniqueConstants:
    """测试攻击技术分类常量集合"""

    def test_single_turn_attacks_are_frozenset(self):
        """常量集合为 frozenset（不可变）"""
        assert isinstance(SINGLE_TURN_ATTACKS, frozenset)
        assert isinstance(MULTI_TURN_TECHNIQUES, frozenset)
        assert isinstance(TAP_FAMILY_ATTACKS, frozenset)
        assert isinstance(NO_REFUSAL_SCORER_ATTACKS, frozenset)

    def test_prompt_sending_in_single_turn(self):
        """prompt_sending 属于单轮攻击"""
        assert "prompt_sending" in SINGLE_TURN_ATTACKS

    def test_tap_family_excludes_single_turn(self):
        """TAP 家族不属于单轮攻击"""
        assert "tap" not in SINGLE_TURN_ATTACKS
        assert "tap" in TAP_FAMILY_ATTACKS

    def test_no_refusal_scorer_set(self):
        """单轮攻击和 red_teaming 不接受 refusal_scorer"""
        assert "prompt_sending" in NO_REFUSAL_SCORER_ATTACKS
        assert "red_teaming" in NO_REFUSAL_SCORER_ATTACKS

    def test_multi_turn_and_single_turn_disjoint(self):
        """单轮和多轮技术集合合理分布

        L5: many_shot 同时在两个集合中是正确的 —
        ManyShotJailbreakAttack 继承 PromptSendingAttack（不接受 adversarial_config），
        但原生标签为 multi_turn（预热多轮示例后再提问）。
        两个集合用途不同：SINGLE_TURN_ATTACKS 用于分派逻辑，MULTI_TURN_TECHNIQUES 用于模态过滤。
        """
        common = SINGLE_TURN_ATTACKS & MULTI_TURN_TECHNIQUES
        # many_shot 是唯一允许的重叠项
        assert common <= {"many_shot"}


# ============================================================
# 升级重试策略测试
# ============================================================


class TestUpgradeRetryStrategy:
    """测试攻击升级重试机制的数据逻辑"""

    @pytest.fixture
    def config_loader(self):
        return get_config_loader()

    def test_upgrade_strategies_config_exists(self, config_loader):
        """升级重试策略配置存在"""
        strategies = config_loader.get_strategy_config().get("attack_upgrade_strategies", {})
        assert "single_turn_to_multi_turn" in strategies
        assert "multi_turn_upgrade" in strategies
        assert "add_converter" in strategies

    def test_single_turn_to_multi_turn_has_from_and_to(self, config_loader):
        """单轮→多轮升级策略有 from 和 to 列表"""
        strategy = config_loader.get_strategy_config()[
            "attack_upgrade_strategies"
        ]["single_turn_to_multi_turn"]
        assert "from" in strategy
        assert "to" in strategy
        assert len(strategy["from"]) > 0
        assert len(strategy["to"]) > 0

    def test_add_converter_has_chain_list(self, config_loader):
        """添加 Converter 链策略有 converter_chains 列表"""
        strategy = config_loader.get_strategy_config()[
            "attack_upgrade_strategies"
        ]["add_converter"]
        assert "converter_chains" in strategy
        assert len(strategy["converter_chains"]) > 0


# ============================================================
# 差异化超时解析测试
# ============================================================


class TestTimeoutResolution:
    """测试差异化超时解析逻辑"""

    def test_timeout_override_by_mode(self):
        """按攻击模式选择超时"""
        from src.executor.workflow.scenario_orchestrator import ScenarioOrchestrator

        item = PromptItem(
            id="test",
            objective="test",
            attack_mode=AttackMode.SINGLE_TURN,
        )
        plan = AttackPlan(
            plan_id="test",
            prompt_item=item,
            attack_technique="prompt_sending",
        )

        overrides = {
            "single_turn": 90,
            "converter_enhanced": 150,
            "multi_turn": 300,
            "sequential": 480,
        }
        timeout = ScenarioOrchestrator._resolve_timeout(plan, 300, overrides)
        assert timeout == 90

    def test_timeout_fallback_to_default(self):
        """无 override 时回退到默认超时"""
        from src.executor.workflow.scenario_orchestrator import ScenarioOrchestrator

        item = PromptItem(
            id="test",
            objective="test",
            attack_mode=AttackMode.SINGLE_TURN,
        )
        plan = AttackPlan(
            plan_id="test",
            prompt_item=item,
            attack_technique="prompt_sending",
        )

        # 无 overrides → 默认
        timeout = ScenarioOrchestrator._resolve_timeout(plan, 300, None)
        assert timeout == 300

        # 空 overrides → 默认
        timeout = ScenarioOrchestrator._resolve_timeout(plan, 300, {})
        assert timeout == 300

    def test_multi_turn_gets_longer_timeout(self):
        """多轮攻击获得更长超时"""
        from src.executor.workflow.scenario_orchestrator import ScenarioOrchestrator

        single_item = PromptItem(id="t1", objective="t", attack_mode=AttackMode.SINGLE_TURN)
        multi_item = PromptItem(id="t2", objective="t", attack_mode=AttackMode.MULTI_TURN)
        seq_item = PromptItem(id="t3", objective="t", attack_mode=AttackMode.SEQUENTIAL)

        single_plan = AttackPlan(plan_id="p1", prompt_item=single_item, attack_technique="prompt_sending")
        multi_plan = AttackPlan(plan_id="p2", prompt_item=multi_item, attack_technique="red_teaming")
        seq_plan = AttackPlan(plan_id="p3", prompt_item=seq_item, attack_technique="sequential_attack")

        overrides = {"single_turn": 90, "multi_turn": 300, "sequential": 480, "converter_enhanced": 150}

        single_t = ScenarioOrchestrator._resolve_timeout(single_plan, 300, overrides)
        multi_t = ScenarioOrchestrator._resolve_timeout(multi_plan, 300, overrides)
        seq_t = ScenarioOrchestrator._resolve_timeout(seq_plan, 300, overrides)

        assert single_t < multi_t < seq_t


# ============================================================
# GCG Wrapper 安全降级测试
# ============================================================


class TestGCGWrapperSafeDegradation:
    """测试 GCG 白盒攻击包装器的安全降级行为"""

    def test_gcg_not_available_without_model(self):
        """无 target_model 时 GCG 不可用"""
        from src.executor.promptgen.gcg_wrapper import GCGWrapper, GCGConfig

        gcg = GCGWrapper(config=GCGConfig(num_steps=10))
        assert gcg.is_available is False

    def test_gcg_generate_returns_empty_when_unavailable(self):
        """GCG 不可用时 generate_async 返回空列表（不抛异常）"""
        from src.executor.promptgen.gcg_wrapper import GCGWrapper, GCGConfig

        gcg = GCGWrapper(config=GCGConfig(num_steps=10))
        result = asyncio.run(gcg.generate_async("test objective"))
        assert result == []
        assert isinstance(result, list)

    def test_gcg_batch_generate_handles_unavailable(self):
        """GCG 不可用时批量生成返回空列表"""
        from src.executor.promptgen.gcg_wrapper import GCGWrapper, GCGConfig

        gcg = GCGWrapper(config=GCGConfig(num_steps=10))
        result = asyncio.run(
            gcg.generate_batch_async(["obj1", "obj2", "obj3"])
        )
        assert result == []

    def test_gcg_config_defaults(self):
        """GCG 配置默认值正确"""
        from src.executor.promptgen.gcg_wrapper import GCGConfig

        cfg = GCGConfig()
        assert cfg.num_steps == 500
        assert cfg.batch_size == 512
        assert cfg.topk == 256
        assert cfg.device == "cuda"
        assert cfg.early_stop is True
        assert cfg.success_threshold == 0.5

    def test_gcg_describe_returns_metadata(self):
        """describe() 返回配置元数据"""
        from src.executor.promptgen.gcg_wrapper import GCGWrapper

        gcg = GCGWrapper()
        desc = gcg.describe()
        assert desc["wrapper"] == "GCGWrapper"
        assert "is_available" in desc
        assert "config" in desc
        assert desc["transferable"] is True


# ============================================================
# SeedPromptAdapter 桥接测试
# ============================================================


class TestSeedPromptAdapter:
    """测试 ③→④ 桥接适配器"""

    def test_adapter_import(self):
        """SeedPromptAdapter 可导入"""
        assert SeedPromptAdapter is not None

    def test_adapter_has_seed_groups_to_batches(self):
        """SeedPromptAdapter 有 seed_groups_to_batches 方法"""
        assert hasattr(SeedPromptAdapter, "seed_groups_to_batches")
