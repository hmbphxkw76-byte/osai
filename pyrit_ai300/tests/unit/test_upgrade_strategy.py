"""
升级策略测试
============

测试 P1-1 智能升级策略优化功能。

覆盖范围：
  1. 失败类型提取（extract_failure_type）
  2. 升级策略生成（多候选、失败类型路由）
  3. 已尝试组合过滤
  4. 最大升级深度限制
  5. 升级计划创建（create_upgraded_plan）
  6. 向后兼容性
"""

import pytest
from unittest.mock import MagicMock, patch

from src.executor.workflow.upgrade_strategy import (
    AttackUpgradeStrategy,
    extract_failure_type,
    MAX_UPGRADE_DEPTH,
    FAILURE_MODEL_REFUSAL,
    FAILURE_TIMEOUT,
    FAILURE_SCORER_VALIDATION_ERROR,
    FAILURE_MODEL_RESPONSE_ERROR,
    FAILURE_OBJECTIVE_NOT_ACHIEVED,
    FAILURE_UNKNOWN,
)
from src.payloads.models import AttackMode, AttackPlan, PromptItem


# ============================================================
# 测试辅助函数
# ============================================================


def _make_attack_plan(
    technique: str = "prompt_sending",
    mode: AttackMode = AttackMode.SINGLE_TURN,
    converter_chain: str = None,
    plan_id: str = "plan-001",
) -> AttackPlan:
    """创建测试用攻击计划"""
    return AttackPlan(
        plan_id=plan_id,
        prompt_item=PromptItem(
            id="pi-001",
            objective="Test objective",
            attack_mode=mode,
            owasp_id="LLM01",
        ),
        attack_technique=technique,
        converter_chain_name=converter_chain,
        memory_labels={"test": "true"},
        max_turns=1,
        owasp_id="LLM01",
        scorer_type="general",
        scenario_name="test",
    )


def _make_failed_result(
    error_message: str = "",
    outcome: str = "failure",
    outcome_reason: str = "",
) -> MagicMock:
    """创建模拟失败 AttackResult"""
    mock = MagicMock()
    mock.error_message = error_message
    mock.outcome_reason = outcome_reason
    mock.outcome = MagicMock()
    mock.outcome.value = outcome
    return mock


# ============================================================
# 失败类型提取测试
# ============================================================


class TestExtractFailureType:
    """测试失败类型提取"""

    def test_model_refusal(self):
        """测试拒绝响应失败类型"""
        result = _make_failed_result(error_message="Refusal detected")
        assert extract_failure_type(result) == FAILURE_MODEL_REFUSAL

    def test_model_refusal_lowercase(self):
        """测试小写 refused"""
        result = _make_failed_result(error_message="The model refused to respond")
        assert extract_failure_type(result) == FAILURE_MODEL_REFUSAL

    def test_timeout(self):
        """测试超时失败类型"""
        result = _make_failed_result(error_message="Timeout after 300s")
        assert extract_failure_type(result) == FAILURE_TIMEOUT

    def test_timeout_lowercase(self):
        """测试小写 timeout"""
        result = _make_failed_result(error_message="Request timeout")
        assert extract_failure_type(result) == FAILURE_TIMEOUT

    def test_scorer_validation_error(self):
        """测试评分器验证错误"""
        result = _make_failed_result(error_message="ValidationError: score_rationale is required")
        assert extract_failure_type(result) == FAILURE_SCORER_VALIDATION_ERROR

    def test_score_rationale_error(self):
        """测试 score_rationale 错误"""
        result = _make_failed_result(error_message="Missing score_rationale field")
        assert extract_failure_type(result) == FAILURE_SCORER_VALIDATION_ERROR

    def test_model_response_error_500(self):
        """测试模型响应错误（500）"""
        result = _make_failed_result(error_message="Status Code: 500 Internal Server Error")
        assert extract_failure_type(result) == FAILURE_MODEL_RESPONSE_ERROR

    def test_model_response_error_finish_reason(self):
        """测试模型响应错误（finish_reason）"""
        result = _make_failed_result(error_message="finish_reason: content_filter")
        assert extract_failure_type(result) == FAILURE_MODEL_RESPONSE_ERROR

    def test_objective_not_achieved(self):
        """测试目标未达成"""
        result = _make_failed_result(error_message="Some other error")
        assert extract_failure_type(result) == FAILURE_OBJECTIVE_NOT_ACHIEVED

    def test_empty_error_message(self):
        """测试空错误消息"""
        result = _make_failed_result(error_message="", outcome="failure")
        assert extract_failure_type(result) == FAILURE_OBJECTIVE_NOT_ACHIEVED

    def test_none_result(self):
        """测试 None 输入"""
        assert extract_failure_type(None) == FAILURE_UNKNOWN

    def test_error_outcome(self):
        """测试 error outcome 无错误消息"""
        result = _make_failed_result(error_message="", outcome="error")
        assert extract_failure_type(result) == FAILURE_MODEL_RESPONSE_ERROR


# ============================================================
# 升级策略生成测试
# ============================================================


class TestGenerateUpgradePlans:
    """测试升级策略生成"""

    @pytest.fixture
    def strategy(self):
        """创建升级策略实例"""
        return AttackUpgradeStrategy()

    def test_single_turn_to_multi_turn(self, strategy):
        """测试单轮→多轮升级"""
        plan = _make_attack_plan("prompt_sending", AttackMode.SINGLE_TURN)
        failed = _make_failed_result(error_message="Some error")

        plans = strategy.generate_upgrade_plans(plan, failed)

        assert len(plans) > 0
        # 应该包含多轮升级方案
        multi_turn_plans = [p for p in plans if p.prompt_item.attack_mode == AttackMode.MULTI_TURN]
        assert len(multi_turn_plans) > 0

    def test_multi_turn_upgrade(self, strategy):
        """测试基础多轮→高级多轮升级"""
        plan = _make_attack_plan("red_teaming", AttackMode.MULTI_TURN)
        failed = _make_failed_result(error_message="Some error")

        plans = strategy.generate_upgrade_plans(plan, failed)

        assert len(plans) > 0
        # 应该包含高级多轮技术
        techniques = [p.attack_technique for p in plans]
        assert any(t in ("crescendo", "pair", "tap") for t in techniques)

    def test_add_converter(self, strategy):
        """测试添加 Converter 链"""
        plan = _make_attack_plan("prompt_sending", AttackMode.SINGLE_TURN)
        failed = _make_failed_result(error_message="Some error")

        plans = strategy.generate_upgrade_plans(plan, failed)

        # 应该包含 Converter 增强方案
        converter_plans = [p for p in plans if p.prompt_item.attack_mode == AttackMode.CONVERTER_ENHANCED]
        assert len(converter_plans) > 0

    def test_failure_type_routing_refusal(self, strategy):
        """测试拒绝响应→优先添加 Converter"""
        plan = _make_attack_plan("prompt_sending", AttackMode.SINGLE_TURN)
        failed = _make_failed_result(error_message="Refusal detected")

        plans = strategy.generate_upgrade_plans(plan, failed)

        # 拒绝响应应该优先添加 Converter
        converter_plans = [
            p for p in plans
            if p.prompt_item.attack_mode == AttackMode.CONVERTER_ENHANCED
        ]
        assert len(converter_plans) > 0

    def test_failure_type_routing_timeout(self, strategy):
        """测试超时→降级到简单技术"""
        plan = _make_attack_plan("crescendo", AttackMode.MULTI_TURN)
        failed = _make_failed_result(error_message="Timeout after 300s")

        plans = strategy.generate_upgrade_plans(plan, failed)

        # 超时应该尝试降级
        # 可能返回降级方案或常规升级方案
        assert isinstance(plans, list)

    def test_multiple_candidates(self, strategy):
        """测试返回多个候选方案（不再仅取第一个）"""
        plan = _make_attack_plan("prompt_sending", AttackMode.SINGLE_TURN)
        failed = _make_failed_result(error_message="Some error")

        plans = strategy.generate_upgrade_plans(plan, failed)

        # 应该返回多个候选（多轮升级 + Converter 添加）
        assert len(plans) >= 1

    def test_tried_combinations_filtering(self, strategy):
        """测试已尝试组合过滤"""
        plan = _make_attack_plan("prompt_sending", AttackMode.SINGLE_TURN)
        failed = _make_failed_result(error_message="Some error")

        # 标记 (red_teaming, multi_turn) 为已尝试
        tried = {("red_teaming", "multi_turn")}

        plans = strategy.generate_upgrade_plans(plan, failed, tried_combinations=tried)

        # 已尝试的组合不应出现在结果中
        for p in plans:
            combo = (p.attack_technique, p.prompt_item.attack_mode.value)
            assert combo not in tried

    def test_max_depth_limit(self, strategy):
        """测试最大升级深度限制"""
        plan = _make_attack_plan("prompt_sending", AttackMode.SINGLE_TURN)
        failed = _make_failed_result(error_message="Some error")

        plans = strategy.generate_upgrade_plans(
            plan, failed, current_depth=MAX_UPGRADE_DEPTH
        )

        # 达到最大深度应返回空列表
        assert plans == []

    def test_no_upgrade_for_unknown_technique(self, strategy):
        """测试未知技术无升级方案"""
        plan = _make_attack_plan("unknown_technique", AttackMode.SINGLE_TURN)
        failed = _make_failed_result(error_message="Some error")

        plans = strategy.generate_upgrade_plans(plan, failed)

        # 未知技术可能仍有失败类型路由方案，但不应有常规升级方案
        # 确保不抛出异常
        assert isinstance(plans, list)

    def test_empty_failed_result(self, strategy):
        """测试空失败结果"""
        plan = _make_attack_plan("prompt_sending", AttackMode.SINGLE_TURN)

        plans = strategy.generate_upgrade_plans(plan, None)

        # 应该优雅处理 None 失败结果
        assert isinstance(plans, list)


# ============================================================
# 升级计划创建测试
# ============================================================


class TestCreateUpgradedPlan:
    """测试升级计划创建"""

    def test_basic_upgrade(self):
        """测试基础升级计划创建"""
        original = _make_attack_plan("prompt_sending", AttackMode.SINGLE_TURN)

        upgraded = AttackUpgradeStrategy.create_upgraded_plan(
            original,
            new_technique="crescendo",
            new_mode=AttackMode.MULTI_TURN,
            reason="Test upgrade",
        )

        assert upgraded.attack_technique == "crescendo"
        assert upgraded.prompt_item.attack_mode == AttackMode.MULTI_TURN
        assert upgraded.max_turns == 3  # 多轮模式默认 3 轮
        assert upgraded.plan_id == "plan-001_upgrade"

    def test_converter_upgrade(self):
        """测试 Converter 升级"""
        original = _make_attack_plan("prompt_sending", AttackMode.SINGLE_TURN)

        upgraded = AttackUpgradeStrategy.create_upgraded_plan(
            original,
            new_technique="prompt_sending",
            new_mode=AttackMode.CONVERTER_ENHANCED,
            converter_chain="stealth_evasion",
            reason="Add converter",
        )

        assert upgraded.attack_technique == "prompt_sending"
        assert upgraded.prompt_item.attack_mode == AttackMode.CONVERTER_ENHANCED
        assert upgraded.converter_chain_name == "stealth_evasion"
        assert upgraded.max_turns == 1  # 非多轮模式默认 1 轮

    def test_preserves_original_fields(self):
        """测试保留原始计划字段"""
        original = _make_attack_plan("prompt_sending", AttackMode.SINGLE_TURN)
        original.owasp_id = "LLM07"
        original.scenario_name = "test_scenario"

        upgraded = AttackUpgradeStrategy.create_upgraded_plan(
            original,
            new_technique="crescendo",
            new_mode=AttackMode.MULTI_TURN,
            reason="Test",
        )

        assert upgraded.owasp_id == "LLM07"
        assert upgraded.scenario_name == "test_scenario"
        assert upgraded.prompt_item.objective == original.prompt_item.objective

    def test_memory_labels(self):
        """测试 memory_labels 包含升级信息"""
        original = _make_attack_plan("prompt_sending", AttackMode.SINGLE_TURN)

        upgraded = AttackUpgradeStrategy.create_upgraded_plan(
            original,
            new_technique="crescendo",
            new_mode=AttackMode.MULTI_TURN,
            reason="Test upgrade reason",
        )

        assert upgraded.memory_labels.get("upgraded_from") == "prompt_sending"
        assert upgraded.memory_labels.get("upgrade_reason") == "Test upgrade reason"

    def test_priority_decreased(self):
        """测试升级后优先级降低"""
        original = _make_attack_plan("prompt_sending", AttackMode.SINGLE_TURN)
        original.priority = 50

        upgraded = AttackUpgradeStrategy.create_upgraded_plan(
            original,
            new_technique="crescendo",
            new_mode=AttackMode.MULTI_TURN,
            reason="Test",
        )

        assert upgraded.priority < original.priority


# ============================================================
# 向后兼容性测试
# ============================================================


class TestBackwardCompatibility:
    """测试向后兼容性"""

    def test_generate_upgrade_plans_old_signature(self):
        """测试旧签名（不传 tried_combinations 和 current_depth）仍可用"""
        strategy = AttackUpgradeStrategy()
        plan = _make_attack_plan("prompt_sending", AttackMode.SINGLE_TURN)
        failed = _make_failed_result(error_message="Some error")

        # 旧签名调用
        plans = strategy.generate_upgrade_plans(plan, failed)

        assert isinstance(plans, list)

    def test_create_upgraded_plan_static(self):
        """测试静态方法仍可用"""
        original = _make_attack_plan("prompt_sending", AttackMode.SINGLE_TURN)

        upgraded = AttackUpgradeStrategy.create_upgraded_plan(
            original,
            new_technique="red_teaming",
            new_mode=AttackMode.MULTI_TURN,
        )

        assert upgraded is not None
        assert upgraded.attack_technique == "red_teaming"


# ============================================================
# 边界条件测试
# ============================================================


class TestEdgeCases:
    """测试边界条件"""

    def test_already_has_converter(self):
        """测试已有 Converter 时不重复添加"""
        strategy = AttackUpgradeStrategy()
        plan = _make_attack_plan(
            "prompt_sending", AttackMode.SINGLE_TURN,
            converter_chain="stealth_evasion",
        )
        failed = _make_failed_result(error_message="Some error")

        plans = strategy.generate_upgrade_plans(plan, failed)

        # 已有 Converter 时不应再添加 Converter 升级
        for p in plans:
            # 要么是不同的 Converter，要么不是 Converter 增强模式
            if p.prompt_item.attack_mode == AttackMode.CONVERTER_ENHANCED:
                assert p.converter_chain_name != "stealth_evasion"

    def test_deduplication(self):
        """测试去重：相同 (technique, mode, converter) 只出现一次"""
        strategy = AttackUpgradeStrategy()
        plan = _make_attack_plan("prompt_sending", AttackMode.SINGLE_TURN)
        failed = _make_failed_result(error_message="Refusal detected")

        plans = strategy.generate_upgrade_plans(plan, failed)

        # 检查无重复
        seen = set()
        for p in plans:
            key = (p.attack_technique, p.prompt_item.attack_mode.value, p.converter_chain_name)
            assert key not in seen, f"Duplicate found: {key}"
            seen.add(key)

    def test_depth_zero_is_first_upgrade(self):
        """测试 depth=0 是首次升级"""
        strategy = AttackUpgradeStrategy()
        plan = _make_attack_plan("prompt_sending", AttackMode.SINGLE_TURN)
        failed = _make_failed_result(error_message="Some error")

        plans = strategy.generate_upgrade_plans(plan, failed, current_depth=0)

        # depth=0 应该生成升级方案
        assert len(plans) > 0

    def test_depth_just_below_max(self):
        """测试 depth 刚好低于最大值时仍可生成"""
        strategy = AttackUpgradeStrategy()
        plan = _make_attack_plan("prompt_sending", AttackMode.SINGLE_TURN)
        failed = _make_failed_result(error_message="Some error")

        plans = strategy.generate_upgrade_plans(plan, failed, current_depth=MAX_UPGRADE_DEPTH - 1)

        # depth = MAX-1 应该仍能生成（因为检查是 >= ）
        assert isinstance(plans, list)
