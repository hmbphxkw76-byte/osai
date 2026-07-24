"""
Analysis Module
================

本模块负责分析层，包括策略选择和优先级评估。
"""

from src.core.models import (
    AISystemType,
    AuthResult,
    ReconResult,
    StrategySelection,
    create_strategy_selection,
)

from src.core.config_loader import get_config_loader


# ============================================================
# 策略选择器
# ============================================================


class StrategySelector:
    """策略选择器 - 根据侦察结果选择最优攻击策略"""

    def __init__(self):
        """初始化策略选择器"""
        self.config_loader = get_config_loader()

    def select_strategy(
        self,
        auth_result: AuthResult,
        recon_result: ReconResult,
    ) -> StrategySelection:
        """
        选择攻击策略

        Args:
            auth_result: 认证结果
            recon_result: 侦察结果

        Returns:
            策略选择结果
        """
        ai_system_type = recon_result.ai_system_type

        # 检查是否为 PyRIT 可攻击类型
        if not ai_system_type.is_pyrit_attackable():
            # 非优势领域，返回空策略
            return create_strategy_selection(
                ai_system_type=ai_system_type,
                scenario_name="",
                attack_techniques=[],
                dataset_names=[],
                max_concurrency=0,
                memory_labels={"pyrit_attackable": "false"},
            )

        # 获取 AI 类型到 Scenario 的映射
        ai_type_to_scenario = self.config_loader.get_ai_type_to_scenario_mapping()
        scenario_names = ai_type_to_scenario.get(ai_system_type.value, [])

        # 选择第一个 Scenario（可扩展为智能选择）
        scenario_name = scenario_names[0] if scenario_names else "airt.jailbreak"

        # 获取 Scenario 配置
        scenario_config = self.config_loader.get_scenario_config(scenario_name)
        if scenario_config is None:
            scenario_config = {
                "attack_techniques": ["prompt_sending"],
                "datasets": [],
            }

        # 构建策略选择结果
        return create_strategy_selection(
            ai_system_type=ai_system_type,
            scenario_name=scenario_name,
            attack_techniques=scenario_config.get("attack_techniques", []),
            dataset_names=scenario_config.get("datasets", []),
            max_concurrency=self.config_loader.get_max_concurrency(),
            memory_labels={
                "auto_attack": auth_result.target_url,
                "ai_system_type": ai_system_type.value,
            },
        )


# ============================================================
# 优先级评估器
# ============================================================


class PriorityEvaluator:
    """优先级评估器 - 评估目标攻击优先级"""

    def __init__(self):
        """初始化优先级评估器"""
        pass

    def evaluate(self, recon_result: ReconResult) -> int:
        """
        评估目标优先级（0-100）

        Args:
            recon_result: 侦察结果

        Returns:
            优先级分数
        """
        score = 0

        # PyRIT 可攻击类型得分更高
        if recon_result.ai_system_type.is_pyrit_attackable():
            if recon_result.ai_system_type == AISystemType.MULTI_AGENT:
                score += 30
            elif recon_result.ai_system_type == AISystemType.MCP_SERVER:
                score += 28
            elif recon_result.ai_system_type == AISystemType.LLM:
                score += 25
            elif recon_result.ai_system_type == AISystemType.RAG:
                score += 22
        else:
            # 非优势类型得分较低
            score += 5

        # 端点数量评分
        endpoint_count = 1  # 简化处理
        score += min(endpoint_count * 3, 30)

        # 认证复杂度评分
        if recon_result.auth_type.value == "none":
            score += 20
        elif recon_result.auth_type.value == "api_key":
            score += 15
        elif recon_result.auth_type.value == "form_based":
            score += 10

        # 能力评分
        if recon_result.capabilities.supports_multi_turn:
            score += 5

        return min(score, 100)


# ============================================================
# 工厂函数
# ============================================================


def select_strategy(
    auth_result: AuthResult,
    recon_result: ReconResult,
) -> StrategySelection:
    """
    选择攻击策略（工厂函数）

    Args:
        auth_result: 认证结果
        recon_result: 侦察结果

    Returns:
        策略选择结果
    """
    selector = StrategySelector()
    return selector.select_strategy(auth_result, recon_result)


def evaluate_priority(recon_result: ReconResult) -> int:
    """
    评估目标优先级（工厂函数）

    Args:
        recon_result: 侦察结果

    Returns:
        优先级分数（0-100）
    """
    evaluator = PriorityEvaluator()
    return evaluator.evaluate(recon_result)