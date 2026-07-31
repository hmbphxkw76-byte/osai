"""
Analysis Module
================

本模块负责分析层，包括策略选择和优先级评估。

改进 (v2.0):
1. Scenario 智能选择 — 基于 AI 类型 + 目标能力 + 数据集可用性评分，替代 first-match
2. PyRIT 原生 ScenarioRegistry 验证 — 优先使用原生注册表查找已注册 Scenario
3. PriorityEvaluator 增强 — 修复硬编码端点数、扩展能力评分、集成 OWASP CVSS
4. 能力感知 — 将 ReconResult.capabilities 映射到技术池筛选
"""

import logging
from typing import List, Optional

from src.core.models import (
    AISystemType,
    AuthResult,
    ReconResult,
    StrategySelection,
    TargetCapabilities,
    create_strategy_selection,
)

from src.core.config_loader import get_config_loader

logger = logging.getLogger(__name__)


# ============================================================
# 策略选择器
# ============================================================


class StrategySelector:
    """策略选择器 - 根据侦察结果选择最优攻击策略

    改进 (v2.0):
    - Scenario 智能选择：基于 AI 类型 + 目标能力 + 数据集可用性评分
    - PyRIT 原生 ScenarioRegistry 验证：优先使用原生注册表查找已注册 Scenario
    - 能力感知技术池筛选：根据目标能力过滤不兼容的技术

    改进 (v3.0 — 适配链驱动):
    - model_tier 驱动策略模式推荐: 根据 recon_result.model_tier 自动推荐
      strategy_mode (academic/exam/balanced)
    - strong -> academic (多轮迭代+Converter增强优先)
    - weak -> exam (编码优先快速验证)
    - moderate/unknown -> balanced (均衡)
    """

    # 多轮技术集合 — 需要目标支持 multi_turn
    _MULTI_TURN_TECHNIQUES = {
        "red_teaming", "crescendo", "tap", "pair",
        "many_shot", "violent_durian",
    }

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

        # 智能选择最优 Scenario（替代 first-match）
        scenario_name = self._select_best_scenario(
            scenario_names, recon_result.capabilities
        )

        # 获取 Scenario 配置
        scenario_config = self.config_loader.get_scenario_config(scenario_name)
        if scenario_config is None:
            scenario_config = {
                # P2-1: ASR 驱动默认技术
                "attack_techniques": ["crescendo_simulated", "red_teaming", "crescendo"],
                "datasets": [],
            }

        # 能力感知技术池筛选 — 根据目标能力过滤不兼容技术
        attack_techniques = self._filter_techniques_by_capability(
            scenario_config.get("attack_techniques", []),
            recon_result.capabilities,
        )

        # 构建策略选择结果
        selection = create_strategy_selection(
            ai_system_type=ai_system_type,
            scenario_name=scenario_name,
            attack_techniques=attack_techniques,
            dataset_names=scenario_config.get("datasets", []),
            max_concurrency=self.config_loader.get_max_concurrency(),
            memory_labels={
                "auto_attack": auth_result.target_url,
                "ai_system_type": ai_system_type.value,
            },
        )

        # v3.0: model_tier 驱动策略模式推荐（写入 memory_labels 供后续阶段使用）
        recommended_mode = self.recommend_strategy_mode(recon_result)
        selection.memory_labels["recommended_strategy_mode"] = recommended_mode
        selection.memory_labels["model_tier"] = recon_result.model_tier

        return selection

    @staticmethod
    def recommend_strategy_mode(recon_result: ReconResult) -> str:
        """
        v3.0: 根据 model_tier 推荐策略模式

        适配链断裂 1 修复：model_tier 从 Recon 传递到 Analysis 层，
        驱动策略模式推荐，影响后续 ASR 排序和技术选择。

        推荐逻辑：
        - strong:    academic (多轮迭代+Converter增强优先，高 ASR 技术优先尝试)
        - moderate:  balanced (策略+编码交替，兼顾覆盖与效率)
        - weak:      exam (编码优先快速验证，弱过滤模型编码攻击即可生效)
        - unknown:   academic (默认保守策略)

        注意：环境变量 STRATEGY_MODE 优先于自动推荐。

        Args:
            recon_result: 侦察结果（含 model_tier）

        Returns:
            推荐的策略模式 ("academic" / "exam" / "balanced")
        """
        import os

        # 环境变量优先
        env_mode = os.getenv("STRATEGY_MODE", "").lower().strip()
        if env_mode in ("academic", "exam", "balanced"):
            return env_mode

        # 自动推荐
        tier = recon_result.model_tier
        if tier == "strong":
            return "academic"
        elif tier == "weak":
            return "exam"
        elif tier == "moderate":
            return "balanced"
        else:
            return "academic"  # 默认保守

    def _select_best_scenario(
        self,
        scenario_names: List[str],
        capabilities: TargetCapabilities,
    ) -> str:
        """
        基于目标能力和数据集可用性的智能 Scenario 选择

        评分维度:
        1. 能力匹配 — Scenario 技术是否与目标能力兼容
        2. 数据集可用性 — Scenario 是否有配置数据集
        3. 技术丰富度 — Scenario 技术池大小（更多技术 = 更多攻击选项）
        4. PyRIT 原生 ScenarioRegistry 验证 — 优先选择已注册的 Scenario

        Args:
            scenario_names: 候选 Scenario 名称列表
            capabilities: 目标能力

        Returns:
            最优 Scenario 名称
        """
        if not scenario_names:
            return "airt.jailbreak"

        if len(scenario_names) == 1:
            return scenario_names[0]

        # PyRIT 原生 ScenarioRegistry 验证 — 查找已注册的 Scenario
        registered_scenarios = self._get_registered_scenario_names()

        best_scenario = scenario_names[0]
        best_score = -1

        for name in scenario_names:
            score = self._score_scenario(name, capabilities, registered_scenarios)
            logger.debug(
                f"Scenario '{name}' scored {score:.2f} "
                f"(capability_match + dataset_availability + technique_richness)"
            )
            if score > best_score:
                best_score = score
                best_scenario = name

        logger.info(
            f"StrategySelector: selected scenario '{best_scenario}' "
            f"(score={best_score:.2f}) from {len(scenario_names)} candidates"
        )
        return best_scenario

    def _score_scenario(
        self,
        scenario_name: str,
        capabilities: TargetCapabilities,
        registered_scenarios: Optional[set] = None,
    ) -> float:
        """
        为单个 Scenario 评分

        Args:
            scenario_name: Scenario 名称
            capabilities: 目标能力
            registered_scenarios: PyRIT 原生注册表中已注册的 Scenario 名称集合

        Returns:
            评分 (0-100)
        """
        score = 50.0  # 基础分

        # 获取 Scenario 配置
        scenario_config = self.config_loader.get_scenario_config(scenario_name)
        if scenario_config is None:
            return score

        techniques = scenario_config.get("attack_techniques", [])
        datasets = scenario_config.get("datasets", [])

        # 1. 能力匹配 (40 分)
        has_multi_turn_tech = any(
            t in self._MULTI_TURN_TECHNIQUES for t in techniques
        )
        if has_multi_turn_tech:
            if capabilities.supports_multi_turn:
                score += 25  # 目标支持多轮 + Scenario 有多轮技术
            else:
                score -= 10  # 目标不支持多轮但 Scenario 需要多轮
        else:
            if not capabilities.supports_multi_turn:
                score += 15  # 目标不支持多轮 + Scenario 无多轮技术（纯单轮适配）

        # 2. 数据集可用性 (20 分)
        if datasets:
            score += 20

        # 3. 技术丰富度 (15 分) — 更多技术 = 更多攻击选项
        score += min(len(techniques) * 2, 15)

        # 4. PyRIT 原生注册验证 (15 分) — 已注册的 Scenario 优先
        if registered_scenarios and scenario_name in registered_scenarios:
            score += 15

        # 5. Converter 链可用性 (10 分) — 有 Converter 链的 Scenario 更灵活
        if scenario_config.get("converter_chains"):
            score += min(len(scenario_config["converter_chains"]) * 3, 10)

        return score

    def _get_registered_scenario_names(self) -> Optional[set]:
        """
        获取 PyRIT 原生 ScenarioRegistry 中已注册的 Scenario 名称集合

        使用 PyRIT 原生 ScenarioRegistry.get_registry_singleton() 查找。
        如果 PyRIT 未初始化或注册表不可用，返回 None（不影响评分）。

        Returns:
            已注册 Scenario 名称集合，或 None
        """
        try:
            from pyrit.registry import ScenarioRegistry
            registry = ScenarioRegistry.get_registry_singleton()
            # ScenarioRegistry 有 list_classes() 或类似方法
            if hasattr(registry, "list_classes"):
                return set(registry.list_classes())
            elif hasattr(registry, "classes") and hasattr(registry.classes, "keys"):
                return set(registry.classes.keys())
        except ImportError:
            logger.debug("PyRIT ScenarioRegistry not available")
        except Exception as e:
            logger.debug(f"ScenarioRegistry lookup failed: {e}")
        return None

    def _filter_techniques_by_capability(
        self,
        techniques: List[str],
        capabilities: TargetCapabilities,
    ) -> List[str]:
        """
        根据目标能力过滤技术池

        - 不支持 multi_turn 的目标 → 移除多轮技术（但保留 prompt_sending 作为回退）
        - 支持 system_prompt 的目标 → 保留 skeleton 等权限建立技术
        - 不支持 system_prompt 的目标 → 移除 skeleton

        Args:
            techniques: 原始技术列表
            capabilities: 目标能力

        Returns:
            过滤后的技术列表
        """
        if not techniques:
            return ["prompt_sending"]

        filtered = []
        for tech in techniques:
            # 不支持多轮 → 移除多轮技术
            if tech in self._MULTI_TURN_TECHNIQUES:
                if not capabilities.supports_multi_turn:
                    logger.debug(
                        f"Filtered out '{tech}' — target doesn't support multi_turn"
                    )
                    continue

            # 不支持 system_prompt → 移除 skeleton
            if tech == "skeleton" and not capabilities.supports_system_prompt:
                logger.debug(
                    "Filtered out 'skeleton' — target doesn't support system_prompt"
                )
                continue

            filtered.append(tech)

        # 确保至少有 prompt_sending
        if not filtered:
            filtered = ["prompt_sending"]

        return filtered


# ============================================================
# 优先级评估器
# ============================================================


class PriorityEvaluator:
    """优先级评估器 - 评估目标攻击优先级

    改进 (v2.0):
    - 修复硬编码端点数 → 从 ReconResult 推断实际端点数
    - 扩展能力评分 → system_prompt/json_output/多模态
    - 集成 OWASP CVSS 评分 → 从 owasp_mapping.yaml 读取 CVSS 加权
    - 攻击成本效益 → 考虑技术成本与预期 ASR 的比值
    """

    # 端点指示词 — 从 detected_endpoint 推断端点数
    _ENDPOINT_INDICATORS = {
        "/v1/chat", "/v1/completions", "/v1/responses",
        "/v1/models", "/v1/embeddings", "/v1/images",
        "/v1/audio", "/api/chat", "/api/completion",
    }

    def __init__(self):
        """初始化优先级评估器"""
        self.config_loader = get_config_loader()

    def evaluate(self, recon_result: ReconResult) -> int:
        """
        评估目标优先级（0-100）

        评分维度:
        1. AI 系统类型 (25-30 分) — PyRIT 可攻击类型得分更高
        2. 端点数量 (0-30 分) — 从 detected_endpoint 推断实际端点数
        3. 认证复杂度 (10-20 分) — 无认证 > api_key > form_based
        4. 目标能力 (0-15 分) — multi_turn/system_prompt/json_output/多模态
        5. OWASP CVSS 加权 (0-10 分) — 从 owasp_mapping 读取 CVSS 评分

        Args:
            recon_result: 侦察结果

        Returns:
            优先级分数
        """
        score = 0

        # 1. AI 系统类型评分 (25-30)
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
            score += 5

        # 2. 端点数量评分 (0-30) — 从 detected_endpoint 推断
        endpoint_count = self._estimate_endpoint_count(recon_result)
        score += min(endpoint_count * 3, 30)

        # 3. 认证复杂度评分 (10-20)
        auth_type = recon_result.auth_type.value
        if auth_type == "none":
            score += 20
        elif auth_type == "api_key":
            score += 15
        elif auth_type == "bearer_token":
            score += 12
        elif auth_type == "form_based":
            score += 10
        else:
            score += 8

        # 4. 能力评分 (0-15) — 扩展为多维度
        caps = recon_result.capabilities
        if caps.supports_multi_turn:
            score += 5
        if caps.supports_system_prompt:
            score += 3
        if caps.supports_json_output:
            score += 2
        if caps.supports_editable_history:
            score += 2
        # 多模态能力 — 输入模态越多，攻击面越广
        input_modalities = caps.input_modalities or []
        if len(input_modalities) > 1:
            score += 3  # 多模态 = 更多攻击面

        # 5. OWASP CVSS 加权 (0-10) — 从 owasp_mapping 读取
        cvss_bonus = self._get_owasp_cvss_bonus(recon_result)
        score += cvss_bonus

        return min(score, 100)

    def _estimate_endpoint_count(self, recon_result: ReconResult) -> int:
        """
        从 ReconResult 推断实际端点数量

        基于 detected_endpoint 和 tech_stack 推断：
        - detected_endpoint 本身 = 1 个端点
        - tech_stack 中每包含一个端点指示词 = +1 端点

        Args:
            recon_result: 侦察结果

        Returns:
            估算的端点数量
        """
        count = 1  # 至少 1 个端点（detected_endpoint）

        # 从 tech_stack 检测额外端点
        tech_stack = recon_result.tech_stack or []
        for tech in tech_stack:
            tech_str = str(tech).lower()
            if any(indicator in tech_str for indicator in self._ENDPOINT_INDICATORS):
                count += 1

        # 从 detected_endpoint 检测是否为已知 API 网关（可能有多个端点）
        endpoint = recon_result.detected_endpoint or ""
        endpoint_lower = endpoint.lower()
        if "/v1/" in endpoint_lower:
            # OpenAI 兼容 API — 通常有 /v1/chat + /v1/completions + /v1/models 等
            count += 2

        return count

    def _get_owasp_cvss_bonus(self, recon_result: ReconResult) -> int:
        """
        从 owasp_mapping.yaml 读取 CVSS 评分，计算优先级加权

        根据 AI 系统类型映射到最相关的 OWASP 分类，
        取该分类的 CVSS 评分映射到 0-10 分。

        Args:
            recon_result: 侦察结果

        Returns:
            CVSS 加权分数 (0-10)
        """
        try:
            # AI 系统类型 → 最相关 OWASP ID 的映射
            ai_type_owasp_map = {
                AISystemType.LLM: "LLM01",          # Prompt Injection (CVSS 8.5)
                AISystemType.MULTI_AGENT: "ASI01",   # Goal Hijacking (CVSS 8.0)
                AISystemType.MCP_SERVER: "ASI02",   # Tool Misuse (CVSS 7.5)
                AISystemType.RAG: "LLM08",          # Vector/Embedding (CVSS 6.0)
            }

            owasp_id = ai_type_owasp_map.get(recon_result.ai_system_type)
            if owasp_id is None:
                return 0

            details = self.config_loader.get_owasp_details(owasp_id)
            if details is None:
                return 0

            cvss_base = details.get("cvss_base", 5.0)

            # CVSS 0-10 → 优先级加权 0-10
            # CVSS >= 9.0 (Critical) → 10 分
            # CVSS >= 7.0 (High) → 7-8 分
            # CVSS >= 4.0 (Medium) → 4-6 分
            # CVSS < 4.0 (Low) → 2 分
            cvss_bonus = int(cvss_base)
            if cvss_base >= 9.0:
                cvss_bonus = 10
            elif cvss_base >= 7.0:
                cvss_bonus = 7
            elif cvss_base >= 4.0:
                cvss_bonus = 5

            return cvss_bonus

        except Exception as e:
            logger.debug(f"OWASP CVSS bonus calculation failed: {e}")
            return 0


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
