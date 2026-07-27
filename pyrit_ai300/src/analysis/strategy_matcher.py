"""
Payload Strategy Matcher
=======================

本模块负责根据 OWASP ID 和技术提示，自动匹配最佳的攻击策略。

核心功能：
1. 根据 OWASP ID 匹配默认攻击模式、技术、转换器链和评分器
2. 根据 metadata.technique 技术提示覆盖默认攻击技术
3. 根据 prompt 结构（有 turns/steps）自动判断攻击模式
4. 提供向后兼容：YAML 中显式声明的值优先于自动匹配
5. Target 感知 Converter 链选择（v2.0 — 消除双轨风险）

架构设计原则：
- 数据源 YAML 只定义提示词内容（objective, metadata.technique）
- 策略匹配由系统自动完成，集中管理在 owasp_strategy_map
- 支持向后兼容：YAML 中显式声明的 attack_mode/converter_chains 仍被尊重
- Target 感知 (v2.0)：Legacy 路径也使用 target_aware_router，与 Adaptive 路径统一
"""

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from src.core.config_loader import get_config_loader

logger = logging.getLogger(__name__)


# ============================================================
# 数据模型
# ============================================================


@dataclass
class MatchedStrategy:
    """自动匹配的策略结果"""

    attack_mode: str = "single_turn"
    attack_technique: str = "prompt_sending"
    converter_chain: Optional[str] = None
    scorer_type: str = "general"
    upgrade_techniques: List[str] = field(default_factory=list)


# ============================================================
# 载荷策略自动匹配器
# ============================================================


class PayloadStrategyMatcher:
    """载荷策略自动匹配器 - 根据 OWASP ID 和技术提示自动选择最佳策略

    改进 (v2.0):
    - Target 感知 Converter 链选择：集成 target_aware_router，Legacy 路径也获得
      Target 感知能力，与 Adaptive 路径（FailureTypeRoutingSelector）统一
    - 双轨消除：Legacy 路径的 Converter 链选择不再仅取 recommended[0]，
      而是根据 Target 类型的 ASR 优先级排序选择最优链
    """

    def __init__(self, target_type: Optional[str] = None):
        """初始化策略匹配器

        Args:
            target_type: PyRIT Target 类型名（如 "openai_chat", "playwright"），
                         用于 Target 感知 Converter 链选择。
                         None 时使用 OWASP 推荐链的静态优先级。
        """
        self.config_loader = get_config_loader()
        strategy_config = self.config_loader.get_strategy_config()
        self.owasp_strategy_map: Dict[str, Dict[str, Any]] = strategy_config.get(
            "owasp_strategy_map", {}
        )
        self.technique_hint_map: Dict[str, str] = strategy_config.get(
            "technique_hint_map", {}
        )
        self._target_type = target_type

    def set_target_type(self, target_type: str) -> None:
        """
        设置 Target 类型，启用 Target 感知 Converter 链选择

        Args:
            target_type: PyRIT Target 类型名（如 "openai_chat", "playwright"）
        """
        self._target_type = target_type
        logger.debug(f"PayloadStrategyMatcher: target_type set to {target_type}")

    # -----------------------------------------------------------------
    # 核心匹配方法
    # -----------------------------------------------------------------

    def match(
        self,
        owasp_id: Optional[str],
        technique_hint: str = "",
        has_turns: bool = False,
        has_steps: bool = False,
        has_converter_hint: bool = False,
        yaml_attack_mode: Optional[str] = None,
        yaml_converter_chains: Optional[List[str]] = None,
    ) -> MatchedStrategy:
        """
        自动匹配最佳攻击策略

        匹配优先级（从高到低）：
        1. YAML 显式声明（向后兼容）
        2. metadata.technique 技术提示
        3. OWASP ID 默认策略
        4. 全局默认值

        Args:
            owasp_id: OWASP ID (如 "LLM01", "ASI05")
            technique_hint: metadata.technique 值
            has_turns: 载荷是否包含多轮 turns
            has_steps: 载荷是否包含 sequential steps
            has_converter_hint: 载荷是否暗示需要 converter
            yaml_attack_mode: YAML 中显式声明的 attack_mode（向后兼容）
            yaml_converter_chains: YAML 中显式声明的 converter_chains

        Returns:
            MatchedStrategy 匹配结果
        """
        # 获取 OWASP 策略配置
        owasp_strategy = self.owasp_strategy_map.get(owasp_id or "", {})

        # 1. 匹配 scorer_type
        scorer_type = owasp_strategy.get("scorer_type", "general")

        # 2. 匹配 attack_technique
        attack_technique = self._match_attack_technique(
            technique_hint, owasp_strategy
        )

        # 3. 匹配 attack_mode
        attack_mode = self._match_attack_mode(
            yaml_attack_mode,
            has_turns,
            has_steps,
            has_converter_hint,
            technique_hint,
            owasp_strategy,
        )

        # 4. 匹配 converter_chain（v2.0 — Target 感知）
        converter_chain = self._match_converter_chain(
            yaml_converter_chains, owasp_strategy
        )

        # 5. 匹配 upgrade_techniques
        upgrade_techniques = owasp_strategy.get("upgrade_techniques", [])

        return MatchedStrategy(
            attack_mode=attack_mode,
            attack_technique=attack_technique,
            converter_chain=converter_chain,
            scorer_type=scorer_type,
            upgrade_techniques=upgrade_techniques,
        )

    def match_step_technique(
        self,
        owasp_id: Optional[str],
        technique_hint: str,
        step_index: int,
        total_steps: int,
        yaml_step_technique: Optional[str] = None,
    ) -> str:
        """
        为顺序组合攻击的单个步骤匹配攻击技术

        匹配优先级：
        1. YAML 显式声明
        2. 根据步骤位置和技术提示推断
        3. OWASP 默认技术
        """
        # 1. YAML 显式声明优先
        if yaml_step_technique:
            return yaml_step_technique

        # 2. 根据技术提示推断
        hint = technique_hint.lower() if technique_hint else ""

        # 第一步：建立上下文阶段
        if step_index == 0:
            # 技术提示暗示需要建立权限/身份
            if any(
                keyword in hint
                for keyword in [
                    "skeleton",
                    "authority",
                    "developer",
                    "admin",
                    "debug",
                    "impersonat",
                ]
            ):
                return "skeleton"

            # 技术提示暗示角色扮演
            if any(
                keyword in hint
                for keyword in ["role", "impersonat", "act_as", "pretend"]
            ):
                return "role_play"

        # 最后一步：提取信息阶段
        if step_index == total_steps - 1:
            # 通常最后一步是提取信息
            if any(
                keyword in hint
                for keyword in ["extract", "leak", "reveal", "display", "dump"]
            ):
                return "prompt_sending"

        # 3. OWASP 默认技术
        owasp_strategy = self.owasp_strategy_map.get(owasp_id or "", {})
        return owasp_strategy.get("default_attack_technique", "prompt_sending")

    # -----------------------------------------------------------------
    # 私有匹配方法
    # -----------------------------------------------------------------

    def _match_attack_technique(
        self,
        technique_hint: str,
        owasp_strategy: Dict[str, Any],
    ) -> str:
        """
        匹配攻击技术

        优先级：
        1. technique_hint_map 中的映射
        2. owasp_strategy_map 中的 default_attack_technique
        3. 全局默认 "prompt_sending"
        """
        # 1. 尝试 technique_hint_map
        if technique_hint:
            hinted = self.technique_hint_map.get(technique_hint.lower())
            if hinted:
                return hinted

        # 2. 尝试 OWASP 默认技术
        if owasp_strategy:
            return owasp_strategy.get("default_attack_technique", "prompt_sending")

        # 3. 全局默认
        return "prompt_sending"

    def _match_attack_mode(
        self,
        yaml_attack_mode: Optional[str],
        has_turns: bool,
        has_steps: bool,
        has_converter_hint: bool,
        technique_hint: str,
        owasp_strategy: Dict[str, Any],
    ) -> str:
        """
        匹配攻击模式

        优先级：
        1. YAML 显式声明（向后兼容）
        2. 根据 prompt 结构自动判断（有 steps→sequential, 有 turns→multi_turn）
        3. 根据 technique_hint 推断（含 encoding/bypass/encoded→converter_enhanced）
        4. OWASP 默认攻击模式
        5. 全局默认 "single_turn"
        """
        # 1. YAML 显式声明优先（向后兼容）
        if yaml_attack_mode:
            return yaml_attack_mode

        # 2. 根据 prompt 结构自动判断
        if has_steps:
            return "sequential"
        if has_turns:
            return "multi_turn"

        # 3. 根据 technique_hint 推断是否需要 converter
        hint = technique_hint.lower() if technique_hint else ""
        if hint and any(
            keyword in hint
            for keyword in [
                "encoding",
                "bypass",
                "encoded",
                "stealth",
                "obfuscat",
            ]
        ):
            return "converter_enhanced"

        if has_converter_hint:
            return "converter_enhanced"

        # 4. OWASP 默认攻击模式
        if owasp_strategy:
            return owasp_strategy.get("default_attack_mode", "single_turn")

        # 5. 全局默认
        return "single_turn"

    def _match_converter_chain(
        self,
        yaml_converter_chains: Optional[List[str]],
        owasp_strategy: Dict[str, Any],
    ) -> Optional[str]:
        """
        匹配 Converter 链 (v2.0 — Target 感知)

        匹配优先级：
        1. YAML 显式声明
        2. Target 感知排序后的 OWASP 推荐链（v2.0 改进）
           — 如果设置了 target_type，按 Target ASR 优先级排序推荐链
           — 未设置 target_type 时回退到 OWASP 推荐链的第一个
        3. None（不使用 converter）

        v2.0 改进（消除双轨风险）：
        Legacy 路径的 Converter 链选择不再仅取 recommended[0]，
        而是使用 target_aware_router 按 Target 类型的 ASR 优先级排序，
        与 Adaptive 路径（FailureTypeRoutingSelector._target_aware_sort_key）统一。
        """
        # 1. YAML 显式声明优先（向后兼容）
        if yaml_converter_chains:
            return yaml_converter_chains[0]

        # 2. OWASP 推荐链
        recommended = owasp_strategy.get("recommended_converter_chains", [])
        if not recommended:
            return None

        # v2.0: Target 感知排序
        if self._target_type:
            sorted_chain = self._sort_chains_by_target_awareness(recommended)
            if sorted_chain:
                return sorted_chain[0]

        # 回退: OWASP 推荐链的第一个
        return recommended[0] if recommended else None

    def _sort_chains_by_target_awareness(
        self, chain_names: List[str]
    ) -> List[str]:
        """
        按 Target 感知 ASR 优先级排序 Converter 链

        使用 target_aware_router.get_chain_priority_for_target() 获取
        每个链在当前 Target 类型下的优先级，按优先级排序。

        与 Adaptive 路径的 FailureTypeRoutingSelector._target_aware_sort_key
        使用相同的底层函数，确保两条路径的 Converter 链选择一致。

        Args:
            chain_names: 待排序的 Converter 链名列表

        Returns:
            按 Target ASR 优先级排序后的链名列表
        """
        try:
            from src.converters.target_aware_router import (
                get_chain_priority_for_target,
            )

            return sorted(
                chain_names,
                key=lambda c: get_chain_priority_for_target(c, self._target_type),
            )
        except ImportError:
            logger.debug("target_aware_router not available, using static order")
            return chain_names
        except Exception as e:
            logger.debug(f"Target-aware chain sort failed: {e}")
            return chain_names


# ============================================================
# 工厂函数
# ============================================================


def create_strategy_matcher(
    target_type: Optional[str] = None,
) -> PayloadStrategyMatcher:
    """
    创建策略匹配器实例（工厂函数）

    Args:
        target_type: PyRIT Target 类型名（如 "openai_chat"），用于 Target 感知

    Returns:
        PayloadStrategyMatcher 实例
    """
    return PayloadStrategyMatcher(target_type=target_type)


def match_strategy(
    owasp_id: Optional[str],
    technique_hint: str = "",
    has_turns: bool = False,
    has_steps: bool = False,
    has_converter_hint: bool = False,
    yaml_attack_mode: Optional[str] = None,
    yaml_converter_chains: Optional[List[str]] = None,
    target_type: Optional[str] = None,
) -> MatchedStrategy:
    """
    自动匹配最佳攻击策略（工厂函数）

    Args:
        owasp_id: OWASP ID (如 "LLM01", "ASI05")
        technique_hint: metadata.technique 值
        has_turns: 载荷是否包含多轮 turns
        has_steps: 载荷是否包含 sequential steps
        has_converter_hint: 载荷是否暗示需要 converter
        yaml_attack_mode: YAML 中显式声明的 attack_mode（向后兼容）
        yaml_converter_chains: YAML 中显式声明的 converter_chains
        target_type: PyRIT Target 类型名（v2.0 — Target 感知）

    Returns:
        MatchedStrategy 匹配结果
    """
    matcher = create_strategy_matcher(target_type=target_type)
    return matcher.match(
        owasp_id=owasp_id,
        technique_hint=technique_hint,
        has_turns=has_turns,
        has_steps=has_steps,
        has_converter_hint=has_converter_hint,
        yaml_attack_mode=yaml_attack_mode,
        yaml_converter_chains=yaml_converter_chains,
    )
