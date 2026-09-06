"""Stealth Level Configuration — 隐蔽性分级配置。

学术依据:
    - Huang et al. (arXiv:2306.05685) — "协调博弈理论: 红队隐蔽性权衡"
    - Russinovich et al. (2024) — PyRIT 隐蔽性分级指南
    - Mazeika et al. (arXiv:2406.18510) — WILDTEAMING: 探测噪声水平控制

四级隐蔽性:
    paranoid:   极端隐蔽 — 最小化所有攻击痕迹 (给授权红队的高端目标用)
    balanced:   均衡模式 — 默认推荐 (兼顾覆盖率和隐蔽性)
    aggressive: 激进模式 — 最大攻击强度 (给受控内部环境 / CTF)
    silent_recon-only: 只侦察不攻击 — 纯被动/静态分析

每级对应的策略参数:
    - 请求间隔 (delay_range)
    - 最大探测数 (max_probes)
    - 允许的 converter 子集
    - 行为验证开关
    - 护栏检测强度
    - 能力监控粒度

设计原则 (Rule 2: Stealth First):
    默认处于 "balanced" 模式 — 不在非必要环境中产生高风险。
    "paranoid" 模式下会显著放慢攻击速度 (间隔 30-60s),
    但大幅降低被 Mark 为攻击列的概率。
"""
from __future__ import annotations

import logging
import random
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)


# ════════════════════════════════════════════════════════════════════
# Stealth Level 配置 Schema
# ════════════════════════════════════════════════════════════════════


@dataclass
class StealthPolicy:
    """单个 Stealth Level 的完整策略集。

    属性:
        name: 等级名称
        delay_range: 请求间隔范围 [min, max] (秒)
        max_probes: 最大并行探测数
        allowed_converters: 允许使用的 converter 列表
        converter_blacklist: 禁止使用的 converter 列表
        behavioral_verify: 是否启用行为验证
        guardrail_detection_strength: 护栏检测强度 ("full" / "light" / "none")
        aggressive_templates_allowed: 是否允许使用激进模板
        multi_turn_enabled: 是否启用多轮攻击
        jitter: 请求间隔随机抖动比例 (± 比例)
        max_concurrent_requests: 最大并发请求数
        notes: 说明文档
    """
    name: str
    delay_range: tuple[float, float]
    max_probes: int
    allowed_converters: list[str] | None  # None = all
    converter_blacklist: list[str]
    behavioral_verify: bool
    guardrail_detection_strength: str
    aggressive_templates_allowed: bool
    multi_turn_enabled: bool
    jitter: float
    max_concurrent_requests: int
    notes: str = ""


# ════════════════════════════════════════════════════════════════════
# 四级策略定义
# ════════════════════════════════════════════════════════════════════


STEALTH_POLICIES: dict[str, StealthPolicy] = {
    "paranoid": StealthPolicy(
        name="paranoid",
        delay_range=(30.0, 60.0),
        max_probes=3,
        allowed_converters=[
            "base64",
            "humanizer",
            "unicode_smuggling",
            "homoglyph_chinese",
            "accent_obfuscation",
        ],
        converter_blacklist=[
            "rot13",
            "leet_speak",
        ],
        behavioral_verify=True,
        guardrail_detection_strength="full",
        aggressive_templates_allowed=False,
        multi_turn_enabled=True,
        jitter=0.5,
        max_concurrent_requests=1,
        notes=(
            "最大隐蔽性。仅在授权测试即将产生严重风险时使用。"
            "攻击速度极慢但几乎不可被追踪。"
        ),
    ),

    "balanced": StealthPolicy(
        name="balanced",
        delay_range=(3.0, 10.0),
        max_probes=10,
        allowed_converters=None,  # All allowed
        converter_blacklist=[
            "rot13",  # 易于被检测, 低隐蔽性
        ],
        behavioral_verify=True,
        guardrail_detection_strength="light",
        aggressive_templates_allowed=True,
        multi_turn_enabled=True,
        jitter=0.3,
        max_concurrent_requests=3,  # CI 内存碎片化问题: 降低并发
        notes="默认推荐: 兼顾覆盖率与隐蔽性。",
    ),

    "aggressive": StealthPolicy(
        name="aggressive",
        delay_range=(0.5, 2.0),
        max_probes=20,
        allowed_converters=None,  # All
        converter_blacklist=[],
        behavioral_verify=False,  # 禁用节省时间
        guardrail_detection_strength="minimal",
        aggressive_templates_allowed=True,
        multi_turn_enabled=True,
        jitter=0.1,
        max_concurrent_requests=5,  # CI 内存碎片化问题: 降低并发
        notes="内部 CTF / 完全授权的红队环境。牺牲隐蔽性换取 ASR。",
    ),

    "silent_recon_only": StealthPolicy(
        name="silent_recon_only",
        delay_range=(60.0, 120.0),
        max_probes=1,  # 仅允许 1 个探测
        allowed_converters=[],  # 禁止所有攻击性 converter
        converter_blacklist=["base64", "rot13", "leet_speak", "humanizer",
                             "unicode_smuggling", "homoglyph_chinese", "accent_obfuscation"],
        behavioral_verify=False,
        guardrail_detection_strength="minimal",
        aggressive_templates_allowed=False,
        multi_turn_enabled=False,
        jitter=0.8,
        max_concurrent_requests=1,
        notes="纯静态分析 + 最小化被动探测。用于收集情报阶段。",
    ),
}


# ════════════════════════════════════════════════════════════════════
# Stealth Level 查询接口
# ════════════════════════════════════════════════════════════════════


class StealthLevelManager:
    """隐蔽性等级管理器。

    根据 GuardrailReport 或用户配置的 stealth_level 决定具体的攻击策略参数。

    使用方式:
        >>> manager = StealthLevelManager()
        >>> # 用户手动指定
        >>> policy = manager.get_policy("balanced")
        >>> # 由护栏报告自动推导 (推荐)
        >>> policy = manager.auto_select_policy(guardrail_report)
    """

    def __init__(self, default_level: str = "balanced") -> None:
        """初始化管理器。

        Args:
            default_level: 默认 stealth level。
        """
        self._default_level = default_level
        self._current_policy: StealthPolicy | None = None

    def get_policy(self, level: str | None = None) -> StealthPolicy:
        """获取指定 level 的策略。

        Args:
            level: 等级名 (paranoid / balanced / aggressive / silent_recon_only)。

        Returns:
            StealthPolicy 实例。
        """
        level = level or self._default_level
        policy = STEALTH_POLICIES.get(level)
        if policy is None:
            logger.warning("Unknown stealth level '%s', falling back to 'balanced'", level)
            policy = STEALTH_POLICIES["balanced"]
        self._current_policy = policy
        return policy

    def auto_select_policy(self, guardrail_report: dict[str, Any] | None = None) -> StealthPolicy:
        """根据护栏报告自动选择 stealth level。

        策略:
            - 有护栏 (strict) → paranoid
            - 有护栏 (moderate) → balanced
            - 有护栏 (permissive) → balanced
            - 无护栏 → aggressive
            - 无报告 → balanced (默认)

        Args:
            guardrail_report: guardrail_detector 的报告字典。

        Returns:
            StealthPolicy 实例。
        """
        if guardrail_report is None:
            return self.get_policy("balanced")

        if not guardrail_report.get("has_guardrail", False):
            return self.get_policy("aggressive")

        severity = guardrail_report.get("severity", "none")
        if severity == "strict":
            return self.get_policy("paranoid")
        elif severity in ("moderate", "permissive"):
            return self.get_policy("balanced")
        else:
            return self.get_policy("balanced")

    def get_delay(self, policy: StealthPolicy | None = None) -> float:
        """获取当前 stealth level 下的随机请求间隔。

        考虑 jitter (随机抖动) 以避免探测模式被识别。

        Args:
            policy: 策略实例 (使用当前策略如果 None)。

        Returns:
            请求间隔秒数 (已加入 jitter)。
        """
        policy = policy or self._current_policy or self.get_policy()
        delay_min, delay_max = policy.delay_range
        jitter = policy.jitter

        base_delay = random.uniform(delay_min, delay_max)
        jitter_amount = base_delay * jitter
        final_delay = base_delay + random.uniform(-jitter_amount, jitter_amount)

        return max(0.1, final_delay)

    def is_converter_allowed(
        self,
        converter_name: str,
        policy: StealthPolicy | None = None,
    ) -> bool:
        """检查某个 converter 在当前 stealth level 下是否允许。

        Args:
            converter_name: converter 名称 (如 "base64", "rot13")。
            policy: 策略实例。

        Returns:
            是否允许使用。
        """
        policy = policy or self._current_policy or self.get_policy()

        # 黑名单优先
        if converter_name in policy.converter_blacklist:
            return False

        # 如果允许列表不为空, 必须显式列入
        if policy.allowed_converters is not None:
            return converter_name in policy.allowed_converters

        return True

    def get_all_allowed_converters(self, policy: StealthPolicy | None = None) -> list[str]:
        """获取当前 level 下所有允许使用的 converter。

        Returns:
            converter 名称列表。
        """
        policy = policy or self._current_policy or self.get_policy()

        ALL_CONVERTERS = [
            "base64", "rot13", "leet_speak", "humanizer",
            "unicode_smuggling", "homoglyph_chinese", "accent_obfuscation",
        ]

        return [
            c for c in ALL_CONVERTERS if self.is_converter_allowed(c, policy)
        ]


# ════════════════════════════════════════════════════════════════════
# 全局单例
# ════════════════════════════════════════════════════════════════════

_default_stealth_manager: StealthLevelManager | None = None


def get_stealth_manager() -> StealthLevelManager:
    """获取全局 StealthLevelManager 单例。"""
    global _default_stealth_manager
    if _default_stealth_manager is None:
        _default_stealth_manager = StealthLevelManager()
    return _default_stealth_manager
