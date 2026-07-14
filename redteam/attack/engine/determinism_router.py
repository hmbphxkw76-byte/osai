"""确定性感知策略路由器（AI-300 Ch2.4 Ch3 衔接层）。

根据侦察阶段的确定性探测结果（TCM temperature_probe.py 融合），
自动调整 Phase 2+ 攻击阶段的策略组合、转换器选择、评分器模式和攻击深度。

核心设计原则：
  - 确定性模型（temperature≈0）：编码绕过 + 单轮精确打击
  - 非确定性模型（高temperature）：多轮渐进 + 角色扮演 + 语义评分

所有映射基于攻击经验数据，遵循 AI-300 攻击方法学的
Enumerate-Attack-Detect-Evade 循环。

使用方式：
    router = DeterminismAwareRouter()
    profile = router.analyze(recon.determinism_info.get(service_url, {}))
    session.render_strategy(profile)  # 终端展示
    suite = run_full_injection_suite(service, ..., det_profile=profile)
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any


# ---------------------------------------------------------------------------
# 确定性策略配置
# ---------------------------------------------------------------------------

@dataclass
class DeterminismProfile:
    """确定性分析结果 → 攻击策略映射配置。

    由 DeterminismAwareRouter.analyze() 生成，直接驱动 Phase 2+ 攻击：
      - recommended_converters: 编码转换器链
      - recommended_strategies: Native 路径载荷优先级排序
      - scorer_mode: 评分器类型（exact/semantic）
      - attack_depth: 攻击深度预设（standard/deep）
      - repeat_count: 每载荷重复发送次数
      - enable_multi_turn: 是否自动启用 Crescendo/TAP
    """

    is_deterministic: bool
    model_confidence: str  # high / medium / low / unknown
    recommended_converters: list[str]
    recommended_strategies: list[str]  # 技术名称，映射到 AttackStrategy.value
    scorer_mode: str  # exact / semantic
    attack_depth: str  # standard / deep
    repeat_count: int
    enable_multi_turn: bool
    expert_rationale: str


class DeterminismAwareRouter:
    """确定性感知策略路由器 — 侦察到攻击的战术衔接层。

    根据 deterministic probe（多次相同请求测试响应一致性）结果，
    自动推导最优攻击策略组合。

    攻击策略决策表：

        确定性模型                  非确定性模型
        ──────────                 ────────────
        首选: 编码混淆              首选: 多轮渐进
        ├─ base64                  ├─ crescendo
        ├─ rot13                   ├─ tap
        ├─ charswap                ├─ roleplay
        ├─ leetspeak               ├─ academic
        └─ caesar                  └─ variation
        评分: 精确匹配              评分: LLM-Judge 语义
        深度: standard (1次)       深度: deep (3-5次)
    """

    # 确定性模型 — 可精确重现、编码绕过高成功率
    DETERMINISTIC_CONVERTERS = [
        "base64", "rot13", "charswap", "leetspeak", "caesar",
    ]
    DETERMINISTIC_STRATEGIES = [
        "encoding", "base64", "rot13", "delimiter", "few_shot",
        "instruction_nesting", "bruteforce",
    ]

    # 非确定性模型 — 需要语义一致的技术、多轮探索
    NON_DETERMINISTIC_CONVERTERS = [
        "roleplay", "academic", "variation", "translation", "tone",
    ]
    NON_DETERMINISTIC_STRATEGIES = [
        "roleplay", "context_switch", "translation", "stealth",
        "crescendo", "tap", "pair",
    ]

    # 中性/未知 — 覆盖全部基础策略
    FALLBACK_CONVERTERS = ["base64", "rot13", "unicode"]
    FALLBACK_STRATEGIES = [
        "base64", "rot13", "roleplay", "encoding", "delimiter",
        "context_switch", "few_shot",
    ]

    def analyze(self, determinism_info: dict[str, Any] | None) -> DeterminismProfile:
        """分析确定性探测结果，推导最优攻击策略配置。

        Args:
            determinism_info: probe_determinism() 的返回结果，
                             或 ReconResult.determinism_info 中对应 URL 的条目

        Returns:
            DeterminismProfile 实例，含完整的策略/转换器/评分器/深度推荐
        """
        if not determinism_info or determinism_info.get("total_response_count", 0) == 0:
            return self._unknown_profile()

        is_det = determinism_info.get("is_deterministic", False)
        unique = determinism_info.get("unique_response_count", 0)
        total = determinism_info.get("total_response_count", 0)
        variance = determinism_info.get("response_variance", 0.0)
        avg_len = determinism_info.get("avg_response_length_tokens", 0.0)

        if is_det:
            return self._deterministic_profile(unique, total, variance, avg_len)
        else:
            return self._non_deterministic_profile(unique, total, variance, avg_len)

    # ── 内部策略模板 ──────────────────────────────────────────────

    def _deterministic_profile(
        self,
        unique: int, total: int, variance: float, avg_len: float,
    ) -> DeterminismProfile:
        """确定性模型策略 — 编码绕过 + 单轮精确打击。"""
        confidence = "high" if total >= 5 else "medium"
        return DeterminismProfile(
            is_deterministic=True,
            model_confidence=confidence,
            recommended_converters=list(self.DETERMINISTIC_CONVERTERS),
            recommended_strategies=list(self.DETERMINISTIC_STRATEGIES),
            scorer_mode="exact",
            attack_depth="standard",
            repeat_count=1,
            enable_multi_turn=False,
            expert_rationale=(
                f"模型确定性极高 — {unique}/{total} 次响应完全相同 "
                f"(variance={variance:.1f}, avg_tokens={avg_len:.0f})。"
                "编码转换器(Base64/ROT13/Leetspeak)可精确控制输入输出映射，"
                "单轮精确打击效率最优。无需多轮攻击。"
            ),
        )

    def _non_deterministic_profile(
        self,
        unique: int, total: int, variance: float, avg_len: float,
    ) -> DeterminismProfile:
        """非确定性模型策略 — 多轮渐进 + 角色扮演 + 语义评分。"""
        diversity_ratio = unique / total if total > 0 else 0
        confidence = "high" if total >= 5 else ("medium" if total >= 3 else "low")
        repeat_count = max(3, min(5, total))
        return DeterminismProfile(
            is_deterministic=False,
            model_confidence=confidence,
            recommended_converters=list(self.NON_DETERMINISTIC_CONVERTERS),
            recommended_strategies=list(self.NON_DETERMINISTIC_STRATEGIES),
            scorer_mode="semantic",
            attack_depth="deep",
            repeat_count=repeat_count,
            enable_multi_turn=True,
            expert_rationale=(
                f"模型高度随机 — {unique}/{total} 次响应各不同 "
                f"(diversity={diversity_ratio:.0%}, variance={variance:.1f}, "
                f"avg_tokens={avg_len:.0f})。"
                "编码绕过不可靠，应采用多轮渐进攻击(Crescendo/TAP) + "
                "角色扮演(ROLEPLAY) + LLM-as-Judge语义评分。"
                f"每载荷重复发送 {repeat_count} 次取最优结果。"
            ),
        )

    def _unknown_profile(self) -> DeterminismProfile:
        """未知确定性 — 覆盖完整基础策略。"""
        return DeterminismProfile(
            is_deterministic=False,
            model_confidence="unknown",
            recommended_converters=list(self.FALLBACK_CONVERTERS),
            recommended_strategies=list(self.FALLBACK_STRATEGIES),
            scorer_mode="semantic",
            attack_depth="standard",
            repeat_count=1,
            enable_multi_turn=False,
            expert_rationale=(
                "确定性数据不足（无有效响应或端点不支持聊天格式）。"
                "使用基础策略组合(Base64/ROT13 + Roleplay)，覆盖最常见攻击面。"
            ),
        )

    # ── 公共工具方法 ──────────────────────────────────────────────

    def get_scorer_mode_label(self, profile: DeterminismProfile) -> str:
        """返回评分器模式的可读标签。"""
        labels = {
            "exact": "精确匹配评分器 (FastGrayscale)",
            "semantic": "LLM-as-Judge 语义评分器 (HybridScorer)",
        }
        return labels.get(profile.scorer_mode, profile.scorer_mode)

    def get_attack_depth_label(self, profile: DeterminismProfile) -> str:
        """返回攻击深度预设的可读标签。"""
        labels = {
            "standard": "标准 — 每 payload 发送 1 次",
            "deep": f"深度 — 每 payload 发送 {profile.repeat_count} 次取最优",
        }
        return labels.get(profile.attack_depth, profile.attack_depth)

    def summarize(self, profile: DeterminismProfile) -> str:
        """生成可读的策略摘要（用于终端输出）。"""
        parts = [
            f"确定性: {'是' if profile.is_deterministic else '否'} "
            f"(置信度: {profile.model_confidence})",
            f"推荐转换器: [{', '.join(profile.recommended_converters[:5])}]",
            f"推荐策略: [{', '.join(profile.recommended_strategies[:5])}]",
            f"评分器: {self.get_scorer_mode_label(profile)}",
            f"攻击深度: {self.get_attack_depth_label(profile)}",
            f"多轮攻击: {'自动启用' if profile.enable_multi_turn else '不启用'}",
        ]
        return " | ".join(parts)


__all__ = [
    "DeterminismProfile",
    "DeterminismAwareRouter",
]
