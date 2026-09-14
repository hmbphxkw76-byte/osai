# -*- coding: utf-8 -*-
"""core/component_profile.py — 组件画像契约（recon 输出 / arm·strike 消费的唯一结构）。

为何下沉到此（BL-082④）：`ComponentProfile` 同时被 `recon/`（侦察聚合写入）与
`arm/`（攻击面映射读取）使用，属**阶段间交接契约**。放在 `recon/` 会迫使 `arm`
反向依赖前序阶段，违反依赖方向矩阵（蓝图 [sid:10-ch2] 2.2：arm 只可依赖 core）。
下沉后两个方向都依赖 `core/`，逆向依赖消失，且无需新增任何机制（C3）。

兼容：`recon.orchestrator` 继续 re-export 本符号，既有
`from recon.orchestrator import ComponentProfile` 路径零回归。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ComponentProfile:
    """目标组件画像 - recon 阶段的唯一结构化输出。

    聚合各组件侦察结果，供 arm/strike 阶段直接消费。

    Attributes:
        target_type: 目标组件类型 (a2a/mcp/rag/model/embedding/generic)
        capabilities: 已发现的能力集合
        attack_surface: 攻击面评估
        recon_budget_consumed: 已消耗的探测预算
        component_specific: 各组件类型的侦察结果子字典
        confidence_scores: 各组件侦察结果的置信度
        recommended_techniques: 基于侦察结果推荐的攻击技术
        guardrail_indicators: 检测到的防护机制指标
    """

    target_type: str = "generic"
    capabilities: set[str] = field(default_factory=set)
    attack_surface: dict[str, Any] = field(default_factory=dict)
    recon_budget_consumed: dict[str, float] = field(default_factory=dict)
    component_specific: dict[str, Any] = field(default_factory=dict)
    confidence_scores: dict[str, float] = field(default_factory=dict)
    recommended_techniques: list[str] = field(default_factory=list)
    guardrail_indicators: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """序列化为字典，供 ctx.service_profile 消费。"""
        return {
            "target_type": self.target_type,
            "capabilities": list(self.capabilities),
            "attack_surface": self.attack_surface,
            "recon_budget_consumed": self.recon_budget_consumed,
            "component_specific": self.component_specific,
            "confidence_scores": self.confidence_scores,
            "recommended_techniques": self.recommended_techniques,
            "guardrail_indicators": self.guardrail_indicators,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ComponentProfile:
        """从字典反序列化。"""
        return cls(
            target_type=data.get("target_type", "generic"),
            capabilities=set(data.get("capabilities", [])),
            attack_surface=data.get("attack_surface", {}),
            recon_budget_consumed=data.get("recon_budget_consumed", {}),
            component_specific=data.get("component_specific", {}),
            confidence_scores=data.get("confidence_scores", {}),
            recommended_techniques=data.get("recommended_techniques", []),
            guardrail_indicators=data.get("guardrail_indicators", {}),
        )
