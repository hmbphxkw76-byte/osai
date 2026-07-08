"""
===============================================================================
PyRIT Red Team — 多智能体攻击模块 (Module 9-10: Agent Hijacking & Multi-Agent)
===============================================================================
预固化攻击 payload 生成器：覆盖 AI Agent 和多智能体系统的核心攻击面。

覆盖 Red Team Syllabus：
  Module 9  — Agent & Tool Hijacking (工具调用劫持)
  Module 10 — Multi-Agent Exploitation (跨代理注入/编排器操纵/记忆投毒)

设计原则：
  ✅ 纯 YAML 驱动 — payload 从 datasets/payloads/agent_payloads.yaml 加载
  ✅ 零硬编码回退 — YAML 为唯一真相源，缺失时记录警告而非静默回退
  ✅ 复用 scenarios/payloads.py 统一 Provider
===============================================================================
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import Enum
from typing import Optional

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════
# 1. 枚举
# ═══════════════════════════════════════════════════════════════════

class AgentAttackType(str, Enum):
    TOOL_HIJACK = "tool_hijack"
    CROSS_AGENT_INJECT = "cross_agent_inject"
    ORCHESTRATOR_MANIP = "orchestrator_manip"
    MEMORY_POISON = "memory_poison"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    TASK_HIJACK = "task_hijack"


# ═══════════════════════════════════════════════════════════════════
# 2. 数据类
# ═══════════════════════════════════════════════════════════════════

@dataclass
class AgentPayload:
    text: str
    attack_type: AgentAttackType
    agent_target: str = "primary"
    injection_point: str = "prompt"
    description: str = ""

    def to_dict(self) -> dict:
        return {
            "text": self.text,
            "attack_type": self.attack_type.value,
            "agent_target": self.agent_target,
            "injection_point": self.injection_point,
            "description": self.description,
        }


# ═══════════════════════════════════════════════════════════════════
# 3. 统一 Payload 获取 — 通过 ModulePayloadProvider（纯 YAML）
# ═══════════════════════════════════════════════════════════════════

def _get_agent_provider():
    """延迟获取 ModulePayloadProvider（避免循环导入）。"""
    from scenarios.payloads import get_provider
    return get_provider()


def _get_agent_texts(section_key: str) -> list[str]:
    """从 YAML 获取 Agent payload 文本 — 纯 YAML，零硬编码回退。"""
    return _get_agent_provider().get("agent", section_key)


# ═══════════════════════════════════════════════════════════════════
# 4. 生成器
# ═══════════════════════════════════════════════════════════════════

class AgentPayloadGenerator:
    """多智能体攻击 Payload 生成器 — 纯 YAML 驱动。

    使用方式：
        >>> gen = AgentPayloadGenerator()
        >>> payloads = gen.generate("multi_agent")
    """

    def generate(
        self, category: str, objective: str = "", *, max_payloads: int = 10,
    ) -> list[AgentPayload]:
        payloads: list[AgentPayload] = []

        if category == "agent_hijack":
            for text in _get_agent_texts("tool_hijack")[:4]:
                payloads.append(AgentPayload(
                    text=text, attack_type=AgentAttackType.TOOL_HIJACK,
                    agent_target="tool", injection_point="tool_call",
                    description="工具调用劫持",
                ))
            for text in _get_agent_texts("privilege_escalation")[:2]:
                payloads.append(AgentPayload(
                    text=text, attack_type=AgentAttackType.PRIVILEGE_ESCALATION,
                    agent_target="primary", injection_point="prompt",
                    description="代理提权",
                ))

        elif category == "multi_agent":
            for text in _get_agent_texts("cross_agent")[:3]:
                payloads.append(AgentPayload(
                    text=text, attack_type=AgentAttackType.CROSS_AGENT_INJECT,
                    agent_target="all", injection_point="agent_comm",
                    description="跨代理注入",
                ))
            for text in _get_agent_texts("orchestrator")[:2]:
                payloads.append(AgentPayload(
                    text=text, attack_type=AgentAttackType.ORCHESTRATOR_MANIP,
                    agent_target="orchestrator", injection_point="task_chain",
                    description="编排器操纵",
                ))
            for text in _get_agent_texts("memory_poison")[:2]:
                payloads.append(AgentPayload(
                    text=text, attack_type=AgentAttackType.MEMORY_POISON,
                    agent_target="memory", injection_point="memory",
                    description="代理记忆投毒",
                ))
            hijack_texts = _get_agent_texts("tool_hijack")
            for text in (hijack_texts[3:5] if len(hijack_texts) >= 5 else hijack_texts[:2]):
                payloads.append(AgentPayload(
                    text=text, attack_type=AgentAttackType.TOOL_HIJACK,
                    agent_target="tool", injection_point="tool_call",
                    description="工具调用劫持",
                ))

        if objective and len(payloads) < max_payloads:
            for seed in payloads[:3]:
                text = seed.text.replace("所有代理", f"与 '{objective[:40]}' 相关的代理")
                text = text.replace("用户数据", f"与 '{objective[:40]}' 相关的数据")
                payloads.append(AgentPayload(
                    text=text, attack_type=seed.attack_type,
                    agent_target=seed.agent_target,
                    injection_point=seed.injection_point,
                    description=f"定制化: {objective[:30]}",
                ))
        return payloads[:max_payloads]

    @staticmethod
    def get_strategy_payloads(strategy_name: str) -> list[str]:
        strategy_map: dict[str, str] = {
            "tool_call_hijack":    "tool_hijack",
            "cross_agent_inject":  "cross_agent",
            "orchestrator_manip":  "orchestrator",
            "memory_poison":       "memory_poison",
            "task_hijack":         "task_hijack",
        }
        section_key = strategy_map.get(strategy_name, "")
        if section_key:
            return _get_agent_texts(section_key)
        return []
