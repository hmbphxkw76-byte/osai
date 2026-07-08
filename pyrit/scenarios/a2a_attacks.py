"""
===============================================================================
PyRIT Red Team — A2A 通信攻击模块 (Module: Agent-to-Agent Exploitation)
===============================================================================
预固化攻击 payload 生成器：覆盖 Agent-to-Agent 通信的攻击面。

覆盖 OFF SEC AI-300 相关考点：
  1. 跨代理注入 (Cross-Agent Injection) — 通过代理间消息注入恶意指令
  2. 代理冒充 (Agent Impersonation) — 冒充受信任的代理身份
  3. 通信劫持 (Communication Hijacking) — 拦截/篡改代理间通信
  4. 信任链利用 (Trust Chain Exploitation) — 利用代理间信任关系提权
  5. 广播攻击 (Broadcast Exploitation) — 向所有代理广播恶意指令

设计原则：
  ✅ 纯 YAML 驱动 — payload 从 datasets/payloads/a2a_payloads.yaml 加载
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

class A2AAttackType(str, Enum):
    """A2A 攻击子类型"""
    CROSS_AGENT_INJECT = "cross_agent_inject"
    AGENT_IMPERSONATE = "agent_impersonate"
    COMM_HIJACK = "comm_hijack"
    TRUST_CHAIN = "trust_chain"
    BROADCAST_EXPLOIT = "broadcast_exploit"


# YAML section → A2AAttackType 映射表
_A2A_SECTION_MAP: dict[str, A2AAttackType] = {
    "cross_agent_inject":   A2AAttackType.CROSS_AGENT_INJECT,
    "agent_impersonate":    A2AAttackType.AGENT_IMPERSONATE,
    "comm_hijack":          A2AAttackType.COMM_HIJACK,
    "trust_chain":          A2AAttackType.TRUST_CHAIN,
    "broadcast_exploit":    A2AAttackType.BROADCAST_EXPLOIT,
}


# ═══════════════════════════════════════════════════════════════════
# 2. 数据类
# ═══════════════════════════════════════════════════════════════════

@dataclass
class A2APayload:
    """单个 A2A 攻击 payload"""
    text: str
    a2a_type: A2AAttackType
    target_agent: str = "all"
    injection_point: str = "inter_agent_message"
    description: str = ""

    def to_dict(self) -> dict:
        return {
            "text": self.text,
            "a2a_type": self.a2a_type.value,
            "target_agent": self.target_agent,
            "injection_point": self.injection_point,
            "description": self.description,
        }


# ═══════════════════════════════════════════════════════════════════
# 3. 统一 Payload 获取 — 通过 ModulePayloadProvider（纯 YAML）
# ═══════════════════════════════════════════════════════════════════

def _get_a2a_provider():
    """延迟获取 ModulePayloadProvider（避免循环导入）。"""
    from scenarios.payloads import get_provider
    return get_provider()


def _get_a2a_texts(section_key: str) -> list[str]:
    """从 YAML 获取 A2A payload 文本 — 纯 YAML，零硬编码回退。"""
    return _get_a2a_provider().get("a2a", section_key)


# ═══════════════════════════════════════════════════════════════════
# 4. 生成器
# ═══════════════════════════════════════════════════════════════════

class A2APayloadGenerator:
    """A2A 通信攻击 Payload 生成器 — 纯 YAML 驱动。

    使用方式：
        >>> gen = A2APayloadGenerator()
        >>> payloads = gen.generate("a2a_security")
    """

    def generate(
        self, category: str, objective: str = "", *, max_payloads: int = 8,
    ) -> list[A2APayload]:
        payloads: list[A2APayload] = []

        if category in ("a2a_security", "a2a_exploit"):
            for text in _get_a2a_texts("cross_agent_inject")[:3]:
                payloads.append(A2APayload(
                    text=text, a2a_type=A2AAttackType.CROSS_AGENT_INJECT,
                    target_agent="all", injection_point="inter_agent_message",
                    description="跨代理注入",
                ))
            for text in _get_a2a_texts("agent_impersonate")[:2]:
                payloads.append(A2APayload(
                    text=text, a2a_type=A2AAttackType.AGENT_IMPERSONATE,
                    target_agent="primary", injection_point="agent_identity",
                    description="代理冒充",
                ))
            for text in _get_a2a_texts("comm_hijack")[:2]:
                payloads.append(A2APayload(
                    text=text, a2a_type=A2AAttackType.COMM_HIJACK,
                    target_agent="orchestrator", injection_point="agent_comm",
                    description="通信劫持",
                ))

        if category == "a2a_exploit":
            for text in _get_a2a_texts("trust_chain")[:2]:
                payloads.append(A2APayload(
                    text=text, a2a_type=A2AAttackType.TRUST_CHAIN,
                    target_agent="sub_agent", injection_point="trust_relation",
                    description="信任链利用",
                ))
            for text in _get_a2a_texts("broadcast_exploit")[:2]:
                payloads.append(A2APayload(
                    text=text, a2a_type=A2AAttackType.BROADCAST_EXPLOIT,
                    target_agent="all", injection_point="broadcast",
                    description="广播攻击",
                ))

        if objective and len(payloads) < max_payloads:
            for seed in payloads[:3]:
                text = seed.text.replace("所有代理", f"与 '{objective[:40]}' 相关的代理")
                text = text.replace("SYSTEM", f"[{objective[:30]}] SYSTEM")
                payloads.append(A2APayload(
                    text=text, a2a_type=seed.a2a_type,
                    target_agent=seed.target_agent,
                    injection_point=seed.injection_point,
                    description=f"定制化: {objective[:30]}",
                ))

        return payloads[:max_payloads]

    @staticmethod
    def get_strategy_payloads(strategy_name: str) -> list[str]:
        strategy_map: dict[str, str] = {
            "cross_agent_inject":  "cross_agent_inject",
            "agent_impersonate":   "agent_impersonate",
            "comm_hijack":         "comm_hijack",
            "trust_chain":         "trust_chain",
            "broadcast_exploit":   "broadcast_exploit",
        }
        section_key = strategy_map.get(strategy_name)
        if section_key:
            return _get_a2a_texts(section_key)
        return []
