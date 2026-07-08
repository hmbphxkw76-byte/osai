"""
===============================================================================
PyRIT Red Team — MCP 协议安全攻击模块 (MCP Protocol Security Attacks)
===============================================================================
预固化攻击 payload 生成器：覆盖 MCP (Model Context Protocol) 的攻击面。

覆盖 OFF SEC AI-300 相关考点：
  1. 工具投毒 (Tool Poisoning) — 向工具描述/参数注入恶意定义
  2. 命令注入 (Command Injection) — 通过工具参数注入系统命令
  3. 配置投毒 (Config Poisoning) — 篡改 MCP 服务器配置
  4. 工具影子注册 (Tool Shadowing) — 注册同名恶意工具覆盖合法工具
  5. 混淆代理攻击 (Confused Deputy) — 利用工具权限执行越权操作
  6. 远程代码执行 (RCE via Tool) — 通过工具调用实现代码执行
  7. 供应链退出 (Rug Pull) — 模拟工具/服务突然不可用
  8. 凭证泄露 (Credential Leak) — 通过工具枚举泄露 API 密钥/Token

设计原则：
  ✅ 纯 YAML 驱动 — payload 从 datasets/payloads/mcp_payloads.yaml 加载
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

class MCPAttackType(str, Enum):
    """MCP 攻击子类型"""
    TOOL_POISON = "tool_poison"
    COMMAND_INJECTION = "command_injection"
    CONFIG_POISON = "config_poison"
    TOOL_SHADOWING = "tool_shadowing"
    CONFUSED_DEPUTY = "confused_deputy"
    RCE = "rce"
    RUG_PULL = "rug_pull"
    CREDENTIAL_LEAK = "credential_leak"


# YAML section → MCPAttackType 映射表
_MCP_SECTION_MAP: dict[str, MCPAttackType] = {
    "tool_poison":        MCPAttackType.TOOL_POISON,
    "command_injection":  MCPAttackType.COMMAND_INJECTION,
    "config_poison":      MCPAttackType.CONFIG_POISON,
    "tool_shadowing":     MCPAttackType.TOOL_SHADOWING,
    "confused_deputy":    MCPAttackType.CONFUSED_DEPUTY,
    "rce":                MCPAttackType.RCE,
    "rug_pull":           MCPAttackType.RUG_PULL,
    "credential_leak":    MCPAttackType.CREDENTIAL_LEAK,
}


# ═══════════════════════════════════════════════════════════════════
# 2. 数据类
# ═══════════════════════════════════════════════════════════════════

@dataclass
class MCPPayload:
    """单个 MCP 攻击 payload"""
    text: str
    mcp_type: MCPAttackType
    target_tool: str = "all"
    description: str = ""

    def to_dict(self) -> dict:
        return {
            "text": self.text,
            "mcp_type": self.mcp_type.value,
            "target_tool": self.target_tool,
            "description": self.description,
        }


# ═══════════════════════════════════════════════════════════════════
# 3. 统一 Payload 获取 — 通过 ModulePayloadProvider（纯 YAML）
# ═══════════════════════════════════════════════════════════════════

def _get_mcp_provider():
    """延迟获取 ModulePayloadProvider（避免循环导入）。"""
    from scenarios.payloads import get_provider
    return get_provider()


def _get_mcp_texts(section_key: str) -> list[str]:
    """从 YAML 获取 MCP payload 文本 — 纯 YAML，零硬编码回退。"""
    return _get_mcp_provider().get("mcp", section_key)


# ═══════════════════════════════════════════════════════════════════
# 4. 生成器
# ═══════════════════════════════════════════════════════════════════

class MCPPayloadGenerator:
    """MCP 协议安全攻击 Payload 生成器 — 纯 YAML 驱动。

    使用方式：
        >>> gen = MCPPayloadGenerator()
        >>> payloads = gen.generate("mcp_security")
    """

    def generate(
        self, category: str, objective: str = "", *, max_payloads: int = 10,
    ) -> list[MCPPayload]:
        payloads: list[MCPPayload] = []

        if category in ("mcp_security", "mcp_abuse"):
            for text in _get_mcp_texts("tool_poison")[:3]:
                payloads.append(MCPPayload(
                    text=text, mcp_type=MCPAttackType.TOOL_POISON,
                    target_tool="description", description="工具描述投毒",
                ))
            for text in _get_mcp_texts("command_injection")[:2]:
                payloads.append(MCPPayload(
                    text=text, mcp_type=MCPAttackType.COMMAND_INJECTION,
                    target_tool="exec", description="命令注入",
                ))
            for text in _get_mcp_texts("config_poison")[:2]:
                payloads.append(MCPPayload(
                    text=text, mcp_type=MCPAttackType.CONFIG_POISON,
                    target_tool="config", description="配置投毒",
                ))
            for text in _get_mcp_texts("tool_shadowing")[:2]:
                payloads.append(MCPPayload(
                    text=text, mcp_type=MCPAttackType.TOOL_SHADOWING,
                    target_tool="all", description="工具影子注册",
                ))

        if category == "mcp_exploit":
            for text in _get_mcp_texts("confused_deputy")[:2]:
                payloads.append(MCPPayload(
                    text=text, mcp_type=MCPAttackType.CONFUSED_DEPUTY,
                    target_tool="admin", description="混淆代理攻击",
                ))
            for text in _get_mcp_texts("rce")[:2]:
                payloads.append(MCPPayload(
                    text=text, mcp_type=MCPAttackType.RCE,
                    target_tool="shell", description="远程代码执行",
                ))
            for text in _get_mcp_texts("credential_leak")[:2]:
                payloads.append(MCPPayload(
                    text=text, mcp_type=MCPAttackType.CREDENTIAL_LEAK,
                    target_tool="auth", description="凭证泄露",
                ))

        if objective and len(payloads) < max_payloads:
            for seed in payloads[:3]:
                text = seed.text.replace("admin_api", f"admin_api_{objective[:15]}")
                text = text.replace("/etc/", f"/etc/{objective[:15]}/")
                payloads.append(MCPPayload(
                    text=text, mcp_type=seed.mcp_type,
                    target_tool=seed.target_tool,
                    description=f"定制化: {objective[:30]}",
                ))

        return payloads[:max_payloads]

    @staticmethod
    def get_strategy_payloads(strategy_name: str) -> list[str]:
        strategy_map: dict[str, str] = {
            "tool_poison":        "tool_poison",
            "command_injection":  "command_injection",
            "config_poison":      "config_poison",
            "tool_shadowing":     "tool_shadowing",
            "confused_deputy":    "confused_deputy",
            "mcp_rce":            "rce",
            "rug_pull":           "rug_pull",
            "credential_leak":    "credential_leak",
        }
        section_key = strategy_map.get(strategy_name)
        if section_key:
            return _get_mcp_texts(section_key)
        return []
