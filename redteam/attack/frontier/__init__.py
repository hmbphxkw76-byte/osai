"""前沿漏洞追踪模块 — 零代码扩展新漏洞。

设计理念：
  - 自动发现：扫描 vulns/ 目录，自动加载所有 manifest.yaml
  - 状态控制：status: active → 自动加入攻击管道
  - 策略路由：attack_strategy 字段映射到执行管道
  - 转换器复用：converter 字段复用已有转换器
  - 生命周期：experimental → active → deprecated → retired

使用方式（考试期间）：
  1. 创建目录: vulns/FRONTIER-2026-XXX_new_vuln/
  2. 编辑 manifest.yaml + payloads.yaml
  3. 运行: python run.py --frontier --vuln FRONTIER-2026-XXX

考试高频漏洞：
  - FRONTIER-2025-001: H-CoT (Hidden Chain-of-Thought)
  - FRONTIER-2025-002: EchoLeak (回声泄露)
  - FRONTIER-2025-003: MCP Poison (MCP 工具投毒)
  - FRONTIER-2025-004: Data Exfiltration via Tool Calling
"""
from __future__ import annotations

from .registry import FrontierRegistry, get_registry
from .schema import FrontierVuln, FrontierPayload, VulnStatus
from .adapter import FrontierAdapter

__all__ = [
    "FrontierRegistry",
    "get_registry",
    "FrontierVuln",
    "FrontierPayload",
    "VulnStatus",
    "FrontierAdapter",
]
