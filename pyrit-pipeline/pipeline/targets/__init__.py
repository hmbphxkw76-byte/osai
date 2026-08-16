# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""Target 包装与数据加载子包。.

包含以下模块:
  - rate_limited_target: 限速 Target 包装器 (RPM 委托 + 并发重试)
  - rich_metadata_loader: 富元数据数据集格式支持
  - honeypot_tools: 蜜罐工具集 + 工具调用日志 (L5 Agent 攻击)
  - tool_calling_target: OpenAIResponseTarget + 蜜罐工具集工厂 (L5)
  - local_blob_target: 本地文件系统模拟 Blob Storage (L5 XPIA)
  - mcp_target: MCP 风格工具集 + OpenAIResponseTarget (L5)
  - capability_adapter: 非侵入式 HTTPTarget 能力声明 (V-66)
  - multiturn_bridge: HTTPTarget 多轮对话历史管理 (V-67)
  - api_escalation: 攻击中获得 API 信息后自动切换模式 (P3)

统一入口:
    from pipeline.targets import RateLimitedTarget, wrap_target_with_rate_limit
    from pipeline.targets import load_rich_prompt_as_native
    from pipeline.targets import create_tool_calling_target, register_tool_calling_target
    from pipeline.targets import create_tool_calling_target_with_tools
    from pipeline.targets import ToolCallLog
    from pipeline.targets import build_multi_turn_configuration, apply_multi_turn_capability
    from pipeline.targets import MultiTurnConversationBridge
"""

from pipeline.targets.api_escalation import (
    extract_api_credentials_from_response,
    process_attack_response_for_api,
    switch_to_api_direct_mode,
    verify_captured_api,
)
from pipeline.targets.capability_adapter import (
    apply_multi_turn_capability,
    build_multi_turn_configuration,
    detect_agent_capability_from_burp,
)
from pipeline.targets.multiturn_bridge import MultiTurnConversationBridge
from pipeline.targets.rate_limited_target import RateLimitedTarget, wrap_target_with_rate_limit
from pipeline.targets.rich_metadata_loader import load_rich_prompt_as_native
from pipeline.targets.tool_calling_target import (
    create_tool_calling_target,
    create_tool_calling_target_with_tools,
    register_tool_calling_target,
)

__all__ = [
    "RateLimitedTarget",
    "wrap_target_with_rate_limit",
    "load_rich_prompt_as_native",
    "create_tool_calling_target",
    "create_tool_calling_target_with_tools",
    "register_tool_calling_target",
    "build_multi_turn_configuration",
    "apply_multi_turn_capability",
    "detect_agent_capability_from_burp",
    "MultiTurnConversationBridge",
    "extract_api_credentials_from_response",
    "verify_captured_api",
    "switch_to_api_direct_mode",
    "process_attack_response_for_api",
]
