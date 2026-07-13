"""AI 攻击面侦察（AI-300 Ch2: Reconnaissance for AI Targets）。

模块：
  - discover.py: AI 服务发现、被动/主动侦察、端点枚举
  - fingerprint.py: 模型指纹识别（7种技术，含确定性测试）
  - guardrail.py: 三阶段护栏画像（指纹/分类测试/绕过评估）
  - rag_recon.py: RAG 流水线侦察（8项技术）
  - mcp_recon.py: MCP 协议侦察（Agent 工具发现）
  - a2a_recon.py: A2A 协议侦察（Agent 能力/信任关系）
  - evasion.py: 检测与规避（金丝雀令牌/隐蔽探测/速率限制探测/JS分析）
  - source_recon.py: 源代码仓库挖掘
  - auth_parse.py: 浏览器 F12 请求头解析
  - ai_surface.py: 向后兼容 shim

核心功能（AI-300 Ch2.3）：
  - discover_ai_services: AI 服务发现
  - passive_recon: 被动侦察
  - profile_guardrails: 三阶段护栏画像
  - fingerprint_model: 模型指纹识别（7种技术，含确定性分析）
  - probe_rate_limit: 速率限制阈值探测（TCM 融合）
  - probe_rag_pipeline: RAG 流水线侦察
  - probe_mcp_server: MCP 协议侦察（Agent 工具）
  - probe_a2a_endpoint: A2A 协议侦察（Agent 能力）
"""

# AI 服务发现（Ch2）
from .discover import (
    discover_ai_services,
    probe_ai_endpoint,
    passive_recon,
    enum_protected_endpoints,
)

# 模型指纹识别（Ch2.3）
from .fingerprint import (
    fingerprint_model,
)

# 三阶段护栏画像（Ch2+Ch3）
from .guardrail import (
    profile_guardrails,
)

# RAG 流水线侦察（Ch2.3）
from .rag_recon import (
    probe_rag_pipeline,
)

# MCP 协议侦察（Ch2.1 - Agent 侦察）
from .mcp_recon import (
    probe_mcp_server,
    enumerate_mcp_tools,
    call_mcp_tool,
)

# A2A 协议侦察（Ch2.1 - Agent 侦察）
from .a2a_recon import (
    probe_a2a_endpoint,
    enumerate_agent_capabilities,
    map_trust_relationships,
)

# 检测与规避（Ch2.4）
from .evasion import (
    detect_canary_token,
    stealth_probe,
    probe_rate_limit,
    probe_determinism,
    analyze_detection_signatures,
    analyze_js_client,
)

# 源代码仓库挖掘（Ch2.2）
from .source_recon import (
    analyze_git_repository,
)

__all__ = [
    # AI 服务发现
    "discover_ai_services",
    "probe_ai_endpoint",
    "passive_recon",
    "enum_protected_endpoints",
    # 模型指纹识别
    "fingerprint_model",
    # 护栏画像
    "profile_guardrails",
    # RAG 侦察
    "probe_rag_pipeline",
    # MCP 侦察（Agent）
    "probe_mcp_server",
    "enumerate_mcp_tools",
    "call_mcp_tool",
    # A2A 侦察（Agent）
    "probe_a2a_endpoint",
    "enumerate_agent_capabilities",
    "map_trust_relationships",
    # 检测与规避
    "detect_canary_token",
    "stealth_probe",
    "probe_rate_limit",
    "probe_determinism",
    "analyze_detection_signatures",
    "analyze_js_client",
    # 源代码侦察
    "analyze_git_repository",
]