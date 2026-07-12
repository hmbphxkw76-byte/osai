"""AI 攻击面侦察（AI-300 Ch2）。

模块：
  - ai_surface.py: AI 服务发现、被动/主动侦察、护栏画像、模型指纹识别、RAG 侦察
  - auth_parse.py: 浏览器 F12 请求头解析

核心功能（AI-300 Ch2.3）：
  - discover_ai_services: AI 服务发现
  - passive_recon: 被动侦察
  - fingerprint_guardrail: 护栏指纹识别
  - fingerprint_model: 模型指纹识别（5种技术）
  - probe_rag_pipeline: RAG 流水线侦察
"""

from .ai_surface import (
    discover_ai_services,
    passive_recon,
    fingerprint_model,
    probe_rag_pipeline,
    detect_canary_token,
    stealth_probe,
    analyze_detection_signatures,
    analyze_js_client,
    enum_protected_endpoints,
    probe_mcp_server,
    probe_a2a_endpoint,
    analyze_git_repository,
)
