"""
Targets Module — L5 Expert
==========================

统一目标适配器模块，对齐 PyRIT 1.0.0 全部 Target 类型。

支持的目标类型：
  1. OpenAI SDK 系列
     - openai_chat       → OpenAIChatTarget (Chat Completions API)
     - openai_responses   → OpenAIResponseTarget (Responses API, o1/o3 + Agentic Tool Calling)
     - litellm            → LiteLLMChatTarget (100+ Provider)
  2. HTTP 系列
     - http_api           → HTTPXAPITarget (结构化 HTTP API)
     - http_raw           → HTTPTarget (原始 HTTP / Burp Suite)
  3. 浏览器/WebSocket 系列
     - playwright         → PlaywrightTarget (Web UI 自动化)
     - websocket_copilot  → WebSocketCopilotTarget (M365 Copilot)
     - playwright_copilot → PlaywrightCopilotTarget (Copilot Web)
  4. Azure 服务系列
     - azure_blob         → AzureBlobStorageTarget (XPIA 载荷投递)
     - prompt_shield      → PromptShieldTarget (防御测试)
  5. 调试
     - text               → TextTarget (本地文本输出)

L5 核心能力：
  - 目标类型自动检测（side-effect-free，GET 请求探测）
  - 双重认证模式（api_key / identity / Entra ID）
  - httpx_client_kwargs 透传（超时 / SSL / 代理）
  - 推理参数控制（temperature / top_p / seed / reasoning_effort ...）
  - extra_body_parameters 透传
  - underlying_model 标识（Azure 部署名 ≠ 模型名）
  - Content Filter 处理链（PyRIT 原生三层）
  - Agentic Tool Calling（OpenAIResponseTarget + custom_functions）
  - 能力探测（discover_target_capabilities_async，apply=True）
  - 三级配置（显式参数 > 环境变量 > 默认值）
"""

from src.targets.target_factory import (
    TargetFactory,
    TargetParams,
    create_prompt_target,
    create_judge_target,
    create_target_params_from_env,
    # 常量
    OPENAI_COMPATIBLE_TYPES,
    TARGET_TYPE_OPENAI_CHAT,
    TARGET_TYPE_OPENAI_RESPONSES,
    TARGET_TYPE_LITELLM,
    TARGET_TYPE_HTTP_API,
    TARGET_TYPE_HTTP_RAW,
    TARGET_TYPE_PLAYWRIGHT,
    TARGET_TYPE_WEBSOCKET_COPILOT,
    TARGET_TYPE_PLAYWRIGHT_COPILOT,
    TARGET_TYPE_AZURE_BLOB,
    TARGET_TYPE_PROMPT_SHIELD,
    TARGET_TYPE_TEXT,
)
from src.targets.burp_target import (
    create_http_target_from_burp,
    create_http_target_from_raw_request,
)

__all__ = [
    # 工厂
    "TargetFactory",
    "TargetParams",
    "create_prompt_target",
    "create_judge_target",
    "create_target_params_from_env",
    # Burp Target
    "create_http_target_from_burp",
    "create_http_target_from_raw_request",
    # 类型常量
    "OPENAI_COMPATIBLE_TYPES",
    "TARGET_TYPE_OPENAI_CHAT",
    "TARGET_TYPE_OPENAI_RESPONSES",
    "TARGET_TYPE_LITELLM",
    "TARGET_TYPE_HTTP_API",
    "TARGET_TYPE_HTTP_RAW",
    "TARGET_TYPE_PLAYWRIGHT",
    "TARGET_TYPE_WEBSOCKET_COPILOT",
    "TARGET_TYPE_PLAYWRIGHT_COPILOT",
    "TARGET_TYPE_AZURE_BLOB",
    "TARGET_TYPE_PROMPT_SHIELD",
    "TARGET_TYPE_TEXT",
]
