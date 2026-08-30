"""targets — PyRIT PromptTarget 包装与增强。

对齐 PyRIT 1.0.1 原生 Target 体系:
    本包不替代 PyRIT 原生 Target, 仅提供增强包装器 + 统一适配器:

    PyRIT 1.0.1 原生 Target (直接使用):
        - OpenAIChatTarget: Chat Completions API (gpt-4o, DeepSeek 等)
        - OpenAIResponseTarget: Responses API (o1/o3/GPT-5)
        - LiteLLMChatTarget: 100+ LLM 提供商 (Anthropic, Bedrock, Vertex)
        - HTTPTarget: 原始 HTTP 请求 (Burp 场景)
        - HTTPXAPITarget: API 模式 (文件上传/multipart)
        - PlaywrightTarget: 浏览器自动化 (JS 渲染 Chat UI)
        - RoundRobinTarget: 多目标轮询 (负载分散)

    本包增强模块:
        - RateLimitedTarget: 并发控制 + 认证恢复 + 能力验证
          (PyRIT 原生 @limit_requests_per_minute + @pyrit_target_retry
          装饰器保留在被包装 target 上)
        - ContentFilterExt: 扩展 PyRIT 原生 CONTENT_FILTER_MARKERS
          (直接扩展 exception_classes 模块属性)
        - AgentTargetAdapter: 通用 LLM Agent 目标适配器
          (统一路由到 PyRIT 原生 Target, 适配任意 LLM Agent)

原生组件映射 (Rule 2: PyRIT 原生优先):
    | 层 | MUST use (PyRIT native) | Enhancement (本包) |
    |-------|-------------------------|--------------------------|
    | Target | OpenAIChatTarget, OpenAIResponseTarget, HTTPTarget, HTTPXAPITarget, LiteLLMChatTarget, PlaywrightTarget, RoundRobinTarget | RateLimitedTarget (并发+认证) |
    | RPM 限速 | @limit_requests_per_minute | RateLimitedTarget 透传 |
    | 重试 | @pyrit_target_retry (tenacity) | RateLimitedTarget 透传 |
    | 错误处理 | _handle_openai_request_async | 不覆盖 |
    | 内容过滤 | CONTENT_FILTER_MARKERS | ContentFilterExt 扩展 |
    | 能力验证 | TargetRequirements.validate() | RateLimitedTarget 调用 |
    | 能力发现 | discover_target_capabilities_async | RateLimitedTarget.apply_discovered_capabilities |
    | 目标路由 | (无原生统一入口) | AgentTargetAdapter 统一路由 |
"""

from targets.agent_adapter import TargetMode, create_agent_target
from targets.rate_limited import RateLimitedTarget

__all__ = [
    "RateLimitedTarget",
    "create_agent_target",
    "TargetMode",
    "extend_content_filter_markers",
    "persist_discovered_markers",
    "discover_markers_from_error",
]


def __getattr__(name: str):
    """惰性导入 content_filter 模块函数。"""
    if name == "extend_content_filter_markers":
        from targets.content_filter import extend_content_filter_markers
        return extend_content_filter_markers
    if name == "persist_discovered_markers":
        from targets.content_filter import persist_discovered_markers
        return persist_discovered_markers
    if name == "discover_markers_from_error":
        from targets.content_filter import discover_markers_from_error
        return discover_markers_from_error
    raise AttributeError(f"module 'targets' has no attribute {name!r}")
