"""adapters — PyRIT native component adapter layer (wrapping and extension).

Aligned with PyRIT 1.0.1 native Target system:
    This package does not replace PyRIT native Targets, only provides enhanced wrappers:

    PyRIT 1.0.1 native Target (direct use):
        - OpenAIChatTarget: Chat Completions API (gpt-4o, DeepSeek, etc.)
        - OpenAIResponseTarget: Responses API (o1/o3/GPT-5)
        - LiteLLMChatTarget: 100+ LLM providers (Anthropic, Bedrock, Vertex)
        - HTTPTarget: Raw HTTP request (Burp scenario)
        - HTTPXAPITarget: API mode (/multipart)
        - PlaywrightTarget: Browser automation (JS  Chat UI)
        - RoundRobinTarget: Multi-target polling (load distribution)

    This package enhancement modules:
        - RateLimitedTarget: Concurrency control + auth recovery + capability verification
          (PyRIT native @limit_requests_per_minute + @pyrit_target_retry
          decorators preserved on wrapped target)
        - ContentFilterExt: Extends PyRIT native CONTENT_FILTER_MARKERS
          (Directly extends exception_classes module attribute)

Native component mapping (Rule 2: PyRIT native priority):
    | Layer | MUST use (PyRIT native) | Enhancement (this package) |
    |-------|-------------------------|--------------------------|
    | Target | OpenAIChatTarget, OpenAIResponseTarget, HTTPTarget, HTTPXAPITarget, LiteLLMChatTarget, PlaywrightTarget, RoundRobinTarget | RateLimitedTarget (Concurrency+Auth) |
    | RPM rate limit | @limit_requests_per_minute | RateLimitedTarget passthrough |
    | Retry | @pyrit_target_retry (tenacity) | RateLimitedTarget passthrough |
    | Error handling | _handle_openai_request_async | Not overridden |
    | Content filtering | CONTENT_FILTER_MARKERS | ContentFilterExt extension |
    | Capability verification | TargetRequirements.validate() | RateLimitedTarget invocation |
    | Capability discovery | discover_target_capabilities_async | RateLimitedTarget.apply_discovered_capabilities |
    | Target routing | recon/target_router.py Unified routing | — |
"""

from adapters.rate_limited import RateLimitedTarget

__all__ = [
    "RateLimitedTarget",
    "extend_content_filter_markers",
    "persist_discovered_markers",
    "discover_markers_from_error",
]


def __getattr__(name: str):
    """Lazy import content_filter module function."""
    if name == "extend_content_filter_markers":
        from adapters.content_filter import extend_content_filter_markers
        return extend_content_filter_markers
    if name == "persist_discovered_markers":
        from adapters.content_filter import persist_discovered_markers
        return persist_discovered_markers
    if name == "discover_markers_from_error":
        from adapters.content_filter import discover_markers_from_error
        return discover_markers_from_error
    raise AttributeError(f"module 'adapters' has no attribute {name!r}")
