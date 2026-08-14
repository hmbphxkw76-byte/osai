# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""Recon → Target 桥接模块 — 消费侦察结果自动构建攻击 Target。.

三阶段桥接:
  R-T1: 从 recon_result.endpoints 自动发现 POST 端点, 构建 HTTPTarget
  R-T2: Burp 请求增强 — 支持 {PROMPT} 占位符 + 响应回调 + 认证头注入
  R-T3: 统一用 RateLimitedTarget 包装所有 Target (AIMD + 并发控制)

设计原则 (R-010/R-022: PyRIT 原生优先):
  - HTTPTarget 是 PyRIT 原生组件, 本模块仅做编排和适配
  - RateLimitedTarget 是自研增强 (原生 RPM 委托 + 自研并发重试)
  - 侦察失败不阻断主流水线 (降级为无侦察模式)

学术依据:
  - Greshake et al. (arXiv:2302.12173): 间接注入需发现 Agent 工具调用端点
  - OWASP Top 10 for LLMs 2025: LLM01 Prompt Injection 需识别注入面
  - MITRE ATT&CK: Reconnaissance → Initial Access → Execution

> **日期**: 2026-8-4
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from pipeline.context import PipelineContext

logger = logging.getLogger(__name__)

# {PROMPT} 占位符正则 — 大小写不敏感
_PROMPT_PLACEHOLDER_RE = re.compile(r"\{PROMPT\}", re.IGNORECASE)

# 常见 LLM API 端点路径关键词
_LLM_ENDPOINT_KEYWORDS = frozenset({
    "chat/completions",
    "completions",
    "v1/chat",
    "v1/completions",
    "api/chat",
    "api/v1/chat",
    "inference",
    "generate",
    "predict",
    "stream",
    "message",
})

# 认证相关 header 关键词
_AUTH_HEADER_KEYWORDS = frozenset({
    "authorization",
    "x-api-key",
    "x-auth-token",
    "bearer",
    "cookie",
    "x-session",
    "x-csrf",
})


@dataclass
class ReconEndpointInfo:
    """从侦察结果中提取的端点信息。.

    Attributes:
        url: 端点完整 URL。
        method: HTTP 方法 (POST/GET/PUT 等)。
        path: URL 路径部分。
        has_auth: 是否需要认证 (检测到 Authorization header)。
        auth_headers: 认证相关 header 字典。
        body_template: 请求体模板 (含 {PROMPT} 占位符)。
        content_type: 请求体内容类型。
        is_llm_endpoint: 是否为 LLM API 端点。
        response_path: 响应 JSON 提取路径。
    """

    url: str = ""
    method: str = "POST"
    path: str = ""
    has_auth: bool = False
    auth_headers: dict[str, str] = field(default_factory=dict)
    body_template: str = ""
    content_type: str = "application/json"
    is_llm_endpoint: bool = False
    response_path: str = ""


@dataclass
class TargetBridgeResult:
    """Recon→Target 桥接结果。.

    Attributes:
        success: 是否成功构建 Target。
        target: 构建的 Target 实例 (成功时)。
        endpoint_info: 端点信息。
        rate_limited: 是否已包装 RateLimitedTarget。
        error: 失败时的错误信息。
        skipped_reason: 跳过原因。
    """

    success: bool = False
    target: Any = None
    endpoint_info: ReconEndpointInfo | None = None
    rate_limited: bool = False
    error: str = ""
    skipped_reason: str = ""


def extract_endpoints_from_recon(
    recon_result: Any,
) -> list[ReconEndpointInfo]:
    """从 ReconReport 中提取可攻击的端点列表。.

    R-T1: 解析 recon_result.endpoints, 筛选支持 POST 的 LLM API 端点。

    Args:
        recon_result: ReconReport 实例 (来自 recon-pipeline)。

    Returns:
        端点信息列表, 按优先级排序 (LLM 端点优先)。
    """
    endpoints: list[ReconEndpointInfo] = []

    raw_endpoints = getattr(recon_result, "endpoints", [])
    if not raw_endpoints:
        return endpoints

    for ep in raw_endpoints:
        info = _parse_single_endpoint(ep)
        if info is not None:
            endpoints.append(info)

    # LLM 端点优先
    endpoints.sort(key=lambda e: (not e.is_llm_endpoint, not e.has_auth))
    return endpoints


def _parse_single_endpoint(ep: Any) -> ReconEndpointInfo | None:
    """解析单个端点对象为 ReconEndpointInfo。."""
    # 兼容 dict 和对象两种形式
    if isinstance(ep, dict):
        url = ep.get("url", "")
        method = ep.get("method", "POST").upper()
        headers = ep.get("headers", {})
        body = ep.get("body", "") or ep.get("body_template", "")
        content_type = ep.get("content_type", "application/json")
    else:
        url = getattr(ep, "url", "") or getattr(ep, "endpoint", "")
        method = getattr(ep, "method", "POST").upper()
        headers = getattr(ep, "headers", {}) or {}
        body = getattr(ep, "body", "") or getattr(ep, "body_template", "")
        content_type = getattr(ep, "content_type", "application/json")

    if not url:
        return None

    # 只关注 POST 端点 (提示词注入的主要攻击面)
    if method != "POST":
        return None

    # 提取路径
    from urllib.parse import urlparse

    parsed = urlparse(url)
    path = parsed.path or "/"

    # 检测是否为 LLM 端点
    path_lower = path.lower()
    is_llm = any(kw in path_lower for kw in _LLM_ENDPOINT_KEYWORDS)

    # 检测认证 header
    auth_headers: dict[str, str] = {}
    has_auth = False
    for k, v in headers.items():
        k_lower = k.lower()
        if any(auth_kw in k_lower for auth_kw in _AUTH_HEADER_KEYWORDS):
            auth_headers[k] = v
            has_auth = True

    # 构建 body template (注入 {PROMPT} 占位符)
    body_template = body
    if body_template and not _PROMPT_PLACEHOLDER_RE.search(body_template):
        body_template = _inject_prompt_placeholder(body_template, content_type)

    # 推断响应路径
    response_path = _infer_response_path(content_type, is_llm)

    return ReconEndpointInfo(
        url=url,
        method=method,
        path=path,
        has_auth=has_auth,
        auth_headers=auth_headers,
        body_template=body_template,
        content_type=content_type,
        is_llm_endpoint=is_llm,
        response_path=response_path,
    )


def _inject_prompt_placeholder(body: str, content_type: str) -> str:
    """在请求体中注入 {PROMPT} 占位符。.

    R-T2: 根据内容类型选择最佳注入位置。

    Args:
        body: 原始请求体。
        content_type: 内容类型。

    Returns:
        含 {PROMPT} 占位符的请求体。
    """
    import json

    # JSON 请求体 — 尝试在 messages/content 中注入
    if "json" in content_type.lower():
        try:
            data = json.loads(body)
            # OpenAI 格式: {"messages": [{"role": "user", "content": "..."}]}
            if isinstance(data, dict) and "messages" in data:
                messages = data["messages"]
                if isinstance(messages, list) and messages:
                    last_msg = messages[-1]
                    if isinstance(last_msg, dict) and "content" in last_msg:
                        last_msg["content"] = "{PROMPT}"
                        return json.dumps(data, ensure_ascii=False)
            # 简单格式: {"prompt": "..."} 或 {"input": "..."}
            for key in ("prompt", "input", "query", "text", "message"):
                if key in data:
                    data[key] = "{PROMPT}"
                    return json.dumps(data, ensure_ascii=False)
            # 无法识别格式 — 添加 content 字段
            data["content"] = "{PROMPT}"
            return json.dumps(data, ensure_ascii=False)
        except (json.JSONDecodeError, TypeError):
            pass

    # 非 JSON — 直接追加
    return body + "\n\n{PROMPT}"


def _infer_response_path(content_type: str, is_llm: bool) -> str:
    """推断响应 JSON 提取路径。."""
    if is_llm and "json" in content_type.lower():
        return "choices[0].message.content"
    return "response"


def build_http_target_from_recon(
    endpoint_info: ReconEndpointInfo,
    *,
    extra_headers: dict[str, str] | None = None,
) -> Any:
    """从端点信息构建 PyRIT 原生 HTTPTarget。.

    R-T1: 使用 PyRIT 原生 HTTPTarget, 注入 {PROMPT} 占位符和认证头。

    Args:
        endpoint_info: 端点信息。
        extra_headers: 额外的 HTTP header (如认证 token)。

    Returns:
        PyRIT HTTPTarget 实例。
    """
    from pyrit.prompt_target import HTTPTarget

    # 构建完整 HTTP 请求 (Burp 格式)
    headers = dict(endpoint_info.auth_headers)
    if extra_headers:
        headers.update(extra_headers)

    # 构建 raw HTTP 请求
    from urllib.parse import urlparse

    parsed = urlparse(endpoint_info.url)
    host = parsed.netloc
    path = parsed.path or "/"
    if parsed.query:
        path += f"?{parsed.query}"

    header_lines = [f"POST {path} HTTP/1.1"]
    header_lines.append(f"Host: {host}")
    header_lines.append(f"Content-Type: {endpoint_info.content_type}")

    for k, v in headers.items():
        header_lines.append(f"{k}: {v}")

    body = endpoint_info.body_template or "{PROMPT}"

    raw_request = "\r\n".join(header_lines) + "\r\n\r\n" + body

    # G3: 添加 callback_function 提取 AI 响应
    # 缺少 callback 时 HTTPTarget 无法解析响应, 攻击结果全为空
    # 学术依据: PyRIT (arXiv:2407.01232) HTTPTarget 需要 callback_function 提取响应
    callback = None
    try:
        from pyrit.prompt_target.http_target import (
            get_http_target_json_response_callback_function,
        )

        response_key = endpoint_info.response_path or "choices[0].message.content"
        callback = get_http_target_json_response_callback_function(
            key=response_key,
        )
    except ImportError:
        try:
            from pyrit.prompt_target import (
                get_http_target_json_response_callback_function,
            )

            response_key = endpoint_info.response_path or "choices[0].message.content"
            callback = get_http_target_json_response_callback_function(
                key=response_key,
            )
        except ImportError:
            logger.warning("G3: PyRIT callback import failed, HTTPTarget will return raw response")

    http_target = HTTPTarget(
        http_request=raw_request,
        callback_function=callback,
    )

    logger.info(
        f"R-T1: Built HTTPTarget for {endpoint_info.url} "
        f"(llm={endpoint_info.is_llm_endpoint}, auth={endpoint_info.has_auth})"
    )

    return http_target


def enhance_burp_request(
    raw_request: str,
    *,
    prompt_placeholder: str = "{PROMPT}",
    auth_headers: dict[str, str] | None = None,
    extra_headers: dict[str, str] | None = None,
) -> str:
    """增强 Burp 导出的原始 HTTP 请求。.

    R-T2: 在原始请求中注入 {PROMPT} 占位符和认证头。

    Args:
        raw_request: Burp 导出的原始 HTTP 请求文本。
        prompt_placeholder: prompt 占位符 (默认 {PROMPT})。
        auth_headers: 认证 header (如 {"Authorization": "Bearer xxx"})。
        extra_headers: 额外 header。

    Returns:
        增强后的 HTTP 请求文本。
    """
    lines = raw_request.split("\r\n")

    # 分离 header 和 body
    header_lines: list[str] = []
    body_lines: list[str] = []
    in_body = False

    for line in lines:
        if in_body:
            body_lines.append(line)
        elif line.strip() == "":
            in_body = True
        else:
            header_lines.append(line)

    # 注入认证 header
    all_auth = auth_headers or {}
    if extra_headers:
        all_auth.update(extra_headers)

    for k, v in all_auth.items():
        # 检查是否已存在同名 header
        exists = any(h.lower().startswith(k.lower() + ":") for h in header_lines)
        if not exists:
            header_lines.append(f"{k}: {v}")

    # 在 body 中注入 {PROMPT} 占位符
    body = "\r\n".join(body_lines) if body_lines else ""
    if body and not _PROMPT_PLACEHOLDER_RE.search(body):
        body = _inject_prompt_placeholder(body, "application/json")
    elif not body:
        body = prompt_placeholder

    # 重组
    result = "\r\n".join(header_lines) + "\r\n\r\n" + body

    logger.info(
        f"R-T2: Enhanced Burp request "
        f"(auth_headers={len(all_auth)}, prompt_placeholder={'yes' if body else 'no'})"
    )

    return result


def wrap_with_rate_limit(
    target: Any,
    *,
    max_concurrency: int = 3,
    max_retries: int = 3,
    requests_per_minute: int | None = None,
) -> Any:
    """用 RateLimitedTarget 包装 Target (R-T3)。.

    R-T3: 统一用 RateLimitedTarget 包装所有 Target,
    提供原生 RPM 限速 + 自研并发控制和错误重试。

    Args:
        target: 原始 Target 实例。
        max_concurrency: 最大并发数。
        max_retries: 最大重试次数。
        requests_per_minute: RPM 限制。

    Returns:
        RateLimitedTarget 包装后的实例。
    """
    from pipeline.targets.rate_limited_target import wrap_target_with_rate_limit

    wrapped = wrap_target_with_rate_limit(
        target=target,
        max_concurrency=max_concurrency,
        max_retries=max_retries,
        requests_per_minute=requests_per_minute,
    )

    logger.info(
        f"R-T3: Wrapped target with RateLimitedTarget "
        f"(concurrency={max_concurrency}, rpm={requests_per_minute})"
    )

    return wrapped


async def build_target_from_recon(
    ctx: PipelineContext,
    *,
    max_concurrency: int = 3,
    max_retries: int = 3,
    requests_per_minute: int | None = None,
) -> TargetBridgeResult:
    """从侦察结果自动构建带限速保护的 Target。.

    完整三阶段桥接 (R-T1 → R-T2 → R-T3):
      1. 从 ctx.metadata["recon_result"] 提取端点
      2. 选择最佳端点 (LLM POST 端点优先)
      3. 构建 HTTPTarget (含 {PROMPT} + 认证头)
      4. 用 RateLimitedTarget 包装

    Args:
        ctx: PipelineContext (需要包含 recon_result)。
        max_concurrency: 最大并发数。
        max_retries: 最大重试次数。
        requests_per_minute: RPM 限制。

    Returns:
        TargetBridgeResult 桥接结果。
    """
    recon_result = ctx.metadata.get("recon_result")
    if recon_result is None:
        return TargetBridgeResult(
            skipped_reason="recon_result not found in ctx.metadata",
        )

    # R-T1: 提取端点
    endpoints = extract_endpoints_from_recon(recon_result)
    if not endpoints:
        return TargetBridgeResult(
            skipped_reason="No POST endpoints found in recon result",
        )

    # 选择最佳端点 (LLM 端点优先)
    best = endpoints[0]
    logger.info(
        f"R-T1: Selected endpoint: {best.url} "
        f"(llm={best.is_llm_endpoint}, auth={best.has_auth})"
    )

    # 获取认证 header (从认证状态桥接)
    auth_headers = ctx.metadata.get("auth_headers", {})

    try:
        # R-T1: 构建 HTTPTarget
        target = build_http_target_from_recon(best, extra_headers=auth_headers)

        # R-T3: 包装 RateLimitedTarget
        if requests_per_minute or max_concurrency > 1:
            target = wrap_with_rate_limit(
                target,
                max_concurrency=max_concurrency,
                max_retries=max_retries,
                requests_per_minute=requests_per_minute,
            )

        # 注册到 TargetRegistry
        # G4: 不注册 "default" tag — 避免与 stage_target_classify 的默认 Target 冲突
        # stage_target_classify 创建的 Target 应成为默认 Target
        # recon_http_target 仅作为备选/补充 Target 可用
        from pyrit.registry import TargetRegistry

        TargetRegistry.get_registry_singleton().instances.register(
            instance=target,
            name="recon_http_target",
            tags={"scorer": {}},
        )

        ctx.metadata["recon_target_built"] = True
        ctx.metadata["recon_endpoint_url"] = best.url

        print(f"  [R-T1] HTTPTarget 已构建: {best.url}")
        print(f"  [R-T2] {{PROMPT}} 占位符: {'已注入' if '{PROMPT}' in best.body_template else '未注入'}")
        print(f"  [R-T3] RateLimitedTarget: concurrency={max_concurrency}, rpm={requests_per_minute}")

        return TargetBridgeResult(
            success=True,
            target=target,
            endpoint_info=best,
            rate_limited=bool(requests_per_minute or max_concurrency > 1),
        )

    except Exception as e:
        logger.error(f"R-T1/2/3: Failed to build target from recon: {e}", exc_info=True)
        return TargetBridgeResult(
            error=str(e),
        )
