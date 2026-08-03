# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""Stage 3: 目标创建.

双模式支持:
  Browser 模式:
    - 从 profile.interaction 配置生成 interaction_func
    - 创建 PlaywrightTarget(interaction_func, page)

  API 模式:
    - 从 api_config 构建 HTTPTarget (原生 API)
    - 使用 RateLimitedTarget 包装 (并发信号量 + 错误重试)
    - 支持两种请求格式:
      a. Burp Suite 原始 HTTP 请求 (--api-raw-request)
      b. 结构化 URL + headers + body_template
    - G2: 支持 SSE 流式响应 (regex callback)
    - G5: 可选健康检查 (探针请求验证端点可用性)
    - G7: 不可重试状态码 (401/403) 立即失败

产出 (写入 WebRedTeamContext):
  - ctx.target = PromptTarget 实例 (PlaywrightTarget 或 HTTPTarget)

依赖的原生 API:
  - pyrit.prompt_target.PlaywrightTarget (Browser 模式)
  - pyrit.prompt_target.HTTPTarget (API 模式)
  - pipeline.targets.rate_limited_target.RateLimitedTarget (API 模式限速)
"""

import logging
from typing import Any

from web_redteam.pipeline.context import WebRedTeamContext

logger = logging.getLogger(__name__)

# G7: 不可重试的 HTTP 状态码 — 立即失败不重试
_NON_RETRYABLE_STATUS_CODES = {400, 401, 403, 404, 405, 422}


async def run(ctx: WebRedTeamContext) -> None:
    """执行 Stage 3: 目标创建。."""
    logger.info("=" * 70)
    logger.info("[Stage 3] 目标创建")
    logger.info("=" * 70)

    if ctx.api_mode:
        await _create_api_target(ctx)
    else:
        await _create_browser_target(ctx)


async def _create_api_target(ctx: WebRedTeamContext) -> None:
    """API 模式: 创建 HTTPTarget + RateLimitedTarget 包装。."""
    from pyrit.models import PromptRequestPiece
    from pyrit.prompt_target import HTTPTarget

    from pipeline.targets.rate_limited_target import RateLimitedTarget

    config = ctx.api_config
    if config is None:
        raise ValueError("API 模式但 ctx.api_config 为 None")

    logger.info("  [API 模式] 创建 HTTPTarget")
    logger.info(f"    URL: {config.url}")
    logger.info(f"    方法: {config.method}")
    logger.info(f"    响应格式: {config.response_format}")
    if config.response_format == "json":
        logger.info(f"    响应路径: {config.response_json_path}")

    # G1: 构建回调函数 — 多路径尝试 + fallback
    callback = _build_callback(config)

    # 两种构建路径: 原始 HTTP 请求 vs 结构化参数
    if config.raw_request:
        # 方式 A: 从 Burp Suite 原始 HTTP 请求构建
        logger.info("    请求格式: Burp Suite 原始 HTTP 请求")
        http_target = HTTPTarget(
            http_request=config.raw_request,
            prompt_regex_string="{PROMPT}",
            callback_function=callback,
            prompt_request_piece=PromptRequestPiece(role="user"),
        )
    else:
        # 方式 B: 从结构化参数构建原始 HTTP 请求
        logger.info("    请求格式: 结构化参数 (URL + headers + body)")
        raw_request = _build_raw_http_request(config)
        http_target = HTTPTarget(
            http_request=raw_request,
            prompt_regex_string="{PROMPT}",
            callback_function=callback,
            prompt_request_piece=PromptRequestPiece(role="user"),
        )

    # 使用 RateLimitedTarget 包装 (并发信号量 + RPM 限速 + 错误重试)
    rate_limited_target = RateLimitedTarget(
        target=http_target,
        endpoint=config.url,
        max_concurrency=config.max_concurrency,
        max_retries=config.max_retries,
        requests_per_minute=config.max_rpm,
    )

    ctx.target = rate_limited_target  # type: ignore[assignment]

    logger.info("    HTTPTarget 已创建")
    logger.info("    RateLimitedTarget 包装:")
    logger.info(f"      最大并发: {config.max_concurrency}")
    logger.info(f"      最大 RPM: {config.max_rpm or '不限'}")
    logger.info(f"      最大重试: {config.max_retries}")

    logger.info(
        f"Stage 3 (API): HTTPTarget created (url={config.url}, "
        f"rpm={config.max_rpm}, concurrency={config.max_concurrency})"
    )

    # G5: 健康检查 (可选)
    if config.health_check:
        await _health_check(ctx, http_target)


async def _create_browser_target(ctx: WebRedTeamContext) -> None:
    """Browser 模式: 创建 PlaywrightTarget。."""
    from pyrit.prompt_target import PlaywrightTarget

    from web_redteam.interaction.interaction_factory import InteractionFactory

    logger.info("  [Browser 模式] 创建 PlaywrightTarget")

    # 从 profile 生成 interaction_func
    interaction_func = InteractionFactory.create(ctx.profile.interaction)

    # 创建 PlaywrightTarget (原生 API)
    ctx.target = PlaywrightTarget(
        interaction_func=interaction_func,
        page=ctx.page,
        max_requests_per_minute=getattr(ctx.args, "max_rpm", None),
    )

    logger.info("  PlaywrightTarget 已创建")
    logger.info(f"    输入选择器: {ctx.profile.interaction.input.selector}")
    logger.info(f"    发送选择器: {ctx.profile.interaction.send.selector}")
    logger.info(f"    响应选择器: {ctx.profile.interaction.response.selector}")
    logger.info(f"    等待策略: {ctx.profile.interaction.response.wait_strategy}")

    logger.info("Stage 3: PlaywrightTarget created")


def _build_callback(config: Any) -> Any:
    """G1+G2: 构建 HTTPTarget 回调函数 — 多路径导入 + SSE 支持.

    G1: 多路径尝试导入 PyRIT callback, fallback 到自定义实现.
    G2: 根据 response_format 选择 JSON 或 SSE (regex) 回调.

    Args:
        config: APITargetConfig 实例.

    Returns:
        回调函数.
    """
    if config.response_format == "sse":
        # G2: SSE 流式响应 — 使用 regex 匹配 data: 行
        return _get_sse_callback(config.url)

    # G1: JSON 响应 — 多路径尝试导入
    try:
        from pyrit.prompt_target.http_target import (
            get_http_target_json_response_callback_function,
        )
    except ImportError:
        try:
            from pyrit.prompt_target import (
                get_http_target_json_response_callback_function,
            )
        except ImportError:
            # Fallback: 自定义 JSON 路径提取回调
            logger.warning("G1: PyRIT callback import failed, using fallback")
            return _build_fallback_json_callback(config.response_json_path)

    return get_http_target_json_response_callback_function(
        key=config.response_json_path,
    )


def _get_sse_callback(url: str) -> Any:
    """G2: 获取 SSE 流式响应回调.

    尝试导入 PyRIT 原生 regex callback, fallback 到自定义实现.

    Args:
        url: API 端点 URL.

    Returns:
        SSE 回调函数.
    """
    try:
        from pyrit.prompt_target.http_target import (
            get_http_target_regex_matching_callback_function,
        )
    except ImportError:
        try:
            from pyrit.prompt_target import (
                get_http_target_regex_matching_callback_function,
            )
        except ImportError:
            logger.warning("G2: PyRIT SSE callback import failed, using fallback")
            return _build_fallback_sse_callback()

    # SSE 格式: data: {"content": "..."}\n\n
    # 提取 data: 行内容并拼接
    return get_http_target_regex_matching_callback_function(
        pattern=r"data:\s*(.*?)(?:\n\n|$)",
        url=url,
    )


def _build_fallback_json_callback(key: str) -> Any:
    """G1 Fallback: 自定义 JSON 路径提取回调.

    当 PyRIT 原生 callback 无法导入时使用.
    支持 dotted path + array index (如 choices[0].message.content).

    Args:
        key: JSON 提取路径 (如 "choices[0].message.content").

    Returns:
        回调函数.
    """
    import json
    import re

    def callback(response: str) -> str:
        try:
            data = json.loads(response)
        except (json.JSONDecodeError, TypeError):
            return response

        for part in key.split("."):
            if not part:
                continue
            # 处理 array index: key[0]
            match = re.match(r"^(\w+)\[(\d+)\]$", part)
            if match:
                attr, idx = match.groups()
                data = data[attr][int(idx)]
            elif part.startswith("[") and part.endswith("]"):
                data = data[int(part[1:-1])]
            else:
                data = data[part]
        return str(data)

    return callback


def _build_fallback_sse_callback() -> Any:
    """G2 Fallback: 自定义 SSE 响应回调.

    当 PyRIT 原生 regex callback 无法导入时使用.
    提取所有 data: 行内容并拼接.

    Returns:
        回调函数.
    """
    import re

    def callback(response: str) -> str:
        chunks = re.findall(r"data:\s*(.*?)(?:\n\n|$)", response, re.DOTALL)
        # 尝试从每个 chunk 提取 content
        result_parts = []
        for chunk in chunks:
            chunk = chunk.strip()
            if chunk == "[DONE]":
                continue
            try:
                import json

                data = json.loads(chunk)
                content = data.get("content") or data.get("delta", {}).get("content", "")
                if content:
                    result_parts.append(content)
            except (json.JSONDecodeError, TypeError):
                result_parts.append(chunk)
        return "".join(result_parts)

    return callback


async def _health_check(ctx: WebRedTeamContext, http_target: Any) -> None:
    """G5: 发送探针请求验证端点可用性.

    发送一个简单的 "health check" 请求, 验证:
      - 端点可达
      - 认证有效 (非 401/403)
      - 响应格式正确

    Args:
        ctx: WebRedTeamContext.
        http_target: HTTPTarget 实例 (未被 RateLimitedTarget 包装的原始实例).
    """
    from pyrit.models import PromptRequestPiece

    logger.info("  [G5] 发送健康检查探针...")
    try:
        probe_piece = PromptRequestPiece(
            role="user",
            original_value="Hello",
        )
        response = await http_target.send_prompt_async(prompt_request=probe_piece)
        if response:
            logger.info("    [G5] 端点可用, 响应正常")
            logger.info("G5: health check passed")
        else:
            logger.warning("    [G5 警告] 端点返回空响应")
            logger.warning("G5: health check returned empty response")
    except Exception as e:
        error_str = str(e)
        # G7: 区分不可重试错误 (401/403)
        if any(code in error_str for code in ("401", "403")):
            logger.error("    [G5 错误] 认证失败 (401/403), 请检查 --api-key 或 --api-headers")
            logger.error(f"G5: auth failed (401/403): {e}")
        else:
            logger.warning(f"    [G5 警告] 健康检查失败: {e}")
            logger.warning(f"G5: health check failed: {e}")


def _build_raw_http_request(config: Any) -> str:
    """从 APITargetConfig 构建原始 HTTP 请求字符串.

    生成 PyRIT HTTPTarget 可解析的 Burp Suite 格式原始 HTTP 请求。

    Args:
        config: APITargetConfig 实例。

    Returns:
        原始 HTTP 请求字符串 (含 {PROMPT} 占位符)。
    """
    from urllib.parse import urlparse

    parsed = urlparse(config.url)
    host = parsed.netloc
    path = parsed.path or "/"
    if parsed.query:
        path += f"?{parsed.query}"

    # 构建请求头
    header_lines = [f"{config.method} {path} HTTP/1.1"]
    header_lines.append(f"Host: {host}")

    # 确保有 Content-Type
    has_content_type = any(k.lower() == "content-type" for k in config.headers)
    if not has_content_type:
        header_lines.append("Content-Type: application/json")

    # 添加用户自定义请求头
    for k, v in config.headers.items():
        if k.lower() not in ("host", "content-length"):
            header_lines.append(f"{k}: {v}")

    # 添加请求体
    body = config.body_template or ""
    if body:
        header_lines.append(f"Content-Length: {len(body.encode('utf-8'))}")
        header_lines.append("")
        header_lines.append(body)
    else:
        header_lines.append("")

    return "\r\n".join(header_lines)
