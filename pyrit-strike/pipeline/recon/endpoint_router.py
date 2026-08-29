"""多端点 Burp 请求路由 — 为每个端点构建独立的 HTTPTarget。
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from pipeline.recon.burp_parser import (
    JSONSafeHTTPTarget,
    ParsedBurpRequest,
    build_raw_http_request,
)
from pipeline.targets.rate_limited import RateLimitedTarget

logger = logging.getLogger(__name__)

def build_endpoint_request(
    base_parsed: ParsedBurpRequest,
    endpoint_path: str,
    *,
    method: str = "POST",
    body_template: str | None = None,
    placeholder_position: str = "body",
) -> ParsedBurpRequest:
    """为单个端点构建 ParsedBurpRequest。
    """
    # 继承原始 headers (排除 Content-Length, 会自动重建)
    raw_headers = [
        (k, v) for k, v in base_parsed.raw_headers
        if k.lower() not in ("content-length", "host")
    ]

    # 根据 placeholder_position 构建路径和 body
    if placeholder_position == "path":
        # {PROMPT} 在路径中 (如 /api/v1/user/{PROMPT})
        final_path = endpoint_path.rstrip("/") + "/{PROMPT}"
        body = ""
    elif placeholder_position == "query":
        # {PROMPT} 在查询参数中 (如 /api/v1/search?q={PROMPT})
        sep = "&" if "?" in endpoint_path else "?"
        final_path = f"{endpoint_path}{sep}q={{PROMPT}}"
        body = ""
    else:
        # {PROMPT} 在 body 中 (默认)
        final_path = endpoint_path
        if body_template:
            body = body_template
        else:
            # 自动生成常见 body 格式
            body = json.dumps({"prompt": "{PROMPT}"}, ensure_ascii=False)

    return ParsedBurpRequest(
        method=method,
        url=f"{'https' if base_parsed.use_tls else 'http'}://{base_parsed.host}{final_path}",
        host=base_parsed.host,
        path=final_path,
        headers=dict(base_parsed.headers),
        raw_headers=raw_headers,
        body=body,
        use_tls=base_parsed.use_tls,
        is_sse=False,
        http_version=base_parsed.http_version,
        has_prompt_placeholder=True,
        target_fingerprint=dict(base_parsed.target_fingerprint),
    )

def build_endpoint_target(
    parsed: ParsedBurpRequest,
) -> RateLimitedTarget:
    """为单个端点构建 RateLimitedTarget 包装的 HTTPTarget。
    """
    raw_request = build_raw_http_request(parsed)

    # 使用原始响应回调 — 直接返回 response.text
    # 传统 Web 漏洞的响应可能是 HTML/JSON/纯文本, 不做路径假设
    def _raw_response_callback(response: Any) -> str:
        """返回原始响应文本。"""
        if hasattr(response, "text") and response.text:
            return response.text
        if hasattr(response, "content"):
            if isinstance(response.content, bytes):
                return response.content.decode("utf-8", errors="replace")
            return str(response.content)
        return str(response)

    target = JSONSafeHTTPTarget(
        http_request=raw_request,
        prompt_regex_string="{PROMPT}",
        callback_function=_raw_response_callback,
        use_tls=parsed.use_tls,
        timeout=120.0,
        follow_redirects=True,
        verify=False,  # 黑盒场景: 跳过 TLS 验证
    )

    return RateLimitedTarget(
        target=target,
        max_concurrency=3,
        max_retries=2,
    )

def create_endpoint_targets(
    base_parsed: ParsedBurpRequest,
    endpoint_configs: list[dict[str, Any]],
) -> dict[str, RateLimitedTarget]:
    """为多个端点批量构建 HTTPTarget。
    """
    targets: dict[str, RateLimitedTarget] = {}

    for config in endpoint_configs:
        path = config.get("path", "")
        method = config.get("method", "POST")
        body_template = config.get("body_template")
        placeholder_pos = config.get("placeholder_position", "body")

        if not path:
            continue

        parsed = build_endpoint_request(
            base_parsed,
            path,
            method=method,
            body_template=body_template,
            placeholder_position=placeholder_pos,
        )

        target = build_endpoint_target(parsed)
        targets[path] = target
        logger.info(
            "Built target for endpoint: %s %s (placeholder=%s)",
            method, path, placeholder_pos,
        )

    return targets

def generate_burp_request_files(
    base_parsed: ParsedBurpRequest,
    endpoints: list[dict[str, Any]],
    output_dir: Path,
) -> list[Path]:
    """为每个端点生成独立的 Burp 请求文件。
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    files: list[Path] = []

    for ep in endpoints:
        path = ep.get("path", "")
        method = ep.get("method", "POST")
        body_template = ep.get("body_template")
        placeholder_pos = ep.get("placeholder_position", "body")

        parsed = build_endpoint_request(
            base_parsed, path,
            method=method,
            body_template=body_template,
            placeholder_position=placeholder_pos,
        )
        raw_request = build_raw_http_request(parsed)

        # 文件名: endpoint_api_v1_search.txt
        safe_name = path.replace("/", "_").strip("_")
        file_path = output_dir / f"endpoint_{safe_name}.txt"
        file_path.write_text(raw_request, encoding="utf-8")
        files.append(file_path)
        logger.info("Generated Burp request file: %s", file_path)

    return files
