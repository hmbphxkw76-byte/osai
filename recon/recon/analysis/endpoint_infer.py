"""
端点推断模块 — 分类 API 端点并推断 Chat API 地址。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

from recon.schema import (
    ApiEndpoint, DynamicRoute, EndpointCategory,
    EndpointType, ApiFormat, Confidence,
)


# ── 端点分类规则 ──

_CATEGORY_RULES = [
    # (路径正则, HTTP方法, 响应Content-Type正则, 分类)
    (r"(?:/chat|/completion|/message|/ask|/query|/generate|/conversation)", None, r"application/json", EndpointCategory.CHAT),
    (r"(?:/login|/auth|/token|/signin|/signup|/register|/oauth)", None, None, EndpointCategory.AUTH),
    (r"(?:/rag|/retriev|/knowledge|/vector|/search|/embedding|/semantic)", None, None, EndpointCategory.RAG),
    (r"(?:/upload|/file|/import|/attachment)", "POST", None, EndpointCategory.UPLOAD),
    (r"(?:/admin|/manage|/dashboard|/panel)", None, None, EndpointCategory.ADMIN),
    (r"(?:/health|/healthz|/ping|/status|/ready|/live)", None, None, EndpointCategory.HEALTH),
    (r"(?:/info|/version|/docs|/openapi|/swagger)", None, None, EndpointCategory.INFO),
    (r"(?:/models|/model|/tags)", None, None, EndpointCategory.MODELS),
    (r"(?:/tool|/tools|/mcp|/function|/plugin)", None, None, EndpointCategory.TOOLS),
    (r"(?:/agent|/orchestrat|/task|/delegat)", None, None, EndpointCategory.AGENT),
    (r"(?:/stream|/sse|/events)", None, None, EndpointCategory.STREAM),
    (r"(?:/debug|/console|/inspect|/trace)", None, None, EndpointCategory.DEBUG),
    (r"\.(?:js|css|png|jpg|svg|ico|woff|ttf|map)$", None, None, EndpointCategory.STATIC),
]


# ── Chat 端点推断优先级模式 ──

_CHAT_ENDPOINT_PATTERNS = [
    # (API格式, 路径模式, 置信度加成)
    (ApiFormat.OPENAI_CHAT.value,     r"/v1/chat/completions$", 0.40),
    (ApiFormat.OPENAI_CHAT.value,     r"/v1/chat$",              0.35),
    (ApiFormat.OPENAI_COMPLETION.value, r"/v1/completions$",      0.35),
    (ApiFormat.OPENAI_CHAT.value,     r"/chat/completions$",     0.35),
    (ApiFormat.ANTHROPIC_MESSAGES.value, r"/v1/messages$",       0.35),
    (ApiFormat.OPENAI_CHAT.value,     r"/api/chat/completions$", 0.30),
    (ApiFormat.RAW_JSON.value,        r"/api/chat$",             0.25),
    (ApiFormat.RAW_JSON.value,        r"/api/generate$",         0.25),
    (ApiFormat.RAW_JSON.value,        r"/chat$",                 0.20),
    (ApiFormat.RAW_JSON.value,        r"/ai/chat$",              0.20),
    (ApiFormat.RAW_JSON.value,        r"/ask$",                  0.15),
    (ApiFormat.RAW_JSON.value,        r"/query$",                0.15),
    (ApiFormat.RAW_JSON.value,        r"/message$",              0.15),
    (ApiFormat.RAW_JSON.value,        r"/conversation$",         0.10),
]


@dataclass
class InferenceResult:
    """端点推断结果。"""
    chat_api_url: str = ""
    api_format: str = ApiFormat.RAW_JSON.value
    endpoint_type: str = EndpointType.UNKNOWN.value
    confidence: float = 0.0
    evidence: list[str] = field(default_factory=list)


class EndpointInferrer:
    """API 端点分类器和 Chat 端点推断器。"""

    def classify_endpoint(self, network_entry: dict) -> ApiEndpoint:
        """根据网络请求信息分类端点。

        Args:
            network_entry: 来自 TrafficCapture 或 DictScanner 的端点信息
                {url, method, status, content_type, body, body_snippet, ...}
        """
        url = network_entry.get("url", "")
        method = network_entry.get("method", "GET")
        status = network_entry.get("status", 0)
        content_type = network_entry.get("content_type", "")

        # 提取路径
        path = self._extract_path(url)

        # 分类
        category = EndpointCategory.UNKNOWN.value
        for path_regex, req_method, ct_regex, cat in _CATEGORY_RULES:
            if re.search(path_regex, path, re.IGNORECASE):
                if req_method and method.upper() != req_method.upper():
                    continue
                if ct_regex and not re.search(ct_regex, content_type, re.IGNORECASE):
                    continue
                category = cat.value
                break

        # 置信度
        if category != EndpointCategory.UNKNOWN.value:
            confidence = Confidence.MEDIUM.value
        else:
            confidence = Confidence.LOW.value

        # 判断是否为 chat 端点
        is_chat = category == EndpointCategory.CHAT.value and method.upper() == "POST"

        # 判断是否需要认证
        requires_auth = status in (401, 403)

        return ApiEndpoint(
            path=path,
            full_url=url,
            method=method,
            status=status,
            content_type=content_type,
            category=category,
            is_chat_endpoint=is_chat,
            requires_auth=requires_auth,
            confidence=confidence,
            response_time_ms=network_entry.get("response_time_ms", 0.0),
            body_snippet=network_entry.get("body_snippet", "") or network_entry.get("body", "")[:300],
        )

    def infer_chat_endpoint(
        self,
        endpoints: list[ApiEndpoint],
        base_url: str = "",
    ) -> InferenceResult:
        """从已发现的端点列表中推断最可能的 Chat API 端点。

        策略：
        1. 优先选择已标记 is_chat_endpoint=True 且返回 200 的
        2. 按 _CHAT_ENDPOINT_PATTERNS 路径模式匹配评分
        3. 降级到选择第一个返回 200 的 POST JSON 端点
        4. 兜底到 base_url + /v1/chat/completions
        """
        result = InferenceResult()

        # 策略 1: 已有的 chat 端点
        chat_eps = [ep for ep in endpoints if ep.is_chat_endpoint and ep.status == 200]
        if chat_eps:
            best = chat_eps[0]
            result.chat_api_url = best.full_url
            result.api_format = self._guess_api_format(best.path, best.content_type)
            result.confidence = 0.90
            result.evidence = [f"chat endpoint (status=200): {best.path}"]
            return result

        # 策略 2: 路径模式评分
        scored = []
        for ep in endpoints:
            if ep.status != 200:
                continue
            for api_fmt, pattern, score in _CHAT_ENDPOINT_PATTERNS:
                if re.search(pattern, ep.path, re.IGNORECASE):
                    scored.append((ep, api_fmt, score))

        if scored:
            scored.sort(key=lambda x: x[2], reverse=True)
            best_ep, api_fmt, score = scored[0]
            result.chat_api_url = best_ep.full_url
            result.api_format = api_fmt
            result.confidence = min(0.30 + score, 0.85)
            result.evidence = [f"pattern match: {best_ep.path} → {api_fmt} (score={score:.2f})"]
            return result

        # 策略 3: 第一个返回 200 的 POST JSON 端点
        for ep in endpoints:
            if ep.status == 200 and ep.method.upper() == "POST" and "json" in ep.content_type.lower():
                result.chat_api_url = ep.full_url
                result.api_format = ApiFormat.RAW_JSON.value
                result.confidence = 0.50
                result.evidence = [f"first 200 POST JSON: {ep.path}"]
                return result

        # 策略 4: 兜底猜测
        result.chat_api_url = f"{base_url}/v1/chat/completions"
        result.api_format = ApiFormat.OPENAI_CHAT.value
        result.confidence = 0.10
        result.evidence = ["fallback guess"]
        return result

    def infer_dynamic_routes(
        self,
        endpoints: list[ApiEndpoint],
        base_url: str = "",
    ) -> list[DynamicRoute]:
        """从端点列表中推断动态路由模式。

        识别路径中的参数占位符（如 hex ID、UUID、数字 ID），
        生成可供字典攻击使用的路由模式。
        """
        routes = []
        seen_patterns = set()

        for ep in endpoints:
            path = ep.path
            if not path or path == "/":
                continue

            # 检测 hex ID 段 (12/16/24/32位)
            hex_match = re.search(r"/([0-9a-fA-F]{12})(?:/|$)", path)
            if hex_match:
                pattern = path.replace(hex_match.group(1), "{hex_id:12}")
                if pattern not in seen_patterns:
                    seen_patterns.add(pattern)
                    routes.append(DynamicRoute(
                        pattern=pattern,
                        method=ep.method,
                        sample_value=hex_match.group(1),
                        inferred_from=f"hex segment in {ep.path}",
                        confidence=Confidence.HIGH.value,
                    ))

            # 检测 UUID
            uuid_match = re.search(
                r"/([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})(?:/|$)",
                path,
            )
            if uuid_match:
                pattern = path.replace(uuid_match.group(1), "{uuid}")
                if pattern not in seen_patterns:
                    seen_patterns.add(pattern)
                    routes.append(DynamicRoute(
                        pattern=pattern,
                        method=ep.method,
                        sample_value=uuid_match.group(1),
                        inferred_from=f"uuid segment in {ep.path}",
                        confidence=Confidence.HIGH.value,
                    ))

            # 检测纯数字 ID
            num_match = re.search(r"/(\d{1,10})(?:/|$)", path)
            if num_match and not hex_match:
                pattern = path.replace(num_match.group(1), "{id}")
                if pattern not in seen_patterns:
                    seen_patterns.add(pattern)
                    routes.append(DynamicRoute(
                        pattern=pattern,
                        method=ep.method,
                        sample_value=num_match.group(1),
                        inferred_from=f"numeric id in {ep.path}",
                        confidence=Confidence.MEDIUM.value,
                    ))

        return routes

    # ── 辅助方法 ──

    @staticmethod
    def _extract_path(url: str) -> str:
        """从完整 URL 提取路径部分。"""
        if "://" in url:
            path = re.sub(r"https?://[^/]+", "", url)
            return path or "/"
        return url if url.startswith("/") else f"/{url}"

    @staticmethod
    def _guess_api_format(path: str, content_type: str) -> str:
        """根据路径和 Content-Type 推测 API 格式。"""
        path_lower = path.lower()
        if "/v1/chat/completions" in path_lower:
            return ApiFormat.OPENAI_CHAT.value
        if "/v1/completions" in path_lower:
            return ApiFormat.OPENAI_COMPLETION.value
        if "/v1/messages" in path_lower:
            return ApiFormat.ANTHROPIC_MESSAGES.value
        if "/api/chat" in path_lower or "/api/generate" in path_lower:
            if "application/json" in content_type:
                return ApiFormat.RAW_JSON.value
            return ApiFormat.RAW_FORM.value
        if "/chat" in path_lower:
            return ApiFormat.RAW_JSON.value
        return ApiFormat.RAW_JSON.value
