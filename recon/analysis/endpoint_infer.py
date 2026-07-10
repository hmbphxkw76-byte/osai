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
    # Chat 类: 覆盖单复数形式的对话/会话/线程端点
    (r"(?:/chat|/chats|/completion|/message|/messages|/ask|/query|/generate|/conversation|/conversations|/thread|/threads)", None, r"application/json", EndpointCategory.CHAT),
    (r"(?:/login|/auth|/token|/signin|/signup|/register|/oauth)", None, None, EndpointCategory.AUTH),
    (r"(?:/login|/auth|/token|/signin|/signup|/register|/oauth)", None, r"application/json", EndpointCategory.AUTH),
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

# RESTful Chat 资源模式 — POST 创建 + GET 获取的复合端点
_RESTFUL_CHAT_PATTERNS = [
    # (API格式, 集合路径正则, 单项路径正则, 置信度加成)
    (ApiFormat.RAW_JSON.value, r"/api/v\d+/conversations?$",     r"/api/v\d+/conversations?/\w+$",                  0.35),
    (ApiFormat.RAW_JSON.value, r"/api/v\d+/chats?$",            r"/api/v\d+/chats?/\w+$",                         0.35),
    (ApiFormat.RAW_JSON.value, r"/api/v\d+/threads?$",          r"/api/v\d+/threads?/\w+$",                       0.35),
    (ApiFormat.RAW_JSON.value, r"/api/v\d+/sessions?$",         r"/api/v\d+/sessions?/\w+$",                      0.30),
    (ApiFormat.RAW_JSON.value, r"/api/v\d+/messages?$",         r"/api/v\d+/messages?/\w+$",                      0.30),
    (ApiFormat.RAW_JSON.value, r"/api/conversations?$",         r"/api/conversations?/\w+$",                       0.30),
    (ApiFormat.RAW_JSON.value, r"/api/chats?$",                 r"/api/chats?/\w+$",                               0.30),
    (ApiFormat.RAW_JSON.value, r"/api/threads?$",               r"/api/threads?/\w+$",                             0.30),
    (ApiFormat.RAW_JSON.value, r"/api/sessions?$",              r"/api/sessions?/\w+$",                            0.25),
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
    # RESTful 资源模式
    (ApiFormat.RAW_JSON.value,        r"/api/v\d+/conversations?$",  0.28),
    (ApiFormat.RAW_JSON.value,        r"/api/v\d+/chats?$",         0.28),
    (ApiFormat.RAW_JSON.value,        r"/api/v\d+/threads?$",       0.28),
    (ApiFormat.RAW_JSON.value,        r"/api/v\d+/messages?$",      0.25),
    (ApiFormat.RAW_JSON.value,        r"/api/v\d+/sessions?$",      0.22),
    (ApiFormat.RAW_JSON.value,        r"/api/conversations?$",      0.25),
    (ApiFormat.RAW_JSON.value,        r"/api/chats?$",              0.25),
    (ApiFormat.RAW_JSON.value,        r"/api/threads?$",            0.25),
    (ApiFormat.RAW_JSON.value,        r"/api/messages?$",           0.22),
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

        # 判断是否为 chat 端点（放宽到 GET/POST，覆盖 RESTful 资源模式）
        is_chat = self._is_chat_endpoint(path, method, category, status, content_type)

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

    @staticmethod
    def _is_chat_endpoint(path: str, method: str, category: str, status: int, content_type: str) -> bool:
        """智能判断端点是否为 AI Chat 端点。

        覆盖两种模式：
        A. 经典 Chat API: POST + 固定路径 (如 /v1/chat/completions)
        B. RESTful Chat API: POST 创建资源 + GET 获取会话/消息
           (如 POST /api/v1/conversations + GET /api/v1/conversations/{id})

        判定规则：
        1. 分类为 CHAT 且状态码 200 的方法（GET/POST 均可）
        2. RESTful 资源模式匹配（POST 集合 + GET 单个资源）
        3. 有 JSON 响应体的会话/消息/线程相关端点
        """
        if status != 200:
            return False

        # 规则 1: 分类器已识别为 CHAT 类别
        if category == EndpointCategory.CHAT.value:
            return True

        # 规则 2: RESTful 资源模式检测
        for _, collection_pat, item_pat, _ in _RESTFUL_CHAT_PATTERNS:
            if re.search(collection_pat, path, re.IGNORECASE) and method.upper() == "POST":
                return True
            if re.search(item_pat, path, re.IGNORECASE) and method.upper() in ("GET", "POST"):
                return True

        # 规则 3: 包含对话关键路径 + JSON 响应（捕获未被规则1命中的端点）
        chat_keywords = ["conversation", "chat", "thread", "message", "session"]
        path_lower = path.lower()
        if any(kw in path_lower for kw in chat_keywords):
            if "json" in content_type.lower():
                return True

        return False

    def infer_chat_endpoint(
        self,
        endpoints: list[ApiEndpoint],
        base_url: str = "",
    ) -> InferenceResult:
        """从已发现的端点列表中推断最可能的 Chat API 端点。

        策略（按优先级降序）：
        1. 优先选择已标记 is_chat_endpoint=True 且 POST 的（直接可攻击）
        2. RESTful 资源模式的 POST 集合端点（如 POST /api/v1/conversations）
        3. 按 _CHAT_ENDPOINT_PATTERNS 路径模式匹配评分
        4. 降级到选择第一个返回 200 的 POST JSON 端点
        5. 兜底到 base_url + /v1/chat/completions
        """
        result = InferenceResult()

        # 策略 1: 已有的 chat 端点（POST 优先）
        chat_eps = [ep for ep in endpoints if ep.is_chat_endpoint and ep.status == 200]
        post_chat = [ep for ep in chat_eps if ep.method.upper() == "POST"]
        if post_chat:
            best = post_chat[0]
            result.chat_api_url = best.full_url
            result.api_format = self._guess_api_format(best.path, best.content_type)
            result.confidence = 0.90
            result.evidence = [f"chat endpoint POST (status=200): {best.path}"]
            return result

        # 策略 2: RESTful 资源模式的 POST 集合端点
        for ep in endpoints:
            if ep.status != 200 or ep.method.upper() != "POST":
                continue
            for _, collection_pat, _, _ in _RESTFUL_CHAT_PATTERNS:
                if re.search(collection_pat, ep.path, re.IGNORECASE):
                    result.chat_api_url = ep.full_url
                    result.api_format = ApiFormat.RAW_JSON.value
                    result.confidence = 0.75
                    result.evidence = [f"RESTful chat collection POST: {ep.path}"]
                    return result

        # 策略 3: 路径模式评分
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

        # 策略 4: 第一个返回 200 的 POST JSON 端点
        for ep in endpoints:
            if ep.status == 200 and ep.method.upper() == "POST" and "json" in ep.content_type.lower():
                result.chat_api_url = ep.full_url
                result.api_format = ApiFormat.RAW_JSON.value
                result.confidence = 0.50
                result.evidence = [f"first 200 POST JSON: {ep.path}"]
                return result

        # 策略 5: 兜底猜测
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

        增加 RESTful 资源模式推断:
        - 当同时发现 POST /api/v1/conversations 和 GET /api/v1/conversations/{id}
          时，推断为标准的 RESTful CRUD 资源
        """
        routes = []
        seen_patterns = set()

        for ep in endpoints:
            path = ep.path
            if not path or path == "/":
                continue

            # 检测 hex ID 段 (8/12/16/24/32位)
            hex_match = re.search(r"/([0-9a-fA-F]{8,32})(?:/|$)", path)
            if hex_match:
                hex_val = hex_match.group(1)
                hex_len = len(hex_val)
                pattern = path.replace(hex_val, f"{{hex_id:{hex_len}}}")
                if pattern not in seen_patterns:
                    seen_patterns.add(pattern)
                    routes.append(DynamicRoute(
                        pattern=pattern,
                        method=ep.method,
                        sample_value=hex_val,
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

        # ── RESTful 资源模式推断 ──
        # 当存在 POST /api/v1/X 和 GET /api/v1/X/{id} 时，标记为 RESTful 资源
        resource_patterns = self._infer_restful_resources(endpoints, routes)
        for rp in resource_patterns:
            if rp.pattern not in seen_patterns:
                seen_patterns.add(rp.pattern)
                routes.append(rp)

        return routes

    @staticmethod
    def _infer_restful_resources(
        endpoints: list[ApiEndpoint],
        existing_routes: list[DynamicRoute],
    ) -> list[DynamicRoute]:
        """推断 RESTful 资源模式 — 匹配 POST 集合 + GET/GET by ID 的组合。

        例如:
          POST /api/v1/conversations        (创建)
          GET  /api/v1/conversations/{id}   (获取单个)
        → 推断这是一个 RESTful 资源，PyRIT 可以用 CRUD 模式攻击
        """
        resources = []

        # 先收集 POST 端点路径（集合端点）
        collection_paths = set()
        for ep in endpoints:
            if ep.method.upper() == "POST" and ep.status in (200, 201):
                path = ep.path.rstrip("/")
                if path and path != "/":
                    collection_paths.add(path)

        # 查看是否存在对应的 GET by ID 端点
        for coll_path in collection_paths:
            for route in existing_routes:
                route_prefix = route.pattern.split("{")[0].rstrip("/")
                if route_prefix == coll_path:
                    # 找到匹配的集合+单项配对
                    resources.append(DynamicRoute(
                        pattern=f"{coll_path}/{{resource_id}}",
                        method="GET",
                        sample_value=route.sample_value,
                        inferred_from=(
                            f"RESTful resource: POST {coll_path} + "
                            f"GET {route.pattern} (from {route.inferred_from})"
                        ),
                        confidence=Confidence.HIGH.value,
                    ))

        # 去重
        seen = set()
        unique = []
        for r in resources:
            if r.pattern not in seen:
                seen.add(r.pattern)
                unique.append(r)
        return unique

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
