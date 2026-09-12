"""recon/graphql_probe.py — GraphQL introspection 探测与 schema 提取（REQ-161 ①）。

职责（recon 层，只探测不攻击）：
    - 判定目标是否为 GraphQL 端点（路径/方法/请求体/响应体四类信号）；
    - 构造标准 introspection 查询；
    - 解析 introspection 响应 → 类型 / Query / Mutation / 是否开启 introspection。

设计约束：
    - 纯函数优先（`is_graphql_signal` / `build_introspection_query` /
      `summarize_introspection` 无 IO，便于单测）；
    - 网络探测（`probe_graphql_endpoint`）仅用 httpx，结果收敛进
      `target_fingerprint`，不新建并行通道（I12）；
    - 失败不抛异常，返回 `GraphQLSchemaSummary(detected=False, ...)`。

学术/标准依据：
    - GraphQL 官方 introspection 规范（`__schema` / `__type`）。
    - OWASP API Security Top 10 2023 API7/API9（GraphQL introspection 暴露）。
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

# 常见 GraphQL 端点路径（供端点发现复用）
GRAPHQL_PATHS: tuple[str, ...] = (
    "/graphql",
    "/api/graphql",
    "/v1/graphql",
    "/v2/graphql",
    "/gql",
    "/query",
    "/api/query",
)

# 响应体/请求体中的 GraphQL 特征词
_GRAPHQL_BODY_MARKERS: tuple[str, ...] = (
    "__schema",
    "__typename",
    "mutation",
    "query {",
    '"data":',
    "graphql",
)


@dataclass
class GraphQLSchemaSummary:
    """GraphQL introspection 结果摘要。"""

    detected: bool = False
    endpoint: str | None = None
    introspection_enabled: bool = False
    types: list[str] = field(default_factory=list)
    queries: list[str] = field(default_factory=list)
    mutations: list[str] = field(default_factory=list)
    subscriptions: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)


def is_graphql_signal(
    path: str = "",
    body: str = "",
    headers: dict[str, str] | None = None,
    content_type: str = "",
) -> bool:
    """Heuristic GraphQL endpoint detection from request/response artefacts.

    Signals (any one is sufficient):
        - path contains a known GraphQL path;
        - `Content-Type: application/graphql` or `application/json` + body markers;
        - request/response body contains `__schema` / `__typename` / `query {`.
    """
    path_lower = (path or "").lower().split("?")[0]
    if any(path_lower.endswith(gp) or path_lower == gp for gp in GRAPHQL_PATHS):
        return True
    if "graphql" in path_lower:
        return True

    ctype = (content_type or "").lower()
    if "application/graphql" in ctype:
        return True
    if headers:
        for key, value in headers.items():
            if key.lower() == "content-type" and "graphql" in str(value).lower():
                return True

    body_lower = (body or "").lower()
    if "__schema" in body_lower or "__typename" in body_lower:
        return True
    if '"query"' in body_lower or "query {" in body_lower or "mutation {" in body_lower:
        return True
    return False


def build_introspection_query() -> str:
    """Standard full introspection query (POST body for `{"query": ...}`)."""
    return (
        "{ __schema { queryType { name } mutationType { name } "
        "subscriptionType { name } types { kind name fields { name } } } }"
    )


def build_introspection_request() -> dict[str, Any]:
    """JSON body for an introspection request."""
    return {"query": build_introspection_query(), "operationName": None, "variables": {}}


def summarize_introspection(payload: Any, endpoint: str | None = None) -> GraphQLSchemaSummary:
    """Parse an introspection response into a compact summary.

    Accepts a decoded JSON object (dict) or a raw JSON string. Never raises.
    """
    summary = GraphQLSchemaSummary(endpoint=endpoint)
    if payload is None:
        return summary

    if isinstance(payload, (str, bytes)):
        try:
            payload = json.loads(payload)
        except (json.JSONDecodeError, TypeError):
            return summary
    if not isinstance(payload, dict):
        return summary

    # GraphQL errors often reveal introspection being disabled
    errors = payload.get("errors")
    if isinstance(errors, list) and errors:
        summary.evidence.append("graphql_errors_present")

    schema = ((payload.get("data") or {}) if isinstance(payload.get("data"), dict) else {}).get("__schema")
    if not isinstance(schema, dict):
        if errors:
            summary.detected = True
            summary.introspection_enabled = False
            summary.evidence.append("introspection_disabled_or_blocked")
        return summary

    summary.detected = True
    summary.introspection_enabled = True
    summary.evidence.append("__schema_returned")

    for type_entry in schema.get("types") or []:
        if not isinstance(type_entry, dict):
            continue
        name = str(type_entry.get("name") or "")
        if not name or name.startswith("__"):
            continue
        summary.types.append(name)
        if name == str((schema.get("queryType") or {}).get("name") or "Query"):
            summary.queries = _field_names(type_entry)
        elif name == str((schema.get("mutationType") or {}).get("name") or "Mutation"):
            summary.mutations = _field_names(type_entry)
        elif name == str((schema.get("subscriptionType") or {}).get("name") or "Subscription"):
            summary.subscriptions = _field_names(type_entry)

    summary.types = sorted(set(summary.types))
    return summary


def _field_names(type_entry: dict[str, Any]) -> list[str]:
    return sorted(
        str(f.get("name")) for f in (type_entry.get("fields") or []) if isinstance(f, dict) and f.get("name")
    )


async def probe_graphql_endpoint(  # pragma: no cover - network path (Tier 2)
    base_url: str,
    *,
    timeout: float = 5.0,
    verify: bool = True,
    headers: dict[str, str] | None = None,
) -> GraphQLSchemaSummary:
    """Actively probe candidate GraphQL endpoints with an introspection request.

    Network path — exercised in Tier 2 / mock range, not in unit tests. Returns a
    negative summary on any failure (never raises).
    """
    try:
        import httpx
    except ImportError:  # pragma: no cover
        logger.warning("[GraphQL] httpx unavailable; skipping probe")
        return GraphQLSchemaSummary()

    request_headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if headers:
        request_headers.update(headers)

    base = base_url.rstrip("/")
    async with httpx.AsyncClient(timeout=timeout, verify=verify) as client:
        for path in GRAPHQL_PATHS:
            url = f"{base}{path}"
            try:
                resp = await client.post(url, json=build_introspection_request(), headers=request_headers)
            except Exception as e:
                logger.debug("[GraphQL] probe %s failed: %s", url, e)
                continue
            if resp.status_code >= 400:
                continue
            summary = summarize_introspection(resp.text, endpoint=url)
            if summary.detected:
                logger.info("[GraphQL] introspection detected at %s (types=%d)", url, len(summary.types))
                return summary
    return GraphQLSchemaSummary()
