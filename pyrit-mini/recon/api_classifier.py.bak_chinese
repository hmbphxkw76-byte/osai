"""API 端点类别检测 — 区分 chat / metadata / unknown。

策略:
    1. 路径关键词匹配 (优先)
    2. body 结构分析 (fallback)
       - body 含 prompt/query/messages → chat
       - body 为空或 GET 请求 → metadata
       - body 无法判断 → unknown
"""

from __future__ import annotations

import json

# metadata API 路径关键词 (不注入 {PROMPT}, 仅提取信息)
_METADATA_PATH_KEYWORDS = [
    "/model/list", "/models", "/model_list",
    "/user/info", "/user/profile", "/userinfo",
    "/config", "/settings",
    "/health", "/status", "/version",
    "/.well-known/", "/agent.json",
    "/auth", "/login", "/token",
]

# chat API 路径关键词 (可注入 {PROMPT})
_CHAT_PATH_KEYWORDS = [
    "/chat", "/completion", "/completions", "/conversation",
    "/message", "/ask", "/query",
    "/prompt", "/generate", "/inference",
]


def detect_api_category(path: str, body: str) -> str:
    """检测 API 端点类别: chat / metadata / unknown。

    Args:
        path: HTTP 请求路径 (如 /api/v1/model/list)。
        body: HTTP 请求 body 字符串。

    Returns:
        "chat" / "metadata" / "unknown"
    """
    path_lower = path.lower()

    # 策略1: 路径关键词匹配 (优先)
    for keyword in _METADATA_PATH_KEYWORDS:
        if keyword in path_lower:
            return "metadata"

    for keyword in _CHAT_PATH_KEYWORDS:
        if keyword in path_lower:
            return "chat"

    # 策略2: body 结构分析
    if body and body.strip():
        try:
            data = json.loads(body)
            if isinstance(data, dict):
                data_str = json.dumps(data).lower()
                if any(kw in data_str for kw in ["prompt", "query", "message", "input", "ask", "question"]):
                    return "chat"
                return "unknown"
        except (json.JSONDecodeError, TypeError):
            pass
    else:
        # 无 body (通常 GET 请求) → metadata
        return "metadata"

    return "unknown"
