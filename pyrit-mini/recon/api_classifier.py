"""API - chat / metadata / unknown

:
    1.  ()
    2. body  (fallback)
       - body  prompt/query/messages -> chat
       - body  GET  -> metadata
       - body  -> unknown
"""

from __future__ import annotations

import json

# metadata API ( {PROMPT}, )
_METADATA_PATH_KEYWORDS = [
    "/model/list", "/models", "/model_list",
    "/user/info", "/user/profile", "/userinfo",
    "/config", "/settings",
    "/health", "/status", "/version",
    "/.well-known/", "/agent.json",
    "/auth", "/login", "/token",
]

# chat API ( {PROMPT})
_CHAT_PATH_KEYWORDS = [
    "/chat", "/completion", "/completions", "/conversation",
    "/message", "/ask", "/query",
    "/prompt", "/generate", "/inference",
]

def detect_api_category(path: str, body: str) -> str:
    """ API : chat / metadata / unknown

    Args:
        path: HTTP  ( /api/v1/model/list)
        body: HTTP  body

    Returns:
        "chat" / "metadata" / "unknown"
    """
    path_lower = path.lower()

 # 1: ()
    for keyword in _METADATA_PATH_KEYWORDS:
        if keyword in path_lower:
            return "metadata"

    for keyword in _CHAT_PATH_KEYWORDS:
        if keyword in path_lower:
            return "chat"

 # 2: body
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
     # body ( GET ) -> metadata
        return "metadata"

    return "unknown"
