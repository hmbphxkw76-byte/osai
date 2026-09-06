"""Prompt 占位符注入 & 会话 ID 自动管理。

职责:
    1. JSON body 中自动检测 prompt 字段并注入 {PROMPT} 占位符
    2. 会话 ID 字段检测与 {CHAT_ID} 占位符注入
    3. 从 Burp Response 中提取会话 ID (ChatId / Object / session_id)
    4. 从 Burp Response 中提取模型信息 (模型名称 / 模型列表)
    5. 从 Burp Request body 中提取原始 prompt 值 (侦察分析用)
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any

logger = logging.getLogger(__name__)

# 会话 ID 字段名匹配列表 (大小写不敏感)
_CHAT_ID_FIELD_NAMES = frozenset({
    "chatid", "chat_id", "chatidvalue", "chatsessionid", "chat_session_id",
    "sessionid", "session_id", "sessionidvalue",
    "conversationid", "conversation_id", "convid", "conv_id",
    "dialogid", "dialog_id",
    "threadid", "thread_id",
    "req_id", "requestid", "request_id",
})

# SSE/JSON Response 中会话 ID 提取的候选 JSON 字段名 (优先级递减)
_RESPONSE_ID_FIELDS = [
    "Object",
    "chat_session_id", "chatsessionid",
    "session_id", "sessionid",
    "Id", "ChatId", "ConversationId", "ConvId",
]

# 候选模型名称 JSON 字段名 (大小写不敏感匹配)
_MODEL_NAME_FIELDS = [
    "displayModelName", "model_name", "modelName", "modelCode",
    "model_type", "modelType", "model", "usedModel",
]

# 模型列表 API 响应中的数组字段名 (大小写不敏感)
_MODEL_LIST_ARRAY_FIELDS = [
    "data", "models", "model_list", "modelList",
]

# ── 启发式评分相关常量 ──
_PROMPT_NAME_HINTS = frozenset({
    "prompt", "query", "input", "message", "ask", "question",
    "text", "content", "instruction", "command", "request",
    "user", "chat", "msg", "q",
})

_NON_PROMPT_PATTERNS = [
    re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I),
    re.compile(r"^[a-zA-Z0-9_/-]{20,}$"),
    re.compile(r"^https?://"),
    re.compile(r"^/\w"),
    re.compile(r"^\d+$"),
]

_NON_PROMPT_VALUES = frozenset({
    "", "true", "false", "null", "none",
    "user", "assistant", "system", "function",
})


def infer_tls(path: str, headers: dict[str, str]) -> bool:
    """从 URL scheme 或 TLS header 推断。"""
    if path.startswith("https://"):
        return True
    if path.startswith("http://"):
        return False
    host = headers.get("host", "")
    if "localhost" in host or "127.0.0.1" in host or "0.0.0.0" in host:
        return False
    return headers.get("x-forwarded-proto", "https") == "https"


def build_full_url(path: str, host: str, use_tls: bool) -> str:
    """构建完整 URL。"""
    if path.startswith(("http://", "https://")):
        return path
    scheme = "https" if use_tls else "http"
    return f"{scheme}://{host}{path}"


def inject_prompt_placeholder(body: str) -> str:
    """自动注入 {PROMPT} 占位符到 JSON body。

    通用启发式策略 (不依赖硬编码字段名列表):
        1. OpenAI messages 数组: 替换最后一条 user message 的 content
        2. 递归深层搜索: 对 JSON body 进行递归遍历, 在所有嵌套层级中
           找到"最可能是用户输入 prompt"的字段并替换其值为 "{PROMPT}"
        3. 顶层字段值评分: 对 JSON body 顶层每个 string 字段进行评分
        4. 无合适候选时: 添加 "prompt": "{PROMPT}" 作为 fallback
    """
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        return body

    if not isinstance(data, dict):
        return body

    # ── 策略1: OpenAI messages 数组格式 (大小写不敏感) ──
    messages_key = _find_key_ci(data, "messages")
    if messages_key is not None and isinstance(data[messages_key], list) and data[messages_key]:
        last_msg = data[messages_key][-1]
        if isinstance(last_msg, dict) and "content" in last_msg:
            last_msg["content"] = "{PROMPT}"
            logger.info("Auto-injected {PROMPT} into messages[-1].content")
            return json.dumps(data, ensure_ascii=False)

    # ── 策略2: 递归深层搜索 ──
    best_path = _recursive_find_prompt_path(data)
    if best_path is not None:
        _set_nested_value(data, best_path, "{PROMPT}")
        logger.info(
            "Auto-injected {PROMPT} into nested path: %s",
            ".".join(str(p) for p in best_path),
        )
        return json.dumps(data, ensure_ascii=False)

    # ── 策略3: 顶层字段值评分 (扁平结构的 fallback) ──
    best_key = _score_prompt_fields(data)
    if best_key is not None:
        data[best_key] = "{PROMPT}"
        logger.info("Auto-injected {PROMPT} into JSON field: '%s'", best_key)
        return json.dumps(data, ensure_ascii=False)

    # ── 策略4: fallback — 添加 prompt 字段 ──
    data["prompt"] = "{PROMPT}"
    logger.info("Auto-injected {PROMPT} as new 'prompt' field (fallback)")
    return json.dumps(data, ensure_ascii=False)


def detect_and_inject_chat_id_placeholder(body: str) -> tuple[str, str | None, bool]:
    """检测 JSON body 中的会话 ID 字段并注入 {CHAT_ID} 占位符。

    策略:
        1. 解析 JSON body
        2. 在顶层字段中查找会话 ID 字段 (大小写不敏感匹配)
        3. 如果找到且值为空字符串, 替换为 {CHAT_ID}
        4. 如果找到但值非空, 注入 {CHAT_ID} 占位符并记录原始值

    Returns:
        (new_body, chat_id_field, has_placeholder) 元组。
    """
    try:
        data = json.loads(body)
    except (json.JSONDecodeError, TypeError):
        return body, None, False

    if not isinstance(data, dict):
        return body, None, False

    for key, value in data.items():
        key_lower = key.lower()
        if key_lower in _CHAT_ID_FIELD_NAMES:
            if isinstance(value, str) and not value.strip():
                data[key] = "{CHAT_ID}"
                new_body = json.dumps(data, ensure_ascii=False)
                return new_body, key, True
            elif isinstance(value, str) and value.strip():
                data[key] = "{CHAT_ID}"
                new_body = json.dumps(data, ensure_ascii=False)
                logger.info(
                    "Chat ID field '%s' has non-empty value, "
                    "injected {CHAT_ID} placeholder (original will "
                    "be used as initial value, auto-updated from responses)",
                    key,
                )
                return new_body, key, True
            else:
                data[key] = "{CHAT_ID}"
                new_body = json.dumps(data, ensure_ascii=False)
                return new_body, key, True

    return body, None, False


def extract_chat_id_from_response(response_text: str) -> str | None:
    """从 HTTP Response (特别是 SSE 流) 中提取会话 ID。

    候选 JSON 字段名 (优先级递减, 大小写不敏感):
        Object > chat_session_id > session_id > Id > ChatId > ...

    Args:
        response_text: HTTP Response 文本 (含 status line + headers + body)。

    Returns:
        提取到的会话 ID 字符串, 或 None。
    """
    if not response_text or not response_text.strip():
        return None

    # 策略1: 逐行解析 SSE data: 行
    for line in response_text.split("\n"):
        line = line.strip()
        if not line.startswith("data:"):
            continue

        data_content = line[5:].strip()
        if data_content in ("[DONE]", "[STOP]", ""):
            continue

        try:
            data_obj = json.loads(data_content)
            if not isinstance(data_obj, dict):
                continue

            for field_name in _RESPONSE_ID_FIELDS:
                val = _find_value_ci(data_obj, field_name)
                if val and isinstance(val, str) and val.strip():
                    return val.strip()
        except (json.JSONDecodeError, ValueError):
            continue

    # 策略2: 正则全局匹配 — 适用于非标准 SSE 格式
    for field_name in _RESPONSE_ID_FIELDS:
        pattern = re.compile(
            rf'"{re.escape(field_name)}"\s*:\s*"([^"]+)"',
            re.IGNORECASE,
        )
        match = pattern.search(response_text)
        if match:
            val = match.group(1).strip()
            if val:
                return val

    return None


def extract_original_prompt_value(body: str) -> str | None:
    """从 JSON body 中提取原始 prompt 值 (在 {PROMPT} 注入前)。

    复用 inject_prompt_placeholder 的评分逻辑找到最可能的 prompt 字段,
    但不修改 body, 仅返回原始值。

    Returns:
        原始 prompt 值字符串, 或 None。
    """
    if not body or not body.strip():
        return None

    try:
        data = json.loads(body)
    except (json.JSONDecodeError, TypeError):
        return None

    if not isinstance(data, dict):
        return None

    # ── 策略1: OpenAI messages 数组格式 ──
    messages_key = _find_key_ci(data, "messages")
    if messages_key is not None and isinstance(data[messages_key], list) and data[messages_key]:
        last_msg = data[messages_key][-1]
        if isinstance(last_msg, dict):
            content_key = _find_key_ci(last_msg, "content")
            if content_key is not None:
                val = last_msg[content_key]
                if isinstance(val, str) and not _is_likely_non_prompt(val):
                    return val.strip()

    # ── 策略2: 递归深层搜索 ──
    best_path = _recursive_find_prompt_path(data)
    if best_path is not None:
        val = _get_nested_value(data, best_path)
        if isinstance(val, str) and val.strip():
            return val.strip()

    # ── 策略3: 顶层字段评分 ──
    best_key = _score_prompt_fields(data)
    if best_key is not None:
        val = data[best_key]
        if isinstance(val, str) and val.strip():
            return val.strip()

    return None


def extract_model_info_from_response(
    response_text: str,
) -> tuple[str | None, str | None]:
    """从 HTTP Response 中提取模型名称和模型列表。

    适配多种响应格式:
        - Qwen 模型列表 API: {"data":[{"modelCode":"Qwen","displayModelName":"Qwen3.7-千问"},...]}
        - DeepSeek SSE 流: data: {"model_type":"default"}
        - OpenAI 兼容: {"model":"gpt-4o","choices":[...]}

    Returns:
        (model_name, model_list_json) 元组。
    """
    if not response_text or not response_text.strip():
        return None, None

    # 分离 body
    body_text = response_text
    body_start = response_text.find("\n\n")
    if body_start != -1:
        body_text = response_text[body_start + 2:]
    elif response_text.startswith("HTTP/"):
        return None, None

    model_name: str | None = None
    model_list: list[dict[str, Any]] | None = None

    # ── 策略1: 逐行解析 SSE data: 行 ──
    has_sse_lines = False
    for line in body_text.split("\n"):
        line = line.strip()
        if not line.startswith("data:"):
            continue
        has_sse_lines = True
        data_content = line[5:].strip()
        if data_content in ("[DONE]", "[STOP]", ""):
            continue
        try:
            data_obj = json.loads(data_content)
            if not isinstance(data_obj, dict):
                continue
            if model_name is None:
                for field_name in _MODEL_NAME_FIELDS:
                    val = _find_value_ci(data_obj, field_name)
                    if val and isinstance(val, str) and val.strip():
                        model_name = val.strip()
                        break
            if model_list is None:
                for arr_field in _MODEL_LIST_ARRAY_FIELDS:
                    arr_val = _find_value_ci(data_obj, arr_field)
                    if isinstance(arr_val, list) and arr_val:
                        has_model_info = any(
                            isinstance(item, dict) and any(
                                _find_value_ci(item, mf) is not None
                                for mf in _MODEL_NAME_FIELDS
                            )
                            for item in arr_val
                        )
                        if has_model_info:
                            model_list = arr_val
                            break
        except (json.JSONDecodeError, ValueError):
            continue

    if model_list is not None:
        return model_name, json.dumps(model_list, ensure_ascii=False)

    # ── 策略2: 整体 JSON 解析 (非 SSE 响应) ──
    if not has_sse_lines:
        try:
            json_obj = json.loads(body_text)
            if isinstance(json_obj, dict):
                if model_name is None:
                    for field_name in _MODEL_NAME_FIELDS:
                        val = _find_value_ci(json_obj, field_name)
                        if val and isinstance(val, str) and val.strip():
                            model_name = val.strip()
                            break
                if model_list is None:
                    for arr_field in _MODEL_LIST_ARRAY_FIELDS:
                        arr_val = _find_value_ci(json_obj, arr_field)
                        if isinstance(arr_val, list) and arr_val:
                            has_model_info = any(
                                isinstance(item, dict) and any(
                                    _find_value_ci(item, mf) is not None
                                    for mf in _MODEL_NAME_FIELDS
                                )
                                for item in arr_val
                            )
                            if has_model_info:
                                model_list = arr_val
                                if model_name is None and model_list:
                                    first_item = model_list[0]
                                    if isinstance(first_item, dict):
                                        for mf in _MODEL_NAME_FIELDS:
                                            val = _find_value_ci(first_item, mf)
                                            if val and isinstance(val, str) and val.strip():
                                                model_name = val.strip()
                                                break
                                break
            if model_list is not None:
                return model_name, json.dumps(model_list, ensure_ascii=False)
        except (json.JSONDecodeError, TypeError):
            pass

    # ── 策略3: 正则全局匹配模型名称字段 ──
    if model_name is None:
        for field_name in _MODEL_NAME_FIELDS:
            pattern = re.compile(
                rf'"{re.escape(field_name)}"\s*:\s*"([^"]+)"',
                re.IGNORECASE,
            )
            match = pattern.search(body_text)
            if match:
                val = match.group(1).strip()
                if val:
                    model_name = val
                    break

    # 策略3b: 提取模型列表 (正则检测数组结构)
    if model_list is None:
        for arr_field in _MODEL_LIST_ARRAY_FIELDS:
            arr_pattern = re.compile(
                rf'"{re.escape(arr_field)}"\s*:\s*\[',
                re.IGNORECASE,
            )
            if arr_pattern.search(body_text):
                model_code_pattern = re.compile(
                    r'"(?:modelCode|displayModelName|modelName|model_name)"\s*:\s*"([^"]+)"',
                    re.IGNORECASE,
                )
                matches = model_code_pattern.findall(body_text)
                if matches:
                    model_list = [{"name": m} for m in matches]
                    break

    if model_list is not None:
        return model_name, json.dumps(model_list, ensure_ascii=False)

    return model_name, None


# ──────────────────────────────────────────────────────────────────────
# 内部辅助函数
# ──────────────────────────────────────────────────────────────────────


def _find_key_ci(data: dict[str, Any], target: str) -> str | None:
    """大小写不敏感地查找 dict key, 返回原始 key 名。"""
    target_lower = target.lower()
    for k in data:
        if k.lower() == target_lower:
            return k
    return None


def _find_value_ci(data: dict[str, Any], target: str) -> Any:
    """大小写不敏感地查找 dict key, 返回对应的值。"""
    target_lower = target.lower()
    for k, v in data.items():
        if k.lower() == target_lower:
            return v
    return None


def _is_likely_non_prompt(value: Any) -> bool:
    """判断一个字段值是否明显不是用户输入的 prompt。"""
    if not isinstance(value, str):
        return True

    stripped = value.strip()

    if not stripped:
        return True

    if stripped.lower() in _NON_PROMPT_VALUES:
        return True

    if len(stripped) < 2:
        return True

    for pattern in _NON_PROMPT_PATTERNS:
        if pattern.match(stripped):
            return True

    return False


def _recursive_find_prompt_path(
    obj: Any,
    current_path: tuple[str | int, ...] | None = None,
) -> tuple[str | int, ...] | None:
    """递归遍历 JSON 树, 找到最可能是 prompt 的字段路径。

    适配 Baidu 等深层嵌套结构:
        message.query[0].data.text.query = "吉隆口岸大楼只剩钢筋骨架"
    """
    if current_path is None:
        current_path = ()

    candidates: list[tuple[tuple[str | int, ...], int]] = []

    def _recurse(o: Any, path: tuple[str | int, ...]) -> None:
        if isinstance(o, dict):
            for k, v in o.items():
                new_path = path + (k,)
                if isinstance(v, str):
                    score = _score_single_prompt_field(k, v)
                    if score > 0:
                        candidates.append((new_path, score))
                elif isinstance(v, (dict, list)):
                    _recurse(v, new_path)
        elif isinstance(o, list):
            for i, item in enumerate(o):
                new_path = path + (i,)
                if isinstance(item, str):
                    score = _score_single_prompt_field("", item)
                    if score > 0:
                        candidates.append((new_path, score))
                elif isinstance(item, (dict, list)):
                    _recurse(item, new_path)

    _recurse(obj, current_path)

    if not candidates:
        return None

    candidates.sort(key=lambda x: x[1], reverse=True)
    best_path, best_score = candidates[0]

    if best_score < 15:
        return None

    logger.debug(
        "Recursive prompt search: best path=%s (score=%d), candidates=%d",
        ".".join(str(p) for p in best_path), best_score, len(candidates),
    )
    return best_path


def _score_single_prompt_field(key: str, value: Any) -> int:
    """对单个字段 (key+value) 评分, 返回 prompt 可能性分数。"""
    if _is_likely_non_prompt(value):
        return 0

    stripped = value.strip()

    has_space = " " in stripped
    has_non_ascii = any(ord(c) > 127 for c in stripped)
    is_natural_lang = has_space or has_non_ascii

    key_lower = key.lower()
    if key_lower in _PROMPT_NAME_HINTS:
        name_score = 30
    else:
        name_score = 0
        for hint in _PROMPT_NAME_HINTS:
            if hint in key_lower:
                name_score = 15
                break

    if is_natural_lang:
        value_score = 60
    elif name_score > 0:
        value_score = 15
    else:
        return 0

    return value_score + name_score


def _set_nested_value(data: Any, path: tuple[str | int, ...], value: Any) -> None:
    """在嵌套 JSON 对象中设置指定路径的值 (原地修改)。"""
    current = data
    for i, key in enumerate(path):
        if i == len(path) - 1:
            if isinstance(key, int):
                if isinstance(current, list):
                    current[key] = value
            elif isinstance(current, dict):
                current[key] = value
        else:
            if isinstance(key, int):
                if isinstance(current, list):
                    current = current[key]
            elif isinstance(current, dict):
                current = current[key]


def _get_nested_value(data: Any, path: tuple[str | int, ...]) -> Any:
    """从嵌套 JSON 对象中获取指定路径的值 (只读)。"""
    current = data
    for key in path:
        if isinstance(key, int):
            if isinstance(current, list) and 0 <= key < len(current):
                current = current[key]
            else:
                return None
        else:
            if isinstance(current, dict) and key in current:
                current = current[key]
            else:
                return None
    return current


def _score_prompt_fields(data: dict[str, Any]) -> str | None:
    """对 JSON body 顶层 string 字段评分, 返回最可能是 prompt 的 key。

    评分维度:
        A. 字段值特征 (含空格或非ASCII → 自然语言, +60)
        B. 字段名语义 (匹配 prompt 语义词, +15~30)
        C. 排除项 (UUID/URL/纯数字 → 跳过)
    """
    candidates: list[tuple[str, int]] = []

    for key, value in data.items():
        if _is_likely_non_prompt(value):
            continue

        stripped = value.strip()

        has_space = " " in stripped
        has_non_ascii = any(ord(c) > 127 for c in stripped)
        is_natural_lang = has_space or has_non_ascii

        key_lower = key.lower()
        if key_lower in _PROMPT_NAME_HINTS:
            name_score = 30
        else:
            name_score = 0
            for hint in _PROMPT_NAME_HINTS:
                if hint in key_lower:
                    name_score = 15
                    break

        if is_natural_lang:
            value_score = 60
        elif name_score > 0:
            value_score = 15
        else:
            continue

        score = value_score + name_score
        candidates.append((key, score))

    if not candidates:
        return None

    candidates.sort(key=lambda x: x[1], reverse=True)
    best_key, best_score = candidates[0]

    if best_score < 15:
        return None

    logger.debug(
        "Prompt field scoring: %s (score=%d), candidates=%s",
        best_key, best_score, [(k, s) for k, s in candidates],
    )
    return best_key
