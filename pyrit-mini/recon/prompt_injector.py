"""Prompt & ID 

:
    1. JSON body  prompt and inject into {PROMPT} 
    2.  ID  {CHAT_ID} 
    3. imports Burp Response  ID (ChatId / Object / session_id)
    4. imports Burp Response  ( / )
    5. imports Burp Request body  prompt  ()
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any

logger = logging.getLogger(__name__)

# ID ()
_CHAT_ID_FIELD_NAMES = frozenset({
    "chatid", "chat_id", "chatidvalue", "chatsessionid", "chat_session_id",
    "sessionid", "session_id", "sessionidvalue",
    "conversationid", "conversation_id", "convid", "conv_id",
    "dialogid", "dialog_id",
    "threadid", "thread_id",
    "req_id", "requestid", "request_id",
})

# SSE/JSON Response ID JSON ()
_RESPONSE_ID_FIELDS = [
    "Object",
    "chat_session_id", "chatsessionid",
    "session_id", "sessionid",
    "Id", "ChatId", "ConversationId", "ConvId",
]

# JSON ()
_MODEL_NAME_FIELDS = [
    "displayModelName", "model_name", "modelName", "modelCode",
    "model_type", "modelType", "model", "usedModel",
]

# API ()
_MODEL_LIST_ARRAY_FIELDS = [
    "data", "models", "model_list", "modelList",
]

# == ==
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
 """imports URL scheme TLS header """
    if path.startswith("https://"):
        return True
    if path.startswith("http://"):
        return False
    host = headers.get("host", "")
    if "localhost" in host or "127.0.0.1" in host or "0.0.0.0" in host:
        return False
    return headers.get("x-forwarded-proto", "https") == "https"


def build_full_url(path: str, host: str, use_tls: bool) -> str:
 """ URL"""
    if path.startswith(("http://", "https://")):
        return path
    scheme = "https" if use_tls else "http"
    return f"{scheme}://{host}{path}"


def inject_prompt_placeholder(body: str) -> str:
 """ {PROMPT} JSON body

     ():
        1. OpenAI messages :  user message  content
        2. Layer:  JSON body , allLayer
           " prompt" "{PROMPT}"
        3. Layer:  JSON body Layerconverter(s) string 
        4. :  "prompt": "{PROMPT}"  fallback
 """
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        return body

    if not isinstance(data, dict):
        return body

 # == 1: OpenAI messages () ==
    messages_key = _find_key_ci(data, "messages")
    if messages_key is not None and isinstance(data[messages_key], list) and data[messages_key]:
        last_msg = data[messages_key][-1]
        if isinstance(last_msg, dict) and "content" in last_msg:
            last_msg["content"] = "{PROMPT}"
            logger.info("Auto-injected {PROMPT} into messages[-1].content")
            return json.dumps(data, ensure_ascii=False)

 # == 2: Layer ==
    best_path = _recursive_find_prompt_path(data)
    if best_path is not None:
        _set_nested_value(data, best_path, "{PROMPT}")
        logger.info(
            "Auto-injected {PROMPT} into nested path: %s",
            ".".join(str(p) for p in best_path),
        )
        return json.dumps(data, ensure_ascii=False)

 # == 3: Layer ( fallback) ==
    best_key = _score_prompt_fields(data)
    if best_key is not None:
        data[best_key] = "{PROMPT}"
        logger.info("Auto-injected {PROMPT} into JSON field: '%s'", best_key)
        return json.dumps(data, ensure_ascii=False)

 # == 4: fallback - prompt ==
    data["prompt"] = "{PROMPT}"
    logger.info("Auto-injected {PROMPT} as new 'prompt' field (fallback)")
    return json.dumps(data, ensure_ascii=False)


def detect_and_inject_chat_id_placeholder(body: str) -> tuple[str, str | None, bool]:
 """ JSON body ID and inject into {CHAT_ID} 

    :
        1.  JSON body
        2. Layer ID  ()
        3. ,  {CHAT_ID}
        4. ,  {CHAT_ID} 

    Returns:
        (new_body, chat_id_field, has_placeholder) 
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
 """imports HTTP Response ( SSE ) ID

     JSON  (, ):
        Object > chat_session_id > session_id > Id > ChatId > ...

    Args:
        response_text: HTTP Response  ( status line + headers + body)

    Returns:
         ID ,  None
 """
    if not response_text or not response_text.strip():
        return None

 # 1: SSE data: 
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

 # 2: - SSE 
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
 """imports JSON body prompt ( {PROMPT} )

     inject_prompt_placeholder  prompt ,
     body, 

    Returns:
         prompt ,  None
 """
    if not body or not body.strip():
        return None

    try:
        data = json.loads(body)
    except (json.JSONDecodeError, TypeError):
        return None

    if not isinstance(data, dict):
        return None

 # == 1: OpenAI messages ==
    messages_key = _find_key_ci(data, "messages")
    if messages_key is not None and isinstance(data[messages_key], list) and data[messages_key]:
        last_msg = data[messages_key][-1]
        if isinstance(last_msg, dict):
            content_key = _find_key_ci(last_msg, "content")
            if content_key is not None:
                val = last_msg[content_key]
                if isinstance(val, str) and not _is_likely_non_prompt(val):
                    return val.strip()

 # == 2: Layer ==
    best_path = _recursive_find_prompt_path(data)
    if best_path is not None:
        val = _get_nested_value(data, best_path)
        if isinstance(val, str) and val.strip():
            return val.strip()

 # == 3: Layer ==
    best_key = _score_prompt_fields(data)
    if best_key is not None:
        val = data[best_key]
        if isinstance(val, str) and val.strip():
            return val.strip()

    return None


def extract_model_info_from_response(
    response_text: str,
) -> tuple[str | None, str | None]:
 """imports HTTP Response 

    :
        - Qwen  API: {"data":[{"modelCode":"Qwen","displayModelName":"Qwen3.7-"},...]}
        - DeepSeek SSE : data: {"model_type":"default"}
        - OpenAI : {"model":"gpt-4o","choices":[...]}

    Returns:
        (model_name, model_list_json) 
 """
    if not response_text or not response_text.strip():
        return None, None

 # body
    body_text = response_text
    body_start = response_text.find("\n\n")
    if body_start != -1:
        body_text = response_text[body_start + 2:]
    elif response_text.startswith("HTTP/"):
        return None, None

    model_name: str | None = None
    model_list: list[dict[str, Any]] | None = None

 # == 1: SSE data: ==
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

 # == 2: JSON ( SSE ) ==
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

 # == 3: ==
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

 # 3b: ()
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


# ======================================================================
# 
# ======================================================================


def _find_key_ci(data: dict[str, Any], target: str) -> str | None:
 """ dict key, key """
    target_lower = target.lower()
    for k in data:
        if k.lower() == target_lower:
            return k
    return None


def _find_value_ci(data: dict[str, Any], target: str) -> Any:
 """ dict key, """
    target_lower = target.lower()
    for k, v in data.items():
        if k.lower() == target_lower:
            return v
    return None


def _is_likely_non_prompt(value: Any) -> bool:
 """converter(s) prompt"""
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
 """ JSON , prompt 

     Baidu Layer:
        message.query[0].data.text.query = ""
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
 """converter(s) (key+value) , prompt """
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
 """ JSON ()"""
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
 """imports JSON ()"""
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
 """ JSON body Layer string , prompt key

    :
        A.  (ASCII -> , +60)
        B.  ( prompt , +15~30)
        C.  (UUID/URL/ -> Skip)
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
