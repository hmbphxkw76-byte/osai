"""Burp Suite HTTP 请求解析 → PyRIT 原生 HTTPTarget 构建。

纯黑盒场景:
    - 全量保留浏览器 header (Cookie, User-Agent, Origin, Referer 等)
    - 自动检测 SSE (text/event-stream)
    - 自动注入 {PROMPT} 占位符 (支持 JSON body 中的常见字段名)
    - 响应路径自动探测 (发送探针请求, 推断 JSON 响应结构)
    - 支持 HTTP/2

真实样本::

    POST /api/chat HTTP/1.1
    Host: target.example.com
    Content-Type: application/json
    Cookie: session_id=xxx
    ...

    {"prompt":"介绍自己"}
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def _make_sse_callback() -> Any:
    """创建 SSE 流式响应解析 callback。

    SSE 格式 (多种变体):
        格式1 — 标准 SSE:
            event: meta
            data: {"request_id": "..."}

            data: {"content": "你好"}

            data: {"content": "我可以帮你"}

        格式2 — OpenAI 兼容:
            data: {"choices":[{"delta":{"content":"Hello"}}]}

            data: {"choices":[{"delta":{"content":" world"}}]}

            data: [DONE]

        格式3 — 纯 JSON:
            {"content": "完整响应"}

        格式4 — DeepSeek JSON Patch (RFC 6902 变体):
            data: {"v":"片段"}
            data: {"v":"另一个片段"}
            data: {"p":"response/fragments/-1/content","o":"APPEND","v":"片段"}
            data: {"p":"response/status","o":"SET","v":"FINISHED"}

            其中 "v" 字段是值片段, "o" 是操作 (APPEND/SET),
            "p" 是 JSON Patch 路径。只提取无 "p"/"o" 的纯值片段
            和 APPEND 到 content 路径的片段。

        格式5 — Qwen JSON Patch 变体:
            data: {"v":"片段"}
            data: {"v":"另一个片段"}

    策略 (4层 fallback):
        1. 逐行解析 SSE data: 行，提取 content/delta.content/v 字段
        2. 如果逐行解析失败，用正则全局匹配 content 字段
        3. 如果 content 正则也失败，用正则全局匹配 "v":"..." 片段
        4. 如果都失败，返回原始文本 (去掉 SSE 前缀)
    """

    def parse_sse_response(response: Any) -> str:
        """解析 SSE 流式响应，拼接所有 content 片段。"""
        import json as json_mod

        # 获取响应文本
        text = None
        if hasattr(response, "text") and response.text is not None:
            text = response.text
        elif hasattr(response, "content"):
            if isinstance(response.content, bytes):
                text = response.content.decode("utf-8", errors="replace")
            else:
                text = str(response.content)
        else:
            text = str(response)

        if not text or not text.strip():
            return ""

        # 策略1: 逐行解析 SSE data: 行 (最准确)
        content_parts: list[str] = []
        for line in text.split("\n"):
            line = line.strip()
            if not line.startswith("data:"):
                continue

            # 提取 data: 后的内容
            data_content = line[5:].strip()

            # 跳过 [DONE] 标记
            if data_content == "[DONE]" or data_content == "[STOP]":
                continue

            # 尝试 JSON 解析
            try:
                data_obj = json_mod.loads(data_content)

                # ── 格式4: DeepSeek JSON Patch 格式 ──
                # data: {"v":"片段"} — 纯值片段 (无 p/o 字段)
                # data: {"p":"...content","o":"APPEND","v":"片段"} — Patch 操作
                if isinstance(data_obj, dict) and "v" in data_obj:
                    v_val = data_obj["v"]
                    # 如果有 p 和 o 字段, 只有 APPEND 到 content 路径的才提取
                    if "p" in data_obj and "o" in data_obj:
                        p_val = str(data_obj.get("p", ""))
                        o_val = str(data_obj.get("o", ""))
                        if o_val == "APPEND" and "content" in p_val:
                            if isinstance(v_val, str):
                                content_parts.append(v_val)
                            elif isinstance(v_val, list):
                                for item in v_val:
                                    if isinstance(item, dict):
                                        c = item.get("content") or item.get("v")
                                        if c and isinstance(c, str):
                                            content_parts.append(c)
                                    elif isinstance(item, str):
                                        content_parts.append(item)
                        # SET 操作 (如 status=FINISHED) 跳过
                        continue
                    else:
                        # 纯值片段 {"v":"片段"} — 直接提取
                        if isinstance(v_val, str):
                            content_parts.append(v_val)
                        elif isinstance(v_val, dict):
                            # 可能是 {"v":{"response":{...}}} 结构
                            inner = _extract_nested_ci(v_val, "content")
                            if inner and isinstance(inner, str):
                                content_parts.append(inner)
                        continue

                # ── 格式1-3: 标准 SSE / OpenAI / 通用 JSON ──
                content_val = (
                    _extract_nested_ci(data_obj, "content")
                    or _extract_nested_ci(data_obj, "delta", "content")
                    or _extract_nested_ci(data_obj, "choices", 0, "delta", "content")
                    or _extract_nested_ci(data_obj, "choices", 0, "message", "content")
                    or _extract_nested_ci(data_obj, "answer")
                    or _extract_nested_ci(data_obj, "response")
                    or _extract_nested_ci(data_obj, "text")
                )
                if content_val and isinstance(content_val, str):
                    content_parts.append(content_val)
            except (json_mod.JSONDecodeError, ValueError):
                # 非 JSON 格式，尝试正则 (大小写不敏感)
                pattern = re.compile(r'"content"\s*:\s*"((?:[^"\\]|\\.)*)"', re.I)
                match = pattern.search(data_content)
                if match:
                    content_parts.append(match.group(1))

        if content_parts:
            full_content = "".join(content_parts)
            # 反转义 JSON 字符串
            full_content = full_content.replace("\\n", "\n").replace("\\\"", "\"").replace("\\t", "\t")
            return full_content

        # 策略2: 正则全局匹配 content 字段 (大小写不敏感)
        pattern = re.compile(r'"content"\s*:\s*"((?:[^"\\]|\\.)*)"', re.I)
        matches = pattern.findall(text)
        if matches:
            full_content = "".join(matches)
            full_content = full_content.replace("\\n", "\n").replace("\\\"", "\"").replace("\\t", "\t")
            return full_content

        # 策略3: 正则全局匹配 "v":"..." 片段 (DeepSeek/Qwen 格式)
        # 匹配 {"v":"片段"} 或 "v":"片段" (跳过含 p/o 的 Patch 操作)
        v_pattern = re.compile(r'"v"\s*:\s*"((?:[^"\\]|\\.)*)"', re.I)
        v_matches = v_pattern.findall(text)
        if v_matches:
            full_content = "".join(v_matches)
            full_content = full_content.replace("\\n", "\n").replace("\\\"", "\"").replace("\\t", "\t")
            return full_content

        # 策略4: 返回原始文本 (清理 SSE 前缀)
        cleaned = re.sub(r"^(event:|data:)\s*", "", text, flags=re.MULTILINE)
        cleaned = cleaned.replace("[DONE]", "").replace("[STOP]", "")
        return cleaned.strip()

    return parse_sse_response


def _extract_nested_ci(obj: Any, *keys: Any) -> Any:
    """从嵌套 dict/list 中提取值 (大小写不敏感)。

    与 _extract_nested 类似, 但 dict key 查找使用大小写不敏感匹配。
    适配不同 API 的 JSON key 命名风格:
        - snake_case: "choices", "delta", "content"
        - PascalCase: "Choices", "Delta", "Content"
        - camelCase:  "choices", "deltaContent"

    Args:
        obj: 起始对象。
        keys: 逐层 key/index 路径 (string key 大小写不敏感, int 按索引)。

    Returns:
        找到的值，或 None。
    """
    current = obj
    for key in keys:
        if current is None:
            return None
        if isinstance(key, int):
            if isinstance(current, list) and 0 <= key < len(current):
                current = current[key]
            else:
                return None
        else:
            if isinstance(current, dict):
                # 大小写不敏感查找: 先精确匹配, 再小写匹配
                if key in current:
                    current = current[key]
                else:
                    key_lower = key.lower()
                    found = False
                    for k, v in current.items():
                        if k.lower() == key_lower:
                            current = v
                            found = True
                            break
                    if not found:
                        return None
            else:
                return None
    return current


def _extract_nested(obj: Any, *keys: Any) -> Any:
    """从嵌套 dict/list 中提取值 (大小写敏感, 保留原始行为)。

    Args:
        obj: 起始对象。
        keys: 逐层 key/index 路径。

    Returns:
        找到的值，或 None。
    """
    current = obj
    for key in keys:
        if current is None:
            return None
        if isinstance(key, int):
            if isinstance(current, list) and 0 <= key < len(current):
                current = current[key]
            else:
                return None
        else:
            if isinstance(current, dict):
                current = current.get(key)
            else:
                return None
    return current


# ════════════════════════════════════════════════════════════════════
# P1-05: TargetFingerprint Schema 显式化
# 学术依据: C3 显式优于隐式 — dict[str, str] 缺乏编译时检查,
# 字段名 typo (如 "chat_id" vs "chatid") 和类型混乱 (str/int/bool 混存)
# 是 2024-2025 年 Python AI 安全工具中常见报告数据损坏根因。
# ════════════════════════════════════════════════════════════════════

@dataclass
class TargetFingerprint:
    """目标指纹信息 — 显式 Schema, 两阶段写入隔离。

    两阶段写入契约:
        Phase 1 (parse-time): 由 ``burp_parser._parse_raw_http`` 填充
            (HTTP 静态解析阶段, 不发送网络请求)
        Phase 2 (probe-time): 由探测模块 (capability_detector/target_router) 填充
            (发送探测请求后动态收集, 字段默认 None / 空 / False)

    向后兼容: 提供 ``get`` / ``__getitem__`` / ``__setitem__`` 接口, 允许
    旧式 ``fp["key"]`` 写法继续工作, 但新增字段强烈推荐 attribute 访问。
    """

    # ── Phase 1: HTTP 请求解析 (必填, _extract_fingerprint 写入) ──
    framework: str = "Unknown"
    api_path: str = ""
    host: str = ""
    auth_type: str = "None"
    content_type: str = "unknown"
    app_type: str = "Web Application"
    api_category: str = "chat"

    # ── Phase 1: HTTP 请求解析 (可选, _parse_raw_http 写入) ──
    ai_framework: str | None = None
    ai_framework_category: str | None = None
    chat_id: str | None = None
    burp_model_name: str | None = None
    has_model_list: bool = False

    # ── Phase 2: 主动探测 (capability_detector / target_router 写入) ──
    language: str | None = None
    model_family: str | None = None
    capabilities: list[str] = field(default_factory=list)
    probe_count: int = 0
    probe_duration_seconds: float = 0.0

    # ── Phase 2: 深度探测 (target_router 后处理写入) ──
    mcp_tools: list[str] = field(default_factory=list)
    mcp_resources: list[str] = field(default_factory=list)
    mcp_prompts: list[str] = field(default_factory=list)
    system_prompt_leaked: bool = False
    extracted_system_prompt: str | None = None
    system_prompt_extraction_method: str | None = None
    openapi_spec_path: str | None = None
    openapi_endpoints: list[str] = field(default_factory=list)
    original_prompt: str | None = None
    session_type: str | None = None

    # ── 动态扩展 (非预期字段落地点, 运行时探测的未知键) ──
    extra: dict[str, Any] = field(default_factory=dict)

    def get(self, key: str, default: Any = None) -> Any:
        """向后兼容 dict.get()。"""
        if hasattr(self, key) and not key.startswith("_"):
            val = getattr(self, key)
            return val if val is not None else default
        return self.extra.get(key, default)

    def __getitem__(self, key: str) -> Any:
        """向后兼容 dict[key] 读。"""
        if hasattr(self, key) and not key.startswith("_"):
            return getattr(self, key)
        return self.extra[key]

    def __setitem__(self, key: str, value: Any) -> None:
        """向后兼容 dict[key] = value 写。优先 attribute, 否则 extra。"""
        if hasattr(self, key) and not key.startswith("_"):
            setattr(self, key, value)
        else:
            self.extra[key] = value

    def to_dict(self) -> dict[str, Any]:
        """序列化为 JSON 兼容字典 (用于报告输出)。"""
        from dataclasses import asdict

        result = asdict(self)
        extra = result.pop("extra", {})
        result.update(extra)
        # 过滤 None / 空 / False, 保留有意义的字段
        return {k: v for k, v in result.items() if v not in (None, "", [], False, 0, 0.0)}


@dataclass
class ParsedBurpRequest:
    """解析后的 Burp 请求。"""

    method: str
    url: str
    host: str
    path: str
    headers: dict[str, str] = field(default_factory=dict)
    # 原始 header 顺序保留 (重建 HTTP 请求时使用)
    raw_headers: list[tuple[str, str]] = field(default_factory=list)
    body: str = ""
    use_tls: bool = True
    is_sse: bool = False
    http_version: str = "HTTP/1.1"
    has_prompt_placeholder: bool = False
    # 探测到的 JSON 响应路径
    response_json_path: str | None = None
    # 目标指纹信息 — P1-05: 显式 Schema (替代 dict[str, str])
    target_fingerprint: TargetFingerprint = field(default_factory=TargetFingerprint)
    # P2-20: 从 Burp Response 中提取的会话 ID (ChatId / Object / conversation_id 等)
    # 用于多轮攻击中保持会话连续性
    chat_id: str | None = None
    # P2-20: JSON body 中会话 ID 字段名 (大小写不敏感匹配)
    # 由 _detect_chat_id_field 自动检测, 如 "ChatId" / "chat_id" / "conversationId" 等
    chat_id_field: str | None = None
    # P2-20: 是否已注入 {CHAT_ID} 占位符到 body 中
    has_chat_id_placeholder: bool = False
    # L5 v53: 从 Burp Request body 中提取的原始 prompt 值 (注入 {PROMPT} 前的值)
    # 用于侦察阶段分析目标用户通常询问的话题, 不转换为攻击 seeds
    original_prompt_value: str | None = None
    # L5 v53: 从 Burp Response 中提取的模型名称 (如 "Qwen3.7-千问" / "deepseek-chat")
    # 用于侦察阶段识别目标模型, 精准匹配 ASR 先验
    burp_model_name: str | None = None
    # L5 v53: 从 Burp Response 中提取的可用模型列表 (模型列表 API 响应)
    # 存储为 JSON 字符串, 供侦察阶段分析目标支持的模型
    burp_model_list: str | None = None
    # L5 v53: API 端点类别 ("chat" / "metadata" / "unknown")
    # chat = 聊天/补全 API (可注入 {PROMPT})
    # metadata = 模型列表/用户信息等 API (不注入 {PROMPT}, 仅提取信息)
    api_category: str = "chat"


def parse_burp_request(file_path: str | Path) -> ParsedBurpRequest:
    """解析 Burp 原始 HTTP 请求文件。

    支持格式::

        POST /api/chat HTTP/1.1
        Host: target.example.com
        Content-Type: application/json
        Cookie: session=xxx

        {"prompt":"{PROMPT}"}

    也支持 Burp 导出的完整 HTTP 交互 (Request + Response)::

        POST /api/chat HTTP/1.1
        Host: target.example.com
        ...

        {"ChatId":"", "Query":"介绍你自己"}

        HTTP/1.1 200 OK
        Content-Type: text/event-stream
        ...

        data: {"Object":"08df05b4-...", "Choices":[...]}
        data: [DONE]

    当文件包含 Response 部分时, 会自动从 SSE Response 中提取会话 ID
    (Object / ChatId / conversation_id 等字段), 用于多轮攻击会话保持。

    Args:
        file_path: Burp 请求文件路径。

    Returns:
        ParsedBurpRequest: 解析结果 (含 chat_id 如果 Response 中有)。

    Raises:
        FileNotFoundError: 文件不存在。
        ValueError: HTTP 请求格式无效。
    """
    raw = Path(file_path).read_text(encoding="utf-8", errors="replace")
    return _parse_raw_http(raw)


def _parse_raw_http(raw: str) -> ParsedBurpRequest:
    """解析原始 HTTP 请求字符串。

    L5 v19 修复: 某些 Burp 导出格式 header 与 body 间无空行分隔
    (如 ``Connection: keep-alive\\r\\n{"prompt":"{PROMPT}"}``),
    导致 body 行被误判为 header。修复策略: 在逐行解析 header 时,
    如果某行不匹配 ``key: value`` 格式 (不以字母开头, 或以 ``{`` 开头),
    则将其及后续所有行视为 body。

    P2-20 增强: 支持 Burp 导出的完整 HTTP 交互 (Request + Response)。
    Burp 导出的 request.txt 通常包含完整的 HTTP 请求和响应, 格式::

        POST /api/chat HTTP/1.1
        Host: ...

        {"ChatId":"", ...}

        HTTP/1.1 200 OK
        Content-Type: text/event-stream

        data: {"Object":"session-uuid", ...}
        data: [DONE]

    本函数会:
        1. 分离 Request 和 Response 部分 (通过 ``HTTP/1.x <status>`` 行检测)
        2. 解析 Request 部分为 ParsedBurpRequest
        3. 从 Response 部分的 SSE data 中提取会话 ID (Object 字段)
        4. 如果 Request body 中有空 ChatId 字段, 自动注入 {CHAT_ID} 占位符
    """
    normalized = raw.replace("\r\n", "\n")

    # P2-20: 分离 Request 和 Response 部分
    # Burp 导出的完整交互以 ``HTTP/1.x <status>`` 开头的行作为 Response 起始
    request_section, response_section = _split_request_response(normalized)

    parts = request_section.split("\n\n", 1)

    header_section = parts[0].strip()
    body = parts[1] if len(parts) > 1 else ""

    header_lines = header_section.split("\n")
    request_line = header_lines[0].split(" ")
    if len(request_line) < 3:
        raise ValueError(f"Invalid HTTP request line: {header_lines[0]}")

    method = request_line[0]
    path = request_line[1]
    http_version = request_line[2]

    # 全量保留 header (保持原始顺序 + 大小写)
    # L5 v19: 智能识别 body 行 (非 header 格式的行视为 body 开始)
    headers: dict[str, str] = {}
    raw_headers: list[tuple[str, str]] = []
    body_from_headers: list[str] = []  # 从 header 段提取的 body 行
    in_body = False

    for line in header_lines[1:]:
        if in_body:
            body_from_headers.append(line)
            continue
        # 检测是否为 body 行 (JSON body, XML body 等)
        # 特征: 以 { 开头, 或不含冒号, 或冒号前有特殊字符
        if line.startswith("{") or line.startswith("<"):
            in_body = True
            body_from_headers.append(line)
            continue
        # 检测是否为有效 header: key 必须是 token (字母/数字/-'_)
        # 且包含冒号
        if ":" in line:
            potential_key = line.split(":", 1)[0].strip()
            # HTTP header name 只允许 token 字符
            if potential_key and all(
                c.isalnum() or c in "-_" for c in potential_key
            ):
                key, value = line.split(":", 1)
                raw_headers.append((key.strip(), value.strip()))
                headers[key.strip().lower()] = value.strip()
                continue
        # 不匹配 header 格式, 视为 body
        in_body = True
        body_from_headers.append(line)

    # 如果从 header 段提取到了 body, 合并到 body
    if body_from_headers:
        extracted_body = "\n".join(body_from_headers).strip()
        if body:
            body = extracted_body + "\n" + body
        else:
            body = extracted_body

    host = headers.get("host", "")
    use_tls = _infer_tls(path, headers)
    full_url = _build_full_url(path, host, use_tls)

    # SSE 检测 (3 层策略):
    #   1. 请求头 Accept: text/event-stream
    #   2. 请求 body 中含 stream:true / "stream":true (大小写不敏感)
    #   3. 响应头 Content-Type: text/event-stream (从 Burp 导出的 Response 中检测)
    accept_header = headers.get("accept", "")
    is_sse = "text/event-stream" in accept_header
    if not is_sse and body:
        try:
            body_data = json.loads(body)
            if isinstance(body_data, dict):
                stream_val = body_data.get("stream") or body_data.get("Stream")
                if stream_val:
                    is_sse = True
        except json.JSONDecodeError:
            pass
    if not is_sse and response_section:
        # 从响应头检测 SSE (DeepSeek 用 Accept: */* 但响应是 text/event-stream)
        resp_lines = response_section.split("\n")
        for line in resp_lines[:20]:  # 只检查响应头前 20 行
            if line.strip().lower().startswith("content-type:") and "text/event-stream" in line.lower():
                is_sse = True
                break

    # L5 v53: API 端点类别检测 (chat / metadata / unknown)
    # metadata API (如模型列表) 不注入 {PROMPT}, 仅提取信息
    api_category = _detect_api_category(path, body)

    # L5 v53: 在注入 {PROMPT} 前提取原始 prompt 值 (用于侦察分析)
    # 复用 _inject_placeholder 的评分逻辑, 找到最可能的 prompt 字段
    # 但不修改 body, 仅返回原始值
    original_prompt_value: str | None = None
    if api_category == "chat" and body and "{PROMPT}" not in body:
        original_prompt_value = _extract_original_prompt_value(body)
        if original_prompt_value:
            logger.info(
                "Extracted original prompt value from body: %s",
                original_prompt_value[:80],
            )

    # 占位符检测 + 自动注入 (仅对 chat API 注入)
    has_placeholder = "{PROMPT}" in body or "{PROMPT}" in path
    if not has_placeholder and body and api_category == "chat":
        body = _inject_placeholder(body)
        has_placeholder = True
    elif api_category == "metadata":
        # metadata API 不注入 {PROMPT}, 标记为无占位符
        has_placeholder = False
        logger.info(
            "Metadata API detected (path=%s), skipping {PROMPT} injection",
            path,
        )

    # 目标指纹
    fingerprint = _extract_fingerprint(headers, path, host, response_section)
    # P1-05: 使用属性赋值替代字典赋值, 获得编译时类型检查
    fingerprint.api_category = api_category

    # 从 Response 部分提取会话 ID (ChatId / Object / chat_session_id / session_id)
    chat_id: str | None = None
    chat_id_field: str | None = None
    has_chat_id_placeholder = False
    # 保存从 Request body 中检测到的原始会话 ID 值
    # (当 Burp 文件中的 session ID 非空时, 作为初始值传给 target,
    #  后续从响应中动态提取更新)
    initial_chat_id_from_body: str | None = None

    # L5 v53: 从 Burp Response 中提取模型信息 (模型名称 / 模型列表)
    burp_model_name: str | None = None
    burp_model_list: str | None = None

    if response_section:
        chat_id = _extract_chat_id_from_response(response_section)
        if chat_id:
            logger.info(
                "Extracted chat_id from Burp Response: %s", chat_id,
            )
            # P1-05: 使用属性赋值
            fingerprint.chat_id = chat_id

        # 提取模型信息
        burp_model_name, burp_model_list = _extract_model_info_from_response(response_section)
        if burp_model_name:
            logger.info("Extracted model name from Burp Response: %s", burp_model_name)
            # P1-05: 使用属性赋值
            fingerprint.burp_model_name = burp_model_name
        if burp_model_list:
            logger.info("Extracted model list from Burp Response (length=%d)", len(burp_model_list))
            # P1-05: 使用 extra dict 存储非 Schema 字段
            fingerprint.extra["burp_model_list"] = "yes"

    # 检测 Request body 中的会话 ID 字段名并注入 {CHAT_ID} 占位符
    if body:
        # 先解析原始 body, 提取会话 ID 的初始值
        try:
            orig_body_data = json.loads(body)
            if isinstance(orig_body_data, dict):
                for k, v in orig_body_data.items():
                    if k.lower() in _CHAT_ID_FIELD_NAMES:
                        if isinstance(v, str) and v.strip():
                            initial_chat_id_from_body = v.strip()
                        break
        except (json.JSONDecodeError, TypeError):
            pass

        body, chat_id_field, has_chat_id_placeholder = _detect_and_inject_chat_id_placeholder(body)
        if chat_id_field:
            logger.info(
                "Detected chat ID field '%s' in request body, "
                "injected {CHAT_ID} placeholder",
                chat_id_field,
            )

    # 如果 Response 中未提取到 chat_id, 使用 Request body 中的原始值作为初始值
    # 这样首次请求使用 Burp 文件中的 session ID, 后续从响应中动态提取更新
    if not chat_id and initial_chat_id_from_body:
        chat_id = initial_chat_id_from_body
        # P1-05: 使用属性赋值
        fingerprint.chat_id = chat_id
        logger.info(
            "Using chat_id from request body as initial value: %s", chat_id,
        )

    return ParsedBurpRequest(
        method=method,
        url=full_url,
        host=host,
        path=path,
        headers=headers,
        raw_headers=raw_headers,
        body=body,
        use_tls=use_tls,
        is_sse=is_sse,
        http_version=http_version,
        has_prompt_placeholder=has_placeholder,
        target_fingerprint=fingerprint,
        chat_id=chat_id,
        chat_id_field=chat_id_field,
        has_chat_id_placeholder=has_chat_id_placeholder,
        original_prompt_value=original_prompt_value,
        burp_model_name=burp_model_name,
        burp_model_list=burp_model_list,
        api_category=api_category,
    )


# 会话 ID 字段名匹配列表 (大小写不敏感)
# 覆盖常见的 ChatId / SessionId / ConversationId 等命名
# 扩展支持 DeepSeek (chat_session_id) / Qwen (session_id) / 通义 等
_CHAT_ID_FIELD_NAMES = frozenset({
    # ChatId 变体
    "chatid", "chat_id", "chatidvalue", "chatsessionid", "chat_session_id",
    # SessionId 变体
    "sessionid", "session_id", "sessionidvalue",
    # ConversationId 变体
    "conversationid", "conversation_id", "convid", "conv_id",
    # DialogId 变体
    "dialogid", "dialog_id",
    # ThreadId 变体
    "threadid", "thread_id",
    # RequestId 变体 (Qwen 等用 req_id 作会话标识)
    "req_id", "requestid", "request_id",
})

# SSE/JSON Response 中会话 ID 提取的候选 JSON 字段名 (大小写不敏感匹配)
# 优先级递减: Object (特定目标) > chat_session_id > session_id > Id > ChatId > ...
# 扩展支持 DeepSeek (chat_session_id) / Qwen (session_id) 等
_RESPONSE_ID_FIELDS = [
    "Object",
    "chat_session_id", "chatsessionid",
    "session_id", "sessionid",
    "Id", "ChatId", "ConversationId", "ConvId",
]


def _split_request_response(normalized: str) -> tuple[str, str | None]:
    """分离 Burp 导出的完整 HTTP 交互中的 Request 和 Response 部分。

    Burp 导出的 request.txt 通常包含完整的 HTTP 请求和响应。
    通过检测 ``HTTP/\\d`` 开头的行来识别 Response 起始位置。

    策略:
        1. 逐行扫描, 检测 ``HTTP/\\d.\\d <status_code>`` 格式的行
        2. 该行之前为 Request 部分 (含 body), 之后为 Response 部分
        3. 如果未检测到 Response 起始行, 整个文本作为 Request 处理

    Args:
        normalized: 已归一化 (\\n) 的原始文本。

    Returns:
        (request_section, response_section) 元组。
        response_section 为 None 表示文件中不含 Response 部分。
    """
    lines = normalized.split("\n")

    # 检测 Response 起始行: HTTP/1.x <status_code>
    response_start_idx: int | None = None
    for i, line in enumerate(lines):
        # 跳过第一行 (Request 行: POST /api/chat HTTP/1.1)
        # Request 行也包含 HTTP/1.1, 但在行尾而非行首
        if i == 0:
            continue
        # 检测 Response 行: HTTP/1.1 200 OK / HTTP/2 404 Not Found
        # 特征: 行首是 HTTP/ 后跟版本号和状态码
        if re.match(r"^HTTP/\d", line.strip()):
            response_start_idx = i
            break

    if response_start_idx is None:
        return normalized, None

    # 回溯: Response 起始行前面的空行归属于 Response
    # 找到 Request 最后一行内容的位置
    request_end_idx = response_start_idx
    while request_end_idx > 0 and not lines[request_end_idx - 1].strip():
        request_end_idx -= 1

    request_section = "\n".join(lines[:request_end_idx])
    response_section = "\n".join(lines[response_start_idx:])

    return request_section, response_section


def _extract_chat_id_from_response(response_text: str) -> str | None:
    """从 HTTP Response (特别是 SSE 流) 中提取会话 ID。

    SSE 流式响应中的每个 data: 行通常包含一个 Object 字段,
    该字段是服务器分配的会话/聊天 ID。

    提取策略 (按优先级):
        1. 逐行解析 SSE data: 行, 从 JSON 中提取候选字段
        2. 如果 SSE 解析失败, 尝试正则全局匹配

    候选 JSON 字段名 (优先级递减, 大小写不敏感):
        Object > chat_session_id > session_id > Id > ChatId > ...

    适配:
        - request.txt: Object 字段
        - DeepSeek: chat_session_id 字段
        - Qwen: session_id 字段

    Args:
        response_text: HTTP Response 文本 (含 status line + headers + body)。

    Returns:
        提取到的会话 ID 字符串, 或 None (未找到)。
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

            # 按优先级检查候选字段 (大小写不敏感)
            for field_name in _RESPONSE_ID_FIELDS:
                # 大小写不敏感查找
                val = _find_value_ci(data_obj, field_name)
                if val and isinstance(val, str) and val.strip():
                    return val.strip()
        except (json.JSONDecodeError, ValueError):
            continue

    # 策略2: 正则全局匹配 — 适用于非标准 SSE 格式
    for field_name in _RESPONSE_ID_FIELDS:
        # 大小写不敏感匹配 "field_name": "value"
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


# ──────────────────────────────────────────────────────────────────────
# L5 v53: 从 Burp Response 中提取模型信息 (模型名称 / 模型列表)
# ──────────────────────────────────────────────────────────────────────

# 候选模型名称 JSON 字段名 (大小写不敏感匹配)
# 覆盖 Qwen (modelCode/displayModelName) / DeepSeek (model_type) / 通用
_MODEL_NAME_FIELDS = [
    "displayModelName", "model_name", "modelName", "modelCode",
    "model_type", "modelType", "model", "usedModel",
]

# 模型列表 API 响应中的数组字段名 (大小写不敏感)
_MODEL_LIST_ARRAY_FIELDS = [
    "data", "models", "model_list", "modelList",
]


def _extract_model_info_from_response(
    response_text: str,
) -> tuple[str | None, str | None]:
    """从 HTTP Response 中提取模型名称和模型列表。

    适配多种响应格式:
        - Qwen 模型列表 API: ``{"data":[{"modelCode":"Qwen","displayModelName":"Qwen3.7-千问"},...]}``
        - DeepSeek SSE 流: ``data: {"model_type":"default"}``
        - OpenAI 兼容: ``{"model":"gpt-4o","choices":[...]}``
        - Baidu SSE: SSE data 行中含 ``usedModel.modelName``

    提取策略 (3 层):
        1. 逐行解析 SSE data: 行, 从 JSON 中提取模型字段
        2. 尝试整体 JSON 解析 (非 SSE 响应)
        3. 正则全局匹配模型字段

    Args:
        response_text: HTTP Response 文本 (含 status line + headers + body)。

    Returns:
        (model_name, model_list_json) 元组:
        - model_name: 提取到的模型名称字符串, 或 None
        - model_list_json: 模型列表的 JSON 字符串, 或 None
    """
    if not response_text or not response_text.strip():
        return None, None

    # 分离 body (去掉 HTTP status line + headers)
    body_text = response_text
    body_start = response_text.find("\n\n")
    if body_start != -1:
        body_text = response_text[body_start + 2:]
    elif response_text.startswith("HTTP/"):
        # 只有 headers 没有 body
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
            # 提取模型名称 (单值)
            if model_name is None:
                for field_name in _MODEL_NAME_FIELDS:
                    val = _find_value_ci(data_obj, field_name)
                    if val and isinstance(val, str) and val.strip():
                        model_name = val.strip()
                        break
            # 提取模型列表 (数组)
            if model_list is None:
                for arr_field in _MODEL_LIST_ARRAY_FIELDS:
                    arr_val = _find_value_ci(data_obj, arr_field)
                    if isinstance(arr_val, list) and arr_val:
                        # 验证数组元素是否包含模型信息字段
                        has_model_info = False
                        for item in arr_val:
                            if isinstance(item, dict):
                                for mf in _MODEL_NAME_FIELDS:
                                    if _find_value_ci(item, mf) is not None:
                                        has_model_info = True
                                        break
                                if has_model_info:
                                    break
                        if has_model_info:
                            model_list = arr_val
                            break
        except (json.JSONDecodeError, ValueError):
            continue

    # 如果 SSE 行中找到模型列表, 直接返回
    if model_list is not None:
        return model_name, json.dumps(model_list, ensure_ascii=False)

    # ── 策略2: 整体 JSON 解析 (非 SSE 响应) ──
    if not has_sse_lines:
        try:
            json_obj = json.loads(body_text)
            if isinstance(json_obj, dict):
                # 提取模型名称
                if model_name is None:
                    for field_name in _MODEL_NAME_FIELDS:
                        val = _find_value_ci(json_obj, field_name)
                        if val and isinstance(val, str) and val.strip():
                            model_name = val.strip()
                            break
                # 提取模型列表
                if model_list is None:
                    for arr_field in _MODEL_LIST_ARRAY_FIELDS:
                        arr_val = _find_value_ci(json_obj, arr_field)
                        if isinstance(arr_val, list) and arr_val:
                            # 验证数组元素是否包含模型信息
                            has_model_info = False
                            for item in arr_val:
                                if isinstance(item, dict):
                                    for mf in _MODEL_NAME_FIELDS:
                                        if _find_value_ci(item, mf) is not None:
                                            has_model_info = True
                                            break
                                    if has_model_info:
                                        break
                            if has_model_info:
                                model_list = arr_val
                                # 从列表第一个元素提取模型名称 (如果还未提取到)
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
        # 检测 "data":[{"modelCode":...}] 等模式
        for arr_field in _MODEL_LIST_ARRAY_FIELDS:
            arr_pattern = re.compile(
                rf'"{re.escape(arr_field)}"\s*:\s*\[',
                re.IGNORECASE,
            )
            if arr_pattern.search(body_text):
                # 找到模型列表数组, 尝试提取所有 modelCode/modelName
                model_code_pattern = re.compile(
                    r'"(?:modelCode|displayModelName|modelName|model_name)"\s*:\s*"([^"]+)"',
                    re.IGNORECASE,
                )
                matches = model_code_pattern.findall(body_text)
                if matches:
                    # 构建简化的模型列表
                    model_list = [{"name": m} for m in matches]
                    break

    if model_list is not None:
        return model_name, json.dumps(model_list, ensure_ascii=False)

    return model_name, None


# ──────────────────────────────────────────────────────────────────────
# L5 v53: 从 Burp Request body 中提取原始 prompt 值 (注入 {PROMPT} 前)
# ──────────────────────────────────────────────────────────────────────

def _extract_original_prompt_value(body: str) -> str | None:
    """从 JSON body 中提取原始 prompt 值 (在 {PROMPT} 注入前)。

    复用 _inject_placeholder 的评分逻辑找到最可能的 prompt 字段,
    但不修改 body, 仅返回原始值。

    适配场景:
        - DeepSeek: ``{"prompt":"介绍自己"}`` → "介绍自己"
        - Baidu: ``message.query[0].data.text.query = "吉隆口岸..."`` → "吉隆口岸..."
        - request.txt: ``{"Query":"介绍你自己"}`` → "介绍你自己"
        - OpenAI: ``messages[-1].content = "Hello"`` → "Hello"

    Args:
        body: HTTP 请求 body 字符串 (注入 {PROMPT} 前的原始 body)。

    Returns:
        原始 prompt 值字符串, 或 None (未找到)。
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


def _get_nested_value(
    data: Any,
    path: tuple[str | int, ...],
) -> Any:
    """从嵌套 JSON 对象中获取指定路径的值 (只读)。

    与 _set_nested_value 配对, 用于读取递归找到的 prompt 路径的值。

    Args:
        data: JSON 对象 (dict/list)。
        path: 路径元组。

    Returns:
        路径对应的值, 或 None。
    """
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


# ──────────────────────────────────────────────────────────────────────
# L5 v53: API 端点类别检测 (chat / metadata / unknown)
# ──────────────────────────────────────────────────────────────────────

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


def _detect_api_category(path: str, body: str) -> str:
    """检测 API 端点类别: chat / metadata / unknown。

    策略:
        1. 路径关键词匹配 (优先)
        2. body 结构分析 (fallback)
           - body 含 prompt/query/messages → chat
           - body 为空或 GET 请求 → metadata
           - body 无法判断 → unknown

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
                # 检测 prompt 相关字段
                data_str = json.dumps(data).lower()
                if any(kw in data_str for kw in ["prompt", "query", "message", "input", "ask", "question"]):
                    return "chat"
                # 有 body 但无 prompt 字段 → unknown (可能是配置 API)
                return "unknown"
        except (json.JSONDecodeError, TypeError):
            pass
    else:
        # 无 body (通常 GET 请求) → metadata
        return "metadata"

    return "unknown"


def _detect_and_inject_chat_id_placeholder(body: str) -> tuple[str, str | None, bool]:
    """检测 JSON body 中的会话 ID 字段并注入 {CHAT_ID} 占位符。

    策略:
        1. 解析 JSON body
        2. 在顶层字段中查找会话 ID 字段 (大小写不敏感匹配)
        3. 如果找到且值为空字符串, 替换为 {CHAT_ID}
        4. 如果找到但值非空, 注入 {CHAT_ID} 占位符并记录原始值
           (响应提取器会在运行时动态替换, 初始用原始值)
        5. 如果未找到, 不做任何修改

    设计意图:
        对于 DeepSeek (chat_session_id="xxx") / Qwen (session_id="xxx") 等
        会话 ID 非空的场景, 仍然注入 {CHAT_ID} 占位符:
        - 初始值用 Burp 文件中的原始 session ID
        - 每次响应后自动提取新的 session ID 并更新
        - 当会话窗口满时, 服务器会创建新 session ID,
          响应提取器自动捕获并更新, 确保会话连续性

    Args:
        body: HTTP 请求 body 字符串。

    Returns:
        (new_body, chat_id_field, has_placeholder) 元组:
        - new_body: 可能修改后的 body 字符串
        - chat_id_field: 检测到的会话 ID 字段名 (原始大小写), 或 None
        - has_placeholder: 是否已注入 {CHAT_ID} 占位符
    """
    try:
        data = json.loads(body)
    except (json.JSONDecodeError, TypeError):
        return body, None, False

    if not isinstance(data, dict):
        return body, None, False

    # 在顶层字段中查找会话 ID 字段 (大小写不敏感)
    for key, value in data.items():
        key_lower = key.lower()
        if key_lower in _CHAT_ID_FIELD_NAMES:
            # 找到会话 ID 字段
            if isinstance(value, str) and not value.strip():
                # 值为空字符串 → 注入 {CHAT_ID} 占位符
                data[key] = "{CHAT_ID}"
                new_body = json.dumps(data, ensure_ascii=False)
                return new_body, key, True
            elif isinstance(value, str) and value.strip():
                # 值非空 → 注入 {CHAT_ID} 占位符
                # 初始值用原始 session ID, 后续从响应中动态提取更新
                # 这样当会话窗口满时, 服务器返回新的 session ID,
                # 响应提取器会自动捕获并更新 target 的 chat_id
                data[key] = "{CHAT_ID}"
                new_body = json.dumps(data, ensure_ascii=False)
                # 记录原始 session ID 供 target 初始化使用
                logger.info(
                    "Chat ID field '%s' has non-empty value, "
                    "injected {CHAT_ID} placeholder (original will "
                    "be used as initial value, auto-updated from responses)",
                    key,
                )
                return new_body, key, True
            else:
                # 非字符串值 (null/int/bool), 仍注入占位符
                data[key] = "{CHAT_ID}"
                new_body = json.dumps(data, ensure_ascii=False)
                return new_body, key, True

    return body, None, False


def _infer_tls(path: str, headers: dict[str, str]) -> bool:
    """从 URL scheme 或 TLS header 推断。"""
    if path.startswith("https://"):
        return True
    if path.startswith("http://"):
        return False
    # localhost 默认 http
    host = headers.get("host", "")
    if "localhost" in host or "127.0.0.1" in host or "0.0.0.0" in host:
        return False
    return headers.get("x-forwarded-proto", "https") == "https"


def _build_full_url(path: str, host: str, use_tls: bool) -> str:
    """构建完整 URL。"""
    if path.startswith(("http://", "https://")):
        return path
    scheme = "https" if use_tls else "http"
    return f"{scheme}://{host}{path}"


def _inject_placeholder(body: str) -> str:
    """自动注入 {PROMPT} 占位符到 JSON body。

    通用启发式策略 (不依赖硬编码字段名列表):
        1. OpenAI messages 数组: 替换最后一条 user message 的 content
        2. 递归深层搜索: 对 JSON body 进行递归遍历, 在所有嵌套层级中
           找到"最可能是用户输入 prompt"的字段并替换其值为 "{PROMPT}"
        3. 顶层字段值评分: 对 JSON body 顶层每个 string 字段进行评分
           (策略 2 的 fallback, 适用于扁平结构)
        4. 无合适候选时: 添加 "prompt": "{PROMPT}" 作为 fallback

    设计理念:
        不同 Agent 应用的 JSON body 结构千差万别, 字段名可能是
        "Query"/"prompt"/"userInput"/"content"/"q"/"ask" 等任意命名,
        且可能嵌套在深层路径中 (如 Baidu: message.query[0].data.text.query),
        不应通过硬编码列表匹配, 而应通过递归分析字段值的特征自动推断。

    字段名语义辅助:
        虽然不依赖硬编码列表, 但字段名包含 prompt 相关语义
        (prompt/query/input/message/ask/text/content 等, 大小写不敏感)
        会给予额外加分, 提高推断准确率。
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

    # ── 策略2: 递归深层搜索 — 在嵌套结构中找最可能的 prompt 字段 ──
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


# ── 启发式评分相关常量 ──

# 字段名中包含这些语义片段 (大小写不敏感) 时加分
_PROMPT_NAME_HINTS = frozenset({
    "prompt", "query", "input", "message", "ask", "question",
    "text", "content", "instruction", "command", "request",
    "user", "chat", "msg", "q", "prompt",
})

# 字段值明显不是 prompt 的模式 (正则)
_NON_PROMPT_PATTERNS = [
    re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I),  # UUID
    re.compile(r"^[a-zA-Z0-9_/-]{20,}$"),  # 长 token/key/路径 (无空格, 含分隔符)
    re.compile(r"^https?://"),  # URL
    re.compile(r"^/\w"),  # 文件路径
    re.compile(r"^\d+$"),  # 纯数字
]

# 明确不是 prompt 的值 (大小写不敏感)
_NON_PROMPT_VALUES = frozenset({
    "", "true", "false", "null", "none",
    "user", "assistant", "system", "function",
})


def _find_key_ci(data: dict[str, Any], target: str) -> str | None:
    """大小写不敏感地查找 dict key, 返回原始 key 名。"""
    target_lower = target.lower()
    for k in data:
        if k.lower() == target_lower:
            return k
    return None


def _find_value_ci(data: dict[str, Any], target: str) -> Any:
    """大小写不敏感地查找 dict key, 返回对应的值 (或 None)。

    与 _find_key_ci 类似但直接返回值, 用于从 JSON 对象中
    大小写不敏感地提取字段值 (如 chat_session_id / Chat_Session_Id)。
    """
    target_lower = target.lower()
    for k, v in data.items():
        if k.lower() == target_lower:
            return v
    return None


def _is_likely_non_prompt(value: Any) -> bool:
    """判断一个字段值是否明显不是用户输入的 prompt。

    Args:
        value: 字段值 (已从 JSON 解析的 Python 对象)。

    Returns:
        True 如果该值明显不是 prompt。
    """
    if not isinstance(value, str):
        return True  # 非字符串 (bool/int/float/list/dict/None) 不是 prompt

    stripped = value.strip()

    # 空字符串
    if not stripped:
        return True

    # 明确的非 prompt 值
    if stripped.lower() in _NON_PROMPT_VALUES:
        return True

    # 太短 (< 2 字符) 不太可能是有效 prompt
    if len(stripped) < 2:
        return True

    # 匹配非 prompt 模式
    for pattern in _NON_PROMPT_PATTERNS:
        if pattern.match(stripped):
            return True

    return False


def _recursive_find_prompt_path(
    obj: Any,
    current_path: tuple[str | int, ...] | None = None,
) -> tuple[str | int, ...] | None:
    """递归遍历 JSON 树, 找到最可能是 prompt 的字段路径。

    深度优先遍历所有 dict 和 list, 对每个 string 值使用与
    _score_prompt_fields 相同的评分逻辑, 返回得分最高的路径。

    适配 Baidu 等深层嵌套结构:
        message.query[0].data.text.query = "吉隆口岸大楼只剩钢筋骨架"
        → 返回 ("message", "query", 0, "data", "text", "query")

    Args:
        obj: JSON 对象 (dict/list/scalar)。
        current_path: 当前递归路径 (用于递归调用)。

    Returns:
        最佳候选的路径元组, 或 None (未找到)。
    """
    if current_path is None:
        current_path = ()

    candidates: list[tuple[tuple[str | int, ...], int]] = []

    def _recurse(o: Any, path: tuple[str | int, ...]) -> None:
        if isinstance(o, dict):
            for k, v in o.items():
                new_path = path + (k,)
                if isinstance(v, str):
                    # 对 string 值评分
                    score = _score_single_prompt_field(k, v)
                    if score > 0:
                        candidates.append((new_path, score))
                elif isinstance(v, (dict, list)):
                    _recurse(v, new_path)
        elif isinstance(o, list):
            for i, item in enumerate(o):
                new_path = path + (i,)
                if isinstance(item, str):
                    # 数组中的 string 元素 — 路径用索引
                    # 不太可能是 prompt (通常是配置数组), 但仍然评分
                    score = _score_single_prompt_field("", item)
                    if score > 0:
                        candidates.append((new_path, score))
                elif isinstance(item, (dict, list)):
                    _recurse(item, new_path)

    _recurse(obj, current_path)

    if not candidates:
        return None

    # 按分数降序排序, 取最高分
    candidates.sort(key=lambda x: x[1], reverse=True)
    best_path, best_score = candidates[0]

    # 最低分数阈值
    if best_score < 15:
        return None

    logger.debug(
        "Recursive prompt search: best path=%s (score=%d), "
        "candidates=%d",
        ".".join(str(p) for p in best_path),
        best_score,
        len(candidates),
    )
    return best_path


def _score_single_prompt_field(key: str, value: Any) -> int:
    """对单个字段 (key+value) 评分, 返回 prompt 可能性分数。

    评分逻辑与 _score_prompt_fields 中的单个字段评分相同,
    但返回分数而非 key, 支持递归调用。

    Args:
        key: 字段名 (可能是空字符串, 如数组元素)。
        value: 字段值。

    Returns:
        prompt 可能性分数 (0 = 不可能是 prompt)。
    """
    if _is_likely_non_prompt(value):
        return 0

    stripped = value.strip()

    # A. 字段值特征评分
    has_space = " " in stripped
    has_non_ascii = any(ord(c) > 127 for c in stripped)
    is_natural_lang = has_space or has_non_ascii

    # B. 字段名语义评分
    key_lower = key.lower()
    if key_lower in _PROMPT_NAME_HINTS:
        name_score = 30
    else:
        name_score = 0
        for hint in _PROMPT_NAME_HINTS:
            if hint in key_lower:
                name_score = 15
                break

    # 策略: 自然语言文本始终是候选; 纯 ASCII 无空格需要字段名语义加分
    if is_natural_lang:
        value_score = 60
    elif name_score > 0:
        value_score = 15
    else:
        # 纯 ASCII 无空格且无字段名语义 — 不是 prompt
        return 0

    return value_score + name_score


def _set_nested_value(
    data: Any,
    path: tuple[str | int, ...],
    value: Any,
) -> None:
    """在嵌套 JSON 对象中设置指定路径的值 (原地修改)。

    用于 _recursive_find_prompt_path 找到路径后注入 {PROMPT}。

    Args:
        data: JSON 对象 (dict/list)。
        path: 路径元组 (如 ("message", "query", 0, "data", "text", "query"))。
        value: 要设置的值。
    """
    current = data
    for i, key in enumerate(path):
        if i == len(path) - 1:
            # 最后一个 key — 设置值
            if isinstance(key, int):
                if isinstance(current, list):
                    current[key] = value
            elif isinstance(current, dict):
                current[key] = value
        else:
            # 中间 key — 深入
            if isinstance(key, int):
                if isinstance(current, list):
                    current = current[key]
            elif isinstance(current, dict):
                current = current[key]


def _score_prompt_fields(data: dict[str, Any]) -> str | None:
    """对 JSON body 顶层 string 字段评分, 返回最可能是 prompt 的 key。

    评分维度:
        A. 字段值特征 (主要依据):
           - 含空格 或 含非 ASCII 字符 (如中文): 自然语言, +60
           - 纯 ASCII 无空格但 >= 5 字符: 可能是 prompt 也可能是配置值, +15
           - 纯 ASCII 无空格且 < 5 字符 (如 "hi"): 弱候选, +10
        B. 字段名语义 (辅助加分):
           - 字段名 (小写) 完全匹配 prompt 语义词: +30
           - 字段名包含 prompt 语义片段: +15
        C. 排除项:
           - 字段值明显不是 prompt (UUID/URL/纯数字/长 token): 跳过
           - 字段值是空数组/空对象/空字符串: 跳过

    Args:
        data: JSON body 解析后的 dict。

    Returns:
        最可能是 prompt 的字段名, 或 None (无合适候选)。
    """
    candidates: list[tuple[str, int]] = []

    for key, value in data.items():
        # 跳过非 prompt 值
        if _is_likely_non_prompt(value):
            continue

        stripped = value.strip()

        # A. 字段值特征评分
        # 含空格 或 含非 ASCII 字符 (如中文/日文/韩文) → 自然语言 prompt
        has_space = " " in stripped
        has_non_ascii = any(ord(c) > 127 for c in stripped)
        is_natural_lang = has_space or has_non_ascii

        # B. 字段名语义评分
        key_lower = key.lower()
        if key_lower in _PROMPT_NAME_HINTS:
            name_score = 30
        else:
            name_score = 0
            for hint in _PROMPT_NAME_HINTS:
                if hint in key_lower:
                    name_score = 15
                    break

        # 策略: 自然语言文本始终是候选; 纯 ASCII 无空格需要字段名语义加分
        if is_natural_lang:
            value_score = 60
        elif name_score > 0:
            # 纯 ASCII 无空格但有字段名语义 — 可能是短 prompt (如 "hi", "hello")
            value_score = 15
        else:
            # 纯 ASCII 无空格且无字段名语义 — 跳过 (如 "gpt-4o", "blocking")
            continue

        score = value_score + name_score
        candidates.append((key, score))

    if not candidates:
        return None

    # 按分数降序排序, 取最高分
    candidates.sort(key=lambda x: x[1], reverse=True)
    best_key, best_score = candidates[0]

    # 最低分数阈值: 自然语言=60+, 字段名+值=30+, 至少15分
    if best_score < 15:
        return None

    logger.debug(
        "Prompt field scoring: %s (score=%d), candidates=%s",
        best_key, best_score,
        [(k, s) for k, s in candidates],
    )
    return best_key


# ════════════════════════════════════════════════════════════════════
# AI 框架/SDK 指纹识别目录 (从 RedAmon ai_signal_catalog.py 借鉴)
# 学术依据: PTES §2 — 框架指纹识别后的针对性探测
#          OWASP WSTG-INFO-03 — 框架指纹识别
# 三层检测: Header 模式 + Title 模式 + Body 指纹
# 全部从 Burp Response 静态提取 (0 额外请求)
# ════════════════════════════════════════════════════════════════════

# AI Header 指纹模式 (响应 header 名匹配, 大小写不敏感)
# (header_name_pattern, framework_name, technology_category)
_AI_HEADER_PATTERNS: list[tuple[re.Pattern[str], str, str]] = [
    # ── AI 运行时 ── (最强信号)
    (re.compile(r"^x-vllm-", re.I), "vllm", "ai-runtime"),
    (re.compile(r"^x-tgi-", re.I), "tgi", "ai-runtime"),
    (re.compile(r"^x-tei-", re.I), "text-embeddings-inference", "ai-runtime"),
    (re.compile(r"^x-bentoml-", re.I), "bentoml", "ai-runtime"),
    (re.compile(r"^x-baseten-", re.I), "baseten", "ai-runtime"),
    (re.compile(r"^x-modal-", re.I), "modal", "ai-runtime"),
    (re.compile(r"^x-replicate-", re.I), "replicate", "ai-runtime"),
    (re.compile(r"^x-runpod-", re.I), "runpod", "ai-runtime"),
    # ── AI 框架/编排器 ──
    (re.compile(r"^x-langchain-", re.I), "langchain", "ai-framework"),
    (re.compile(r"^x-llamaindex-", re.I), "llamaindex", "ai-framework"),
    (re.compile(r"^langfuse-", re.I), "langfuse", "ai-framework"),
    # ── AI 代理/网关 ──
    (re.compile(r"^x-litellm-", re.I), "litellm", "ai-proxy"),
    (re.compile(r"^x-helicone-", re.I), "helicone", "ai-proxy"),
    (re.compile(r"^x-portkey-", re.I), "portkey", "ai-proxy"),
    (re.compile(r"^x-omniroute-", re.I), "omniroute", "ai-proxy"),
    (re.compile(r"^cf-aig-", re.I), "cloudflare-ai-gateway", "ai-proxy"),
    (re.compile(r"^together-", re.I), "together", "ai-proxy"),
    # ── AI SDK 客户端 (代理的厂商调用) ──
    (re.compile(r"^openai-(organization|version|processing-ms)", re.I), "openai", "ai-sdk-client"),
    (re.compile(r"^anthropic-(version|beta|ratelimit-)", re.I), "anthropic", "ai-sdk-client"),
    (re.compile(r"^x-ms-region$|^azureml-model-session$", re.I), "azure-openai", "ai-sdk-client"),
    (re.compile(r"^x-ratelimit-limit-tokens-cache-adjusted-prompt$|^x-fireworks-account-id$", re.I), "fireworks", "ai-sdk-client"),
    # ── MCP ──
    (re.compile(r"^x-mcp-", re.I), "mcp", "ai-framework"),
]

# AI Title 指纹模式 (HTML <title> 匹配, 大小写不敏感)
_AI_TITLE_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # ── 聊天/通用 LLM 前端 ──
    (re.compile(r"\bOpen WebUI\b", re.I), "open-webui"),
    (re.compile(r"\bLibreChat\b", re.I), "librechat"),
    (re.compile(r"\bAnythingLLM\b", re.I), "anythingllm"),
    (re.compile(r"\bFlowise\b", re.I), "flowise"),
    (re.compile(r"\bLangflow\b", re.I), "langflow"),
    (re.compile(r"\bDify\b", re.I), "dify"),
    (re.compile(r"\bComfyUI\b", re.I), "comfyui"),
    (re.compile(r"\bGradio\b", re.I), "gradio"),
    (re.compile(r"\bStreamlit\b", re.I), "streamlit"),
    (re.compile(r"\bBetterChatGPT\b", re.I), "betterchatgpt"),
    (re.compile(r"\bOnyx\b|\bDanswer\b", re.I), "onyx"),
    (re.compile(r"\bChatGPT\b", re.I), "chatgpt-clone"),
    (re.compile(r"\bHuggingFace Chat UI\b", re.I), "hf-chat-ui"),
    (re.compile(r"\bLobeChat\b|\bLobeHub\b", re.I), "lobechat"),
    (re.compile(r"\bNextChat\b", re.I), "nextchat"),
    (re.compile(r"\bSillyTavern\b", re.I), "sillytavern"),
    (re.compile(r"\bh2oGPT\b", re.I), "h2ogpt"),
    (re.compile(r"\bPrivateGPT\b", re.I), "privategpt"),
    (re.compile(r"\bQuivr\b", re.I), "quivr"),
    # ── 图像生成 UI ──
    (re.compile(r"\bInvoke\s*-\s*Community Edition\b", re.I), "invokeai"),
    (re.compile(r"^Stable Diffusion$", re.I), "automatic1111"),
    # ── MLOps/可观测性前端 ──
    (re.compile(r"^MLflow$", re.I), "mlflow"),
    (re.compile(r"^Labelstudio$", re.I), "label-studio"),
    (re.compile(r"\bRay Dashboard\b", re.I), "ray-dashboard"),
    (re.compile(r"\bRedisInsight\b", re.I), "redis-insight"),
    (re.compile(r"\bAutoGen Studio\b", re.I), "autogen-studio"),
    (re.compile(r"\bLangfuse\b", re.I), "langfuse-ui"),
    (re.compile(r"\bArize Phoenix\b|^Phoenix$", re.I), "phoenix-arize"),
    (re.compile(r"\bArgilla\b", re.I), "argilla"),
    (re.compile(r"\bGPT Researcher\b", re.I), "gpt-researcher"),
]

# AI Body 指纹 (Wappalyzer 风格, 响应体正则匹配)
_AI_BODY_FINGERPRINTS: list[tuple[re.Pattern[str], str, str]] = [
    # ── 运行时 ──
    (re.compile(r"""(?:action|href|fetch\()\s*=?\s*["']/generate_stream["']""", re.I), "tgi", "ai-runtime"),
    (re.compile(r"\bvllm_session\b", re.I), "vllm", "ai-runtime"),
    (re.compile(r"\bOllama is running\b", re.I), "ollama", "ai-runtime"),
    # ── 框架 ──
    (re.compile(r"window\.__LANGCHAIN__|window\.__LANGCHAIN_TRACING_V2__", re.I), "langchain", "ai-framework"),
    (re.compile(r"""@langchain/(core|community|langgraph|openai|anthropic)["']""", re.I), "langchain", "ai-framework"),
    (re.compile(r"""@llamaindex/(core|flow|langchain)["']""", re.I), "llamaindex", "ai-framework"),
    # ── 前端产品 ──
    (re.compile(r"\btxt2img_textarea\b", re.I), "automatic1111", "ai-frontend"),
    (re.compile(r'"flowise_"', re.I), "flowise", "ai-frontend"),
    (re.compile(r"\bstreamlit_\b", re.I), "streamlit", "ai-frontend"),
    (re.compile(r'\bgradio\b', re.I), "gradio", "ai-frontend"),
    # ── SDK ──
    (re.compile(r"""from openai import|import openai""", re.I), "openai-sdk", "ai-sdk-client"),
    (re.compile(r"""from anthropic import|import anthropic""", re.I), "anthropic-sdk", "ai-sdk-client"),
    (re.compile(r"""from litellm import|import litellm""", re.I), "litellm", "ai-proxy"),
]


def _extract_fingerprint(
    headers: dict[str, str],
    path: str,
    host: str,
    response_section: str | None = None,
) -> TargetFingerprint:
    """从 HTTP 请求和响应中提取目标指纹信息 (Phase 1 解析输出)。

    用于报告中的目标识别:
        - framework: 从 header 推断前端框架
        - api_path: API 路径
        - auth_type: 认证方式
        - content_type: 请求内容类型
        - ai_framework: AI 框架/SDK 识别 (从 Response headers/title/body)
        - ai_framework_category: AI 技术类别 (ai-runtime/ai-framework/ai-proxy/ai-frontend/ai-sdk-client)

    学术依据:
        - PTES §2 — 框架指纹识别后的针对性探测
        - OWASP WSTG-INFO-03 — 框架指纹识别
        - RedAmon ai_signal_catalog.py — AI 框架指纹三层检测

    Args:
        headers: 请求 headers (大小写不敏感)。
        path: 请求路径。
        host: 主机名。
        response_section: Burp Response 原始文本 (可选, 用于 AI 框架指纹识别)。

    Returns:
        TargetFingerprint 指纹信息实例。
    """
    # ── Phase 1: 解析框架 / 认证 / 内容类型 ──
    server = headers.get("server", "")
    x_powered = headers.get("x-powered-by", "")
    if "next" in (server + x_powered).lower():
        framework = "Next.js"
    elif "express" in (server + x_powered).lower():
        framework = "Express.js"
    elif "fastapi" in (server + x_powered).lower():
        framework = "FastAPI"
    elif "django" in (server + x_powered).lower():
        framework = "Django"
    else:
        framework = "Unknown"

    if "authorization" in headers:
        auth = headers["authorization"]
        if auth.lower().startswith("bearer"):
            auth_type = "Bearer Token"
        elif auth.lower().startswith("basic"):
            auth_type = "Basic Auth"
        else:
            auth_type = "Custom Auth Header"
    elif "cookie" in headers:
        auth_type = "Cookie-based"
    else:
        auth_type = "None"

    content_type = headers.get("content-type", "unknown")

    # 从路径推断应用类型 (通用分类, 适配任意 LLM Agent 应用)
    path_lower = path.lower()
    if "/challenges/" in path_lower or "/scenarios/" in path_lower or "/arena/" in path_lower:
        app_type = "Testing/Arena"
    elif "/agent" in path_lower or "/mcp" in path_lower or "/tool" in path_lower:
        app_type = "Agent Application"
    elif "/chat" in path_lower or "/completion" in path_lower or "/message" in path_lower:
        app_type = "Chat Application"
    elif "/rag" in path_lower or "/knowledge" in path_lower or "/retriev" in path_lower or "/embed" in path_lower:
        app_type = "RAG Application"
    else:
        app_type = "Web Application"

    # ════════════════════════════════════════════════════════════════
    # AI 框架/SDK 指纹识别 (从 Burp Response 静态提取, 0 额外请求)
    # 学术依据: RedAmon ai_signal_catalog.py — 三层检测
    # ════════════════════════════════════════════════════════════════
    ai_fw: str | None = None
    ai_fw_cat: str | None = None
    if response_section:
        ai_fw, ai_fw_cat = _extract_ai_framework_fingerprint(response_section)
    # 从请求 header 中检测 AI SDK 客户端特征
    sdk_fw, sdk_fw_cat = _extract_ai_sdk_from_request_headers(headers)
    if sdk_fw and not ai_fw:
        ai_fw, ai_fw_cat = sdk_fw, sdk_fw_cat

    return TargetFingerprint(
        framework=framework,
        api_path=path,
        host=host,
        auth_type=auth_type,
        content_type=content_type,
        app_type=app_type,
        ai_framework=ai_fw,
        ai_framework_category=ai_fw_cat,
    )


def _extract_ai_framework_fingerprint(
    response_section: str,
) -> tuple[str | None, str | None]:
    """从 Burp Response 中提取 AI 框架指纹 (0 额外请求)。

    三层检测:
        1. Response Header 模式匹配 (x-vllm-*, x-langchain-*, 等)
        2. HTML <title> 模式匹配 (Open WebUI, LibreChat, Gradio, 等)
        3. Body Wappalyzer 风格指纹 (LangChain globals, SDK import, 等)

    Args:
        response_section: Burp Response 原始文本。

    Returns:
        (framework_name, category) 元组, 未检测到返回 (None, None)。
    """
    if not response_section or not response_section.strip():
        return None, None

    # 分离 Response headers 和 body
    resp_headers, resp_body = _split_response_headers_body(response_section)

    # ── 层 1: Response Header 模式匹配 ──
    for header_name, _header_value in resp_headers:
        for pattern, fw_name, fw_category in _AI_HEADER_PATTERNS:
            if pattern.search(header_name):
                logger.debug(
                    "AI framework detected from response header '%s': %s (%s)",
                    header_name,
                    fw_name,
                    fw_category,
                )
                return fw_name, fw_category

    # ── 层 2: HTML <title> 模式匹配 ──
    title_match = re.search(r"<title[^>]*>(.*?)</title>", resp_body, re.I | re.DOTALL)
    if title_match:
        title_text = title_match.group(1).strip()
        for pattern, fw_name in _AI_TITLE_PATTERNS:
            if pattern.search(title_text):
                logger.debug("AI framework detected from <title>: %s", fw_name)
                return fw_name, "ai-frontend"

    # ── 层 3: Body Wappalyzer 风格指纹 ──
    for pattern, fw_name, fw_category in _AI_BODY_FINGERPRINTS:
        if pattern.search(resp_body):
            logger.debug(
                "AI framework detected from body fingerprint: %s (%s)",
                fw_name,
                fw_category,
            )
            return fw_name, fw_category

    return None, None


def _extract_ai_sdk_from_request_headers(
    request_headers: dict[str, str],
) -> tuple[str | None, str | None]:
    """从请求 headers 中检测 AI SDK 客户端特征。

    请求 header 中的认证 header 或自定义 header 可能暴露 SDK 来源:
        - Authorization: Bearer sk-xxx → OpenAI 风格
        - x-api-key: xxx → Anthropic 风格
        - api-key: xxx → Azure OpenAI 风格

    Args:
        request_headers: 请求 headers。

    Returns:
        (framework_name, category) 元组, 未检测到返回 (None, None)。
    """
    # 检测 Anthropic SDK 特征
    for key in request_headers:
        if key.lower().startswith("anthropic-"):
            return "anthropic", "ai-sdk-client"

    # 检测 OpenAI SDK 特征
    for key in request_headers:
        if key.lower().startswith("openai-"):
            return "openai", "ai-sdk-client"

    # 检测 Azure OpenAI 特征
    if "api-key" in request_headers or "x-ms-region" in request_headers:
        return "azure-openai", "ai-sdk-client"

    # 检测 MCP 特征
    for key in request_headers:
        if key.lower().startswith("x-mcp-"):
            return "mcp", "ai-framework"

    return None, None


def _split_response_headers_body(
    response_section: str,
) -> tuple[list[tuple[str, str]], str]:
    """分离 Response 的 headers 和 body。

    Args:
        response_section: Burp Response 原始文本
            (格式: "HTTP/1.x status\\r?\\nheaders\\r?\\n\\r?\\nbody")。

    Returns:
        (headers_list, body_text) 元组:
        - headers_list: [(header_name, header_value), ...]
        - body_text: 响应体文本。
    """
    normalized = response_section.replace("\r\n", "\n").replace("\r", "\n")

    # 找到 headers 和 body 的分隔点 (第一个空行)
    split_idx = normalized.find("\n\n")
    if split_idx == -1:
        # 无空行分隔, 全部视为 body
        return [], normalized

    header_section = normalized[:split_idx]
    body = normalized[split_idx + 2:]

    # R8-4 边界条件: body 可能为空 (如 204 No Content)
    # 解析 headers (跳过 status line)
    headers_list: list[tuple[str, str]] = []
    for line in header_section.split("\n"):
        line = line.strip()
        if not line or line.startswith("HTTP/"):
            continue
        if ":" in line:
            name, value = line.split(":", 1)
            headers_list.append((name.strip(), value.strip()))

    return headers_list, body


def build_raw_http_request(parsed: ParsedBurpRequest) -> str:
    """重建原始 HTTP 请求字符串 (CRLF 格式)。

    使用原始 header 顺序, 自动更新 Content-Length。
    """
    lines = [f"{parsed.method} {parsed.path} {parsed.http_version}"]

    for key, value in parsed.raw_headers:
        if key.lower() == "content-length":
            continue
        lines.append(f"{key}: {value}")

    if parsed.body:
        lines.append(f"Content-Length: {len(parsed.body.encode('utf-8'))}")

    request = "\r\n".join(lines)
    if parsed.body:
        request += "\r\n\r\n" + parsed.body
    else:
        request += "\r\n\r\n"
    return request


# Re-exports from split modules for backwards compatibility (at end to avoid circular imports)
from recon.capability_detector import (  # noqa: F401, E402
    _detect_language,
    _detect_model_family,
    _infer_json_path,
    _probe_capabilities,
    probe_active_capabilities,
    probe_response_path,
)
from recon.target_builder import (  # noqa: F401, E402
    build_http_target,
    build_httpx_api_target,
    RequestPreprocessor,
    ChatIdStateManager,
)
