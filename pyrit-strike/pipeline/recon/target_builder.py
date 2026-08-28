"""target_builder — 从 burp_parser.py 拆分而来.

包含 JSONSafeHTTPTarget, HTTP target 构建, callback 选择.
"""

import logging
import re
from typing import Any

from pyrit.prompt_target import HTTPTarget, get_http_target_json_response_callback_function

from pipeline.recon.burp_parser import ParsedBurpRequest, _make_sse_callback, build_raw_http_request

logger = logging.getLogger(__name__)

class JSONSafeHTTPTarget(HTTPTarget):
    """JSON 安全的 HTTPTarget — 正确转义 prompt 中的特殊字符。

    L5 v4 修复:
        原始 HTTPTarget._inject_prompt_into_request 使用正则替换 {PROMPT}，
        当 prompt 包含 \\n, \\", \\\\ 等字符时会破坏 JSON body 结构，
        导致 422 Unprocessable Entity 错误。

    本子类重写 _inject_prompt_to_target_async，在替换 {PROMPT} 后
    重新序列化 JSON body，确保所有特殊字符被正确转义。

    仅当 body 是 JSON 格式时才进行此处理；非 JSON body 走原始路径。
    """

    def _inject_prompt_into_request(self, request: Any) -> str:
        """注入 prompt 到 HTTP 请求，JSON body 安全转义。

        策略:
            1. 检测 body 是否为 JSON 格式
            2. 如果是 JSON: 解析 → 替换 {PROMPT} → 重新序列化
            3. 如果不是 JSON: 走原始正则替换路径
        """
        import json as json_mod

        re_pattern = re.compile(self.prompt_regex_string)
        if not re.search(self.prompt_regex_string, self.http_request):
            return self.http_request

        # 获取 prompt 文本
        prompt_text = request.converted_value

        # 尝试 JSON 安全注入
        normalized = self.http_request.replace("\r\n", "\n")
        parts = normalized.split("\n\n", 1)
        if len(parts) < 2 or not parts[1].strip():
            # 无 body，走原始路径
            return re_pattern.sub(lambda m: prompt_text, self.http_request)

        body_text = parts[1]

        # 尝试解析为 JSON
        try:
            body_obj = json_mod.loads(body_text)
        except (json_mod.JSONDecodeError, TypeError):
            # 非 JSON body，走原始路径
            return re_pattern.sub(lambda m: prompt_text, self.http_request)

        # JSON body: 递归替换所有 {PROMPT} 值
        def _replace_in_obj(obj: Any) -> Any:
            if isinstance(obj, str):
                if obj == "{PROMPT}":
                    return prompt_text
                return obj.replace("{PROMPT}", prompt_text)
            elif isinstance(obj, dict):
                return {k: _replace_in_obj(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [_replace_in_obj(item) for item in obj]
            return obj

        body_replaced = _replace_in_obj(body_obj)
        new_body = json_mod.dumps(body_replaced, ensure_ascii=False)

        # 重建 HTTP 请求 (保持 CRLF 格式)
        # 保留原始 header 部分 (含 \r\n)
        raw_headers = parts[0].replace("\n", "\r\n")
        result = raw_headers + "\r\n\r\n" + new_body

        return result

def build_http_target(
    parsed: ParsedBurpRequest,
    *,
    enable_multi_turn: bool = False,
) -> HTTPTarget:
    """从解析结果构建 PyRIT 原生 HTTPTarget。

    L5 v4: 使用 JSONSafeHTTPTarget 替代原始 HTTPTarget，
    确保包含控制字符的 prompt 不会破坏 JSON body 结构。

    回调函数选择:
        - 如果已探测到 JSON 路径 → 使用该路径
        - SSE 响应 → regex 匹配
        - JSON 响应 → 尝试常见路径
        - 默认 → 返回原始响应内容

    Args:
        parsed: 解析后的 Burp 请求。
        enable_multi_turn: 是否声明多轮攻击能力 (用于 Crescendo/TAP)。
            HTTPTarget 本身是无状态的，多轮对话通过在 prompt 中
            携带对话历史来实现。

    Returns:
        HTTPTarget: PyRIT 原生 HTTP 目标实例。
    """
    raw_request = build_raw_http_request(parsed)
    callback = _select_callback(parsed)

    httpx_kwargs: dict[str, Any] = {
        "timeout": 120.0,
        "follow_redirects": True,
    }

    # 构建 custom_configuration (声明多轮攻击能力)
    custom_config = None
    if enable_multi_turn:
        from pyrit.prompt_target.common.target_configuration import (
            TargetCapabilities,
            TargetConfiguration,
        )
        custom_config = TargetConfiguration(
            capabilities=TargetCapabilities(
                supports_multi_turn=True,
                supports_editable_history=True,
            ),
        )

    # L5 v4: 使用 JSONSafeHTTPTarget 替代原始 HTTPTarget
    target = JSONSafeHTTPTarget(
        http_request=raw_request,
        prompt_regex_string="{PROMPT}",
        callback_function=callback,
        use_tls=parsed.use_tls,
        custom_configuration=custom_config,
        **httpx_kwargs,
    )

    logger.info(
        "JSONSafeHTTPTarget built: %s %s (TLS=%s, SSE=%s, placeholder=%s, callback=%s, multi_turn=%s)",
        parsed.method,
        parsed.url,
        parsed.use_tls,
        parsed.is_sse,
        parsed.has_prompt_placeholder,
        getattr(callback, "__name__", "None"),
        enable_multi_turn,
    )
    return target

def _select_callback(parsed: ParsedBurpRequest) -> Any:
    """根据响应格式选择回调函数。

    优先级:
        1. 已探测的 JSON 路径
        2. SSE → regex 匹配
        3. JSON 常见路径
    """
    # 1. 已探测的 JSON 路径
    if parsed.response_json_path:
        callback = get_http_target_json_response_callback_function(key=parsed.response_json_path)
        logger.info("Using probed JSON callback with path: %s", parsed.response_json_path)
        return callback

    # 2. SSE
    if parsed.is_sse:
        logger.info("Using custom SSE callback for response parsing")
        return _make_sse_callback()

    # 3. JSON 常见路径 (按优先级排序)
    json_paths = [
        "choices[0].message.content",   # OpenAI 格式
        "data.content",                 # 通用 data.content
        "response",                     # 直接 response
        "result",                       # result
        "output",                       # output
        "message",                      # message
        "text",                         # text
        "content",                      # content
        "answer",                       # answer
        "reply",                        # reply
        "data.message",                 # data.message
        "data.response",                # data.response
        "data.answer",                  # data.answer
    ]

    # 使用第一个路径 (最常见)
    path = json_paths[0]
    callback = get_http_target_json_response_callback_function(key=path)
    logger.info("Using default JSON callback with path: %s", path)
    return callback
