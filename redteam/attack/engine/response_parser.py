"""LLM API 响应解析工具 — 兼容 OpenAI 标准格式与 Ollama 原生格式。

AI-300 章节映射：Ch3: Single-Agent Attacks
技术点：Ollama 非标准 /v1/chat/completions 响应解析、done_reason:"load" 检测与重试
"""

from __future__ import annotations

import json
import logging

logger = logging.getLogger(__name__)


def extract_response_text(body_text: str) -> str:
    """从 LLM API 响应（JSON 文本）中提取实际回复内容。

    兼容格式：
      - OpenAI 标准: {"choices": [{"message": {"content": "..."}}]}
      - Ollama 原生:   {"response": "...", "done": true}
      - Ollama 非标准: {"message": {"content": "..."}}

    Args:
        body_text: API 响应原始文本

    Returns:
        提取的文本内容，解析失败则返回原始 body_text
    """
    try:
        data = json.loads(body_text)
    except json.JSONDecodeError:
        return body_text

    # 标准 OpenAI 格式
    choices = data.get("choices")
    if choices and isinstance(choices, list) and choices:
        return choices[0].get("message", {}).get("content", body_text)

    # Ollama 原生 response 字段
    response = data.get("response")
    if response:
        return response

    # Ollama 某些版本的 message.content
    msg_content = data.get("message", {}).get("content")
    if msg_content:
        return msg_content

    return body_text


def is_ollama_loading(body_text: str) -> bool:
    """检测 Ollama 模型懒加载中的响应。

    Ollama 默认 5 分钟空闲后卸载模型。首次请求触发加载时返回：
      {"model":"...","response":"","done":true,"done_reason":"load"}

    Args:
        body_text: API 响应原始文本

    Returns:
        True 表示模型正在加载，需要等待并重试
    """
    return '"done_reason":"load"' in body_text


def _ollama_load_retry(
    client_factory,
    max_retries: int = 3,
    delay_seconds: float = 3.0,
) -> str | None:
    """Ollama 模型加载重试循环（内部工具函数）。

    Args:
        client_factory: 可调用对象，返回 (response, body_text) 元组
        max_retries: 最大重试次数
        delay_seconds: 重试间隔（秒）

    Returns:
        最终 body_text，加载成功返回响应文本，超时返回 None（调用方应使用最后一次结果）
    """
    import time

    for attempt in range(1, max_retries + 1):
        logger.info(
            "Ollama 模型加载中（%d/%d），等待 %.0fs 后重试...",
            attempt, max_retries, delay_seconds,
        )
        time.sleep(delay_seconds)
        _r, body_text = client_factory()
        if not is_ollama_loading(body_text):
            return body_text

    logger.warning("Ollama 模型加载重试耗尽（%d 次），使用最后一次响应", max_retries)
    return None


__all__ = [
    "extract_response_text",
    "is_ollama_loading",
]
