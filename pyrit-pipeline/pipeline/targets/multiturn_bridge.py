# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""MultiTurnConversationBridge — HTTPTarget 多轮对话历史管理 (V-67).

为 Burp 模式下的 HTTPTarget 提供多轮对话历史管理,
使 Crescendo/TAP/PAIR 等多轮攻击技术能够在 HTTP API 端点上执行.

核心原理:
  - HTTPTarget 是无状态 HTTP 请求发送器 (每次发送独立请求)
  - 多轮攻击 (如 Crescendo) 需要在多轮之间维护对话历史
  - 本模块通过在 Burp 请求体中注入历史消息实现多轮对话
  - 每轮攻击的 {PROMPT} 占位符被替换为: 历史消息 + 当前攻击消息

设计原则 (R-022: PyRIT 原生优先):
  - 不修改 PyRIT 原生 HTTPTarget 类
  - 不继承、不覆盖 send_prompt_async
  - 仅作为数据层: 构建多轮请求体, 由 RateLimitedTarget 发送
  - 通过 session_id 关联同一对话的多轮请求

学术依据:
  - Russinovich et al. (arXiv:2402.12109): Crescendo 渐进攻击需多轮对话
  - Mehrotra et al. (arXiv:2312.02191): TAP 树搜索需对话历史
  - PyRIT (arXiv:2407.01232): HTTPTarget 无状态, 需外部管理历史

> **日期**: 2026-8-16
"""

from __future__ import annotations

import json
import logging
import uuid

logger = logging.getLogger(__name__)

# ── A-7: 重要性评分权重 ──
_IMPORTANCE_WEIGHTS = {
    "success_indicator": 0.4,  # 包含攻击成功关键词
    "refusal_indicator": 0.3,  # 包含拒绝关键词 (帮助分析失败)
    "length_factor": 0.1,  # 长响应通常更相关
    "position_factor": 0.2,  # 较新消息权重更高
}

_SUCCESS_KEYWORDS = {
    "sure", "here is", "here's", "certainly", "of course", "i can",
    "当然", "好的", "没问题", "以下是", "我帮你",
}
_REFUSAL_KEYWORDS = {
    "sorry", "cannot", "can't", "i'm not able", "i cannot",
    "抱歉", "不能", "无法", "拒绝", "不可以",
}


class MultiTurnConversationBridge:
    """HTTPTarget 多轮对话历史管理器.

    为无状态的 HTTPTarget 管理多轮对话历史,
    通过在 Burp 请求体中注入历史消息实现多轮效果.

    使用方式::

        bridge = MultiTurnConversationBridge()
        session_id = bridge.create_session()

        # 第一轮
        body_round_1 = bridge.inject_history(
            raw_body=original_body,
            session_id=session_id,
            current_prompt="第一轮攻击消息",
        )

        # 第二轮 (含第一轮历史)
        body_round_2 = bridge.inject_history(
            raw_body=original_body,
            session_id=session_id,
            current_prompt="第二轮攻击消息",
        )
    """

    def __init__(
        self,
        *,
        max_history_turns: int = 10,
        max_history_tokens: int = 4000,
        smart_truncation: bool = True,
    ) -> None:
        """初始化多轮对话桥接器.

        Args:
            max_history_turns: 最大保留历史轮次 (防止请求体过大).
            max_history_tokens: 最大保留历史 token 数 (P1: 防止长历史导致 API 超时).
                按 1 token ≈ 4 chars 估算, 超过时从最旧消息开始删除.
            smart_truncation: A-7 启用智能截断 — 基于重要性评分保留关键消息.
                重要性评分 = 成功/拒绝关键词匹配 + 消息长度 + 位置权重.
                超过 token 限制时, 优先保留高重要性消息.
        """
        self._sessions: dict[str, list[dict[str, str]]] = {}
        self._max_history_turns = max_history_turns
        self._max_history_tokens = max_history_tokens
        self._smart_truncation = smart_truncation

    def create_session(self) -> str:
        """创建新的对话会话.

        Returns:
            唯一会话 ID (UUID v4).
        """
        session_id = str(uuid.uuid4())
        self._sessions[session_id] = []
        return session_id

    def add_turn(
        self,
        session_id: str,
        *,
        role: str,
        content: str,
    ) -> None:
        """向会话添加一轮对话.

        Args:
            session_id: 会话 ID.
            role: 消息角色 (user/assistant/system).
            content: 消息内容.
        """
        if session_id not in self._sessions:
            self._sessions[session_id] = []

        self._sessions[session_id].append({"role": role, "content": content})

        # 截断历史 (保留最近的 N 轮)
        if len(self._sessions[session_id]) > self._max_history_turns * 2:
            # 保留最后 max_history_turns * 2 条消息 (每轮 user+assistant)
            self._sessions[session_id] = self._sessions[session_id][
                -(self._max_history_turns * 2):
            ]

        # P1: Token 级截断 — 防止长历史导致 API 超时
        if self._smart_truncation:
            self._smart_truncate_by_tokens(session_id)
        else:
            self._truncate_by_tokens(session_id)

    def inject_history(
        self,
        raw_body: str,
        *,
        session_id: str,
        current_prompt: str,
    ) -> str:
        """将对话历史注入到 Burp 请求体中.

        将 {PROMPT} 占位符替换为: 历史消息数组 + 当前攻击消息.
        支持 OpenAI messages 格式和非 OpenAI 格式.

        Args:
            raw_body: 原始 Burp 请求体 (含 {PROMPT} 占位符).
            session_id: 会话 ID.
            current_prompt: 当前轮次的攻击消息.

        Returns:
            注入历史后的请求体.
        """
        history = self._sessions.get(session_id, [])

        try:
            data = json.loads(raw_body)

            if isinstance(data, dict) and "messages" in data:
                # OpenAI 格式: 追加历史消息 + 当前消息
                messages = data["messages"]
                if isinstance(messages, list):
                    # 替换 {PROMPT} 为当前攻击消息
                    for msg in messages:
                        if isinstance(msg, dict) and msg.get("content") == "{PROMPT}":
                            msg["content"] = current_prompt
                    # 在 {PROMPT} 消息之前插入历史
                    # 找到 {PROMPT} 消息的位置 (已在上面被替换)
                    # 历史消息插入到当前消息之前
                    prompt_idx = None
                    for i, msg in enumerate(messages):
                        if isinstance(msg, dict) and msg.get("content") == current_prompt:
                            prompt_idx = i
                            break
                    if prompt_idx is not None and history:
                        messages = messages[:prompt_idx] + history + messages[prompt_idx:]
                        data["messages"] = messages
                    return json.dumps(data, ensure_ascii=False)

            # 非 OpenAI 格式: 尝试将历史拼接到 prompt 字段
            if isinstance(data, dict):
                prompt_field = None
                for field_name in ("prompt", "input", "query", "text", "message", "content"):
                    if field_name in data and isinstance(data[field_name], str):
                        prompt_field = field_name
                        break
                if prompt_field and data[prompt_field] == "{PROMPT}":
                    # 构建历史上下文前缀
                    history_text = self._format_history_as_text(history)
                    data[prompt_field] = history_text + current_prompt if history_text else current_prompt
                    return json.dumps(data, ensure_ascii=False)

        except (json.JSONDecodeError, TypeError):
            pass

        # 非 JSON: 直接替换 {PROMPT}
        history_text = self._format_history_as_text(history)
        result = raw_body.replace(
            "{PROMPT}",
            (history_text + current_prompt) if history_text else current_prompt,
        )
        return result

    def _format_history_as_text(self, history: list[dict[str, str]]) -> str:
        """将历史消息格式化为文本前缀.

        Args:
            history: 历史消息列表.

        Returns:
            格式化的历史文本 (含换行分隔), 或空字符串.
        """
        if not history:
            return ""

        lines: list[str] = ["[Previous conversation history]"]
        for msg in history:
            role = msg.get("role", "unknown")
            content = msg.get("content", "")
            lines.append(f"{role}: {content}")
        lines.append("[End of history]")
        lines.append("")  # 空行分隔
        return "\n".join(lines)

    def _truncate_by_tokens(self, session_id: str) -> None:
        """P1: 按 token 估算截断历史, 防止长历史导致 API 超时.

        估算规则: 1 token ≈ 4 chars (英文), 中文约 1 token ≈ 2 chars.
        取保守值 3 chars/token 进行估算.

        超过 max_history_tokens 时, 从最旧的消息开始删除,
        直到总 token 数不超过阈值.
        """
        messages = self._sessions.get(session_id, [])
        if not messages:
            return

        total_chars = sum(len(m.get("content", "")) for m in messages)
        estimated_tokens = total_chars // 3  # 保守估算

        while estimated_tokens > self._max_history_tokens and len(messages) > 2:
            # 删除最旧的消息 (保持至少 1 轮 user+assistant)
            messages.pop(0)
            total_chars = sum(len(m.get("content", "")) for m in messages)
            estimated_tokens = total_chars // 3

        self._sessions[session_id] = messages

    def _smart_truncate_by_tokens(self, session_id: str) -> None:
        """A-7: 智能截断 — 基于重要性评分保留关键消息.

        为每条消息计算重要性评分, 超过 token 限制时
        优先保留高重要性消息 (成功指示 / 拒绝指示 / 较新消息).

        评分公式:
            score = 0.4 * success_match + 0.3 * refusal_match
                  + 0.1 * length_factor + 0.2 * position_factor

        Args:
            session_id: 会话 ID.
        """
        messages = self._sessions.get(session_id, [])
        if not messages:
            return

        total_chars = sum(len(m.get("content", "")) for m in messages)
        estimated_tokens = total_chars // 3

        if estimated_tokens <= self._max_history_tokens:
            return

        # 计算每条消息的重要性评分
        n = len(messages)
        scored_messages: list[tuple[float, dict[str, str]]] = []
        for i, msg in enumerate(messages):
            content = msg.get("content", "")
            content_lower = content.lower()

            # 成功关键词匹配
            success_match = 1.0 if any(kw in content_lower for kw in _SUCCESS_KEYWORDS) else 0.0

            # 拒绝关键词匹配
            refusal_match = 1.0 if any(kw in content_lower for kw in _REFUSAL_KEYWORDS) else 0.0

            # 长度因子 (归一化到0-1)
            length_factor = min(len(content) / 500.0, 1.0)

            # 位置因子 (较新消息权重更高, 归一化到0-1)
            position_factor = (i + 1) / n if n > 0 else 0.0

            score = (
                _IMPORTANCE_WEIGHTS["success_indicator"] * success_match
                + _IMPORTANCE_WEIGHTS["refusal_indicator"] * refusal_match
                + _IMPORTANCE_WEIGHTS["length_factor"] * length_factor
                + _IMPORTANCE_WEIGHTS["position_factor"] * position_factor
            )

            scored_messages.append((score, msg))

        # 按评分降序排序, 保留高评分消息
        # 但始终保留最后 2 条消息 (最新一轮对话)
        scored_messages.sort(key=lambda x: x[0], reverse=True)

        max_chars = self._max_history_tokens * 3
        kept_messages: list[dict[str, str]] = []
        current_chars = 0

        # 先保留最后 2 条 (最新一轮)
        if len(messages) >= 2:
            for msg in messages[-2:]:
                kept_messages.append(msg)
                current_chars += len(msg.get("content", ""))

        # 按评分添加其余消息
        for _score, msg in scored_messages:
            if msg in kept_messages:
                continue
            msg_chars = len(msg.get("content", ""))
            if current_chars + msg_chars > max_chars:
                continue
            kept_messages.append(msg)
            current_chars += msg_chars

        # 按原始顺序排序
        kept_indices = [id(m) for m in kept_messages]
        self._sessions[session_id] = [
            m for m in messages if id(m) in kept_indices
        ]

        logger.debug(
            f"Smart truncation: {len(messages)} → {len(self._sessions[session_id])} messages "
            f"(tokens: {estimated_tokens} → {current_chars // 3})"
        )

    def clear_session(self, session_id: str) -> None:
        """清除会话历史.

        Args:
            session_id: 会话 ID.
        """
        self._sessions.pop(session_id, None)

    def clear_all(self) -> None:
        """清除所有会话历史."""
        self._sessions.clear()
        logger.debug("MultiTurnConversationBridge: all sessions cleared")

    @property
    def session_count(self) -> int:
        """当前活跃会话数."""
        return len(self._sessions)
