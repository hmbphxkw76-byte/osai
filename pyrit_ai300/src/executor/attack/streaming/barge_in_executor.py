"""
Barge-In Attack Executor (Streaming Stub)
==========================================

打断式攻击执行器（stub，deprecated）— 对齐 pyrit.executor.attack.streaming.BargeInAttack

PyRIT 1.0.0 中 BargeInAttack 需要 audio_chunks (AsyncIterator[bytes])，
纯文本场景不适用，标记为 deprecated 并回退到 prompt_sending。
"""

import logging

logger = logging.getLogger(__name__)


class BargeInExecutor:
    """
    打断式攻击执行器（stub）

    BargeInAttack 需要实时音频流输入，在纯文本 AI 红队场景中不适用。
    此类仅作为架构占位符，实际执行回退到 prompt_sending。

    如需使用 BargeInAttack，需要：
    1. 提供实现 AsyncIterator[bytes] 的音频源
    2. 配置支持流式音频的目标 Target
    3. 在 attack_builder 中移除 deprecated 标记
    """

    def __init__(self):
        self._fallback_technique = "prompt_sending"

    async def execute(self, *args, **kwargs):
        """回退到 prompt_sending 执行"""
        logger.warning(
            "BargeInAttack 需要 audio_chunks (AsyncIterator[bytes])，"
            "纯文本场景不适用，回退到 prompt_sending"
        )
        from src.executor.attack.core.native_executor import get_direct_executor
        executor = get_direct_executor()
        return await executor.execute_single_attack(*args, **kwargs)
