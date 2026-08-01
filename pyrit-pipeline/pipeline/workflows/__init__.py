# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""XPIA (Cross-Domain Prompt Injection Attack) 工作流集成。.

使用 PyRIT 原生 ``pyrit.executor.workflow.xpia`` API。

XPIA 攻击链:
  1. 攻击者将恶意指令嵌入到外部数据源 (文档/网页/邮件)
  2. 目标 LLM 系统消费该数据源时被间接注入
  3. LLM 执行攻击者指令而非用户指令

原生 API:
  - ``XpiaWorkflow``: XPIA 工作流策略
  - ``XPIAContext``: 工作流上下文
  - ``XPIAResult``: 工作流结果

学术依据:
  - Greshake et al. (arXiv:2302.12173) "Not what you've signed up for:
    Compromising Real-World LLM-Integrated Applications with Indirect
    Prompt Injection"
  - PyRIT 官方 XPIA 实现: ``pyrit/executor/workflow/xpia.py``

> **日期**: 2026-8-1
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from pyrit.prompt_target import PromptTarget
    from pyrit.score import Scorer


async def run_xpia_workflow_async(
    *,
    attack_setup_target: PromptTarget,
    processing_target: PromptTarget,
    attack_content: str,
    scorer: Scorer | None = None,
    processing_prompt: str | None = None,
    memory_labels: dict[str, str] | None = None,
) -> Any:
    """执行 XPIA 工作流 (原生 API)。.

    Args:
        attack_setup_target: 攻击设置目标 (如文档存储/网页)。
        processing_target: 处理目标 (消费攻击内容的 LLM 系统)。
        attack_content: 攻击内容 (嵌入的恶意指令)。
        scorer: 评分器 (评估注入是否成功)。
        processing_prompt: 发送给处理目标的提示 (可选)。
        memory_labels: 附加标签。

    Returns:
        XPIAResult: 工作流结果。
    """
    from pyrit.executor.workflow.xpia import XPIAContext, XpiaWorkflow
    from pyrit.models import Message

    # 构建攻击内容消息
    attack_message = Message(role="user", text=attack_content)

    # 构建 XPIA 上下文
    context_kwargs: dict[str, Any] = {
        "attack_content": attack_message,
    }

    if processing_prompt:
        context_kwargs["processing_prompt"] = Message(role="user", text=processing_prompt)

    if memory_labels:
        context_kwargs["memory_labels"] = memory_labels

    context = XPIAContext(**context_kwargs)

    # 构建工作流
    workflow = XpiaWorkflow(
        attack_setup_target=attack_setup_target,
        processing_target=processing_target,
        scorer=scorer,
    )

    # 执行
    result = await workflow.execute_async(context=context)

    logger.info(f"XPIA workflow complete: status={result.status}, has_score={result.score is not None}")

    return result
