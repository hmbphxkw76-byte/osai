# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""Tool Calling Target 工厂 — 使用 PyRIT 原生 ``OpenAIResponseTarget`` 注册蜜罐工具集。

本模块是 **原生组件增强** (R-022: PyRIT 原生优先), 不是自造 Target 子类。

核心功能:
  - 使用 PyRIT 原生 ``OpenAIResponseTarget`` 作为支持工具调用的 Target
  - 通过 ``custom_functions`` 参数注册蜜罐工具集 (8 个工具)
  - 通过 ``extra_body_parameters={"tools": [...]}`` 注册工具定义
  - 返回 ``ToolCallLog`` 实例供攻击后验证

原生 OpenAIResponseTarget 提供:
  - 完整的工具调用循环 (function_call → function_call_output → text)
  - 多轮对话上下文管理
  - 原生 Memory 持久化
  - JSON Mode / 结构化输出支持

设计原则 (R-022):
  - **不自造 Target 子类**: 直接使用 ``OpenAIResponseTarget``
  - **不自造工具调用循环**: 使用原生 ``custom_functions`` + Responses API
  - **数据层增强**: ``ToolCallLog`` 为独立数据层, 不修改原生生命周期
  - **keyword-only 参数**: 对齐 PyRIT 1.0+ 命名规范
  - **完整类型注解**: 全量 type hints

学术依据:
  - Greshake et al. (arXiv:2302.12173): 间接注入导致工具劫持
  - Zhan et al. (arXiv:2307.00929): InjecAgent — Agent 工具滥用评估框架
  - OWASP Agentic Top 10 (2025): ASI02/ASI05

> **日期**: 2026-8-14
"""

from __future__ import annotations

import logging
import os
from typing import Any

from pipeline.targets.honeypot_tools import (
    ToolCallLog,
    build_honeypot_custom_functions,
    build_honeypot_tool_definitions,
)

logger = logging.getLogger(__name__)


def create_tool_calling_target(
    *,
    endpoint: str | None = None,
    api_key: str | None = None,
    model_name: str | None = None,
    fail_on_missing_function: bool = False,
) -> tuple[Any, ToolCallLog] | None:
    """创建支持工具调用的 ``OpenAIResponseTarget`` 并注册蜜罐工具集。

    使用 PyRIT 原生 ``OpenAIResponseTarget``, 注入蜜罐工具集作为 ``custom_functions``。

    环境变量 (PyRIT 原生约定):
      - ``OPENAI_RESPONSES_ENDPOINT``: API 端点
      - ``OPENAI_RESPONSES_KEY``: API 密钥
      - ``OPENAI_RESPONSES_MODEL``: 模型名称

    也可使用与 ``OpenAIChatTarget`` 相同的端点配置 (通过参数传入)。

    Args:
        endpoint: API 端点 URL (可选, 默认从 ``OPENAI_RESPONSES_ENDPOINT`` 或
            ``OPENAI_CHAT_ENDPOINT`` 读取)。
        api_key: API 密钥 (可选, 默认从 ``OPENAI_RESPONSES_KEY`` 或
            ``OPENAI_CHAT_KEY`` 读取)。
        model_name: 模型名称 (可选, 默认从 ``OPENAI_RESPONSES_MODEL`` 或
            ``OPENAI_CHAT_MODEL`` 读取)。
        fail_on_missing_function: 当模型调用未知函数时是否报错 (默认 False,
            允许模型自我恢复)。

    Returns:
        ``(target, tool_call_log)`` 元组, 或 ``None`` (创建失败)。
        - target: ``OpenAIResponseTarget`` 实例
        - tool_call_log: ``ToolCallLog`` 实例, 记录所有工具调用
    """
    try:
        from pyrit.prompt_target import OpenAIResponseTarget
    except ImportError as e:
        logger.error(f"OpenAIResponseTarget import failed: {e}")
        return None

    # 解析端点配置 — 优先使用参数, 回退到环境变量
    # 支持 OPENAI_RESPONSES_* 和 OPENAI_CHAT_* 双环境变量
    resolved_endpoint = (
        endpoint
        or os.environ.get("OPENAI_RESPONSES_ENDPOINT")
        or os.environ.get("OPENAI_CHAT_ENDPOINT")
    )
    resolved_key = (
        api_key
        or os.environ.get("OPENAI_RESPONSES_KEY")
        or os.environ.get("OPENAI_CHAT_KEY")
    )
    resolved_model = (
        model_name
        or os.environ.get("OPENAI_RESPONSES_MODEL")
        or os.environ.get("OPENAI_CHAT_MODEL")
    )

    if not resolved_endpoint or not resolved_key:
        logger.warning(
            "Tool Calling Target 创建失败: 缺少 endpoint 或 api_key。"
            "请设置 OPENAI_RESPONSES_ENDPOINT/OPENAI_RESPONSES_KEY 或 "
            "OPENAI_CHAT_ENDPOINT/OPENAI_CHAT_KEY 环境变量。"
        )
        return None

    # 创建工具调用日志
    tool_call_log = ToolCallLog()

    # 构建蜜罐 custom_functions
    custom_functions = build_honeypot_custom_functions(tool_call_log)

    # 构建工具定义 (用于 extra_body_parameters)
    tool_definitions = build_honeypot_tool_definitions()

    # 构建 kwargs — 传递给 OpenAIResponseTarget
    target_kwargs: dict[str, Any] = {
        "endpoint": resolved_endpoint,
        "api_key": resolved_key,
        "model_name": resolved_model,
        "custom_functions": custom_functions,
        "fail_on_missing_function": fail_on_missing_function,
        "extra_body_parameters": {"tools": tool_definitions},
    }

    # 创建原生 OpenAIResponseTarget
    try:
        target = OpenAIResponseTarget(**target_kwargs)
        logger.info(
            f"Tool Calling Target created: model={resolved_model}, "
            f"endpoint={resolved_endpoint}, tools={len(tool_definitions)}"
        )
        return target, tool_call_log
    except Exception as e:
        logger.error(f"OpenAIResponseTarget creation failed: {e}")
        return None


def register_tool_calling_target(
    *,
    endpoint: str | None = None,
    api_key: str | None = None,
    model_name: str | None = None,
    name: str = "tool_calling_target",
) -> tuple[Any, ToolCallLog] | None:
    """创建并注册 Tool Calling Target 到 PyRIT TargetRegistry。

    在 ``create_tool_calling_target`` 基础上, 将创建的 Target 注册到
    PyRIT 原生 ``TargetRegistry``, 使其可通过 ``_get_attack_targets()`` 获取。

    Args:
        endpoint: API 端点 URL (可选)。
        api_key: API 密钥 (可选)。
        model_name: 模型名称 (可选)。
        name: 注册名称 (默认 "tool_calling_target")。

    Returns:
        ``(target, tool_call_log)`` 元组, 或 ``None`` (创建失败)。
    """
    result = create_tool_calling_target(
        endpoint=endpoint,
        api_key=api_key,
        model_name=model_name,
    )
    if result is None:
        return None

    target, tool_call_log = result

    # 注册到原生 TargetRegistry
    try:
        from pyrit.registry import TargetRegistry

        TargetRegistry.get_registry_singleton().instances.register(
            instance=target,
            name=name,
            tags={"agent_attack": {}, "tool_calling": {}},
        )
        logger.info(f"Tool Calling Target registered as '{name}' in TargetRegistry")
    except Exception as e:
        logger.warning(f"Failed to register Tool Calling Target in registry: {e}")

    return target, tool_call_log
