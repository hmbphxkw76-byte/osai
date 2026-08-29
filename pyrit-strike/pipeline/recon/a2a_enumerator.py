"""A2A (Agent-to-Agent) 协议枚举模块 — 发现并攻击 A2A 端点。

学术依据:
    - Google A2A Protocol Specification (2024) — Agent Card 发现机制
    - OWASP ASI07 — Cross-Agent Injection via Trust
    - Greshake et al. (arXiv:2302.12173) — 间接提示注入
    - Eidam et al. (arXiv:2407.16924) — A2A 安全分析

A2A 协议核心概念:
    1. Agent Card: 每个 A2A agent 在 /.well-known/agent.json 暴露
       其能力声明 (name, description, skills, endpoints)
    2. JSON-RPC: agent 间通信使用 JSON-RPC 2.0
    3. Task Lifecycle: submitted → working → input-required → completed/failed
    4. Skills: agent 声明的可执行能力, 每个技能有 name/description/tags

攻击策略:
    1. 枚举: 发现 /.well-known/agent.json → 提取 skills 和 endpoints
    2. 信任利用: 通过目标 agent 向其他信任 agent 发送恶意指令
    3. 能力滥用: 利用 agent 的 skills 执行未授权操作
    4. 中间人: 拦截 agent 间通信, 篡改 JSON-RPC 消息

PyRIT 原生优先 (Rule 2):
    使用 PyRIT 原生 HTTPTarget 发送 A2A JSON-RPC 请求。
    使用 PromptSendingAttack 执行 A2A 定向攻击种子。
    不修改 PyRIT 源码, 仅在胶水层增强。
"""

from __future__ import annotations

import json
import logging
from typing import Any

from pipeline.context import PipelineContext

logger = logging.getLogger(__name__)

# A2A 协议路径
_AGENT_CARD_PATH = "/.well-known/agent.json"

# A2A JSON-RPC 方法
_A2A_METHODS = {
    "tasks/send": "发送任务到目标 agent",
    "tasks/get": "获取任务状态",
    "tasks/cancel": "取消任务",
    "tasks/sendSubscribe": "发送任务并订阅流式响应",
    "tasks/pushNotification/set": "设置推送通知回调",
}


async def enumerate_a2a_endpoint(
    ctx: PipelineContext,
) -> dict[str, Any]:
    """枚举目标的 A2A 协议端点, 提取 Agent Card 信息。

    学术依据:
        - Google A2A Protocol Specification (2024)
        - OWASP ASI07 — Cross-Agent Injection

    策略:
        1. 请求 /.well-known/agent.json
        2. 解析 Agent Card (name, description, skills, endpoints)
        3. 提取可用的 A2A skills 和通信端点
        4. 将发现的信息存储到 target_fingerprint 中

    Args:
        ctx: 流水线上下文。

    Returns:
        A2A 枚举结果字典, 包含 agent_card 和 skills。
    """
    import asyncio

    results: dict[str, Any] = {
        "has_a2a": False,
        "agent_card": None,
        "skills": [],
        "endpoints": [],
    }

    if not ctx.parsed_request:
        logger.debug("A2A enumerate: no parsed_request")
        return results

    try:
        from pyrit.models import Message, MessagePiece

        from pipeline.recon.burp_parser import build_http_target

        # 构建探针请求 — 复用原始请求但修改路径
        probe_parsed = _build_a2a_probe_request(ctx.parsed_request)
        if probe_parsed is None:
            return results

        target = build_http_target(probe_parsed)
        if target is None:
            return results

        async def _send_a2a_probe():
            if hasattr(target, "send_prompt_async"):
                # PyRIT 1.0.1: send_prompt_async(*, message: Message)
                msg = Message(message_pieces=[
                    MessagePiece(role="user", original_value="Enumerate A2A endpoint")
                ])
                responses = await target.send_prompt_async(message=msg)
                if responses and len(responses) > 0:
                    resp_msg = responses[-1]
                    pieces = resp_msg.message_pieces
                    if pieces:
                        return pieces[0].converted_value
                return None
            return None

        response_text = await asyncio.wait_for(_send_a2a_probe(), timeout=15)

        if response_text:
            agent_card = _parse_agent_card(response_text)
            if agent_card:
                results["has_a2a"] = True
                results["agent_card"] = agent_card
                results["skills"] = agent_card.get("skills", [])
                results["endpoints"] = agent_card.get("endpoints", [])

                logger.info(
                    "A2A endpoint discovered: agent=%s, skills=%d",
                    agent_card.get("name", "unknown"),
                    len(results["skills"]),
                )

                # 更新 target_fingerprint
                if ctx.parsed_request and hasattr(ctx.parsed_request, "target_fingerprint"):
                    fp = ctx.parsed_request.target_fingerprint
                    existing_caps = fp.get("capabilities", "")
                    if "a2a" not in existing_caps:
                        fp["capabilities"] = (
                            f"{existing_caps},a2a" if existing_caps else "a2a"
                        )
                    fp["a2a_agent_card"] = agent_card

    except asyncio.TimeoutError:
        logger.debug("A2A enumerate: timeout")
    except Exception as e:
        logger.debug("A2A enumerate failed: %s", e)

    return results


def _build_a2a_probe_request(parsed_request: Any) -> Any:
    """构建 A2A Agent Card 探针请求。

    复用原始请求的 headers 和认证信息,
    但将路径改为 /.well-known/agent.json,
    方法改为 GET。

    Args:
        parsed_request: 原始 ParsedBurpRequest。

    Returns:
        修改后的 ParsedBurpRequest, 或 None 如果失败。
    """
    try:
        import copy


        probe = copy.deepcopy(parsed_request)

        # 修改路径为 A2A Agent Card 端点
        # ParsedBurpRequest 的 path 属性
        if hasattr(probe, "path"):
            probe.path = _AGENT_CARD_PATH
        elif hasattr(probe, "url"):
            # 如果有 url 属性, 替换路径部分
            from urllib.parse import urlparse, urlunparse

            parsed = urlparse(str(probe.url))
            probe.url = urlunparse((
                parsed.scheme, parsed.netloc,
                _AGENT_CARD_PATH, parsed.params,
                "", "",
            ))

        # 修改方法为 GET
        if hasattr(probe, "method"):
            probe.method = "GET"

        # 清空 body
        if hasattr(probe, "body"):
            probe.body = ""

        return probe
    except Exception as e:
        logger.debug("A2A probe request build failed: %s", e)
        return None


def _parse_agent_card(response_text: str) -> dict[str, Any] | None:
    """解析 A2A Agent Card JSON 响应。

    Agent Card 格式 (Google A2A spec):
        {
            "name": "agent-name",
            "description": "Agent description",
            "version": "1.0.0",
            "skills": [
                {
                    "id": "skill-1",
                    "name": "Skill Name",
                    "description": "Skill description",
                    "tags": ["category"]
                }
            ],
            "endpoints": [
                {"url": "https://agent.example.com/a2a", "type": "jsonrpc"}
            ]
        }

    Args:
        response_text: HTTP 响应文本。

    Returns:
        解析后的 Agent Card 字典, 或 None 如果不是有效的 Agent Card。
    """
    try:
        data = json.loads(response_text)
    except (json.JSONDecodeError, TypeError):
        # 响应不是 JSON, 尝试从文本中提取 JSON
        import re

        json_match = re.search(r'\{[\s\S]*\}', response_text)
        if json_match:
            try:
                data = json.loads(json_match.group(0))
            except (json.JSONDecodeError, TypeError):
                return None
        else:
            return None

    # 验证是否为 Agent Card (至少有 name 或 skills 字段)
    if not isinstance(data, dict):
        return None

    if "name" not in data and "skills" not in data and "endpoints" not in data:
        return None

    return data


async def send_a2a_task(
    ctx: PipelineContext,
    agent_endpoint: str,
    task_payload: dict[str, Any],
) -> dict[str, Any] | None:
    """通过 A2A JSON-RPC 协议向目标 agent 发送任务。

    使用 PyRIT 原生 HTTPTarget 发送 JSON-RPC 请求。
    A2A JSON-RPC 2.0 格式:
        {
            "jsonrpc": "2.0",
            "method": "tasks/send",
            "params": {
                "id": "task-xxx",
                "message": {
                    "role": "user",
                    "parts": [{"type": "text", "text": "..."}]
                }
            },
            "id": "req-xxx"
        }

    Args:
        ctx: 流水线上下文。
        agent_endpoint: A2A agent 的 JSON-RPC 端点 URL。
        task_payload: 任务参数。

    Returns:
        JSON-RPC 响应字典, 或 None 如果失败。
    """
    import asyncio

    try:
        from pyrit.models import Message, MessagePiece

        from pipeline.recon.burp_parser import build_http_target

        # 构建 A2A JSON-RPC 请求
        jsonrpc_request = {
            "jsonrpc": "2.0",
            "method": "tasks/send",
            "params": task_payload,
            "id": f"strike-a2a-{asyncio.get_event_loop().time():.0f}",
        }

        # 复用原始请求的认证信息
        if ctx.parsed_request:
            probe_parsed = _build_a2a_jsonrpc_request(
                ctx.parsed_request, agent_endpoint, jsonrpc_request
            )
            if probe_parsed is None:
                return None

            target = build_http_target(probe_parsed)
            if target is None:
                return None

            async def _send():
                if hasattr(target, "send_prompt_async"):
                    # PyRIT 1.0.1: send_prompt_async(*, message: Message)
                    msg = Message(message_pieces=[
                        MessagePiece(role="user", original_value=json.dumps(jsonrpc_request))
                    ])
                    responses = await target.send_prompt_async(message=msg)
                    if responses and len(responses) > 0:
                        resp_msg = responses[-1]
                        pieces = resp_msg.message_pieces
                        if pieces:
                            return pieces[0].converted_value
                    return None
                return None

            response_text = await asyncio.wait_for(_send(), timeout=30)

            if response_text:
                try:
                    return json.loads(response_text)
                except (json.JSONDecodeError, TypeError):
                    return {"raw_response": response_text}

    except asyncio.TimeoutError:
        logger.warning("A2A task send: timeout")
    except Exception as e:
        logger.warning("A2A task send failed: %s", e)

    return None


def _build_a2a_jsonrpc_request(
    parsed_request: Any,
    endpoint: str,
    jsonrpc_payload: dict[str, Any],
) -> Any:
    """构建 A2A JSON-RPC HTTP 请求。

    Args:
        parsed_request: 原始 ParsedBurpRequest (复用认证)。
        endpoint: A2A agent 端点路径。
        jsonrpc_payload: JSON-RPC 请求体。

    Returns:
        修改后的 ParsedBurpRequest。
    """
    try:
        import copy

        probe = copy.deepcopy(parsed_request)

        # 修改路径为 A2A 端点
        if hasattr(probe, "path"):
            probe.path = endpoint

        # 修改方法为 POST
        if hasattr(probe, "method"):
            probe.method = "POST"

        # 设置 body 为 JSON-RPC
        if hasattr(probe, "body"):
            probe.body = json.dumps(jsonrpc_payload, ensure_ascii=False)

        return probe
    except Exception as e:
        logger.debug("A2A JSON-RPC request build failed: %s", e)
        return None

# 从 a2a_attacks re-export 以保持向后兼容
from pipeline.recon.a2a_attacks import (  # noqa: F401, E402
    generate_a2a_attack_seeds,
    run_a2a_enumeration,
)
