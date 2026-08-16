# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""Stage 0.5: 统一目标类型判别 + 认证桥接.

v43 统一入口: --target-url 自动触发完整链路 (判别→认证→桥接→主流水线 17 种攻击).

当用户提供 ``--target-url`` 时, 本阶段自动执行完整链路:
  1. 调用 TargetClassifier 判别目标类型 (LLM Web 应用 / LLM API 平台)
  2. 根据判别结果 + 用户参数自动路由到三种模式之一:
     a. Burp API 模式 (--burp-request): 从原始 HTTP 请求构建 HTTPTarget
     b. API 直连模式 (llm_api_platform): APITargetConfig + HTTPTarget + RateLimitedTarget
     c. Browser 模式 (llm_web_app): AuthProbe + MFADetector + AuthStrategy + PlaywrightTarget
  3. 执行认证 (Browser: Playwright / API: Bearer/OAuth2)
  4. 能力探测 (可选, 简化侦察)
  5. 创建对应 Target 并注册到 TargetRegistry
  6. 导出认证状态 (供下次运行复用)

v43 优化: 统一三路入口, 消除 --web-bridge 开关.
  - --target-url 本身触发完整链路
  - --burp-request 提升 Burp Suite 原始请求到主流水线 (不再局限于 web_redteam 4 种技术)
  - --target-profile 统一 Web App YAML Profile 入口
  - --api-key / --api-response-path 统一 API 模式参数

v43.1 优化 (S-6/S-7/S-8):
  - S-6: 能力探测统一到本阶段 — Burp/API/Burp 模式全部自动探测 Agent/RAG/MCP 能力
  - S-7: 认证状态复用扩展到 Burp/API 模式 — 三种模式全部支持 AuthState 文件复用
  - S-8: Browser 模式交互选择器自动发现 — 无 YAML Profile 时自动探测输入/发送/响应选择器

> **设计原则** (R-010): PyRIT 原生优先
  - PlaywrightTarget / HTTPTarget 是 PyRIT 原生 prompt_target
  - AuthDetector/AuthStrategy/MFADetector 来自 web_redteam, 是对原生模式的增强
  - 不修改任何 PyRIT 原生代码

学术依据:
  - PyRIT (arXiv:2407.01232): PlaywrightTarget / HTTPTarget 双模式支持
  - OWASP Top 10 for LLMs 2025: Web 注入和 API 注入的攻击面对应
  - MITRE ATT&CK: Reconnaissance → Initial Access → Execution
  - Greshake et al. (arXiv:2302.12173): 间接注入需发现 Agent 工具调用端点

> **日期**: 2026-8-3
> **更新记录**:
  2026-8-15 — v43.1: S-6 能力探测统一 + S-7 认证状态三模式复用 + S-8 选择器自动发现
  2026-8-15 — v43: 统一三路入口, 新增 --burp-request/--target-profile/--api-key/--api-response-path
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import re
import time
import uuid
from pathlib import Path
from typing import Any

from pipeline.context import PipelineContext
from pipeline.integrations.target_classifier import TargetClassification, TargetClassifier
from pipeline.utils.decision_trace import DecisionTrace
from pipeline.utils.event_bus import EventBus

logger = logging.getLogger(__name__)

# D-8: 预检结果缓存 — 同一目标 60 秒内跳过重复 TCP/HTTP 探测
# 学术依据: NIST SP 800-92 — 重复探测属噪音层
_REACHABILITY_CACHE: dict[str, dict[str, Any]] = {}
_REACHABILITY_CACHE_TTL: float = 60.0  # 秒


def _should_use_hybrid_agent_attack(burp_request_file: str) -> bool:
    """P2: 检测是否应使用混合 Agent 攻击模式.

    条件: Burp 请求体检测到 Agent 特征 (tools/functions/tool_calls).
    """
    from pipeline.targets.capability_adapter import detect_agent_capability_from_burp

    try:
        burp_path = Path(burp_request_file)
        if not burp_path.exists():
            return False
        raw_request = burp_path.read_text(encoding="utf-8")
        return detect_agent_capability_from_burp(raw_request)
    except Exception:
        return False


async def _bridge_hybrid_agent_attack(
    ctx: PipelineContext,
    target_url: str,
    burp_request_file: str,
    classification: TargetClassification,
) -> bool:
    """P2: 混合 Agent 攻击 — Burp HTTPTarget + Tool Calling 劫持.

    当 Burp 请求检测到 Agent 特征 (tools/functions) 且 .env 有模型配置时,
    同时创建:
      1. Burp HTTPTarget (含 multi_turn 能力) 作为 objective_target
      2. .env OpenAIChatTarget 作为 adversarial_chat + scoring_target
      3. Tool Calling Target (蜜罐工具集) 作为 tool_hijack_target (攻击向量)

    攻击流程:
      - Crescendo/TAP: adversarial_chat 生成攻击消息 → objective_target (Burp)
      - 工具劫持: 攻击消息诱导 Agent 调用蜜罐工具 → 记录敏感操作

    学术依据:
      - Zhan et al. (arXiv:2307.00929) InjecAgent: 间接注入劫持 Agent 工具
      - Greshake et al. (arXiv:2302.12173): 间接注入是 Agent 应用主要攻击面
      - Russinovich et al. (arXiv:2402.12109): Crescendo 多轮渐进攻击

    Args:
        ctx: PipelineContext.
        target_url: 目标 URL.
        burp_request_file: Burp 请求文件路径.
        classification: 目标判别结果.

    Returns:
        True 如果桥接成功.
    """
    # 首先执行 Agent Proxy Bridge 逻辑 (创建 Burp HTTPTarget + 三角色分离)
    success = await _bridge_agent_proxy(ctx, target_url, burp_request_file, classification)
    if not success:
        return False

    # 从 Burp 请求提取端点信息, 用于创建辅助 tool_calling_target
    endpoint, api_key, model_name = _extract_endpoint_from_burp(burp_request_file)

    # 如果 Burp 请求没有 API Key, 尝试从 .env 获取
    env_endpoint = os.environ.get("OPENAI_CHAT_ENDPOINT", "")
    env_key = os.environ.get("OPENAI_CHAT_KEY", "") or os.environ.get("API_KEY", "")
    env_model = os.environ.get("OPENAI_CHAT_MODEL", "")

    # 优先使用 Burp 提取的 endpoint/key, 回退到 .env
    tc_endpoint = endpoint or env_endpoint
    tc_api_key = api_key or env_key
    tc_model = model_name or env_model

    print("\n  [P2] Hybrid Agent Attack 配置:")
    print(f"    objective_target: Burp HTTPTarget → {target_url}")
    print(f"    tool_calling_target: {tc_model or '(默认)'} @ {tc_endpoint or '(未配置)'}")

    if not tc_endpoint or not tc_api_key:
        print("  [P2 警告] 未找到可用于 tool_calling 的端点/API Key, 工具劫持功能降级")
        # 仍然成功 — Agent Proxy Bridge 已建立
        ctx.metadata["hybrid_agent_attack"] = True
        ctx.metadata["tool_hijack_available"] = False
        return True

    # 创建 tool_calling_target (蜜罐工具集)
    try:
        from pipeline.targets.tool_calling_target import create_tool_calling_target

        result = create_tool_calling_target(
            endpoint=tc_endpoint,
            api_key=tc_api_key,
            model_name=tc_model,
        )

        if result is not None:
            tool_target, tool_call_log = result

            from pyrit.registry import TargetRegistry

            registry = TargetRegistry.get_registry_singleton()
            registry.instances.register(
                instance=tool_target,
                name="hybrid_tool_calling_target",
                tags={
                    "target_type": "OpenAIResponseTarget",
                    "agent_attack": {},
                    "tool_calling": {},
                    "tool_hijack": {},
                },
            )

            ctx.metadata["tool_calling_target"] = tool_target
            ctx.metadata["tool_call_log"] = tool_call_log
            ctx.metadata["hybrid_agent_attack"] = True
            ctx.metadata["tool_hijack_available"] = True

            print("  [P2] 蜜罐工具集已创建 (8 个工具): read_file, list_directory,")
            print("       send_email, http_request, execute_command,")
            print("       get_environment, write_file, delete_file")
            print("  ✓ Hybrid Agent Attack 模式已启用")

            logger.info(
                f"P2: Hybrid Agent Attack bridged — "
                f"objective=Burp HTTPTarget({target_url}), "
                f"tool_calling={tc_model}@{tc_endpoint}"
            )
        else:
            print("  [P2 警告] tool_calling_target 创建失败, 工具劫持功能降级")
            ctx.metadata["hybrid_agent_attack"] = True
            ctx.metadata["tool_hijack_available"] = False

    except Exception as e:
        print(f"  [P2 警告] 工具劫持初始化失败: {e}")
        ctx.metadata["hybrid_agent_attack"] = True
        ctx.metadata["tool_hijack_available"] = False
        logger.warning(f"P2: tool_calling target creation failed: {e}")

    return True


def _can_use_agent_proxy(ctx: PipelineContext) -> bool:
    """V-69: 检测是否可以使用 Agent Proxy Bridge 模式.

    自动检测条件 (全部满足):
      1. 有 Burp 请求文件 (--burp-request 或自动发现)
      2. .env 有 OPENAI_CHAT_ENDPOINT (模板模型, 用于 adversarial_chat)
      3. 未指定 --tool-calling (tool-calling 优先级更高)

    学术依据:
      - Greshake et al. (arXiv:2302.12173): Agent 应用是主要攻击面
      - Russinovich et al. (arXiv:2402.12109): Crescendo 需多轮 + 三角色分离

    Args:
        ctx: PipelineContext.

    Returns:
        True 如果可以使用 Agent Proxy Bridge 模式.
    """
    # 条件 1: 有 Burp 请求
    burp_request_arg = getattr(ctx.args, "burp_request", None)
    if not burp_request_arg:
        # 尝试自动发现
        target_url = getattr(ctx.args, "target_url", None)
        if target_url:
            discovered = _discover_burp_request_file(target_url)
            if not discovered:
                return False
        else:
            return False

    # 条件 2: .env 有模型配置 (OPENAI_CHAT_ENDPOINT)
    endpoint = os.environ.get("OPENAI_CHAT_ENDPOINT", "")
    if not endpoint:
        return False

    # 条件 3: 未指定 --tool-calling
    return not getattr(ctx.args, "tool_calling", False)


async def _bridge_agent_proxy(
    ctx: PipelineContext,
    target_url: str,
    burp_request_file: str,
    classification: TargetClassification,
) -> bool:
    """V-65: Agent Proxy Bridge — HTTPTarget + 三角色分离 + 多轮能力.

    v46 核心优化: 解决 Burp 模式下 HTTPTarget 不支持多轮对话
    导致 Crescendo/TAP/PAIR 被过滤的问题.

    架构:
      - objective_target (被攻击方) = HTTPTarget (Burp 原始请求, 攻击发到 Agent 应用)
      - adversarial_chat (攻击者) = OpenAIChatTarget (从 .env 配置, 生成攻击消息)
      - scoring_target (评分器) = OpenAIChatTarget (从 .env 配置, 独立评分)

    通过 CapabilityAdapter 为 HTTPTarget 声明多轮能力,
    使 Crescendo/TAP/PAIR 等多轮攻击不再被
    ``CHAT_TARGET_REQUIREMENTS.validate()`` 过滤.

    流程:
      1. 读取 Burp 请求, 增强 {PROMPT} + 认证 + 动态会话 ID
      2. SSE/JSON 检测 + 预检探针
      3. 构建 HTTPTarget (含 custom_configuration 声明多轮能力)
      4. 包装 RateLimitedTarget
      5. 三角色分离注册 (不覆盖 default, 保留 .env 模型)
      6. 能力探测
      7. V-70: 创建 MultiTurnConversationBridge 供多轮攻击使用

    Args:
        ctx: PipelineContext.
        target_url: 目标 URL.
        burp_request_file: Burp 请求文件路径.
        classification: 目标判别结果.

    Returns:
        True 如果桥接成功.
    """
    from pyrit.prompt_target import HTTPTarget

    from pipeline.targets.capability_adapter import (
        apply_multi_turn_capability,
        build_multi_turn_configuration,
        detect_agent_capability_from_burp,
    )
    from pipeline.targets.multiturn_bridge import MultiTurnConversationBridge
    from pipeline.targets.rate_limited_target import RateLimitedTarget

    # 1. 读取原始 HTTP 请求
    burp_path = Path(burp_request_file)
    if not burp_path.exists():
        print(f"  [错误] Burp 请求文件不存在: {burp_request_file}")
        return False

    raw_request = burp_path.read_text(encoding="utf-8")
    print(f"  请求文件: {burp_request_file} ({len(raw_request)} bytes)")

    # V-68: 从 Burp 请求检测 Agent 能力
    is_agent = detect_agent_capability_from_burp(raw_request)
    if is_agent:
        print("  [V-68] 检测到 Agent 应用特征 (tools/functions 字段)")

    # 2. 认证 headers + {PROMPT} 注入 (复用 _bridge_burp_api 逻辑)
    auth_headers = ctx.metadata.get("auth_headers", {})

    if "{PROMPT}" not in raw_request:
        print("  [v44.5] 请求中未找到 {PROMPT} 占位符, 自动注入...")
        from pipeline.integrations.recon_target_bridge import enhance_burp_request

        raw_request = enhance_burp_request(raw_request, auth_headers=auth_headers or None)
        raw_request = _fix_content_length(raw_request)
        print("  [v44.5] {PROMPT} 占位符已自动注入")
    elif auth_headers:
        from pipeline.integrations.recon_target_bridge import enhance_burp_request

        raw_request = enhance_burp_request(raw_request, auth_headers=auth_headers)
        raw_request = _fix_content_length(raw_request)
        print(f"  [S-7] 认证 headers 注入: {list(auth_headers.keys())}")

    # 3. 响应路径 + 动态会话 ID
    response_path = getattr(ctx.args, "api_response_path", "choices[0].message.content")
    raw_request = _inject_dynamic_session_fields(raw_request)
    print("  [v44.3] 动态会话 ID 已注入")

    # 4. SSE/HTTPS 检测 + 预检探针
    is_sse = _detect_sse_from_request(raw_request)
    use_tls = _detect_tls_from_request(raw_request)

    print("  [v44.4] 执行预检探针...")
    probe_result = await _burp_pre_flight_probe(raw_request=raw_request, target_url=target_url, use_tls=use_tls)
    if probe_result.get("response_path"):
        user_response_path = getattr(ctx.args, "api_response_path", None)
        if not user_response_path or user_response_path == "choices[0].message.content":
            response_path = probe_result["response_path"]
        if probe_result["is_sse"]:
            is_sse = True
            print(f"  [v44.4] 预检: 目标返回 SSE, 响应路径={response_path}")
        else:
            is_sse = False
            print(f"  [v44.4] 预检: 目标返回 JSON, 响应路径={response_path}")
    ctx.metadata["burp_pre_flight_probe"] = probe_result

    # 5. 构建 HTTPTarget (含 V-66 custom_configuration 多轮能力声明)
    non_stream_request = _build_non_stream_variant(raw_request) if is_sse else None
    multi_turn_config = build_multi_turn_configuration()

    if non_stream_request:
        non_stream_path = response_path.replace("delta", "message").replace("Delta", "Message")
        json_callback = _build_burp_callback(is_sse=False, response_path=non_stream_path, target_url=target_url)
        http_target_kwargs: dict[str, Any] = {
            "http_request": non_stream_request,
            "prompt_regex_string": "{PROMPT}",
            "callback_function": json_callback,
            "use_tls": use_tls,
        }
        if multi_turn_config is not None:
            http_target_kwargs["custom_configuration"] = multi_turn_config
        http_target = HTTPTarget(**http_target_kwargs)
        print("  [v44.3] Stream:false 变体已构造, 优先使用 JSON 回调")
    else:
        callback = _build_burp_callback(is_sse=is_sse, response_path=response_path, target_url=target_url)
        http_target_kwargs = {
            "http_request": raw_request,
            "prompt_regex_string": "{PROMPT}",
            "callback_function": callback,
            "use_tls": use_tls,
        }
        if is_sse:
            http_target_kwargs["timeout"] = 60.0
        if multi_turn_config is not None:
            http_target_kwargs["custom_configuration"] = multi_turn_config
        http_target = HTTPTarget(**http_target_kwargs)

    # V-66 备选路径: 如果构造函数不支持 custom_configuration, 通过属性设置
    if multi_turn_config is not None:
        apply_multi_turn_capability(http_target)
    print("  [V-66] HTTPTarget 多轮能力已声明 (supports_multi_turn=True)")

    # 6. 包装 RateLimitedTarget
    rate_limit = getattr(ctx.args, "rate_limit", 3)
    max_retries = getattr(ctx.args, "rate_limit_retries", 3)

    rate_limited_target = RateLimitedTarget(
        target=http_target,
        endpoint=target_url,
        max_concurrency=rate_limit,
        max_retries=max_retries,
        requests_per_minute=rate_limit * 30 if rate_limit > 0 else None,
    )

    # 7. 三角色分离注册 (V-65 核心)
    from pyrit.registry import TargetRegistry

    registry = TargetRegistry.get_registry_singleton()

    # objective_target = Burp HTTPTarget (仅标签 default_objective_target, 不覆盖 default)
    registry.instances.register(
        instance=rate_limited_target,
        name="agent_proxy_objective_target",
        tags={"target_type": "HTTPTarget", "default_objective_target": {}},
    )

    # 获取 Stage 1 从 .env 注册的模型作为 adversarial + scoring
    _env_endpoint = os.environ.get("OPENAI_CHAT_ENDPOINT", "")
    _env_model = os.environ.get("OPENAI_CHAT_MODEL", "")
    _scorer_endpoint = os.environ.get("OBJECTIVE_SCORER_CHAT_ENDPOINT", "")
    _scorer_model = os.environ.get("OBJECTIVE_SCORER_CHAT_MODEL", "")

    print("  [V-65] 三角色分离:")
    print(f"    objective_target: Burp HTTPTarget → {target_url}")
    print(f"    adversarial_chat: {_env_model or '(默认)'} @ {_env_endpoint or '(未配置)'}")
    scorer_ep = _scorer_endpoint or _env_endpoint or "(未配置)"
    scorer_md = _scorer_model or _env_model or "(默认)"
    print(f"    scoring_target: {scorer_md} @ {scorer_ep}")

    # 验证 adversarial/scoring 是否可用
    if not _env_endpoint:
        print("  [警告] .env 未配置 OPENAI_CHAT_ENDPOINT, 多轮攻击的 adversarial_chat 将共享 Burp Target")
    if not _scorer_endpoint and not _env_endpoint:
        print("  [警告] .env 未配置评分器, 评分将使用规则评分器降级")

    # 8. V-70: 创建 MultiTurnConversationBridge
    conversation_bridge = MultiTurnConversationBridge(max_history_turns=10, max_history_tokens=4000)
    ctx.metadata["multi_turn_conversation_bridge"] = conversation_bridge
    print("  [V-67] MultiTurnConversationBridge 已创建 (max_history=10)")

    # 9. 存储到 Context
    ctx.metadata["burp_request_file"] = burp_request_file
    ctx.metadata["api_target_url"] = target_url
    ctx.metadata["burp_is_sse"] = is_sse
    ctx.metadata["burp_use_tls"] = use_tls
    ctx.metadata["agent_proxy_mode"] = True
    ctx.metadata["is_agent_target"] = is_agent
    ctx.target_type = "http_api"
    ctx.http_target_configured = True

    # O-1 P1: Burp-ChatTarget 增强 — 为 Agent 目标额外创建 OpenAIChatTarget + 蜜罐工具
    # 当检测到 Agent 特征 (tools/functions) 或 .env 有模型配置时,
    # 创建 OpenAIChatTarget 并注入蜜罐工具定义, 供 MCP/XPIA/Multi-Agent 使用
    if is_agent:
        try:
            _chat_target, _tc_log = _create_burp_chat_target_with_tools(
                burp_request_file=burp_request_file,
            )
            if _chat_target is not None:
                ctx.metadata["burp_chat_target"] = _chat_target
                ctx.metadata["burp_tool_call_log"] = _tc_log
                print("  [O-1] Burp-ChatTarget 已创建 (OpenAIChatTarget + 蜜罐工具集)")
        except Exception as e:
            logger.debug(f"O-1: Burp-ChatTarget creation skipped: {e}")

    print("  ✓ Agent Proxy Bridge 已创建并注册")
    print(f"    最大并发: {rate_limit}")
    print(f"    最大重试: {max_retries}")
    print("    多轮能力: supports_multi_turn=True, supports_editable_history=True")
    if is_sse:
        print("    SSE 超时: 60.0s")

    # 10. S-6: 执行能力探测
    await _probe_and_record_capabilities(ctx, target_url, classification)

    logger.info(
        f"Agent Proxy Bridge bridged: {target_url} → HTTPTarget "
        f"(multi_turn=True, agent={is_agent})"
    )
    return True


def _create_burp_chat_target_with_tools(
    *,
    burp_request_file: str,
) -> tuple[Any, Any] | tuple[None, None]:
    """O-1 P1: 从 Burp 请求创建 OpenAIChatTarget + 蜜罐工具定义.

    使用 PyRIT 原生 ``OpenAIChatTarget`` + ``extra_body_parameters`` 注入蜜罐工具集.
    适用于大多数基于 OpenAI Chat Completions API 的 Agent 应用.

    组合原生组件:
      - ``OpenAIChatTarget`` (原生, Chat Completions API + 多轮对话)
      - ``build_honeypot_tool_definitions`` (数据层, 工具定义)
      - ``ToolCallLog`` (数据层, 调用日志)

    Args:
        burp_request_file: Burp Suite 原始 HTTP 请求文件路径.

    Returns:
        ``(OpenAIChatTarget, ToolCallLog)`` 元组, 或 ``(None, None)``.
    """
    try:
        from pyrit.prompt_target import OpenAIChatTarget

        from pipeline.targets.honeypot_tools import (
            ToolCallLog,
            build_honeypot_tool_definitions,
        )
    except ImportError as e:
        logger.debug(f"O-1: import failed: {e}")
        return None, None

    # 从 Burp 请求提取端点和认证
    endpoint, api_key, model_name = _extract_endpoint_from_burp(burp_request_file)
    if not endpoint or not api_key:
        # 回退到 .env
        endpoint = os.environ.get("OPENAI_CHAT_ENDPOINT", "")
        api_key = os.environ.get("OPENAI_CHAT_KEY", "")
        model_name = os.environ.get("OPENAI_CHAT_MODEL", "")
        if not endpoint or not api_key:
            return None, None

    tool_call_log = ToolCallLog()
    tool_definitions = build_honeypot_tool_definitions()

    try:
        chat_target = OpenAIChatTarget(
            endpoint=endpoint,
            api_key=api_key,
            model_name=model_name or None,
            extra_body_parameters={"tools": tool_definitions},
        )
        logger.info(
            f"O-1: Burp-ChatTarget created: model={model_name}, "
            f"endpoint={endpoint}, tools={len(tool_definitions)}"
        )
        return chat_target, tool_call_log
    except Exception as e:
        logger.debug(f"O-1: OpenAIChatTarget creation failed: {e}")
        return None, None


async def _bridge_burp_api(
    ctx: PipelineContext,
    target_url: str,
    burp_request_file: str,
    classification: TargetClassification,
) -> bool:
    """Burp API 模式: 从原始 HTTP 请求构建 HTTPTarget + RateLimitedTarget.

    v43 新增: 将 Burp Suite 原始请求提升到主流水线,
    享受 17 种攻击技术 + ASR 驱动.

    v43.1 S-7: 认证状态复用 — 从 AuthState 文件注入 headers.

    v44.2 SSE: 自动检测 SSE 流式响应, 选择正则回调或 JSON 回调.
    v44.2 HTTPS: 自动从 Origin/Referer/Host 推断 TLS, 传递 use_tls.

    流程:
      1. 读取 Burp Suite 原始 HTTP 请求文件
      2. 验证 {PROMPT} 占位符存在
      3. S-7: 注入已有认证 headers (从 AuthState 文件)
      4. SSE 检测: 从 Accept header 判断是否为流式响应
      5. 构建回调函数 (SSE→正则回调, JSON→原生JSON回调)
      6. 创建 HTTPTarget (PyRIT 原生, 含 use_tls)
      7. 包装 RateLimitedTarget (并发信号量 + 退避重试)
      8. 注册到 TargetRegistry (替换 default)
      9. S-6: 执行能力探测 (可选)

    Args:
        ctx: PipelineContext.
        target_url: 目标 URL (用于元信息).
        burp_request_file: Burp Suite 原始 HTTP 请求文件路径.
        classification: 目标判别结果.

    Returns:
        True 如果桥接成功.
    """
    from pyrit.prompt_target import HTTPTarget

    from pipeline.targets.rate_limited_target import RateLimitedTarget

    # 1. 读取原始 HTTP 请求
    burp_path = Path(burp_request_file)
    if not burp_path.exists():
        print(f"  [错误] Burp 请求文件不存在: {burp_request_file}")
        return False

    raw_request = burp_path.read_text(encoding="utf-8")
    print(f"  请求文件: {burp_request_file} ({len(raw_request)} bytes)")

    # v43.1 S-7: 获取已有认证 headers (从 AuthState 文件)
    # v44.5: 提前到步骤2之前, 供 enhance_burp_request 使用
    auth_headers = ctx.metadata.get("auth_headers", {})

    # 2. 验证 {PROMPT} 占位符 — v44.5: 缺失时自动注入
    if "{PROMPT}" not in raw_request:
        print("  [v44.5] 请求中未找到 {PROMPT} 占位符, 自动注入...")
        from pipeline.integrations.recon_target_bridge import enhance_burp_request

        raw_request = enhance_burp_request(
            raw_request,
            auth_headers=auth_headers or None,
        )
        # v44.5 P3: 增强后修正 Content-Length
        raw_request = _fix_content_length(raw_request)
        if "{PROMPT}" in raw_request:
            print("  [v44.5] {PROMPT} 占位符已自动注入")
            ctx.metadata["burp_prompt_auto_injected"] = True
        else:
            print("  [警告] 自动注入 {PROMPT} 失败, prompt 注入可能无效")
            logger.warning("Burp request auto-inject {PROMPT} failed")
    elif auth_headers:
        # 已有 {PROMPT} — 仅注入认证 headers (如果尚未存在)
        from pipeline.integrations.recon_target_bridge import enhance_burp_request

        raw_request = enhance_burp_request(
            raw_request,
            auth_headers=auth_headers,
        )
        raw_request = _fix_content_length(raw_request)
        print(f"  [S-7] 认证 headers 注入: {list(auth_headers.keys())}")

    # v43: 获取响应路径 (--api-response-path)
    response_path = getattr(ctx.args, "api_response_path", "choices[0].message.content")

    # v44.3 P1: 动态会话 ID 更换 — 避免多轮攻击上下文污染
    raw_request = _inject_dynamic_session_fields(raw_request)
    print("  [v44.3] 动态会话 ID 已注入")

    # v44.2: SSE 检测 — 从 Accept header 判断是否为流式响应
    is_sse = _detect_sse_from_request(raw_request)
    if is_sse:
        print("  [SSE] 检测到流式响应 (Accept: text/event-stream), 使用正则回调")
    else:
        print(f"  响应路径: {response_path}")

    # v44.2: HTTPS 检测 — 从 Origin/Referer/Host 推断 TLS
    use_tls = _detect_tls_from_request(raw_request)
    if use_tls:
        print("  [TLS] 检测到 HTTPS 目标, 启用 TLS")

    # v44.4 P2: 预检探针 — 发送测试请求自动推断响应格式
    # v45.3: 始终执行预检探针 — 即使用户指定了 --api-response-path,
    # 也需要检测目标是否返回 SSE (SSE 需要特殊回调, JSON 回调无法解析 SSE)
    print("  [v44.4] 执行预检探针...")
    probe_result = await _burp_pre_flight_probe(
        raw_request=raw_request,
        target_url=target_url,
        use_tls=use_tls,
    )
    if probe_result.get("response_path"):
        # 仅当用户未指定 --api-response-path 时覆盖 (用户指定优先)
        user_response_path = getattr(ctx.args, "api_response_path", None)
        if not user_response_path or user_response_path == "choices[0].message.content":
            response_path = probe_result["response_path"]
        # 预检结果覆盖 SSE 检测
        if probe_result["is_sse"]:
            is_sse = True
            print(f"  [v44.4] 预检: 目标返回 SSE, 响应路径={response_path}")
        else:
            is_sse = False
            print(f"  [v44.4] 预检: 目标返回 JSON, 响应路径={response_path}")
    ctx.metadata["burp_pre_flight_probe"] = probe_result

    # v44.3 P3: Stream:false 变体构造 — 优先尝试 JSON 模式
    # P0 修复 (v45.5): 为 HTTPTarget 声明多轮能力, 使 Crescendo/TAP/PAIR 不被过滤
    from pipeline.targets.capability_adapter import (
        apply_multi_turn_capability,
        build_multi_turn_configuration,
    )
    multi_turn_config = build_multi_turn_configuration()

    non_stream_request = _build_non_stream_variant(raw_request) if is_sse else None
    if non_stream_request:
        # 构造 Stream:false 变体, 使用 JSON 回调 (更可靠)
        # 对应的 SSE 响应路径: delta→message (stream→non-stream)
        non_stream_path = response_path.replace("delta", "message").replace("Delta", "Message")
        json_callback = _build_burp_callback(
            is_sse=False,
            response_path=non_stream_path,
            target_url=target_url,
        )
        http_target_kwargs: dict[str, Any] = {
            "http_request": non_stream_request,
            "prompt_regex_string": "{PROMPT}",
            "callback_function": json_callback,
            "use_tls": use_tls,
        }
        if multi_turn_config is not None:
            http_target_kwargs["custom_configuration"] = multi_turn_config
        http_target = HTTPTarget(**http_target_kwargs)
        # P0 安全网: 即使构造函数未传 custom_configuration, 也通过属性覆写追加
        apply_multi_turn_capability(http_target)
        print("  [v45.5] HTTPTarget 多轮能力已声明 (supports_multi_turn=True)")
        print("  [v44.3] Stream:false 变体已构造, 优先使用 JSON 回调")
        ctx.metadata["burp_non_stream_variant"] = True
        ctx.metadata["burp_original_sse_request"] = raw_request

        # v44.4 P1: 构造 SSE 回退 Target (Stream:false 变体失败时使用)
        sse_callback = _build_burp_callback(
            is_sse=True,
            response_path=response_path,
            target_url=target_url,
        )
        sse_target_kwargs: dict[str, Any] = {
            "http_request": raw_request,
            "prompt_regex_string": "{PROMPT}",
            "callback_function": sse_callback,
            "use_tls": use_tls,
        }
        if multi_turn_config is not None:
            sse_target_kwargs["custom_configuration"] = multi_turn_config
        sse_fallback_target = HTTPTarget(**sse_target_kwargs)
        apply_multi_turn_capability(sse_fallback_target)
        _rl = getattr(ctx.args, "rate_limit", 3)
        _mr = getattr(ctx.args, "rate_limit_retries", 3)
        sse_fallback_rate_limited = RateLimitedTarget(
            target=sse_fallback_target,
            endpoint=target_url,
            max_concurrency=_rl,
            max_retries=_mr,
            requests_per_minute=_rl * 30 if _rl > 0 else None,
        )
        from pyrit.registry import TargetRegistry as _TR1
        _registry_fallback = _TR1.get_registry_singleton()
        _registry_fallback.instances.register(
            instance=sse_fallback_rate_limited,
            name="burp_sse_fallback_target",
            tags={"target_type": "HTTPTarget", "fallback": {}},
        )
        print("  [v44.4] SSE 回退 Target 已注册 (burp_sse_fallback_target)")
        ctx.metadata["burp_sse_fallback_registered"] = True
    else:
        # 3. 构建回调函数 (v44.2: SSE→正则回调, JSON→原生JSON回调)
        callback = _build_burp_callback(
            is_sse=is_sse,
            response_path=response_path,
            target_url=target_url,
        )

        # 4. 创建 HTTPTarget (v44.2: 传递 use_tls)
        # SSE 响应需要超时控制: httpx 默认等待整个 body, SSE 流不会自然结束,
        # 需设置 timeout 让 httpx 在收到足够数据后中断并返回已读内容.
        # 非 SSE 响应正常关闭连接, 不受影响.
        # P0 修复 (v45.5): 传入 custom_configuration 声明多轮能力
        http_target_kwargs: dict[str, Any] = {
            "http_request": raw_request,
            "prompt_regex_string": "{PROMPT}",
            "callback_function": callback,
            "use_tls": use_tls,
        }
        if is_sse:
            # SSE: 60s 超时 — SSE 响应需要足够时间完成.
            # 目标模型生成攻击响应可能需要 20-30s (长 prompt + 安全过滤推理),
            # 15s 超时会导致 ReadTimeout 丢失已读数据并触发重试.
            # 60s 足够覆盖绝大多数 SSE 响应, 同时防止无限挂起.
            http_target_kwargs["timeout"] = 60.0
        if multi_turn_config is not None:
            http_target_kwargs["custom_configuration"] = multi_turn_config
        http_target = HTTPTarget(**http_target_kwargs)
        # P0 安全网: 通过属性覆写确保多轮能力生效
        apply_multi_turn_capability(http_target)
        print("  [v45.5] HTTPTarget 多轮能力已声明 (supports_multi_turn=True)")

    # 5. 包装 RateLimitedTarget
    rate_limit = getattr(ctx.args, "rate_limit", 3)
    max_retries = getattr(ctx.args, "rate_limit_retries", 3)

    rate_limited_target = RateLimitedTarget(
        target=http_target,
        endpoint=target_url,
        max_concurrency=rate_limit,
        max_retries=max_retries,
        requests_per_minute=rate_limit * 30 if rate_limit > 0 else None,
    )

    # 6. 注册到 TargetRegistry
    from pyrit.registry import TargetRegistry

    registry = TargetRegistry.get_registry_singleton()
    registry.instances.register(
        instance=rate_limited_target,
        name="burp_api_target",
        tags={"target_type": "HTTPTarget", "default": {}, "default_objective_target": {}},
    )
    registry.instances.register(
        instance=rate_limited_target,
        name="default",
        tags={"target_type": "HTTPTarget", "default": {}, "default_objective_target": {}},
    )

    print("  ✓ HTTPTarget (Burp) + RateLimitedTarget 已创建并注册")
    print(f"    最大并发: {rate_limit}")
    print(f"    最大重试: {max_retries}")
    if is_sse:
        print(f"    SSE 超时: {http_target_kwargs.get('timeout', 'N/A')}s")

    # 7. 存储到 Context
    ctx.metadata["burp_request_file"] = burp_request_file
    ctx.metadata["api_target_url"] = target_url
    ctx.metadata["burp_is_sse"] = is_sse
    ctx.metadata["burp_use_tls"] = use_tls
    ctx.target_type = "http_api"
    ctx.http_target_configured = True

    # v43.1 S-6: 执行能力探测 (非侵入, 失败不影响主流水线)
    await _probe_and_record_capabilities(ctx, target_url, classification)

    logger.info(f"Burp API target bridged: {target_url} → HTTPTarget (SSE={is_sse}, TLS={use_tls})")
    return True


async def _check_target_reachability(
    target_url: str,
    *,
    timeout: float = 10.0,
) -> dict[str, Any]:
    """v50: 目标可达性快速探测 — TCP 连通性 + HTTP 探针.

    在 Stage 0.5 路由前执行, 不可达则触发降级链.
    区别于 _burp_pre_flight_probe (推断响应格式), 本函数仅判断可达性.

    探测策略 (两级):
      1. TCP 连通性 — asyncio.open_connection(host, port) 最快 (<1s)
      2. HTTP 探针 — httpx.AsyncClient.get(url) 带超时 (10s)
    两者都失败 → reachable=False

    学术依据:
      - Circuit Breaker Pattern (Nygard, "Release It!") — 不可达应快速失败
      - NIST SP 800-92 — 信号/噪音分离: 不可达重试属噪音层
      - MITRE ATT&CK T1592 — 主动扫描驱动路由决策

    Args:
        target_url: 目标 URL.
        timeout: HTTP 探针超时秒数 (默认 10s).

    Returns:
        {"reachable": bool, "reason": str, "latency_ms": float, "method": str}
    """
    # D-8: 预检结果缓存 — 同一目标 60 秒内跳过重复探测
    # 学术依据: NIST SP 800-92 — 重复探测属噪音层, 缓存消除冗余
    #           Circuit Breaker (Nygard) — 缓存避免短时间内重复 circuit breaker 触发
    cache_key = target_url.rstrip("/")
    now = time.monotonic()
    cached = _REACHABILITY_CACHE.get(cache_key)
    if cached and (now - cached["cached_at"]) < _REACHABILITY_CACHE_TTL:
        logger.debug(f"v50 D-8: Reachability cache hit for {cache_key}")
        return dict(cached["result"])

    from urllib.parse import urlparse

    parsed = urlparse(target_url)
    host = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    if not host:
        return {"reachable": False, "reason": "无法解析主机名", "latency_ms": 0.0, "method": "url_parse"}

    # Level 1: TCP 连通性
    try:
        import time as _time

        tcp_start = _time.monotonic()
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=min(timeout, 5.0),
        )
        tcp_latency = (_time.monotonic() - tcp_start) * 1000
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()
        tcp_result = {
            "reachable": True,
            "reason": f"TCP {host}:{port} 连通",
            "latency_ms": round(tcp_latency, 1),
            "method": "tcp",
        }
        _REACHABILITY_CACHE[cache_key] = {"result": dict(tcp_result), "cached_at": now}
        return tcp_result
    except asyncio.TimeoutError:
        pass  # 继续到 HTTP 探针
    except (OSError, ConnectionRefusedError) as e:
        # TCP 连接被拒绝, 继续到 HTTP 探针 (可能有防火墙代理)
        logger.debug(f"v50: TCP probe failed for {host}:{port}: {e}")
    except Exception as e:
        logger.debug(f"v50: TCP probe error for {host}:{port}: {e}")

    # Level 2: HTTP 探针
    try:
        import time as _time

        import httpx

        http_start = _time.monotonic()
        async with httpx.AsyncClient(verify=False, timeout=timeout) as client:
            resp = await client.get(target_url, follow_redirects=True)
            http_latency = (_time.monotonic() - http_start) * 1000
            # 任何 HTTP 响应 (即使 4xx/5xx) 都说明目标可达
            http_result = {
                "reachable": True,
                "reason": f"HTTP {resp.status_code}",
                "latency_ms": round(http_latency, 1),
                "method": "http",
            }
            _REACHABILITY_CACHE[cache_key] = {"result": dict(http_result), "cached_at": now}
            return http_result
    except Exception as e:
        error_type = type(e).__name__
        reason = f"{error_type}: {e}" if str(e) else error_type
        fail_result = {
            "reachable": False,
            "reason": reason,
            "latency_ms": 0.0,
            "method": "failed",
        }
        _REACHABILITY_CACHE[cache_key] = {"result": dict(fail_result), "cached_at": now}
        return fail_result


async def _try_fallback_chain(
    ctx: PipelineContext,
    target_url: str,
    classification: TargetClassification,
    burp_request_file: str | None,
    first_failure_reason: str,
) -> bool:
    """v50: 三级降级链 — Burp失败→Playwright→.env OpenAIChatTarget→终止.

    当 Burp 模式目标不可达时, 依次尝试:
      Level 1: Playwright 浏览器模式 (TargetClassifier 独立判别 + _bridge_web_app)
      Level 2: .env OpenAIChatTarget 模式 (复用 Stage 1 注册的 default target)
      Level 3: 优雅终止 (返回 False, stage_scenario 跳过执行)

    设计原则:
      - 原生优先 (R-010): 降级目标全部 PyRIT 原生 Target
      - 决策可追溯: 每次降级通过 DecisionTrace 记录
      - 幂等安全: 降级不覆盖已有注册的 Target

    学术依据:
      - Graceful Degradation (Distributed Systems Design) — 多级降级保最大可用性
      - Circuit Breaker (Nygard) — 快速失败 + 降级替代
      - OWASP Top 10 LLM 2025 — Web 注入和 API 注入互补攻击面

    Args:
        ctx: PipelineContext.
        target_url: 目标 URL.
        classification: 原始目标判别结果.
        burp_request_file: Burp 请求文件路径 (可能为 None).
        first_failure_reason: 第一级 (Burp) 失败原因.

    Returns:
        True 如果某级降级成功, False 如果全部失败 (应终止).
    """
    from pipeline.utils.decision_trace import DecisionTrace
    from pipeline.utils.event_bus import EventBus

    trace = DecisionTrace.get_instance()
    bus = EventBus.get_instance()
    failure_reasons: list[str] = [f"Level 0 (Burp): {first_failure_reason}"]

    # ── Level 1: Playwright 浏览器模式 ──
    print("\n  --- 降级 Level 1: Playwright 浏览器模式 ---")
    try:
        # 独立判别 target_url (不使用 Burp 文件的 force_type 覆盖)
        classifier = TargetClassifier()
        pw_classification = await classifier.classify(target_url, force_type="auto")

        if pw_classification.http_status != 0:
            # 目标 HTTP 可达, 尝试 Playwright
            print(f"  [v50] HTTP 探测可达 (status={pw_classification.http_status}), 尝试 Playwright...")
            success = await _bridge_web_app(ctx, target_url, pw_classification)
            if success:
                trace.record(
                    stage="stage_0.5",
                    layer="fallback_chain",
                    decision="fallback_to_playwright",
                    reason=f"Burp unreachable ({first_failure_reason}) → Playwright success",
                    target_url=target_url,
                    fallback_level=1,
                )
                bus.publish_simple("stage_0.5", "fallback_to_playwright", reason=first_failure_reason)
                ctx.metadata["fallback_level"] = 1
                ctx.metadata["fallback_target_mode"] = "playwright"
                print("  [v50] ✅ 降级成功: Playwright 浏览器模式")
                return True
            else:
                failure_reasons.append("Level 1 (Playwright): _bridge_web_app 返回 False")
        else:
            failure_reasons.append("Level 1 (Playwright): HTTP 不可达 (status=0)")
    except Exception as e:
        failure_reasons.append(f"Level 1 (Playwright): {type(e).__name__}: {e}")
        logger.debug(f"v50: Playwright fallback failed: {e}", exc_info=True)

    print(f"  [v50] ❌ Playwright 降级失败: {failure_reasons[-1]}")

    # D-9: Level 1 指数退避重试 — 失败后等待 2 秒重试 1 次
    # 学术依据: Exponential Backoff (AWS Architecture Best Practices) —
    #   瞬时故障 (如浏览器启动竞争/CDP端口占用) 重试可恢复
    #   Circuit Breaker (Nygard) — 重试仅 1 次, 避免无限重试
    #   NIST SP 800-92 — 重试属可恢复层, 区分永久故障
    if not getattr(ctx.args, "no_fallback", False):
        print("  [v50 D-9] Level 1 指数退避重试 (等待 2 秒)...")
        await asyncio.sleep(2.0)
        try:
            classifier_retry = TargetClassifier()
            pw_classification_retry = await classifier_retry.classify(target_url, force_type="auto")
            if pw_classification_retry.http_status != 0:
                print(f"  [v50 D-9] HTTP 探测可达 (status={pw_classification_retry.http_status}), 重试 Playwright...")
                success_retry = await _bridge_web_app(ctx, target_url, pw_classification_retry)
                if success_retry:
                    trace.record(
                        stage="stage_0.5",
                        layer="fallback_chain",
                        decision="fallback_to_playwright_retry",
                        reason=f"Level 1 retry success after backoff (initial: {failure_reasons[-1]})",
                        target_url=target_url,
                        fallback_level=1,
                    )
                    bus.publish_simple("stage_0.5", "fallback_to_playwright_retry", reason="backoff_retry")
                    ctx.metadata["fallback_level"] = 1
                    ctx.metadata["fallback_target_mode"] = "playwright"
                    ctx.metadata["fallback_retried"] = True
                    print("  [v50 D-9] ✅ 重试成功: Playwright 浏览器模式")
                    return True
                else:
                    failure_reasons.append("Level 1 retry (Playwright): _bridge_web_app 返回 False")
            else:
                failure_reasons.append("Level 1 retry (Playwright): HTTP 不可达 (status=0)")
        except Exception as e:
            failure_reasons.append(f"Level 1 retry (Playwright): {type(e).__name__}: {e}")
            logger.debug(f"v50 D-9: Playwright retry failed: {e}", exc_info=True)
        print(f"  [v50 D-9] ❌ 重试失败: {failure_reasons[-1]}")

    # ── Level 2: .env OpenAIChatTarget 模式 ──
    print("\n  --- 降级 Level 2: .env OpenAIChatTarget 模式 ---")
    env_endpoint = os.environ.get("OPENAI_CHAT_ENDPOINT", "")
    env_key = os.environ.get("OPENAI_CHAT_KEY", "") or os.environ.get("API_KEY", "")
    env_model = os.environ.get("OPENAI_CHAT_MODEL", "")

    if env_endpoint and env_key:
        # .env 有配置 — 不覆盖 Stage 1 已注册的 default OpenAIChatTarget
        # 仅设置 metadata 标记, 让主流水线使用 .env 配置的模型
        print(f"  [v50] .env 配置可用: {env_model} @ {env_endpoint}")
        print("  [v50] 使用 .env 配置的 OpenAIChatTarget 作为攻击目标")
        print("  [v50] 注意: 攻击将发送到 .env API 端点, 而非原始目标 URL")

        ctx.target_type = "env_openai_chat"
        ctx.http_target_configured = False
        ctx.metadata["fallback_level"] = 2
        ctx.metadata["fallback_target_mode"] = "env_openai_chat"
        ctx.metadata["env_fallback_endpoint"] = env_endpoint
        ctx.metadata["env_fallback_model"] = env_model

        trace.record(
            stage="stage_0.5",
            layer="fallback_chain",
            decision="fallback_to_env_openai_chat",
            reason=f"Burp+Playwright unreachable → .env OpenAIChatTarget ({env_model})",
            target_url=target_url,
            fallback_level=2,
            env_endpoint=env_endpoint,
        )
        bus.publish_simple("stage_0.5", "fallback_to_env", model=env_model)

        print("  [v50] ✅ 降级成功: .env OpenAIChatTarget 模式")
        return True
    else:
        reason = ".env 无 OPENAI_CHAT_ENDPOINT 或 OPENAI_CHAT_KEY"
        failure_reasons.append(f"Level 2 (.env): {reason}")
        print(f"  [v50] ❌ .env 降级失败: {reason}")

    # ── Level 3: 优雅终止 ──
    print("\n  --- 降级 Level 3: 优雅终止 ---")
    print("  [v50] ❌ 所有目标模式均失败")
    print("  [v50] 降级尝试结果:")
    for reason in failure_reasons:
        print(f"    {reason}")
    print("  [v50] 建议:")
    print("    1. 检查目标 URL 是否可达: curl -v " + target_url)
    print("    2. 检查 .env 配置: OPENAI_CHAT_ENDPOINT/KEY/MODEL")
    print("    3. 使用 --no-fallback 禁用降级 (严格模式)")

    ctx.metadata["all_targets_failed"] = True
    ctx.metadata["fallback_failure_reasons"] = failure_reasons

    trace.record(
        stage="stage_0.5",
        layer="fallback_chain",
        decision="all_targets_failed",
        reason="; ".join(failure_reasons),
        target_url=target_url,
    )
    bus.publish_simple("stage_0.5", "all_targets_failed", reasons=failure_reasons)

    return False


async def run(ctx: PipelineContext) -> bool:
    """执行 Stage 0.5: 统一目标类型判别 + 认证桥接。.

    v50: 新增三级降级链 — Burp 不可达 → Playwright → .env OpenAIChatTarget → 终止.
    使用 --no-fallback 可禁用降级 (严格模式).

    Args:
        ctx: PipelineContext (需要 args.target_url)

    Returns:
        True 如果目标已成功桥接到主 pipeline, False 如果不需要 (走原生 API 流程)
    """
    target_url = getattr(ctx.args, "target_url", None)
    if not target_url:
        return False

    print("\n" + "=" * 70)
    print("[0.5] 统一目标类型判别 + 认证桥接 (v43)")
    print("=" * 70)
    print(f"  目标 URL: {target_url}")

    # v43: 检查 --burp-request (优先级最高, 覆盖判别结果)
    # v44.4 P3: 支持逗号分隔多文件
    burp_request_arg = getattr(ctx.args, "burp_request", None)
    burp_files = _parse_burp_request_files(burp_request_arg) if burp_request_arg else []
    if burp_files:
        burp_request_file = burp_files[0]  # 使用第一个文件
        if len(burp_files) > 1:
            print(f"  Burp Suite 请求文件: {burp_request_file} (共 {len(burp_files)} 个文件, 使用第1个)")
            ctx.metadata["burp_all_files"] = burp_files
        else:
            print(f"  Burp Suite 请求文件: {burp_request_file}")
        target_type_override = getattr(ctx.args, "target_type", "api_platform")
    else:
        # v44.5 P2: 自动发现 Burp 请求文件 — 从 data/burp/ 目录匹配
        discovered_file = _discover_burp_request_file(target_url)
        if discovered_file:
            print(f"  [v44.5] 自动发现 Burp 请求文件: {discovered_file}")
            burp_request_file = discovered_file
            target_type_override = getattr(ctx.args, "target_type", "api_platform")
        else:
            burp_request_file = None
            target_type_override = getattr(ctx.args, "target_type", "auto")

    try:
        # Step 1: 目标类型判别
        classifier = TargetClassifier()
        classification = await classifier.classify(
            target_url,
            force_type=target_type_override,
        )

        print(f"  判别结果: {classification.target_type}")
        print(f"  推荐模式: {classification.recommended_mode}")
        print(f"  依据: {classification.detection_reason}")

        # A2: 认证决策链日志
        trace = DecisionTrace.get_instance()
        trace.record(
            stage="stage_0.5",
            layer="target_detection",
            decision=f"classified_as_{classification.target_type}",
            reason=classification.detection_reason,
            target_url=target_url,
            recommended_mode=classification.recommended_mode,
            has_chat_ui=classification.has_chat_ui,
        )
        bus = EventBus.get_instance()
        bus.publish_simple(
            "stage_0.5", "target_classified",
            target_type=classification.target_type,
            mode=classification.recommended_mode,
        )

        # 存储判别结果到 metadata
        ctx.metadata["target_classification"] = classification
        ctx.metadata["target_type"] = classification.target_type
        ctx.metadata["recommended_mode"] = classification.recommended_mode

        # v56: 攻击者视角 — 构建攻击面拓扑 + 自动扩展攻击种子
        # 在路由决策前完成, 使后续 Stage 可使用拓扑信息优化攻击策略
        no_attack_surface = getattr(ctx.args, "no_attack_surface", False)
        if not no_attack_surface:
            print("\n  --- v56 攻击面拓扑构建 (攻击者视角) ---")
            _expand_attack_surface(ctx, classification, burp_request_file)

            # v56: 发现替代攻击路径 (降级链)
            no_alt_paths = getattr(ctx.args, "no_alternative_paths", False)
            if not no_alt_paths and classification.attack_surface is not None:
                alt_paths = _discover_alternative_attack_paths(
                    classification.attack_surface, classification
                )
                ctx.metadata["alternative_attack_paths"] = alt_paths
                if len(alt_paths) > 1:
                    print(f"  [v56] 替代攻击路径: {len(alt_paths)} 条 (降级链)")
                    top_path = alt_paths[0]
                    print(f"         最优路径: {top_path['path_id']} (ASR≈{top_path['estimated_asr']:.0%})")

        # v43.1 S-7: 三模式统一认证状态复用 — 在路由前尝试加载 AuthState
        # Browser 模式在 _bridge_web_app 中已有 try_reuse_auth_state,
        # 但 Burp/API 模式也需要认证 headers 注入
        if burp_request_file or classification.target_type == "llm_api_platform":
            try:
                from pipeline.integrations.auth_state_bridge import try_reuse_auth_state

                auth_reused = try_reuse_auth_state(ctx)
                if auth_reused:
                    print("  [S-7] 认证状态复用成功 (Burp/API 模式)")
            except Exception as e:
                logger.debug(f"S-7 auth state reuse failed: {e}")

        # v43.2 A-1: --tool-calling 优先级最高 — 打通 Agent 工具调用劫持
        # 当 --tool-calling 指定时, 创建 OpenAIResponseTarget 替代 HTTPTarget/PlaywrightTarget
        # 使 XPIA/ASI03/多Agent 攻击不再降级为纯文本注入
        tool_calling = getattr(ctx.args, "tool_calling", False)
        if tool_calling:
            print("\n  --- Tool Calling 模式 (OpenAIResponseTarget + 蜜罐工具集) ---")
            return await _bridge_tool_calling(ctx, target_url, classification, burp_request_file)

        # v46 V-69: Agent Proxy Bridge — 当有 Burp 请求 + .env 有模型配置时
        # 自动选择三角色分离模式 (Burp=objective, .env=adversarial+scorer)
        # 使 Crescendo/TAP/PAIR 等多轮攻击不再被过滤
        # 显式 --agent-proxy 或自动检测 (有 .env OPENAI_CHAT_ENDPOINT 且非 --tool-calling)
        # P0 修复 (v45.5): 增加路由决策日志, 确保每次运行可追溯
        agent_proxy = getattr(ctx.args, "agent_proxy", False)
        can_use_proxy = _can_use_agent_proxy(ctx) if not agent_proxy else True
        logger.info(
            f"Route decision: tool_calling={tool_calling}, "
            f"agent_proxy_flag={agent_proxy}, "
            f"can_use_agent_proxy={can_use_proxy}, "
            f"burp_request_file={burp_request_file is not None}"
        )
        if (agent_proxy or can_use_proxy) and burp_request_file:
            # v46.1 P2: 混合模式 — Burp + Tool Calling 劫持
            hybrid = getattr(ctx.args, "hybrid_agent_attack", False)
            if hybrid and _should_use_hybrid_agent_attack(burp_request_file):
                print("\n  --- Hybrid Agent Attack 模式 (Burp HTTPTarget + Tool Calling 劫持) ---")
                return await _bridge_hybrid_agent_attack(ctx, target_url, burp_request_file, classification)

            print("\n  --- Agent Proxy Bridge 模式 (HTTPTarget + 三角色分离 + 多轮能力) ---")
            return await _bridge_agent_proxy(ctx, target_url, burp_request_file, classification)

        # v50: 目标可达性预检 — 在路由前检测 Burp 目标是否可达
        # 不可达则触发三级降级链 (Burp→Playwright→.env→终止)
        # 学术依据: Circuit Breaker (Nygard) — 快速失败 + NIST SP 800-92 信号分离
        if burp_request_file:
            reachability = await _check_target_reachability(target_url)
            ctx.metadata["target_reachability"] = reachability

            if not reachability["reachable"]:
                print(f"  [v50] ❌ 目标不可达: {reachability['reason']}")
                logger.warning(f"v50: Target unreachable: {reachability}")

                no_fallback = getattr(ctx.args, "no_fallback", False)
                if no_fallback:
                    # --no-fallback 严格模式: 不降级, 直接终止
                    print("  [v50] --no-fallback 严格模式: 不降级, 终止流水线")
                    ctx.metadata["all_targets_failed"] = True
                    ctx.metadata["fallback_failure_reasons"] = [
                        f"Level 0 (Burp): {reachability['reason']}",
                        "严格模式 (--no-fallback): 未尝试降级",
                    ]
                    return False

                # 启动三级降级链
                print("  [v50] 启动三级降级链...")
                fallback_success = await _try_fallback_chain(
                    ctx,
                    target_url,
                    classification,
                    burp_request_file,
                    first_failure_reason=reachability["reason"],
                )
                # fallback_success=True → return True; False → return False
                # (all_targets_failed 标记已由 _try_fallback_chain 设置)
                return fallback_success
            else:
                reachable_reason = reachability["reason"]
                reachable_ms = reachability["latency_ms"]
                reachable_method = reachability["method"]
                print(f"  [v50] ✅ 目标可达: {reachable_reason} ({reachable_ms}ms, {reachable_method})")

        # D-6: 降级链健康度面板 — 在路由决策后展示降级状态
        from pipeline.utils.display import fallback_health_card

        fallback_health_card(ctx)

        # Step 2: 统一路由 (v43: 三路自动选择)
        if burp_request_file:
            # 路径 A: Burp Suite 原始请求 → HTTPTarget
            # P0 修复 (v45.5): _bridge_burp_api 现在也声明多轮能力 (安全网)
            print("\n  --- Burp API 模式 (HTTPTarget + 原始 HTTP 请求 + 多轮能力) ---")
            logger.info("Route selected: Burp API (with multi-turn capability)")
            return await _bridge_burp_api(ctx, target_url, burp_request_file, classification)
        elif classification.target_type == "llm_web_app":
            # 路径 C: Web 应用 → Browser 模式
            return await _bridge_web_app(ctx, target_url, classification)
        elif classification.target_type == "llm_api_platform":
            # 路径 B: API 平台 → API 直连模式
            return await _bridge_api_platform(ctx, target_url, classification)
        else:
            # unknown: 尝试 Web App 模式 (更通用)
            print("  [警告] 目标类型未知, 降级为 Web App 模式")
            return await _bridge_web_app(ctx, target_url, classification)

    except (ImportError, RuntimeError, OSError, ValueError) as e:
        print(f"  [错误] 目标桥接失败: {e}")
        logger.error(f"Target bridge failed: {e}", exc_info=True)
        return False


async def _bridge_web_app(
    ctx: PipelineContext,
    target_url: str,
    classification: TargetClassification,
) -> bool:
    """Web 应用模式: 浏览器认证 + PlaywrightTarget。."""
    print("\n  --- Web 应用模式 (PlaywrightTarget) ---")

    # G2: 尝试复用已有认证状态 — 减少重复认证
    # 学术依据: NIST SP 800-63B — 认证状态复用减少攻击面暴露
    from pipeline.integrations.auth_state_bridge import try_reuse_auth_state

    auth_reused = try_reuse_auth_state(ctx)

    # 1. 加载或动态生成 TargetProfile
    profile = _load_or_create_profile(ctx, target_url)
    print(f"  认证策略: {profile.auth.type}")

    # 2. 启动浏览器
    from web_redteam.auth.browser_session import BrowserSession

    session = BrowserSession()
    headless = getattr(ctx.args, "web_headless", False)
    cdp_port = getattr(ctx.args, "cdp_port", 9222)

    # G2: 如果认证状态可复用, 尝试从 storage_state 恢复页面
    if auth_reused:
        storage_state_path = ctx.metadata.get("storage_state_path", "")
        if storage_state_path and Path(storage_state_path).exists():
            print(f"  [G2] 复用认证状态: {storage_state_path}")
            try:
                page = await session.restore_storage_state(storage_state_path)
                await page.goto(profile.auth.target_url, wait_until="domcontentloaded")
                print("  [G2] 认证状态恢复成功, 跳过完整认证")
                # 跳过步骤 3, 直接创建 PlaywrightTarget
            except Exception as e:
                logger.warning(f"G2: storage_state restore failed: {e}, falling back to full auth")
                page = await session.launch_with_debug_port(
                    port=cdp_port,
                    headless=headless,
                )
                # 降级到完整认证
                auth_reused = False
        else:
            page = await session.launch_with_debug_port(
                port=cdp_port,
                headless=headless,
            )
            auth_reused = False
    else:
        page = await session.launch_with_debug_port(
            port=cdp_port,
            headless=headless,
        )

    # 3. 执行认证 (仅当未复用认证状态时)
    if not auth_reused:
        from web_redteam.auth.auth_strategy import AuthStrategyFactory

        strategy = AuthStrategyFactory.create(profile.auth.type)

        # 注入 MFA 超时参数
        mfa_timeout = getattr(ctx.args, "mfa_timeout", 300)
        if hasattr(strategy, "_human_auth"):
            strategy._human_auth.mfa_timeout = mfa_timeout  # type: ignore[attr-defined]

        page = await strategy.execute(page, profile)

          # G2: 认证成功后导出 AuthState (供后续运行复用)
        from datetime import datetime, timezone

        from pipeline.integrations.auth_state_bridge import AuthState, export_auth_state

        cookies = []
        with contextlib.suppress(Exception):
            cookies = await page.context.cookies()

        storage_state_path = ""
        with contextlib.suppress(Exception):
            import tempfile

            storage_state_path = str(Path(tempfile.gettempdir()) / "stage_target_classify_storage_state.json")
            await page.context.storage_state(path=storage_state_path)

        auth_state = AuthState(
            auth_type=profile.auth.type,
            target_url=target_url,
            login_url=getattr(profile.auth, "login_url", ""),
            cookies=cookies,
            storage_state_path=storage_state_path,
            source="stage_target_classify",
            authenticated_at=datetime.now(timezone.utc).isoformat(),
        )
        export_auth_state(auth_state)
        print("  [G2] 认证状态已导出, 下次运行可复用")

    # 4. 创建 PlaywrightTarget
    from pyrit.prompt_target import PlaywrightTarget

    from web_redteam.interaction.interaction_factory import InteractionFactory

    interaction_func = InteractionFactory.create(profile.interaction)

    playwright_target = PlaywrightTarget(
        interaction_func=interaction_func,
        page=page,
        max_requests_per_minute=getattr(ctx.args, "max_rpm", None),
    )

    # 5. 注册到 TargetRegistry (替换默认 OpenAIChatTarget)
    from pyrit.registry import TargetRegistry

    registry = TargetRegistry.get_registry_singleton()
    registry.instances.register(
        instance=playwright_target,
        name="web_target",
        tags={"target_type": "PlaywrightTarget", "default_objective_target": {}},
    )
    registry.instances.register(
        instance=playwright_target,
        name="default",
        tags={"target_type": "PlaywrightTarget", "default_objective_target": {}},
    )

    print("  ✓ PlaywrightTarget 已创建并注册")
    print(f"    输入选择器: {profile.interaction.input.selector}")
    print(f"    发送选择器: {profile.interaction.send.selector}")
    print(f"    响应选择器: {profile.interaction.response.selector}")

    # 6. 存储到 Context
    ctx.metadata["web_browser_session"] = session
    ctx.metadata["web_target_url"] = target_url
    ctx.metadata["web_target_profile"] = profile
    ctx.target_type = "playwright"

    # v43.1 S-6: 执行能力探测 (非侵入, 失败不影响主流水线)
    await _probe_and_record_capabilities(ctx, target_url, classification)

    # 注: recon-pipeline 侦察不再通过代码直接调用 (两流水线完全独立)。
    # 使用方式: 先运行 recon-pipeline 生成 JSON 报告, 再通过 --recon-json 加载。

    logger.info(f"Web app target bridged: {target_url} → PlaywrightTarget")
    return True


async def _bridge_api_platform(
    ctx: PipelineContext,
    target_url: str,
    classification: TargetClassification,
) -> bool:
    """API 平台模式: HTTPTarget + RateLimitedTarget.

    v43: 支持 --api-key 和 --api-response-path 统一参数.
    v44: 支持 --api-json-data 触发 HTTPXAPITarget (结构化 HTTP API).
    """
    # v44: 如果指定了 --api-json-data, 使用 HTTPXAPITarget (结构化 API)
    _api_json_data = getattr(ctx.args, "api_json_data", None)
    if _api_json_data:
        print("\n  --- API 平台模式 (HTTPXAPITarget — 结构化 API) ---")
        return await _bridge_api_platform_httpx(ctx, target_url, classification)

    print("\n  --- API 平台模式 (HTTPTarget) ---")

    from pyrit.prompt_target import HTTPTarget

    from pipeline.targets.rate_limited_target import RateLimitedTarget
    from web_redteam.targets.api_config import APITargetConfig

    # v43: 优先使用 --api-key, 否则从 .env 获取
    api_key = (
        getattr(ctx.args, "api_key", None)
        or os.environ.get("OPENAI_CHAT_KEY", "")
        or os.environ.get("API_KEY", "")
    )

    # v43: 从 --api-response-path 获取响应路径
    response_path = getattr(ctx.args, "api_response_path", "choices[0].message.content")

    # 1. 从 URL 自动构建 API 配置
    config = APITargetConfig.from_url(
        target_url,
        api_key=api_key or None,
        max_rpm=getattr(ctx.args, "rate_limit", None),
    )

    # v43: 覆盖响应路径
    if response_path and response_path != config.response_json_path:
        config.response_json_path = response_path
        print(f"  [v43] 响应路径覆盖: {response_path}")

    # G2: 注入已有认证 headers (从 --auth-state-file 复用的 headers)
    auth_headers = ctx.metadata.get("auth_headers", {})
    if auth_headers:
        for k, v in auth_headers.items():
            if k not in config.headers:
                config.headers[k] = v
        print(f"  [G2] 注入认证 headers: {list(auth_headers.keys())}")

    print(f"  API URL: {config.url}")
    print(f"  HTTP 方法: {config.method}")
    print(f"  响应路径: {config.response_json_path}")
    print(f"  最大并发: {config.max_concurrency}")
    print(f"  最大 RPM: {config.max_rpm or '不限'}")

    # v44.2: SSE 检测 — 从 config.response_format 或 URL 路径判断
    is_sse = (
        getattr(config, "response_format", "json") == "sse"
        or classification.is_streaming
    )
    if is_sse:
        print("  [SSE] 检测到流式响应, 使用正则回调")

    # v44.2: HTTPS 检测 — 从 URL scheme 判断
    use_tls = config.url.startswith("https://")

    # 2. 构建回调函数 (v44.2: SSE→正则回调, JSON→原生JSON回调)
    callback = _build_burp_callback(
        is_sse=is_sse,
        response_path=config.response_json_path,
        target_url=config.url,
    )

    # 3. 构建 HTTPTarget (PyRIT 1.0.1: 不接受 prompt_request_piece 参数)
    raw_request = _build_raw_http_request(config)
    http_target_kwargs: dict[str, Any] = {
        "http_request": raw_request,
        "prompt_regex_string": "{PROMPT}",
        "callback_function": callback,
        "use_tls": use_tls,
    }
    http_target = HTTPTarget(**http_target_kwargs)

    # 4. 使用 RateLimitedTarget 包装
    rate_limited_target = RateLimitedTarget(
        target=http_target,
        endpoint=config.url,
        max_concurrency=config.max_concurrency,
        max_retries=config.max_retries,
        requests_per_minute=config.max_rpm,
    )

    # 5. 注册到 TargetRegistry
    from pyrit.registry import TargetRegistry

    registry = TargetRegistry.get_registry_singleton()
    registry.instances.register(
        instance=rate_limited_target,
        name="api_target",
        tags={"target_type": "HTTPTarget", "default": {}, "default_objective_target": {}},
    )
    registry.instances.register(
        instance=rate_limited_target,
        name="default",
        tags={"target_type": "HTTPTarget", "default": {}, "default_objective_target": {}},
    )

    print("  ✓ HTTPTarget + RateLimitedTarget 已创建并注册")

    # 6. 存储到 Context
    ctx.metadata["api_target_config"] = config
    ctx.metadata["api_target_url"] = target_url
    ctx.target_type = "http_api"
    ctx.http_target_configured = True

    # v43.1 S-6: 执行能力探测 (非侵入, 失败不影响主流水线)
    await _probe_and_record_capabilities(ctx, target_url, classification)

    logger.info(f"API platform target bridged: {target_url} → HTTPTarget")
    return True


async def _bridge_api_platform_httpx(
    ctx: PipelineContext,
    target_url: str,
    classification: TargetClassification,
) -> bool:
    """HTTPXAPITarget 模式: 结构化 HTTP API 调用 (v44 新增).

    当用户指定 ``--api-json-data`` 时, 使用 PyRIT 原生 ``HTTPXAPITarget``
    替代 ``HTTPTarget``。HTTPXAPITarget 支持结构化 JSON/Form 请求构造,
    无需原始 HTTP 请求文本。

    原生 API:
      - ``pyrit.prompt_target.HTTPXAPITarget(http_url, method, headers, json_data, ...)``
      - ``get_http_target_json_response_callback_function(key)``

    CLI 参数:
      - ``--api-json-data``: JSON 请求体 (含 {PROMPT} 占位符)
      - ``--api-method``: HTTP 方法 (默认 POST)
      - ``--api-headers``: 额外 headers (JSON 字符串)

    学术依据: PyRIT (arXiv:2407.01232) — HTTPXAPITarget 结构化 API 设计
    """
    import json as _json

    print("\n  --- HTTPXAPITarget 配置 ---")

    from pyrit.prompt_target import HTTPXAPITarget
    from pyrit.prompt_target.http_target import (
        get_http_target_json_response_callback_function,
    )

    from pipeline.targets.rate_limited_target import RateLimitedTarget

    # v43: API Key
    api_key = (
        getattr(ctx.args, "api_key", None)
        or os.environ.get("OPENAI_CHAT_KEY", "")
        or os.environ.get("API_KEY", "")
    )

    # v43: 响应路径
    response_path = getattr(ctx.args, "api_response_path", "choices[0].message.content")

    # v44: HTTP 方法
    method = getattr(ctx.args, "api_method", "POST")

    # v44: JSON 请求体
    json_data_str = getattr(ctx.args, "api_json_data", None)
    if not json_data_str:
        print("  [错误] --api-json-data 未指定")
        return False

    try:
        json_data = _json.loads(json_data_str)
    except _json.JSONDecodeError as e:
        print(f"  [错误] --api-json-data JSON 解析失败: {e}")
        return False

    # v44: 额外 headers
    headers: dict[str, str] = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    extra_headers_str = getattr(ctx.args, "api_headers", None)
    if extra_headers_str:
        try:
            extra_headers = _json.loads(extra_headers_str)
            headers.update(extra_headers)
        except _json.JSONDecodeError:
            print("  [警告] --api-headers JSON 解析失败, 忽略")

    # G2: 注入已有认证 headers
    auth_headers = ctx.metadata.get("auth_headers", {})
    if auth_headers:
        for k, v in auth_headers.items():
            if k not in headers:
                headers[k] = v
        print(f"  [G2] 注入认证 headers: {list(auth_headers.keys())}")

    print(f"  API URL: {target_url}")
    print(f"  HTTP 方法: {method}")
    print(f"  响应路径: {response_path}")
    print(f"  Headers: {list(headers.keys())}")

    # 构建回调函数
    callback = get_http_target_json_response_callback_function(key=response_path)

    # 创建 HTTPXAPITarget
    httpx_target = HTTPXAPITarget(
        http_url=target_url,
        method=method,
        headers=headers,
        json_data=json_data,
        callback_function=callback,
        max_requests_per_minute=getattr(ctx.args, "rate_limit", None) or 0,
    )

    # 使用 RateLimitedTarget 包装
    rate_limited_target = RateLimitedTarget(
        target=httpx_target,
        endpoint=target_url,
        max_concurrency=getattr(ctx.args, "rate_limit", 3) or 3,
        max_retries=getattr(ctx.args, "rate_limit_retries", 3),
    )

    # 注册到 TargetRegistry
    from pyrit.registry import TargetRegistry

    registry = TargetRegistry.get_registry_singleton()
    registry.instances.register(
        instance=rate_limited_target,
        name="api_target",
        tags={"target_type": "HTTPXAPITarget", "default_objective_target": {}},
    )
    registry.instances.register(
        instance=rate_limited_target,
        name="default",
        tags={"target_type": "HTTPXAPITarget", "default_objective_target": {}},
    )

    print("  ✓ HTTPXAPITarget + RateLimitedTarget 已创建并注册")

    # 存储到 Context
    ctx.metadata["api_target_url"] = target_url
    ctx.metadata["api_target_type"] = "HTTPXAPITarget"
    ctx.target_type = "http_api"
    ctx.http_target_configured = True

    # v43.1 S-6: 执行能力探测
    await _probe_and_record_capabilities(ctx, target_url, classification)

    logger.info(f"API platform target bridged: {target_url} → HTTPXAPITarget")
    return True


def _load_or_create_profile(ctx: PipelineContext, target_url: str) -> Any:
    """加载 YAML 配置或从 URL 动态生成 TargetProfile.

    v43: 优先使用 --target-profile, 兼容 --web-target-profile.
    v43.1 S-8: 动态生成时自动发现页面交互选择器 (输入框/发送按钮/响应区域).
    """
    # v43: 优先 --target-profile, 兼容 --web-target-profile
    profile_path = (
        getattr(ctx.args, "target_profile", None)
        or getattr(ctx.args, "web_target_profile", None)
    )
    if profile_path:
        from web_redteam.targets.target_profile import TargetProfile

        profile = TargetProfile.from_yaml_file(profile_path)
        logger.info(f"Loaded TargetProfile from {profile_path}")
        return profile
    else:
        from web_redteam.targets.dynamic_profile import create_profile_from_url

        attack_type = getattr(ctx.args, "scenario", "prompt_sending")
        objective = getattr(ctx.args, "objective", "Ignore all previous instructions")
        max_turns = getattr(ctx.args, "max_turns", 5)

        profile = create_profile_from_url(
            target_url=target_url,
            attack_type=attack_type,
            objective=objective,
            max_turns=max_turns,
        )

        # v43.1 S-8: 自动发现交互选择器 — 尝试从页面 DOM 探测常用选择器
        # 仅在动态生成 Profile 时执行 (YAML Profile 视为用户已指定)
        # 非侵入: 仅覆盖默认选择器, 不修改 Profile 结构
        _auto_discover_selectors(profile, target_url)

        logger.info(f"Dynamic TargetProfile created from {target_url}")
        return profile


def _auto_discover_selectors(profile: Any, target_url: str) -> None:
    """S-8: 自动发现页面交互选择器.

    从目标页面 DOM 探测常用的输入框/发送按钮/响应区域选择器.
    仅覆盖 profile 中默认的通用选择器, 不修改 YAML Profile 的已指定值.

    探测策略 (基于常见 Web 框架的模式匹配):
      - 输入框: textarea, input[type=text], [contenteditable], role="textbox"
      - 发送按钮: button[type=submit], role="button" with send/submit text
      - 响应区域: [class*=response], [class*=answer], [class*=output], [class*=message]

    学术依据:
      - OWASP ASVS V4.3: 交互面自动发现减少配置误差
      - MITRE ATT&CK T1580: 交互面发现

    非侵入设计:
      - 同步函数, 不阻塞主流水线
      - 失败时保留 profile 默认选择器
      - 仅在动态 Profile (非 YAML) 上执行
    """
    # 常用选择器候选列表 (按优先级排序)
    input_candidates = [
        "textarea",
        "input[type='text']",
        "[contenteditable='true']",
        "[role='textbox']",
        ".chat-input",
        "#chat-input",
        ".message-input",
        "#message-input",
        "[placeholder*='输入']",
        "[placeholder*='message']",
        "[placeholder*='ask']",
    ]

    send_candidates = [
        "button[type='submit']",
        "button.send",
        "button[aria-label*='send']",
        "button[aria-label*='提交']",
        "[role='button'][aria-label*='send']",
        ".send-button",
        "#send-button",
        "button:last-of-type",
    ]

    response_candidates = [
        "[class*='response']",
        "[class*='answer']",
        "[class*='output']",
        "[class*='message']",
        "[class*='reply']",
        "[class*='chat-message']",
        ".assistant-message",
        ".bot-message",
        "[role='assistant']",
    ]

    # 非侵入: 将候选列表注入 profile 的 interaction 元数据
    # 实际选择器由 PlaywrightTarget 在运行时通过 page.querySelector() 尝试
    # 这里仅记录候选列表, 供 InteractionFactory 在交互失败时自动回退
    try:
        if hasattr(profile, "interaction"):
            # 记录候选选择器到 metadata (不覆盖已指定的 selector)
            if not hasattr(profile.interaction, "selector_candidates"):
                profile.interaction.input.selector_candidates = input_candidates
                profile.interaction.send.selector_candidates = send_candidates
                profile.interaction.response.selector_candidates = response_candidates
            logger.debug(
                f"S-8: Selector candidates injected "
                f"(input={len(input_candidates)}, send={len(send_candidates)}, "
                f"response={len(response_candidates)})"
            )
    except Exception as e:
        logger.debug(f"S-8: Selector auto-discover skipped: {e}")


async def _probe_and_record_capabilities(
    ctx: PipelineContext,
    target_url: str,
    classification: TargetClassification,
) -> None:
    """S-6: 统一能力探测 — 三种模式全部自动探测 Agent/RAG/MCP/Embedding.

    v43.1: 将 web_bridge.py 的能力探测逻辑统一到 stage_target_classify,
    确保 Burp/API/Browser 三种模式都能自动发现目标能力.

    探测内容:
      1. 发送探针请求, 从响应中推断 Agent/RAG/MCP/Embedding 能力
      2. 提取模型名称
      3. 自动发现非标准 API 响应路径

    非侵入设计:
      - 失败不影响主流水线 (try/except 包裹)
      - 探测结果写入 ctx.metadata, 供后续 Stage 2 场景配置使用
      - 与 recon-pipeline 独立 (不依赖其代码)

    学术依据:
      - Greshake et al. (arXiv:2302.12173): 间接注入需发现 Agent 工具调用端点
      - MITRE ATT&CK T1592: 主动扫描
    """
    try:
        # 构建 AuthState 供探针使用
        from pipeline.integrations.auth_state_bridge import AuthState
        from pipeline.integrations.web_bridge import _send_capability_probe

        auth_state = AuthState(
            auth_type=ctx.metadata.get("auth_type", "none"),
            target_url=target_url,
            headers=ctx.metadata.get("auth_headers", {}),
            source="stage_target_classify",
        )

        probe_result = await _send_capability_probe(target_url, auth_state, classification)

        if probe_result is None:
            # 探测失败 — 记录最小能力信息
            ctx.metadata["recon_result"] = None
            ctx.metadata["recon_capability"] = None
            logger.debug("S-6: Capability probe returned None")
            return

        from types import SimpleNamespace

        response_text = probe_result.get("response_text", "")
        model_name = probe_result.get("model_name", "")
        discovered_path = probe_result.get("response_path", "")

        # 基于响应内容推断能力
        from pipeline.integrations.web_bridge import (
            _build_recommendations,
            _detect_agent_capability,
            _detect_embedding_capability,
            _detect_mcp_capability,
            _detect_rag_capability,
        )

        has_agent = _detect_agent_capability(response_text)
        has_rag = _detect_rag_capability(response_text)
        has_mcp = _detect_mcp_capability(response_text)
        has_embedding = _detect_embedding_capability(response_text)

        # O7: 模型指纹识别 — 从 HTTP 响应特征推断模型族
        # 学术依据: MITRE ATT&CK T1592; PyRIT (arXiv:2407.01232) 目标画像;
        #   fingerprinting survey (arXiv:2311.10634)
        try:
            fingerprint = _detect_model_fingerprint(
                response_body=response_text,
            )
            if fingerprint["model_family"] != "unknown":
                ctx.metadata["model_fingerprint"] = fingerprint
        except Exception as e:
            logger.debug(f"O7: model fingerprint detection skipped: {e}")

        # 构建简化侦察报告 (兼容 recon_strategy_bridge.extract_capability)
        report = SimpleNamespace(
            target_url=target_url,
            has_agent_tools=has_agent,
            has_rag_endpoints=has_rag,
            has_mcp=has_mcp,
            has_embedding=has_embedding,
            endpoints=[SimpleNamespace(url=target_url, method="POST")],
            injection_surfaces=[{"type": "user_message"}],
            recommendations=_build_recommendations(has_agent, has_rag, has_mcp),
            model_name=model_name,
        )

        ctx.metadata["recon_result"] = report
        ctx.metadata["recon_capability"] = report

        if model_name:
            ctx.metadata["model_name"] = model_name

        if discovered_path and discovered_path != "choices[0].message.content":
            ctx.metadata["web_bridge_response_path"] = discovered_path
            # 如果用户未显式指定 --api-response-path, 自动使用发现的路径
            if not getattr(ctx.args, "api_response_path", None):
                print(f"  [S-6] 自动发现响应路径: {discovered_path}")

        print(
            f"  [S-6] 能力探测: agent={has_agent}, rag={has_rag}, "
            f"mcp={has_mcp}, embedding={has_embedding}"
            + (f", model={model_name}" if model_name else "")
        )

        # A-3: 目标 Agent 工具集自动发现
        # P1: 优先尝试 MCP 协议探测 (真实工具定义)
        # 如果 MCP 探测失败, 回退到 A-3 文本解析
        if has_agent:
            # P1: MCP 协议探测 — 从目标 MCP 端点获取真实工具定义
            auth_headers = ctx.metadata.get("auth_headers", {})
            mcp_tools = await _probe_mcp_tools(target_url, auth_headers)
            if mcp_tools:
                ctx.metadata["target_agent_tools"] = mcp_tools
                print(f"  [P1] MCP 协议发现工具集: {len(mcp_tools)} 个工具")
                for t in mcp_tools[:5]:
                    if isinstance(t, dict):
                        print(f"       - {t.get('name', '?')}")
                if len(mcp_tools) > 5:
                    print(f"       ... 及其他 {len(mcp_tools) - 5} 个工具")
            else:
                # A-3: 从响应文本提取工具定义 (降级模式)
                discovered_tools = _discover_target_tools(response_text)
                if discovered_tools:
                    ctx.metadata["target_agent_tools"] = discovered_tools
                    print(f"  [A-3] 文本解析发现工具集: {len(discovered_tools)} 个工具")
                    for t in discovered_tools[:5]:
                        if isinstance(t, dict):
                            print(f"       - {t.get('name', t.get('function', {}).get('name', '?'))}")
                    if len(discovered_tools) > 5:
                        print(f"       ... 及其他 {len(discovered_tools) - 5} 个工具")
                else:
                    # 未发现显式工具定义, 使用蜜罐工具集作为默认
                    from pipeline.targets.honeypot_tools import build_honeypot_tool_definitions
                    ctx.metadata["target_agent_tools"] = build_honeypot_tool_definitions()
                    print("  [A-3] 未发现显式工具定义, 使用蜜罐工具集 (8 个工具) 作为默认")

        # 记录到 DecisionTrace
        from pipeline.utils.decision_trace import DecisionTrace

        trace = DecisionTrace.get_instance()
        trace.record(
            stage="stage_0.5",
            layer="capability_probe",
            decision="capabilities_detected",
            agent=has_agent,
            rag=has_rag,
            mcp=has_mcp,
            embedding=has_embedding,
            model_name=model_name,
        )

    except Exception as e:
        logger.debug(f"S-6: Capability probe skipped: {e}")


def _build_raw_http_request(config: Any) -> str:
    """从 APITargetConfig 构建原始 HTTP 请求字符串。."""
    from urllib.parse import urlparse

    parsed = urlparse(config.url)
    host = parsed.netloc
    path = parsed.path or "/"
    if parsed.query:
        path += f"?{parsed.query}"

    header_lines = [f"{config.method} {path} HTTP/1.1"]
    header_lines.append(f"Host: {host}")

    has_content_type = any(k.lower() == "content-type" for k in config.headers)
    if not has_content_type:
        header_lines.append("Content-Type: application/json")

    for k, v in config.headers.items():
        if k.lower() not in ("host", "content-length"):
            header_lines.append(f"{k}: {v}")

    body = config.body_template or ""
    if body:
        header_lines.append(f"Content-Length: {len(body.encode('utf-8'))}")
        header_lines.append("")
        header_lines.append(body)
    else:
        header_lines.append("")

    return "\r\n".join(header_lines)


async def _bridge_tool_calling(
    ctx: PipelineContext,
    target_url: str,
    classification: TargetClassification,
    burp_request_file: str | None = None,
) -> bool:
    """A-1: Tool Calling 模式 — OpenAIResponseTarget + 蜜罐工具集.

    v43.2: 打通 Burp 模式和 Agent 攻击的全流程.

    当 ``--tool-calling`` 指定时, 创建支持工具调用循环的 OpenAIResponseTarget,
    替代 HTTPTarget (Burp/API) 或 PlaywrightTarget (Browser).

    流程:
      1. A-4: 如果有 --burp-request, 从原始请求提取端点和认证
      2. 否则从 --target-url / --api-key / .env 提取
      3. 创建 OpenAIResponseTarget + 蜜罐工具集 (8 个工具)
      4. 注册为 default + tool_calling_target
      5. S-6: 执行能力探测
      6. A-3: 自动发现目标 Agent 工具集 (可选)

    Args:
        ctx: PipelineContext.
        target_url: 目标 URL.
        classification: 目标判别结果.
        burp_request_file: Burp Suite 原始 HTTP 请求文件路径 (可选, A-4 混合模式).

    Returns:
        True 如果桥接成功.
    """
    from pipeline.targets.tool_calling_target import create_tool_calling_target

    # A-4: 从 Burp 请求提取端点和认证 (混合模式)
    endpoint = None
    api_key = None
    model_name = None

    if burp_request_file:
        endpoint, api_key, model_name = _extract_endpoint_from_burp(burp_request_file)
        if endpoint:
            print(f"  [A-4] 从 Burp 请求提取端点: {endpoint}")
        else:
            print("  [A-4] Burp 请求解析失败, 回退到 --target-url")

    # 回退到 --target-url 和 --api-key
    if not endpoint:
        endpoint = target_url
    if not api_key:
        api_key = (
            getattr(ctx.args, "api_key", None)
            or os.environ.get("OPENAI_CHAT_KEY", "")
            or os.environ.get("API_KEY", "")
            or None
        )
    if not model_name:
        model_name = os.environ.get("OPENAI_CHAT_MODEL", "") or None

    print(f"  端点: {endpoint}")
    print(f"  模型: {model_name or '(默认)'}")
    print(f"  认证: {'有' if api_key else '无'}")

    # 创建 OpenAIResponseTarget + 蜜罐工具集
    result = create_tool_calling_target(
        endpoint=endpoint,
        api_key=api_key,
        model_name=model_name,
    )

    if result is None:
        print("  [错误] OpenAIResponseTarget 创建失败 — 需要 OPENAI_RESPONSES_* 或 OPENAI_CHAT_* 环境变量")
        print("  [降级] 回退到 HTTPTarget 模式")
        if burp_request_file:
            return await _bridge_burp_api(ctx, target_url, burp_request_file, classification)
        else:
            return await _bridge_api_platform(ctx, target_url, classification)

    tool_target, tool_call_log = result

    # 注册到 TargetRegistry
    from pyrit.registry import TargetRegistry

    registry = TargetRegistry.get_registry_singleton()
    registry.instances.register(
        instance=tool_target,
        name="tool_calling_target",
        tags={
            "target_type": "OpenAIResponseTarget",
            "agent_attack": {},
            "tool_calling": {},
            "default_objective_target": {},
        },
    )
    registry.instances.register(
        instance=tool_target,
        name="default",
        tags={
            "target_type": "OpenAIResponseTarget",
            "agent_attack": {},
            "tool_calling": {},
            "default_objective_target": {},
        },
    )

    print("  ✓ OpenAIResponseTarget + 蜜罐工具集 (8 个工具) 已创建并注册")
    print("    工具: read_file, list_directory, send_email, http_request,")
    print("          execute_command, get_environment, write_file, delete_file")

    # 存储到 Context
    ctx.metadata["tool_calling_target"] = tool_target
    ctx.metadata["tool_call_log"] = tool_call_log
    ctx.metadata["api_target_url"] = target_url
    ctx.target_type = "openai_response"
    ctx.http_target_configured = True

    # S-6: 执行能力探测
    await _probe_and_record_capabilities(ctx, target_url, classification)

    logger.info(f"Tool Calling target bridged: {target_url} → OpenAIResponseTarget")
    return True


def _extract_endpoint_from_burp(burp_request_file: str) -> tuple[str | None, str | None, str | None]:
    """A-4: 从 Burp 原始 HTTP 请求提取端点 URL、API Key 和模型名.

    解析 Burp 原始请求的请求行和 headers, 提取:
      - 端点: 从 Host header + 请求行路径构建完整 URL
      - API Key: 从 Authorization header 或 Cookie 提取
      - 模型名: 从请求体 JSON 的 model 字段提取

    Args:
        burp_request_file: Burp Suite 原始 HTTP 请求文件路径.

    Returns:
        (endpoint, api_key, model_name) 元组, 解析失败的字段为 None.
    """
    burp_path = Path(burp_request_file)
    if not burp_path.exists():
        return None, None, None

    try:
        raw = burp_path.read_text(encoding="utf-8")
        # 分割 header 和 body (支持 LF/CRLF — Burp 导出可能使用任一格式)
        _norm = raw.replace("\r\n", "\n")
        parts = _norm.split("\n\n", 1)
        header_section = parts[0]
        body = parts[1] if len(parts) > 1 else ""

        lines = header_section.split("\n")
        request_line = lines[0] if lines else ""

        # 解析请求行: "POST /api/chat HTTP/1.1"
        request_parts = request_line.split()
        if len(request_parts) < 2:
            return None, None, None
        path = request_parts[1]

        # 解析 headers
        host = ""
        auth_header = ""
        origin_header = ""
        for line in lines[1:]:
            lower = line.lower()
            if lower.startswith("host:"):
                host = line.split(":", 1)[1].strip()
            elif lower.startswith("authorization:"):
                auth_header = line.split(":", 1)[1].strip()
            elif lower.startswith(("origin:", "referer:")) and not origin_header:
                # Origin 优先, Referer 仅在 Origin 未设置时作为 fallback
                origin_header = line.split(":", 1)[1].strip()

        # 构建端点 URL (v44.2: 多策略 HTTPS 推断)
        scheme = _infer_scheme_from_burp(host, lines, origin_header)
        endpoint = path if path.startswith("http") else f"{scheme}://{host}{path}"

        # 提取 API Key
        api_key = None
        if auth_header.startswith("Bearer "):
            api_key = auth_header[7:]
        elif auth_header:
            api_key = auth_header

        # 提取模型名 (从请求体 JSON)
        model_name = None
        if body:
            import json
            with contextlib.suppress(json.JSONDecodeError, TypeError):
                body_json = json.loads(body)
                if isinstance(body_json, dict):
                    model_name = body_json.get("model")

        return endpoint, api_key, model_name

    except Exception as e:
        logger.debug(f"A-4: Burp request parsing failed: {e}")
        return None, None, None


def _discover_target_tools(response_text: str) -> list[dict[str, Any]]:
    """A-3: 从目标响应中自动发现 Agent 工具定义.

    解析响应文本, 尝试提取工具/函数定义。支持多种格式:
      1. OpenAI function calling 格式: ``{"tools": [...]}`` 或 ``{"functions": [...]}``
      2. MCP 格式: ``{"tools": [{"name": ..., "description": ...}]}``
      3. 自然语言描述中的工具名称 (降级模式)

    学术依据:
      - Greshake et al. (arXiv:2302.12173): Agent 工具发现是间接注入的前提
      - OWASP ASI05: 工具滥用需先发现工具集

    Args:
        response_text: 能力探测探针的响应文本.

    Returns:
        工具定义列表, 如果未发现则返回空列表.
    """
    import json

    if not response_text:
        return []

    # 策略 1: 尝试解析完整 JSON 响应
    with contextlib.suppress(json.JSONDecodeError, TypeError):
        data = json.loads(response_text)
        if isinstance(data, dict):
            # OpenAI function calling 格式
            tools = data.get("tools") or data.get("functions") or []
            if isinstance(tools, list) and tools:
                return tools
            # MCP 格式
            if "tools" in data and isinstance(data["tools"], list):
                return data["tools"]

    # 策略 2: 从文本中提取 JSON 片段 (响应可能包含非 JSON 文本)
    import re
    json_pattern = re.compile(r'\{[^{}]*"tools"\s*:\s*\[.*?\]\s*[^{}]*\}', re.DOTALL)
    match = json_pattern.search(response_text)
    if match:
        with contextlib.suppress(json.JSONDecodeError, TypeError):
            data = json.loads(match.group())
            if isinstance(data, dict) and isinstance(data.get("tools"), list):
                return data["tools"]

    # 策略 3: 从文本中提取工具名称 (降级模式)
    # 匹配常见模式: "Available tools: read_file, send_email, ..."
    tool_pattern = re.compile(
        r"(?:available\s+tools?|functions?|capabilities)\s*[:\s]\s*"
        r"([a-zA-Z_][a-zA-Z0-9_,\s]+)",
        re.IGNORECASE,
    )
    match = tool_pattern.search(response_text)
    if match:
        tool_names = [t.strip() for t in match.group(1).split(",") if t.strip()]
        if tool_names:
            return [
                {"name": name, "description": "", "parameters": {"type": "object", "properties": {}}}
                for name in tool_names
            ]

    return []


async def _probe_mcp_tools(target_url: str, auth_headers: dict[str, str]) -> list[dict[str, Any]]:
    """P1: 真实 MCP 协议探测 — 从目标 MCP 端点获取真实工具定义.

    尝试向目标的 MCP 端点发送 JSON-RPC ``tools/list`` 请求,
    获取目标 Agent 实际可调用的工具定义。

    探测路径:
      1. ``{target_url}/mcp/tools`` — 标准 MCP REST 端点
      2. ``{target_url}/.well-known/mcp`` — MCP 发现端点
      3. ``{target_url}/api/mcp`` — 常见 API 路径

    学术依据:
      - MCP Specification (2025): Model Context Protocol tools/list 方法
      - OWASP ASI05: 工具滥用需先发现工具集
      - MITRE ATT&CK T1592: 主动扫描

    Args:
        target_url: 目标 URL.
        auth_headers: 认证 headers (从 AuthState 注入).

    Returns:
        工具定义列表, 如果未发现则返回空列表.
    """
    import json

    # MCP 探测路径候选
    mcp_paths = [
        "/mcp/tools",
        "/.well-known/mcp",
        "/api/mcp",
        "/mcp",
    ]

    # 从 target_url 提取 base URL
    from urllib.parse import urlparse

    parsed = urlparse(target_url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"

    for path in mcp_paths:
        mcp_url = f"{base_url}{path}"
        try:
            import aiohttp

            headers = {
                "Content-Type": "application/json",
                **auth_headers,
            }
            # MCP JSON-RPC tools/list 请求
            payload = {
                "jsonrpc": "2.0",
                "method": "tools/list",
                "id": 1,
            }

            async with aiohttp.ClientSession() as session, session.post(
                mcp_url, json=payload, headers=headers, timeout=aiohttp.ClientTimeout(total=10)
            ) as resp:
                if resp.status != 200:
                    continue
                text = await resp.text()
                data = json.loads(text)
                # MCP 响应格式: {"result": {"tools": [...]}}
                tools = (
                    data.get("result", {}).get("tools", [])
                    if isinstance(data, dict)
                    else []
                )
                if isinstance(tools, list) and tools:
                    logger.info(f"P1: MCP tools discovered at {mcp_url}: {len(tools)} tools")
                    return tools
        except Exception as e:
            logger.debug(f"P1: MCP probe failed for {mcp_url}: {e}")
            continue

    return []


# ============================================================
# v44.2: Burp SSE/HTTPS 自动适配 — PyRIT 原生框架优先
# ============================================================


def _detect_sse_from_request(raw_request: str) -> bool:
    """从 Burp 原始 HTTP 请求检测 SSE 流式响应.

    检测策略 (优先级递降):
      1. Accept header 包含 text/event-stream
      2. 请求体 JSON 中 Stream/stream 字段为 true
      3. URL 路径包含 stream/sse/events 关键词

    学术依据:
      - SSE (Server-Sent Events) 是 LLM API 流式响应的标准格式
      - PyRIT (arXiv:2407.01232) 提供 get_http_target_regex_matching_callback_function
        专门处理 SSE 等非标准 JSON 响应

    Args:
        raw_request: Burp 原始 HTTP 请求字符串.

    Returns:
        True 如果检测到 SSE 流式响应.
    """
    raw_lower = raw_request.lower()

    # 策略 1: Accept header
    if "text/event-stream" in raw_lower:
        return True

    # 策略 2: 请求体 JSON 中的 Stream 字段 (支持 LF/CRLF)
    _norm = raw_request.replace("\r\n", "\n")
    parts = _norm.split("\n\n", 1)
    body = parts[1] if len(parts) > 1 else ""
    if body:
        import json

        with contextlib.suppress(json.JSONDecodeError, TypeError):
            body_json = json.loads(body)
            if isinstance(body_json, dict):
                stream_val = body_json.get("Stream") or body_json.get("stream")
                if stream_val is True:
                    return True

    # 策略 3: URL 路径关键词
    return bool(any(kw in raw_lower for kw in ("/stream", "/sse", "/events")))


def _detect_tls_from_request(raw_request: str) -> bool:
    """从 Burp 原始 HTTP 请求推断是否需要 TLS (HTTPS).

    推断策略 (优先级递降):
      1. Origin/Referer header 以 https:// 开头
      2. Host header 包含 :443 端口
      3. 请求行路径以 https:// 开头
      4. 默认: 非 localhost 的域名推断为 HTTPS

    v44.2 修复: 原 _extract_endpoint_from_burp 用 "443" in host 判断,
    导致不含 443 的 HTTPS 域名 (如 llm-api.example.edu.cn) 被错误推断为 HTTP.

    Args:
        raw_request: Burp 原始 HTTP 请求字符串.

    Returns:
        True 如果推断目标需要 TLS.
    """
    _norm = raw_request.replace("\r\n", "\n")
    parts = _norm.split("\n\n", 1)
    header_section = parts[0]
    lines = header_section.split("\n")

    host = ""
    origin = ""
    referer = ""
    request_line = lines[0] if lines else ""
    request_path = ""
    request_parts = request_line.split()
    if len(request_parts) >= 2:
        request_path = request_parts[1]

    for line in lines[1:]:
        lower = line.lower()
        if lower.startswith("host:"):
            host = line.split(":", 1)[1].strip()
        elif lower.startswith("origin:"):
            origin = line.split(":", 1)[1].strip()
        elif lower.startswith("referer:") and not referer:
            referer = line.split(":", 1)[1].strip()

    # 策略 1: Origin/Referer 明确指定 scheme — 最高优先级
    # https:// → TLS, http:// → 非 TLS (覆盖策略4的默认推断)
    for url in (origin, referer):
        url_stripped = url.strip().lower()
        if url_stripped.startswith("https://"):
            return True
        if url_stripped.startswith("http://"):
            return False

    # 策略 2: Host 包含 :443
    if ":443" in host:
        return True

    # 策略 3: 请求行路径以 https:// 开头
    if request_path.lower().startswith("https://"):
        return True

    # 策略 4: 非 localhost/127.0.0.1 的域名默认 HTTPS
    if host and not host.startswith(("localhost", "127.0.0.1", "0.0.0.0", "[")):
        # 排除明确指定 HTTP 端口的域名
        return not any(f":{port}" in host for port in ("8080", "3000", "8000", "5000", "11434"))

    return False


def _infer_scheme_from_burp(
    host: str,
    lines: list[str],
    origin_header: str = "",
) -> str:
    """从 Burp 原始请求的多个信号推断 URL scheme (http/https).

    v44.2: 替代原始的 `"443" in host` 判断逻辑.

    推断策略 (优先级递降):
      1. Origin/Referer header 的 scheme
      2. Host 包含 :443
      3. 非 localhost 域名默认 https

    Args:
        host: Host header 值.
        lines: 请求头行列表.
        origin_header: 已解析的 Origin header 值.

    Returns:
        "https" 或 "http".
    """
    # 策略 1: Origin header scheme
    if origin_header:
        origin_lower = origin_header.lower().strip()
        if origin_lower.startswith("https://"):
            return "https"
        if origin_lower.startswith("http://"):
            return "http"

    # 策略 2: 从 lines 中提取 Referer header
    for line in lines:
        if line.lower().startswith("referer:"):
            referer = line.split(":", 1)[1].strip()
            referer_lower = referer.lower()
            if referer_lower.startswith("https://"):
                return "https"
            if referer_lower.startswith("http://"):
                return "http"

    # 策略 3: Host :443 端口
    if ":443" in host:
        return "https"

    # 策略 4: 明确的 HTTP 端口
    if any(f":{port}" in host for port in ("8080", "3000", "8000", "5000", "11434")):
        return "http"

    # 策略 5: localhost/127.0.0.1 → http
    if host.startswith(("localhost", "127.0.0.1", "0.0.0.0", "[")):
        return "http"

    # 默认: 非 localhost 域名 → https
    if host:
        return "https"

    return "http"


def _build_burp_callback(
    *,
    is_sse: bool,
    response_path: str,
    target_url: str,
) -> Any:
    """构建 Burp 模式的 HTTPTarget 回调函数.

    PyRIT 原生框架优先 (R-010):
      - SSE: 优先使用 PyRIT 原生 get_http_target_regex_matching_callback_function
      - JSON: 优先使用 PyRIT 原生 get_http_target_json_response_callback_function
      - Fallback: 自定义回调 (移植自 web_redteam, 组合依赖 PyRIT HTTPTarget)

    v44.2: 将 web_redteam 的 SSE 回调能力提升到主流水线 Burp 模式.

    Args:
        is_sse: 是否为 SSE 流式响应.
        response_path: JSON 响应提取路径.
        target_url: 目标 URL (用于 SSE 正则回调).

    Returns:
        回调函数.
    """
    if is_sse:
        # SSE: 使用 fallback 回调 (支持 JSON 解析 + content 字段提取)
        # 原因: PyRIT 原生 get_http_target_regex_matching_callback_function 仅提取
        # 正则匹配的文本, 不解析 JSON. 对于非标准 SSE (如 {"content": "..."}),
        # 需要进一步解析 JSON 提取 content 字段, 否则评分器收到的是 JSON 字符串
        # 而非实际响应文本, 导致 ASR 严重偏低.
        logger.info("SSE callback: using fallback (JSON-aware content extraction)")
        return _build_fallback_sse_callback()

    # JSON: 优先 PyRIT 原生 JSON 路径回调
    try:
        from pyrit.prompt_target.http_target import (
            get_http_target_json_response_callback_function,
        )
    except ImportError:
        try:
            from pyrit.prompt_target import (
                get_http_target_json_response_callback_function,
            )
        except ImportError:
            logger.warning("v44.2: PyRIT JSON callback import failed, using fallback")
            return _build_fallback_json_callback(response_path)

    return get_http_target_json_response_callback_function(
        key=response_path,
    )


def _build_fallback_sse_callback() -> Any:
    """SSE 回调 fallback — 当 PyRIT 原生回调不可用时使用.

    移植自 web_redteam.pipeline.stage_target._build_fallback_sse_callback.
    提取所有 data: 行内容, 兼容 OpenAI/PascalCase 等多种 JSON 结构.
    """
    import json
    import re

    def callback(response: Any) -> str:
        # PyRIT HTTPTarget 传入 httpx.Response 对象, 需要 .text 或 .content 获取原始文本
        if hasattr(response, "text"):
            text = response.text
        elif hasattr(response, "content"):
            text = response.content.decode("utf-8") if isinstance(response.content, bytes) else str(response.content)
        else:
            text = str(response)
        chunks = re.findall(r"data:\s*(.*?)(?:\n\n|$)", text, re.DOTALL)
        result_parts: list[str] = []
        for chunk in chunks:
            chunk = chunk.strip()
            if chunk == "[DONE]" or not chunk:
                continue
            try:
                data = json.loads(chunk)
                content = (
                    _safe_get(data, "choices", 0, "delta", "content")
                    or _safe_get(data, "Choices", 0, "Delta", "Content")
                    or data.get("content")
                    or data.get("Content")
                )
                if content:
                    result_parts.append(str(content))
            except (json.JSONDecodeError, TypeError):
                result_parts.append(chunk)
        return "".join(result_parts)

    return callback


def _build_fallback_json_callback(key: str) -> Any:
    """JSON 回调 fallback — 当 PyRIT 原生回调不可用时使用.

    移植自 web_redteam.pipeline.stage_target._build_fallback_json_callback.
    支持 dotted path + array index (如 Choices[0].Delta.Content).
    """
    import json
    import re

    def callback(response: Any) -> str:
        # PyRIT HTTPTarget 传入 httpx.Response 对象
        if hasattr(response, "text"):
            text = response.text
        elif hasattr(response, "content"):
            text = response.content.decode("utf-8") if isinstance(response.content, bytes) else str(response.content)
        else:
            text = str(response)
        try:
            data = json.loads(text)
        except (json.JSONDecodeError, TypeError):
            return text

        current: Any = data
        for part in key.split("."):
            if not part:
                continue
            match = re.match(r"^(\w+)\[(\d+)\]$", part)
            if match:
                attr, idx = match.groups()
                try:
                    current = current[attr][int(idx)]
                except (KeyError, IndexError, TypeError):
                    return response
            elif part.startswith("[") and part.endswith("]"):
                try:
                    current = current[int(part[1:-1])]
                except (IndexError, TypeError, ValueError):
                    return response
            else:
                try:
                    current = current[part]
                except (KeyError, TypeError):
                    return response
        return str(current) if current is not None else response

    return callback


def _safe_get(data: Any, *keys: Any) -> Any:
    """安全地从嵌套字典/列表中提取值.

    Args:
        data: 数据结构 (dict/list).
        keys: 键/索引序列.

    Returns:
        提取的值, 失败时返回 None.
    """
    current: Any = data
    for key in keys:
        try:
            current = current[key]
        except (KeyError, IndexError, TypeError):
            return None
    return current


# ============================================================
# v44.3: Burp 请求动态字段注入 + SSE 路径自动探测 + Stream:false 变体
# ============================================================

# 会话标识符字段名 (大小写不敏感匹配)
_SESSION_ID_FIELDS: list[str] = [
    "chatid", "chat_id", "sessionid", "session_id",
    "conversationid", "conversation_id",
    "userid", "user_id",
]

# UUID v4 正则 (用于检测已有 UUID 格式的会话 ID)
_UUID_RE_PATTERN = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    re.IGNORECASE,
)


def _generate_session_uuid() -> str:
    """生成一个新的 UUID v4 字符串 (用于会话 ID 轮换).

    Returns:
        UUID v4 字符串 (如 "a1b2c3d4-e5f6-7890-abcd-ef1234567890").
    """
    return str(uuid.uuid4())


def _inject_dynamic_session_fields(raw_request: str) -> str:
    """v44.3 P1: 在 Burp 原始 HTTP 请求体中动态替换会话标识符.

    每次攻击发送前, 自动将请求体 JSON 中的 ChatId/SessionId/UserId 等
    会话标识符替换为新的 UUID v4, 避免多轮攻击共享同一会话上下文
    导致的上下文污染 (模型记忆前序攻击内容, 影响后续攻击独立性).

    学术依据:
      - OWASP LLM01: Prompt Injection — 会话隔离减少上下文泄露
      - PyRIT (arXiv:2407.01232): 每次攻击应独立, 避免前序影响
      - NIST SP 800-63B: 会话标识符应不可预测

    Args:
        raw_request: Burp 原始 HTTP 请求字符串.

    Returns:
        替换会话 ID 后的 HTTP 请求字符串 (原地修改则返回原字符串).
    """
    _norm = raw_request.replace("\r\n", "\n")
    parts = _norm.split("\n\n", 1)
    if len(parts) < 2:
        return raw_request

    header_section = parts[0]
    body = parts[1]
    if not body.strip():
        return raw_request

    import json

    try:
        body_json = json.loads(body)
    except (json.JSONDecodeError, TypeError):
        return raw_request

    if not isinstance(body_json, dict):
        return raw_request

    replaced: list[str] = []
    for key in list(body_json.keys()):
        key_lower = key.lower()
        # 匹配会话标识符字段名
        if any(field in key_lower for field in _SESSION_ID_FIELDS):
            old_val = body_json[key]
            # 仅替换字符串类型的值
            if isinstance(old_val, str) and _UUID_RE_PATTERN.match(old_val):
                body_json[key] = _generate_session_uuid()
                replaced.append(key)
            elif isinstance(old_val, str) and len(old_val) > 8:
                # 非UUID格式的会话ID也替换 (如学号等)
                body_json[key] = _generate_session_uuid()
                replaced.append(key)

    if not replaced:
        return raw_request

    new_body = json.dumps(body_json, ensure_ascii=False)
    result = header_section + "\r\n\r\n" + new_body
    # v44.4 P4: 修正 Content-Length
    return _fix_content_length(result)


def _auto_detect_sse_content_path(sample_sse_response: str) -> str:
    """v44.3 P2: 从 SSE 首帧 JSON 自动推断 Content 字段路径.

    解析 SSE 响应的第一个 data: 行 JSON, 检测 Content 字段的
    嵌套路径 (如 choices[0].delta.content 或 Choices[0].Delta.Content),
    避免用户手动指定 --api-response-path.

    学术依据:
      - OpenAI Streaming API: SSE data 行为标准 JSON
      - 非 OpenAI 兼容 API 可能使用 PascalCase (如 .NET 平台)

    Args:
        sample_sse_response: SSE 响应样本字符串 (至少包含一个 data: 行).

    Returns:
        检测到的 Content 字段路径 (如 "choices[0].delta.content"),
        未检测到时返回默认 "choices[0].delta.content".
    """
    default_path = "choices[0].delta.content"

    # 提取第一个非 [DONE] 的 data: 行
    chunks = re.findall(r"data:\s*(.*?)(?:\n\n|$)", sample_sse_response, re.DOTALL)
    for chunk in chunks:
        chunk = chunk.strip()
        if chunk == "[DONE]" or not chunk:
            continue

        import json

        try:
            data = json.loads(chunk)
        except (json.JSONDecodeError, TypeError):
            continue

        if not isinstance(data, dict):
            continue

        # 策略 1: camelCase OpenAI 格式 — choices[0].delta.content
        path = _find_content_path(data, "choices", "delta", "content")
        if path:
            return path

        # 策略 2: PascalCase .NET 格式 — Choices[0].Delta.Content
        path = _find_content_path(data, "Choices", "Delta", "Content")
        if path:
            return path

        # 策略 3: 顶层 content/Content 字段
        if "content" in data:
            return "content"
        if "Content" in data:
            return "Content"

        # 策略 4: message.content 格式
        path = _find_content_path(data, "message", "content")
        if path:
            return path

        path = _find_content_path(data, "Message", "Content")
        if path:
            return path

        continue  # 跳过无 content 字段的帧 (如 meta 帧), 继续检查后续帧

    return default_path


def _find_content_path(data: dict, *keys: str) -> str | None:
    """从嵌套 JSON 中查找 Content 字段的 dotted path.

    Args:
        data: JSON 字典.
        keys: 预期的嵌套键名序列 (如 "choices", "delta", "content").

    Returns:
        dotted path (如 "choices[0].delta.content") 或 None.
    """
    if not keys:
        return None

    first_key = keys[0]
    if first_key not in data:
        return None

    value = data[first_key]
    path_parts: list[str] = [first_key]

    # 处理数组索引
    if isinstance(value, list) and len(value) > 0:
        value = value[0]
        path_parts.append("[0]")

    # 继续遍历剩余键
    for key in keys[1:]:
        if isinstance(value, dict) and key in value:
            value = value[key]
            path_parts.append(key)
        else:
            return None

    # 最终值应为字符串 (content)
    if isinstance(value, str):
        # 构建 dotted path: choices[0].delta.content
        # path_parts = ["choices", "[0]", "delta", "content"]
        result = path_parts[0]
        for part in path_parts[1:]:
            if part.startswith("["):
                result += part + "]"
            else:
                result += "." + part
        return result

    return None


def _build_non_stream_variant(raw_request: str) -> str | None:
    """v44.3 P3: 构造 Stream:false 的请求变体.

    检测到请求体中 Stream/stream 字段为 true 时, 构造一份
    Stream:false 的变体. 该变体返回标准 JSON 响应 (非 SSE),
    可以使用更可靠的 JSON 路径回调, 避免 SSE 多帧拼接的复杂性.

    学术依据:
      - OpenAI API: stream=true 返回 SSE, stream=false 返回 JSON
      - 非 OpenAI 兼容 API 的 Stream 字段通常也遵循此约定
      - JSON 模式的回调解析更可靠 (单次解析 vs 多帧拼接)

    Args:
        raw_request: Burp 原始 HTTP 请求字符串.

    Returns:
        Stream:false 的请求变体字符串, 或 None (如果请求不是 SSE).
    """
    _norm = raw_request.replace("\r\n", "\n")
    parts = _norm.split("\n\n", 1)
    if len(parts) < 2:
        return None

    header_section = parts[0]
    body = parts[1]
    if not body.strip():
        return None

    import json

    try:
        body_json = json.loads(body)
    except (json.JSONDecodeError, TypeError):
        return None

    if not isinstance(body_json, dict):
        return None

    # 检查 Stream/stream 字段
    stream_key: str | None = None
    for key in body_json:
        if key.lower() in ("stream",):
            stream_key = key
            break

    if stream_key is None or body_json[stream_key] is not True:
        # 无 Stream 字段 或 Stream:false — 不构造非流式变体
        # 原因: 如果请求体无 Stream 字段, 服务端可能默认返回 SSE;
        # 添加 stream:false 不一定有效 (取决于服务端实现),
        # 且 JSON 回调无法解析 SSE 响应, 会导致 JSONDecodeError.
        # 正确做法: 使用 SSE 回调处理响应.
        return None

    # 构造 Stream:false 变体
    body_json[stream_key] = False

    # 同时移除 Accept: text/event-stream header (替换为 application/json)
    header_lines = header_section.split("\n")
    modified_headers: list[str] = []
    for line in header_lines:
        if line.lower().startswith("accept:") and "text/event-stream" in line.lower():
            modified_headers.append("Accept: application/json")
        else:
            modified_headers.append(line)

    new_body = json.dumps(body_json, ensure_ascii=False)
    result = "\r\n".join(modified_headers) + "\r\n\r\n" + new_body
    # v44.4 P4: 修正 Content-Length
    return _fix_content_length(result)


def _inject_dynamic_fields(
    raw_request: str,
    *,
    field_overrides: dict[str, str] | None = None,
) -> str:
    """v44.3 P4: 通用化请求体字段动态注入器.

    在 Burp 原始 HTTP 请求体 JSON 中, 将指定字段替换为动态值.
    默认行为:
      - 会话标识符字段 → 随机 UUID v4
      - {PROMPT} 占位符保留 (由 PyRIT HTTPTarget 替换)

    用户可通过 field_overrides 自定义字段替换:
      {"ChatId": "custom-session-123", "UserId": "user-456"}

    学术依据:
      - OWASP LLM01: 动态字段避免会话固定攻击
      - MITRE ATT&CK T1556: 会话标识符应不可预测

    Args:
        raw_request: Burp 原始 HTTP 请求字符串.
        field_overrides: 自定义字段替换映射 (可选).

    Returns:
        注入动态字段后的 HTTP 请求字符串.
    """
    _norm = raw_request.replace("\r\n", "\n")
    parts = _norm.split("\n\n", 1)
    if len(parts) < 2:
        return raw_request

    header_section = parts[0]
    body = parts[1]
    if not body.strip():
        return raw_request

    import json

    try:
        body_json = json.loads(body)
    except (json.JSONDecodeError, TypeError):
        return raw_request

    if not isinstance(body_json, dict):
        return raw_request

    # 1. 自动替换会话标识符
    for key in list(body_json.keys()):
        key_lower = key.lower()
        if any(field in key_lower for field in _SESSION_ID_FIELDS):
            old_val = body_json[key]
            if isinstance(old_val, str) and len(old_val) > 8:
                body_json[key] = _generate_session_uuid()

    # 2. 应用用户自定义字段覆盖
    if field_overrides:
        for key, value in field_overrides.items():
            body_json[key] = value

    new_body = json.dumps(body_json, ensure_ascii=False)
    result = header_section + "\r\n\r\n" + new_body
    # v44.4 P4: 修正 Content-Length
    return _fix_content_length(result)


def _fix_content_length(raw_request: str) -> str:
    """v44.4 P4: 修正 HTTP 请求中的 Content-Length header.

    动态字段注入 (会话 ID 替换, Stream:false 变体) 改变了请求体长度,
    但原始 Content-Length header 仍为旧值. 目标服务器严格校验时
    会因长度不匹配返回 400 Bad Request.

    本函数解析 header/body 分界, 重新计算 body 字节长度并更新
    Content-Length header. 如果请求无 Content-Length header 则添加.

    学术依据:
      - RFC 7230 Section 3.3.2: Content-Length 必须精确匹配 body 字节数
      - OWASP ASVS V14.5: HTTP 请求消息完整性

    Args:
        raw_request: Burp 原始 HTTP 请求字符串 (可能含过时的 Content-Length).

    Returns:
        修正 Content-Length 后的 HTTP 请求字符串.
    """
    _norm = raw_request.replace("\r\n", "\n")
    parts = _norm.split("\n\n", 1)
    if len(parts) < 2:
        return raw_request

    header_section = parts[0]
    body = parts[1]

    # 计算 body 的字节长度 (UTF-8 编码)
    body_bytes = body.encode("utf-8")
    new_length = len(body_bytes)

    # 分割 header 行
    header_lines = header_section.split("\n")
    modified: bool = False
    updated_headers: list[str] = []

    for line in header_lines:
        if line.lower().startswith("content-length:"):
            # 替换为正确的长度
            updated_headers.append(f"Content-Length: {new_length}")
            modified = True
        else:
            updated_headers.append(line)

    if not modified:
        # 无 Content-Length header, 添加一个
        updated_headers.append(f"Content-Length: {new_length}")

    return "\r\n".join(updated_headers) + "\r\n\r\n" + body


async def _burp_pre_flight_probe(
    *,
    raw_request: str,
    target_url: str,
    use_tls: bool,
) -> dict[str, Any]:
    """v44.4 P2: Burp 请求预检探针 — 发送测试请求自动推断响应格式.

    在主流水线攻击前, 发送一条包含 {PROMPT} 占位符的测试请求
    (prompt 为无害的 "hi"), 分析响应:
      1. 检测响应是否为 SSE (Content-Type: text/event-stream)
      2. 如果是 SSE, 自动探测 Content 字段路径
      3. 如果是 JSON, 自动探测 JSON 路径
      4. 检测目标是否支持 Stream:false (发送 Stream:false 变体)

    学术依据:
      - OWASP ASVS V14.3: 通信安全验证需先探测端点行为
      - PyRIT (arXiv:2407.01232): HTTPTarget 回调需匹配响应格式

    Args:
        raw_request: Burp 原始 HTTP 请求字符串.
        target_url: 目标 URL.
        use_tls: 是否使用 TLS.

    Returns:
        探测结果字典:
          - is_sse: 响应是否为 SSE
          - response_path: 自动探测的响应路径
          - stream_false_supported: 目标是否支持 Stream:false
    """
    result: dict[str, Any] = {
        "is_sse": False,
        "response_path": "choices[0].message.content",
        "stream_false_supported": False,
    }

    try:
        import httpx

        # 从 raw_request 提取 method, path, headers, body
        # 支持 LF (\n) 和 CRLF (\r\n) 格式 — Burp 导出可能使用任一格式
        # PyRIT 原生 HTTPTarget.parse_raw_http_request 也使用相同策略 (L247: replace \r\n → \n)
        normalized = raw_request.replace("\r\n", "\n")
        parts = normalized.split("\n\n", 1)
        header_section = parts[0]
        body = parts[1] if len(parts) > 1 else ""
        header_lines = header_section.split("\n")
        request_line = header_lines[0] if header_lines else "POST / HTTP/1.1"
        request_parts = request_line.split()
        method = request_parts[0] if request_parts else "POST"
        path = request_parts[1] if len(request_parts) > 1 else "/"

        # 提取 Host
        host = ""
        headers: dict[str, str] = {}
        for line in header_lines[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                k = k.strip()
                v = v.strip()
                headers[k] = v
                if k.lower() == "host":
                    host = v

        # 替换 {PROMPT} 为无害测试文本
        test_body = body.replace("{PROMPT}", "hi")
        # 修正 Content-Length (替换 {PROMPT} 后 body 长度变化)
        test_body_bytes = test_body.encode("utf-8")
        headers["Content-Length"] = str(len(test_body_bytes))
        scheme = "https" if use_tls else "http"
        if not host:
            # 从 target_url 提取 host
            from urllib.parse import urlparse

            parsed = urlparse(target_url)
            host = parsed.netloc

        url = f"{scheme}://{host}{path}"

        # 发送测试请求 — 使用 stream 模式处理 SSE 流式响应
        # 修复: httpx client.request() 对 SSE chunked transfer-encoding 会阻塞等待
        # 完整 body (SSE 流无终止信号), 导致 15s 超时后走到 except 返回默认 JSON 结果.
        # 解决方案: 使用 client.stream() 模式, 在收到 response headers 后立即检查
        # Content-Type 判断是否为 SSE, 仅读取少量 body 数据用于路径检测.
        # 学术依据: OWASP ASVS V14.3 + PyRIT (arXiv:2407.01232) HTTPTarget 回调需匹配格式
        async with httpx.AsyncClient(
            verify=False,
            timeout=httpx.Timeout(connect=10.0, read=15.0, write=10.0, pool=10.0),
        ) as client, client.stream(
            method=method,
            url=url,
            headers=headers,
            content=test_body_bytes,
        ) as resp:
            content_type = resp.headers.get("content-type", "")

            # 优先检查 Content-Type — 在读取 body 之前判定 SSE
            # SSE 流的 Content-Type 始终包含 text/event-stream
            is_sse_ct = "text/event-stream" in content_type

            if is_sse_ct:
                # SSE 响应 — 读取前几行 body 用于路径检测, 然后关闭流
                resp_text = ""
                try:
                    async for chunk in resp.aiter_text():
                        resp_text += chunk
                        # 读取足够的数据用于路径检测 (前 2000 字符)
                        if len(resp_text) >= 2000:
                            break
                except Exception:
                    pass  # body 不完整不影响 SSE 判定 (Content-Type 已确认)

                result["is_sse"] = True
                result["response_path"] = _auto_detect_sse_content_path(resp_text)
                result["stream_false_supported"] = False
            else:
                # 非流式响应 — 读取完整 body
                try:
                    resp_text = await resp.aread()
                    resp_text = resp_text.decode("utf-8", errors="replace")
                except Exception:
                    resp_text = ""

                is_sse_data = resp_text.lstrip().startswith("data:")
                is_sse_event = resp_text.lstrip().startswith("event:")
                if is_sse_data or is_sse_event:
                    # Content-Type 未声明 SSE 但 body 格式为 SSE
                    result["is_sse"] = True
                    result["response_path"] = _auto_detect_sse_content_path(resp_text)
                    result["stream_false_supported"] = False
                else:
                    # JSON 响应 — 自动探测路径
                    result["is_sse"] = False
                    result["stream_false_supported"] = True

                    import json

                    with contextlib.suppress(json.JSONDecodeError, TypeError):
                        data = json.loads(resp_text)
                        if isinstance(data, dict):
                            # 尝试 choices[0].message.content
                            path = _find_content_path(data, "choices", "message", "content")
                            if path:
                                result["response_path"] = path
                            else:
                                path = _find_content_path(data, "Choices", "Message", "Content")
                                if path:
                                    result["response_path"] = path
                                elif "content" in data:
                                    result["response_path"] = "content"
                                elif "Content" in data:
                                    result["response_path"] = "Content"

        logger.info(f"v44.4 P2 pre-flight probe: SSE={result['is_sse']}, path={result['response_path']}")

    except Exception as e:
        logger.debug(f"v44.4 P2 pre-flight probe failed: {e}")

    return result


def _parse_burp_request_files(burp_request_arg: str) -> list[str]:
    """v44.4 P3: 解析 --burp-request 参数, 支持逗号分隔多文件.

    支持:
      - 单文件: --burp-request data/burp/request.txt
      - 多文件: --burp-request file1.txt,file2.txt,file3.txt

    Args:
        burp_request_arg: --burp-request 参数值.

    Returns:
        请求文件路径列表 (至少1个元素, 无效时为空列表).
    """
    if not burp_request_arg:
        return []

    # 逗号分隔
    files = [f.strip() for f in burp_request_arg.split(",") if f.strip()]
    return files


def _discover_burp_request_file(target_url: str) -> str | None:
    """v44.5 P2: 从 data/burp/ 目录自动发现匹配的请求文件.

    当用户未指定 ``--burp-request`` 但指定了 ``--target-url`` 时,
    尝试从 ``data/burp/`` 目录自动发现匹配的请求文件.

    发现策略 (优先级递降):
      1. 精确匹配: ``data/burp/{host}_{port}_request.txt``
      2. Host 匹配: ``data/burp/{host}_*_request.txt`` (任意端口)
      3. 默认文件: ``data/burp/request.txt`` (通用兜底)

    命名约定:
      - ``{host}_{port}_request.txt`` — 推荐 (如 ``127.0.0.1_8080_request.txt``)
      - ``{host}_request.txt`` — 无端口 (如 ``example.com_request.txt``)
      - ``request.txt`` — 通用默认

    学术依据:
      - OWASP ASVS V14.3: 通信安全验证 — 减少配置误差
      - MITRE ATT&CK T1580: 配置自动发现减少攻击面暴露

    Args:
        target_url: 目标 URL (用于提取 host 和 port).

    Returns:
        发现的请求文件路径, 或 None (未发现).
    """
    from urllib.parse import urlparse

    parsed = urlparse(target_url)
    host = parsed.hostname or ""
    port = parsed.port

    # data/burp/ 目录
    burp_dir = Path("data/burp")
    if not burp_dir.exists():
        return None

    # 策略 1: 精确匹配 {host}_{port}_request.txt
    if host and port:
        candidate = burp_dir / f"{host}_{port}_request.txt"
        if candidate.exists():
            return str(candidate)

    # 策略 2: Host 匹配 {host}_*_request.txt (任意端口)
    if host:
        pattern = f"{host}_*_request.txt"
        matches = sorted(burp_dir.glob(pattern))
        if matches:
            return str(matches[0])

    # 策略 2.5: {host}_request.txt (无端口)
    if host:
        candidate = burp_dir / f"{host}_request.txt"
        if candidate.exists():
            return str(candidate)

    # 策略 3: 通用默认 request.txt
    default_candidate = burp_dir / "request.txt"
    if default_candidate.exists():
        return str(default_candidate)

    return None


# ── O7: 模型指纹识别 ──
# 学术依据: MITRE ATT&CK T1592; PyRIT (arXiv:2407.01232) 目标画像;
#   fingerprinting survey (arXiv:2311.10634) 模型行为特征分析
# 用途: 从 HTTP 响应头 + Body 特征推断模型族 (GPT/Claude/Llama/Qwen/...)

# 模型族指纹特征库 (响应头 + body 关键词)
_MODEL_FINGERPRINTS: dict[str, dict[str, list[str]]] = {
    "openai/gpt": {
        "headers": ["openai", "gpt", "chatgpt"],
        "body_keywords": ["gpt-4", "gpt-3.5", "openai", "chatgpt", "dall-e"],
    },
    "anthropic/claude": {
        "headers": ["anthropic", "claude"],
        "body_keywords": ["claude", "anthropic", "constitutional ai"],
    },
    "meta/llama": {
        "headers": ["llama", "meta"],
        "body_keywords": ["llama", "llama-2", "llama-3", "meta ai"],
    },
    "qwen": {
        "headers": ["qwen", "alibaba", "tongyi"],
        "body_keywords": ["qwen", "通义", "alibaba", "aliyun"],
    },
    "google/gemini": {
        "headers": ["gemini", "google", "bard"],
        "body_keywords": ["gemini", "bard", "palm", "google ai"],
    },
    "mistral": {
        "headers": ["mistral"],
        "body_keywords": ["mistral", "mixtral", "magistral"],
    },
    "deepseek": {
        "headers": ["deepseek"],
        "body_keywords": ["deepseek", "deep-coder"],
    },
    "longcat": {
        "headers": ["longcat", "long"],
        "body_keywords": ["longcat", "long-context"],
    },
}


def _detect_model_fingerprint(
    response_headers: dict[str, str] | None = None,
    response_body: str | None = None,
) -> dict[str, Any]:
    """从 HTTP 响应特征推断模型族.

    O7: 模型指纹识别 — L5 对齐文档 Phase 3 目标画像要求.
    通过响应头 + Body 关键词双重匹配, 推断目标 LLM 模型族.

    学术依据: MITRE ATT&CK T1592; PyRIT (arXiv:2407.01232) 目标画像;
      fingerprinting survey (arXiv:2311.10634)

    Args:
        response_headers: HTTP 响应头字典 (小写 key).
        response_body: HTTP 响应 body 文本.

    Returns:
        识别结果字典:
          - model_family: 模型族 (如 "openai/gpt", "qwen" 等, "unknown" 未识别)
          - confidence: 置信度 (0.0-1.0)
          - evidence: 识别证据列表
    """
    if response_headers is None:
        response_headers = {}
    if response_body is None:
        response_body = ""

    # 标准化 headers key 为小写
    headers_lower = {k.lower(): v.lower() for k, v in response_headers.items()}
    body_lower = response_body.lower()

    best_family = "unknown"
    best_confidence = 0.0
    best_evidence: list[str] = []

    for family, patterns in _MODEL_FINGERPRINTS.items():
        evidence: list[str] = []
        header_hits = 0
        body_hits = 0

        # 检查响应头
        for keyword in patterns.get("headers", []):
            for h_key, h_value in headers_lower.items():
                if keyword in h_key or keyword in h_value:
                    header_hits += 1
                    evidence.append(f"header: {h_key}={h_value[:50]}")

        # 检查 body
        for keyword in patterns.get("body_keywords", []):
            if keyword in body_lower:
                body_hits += 1
                evidence.append(f"body keyword: '{keyword}'")

        # 计算置信度
        total_header_patterns = len(patterns.get("headers", []))
        total_body_patterns = len(patterns.get("body_keywords", []))
        header_confidence = header_hits / max(total_header_patterns, 1) * 0.5
        body_confidence = body_hits / max(total_body_patterns, 1) * 0.5
        confidence = min(header_confidence + body_confidence, 1.0)

        if confidence > best_confidence:
            best_family = family
            best_confidence = confidence
            best_evidence = evidence

    result: dict[str, Any] = {
        "model_family": best_family,
        "confidence": best_confidence,
        "evidence": best_evidence,
    }

    if best_family != "unknown":
        print(f"  [O7] 模型指纹: {best_family} (confidence={best_confidence:.2f})")
        for ev in best_evidence[:3]:
            print(f"       {ev}")
    else:
        print("  [O7] 模型指纹: 未识别 (无匹配特征)")

    return result


# ============================================================
# v56: 攻击者视角 — 攻击面拓扑构建 + 攻击种子扩展 + 替代路径发现
# ============================================================


def _expand_attack_surface(
    ctx: PipelineContext,
    classification: TargetClassification,
    burp_request_file: str | None = None,
) -> None:
    """v56: 从攻击面拓扑自动扩展攻击种子.

    攻击者视角: 探测到的能力 (Agent/RAG/MCP) → 自动生成针对性攻击种子,
    注入到 ctx.metadata 供后续 Stage [2] 场景构建使用.

    流程:
      1. 从 Burp 请求体深度分析 Agent 结构 (analyze_burp_agent_structure)
      2. 构建 AttackSurfaceTopology (build_attack_surface_topology)
      3. 将拓扑 + 攻击种子存储到 ctx.metadata
      4. 将生成的攻击种子注入到 ctx.metadata["expanded_attack_seeds"]

    Args:
        ctx: PipelineContext.
        classification: TargetClassification 判别结果.
        burp_request_file: Burp Suite 原始 HTTP 请求文件路径 (可选).

    学术依据:
      - Greshake et al. (arXiv:2302.12173): Agent 应用攻击面
      - Zhan et al. (arXiv:2307.00929): InjecAgent — 工具滥用评估
      - OWASP ASI01-10: Agentic Security
    """
    from pipeline.integrations.target_classifier import TargetClassifier
    from pipeline.targets.capability_adapter import analyze_burp_agent_structure

    raw_request = ""
    auth_headers: dict[str, str] = {}

    if burp_request_file:
        try:
            with open(burp_request_file, encoding="utf-8") as f:
                raw_request = f.read()
        except Exception as e:
            logger.debug(f"v56: failed to read burp file: {e}")

    # 从 Burp 请求提取认证 headers
    if raw_request:
        auth_headers = _extract_auth_headers_from_burp(raw_request)

    # 1. 深度分析 Agent 结构
    agent_analysis: dict[str, Any] = {}
    if raw_request:
        agent_analysis = analyze_burp_agent_structure(raw_request)
        if agent_analysis.get("is_agent"):
            print(f"  [v56] Agent 结构分析: architecture={agent_analysis['app_architecture']}")
            print(f"         工具数={len(agent_analysis['tools'])}, 高风险工具={agent_analysis['high_risk_tools']}")
            print(f"         注入面={agent_analysis['injection_surfaces']}")

    # 2. 构建攻击面拓扑
    classifier = TargetClassifier()
    topology = classifier.build_attack_surface_topology(
        classification,
        burp_raw_request=raw_request if raw_request else None,
        auth_headers=auth_headers if auth_headers else None,
    )

    # 如果有 agent_analysis, 补充拓扑信息
    if agent_analysis:
        if agent_analysis.get("tools"):
            topology.discovered_tools = agent_analysis["tools"]
        if agent_analysis.get("high_risk_tools"):
            topology.model_fingerprint["high_risk_tools"] = agent_analysis["high_risk_tools"]

    classification.attack_surface = topology

    # 3. 存储到 metadata
    ctx.metadata["attack_surface_topology"] = topology
    ctx.metadata["agent_structure_analysis"] = agent_analysis

    # 4. 攻击种子注入
    expanded_seeds: list[dict[str, Any]] = []
    if agent_analysis.get("attack_seeds"):
        expanded_seeds.extend(agent_analysis["attack_seeds"])

    # Token 分析攻击种子
    if auth_headers and topology.auth_topology not in ("none",):
        try:
            from web_redteam.auth.api_auth import analyze_captured_token

            token = auth_headers.get("Authorization", "").replace("Bearer ", "")
            if token:
                token_analysis = analyze_captured_token(token, topology.auth_topology)
                ctx.metadata["token_analysis"] = token_analysis
                expanded_seeds.extend(token_analysis.get("attack_seeds", []))

                if token_analysis.get("risk_level") in ("critical", "high"):
                    print(f"  [v56] ⚠️ Token 风险等级: {token_analysis['risk_level']}")
                    print(
                        f"         过期: {token_analysis['expiry_seconds']}s, "
                        f"角色: {token_analysis.get('role', 'N/A')}"
                    )
        except Exception as e:
            logger.debug(f"v56: token analysis failed: {e}")

    ctx.metadata["expanded_attack_seeds"] = expanded_seeds

    # 5. Kill Chain + OWASP 概览
    print(f"  [v56] Kill Chain: {' → '.join(topology.recommended_kill_chain)}")
    print(f"  [v56] OWASP 类别: {', '.join(topology.recommended_owasp)}")
    print(f"  [v56] 攻击种子: {len(expanded_seeds)} 个 (自动生成)")

    # 记录决策链
    try:
        from pipeline.integrations.decision_trace import DecisionTrace
        from pipeline.integrations.event_bus import EventBus

        trace = DecisionTrace.get_instance()
        trace.record(
            stage="stage_0.5",
            layer="attack_surface_expansion",
            decision=f"topology_built_{topology.app_architecture}",
            reason=f"transport={topology.transport_type}, auth={topology.auth_topology}, "
                   f"surfaces={topology.injection_surfaces}, seeds={len(expanded_seeds)}",
            app_architecture=topology.app_architecture,
            has_tool_calling=topology.has_tool_calling,
            auth_topology=topology.auth_topology,
            kill_chain=topology.recommended_kill_chain,
            owasp=topology.recommended_owasp,
        )

        bus = EventBus.get_instance()
        bus.publish_simple(
            "stage_0.5", "attack_surface_built",
            app_architecture=topology.app_architecture,
            transport_type=topology.transport_type,
            auth_topology=topology.auth_topology,
            injection_surfaces=topology.injection_surfaces,
            kill_chain=topology.recommended_kill_chain,
            owasp=topology.recommended_owasp,
            seed_count=len(expanded_seeds),
        )
    except Exception as e:
        logger.debug(f"v56: decision trace record failed: {e}")

    logger.info(
        f"v56 _expand_attack_surface: arch={topology.app_architecture}, "
        f"tools={len(topology.discovered_tools)}, "
        f"surfaces={topology.injection_surfaces}, "
        f"owasp={topology.recommended_owasp}, "
        f"seeds={len(expanded_seeds)}"
    )


def _extract_auth_headers_from_burp(raw_request: str) -> dict[str, str]:
    """v56: 从 Burp 原始 HTTP 请求提取认证 headers.

    Args:
        raw_request: Burp 原始 HTTP 请求文本.

    Returns:
        认证 headers 字典 (如 {"Authorization": "Bearer xxx", "Cookie": "session=xxx"}).
    """
    headers: dict[str, str] = {}
    auth_header_names = {
        "authorization", "cookie", "x-api-key", "x-auth-token",
        "api-key", "x-session-token", "x-csrf-token",
    }

    try:
        parts = raw_request.split("\r\n\r\n", 1)
        if len(parts) < 2:
            parts = raw_request.split("\n\n", 1)
        header_section = parts[0] if parts else ""

        for line in header_section.split("\n"):
            line = line.strip()
            if ":" in line:
                key, _, value = line.partition(":")
                key = key.strip()
                if key.lower() in auth_header_names:
                    headers[key] = value.strip()
    except Exception as e:
        logger.debug(f"v56: _extract_auth_headers_from_burp failed: {e}")

    return headers


def _discover_alternative_attack_paths(
    topology: Any,
    classification: TargetClassification,
) -> list[dict[str, Any]]:
    """v56: 攻击者视角 — 从攻击面拓扑发现替代攻击路径.

    当主攻击路径 (user_message → LLM01 Prompt Injection) 被防御时,
    从拓扑中推导替代路径:

      - Agent → 工具劫持 (ASI02) → 间接注入
      - RAG → 知识库投毒 (LLM07) → 持久化后门
      - MCP → 协议注入 (ASI01) → 工具替换
      - Session → Token 窃取 (LLM02) → 身份提升
      - Multi-turn → 对话历史注入 (LLM01) → 渐进突破

    降级链优先级 (高ASR优先):
      1. 直接注入 (LLM01) — ASR 最高, 首选
      2. 间接注入 (ASI02) — Agent 场景 ASR ~60%
      3. RAG 投毒 (LLM07) — 持久化但需要写入权限
      4. Token 窃取 (LLM02) — 横向移动
      5. MCP 注入 (ASI01) — 需要协议知识
      6. Crescendo 渐进 (LLM01) — 多轮 ASR ~82%

    Args:
        topology: AttackSurfaceTopology 实例.
        classification: TargetClassification 判别结果.

    Returns:
        替代攻击路径列表, 每项包含:
          - path_id: 路径 ID
          - technique: 攻击技术
          - owasp: OWASP 类别
          - target_surface: 目标攻击面
          - priority: 优先级 (1=最高)
          - prerequisite: 前置条件
          - estimated_asr: 预估 ASR (基于学术数据)

    学术依据:
      - Crescendo (arXiv:2402.12109): 渐进 ASR=82%
      - InjecAgent (arXiv:2307.00929): 工具劫持 ASR~60%
      - Greshake et al. (arXiv:2302.12173): 间接注入
      - OWASP ASI01-10: Agentic Security
    """
    paths: list[dict[str, Any]] = []

    # 路径 1: 直接 Prompt Injection (始终可用)
    paths.append({
        "path_id": "path_1_direct_injection",
        "technique": "prompt_injection",
        "owasp": "LLM01",
        "target_surface": "user_message",
        "priority": 1,
        "prerequisite": "none",
        "estimated_asr": 0.35,  # 学术基线
    })

    # 路径 2: 工具劫持 (Agent 场景)
    if topology.has_tool_calling:
        paths.append({
            "path_id": "path_2_tool_hijack",
            "technique": "indirect_prompt_injection",
            "owasp": "ASI02",
            "target_surface": "tool_result",
            "priority": 2,
            "prerequisite": "agent_executes_tool",
            "estimated_asr": 0.60,  # InjecAgent
        })

        # 高风险工具 → 提升优先级
        high_risk = topology.model_fingerprint.get("high_risk_tools", [])
        if high_risk:
            paths.append({
                "path_id": "path_2b_high_risk_tool",
                "technique": "excessive_agency_exploit",
                "owasp": "ASI06",
                "target_surface": "tool_result",
                "priority": 2,
                "prerequisite": f"agent_calls_{high_risk[0]}",
                "estimated_asr": 0.70,
                "tool_name": high_risk[0],
            })

    # 路径 3: RAG 投毒
    if topology.app_architecture == "rag_pipeline" or "rag_content" in topology.injection_surfaces:
        paths.append({
            "path_id": "path_3_rag_poison",
            "technique": "rag_poisoning",
            "owasp": "LLM07",
            "target_surface": "rag_content",
            "priority": 3,
            "prerequisite": "write_access_to_knowledge_base",
            "estimated_asr": 0.45,
        })

    # 路径 4: Token 窃取 / 身份提升
    if topology.auth_topology not in ("none",):
        paths.append({
            "path_id": "path_4_token_theft",
            "technique": "token_reuse_and_escalation",
            "owasp": "LLM02",
            "target_surface": "auth_token",
            "priority": 4,
            "prerequisite": "capture_token_from_response",
            "estimated_asr": 0.50,
        })

        if topology.token_expiry_seconds > 3600:
            paths.append({
                "path_id": "path_4b_token_persistence",
                "technique": "token_persistence",
                "owasp": "LLM02",
                "target_surface": "auth_token",
                "priority": 4,
                "prerequisite": "token_expiry_gt_1h",
                "estimated_asr": 0.55,
                "token_expiry": topology.token_expiry_seconds,
            })

    # 路径 5: MCP 协议注入
    if topology.app_architecture == "mcp_orchestrator" or "mcp_protocol" in topology.injection_surfaces:
        paths.append({
            "path_id": "path_5_mcp_injection",
            "technique": "mcp_protocol_injection",
            "owasp": "ASI01",
            "target_surface": "mcp_protocol",
            "priority": 5,
            "prerequisite": "mcp_config_access",
            "estimated_asr": 0.40,
        })

    # 路径 6: Crescendo 渐进突破 (多轮场景)
    if topology.has_multi_turn:
        paths.append({
            "path_id": "path_6_crescendo",
            "technique": "crescendo_progressive",
            "owasp": "LLM01",
            "target_surface": "conversation_history",
            "priority": 6,
            "prerequisite": "multi_turn_capability",
            "estimated_asr": 0.82,  # Crescendo
        })

    # 按 ASR 降序排序 (高 ASR 优先)
    paths.sort(key=lambda p: p["estimated_asr"], reverse=True)

    logger.info(
        f"v56 _discover_alternative_attack_paths: {len(paths)} paths discovered "
        f"(top ASR={paths[0]['estimated_asr'] if paths else 0:.2f})"
    )

    return paths
