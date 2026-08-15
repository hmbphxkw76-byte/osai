# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""Web Bridge — web_redteam 与主流水线自动串联编排层。

当用户提供 ``--target-url`` + ``--web-bridge`` 时, 自动执行完整链路:

  1. 调用 web_redteam 认证流程 (同域/跨域/MFA/OAuth2)
  2. 导出认证状态到 AuthState JSON
  3. 自动生成侦察报告 (从认证后的页面/API 探测能力)
  4. 将认证状态 + 侦察结果注入主流水线 PipelineContext
  5. 主流水线后续阶段 (Stage 2-6) 使用桥接后的 Target 执行完整攻击

与非桥接模式的区别:
  - ``--target-url`` (不带 ``--web-bridge``): 假定已知 API Key/Endpoint, 走 stage_target_classify
  - ``--target-url --web-bridge``: 通过 Web 应用认证获取会话 Token, 再桥接到 AI 端点

设计原则 (R-022: PyRIT 原生优先):
  - 认证流程复用 web_redteam/auth/ 原有模块
  - Target 创建复用 stage_target_classify 的 _bridge_api_platform / _bridge_web_app
  - 认证状态复用 auth_state_bridge 的 AuthState
  - 侦察结果复用 recon_strategy_bridge 的能力提取
  - 本模块仅做编排, 不重新实现任何认证/攻击逻辑

学术依据:
  - OWASP Top 10 for LLMs 2025: Web 注入和 API 注入的攻击面对应
  - MITRE ATT&CK: Reconnaissance → Initial Access → Execution
  - Greshake et al. (arXiv:2302.12173): 间接注入需发现 Agent 工具调用端点

> **日期**: 2026-8-14
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
from pathlib import Path
from typing import TYPE_CHECKING, Any

from pipeline.integrations.auth_state_bridge import (
    AuthState,
    export_auth_state,
    inject_auth_state_to_context,
)
from pipeline.integrations.recon_strategy_bridge import (
    extract_capability,
)
from pipeline.utils.decision_trace import DecisionTrace
from pipeline.utils.event_bus import EventBus

if TYPE_CHECKING:
    from pipeline.context import PipelineContext

logger = logging.getLogger(__name__)


async def run_web_bridge(ctx: PipelineContext) -> bool:
    """执行 Web Bridge — web_redteam 认证 + 侦察 + 桥接到主流水线。

    在 main.py 的 Stage 0.5 之前调用, 当 ``--web-bridge`` 启用时:

    1. 从 web_redteam 执行浏览器/API 认证
    2. 提取认证状态 (Cookie/Token/headers)
    3. 自动探测目标能力 (Agent/RAG/MCP/Embedding)
    4. 生成简化侦察报告注入 ctx.metadata
    5. 创建 HTTPTarget/PlaywrightTarget 并注册到 TargetRegistry

    Args:
        ctx: PipelineContext (需要 args.target_url)

    Returns:
        True 如果桥接成功, False 如果失败或不需要。
    """
    target_url = getattr(ctx.args, "target_url", None)
    if not target_url:
        return False

    # v43: --web-bridge 已废弃, 委托到 stage_target_classify 统一入口
    # stage_target_classify.run() 现已内置完整链路:
    #   判别 → 认证 → 桥接 → 注册到 TargetRegistry → 主流水线 17 种攻击
    logger.info(
        "v43: --web-bridge is deprecated. Delegating to stage_target_classify.run() "
        "which now handles the full pipeline (classify → auth → bridge → 17 techniques + ASR)."
    )
    from pipeline.stages.stage_target_classify import run as _stage_target_classify

    return await _stage_target_classify(ctx)

    trace = DecisionTrace.get_instance()
    bus = EventBus.get_instance()

    # Step 1: 目标类型判别 (复用 TargetClassifier)
    from pipeline.integrations.target_classifier import TargetClassifier

    classifier = TargetClassifier()
    target_type_override = getattr(ctx.args, "target_type", "auto")
    classification = await classifier.classify(
        target_url,
        force_type=target_type_override,
    )

    print(f"  判别结果: {classification.target_type}")
    print(f"  推荐模式: {classification.recommended_mode}")
    print(f"  依据: {classification.detection_reason}")

    trace.record(
        stage="web_bridge",
        layer="target_detection",
        decision=f"bridged_as_{classification.target_type}",
        reason=classification.detection_reason,
        target_url=target_url,
        recommended_mode=classification.recommended_mode,
    )

    ctx.metadata["target_classification"] = classification
    ctx.metadata["target_type"] = classification.target_type
    ctx.metadata["recommended_mode"] = classification.recommended_mode

    # Step 2: 执行认证
    auth_state = await _authenticate(ctx, target_url, classification)
    if auth_state is None:
        print("  [警告] 认证失败, 降级为无认证模式")
        auth_state = AuthState(
            auth_type="none",
            target_url=target_url,
            source="web_bridge",
        )
    else:
        print(f"  认证类型: {auth_state.auth_type}")
        print(f"  认证来源: {auth_state.source}")
        if auth_state.mfa_required:
            print(f"  MFA 类型: {auth_state.mfa_types}")

    # Step 3: 注入认证状态到主流水线
    inject_auth_state_to_context(ctx, auth_state)

    # 导出认证状态文件 (供后续运行复用)
    auth_file = export_auth_state(auth_state)
    ctx.metadata["auth_state_file"] = str(auth_file)
    print(f"  认证状态已导出: {auth_file}")

    bus.publish_simple(
        "web_bridge", "auth_completed",
        auth_type=auth_state.auth_type,
        mfa_required=auth_state.mfa_required,
    )

    # Step 4: 自动探测目标能力 (生成简化侦察报告)
    recon_report = await _probe_capabilities(ctx, target_url, auth_state, classification)
    if recon_report:
        ctx.metadata["recon_result"] = recon_report
        ctx.metadata["web_bridge_recon"] = True
        print("  侦察报告已生成 (web_bridge 自动探测)")

        # 提取能力标志
        capability = extract_capability(recon_report)
        ctx.metadata["recon_capability"] = capability
        print(f"  能力: agent={capability.has_agent_tools}, rag={capability.has_rag_endpoints}, "
              f"mcp={capability.has_mcp}, embedding={capability.has_embedding}")

        trace.record(
            stage="web_bridge",
            layer="capability_probe",
            decision="capabilities_detected",
            agent=capability.has_agent_tools,
            rag=capability.has_rag_endpoints,
            mcp=capability.has_mcp,
            embedding=capability.has_embedding,
        )

    # Step 5: 创建 Target 并注册到 TargetRegistry
    target_created = await _create_and_register_target(
        ctx, target_url, classification, auth_state
    )
    if not target_created:
        print("  [错误] Target 创建失败")
        return False

    # Step 6: 认证 header 注入到 ctx.metadata (供 recon_target_bridge 使用)
    auth_headers = auth_state.to_auth_headers()
    if auth_headers:
        ctx.metadata["auth_headers"] = auth_headers

    print("\n  [Web Bridge] 桥接完成 — 主流水线将使用桥接后的 Target 执行完整攻击")
    print(f"    Target 类型: {classification.target_type}")
    print(f"    认证: {auth_state.auth_type}")
    print(f"    侦察: {'已生成' if recon_report else '无'}")
    print("    攻击技术: 17 种原生 PyRIT 技术 (ASR 驱动)")

    return True


async def _authenticate(
    ctx: PipelineContext,
    target_url: str,
    classification: Any,
) -> AuthState | None:
    """执行认证流程 (复用 web_redteam/auth/ 模块)。

    根据 target_type 选择认证方式:
      - llm_web_app → 浏览器认证 (Playwright + AuthStrategy)
      - llm_api_platform → API 认证 (Bearer/OAuth2 from .env or --api-key)
    """
    # 尝试复用已有认证状态
    auth_state_file = getattr(ctx.args, "auth_state_file", None)
    if auth_state_file:
        from pipeline.integrations.auth_state_bridge import import_auth_state

        existing = import_auth_state(Path(auth_state_file))
        if existing and existing.is_valid():
            print(f"  [认证] 复用已有认证状态: {auth_state_file}")
            existing.source = "reused"
            return existing

    if classification.target_type == "llm_web_app":
        return await _browser_auth(ctx, target_url)
    elif classification.target_type == "llm_api_platform":
        return _api_auth(ctx, target_url)
    else:
        # unknown — 尝试 API 认证 (更安全)
        return _api_auth(ctx, target_url)


async def _browser_auth(
    ctx: PipelineContext,
    target_url: str,
) -> AuthState | None:
    """浏览器认证 — 复用 web_redteam 的 Playwright 认证流程。"""
    try:
        from web_redteam.auth.auth_strategy import AuthStrategyFactory
        from web_redteam.auth.browser_session import BrowserSession
        from web_redteam.targets.dynamic_profile import create_profile_from_url

        print("\n  --- 浏览器认证 (Playwright) ---")

        # 创建动态 Profile
        profile = create_profile_from_url(
            target_url=target_url,
            attack_type="prompt_sending",
            objective="Probe",
            max_turns=1,
        )

        # 启动浏览器
        session = BrowserSession()
        headless = getattr(ctx.args, "web_headless", False)
        cdp_port = getattr(ctx.args, "cdp_port", 9222)

        page = await session.launch_with_debug_port(
            port=cdp_port,
            headless=headless,
        )

        # 执行认证
        strategy = AuthStrategyFactory.create(profile.auth.type)
        mfa_timeout = getattr(ctx.args, "mfa_timeout", 300)
        if hasattr(strategy, "_human_auth"):
            strategy._human_auth.mfa_timeout = mfa_timeout  # type: ignore[attr-defined]

        page = await strategy.execute(page, profile)

        # 提取认证状态
        from datetime import datetime, timezone

        cookies = []
        with contextlib.suppress(Exception):
            cookies = await page.context.cookies()

        # 提取 storage_state
        storage_state_path = ""
        try:
            import tempfile

            storage_state_path = str(
                Path(tempfile.gettempdir()) / "web_bridge_storage_state.json"
            )
            await page.context.storage_state(path=storage_state_path)
        except Exception:
            pass

        auth_state = AuthState(
            auth_type=profile.auth.type,
            target_url=target_url,
            login_url=getattr(profile.auth, "login_url", ""),
            cookies=cookies,
            storage_state_path=storage_state_path,
            source="web_bridge",
            authenticated_at=datetime.now(timezone.utc).isoformat(),
        )

        # 存储浏览器会话到 ctx (供后续 PlaywrightTarget 使用)
        ctx.metadata["web_browser_session"] = session
        ctx.metadata["web_target_profile"] = profile
        ctx.metadata["web_target_url"] = target_url
        ctx.metadata["web_bridge_page"] = page

        # G1: 不关闭浏览器 — 保留 page 供后续 PlaywrightTarget 直接使用
        # 认证状态已提取 (cookies + storage_state), 但 page 仍需保持活跃
        # 浏览器会由 main.py 的 _cleanup_web_session() 在 finally 块中关闭
        # 学术依据: OWASP ASVS V2.4 — 认证验证应最小化重复
        print(f"  [认证] 浏览器认证成功 (cookies={len(cookies)})")
        return auth_state

    except Exception as e:
        logger.error(f"Browser auth failed: {e}", exc_info=True)
        print(f"  [认证错误] 浏览器认证失败: {e}")
        return None


def _api_auth(
    ctx: PipelineContext,
    target_url: str,
) -> AuthState | None:
    """API 认证 — 从 .env / --api-key / 环境变量提取认证信息。"""
    from datetime import datetime, timezone

    headers: dict[str, str] = {}

    # 优先级: --api-key > .env OPENAI_CHAT_KEY > .env API_KEY > 无认证
    api_key = (
        getattr(ctx.args, "api_key", None)
        or os.environ.get("OPENAI_CHAT_KEY", "")
        or os.environ.get("API_KEY", "")
    )

    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    # 从 .env 获取 model
    model_name = os.environ.get("OPENAI_CHAT_MODEL", "")

    auth_state = AuthState(
        auth_type="bearer" if api_key else "none",
        target_url=target_url,
        headers=headers,
        source="web_bridge",
        authenticated_at=datetime.now(timezone.utc).isoformat(),
    )

    print(f"  [认证] API 认证: type={auth_state.auth_type}, has_key={bool(api_key)}")
    if model_name:
        ctx.metadata["web_bridge_model_name"] = model_name
        print(f"  [认证] 模型: {model_name}")

    return auth_state


async def _probe_capabilities(
    ctx: PipelineContext,
    target_url: str,
    auth_state: AuthState,
    classification: Any,
) -> Any | None:
    """自动探测目标能力 — 生成简化侦察报告。

    通过发送探针请求探测:
      1. 目标是否为 Agent (有工具调用能力)
      2. 目标是否有 RAG (检索增强)
      3. 目标是否有 MCP (Model Context Protocol)
      4. 目标是否有 Embedding
      5. 目标模型名称

    使用 SimpleNamespace 兼容 recon_strategy_bridge.extract_capability。
    """
    from types import SimpleNamespace

    # 发送探针请求探测目标能力
    probe_result = await _send_capability_probe(target_url, auth_state, classification)

    if probe_result is None:
        # 探测失败 — 生成最小侦察报告
        return SimpleNamespace(
            target_url=target_url,
            has_agent_tools=False,
            has_rag_endpoints=False,
            has_mcp=False,
            has_embedding=False,
            endpoints=[],
            injection_surfaces=[{"type": "user_message"}],
            recommendations=[],
        )

    # 从探针响应中提取能力信息
    response_text = probe_result.get("response_text", "")
    model_name = probe_result.get("model_name", "")

    # 存储模型名称
    if model_name:
        ctx.metadata["web_bridge_model_name"] = model_name

    # P1-S3: 存储发现的响应路径 (供 APITargetConfig 使用)
    discovered_path = probe_result.get("response_path", "")
    if discovered_path and discovered_path != "choices[0].message.content":
        ctx.metadata["web_bridge_response_path"] = discovered_path
        print(f"  [P1-S3] 非标准响应路径: {discovered_path}")

    # 基于响应内容推断能力
    has_agent = _detect_agent_capability(response_text)
    has_rag = _detect_rag_capability(response_text)
    has_mcp = _detect_mcp_capability(response_text)
    has_embedding = _detect_embedding_capability(response_text)

    # 构建端点信息
    endpoints = [
        SimpleNamespace(
            url=target_url,
            method="POST",
            headers={},
            body="",
            content_type="application/json",
        )
    ]

    # 构建注入面
    injection_surfaces = [{"type": "user_message"}]
    if has_agent:
        injection_surfaces.append({"type": "tool_output"})
    if has_rag:
        injection_surfaces.append({"type": "rag_document"})
    if has_mcp:
        injection_surfaces.append({"type": "mcp_resource"})

    # 构建推荐
    recommendations = _build_recommendations(has_agent, has_rag, has_mcp)

    report = SimpleNamespace(
        target_url=target_url,
        has_agent_tools=has_agent,
        has_rag_endpoints=has_rag,
        has_mcp=has_mcp,
        has_embedding=has_embedding,
        endpoints=endpoints,
        injection_surfaces=injection_surfaces,
        recommendations=recommendations,
        model_name=model_name,
    )

    return report


async def _send_capability_probe(
    target_url: str,
    auth_state: AuthState,
    classification: Any,
) -> dict[str, Any] | None:
    """发送能力探测探针请求。

    发送一个简单的 prompt, 从响应中推断目标能力。
    """
    import os

    probe_prompt = (
        "Hello, what tools and capabilities do you have? "
        "Are you connected to any external tools, knowledge bases, or databases?"
    )

    # G5: SSL 验证可配置 — 企业内网自签证书场景支持
    # --web-bridge-ssl-verify 或 WEB_BRIDGE_SSL_VERIFY=true 启用
    # 默认 False (兼容性优先, 与原行为一致)
    ssl_verify = os.environ.get("WEB_BRIDGE_SSL_VERIFY", "").lower() in ("true", "1", "yes")

    try:
        import aiohttp

        headers = {"Content-Type": "application/json"}
        headers.update(auth_state.to_auth_headers())

        # 构建请求体 — 尝试多种格式
        body_templates = [
            # OpenAI 格式
            json.dumps({
                "model": "default",
                "messages": [{"role": "user", "content": probe_prompt}],
            }),
            # 简单格式
            json.dumps({"message": probe_prompt}),
            # 通用格式
            json.dumps({"input": probe_prompt}),
        ]

        for body in body_templates:
            try:
                async with aiohttp.ClientSession() as session, session.post(
                    target_url,
                    headers=headers,
                    data=body,
                    timeout=aiohttp.ClientTimeout(total=15),
                    ssl=ssl_verify,
                ) as response:
                    if response.status == 200:
                        resp_text = await response.text()
                        resp_json = {}
                        with contextlib.suppress(json.JSONDecodeError, TypeError):
                            resp_json = json.loads(resp_text)

                        # 提取模型名称
                        model_name = (
                            resp_json.get("model", "")
                            or resp_json.get("model_name", "")
                            or _extract_model_from_response(resp_json)
                        )

                        # 提取响应文本
                        response_text = (
                            _extract_response_text(resp_json)
                            or resp_text[:2000]
                        )

                        # P1-S3: 自动发现响应路径
                        discovered_path = discover_response_path(resp_json) if resp_json else ""
                        if discovered_path:
                            logger.info(f"P1-S3: Discovered response path: {discovered_path}")

                        return {
                            "response_text": response_text,
                            "model_name": model_name,
                            "status": response.status,
                            "response_path": discovered_path,
                        }

            except Exception:
                continue

        # 所有格式都失败
        logger.debug("Capability probe: all body formats failed")
        return None

    except ImportError:
        # aiohttp 不可用 — 降级
        logger.debug("aiohttp not available for capability probe")
        return None
    except Exception as e:
        logger.debug(f"Capability probe failed: {e}")
        return None


# 响应路径候选列表 (按优先级排序)
# 用于自动发现非标准 API 的响应路径
_RESPONSE_PATH_CANDIDATES: list[str] = [
    "choices[0].message.content",  # OpenAI 格式
    "choices[0].text",             # OpenAI legacy completions
    "response",
    "output",
    "answer",
    "text",
    "result",
    "content",
    "data.content",
    "data.text",
    "data.message",
    "data.response",
    "data.output",
    "message",
    "reply",
    "generation",
    "generated_text",
]


def discover_response_path(resp_json: dict) -> str:
    """自动发现 JSON 响应中的文本内容路径 (P1-S3)。

    当非标准 API 不使用 OpenAI 格式时, 自动遍历 JSON 树
    找到包含文本内容的路径。

    策略:
      1. 按候选路径列表尝试 (覆盖常见格式)
      2. 深度优先搜索 JSON 树, 找到第一个字符串值
      3. 返回点分隔的路径 (如 "data.choices[0].message.content")

    Args:
        resp_json: JSON 响应字典。

    Returns:
        响应路径字符串 (点分隔), 如未找到返回空字符串。
    """
    if not isinstance(resp_json, dict):
        return ""

    # 策略 1: 按候选路径列表尝试
    for path in _RESPONSE_PATH_CANDIDATES:
        if _try_path(resp_json, path):
            return path

    # 策略 2: 深度优先搜索
    found_path = _dfs_find_string(resp_json, max_depth=5)
    return found_path


def _try_path(data: Any, path: str) -> bool:
    """尝试沿路径提取值, 返回是否能找到字符串值。"""
    import re

    current: Any = data
    for part in path.split("."):
        if not part:
            continue
        match = re.match(r"^(\w+)\[(\d+)\]$", part)
        if match:
            attr, idx = match.groups()
            try:
                current = current[attr][int(idx)]
            except (KeyError, IndexError, TypeError):
                return False
        else:
            try:
                current = current[part]
            except (KeyError, TypeError):
                return False

    return isinstance(current, str) and len(current) > 0


def _dfs_find_string(data: Any, max_depth: int = 5, current_path: str = "", depth: int = 0) -> str:
    """深度优先搜索 JSON 树, 找到第一个有意义的字符串值。"""
    if depth >= max_depth:
        return ""

    if isinstance(data, str):
        if len(data) > 5:  # 过滤掉短字符串 (如 "ok", "true")
            return current_path if current_path else ""
        return ""

    if isinstance(data, dict):
        for key, value in data.items():
            new_path = f"{current_path}.{key}" if current_path else key
            result = _dfs_find_string(value, max_depth, new_path, depth + 1)
            if result:
                return result

    if isinstance(data, list) and data:
        new_path = f"{current_path}[0]" if current_path else "[0]"
        result = _dfs_find_string(data[0], max_depth, new_path, depth + 1)
        if result:
            return result

    return ""


def _extract_response_text(resp_json: dict) -> str:
    """从 JSON 响应中提取文本 (多路径尝试 + 自动发现)。"""
    # OpenAI 格式
    try:
        return resp_json["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError):
        pass

    # 常见替代格式
    for key in ("response", "output", "answer", "text", "result", "content"):
        if key in resp_json:
            val = resp_json[key]
            if isinstance(val, str):
                return val
            if isinstance(val, dict):
                # 嵌套: {"response": {"text": "..."}}
                for sub_key in ("text", "content", "message", "output"):
                    if sub_key in val:
                        return str(val[sub_key])

    # data 嵌套
    if "data" in resp_json:
        data = resp_json["data"]
        if isinstance(data, str):
            return data
        if isinstance(data, dict):
            for key in ("content", "text", "message", "response"):
                if key in data:
                    return str(data[key])

    return ""


def _extract_model_from_response(resp_json: dict) -> str:
    """从响应 JSON 中提取模型名称。"""
    for key in ("model", "model_name", "engine"):
        if key in resp_json:
            return str(resp_json[key])

    # 嵌套在 data/meta 中
    for parent in ("data", "meta", "metadata"):
        if parent in resp_json and isinstance(resp_json[parent], dict):
            for key in ("model", "model_name", "engine"):
                if key in resp_json[parent]:
                    return str(resp_json[parent][key])

    return ""


def _detect_agent_capability(response_text: str) -> bool:
    """从响应中检测 Agent 工具调用能力。"""
    text_lower = response_text.lower()
    agent_keywords = [
        "tool", "function call", "agent", "assistant tool",
        "i can use", "i have access to", "i'm able to",
        "我能使用", "我可以调用", "工具", "函数调用",
    ]
    return any(kw in text_lower for kw in agent_keywords)


def _detect_rag_capability(response_text: str) -> bool:
    """从响应中检测 RAG 能力。."""
    text_lower = response_text.lower()

    # 否定上下文检测 — "I don't have any database access" 不应匹配
    negation_patterns = [
        "don't have", "doesn't have", "not have", "no access to",
        "cannot access", "no knowledge base", "without",
        "无法访问", "没有", "不包含",
    ]
    if any(neg in text_lower for neg in negation_patterns):
        return False

    rag_keywords = [
        "retrieval", "knowledge base", "document", "search",
        "rag", "vector", "embedding", "database",
        "知识库", "文档检索", "向量",
    ]
    return any(kw in text_lower for kw in rag_keywords)


def _detect_mcp_capability(response_text: str) -> bool:
    """从响应中检测 MCP 能力。"""
    text_lower = response_text.lower()
    mcp_keywords = [
        "mcp", "model context protocol", "context server",
        "resource", "resource provider",
    ]
    return any(kw in text_lower for kw in mcp_keywords)


def _detect_embedding_capability(response_text: str) -> bool:
    """从响应中检测 Embedding 能力。"""
    text_lower = response_text.lower()
    embedding_keywords = [
        "embedding", "vectorize", "vector representation",
        "semantic search", "similarity",
    ]
    return any(kw in text_lower for kw in embedding_keywords)


def _build_recommendations(
    has_agent: bool,
    has_rag: bool,
    has_mcp: bool,
) -> list[Any]:
    """基于探测到的能力构建攻击推荐。"""
    from types import SimpleNamespace

    recs: list[Any] = []

    # 始终推荐 prompt injection
    recs.append(SimpleNamespace(
        owasp_id="LLM01",
        attack_strategy="prompt_sending",
        priority=1,
        rationale="Direct prompt injection via chat endpoint",
        target_type="llm_api",
    ))

    if has_agent:
        recs.append(SimpleNamespace(
            owasp_id="LLM06",
            attack_strategy="red_teaming",
            priority=2,
            rationale="Agent tool hijack via multi-turn",
            target_type="agent",
        ))

    if has_rag:
        recs.append(SimpleNamespace(
            owasp_id="LLM08",
            attack_strategy="many_shot",
            priority=3,
            rationale="RAG document poisoning via indirect injection",
            target_type="rag",
        ))

    if has_mcp:
        recs.append(SimpleNamespace(
            owasp_id="LLM07",
            attack_strategy="pair",
            priority=4,
            rationale="MCP resource injection via supply chain",
            target_type="mcp",
        ))

    # 始终推荐 skeleton_key
    recs.append(SimpleNamespace(
        owasp_id="LLM02",
        attack_strategy="skeleton_key",
        priority=5,
        rationale="Sensitive information disclosure via skeleton key",
        target_type="llm_api",
    ))

    return recs


async def _create_and_register_target(
    ctx: PipelineContext,
    target_url: str,
    classification: Any,
    auth_state: AuthState,
) -> bool:
    """创建 Target 并注册到 TargetRegistry。

    复用 stage_target_classify 的 _bridge_api_platform / _bridge_web_app,
    但注入 web_bridge 提取的认证状态。
    """
    # 注入认证 headers 到 ctx.metadata (供 recon_target_bridge 使用)
    auth_headers = auth_state.to_auth_headers()
    if auth_headers:
        ctx.metadata["auth_headers"] = auth_headers
        ctx.metadata["auth_type"] = auth_state.auth_type

    if classification.target_type == "llm_api_platform":
        return await _create_api_target(ctx, target_url, classification, auth_state)
    elif classification.target_type == "llm_web_app":
        return await _create_browser_target(ctx, target_url, classification, auth_state)
    else:
        # unknown — 默认 API 模式
        return await _create_api_target(ctx, target_url, classification, auth_state)


async def _create_api_target(
    ctx: PipelineContext,
    target_url: str,
    classification: Any,
    auth_state: AuthState,
) -> bool:
    """API 模式: 创建 HTTPTarget + RateLimitedTarget (注入认证 headers)。

    复用 stage_target_classify._bridge_api_platform 的已验证模式,
    但在创建 APITargetConfig 后注入 web_bridge 提取的认证 headers。
    """
    from pyrit.prompt_target import HTTPTarget
    from pyrit.prompt_target.http_target import (
        get_http_target_json_response_callback_function,
    )

    from pipeline.targets.rate_limited_target import RateLimitedTarget
    from web_redteam.targets.api_config import APITargetConfig

    print("\n  --- Target 创建 (HTTPTarget + Web Bridge 认证注入) ---")

    # 1. 从 URL 自动构建 API 配置 (复用已验证的 APITargetConfig.from_url)
    api_key = auth_state.to_auth_headers().get("Authorization", "")
    if api_key.startswith("Bearer "):
        api_key = api_key[7:]

    model_name = (
        ctx.metadata.get("web_bridge_model_name", "")
        or None
    )

    config = APITargetConfig.from_url(
        target_url,
        api_key=api_key or None,
        model_name=model_name,
        max_rpm=getattr(ctx.args, "rate_limit", None),
    )

    # 2. 注入 web_bridge 提取的额外认证 headers
    auth_headers = auth_state.to_auth_headers()
    for k, v in auth_headers.items():
        if k.lower() not in ("content-type", "content-length"):
            config.headers[k] = v

    # P1-S3: 覆盖响应路径 (如果探测到非标准路径)
    discovered_path = ctx.metadata.get("web_bridge_response_path", "")
    if discovered_path and discovered_path != config.response_json_path:
        config.response_json_path = discovered_path
        print(f"    [P1-S3] 响应路径覆盖: {discovered_path}")

    print(f"    URL: {config.url}")
    print(f"    模型: {config.model_name}")
    print(f"    认证: {auth_state.auth_type}")
    print(f"    响应路径: {config.response_json_path}")
    print(f"    最大并发: {config.max_concurrency}")

    # 3. 构建回调函数 (PyRIT 原生)
    callback = get_http_target_json_response_callback_function(
        key=config.response_json_path,
    )

    # 4. 构建 HTTPTarget (复用 stage_target_classify._build_raw_http_request)
    from pipeline.stages.stage_target_classify import _build_raw_http_request

    raw_request = _build_raw_http_request(config)
    http_target = HTTPTarget(
        http_request=raw_request,
        prompt_regex_string="{PROMPT}",
        callback_function=callback,
    )

    # 5. 使用 RateLimitedTarget 包装
    rate_limited_target = RateLimitedTarget(
        target=http_target,
        endpoint=config.url,
        max_concurrency=config.max_concurrency,
        max_retries=config.max_retries,
        requests_per_minute=config.max_rpm,
    )

    # 6. 注册到 TargetRegistry
    from pyrit.registry import TargetRegistry

    registry = TargetRegistry.get_registry_singleton()
    registry.instances.register(
        instance=rate_limited_target,
        name="web_bridge_target",
        tags={"target_type": "HTTPTarget"},
    )
    registry.instances.register(
        instance=rate_limited_target,
        name="default",
        tags={"target_type": "HTTPTarget"},
    )

    ctx.metadata["api_target_config"] = config
    ctx.metadata["api_target_url"] = target_url
    ctx.metadata["web_bridge_model_name"] = config.model_name
    ctx.target_type = "http_api"
    ctx.http_target_configured = True

    print("  ✓ HTTPTarget + RateLimitedTarget 已创建并注册")
    return True


async def _create_browser_target(
    ctx: PipelineContext,
    target_url: str,
    classification: Any,
    auth_state: AuthState,
) -> bool:
    """Browser 模式: 创建 PlaywrightTarget (注入认证 cookies/storage_state)。

    复用 stage_target_classify._bridge_web_app 的已验证模式,
    但在创建 BrowserSession 后注入 web_bridge 提取的认证状态。
    """
    print("\n  --- Target 创建 (PlaywrightTarget + Web Bridge 认证注入) ---")

    from pyrit.prompt_target import PlaywrightTarget

    from web_redteam.auth.browser_session import BrowserSession
    from web_redteam.interaction.interaction_factory import InteractionFactory
    from web_redteam.targets.dynamic_profile import create_profile_from_url

    # 1. 重新打开浏览器
    session = BrowserSession()
    headless = getattr(ctx.args, "web_headless", False)
    cdp_port = getattr(ctx.args, "cdp_port", 9222)

    # 2. 优先使用 storage_state 恢复 (更完整)
    if auth_state.storage_state_path and Path(auth_state.storage_state_path).exists():
        page = await session.restore_storage_state(auth_state.storage_state_path)
        print(f"    Storage state 恢复: {auth_state.storage_state_path}")
    else:
        page = await session.launch_with_debug_port(
            port=cdp_port,
            headless=headless,
        )

        # 注入 cookies
        if auth_state.cookies:
            try:
                await page.context.add_cookies(auth_state.cookies)
                print(f"    Cookies 注入: {len(auth_state.cookies)} 个")
            except Exception as e:
                logger.warning(f"Cookie injection failed: {e}")

    # 3. 导航到目标 URL
    await page.goto(target_url, wait_until="domcontentloaded")

    # 4. 创建 Profile (复用 stage_target_classify._load_or_create_profile 逻辑)
    profile = create_profile_from_url(
        target_url=target_url,
        attack_type=getattr(ctx.args, "scenario", "prompt_sending"),
        objective=getattr(ctx.args, "objective", "Ignore all previous instructions"),
        max_turns=getattr(ctx.args, "max_turns", 5),
    )

    # 5. 创建 PlaywrightTarget (PyRIT 原生)
    interaction_func = InteractionFactory.create(profile.interaction)

    playwright_target = PlaywrightTarget(
        interaction_func=interaction_func,
        page=page,
        max_requests_per_minute=getattr(ctx.args, "rate_limit", None),
    )

    # 6. 注册到 TargetRegistry
    from pyrit.registry import TargetRegistry

    registry = TargetRegistry.get_registry_singleton()
    registry.instances.register(
        instance=playwright_target,
        name="web_bridge_target",
        tags={"target_type": "PlaywrightTarget"},
    )
    registry.instances.register(
        instance=playwright_target,
        name="default",
        tags={"target_type": "PlaywrightTarget"},
    )

    ctx.metadata["web_browser_session"] = session
    ctx.metadata["web_target_url"] = target_url
    ctx.metadata["web_target_profile"] = profile
    ctx.target_type = "playwright"

    print(f"    输入选择器: {profile.interaction.input.selector}")
    print(f"    发送选择器: {profile.interaction.send.selector}")
    print(f"    响应选择器: {profile.interaction.response.selector}")
    print("  ✓ PlaywrightTarget 已创建并注册")
    return True


def _infer_model_name(url: str) -> str:
    """从 API URL 推断模型名称 (仅供 web_bridge 内部使用)。"""
    from urllib.parse import urlparse

    domain = urlparse(url).netloc or "unknown"
    return domain.replace(".", "_").replace(":", "_")
