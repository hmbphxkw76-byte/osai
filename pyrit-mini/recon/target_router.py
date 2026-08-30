# arXiv:2402.12109 — Russinovich et al., Crescendo
# arXiv:2402.19181 — Zeng et al., Persuasion
# arXiv:2407.01232 — PyRIT, framework foundation
"""目标路由 — 纯黑盒 Burp 场景。

唯一路径:
    Burp 请求 → 解析 → 探测响应路径 → 构建 HTTPTarget → RateLimitedTarget 包装

辅助角色:
    - adversarial_target: 从 .env 读取 (用户自己的 LLM API)
    - scoring_target: 从 .env 读取或复用 adversarial
"""

from __future__ import annotations

import logging
import os
from typing import Any

from core.context import PipelineContext
from recon.burp_parser import (
    build_http_target,
    parse_burp_request,
    probe_active_capabilities,
    probe_response_path,
)
from targets.rate_limited import RateLimitedTarget

logger = logging.getLogger(__name__)


async def create_target(ctx: PipelineContext) -> None:
    """创建并注册攻击目标。

    路由逻辑:
        1. --browser-url → PlaywrightTarget (浏览器渲染 Chat UI, PyRIT 原生)
        2. --target-api-endpoint + --target-api-key → API 直连模式
           (L5 v52: OpenAIChatTarget / OpenAIResponseTarget 原生路由)
        3. --burp → Burp 模式 (HTTPTarget + RateLimitedTarget)
        4. --target-url + --api-key → API 直连模式 (HTTPTarget)
        5. 无参数 → .env 默认 (OpenAIChatTarget)

    L5 v38: 新增 PlaywrightTarget 路由 (PyRIT 原生优势)
        学术依据: PyRIT (arXiv:2407.01232) — PlaywrightTarget 是
        PyRIT 原生浏览器自动化 Target, 可攻击需要 JS 渲染的 Web Chat UI

    L5 v52: 新增 OpenAIChatTarget/OpenAIResponseTarget 原生路由
        学术依据: PyRIT (arXiv:2407.01232) — 原生 Target 支持:
        - OpenAIChatTarget: gpt-4o, gpt-4, DeepSeek, llama, phi-4, gpt-3.5
        - OpenAIResponseTarget: o1, o3, o4-mini, GPT-5 (Responses API)
        - 原生 RPM 限速: max_requests_per_minute 参数
        - 原生 JSON 输出: response_format + json_schema
        - 原生多模态: text + image_path 输入
        - 原生能力声明: TargetCapabilities 自动匹配模型

    流程:
        1. (新增) 如果 --browser-url 设置 → 创建 PlaywrightTarget
        2. (L5 v52) 如果 --target-api-endpoint 设置 → 创建原生 OpenAIChatTarget/OpenAIResponseTarget
        3. 解析 Burp 请求 → ParsedBurpRequest
        4. L5 v12: 目标可用性预检 (发送探针请求, 确保目标在线)
        5. 探测响应路径 (发送 "hi" 探针)
        6. 构建 HTTPTarget
        7. 包装 RateLimitedTarget (并发控制 + 重试)
        8. 创建 adversarial + scoring target (从 .env)

    Args:
        ctx: 流水线上下文。
    """
    # ── L5 v52: OpenAIChatTarget/OpenAIResponseTarget 原生路由 ──
    # 学术依据: PyRIT (arXiv:2407.01232) — 原生 Target 支持
    # OpenAIChatTarget: 支持 gpt-4o, DeepSeek, llama, phi-4 等 OpenAI 兼容模型
    # OpenAIResponseTarget: 支持 o1/o3/o4-mini/GPT-5 Responses API
    # 原生优势: RPM 限速, JSON 输出, 多模态输入, TargetCapabilities 自动匹配
    target_api_endpoint = getattr(ctx.args, "target_api_endpoint", None)
    target_api_key = getattr(ctx.args, "target_api_key", None)
    target_api_model = getattr(ctx.args, "target_api_model", None)
    target_api_type = getattr(ctx.args, "target_api_type", "chat")  # chat | responses

    # ── LiteLLM 多提供商路由 (对齐 PyRIT 1.0.1 LiteLLMChatTarget) ──
    # 学术依据: PyRIT (arXiv:2407.01232) — LiteLLMChatTarget 原生 Target
    # 通过 LiteLLM SDK 访问 100+ LLM 提供商 (Anthropic, Bedrock, Vertex 等)
    # 适配任意基于 LLM 开发的 Agent 目标, 提升 attack coverage 广度
    litellm_model = getattr(ctx.args, "litellm_model", None) or os.environ.get("LITELLM_MODEL")
    if litellm_model:
        logger.info(
            "LiteLLM mode — creating native LiteLLMChatTarget for %s",
            litellm_model,
        )
        await _create_litellm_target(ctx, model_name=litellm_model)
        # 仍需创建 adversarial + scoring target
        # 多 endpoint 模式: 跳过已存在的 target (复用, 避免资源泄漏)
        if ctx.adversarial_target is None:
            ctx.adversarial_target = _create_adversarial_target()
        if ctx.adversarial_target:
            logger.info("Adversarial target: %s", type(ctx.adversarial_target).__name__)
        if not ctx.extra_adversarial_targets:
            ctx.extra_adversarial_targets = _create_extra_adversarial_targets()
        if ctx.scoring_target is None:
            ctx.scoring_target = _create_scoring_target(ctx)
        if ctx.converter_target is None:
            ctx.converter_target = ctx.scoring_target or ctx.adversarial_target
        logger.info(
            "Targets configured: objective=%s, adversarial=%s, scorer=%s",
            type(ctx.objective_target).__name__,
            type(ctx.adversarial_target).__name__ if ctx.adversarial_target else "None",
            type(ctx.scoring_target).__name__ if ctx.scoring_target else "None",
        )
        return

    if target_api_endpoint and target_api_key:
        logger.info(
            "L5 v52: API direct mode — creating native %s for %s",
            "OpenAIResponseTarget" if target_api_type == "responses" else "OpenAIChatTarget",
            target_api_endpoint,
        )
        await _create_native_openai_target(
            ctx,
            endpoint=target_api_endpoint,
            api_key=target_api_key,
            model_name=target_api_model or "gpt-4o",
            api_type=target_api_type,
        )
        # 仍需创建 adversarial + scoring target
        # 多 endpoint 模式: 跳过已存在的 target (复用, 避免资源泄漏)
        if ctx.adversarial_target is None:
            ctx.adversarial_target = _create_adversarial_target()
        if ctx.adversarial_target:
            logger.info("Adversarial target: %s", type(ctx.adversarial_target).__name__)
        if not ctx.extra_adversarial_targets:
            ctx.extra_adversarial_targets = _create_extra_adversarial_targets()
        if ctx.scoring_target is None:
            ctx.scoring_target = _create_scoring_target(ctx)
        if ctx.converter_target is None:
            ctx.converter_target = ctx.scoring_target or ctx.adversarial_target
        logger.info(
            "Targets configured: objective=%s, adversarial=%s, scorer=%s",
            type(ctx.objective_target).__name__,
            type(ctx.adversarial_target).__name__ if ctx.adversarial_target else "None",
            type(ctx.scoring_target).__name__ if ctx.scoring_target else "None",
        )
        return

    # ── L5 v38: PlaywrightTarget 路由 (PyRIT 原生优势) ──
    # 学术依据: PyRIT (arXiv:2407.01232) — PlaywrightTarget 原生浏览器自动化
    browser_url = getattr(ctx.args, "browser_url", None)
    if browser_url:
        logger.info("L5 v38: Browser mode — creating PlaywrightTarget for %s", browser_url)
        await _create_playwright_target(ctx, browser_url)
        # 仍需创建 adversarial + scoring target
        # 多 endpoint 模式: 跳过已存在的 target (复用, 避免资源泄漏)
        if ctx.adversarial_target is None:
            ctx.adversarial_target = _create_adversarial_target()
        if ctx.adversarial_target:
            logger.info("Adversarial target: %s", type(ctx.adversarial_target).__name__)
        if not ctx.extra_adversarial_targets:
            ctx.extra_adversarial_targets = _create_extra_adversarial_targets()
        if ctx.scoring_target is None:
            ctx.scoring_target = _create_scoring_target(ctx)
        if ctx.converter_target is None:
            ctx.converter_target = ctx.scoring_target or ctx.adversarial_target
        logger.info(
            "Targets configured: objective=%s, adversarial=%s, scorer=%s",
            type(ctx.objective_target).__name__,
            type(ctx.adversarial_target).__name__ if ctx.adversarial_target else "None",
            type(ctx.scoring_target).__name__ if ctx.scoring_target else "None",
        )
        return
    # ── 解析 Burp 请求 ──
    parsed = parse_burp_request(ctx.args.burp)
    ctx.parsed_request = parsed
    ctx.model_name = f"HTTP:{parsed.host}{parsed.path}"

    # ── L5 v53: 将 Burp 提取的模型信息和原始 prompt 值传递到 ctx ──
    # 这些信息在侦察阶段从 Burp 文件中提取, 无需额外探测请求
    # 数据流: burp_parser → parsed_request → target_fingerprint → ctx
    if parsed.burp_model_name:
        # 如果 Burp 响应中有模型名称, 优先使用它
        ctx.model_name = parsed.burp_model_name
        parsed.target_fingerprint["burp_model_name"] = parsed.burp_model_name
        logger.info(
            "L5 v53: Model name from Burp response: %s",
            parsed.burp_model_name,
        )

    if parsed.burp_model_list:
        parsed.target_fingerprint["burp_model_list"] = "yes"
        logger.info(
            "L5 v53: Model list extracted from Burp response "
            "(length=%d chars)",
            len(parsed.burp_model_list),
        )

    if parsed.original_prompt_value:
        parsed.target_fingerprint["original_prompt"] = parsed.original_prompt_value[:200]
        logger.info(
            "L5 v53: Original prompt value from Burp request: %s",
            parsed.original_prompt_value[:80],
        )

    if parsed.api_category != "chat":
        logger.info(
            "L5 v53: Non-chat API detected (category=%s, path=%s) — "
            "model info extracted, {PROMPT} injection skipped",
            parsed.api_category,
            parsed.path,
        )

    # ── L5 v12: 目标可用性预检 ──
    # 学术依据: Heroux et al. (arXiv:2403.04206) — 超时恢复策略
    # 在攻击开始前检测目标是否在线, 避免浪费时间在不可达目标上。
    # 如果目标不可达 (连接拒绝/超时/402/503), 提前终止。
    target_available = await _check_target_availability(parsed)
    if not target_available:
        logger.error(
            "L5 v12: Target %s://%s%s is NOT available. Aborting pipeline.",
            "https" if parsed.use_tls else "http",
            parsed.host,
            parsed.path,
        )
        raise ConnectionError(
            f"Target {parsed.host}:{parsed.path} is not available. "
            "Please ensure the target service is running."
        )

    logger.info("L5 v12: Target availability check passed.")

    # ── 探测响应路径 ──
    logger.info("Probing response format...")
    try:
        await probe_response_path(parsed)
    except Exception as e:
        logger.warning("Response path probing failed (non-fatal): %s — using default", e)
    if parsed.response_json_path:
        logger.info("Response path detected: %s", parsed.response_json_path)
    else:
        logger.info("No response path detected, using default callback")

    # P2-20: 如果探针从响应中提取到了 chat_id, 记录日志
    if parsed.chat_id:
        logger.info("P2-20: Chat ID from probe/Burp response: %s", parsed.chat_id)
    elif parsed.has_chat_id_placeholder:
        logger.info(
            "P2-20: Chat ID field '%s' detected in body with {CHAT_ID} placeholder, "
            "will extract from first response",
            parsed.chat_id_field,
        )

    # ── 探针计数 & 耗时追踪 (P2-2 数据源) ──
    # 学术依据: PTES §2 — 情报收集阶段需记录探测元数据
    # _probe_count 追踪发送的探针请求总数, _probe_start 记录起始时间
    # 最终写入 target_fingerprint["probe_count"] 和 ["probe_duration_seconds"]
    # 数据流: target_router → target_fingerprint → recon_report → evidence
    import time as _time
    _probe_start = _time.monotonic()
    _probe_count = 0

    # ── 主动能力探测 (P1-7) ──
    # 学术依据: Greshake et al. (arXiv:2302.12173), Zhan et al. (arXiv:2307.00929)
    # 发送专门的探针 prompt 主动检测 Agent/MCP/RAG 能力
    # 比被动关键词匹配更可靠 — 目标被直接询问时会暴露更多能力
    logger.info("Probing active capabilities (agent/mcp/rag)...")
    try:
        active_caps = await probe_active_capabilities(parsed)
        _probe_count += 3  # probe_active_capabilities 发送 3 个探针 (agent_mcp, rag, model_identity)
        if active_caps:
            existing_caps = parsed.target_fingerprint.get("capabilities", "")
            all_caps = set(existing_caps.split(",")) if existing_caps else set()
            # model_family 是字符串, 不是布尔能力, 需单独处理
            for cap_key, cap_val in active_caps.items():
                if cap_key == "model_family" and cap_val:
                    parsed.target_fingerprint["model_family"] = cap_val
                    logger.info(
                        "P2-20: model_family from active probe: %s", cap_val,
                    )
                elif cap_val:
                    all_caps.add(cap_key)
            parsed.target_fingerprint["capabilities"] = ",".join(sorted(all_caps))
            logger.info("Active probe detected capabilities: %s", sorted(all_caps))
    except Exception as e:
        logger.warning("Active capability probing failed (non-fatal): %s — continuing without active caps", e)

    # ── P2-19: 通用深度能力探测 ──
    # 学术依据: Greshake et al. (arXiv:2302.12173) — 目标能力指纹
    # 对任意目标进行动态能力探测, 不依赖特定路径或 ID 约定
    try:
        from recon.capability_probe import deep_probe_capabilities
        deep_caps = await deep_probe_capabilities(parsed)
        _probe_count += 8  # deep_probe 发送 8 个并行探针 (含 model_identity)
        # R8-5 审计日志: deep_probe 内部还调用 probe_model_family_via_api (5 个端点)
        _probe_count += 5  # 模型列表端点探测
        if deep_caps:
            # 合并布尔能力到 capabilities 字段
            existing_caps_str = parsed.target_fingerprint.get("capabilities", "")
            all_caps = set(existing_caps_str.split(",")) if existing_caps_str else set()
            for cap_key in [
                "has_function_calling", "has_memory", "has_workflow",
                "has_multi_tenant", "has_session_auth", "has_mcp_protocol",
            ]:
                if deep_caps.get(cap_key):
                    # 转换 has_function_calling → function_calling
                    cap_name = cap_key.replace("has_", "")
                    all_caps.add(cap_name)
            parsed.target_fingerprint["capabilities"] = ",".join(sorted(all_caps))
            if deep_caps.get("secret_format"):
                parsed.target_fingerprint["secret_format"] = deep_caps["secret_format"]
            if deep_caps.get("tool_schemas"):
                parsed.target_fingerprint["tool_schemas"] = deep_caps["tool_schemas"]
            if deep_caps.get("session_type"):
                parsed.target_fingerprint["session_type"] = deep_caps["session_type"]
            # L5 v48: 写入置信度评分和触发建议到 target_fingerprint
            # 学术依据: Zheng et al. (arXiv:2306.05685) §4.3 — 置信度分级
            if deep_caps.get("capability_confidence"):
                parsed.target_fingerprint["capability_confidence"] = deep_caps["capability_confidence"]
            if deep_caps.get("capability_recommendations"):
                parsed.target_fingerprint["capability_recommendations"] = deep_caps["capability_recommendations"]
            # P2-20: 写入 model_family 到 target_fingerprint
            # 学术依据: Mazeika et al. (arXiv:2406.18510) — WILDTEAMING
            #   模型族→安全策略→种子定制, 不同模型族安全对齐策略不同
            if deep_caps.get("model_family"):
                parsed.target_fingerprint["model_family"] = deep_caps["model_family"]
                logger.info(
                    "P2-20: model_family from deep probe: %s",
                    deep_caps["model_family"],
                )
            # P1-4: 写入 model_ids 和 api_behavior (模型族 API 行为指纹)
            # 学术依据: Mazeika et al. (arXiv:2406.18510) — WILDTEAMING
            #   不依赖模型自报, 通过 API 行为特征识别模型族
            if deep_caps.get("model_ids"):
                parsed.target_fingerprint["model_ids"] = deep_caps["model_ids"]
            if deep_caps.get("api_behavior"):
                parsed.target_fingerprint["api_behavior"] = deep_caps["api_behavior"]
            logger.info(
                "P2-19: Deep capability probe complete. Capabilities: %s, secret_format: %s",
                sorted(all_caps),
                deep_caps.get("secret_format"),
            )
    except Exception as e:
        logger.warning("P2-19: Deep capability probing failed (non-fatal): %s", e)

    # ── MCP 端点枚举 (PyRIT 设计域边界: MCP JSON-RPC 例外) ──
    # 学术依据:
    #   - Anthropic MCP Specification (2024) §3.2 — tools/list, resources/list
    #   - Greshake et al. (arXiv:2302.12173) §4 — 间接注入利用工具信任
    #   - 课程 AI-300 Ch7.1 — "Extract detailed tool schemas through error-based enumeration"
    # 当能力探测检测到 MCP 能力时, 主动枚举 MCP Server 的 tools/resources/prompts
    # 枚举结果存入 target_fingerprint, 供后续 mcp_attack 种子精准注入使用
    capabilities_str = parsed.target_fingerprint.get("capabilities", "")
    if "mcp" in capabilities_str or "mcp_protocol" in capabilities_str:
        logger.info("MCP capability detected, launching MCP endpoint enumeration...")
        try:
            from recon.mcp_enumerator import enumerate_mcp_endpoint

            mcp_results = await enumerate_mcp_endpoint(parsed)
            if mcp_results.get("has_mcp"):
                # 将 MCP 枚举结果存入 target_fingerprint
                parsed.target_fingerprint["mcp_tools"] = mcp_results.get("tools", [])
                parsed.target_fingerprint["mcp_resources"] = mcp_results.get("resources", [])
                parsed.target_fingerprint["mcp_prompts"] = mcp_results.get("prompts", [])
                parsed.target_fingerprint["mcp_tool_names"] = mcp_results.get("tool_names", [])
                parsed.target_fingerprint["mcp_server_info"] = mcp_results.get("server_info")
                # P1-2: MCP 工具静态安全分析结果
                parsed.target_fingerprint["mcp_tool_safety"] = mcp_results.get("tool_safety", [])
                logger.info(
                    "MCP enumeration complete: %d tools, %d resources, %d prompts, %d safety findings",
                    len(mcp_results.get("tools", [])),
                    len(mcp_results.get("resources", [])),
                    len(mcp_results.get("prompts", [])),
                    sum(len(t.get("risks", [])) for t in mcp_results.get("tool_safety", [])),
                )
        except Exception as e:
            logger.warning("MCP endpoint enumeration failed (non-fatal): %s", e)
    else:
        logger.debug("No MCP capability detected, skipping MCP enumeration")

    # ── L5 v48: 认证状态管理 ──
    # 学术依据: Heroux et al. (arXiv:2403.04206) §3.2 — 认证失效恢复策略
    # 在构建 target 前检测认证类型, 初始化 AuthStateManager
    # 攻击执行中 401/403 时可自动尝试 token 刷新 / 租户切换 / 匿名降级
    auth_manager = None
    auth_state = None
    auth_refresh_enabled = getattr(ctx.args, "auth_refresh_enabled", True)
    if auth_refresh_enabled:
        from recon.auth_state_manager import AuthStateManager
        auth_manager = AuthStateManager(
            max_refreshes=getattr(ctx.args, "auth_refresh_max_retries", 3),
        )
        auth_state = await auth_manager.detect_auth_type(parsed)
        logger.info(
            "L5 v48: Auth state detected: type=%s, tenant=%s, csrf=%s",
            auth_state.auth_type,
            auth_state.tenant_id or "N/A",
            "yes" if auth_state.csrf_token else "no",
        )
        parsed.target_fingerprint["auth_type"] = auth_state.auth_type
        if auth_state.tenant_id:
            parsed.target_fingerprint["tenant_id"] = auth_state.tenant_id
        if auth_state.token_expiry:
            import time
            remaining = auth_state.token_expiry - time.time()
            logger.info(
                "Token expiry: %.0fs remaining (auto-refresh at %.0fs)",
                remaining,
                remaining - 60,
            )
            if remaining < 300:
                logger.warning(
                    "Token expires in <5 min — consider refreshing before attack",
                )

    # ── L5 v48: 跨端口端点发现 ──
    # 学术依据: Arbis et al. (arXiv:2306.01943) §4.5 — 跨端口端点发现
    # Agent 服务常部署在非标准端口 (3001, 8080, 11434 等)
    port_discovery_enabled = getattr(ctx.args, "port_discovery_enabled", True)
    if port_discovery_enabled:
        from recon.port_expander import discover_port_endpoints

        try:
            port_endpoints = await discover_port_endpoints(
                parsed,
                timeout=getattr(ctx.args, "port_discovery_timeout", 3.0),
                max_concurrent=getattr(ctx.args, "port_discovery_max_concurrent", 10),
                early_stop=getattr(ctx.args, "port_discovery_early_stop", 3),
            )
            if port_endpoints:
                logger.info(
                    "L5 v48: Port discovery found %d additional endpoints",
                    len(port_endpoints),
                )
                parsed.target_fingerprint["port_endpoints"] = [
                    {
                        "port": pe.port,
                        "path": pe.path,
                        "status_code": pe.status_code,
                        "service_type": pe.service_type,
                        "use_tls": pe.use_tls,
                    }
                    for pe in port_endpoints
                ]
        except Exception as e:
            logger.warning("L5 v48: Port discovery failed (non-fatal): %s", e)

    # ── OpenAPI/Swagger 文档发现 (P1-2) ──
    # 学术依据:
    #   - OWASP WSTG-INFO-05 — OpenAPI 文档发现
    #   - Arbis et al. (arXiv:2306.01943) §4.5 — API 端点发现
    #   - Zhan et al. (arXiv:2307.00929) §3.3 — 工具 schema 提取
    # 探测 /openapi.json, /swagger.json 等常见路径, 解析端点和参数 schema
    # 发现结果存入 target_fingerprint, 供 arm 阶段生成定向参数注入种子
    # 数据流: openapi_discoverer → target_fingerprint["openapi_endpoints"] → arm/seed_ranker
    openapi_enabled = getattr(ctx.args, "openapi_discovery_enabled", True)
    if openapi_enabled:
        try:
            from recon.openapi_discoverer import discover_openapi_spec

            openapi_result = await discover_openapi_spec(parsed)
            _probe_count += len(__import__(
                "recon.openapi_discoverer", fromlist=["_OPENAPI_PATHS"],
            )._OPENAPI_PATHS)
            if openapi_result and openapi_result.endpoints:
                parsed.target_fingerprint["openapi_spec_path"] = openapi_result.spec_path
                parsed.target_fingerprint["openapi_version"] = openapi_result.spec_version
                parsed.target_fingerprint["openapi_title"] = openapi_result.title
                parsed.target_fingerprint["openapi_endpoints"] = [
                    {
                        "path": ep.path,
                        "method": ep.method,
                        "summary": ep.summary,
                        "parameters": ep.parameters,
                        "has_auth": ep.has_auth,
                    }
                    for ep in openapi_result.endpoints
                ]
                parsed.target_fingerprint["openapi_security_schemes"] = openapi_result.security_schemes
                # 将 OpenAPI 发现的能力标记到 capabilities 字段
                existing_caps_str = parsed.target_fingerprint.get("capabilities", "")
                all_caps = set(existing_caps_str.split(",")) if existing_caps_str else set()
                all_caps.add("openapi")
                if openapi_result.security_schemes:
                    all_caps.add("openapi_auth")
                parsed.target_fingerprint["capabilities"] = ",".join(sorted(c for c in all_caps if c))
                logger.info(
                    "P1-2: OpenAPI spec found at %s (v%s, %d endpoints, %d security schemes)",
                    openapi_result.spec_path,
                    openapi_result.spec_version,
                    len(openapi_result.endpoints),
                    len(openapi_result.security_schemes),
                )
        except Exception as e:
            logger.warning("P1-2: OpenAPI discovery failed (non-fatal): %s", e)

    # ════════════════════════════════════════════════════════════════════
    # 深度探测能力补充 (P0-P2 优先级矩阵)
    # 学术依据:
    #   - Greshake et al. (arXiv:2302.12173) — system prompt 泄露探测
    #   - Morris et al. (arXiv:2310.06870) — 向量数据库确认
    #   - Cisco AI Defense — MCP 工具静态安全分析
    #   - Mazeika et al. (arXiv:2406.18510) — 模型族 API 行为指纹
    #   - Arbis et al. (arXiv:2306.01943) — 跨端点攻击面图谱
    # ════════════════════════════════════════════════════════════════════

    # ── P0-1: System Prompt 提取与泄露探测 ──
    # 数据流: system_prompt_extractor → target_fingerprint → arm/seed_ranker
    # 学术依据: Greshake et al. (arXiv:2302.12173) §4
    try:
        from recon.system_prompt_extractor import extract_system_prompt

        sp_result = await extract_system_prompt(parsed)
        _probe_count += 3  # 3 个并行探针
        if sp_result.get("system_prompt_leaked"):
            parsed.target_fingerprint["system_prompt_leaked"] = True
            parsed.target_fingerprint["extracted_system_prompt"] = sp_result.get(
                "extracted_system_prompt", ""
            )
            parsed.target_fingerprint["system_prompt_extraction_method"] = sp_result.get(
                "extraction_method", ""
            )
            parsed.target_fingerprint["system_prompt_length"] = sp_result.get(
                "system_prompt_length", 0
            )
            logger.warning(
                "P0-1: System prompt LEAKED via %s (length=%d)",
                sp_result.get("extraction_method"),
                sp_result.get("system_prompt_length", 0),
            )
        else:
            parsed.target_fingerprint["system_prompt_leaked"] = False
            logger.debug("P0-1: System prompt extraction: no leak detected")
    except Exception as e:
        logger.warning("P0-1: System prompt extraction failed (non-fatal): %s", e)
        parsed.target_fingerprint["system_prompt_leaked"] = False

    # ── P1-4: 模型族 API 行为指纹 (已在 capability_probe 中集成) ──
    # capability_probe.py 的 deep_probe_capabilities 已调用 probe_model_family_via_api
    # 结果已写入 parsed.target_fingerprint 中 (model_ids, api_behavior)
    # 这里只做日志确认
    model_ids = parsed.target_fingerprint.get("model_ids", [])
    if model_ids:
        logger.info(
            "P1-4: Model IDs from API behavior: %d models discovered",
            len(model_ids),
        )

    # ── P2-5: 向量数据库确认探测 ──
    # 数据流: port_expander.confirm_vector_dbs → target_fingerprint["vector_dbs"]
    # 学术依据: Morris et al. (arXiv:2310.06870)
    try:
        from recon.port_expander import confirm_vector_dbs

        # 复用之前 port_expander 发现的端点
        port_endpoints_data = parsed.target_fingerprint.get("port_endpoints", [])
        from recon.port_expander import DiscoveredPortEndpoint

        port_endpoints_list: list[DiscoveredPortEndpoint] = []
        for pe_data in port_endpoints_data:
            try:
                port_endpoints_list.append(DiscoveredPortEndpoint(
                    port=pe_data["port"],
                    path=pe_data.get("path", ""),
                    status_code=pe_data.get("status_code", 0),
                    service_type=pe_data.get("service_type", "unknown"),
                    use_tls=pe_data.get("use_tls", parsed.use_tls),
                ))
            except (KeyError, TypeError):
                continue

        _probe_count += len(port_endpoints_list) if port_endpoints_list else 7
        vdb_results = await confirm_vector_dbs(
            parsed,
            port_endpoints=port_endpoints_list if port_endpoints_list else None,
        )
        if vdb_results:
            parsed.target_fingerprint["vector_dbs"] = [
                {
                    "tech": vdb.tech,
                    "host": vdb.host,
                    "port": vdb.port,
                    "confirmed_via": vdb.confirmed_via,
                    "response_preview": vdb.response_preview,
                }
                for vdb in vdb_results
            ]
            logger.info(
                "P2-5: Vector DB confirmed: %d databases",
                len(vdb_results),
            )
        else:
            parsed.target_fingerprint["vector_dbs"] = []
    except Exception as e:
        logger.warning("P2-5: Vector DB confirmation failed (non-fatal): %s", e)
        parsed.target_fingerprint["vector_dbs"] = []

    # ── 探针计数 & 耗时写入 target_fingerprint (P2-2 数据完整化) ──
    # 数据流: target_router _probe_count → target_fingerprint → recon_report → evidence
    # recon_report.py 第 218-219 行读取这两个字段, 之前始终为 N/A
    _probe_duration = _time.monotonic() - _probe_start
    parsed.target_fingerprint["probe_count"] = _probe_count
    parsed.target_fingerprint["probe_duration_seconds"] = round(_probe_duration, 2)
    logger.info(
        "Recon probe summary: %d probes sent, %.2fs total duration",
        _probe_count,
        _probe_duration,
    )

    # ── 构建 HTTPTarget (单轮) ──
    target = build_http_target(parsed)

    # ── 包装 RateLimitedTarget ──
    target = RateLimitedTarget(
        target=target,
        max_concurrency=ctx.args.max_concurrency or 3,
        auth_state_manager=auth_manager,
        auth_state=auth_state,
    )
    ctx.objective_target = target

    # ── 构建多轮 HTTPTarget (用于 Crescendo/TAP 升级) ──
    # HTTPTarget 本身无状态，多轮通过在 prompt 中携带对话历史实现
    multi_turn_target = build_http_target(parsed, enable_multi_turn=True)
    multi_turn_target = RateLimitedTarget(
        target=multi_turn_target,
        max_concurrency=ctx.args.max_concurrency or 3,
    )
    ctx.multi_turn_target = multi_turn_target

    # ── L5 v48: 为跨端口发现的端点构建攻击 target ──
    # 学术依据: Arbis et al. (arXiv:2306.01943) §4.5 — 跨端口端点发现
    # 将 port_expander 发现的端点构建为独立的 HTTPTarget + RateLimitedTarget
    # 存入 ctx.extra_objective_targets 供后续攻击使用
    port_endpoints_data = parsed.target_fingerprint.get("port_endpoints", [])
    if port_endpoints_data:
        from recon.burp_parser import ParsedBurpRequest
        from recon.port_expander import build_port_parsed_request

        for pe_data in port_endpoints_data:
            try:
                # 构造 DiscoveredPortEndpoint 对象
                from recon.port_expander import DiscoveredPortEndpoint
                pe = DiscoveredPortEndpoint(
                    port=pe_data["port"],
                    path=pe_data["path"],
                    status_code=pe_data["status_code"],
                    service_type=pe_data.get("service_type", "unknown"),
                    use_tls=pe_data.get("use_tls", parsed.use_tls),
                )
                # 构建 ParsedBurpRequest 副本
                port_params = build_port_parsed_request(parsed, pe)
                port_parsed = ParsedBurpRequest(
                    method=port_params["method"],
                    url=f"{('https' if port_params['use_tls'] else 'http')}://{port_params['host']}:{port_params['port']}{port_params['path']}",
                    host=port_params["host"],
                    path=port_params["path"],
                    headers=port_params["headers"],
                    raw_headers=list(port_params["headers"].items()),
                    body="{}",
                    use_tls=port_params["use_tls"],
                    is_sse=False,
                    http_version=parsed.http_version,
                    has_prompt_placeholder=True,
                )
                port_target = build_http_target(port_parsed)
                if port_target:
                    port_target = RateLimitedTarget(
                        target=port_target,
                        max_concurrency=ctx.args.max_concurrency or 3,
                        auth_state_manager=auth_manager,
                        auth_state=auth_state,
                    )
                    ctx.extra_objective_targets[pe.port] = port_target
                    logger.info(
                        "L5 v48: Built target for port %d (%s) → %s",
                        pe.port, pe.service_type, port_params["path"],
                    )
            except Exception as e:
                logger.debug("Failed to build target for port %d: %s", pe_data.get("port"), e)

        logger.info(
            "L5 v48: %d extra objective targets built from port discovery",
            len(ctx.extra_objective_targets),
        )

    # ── 创建 adversarial target (用户自己的 LLM API) ──
    # 多 endpoint 模式: 如果 adversarial_target 已存在 (前一个 endpoint 创建),
    # 跳过重新创建以避免资源泄漏 (arXiv:2403.04206 §3.2)
    if ctx.adversarial_target is None:
        ctx.adversarial_target = _create_adversarial_target()
    if ctx.adversarial_target:
        logger.info("Adversarial target: %s", type(ctx.adversarial_target).__name__)

    # L5 v10: 加载额外 adversarial targets (多模型互补)
    # 多 endpoint 模式: 仅在首次创建时加载
    if not ctx.extra_adversarial_targets:
        extra_targets = _create_extra_adversarial_targets()
        if extra_targets:
            ctx.extra_adversarial_targets = extra_targets
            logger.info("Extra adversarial targets: %d", len(extra_targets))

    # ── 创建 scoring target (缺失时复用 adversarial) ──
    # 多 endpoint 模式: 跳过重新创建
    if ctx.scoring_target is None:
        ctx.scoring_target = _create_scoring_target(ctx)
    if ctx.scoring_target:
        logger.info("Scoring target: %s", type(ctx.scoring_target).__name__)

    # converter target = scoring target (Qwen3-32B, JSON 兼容性好于 DeepSeek-V3)
    # L5 v34: DeepSeek-V3 对 PersuasionConverter 的 JSON schema 返回 500 错误
    # Qwen3-32B 对 PyRIT converter 的 JSON 格式兼容性更好
    # converter 只做文本改写, 不需要最强攻击能力
    # 多 endpoint 模式: 跳过重新创建 (复用已有的)
    if ctx.converter_target is None:
        ctx.converter_target = ctx.scoring_target or ctx.adversarial_target

    logger.info(
        "Targets configured: objective=%s, adversarial=%s, scorer=%s",
        type(target).__name__,
        type(ctx.adversarial_target).__name__ if ctx.adversarial_target else "None",
        type(ctx.scoring_target).__name__ if ctx.scoring_target else "None",
    )


async def _check_target_availability(parsed: Any) -> bool:
    """L5 v12: 检查目标 API 是否可用。

    学术依据: Heroux et al. (arXiv:2403.04206) — 超时恢复策略
    在攻击开始前发送一个简单的探针请求, 检测目标是否在线。
    避免在不可达目标上浪费时间 (之前多次运行因 402/连接拒绝失败)。

    检查策略:
        1. 发送简单 POST 请求, 使用 stream=True 只读取响应头
        2. 连接超时 5s, 读取超时 15s (SSE 流式响应需要更长)
        3. 接受任何 HTTP 响应 (200/400/401/403 都算在线)
        4. 连接拒绝/超时 = 不可用

    L5 v22 修复: SSE 流式响应导致 httpx 等待整个响应体完成才返回,
    但 SSE 连接不会主动关闭, 5 秒超时必然触发 TimeoutException。
    修复: 使用 stream=True 只读取响应头即可判断可用性,
    不等待整个响应体完成。增加 read 超时到 15 秒。

    Args:
        parsed: 解析后的 Burp 请求。

    Returns:
        True 如果目标在线, False 如果不可达。
    """
    import httpx

    scheme = "https" if parsed.use_tls else "http"
    check_url = f"{scheme}://{parsed.host}{parsed.path}"

    # 构建探针 headers (排除 Content-Length 和 Host)
    check_headers: dict[str, str] = {}
    for key, value in parsed.raw_headers:
        if key.lower() not in ("content-length", "host"):
            check_headers[key] = value

    # 构建探针 body: 使用 parsed.body 模板替换 {PROMPT}, 而非硬编码
    # 这样 Baidu/Qwen/DeepSeek 等不同 body 结构都能正确发送可用性检查
    from recon.capability_detector import _build_probe_body
    check_body = _build_probe_body(parsed, "hi")

    try:
        # L5 v22: 使用 stream=True 避免等待 SSE 响应体完成
        # SSE 流式连接不会主动关闭, httpx 默认等待整个响应体完成
        # 使用 stream=True 后, httpx 在读取到响应头时即返回
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(connect=5.0, read=15.0, write=5.0, pool=5.0),
            follow_redirects=True,
            verify=False,
        ) as client:
            async with client.stream(
                method=parsed.method,
                url=check_url,
                headers=check_headers,
                content=check_body,
            ) as response:
                # 402 Payment Required = 目标 API 余额耗尽
                if response.status_code == 402:
                    logger.error(
                        "Target returned 402 Payment Required — API balance depleted."
                    )
                    return False

                # 503 Service Unavailable = 目标临时不可用
                if response.status_code == 503:
                    logger.error("Target returned 503 Service Unavailable.")
                    return False

                # 任何其他响应 (200/400/401/403/429) = 目标在线
                logger.info(
                    "Target availability check: HTTP %d (target is online)",
                    response.status_code,
                )
                return True

    except httpx.ConnectError as e:
        logger.error("Target connection refused: %s", e)
        return False
    except httpx.TimeoutException:
        logger.error("Target availability check timed out (connect=5s, read=15s).")
        return False
    except Exception as e:
        logger.error("Target availability check failed: %s", e)
        return False


def _create_adversarial_target() -> Any:
    """从 .env 创建 adversarial chat 目标。

    读取环境变量:
    ADVERSARIAL_CHAT_ENDPOINT
    ADVERSARIAL_CHAT_KEY
    ADVERSARIAL_CHAT_MODEL (默认 gpt-4o)

    L5 v52: 使用 PyRIT 原生 max_requests_per_minute 参数进行 RPM 限速,
    替代外部 RateLimitedTarget 包装 (原生装饰器更高效)。

    Returns:
    OpenAIChatTarget 实例, 或 None (未配置时)。
    """
    from pyrit.prompt_target import OpenAIChatTarget

    endpoint = os.environ.get("ADVERSARIAL_CHAT_ENDPOINT")
    api_key = os.environ.get("ADVERSARIAL_CHAT_KEY")
    model = os.environ.get("ADVERSARIAL_CHAT_MODEL", "gpt-4o")

    # L5 v52: 从环境变量读取 RPM (PyRIT 原生限速)
    # rate_limit 从 config/defaults.yaml 的 rate_limit 键读取,
    # 在 main.py 的 _apply_defaults 中映射到 args.rate_limit。
    # 这里无法访问 ctx, 从环境变量 RATE_LIMIT 读取 (由 main.py 设置)。
    rpm_str = os.environ.get("RATE_LIMIT", "")
    rpm = int(rpm_str) if rpm_str.isdigit() else None

    if endpoint and api_key:
        return OpenAIChatTarget(
            endpoint=endpoint,
            api_key=api_key,
            model_name=model,
            max_requests_per_minute=rpm,
        )

    logger.warning(
        "Adversarial target not configured. "
        "Set ADVERSARIAL_CHAT_ENDPOINT and ADVERSARIAL_CHAT_KEY in .env. "
        "Multi-turn attacks (Crescendo, TAP) will be skipped."
    )
    return None


def _create_extra_adversarial_targets() -> list[Any]:
    """L5 v10: 创建额外的 adversarial targets (多模型并行攻击)。

    学术依据: Chao et al. (arXiv:2310.08419) — 不同 LLM (GPT-4o,
    Claude, Gemini) 在越狱 prompt 生成方面有互补性。
    多模型并行使 ASR 提升 ~20% (联合概率 P = 1 - ∏(1-p_i))。

    读取环境变量 (序号 2, 3 ...):
        ADVERSARIAL_CHAT_ENDPOINT_2, ADVERSARIAL_CHAT_KEY_2, ADVERSARIAL_CHAT_MODEL_2
        ADVERSARIAL_CHAT_ENDPOINT_3, ADVERSARIAL_CHAT_KEY_3, ADVERSARIAL_CHAT_MODEL_3

    Returns:
        额外 adversarial target 列表 (空列表表示无额外配置)。
    """
    from pyrit.prompt_target import OpenAIChatTarget

    targets: list[Any] = []

    for i in (2, 3, 4):
        endpoint = os.environ.get(f"ADVERSARIAL_CHAT_ENDPOINT_{i}")
        api_key = os.environ.get(f"ADVERSARIAL_CHAT_KEY_{i}")
        model = os.environ.get(f"ADVERSARIAL_CHAT_MODEL_{i}", "gpt-4o")

        if endpoint and api_key:
            try:
                target = OpenAIChatTarget(
                    endpoint=endpoint,
                    api_key=api_key,
                    model_name=model,
                )
                targets.append(target)
                logger.info("Extra adversarial target %d: %s", i, model)
            except Exception as e:
                logger.warning("Failed to create adversarial target %d: %s", i, e)

    return targets


def _create_scoring_target(ctx: PipelineContext) -> Any:
    """从 .env 创建评分器目标 (缺失时复用 adversarial)。

    读取环境变量:
        SCORER_CHAT_ENDPOINT
        SCORER_CHAT_KEY
        SCORER_CHAT_MODEL (默认 gpt-4o)

    L5 v52: 创建后使用 PyRIT 原生 TargetRequirements 验证评分目标能力,
    确保满足 LLM-as-a-Judge 评分需求 (JSON 输出 + text 模态)。

    Returns:
        OpenAIChatTarget 实例, 或 None (未配置时复用 adversarial)。
    """
    from pyrit.prompt_target import OpenAIChatTarget

    # L5 v32: 优先读取 SCORING_CHAT_* (与 asr_tracker 一致), fallback 到 SCORER_CHAT_*
    endpoint = os.environ.get("SCORING_CHAT_ENDPOINT") or os.environ.get("SCORER_CHAT_ENDPOINT")
    api_key = os.environ.get("SCORING_CHAT_KEY") or os.environ.get("SCORER_CHAT_KEY")
    model = os.environ.get("SCORING_CHAT_MODEL") or os.environ.get("SCORER_CHAT_MODEL", "gpt-4o")

    target = None
    if endpoint and api_key:
        # L5 v52: 从环境变量读取 RPM (PyRIT 原生限速)
        rpm_str = os.environ.get("RATE_LIMIT", "")
        rpm = int(rpm_str) if rpm_str.isdigit() else None

        target = OpenAIChatTarget(
            endpoint=endpoint,
            api_key=api_key,
            model_name=model,
            max_requests_per_minute=rpm,
        )
    else:
        # 复用 adversarial target
        if ctx.adversarial_target:
            logger.info("Scorer target not configured, reusing adversarial target")
            target = ctx.adversarial_target

    # L5 v52: PyRIT 原生 TargetRequirements 验证
    # 学术依据: PyRIT (arXiv:2407.01232) — 验证 scoring_target 能力
    # 在目标创建后、注册到 ctx 前验证, 确保满足评分器需求
    if target:
        try:
            from assess.scorer import validate_scoring_target_capabilities

            if not validate_scoring_target_capabilities(target):
                logger.warning(
                    "L5 v52: Scoring target %s failed capability validation; "
                    "LLM-based scoring may fail — consider configuring "
                    "SCORING_CHAT_* with a model that supports JSON output",
                    type(target).__name__,
                )
            else:
                logger.info(
                    "L5 v52: Scoring target %s passed capability validation",
                    type(target).__name__,
                )
        except Exception as e:
            logger.debug("L5 v52: Scoring target validation skipped: %s", e)

    return target


async def _create_playwright_target(ctx: PipelineContext, browser_url: str) -> None:
    """创建 PyRIT 原生 PlaywrightTarget — 浏览器渲染 Chat UI 攻击。

    学术依据:
        - PyRIT (arXiv:2407.01232) — PlaywrightTarget 是 PyRIT 原生
          浏览器自动化 Target, 用于攻击需要 JavaScript 渲染的 Web Chat UI

    PyRIT 原生优势 (Rule 2: 原生优先):
        - 浏览器渲染: 能攻击需要 JS 渲染的 Web Chat 界面 (如 ChatGPT Web)
        - 自定义交互: InteractionFunction 定义任意的页面交互逻辑
        - 原生 Target: 与 PyRIT 的 PromptSendingAttack / CrescendoAttack 等完全兼容
        - 速率限制: 内置 RPM 控制

    交互逻辑:
        1. 打开目标 URL
        2. 定位输入框 (常见选择器: textarea, input[type=text], [contenteditable])
        3. 输入 prompt 文本
        4. 等待响应出现 (常见选择器: .message, .response, [data-role="assistant"])
        5. 提取响应文本

    Args:
        ctx: 流水线上下文。
        browser_url: 目标 Web Chat UI 的 URL。
    """
    # 检查 playwright 是否安装 (使用 find_spec 避免 F401 unused import)
    import importlib.util

    if importlib.util.find_spec("playwright") is None:
        logger.error(
            "Playwright not installed. Install with: pip install playwright && playwright install chromium"
        )
        raise ImportError(
            "Playwright is required for --browser-url mode. "
            "Install with: pip install playwright && playwright install chromium"
        )

    try:
        from pyrit.prompt_target import PlaywrightTarget
    except ImportError as e:
        logger.error("PyRIT PlaywrightTarget not available: %s", e)
        raise

    # 定义浏览器交互函数
    # PyRIT PlaywrightTarget 需要 InteractionFunction 和 Page 对象
    # 对齐 PyRIT 1.0.1: InteractionFunction 签名为
    #   async def __call__(self, page: Page, message: Message) -> str
    # 交互函数接收完整 Message 对象 (非字符串)
    async def _chat_interaction(page, message):
        """与 Web Chat UI 交互的函数。

        对齐 PyRIT 1.0.1 InteractionFunction Protocol:
            - 参数: page (Playwright Page), message (Message 对象)
            - 返回: str (目标 UI 的响应文本)

        Args:
            page: Playwright Page 对象。
            message: PyRIT Message 对象 (含 message_pieces).

        Returns:
            目标 Chat UI 的响应文本。
        """
        # 从 Message 中提取 prompt 文本 — 对齐 PyRIT 1.0.1 MessagePiece API
        # message.message_pieces[0].converted_value 是注入的 prompt 文本
        prompt_text = (
            message.message_pieces[0].converted_value
            if hasattr(message, "message_pieces") and message.message_pieces
            else str(message)
        )
        # 导航到目标 URL
        await page.goto(browser_url, wait_until="domcontentloaded")

        # 等待页面加载完成 (常见 Chat UI 容器)
        await page.wait_for_selector(
            "textarea, input[type='text'], [contenteditable='true']",
            timeout=10000,
        )

        # 定位输入框 (按优先级尝试常见选择器)
        input_selector = await page.query_selector("textarea") or \
            await page.query_selector("input[type='text']") or \
            await page.query_selector("[contenteditable='true']")

        if input_selector is None:
            raise RuntimeError("Could not find input element on the page")

        # 输入 prompt
        await input_selector.fill(prompt_text)

        # 按 Enter 或点击发送按钮
        send_button = await page.query_selector(
            "button[type='submit'], button[aria-label*='send'], button[aria-label*='Send']"
        )
        if send_button:
            await send_button.click()
        else:
            await input_selector.press("Enter")

        # 等待响应出现 (常见响应容器选择器)
        response_selector = (
            ".message:last-child, .response:last-child, "
            "[data-role='assistant']:last-child, .chat-message:last-child"
        )
        try:
            await page.wait_for_selector(response_selector, timeout=30000)
            # 额外等待响应稳定 (内容不再变化)
            await page.wait_for_timeout(2000)
        except Exception:
            logger.warning("Response selector not found, waiting for any text change")
            await page.wait_for_timeout(5000)

        # 提取响应文本
        response_element = await page.query_selector(response_selector)
        if response_element:
            response_text = await response_element.inner_text()
            return response_text.strip()

        # Fallback: 提取页面所有文本
        return await page.inner_text("body")

    # 创建 PlaywrightTarget — 需要有效的 Page 对象
    try:
        from playwright.async_api import async_playwright

        # L5 v38 修复: _create_playwright_target 是 async 函数,
        # 直接 await 获取 Page 对象, 不再创建嵌套事件循环
        # (嵌套事件循环在已有 async 上下文中会崩溃)
        # 生产级修复: 存储引用到 ctx 以便后续清理
        _playwright_instance = await async_playwright().start()
        _browser = await _playwright_instance.chromium.launch(headless=True)
        _context = await _browser.new_context()
        page = await _context.new_page()

        target = PlaywrightTarget(
            interaction_func=_chat_interaction,
            page=page,
            max_requests_per_minute=int(os.environ.get("BROWSER_TARGET_RPM", "10")),
        )
        ctx.objective_target = target
        ctx.multi_turn_target = target  # PlaywrightTarget 支持多轮
        ctx.model_name = f"Browser:{browser_url}"

        # 断点修复: 为非Burp路径创建 parsed_request, 确保 arm/strike/report 阶段数据流一致
        _ensure_parsed_request_for_api_path(ctx, mode="browser", model_name=browser_url, endpoint=browser_url)

        # 生产级资源管理: 存储引用供流水线结束时清理
        ctx._playwright_instance = _playwright_instance
        ctx._browser = _browser
        ctx._browser_context = _context

        logger.info(
            "L5 v38: PlaywrightTarget created for %s (RPM=%s)",
            browser_url,
            os.environ.get("BROWSER_TARGET_RPM", "10"),
        )
    except Exception as e:
        logger.error("Failed to create PlaywrightTarget: %s", e)
        raise


async def _create_native_openai_target(
    ctx: PipelineContext,
    *,
    endpoint: str,
    api_key: str,
    model_name: str,
    api_type: str = "chat",
) -> None:
    """L5 v52: 创建 PyRIT 原生 OpenAIChatTarget 或 OpenAIResponseTarget。

    学术依据: PyRIT (arXiv:2407.01232) — 原生 Target 支持

    PyRIT 原生优势:
        1. OpenAIChatTarget:
           - 支持 gpt-4o, gpt-4, DeepSeek, llama, phi-4, gpt-3.5
           - 原生 RPM 限速: max_requests_per_minute 参数
           - 原生 JSON 输出: response_format + json_schema (prompt_metadata)
           - 原生多模态: text + image_path 输入
           - 原生 TargetCapabilities: get_known_capabilities 自动匹配模型
           - 原生错误处理: pyrit_target_retry 重试装饰器
           - 原生温度控制: temperature, top_p, frequency_penalty 等
           - Azure Entra ID 认证: 支持无 API key 的 identity 认证

        2. OpenAIResponseTarget:
           - 支持 o1, o3, o4-mini, GPT-5 (Responses API)
           - 原生 reasoning 控制: reasoning_effort + reasoning_summary
           - 原生 tool calling: custom_functions 注册自定义工具
           - 原生 web search: 内置 web search tool
           - 原生 agentic loop: 自动处理 function_call → function_call_output
           - 原生 JSON schema: text.format.json_schema
           - 原生 TargetCapabilities: 支持 function_call, tool_call 数据类型

    包装策略:
        - 使用 RateLimitedTarget 包装, 提供并发控制 + 重试
        - 保持原生 TargetCapabilities (不覆盖 custom_configuration)
        - 复用原生 max_requests_per_minute 限速

    Args:
        ctx: 流水线上下文。
        endpoint: API endpoint URL。
        api_key: API key。
        model_name: 模型名称 (如 gpt-4o, o3-mini)。
        api_type: "chat" → OpenAIChatTarget, "responses" → OpenAIResponseTarget。
    """
    from pyrit.prompt_target import OpenAIChatTarget, OpenAIResponseTarget

    # 从 config 读取 RPM (与 RateLimitedTarget 一致)
    rpm = getattr(ctx.args, "rate_limit", None) or None

    if api_type == "responses":
        # OpenAIResponseTarget — Responses API (o1/o3/o4-mini/GPT-5)
        # 原生支持 reasoning_effort, reasoning_summary, custom_functions
        target = OpenAIResponseTarget(
            endpoint=endpoint,
            api_key=api_key,
            model_name=model_name,
            max_requests_per_minute=rpm,
        )
        logger.info(
            "L5 v52: OpenAIResponseTarget created: endpoint=%s, model=%s, RPM=%s",
            endpoint, model_name, rpm or "unlimited",
        )
    else:
        # OpenAIChatTarget — Chat Completions API (gpt-4o, DeepSeek 等)
        # 原生支持 temperature, top_p, frequency_penalty, max_completion_tokens
        target = OpenAIChatTarget(
            endpoint=endpoint,
            api_key=api_key,
            model_name=model_name,
            max_requests_per_minute=rpm,
        )
        logger.info(
            "L5 v52: OpenAIChatTarget created: endpoint=%s, model=%s, RPM=%s",
            endpoint, model_name, rpm or "unlimited",
        )

    # 包装 RateLimitedTarget (并发控制 + 认证恢复)
    # PyRIT 原生 @limit_requests_per_minute + @pyrit_target_retry 装饰器
    # 保留在被包装 target 上, RateLimitedTarget 仅增强并发控制
    wrapped_target = RateLimitedTarget(
        target=target,
        max_concurrency=ctx.args.max_concurrency or 3,
    )
    ctx.objective_target = wrapped_target
    ctx.multi_turn_target = wrapped_target  # 原生支持多轮

    # 设置 model_name
    ctx.model_name = f"OpenAI:{model_name}"

    # 断点修复: 为非Burp路径创建 parsed_request, 确保 arm/strike/report 阶段数据流一致
    # 数据流: target_router → ctx.parsed_request.target_fingerprint → arm (language/capabilities/model_family) → report
    _ensure_parsed_request_for_api_path(ctx, mode=api_type, model_name=model_name, endpoint=endpoint)

    # L5 v52: 可选 — 运行 PyRIT 原生能力探测
    # 原生 OpenAIChatTarget/OpenAIResponseTarget 已有正确的 TargetCapabilities,
    # 但运行时探测可以发现端点实际支持的能力 (如 Azure 部署可能禁用了某些能力)
    auto_discover = getattr(ctx.args, "auto_discover_capabilities", False)
    if auto_discover:
        logger.info("L5 v52: Running native capability discovery...")
        await wrapped_target.apply_discovered_capabilities(timeout_s=15.0)


async def _create_litellm_target(
    ctx: PipelineContext,
    *,
    model_name: str,
) -> None:
    """创建 PyRIT 原生 LiteLLMChatTarget — 适配 100+ LLM 提供商。

    对齐 PyRIT 1.0.1:
        LiteLLMChatTarget 通过 LiteLLM SDK 访问 100+ LLM 提供商:
        - Anthropic (Claude 系列): model_name="anthropic/claude-sonnet-4-6"
        - AWS Bedrock: model_name="bedrock/anthropic.claude-v2"
        - Google Vertex (Gemini): model_name="vertex_ai/gemini-pro"
        - Cohere, Mistral, AI21 等
        - 自托管 LLM: 通过 endpoint 参数指向自定义 API

    原生优势:
        - 统一 OpenAI Chat Completions 线格式
        - 自动从环境变量读取提供商 API key
          (ANTHROPIC_API_KEY, AWS_ACCESS_KEY_ID 等)
        - 原生 drop_unsupported_params: 跨提供商参数兼容
        - 原生 LiteLLM 重试: 提供商感知的重试策略
        - 原生 TargetCapabilities: 从 LiteLLM 元数据自动推导

    适配任意基于 LLM 开发的 Agent:
        - 国产 LLM (通义千问, 文心一言, 智谱 GLM):
          通过 OpenAI 兼容接口, model_name="openai/模型名" + LITELLM_ENDPOINT
        - 自建 Agent API: 通过 LITELLM_ENDPOINT 指向自定义 API 网关
        - 多云部署: 通过 LiteLLM 路由到不同云提供商

    包装策略:
        - 使用 RateLimitedTarget 包装, 提供并发控制
        - 保持原生 TargetCapabilities (不覆盖 custom_configuration)
        - 复用原生 max_requests_per_minute 限速
        - 保留原生 @limit_requests_per_minute + LiteLLM 重试

    学术依据:
        - PyRIT (arXiv:2407.01232) — LiteLLMChatTarget 原生 Target

    Args:
        ctx: 流水线上下文。
        model_name: LiteLLM 模型字符串 (如 "anthropic/claude-sonnet-4-6")。
    """
    try:
        from pyrit.prompt_target import LiteLLMChatTarget
    except ImportError as e:
        raise ImportError(
            "LiteLLMChatTarget requires litellm. "
            "Install with: pip install pyrit[litellm] or pip install litellm"
        ) from e

    # 从环境变量读取配置
    api_key = os.environ.get("LITELLM_API_KEY")
    endpoint = os.environ.get("LITELLM_ENDPOINT")
    headers_str = os.environ.get("LITELLM_HEADERS", "")
    # RPM 限速 (与 RateLimitedTarget 一致)
    rpm_str = os.environ.get("RATE_LIMIT", "")
    rpm = int(rpm_str) if rpm_str.isdigit() else None

    # 解析额外 headers (JSON 格式)
    headers: dict[str, str] | None = None
    if headers_str:
        import json
        try:
            headers = json.loads(headers_str)
        except (json.JSONDecodeError, TypeError):
            logger.warning("LITELLM_HEADERS not valid JSON, ignoring: %s", headers_str)

    target = LiteLLMChatTarget(
        model_name=model_name,
        api_key=api_key,
        endpoint=endpoint,
        headers=headers,
        max_requests_per_minute=rpm,
    )

    logger.info(
        "LiteLLMChatTarget created: model=%s, endpoint=%s, RPM=%s",
        model_name,
        endpoint or "(provider default)",
        rpm or "unlimited",
    )

    # 包装 RateLimitedTarget (并发控制)
    # PyRIT 原生 @limit_requests_per_minute + LiteLLM 提供商感知重试
    # RateLimitedTarget 仅增强并发控制
    wrapped_target = RateLimitedTarget(
        target=target,
        max_concurrency=ctx.args.max_concurrency or 3,
    )
    ctx.objective_target = wrapped_target
    ctx.multi_turn_target = wrapped_target  # LiteLLMChatTarget 原生支持多轮

    # 设置 model_name
    ctx.model_name = f"LiteLLM:{model_name}"

    # 断点修复: 为非Burp路径创建 parsed_request, 确保 arm/strike/report 阶段数据流一致
    _ensure_parsed_request_for_api_path(ctx, mode="litellm", model_name=model_name, endpoint=endpoint)

    # 可选 — 运行 PyRIT 原生能力探测
    auto_discover = getattr(ctx.args, "auto_discover_capabilities", False)
    if auto_discover:
        logger.info("Running native capability discovery on LiteLLMChatTarget...")
        await wrapped_target.apply_discovered_capabilities(timeout_s=15.0)


def _ensure_parsed_request_for_api_path(
    ctx: PipelineContext,
    *,
    mode: str,
    model_name: str,
    endpoint: str | None,
) -> None:
    """为非Burp路径创建轻量级 parsed_request, 确保数据流一致性。

    断点修复: 之前 LiteLLM/OpenAI API/Playwright 路径不设置 ctx.parsed_request,
    导致后续阶段无法提取 target_fingerprint:
      - arm 阶段: target_language/target_capabilities/target_model_family 全为 None
      - report 阶段: target_fingerprint 为空 dict, 报告中侦察信息缺失
      - main.py: orchestration_log 在非Burp路径不记录 recon 决策

    数据流 (修复后):
      target_router → ctx.parsed_request.target_fingerprint
      → arm (language/capabilities/model_family 提取)
      → strike (model_family 用于 ASR 先验)
      → report (target_fingerprint 展示在报告中)

    Args:
        ctx: 流水线上下文。
        mode: 路由模式 (litellm/chat/responses/browser)。
        model_name: 模型名称或浏览器URL。
        endpoint: API 端点URL。
    """
    from recon.burp_parser import ParsedBurpRequest

    # 根据模式推导能力指纹
    capabilities = "text"  # 默认能力
    app_type = mode
    auth_type = "api_key"
    language = "en"

    if mode == "litellm":
        # LiteLLM 模型名通常包含提供商前缀 (anthropic/claude-sonnet-4-6)
        provider = model_name.split("/")[0].lower() if "/" in model_name else ""
        if provider in ("anthropic",):
            language = "en"
            model_family = "claude"
        elif provider in ("bedrock",):
            language = "en"
            model_family = "bedrock"
        elif provider in ("vertex_ai", "vertexai"):
            language = "en"
            model_family = "gemini"
        else:
            model_family = provider or "litellm"
    elif mode in ("chat", "responses"):
        model_lower = model_name.lower()
        if "gpt" in model_lower or "o1" in model_lower or "o3" in model_lower or "o4" in model_lower:
            model_family = "openai"
        elif "deepseek" in model_lower:
            model_family = "deepseek"
            language = "zh"
        elif "qwen" in model_lower or "通义" in model_lower:
            model_family = "qwen"
            language = "zh"
        elif "claude" in model_lower:
            model_family = "claude"
        elif "llama" in model_lower:
            model_family = "llama"
        elif "phi" in model_lower:
            model_family = "phi"
        else:
            model_family = "openai_compatible"
    elif mode == "browser":
        model_family = "browser"
        auth_type = "none"
        capabilities = "text"
    else:
        model_family = mode

    # 解析 endpoint URL 以提取 host/path/use_tls
    _use_tls = True
    _host = endpoint or ""
    _path = ""
    if endpoint:
        from urllib.parse import urlparse
        _parsed_url = urlparse(endpoint)
        _use_tls = _parsed_url.scheme == "https"
        _host = _parsed_url.netloc or _parsed_url.path or endpoint
        _path = _parsed_url.path or ""

    # 非 Burp 路径不存在 {PROMPT} 占位符 — 使用 API 原生参数传递
    # has_prompt_placeholder=False 是正确的, 因为 OpenAIChatTarget/LiteLLMChatTarget
    # 通过 API 参数 (不是 HTTP body 占位符) 发送 prompt
    fingerprint = {
        "app_type": app_type,
        "auth_type": auth_type,
        "capabilities": capabilities,
        "model_family": model_family,
        "language": language,
        "api_category": mode,
        "target_type": mode,
        "endpoint": endpoint or "",
        "model_name": model_name,
    }

    ctx.parsed_request = ParsedBurpRequest(
        method="POST",
        url=endpoint or "",
        host=_host,
        path=_path,
        use_tls=_use_tls,
        has_prompt_placeholder=False,  # API 模式无 {PROMPT} 占位符
        target_fingerprint=fingerprint,
    )
    logger.debug(
        "Non-Burp path: created parsed_request for mode=%s, model_family=%s",
        mode, model_family,
    )
