"""Target Router Helpers - extracted from recon/target_router.py.

Contains:
- _log_probe_failure    - logging helper
- _ProbeCounter         - adaptive probe counter class
- _configure_remaining_targets - post-create target configuration
- _init_adaptive_probe  - 6-strategy adaptive probe initialization
- _run_background_probes - background health probes
- _check_target_availability - target reachability check
- _create_adversarial_target / _create_extra_adversarial_targets
- _create_scoring_target
- _create_playwright_target
- _create_native_openai_target
- _create_litellm_target
- _ensure_parsed_request_for_api_path
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

# Target construction was split out (R-DELIVERY-1) into `recon/_target_factory.py`
# to keep this module focused on probe / adaptive-orchestration logic. Re-export the
# builders so `recon.target_router` and callers of `_target_router_helpers` keep
# working unchanged.
from recon._target_factory import (
    _create_adversarial_target,
    _create_extra_adversarial_targets,
    _create_litellm_target,
    _create_native_openai_target,
    _create_playwright_target,
    _create_scoring_target,
    _ensure_parsed_request_for_api_path,
)
from recon.api.adaptive_config import compute_probe_budget
from recon.capability_detector import probe_active_capabilities
from recon.guardrail_detector import detect_guardrail
from recon.model.seed_mapper import get_seeds_for_model
from recon.stealth_config import get_stealth_manager

if TYPE_CHECKING:
    from core.context import PipelineContext

logger = logging.getLogger(__name__)

# Module-level Playwright handles (moved out of ctx to keep context ASR-centered)
# These are operational resource handles, not attack data.
_playwright_handles: dict[str, Any] = {}


def get_playwright_handles() -> dict[str, Any]:
    """Get module-level Playwright handles for cleanup. Not part of ASR data flow."""
    return _playwright_handles


#: Default max probe count (used when adaptive probe budget not configured)
_MAX_PROBE_COUNT: int = 10

#: TLS verification setting for httpx probes (False for self-signed certs in lab environments)
_TLS_VERIFY: bool = False


def _log_probe_failure(
    ctx: Any,
    probe_phase: str,
    error: Exception,
    is_fatal: bool = False,
) -> None:
    """Local orchestration_log helper (mirrors target_router._log_probe_failure)."""
    if ctx is None or not hasattr(ctx, "orchestration_log"):
        return
    ctx.orchestration_log.append(
        {
            "phase": "recon",
            "decision": f"probe_{probe_phase}_failed",
            "input": {"target": getattr(ctx, "model_name", "unknown")},
            "output": {
                "error_type": type(error).__name__,
                "error_message": str(error)[:500],
                "is_fatal": is_fatal,
            },
            "reasoning": (
                f"Probe '{probe_phase}' failed with {type(error).__name__}: {str(error)[:200]}. "
                f"{'Fatal: aborting.' if is_fatal else 'Non-fatal: continuing with degraded capability.'}"
            ),
        }
    )


async def _configure_remaining_targets(ctx: PipelineContext) -> None:
    """adversarial/scoring/converter targets."""
    # adversarial target
    if ctx.adversarial_target is None:
        ctx.adversarial_target = _create_adversarial_target()
    if ctx.adversarial_target:
        logger.info("Adversarial target: %s", type(ctx.adversarial_target).__name__)

    # extra adversarial targets
    if not ctx.extra_adversarial_targets:
        extra_targets = _create_extra_adversarial_targets()
        if extra_targets:
            ctx.extra_adversarial_targets = extra_targets
            logger.info("Extra adversarial targets: %d", len(extra_targets))

    # scoring target
    if ctx.scoring_target is None:
        ctx.scoring_target = _create_scoring_target(ctx)
    if ctx.scoring_target:
        logger.info("Scoring target: %s", type(ctx.scoring_target).__name__)

    # converter target
    if ctx.converter_target is None:
        ctx.converter_target = ctx.scoring_target or ctx.adversarial_target

    logger.info(
        "Targets configured: objective=%s, adversarial=%s, scorer=%s",
        type(ctx.objective_target).__name__ if ctx.objective_target else "None",
        type(ctx.adversarial_target).__name__ if ctx.adversarial_target else "None",
        type(ctx.scoring_target).__name__ if ctx.scoring_target else "None",
    )


# ====================================================================
# -
# ====================================================================


class _ProbeCounter:
    """

    L5 v54+:  max_probes ( _init_adaptive_probe )
    """

    def __init__(self) -> None:
        self.value: int = 0
        self._adaptive_max: int | None = None  # Set by _init_adaptive_probe
        # == 深度探测独立预算（消费 probe_budget["deep_probe_budget"]）==
        # 此前 deep_probe_budget 被计算、被打印，但**从未用于门控**（C7 断链）：
        # 深度探测（deep_probe_capabilities / OpenAPI / GraphQL / 限流）共用总预算，
        # 在典型预算（complex=12）下必然超支被跳过，等价于"声明但不可执行"。
        self.deep_value: int = 0
        self._deep_max: int | None = None

    def add(self, n: int = 1) -> None:
        self.value += n

    def add_deep(self, n: int = 1) -> None:
        self.deep_value += n

    def can_probe(self, n: int = 1, max_probes: int = _MAX_PROBE_COUNT) -> bool:
        # max ()
        effective_max = self._adaptive_max if self._adaptive_max is not None else max_probes
        return self.value + n <= effective_max

    def can_deep_probe(self, n: int = 1, max_probes: int = _MAX_PROBE_COUNT) -> bool:
        """深度探测独立预算（`deep_probe_budget`）；未初始化时回退总预算上限。"""
        effective_max = self._deep_max if self._deep_max is not None else max_probes
        return self.deep_value + n <= effective_max

    def get_budget_remaining(self, max_probes: int = _MAX_PROBE_COUNT) -> int:
        """Return remaining probe budget."""
        effective_max = self._adaptive_max if self._adaptive_max is not None else max_probes
        return max(0, effective_max - self.value)


# ====================================================================
# L5 v54+: Adaptive Probe Initialization - 6-Strategy Integration Hub
# ====================================================================


async def _init_adaptive_probe(
    ctx: Any,
    parsed: Any,
    counter: _ProbeCounter,
) -> dict[str, Any]:
    """- 6

     ():
        1. Guardrail Detection -> severity, stealth_level
        2. Stealth Config -> delay_range, max_probes, allowed_converters
        3. Adaptive Probe Budget -> total budget, deep_budget, behavioral_budget
        4. Model Seed Mapping -> preferred_templates, optimal_converters
        5. Behavioral Verify -> adjust confidence for S3 confirmation
        6. Capability Monitor -> baseline snapshot for drift detection

    Args:
        ctx: PipelineContext .
        parsed: ParsedBurpRequest .
        counter: _ProbeCounter .

    Returns:
        dict: all.
    """
    probe_ctx: dict[str, Any] = {
        "guardrail_report": {},
        "stealth_policy": {},
        "probe_budget": {},
        "seed_mapping": {},
        "behavioral_report": {},
    }

    model_name = getattr(parsed, "burp_model_name", "") or "unknown"

    # == Phase 1: Guardrail Detection () ==
    try:
        logger.info("[Adaptive] Phase 1: Guardrail detection...")
        guardrail_report = await detect_guardrail(parsed)
        probe_ctx["guardrail_report"] = guardrail_report.to_dict()
        logger.info(
            "[Adaptive] Guardrail: type=%s, severity=%s, stealth=%s",
            guardrail_report.guardrail_type,
            guardrail_report.severity,
            guardrail_report.stealth_level,
        )
        counter.add(3)  # 3 grayscale probes
    except Exception as e:
        logger.debug("[Adaptive] Guardrail detection failed: %s", e)
        probe_ctx["guardrail_report"] = {
            "has_guardrail": False,
            "severity": "none",
            "stealth_level": "balanced",
        }

    # == Phase 2: Stealth Level -> Policy ==
    try:
        stealth_mgr = get_stealth_manager()
        guardrail_severity = probe_ctx["guardrail_report"].get("severity", "none")
        recommended_stealth = probe_ctx["guardrail_report"].get("stealth_level", "balanced")

        # guardrail ,
        user_stealth = getattr(ctx.args, "stealth_level", None) or recommended_stealth
        stealth_policy = stealth_mgr.get_policy(user_stealth)
        probe_ctx["stealth_policy"] = {
            "name": stealth_policy.name,
            "delay_range": list(stealth_policy.delay_range),
            "allowed_converters": stealth_policy.allowed_converters,
            "behavioral_verify": stealth_policy.behavioral_verify,
        }
        logger.info("[Adaptive] Stealth policy: %s", stealth_policy.name)
    except Exception as e:
        logger.debug("[Adaptive] Stealth config failed: %s", e)
        probe_ctx["stealth_policy"] = {"name": "balanced", "behavioral_verify": True}

    # == Phase 3: Adaptive Probe Budget ==
    try:
        # ( parsed target_fingerprint )
        existing_caps_str = parsed.target_fingerprint.extra.get("capabilities", "")
        existing_caps = {}
        if existing_caps_str:
            for cap in existing_caps_str.split(","):
                if cap.strip():
                    existing_caps[cap.strip()] = True

        app_type = parsed.target_fingerprint.app_type if hasattr(parsed, "target_fingerprint") else "chat"

        probe_budget = compute_probe_budget(
            capabilities=existing_caps,
            guardrail_severity=guardrail_severity,
            app_type=app_type,
            stealth_level=probe_ctx["stealth_policy"].get("name", "balanced"),
        )
        probe_ctx["probe_budget"] = probe_budget
        # max_probes ()
        counter._adaptive_max = probe_budget["budget"]
        # 深度探测独立预算门控（此前 deep_probe_budget 计算后从未被消费，C7 断链）
        counter._deep_max = probe_budget.get("deep_probe_budget", probe_budget["budget"])
        # 注：原日志行访问不存在的 `behavioral_verify_budget` 键 → KeyError 被下方
        # except 静默吞掉 → 已算出的 probe_budget 被降级字典覆盖（下游
        # `core.phases.arm._get_adaptive_max_seeds` 因此恒见 budget=5）。
        # 现改为只打印实际存在的键，预算不再被无谓覆盖。
        logger.info(
            "[Adaptive] Probe budget: total=%d, parallel=%d, deep=%d (complexity=%s)",
            probe_budget["budget"],
            probe_budget["parallel"],
            probe_budget["deep_probe_budget"],
            probe_budget["complexity_level"],
        )
    except Exception as e:
        logger.debug("[Adaptive] Probe budget calc failed: %s", e)
        probe_ctx["probe_budget"] = {"budget": 5, "parallel": 1, "complexity_level": "moderate"}

    # == Phase 4: Model Seed Mapping ( model_name ) ==
    try:
        if model_name and model_name != "unknown":
            seed_mapping = get_seeds_for_model(model_name)
            probe_ctx["seed_mapping"] = seed_mapping
            logger.info(
                "[Adaptive] Seed mapping for '%s': templates=%s, converters=%s (source=%s)",
                model_name,
                seed_mapping.get("preferred_templates", []),
                seed_mapping.get("optimal_converters", []),
                seed_mapping.get("source", "default"),
            )

            # ctx arm
            ctx.seed_preferences = seed_mapping
    except Exception as e:
        logger.debug("[Adaptive] Seed mapping failed: %s", e)

    # == Phase 5: Behavioral Verification ( S1 ) ==
    behavioral_enabled = probe_ctx["stealth_policy"].get("behavioral_verify", True)
    behavioral_budget = probe_ctx["probe_budget"].get("behavioral_verify_budget", 0)

    if behavioral_enabled and behavioral_budget > 0:
        # v1.5: Behavioral verification removed (no ASR contribution, over-engineering)
        # probe_ctx["behavioral_report"] = {}  # Disabled
        pass

    logger.info("[Adaptive] Probe initialization complete: %s", probe_ctx["probe_budget"])
    return probe_ctx


# ====================================================================
# P1 ()
# ====================================================================


def _to_dict_safe(obj: Any) -> dict[str, Any]:
    """`obj.to_dict()` when available, else empty dict (never raises)."""
    to_dict = getattr(obj, "to_dict", None)
    if not callable(to_dict):
        return {}
    try:
        value = to_dict()
    except Exception as e:  # 单个结果序列化失败不得拖垮整段侦察
        logger.debug("to_dict() failed: %s", e)
        return {}
    return value if isinstance(value, dict) else {}


async def _probe_mcp_locally(
    parsed: Any,
    counter: _ProbeCounter,
    target_url: str,
) -> dict[str, Any]:
    """本地 MCP 专项侦察（`recon.mcp.*`，零外部依赖）。

    当 MCPSec 桥不可用时作为**回退**（BL-029 接线），覆盖 REQ-161 的 MCP 专项要求：
        - `probe_mcp_capabilities`     → transport / 协议版本 / 能力位
        - `scan_mcp_security_surface`  → 认证 / TLS / 输入校验 / 限流 + findings
        - `fingerprint_mcp_version`    → 实现族与版本指纹
        - `scan_mcp_tool_inventory`    → 仅在已发现 tool schema 时评估 inputSchema 风险

    全部结果写入 `target_fingerprint`（recon 唯一输出总线，不新建并行通道，I12）。
    单个子探测失败不影响其余子探测（逐个隔离）。
    """
    from recon.mcp.capability_probe import probe_mcp_capabilities
    from recon.mcp.surface_scanner import scan_mcp_security_surface
    from recon.mcp.tool_inventory import scan_mcp_tool_inventory
    from recon.mcp.version_fingerprint import fingerprint_mcp_version

    result: dict[str, Any] = {}
    extra = parsed.target_fingerprint.extra

    probes = (
        ("capabilities", probe_mcp_capabilities),
        ("surface", scan_mcp_security_surface),
        ("version", fingerprint_mcp_version),
    )
    for key, probe_fn in probes:
        try:
            payload = _to_dict_safe(await probe_fn(target_url))
        except Exception as e:
            logger.debug("Local MCP probe '%s' failed: %s", key, e)
            continue
        if payload:
            result[key] = payload
            extra[f"mcp_{key}"] = payload

    # 工具清单：复用已发现的 tool schema，避免为风险评分再打一轮协议探测
    tool_defs = extra.get("tool_schemas") or []
    if isinstance(tool_defs, list) and tool_defs:
        try:
            inventory = await scan_mcp_tool_inventory(target_url, tool_defs)
            payload = _to_dict_safe(inventory)
            if payload:
                result["tool_inventory"] = payload
                extra["mcp_tool_inventory"] = payload
                names = [str(t.get("name")) for t in inventory.tools if isinstance(t, dict) and t.get("name")]
                if names:
                    parsed.target_fingerprint.mcp_tools = names
        except Exception as e:
            logger.debug("Local MCP tool inventory failed: %s", e)

    counter.add(3)  # 3 次协议探测（每类不超过一个 JSON-RPC 往返的探测序列）
    return result


async def _run_deep_probe_queue(parsed: Any, counter: _ProbeCounter, ctx: Any) -> None:
    """深度探测显式优先级队列（BL-036）。

    每个深度探测声明 ``(priority, cost)`` 二元组，按 priority 降序贪心入队：
    预算（``counter.can_deep_probe(cost)``，对齐 ``probe_budget["deep_probe_budget"]``）
    内**确定性**调度；预算不足时低优先级探测被**显式跳过并记录**（不再由代码书写顺序
    隐式决定"饥饿"）。``cost`` 为探测预算单元（≈实际请求数），已按真实请求数校准
    （deep_capabilities 此前声明 8，实测为单次能力探测通量，校准为 4；openapi 5→3）。
    """
    scheme = "https" if parsed.use_tls else "http"
    base_headers = {
        k: v
        for k, v in (getattr(parsed, "raw_headers", []) or [])
        if k.lower() not in ("content-length", "host")
    }
    rl_url = f"{scheme}://{parsed.host}{getattr(parsed, 'path', '') or '/'}"

    def _stealth() -> bool:
        if ctx is not None:
            policy = getattr(ctx, "stealth_policy", None)
            if isinstance(policy, dict) and policy.get("name") == "aggressive":
                return False
        return True

    async def _p_graphql() -> None:
        from recon.graphql_probe import is_graphql_signal, probe_graphql_endpoint

        summary = await probe_graphql_endpoint(
            f"{scheme}://{parsed.host}", headers=base_headers, verify=_TLS_VERIFY
        )
        counter.add_deep(2)
        passive = is_graphql_signal(
            path=getattr(parsed, "path", "") or "",
            body=getattr(parsed, "body", "") or "",
            headers=base_headers,
            content_type=getattr(parsed.target_fingerprint, "content_type", "") or "",
        )
        if summary.detected or passive:
            parsed.target_fingerprint.extra["graphql"] = {
                "detected": summary.detected,
                "passive_signal": passive,
                "endpoint": summary.endpoint,
                "introspection_enabled": summary.introspection_enabled,
                "types": summary.types[:40],
                "queries": summary.queries[:40],
                "mutations": summary.mutations[:40],
                "evidence": summary.evidence,
            }
            logger.info(
                "Background: GraphQL detected (introspection=%s, types=%d, passive=%s)",
                summary.introspection_enabled, len(summary.types), passive,
            )

    async def _p_rate_limit() -> None:
        from recon.waf_detector import probe_rate_limit

        rate_info = await probe_rate_limit(rl_url, headers=base_headers, verify=_TLS_VERIFY)
        counter.add_deep(1)
        parsed.target_fingerprint.extra["rate_limit_active"] = {
            "limited": rate_info.limited,
            "limit": rate_info.limit,
            "remaining": rate_info.remaining,
            "reset_seconds": rate_info.reset_seconds,
            "retry_after_seconds": rate_info.retry_after_seconds,
        }

    async def _p_deep_caps() -> None:
        from recon.capability_probe import deep_probe_capabilities

        deep_caps = await deep_probe_capabilities(parsed, stealth_mode=_stealth())
        counter.add_deep(4)
        if deep_caps:
            existing = parsed.target_fingerprint.extra.get("capabilities", "")
            all_caps = set(existing.split(",")) if existing else set()
            for cap_key in (
                "has_function_calling", "has_memory", "has_workflow", "has_multi_tenant",
                "has_session_auth", "has_mcp_protocol", "has_a2a_protocol", "has_embedding_rag",
            ):
                if deep_caps.get(cap_key):
                    all_caps.add(cap_key.replace("has_", ""))
            parsed.target_fingerprint.extra["capabilities"] = ",".join(sorted(all_caps))
            for k in ("secret_format", "tool_schemas", "model_family"):
                if deep_caps.get(k):
                    parsed.target_fingerprint.extra[k] = deep_caps[k]
            if deep_caps.get("session_type"):
                parsed.target_fingerprint.session_type = deep_caps["session_type"]
            for k in ("model_ids", "api_behavior", "capability_confidence", "capability_recommendations"):
                if deep_caps.get(k):
                    parsed.target_fingerprint.extra[k] = deep_caps[k]

    async def _p_openapi() -> None:
        from recon.api.openapi_discoverer import discover_openapi_spec

        openapi_result = await discover_openapi_spec(parsed, stealth_mode=_stealth())
        counter.add_deep(3)
        if openapi_result and openapi_result.endpoints:
            parsed.target_fingerprint.openapi_spec_path = openapi_result.spec_path
            parsed.target_fingerprint.openapi_endpoints = [
                {"path": ep.path, "method": ep.method, "summary": ep.summary}
                for ep in openapi_result.endpoints[:20]
            ]

    # (priority, cost, runner, name) — priority 降序贪心；cost 为预算单元
    tasks = [
        (90, 4, _p_deep_caps, "deep_capabilities"),
        (85, 2, _p_graphql, "graphql"),
        (80, 3, _p_openapi, "openapi"),
        (75, 1, _p_rate_limit, "rate_limit"),
    ]
    for priority, cost, runner, name in sorted(tasks, key=lambda t: -t[0]):
        if not counter.can_deep_probe(cost):
            logger.info(
                "Background: deep probe '%s' (cost=%d) skipped — deep_probe_budget exhausted",
                name, cost,
            )
            _log_probe_failure(ctx, name, RuntimeError("deep_probe_budget exhausted"), is_fatal=False)
            continue
        try:
            await runner()
        except Exception as e:
            logger.warning("Background: deep probe '%s' failed: %s", name, e)
            _log_probe_failure(ctx, name, e, is_fatal=False)


async def _run_background_probes(
    parsed: Any,
    counter: _ProbeCounter,
    ctx: Any = None,  # P2-07: PipelineContext, orchestration_log
    deep_probe: bool = False,
) -> None:
    """

     ( ASR ):
        1. probe_active_capabilities (agent/mcp/rag )
        2. MCP  ( MCP )
        3. system_prompt_extraction ()

    P0-02  ( deep_probe=True):
        - deep_probe_capabilities (8 converter(s))
        - OpenAPI  (API schema )
        - Confirmation (RAG )

    Args:
        parsed:  Burp
        counter: n        ctx:  PipelineContext (P2-07:  orchestration_log)
        deep_probe:  ( False)
    """
    logger.info("Background probes started (cap=%d)...", _MAX_PROBE_COUNT)

    # == P1-1: probe_active_capabilities (3 ) ==
    try:
        active_caps = await probe_active_capabilities(parsed)
        counter.add(3)
        if active_caps:
            # P1-05:
            existing_caps = parsed.target_fingerprint.extra.get("capabilities", "")
            all_caps = set(existing_caps.split(",")) if existing_caps else set()
            for cap_key, cap_val in active_caps.items():
                if cap_key == "model_family" and cap_val:
                    parsed.target_fingerprint.model_family = cap_val
                elif cap_val:
                    all_caps.add(cap_key)
            parsed.target_fingerprint.extra["capabilities"] = ",".join(sorted(all_caps))
            logger.info("Background: active probe detected: %s", sorted(all_caps))
    except Exception as e:
        # P2-07: orchestration_log ()
        logger.warning("Background: active probe failed: %s", e)
        _log_probe_failure(ctx, "active_capability", e, is_fatal=False)

    # == P1-2: MCP Enumeration (MCPSec v2.7.2) ==
    capabilities_str = parsed.target_fingerprint.extra.get("capabilities", "")
    if "mcp" in capabilities_str or "mcp_protocol" in capabilities_str:
        logger.info("MCP capability detected, launching MCPSec enumeration...")
        try:
            # Use MCPSec bridge for dynamic MCP reconnaissance
            target_url = getattr(ctx.args, "target_url", None) if hasattr(ctx, "args") else None
            if target_url:
                from strike.mcp.orchestrator import get_shared_bridge

                bridge = get_shared_bridge()
                if bridge.is_available:
                    mcp_info = await bridge.enumerate_surface(target_url)
                    tools = mcp_info.get("tools", [])
                    parsed.target_fingerprint.mcp_tools = tools
                    parsed.target_fingerprint.mcp_resources = mcp_info.get("resources", [])
                    parsed.target_fingerprint.mcp_prompts = mcp_info.get("prompts", [])
                    # Store MCPSec bridge reference for phase reuse
                    ctx.service_profile["mcpsec_enumerated"] = True
                    ctx.service_profile["mcpsec_tools_count"] = len(tools)
                    logger.info(
                        "Background: MCPSec enumeration: %d tools discovered",
                        len(tools),
                    )
                else:
                    # MCPSec 桥不可用 → 回退到本地 recon.mcp.* 专项侦察（BL-029 接线）
                    logger.info("MCPSec unavailable; falling back to local recon.mcp probes")
                    local_recon = await _probe_mcp_locally(parsed, counter, target_url)
                    ctx.service_profile["mcpsec_enumerated"] = bool(local_recon)
                    ctx.service_profile["mcp_local_recon"] = sorted(local_recon.keys())
                    logger.info("Background: local MCP recon produced %s", sorted(local_recon.keys()))
            else:
                logger.debug("No target_url set, skipping MCP enumeration")
        except Exception as e:
            logger.warning("Background: MCPSec MCP enumeration failed: %s", e)
            _log_probe_failure(ctx, "mcpsec_enum", e, is_fatal=False)

    # == P1-3: ( - ) ==
    if counter.can_probe(3, _MAX_PROBE_COUNT):
        try:
            from recon.model.system_prompt_extract import extract_system_prompt

            # Derive stealth_mode from ctx.stealth_policy
            stealth_mode = True
            if ctx is not None:
                policy = getattr(ctx, "stealth_policy", None)
                if isinstance(policy, dict) and policy.get("name") == "aggressive":
                    stealth_mode = False
            sp_result = await extract_system_prompt(parsed, stealth_mode=stealth_mode)
            counter.add(3)
            if sp_result.get("system_prompt_leaked"):
                # P1-05:
                parsed.target_fingerprint.system_prompt_leaked = True
                parsed.target_fingerprint.extracted_system_prompt = sp_result.get("extracted_system_prompt", "")
                parsed.target_fingerprint.system_prompt_extraction_method = sp_result.get("extraction_method", "")
                logger.warning(
                    "Background: System prompt LEAKED via %s (length=%d)",
                    sp_result.get("extraction_method"),
                    sp_result.get("system_prompt_length", 0),
                )
            else:
                parsed.target_fingerprint.system_prompt_leaked = False
        except Exception as e:
            # P2-07: orchestration_log ()
            logger.warning("Background: system prompt extraction failed: %s", e)
            _log_probe_failure(ctx, "system_prompt", e, is_fatal=False)

    # == 裸 URL 关联端点发现（REQ-160 ④ / BL-032）==
    # 从目标基础路径探测常见 API 文档与路由前缀，将发现的关联端点收敛进
    # `target_fingerprint.extra["related_endpoints"]`（recon 唯一输出总线，I12）。
    # 浅层、有界（默认词表 + 短超时 + 并发上限），失败不阻断主链路。
    try:
        from recon.api.url_endpoint_discoverer import discover_related_endpoints

        _scheme = "https" if parsed.use_tls else "http"
        _base_headers = {
            k: v
            for k, v in (getattr(parsed, "raw_headers", []) or [])
            if k.lower() not in ("content-length", "host")
        }
        related = await discover_related_endpoints(
            f"{_scheme}://{parsed.host}{getattr(parsed, 'path', '') or '/'}",
            headers=_base_headers,
            verify=_TLS_VERIFY,
        )
        if related:
            parsed.target_fingerprint.extra["related_endpoints"] = related
            logger.info("Background: discovered %d related endpoint(s)", len(related))
    except Exception as e:
        logger.debug("Background: related endpoint discovery skipped: %s", e)

    # == P2 ( deep_probe=True): ==
    if not deep_probe:
        logger.info("Background probes complete (deep probe disabled).")
        return

    # == 深度探测：显式优先级队列（BL-036，消除"顺序决定饥饿"）==
    # 每个深度探测声明 (priority, cost) 二元组，按 priority 降序贪心入队；
    # 预算（`probe_budget["deep_probe_budget"]`）内确定性调度，预算不足时低优先级探测
    # 被**显式跳过并记录**（不再由代码书写顺序隐式决定"饥饿"）。调度逻辑见
    # `_run_deep_probe_queue`（cost 已按真实请求数校准）。
    await _run_deep_probe_queue(parsed, counter, ctx)

    # v1.5: Health probe removed (80 API endpoints = over-engineering, no ASR contribution)
    # v1.5: Port expander + vector DB confirmation removed (60+ ports, DEPRECATED)

    logger.info("Background probes complete. Total probes: %d", counter.value)


# ====================================================================
# P0
# ====================================================================


async def _check_target_availability(parsed: Any) -> bool:
    """P0: API

    :
        1.  POST ,  stream=True
        2.  5s,  15s
        3.  HTTP  (200/400/401/403 )
        4. 402/503 = ; / =

    Args:
        parsed:  Burp

    Returns:
        True , False
    """
    import httpx

    scheme = "https" if parsed.use_tls else "http"
    check_url = f"{scheme}://{parsed.host}{parsed.path}"

    check_headers: dict[str, str] = {}
    for key, value in parsed.raw_headers:
        if key.lower() not in ("content-length", "host"):
            check_headers[key] = value

    from recon.capability_detector import _build_probe_body

    check_body = _build_probe_body(parsed, "hi")

    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(connect=5.0, read=15.0, write=5.0, pool=5.0),
            follow_redirects=True,
            verify=_TLS_VERIFY,
        ) as client:
            async with client.stream(
                method=parsed.method,
                url=check_url,
                headers=check_headers,
                content=check_body,
            ) as response:
                if response.status_code == 402:
                    logger.error("Target returned 402 Payment Required.")
                    return False
                if response.status_code == 503:
                    logger.error("Target returned 503 Service Unavailable.")
                    return False
                logger.info("Target availability check: HTTP %d (online)", response.status_code)
                return True

    except httpx.ConnectError as e:
        logger.error("Target connection refused: %s", e)
        return False
    except httpx.TimeoutException:
        logger.error("Target availability check timed out.")
        return False
    except Exception as e:
        logger.error("Target availability check failed: %s", e)
        return False
