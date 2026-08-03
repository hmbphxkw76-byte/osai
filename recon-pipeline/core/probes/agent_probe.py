# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""AgentProbe: 增强型 Agent 工具侦察探针 (v2.0).

职责 (六层侦察能力):
  1. 被动筛选: 从 NetworkInterceptor 结果中过滤 AGENT_TOOL_API 端点
  2. 主动探测: Agent 框架握手 + 工具枚举 + 会话多轮交互
  3. 框架指纹: 6 类 Agent 框架识别 (LangChain/AutoGen/CrewAI/SK/BeeAI/OpenAI Agents SDK)
  4. 错误分类: 集成 ErrorClass 诊断 (8 类错误分类 + 3 级 5xx 延迟分层)
  5. 响应指纹: SHA256 去重 + 噪声归一化 + 行为变更检测
  6. 过度代理: 委托 ToolPermissionAnalyzer 构建工具权限矩阵 (LLM06)

学术依据:
  - OWASP LLM06: Excessive Agency — 活跃会话中发现的高权限工具
  - OWASP LLM01: 间接注入操控 Agent 工具
  - MITRE ATT&CK T1059: Command and Scripting Interpreter
  - RedAmon ai_surface_recon.py 7 类工作负载对齐

v2.0 变更 (2026-08-03):
  - 从被动筛选升级为主动多轮会话探测
  - 集成 error_class.py / response_fingerprint.py
  - 框架指纹通过 ProbePackEngine (YAML) 实现
  - 诊断能力: response_class, duration_ms, error_class 字段

> **日期**: 2026-8-3
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
import time
from typing import TYPE_CHECKING, Any

import httpx

from core.models.recon_report import DiscoveredEndpoint, EndpointType
from core.probes.base import ReconProbe
from core.probes.error_class import (
    ErrorClass,
    classify_http_response,
    error_class_severity,
    is_recoverable_error,
)
from core.probes.response_fingerprint import (
    fingerprint_response,
    fingerprint_text,
    FingerprintSet,
)
from core.probes.tool_permission_matrix import (
    ToolActionType,
    ToolPermission,
    ToolPermissionAnalyzer,
    ToolPermissionMatrix,
    ToolRiskLevel,
)
from core.probes.mcp_yara import scan_mcp_text

if TYPE_CHECKING:
    from core.session import ReconSession

logger = logging.getLogger(__name__)

# ── Agent framework detection: URL + body patterns ──
# 6 families × (URL regex, body regex, framework_name, category)

_AGENT_FRAMEWORK_PATTERNS: list[tuple[re.Pattern[str], re.Pattern[str], str, str]] = [
    # LangChain / LangGraph
    (re.compile(r"(langchain|langgraph|langserve)", re.I),
     re.compile(r"(langchain|langgraph|langserve|langchain_core|langsmith)", re.I),
     "LangChain", "agent-framework"),
    # Microsoft AutoGen
    (re.compile(r"(autogen|ag2|groupchat)", re.I),
     re.compile(r"(autogen|pyautogen|microsoft/autogen|groupchat_manager|speaker_selection)", re.I),
     "Microsoft AutoGen", "agent-framework"),
    # CrewAI
    (re.compile(r"(crewai|crew\.kickoff|crews/)", re.I),
     re.compile(r"(crewai|crewAI|from crewai import|manager_llm|hierarchical)", re.I),
     "CrewAI", "agent-framework"),
    # Microsoft Semantic Kernel
    (re.compile(r"(semantic[\-_]?kernel|kernel[\-_]?plugin|kernel[\-_]?process)", re.I),
     re.compile(r"(Microsoft\.SemanticKernel|semantic-kernel|@microsoft/semantic-kernel|KernelFunction|KernelProcess)", re.I),
     "Microsoft Semantic Kernel", "agent-framework"),
    # BeeAI (IBM)
    (re.compile(r"(beeai|bee[\-_]agent)", re.I),
     re.compile(r"(beeai|bee-agent|@i-am-bee/beeai|BeeAgent|UnconstrainedMemory)", re.I),
     "IBM BeeAI", "agent-framework"),
    # OpenAI Agents SDK / Swarm
    (re.compile(r"(openai[\-_]agents|openai[\-_]swarm|handoff)", re.I),
     re.compile(r"(openai-agents|openai_agents|from agents import|openai-swarm|Swarm|handoff|@function_tool|FunctionTool)", re.I),
     "OpenAI Agents SDK", "agent-framework"),
]

# ── Active agent handshake paths ──

_AGENT_HANDSHAKE_PATHS: list[str] = [
    "/api/agents",
    "/api/v1/agents",
    "/agent/invoke",
    "/invoke",
    "/api/tools",
    "/api/tools/list",
    "/api/v1/tools",
    "/runs",
    "/api/v1/crews",
]

# ── Agent conversation probe payloads (OWASP LLM01 injection surfaces) ──

_AGENT_PROBE_PAYLOADS: list[dict[str, Any]] = [
    {"input": "ping"},
    {"message": "ping"},
    {"query": "hello"},
    {"prompt": "test"},
    {"messages": [{"role": "user", "content": "ping"}]},
    {"inputs": {"query": "ping"}},
]


class AgentProbe(ReconProbe):
    """增强型 Agent 工具侦察探针。

    六层侦察: 被动筛选 → 主动探测 → 框架指纹 → 错误分类 → 响应指纹 → 过度代理。

    用法::
        probe = AgentProbe(active_timeout=10.0, max_conversation_rounds=3)
        result = await probe.probe(session)
        # result["endpoints"] → Agent Tool API 端点
        # result["agent_frameworks"] → 框架指纹
        # result["diagnostics"] → 错误分类 + 延迟统计
        # result["tool_permission_matrix"] → 工具权限矩阵
        # result["fingerprints"] → 响应指纹集合
    """

    def __init__(
        self,
        active_timeout: float = 10.0,
        max_conversation_rounds: int = 2,
        enable_active_probing: bool = True,
    ) -> None:
        self._active_timeout = active_timeout
        self._max_rounds = max_conversation_rounds
        self._enable_active = enable_active_probing
        self._analyzer = ToolPermissionAnalyzer()
        self._fingerprints = FingerprintSet()

    @property
    def name(self) -> str:
        return "AgentProbe"

    @property
    def requires_browser(self) -> bool:
        return True

    async def probe(self, session: ReconSession) -> dict[str, Any]:
        """执行 Agent 探针。

        Args:
            session: 侦察会话。

        Returns:
            包含 endpoints, agent_frameworks, diagnostics, tool_permission_matrix,
            fingerprints 的结果字典。
        """
        start_time = time.monotonic()

        # ── Layer 1: Passive filtering ──
        agent_endpoints = [
            e for e in session.report.endpoints
            if e.endpoint_type == EndpointType.AGENT_TOOL_API
        ]

        # ── Layer 2: Framework fingerprinting (passive, from URL/body) ──
        frameworks = self._fingerprint_frameworks(agent_endpoints)

        # ── Layer 3: Active probing (handshake + conversation rounds) ──
        active_results: list[dict[str, Any]] = []
        if self._enable_active and agent_endpoints:
            headers = session.auth_headers if session.auth_state else {}
            active_results = await self._active_agent_probe(agent_endpoints, headers)

        # ── Layer 4: Error class diagnosis ──
        diagnostics = self._diagnose_endpoints(agent_endpoints, active_results)

        # ── Layer 5: Response fingerprinting ──
        fingerprints = self._compute_fingerprints(agent_endpoints, active_results)

        # ── Layer 6: Over-agency analysis ──
        matrix = None
        if agent_endpoints:
            matrix = self._analyzer.analyze(agent_endpoints)
            # Enrich with error classes and fingerprints
            self._enrich_matrix(matrix, diagnostics, fingerprints)

        elapsed = time.monotonic() - start_time

        logger.info(
            "AgentProbe: %d agent endpoints, %d frameworks, "
            "%d active probes, score=%d, elapsed=%.1fs",
            len(agent_endpoints), len(frameworks),
            len(active_results),
            matrix.over_agency_score if matrix else 0,
            elapsed,
        )

        return {
            "endpoints": agent_endpoints,
            "agent_frameworks": frameworks,
            "diagnostics": diagnostics,
            "tool_permission_matrix": matrix.to_dict() if matrix else {},
            "fingerprints": fingerprints.to_dict(),
            "summary": {
                "agent_endpoint_count": len(agent_endpoints),
                "framework_count": len(frameworks),
                "active_probe_count": len(active_results),
                "unique_fingerprints": len(fingerprints.fingerprints),
                "over_agency_score": matrix.over_agency_score if matrix else 0,
                "critical_tools": matrix.critical_count if matrix else 0,
                "high_risk_tools": matrix.high_count if matrix else 0,
                "elapsed_seconds": round(elapsed, 2),
            },
        }

    # ── Layer 2: Framework fingerprinting ──────────────────────────────────

    def _fingerprint_frameworks(
        self, endpoints: list[DiscoveredEndpoint],
    ) -> list[dict[str, str]]:
        """Detect agent frameworks from URL paths and response body markers.

        Returns list of {framework_name, category, evidence_url, confidence}.
        """
        seen: set[str] = set()
        results: list[dict[str, str]] = []

        for ep in endpoints:
            url = ep.url
            body = ep.response_body_preview or ""

            for url_pat, body_pat, fw_name, fw_cat in _AGENT_FRAMEWORK_PATTERNS:
                if fw_name in seen:
                    continue
                url_match = url_pat.search(url)
                body_match = body_pat.search(body) if body else False
                if url_match or body_match:
                    confidence = "high" if (url_match and body_match) else "medium"
                    evidence = []
                    if url_match:
                        evidence.append(f"URL: {url_match.group()}")
                    if body_match:
                        evidence.append(f"Body: {body_match.group()}")
                    results.append({
                        "framework_name": fw_name,
                        "category": fw_cat,
                        "evidence_url": url,
                        "confidence": confidence,
                        "evidence": "; ".join(evidence),
                    })
                    seen.add(fw_name)

        logger.info("AgentProbe: fingerprinted %d agent frameworks", len(results))
        return results

    # ── Layer 3: Active probing ────────────────────────────────────────────

    async def _active_agent_probe(
        self,
        agent_endpoints: list[DiscoveredEndpoint],
        headers: dict[str, str],
    ) -> list[dict[str, Any]]:
        """Perform active handshake and multi-round conversation probing.

        1. Discover candidate base URLs + agent handshake paths
        2. Execute handshake (GET) to confirm agent API
        3. Execute conversation rounds with varied payloads
        4. Record timing, status, errors for diagnostics
        """
        results: list[dict[str, Any]] = []

        # Build candidate probe URLs
        candidates = self._build_agent_candidates(agent_endpoints)

        async with httpx.AsyncClient(
            timeout=self._active_timeout,
            verify=False,
            follow_redirects=False,
        ) as client:
            for candidate in candidates:
                url = candidate["url"]
                method = candidate.get("method", "GET")
                payload = candidate.get("payload")

                t0 = time.monotonic()
                try:
                    if method == "POST" and payload:
                        resp = await client.post(
                            url,
                            json=payload,
                            headers=headers,
                        )
                    else:
                        resp = await client.get(url, headers=headers)

                    duration_ms = int((time.monotonic() - t0) * 1000)
                    body = resp.text[:2000]
                    error_class = classify_http_response(
                        status_code=resp.status_code,
                        body=body,
                        duration_ms=duration_ms,
                    )
                    fp = fingerprint_response(
                        body=body,
                        status_code=resp.status_code,
                        headers=dict(resp.headers),
                    )

                    results.append({
                        "url": url,
                        "method": method,
                        "status_code": resp.status_code,
                        "duration_ms": duration_ms,
                        "error_class": error_class,
                        "fingerprint": fp,
                        "body_preview": body[:200],
                        "recoverable": is_recoverable_error(error_class),
                        "severity": error_class_severity(error_class),
                        "payload": str(payload)[:100] if payload else None,
                    })
                except (httpx.RequestError, asyncio.TimeoutError) as exc:
                    duration_ms = int((time.monotonic() - t0) * 1000)
                    results.append({
                        "url": url,
                        "method": method,
                        "status_code": None,
                        "duration_ms": duration_ms,
                        "error_class": ErrorClass.TRANSPORT.value,
                        "error_message": str(exc)[:200],
                        "fingerprint": "",
                        "body_preview": "",
                        "recoverable": True,
                        "severity": error_class_severity(ErrorClass.TRANSPORT.value),
                        "payload": str(payload)[:100] if payload else None,
                    })

        logger.info(
            "AgentProbe: %d active probes executed across %d candidates",
            len(results), len(candidates),
        )
        return results

    def _build_agent_candidates(
        self, endpoints: list[DiscoveredEndpoint],
    ) -> list[dict[str, Any]]:
        """Build candidate probe URLs from discovered endpoints."""
        from urllib.parse import urlparse

        # Collect unique base URLs
        bases: set[str] = set()
        for ep in endpoints:
            parsed = urlparse(ep.url)
            base = f"{parsed.scheme}://{parsed.netloc}"
            bases.add(base)

        candidates: list[dict[str, Any]] = []

        # 1. Handshake paths on each base
        for base in bases:
            for path in _AGENT_HANDSHAKE_PATHS:
                candidates.append({
                    "url": f"{base.rstrip('/')}{path}",
                    "method": "GET",
                })

        # 2. Conversation probes on each endpoint
        for ep in endpoints:
            for payload in _AGENT_PROBE_PAYLOADS:
                candidates.append({
                    "url": ep.url,
                    "method": "POST",
                    "payload": payload,
                })

        # Deduplicate by (url, method) — keep first
        seen: set[tuple[str, str]] = set()
        unique: list[dict[str, Any]] = []
        for c in candidates:
            key = (c["url"], c["method"])
            if key not in seen:
                seen.add(key)
                unique.append(c)

        return unique

    # ── Layer 4: Error class diagnostics ───────────────────────────────────

    def _diagnose_endpoints(
        self,
        passive: list[DiscoveredEndpoint],
        active: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Aggregate error class diagnostics across passive + active results."""
        error_counts: dict[str, int] = {}
        total_duration = 0
        total_requests = 0
        min_duration = float("inf")
        max_duration = 0

        # Passive endpoints
        for ep in passive:
            if ep.status_code and ep.duration_ms:
                ec = ep.response_class or classify_http_response(
                    status_code=ep.status_code,
                    body=ep.response_body_preview,
                    duration_ms=ep.duration_ms,
                )
                error_counts[ec] = error_counts.get(ec, 0) + 1
                total_duration += ep.duration_ms
                total_requests += 1
                if ep.duration_ms < min_duration:
                    min_duration = ep.duration_ms
                if ep.duration_ms > max_duration:
                    max_duration = ep.duration_ms

        # Active probes
        for r in active:
            ec = r.get("error_class", ErrorClass.TRANSPORT.value)
            error_counts[ec] = error_counts.get(ec, 0) + 1
            dur = r.get("duration_ms", 0)
            total_duration += dur
            total_requests += 1
            if dur < min_duration:
                min_duration = dur
            if dur > max_duration:
                max_duration = dur

        # Health score: weighted by severity
        health_score = 100
        for ec, count in error_counts.items():
            health_score -= error_class_severity(ec) * count
        health_score = max(0, min(100, health_score))

        return {
            "error_class_distribution": error_counts,
            "health_score": health_score,
            "total_requests": total_requests,
            "total_duration_ms": total_duration,
            "avg_duration_ms": total_duration // total_requests if total_requests else 0,
            "min_duration_ms": int(min_duration) if total_requests else 0,
            "max_duration_ms": max_duration,
            "recoverable_count": sum(
                count for ec, count in error_counts.items()
                if is_recoverable_error(ec)
            ),
            "non_recoverable_count": sum(
                count for ec, count in error_counts.items()
                if not is_recoverable_error(ec) and ec != ErrorClass.SUCCESS.value
            ),
        }

    # ── Layer 5: Response fingerprinting ───────────────────────────────────

    def _compute_fingerprints(
        self,
        passive: list[DiscoveredEndpoint],
        active: list[dict[str, Any]],
    ) -> FingerprintSet:
        """Compute composite fingerprints for dedup and change detection."""
        fps = FingerprintSet()

        for ep in passive:
            fp = fingerprint_response(
                body=ep.response_body_preview,
                status_code=ep.status_code,
            )
            fps.add(ep.url, ep.response_body_preview, ep.status_code)

        for r in active:
            fp = r.get("fingerprint", "")
            if fp:
                url = r.get("url", f"active-{len(fps.fingerprints)}")
                fps.add(url, r.get("body_preview", ""), r.get("status_code"))

        logger.debug(
            "AgentProbe: computed %d fingerprints, %d unique",
            len(passive) + len(active),
            len(set(fps.fingerprints.values())),
        )
        return fps

    # ── Layer 6: Matrix enrichment ─────────────────────────────────────────

    def _enrich_matrix(
        self,
        matrix: ToolPermissionMatrix,
        diagnostics: dict[str, Any],
        fingerprints: FingerprintSet,
    ) -> None:
        """Enrich ToolPermission entries with error classes and fingerprints."""
        for tool in matrix.tools:
            # Attach fingerprint if available
            fp = fingerprints.fingerprints.get(tool.endpoint_url, "")
            if fp:
                tool.response_fingerprint = fp

            # Infer error class from diagnostics
            # If endpoint had errors, mark the tool
            error_dist = diagnostics.get("error_class_distribution", {})
            if error_dist:
                # Use the dominant error class (most frequent non-success)
                dominant = ErrorClass.SUCCESS.value
                dominant_count = 0
                for ec, count in error_dist.items():
                    if ec != ErrorClass.SUCCESS.value and count > dominant_count:
                        dominant = ec
                        dominant_count = count
                if dominant != ErrorClass.SUCCESS.value:
                    tool.error_class = dominant
