# -*- coding: utf-8 -*-
"""
阶段 8：分析

汇总侦察数据并生成 TargetProfile：
  - 从网络拦截器提取 LLM API 端点、模型名、通信协议
  - 推断部署平台、模型族、提供商
  - 识别 RAG / Agent 特征
  - 评估攻击面与风险等级并生成攻击建议
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Dict, List

from src.auth import extract_domain_from_url
from src.network import TrafficAnalyzer
from src.recon import TargetProfile
from src.utils import truncate_error

from ..base import PipelineStage
from ..context import PipelineContext, StageResult

logger = logging.getLogger(__name__)


class AnalysisStage(PipelineStage):
    """分析阶段：汇总侦察数据生成 TargetProfile"""

    name = "analysis"
    description = "分析流量、提取模型名与攻击面"

    async def run(self, context: PipelineContext) -> StageResult:
        network_cfg = self._config(context, "network", {})
        analyzer = TrafficAnalyzer(config=network_cfg)
        profile = context.profile or TargetProfile(target=context.target_url, target_type=context.target_type)
        context.profile = profile
        profile.created_at = datetime.now().isoformat()

        # 1. 基础指纹
        await self._apply_basic_fingerprint(context, profile)

        # 2. 网络流量分析
        interceptor = context.interceptor
        api_probe_result = context.config.get("api_probe_result") or {}

        captured: List[Dict[str, Any]] = []
        if interceptor:
            captured = getattr(interceptor, "captured", []) or []
        elif api_probe_result:
            captured = api_probe_result.get("entries", [])

        llm_endpoints = [e for e in captured if e.get("is_llm_api")]

        # 3. 更新指纹
        profile.fingerprint.llm_api_endpoints = llm_endpoints
        profile.fingerprint.model_name = self._extract_model_name(analyzer, captured, api_probe_result)
        profile.fingerprint.model_family = self._infer_model_family(profile.fingerprint.model_name)
        profile.fingerprint.deployment_platform = self._detect_deployment_platform(analyzer, captured, context.target_url)
        profile.fingerprint.provider = self._infer_provider(
            profile.fingerprint.deployment_platform,
            profile.fingerprint.model_name,
            captured,
        )
        profile.fingerprint.protocols = self._extract_protocols(analyzer, captured)
        profile.fingerprint.rag_features = self._flatten_features(captured, "rag_features")
        profile.fingerprint.agent_features = self._flatten_features(captured, "agent_features")
        profile.fingerprint.extracted_credentials = self._extract_credentials(captured)
        profile.fingerprint.chat_urls = analyzer.detect_chat_urls(captured)
        profile.fingerprint.llm_features = analyzer.aggregate_llm_features(captured)
        profile.fingerprint.capabilities = self._infer_capabilities(captured)

        # 4. 探测响应与 DOM 响应容器
        profile.fingerprint.response_containers = self._collect_response_containers(context)
        profile.raw_results["probe_responses"] = context.config.get("probe_responses", [])

        # 5. 生成攻击入口点
        self._build_entry_points(profile, captured, context)

        # 6. 推断攻击面与漏洞
        self._infer_surfaces_and_vulns(profile)

        # 7. 生成攻击建议
        profile.attack_recommendations = self._generate_attack_recommendations(profile)

        # 8. 风险定级
        profile.risk_level = profile.classify_risk()

        # 9. 流量摘要
        profile.raw_results["traffic_summary"] = self._build_traffic_summary(captured, llm_endpoints)

        return StageResult(
            success=True,
            message=f"分析完成: 模型={profile.fingerprint.model_name or '未知'}, 平台={profile.fingerprint.deployment_platform}, API端点={len(llm_endpoints)}",
            data={
                "model_name": profile.fingerprint.model_name,
                "model_family": profile.fingerprint.model_family,
                "provider": profile.fingerprint.provider,
                "deployment_platform": profile.fingerprint.deployment_platform,
                "protocols": profile.fingerprint.protocols,
                "llm_endpoints_count": len(llm_endpoints),
                "rag_features_count": len(profile.fingerprint.rag_features),
                "agent_features_count": len(profile.fingerprint.agent_features),
                "risk_level": profile.risk_level,
            },
        )

    async def _apply_basic_fingerprint(self, context: PipelineContext, profile: TargetProfile) -> None:
        """从页面上下文补充基础指纹"""
        page = context.page
        if page:
            try:
                profile.fingerprint.url = page.url
                profile.fingerprint.title = await page.title()
                profile.fingerprint.domain = extract_domain_from_url(page.url)
            except Exception as exc:
                logger.warning("Failed to apply basic fingerprint: %s", truncate_error(str(exc), context.config))
        else:
            profile.fingerprint.url = context.target_url
            profile.fingerprint.domain = extract_domain_from_url(context.target_url)

        detection = context.detection or {}
        if detection:
            profile.fingerprint.detected_selectors = detection

    def _extract_model_name(
        self,
        analyzer: TrafficAnalyzer,
        captured: List[Dict[str, Any]],
        api_probe_result: Dict[str, Any],
    ) -> str:
        """提取模型名：拦截流量优先，API 探测结果兜底"""
        for entry in captured:
            model = entry.get("model_name")
            if model:
                return model
        return api_probe_result.get("model_name", "")

    def _infer_model_family(self, model_name: str) -> str:
        """根据模型名推断模型族"""
        if not model_name:
            return ""
        lower = model_name.lower()
        if "deepseek" in lower:
            return "deepseek"
        if "qwen" in lower or "tongyi" in lower:
            return "qwen"
        if "gpt" in lower or "o1" in lower or "o3" in lower:
            return "openai_gpt"
        if "claude" in lower:
            return "claude"
        if "gemini" in lower:
            return "gemini"
        if "kimi" in lower or "moonshot" in lower:
            return "moonshot"
        if "chatglm" in lower or "glm" in lower:
            return "chatglm"
        if "wenxin" in lower or "ernie" in lower:
            return "ernie"
        if "xinghuo" in lower or "spark" in lower:
            return "spark"
        if "llama" in lower:
            return "llama"
        if "qwq" in lower:
            return "qwen"
        return ""

    def _infer_provider(self, deployment_platform: str, model_name: str, captured: List[Dict[str, Any]]) -> str:
        """根据部署平台和模型名推断服务提供商"""
        if deployment_platform and deployment_platform != "unknown":
            platform_map = {
                "aliyun": "aliyun",
                "baidu": "baidu",
                "iflytek": "iflytek",
                "moonshot": "moonshot",
                "zhipu": "zhipu",
                "deepseek": "deepseek",
                "openai": "openai",
                "azure_openai": "azure_openai",
                "anthropic": "anthropic",
                "google": "google",
                "aws_bedrock": "aws",
                "cloudflare": "cloudflare",
                "ollama": "ollama",
            }
            if deployment_platform in platform_map:
                return platform_map[deployment_platform]

        # 从模型名兜底
        lower = model_name.lower() if model_name else ""
        if "deepseek" in lower:
            return "deepseek"
        if "qwen" in lower or "tongyi" in lower:
            return "aliyun"
        if "kimi" in lower or "moonshot" in lower:
            return "moonshot"

        # 从 LLM API 域名兜底
        for entry in captured:
            if not entry.get("is_llm_api"):
                continue
            url = entry.get("url", "").lower()
            if "volcengine" in url or "volces" in url:
                return "volcengine"
            if "openai" in url:
                return "openai"
            if "aliyun" in url or "dashscope" in url:
                return "aliyun"
            if "baidu" in url or "qianfan" in url:
                return "baidu"
            if "moonshot" in url:
                return "moonshot"
            if "deepseek" in url:
                return "deepseek"

        return ""

    def _extract_protocols(
        self,
        analyzer: TrafficAnalyzer,
        captured: List[Dict[str, Any]],
    ) -> List[str]:
        """提取通信协议列表"""
        protocols = set()
        for entry in captured:
            protocol = entry.get("protocol")
            if protocol:
                protocols.add(protocol)
            if analyzer.is_streaming_response(entry.get("response_headers", {})):
                protocols.add("sse")
        return sorted(protocols)

    def _infer_capabilities(self, captured: List[Dict[str, Any]]) -> Dict[str, Any]:
        """从请求体中推断模型能力参数，如 stream（大小写不敏感）"""
        capabilities: Dict[str, Any] = {}
        for entry in captured:
            if not entry.get("is_llm_api"):
                continue
            body = entry.get("request_body", "")
            try:
                import json
                data = json.loads(body)
                if not isinstance(data, dict):
                    continue
                # 大小写不敏感键映射
                key_map = {k.lower(): k for k in data.keys() if isinstance(k, str)}
                for canon, target in [("stream", "stream"), ("temperature", "temperature"), ("max_tokens", "max_tokens")]:
                    actual = key_map.get(canon)
                    if actual is not None and data[actual] is not None:
                        capabilities[target] = data[actual]
            except Exception:
                continue
        return capabilities

    def _flatten_features(
        self,
        captured: List[Dict[str, Any]],
        feature_key: str,
    ) -> List[Dict[str, Any]]:
        """将拦截流量中的特征列表扁平化"""
        results: List[Dict[str, Any]] = []
        seen = set()
        for entry in captured:
            url = entry.get("url", "")
            features = entry.get(feature_key, [])
            if not features:
                continue
            for feature in features:
                signature = (url, feature.get("keyword", ""))
                if signature in seen:
                    continue
                seen.add(signature)
                results.append({"url": url, **feature})
        return results

    def _extract_credentials(self, captured: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """汇总提取到的凭据线索"""
        results: List[Dict[str, Any]] = []
        seen = set()
        for entry in captured:
            keys = entry.get("api_keys", [])
            if not keys:
                continue
            url = entry.get("url", "")
            if url in seen:
                continue
            seen.add(url)
            results.append({"url": url, "keys": keys})
        return results

    def _detect_deployment_platform(
        self,
        analyzer: TrafficAnalyzer,
        captured: List[Dict[str, Any]],
        target_url: str,
    ) -> str:
        """推断部署平台"""
        # 优先根据 LLM API URL 推断
        for entry in captured:
            if entry.get("is_llm_api"):
                platform = analyzer.detect_deployment_platform(entry.get("url", ""))
                if platform != "unknown":
                    return platform
        # 兜底根据目标 URL 推断
        return analyzer.detect_deployment_platform(target_url)

    def _build_entry_points(
        self,
        profile: TargetProfile,
        captured: List[Dict[str, Any]],
        context: PipelineContext,
    ) -> None:
        """构建攻击入口点"""
        seen_urls = set()

        # API 入口
        for entry in captured:
            if not entry.get("is_llm_api"):
                continue
            url = entry.get("url", "")
            if url in seen_urls:
                continue
            seen_urls.add(url)
            profile.add_entry_point(
                entry_type="api",
                url=url,
                api_type=entry.get("api_type", "unknown"),
                model_name=entry.get("model_name", ""),
                score=0.95,
                extra={
                    "method": entry.get("method"),
                    "status": entry.get("response_status"),
                    "protocol": entry.get("protocol"),
                    "rag_features": entry.get("rag_features", []),
                    "agent_features": entry.get("agent_features", []),
                },
            )

        # Web UI 入口
        detection = context.detection or {}
        if detection.get("input_selector"):
            profile.add_entry_point(
                entry_type="web_ui",
                selector=detection["input_selector"],
                score=detection.get("input_score", 0.0),
                extra={
                    "send_selector": detection.get("send_selector"),
                    "send_score": detection.get("send_score"),
                    "response_selector": detection.get("response_selector"),
                    "response_score": detection.get("response_score"),
                    "chat_entry": context.chat_entry,
                },
            )

    def _collect_response_containers(self, context: PipelineContext) -> List[Dict[str, Any]]:
        """收集探测阶段捕获的 DOM 响应容器"""
        send_result = context.send_result or {}
        return send_result.get("response_containers", []) or []

    def _build_traffic_summary(
        self,
        captured: List[Dict[str, Any]],
        llm_endpoints: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """生成流量摘要"""
        rag_endpoints = [e for e in captured if e.get("rag_features")]
        return {
            "total_requests": len(captured),
            "total_responses": len(captured),
            "llm_api_calls": len(llm_endpoints),
            "rag_api_calls": len(rag_endpoints),
            "primary_llm_endpoint": llm_endpoints[0].get("url", "") if llm_endpoints else "",
            "llm_endpoints": [e.get("url", "") for e in llm_endpoints],
            "rag_endpoints": [e.get("url", "") for e in rag_endpoints],
            "websocket_connections": 0,
            "websocket_messages": 0,
        }

    def _infer_surfaces_and_vulns(self, profile: TargetProfile) -> None:
        """推断攻击面并添加漏洞发现"""
        has_chat = any(ep["type"] == "web_ui" for ep in profile.entry_points)
        has_api = bool(profile.fingerprint.llm_api_endpoints)
        has_rag = bool(profile.fingerprint.rag_features)
        has_agent = bool(profile.fingerprint.agent_features)
        has_credentials = bool(profile.fingerprint.extracted_credentials)

        surfaces: List[str] = []
        if has_chat:
            surfaces.extend(["prompt", "prompt_injection", "jailbreak"])
        if has_api:
            surfaces.extend(["api_prompt_injection", "model_extraction"])
        if has_rag:
            surfaces.extend(["rag", "rag_poisoning", "knowledge_base_extraction"])
        if has_agent:
            surfaces.extend(["agent", "agent_tool_misuse", "mcp_hijacking"])
        if has_credentials:
            surfaces.append("credential_exposure")

        # 去重保持顺序
        seen = set()
        unique: List[str] = []
        for s in surfaces:
            if s not in seen:
                seen.add(s)
                unique.append(s)
        profile.surfaces = unique

        # 漏洞记录
        if has_api:
            for ep in profile.fingerprint.llm_api_endpoints:
                profile.add_vulnerability(
                    owasp_category="LLM01:2025 - Prompt Injection",
                    description=f"LLM API endpoint detected: {ep.get('url', '')}",
                    evidence={
                        "url": ep.get("url", ""),
                        "method": ep.get("method", ""),
                        "model": ep.get("model_name", ""),
                        "streaming": "sse" in (ep.get("protocol", "") or ""),
                    },
                    risk_level="medium",
                    remediation="Restrict API endpoint exposure and validate all user inputs server-side.",
                )
            if not profile.fingerprint.model_name:
                profile.add_vulnerability(
                    owasp_category="LLM06:2025 - Sensitive Information Disclosure",
                    description="LLM API endpoint exposed but model name could not be determined.",
                    evidence={"endpoints": [ep.get("url") for ep in profile.fingerprint.llm_api_endpoints]},
                    risk_level="medium",
                    remediation="Restrict API endpoint exposure and avoid returning model metadata in error responses.",
                )

        if profile.fingerprint.model_name:
            profile.add_vulnerability(
                owasp_category="LLM02:2025 - Sensitive Information Disclosure",
                description=f"Backend LLM model identified: {profile.fingerprint.model_name}",
                evidence={"model": profile.fingerprint.model_name, "provider": profile.fingerprint.provider},
                risk_level="low",
                remediation="Avoid exposing model names in client-facing requests or responses.",
            )

        if "stream" in profile.fingerprint.capabilities:
            profile.add_vulnerability(
                owasp_category="",
                description="Target LLM API supports streaming (SSE).",
                evidence={"stream": profile.fingerprint.capabilities["stream"]},
                risk_level="low",
                remediation="",
            )

        if has_rag:
            profile.add_vulnerability(
                owasp_category="LLM08:2025 - Vector and Embedding Weaknesses",
                description="RAG components detected, potential knowledge base poisoning or extraction.",
                evidence={"rag_features": profile.fingerprint.rag_features},
                risk_level="high",
                remediation="Validate retrieval sources and enforce access control on knowledge base endpoints.",
            )

        if has_agent:
            profile.add_vulnerability(
                owasp_category="LLM09:2025 - Agent Authorization",
                description="Agent / Copilot / MCP components detected, potential tool misuse or hijacking.",
                evidence={"agent_features": profile.fingerprint.agent_features},
                risk_level="high",
                remediation="Restrict agent tool access and validate tool call authorization.",
            )

        if has_credentials:
            profile.add_vulnerability(
                owasp_category="LLM06:2025 - Sensitive Information Disclosure",
                description="Authentication tokens or API keys observed in intercepted traffic.",
                evidence={"credentials": profile.fingerprint.extracted_credentials},
                risk_level="high",
                remediation="Rotate exposed credentials and avoid transmitting long-lived API keys in client-side requests.",
            )

    def _generate_attack_recommendations(self, profile: TargetProfile) -> List[str]:
        """根据攻击面生成攻击建议"""
        recommendations: List[str] = []
        has_api = bool(profile.fingerprint.llm_api_endpoints)
        has_rag = bool(profile.fingerprint.rag_features)
        has_streaming = "sse" in profile.fingerprint.protocols or profile.fingerprint.capabilities.get("stream")

        if has_api:
            recommendations.append("LLM01 Prompt Injection → 直接注入攻击（DIRECT_SINGLE）")
            recommendations.append("LLM02 Sensitive Info → 开放式探索（EXPLORATORY）")
        if has_rag:
            recommendations.append("LLM04 Insecure Output → 直接注入攻击（DIRECT_SINGLE）")
            recommendations.append("目标包含 RAG，增加上下文溢出攻击 + RAG 投毒")
        if has_streaming:
            recommendations.append("支持流式响应，增加流式注入检测")
        return recommendations
