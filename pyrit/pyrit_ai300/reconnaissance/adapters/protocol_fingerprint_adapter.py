# -*- coding: utf-8 -*-
"""
AI-300 Framework - Protocol Fingerprint Adapter
协议指纹适配器：探测目标 AI 框架/协议类型（AIMAP 指纹逻辑，无 Shodan 依赖）

设计原则：
- 零外部依赖：仅使用 stdlib urllib（通过 http_client.py）
- 被动探测：发送 HTTP 请求识别框架，不执行攻击
- 填充 TargetProfile：fingerprint + surfaces + entry_points

支持的协议检测：
  - MCP (Model Context Protocol)：SSE transport, JSON-RPC
  - Ollama：/api/tags, /api/show, /api/generate
  - vLLM / LiteLLM：/v1/models, /v1/chat/completions
  - LangServe / LangChain：/playground, /invoke
  - Gradio：API endpoints, title markers
  - Streamlit：HTML markers
  - Open WebUI / LibreChat：title markers
  - HuggingFace TGI：HTML markers
  - Generic OpenAI-compat：/v1/models
"""

from __future__ import annotations

import logging
import os
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

from .base_adapter import AdapterResult, BaseAdapter
from ..utils.http_client import http_get, http_post

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    os.environ["PYTHONIOENCODING"] = "utf-8"

logger = logging.getLogger(__name__)

# ── 协议检测规则 ──
# 每个协议：(检测路径, 匹配条件, 协议名称, 攻击面列表)
PROTOCOL_RULES: List[Dict[str, Any]] = [
    {
        "name": "mcp",
        "paths": ["/mcp/sse", "/mcp", "/sse", "/api/mcp"],
        "match": {"status": [200, 405], "content_type": "text/event-stream"},
        "surfaces": ["mcp", "agent"],
        "entry_points": ["/mcp/sse", "/mcp", "/api/mcp"],
    },
    {
        "name": "ollama",
        "paths": ["/api/tags", "/api/show", "/api/version"],
        "match": {"status": [200], "json_key": "models"},
        "surfaces": ["prompt", "model_extraction"],
        "entry_points": ["/api/generate", "/api/chat", "/api/tags", "/api/show"],
    },
    {
        "name": "vllm",
        "paths": ["/v1/models", "/v1/chat/completions"],
        "match": {"status": [200], "json_key": "data"},
        "surfaces": ["prompt", "rag"],
        "entry_points": ["/v1/chat/completions", "/v1/models", "/v1/completions"],
    },
    {
        "name": "langserve",
        "paths": ["/playground", "/invoke", "/batch", "/stream"],
        "match": {"status": [200], "html_marker": "langserve"},
        "surfaces": ["prompt", "agent"],
        "entry_points": ["/invoke", "/batch", "/stream"],
    },
    {
        "name": "gradio",
        "paths": ["/api/predict", "/api/queue/join", "/"],
        "match": {"status": [200], "html_marker": "gradio"},
        "surfaces": ["prompt"],
        "entry_points": ["/api/predict", "/api/queue/join"],
    },
    {
        "name": "streamlit",
        "paths": ["/"],
        "match": {"status": [200], "html_marker": "streamlit"},
        "surfaces": ["prompt"],
        "entry_points": ["/_stcore/message"],
    },
    {
        "name": "openwebui",
        "paths": ["/api/models", "/api/chat/completions"],
        "match": {"status": [200], "json_key": "data"},
        "surfaces": ["prompt", "rag"],
        "entry_points": ["/api/chat/completions", "/api/models"],
    },
    {
        "name": "tgi",
        "paths": ["/info", "/generate", "/"],
        "match": {"status": [200], "html_marker": "text-generation-inference"},
        "surfaces": ["prompt"],
        "entry_points": ["/generate", "/info"],
    },
]

# 系统提示泄露检测路径
SYSTEM_PROBE_PATHS = [
    "/v1/chat/completions",
    "/api/chat",
    "/api/generate",
]


class ProtocolFingerprintAdapter(BaseAdapter):
    """
    协议指纹适配器（AIMAP 指纹逻辑，无 Shodan 依赖）

    通过 HTTP 探测识别目标 AI 框架类型，填充 TargetProfile 的
    fingerprint、surfaces、entry_points 字段。
    """

    @property
    def name(self) -> str:
        return "protocol_fingerprint"

    def run(self, target: str, config: dict) -> AdapterResult:
        """
        执行协议指纹探测

        Args:
            target: 目标 URL（如 http://192.168.1.100:11434）
            config: 配置字典（timeout 等）

        Returns:
            AdapterResult（data 包含 fingerprint/surfaces/entry_points）
        """
        start_time = time.time()
        timeout = config.get("timeout", 30)

        # 标准化目标 URL
        base_url = target.rstrip("/")
        if not base_url.startswith("http"):
            base_url = f"http://{base_url}"

        data: Dict[str, Any] = {
            "target": base_url,
            "detected_protocols": [],
            "surfaces": [],
            "entry_points": [],
            "provider": None,
            "model_name": None,
            "model_family": None,
            "capabilities": [],
            "auth_required": False,
            "system_prompt_leaked": False,
        }

        findings: List[Dict[str, Any]] = []
        errors: List[str] = []

        try:
            # ── 步骤 1：协议检测 ──
            detected = self._detect_protocols(base_url, timeout)
            data["detected_protocols"] = [d["name"] for d in detected]

            # 合并攻击面和入口点
            surfaces_set = set()
            entry_points_set = set()
            for d in detected:
                surfaces_set.update(d.get("surfaces", []))
                for ep in d.get("entry_points", []):
                    entry_points_set.add(f"{base_url}{ep}")
            data["surfaces"] = list(surfaces_set)
            data["entry_points"] = [
                {"url": ep, "method": "POST", "protocol": d["name"]}
                for d in detected
                for ep in d.get("entry_points", [])
                if ep in entry_points_set
            ]
            # 去重 entry_points
            seen_urls = set()
            unique_eps = []
            for ep in data["entry_points"]:
                if ep["url"] not in seen_urls:
                    seen_urls.add(ep["url"])
                    unique_eps.append(ep)
            data["entry_points"] = unique_eps

            # ── 步骤 2：模型信息提取 ──
            model_info = self._extract_model_info(base_url, data["detected_protocols"], timeout)
            data.update(model_info)

            # ── 步骤 3：认证检测 ──
            auth_info = self._check_auth(base_url, data["detected_protocols"], timeout)
            data["auth_required"] = auth_info["auth_required"]
            data["auth_type"] = auth_info.get("auth_type")

            # ── 步骤 4：系统提示泄露检测 ──
            prompt_leak = self._check_system_prompt_leak(base_url, data["detected_protocols"], timeout)
            data["system_prompt_leaked"] = prompt_leak["leaked"]
            data["system_prompt"] = prompt_leak.get("prompt")

            # ── 步骤 5：MCP 工具枚举 ──
            if "mcp" in data["detected_protocols"]:
                mcp_tools = self._enumerate_mcp_tools(base_url, timeout)
                data["mcp_tools"] = mcp_tools
                if mcp_tools:
                    data["capabilities"].append("tools")

            # 构建 findings
            for protocol in data["detected_protocols"]:
                findings.append({
                    "category": "protocol_detected",
                    "severity": "low",
                    "description": f"Detected {protocol} protocol on {base_url}",
                    "evidence": f"Protocol: {protocol}",
                    "owasp_mapping": self._map_protocol_to_owasp(protocol),
                    "confidence": 0.9,
                })

            if data["auth_required"]:
                findings.append({
                    "category": "auth_detected",
                    "severity": "low",
                    "description": f"Authentication required: {data.get('auth_type', 'unknown')}",
                    "evidence": f"Auth type: {data.get('auth_type')}",
                    "owasp_mapping": "",
                    "confidence": 0.8,
                })
            else:
                findings.append({
                    "category": "no_auth",
                    "severity": "medium",
                    "description": "No authentication required on exposed endpoint",
                    "evidence": f"Endpoint {base_url} accessible without auth",
                    "owasp_mapping": "LLM01",
                    "confidence": 0.85,
                })

            if data["system_prompt_leaked"]:
                findings.append({
                    "category": "system_prompt_leak",
                    "severity": "high",
                    "description": "System prompt leaked in response",
                    "evidence": data.get("system_prompt", "")[:200],
                    "owasp_mapping": "LLM07",
                    "confidence": 0.9,
                })

            duration = time.time() - start_time
            return AdapterResult(
                tool=self.name,
                success=True,
                data=data,
                findings=findings,
                errors=errors,
                duration=duration,
            )

        except Exception as e:
            duration = time.time() - start_time
            logger.error("Protocol fingerprint failed: %s", str(e))
            return AdapterResult(
                tool=self.name,
                success=False,
                data=data,
                errors=[str(e)],
                duration=duration,
            )

    # ── 私有方法 ──

    def _detect_protocols(self, base_url: str, timeout: int) -> List[Dict[str, Any]]:
        """探测目标支持的协议"""
        detected = []

        for rule in PROTOCOL_RULES:
            for path in rule["paths"]:
                url = f"{base_url}{path}"
                result = http_get(url, timeout=timeout)

                if self._match_rule(result, rule):
                    logger.debug("Protocol detected: %s via %s", rule["name"], path)
                    detected.append(rule)
                    break  # 该协议已匹配，跳过后续路径

        # 兜底：通用 OpenAI 兼容检测
        if not detected:
            result = http_get(f"{base_url}/v1/models", timeout=timeout)
            if result["status"] == 200 and isinstance(result["data"], dict):
                detected.append({
                    "name": "openai_compatible",
                    "surfaces": ["prompt"],
                    "entry_points": ["/v1/chat/completions", "/v1/models"],
                })

        return detected

    def _match_rule(self, result: Dict[str, Any], rule: Dict[str, Any]) -> bool:
        """匹配检测规则"""
        match = rule.get("match", {})
        status_ok = result["status"] in match.get("status", [200])

        if not status_ok:
            return False

        # JSON key 检查
        json_key = match.get("json_key")
        if json_key:
            if not isinstance(result["data"], dict):
                return False
            if json_key not in result["data"]:
                return False

        # HTML marker 检查（简化：检查原始文本）
        html_marker = match.get("html_marker")
        if html_marker:
            raw = str(result.get("data", "")).lower()
            if html_marker not in raw:
                # 二次检查：某些框架在 title 或 meta 中
                if "title" in raw and html_marker in raw:
                    pass
                else:
                    return False

        return True

    def _extract_model_info(
        self, base_url: str, protocols: List[str], timeout: int
    ) -> Dict[str, Any]:
        """提取模型信息"""
        info: Dict[str, Any] = {}

        if "ollama" in protocols:
            # Ollama: GET /api/tags
            result = http_get(f"{base_url}/api/tags", timeout=timeout)
            if result["status"] == 200 and isinstance(result["data"], dict):
                models = result["data"].get("models", [])
                if models:
                    info["model_name"] = models[0].get("name", "")
                    info["model_family"] = self._extract_model_family(info["model_name"])
                    info["provider"] = "ollama"
                    info["capabilities"] = ["local_inference"]

        elif "vllm" in protocols or "openai_compatible" in protocols:
            # vLLM: GET /v1/models
            result = http_get(f"{base_url}/v1/models", timeout=timeout)
            if result["status"] == 200 and isinstance(result["data"], dict):
                models = result["data"].get("data", [])
                if models:
                    info["model_name"] = models[0].get("id", "")
                    info["model_family"] = self._extract_model_family(info["model_name"])
                    info["provider"] = "vllm" if "vllm" in protocols else "openai_compatible"
                    info["capabilities"] = ["api_inference"]

        elif "openwebui" in protocols:
            result = http_get(f"{base_url}/api/models", timeout=timeout)
            if result["status"] == 200 and isinstance(result["data"], dict):
                models = result["data"].get("data", [])
                if models:
                    info["model_name"] = models[0].get("id", models[0].get("name", ""))
                    info["model_family"] = self._extract_model_family(info["model_name"])
                    info["provider"] = "openwebui"
                    info["capabilities"] = ["api_inference", "multi_model"]

        return info

    def _check_auth(
        self, base_url: str, protocols: List[str], timeout: int
    ) -> Dict[str, Any]:
        """检测是否需要认证"""
        # 发送不带认证头的请求，检查是否返回 401/403
        test_paths = {
            "ollama": "/api/tags",
            "vllm": "/v1/models",
            "openai_compatible": "/v1/models",
            "openwebui": "/api/models",
            "mcp": "/mcp/sse",
        }

        # 有检测到协议的路径时，按协议检测
        for protocol in protocols:
            path = test_paths.get(protocol)
            if path:
                result = http_get(f"{base_url}{path}", timeout=timeout)
                if result["status"] in (401, 403):
                    return {"auth_required": True, "auth_type": "bearer"}
                elif result["status"] == 200:
                    return {"auth_required": False, "auth_type": None}

        # 无协议匹配时，探测常见路径判断是否需认证
        if not protocols:
            fallback_paths = ["/api/tags", "/v1/models", "/api/models", "/mcp/sse"]
            for path in fallback_paths:
                result = http_get(f"{base_url}{path}", timeout=timeout)
                if result["status"] in (401, 403):
                    return {"auth_required": True, "auth_type": "bearer"}

        return {"auth_required": False, "auth_type": None}

    def _check_system_prompt_leak(
        self, base_url: str, protocols: List[str], timeout: int
    ) -> Dict[str, Any]:
        """检测系统提示是否泄露"""
        # 发送一个最小请求，检查响应中是否包含 system prompt
        payload = {
            "model": "test",
            "messages": [{"role": "user", "content": "Hello"}],
            "max_tokens": 1,
        }

        test_paths = {
            "ollama": "/api/chat",
            "vllm": "/v1/chat/completions",
            "openai_compatible": "/v1/chat/completions",
            "openwebui": "/api/chat/completions",
        }

        for protocol in protocols:
            path = test_paths.get(protocol)
            if path:
                result = http_post(f"{base_url}{path}", json_data=payload, timeout=timeout)
                if result["status"] == 200:
                    # 检查响应中是否包含 system role 内容
                    raw = str(result.get("data", ""))
                    if '"role":"system"' in raw or '"role": "system"' in raw:
                        return {"leaked": True, "prompt": raw[:500]}
                    # 检查错误消息中是否泄露
                    if "system_prompt" in raw.lower() or "system prompt" in raw.lower():
                        return {"leaked": True, "prompt": raw[:500]}

        return {"leaked": False, "prompt": None}

    def _enumerate_mcp_tools(self, base_url: str, timeout: int) -> List[Dict[str, Any]]:
        """枚举 MCP 工具列表"""
        tools = []

        # 尝试 MCP JSON-RPC tools/list
        mcp_endpoints = [f"{base_url}/mcp", f"{base_url}/mcp/sse", f"{base_url}/api/mcp"]
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list",
            "params": {},
        }

        for endpoint in mcp_endpoints:
            result = http_post(endpoint, json_data=payload, timeout=timeout)
            if result["status"] == 200 and isinstance(result["data"], dict):
                result_data = result["data"].get("result", {})
                if isinstance(result_data, dict):
                    tool_list = result_data.get("tools", [])
                    for tool in tool_list:
                        tools.append({
                            "name": tool.get("name", ""),
                            "description": tool.get("description", ""),
                        })
                    if tools:
                        break

        return tools

    @staticmethod
    def _extract_model_family(model_name: str) -> str:
        """从模型名称提取家族"""
        if not model_name:
            return ""
        name = model_name.lower()
        if "llama" in name:
            return "llama"
        elif "gpt" in name:
            return "gpt"
        elif "claude" in name:
            return "claude"
        elif "qwen" in name:
            return "qwen"
        elif "mistral" in name:
            return "mistral"
        elif "phi" in name:
            return "phi"
        elif "gemma" in name:
            return "gemma"
        elif "deepseek" in name:
            return "deepseek"
        else:
            return name.split("-")[0] if "-" in name else name

    @staticmethod
    def _map_protocol_to_owasp(protocol: str) -> str:
        """协议映射到 OWASP"""
        mapping = {
            "mcp": "ASI03",
            "ollama": "LLM02",
            "vllm": "LLM02",
            "langserve": "LLM01",
            "gradio": "LLM01",
            "streamlit": "LLM01",
            "openwebui": "LLM02",
            "tgi": "LLM02",
            "openai_compatible": "LLM02",
        }
        return mapping.get(protocol, "")
