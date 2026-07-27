# -*- coding: utf-8 -*-
"""
Traffic Analyzer
================

网络流量分析器：
  - 识别 LLM API 端点（OpenAI / Claude / Gemini / 国内厂商）
  - 从 JSON / SSE 流中提取模型名
  - 提取 LLM 响应文本
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class TrafficAnalyzer:
    """网络流量分析器：识别 LLM API、解析响应、提取模型名、API Key、RAG/Agent 特征"""

    DEPLOYMENT_PATTERNS = {
        "ollama": ["localhost:11434", "127.0.0.1:11434", ":11434"],
        "openai": ["api.openai.com", "openai.com"],
        "azure_openai": ["openai.azure.com", ".azure.com/openai"],
        "aws_bedrock": ["bedrock-runtime", ".amazonaws.com"],
        "cloudflare": ["workers.ai", "cloudflare"],
        "aliyun": ["tongyi.aliyun.com", "dashscope.aliyuncs.com", "aliyun.com", "qianwen"],
        "baidu": ["yiyan.baidu.com", "qianfan.baidu.com", "baidu.com"],
        "iflytek": ["xinghuo.xfyun.cn", "xfyun.cn"],
        "moonshot": ["kimi.moonshot.cn", "moonshot.cn"],
        "zhipu": ["chatglm.cn", "zhipu"],
        "deepseek": ["deepseek.com", "api.deepseek.com"],
        "volcengine": ["volcengine.com", "volces.com", "appsharing-ai"],
        "google": ["gemini.google.com", "generativelanguage.googleapis.com"],
        "anthropic": ["claude.ai", "api.anthropic.com"],
    }

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        # 文本分析长度限制，未配置时使用最优默认值
        self.text_length_limit = self.config.get("text_length_limit", 5000)

        self.llm_api_patterns = [
            # OpenAI 兼容
            r"/v\d+/chat/completions",
            r"/chat/completions",
            r"/completions",
            r"/v1/embeddings",
            r"/v1/models",
            # 国内厂商
            r"/api/v1/services/aigc/text-generation",
            r"/api/paas/v4/chat/completions",
            r"/compatible-mode/v1/chat/completions",
            r"/api/llm/chat",
            r"/api/chat",
            r"/v1/conversation",
            r"/api/v3/chat",
            r"/prod/api/conversation",
            # Copilot / Claude / Gemini
            r"/conversation",
            r"/api/conversation",
            r"/v1/streams/chat",
            r"/v1beta/models/",
            r"/v1/generateContent",
            # 通用 LLM 关键词
            r"/llm/",
            r"/ai/",
            r"/aigc/",
            r"/generate",
            r"/stream",
        ]
        self.model_name_keys = [
            "model",
            "model_name",
            "modelName",
            "model_id",
            "modelId",
            "model_code",
            "modelCode",
            "modelVersion",
        ]

        # RAG 相关 URL/Body 关键词（避免与通用 JSON 字段冲突，如 index/search）
        self.rag_keywords = [
            "rag", "retrieval", "knowledge_base", "knowledgebase", "knowledge base",
            "embedding", "vector", "vector_store", "vectorstore",
            "知识库", "检索", "向量", "向量库",
        ]

        # Agent / Copilot / MCP 相关关键词（避免与 message.role=assistant 等冲突）
        self.agent_keywords = [
            "agent", "copilot", "function_call", "functioncall", "plugin",
            "mcp", "model_context_protocol", "model-context-protocol",
            "workflow", "tool_call", "toolcall",
            "智能体", "插件", "工作流", "工具调用",
        ]

        # API Key 正则（仅识别前缀，避免完整泄露敏感 token）
        self.api_key_patterns = [
            re.compile(r'(sk-[a-zA-Z0-9]{20,})', re.IGNORECASE),
            re.compile(r'(Bearer\s+)([a-zA-Z0-9_\-]{20,})', re.IGNORECASE),
            re.compile(r'(api[_-]?key["\']?\s*[:=]\s*["\']?)([a-zA-Z0-9_\-]{8,})', re.IGNORECASE),
        ]

    def analyze_request(self, entry: Dict[str, Any]) -> Dict[str, Any]:
        """分析单个请求条目，返回 LLM 识别结果"""
        url = entry.get("url", "")
        body = entry.get("request_body", "")
        response = entry.get("response_body", "")
        req_headers = entry.get("request_headers", {})
        resp_headers = entry.get("response_headers", {})

        result = {
            "is_llm_api": False,
            "api_type": "",
            "model_name": "",
            "api_keys": [],
            "protocol": self._detect_protocol(resp_headers, url),
            "rag_features": [],
            "agent_features": [],
        }

        # 1. URL 模式匹配
        api_type = self._detect_api_type(url)
        if api_type:
            result["is_llm_api"] = True
            result["api_type"] = api_type

        # 2. Body 中的 model 字段
        model_from_body = self._extract_model_from_text(body)
        if model_from_body:
            result["model_name"] = model_from_body
            result["is_llm_api"] = True

        # 3. 响应体中的模型名
        model_from_response = self._extract_model_from_text(response)
        if model_from_response and not result["model_name"]:
            result["model_name"] = model_from_response

        # 4. SSE 流内容提取
        sse_model = self._extract_model_from_sse(response)
        if sse_model:
            result["model_name"] = sse_model
            result["is_llm_api"] = True

        # 5. 响应头线索
        content_type = resp_headers.get("content-type", "")
        if "text/event-stream" in content_type.lower() and api_type:
            result["is_llm_api"] = True

        # 6. API Key 提取
        result["api_keys"] = self._extract_api_keys(req_headers, body)

        # 7. RAG / Agent 特征识别
        result["rag_features"] = self._detect_rag_features(url, body, response)
        result["agent_features"] = self._detect_agent_features(url, body, response)

        return result

    def _detect_api_type(self, url: str) -> str:
        """根据 URL 判断 API 类型"""
        lower_url = url.lower()
        if "/v1/chat/completions" in lower_url or "/chat/completions" in lower_url:
            return "openai_compatible"
        if "/v1/completions" in lower_url:
            return "openai_completions"
        if "/v1/embeddings" in lower_url:
            return "openai_embeddings"
        if "/v1/models" in lower_url:
            return "openai_models"
        if "/conversation" in lower_url:
            return "claude_compatible"
        if "/v1beta/models/" in lower_url or "/generateContent" in lower_url:
            return "gemini_compatible"
        if "/api/paas/v4" in lower_url or "/compatible-mode/v1" in lower_url:
            return "moonshot_compatible"
        if "/api/v1/services/aigc" in lower_url or "/qianfan" in lower_url:
            return "baidu_qianfan"
        if "/api/v3/chat" in lower_url or "/prod/api/conversation" in lower_url:
            return "zhipu_compatible"
        if "/api/llm/chat" in lower_url or "/api/chat" in lower_url:
            return "generic_llm"
        for pattern in self.llm_api_patterns:
            if re.search(pattern, lower_url):
                return "generic_llm"
        return ""

    def _extract_model_from_text(self, text: str) -> str:
        """从 JSON 文本中提取 model 字段（大小写不敏感）"""
        if not text or len(text) > self.text_length_limit:
            return ""

        def _find_in_dict(data: Dict[str, Any]) -> str:
            # 构建大小写不敏感的键映射，兼容 "Model" / "model" / "MODEL"
            key_map = {k.lower(): k for k in data.keys() if isinstance(k, str)}
            for key in self.model_name_keys:
                actual_key = key_map.get(key.lower())
                if actual_key and data[actual_key]:
                    return str(data[actual_key])
            return ""

        try:
            data = json.loads(text)
            if isinstance(data, dict):
                model = _find_in_dict(data)
                if model:
                    return model
                # 兼容嵌套结构：{"data": {"model": "xxx"}}
                for nested_key in ["data", "payload", "body", "params", "result", "response"]:
                    nested = data.get(nested_key)
                    if isinstance(nested, dict):
                        model = _find_in_dict(nested)
                        if model:
                            return model
        except json.JSONDecodeError:
            pass

        # 非 JSON 或 SSE 多行体：使用大小写不敏感正则兜底
        for key in self.model_name_keys:
            pattern = rf'"{re.escape(key)}"\s*:\s*"([^"]+)"'
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                return match.group(1)
        return ""

    def _extract_model_from_sse(self, text: str) -> str:
        """从 SSE 流中提取模型名"""
        if not text:
            return ""
        for line in text.splitlines():
            line = line.strip()
            if line.startswith("data:"):
                payload = line[5:].strip()
                if payload == "[DONE]":
                    continue
                model = self._extract_model_from_text(payload)
                if model:
                    return model
        return ""

    def _detect_protocol(self, response_headers: Dict[str, str], url: str) -> str:
        """识别通信协议"""
        ct = response_headers.get("content-type", "").lower()
        if "text/event-stream" in ct:
            return "sse"
        if "grpc-web" in ct or "/grpc/" in url.lower():
            return "grpc-web"
        if url.lower().startswith("wss://") or url.lower().startswith("ws://"):
            return "websocket"
        return "http"

    def _extract_api_keys(self, headers: Dict[str, str], body: str) -> List[Dict[str, Any]]:
        """从请求头和请求体中提取 API Key 线索"""
        findings: List[Dict[str, Any]] = []
        text_pool = " ".join([f"{k}: {v}" for k, v in headers.items()])
        text_pool += " " + body

        for pattern in self.api_key_patterns:
            for match in pattern.finditer(text_pool):
                full = match.group(0)
                key_value = match.group(2) if len(match.groups()) > 1 else full
                prefix = key_value[:8]
                findings.append({
                    "type": "api_key",
                    "prefix": prefix,
                    "length": len(key_value),
                    "source": "header" if full in str(headers) else "body",
                })

        # 显式 API Key 头
        for name in ["x-api-key", "api-key", "x-auth-token", "x-access-token"]:
            value = headers.get(name) or headers.get(name.title()) or headers.get(name.upper())
            if value:
                findings.append({
                    "type": "api_key_header",
                    "header": name,
                    "prefix": str(value)[:8],
                    "length": len(str(value)),
                    "source": "header",
                })

        return findings

    def _detect_rag_features(self, url: str, body: str, response: str) -> List[Dict[str, Any]]:
        """识别 RAG 相关特征"""
        findings: List[Dict[str, Any]] = []
        combined = f"{url} {body} {response}".lower()
        for keyword in self.rag_keywords:
            if keyword.lower() in combined:
                findings.append({"keyword": keyword, "context": "url/body/response"})
        return findings

    def _detect_agent_features(self, url: str, body: str, response: str) -> List[Dict[str, Any]]:
        """识别 Agent / Copilot / MCP 相关特征"""
        findings: List[Dict[str, Any]] = []
        combined = f"{url} {body} {response}".lower()
        for keyword in self.agent_keywords:
            if keyword.lower() in combined:
                findings.append({"keyword": keyword, "context": "url/body/response"})
        return findings

    def extract_response_text(self, response_body: str) -> str:
        """从 LLM 响应体中提取最终文本"""
        if not response_body:
            return ""

        # 1. OpenAI 兼容格式
        try:
            data = json.loads(response_body)
            if isinstance(data, dict):
                choices = data.get("choices", [])
                if choices and isinstance(choices, list):
                    msg = choices[0].get("message", {})
                    content = msg.get("content") or choices[0].get("text", "")
                    if content:
                        return str(content)
        except Exception:
            pass

        # 2. SSE 流
        texts = []
        for line in response_body.splitlines():
            line = line.strip()
            if line.startswith("data:"):
                payload = line[5:].strip()
                if payload == "[DONE]":
                    continue
                try:
                    data = json.loads(payload)
                    choices = data.get("choices", [])
                    if choices:
                        delta = choices[0].get("delta", {})
                        content = delta.get("content", "")
                        if content:
                            texts.append(content)
                except Exception:
                    continue
        return "".join(texts)

    def is_streaming_response(self, response_headers: Dict[str, str]) -> bool:
        """判断响应是否为流式"""
        ct = response_headers.get("content-type", "").lower()
        return "text/event-stream" in ct or "chunked" in ct

    def detect_deployment_platform(self, url: str) -> str:
        """
        根据 URL / Host 推断 LLM 部署平台。
        返回最匹配的平台名，无法识别时返回 unknown。
        """
        if not url:
            return "unknown"
        lower_url = url.lower()
        for platform, markers in self.DEPLOYMENT_PATTERNS.items():
            for marker in markers:
                if marker.lower() in lower_url:
                    return platform
        return "unknown"

    def detect_chat_urls(self, entries: List[Dict[str, Any]]) -> List[str]:
        """
        从拦截流量中提取疑似聊天/对话相关的 URL。
        包含 LLM API 端点和页面内的聊天路由。
        """
        chat_urls: List[str] = []
        seen = set()
        for entry in entries:
            url = entry.get("url", "")
            if not url or url in seen:
                continue
            seen.add(url)
            lower_url = url.lower()
            if entry.get("is_llm_api"):
                chat_urls.append(url)
                continue
            # 页面内聊天路由关键词
            chat_keywords = [
                "/chat", "/conversation", "/dialog", "/message", "/ask",
                "/completion", "/generate", "/stream", "/v1/",
            ]
            if any(kw in lower_url for kw in chat_keywords):
                chat_urls.append(url)
        return chat_urls

    def aggregate_llm_features(self, entries: List[Dict[str, Any]]) -> List[str]:
        """
        聚合 LLM 特征标签，用于快速刻画目标能力。
        """
        features: set = set()
        protocols = set()
        has_api = False
        has_streaming = False
        has_rag = False
        has_agent = False

        for entry in entries:
            if entry.get("is_llm_api"):
                has_api = True
                api_type = entry.get("api_type", "")
                if api_type:
                    features.add(api_type)
                if entry.get("model_name"):
                    features.add(f"model:{entry['model_name']}")
            if entry.get("protocol"):
                protocols.add(entry["protocol"])
            if self.is_streaming_response(entry.get("response_headers", {})):
                has_streaming = True
            if entry.get("rag_features"):
                has_rag = True
            if entry.get("agent_features"):
                has_agent = True

        if has_api:
            features.add("llm_api_exposed")
        if has_streaming or "sse" in protocols:
            features.add("sse_streaming")
        if "websocket" in protocols:
            features.add("websocket")
        if "grpc-web" in protocols:
            features.add("grpc-web")
        if has_rag:
            features.add("rag_enabled")
        if has_agent:
            features.add("agent_enabled")

        return sorted(features)
