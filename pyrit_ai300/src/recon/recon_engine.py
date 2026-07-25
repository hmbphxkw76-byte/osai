"""
Recon Module
============

本模块负责侦察层，包括端点发现、能力探测、AI 系统类型识别（遵循开发规则 1.4.3）。

仅包含 PyRIT 原生支持的部分（端点识别、能力探测）。
"""

import asyncio
import httpx
import re
import logging
from typing import Any, Dict, List, Optional
from datetime import datetime

from pyrit.prompt_target import (
    HTTPXAPITarget,
    OpenAIChatTarget,
    discover_target_capabilities_async,
)

from src.core.models import (
    AISystemType,
    AuthType,
    ReconResult,
    TargetCapabilities,
    create_recon_result,
)

from src.core.config_loader import get_config_loader

logger = logging.getLogger(__name__)


# ============================================================
# 侦察引擎
# ============================================================


class ReconEngine:
    """侦察引擎 - 负责端点发现和 AI 系统类型识别"""

    def __init__(self):
        """初始化侦察引擎"""
        self.config_loader = get_config_loader()

    async def probe_endpoint(
        self,
        base_url: str,
        endpoint: str,
        method: str = "POST",
        headers: Optional[Dict[str, str]] = None,
    ) -> Optional[Dict[str, Any]]:
        """
        探测单个端点

        Args:
            base_url: 基础 URL
            endpoint: 端点路径
            method: HTTP 方法
            headers: 请求头

        Returns:
            响应信息字典，如果端点不可用则返回 None
        """
        url = base_url.rstrip("/") + endpoint
        headers = headers or {"Content-Type": "application/json"}

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                if method.upper() == "POST":
                    # 尝试带 model 字段的请求 (Ollama 等 OpenAI 兼容端点需要)
                    response = await client.post(
                        url,
                        json={
                            "model": "test",
                            "messages": [{"role": "user", "content": "test"}],
                        },
                        headers=headers,
                    )
                else:
                    response = await client.get(url, headers=headers)

                # 200/201 = 成功, 400 = 端点存在但请求格式有误, 401 = 需要认证
                # 422 = 端点存在但参数验证失败
                if response.status_code in (200, 201, 400, 401, 422):
                    return {
                        "status_code": response.status_code,
                        "headers": dict(response.headers),
                        "body": response.text[:1000],  # 限制长度
                    }

                # 404 可能是端点不存在，也可能是模型不存在 (OpenAI 兼容端点)
                # 区分方法: 端点不存在的 404 通常返回纯文本 (如 "404 page not found")
                #           模型不存在的 404 返回 JSON (如 {"error":{"message":"model not found"}})
                if response.status_code == 404:
                    body = response.text.strip()
                    if body.startswith("{") or body.startswith("["):
                        # JSON 响应，说明端点存在但模型不存在
                        return {
                            "status_code": response.status_code,
                            "headers": dict(response.headers),
                            "body": body[:1000],
                        }
        except Exception:
            pass

        return None

    async def discover_endpoints(self, target_url: str) -> str:
        """
        发现可用端点

        Args:
            target_url: 目标 URL

        Returns:
            检测到的端点路径
        """
        supported_endpoints = self.config_loader.get_supported_endpoints()
        headers = {"Content-Type": "application/json"}

        for endpoint in supported_endpoints:
            result = await self.probe_endpoint(target_url, endpoint, headers=headers)
            if result is not None:
                return endpoint

        # 默认返回第一个端点
        return supported_endpoints[0] if supported_endpoints else "/v1/chat"

    async def detect_auth_type(self, target_url: str, endpoint: str) -> AuthType:
        """
        检测认证类型

        Args:
            target_url: 目标 URL
            endpoint: 端点路径

        Returns:
            认证类型
        """
        url = target_url.rstrip("/") + endpoint
        headers = {"Content-Type": "application/json"}

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.post(
                    url,
                    json={
                        "model": "test",
                        "messages": [{"role": "user", "content": "test"}],
                    },
                    headers=headers,
                )

                # 401 Unauthorized - 需要认证
                if response.status_code == 401:
                    www_authenticate = response.headers.get("WWW-Authenticate", "").lower()
                    if "bearer" in www_authenticate:
                        return AuthType.BEARER_TOKEN
                    elif "apikey" in www_authenticate:
                        return AuthType.API_KEY
                    elif "basic" in www_authenticate:
                        return AuthType.FORM_BASED
                    return AuthType.UNKNOWN

                # 200/201/400/422 - 端点可用，无需认证
                # 400/422 表示请求格式有误但端点不需要认证 (如 Ollama 缺少 model 字段)
                elif response.status_code in (200, 201, 400, 422):
                    return AuthType.NONE

                # 404 with JSON body = 模型不存在但端点可用 (OpenAI 兼容端点)
                elif response.status_code == 404:
                    body = response.text.strip()
                    if body.startswith("{") or body.startswith("["):
                        return AuthType.NONE

        except Exception:
            pass

        return AuthType.UNKNOWN

    async def discover_capabilities(
        self, target_url: str, api_key: Optional[str] = None, model_name: Optional[str] = None
    ) -> TargetCapabilities:
        """
        发现目标能力（使用 PyRIT 原生功能）

        L5 优化：根据目标类型选择合适的探测 Target，避免对所有目标都用 HTTPXAPITarget
        - OpenAI 兼容目标 → 使用 OpenAIChatTarget 探测（支持多轮/系统提示等能力）
        - 非 OpenAI 目标 → 使用 HTTPXAPITarget 探测（基础能力）

        Args:
            target_url: 目标 URL
            api_key: 目标 API Key（用于能力探测认证）
            model_name: 目标模型名称（用于能力探测，避免无效模型错误）

        Returns:
            目标能力对象
        """
        try:
            # 检测目标类型
            from src.targets.target_factory import TargetFactory, OPENAI_COMPATIBLE_TYPES
            target_type = await TargetFactory.detect_target_type(target_url)

            # 根据目标类型创建合适的探测 Target
            if target_type in OPENAI_COMPATIBLE_TYPES:
                temp_target = OpenAIChatTarget(
                    endpoint=f"{target_url.rstrip('/')}/v1",
                    api_key=api_key or "placeholder",
                    model_name=model_name or "test",
                )
            else:
                temp_target = HTTPXAPITarget(
                    http_url=target_url,
                    method="POST",
                    headers={"Content-Type": "application/json"},
                    json_data={"messages": [{"role": "user", "content": "{PROMPT}"}]},
                )

            # 使用 PyRIT 原生能力发现（添加整体超时避免小模型卡死）
            capabilities = await asyncio.wait_for(
                discover_target_capabilities_async(
                    target=temp_target,
                    per_probe_timeout_s=10.0,
                ),
                timeout=30.0,
            )

            # 提取模态列表
            input_modalities = []
            output_modalities = []
            try:
                input_modalities = [
                    list(m) if isinstance(m, (set, frozenset)) else [m]
                    for m in capabilities.input_modalities
                ]
                input_modalities = [item for sublist in input_modalities for item in sublist]
            except Exception:
                pass
            try:
                output_modalities = [
                    list(m) if isinstance(m, (set, frozenset)) else [m]
                    for m in capabilities.output_modalities
                ]
                output_modalities = [item for sublist in output_modalities for item in sublist]
            except Exception:
                pass

            result = TargetCapabilities(
                supports_multi_turn=capabilities.supports_multi_turn,
                supports_editable_history=capabilities.supports_editable_history,
                supports_system_prompt=capabilities.supports_system_prompt,
                supports_json_output=capabilities.supports_json_output,
                input_modalities=input_modalities,
                output_modalities=output_modalities,
                raw_response={
                    "supports_conversation": True,
                    "target_type": target_type,
                },
            )

            # L5: 如果所有探测都失败（探针触发空响应），回退到 OpenAI 兼容默认值
            # 某些 API（如 LongCat）对探针格式返回空响应，但实际支持这些能力
            if target_type in OPENAI_COMPATIBLE_TYPES:
                if not any([result.supports_multi_turn, result.supports_editable_history,
                           result.supports_system_prompt, result.supports_json_output]):
                    logger.info("All capability probes failed; using OpenAI-compatible defaults")
                    result.supports_multi_turn = True
                    result.supports_editable_history = True
                    result.supports_system_prompt = True
                    result.supports_json_output = True
                    if not result.input_modalities:
                        result.input_modalities = ["text"]
                    if not result.output_modalities:
                        result.output_modalities = ["text"]

            return result
        except Exception as e:
            logger.warning(f"Capability discovery failed: {e}")
            # 如果 PyRIT 探测失败，返回默认值
            return TargetCapabilities()

    def identify_ai_system_type(
        self, endpoint: str, response_indicators: Optional[List[str]] = None
    ) -> AISystemType:
        """
        识别 AI 系统类型

        Args:
            endpoint: 检测到的端点
            response_indicators: 响应中的指示器

        Returns:
            AI 系统类型
        """
        response_indicators = response_indicators or []

        # 从配置加载识别规则
        ai_type_rules = self.config_loader.get_ai_type_detection_rules()

        # 按优先级检查
        # 1. MCP 服务器
        mcp_config = ai_type_rules.get("mcp_server", {})
        mcp_patterns = mcp_config.get("endpoint_patterns", [])
        if any(pattern in endpoint for pattern in mcp_patterns):
            return AISystemType.MCP_SERVER

        # 2. Multi-agent
        agent_config = ai_type_rules.get("multi_agent", {})
        agent_patterns = agent_config.get("endpoint_patterns", [])
        if any(pattern in endpoint for pattern in agent_patterns):
            return AISystemType.MULTI_AGENT
        agent_indicators = agent_config.get("response_indicators", [])
        if any(indicator in str(response_indicators) for indicator in agent_indicators):
            return AISystemType.MULTI_AGENT

        # 3. RAG
        rag_config = ai_type_rules.get("rag", {})
        rag_patterns = rag_config.get("endpoint_patterns", [])
        if any(pattern in endpoint for pattern in rag_patterns):
            return AISystemType.RAG
        rag_indicators = rag_config.get("response_indicators", [])
        if any(indicator in str(response_indicators) for indicator in rag_indicators):
            return AISystemType.RAG

        # 4. Embeddings（非 PyRIT 优势）
        emb_config = ai_type_rules.get("embeddings", {})
        emb_patterns = emb_config.get("endpoint_patterns", [])
        if any(pattern in endpoint for pattern in emb_patterns):
            return AISystemType.EMBEDDINGS

        # 5. Infrastructure（非 PyRIT 优势）
        infra_config = ai_type_rules.get("infrastructure", {})
        infra_patterns = infra_config.get("endpoint_patterns", [])
        if any(pattern in endpoint for pattern in infra_patterns):
            return AISystemType.INFRASTRUCTURE

        # 6. LLM（默认，PyRIT 核心攻击目标）
        llm_config = ai_type_rules.get("llm", {})
        llm_patterns = llm_config.get("endpoint_patterns", [])
        if any(pattern in endpoint for pattern in llm_patterns):
            return AISystemType.LLM

        return AISystemType.UNKNOWN

    async def execute_recon(
        self, target_url: str, api_key: Optional[str] = None, model_name: Optional[str] = None
    ) -> ReconResult:
        """
        执行完整侦察流程

        Args:
            target_url: 目标 URL
            api_key: 目标 API Key（用于能力探测认证）
            model_name: 目标模型名称（用于能力探测）

        Returns:
            侦察结果
        """
        # 1. 发现端点
        detected_endpoint = await self.discover_endpoints(target_url)

        # 2. 检测认证类型
        auth_type = await self.detect_auth_type(target_url, detected_endpoint)

        # 3. 发现能力
        capabilities = await self.discover_capabilities(
            target_url, api_key=api_key, model_name=model_name
        )

        # 4. 识别 AI 系统类型
        ai_system_type = self.identify_ai_system_type(detected_endpoint)

        # 5. 获取外部工具推荐（非 PyRIT 优势类型）
        external_tools = None
        if not ai_system_type.is_pyrit_attackable():
            external_tools = self.config_loader.get_external_tools(ai_system_type.value)

        # 6. 创建侦察结果
        return create_recon_result(
            target_url=target_url,
            detected_endpoint=detected_endpoint,
            auth_type=auth_type,
            ai_system_type=ai_system_type,
            capabilities=capabilities,
            tech_stack=[],  # 可选：从响应头提取
            external_tools=external_tools,
        )


# ============================================================
# 工厂函数
# ============================================================


async def recon_target(
    target_url: str, api_key: Optional[str] = None, model_name: Optional[str] = None
) -> ReconResult:
    """
    侦察目标（工厂函数）

    Args:
        target_url: 目标 URL
        api_key: 目标 API Key（用于能力探测认证）
        model_name: 目标模型名称（用于能力探测）

    Returns:
        侦察结果
    """
    engine = ReconEngine()
    return await engine.execute_recon(target_url, api_key=api_key, model_name=model_name)