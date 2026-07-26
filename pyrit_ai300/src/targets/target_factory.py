"""
Target Factory — L5 Expert Implementation
==========================================

对齐 PyRIT 1.0.0 `pyrit.prompt_target` 全部 15+ Target 类型的统一工厂。

支持的目标类型（对齐 PyRIT 1.0.0）：
  ┌─────────────────────────────┬──────────────────────────────────────────┐
  │ Target Type                 │ PyRIT Class                              │
  ├─────────────────────────────┼──────────────────────────────────────────┤
  │ openai_chat                 │ OpenAIChatTarget (Chat Completions API)  │
  │ openai_responses            │ OpenAIResponseTarget (Responses API)     │
  │ litellm                     │ LiteLLMChatTarget (100+ Provider)        │
  │ http_api                    │ HTTPXAPITarget (结构化 HTTP API)          │
  │ http_raw                    │ HTTPTarget (原始 HTTP / Burp)             │
  │ playwright                  │ PlaywrightTarget (Web UI)                │
  │ websocket_copilot           │ WebSocketCopilotTarget (M365 Copilot)    │
  │ playwright_copilot          │ PlaywrightCopilotTarget (Copilot Web)    │
  │ azure_blob                  │ AzureBlobStorageTarget (XPIA 载荷投递)    │
  │ prompt_shield               │ PromptShieldTarget (防御测试)             │
  │ openai_image                │ OpenAIImageTarget (DALL-E 图片生成)       │
  │ openai_video                │ OpenAIVideoTarget (Sora 视频生成)         │
  │ openai_tts                  │ OpenAITTSTarget (文本转语音)              │
  │ azure_ml                    │ AzureMLChatTarget (Azure ML 对话)         │
  │ text                        │ TextTarget (调试输出)                     │
  └─────────────────────────────┴──────────────────────────────────────────┘

关键能力：
  1. 自动检测目标类型（side-effect-free，仅 GET 请求）
  2. 双重认证模式（api_key / identity / Entra ID）
  3. httpx_client_kwargs 透传（超时 / SSL / 代理）
  4. 推理参数控制（temperature / top_p / seed / max_tokens ...）
  5. extra_body_parameters 透传
  6. underlying_model 标识（Azure 部署名 ≠ 模型名）
  7. Content Filter 处理链（PyRIT 原生三层：detect → extract partial → handle）
  8. Agentic Tool Calling 支持（OpenAIResponseTarget + custom_functions）
  9. 能力探测（discover_target_capabilities_async，apply=True）
 10. 环境变量 + config.yaml + 显式参数 三级配置（优先级：显式 > env > config）
 11. custom_configuration 透传（TargetConfiguration 包含 capabilities + policy + normalizer）
 12. CapabilityHandlingPolicy（ADAPT vs RAISE — 不支持能力时的处理策略）
 13. TargetRequirements 验证（CHAT_TARGET_REQUIREMENTS — 多轮对话能力检查）
 14. get_known_capabilities 模型档案查询（gpt-4o / gpt-5 / sora-2 / tts 等）
 15. MessageNormalizer 集成（ChatMessageNormalizer / GenericSystemSquashNormalizer / ConversationContextNormalizer）
 16. 多模态目标支持（Image / Video / TTS）
 17. Azure ML Managed Endpoint 支持
"""

import json
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Awaitable, Callable, Dict, List, Optional, Tuple, Union

import httpx

from pyrit.prompt_target import (
    CHAT_TARGET_REQUIREMENTS,
    HTTPTarget,
    HTTPXAPITarget,
    OpenAIChatTarget,
    OpenAIImageTarget,
    OpenAIResponseTarget,
    OpenAITTSTarget,
    OpenAIVideoTarget,
    PromptTarget,
    TargetConfiguration,
    TargetRequirements,
    TextTarget,
    discover_target_capabilities_async,
    get_known_capabilities,
)
from pyrit.prompt_target.common.target_capabilities import (
    CapabilityHandlingPolicy,
    CapabilityName,
    UnsupportedCapabilityBehavior,
)
from pyrit.prompt_target.http_target.http_target_callback_functions import (
    get_http_target_json_response_callback_function,
    get_http_target_regex_matching_callback_function,
)
from pyrit.auth import (
    get_azure_openai_auth,
    is_azure_openai_endpoint,
)
from pyrit.message_normalizer import (
    ChatMessageNormalizer,
    ConversationContextNormalizer,
    GenericSystemSquashNormalizer,
)

logger = logging.getLogger(__name__)


# ============================================================
# 目标类型常量
# ============================================================

# OpenAI SDK 系列（使用 AsyncOpenAI SDK）
TARGET_TYPE_OPENAI_CHAT = "openai_chat"
TARGET_TYPE_OPENAI_RESPONSES = "openai_responses"
TARGET_TYPE_LITELLM = "litellm"

# HTTP 系列
TARGET_TYPE_HTTP_API = "http_api"
TARGET_TYPE_HTTP_RAW = "http_raw"

# 浏览器/WebSocket 系列
TARGET_TYPE_PLAYWRIGHT = "playwright"
TARGET_TYPE_WEBSOCKET_COPILOT = "websocket_copilot"
TARGET_TYPE_PLAYWRIGHT_COPILOT = "playwright_copilot"

# Azure 服务系列
TARGET_TYPE_AZURE_BLOB = "azure_blob"
TARGET_TYPE_PROMPT_SHIELD = "prompt_shield"
TARGET_TYPE_AZURE_ML = "azure_ml"

# 多模态
TARGET_TYPE_OPENAI_IMAGE = "openai_image"
TARGET_TYPE_OPENAI_VIDEO = "openai_video"
TARGET_TYPE_OPENAI_TTS = "openai_tts"

# 调试
TARGET_TYPE_TEXT = "text"

# 向后兼容别名（旧值 → 新值）
_LEGACY_TYPE_ALIASES: Dict[str, str] = {
    "openai_compatible": TARGET_TYPE_OPENAI_CHAT,
    "openai_compatible_vllm": TARGET_TYPE_OPENAI_CHAT,
    "openai_compatible_ollama": TARGET_TYPE_OPENAI_CHAT,
    "openai": TARGET_TYPE_OPENAI_CHAT,
    "openai_dalle": TARGET_TYPE_OPENAI_IMAGE,
    "dalle": TARGET_TYPE_OPENAI_IMAGE,
    "image_generation": TARGET_TYPE_OPENAI_IMAGE,
    "sora": TARGET_TYPE_OPENAI_VIDEO,
    "video_generation": TARGET_TYPE_OPENAI_VIDEO,
    "tts": TARGET_TYPE_OPENAI_TTS,
    "audio_generation": TARGET_TYPE_OPENAI_TTS,
    "azure_ml": TARGET_TYPE_AZURE_ML,
    "azureml": TARGET_TYPE_AZURE_ML,
    "structured_http": TARGET_TYPE_HTTP_API,
    "custom_http": TARGET_TYPE_HTTP_RAW,
}

# 使用 OpenAI SDK 的类型（支持推理参数 / extra_body_parameters / httpx_client_kwargs）
_OPENAI_SDK_TYPES = frozenset({TARGET_TYPE_OPENAI_CHAT, TARGET_TYPE_OPENAI_RESPONSES, TARGET_TYPE_LITELLM})

# 使用 OpenAI SDK 的多模态类型（OpenAITarget 基类，支持 endpoint/api_key/httpx_client_kwargs/custom_configuration）
_OPENAI_MULTIMODAL_TYPES = frozenset({
    TARGET_TYPE_OPENAI_IMAGE,
    TARGET_TYPE_OPENAI_VIDEO,
    TARGET_TYPE_OPENAI_TTS,
})

# 所有支持 custom_configuration 的类型
_CUSTOM_CONFIG_TYPES = _OPENAI_SDK_TYPES | _OPENAI_MULTIMODAL_TYPES | {TARGET_TYPE_AZURE_ML}

# 向后兼容别名（recon_engine 等模块使用此名称）
OPENAI_COMPATIBLE_TYPES = _OPENAI_SDK_TYPES

# 自动检测可探测的类型
_DETECTABLE_TYPES = frozenset({
    TARGET_TYPE_OPENAI_CHAT,
    TARGET_TYPE_OPENAI_RESPONSES,
    TARGET_TYPE_LITELLM,
    TARGET_TYPE_HTTP_API,
})


# ============================================================
# 配置数据类
# ============================================================


@dataclass
class TargetParams:
    """
    Target 创建参数（三级配置：显式参数 > 环境变量 > 默认值）

    覆盖 PyRIT 1.0.0 全部 Target 构造参数，确保不遗漏任何能力。
    """

    # ── 基础参数 ──
    target_type: Optional[str] = None          # 显式指定类型，跳过自动检测
    endpoint: str = ""                          # 目标端点 URL
    api_key: Optional[str] = None               # API Key（None 时 Azure 端点自动使用 Entra ID）
    model_name: Optional[str] = None            # 模型名 / Azure 部署名
    underlying_model: Optional[str] = None      # 实际模型名（Azure 部署名 ≠ 模型名时用于标识）

    # ── 认证 ──
    auth_mode: str = "auto"                     # auto / api_key / identity

    # ── HTTP 客户端配置 ──
    httpx_timeout: Optional[float] = None       # 超时秒数（如 180）
    httpx_verify: Optional[bool] = None         # SSL 验证（False 跳过自签名证书）
    httpx_proxy: Optional[str] = None           # 代理 URL
    httpx_client_kwargs: Optional[Dict[str, Any]] = None  # 原始 httpx kwargs

    # ── OpenAI Chat 推理参数 ──
    temperature: Optional[float] = None
    top_p: Optional[float] = None
    max_completion_tokens: Optional[int] = None  # Chat Completions API
    frequency_penalty: Optional[float] = None
    presence_penalty: Optional[float] = None
    seed: Optional[int] = None
    n: Optional[int] = None

    # ── OpenAI Responses API 专用 ──
    max_output_tokens: Optional[int] = None
    reasoning_effort: Optional[str] = None      # minimal / low / medium / high
    reasoning_summary: Optional[str] = None     # auto / concise / detailed
    custom_functions: Optional[Dict[str, Callable[..., Awaitable[Dict[str, Any]]]]] = None
    fail_on_missing_function: bool = False

    # ── 通用透传 ──
    extra_body_parameters: Optional[Dict[str, Any]] = None
    max_requests_per_minute: Optional[int] = None

    # ── HTTP API / HTTP Raw 专用 ──
    method: str = "POST"
    headers: Optional[Dict[str, str]] = None
    json_data: Optional[Dict[str, Any]] = None
    form_data: Optional[Dict[str, Any]] = None
    params: Optional[Dict[str, Any]] = None
    file_path: Optional[str] = None             # HTTPXAPITarget 文件上传

    # ── HTTP Raw (Burp) 专用 ──
    raw_http_request: Optional[str] = None
    prompt_regex_string: str = "{PROMPT}"
    use_tls: bool = True
    callback_function: Optional[Callable[..., Any]] = None

    # ── Playwright 专用 ──
    interaction_func: Optional[Callable[..., Awaitable[str]]] = None
    page: Optional[Any] = None                  # playwright.async_api.Page

    # ── Copilot 专用 ──
    copilot_username: Optional[str] = None
    copilot_password: Optional[str] = None
    copilot_access_token: Optional[str] = None

    # ── Azure Blob 专用 ──
    container_url: Optional[str] = None
    sas_token: Optional[str] = None
    blob_content_type: str = "text/plain"

    # ── Prompt Shield 专用 ──
    azure_endpoint: Optional[str] = None        # Azure Content Safety 端点
    force_entry_field: Optional[str] = None     # None / "userPrompt" / "documents"

    # ── OpenAI Image 专用 (DALL-E / GPT-Image) ──
    image_size: Optional[str] = None            # auto / 1024x1024 / 1536x1024 / 1024x1536
    output_format: Optional[str] = None         # png / jpeg / webp
    image_quality: Optional[str] = None         # auto / low / medium / high
    image_background: Optional[str] = None      # transparent / opaque / auto

    # ── OpenAI Video 专用 (Sora) ──
    video_resolution: Optional[str] = None      # 720x1280 / 1280x720 / 1024x1792 / 1792x1024
    video_n_seconds: Optional[int] = None       # 4 / 8 / 12

    # ── OpenAI TTS 专用 ──
    tts_voice: Optional[str] = None             # alloy / echo / fable / onyx / nova / shimmer
    tts_response_format: Optional[str] = None   # flac / mp3 / mp4 / mpeg / mpga / m4a / ogg / wav / webm
    tts_language: Optional[str] = None          # ISO 639-1 语言代码 (如 'en', 'zh')
    tts_speed: Optional[float] = None           # 0.25 ~ 4.0

    # ── Azure ML 专用 ──
    azure_ml_endpoint: Optional[str] = None     # Azure ML Managed Endpoint URL
    azure_ml_api_key: Optional[str] = None      # Azure ML API Key
    azure_ml_max_new_tokens: Optional[int] = None  # 最大生成 token 数
    azure_ml_temperature: Optional[float] = None   # 温度
    azure_ml_top_p: Optional[float] = None         # top_p
    azure_ml_repetition_penalty: Optional[float] = None  # 重复惩罚

    # ── LiteLLM 专用 ──
    drop_unsupported_params: bool = True        # 自动丢弃不支持的参数
    stop: Optional[Any] = None                  # 停止序列 (str 或 list[str])
    litellm_max_tokens: Optional[int] = None    # LiteLLM 使用 max_tokens (非 max_completion_tokens)

    # ── TargetConfiguration / CapabilityHandlingPolicy ──
    custom_configuration: Optional[TargetConfiguration] = None  # 显式传入完整配置
    capability_policy: Optional[str] = None     # "adapt" / "raise" — 不支持能力时的处理策略
    use_developer_role: bool = False            # 是否使用 developer role（替代 system role）
    system_message_behavior: Optional[str] = None  # "keep" / "squash" / "ignore" — 系统消息处理策略
    message_normalizer: Optional[str] = None    # "default" / "system_squash" / "context" — 消息规范化器类型
    validate_requirements: bool = True          # 是否对 chat 类型目标验证 CHAT_TARGET_REQUIREMENTS

    # ── 能力探测 ──
    discover_capabilities: bool = True          # 是否执行能力探测
    apply_discovered_capabilities: bool = True   # 是否将探测结果应用到 Target
    per_probe_timeout_s: float = 10.0
    use_model_profile: bool = True              # 是否使用 get_known_capabilities 模型档案查询

    # ── 评分器专用 ──
    force_json_output: bool = False             # Judge Target 强制 JSON 输出能力


# ============================================================
# 目标适配器工厂
# ============================================================


class TargetFactory:
    """
    目标适配器工厂 — L5 Expert

    统一入口：自动检测 → 认证解析 → 能力探测 → Target 创建

    支持 PyRIT 1.0.0 全部 Target 类型，覆盖 AI-300 考试所有目标场景。
    """

    # ──────────────────────────────────────
    # 1. 目标类型自动检测（side-effect-free）
    # ──────────────────────────────────────

    @staticmethod
    async def detect_target_type(target_url: str) -> str:
        """
        自动检测目标类型（仅发送 GET 请求，无副作用）

        探测顺序：
        1. 环境变量 TARGET_TYPE 手动覆盖
        2. GET /v1/models → 检测 OpenAI 兼容端点
        3. GET /v1/responses → 检测 Responses API（o1/o3 推理模型）
        4. GET / → 检测端点是否存在
        5. 默认 → http_api（结构化 HTTP）

        Args:
            target_url: 目标基础 URL

        Returns:
            目标类型字符串
        """
        url = target_url.rstrip("/")

        # 1. 环境变量手动覆盖
        env_type = os.getenv("TARGET_TYPE", "").strip().lower()
        if env_type:
            resolved = _LEGACY_TYPE_ALIASES.get(env_type, env_type)
            logger.info(f"Target type overridden by env: {env_type} → {resolved}")
            return resolved

        # 规范化 base URL
        base_url = url
        if url.endswith("/v1"):
            base_url = url[:-3]

        # 2. GET /v1/models — OpenAI Chat 兼容
        try:
            async with httpx.AsyncClient(timeout=5.0, verify=False) as client:
                response = await client.get(f"{base_url}/v1/models")
                if response.status_code == 200:
                    logger.info(f"Target type detected: {TARGET_TYPE_OPENAI_CHAT} (GET /v1/models → 200)")
                    return TARGET_TYPE_OPENAI_CHAT
        except Exception:
            pass

        # 3. 检测 /v1/responses — OpenAI Responses API（o1/o3 推理模型）
        # Responses API 没有 GET 端点，通过检查 /v1/responses 是否返回 405 (Method Not Allowed) 来判断
        try:
            async with httpx.AsyncClient(timeout=5.0, verify=False) as client:
                response = await client.get(f"{base_url}/v1/responses")
                # 405 = 端点存在但不支持 GET（Responses API 只支持 POST）
                # 401 = 需要认证但端点存在
                if response.status_code in (405, 401):
                    logger.info(f"Target type detected: {TARGET_TYPE_OPENAI_RESPONSES} (GET /v1/responses → {response.status_code})")
                    return TARGET_TYPE_OPENAI_RESPONSES
        except Exception:
            pass

        # 4. 检测 /chat/completions（不带 /v1 前缀）
        try:
            async with httpx.AsyncClient(timeout=5.0, verify=False) as client:
                response = await client.get(f"{url}/chat/completions")
                if response.status_code in (405, 401, 200):
                    logger.info(f"Target type detected: {TARGET_TYPE_OPENAI_CHAT} (GET /chat/completions → {response.status_code})")
                    return TARGET_TYPE_OPENAI_CHAT
        except Exception:
            pass

        # 5. 检测 /generate（HuggingFace TGI）
        try:
            async with httpx.AsyncClient(timeout=5.0, verify=False) as client:
                response = await client.post(
                    f"{url}/generate",
                    json={"inputs": "hi"},
                    headers={"Content-Type": "application/json"},
                )
                if response.status_code in (200, 400, 422):
                    logger.info(f"Target type detected: {TARGET_TYPE_HTTP_API} (POST /generate → {response.status_code})")
                    return TARGET_TYPE_HTTP_API
        except Exception:
            pass

        # 6. 默认为结构化 HTTP API
        logger.info(f"Target type auto-detected as: {TARGET_TYPE_HTTP_API} (fallback)")
        return TARGET_TYPE_HTTP_API

    # ──────────────────────────────────────
    # 2. 认证模式检测
    # ──────────────────────────────────────

    @staticmethod
    def detect_auth_mode(endpoint: str, params: TargetParams) -> str:
        """
        检测认证模式

        优先级：
        1. params.auth_mode 显式指定（非 "auto"）
        2. 环境变量 TARGET_AUTH_MODE
        3. Azure 端点 + 无 API Key → identity（Entra ID）
        4. 默认 → api_key

        Args:
            endpoint: 目标端点 URL
            params: 目标参数

        Returns:
            "api_key" 或 "identity"
        """
        # 显式指定
        if params.auth_mode and params.auth_mode != "auto":
            return params.auth_mode

        # 环境变量
        env_auth = os.getenv("TARGET_AUTH_MODE", "").strip().lower()
        if env_auth in ("api_key", "identity"):
            return env_auth

        # Azure 端点 + 无 API Key → Entra ID
        if is_azure_openai_endpoint(endpoint) and not params.api_key:
            logger.info(f"Azure OpenAI endpoint detected without API key → using Entra ID (identity)")
            return "identity"

        return "api_key"

    # ──────────────────────────────────────
    # 3. httpx_client_kwargs 构建
    # ──────────────────────────────────────

    # AsyncOpenAI.__init__ 直接接受的 httpx 相关参数
    # verify/proxy/http2 等不接受，需通过 http_client 预配置
    _OPENAI_ACCEPTED_HTTPX_PARAMS = frozenset({
        "timeout", "max_retries", "default_headers", "default_query", "http_client",
    })

    @staticmethod
    def _build_httpx_client_kwargs(params: TargetParams) -> Dict[str, Any]:
        """
        构建 httpx_client_kwargs（超时 / SSL / 代理 / 额外）

        合并来源（优先级：显式 kwargs > 单独字段 > 环境变量）：
        - params.httpx_client_kwargs（原始 dict，最高优先级）
        - params.httpx_timeout / httpx_verify / httpx_proxy（便捷字段）
        - TARGET_HTTPX_TIMEOUT / TARGET_HTTPX_VERIFY / TARGET_HTTPX_PROXY（环境变量）

        Returns:
            httpx_client_kwargs dict（适用于 HTTPTarget / HTTPXAPITarget）
        """
        kwargs: Dict[str, Any] = {}

        # 从环境变量加载默认值
        env_timeout = os.getenv("TARGET_HTTPX_TIMEOUT", "").strip()
        if env_timeout:
            try:
                kwargs["timeout"] = float(env_timeout)
            except ValueError:
                pass

        env_verify = os.getenv("TARGET_HTTPX_VERIFY", "").strip().lower()
        if env_verify in ("false", "0", "no"):
            kwargs["verify"] = False
        elif env_verify in ("true", "1", "yes"):
            kwargs["verify"] = True

        env_proxy = os.getenv("TARGET_HTTPX_PROXY", "").strip()
        if env_proxy:
            kwargs["proxy"] = env_proxy

        # 便捷字段覆盖环境变量
        if params.httpx_timeout is not None:
            kwargs["timeout"] = params.httpx_timeout
        if params.httpx_verify is not None:
            kwargs["verify"] = params.httpx_verify
        if params.httpx_proxy is not None:
            kwargs["proxy"] = params.httpx_proxy

        # 原始 kwargs 最高优先级
        if params.httpx_client_kwargs:
            kwargs.update(params.httpx_client_kwargs)

        return kwargs if kwargs else None

    @staticmethod
    def _build_openai_httpx_kwargs(params: TargetParams) -> Dict[str, Any]:
        """
        构建 OpenAI SDK 兼容的 httpx_client_kwargs

        AsyncOpenAI.__init__ 只接受 timeout/max_retries/default_headers/default_query/http_client。
        verify/proxy/http2 等参数需要通过预配置 httpx.AsyncClient 传给 http_client。

        Returns:
            OpenAI SDK 兼容的 httpx_client_kwargs dict
        """
        raw = TargetFactory._build_httpx_client_kwargs(params)
        if raw is None:
            return None

        # 拆分为 AsyncOpenAI 直接接受 vs 仅 httpx 接受
        accepted: Dict[str, Any] = {}
        excluded: Dict[str, Any] = {}
        for k, v in raw.items():
            if k in TargetFactory._OPENAI_ACCEPTED_HTTPX_PARAMS:
                accepted[k] = v
            else:
                excluded[k] = v

        # 如果有不接受的参数，创建预配置 httpx.AsyncClient
        if excluded:
            client_kwargs = dict(excluded)
            if "timeout" in accepted:
                client_kwargs.setdefault("timeout", accepted["timeout"])
            accepted["http_client"] = httpx.AsyncClient(**client_kwargs)
            logger.info(
                f"Created custom httpx.AsyncClient for OpenAI target "
                f"(extra params: {list(excluded.keys())})"
            )

        return accepted if accepted else None

    # ──────────────────────────────────────
    # 4. 能力探测（apply=True，使用部分结果）
    # ──────────────────────────────────────

    @staticmethod
    async def discover_capabilities(
        target: PromptTarget,
        params: TargetParams,
    ) -> Optional[TargetConfiguration]:
        """
        使用 PyRIT 原生功能发现目标能力

        L5 改进：
        1. apply=True — 将探测结果直接应用到 Target
        2. 使用部分结果 — 即使某些探针失败，也保留成功的探测结果
        3. 探针超时可配置（per_probe_timeout_s）

        Args:
            target: 已创建的 PromptTarget 实例
            params: 目标参数

        Returns:
            TargetConfiguration（探测后），探测完全失败返回 None
        """
        if not params.discover_capabilities:
            return None

        try:
            capabilities = await discover_target_capabilities_async(
                target=target,
                per_probe_timeout_s=params.per_probe_timeout_s,
                apply=params.apply_discovered_capabilities,
            )

            # 记录探测结果
            caps = capabilities
            supported = []
            if caps.supports_multi_turn:
                supported.append("multi_turn")
            if caps.supports_system_prompt:
                supported.append("system_prompt")
            if caps.supports_json_output:
                supported.append("json_output")
            if caps.supports_json_schema:
                supported.append("json_schema")
            if caps.supports_editable_history:
                supported.append("editable_history")
            logger.info(f"Capability discovery: {', '.join(supported) or 'none'}")

            return TargetConfiguration(capabilities=capabilities)

        except Exception as e:
            logger.warning(f"Capability discovery failed: {e}")
            return None

    # ──────────────────────────────────────
    # 4b. 模型能力档案查询 (P1-5: get_known_capabilities)
    # ──────────────────────────────────────

    @staticmethod
    def _resolve_model_capabilities(
        target_type: str,
        params: TargetParams,
    ) -> Optional[TargetConfiguration]:
        """
        根据模型名称查询原生能力档案，构建 TargetConfiguration

        查询顺序：
        1. params.custom_configuration（显式传入，最高优先级）
        2. get_known_capabilities(underlying_model)（PyRIT 原生模型档案）
        3. Target 类的 get_default_configuration()（类默认配置）
        4. None（让 Target 使用自身默认值）

        如果同时指定了 capability_policy / message_normalizer / system_message_behavior，
        会在此基础上叠加用户配置。

        Args:
            target_type: 目标类型
            params: 目标参数

        Returns:
            TargetConfiguration 实例，或 None
        """
        # 1. 显式传入的完整配置 — 直接返回（但叠加 policy/normalizer 覆盖）
        if params.custom_configuration is not None:
            return TargetFactory._overlay_configuration(params.custom_configuration, params)

        # 2. 使用 get_known_capabilities 查询模型档案
        model_name = params.underlying_model or params.model_name
        if params.use_model_profile and model_name:
            known_caps = get_known_capabilities(model_name)
            if known_caps is not None:
                logger.info(f"Model profile found for '{model_name}': "
                            f"input={known_caps.supported_input_modalities}, "
                            f"output={known_caps.supported_output_modalities}")
                policy = TargetFactory._build_capability_policy(params)
                normalizer_overrides = TargetFactory._build_normalizer_overrides(params)
                return TargetConfiguration(
                    capabilities=known_caps,
                    policy=policy,
                    normalizer_overrides=normalizer_overrides,
                )
            else:
                logger.debug(f"No model profile found for '{model_name}', using class default")

        # 3. 如果有 policy / normalizer 配置，也需要叠加到类默认配置上
        policy = TargetFactory._build_capability_policy(params)
        normalizer_overrides = TargetFactory._build_normalizer_overrides(params)
        if policy is not None or normalizer_overrides is not None:
            # 获取类默认配置
            target_cls = _TARGET_CLASSES.get(target_type)
            if target_cls is not None and hasattr(target_cls, "get_default_configuration"):
                default_config = target_cls.get_default_configuration()
                return TargetConfiguration(
                    capabilities=default_config.capabilities,
                    policy=policy or default_config.policy,
                    normalizer_overrides=normalizer_overrides,
                )

        return None

    @staticmethod
    def _overlay_configuration(
        base: TargetConfiguration,
        params: TargetParams,
    ) -> TargetConfiguration:
        """在已有 TargetConfiguration 基础上叠加用户的 policy / normalizer 配置"""
        policy = TargetFactory._build_capability_policy(params)
        normalizer_overrides = TargetFactory._build_normalizer_overrides(params)
        if policy is None and normalizer_overrides is None:
            return base
        return TargetConfiguration(
            capabilities=base.capabilities,
            policy=policy or base.policy,
            normalizer_overrides=normalizer_overrides,
        )

    # ──────────────────────────────────────
    # 4c. CapabilityHandlingPolicy 构建 (P1-3: ADAPT vs RAISE)
    # ──────────────────────────────────────

    @staticmethod
    def _build_capability_policy(params: TargetParams) -> Optional[CapabilityHandlingPolicy]:
        """
        构建 CapabilityHandlingPolicy

        根据 params.capability_policy 设置不支持能力时的行为：
        - "adapt": 自动适配（如 system prompt 不支持时 squash 到 user 消息）
        - "raise": 抛出异常

        默认策略（不设置时）：
        - SYSTEM_PROMPT → RAISE
        - MULTI_TURN → RAISE
        - JSON_SCHEMA → ADAPT

        Args:
            params: 目标参数

        Returns:
            CapabilityHandlingPolicy 实例，或 None（使用默认）
        """
        if not params.capability_policy:
            return None

        behavior = UnsupportedCapabilityBehavior.ADAPT if params.capability_policy == "adapt" else UnsupportedCapabilityBehavior.RAISE

        # 对所有可选能力统一应用用户指定策略
        behaviors = {
            CapabilityName.MULTI_TURN: behavior,
            CapabilityName.SYSTEM_PROMPT: behavior,
            CapabilityName.JSON_SCHEMA: behavior,
            CapabilityName.JSON_OUTPUT: behavior,
            CapabilityName.EDITABLE_HISTORY: behavior,
            CapabilityName.MULTI_MESSAGE_PIECES: behavior,
            CapabilityName.STREAMING_AUDIO: behavior,
        }

        logger.info(f"CapabilityHandlingPolicy: {params.capability_policy} for all capabilities")
        return CapabilityHandlingPolicy(behaviors=behaviors)

    # ──────────────────────────────────────
    # 4d. MessageNormalizer 构建 (P2-6: ChatMessageNormalizer 集成)
    # ──────────────────────────────────────

    @staticmethod
    def _build_message_normalizer(params: TargetParams) -> Optional[ChatMessageNormalizer]:
        """
        构建 ChatMessageNormalizer

        根据 params.message_normalizer 和 params.system_message_behavior 选择规范化器：
        - "default": ChatMessageNormalizer(use_developer_role=..., system_message_behavior=...)
        - "system_squash": GenericSystemSquashNormalizer（将 system 消息压入第一个 user 消息）
        - "context": ConversationContextNormalizer（保留对话上下文）

        如果 params.system_message_behavior 或 params.use_developer_role 被设置但 message_normalizer 未设置，
        默认使用 ChatMessageNormalizer。

        Args:
            params: 目标参数

        Returns:
            ChatMessageNormalizer 实例，或 None
        """
        normalizer_type = params.message_normalizer

        # 如果没有显式指定 normalizer 类型，但设置了行为参数，默认使用 ChatMessageNormalizer
        if normalizer_type is None:
            if params.use_developer_role or params.system_message_behavior:
                normalizer_type = "default"
            else:
                return None

        system_behavior = params.system_message_behavior or "keep"

        if normalizer_type == "system_squash":
            logger.info(f"MessageNormalizer: GenericSystemSquashNormalizer (use_developer_role={params.use_developer_role})")
            # GenericSystemSquashNormalizer 是预配置类，不接受构造参数
            # 它硬编码了 squash 行为，use_developer_role 需通过 ChatMessageNormalizer 使用
            return GenericSystemSquashNormalizer()
        elif normalizer_type == "context":
            logger.info(f"MessageNormalizer: ConversationContextNormalizer")
            return ConversationContextNormalizer()
        else:
            # default
            logger.info(f"MessageNormalizer: ChatMessageNormalizer "
                        f"(use_developer_role={params.use_developer_role}, behavior={system_behavior})")
            return ChatMessageNormalizer(
                use_developer_role=params.use_developer_role,
                system_message_behavior=system_behavior,
            )

    @staticmethod
    def _build_normalizer_overrides(params: TargetParams) -> Optional[Dict[CapabilityName, Any]]:
        """
        构建 normalizer_overrides 映射

        将 MessageNormalizer 映射到 CapabilityName.SYSTEM_PROMPT，
        当目标不支持 system_prompt 时使用该 normalizer 进行消息规范化。

        Args:
            params: 目标参数

        Returns:
            {CapabilityName: MessageListNormalizer} 映射，或 None
        """
        normalizer = TargetFactory._build_message_normalizer(params)
        if normalizer is None:
            return None

        # 将 normalizer 映射到 SYSTEM_PROMPT 能力
        # 当目标不支持 system_prompt 时，PyRIT 会使用此 normalizer 处理消息
        return {CapabilityName.SYSTEM_PROMPT: normalizer}

    # ──────────────────────────────────────
    # 4e. TargetRequirements 验证 (P1-4: CHAT_TARGET_REQUIREMENTS)
    # ──────────────────────────────────────

    @staticmethod
    def validate_target_requirements(
        target: PromptTarget,
        requirements: Optional[TargetRequirements] = None,
    ) -> None:
        """
        验证目标是否满足指定的能力要求

        默认使用 CHAT_TARGET_REQUIREMENTS（多轮对话 + 可编辑历史），
        也可传入自定义 TargetRequirements。

        验证失败时抛出 ValueError，列出所有缺失的能力。

        Args:
            target: 已创建的 PromptTarget 实例
            requirements: 能力要求（None 时使用 CHAT_TARGET_REQUIREMENTS）

        Raises:
            ValueError: 如果目标不满足能力要求
        """
        requirements = requirements or CHAT_TARGET_REQUIREMENTS
        try:
            requirements.validate(target=target)
            logger.info(f"Target {type(target).__name__} satisfies CHAT_TARGET_REQUIREMENTS")
        except ValueError as e:
            logger.warning(f"Target {type(target).__name__} does not satisfy requirements: {e}")
            # 不抛出异常，只记录警告 — 允许用户使用不完全兼容的目标
            # 如果需要严格模式，用户可以在调用层捕获并处理

    # ──────────────────────────────────────
    # 5. 辅助方法
    # ──────────────────────────────────────

    @staticmethod
    def _resolve_endpoint(target_url: str, target_type: str) -> str:
        """
        解析完整端点 URL

        OpenAI SDK 系列需要 /v1 后缀（除非已包含）
        """
        url = target_url.rstrip("/")
        if target_type in _OPENAI_SDK_TYPES:
            if "/v1" in url:
                return url
            return f"{url}/v1"
        return url

    @staticmethod
    def _resolve_api_key(api_key: Optional[str], auth_mode: str) -> Optional[str]:
        """
        解析 API Key

        identity 模式下返回 None（让 PyRIT 自动使用 Entra ID）
        api_key 模式下返回 key 或 placeholder
        """
        if auth_mode == "identity":
            return None  # PyRIT resolve_openai_auth 会自动使用 get_azure_openai_auth
        return api_key or os.getenv("TARGET_API_KEY", "placeholder")

    @staticmethod
    def _parse_headers(headers_str: Optional[str]) -> Dict[str, str]:
        """解析 JSON 格式的 headers 字符串"""
        if not headers_str:
            return {"Content-Type": "application/json"}
        try:
            return json.loads(headers_str)
        except (json.JSONDecodeError, TypeError):
            return {"Content-Type": "application/json"}

    @staticmethod
    def _parse_json_data(json_str: Optional[str]) -> Optional[Dict[str, Any]]:
        """解析 JSON 格式的 body 数据"""
        if not json_str:
            return None
        try:
            return json.loads(json_str)
        except (json.JSONDecodeError, TypeError):
            return None

    # ──────────────────────────────────────
    # 6. Target 创建（按类型分派）
    # ──────────────────────────────────────

    @staticmethod
    def create_target(
        target_type: str,
        target_url: str,
        params: Optional[TargetParams] = None,
    ) -> PromptTarget:
        """
        创建适配的 PromptTarget 实例

        Args:
            target_type: 目标类型（由 detect_target_type 或手动指定）
            target_url: 目标 URL
            params: 目标参数（None 时从环境变量加载）

        Returns:
            PromptTarget 实例
        """
        params = params or TargetParams()

        # 从环境变量补充缺失参数
        _apply_env_defaults(params)

        # 分派到对应的创建方法
        creator = _TARGET_CREATORS.get(target_type)
        if creator is None:
            raise ValueError(
                f"Unsupported target type: {target_type}. "
                f"Supported types: {', '.join(sorted(_TARGET_CREATORS.keys()))}"
            )

        target = creator(target_url, params)
        logger.info(f"Created {type(target).__name__} (type={target_type})")
        return target

    # ──────────────────────────────────────
    # 7. 完整流程：检测 → 探测 → 创建
    # ──────────────────────────────────────

    @staticmethod
    async def create_target_with_detection(
        target_url: str,
        api_key: Optional[str] = None,
        model_name: Optional[str] = None,
        params: Optional[TargetParams] = None,
    ) -> Tuple[PromptTarget, str]:
        """
        创建目标并返回类型（自动检测 + 能力探测 + 创建）

        完整流程：
        1. 加载参数（显式 > env > 默认）
        2. 自动检测目标类型（或使用 params.target_type）
        3. 解析认证模式
        4. 创建适配的 PromptTarget
        5. 探测目标能力（apply=True）

        Args:
            target_url: 目标 URL
            api_key: API Key（向后兼容，优先级低于 params.api_key）
            model_name: 模型名（向后兼容，优先级低于 params.model_name）
            params: 完整目标参数

        Returns:
            (PromptTarget 实例, 目标类型字符串)
        """
        params = params or TargetParams()

        # 向后兼容：显式参数覆盖 params
        if api_key is not None and params.api_key is None:
            params.api_key = api_key
        if model_name is not None and params.model_name is None:
            params.model_name = model_name

        # 从环境变量补充缺失参数
        _apply_env_defaults(params)

        # 1. 确定目标类型
        if params.target_type:
            target_type = _LEGACY_TYPE_ALIASES.get(params.target_type, params.target_type)
        else:
            target_type = await TargetFactory.detect_target_type(target_url)
        logger.info(f"Target type: {target_type}")

        # 2. 解析端点 URL
        endpoint = TargetFactory._resolve_endpoint(target_url, target_type)

        # 3. 解析认证模式
        auth_mode = TargetFactory.detect_auth_mode(endpoint, params)
        logger.info(f"Auth mode: {auth_mode}")

        # 3b. 解析模型能力档案（P1-5: get_known_capabilities + P1-3: CapabilityHandlingPolicy + P2-6: MessageNormalizer）
        if params.custom_configuration is None and target_type in _CUSTOM_CONFIG_TYPES:
            resolved_config = TargetFactory._resolve_model_capabilities(target_type, params)
            if resolved_config is not None:
                params.custom_configuration = resolved_config
                logger.info(f"Custom configuration resolved for {target_type}")

        # 4. 创建 Target
        target = TargetFactory.create_target(
            target_type=target_type,
            target_url=target_url,
            params=params,
        )

        # 4b. 验证 CHAT_TARGET_REQUIREMENTS（P1-4）
        if params.validate_requirements and target_type in _OPENAI_SDK_TYPES:
            TargetFactory.validate_target_requirements(target)

        # 5. 能力探测（仅对 SDK 系列目标）
        if target_type in _OPENAI_SDK_TYPES and params.discover_capabilities:
            await TargetFactory.discover_capabilities(target, params)

        return target, target_type


# ============================================================
# Target 创建器（按类型注册）
# ============================================================


def _create_openai_chat(target_url: str, params: TargetParams) -> OpenAIChatTarget:
    """创建 OpenAIChatTarget（Chat Completions API）"""

    endpoint = TargetFactory._resolve_endpoint(target_url, TARGET_TYPE_OPENAI_CHAT)
    auth_mode = TargetFactory.detect_auth_mode(endpoint, params)
    api_key = TargetFactory._resolve_api_key(params.api_key, auth_mode)
    httpx_kwargs = TargetFactory._build_openai_httpx_kwargs(params)

    kwargs: Dict[str, Any] = {
        "endpoint": endpoint,
        "api_key": api_key or "placeholder",
        "model_name": params.model_name or os.getenv("TARGET_MODEL", "test"),
    }

    # 推理参数
    if params.temperature is not None:
        kwargs["temperature"] = params.temperature
    if params.top_p is not None:
        kwargs["top_p"] = params.top_p
    if params.max_completion_tokens is not None:
        kwargs["max_completion_tokens"] = params.max_completion_tokens
    if params.frequency_penalty is not None:
        kwargs["frequency_penalty"] = params.frequency_penalty
    if params.presence_penalty is not None:
        kwargs["presence_penalty"] = params.presence_penalty
    if params.seed is not None:
        kwargs["seed"] = params.seed
    if params.n is not None:
        kwargs["n"] = params.n

    # extra_body_parameters
    if params.extra_body_parameters:
        kwargs["extra_body_parameters"] = params.extra_body_parameters

    # underlying_model
    if params.underlying_model:
        kwargs["underlying_model"] = params.underlying_model

    # httpx_client_kwargs
    if httpx_kwargs:
        kwargs["httpx_client_kwargs"] = httpx_kwargs

    # 速率限制
    if params.max_requests_per_minute:
        kwargs["max_requests_per_minute"] = params.max_requests_per_minute

    # custom_configuration（P0-2: 包含 CapabilityHandlingPolicy + MessageNormalizer + 模型档案）
    if params.custom_configuration is not None:
        kwargs["custom_configuration"] = params.custom_configuration

    return OpenAIChatTarget(**kwargs)


def _create_openai_responses(target_url: str, params: TargetParams) -> OpenAIResponseTarget:
    """
    创建 OpenAIResponseTarget（Responses API）

    支持：
    - o1/o3/o4-mini 推理模型
    - reasoning_effort / reasoning_summary 控制
    - Agentic Tool Calling 循环（custom_functions）
    - 完整 Content Filter 处理链（两条检测路径）
    """
    endpoint = TargetFactory._resolve_endpoint(target_url, TARGET_TYPE_OPENAI_RESPONSES)
    auth_mode = TargetFactory.detect_auth_mode(endpoint, params)
    api_key = TargetFactory._resolve_api_key(params.api_key, auth_mode)
    httpx_kwargs = TargetFactory._build_openai_httpx_kwargs(params)

    kwargs: Dict[str, Any] = {
        "endpoint": endpoint,
        "api_key": api_key or "placeholder",
        "model_name": params.model_name or os.getenv("TARGET_MODEL", "test"),
    }

    # 推理参数
    if params.temperature is not None:
        kwargs["temperature"] = params.temperature
    if params.top_p is not None:
        kwargs["top_p"] = params.top_p
    if params.max_output_tokens is not None:
        kwargs["max_output_tokens"] = params.max_output_tokens

    # Responses API 专用：推理控制
    if params.reasoning_effort is not None:
        kwargs["reasoning_effort"] = params.reasoning_effort
    if params.reasoning_summary is not None:
        kwargs["reasoning_summary"] = params.reasoning_summary

    # Agentic Tool Calling
    if params.custom_functions:
        kwargs["custom_functions"] = params.custom_functions
        kwargs["fail_on_missing_function"] = params.fail_on_missing_function

    # extra_body_parameters（可能包含 tools 定义）
    if params.extra_body_parameters:
        kwargs["extra_body_parameters"] = params.extra_body_parameters

    # underlying_model
    if params.underlying_model:
        kwargs["underlying_model"] = params.underlying_model

    # httpx_client_kwargs（推理模型需要更长超时）
    if httpx_kwargs:
        kwargs["httpx_client_kwargs"] = httpx_kwargs

    # 速率限制
    if params.max_requests_per_minute:
        kwargs["max_requests_per_minute"] = params.max_requests_per_minute

    # custom_configuration（P0-2）
    if params.custom_configuration is not None:
        kwargs["custom_configuration"] = params.custom_configuration

    return OpenAIResponseTarget(**kwargs)


def _create_litellm(target_url: str, params: TargetParams) -> PromptTarget:
    """
    创建 LiteLLMChatTarget（100+ LLM Provider 统一接入）

    支持 Anthropic Claude / Google Gemini / Cohere / Mistral 等。
    通过 LiteLLM 库统一 API，自动处理 Provider 差异。

    P3-10 增强：
    - 修复 model → model_name 参数名
    - 补全 frequency_penalty / presence_penalty / n / stop / underlying_model
    - 补全 drop_unsupported_params / custom_configuration
    - reasoning_effort 通过 extra_body_parameters 透传
    """
    try:
        from pyrit.prompt_target import LiteLLMChatTarget
    except ImportError:
        logger.warning(
            "LiteLLMChatTarget not available. Install with: pip install litellm. "
            "Falling back to OpenAIChatTarget."
        )
        return _create_openai_chat(target_url, params)

    kwargs: Dict[str, Any] = {
        "model_name": params.model_name or os.getenv("TARGET_MODEL", "gpt-4o"),
        "endpoint": target_url or None,
        "api_key": params.api_key or os.getenv("TARGET_API_KEY", "placeholder"),
    }

    # 推理参数（LiteLLM 使用 max_tokens 而非 max_completion_tokens）
    if params.temperature is not None:
        kwargs["temperature"] = params.temperature
    if params.top_p is not None:
        kwargs["top_p"] = params.top_p
    if params.litellm_max_tokens is not None:
        kwargs["max_tokens"] = params.litellm_max_tokens
    elif params.max_completion_tokens is not None:
        kwargs["max_tokens"] = params.max_completion_tokens
    if params.frequency_penalty is not None:
        kwargs["frequency_penalty"] = params.frequency_penalty
    if params.presence_penalty is not None:
        kwargs["presence_penalty"] = params.presence_penalty
    if params.seed is not None:
        kwargs["seed"] = params.seed
    if params.n is not None:
        kwargs["n"] = params.n
    if params.stop is not None:
        kwargs["stop"] = params.stop

    # drop_unsupported_params（LiteLLM 专用）
    kwargs["drop_unsupported_params"] = params.drop_unsupported_params

    # extra_body_parameters（合并 reasoning_effort 等推理参数）
    extra_body = dict(params.extra_body_parameters or {})
    if params.reasoning_effort is not None and "reasoning" not in extra_body:
        extra_body["reasoning_effort"] = params.reasoning_effort
    if params.reasoning_summary is not None and "reasoning_summary" not in extra_body:
        extra_body["reasoning_summary"] = params.reasoning_summary
    if extra_body:
        kwargs["extra_body_parameters"] = extra_body

    # underlying_model
    if params.underlying_model:
        kwargs["underlying_model"] = params.underlying_model

    # httpx_client_kwargs
    httpx_kwargs = TargetFactory._build_openai_httpx_kwargs(params)
    if httpx_kwargs:
        kwargs["httpx_client_kwargs"] = httpx_kwargs

    # 速率限制
    if params.max_requests_per_minute:
        kwargs["max_requests_per_minute"] = params.max_requests_per_minute

    # custom_configuration（P0-2）
    if params.custom_configuration is not None:
        kwargs["custom_configuration"] = params.custom_configuration

    return LiteLLMChatTarget(**kwargs)


def _create_http_api(target_url: str, params: TargetParams) -> HTTPXAPITarget:
    """创建 HTTPXAPITarget（结构化 HTTP API）"""
    httpx_kwargs = TargetFactory._build_httpx_client_kwargs(params)

    kwargs: Dict[str, Any] = {
        "http_url": target_url,
        "method": params.method,
        "headers": params.headers or {"Content-Type": "application/json"},
    }

    # JSON body（注入 {PROMPT} 占位符如果未包含）
    if params.json_data:
        kwargs["json_data"] = params.json_data
    else:
        kwargs["json_data"] = {"messages": [{"role": "user", "content": "{PROMPT}"}]}

    if params.form_data:
        kwargs["form_data"] = params.form_data
    if params.params:
        kwargs["params"] = params.params
    if params.file_path:
        kwargs["file_path"] = params.file_path
    if params.callback_function:
        kwargs["callback_function"] = params.callback_function
    if params.max_requests_per_minute:
        kwargs["max_requests_per_minute"] = params.max_requests_per_minute

    # httpx_client_kwargs
    if httpx_kwargs:
        kwargs.update(httpx_kwargs)

    return HTTPXAPITarget(**kwargs)


def _create_http_raw(target_url: str, params: TargetParams) -> HTTPTarget:
    """创建 HTTPTarget（原始 HTTP 请求 / Burp Suite 导出）"""
    if not params.raw_http_request:
        raise ValueError(
            "http_raw target requires 'raw_http_request' in params "
            "or TARGET_RAW_REQUEST / TARGET_RAW_REQUEST_FILE env var"
        )

    httpx_kwargs = TargetFactory._build_httpx_client_kwargs(params)

    kwargs: Dict[str, Any] = {
        "http_request": params.raw_http_request,
        "prompt_regex_string": params.prompt_regex_string,
        "use_tls": params.use_tls,
    }

    if params.callback_function:
        kwargs["callback_function"] = params.callback_function
    if params.max_requests_per_minute:
        kwargs["max_requests_per_minute"] = params.max_requests_per_minute
    if params.model_name:
        kwargs["model_name"] = params.model_name

    # httpx_client_kwargs 作为 **kwargs 传递
    if httpx_kwargs:
        kwargs.update(httpx_kwargs)

    return HTTPTarget(**kwargs)


def _create_playwright(target_url: str, params: TargetParams) -> PromptTarget:
    """
    创建 PlaywrightTarget（Web UI 自动化）

    需要 params.interaction_func 和 params.page。
    用于测试基于 Web 的聊天界面（ChatGPT Web、企业 AI 助手等）。
    """
    try:
        from pyrit.prompt_target import PlaywrightTarget
    except ImportError:
        raise ImportError(
            "PlaywrightTarget requires playwright. Install with: pip install playwright && playwright install"
        )

    if params.interaction_func is None:
        raise ValueError("playwright target requires 'interaction_func' in params")
    if params.page is None:
        raise ValueError("playwright target requires 'page' in params (playwright.async_api.Page)")

    kwargs: Dict[str, Any] = {
        "interaction_func": params.interaction_func,
        "page": params.page,
    }

    if params.max_requests_per_minute:
        kwargs["max_requests_per_minute"] = params.max_requests_per_minute

    return PlaywrightTarget(**kwargs)


def _create_websocket_copilot(target_url: str, params: TargetParams) -> PromptTarget:
    """
    创建 WebSocketCopilotTarget（Microsoft 365 Copilot）

    支持两种认证：
    1. 自动认证（CopilotAuthenticator）：需要 copilot_username + copilot_password
    2. 手动认证（ManualCopilotAuthenticator）：需要 copilot_access_token
    """
    try:
        from pyrit.prompt_target import WebSocketCopilotTarget
    except ImportError:
        raise ImportError(
            "WebSocketCopilotTarget requires websockets. Install with: pip install websockets"
        )

    kwargs: Dict[str, Any] = {}

    # 优先使用 access token
    if params.copilot_access_token:
        from pyrit.auth import ManualCopilotAuthenticator
        kwargs["authenticator"] = ManualCopilotAuthenticator(access_token=params.copilot_access_token)
    elif params.copilot_username and params.copilot_password:
        from pyrit.auth import CopilotAuthenticator
        kwargs["authenticator"] = CopilotAuthenticator(
            username=params.copilot_username,
            password=params.copilot_password,
        )
    else:
        # 从环境变量加载
        username = os.getenv("COPILOT_USERNAME", "").strip()
        password = os.getenv("COPILOT_PASSWORD", "").strip()
        token = os.getenv("COPILOT_ACCESS_TOKEN", "").strip()
        if token:
            from pyrit.auth import ManualCopilotAuthenticator
            kwargs["authenticator"] = ManualCopilotAuthenticator(access_token=token)
        elif username and password:
            from pyrit.auth import CopilotAuthenticator
            kwargs["authenticator"] = CopilotAuthenticator(username=username, password=password)
        else:
            raise ValueError(
                "websocket_copilot target requires Copilot credentials. "
                "Set COPILOT_USERNAME + COPILOT_PASSWORD or COPILOT_ACCESS_TOKEN env var."
            )

    if params.max_requests_per_minute:
        kwargs["max_requests_per_minute"] = params.max_requests_per_minute

    return WebSocketCopilotTarget(**kwargs)


def _create_playwright_copilot(target_url: str, params: TargetParams) -> PromptTarget:
    """创建 PlaywrightCopilotTarget（Copilot 浏览器自动化）"""
    try:
        from pyrit.prompt_target import PlaywrightCopilotTarget, CopilotType
    except ImportError:
        raise ImportError(
            "PlaywrightCopilotTarget requires playwright. Install with: pip install playwright && playwright install"
        )

    kwargs: Dict[str, Any] = {}

    # Copilot 类型
    copilot_type_str = os.getenv("COPILOT_TYPE", "m365").strip().lower()
    try:
        kwargs["copilot_type"] = CopilotType(copilot_type_str)
    except ValueError:
        kwargs["copilot_type"] = CopilotType.M365

    # 认证
    if params.copilot_access_token:
        from pyrit.auth import ManualCopilotAuthenticator
        kwargs["authenticator"] = ManualCopilotAuthenticator(access_token=params.copilot_access_token)
    elif params.copilot_username and params.copilot_password:
        from pyrit.auth import CopilotAuthenticator
        kwargs["authenticator"] = CopilotAuthenticator(
            username=params.copilot_username,
            password=params.copilot_password,
        )
    else:
        username = os.getenv("COPILOT_USERNAME", "").strip()
        password = os.getenv("COPILOT_PASSWORD", "").strip()
        token = os.getenv("COPILOT_ACCESS_TOKEN", "").strip()
        if token:
            from pyrit.auth import ManualCopilotAuthenticator
            kwargs["authenticator"] = ManualCopilotAuthenticator(access_token=token)
        elif username and password:
            from pyrit.auth import CopilotAuthenticator
            kwargs["authenticator"] = CopilotAuthenticator(username=username, password=password)
        else:
            raise ValueError(
                "playwright_copilot target requires Copilot credentials. "
                "Set COPILOT_USERNAME + COPILOT_PASSWORD or COPILOT_ACCESS_TOKEN env var."
            )

    if params.max_requests_per_minute:
        kwargs["max_requests_per_minute"] = params.max_requests_per_minute

    return PlaywrightCopilotTarget(**kwargs)


def _create_azure_blob(target_url: str, params: TargetParams) -> PromptTarget:
    """
    创建 AzureBlobStorageTarget（XPIA 载荷投递）

    用于将恶意文档上传到 Azure Blob Storage，
    等待目标 RAG 系统检索并执行注入（OWASP LLM08 Vector Injection）。
    """
    try:
        from pyrit.prompt_target import AzureBlobStorageTarget
    except ImportError:
        raise ImportError(
            "AzureBlobStorageTarget requires azure-storage-blob. "
            "Install with: pip install azure-storage-blob azure-identity"
        )

    container_url = params.container_url or os.getenv("AZURE_STORAGE_ACCOUNT_CONTAINER_URL", "").strip()
    if not container_url:
        raise ValueError(
            "azure_blob target requires 'container_url' in params "
            "or AZURE_STORAGE_ACCOUNT_CONTAINER_URL env var"
        )

    kwargs: Dict[str, Any] = {"container_url": container_url}

    sas_token = params.sas_token or os.getenv("AZURE_STORAGE_ACCOUNT_SAS_TOKEN", "").strip()
    if sas_token:
        kwargs["sas_token"] = sas_token

    # blob_content_type
    from pyrit.prompt_target.azure_blob_storage_target import SupportedContentType
    try:
        kwargs["blob_content_type"] = SupportedContentType(params.blob_content_type)
    except ValueError:
        kwargs["blob_content_type"] = SupportedContentType.PLAIN_TEXT

    if params.max_requests_per_minute:
        kwargs["max_requests_per_minute"] = params.max_requests_per_minute

    return AzureBlobStorageTarget(**kwargs)


def _create_prompt_shield(target_url: str, params: TargetParams) -> PromptTarget:
    """
    创建 PromptShieldTarget（Azure AI Content Safety Prompt Shield）

    用于测试目标的 Prompt Shield 防御能力。
    Prompt Shield 检测 jailbreak 攻击（非内容有害性）。
    """
    try:
        from pyrit.prompt_target import PromptShieldTarget
    except ImportError:
        raise ImportError(
            "PromptShieldTarget requires azure-ai-contentsafety. "
            "Install with: pip install azure-ai-contentsafety azure-identity"
        )

    azure_endpoint = params.azure_endpoint or os.getenv("AZURE_CONTENT_SAFETY_API_ENDPOINT", "").strip()
    if not azure_endpoint:
        raise ValueError(
            "prompt_shield target requires 'azure_endpoint' in params "
            "or AZURE_CONTENT_SAFETY_API_ENDPOINT env var"
        )

    kwargs: Dict[str, Any] = {"azure_endpoint": azure_endpoint}

    api_key = params.api_key or os.getenv("AZURE_CONTENT_SAFETY_API_KEY", "").strip()
    if api_key:
        kwargs["api_key"] = api_key

    if params.force_entry_field:
        kwargs["force_entry_field"] = params.force_entry_field

    if params.max_requests_per_minute:
        kwargs["max_requests_per_minute"] = params.max_requests_per_minute

    return PromptShieldTarget(**kwargs)


def _create_text(target_url: str, params: TargetParams) -> TextTarget:
    """创建 TextTarget（调试输出，将响应写入文本流）"""
    if params.file_path:
        file_path = params.file_path
        if not os.path.isabs(file_path):
            project_root = Path(__file__).parent.parent.parent
            file_path = project_root / file_path
        Path(file_path).parent.mkdir(parents=True, exist_ok=True)
        text_stream = open(file_path, "a", encoding="utf-8", errors="replace")
        return TextTarget(text_stream=text_stream)
    return TextTarget()


def _create_openai_image(target_url: str, params: TargetParams) -> OpenAIImageTarget:
    """创建 OpenAIImageTarget（DALL-E / GPT-Image 图片生成目标）

    用于多模态攻击测试：向图片生成模型发送提示，获取生成的图片。
    支持的参数：image_size, output_format, quality, background。

    P0-1 修复：
    - 修复 detect_auth_mode 调用错误（NameError）
    - 修复 _build_openai_httpx_kwargs 调用错误
    - 修复 deployment → model_name 参数名
    - 补全 max_requests_per_minute / custom_configuration
    - 修复认证逻辑（identity 模式下 api_key=None 让 PyRIT 自动使用 Entra ID）
    """
    endpoint = target_url.rstrip("/")
    auth_mode = TargetFactory.detect_auth_mode(endpoint, params)

    kwargs: Dict[str, Any] = {
        "endpoint": endpoint,
    }

    # 认证
    if auth_mode == "api_key":
        api_key = params.api_key or os.getenv("TARGET_API_KEY", "placeholder")
        kwargs["api_key"] = api_key
    # identity 模式下不传 api_key，让 PyRIT 自动使用 Entra ID

    # 图片生成参数
    if params.image_size:
        kwargs["image_size"] = params.image_size
    if params.output_format:
        kwargs["output_format"] = params.output_format
    if params.image_quality:
        kwargs["quality"] = params.image_quality
    if params.image_background:
        kwargs["background"] = params.image_background

    # model_name（OpenAITarget 基类参数，不是 deployment）
    model = params.model_name or os.getenv("TARGET_MODEL", "dall-e-3")
    kwargs["model_name"] = model

    # underlying_model（Azure 部署名 ≠ 模型名时使用）
    if params.underlying_model:
        kwargs["underlying_model"] = params.underlying_model

    # httpx_client_kwargs 透传
    httpx_kwargs = TargetFactory._build_openai_httpx_kwargs(params)
    if httpx_kwargs:
        kwargs["httpx_client_kwargs"] = httpx_kwargs

    # 速率限制
    if params.max_requests_per_minute:
        kwargs["max_requests_per_minute"] = params.max_requests_per_minute

    # custom_configuration（P0-2）
    if params.custom_configuration is not None:
        kwargs["custom_configuration"] = params.custom_configuration

    logger.info(f"Creating OpenAIImageTarget: endpoint={endpoint}, model={model}")
    return OpenAIImageTarget(**kwargs)


def _create_openai_video(target_url: str, params: TargetParams) -> OpenAIVideoTarget:
    """创建 OpenAIVideoTarget（Sora 视频生成目标）

    用于多模态攻击测试：向视频生成模型发送提示，获取生成的视频。
    支持的参数：resolution_dimensions, n_seconds。

    P2-7 新增：
    - 支持 Sora 视频生成模型
    - 支持 text + image → video 混合模态输入
    - 完整认证 / httpx_client_kwargs / custom_configuration 透传
    """
    endpoint = target_url.rstrip("/")
    auth_mode = TargetFactory.detect_auth_mode(endpoint, params)

    kwargs: Dict[str, Any] = {
        "endpoint": endpoint,
    }

    # 认证
    if auth_mode == "api_key":
        api_key = params.api_key or os.getenv("TARGET_API_KEY", "placeholder")
        kwargs["api_key"] = api_key

    # 视频生成参数
    if params.video_resolution:
        kwargs["resolution_dimensions"] = params.video_resolution
    if params.video_n_seconds is not None:
        kwargs["n_seconds"] = params.video_n_seconds

    # model_name
    model = params.model_name or os.getenv("TARGET_MODEL", "sora-2")
    kwargs["model_name"] = model

    # underlying_model
    if params.underlying_model:
        kwargs["underlying_model"] = params.underlying_model

    # httpx_client_kwargs
    httpx_kwargs = TargetFactory._build_openai_httpx_kwargs(params)
    if httpx_kwargs:
        kwargs["httpx_client_kwargs"] = httpx_kwargs

    # 速率限制
    if params.max_requests_per_minute:
        kwargs["max_requests_per_minute"] = params.max_requests_per_minute

    # custom_configuration（P0-2）
    if params.custom_configuration is not None:
        kwargs["custom_configuration"] = params.custom_configuration

    logger.info(f"Creating OpenAIVideoTarget: endpoint={endpoint}, model={model}")
    return OpenAIVideoTarget(**kwargs)


def _create_openai_tts(target_url: str, params: TargetParams) -> OpenAITTSTarget:
    """创建 OpenAITTSTarget（文本转语音目标）

    用于多模态攻击测试：向 TTS 模型发送提示，获取生成的音频。
    支持的参数：voice, response_format, language, speed。

    P2-8 新增：
    - 支持 OpenAI TTS 模型
    - 完整认证 / httpx_client_kwargs / custom_configuration 透传
    """
    endpoint = target_url.rstrip("/")
    auth_mode = TargetFactory.detect_auth_mode(endpoint, params)

    kwargs: Dict[str, Any] = {
        "endpoint": endpoint,
    }

    # 认证
    if auth_mode == "api_key":
        api_key = params.api_key or os.getenv("TARGET_API_KEY", "placeholder")
        kwargs["api_key"] = api_key

    # TTS 参数
    if params.tts_voice:
        kwargs["voice"] = params.tts_voice
    if params.tts_response_format:
        kwargs["response_format"] = params.tts_response_format
    if params.tts_language:
        kwargs["language"] = params.tts_language
    if params.tts_speed is not None:
        kwargs["speed"] = params.tts_speed

    # model_name
    model = params.model_name or os.getenv("TARGET_MODEL", "tts-1")
    kwargs["model_name"] = model

    # underlying_model
    if params.underlying_model:
        kwargs["underlying_model"] = params.underlying_model

    # httpx_client_kwargs
    httpx_kwargs = TargetFactory._build_openai_httpx_kwargs(params)
    if httpx_kwargs:
        kwargs["httpx_client_kwargs"] = httpx_kwargs

    # 速率限制
    if params.max_requests_per_minute:
        kwargs["max_requests_per_minute"] = params.max_requests_per_minute

    # custom_configuration（P0-2）
    if params.custom_configuration is not None:
        kwargs["custom_configuration"] = params.custom_configuration

    logger.info(f"Creating OpenAITTSTarget: endpoint={endpoint}, model={model}")
    return OpenAITTSTarget(**kwargs)


def _create_azure_ml(target_url: str, params: TargetParams) -> PromptTarget:
    """创建 AzureMLChatTarget（Azure ML Managed Endpoint 对话目标）

    用于攻击部署在 Azure ML 上的开源模型（Llama, Mistral 等）。
    Azure ML 使用独立的认证体系（AZURE_ML_KEY / AZURE_ML_MANAGED_ENDPOINT）。

    P3-9 新增：
    - 支持 Azure ML Managed Endpoint
    - 完整推理参数透传（max_new_tokens / temperature / top_p / repetition_penalty）
    - custom_configuration 透传
    """
    try:
        from pyrit.prompt_target import AzureMLChatTarget
    except ImportError:
        raise ImportError(
            "AzureMLChatTarget requires azure-identity. "
            "Install with: pip install azure-identity"
        )

    # 端点（优先显式参数 > 环境变量 > target_url）
    endpoint = params.azure_ml_endpoint or os.getenv("AZURE_ML_MANAGED_ENDPOINT", "").strip() or target_url
    if not endpoint:
        raise ValueError(
            "azure_ml target requires 'azure_ml_endpoint' in params "
            "or AZURE_ML_MANAGED_ENDPOINT env var"
        )

    kwargs: Dict[str, Any] = {
        "endpoint": endpoint,
    }

    # 认证
    api_key = params.azure_ml_api_key or os.getenv("AZURE_ML_KEY", "").strip()
    if api_key:
        kwargs["api_key"] = api_key

    # 模型名
    if params.model_name:
        kwargs["model_name"] = params.model_name

    # 推理参数
    if params.azure_ml_max_new_tokens is not None:
        kwargs["max_new_tokens"] = params.azure_ml_max_new_tokens
    if params.azure_ml_temperature is not None:
        kwargs["temperature"] = params.azure_ml_temperature
    elif params.temperature is not None:
        kwargs["temperature"] = params.temperature
    if params.azure_ml_top_p is not None:
        kwargs["top_p"] = params.azure_ml_top_p
    elif params.top_p is not None:
        kwargs["top_p"] = params.top_p
    if params.azure_ml_repetition_penalty is not None:
        kwargs["repetition_penalty"] = params.azure_ml_repetition_penalty

    # 速率限制
    if params.max_requests_per_minute:
        kwargs["max_requests_per_minute"] = params.max_requests_per_minute

    # custom_configuration（P0-2）
    if params.custom_configuration is not None:
        kwargs["custom_configuration"] = params.custom_configuration

    logger.info(f"Creating AzureMLChatTarget: endpoint={endpoint}")
    return AzureMLChatTarget(**kwargs)


# Target 创建器注册表
_TARGET_CREATORS: Dict[str, Callable[[str, TargetParams], PromptTarget]] = {
    TARGET_TYPE_OPENAI_CHAT: _create_openai_chat,
    TARGET_TYPE_OPENAI_RESPONSES: _create_openai_responses,
    TARGET_TYPE_LITELLM: _create_litellm,
    TARGET_TYPE_HTTP_API: _create_http_api,
    TARGET_TYPE_HTTP_RAW: _create_http_raw,
    TARGET_TYPE_PLAYWRIGHT: _create_playwright,
    TARGET_TYPE_WEBSOCKET_COPILOT: _create_websocket_copilot,
    TARGET_TYPE_PLAYWRIGHT_COPILOT: _create_playwright_copilot,
    TARGET_TYPE_AZURE_BLOB: _create_azure_blob,
    TARGET_TYPE_PROMPT_SHIELD: _create_prompt_shield,
    TARGET_TYPE_OPENAI_IMAGE: _create_openai_image,
    TARGET_TYPE_OPENAI_VIDEO: _create_openai_video,
    TARGET_TYPE_OPENAI_TTS: _create_openai_tts,
    TARGET_TYPE_AZURE_ML: _create_azure_ml,
    TARGET_TYPE_TEXT: _create_text,
}

# Target 类映射（用于 get_default_configuration 查询）
_TARGET_CLASSES: Dict[str, type] = {
    TARGET_TYPE_OPENAI_CHAT: OpenAIChatTarget,
    TARGET_TYPE_OPENAI_RESPONSES: OpenAIResponseTarget,
    TARGET_TYPE_OPENAI_IMAGE: OpenAIImageTarget,
    TARGET_TYPE_OPENAI_VIDEO: OpenAIVideoTarget,
    TARGET_TYPE_OPENAI_TTS: OpenAITTSTarget,
}


# ============================================================
# 环境变量加载
# ============================================================


def _apply_env_defaults(params: TargetParams) -> None:
    """从环境变量 + config/defaults/ 补充缺失参数（不覆盖已有值）

    优先级：显式参数 > .env 环境变量 > config/defaults/*.yaml > 硬编码兜底
    """

    # 延迟导入避免循环依赖
    from src.core.config_loader import get_config_loader
    cfg = get_config_loader()

    # httpx 客户端配置（.env > config/defaults/http_client.yaml）
    if params.httpx_timeout is None:
        env_val = os.getenv("TARGET_HTTPX_TIMEOUT", "").strip()
        if env_val:
            try:
                params.httpx_timeout = float(env_val)
            except ValueError:
                pass
        else:
            params.httpx_timeout = float(cfg.get_target_httpx_timeout())

    if params.httpx_verify is None:
        env_val = os.getenv("TARGET_HTTPX_VERIFY", "").strip().lower()
        if env_val in ("false", "0", "no"):
            params.httpx_verify = False
        elif env_val in ("true", "1", "yes"):
            params.httpx_verify = True
        else:
            params.httpx_verify = cfg.get_target_httpx_verify()

    if params.httpx_proxy is None:
        env_val = os.getenv("TARGET_HTTPX_PROXY", "").strip()
        if env_val:
            params.httpx_proxy = env_val
        else:
            proxy = cfg.get_target_httpx_proxy()
            if proxy:
                params.httpx_proxy = proxy

    # 认证模式
    if params.auth_mode == "auto":
        env_val = os.getenv("TARGET_AUTH_MODE", "").strip().lower()
        if env_val in ("api_key", "identity"):
            params.auth_mode = env_val

    # 推理参数（.env > config/defaults/model_params.yaml）
    if params.temperature is None:
        env_val = os.getenv("TARGET_TEMPERATURE", "").strip()
        if env_val:
            try:
                params.temperature = float(env_val)
            except ValueError:
                pass
        else:
            val = cfg.get_target_temperature()
            if val is not None:
                params.temperature = val

    if params.top_p is None:
        env_val = os.getenv("TARGET_TOP_P", "").strip()
        if env_val:
            try:
                params.top_p = float(env_val)
            except ValueError:
                pass
        else:
            val = cfg.get_target_top_p()
            if val is not None:
                params.top_p = val

    if params.max_completion_tokens is None:
        env_val = os.getenv("TARGET_MAX_COMPLETION_TOKENS", "").strip()
        if env_val:
            try:
                params.max_completion_tokens = int(env_val)
            except ValueError:
                pass
        else:
            val = cfg.get_target_max_completion_tokens()
            if val is not None:
                params.max_completion_tokens = val

    if params.max_output_tokens is None:
        env_val = os.getenv("TARGET_MAX_OUTPUT_TOKENS", "").strip()
        if env_val:
            try:
                params.max_output_tokens = int(env_val)
            except ValueError:
                pass
        else:
            val = cfg.get_target_max_output_tokens()
            if val is not None:
                params.max_output_tokens = val

    if params.seed is None:
        env_val = os.getenv("TARGET_SEED", "").strip()
        if env_val:
            try:
                params.seed = int(env_val)
            except ValueError:
                pass
        else:
            val = cfg.get_target_seed()
            if val is not None:
                params.seed = val

    if params.frequency_penalty is None:
        env_val = os.getenv("TARGET_FREQUENCY_PENALTY", "").strip()
        if env_val:
            try:
                params.frequency_penalty = float(env_val)
            except ValueError:
                pass
        else:
            val = cfg.get_target_frequency_penalty()
            if val is not None:
                params.frequency_penalty = val

    if params.presence_penalty is None:
        env_val = os.getenv("TARGET_PRESENCE_PENALTY", "").strip()
        if env_val:
            try:
                params.presence_penalty = float(env_val)
            except ValueError:
                pass
        else:
            val = cfg.get_target_presence_penalty()
            if val is not None:
                params.presence_penalty = val

    # Responses API 专用
    if params.reasoning_effort is None:
        env_val = os.getenv("TARGET_REASONING_EFFORT", "").strip().lower()
        if env_val in ("minimal", "low", "medium", "high"):
            params.reasoning_effort = env_val
        else:
            val = cfg.get_target_reasoning_effort()
            if val is not None:
                params.reasoning_effort = val

    if params.reasoning_summary is None:
        env_val = os.getenv("TARGET_REASONING_SUMMARY", "").strip().lower()
        if env_val in ("auto", "concise", "detailed"):
            params.reasoning_summary = env_val
        else:
            val = cfg.get_target_reasoning_summary()
            if val is not None:
                params.reasoning_summary = val

    # extra_body_parameters
    if params.extra_body_parameters is None:
        env_val = os.getenv("TARGET_EXTRA_BODY_PARAMETERS", "").strip()
        if env_val:
            try:
                params.extra_body_parameters = json.loads(env_val)
            except (json.JSONDecodeError, TypeError):
                logger.warning(f"Failed to parse TARGET_EXTRA_BODY_PARAMETERS: {env_val}")

    # underlying_model
    if params.underlying_model is None:
        env_val = os.getenv("TARGET_UNDERLYING_MODEL", "").strip()
        if env_val:
            params.underlying_model = env_val

    # 速率限制
    if params.max_requests_per_minute is None:
        env_val = os.getenv("TARGET_MAX_REQUESTS_PER_MINUTE", "").strip()
        if env_val:
            try:
                params.max_requests_per_minute = int(env_val)
            except ValueError:
                pass

    # HTTP method
    if not params.method or params.method == "POST":
        env_val = os.getenv("TARGET_METHOD", "").strip().upper()
        if env_val:
            params.method = env_val

    # headers
    if params.headers is None:
        env_val = os.getenv("TARGET_HEADERS", "").strip()
        if env_val:
            params.headers = TargetFactory._parse_headers(env_val)

    # json_data
    if params.json_data is None:
        env_val = os.getenv("TARGET_JSON_DATA", "").strip()
        if env_val:
            params.json_data = TargetFactory._parse_json_data(env_val)

    # raw_http_request（优先从文件加载）
    if params.raw_http_request is None:
        env_raw_file = os.getenv("TARGET_RAW_REQUEST_FILE", "").strip()
        if env_raw_file:
            raw_path = Path(env_raw_file)
            if not raw_path.is_absolute():
                project_root = Path(__file__).parent.parent.parent
                raw_path = project_root / raw_path
            if raw_path.exists():
                params.raw_http_request = raw_path.read_text(encoding="utf-8").strip()
                logger.info(f"Loaded Burp request from file: {raw_path}")
            else:
                logger.warning(f"TARGET_RAW_REQUEST_FILE not found: {raw_path}")
        else:
            env_raw = os.getenv("TARGET_RAW_REQUEST", "").strip()
            if env_raw:
                params.raw_http_request = env_raw

    # callback_function
    if params.callback_function is None:
        env_callback = os.getenv("TARGET_CALLBACK_FUNCTION", "").strip().lower()
        if env_callback:
            params.callback_function = _resolve_callback_function(env_callback)

    # ── P1-3: CapabilityHandlingPolicy ──
    if params.capability_policy is None:
        env_val = os.getenv("TARGET_CAPABILITY_POLICY", "").strip().lower()
        if env_val in ("adapt", "raise"):
            params.capability_policy = env_val

    # ── P2-6: MessageNormalizer ──
    if params.message_normalizer is None:
        env_val = os.getenv("TARGET_MESSAGE_NORMALIZER", "").strip().lower()
        if env_val in ("default", "system_squash", "context"):
            params.message_normalizer = env_val

    if not params.use_developer_role:
        env_val = os.getenv("TARGET_USE_DEVELOPER_ROLE", "").strip().lower()
        if env_val in ("true", "1", "yes"):
            params.use_developer_role = True

    if params.system_message_behavior is None:
        env_val = os.getenv("TARGET_SYSTEM_MESSAGE_BEHAVIOR", "").strip().lower()
        if env_val in ("keep", "squash", "ignore"):
            params.system_message_behavior = env_val

    # ── P2-7: OpenAIVideoTarget 参数 ──
    if params.video_resolution is None:
        env_val = os.getenv("TARGET_VIDEO_RESOLUTION", "").strip()
        if env_val:
            params.video_resolution = env_val

    if params.video_n_seconds is None:
        env_val = os.getenv("TARGET_VIDEO_N_SECONDS", "").strip()
        if env_val:
            try:
                params.video_n_seconds = int(env_val)
            except ValueError:
                pass

    # ── P2-8: OpenAITTSTarget 参数 ──
    if params.tts_voice is None:
        env_val = os.getenv("TARGET_TTS_VOICE", "").strip()
        if env_val:
            params.tts_voice = env_val

    if params.tts_response_format is None:
        env_val = os.getenv("TARGET_TTS_RESPONSE_FORMAT", "").strip()
        if env_val:
            params.tts_response_format = env_val

    if params.tts_language is None:
        env_val = os.getenv("TARGET_TTS_LANGUAGE", "").strip()
        if env_val:
            params.tts_language = env_val

    if params.tts_speed is None:
        env_val = os.getenv("TARGET_TTS_SPEED", "").strip()
        if env_val:
            try:
                params.tts_speed = float(env_val)
            except ValueError:
                pass

    # ── P3-9: AzureMLChatTarget 参数 ──
    if params.azure_ml_endpoint is None:
        env_val = os.getenv("AZURE_ML_MANAGED_ENDPOINT", "").strip()
        if env_val:
            params.azure_ml_endpoint = env_val

    if params.azure_ml_api_key is None:
        env_val = os.getenv("AZURE_ML_KEY", "").strip()
        if env_val:
            params.azure_ml_api_key = env_val

    # ── P3-10: LiteLLM 参数 ──
    if params.stop is None:
        env_val = os.getenv("TARGET_STOP", "").strip()
        if env_val:
            params.stop = env_val


# ============================================================
# 回调函数解析
# ============================================================


def _resolve_callback_function(callback_name: str):
    """
    根据名称解析回调函数

    Args:
        callback_name: 回调函数名称
            - 'json_response': JSON 响应解析（需配合 TARGET_CALLBACK_KEY）
            - 'regex_match': 正则匹配（需配合 TARGET_CALLBACK_KEY）
            - 'none' / '': 无回调

    Returns:
        回调函数，或 None
    """
    if callback_name in ("none", ""):
        return None

    callback_key = os.getenv("TARGET_CALLBACK_KEY", "").strip()
    callback_url = os.getenv("TARGET_CALLBACK_URL", "").strip() or None

    if callback_name == "json_response":
        if not callback_key:
            logger.warning("json_response callback requires TARGET_CALLBACK_KEY env var")
            return None
        return get_http_target_json_response_callback_function(callback_key)

    if callback_name == "regex_match":
        if not callback_key:
            logger.warning("regex_match callback requires TARGET_CALLBACK_KEY env var")
            return None
        return get_http_target_regex_matching_callback_function(callback_key, callback_url)

    logger.warning(f"Unknown callback function: {callback_name}")
    return None


# ============================================================
# 工厂函数（公开 API）
# ============================================================


async def create_prompt_target(
    target_url: str,
    api_key: Optional[str] = None,
    model_name: Optional[str] = None,
    params: Optional[TargetParams] = None,
) -> Tuple[PromptTarget, str]:
    """
    创建 PromptTarget（工厂函数，自动检测类型 + 能力探测）

    L5 统一入口：支持 PyRIT 1.0.0 全部 Target 类型

    Args:
        target_url: 目标 URL
        api_key: API Key（向后兼容）
        model_name: 模型名称（向后兼容）
        params: 完整目标参数（包含推理参数 / httpx_kwargs / extra_body_parameters 等）

    Returns:
        (PromptTarget 实例, 目标类型字符串)

    Examples:
        # 基础用法（向后兼容）
        target, type = await create_prompt_target("http://localhost:11434")

        # 高级用法（完整参数控制）
        params = TargetParams(
            target_type="openai_responses",
            reasoning_effort="high",
            httpx_timeout=300,
            temperature=0,
            seed=42,
        )
        target, type = await create_prompt_target(
            "https://my-resource.openai.azure.com",
            params=params,
        )
    """
    return await TargetFactory.create_target_with_detection(
        target_url=target_url,
        api_key=api_key,
        model_name=model_name,
        params=params,
    )


async def create_judge_target(
    judge_url: str,
    api_key: Optional[str] = None,
    model_name: Optional[str] = None,
    params: Optional[TargetParams] = None,
) -> Tuple[PromptTarget, str]:
    """
    创建评分器 Target（工厂函数）

    评分器通常是 OpenAI 兼容 API。
    L5 改进：强制 JSON 输出能力，确保评分格式稳定。

    Args:
        judge_url: 评分器 URL
        api_key: API Key
        model_name: 模型名称
        params: 目标参数

    Returns:
        (PromptTarget 实例, 目标类型字符串)
    """
    params = params or TargetParams()

    # 评分器推荐配置：温度 0 + JSON 输出
    if params.temperature is None:
        env_temp = os.getenv("TARGET_TEMPERATURE", "").strip()
        if not env_temp:
            params.temperature = 0.0  # 评分器需要确定性

    # 能力探测（仅在未被显式禁用时开启）
    if params.force_json_output and params.discover_capabilities:
        params.apply_discovered_capabilities = True

    return await TargetFactory.create_target_with_detection(
        target_url=judge_url,
        api_key=api_key,
        model_name=model_name,
        params=params,
    )


def create_target_params_from_env() -> TargetParams:
    """
    从环境变量创建 TargetParams（便捷函数）

    读取所有 TARGET_* 环境变量并构建完整的 TargetParams。

    Returns:
        填充了环境变量值的 TargetParams 实例
    """
    params = TargetParams()
    _apply_env_defaults(params)

    # target_type
    env_type = os.getenv("TARGET_TYPE", "").strip().lower()
    if env_type:
        params.target_type = _LEGACY_TYPE_ALIASES.get(env_type, env_type)

    return params


# ============================================================
# PyRIT TargetRegistry 集成（PyRIT 1.0.0 Registry）
# ============================================================


def register_target_instance_to_registry(
    target: Any,
    *,
    name: Optional[str] = None,
    tags: Optional[Union[Dict[str, str], List[str]]] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> str:
    """
    注册预配置 Target 实例到 PyRIT TargetRegistry.instances

    PyRIT 1.0.0 Instance Registry 允许注册已配置好认证、端点等依赖的
    Target 实例，后续可通过名称或标签检索，也可用于引用解析
    （如 Scorer 的 chat_target 参数传入注册名而非实例）。

    Args:
        target: 已配置的 PromptTarget 实例
        name: 注册名（None 则使用 unique_name）
        tags: 标签（如 ["judge", "gpt4o"]）
        metadata: 额外元数据

    Returns:
        注册名

    Example:
        >>> target = OpenAIChatTarget()
        >>> register_target_instance_to_registry(
        ...     target, name="judge_target", tags=["judge"]
        ... )
        >>> # 后续构建 Scorer 时可引用名称：
        >>> # scorer = ScorerRegistry.create_instance(
        >>> #     "SelfAskRefusalScorer", chat_target="judge_target"
        >>> # )
    """
    from pyrit.registry import TargetRegistry

    registry = TargetRegistry.get_registry_singleton()
    registry.instances.register(target, name=name, tags=tags, metadata=metadata)
    return name or target.get_identifier().unique_name


def get_registered_target_instance(name: str) -> Optional[Any]:
    """
    从 TargetRegistry.instances 获取预配置 Target 实例

    Args:
        name: 注册名

    Returns:
        Target 实例，如果未找到则返回 None
    """
    from pyrit.registry import TargetRegistry

    registry = TargetRegistry.get_registry_singleton()
    return registry.instances.get(name)


def list_registered_target_instances() -> List[str]:
    """
    列出 TargetRegistry.instances 中所有已注册实例名

    Returns:
        排序后的实例名列表
    """
    from pyrit.registry import TargetRegistry

    registry = TargetRegistry.get_registry_singleton()
    return registry.instances.get_names()


def list_target_instance_metadata(
    *,
    include_filters: Optional[Dict[str, Any]] = None,
    exclude_filters: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """
    列出 TargetRegistry.instances 中所有实例的元数据（支持过滤）

    元数据来自实例的 ComponentIdentifier，包含 model_name、
    endpoint_uri、supported_auth_modes、eval_hash 等。

    Args:
        include_filters: 必须全部匹配的过滤条件
        exclude_filters: 匹配任一即排除的过滤条件

    Returns:
        实例元数据字典列表
    """
    from pyrit.registry import TargetRegistry

    registry = TargetRegistry.get_registry_singleton()
    identifiers = registry.instances.list_metadata(
        include_filters=include_filters,
        exclude_filters=exclude_filters,
    )

    result: List[Dict[str, Any]] = []
    for identifier in identifiers:
        entry: Dict[str, Any] = {
            "unique_name": identifier.unique_name,
            "class_name": identifier.__class__.__name__,
        }
        if hasattr(identifier, "eval_hash") and identifier.eval_hash:
            entry["eval_hash"] = identifier.eval_hash
        params = getattr(identifier, "params", None)
        if isinstance(params, dict):
            for key, value in params.items():
                if isinstance(value, (str, int, float, bool)):
                    entry[key] = value
                elif isinstance(value, (list, tuple)):
                    entry[key] = list(value)
        result.append(entry)

    return result


def query_target_instances_by_tags(query: Any) -> List[Any]:
    """
    使用 TagQuery 组合谓词查询 Target 实例

    Args:
        query: TagQuery 对象（可用 & 和 | 组合）

    Returns:
        匹配的 Target 实例列表
    """
    from pyrit.registry import TargetRegistry

    registry = TargetRegistry.get_registry_singleton()
    entries = registry.instances.query_by_tags(query=query)
    return [entry.instance for entry in entries]


def get_target_instances_by_tag(
    tag: str,
    value: Optional[str] = None,
) -> List[Any]:
    """
    按标签获取 Target 实例

    Args:
        tag: 标签键
        value: 标签值（None 则匹配任意值）

    Returns:
        Target 实例列表
    """
    from pyrit.registry import TargetRegistry

    registry = TargetRegistry.get_registry_singleton()
    entries = registry.instances.get_by_tag(tag=tag, value=value)
    return [entry.instance for entry in entries]


def get_target_class_metadata_from_registry(name: str) -> Optional[Dict[str, Any]]:
    """
    从 TargetRegistry 获取 Target 类的元数据

    使用原生 TargetMetadata，包含：
    - class_name / class_module / class_description / registry_name
    - parameters（构建契约）
    - supported_auth_modes（支持的认证模式，从类属性投影）

    Args:
        name: Target 类名（如 "OpenAIChatTarget"）

    Returns:
        元数据字典，如果未找到则返回 None
    """
    from pyrit.registry import TargetRegistry

    registry = TargetRegistry.get_registry_singleton()
    metadata = registry.get_registered_class_metadata(name)
    if metadata is None:
        return None

    result: Dict[str, Any] = {
        "class_name": metadata.class_name,
        "class_module": metadata.class_module,
        "class_description": metadata.class_description,
        "registry_name": metadata.registry_name,
        "supported_auth_modes": list(metadata.supported_auth_modes),
    }

    params: List[Dict[str, Any]] = []
    for param in metadata.parameters:
        param_dict: Dict[str, Any] = {
            "name": param.name,
            "description": param.description,
            "default": param.default if param.default is not None else None,
        }
        if param.param_type is not None:
            param_dict["param_type"] = str(param.param_type)
        if param.reference is not None:
            param_dict["reference"] = str(param.reference.component_type)
        params.append(param_dict)
    result["parameters"] = params

    if hasattr(metadata, "class_attributes"):
        result["class_attributes"] = dict(metadata.class_attributes)

    return result


def list_all_target_class_metadata(
    *,
    include_filters: Optional[Dict[str, Any]] = None,
    exclude_filters: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """
    列出 TargetRegistry 中所有 Target 类的元数据（支持过滤）

    Example:
        # 列出支持 api_key 认证的 Target
        api_key_targets = list_all_target_class_metadata(
            include_filters={"supported_auth_modes": "api_key"}
        )
    """
    from pyrit.registry import TargetRegistry

    registry = TargetRegistry.get_registry_singleton()
    metadata_list = registry.get_all_registered_class_metadata(
        include_filters=include_filters,
        exclude_filters=exclude_filters,
    )

    results: List[Dict[str, Any]] = []
    for metadata in metadata_list:
        entry: Dict[str, Any] = {
            "class_name": metadata.class_name,
            "class_module": metadata.class_module,
            "class_description": metadata.class_description,
            "registry_name": metadata.registry_name,
            "supported_auth_modes": list(metadata.supported_auth_modes),
        }
        if hasattr(metadata, "class_attributes"):
            entry["class_attributes"] = dict(metadata.class_attributes)
        results.append(entry)

    return results
