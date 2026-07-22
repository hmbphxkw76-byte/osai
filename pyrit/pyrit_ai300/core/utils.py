# -*- coding: utf-8 -*-
"""
AI-300 Framework - Core Utilities
共享工具函数：无业务依赖的纯函数

设计原则：
- 仅依赖 Python 标准库
- 不导入任何业务模块（reconnaissance/pipeline/orchestrators）
- 所有函数为纯函数或 staticmethod，无副作用
"""

from __future__ import annotations

import sys
import os
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    os.environ["PYTHONIOENCODING"] = "utf-8"


# ── 已知 LLM 服务端口 ──
KNOWN_LLM_PORTS = frozenset({11434, 8080, 3000, 5000, 7860, 8000, 1234, 2333, 9997})

# ── API 路径模式 ──
API_PATH_PATTERNS = frozenset({
    "/v1/chat/completions", "/v1/completions", "/v1/models",
    "/v1/embeddings", "/v1/generate",
    "/api/generate", "/api/chat", "/api/tags", "/api/show",
    "/api/embeddings", "/api/pull", "/api/push",
    "/chat/completions", "/completions",
})

# ── Web 应用路径 ──
WEB_APP_PATHS = frozenset({
    "/chat", "/home", "/dashboard", "/app", "/portal",
    "/assistant", "/playground", "/chatbot", "/ai",
    "/copilot", "/chat-room", "/conversation",
})


def detect_target_type(
    target_url: str,
    spa_config: Optional[str],
) -> str:
    """
    自动检测目标类型（Web/SPA 应用 vs API 端点）

    检测策略（优先级递减）：
    1. 显式 spa_config → "spa"
    2. 明确的 API 端点特征 → "api"
    3. 明确的 Web 应用特征 → "spa"
    4. 默认 → "spa"（绝大多数互联网 AI 应用是 Web 应用）

    API 端点特征：
    - 路径含 /v1/、/api/、/chat/completions 等 API 路由
    - localhost / 127.0.0.1 / 0.0.0.0（本地部署 LLM 服务）
    - 已知 LLM 服务端口（11434/8080/3000/5000/7860 等）
    - api. 子域名
    - 路径以 /v1/chat/completions 等结尾

    Web 应用特征：
    - Hash 路由（/#/、#/）
    - 常见 Web 应用路径（/chat、/home、/dashboard、/assistant 等）
    - 公网域名 + 非 API 路径

    Args:
        target_url: 目标 URL
        spa_config: SPA 配置文件路径（可选）

    Returns:
        "spa" 或 "api"
    """
    # 1. 显式 SPA 配置
    if spa_config:
        return "spa"

    if not target_url:
        return "api"

    url_lower = target_url.lower()
    parsed = urlparse(target_url)
    hostname = (parsed.hostname or "").lower()
    path = (parsed.path or "").lower().rstrip("/")
    port = parsed.port

    # ── 2. 明确的 API 端点特征 → "api" ──

    # 2a. API 路径模式
    if any(p in path for p in API_PATH_PATTERNS):
        return "api"

    # 2b. localhost / 内网 IP（本地部署的 LLM 服务）
    if hostname in ("localhost", "127.0.0.1", "0.0.0.0"):
        return "api"

    # 2c. 已知 LLM 服务端口
    if port and port in KNOWN_LLM_PORTS:
        return "api"

    # 2d. api. 子域名
    if hostname.startswith("api."):
        return "api"

    # 2e. URL 明确包含 API 路径前缀
    if path.startswith("/v1/") or path.startswith("/api/"):
        return "api"

    # ── 3. 明确的 Web 应用特征 → "spa" ──

    # 3a. Hash 路由（Vue/React/Angular SPA）
    if "/#" in url_lower or "#/" in url_lower:
        return "spa"

    # 3b. 常见 Web 应用路径
    if path in WEB_APP_PATHS:
        return "spa"

    # 3c. 公网域名 + 根路径或非 API 路径 → 默认 Web 应用
    # （ChatGPT/Claude/Gemini/通义/文心/Kimi 等都是 Web 应用）
    if hostname and not hostname.startswith("api."):
        # 有域名但无 API 特征 → Web 应用
        return "spa"

    # 4. 兜底
    return "spa"


def extract_spa_llm_endpoint(profile: Any) -> Optional[str]:
    """
    从 SPA 侦察画像中提取 LLM API 端点 URL

    查找顺序：
    1. profile.entry_points[0].url
    2. profile.fingerprint.endpoint
    3. profile.raw_data 中的 entry_points

    Args:
        profile: TargetProfile 实例

    Returns:
        LLM API 端点 URL 或 None
    """
    # 1. 从 entry_points 提取
    if hasattr(profile, 'entry_points') and profile.entry_points:
        for ep in profile.entry_points:
            url = ep.get("url", "") if isinstance(ep, dict) else ""
            if url and url.startswith("http"):
                return url

    # 2. 从 fingerprint 提取
    if hasattr(profile, 'fingerprint') and profile.fingerprint:
        fp = profile.fingerprint
        if hasattr(fp, 'endpoint') and fp.endpoint:
            return fp.endpoint

    # 3. 从 raw_data / extra 提取
    if hasattr(profile, 'raw_data') and profile.raw_data:
        entry_points = profile.raw_data.get("entry_points", [])
        for ep in entry_points:
            url = ep.get("url", "") if isinstance(ep, dict) else ""
            if url and url.startswith("http"):
                return url

    return None


def extract_spa_model_name(profile: Any) -> Optional[str]:
    """
    从 SPA 侦察画像中提取模型名称

    查找顺序：
    1. profile.fingerprint.model_name
    2. profile.raw_data 中的 model_name

    Args:
        profile: TargetProfile 实例

    Returns:
        模型名称或 None
    """
    # 1. 从 fingerprint 提取
    if hasattr(profile, 'fingerprint') and profile.fingerprint:
        fp = profile.fingerprint
        if hasattr(fp, 'model_name') and fp.model_name:
            return fp.model_name

    # 2. 从 raw_data 提取
    if hasattr(profile, 'raw_data') and profile.raw_data:
        model = (
            profile.raw_data.get("model_name")
            or profile.raw_data.get("model_name_from_traffic")
            or profile.raw_data.get("model_name_from_probe")
        )
        if model:
            return model

    return None


def build_aimap_data_from_spa_profile(profile: Any) -> Dict[str, Any]:
    """
    从 SPA 侦察画像构建等价 aimap_data

    SPA Recon 已被动发现协议/能力/攻击面等信息，
    将其转换为 NativeProbe/DeepTeam 适配器期望的 aimap_data 格式，
    驱动动态 probe 选择和 Agentic 漏洞触发。

    Args:
        profile: SPA 侦察产出的 TargetProfile

    Returns:
        aimap_data 字典，包含 detected_protocols / surfaces / capabilities / model_family
    """
    aimap_data: Dict[str, Any] = {
        "detected_protocols": [],
        "surfaces": [],
        "capabilities": [],
        "model_family": "",
    }

    if not profile:
        aimap_data["surfaces"] = ["prompt"]
        return aimap_data

    # 提取 surfaces
    if hasattr(profile, 'surfaces') and profile.surfaces:
        aimap_data["surfaces"] = list(profile.surfaces)

    # 提取 fingerprint 信息
    if hasattr(profile, 'fingerprint') and profile.fingerprint:
        fp = profile.fingerprint
        if hasattr(fp, 'capabilities') and fp.capabilities:
            aimap_data["capabilities"] = list(fp.capabilities)
        if hasattr(fp, 'model_family') and fp.model_family:
            aimap_data["model_family"] = fp.model_family

    # 从 raw_results 提取更多协议信息（SPA traffic_capture 可能发现）
    if hasattr(profile, 'raw_results') and profile.raw_results:
        spa_raw = profile.raw_results.get("spa_chat_recon", {})
        if isinstance(spa_raw, dict):
            data = spa_raw.get("data", {})
            if isinstance(data, dict):
                # SPA 可能检测到的协议
                detected = data.get("detected_protocols", [])
                if detected:
                    aimap_data["detected_protocols"] = detected
                # SPA 可能发现 mcp/agent 等攻击面
                extra_surfaces = data.get("surfaces", [])
                for s in extra_surfaces:
                    if s not in aimap_data["surfaces"]:
                        aimap_data["surfaces"].append(s)

    # 确保 prompt 攻击面存在（SPA 聊天应用必定有 prompt 攻击面）
    if "prompt" not in aimap_data["surfaces"]:
        aimap_data["surfaces"].insert(0, "prompt")

    return aimap_data


def inject_credentials_to_recon(
    resolution: Any,
) -> Dict[str, Dict[str, Any]]:
    """
    将凭据注入到侦察工具配置中

    为 NativeProbe 和 DeepTeam 适配器生成凭据配置参数。

    Args:
        resolution: CredentialResolution 实例

    Returns:
        工具名 → 凭据配置参数的字典
    """
    if not resolution or not resolution.has_credentials:
        return {}

    config: Dict[str, Dict[str, Any]] = {}

    # NativeProbe 凭据注入（Bearer Token / Cookie）
    probe_auth = _extract_native_probe_auth(resolution)
    if probe_auth:
        bearer = probe_auth.get("bearer_token", "")
        cookie = probe_auth.get("cookie", "")
        config["native_probe"] = {
            "credential_bearer": bearer,
            "credential_headers": {
                "Authorization": f"Bearer {bearer}" if bearer else "",
                **({"Cookie": cookie} if cookie else {}),
            },
        }

    # DeepTeam 凭据注入（请求头方式）
    deepteam_headers = _extract_deepteam_headers(resolution)
    if deepteam_headers:
        config["deepteam"] = {
            "credential_headers": deepteam_headers,
            "credential_bearer": "",
        }

    return config


def _extract_native_probe_auth(resolution: Any) -> Dict[str, str]:
    """提取 NativeProbe 适配器所需的认证信息"""
    env: Dict[str, str] = {}
    if not resolution or not resolution.has_credentials or not resolution.profile:
        return env

    profile = resolution.profile

    # 提取 Bearer Token
    auth_header = profile.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header[7:].strip()
        if token:
            env["bearer_token"] = token

    # Cookie 也可以传递
    if profile.raw_cookies:
        env["cookie"] = profile.raw_cookies

    return env


def _extract_deepteam_headers(resolution: Any) -> Dict[str, str]:
    """提取 DeepTeam 适配器所需的请求头"""
    headers: Dict[str, str] = {"Content-Type": "application/json"}
    if not resolution or not resolution.has_credentials or not resolution.profile:
        return headers

    profile = resolution.profile

    # 注入 Authorization 头
    auth_header = profile.headers.get("Authorization", "")
    if auth_header:
        headers["Authorization"] = auth_header

    # 注入 Cookie 头
    if profile.raw_cookies:
        headers["Cookie"] = profile.raw_cookies

    # 注入其他自定义头（User-Agent 等）
    for key, value in profile.headers.items():
        if key not in ("Authorization",) and key not in headers:
            headers[key] = value

    return headers


def inject_credentials_to_attack(
    resolution: Any,
    engine: Any,
) -> None:
    """
    将凭据注入到攻击阶段的目标配置中

    最佳实践：
    - Bearer Token → OpenAIChatTarget 的 api_key 参数
    - Cookie → HTTPTarget 的 Authorization 头
    - AuthProfile → PlaywrightTarget 的 inject_auth()

    Args:
        resolution: 凭据解析结果
        engine: AI300Engine 实例
    """
    if not resolution or not resolution.has_credentials:
        return

    profile = resolution.profile

    # 获取 OpenAI Target 格式的凭据
    oai_api_key = _extract_openai_api_key(resolution)
    if oai_api_key:
        engine._credential_api_key = oai_api_key

    # HTTP Target 格式
    http_auth = _extract_http_auth(resolution)
    if http_auth:
        engine._credential_http_auth = http_auth


def _extract_openai_api_key(resolution: Any) -> str:
    """从凭据中提取 OpenAI api_key"""
    if not resolution or not resolution.has_credentials or not resolution.profile:
        return ""

    profile = resolution.profile
    auth_header = profile.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header[7:].strip()
        if token:
            return token

    return ""


def _extract_http_auth(resolution: Any) -> Optional[str]:
    """从凭据中提取 HTTP Authorization 头值"""
    if not resolution or not resolution.has_credentials or not resolution.profile:
        return None

    return resolution.profile.headers.get("Authorization", "") or None
