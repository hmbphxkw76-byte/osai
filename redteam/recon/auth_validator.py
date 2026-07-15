"""认证验证工具 — 在发送提示词前先验证认证是否有效。

AI-300 考试场景：
  - 认证失败导致提示词发送失败，浪费时间
  - 需要快速诊断认证问题并给出修复建议
  - 支持多种认证方式（API Key、Cookie、Bearer Token、Basic Auth）

验证流程：
  1. 发送无认证请求检测目标是否需要认证
  2. 如果不需要认证 → 直接返回成功，跳过验证
  3. 如果需要认证但用户没提供 → 返回需要认证的提示
  4. 如果需要认证且用户提供了 → 验证认证是否有效
  5. 根据状态码和响应内容判断认证问题类型
  6. 给出具体的错误提示和修复建议
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
from urllib.parse import urlparse

from redteam.core.http_client import send_get, send_post
from redteam.core.models import AuthContext


class TargetType(str, Enum):
    """目标类型分类 — 区分不同 AI 服务形态。"""
    OLLAMA = "ollama"                    # Ollama 模型服务器 (11434)
    OPENAI_COMPATIBLE = "openai"         # OpenAI 兼容 API
    MODEL_PLATFORM = "model_platform"    # 模型服务平台（智谱、百度等）
    AI_CHAT_WEBSITE = "ai_website"       # AI 聊天网站（qwen.com 等）
    WEB_APP = "web_app"                  # 通用 Web 应用（含 AI 功能）
    UNKNOWN = "unknown"                  # 无法识别


# 已知 AI 平台域名特征
_KNOWN_PLATFORMS: dict[str, dict[str, str]] = {
    "openai.com":        {"name": "OpenAI",           "api_path": "/v1/chat/completions"},
    "deepseek.com":      {"name": "DeepSeek",         "api_path": "/v1/chat/completions"},
    "zhipuai.cn":        {"name": "智谱 AI (GLM)",    "api_path": "/api/paas/v4/chat/completions"},
    "bigmodel.cn":       {"name": "智谱 BigModel",    "api_path": "/api/paas/v4/chat/completions"},
    "qwen.com":          {"name": "通义千问",          "api_path": "/v1/chat/completions"},
    "qianwen.aliyun.com": {"name": "阿里云通义千问",   "api_path": "/v1/chat/completions"},
    "dashscope.aliyuncs.com": {"name": "阿里云 DashScope", "api_path": "/compatible-mode/v1/chat/completions"},
    "baidu.com":         {"name": "百度文心",          "api_path": "/rpc/2.0/ai_custom/v1/wenxinworkshop/chat"},
    "baidubce.com":      {"name": "百度智能云",        "api_path": "/rpc/2.0/ai_custom/v1/wenxinworkshop/chat"},
    "moonshot.cn":       {"name": "月之暗面 (Kimi)",   "api_path": "/v1/chat/completions"},
    "x.ai":              {"name": "xAI (Grok)",       "api_path": "/v1/chat/completions"},
    "anthropic.com":     {"name": "Anthropic",        "api_path": "/v1/messages"},
    "cohere.com":        {"name": "Cohere",           "api_path": "/v1/chat"},
    "huggingface.co":    {"name": "HuggingFace",      "api_path": "/v1/chat/completions"},
    "aiyunos.com":       {"name": "AI 云服务",         "api_path": "/v1/chat/completions"},
}


@dataclass
class ProbeDetail:
    """单次探测详情。"""
    url: str
    method: str  # GET / POST
    status: int
    success: bool
    content_type: str = ""
    body_preview: str = ""
    note: str = ""


@dataclass
class ConnectivityResult:
    """连通性探测完整结果。"""
    connected: bool
    probe_url: str
    status_code: int
    error_msg: str
    endpoint_type: str  # "get", "post", "web", "unknown"
    target_type: TargetType = TargetType.UNKNOWN
    probes: list[ProbeDetail] = field(default_factory=list)
    platform_name: str = ""
    exposed_models: list[str] = field(default_factory=list)
    ollama_version: str = ""


@dataclass
class AuthValidationResult:
    """认证验证结果。"""
    success: bool
    requires_auth: bool
    status_code: int
    error_type: str
    message: str
    suggestion: str
    connectivity: ConnectivityResult | None = None


_AUTH_ERROR_PATTERNS = {
    "invalid_token": [
        "invalid token",
        "token expired",
        "token invalid",
        "expired token",
        "authentication failed",
        "invalid signature",
        "signature invalid",
    ],
    "missing_auth": [
        "missing authentication",
        "no auth",
        "no authentication",
        "authorization required",
        "authentication required",
    ],
    "rate_limit": [
        "rate limit",
        "too many requests",
        "rate limited",
    ],
    "invalid_key": [
        "invalid api key",
        "api key invalid",
        "invalid key",
        "key invalid",
    ],
}


def _detect_error_type(status_code: int, response: str) -> tuple[str, str]:
    """根据状态码和响应内容检测错误类型。"""
    response_lower = response.lower()
    
    if status_code == 401:
        for err_type, patterns in _AUTH_ERROR_PATTERNS.items():
            for pattern in patterns:
                if pattern in response_lower:
                    return err_type, pattern
        return "unauthorized", "认证失败"
    
    if status_code == 403:
        return "forbidden", "访问被拒绝"
    
    if status_code == 429:
        return "rate_limit", "请求频率过高"
    
    if status_code == 404:
        return "not_found", "目标不存在"
    
    if status_code == 405:
        return "method_not_allowed", "请求方法不允许"
    
    if status_code == 500:
        return "server_error", "服务器内部错误"
    
    if status_code == 503:
        return "service_unavailable", "服务不可用"
    
    return "unknown", "未知错误"


_AI_PROBE_GET_PATHS = [
    "/v1/models",
    "/api/tags",
    "/api/version",
    "/api/status",
    "/models",
]

_AI_PROBE_POST_PATHS = [
    "/v1/chat/completions",
    "/api/chat",
    "/api/embeddings",
    "/v1/embeddings",
    "/v1/messages",
    "/chat/completions",
]


def _try_get_json_models(body: str) -> list[str]:
    """尝试从 JSON 响应体中提取模型名称。"""
    try:
        data = json.loads(body)
        # Ollama /api/tags 格式
        if isinstance(data, dict) and "models" in data:
            return [m.get("name", m.get("model", str(m))) for m in data["models"] if isinstance(m, dict)]
        # OpenAI /v1/models 格式
        if isinstance(data, dict) and "data" in data:
            items = data["data"]
            if isinstance(items, list):
                return [m.get("id", str(m)) for m in items if isinstance(m, dict)]
        return []
    except (json.JSONDecodeError, TypeError):
        return []


def _classify_target(
    target_url: str,
    host_reachable: bool,
    probes: list[ProbeDetail],
) -> TargetType:
    """根据域名和探测结果对目标类型分类。

    分类优先级：
    1. 域名/端口特征 → 模型服务器
    2. 域名匹配已知平台 → 模型服务平台
    3. 域名匹配已知 AI 网站 → AI 聊天网站
    4. 探测到标准 API → OpenAI 兼容
    5. HTML 网页 → Web 应用/AI 聊天网站
    6. 其他 → 未知
    """
    parsed = urlparse(target_url)
    host = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    host_lower = host.lower()

    # 1. 端口特征：Ollama 默认端口 11434
    if port == 11434:
        return TargetType.OLLAMA

    # 2. 域名匹配已知平台
    for domain, info in _KNOWN_PLATFORMS.items():
        if domain in host_lower:
            return TargetType.MODEL_PLATFORM

    # 3. 域名匹配 AI 聊天网站特征
    ai_web_domains = ["qwen.com", "tongyi.aliyun.com", "chat.baidu.com", "yiyan.baidu.com",
                      "kimi.moonshot.cn", "doubao.com", "xinghuo.xfyun.cn"]
    for d in ai_web_domains:
        if d in host_lower:
            return TargetType.AI_CHAT_WEBSITE

    # 4. 探测到标准 AI API
    for p in probes:
        if p.success and p.status in (200, 401, 403):
            if any(path in p.url for path in ("/v1/chat/completions", "/api/chat", "/v1/models", "/api/tags")):
                return TargetType.OPENAI_COMPATIBLE

    # 5. HTML 网页
    for p in probes:
        if "text/html" in p.content_type.lower():
            return TargetType.AI_CHAT_WEBSITE

    # 6. 内网 IP → 可能是模型服务器
    if _is_private_ip(host):
        return TargetType.OLLAMA

    return TargetType.UNKNOWN


def _tcp_reachable(target_url: str, timeout: float = 3.0) -> bool:
    """TCP 级别可达性预检查。

    在发送 HTTP 请求前先检查主机是否可达，快速区分网络问题和应用层问题。
    支持 IPv4 和 IPv6。
    """
    import socket

    parsed = urlparse(target_url)
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    if not host:
        return False

    try:
        for addr_info in socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM):
            family, socktype, proto, _, sockaddr = addr_info
            try:
                s = socket.socket(family, socktype, proto)
                s.settimeout(timeout)
                s.connect(sockaddr)
                s.close()
                return True
            except Exception:
                continue
        return False
    except Exception:
        return False


def _probe_connectivity(target_url: str) -> ConnectivityResult:
    """多路径连通性探测 — AI 红队专家视角。

    针对 4 类目标执行差异化探测：

    1. Ollama 模型服务器 (http://192.168.0.25:11434)
       → GET /api/tags 枚举模型列表
       → GET /api/version 获取版本

    2. OpenAI 兼容 API (https://api.openai.com/v1)
       → GET /v1/models 枚举模型
       → POST /v1/chat/completions 验证可用性

    3. AI 聊天网站 (https://www.qwen.com/)
       → GET / 确认网页可达
       → 探测常见 API 路径（通常 404）
       → 标记为"需 JS 分析发现隐藏端点"

    4. 模型服务平台 (https://open.bigmodel.cn/)
       → 探测已知 API 路径
       → 识别平台品牌

    Returns:
        ConnectivityResult 包含探测详情和目标类型
    """
    probes: list[ProbeDetail] = []

    if not _tcp_reachable(target_url):
        return ConnectivityResult(
            connected=False, probe_url=target_url, status_code=0,
            error_msg="主机不可达（TCP 连接失败）", endpoint_type="unknown",
            target_type=TargetType.UNKNOWN, probes=probes,
        )

    parsed = urlparse(target_url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"
    path = parsed.path.rstrip("/")

    # ━━━ 1. GET 探测器 ━━━
    probe_urls_get: list[str] = []
    # 首先探测用户原始 URL
    probe_urls_get.append(target_url)
    # 然后探测标准 AI API 只读端点
    for probe_path in _AI_PROBE_GET_PATHS:
        full_path = path + probe_path if path else probe_path
        probe_urls_get.append(f"{base_url}{full_path}")
    probe_urls_get = list(dict.fromkeys(probe_urls_get))  # 去重

    exposed_models: list[str] = []
    ollama_version = ""
    best_get_url = ""
    best_get_status = 0

    for url in probe_urls_get:
        try:
            result = send_get(url, auth=None, timeout=6.0, verify_ssl=False, stealth=True)
        except Exception:
            probes.append(ProbeDetail(url=url, method="GET", status=0,
                                       success=False, note="请求异常"))
            continue

        if result is None:
            probes.append(ProbeDetail(url=url, method="GET", status=0,
                                       success=False, note="无响应"))
            continue

        status = result.get("status", 0)
        body = result.get("body", "")
        headers = result.get("headers", {})
        content_type = headers.get("content-type", headers.get("Content-Type", ""))

        note = ""
        if 200 <= status < 300:
            if "text/html" in content_type.lower():
                body_preview = body[:100].replace("\n", " ").strip()
                note = f"HTML 网页 — {body_preview}" if body_preview else "HTML 网页"
            elif "application/json" in content_type.lower():
                models = _try_get_json_models(body)
                if models:
                    exposed_models.extend(models)
                    note = f"JSON API — 发现 {len(models)} 个模型"
                else:
                    body_preview = body[:120].replace("\n", " ")
                    note = f"JSON API — {body_preview}" if body_preview else "JSON API"
                # 尝试提取 Ollama 版本
                if "/api/version" in url:
                    try:
                        ver_data = json.loads(body)
                        ollama_version = ver_data.get("version", "")
                    except (json.JSONDecodeError, TypeError):
                        pass
            else:
                note = f"HTTP {status}"
            best_get_url = url
            best_get_status = status
        elif status in (401, 403):
            note = "需要认证"
            best_get_url = url
            best_get_status = status
        elif status in (404, 405):
            note = f"HTTP {status}（不存在）"
        elif status == 429:
            note = "速率限制"
        elif status >= 500:
            note = f"HTTP {status}（服务器错误）"
        else:
            note = f"HTTP {status}"

        probes.append(ProbeDetail(
            url=url, method="GET", status=status,
            success=(200 <= status < 300),
            content_type=content_type, note=note,
        ))

    # ━━━ 2. POST 探测器 ━━━
    probe_urls_post: list[str] = []
    for probe_path in _AI_PROBE_POST_PATHS:
        full_path = path + probe_path if path else probe_path
        probe_urls_post.append(f"{base_url}{full_path}")
    probe_urls_post = list(dict.fromkeys(probe_urls_post))

    best_post_url = ""
    best_post_status = 0

    for url in probe_urls_post:
        try:
            result = send_post(
                url,
                data={"messages": [{"role": "user", "content": "Hello"}]},
                auth=None, timeout=6.0, verify_ssl=False, stealth=True,
            )
        except Exception:
            probes.append(ProbeDetail(url=url, method="POST", status=0,
                                       success=False, note="请求异常"))
            continue

        if result is None:
            probes.append(ProbeDetail(url=url, method="POST", status=0,
                                       success=False, note="无响应"))
            continue

        status = result.get("status", 0)
        body = result.get("body", "")
        headers = result.get("headers", {})
        content_type = headers.get("content-type", headers.get("Content-Type", ""))

        note = ""
        if 200 <= status < 300:
            if "application/json" in content_type.lower():
                note = "可用 — 接受聊天请求"
            else:
                note = f"HTTP {status}"
            best_post_url = url
            best_post_status = status
        elif status in (401, 403):
            note = "需要认证"
            best_post_url = url
            best_post_status = status
        elif status in (400, 422):
            # 400/422 也可能表示端点存在但请求格式不对
            note = f"HTTP {status}（端点存在，可能需要特定格式）"
        elif status in (404, 405):
            note = f"HTTP {status}（不存在）"
        elif status == 429:
            note = "速率限制"
        else:
            note = f"HTTP {status}"

        probes.append(ProbeDetail(
            url=url, method="POST", status=status,
            success=(200 <= status < 300),
            content_type=content_type, note=note,
        ))

    # ━━━ 3. 目标分类 ━━━
    any_reachable = any(p.status > 0 for p in probes)
    target_type = _classify_target(target_url, any_reachable, probes)

    # ━━━ 4. 平台名称（已知平台） ━━━
    platform_name = ""
    host_lower = (urlparse(target_url).hostname or "").lower()
    for domain, info in _KNOWN_PLATFORMS.items():
        if domain in host_lower:
            platform_name = info["name"]
            break

    # ━━━ 5. 确定最终状态 ━━━
    if best_get_url and best_get_status in (200, 401, 403):
        msg = "成功" if best_get_status == 200 else "需要认证"
        return ConnectivityResult(
            connected=True, probe_url=best_get_url, status_code=best_get_status,
            error_msg=msg, endpoint_type="get",
            target_type=target_type, probes=probes,
            platform_name=platform_name,
            exposed_models=list(dict.fromkeys(exposed_models)),
            ollama_version=ollama_version,
        )

    if best_post_url and best_post_status in (200, 401, 403):
        msg = "成功" if best_post_status == 200 else "需要认证"
        return ConnectivityResult(
            connected=True, probe_url=best_post_url, status_code=best_post_status,
            error_msg=msg, endpoint_type="post",
            target_type=target_type, probes=probes,
            platform_name=platform_name,
            exposed_models=list(dict.fromkeys(exposed_models)),
            ollama_version=ollama_version,
        )

    if any_reachable:
        return ConnectivityResult(
            connected=False, probe_url=target_url, status_code=0,
            error_msg="主机可达，但未发现标准 AI API 端点",
            endpoint_type="web",
            target_type=target_type, probes=probes,
            platform_name=platform_name,
            exposed_models=list(dict.fromkeys(exposed_models)),
        )

    return ConnectivityResult(
        connected=False, probe_url=target_url, status_code=0,
        error_msg="所有路径均无法连接", endpoint_type="unknown",
        target_type=TargetType.UNKNOWN, probes=probes,
    )


def validate_auth(target_url: str, auth: AuthContext | None) -> AuthValidationResult:
    """验证认证信息是否有效。

    先发送无认证请求检测目标是否需要认证：
    - 返回200 → 不需要认证，直接成功
    - 返回401/403 → 需要认证，验证用户提供的认证信息

    连通性测试策略：
    - Ollama: 探测 /api/tags, /api/embeddings, /v1/*
    - OpenAI兼容: 探测 /v1/chat/completions, /v1/models
    - 开放API平台: 探测标准路径
    - 自定义路径: 保留用户提供的路径
    - 网页目标: 主机可达但无标准API，允许继续侦察

    Args:
        target_url: 目标 URL
        auth: 认证上下文（可选）

    Returns:
        AuthValidationResult，包含验证结果和错误建议
    """
    try:
        conn = _probe_connectivity(target_url)

        if not conn.connected:
            if conn.target_type in (TargetType.AI_CHAT_WEBSITE, TargetType.WEB_APP):
                return AuthValidationResult(
                    success=True, requires_auth=False, status_code=0,
                    error_type="web_target",
                    message=f"目标可达（{conn.platform_name or conn.target_type.value}），未暴露标准 AI API，将继续侦察发现端点",
                    suggestion="", connectivity=conn,
                )

            return AuthValidationResult(
                success=False, requires_auth=False, status_code=0,
                error_type="connection_error",
                message=f"无法连接到目标: {conn.error_msg}",
                suggestion=_get_connection_suggestion(target_url),
                connectivity=conn,
            )

        # 端点可达
        if conn.endpoint_type == "get":
            if 200 <= conn.status_code < 300:
                return AuthValidationResult(
                    success=True, requires_auth=False,
                    status_code=conn.status_code, error_type="",
                    message=f"AI API 端点可达: {conn.probe_url}",
                    suggestion="", connectivity=conn,
                )
            elif conn.status_code in (401, 403):
                if not auth:
                    return AuthValidationResult(
                        success=False, requires_auth=True,
                        status_code=conn.status_code, error_type="requires_auth",
                        message="目标需要认证，但未提供认证信息",
                        suggestion="请提供 --api-key 或 --header-file 参数\n\n"
                                  "获取认证信息方法：\n"
                                  "  1. 打开浏览器 F12 → 网络(Network) → 找到 AI 相关请求\n"
                                  "  2. 右键复制请求头(Copy headers)\n"
                                  "  3. 保存到文件: headers.txt\n"
                                  "  4. 使用命令: redteam quicktest --target https://xxx --header-file headers.txt",
                        connectivity=conn,
                    )

                auth_result = send_post(
                    conn.probe_url,
                    data={"messages": [{"role": "user", "content": "Hello"}]},
                    auth=auth, timeout=5.0, verify_ssl=False, stealth=True,
                )

                if auth_result is None:
                    return AuthValidationResult(
                        success=False, requires_auth=True, status_code=0,
                        error_type="connection_error",
                        message="带认证信息连接目标失败",
                        suggestion="请检查网络连接和目标 URL",
                        connectivity=conn,
                    )

                auth_status_code = auth_result.get("status", 0)

                if 200 <= auth_status_code < 300:
                    return AuthValidationResult(
                        success=True, requires_auth=True,
                        status_code=auth_status_code, error_type="",
                        message="认证成功", suggestion="",
                        connectivity=conn,
                    )

                return AuthValidationResult(
                    success=False, requires_auth=True,
                    status_code=auth_status_code, error_type="auth_failed",
                    message=f"认证失败 (HTTP {auth_status_code})",
                    suggestion=_get_suggestion("unauthorized", auth),
                    connectivity=conn,
                )

        # POST 端点类型 — 执行标准认证流程
        no_auth_result = send_post(
            conn.probe_url,
            data={"messages": [{"role": "user", "content": "Hello"}]},
            auth=None, timeout=5.0, verify_ssl=False, stealth=True,
        )

        if no_auth_result is None:
            return AuthValidationResult(
                success=False, requires_auth=False, status_code=0,
                error_type="connection_error",
                message="无法连接到目标",
                suggestion=_get_connection_suggestion(target_url),
                connectivity=conn,
            )

        status_code = no_auth_result.get("status", 0)

        if 200 <= status_code < 300:
            return AuthValidationResult(
                success=True, requires_auth=False, status_code=status_code,
                error_type="",
                message="目标不需要认证，可直接发送提示词",
                suggestion="", connectivity=conn,
            )

        if status_code not in (401, 403):
            error_type, error_msg = _detect_error_type(status_code, no_auth_result.get("body", ""))

            if error_type in ["method_not_allowed", "not_found", "server_error", "service_unavailable", "unknown"]:
                return AuthValidationResult(
                    success=True, requires_auth=False, status_code=status_code,
                    error_type=error_type,
                    message=f"目标返回 {error_msg} (HTTP {status_code})，但非认证错误，允许继续执行",
                    suggestion=_get_suggestion(error_type, auth),
                    connectivity=conn,
                )

            return AuthValidationResult(
                success=False, requires_auth=False, status_code=status_code,
                error_type=error_type,
                message=f"{error_msg} (HTTP {status_code})",
                suggestion=_get_suggestion(error_type, auth),
                connectivity=conn,
            )

        if not auth:
            return AuthValidationResult(
                success=False, requires_auth=True, status_code=status_code,
                error_type="requires_auth",
                message="目标需要认证，但未提供认证信息",
                suggestion="请提供 --api-key 或 --header-file 参数\n\n"
                          "获取认证信息方法：\n"
                          "  1. 打开浏览器 F12 → 网络(Network) → 找到 AI 相关请求\n"
                          "  2. 右键复制请求头(Copy headers)\n"
                          "  3. 保存到文件: headers.txt\n"
                          "  4. 使用命令: redteam quicktest --target https://xxx --header-file headers.txt",
                connectivity=conn,
            )

        auth_result = send_post(
            target_url,
            data={"messages": [{"role": "user", "content": "Hello"}]},
            auth=auth, timeout=5.0, verify_ssl=False, stealth=True,
        )

        if auth_result is None:
            return AuthValidationResult(
                success=False, requires_auth=True, status_code=0,
                error_type="connection_error",
                message="带认证信息连接目标失败",
                suggestion="请检查网络连接和目标 URL",
                connectivity=conn,
            )

        auth_status_code = auth_result.get("status", 0)

        if 200 <= auth_status_code < 300:
            return AuthValidationResult(
                success=True, requires_auth=True,
                status_code=auth_status_code, error_type="",
                message="认证成功", suggestion="",
                connectivity=conn,
            )

        response_text = auth_result.get("body", "")
        error_type, error_msg = _detect_error_type(auth_status_code, response_text)

        return AuthValidationResult(
            success=False, requires_auth=True,
            status_code=auth_status_code, error_type=error_type,
            message=f"认证失败: {error_msg} (HTTP {auth_status_code})",
            suggestion=_get_suggestion(error_type, auth, response_text),
            connectivity=conn,
        )

    except Exception as e:
        return AuthValidationResult(
            success=False, requires_auth=False, status_code=0,
            error_type="exception",
            message=f"连接异常: {str(e)}",
            suggestion="请检查网络连接和目标 URL",
        )


def _is_private_ip(host: str) -> bool:
    """判断是否为内网 IP 地址。"""
    import ipaddress
    
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_private
    except ValueError:
        return False


def _get_connection_suggestion(target_url: str) -> str:
    """根据目标类型生成连通性测试失败的修复建议。"""
    from urllib.parse import urlparse
    
    parsed = urlparse(target_url)
    host = parsed.hostname or ""
    port = parsed.port or ""
    suggestions = []
    
    is_local = "localhost" in parsed.netloc or "127.0.0.1" in parsed.netloc or "0.0.0.0" in parsed.netloc
    is_private = _is_private_ip(host)
    is_ollama_port = port == 11434
    has_v1_path = "/v1" in parsed.path.lower()
    
    if is_local or (is_private and is_ollama_port):
        suggestions.append("\n🔌 本地/Ollama 服务连接失败，请检查：")
        suggestions.append("  - Ollama 服务是否运行？(运行命令: ollama serve)")
        suggestions.append("  - LM Studio 是否启动？")
        suggestions.append("  - 端口是否正确？(Ollama默认11434, LM Studio默认1234)")
        suggestions.append("  - 本地防火墙是否阻止了连接")
        if not has_v1_path:
            suggestions.append(f"  - URL 建议添加 /v1 路径: {parsed.scheme}://{parsed.netloc}/v1")
        suggestions.append("\n常见本地服务 URL：")
        suggestions.append("  Ollama: http://localhost:11434/v1")
        suggestions.append("  LM Studio: http://localhost:1234/v1")
        suggestions.append("  LocalAI: http://localhost:8080/v1")
    
    elif "ollama" in parsed.netloc.lower():
        suggestions.append("\n🔌 Ollama 服务连接失败，请检查：")
        suggestions.append("  - 服务器地址是否正确")
        if not has_v1_path:
            suggestions.append(f"  - URL 建议添加 /v1 路径: {parsed.scheme}://{parsed.netloc}/v1")
        suggestions.append("  - 服务器防火墙是否允许访问")
        suggestions.append("\n正确格式：http://your-ollama-host:11434/v1")
    
    elif "deepseek" in parsed.netloc.lower():
        suggestions.append("\n🔌 DeepSeek API 连接失败，请检查：")
        suggestions.append("  - URL 是否正确 (api.deepseek.com)")
        suggestions.append("  - 是否提供了 API Key")
        suggestions.append("  - 网络是否能访问外网")
        suggestions.append("\n正确格式：https://api.deepseek.com/v1")
    
    elif is_private:
        suggestions.append("\n🔌 内网 AI 服务连接失败，请检查：")
        suggestions.append("  - 服务器地址是否正确")
        suggestions.append("  - 服务是否已启动")
        suggestions.append("  - 服务器防火墙是否允许访问")
        if not has_v1_path:
            suggestions.append(f"  - URL 建议添加 /v1 路径: {parsed.scheme}://{parsed.netloc}/v1")
        suggestions.append("\n常见内网 AI 服务 URL：")
        suggestions.append("  Ollama: http://192.168.x.x:11434/v1")
        suggestions.append("  LM Studio: http://192.168.x.x:1234/v1")
        suggestions.append("  LocalAI: http://192.168.x.x:8080/v1")
    
    else:
        suggestions.append("\n🔌 连接失败，请检查：")
        suggestions.append("  - 目标 URL 是否正确")
        suggestions.append("  - 网络是否可达（ping/telnet 测试）")
        suggestions.append("  - 防火墙是否允许访问")
        if not has_v1_path:
            suggestions.append("  - 是否需要添加 /v1/chat/completions 路径")
        suggestions.append("\n常见 AI 服务 URL 格式：")
        suggestions.append("  OpenAI: https://api.openai.com/v1")
        suggestions.append("  DeepSeek: https://api.deepseek.com/v1")
        suggestions.append("  Ollama: http://localhost:11434/v1")
        suggestions.append("  LM Studio: http://localhost:1234/v1")
    
    return "\n".join(suggestions)


def _get_suggestion(error_type: str, auth: AuthContext | None, response: str = "") -> str:
    """根据错误类型生成修复建议。"""
    suggestions = []

    if error_type in ("unauthorized", "invalid_token", "invalid_key"):
        suggestions.append("\n🚨 认证失败，请检查以下内容：")
        
        if auth:
            if auth.bearer:
                suggestions.append("  - Bearer Token 是否正确？")
                if "expired" in response.lower():
                    suggestions.append("  - Token 可能已过期，请重新获取")
            
            if auth.cookies:
                suggestions.append("  - Cookie 是否有效？（可能已过期）")
            
            if auth.basic_auth:
                suggestions.append("  - Basic Auth 用户名和密码是否正确？")
            
            if auth.api_keys:
                suggestions.append("  - API Key 是否正确？")
        
        suggestions.append("\n📋 修复方法：")
        suggestions.append("  1. 打开浏览器 F12 → 网络(Network)")
        suggestions.append("  2. 找到 AI 相关请求 → 右键复制请求头")
        suggestions.append("  3. 保存到文件: headers.txt")
        suggestions.append("  4. 使用命令: redteam quicktest --target https://xxx --header-file headers.txt")

    elif error_type == "requires_auth":
        suggestions.append("\n🔐 目标需要认证，请提供认证信息：")
        suggestions.append("\n方法一：使用 API Key")
        suggestions.append("  redteam quicktest --target https://xxx --api-key sk-xxx")
        suggestions.append("\n方法二：使用浏览器请求头")
        suggestions.append("  1. 打开浏览器 F12 → 网络(Network)")
        suggestions.append("  2. 找到 AI 相关请求 → 右键复制请求头")
        suggestions.append("  3. 保存到文件: headers.txt")
        suggestions.append("  4. 运行命令: redteam quicktest --target https://xxx --header-file headers.txt")

    elif error_type == "forbidden":
        suggestions.append("\n🚫 认证凭据有效，但权限不足：")
        suggestions.append("  - 检查是否缺少必要的请求头（如 Origin、Referer）")
        suggestions.append("  - 尝试从浏览器复制完整请求头")

    elif error_type == "method_not_allowed":
        suggestions.append("\n🔄 请求方法不允许：")
        suggestions.append("  - 目标可能不是标准的 Chat Completions API")
        suggestions.append("  - 尝试在 URL 后添加 /v1/chat/completions 路径")
        suggestions.append("  - 继续执行侦察阶段，系统会自动发现正确的端点")

    elif error_type == "rate_limit":
        suggestions.append("\n⏱️ 请求频率过高：")
        suggestions.append("  - 请稍后重试")
        suggestions.append("  - 使用 --max-concurrent 1 参数降低并发")

    elif error_type == "not_found":
        suggestions.append("\n📭 目标不存在：")
        suggestions.append("  - 请检查目标 URL 是否正确")
        suggestions.append("  - 尝试添加 /v1/chat/completions 路径")

    elif error_type == "connection_error":
        suggestions.append("\n🔌 连接失败：")
        suggestions.append("  - 请检查目标 URL 是否正确")
        suggestions.append("  - 请检查网络是否可达")

    elif error_type == "server_error":
        suggestions.append("\n⚠️ 服务器内部错误：")
        suggestions.append("  - 请稍后重试")

    else:
        suggestions.append("\n💡 请检查认证信息或联系管理员")

    return "\n".join(suggestions)


def validate_and_report(
    target_url: str,
    auth: AuthContext | None,
    command_name: str,
) -> tuple[bool, bool, ConnectivityResult | None]:
    """验证认证并输出报告 — AI 红队专家视角。

    展示目标类型、连通性探测详情和风险评估。

    Args:
        target_url: 目标 URL
        auth: 认证上下文
        command_name: 命令名称（用于生成示例命令）

    Returns:
        (can_proceed, requires_auth, connectivity)
        - can_proceed: 是否可以继续执行侦察
        - requires_auth: 目标是否需要认证
        - connectivity: 连通性探测结果（传递给后续阶段）
    """
    from rich.console import Console
    from rich.table import Table
    from rich import box

    console = Console()

    result = validate_auth(target_url, auth)
    conn = result.connectivity

    # ━━━ 探测详情表格 ━━━
    if conn and conn.probes:
        # 只展示有意义的探测结果（非全部 404）
        meaningful = [p for p in conn.probes
                      if p.status > 0 and not (p.status == 404 and "不存在" in p.note)]
        if not meaningful:
            meaningful = conn.probes[:6]  # fallback

        table = Table(box=box.SIMPLE, show_header=True, show_edge=False,
                      padding=(0, 1), collapse_padding=True)
        table.add_column("方法", style="dim", width=5, no_wrap=True)
        table.add_column("路径", style="white", no_wrap=True)
        table.add_column("状态", width=8, no_wrap=True)
        table.add_column("说明", style="cyan")

        for p in meaningful[:12]:
            method_style = "[green]" if p.success else "[dim]" if p.status == 404 else "[yellow]"
            status_style = "[green]" if p.success else "[red]" if p.status in (401, 403) else "[dim]"
            status_text = f"{status_style}{p.status}[/]"

            # 缩短路径显示
            path_display = p.url.replace(target_url.rstrip("/"), "") if target_url.rstrip("/") in p.url else p.url
            if len(path_display) > 50:
                path_display = "..." + path_display[-47:]
            if not path_display:
                path_display = "/"

            table.add_row(
                f"{method_style}{p.method}[/]",
                path_display,
                status_text,
                p.note if p.note else "-",
            )

        console.print(table)

    # ━━━ 目标类型 & 风险评估 ━━━
    _print_target_assessment(console, result, conn)

    # ━━━ 结果处理 ━━━
    if result.success:
        return True, result.requires_auth, conn

    console.print(f"\n[red]❌ {result.message}[/]")

    if result.suggestion:
        console.print(f"\n[yellow]💡 修复建议[/]")
        console.print(f"{result.suggestion}")

    return False, result.requires_auth, conn


def _print_target_assessment(console, result: AuthValidationResult, conn: ConnectivityResult | None) -> None:
    """根据目标类型打印 AI 红队专家评估。"""
    if conn is None:
        return

    tt = conn.target_type
    platform = conn.platform_name

    # 目标类型图标和标签
    type_config = {
        TargetType.OLLAMA:               ("🖥️", "Ollama 模型服务器", "green"),
        TargetType.OPENAI_COMPATIBLE:    ("🔌", "OpenAI 兼容 API", "green"),
        TargetType.MODEL_PLATFORM:       ("☁️", f"模型服务平台{' — ' + platform if platform else ''}", "cyan"),
        TargetType.AI_CHAT_WEBSITE:      ("🌐", f"AI 聊天网站{' — ' + platform if platform else ''}", "yellow"),
        TargetType.WEB_APP:              ("🌐", "Web 应用（含 AI 功能）", "yellow"),
        TargetType.UNKNOWN:              ("❓", "未知目标", "dim"),
    }
    icon, label, color = type_config.get(tt, ("❓", "未知目标", "dim"))

    console.print(f"\n  [{color}]{icon} 目标类型: {label}[/]")

    # 认证状态
    if result.requires_auth:
        console.print(f"  [red]🔒 认证状态: 需要认证[/]")
    elif conn.connected:
        console.print(f"  [green]🔓 认证状态: 无需认证[/]")

    # 发现模型
    if conn.exposed_models:
        models_str = ", ".join(conn.exposed_models[:8])
        if len(conn.exposed_models) > 8:
            models_str += f" ... 等 {len(conn.exposed_models)} 个"
        console.print(f"  [green]📋 暴露模型: {models_str}[/]")

    # Ollama 版本
    if conn.ollama_version:
        console.print(f"  [dim]🔖 Ollama 版本: {conn.ollama_version}[/]")

    # 红队评估
    console.print(f"\n  [bold]⚔️ 红队评估:[/]")
    _print_risk_assessment(console, tt, conn, result.requires_auth)


def _print_risk_assessment(console, tt: TargetType, conn: ConnectivityResult, requires_auth: bool) -> None:
    """根据目标类型输出风险评语和攻击建议。"""
    if tt == TargetType.OLLAMA:
        if not requires_auth and conn.exposed_models:
            console.print(f"    [red]高优先级目标[/] — 无认证 Ollama 实例，可执行：")
            console.print(f"      • 枚举所有模型（已发现 {len(conn.exposed_models)} 个）")
            console.print(f"      • 直接调用模型 API（/api/chat, /api/generate）")
            console.print(f"      • 系统提示提取 & 越狱攻击")
            console.print(f"      • 恶意模型注入 & 记忆投毒")
            console.print(f"      • API 滥用（挖矿、垃圾内容生成）")
        elif not requires_auth:
            console.print(f"    [yellow]中优先级[/] — Ollama 可访问但未枚举到模型，继续侦察")

    elif tt == TargetType.OPENAI_COMPATIBLE:
        if not requires_auth:
            console.print(f"    [red]高优先级目标[/] — 开放 OpenAI 兼容端点，可执行：")
            console.print(f"      • 提示注入 / 系统提示提取 / 越狱")
            console.print(f"      • Embedding 反演 & 成员推断攻击")
            console.print(f"      • 工具调用劫持（如有 function calling）")
        else:
            console.print(f"    [yellow]中优先级[/] — 认证后可执行全量攻击")

    elif tt == TargetType.MODEL_PLATFORM:
        platform = conn.platform_name or "未知平台"
        console.print(f"    [cyan]标准目标[/] — {platform} 平台，典型攻击面：")
        console.print(f"      • API Key 泄露 & 权限滥用")
        console.print(f"      • 提示注入 & 越狱（如平台有聊天接口）")
        console.print(f"      • 模型投毒（如有模型微调/训练接口）")
        console.print(f"      • 速率限制绕过 & 资源滥用")
        if requires_auth:
            console.print(f"    [yellow]⚠ 需要有效 API Key 或会话凭据[/]")

    elif tt == TargetType.AI_CHAT_WEBSITE:
        console.print(f"    [yellow]需进一步侦察[/] — AI 聊天网站通常隐藏真实 API 端点：")
        console.print(f"      • 后续 Phase 1 将分析 JS 客户端代码发现 API 端点")
        console.print(f"      • 浏览器 F12 流量分析获取真实请求格式")
        console.print(f"      • 认证通常通过 Cookie/Session，需要从浏览器复制")
        console.print(f"      • 如果获取到 API 端点，可执行标准 API 攻击")

    elif tt == TargetType.WEB_APP:
        console.print(f"    [yellow]需进一步侦察[/] — Web 应用需分析 JS 客户端和 API 路由：")
        console.print(f"      • 后续侦察将枚举隐藏路径和 API 端点")
        console.print(f"      • 检查是否有 /api/*, /v1/* 等 AI 相关路由")

    else:
        console.print(f"    [dim]无法确定目标类型，继续侦察以收集更多信息[/]")