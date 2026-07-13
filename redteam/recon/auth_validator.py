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

from dataclasses import dataclass
from typing import Optional

from redteam.core.http_client import send_post
from redteam.core.models import AuthContext


@dataclass
class AuthValidationResult:
    """认证验证结果。"""
    success: bool
    requires_auth: bool
    status_code: int
    error_type: str
    message: str
    suggestion: str


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
    "/api/status",
    "/models",
]

_AI_PROBE_POST_PATHS = [
    "/v1/chat/completions",
    "/api/embeddings",
    "/v1/embeddings",
    "/v1/messages",
    "/chat/completions",
]

def _tcp_reachable(target_url: str, timeout: float = 3.0) -> bool:
    """TCP 级别可达性预检查。
    
    在发送 HTTP 请求前先检查主机是否可达，快速区分网络问题和应用层问题。
    支持 IPv4 和 IPv6。
    """
    import socket
    from urllib.parse import urlparse
    
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


def _is_web_html(response: dict) -> bool:
    """判断响应是否为 HTML 网页。"""
    headers = response.get("headers", {})
    content_type = headers.get("content-type", headers.get("Content-Type", ""))
    return "text/html" in content_type.lower()


def _probe_connectivity(target_url: str) -> tuple[bool, str, int, str, str]:
    """多路径连通性探测。
    
    针对不同类型目标（Ollama、OpenAI兼容、开放API、网页）尝试多种探测路径。
    
    用户输入场景：
    - https://www.qwen.com/           → 网页首页，需要发现 API 端点
    - http://192.168.0.24:11434       → Ollama 服务，需要添加 /v1 路径
    - http://192.168.0.24/            → 可能是网页或本地服务
    
    探测策略：
    1. TCP 级别预检查（快速失败）
    2. GET 请求探测原始 URL（判断是网页还是 API）
    3. GET 请求探测 /v1/models, /api/tags 等只读端点
    4. POST 请求探测 /v1/chat/completions 等聊天端点
    
    Returns:
        (success, url, status_code, error_msg, endpoint_type)
        - endpoint_type: "get", "post", "web", "unknown"
    """
    from urllib.parse import urlparse
    
    if not _tcp_reachable(target_url):
        return False, target_url, 0, "主机不可达（TCP 连接失败）", "unknown"
    
    host_reachable = False
    
    parsed = urlparse(target_url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"
    path = parsed.path.rstrip("/")
    
    probe_urls_get = []
    probe_urls_post = []
    
    probe_urls_get.append(target_url)
    
    for probe_path in _AI_PROBE_GET_PATHS:
        full_path = path + probe_path if path else probe_path
        probe_urls_get.append(f"{base_url}{full_path}")
    
    for probe_path in _AI_PROBE_POST_PATHS:
        full_path = path + probe_path if path else probe_path
        probe_urls_post.append(f"{base_url}{full_path}")
    
    probe_urls_get = list(dict.fromkeys(probe_urls_get))[:10]
    probe_urls_post = list(dict.fromkeys(probe_urls_post))[:10]
    
    from redteam.core.http_client import send_get
    
    for url in probe_urls_get:
        try:
            result = send_get(
                url,
                auth=None,
                timeout=5.0,
                verify_ssl=False,
                stealth=True,
            )
            
            if result is not None:
                host_reachable = True
                status = result.get("status", 0)
                if 200 <= status < 300:
                    if _is_web_html(result):
                        continue
                    return True, url, status, "成功", "get"
                elif status in (401, 403):
                    return True, url, status, "需要认证", "get"
                elif status in (404, 405):
                    continue
                else:
                    return True, url, status, f"返回 HTTP {status}", "get"
        except Exception:
            continue
    
    for url in probe_urls_post:
        try:
            result = send_post(
                url,
                data={"messages": [{"role": "user", "content": "Hello"}]},
                auth=None,
                timeout=5.0,
                verify_ssl=False,
                stealth=True,
            )
            
            if result is not None:
                host_reachable = True
                status = result.get("status", 0)
                if 200 <= status < 300:
                    return True, url, status, "成功", "post"
                elif status in (401, 403):
                    return True, url, status, "需要认证", "post"
                elif status in (404, 405):
                    continue
                else:
                    return True, url, status, f"返回 HTTP {status}", "post"
        except Exception:
            continue
    
    if host_reachable:
        return False, target_url, 0, "主机可达，但未发现标准 AI API 端点", "web"
    
    return False, target_url, 0, "所有路径均无法连接", "unknown"


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
        connected, probe_url, status_code, error_msg, endpoint_type = _probe_connectivity(target_url)
        
        if not connected:
            if endpoint_type == "web":
                return AuthValidationResult(
                    success=True,
                    requires_auth=False,
                    status_code=0,
                    error_type="web_target",
                    message="目标可达（网页），未发现标准 AI API 端点，将继续侦察发现端点",
                    suggestion="",
                )
            
            return AuthValidationResult(
                success=False,
                requires_auth=False,
                status_code=0,
                error_type="connection_error",
                message=f"无法连接到目标: {error_msg}",
                suggestion=_get_connection_suggestion(target_url),
            )
        
        if endpoint_type == "get":
            if 200 <= status_code < 300:
                return AuthValidationResult(
                    success=True,
                    requires_auth=False,
                    status_code=status_code,
                    error_type="",
                    message=f"发现 AI API 端点: {probe_url}",
                    suggestion="",
                )
            elif status_code in (401, 403):
                if not auth:
                    return AuthValidationResult(
                        success=False,
                        requires_auth=True,
                        status_code=status_code,
                        error_type="requires_auth",
                        message="目标需要认证，但未提供认证信息",
                        suggestion="请提供 --api-key 或 --header-file 参数\n\n"
                                  "获取认证信息方法：\n"
                                  "  1. 打开浏览器 F12 → 网络(Network) → 找到 AI 相关请求\n"
                                  "  2. 右键复制请求头(Copy headers)\n"
                                  "  3. 保存到文件: headers.txt\n"
                                  "  4. 使用命令: redteam quicktest --target https://xxx --header-file headers.txt",
                    )
                
                auth_result = send_post(
                    probe_url,
                    data={"messages": [{"role": "user", "content": "Hello"}]},
                    auth=auth,
                    timeout=5.0,
                    verify_ssl=False,
                    stealth=True,
                )
                
                if auth_result is None:
                    return AuthValidationResult(
                        success=False,
                        requires_auth=True,
                        status_code=0,
                        error_type="connection_error",
                        message="带认证信息连接目标失败",
                        suggestion="请检查网络连接和目标 URL",
                    )
                
                auth_status_code = auth_result.get("status", 0)
                
                if 200 <= auth_status_code < 300:
                    return AuthValidationResult(
                        success=True,
                        requires_auth=True,
                        status_code=auth_status_code,
                        error_type="",
                        message="认证成功",
                        suggestion="",
                    )
                
                return AuthValidationResult(
                    success=False,
                    requires_auth=True,
                    status_code=auth_status_code,
                    error_type="auth_failed",
                    message=f"认证失败 (HTTP {auth_status_code})",
                    suggestion=_get_suggestion("unauthorized", auth),
                )
        
        no_auth_result = send_post(
            probe_url,
            data={"messages": [{"role": "user", "content": "Hello"}]},
            auth=None,
            timeout=5.0,
            verify_ssl=False,
            stealth=True,
        )

        if no_auth_result is None:
            return AuthValidationResult(
                success=False,
                requires_auth=False,
                status_code=0,
                error_type="connection_error",
                message="无法连接到目标",
                suggestion=_get_connection_suggestion(target_url),
            )

        status_code = no_auth_result.get("status", 0)

        if 200 <= status_code < 300:
            return AuthValidationResult(
                success=True,
                requires_auth=False,
                status_code=status_code,
                error_type="",
                message="目标不需要认证，可直接发送提示词",
                suggestion="",
            )

        if status_code not in (401, 403):
            error_type, error_msg = _detect_error_type(status_code, no_auth_result.get("body", ""))
            
            if error_type in ["method_not_allowed", "not_found", "server_error", "service_unavailable", "unknown"]:
                return AuthValidationResult(
                    success=True,
                    requires_auth=False,
                    status_code=status_code,
                    error_type=error_type,
                    message=f"目标返回 {error_msg} (HTTP {status_code})，但非认证错误，允许继续执行",
                    suggestion=_get_suggestion(error_type, auth),
                )
            
            return AuthValidationResult(
                success=False,
                requires_auth=False,
                status_code=status_code,
                error_type=error_type,
                message=f"{error_msg} (HTTP {status_code})",
                suggestion=_get_suggestion(error_type, auth),
            )

        if not auth:
            return AuthValidationResult(
                success=False,
                requires_auth=True,
                status_code=status_code,
                error_type="requires_auth",
                message="目标需要认证，但未提供认证信息",
                suggestion="请提供 --api-key 或 --header-file 参数\n\n"
                          "获取认证信息方法：\n"
                          "  1. 打开浏览器 F12 → 网络(Network) → 找到 AI 相关请求\n"
                          "  2. 右键复制请求头(Copy headers)\n"
                          "  3. 保存到文件: headers.txt\n"
                          "  4. 使用命令: redteam quicktest --target https://xxx --header-file headers.txt",
            )

        auth_result = send_post(
            target_url,
            data={"messages": [{"role": "user", "content": "Hello"}]},
            auth=auth,
            timeout=5.0,
            verify_ssl=False,
            stealth=True,
        )

        if auth_result is None:
            return AuthValidationResult(
                success=False,
                requires_auth=True,
                status_code=0,
                error_type="connection_error",
                message="带认证信息连接目标失败",
                suggestion="请检查网络连接和目标 URL",
            )

        auth_status_code = auth_result.get("status", 0)

        if 200 <= auth_status_code < 300:
            return AuthValidationResult(
                success=True,
                requires_auth=True,
                status_code=auth_status_code,
                error_type="",
                message="认证成功",
                suggestion="",
            )

        response_text = auth_result.get("body", "")
        error_type, error_msg = _detect_error_type(auth_status_code, response_text)

        return AuthValidationResult(
            success=False,
            requires_auth=True,
            status_code=auth_status_code,
            error_type=error_type,
            message=f"认证失败: {error_msg} (HTTP {auth_status_code})",
            suggestion=_get_suggestion(error_type, auth, response_text),
        )

    except Exception as e:
        return AuthValidationResult(
            success=False,
            requires_auth=False,
            status_code=0,
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
) -> tuple[bool, bool]:
    """验证认证并输出报告（CLI 使用）。
    
    Args:
        target_url: 目标 URL
        auth: 认证上下文
        command_name: 命令名称（用于生成示例命令）
    
    Returns:
        (can_proceed, requires_auth)
        - can_proceed: 是否可以继续发送提示词
        - requires_auth: 目标是否需要认证
    """
    from rich.console import Console
    
    console = Console()
    
    console.print(f"\n[cyan]🔍 认证验证[/]")
    
    result = validate_auth(target_url, auth)
    
    if result.success:
        if result.requires_auth:
            console.print(f"[green]✅ 认证成功[/]")
        else:
            console.print(f"[green]✅ 目标不需要认证[/]")
        return True, result.requires_auth
    
    console.print(f"[red]❌ {result.message}[/]")
    
    if result.suggestion:
        console.print(f"\n[yellow]💡 修复建议[/]")
        console.print(f"{result.suggestion}")
    
    return False, result.requires_auth