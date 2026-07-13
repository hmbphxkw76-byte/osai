"""统一 HTTP 客户端（AI-300 考试兼容）。

分层降级策略：httpx → requests → urllib，确保在任何环境都能运行。

对齐 AI-300 要求：
  - 支持 OpenAI 兼容的 chat/completions 格式
  - 支持自定义认证上下文（Bearer/Cookie/Basic Auth）
  - 无需外部依赖时自动降级到标准库
"""
from __future__ import annotations

import json
from typing import Any, Optional

from redteam.core.models import AuthContext

try:
    import httpx
    _HTTP_LIB = "httpx"
except ImportError:
    try:
        import requests
        _HTTP_LIB = "requests"
    except ImportError:
        _HTTP_LIB = "urllib"


def send_post(
    url: str,
    data: dict[str, Any],
    auth: Optional[AuthContext] = None,
    timeout: float = 8.0,
    verify_ssl: bool = False,
) -> dict[str, Any] | None:
    """发送 POST 请求。

    Args:
        url: 请求 URL
        data: JSON 请求体
        auth: 认证上下文
        timeout: 超时时间（秒）
        verify_ssl: 是否验证 SSL 证书

    Returns:
        响应字典：{"status": int, "body": str, "headers": dict, "is_json": bool}
        失败返回 None
    """
    headers = {"Content-Type": "application/json"}
    if auth:
        headers.update(auth.to_header_dict())

    try:
        if _HTTP_LIB == "httpx":
            with httpx.Client(timeout=timeout, verify=verify_ssl) as client:
                resp = client.post(url, json=data, headers=headers)
                return _parse_response(resp)

        elif _HTTP_LIB == "requests":
            resp = requests.post(
                url, json=data, headers=headers,
                timeout=timeout, verify=verify_ssl
            )
            return _parse_response(resp)

        else:
            data_bytes = json.dumps(data).encode("utf-8")
            req = __import__("urllib.request").request.Request(
                url, data=data_bytes, headers=headers, method="POST"
            )
            with __import__("urllib.request").request.urlopen(req, timeout=timeout) as resp:
                body = resp.read().decode("utf-8")
                return {
                    "status": resp.status,
                    "body": body,
                    "headers": dict(resp.headers),
                    "is_json": "json" in resp.headers.get("content-type", ""),
                }

    except Exception:
        return None


def send_get(
    url: str,
    auth: Optional[AuthContext] = None,
    timeout: float = 5.0,
    verify_ssl: bool = False,
) -> dict[str, Any] | None:
    """发送 GET 请求。"""
    headers = {}
    if auth:
        headers.update(auth.to_header_dict())

    try:
        if _HTTP_LIB == "httpx":
            with httpx.Client(timeout=timeout, verify=verify_ssl) as client:
                resp = client.get(url, headers=headers)
                return _parse_response(resp)

        elif _HTTP_LIB == "requests":
            resp = requests.get(url, headers=headers, timeout=timeout, verify=verify_ssl)
            return _parse_response(resp)

        else:
            req = __import__("urllib.request").request.Request(url, headers=headers)
            with __import__("urllib.request").request.urlopen(req, timeout=timeout) as resp:
                body = resp.read().decode("utf-8")
                return {
                    "status": resp.status,
                    "body": body,
                    "headers": dict(resp.headers),
                    "is_json": "json" in resp.headers.get("content-type", ""),
                }

    except Exception:
        return None


def send_chat(
    url: str,
    content: str,
    auth: Optional[AuthContext] = None,
    timeout: float = 8.0,
) -> dict[str, Any] | None:
    """发送 OpenAI 格式的聊天请求。

    Args:
        url: Chat API 端点 URL
        content: 用户消息内容
        auth: 认证上下文
        timeout: 超时时间（秒）

    Returns:
        响应字典，包含 status, body, headers, is_json
    """
    return send_post(
        url,
        {"messages": [{"role": "user", "content": content}]},
        auth=auth,
        timeout=timeout,
        verify_ssl=False,
    )


def _parse_response(resp) -> dict[str, Any]:
    """统一解析响应，兼容不同库的响应对象。"""
    if hasattr(resp, "text"):
        body = resp.text
    elif hasattr(resp, "read"):
        body = resp.read().decode("utf-8")
    else:
        body = str(resp)

    headers = {}
    if hasattr(resp, "headers"):
        headers = dict(resp.headers)

    is_json = "json" in headers.get("content-type", "")

    status = 200
    if hasattr(resp, "status_code"):
        status = resp.status_code
    elif hasattr(resp, "status"):
        status = resp.status

    return {
        "status": status,
        "body": body,
        "headers": headers,
        "is_json": is_json,
    }


__all__ = ["send_post", "send_get", "send_chat"]


def _print_response(resp: dict[str, Any] | None) -> None:
    """格式化输出响应，方便考试时快速查看。"""
    if resp is None:
        print("[ERROR] 请求失败")
        return

    print(f"[STATUS] {resp['status']}")
    print(f"[HEADERS] {json.dumps(dict(resp['headers']), indent=2, ensure_ascii=False)}")
    print("[BODY]")
    try:
        body = json.loads(resp["body"])
        print(json.dumps(body, indent=2, ensure_ascii=False))
    except ValueError:
        print(resp["body"])


def _build_auth(token: str | None) -> AuthContext | None:
    """从 token 参数构建认证上下文。"""
    if token:
        return AuthContext(api_key=token)
    return None


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="AI-300 统一 HTTP 客户端（支持 httpx → requests → urllib 降级）"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    chat_parser = subparsers.add_parser("chat", help="发送 OpenAI 格式聊天请求")
    chat_parser.add_argument("--url", required=True, help="API 端点 URL")
    chat_parser.add_argument("--content", required=True, help="用户消息内容")
    chat_parser.add_argument("--token", help="Bearer Token")
    chat_parser.add_argument("--timeout", type=float, default=8.0, help="超时时间")

    post_parser = subparsers.add_parser("post", help="发送 POST 请求")
    post_parser.add_argument("--url", required=True, help="API 端点 URL")
    post_parser.add_argument("--data", required=True, help="JSON 请求体")
    post_parser.add_argument("--token", help="Bearer Token")
    post_parser.add_argument("--timeout", type=float, default=8.0, help="超时时间")

    get_parser = subparsers.add_parser("get", help="发送 GET 请求")
    get_parser.add_argument("--url", required=True, help="API 端点 URL")
    get_parser.add_argument("--token", help="Bearer Token")
    get_parser.add_argument("--timeout", type=float, default=5.0, help="超时时间")

    probe_rate_parser = subparsers.add_parser(
        "probe-rate",
        help="速率限制阈值探测（TCM rate_limit_tester.py 融合）",
        description="通过逐步提高请求速率，确定目标的速率限制阈值，支持并发模式和 CSV 导出"
    )
    probe_rate_parser.add_argument("--url", required=True, help="API 端点 URL")
    probe_rate_parser.add_argument("--token", help="Bearer Token")
    probe_rate_parser.add_argument("--timeout", type=float, default=8.0, help="超时时间")
    probe_rate_parser.add_argument("--max-requests", type=int, default=50, help="每个速率下的最大请求数")
    probe_rate_parser.add_argument("--test-rates", type=str, default="30,60,120,180", help="测试速率列表（逗号分隔，单位 req/min）")
    probe_rate_parser.add_argument("--concurrent", action="store_true", help="启用并发模式")
    probe_rate_parser.add_argument("--output", help="CSV 输出文件路径")

    probe_det_parser = subparsers.add_parser(
        "probe-determinism",
        help="确定性探测（TCM temperature_probe.py 融合）",
        description="通过发送多次相同请求，分析响应一致性，检测模型的随机性（temperature）"
    )
    probe_det_parser.add_argument("--url", required=True, help="API 端点 URL")
    probe_det_parser.add_argument("--token", help="Bearer Token")
    probe_det_parser.add_argument("--timeout", type=float, default=8.0, help="超时时间")
    probe_det_parser.add_argument("--count", type=int, default=10, help="请求次数")
    probe_det_parser.add_argument("--rate", type=float, default=10.0, help="请求速率（req/min）")
    probe_det_parser.add_argument("--concurrent", action="store_true", help="启用并发模式")
    probe_det_parser.add_argument("--output", help="CSV 输出文件路径")

    args = parser.parse_args()
    auth = _build_auth(args.token)

    if args.command == "chat":
        resp = send_chat(args.url, args.content, auth, args.timeout)
    elif args.command == "post":
        try:
            data = json.loads(args.data)
        except ValueError:
            print("[ERROR] 无效的 JSON 数据")
            exit(1)
        resp = send_post(args.url, data, auth, args.timeout)
    elif args.command == "get":
        resp = send_get(args.url, auth, args.timeout)
    elif args.command == "probe-rate":
        from redteam.recon.evasion import probe_rate_limit
        test_rates = [int(r.strip()) for r in args.test_rates.split(",")]
        result = probe_rate_limit(
            args.url,
            auth=auth,
            timeout=args.timeout,
            test_rates=test_rates,
            max_requests=args.max_requests,
            concurrent=args.concurrent,
            output_file=args.output,
        )
        print(json.dumps(result, indent=2, ensure_ascii=False))
    elif args.command == "probe-determinism":
        from redteam.recon.evasion import probe_determinism
        result = probe_determinism(
            args.url,
            auth=auth,
            timeout=args.timeout,
            num_requests=args.count,
            rate=args.rate,
            concurrent=args.concurrent,
            output_file=args.output,
        )
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        resp = None

    if args.command not in ("probe-rate", "probe-determinism"):
        _print_response(resp)