"""AIVP 适配器代理 — 将 AIVP 自定义 API 转为 OpenAI 兼容格式

AIVP 平台使用自定义 API：
  POST /api/labs/{lab_id}/chat  body: {"prompt": "..."}  → SSE 流式响应
  GET  /api/config                                       → 平台配置（含模型名）

本代理将其转为 OpenAI 兼容格式：
  POST /v1/chat/completions  body: {"messages": [...], "model": "..."}  → JSON 响应
  GET  /v1/models                                          → 模型列表

最佳实践：模型名自动发现（非 .env 手动配置）
  启动时自动查询 /api/config 获取 ollama_model_default 字段
  --model-name 仅作 fallback，当自动发现失败时使用

用法：
  python pipeline/aivp_adapter.py --port 8082 --lab-id PI_01
  然后在 .env 中设置:
    OPENAI_TARGET_ENDPOINT=http://localhost:8082/v1
    OPENAI_TARGET_MODEL=auto        # 'auto' = 由适配器自动发现
    OPENAICompatible_API_KEY=none
  运行: python main.py --openai
"""

from __future__ import annotations

import argparse
import json
import logging
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

# 全局配置
_AIVP_BASE = "http://192.168.40.198"
_LAB_ID = "PI_01"
_MODEL_NAME = "LongCat-2.0"

# 模块级适配器服务器引用（供 auto_adapt 管理生命周期）
_adapter_server: ThreadingHTTPServer | None = None


def call_aivp_chat(prompt: str, timeout: int = 120) -> str:
    """调用 AIVP chat 端点，解析 SSE 流式响应，返回完整文本

    AIVP SSE 格式：
      event: meta
      data: {"request_id": "...", "lab_id": "...", ...}

      data: {"content": "chunk1"}

      data: {"content": "chunk2"}

      data: [DONE]
    """
    url = f"{_AIVP_BASE}/api/labs/{_LAB_ID}/chat"
    data = json.dumps({"prompt": prompt}).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        resp = urllib.request.urlopen(req, timeout=timeout)
        content_type = resp.headers.get("Content-Type", "")

        if "text/event-stream" in content_type:
            # SSE 流式响应
            full_text = []
            for line in resp:
                line = line.decode("utf-8", errors="replace").strip()
                if line.startswith("data: "):
                    data_str = line[6:]  # 去掉 "data: " 前缀
                    if data_str == "[DONE]":
                        break
                    try:
                        obj = json.loads(data_str)
                        if "content" in obj:
                            full_text.append(obj["content"])
                    except json.JSONDecodeError:
                        pass
            return "".join(full_text)
        else:
            # 非流式响应（JSON）
            body = resp.read().decode("utf-8", errors="replace")
            try:
                obj = json.loads(body)
                return obj.get("content") or obj.get("response") or body
            except json.JSONDecodeError:
                return body
    except urllib.error.HTTPError as e:
        err_body = ""
        if e.fp:
            err_body = e.read(500).decode("utf-8", errors="replace")
        logger.error("AIVP chat 错误 [%d]: %s", e.code, err_body[:200])
        return f"[ERROR {e.code}: {err_body[:200]}]"
    except Exception as e:
        logger.error("AIVP chat 异常: %s", e)
        return f"[ERROR: {e}]"


class AdapterHandler(BaseHTTPRequestHandler):
    """OpenAI 兼容请求处理器"""

    def log_message(self, format, *args):
        # 简化日志：只记录方法和路径
        logger.info("  %s %s", self.command, self.path)

    def do_GET(self):
        """处理 GET 请求"""
        if self.path == "/v1/models" or self.path == "/models":
            self._handle_models()
        elif self.path == "/health" or self.path == "/":
            self._send_json(200, {"status": "ok"})
        else:
            self._send_json(404, {"error": "Not Found"})

    def do_POST(self):
        """处理 POST 请求"""
        if self.path == "/v1/chat/completions" or self.path == "/chat/completions":
            self._handle_chat_completions()
        else:
            self._send_json(404, {"error": "Not Found"})

    def do_OPTIONS(self):
        """处理 CORS 预检请求"""
        self.send_response(204)
        self._send_cors_headers()
        self.end_headers()

    def _handle_models(self):
        """返回模型列表（OpenAI /v1/models 格式）"""
        models = [
            {
                "id": _MODEL_NAME,
                "object": "model",
                "created": int(time.time()),
                "owned_by": "aivp",
            }
        ]
        self._send_json(200, {"object": "list", "data": models})

    def _handle_chat_completions(self):
        """将 OpenAI chat/completions 请求转为 AIVP 格式"""
        # 读取请求体
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length > 0 else b"{}"

        try:
            req_data = json.loads(body.decode("utf-8"))
        except json.JSONDecodeError:
            self._send_json(400, {"error": "Invalid JSON"})
            return

        # 从 messages 数组提取最后一条 user 消息
        messages = req_data.get("messages", [])
        prompt = ""
        for msg in reversed(messages):
            if msg.get("role") == "user":
                prompt = msg.get("content", "")
                break

        if not prompt:
            # 如果没有 user 消息，拼接所有消息
            prompt = "\n".join(
                m.get("content", "") for m in messages if m.get("content")
            )

        if not prompt:
            self._send_json(400, {"error": "No prompt found in messages"})
            return

        stream = req_data.get("stream", False)
        logger.info(
            "  → AIVP chat (prompt 长度=%d, stream=%s)",
            len(prompt), stream,
        )

        # 调用 AIVP chat
        start_time = time.time()
        full_response = call_aivp_chat(prompt, timeout=120)
        elapsed = time.time() - start_time
        logger.info(
            "  ← AIVP response (长度=%d, 耗时=%.1fs)",
            len(full_response), elapsed,
        )

        if stream:
            # SSE 流式响应（模拟 OpenAI 流式格式）
            self.send_response(200)
            self._send_cors_headers()
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()

            # 分块发送
            chunk_size = 20  # 每块约 20 字符
            for i in range(0, len(full_response), chunk_size):
                chunk = full_response[i : i + chunk_size]
                chunk_data = {
                    "id": f"chatcmpl-aivp-{int(time.time())}",
                    "object": "chat.completion.chunk",
                    "created": int(time.time()),
                    "model": _MODEL_NAME,
                    "choices": [
                        {
                            "index": 0,
                            "delta": {"content": chunk},
                            "finish_reason": None,
                        }
                    ],
                }
                self.wfile.write(
                    f"data: {json.dumps(chunk_data)}\n\n".encode()
                )
                self.wfile.flush()

            # 发送结束标记
            end_data = {
                "id": f"chatcmpl-aivp-{int(time.time())}",
                "object": "chat.completion.chunk",
                "created": int(time.time()),
                "model": _MODEL_NAME,
                "choices": [
                    {"index": 0, "delta": {}, "finish_reason": "stop"}
                ],
            }
            self.wfile.write(f"data: {json.dumps(end_data)}\n\n".encode())
            self.wfile.write(b"data: [DONE]\n\n")
            self.wfile.flush()
        else:
            # 非流式 JSON 响应（标准 OpenAI 格式）
            response = {
                "id": f"chatcmpl-aivp-{int(time.time())}",
                "object": "chat.completion",
                "created": int(time.time()),
                "model": _MODEL_NAME,
                "choices": [
                    {
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "content": full_response,
                        },
                        "finish_reason": "stop",
                    }
                ],
                "usage": {
                    "prompt_tokens": len(prompt) // 4,
                    "completion_tokens": len(full_response) // 4,
                    "total_tokens": (len(prompt) + len(full_response)) // 4,
                },
            }
            self._send_json(200, response)

    def _send_json(self, status: int, data: dict):
        """发送 JSON 响应"""
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self._send_cors_headers()
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_cors_headers(self):
        """发送 CORS 头"""
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header(
            "Access-Control-Allow-Methods", "GET, POST, OPTIONS"
        )
        self.send_header(
            "Access-Control-Allow-Headers", "Content-Type, Authorization"
        )


class ThreadingHTTPServer(HTTPServer):
    """多线程 HTTP 服务器（处理并发请求）"""

    def __init__(self, server_address, RequestHandlerClass):
        super().__init__(server_address, RequestHandlerClass)
        self.daemon_threads = True


def test_openai_compat(endpoint: str, timeout: int = 5) -> bool:
    """测试端点是否 OpenAI 兼容（GET {endpoint}/models 返回 JSON 模型列表）

    :param endpoint: 待测端点 base URL
    :param timeout: 超时秒数
    :returns: True=OpenAI 兼容，False=不兼容
    """
    test_url = endpoint.rstrip("/") + "/models"
    try:
        resp = urllib.request.urlopen(test_url, timeout=timeout)
        ct = resp.headers.get("Content-Type", "")
        body = resp.read(500).decode("utf-8", errors="replace")
        # OpenAI /models 返回 JSON + Content-Type: application/json
        if "json" in ct and '"data"' in body:
            return True
        # SPA 会返回 HTML（catch-all routing）
        if "html" in ct or body.lstrip().startswith("<!"):
            return False
        # 其他 JSON 但无 data 字段
        return False
    except urllib.error.HTTPError:
        # 404/401 等明确非兼容
        return False
    except Exception:
        return False


def _detect_aivp_params(endpoint: str, target_url: str) -> tuple[str, str] | None:
    """从发现的端点推断 AIVP base + lab_id

    Playwright 发现的端点格式可能为:
      http://192.168.40.198/api/labs/PI_01  (去掉 /chat 后缀)
    从中提取:
      aivp_base = http://192.168.40.198
      lab_id    = PI_01

    :returns: (aivp_base, lab_id) 或 None（非 AIVP 端点）
    """
    parsed = urlparse(endpoint)
    root = f"{parsed.scheme}://{parsed.netloc}"
    path = parsed.path

    # 匹配 /api/labs/{lab_id}
    import re
    m = re.match(r"(.*)/api/labs/([^/]+)", path)
    if m:
        base_path = m.group(1)
        aivp_base = root + base_path if base_path else root
        return aivp_base, m.group(2)

    # 也检查 target_url 是否含 labs 路径
    parsed2 = urlparse(target_url)
    m2 = re.match(r".*/labs/([^/]+)", parsed2.path)
    if m2:
        return root, m2.group(1)

    return None


def auto_adapt_for_web_target(
    discovered_endpoint: str,
    discovered_model: str,
    target_url: str,
    adapter_port: int = 8082,
) -> dict[str, str]:
    """Web 模式自动适配 — 检测 OpenAI 兼容性，不兼容则启动适配器

    这是 Web URL 模式的核心适配逻辑：
      1. 测试发现的端点是否 OpenAI 兼容
      2. 兼容 → 直接使用原端点（标准 OpenAI API）
      3. 不兼容 → 检测是否 AIVP 格式 → 启动适配器代理
      4. 返回新的 target dict（endpoint/model 已重写）

    :param discovered_endpoint: Playwright 发现的端点
    :param discovered_model: Playwright 发现的模型名
    :param target_url: 原始目标 URL（用于推断 AIVP 参数）
    :param adapter_port: 适配器监听端口
    :returns: {"endpoint": str, "model": str, "adapted": bool, "adapter_url": str}
    """
    global _AIVP_BASE, _LAB_ID, _MODEL_NAME, _adapter_server

    # 1. 测试 OpenAI 兼容性
    if test_openai_compat(discovered_endpoint):
        logger.info("✅ 端点 OpenAI 兼容: %s", discovered_endpoint)
        return {
            "endpoint": discovered_endpoint,
            "model": discovered_model,
            "adapted": False,
            "adapter_url": "",
        }

    logger.info("⚠️ *端点非 OpenAI 兼容: %s", discovered_endpoint)

    # 2. 检测 AIVP 参数
    aivp_params = _detect_aivp_params(discovered_endpoint, target_url)
    if aivp_params is None:
        # 非 AIVP 也非 OpenAI → 尝试兜底（用 target_url 的域作为 base）
        parsed = urlparse(target_url)
        root = f"{parsed.scheme}://{parsed.netloc}"
        import re
        m = re.search(r"/labs/([^/]+)", parsed.path)
        aivp_params = (root, m.group(1) if m else "PI_01")

    aivp_base, lab_id = aivp_params
    logger.info("🔍 检测到 AIVP 平台: base=%s, lab_id=%s", aivp_base, lab_id)

    # 3. 自动发现模型名（从 /api/config）
    model_name = discover_model_name(aivp_base, fallback=discovered_model or "unknown-model")

    # 4. 启动适配器代理（后台线程）
    _AIVP_BASE = aivp_base
    _LAB_ID = lab_id
    _MODEL_NAME = model_name

    adapter_url = f"http://127.0.0.1:{adapter_port}/v1"

    # 如果适配器已在运行，先关闭
    if _adapter_server is not None:
        try:
            _adapter_server.shutdown()
        except Exception:
            pass
        _adapter_server = None

    _adapter_server = ThreadingHTTPServer(
        ("127.0.0.1", adapter_port), AdapterHandler
    )
    t = threading.Thread(target=_adapter_server.serve_forever, daemon=True)
    t.start()
    logger.info("🚀 适配器代理已自动启动: %s (后台线程)", adapter_url)
    logger.info("   AIVP 后端: %s/api/labs/%s/chat", aivp_base, lab_id)
    logger.info("   模型: %s (自动发现)", model_name)

    # 5. 返回重写后的 target
    return {
        "endpoint": adapter_url,
        "model": model_name,
        "adapted": True,
        "adapter_url": adapter_url,
    }


def discover_model_name(aivp_base: str, fallback: str = "unknown-model") -> str:
    """自动发现模型名 — 从 AIVP /api/config 端点获取 ollama_model_default

    这是最佳实践：模型名通过侦察自动发现，而非 .env 手动配置。
    发现优先级：
      1. /api/config 的 ollama_model_default 字段
      2. fallback 参数（CLI --model-name）
      3. "unknown-model" 兜底

    :param aivp_base: AIVP 平台基址
    :param fallback: 自动)自动发现失败时的兜底模型名
    :returns: 发现的模型名
    """
    config_url = f"{aivp_base}/api/config"
    try:
        resp = urllib.request.urlopen(config_url, timeout=10)
        data = json.loads(resp.read().decode("utf-8", errors="replace"))
        model = data.get("ollama_model_default") or data.get("model") or ""
        if model:
            logger.info("🔍 模型名自动发现: %s (来源: /api/config)", model)
            return model
    except Exception as exc:
        logger.warning("模型名自动发现失败: %s，使用 fallback", exc)
    logger.info("🔍 模型名使用 fallback: %s", fallback)
    return fallback


def main():
    global _AIVP_BASE, _LAB_ID, _MODEL_NAME

    parser = argparse.ArgumentParser(description="AIVP → OpenAI 兼容适配器代理")
    parser.add_argument("--port", type=int, default=8082, help="监听端口")
    parser.add_argument("--host", default="127.0.0.1", help="监听地址")
    parser.add_argument(
        "--aivp-base", default="http://192.168.40.198", help="AIVP 平台基址"
    )
    parser.add_argument("--lab-id", default="PI_01", help="AIVP Lab ID")
    parser.add_argument(
        "--model-name", default=None,
        help="模型名 fallback（最佳实践：留空自动从 /api/config 发现）",
    )

    args = parser.parse_args()
    _AIVP_BASE = args.aivp_base.rstrip("/")
    _LAB_ID = args.lab_id

    # ── 最佳实践：模型名自动发现（非 .env 手动配置） ──
    fallback_model = args.model_name or "LongCat-2.0"
    _MODEL_NAME = discover_model_name(_AIVP_BASE, fallback=fallback_model)

    # 启动前测试连通性
    logger.info("测试 AIVP 连通性: %s/api/labs/%s/chat", _AIVP_BASE, _LAB_ID)
    test_response = call_aivp_chat("Hello", timeout=30)
    if test_response.startswith("[ERROR"):
        logger.error("AIVP 连通性测试失败: %s", test_response[:200])
        logger.error("请检查 AIVP 平台是否可访问")
        return

    logger.info("✅ AIVP 连通性正常 (响应: %s...)", test_response[:80])

    server = ThreadingHTTPServer(
        (args.host, args.port), AdapterHandler
    )
    logger.info(
        "🚀 AIVP 适配器代理已启动: http://%s:%d/v1", args.host, args.port
    )
    logger.info("   AIVP 后端: %s/api/labs/%s/chat", _AIVP_BASE, _LAB_ID)
    logger.info("   模型: %s (自动发现)", _MODEL_NAME)
    logger.info("   等待 garak 请求...")
    logger.info("")
    logger.info("在 .env 中配置:")
    logger.info("  OPENAI_TARGET_ENDPOINT=http://%s:%d/v1", args.host, args.port)
    logger.info("  OPENAI_TARGET_MODEL=%s  # 由适配器自动发现", _MODEL_NAME)
    logger.info("  OPENAICompatible_API_KEY=none")
    logger.info("")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("停止适配器代理")
        server.shutdown()


if __name__ == "__main__":
    main()
