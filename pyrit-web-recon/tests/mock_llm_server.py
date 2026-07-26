# -*- coding: utf-8 -*-
"""
本地 Mock LLM Web 应用

用于完整流水线测试：
  - 提供带输入框 / 发送按钮 / 响应区的聊天页面
  - POST /api/chat 返回 OpenAI 兼容 JSON
  - 无需登录、无需外部网络

启动：
  python tests/mock_llm_server.py

默认监听：http://127.0.0.1:18080
"""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, HTTPServer

HTML_PAGE = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Mock AI Assistant</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 800px; margin: 40px auto; padding: 20px; }
        #chat-container { border: 1px solid #ccc; border-radius: 8px; padding: 20px; min-height: 300px; }
        #messages { margin-bottom: 20px; }
        .message { margin: 10px 0; padding: 10px; border-radius: 6px; }
        .user { background: #e3f2fd; text-align: right; }
        .assistant { background: #f5f5f5; }
        .input-row { display: flex; gap: 10px; }
        #user-input { flex: 1; padding: 10px; border: 1px solid #ccc; border-radius: 4px; }
        #send-button { padding: 10px 20px; background: #1976d2; color: white; border: none; border-radius: 4px; cursor: pointer; }
        #send-button:hover { background: #1565c0; }
    </style>
</head>
<body>
    <h1>Mock AI Assistant</h1>
    <div id="chat-container">
        <div id="messages"></div>
        <div class="input-row">
            <input type="text" id="user-input" placeholder="请输入消息...">
            <button id="send-button">发送</button>
        </div>
    </div>
    <script>
        const input = document.getElementById('user-input');
        const sendBtn = document.getElementById('send-button');
        const messages = document.getElementById('messages');

        async function sendMessage() {
            const text = input.value.trim();
            if (!text) return;
            appendMessage('user', text);
            input.value = '';
            try {
                const resp = await fetch('/api/chat', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ message: text })
                });
                const data = await resp.json();
                appendMessage('assistant', data.choices?.[0]?.message?.content || '无响应');
            } catch (e) {
                appendMessage('assistant', '请求失败: ' + e.message);
            }
        }

        function appendMessage(role, text) {
            const div = document.createElement('div');
            div.className = 'message ' + role;
            div.textContent = text;
            messages.appendChild(div);
        }

        sendBtn.addEventListener('click', sendMessage);
        input.addEventListener('keydown', (e) => { if (e.key === 'Enter') sendMessage(); });
    </script>
</body>
</html>
"""


class MockLLMHandler(BaseHTTPRequestHandler):
    """Mock LLM HTTP 处理器"""

    def log_message(self, format, *args):
        # 关闭访问日志，避免污染输出
        pass

    def _send_json(self, status: int, data: dict) -> None:
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/":
            body = HTML_PAGE.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        if self.path == "/api/chat":
            try:
                length = int(self.headers.get("Content-Length", "0"))
                payload = self.rfile.read(length)
                request = json.loads(payload.decode("utf-8"))
                user_msg = request.get("message", "")
                response = {
                    "id": "chatcmpl-mock",
                    "object": "chat.completion",
                    "model": "gpt-mock-model",
                    "choices": [
                        {
                            "index": 0,
                            "message": {
                                "role": "assistant",
                                "content": f"Mock 回复：已收到你的消息 \"{user_msg}\"。",
                            },
                            "finish_reason": "stop",
                        }
                    ],
                }
                self._send_json(200, response)
            except Exception:
                self._send_json(500, {"error": "internal server error"})
        else:
            self.send_response(404)
            self.end_headers()


def run_server(host: str = "127.0.0.1", port: int = 18080) -> None:
    """启动 Mock 服务器"""
    server = HTTPServer((host, port), MockLLMHandler)
    print(f"Mock LLM server running at http://{host}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down mock server...")
    finally:
        server.server_close()


if __name__ == "__main__":
    run_server()
