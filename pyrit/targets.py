"""
===============================================================================
OffSec AI-300 — .env 配置加载器 & 自定义 HTTP Target 工厂
===============================================================================
包含:
- load_env_config(): 加载 .env 配置文件，解析 CHAT_MODEL + SCORER_MODEL 双模型键
- CustomHttpChatTarget: 自定义 HTTP Chat Target（非标准 OpenAI 格式/内网自签证书）
- create_scorer_target() / create_attack_target(): Target 工厂函数
===============================================================================

CustomHttpChatTarget 使用示例:
  [1] 通用 Chat API（raw 格式，兼容任意内部 Web 应用）
      python main.py --lang cn --phase probe \
        --target-url http://localhost:5000/api/chat \
        --target-api-format raw

  [2] Cookie + Authorization 双重认证（常见考试场景）
      python main.py --lang cn --phase probe \
        --target-url http://localhost:5000/api/chat \
        --target-api-format raw \
        --target-cookie "session_id=abc123; auth_token=xyz" \
        --target-jwt "eyJhbGciOi..."

  [3] Cookie 认证 + 浏览器 UA 伪装（Web 应用 Session 认证）
      python main.py --lang cn --phase probe \
        --target-url http://192.168.1.100/internal/chat \
        --target-api-format raw \
        --target-cookie "alimail_device_id=49816375-..."

  [4] HTTPS 自签证书 + 自定义认证头（X-API-Key / X-CSRF-Token 等）
      python main.py --lang cn --phase probe \
        --target-url https://internal-app/api/v1/query \
        --target-api-format raw \
        --target-extra-headers '{"X-API-Key":"sk-secret","X-CSRF-Token":"csrf-xyz"}' \
        --target-no-ssl

  [5] GET 信息收集/探测（无 body，prompt 拼接到 URL query）
      python main.py --lang cn --phase probe \
        --target-url http://192.168.1.100/api/info \
        --target-api-format raw \
        --target-http-method GET \
        --target-cookie "alimail_device_id=..."

  [6] JWT Bearer Token 认证
      python main.py --lang cn --phase probe \
        --target-url https://app/api/chat \
        --target-api-format raw \
        --target-jwt "eyJhbGciOi..."

  [7] form-urlencoded POST body + Cookie 认证
      python main.py --lang cn --phase probe \
        --target-url http://target/api/chat \
        --target-api-format raw \
        --target-content-type application/x-www-form-urlencoded \
        --target-cookie "JSESSIONID=abc123"

===============================================================================
"""
import asyncio
import os
import sys
import configparser
import random
import json
from typing import Optional
from urllib.parse import urlencode

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from dotenv import load_dotenv
from rich.console import Console
from rich.panel import Panel

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from pyrit.prompt_target import OpenAIChatTarget, PromptTarget
from pyrit.models import MessagePiece
from pyrit.models.messages.message import Message

console = Console()

# ================= 0. .env 配置加载器 & 自定义 HTTP Target =================

def load_env_config(env_path: str = ".env") -> tuple[dict, dict]:
    """
    加载 .env 配置文件，返回攻击者配置和评分器配置。

    每个平台节统一使用 CHAT_MODEL + SCORER_MODEL 双模型键:

    用法 1 — 同平台不同模型（评分器用更强模型）:
        PLATFORM_SELECTOR=ZHIPU
        [ZHIPU]
        CHAT_MODEL=GLM-4.7-Flash          ← 攻击者模型
        SCORER_MODEL=GLM-5.2              ← 评分器模型（更强）

    用法 2 — 评分器使用不同平台:
        PLATFORM_SELECTOR=OLLAMA
        SCORER_PLATFORM_SELECTOR=ZHIPU
        [OLLAMA]
        CHAT_MODEL=tinyllama              ← 攻击者模型
        SCORER_MODEL=qwen3:1.8b           ← 评分器模型
        [ZHIPU]
        SCORER_MODEL=GLM-5.2              ← 评分器模型

    用法 3 — 只配置评分器（攻击自定义 API --target-url 时）:
        SCORER_PLATFORM_SELECTOR=ZHIPU
        [ZHIPU]
        SCORER_MODEL=GLM-5.2              ← 仅需评分器，忽略 CHAT_MODEL

    返回: (attacker_config, scorer_config)
    """
    if not os.path.exists(env_path):
        console.print(f"[yellow]⚠️ .env 文件未找到 ({env_path})，使用 PyRIT 默认环境变量[/yellow]")
        return {}, {}

    # Step 1: 使用 python-dotenv 加载平铺 KEY=VALUE 变量到 os.environ
    load_dotenv(env_path, override=False)

    # Step 2: 从 os.environ 读取顶层通用配置
    platform = os.getenv("PLATFORM_SELECTOR", "")
    scorer_platform_selector = os.getenv("SCORER_PLATFORM_SELECTOR", "")
    temperature = float(os.getenv("TEMPERATURE", "0.7"))
    max_tokens = int(os.getenv("MAX_TOKENS", "4096"))
    timeout = int(os.getenv("REQUEST_TIMEOUT", "60"))

    # Step 3: 使用 configparser 读取 [SECTION] 专属配置
    config = configparser.ConfigParser()
    config.optionxform = lambda option: option  # 保留大小写
    with open(env_path, "r", encoding="utf-8") as f:
        config_string = "[DEFAULT]\n" + f.read()
    config.read_string(config_string)

    def _clean_value(raw: str) -> str:
        """清洗配置值：去除内联注释（# 及之后内容）和首尾空白。"""
        if not raw:
            return ""
        # 定位第一个不被引号包裹的 # 作为注释起始
        # configparser 会把多字值原样保留，需要手动剥离行内注释
        comment_idx = raw.find("#")
        if comment_idx >= 0:
            raw = raw[:comment_idx]
        # 也处理中文箭头 ← 等引导的注释（可选）
        for sep in ("←", "←"):
            idx = raw.find(sep)
            if idx >= 0:
                raw = raw[:idx]
        return raw.strip()

    def _build_config(section_name: str, model_key: str = "CHAT_MODEL") -> dict:
        """从 config section 构建配置字典。

        Args:
            section_name: 平台节名
            model_key: 模型键名（默认 CHAT_MODEL 用于攻击者，SCORER_MODEL 用于评分器）
        """
        if not section_name or section_name not in config.sections():
            return {}
        s = config[section_name]
        model = _clean_value(s.get(model_key, ""))

        # 密钥兼容: 优先 OPENAI_CHAT_KEY，回退到平台专属密钥名
        api_key = s.get("OPENAI_CHAT_KEY", "")
        if not api_key:
            ALT_KEY_MAP = {
                "ANTHROPIC": "ANTHROPIC_API_KEY",
                "GOOGLE_GEMINI": "GEMINI_API_KEY",
                "COHERE": "COHERE_API_KEY",
                "VOYAGE": "VOYAGE_API_KEY",
                "AWS_BEDROCK": "BEDROCK_ACCESS_KEY",
            }
            api_key = s.get(ALT_KEY_MAP.get(section_name, ""), "")

        # api_format 自动检测: Gemini/Claude/Cohere 使用非 OpenAI 格式
        API_FORMAT_MAP = {
            "GOOGLE_GEMINI": "gemini",
            "ANTHROPIC": "claude",
        }
        api_format = API_FORMAT_MAP.get(section_name, "openai")

        return {
            "platform": section_name,
            "endpoint": s.get("OPENAI_CHAT_ENDPOINT", ""),
            "model": model,
            "api_key": api_key,
            "api_format": api_format,
            "temperature": temperature,
            "max_tokens": max_tokens,
            "timeout": timeout,
        }

    # ── 攻击者配置（始终从节的 CHAT_MODEL 读取） ──
    attacker_config = {}
    if platform and platform in config.sections():
        attacker_config = _build_config(platform, model_key="CHAT_MODEL")
        if attacker_config.get("model"):
            console.print(f"[green]✅ 攻击者 [{platform}] {attacker_config['model']} @ {attacker_config['endpoint']}[/green]")
        else:
            console.print(f"[yellow]⚠️ [{platform}] 未设置 CHAT_MODEL[/yellow]")
    elif platform:
        console.print(f"[yellow]⚠️ PLATFORM_SELECTOR={platform} 但对应节未找到[/yellow]")

    # ── 评分器配置（始终从 SCORER_MODEL 读取，支持独立平台） ──
    scorer_config = {}
    scorer_section_name = scorer_platform_selector or platform

    if scorer_section_name and scorer_section_name in config.sections():
        scorer_config = _build_config(scorer_section_name, model_key="SCORER_MODEL")
        if scorer_config.get("model"):
            label = "独立平台" if scorer_platform_selector else "同平台"
            console.print(f"[blue]🔍 评分器 [{scorer_section_name}] ({label}) {scorer_config['model']}[/blue]")
        else:
            # SCORER_MODEL 未设置 → 回退到 CHAT_MODEL（向后兼容）
            fallback = _build_config(scorer_section_name, model_key="CHAT_MODEL")
            if fallback.get("model"):
                scorer_config = fallback
                console.print(f"[blue]🔍 评分器 [{scorer_section_name}] (回退 CHAT_MODEL) {scorer_config['model']}[/blue]")
            else:
                console.print(f"[yellow]⚠️ [{scorer_section_name}] 未设置 SCORER_MODEL 也未设置 CHAT_MODEL[/yellow]")
    elif scorer_section_name:
        console.print(f"[yellow]⚠️ SCORER 平台 {scorer_section_name} 对应节未找到[/yellow]")

    return attacker_config, scorer_config


class CustomHttpChatTarget(PromptTarget):
    """
    自定义 HTTP Chat Target — 基于 requests 库，用于攻击任意 Chat API。

    适用场景:
    - 内网自部署 LLM 应用（HTTP/HTTPS）
    - 自签证书的 HTTPS 端点
    - 需要 Cookie / Session / Token 等 Web 认证的应用
    - 非标准请求/响应格式的 Chat API

    认证方式:
    1. api_key → Bearer (openai) / x-api-key (claude) / URL param (gemini)
    2. extra_headers → 任意自定义头 (Cookie, X-API-Key 等)
    3. verify_ssl → HTTPS 证书校验开关
    """

    _BROWSER_HEADERS: dict = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/131.0.0.0 Safari/537.36"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "Priority": "u=0, i",
    }
    
    def __init__(
        self,
        endpoint: str,
        api_key: str = "",
        model: str = "default",
        temperature: float = 0.9,
        max_tokens: int = 4096,
        timeout: int = 60,
        verify_ssl: bool = False,
        extra_headers: Optional[dict] = None,
        api_format: str = "openai",
        content_type: str = "application/json",
        http_method: str = "POST",
        jwt_token: str = "",
    ):
        """
        Args:
            endpoint: 目标 Chat API URL
            api_key: API Key（自动转为 Bearer / x-api-key 或 Gemini URL param）
            model: 模型名称
            temperature: 采样温度
            max_tokens: 最大输出 token
            timeout: 请求超时（秒）
            verify_ssl: HTTPS 证书校验（内网自签证书设为 False）
            extra_headers: 额外的 HTTP 请求头（覆盖默认浏览器头）
            api_format: API 格式: "openai"(默认) / "gemini" / "claude" / "raw"
            content_type: POST Content-Type: json / form-urlencoded / text
            http_method: HTTP 方法: POST(默认, Chat API) / GET(信息收集/探测)
            jwt_token: JWT Token — 快捷方式，自动转为 Authorization: Bearer <jwt>
                       若同时设置 jwt_token 和 api_key，jwt_token 优先
        """
        super().__init__()
        self._endpoint = endpoint.rstrip("/")
        self._api_key = api_key
        self._model = model
        self._temperature = temperature
        self._max_tokens = max_tokens
        self._timeout = timeout
        self._extra_headers = extra_headers or {}
        self._api_format = api_format
        self._content_type = self._extra_headers.get("Content-Type", content_type)
        self._http_method = http_method.upper()
        self._jwt_token = jwt_token
        # SSL: requests 直接传 bool, HTTP 时强制 False
        self._verify_ssl = False if endpoint.lower().startswith("http://") else verify_ssl
        # requests Session (带重试) — 线程安全，可复用
        self._session = self._build_session()
    
    def _build_session(self) -> requests.Session:
        """构建带重试策略的 requests.Session。"""
        s = requests.Session()
        retry_strategy = Retry(
            total=3,
            backoff_factor=1.0,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=frozenset({"GET", "POST", "PUT", "DELETE", "PATCH"}),
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        s.mount("https://", adapter)
        s.mount("http://", adapter)
        return s
    
    # ── Payload 构建（保持原有逻辑，不变） ──

    def _build_request_payload(self, prompt: str, conversation_id: str = "") -> dict:
        if self._api_format == "gemini":
            return self._build_gemini_payload(prompt)
        elif self._api_format == "claude":
            return self._build_claude_payload(prompt)
        elif self._api_format == "raw":
            return self._build_raw_payload(prompt, conversation_id)
        else:
            return self._build_openai_payload(prompt)

    def _build_openai_payload(self, prompt: str) -> dict:
        return {
            "model": self._model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": self._temperature,
            "max_tokens": self._max_tokens,
        }

    def _build_gemini_payload(self, prompt: str) -> dict:
        return {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {
                "temperature": self._temperature,
                "maxOutputTokens": self._max_tokens,
            },
        }

    def _build_claude_payload(self, prompt: str) -> dict:
        return {
            "model": self._model,
            "max_tokens": self._max_tokens,
            "messages": [{"role": "user", "content": prompt}],
        }

    def _build_raw_payload(self, prompt: str, conversation_id: str = "") -> dict:
        """通用 Chat API payload — 兼容常见 Web 应用格式:
        {"message": prompt, "conversation_id": cid}
        也回退支持 {"prompt": prompt}（通过 extra_headers 中的 X-Payload-Format 控制）"""
        if self._extra_headers.get("X-Payload-Format") == "prompt":
            return {"prompt": prompt}
        return {"message": prompt, "conversation_id": conversation_id or ""}

    # ── Headers 组装 & POST body 编码 ──

    def _build_headers(self) -> dict:
        """组装请求头: 默认浏览器头 ⊂ extra_headers ⊂ 认证头（JWT 优先于 api_key）。"""
        headers = dict(self._BROWSER_HEADERS)
        headers.update(self._extra_headers)
        if "Content-Type" not in headers:
            headers["Content-Type"] = self._content_type
        # JWT token 优先覆盖 api_key（两者都对 non-gemini/claude 格式追加 Bearer）
        effective_key = self._jwt_token or self._api_key
        if effective_key:
            if self._api_format == "claude":
                headers["x-api-key"] = effective_key
                headers["anthropic-version"] = "2023-06-01"
            elif self._api_format != "gemini":
                headers["Authorization"] = f"Bearer {effective_key}"
        return headers

    def _encode_body(self, payload: dict, headers: dict) -> tuple:
        """根据 Content-Type 编码 POST body，返回 (body_kwargs, data_or_json)。
        
        requests 库原生支持 json= / data= 参数选择:
        - application/json             → json=payload (自动序列化)
        - application/x-www-form-urlencoded → data=urlencode字符串
        - 其他                          → data=json字符串
        """
        ct = headers.get("Content-Type", self._content_type)
        if "json" in ct:
            return ("json", payload)
        elif "form" in ct or "urlencoded" in ct:
            flat = {}
            for k, v in payload.items():
                flat[k] = json.dumps(v, ensure_ascii=False) if isinstance(v, (dict, list)) else str(v)
            return ("data", urlencode(flat))
        else:
            return ("data", json.dumps(payload, ensure_ascii=False))

    @staticmethod
    def _safe_read_response(resp: requests.Response):
        """安全读取响应: 优先 JSON，回退文本。"""
        try:
            return resp.json()
        except (ValueError, json.JSONDecodeError):
            return resp.text

    # ── 响应解析 ──

    def _parse_response(self, response_data) -> str:
        """从 HTTP 响应中提取文本。纯文本直接返回，dict 按格式解析。"""
        if isinstance(response_data, str):
            return response_data
        if self._api_format == "gemini":
            return self._parse_gemini_response(response_data)
        elif self._api_format == "claude":
            return self._parse_claude_response(response_data)
        elif self._api_format == "raw":
            return json.dumps(response_data, ensure_ascii=False)
        else:
            return self._parse_openai_response(response_data)

    def _parse_openai_response(self, response_data: dict) -> str:
        try:
            return response_data["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError):
            pass
        for key in ("response", "content", "text"):
            if key in response_data:
                return str(response_data[key])
        if "data" in response_data and isinstance(response_data["data"], str):
            return response_data["data"]
        return json.dumps(response_data, ensure_ascii=False)

    def _parse_gemini_response(self, response_data: dict) -> str:
        try:
            return response_data["candidates"][0]["content"]["parts"][0]["text"]
        except (KeyError, IndexError, TypeError):
            return self._parse_openai_response(response_data)

    def _parse_claude_response(self, response_data: dict) -> str:
        try:
            content = response_data["content"]
            if isinstance(content, list) and len(content) > 0:
                return content[0].get("text", "")
            return str(content)
        except (KeyError, IndexError, TypeError):
            return self._parse_openai_response(response_data)

    # ── 核心: 同步 HTTP 请求 → 线程池桥接为 async ──

    def _request_sync(self, target_url: str, headers: dict, body_mode: str = "", body_content=None) -> requests.Response:
        """同步 HTTP 请求（在线程池中运行），支持 GET / POST / PUT / DELETE。"""
        kwargs = {"headers": headers, "timeout": self._timeout, "verify": self._verify_ssl}
        if self._http_method in ("POST", "PUT", "PATCH") and body_content is not None:
            if body_mode == "json":
                kwargs["json"] = body_content
            else:
                kwargs["data"] = body_content
        return self._session.request(self._http_method, target_url, **kwargs)

    async def send_prompt_async(self, *, message: Message) -> list[Message]:
        return await self._send_prompt_to_target_async(normalized_conversation=[message])

    async def _send_prompt_to_target_async(self, *, normalized_conversation: list[Message]) -> list[Message]:
        """PyRIT 0.14.0 abstract method — 核心 HTTP 发送逻辑。
        同步 requests 调用通过 asyncio.to_thread 桥接到异步世界。
        支持 POST (Chat API) / GET (信息收集/探测)。"""
        last_msg = normalized_conversation[-1] if normalized_conversation else None
        if not last_msg or not last_msg.message_pieces:
            return []

        user_text = last_msg.message_pieces[-1].converted_value or last_msg.message_pieces[-1].original_value
        conversation_id = last_msg.message_pieces[0].conversation_id if last_msg.message_pieces else ""

        headers = self._build_headers()

        # GET 请求: 无 body，prompt 拼接为 query param；POST 请求: 构建 body
        target_url = self._endpoint
        body_mode, body_content = "", None
        if self._http_method == "GET":
            # prompt 追加为 URL query 参数（考试信息收集场景）
            separator = "&" if "?" in target_url else "?"
            target_url = f"{target_url}{separator}prompt={urlencode({'q': user_text})[2:]}"
        else:
            payload = self._build_request_payload(user_text, conversation_id)
            body_mode, body_content = self._encode_body(payload, headers)
            # Gemini: API Key 追加为 URL query 参数
            if self._api_format == "gemini" and self._api_key:
                separator = "&" if "?" in target_url else "?"
                target_url = f"{target_url}{separator}key={self._api_key}"

        max_retries = 3
        last_error = None

        for attempt in range(max_retries):
            try:
                resp = await asyncio.to_thread(
                    self._request_sync, target_url, headers, body_mode, body_content
                )
                response_data = self._safe_read_response(resp)

                if resp.status_code >= 400:
                    error_detail = json.dumps(response_data, ensure_ascii=False)[:300] if isinstance(response_data, dict) else str(response_data)[:300]
                    raise requests.HTTPError(f"HTTP {resp.status_code}: {error_detail}", response=resp)

                response_text = self._parse_response(response_data)

                resp_piece = MessagePiece(
                    role="assistant",
                    original_value=response_text,
                    converted_value=response_text,
                    prompt_target_identifier=self.get_identifier(),
                )
                return [Message(message_pieces=[resp_piece])]

            except (requests.RequestException, OSError) as e:
                last_error = e
                if attempt < max_retries - 1:
                    wait_time = (2 ** attempt) + random.uniform(0, 1.5)
                    console.print(f"[yellow]⚠️ 目标 [{self._endpoint}] 连接失败，{wait_time:.1f}s 后重试 ({attempt+1}/{max_retries})...[/yellow]")
                    await asyncio.sleep(wait_time)

        raise ConnectionError(f"无法连接目标 [{self._endpoint}]，已重试 {max_retries} 次。最后错误: {last_error}")

    async def close(self):
        """清理 HTTP session（requests 不需要 await，但保留 async 签名兼容调用方）。"""
        if self._session:
            self._session.close()
            self._session = None

    def get_identifier(self) -> str:
        return f"CustomHttpChatTarget::{self._endpoint}"


def create_scorer_target(scorer_config: dict) -> OpenAIChatTarget:
    """
    使用独立评分器配置创建评分器用 LLM Target。
    支持与攻击者不同的模型/平台（解决低能力模型无法胜任 Judge 的问题）。

    scorer_config 优先级:
    1. SCORER_PLATFORM_SELECTOR 指定的独立平台
    2. 同平台 SCORER_MODEL 覆盖模型
    3. 完全复用攻击者配置
    4. 回退到 PyRIT 默认环境变量
    """
    if scorer_config and scorer_config.get("endpoint") and scorer_config.get("api_key"):
        os.environ["OPENAI_CHAT_ENDPOINT"] = scorer_config["endpoint"]
        os.environ["OPENAI_CHAT_KEY"] = scorer_config["api_key"]
        os.environ["OPENAI_CHAT_MODEL"] = scorer_config.get("model", "")
        console.print(f"[blue]🔍 评分器: [{scorer_config['platform']}] {scorer_config['model']}[/blue]")
    else:
        console.print("[yellow]⚠️ 评分器使用 PyRIT 默认环境变量[/yellow]")
    
    return OpenAIChatTarget(temperature=0)


def create_attack_target(custom_target_url: str = "", env_config: dict = None, api_format: str = "openai",
                         verify_ssl: bool = False, extra_headers: Optional[dict] = None,
                         content_type: str = "application/json", http_method: str = "POST",
                         jwt_token: str = "") -> PromptTarget:
    """
    创建攻击目标 Target（即 PROBE/单轮/Crescendo 所有攻击流量的投递对象）。

    三种模式：
    ┌──────────────────────────────────────────────────────────────────┐
    │ 模式 A: 未指定 --target-url → 探测 .env 中的 LLM API 自身（OpenAI 兼容）│
    │   目标 = OpenAIChatTarget(temperature=0.9)                       │
    │   支持: OPENAI, ZHIPU, QWEN, DEEPSEEK, OLLAMA, MISTRAL 等        │
    ├──────────────────────────────────────────────────────────────────┤
    │ 模式 B: 指定 --target-url + api_format → 探测自定义 Chat API     │
    │   支持: "openai"(默认) / "gemini" / "claude" / "raw"(万能回退)    │
    │   Gemini: 自动追加 API Key 到 URL query param                     │
    │   Claude: 自动使用 x-api-key + anthropic-version 头              │
    │   raw: {"prompt": text} → 返回完整 JSON 文本 — 适配任意非标准 API │
    ├──────────────────────────────────────────────────────────────────┤
    │ 模式 C: .env 配置 Gemini/Claude → 自动选择 CustomHttpChatTarget  │
    │   .env [GOOGLE_GEMINI] / [ANTHROPIC] → 自动构造端点 + 格式      │
    └──────────────────────────────────────────────────────────────────┘

    无论哪种模式，评分器 (Judge) 始终使用 .env 中配置的 LLM API 进行判定。
    """
    # ── 模式 B: --target-url 指定自定义 API ──
    if custom_target_url:
        af = api_format or (env_config.get("api_format", "openai") if env_config else "openai")
        # 协议检测: HTTP 自动跳过 SSL (verify_ssl=False 无意义)
        is_http = custom_target_url.lower().startswith("http://")
        effective_verify_ssl = False if is_http else verify_ssl
        proto = "HTTP" if is_http else "HTTPS"
        ssl_info = "N/A" if is_http else ("verify" if effective_verify_ssl else "skip")
        console.print(f"[bold magenta]🎯 攻击目标: {custom_target_url} ({af}, {proto}, SSL={ssl_info})[/bold magenta]")
        return CustomHttpChatTarget(
            endpoint=custom_target_url,
            api_key=env_config.get("api_key", "") if env_config else "",
            model=env_config.get("model", "default") if env_config else "default",
            temperature=0.9,
            timeout=env_config.get("timeout", 60) if env_config else 60,
            verify_ssl=effective_verify_ssl,
            api_format=af,
            extra_headers=extra_headers,
            content_type=content_type,
            http_method=http_method,
            jwt_token=jwt_token,
        )

    if env_config and env_config.get("api_key"):
        af = env_config.get("api_format", "openai")
        endpoint = env_config.get("endpoint", "")
        model = env_config.get("model", "")

        # ── 模式 C: .env 非 OpenAI 格式（Gemini / Claude） ──
        if af in ("gemini", "claude"):
            if not endpoint:
                # 自动构造非 OpenAI 格式端点
                if af == "gemini":
                    endpoint = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
                elif af == "claude":
                    endpoint = "https://api.anthropic.com/v1/messages"
            console.print(f"[bold magenta]🎯 攻击目标: [{env_config['platform']}] {model} ({af})[/bold magenta]")
            return CustomHttpChatTarget(
                endpoint=endpoint,
                api_key=env_config["api_key"],
                model=model,
                temperature=0.9,
                timeout=env_config.get("timeout", 60),
                verify_ssl=True,
                api_format=af,
            )

        # ── 模式 A: .env OpenAI 兼容格式 ──
        os.environ["OPENAI_CHAT_ENDPOINT"] = endpoint
        os.environ["OPENAI_CHAT_KEY"] = env_config["api_key"]
        os.environ["OPENAI_CHAT_MODEL"] = model
        console.print(f"[bold cyan]🎯 攻击目标: [{env_config['platform']}] {model}[/bold cyan]")
    else:
        console.print("[bold cyan]🎯 攻击目标: PyRIT 默认环境变量[/bold cyan]")
    
    return OpenAIChatTarget(temperature=0.9)
