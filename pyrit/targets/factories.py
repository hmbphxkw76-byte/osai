"""
===============================================================================
OffSec AI-300 — Target 工厂函数 (PyRIT 0.14.0 原生接口 + 全量 Target 支持)
===============================================================================
包含:
- create_scorer_target(): 评分器 Target 工厂
- create_attack_target(): 攻击 Target 工厂（4 种模式）
- 🆕 create_round_robin_target(): 多目标轮询 Target（负载均衡 + A/B 测试）
- 🆕 create_playwright_target(): 浏览器自动化 Target（Web Chat UI 红队）

PyRIT 最佳实践:
  ✅ 通过 OpenAIChatTarget(endpoint=..., api_key=..., model_name=...) 构造参数直接传入
  ✅ 不修改 os.environ（避免进程级全局状态污染，线程安全）
  ✅ 与 CentralMemory 单例模式兼容（不影响其他 Target 实例）
  ✅ OpenAIChatTarget 构造参数沿 MRO 链传递:
       OpenAIChatTarget(**kwargs) → OpenAITarget(endpoint=, api_key=, model_name=) → PromptTarget
===============================================================================
"""
from typing import Optional

from pyrit.prompt_target import OpenAIChatTarget, PromptTarget
from rich.console import Console

from targets.http_target import CustomHttpChatTarget
from utils import DEFAULT_MODEL_NAME

console = Console()


def create_scorer_target(scorer_config: dict) -> OpenAIChatTarget:
    """
    使用独立评分器配置创建评分器用 LLM Target（PyRIT 原生构造参数）。
    支持与攻击者不同的模型/平台（解决低能力模型无法胜任 Judge 的问题）。

    PyRIT 0.14.0 方式: 通过 OpenAIChatTarget(endpoint=..., api_key=..., model_name=...)
    直接传入配置，替代旧版 os.environ 全局污染。

    scorer_config 优先级:
    1. SCORER_PLATFORM_SELECTOR 指定的独立平台
    2. 同平台 SCORER_MODEL 覆盖模型
    3. 完全复用攻击者配置
    4. 回退到 PyRIT 默认环境变量
    """
    if scorer_config and scorer_config.get("endpoint") and scorer_config.get("api_key"):
        console.print(f"[blue]🔍 评分器: [{scorer_config['platform']}] {scorer_config['model']}[/blue]")
        return OpenAIChatTarget(
            endpoint=scorer_config["endpoint"],
            api_key=scorer_config["api_key"],
            model_name=scorer_config.get("model", ""),
            temperature=0,
        )
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
            model=env_config.get("model", DEFAULT_MODEL_NAME) if env_config else DEFAULT_MODEL_NAME,
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
        console.print(f"[bold cyan]🎯 攻击目标: [{env_config['platform']}] {model}[/bold cyan]")
        return OpenAIChatTarget(
            endpoint=endpoint,
            api_key=env_config["api_key"],
            model_name=model,
            temperature=0.9,
        )
    else:
        console.print("[bold cyan]🎯 攻击目标: PyRIT 默认环境变量[/bold cyan]")
    
    return OpenAIChatTarget(temperature=0.9)



