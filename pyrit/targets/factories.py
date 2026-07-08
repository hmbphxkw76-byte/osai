"""
===============================================================================
PyRIT Red Team — Target 工厂函数 (PyRIT 0.14.0 原生接口 + 全量 Target 支持)
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
from targets.openai_sdk_target import OpenAICompatibleTarget
from targets.gemini_target import GeminiTarget
from targets.claude_target import ClaudeTarget
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
    │   openai/ollama → OpenAICompatibleTarget (openai SDK)             │
    │   gemini         → GeminiTarget (google-genai SDK)                │
    │   claude         → ClaudeTarget (anthropic SDK)                   │
    │   raw            → CustomHttpChatTarget (仅非标准 API 兜底)        │
    ├──────────────────────────────────────────────────────────────────┤
    │ 模式 C: .env 配置 Gemini/Claude → 自动选择对应 SDK Target       │
    │   .env [GOOGLE_GEMINI] / [ANTHROPIC] → GeminiTarget / ClaudeTarget │
    └──────────────────────────────────────────────────────────────────┘

    无论哪种模式，评分器 (Judge) 始终使用 .env 中配置的 LLM API 进行判定。
    """
    # ── 模式 B: --target-url 指定自定义 API ──
    if custom_target_url:
        af = api_format or (env_config.get("api_format", "openai") if env_config else "openai")
        is_http = custom_target_url.lower().startswith("http://")
        effective_verify_ssl = False if is_http else verify_ssl
        proto = "HTTP" if is_http else "HTTPS"
        ssl_info = "N/A" if is_http else ("verify" if effective_verify_ssl else "skip")
        model = env_config.get("model", DEFAULT_MODEL_NAME) if env_config else DEFAULT_MODEL_NAME
        api_key_val = env_config.get("api_key", "") if env_config else ""

        # OpenAI 兼容格式 → 使用 OpenAI SDK 驱动的稳健 Target
        if af in ("openai", "ollama"):
            base_url = _to_openai_base_url(custom_target_url, af)
            console.print(
                f"[bold magenta]🎯 攻击目标 (OpenAI SDK): {base_url} "
                f"({af}, {proto}, SSL={ssl_info})[/bold magenta]"
            )
            return OpenAICompatibleTarget(
                base_url=base_url,
                api_key=api_key_val,
                model=model,
                temperature=0.9,
                timeout=env_config.get("timeout", 60) if env_config else 60,
                verify_ssl=effective_verify_ssl,
                extra_headers=extra_headers,
            )

        # Gemini → Google Generative AI SDK
        if af == "gemini":
            console.print(
                f"[bold magenta]🎯 攻击目标 (Gemini SDK): {model} "
                f"({proto}, SSL={ssl_info})[/bold magenta]"
            )
            return GeminiTarget(
                api_key=api_key_val,
                model=model,
                temperature=0.9,
                timeout=env_config.get("timeout", 60) if env_config else 60,
            )

        # Claude → Anthropic SDK
        if af == "claude":
            console.print(
                f"[bold magenta]🎯 攻击目标 (Claude SDK): {model} "
                f"({proto}, SSL={ssl_info})[/bold magenta]"
            )
            return ClaudeTarget(
                api_key=api_key_val,
                model=model,
                temperature=0.9,
                timeout=env_config.get("timeout", 60) if env_config else 60,
                verify_ssl=effective_verify_ssl,
            )

        # raw → 保留 CustomHttpChatTarget（仅非标准 API 兜底）
        console.print(
            f"[bold magenta]🎯 攻击目标 (HTTP): {custom_target_url} "
            f"({af}, {proto}, SSL={ssl_info})[/bold magenta]"
        )
        return CustomHttpChatTarget(
            endpoint=custom_target_url,
            api_key=api_key_val,
            model=model,
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
        if af == "gemini":
            console.print(f"[bold magenta]🎯 攻击目标 (Gemini SDK): [{env_config['platform']}] {model}[/bold magenta]")
            return GeminiTarget(
                api_key=env_config["api_key"],
                model=model,
                temperature=0.9,
                timeout=env_config.get("timeout", 60),
            )

        if af == "claude":
            console.print(f"[bold magenta]🎯 攻击目标 (Claude SDK): [{env_config['platform']}] {model}[/bold magenta]")
            return ClaudeTarget(
                api_key=env_config["api_key"],
                model=model,
                temperature=0.9,
                timeout=env_config.get("timeout", 60),
                verify_ssl=True,
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


# ── 内部辅助 ──────────────────────────────────────────────────────────────────

def _to_openai_base_url(raw_url: str, api_format: str) -> str:
    """将用户输入的 URL 标准化为 OpenAI 兼容 base_url（供 AsyncOpenAI 使用）。

    OpenAI SDK 期望 base_url 在构造时指定，后续 chat.completions.create()
    会自动拼接 /chat/completions 路径。因此 base_url 应为 /v1 级别。

    转换规则:
      openai:  https://api.openai.com            → https://api.openai.com/v1
      ollama:  http://host:11434                 → http://host:11434/v1
               http://host:11434/api/chat        → http://host:11434/v1
               http://host:11434/v1              → http://host:11434/v1 (不变)
    """
    from urllib.parse import urlparse, urlunparse
    import re

    url = raw_url.rstrip("/")
    parsed = urlparse(url)

    if api_format == "ollama":
        # Ollama: 提取 host:port，拼接 /v1
        base = f"{parsed.scheme}://{parsed.netloc}"
        return f"{base}/v1"

    # openai / 其他: base_url 应指向 /v1
    if not url.endswith("/v1"):
        # 去掉已有的 /chat/completions 后缀
        url = re.sub(r'/(chat/completions|completions)$', '', url)
        if not url.endswith("/v1"):
            url = url.rstrip("/") + "/v1"
    return url



