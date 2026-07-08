"""
===============================================================================
PyRIT Red Team — .env 配置加载器
===============================================================================
设计决策: 为何自定义配置解析器而非仅使用 PyRIT 环境变量?
  PyRIT 原生配置系统基于 os.environ (AZURE_OPENAI_ENDPOINT / OPENAI_CHAT_ENDPOINT
  等)，适合 Azure/OpenAI 生态。但 红队渗透需要同时管理:
  - 多平台切换: ZHIPU / QWEN / DEEPSEEK / OLLAMA / MISTRAL / ANTHROPIC / GEMINI
  - 双模型键: CHAT_MODEL (攻击者) + SCORER_MODEL (评分器)
  - 跨平台评分器: 攻击走 OLLAMA 本地模型，评分走 ZHIPU 云模型
  这些需求远超 PyRIT 原生 env var 设置的能力，故使用 configparser + dotenv
  构建多节配置加载器。

load_env_config(): 加载 .env 配置文件，解析 CHAT_MODEL + SCORER_MODEL 双模型键。
支持攻击者与评分器分属不同平台、不同模型的场景。
===============================================================================
"""
import os
import sys
import io
import configparser

from dotenv import load_dotenv
from rich.console import Console

console = Console()

_SHARED_PATH = "configs/shared.env"


def _read_shared_env() -> str:
    """读取共享凭证文件内容，供所有配置加载器复用。"""
    if os.path.exists(_SHARED_PATH):
        with open(_SHARED_PATH, "r", encoding="utf-8") as f:
            return f.read()
    return ""


def load_env_config(env_path: str = ".env", platforms_path: str = "configs/platforms.env") -> tuple[dict, dict]:
    """
    加载配置文件，返回攻击者配置和评分器配置。

    配置拆分:
      .env                  → 通用参数 + PLATFORM_SELECTOR (dotenv 加载)
      configs/platforms.env → DEFAULT 变量 + 预设节 (configparser 读取)

    用法:
      platforms.env 定义 DEFAULT 变量和预设节:

        BASE_URL  = https://api.siliconflow.cn         ← 攻击默认值
        BASE_API  = sk-xxx
        BASE_MODEL = Qwen/Qwen3-8B

        SCORE_BASE_URL = https://open.bigmodel.cn/api/paas/v4  ← 评分默认值
        SCORE_BASE_API  = xxx
        SCORE_BASE_MODEL = GLM-5.1

      ── 三种预设节（.env 用 PLATFORM_SELECTOR 选择）──

        [ATTACK_with_SCORE]    ← 攻击 + 评分
        [Only_SCORE]           ← 只要评分（--target-url 模式）
        [ONLY_ATTACK]          ← 只要攻击

      每个节内包含对应的 ATTACK_URL/API/MODEL 和/或 SCORE_URL/API/MODEL。

      .env 设置:
        PLATFORM_SELECTOR=ATTACK_with_SCORE

    优先级: PLATFORM_SELECTOR 指向的节 > DEFAULT 平铺变量

    Args:
        env_path: .env 文件路径
        platforms_path: 平台配置文件路径

    返回: (attacker_config, scorer_config)
    """
    if not os.path.exists(env_path):
        console.print(f"[yellow]⚠️ .env 文件未找到 ({env_path})，使用 PyRIT 默认环境变量[/yellow]")
        return {}, {}

    # Step 1: 使用 python-dotenv 加载通用参数到 os.environ
    load_dotenv(env_path, override=False)

    # Step 2: 从 os.environ 读取通用配置 + 选择器
    temperature = float(os.getenv("TEMPERATURE", "0.7"))
    max_tokens = int(os.getenv("MAX_TOKENS", "4096"))
    timeout = int(os.getenv("REQUEST_TIMEOUT", "60"))
    platform_selector = os.getenv("PLATFORM_SELECTOR", "").strip()

    # Step 3: 使用 configparser 读取 platforms.env（前置 shared.env 公共变量）
    if not os.path.exists(platforms_path):
        console.print(f"[yellow]⚠️ 平台配置文件未找到 ({platforms_path})[/yellow]")
        return {}, {}

    # 读取共享凭证
    shared_text = _read_shared_env()

    config = configparser.ConfigParser(inline_comment_prefixes=('#',))
    config.optionxform = lambda option: option  # 保留大小写
    with open(platforms_path, "r", encoding="utf-8") as f:
        raw_text = f.read()
    config_string = "[DEFAULT]\n" + shared_text + "\n" + raw_text
    config.read_file(io.StringIO(config_string))
    default = config["DEFAULT"]

    # 预扫描：记录每个节显式定义了哪些键（排除 DEFAULT 继承）
    _explicit_keys = {}
    current_section = None
    for line in raw_text.split("\n"):
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            current_section = stripped[1:-1]
            _explicit_keys[current_section] = set()
        elif current_section and "=" in stripped and not stripped.startswith("#"):
            key = stripped.split("=", 1)[0].strip()
            _explicit_keys[current_section].add(key)

    # ── 确定数据来源 ──
    section = config[platform_selector] if platform_selector and platform_selector in config else None

    if section:
        console.print(f"[bold cyan]📋 平台模式: {platform_selector}[/bold cyan]")
    else:
        if platform_selector:
            console.print(f"[yellow]⚠️ PLATFORM_SELECTOR={platform_selector} 但节未找到，回退 DEFAULT[/yellow]")
        console.print("[dim]📋 平台模式: DEFAULT（无选择器）[/dim]")

    def _resolve(section_obj, section_name, key, default_key) -> str:
        """从节或 DEFAULT 解析值，支持变量名引用。
        
        逻辑:
        - 有节且节显式包含 key → 取节值，若值匹配 DEFAULT 中的键名则二次解析
        - 有节但节不含 key    → 返回空（Mode 如 Only_SCORE 不含 ATTACK_*）
        - 无节                 → 从 DEFAULT 取 default_key
        """
        if section_obj and section_name:
            explicit = _explicit_keys.get(section_name, set())
            if key in explicit:
                val = section_obj.get(key, "").strip()
                # 节值可能是 DEFAULT 变量名，二次解析
                if val and val in default:
                    return default.get(val, val).strip()
                return val
            return ""
        return default.get(default_key, "").strip()

    # ── 攻击者配置 ──
    attacker_config = {}
    attack_model = _resolve(section, platform_selector, "ATTACK_MODEL", "BASE_MODEL")
    if attack_model:
        attacker_config = {
            "platform": platform_selector or "ATTACK",
            "endpoint": _resolve(section, platform_selector, "ATTACK_URL", "BASE_URL"),
            "model": attack_model,
            "api_key": _resolve(section, platform_selector, "ATTACK_API", "BASE_API"),
            "api_format": "openai",
            "temperature": temperature,
            "max_tokens": max_tokens,
            "timeout": timeout,
        }
        console.print(
            f"[green]✅ 攻击者 {attacker_config['model']} "
            f"@ {attacker_config['endpoint']}[/green]"
        )
    else:
        console.print("[dim]ℹ️ 攻击模型未设置 — 将使用 --target-url 自定义目标模式[/dim]")

    # ── 评分器配置 ──
    scorer_config = {}
    score_model = _resolve(section, platform_selector, "SCORE_MODEL", "SCORE_BASE_MODEL")
    if score_model:
        scorer_config = {
            "platform": platform_selector or "SCORE",
            "endpoint": _resolve(section, platform_selector, "SCORE_URL", "SCORE_BASE_URL"),
            "model": score_model,
            "api_key": _resolve(section, platform_selector, "SCORE_API", "SCORE_BASE_API"),
            "api_format": "openai",
            "temperature": temperature,
            "max_tokens": max_tokens,
            "timeout": timeout,
        }
        console.print(
            f"[blue]🔍 评分器 {scorer_config['model']} "
            f"@ {scorer_config['endpoint']}[/blue]"
        )
    else:
        console.print("[yellow]⚠️ 评分模型未设置[/yellow]")

    return attacker_config, scorer_config


def load_target_preset(targets_path: str = "configs/targets.env") -> dict:
    """从 targets.env 加载目标场景预设。

    读取 .env 中 TARGET_PRESET 选择器，定位到对应的 [TARGET_xxx] 节，
    将节内所有 TARGET_* 键值对解析为 dict 返回。

    配置拆分:
      .env                  → TARGET_PRESET=场景名 (选择器，由 dotenv 加载)
      configs/targets.env   → [TARGET_xxx] 节定义 (configparser 读取)

    支持的预设键映射:
      TARGET_URL            → target_url
      TARGET_API_FORMAT     → target_api_format
      TARGET_API_KEY        → target_api_key
      TARGET_MODEL          → target_model
      TARGET_COOKIE         → target_cookie
      TARGET_JWT            → target_jwt
      TARGET_EXTRA_HEADERS  → target_extra_headers (JSON 字符串)
      TARGET_USER_AGENT     → target_user_agent
      TARGET_CONTENT_TYPE   → target_content_type
      TARGET_HTTP_METHOD    → target_http_method
      TARGET_NO_SSL         → target_no_ssl ("1"/"true" → True; 其他 → 使用 CLI 默认)
      SCENARIO              → scenario (场景行为预设 ID)

    CLI 参数显式指定的值始终覆盖预设值（在 bootstrap 层处理）。

    Args:
        targets_path: 目标场景预设文件路径

    Returns:
        目标配置 dict 或空 dict（未设置 TARGET_PRESET / 节不存在）
    """
    import configparser

    if not os.path.exists(targets_path):
        return {}

    # 使用 configparser 读取节（前置 shared.env 公共变量）
    shared_text = _read_shared_env()
    config = configparser.ConfigParser(inline_comment_prefixes=('#',))
    config.optionxform = lambda option: option  # 保留大小写
    with open(targets_path, "r", encoding="utf-8") as f:
        config_string = "[DEFAULT]\n" + shared_text + "\n" + f.read()
    config.read_file(io.StringIO(config_string))

    # 读取顶层选择器（dotenv 已加载到 os.environ）
    preset_name = os.getenv("TARGET_PRESET", "").strip()
    if not preset_name:
        return {}

    section_name = f"TARGET_{preset_name}"
    if section_name not in config.sections():
        console.print(f"[yellow]⚠️ TARGET_PRESET={preset_name} 但节 [{section_name}] 未找到[/yellow]")
        return {}

    s = config[section_name]

    # 键映射: 节内键 → 返回 dict 键
    KEY_MAP = {
        "TARGET_URL": "target_url",
        "TARGET_API_FORMAT": "target_api_format",
        "TARGET_API_KEY": "target_api_key",
        "TARGET_MODEL": "target_model",
        "TARGET_COOKIE": "target_cookie",
        "TARGET_JWT": "target_jwt",
        "TARGET_EXTRA_HEADERS": "target_extra_headers",
        "TARGET_USER_AGENT": "target_user_agent",
        "TARGET_CONTENT_TYPE": "target_content_type",
        "TARGET_HTTP_METHOD": "target_http_method",
        "TARGET_NO_SSL": "target_no_ssl",
        "SCENARIO": "scenario",
    }

    result = {}
    for raw_key, mapped_key in KEY_MAP.items():
        value = s.get(raw_key, "").strip()
        if value:
            # 特殊处理布尔型
            if raw_key == "TARGET_NO_SSL":
                result[mapped_key] = value.lower() in ("1", "true", "yes", "on")
            else:
                result[mapped_key] = value

    if result:
        console.print(
            f"[bold cyan]🎯 目标场景预设: {preset_name}[/bold cyan] "
            f"[dim](URL: {result.get('target_url', 'N/A')})[/dim]"
        )
        if "scenario" in result:
            console.print(f"[dim]   关联行为预设: --scenario {result['scenario']}[/dim]")

    return result


def load_recon_preset(recons_path: str = "configs/recons.env") -> dict:
    """从 recons.env 加载侦查阶段预设。

    与 load_target_preset 相同的机制，但从独立的 recons.env 文件加载。

    用法:
      .env: RECON_PRESET=MODELS_RECON
      recons.env: [TARGET_MODELS_RECON] 节定义

    Args:
        recons_path: 侦查预设文件路径

    Returns:
        目标配置 dict 或空 dict
    """
    import configparser

    if not os.path.exists(recons_path):
        return {}

    config = configparser.ConfigParser(inline_comment_prefixes=('#',))
    config.optionxform = lambda option: option
    with open(recons_path, "r", encoding="utf-8") as f:
        config_string = "[DEFAULT]\n" + _read_shared_env() + "\n" + f.read()
    config.read_file(io.StringIO(config_string))

    preset_name = os.getenv("RECON_PRESET", "").strip()
    if not preset_name:
        return {}

    section_name = f"TARGET_{preset_name}"
    if section_name not in config.sections():
        console.print(f"[yellow]⚠️ RECON_PRESET={preset_name} 但节 [{section_name}] 未找到[/yellow]")
        return {}

    s = config[section_name]

    KEY_MAP = {
        "TARGET_URL": "target_url",
        "TARGET_API_FORMAT": "target_api_format",
        "TARGET_API_KEY": "target_api_key",
        "TARGET_MODEL": "target_model",
        "TARGET_COOKIE": "target_cookie",
        "TARGET_JWT": "target_jwt",
        "TARGET_EXTRA_HEADERS": "target_extra_headers",
        "TARGET_USER_AGENT": "target_user_agent",
        "TARGET_CONTENT_TYPE": "target_content_type",
        "TARGET_HTTP_METHOD": "target_http_method",
        "TARGET_NO_SSL": "target_no_ssl",
        "SCENARIO": "scenario",
    }

    result = {}
    for raw_key, mapped_key in KEY_MAP.items():
        value = s.get(raw_key, "").strip()
        if value:
            if raw_key == "TARGET_NO_SSL":
                result[mapped_key] = value.lower() in ("1", "true", "yes", "on")
            else:
                result[mapped_key] = value

    if result:
        console.print(
            f"[bold cyan]🔎 侦查预设: {preset_name}[/bold cyan] "
            f"[dim](URL: {result.get('target_url', 'N/A')})[/dim]"
        )
        if "scenario" in result:
            console.print(f"[dim]   关联行为预设: --scenario {result['scenario']}[/dim]")

    return result
