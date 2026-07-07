"""
===============================================================================
OffSec AI-300 — .env 配置加载器
===============================================================================
设计决策: 为何自定义配置解析器而非仅使用 PyRIT 环境变量?
  PyRIT 原生配置系统基于 os.environ (AZURE_OPENAI_ENDPOINT / OPENAI_CHAT_ENDPOINT
  等)，适合 Azure/OpenAI 生态。但 AI-300 考试需要同时管理:
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
import configparser

from dotenv import load_dotenv
from rich.console import Console

console = Console()


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
