"""模型配置解析工具 — 管理攻击者侧 LLM 提供商配置。

支持从 config/credentials/ 目录加载模型配置：
  - YAML 格式配置文件
  - 按提供商组织：Ollama、LM Studio、OpenAI、Anthropic、Gemini
  - 自动搜索三种路径格式

配置文件存放位置：config/credentials/
示例文件：
  - config/credentials/ollama.yaml
  - config/credentials/lm_studio.yaml
  - config/credentials/openai.yaml
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import yaml

_CONFIG_DIR = Path("config/credentials")


@dataclass
class ModelConfig:
    """模型提供商配置。"""
    provider: str
    name: str
    base_url: str
    api_key: str = ""
    timeout: float = 30.0


def _ensure_config_dir() -> None:
    """确保配置目录存在。"""
    _CONFIG_DIR.mkdir(parents=True, exist_ok=True)


def parse_model_config(raw: str) -> ModelConfig:
    """从原始文本解析模型配置（支持 YAML 格式和 key=value 格式）。

    Args:
        raw: 原始配置文本

    Returns:
        解析后的 ModelConfig

    Raises:
        ValueError: 无法解析配置
    """
    try:
        data = yaml.safe_load(raw)
        if isinstance(data, dict):
            return ModelConfig(
                provider=data.get("provider", ""),
                name=data.get("name", ""),
                base_url=data.get("base_url", ""),
                api_key=data.get("api_key", ""),
                timeout=data.get("timeout", 30.0),
            )
    except yaml.YAMLError:
        pass

    # fallback: key=value 格式
    provider = ""
    name = ""
    base_url = ""
    api_key = ""

    for line in raw.strip().split("\n"):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" in line:
            key, value = line.split("=", 1)
            key = key.strip().lower()
            value = value.strip().strip('"').strip("'")
            if key == "provider":
                provider = value
            elif key == "name":
                name = value
            elif key == "base_url":
                base_url = value
            elif key == "api_key":
                api_key = value

    if provider:
        return ModelConfig(provider=provider, name=name, base_url=base_url, api_key=api_key)
    raise ValueError("无法解析模型配置，请使用 YAML 格式")


def parse_model_config_file(path: str | Path) -> ModelConfig:
    """从文件读取模型配置。

    Args:
        path: 配置文件路径

    Returns:
        解析后的 ModelConfig
    """
    return parse_model_config(Path(path).read_text(encoding="utf-8"))


def load_model_config(provider: str) -> Optional[ModelConfig]:
    """从默认目录加载指定提供商的配置文件。

    搜索顺序：
      1. config/credentials/{provider}.yaml
      2. config/credentials/{provider}.yml
      3. config/credentials/{provider}/default.yaml

    Args:
        provider: 提供商名称（ollama, lm_studio, openai, anthropic, gemini）

    Returns:
        ModelConfig 或 None（未找到）
    """
    _ensure_config_dir()

    paths = [
        _CONFIG_DIR / f"{provider}.yaml",
        _CONFIG_DIR / f"{provider}.yml",
        _CONFIG_DIR / provider / "default.yaml",
    ]

    for p in paths:
        if p.exists():
            return parse_model_config_file(p)

    return None


def list_available_configs() -> list[str]:
    """列出所有可用的模型配置文件。

    Returns:
        配置名称列表（不含扩展名）
    """
    _ensure_config_dir()

    configs = []
    for p in _CONFIG_DIR.glob("*.yaml"):
        configs.append(p.stem)
    for p in _CONFIG_DIR.glob("*.yml"):
        configs.append(p.stem)

    return sorted(set(configs))


def save_model_config(config: ModelConfig, filename: str | None = None) -> None:
    """保存模型配置到文件。

    Args:
        config: 模型配置
        filename: 文件名（默认使用 provider.yaml）
    """
    _ensure_config_dir()

    if filename is None:
        filename = f"{config.provider}.yaml"

    path = _CONFIG_DIR / filename

    data = {
        "provider": config.provider,
        "name": config.name,
        "base_url": config.base_url,
        "api_key": config.api_key,
        "timeout": config.timeout,
    }

    with open(path, "w", encoding="utf-8") as f:
        yaml.dump(data, f, default_flow_style=False, sort_keys=False)


def describe_model_config(config: ModelConfig) -> str:
    """生成模型配置的可读描述。

    Args:
        config: 模型配置

    Returns:
        格式化的描述字符串
    """
    lines = [
        f"提供商: {config.provider}",
        f"模型名称: {config.name}",
        f"基础 URL: {config.base_url}",
        f"API Key: {'***' if config.api_key else '(无)'}",
        f"超时时间: {config.timeout}秒",
    ]
    return "\n".join(lines)


def create_default_configs() -> None:
    """创建默认配置文件模板（如文件不存在）。"""
    _ensure_config_dir()

    defaults = [
        ModelConfig(
            provider="ollama",
            name="qwen2.5:7b",
            base_url="http://localhost:11434/v1",
            api_key="",
            timeout=30.0,
        ),
        ModelConfig(
            provider="lm_studio",
            name="lmstudio-community/Meta-Llama-3.2-3B-Instruct",
            base_url="http://localhost:1234/v1",
            api_key="",
            timeout=30.0,
        ),
        ModelConfig(
            provider="openai",
            name="gpt-3.5-turbo",
            base_url="https://api.openai.com/v1",
            api_key="your-api-key-here",
            timeout=30.0,
        ),
        ModelConfig(
            provider="anthropic",
            name="claude-3-sonnet",
            base_url="https://api.anthropic.com/v1",
            api_key="your-api-key-here",
            timeout=30.0,
        ),
        ModelConfig(
            provider="gemini",
            name="gemini-1.5-pro",
            base_url="https://generativelanguage.googleapis.com/v1",
            api_key="your-api-key-here",
            timeout=30.0,
        ),
    ]

    for config in defaults:
        path = _CONFIG_DIR / f"{config.provider}.yaml"
        if not path.exists():
            save_model_config(config)
