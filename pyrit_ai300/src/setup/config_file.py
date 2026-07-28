"""
Config File Support — 对齐 PyRIT ~/.pyrit/.pyrit_conf
======================================================

PyRIT 1.0.0 Configuration 文档要求：
  "If you don't want to explicitly set up PyRIT, but do have a configuration
   you would like to persist, use ~/.pyrit/.pyrit_conf"

  from pyrit.setup.configuration_loader import initialize_from_config_async
  await initialize_from_config_async()

本模块提供：
  1. AI300ConfigFile — ~/.pyrit/.pyrit_conf 配置文件数据类
  2. load_config_file() — 加载配置文件
  3. save_config_file() — 保存配置文件

配置文件格式（YAML）:
  memory_db_type: SQLite
  initializers:
    - name: target
      args:
        tags: [default, scorer]
    - name: scorer
    - name: technique
    - name: load_default_datasets
  initialization_scripts: []
  env_files: []
  silent: false
  scenario_max_retries: 3
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml


# ============================================================
# 配置文件路径
# ============================================================

DEFAULT_CONFIG_PATH = Path.home() / ".pyrit" / ".pyrit_conf"


# ============================================================
# 配置文件数据类
# ============================================================

@dataclass
class AI300ConfigFile:
    """
    AI-300 配置文件

    对齐 PyRIT ConfigurationLoader 的字段：
      - memory_db_type / initializers / initialization_scripts
      - env_files / env_akv_ref / silent
      - max_concurrent_scenario_runs

    扩展字段：
      - scenario_max_retries — Scenario 级别重试次数
    """
    memory_db_type: str = "SQLite"
    initializers: List[Dict[str, Any]] = field(default_factory=list)
    initialization_scripts: List[str] = field(default_factory=list)
    env_files: List[str] = field(default_factory=list)
    env_akv_ref: List[str] = field(default_factory=list)
    silent: bool = False
    operator: Optional[str] = None
    operation: Optional[str] = None
    max_concurrent_scenario_runs: int = 3
    allow_custom_initializers: bool = False
    scenario_max_retries: int = 0

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "memory_db_type": self.memory_db_type,
            "initializers": self.initializers,
            "initialization_scripts": self.initialization_scripts,
            "env_files": self.env_files,
            "env_akv_ref": self.env_akv_ref,
            "silent": self.silent,
            "operator": self.operator,
            "operation": self.operation,
            "max_concurrent_scenario_runs": self.max_concurrent_scenario_runs,
            "allow_custom_initializers": self.allow_custom_initializers,
            "scenario_max_retries": self.scenario_max_retries,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AI300ConfigFile":
        """从字典创建"""
        return cls(
            memory_db_type=data.get("memory_db_type", "SQLite"),
            initializers=data.get("initializers", []),
            initialization_scripts=data.get("initialization_scripts", []),
            env_files=data.get("env_files", []),
            env_akv_ref=data.get("env_akv_ref", []),
            silent=data.get("silent", False),
            operator=data.get("operator"),
            operation=data.get("operation"),
            max_concurrent_scenario_runs=data.get("max_concurrent_scenario_runs", 3),
            allow_custom_initializers=data.get("allow_custom_initializers", False),
            scenario_max_retries=data.get("scenario_max_retries", 0),
        )

    def to_yaml(self) -> str:
        """序列化为 YAML 字符串"""
        return yaml.dump(self.to_dict(), default_flow_style=False, allow_unicode=True)


# ============================================================
# 配置文件加载/保存
# ============================================================

def load_config_file(
    config_path: Optional[Path | str] = None,
) -> AI300ConfigFile:
    """
    加载 PyRIT 配置文件

    Args:
        config_path: 配置文件路径，默认为 ~/.pyrit/.pyrit_conf

    Returns:
        AI300ConfigFile 实例

    Raises:
        FileNotFoundError: 配置文件不存在
    """
    if config_path is None:
        config_path = DEFAULT_CONFIG_PATH

    config_path = Path(config_path)

    if not config_path.exists():
        raise FileNotFoundError(
            f"PyRIT config file not found: {config_path}\n"
            f"  Create one with save_config_file() or use initialize_ai300_async() directly."
        )

    with open(config_path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    if data is None:
        data = {}

    return AI300ConfigFile.from_dict(data)


def save_config_file(
    config: AI300ConfigFile,
    config_path: Optional[Path | str] = None,
) -> Path:
    """
    保存 PyRIT 配置文件

    Args:
        config: 配置文件数据
        config_path: 配置文件路径，默认为 ~/.pyrit/.pyrit_conf

    Returns:
        实际保存的文件路径
    """
    if config_path is None:
        config_path = DEFAULT_CONFIG_PATH

    config_path = Path(config_path)
    config_path.parent.mkdir(parents=True, exist_ok=True)

    with open(config_path, "w", encoding="utf-8") as f:
        f.write("# PyRIT Configuration File\n")
        f.write("# Generated by AI-300 Setup Module\n")
        f.write(f"# Path: {config_path}\n\n")
        f.write(config.to_yaml())

    return config_path


def create_default_config_file(
    config_path: Optional[Path | str] = None,
) -> Path:
    """
    创建默认配置文件

    包含推荐的初始配置：
      - SQLite 数据库
      - 四大内置初始化器
      - Scenario 重试 3 次

    Returns:
        保存的文件路径
    """
    config = AI300ConfigFile(
        memory_db_type="SQLite",
        initializers=[
            {"name": "target", "args": {"tags": ["default", "scorer"]}},
            {"name": "scorer"},
            {"name": "technique"},
            {"name": "load_default_datasets"},
        ],
        scenario_max_retries=3,
    )
    return save_config_file(config, config_path)
