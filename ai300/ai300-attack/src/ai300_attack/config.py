# -*- coding: utf-8 -*-
"""
配置加载
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Dict, List

from dotenv import load_dotenv


@dataclass
class AttackToolkitConfig:
    """攻击工具包配置"""

    # 默认输出目录
    output_dir: str = "results/attacks"
    # 默认 adapter 列表
    adapters: List[str] = field(default_factory=lambda: ["garak"])
    # Garak 额外参数
    garak_probes: List[str] = field(default_factory=list)
    # PyRIT 额外参数
    pyrit_attack_strategy: str = "prompt_sending"
    # 是否 dry-run（仅预览策略，不执行）
    dry_run: bool = False
    # 超时秒数
    timeout: int = 300
    # 任意附加配置
    extra: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_env(cls, env_path: str = ".env") -> "AttackToolkitConfig":
        """从 .env 文件和环境变量加载配置"""
        if os.path.exists(env_path):
            load_dotenv(env_path)

        def _bool(name: str, default: bool = False) -> bool:
            value = os.getenv(name, "").lower()
            return value in ("1", "true", "yes", "on") if value else default

        def _list(name: str) -> List[str]:
            value = os.getenv(name, "").strip()
            return [x.strip() for x in value.split(",") if x.strip()] if value else []

        return cls(
            output_dir=os.getenv("ATTACK_OUTPUT_DIR", "results/attacks"),
            adapters=_list("ATTACK_ADAPTERS") or ["garak"],
            garak_probes=_list("ATTACK_GARAK_PROBES"),
            pyrit_attack_strategy=os.getenv("ATTACK_PYRIT_STRATEGY", "prompt_sending"),
            dry_run=_bool("ATTACK_DRY_RUN"),
            timeout=int(os.getenv("ATTACK_TIMEOUT", "300")),
        )
