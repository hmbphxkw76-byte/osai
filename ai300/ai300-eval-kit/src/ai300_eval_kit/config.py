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
class EvalConfig:
    """评估工具包配置"""

    # 默认输出目录
    output_dir: str = "results/eval"
    # 默认 adapter 列表
    adapters: List[str] = field(default_factory=lambda: ["giskard"])
    # Giskard 扫描额外参数
    giskard_extra_args: List[str] = field(default_factory=list)
    # 是否 dry-run（仅预览策略，不执行）
    dry_run: bool = False
    # 超时秒数
    timeout: int = 300
    # 任意附加配置
    extra: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_env(cls, env_path: str = ".env") -> "EvalConfig":
        """从 .env 文件和环境变量加载配置"""
        if os.path.exists(env_path):
            load_dotenv(env_path)

        def _bool(name: str, default: bool = False) -> bool:
            """解析布尔环境变量"""
            value = os.getenv(name, "").lower()
            return value in ("1", "true", "yes", "on") if value else default

        def _list(name: str) -> List[str]:
            """解析逗号分隔列表环境变量"""
            value = os.getenv(name, "").strip()
            return [x.strip() for x in value.split(",") if x.strip()] if value else []

        return cls(
            output_dir=os.getenv("EVAL_OUTPUT_DIR", "results/eval"),
            adapters=_list("EVAL_ADAPTERS") or ["giskard"],
            giskard_extra_args=_list("EVAL_GISKARD_EXTRA_ARGS"),
            dry_run=_bool("EVAL_DRY_RUN"),
            timeout=int(os.getenv("EVAL_TIMEOUT", "300")),
        )
