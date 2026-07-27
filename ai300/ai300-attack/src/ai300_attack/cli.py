# -*- coding: utf-8 -*-
"""
命令行接口
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
from pathlib import Path
from typing import List, Optional

from .config import AttackToolkitConfig


def build_parser() -> argparse.ArgumentParser:
    """构建命令行参数解析器"""
    parser = argparse.ArgumentParser(
        prog="ai300-attack",
        description="基于侦察结果执行 LLM 对话层攻击（PyRIT / Garak）",
    )
    parser.add_argument(
        "--profile",
        default=os.getenv("ATTACK_PROFILE", ""),
        help="ai300-recon 生成的 TargetProfile JSON 路径",
    )
    parser.add_argument(
        "--pyrit-target",
        default=os.getenv("ATTACK_PYRIT_TARGET", ""),
        help="ai300-recon 生成的 PyRIT target JSON 路径",
    )
    parser.add_argument(
        "--adapter",
        default=os.getenv("ATTACK_ADAPTERS", "garak"),
        help="攻击适配器，逗号分隔：garak,pyrit,all",
    )
    parser.add_argument(
        "--output-dir",
        default=os.getenv("ATTACK_OUTPUT_DIR", "results/attacks"),
        help="攻击结果输出目录",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        default=os.getenv("ATTACK_DRY_RUN", "").lower() in ("1", "true", "yes"),
        help="仅预览策略，不执行攻击",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=int(os.getenv("ATTACK_TIMEOUT", "300")),
        help="单次攻击超时秒数",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="输出详细日志",
    )
    parser.add_argument(
        "--env",
        default=".env",
        help="环境变量文件路径",
    )
    return parser


def setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        stream=sys.stdout,
    )


def resolve_profile_path(args) -> Optional[Path]:
    """解析 profile 路径"""
    if args.profile:
        return Path(args.profile)
    # 默认查找 ai300-recon 最新输出
    from .loaders import find_latest_profile

    return find_latest_profile()


def resolve_pyrit_target_path(args) -> Optional[Path]:
    """解析 PyRIT target 路径"""
    if args.pyrit_target:
        return Path(args.pyrit_target)
    from .loaders import find_latest_pyrit_target

    return find_latest_pyrit_target()


def parse_adapters(adapter_arg: str) -> List[str]:
    """解析适配器列表"""
    adapters = [a.strip().lower() for a in adapter_arg.split(",") if a.strip()]
    if "all" in adapters:
        return ["garak", "pyrit"]
    return adapters
