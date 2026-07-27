# -*- coding: utf-8 -*-
"""
Profile Loader
==============

读取 ai300-recon 生成的侦察结果。
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Optional, Union

from ai300_schemas import PyRITTargetConfig, TargetProfile

logger = logging.getLogger(__name__)


def load_target_profile(path: Union[str, Path]) -> TargetProfile:
    """从 JSON/YAML 文件加载 TargetProfile"""
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Profile not found: {path}")

    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    return TargetProfile.from_dict(data)


def load_pyrit_target(path: Union[str, Path]) -> PyRITTargetConfig:
    """从 PyRIT target JSON 文件加载配置"""
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"PyRIT target not found: {path}")

    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    return PyRITTargetConfig.from_dict(data)


def find_latest_profile(
    profile_dir: Union[str, Path] = "../ai300-recon/results/recon/profiles",
) -> Optional[Path]:
    """查找目录下最新的 TargetProfile JSON 文件"""
    profile_dir = Path(profile_dir)
    if not profile_dir.exists():
        return None

    candidates = sorted(profile_dir.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    return candidates[0] if candidates else None


def find_latest_pyrit_target(
    pyrit_dir: Union[str, Path] = "../ai300-recon/results/recon/pyrit",
) -> Optional[Path]:
    """查找目录下最新的 PyRIT target JSON 文件"""
    pyrit_dir = Path(pyrit_dir)
    if not pyrit_dir.exists():
        return None

    candidates = sorted(pyrit_dir.glob("*_pyrit_target.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    return candidates[0] if candidates else None
