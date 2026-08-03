# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""阶段注册表。

集中登记阶段, 支持按名称检索与有序编排, 使 runner 与具体阶段解耦。
新增阶段只需在此注册 (或运行时 register), 无需改动 runner。
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import TYPE_CHECKING

from pipeline.stages.base import PipelineStage

if TYPE_CHECKING:
    pass

STAGES_DIR = Path(__file__).resolve().parent / "stages"

_REGISTRY: dict[str, type[PipelineStage]] = {}


def register(stage_cls: type[PipelineStage]) -> type[PipelineStage]:
    """注册一个阶段类 (可用作装饰器)。"""
    _REGISTRY[stage_cls.name] = stage_cls
    return stage_cls


def get_stage(name: str) -> type[PipelineStage]:
    """按名称获取阶段类。"""
    if name not in _REGISTRY:
        raise KeyError(f"Unknown pipeline stage: {name!r}. Registered: {list(_REGISTRY)}")
    return _REGISTRY[name]


def list_stages() -> list[str]:
    """列出所有已注册阶段名。"""
    return list(_REGISTRY)


def all_stages() -> dict[str, type[PipelineStage]]:
    """返回全部注册表 (名称 -> 类)。"""
    return dict(_REGISTRY)


def _discover_module_paths(stages_dir: Path = STAGES_DIR) -> list[Path]:
    """发现 pipeline/stages/ 下的阶段文件 (*_stage.py, 排除 __init__/base)。"""
    if not stages_dir.exists():
        return []
    paths = [
        p for p in stages_dir.glob("*_stage.py")
        if p.name not in ("__init__.py", "base.py")
    ]
    paths.sort(key=lambda p: p.name)
    return paths


def autodiscover(stages_dir: Path = STAGES_DIR) -> list[str]:
    """扫描 stages 目录, 加载并注册所有 PipelineStage 子类。

    仅定义, 不自动执行 — 由运行时入口 (recon-main) 或测试显式调用,
    避免 import pipeline 包即产生副作用。
    """
    registered: list[str] = []
    for module_path in _discover_module_paths(stages_dir):
        module_name = f"_recon_stage_{module_path.stem}"
        spec = importlib.util.spec_from_file_location(module_name, module_path)
        if spec is None or spec.loader is None:
            continue
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)  # type: ignore[union-attr]
        for attr_name in dir(module):
            attr = getattr(module, attr_name)
            if (
                isinstance(attr, type)
                and issubclass(attr, PipelineStage)
                and attr is not PipelineStage
                and getattr(attr, "name", None)
            ):
                register(attr)
                registered.append(attr.name)
    return registered
