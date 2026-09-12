# -*- coding: utf-8 -*-
"""strike/strategies/params.py — 攻击算法参数唯一访问器（plan Wave 4.3 / C7 / C3）。

职责：
    1. 从 `config/defaults.yaml`（唯一 YAML SSOT）读取算法参数；
    2. 允许 `ctx.args` 覆盖（CLI/配置文件优先级更高，符合 C7 单向数据流）；
    3. 为 TAP / PAIR / Crescendo 各提供**一个**取值函数，消灭分散硬编码。

非职责：本模块不发起任何攻击，仅产出参数字典（C13：扩展层只构造配置）。

Academic basis:
    - Mehrotra et al. (arXiv:2312.02119) TAP — tree width/depth 决定探索广度与深度
    - Chao et al. (arXiv:2310.08419) PAIR — max_iterations 决定迭代精化轮次
    - Russinovich et al. (arXiv:2404.01833) Crescendo — max_backtracks 决定回退次数
"""

from __future__ import annotations

import logging
from functools import lru_cache
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_DEFAULTS_YAML = _PROJECT_ROOT / "config" / "defaults.yaml"

# 算法参数 → (defaults.yaml 键, 兜底常量)
# 兜底常量仅在 YAML 缺失/损坏时生效，并会 WARNING 留痕（C9 禁止静默回退）。
_SPECS: dict[str, dict[str, tuple[str, Any]]] = {
    "crescendo": {
        "max_backtracks": ("crescendo_max_backtracks", 2),
    },
    "tap": {
        "width": ("tap_tree_width", 3),
        "depth": ("tap_tree_depth", 3),
    },
    "pair": {
        "max_iterations": ("pair_max_iterations", 5),
    },
}


@lru_cache(maxsize=1)
def _load_yaml_defaults() -> dict[str, Any]:
    """读取 config/defaults.yaml（进程内缓存一次）。"""
    if not _DEFAULTS_YAML.exists():
        logger.warning("算法参数 SSOT 缺失：%s（回退内置常量）", _DEFAULTS_YAML)
        return {}
    try:
        import yaml

        with open(_DEFAULTS_YAML, encoding="utf-8") as f:
            data = yaml.safe_load(f)
        return data if isinstance(data, dict) else {}
    except Exception as e:
        logger.warning("算法参数 SSOT 读取失败：%s（回退内置常量）", e)
        return {}


def _resolve(yaml_key: str, fallback: Any, args: Any | None) -> Any:
    """按 C7 优先级取值：args（CLI/配置文件）> defaults.yaml > 内置常量。"""
    # 1) args 优先（CLI > config file > defaults.yaml，三者已由 parse_args 归并）
    if args is not None:
        value = getattr(args, yaml_key, None)
        if value is not None:
            return value

    # 2) defaults.yaml
    value = _load_yaml_defaults().get(yaml_key)
    if value is not None:
        return value

    # 3) 内置常量
    logger.warning("算法参数 %s 未在任何配置源声明，使用内置兜底 %r（C7 断链）", yaml_key, fallback)
    return fallback


def algo_params(name: str, args: Any | None = None) -> dict[str, Any]:
    """取得指定算法的参数字典。

    Args:
        name: 算法名，取 `crescendo` / `tap` / `pair`。
        args: 可选的 CLI 命名空间（`ctx.args`）；提供时优先级高于 defaults.yaml。

    Returns:
        可直接 `**kwargs` 展开传给 PyRIT 原生攻击类的参数字典。
        未知算法名返回空字典并记录 WARNING（IA-6：未知不崩溃）。
    """
    spec = _SPECS.get(name)
    if spec is None:
        logger.warning("未知算法名 %r，无参数可解析（已知：%s）", name, ", ".join(sorted(_SPECS)))
        return {}
    return {param: _resolve(yaml_key, fallback, args) for param, (yaml_key, fallback) in spec.items()}


def crescendo_params(args: Any | None = None) -> dict[str, Any]:
    """CrescendoAttack 参数（SSOT：`crescendo_max_backtracks`）。"""
    return algo_params("crescendo", args)


def tap_params(args: Any | None = None) -> dict[str, Any]:
    """TAPAttack 参数（SSOT：`tap_tree_width` / `tap_tree_depth`）。"""
    return algo_params("tap", args)


def pair_params(args: Any | None = None) -> dict[str, Any]:
    """PAIRAttack 参数（SSOT：`pair_max_iterations`）。"""
    return algo_params("pair", args)
