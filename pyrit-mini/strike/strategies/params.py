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
# 参数名必须与 PyRIT 原生攻击类的**构造形参名逐字一致**（C1：不得自研命名）。
# 2026-09-12 修正：TAP/PAIR 的形参是 `tree_width` / `tree_depth`（不是 `width` / `depth`），
# PAIRAttack **不存在** `max_iterations` —— 旧映射使三个多轮攻击类构造必然抛异常
# 并被静默吞掉，L2/L3/L4 升级链 100% 空转。回归见 `tests/test_native_attack_construction.py`。
_SPECS: dict[str, dict[str, tuple[str, Any]]] = {
    "crescendo": {
        "max_backtracks": ("crescendo_max_backtracks", 2),
        "max_turns": ("crescendo_max_turns", 10),
    },
    "tap": {
        "tree_width": ("tap_tree_width", 3),
        "tree_depth": ("tap_tree_depth", 3),
        # BL-038 接真（CP-003）：`tap_branching` 此前为零消费者死键。
        # 对应 PyRIT TAPAttack(branching_factor=...)，默认 2 与 YAML 值一致 → 零行为变更。
        "branching_factor": ("tap_branching", 2),
    },
    "pair": {
        # PAIRAttack 无 `max_iterations` 形参：其"迭代精化轮次"就是 `tree_depth`。
        # 故以 `pair_tree_depth` 为深度 SSOT，消除与 `pair_max_iterations` 的双口径。
        "tree_width": ("pair_tree_width", 1),
        "tree_depth": ("pair_tree_depth", 4),
    },
    # BL-034 接真：以下三类参数此前只被 `_apply_defaults` 拷进 args、**无任何消费者**，
    # 导致 terminal（technique_param_labels）展示的数值与 PyRIT 实际使用的默认值不一致
    # （C9 诚实汇报违规）。现统一经本 SSOT 读取并传入 PyRIT 原生攻击类。
    "many_shot": {
        "example_count": ("many_shot_example_count", 100),
    },
    "chunked_request": {
        "chunk_size": ("chunked_request_chunk_size", 50),
        "total_length": ("chunked_request_total_length", 200),
    },
    "red_teaming": {
        "max_turns": ("red_teaming_max_turns", 3),
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
    """TAPAttack 参数（SSOT：`tap_tree_width` / `tap_tree_depth`）。

    Academic basis: Mehrabi et al. (arXiv:2405.17350) — Tree of Attacks with Pruning
    """
    return algo_params("tap", args)


def pair_params(args: Any | None = None) -> dict[str, Any]:
    """PAIRAttack 参数（SSOT：`pair_max_iterations`）。"""
    return algo_params("pair", args)


def many_shot_params(args: Any | None = None) -> dict[str, Any]:
    """ManyShotJailbreakAttack 参数（SSOT：`many_shot_example_count`）。

    Academic basis: Anthropic (arXiv:2402.05124) — many-shot jailbreaking，示例数直接决定 ASR。
    """
    return algo_params("many_shot", args)


def chunked_request_params(args: Any | None = None) -> dict[str, Any]:
    """ChunkedRequestAttack 参数（SSOT：`chunked_request_chunk_size` / `chunked_request_total_length`）。"""
    return algo_params("chunked_request", args)


def red_teaming_params(args: Any | None = None) -> dict[str, Any]:
    """RedTeamingAttack 参数（SSOT：`red_teaming_max_turns`）。"""
    return algo_params("red_teaming", args)
