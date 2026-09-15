"""core/component_techniques.py — S9 组件 technique 运行时索引（REQ-151 / PlaybookEngine 接线落点）。

SSOT：tools.audit._purity_baselines._STRIKE_COMPONENT_BASELINES（S9 24 项来源）。
映射：
    - 组件级：component_key → registry spec.id（短名，如 mcp）
             → baselines[id].required_techniques
    - 反向：  technique 名 → 所属组件短 id（供 chain_planner 按 technique 生成链步骤）

职责边界（C3）：本模块**仅查表**，不引入第二套链机制；真实执行由
chain_executor / PlaybookEngine 负责。切片 A（可见性）与切片 B（真实路由）共用本索引，
从而消除 slice A 中 `arm → tools` 的临时方向依赖。

已知债务（option C 完整落地）：required_techniques 现仍由 tools 数据表提供；未来应提升进
config/components/*.yaml + ComponentSpec（消除对 tools 的运行时依赖）。本模块用 try/except
保证 tools / 注册表不可用时降级为 []，零回归、不阻断主链路——但降级**必须留痕**（WARNING），
禁止静默（C9 / R-H1）。
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


def _baselines() -> dict[str, Any]:
    """惰性读取 S9 组件 baseline 数据表（tools 不可用时返回空）。

    降级虽为保证零回归，但**必须留痕**（C9 / R-H1）：`tools/_purity_baselines` 整体迁入
    `tools/audit/` 时，此处原本的静默 `except` 让故障以「逐 technique 路由静默退化」的
    形式远距离暴露（表现为 `tests/common/test_attack_chain.py` 中难以归因的断言失败），
    故降级路径补 WARNING，使故障在真正的故障点即可观测。
    """
    try:
        from tools.audit._purity_baselines import _STRIKE_COMPONENT_BASELINES
    except Exception as exc:  # pragma: no cover - 降级分支由单测显式注入覆盖
        logger.warning(
            "[component_techniques] S9 baseline 表不可用，technique 索引降级为空：%s: %s",
            type(exc).__name__,
            exc,
        )
        return {}
    return _STRIKE_COMPONENT_BASELINES or {}


# 反向索引 technique -> 组件短 id（首次调用时惰性构建，模块级缓存）
_technique_to_component: dict[str, str] | None = None


def _component_id_for_technique() -> dict[str, str]:
    global _technique_to_component
    if _technique_to_component is not None:
        return _technique_to_component
    out: dict[str, str] = {}
    for cid, spec in _baselines().items():
        for tech in spec.get("required_techniques", []) or []:
            out.setdefault(tech, cid)
    _technique_to_component = out
    return out


def component_id_for_technique(technique: str) -> str | None:
    """返回某 technique 所属组件短 id（如 tool_poisoning -> 'mcp'）；未知返回 None。"""
    return _component_id_for_technique().get(technique)


def required_techniques_for(component_key: str) -> list[str]:
    """返回某组件键的 required_techniques（S9 覆盖项）；缺失返回 []。"""
    try:
        from core.registry import get_registry

        spec = get_registry().spec(component_key)
    except Exception:
        return []
    if spec is None:
        return []
    baseline = _baselines().get(spec.id)
    if not baseline:
        return []
    return list(baseline.get("required_techniques", []))


def techniques_for_component(component_key: str) -> list[str]:
    """语义化别名（chain_planner 使用）：返回组件键的 required_techniques。"""
    return required_techniques_for(component_key)
