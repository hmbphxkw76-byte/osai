"""strike/common/chain_executor.py — 攻击链步骤执行器（plan Wave 3）。

把 `AttackStep`（component_key + action）真正路由到 `strike/<component>/` 下的模块，
实现「每种组件都有 ≥1 条可执行攻击路径」的 DoD。

路由策略（C13 原则 2：扩展层仅构造配置，攻击执行委托 PyRIT 原生类）：
    1. 由 ComponentSpec.strike_modules 解析 action → dotted path
    2. 在该模块内按优先级查找入口：`run_<action>` → `execute` → `run` → `main`
    3. 以 (ctx) / (ctx, state) 两种签名尝试调用（async / sync 均可）
    4. 找不到入口 → 显式失败并记录 reason（**禁止静默跳过**，C9）

未命中任何可执行入口时，步骤记为失败并写入 `ChainState.failed_steps`，
由 `continue_on_step_failure` 决定是否继续。

Academic basis:
    - PyRIT (arXiv:2407.01232): 攻击执行委托原生 Attack 类
    - Greshake et al. (arXiv:2302.12173): 跨组件攻击链
"""

from __future__ import annotations

import asyncio
import inspect
import logging
from importlib import import_module
from typing import Any

logger = logging.getLogger(__name__)

# 模块内候选入口函数名（按优先级）
_ENTRY_CANDIDATES: tuple[str, ...] = ("execute", "run", "main", "run_attacks", "execute_async")


def resolve_module(component_key: str, action: str) -> str | None:
    """把 (component_key, action) 解析为 strike 模块 dotted path。"""
    try:
        from core.registry import get_registry

        spec = get_registry().spec(component_key)
    except Exception:
        return None
    if spec is None:
        return None
    for dotted in spec.strike_modules:
        if dotted.rsplit(".", 1)[-1] == action:
            return dotted
    # action 可能就是 preferred_attack_class（非模块名）→ 取首个声明模块
    return spec.strike_modules[0] if spec.strike_modules else None


def _pick_entry(mod: Any, action: str) -> Any:
    """在模块内挑选入口可调用对象。"""
    named = getattr(mod, f"run_{action}", None)
    if callable(named):
        return named
    for name in _ENTRY_CANDIDATES:
        fn = getattr(mod, name, None)
        if callable(fn):
            return fn
    return None


async def _invoke(fn: Any, ctx: Any, state: Any) -> Any:
    """按签名健壮地调用入口函数：(ctx) / (ctx, state) / ()。"""
    try:
        params = inspect.signature(fn).parameters
        positional = [p for p in params.values() if p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD)]
        accepts_var = any(p.kind == p.VAR_POSITIONAL for p in params.values())
    except (TypeError, ValueError):
        positional, accepts_var = [], True

    if accepts_var or len(positional) >= 2:
        result = fn(ctx, state)
    elif len(positional) == 1:
        result = fn(ctx)
    else:
        result = fn()

    if inspect.isawaitable(result):
        return await result
    return result


async def execute_step(step: Any, state: Any, *, ctx: Any) -> dict[str, Any]:
    """执行单个攻击链步骤，返回产出物 dict。

    Raises:
        RuntimeError: 模块/入口缺失（由状态机记录为 failed，不静默）。
    """
    component_key = str(getattr(step, "component_key", "") or "")
    action = str(getattr(step, "action", "") or "")

    dotted = resolve_module(component_key, action)
    if not dotted:
        raise RuntimeError(f"组件 {component_key} 无 strike 模块声明（action={action}）")

    try:
        mod = import_module(dotted)
    except Exception as e:
        raise RuntimeError(f"strike 模块导入失败 {dotted}: {e}") from e

    entry = _pick_entry(mod, action)
    if entry is None:
        raise RuntimeError(
            f"模块 {dotted} 无可调用入口（已尝试 run_{action} / {', '.join(_ENTRY_CANDIDATES)}）"
        )

    # 预算闸门（plan §4.4：与接线同批落地）
    budget = getattr(ctx, "budget", None)
    if budget is not None:
        cost = int(getattr(step, "budget_cost", 1) or 1)
        if not budget.consume(component_key, cost=cost):
            raise RuntimeError(f"预算不足，组件 {component_key} 步骤被裁剪")

    logger.info("[ChainExecutor] 执行步骤 %s → %s.%s", step.id, dotted, getattr(entry, "__name__", "?"))

    try:
        raw = await _invoke(entry, ctx, state)
    except asyncio.CancelledError:
        raise
    except Exception as e:
        raise RuntimeError(f"{dotted}.{getattr(entry, '__name__', '?')} 执行失败: {e}") from e

    # 归一化产出物：只保留 step.produces 声明的键
    produced: dict[str, Any] = {}
    if isinstance(raw, dict):
        for key in getattr(step, "produces", []) or []:
            if key in raw:
                produced[key] = raw[key]
        # 未显式声明产出时，把整个结果作为一个仓储键，保证下游可消费
        if not produced and raw:
            produced["raw_result"] = raw
    elif raw is not None:
        produced["raw_result"] = raw

    # 组件专属侦察/攻击结果回填 service_profile（供后续步骤消费）
    if isinstance(raw, dict) and hasattr(ctx, "service_profile"):
        for key in ("mcpsec_surface", "a2a_topology", "rag_kb_map", "session_state"):
            if key in raw and isinstance(raw[key], (dict, list, str)):
                ctx.service_profile.setdefault(key, raw[key])

    return produced
