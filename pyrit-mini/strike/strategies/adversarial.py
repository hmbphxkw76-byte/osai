"""strike/strategies/adversarial.py — PyRIT 原生多轮攻击的统一构造适配器。

**缺陷背景（2026-09-12 实测发现）**
    PyRIT 1.0.1 的 `CrescendoAttack` / `TAPAttack` / `PAIRAttack` / `RedTeamingAttack`
    构造函数均要求 **`attack_adversarial_config` 为必填参数**（无默认值），且：
        - `TAPAttack`/`PAIRAttack` 的参数名是 `tree_width` / `tree_depth`，
          **不是** `width` / `depth`；
        - `PAIRAttack` **不存在** `max_iterations` 参数。
    本仓库此前全部调用点都是
    `TAPAttack(objective_target=..., **{"width": 3, "depth": 3})` 形态，
    构造必然抛 `TypeError`/`ValueError`，异常又被外层 `try/except` 静默吞掉 ——
    结果是 **L2 Crescendo / L3 TAP / L4 PAIR 整条升级链与渐进式多轮策略 100% 空转**
    （R-H1 静默降级 / R-H2 静默吞错 / C2 ASR 至上三重违例）。

**本模块职责**
    1. 从 `ctx.adversarial_target` 构造 `AttackAdversarialConfig`（I5 三角色分离）；
    2. 把 `strike.strategies.params` 产出的参数字典**按真实 PyRIT 签名过滤**，
       剔除 PyRIT 不接受的参数（防御 PyRIT 升级导致的 API 失效，R-DRIFT-1）；
    3. 缺失必填项时**显式返回 None 并留痕**，由调用方决定降级——禁止静默。

Academic basis:
    - Russinovich et al. (arXiv:2404.01833) Crescendo — 需要对抗侧 LLM 生成渐进提示
    - Mehrabi et al. (arXiv:2405.17350) TAP — 需要对抗侧 LLM 生成分支候选
    - Chao et al. (arXiv:2310.08419) PAIR — 需要攻击者 LLM 迭代精化
Constitution:
    - C1：只做**构造适配**，不重写任何攻击逻辑（攻击执行仍 100% 委托原生类）
    - I5：对抗侧目标只能取 `ctx.adversarial_target`（三角色分离）
    - C9：能力缺失必须 WARNING 留痕，禁止静默吞掉
"""

from __future__ import annotations

import inspect
import logging
from typing import Any

logger = logging.getLogger(__name__)


def build_adversarial_config(ctx: Any) -> Any | None:
    """从 `ctx.adversarial_target` 构造 PyRIT `AttackAdversarialConfig`。

    Args:
        ctx: 流水线上下文（读 `ctx.adversarial_target`）。

    Returns:
        `AttackAdversarialConfig`；对抗侧目标缺失或 PyRIT 不可用时返回 None（留痕）。
    """
    target = getattr(ctx, "adversarial_target", None)
    if target is None:
        logger.warning(
            "[NativeAttack] ctx.adversarial_target 缺失：Crescendo/TAP/PAIR/RedTeaming "
            "等需要对抗侧 LLM 的原生攻击无法构造（I5 三角色分离），本次调用将显式降级"
        )
        return None
    try:
        from pyrit.executor.attack import AttackAdversarialConfig

        return AttackAdversarialConfig(target=target)
    except Exception as e:
        logger.warning("[NativeAttack] AttackAdversarialConfig 构造失败: %s", e)
        return None


def accepted_kwargs(cls: Any, params: dict[str, Any]) -> dict[str, Any]:
    """按真实 PyRIT 构造函数签名过滤参数（R-DRIFT-1 防线）。

    被剔除的参数会 WARNING 留痕——它们意味着 `config/defaults.yaml` 与
    PyRIT API 之间出现漂移，必须被人看见而不是静默丢弃（C9）。

    Args:
        cls: PyRIT 原生攻击类。
        params: `strike.strategies.params` 产出的参数字典。

    Returns:
        仅含 `cls.__init__` 接受项的参数字典。
    """
    try:
        signature = inspect.signature(cls.__init__)
    except (TypeError, ValueError):  # 内建/异常类，无法取签名
        return dict(params)

    params_view = list(signature.parameters.values())
    accepts_var_keyword = any(p.kind is inspect.Parameter.VAR_KEYWORD for p in params_view)

    # 签名形如 `(*args, **kwargs)`（通常是 MagicMock 等无法枚举形参的对象）：
    # 此时无法判断哪些键被接受，选择**放行全部**参数而非误剔除（R-DRIFT-1 在真实
    # 类上仍然生效；只在不可枚举时才放宽，避免把合法参数当漂移剔掉）。
    if accepts_var_keyword and len(params_view) <= 1:
        return dict(params)

    accepted = set(signature.parameters)
    kept = {k: v for k, v in params.items() if k in accepted}
    dropped = sorted(set(params) - accepted)
    if dropped:
        logger.warning(
            "[NativeAttack] %s 不接受参数 %s —— 疑似 PyRIT API 漂移（R-DRIFT-1），已剔除",
            getattr(cls, "__name__", cls),
            dropped,
        )
    return kept


# 本仓 0-token 判定 SSOT（30+ 拒绝关键词、0 LLM 调用，I2 / R-NATIVE-3）
_ZERO_TOKEN_REFUSAL_SCORER_FACTORY = "strike.common._executor_helpers._MultiKeywordRefusalScorer"

# TAP / PAIR 额外要求 objective_scorer 必须是 `FloatScaleThresholdScorer`
_FLOAT_THRESHOLD_SCORING_CLASSES = frozenset({"TAPAttack", "PAIRAttack", "TreeOfAttacksWithPruningAttack"})


def _build_zero_token_objective_scorer() -> Any:
    """构造 0-token 的 `TrueFalseInverterScorer`（与单轮 FIRST_SUCCESS 同口径）。"""
    import importlib

    module_path, _, factory = _ZERO_TOKEN_REFUSAL_SCORER_FACTORY.rpartition(".")
    refusal_scorer = getattr(importlib.import_module(module_path), factory)()
    from pyrit.score import TrueFalseInverterScorer

    return TrueFalseInverterScorer(scorer=refusal_scorer)


def build_zero_token_scoring_config(ctx: Any, *, cls: Any = None) -> Any | None:
    """构造**0-token** 的评分配置（I2：攻击执行路径禁止 LLM 评分器）。

    PyRIT 1.0.1 的多轮攻击类在缺少 `attack_scoring_config.objective_scorer` 时会直接
    `raise ValueError("Objective scorer must be provided...")`——这是本次缺陷的
    **第二层**：即使补上对抗侧配置，没有 objective scorer 依然构造失败。
    而 `TAPAttack` / `PAIRAttack` 还额外要求 objective_scorer 必须被
    `FloatScaleThresholdScorer` 包裹（**第三层**）。

    Args:
        ctx: 流水线上下文（不参与构造，保留以维持 C7 单一入口形态）。
        cls: 目标攻击类；命中 TAP/PAIR 时产出 `TAPAttackScoringConfig`。

    Returns:
        评分配置对象；构造失败返回 None（调用方据此显式降级）。
    """
    try:
        objective_scorer = _build_zero_token_objective_scorer()
        cls_name = getattr(cls, "__name__", "") or ""
        if cls_name in _FLOAT_THRESHOLD_SCORING_CLASSES:
            from pyrit.executor.attack.multi_turn.tree_of_attacks import TAPAttackScoringConfig
            from pyrit.score import FloatScaleThresholdScorer

            return TAPAttackScoringConfig(
                objective_scorer=FloatScaleThresholdScorer(scorer=objective_scorer, threshold=0.5)
            )

        from pyrit.executor.attack import AttackScoringConfig

        return AttackScoringConfig(objective_scorer=objective_scorer)
    except Exception as e:
        logger.warning("[NativeAttack] 0-token scoring config 构造失败: %s", e)
        return None


def build_native_attack_kwargs(
    ctx: Any,
    cls: Any,
    params: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    """组装原生攻击类的完整构造 kwargs。

    补齐两类 PyRIT 1.0.1 的**必填/隐含必填**项：
        1. `attack_adversarial_config`（对抗侧 LLM，I5 三角色分离）
        2. `attack_scoring_config`（0-token objective scorer，I2）
    缺任一项都返回 None —— 调用方必须据此**显式留痕**，禁止静默跳过。

    Args:
        ctx: 流水线上下文。
        cls: PyRIT 原生攻击类。
        params: 算法参数字典（`strike.strategies.params` 产出）。

    Returns:
        可直接 `cls(objective_target=..., **kwargs)` 的字典；不可构造时返回 None。
    """
    kwargs = accepted_kwargs(cls, params or {})

    try:
        signature = inspect.signature(cls.__init__)
    except (TypeError, ValueError):
        return kwargs
    parameters = signature.parameters

    if "attack_adversarial_config" in parameters:
        adversarial_config = build_adversarial_config(ctx)
        if adversarial_config is None:
            return None  # 显式降级：调用方必须据此留痕，不得静默跳过
        kwargs["attack_adversarial_config"] = adversarial_config

    if "attack_scoring_config" in parameters:
        scoring_config = build_zero_token_scoring_config(ctx, cls=cls)
        if scoring_config is None:
            logger.warning(
                "[NativeAttack] %s 需要 objective scorer 但 0-token 配置不可用，显式降级",
                getattr(cls, "__name__", cls),
            )
            return None
        kwargs["attack_scoring_config"] = scoring_config

    return kwargs
