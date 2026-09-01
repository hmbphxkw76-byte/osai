"""自适应执行器模块 — 合并 2 个执行器相关模块。

合并来源:
    - text_adaptive_executor.py: PyRIT 原生 TextAdaptive Scenario
    - best_of_n_retry.py: Best-of-N 重试 + Crescendo 升级

v60 重构: 统一入口逻辑, 支持 synergy_config.technique_tags 直接传入。

数据流:
    synergy_config.technique_tags → adaptive_technique_filter → TextAdaptive

学术依据:
    - PyRIT TextAdaptive (arXiv:2407.01232) — ε-贪心自适应技术选择
    - Chao et al. (arXiv:2402.01135) — Best-of-N, N=5 ASR 提升 1.8x
    - Crescendo (arXiv:2402.12109) — 10 turns ASR=82%

PyRIT 原生优先 (Rule 2):
    使用 PyRIT 原生 TextAdaptive + PromptSendingAttack 作为主引擎。
"""

from __future__ import annotations

import asyncio
import logging
import time
from pathlib import Path
from typing import Any

from core.context import PipelineContext, _get_config_int, get_effective_concurrency

logger = logging.getLogger(__name__)

# 椤圭洰鏍圭洰褰?(pipeline/strike/ 鈫?涓婃函涓ょ骇)
_PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _adaptive_outcome_success(result: Any) -> bool:
    """判断攻击结果是否成功 (进度统计用, 与 executor._is_success 逻辑一致)."""
    outcome = getattr(result, "outcome", None)
    if outcome:
        outcome_str = str(outcome).lower()
        if "success" in outcome_str:
            return True
        if "failure" in outcome_str or "fail" in outcome_str:
            return False
    score_val = getattr(result, "score_value", None)
    if score_val:
        if isinstance(score_val, str):
            return score_val.lower() in ("true", "1", "success")
        if isinstance(score_val, (int, float)):
            return score_val > 0
    scores = getattr(result, "scores", None)
    if scores:
        try:
            for s in scores:
                sv = getattr(s, "score_value", "")
                if str(sv).lower() in ("true", "1", "success"):
                    return True
        except Exception:
            pass
    return False


def _get_best_of_n_retries(ctx: Any | None = None) -> int:
    """L5 v44: 从 config/defaults.yaml 或 ctx.args 读取 best_of_n_retries 配置.

    增量借鉴: 如果传入 ctx, 优先从 ctx.args 读取 --config-file 覆盖值。
    数据流: config.py (scoring.best_of_n_retries) → args → ctx.args → 此函数

    学术依据: Chao et al. (arXiv:2402.01135) — N=5 ASR 1.8x, token 成本为 N=10 的 50%
    R10 override: N≥5 即满足考试要求

    Returns:
        best_of_n_retries 值 (默认 5, 如配置文件不可用)
    """
    # 增量借鉴: 优先从 ctx.args 读取 --config-file 覆盖值
    if ctx is not None:
        _args = getattr(ctx, "args", None)
        if _args is not None:
            n = getattr(_args, "best_of_n_retries", None)
            if isinstance(n, int) and n >= 5:
                return n
            if n is not None:
                logger.warning("best_of_n_retries=%s (below minimum), using default", n)
    try:
        import yaml

        config_path = _PROJECT_ROOT / "config" / "defaults.yaml"
        if config_path.exists():
            with open(config_path, encoding="utf-8") as f:
                config = yaml.safe_load(f)
            n = config.get("best_of_n_retries", 5)
            if isinstance(n, int) and n >= 5:
                return n
            logger.warning("best_of_n_retries=%s (below minimum), using default", n)
    except Exception as e:
        logger.warning("Failed to read best_of_n_retries from config: %s, using default", e)
    return 5


def _load_adaptive_config(ctx: Any | None = None) -> dict[str, Any]:
    """v53: Read all adaptive scenario config from config/defaults.yaml in one I/O.

    R8 §8.1 Production-Grade: single YAML read per invocation (no repeated I/O).
    R7 SSOT: all adaptive parameters sourced from config/defaults.yaml.

    增量借鉴: 如果传入 ctx, 优先从 ctx.args 读取 --config-file 覆盖值。
    数据流: config.py (adaptive section) → args → ctx.args → 此函数
    优先级: ctx.args (--config-file) > config/defaults.yaml > PyRIT 官方默认值

    Returns dict with keys: epsilon, random_seed, max_attempts, technique_filter.
    Each value falls back to PyRIT official default if config unavailable.

    PyRIT official defaults (arXiv:2407.01232 §4):
        epsilon=0.2, random_seed=42, max_attempts=3, technique_filter=None
    """
    defaults: dict[str, Any] = {
        "epsilon": 0.2,
        "random_seed": 42,
        "max_attempts": 3,
        "technique_filter": None,
    }

    # 增量借鉴: 优先从 ctx.args 读取 --config-file 覆盖值
    if ctx is not None:
        _args = getattr(ctx, "args", None)
        if _args is not None:
            _eps = getattr(_args, "adaptive_epsilon", None)
            if isinstance(_eps, (int, float)) and 0.0 <= float(_eps) <= 1.0:
                defaults["epsilon"] = float(_eps)
            _seed = getattr(_args, "adaptive_random_seed", None)
            if isinstance(_seed, int):
                defaults["random_seed"] = _seed
            _ma = getattr(_args, "adaptive_max_attempts", None)
            if isinstance(_ma, int) and _ma >= 1:
                defaults["max_attempts"] = _ma
            _tf = getattr(_args, "adaptive_technique_filter", None)
            if _tf is None:
                pass
            elif isinstance(_tf, list):
                defaults["technique_filter"] = _tf
            elif isinstance(_tf, str):
                defaults["technique_filter"] = [_tf]
            return defaults
    try:
        import yaml

        config_path = _PROJECT_ROOT / "config" / "defaults.yaml"
        if not config_path.exists():
            return defaults
        with open(config_path, encoding="utf-8") as f:
            config = yaml.safe_load(f)
        if not isinstance(config, dict):
            return defaults

        # epsilon (float, clamped to [0.0, 1.0])
        _eps = config.get("adaptive_epsilon", defaults["epsilon"])
        if isinstance(_eps, (int, float)) and 0.0 <= float(_eps) <= 1.0:
            defaults["epsilon"] = float(_eps)
        else:
            logger.warning(
                "adaptive_epsilon=%s invalid (must be 0.0-1.0), using default %.1f",
                _eps, defaults["epsilon"],
            )

        # random_seed (int)
        _seed = config.get("adaptive_random_seed", defaults["random_seed"])
        if isinstance(_seed, int):
            defaults["random_seed"] = _seed

        # max_attempts (int, >=1)
        _ma = config.get("adaptive_max_attempts", defaults["max_attempts"])
        if isinstance(_ma, int) and _ma >= 1:
            defaults["max_attempts"] = _ma
        else:
            logger.warning(
                "adaptive_max_attempts=%s invalid (must be >=1), using default %d",
                _ma, defaults["max_attempts"],
            )

        # technique_filter (list[str] | None)
        _tf = config.get("adaptive_technique_filter", None)
        if _tf is None:
            pass  # keep None default
        elif isinstance(_tf, list):
            defaults["technique_filter"] = _tf
        elif isinstance(_tf, str):
            defaults["technique_filter"] = [_tf]
        else:
            logger.warning(
                "adaptive_technique_filter=%s invalid type, using None",
                type(_tf).__name__,
            )
    except Exception as e:
        logger.warning("Failed to load adaptive config: %s, using defaults", e)
    return defaults


# 鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺?
# TextAdaptive Scenario 鈥?蔚-璐績鑷€傚簲鎶€鏈€夋嫨
# 鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺?

async def execute_text_adaptive(ctx: PipelineContext) -> dict[str, list[Any]]:
    """浣跨敤 PyRIT 鍘熺敓 TextAdaptive 鍦烘櫙鎵ц鏀诲嚮銆?

    L5 v50: 澧炲己闆嗘垚 鈥?娉ㄥ唽椤圭洰 AttackTechniqueFactory 鍒?PyRIT registry,
    浣?TextAdaptive 鑷姩鍙戠幇 Crescendo/TAP/PAIR/BestOfN 绛夋妧鏈€?

    TextAdaptive 鑷姩:
        1. 涓烘瘡涓?objective 閫夋嫨鏈€浣虫敾鍑绘妧鏈?(epsilon-greedy)
        2. 鏍规嵁鍘嗗彶鎴愬姛鐜囧姩鎬佽皟鏁存妧鏈€夋嫨姒傜巼
        3. prompt_sending 浣滀负 baseline 瀵规瘮
        4. 鏀寔 scenario_result_id 鎭㈠涓柇鐨勮繍琛?
    5. L5 v50: 浠?AttackTechniqueRegistry 鍙戠幇宸叉敞鍐岀殑鑷畾涔夋妧鏈?

    瀛︽湳渚濇嵁:
        - PyRIT TextAdaptive (arXiv:2407.01232) 鈥?蔚-璐績鑷€傚簲鎶€鏈€夋嫨
        - Chao et al. (arXiv:2310.08419) 鈥?PAIR 鑷€傚簲绛栫暐閫夋嫨
        - Mehrotra et al. (arXiv:2312.02191) 鈥?TAP 鏍戞悳绱?
        - Russinovich et al. (arXiv:2402.12109) 鈥?Crescendo 娓愯繘鍗囩骇

    Args:
        ctx: 娴佹按绾夸笂涓嬫枃銆?

    Returns:
        鏀诲嚮缁撴灉瀛楀吀 {technique_name: [AttackResult, ...]}銆?
    """
    from pyrit.scenario.scenarios.adaptive import (
        EpsilonGreedyTechniqueSelector,
        TextAdaptive,
    )

    from arm.dataset_config import build_text_adaptive_dataset_config
    from strike.technique_registry import (
        build_scenario_techniques,
        register_project_techniques,
    )

    # L5 v50: 娉ㄥ唽椤圭洰鏀诲嚮鎶€鏈埌 PyRIT 鍘熺敓 AttackTechniqueRegistry
    # 浣?TextAdaptive 鑳借嚜鍔ㄥ彂鐜?Crescendo/TAP/PAIR/BestOfN 绛夋妧鏈?
    # arXiv:2407.01232 鈥?AttackTechniqueRegistry + tag 鏌ヨ鑷姩鍙戠幇
    # R6 §6.4b: 传入 config_overrides 使 technique_registry 从 SSOT 读取攻击参数
    _tech_cfg: dict[str, Any] = {}
    try:
        import yaml as _yaml
        _cfg_path = _PROJECT_ROOT / "config" / "defaults.yaml"
        if _cfg_path.exists():
            with open(_cfg_path, encoding="utf-8") as _f:
                _tech_cfg = _yaml.safe_load(_f) or {}
    except Exception as _e:
        logger.warning("Failed to load defaults.yaml for technique config: %s", _e)

    registered = register_project_techniques(
        adversarial_target=ctx.adversarial_target,
        converter_target=ctx.converter_target,
        config_overrides=_tech_cfg,
    )
    if registered:
        logger.info(
            "L5 v50: TextAdaptive will use %d registered techniques: %s",
            len(registered),
            ", ".join(registered.keys()),
        )

    seed_names = getattr(ctx.args, "seeds", "elite_jailbreaks")
    max_seeds = getattr(ctx.args, "max_seeds", 25) or 25
    dataset_config = build_text_adaptive_dataset_config(seed_names, max_seeds)

    if dataset_config is None:
        logger.warning("TextAdaptive: dataset config build failed, falling back to executor.py")
        from strike.executor import execute_attacks
        return await execute_attacks(ctx)

    scorer = _build_text_adaptive_scorer(ctx)

    if scorer is None:
        logger.warning(
            "TextAdaptive: scorer build failed, falling back to executor.py v35 "
            "(TextAdaptive requires a valid TrueFalseScorer)"
        )
        from strike.executor import execute_attacks
        return await execute_attacks(ctx)

    # v53: PyRIT Adaptive Scenarios alignment — epsilon-greedy selector
    # PyRIT official: EpsilonGreedyTechniqueSelector(epsilon=..., random_seed=...)
    # epsilon=0.2: 20% exploration (random technique), 80% exploitation (best success rate)
    # arXiv:2407.01232 — epsilon-greedy adaptive attack technique selection
    # R8 sec8.1: single I/O read for all adaptive config (SSOT consistency)
    _config = _load_adaptive_config(ctx)
    _epsilon = _config["epsilon"]
    _random_seed = _config["random_seed"]
    _max_attempts = _config["max_attempts"]
    _technique_filter = _config["technique_filter"]

    # v60: 优先使用 synergy_config.technique_tags (来自攻击面分类→技术标签映射)
    # 数据流: burp_profile → synergy_config → technique_tags → adaptive_technique_filter
    # 优先级: synergy_config.technique_tags > args.adaptive_technique_filter > config defaults
    _synergy_config = getattr(ctx, "synergy_config", None)
    if _synergy_config is not None:
        _synergy_tags = getattr(_synergy_config, "technique_tags", None)
        if _synergy_tags is not None:
            _technique_filter = _synergy_tags
            logger.info(
                "v60: Using synergy_config.technique_tags as filter: %s",
                _technique_filter,
            )
        elif _synergy_config.attack_surface == "standard_llm_api":
            # standard_llm_api → 使用全部技术 (不设 filter)
            _technique_filter = None
            logger.info(
                "v60: standard_llm_api surface — using all techniques (no filter)"
            )

    # v53: build scenario_techniques (tag-based filter)
    # PyRIT official: scenario_techniques=[technique_class("single_turn")]
    # R8 sec8.4: boundary defense — empty technique_filter is treated as None
    if _technique_filter:
        scenario_techniques = build_scenario_techniques(
            technique_filter=_technique_filter,
            adversarial_target=ctx.adversarial_target,
            converter_target=ctx.converter_target,
        )
    else:
        scenario_techniques = None

    # R8 sec8.4: defend against empty list — None is safer than []
    # (empty list may cause TextAdaptive to think no techniques are available)
    if scenario_techniques is not None and len(scenario_techniques) == 0:
        logger.warning(
            "v53: scenario_techniques is empty list (filter=%s) — "
            "falling back to default (all registered techniques)",
            _technique_filter,
        )
        scenario_techniques = None

    # v53: build epsilon-greedy selector
    selector = EpsilonGreedyTechniqueSelector(
        epsilon=_epsilon,
        random_seed=_random_seed,
    )
    logger.info(
        "v53: TextAdaptive using EpsilonGreedyTechniqueSelector "
        "(epsilon=%.2f, seed=%d, max_attempts=%d, filter=%s)",
        _epsilon, _random_seed, _max_attempts, _technique_filter,
    )

    scenario = TextAdaptive(
        objective_scorer=scorer,
        selector=selector,
    )

    params: dict[str, Any] = {
        "max_concurrency": getattr(ctx.args, "max_concurrency", 3) or 3,
        "max_retries": 1,
        "include_baseline": True,
        # v53: PyRIT Adaptive alignment — max_attempts_per_objective
        "max_attempts_per_objective": _max_attempts,
    }

    if ctx.objective_target is not None:
        params["objective_target"] = ctx.objective_target

    if dataset_config is not None:
        params["dataset_config"] = dataset_config

    # v53: PyRIT Adaptive alignment — scenario_techniques (tag-based filter)
    if scenario_techniques is not None:
        params["scenario_techniques"] = scenario_techniques
        logger.info(
            "v53: TextAdaptive technique filter applied: %s (%d techniques)",
            _technique_filter,
            len(scenario_techniques),
        )

    scenario_result_id = getattr(ctx.args, "resume", None)
    if scenario_result_id:
        params["scenario_result_id"] = scenario_result_id
        logger.info("TextAdaptive: resuming from scenario_result_id=%s", scenario_result_id)

    try:
        scenario.set_params_from_args(params)
    except Exception as e:
        logger.warning("TextAdaptive: set_params_from_args failed: %s, using defaults", e)

    logger.info(
        "TextAdaptive: launching with concurrency=%d, retries=%d",
        params.get("max_concurrency", 3),
        params.get("max_retries", 1),
    )

    # 进度展示: 计时开始
    _adaptive_start = time.monotonic()
    try:
        from utils.display import print_strike_phase_summary as _adaptive_summ
    except Exception:
        _adaptive_summ = None

    timeout = getattr(ctx.args, "timeout", 1200) or 1200
    try:
        result = await asyncio.wait_for(
            scenario.run_async(),
            timeout=timeout,
        )
    except asyncio.TimeoutError:
        logger.warning("TextAdaptive: timed out after %ds, retrieving partial results", timeout)
        from strike.executor import _retrieve_partial_results
        await _retrieve_partial_results(ctx, "text_adaptive")

        # 进度展示: 超时路径输出摘要
        if _adaptive_summ is not None:
            _elapsed = time.monotonic() - _adaptive_start
            try:
                _adaptive_summ(
                    ctx,
                    total_results=sum(len(v) for v in ctx.attack_results.values()),
                    total_success=sum(
                        1 for results in ctx.attack_results.values()
                        for r in results
                        if _adaptive_outcome_success(r)
                    ),
                    elapsed_seconds=_elapsed,
                )
            except Exception:
                pass

        # R8 sec8.5: timeout 路径编排日志 — 记录 partial results 上下文
        # 主编排日志由 main.py 第 871 行统一添加, 此处仅记录 timeout 决策
        ctx.orchestration_log.append({
            "phase": "strike",
            "decision": "text_adaptive_timeout",
            "input": {"timeout": timeout, "mode": "adaptive"},
            "output": {
                "partial_results": sum(len(v) for v in ctx.attack_results.values()),
            },
            "reasoning": (
                "TextAdaptive timed out, partial results retrieved from PyRIT memory"
            ),
        })
        return ctx.attack_results
    except Exception as e:
        logger.error("TextAdaptive: execution failed: %s — falling back to executor.py", e)
        # R8 sec8.5: fallback 路径编排日志 — 记录 fallback 决策
        ctx.orchestration_log.append({
            "phase": "strike",
            "decision": "text_adaptive_fallback",
            "input": {"mode": "adaptive", "error": str(e)[:200]},
            "output": {},
            "reasoning": "TextAdaptive failed, falling back to multi-path executor.py",
        })

        # 进度展示: fallback 路径输出摘要
        if _adaptive_summ is not None:
            _elapsed = time.monotonic() - _adaptive_start
            try:
                _adaptive_summ(
                    ctx,
                    total_results=sum(len(v) for v in ctx.attack_results.values()),
                    total_success=0,
                    elapsed_seconds=_elapsed,
                )
            except Exception:
                pass

        from strike.executor import execute_attacks
        return await execute_attacks(ctx)

    attack_results: dict[str, list[Any]] = {}
    if hasattr(result, "attack_results"):
        for ar in result.attack_results:
            technique = getattr(ar, "attack_technique", None) or \
                getattr(ar, "technique", None) or "adaptive_text"
            attack_results.setdefault(technique, []).append(ar)

    ctx.attack_results.update(attack_results)
    ctx.scenario_result = result

    logger.info(
        "TextAdaptive: completed, %d techniques, %d total results",
        len(attack_results),
        sum(len(v) for v in attack_results.values()),
    )

    # R8 sec8.5: 成功路径编排日志 — 记录 adaptive 执行参数和结果
    # 注意: main.py 第 871 行会添加统一的 strike 阶段编排日志,
    # 此处记录的是 adaptive 特有决策 (epsilon/filter/partial_results),
    # 两者互补: adaptive 决策细节 + 统一 strike 概要
    ctx.orchestration_log.append({
        "phase": "strike",
        "decision": "text_adaptive_execution",
        "input": {
            "mode": "adaptive",
            "epsilon": _epsilon,
            "random_seed": _random_seed,
            "max_attempts": _max_attempts,
            "technique_filter": _technique_filter,
            "seeds_count": max_seeds,
        },
        "output": {
            "techniques_executed": list(attack_results.keys()),
            "total_results": sum(len(v) for v in attack_results.values()),
        },
        "reasoning": (
            "PyRIT TextAdaptive (arXiv:2407.01232) epsilon-greedy "
            "adaptive technique selection with registered AttackTechniqueFactories"
        ),
    })

    # 进度展示: 成功路径输出摘要
    if _adaptive_summ is not None:
        _elapsed = time.monotonic() - _adaptive_start
        try:
            _adaptive_summ(
                ctx,
                total_results=sum(len(v) for v in ctx.attack_results.values()),
                total_success=sum(
                    1 for results in ctx.attack_results.values()
                    for r in results
                    if _adaptive_outcome_success(r)
                ),
                elapsed_seconds=_elapsed,
            )
        except Exception:
            pass

    return ctx.attack_results


def _build_text_adaptive_scorer(ctx: PipelineContext) -> Any:
    """鏋勫缓 TextAdaptive 鍦烘櫙鐨?objective_scorer銆?

    L5 v42 鏀硅繘: 鐩存帴浣跨敤 _MultiKeywordRefusalScorer (30+ 鍏抽敭璇? 0 token)
    闂璇婃柇: v41 灏濊瘯浠?_build_scoring_config 鎻愬彇 scorer, 浣嗚鍑芥暟杩斿洖绌?
    AttackScoringConfig() (v34 琛屼负, 鏃?objective_scorer), 瀵艰嚧 fallback 鍒?
    鍗曞叧閿瘝 SubStringScorer(substring="i cannot") 鈥?鍋囬槾鎬х巼 >60%銆?
    淇: 鐩存帴瀹炰緥鍖?_MultiKeywordRefusalScorer, 缁曡繃 _build_scoring_config銆?
    瀛︽湳渚濇嵁:
        - Mazeika et al. (arXiv:2402.04249) HarmBench 鈥?澶氬叧閿瘝瑕嗙洊闄嶄綆鍋囬槾鎬х巼
        - Wei et al. (arXiv:2307.15043) 鈥?鎷掔粷妯″紡澶氭牱鍖? 鍗曞叧閿瘝涓嶈冻

    绛栫暐:
        1. 浼樺厛浣跨敤 _MultiKeywordRefusalScorer (澶氬叧閿瘝, 0 token)
        2. Fallback: SubStringScorer+Inverter (鍗曞叧閿瘝, 鍏煎)
        3. Fallback 2: SelfAskTrueFalseScorer (calibrated rubric)
    """
    # 浼樺厛: _MultiKeywordRefusalScorer (30+ 鍏抽敭璇? 0 token)
    try:
        from pyrit.score import TrueFalseInverterScorer

        from strike.executor import _MultiKeywordRefusalScorer

        refusal_scorer = TrueFalseInverterScorer(
            scorer=_MultiKeywordRefusalScorer(),
        )
        logger.info("TextAdaptive scorer: _MultiKeywordRefusalScorer+Inverter (0 token, 30+ keywords, L5 v42)")
        return refusal_scorer
    except Exception as e:
        logger.warning("TextAdaptive: _MultiKeywordRefusalScorer failed: %s, falling back", e)

    # Fallback: SubStringScorer + Inverter (鍗曞叧閿瘝, 鍏煎)
    try:
        from pyrit.score import SubStringScorer, TrueFalseInverterScorer

        refusal_scorer = TrueFalseInverterScorer(
            scorer=SubStringScorer(
                substring="i cannot",
                categories=["refusal_detection"],
            ),
        )
        logger.info("TextAdaptive scorer: SubStringScorer+Inverter (0 token, single keyword fallback)")
        return refusal_scorer
    except Exception as e:
        logger.warning("TextAdaptive: SubStringScorer fallback failed: %s", e)

    # Fallback 2: SelfAskTrueFalseScorer
    if ctx.scoring_target:
        try:
            from pyrit.score import SelfAskTrueFalseScorer, TrueFalseQuestion

            calibrated_rubric_path = _PROJECT_ROOT / "data" / "scorers" / "calibrated_task_achieved.yaml"
            if calibrated_rubric_path.exists():
                question = TrueFalseQuestion.from_yaml(calibrated_rubric_path)
                scorer = SelfAskTrueFalseScorer.from_question(
                    chat_target=ctx.scoring_target,
                    question=question,
                )
                logger.info("TextAdaptive scorer: SelfAskTrueFalseScorer (calibrated)")
                return scorer
        except Exception as e:
            logger.warning("TextAdaptive: SelfAskTrueFalseScorer failed: %s", e)

    return None


# 鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺?
# Best-of-N 閲嶈瘯 + Crescendo 鍗囩骇
# 鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺?

async def _best_of_n_retry(
    ctx: PipelineContext,
    failed_objectives: list[tuple[str, Any]],
) -> None:
    """瀵瑰け璐ョ瀛愪娇鐢?VariationConverter 鐢熸垚鍙樹綋閲嶈瘯 (Best-of-N) + Crescendo 鍗囩骇銆?

    L5 v35 绛栫暐:
        1. 瀵规瘡涓け璐?objective, 鐢熸垚 N=5 涓嫭绔嬪彉浣撹矾寰?
        2. 姣忔潯璺緞鍙惈 1 涓?converter (涓嶄覆鑱斿彔鍔?
        3. 瀵规瘡涓彉浣撴墽琛?PromptSendingAttack
        4. 鍙鏈?1 涓彉浣撴垚鍔? 鍗虫爣璁拌 objective 涓烘垚鍔?
        5. 濡傛灉鎵€鏈夊彉浣撻兘澶辫触 鈫?鐢?check_and_escalate 瑙﹀彂澶氳疆鍗囩骇

    L5 v28: 姝ゆ椂 ctx._failed_objectives 宸茶璁剧疆, _prune_low_asr_converters
    鍦?_build_converter_config 涓細璇诲彇 n_failed, 浣跨敤鍔ㄦ€侀槇鍊?
    n_failed > 10 鈫?10% (婵€杩?, 鈮? 鈫?5%, <5 鈫?3% (淇濆畧)

    瀛︽湳渚濇嵁:
        - Best-of-N (arXiv:2402.01135): N=5 ASR 鎻愬崌 1.8x
        - Crescendo (arXiv:2402.12109): 10 turns ASR=82%
        - Wei et al. (arXiv:2307.15043): 涓茶仈 >2 灞?ASR 浠?12% 闄嶈嚦 4%
        - Zeng et al. (arXiv:2402.19181): authority ASR 38.4% 鏈€楂?
    """
    from pyrit.converter import VariationConverter
    from pyrit.executor.attack import (
        AttackConverterConfig,
        PromptSendingAttack,
    )
    from pyrit.executor.attack.core.attack_executor import AttackExecutor
    from pyrit.models import AttackSeedGroup, SeedObjective
    from pyrit.prompt_normalizer import ConverterConfiguration

    # L5 v44: N_RETRIES 浠?config/defaults.yaml 璇诲彇 (best_of_n_retries=5)
    # 瀛︽湳渚濇嵁: Chao et al. (arXiv:2402.01135) 鈥?N=5 ASR 1.8x, token 鎴愭湰浠?N=10 鐨?50%
    # R10 override: N鈮? 鍗虫弧瓒宠€冭瘯瑕佹眰
    N_RETRIES = _get_best_of_n_retries(ctx)

    # L5 v54: n_persuasion 从 config 读取 (bon_persuasion_count), 默认 3
    n_persuasion = _get_config_int(ctx, "bon_persuasion_count", 3)
    n_persuasion = max(0, min(n_persuasion, N_RETRIES - 1))  # 确保 n_variation >= 1

    from strike.executor import _build_scoring_config
    scoring_config = _build_scoring_config(ctx)

    # L5 v54: 并发信号量控制, 防止 API 限流
    # R7 SSOT: 与 max_concurrency 保持一致的并发限制
    _max_parallel = get_effective_concurrency(ctx)
    _semaphore = asyncio.Semaphore(_max_parallel)

    logger.info(
        "L5 v25: Best-of-N parallel retry: %d failed objectives, "
        "launching in parallel (asyncio.gather, semaphore=%d)",
        len(failed_objectives), _max_parallel,
    )

    async def _best_of_n_single(
        objective: str,
    ) -> tuple[str, list[Any]]:
        """瀵瑰崟涓?objective 鎵ц Best-of-N 閲嶈瘯銆?"""
        async with _semaphore:
            logger.info("Best-of-N retry for: %s...", objective[:60])

            try:
                _n_persuasion = n_persuasion
                _n_variation = N_RETRIES - _n_persuasion
                converter_configurations: list[Any] = []

                if ctx.converter_target is not None:
                    try:
                        from arm.converter_chains import _conv
                        PersuasionConverter = _conv("PersuasionConverter")
                        for _ in range(_n_persuasion):
                            persuasion_converter = PersuasionConverter(
                                converter_target=ctx.converter_target,
                                persuasion_technique="authority_endorsement",
                            )
                            converter_configurations.append(
                                ConverterConfiguration(
                                    converters=[persuasion_converter],
                                )
                            )
                        logger.info(
                            "L5 v35: Best-of-N: %d Persuasion(authority) + %d Variation "
                            "(all single-converter paths, no serial stacking)",
                            _n_persuasion, _n_variation,
                        )
                    except Exception as e:
                        logger.warning("L5 v34: Persuasion failed, using all Variation: %s", e)
                        _n_variation = N_RETRIES
                else:
                    _n_variation = N_RETRIES

                for _ in range(_n_variation):
                    var_conv = VariationConverter(
                        converter_target=ctx.converter_target,
                    )
                    converter_configurations.append(
                        ConverterConfiguration(converters=[var_conv])
                    )

                converter_config = AttackConverterConfig(
                    request_converters=converter_configurations,
                )

                # v53: Use native PrependedConversationConfig via PromptSendingAttack constructor
                # R2 (PyRIT Native First): prepended_conversation_config controls converter
                # role application and non-chat target normalization natively
                from strike.executor import _build_prepended_conversation_config as _build_prepended_config_safe
                bon_prepended_config = _build_prepended_config_safe(ctx)
                attack = PromptSendingAttack(
                    objective_target=ctx.objective_target,
                    attack_scoring_config=scoring_config,
                    attack_converter_config=converter_config,
                    prepended_conversation_config=bon_prepended_config,
                )

                executor = AttackExecutor(max_concurrency=get_effective_concurrency(ctx))

                seed_groups = [
                    AttackSeedGroup(seeds=[SeedObjective(value=objective)]),
                ]

                bon_executor_kwargs: dict[str, Any] = {
                    "attack": attack,
                    "seed_groups": seed_groups,
                    "return_partial_on_failure": True,
                }
                # v53: prepended_conversation_config passed natively via PromptSendingAttack constructor
                retry_result = await asyncio.wait_for(
                    executor.execute_attack_from_seed_groups_async(**bon_executor_kwargs),
                    timeout=300,
                )

                results = list(retry_result.completed_results)
                if results:
                    logger.info(
                        "Best-of-N retry: %d successes for objective: %s...",
                        len(results),
                        objective[:60],
                    )
                else:
                    logger.info(
                        "Best-of-N retry: all %d variations failed for: %s...",
                        N_RETRIES,
                        objective[:60],
                    )
                return objective, results

            except asyncio.TimeoutError:
                logger.warning("Best-of-N retry timed out for: %s...", objective[:60])
                return objective, []
            except Exception as e:
                exc_str = str(e).lower()
                if "integrityerror" in exc_str or "unique constraint" in exc_str:
                    logger.warning(
                        "Best-of-N retry: IntegrityError for %s... (parallel write conflict), "
                        "result lost",
                        objective[:60],
                    )
                else:
                    logger.warning("Best-of-N retry failed for: %s: %s", objective[:60], e)
                return objective, []

    parallel_results = await asyncio.gather(
        *[_best_of_n_single(obj) for obj, _ in failed_objectives],
        return_exceptions=True,
    )

    still_failed: list[str] = []
    for res in parallel_results:
        if isinstance(res, Exception):
            logger.warning("Best-of-N parallel sub-task failed: %s", res)
            continue
        if isinstance(res, tuple):
            objective, results = res
            if results:
                # v52: Backfill converter info to results
                _bon_converter_names = "PersuasionConverter:authority_endorsement, VariationConverter"
                for r in results:
                    existing_meta = getattr(r, "metadata", {}) or {}
                    if "converter" not in existing_meta:
                        existing_meta["converter"] = _bon_converter_names
                        try:
                            r.metadata = existing_meta
                        except Exception:
                            pass
                ctx.attack_results.setdefault("best_of_n_retry", []).extend(results)
            else:
                still_failed.append(objective)

    if still_failed:
        logger.info(
            "L5 v12: %d objectives still failed after Best-of-N, "
            "will be escalated via check_and_escalate (Crescendo+TAP+PAIR parallel)",
            len(still_failed),
        )


async def _escalate_to_crescendo(
    ctx: PipelineContext,
    objectives: list[str],
) -> None:
    """瀵?Best-of-N 澶辫触鐨勭洰鏍囪Е鍙?Crescendo 澶氳疆鏀诲嚮銆?

    瀛︽湳渚濇嵁: Crescendo (arXiv:2402.12109) 鈥?10 turns ASR=82%
    """
    from pyrit.executor.attack import (
        AttackAdversarialConfig,
        CrescendoAttack,
    )
    from pyrit.executor.attack.core.attack_executor import AttackExecutor
    from pyrit.models import AttackSeedGroup, SeedObjective

    try:
        from strike.escalation import _build_refusal_inverter_scoring_config
        scoring_config = _build_refusal_inverter_scoring_config(ctx)

        # v51: PyRIT 鍘熺敓瀵归綈 鈥?娣诲姞 Crescendo 涓撶敤 system_prompt
        adversarial_config_kwargs: dict[str, Any] = {
            "target": ctx.adversarial_target,
        }
        try:
            from pyrit.common.path import EXECUTOR_SEED_PROMPT_PATH
            crescendo_prompt_path = EXECUTOR_SEED_PROMPT_PATH / "crescendo" / "text_generation.yaml"
            if crescendo_prompt_path.exists():
                from pyrit.models import SeedPrompt
                system_prompt = SeedPrompt.from_yaml_file(str(crescendo_prompt_path))
                adversarial_config_kwargs["system_prompt"] = system_prompt
                logger.info("v51: Crescendo fallback using official system_prompt")
        except Exception as e:
            logger.debug("v51: Crescendo fallback system_prompt not available: %s", e)

        attack = CrescendoAttack(
            objective_target=ctx.multi_turn_target or ctx.objective_target,
            attack_adversarial_config=AttackAdversarialConfig(**adversarial_config_kwargs),
            attack_scoring_config=scoring_config,
            max_turns=_get_config_int(ctx, "crescendo_max_turns", 10),
            max_backtracks=_get_config_int(ctx, "crescendo_max_backtracks", 10),
        )

        seed_groups = [
            AttackSeedGroup(seeds=[SeedObjective(value=obj)])
            for obj in objectives
        ]

        executor = AttackExecutor(max_concurrency=get_effective_concurrency(ctx))

        logger.info("Crescendo fallback: attacking %d objectives...", len(objectives))

        executor_result = await asyncio.wait_for(
            executor.execute_attack_from_seed_groups_async(
                attack=attack,
                seed_groups=seed_groups,
                return_partial_on_failure=True,
            ),
            timeout=600,
        )

        if executor_result.completed_results:
            ctx.attack_results.setdefault("crescendo_fallback", []).extend(
                list(executor_result.completed_results)
            )
            logger.info(
                "Crescendo fallback: %d successes, %d failed",
                len(executor_result.completed_results),
                len(executor_result.incomplete_objectives),
            )
        else:
            logger.warning(
                "Crescendo fallback: all %d objectives failed",
                len(objectives),
            )

    except asyncio.TimeoutError:
        logger.warning("Crescendo fallback timed out after 600s")
        from strike.executor import _retrieve_partial_results
        await _retrieve_partial_results(ctx, "crescendo_fallback")
    except Exception as e:
        logger.error("Crescendo fallback failed: %s", e)

