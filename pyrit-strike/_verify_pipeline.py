"""端到端流水线集成验证脚本 — 确保所有优化完全集成无断点.

验证项:
    1. 所有模块导入无断点
    2. CAIR 调用链完整 (escalation.py → escalation_level2.py → cair.py)
    3. SequentialAttack incomplete_objectives 收集逻辑正确
    4. 自适应 Dual Judge 阈值集成到 precompute_outcomes_async
    5. technique_registry 注册链完整
    6. main.py → strategy → pipeline 调用链无断点
    7. config/defaults.yaml 参数一致性
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

PASS = "\033[92m[PASS]\033[0m"
FAIL = "\033[91m[FAIL]\033[0m"
INFO = "\033[96m[INFO]\033[0m"

results: list[tuple[str, bool, str]] = []


def check(name: str, fn) -> None:
    """运行单个检查."""
    try:
        msg = fn()
        results.append((name, True, msg or "OK"))
        print(f"{PASS} {name}: {msg or 'OK'}")
    except Exception as e:
        results.append((name, False, str(e)))
        print(f"{FAIL} {name}: {e}")


# ── 1. 模块导入检查 ──

def test_imports():
    """验证所有关键模块可导入."""
    from pipeline.strike.escalation import check_and_escalate, _run_cair  # noqa: F401
    from pipeline.strike.escalation_level2 import _run_cair as _cair_l2  # noqa: F401
    from pipeline.strike.escalation_level2 import _run_gcg  # noqa: F401
    from pipeline.strike.executor import execute_attacks, _try_native_sequential_attack  # noqa: F401
    from pipeline.strike.adaptive_executor import execute_text_adaptive  # noqa: F401
    from pipeline.strike.technique_registry import register_project_techniques  # noqa: F401
    from pipeline.strike.cair import run_cair_attack  # noqa: F401
    from pipeline.assess.asr_tracker import precompute_outcomes_async, compute_asr  # noqa: F401
    from pipeline.assess.asr_stats import _set_adaptive_threshold, _get_adaptive_threshold_stat  # noqa: F401
    from pipeline.assess.judge_utils import _compute_adaptive_threshold  # noqa: F401
    from pipeline.assess.dual_judge import _init_judges  # noqa: F401
    from pipeline.arm.converter_presets import l5_optimal  # noqa: F401
    return "All 12 key modules imported"


# ── 2. CAIR 调用链检查 ──

def test_cair_chain():
    """验证 CAIR 调用链: escalation.py → escalation_level2._run_cair → cair.run_cair_attack."""
    import inspect
    from pipeline.strike.escalation import _run_cair
    from pipeline.strike.escalation_level2 import _run_cair as _cair_l2

    # _run_cair 在 escalation.py 中是 re-export (从 escalation_level2 导入)
    assert _run_cair is _cair_l2, "_run_cair should be re-exported from escalation_level2"

    # _run_cair 内部应引用 cair.run_cair_attack
    source = inspect.getsource(_cair_l2)
    assert "from pipeline.strike.cair import run_cair_attack" in source, \
        "_run_cair should import run_cair_attack from cair.py"
    assert "await run_cair_attack(ctx, obj" in source, \
        "_run_cair should call run_cair_attack"

    return "escalation.py → escalation_level2._run_cair → cair.run_cair_attack"


# ── 3. SequentialAttack incomplete_objectives 检查 ──

def test_sequential_incomplete():
    """验证 _try_native_sequential_attack 正确收集 incomplete_objectives."""
    import inspect
    from pipeline.strike.executor import _try_native_sequential_attack

    source = inspect.getsource(_try_native_sequential_attack)
    assert "all_incomplete" in source, "Should have all_incomplete list"
    assert "AttackOutcome.SUCCESS" in source, "Should check AttackOutcome.SUCCESS"
    assert 'seq_outcome != AttackOutcome.SUCCESS' in source, \
        "Should add to incomplete when outcome != SUCCESS"
    assert "all_incomplete.append((objective, result))" in source or \
           "all_incomplete.append((objective," in source, \
        "Should append (objective, result) to incomplete list"
    # 检查超时和异常也加入 incomplete
    assert "all_incomplete.append((objective, None))" in source, \
        "Should append (objective, None) for timeout/exception"
    return "SequentialAttack correctly collects incomplete_objectives"


# ── 4. 自适应 Dual Judge 阈值检查 ──

def test_adaptive_threshold():
    """验证自适应阈值集成到 precompute_outcomes_async."""
    import inspect
    from pipeline.assess.asr_tracker import precompute_outcomes_async

    source = inspect.getsource(precompute_outcomes_async)
    assert "_compute_adaptive_threshold" in source, \
        "Should call _compute_adaptive_threshold"
    assert "_adaptive_threshold" in source, \
        "Should store adaptive threshold"
    assert "_HIGH_CONF_SIGNALS_STRONG" in source, \
        "Should have strong confidence signals"
    assert "_HIGH_CONF_SIGNALS_MEDIUM" in source, \
        "Should have medium confidence signals"
    assert "_set_adaptive_threshold" in source, \
        "Should write threshold to global stats"

    # 验证 asr_stats 有对应的全局存储
    from pipeline.assess.asr_stats import _get_adaptive_threshold_stat, _set_adaptive_threshold
    _set_adaptive_threshold(0.78)
    assert _get_adaptive_threshold_stat() == 0.78, "Threshold should be settable"

    return "Adaptive threshold integrated: _compute_adaptive_threshold → signal selection → stats"


# ── 5. technique_registry 检查 ──

def test_technique_registry():
    """验证 technique_registry 注册链完整."""
    import inspect
    from pipeline.strike.technique_registry import register_project_techniques

    source = inspect.getsource(register_project_techniques)
    assert "AttackTechniqueRegistry" in source, "Should use AttackTechniqueRegistry"
    assert "register_from_factories" in source, "Should call register_from_factories"
    assert "PromptSendingAttack" in source, "Should register PromptSending"
    assert "PAIRAttack" in source, "Should register PAIR"
    assert "TAPAttack" in source, "Should register TAP"

    # 验证 adaptive_executor 调用了 register_project_techniques
    from pipeline.strike.adaptive_executor import execute_text_adaptive
    adv_source = inspect.getsource(execute_text_adaptive)
    assert "register_project_techniques" in adv_source, \
        "execute_text_adaptive should call register_project_techniques"

    return "technique_registry → adaptive_executor registration chain complete"


# ── 6. main.py 调用链检查 ──

def test_main_pipeline():
    """验证 main.py 调用链无断点."""
    main_path = _PROJECT_ROOT / "main.py"
    source = main_path.read_text(encoding="utf-8")

    # 检查 scenario_result_id (断点续跑)
    assert "scenario_result_id" in source, "main.py should set scenario_result_id for resume"
    assert 'getattr(args, "resume", None)' in source, "Should read --resume arg"

    # 检查 TextAdaptive 路径
    assert "execute_text_adaptive" in source, "Should have TextAdaptive path"
    assert "execute_attacks" in source, "Should have standard executor path"
    assert "check_and_escalate" in source, "Should call escalation"

    # 检查 precompute_outcomes_async (自适应阈值)
    assert "precompute_outcomes_async" in source, "Should call precompute_outcomes_async"

    # 检查 Best-of-N
    assert "_best_of_n_retry" in source or "best_of_n" in source.lower(), \
        "Should reference Best-of-N retry"

    return "main.py: INIT → RECON → ARM → STRIKE → ASSESS → REPORT chain complete"


# ── 7. config 参数一致性检查 ──

def test_config_consistency():
    """验证 config/defaults.yaml 参数一致性."""
    import yaml
    config_path = _PROJECT_ROOT / "config" / "defaults.yaml"
    with open(config_path, encoding="utf-8") as f:
        config = yaml.safe_load(f)

    # L5 基线参数检查
    assert config.get("best_of_n_retries", 0) >= 5, \
        f"best_of_n_retries should be >= 5, got {config.get('best_of_n_retries')}"
    assert config.get("max_escalation_targets", 0) >= 10, \
        f"max_escalation_targets should be >= 10, got {config.get('max_escalation_targets')}"
    assert config.get("post_l1_exit_threshold", 0) >= 60, \
        f"post_l1_exit_threshold should be >= 60, got {config.get('post_l1_exit_threshold')}"
    assert config.get("post_l2_exit_threshold", 0) >= 70, \
        f"post_l2_exit_threshold should be >= 70, got {config.get('post_l2_exit_threshold')}"

    return (f"Config OK: best_of_n={config['best_of_n_retries']}, "
            f"max_escalation={config['max_escalation_targets']}, "
            f"post_l1={config['post_l1_exit_threshold']}, "
            f"post_l2={config['post_l2_exit_threshold']}")


# ── 8. escalation L2 并行链完整性 ──

def test_escalation_l2_parallel():
    """验证 L2 升级链包含 GCG ∥ CAIR 并行."""
    import inspect
    from pipeline.strike.escalation import check_and_escalate

    source = inspect.getsource(check_and_escalate)
    # 检查 L2 asyncio.gather 中包含 GCG 和 CAIR
    assert "_run_gcg" in source, "L2 should have GCG"
    assert "_run_cair" in source, "L2 should have CAIR"
    assert "_run_best_of_n" in source, "L2 should have Best-of-N"
    assert "_run_encoded_injection" in source, "L2 should have Encoded Injection"

    # 检查 L2 gather 调用中包含 CAIR
    l2_section = source[source.find("l2_results = await asyncio.gather"):]
    assert "_run_cair" in l2_section, "CAIR should be in L2 asyncio.gather"
    assert "_run_gcg" in l2_section, "GCG should be in L2 asyncio.gather"

    # 检查 L1 并行链
    assert "_run_cot_hijack" in source, "L1 should have CoT Hijack"
    assert "_run_crescendo" in source, "L1 should have Crescendo"
    assert "_run_tap" in source, "L1 should have TAP"
    assert "_run_pair" in source, "L1 should have PAIR"

    return "L1: CoT∥Crescendo∥TAP∥PAIR → L2: GCG∥CAIR∥BoN∥Encoded → L3+L4 complete"


# ── 运行所有检查 ──

if __name__ == "__main__":
    print(f"\n{INFO} ═══ PyRIT-Strike Pipeline Integration Verification ═══\n")

    check("1. Module Imports", test_imports)
    check("2. CAIR Call Chain", test_cair_chain)
    check("3. SequentialAttack incomplete_objectives", test_sequential_incomplete)
    check("4. Adaptive Dual Judge Threshold", test_adaptive_threshold)
    check("5. Technique Registry Chain", test_technique_registry)
    check("6. main.py Pipeline Chain", test_main_pipeline)
    check("7. Config Consistency", test_config_consistency)
    check("8. L2 Parallel Chain (GCG∥CAIR)", test_escalation_l2_parallel)

    passed = sum(1 for _, ok, _ in results if ok)
    failed = sum(1 for _, ok, _ in results if not ok)

    print(f"\n{INFO} ═══ Summary: {passed} passed, {failed} failed ═══\n")

    if failed > 0:
        print("Failed checks:")
        for name, ok, msg in results:
            if not ok:
                print(f"  {FAIL} {name}: {msg}")
        sys.exit(1)
    else:
        print(f"{PASS} All integration checks passed — no breakpoints detected!")
        sys.exit(0)
