"""端到端流水线集成验证 — 全量检查所有模块和调用链.

用法 (从项目根目录)::

    python -m pytest tests/pipeline/test_full_integration.py -s -v
"""

from __future__ import annotations

import importlib
import inspect
import os
import sys
from pathlib import Path

import pytest
import yaml

# 确保项目根目录在 sys.path 中, 并切换 CWD 到项目根目录
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

os.chdir(_PROJECT_ROOT)

errors: list[str] = []

# ── 辅助函数 ──

def _run_compile_check() -> tuple[int, int, list[str]]:
    """全量 Python 编译检查."""
    import py_compile

    py_files = list((_PROJECT_ROOT / "pipeline").rglob("*.py"))
    compile_err = 0
    local_errors: list[str] = []
    for f in sorted(py_files):
        try:
            py_compile.compile(str(f), doraise=True)
        except py_compile.PyCompileError as e:
            compile_err += 1
            local_errors.append(f"{f}: {e}")
    return len(py_files), compile_err, local_errors


def _run_yaml_seeds_check() -> tuple[int, list[str]]:
    """全量 YAML 种子验证."""
    seeds_dir = _PROJECT_ROOT / "data" / "seeds"
    total_seeds = 0
    local_errors: list[str] = []
    for f in sorted(seeds_dir.glob("*.prompt")):
        try:
            with open(f, encoding="utf-8") as fh:
                data = yaml.safe_load(fh)
            if isinstance(data, list):
                total_seeds += len(data)
                bad = sum(1 for item in data if not isinstance(item, dict) or "value" not in item)
                if bad:
                    local_errors.append(f"{f.name}: {bad} malformed seeds")
            else:
                local_errors.append(f"{f.name}: not a list")
        except Exception as e:
            local_errors.append(f"{f.name}: {e}")
    return total_seeds, local_errors


# ── 3. Import 链验证数据 ──
IMPORT_TESTS = [
    ("pipeline.context", "PipelineContext"),
    ("pipeline.strike.escalation", None),
    ("pipeline.strike.multi_turn_attacks", "run_best_of_n_attack"),
    ("pipeline.strike.encoded_injection", "run_encoded_injection_attack"),
    ("pipeline.strike.encoded_injection", "generate_encoded_variants"),
    ("pipeline.strike.cot_hijack", "run_cot_hijack_attack"),
    ("pipeline.strike.multi_turn_attacks", "run_multi_prompt_attack"),
    ("pipeline.strike.multi_turn_attacks", "run_sequential_attack"),
    ("pipeline.strike.cair", "analyze_refusal_pattern"),
    ("pipeline.strike.cair", "_get_response_text"),
    ("pipeline.recon.burp_parser", "_probe_capabilities"),
    ("pipeline.recon.burp_parser", "_detect_model_family"),
    ("pipeline.recon.burp_parser", "probe_active_capabilities"),
]

# ── 4. Escalation 函数完整性数据 ──
ESC_FUNCTIONS = [
    "check_and_escalate",
    "_run_crescendo", "_run_tap", "_run_pair",
    "_run_gcg", "_run_cot_hijack",
    "_run_multi_model_escalation",
    # 精简版: L3 函数已移除 (skeleton_key_native, mcp_rag_attacks, rogue_agent, embedding_inversion)
    "_run_best_of_n", "_run_encoded_injection",
    "_select_still_failed_clustered",
    "_llm_judge_rescore",
    "_analyze_escalation_results",
    "_select_still_failed",
    "_build_refusal_inverter_scoring_config",
    "_compute_overall_asr",
    "_is_success", "_get_objective",
]

# ── 5. 调用链验证数据 ──
CALL_CHECKS = [
    ("_analyze_escalation_results", "_analyze_escalation_results"),
    ("_run_best_of_n", "_run_best_of_n"),
    ("_run_encoded_injection", "_run_encoded_injection"),
    ("precompute_outcomes_async", "precompute_outcomes_async"),
    ("_select_failed_objectives", "_select_failed_objectives"),
    ("_run_cot_hijack", "_run_cot_hijack"),
    ("_run_crescendo", "_run_crescendo"),
    ("_run_gcg", "_run_gcg"),
    # 精简版: L3 (skeleton_key_native, mcp_rag_attacks) 执行已跳过, 仅保留函数定义
    # ("_run_skeleton_key_native", "_run_skeleton_key_native"),
    # ("_run_mcp_rag_attacks", "_run_mcp_rag_attacks"),
]

# ── 7. 模型检测验证数据 ──
MODEL_DETECT_CASES = [
    ("I am ChatGPT, an AI assistant", "gpt"),
    ("I am Claude, made by Anthropic", "claude"),
    ("I am Gemini, a Google AI", "gemini"),
    ("I am Llama, from Meta AI", "llama"),
    ("I am an AI assistant", None),
]

# ── 8. PyRIT API 兼容性数据 ──
PYRIT_CHECKS = [
    ("pyrit.executor.attack", "PromptSendingAttack"),
    ("pyrit.executor.attack", "RedTeamingAttack"),
    ("pyrit.executor.attack", "SkeletonKeyAttack"),
    ("pyrit.executor.attack", "BargeInAttack"),
    ("pyrit.executor.attack", "ChunkedRequestAttack"),
    ("pyrit.executor.attack", "MultiPromptSendingAttack"),
    ("pyrit.executor.attack", "SequentialAttack"),
    ("pyrit.executor.attack.core.attack_executor", "AttackExecutor"),
    ("pyrit.executor.attack.multi_turn.pair", "PAIRAttack"),
    ("pyrit.models", "AttackSeedGroup"),
    ("pyrit.models", "SeedObjective"),
    ("pyrit.models", "AttackOutcome"),
    ("pyrit.score", "SelfAskTrueFalseScorer"),
    ("pyrit.score", "SelfAskRefusalScorer"),
    ("pyrit.score", "TrueFalseInverterScorer"),
]


# ═══════════════════════════════════════════════════════
# Pytest 测试类
# ═══════════════════════════════════════════════════════


class TestFullIntegration:
    """端到端流水线集成验证."""

    def test_python_compile(self):
        """1. 全量 Python 编译."""
        total, err_count, errs = _run_compile_check()
        assert err_count == 0, f"{err_count}/{total} files have compile errors: {errs}"

    def test_yaml_seeds(self):
        """2. 全量 YAML 种子验证."""
        total_seeds, errs = _run_yaml_seeds_check()
        assert not errs, f"YAML seed errors: {errs}"
        assert total_seeds > 0, "No seeds found"

    @pytest.mark.parametrize("mod_path, attr_name", IMPORT_TESTS)
    def test_import_chain(self, mod_path, attr_name):
        """3. Import 链验证."""
        mod = importlib.import_module(mod_path)
        if attr_name:
            getattr(mod, attr_name)

    @pytest.mark.parametrize("fn_name", ESC_FUNCTIONS)
    def test_escalation_functions(self, fn_name):
        """4. Escalation 函数完整性."""
        from pipeline.strike import escalation as esc

        fn = getattr(esc, fn_name, None)
        assert fn is not None and callable(fn), f"Missing: {fn_name}"

    @pytest.mark.parametrize("name, expected_in_src", CALL_CHECKS)
    def test_call_chain(self, name, expected_in_src):
        """5. check_and_escalate 调用链验证."""
        from pipeline.strike import escalation as esc

        src = inspect.getsource(esc.check_and_escalate)
        assert expected_in_src in src, f"Call chain missing: {name}"

    @pytest.mark.parametrize("text, expected", MODEL_DETECT_CASES)
    def test_model_detection(self, text, expected):
        """7. burp_parser 模型检测链路."""
        from pipeline.recon.burp_parser import _detect_model_family

        result = _detect_model_family(text)
        assert result == expected, f"detect('{text[:20]}...'): got {result}, expected {expected}"

    @pytest.mark.parametrize("mod_path, attr", PYRIT_CHECKS)
    def test_pyrit_api_compatibility(self, mod_path, attr):
        """8. PyRIT API 兼容性."""
        mod = importlib.import_module(mod_path)
        getattr(mod, attr)

    def test_encoded_variants(self):
        """10. 编码混淆函数验证."""
        from pipeline.strike.encoded_injection import generate_encoded_variants

        test_text = "system prompt reveal password admin"
        variants = generate_encoded_variants(test_text)
        # 编码变体至少 5 种 (base64, rot13, unicode_homoglyph, separator_insertion, emoji_substitution, ...)
        assert len(variants) >= 5, f"Expected at least 5 encoded variants, got {len(variants)}"
