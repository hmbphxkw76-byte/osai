"""L5 v45: SSOT 配置一致性守卫测试.

验证代码实现中的参数值与 config/defaults.yaml (SSOT) 声明一致。
任何硬编码偏离都会被此测试捕获, 防止"声明 3 实际 2"的问题再次发生。

学术依据:
    - 可复现性要求 (arXiv:2407.01232 PyRIT §5) — 参数声明与实现必须一致
    - SSOT 原则 (Single Source of Truth) — 消除配置漂移
"""

from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

import pytest
import yaml

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

_STRIKE_DIR = _PROJECT_ROOT / "pipeline" / "strike"
_CONTEXT_FILE = _PROJECT_ROOT / "pipeline" / "context.py"
_DEFAULTS_YAML = _PROJECT_ROOT / "config" / "defaults.yaml"


def _load_defaults() -> dict:
    """加载 defaults.yaml."""
    with open(_DEFAULTS_YAML, encoding="utf-8") as f:
        return yaml.safe_load(f)


class TestSSOTConsistency:
    """验证代码参数与 defaults.yaml 声明一致."""

    @pytest.fixture(autouse=True)
    def _load_config(self):
        self.defaults = _load_defaults()

    def _scan_for_hardcoded_pattern(
        self, directory: Path, pattern: str, exclude: set[str] | None = None,
    ) -> list[tuple[str, int, str]]:
        """扫描目录中所有 .py 文件, 查找硬编码模式.

        Returns:
            [(filename, line_number, line_content), ...]
        """
        exclude = exclude or set()
        hits = []
        for py_file in directory.rglob("*.py"):
            if py_file.name in exclude:
                continue
            try:
                text = py_file.read_text(encoding="utf-8")
            except Exception:
                continue
            for i, line in enumerate(text.splitlines(), 1):
                if re.search(pattern, line):
                    hits.append((py_file.name, i, line.strip()))
        return hits

    # ═══════════════════════════════════════════════════════
    # max_concurrency: 不允许硬编码 =2
    # ═══════════════════════════════════════════════════════

    def test_no_hardcoded_max_concurrency_2(self):
        """pipeline/strike/ 下不允许出现 max_concurrency=2 硬编码.

        L5 v45 修复: 所有子模块应通过 get_effective_concurrency(ctx) 读取。
        """
        hits = self._scan_for_hardcoded_pattern(
            _STRIKE_DIR,
            r"max_concurrency\s*=\s*2\b",
        )
        assert hits == [], (
            f"Found hardcoded max_concurrency=2 in: {hits}. "
            "Use get_effective_concurrency(ctx) instead."
        )

    def test_no_hardcoded_max_concurrency_or_2(self):
        """不允许 getattr(..., 'max_concurrency', None) or 2 模式."""
        hits = self._scan_for_hardcoded_pattern(
            _STRIKE_DIR,
            r"max_concurrency.*or\s+2",
        )
        assert hits == [], (
            f"Found 'or 2' fallback for max_concurrency in: {hits}. "
            "Use get_effective_concurrency(ctx) instead."
        )

    def test_get_effective_concurrency_default_matches_yaml(self):
        """get_effective_concurrency 的 default 值应与 defaults.yaml 一致."""
        from pipeline.context import get_effective_concurrency

        # Mock ctx with no args.max_concurrency
        from unittest.mock import MagicMock
        ctx = MagicMock()
        ctx.args.max_concurrency = None

        result = get_effective_concurrency(ctx)
        assert result == self.defaults.get("max_concurrency", 3), (
            f"get_effective_concurrency default={result}, "
            f"but defaults.yaml max_concurrency={self.defaults.get('max_concurrency')}"
        )

    # ═══════════════════════════════════════════════════════
    # best_of_n_retries: N=5 对齐
    # ═══════════════════════════════════════════════════════

    def test_best_of_n_default_matches_yaml(self):
        """adaptive_executor._get_best_of_n_retries 应返回 defaults.yaml 的值."""
        from pipeline.strike.adaptive_executor import _get_best_of_n_retries

        result = _get_best_of_n_retries()
        expected = self.defaults.get("best_of_n_retries", 5)
        assert result == expected, (
            f"_get_best_of_n_retries()={result}, "
            f"but defaults.yaml best_of_n_retries={expected}"
        )

    def test_best_of_n_run_attack_n_default_is_none(self):
        """run_best_of_n_attack 的 n 参数默认应为 None (从 config 读取)."""
        import inspect

        from pipeline.strike.multi_turn_attacks import run_best_of_n_attack

        sig = inspect.signature(run_best_of_n_attack)
        n_param = sig.parameters.get("n")
        assert n_param is not None, "run_best_of_n_attack should have 'n' parameter"
        assert n_param.default is None, (
            f"run_best_of_n_attack n default={n_param.default}, "
            "should be None (read from config)"
        )

    # ═══════════════════════════════════════════════════════
    # PAIR/TAP tree_depth/width: 从 config 读取
    # ═══════════════════════════════════════════════════════

    def test_pair_tree_depth_in_defaults_yaml(self):
        """defaults.yaml 应包含 pair_tree_depth."""
        assert "pair_tree_depth" in self.defaults, (
            "defaults.yaml should contain pair_tree_depth (PAIR tree depth)"
        )
        assert self.defaults["pair_tree_depth"] == 10, (
            f"pair_tree_depth={self.defaults.get('pair_tree_depth')}, expected 10"
        )

    def test_pair_tree_width_in_defaults_yaml(self):
        """defaults.yaml 应包含 pair_tree_width."""
        assert "pair_tree_width" in self.defaults
        assert self.defaults["pair_tree_width"] == 1

    def test_tap_tree_depth_matches_yaml(self):
        """defaults.yaml tap_tree_depth 应为 4."""
        assert self.defaults.get("tap_tree_depth") == 4

    def test_tap_tree_width_matches_yaml(self):
        """defaults.yaml tap_tree_width 应为 4."""
        assert self.defaults.get("tap_tree_width") == 4

    # ═══════════════════════════════════════════════════════
    # L5 基线参数验证
    # ═══════════════════════════════════════════════════════

    def test_l5_baseline_params_not_below_minimum(self):
        """L5 基线参数不得低于最小值 (SKILL.md 声明)."""
        l5_minimums = {
            "max_concurrency": 3,
            "max_attempts": 3,
            "max_seeds": 25,
            "escalation_asr_threshold": 90,
            "crescendo_max_turns": 10,
            "tap_tree_width": 4,
            "tap_tree_depth": 4,
            "best_of_n_retries": 5,
            "l5_optimal_paths": 7,
        }
        failures = []
        for key, min_val in l5_minimums.items():
            actual = self.defaults.get(key)
            if actual is None:
                failures.append(f"{key}: missing from defaults.yaml")
            elif actual < min_val:
                failures.append(f"{key}: {actual} < {min_val} (L5 minimum)")
        assert failures == [], f"L5 baseline violations: {failures}"

    # ═══════════════════════════════════════════════════════
    # 策略预设 max_concurrency 一致性
    # ═══════════════════════════════════════════════════════

    def test_all_strategy_presets_use_ssot_concurrency(self):
        """所有策略预设的 max_concurrency 应与 defaults.yaml 一致 (=3)."""
        from pipeline.strategy.presets import STRATEGY_PRESETS

        expected = self.defaults.get("max_concurrency", 3)
        violations = []
        for name, preset in STRATEGY_PRESETS.items():
            actual = preset.max_concurrency
            if actual != expected:
                violations.append(
                    f"{name}: max_concurrency={actual} (expected {expected})"
                )
        assert violations == [], (
            f"Strategy preset max_concurrency violations: {violations}"
        )

    def test_get_effective_concurrency_exists(self):
        """context.py 应导出 get_effective_concurrency 函数."""
        from pipeline.context import get_effective_concurrency
        assert callable(get_effective_concurrency)

    def test_get_config_int_exists(self):
        """context.py 应导出 _get_config_int 函数."""
        from pipeline.context import _get_config_int
        assert callable(_get_config_int)

    def test_get_config_int_reads_from_args(self):
        """_get_config_int 应从 ctx.args 读取对应属性."""
        from unittest.mock import MagicMock
        from pipeline.context import _get_config_int

        ctx = MagicMock()
        ctx.args.tap_tree_width = 4
        ctx.args.tap_tree_depth = 4

        assert _get_config_int(ctx, "tap_tree_width", 999) == 4
        assert _get_config_int(ctx, "tap_tree_depth", 999) == 4

    def test_get_config_int_fallback_on_missing(self):
        """_get_config_int 缺失时返回 default."""
        from unittest.mock import MagicMock
        from pipeline.context import _get_config_int

        ctx = MagicMock()
        ctx.args.tap_tree_width = None  # 模拟未设置

        assert _get_config_int(ctx, "tap_tree_width", 4) == 4
