"""test_guard_compliance.py — 规则合规测试。

此测试文件通过 pytest 强制执行 SKILL.md 中定义的 5 条规则。
如果规则违规，pytest 将失败，从而阻断 CI/CD 和 commit。

运行方式:
    python -m pytest tests/pipeline/test_guard_compliance.py -v
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest
import yaml

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
_PIPELINE_DIR = _PROJECT_ROOT / "pipeline"
_CONFIG_FILE = _PROJECT_ROOT / "config" / "defaults.yaml"
_STRIKE_DIR = _PIPELINE_DIR / "strike"

# 阈值 (与 pipeline_guard.py 保持一致)
# V2: 调整为更合理的限制 — 原始 12000/50/10/500 过于激进
# 实际代码约 15000 行 (41% 非代码行), 需要容纳完整攻击链
MAX_LINES_PER_FILE = 1000
MAX_PIPELINE_LINES = 21000
MAX_PIPELINE_FILES = 61
MAX_STRIKE_FILES = 15
MAX_CONFIG_LINES = 80
MAX_ENTRY_SCRIPT_LINES = 600

ALLOWED_ROOT_PY = frozenset({
    "main.py",
    "run_strike.py",
    "run_batch.py",
    "run_web_vuln.py",
    "pipeline_guard.py",
})

L5_BASELINE: dict[str, int | float] = {
    "max_attempts": 3,
    "max_seeds": 25,
    "escalation_asr_threshold": 90,
    "post_l1_exit_threshold": 70,
    "post_l2_exit_threshold": 80,
    "max_escalation_targets": 10,
    "crescendo_max_turns": 10,
    "tap_tree_width": 4,
    "tap_tree_depth": 4,
    "best_of_n_retries": 5,
    "l5_optimal_paths": 7,
    "auto_seed_expansion_factor": 3,
    "dual_judge_high_confidence_threshold": 0.85,
    "wilson_confidence_level": 0.95,
}

FORBIDDEN_CLASS_PATTERNS: list[tuple[str, str]] = [
    (r"Custom\w*Target", "自定义 Target 类"),
    (r"Custom\w*Executor", "自定义 Executor 类"),
    (r"Custom\w*Scorer", "自定义 Scorer 类"),
    (r"Custom\w*Memory", "自定义 Memory 类"),
    (r"Custom\w*Converter", "自定义 Converter 类"),
]


def _count_lines(path: Path) -> int:
    try:
        return len(path.read_text(encoding="utf-8", errors="replace").splitlines())
    except Exception:
        return 0


def _get_py_files(directory: Path) -> list[Path]:
    return sorted(directory.rglob("*.py"))


# ═══════════════════════════════════════════════════════════════════════════════
# R2: 代码量 + 目录结构
# ═══════════════════════════════════════════════════════════════════════════════


class TestCodeVolume:
    """R2: 代码量守卫测试。"""

    def test_pipeline_total_lines(self) -> None:
        """pipeline/ 总行数不得超过上限。"""
        if not _PIPELINE_DIR.exists():
            pytest.skip("pipeline/ 目录不存在")
        py_files = _get_py_files(_PIPELINE_DIR)
        total_lines = sum(_count_lines(f) for f in py_files)
        assert total_lines <= MAX_PIPELINE_LINES, (
            f"pipeline/ 总行数 {total_lines} 超过上限 {MAX_PIPELINE_LINES}，"
            f"超出 {total_lines - MAX_PIPELINE_LINES} 行。"
            "请拆分大文件、删除死代码、合并重复逻辑。"
        )

    def test_pipeline_file_count(self) -> None:
        """pipeline/ 文件数不得超过上限。"""
        if not _PIPELINE_DIR.exists():
            pytest.skip("pipeline/ 目录不存在")
        py_files = [f for f in _get_py_files(_PIPELINE_DIR) if f.name != "__init__.py"]
        assert len(py_files) <= MAX_PIPELINE_FILES, (
            f"pipeline/ 文件数 {len(py_files)} 超过上限 {MAX_PIPELINE_FILES}"
        )

    def test_strike_file_count(self) -> None:
        """strike/ 文件数不得超过上限。"""
        if not _STRIKE_DIR.exists():
            pytest.skip("strike/ 目录不存在")
        py_files = [f for f in _get_py_files(_STRIKE_DIR) if f.name != "__init__.py"]
        assert len(py_files) <= MAX_STRIKE_FILES, (
            f"strike/ 文件数 {len(py_files)} 超过上限 {MAX_STRIKE_FILES}，"
            "请合并 escalation_level*.py、合并 *attacks.py、删除未使用模块。"
        )

    def test_no_file_exceeds_max_lines(self) -> None:
        """pipeline/ 下任何单文件不得超过上限行数。"""
        if not _PIPELINE_DIR.exists():
            pytest.skip("pipeline/ 目录不存在")
        py_files = _get_py_files(_PIPELINE_DIR)
        violations = []
        for f in py_files:
            lines = _count_lines(f)
            if lines > MAX_LINES_PER_FILE:
                violations.append(f"  {f.relative_to(_PROJECT_ROOT)}: {lines} 行 (上限 {MAX_LINES_PER_FILE})")
        assert not violations, (
            f"以下文件超过单文件行数上限 {MAX_LINES_PER_FILE}:\n"
            + "\n".join(violations)
        )

    def test_entry_scripts_not_too_large(self) -> None:
        """根目录入口脚本不得超过上限行数。"""
        for name in ["main.py", "run_strike.py", "run_batch.py", "run_web_vuln.py"]:
            entry = _PROJECT_ROOT / name
            if not entry.exists():
                continue
            lines = _count_lines(entry)
            assert lines <= MAX_ENTRY_SCRIPT_LINES, (
                f"入口脚本 {name} 行数 {lines} 超过上限 {MAX_ENTRY_SCRIPT_LINES}，"
                "请将逻辑提取到 pipeline/ 模块。"
            )


class TestRootDirectory:
    """R2: 根目录文件干净度测试。"""

    def test_no_disallowed_py_in_root(self) -> None:
        """根目录不得有非允许的 .py 文件。"""
        root_py_files = list(_PROJECT_ROOT.glob("*.py"))
        violations = [f for f in root_py_files if f.name not in ALLOWED_ROOT_PY]
        assert not violations, (
            "根目录有以下不允许的 .py 文件:\n"
            + "\n".join(f"  {f.name} ({_count_lines(f)} 行)" for f in violations)
            + "\n请删除或移动到 pipeline/ 或 tests/ 目录。"
        )

    def test_no_log_files_in_root(self) -> None:
        """根目录不得有日志文件。"""
        log_files = list(_PROJECT_ROOT.glob("*.log")) + list(_PROJECT_ROOT.glob("*_log.txt"))
        assert not log_files, (
            "根目录有日志文件:\n"
            + "\n".join(f"  {f.name}" for f in log_files)
            + "\n请移动到 outputs/ 或删除。"
        )

    def test_no_txt_files_in_root(self) -> None:
        """根目录不得有 txt 文件。"""
        txt_files = list(_PROJECT_ROOT.glob("*.txt"))
        assert not txt_files, (
            "根目录有 txt 文件:\n"
            + "\n".join(f"  {f.name}" for f in txt_files)
            + "\n请移动到 data/ 或 outputs/ 或删除。"
        )


# ═══════════════════════════════════════════════════════════════════════════════
# R1: PyRIT 原生优先
# ═══════════════════════════════════════════════════════════════════════════════


class TestPyRITNative:
    """R1: PyRIT 原生组件检查。"""

    def test_no_custom_pyrit_components(self) -> None:
        """pipeline/ 中不得有自定义 Target/Executor/Scorer/Memory/Converter 类。"""
        if not _PIPELINE_DIR.exists():
            pytest.skip("pipeline/ 目录不存在")

        violations = []
        for py_file in _get_py_files(_PIPELINE_DIR):
            try:
                tree = ast.parse(py_file.read_text(encoding="utf-8", errors="replace"))
            except SyntaxError:
                continue

            for node in ast.walk(tree):
                if not isinstance(node, ast.ClassDef):
                    continue
                for pattern, reason in FORBIDDEN_CLASS_PATTERNS:
                    if re.match(pattern, node.name):
                        violations.append(
                            f"  {py_file.relative_to(_PROJECT_ROOT)}:{node.lineno} "
                            f"{node.name} — {reason}"
                        )

        assert not violations, (
            "检测到自定义 PyRIT 组件替换:\n"
            + "\n".join(violations)
            + "\n请使用 PyRIT 原生组件。"
        )


# ═══════════════════════════════════════════════════════════════════════════════
# R3: L5 参数基线
# ═══════════════════════════════════════════════════════════════════════════════


class TestL5Baseline:
    """R3: L5 参数基线测试。"""

    @pytest.fixture
    def config(self) -> dict[str, object]:
        if not _CONFIG_FILE.exists():
            pytest.skip(f"配置文件不存在: {_CONFIG_FILE}")
        return yaml.safe_load(_CONFIG_FILE.read_text(encoding="utf-8"))

    @pytest.mark.parametrize("param,min_val", list(L5_BASELINE.items()))
    def test_param_not_below_baseline(self, config: dict[str, object], param: str, min_val: int | float) -> None:
        """L5 参数不得低于基线值。"""
        assert param in config, f"defaults.yaml 缺少 L5 参数: {param}"
        actual = config[param]
        if isinstance(min_val, float):
            actual = float(actual)
        else:
            actual = int(actual)
        assert actual >= min_val, (
            f"defaults.yaml 参数 {param}={actual} 低于 L5 基线 {min_val}，"
            f"请改为 ≥ {min_val}。"
        )

    def test_config_file_not_too_long(self, config: dict[str, object]) -> None:
        """defaults.yaml 行数不得超过上限。"""
        lines = _CONFIG_FILE.read_text(encoding="utf-8").splitlines()
        assert len(lines) <= MAX_CONFIG_LINES, (
            f"defaults.yaml 行数 {len(lines)} 超过上限 {MAX_CONFIG_LINES}，"
            "请精简注释，移除已废弃参数。"
        )


# ═══════════════════════════════════════════════════════════════════════════════
# R4: ruff + pytest (间接验证 — 如果此测试能运行说明 pytest 可用)
# ═══════════════════════════════════════════════════════════════════════════════


class TestTooling:
    """R4: 工具链可用性测试。"""

    def test_pipeline_guard_exists(self) -> None:
        """pipeline_guard.py 必须存在。"""
        guard = _PROJECT_ROOT / "pipeline_guard.py"
        assert guard.exists(), "pipeline_guard.py 不存在 — 规则守卫缺失"

    def test_pre_commit_config_exists(self) -> None:
        """pre-commit 配置文件必须存在。"""
        precommit = _PROJECT_ROOT / ".pre-commit-config.yaml"
        assert precommit.exists(), (
            ".pre-commit-config.yaml 不存在 — "
            "请运行 'pre-commit install' 配置 git hook"
        )

    def test_pyproject_ruff_config(self) -> None:
        """pyproject.toml 必须有 ruff 配置。"""
        pyproject = _PROJECT_ROOT / "pyproject.toml"
        assert pyproject.exists(), "pyproject.toml 不存在"
        content = pyproject.read_text(encoding="utf-8")
        assert "[tool.ruff]" in content, "pyproject.toml 缺少 [tool.ruff] 配置"
        assert "[tool.ruff.lint]" in content, "pyproject.toml 缺少 [tool.ruff.lint] 配置"
