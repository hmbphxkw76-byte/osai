#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass
from enum import IntEnum
from pathlib import Path

# 尝试导入 yaml (用于 R4 参数检查)
try:
    import yaml
except ImportError:
    yaml = None

# UTF-8 enforcement (Windows GBK terminal compatibility)
os.environ.setdefault("PYTHONIOENCODING", "utf-8")
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

# ═══════════════════════════════════════════════════════════════════════════════
# 配置
# ═══════════════════════════════════════════════════════════════════════════════

_PROJECT_ROOT = Path(__file__).resolve().parent.parent

# 允许在项目根目录的文件/目录 (R3)
_ALLOWED_ROOT_ENTRIES: set[str] = {
    "main.py",                 # 主入口
    "guard.py",                 # 宪法守卫入口 (guard.bat 调用)
    "guard.bat",                # 宪法守卫一键启动器
    "pyproject.toml",           # 项目配置
    ".env",                     # 环境变量
    ".gitignore",               # Git 忽略
    ".assistant_pyrit",         # AI 技能
    "config",                   # 配置目录
    "data",                     # 数据目录
    "docs",                     # 文档目录
    "outputs",                  # 输出目录
    "core",                     # 流水线核心
    "recon",                    # 侦察模块
    "arm",                      # 武器化模块
    "strike",                   # 攻击执行模块
    "assess",                   # 评分模块
    "report",                   # 报告模块
    "targets",                  # 目标适配层
    "utils",                    # 工具模块
    "tests",                    # 测试目录
    "__pycache__",              # 缓存 (会被清理)
    ".pytest_cache",            # pytest 缓存
    ".ruff_cache",              # ruff 缓存
    "pyrit_mini.egg-info",      # 安装元数据
    ".git",                     # Git 目录
    ".venv",                    # 虚拟环境
    "node_modules",             # Node 依赖
    ".idea",                    # IDE 配置
    ".vscode",                  # IDE 配置
}

# 必须使用的 PyRIT 原生攻击策略 (R6)
_REQUIRED_NATIVE_ATTACKS: dict[str, str] = {
    "PromptSendingAttack": "pyrit.executor.attack",
    "CrescendoAttack": "pyrit.executor.attack",
    "TAPAttack": "pyrit.executor.attack",
    "PAIRAttack": "pyrit.executor.attack",
    "SequentialAttack": "pyrit.executor.attack.compound.sequential_attack",
    "RedTeamingAttack": "pyrit.executor.attack",
    "SkeletonKeyAttack": "pyrit.executor.attack",
    "ManyShotJailbreakAttack": "pyrit.executor.attack",
    "MultiPromptSendingAttack": "pyrit.executor.attack",
    "ChunkedRequestAttack": "pyrit.executor.attack",
}

# 禁止的自定义类名模式 (R2)
_FORBIDDEN_CUSTOM_PATTERNS: list[tuple[str, str]] = [
    (r"class\s+\w*(Executor|CustomExecutor)\w*\s*[:({]", "禁止自定义 Executor — 必须使用 PyRIT 原生 PromptSendingAttack / AttackExecutor"),
    (r"class\s+\w*(CustomTarget|MyTarget)\w*\s*[:({]", "禁止自定义 Target — 必须使用 PyRIT 原生 HTTPTarget / OpenAIChatTarget"),
    (r"class\s+\w*(CustomScorer|MyScorer)\w*\s*[:({]", "禁止自定义 Scorer 基类 — 必须使用 PyRIT 原生 Scorer 子类"),
]

# 串联堆叠检测正则 (R6/R2)
# 匹配: ConverterConfiguration(converters=[X, Y]) — 多于 1 个 converter
_SERIAL_STACKING_PATTERN = re.compile(
    r"ConverterConfiguration\s*\(\s*converters\s*=\s*\["  # ConverterConfiguration(converters=[
    r"[^\]]*,\s*"  # 第一个 converter 后有逗号 → 至少 2 个
    r"[^\]]*\]"    # 闭合
)

# 但允许例外: 链式 SelectiveTextConverter (有条件允许)
_CHAINED_SELECTIVE_EXCEPTION = re.compile(
    r"#.*chain|.*SelectiveText.*|.*选择性.*|.*链式.*",
    re.IGNORECASE,
)

# L5 参数基线 (R4) — 值不得低于此
_L5_BASELINE: dict[str, float] = {
    "max_attempts": 3,
    "max_seeds": 25,
    "escalation_asr_threshold": 90,
    "crescendo_max_turns": 10,
    "tap_tree_width": 4,
    "tap_tree_depth": 4,
    "best_of_n_retries": 5,
    "l5_optimal_paths": 7,
    "post_l1_exit_threshold": 70,
    "post_l2_exit_threshold": 80,
    "dual_judge_high_confidence_threshold": 0.85,
    "dual_judge_disagreement_strategy": "or",  # v56: configurable aggregation
    "wilson_confidence_level": 0.95,
    "auto_seed_expansion_factor": 3,
    "max_escalation_targets": 10,
}

# 禁止硬编码的效率参数名 (R7) — 必须从 defaults.yaml 读取
_HARDCODED_PARAM_NAMES: list[str] = [
    "post_l1_exit_threshold",
    "post_l2_exit_threshold",
    "max_escalation_targets",
    "auto_seed_expansion_factor",
    "dual_judge_high_confidence_threshold",
    "dual_judge_disagreement_strategy",  # v56: must be read from config
    "best_of_n_retries",
    "l5_optimal_paths",
    "escalation_asr_threshold",
    # v53: Adaptive scenario parameters (arXiv:2407.01232)
    "adaptive_epsilon",
    "adaptive_random_seed",
    "adaptive_max_attempts",
    # v54: 配置数据流断层检测 (R9)
    "crescendo_max_turns",
    "tap_tree_width",
    "tap_tree_depth",
    "wilson_confidence_level",
]

# 安全护栏关键词 (R1) — 在攻击端不应出现
_SAFETY_GUARDRAIL_PATTERNS: list[tuple[str, str]] = [
    (r"content_filter\s*\([^)]*block|filter_harmful|safety_check|guardrail", "安全护栏逻辑 — 攻击端不得添加内容过滤/安全检查"),
    (r"if.*(?:is_harmful|is_unsafe|is_toxic|violates_safety).*:\s*(?:return|raise|block|skip)", "安全判断逻辑 — 攻击端不得判断输出是否有害并阻止"),
]

# 攻击技术关键词 (R5) — 出现这些词时需要 arXiv 引用
_TECHNIQUE_KEYWORDS: list[str] = [
    "Crescendo", "TAPAttack", "PAIRAttack", "SkeletonKey", "RedTeaming",
    "GCG", "AutoDAN", "Decomposition", "Persuasion", "BestOfN",
    "best_of_n", "crescendo", "FloatScaleThreshold",
]
_ARXIV_PATTERN = re.compile(r"arXiv:\d{4}\.\d{4,5}", re.IGNORECASE)


# ═══════════════════════════════════════════════════════════════════════════════
# 违规等级
# ═══════════════════════════════════════════════════════════════════════════════

class Severity(IntEnum):
    BLOCKING = 0      # CI 阻止合并
    WARNING = 1       # 警告但不阻止
    INFO = 2          # 信息提示


@dataclass
class Violation:
    """架构违规记录。"""
    rule: str
    severity: Severity
    file: str
    line: int
    description: str
    fix_hint: str = ""


# ═══════════════════════════════════════════════════════════════════════════════
# 检查器
# ═══════════════════════════════════════════════════════════════════════════════

class ArchitectureGuard:
    """架构契约自动验证器。"""

    def __init__(self, project_root: Path) -> None:
        self.root = project_root
        self.violations: list[Violation] = []
        self._source_files: list[Path] | None = None

    @property
    def source_files(self) -> list[Path]:
        """获取所有 Python 源文件 (排除 outputs, .venv, __pycache__)。"""
        if self._source_files is not None:
            return self._source_files

        exclude_dirs = {"outputs", ".venv", "__pycache__", ".pytest_cache",
                        ".ruff_cache", "node_modules", ".git", ".assistant_pyrit",
                        ".idea", ".vscode", "pyrit_strike.egg-info"}
        self._source_files = []
        for path in self.root.rglob("*.py"):
            if any(part in exclude_dirs for part in path.parts):
                continue
            self._source_files.append(path)
        return self._source_files

    def check_all(self) -> list[Violation]:
        """运行所有检查。"""
        self.violations.clear()
        # R6: 攻击就绪检查
        self.check_serial_stacking()
        self.check_native_attack_usage()
        self.check_native_attack_instantiation()
        self.check_native_params_from_config()
        self.check_llm_scorer_in_attack()
        self.check_cascade_order()
        # R2: 原生优先检查
        self.check_forbidden_custom_classes()
        # R3: 工程门禁检查
        self.check_root_directory()
        self.check_test_coverage()
        # R4: L5 参数基线检查
        self.check_l5_params()
        # R7: 硬编码效率参数检查
        self.check_hardcoded_params()
        self.check_intermediate_exit()
        # R5: arXiv 引用检查
        self.check_arxiv_citations()
        # R1: 安全护栏检查
        self.check_safety_guardrails()
        # R2: PyRIT 原生 output 检查
        self.check_pyrit_native_output()
        # R9: 配置数据流一致性检查
        self.check_config_data_flow()
        # R10: --dry-run 可用性检查
        self.check_dry_run_available()
        # R1/R7: 精准投放四大机制完整性检查
        self.check_precision_targeting()
        # R11: Scenario 配置合规性检查
        self.check_scenario_config()
        # T0-1: R-H1 静默降级检测 (stub / 空 return 进编排链)
        self.check_silent_degradation()
        # T0-2: R-H2 静默吞错检测 (裸 except pass)
        self.check_silent_swallowing()
        # T0-3: R-H3 双轨新增检测 (近似模块名)
        self.check_dual_track()
        return self.violations

    # ── 检查 1: Converter 串联堆叠 (R6/R2) ──

    def check_serial_stacking(self) -> None:
        """检测 ConverterConfiguration(converters=[conv1, conv2]) 串联堆叠。"""
        for path in self.source_files:
            try:
                content = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            lines = content.split("\n")
            for i, line in enumerate(lines, 1):
                # 跳过注释行和文档字符串
                stripped = line.strip()
                if stripped.startswith("#") or stripped.startswith('"""') or stripped.startswith("'''"):
                    continue

                # 检测: converters=[X, Y] 模式 (多于 1 个 converter)
                if "ConverterConfiguration" in line and "converters=[" in line:
                    # 提取 converters=[...] 内容
                    match = re.search(r"converters\s*=\s*\[(.*?)\]", line)
                    if not match:
                        continue

                    inner = match.group(1).strip()
                    # 统计逗号数量 (排除在函数调用参数内的逗号)
                    # 简化: 如果有顶层逗号 → 多于 1 个 converter
                    comma_count = self._count_top_level_commas(inner)

                    if comma_count > 0:
                        # 检查是否有例外注释 (链式 SelectiveText)
                        # 查看前后 2 行是否有例外说明
                        context = "\n".join(lines[max(0, i-3):i+2])
                        is_exempt = bool(_CHAINED_SELECTIVE_EXCEPTION.search(context))

                        if is_exempt:
                            self.violations.append(Violation(
                                rule="R6",
                                severity=Severity.WARNING,
                                file=str(path.relative_to(self.root)),
                                line=i,
                                description=f"链式 SelectiveTextConverter 串联 (条件允许): {line.strip()[:80]}",
                                fix_hint="确认链式选择性编码是有意设计，添加注释说明 ASR 理由",
                            ))
                        else:
                            self.violations.append(Violation(
                rule="R6",
                severity=Severity.BLOCKING,
                file=str(path.relative_to(self.root)),
                line=i,
                description=f"Converter 串联堆叠 (ASR 12%→4%): {line.strip()[:80]}",
                                fix_hint="改为每个 converter 独立路径: ConverterConfiguration(converters=[single_conv])",
                            ))

    @staticmethod
    def _count_top_level_commas(s: str) -> int:
        """计算顶层逗号数量 (忽略括号内的逗号)。"""
        depth = 0
        count = 0
        for char in s:
            if char in "([{":
                depth += 1
            elif char in ")]}":
                depth -= 1
            elif char == "," and depth == 0:
                count += 1
        return count

    # ── 检查 2: PyRIT 原生攻击策略使用 (R6) ──

    def check_native_attack_usage(self) -> None:
        """检测是否导入并使用了所有 7 种 PyRIT 原生攻击策略。"""
        all_imports: dict[str, set[str]] = {}  # class_name → {file, ...}

        for path in self.source_files:
            try:
                content = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            for class_name in _REQUIRED_NATIVE_ATTACKS:
                # 检测 import 语句或直接使用 (支持多行 import)
                patterns = [
                    rf"\bimport\s+{class_name}\b",
                    rf"\bfrom\s+\S+\s+import\s+\([^)]*\b{class_name}\b",  # 多行: from X import (\n  ... Class ...
                    rf"\bfrom\s+\S+\s+import\s+\S*{class_name}",           # 单行: from X import Class
                    rf"\b{class_name}\s*\(",
                    rf"\b{class_name}\b.*\bfrom_question\b",
                ]
                for pattern in patterns:
                    if re.search(pattern, content, re.DOTALL):
                        rel = str(path.relative_to(self.root))
                        all_imports.setdefault(class_name, set()).add(rel)
                        break

        for class_name, module in _REQUIRED_NATIVE_ATTACKS.items():
            if class_name not in all_imports:
                self.violations.append(Violation(
                    rule="R6",
                    severity=Severity.WARNING,
                    file="(全局)",
                    line=0,
                    description=f"未导入/使用 PyRIT 原生攻击策略: {class_name} (来自 {module})",
                    fix_hint=f"在适当的模块中添加: from {module} import {class_name}",
                ))

    # ── 检查 2a: 原生攻击实例化与执行 (R6 §6.4a) ──

    @staticmethod
    def _strip_comments_and_docstrings(content: str) -> str:
        """Remove comments and docstrings from Python source code.

        Used by check_native_attack_instantiation to avoid false positives
        from class names mentioned in comments/docstrings.
        """
        import io
        import tokenize
        try:
            tokens = list(tokenize.generate_tokens(io.StringIO(content).readline))
        except Exception:
            return content
        lines = content.splitlines(keepends=True)
        # Mark ranges to remove (comments and docstrings)
        remove_ranges: list[tuple[int, int]] = []
        for token in tokens:
            if token.type == tokenize.COMMENT:
                remove_ranges.append((token.start[0], token.end[0]))
            elif token.type == tokenize.STRING:
                # Check if it's a docstring (at module level or first statement in function/class)
                # Simple heuristic: string on its own line or preceded by whitespace only
                s = token.string
                if (s.startswith('"""') or s.startswith("'''")) and token.start[1] == 0:
                    remove_ranges.append((token.start[0], token.end[0]))
        # Build filtered content
        result_lines = []
        skip_lines: set[int] = set()
        for start, end in remove_ranges:
            for i in range(start, end + 1):
                skip_lines.add(i)
        for i, line in enumerate(lines, 1):
            if i not in skip_lines:
                # Also strip inline comments
                stripped = line.split("#")[0] if "#" in line else line
                result_lines.append(stripped)
        return "".join(result_lines)

    @staticmethod
    def _strip_string_literals(content: str) -> str:
        """Replace string literal contents with empty strings.

        Used by check_native_params_from_config to avoid false positives
        from parameter values in PoC template strings and log messages.
        Keeps the quotes to preserve line structure.
        """
        import io
        import tokenize
        try:
            tokens = list(tokenize.generate_tokens(io.StringIO(content).readline))
        except Exception:
            return content
        # Build content with string literals replaced
        result = []
        last_end = 0
        for token in tokens:
            if token.type == tokenize.STRING:
                # Find the actual position in content
                # token.start gives (row, col) — need to convert to offset
                lines = content.splitlines(keepends=True)
                offset = sum(len(lines[i]) for i in range(token.start[0] - 1)) + token.start[1]
                end_offset = sum(len(lines[i]) for i in range(token.end[0] - 1)) + token.end[1]
                result.append(content[last_end:offset])
                # Keep quote chars but remove content
                s = token.string
                if s.startswith('"""') or s.startswith("'''"):
                    result.append(s[:3] + s[-3:])
                elif s.startswith('"') or s.startswith("'"):
                    result.append(s[0] + s[-1])
                else:  # f-string, r-string, etc.
                    result.append('""')
                last_end = end_offset
        result.append(content[last_end:])
        return "".join(result)

    def check_native_attack_instantiation(self) -> None:
        """检测攻击类是否不仅被导入, 还被正确实例化和执行.

        R6 §6.4a: Importing a class is NOT sufficient — each attack MUST be
        instantiated with constructor and executed via execute_async() or
        execute_attack_from_seed_groups_async().
        """
        for path in self.source_files:
            try:
                content = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            rel = str(path.relative_to(self.root))

            # Strip comments and docstrings for import detection
            # to avoid false positives from class names mentioned in comments
            code_only = self._strip_comments_and_docstrings(content)

            for class_name in _REQUIRED_NATIVE_ATTACKS:
                # Skip SequentialAttack/SequentialChildAttack — internal composite
                if class_name in ("SequentialAttack", "SequentialChildAttack"):
                    continue

                # Check if class is imported in this file (code lines only)
                # Use negative lookahead to avoid matching substrings
                # (e.g. TAPAttackScoringConfig matching TAPAttack)
                import_patterns = [
                    rf"\bimport\s+{class_name}\b(?![A-Za-z0-9_])",
                    rf"\bfrom\s+\S+\s+import\s+\([^)]*\b{class_name}\b(?![A-Za-z0-9_])",
                    rf"\bfrom\s+\S+\s+import\s+[^,\n]*\b{class_name}\b(?![A-Za-z0-9_])",
                ]
                is_imported = any(
                    re.search(p, code_only, re.DOTALL) for p in import_patterns
                )
                if not is_imported:
                    continue

                # Check if class is instantiated ( ClassName(...) )
                instantiate_pattern = rf"\b{class_name}\s*\("
                # Also check factory registration patterns:
                # 1. attack_class=ClassName (keyword argument)
                # 2. "attack_class": ClassName (dict key-value)
                # PyRIT AttackTechniqueFactory(attack_class=ClassName) or
                # {"attack_class": ClassName} are valid instantiation patterns
                # — factory.create() calls ClassName() at runtime
                factory_pattern = rf"""["']?attack_class["']?\s*[:=]\s*\b{class_name}\b"""
                # Also check class attribute access: ClassName. (e.g. SkeletonKeyAttack.DEFAULT_PATH)
                attr_access_pattern = rf"\b{class_name}\s*\."
                is_instantiated = bool(re.search(instantiate_pattern, code_only))
                is_factory_registered = bool(re.search(factory_pattern, code_only))
                is_attr_accessed = bool(re.search(attr_access_pattern, code_only))

                if is_imported and not is_instantiated and not is_factory_registered and not is_attr_accessed:
                    self.violations.append(Violation(
                        rule="R6",
                        severity=Severity.WARNING,
                        file=rel,
                        line=content.find(class_name) and content[:content.find(class_name)].count("\n") + 1 or 0,
                        description=f"攻击类 {class_name} 已导入但未实例化 — R6 §6.4a 要求导入后必须实例化并执行",
                        fix_hint=f"添加: attack = {class_name}(objective_target=..., attack_scoring_config=...)",
                    ))

    # ── 检查 2b: 原生攻击参数来源 (R6 §6.4b) ──

    # 攻击参数名 → 允许的硬编码默认值 (用于 _get_config_int fallback)
    _ATTACK_PARAMS_TO_CHECK: dict[str, list[str]] = {
        "example_count": ["ManyShotJailbreakAttack"],
        "chunk_size": ["ChunkedRequestAttack"],
        "total_length": ["ChunkedRequestAttack"],
        "tree_width": ["TAPAttack", "PAIRAttack"],
        "tree_depth": ["TAPAttack", "PAIRAttack"],
        "max_turns": ["CrescendoAttack", "RedTeamingAttack"],
        "max_backtracks": ["CrescendoAttack"],
    }

    def check_native_params_from_config(self) -> None:
        """检测攻击参数是否从 config/defaults.yaml 读取而非硬编码.

        R6 §6.4b: Attack parameters MUST be read from config/defaults.yaml (R7 SSOT),
        NOT hardcoded in pipeline code.

        允许的例外:
        - _get_config_int(ctx, "param_name", fallback) — 从 config 读取, fallback 是允许的
        - chunk_type="characters" — 字符串常量, 非数值参数
        - on_topic_checking_enabled=False — 布尔标志, 非数值参数
        - PoC template strings (report/poc_generator.py) — generated code, not runtime
        """
        for param_name, _attack_classes in self._ATTACK_PARAMS_TO_CHECK.items():
            # Simple match: param_name=<number>
            hardcoded_pattern = rf"\b{param_name}\s*=\s*(\d+)"

            for path in self.source_files:
                # Skip config files, tests, and PoC generator (template code, not runtime)
                rel = path.relative_to(self.root)
                if "config" in rel.parts or "test" in str(rel).lower():
                    continue
                # PoC generator uses template strings with hardcoded values
                # for generated scripts — these are NOT runtime parameters
                if "poc_generator" in str(rel):
                    continue

                try:
                    content = path.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue

                # Strip comments to avoid false positives from comment lines
                code_only = self._strip_comments_and_docstrings(content)

                for match in re.finditer(hardcoded_pattern, code_only):
                    line_num = code_only[:match.start()].count("\n") + 1
                    # Check if this line has _get_config_int (already reading from config)
                    line_start = code_only.rfind("\n", 0, match.start()) + 1
                    line_end = code_only.find("\n", match.end())
                    if line_end == -1:
                        line_end = len(code_only)
                    line = code_only[line_start:line_end]

                    if "_get_config_int" in line or "_get_config_float" in line:
                        continue  # Already reading from config

                    self.violations.append(Violation(
                        rule="R6",
                        severity=Severity.WARNING,
                        file=str(rel),
                        line=line_num,
                        description=f"攻击参数 {param_name}={match.group(1)} 硬编码 — R6 §6.4b 要求从 config/defaults.yaml 读取",
                        fix_hint=f'使用: {param_name}=_get_config_int(ctx, "{param_name}", {match.group(1)})',
                    ))

    # ── 检查 3: 禁止的自定义类 (R2) ──

    def check_forbidden_custom_classes(self) -> None:
        """检测自定义 Executor/Target/Scorer 替换原生组件。"""
        for path in self.source_files:
            # 跳过非源文件
            rel = path.relative_to(self.root)
            try:
                content = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            for pattern, message in _FORBIDDEN_CUSTOM_PATTERNS:
                for match in re.finditer(pattern, content):
                    line_num = content[:match.start()].count("\n") + 1
                    # RateLimitedTarget 是允许的 enhancement
                    matched_text = match.group(0)
                    if "RateLimited" in matched_text or "ContentFilter" in matched_text:
                        continue

                    self.violations.append(Violation(
                        rule="R2",
                        severity=Severity.BLOCKING,
                        file=str(rel),
                        line=line_num,
                        description=f"{message}: {matched_text[:60]}",
                        fix_hint="改用 PyRIT 原生组件，或编写 enhancement wrapper (保持原生组件为引擎)",
                    ))

    # ── 检查 4: 项目根目录文件混乱 (R3) ──

    def check_root_directory(self) -> None:
        """检测项目根目录中的非法文件。"""
        if not self.root.exists():
            return

        for item in self.root.iterdir():
            name = item.name
            if name.startswith("."):
                name = name  # 保留点文件名

            if name not in _ALLOWED_ROOT_ENTRIES and not name.startswith("."):
                # 允许 .gitignore, .env 等
                if item.is_file() and name.endswith(".py"):
                    self.violations.append(Violation(
                rule="R3",
                severity=Severity.BLOCKING,
                file=name,
                line=0,
                description=f"根目录存在非法 .py 文件: {name}",
                        fix_hint="移动到适当的子目录 (strike/ 或 utils/ 等)，或删除",
                    ))
                elif item.is_file() and (name.endswith(".log") or name.endswith(".txt")):
                    self.violations.append(Violation(
                rule="R3",
                severity=Severity.WARNING,
                file=name,
                line=0,
                description=f"根目录存在日志/文本文件: {name}",
                        fix_hint="移动到 outputs/ 或删除",
                    ))

    # ── 检查 5: 测试覆盖率 (R3) ──

    def check_test_coverage(self) -> None:
        """检测测试目录是否存在且有测试文件。"""
        tests_dir = self.root / "tests"
        if not tests_dir.exists():
            self.violations.append(Violation(
                rule="R3",
                severity=Severity.BLOCKING,
                file="(全局)",
                line=0,
                description="tests/ 目录不存在 — 零测试覆盖率",
                fix_hint="创建 tests/ 目录，为每个模块编写 test_*.py 文件",
            ))
            return

        test_files = list(tests_dir.rglob("test_*.py"))
        if not test_files:
            self.violations.append(Violation(
                rule="R3",
                severity=Severity.BLOCKING,
                file="(全局)",
                line=0,
                description="tests/ 目录中无 test_*.py 文件 — 零测试覆盖率",
                fix_hint="为每个模块创建对应的 test_*.py 文件",
            ))

    # ── 检查 6: LLM 评分器在攻击执行期间使用 (R6/R7) ──

    def check_llm_scorer_in_attack(self) -> None:
        """检测在攻击执行路径中使用 LLM 评分器 (应使用 0-token 启发式)。"""
        attack_dirs = {"strike", "arm"}
        llm_scorer_patterns = [
            r"SelfAskTrueFalseScorer\s*\(",
            r"SelfAskRefusalScorer\s*\(",
            r"SelfAskLikertScorer\s*\(",
        ]
        # 例外: post-hoc 评分 / 多轮攻击必需的 LLM scorer 豁免
        # R6 §6.2 例外: 多轮攻击 (Crescendo/TAP/PAIR) 原生要求 LLM scorer 做迭代决策
        # R6 §6.2 例外: post-hoc 二次评分验证 (LLM-as-a-Judge) 不在攻击执行路径中
        post_hoc_exceptions = [
            "_build_scoring_config",
            "_create_objective_scorer",
            "create_objective_scorer",
            "_create_auxiliary_scorers",
            "_build_refusal_inverter_scoring_config",
            "_llm_judge_rescore",
            "_create_fallback_fsts",
            "post_hoc",
            "post-hoc",
            "fallback",
        ]

        for path in self.source_files:
            rel = path.relative_to(self.root)
            parts = rel.parts
            if not any(d in parts for d in attack_dirs):
                continue

            try:
                content = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            lines = content.split("\n")
            for i, line in enumerate(lines, 1):
                for pattern in llm_scorer_patterns:
                    if re.search(pattern, line):
                        # 检查是否在 post-hoc 函数内
                        # 向上搜索函数定义 (40 行覆盖大多数函数体)
                        func_context = "\n".join(lines[max(0, i-40):i])
                        is_exempt = any(exc in func_context for exc in post_hoc_exceptions)

                        if not is_exempt:
                            self.violations.append(Violation(
                                rule="R6",
                                severity=Severity.WARNING,
                                file=str(rel),
                                line=i,
                                description=f"攻击执行路径中使用 LLM 评分器 (浪费 token): {line.strip()[:60]}",
                                fix_hint="改用 SubStringScorer + TrueFalseInverterScorer (0 token) 做 FIRST_SUCCESS 判断",
                            ))

    # ── 检查 7: L5 参数基线 (R4) ──

    def check_l5_params(self) -> None:
        """检查 config/defaults.yaml 中的参数不低于 L5 基线。"""
        if yaml is None:
            self.violations.append(Violation(
                rule="R4",
                severity=Severity.WARNING,
                file="(全局)",
                line=0,
                description="PyYAML 未安装 — 无法检查 L5 参数基线",
                fix_hint="pip install pyyaml",
            ))
            return

        defaults_path = self.root / "config" / "defaults.yaml"
        if not defaults_path.exists():
            self.violations.append(Violation(
                rule="R4",
                severity=Severity.BLOCKING,
                file="config/defaults.yaml",
                line=0,
                description="config/defaults.yaml 不存在 — 无 L5 SSOT",
                fix_hint="创建 config/defaults.yaml 并定义所有 L5 基线参数",
            ))
            return

        try:
            with open(defaults_path, encoding="utf-8") as f:
                config = yaml.safe_load(f) or {}
        except Exception as exc:
            self.violations.append(Violation(
                rule="R4",
                severity=Severity.BLOCKING,
                file="config/defaults.yaml",
                line=0,
                description=f"defaults.yaml 解析失败: {exc}",
                fix_hint="检查 YAML 语法",
            ))
            return

        for param, baseline in _L5_BASELINE.items():
            actual = config.get(param)
            if actual is None:
                self.violations.append(Violation(
                    rule="R4",
                    severity=Severity.WARNING,
                    file="config/defaults.yaml",
                    line=0,
                    description=f"L5 参数缺失: {param} (基线值 >= {baseline})",
                    fix_hint=f"在 defaults.yaml 中添加 {param}: {baseline}",
                ))
            elif isinstance(actual, (int, float)) and actual < baseline:
                self.violations.append(Violation(
                    rule="R4",
                    severity=Severity.BLOCKING,
                    file="config/defaults.yaml",
                    line=0,
                    description=f"L5 参数低于基线: {param}={actual} (基线 >= {baseline})",
                    fix_hint=f"将 {param} 提升至 >= {baseline}",
                ))

    # ── 检查 8: 硬编码效率参数 (R7) ──

    def check_hardcoded_params(self) -> None:
        """检测在管道代码中硬编码效率参数 (应从 defaults.yaml 读取)。"""
        # 只检查管道模块，不检查 config.py / defaults.yaml 自身
        pipeline_dirs = {"strike", "arm", "assess", "recon", "report", "targets", "utils", "core"}

        for path in self.source_files:
            rel = path.relative_to(self.root)
            parts = rel.parts
            if not any(d in parts for d in pipeline_dirs):
                continue
            # 跳过 architecture_guard 自身
            if "architecture_guard" in str(rel):
                continue

            try:
                content = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            lines = content.split("\n")
            in_docstring = False
            for i, line in enumerate(lines, 1):
                stripped = line.strip()
                # 跳过注释行
                if stripped.startswith("#"):
                    continue
                # 跟踪三引号 docstring 状态
                triple_count = line.count('"""')
                if triple_count == 1:
                    in_docstring = not in_docstring
                # 跳过 docstring 内的行
                if in_docstring or (triple_count == 1 and stripped.endswith('"""')):
                    continue

                for param in _HARDCODED_PARAM_NAMES:
                    # 检测: param = <数字> (赋值，而非从 args/config 读取)
                    pattern = rf"\b{param}\s*[:=]\s*(\d+\.?\d*)"
                    match = re.search(pattern, line)
                    if match:
                        # 排除: 从 args.xxx 或 config.xxx 读取的情况
                        if f"args.{param}" in line or f"config.{param}" in line or "getattr" in line:
                            continue
                        # 排除: 注释中提到
                        if "#" in line and line.index("#") < line.index(param):
                            continue

                        self.violations.append(Violation(
                            rule="R7",
                            severity=Severity.WARNING,
                            file=str(rel),
                            line=i,
                            description=f"硬编码效率参数: {param}={match.group(1)} (应从 defaults.yaml 读取)",
                            fix_hint=f"改为从 args 或 config 读取: getattr(args, '{param}', default)",
                        ))

    # ── 检查 9: arXiv 引用缺失 (R5) ──

    def check_arxiv_citations(self) -> None:
        """检测使用攻击技术但缺少 arXiv 引用的代码。每文件每技术只报首次出现。"""
        pipeline_dirs = {"strike", "arm", "assess", "recon", "report"}

        for path in self.source_files:
            rel = path.relative_to(self.root)
            parts = rel.parts
            if not any(d in parts for d in pipeline_dirs):
                continue

            try:
                content = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            # 检查文件头部 20 行是否有全局 arXiv 引用
            lines = content.split("\n")
            header = "\n".join(lines[:20])
            has_header_arxiv = bool(_ARXIV_PATTERN.search(header))

            reported_keywords: set[str] = set()  # 已报过的关键词

            for i, line in enumerate(lines, 1):
                for keyword in _TECHNIQUE_KEYWORDS:
                    kw_lower = keyword.lower()
                    if kw_lower in reported_keywords:
                        continue
                    if kw_lower not in line.lower():
                        continue

                    # 文件头部有 arXiv 引用 → 整文件豁免
                    if has_header_arxiv:
                        reported_keywords.add(kw_lower)
                        continue

                    # 检查当前行及前后 3 行是否有 arXiv 引用
                    context = "\n".join(lines[max(0, i-3):i+3])
                    if _ARXIV_PATTERN.search(context):
                        reported_keywords.add(kw_lower)
                        continue

                    # 首次报出
                    self.violations.append(Violation(
                        rule="R5",
                        severity=Severity.WARNING,
                        file=str(rel),
                        line=i,
                        description=f"攻击技术 '{keyword}' 缺少 arXiv 引用 (首次出现于第 {i} 行)",
                        fix_hint="在文件头部或技术使用处添加: # arXiv:XXXX.XXXXX — Author et al.",
                    ))
                    reported_keywords.add(kw_lower)

    # ── 检查 10: 安全护栏检测 (R1) ──

    def check_safety_guardrails(self) -> None:
        """检测在攻击端添加的安全护栏/内容过滤逻辑。"""
        attack_dirs = {"strike", "arm"}

        for path in self.source_files:
            rel = path.relative_to(self.root)
            parts = rel.parts
            if not any(d in parts for d in attack_dirs):
                continue

            try:
                content = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            lines = content.split("\n")
            for i, line in enumerate(lines, 1):
                stripped = line.strip()
                if stripped.startswith("#"):
                    continue

                for pattern, message in _SAFETY_GUARDRAIL_PATTERNS:
                    if re.search(pattern, line, re.IGNORECASE):
                        self.violations.append(Violation(
                            rule="R1",
                            severity=Severity.BLOCKING,
                            file=str(rel),
                            line=i,
                            description=f"R1 违规: {message}: {stripped[:60]}",
                            fix_hint="删除安全护栏逻辑 — 攻击端不得添加内容过滤或安全检查",
                        ))

    # ── 检查 11: 中间退出检查点 (R7) ──

    def check_intermediate_exit(self) -> None:
        """检测 escalation.py 中是否存在 L1/L2 中间退出检查点。

        R7 要求: L1 后 ASR >= post_l1_exit_threshold → 跳过 L2-L4
                   L2 后 ASR >= post_l2_exit_threshold → 跳过 L3-L4
        缺少这些检查点会导致无条件执行全部 4 级升级, 浪费 60-80% token。
        """
        escalation_file = self.root / "strike" / "escalation.py"
        if not escalation_file.exists():
            # 尝试 pipeline/escalation.py 兼容路径
            escalation_file = self.root / "pipeline" / "escalation.py"
            if not escalation_file.exists():
                return

        try:
            content = escalation_file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return

        # 检测 post_l1 退出检查点
        has_l1_exit = bool(
            re.search(r"post_l1.*exit|_POST_L1_EXIT|post_l1_asr.*>=", content, re.IGNORECASE)
        )
        # 检测 post_l2 退出检查点
        has_l2_exit = bool(
            re.search(r"post_l2.*exit|_POST_L2_EXIT|post_l2_asr.*>=", content, re.IGNORECASE)
        )

        rel = str(escalation_file.relative_to(self.root))

        if not has_l1_exit:
            self.violations.append(Violation(
                rule="R7",
                severity=Severity.BLOCKING,
                file=rel,
                line=0,
                description="缺少 L1 中间退出检查点 (post_l1_exit_threshold) — 会无条件执行全部 4 级升级, 浪费 60-80% token",
                fix_hint="在 L1 (Crescendo+TAP+PAIR) 后添加: if post_l1_asr >= _POST_L1_EXIT_THRESHOLD: return",
            ))
        if not has_l2_exit:
            self.violations.append(Violation(
                rule="R7",
                severity=Severity.BLOCKING,
                file=rel,
                line=0,
                description="缺少 L2 中间退出检查点 (post_l2_exit_threshold) — 会无条件执行 L3-L4, 浪费 40-50% token",
                fix_hint="在 L2 (GCG+Best-of-N+Encoded) 后添加: if post_l2_asr >= _POST_L2_EXIT_THRESHOLD: return",
            ))

    # ── 检查 12: 级联评分顺序 (R6 §6.2) ──

    def check_cascade_order(self) -> None:
        """检测 LLM Judge 是否在 T0 预过滤之前被调用。

        R6 §6.2 要求: T0 (0-token) → J1 → J2 → J3 顺序执行, 不得跳过 T0。
        跳过 T0 会导致所有结果直接进入 LLM Judge, 浪费 ~30-40% 的 token。
        """
        assess_files = {"assess"}
        # T0 预过滤的关键模式 (0-token heuristic)
        t0_patterns = [
            r"_t0_refusal_check",
            r"t0_fast_path",
            r"_MultiKeywordRefusalScorer",
            r"SubStringScorer",
            r"TrueFalseInverterScorer",
        ]
        # LLM Judge 的关键模式
        llm_judge_patterns = [
            r"SelfAskTrueFalseScorer\s*\(",
            r"_init_judges",
            r"precompute_outcomes",
        ]

        for path in self.source_files:
            rel = path.relative_to(self.root)
            parts = rel.parts
            if not any(d in parts for d in assess_files):
                continue

            try:
                content = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            # 排除: __init__.py (纯 re-export) 和 asr_stats.py (纯统计工具函数)
            _CASCADE_EXCLUDE_FILES = {"__init__.py", "asr_stats.py", "asr_history.py", "asr_compute.py", "asr_tracker.py", "judge_utils.py", "response_parser.py"}
            if rel.name in _CASCADE_EXCLUDE_FILES:
                continue

            # 检查: 如果文件中同时有 LLM Judge 和 T0 模式
            has_t0 = any(re.search(p, content) for p in t0_patterns)
            has_llm_judge = any(re.search(p, content) for p in llm_judge_patterns)

            if has_llm_judge and not has_t0:
                # 该文件使用 LLM Judge 但没有 T0 预过滤
                self.violations.append(Violation(
                    rule="R6",
                    severity=Severity.WARNING,
                    file=str(rel),
                    line=0,
                    description="使用 LLM Judge 但缺少 T0 预过滤 — 跳过 T0 会浪费 ~30-40% token",
                    fix_hint="在 LLM Judge 调用前添加 T0 预过滤: _t0_refusal_check() / SubStringScorer",
                ))

    # ── 检查 13: 配置数据流一致性 (R9) ──

    def check_config_data_flow(self) -> None:
        """检测配置数据流中的三类断点 (R9)。

        R9 要求: 从 CLI/YAML → config.py → PipelineContext → 执行模块 → 日志/报告
        的完整数据流不得出现断点。检测三类系统性根因:

        根因 A — 配置读取断层: 模块用 x=5 而非 getattr(ctx.args, 'x', 5)
        根因 B — 上下文传递断层: 函数缺少 ctx 参数, 被迫硬编码 fallback
        根因 C — 可观测性断层: 日志描述硬编码而非反映真实配置
        """
        pipeline_dirs = {"strike", "arm", "assess", "recon", "report", "targets", "utils", "core"}

        # R9-A: 检测硬编码赋值 (已在 check_hardcoded_params 中部分覆盖)
        # 这里补充检测: 函数体内缺少 ctx/args 读取的硬编码赋值
        for path in self.source_files:
            rel = path.relative_to(self.root)
            parts = rel.parts
            if not any(d in parts for d in pipeline_dirs):
                continue
            if "architecture_guard" in str(rel):
                continue
            # 跳过 config.py 自身 (它是配置加载中心, 允许定义默认值)
            if rel.name == "config.py" or rel.name == "defaults.yaml":
                continue

            try:
                content = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            lines = content.split("\n")
            in_docstring = False
            for i, line in enumerate(lines, 1):
                stripped = line.strip()
                if stripped.startswith("#"):
                    continue
                triple_count = line.count('"""')
                if triple_count == 1:
                    in_docstring = not in_docstring
                if in_docstring or (triple_count == 1 and stripped.endswith('"""')):
                    continue

                # R9-A: 检测硬编码赋值模式 (扩展参数集)
                for param in _HARDCODED_PARAM_NAMES:
                    pattern = rf"\b{param}\s*[:=]\s*(\d+\.?\d*)"
                    match = re.search(pattern, line)
                    if match:
                        # 排除: 从 args.xxx / config.xxx / getattr / _resolve 读取 (动态配置读取函数)
                        if f"args.{param}" in line or f"config.{param}" in line or "getattr" in line or "_resolve(" in line:
                            continue
                        # 排除: 注释中提到
                        if "#" in line and line.index("#") < line.index(param):
                            continue
                        # 排除: 在 dict/yaml 字面量中 (如 {"param": value})
                        if "yaml" in str(rel).lower() or rel.name == "defaults.yaml":
                            continue

                        self.violations.append(Violation(
                            rule="R9",
                            severity=Severity.WARNING,
                            file=str(rel),
                            line=i,
                            description=f"配置数据流断点 A (硬编码): {param}={match.group(1)} — 应从 ctx.args 读取",
                            fix_hint=f"改为: getattr(ctx.args, '{param}', {match.group(1)}) 或从 ctx.args 读取",
                        ))

        # R9-B: 检测函数缺少 ctx 参数但硬编码 fallback
        # 模式: def _xxx(...): ... = 5  (没有 ctx 参数的函数体内硬编码效率参数)
        ctx_less_functions: list[tuple[str, str, int]] = []  # (file, func_name, line)
        for path in self.source_files:
            rel = path.relative_to(self.root)
            parts = rel.parts
            if not any(d in parts for d in pipeline_dirs):
                continue
            if "architecture_guard" in str(rel):
                continue
            if rel.name == "config.py":
                continue

            try:
                content = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            lines = content.split("\n")
            # 找到所有函数定义, 检查参数中是否有 ctx 或 context
            func_pattern = re.compile(r"^\s*(?:async\s+)?def\s+(\w+)\s*\((.*?)\)")
            for i, line in enumerate(lines, 1):
                match = func_pattern.match(line)
                if not match:
                    continue
                func_name = match.group(1)
                params = match.group(2)
                # 检查参数中是否有 ctx/context/pipeline_ctx/args
                has_ctx = any(kw in params for kw in ["ctx", "context", "pipeline_ctx", "args"])
                if has_ctx:
                    continue
                # 检查函数体内是否有硬编码效率参数 (向后扫描至下一个 def)
                func_body = []
                for j in range(i, min(i + 50, len(lines))):
                    if re.match(r"^\s*(?:async\s+)?def\s+", lines[j]):
                        break
                    func_body.append(lines[j])
                func_body_text = "\n".join(func_body)
                for param in _HARDCODED_PARAM_NAMES:
                    if re.search(rf"\b{param}\s*[:=]\s*\d+", func_body_text):
                        # 排除: 有 getattr 读取
                        if "getattr" in func_body_text and param in func_body_text:
                            continue
                        ctx_less_functions.append((str(rel), func_name, i))
                        break

        for file, func_name, line in ctx_less_functions:
            self.violations.append(Violation(
                rule="R9",
                severity=Severity.WARNING,
                file=file,
                line=line,
                description=f"配置数据流断点 B (上下文缺失): 函数 '{func_name}' 缺少 ctx 参数, 内部硬编码效率参数",
                fix_hint=f"为函数 '{func_name}' 添加 ctx 参数, 通过 getattr(ctx.args, ...) 读取配置",
            ))

        # R9-C: 检测日志/报告描述硬编码而非反映真实配置
        # 模式: log/debug/info/print 中包含效率参数的固定描述
        log_hardcode_patterns = [
            (r'(?:log(?:ger)?\.|debug\(|info\(|warning\(|print\().*?(?:max_turns|best_of_n|asr_threshold|exit_threshold|high_confidence).*?(?:=|:)?\s*\d+(?:\.\d+)?(?!["\'])', "日志硬编码效率参数值"),
            (r'f".*?(?:max_turns|best_of_n|asr_threshold).*?(?:=|:)?\s*\d+(?:\.\d+)?(?!["\'])', "f-string 中硬编码效率参数值"),
        ]
        for path in self.source_files:
            rel = path.relative_to(self.root)
            parts = rel.parts
            if not any(d in parts for d in pipeline_dirs):
                continue
            if "architecture_guard" in str(rel):
                continue

            try:
                content = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            lines = content.split("\n")
            in_docstring = False
            for i, line in enumerate(lines, 1):
                stripped = line.strip()
                if stripped.startswith("#"):
                    continue
                triple_count = line.count('"""')
                if triple_count == 1:
                    in_docstring = not in_docstring
                if in_docstring or (triple_count == 1 and stripped.endswith('"""')):
                    continue

                for pattern, message in log_hardcode_patterns:
                    if re.search(pattern, line, re.IGNORECASE):
                        # 排除 A: 显式动态读取 (getattr / args / ctx / _resolve)
                        if "getattr" in line or "args." in line or "ctx." in line or "_resolve(" in line:
                            continue

                        # 排除 B: 关键词仅出现在 f-string 插值 {} 内 — 视为动态引用
                        # 例: f"{exit_threshold:.0f}%" 虽触发正则 ":0f", 等等
                        keyword_match = re.search(
                            r"(?:max_turns|best_of_n|asr_threshold|exit_threshold|high_confidence|wilson_confidence_level|crescendo_max_turns|tap_tree_width|tap_tree_depth)",
                            line, re.IGNORECASE,
                        )
                        if keyword_match:
                            kw_start = keyword_match.start()
                            kw_end = keyword_match.end()
                            # 找出关键词左侧最近的未匹配 { 与右侧最近的 }
                            before = line[:kw_start]
                            after = line[kw_end:]
                            last_open = before.rfind("{")
                            next_close = after.find("}")
                            if last_open != -1 and next_close != -1:
                                # 确认关键词在 {param 插值内: 左有 { 且中间无 } 隔断
                                segment = line[last_open:kw_end]
                                opens = segment.count("{")
                                closes = segment.count("}")
                                # 若在 {} 内: opens > closes (缺少右侧 } 即未平衡)
                                if opens > closes:
                                    continue

                        self.violations.append(Violation(
                            rule="R9",
                            severity=Severity.INFO,
                            file=str(rel),
                            line=i,
                            description=f"配置数据流断点 C (可观测性): {message}",
                            fix_hint="日志/报告描述应引用运行时配置值, 而非硬编码数字",
                        ))
                        break  # 每行只报一次

    # ── 检查 14: PyRIT 原生 output 使用 (R2) ──

    def check_pyrit_native_output(self) -> None:
        """检测 generate_report 函数中是否调用了 PyRIT 官方 output 模块。

        R2 要求: generate_report() 必须调用 pyrit.output 官方模块
        (output_attack_async / output_scenario_async) 生成标准格式输出文件。

        缺少原生 output 会导致输出不符合 PyRIT 官方标准，
        无法证明 PyRIT 框架掌握能力 (OffSec AI-300 考试要求)。
        """
        generator_file = self.root / "report" / "generator.py"
        if not generator_file.exists():
            return

        try:
            content = generator_file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return

        rel = str(generator_file.relative_to(self.root))

        # 检测 pyrit.output 官方模块调用
        has_native_output = bool(
            re.search(
                r"from\s+report\.pyrit_native_output\s+import|"
                r"generate_native_output_files\s*\(|"
                r"from\s+pyrit\.output\s+import",
                content,
            )
        )

        if not has_native_output:
            self.violations.append(Violation(
                rule="R2",
                severity=Severity.BLOCKING,
                file=rel,
                line=0,
                description="generate_report() 未调用 PyRIT 官方 output 模块 — 输出不符合 PyRIT 原生标准",
                fix_hint="在 generate_report() 中添加: from report.pyrit_native_output import generate_native_output_files; await generate_native_output_files(...)",
            ))

    # ── 检查 15: --dry-run 可用性 (R10) ──

    def check_dry_run_available(self) -> None:
        """检测 --dry-run 参数和实现是否存在。

        R10 要求: 每次代码修改后必须运行 python main.py --dry-run --max-seeds 1
        进行零 token 流水线完整性验证。此检查确保:
        1. core/config.py 定义了 --dry-run CLI 参数
        2. main.py 实现了 dry-run 逻辑 (检查 _is_dry_run 或 dry_run 变量)
        3. dry-run 时跳过 strike 阶段 (不调用 execute_attacks/execute_text_adaptive)
        4. dry-run 时跳过 escalate 阶段 (不调用 check_and_escalate)
        """
        # 1. 检查 config.py 是否定义了 --dry-run 参数
        config_file = self.root / "core" / "config.py"
        if config_file.exists():
            try:
                config_content = config_file.read_text(encoding="utf-8", errors="replace")
                has_dry_run_arg = bool(re.search(r'"--dry-run"', config_content))
                if not has_dry_run_arg:
                    self.violations.append(Violation(
                        rule="R10",
                        severity=Severity.BLOCKING,
                        file="core/config.py",
                        line=0,
                        description="缺少 --dry-run CLI 参数定义 — R10 要求零 token 流水线验证可用",
                        fix_hint='在 parse_args() 中添加: parser.add_argument("--dry-run", action="store_true", default=False)',
                    ))
            except OSError:
                pass

        # 2. 检查 main.py 是否实现了 dry-run 逻辑
        main_file = self.root / "main.py"
        if main_file.exists():
            try:
                main_content = main_file.read_text(encoding="utf-8", errors="replace")
                has_dry_run_logic = bool(re.search(r'_is_dry_run|dry_run', main_content))
                if not has_dry_run_logic:
                    self.violations.append(Violation(
                        rule="R10",
                        severity=Severity.BLOCKING,
                        file="main.py",
                        line=0,
                        description="缺少 --dry-run 实现逻辑 — R10 要求 main.py 实现 dry-run 阶段跳过",
                        fix_hint="在 _run_single_endpoint 中添加: _is_dry_run = getattr(args, 'dry_run', False); if _is_dry_run: skip attack execution",
                    ))
                    return  # 无实现则后续检查无意义

                # 3. 检查 dry-run 时是否跳过 strike 执行
                has_strike_skip = bool(re.search(r'_is_dry_run.*execute_attacks|dry_run.*execute_text_adaptive|\[DRY-RUN\].*跳过攻击', main_content, re.IGNORECASE))
                if not has_strike_skip:
                    self.violations.append(Violation(
                        rule="R10",
                        severity=Severity.WARNING,
                        file="main.py",
                        line=0,
                        description="dry-run 模式未跳过 strike 阶段攻击执行 — 可能消耗目标 API token",
                        fix_hint="在 strike 阶段添加: if _is_dry_run: ctx.attack_results = {}; continue (跳过 execute_attacks)",
                    ))

                # 4. 检查 dry-run 时是否跳过 escalate 执行
                has_escalate_skip = bool(re.search(r'_is_dry_run.*check_and_escalate|\[DRY-RUN\].*跳过升级|dry_run.*escalate', main_content, re.IGNORECASE))
                if not has_escalate_skip:
                    self.violations.append(Violation(
                        rule="R10",
                        severity=Severity.WARNING,
                        file="main.py",
                        line=0,
                        description="dry-run 模式未跳过 escalate 阶段升级链 — 可能消耗目标 API token",
                        fix_hint="在 escalate 阶段添加: if _is_dry_run: skip check_and_escalate()",
                    ))
            except OSError:
                pass

    # ── 检查 16: 精准投放四大机制完整性 (R1/R7) ──

    def check_precision_targeting(self) -> None:
        """检测精准投放四大机制是否完整集成到主代码和流水线中.

        R1 (攻击者视角) + R7 (ASR-token-time 平衡) 要求:
        1. 三级 Converter 排序 (全局→OWASP→category) — converter_selector.py
        2. ASR 历史排序 (UCB1) — seed_ranking.py + seed_ranker.py
        3. 0% ASR 种子裁剪 — seed_ranker.py
        4. 模型特定先验 — seed_ranking.py + seed_ranker.py

        每个机制检查两个维度:
        - 机制实现存在性: 关键函数是否定义
        - 流水线集成性: 关键函数是否在 main.py 或 strike/ 中被调用
        """
        # ── 机制 1: 三级 Converter 排序 ──
        converter_selector = self.root / "arm" / "converter_selector.py"
        if converter_selector.exists():
            try:
                content = converter_selector.read_text(encoding="utf-8", errors="replace")
            except OSError:
                content = ""

            # 检查三级优先级函数是否都存在
            _required_converter_funcs = [
                ("_get_owasp_converter_priorities", "OWASP 级别 Converter 优先级"),
                ("_get_category_converter_priorities", "Category 级别 Converter 优先级"),
                ("_get_suitable_for_converter_strategy", "suitable_for 策略过滤"),
            ]
            for func_name, desc in _required_converter_funcs:
                if not re.search(rf"def\s+{func_name}\s*\(", content):
                    self.violations.append(Violation(
                        rule="R1",
                        severity=Severity.WARNING,
                        file="arm/converter_selector.py",
                        line=0,
                        description=f"精准投放-机制1 缺失: {desc} 函数 {func_name} 未定义",
                        fix_hint=f"在 arm/converter_selector.py 中实现 {func_name}()",
                    ))

            # 检查 OWASP 和 category 优先级是否在 _get_candidate_converters / _build_converter_config 中被调用
            for caller_func in ["_get_candidate_converters", "_build_converter_config"]:
                caller_match = re.search(
                    rf"def\s+{caller_func}\s*\([^)]*\).*?(?=\n    def |\nclass |\Z)",
                    content,
                    re.DOTALL,
                )
                if not caller_match:
                    continue
                caller_body = caller_match.group(0)
                if "_get_owasp_converter_priorities" not in caller_body:
                    self.violations.append(Violation(
                        rule="R1",
                        severity=Severity.WARNING,
                        file="arm/converter_selector.py",
                        line=0,
                        description=f"精准投放-机制1 集成缺口: {caller_func} 中未调用 _get_owasp_converter_priorities (OWASP 级别覆盖缺失)",
                        fix_hint=f"在 {caller_func} 中添加: owasp_priorities = _get_owasp_converter_priorities(ctx)",
                    ))
                if "_get_category_converter_priorities" not in caller_body:
                    self.violations.append(Violation(
                        rule="R1",
                        severity=Severity.WARNING,
                        file="arm/converter_selector.py",
                        line=0,
                        description=f"精准投放-机制1 集成缺口: {caller_func} 中未调用 _get_category_converter_priorities (Category 级别覆盖缺失)",
                        fix_hint=f"在 {caller_func} 中添加: category_priorities = _get_category_converter_priorities(ctx)",
                    ))

        # 检查 owasp_converter_map 和 category_converter_map 是否在 asr_priors.yaml 中定义
        priors_path = self.root / "config" / "asr_priors.yaml"
        if priors_path.exists():
            try:
                priors_content = priors_path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                priors_content = ""
            if "owasp_converter_map:" not in priors_content:
                self.violations.append(Violation(
                    rule="R1",
                    severity=Severity.WARNING,
                    file="config/asr_priors.yaml",
                    line=0,
                    description="精准投放-机制1 配置缺失: owasp_converter_map 未在 asr_priors.yaml 中定义",
                    fix_hint="在 asr_priors.yaml 中添加 owasp_converter_map 节点",
                ))
            if "category_converter_map:" not in priors_content:
                self.violations.append(Violation(
                    rule="R1",
                    severity=Severity.WARNING,
                    file="config/asr_priors.yaml",
                    line=0,
                    description="精准投放-机制1 配置缺失: category_converter_map 未在 asr_priors.yaml 中定义",
                    fix_hint="在 asr_priors.yaml 中添加 category_converter_map 节点",
                ))

        # ── 机制 2: ASR 历史排序 (UCB1) ──
        seed_ranking = self.root / "arm" / "seed_ranking.py"
        if seed_ranking.exists():
            try:
                sr_content = seed_ranking.read_text(encoding="utf-8", errors="replace")
            except OSError:
                sr_content = ""

            if not re.search(r"def\s+_rank_by_asr\s*\(", sr_content):
                self.violations.append(Violation(
                    rule="R1",
                    severity=Severity.WARNING,
                    file="arm/seed_ranking.py",
                    line=0,
                    description="精准投放-机制2 缺失: UCB1 排序函数 _rank_by_asr 未定义",
                    fix_hint="在 arm/seed_ranking.py 中实现 _rank_by_asr() (arXiv:cs/0207052)",
                ))

            # 检查 UCB 公式是否存在
            if "ucb" not in sr_content.lower() or "sqrt" not in sr_content.lower():
                self.violations.append(Violation(
                    rule="R1",
                    severity=Severity.WARNING,
                    file="arm/seed_ranking.py",
                    line=0,
                    description="精准投放-机制2 实现不完整: UCB1 公式 (avg_asr + C*sqrt(2*ln(N)/n_i)) 缺失",
                    fix_hint="在 _rank_by_asr 中实现 UCB 公式: ucb_score = asr + C * sqrt(2*ln(N)/n_i)",
                ))

        # 检查 _rank_by_asr 是否在 seed_ranker.py 中被调用
        seed_ranker = self.root / "arm" / "seed_ranker.py"
        if seed_ranker.exists():
            try:
                sk_content = seed_ranker.read_text(encoding="utf-8", errors="replace")
            except OSError:
                sk_content = ""
            if "_rank_by_asr" not in sk_content:
                self.violations.append(Violation(
                    rule="R1",
                    severity=Severity.WARNING,
                    file="arm/seed_ranker.py",
                    line=0,
                    description="精准投放-机制2 集成缺口: load_seeds 中未调用 _rank_by_asr (ASR 排序未集成到种子加载流程)",
                    fix_hint="在 load_seeds() 中添加: seed_groups = _rank_by_asr(seed_groups, asr_history)",
                ))

        # ── 机制 3: 0% ASR 种子裁剪 ──
        if seed_ranker.exists():
            if not re.search(r"def\s+_prune_zero_asr_seeds\s*\(", sk_content):
                self.violations.append(Violation(
                    rule="R7",
                    severity=Severity.WARNING,
                    file="arm/seed_ranker.py",
                    line=0,
                    description="精准投放-机制3 缺失: 0% ASR 种子裁剪函数 _prune_zero_asr_seeds 未定义",
                    fix_hint="在 arm/seed_ranker.py 中实现 _prune_zero_asr_seeds() (arXiv:cs/0207052)",
                ))
            elif "_prune_zero_asr_seeds" not in sk_content.split("def _prune_zero_asr_seeds")[0]:
                # 函数定义存在但未在 load_seeds 中调用
                # 检查 load_seeds 函数体是否调用了 _prune_zero_asr_seeds
                load_seeds_match = re.search(
                    r"def\s+load_seeds\s*\([^)]*\).*?(?=\n    def |\nclass |\Z)",
                    sk_content,
                    re.DOTALL,
                )
                if load_seeds_match and "_prune_zero_asr_seeds" not in load_seeds_match.group(0):
                    self.violations.append(Violation(
                        rule="R7",
                        severity=Severity.WARNING,
                        file="arm/seed_ranker.py",
                        line=0,
                        description="精准投放-机制3 集成缺口: load_seeds 中未调用 _prune_zero_asr_seeds (0% ASR 裁剪未集成到种子加载流程)",
                        fix_hint="在 load_seeds() 中添加: seed_groups = _prune_zero_asr_seeds(seed_groups, max_seeds)",
                    ))

        # ── 机制 4: 模型特定先验 ──
        # 检查 load_asr_priors 函数是否存在
        if not re.search(r"def\s+load_asr_priors\s*\(", sr_content):
            self.violations.append(Violation(
                rule="R1",
                severity=Severity.WARNING,
                file="arm/seed_ranking.py",
                line=0,
                description="精准投放-机制4 缺失: 模型特定先验加载函数 load_asr_priors 未定义",
                fix_hint="在 arm/seed_ranking.py 中实现 load_asr_priors() (arXiv:2402.01135)",
            ))

        # 检查 load_seeds 中是否接收并使用 model_family 参数
        if seed_ranker.exists():
            if "model_family" not in sk_content:
                self.violations.append(Violation(
                    rule="R1",
                    severity=Severity.WARNING,
                    file="arm/seed_ranker.py",
                    line=0,
                    description="精准投放-机制4 集成缺口: load_seeds 不接收 model_family 参数 (模型特定先验无法传递)",
                    fix_hint="为 load_seeds() 添加 model_family 参数, 调用 load_asr_priors(model_family)",
                ))
            else:
                # 检查 load_seeds 函数体中是否调用了 load_asr_priors
                load_seeds_match = re.search(
                    r"def\s+load_seeds\s*\([^)]*\).*?(?=\n    def |\nclass |\Z)",
                    sk_content,
                    re.DOTALL,
                )
                if load_seeds_match and "load_asr_priors" not in load_seeds_match.group(0):
                    self.violations.append(Violation(
                        rule="R1",
                        severity=Severity.WARNING,
                        file="arm/seed_ranker.py",
                        line=0,
                        description="精准投放-机制4 集成缺口: load_seeds 中未调用 load_asr_priors (模型特定先验未集成到种子加载流程)",
                        fix_hint="在 load_seeds() 中添加: priors = load_asr_priors(model_family)",
                    ))

        # 检查 main.py 中是否传递 model_family 到 load_seeds
        main_file = self.root / "main.py"
        if main_file.exists():
            try:
                main_content = main_file.read_text(encoding="utf-8", errors="replace")
            except OSError:
                main_content = ""
            if "model_family" not in main_content or "load_seeds" not in main_content:
                self.violations.append(Violation(
                    rule="R1",
                    severity=Severity.WARNING,
                    file="main.py",
                    line=0,
                    description="精准投放-机制4 流水线缺口: main.py 中未传递 model_family 到 load_seeds (模型先验数据流断裂)",
                    fix_hint="在 main.py load_seeds() 调用中添加: model_family=target_model_family",
                ))

        # 检查 update_asr_priors 是否在 main.py assess 阶段被调用
        if main_file.exists() and "update_asr_priors" not in main_content:
            self.violations.append(Violation(
                rule="R1",
                severity=Severity.WARNING,
                file="main.py",
                line=0,
                description="精准投放-机制4 闭环缺口: main.py 中未调用 update_asr_priors (EMA 跨目标知识迁移未集成)",
                fix_hint="在 assess 阶段添加: update_asr_priors(model_family, ctx.asr_per_technique)",
            ))

        # 检查 save_asr_history 是否在 main.py 中被调用 (闭环数据流)
        if main_file.exists() and "save_asr_history" not in main_content:
            self.violations.append(Violation(
                rule="R1",
                severity=Severity.WARNING,
                file="main.py",
                line=0,
                description="精准投放-机制2 闭环缺口: main.py 中未调用 save_asr_history (ASR 历史未写入, UCB 排序无数据)",
                fix_hint="在 assess 阶段添加: save_asr_history(ctx.asr_per_technique, attack_results=ctx.attack_results)",
            ))

    # ── 检查 17: Scenario 配置合规性 (R11) ──

    def check_scenario_config(self) -> None:
        """检测 Scenario 配置合规性 (v60: 使用 defaults.yaml).

        R11 要求 (v60):
        1. config/defaults.yaml 必须存在且包含 scenario_technique_filters
        2. scenario_technique_filters 必须包含至少一个攻击面映射
        3. Scenario 路由器 (core/scenario_router.py) 必须被 main.py 调用
        """
        if yaml is None:
            self.violations.append(Violation(
                rule="R11",
                severity=Severity.WARNING,
                file="(全局)",
                line=0,
                description="PyYAML 未安装 — 无法检查 Scenario 配置合规性",
                fix_hint="pip install pyyaml",
            ))
            return

        # v60: 检查 defaults.yaml 中的 scenario_technique_filters
        defaults_file = self.root / "config" / "defaults.yaml"
        if not defaults_file.exists():
            self.violations.append(Violation(
                rule="R11",
                severity=Severity.BLOCKING,
                file="config/defaults.yaml",
                line=0,
                description="defaults.yaml 不存在 — Scenario 配置无法加载",
                fix_hint="创建 config/defaults.yaml 并添加 scenario_technique_filters 节点",
            ))
            return

        # 加载并验证 YAML 格式
        try:
            with open(defaults_file, encoding="utf-8") as f:
                config = yaml.safe_load(f) or {}
        except Exception as exc:
            self.violations.append(Violation(
                rule="R11",
                severity=Severity.BLOCKING,
                file="config/defaults.yaml",
                line=0,
                description=f"defaults.yaml 解析失败: {exc}",
                fix_hint="检查 YAML 语法",
            ))
            return

        # 验证 scenario_technique_filters 节点存在
        scenario_filters = config.get("scenario_technique_filters")
        if not scenario_filters or not isinstance(scenario_filters, dict):
            self.violations.append(Violation(
                rule="R11",
                severity=Severity.BLOCKING,
                file="config/defaults.yaml",
                line=0,
                description="缺少 scenario_technique_filters 节点 — 目标感知攻击链功能不可用",
                fix_hint="在 defaults.yaml 中添加 scenario_technique_filters 节点，定义攻击面→技术标签映射",
            ))
            return

        # 验证至少有一个攻击面映射
        if len(scenario_filters) == 0:
            self.violations.append(Violation(
                rule="R11",
                severity=Severity.WARNING,
                file="config/defaults.yaml",
                line=0,
                description="scenario_technique_filters 为空 — 无攻击面映射配置",
                fix_hint="添加至少一个攻击面映射 (如 mcp_server, multi_agent_system, rag_system)",
            ))

        # 验证每个攻击面映射的必要字段
        for surface_name, surface_config in scenario_filters.items():
            if not isinstance(surface_config, dict):
                self.violations.append(Violation(
                    rule="R11",
                    severity=Severity.WARNING,
                    file="config/defaults.yaml",
                    line=0,
                    description=f"攻击面 '{surface_name}' 配置格式错误 — 必须为字典类型",
                    fix_hint=f"确保 {surface_name}: 下为键值对格式",
                ))
                continue

            # 检查 description 字段
            if "description" not in surface_config:
                self.violations.append(Violation(
                    rule="R11",
                    severity=Severity.INFO,
                    file="config/defaults.yaml",
                    line=0,
                    description=f"攻击面 '{surface_name}' 缺少 description 字段",
                    fix_hint=f"在 {surface_name} 下添加 description: <描述文本>",
                ))

        # 验证 Scenario 路由器被 main.py 调用
        main_file = self.root / "main.py"
        if main_file.exists():
            try:
                main_content = main_file.read_text(encoding="utf-8", errors="replace")
                if "scenario_router" not in main_content:
                    self.violations.append(Violation(
                        rule="R11",
                        severity=Severity.BLOCKING,
                        file="main.py",
                        line=0,
                        description="main.py 未导入 Scenario 路由器 — 目标感知攻击链未集成到流水线",
                        fix_hint="在 main.py 中添加: from core.scenario_router import get_router, apply_scenario_overrides",
                    ))
                elif "apply_scenario_overrides" not in main_content:
                    self.violations.append(Violation(
                        rule="R11",
                        severity=Severity.WARNING,
                        file="main.py",
                        line=0,
                        description="main.py 未调用 apply_scenario_overrides — Scenario 配置不会生效",
                        fix_hint="在 SYNERGY 阶段后添加: apply_scenario_overrides(ctx, scenario_config, args)",
                    ))
            except OSError:
                pass

        # 验证 core/scenario_router.py 存在
        router_file = self.root / "core" / "scenario_router.py"
        if not router_file.exists():
            self.violations.append(Violation(
                rule="R11",
                severity=Severity.BLOCKING,
                file="core/scenario_router.py",
                line=0,
                description="Scenario 路由器模块不存在 — 目标感知攻击链功能不可用",
                fix_hint="创建 core/scenario_router.py 并实现 ScenarioRouter 类",
            ))

    # ── T0-1: R-H1 静默降级检测 (Scaffold / Stub 进入编排链) ──

    # 编排语义前缀 (这些前缀暗示函数进入 run_attack_pipeline)
    _ORCHESTRATION_PREFIXES = ("run_", "execute_", "process_", "handle_", "evaluate_", "apply_")
    # 已声明的 stub 函数 (docstring 含 "STUB" / "TODO" 前缀的不报 — 显式宣告符合 C9)
    _STUB_ACKNOWLEDGED_MARKERS = ("STUB:", "STUB]", "TODO:", "FIXME:", "scaffold", "placeholder")

    def _is_stub_acknowledged(self, content: str, func_line_idx: int) -> bool:
        """检查函数 docstring 是否显式声明为 stub (符合 C9 显式 gap)。"""
        # 向后扫描 docstring 起始的三引号
        for j in range(func_line_idx, min(func_line_idx + 8, len(content.split("\n")))):
            line = content.split("\n")[j]
            if "\"\"\"" in line or "'''" in line:
                snippet = "\n".join(content.split("\n")[func_line_idx:j + 1])
                return any(m in snippet for m in self._STUB_ACKNOWLEDGED_MARKERS)
        return False

    def check_silent_degradation(self) -> None:
        """R-H1: 检测编排链中未被显式声明的静默降级 stub。

        C9 要求承认能力缺口并显式标记。若函数名暗示编排角色
        (run_/execute_/process_/handle_/evaluate_/apply_)，
        但函数体仅含 return {} / return None / pass 且未声明 STUB/TODO，
        则为 静默降级 scaffold — 编排器调用时代码表现与语义不符。
        """
        pipeline_dirs = {"strike", "arm", "assess", "recon", "report", "targets", "utils", "core"}
        for path in self.source_files:
            rel = path.relative_to(self.root)
            parts = rel.parts
            if not any(d in parts for d in pipeline_dirs):
                continue
            if "architecture_guard" in str(rel):
                continue

            try:
                content = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            lines = content.split("\n")
            func_pattern = re.compile(r"^\s*(?:async\s+)?def\s+(\w+)\s*\([^\)]*\)")

            for i, line in enumerate(lines):
                match = func_pattern.match(line)
                if not match:
                    continue
                func_name = match.group(1)
                if not any(func_name.startswith(p) for p in self._ORCHESTRATION_PREFIXES):
                    continue
                if func_name.startswith("_"):
                    continue  # 私有 helper 不报

                # 提取函数体 (直到下一个同缩进 def/EOF)
                body_lines: list[str] = []
                func_indent = len(line) - len(line.lstrip())
                for j in range(i + 1, len(lines)):
                    body_line = lines[j]
                    if not body_line.strip():
                        body_lines.append(body_line)
                        continue
                    body_indent = len(body_line) - len(body_line.lstrip())
                    if body_indent <= func_indent and body_line.strip():
                        break
                    body_lines.append(body_line)

                # 过滤空行与 docstring 行，保留实际代码
                code_only = []
                in_doc = False
                for bl in body_lines:
                    stripped = bl.strip()
                    if not stripped:
                        continue
                    if stripped.count('"""') == 1 or stripped.count("'''") == 1:
                        in_doc = not in_doc
                        continue
                    if in_doc:
                        continue
                    if stripped.startswith("#"):
                        continue
                    code_only.append(stripped)

                # stub 判定: ≤ 2 行实际代码 且 含 return {} / return None / pass + return / raise NotImplementedError
                if len(code_only) > 2:
                    continue
                has_empty_return = any(
                    rc in code_only
                    for rc in [
                        "return {}", "return None", "pass",
                        "raise NotImplementedError", "return []", "return 0",
                    ]
                )
                if not has_empty_return:
                    continue

                # 排除 docstring 显式声明的 stub
                if self._is_stub_acknowledged(content, i):
                    continue

                self.violations.append(Violation(
                    rule="R-H1",
                    severity=Severity.WARNING,
                    file=str(rel),
                    line=i + 1,
                    description=(
                        f"编排链静默降级 (R-H1): 函数 '{func_name}' 名暗示编排角色 "
                        f"但函数体仅含空 return / pass — 调用后返回无效结果"
                    ),
                    fix_hint=(
                        f"显式声明 stub: docstring 添加 'STUB: <原因>' "
                        f"或实现实际逻辑; 若已废弃请移除编排器对该函数的调用"
                    ),
                ))

    # ── T0-2: R-H2 静默吞错检测 ──

    def check_silent_swallowing(self) -> None:
        """R-H2: 检测大 try 块 + 极简 except (静默吞错/体量失衡).

        C9 要求承认能力缺口而不隐藏。若 try 块体量 >> except 块体量
        且 except 仅含 pass / ellipsis / 单行 logging, 则为例外被吞没 —
        静默吞错违反完整性。
        """
        pipeline_dirs = {"strike", "arm", "assess", "recon", "report", "targets", "utils", "core"}
        for path in self.source_files:
            rel = path.relative_to(self.root)
            parts = rel.parts
            if not any(d in parts for d in pipeline_dirs):
                continue
            if "architecture_guard" in str(rel):
                continue

            try:
                content = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            lines = content.split("\n")
            in_docstring = False

            for i, line in enumerate(lines):
                stripped = line.strip()
                if stripped.startswith("#"):
                    continue
                if stripped.count('"""') == 1 or stripped.count("'''") == 1:
                    in_docstring = not in_docstring
                if in_docstring:
                    continue

                if stripped != "try:":
                    continue

                try_indent = len(line) - len(line.lstrip())
                # 收集 try 块 + 匹配的 except 块
                try_body: list[str] = []
                except_blocks: list[list[str]] = []
                current_block: list[str] = []
                j = i + 1
                while j < len(lines):
                    bl = lines[j]
                    if not bl.strip():
                        if current_block is not None:
                            current_block.append(bl)
                        j += 1
                        continue
                    bl_indent = len(bl) - len(bl.lstrip())
                    if bl_indent <= try_indent and bl.strip():
                        break
                    # 新的 except/finally 块
                    if bl_indent == try_indent + 1 and (bl.strip().startswith("except") or bl.strip() == "finally:"):
                        if current_block:
                            if except_blocks or not try_body:
                                except_blocks.append(current_block)
                            else:
                                try_body = current_block
                        current_block = []
                        j += 1
                        continue
                    if current_block is not None:
                        current_block.append(bl)
                    j += 1
                if current_block and (except_blocks or try_body):
                    except_blocks.append(current_block)
                elif current_block and not try_body and not except_blocks:
                    try_body = current_block

                # 过滤空行统计 try 体量
                try_code = [l for l in try_body if l.strip() and not l.strip().startswith("#")]
                if len(try_code) < 3:
                    continue  # 太小不报

                for eb in except_blocks:
                    except_code = [
                        l for l in eb
                        if l.strip() and not l.strip().startswith("#")
                        and not l.strip().startswith("except") and l.strip() != "finally:"
                    ]
                    # 极简 except 判定: ≤ 1 行有效代码 且 只含 pass / ... / logging / raise 同异常
                    if len(except_code) > 1:
                        continue
                    if not except_code:
                        continue
                    ec_line = except_code[0].strip()
                    if ec_line in ("pass", "...", "continue", "return", "return None", "break"):
                        continue
                    # 单行 logging/warn 也报体量失衡
                    if re.match(r"(?:log(?:ger)?|logger|logging)\.(?:warning|info|debug|error|log)\(", ec_line):
                        continue

                    self.violations.append(Violation(
                        rule="R-H2",
                        severity=Severity.WARNING,
                        file=str(rel),
                        line=i + 1,
                        description=(
                            f"静默吞错 (R-H2): try 块 {len(try_code)} 行 vs except 块 {len(except_code)} 行 "
                            f"— 异常 #{i+1} 被静默吞没"
                        ),
                        fix_hint=(
                            "显式声明行为: except 中 log + raise 特定异常, "
                            "或文档化吞没原因 (C9 显式 gap)"
                        ),
                    ))

    # ── T0-3: R-H3 双轨新增检测 ──

    # 语义根 (模块名共享 ≥ 4 字符则触发双轨检测)
    _DUAL_TRACK_ROOTS = ("asr_manager", "judge", "escalation", "score", "response", "seed", "arm", "target", "search", "converter", "scorer")

    def check_dual_track(self) -> None:
        """R-H3: 检测新增/改名的近似模块 (双轨治理失效)。

        D-11 报告曾指出双轨新增: 模块版本迭代时保留别名/同名 manager/pipeline/export，
        导致调用方不确定应导入哪个。

        检测策略: 同包内模块文件的主干名共享语义根且非同一文件的变体（如 _base/_test）。
        仅标记 INFO — 需人工核查是否应合并/废弃/重命名。
        """
        from importlib.machinery import SOURCE_SUFFIXES

        pkg_modules: dict[str, list[tuple[str, str]]] = {}  # pkg -> [(stem, rel_path)]

        for path in self.source_files:
            rel = path.relative_to(self.root)
            parts = rel.parts
            # 只含 .py 源文件
            if not path.suffix == ".py":
                continue
            # __init__.py 忽略
            if path.name == "__init__.py":
                continue
            # core/toplevel 不在同包内不报
            if len(parts) < 2:
                continue
            pkg = parts[0]
            stem = path.stem  # e.g. "asr_manager"

            pkg_modules.setdefault(pkg, []).append((stem, str(rel)))

        # 按语义根聚类
        root_to_files: dict[str, list[str]] = {}
        for pkg, files in pkg_modules.items():
            for stem, rel_path in files:
                for root in self._DUAL_TRACK_ROOTS:
                    if stem.startswith(root) or root in stem:
                        key = f"{pkg}/{root}"
                        root_to_files.setdefault(key, []).append(rel_path)

        # 标记同语义根下超过 1 个文件且文件名差异不构成主-从关系
        for key, file_list in root_to_files.items():
            if len(file_list) < 2:
                continue
            # 排除 _test / _base / _v2 等常规变体
            main_files = [
                f for f in file_list
                if not any(suffix in f for suffix in ("_test.py", "_base.py", "_v2.py"))
            ]
            if len(main_files) < 2:
                continue

            severity = Severity.INFO
            self.violations.append(Violation(
                rule="R-H3",
                severity=severity,
                file=", ".join(main_files[:4]),
                line=0,
                description=(
                    f"双轨新增征兆 (R-H3): 语义根 '{key}' 下发现 {len(main_files)} 个近似模块 "
                    f"— {' / '.join(main_files[:4])} — 建议核查是否应合并/废弃"
                ),
                fix_hint="确认双轨职责边界; 若废弃保留模块, 请从编排链路和 import 图移除引用",
            ))

    # ── T1-3: Specs 裁决序联动 (版本读取) ──

    def _read_specs_version(self) -> str | None:
        """读取 00-CONSTITUTION.md 顶部版本号, 用于 specs-guard 联动校验。"""
        const_file = self.root / "docs" / "specs" / "00-CONSTITUTION.md"
        if not const_file.exists():
            return None
        try:
            head = const_file.read_text(encoding="utf-8", errors="replace")[:1024]
            # 优先匹配中文 "**版本**：v1.2" / "版本：v1.2"
            m = re.search(r"\*{0,2}[*]*版本[*]*\s*[:：]\s*v?(\d+\.\d+|\d+)", head)
            if not m:
                m = re.search(r"\bversion\s*[:：]\s*v?(\d+\.\d+|\d+)", head)
            return m.group(1) if m else None
        except OSError:
            return None

    @property
    def specs_version(self) -> str:
        """返回 specs 宪法版本 (懒加载, 读取失败返回 'unknown')。"""
        if not hasattr(self, "_specs_version_cached"):
            ver = self._read_specs_version()
            self._specs_version_cached = ver if ver else "unknown"
        return self._specs_version_cached

    # ── 输出 ──

    def report_text(self, show_fix_hints: bool = False) -> str:
        """生成文本报告。"""
        if not self.violations:
            return ("✅ 架构契约检查通过 — 0 违规\n"
                    f"   specs 版本: {self.specs_version}")

        blocking = [v for v in self.violations if v.severity == Severity.BLOCKING]
        warnings = [v for v in self.violations if v.severity == Severity.WARNING]
        infos = [v for v in self.violations if v.severity == Severity.INFO]

        lines = []
        lines.append(f"{'✅' if not blocking else '❌'} 架构契约检查: "
                      f"{len(blocking)} BLOCKING, {len(warnings)} WARNING, {len(infos)} INFO")
        lines.append("")

        for v in self.violations:
            severity_label = {0: "BLOCKING", 1: "WARNING", 2: "INFO"}[v.severity]
            lines.append(f"[{severity_label}] Rule {v.rule} | {v.file}:{v.line}")
            lines.append(f"  违规: {v.description}")
            if show_fix_hints and v.fix_hint:
                lines.append(f"  修复: {v.fix_hint}")
            lines.append("")

        lines.append(f"specs 版本: {self.specs_version}  (裁决序基准: 00-CONSTITUTION.md)")
        return "\n".join(lines)

    def report_json(self) -> str:
        """生成 JSON 报告 (CI 集成用)。"""
        data = {
            "summary": {
                "total": len(self.violations),
                "blocking": sum(1 for v in self.violations if v.severity == Severity.BLOCKING),
                "warning": sum(1 for v in self.violations if v.severity == Severity.WARNING),
                "info": sum(1 for v in self.violations if v.severity == Severity.INFO),
                "passed": len(self.violations) == 0 or all(
                    v.severity != Severity.BLOCKING for v in self.violations
                ),
                "specs_version": self.specs_version,
            },
            "violations": [
                {
                    "rule": v.rule,
                    "severity": Severity(v.severity).name,
                    "file": v.file,
                    "line": v.line,
                    "description": v.description,
                    "fix_hint": v.fix_hint,
                }
                for v in self.violations
            ],
        }
        return json.dumps(data, indent=2, ensure_ascii=False)


# ═══════════════════════════════════════════════════════════════════════════════
# 入口
# ═══════════════════════════════════════════════════════════════════════════════

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="架构契约自动验证")
    parser.add_argument("--fix-hints", action="store_true", help="输出修复建议")
    parser.add_argument("--rule", type=str, default=None, help="只检查指定规则 (如 R10)")
    parser.add_argument("--json", action="store_true", help="JSON 输出 (CI 集成)")
    parser.add_argument("--project-root", type=str, default=None, help="项目根目录")
    args = parser.parse_args(argv)

    root = Path(args.project_root) if args.project_root else _PROJECT_ROOT
    guard = ArchitectureGuard(root)
    guard.check_all()

    if args.rule:
        guard.violations = [v for v in guard.violations if v.rule == args.rule.upper().replace("RULE", "R")]

    if args.json:
        print(guard.report_json())
    else:
        print(guard.report_text(show_fix_hints=args.fix_hints))

    # 退出码: 0=通过, 1=有 BLOCKING 违规
    has_blocking = any(v.severity == Severity.BLOCKING for v in guard.violations)
    return 1 if has_blocking else 0


if __name__ == "__main__":
    sys.exit(main())
