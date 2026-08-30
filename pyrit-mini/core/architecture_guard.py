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
    "pipeline",                 # 兼容别名 (策略/批量)
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
    "best_of_n_retries",
    "l5_optimal_paths",
    "escalation_asr_threshold",
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
            _CASCADE_EXCLUDE_FILES = {"__init__.py", "asr_stats.py", "asr_history.py", "judge_utils.py", "response_parser.py"}
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

    # ── 检查 13: PyRIT 原生 output 使用 (R2) ──

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

    # ── 输出 ──

    def report_text(self, show_fix_hints: bool = False) -> str:
        """生成文本报告。"""
        if not self.violations:
            return "✅ 架构契约检查通过 — 0 违规"

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
