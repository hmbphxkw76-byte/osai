#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import logging
import os
import re
import sys
from dataclasses import dataclass
from enum import IntEnum
from pathlib import Path

#  yaml ( R4 )
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

# ===============================================================================
# 
# ===============================================================================

_PROJECT_ROOT = Path(__file__).resolve().parent.parent

logger = logging.getLogger(__name__)

# / (R3)
_ALLOWED_ROOT_ENTRIES: set[str] = {
    "main.py",                 # 
    "guard.py",                 #  (guard.bat )
    "guard.bat",                # 
    "pyproject.toml",           # 
    ".env",                     # 
    ".gitignore",               # Git 
    ".assistant_pyrit",         # AI 
    "config",                   # 
    "data",                     # 
    "docs",                     # 
    "outputs",                  # Output directory
    "core",                     # 
    "recon",                    # 
    "arm",                      # 
    "strike",                   # 
    "assess",                   # 
    "report",                   # 
    "targets",                  # Layer
    "utils",                    # 
    "tests",                    # 
    "__pycache__",              # cache ()
    ".pytest_cache",            # pytest cache
    ".ruff_cache",              # ruff cache
    "pyrit_mini.egg-info",      # 
    ".git",                     # Git 
    ".venv",                    # 
    "node_modules",             # Node 
    ".idea",                    # IDE 
    ".vscode",                  # IDE 
}

#  PyRIT  (R6)
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

#  (R2)
_FORBIDDEN_CUSTOM_PATTERNS: list[tuple[str, str]] = [
    (r"class\s+\w*(Executor|CustomExecutor)\w*\s*[:({]", " Executor —  PyRIT  PromptSendingAttack / AttackExecutor"),
    (r"class\s+\w*(CustomTarget|MyTarget)\w*\s*[:({]", " Target —  PyRIT  HTTPTarget / OpenAIChatTarget"),
    (r"class\s+\w*(CustomScorer|MyScorer)\w*\s*[:({]", " Scorer  —  PyRIT  Scorer "),
]

#  (R6/R2)
# : ConverterConfiguration(converters=[X, Y]) —  1  converter
_SERIAL_STACKING_PATTERN = re.compile(
    r"ConverterConfiguration\s*\(\s*converters\s*=\s*\["  # ConverterConfiguration(converters=[
    r"[^\]]*,\s*"  # converter(s)  →  2 converter(s)
    r"[^\]]*\]"    # 
)

# :  SelectiveTextConverter ()
_CHAINED_SELECTIVE_EXCEPTION = re.compile(
    r"#.*chain|.*SelectiveText.*|.*.*|.*.*",
    re.IGNORECASE,
)

# ===============================================================================
# R-CONV : Converter 
# ===============================================================================

# R-CONV-1:  converter  ()
# : return [\n    _conv("X")(),\n    _conv("Y")(arg=val),\n    ...\n]
# NOTE:  converter  ( _conv("X")(arg=val))
# NOTE:  (?!def\\s) 
_MULTI_CONVERTER_RETURN_PATTERN = re.compile(
    r"def\s+(\w+)\s*\([^)]*\)[^:]*:\s*\n"  #  +  + 
    r"(?:(?!\s*def\s).)*?"                 #  return, converter(s) def
    r"return\s*\[\s*\n"                   # return [
    r"((?:\s*_conv\([^)]+\)\([^)]*?\).*\n)+)"  #  _conv("X")(...) 
    r"\s*\]",                             # ]
    re.MULTILINE | re.DOTALL,
)

# R-CONV-2:  _conv("XXX")(...)  (, )
_CONVERTER_INSTANTIATION_PATTERN = re.compile(r'_conv\([^)]+\)\([^)]*\)')

# R-CONV-3: TokenSelectionStrategy ( iron_tag )
_TOKEN_SELECTION_STRATEGY_PATTERN = re.compile(
    r'TokenSelectionStrategy\s*\(',
)

# R-CONV-4: preserve_tokens=True ( iron_tag )
_PRESERVE_TOKENS_PATTERN = re.compile(r'preserve_tokens\s*=\s*True')

# Wei et al. (arXiv:2307.15043) Layer
_WEI_MAX_STACK_DEPTH = 2  #  2 converter(s)  (1Layer, 2Layer, >2Layer)
_WEI_HARD_MAX_STACK = 3   # : 3 converter(s)

# L5  (R4) — 
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

#  (R7) —  defaults.yaml 
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
    # v54: Data flowLayer (R9)
    "crescendo_max_turns",
    "tap_tree_width",
    "tap_tree_depth",
    "wilson_confidence_level",
]

#  (R1) — 
_SAFETY_GUARDRAIL_PATTERNS: list[tuple[str, str]] = [
    (r"content_filter\s*\([^)]*block|filter_harmful|safety_check|guardrail", " — Content filtering/"),
    (r"if.*(?:is_harmful|is_unsafe|is_toxic|violates_safety).*:\s*(?:return|raise|block|skip)", " — "),
]

#  (R5) —  arXiv 
_TECHNIQUE_KEYWORDS: list[str] = [
    "Crescendo", "TAPAttack", "PAIRAttack", "SkeletonKey", "RedTeaming",
    "GCG", "AutoDAN", "Decomposition", "Persuasion", "BestOfN",
    "best_of_n", "crescendo", "FloatScaleThreshold",
]
_ARXIV_PATTERN = re.compile(r"arXiv:\d{4}\.\d{4,5}", re.IGNORECASE)


# ===============================================================================
# 
# ===============================================================================

class Severity(IntEnum):
    BLOCKING = 0      # CI 
    WARNING = 1       # 
    INFO = 2          # 


@dataclass
class Violation:
    """"""
    rule: str
    severity: Severity
    file: str
    line: int
    description: str
    fix_hint: str = ""


# ===============================================================================
# 
# ===============================================================================

class ArchitectureGuard:
    """"""

    def __init__(self, project_root: Path) -> None:
        self.root = project_root
        self.violations: list[Violation] = []
        self._source_files: list[Path] | None = None

    @property
    def source_files(self) -> list[Path]:
        """all Python  ( outputs, .venv, __pycache__)"""
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
        """all"""
        self.violations.clear()
        # R6: 
        self.check_serial_stacking()
        self.check_native_attack_usage()
        self.check_native_attack_instantiation()
        self.check_native_params_from_config()
        self.check_llm_scorer_in_attack()
        self.check_cascade_order()
        # R2: 
        self.check_forbidden_custom_classes()
        # R3: 
        self.check_root_directory()
        self.check_test_coverage()
        # R4: L5 
        self.check_l5_params()
        # R7: 
        self.check_hardcoded_params()
        self.check_intermediate_exit()
        # R5: arXiv 
        self.check_arxiv_citations()
        # R1: 
        self.check_safety_guardrails()
        # R2: PyRIT  output 
        self.check_pyrit_native_output()
        # R9: Data flow
        self.check_config_data_flow()
        # R10: --dry-run 
        self.check_dry_run_available()
        # R1/R7: 
        self.check_precision_targeting()
        # R11: Scenario 
        self.check_scenario_config()
        # T0-1: R-H1  (stub /  return )
        self.check_silent_degradation()
        # T0-2: R-H2  ( except pass)
        self.check_silent_swallowing()
        # T0-3: R-H3  ()
        self.check_dual_track()
        # R-CONV: Converter  (Wei et al. Layer)
        self.check_converter_chain_integrity()
        # ===================================================================
        # : R-PIPE / R-IMPORT / R-REDTEAM / R-EVID / R-REPORT
        # ===================================================================
        try:
            from core.architecture_guard_extended import register_extended_checks
            register_extended_checks(type(self))
            # R-PIPE: Data flow
            self.check_pipeline_integration()
            self.check_data_flow_consistency()
            # R-IMPORT: 
            self.check_circular_imports()
            self.check_dead_code()
            # R-REDTEAM: 
            self.check_best_practices()
            self.check_academic_citations()
            self.check_asr_completeness()
            # R-EVID: 
            self.check_evidence_completeness()
            # R-REPORT: 
            self.check_report_completeness()
        except ImportError:
            logger.debug("ExtendLoad (architecture_guard_extended.py )")
        return self.violations

    # ==  1: Converter  (R6/R2) ==

    def check_serial_stacking(self) -> None:
        """ ConverterConfiguration(converters=[conv1, conv2]) """
        for path in self.source_files:
            try:
                content = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            lines = content.split("\n")
            for i, line in enumerate(lines, 1):
                # Skip
                stripped = line.strip()
                if stripped.startswith("#") or stripped.startswith('"""') or stripped.startswith("'''"):
                    continue

                # : converters=[X, Y]  ( 1  converter)
                if "ConverterConfiguration" in line and "converters=[" in line:
                    #  converters=[...] 
                    match = re.search(r"converters\s*=\s*\[(.*?)\]", line)
                    if not match:
                        continue

                    inner = match.group(1).strip()
                    #  ()
                    # : Layer →  1  converter
                    comma_count = self._count_top_level_commas(inner)

                    if comma_count > 0:
                        #  ( SelectiveText)
                        #  2 
                        context = "\n".join(lines[max(0, i-3):i+2])
                        is_exempt = bool(_CHAINED_SELECTIVE_EXCEPTION.search(context))

                        if is_exempt:
                            self.violations.append(Violation(
                                rule="R6",
                                severity=Severity.WARNING,
                                file=str(path.relative_to(self.root)),
                                line=i,
                                description=f" SelectiveTextConverter  (): {line.strip()[:80]}",
                                fix_hint="Confirmation ASR ",
                            ))
                        else:
                            self.violations.append(Violation(
                rule="R6",
                severity=Severity.BLOCKING,
                file=str(path.relative_to(self.root)),
                line=i,
                description=f"Converter  (ASR 12%→4%): {line.strip()[:80]}",
                                fix_hint="converter(s) : ConverterConfiguration(converters=[single_conv])",
                            ))

    @staticmethod
    def _count_top_level_commas(s: str) -> int:
        """Layer ()"""
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

    # ==  18: Converter  (R-CONV) ==

    def check_converter_chain_integrity(self) -> None:
        """R-CONV :  converter 

        R-CONV-1:  converter  (>1 converter) — ,
                   Wei et al. (arXiv:2307.15043) Layer
        R-CONV-2:  TokenSelectionStrategy  — 
                  preserve_tokens=True  "iron_tag" , 
        R-CONV-3:  chain builder  — Ensure _build_chain_builders
                   >2 converter 
        R-CONV-4:  l5_optimal  design-for-stacking 

        Wei et al. : Layer ASR 7%, Layer 12%, Layer <4% (payload )
        pyrit-mini :  converter  + SequentialAttack FIRST_SUCCESS

        : 
        """
        chain_files = [
            p for p in self.source_files
            if "converter_chains.py" in str(p) or "converter_presets.py" in str(p)
        ]

        for path in chain_files:
            try:
                content = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            lines = content.split("\n")

            # == R-CONV-1:  converter  ==
            self._detect_multi_converter_returns(path, lines)

            # == R-CONV-2:  TokenSelectionStrategy  ==
            self._detect_orphan_token_selection(path, lines)

        # == R-CONV-3 + R-CONV-4:  chain builder  l5_optimal  ==
        self._check_chain_builder_registration_conflicts()

    def _detect_multi_converter_returns(self, path, lines: list[str]) -> None:
        """:  return [...] converter(s) _conv 

        :
        1. converter(s)
        2. converter(s) return [ 
        3.  _conv(...) 
        """
        # Step 1: 
        func_stack = []  # [(name, def_line_num, indent)]
        func_ranges = []  # [(name, start_line, end_line)]

        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith("def ") and "(" in stripped:
                name_match = re.match(r"def\s+(\w+)\s*\(", stripped)
                if name_match:
                    indent = len(line) - len(line.lstrip())
                    func_stack.append((name_match.group(1), i + 1, indent))
            elif func_stack and stripped and not stripped.startswith("#"):
                current_indent = len(line) - len(line.lstrip())
                #  <= ,  def → 
                while func_stack and current_indent <= func_stack[-1][2]:
                    if not stripped.startswith("def "):
                        name,start,ind = func_stack.pop()
                        func_ranges.append((name, start, i))
                    else:
                        break

        # 
        while func_stack:
            name, start, ind = func_stack.pop()
            func_ranges.append((name, start, len(lines)))

        # Step 2:  return [...]
        for func_name, start_line, end_line in func_ranges:
            # Skip/ ( deprecated  chain)
            if func_name.startswith("_"):
                continue

            body = lines[start_line - 1 : end_line]
            self._check_function_return_block(path, func_name, start_line, body)

    def _check_function_return_block(self, path, func_name: str, def_line: int, body: list[str]) -> None:
        """converter(s) return [...]  converter """
        i = 0
        while i < len(body):
            stripped = body[i].strip()

            #  return [  ()
            if "return" in stripped and "[" in stripped:
                if stripped.endswith("[") and "]" not in stripped:
                    #  return 
                    conv_count = 0
                    j = i + 1
                    while j < len(body):
                        inner = body[j].strip()
                        if inner == "]" or inner.startswith("]"):
                            break
                        if "_conv(" in inner and not inner.startswith("#"):
                            conv_count += 1
                        j += 1

                    self._emit_stacking_violation(path, func_name, def_line, conv_count)
                    i = j + 1
                    continue
                elif stripped.count("[") > 0 and stripped.count("]") > 0:
                    #  return [...]
                    conv_instances = re.findall(r"_conv\([^)]*\)\([^)]*\)", stripped)
                    self._emit_stacking_violation(path, func_name, def_line, len(conv_instances))

            i += 1

    def _emit_stacking_violation(self, path, func_name: str, line: int, conv_count: int) -> None:
        """ converter """
        if conv_count > _WEI_HARD_MAX_STACK:
            self.violations.append(Violation(
                rule="R-CONV-1",
                severity=Severity.BLOCKING,
                file=str(path.relative_to(self.root)),
                line=line,
                description=(
                    f" '{func_name}'  {conv_count} converter(s) (Wei et al. : "
                    f"<={_WEI_HARD_MAX_STACK}). Layer ASR <4% (payload )."
                ),
                fix_hint=(
                    f" {conv_count} converter(s) converter ,  ASR  1-2 converter(s). "
                    f",  _chained_*  l5_optimal ."
                ),
            ))
        elif conv_count > _WEI_MAX_STACK_DEPTH:
            self.violations.append(Violation(
                rule="R-CONV-1",
                severity=Severity.WARNING,
                file=str(path.relative_to(self.root)),
                line=line,
                description=(
                    f" '{func_name}'  {conv_count} converter(s) ( Wei et al. "
                    f"Layer: ASR 12%→4%)."
                ),
                fix_hint=": Ensure iron_tag .",
            ))

    def _detect_orphan_token_selection(self, path, lines: list[str]) -> None:
        """R-CONV-2:  TokenSelectionStrategy  ( preserve_tokens=True)"""
        #  TokenSelectionStrategy 
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("#") or stripped.startswith("import"):
                continue
            if "TokenSelectionStrategy" in line and "import" not in line:
                #  ( 15 )  preserve_tokens
                context_start = max(0, i - 15)
                context_end = min(len(lines), i + 5)
                context = "\n".join(lines[context_start:context_end])

                if "preserve_tokens" not in context:
                    self.violations.append(Violation(
                        rule="R-CONV-2",
                        severity=Severity.BLOCKING,
                        file=str(path.relative_to(self.root)),
                        line=i,
                        description=(
                            "TokenSelectionStrategy  preserve_tokens=True — "
                            " iron_tag , Layer ROT13 ."
                        ),
                        fix_hint=(
                            ", Layer preserve_tokens=True; "
                            " TokenSelectionStrategy  ROT13 ."
                        ),
                    ))

    def _check_chain_builder_registration_conflicts(self) -> None:
        """ _build_chain_builders  stacking  l5_optimal 

         stacking , 
        """
        chains_file = presets_file = None
        for p in self.source_files:
            if p.name == "converter_chains.py":
                chains_file = p
            elif p.name == "converter_presets.py":
                presets_file = p

        if not chains_file or not presets_file:
            return

        try:
            chains_lines = chains_file.read_text(encoding="utf-8", errors="replace").split("\n")
            presets_content = presets_file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return

        #  stacking 
        stacking_funcs: set[str] = set()
        func_stack: list[tuple[str, int, int]] = []  # (name, line, indent)

        for i, line in enumerate(chains_lines):
            stripped = line.strip()
            if stripped.startswith("def ") and "(" in stripped:
                name_match = re.match(r"def\s+(\w+)\s*\(", stripped)
                if name_match:
                    indent = len(line) - len(line.lstrip())
                    func_stack.append((name_match.group(1), i + 1, indent))
            elif func_stack and stripped and not stripped.startswith("#"):
                current_indent = len(line) - len(line.lstrip())
                while func_stack and current_indent <= func_stack[-1][2]:
                    if not stripped.startswith("def "):
                        name,start,ind = func_stack.pop()
                        body_lines = chains_lines[start - 1:i]
                        self._count_conv_in_func_body(name, body_lines, stacking_funcs)
                    else:
                        break

        while func_stack:
            name,start,ind = func_stack.pop()
            body_lines = chains_lines[start - 1:len(chains_lines)]
            self._count_conv_in_func_body(name, body_lines, stacking_funcs)

        if not stacking_funcs:
            return

        #  _build_chain_builders 
        builder_block_match = re.search(
            r"def _build_chain_builders.*?return\s*\{(.*?)\}",
            presets_content,
            re.DOTALL,
        )
        if not builder_block_match:
            return

        builder_block = builder_block_match.group(1)
        for func_name in stacking_funcs:
            if f'"{func_name}"' not in builder_block and f"'{func_name}'" not in builder_block:
                continue

            #  l5_optimal 
            l5_optimal_block_match = re.search(
                r"def l5_optimal.*?from arm\.converter_chains import \((.*?)\)",
                presets_content,
                re.DOTALL,
            )
            if l5_optimal_block_match:
                l5_imports = l5_optimal_block_match.group(1)
                if func_name not in l5_imports:
                    #  builder 
                    idx = builder_block.find(func_name)
                    if idx >= 0:
                        abs_pos = builder_block_match.start(1) + idx
                        line_num = presets_content[:abs_pos].count("\n") + 1
                    else:
                        line_num = 0

                    self.violations.append(Violation(
                        rule="R-CONV-3",
                        severity=Severity.WARNING,
                        file=str(presets_file.relative_to(self.root)),
                        line=line_num,
                        description=(
                            f"Chain builder  '{func_name}' (converter(s), ) "
                            f" l5_optimal .  chain Layer."
                        ),
                        fix_hint=(
                            f"imports _build_chain_builders , "
                            f" docstring  'NOT FOR L5 OPTIMAL - STACKING SEMANTICS'."
                        ),
                    ))

    def _count_conv_in_func_body(self, func_name: str, body_lines: list[str], stacking_funcs: set[str]) -> None:
        """ return [...]  _conv ,  stacking_funcs"""
        # Skip
        if func_name.startswith("_"):
            return

        i = 0
        while i < len(body_lines):
            line = body_lines[i]
            stripped = line.strip()

            #  return [ 
            if "return" in stripped and "[" in stripped and stripped.endswith("["):
                conv_count = 0
                j = i + 1
                while j < len(body_lines):
                    inner = body_lines[j].strip()
                    if inner == "]" or inner.startswith("]"):
                        break
                    if "_conv(" in inner and not inner.startswith("#"):
                        conv_count += 1
                    j += 1

                if conv_count > _WEI_MAX_STACK_DEPTH:
                    stacking_funcs.add(func_name)
                return  #  return , converter(s)

            i += 1

    # ==  2: PyRIT  (R6) ==

    def check_native_attack_usage(self) -> None:
        """fromall 7  PyRIT """
        all_imports: dict[str, set[str]] = {}  # class_name → {file, ...}

        for path in self.source_files:
            try:
                content = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            for class_name in _REQUIRED_NATIVE_ATTACKS:
                #  import  ( import)
                patterns = [
                    rf"\bimport\s+{class_name}\b",
                    rf"\bfrom\s+\S+\s+import\s+\([^)]*\b{class_name}\b",  # : from X import (\n  ... Class ...
                    rf"\bfrom\s+\S+\s+import\s+\S*{class_name}",           # : from X import Class
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
                    file="()",
                    line=0,
                    description=f"from/ PyRIT : {class_name} ( {module})",
                    fix_hint=f": from {module} import {class_name}",
                ))

    # ==  2a:  (R6 §6.4a) ==

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
        """from, .

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
                        description=f" {class_name} from — R6 §6.4a fromand performs",
                        fix_hint=f": attack = {class_name}(objective_target=..., attack_scoring_config=...)",
                    ))

    # ==  2b:  (R6 §6.4b) ==

    #  →  ( _get_config_int fallback)
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
        """imports config/defaults.yaml .

        R6 §6.4b: Attack parameters MUST be read from config/defaults.yaml (R7 SSOT),
        NOT hardcoded in pipeline code.

        :
        - _get_config_int(ctx, "param_name", fallback) — imports config , fallback 
        - chunk_type="characters" — , 
        - on_topic_checking_enabled=False — , 
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
                        description=f" {param_name}={match.group(1)}  — R6 §6.4b imports config/defaults.yaml ",
                        fix_hint=f': {param_name}=_get_config_int(ctx, "{param_name}", {match.group(1)})',
                    ))

    # ==  3:  (R2) ==

    def check_forbidden_custom_classes(self) -> None:
        """ Executor/Target/Scorer """
        for path in self.source_files:
            # Skip
            rel = path.relative_to(self.root)
            try:
                content = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            for pattern, message in _FORBIDDEN_CUSTOM_PATTERNS:
                for match in re.finditer(pattern, content):
                    line_num = content[:match.start()].count("\n") + 1
                    # RateLimitedTarget  enhancement
                    matched_text = match.group(0)
                    if "RateLimited" in matched_text or "ContentFilter" in matched_text:
                        continue

                    self.violations.append(Violation(
                        rule="R2",
                        severity=Severity.BLOCKING,
                        file=str(rel),
                        line=line_num,
                        description=f"{message}: {matched_text[:60]}",
                        fix_hint=" PyRIT  enhancement wrapper ()",
                    ))

    # ==  4:  (R3) ==

    def check_root_directory(self) -> None:
        """"""
        if not self.root.exists():
            return

        for item in self.root.iterdir():
            name = item.name
            if name.startswith("."):
                name = name  # 

            if name not in _ALLOWED_ROOT_ENTRIES and not name.startswith("."):
                #  .gitignore, .env 
                if item.is_file() and name.endswith(".py"):
                    self.violations.append(Violation(
                rule="R3",
                severity=Severity.BLOCKING,
                file=name,
                line=0,
                description=f" .py : {name}",
                        fix_hint=" (strike/  utils/ )",
                    ))
                elif item.is_file() and (name.endswith(".log") or name.endswith(".txt")):
                    self.violations.append(Violation(
                rule="R3",
                severity=Severity.WARNING,
                file=name,
                line=0,
                description=f"/: {name}",
                        fix_hint=" outputs/ ",
                    ))

    # ==  5:  (R3) ==

    def check_test_coverage(self) -> None:
        """"""
        tests_dir = self.root / "tests"
        if not tests_dir.exists():
            self.violations.append(Violation(
                rule="R3",
                severity=Severity.BLOCKING,
                file="()",
                line=0,
                description="tests/  — ",
                fix_hint=" tests/ converter(s) test_*.py ",
            ))
            return

        test_files = list(tests_dir.rglob("test_*.py"))
        if not test_files:
            self.violations.append(Violation(
                rule="R3",
                severity=Severity.BLOCKING,
                file="()",
                line=0,
                description="tests/  test_*.py  — ",
                fix_hint="converter(s) test_*.py ",
            ))

    # ==  6: LLM  (R6/R7) ==

    def check_llm_scorer_in_attack(self) -> None:
        """ LLM  ( 0-token )"""
        attack_dirs = {"strike", "arm"}
        llm_scorer_patterns = [
            r"SelfAskTrueFalseScorer\s*\(",
            r"SelfAskRefusalScorer\s*\(",
            r"SelfAskLikertScorer\s*\(",
        ]
        # : post-hoc  /  LLM scorer 
        # R6 §6.2 :  (Crescendo/TAP/PAIR)  LLM scorer 
        # R6 §6.2 : post-hoc  (LLM-as-a-Judge) 
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
                        #  post-hoc 
                        #  (40 )
                        func_context = "\n".join(lines[max(0, i-40):i])
                        is_exempt = any(exc in func_context for exc in post_hoc_exceptions)

                        if not is_exempt:
                            self.violations.append(Violation(
                                rule="R6",
                                severity=Severity.WARNING,
                                file=str(rel),
                                line=i,
                                description=f" LLM  ( token): {line.strip()[:60]}",
                                fix_hint=" SubStringScorer + TrueFalseInverterScorer (0 token)  FIRST_SUCCESS ",
                            ))

    # ==  7: L5  (R4) ==

    def check_l5_params(self) -> None:
        """ config/defaults.yaml  L5 """
        if yaml is None:
            self.violations.append(Violation(
                rule="R4",
                severity=Severity.WARNING,
                file="()",
                line=0,
                description="PyYAML  —  L5 ",
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
                description="config/defaults.yaml  —  L5 SSOT",
                fix_hint=" config/defaults.yaml all L5 ",
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
                description=f"defaults.yaml : {exc}",
                fix_hint=" YAML ",
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
                    description=f"L5 : {param} ( >= {baseline})",
                    fix_hint=f" defaults.yaml  {param}: {baseline}",
                ))
            elif isinstance(actual, (int, float)) and actual < baseline:
                self.violations.append(Violation(
                    rule="R4",
                    severity=Severity.BLOCKING,
                    file="config/defaults.yaml",
                    line=0,
                    description=f"L5 : {param}={actual} ( >= {baseline})",
                    fix_hint=f" {param}  >= {baseline}",
                ))

    # ==  8:  (R7) ==

    def check_hardcoded_params(self) -> None:
        """ (imports defaults.yaml )"""
        #  config.py / defaults.yaml 
        pipeline_dirs = {"strike", "arm", "assess", "recon", "report", "targets", "utils", "core"}

        for path in self.source_files:
            rel = path.relative_to(self.root)
            parts = rel.parts
            if not any(d in parts for d in pipeline_dirs):
                continue
            # Skip architecture_guard 
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
                # Skip
                if stripped.startswith("#"):
                    continue
                #  docstring 
                triple_count = line.count('"""')
                if triple_count == 1:
                    in_docstring = not in_docstring
                # Skip docstring 
                if in_docstring or (triple_count == 1 and stripped.endswith('"""')):
                    continue

                for param in _HARDCODED_PARAM_NAMES:
                    # : param = <> ( args/config )
                    pattern = rf"\b{param}\s*[:=]\s*(\d+\.?\d*)"
                    match = re.search(pattern, line)
                    if match:
                        # :  args.xxx  config.xxx 
                        if f"args.{param}" in line or f"config.{param}" in line or "getattr" in line:
                            continue
                        # : 
                        if "#" in line and line.index("#") < line.index(param):
                            continue

                        self.violations.append(Violation(
                            rule="R7",
                            severity=Severity.WARNING,
                            file=str(rel),
                            line=i,
                            description=f": {param}={match.group(1)} (imports defaults.yaml )",
                            fix_hint=f"imports args  config : getattr(args, '{param}', default)",
                        ))

    # ==  9: arXiv  (R5) ==

    def check_arxiv_citations(self) -> None:
        """ arXiv """
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

            #  20  arXiv 
            lines = content.split("\n")
            header = "\n".join(lines[:20])
            has_header_arxiv = bool(_ARXIV_PATTERN.search(header))

            reported_keywords: set[str] = set()  # 

            for i, line in enumerate(lines, 1):
                for keyword in _TECHNIQUE_KEYWORDS:
                    kw_lower = keyword.lower()
                    if kw_lower in reported_keywords:
                        continue
                    if kw_lower not in line.lower():
                        continue

                    #  arXiv  → 
                    if has_header_arxiv:
                        reported_keywords.add(kw_lower)
                        continue

                    #  3  arXiv 
                    context = "\n".join(lines[max(0, i-3):i+3])
                    if _ARXIV_PATTERN.search(context):
                        reported_keywords.add(kw_lower)
                        continue

                    # 
                    self.violations.append(Violation(
                        rule="R5",
                        severity=Severity.WARNING,
                        file=str(rel),
                        line=i,
                        description=f" '{keyword}'  arXiv  ( {i} )",
                        fix_hint=": # arXiv:XXXX.XXXXX — Author et al.",
                    ))
                    reported_keywords.add(kw_lower)

    # ==  10:  (R1) ==

    def check_safety_guardrails(self) -> None:
        """/Content filtering"""
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
                            description=f"R1 : {message}: {stripped[:60]}",
                            fix_hint=" — Content filtering",
                        ))

    # ==  11:  (R7) ==

    def check_intermediate_exit(self) -> None:
        """ escalation.py  L1/L2 

        R7 : L1  ASR >= post_l1_exit_threshold → Skip L2-L4
                   L2  ASR >= post_l2_exit_threshold → Skip L3-L4
         4 ,  60-80% token
        """
        escalation_file = self.root / "strike" / "escalation.py"
        if not escalation_file.exists():
            #  pipeline/escalation.py 
            escalation_file = self.root / "pipeline" / "escalation.py"
            if not escalation_file.exists():
                return

        try:
            content = escalation_file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return

        #  post_l1 
        has_l1_exit = bool(
            re.search(r"post_l1.*exit|_POST_L1_EXIT|post_l1_asr.*>=", content, re.IGNORECASE)
        )
        #  post_l2 
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
                description=" L1  (post_l1_exit_threshold) —  4 ,  60-80% token",
                fix_hint=" L1 (Crescendo+TAP+PAIR) : if post_l1_asr >= _POST_L1_EXIT_THRESHOLD: return",
            ))
        if not has_l2_exit:
            self.violations.append(Violation(
                rule="R7",
                severity=Severity.BLOCKING,
                file=rel,
                line=0,
                description=" L2  (post_l2_exit_threshold) —  L3-L4,  40-50% token",
                fix_hint=" L2 (GCG+Best-of-N+Encoded) : if post_l2_asr >= _POST_L2_EXIT_THRESHOLD: return",
            ))

    # ==  12:  (R6 §6.2) ==

    def check_cascade_order(self) -> None:
        """ LLM Judge  T0 

        R6 §6.2 : T0 (0-token) → J1 → J2 → J3 , Skip T0
        Skip T0 all LLM Judge,  ~30-40%  token
        """
        assess_files = {"assess"}
        # T0  (0-token heuristic)
        t0_patterns = [
            r"_t0_refusal_check",
            r"t0_fast_path",
            r"_MultiKeywordRefusalScorer",
            r"SubStringScorer",
            r"TrueFalseInverterScorer",
        ]
        # LLM Judge 
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

            # : __init__.py ( re-export)  asr_stats.py ()
            _CASCADE_EXCLUDE_FILES = {"__init__.py", "asr_stats.py", "asr_history.py", "asr_compute.py", "asr_tracker.py", "judge_utils.py", "response_parser.py"}
            if rel.name in _CASCADE_EXCLUDE_FILES:
                continue

            # :  LLM Judge  T0 
            has_t0 = any(re.search(p, content) for p in t0_patterns)
            has_llm_judge = any(re.search(p, content) for p in llm_judge_patterns)

            if has_llm_judge and not has_t0:
                #  LLM Judge  T0 
                self.violations.append(Violation(
                    rule="R6",
                    severity=Severity.WARNING,
                    file=str(rel),
                    line=0,
                    description=" LLM Judge  T0  — Skip T0  ~30-40% token",
                    fix_hint=" LLM Judge  T0 : _t0_refusal_check() / SubStringScorer",
                ))

    # ==  13: Data flow (R9) ==

    def check_config_data_flow(self) -> None:
        """Data flow (R9)

        R9 : imports CLI/YAML → config.py → PipelineContext →  → /
        Data flow:

         A — Layer:  x=5  getattr(ctx.args, 'x', 5)
         B — Layer:  ctx ,  fallback
         C — Layer: 
        """
        pipeline_dirs = {"strike", "arm", "assess", "recon", "report", "targets", "utils", "core"}

        # R9-A:  ( check_hardcoded_params )
        # :  ctx/args 
        for path in self.source_files:
            rel = path.relative_to(self.root)
            parts = rel.parts
            if not any(d in parts for d in pipeline_dirs):
                continue
            if "architecture_guard" in str(rel):
                continue
            # Skip config.py  (, )
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

                # R9-A:  ()
                for param in _HARDCODED_PARAM_NAMES:
                    pattern = rf"\b{param}\s*[:=]\s*(\d+\.?\d*)"
                    match = re.search(pattern, line)
                    if match:
                        # :  args.xxx / config.xxx / getattr / _resolve  ()
                        if f"args.{param}" in line or f"config.{param}" in line or "getattr" in line or "_resolve(" in line:
                            continue
                        # : 
                        if "#" in line and line.index("#") < line.index(param):
                            continue
                        # :  dict/yaml  ( {"param": value})
                        if "yaml" in str(rel).lower() or rel.name == "defaults.yaml":
                            continue

                        self.violations.append(Violation(
                            rule="R9",
                            severity=Severity.WARNING,
                            file=str(rel),
                            line=i,
                            description=f"Data flow A (): {param}={match.group(1)} — imports ctx.args ",
                            fix_hint=f": getattr(ctx.args, '{param}', {match.group(1)}) imports ctx.args ",
                        ))

        # R9-B:  ctx  fallback
        # : def _xxx(...): ... = 5  ( ctx )
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
            # ,  ctx  context
            func_pattern = re.compile(r"^\s*(?:async\s+)?def\s+(\w+)\s*\((.*?)\)")
            for i, line in enumerate(lines, 1):
                match = func_pattern.match(line)
                if not match:
                    continue
                func_name = match.group(1)
                params = match.group(2)
                #  ctx/context/pipeline_ctx/args
                has_ctx = any(kw in params for kw in ["ctx", "context", "pipeline_ctx", "args"])
                if has_ctx:
                    continue
                #  ( def)
                func_body = []
                for j in range(i, min(i + 50, len(lines))):
                    if re.match(r"^\s*(?:async\s+)?def\s+", lines[j]):
                        break
                    func_body.append(lines[j])
                func_body_text = "\n".join(func_body)
                for param in _HARDCODED_PARAM_NAMES:
                    if re.search(rf"\b{param}\s*[:=]\s*\d+", func_body_text):
                        # :  getattr 
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
                description=f"Data flow B ():  '{func_name}'  ctx , ",
                fix_hint=f" '{func_name}'  ctx ,  getattr(ctx.args, ...) ",
            ))

        # R9-C: /
        # : log/debug/info/print 
        log_hardcode_patterns = [
            (r'(?:log(?:ger)?\.|debug\(|info\(|warning\(|print\().*?(?:max_turns|best_of_n|asr_threshold|exit_threshold|high_confidence).*?(?:=|:)?\s*\d+(?:\.\d+)?(?!["\'])', ""),
            (r'f".*?(?:max_turns|best_of_n|asr_threshold).*?(?:=|:)?\s*\d+(?:\.\d+)?(?!["\'])', "f-string "),
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
                        #  A:  (getattr / args / ctx / _resolve)
                        if "getattr" in line or "args." in line or "ctx." in line or "_resolve(" in line:
                            continue

                        #  B:  f-string  {}  — 
                        # : f"{exit_threshold:.0f}%"  ":0f", 
                        keyword_match = re.search(
                            r"(?:max_turns|best_of_n|asr_threshold|exit_threshold|high_confidence|wilson_confidence_level|crescendo_max_turns|tap_tree_width|tap_tree_depth)",
                            line, re.IGNORECASE,
                        )
                        if keyword_match:
                            kw_start = keyword_match.start()
                            kw_end = keyword_match.end()
                            #  {  }
                            before = line[:kw_start]
                            after = line[kw_end:]
                            last_open = before.rfind("{")
                            next_close = after.find("}")
                            if last_open != -1 and next_close != -1:
                                # Confirmation {param :  {  } 
                                segment = line[last_open:kw_end]
                                opens = segment.count("{")
                                closes = segment.count("}")
                                #  {} : opens > closes ( } )
                                if opens > closes:
                                    continue

                        self.violations.append(Violation(
                            rule="R9",
                            severity=Severity.INFO,
                            file=str(rel),
                            line=i,
                            description=f"Data flow C (): {message}",
                            fix_hint="/, ",
                        ))
                        break  # 

    # ==  14: PyRIT  output  (R2) ==

    def check_pyrit_native_output(self) -> None:
        """ generate_report  PyRIT  output 

        R2 : generate_report()  pyrit.output 
        (output_attack_async / output_scenario_async) 

         output  PyRIT 
         PyRIT  (OffSec AI-300 )
        """
        generator_file = self.root / "report" / "generator.py"
        if not generator_file.exists():
            return

        try:
            content = generator_file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return

        rel = str(generator_file.relative_to(self.root))

        #  pyrit.output 
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
                description="generate_report()  PyRIT  output  —  PyRIT ",
                fix_hint=" generate_report() : from report.pyrit_native_output import generate_native_output_files; await generate_native_output_files(...)",
            ))

    # ==  15: --dry-run  (R10) ==

    def check_dry_run_available(self) -> None:
        """ --dry-run 

        R10 :  python main.py --dry-run --max-seeds 1
         token Ensure:
        1. core/config.py  --dry-run CLI 
        2. main.py  dry-run  ( _is_dry_run  dry_run )
        3. dry-run Skip strike  ( execute_attacks/execute_text_adaptive)
        4. dry-run Skip escalate  ( check_and_escalate)
        """
        # 1.  config.py  --dry-run 
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
                        description=" --dry-run CLI  — R10  token ",
                        fix_hint=' parse_args() : parser.add_argument("--dry-run", action="store_true", default=False)',
                    ))
            except OSError:
                pass

        # 2.  main.py  dry-run 
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
                        description=" --dry-run  — R10  main.py  dry-run Skip",
                        fix_hint=" _run_single_endpoint : _is_dry_run = getattr(args, 'dry_run', False); if _is_dry_run: skip attack execution",
                    ))
                    return  # 

                # 3.  dry-run Skip strike 
                has_strike_skip = bool(re.search(r'_is_dry_run.*execute_attacks|dry_run.*execute_text_adaptive|\[DRY-RUN\].*Skip', main_content, re.IGNORECASE))
                if not has_strike_skip:
                    self.violations.append(Violation(
                        rule="R10",
                        severity=Severity.WARNING,
                        file="main.py",
                        line=0,
                        description="dry-run Skip strike  —  API token",
                        fix_hint=" strike : if _is_dry_run: ctx.attack_results = {}; continue (Skip execute_attacks)",
                    ))

                # 4.  dry-run Skip escalate 
                has_escalate_skip = bool(re.search(r'_is_dry_run.*check_and_escalate|\[DRY-RUN\].*Skip|dry_run.*escalate', main_content, re.IGNORECASE))
                if not has_escalate_skip:
                    self.violations.append(Violation(
                        rule="R10",
                        severity=Severity.WARNING,
                        file="main.py",
                        line=0,
                        description="dry-run Skip escalate  —  API token",
                        fix_hint=" escalate : if _is_dry_run: skip check_and_escalate()",
                    ))
            except OSError:
                pass

    # ==  16:  (R1/R7) ==

    def check_precision_targeting(self) -> None:
        """.

        R1 () + R7 (ASR-token-time ) :
        1.  Converter  (→OWASP→category) — converter_selector.py
        2. ASR  (UCB1) — seed_ranking.py + seed_ranker.py
        3. 0% ASR  — seed_ranker.py
        4. Model-specific priors — seed_ranking.py + seed_ranker.py

        converter(s)converter(s):
        - : 
        - :  main.py  strike/ 
        """
        # ==  1:  Converter  ==
        converter_selector = self.root / "arm" / "converter_selector.py"
        if converter_selector.exists():
            try:
                content = converter_selector.read_text(encoding="utf-8", errors="replace")
            except OSError:
                content = ""

            # 
            _required_converter_funcs = [
                ("_get_owasp_converter_priorities", "OWASP  Converter "),
                ("_get_category_converter_priorities", "Category  Converter "),
                ("_get_suitable_for_converter_strategy", "suitable_for "),
            ]
            for func_name, desc in _required_converter_funcs:
                if not re.search(rf"def\s+{func_name}\s*\(", content):
                    self.violations.append(Violation(
                        rule="R1",
                        severity=Severity.WARNING,
                        file="arm/converter_selector.py",
                        line=0,
                        description=f"-1 : {desc}  {func_name} ",
                        fix_hint=f" arm/converter_selector.py  {func_name}()",
                    ))

            #  OWASP  category  _get_candidate_converters / _build_converter_config 
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
                        description=f"-1 : {caller_func}  _get_owasp_converter_priorities (OWASP )",
                        fix_hint=f" {caller_func} : owasp_priorities = _get_owasp_converter_priorities(ctx)",
                    ))
                if "_get_category_converter_priorities" not in caller_body:
                    self.violations.append(Violation(
                        rule="R1",
                        severity=Severity.WARNING,
                        file="arm/converter_selector.py",
                        line=0,
                        description=f"-1 : {caller_func}  _get_category_converter_priorities (Category )",
                        fix_hint=f" {caller_func} : category_priorities = _get_category_converter_priorities(ctx)",
                    ))

        #  owasp_converter_map  category_converter_map  asr_priors.yaml 
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
                    description="-1 : owasp_converter_map  asr_priors.yaml ",
                    fix_hint=" asr_priors.yaml  owasp_converter_map ",
                ))
            if "category_converter_map:" not in priors_content:
                self.violations.append(Violation(
                    rule="R1",
                    severity=Severity.WARNING,
                    file="config/asr_priors.yaml",
                    line=0,
                    description="-1 : category_converter_map  asr_priors.yaml ",
                    fix_hint=" asr_priors.yaml  category_converter_map ",
                ))

        # ==  2: ASR  (UCB1) ==
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
                    description="-2 : UCB1  _rank_by_asr ",
                    fix_hint=" arm/seed_ranking.py  _rank_by_asr() (arXiv:cs/0207052)",
                ))

            #  UCB 
            if "ucb" not in sr_content.lower() or "sqrt" not in sr_content.lower():
                self.violations.append(Violation(
                    rule="R1",
                    severity=Severity.WARNING,
                    file="arm/seed_ranking.py",
                    line=0,
                    description="-2 : UCB1  (avg_asr + C*sqrt(2*ln(N)/n_i)) ",
                    fix_hint=" _rank_by_asr  UCB : ucb_score = asr + C * sqrt(2*ln(N)/n_i)",
                ))

        #  _rank_by_asr  seed_ranker.py 
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
                    description="-2 : load_seeds  _rank_by_asr (ASR Load)",
                    fix_hint=" load_seeds() : seed_groups = _rank_by_asr(seed_groups, asr_history)",
                ))

        # ==  3: 0% ASR  ==
        if seed_ranker.exists():
            if not re.search(r"def\s+_prune_zero_asr_seeds\s*\(", sk_content):
                self.violations.append(Violation(
                    rule="R7",
                    severity=Severity.WARNING,
                    file="arm/seed_ranker.py",
                    line=0,
                    description="-3 : 0% ASR  _prune_zero_asr_seeds ",
                    fix_hint=" arm/seed_ranker.py  _prune_zero_asr_seeds() (arXiv:cs/0207052)",
                ))
            elif "_prune_zero_asr_seeds" not in sk_content.split("def _prune_zero_asr_seeds")[0]:
                #  load_seeds 
                #  load_seeds  _prune_zero_asr_seeds
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
                        description="-3 : load_seeds  _prune_zero_asr_seeds (0% ASR Load)",
                        fix_hint=" load_seeds() : seed_groups = _prune_zero_asr_seeds(seed_groups, max_seeds)",
                    ))

        # ==  4: Model-specific priors ==
        #  load_asr_priors 
        if not re.search(r"def\s+load_asr_priors\s*\(", sr_content):
            self.violations.append(Violation(
                rule="R1",
                severity=Severity.WARNING,
                file="arm/seed_ranking.py",
                line=0,
                description="-4 : Model-specific priorsLoad load_asr_priors ",
                fix_hint=" arm/seed_ranking.py  load_asr_priors() (arXiv:2402.01135)",
            ))

        #  load_seeds  model_family 
        if seed_ranker.exists():
            if "model_family" not in sk_content:
                self.violations.append(Violation(
                    rule="R1",
                    severity=Severity.WARNING,
                    file="arm/seed_ranker.py",
                    line=0,
                    description="-4 : load_seeds  model_family  (Model-specific priors)",
                    fix_hint=" load_seeds()  model_family ,  load_asr_priors(model_family)",
                ))
            else:
                #  load_seeds  load_asr_priors
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
                        description="-4 : load_seeds  load_asr_priors (Model-specific priorsLoad)",
                        fix_hint=" load_seeds() : priors = load_asr_priors(model_family)",
                    ))

        #  main.py  model_family  load_seeds
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
                    description="-4 : main.py  model_family  load_seeds (Data flow)",
                    fix_hint=" main.py load_seeds() : model_family=target_model_family",
                ))

        #  update_asr_priors  main.py assess 
        if main_file.exists() and "update_asr_priors" not in main_content:
            self.violations.append(Violation(
                rule="R1",
                severity=Severity.WARNING,
                file="main.py",
                line=0,
                description="-4 : main.py  update_asr_priors (EMA )",
                fix_hint=" assess : update_asr_priors(model_family, ctx.asr_per_technique)",
            ))

        #  save_asr_history  main.py  (Data flow)
        if main_file.exists() and "save_asr_history" not in main_content:
            self.violations.append(Violation(
                rule="R1",
                severity=Severity.WARNING,
                file="main.py",
                line=0,
                description="-2 : main.py  save_asr_history (ASR , UCB )",
                fix_hint=" assess : save_asr_history(ctx.asr_per_technique, attack_results=ctx.attack_results)",
            ))

    # ==  17: Scenario  (R11) ==

    def check_scenario_config(self) -> None:
        """ Scenario  (v60:  defaults.yaml).

        R11  (v60):
        1. config/defaults.yaml  scenario_technique_filters
        2. scenario_technique_filters converter(s)
        3. Scenario router (core/scenario_router.py)  main.py 
        """
        if yaml is None:
            self.violations.append(Violation(
                rule="R11",
                severity=Severity.WARNING,
                file="()",
                line=0,
                description="PyYAML  —  Scenario ",
                fix_hint="pip install pyyaml",
            ))
            return

        # v60:  defaults.yaml  scenario_technique_filters
        defaults_file = self.root / "config" / "defaults.yaml"
        if not defaults_file.exists():
            self.violations.append(Violation(
                rule="R11",
                severity=Severity.BLOCKING,
                file="config/defaults.yaml",
                line=0,
                description="defaults.yaml  — Scenario Load",
                fix_hint=" config/defaults.yaml  scenario_technique_filters ",
            ))
            return

        #  YAML 
        try:
            with open(defaults_file, encoding="utf-8") as f:
                config = yaml.safe_load(f) or {}
        except Exception as exc:
            self.violations.append(Violation(
                rule="R11",
                severity=Severity.BLOCKING,
                file="config/defaults.yaml",
                line=0,
                description=f"defaults.yaml : {exc}",
                fix_hint=" YAML ",
            ))
            return

        #  scenario_technique_filters 
        scenario_filters = config.get("scenario_technique_filters")
        if not scenario_filters or not isinstance(scenario_filters, dict):
            self.violations.append(Violation(
                rule="R11",
                severity=Severity.BLOCKING,
                file="config/defaults.yaml",
                line=0,
                description=" scenario_technique_filters  — ",
                fix_hint=" defaults.yaml  scenario_technique_filters →",
            ))
            return

        # 
        if len(scenario_filters) == 0:
            self.violations.append(Violation(
                rule="R11",
                severity=Severity.WARNING,
                file="config/defaults.yaml",
                line=0,
                description="scenario_technique_filters  — ",
                fix_hint="converter(s) ( mcp_server, multi_agent_system, rag_system)",
            ))

        # 
        for surface_name, surface_config in scenario_filters.items():
            if not isinstance(surface_config, dict):
                self.violations.append(Violation(
                    rule="R11",
                    severity=Severity.WARNING,
                    file="config/defaults.yaml",
                    line=0,
                    description=f" '{surface_name}'  — ",
                    fix_hint=f"Ensure {surface_name}: ",
                ))
                continue

            #  description 
            if "description" not in surface_config:
                self.violations.append(Violation(
                    rule="R11",
                    severity=Severity.INFO,
                    file="config/defaults.yaml",
                    line=0,
                    description=f" '{surface_name}'  description ",
                    fix_hint=f" {surface_name}  description: <>",
                ))

        #  Scenario router main.py 
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
                        description="main.py from Scenario router — ",
                        fix_hint=" main.py : from core.scenario_router import get_router, apply_scenario_overrides",
                    ))
                elif "apply_scenario_overrides" not in main_content:
                    self.violations.append(Violation(
                        rule="R11",
                        severity=Severity.WARNING,
                        file="main.py",
                        line=0,
                        description="main.py  apply_scenario_overrides — Scenario ",
                        fix_hint=" SYNERGY : apply_scenario_overrides(ctx, scenario_config, args)",
                    ))
            except OSError:
                pass

        #  core/scenario_router.py 
        router_file = self.root / "core" / "scenario_router.py"
        if not router_file.exists():
            self.violations.append(Violation(
                rule="R11",
                severity=Severity.BLOCKING,
                file="core/scenario_router.py",
                line=0,
                description="Scenario router — ",
                fix_hint=" core/scenario_router.py  ScenarioRouter ",
            ))

    # == T0-1: R-H1  (Scaffold / Stub ) ==

    #  ( run_attack_pipeline)
    _ORCHESTRATION_PREFIXES = ("run_", "execute_", "process_", "handle_", "evaluate_", "apply_")
    #  stub  (docstring  "STUB" / "TODO"  —  C9)
    _STUB_ACKNOWLEDGED_MARKERS = ("STUB:", "STUB]", "TODO:", "FIXME:", "scaffold", "placeholder")

    def _is_stub_acknowledged(self, content: str, func_line_idx: int) -> bool:
        """ docstring  stub ( C9  gap)"""
        #  docstring 
        for j in range(func_line_idx, min(func_line_idx + 8, len(content.split("\n")))):
            line = content.split("\n")[j]
            if "\"\"\"" in line or "'''" in line:
                snippet = "\n".join(content.split("\n")[func_line_idx:j + 1])
                return any(m in snippet for m in self._STUB_ACKNOWLEDGED_MARKERS)
        return False

    def check_silent_degradation(self) -> None:
        """R-H1:  stub

        C9 
        (run_/execute_/process_/handle_/evaluate_/apply_)
         return {} / return None / pass  STUB/TODO
          scaffold — 
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
                    continue  #  helper 

                #  ( def/EOF)
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

                #  docstring 
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

                # stub : ≤ 2    return {} / return None / pass + return / raise NotImplementedError
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

                #  docstring  stub
                if self._is_stub_acknowledged(content, i):
                    continue

                self.violations.append(Violation(
                    rule="R-H1",
                    severity=Severity.WARNING,
                    file=str(rel),
                    line=i + 1,
                    description=(
                        f" (R-H1):  '{func_name}'  "
                        f" return / pass — "
                    ),
                    fix_hint=(
                        f" stub: docstring  'STUB: <>' "
                        f"; "
                    ),
                ))

    # == T0-2: R-H2  ==

    def check_silent_swallowing(self) -> None:
        """R-H2:  try  +  except (/).

        C9  try  >> except 
         except  pass / ellipsis /  logging,  —
        
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
                #  try  +  except 
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
                    #  except/finally 
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

                #  try 
                try_code = [l for l in try_body if l.strip() and not l.strip().startswith("#")]
                if len(try_code) < 3:
                    continue  # 

                for eb in except_blocks:
                    except_code = [
                        l for l in eb
                        if l.strip() and not l.strip().startswith("#")
                        and not l.strip().startswith("except") and l.strip() != "finally:"
                    ]
                    #  except : ≤ 1    pass / ... / logging / raise 
                    if len(except_code) > 1:
                        continue
                    if not except_code:
                        continue
                    ec_line = except_code[0].strip()
                    if ec_line in ("pass", "...", "continue", "return", "return None", "break"):
                        continue
                    #  logging/warn 
                    if re.match(r"(?:log(?:ger)?|logger|logging)\.(?:warning|info|debug|error|log)\(", ec_line):
                        continue

                    self.violations.append(Violation(
                        rule="R-H2",
                        severity=Severity.WARNING,
                        file=str(rel),
                        line=i + 1,
                        description=(
                            f" (R-H2): try  {len(try_code)}  vs except  {len(except_code)}  "
                            f"—  #{i+1} "
                        ),
                        fix_hint=(
                            ": except  log + raise , "
                            " (C9  gap)"
                        ),
                    ))

    # == T0-3: R-H3  ==

    #  ( ≥ 4 )
    _DUAL_TRACK_ROOTS = ("asr_manager", "judge", "escalation", "score", "response", "seed", "arm", "target", "search", "converter", "scorer")

    # R-H3  — Layer (2026-09-06 )
    # Confirmation, Layer/:
    #   arm/converter:    chains(Layer) / presets(+) / selector(+)
    #   arm/seed:         auto_expander() / ranker(+) / ranking()
    #   judge*:            adaptive_dual_judge() / dual_judge() / judge_manager(SSOT)
    #   score*:            scorer() / score_pipeline(+)
    #   recon/target:      target_builder() / target_router(Target routing)
    #   strike/escalation: escalation() / escalation_chain()
    # : judge*  score* Layer (assess.py + assess/judge/ + assess/expand/)
    _DUAL_TRACK_WHITELIST = {
        # arm/  — Layer
        "arm/converter",   # chains / presets / selector Layer: →→
        "arm/seed",        # auto_expander / ranker / ranking Layer: →Load→
        # assess/  — Layer (assess.py + assess/judge/ + assess/expand/)
        "assess/judge",    # adaptive_dual_judge / dual_judge / judge_manager — v57 
        "assess/score",    # scorer / score_pipeline —  + /
        # recon/  — Layer
        "recon/target",    # target_builder / target_router — →
        # strike/  — Layer
        "strike/escalation",  # escalation / escalation_chain — →
    }

    def check_dual_track(self) -> None:
        """R-H3: / ()

        D-11 : / manager/pipeline/export
        fromconverter(s)

        :  _base/_test
         INFO — //

        : _DUAL_TRACK_WHITELIST ConfirmationLayer,
        Skip, 
        """
        from importlib.machinery import SOURCE_SUFFIXES

        pkg_modules: dict[str, list[tuple[str, str]]] = {}  # pkg -> [(stem, rel_path)]

        for path in self.source_files:
            rel = path.relative_to(self.root)
            parts = rel.parts
            #  .py 
            if not path.suffix == ".py":
                continue
            # __init__.py 
            if path.name == "__init__.py":
                continue
            # core/toplevel 
            if len(parts) < 2:
                continue
            pkg = parts[0]
            stem = path.stem  # e.g. "asr_manager"

            pkg_modules.setdefault(pkg, []).append((stem, str(rel)))

        # 
        root_to_files: dict[str, list[str]] = {}
        for pkg, files in pkg_modules.items():
            for stem, rel_path in files:
                for root in self._DUAL_TRACK_ROOTS:
                    if stem.startswith(root) or root in stem:
                        key = f"{pkg}/{root}"
                        root_to_files.setdefault(key, []).append(rel_path)

        #  1 -
        for key, file_list in root_to_files.items():
            if len(file_list) < 2:
                continue
            #  _test / _base / _v2 
            main_files = [
                f for f in file_list
                if not any(suffix in f for suffix in ("_test.py", "_base.py", "_v2.py"))
            ]
            if len(main_files) < 2:
                continue

            #  — Layer
            if key in self._DUAL_TRACK_WHITELIST:
                continue

            severity = Severity.INFO
            self.violations.append(Violation(
                rule="R-H3",
                severity=severity,
                file=", ".join(main_files[:4]),
                line=0,
                description=(
                    f" (R-H3):  '{key}'  {len(main_files)} converter(s) "
                    f"— {' / '.join(main_files[:4])} — /"
                ),
                fix_hint="Confirmation; , imports import ",
            ))

    # == T1-3: Specs  () ==

    def _read_specs_version(self) -> str | None:
        """ 00-CONSTITUTION.md ,  specs-guard """
        const_file = self.root / "docs" / "specs" / "00-CONSTITUTION.md"
        if not const_file.exists():
            return None
        try:
            head = const_file.read_text(encoding="utf-8", errors="replace")[:1024]
            #  "****v1.2" / "v1.2"
            m = re.search(r"\*{0,2}[*]*[*]*\s*[:]\s*v?(\d+\.\d+|\d+)", head)
            if not m:
                m = re.search(r"\bversion\s*[:]\s*v?(\d+\.\d+|\d+)", head)
            return m.group(1) if m else None
        except OSError:
            return None

    @property
    def specs_version(self) -> str:
        """ specs  (Load,  'unknown')"""
        if not hasattr(self, "_specs_version_cached"):
            ver = self._read_specs_version()
            self._specs_version_cached = ver if ver else "unknown"
        return self._specs_version_cached

    # ==  ==

    def report_text(self, show_fix_hints: bool = False) -> str:
        """"""
        if not self.violations:
            return ("✅  — 0 \n"
                    f"   specs : {self.specs_version}")

        blocking = [v for v in self.violations if v.severity == Severity.BLOCKING]
        warnings = [v for v in self.violations if v.severity == Severity.WARNING]
        infos = [v for v in self.violations if v.severity == Severity.INFO]

        lines = []
        lines.append(f"{'✅' if not blocking else '❌'} : "
                      f"{len(blocking)} BLOCKING, {len(warnings)} WARNING, {len(infos)} INFO")
        lines.append("")

        for v in self.violations:
            severity_label = {0: "BLOCKING", 1: "WARNING", 2: "INFO"}[v.severity]
            lines.append(f"[{severity_label}] Rule {v.rule} | {v.file}:{v.line}")
            lines.append(f"  : {v.description}")
            if show_fix_hints and v.fix_hint:
                lines.append(f"  : {v.fix_hint}")
            lines.append("")

        lines.append(f"specs : {self.specs_version}  (: 00-CONSTITUTION.md)")
        return "\n".join(lines)

    def report_json(self) -> str:
        """ JSON  (CI )"""
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


# ===============================================================================
# 
# ===============================================================================

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="")
    parser.add_argument("--fix-hints", action="store_true", help="")
    parser.add_argument("--rule", type=str, default=None, help=" ( R10)")
    parser.add_argument("--json", action="store_true", help="JSON  (CI )")
    parser.add_argument("--project-root", type=str, default=None, help="")
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

    # : 0=, 1= BLOCKING 
    has_blocking = any(v.severity == Severity.BLOCKING for v in guard.violations)
    return 1 if has_blocking else 0


if __name__ == "__main__":
    sys.exit(main())
