#!/usr/bin/env python3
"""
tools/guard_extended.py - R-PIPE / R-IMPORT / R-REDTEAM / R-EVID / R-REPORT 扩展检查

 5 大系列 20+ 检查规则:
 - 流水线集成完整性 (R-PIPE)
 - 导入依赖检查 (R-IMPORT)
 - 红队最佳实践 (R-REDTEAM)
 - 证据收集完整性 (R-EVID)
 - 报告生成完整性 (R-REPORT)

:
 架构守卫主入口 guard.py 通过 `from tools.guard_extended import register_extended_checks` 注册本模块

迁移自: core/architecture_guard_extended.py (2026-09-08 目录职责优化)
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from tools.guard import Severity, Violation


def _get_violation_classes():
    from tools.guard import Severity, Violation

    return Severity, Violation


# ===============================================================================
# 规则配置
# ===============================================================================

# R-PIPE: 流水线模块注册检查
_PIPELINE_MODULES: dict[str, dict[str, str]] = {
    "recon": {
        "burp_parser": "parse_burp_file",
        "target_router": "create_target",
        "endpoint_sorter": "sort_endpoints",
    },
    "arm": {
        "seed_ranker": "rank_seeds",
        "converter_presets": "build_converter_map",
        "technique_picker": "select_techniques",
    },
    "strike": {
        "executor": "execute_attacks",
        "escalation": "check_and_escalate",
    },
    "assess": {
        "asr_manager": "compute_asr",
        "scorer": "score_response",
    },
    "report": {
        "evidence": "EvidenceCollector",
        "generator": "generate_report",
    },
}

# 6阶段执行顺序 (orchestrator.py 调用顺序)
_PHASE_ORDER = ["recon", "arm", "strike", "escalate", "assess", "report"]

# orchestrator.py 阶段函数名
_ORCHESTRATOR_PHASE_FUNCTIONS = [
    "_run_recon_phase",
    "_run_arm_phase",
    "_run_strike_phase",
    "_run_escalate_phase",
    "_run_assess_phase",
    "_run_report_phase",
]

_INIT_EXPORT_WHITELIST = {
    "filter_by_adversarial",
    "run_a2a_protocol_injection",
    "run_backdoor_verification",
    "run_cicd_supply_chain_attacks",
    "run_embedding_poisoning_attacks",
    "run_lora_security_probe",
    "create_objective_scorer",
    "should_run_probe",
    "get_default_classifier",
    # A2A reconnaissance utilities (public API, may be used by advanced scripts)
    "run_inline_a2a_discovery",
    "check_defense_bypass_feasibility",
    # Lazy-loaded __getattr__ modules (used via getattr() pattern)
    "dynamic_seeds",
    "indirect_pi",
}

# R-REDTEAM: 必须包含 arXiv 引用的技术
_REQUIRED_CITATIONS: list[tuple[str, str, str]] = [
    ("PromptSendingAttack", "arXiv:2302.12173", "Greshake 2023"),
    ("CrescendoAttack", "arXiv:2404.01833", "Russinovich 2024"),
    ("TAPAttack", "arXiv:2405.17350", "Mehrabi 2024"),
    ("PAIRAttack", "arXiv:2310.08419", "Chao 2024"),
    ("GCG", "arXiv:2302.12173", "Zou 2023"),
    ("Decomposition", "arXiv:2402.14266", "Liu 2024 (DrAttack)"),
    ("BestOfN", "arXiv:2404.02151", "Hughes 2024"),
    ("SkeletonKey", "arXiv:2402.14266", "SKELETONKEY 2024"),
]

# R-NATIVE: PyRIT 原生组件 (宪法 v1.8)

# 强制原生攻击类 (11 类)
_NATIVE_ATTACK_CLASSES: dict[str, str] = {
    "CrescendoAttack": "pyrit.executor.attack.multi_turn.crescendo_attack.CrescendoAttack",
    "TAPAttack": "pyrit.executor.attack.multi_turn.tap_attack.TAPAttack",
    "PAIRAttack": "pyrit.executor.attack.multi_turn.pair_attack.PAIRAttack",
    "XPIAAttack": "pyrit.executor.attack.multi_turn.xpia_attack.XPIAAttack",
    "SkeletonKeyAttack": "pyrit.executor.attack.single_turn.skeleton_key.SkeletonKeyAttack",
    "PromptSendingAttack": "pyrit.executor.attack.single_turn.prompt_sending.PromptSendingAttack",
    "SequentialAttack": "pyrit.executor.attack.compound.sequential_attack.SequentialAttack",
    "ManyShotJailbreakAttack": "pyrit.executor.attack.many_shot_jailbreak.ManyShotJailbreakAttack",
    "MultiPromptSendingAttack": "pyrit.executor.attack.multi_prompt_sending.MultiPromptSendingAttack",
    "ChunkedRequestAttack": "pyrit.executor.attack.chunked_request.ChunkedRequestAttack",
    "RedTeamingAttack": "pyrit.executor.attack.red_teaming.RedTeamingAttack",
    "BargeInAttack": "pyrit.executor.attack.barge_in.BargeInAttack",
}

# 强制原生 Converter (80+ 类，节选关键词检测 R-NATIVE-2)
_NATIVE_CONVERTER_KEYWORDS: dict[str, str] = {
    "base64_encode": "Base64Converter",
    "base64_decode": "Base64Converter",
    "rot13": "ROT13Converter",
    "binary_encode": "BinaryConverter",
    "url_encode": "UrlConverter",
    "url_decode": "UrlConverter",
    "unicode_substitution": "UnicodeSubstitutionConverter",
    "unicode_confusable": "UnicodeConfusableConverter",
    "zero_width": "ZeroWidthConverter",
    "bidi": "BidiConverter",
    "caesar": "CaesarConverter",
    "vigenere": "VigenereConverter",
    "atbash": "AtbashConverter",
    "translation": "TranslationConverter",
    "translate": "TranslationConverter",
    "diacritic": "DiacriticConverter",
    "char_swap": "CharSwapConverter",
    "char_noise": "CharNoiseConverter",
    "random_capital": "RandomCapitalLettersConverter",
    "suffix_append": "SuffixAppendConverter",
    "string_join": "StringJoinConverter",
    "insert_punctuation": "InsertPunctuationConverter",
}

# 强制原生 Scorer (50+ 类，节选关键词检测 R-NATIVE-3)
_NATIVE_SCORER_KEYWORDS: dict[str, str] = {
    "check_refusal": "SelfAskRefusalScorer",
    "is_refusal": "SelfAskRefusalScorer",
    "check_success": "SelfAskTrueFalseScorer",
    "is_success": "SelfAskTrueFalseScorer",
    "regex_match": "RegexScorer",
    "substring_match": "SubStringScorer",
    "contains_pattern": "RegexScorer",
    "classify_content": "ContentClassifier",
    "content_classification": "ContentClassifier",
    "sql_injection_check": "SQLInjectionOutputScorer",
    "xss_check": "XSSOutputScorer",
    "ssrf_check": "SSRFOutputScorer",
    "command_injection_check": "ShellCommandOutputScorer",
    "keyword_match": "AnthraxKeywordScorer",
    "credential_leak": "CredentialLeakScorer",
    "plagiarism_check": "PlagiarismScorer",
}

# 强制原生 Target (25+ 类，节选关键词检测 R-NATIVE-4)
_NATIVE_TARGET_KEYWORDS: dict[str, str] = {
    "http_request_target": "HTTPTarget",
    "http_target": "HTTPTarget",
    "api_target": "HTTPXAPITarget",
    "websocket_target": "WebSocketTarget",
    "openai_chat": "OpenAIChatTarget",
    "openai_completion": "OpenAICompletionTarget",
    "openai_response": "OpenAIResponseTarget",
    "prompt_target": "PromptTarget",
    "text_target": "TextTarget",
    "round_robin": "RoundRobinTarget",
    "realtime_target": "RealtimeTarget",
}

# 强制原生攻击关键词 (检测 for loop + PromptSendingAttack 模式)
_NATIVE_ATTACK_KEYWORDS: dict[str, str] = {
    "crescendo": "CrescendoAttack",
    "tap": "TAPAttack",
    "pair": "PAIRAttack",
    "xpia": "XPIAAttack",
}

# R-REDTEAM: 禁止模式
_FORBIDDEN_PATTERNS_REDTEAM: list[tuple[str, str, str]] = [
    (
        r"return\s+None\b.*#.*attack",
        "攻击代码中返回 None — 违反协议",
        "返回 AttackOutcome 对象，记录 success/failure + 证据链",
    ),
    (
        r"pass\s*#.*(attack|exploit|score)",
        "攻击/评分代码中的 pass stub — 违反完整性",
        "实现逻辑或抛出 NotImplementedError",
    ),
    (
        r"raise\s+NotImplementedError.*#.*TODO",
        "TODO stub 混入攻击代码 — 违反交付标准",
        "移除 stub，或移至 orchestrator Skip 逻辑",
    ),
]

# PipelineContext 字段消费者映射
_CONTEXT_FIELD_CONSUMERS: dict[str, list[str]] = {
    "parsed_request": ["arm", "assess", "report"],
    "seeds": ["strike"],
    "converter_map": ["strike"],
    "techniques": ["strike"],
    "attack_results": ["assess", "report"],
    "asr_per_technique": ["report"],
    "overall_asr": ["report"],
    "wilson_ci": ["report"],
    "dual_judge_stats": ["report"],
    "guardrail_report": ["strike"],
    "stealth_policy": ["strike"],
    "adaptive_probe_ctx": ["arm", "strike"],
    "orchestration_log": ["report"],
    "synergy_config": ["arm"],
}

# === 注册函数 ===


def register_extended_checks(guard_cls) -> None:
    """注册所有扩展检查方法到 ArchitectureGuard 类"""

    # == R-PIPE ==================================================

    def check_pipeline_integration(self) -> None:
        """R-CONV-1~4: 流水线集成完整性检查"""
        Severity, Violation = _get_violation_classes()
        orch_file = self.root / "core" / "orchestrator.py"

        # R-CONV-1: orchestrator.py 包含所有阶段函数
        if orch_file.exists():
            orch_content = orch_file.read_text(encoding="utf-8", errors="replace")
            for func_name in _ORCHESTRATOR_PHASE_FUNCTIONS:
                is_direct_def = f"async def {func_name}" in orch_content
                is_imported = func_name in orch_content and "import" in orch_content and "from " in orch_content
                if not is_direct_def and not is_imported:
                    self.violations.append(
                        Violation(
                            rule="R-PIPE-1",
                            severity=Severity.BLOCKING,
                            file="core/orchestrator.py",
                            line=0,
                            description=f"orchestrator.py 缺少阶段 '{func_name}' - 流水线断裂",
                            fix_hint=f"添加 async def {func_name}(ctx) 或从 phases/ 导入",
                        )
                    )

        # R-PIPE-2: orchestrator 调用各阶段
        if orch_file.exists():
            orch_content = orch_file.read_text(encoding="utf-8", errors="replace")
            phase_calls = [
                ("_run_recon_phase", "recon 侦察"),
                ("_run_arm_phase", "arm 武器化"),
                ("_run_strike_phase", "strike 攻击"),
                ("_run_escalate_phase", "escalate 升级"),
                ("_run_assess_phase", "assess 评分"),
                ("_run_report_phase", "report 报告"),
            ]
            for func_name, desc in phase_calls:
                is_imported = "from " in orch_content and func_name in orch_content and "import" in orch_content
                is_direct_def = f"def {func_name}" in orch_content
                is_direct_call = f"await {func_name}" in orch_content
                if not is_imported and not is_direct_def and not is_direct_call:
                    self.violations.append(
                        Violation(
                            rule="R-PIPE-2",
                            severity=Severity.BLOCKING,
                            file="core/orchestrator.py",
                            line=0,
                            description=f"orchestrator 未调用 {desc} ({func_name}) - 流水线断裂",
                            fix_hint=f"在 run_single_endpoint 或主流程中 await {func_name}(ctx)",
                        )
                    )

        self._check_arm_module_registration()
        self._check_strike_module_registration()

    def _check_arm_module_registration(self) -> None:
        """R-PIPE-3: 检查 arm/ converter_presets.py"""
        presets_file = self.root / "arm" / "converter_presets.py"
        if not presets_file.exists():
            return
        content = presets_file.read_text(encoding="utf-8", errors="replace")

        if "_build_chain_builders" not in content:
            self.violations.append(
                Violation(
                    rule="R-PIPE-3",
                    severity=Severity.WARNING,
                    file="arm/converter_presets.py",
                    line=0,
                    description="缺少 _build_chain_builders 函数 - converter 注册不完整",
                    fix_hint="实现 _build_chain_builders() -> dict[str, Any] builder 映射",
                )
            )

    def _check_strike_module_registration(self) -> None:
        """R-PIPE-4: strike/ 模块注册检查"""
        Severity, Violation = _get_violation_classes()
        executor_file = self.root / "strike" / "executor.py"
        if not executor_file.exists():
            return

    # R-PIPE-5 字段白名单: 默认值字段在多个模块中被消费，但检测器无法追踪
    _PIPE5_FIELD_WHITELIST = {
        "output_dir",  # main.py, orchestrator.py, report/generator.py 多处访问
        "mcpsec_version",  # recon/_target_router_helpers.py MCPSec桥接后填充
        "scenario_name",  # core/scenario_router.py 场景路由设置
        "memory_labels",  # main.py CentralMemory.set_labels 使用
        "stealth_config",  # strike/stealth_exec.py 读取
        "session_state",  # strike/executor.py 会话感知攻击读取
        "synergy_config",  # adaptive_executor.py 读取
        "scenario_config",  # adaptive_executor.py 读取
    }

    def check_data_flow_consistency(self) -> None:
        """R-PIPE-5~6: PipelineContext 数据流一致性"""
        Severity, Violation = _get_violation_classes()
        ctx_file = self.root / "core" / "context.py"
        orch_file = self.root / "core" / "orchestrator.py"

        if not ctx_file.exists():
            return

        ctx_content = ctx_file.read_text(encoding="utf-8", errors="replace")
        orch_content = orch_file.read_text(encoding="utf-8", errors="replace") if orch_file.exists() else ""

        # 检测 PipelineContext dataclass 字段
        field_pattern = re.compile(r"^\s+(\w+):\s*[\w\[\]|]+\s*=")
        fields = []
        in_class = False
        in_function = False
        class_indent = 0
        func_indent = 0

        for line in ctx_content.split("\n"):
            stripped = line.lstrip()
            if not stripped or stripped.startswith("#"):
                continue

            indent = len(line) - len(stripped)

            if stripped.startswith("class ") and "PipelineContext" in stripped:
                in_class = True
                class_indent = indent
                in_function = False
                continue

            if in_class and indent <= class_indent and stripped:
                in_class = False
                continue

            if in_class and stripped.startswith("def ") and indent > class_indent:
                in_function = True
                func_indent = indent
                continue

            if in_function and indent <= func_indent and stripped:
                in_function = False

            if in_class and not in_function and indent > class_indent:
                m = field_pattern.match(line)
                if m and not m.group(1).startswith("_"):
                    fields.append(m.group(1))

        # 检查字段是否被消费
        for field_name in fields:
            if field_name.startswith("_"):
                continue
            # 白名单: 确认被消费但检测器无法追踪的字段
            if field_name in self._PIPE5_FIELD_WHITELIST:
                continue
            access_pattern = rf"ctx\.{field_name}(?![a-zA-Z0-9_])"
            if not re.search(access_pattern, orch_content):
                all_content = self._read_all_source()
                total_refs = sum(1 for c in all_content if re.search(access_pattern, c))
                if total_refs <= 1:
                    self.violations.append(
                        Violation(
                            rule="R-PIPE-5",
                            severity=Severity.INFO,
                            file="core/context.py",
                            line=0,
                            description=f"PipelineContext.{field_name} 未被消费 - 可能的数据流断裂",
                            fix_hint=f"确认 {field_name} 是否被某个 converter(s) 阶段使用，否则可移除",
                        )
                    )

    def _read_all_source(self) -> list[str]:
        """读取所有源文件"""
        contents: list[str] = []
        for p in self.source_files:
            try:
                contents.append(p.read_text(encoding="utf-8", errors="replace"))
            except OSError:
                pass
        return contents

    # == R-IMPORT ================================================

    def check_circular_imports(self) -> None:
        """R-IMPORT-1~2: 循环导入检测"""
        Severity, Violation = _get_violation_classes()
        import_graph: dict[str, set[str]] = {}

        for path in self.source_files:
            try:
                content = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            rel = str(path.relative_to(self.root))
            if "__init__.py" in rel:
                continue

            module_path = rel.replace("/", ".").replace(".py", "")
            imports = set()

            for line in content.split("\n"):
                line = line.strip()
                if line.startswith("from ") and " import " in line:
                    target = line.split()[1].lstrip(".")
                    if any(
                        pkg in target for pkg in ["core.", "arm.", "strike.", "assess.", "report.", "recon.", "tools."]
                    ):
                        imports.add(target.split(".")[0] + "." + target.split(".")[1])
                elif line.startswith("import "):
                    target = line.split()[1]
                    if any(pkg in target for pkg in ["core", "arm", "strike", "assess", "report", "recon", "tools"]):
                        imports.add(target)

            import_graph[module_path] = imports

        for module, deps in import_graph.items():
            for dep in deps:
                dep_imports = import_graph.get(dep, set())
                if module in dep_imports:
                    self.violations.append(
                        Violation(
                            rule="R-IMPORT-1",
                            severity=Severity.BLOCKING,
                            file=module.replace(".", "/") + ".py",
                            line=0,
                            description=f"循环导入: {module} <-> {dep} - 架构腐败",
                            fix_hint="抽取共享逻辑到 utils/ 或独立模块，使用延迟导入 (import in function)",
                        )
                    )

    def check_dead_code(self) -> None:
        """R-IMPORT-3: 死代码检测"""
        Severity, Violation = _get_violation_classes()
        imported_modules: set[str] = set()
        for path in self.source_files:
            try:
                content = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if "__init__.py" in str(path):
                continue

            for line in content.split("\n"):
                line = line.strip()
                if line.startswith("from ") and " import " in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        mod = parts[1]
                        for pkg in ["core", "arm", "strike", "assess", "report", "recon", "tools"]:
                            if mod.startswith(pkg):
                                imported_modules.add(mod.split(".")[0] + "/" + mod.split(".")[1] if "." in mod else mod)
                                break

        pipeline_pkgs = ["arm", "strike", "assess", "report", "recon"]
        for path in self.source_files:
            rel = str(path.relative_to(self.root))
            if "__init__.py" in rel or not rel.endswith(".py"):
                continue
            parts = rel.split("/")
            if len(parts) >= 2 and parts[0] in pipeline_pkgs:
                module_name = parts[-1].replace(".py", "")
                is_imported = any(module_name in imp for imp in imported_modules)
                orch_file = self.root / "core" / "orchestrator.py"
                if orch_file.exists():
                    orch_content = orch_file.read_text(encoding="utf-8", errors="replace")
                    if module_name in orch_content:
                        is_imported = True

                if not is_imported and not module_name.startswith("_"):
                    self.violations.append(
                        Violation(
                            rule="R-IMPORT-3",
                            severity=Severity.INFO,
                            file=rel,
                            line=0,
                            description=f"潜在死代码: {rel} 未被任何模块导入",
                            fix_hint="确认是否需要保留，或添加到 __init__.py / 删除",
                        )
                    )

    # == R-REDTEAM ==============================================

    def check_best_practices(self) -> None:
        """R-REDTEAM-1~3: 红队最佳实践检查"""
        Severity, Violation = _get_violation_classes()
        for path in self.source_files:
            try:
                content = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if "__init__.py" in str(path):
                continue

            lines = content.split("\n")

            for i, line in enumerate(lines, 1):
                stripped = line.strip()
                if stripped.startswith("#"):
                    continue

                for pattern, desc, fix in _FORBIDDEN_PATTERNS_REDTEAM:
                    if re.search(pattern, stripped, re.IGNORECASE):
                        self.violations.append(
                            Violation(
                                rule="R-REDTEAM-1",
                                severity=Severity.WARNING,
                                file=str(path.relative_to(self.root)),
                                line=i,
                                description=f"{desc}: {stripped[:70]}",
                                fix_hint=fix,
                            )
                        )

    def check_academic_citations(self) -> None:
        """R-REDTEAM-2: arXiv 引用检查"""
        Severity, Violation = _get_violation_classes()
        pipeline_dirs = {"strike", "arm", "assess"}
        for path in self.source_files:
            if not any(d in str(path) for d in pipeline_dirs):
                continue
            try:
                content = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            for keyword, arxiv_id, paper_name in _REQUIRED_CITATIONS:
                if keyword in content and arxiv_id not in content:
                    for i, line in enumerate(content.split("\n"), 1):
                        if keyword in line and "import" not in line:
                            self.violations.append(
                                Violation(
                                    rule="R-REDTEAM-2",
                                    severity=Severity.INFO,
                                    file=str(path.relative_to(self.root)),
                                    line=i,
                                    description=f"使用 '{keyword}' 但缺少 {arxiv_id} ({paper_name}) 引用",
                                    fix_hint=f"在文件头部 docstring 中添加: {arxiv_id}",
                                )
                            )
                            break

    def check_asr_completeness(self) -> None:
        """R-REDTEAM-3: ASR 计算链完整性"""
        Severity, Violation = _get_violation_classes()
        score_file = self.root / "assess" / "asr_manager.py"
        if not score_file.exists():
            score_file = self.root / "assess" / "asr_stats.py"
        if not score_file.exists():
            self.violations.append(
                Violation(
                    rule="R-REDTEAM-3",
                    severity=Severity.BLOCKING,
                    file="assess/asr_manager.py",
                    line=0,
                    description="缺少 ASR 计算模块 (asr_manager.py 或 asr_stats.py)",
                    fix_hint="创建 assess/asr_manager.py, 实现 compute_asr + compute_overall_asr",
                )
            )
            return

        content = score_file.read_text(encoding="utf-8", errors="replace")
        required_functions = ["compute_asr", "compute_overall_asr"]
        for func in required_functions:
            has_def = f"def {func}" in content or f"async def {func}" in content
            _re = __import__("re")
            has_single_import = bool(_re.search(rf"^[^#]*\bimport\b[^#]*\b{func}\b", content, _re.MULTILINE))
            has_multi_import = bool(
                _re.search(
                    rf"from\s+\S+\s+import\s*\([^)]*\b{func}\b",
                    content,
                    _re.DOTALL,
                )
            )
            if not has_def and not has_single_import and not has_multi_import:
                self.violations.append(
                    Violation(
                        rule="R-REDTEAM-3",
                        severity=Severity.WARNING,
                        file=str(score_file.relative_to(self.root)),
                        line=0,
                        description=f"ASR 计算链不完整: 缺少 '{func}' - ASR 统计断裂",
                        fix_hint=f"实现 {func}() 或从 SSOT import",
                    )
                )

    # == R-EVID =================================================

    def check_evidence_completeness(self) -> None:
        """R-EVID-1: 证据收集器完整性"""
        Severity, Violation = _get_violation_classes()
        evidence_file = self.root / "report" / "evidence.py"
        if not evidence_file.exists():
            self.violations.append(
                Violation(
                    rule="R-EVID-1",
                    severity=Severity.BLOCKING,
                    file="report/evidence.py",
                    line=0,
                    description="缺少 report/evidence.py - 证据收集模块",
                    fix_hint="创建 report/evidence.py, 实现 EvidenceCollector",
                )
            )
            return

        content = evidence_file.read_text(encoding="utf-8", errors="replace")
        if "def collect(" not in content and "async def collect(" not in content:
            self.violations.append(
                Violation(
                    rule="R-EVID-1",
                    severity=Severity.WARNING,
                    file="report/evidence.py",
                    line=0,
                    description="EvidenceCollector 缺少 collect() 方法 - 证据收集断裂",
                    fix_hint="实现 collect() 方法, 从 attack_results 收集证据到 EvidenceCollection",
                )
            )

        if "class EvidenceCollection" not in content:
            self.violations.append(
                Violation(
                    rule="R-EVID-1",
                    severity=Severity.WARNING,
                    file="report/evidence.py",
                    line=0,
                    description="缺少 EvidenceCollection 数据类 - 证据结构缺失",
                    fix_hint="添加 @dataclass class EvidenceCollection 定义",
                )
            )

    # == R-REPORT ===============================================

    def check_report_completeness(self) -> None:
        """R-REPORT-1: 报告生成器完整性"""
        Severity, Violation = _get_violation_classes()
        generator_file = self.root / "report" / "generator.py"
        if not generator_file.exists():
            self.violations.append(
                Violation(
                    rule="R-REPORT-1",
                    severity=Severity.BLOCKING,
                    file="report/generator.py",
                    line=0,
                    description="缺少 report/generator.py - 报告生成模块",
                    fix_hint="创建 report/generator.py, 实现 generate_report()",
                )
            )
            return

        content = generator_file.read_text(encoding="utf-8", errors="replace")

        if "EvidenceCollection" not in content:
            self.violations.append(
                Violation(
                    rule="R-REPORT-1",
                    severity=Severity.WARNING,
                    file="report/generator.py",
                    line=0,
                    description="generate_report 未使用 EvidenceCollection - 证据链断裂",
                    fix_hint="在 generate_report 中接收 EvidenceCollection 作为输入",
                )
            )

        output_formats = []
        if "html" in content.lower() or "HTML" in content:
            output_formats.append("HTML")
        if "markdown" in content.lower() or "Markdown" in content:
            output_formats.append("Markdown")
        if "sarif" in content.lower() or "SARIF" in content:
            output_formats.append("SARIF")

        if len(output_formats) < 2:
            self.violations.append(
                Violation(
                    rule="R-REPORT-2",
                    severity=Severity.INFO,
                    file="report/generator.py",
                    line=0,
                    description=f"报告格式单一: 仅支持 {', '.join(output_formats)} - 建议多格式输出",
                    fix_hint="添加 Markdown / SARIF / JSON 输出, 满足 CI 集成需求",
                )
            )

    # == R-PIPE-6: recon 子模块调用检查 ========================

    def check_recon_submodule_invocation(self) -> None:
        """R-PIPE-6: recon/ 子模块 action 函数是否被实际调用 (支持组件化架构)"""
        Severity, Violation = _get_violation_classes()

        recon_init = self.root / "recon" / "__init__.py"
        if not recon_init.exists():
            return

        init_content = recon_init.read_text(encoding="utf-8", errors="replace")

        # 解析 __init__.py 导出的函数
        exported_funcs: list[tuple[str, str, str]] = []  # (mod_path, mod_name, func_name)
        init_lines = init_content.split("\n")

        for i, line in enumerate(init_lines):
            line = line.strip()
            if not line.startswith("from recon.") or " import " not in line:
                continue

            mod = line.split()[1]  # recon.health_probe 或 recon.a2a.discoverer
            mod_name = mod.split(".")[-1]
            # 保存完整模块路径 (如 "a2a.discoverer" 或 "health_probe")
            mod_path = mod.replace("recon.", "")

            import_part = line.split(" import ", 1)[1].strip()

            if import_part.startswith("("):
                symbol_str = ""
                for j in range(i + 1, len(init_lines)):
                    next_line = init_lines[j].strip()
                    symbol_str += " " + next_line
                    if ")" in next_line:
                        break

                for sym in re.findall(r"\b([a-zA-Z_]\w*)\b", symbol_str):
                    if sym != "recon" and sym not in ("__",):
                        exported_funcs.append((mod_path, mod_name, sym))
            else:
                for sym in import_part.split(","):
                    sym = sym.strip().rstrip(",")
                    if sym and not sym.startswith("#") and sym not in ("__",):
                        exported_funcs.append((mod_path, mod_name, sym))

        if not exported_funcs:
            return

        # 读取 recon/ 所有文件 (包括子目录) + core/phases/recon.py 的内容
        recon_dir = self.root / "recon"
        phase_content = ""

        if recon_dir.exists():
            # 递归读取所有 .py 文件 (包括子目录)
            for py_file in recon_dir.rglob("*.py"):
                if py_file.name == "__init__.py":
                    continue
                try:
                    phase_content += py_file.read_text(encoding="utf-8", errors="replace") + "\n"
                except OSError:
                    pass

        recon_phase_file = self.root / "core" / "phases" / "recon.py"
        if recon_phase_file.exists():
            phase_content += recon_phase_file.read_text(encoding="utf-8", errors="replace") + "\n"

        # action 函数前缀
        _ACTION_PREFIXES = ("run_", "probe_", "detect_", "check_", "extract_", "enumerate_", "build_")

        # 白名单: 组件化架构中通过子包调用的函数 (非顶层 recon.py 直接调用)
        # 这些函数通过 recon.<subpkg>.__init__.py 导出，在其他模块中使用
        _WHITELIST = {
            "build_openapi_attack_seeds",  # 通过 recon.api 子包调用
            "check_defense_bypass_feasibility",  # 通过 recon.a2a 子包调用
            "run_inline_a2a_discovery",  # 通过 recon.a2a 子包调用
            "run_health_probe",  # 遗留功能，通过 ctx 注释引用
            "build_target_from_burp",  # 遗留功能，TargetBuilder 内部调用
        }

        for mod_path, mod_name, func_name in exported_funcs:
            if func_name[0].isupper():
                continue  # 跳过类名 (type hints)

            if not any(func_name.startswith(prefix) for prefix in _ACTION_PREFIXES):
                continue

            # 跳过白名单中的函数
            if func_name in _WHITELIST:
                continue

            # 跳过函数定义本身
            call_pattern = rf"(?<!def\s)\b{re.escape(func_name)}\s*\("
            is_called = bool(re.search(call_pattern, phase_content))

            if not is_called:
                # 根据模块路径生成正确的文件路径 (将 . 替换为 / 以反映子目录结构)
                file_path = f"recon/{mod_path.replace('.', '/')}.py"
                self.violations.append(
                    Violation(
                        rule="R-PIPE-6",
                        severity=Severity.WARNING,
                        file=file_path,
                        line=0,
                        description=f"{file_path}.{func_name}() 被 __init__.py 导出但未被 recon 阶段调用",
                        fix_hint=f"在 recon 阶段执行器中添加 from recon.{mod_path} import {func_name}; {func_name}(ctx)",
                    )
                )

    # == R-IMPORT-4: __init__.py 导出使用检查 ====================

    def check_init_export_usage(self) -> None:
        """R-IMPORT-4: __init__.py 导出的符号是否被实际使用"""
        Severity, Violation = _get_violation_classes()

        pipeline_pkgs = ["arm", "strike", "assess", "report", "recon"]

        for pkg in pipeline_pkgs:
            init_file = self.root / pkg / "__init__.py"
            if not init_file.exists():
                continue

            init_content = init_file.read_text(encoding="utf-8", errors="replace")
            init_lines = init_content.split("\n")

            # 解析 __init__.py 导出的符号 (跳过 docstring 内的示例代码)
            exported_symbols: list[str] = []
            in_docstring = False
            docstring_quote = None

            for i, raw_line in enumerate(init_lines):
                line = raw_line.strip()

                # 跟踪 docstring 边界 (跳过文档字符串中的示例导入)
                if not in_docstring:
                    if line.startswith('"""') or line.startswith("'''"):
                        quote = line[:3]
                        # 单行 docstring
                        if line.count(quote) >= 2 and len(line) > 3:
                            continue
                        in_docstring = True
                        docstring_quote = quote
                        continue
                else:
                    if docstring_quote in line:
                        in_docstring = False
                    continue

                if not line.startswith(f"from {pkg}.") or " import " not in line:
                    continue

                import_part = line.split(" import ", 1)[1].strip()

                if import_part.startswith("("):
                    symbol_str = ""
                    for j in range(i + 1, len(init_lines)):
                        next_line = init_lines[j].strip()
                        symbol_str += " " + next_line
                        if ")" in next_line:
                            break
                    for sym in re.findall(r"\b([a-zA-Z_]\w*)\b", symbol_str):
                        if sym != pkg:
                            exported_symbols.append(sym)
                else:
                    for sym in import_part.split(","):
                        sym = sym.strip().rstrip(",")
                        if " #" in sym:
                            sym = sym.split(" #")[0].strip()
                        if sym and not sym.startswith("#"):
                            exported_symbols.append(sym)

            if not exported_symbols:
                continue

            # 解析 __all__ 列表中的符号 (这些是公共 API，即使内部未使用也允许)
            all_symbols: set[str] = set()
            in_all = False
            for line in init_lines:
                stripped = line.strip()
                if stripped.startswith("__all__"):
                    in_all = True
                if in_all:
                    for sym in re.findall(r'"(\w+)"', stripped):
                        all_symbols.add(sym)
                    if "]" in stripped and not stripped.startswith("]"):
                        in_all = False

            # 检测 __getattr__ 懒加载模式 (如 strike/__init__.py)
            has_getattr = "def __getattr__" in init_content

            # 读取所有非 __init__.py 源文件
            combined_usage = ""
            for p in self.source_files:
                if "__init__.py" in p.name:
                    continue
                try:
                    combined_usage += p.read_text(encoding="utf-8", errors="replace") + "\n"
                except OSError:
                    pass

            for symbol in exported_symbols:
                if symbol in _INIT_EXPORT_WHITELIST:
                    continue
                # 符号在 __all__ 中 = 公共 API 导出，跳过
                if symbol in all_symbols:
                    continue
                # __getattr__ 懒加载模式下，导出符号通过属性访问使用，跳过检查
                if has_getattr and f'if name == "{symbol}"' in init_content:
                    continue
                matches = re.findall(rf"\b{re.escape(symbol)}\b", combined_usage)
                if len(matches) <= 1:
                    self.violations.append(
                        Violation(
                            rule="R-IMPORT-4",
                            severity=Severity.INFO,
                            file=f"{pkg}/__init__.py",
                            line=0,
                            description=f"{pkg}/__init__.py 导出的 '{symbol}' 未被实际使用",
                            fix_hint=f"如 {symbol} 确实需要作为公共 API 保留，请添加到 _INIT_EXPORT_WHITELIST",
                        )
                    )

    # == R-EVENT-1 (目标架构 v4.0 / ADR-007): 编排层禁止硬编码组件名 ==
    # 组件差异只准声明在 config/components/*.yaml + core/registry.py（ComponentRegistry）
    # 级别：W0 为 WARNING（既有 dispatcher 尚未迁移）；W4 迁移完成后升级 BLOCKING
    def check_no_hardcoded_component_names(self) -> None:
        """R-EVENT-1: 编排层禁止硬编码组件名字面量（组件差异须声明式）。"""
        Severity, Violation = _get_violation_classes()

        orchestration_files = [
            "core/phases/recon.py",
            "core/phases/arm.py",
            "core/phases/strike.py",
            "core/phases/assess.py",
            "core/phases/report.py",
            "core/phases/executor.py",
            "strike/common/dispatcher.py",
        ]
        # 既有硬编码迁移豁免（W4 交付前消除，见 CP-001 §3.2 与 W4-2）
        exempt_files = {"strike/common/dispatcher.py"}

        comp = r"(?:mcp|a2a|rag|agent|model|memory|session|web)"
        patterns = [
            re.compile(rf'==\s*["\']{comp}["\']'),
            re.compile(rf'["\']component_type["\']\s*\]\s*=\s*["\']{comp}["\']'),
        ]

        for rel in orchestration_files:
            if rel in exempt_files:
                continue
            path = self.root / rel
            if not path.exists():
                continue
            try:
                content = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            hits: list[tuple[int, str]] = []
            for lineno, line in enumerate(content.splitlines(), 1):
                for pat in patterns:
                    if pat.search(line):
                        hits.append((lineno, line.strip()[:80]))
                        break

            if hits:
                self.violations.append(
                    Violation(
                        rule="R-EVENT-1",
                        severity=Severity.WARNING,
                        file=rel,
                        line=hits[0][0],
                        description=(
                            f"编排层硬编码组件名（{hits[0][1]}）— 组件差异须声明在 "
                            f"config/components/*.yaml，编排层查表（ADR-007 / IC-1）"
                        ),
                        fix_hint="改用 ComponentRegistry.get(name) 查表；W4 起本规则升级为 BLOCKING",
                    )
                )

    # == 注册所有检查方法 ==
    guard_cls.check_pipeline_integration = check_pipeline_integration
    guard_cls._check_arm_module_registration = _check_arm_module_registration
    guard_cls._check_strike_module_registration = _check_strike_module_registration
    guard_cls.check_data_flow_consistency = check_data_flow_consistency
    guard_cls._read_all_source = _read_all_source
    guard_cls.check_circular_imports = check_circular_imports
    guard_cls.check_dead_code = check_dead_code
    guard_cls.check_best_practices = check_best_practices
    guard_cls.check_academic_citations = check_academic_citations
    guard_cls.check_asr_completeness = check_asr_completeness
    guard_cls.check_evidence_completeness = check_evidence_completeness
    guard_cls.check_report_completeness = check_report_completeness
    # R-PIPE-6 / R-IMPORT-4: 运行时集成检查 (2026-09-08 patch)
    guard_cls.check_recon_submodule_invocation = check_recon_submodule_invocation
    guard_cls.check_init_export_usage = check_init_export_usage
    # R-NATIVE-1~4: PyRIT 原生组件优先使用检查器 (v1.8)
    guard_cls.check_native_attack_class_usage = check_native_attack_class_usage
    guard_cls.check_native_converter_usage = check_native_converter_usage
    guard_cls.check_native_scorer_usage = check_native_scorer_usage
    guard_cls.check_native_target_usage = check_native_target_usage
    # R-SESSION-1~6: 会话感知攻击架构检查器 (v2.0)
    guard_cls.check_session_module_completeness = check_session_module_completeness
    guard_cls.check_session_integration_completeness = check_session_integration_completeness
    guard_cls.check_session_config_exists = check_session_config_exists
    guard_cls.check_session_test_coverage = check_session_test_coverage
    guard_cls.check_session_pyrit_native_compatibility = check_session_pyrit_native_compatibility
    guard_cls.check_session_context_integration = check_session_context_integration
    # R-DELIVERY-1~5: 红队交付保障框架检查器 (v2.0, 通用化)
    guard_cls.check_delivery_module_size = check_delivery_module_size
    guard_cls.check_delivery_test_coverage = check_delivery_test_coverage
    guard_cls.check_delivery_architecture_alignment = check_delivery_architecture_alignment
    guard_cls.check_delivery_init_export_consistency = check_delivery_init_export_consistency
    guard_cls.check_delivery_module_docstring = check_delivery_module_docstring
    # R-DOC-1~4: 代码-文档同步护栏检查器 (v2.7)
    guard_cls.check_cli_params_documented = check_cli_params_documented
    guard_cls.check_attack_gap_documented = check_attack_gap_documented
    guard_cls.check_requirements_guardrails_synced = check_requirements_guardrails_synced
    guard_cls.check_readme_version_synced = check_readme_version_synced
    # R-L1 / R-L7: 攻击端防御逻辑检查 + 根目录结构检查 (v2.9 新增实现, 修复 spec-code drift)
    guard_cls.check_no_defense_in_attack_dirs = check_no_defense_in_attack_dirs
    guard_cls.check_top_level_structure = check_top_level_structure
    guard_cls.check_no_hardcoded_component_names = check_no_hardcoded_component_names


# ===============================================================================
# R-DOC: Code-Documentation Sync Checks (v2.7)
# ===============================================================================

# Document paths
_DOCS_GAP_PATH = "docs/specs/55-ATTACK-GAP-CLOSURE.md"
_DOCS_REQ_PATH = "docs/specs/20-REQUIREMENTS.md"
_DOCS_GR_PATH = "docs/specs/40-GUARDRAILS.md"
_DOCS_README_PATH = "docs/specs/README.md"
_CONFIG_PATH = "core/config.py"


def _read_file_safely(root: Path, rel_path: str) -> str:
    """Read file with UTF-8 encoding, return empty string on failure."""
    try:
        return (root / rel_path).read_text(encoding="utf-8", errors="replace")
    except FileNotFoundError:
        return ""
    except OSError:
        return ""


def check_cli_params_documented(self) -> None:  # type: ignore[override]
    """R-DOC-1: Every CLI option must be self-describing.

    The CLI parameter SSOT is the code itself (argparse in core/config.py and
    main.py). Each ``--xxx`` option must carry a non-empty ``help=`` so that
    ``python main.py --help`` is the authoritative, always-in-sync reference
    (specs/40-GUARDRAILS.md R-DOC-1). We no longer depend on an external
    markdown doc, which drifted and was removed from the repo.
    """
    Severity, Violation = _get_violation_classes()

    cli_files = ["core/config.py", "main.py"]
    missing = []
    for rel in cli_files:
        content = _read_file_safely(self.root, rel)
        if not content:
            continue
        for call in _iter_add_argument_calls(content):
            pre = re.split(r"[A-Za-z_]\w*\s*=", call, maxsplit=1)[0]
            options = re.findall(r'["\'](--[\w-]+)["\']', pre)
            if not options:
                continue
            if _call_has_help(call):
                continue
            missing.extend(options)

    if missing:
        uniq = sorted(set(missing))
        self.violations.append(
            Violation(
                rule="R-DOC-1",
                severity=Severity.WARNING,
                file=", ".join(cli_files),
                line=0,
                description=(
                    f"CLI options without a non-empty help= (code is the CLI "
                    f"SSOT; run `python main.py --help` to verify): "
                    f"{', '.join(uniq[:5])}{'...' if len(uniq) > 5 else ''}"
                ),
                fix_hint=(
                    "Add a non-empty help= to each add_argument(...) so the CLI "
                    "is self-describing (specs/40-GUARDRAILS.md R-DOC-1)."
                ),
            )
        )


def _iter_add_argument_calls(content: str):
    """Yield the text of each top-level ``add_argument(...)`` call in *content*."""
    for m in re.finditer(r"add_argument\s*\(", content):
        start = m.start()
        i = content.index("(", start)
        depth = 0
        in_str = None
        while i < len(content):
            ch = content[i]
            if in_str:
                if ch == "\\":
                    i += 2
                    continue
                if ch == in_str:
                    in_str = None
                i += 1
                continue
            if ch in ("'", '"'):
                in_str = ch
            elif ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    yield content[start : i + 1]
                    break
            i += 1


def _call_has_help(call: str) -> bool:
    """Return True if an ``add_argument(...)`` call sets a non-empty ``help=``."""
    m = re.search(r"help\s*=\s*([^\n,)]+)", call)
    if not m:
        return False
    rhs = m.group(1).strip().strip("\"'")
    if rhs == "":
        return False
    if rhs.startswith("("):
        return False
    return True


def check_attack_gap_documented(self) -> None:  # type: ignore[override]
    """R-DOC-2: New attack modules must be documented in 55-ATTACK-GAP-CLOSURE.md."""
    Severity, Violation = _get_violation_classes()

    gap_content = _read_file_safely(self.root, _DOCS_GAP_PATH)
    if not gap_content:
        return

    # Find attack executor modules in strike/ directory
    strike_dir = self.root / "strike"
    if not strike_dir.is_dir():
        return

    undocumented = []
    for py_file in sorted(strike_dir.glob("*_executor.py")):
        module_name = py_file.stem
        # Check if module is referenced in gap doc
        if module_name not in gap_content and py_file.name not in gap_content:
            undocumented.append(module_name)

    if undocumented:
        self.violations.append(
            Violation(
                rule="R-DOC-2",
                severity=Severity.WARNING,
                file="strike/",
                line=0,
                description=f"Attack modules not documented in 55-ATTACK-GAP-CLOSURE.md: {', '.join(undocumented)}",
                fix_hint=f"Add gap analysis section in docs/specs/55-ATTACK-GAP-CLOSURE.md for: {', '.join(undocumented)}",
            )
        )


def check_requirements_guardrails_synced(self) -> None:  # type: ignore[override]
    """R-DOC-3: New requirements/guardrails must be synced across 20-REQUIREMENTS.md and 40-GUARDRAILS.md."""
    Severity, Violation = _get_violation_classes()

    req_content = _read_file_safely(self.root, _DOCS_REQ_PATH)
    gr_content = _read_file_safely(self.root, _DOCS_GR_PATH)

    if not req_content or not gr_content:
        return

    # Look for potential orphans: REQ items that might need guardrail rules
    # This is a heuristic check - flag patterns like "check_xxx" functions without R-xxx
    checker_funcs = set(re.findall(r"def (check_\w+)", gr_content))
    registered_checkers = set(re.findall(r"guard_cls\.(\w+) = ", gr_content))

    orphans = checker_funcs - registered_checkers
    # Filter out private/internal checkers
    orphans = {f for f in orphans if not f.startswith("_") and f != "check_mcpsec_bridge_integration"}

    if orphans:
        self.violations.append(
            Violation(
                rule="R-DOC-3",
                severity=Severity.WARNING,
                file=_DOCS_GR_PATH,
                line=0,
                description=f"Checker functions not registered in 1F registry: {', '.join(list(orphans)[:3])}{'...' if len(orphans) > 3 else ''}",
                fix_hint="Register new checker functions in 40-GUARDRAILS.md 1F registry and tools/guard_extended.py register_extended_checks()",
            )
        )


def check_readme_version_synced(self) -> None:  # type: ignore[override]
    """R-DOC-4: Document version numbers must be synced in README.md pyramid index."""
    Severity, Violation = _get_violation_classes()

    readme_content = _read_file_safely(self.root, _DOCS_README_PATH)
    if not readme_content:
        return

    # Extract version numbers from README
    versions_in_readme = {}
    for match in re.finditer(
        r"\[(\d+)-(CONSTITUTION|ARCHITECTURE|REQUIREMENTS|TASKS|GUARDRAILS|ROADMAP|ATTACK-GAP|COMPONENT|CROSS-MODEL)[^\]]*\]\([^)]+\).*?\b(v[\d.]+)\b",
        readme_content,
    ):
        doc_key = f"{match.group(1)}-{match.group(2)}"
        versions_in_readme[doc_key] = match.group(3)

    # Check individual doc files for mismatches
    # 版本行格式：`> **版本**：vX.Y（...）`。冒号兼容全角/半角（历史文件两种都出现过）。
    _VERSION_PATTERN = r"\*\*版本\*\*[:：]\s*(v[\d.]+)"
    doc_files = {
        "00-CONSTITUTION": ("docs/specs/00-CONSTITUTION.md", _VERSION_PATTERN),
        "10-ARCHITECTURE": ("docs/specs/10-ARCHITECTURE.md", _VERSION_PATTERN),
        "20-REQUIREMENTS": ("docs/specs/20-REQUIREMENTS.md", _VERSION_PATTERN),
        "30-TASKS": ("docs/specs/30-TASKS.md", _VERSION_PATTERN),
        "40-GUARDRAILS": ("docs/specs/40-GUARDRAILS.md", _VERSION_PATTERN),
        "50-ROADMAP": ("docs/specs/50-ROADMAP.md", _VERSION_PATTERN),
        "80-COMPONENT": ("docs/specs/80-COMPONENT-ARCHITECTURE-RULES.md", _VERSION_PATTERN),
        "55-ATTACK-GAP": ("docs/specs/55-ATTACK-GAP-CLOSURE.md", _VERSION_PATTERN),
        "60-CROSS-MODEL": ("docs/specs/60-CROSS-MODEL-VERIFICATION.md", _VERSION_PATTERN),
    }

    mismatches = []
    for key, (doc_path, version_pattern) in doc_files.items():
        doc_content = _read_file_safely(self.root, doc_path)
        if not doc_content:
            continue
        doc_match = re.search(version_pattern, doc_content)
        if doc_match:
            doc_version = doc_match.group(1)
            readme_key = (
                key.replace("CONSTITUTION", "CONSTITUTION")
                .replace("ARCHITECTURE", "ARCHITECTURE")
                .replace("REQUIREMENTS", "REQUIREMENTS")
                .replace("GUARDRAILS", "GUARDRAILS")
                .replace("ATTACK-GAP", "ATTACK-GAP")
            )
            if readme_key in versions_in_readme:
                if versions_in_readme[readme_key] != doc_version:
                    mismatches.append((key, versions_in_readme[readme_key], doc_version))

    if mismatches:
        details = "; ".join(f"{k}: README={v1}, doc={v2}" for k, v1, v2 in mismatches)
        self.violations.append(
            Violation(
                rule="R-DOC-4",
                severity=Severity.INFO,
                file=_DOCS_README_PATH,
                line=0,
                description=f"Version mismatch: {details}",
                fix_hint="Sync version numbers in docs/specs/README.md pyramid index to match individual document version headers",
            )
        )


# ===============================================================================
# R-MCPSec: MCPSec v2.7.2 Bridge Integration
# ===============================================================================

_MCPSEC_REQUIRED_MODULES = {
    "malicious_mcp_server": "Malicious MCP server for side-effect verification",
    "dynamic_mcp_seeds": "Dynamic seed generation via MCPSec",
    "mcpsec_orchestrator": "Full MCPSec + PyRIT orchestrator",
}

_MCPSEC_REQUIRED_FIELDS = [
    "mcpsec_surface",
    "mcpsec_scan_results",
    "mcpsec_version",
]


def check_mcpsec_bridge_integration(self) -> None:
    """R-PIPE-7 / R-MCPSec: MCPSec v2.7.2 bridge integration checks."""
    Severity, Violation = _get_violation_classes()

    strike_dir = self.root / "strike"

    for module_name, description in _MCPSEC_REQUIRED_MODULES.items():
        module_file = strike_dir / f"{module_name}.py"
        if not module_file.exists():
            self.violations.append(
                Violation(
                    rule="R-MCPSec-1",
                    severity=Severity.WARNING,
                    file=f"strike/{module_name}.py",
                    line=0,
                    description=f"Missing MCPSec module: {description}",
                    fix_hint=f"Create strike/{module_name}.py for MCPSec v2.7.2 integration",
                )
            )

    context_file = self.root / "core" / "context.py"
    if context_file.exists():
        context_content = context_file.read_text(encoding="utf-8", errors="replace")
        for field_name in _MCPSEC_REQUIRED_FIELDS:
            if field_name not in context_content:
                self.violations.append(
                    Violation(
                        rule="R-MCPSec-2",
                        severity=Severity.WARNING,
                        file="core/context.py",
                        line=0,
                        description=f"PipelineContext missing MCPSec field: {field_name}",
                        fix_hint=f"Add {field_name}: ... to PipelineContext dataclass",
                    )
                )

    old_mcp_enumerator = self.root / "recon" / "mcp_enumerator.py"
    if old_mcp_enumerator.exists():
        self.violations.append(
            Violation(
                rule="R-MCPSec-3",
                severity=Severity.BLOCKING,
                file="recon/mcp_enumerator.py",
                line=0,
                description="Self-developed mcp_enumerator.py still exists (should be replaced by MCPSec)",
                fix_hint="Delete recon/mcp_enumerator.py and use MCPSec bridge instead",
            )
        )

    old_helpers = self.root / "recon" / "_mcp_enumerator_helpers.py"
    if old_helpers.exists():
        self.violations.append(
            Violation(
                rule="R-MCPSec-3",
                severity=Severity.BLOCKING,
                file="recon/_mcp_enumerator_helpers.py",
                line=0,
                description="Self-developed _mcp_enumerator_helpers.py still exists",
                fix_hint="Delete recon/_mcp_enumerator_helpers.py and use MCPSec bridge instead",
            )
        )


# ===============================================================================
# R-NATIVE-1~4: PyRIT 原生组件优先使用检查器 (v1.8)
# ===============================================================================


def check_native_attack_class_usage(self) -> None:
    """R-NATIVE-1: 检测是否自行实现了本应使用 PyRIT 原生 API 的攻击"""
    Severity, Violation = _get_violation_classes()

    check_files = [
        self.root / "strike" / "escalation_runtime.py",
        self.root / "strike" / "multi_turn_attacks.py",
        self.root / "strike" / "native_attacks.py",
    ]

    for file_path in check_files:
        if not file_path.exists():
            continue

        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        rel_path = str(file_path.relative_to(self.root))

        for keyword, native_class in _NATIVE_ATTACK_KEYWORDS.items():
            keyword_pattern = rf"\b{keyword}\b"
            if not re.search(keyword_pattern, content, re.IGNORECASE):
                continue

            native_import_patterns = [
                f"from pyrit.executor.attack import {native_class}",
                f"from pyrit.executor.attack.multi_turn import {native_class}",
                f"from pyrit.executor.attack.multi_turn.crescendo_attack import {native_class}",
                f"from pyrit.executor.attack.multi_turn.tap_attack import {native_class}",
                f"from pyrit.executor.attack.multi_turn.pair_attack import {native_class}",
            ]
            has_native_import = any(p in content for p in native_import_patterns)

            manual_loop_patterns = [
                r"for\s+turn_num.*PromptSendingAttack",
                r"for\s+turn.*?in\s+range.*\n.*PromptSendingAttack",
                rf"_generate_{keyword}_prompts",
            ]
            has_manual_loop = any(re.search(p, content, re.IGNORECASE | re.DOTALL) for p in manual_loop_patterns)

            if has_manual_loop and not has_native_import:
                violation_line = 0
                for i, line in enumerate(content.split("\n"), 1):
                    if f"_generate_{keyword}_prompts" in line or f"execute_{keyword}_attack" in line:
                        violation_line = i
                        break

                self.violations.append(
                    Violation(
                        rule="R-NATIVE-1",
                        severity=Severity.BLOCKING,
                        file=rel_path,
                        line=violation_line,
                        description=(
                            f"检测到自行实现 {keyword} 攻击（手动 for loop + PromptSendingAttack）"
                            f"应使用 PyRIT 原生 {native_class}"
                        ),
                        fix_hint=(
                            f"导入 {native_class} 并替换手动循环："
                            f"from pyrit.executor.attack.multi_turn import {native_class}; "
                            f"attack = {native_class}(objective_target=ctx.objective_target, ...)"
                        ),
                    )
                )


def check_native_converter_usage(self) -> None:
    """R-NATIVE-2: 检测是否自行实现了本应使用 PyRIT 原生 Converter 的编码/解码/混淆"""
    Severity, Violation = _get_violation_classes()

    check_dirs = [self.root / "arm", self.root / "strike"]

    custom_impl_patterns = [
        r"def\s+base64_(?:encode|decode)\s*\(",
        r"def\s+rot13\s*\(",
        r"def\s+binary_(?:encode|decode)\s*\(",
        r"def\s+url_(?:encode|decode)\s*\(",
        r"def\s+unicode_(?:substitute|confuse|replace)\s*\(",
        r"def\s+caesar_(?:encode|decode|shift)\s*\(",
        r"def\s+vigenere_(?:encode|decode)\s*\(",
        r"def\s+atbash\s*\(",
        r"def\s+translate\s*\(",
        r"def\s+diacritic_(?:add|remove)\s*\(",
        r"def\s+char_swap\s*\(",
        r"def\s+char_noise\s*\(",
        r"def\s+random_capital\s*\(",
        r"def\s+suffix_append\s*\(",
        r"def\s+string_join\s*\(",
        r"def\s+insert_punctuation\s*\(",
        r"def\s+zero_width_(?:insert|remove)\s*\(",
        r"def\s+bidi_(?:insert|reverse)\s*\(",
    ]

    for check_dir in check_dirs:
        if not check_dir.exists():
            continue

        for py_file in check_dir.glob("*.py"):
            if py_file.name == "__init__.py":
                continue

            try:
                content = py_file.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            rel_path = str(py_file.relative_to(self.root))

            for pattern in custom_impl_patterns:
                match = re.search(pattern, content, re.IGNORECASE)
                if match:
                    line_num = content[: match.start()].count("\n") + 1
                    has_native_converter = (
                        "from pyrit.converter import" in content or "import pyrit.converter" in content
                    )

                    if not has_native_converter:
                        self.violations.append(
                            Violation(
                                rule="R-NATIVE-2",
                                severity=Severity.WARNING,
                                file=rel_path,
                                line=line_num,
                                description=f"检测到自研编码/解码/混淆函数：{match.group().strip()}，应使用 PyRIT 原生 Converter",
                                fix_hint="导入 PyRIT 原生 Converter 并替换自研实现：from pyrit.converter import Base64Converter, ...",
                            )
                        )


def check_native_scorer_usage(self) -> None:
    """R-NATIVE-3: 检测是否自行实现了本应使用 PyRIT 原生 Scorer 的评分逻辑"""
    Severity, Violation = _get_violation_classes()

    check_dirs = [self.root / "assess", self.root / "strike"]

    custom_impl_patterns = [
        r"def\s+check_refusal\s*\(",
        r"def\s+is_refusal\s*\(",
        r"def\s+check_success\s*\(",
        r"def\s+is_success\s*\(",
        r"def\s+regex_match\s*\(",
        r"def\s+substring_match\s*\(",
        r"def\s+contains_pattern\s*\(",
        r"def\s+classify_content\s*\(",
        r"def\s+content_classification\s*\(",
        r"def\s+sql_injection_check\s*\(",
        r"def\s+xss_check\s*\(",
        r"def\s+ssrf_check\s*\(",
        r"def\s+command_injection_check\s*\(",
        r"def\s+keyword_match\s*\(",
        r"def\s+credential_leak\s*\(",
        r"def\s+plagiarism_check\s*\(",
    ]

    for check_dir in check_dirs:
        if not check_dir.exists():
            continue

        for py_file in check_dir.glob("*.py"):
            if py_file.name == "__init__.py":
                continue

            try:
                content = py_file.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            rel_path = str(py_file.relative_to(self.root))

            for pattern in custom_impl_patterns:
                match = re.search(pattern, content, re.IGNORECASE)
                if match:
                    line_num = content[: match.start()].count("\n") + 1
                    has_native_scorer = "from pyrit.score import" in content or "import pyrit.score" in content

                    if not has_native_scorer:
                        self.violations.append(
                            Violation(
                                rule="R-NATIVE-3",
                                severity=Severity.WARNING,
                                file=rel_path,
                                line=line_num,
                                description=f"检测到自研评分函数：{match.group().strip()}，应使用 PyRIT 原生 Scorer",
                                fix_hint="导入 PyRIT 原生 Scorer 并替换自研实现：from pyrit.score import SelfAskRefusalScorer, ...",
                            )
                        )


def check_native_target_usage(self) -> None:
    """R-NATIVE-4: 检测是否自行实现了本应使用 PyRIT 原生 Target 的连接逻辑"""
    Severity, Violation = _get_violation_classes()

    check_dirs = [self.root / "recon", self.root / "strike"]

    custom_target_patterns = [
        r"class\s+HTTPRequestTarget\s*\(",
        r"class\s+HTTPTarget\s*\(",
        r"class\s+APITarget\s*\(",
        r"class\s+WebSocketTarget\s*\(",
        r"class\s+OpenAIChat\s*\(",
        r"class\s+OpenAICompletion\s*\(",
        r"class\s+OpenAIResponse\s*\(",
        r"class\s+PromptTarget\s*\(",
        r"class\s+TextTarget\s*\(",
        r"class\s+RoundRobinTarget\s*\(",
        r"class\s+RealtimeTarget\s*\(",
    ]

    for check_dir in check_dirs:
        if not check_dir.exists():
            continue

        for py_file in check_dir.glob("*.py"):
            if py_file.name == "__init__.py":
                continue

            try:
                content = py_file.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            rel_path = str(py_file.relative_to(self.root))

            for pattern in custom_target_patterns:
                match = re.search(pattern, content, re.IGNORECASE)
                if match:
                    line_num = content[: match.start()].count("\n") + 1
                    has_native_target = (
                        "from pyrit.prompt_target import" in content or "import pyrit.prompt_target" in content
                    )

                    if not has_native_target:
                        self.violations.append(
                            Violation(
                                rule="R-NATIVE-4",
                                severity=Severity.WARNING,
                                file=rel_path,
                                line=line_num,
                                description=f"检测到自研 Target 类：{match.group().strip()}，应使用 PyRIT 原生 PromptTarget",
                                fix_hint="导入 PyRIT 原生 Target 并替换自研实现：from pyrit.prompt_target import HTTPTarget, ...",
                            )
                        )


# ===============================================================================
# R-SESSION: 会话感知攻击架构检查 (Session-Aware Attack Framework)
# ===============================================================================

# R-SESSION 必须存在的模块
_SESSION_REQUIRED_MODULES = {
    "strike/session/__init__.py": ["SessionStateManager", "SessionConfig"],
    "strike/session/session_manager.py": ["SessionStateManager"],
    "strike/session/session_config.py": ["SessionConfig", "ExtractionRule", "InjectionRule"],
    "strike/session/extraction.py": ["SessionExtractor"],
    "strike/session/injection.py": ["SessionInjector"],
    "strike/session/validation.py": ["SessionValidator"],
    "strike/session/rotation.py": ["SessionRotationPolicy"],
}

# R-SESSION 必须集成的消费方
_SESSION_REQUIRED_CONSUMERS = {
    "strike/executor.py": ["SessionStateManager", "session_state"],
    "strike/escalation_runtime.py": ["SessionStateManager", "session_state"],
    "recon/target_builder.py": ["SessionStateManager"],
}

# R-SESSION 必须存在的配置
_SESSION_REQUIRED_CONFIGS = [
    "strike/session/defaults.yaml",
]

# R-SESSION 必须存在的测试 (2026-09-11 对齐子目录结构)
_SESSION_REQUIRED_TESTS = [
    "tests/session/test_session_manager.py",
    "tests/session/test_session_extraction.py",
    "tests/session/test_session_injection.py",
]


def check_session_module_completeness(self) -> None:
    """R-SESSION-1: 检查会话感知模块完整性 (BLOCKING)"""
    Severity, Violation = _get_violation_classes()

    for module_path, required_symbols in _SESSION_REQUIRED_MODULES.items():
        full_path = self.root / module_path
        if not full_path.exists():
            self.violations.append(
                Violation(
                    rule="R-SESSION-1",
                    severity=Severity.BLOCKING,
                    file=module_path,
                    line=0,
                    description=f"缺少会话模块: {module_path}",
                    fix_hint=f"创建 {module_path} 并实现: {', '.join(required_symbols)}",
                )
            )
            continue

        try:
            content = full_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        for symbol in required_symbols:
            # 检查类/函数定义或导入
            def_pattern = rf"(class|def)\s+{symbol}\s*[:\(]"
            import_pattern = rf"from\s+.*import\s+.*{symbol}|import\s+.*{symbol}|\b{symbol}\b"
            if not re.search(def_pattern, content) and not re.search(import_pattern, content):
                self.violations.append(
                    Violation(
                        rule="R-SESSION-1",
                        severity=Severity.BLOCKING,
                        file=module_path,
                        line=0,
                        description=f"{module_path} 缺少必需符号: {symbol}",
                        fix_hint=f"在 {module_path} 中定义或导入 {symbol}",
                    )
                )


def check_session_integration_completeness(self) -> None:
    """R-SESSION-2: 检查会话感知集成完整性 (WARNING)

    2026-09-09: 降级为WARNING，会话感知攻击架构为v2.0特性，
    当前代码库尚未实施，保留检查但不阻断。
    """
    Severity, Violation = _get_violation_classes()

    for module_path, required_symbols in _SESSION_REQUIRED_CONSUMERS.items():
        full_path = self.root / module_path
        if not full_path.exists():
            continue  # 模块不存在不检查（可能是可选的）

        try:
            content = full_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        for symbol in required_symbols:
            # 检查导入或使用
            import_pattern = rf"from\s+.*import\s+.*{symbol}|import\s+.*{symbol}"
            usage_pattern = rf"\b{symbol}\b"
            if not re.search(import_pattern, content) and not re.search(usage_pattern, content):
                self.violations.append(
                    Violation(
                        rule="R-SESSION-2",
                        severity=Severity.WARNING,
                        file=module_path,
                        line=0,
                        description=f"{module_path} 未集成会话感知: 缺少 {symbol}",
                        fix_hint=f"在 {module_path} 中导入并使用 {symbol}",
                    )
                )


def check_session_config_exists(self) -> None:
    """R-SESSION-3: 检查会话配置文件存在 (WARNING)"""
    Severity, Violation = _get_violation_classes()

    for config_path in _SESSION_REQUIRED_CONFIGS:
        full_path = self.root / config_path
        if not full_path.exists():
            self.violations.append(
                Violation(
                    rule="R-SESSION-3",
                    severity=Severity.WARNING,
                    file=config_path,
                    line=0,
                    description=f"缺少会话配置文件: {config_path}",
                    fix_hint=f"创建 {config_path} 定义默认会话提取/注入规则",
                )
            )


def check_session_test_coverage(self) -> None:
    """R-SESSION-4: 检查会话模块测试覆盖 (WARNING)"""
    Severity, Violation = _get_violation_classes()

    for test_path in _SESSION_REQUIRED_TESTS:
        full_path = self.root / test_path
        if not full_path.exists():
            self.violations.append(
                Violation(
                    rule="R-SESSION-4",
                    severity=Severity.WARNING,
                    file=test_path,
                    line=0,
                    description=f"缺少会话测试: {test_path}",
                    fix_hint=f"创建 {test_path} 覆盖会话核心功能",
                )
            )


def check_session_pyrit_native_compatibility(self) -> None:
    """R-SESSION-5: 检查 PyRIT 原生兼容性 (BLOCKING)"""
    Severity, Violation = _get_violation_classes()

    session_dir = self.root / "strike" / "session"
    if not session_dir.exists():
        return

    # 检查是否使用了 PyRIT 原生 HTTPTarget 回调机制
    target_builder = self.root / "recon" / "target_builder.py"
    if target_builder.exists():
        content = target_builder.read_text(encoding="utf-8", errors="replace")
        if "SessionStateManager" in content and "callback_function" not in content:
            self.violations.append(
                Violation(
                    rule="R-SESSION-5",
                    severity=Severity.BLOCKING,
                    file="recon/target_builder.py",
                    line=0,
                    description="SessionStateManager 未通过 callback_function 集成到 PyRIT 原生回调链",
                    fix_hint="使用 HTTPTarget.callback_function 机制集成会话状态管理",
                )
            )

    # 检查是否使用了 ConversationManager
    executor = self.root / "strike" / "executor.py"
    if executor.exists():
        content = executor.read_text(encoding="utf-8", errors="replace")
        if "SessionStateManager" in content:
            if "ConversationManager" not in content and "conversation_manager" not in content:
                self.violations.append(
                    Violation(
                        rule="R-SESSION-5",
                        severity=Severity.WARNING,
                        file="strike/executor.py",
                        line=0,
                        description="建议通过 ConversationManager 集成会话状态到多轮攻击",
                        fix_hint="使用 PyRIT ConversationManager 管理多轮对话上下文",
                    )
                )


def check_session_context_integration(self) -> None:
    """R-SESSION-6: 检查 PipelineContext 会话字段集成 (WARNING)"""
    Severity, Violation = _get_violation_classes()

    context_file = self.root / "core" / "context.py"
    if not context_file.exists():
        return

    content = context_file.read_text(encoding="utf-8", errors="replace")
    if "session_state" not in content.lower() and "session" not in content.lower():
        self.violations.append(
            Violation(
                rule="R-SESSION-6",
                severity=Severity.WARNING,
                file="core/context.py",
                line=0,
                description="PipelineContext 缺少 session_state 字段",
                fix_hint="在 PipelineContext 中新增 session_state: SessionStateManager 字段",
            )
        )


# ===============================================================================
# R-DELIVERY: 红队交付保障框架规则 (Red Team Delivery Assurance Framework)
# 通用规则：适用于所有包的任意模块和功能的优化
# 覆盖范围：strike/recon/arm/assess/core/report/utils/tools 全部分层
# 不依赖于特定模块，任意功能优化均自动验证
# ===============================================================================

# R-DELIVERY-1: 模块行数限制阈值统一定义在 tools.guard
# (_SIZE_WARNING_THRESHOLD=850 / _SIZE_BLOCKING_THRESHOLD=1500 + _SIZE_BYPASS_WHITELIST)，
# 由 check_delivery_module_size 直接 import 复用，避免重复硬编码/漂移。

# R-DELIVERY-2: 需要测试覆盖的包
_DELIVERY_PACKAGES_REQUIRING_TESTS = [
    "strike",
    "recon",
    "arm",
    "assess",
    "core",
    "report",
]

# R-DELIVERY-2 豁免白名单: 已通过集成测试覆盖 / PyRIT原生封装
# 2026-09-09: 已通过 test_strike.py / test_recon.py 集成测试覆盖
_DELIVERY_TEST_WHITELIST = {
    # strike/ - 通过 test_strike.py 集成覆盖
    "strike/escalation_runtime.py",  # Crescendo/TAP升级链 (test_strike.py覆盖)
    "strike/mcpsec_orchestrator.py",  # MCPSec MCP/RAG专用攻击编排 (test_strike.py覆盖)
    "strike/mcp_rag_attack.py",  # MCP/RAG攻击 (test_strike.py覆盖)
    "strike/file_upload_executor.py",  # 文件上传执行器 (test_strike.py覆盖)
    "strike/web_page_injector.py",  # 恶意页面生成器 (test_strike.py覆盖)
    "strike/dynamic_mcp_seeds.py",  # 动态MCP种子生成 (test_strike.py覆盖)
    "strike/malicious_mcp_server.py",  # 恶意MCP服务器 (test_strike.py覆盖)
    "strike/decision_safety.py",  # 安全检查器 (test_decision_system.py覆盖)
    "strike/pair_tap_strategies.py",  # PAIR/TAP策略 (test_strike.py覆盖)
    "strike/attack_knowledge_base.py",  # 攻击知识库 (test_decision_system.py覆盖)
    "strike/asr_trend_tracker.py",  # ASR趋势追踪 (test_decision_system.py覆盖)
    "strike/auth_attacks.py",  # 认证攻击 (test_strike.py集成覆盖)
    "strike/backdoor_attack.py",  # 后门攻击 (test_advanced_attacks.py覆盖)
    "strike/multimodal_injection.py",  # 多模态注入 (test_advanced_attacks.py覆盖)
    "strike/output_filter_bypass.py",  # 输出过滤绕过 (test_advanced_attacks.py覆盖)
    "strike/http_attack_engine.py",  # HTTP攻击引擎 (test_advanced_attacks.py覆盖)
    "strike/audit_evasion.py",  # 审计规避 (test_advanced_attacks.py覆盖)
    "strike/adaptive_executor.py",  # 自适应执行器，executor.py子集
    "strike/web_attacks.py",  # Web攻击入口
    "strike/web_orchestrator.py",  # Web编排器
    "strike/asr_forensics.py",  # Why-Success取证 (test_strike.py覆盖)
    "strike/executor.py",  # 主攻击执行器 (test_strike.py覆盖)
    "strike/rag_targeted_consumer.py",  # RAG定向消费 (test_strike.py覆盖)
    "strike/document_poisoner.py",  # 文档投毒 (test_strike.py覆盖)
    # recon/ - 通过 test_recon.py 集成覆盖
    "recon/target_wrapper.py",  # レート限制封装 (test_recon.py覆盖)
    "recon/rag_pipeline_probe.py",  # RAG流水线探测 (test_rag_metadata_parser.py覆盖)
    "recon/stealth_timing.py",  # 隐蔽计时 (test_recon.py覆盖)
    "recon/recursive_expander.py",  # 递归扩展器 (test_recon.py覆盖)
    "recon/sse_parser.py",  # SSE解析器 (test_recon.py覆盖)
    "recon/system_prompt_extractor.py",  # 系统提示提取 (test_recon.py覆盖)
    "recon/prompt_injector.py",  # 黑盒prompt注入 (test_recon.py覆盖)
    "recon/health_probe.py",  # 健康探测 (test_recon.py覆盖)
    "recon/rag_typo_fuzzer.py",  # 拼写模糊 (test_rag_metadata_parser.py覆盖)
    "recon/burp_parser.py",  # Burp解析器 (test_recon.py覆盖)
    "recon/target_builder.py",  # 目标构建器 (test_recon.py覆盖)
    "recon/endpoint_sorter.py",  # 端点排序 (test_recon.py覆盖)
    "recon/a2a_discoverer.py",  # A2A发现 (test_recon.py覆盖)
    "recon/a2a_agent_card.py",  # A2A代理卡 (test_recon.py覆盖)
    "recon/openapi_discoverer.py",  # OpenAPI发现 (test_recon.py覆盖)
    "recon/guardrail_detector.py",  # 护栏检测 (test_recon.py覆盖)
    "recon/auth_detector.py",  # 认证检测 (test_recon.py覆盖)
    "recon/target_router.py",  # 目标路由器 (test_recon.py覆盖)
    "recon/confidence_scorer.py",  # 置信度评分 (test_recon.py覆盖)
    "recon/config_loader.py",  # 配置加载器 (test_recon.py覆盖)
    "recon/fingerprint.py",  # 指纹提取 (test_recon.py覆盖)
    "recon/adaptive_probe_config.py",  # 自适应探针配置 (test_recon.py覆盖)
    "recon/trust_chain_probe.py",  # 信任链探针 (test_recon.py覆盖)
    "recon/trust_level_enum.py",  # 信任层级枚举 (test_recon.py覆盖)
    "recon/capability_detector.py",  # 能力检测器 (test_recon.py覆盖)
    "recon/api_classifier.py",  # API分类器 (test_recon.py覆盖)
    "recon/capability_probe.py",  # 能力探针 (test_recon.py覆盖)
    "recon/model_seed_mapper.py",  # 模型种子映射 (test_recon.py覆盖)
    "recon/stealth_config.py",  # 隐蔽配置 (test_recon.py覆盖)
    "recon/rag_metadata_parser.py",  # RAG元数据解析器 (test_rag_metadata_parser.py覆盖)
    # arm/ - 通过 test_arm.py 集成覆盖
    "arm/seed_ranker.py",  # 种子排序器 (test_arm.py覆盖)
    "arm/steganography_encoder.py",  # 隐写编码器 (test_arm.py覆盖)
    "arm/unicode_code_obfuscator.py",  # Unicode混淆器 (test_arm.py覆盖)
    # core/ - 通过 test_core.py / test_strike.py 集成覆盖
    "core/config.py",  # CLI配置 (test_core.py覆盖)
    "core/context.py",  # 流水线上下文 (test_core.py覆盖)
    "core/orchestrator.py",  # 编排器 (test_core.py覆盖)
    "core/cleanup.py",  # 清理模块 (test_core.py覆盖)
    "core/initializer_registry.py",  # 初始化注册表 (test_core.py覆盖)
    "core/logging_config.py",  # 日志配置 (test_core.py覆盖)
    "core/seed_loader.py",  # 数据加载器 (集成测试覆盖)
    # recon/
    "recon/orchestrator.py",  # 编排器 (集成测试覆盖)
    # assess/
    "assess/asr_manager.py",  # ASR管理器 (test_assess.py覆盖)
    "assess/asr_stats.py",  # ASR统计 (test_assess.py覆盖)
    "assess/scorer.py",  # 评分器 (test_assess.py覆盖)
    "assess/judge_manager.py",  # 评判管理器 (test_assess.py覆盖)
    "assess/score_pipeline.py",  # 评分流水线 (test_assess.py覆盖)
    # report/
    "report/generator.py",  # 报告生成器 (test_report.py覆盖)
    "report/evidence.py",  # 证据收集 (test_report.py覆盖)
    "report/evidence_extract.py",  # 证据提取 (test_report.py覆盖)
    "report/owasp_constants.py",  # OWASP常量 (test_report.py覆盖)
    "report/owasp_mapping.py",  # OWASP映射 (test_report.py覆盖)
    "report/poc_generator.py",  # PoC生成器 (test_report.py覆盖)
    "report/pyrit_native_output.py",  # PyRIT输出 (test_report.py覆盖)
    "report/report_html.py",  # HTML报告 (test_report.py覆盖)
    "report/report_markdown.py",  # Markdown报告 (test_report.py覆盖)
    "report/report_sections.py",  # 报告段落 (test_report.py覆盖)
    "report/sarif_report.py",  # SARIF报告 (test_report.py覆盖)
}

# R-DELIVERY-3: 架构分层定义 (对齐 10-ARCHITECTURE.md)
_DELIVERY_ARCHITECTURE_LAYERS = {
    "recon": "recon",
    "arm": "arm",
    "strike": "strike",
    "assess": "assess",
    "core": "core",
    "report": "report",
    "utils": "utils",
    "tools": "tools",
}

# R-DELIVERY-4: 需要导出公共API的包
_DELIVERY_PACKAGES_WITH_PUBLIC_API = [
    "strike/session",
    "strike",
    "recon",
    "arm",
    "assess",
    "core",
    "report",
]

# R-DELIVERY-5: 必须包含docstring的模块前缀
_DELIVERY_MODULES_REQUIRING_DOCSTRING = [
    "strike/",
    "recon/",
    "arm/",
    "assess/",
    "core/",
    "report/",
    "utils/",
]


def check_delivery_module_size(self) -> None:
    """R-DELIVERY-1: 检查交付模块行数限制 (与 R-SIZE 治理统一)

    与项目实际的 R-SIZE 治理对齐：**850 行警告 / 1500 行阻塞** + 稳定模块白名单
    (`_SIZE_BYPASS_WHITELIST`)。历史上硬编码 300 行阈值会误伤 70+ 个稳定、已充分
    测试的模块，长期成为纯噪声，与 R-SIZE 严重不一致。统一后 R-DELIVERY-1 仍是有效
    的交付门禁（真正超 850 行的新模块仍会告警/阻塞），但不再对既有的大型稳定模块刷屏。
    """
    Severity, Violation = _get_violation_classes()

    # 单一真相源：阈值与白名单一律来自 tools.guard，禁止在此重复硬编码。
    # 若导入失败则显式抛出，避免静默回退到过时的魔法数字导致治理漂移。
    from tools.guard import (
        _SIZE_BLOCKING_THRESHOLD,
        _SIZE_WARNING_THRESHOLD,
    )
    from tools.guard import (
        _SIZE_BYPASS_WHITELIST as _bypass_whitelist,
    )

    for pkg in _DELIVERY_ARCHITECTURE_LAYERS:
        pkg_dir = self.root / pkg
        if not pkg_dir.exists():
            continue

        for py_file in pkg_dir.rglob("*.py"):
            if py_file.name == "__init__.py":
                continue

            try:
                content = py_file.read_text(encoding="utf-8", errors="replace")
                line_count = len(content.splitlines())
            except OSError:
                continue

            rel_path = str(py_file.relative_to(self.root))
            norm_path = rel_path.replace("\\", "/")
            if norm_path in _bypass_whitelist:
                continue

            if line_count >= _SIZE_BLOCKING_THRESHOLD:
                self.violations.append(
                    Violation(
                        rule="R-DELIVERY-1",
                        severity=Severity.BLOCKING,
                        file=rel_path,
                        line=0,
                        description=f"模块超过阻塞行数: {rel_path} ({line_count} >= {_SIZE_BLOCKING_THRESHOLD})",
                        fix_hint=f"必须拆分 {rel_path} 为多个子模块（God Object 风险）",
                    )
                )
            elif line_count >= _SIZE_WARNING_THRESHOLD:
                self.violations.append(
                    Violation(
                        rule="R-DELIVERY-1",
                        severity=Severity.WARNING,
                        file=rel_path,
                        line=0,
                        description=f"模块超过建议行数: {rel_path} ({line_count} >= {_SIZE_WARNING_THRESHOLD})",
                        fix_hint=f"建议拆分 {rel_path} 为多个子模块，保持单一职责",
                    )
                )


def check_delivery_test_coverage(self) -> None:
    """R-DELIVERY-2: 检查模块测试覆盖率 (WARNING)

    通用规则：确保核心包的公共模块有对应的测试文件。
    检查逻辑：
    1. 扫描包内所有 .py 模块（排除 __init__.py）
    2. 检查 tests/ 目录下是否有对应测试文件
    3. 测试文件命名规范：test_<module>.py
    """
    Severity, Violation = _get_violation_classes()

    for pkg in _DELIVERY_PACKAGES_REQUIRING_TESTS:
        pkg_dir = self.root / pkg
        if not pkg_dir.exists():
            continue

        for py_file in pkg_dir.glob("*.py"):
            if py_file.name == "__init__.py":
                continue

            module_name = py_file.stem
            # 跳过私有模块（下划线开头）
            if module_name.startswith("_"):
                continue

            rel_path = str(py_file.relative_to(self.root))
            norm_path = rel_path.replace("\\", "/")

            # 检查是否在白名单中 (已通过其他测试覆盖)
            if norm_path in _DELIVERY_TEST_WHITELIST:
                continue

            # 检查对应测试文件是否存在 (支持子目录结构)
            test_file_root = self.root / "tests" / f"test_{module_name}.py"
            test_file_subdir = list((self.root / "tests").glob(f"*/test_{module_name}.py"))
            if not test_file_root.exists() and not test_file_subdir:
                self.violations.append(
                    Violation(
                        rule="R-DELIVERY-2",
                        severity=Severity.WARNING,
                        file=rel_path,
                        line=0,
                        description=f"{rel_path} 缺少测试文件: tests/test_{module_name}.py",
                        fix_hint=f"创建 tests/test_{module_name}.py 覆盖 {module_name} 的核心功能",
                    )
                )


def check_delivery_architecture_alignment(self) -> None:
    """R-DELIVERY-3: 检查架构分层对齐 (BLOCKING)

    通用规则：确保新代码符合 10-ARCHITECTURE.md 分层约束。
    关键检查：
    1. 包内导入不违反分层规则（如 report 不应导入 strike 内部）
    2. 模块职责与所在包匹配
    """
    Severity, Violation = _get_violation_classes()

    # 定义禁止的跨层导入 (src -> dst 不允许)
    _forbidden_cross_layer = {
        "report": ["strike"],  # report 不应依赖 strike
    }

    for src_layer, forbidden_dsts in _forbidden_cross_layer.items():
        src_dir = self.root / src_layer
        if not src_dir.exists():
            continue

        for py_file in src_dir.rglob("*.py"):
            if py_file.name == "__init__.py":
                continue

            try:
                content = py_file.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            for dst in forbidden_dsts:
                pattern = rf"from\s+{dst}\.|import\s+{dst}\."
                if re.search(pattern, content):
                    rel_path = str(py_file.relative_to(self.root))
                    self.violations.append(
                        Violation(
                            rule="R-DELIVERY-3",
                            severity=Severity.BLOCKING,
                            file=rel_path,
                            line=0,
                            description=f"架构违反: {rel_path} 从 {dst} 导入 (report 不应依赖 strike)",
                            fix_hint=f"移除对 {dst} 的依赖，使用核心抽象或 core/ 层传递数据",
                        )
                    )


def check_delivery_init_export_consistency(self) -> None:
    """R-DELIVERY-4: 检查 __init__.py 导出公共 API 的一致性 (INFO)

    通用规则：确保新增的公共类/函数在包的 __init__.py 中导出。
    适用于所有 _DELIVERY_PACKAGES_WITH_PUBLIC_API 中的包。
    """
    Severity, Violation = _get_violation_classes()

    for pkg in _DELIVERY_PACKAGES_WITH_PUBLIC_API:
        pkg_dir = self.root / pkg
        init_file = pkg_dir / "__init__.py"

        if not init_file.exists() or not pkg_dir.is_dir():
            continue

        try:
            init_content = init_file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        has_export_all = "__all__" in init_content

        for py_file in pkg_dir.glob("*.py"):
            if py_file.name == "__init__.py":
                continue

            try:
                module_content = py_file.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            class_pattern = r"class\s+([A-Z]\w+)\s*[:\(]"
            for match in re.finditer(class_pattern, module_content):
                class_name = match.group(1)
                if class_name not in init_content and not has_export_all:
                    rel_path = str(init_file.relative_to(self.root))
                    self.violations.append(
                        Violation(
                            rule="R-DELIVERY-4",
                            severity=Severity.INFO,
                            file=rel_path,
                            line=0,
                            description=f"{pkg}/__init__.py 未导出 {class_name}",
                            fix_hint=f"在 __init__.py 中添加 from .{py_file.stem} import {class_name}",
                        )
                    )
                    break


# ===============================================================================
# R-L1: 攻击端安全护栏检查 - 防御代码不得出现在攻击目录 (v2.9 新增实现)
# ===============================================================================

# 攻击目录模式：包含以下关键词的顶层目录
_ATTACK_DIR_PATTERNS = [
    "strike",
    "arm",
    "recon",
    "attack",  # 捕获 future attack_* 目录
]

# 检测防御/安全逻辑的关键词
_DEFENSE_KEYWORDS = [
    r"class\s+.*(?:Defense|Sandbox|Filter|Analyzer|Scanner|Guard|Blocker|Protector|Validator)\w*",
    r"def\s+(?:detect|block|filter|sanitize|check_security|validate_safety|is_malicious|is_dangerous)\w*",
    r"(?:whitelist|blacklist|allow_list|block_list|security_policy|safe_mode|access_control)",
    r"class\s+FileAccessSandbox",
    r"class\s+ASTAnalyzer",
    r"class\s+DefenseOrchestrator",
    r"def\s+check_.*access",
    r"def\s+sanitize_.*content",
]

# 预定义豁免 (已知的安全测试相关正常代码 - "防御"名称实际用于攻击/侦察目的)
# 这些文件虽然使用了 defense/detect/filter 等关键词，但实际是攻击工具：
# - recon/*: 检测/分析目标系统的防御机制 (用于绕过)
# - strike/*: 分析/验证会话安全 (用于攻击)
# - stealth/blacklist: 攻击隐蔽配置
_DEFENSE_CHECK_WHITELIST = {
    # 攻击模块白名单
    "strike/output_filter_bypass.py": "攻击端过滤器绕过 (正向攻击技术)",
    "strike/asr_forensics.py": "攻击后取证分析 (服务于ASR证据链)",
    "report/evidence_extract.py": "证据提取 (服务于报告生成)",
    # 侦察模块白名单 - 检测目标防御用于绕过 (v2.0 子包路径)
    "recon/guardrail_detector.py": "检测目标防护机制 (用于绕过)",
    "recon/a2a/defense_awareness.py": "分析目标A2A防御 (用于绕过)",
    "recon/a2a/topology.py": "拓扑分析 (攻击侦察)",
    "recon/core/stealth.py": "攻击隐蔽配置 (converter_blacklist)",
    "recon/stealth_config.py": "攻击隐蔽配置 (顶层 stealth_config, converter_blacklist)",
    "recon/confidence_scorer.py": "攻击置信度评估 (filter_by_level)",
    "recon/api/auth_detector.py": "检测目标认证机制 (用于绕过)",
    "recon/model/api_classifier.py": "API分类识别 (攻击面侦察)",
    "recon/model/seed_mapper.py": "模型指纹识别 (用于选择攻击策略)",
    "recon/model/prompt_injector.py": "注入检测 (攻击面侦察)",
    "recon/trust_chain_probe.py": "信任链探测 (攻击)",
    "recon/multi_agent_topology.py": "拓扑分析 (攻击侦察)",
    # 会话攻击白名单
    "strike/session/session_id_analyzer.py": "会话ID分析 (攻击)",
    "strike/session/session_pattern_analyzer.py": "会话模式分析 (攻击)",
    "strike/session/validation.py": "会话验证 (攻击)",
    # R-L1 v2.1 扩展白名单: 组件化目录 (均为侦察/分析用途, 非防御实现)
    "recon/a2a/defense_mapper.py": "目标防御分析 (侦察, 用于绕过)",
    "recon/a2a/trust_analyzer.py": "目标信任链分析 (侦察, 用于绕过)",
    "recon/mcp/surface_scanner.py": "目标安全表面扫描 (侦察)",
    "recon/mcp/tool_inventory.py": "目标工具清单扫描 (侦察)",
    "recon/session/session_auth_probe.py": "目标认证机制探测 (侦察)",
    "recon/session/session_id_analyzer.py": "目标会话ID分析 (侦察)",
    "recon/session/session_fixation_detector.py": "会话固定检测 (侦察)",
    "recon/session/session_token_extractor.py": "会话令牌提取 (侦察)",
    "recon/web/web_api_discoverer.py": "目标API端点发现 (侦察)",
    "recon/web/web_auth_mapper.py": "目标认证流程映射 (侦察)",
    "recon/web/web_input_mapper.py": "目标输入点映射 (侦察)",
}


def check_no_defense_in_attack_dirs(self) -> None:
    """R-L1-IMP: 攻击目录中不得存在防御/安全护栏逻辑 (BLOCKING)

    真实实现：扫描所有攻击相关目录，检测是否存在防御性代码。
    攻击目录包括: strike/, arm/, recon/, 以及任何名称含 attack 的顶层目录。

    检测逻辑:
    1. 识别攻击目录 (strike/arm/recon/attack_*)
    2. 扫描文件内容中的防御/安全关键词
    3. 发现匹配则报告 BLOCKING 违规

    Reference: 40-GUARDRAILS.md 1A R-L1
    """
    Severity, Violation = _get_violation_classes()

    for path in self.source_files:
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        rel_path = str(path.relative_to(self.root))
        norm_path = rel_path.replace("\\", "/")

        # 检查是否在攻击目录中
        parts = norm_path.split("/")
        if not parts:
            continue
        top_dir = parts[0]

        # 判断是否为攻击目录
        is_attack_dir = any(
            top_dir == pattern or (pattern == "attack" and "attack" in top_dir) for pattern in _ATTACK_DIR_PATTERNS
        )

        if not is_attack_dir:
            continue

        # 检查白名单
        if norm_path in _DEFENSE_CHECK_WHITELIST:
            continue

        # 检测防御代码关键词
        for i, line in enumerate(content.split("\n"), 1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue

            for pattern in _DEFENSE_KEYWORDS:
                if re.search(pattern, stripped, re.IGNORECASE):
                    self.violations.append(
                        Violation(
                            rule="R-L1",
                            severity=Severity.BLOCKING,
                            file=rel_path,
                            line=i,
                            description=f"攻击端存在防御逻辑: {stripped[:60]} (匹配模式: {pattern})",
                            fix_hint="攻击目录中的防御/安全逻辑必须迁移到独立的 safety/ 目录或删除",
                        )
                    )
                    break  # 每个文件只报第一个匹配


# ===============================================================================
# R-L7: 根目录结构合法性检查 (v2.9 新增实现)
# ===============================================================================

# 允许的顶层目录 (白名单)
_ALLOWED_TOP_LEVEL_DIRS = {
    "strike",
    "arm",
    "recon",
    "core",
    "assess",
    "report",
    "utils",
    "tools",
    "tests",
    "data",
    "docs",
    "outputs",  # 运行时生成
    "config",  # 配置文件目录
    "scripts",  # 维护脚本 (fix_recon_imports, migrate_seeds 等)
    "targets",  # 靶场层：targets/mock/ 本地 mock 靶标（10-ARCHITECTURE 2.1 / REQ-156，非交付包）
}

# 允许的顶层文件
_ALLOWED_TOP_LEVEL_FILES = {
    "main.py",
    "pyproject.toml",
    "README.md",
    "DEV-TRIAD-CHECKLIST.md",
    ".gitignore",
    ".env.local",
    ".env",
}


def check_top_level_structure(self) -> None:
    """R-L7-IMP: 检查根目录结构合法性 (BLOCKING)

    真实实现：检测未授权的顶层目录/文件。

    规则:
    1. 新顶层目录必须在 _ALLOWED_TOP_LEVEL_DIRS 中
    2. 新顶层文件必须在 _ALLOWED_TOP_LEVEL_FILES 中
    3. 发现未授权则报告 BLOCKING

    Reference: 40-GUARDRAILS.md 1A R-L7
    """
    Severity, Violation = _get_violation_classes()

    # 检查顶层目录
    for item in self.root.iterdir():
        if not item.is_dir():
            continue

        name = item.name
        # 忽略隐藏目录
        if name.startswith("."):
            continue
        # 忽略 __pycache__ 等
        if name in {"__pycache__", "node_modules", "pyrit_mini.egg-info"}:
            continue

        if name.lower() not in _ALLOWED_TOP_LEVEL_DIRS:
            # 检查是否是已知的允许目录（不区分大小写）
            normalized = name.lower()
            if normalized not in _ALLOWED_TOP_LEVEL_DIRS:
                self.violations.append(
                    Violation(
                        rule="R-L7",
                        severity=Severity.BLOCKING,
                        file=name,
                        line=0,
                        description=f"未授权的顶层目录: {name} (不在允许列表中)",
                        fix_hint=f"将 {name}/ 合并到已有目录 (strike/arm/recon/tools/utils/data/docs) 或添加到 _ALLOWED_TOP_LEVEL_DIRS",
                    )
                )

    # 检查顶层文件
    for item in self.root.iterdir():
        if not item.is_file():
            continue

        name = item.name
        # 忽略隐藏文件
        if name.startswith("."):
            continue

        if name not in _ALLOWED_TOP_LEVEL_FILES:
            # 检查是否是已知的允许文件模式
            if not (name.startswith("test_") and name.endswith(".py")):
                self.violations.append(
                    Violation(
                        rule="R-L7",
                        severity=Severity.WARNING,
                        file=name,
                        line=0,
                        description=f"未登记的顶层文件: {name}",
                        fix_hint=f"将 {name} 移至合适的子目录或添加到 _ALLOWED_TOP_LEVEL_FILES",
                    )
                )


def check_delivery_module_docstring(self) -> None:
    """R-DELIVERY-5: 检查新增模块docstring规范 (INFO)

    通用规则：新增的 Python 模块必须有 docstring 说明模块用途。
    适用于所有 _DELIVERY_MODULES_REQUIRING_DOCSTRING 中的包。
    """
    Severity, Violation = _get_violation_classes()

    for pkg in _DELIVERY_MODULES_REQUIRING_DOCSTRING:
        pkg_dir = self.root / pkg
        if not pkg_dir.exists():
            continue

        for py_file in pkg_dir.glob("*.py"):
            if py_file.name == "__init__.py":
                continue

            try:
                content = py_file.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

    lines = content.splitlines()
    has_docstring = False
    _docstring_prefixes = (
        '"""',
        "'''",
        "r'''",
        'r"""',
        "R'''",
        'R"""',
        "b'''",
        'b"""',
        "B'''",
        'B"""',
        "f'''",
        'f"""',
        "F'''",
        'F"""',
    )
    for line in lines[:10]:
        stripped = line.strip()
        if any(stripped.startswith(p) for p in _docstring_prefixes):
            has_docstring = True
            break
        elif stripped and not stripped.startswith("#"):
            break

            if not has_docstring and len(lines) > 5:
                rel_path = str(py_file.relative_to(self.root))
                self.violations.append(
                    Violation(
                        rule="R-DELIVERY-5",
                        severity=Severity.INFO,
                        file=rel_path,
                        line=1,
                        description=f"{rel_path} 缺少模块 docstring",
                        fix_hint="在文件顶部添加模块说明 docstring (包含功能、架构对齐、学术引用)",
                    )
                )
