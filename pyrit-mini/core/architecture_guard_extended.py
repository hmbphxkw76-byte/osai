#!/usr/bin/env python3
"""
Architecture Guard Extend - R-PIPE / R-IMPORT / R-REDTEAM / R-EVID / R-REPORT

 5  20+ :
  - Data flow (R-PIPE)
  - from (R-IMPORT)
  -  (R-REDTEAM)
  -  (R-EVID)
  -  (R-REPORT)

:

:  architecture_guard.py  from .architecture_guard_extended import register_extended_checks
"""

from __future__ import annotations

import re


def _get_violation_classes():
    from core.architecture_guard import Severity, Violation
    return Severity, Violation

# ===============================================================================
#
# ===============================================================================

# R-PIPE:
_PIPELINE_MODULES: dict[str, dict[str, str]] = {
    # phase -> {module_name: entry_function}
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

# phase (orchestrator.py )
_PHASE_ORDER = ["recon", "arm", "strike", "escalate", "assess", "report"]

# orchestrator.py phase
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
}

# R-REDTEAM: ()
_REQUIRED_CITATIONS: list[tuple[str, str, str]] = [
    # (, arXiv ID, )
    ("PromptSendingAttack", "arXiv:2302.12173", "Greshake 2023"),
    ("CrescendoAttack", "arXiv:2404.01833", "Russinovich 2024"),
    ("TAPAttack", "arXiv:2405.17350", "Mehrabi 2024"),
    ("PAIRAttack", "arXiv:2310.08419", "Chao 2024"),
    ("GCG", "arXiv:2302.12173", "Zou 2023"),
    ("Decomposition", "arXiv:2402.14266", "Liu 2024 (DrAttack)"),
    ("BestOfN", "arXiv:2404.02151", "Hughes 2024"),
    ("SkeletonKey", "arXiv:2402.14266", "SKELETONKEY 2024"),
]

# R-NATIVE: PyRIT  ( v1.8 )
#       PyRIT

#  ( 11 类)
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

#  ( 80+ 类，   R-NATIVE-2)
_NATIVE_CONVERTER_KEYWORDS: dict[str, str] = {
    #
    "base64_encode": "Base64Converter",
    "base64_decode": "Base64Converter",
    "rot13": "ROT13Converter",
    "binary_encode": "BinaryConverter",
    "url_encode": "UrlConverter",
    "url_decode": "UrlConverter",
    # Unicode
    "unicode_substitution": "UnicodeSubstitutionConverter",
    "unicode_confusable": "UnicodeConfusableConverter",
    "zero_width": "ZeroWidthConverter",
    "bidi": "BidiConverter",
    #
    "caesar": "CaesarConverter",
    "vigenere": "VigenereConverter",
    "atbash": "AtbashConverter",
    #
    "translation": "TranslationConverter",
    "translate": "TranslationConverter",
    #
    "diacritic": "DiacriticConverter",
    "char_swap": "CharSwapConverter",
    "char_noise": "CharNoiseConverter",
    "random_capital": "RandomCapitalLettersConverter",
    #
    "suffix_append": "SuffixAppendConverter",
    "string_join": "StringJoinConverter",
    "insert_punctuation": "InsertPunctuationConverter",
}

#  ( 50+ 类，   R-NATIVE-3)
_NATIVE_SCORER_KEYWORDS: dict[str, str] = {
    # 0-token
    "check_refusal": "SelfAskRefusalScorer",
    "is_refusal": "SelfAskRefusalScorer",
    "check_success": "SelfAskTrueFalseScorer",
    "is_success": "SelfAskTrueFalseScorer",
    #
    "regex_match": "RegexScorer",
    "substring_match": "SubStringScorer",
    "contains_pattern": "RegexScorer",
    #
    "classify_content": "ContentClassifier",
    "content_classification": "ContentClassifier",
    #
    "sql_injection_check": "SQLInjectionOutputScorer",
    "xss_check": "XSSOutputScorer",
    "ssrf_check": "SSRFOutputScorer",
    "command_injection_check": "ShellCommandOutputScorer",
    #
    "keyword_match": "AnthraxKeywordScorer",
    "credential_leak": "CredentialLeakScorer",
    "plagiarism_check": "PlagiarismScorer",
}

#  ( 25+ 类，   R-NATIVE-4)
_NATIVE_TARGET_KEYWORDS: dict[str, str] = {
    # HTTP
    "http_request_target": "HTTPTarget",
    "http_target": "HTTPTarget",
    "api_target": "HTTPXAPITarget",
    "websocket_target": "WebSocketTarget",
    # OpenAI
    "openai_chat": "OpenAIChatTarget",
    "openai_completion": "OpenAICompletionTarget",
    "openai_response": "OpenAIResponseTarget",
    #
    "prompt_target": "PromptTarget",
    "text_target": "TextTarget",
    #
    "round_robin": "RoundRobinTarget",
    "realtime_target": "RealtimeTarget",
}

#  (  for loop + PromptSendingAttack)
#     CrescendoAttack/TAPAttack
_NATIVE_ATTACK_KEYWORDS: dict[str, str] = {
    "crescendo": "CrescendoAttack",
    "tap": "TAPAttack",
    "pair": "PAIRAttack",
    "xpia": "XPIAAttack",
}

# R-REDTEAM:
_FORBIDDEN_PATTERNS_REDTEAM: list[tuple[str, str, str]] = [
    # (, , )
    (r"return\s+None\b.*#.*attack",
     " None  - ",
     " AttackOutcome ,  success/failure + "),
    (r"pass\s*#.*(attack|exploit|score)",
     "/ pass stub - ",
     ",  NotImplementedError"),
    (r"raise\s+NotImplementedError.*#.*TODO",
     "TODO stub  - ",
     " stub,  orchestrator Skip"),
]

# PipelineContext phase ()
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

# === ===

def register_extended_checks(guard_cls) -> None:
    """all ArchitectureGuard"""

    # == R-PIPE ==================================================

    def check_pipeline_integration(self) -> None:
        """R-CONV-1~4:

        :
        1.  phase  orchestrator.py
        2. PipelineContext
        3.
        4.  ()
        """
        Severity, Violation = _get_violation_classes()
        orch_file = self.root / "core" / "orchestrator.py"

 # R-CONV-1: orchestrator.py phase
        if orch_file.exists():
            orch_content = orch_file.read_text(encoding="utf-8", errors="replace")
            for func_name in _ORCHESTRATOR_PHASE_FUNCTIONS:
                # :  ( import)
                is_direct_def = f"async def {func_name}" in orch_content
                is_imported = func_name in orch_content and "import" in orch_content and "from " in orch_content
                if not is_direct_def and not is_imported:
                    self.violations.append(Violation(
                        rule="R-PIPE-1",
                        severity=Severity.BLOCKING,
                        file="core/orchestrator.py",
                        line=0,
                        description=f"orchestrator.py  '{func_name}' - ",
                        fix_hint=f" async def {func_name}(ctx) ",
                    ))

 # R-PIPE-2: phase orchestrator
        if orch_file.exists():
            orch_content = orch_file.read_text(encoding="utf-8", errors="replace")
            phase_calls = [
                ("_run_recon_phase", "recon "),
                ("_run_arm_phase", "arm "),
                ("_run_strike_phase", "strike "),
                ("_run_escalate_phase", "escalate "),
                ("_run_assess_phase", "assess "),
                ("_run_report_phase", "report "),
            ]
            for func_name, desc in phase_calls:
                #  :  ( )  ( )
                #  executor.py run_single_endpoint ( )
                is_imported = "from " in orch_content and func_name in orch_content and "import" in orch_content
                is_direct_def = f"def {func_name}" in orch_content
                is_direct_call = f"await {func_name}" in orch_content
                if not is_imported and not is_direct_def and not is_direct_call:
                    self.violations.append(Violation(
                        rule="R-PIPE-2",
                        severity=Severity.BLOCKING,
                        file="core/orchestrator.py",
                        line=0,
                        description=f"orchestrator  {desc} ({func_name}) - ",
                        fix_hint=f" run_single_endpoint  await {func_name}(ctx) ",
                    ))

 # R-PIPE-3: arm/ converter_presets
        self._check_arm_module_registration()

 # R-PIPE-4: strike/ exporter executor
        self._check_strike_module_registration()

    def _check_arm_module_registration(self) -> None:
        """ arm/ converter_presets.py"""
        presets_file = self.root / "arm" / "converter_presets.py"
        if not presets_file.exists():
            return
        content = presets_file.read_text(encoding="utf-8", errors="replace")

 # _build_chain_builders
        if "_build_chain_builders" not in content:
            self.violations.append(Violation(
                rule="R-PIPE-3",
                severity=Severity.WARNING,
                file="arm/converter_presets.py",
                line=0,
                description=" _build_chain_builders  - converter ",
                fix_hint=" _build_chain_builders() -> dict[str, Any] ->",
            ))

    def _check_strike_module_registration(self) -> None:
        """ strike/ attack executor executor.py

        : executor.py fromall -  orchestrator
        ( orchestrator.py ):
        - orchestrator._run_strike_phase -> executor.execute_attacks
        - orchestrator._run_escalate_phase -> strike.escalation.check_and_escalate
        Therefore, import.
        """
        Severity, Violation = _get_violation_classes()
        executor_file = self.root / "strike" / "executor.py"
        if not executor_file.exists():
            return

 # python executor.py
 # native_attacks escalation , orchestrator
 # executor.py

    def check_data_flow_consistency(self) -> None:
        """R-PIPE-5~6: Data flow

        :
        1. PipelineContext  (who sets)
        2. PipelineContext  (who reads)
        3. Phase Layer

        (P3):  dataclass ,
        """
        Severity, Violation = _get_violation_classes()
        ctx_file = self.root / "core" / "context.py"
        orch_file = self.root / "core" / "orchestrator.py"

        if not ctx_file.exists():
            return

        ctx_content = ctx_file.read_text(encoding="utf-8", errors="replace")
        orch_content = orch_file.read_text(encoding="utf-8", errors="replace") if orch_file.exists() else ""

 # PipelineContext dataclass ()
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

 #
            if stripped.startswith("class ") and "PipelineContext" in stripped:
                in_class = True
                class_indent = indent
                in_function = False
                continue

 # : ()
            if in_class and indent <= class_indent and stripped:
                in_class = False
                continue

 # ()
            if in_class and stripped.startswith("def ") and indent > class_indent:
                in_function = True
                func_indent = indent
                continue

 # ,
            if in_function and indent <= func_indent and stripped:
                in_function = False

 # dataclass (Layer, )
            if in_class and not in_function and indent > class_indent:
                m = field_pattern.match(line)
                if m and not m.group(1).startswith("_"):
                    fields.append(m.group(1))

 #
        for field_name in fields:
            if field_name.startswith("_"):
                continue
 # orchestrator
            access_pattern = rf"ctx\.{field_name}[^.a-zA-Z]"
            if not re.search(access_pattern, orch_content):
             # -
                all_content = self._read_all_source()
                total_refs = sum(1 for c in all_content if re.search(access_pattern, c))
                if total_refs <= 1:  #
                    self.violations.append(Violation(
                        rule="R-PIPE-5",
                        severity=Severity.INFO,
                        file="core/context.py",
                        line=0,
                        description=f"PipelineContext.{field_name}  - Data flow",
                        fix_hint=f"Confirmation {field_name} converter(s) phase , ",
                    ))

    def _read_all_source(self) -> list[str]:
        """all"""
        for p in self.source_files:
            try:
                contents.append(p.read_text(encoding="utf-8", errors="replace"))
            except OSError:
                pass
        return contents

 # == R-IMPORT ================================================

    def check_circular_imports(self) -> None:
        """R-IMPORT-1~2: from

        :
        1.  (A->B->A)
        2.  (from)
        """
        Severity, Violation = _get_violation_classes()
 #
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

 # from X import Y import X
            for line in content.split("\n"):
                line = line.strip()
                if line.startswith("from ") and " import " in line:
                    target = line.split()[1].lstrip(".")
                    if any(pkg in target for pkg in ["core.", "arm.", "strike.", "assess.", "report.", "recon."]):
                        imports.add(target.split(".")[0] + "." + target.split(".")[1])
                elif line.startswith("import "):
                    target = line.split()[1]
                    if any(pkg in target for pkg in ["core", "arm", "strike", "assess", "report", "recon"]):
                        imports.add(target)

            import_graph[module_path] = imports

 #
        for module, deps in import_graph.items():
            for dep in deps:
                dep_imports = import_graph.get(dep, set())
                if module in dep_imports:
                    self.violations.append(Violation(
                        rule="R-IMPORT-1",
                        severity=Severity.BLOCKING,
                        file=module.replace(".", "/") + ".py",
                        line=0,
                        description=f"from: {module} <-> {dep} - ",
                        fix_hint=" utils/ , from ( import)",
                    ))

    def check_dead_code(self) -> None:
        """R-IMPORT-3:

        :
        1. from
        2. fromimports
        """
        Severity, Violation = _get_violation_classes()
 #
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
 #
                        for pkg in ["core", "arm", "strike", "assess", "report", "recon"]:
                            if mod.startswith(pkg):
                                imported_modules.add(mod.split(".")[0] + "/" + mod.split(".")[1] if "." in mod else mod)
                                break

 # arm/ strike/ assess/ report/recon/
        pipeline_pkgs = ["arm", "strike", "assess", "report", "recon"]
        for path in self.source_files:
            rel = str(path.relative_to(self.root))
            if "__init__.py" in rel or not rel.endswith(".py"):
                continue
            parts = rel.split("/")
            if len(parts) >= 2 and parts[0] in pipeline_pkgs:
                module_name = parts[-1].replace(".py", "")
 #
                is_imported = any(module_name in imp for imp in imported_modules)
 # orchestrator
                orch_file = self.root / "core" / "orchestrator.py"
                if orch_file.exists():
                    orch_content = orch_file.read_text(encoding="utf-8", errors="replace")
                    if module_name in orch_content:
                        is_imported = True

                if not is_imported and not module_name.startswith("_"):
                    self.violations.append(Violation(
                        rule="R-IMPORT-3",
                        severity=Severity.INFO,
                        file=rel,
                        line=0,
                        description=f" {rel} from - ",
                        fix_hint=" (from), /",
                    ))

 # == R-REDTEAM ==============================================

    def check_best_practices(self) -> None:
        """R-REDTEAM-1~3:

        :
        1.  None  pass stub
        2.  arXiv
        3.
        """
        Severity, Violation = _get_violation_classes()
        for path in self.source_files:
            try:
                content = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if "__init__.py" in str(path):
                continue

            lines = content.split("\n")

 # R-REDTEAM-1:
            for i, line in enumerate(lines, 1):
                stripped = line.strip()
                if stripped.startswith("#"):
                    continue

                for pattern, desc, fix in _FORBIDDEN_PATTERNS_REDTEAM:
                    if re.search(pattern, stripped, re.IGNORECASE):
                        self.violations.append(Violation(
                            rule="R-REDTEAM-1",
                            severity=Severity.WARNING,
                            file=str(path.relative_to(self.root)),
                            line=i,
                            description=f"{desc}: {stripped[:70]}",
                            fix_hint=fix,
                        ))

    def check_academic_citations(self) -> None:
        """R-REDTEAM-2: """
        pipeline_dirs = {"strike", "arm", "assess"}
        for path in self.source_files:
            if not any(d in str(path) for d in pipeline_dirs):
                continue
            try:
                content = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

 # arXiv
            for keyword, arxiv_id, paper_name in _REQUIRED_CITATIONS:
                if keyword in content and arxiv_id not in content:
                 #
                    for i, line in enumerate(content.split("\n"), 1):
                        if keyword in line and "import" not in line:
                            self.violations.append(Violation(
                                rule="R-REDTEAM-2",
                                severity=Severity.INFO,
                                file=str(path.relative_to(self.root)),
                                line=i,
                                description=f" '{keyword}'  {arxiv_id} ({paper_name})",
                                fix_hint=f" docstring : {arxiv_id}",
                            ))
                            break

    def check_asr_completeness(self) -> None:
        """R-REDTEAM-3: ASR """
        score_file = self.root / "assess" / "asr_manager.py"
        if not score_file.exists():
            score_file = self.root / "assess" / "asr_stats.py"
        if not score_file.exists():
            self.violations.append(Violation(
                rule="R-REDTEAM-3",
                severity=Severity.BLOCKING,
                file="assess/asr_manager.py",
                line=0,
                description=" ASR  (asr_manager.py  asr_stats.py)",
                fix_hint=" assess/asr_manager.py,  compute_asr + compute_overall_asr",
            ))
            return

        content = score_file.read_text(encoding="utf-8", errors="replace")
        required_functions = ["compute_asr", "compute_overall_asr"]
        for func in required_functions:
         # SSOT : (def)(from ... import)
            has_def = f"def {func}" in content or f"async def {func}" in content
 # (from x import func / import func)
            _re = __import__("re")
            has_single_import = bool(
                _re.search(rf'^[^#]*\bimport\b[^#]*\b{func}\b', content, _re.MULTILINE)
            )
 # : from ... import (\n... func\n)
            has_multi_import = bool(
                _re.search(
                    rf'from\s+\S+\s+import\s*\([^)]*\b{func}\b',
                    content,
                    _re.DOTALL,
                )
            )
            if not has_def and not has_single_import and not has_multi_import:
                self.violations.append(Violation(
                    rule="R-REDTEAM-3",
                    severity=Severity.WARNING,
                    file=str(score_file.relative_to(self.root)),
                    line=0,
                    description=f"ASR  '{func}' - ASR ",
                    fix_hint=f" {func}() imports SSOT from",
                ))

 # == R-EVID =================================================

    def check_evidence_completeness(self) -> None:
        """R-EVID-1: """
        evidence_file = self.root / "report" / "evidence.py"
        if not evidence_file.exists():
            self.violations.append(Violation(
                rule="R-EVID-1",
                severity=Severity.BLOCKING,
                file="report/evidence.py",
                line=0,
                description=" report/evidence.py - ",
                fix_hint=" report/evidence.py,  EvidenceCollector ",
            ))
            return

        content = evidence_file.read_text(encoding="utf-8", errors="replace")
 # EvidenceCollector collect
        if "def collect(" not in content and "async def collect(" not in content:
            self.violations.append(Violation(
                rule="R-EVID-1",
                severity=Severity.WARNING,
                file="report/evidence.py",
                line=0,
                description="EvidenceCollector  collect()  - ",
                fix_hint=" collect() ,  attack_results  EvidenceCollection",
            ))

 # EvidenceCollection
        if "class EvidenceCollection" not in content:
            self.violations.append(Violation(
                rule="R-EVID-1",
                severity=Severity.WARNING,
                file="report/evidence.py",
                line=0,
                description=" EvidenceCollection  - ",
                fix_hint=" @dataclass class EvidenceCollection ",
            ))

 # == R-REPORT ===============================================

    def check_report_completeness(self) -> None:
        """R-REPORT-1: """
        generator_file = self.root / "report" / "generator.py"
        if not generator_file.exists():
            self.violations.append(Violation(
                rule="R-REPORT-1",
                severity=Severity.BLOCKING,
                file="report/generator.py",
                line=0,
                description=" report/generator.py - ",
                fix_hint=" report/generator.py,  generate_report()",
            ))
            return

        content = generator_file.read_text(encoding="utf-8", errors="replace")

 # EvidenceCollection ()
        if "EvidenceCollection" not in content:
            self.violations.append(Violation(
                rule="R-REPORT-1",
                severity=Severity.WARNING,
                file="report/generator.py",
                line=0,
                description="generate_report  EvidenceCollection - ",
                fix_hint=" generate_report from EvidenceCollection ",
            ))

 #
        output_formats = []
        if "html" in content.lower() or "HTML" in content:
            output_formats.append("HTML")
        if "markdown" in content.lower() or "Markdown" in content:
            output_formats.append("Markdown")
        if "sarif" in content.lower() or "SARIF" in content:
            output_formats.append("SARIF")

        if len(output_formats) < 2:
            self.violations.append(Violation(
                rule="R-REPORT-2",
                severity=Severity.INFO,
                file="report/generator.py",
                line=0,
                description=f" {', '.join(output_formats)}  - ",
                fix_hint=" Markdown / SARIF  CI ",
            ))

 # == R-PIPE-6: recon  ========================================

    def check_recon_submodule_invocation(self) -> None:
        """R-PIPE-6: recon/  phase

        :
        recon/ ( rag_pipeline_probe.py) ( run_rag_pipeline_probe)
         __init__.py    recon  phase (_run_recon_phase)

         recon/  ( recon/__init__.py)
         ( recon  phase )
        """
        Severity, Violation = _get_violation_classes()

 # 1. recon/__init__.py imports
        recon_init = self.root / "recon" / "__init__.py"
        if not recon_init.exists():
            return

        init_content = recon_init.read_text(encoding="utf-8", errors="replace")

 #  recon/__init__.py from recon.X import func_name
 #  ( import & )
        exported_funcs: list[tuple[str, str]] = []
        init_lines = init_content.split("\n")

        for i, line in enumerate(init_lines):
            line = line.strip()
            if not line.startswith("from recon.") or " import " not in line:
                continue

            mod = line.split()[1]  # recon.health_probe
            mod_name = mod.split(".")[-1]

 # : from recon.X import func1, func2  OR  from recon.X import (...)
            import_part = line.split(" import ", 1)[1].strip()

            if import_part.startswith("("):
 #  import ( ... )
                symbol_str = ""
                for j in range(i + 1, len(init_lines)):
                    next_line = init_lines[j].strip()
                    symbol_str += " " + next_line
                    if ")" in next_line:
                        break

                for sym in re.findall(r"\b([a-zA-Z_]\w*)\b", symbol_str):
                    if sym != "recon":
                        exported_funcs.append((mod_name, sym))
            else:
 #  import func1, func2
                for sym in import_part.split(","):
                    sym = sym.strip().rstrip(",")
                    if sym and not sym.startswith("#"):
                        exported_funcs.append((mod_name, sym))

        if not exported_funcs:
            return

 # 2. ALL recon/  ( __init__.py) + core/phases/recon.py
        recon_dir = self.root / "recon"
        phase_content = ""

        if recon_dir.exists():
            for py_file in recon_dir.glob("*.py"):
                if py_file.name == "__init__.py":
                    continue
                try:
                    phase_content += py_file.read_text(encoding="utf-8", errors="replace") + "\n"
                except OSError:
                    pass

 #  core/phases/recon.py ( run_rag_pipeline_probe  phase )
        recon_phase_file = self.root / "core" / "phases" / "recon.py"
        if recon_phase_file.exists():
            phase_content += recon_phase_file.read_text(encoding="utf-8", errors="replace") + "\n"

 # 3.  recon  phase
 #  ( uppercase) - type hints
 #  run_*/probe_*/detect_*/check_*/extract_*/enumerate_*/build_* - probe
        _ACTION_PREFIXES = ("run_", "probe_", "detect_", "check_", "extract_", "enumerate_", "build_")

        for mod_name, func_name in exported_funcs:
            if func_name[0].isupper():
                continue  # Skip classes/type hints (ParsedBurpRequest, AuthDetector, etc.)

 #  probe  action
            if not any(func_name.startswith(prefix) for prefix in _ACTION_PREFIXES):
                continue

 #  (  ()  = ,  def )
 #  def detect_model_family( - definition, not a call
            call_pattern = rf'(?<!def\s)\b{re.escape(func_name)}\s*\('
            is_called = bool(re.search(call_pattern, phase_content))

            if not is_called:
                self.violations.append(Violation(
                    rule="R-PIPE-6",
                    severity=Severity.WARNING,
                    file=f"recon/{mod_name}.py",
                    line=0,
                    description=f"recon/{mod_name}.{func_name}()  __init__.py  -  recon  phase ",
                    fix_hint=f" recon  phase  from recon.{mod_name} import {func_name}; {func_name}(...) ",
                ))

 # == R-IMPORT-4: __init__.py  ============================

    def check_init_export_usage(self) -> None:
        """R-IMPORT-4: __init__.py

        :
         __init__.py from pkg.X import func
          pkg/  func

          __init__.py  ( import)
          __init__.py ( pass-through)

        :   __init__.py from pkg.X import Y
         ( pkg/  __init__.py)
        """
        Severity, Violation = _get_violation_classes()

 # pipeline
        pipeline_pkgs = ["arm", "strike", "assess", "report", "recon"]

        for pkg in pipeline_pkgs:
            init_file = self.root / pkg / "__init__.py"
            if not init_file.exists():
                continue

            init_content = init_file.read_text(encoding="utf-8", errors="replace")
            init_lines = init_content.split("\n")

 #  from pkg.X func_name ( )
            exported_symbols: list[str] = []

            for i, raw_line in enumerate(init_lines):
                line = raw_line.strip()
                if not line.startswith(f"from {pkg}.") or " import " not in line:
                    continue

                import_part = line.split(" import ", 1)[1].strip()

                if import_part.startswith("("):
 #  import ( ... )
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
 #  import func1, func2
                    for sym in import_part.split(","):
                        sym = sym.strip().rstrip(",")
 #  inline comments (  # exported)
                        if " #" in sym:
                            sym = sym.split(" #")[0].strip()
                        if sym and not sym.startswith("#"):
                            exported_symbols.append(sym)

            if not exported_symbols:
                continue

 #  __init__.py  (  __init__.py)
 # :   __init__.py   ,
 #   __init__.py  (  __init__.py)
            combined_usage = ""
            for p in self.source_files:
                if "__init__.py" in p.name:
                    continue
                try:
                    combined_usage += p.read_text(encoding="utf-8", errors="replace") + "\n"
                except OSError:
                    pass

            for symbol in exported_symbols:
                #   ()
                if symbol in _INIT_EXPORT_WHITELIST:
                    continue
                #  symbol ( __init__.py)
                matches = re.findall(rf'\b{re.escape(symbol)}\b', combined_usage)
                if len(matches) <= 1:
                    self.violations.append(Violation(
                        rule="R-IMPORT-4",
                        severity=Severity.INFO,
                        file=f"{pkg}/__init__.py",
                        line=0,
                        description=f"{pkg}/__init__.py  '{symbol}'  ",
                        fix_hint=f"  {symbol}   __init__.py ",
                    ))

 # == ==

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
    # R-PIPE-6 / R-IMPORT-4: Runtime integration checks (2026-09-08 patch)
    guard_cls.check_recon_submodule_invocation = check_recon_submodule_invocation
    guard_cls.check_init_export_usage = check_init_export_usage
    # R-PIPE-7 / R-MCPSec: MCPSec v2.7.2 bridge integration checks (2026-09-08)
    guard_cls.check_mcpsec_bridge_integration = check_mcpsec_bridge_integration
    # R-NATIVE-1~4: PyRIT 原生组件优先使用检查器 (v1.8)
    guard_cls.check_native_attack_class_usage = check_native_attack_class_usage
    guard_cls.check_native_converter_usage = check_native_converter_usage
    guard_cls.check_native_scorer_usage = check_native_scorer_usage
    guard_cls.check_native_target_usage = check_native_target_usage

# ===============================================================================
# R-MCPSec: MCPSec v2.7.2 Bridge Integration
# ===============================================================================

_MCPSEC_REQUIRED_MODULES = {
    "mcpsec_bridge": "MCPSec CLI bridge",
    "mcp_agent_target": "MCP Agent PyRIT target",
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
    """R-PIPE-7 / R-MCPSec: MCPSec v2.7.2 bridge integration checks.

    Ensures:
    1. MCPSec bridge modules exist in strike/
    2. PipelineContext has MCPSec-related fields
    3. Strike phase uses MCPSec dynamic seeds
    4. Recon phase uses MCPSec enumeration
    5. Self-developed mcp_enumerator is removed
    """
    Severity, Violation = _get_violation_classes()

    strike_dir = self.root / "strike"

    # Check MCPSec bridge modules exist
    for module_name, description in _MCPSEC_REQUIRED_MODULES.items():
        module_file = strike_dir / f"{module_name}.py"
        if not module_file.exists():
            self.violations.append(Violation(
                rule="R-MCPSec-1",
                severity=Severity.WARNING,
                file=f"strike/{module_name}.py",
                line=0,
                description=f"Missing MCPSec module: {description}",
                fix_hint=f"Create strike/{module_name}.py for MCPSec v2.7.2 integration",
            ))

    # Check PipelineContext has MCPSec fields
    context_file = self.root / "core" / "context.py"
    if context_file.exists():
        context_content = context_file.read_text(encoding="utf-8", errors="replace")
        for field_name in _MCPSEC_REQUIRED_FIELDS:
            if field_name not in context_content:
                self.violations.append(Violation(
                    rule="R-MCPSec-2",
                    severity=Severity.WARNING,
                    file="core/context.py",
                    line=0,
                    description=f"PipelineContext missing MCPSec field: {field_name}",
                    fix_hint=f"Add {field_name}: ... to PipelineContext dataclass",
                ))

    # Check self-developed mcp_enumerator is removed
    old_mcp_enumerator = self.root / "recon" / "mcp_enumerator.py"
    if old_mcp_enumerator.exists():
        self.violations.append(Violation(
            rule="R-MCPSec-3",
            severity=Severity.BLOCKING,
            file="recon/mcp_enumerator.py",
            line=0,
            description="Self-developed mcp_enumerator.py still exists (should be replaced by MCPSec)",
            fix_hint="Delete recon/mcp_enumerator.py and use MCPSec bridge instead",
        ))

    old_helpers = self.root / "recon" / "_mcp_enumerator_helpers.py"
    if old_helpers.exists():
        self.violations.append(Violation(
            rule="R-MCPSec-3",
            severity=Severity.BLOCKING,
            file="recon/_mcp_enumerator_helpers.py",
            line=0,
            description="Self-developed _mcp_enumerator_helpers.py still exists",
            fix_hint="Delete recon/_mcp_enumerator_helpers.py and use MCPSec bridge instead",
        ))

    # Check strike/mcp_rag_attack.py uses MCPSec
    mcp_rag_file = strike_dir / "mcp_rag_attack.py"
    if mcp_rag_file.exists():
        mcp_rag_content = mcp_rag_file.read_text(encoding="utf-8", errors="replace")
        if "mcpsec_bridge" in mcp_rag_content.lower() or "MCPSec" in mcp_rag_content:
            pass  # Good: uses MCPSec
        elif "static" in mcp_rag_content.lower() and "_load_specialty_seeds" in mcp_rag_content:
            self.violations.append(Violation(
                rule="R-MCPSec-4",
                severity=Severity.INFO,
                file="strike/mcp_rag_attack.py",
                line=0,
                description="mcp_rag_attack.py uses static seeds without MCPSec integration",
                fix_hint="Add MCPSec bridge integration for dynamic seed generation",
            ))

    # Check dynamic_mcp_seeds exists
    dynamic_seeds_file = strike_dir / "dynamic_mcp_seeds.py"
    if not dynamic_seeds_file.exists():
        self.violations.append(Violation(
            rule="R-MCPSec-5",
            severity=Severity.INFO,
            file="strike/dynamic_mcp_seeds.py",
            line=0,
            description="Missing dynamic_mcp_seeds.py for MCPSec-powered seed generation",
            fix_hint="Create strike/dynamic_mcp_seeds.py with MCPSec integration",
        ))

# ===============================================================================
# R-NATIVE-1~4: PyRIT 原生组件优先使用检查器 (v1.8)
# ===============================================================================

def check_native_attack_class_usage(self) -> None:
    """R-NATIVE-1: 检测是否自行实现了本应使用 PyRIT 原生 API 的攻击。

    宪法 C1 (PyRIT Native First) 强制要求：
    - CrescendoAttack/TAPAttack/PAIRAttack/XPIAAttack 必须使用 PyRIT 原生类
    - 不得使用 PromptSendingAttack + for loop 替代原生多轮攻击

    检测逻辑：
    1. 扫描 escalation_runtime.py 等文件中的攻击关键词
    2. 检查是否同时存在"手动循环"模式（for turn_num in range）
    3. 若存在手动循环但未导入 PyRIT 原生类 → BLOCKING
    """
    Severity, Violation = _get_violation_classes()

    # 需要检查的文件
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

        # 检测每个关键词
        for keyword, native_class in _NATIVE_ATTACK_KEYWORDS.items():
            # 检测文件中是否包含该关键词（函数名/注释/字符串）
            keyword_pattern = rf'\b{keyword}\b'
            if not re.search(keyword_pattern, content, re.IGNORECASE):
                continue

            # 检查是否已导入 PyRIT 原生类
            native_import_patterns = [
                f"from pyrit.executor.attack import {native_class}",
                f"from pyrit.executor.attack.multi_turn import {native_class}",
                f"from pyrit.executor.attack.multi_turn.crescendo_attack import {native_class}",
                f"from pyrit.executor.attack.multi_turn.tap_attack import {native_class}",
                f"from pyrit.executor.attack.multi_turn.pair_attack import {native_class}",
            ]
            has_native_import = any(p in content for p in native_import_patterns)

            # 检测手动循环模式（for turn_num/range + PromptSendingAttack）
            # 这是自行实现多轮攻击的典型特征
            manual_loop_patterns = [
                r'for\s+turn_num.*PromptSendingAttack',
                r'for\s+turn.*?in\s+range.*\n.*PromptSendingAttack',
                rf'_generate_{keyword}_prompts',
            ]
            has_manual_loop = any(re.search(p, content, re.IGNORECASE | re.DOTALL) for p in manual_loop_patterns)

            # 如果使用了关键词但没有导入原生类，或者存在手动循环
            if has_manual_loop and not has_native_import:
                # 找到违规行号
                violation_line = 0
                for i, line in enumerate(content.split("\n"), 1):
                    if f"_generate_{keyword}_prompts" in line or f"execute_{keyword}_attack" in line:
                        violation_line = i
                        break

                self.violations.append(Violation(
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
                ))


def check_native_converter_usage(self) -> None:
    """R-NATIVE-2: 检测是否自行实现了本应使用 PyRIT 原生 Converter 的编码/解码/混淆。

    宪法 C1 (PyRIT Native First) 强制要求：
    - Base64/ROT13/Unicode/Translation/Caesar 等 80+ 种编码必须使用 PyRIT 原生 Converter
    - 不得自研 base64_encode/rot13/translate 等函数替代原生 Converter

    检测逻辑：
    1. 扫描 arm/ 和 strike/ 目录中的编码/解码/混淆函数
    2. 检查是否同时存在自研实现（def xxx_encode/decode/translate）
    3. 若存在自研实现但未导入 PyRIT 原生 Converter → WARNING
    """
    Severity, Violation = _get_violation_classes()

    # 需要检查的目录
    check_dirs = [
        self.root / "arm",
        self.root / "strike",
    ]

    # 自研编码/解码/混淆的典型函数签名
    custom_impl_patterns = [
        r'def\s+base64_(?:encode|decode)\s*\(',
        r'def\s+rot13\s*\(',
        r'def\s+binary_(?:encode|decode)\s*\(',
        r'def\s+url_(?:encode|decode)\s*\(',
        r'def\s+unicode_(?:substitute|confuse|replace)\s*\(',
        r'def\s+caesar_(?:encode|decode|shift)\s*\(',
        r'def\s+vigenere_(?:encode|decode)\s*\(',
        r'def\s+atbash\s*\(',
        r'def\s+translate\s*\(',
        r'def\s+diacritic_(?:add|remove)\s*\(',
        r'def\s+char_swap\s*\(',
        r'def\s+char_noise\s*\(',
        r'def\s+random_capital\s*\(',
        r'def\s+suffix_append\s*\(',
        r'def\s+string_join\s*\(',
        r'def\s+insert_punctuation\s*\(',
        r'def\s+zero_width_(?:insert|remove)\s*\(',
        r'def\s+bidi_(?:insert|reverse)\s*\(',
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

            # 检测自研实现
            for pattern in custom_impl_patterns:
                match = re.search(pattern, content, re.IGNORECASE)
                if match:
                    # 找到匹配的行号
                    line_num = content[:match.start()].count("\n") + 1

                    # 检查是否已导入 PyRIT 原生 Converter
                    has_native_converter = "from pyrit.converter import" in content or "import pyrit.converter" in content

                    if not has_native_converter:
                        self.violations.append(Violation(
                            rule="R-NATIVE-2",
                            severity=Severity.WARNING,
                            file=rel_path,
                            line=line_num,
                            description=(
                                f"检测到自研编码/解码/混淆函数：{match.group().strip()}"
                                f"应使用 PyRIT 原生 Converter"
                            ),
                            fix_hint=(
                                "导入 PyRIT 原生 Converter 并替换自研实现："
                                "from pyrit.converter import Base64Converter, ROT13Converter, ..."
                            ),
                        ))


def check_native_scorer_usage(self) -> None:
    """R-NATIVE-3: 检测是否自行实现了本应使用 PyRIT 原生 Scorer 的评分逻辑。

    宪法 C1 (PyRIT Native First) 强制要求：
    - 拒绝检测/成功检测/正则匹配/内容分类等 50+ 种评分必须使用 PyRIT 原生 Scorer
    - 不得自研 check_refusal/is_success/regex_match 等函数替代原生 Scorer

    检测逻辑：
    1. 扫描 assess/ 和 strike/ 目录中的评分函数
    2. 检查是否同时存在自研实现（def check_refusal/is_success/regex_match）
    3. 若存在自研实现但未导入 PyRIT 原生 Scorer → WARNING
    """
    Severity, Violation = _get_violation_classes()

    # 需要检查的目录
    check_dirs = [
        self.root / "assess",
        self.root / "strike",
    ]

    # 自研评分逻辑的典型函数签名
    custom_impl_patterns = [
        r'def\s+check_refusal\s*\(',
        r'def\s+is_refusal\s*\(',
        r'def\s+check_success\s*\(',
        r'def\s+is_success\s*\(',
        r'def\s+regex_match\s*\(',
        r'def\s+substring_match\s*\(',
        r'def\s+contains_pattern\s*\(',
        r'def\s+classify_content\s*\(',
        r'def\s+content_classification\s*\(',
        r'def\s+sql_injection_check\s*\(',
        r'def\s+xss_check\s*\(',
        r'def\s+ssrf_check\s*\(',
        r'def\s+command_injection_check\s*\(',
        r'def\s+keyword_match\s*\(',
        r'def\s+credential_leak\s*\(',
        r'def\s+plagiarism_check\s*\(',
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

            # 检测自研实现
            for pattern in custom_impl_patterns:
                match = re.search(pattern, content, re.IGNORECASE)
                if match:
                    # 找到匹配的行号
                    line_num = content[:match.start()].count("\n") + 1

                    # 检查是否已导入 PyRIT 原生 Scorer
                    has_native_scorer = "from pyrit.score import" in content or "import pyrit.score" in content

                    if not has_native_scorer:
                        self.violations.append(Violation(
                            rule="R-NATIVE-3",
                            severity=Severity.WARNING,
                            file=rel_path,
                            line=line_num,
                            description=(
                                f"检测到自研评分函数：{match.group().strip()}"
                                f"应使用 PyRIT 原生 Scorer"
                            ),
                            fix_hint=(
                                "导入 PyRIT 原生 Scorer 并替换自研实现："
                                "from pyrit.score import SelfAskRefusalScorer, SelfAskTrueFalseScorer, ..."
                            ),
                        ))


def check_native_target_usage(self) -> None:
    """R-NATIVE-4: 检测是否自行实现了本应使用 PyRIT 原生 Target 的连接逻辑。

    宪法 C1 (PyRIT Native First) 强制要求：
    - HTTP/WebSocket/OpenAI/HuggingFace 等 25+ 种目标连接必须使用 PyRIT 原生 Target
    - 不得自研 HTTPRequestTarget/OpenAIChat 等类替代原生 Target

    检测逻辑：
    1. 扫描 recon/ 和 strike/ 目录中的 Target 类定义
    2. 检查是否同时存在自研实现（class HTTPRequestTarget/OpenAIChat）
    3. 若存在自研实现但未导入 PyRIT 原生 Target → WARNING
    """
    Severity, Violation = _get_violation_classes()

    # 需要检查的目录
    check_dirs = [
        self.root / "recon",
        self.root / "strike",
    ]

    # 自研 Target 的典型类名
    custom_target_patterns = [
        r'class\s+HTTPRequestTarget\s*\(',
        r'class\s+HTTPTarget\s*\(',
        r'class\s+APITarget\s*\(',
        r'class\s+WebSocketTarget\s*\(',
        r'class\s+OpenAIChat\s*\(',
        r'class\s+OpenAICompletion\s*\(',
        r'class\s+OpenAIResponse\s*\(',
        r'class\s+PromptTarget\s*\(',
        r'class\s+TextTarget\s*\(',
        r'class\s+RoundRobinTarget\s*\(',
        r'class\s+RealtimeTarget\s*\(',
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

            # 检测自研实现
            for pattern in custom_target_patterns:
                match = re.search(pattern, content, re.IGNORECASE)
                if match:
                    # 找到匹配的行号
                    line_num = content[:match.start()].count("\n") + 1

                    # 检查是否已导入 PyRIT 原生 Target
                    has_native_target = "from pyrit.prompt_target import" in content or "import pyrit.prompt_target" in content

                    if not has_native_target:
                        self.violations.append(Violation(
                            rule="R-NATIVE-4",
                            severity=Severity.WARNING,
                            file=rel_path,
                            line=line_num,
                            description=(
                                f"检测到自研 Target 类：{match.group().strip()}"
                                f"应使用 PyRIT 原生 PromptTarget"
                            ),
                            fix_hint=(
                                "导入 PyRIT 原生 Target 并替换自研实现："
                                "from pyrit.prompt_target import HTTPTarget, HTTPXAPITarget, OpenAIChatTarget, ..."
                            ),
                        ))
