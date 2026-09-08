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
                is_imported = f"from " in orch_content and func_name in orch_content and "import" in orch_content
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
