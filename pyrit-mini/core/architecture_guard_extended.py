#!/usr/bin/env python3
"""
Architecture Guard 扩展规则集 — R-PIPE / R-IMPORT / R-REDTEAM / R-EVID / R-REPORT

新增 5 大系列 20+ 项架构检查，覆盖:
  - 流水线集成完整性与数据流断点 (R-PIPE)
  - 循环导入与死代码检测 (R-IMPORT)
  - 红队最佳实践与学术理论遵循 (R-REDTEAM)
  - 证据收集完整性 (R-EVID)
  - 报告生成完整性 (R-REPORT)

目标: 高攻击成功率、准确定级、完整取证、详实报告。

注册方式: 在 architecture_guard.py 末尾 from .architecture_guard_extended import register_extended_checks
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from core.architecture_guard import ArchitectureGuard


# ═══════════════════════════════════════════════════════════════════════════════
# 规则常量配置
# ═══════════════════════════════════════════════════════════════════════════════

# R-PIPE: 流水线集成完整性
_PIPELINE_MODULES: dict[str, dict[str, str]] = {
    # phase → {module_name: entry_function}
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

# 理想的 phase 执行顺序 (orchestrator.py 应调用)
_PHASE_ORDER = ["recon", "arm", "strike", "escalate", "assess", "report"]

# orchestrator.py 应调用的 phase 函数
_ORCHESTRATOR_PHASE_FUNCTIONS = [
    "_run_recon_phase",
    "_run_arm_phase",
    "_run_strike_phase",
    "_run_escalate_phase",
    "_run_assess_phase",
    "_run_report_phase",
]

# R-REDTEAM: 红队框架参考文献 (最低引用要求)
_REQUIRED_CITATIONS: list[tuple[str, str, str]] = [
    # (技术关键词, arXiv ID, 论文简称)
    ("PromptSendingAttack", "arXiv:2302.12173", "Greshake 2023"),
    ("CrescendoAttack", "arXiv:2404.01833", "Russinovich 2024"),
    ("TAPAttack", "arXiv:2405.17350", "Mehrabi 2024"),
    ("PAIRAttack", "arXiv:2310.08419", "Chao 2024"),
    ("GCG", "arXiv:2302.12173", "Zou 2023"),
    ("Decomposition", "arXiv:2402.14266", "Liu 2024 (DrAttack)"),
    ("BestOfN", "arXiv:2404.02151", "Hughes 2024"),
    ("SkeletonKey", "arXiv:2402.14266", "SKELETONKEY 2024"),
]

# R-REDTEAM: 禁止的学术不正确模式
_FORBIDDEN_PATTERNS_REDTEAM: list[tuple[str, str, str]] = [
    # (正则, 违规说明, 修复建议)
    (r"return\s+None\b.*#.*attack",
     "攻击函数返回 None 而非明确结果 — 违反攻击可观测性",
     "返回结构化 AttackOutcome 对象, 包含 success/failure + 证据"),
    (r"pass\s*#.*(attack|exploit|score)",
     "攻击/评分逻辑使用 pass stub — 功能缺失",
     "实现完整的逻辑, 或明确标记为 NotImplementedError"),
    (r"raise\s+NotImplementedError.*#.*TODO",
     "TODO stub 进入生产代码 — 流水线将有功能缺口",
     "移除 stub, 提供真实实现或在 orchestrator 中跳过该技术"),
]

# PipelineContext 字段到消费 phase 的映射 (用于断点检测)
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

# ═══ 扩展检查函数 ═══


def register_extended_checks(guard_cls) -> None:
    """向 ArchitectureGuard 类注册所有扩展检查规则。"""

    # ── R-PIPE 系列 ──────────────────────────────────────────────────

    def check_pipeline_integration(self) -> None:
        """R-CONV-1~4: 流水线集成完整性检测。

        检测项目:
          1. 各 phase 模块是否在 orchestrator.py 中有对应调用
          2. PipelineContext 各字段是否有对应生产者和消费者
          3. 新增模块是否自动注册到流水线
          4. 数据传递是否有断点 (字段设置后无消费)
        """
        orch_file = self.root / "core" / "orchestrator.py"
        ctx_file = self.root / "core" / "context.py"

        # R-CONV-1: 检测 orchestrator.py 是否包含各 phase 函数
        if orch_file.exists():
            orch_content = orch_file.read_text(encoding="utf-8", errors="replace")
            for func_name in _ORCHESTRATOR_PHASE_FUNCTIONS:
                if f"async def {func_name}" not in orch_content:
                    self.violations.append(Violation(
                        rule="R-PIPE-1",
                        severity=Severity.BLOCKING,
                        file="core/orchestrator.py",
                        line=0,
                        description=f"orchestrator.py 缺少阶段函数 '{func_name}' — 流水线阶段执行缺失",
                        fix_hint=f"添加 async def {func_name}(ctx) 实现对应阶段逻辑",
                    ))

        # R-PIPE-2: 检测各 phase 被 orchestrator 调用
        if orch_file.exists():
            orch_content = orch_file.read_text(encoding="utf-8", errors="replace")
            phase_calls = [
                ("_run_recon_phase(ctx", "recon 阶段"),
                ("_run_arm_phase(ctx", "arm 阶段"),
                ("_run_strike_phase(ctx", "strike 阶段"),
                ("_run_escalate_phase(ctx", "escalate 阶段"),
                ("_run_assess_phase(ctx", "assess 阶段"),
                ("_run_report_phase(ctx", "report 阶段"),
            ]
            for call_pattern, desc in phase_calls:
                if call_pattern not in orch_content:
                    self.violations.append(Violation(
                        rule="R-PIPE-2",
                        severity=Severity.BLOCKING,
                        file="core/orchestrator.py",
                        line=0,
                        description=f"orchestrator 未调用 {desc} — 流水线阶段断开",
                        fix_hint=f"在 run_single_endpoint 中添加 {call_pattern} 调用",
                    ))

        # R-PIPE-3: 检测 arm/ 新增模块是否注册到 converter_presets
        self._check_arm_module_registration()

        # R-PIPE-4: 检测 strike/ 新增 exporter 是否注册到 executor
        self._check_strike_module_registration()

    def _check_arm_module_registration(self) -> None:
        """检测 arm/ 包内模块是否正确注册到 converter_presets.py"""
        presets_file = self.root / "arm" / "converter_presets.py"
        if not presets_file.exists():
            return
        content = presets_file.read_text(encoding="utf-8", errors="replace")

        # 检查 _build_chain_builders 注册
        if "_build_chain_builders" not in content:
            self.violations.append(Violation(
                rule="R-PIPE-3",
                severity=Severity.WARNING,
                file="arm/converter_presets.py",
                line=0,
                description="缺少 _build_chain_builders 函数 — converter 链注册工厂缺失",
                fix_hint="添加 _build_chain_builders() -> dict[str, Any] 返回链名→构建函数映射",
            ))

    def _check_strike_module_registration(self) -> None:
        """检测 strike/ 包内 attack executor 是否注册到主 executor.py"""
        executor_file = self.root / "strike" / "executor.py"
        if not executor_file.exists():
            return
        content = executor_file.read_text(encoding="utf-8", errors="replace")

        # 检测是否导入关键技术模块
        required_imports = [
            ("strike.native_attacks", "原生攻击策略模块"),
            ("strike.escalation", "技术升级模块"),
        ]
        for module_path, desc in required_imports:
            if f"import {module_path}" not in content and f"from {module_path}" not in content:
                # 允许延迟导入: 检查是否在有条件分支中使用
                short_name = module_path.split(".")[-1]
                if f"import {short_name}" not in content:
                    self.violations.append(Violation(
                        rule="R-PIPE-4",
                        severity=Severity.WARNING,
                        file="strike/executor.py",
                        line=0,
                        description=f"executor.py 未引用 {desc} ({module_path}) — 可能缺少关键攻击路径",
                        f"确认 {short_name} 在其他地方被调用, 或添加显式导入/调用",
                    ))

    def check_data_flow_consistency(self) -> None:
        """R-PIPE-5~6: 数据流一致性检测。

        检测项目:
          1. PipelineContext 字段声明后是否有生产者 (who sets)
          2. PipelineContext 字段设置后是否有消费者 (who reads)
          3. Phase 间数据传递是否有断层
        """
        ctx_file = self.root / "core" / "context.py"
        orch_file = self.root / "core" / "orchestrator.py"

        if not ctx_file.exists():
            return

        ctx_content = ctx_file.read_text(encoding="utf-8", errors="replace")
        orch_content = orch_file.read_text(encoding="utf-8", errors="replace") if orch_file.exists() else ""

        # 提取 PipelineContext 字段
        field_pattern = re.compile(r"^\s+(\w+):\s*[\w\[\]|]+\s*=")
        fields = []
        for line in ctx_content.split("\n"):
            m = field_pattern.match(line)
            if m and not m.group(1).startswith("_"):
                fields.append(m.group(1))

        # 检测每个字段是否有读取
        for field_name in fields:
            if field_name.startswith("_"):
                continue
            # 在 orchestrator 中搜索字段访问
            access_pattern = rf"ctx\.{field_name}[^.a-zA-Z]"
            if not re.search(access_pattern, orch_content):
                # 可能在其他模块中消费 - 放宽检测
                all_content = self._read_all_source()
                total_refs = sum(1 for c in all_content if re.search(access_pattern, c))
                if total_refs <= 1:  # 只有声明无引用
                    self.violations.append(Violation(
                        rule="R-PIPE-5",
                        severity=Severity.INFO,
                        file="core/context.py",
                        line=0,
                        description=f"PipelineContext.{field_name} 无消费点 — 数据流断点或死字段",
                        f"确认 {field_name} 在某个 phase 中被使用, 或移除未使用字段",
                    ))

    def _read_all_source(self) -> list[str]:
        """读取所有源文件内容"""
        contents = []
        for p in self.source_files:
            try:
                contents.append(p.read_text(encoding="utf-8", errors="replace"))
            except OSError:
                pass
        return contents

    # ── R-IMPORT 系列 ────────────────────────────────────────────────

    def check_circular_imports(self) -> None:
        """R-IMPORT-1~2: 循环导入与死代码检测。

        检测项目:
          1. 模块间的循环依赖 (A→B→A)
          2. 模块注册检测 (模块存在但被导入但未被使用)
        """
        # 构建导入图
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

            # 检测 from X import Y 和 import X
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

        # 检测循环
        for module, deps in import_graph.items():
            for dep in deps:
                dep_imports = import_graph.get(dep, set())
                if module in dep_imports:
                    self.violations.append(Violation(
                        rule="R-IMPORT-1",
                        severity=Severity.BLOCKING,
                        file=module.replace(".", "/") + ".py",
                        line=0,
                        description=f"循环导入: {module} ↔ {dep} — 启动时崩溃或不可预测行为",
                        f"将共享逻辑提取到独立 utils/ 模块, 或改用延迟导入 (函数内 import)",
                    ))

    def check_dead_code(self) -> None:
        """R-IMPORT-3: 死代码与孤儿模块检测。

        检测项目:
          1. 文件存在但无任何其他模块导入
          2. 被导入但从未调用
        """
        # 收集所有导入引用
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
                        # 提取包名
                        for pkg in ["core", "arm", "strike", "assess", "report", "recon"]:
                            if mod.startswith(pkg):
                                imported_modules.add(mod.split(".")[0] + "/" + mod.split(".")[1] if "." in mod else mod)
                                break

        # 检测 arm/ strike/ assess/ report/recon/ 中未被引用的子模块
        pipeline_pkgs = ["arm", "strike", "assess", "report", "recon"]
        for path in self.source_files:
            rel = str(path.relative_to(self.root))
            if "__init__.py" in rel or not rel.endswith(".py"):
                continue
            parts = rel.split("/")
            if len(parts) >= 2 and parts[0] in pipeline_pkgs:
                module_name = parts[-1].replace(".py", "")
                # 是否被导入
                is_imported = any(module_name in imp for imp in imported_modules)
                # 是否在 orchestrator 中被直接引用
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
                        description=f"模块 {rel} 未被任何其他模块导入 — 可能是未集成的新功能或死代码",
                        f"将该模块集成到流水线 (导入并调用), 或移除/归档",
                    ))

    # ── R-REDTEAM 系列 ──────────────────────────────────────────────

    def check_best_practices(self) -> None:
        """R-REDTEAM-1~3: 红队最佳实践遵循检测。

        检测项目:
          1. 攻击函数返回 None 或 pass stub
          2. 缺少 arXiv 引用
          3. 违反学术建议的代码模式
        """
        for path in self.source_files:
            try:
                content = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if "__init__.py" in str(path):
                continue

            lines = content.split("\n")

            # R-REDTEAM-1: 检测禁止模式
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
        """R-REDTEAM-2: 检测关键技术是否缺少学术引用"""
        pipeline_dirs = {"strike", "arm", "assess"}
        for path in self.source_files:
            if not any(d in str(path) for d in pipeline_dirs):
                continue
            try:
                content = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            # 对每个技术关键词检测是否有 arXiv 引用
            for keyword, arxiv_id, paper_name in _REQUIRED_CITATIONS:
                if keyword in content and arxiv_id not in content:
                    # 查找第一个出现的行号
                    for i, line in enumerate(content.split("\n"), 1):
                        if keyword in line and "import" not in line:
                            self.violations.append(Violation(
                                rule="R-REDTEAM-2",
                                severity=Severity.INFO,
                                file=str(path.relative_to(self.root)),
                                line=i,
                                description=f"使用 '{keyword}' 但缺少引用 {arxiv_id} ({paper_name})",
                                fix_hint=f"在文件头部 docstring 或附近添加引用: {arxiv_id}",
                            ))
                            break

    def check_asr_completeness(self) -> None:
        """R-REDTEAM-3: 检测 ASR 计算链完整性"""
        score_file = self.root / "assess" / "asr_manager.py"
        if not score_file.exists():
            score_file = self.root / "assess" / "asr_stats.py"
        if not score_file.exists():
            self.violations.append(Violation(
                rule="R-REDTEAM-3",
                severity=Severity.BLOCKING,
                file="assess/asr_manager.py",
                line=0,
                description="缺少 ASR 管理模块 (asr_manager.py 或 asr_stats.py)",
                fix_hint="创建 assess/asr_manager.py, 实现 compute_asr + compute_overall_asr",
            ))
            return

        content = score_file.read_text(encoding="utf-8", errors="replace")
        required_functions = ["compute_asr", "compute_overall_asr"]
        for func in required_functions:
            if f"def {func}" not in content and f"async def {func}" not in content:
                self.violations.append(Violation(
                    rule="R-REDTEAM-3",
                    severity=Severity.WARNING,
                    file=str(score_file.relative_to(self.root)),
                    line=0,
                    description=f"ASR 模块缺少函数 '{func}' — ASR 统计链不完整",
                    fix_hint=f"实现 {func}() 函数并集成到 assess 阶段",
                ))

    # ── R-EVID 系列 ─────────────────────────────────────────────────

    def check_evidence_completeness(self) -> None:
        """R-EVID-1: 证据收集流水完整性检测"""
        evidence_file = self.root / "report" / "evidence.py"
        if not evidence_file.exists():
            self.violations.append(Violation(
                rule="R-EVID-1",
                severity=Severity.BLOCKING,
                file="report/evidence.py",
                line=0,
                description="缺少 report/evidence.py — 证据收集系统缺失",
                fix_hint="创建 report/evidence.py, 实现 EvidenceCollector 类",
            ))
            return

        content = evidence_file.read_text(encoding="utf-8", errors="replace")
        required_methods = ["collect_evidence", "save_evidence"]
        for method in required_methods:
            if f"def {method}" not in content and f"async def {method}" not in content:
                self.violations.append(Violation(
                    rule="R-EVID-1",
                    severity=Severity.WARNING,
                    file="report/evidence.py",
                    line=0,
                    description=f"EvidenceCollector 缺少方法 '{method}' — 证据收集流程不完整",
                    fix_hint=f"实现 {method}() 方法",
                ))

    # ── R-REPORT 系列 ───────────────────────────────────────────────

    def check_report_completeness(self) -> None:
        """R-REPORT-1: 报告生成完整性检测"""
        generator_file = self.root / "report" / "generator.py"
        if not generator_file.exists():
            self.violations.append(Violation(
                rule="R-REPORT-1",
                severity=Severity.BLOCKING,
                file="report/generator.py",
                line=0,
                description="缺少 report/generator.py — 报告生成系统缺失",
                fix_hint="创建 report/generator.py, 实现 generate_report()",
            ))
            return

        content = generator_file.read_text(encoding="utf-8", errors="replace")

        # 检测是否调用 EvidenceCollector
        if "EvidenceCollector" not in content:
            self.violations.append(Violation(
                rule="R-REPORT-1",
                severity=Severity.WARNING,
                file="report/generator.py",
                line=0,
                description="generate_report 未使用 EvidenceCollector — 证据可能未纳入报告",
                fix_hint="在 generate_report 中实例化 EvidenceCollector 并传入",
            ))

        # 检测是否输出多个格式
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
                description=f"报告仅支持 {', '.join(output_formats)} 格式 — 建议多格式输出",
                fix_hint="增加 Markdown / SARIF 输出以便 CI 集成和缺陷跟踪",
            ))

    # ── 注册方法 ──

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
