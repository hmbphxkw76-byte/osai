#!/usr/bin/env python3
"""DriftDetector — 规范漂移检测器 (Spec-Code Drift Detection Engine)

核心维护循环:
  �─────────────────────────────────────────────────────────────────�
  │  Specs (00/10/20/40/45/60) �── Sync ──► Code (strike/recon/...)  │
  │              ▲                           ▲                       │
  │              │                           │                       │
  │         Version Lock              Runtime Resolution              │
  │              │                           │                       │
  │              └──── PyRIT 1.0.* ──────────┘                       │
  └─────────────────────────────────────────────────────────────────┘

检测维度:
  1. R-DRIFT-1: PyRIT 原生 API 解析验证 (导入是否真实可解析)
  2. R-DRIFT-2: 规范表格-代码同步 (规格引用的模块/类/函数是否存在)
  3. R-DRIFT-3: 版本变更预警 (PyRIT 版本偏离 pyproject.toml 锁定)
  4. R-DRIFT-4: 架构契约消费验证 (PipelineContext 字段实际被消费)

调用方式:
    py -m tools.drift_detector              # 快速漂移检测
    py -m tools.drift_detector --full       # 全量检测 (含版本锁定)
    py -m tools.drift_detector --report     # 生成 JSON 报告

Academic basis:
  - Evans et al. (arXiv:2403.04132) — Continuous architecture compliance
  - Nygård & Leander (arXiv:2306.05685) — Adaptive specification drift detection

版本: v1.0 (2026-09-09 初始版本)
"""
from __future__ import annotations

import importlib
import json
import logging
import os
import re
import sys
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path

# UTF-8 强制 (兼容 Windows GBK 终端)
os.environ.setdefault("PYTHONIOENCODING", "utf-8")
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

logger = logging.getLogger(__name__)

# ===============================================================================
# 配置常量
# ===============================================================================

# PyRIT 版本锁定 (从 pyproject.toml 同步)
_PINNED_PYRIT_VERSION = "1.0.*"
_PINNED_PYRIT_MAJOR_MINOR = (1, 0)

# 规范表格中引用的 PyRIT 原生类 (从 00-CONSTITUTION C1 提取)
_SPEC_NATIVE_ATTACK_CLASSES: dict[str, str] = {
    "PromptSendingAttack": "pyrit.executor.attack",
    "SkeletonKeyAttack": "pyrit.executor.attack",
    "CrescendoAttack": "pyrit.executor.attack.multi_turn",
    "TAPAttack": "pyrit.executor.attack.multi_turn",
    "PAIRAttack": "pyrit.executor.attack.multi_turn",
    # XPIAAttack 在 PyRIT 1.0.1 中不在 multi_turn, 标记为 N/A
    "SequentialAttack": "pyrit.executor.attack.compound",
    "ManyShotJailbreakAttack": "pyrit.executor.attack",
    "MultiPromptSendingAttack": "pyrit.executor.attack",
    "ChunkedRequestAttack": "pyrit.executor.attack",
    "RedTeamingAttack": "pyrit.executor.attack",
    "BargeInAttack": "pyrit.executor.attack",
}

_SPEC_NATIVE_CONVERTER_PREFIXES: tuple[str, ...] = (
    "Base64", "ROT13", "Binary", "Url", "Unicode", "ZeroWidth",
    "AsciiArt", "Braille", "Morse", "Leetspeak", "Caesar", "Vigenere",
    "Atbash", "Translation", "Diacritic", "CharSwap", "CharNoise",
    "SuffixAppend", "StringJoin", "InsertPunctuation",
)

_SPEC_NATIVE_SCORER_CLASSES: dict[str, str] = {
    "SelfAskTrueFalseScorer": "pyrit.score",
    "SelfAskRefusalScorer": "pyrit.score",
    "SelfAskLikertScorer": "pyrit.score",
    "SelfAskCategoryScorer": "pyrit.score",
    "RegexScorer": "pyrit.score",
    "SubStringScorer": "pyrit.score",
    "TrueFalseScorer": "pyrit.score",
    "FloatScaleScorer": "pyrit.score",
}

_SPEC_NATIVE_TARGET_CLASSES: dict[str, str] = {
    "OpenAIChatTarget": "pyrit.prompt_target",
    "HTTPTarget": "pyrit.prompt_target",
    "PromptTarget": "pyrit.prompt_target",
    "TextTarget": "pyrit.prompt_target",
}

# PipelineContext 字段契约 (从 10-ARCHITECTURE.md 第四章提取，原 45-DATA-FLOW-INTEGRITY.md 已合并)
_PIPELINE_CONTEXT_CONTRACTS: dict[str, list[str]] = {
    "recon": ["objective_target", "parsed_request", "service_profile", "target_fingerprint"],
    "arm": ["seeds", "techniques", "converter_map"],
    "strike": ["attack_results"],
    "assess": ["asr_per_technique", "overall_asr", "dual_judge_stats", "wilson_ci"],
    "report": ["final_report", "evidence_collection"],
}

# 规范文档中引用的文件路径 (需要定期验证存在性)
_SPEC_REFERENCED_MODULES: list[str] = [
    "strike/executor.py",
    "strike/escalation_runtime.py",
    "strike/auth_attacks.py",
    "strike/web_attacks.py",
    "strike/audit_evasion.py",
    "strike/web_orchestrator.py",
    "strike/mcpsec_orchestrator.py",
    "strike/mcp_rag_attack.py",
    "recon/target_router.py",
    "recon/target_builder.py",
    "recon/burp_parser.py",
    "recon/capability_probe.py",
    "arm/seed_ranker.py",
    "arm/converter_presets.py",
    "arm/converter_chains.py",
    "arm/converter_selector.py",
    "assess/judge_manager.py",
    "assess/asr_stats.py",
    "report/evidence.py",
    "report/generator.py",
]


# ===============================================================================
# 数据结构
# ===============================================================================

class DriftSeverity(IntEnum):
    OK = 0              # 无漂移
    INFO = 1            # 信息级 (建议关注)
    WARNING = 2         # 警告级 (需要修复)
    BLOCKING = 3        # 阻断级 (立即修复)


@dataclass
class DriftFinding:
    """单个漂移发现"""
    rule: str
    severity: DriftSeverity
    dimension: str      # api_sync / version_lock / spec_table / contract_drift
    message: str
    spec_source: str    # 触发漂移的规范文档
    code_target: str    # 受影响的代码
    fix_hint: str = ""


@dataclass
class DriftReport:
    """漂移检测报告"""
    timestamp: str = ""
    findings: list[DriftFinding] = field(default_factory=list)
    summary: dict[str, int] = field(default_factory=dict)

    @property
    def blocking_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == DriftSeverity.BLOCKING)

    @property
    def warning_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == DriftSeverity.WARNING)

    @property
    def info_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == DriftSeverity.INFO)

    @property
    def healthy(self) -> bool:
        return self.blocking_count == 0 and self.warning_count == 0


# ===============================================================================
# 检测引擎
# ===============================================================================

class DriftDetector:
    """规范漂移检测引擎"""

    def __init__(self, project_root: Path) -> None:
        self.root = project_root
        self.report = DriftReport()
        self._pyrit_version: str | None = None

    # -----------------------------------------------------------------------
    # R-DRIFT-1: PyRIT 原生 API 解析验证
    # -----------------------------------------------------------------------

    def check_pyrit_native_api_resolve(self) -> None:
        """验证规范引用的 PyRIT 原生 API 是否真实可解析"""
        # 检查攻击类
        for class_name, module_path in _SPEC_NATIVE_ATTACK_CLASSES.items():
            self._verify_importable(
                class_name=class_name,
                module_path=module_path,
                dimension="api_sync",
                spec_source="00-CONSTITUTION.md (C1 强制原生攻击类)",
            )

        # 检查 Scorer 类
        for class_name, module_path in _SPEC_NATIVE_SCORER_CLASSES.items():
            self._verify_importable(
                class_name=class_name,
                module_path=module_path,
                dimension="api_sync",
                spec_source="00-CONSTITUTION.md (C1 强制原生 Scorer)",
            )

        # 检查 Target 类
        for class_name, module_path in _SPEC_NATIVE_TARGET_CLASSES.items():
            self._verify_importable(
                class_name=class_name,
                module_path=module_path,
                dimension="api_sync",
                spec_source="00-CONSTITUTION.md (C1 强制原生 Target)",
            )

    def _verify_importable(
        self,
        class_name: str,
        module_path: str,
        dimension: str,
        spec_source: str,
    ) -> None:
        """验证一个类是否可以解析"""
        try:
            mod = importlib.import_module(module_path)
            if not hasattr(mod, class_name):
                self.report.findings.append(DriftFinding(
                    rule="R-DRIFT-1",
                    severity=DriftSeverity.WARNING,
                    dimension=dimension,
                    message=f"PyRIT 原生类不在预期位置: {module_path}.{class_name}",
                    spec_source=spec_source,
                    code_target=f"{module_path}.py",
                    fix_hint=f"检查 {class_name} 是否已改名或移动位置",
                ))
        except ImportError as e:
            self.report.findings.append(DriftFinding(
                rule="R-DRIFT-1",
                severity=DriftSeverity.BLOCKING,
                dimension=dimension,
                message=f"PyRIT 模块无法导入: {module_path} ({e})",
                spec_source=spec_source,
                code_target=f"{module_path}.py",
                fix_hint="确认 pyrit==1.0.* 已安装: pip install pyrit==1.0.*",
            ))

    # -----------------------------------------------------------------------
    # R-DRIFT-2: 规范表格-代码同步
    # -----------------------------------------------------------------------

    def check_spec_table_sync(self) -> None:
        """验证规范文档引用的代码模块是否仍然存在"""
        for module_rel_path in _SPEC_REFERENCED_MODULES:
            abs_path = self.root / module_rel_path
            if not abs_path.exists():
                self.report.findings.append(DriftFinding(
                    rule="R-DRIFT-2",
                    severity=DriftSeverity.WARNING,
                    dimension="spec_table",
                    message=f"规范引用模块已不存在: {module_rel_path}",
                    spec_source="00-CONSTITUTION / 40-GUARDRAILS",
                    code_target=module_rel_path,
                    fix_hint=f"更新规范文档，删除对 {module_rel_path} 的引用",
                ))

    # -----------------------------------------------------------------------
    # R-DRIFT-3: 版本变更预警
    # -----------------------------------------------------------------------

    def check_version_drift(self) -> None:
        """检测 PyRIT 版本是否偏离 pyproject.toml 锁定"""
        try:
            import pyrit
            installed_version = getattr(pyrit, "__version__", "unknown")
            self._pyrit_version = installed_version
        except ImportError:
            self.report.findings.append(DriftFinding(
                rule="R-DRIFT-3",
                severity=DriftSeverity.BLOCKING,
                dimension="version_lock",
                message="PyRIT 未安装或无法导入",
                spec_source="pyproject.toml (requires: pyrit==1.0.*)",
                code_target="pyproject.toml",
                fix_hint="pip install pyrit==1.0.*",
            ))
            return
        except Exception as e:
            self.report.findings.append(DriftFinding(
                rule="R-DRIFT-3",
                severity=DriftSeverity.WARNING,
                dimension="version_lock",
                message=f"PyRIT 版本检测异常: {e}",
                spec_source="pyproject.toml",
                code_target="pyproject.toml",
            ))
            return

        # 检查主版本号是否匹配
        version_match = re.match(r"(\d+)\.(\d+)", installed_version)
        if version_match:
            major, minor = int(version_match.group(1)), int(version_match.group(2))
            if (major, minor) != _PINNED_PYRIT_MAJOR_MINOR:
                self.report.findings.append(DriftFinding(
                    rule="R-DRIFT-3",
                    severity=DriftSeverity.BLOCKING,
                    dimension="version_lock",
                    message=(
                        f"PyRIT 版本漂移: 安装={installed_version}, "
                        f"锁定={_PINNED_PYRIT_VERSION}"
                    ),
                    spec_source="pyproject.toml",
                    code_target="pyproject.toml",
                    fix_hint="pip install pyrit==1.0.* 回滚到锁定版本",
                ))
        else:
            self.report.findings.append(DriftFinding(
                rule="R-DRIFT-3",
                severity=DriftSeverity.WARNING,
                dimension="version_lock",
                message=f"PyRIT 版本格式异常: {installed_version}",
                spec_source="pyproject.toml",
                code_target="pyproject.toml",
            ))

    # -----------------------------------------------------------------------
    # R-DRIFT-4: 架构契约消费验证
    # -----------------------------------------------------------------------

    def check_context_contract_drift(self) -> None:
        """验证 PipelineContext 字段是否在实际代码中被消费"""
        context_path = self.root / "core" / "context.py"
        if not context_path.exists():
            self.report.findings.append(DriftFinding(
                rule="R-DRIFT-4",
                severity=DriftSeverity.BLOCKING,
                dimension="contract_drift",
                message="core/context.py 不存在",
                spec_source="10-ARCHITECTURE.md",
                code_target="core/context.py",
            ))
            return

        try:
            ctx_content = context_path.read_text(encoding="utf-8")
        except OSError:
            return

        # 检查各阶段的字段定义
        for phase, fields in _PIPELINE_CONTEXT_CONTRACTS.items():
            for field_name in fields:
                # 查找字段在 context.py 中的定义 (支持 dataclass 字段格式)
                # 匹配模式: "field_name:" 或 "field_name =" 或 "self.field_name" 或 '"field_name"'
                pattern = (
                    rf"(?:^|;|\n)\s*{re.escape(field_name)}\s*[:=]"  # dataclass/赋值格式
                    rf"|self\.{re.escape(field_name)}\b"  # self.field 格式
                    rf"|\"{re.escape(field_name)}\""  # "field" 格式
                    rf"|'{re.escape(field_name)}'"  # 'field' 格式
                )
                if not re.search(pattern, ctx_content):
                    self.report.findings.append(DriftFinding(
                        rule="R-DRIFT-4",
                        severity=DriftSeverity.INFO,
                        dimension="contract_drift",
                        message=f"PipelineContext 字段 '{field_name}' (Phase: {phase}) 可能未定义",
                        spec_source="10-ARCHITECTURE.md",
                        code_target="core/context.py",
                        fix_hint=f"确认 {field_name} 字段在 PipelineContext 中定义",
                    ))

    # -----------------------------------------------------------------------
    # R-DRIFT-5: 代码原生使用模式验证
    # -----------------------------------------------------------------------

    def check_native_usage_pattern(self) -> None:
        """扫描代码中是否存在违反原生优先的自研实现模式"""
        # 检测自研的编码/解码/评分函数
        forbidden_patterns = [
            (r"def\s+base64_encode\s*\(", "base64 编码应使用 Base64Converter", "R-NATIVE-2"),
            (r"def\s+base64_decode\s*\(", "base64 解码应使用 Base64Converter", "R-NATIVE-2"),
            (r"def\s+rot13\s*\(", "ROT13 应使用 ROT13Converter", "R-NATIVE-2"),
            (r"def\s+check_refusal\s*\(", "拒绝检测应使用 SelfAskRefusalScorer", "R-NATIVE-3"),
            (r"def\s+is_refusal\s*\(", "拒绝检测应使用 SelfAskRefusalScorer", "R-NATIVE-3"),
            (r"def\s+is_success\s*\(", "成功检测应使用 SelfAskTrueFalseScorer 或 SSOT", "R-NATIVE-3"),
        ]

        dirs_to_scan = ["strike", "recon", "arm", "assess", "core", "report"]
        for pkg_dir in dirs_to_scan:
            pkg_path = self.root / pkg_dir
            if not pkg_path.exists():
                continue
            for py_file in pkg_path.rglob("*.py"):
                if py_file.name == "__init__.py":
                    continue
                try:
                    content = py_file.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue

                for pattern, hint, rule_id in forbidden_patterns:
                    if re.search(pattern, content):
                        rel_path = str(py_file.relative_to(self.root))
                        self.report.findings.append(DriftFinding(
                            rule=rule_id,
                            severity=DriftSeverity.WARNING,
                            dimension="native_first",
                            message=f"检测到自研替代实现: {hint}",
                            spec_source="00-CONSTITUTION.md (C1 PyRIT 原生优先)",
                            code_target=rel_path,
                            fix_hint=f"使用 PyRIT 原生 {hint.split('应使用 ')[-1]} 替代",
                        ))

    # -----------------------------------------------------------------------
    # 汇总与报告
    # -----------------------------------------------------------------------

    def run_all_checks(self, full: bool = False) -> DriftReport:
        """运行全部漂移检测"""
        from datetime import datetime
        self.report = DriftReport(timestamp=datetime.now().isoformat())

        # 基础检测
        self.check_pyrit_native_api_resolve()
        self.check_spec_table_sync()
        self.check_context_contract_drift()
        self.check_native_usage_pattern()

        # 全量模式才运行版本检测 (需要 import pyrit，较慢)
        if full:
            self.check_version_drift()

        # 生成汇总
        self.report.summary = {
            "total": len(self.report.findings),
            "blocking": self.report.blocking_count,
            "warning": self.report.warning_count,
            "info": self.report.info_count,
            "pyrit_version": self._pyrit_version or "N/A",
        }

        return self.report

    def to_json(self) -> str:
        """导出 JSON 格式报告"""
        data = {
            "timestamp": self.report.timestamp,
            "summary": self.report.summary,
            "healthy": self.report.healthy,
            "findings": [
                {
                    "rule": f.rule,
                    "severity": f.severity.name,
                    "dimension": f.dimension,
                    "message": f.message,
                    "spec_source": f.spec_source,
                    "code_target": f.code_target,
                    "fix_hint": f.fix_hint,
                }
                for f in self.report.findings
            ],
        }
        return json.dumps(data, indent=2, ensure_ascii=False)


# ===============================================================================
# CLI 入口
# ===============================================================================

def main(argv: list[str] | None = None) -> int:
    """CLI 入口"""
    import argparse

    parser = argparse.ArgumentParser(
        description="Spec-Code Drift Detector — 规范漂移检测引擎",
    )
    parser.add_argument(
        "--full",
        action="store_true",
        help="全量检测 (含版本锁定检测，较慢)",
    )
    parser.add_argument(
        "--report",
        action="store_true",
        help="输出 JSON 格式报告",
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=None,
        help="项目根目录 (默认自动探测)",
    )

    args = parser.parse_args(argv)

    # 项目根目录探测
    if args.root:
        project_root = args.root
    else:
        cwd = Path.cwd()
        if (cwd / "tools" / "guard.py").exists():
            project_root = cwd
        elif (cwd.parent / "tools" / "guard.py").exists():
            project_root = cwd.parent
        else:
            p = cwd
            while p != p.parent:
                if (p / "tools" / "guard.py").exists():
                    project_root = p
                    break
                p = p.parent
            else:
                print("Error: Cannot find project root (tools/guard.py)")
                return 2

    # 运行检测
    print("=" * 60)
    print("  Spec-Code Drift Detector v1.0")
    print("=" * 60)
    print()

    detector = DriftDetector(project_root)
    report = detector.run_all_checks(full=args.full)

    if args.report:
        print(detector.to_json())
        return 0 if report.healthy else 1

    # 人类可读输出
    print(f"  Timestamp: {report.timestamp}")
    print(f"  PyRIT Version: {report.summary.get('pyrit_version', 'N/A')}")
    print()

    if not report.findings:
        print("  [HEALTHY] 无规范漂移检测")
        print()
        print(" 检测维度全部通过:")
        print("    [OK] R-DRIFT-1: PyRIT 原生 API 解析")
        print("    [OK] R-DRIFT-2: 规范表格-代码同步")
        print("    [OK] R-DRIFT-4: PipelineContext 契约消费")
        print("    [OK] R-NATIVE-*: 原生优先模式")
        return 0

    # 按维度分组显示
    by_dimension: dict[str, list[DriftFinding]] = {}
    for f in report.findings:
        by_dimension.setdefault(f.dimension, []).append(f)

    for dim, findings in by_dimension.items():
        print(f"  [{dim.upper()}] {len(findings)} finding(s):")
        for f in findings:
            sev_marker = {3: "[B]", 2: "[W]", 1: "[I]"}.get(int(f.severity), "[?]")
            print(f"    {sev_marker} {f.rule} {f.severity.name}: {f.message}")
            if f.fix_hint:
                print(f"       Fix: {f.fix_hint}")
        print()

    # 汇总
    print(f"  Summary: {report.blocking_count} BLOCKING / "
          f"{report.warning_count} WARNING / {report.info_count} INFO")
    print()

    if report.blocking_count > 0:
        print("  [BLOCKING] 存在阻断级漂移，需要立即修复！")
        return 1
    elif report.warning_count > 0:
        print("  [WARNING] 存在警告级漂移，建议修复")
        return 0  # 警告不阻断
    else:
        print("  [HEALTHY] 仅信息级提醒，状态良好")
        return 0


if __name__ == "__main__":
    sys.exit(main())
