"""
数据流完整性验证器 — 命令行入口

提供 CLI 接口和演示模式。
独立模块避免 validator.py 膨胀。

Academic basis:
    - NIST SP 800-115: Technical Guide to Information Security Testing
"""

from __future__ import annotations

import json
import time
from pathlib import Path

from tools.dataflow.format import format_report, report_to_json
from tools.dataflow.models import DataFlowReport, DataSnapshot, ValidationResult
from tools.dataflow.validator import DataFlowValidator


def audit_from_log(log_entries: list[dict]) -> DataFlowReport:
    """从 orchestration_log 审计数据流"""
    from datetime import datetime

    validator = DataFlowValidator()

    # 根据 orchestration_log 构建虚拟快照
    phases_seen = set()
    for entry in log_entries:
        phase = entry.get("phase", "unknown")
        phases_seen.add(phase)

        # 创建虚拟快照
        snap = DataSnapshot(
            phase=f"post_{phase}",
            timestamp=time.time(),
            context_hash=id(log_entries),
            fields={"orchestration_entry": entry},
            metadata=entry,
        )
        validator.snapshots[f"post_{phase}"] = snap

    # 仅执行传递规则
    results = []
    for rule in DataFlowValidator.TRANSFER_RULES:
        from_phase = rule["from"]
        if from_phase in phases_seen:
            results.append(
                ValidationResult(
                    rule_id=rule["id"],
                    rule_name=rule["name"],
                    passed=True,
                    phase_from=from_phase,
                    phase_to=rule["to"],
                    message=f"阶段 {from_phase} 出现在 orchestration_log 中 ✓",
                    severity="info",
                )
            )
        else:
            results.append(
                ValidationResult(
                    rule_id=rule["id"],
                    rule_name=rule["name"],
                    passed=False,
                    phase_from=from_phase,
                    phase_to=rule["to"],
                    message=f"阶段 {from_phase} 未出现在 orchestration_log 中",
                    severity="warning",
                )
            )

    return DataFlowReport(
        timestamp=datetime.now().isoformat(),
        total_rules=len(results),
        passed=sum(1 for r in results if r.passed),
        failed=sum(1 for r in results if not r.passed and r.severity == "error"),
        warnings=sum(1 for r in results if r.severity == "warning"),
        results=results,
        snapshots=list(validator.snapshots.values()),
        duration_seconds=0.0,
    )


def demo_validation() -> DataFlowReport:
    """运行演示验证（模拟完整流水线 Recon → ARM → Strike → Assess → Report）"""

    # 模拟 Recon 输出
    class MockCtx:
        objective_target = object()
        parsed_request = type(
            "FP",
            (),
            {
                "target_fingerprint": {
                    "model_family": "gpt",
                    "language": "en",
                    "capabilities": ["function_calling"],
                    "model_name": "gpt-4",
                },
                "host": "api.example.com",
                "path": "/v1/chat/completions",
                "use_tls": True,
            },
        )()
        service_profile = {
            "model_name": "gpt-4",
            "auth_type": "bearer",
            "rag_kb_map": {"document_count": 10},
            "backend_vendor": "openai",
        }
        mcpsec_surface = {"tools": [{"name": "search"}], "resources": [], "prompts": []}
        mcpsec_scan_results = {"vulnerabilities": []}
        seeds = []
        techniques = []
        converter_map = {}
        attack_results = {}
        asr_per_technique = {}
        overall_asr = 0.0
        dual_judge_stats = {}
        wilson_ci = (0.0, 0.0)
        orchestration_log = [{"phase": "recon", "decision": "target_created"}]

    ctx = MockCtx()
    validator = DataFlowValidator(ctx)

    # Recon 阶段快照
    validator.snapshot("post_recon", {"demo": True})

    # 模拟 ARM 输出
    ctx.seeds = [{"value": "seed1"}, {"value": "seed2"}, {"value": "seed3"}]
    ctx.techniques = ["prompt_sending", "skeleton_key", "role_play"]
    ctx.converter_map = {
        "prompt_sending": ["conv_baseline"],
        "skeleton_key": ["conv_base64"],
        "role_play": ["conv_fewshot"],
    }
    ctx.orchestration_log.append({"phase": "arm", "decision": "seeds_ranked"})
    validator.snapshot("post_arm")

    # 模拟 Strike 输出
    ctx.attack_results = {
        "prompt_sending": [object(), object(), object()],
        "skeleton_key": [object(), object()],
        "role_play": [object(), object(), object()],
    }
    ctx.orchestration_log.append({"phase": "strike", "decision": "attacks_completed"})
    validator.snapshot("post_strike")

    # 模拟 Assess 输出
    ctx.asr_per_technique = {"prompt_sending": 33.3, "skeleton_key": 50.0, "role_play": 33.3}
    ctx.overall_asr = 38.9
    ctx.dual_judge_stats = {"total_scored": 24, "agreements": 20, "disagreements": 4, "cohens_kappa": 0.78}
    ctx.wilson_ci = (0.28, 0.52)
    ctx.orchestration_log.append({"phase": "assess", "decision": "asr_computed"})
    validator.snapshot("post_assess")

    # 模拟 Report/Evidence 输出
    ctx.evidence_collection = type(
        "Evidence",
        (),
        {
            "total_attacks": 8,
            "successful_attacks": 3,
            "findings": [{"title": "Prompt Injection"}, {"title": "Role Play Bypass"}],
            "owasp_llm_compliance": {"LLM01": {"tested": 8, "success": 3}},
        },
    )()
    ctx.orchestration_log.append({"phase": "report", "decision": "report_generated"})
    validator.snapshot("post_report")

    return validator.validate_all()


def main():
    """命令行入口: 审计 orchestration_log 中的数据流"""
    import argparse

    parser = argparse.ArgumentParser(description="Recon → ARM → Strike → Assess → Report/Evidence 数据流验证器")
    parser.add_argument("--log-file", type=str, help="orchestration_log JSON 文件路径")
    parser.add_argument("--output", type=str, help="输出报告文件路径")
    parser.add_argument("--format", choices=["text", "json"], default="text", help="输出格式")
    args = parser.parse_args()

    if args.log_file:
        # 从文件审计
        log_path = Path(args.log_file)
        if not log_path.exists():
            print(f"错误: 文件不存在 {log_path}")
            return

        data = json.loads(log_path.read_text(encoding="utf-8"))
        report = audit_from_log(data)
    else:
        # 演示模式: 运行模拟验证
        print("运行演示模式 (--log-file 参数可审计实际运行日志)")
        print()
        report = demo_validation()

    # 输出报告
    if args.format == "text":
        # 检测是否在需要 ASCII 的环境 (如 Windows 终端)
        try:
            output = format_report(report, ascii_only=False)
            output.encode("gbk")
        except (UnicodeEncodeError, LookupError):
            output = format_report(report, ascii_only=True)
    else:
        output = report_to_json(report)

    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
        print(f"报告已保存: {args.output}")
    else:
        # 处理 Windows 终端编码问题
        try:
            print(output)
        except UnicodeEncodeError:
            # 编码回退: 替换无法编码的字符
            safe_output = output.encode("ascii", errors="replace").decode("ascii")
            print(safe_output)


if __name__ == "__main__":
    main()
