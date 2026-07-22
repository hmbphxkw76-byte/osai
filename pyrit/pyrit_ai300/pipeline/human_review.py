# -*- coding: utf-8 -*-
"""
AI-300 Framework - Human-in-the-Loop Review (Phase 4.3)
人工审查：高风险发现的人工确认与分类

核心功能：
1. 从攻击结果中筛选高风险发现（Critical/High severity + 成功渗透）
2. 生成审查清单（JSON 格式，可导入审查工具）
3. 支持交互式确认（终端 prompt）和非交互式标记两种模式
4. 将审查结果回写到攻击结果中，供报告阶段使用

设计原则：
- 非阻塞：无人工干预时自动标记为 "pending_review"，不中断流水线
- 可配置：通过 enable_human_review 参数控制是否启用
- 可追溯：所有审查决策记录到 tracker 中
- 轻量化：不引入额外依赖，纯 Python 标准库实现

使用方式：
    # 非交互式（默认）：标记高风险发现，在报告中突出显示
    reviewer = HumanReviewer(interactive=False)
    review_report = reviewer.review(attack_results)

    # 交互式：终端逐条确认
    reviewer = HumanReviewer(interactive=True)
    review_report = reviewer.review(attack_results)
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class HumanReviewer:
    """
    人工审查器

    从攻击结果中提取高风险发现，生成审查清单。
    支持交互式确认和非交互式标记两种模式。
    """

    # 触发人工审查的条件：成功率 >= 此阈值或严重度 >= 此级别
    HIGH_RISK_SUCCESS_RATE = 50.0  # 成功率 >= 50% 的攻击自动标记为高风险
    HIGH_RISK_SEVERITIES = {"critical", "high"}

    def __init__(
        self,
        interactive: bool = False,
        output_dir: str = "results/review",
        auto_threshold: float = 50.0,
    ):
        """
        Args:
            interactive: 是否启用交互式确认（终端 prompt）
            output_dir: 审查清单输出目录
            auto_threshold: 自动标记为高风险的成功率阈值（%）
        """
        self.interactive = interactive
        self.output_dir = Path(output_dir)
        self.auto_threshold = auto_threshold
        self._review_findings: List[Dict[str, Any]] = []

    def review(
        self,
        attack_results: List[Dict[str, Any]],
        tracker: Optional[Any] = None,
    ) -> Dict[str, Any]:
        """
        执行人工审查

        从攻击结果中筛选高风险发现，生成审查清单。
        交互式模式下逐条确认，非交互式模式下自动标记。

        Args:
            attack_results: 攻击结果列表（scope_results 格式）
            tracker: PipelineTracker 实例（可选）

        Returns:
            审查报告字典：
            {
                "total_findings": int,
                "high_risk_findings": List[Dict],
                "reviewed": int,
                "confirmed": int,
                "rejected": int,
                "pending": int,
                "review_file": str,
            }
        """
        # 步骤 1：提取高风险发现
        high_risk = self._extract_high_risk_findings(attack_results)

        # 步骤 2：生成审查清单
        self._review_findings = high_risk

        # 步骤 3：交互式确认或自动标记
        if self.interactive and high_risk:
            self._interactive_review(high_risk)
        else:
            for finding in high_risk:
                finding["review_status"] = "pending_review"
                finding["reviewer"] = "auto"
                finding["review_time"] = datetime.now().isoformat()

        # 步骤 4：保存审查清单
        review_file = self._save_review_report()

        # 步骤 5：生成摘要
        confirmed = sum(1 for f in high_risk if f.get("review_status") == "confirmed")
        rejected = sum(1 for f in high_risk if f.get("review_status") == "rejected")
        pending = sum(1 for f in high_risk if f.get("review_status") == "pending_review")

        report = {
            "total_findings": len(high_risk),
            "high_risk_findings": high_risk,
            "reviewed": confirmed + rejected,
            "confirmed": confirmed,
            "rejected": rejected,
            "pending": pending,
            "review_file": str(review_file),
        }

        if tracker and high_risk:
            tracker.log_execution({
                "payload": f"[HUMAN_REVIEW] {len(high_risk)} high-risk findings identified",
                "status": "review_pending" if pending > 0 else "reviewed",
                "outcome": f"confirmed={confirmed}, rejected={rejected}, pending={pending}",
                "response": f"Review file: {review_file}",
            })

        logger.info(
            "Human review: %d high-risk findings (%d confirmed, %d rejected, %d pending)",
            len(high_risk), confirmed, rejected, pending,
        )

        return report

    def _extract_high_risk_findings(
        self,
        attack_results: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """从攻击结果中提取高风险发现"""
        findings = []

        for scope_result in attack_results:
            scope = scope_result.get("scope", "unknown")
            owasp_ids = scope_result.get("owasp_ids", [])

            for attack in scope_result.get("attacks", []):
                attack_name = attack.get("attack_name", "unknown")
                severity = attack.get("severity", "medium").lower()
                success_count = attack.get("success_count", 0)
                failure_count = attack.get("failure_count", 0)
                total = success_count + failure_count
                rate = (success_count / total * 100) if total > 0 else 0

                # 判断是否为高风险
                is_high_severity = severity in self.HIGH_RISK_SEVERITIES
                is_high_rate = rate >= self.auto_threshold and success_count > 0

                if is_high_severity or is_high_rate:
                    # 提取成功载荷作为证据
                    evidence = []
                    for r in attack.get("results", []):
                        if r.get("status") == "success":
                            evidence.append({
                                "payload": r.get("payload", "")[:200],
                                "response": r.get("response", "")[:200],
                                "attack_class": r.get("attack_class", ""),
                                "attack_family": r.get("attack_family", ""),
                            })
                            if len(evidence) >= 3:
                                break

                    findings.append({
                        "finding_id": f"HR-{len(findings) + 1:03d}",
                        "scope": scope,
                        "owasp_ids": owasp_ids,
                        "attack_name": attack_name,
                        "severity": severity.upper(),
                        "success_rate": round(rate, 1),
                        "total_payloads": total,
                        "successful": success_count,
                        "evidence": evidence,
                        "review_status": "pending_review",
                        "reviewer": "",
                        "review_time": "",
                        "review_notes": "",
                    })

        return findings

    def _interactive_review(self, findings: List[Dict[str, Any]]) -> None:
        """交互式逐条确认"""
        print("\n" + "=" * 60)
        print("  Human-in-the-Loop Review")
        print("  高风险发现人工审查")
        print("=" * 60)
        print(f"  共 {len(findings)} 个高风险发现需要审查")
        print("  操作: [c]onfirm / [r]eject / [s]kip / [q]uit all")
        print("=" * 60 + "\n")

        for i, finding in enumerate(findings):
            print(f"\n--- Finding {i + 1}/{len(findings)} ---")
            print(f"  ID:       {finding['finding_id']}")
            print(f"  Scope:    {finding['scope']}")
            print(f"  OWASP:    {', '.join(finding['owasp_ids'])}")
            print(f"  Attack:   {finding['attack_name']}")
            print(f"  Severity: {finding['severity']}")
            print(f"  ASR:      {finding['success_rate']}% ({finding['successful']}/{finding['total_payloads']})")

            if finding["evidence"]:
                print(f"  Evidence: {finding['evidence'][0]['payload'][:100]}...")

            try:
                choice = input("\n  Decision [c/r/s/q]: ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                choice = "s"

            if choice == "c":
                finding["review_status"] = "confirmed"
                finding["reviewer"] = "human"
                finding["review_time"] = datetime.now().isoformat()
            elif choice == "r":
                finding["review_status"] = "rejected"
                finding["reviewer"] = "human"
                finding["review_time"] = datetime.now().isoformat()
            elif choice == "q":
                # 跳过剩余所有
                for remaining in findings[i:]:
                    remaining["review_status"] = "pending_review"
                    remaining["reviewer"] = "auto"
                    remaining["review_time"] = datetime.now().isoformat()
                break
            else:
                finding["review_status"] = "pending_review"
                finding["reviewer"] = "auto"
                finding["review_time"] = datetime.now().isoformat()

        print("\n" + "=" * 60)
        confirmed = sum(1 for f in findings if f.get("review_status") == "confirmed")
        rejected = sum(1 for f in findings if f.get("review_status") == "rejected")
        pending = sum(1 for f in findings if f.get("review_status") == "pending_review")
        print(f"  Review complete: {confirmed} confirmed, {rejected} rejected, {pending} pending")
        print("=" * 60 + "\n")

    def _save_review_report(self) -> Path:
        """保存审查清单到文件"""
        self.output_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        review_file = self.output_dir / f"human_review_{timestamp}.json"

        report = {
            "generated_at": datetime.now().isoformat(),
            "total_findings": len(self._review_findings),
            "findings": self._review_findings,
        }

        with open(review_file, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=2)

        logger.info("Human review report saved: %s", review_file)
        return review_file

    def get_review_findings(self) -> List[Dict[str, Any]]:
        """获取审查发现列表（供报告阶段使用）"""
        return self._review_findings
