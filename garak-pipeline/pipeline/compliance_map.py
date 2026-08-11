"""合规框架映射 — OWASP LLM Top10 → 国际合规标准

将 garak 扫描结果映射到：
  1. GDPR（EU 通用数据保护条例）
  2. ISO 27001（信息安全管理体系）
  3. NIST AI RMF（AI 风险管理框架）
  4. EU AI Act（欧盟 AI 法案）

产物: outputs/05_export/compliance_{run_id}.json
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# OWASP LLM Top10 → 合规框架映射表
OWASP_TO_COMPLIANCE: dict[str, dict[str, list[str]]] = {
    "LLM01_Prompt_Injection": {
        "GDPR": ["Art.22（自动化决策安全）", "Art.32（安全处理）"],
        "ISO27001": ["A.5.7（威胁情报）", "A.8.28（安全编码）"],
        "NIST_AI_RMF": ["MS-1.1（输入完整性）", "MS-2.2（鲁棒性）"],
        "EU_AI_ACT": ["Art.15（准确性/鲁棒性）", "Art.27（高风险 AI 透明度）"],
    },
    "LLM02_Insecure_Output_Handling": {
        "GDPR": ["Art.32（安全处理）", "Art.25（数据保护设计）"],
        "ISO27001": ["A.8.28（安全编码）", "A.8.29（安全测试）"],
        "NIST_AI_RMF": ["MS-3.1（输出验证）", "MS-3.2（安全部署）"],
        "EU_AI_ACT": ["Art.15（准确性/鲁棒性）", "Art.16（运营者义务）"],
    },
    "LLM03_Training_Data_Poisoning": {
        "GDPR": ["Art.5（数据质量原则）", "Art.25（数据保护设计）"],
        "ISO27001": ["A.5.20（数据安全）", "A.5.32（供应链安全）"],
        "NIST_AI_RMF": ["MD-1.1（数据来源验证）", "MD-2.1（数据完整性）"],
        "EU_AI_ACT": ["Art.10（数据治理）", "Art.15（准确性/鲁棒性）"],
    },
    "LLM04_Model_Denial_of_Service": {
        "GDPR": ["Art.32（安全处理）"],
        "ISO27001": ["A.8.6（容量管理）", "A.8.7（防恶意软件）"],
        "NIST_AI_RMF": ["MS-2.3（弹性）", "MS-2.4（可用性）"],
        "EU_AI_ACT": ["Art.15（准确性/鲁棒性）"],
    },
    "LLM05_Supply_Chain_Vulnerabilities": {
        "GDPR": ["Art.28（数据处理者）", "Art.32（安全处理）"],
        "ISO27001": ["A.5.19（供应商关系）", "A.5.32（供应链安全）"],
        "NIST_AI_RMF": ["MS-4.1（第三方组件验证）", "MS-4.2（供应链风险管理）"],
        "EU_AI_ACT": ["Art.16（运营者义务）", "Art.25（高风险 AI 记录）"],
    },
    "LLM06_Sensitive_Information_Disclosure": {
        "GDPR": ["Art.5（数据处理原则）", "Art.32（安全处理）", "Art.33（数据泄露通知）"],
        "ISO27001": ["A.5.12（信息分类）", "A.5.34（隐私保护）", "A.8.11（数据脱敏）"],
        "NIST_AI_RMF": ["MD-3.1（隐私增强）", "MS-3.3（信息泄露防护）"],
        "EU_AI_ACT": ["Art.10（数据治理）", "Art.13（透明度义务）", "Art.26（高风险 AI 监督）"],
    },
    "LLM07_Insecure_Plugin_Design": {
        "GDPR": ["Art.25（数据保护设计）", "Art.32（安全处理）"],
        "ISO27001": ["A.5.19（供应商关系）", "A.8.28（安全编码）"],
        "NIST_AI_RMF": ["MS-4.1（第三方组件验证）", "MS-4.3（接口安全）"],
        "EU_AI_ACT": ["Art.16（运营者义务）", "Art.27（高风险 AI 透明度）"],
    },
    "LLM08_Vector_Embedding_Weaknesses": {
        "GDPR": ["Art.5（数据质量原则）", "Art.25（数据保护设计）"],
        "ISO27001": ["A.5.12（信息分类）", "A.8.11（数据脱敏）"],
        "NIST_AI_RMF": ["MD-2.1（数据完整性）", "MD-3.1（隐私增强）"],
        "EU_AI_ACT": ["Art.10（数据治理）"],
    },
    "LLM09_Misinformation": {
        "GDPR": ["Art.5（数据质量原则）"],
        "ISO27001": ["A.5.12（信息分类）"],
        "NIST_AI_RMF": ["MS-1.2（输出可靠性）", "MS-2.5（幻觉控制）"],
        "EU_AI_ACT": ["Art.13（透明度义务）", "Art.50（深度合成标注）"],
    },
    "LLM10_Unbounded_Consumption": {
        "GDPR": ["Art.32（安全处理）"],
        "ISO27001": ["A.8.6（容量管理）"],
        "NIST_AI_RMF": ["MS-2.3（弹性）", "MS-2.4（可用性）"],
        "EU_AI_ACT": ["Art.15（准确性/鲁棒性）"],
    },
}

# 合规框架名称
COMPLIANCE_FRAMEWORKS = {
    "GDPR": "EU 通用数据保护条例",
    "ISO27001": "ISO/IEC 27001:2022 信息安全管理体系",
    "NIST_AI_RMF": "NIST AI 风险管理框架 1.0",
    "EU_AI_ACT": "欧盟 AI 法案",
}


def generate_compliance_report(
    analysis: dict[str, Any],
    run_id: str,
    artifacts_dir: str = "outputs",
) -> dict[str, Any]:
    """从 Stage4 分析结果生成合规映射报告

    :param analysis: Stage4 的 analysis_{run_id}.json 内容
    :param run_id: 运行标识
    :param artifacts_dir: 产物根目录
    :returns: 合规报告 dict
    """
    owasp_llm = analysis.get("owasp_llm", {})
    overall = analysis.get("overall", {})

    # 遍历 OWASP 类，映射到合规框架
    framework_findings: dict[str, list[dict]] = {
        fw: [] for fw in COMPLIANCE_FRAMEWORKS
    }

    for owasp_cat, cat_data in owasp_llm.items():
        if not isinstance(cat_data, dict):
            continue
        asr = cat_data.get("worst_asr", 0)
        defcon = cat_data.get("defcon", 5)
        # 仅映射有风险的类（ASR > 0 或 DEFCON <= 3）
        if asr == 0 and defcon > 3:
            continue

        compliance_map = OWASP_TO_COMPLIANCE.get(owasp_cat, {})
        for fw, clauses in compliance_map.items():
            framework_findings[fw].append({
                "owasp_category": owasp_cat,
                "asr": asr,
                "defcon": defcon,
                "clauses": clauses,
                "status": "fail" if defcon <= 2 else "warn" if defcon <= 3 else "pass",
            })

    # 按框架生成合规检查清单
    compliance_checklist: dict[str, dict[str, Any]] = {}
    for fw, findings in framework_findings.items():
        failed = sum(1 for f in findings if f["status"] == "fail")
        warned = sum(1 for f in findings if f["status"] == "warn")
        passed = len(COMPLIANCE_FRAMEWORKS) - failed - warned

        compliance_checklist[fw] = {
            "framework_name": COMPLIANCE_FRAMEWORKS[fw],
            "total_findings": len(findings),
            "failed": failed,
            "warned": warned,
            "passed": max(0, passed),
            "compliance_score": round(100.0 * max(0, passed) / max(1, len(findings) + passed), 1),
            "findings": findings,
        }

    result = {
        "run_id": run_id,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "target_model": analysis.get("target_model", ""),
        "overall_defcon": overall.get("defcon", "N/A"),
        "worst_asr": overall.get("worst_asr", 0),
        "compliance_checklist": compliance_checklist,
        "summary": {
            "frameworks_assessed": list(COMPLIANCE_FRAMEWORKS.keys()),
            "total_findings": sum(len(f) for f in framework_findings.values()),
            "critical_findings": sum(
                1 for f in framework_findings.values()
                for finding in f if finding["status"] == "fail"
            ),
        },
    }

    # 保存产物
    out_dir = Path(artifacts_dir) / "05_export"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"compliance_{run_id}.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
    result["output_path"] = str(out_path)

    return result
