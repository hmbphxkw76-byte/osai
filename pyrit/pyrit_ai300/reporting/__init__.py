"""
AI-300 Framework - Reporting Module
报告生成模块：生成执行报告和最终评估报告
"""

from .report_generator import ReportGenerator
from .execution_report import ExecutionReportGenerator
from .cvss_calculator import CVSSCalculator, calculate_cvss, CVSSResult, CVSSVector
from .atlas_mapper import ATLASMapper, ATLASMapping
from .attack_chain_graph import AttackChainGenerator, generate_mermaid_chain
from .remediation_roi import ROICalculator, RemediationSuggestion, calculate_roi_and_rank

__all__ = [
    "ReportGenerator",
    "ExecutionReportGenerator",
    # REV-6: CVSS 3.1 Calculator
    "CVSSCalculator",
    "calculate_cvss",
    "CVSSResult",
    "CVSSVector",
    # REV-7: MITRE ATLAS Mapper
    "ATLASMapper",
    "ATLASMapping",
    # REV-8: Attack Chain Graph
    "AttackChainGenerator",
    "generate_mermaid_chain",
    # REV-10: Remediation ROI Calculator
    "ROICalculator",
    "RemediationSuggestion",
    "calculate_roi_and_rank",
]
