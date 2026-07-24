"""
Reporting Module
=================

本模块负责报告层，包括报告生成、OWASP 映射、证据导出。
"""

from src.reporting.report_generator import (
    OWASPMapper,
    EvidenceExporter,
    ReportGenerator,
    generate_report,
    map_attacks_to_owasp,
)

__all__ = [
    "OWASPMapper",
    "EvidenceExporter",
    "ReportGenerator",
    "generate_report",
    "map_attacks_to_owasp",
]