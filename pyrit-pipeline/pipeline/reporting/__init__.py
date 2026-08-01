# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""
Reporting Module
=================

本模块负责报告层，包括报告生成、OWASP 映射、格式转换、双通道输出。

L5 对齐 PyRIT 原生 output 模块:
  - re-export PyRIT 原生 output 公共 API (Sink/Printer/便捷函数)
  - ReportGenerator 集成 output_scenario_async / output_scorer_async
  - 格式转换: Markdown → HTML → PDF (weasyprint / xhtml2pdf)
  - 双通道输出: StdoutSink + FileSink

统一入口:
    from pipeline.reporting import generate_report, OWASPMapper
"""

# 报告生成
from pipeline.reporting.report_generator import (
    OWASPFinding,
    OWASPMapper,
    ReportGenerator,
    ReportResult,
    generate_report,
    map_attacks_to_owasp,
)

# 证据导出
from pipeline.reporting.evidence_exporter import (
    EvidenceExporter,
)

# OWASP 数据
from pipeline.reporting.owasp_data import (
    ALL_OWASP_DETAILS,
    OWASP_ASI_DETAILS,
    OWASP_LLM_DETAILS,
    get_all_owasp_standards,
    get_owasp_details,
)

# 格式转换
from pipeline.reporting.format_converter import (
    check_pdf_engine_available,
    convert_markdown_to_html,
    convert_markdown_to_pdf,
    convert_report_formats,
)

# 双通道输出 + 目录结构管理
from pipeline.reporting.output_manager import (
    DualOutputManager,
    OutputManager,
    ProgressDashboard,
    SummaryTable,
)

# Re-export PyRIT 原生 output 公共 API (便于上层统一导入)
try:
    from pyrit.output import (
        FileSink,
        OutputFormat,
        Sink,
        StdoutSink,
        get_default_sink,
        output_attack_async,
        output_conversation_async,
        output_scenario_async,
        output_score_async,
        output_scorer_async,
    )
except ImportError:
    pass

__all__ = [
    # 报告生成
    "OWASPFinding",
    "OWASPMapper",
    "ReportGenerator",
    "ReportResult",
    "generate_report",
    "map_attacks_to_owasp",
    # 证据导出
    "EvidenceExporter",
    # OWASP 数据
    "ALL_OWASP_DETAILS",
    "OWASP_ASI_DETAILS",
    "OWASP_LLM_DETAILS",
    "get_all_owasp_standards",
    "get_owasp_details",
    # 格式转换
    "check_pdf_engine_available",
    "convert_markdown_to_html",
    "convert_markdown_to_pdf",
    "convert_report_formats",
    # 双通道输出 + 目录结构管理
    "DualOutputManager",
    "OutputManager",
    "ProgressDashboard",
    "SummaryTable",
    # PyRIT 原生 output (re-export)
    "FileSink",
    "OutputFormat",
    "Sink",
    "StdoutSink",
    "get_default_sink",
    "output_attack_async",
    "output_conversation_async",
    "output_scenario_async",
    "output_score_async",
    "output_scorer_async",
]
