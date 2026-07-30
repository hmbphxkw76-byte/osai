"""
Reporting Module
=================

本模块负责报告层，包括报告生成、OWASP 映射、证据导出、统一输出管理。

L5 对齐 PyRIT 1.0.0 output 模块：
- re-export PyRIT 原生 output 公共 API（Sink/Printer/便捷函数）
- OutputManager 集成 output_scenario_async / output_scorer_async
- EvidenceExporter 使用 render_async() 替代 write_async()+read-back
"""

from src.reporting.report_generator import (
    OWASPMapper,
    EvidenceExporter,
    ReportGenerator,
    generate_report,
    map_attacks_to_owasp,
)
from src.reporting.output_manager import (
    OutputManager,
    ProgressDashboard,
    SummaryTable,
)
from src.reporting.format_converter import (
    convert_markdown_to_html,
    convert_markdown_to_pdf,
    convert_report_formats,
    check_pdf_engine_available,
)
from src.reporting.diversity_analyzer import (
    DiversityAnalyzer,
    DiversityAnalysisResult,
    calculate_shannon_entropy,
    calculate_normalized_entropy,
    render_diversity_section,
)
from src.reporting.converter_log import (
    ConverterTransformationLog,
    ConverterVariantPreview,
    TECHNIQUE_NAME_MAP,
    extract_converter_info_from_result,
    format_technique_display,
    generate_converter_log_for_result,
    generate_variant_preview_for_technique,
    get_attack_class_name,
    get_technique_name,
    render_transformation_log_markdown,
    render_variant_preview_markdown,
)

# Re-export PyRIT 原生 output 公共 API（便于上层统一导入）
from pyrit.output import (
    FileSink,
    IPythonMarkdownSink,
    OutputFormat,
    PrinterBase,
    Sink,
    StdoutSink,
    get_default_sink,
    output_attack_async,
    output_conversation_async,
    output_scenario_async,
    output_score_async,
    output_scorer_async,
)

__all__ = [
    # 报告生成
    "OWASPMapper",
    "EvidenceExporter",
    "ReportGenerator",
    "generate_report",
    "map_attacks_to_owasp",
    # 输出管理
    "OutputManager",
    "ProgressDashboard",
    "SummaryTable",
    # 格式转换
    "convert_markdown_to_html",
    "convert_markdown_to_pdf",
    "convert_report_formats",
    "check_pdf_engine_available",
    # 多样性分析
    "DiversityAnalyzer",
    "DiversityAnalysisResult",
    "calculate_shannon_entropy",
    "calculate_normalized_entropy",
    "render_diversity_section",
    # Converter 转换日志 & 变体预览
    "ConverterTransformationLog",
    "ConverterVariantPreview",
    "TECHNIQUE_NAME_MAP",
    "extract_converter_info_from_result",
    "format_technique_display",
    "generate_converter_log_for_result",
    "generate_variant_preview_for_technique",
    "get_attack_class_name",
    "get_technique_name",
    "render_transformation_log_markdown",
    "render_variant_preview_markdown",
    # PyRIT 原生 output 公共 API（re-export）
    "FileSink",
    "IPythonMarkdownSink",
    "OutputFormat",
    "PrinterBase",
    "Sink",
    "StdoutSink",
    "get_default_sink",
    "output_attack_async",
    "output_conversation_async",
    "output_scenario_async",
    "output_score_async",
    "output_scorer_async",
]
