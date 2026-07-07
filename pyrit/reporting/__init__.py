"""
===============================================================================
OffSec AI-300 — 结果分析与报告生成（reporting 包）
===============================================================================
模块化后的公共 API，保持与旧 reporter.py 完全兼容。

结构:
  reporting/data.py        — 用例分类 + PROBE 后续攻击映射（纯数据）
  reporting/engine.py      — 后续攻击推荐引擎（纯逻辑，DRY）
  reporting/heatmap.py     — 热力图可视化（依赖 seaborn/matplotlib）
  reporting/terminal.py    — 终端 Rich 战报
  reporting/exam.py        — Markdown 考试漏洞报告

使用方式:
  from reporting import analyze_and_visualize, print_detailed_report, generate_exam_report
===============================================================================
"""
from reporting.terminal import print_detailed_report
from reporting.exam import generate_exam_report

__all__ = [
    "analyze_and_visualize",
    "print_detailed_report",
    "generate_exam_report",
]


def analyze_and_visualize(all_results, report_title, output_filename):
    """生成热力图分析报告（惰性导入，仅在调用时加载 seaborn/matplotlib）。"""
    from reporting.heatmap import analyze_and_visualize as _impl
    return _impl(all_results, report_title, output_filename)
