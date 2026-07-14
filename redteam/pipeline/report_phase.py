"""威胁建模与报告模块 (AI-300 Ch10+Ch11)。

注意：报告生成已重构为增量写入模式。各阶段攻击/侦察结果通过
ReportWriter (report_writer.py) 追加到 reports/{run_id}/AI300_Report.md，
最终由 Phase 2（未来）从此 .md 提取内容制作 OffSec AI-300 考试风格报告。

原有 report_phase() 单次报告生成函数已移除。
"""
