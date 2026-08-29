"""report — 结果输出和证据收集阶段。

攻击链路第 6 步: 收集证据, 生成 evidence JSON + PoC 脚本 + Markdown/HTML 报告。

核心模块:
    - evidence: 证据收集 (VulnerabilityEvidence + EvidenceCollection)
    - generator: 报告生成协调器 (MD + HTML + JSON + PoC + CSV + ZIP + SARIF)
    - pyrit_native_output: PyRIT 官方 output 适配层 (原生 pretty + markdown)
    - owasp_constants: OWASP 标准常量 + MITRE ATLAS 映射
    - owasp_mapping: OWASP ID 映射 + 严重性计算
    - poc_generator: PyRIT 原生 PoC 脚本生成
    - report_markdown: Markdown 报告生成
    - report_html: HTML 报告生成
    - sarif_report: SARIF 2.1 格式报告
"""

from report.evidence import EvidenceCollection, EvidenceCollector
from report.generator import generate_report
from report.pyrit_native_output import generate_native_output_files

__all__ = [
    "EvidenceCollection",
    "EvidenceCollector",
    "generate_report",
    "generate_native_output_files",
]
