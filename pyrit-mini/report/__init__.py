"""report — Evidence collection, report generation, and PoC output.

Core modules:
    - evidence: VulnerabilityEvidence + EvidenceCollection data classes
    - generator: Multi-format report generation (MD + HTML + JSON + PoC + CSV + ZIP + SARIF)
    - pyrit_native_output: PyRIT native output adapter (pretty + markdown)
    - owasp_constants: OWASP categories + MITRE ATLAS mappings
    - owasp_mapping: OWASP ID mapping + CVSS scoring
    - poc_generator: PyRIT native PoC script generation
    - report_markdown: Markdown report builder
    - report_html: HTML report builder (pure Python, no Jinja2)
    - sarif_report: SARIF 2.1 output for CI/CD integration
    - evidence_extract: Evidence field extraction from PyRIT AttackResult
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
