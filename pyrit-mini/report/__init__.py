"""report — 

 6 : ,  evidence JSON + PoC  + Markdown/HTML 

Core modules:
    - evidence:  (VulnerabilityEvidence + EvidenceCollection)
    - generator:  (MD + HTML + JSON + PoC + CSV + ZIP + SARIF)
    - pyrit_native_output: PyRIT  output Layer ( pretty + markdown)
    - owasp_constants: OWASP  + MITRE ATLAS 
    - owasp_mapping: OWASP ID  + 
    - poc_generator: PyRIT  PoC 
    - report_markdown: Markdown 
    - report_html: HTML 
    - sarif_report: SARIF 2.1 
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
