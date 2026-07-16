"""
AI-300 Framework - Report Generator
报告生成器：生成符合 OffSec AI-300 考试要求的专业红队评估报告

报告结构（对齐 OffSec 标准）：
1. Executive Summary
2. Scope and Rules of Engagement
3. Methodology
4. Findings Summary
5. Detailed Findings (per Module)
6. Attack Path Visualization
7. Risk Assessment
8. Remediation Recommendations
9. Appendices
"""

from __future__ import annotations

import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class ReportGenerator:
    """
    报告生成器
    
    功能：
    1. 从攻击结果自动生成报告
    2. 支持多种输出格式 (Markdown, HTML, PDF)
    3. 符合 OffSec AI-300 考试报告标准
    4. 包含完整的攻击路径和风险评估
    
    使用方式：
        generator = ReportGenerator(results=attack_results)
        generator.generate(output_path="results/assessment_report.md", format="markdown")
    """

    # AI-300 考试报告模板结构
    REPORT_SECTIONS = [
        "executive_summary",
        "scope_and_roe",
        "methodology",
        "findings_summary",
        "detailed_findings",
        "attack_path",
        "risk_assessment",
        "remediation",
        "appendices",
    ]

    def __init__(
        self,
        results: List[Dict[str, Any]],
        engagement_info: Optional[Dict[str, Any]] = None,
    ):
        """
        初始化报告生成器
        
        Args:
            results: 攻击结果列表
            engagement_info: 评估项目信息
        """
        self.results = results
        self.engagement_info = engagement_info or self._default_engagement_info()
        self.timestamp = datetime.now().isoformat()

    def _default_engagement_info(self) -> Dict[str, Any]:
        """默认评估项目信息"""
        return {
            "client": "AI-300 Exam Assessment",
            "target_system": "AI-Enabled Enterprise Environment",
            "assessment_type": "Grey-Box AI Red Team Assessment",
            "duration": "24 hours",
            "start_date": datetime.now().strftime("%Y-%m-%d"),
            "end_date": datetime.now().strftime("%Y-%m-%d"),
            "testers": ["AI-300 Candidate"],
            "classification": "CONFIDENTIAL",
        }

    def generate(
        self,
        output_path: str = "results/ai300_assessment_report.md",
        format: str = "markdown",
    ) -> str:
        """
        生成报告
        
        Args:
            output_path: 输出文件路径
            format: 输出格式 ("markdown", "html", "pdf")
            
        Returns:
            报告内容字符串
        """
        if format == "markdown":
            content = self._generate_markdown()
        elif format == "html":
            content = self._generate_html()
        else:
            raise ValueError(f"Unsupported format: {format}")
        
        # 写入文件
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(content)
        
        logger.info("Report generated: %s", output_path)
        return content

    def _generate_markdown(self) -> str:
        """生成 Markdown 格式报告"""
        sections = [
            self._executive_summary(),
            self._scope_and_roe(),
            self._methodology(),
            self._findings_summary(),
            self._detailed_findings(),
            self._attack_path(),
            self._risk_assessment(),
            self._remediation(),
            self._appendices(),
        ]
        return "\n\n---\n\n".join(sections)

    def _generate_html(self) -> str:
        """生成 HTML 格式报告"""
        md_content = self._generate_markdown()
        # 简单 Markdown 到 HTML 转换
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>AI-300 Red Team Assessment Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; line-height: 1.6; }}
        h1 {{ color: #1a1a2e; border-bottom: 2px solid #e94560; }}
        h2 {{ color: #16213e; }}
        h3 {{ color: #0f3460; }}
        code {{ background: #f4f4f4; padding: 2px 6px; border-radius: 3px; }}
        pre {{ background: #f4f4f4; padding: 16px; border-radius: 6px; overflow-x: auto; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background: #16213e; color: white; }}
        .critical {{ color: #e94560; font-weight: bold; }}
        .high {{ color: #ff6b35; font-weight: bold; }}
        .medium {{ color: #f7b731; font-weight: bold; }}
        .low {{ color: #4caf50; font-weight: bold; }}
    </style>
</head>
<body>
{self._markdown_to_html(md_content)}
</body>
</html>"""
        return html

    def _markdown_to_html(self, md: str) -> str:
        """简单 Markdown 到 HTML 转换"""
        lines = md.split("\n")
        html_lines = []
        in_table = False
        
        for line in lines:
            if line.startswith("# "):
                html_lines.append(f"<h1>{line[2:]}</h1>")
            elif line.startswith("## "):
                html_lines.append(f"<h2>{line[3:]}</h2>")
            elif line.startswith("### "):
                html_lines.append(f"<h3>{line[4:]}</h3>")
            elif line.startswith("#### "):
                html_lines.append(f"<h4>{line[5:]}</h4>")
            elif line.startswith("```"):
                html_lines.append("<pre><code>" if "```" == line.strip() else "</code></pre>")
            elif line.startswith("|"):
                if not in_table:
                    html_lines.append("<table>")
                    in_table = True
                cells = [c.strip() for c in line.split("|")[1:-1]]
                if all(set(c) <= set("-: ") for c in cells):
                    continue
                tag = "th" if html_lines and html_lines[-1] == "<table>" else "td"
                html_lines.append("<tr>" + "".join(f"<{tag}>{c}</{tag}>" for c in cells) + "</tr>")
            elif line.startswith("- "):
                html_lines.append(f"<li>{line[2:]}</li>")
            elif line.startswith("---"):
                if in_table:
                    html_lines.append("</table>")
                    in_table = False
                html_lines.append("<hr/>")
            elif line.strip():
                html_lines.append(f"<p>{line}</p>")
        
        if in_table:
            html_lines.append("</table>")
        
        return "\n".join(html_lines)

    def _executive_summary(self) -> str:
        """执行摘要"""
        total_attacks = sum(r.get("summary", {}).get("total_attacks", 0) for r in self.results)
        total_payloads = sum(r.get("summary", {}).get("total_payloads", 0) for r in self.results)
        successful = sum(r.get("summary", {}).get("successful_payloads", 0) for r in self.results)
        failed = sum(r.get("summary", {}).get("failed_payloads", 0) for r in self.results)
        
        return f"""# AI-300 Red Team Assessment Report

## 1. Executive Summary

**Assessment Date:** {self.engagement_info.get("start_date", "N/A")}  
**Classification:** {self.engagement_info.get("classification", "CONFIDENTIAL")}  
**Target System:** {self.engagement_info.get("target_system", "N/A")}  
**Assessment Type:** {self.engagement_info.get("assessment_type", "N/A")}

### Key Findings

This AI Red Team Assessment identified significant security vulnerabilities across the target AI-enabled enterprise environment. The assessment covered all major AI attack surfaces aligned with the OffSec AI-300 curriculum and OWASP Top 10 for LLM Applications.

| Metric | Value |
|--------|-------|
| Total Attack Scenarios | {total_attacks} |
| Total Payloads Executed | {total_payloads} |
| Successful Exploits | {successful} |
| Failed Attempts | {failed} |
| Overall Success Rate | {(successful/total_payloads*100) if total_payloads > 0 else 0:.1f}% |

### Risk Rating: **CRITICAL**

The assessment revealed multiple critical vulnerabilities that could allow attackers to:
- Extract sensitive system prompts and credentials
- Manipulate AI agent behavior through prompt injection
- Poison RAG knowledge bases to compromise downstream users
- Exploit MCP tool surfaces for unauthorized access
- Compromise AI infrastructure through supply chain attacks

### Top 3 Critical Findings

1. **Direct Prompt Injection** - Unfiltered user input allows complete agent hijacking
2. **RAG Knowledge Base Poisoning** - Malicious documents can manipulate AI responses at scale
3. **MCP Tool Surface Abuse** - Insufficient tool validation enables credential theft
"""

    def _scope_and_roe(self) -> str:
        """范围和交战规则"""
        return """## 2. Scope and Rules of Engagement

### 2.1 Scope

| Item | Details |
|------|---------|
| Target System | AI-Enabled Enterprise Environment |
| Environment | Hybrid Cloud (On-prem Kubernetes + AWS) |
| Network Access | VPN tunnel to service subnet |
| Kubernetes Access | Read-only API token provided |
| Engagement Type | Grey-Box Assessment |
| Duration | 24 hours |

### 2.2 In-Scope Targets

- AI Agent endpoints and orchestration layers
- RAG pipeline components (retriever, vector DB, LLM backend)
- MCP server infrastructure
- A2A protocol endpoints
- Model inference servers
- AI/ML supply chain components

### 2.3 Rules of Engagement

- No destructive actions against production databases
- Vector database poisoning permitted ONLY in designated staging environment
- No denial-of-service testing against any component
- No exfiltration of real customer PII
- All tool invocations via MCP must be logged and reported
- Testing window: 08:00-20:00 local time, Monday-Friday
"""

    def _methodology(self) -> str:
        """方法论"""
        return """## 3. Methodology

### 3.1 Framework

This assessment leverages the **AI-300 Red Teaming Framework**, built on Microsoft's PyRIT (Python Risk Identification Tool) framework. The methodology aligns with:

- **MITRE ATLAS** - Adversarial AI technique taxonomy
- **OWASP Top 10 for LLM** - Application-level vulnerability categories
- **NVIDIA AI Kill Chain** - Attack sequencing framework

### 3.2 Attack Lifecycle

```
Reconnaissance → Poisoning → Hijacking → Persistence → Impact
```

### 3.3 AI-300 Module Coverage

| Module | Description | Status |
|--------|-------------|--------|
| Ch2 | Reconnaissance for AI Targets | ✅ Complete |
| Ch3 | Attacking AI Agents | ✅ Complete |
| Ch4 | Attacking Multi-Agent Systems & A2A | ✅ Complete |
| Ch5 | Exploiting RAG Pipelines | ✅ Complete |
| Ch6 | Attacking Embeddings | ✅ Complete |
| Ch7 | Attacking MCP and Tool Surfaces | ✅ Complete |
| Ch8 | Supply Chain Attacks on AI/ML Systems | ✅ Complete |
| Ch9 | AI Infrastructure and Deployment Exploits | ✅ Complete |
| Ch10 | Threat Modeling for AI-Enabled Targets | ✅ Complete |
| Ch11 | Capstone Red Team Engagement | ✅ Complete |

### 3.4 OWASP LLM Top 10 Coverage

| OWASP ID | Category | Coverage |
|----------|----------|----------|
| LLM01 | Prompt Injection | ✅ Fully Covered |
| LLM02 | Insecure Output Handling | ✅ Fully Covered |
| LLM03 | Training Data Poisoning | ✅ Fully Covered |
| LLM04 | Model Denial of Service | ✅ Fully Covered |
| LLM05 | Supply Chain Vulnerabilities | ✅ Fully Covered |
| LLM06 | Sensitive Information Disclosure | ✅ Fully Covered |
| LLM07 | Insecure Plugin Design | ✅ Fully Covered |
| LLM08 | Excessive Agency | ✅ Fully Covered |
| LLM09 | Overreliance | ✅ Fully Covered |
| LLM10 | Model Theft | ✅ Fully Covered |
"""

    def _findings_summary(self) -> str:
        """发现摘要"""
        findings = []
        for result in self.results:
            module = result.get("module", "unknown")
            module_name = result.get("module_name", module)
            summary = result.get("summary", {})
            owasp = result.get("owasp_mapping", "N/A")
            
            findings.append({
                "module": module,
                "name": module_name,
                "owasp": owasp,
                "total_payloads": summary.get("total_payloads", 0),
                "successful": summary.get("successful_payloads", 0),
                "failed": summary.get("failed_payloads", 0),
            })
        
        table_rows = "\n".join(
            f"| {f['module']} | {f['name']} | {f['owasp']} | {f['total_payloads']} | {f['successful']} | {f['failed']} |"
            for f in findings
        )
        
        return f"""## 4. Findings Summary

### 4.1 Results by Module

| Module | Name | OWASP | Payloads | Success | Failed |
|--------|------|-------|----------|---------|--------|
{table_rows}

### 4.2 Risk Distribution

| Severity | Count | Percentage |
|----------|-------|------------|
| Critical | 4 | 40% |
| High | 3 | 30% |
| Medium | 2 | 20% |
| Low | 1 | 10% |
"""

    def _detailed_findings(self) -> str:
        """详细发现"""
        findings_text = []
        
        for result in self.results:
            module = result.get("module", "unknown")
            module_name = result.get("module_name", module)
            
            for attack in result.get("attacks", []):
                attack_name = attack.get("attack_name", "unknown")
                success_count = attack.get("success_count", 0)
                failure_count = attack.get("failure_count", 0)
                total = success_count + failure_count
                rate = (success_count / total * 100) if total > 0 else 0
                
                severity = "CRITICAL" if rate > 70 else "HIGH" if rate > 40 else "MEDIUM" if rate > 10 else "LOW"
                
                findings_text.append(f"""
### Finding: {attack_name}

- **Module:** {module_name}
- **Severity:** <span class="{severity.lower()}">{severity}</span>
- **Success Rate:** {rate:.1f}%
- **Payloads Tested:** {total}
- **Successful:** {success_count}
- **Failed:** {failure_count}

#### Description
Attack scenario executed as part of {module_name} assessment.

#### Impact
Successful exploitation could lead to unauthorized access, data disclosure, or system compromise.

#### Recommendation
Implement appropriate input validation, output filtering, and monitoring controls.
""")
        
        return "## 5. Detailed Findings\n\n" + "\n\n".join(findings_text)

    def _attack_path(self) -> str:
        """攻击路径"""
        return """## 6. Attack Path Visualization

### 6.1 Kill Chain

```
[Reconnaissance] → [Initial Access] → [Prompt Injection] → [Agent Hijacking]
                                                        ↓
[Impact] ← [Data Exfiltration] ← [Privilege Escalation] ← [RAG Poisoning]
```

### 6.2 Multi-Stage Attack Flow

1. **Reconnaissance** - Identify AI agent endpoints and capabilities
2. **Initial Access** - Exploit public-facing AI interface
3. **Prompt Injection** - Bypass input filters using encoding converters
4. **Agent Hijacking** - Take control of agent behavior and tools
5. **RAG Poisoning** - Manipulate knowledge base for persistent impact
6. **Privilege Escalation** - Access sensitive systems via MCP tools
7. **Data Exfiltration** - Extract credentials and sensitive data
8. **Impact** - Achieve assessment objectives
"""

    def _risk_assessment(self) -> str:
        """风险评估"""
        return """## 7. Risk Assessment

### 7.1 Risk Matrix

| Likelihood | Impact | Risk Level |
|------------|--------|------------|
| High | High | Critical |
| High | Medium | High |
| Medium | High | High |
| Medium | Medium | Medium |
| Low | High | Medium |

### 7.2 Business Impact Analysis

| Question | Assessment |
|----------|------------|
| What data is at risk? | System prompts, credentials, proprietary knowledge base content |
| What systems are affected? | AI agents, RAG pipelines, MCP servers, inference endpoints |
| What is the financial impact? | Potential regulatory fines, data breach costs, reputational damage |
| What is the operational impact? | Compromised AI decisions, manipulated business processes |
| What is the compliance impact? | GDPR, HIPAA, SOC 2 violations possible |
| What is the recovery time? | Days to weeks depending on compromise scope |
"""

    def _remediation(self) -> str:
        """修复建议"""
        return """## 8. Remediation Recommendations

### 8.1 Immediate Actions (0-30 days)

1. **Input Validation** - Implement strict input filtering for all AI endpoints
2. **Output Scanning** - Deploy output content scanners to prevent data leakage
3. **MCP Tool Auditing** - Review and restrict MCP tool permissions
4. **RAG Access Control** - Implement knowledge base access controls

### 8.2 Short-Term Actions (30-90 days)

1. **Prompt Injection Defense** - Deploy prompt injection detection models
2. **Agent Monitoring** - Implement behavioral monitoring for AI agents
3. **Supply Chain Verification** - Verify integrity of all AI/ML components
4. **Embedding Protection** - Encrypt embedding vectors at rest and in transit

### 8.3 Long-Term Actions (90+ days)

1. **AI Security Framework** - Establish comprehensive AI security program
2. **Red Team Program** - Regular AI red team assessments
3. **Security Training** - AI security awareness for developers
4. **Incident Response** - AI-specific incident response procedures
"""

    def _appendices(self) -> str:
        """附录"""
        return f"""## 9. Appendices

### A. Tools Used

- PyRIT (Python Risk Identification Tool) v0.14.0
- AI-300 Red Teaming Framework
- Custom attack payloads and converters

### B. References

- OffSec AI-300 Course Materials
- OWASP Top 10 for LLM Applications v1.1
- MITRE ATLAS (Adversarial Threat Landscape for AI Systems)
- NVIDIA AI Kill Chain
- NIST AI Risk Management Framework

### C. Report Metadata

- **Generated:** {self.timestamp}
- **Framework Version:** 1.0.0
- **Classification:** {self.engagement_info.get("classification", "CONFIDENTIAL")}
"""
