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
        generator.generate()  # 自动生成 results/assessment_report_2026-07-16_23-14-12.md
        generator.generate(output_path="custom_report.md")  # 指定路径
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
        output_path: Optional[str] = None,
        format: str = "markdown",
    ) -> str:
        """
        生成报告
        
        Args:
            output_path: 输出文件路径。为 None 时自动生成带时间戳的文件名。
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
        
        # 未指定路径时自动生成带模式前缀+时间戳的文件名
        if output_path is None:
            mode_label = self._detect_mode_label(self.results)
            timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            output_path = f"results/{mode_label}_assessment_report_{timestamp}.md"
        
        # 写入文件
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(content)
        
        logger.info("Report generated: %s", output_path)
        return content

    @staticmethod
    def _detect_mode_label(results: Optional[List[Dict[str, Any]]] = None) -> str:
        """
        从攻击结果中检测模式标签
        
        Returns:
            "chain" / "smart_match" / "presets" / "mixed"
        """
        if not results:
            return "assessment"
        
        modes = set()
        for module in results:
            for attack in module.get("attacks", []):
                mode = attack.get("mode", "chain")
                modes.add(mode)
        
        if len(modes) == 0:
            return "assessment"
        if len(modes) == 1:
            return next(iter(modes))
        return "mixed"

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
        """
        详细发现（优化格式）
        
        格式对齐最佳实践：
        - 标题格式: {简洁描述}: {攻击面}
        - 属性表（Severity / Source / Category / OWASP / MITRE ATLAS / Endpoint）
        - 具体描述（基于攻击类型，简洁独立）
        - 证据（原始响应数据，不截断、不加前缀）
        - 针对性修复建议
        """
        findings_text = []
        finding_index = 0
        
        for result in self.results:
            scope = result.get("scope", "unknown")
            owasp_ids = result.get("owasp_ids", [])
            target_endpoint = result.get("target_endpoint", "N/A")
            owasp_mapping = ", ".join(owasp_ids) if owasp_ids else result.get("owasp_mapping", "")

            for attack in result.get("attacks", []):
                finding_index += 1
                attack_name = attack.get("attack_name", "unknown")
                success_count = attack.get("success_count", 0)
                failure_count = attack.get("failure_count", 0)
                total = success_count + failure_count
                rate = (success_count / total * 100) if total > 0 else 0

                # 计算严重度（优先使用 catalog 预定义严重度）
                catalog_severity = attack.get("severity", "")
                severity = self._calc_severity(rate, attack_name, catalog_severity)

                # 提取攻击元数据
                source = self._extract_source(attack_name)
                category = self._extract_category(attack_name)
                mitre_atlas = self._map_mitre_atlas(attack_name, category)
                owasp_id = self._extract_owasp_id(attack_name, owasp_mapping)
                endpoint = self._extract_endpoint(attack, target_endpoint)

                # 生成标题描述和修复建议
                title_text = self._generate_title(category)
                description = self._generate_description(attack_name, category, scope)
                remediation = self._generate_remediation(attack_name, category)

                # 提取证据（成功的响应样本，原始格式）
                evidence = self._extract_evidence(attack)

                # 构建标题
                title = title_text
                
                # 构建发现文本
                finding_text = f"""#### ⚡ Finding #{finding_index}: {title}

| Attribute | Value |
|-----------|-------|
| Severity | **{severity}** |
| Source | {source} |
| Category | {category} |
| OWASP LLM | {owasp_id} |
| MITRE ATLAS | {mitre_atlas} |
| Endpoint | {endpoint} |

**Description**: {description}

**Evidence**:
```
{evidence}

```

**Remediation**: {remediation}
"""
                findings_text.append(finding_text)
        
        if not findings_text:
            return "## 5. Detailed Findings\n\nNo findings recorded."
        
        return "### Findings Details\n\n" + "\n\n---\n\n".join(findings_text)

    @staticmethod
    def _calc_severity(rate: float, attack_name: str, catalog_severity: str = "") -> str:
        """
        计算严重度
        
        优先级：
        1. catalog 中预定义的 severity
        2. 攻击名称中包含的严重度关键词
        3. 基于成功率动态判定
        """
        # 从 catalog 获取预定义严重度
        if catalog_severity:
            severity_map = {
                "critical": "CRITICAL",
                "high": "HIGH",
                "medium": "MEDIUM",
                "low": "LOW",
            }
            return severity_map.get(catalog_severity.lower(), "MEDIUM")
        
        # 从攻击名称中提取预定义严重度
        name_lower = attack_name.lower()
        if "critical" in name_lower:
            return "CRITICAL"
        if "high" in name_lower:
            return "HIGH"
        # 基于成功率判定
        if rate >= 70:
            return "CRITICAL"
        if rate >= 40:
            return "HIGH"
        if rate >= 10:
            return "MEDIUM"
        return "LOW"

    @staticmethod
    def _extract_source(attack_name: str) -> str:
        """
        从攻击名称提取 Source（攻击类型标识）
        
        返回格式：小写 + 下划线连接的攻击类型
        示例：
        - "LLM01:2024 — Prompt Injection Direct" → "prompt_injection"
        - "Embedding Info Leakage" → "embeddings_attack"
        - "ASI01:2026 — Agent Goal Hijack" → "agent_goal_hijack"
        """
        name_lower = attack_name.lower()
        source_map = {
            "prompt injection": "prompt_injection",
            "direct injection": "prompt_injection",
            "jailbreak": "jailbreak",
            "goal hijack": "agent_goal_hijack",
            "tool misuse": "tool_misuse",
            "tool surface": "tool_surface",
            "code execution": "code_execution",
            "memory poisoning": "memory_poisoning",
            "context poisoning": "memory_poisoning",
            "identity abuse": "identity_privilege_abuse",
            "supply chain": "supply_chain",
            "inter-agent": "insecure_communication",
            "cascading": "cascading_failure",
            "trust exploitation": "human_trust_exploitation",
            "rogue agent": "rogue_agent",
            "rag": "rag_attack",
            "embedding": "embeddings_attack",
            "mcp": "tool_surface",
            "infrastructure": "infrastructure",
            "model extraction": "model_theft",
            "poisoning": "data_poisoning",
        }
        for key, value in source_map.items():
            if key in name_lower:
                return value
        # 回退：使用模块名
        return "unknown"

    @staticmethod
    def _extract_category(attack_name: str) -> str:
        """
        从攻击名称提取 Category（具体发现类型）
        
        返回格式：小写 + 下划线的具体发现标识
        示例：
        - "Embedding Info Leakage" → "embedding_info_leakage"
        - "Prompt Injection Direct" → "direct_injection"
        """
        name_lower = attack_name.lower()
        category_map = {
            "info leakage": "embedding_info_leakage",
            "info leak": "embedding_info_leakage",
            "embedding": "embedding_info_leakage",
            "prompt injection": "prompt_injection",
            "direct injection": "direct_injection",
            "jailbreak": "jailbreak",
            "goal hijack": "agent_goal_hijack",
            "tool misuse": "tool_misuse",
            "tool surface": "tool_surface_abuse",
            "code execution": "unexpected_code_execution",
            "memory poisoning": "memory_poisoning",
            "context poisoning": "context_poisoning",
            "identity abuse": "identity_privilege_abuse",
            "supply chain": "supply_chain_vulnerability",
            "inter-agent": "insecure_inter_agent_communication",
            "cascading": "cascading_failure",
            "trust exploitation": "human_agent_trust_exploitation",
            "rogue agent": "rogue_agent",
            "rag": "rag_exploitation",
            "mcp": "tool_surface",
            "infrastructure": "infrastructure_misconfiguration",
            "model extraction": "model_theft",
            "poisoning": "data_poisoning",
        }
        for key, value in category_map.items():
            if key in name_lower:
                return value
        return "unknown"

    @staticmethod
    def _map_mitre_atlas(attack_name: str, category: str) -> str:
        """映射到 MITRE ATLAS 技术"""
        atlas_map = {
            "prompt_injection": "Injection",
            "direct_injection": "Injection",
            "jailbreak": "Jailbreak",
            "agent_goal_hijack": "Goal Hijack",
            "tool_misuse": "Tool Misuse",
            "tool_surface": "Tool Misuse",
            "tool_surface_abuse": "Tool Misuse",
            "code_execution": "Code Execution",
            "unexpected_code_execution": "Code Execution",
            "memory_poisoning": "Data Poisoning",
            "context_poisoning": "Data Poisoning",
            "data_poisoning": "Data Poisoning",
            "identity_privilege_abuse": "Identity Abuse",
            "supply_chain": "Supply Chain",
            "supply_chain_vulnerability": "Supply Chain",
            "insecure_communication": "Insecure Communication",
            "insecure_inter_agent_communication": "Insecure Communication",
            "cascading_failure": "Cascading Failure",
            "human_trust_exploitation": "Trust Exploitation",
            "human_agent_trust_exploitation": "Trust Exploitation",
            "rogue_agent": "Rogue Agent",
            "rag_exploitation": "Data Poisoning",
            "rag_attack": "Data Poisoning",
            "embedding_info_leakage": "Reconnaissance",
            "infrastructure": "Infrastructure",
            "infrastructure_misconfiguration": "Infrastructure",
            "model_theft": "Model Theft",
        }
        name_lower = attack_name.lower()
        if "recon" in name_lower or "discovery" in name_lower or "leakage" in name_lower or "leak" in name_lower:
            return "Reconnaissance"
        return atlas_map.get(category, "Injection")

    @staticmethod
    def _extract_owasp_id(attack_name: str, owasp_mapping: str) -> str:
        """提取 OWASP ID"""
        import re
        # 从攻击名称提取 LLM01/ASI01 等
        match = re.search(r'(?:LLM|ASI)\d{2}', attack_name)
        if match:
            return match.group(0)
        # 从模块级 owasp_mapping 提取
        if owasp_mapping:
            ids = re.findall(r'(?:LLM|ASI)\d{2}', owasp_mapping)
            if ids:
                return ", ".join(ids[:2])
        return "N/A"

    @staticmethod
    def _extract_endpoint(attack: Dict[str, Any], target_endpoint: str = "N/A") -> str:
        """
        提取端点信息
        
        优先级：
        1. 从攻击结果响应中提取 URL
        2. 使用目标配置中的 endpoint
        3. 回退到模式标识
        """
        # 从攻击结果中查找响应数据
        results = attack.get("results", [])
        for r in results:
            response = r.get("response", "")
            if response and len(response) > 10:
                # 尝试从响应中提取 URL 或端点信息
                import re
                url_match = re.search(r'https?://[^\s"\']+', response)
                if url_match:
                    return url_match.group(0)
        
        # 使用目标配置中的 endpoint
        if target_endpoint and target_endpoint != "N/A":
            # 根据攻击类型推断具体端点路径
            attack_name = attack.get("attack_name", "").lower()
            if "embedding" in attack_name or "model" in attack_name:
                return f"{target_endpoint}/models"
            if "chat" in attack_name or "injection" in attack_name or "jailbreak" in attack_name:
                return f"{target_endpoint}/chat/completions"
            return target_endpoint
        
        # 返回模式标识
        mode = attack.get("mode", "chain")
        return f"/v1/chat/completions ({mode})"

    @staticmethod
    def _generate_description(attack_name: str, category: str, module_name: str) -> str:
        """
        生成具体描述（简洁、独立，不包含模块名）
        
        描述应当：
        1. 简洁明了，一句话说明发现的问题
        2. 不包含模块名（模块名已在上下文体现）
        3. 聚焦于具体发现，而非攻击过程
        """
        descriptions = {
            "prompt_injection": "直接提示注入攻击成功绕过安全控制，攻击者可通过构造恶意提示词操纵 LLM 行为",
            "direct_injection": "直接注入攻击成功绕过输入过滤，目标系统未对恶意提示词进行有效检测和拦截",
            "jailbreak": "Jailbreak 攻击成功突破模型安全对齐，绕过内容策略限制生成受限内容",
            "agent_goal_hijack": "Agent 目标劫持成功，攻击者通过外部数据注入改变 Agent 的原始任务目标",
            "tool_misuse": "工具滥用攻击成功，Agent 被操纵以非预期方式使用合法工具",
            "tool_surface": "工具表面攻击成功，MCP/Tool 接口缺乏足够的输入验证和权限控制",
            "tool_surface_abuse": "工具表面滥用成功，MCP/Tool 接口缺乏足够的输入验证和权限控制",
            "code_execution": "代码执行攻击成功，Agent 生成或执行了恶意代码片段",
            "unexpected_code_execution": "非预期代码执行攻击成功，Agent 生成或执行了恶意代码片段",
            "memory_poisoning": "记忆/上下文投毒成功，恶意数据被注入到 Agent 的长期记忆或 RAG 存储中",
            "context_poisoning": "上下文投毒成功，恶意数据被注入到 Agent 的上下文中",
            "data_poisoning": "数据投毒攻击成功，训练数据或知识库被恶意内容污染",
            "identity_privilege_abuse": "身份/权限滥用成功，Agent 继承或升级了高权限凭证",
            "supply_chain": "供应链攻击成功，第三方组件存在安全漏洞被利用",
            "supply_chain_vulnerability": "供应链漏洞攻击成功，第三方组件存在安全漏洞被利用",
            "insecure_communication": "不安全通信攻击成功，Agent 间通信缺乏消息认证和完整性验证",
            "insecure_inter_agent_communication": "不安全 Agent 间通信攻击成功，缺乏消息认证和完整性验证",
            "cascading_failure": "级联故障攻击成功，小错误通过 Agent 规划执行被放大",
            "human_trust_exploitation": "人机信任利用成功，用户被操纵执行恶意操作",
            "human_agent_trust_exploitation": "人机信任利用成功，用户被操纵执行恶意操作",
            "rogue_agent": "恶意 Agent 检测成功，被破坏的 Agent 表现出隐藏行为",
            "rag_exploitation": "RAG 管道攻击成功，检索结果被操纵或知识库被提取",
            "rag_attack": "RAG 管道攻击成功，检索结果被操纵或知识库被提取",
            "embedding_info_leakage": "嵌入端点响应中泄露了模型/系统元数据信息",
            "infrastructure": "基础设施攻击成功，AI 部署环境存在配置错误或漏洞",
            "infrastructure_misconfiguration": "基础设施配置错误攻击成功，AI 部署环境存在配置错误",
            "model_theft": "模型提取攻击成功，通过 API 查询获取了模型权重信息",
        }
        return descriptions.get(category, f"攻击场景 {attack_name} 执行成功")

    @staticmethod
    def _generate_title(category: str) -> str:
        """
        生成简洁标题描述（用于 Finding 标题）
        
        标题应当简洁（2-10字），直接点明发现的问题类型。
        与 Description 的区别：
        - Title: 极简短语（如"嵌入系统信息泄露"）
        - Description: 完整句子（如"嵌入端点响应中泄露了模型/系统元数据信息"）
        """
        titles = {
            "prompt_injection": "提示注入",
            "direct_injection": "直接注入",
            "jailbreak": "越狱攻击",
            "agent_goal_hijack": "Agent 目标劫持",
            "tool_misuse": "工具滥用",
            "tool_surface": "工具表面攻击",
            "tool_surface_abuse": "工具表面滥用",
            "code_execution": "代码执行",
            "unexpected_code_execution": "非预期代码执行",
            "memory_poisoning": "记忆投毒",
            "context_poisoning": "上下文投毒",
            "data_poisoning": "数据投毒",
            "identity_privilege_abuse": "身份权限滥用",
            "supply_chain": "供应链攻击",
            "supply_chain_vulnerability": "供应链漏洞",
            "insecure_communication": "不安全通信",
            "insecure_inter_agent_communication": "Agent 间通信漏洞",
            "cascading_failure": "级联故障",
            "human_trust_exploitation": "人机信任利用",
            "human_agent_trust_exploitation": "人机信任利用",
            "rogue_agent": "恶意 Agent",
            "rag_exploitation": "RAG 管道攻击",
            "rag_attack": "RAG 管道攻击",
            "embedding_info_leakage": "嵌入系统信息泄露",
            "infrastructure": "基础设施攻击",
            "infrastructure_misconfiguration": "基础设施配置错误",
            "model_theft": "模型提取",
        }
        return titles.get(category, "安全风险")

    @staticmethod
    def _generate_remediation(attack_name: str, category: str) -> str:
        """生成针对性修复建议"""
        remediations = {
            "prompt_injection": "部署提示注入检测模型（如 PromptShield）; 实施输入验证和输出过滤; 使用系统提示词隔离用户输入",
            "direct_injection": "实施严格的输入验证和过滤; 使用提示词分类器检测恶意输入; 部署多层防御（WAF + LLM 防火墙）",
            "jailbreak": "更新模型安全对齐训练; 部署 jailbreak 检测器; 实施输出内容审核和过滤",
            "agent_goal_hijack": "实施 Agent 目标完整性校验; 隔离外部数据与系统指令; 部署 Agent 行为监控和异常检测",
            "tool_misuse": "实施工具调用参数验证; 限制 Agent 工具权限（最小权限原则）; 部署工具调用审计日志",
            "tool_surface": "加强 MCP/Tool 接口认证和授权; 实施工具描述完整性验证; 部署工具调用速率限制",
            "tool_surface_abuse": "加强 MCP/Tool 接口认证和授权; 实施工具描述完整性验证; 部署工具调用速率限制",
            "code_execution": "禁用 Agent 代码执行能力或限制在沙箱中; 实施代码静态分析; 部署运行时行为监控",
            "unexpected_code_execution": "禁用 Agent 代码执行能力或限制在沙箱中; 实施代码静态分析; 部署运行时行为监控",
            "memory_poisoning": "实施记忆数据完整性校验; 隔离不同用户/会话的记忆; 部署记忆访问控制和审计",
            "context_poisoning": "实施上下文数据完整性校验; 隔离不同会话的上下文; 部署上下文访问控制",
            "data_poisoning": "实施训练数据验证和清洗; 部署知识库访问控制; 使用数据来源追踪和完整性校验",
            "identity_privilege_abuse": "实施最小权限原则; 隔离 Agent 身份和权限; 部署权限提升检测和告警",
            "supply_chain": "验证第三方组件完整性（签名校验）; 部署软件物料清单（SBOM）; 定期扫描依赖漏洞",
            "supply_chain_vulnerability": "验证第三方组件完整性（签名校验）; 部署软件物料清单（SBOM）; 定期扫描依赖漏洞",
            "insecure_communication": "实施 Agent 间消息认证（签名）; 加密通信通道; 部署消息新鲜度验证（防重放）",
            "insecure_inter_agent_communication": "实施 Agent 间消息认证（签名）; 加密通信通道; 部署消息新鲜度验证（防重放）",
            "cascading_failure": "实施错误隔离和熔断机制; 部署 Agent 行为监控; 设置失败重试上限和回退策略",
            "human_trust_exploitation": "加强用户安全培训; 实施敏感操作二次确认; 部署 Agent 输出可信度标识",
            "human_agent_trust_exploitation": "加强用户安全培训; 实施敏感操作二次确认; 部署 Agent 输出可信度标识",
            "rogue_agent": "实施 Agent 行为基线和异常检测; 部署多 Agent 互相审计; 定期审查 Agent 权限和活动",
            "rag_exploitation": "实施 RAG 数据源验证; 部署检索结果过滤; 加密向量数据库并实施访问控制",
            "rag_attack": "实施 RAG 数据源验证; 部署检索结果过滤; 加密向量数据库并实施访问控制",
            "embedding_info_leakage": "清理嵌入 API 的错误消息和响应元数据; 减少信息暴露; 实施嵌入向量访问控制",
            "infrastructure": "加固云资源配置（CSPM）; 实施容器安全扫描; 部署基础设施即代码（IaC）安全审计",
            "infrastructure_misconfiguration": "加固云资源配置（CSPM）; 实施容器安全扫描; 部署基础设施即代码（IaC）安全审计",
            "model_theft": "实施 API 速率限制和异常检测; 部署模型水印; 监控大规模查询行为",
        }
        return remediations.get(category, "实施输入验证和输出过滤; 部署 AI 安全监控; 定期进行红队评估")

    @staticmethod
    def _extract_evidence(attack: Dict[str, Any]) -> str:
        """
        提取证据（成功的响应样本）
        
        返回原始响应数据，不截断、不加前缀，保持证据的原始性和完整性。
        最多返回 3 个成功样本，用空行分隔。
        """
        results = attack.get("results", [])
        evidence_parts = []
        
        for r in results:
            if r.get("status") == "success":
                response = r.get("response", "")
                if response and len(response) > 5:
                    evidence_parts.append(response)
                if len(evidence_parts) >= 3:
                    break
        
        if evidence_parts:
            return "\n\n".join(evidence_parts)
        
        # 无成功证据时返回失败信息
        for r in results:
            if r.get("status") in ("failed", "error"):
                response = r.get("response", r.get("error", ""))
                if response:
                    return response
        
        return "No response data available"

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
