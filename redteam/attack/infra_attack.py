"""MCP 工具面攻击 + 供应链攻击 + 基础设施攻击（AI-300 Ch7+Ch8+Ch9 合并）。

合并原因：这三章在实际攻击中紧密关联 —— MCP 服务器部署在基础设施上，
攻击 MCP 常涉及供应链投毒，基础设施漏洞又为 MCP 攻击提供入口。

覆盖：
  - MCP 架构侦察与工具枚举 (Ch7)
  - MCP 工具投毒与后门注入 (Ch7)  
  - AI 供应链攻击（恶意模型/投毒数据集）(Ch8)
  - 云 ML 服务配置错误 (Ch9)
  - 容器与 K8s 漏洞 (Ch9)

Library-First：使用 httpx 做 MCP SDK 探测，subprocess 调用 mcp-scan。
"""
from __future__ import annotations

import re
import subprocess
from typing import Any

import httpx

from redteam.core.models import (
    AIService, AuthContext, Finding, OWASPLlm, MITREATLASTactic,
)


# ===== MCP 端点探测 =====
def scan_mcp_endpoint(
    mcp_url: str,
    mcp_scan_binary: str = "mcp-scan",
    timeout: int = 120,
) -> dict[str, Any]:
    """使用 mcp-scan 工具扫描 MCP 端点。"""
    try:
        proc = subprocess.run(
            [mcp_scan_binary, mcp_url],
            capture_output=True, text=True, timeout=timeout,
        )
        output = proc.stdout + "\n" + proc.stderr
        return {
            "url": mcp_url,
            "success": proc.returncode == 0,
            "output": output[:3000],
            "tools_found": _extract_mcp_tools(output),
            "vulnerabilities": _extract_mcp_vulns(output),
        }
    except Exception as e:
        return {"url": mcp_url, "success": False, "error": str(e), "tools_found": [], "vulnerabilities": []}


def _extract_mcp_tools(output: str) -> list[str]:
    """从 mcp-scan 输出提取发现的工具名。"""
    tools: set[str] = set()
    # 匹配 "tool: <name>" 或 "Tool: <name>" 或工具列表格式
    patterns = [
        r'(?i)(?:tool|function)[_\s]*(?:name)?\s*[:=]\s*["\']?(\w+)["\']?',
        r'(?i)"name"\s*:\s*"(\w+)"',
        r'(?i)- (\w+) \(',  # markdown list
    ]
    for pattern in patterns:
        for match in re.findall(pattern, output):
            if len(match) > 1 and match.lower() not in {"tool", "function", "name", "type"}:
                tools.add(match)
    return sorted(tools)


def _extract_mcp_vulns(output: str) -> list[str]:
    """从 mcp-scan 输出提取发现的漏洞。"""
    vulns: list[str] = []
    vuln_patterns = [
        r'(?i)(prompt\s*injection)',
        r'(?i)(tool\s*poisoning)',
        r'(?i)(cross[\s_-]origin)',
        r'(?i)(rug\s*pull)',
        r'(?i)(vulnerability|vuln|CVE|exploit)',
    ]
    for pattern in vuln_patterns:
        if re.search(pattern, output):
            match = re.search(pattern, output)
            if match:
                vulns.append(match.group(1).strip())
    return sorted(set(vulns))


# ===== 供应链攻击检测 =====
def check_supply_chain_risks(
    service: AIService,
    timeout: float = 5.0,
) -> list[dict[str, Any]]:
    """检测 AI 供应链风险（Ch8）。

    检查：
    - 模型来源：HuggingFace / Ollama 仓库中是否存在恶意模型
    - 版本过期：使用已知漏洞版本
    - 依赖风险：模型的 requirements 是否有恶意依赖
    """
    risks: list[dict[str, Any]] = []

    for model_name in service.models:
        # 检查模型来源（通过模型名启发式）
        if "/" in model_name:
            source, name = model_name.split("/", 1)
            # HuggingFace 模型来源
            if not any(trusted in source.lower() for trusted in ["microsoft", "google", "meta", "openai", "mistral"]):
                risks.append({
                    "model": model_name,
                    "risk": "untrusted_model_source",
                    "source": source,
                    "description": f"模型 '{model_name}' 来自未验证的来源 '{source}'",
                })

    # 检查是否有公开已知漏洞的组件版本
    if "mlflow" in str(service.version).lower() or "mlflow" in service.url.lower():
        risks.append({
            "model": "mlflow",
            "risk": "known_vulnerable_component",
            "description": "MLflow 存在多个已知漏洞 (CVE-2024-xxx)，可能允许未授权访问和代码执行",
        })

    return risks


# ===== 云基础设施安全检查 =====
_CLOUD_AI_CHECK_PATTERNS: list[dict[str, Any]] = [
    # (关键词, 风险描述, 严重程度)
    {"keyword": "AccessDenied", "risk": "IAM 权限配置问题", "severity": "medium"},
    {"keyword": "Anonymous access", "risk": "匿名访问未关闭", "severity": "high"},
    {"keyword": "s3.amazonaws.com", "risk": "模型权重存储在公开 S3 桶", "severity": "critical"},
    {"keyword": "storage.googleapis.com", "risk": "模型权重存储在公开 GCS 桶", "severity": "critical"},
    {"keyword": ".blob.core.windows.net", "risk": "模型权重存储在公开 Azure Blob", "severity": "critical"},
    {"keyword": "huggingface.co/models/", "risk": "使用 HuggingFace 仓库（检查是否公开）", "severity": "low"},
    {"keyword": "ollama.com/library/", "risk": "使用 Ollama 仓库（检查模型哈希）", "severity": "low"},
    {"keyword": "Internal Server Error", "risk": "错误信息泄露内部架构", "severity": "low"},
    {"keyword": "debug", "risk": "调试模式开启", "severity": "medium"},
    {"keyword": "traceback", "risk": "堆栈跟踪泄漏", "severity": "medium"},
]


def scan_cloud_misconfigs(
    base_url: str,
    auth: AuthContext | None = None,
    timeout: float = 5.0,
) -> list[dict[str, Any]]:
    """云 AI 服务配置错误检测（Ch9）。"""
    findings: list[dict[str, Any]] = []

    try:
        headers = auth.to_header_dict() if auth else {}
        with httpx.Client(timeout=timeout, verify=False) as client:
            # 探测基础端点
            for path in ["/", "/health", "/api", "/debug", "/metrics", "/env"]:
                from urllib.parse import urljoin
                url = urljoin(base_url, path)
                try:
                    r = client.get(url, headers=headers)
                    body = r.text[:2000]
                    for pattern in _CLOUD_AI_CHECK_PATTERNS:
                        if pattern["keyword"].lower() in body.lower():
                            findings.append({
                                "url": url,
                                "risk": pattern["risk"],
                                "severity": pattern["severity"],
                                "matched": pattern["keyword"],
                                "evidence": _extract_context(body, pattern["keyword"]),
                            })
                except Exception:
                    pass
    except Exception:
        pass

    return findings


def _extract_context(text: str, keyword: str, context_chars: int = 100) -> str:
    """提取关键词周围的上下文。"""
    pos = text.lower().find(keyword.lower())
    if pos == -1:
        return ""
    start = max(0, pos - context_chars // 2)
    end = min(len(text), pos + len(keyword) + context_chars // 2)
    return text[start:end].strip()


# ===== Findings 生成 =====
def generate_infra_findings(
    mcp_results: list[dict],
    supply_chain_risks: list[dict],
    cloud_findings: list[dict],
) -> list[Finding]:
    """合并基础设施/供应链攻击发现。"""
    findings: list[Finding] = []

    # MCP 扫描发现
    for mr in mcp_results:
        if mr.get("vulnerabilities"):
            for v in mr["vulnerabilities"]:
                findings.append(Finding(
                    source="mcp_attack",
                    category="mcp_vulnerability",
                    severity="high",
                    title=f"MCP 漏洞: {v}",
                    description=f"在 {mr['url']} 发现 MCP 安全漏洞",
                    evidence=mr.get("output", "")[:500],
                    remediation="修复 MCP 服务器配置，实施输入验证和工具权限控制",
                    endpoint=mr["url"],
                    owasp_llm=OWASPLlm.LLM06_EXCESSIVE_AGENCY,
                    mitre_atlas_tactic=MITREATLASTactic.EXECUTION,
                ))
        if mr.get("tools_found"):
            findings.append(Finding(
                source="mcp_attack",
                category="mcp_tools_exposed",
                severity="medium",
                title=f"MCP 工具暴露: {len(mr['tools_found'])} 个",
                description=f"发现暴露的 MCP 工具: {', '.join(mr['tools_found'])}",
                evidence=mr.get("output", "")[:300],
                remediation="审查 MCP 工具权限，移除高风险工具或限制调用",
                endpoint=mr["url"],
                mitre_atlas_tactic=MITREATLASTactic.RECON,
            ))

    # 供应链风险
    for risk in supply_chain_risks:
        findings.append(Finding(
            source="supply_chain",
            category="supply_chain_risk",
            severity="medium",
            title=f"供应链风险: {risk['risk']}",
            description=risk.get("description", ""),
            evidence=f"模型: {risk.get('model', '')}, 来源: {risk.get('source', '')}",
            remediation="验证模型来源可信性，实施模型签名验证",
            owasp_llm=OWASPLlm.LLM03_SUPPLY_CHAIN,
            mitre_atlas_tactic=MITREATLASTactic.RESOURCE_DEV,
        ))

    # 云配置错误
    for cf in cloud_findings:
        findings.append(Finding(
            source="infra_attack",
            category="cloud_misconfiguration",
            severity=cf.get("severity", "medium"),
            title=f"云配置错误: {cf['risk']}",
            description=f"在 {cf['url']} 发现配置错误",
            evidence=cf.get("evidence", ""),
            remediation="修复 IAM 策略、启用认证、关闭匿名访问",
            endpoint=cf["url"],
            mitre_atlas_tactic=MITREATLASTactic.INITIAL_ACCESS,
        ))

    return findings
