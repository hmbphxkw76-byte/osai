# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""OWASP 数据 — LLM Top 10 + Agentic AI Top 10 完整定义。

外部化 OWASP 数据, 供 ReportGenerator + OWASPMapper + EvidenceExporter 共享。
数据源: OWASP Top 10 for LLM Applications 2025 + OWASP Top 10 for Agentic AI。

学术依据:
  - OWASP Top 10 for LLM Applications 2025 (https://owasp.org/www-project-top-10-for-large-language-model-applications/)
  - OWASP Top 10 for Agentic AI (https://owasp.org/www-project-top-10-for-agentic-ai/)
"""

from __future__ import annotations

from typing import Any


# ============================================================
# OWASP Top 10 for LLM Applications 2025
# ============================================================

OWASP_LLM_DETAILS: dict[str, dict[str, Any]] = {
    "LLM01": {
        "name": "Prompt Injection",
        "severity": "CRITICAL",
        "cvss_base": 8.0,
        "description": "攻击者通过精心构造的输入操纵 LLM 行为, 覆盖系统指令或执行非预期操作。",
        "indicators": ["异常输出模式", "系统指令泄漏", "角色越权"],
        "remediation": ["输入验证", "指令层级隔离", "输出过滤"],
    },
    "LLM02": {
        "name": "Sensitive Information Disclosure",
        "severity": "HIGH",
        "cvss_base": 7.0,
        "description": "LLM 泄露敏感数据, 包括训练数据、PII、系统配置或对话历史。",
        "indicators": ["PII 泄露", "训练数据提取", "配置信息暴露"],
        "remediation": ["数据脱敏", "访问控制", "输出审查"],
    },
    "LLM03": {
        "name": "Supply Chain Vulnerabilities",
        "severity": "HIGH",
        "cvss_base": 7.0,
        "description": "第三方模型、数据集或插件中的漏洞引入供应链风险。",
        "indicators": ["依赖漏洞", "模型篡改", "插件后门"],
        "remediation": ["依赖审计", "模型签名验证", "插件沙箱"],
    },
    "LLM04": {
        "name": "Data and Model Poisoning",
        "severity": "HIGH",
        "cvss_base": 7.0,
        "description": "篡改训练数据或微调数据, 在模型中植入后门或偏差。",
        "indicators": ["异常触发模式", "偏差输出", "后门激活"],
        "remediation": ["数据验证", "差分隐私", "模型审计"],
    },
    "LLM05": {
        "name": "Improper Output Handling",
        "severity": "MEDIUM",
        "cvss_base": 5.0,
        "description": "LLM 输出未经安全处理直接渲染, 导致 XSS、SSRF 或代码执行。",
        "indicators": ["XSS 载荷", "SSRF 请求", "HTML 注入"],
        "remediation": ["输出编码", "CSP 策略", "沙箱渲染"],
    },
    "LLM06": {
        "name": "Excessive Agency",
        "severity": "HIGH",
        "cvss_base": 7.0,
        "description": "LLM Agent 拥有过多权限, 可执行未授权操作或访问敏感资源。",
        "indicators": ["权限越界", "未授权操作", "资源滥用"],
        "remediation": ["最小权限", "操作审批", "权限隔离"],
    },
    "LLM07": {
        "name": "System Prompt Leakage",
        "severity": "MEDIUM",
        "cvss_base": 5.0,
        "description": "系统提示词泄露, 暴露模型行为约束和安全策略。",
        "indicators": ["系统指令暴露", "策略提取", "角色定义泄漏"],
        "remediation": ["指令混淆", "输出过滤", "指令版本化"],
    },
    "LLM08": {
        "name": "Vector and Embedding Weaknesses",
        "severity": "MEDIUM",
        "cvss_base": 5.0,
        "description": "向量数据库和嵌入模型的弱点, 导致数据泄露或注入攻击。",
        "indicators": ["向量反转", "数据注入", "相似性泄露"],
        "remediation": ["访问控制", "嵌入加密", "查询过滤"],
    },
    "LLM09": {
        "name": "Misinformation",
        "severity": "MEDIUM",
        "cvss_base": 5.0,
        "description": "LLM 生成虚假信息, 导致决策错误或声誉损害。",
        "indicators": ["幻觉输出", "虚假引用", "误导信息"],
        "remediation": ["事实验证", "置信度标注", "来源标注"],
    },
    "LLM10": {
        "name": "Unbounded Consumption",
        "severity": "MEDIUM",
        "cvss_base": 5.0,
        "description": "攻击者通过大量请求消耗 LLM 资源, 导致拒绝服务。",
        "indicators": ["资源耗尽", "速率滥用", "上下文填充"],
        "remediation": ["速率限制", "配额管理", "上下文限制"],
    },
}


# ============================================================
# OWASP Top 10 for Agentic AI
# ============================================================

OWASP_ASI_DETAILS: dict[str, dict[str, Any]] = {
    "ASI01": {
        "name": "Agent Identity Spoofing",
        "severity": "HIGH",
        "cvss_base": 7.0,
        "description": "攻击者冒充合法 Agent 身份, 获取未授权访问。",
        "indicators": ["身份伪造", "凭据窃取", "会话劫持"],
        "remediation": ["身份验证", "会话令牌", "双向认证"],
    },
    "ASI02": {
        "name": "Tool Misuse",
        "severity": "HIGH",
        "cvss_base": 7.0,
        "description": "Agent 被诱导误用工具, 执行非预期操作。",
        "indicators": ["工具滥用", "参数篡改", "非预期调用"],
        "remediation": ["工具白名单", "参数验证", "调用审计"],
    },
    "ASI03": {
        "name": "Unauthorized Actions",
        "severity": "CRITICAL",
        "cvss_base": 8.0,
        "description": "Agent 执行超出授权范围的操作。",
        "indicators": ["权限越界", "未授权操作", "资源滥用"],
        "remediation": ["最小权限", "操作审批", "权限隔离"],
    },
    "ASI04": {
        "name": "Data Exfiltration",
        "severity": "HIGH",
        "cvss_base": 7.0,
        "description": "Agent 被利用泄露敏感数据到外部。",
        "indicators": ["数据外泄", "隐蔽通道", "信息编码"],
        "remediation": ["DLP 策略", "流量监控", "输出审查"],
    },
    "ASI05": {
        "name": "Code Execution",
        "severity": "CRITICAL",
        "cvss_base": 9.0,
        "description": "攻击者利用 Agent 的代码执行能力运行恶意代码。",
        "indicators": ["代码注入", "命令执行", "沙箱逃逸"],
        "remediation": ["代码沙箱", "执行限制", "代码审查"],
    },
    "ASI06": {
        "name": "Memory Poisoning",
        "severity": "HIGH",
        "cvss_base": 7.0,
        "description": "篡改 Agent 的记忆/上下文, 注入恶意指令。",
        "indicators": ["记忆篡改", "上下文注入", "持久化后门"],
        "remediation": ["记忆加密", "完整性校验", "记忆隔离"],
    },
    "ASI07": {
        "name": "Cross-Agent Injection",
        "severity": "MEDIUM",
        "cvss_base": 5.0,
        "description": "通过 Agent 间通信注入恶意指令。",
        "indicators": ["Agent 间注入", "消息篡改", "信任链利用"],
        "remediation": ["消息签名", "通信加密", "信任验证"],
    },
    "ASI08": {
        "name": "Cascading Failures",
        "severity": "HIGH",
        "cvss_base": 7.0,
        "description": "单个 Agent 失败导致多 Agent 系统连锁崩溃。",
        "indicators": ["连锁故障", "级联错误", "系统崩溃"],
        "remediation": ["故障隔离", "熔断机制", "降级策略"],
    },
    "ASI09": {
        "name": "Trust Exploit",
        "severity": "HIGH",
        "cvss_base": 7.0,
        "description": "利用 Agent 间的信任关系实施攻击。",
        "indicators": ["信任滥用", "权限提升", "代理攻击"],
        "remediation": ["信任最小化", "权限分级", "审计追踪"],
    },
    "ASI10": {
        "name": "Rogue Agent",
        "severity": "CRITICAL",
        "cvss_base": 8.0,
        "description": "Agent 被完全控制, 成为恶意代理。",
        "indicators": ["Agent 失控", "恶意行为", "持久化控制"],
        "remediation": ["行为监控", "异常检测", "应急响应"],
    },
}


# ============================================================
# 合并字典
# ============================================================

ALL_OWASP_DETAILS: dict[str, dict[str, Any]] = {**OWASP_LLM_DETAILS, **OWASP_ASI_DETAILS}


def get_owasp_details(owasp_id: str) -> dict[str, Any]:
    """获取 OWASP 漏洞详细信息。"""
    return ALL_OWASP_DETAILS.get(owasp_id, {
        "name": "Unknown",
        "severity": "MEDIUM",
        "cvss_base": 5.0,
        "description": "",
        "indicators": [],
        "remediation": [],
    })


def get_all_owasp_standards() -> dict[str, dict[str, Any]]:
    """获取所有 OWASP 标准定义。"""
    return ALL_OWASP_DETAILS.copy()
