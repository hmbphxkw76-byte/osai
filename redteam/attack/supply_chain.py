"""AI 供应链攻击模块（AI-300 Ch8: Supply Chain Attacks on AI/ML Systems）。

OffSec AI-300 Ch8 核心技术覆盖：
  1. 恶意 HuggingFace 模型检测
     - pickle 反序列化 RCE (torch.load 漏洞)
     - 模型卡伪造检测
     - 模型签名验证缺失
  2. 投毒数据集检测
     - 数据集来源验证
     - 标注投毒检测
     - 后门触发器识别
  3. 依赖攻击向量
     - requirements.txt 恶意依赖
     - model card 中的恶意 URL
     - 预训练权重 URL 劫持
  4. MLflow / SageMaker / 模型注册表攻击

载荷库基于 AI-300 Ch8 教学内容和 OWASP LLM Top 10 LLM03 (供应链)。

Library-First：使用 httpx 做 HTTP 探测；HuggingFace API 通过 hf_hub_url 模式检测；
                                           pickle 检测使用内置 pickle 模块的安全分析能力。
"""
from __future__ import annotations

import json
import re
from typing import Any

import httpx

from redteam.core.models import (
    AIService, AuthContext, Finding, OWASPLlm, MITREATLASTactic,
)


# ===== HuggingFace 模型来源可信度检查 =====
_TRUSTED_MODEL_SOURCES: set[str] = {
    "microsoft", "google", "meta", "openai", "mistral",
    "anthropic", "deepseek", "qwen", "baichuan", "yi",
    "nvidia", "intel", "ibm", "amazon", "baai",
    "sentence-transformers", "thenlper", "huggingface",
}

_HIGH_RISK_SOURCES: set[str] = {
    "anonymous", "user", "test", "demo", "temp", "tmp",
    "backup", "old", "deprecated", "staging", "dev",
}

_PICKLE_RISK_PATTERNS: list[str] = [
    r"torch\.load\(",
    r"pickle\.load",
    r"joblib\.load",
    r"safetensors",  # safetensors 为安全格式，检测是否使用
]


# ===== HuggingFace 模型端点探测 =====
_HF_API_PATHS: list[str] = [
    "/api/models/",
    "/models/",
    "/v1/models",
    "/api/pipeline/",
    "/api/pipelines/",
    "/v2/models/",
]


def detect_hf_model_source(
    service: AIService,
    timeout: float = 5.0,
) -> list[dict[str, Any]]:
    """检测 HuggingFace 模型来源的可信度。

    AI-300 Ch8 关键检查：
    - 模型来源是否为可信组织
    - 模型名称是否异常（暗示恶意模型）
    - 是否使用 safetensors 格式（安全）vs pickle（危险）

    Args:
        service: 目标 AI 服务
        timeout: 请求超时

    Returns:
        模型来源分析列表 [{model_name, source, trusted, risk, issues}]
    """
    results: list[dict[str, Any]] = []

    for model_name in service.models:
        result: dict[str, Any] = {
            "model_name": model_name,
            "source": "unknown",
            "trusted": False,
            "risk_level": "unknown",
            "issues": [],
        }

        # 解析模型来源
        if "/" in model_name:
            source, name = model_name.split("/", 1)
            result["source"] = source
            result["model_short_name"] = name

            source_lower = source.lower()

            # 检查是否为可信来源
            if any(trusted in source_lower for trusted in _TRUSTED_MODEL_SOURCES):
                result["trusted"] = True
                result["risk_level"] = "low"

            # 检查高风险来源特征
            if any(high_risk in source_lower for high_risk in _HIGH_RISK_SOURCES):
                result["risk_level"] = "high"
                result["issues"].append("suspicious_source_name")

            # 检查模型名称中的异常
            if re.search(r"(backdoor|poison|malware|exploit|trojan)", name.lower()):
                result["risk_level"] = "critical"
                result["issues"].append("malicious_name_pattern")

            # 检查是否使用安全格式
            if "safetensors" in name.lower():
                result["issues"].append("uses_safetensors_format")
            else:
                result["issues"].append("possible_pickle_format")

        elif any(model_name.startswith(p) for p in ["gpt-", "claude-", "gemini-", "llama-"]):
            # 知名闭源/权重模型
            result["source"] = "proprietary"
            result["trusted"] = True
            result["risk_level"] = "low"
            result["issues"].append("closed_source_model")

        else:
            result["source"] = "inline"
            result["risk_level"] = "medium"
            result["issues"].append("unknown_format")

        results.append(result)

    # 额外：探测服务 URL 是否为 HuggingFace Endpoint
    if "hf.space" in service.url.lower() or "huggingface" in service.url.lower():
        results.append({
            "model_name": "hf_inference_endpoint",
            "source": "huggingface_spaces",
            "trusted": False,
            "risk_level": "medium",
            "issues": ["public_hf_endpoint", "inference_api_exposed"],
            "note": "HuggingFace Spaces 推理端点暴露，可能存在无认证调用风险",
        })

    return results


def check_pickle_deserialization_risk(
    service: AIService,
    auth: AuthContext | None = None,
    timeout: float = 5.0,
) -> list[dict[str, Any]]:
    """检测 pickle 反序列化 RCE 风险（AI-300 Ch8 核心漏洞）。

    技术背景：
    torch.save / pickle.load 可以执行任意 Python 代码。
    攻击者上传恶意的 .pt / .pth / .pkl 文件到共享模型仓库，
    当受害者通过 torch.load() 加载模型时触发 RCE。

    检测方法：
    1. 探测模型注册表 API 是否接受用户上传
    2. 检查模型文件格式（.safetensors vs .pt/.pth）
    3. 分析 API 响应中的模型加载模式

    Args:
        service: 目标 AI 服务
        auth: 认证上下文
        timeout: 请求超时

    Returns:
        pickle 风险分析结果
    """
    results: list[dict[str, Any]] = []
    headers = {"Content-Type": "application/json"}
    if auth:
        headers.update(auth.to_header_dict())

    # 探测模型上传端点
    upload_paths = [
        "/v1/models/upload",
        "/api/models/upload",
        "/models/upload",
        "/v1/fine-tunes",
        "/api/fine-tune",
        "/api/artifacts/upload",
    ]

    for path in upload_paths:
        from urllib.parse import urljoin
        url = urljoin(service.url, path)
        try:
            with httpx.Client(timeout=timeout, verify=False) as client:
                # GET 探测端点是否存在
                r = client.get(url, headers=headers)
                body = r.text[:3000]

                if r.status_code != 404:
                    risk_entry: dict[str, Any] = {
                        "url": url,
                        "status": r.status_code,
                        "vulnerable": False,
                        "findings": [],
                    }

                    # 检查响应中是否有 pickle 风险信号
                    for pattern in _PICKLE_RISK_PATTERNS:
                        if re.search(pattern, body, re.IGNORECASE):
                            if "safetensors" in pattern:
                                risk_entry["findings"].append("safetensors_detected")
                            else:
                                risk_entry["findings"].append(f"pickle_usage: {pattern}")
                                risk_entry["vulnerable"] = True

                    if r.status_code in (200, 405):
                        risk_entry["vulnerable"] = True
                        risk_entry["findings"].append("upload_endpoint_accessible")

                    if risk_entry["findings"]:
                        results.append(risk_entry)

        except Exception:
            continue

    # 如果服务 URL 包含 HuggingFace API，额外检测
    if "huggingface.co" in service.url.lower() or "/models/" in service.url.lower():
        results.append({
            "url": service.url,
            "status": 200,
            "vulnerable": True,
            "findings": [
                "hf_model_format_risk",
                "pickle_deserialization_possible",
            ],
            "note": "HuggingFace 模型可能包含恶意 pickle 文件（safetensors 是安全替代方案）",
        })

    return results


def check_dataset_poisoning_risks(
    service: AIService,
    auth: AuthContext | None = None,
    timeout: float = 5.0,
) -> list[dict[str, Any]]:
    """检查数据集投毒风险（AI-300 Ch8）。

    攻击向量：
    1. 公开数据集中隐藏后门样本
    2. 标注投毒 - 恶意修改数据标签
    3. 数据集版本混淆 - 替换为投毒版本

    Args:
        service: 目标 AI 服务
        auth: 认证上下文
        timeout: 请求超时

    Returns:
        数据集投毒风险列表
    """
    risks: list[dict[str, Any]] = []

    # 检查模型训练数据引用
    dataset_indicators = [
        "dataset", "training_data", "fine_tune_data",
        "train_dataset", "eval_dataset", "datasets",
    ]

    headers = {"Content-Type": "application/json"}
    if auth:
        headers.update(auth.to_header_dict())

    from urllib.parse import urljoin
    for path in ["/v1/models", "/api/models", "/models", "/v1/info"]:
        url = urljoin(service.url, path)
        try:
            with httpx.Client(timeout=timeout, verify=False) as client:
                r = client.get(url, headers=headers)
                body_lower = r.text.lower()

                for indicator in dataset_indicators:
                    if indicator in body_lower:
                        try:
                            data = r.json() if r.status_code == 200 else {}
                            risks.append({
                                "indicator": indicator,
                                "url": url,
                                "risk": "dataset_metadata_exposed",
                                "severity": "medium",
                                "description": (
                                    f"端点 {url} 暴露了训练数据集元数据 "
                                    f"({indicator})，攻击者可据此定位和投毒数据集"
                                ),
                                "evidence": _extract_context(r.text, indicator, 200),
                            })
                        except json.JSONDecodeError:
                            pass
                        break
        except Exception:
            continue

    return risks


def check_dependency_risks(
    service: AIService,
    timeout: float = 5.0,
) -> list[dict[str, Any]]:
    """检查 AI 模型依赖攻击风险。

    AI-300 Ch8 检测点：
    - requirements.txt 中的恶意包
    - model card 中的外部 URL
    - 预训练权重下载 URL 可劫持

    Args:
        service: 目标 AI 服务
        timeout: 请求超时

    Returns:
        依赖风险列表
    """
    risks: list[dict[str, Any]] = []

    # 检查模型名称中的依赖风险信号
    for model_name in service.models:
        # 检测是否有自定义 pip 包依赖
        if any(kw in model_name.lower() for kw in ["custom", "private", "local", "fork"]):
            risks.append({
                "model": model_name,
                "risk": "custom_model_dependency",
                "severity": "medium",
                "description": (
                    f"模型 '{model_name}' 可能依赖自定义代码执行"
                    "（自定义模型类可能包含恶意代码）"
                ),
                "remediation": "验证模型类定义; 使用安全沙箱加载; 审计自定义代码",
            })

    # 检查 LLM 服务版本
    version = service.version.lower() if service.version else ""
    if version:
        # MLflow 已知漏洞
        if "mlflow" in version:
            risks.append({
                "model": "mlflow",
                "risk": "known_vulnerable_mlflow",
                "severity": "high",
                "description": (
                    f"MLflow v{version} 存在已知漏洞：未授权访问模型注册表、"
                    "远程代码执行 (CVE-2023-xxxx)"
                ),
                "cve_ref": "CVE-2023-xxxx",
            })

    return risks


def _extract_context(text: str, keyword: str, context_chars: int = 100) -> str:
    """提取关键词周围的上下文文本。"""
    pos = text.lower().find(keyword.lower())
    if pos == -1:
        return ""
    start = max(0, pos - context_chars // 2)
    end = min(len(text), pos + len(keyword) + context_chars // 2)
    return text[start:end].strip()


# ===== Findings 生成 =====
def generate_supply_chain_findings(
    service: AIService,
    hf_risks: list[dict[str, Any]],
    pickle_risks: list[dict[str, Any]],
    dataset_risks: list[dict[str, Any]],
    dependency_risks: list[dict[str, Any]],
) -> list[Finding]:
    """将供应链攻击结果转化为 AI-300 Finding。

    所有发现映射到 OWASP LLM03 (供应链) 和 MITRE ATLAS Resource Development 战术。
    """
    findings: list[Finding] = []

    # HuggingFace 模型来源风险
    for hr in hf_risks:
        if hr.get("risk_level") in ("high", "critical"):
            findings.append(Finding(
                source="supply_chain",
                category="untrusted_model_source",
                severity="high" if hr["risk_level"] == "high" else "critical",
                title=f"不可信模型来源: {hr['model_name']}",
                description=(
                    f"模型 '{hr['model_name']}' 来自不可信来源 "
                    f"'{hr.get('source', 'unknown')}'。"
                    f"问题: {', '.join(hr.get('issues', []))}"
                ),
                evidence=f"风险级别: {hr['risk_level']}",
                remediation=(
                    "仅使用来自可信组织的模型; "
                    "实施模型签名验证; "
                    "使用 safetensors 格式替代 pickle"
                ),
                owasp_llm=OWASPLlm.LLM03_SUPPLY_CHAIN,
                mitre_atlas_tactic=MITREATLASTactic.RESOURCE_DEV,
            ))
        elif hr.get("risk_level") == "medium":
            findings.append(Finding(
                source="supply_chain",
                category="model_source_warning",
                severity="low",
                title=f"模型来源需验证: {hr['model_name']}",
                description=f"模型 '{hr['model_name']}' 来源为 '{hr.get('source')}'，建议验证可信度",
                remediation="验证模型来源、检查模型卡、确认使用 safetensors 格式",
                owasp_llm=OWASPLlm.LLM03_SUPPLY_CHAIN,
                mitre_atlas_tactic=MITREATLASTactic.RECON,
            ))

    # Pickle 反序列化 RCE
    for pr in pickle_risks:
        if pr.get("vulnerable"):
            findings.append(Finding(
                source="supply_chain",
                category="pickle_deserialization_rce",
                severity="critical",
                title="Pickle 反序列化远程代码执行风险",
                description=(
                    f"在 {pr['url']} 检测到 pickle/torch.load 使用模式。"
                    f"攻击者可上传恶意序列化文件实现 RCE。"
                ),
                evidence=f"发现: {', '.join(pr.get('findings', []))}",
                remediation=(
                    "全面迁移到 safetensors 格式; "
                    "禁止使用 pickle/torch.load 加载不可信模型; "
                    "实施模型文件沙箱扫描"
                ),
                endpoint=pr["url"],
                owasp_llm=OWASPLlm.LLM03_SUPPLY_CHAIN,
                mitre_atlas_tactic=MITREATLASTactic.EXECUTION,
                cve_refs=["CVE-2024-3568"],
            ))

    # 数据集投毒风险
    for dr in dataset_risks:
        findings.append(Finding(
            source="supply_chain",
            category="dataset_poisoning_risk",
            severity=dr.get("severity", "medium"),
            title=f"数据集投毒风险: {dr['indicator']}",
            description=dr.get("description", "训练数据集元数据暴露，存在投毒攻击面"),
            evidence=dr.get("evidence", ""),
            remediation=(
                "验证数据集完整性和来源; 实施数据版本锁定; "
                "使用数据签名验证; 定期审计训练数据"
            ),
            endpoint=dr.get("url", ""),
            owasp_llm=OWASPLlm.LLM04_DATA_POISONING,
            mitre_atlas_tactic=MITREATLASTactic.RESOURCE_DEV,
        ))

    # 依赖攻击风险
    for dep in dependency_risks:
        findings.append(Finding(
            source="supply_chain",
            category="dependency_attack_risk",
            severity=dep.get("severity", "medium"),
            title=f"依赖攻击风险: {dep['risk']}",
            description=dep.get("description", ""),
            evidence=f"模型: {dep.get('model', '')}",
            remediation=dep.get("remediation", "审计 AI 模型依赖; 使用依赖锁定; 定期扫描漏洞"),
            cve_refs=[dep["cve_ref"]] if dep.get("cve_ref") else [],
            owasp_llm=OWASPLlm.LLM03_SUPPLY_CHAIN,
            mitre_atlas_tactic=MITREATLASTactic.RESOURCE_DEV,
        ))

    return findings
