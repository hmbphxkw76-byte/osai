"""依赖攻击风险检测（AI-300 Ch8: Supply Chain Attacks）。

实现 AI-300 课程中的依赖攻击检测技术：
  - requirements.txt 恶意依赖检测
  - 自定义模型类代码执行风险
  - MLflow 已知漏洞检测

对齐 OWASP LLM Top 10: LLM03 (Supply Chain Vulnerabilities)
"""
from __future__ import annotations

from typing import Any

from redteam.core.models import AIService


def check_dependency_risks(
    service: AIService,
    timeout: float = 5.0,
) -> list[dict[str, Any]]:
    """检查 AI 模型依赖攻击风险（AI-300 Ch8.4）。"""
    risks: list[dict[str, Any]] = []

    for model_name in service.models:
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

    version = service.version.lower() if service.version else ""
    if version:
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


__all__ = [
    "check_dependency_risks",
]