# -*- coding: utf-8 -*-
"""
AI-300 Framework - DeepTeam Adapter
DeepTeam 适配器：OWASP 红队扫描（Python import 调用）

DeepTeam v1.0.7 (Confident AI, LLM red teaming framework)
- PyPI: pip install deepteam>=1.0.7
- API: from deepteam import red_team
- 支持 OWASP Top 10 for LLMs 2026 / OWASP Top 10 for Agents / NIST AI RMF

内置漏洞类型（直接对应考试）：
  - LLM01: Prompt Injection, Jailbreak
  - LLM02: Sensitive Information Disclosure
  - LLM03: Training Data Poisoning
  - LLM04: Insecure Output Handling
  - LLM05: Excessive Agency
  - LLM06: System Prompt Disclosure
  - LLM07: RAG Vulnerability
  - LLM08: Excessive Agency
  - LLM09: Overreliance
  - LLM10: Model Theft

Agentic 漏洞（ASI01-ASI10）：
  - Goal Theft, Recursive Hijacking
  - Tool Orchestration Abuse
  - Agent Identity & Trust Abuse
"""

from __future__ import annotations

import logging
import os
import sys
import time
from typing import Any, Dict, List

from .base_adapter import AdapterResult, BaseAdapter

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    os.environ["PYTHONIOENCODING"] = "utf-8"

logger = logging.getLogger(__name__)

# DeepTeam 漏洞类型 → OWASP 映射
VULNERABILITY_OWASP_MAP = {
    "prompt_injection": "LLM01",
    "jailbreak": "LLM01",
    "leakage": "LLM02",
    "data_exposure": "LLM02",
    "pii_leakage": "LLM02",
    "poisoning": "LLM03",
    "insecure_output": "LLM04",
    "excessive_agency": "LLM05",
    "system_prompt": "LLM06",
    "rag": "LLM07",
    "bias": "LLM08",
    "toxicity": "LLM09",
    "hallucination": "LLM09",
    "model_theft": "LLM10",
    # Agentic
    "goal_theft": "ASI01",
    "recursive_hijacking": "ASI02",
    "tool_abuse": "ASI03",
    "identity_abuse": "ASI04",
}

# 默认漏洞类型（覆盖 AI-300 核心考点）
DEFAULT_VULNERABILITIES = [
    "prompt_injection",
    "jailbreak",
    "leakage",
    "poisoning",
    "insecure_output",
    "excessive_agency",
    "system_prompt",
    "rag",
    "bias",
    "toxicity",
    "hallucination",
]


class DeepTeamAdapter(BaseAdapter):
    """DeepTeam 薄壳适配器（OWASP 红队扫描）"""

    @property
    def name(self) -> str:
        return "deepteam"

    def check_available(self) -> bool:
        """检查 DeepTeam 是否已安装"""
        try:
            import deepteam  # noqa: F401
            return True
        except ImportError:
            return False

    def run(self, target: str, config: dict) -> AdapterResult:
        """
        执行 DeepTeam 红队扫描

        Args:
            target: 目标 URL/endpoint
            config: 配置字典（vulnerabilities, attacks, model_callback 等）

        Returns:
            AdapterResult
        """
        vulnerabilities = config.get("vulnerabilities", DEFAULT_VULNERABILITIES)
        attacks = config.get("attacks", [])
        start_time = time.time()

        try:
            from deepteam import red_team

            # 构建 model_callback（目标 LLM 的调用函数）
            model_callback = self._build_model_callback(target, config)

            # 执行红队扫描
            result = red_team(
                model_callback=model_callback,
                vulnerabilities=None,  # 使用默认全部
                attacks=None,  # 使用默认全部
                async_mode=False,  # 同步模式（适配框架）
                max_concurrent=5,
            )

            duration = time.time() - start_time

            # 标准化发现
            findings = self._extract_findings(result)

            return AdapterResult(
                tool=self.name,
                success=True,
                data={
                    "vulnerabilities_tested": vulnerabilities,
                    "attacks_used": attacks or "default",
                    "scan_result": str(result),
                },
                findings=findings,
                duration=duration,
                raw_output=str(result),
            )

        except ImportError:
            logger.warning("DeepTeam not installed, skipping")
            return self._make_error_result("DeepTeam not installed (pip install deepteam>=1.0.7)")
        except Exception as e:
            duration = time.time() - start_time
            logger.error("DeepTeam execution failed: %s", str(e))
            return AdapterResult(
                tool=self.name,
                success=False,
                errors=[str(e)],
                duration=duration,
            )

    def _build_model_callback(self, target: str, config: dict):
        """
        构建 DeepTeam 所需的 model_callback 函数

        Args:
            target: 目标 URL
            config: 配置（api_key, model 等）

        Returns:
            callback 函数: str → str
        """
        import json
        import urllib.request

        api_key = config.get("api_key", "")
        model = config.get("model", "")
        timeout = config.get("timeout", 60)

        def model_callback(prompt: str) -> str:
            """调用目标 LLM 并返回回答"""
            try:
                payload = json.dumps({
                    "model": model,
                    "messages": [{"role": "user", "content": prompt}],
                    "max_tokens": 1024,
                }).encode("utf-8")

                req = urllib.request.Request(
                    target,
                    data=payload,
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                if api_key:
                    req.add_header("Authorization", f"Bearer {api_key}")

                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    response = json.loads(resp.read().decode("utf-8"))
                    return response.get("choices", [{}])[0].get("message", {}).get("content", "")
            except Exception as e:
                logger.warning("Model callback failed: %s", str(e))
                return ""

        return model_callback

    def _extract_findings(self, result: Any) -> List[Dict[str, Any]]:
        """从 DeepTeam 结果中提取标准化发现"""
        findings = []

        # DeepTeam 返回 RedTeamResult 对象
        if hasattr(result, 'test_cases'):
            for tc in result.test_cases:
                finding = {
                    "category": getattr(tc, 'vulnerability_type', 'unknown'),
                    "severity": getattr(tc, 'severity', 'medium'),
                    "description": getattr(tc, 'input', ''),
                    "evidence": getattr(tc, 'actual_output', ''),
                    "owasp_mapping": VULNERABILITY_OWASP_MAP.get(
                        getattr(tc, 'vulnerability_type', '').lower(), ""
                    ),
                    "confidence": float(getattr(tc, 'score', 0.5)),
                }
                findings.append(finding)
        elif isinstance(result, dict):
            # 兼容字典格式
            for vuln_type, vuln_results in result.items():
                if isinstance(vuln_results, list):
                    for r in vuln_results:
                        finding = {
                            "category": vuln_type,
                            "severity": r.get("severity", "medium"),
                            "description": r.get("description", ""),
                            "evidence": str(r.get("evidence", "")),
                            "owasp_mapping": VULNERABILITY_OWASP_MAP.get(vuln_type.lower(), ""),
                            "confidence": float(r.get("score", 0.5)),
                        }
                        findings.append(finding)

        return findings
