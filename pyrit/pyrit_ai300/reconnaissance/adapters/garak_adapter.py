# -*- coding: utf-8 -*-
"""
AI-300 Framework - Garak Adapter
Garak 适配器：LLM 漏洞扫描（Python SDK 调用）

Garak v0.15.1 (NVIDIA, LLM vulnerability scanner)
- PyPI: pip install garak>=0.15.1
- CLI: garak --model_type openai --model_name gpt-4o --probes promptinject
- Python API: garak.cli.main() 或 garak.run

核心 probe 直接对应 AI-300 考点：
  - promptinject → LLM01 Prompt Injection
  - malgen → LLM06 Sensitive Information Disclosure
  - hallucination → LLM09 Overreliance
  - misinformation → LLM08 Excessive Agency
  - toxicity → LLM03 Training Data Poisoning
  - dan/jailbreak → LLM01 Jailbreak
  - continuation → LLM01 Jailbreak
  - goodside → LLM01 Prompt Injection
  - av_spam → LLM03 Training Data Poisoning
  - leakreplay → LLM06 Sensitive Information Disclosure
  - xss → LLM04 Insecure Output Handling
  - encoder → LLM01 Prompt Injection
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

# Garak probe → OWASP 映射
PROBE_OWASP_MAP = {
    "promptinject": "LLM01",
    "dan": "LLM01",
    "jailbreak": "LLM01",
    "continuation": "LLM01",
    "goodside": "LLM01",
    "encoder": "LLM01",
    "malgen": "LLM06",
    "leakreplay": "LLM06",
    "hallucination": "LLM09",
    "misinformation": "LLM08",
    "toxicity": "LLM03",
    "av_spam": "LLM03",
    "xss": "LLM04",
}

# 默认 probe 列表（覆盖 AI-300 核心考点）
DEFAULT_PROBES = [
    "promptinject",
    "dan",
    "malgen",
    "hallucination",
    "misinformation",
    "toxicity",
]


class GarakAdapter(BaseAdapter):
    """Garak 薄壳适配器（LLM 漏洞扫描）"""

    @property
    def name(self) -> str:
        return "garak"

    def check_available(self) -> bool:
        """检查 Garak 是否已安装"""
        try:
            import garak  # noqa: F401
            return True
        except ImportError:
            return False

    def run(self, target: str, config: dict) -> AdapterResult:
        """
        执行 Garak 漏洞扫描

        Args:
            target: 目标 URL/endpoint（如 http://student.syxy.com 或 http://localhost:11434/v1）
            config: 配置字典（probes, detectors, model_name, timeout 等）

        Returns:
            AdapterResult
        """
        probes = config.get("probes", DEFAULT_PROBES)
        detectors = config.get("detectors", [])
        model_name = config.get("model_name", "")
        start_time = time.time()

        try:
            from garak import cli as garak_cli

            # 构建 Garak CLI 参数
            garak_args = self._build_garak_args(target, probes, detectors, model_name)

            # 支持直接 URL 目标：通过环境变量传递 endpoint
            if target and target.startswith("http"):
                os.environ["OPENAI_BASE_URL"] = target

            # 执行扫描（通过 CLI 入口）
            garak_cli.main(garak_args)

            duration = time.time() - start_time

            # 读取 Garak 报告（JSONL 格式）
            findings = self._parse_garak_output()

            return AdapterResult(
                tool=self.name,
                success=True,
                data={
                    "probes_used": probes,
                    "detectors_used": detectors or "default",
                    "model_name": model_name,
                    "garak_args": garak_args,
                },
                findings=findings,
                duration=duration,
                raw_output=f"garak {' '.join(garak_args)}",
            )

        except ImportError:
            logger.warning("Garak not installed, skipping")
            return self._make_error_result("Garak not installed (pip install garak>=0.15.1)")
        except Exception as e:
            duration = time.time() - start_time
            logger.error("Garak execution failed: %s", str(e))
            return AdapterResult(
                tool=self.name,
                success=False,
                errors=[str(e)],
                duration=duration,
            )

    def _build_garak_args(
        self,
        target: str,
        probes: List[str],
        detectors: List[str],
        model_name: str,
    ) -> List[str]:
        """构建 Garak CLI 参数"""
        args = [
            "--model_type", "openai",
            "--model_name", model_name or "gpt-4o",
            "--probes", ",".join(probes),
        ]
        # 支持直接 URL 目标（如 http://student.syxy.com）
        if target and target.startswith("http"):
            # Garak 通过 OPENAI_BASE_URL 环境变量或 --endpoint 传递 endpoint
            # 检查 Garak 是否支持 --endpoint 参数
            args.extend(["--endpoint", target])
        if detectors:
            args.extend(["--detectors", ",".join(detectors)])
        return args

    def _parse_garak_output(self) -> List[Dict[str, Any]]:
        """解析 Garak JSONL 输出"""
        import json
        from pathlib import Path

        findings = []

        # Garak 输出目录
        output_dir = Path("garak_output")
        if not output_dir.exists():
            return findings

        for jsonl_file in output_dir.glob("*.jsonl"):
            try:
                with open(jsonl_file, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            record = json.loads(line)
                            if record.get("status") == "completed":
                                finding = {
                                    "category": record.get("probe", "unknown"),
                                    "severity": self._map_severity(record.get("score", 0)),
                                    "description": record.get("detector", ""),
                                    "evidence": str(record.get("output", "")),
                                    "owasp_mapping": PROBE_OWASP_MAP.get(
                                        record.get("probe", "").lower(), ""
                                    ),
                                    "confidence": float(record.get("score", 0.5)),
                                }
                                findings.append(finding)
                        except json.JSONDecodeError:
                            continue
            except Exception as e:
                logger.warning("Failed to parse %s: %s", jsonl_file, str(e))

        return findings

    @staticmethod
    def _map_severity(score: float) -> str:
        """分数映射到严重程度"""
        if score >= 0.8:
            return "critical"
        elif score >= 0.6:
            return "high"
        elif score >= 0.4:
            return "medium"
        return "low"
