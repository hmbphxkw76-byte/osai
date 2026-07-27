# -*- coding: utf-8 -*-
"""
Garak Adapter
=============

通过 subprocess 调用 Garak CLI 执行 LLM 漏洞扫描。
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, List

import yaml

from ai300_schemas import PyRITTargetConfig, UnifiedFinding

from ..adapters.base import AttackAdapter, AttackResult, AttackStrategy
from ..reporting.unified_converter import finding_from_garak

logger = logging.getLogger(__name__)


class GarakAdapter(AttackAdapter):
    """Garak CLI 适配器"""

    name = "garak"

    def is_available(self) -> bool:
        """检查 garak 命令是否可用"""
        return shutil.which("garak") is not None

    def supported_strategies(self) -> List[str]:
        return [
            "jailbreak_direct",
            "api_prompt_injection",
            "web_ui_prompt_injection",
            "rag_context_manipulation",
            "agent_tool_misuse",
            "sensitive_data_exfil",
        ]

    def run(
        self,
        target: PyRITTargetConfig,
        strategy: AttackStrategy,
    ) -> AttackResult:
        """
        调用 Garak 执行指定策略。

        Args:
            target: PyRIT target 配置（含 endpoint、model_name 等）
            strategy: 攻击策略
        """
        if not self.is_available():
            return AttackResult(
                adapter=self.name,
                strategy=strategy.name,
                success=False,
                error="garak command not found. Install with: pip install garak",
            )

        probes = strategy.tool_params.get("probes", ["promptinject"])
        model_type = self._infer_garak_model_type(target)

        # Garak 输出目录
        output_dir = Path(self.config.get("output_dir", "results/attacks/garak"))
        output_dir.mkdir(parents=True, exist_ok=True)
        report_dir = tempfile.mkdtemp(prefix="garak_", dir=str(output_dir))

        cmd = self._build_command(
            model_type=model_type,
            target=target,
            probes=probes,
            report_dir=report_dir,
        )

        logger.info("Running Garak: %s", " ".join(cmd))

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.config.get("timeout", 300),
                check=False,
            )
        except subprocess.TimeoutExpired:
            return AttackResult(
                adapter=self.name,
                strategy=strategy.name,
                success=False,
                error=f"Garak timed out after {self.config.get('timeout', 300)}s",
            )
        except Exception as exc:
            return AttackResult(
                adapter=self.name,
                strategy=strategy.name,
                success=False,
                error=str(exc),
            )

        # 解析 Garak 报告
        findings = self._parse_garak_report(report_dir, target)

        return AttackResult(
            adapter=self.name,
            strategy=strategy.name,
            success=result.returncode in (0, 1),  # Garak 可能以 1 返回有发现
            findings=findings,
            raw_output={
                "returncode": result.returncode,
                "stdout": result.stdout[-5000:] if result.stdout else "",
                "stderr": result.stderr[-2000:] if result.stderr else "",
                "report_dir": report_dir,
            },
            error=result.stderr[-1000:] if result.returncode not in (0, 1) else "",
        )

    def _infer_garak_model_type(self, target: PyRITTargetConfig) -> str:
        """根据 target 推断 Garak model_type"""
        tt = target.target_type
        if tt == "AzureOpenAITarget":
            return "azure"
        if tt == "OpenAITarget":
            return "openai"

        api_type = target.api_type.lower()
        if "azure" in api_type:
            return "azure"
        # 本地或 OpenAI 兼容服务使用 OpenAICompatible generator
        if "openai_compatible" in api_type or self._is_local_endpoint(target.endpoint):
            return "openai.OpenAICompatible"
        if "openai" in api_type:
            return "openai"
        if "huggingface" in api_type:
            return "huggingface"
        # 默认使用 openai 兼容
        return "openai.OpenAICompatible"

    def _is_local_endpoint(self, endpoint: str) -> bool:
        """判断 endpoint 是否为本地地址"""
        if not endpoint:
            return False
        lower = endpoint.lower()
        return lower.startswith("http://127.") or lower.startswith("http://localhost")

    def _openai_base_url(self, endpoint: str) -> str:
        """从 OpenAI chat/completions endpoint 提取 base_url"""
        # endpoint: http://host/v1/chat/completions -> http://host/v1/
        if endpoint.endswith("/chat/completions"):
            return endpoint[: -len("chat/completions")]
        # 兜底：确保以 /v1/ 结尾
        if "/v1" in endpoint:
            return endpoint.split("/v1")[0] + "/v1/"
        return endpoint.rstrip("/") + "/v1/"

    def _build_command(
        self,
        model_type: str,
        target: PyRITTargetConfig,
        probes: List[str],
        report_dir: str,
    ) -> List[str]:
        """构造 Garak 命令"""
        cmd = [
            "garak",
            "--model_type",
            model_type,
            "--model_name",
            target.model_name or "default",
            "--probes",
            ",".join(probes),
            "--generations",
            "1",
            "--report_prefix",
            os.path.join(report_dir, "report"),
        ]

        # OpenAI 兼容服务通过 YAML 配置文件传入 base_url / api_key
        if model_type == "openai.OpenAICompatible":
            config_path = self._write_garak_config(report_dir, target)
            cmd.extend(["--config", config_path])
            os.environ.setdefault(
                "OPENAICOMPATIBLE_API_KEY",
                target.api_key or "sk-mock-no-key",
            )
        elif target.api_key:
            os.environ["OPENAI_API_KEY"] = target.api_key

        # 额外参数
        extra = self.config.get("garak_extra_args", [])
        if extra:
            cmd.extend(extra)

        return cmd

    def _write_garak_config(
        self,
        report_dir: str,
        target: PyRITTargetConfig,
    ) -> str:
        """为 Garak OpenAICompatible generator 生成 YAML 配置文件"""
        uri = self._openai_base_url(target.endpoint or "")
        config: Dict[str, Any] = {
            "plugins": {
                "generators": {
                    "openai": {
                        "OpenAICompatible": {
                            "uri": uri,
                        }
                    }
                }
            }
        }
        config_path = os.path.join(report_dir, "garak_config.yaml")
        with open(config_path, "w", encoding="utf-8") as f:
            yaml.safe_dump(config, f, allow_unicode=True, sort_keys=False)
        return config_path

    def _parse_garak_report(
        self,
        report_dir: str,
        target: PyRITTargetConfig,
    ) -> List[UnifiedFinding]:
        """解析 Garak JSON/JSONL 报告"""
        findings: List[UnifiedFinding] = []

        report_path = Path(report_dir) / "report.report.jsonl"
        if not report_path.exists():
            report_path = Path(report_dir) / "report.report.json"
        if not report_path.exists():
            candidates = list(Path(report_dir).glob("*.json*"))
            if candidates:
                report_path = candidates[0]
            else:
                logger.warning("No Garak report found in %s", report_dir)
                return findings

        try:
            entries: List[Dict[str, Any]] = []
            if report_path.suffix == ".jsonl":
                with open(report_path, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            entries.append(json.loads(line))
            else:
                with open(report_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    entries = data if isinstance(data, list) else data.get("entries", data.get("runs", []))
        except Exception as exc:
            logger.warning("Failed to parse Garak report: %s", exc)
            return findings

        for entry in entries:
            if not isinstance(entry, dict):
                continue
            if entry.get("entry_type") != "attempt":
                continue

            probe = entry.get("probe_classname", "unknown")
            prompt_turns = entry.get("prompt", {}).get("turns", [])
            prompt = ""
            if prompt_turns and isinstance(prompt_turns[0], dict):
                prompt = prompt_turns[0].get("content", {}).get("text", "")
            outputs = entry.get("outputs", [])
            output = ""
            if outputs and isinstance(outputs[0], dict):
                output = outputs[0].get("text", "")

            # detector_results 为空则默认通过；存在 hit 则认为未通过
            detector_results = entry.get("detector_results", {})
            passed = True
            if detector_results:
                passed = not any(
                    isinstance(v, dict) and v.get("hit") for v in detector_results.values()
                )

            findings.append(
                finding_from_garak(
                    probe_name=probe,
                    detector_name=entry.get("goal", "unknown"),
                    prompt=prompt,
                    output=output,
                    passed=passed,
                    target=target.endpoint,
                    endpoint_url=target.endpoint,
                )
            )

        return findings
