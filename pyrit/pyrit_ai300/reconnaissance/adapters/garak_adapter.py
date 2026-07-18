# -*- coding: utf-8 -*-
"""
AI-300 Framework - Garak Adapter
Garak 适配器：LLM 漏洞扫描（subprocess 调用独立 venv）

Garak v0.15.1 (NVIDIA, LLM vulnerability scanner)
- 独立 venv 安装：uv venv .garak && .garak/Scripts/pip install -r garak-requirements.txt
- 调用方式：subprocess 调用 .garak/Scripts/python -m garak
- 输出解析：读取 garak_output/*.jsonl

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
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

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

# Garak venv 路径（相对项目根目录）
GARAK_VENV_DIR = ".garak"
GARAK_REQUIREMENTS = "garak-requirements.txt"


def _get_garak_python() -> Optional[str]:
    """
    自动检测 garak Python 解释器路径

    优先级：
    1. 环境变量 GARAK_PYTHON
    2. 项目根目录下 .garak venv
    3. 系统 PATH 中的 garak 命令

    Returns:
        Python 解释器路径，未找到返回 None
    """
    # 1. 环境变量覆盖
    env_path = os.environ.get("GARAK_PYTHON")
    if env_path and Path(env_path).exists():
        return env_path

    # 2. 项目根目录 .garak venv
    # 从当前文件位置向上找到项目根目录（pyrit_ai300/ 的父目录）
    project_root = Path(__file__).resolve().parent.parent.parent.parent
    if sys.platform == "win32":
        venv_python = project_root / GARAK_VENV_DIR / "Scripts" / "python.exe"
    else:
        venv_python = project_root / GARAK_VENV_DIR / "bin" / "python"

    if venv_python.exists():
        return str(venv_python)

    # 3. 系统 PATH 中查找 garak
    garak_cmd = shutil.which("garak")
    if garak_cmd:
        return garak_cmd

    return None


class GarakAdapter(BaseAdapter):
    """Garak 薄壳适配器（LLM 漏洞扫描，subprocess 模式）"""

    @property
    def name(self) -> str:
        return "garak"

    def check_available(self) -> bool:
        """检查 Garak 是否可用（检测 venv 或系统命令）"""
        garak_path = _get_garak_python()
        if not garak_path:
            return False

        # 验证 garak 模块可执行
        try:
            result = subprocess.run(
                [garak_path, "-c", "import garak; print(garak.__version__)"],
                capture_output=True, text=True, timeout=30,
            )
            if result.returncode == 0:
                version = result.stdout.strip()
                logger.info("Garak found: version=%s, path=%s", version, garak_path)
                return True
        except Exception:
            pass
        return False

    def run(self, target: str, config: dict) -> AdapterResult:
        """
        执行 Garak 漏洞扫描（subprocess 模式）

        Args:
            target: 目标 URL/endpoint（如 http://www.example.com 或 http://localhost:11434/v1）
            config: 配置字典（probes, detectors, model_name, timeout 等）

        Returns:
            AdapterResult
        """
        start_time = time.time()

        # 检测 garak 路径
        garak_python = _get_garak_python()
        if not garak_python:
            return self._make_error_result(
                "Garak not found. Run: uv venv .garak && .garak/Scripts/pip install -r garak-requirements.txt"
            )

        probes = config.get("probes", DEFAULT_PROBES)
        detectors = config.get("detectors", [])
        model_name = config.get("model_name", "")
        model_type = config.get("model_type", "")
        timeout = config.get("timeout", 600)

        try:
            # 构建 Garak CLI 参数
            garak_args = self._build_garak_args(target, probes, detectors, model_name, model_type)

            # 环境变量（支持目标 endpoint）
            env = os.environ.copy()
            if target and target.startswith("http"):
                env["OPENAI_BASE_URL"] = target

            # Ollama 预热：确保模型已加载（避免首次请求超时）
            warmup = config.get("warmup", True)
            if warmup and self._is_ollama_target(target):
                self._warmup_ollama(target, model_name)

            # 执行 garak（subprocess）
            cmd = [garak_python, "-m", "garak"] + garak_args
            logger.info("Running garak: %s", " ".join(cmd))

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                env=env,
                cwd=str(Path(__file__).resolve().parent.parent.parent.parent),
            )

            duration = time.time() - start_time

            # 读取 Garak 报告（JSONL 格式）
            findings = self._parse_garak_output()

            # garak 返回非零但仍有输出时，标记为部分成功
            success = result.returncode == 0 or len(findings) > 0
            errors = []
            if result.returncode != 0:
                errors.append(f"garak exit code {result.returncode}: {result.stderr[:500]}")

            return AdapterResult(
                tool=self.name,
                success=success,
                data={
                    "probes_used": probes,
                    "detectors_used": detectors or "default",
                    "model_name": model_name or "auto-detected",
                    "model_type": model_type or "auto-detected",
                    "garak_args": garak_args,
                    "exit_code": result.returncode,
                    "stdout_tail": result.stdout[-1000:] if result.stdout else "",
                },
                findings=findings,
                errors=errors,
                duration=duration,
                raw_output=result.stdout[-2000:] if result.stdout else "",
            )

        except subprocess.TimeoutExpired:
            duration = time.time() - start_time
            logger.error("Garak timed out after %ds", timeout)
            return AdapterResult(
                tool=self.name,
                success=False,
                errors=[f"Garak timed out after {timeout}s"],
                duration=duration,
            )
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
        model_type: str = "",
    ) -> List[str]:
        """
        构建 Garak CLI 参数

        自动检测目标类型：
        - Ollama 本地端点（含 /api/tags 或端口 11434）→ --model_type ollama
        - 其他 OpenAI 兼容 → --model_type openai
        """
        # 自动检测目标类型
        detected_type, detected_model = self._detect_target_model(
            target, model_name, model_type
        )

        args = [
            "--model_type", detected_type,
            "--model_name", detected_model,
            "--probes", ",".join(probes),
        ]
        # 支持直接 URL 目标（如 http://www.example.com）
        if target and target.startswith("http"):
            args.extend(["--endpoint", target])
        if detectors:
            args.extend(["--detectors", ",".join(detectors)])
        return args

    @staticmethod
    def _detect_target_model(
        target: str, config_model: str, config_type: str
    ) -> tuple:
        """
        自动检测目标 LLM 类型，返回 (model_type, model_name)

        策略：
        1. 用户显式配置 model_type 且非空 → 使用用户配置
        2. 目标包含 ollama 特征（/api/tags, 端口 11434）→ ollama 类型
        3. 默认 → openai/gpt-4o

        Returns:
            (model_type, model_name) 元组
        """
        # 1. 用户显式配置 model_type 优先
        if config_type and config_model:
            return (config_type, config_model)

        # 2. 检测 Ollama 特征
        ollama_indicators = [
            "11434",           # 默认 Ollama 端口
            "/api/tags",       # Ollama API 路径
            "/api/show",       # Ollama API 路径
            "ollama",          # 主机名含 ollama
        ]
        target_lower = target.lower()
        if any(indicator in target_lower for indicator in ollama_indicators):
            logger.info("Detected Ollama endpoint, using model_type=ollama")
            return ("ollama", config_model or "llama3.2")

        # 3. 默认 OpenAI
        return ("openai", config_model or "gpt-4o")

    @staticmethod
    def _is_ollama_target(target: str) -> bool:
        """检测目标是否为 Ollama 端点"""
        ollama_indicators = ["11434", "/api/tags", "/api/show", "ollama"]
        target_lower = target.lower()
        return any(indicator in target_lower for indicator in ollama_indicators)

    @staticmethod
    def _warmup_ollama(target: str, model_name: str) -> None:
        """
        预热 Ollama 模型：发送短请求确保模型已加载到内存

        Ollama 默认 5 分钟空闲后卸载模型，首次请求返回 done_reason:"load" + 空 response。
        预热请求提前触发模型加载，避免 Garak 扫描时超时。
        """
        import json
        import urllib.request

        # 规范化目标 URL（移除 /v1 后缀，使用 /api/generate）
        base_url = target.rstrip("/").replace("/v1", "")
        if not base_url.endswith("/api/generate"):
            warmup_url = f"{base_url}/api/generate"
        else:
            warmup_url = base_url

        try:
            payload = json.dumps({
                "model": model_name or "llama3.2",
                "prompt": "hi",
                "stream": False,
                "options": {"num_predict": 1},  # 最小化响应
            }).encode("utf-8")

            req = urllib.request.Request(
                warmup_url,
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )

            logger.info("Warming up Ollama model at %s", warmup_url)
            with urllib.request.urlopen(req, timeout=120) as resp:
                resp.read()  # 读取完整响应确保模型加载
            logger.info("Ollama warmup complete")
        except Exception as e:
            logger.warning("Ollama warmup failed (non-fatal): %s", str(e))

    def _parse_garak_output(self) -> List[Dict[str, Any]]:
        """解析 Garak JSONL 输出"""
        import json

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
