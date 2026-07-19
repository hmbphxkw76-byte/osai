# -*- coding: utf-8 -*-
"""
AI-300 Framework - Garak Adapter (v2 Optimized)
Garak 适配器：LLM 漏洞扫描（subprocess 调用独立 venv）

v2 优化项（2026-07-19）:
  - OPT-G1: Probe 动态选择（基于 AIMAP 检测结果）
  - OPT-G2: 深度分层 Probe 策略（quick/standard/deep）
  - OPT-G3: 结果解析增强（hitlog + report.html + fail 记录）
  - OPT-G4: Detector 精确配置（probe-specific detector）
  - OPT-G5: 增量执行缓存（按 target+model+probe 哈希）
  - OPT-G6: 通用预热（vLLM / TGI / OpenAI-compat）

Garak v0.15.1 (NVIDIA, LLM vulnerability scanner)
- 独立 venv 安装：uv venv .garak && .garak/Scripts/pip install -r garak-requirements.txt
- 调用方式：subprocess 调用 .garak/Scripts/python -m garak
- 输出解析：读取 garak_output/*.jsonl + hitlog/*.jsonl
"""

from __future__ import annotations

import hashlib
import json
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
    "lmrc": "LLM01",
    "latentinjection": "LLM01",
    "visual_jailbreak": "LLM01",
    "malgen": "LLM02",
    "leakreplay": "LLM02",
    "hallucination": "LLM09",
    "misinformation": "LLM08",
    "toxicity": "LLM03",
    "av_spam": "LLM03",
    "xss": "LLM04",
}

# ── OPT-G2: 深度分层 Probe 策略 ──
PROBES_BY_DEPTH: Dict[str, List[str]] = {
    "quick": [
        "promptinject",
        "dan",
    ],
    "standard": [
        "promptinject",
        "dan",
        "malgen",
        "hallucination",
        "misinformation",
        "toxicity",
    ],
    "deep": [
        "promptinject",
        "dan",
        "jailbreak",
        "continuation",
        "goodside",
        "encoder",
        "lmrc",
        "malgen",
        "leakreplay",
        "hallucination",
        "misinformation",
        "toxicity",
        "av_spam",
        "xss",
    ],
}

# ── OPT-G4: Detector 精确配置 ──
PROBE_DETECTOR_MAP: Dict[str, str] = {
    "promptinject": "mitigation.MitigationBypass",
    "dan": "jailbreak.JailbreakDetect",
    "jailbreak": "jailbreak.JailbreakDetect",
    "continuation": "continuation.ContinuationDetect",
    "goodside": "jailbreak.JailbreakDetect",
    "encoder": "encoding.EncodingDetect",
    "lmrc": "jailbreak.JailbreakDetect",
    "malgen": "malware.MalwareFamilyDetector",
    "leakreplay": "leakreplay.LeakReplayDetect",
    "hallucination": "hallucination.HallucinationDetector",
    "misinformation": "misinformation.MisinformationDetector",
    "toxicity": "toxicity.ToxicityDetector",
    "av_spam": "spam.SpamDetector",
    "xss": "xss.XPathDetector",
    "visual_jailbreak": "jailbreak.JailbreakDetect",
}

# 默认 probe 列表（覆盖 AI-300 核心考点，向后兼容）
DEFAULT_PROBES = PROBES_BY_DEPTH["standard"]

# Garak venv 路径（相对项目根目录）
GARAK_VENV_DIR = ".garak"
GARAK_REQUIREMENTS = "garak-requirements.txt"

# ── OPT-G5: 缓存目录 ──
GARAK_CACHE_DIR = "results/recon/cache/garak"


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
    """Garak 薄壳适配器 v2（LLM 漏洞扫描，subprocess 模式）"""

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
        执行 Garak 漏洞扫描（v2 优化版）

        Args:
            target: 目标 URL/endpoint（如 http://www.example.com 或 http://localhost:11434/v1）
            config: 配置字典（probes, detectors, model_name, timeout, depth,
                    aimap_data, use_cache 等）

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

        # ── OPT-G1: Probe 动态选择 ──
        probes = self._select_probes(config)
        # ── OPT-G4: Detector 精确配置 ──
        detectors = self._select_detectors(probes, config)
        model_name = config.get("model_name", "")
        model_type = config.get("model_type", "")
        # ── OPT-E3: 深度自适应超时 ──
        depth = config.get("depth", "standard")
        timeout = config.get("timeout") or self._get_depth_timeout(depth)
        # ── OPT-G5: 增量缓存 ──
        use_cache = config.get("use_cache", True)
        cache_key = self._compute_cache_key(target, model_name, probes, depth)

        # 检查缓存
        if use_cache:
            cached = self._load_cache(cache_key)
            if cached:
                logger.info("Garak cache hit: %s (skipping execution)", cache_key)
                cached["cache_hit"] = True
                return AdapterResult(
                    tool=self.name,
                    success=True,
                    data=cached.get("data", {}),
                    findings=cached.get("findings", []),
                    duration=0.0,
                    raw_output="[CACHED] " + cached.get("data", {}).get("stdout_tail", "")[:200],
                )

        try:
            # 构建 Garak CLI 参数
            garak_args = self._build_garak_args(target, probes, detectors, model_name, model_type)

            # 环境变量（支持目标 endpoint）
            env = os.environ.copy()
            if target and target.startswith("http"):
                env["OPENAI_BASE_URL"] = target

            # ── OPT-G6: 通用预热 ──
            warmup = config.get("warmup", True)
            if warmup:
                self._warmup_target(target, model_name, model_type)

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

            # ── OPT-G3: 结果解析增强 ──
            findings = self._parse_garak_output_enhanced()

            # garak 返回非零但仍有输出时，标记为部分成功
            success = result.returncode == 0 or len(findings) > 0
            errors = []
            if result.returncode != 0:
                errors.append(f"garak exit code {result.returncode}: {result.stderr[:500]}")

            result_data = {
                "probes_used": probes,
                "detectors_used": detectors or "default",
                "model_name": model_name or "auto-detected",
                "model_type": model_type or "auto-detected",
                "garak_args": garak_args,
                "exit_code": result.returncode,
                "stdout_tail": result.stdout[-1000:] if result.stdout else "",
                "depth": depth,
                "cache_key": cache_key,
            }

            # ── OPT-G5: 保存缓存 ──
            if use_cache and success:
                self._save_cache(cache_key, {"data": result_data, "findings": findings})

            return AdapterResult(
                tool=self.name,
                success=success,
                data=result_data,
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

    # ── OPT-G1: Probe 动态选择 ──

    def _select_probes(self, config: dict) -> List[str]:
        """
        动态选择 Probe（OPT-G1）

        策略：
        1. 用户显式配置 probes -> 使用用户配置
        2. 基于 AIMAP 检测结果（aimap_data）动态选择
        3. 基于深度分层（OPT-G2）选择
        """
        # 1. 用户显式配置优先
        user_probes = config.get("probes")
        if user_probes:
            return user_probes

        # 2. 基于 AIMAP 数据动态选择
        aimap_data = config.get("aimap_data", {})
        depth = config.get("depth", "standard")

        # 基础 probe 集（按深度分层）
        base_probes = list(PROBES_BY_DEPTH.get(depth, PROBES_BY_DEPTH["standard"]))

        # AIMAP 驱动的动态扩展
        detected_protocols = aimap_data.get("detected_protocols", [])
        surfaces = aimap_data.get("surfaces", [])
        capabilities = aimap_data.get("capabilities", [])
        model_family = aimap_data.get("model_family", "")

        # MCP -> 增加 lmrc
        if "mcp" in detected_protocols and "lmrc" not in base_probes:
            base_probes.append("lmrc")

        # function_calling -> 增加 promptinject（已包含）
        if "function_calling" in capabilities and "promptinject" not in base_probes:
            base_probes.append("promptinject")

        # RAG -> 增加 leakreplay
        if "rag" in surfaces and "leakreplay" not in base_probes and depth == "deep":
            base_probes.append("leakreplay")

        # Llama 家族 -> 增加 continuation
        if model_family == "llama" and "continuation" not in base_probes and depth != "quick":
            base_probes.append("continuation")

        # vision -> 增加 visual_jailbreak
        if "vision" in capabilities and "visual_jailbreak" not in base_probes:
            base_probes.append("visual_jailbreak")

        # 向量 DB -> 增加 leakreplay
        if "vector" in surfaces and "leakreplay" not in base_probes and depth != "quick":
            base_probes.append("leakreplay")

        logger.info("Garak probes selected (dynamic): %s (depth=%s)", base_probes, depth)
        return base_probes

    # ── OPT-G2: 深度自适应超时 ──

    @staticmethod
    def _get_depth_timeout(depth: str) -> int:
        """深度自适应超时（OPT-G2 + OPT-E3）"""
        timeouts = {
            "quick": 120,
            "standard": 300,
            "deep": 600,
        }
        return timeouts.get(depth, 300)

    # ── OPT-G4: Detector 精确配置 ──

    @staticmethod
    def _select_detectors(probes: List[str], config: dict) -> List[str]:
        """
        Detector 精确配置（OPT-G4）

        策略：
        1. 用户显式配置 detectors -> 使用用户配置
        2. 基于 probe 列表自动匹配 detector
        """
        user_detectors = config.get("detectors")
        if user_detectors:
            return user_detectors

        # 自动匹配 detector
        detectors = []
        for probe in probes:
            detector = PROBE_DETECTOR_MAP.get(probe)
            if detector and detector not in detectors:
                detectors.append(detector)

        logger.info("Garak detectors selected: %s", detectors)
        return detectors

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

    # ── OPT-G6: 通用预热 ──

    @staticmethod
    def _warmup_target(target: str, model_name: str, model_type: str) -> None:
        """
        通用预热（OPT-G6 优化）

        根据目标类型发送最小请求确保端点就绪：
        - Ollama: POST /api/generate with num_predict=1
        - vLLM / OpenAI-compat: POST /v1/chat/completions with max_tokens=1
        - TGI: POST /generate with max_new_tokens=1
        - 通用: GET /v1/models 确保端点可达
        """
        import urllib.request

        base_url = target.rstrip("/")

        # 规范化 URL
        if base_url.endswith("/v1"):
            api_base = base_url
            raw_base = base_url[:-3]
        else:
            api_base = base_url + "/v1" if not base_url.endswith("/v1") else base_url
            raw_base = base_url

        # Ollama 预热
        if GarakAdapter._is_ollama_target(target):
            GarakAdapter._warmup_ollama(target, model_name)
            return

        # vLLM / OpenAI-compat 预热
        try:
            warmup_url = f"{api_base}/chat/completions"
            payload = json.dumps({
                "model": model_name or "gpt-4o",
                "messages": [{"role": "user", "content": "hi"}],
                "max_tokens": 1,
            }).encode("utf-8")

            req = urllib.request.Request(
                warmup_url,
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )

            logger.info("Warming up target at %s", warmup_url)
            with urllib.request.urlopen(req, timeout=60) as resp:
                resp.read()
            logger.info("Target warmup complete")
        except Exception as e:
            # 降级：尝试 GET /v1/models
            try:
                models_url = f"{api_base}/models"
                req = urllib.request.Request(models_url, method="GET")
                logger.info("Fallback warmup: GET %s", models_url)
                with urllib.request.urlopen(req, timeout=30) as resp:
                    resp.read()
            except Exception:
                logger.warning("Target warmup failed (non-fatal): %s", str(e))

    @staticmethod
    def _warmup_ollama(target: str, model_name: str) -> None:
        """
        预热 Ollama 模型：发送短请求确保模型已加载到内存

        Ollama 默认 5 分钟空闲后卸载模型，首次请求返回 done_reason:"load" + 空 response。
        预热请求提前触发模型加载，避免 Garak 扫描时超时。
        """
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

    # ── OPT-G3: 结果解析增强 ──

    def _parse_garak_output_enhanced(self) -> List[Dict[str, Any]]:
        """
        结果解析增强（OPT-G3 优化）

        解析内容：
        1. garak_output/*.jsonl 中 status=completed 的记录（原有）
        2. hitlog/*.jsonl 更详细的命中日志（新增）
        3. fail 记录（探测失败 != 无漏洞，可能是超时）（新增）
        4. 提取 trigger 信息（具体触发的 payload）（新增）
        """
        findings = []

        # 1. 解析 garak_output/*.jsonl（主输出）
        output_dir = Path("garak_output")
        if output_dir.exists():
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
                                        "trigger": record.get("prompt", record.get("trigger", "")),
                                        "source": "garak_output",
                                    }
                                    findings.append(finding)
                                elif record.get("status") == "fail":
                                    # 探测失败记录（可能是超时或错误，不等于无漏洞）
                                    finding = {
                                        "category": record.get("probe", "unknown"),
                                        "severity": "low",
                                        "description": f"Garak probe failed (may be timeout/error): {record.get('error', '')}",
                                        "evidence": str(record.get("output", "")),
                                        "owasp_mapping": PROBE_OWASP_MAP.get(
                                            record.get("probe", "").lower(), ""
                                        ),
                                        "confidence": 0.3,
                                        "trigger": record.get("prompt", ""),
                                        "source": "garak_output_fail",
                                    }
                                    findings.append(finding)
                            except json.JSONDecodeError:
                                continue
                except Exception as e:
                    logger.warning("Failed to parse %s: %s", jsonl_file, str(e))

        # 2. 解析 hitlog/*.jsonl（更详细的命中日志）
        hitlog_dir = Path("garak_output/hitlog")
        if not hitlog_dir.exists():
            hitlog_dir = Path("hitlog")
        if hitlog_dir.exists():
            for jsonl_file in hitlog_dir.glob("*.jsonl"):
                try:
                    with open(jsonl_file, "r", encoding="utf-8") as f:
                        for line in f:
                            line = line.strip()
                            if not line:
                                continue
                            try:
                                record = json.loads(line)
                                # hitlog 记录通常包含更详细的触发信息
                                finding = {
                                    "category": record.get("probe", record.get("module", "unknown")),
                                    "severity": self._map_severity(record.get("score", 0.7)),
                                    "description": f"Hit: {record.get('detector', record.get('description', ''))}",
                                    "evidence": str(record.get("output", record.get("response", ""))),
                                    "owasp_mapping": PROBE_OWASP_MAP.get(
                                        record.get("probe", "").lower(), ""
                                    ),
                                    "confidence": float(record.get("score", 0.7)),
                                    "trigger": record.get("prompt", record.get("input", "")),
                                    "source": "hitlog",
                                }
                                findings.append(finding)
                            except json.JSONDecodeError:
                                continue
                except Exception as e:
                    logger.warning("Failed to parse hitlog %s: %s", jsonl_file, str(e))

        # 3. 解析 garak_report.html 中的汇总统计（如果存在）
        report_html = Path("garak_output/garak_report.html")
        if report_html.exists():
            try:
                content = report_html.read_text(encoding="utf-8", errors="replace")
                # 提取简单的统计信息
                if "overall" in content.lower():
                    # 查找 pass/fail 比率
                    import re
                    pass_match = re.search(r"pass[:\s]+([\d.]+)", content, re.IGNORECASE)
                    fail_match = re.search(r"fail[:\s]+([\d.]+)", content, re.IGNORECASE)
                    if pass_match or fail_match:
                        finding = {
                            "category": "garak_summary",
                            "severity": "low",
                            "description": f"Garak summary: pass={pass_match.group(1) if pass_match else 'N/A'}, fail={fail_match.group(1) if fail_match else 'N/A'}",
                            "evidence": content[:500],
                            "owasp_mapping": "",
                            "confidence": 0.5,
                            "trigger": "",
                            "source": "garak_report_html",
                        }
                        findings.append(finding)
            except Exception as e:
                logger.warning("Failed to parse garak_report.html: %s", str(e))

        return findings

    def _parse_garak_output(self) -> List[Dict[str, Any]]:
        """解析 Garak JSONL 输出（向后兼容）"""
        return self._parse_garak_output_enhanced()

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

    # ── OPT-G5: 增量缓存 ──

    @staticmethod
    def _compute_cache_key(target: str, model_name: str, probes: List[str], depth: str) -> str:
        """计算缓存键（target + model + probes + depth 的哈希）"""
        key_str = f"{target}|{model_name}|{','.join(sorted(probes))}|{depth}"
        return hashlib.md5(key_str.encode("utf-8")).hexdigest()

    @staticmethod
    def _load_cache(cache_key: str) -> Optional[Dict[str, Any]]:
        """加载缓存"""
        cache_file = Path(GARAK_CACHE_DIR) / f"{cache_key}.json"
        if not cache_file.exists():
            return None

        # 检查缓存是否过期（24小时）
        import time as _time
        mtime = cache_file.stat().st_mtime
        if _time.time() - mtime > 86400:  # 24h
            logger.debug("Garak cache expired: %s", cache_key)
            return None

        try:
            with open(cache_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            logger.warning("Failed to load garak cache: %s", str(e))
            return None

    @staticmethod
    def _save_cache(cache_key: str, data: Dict[str, Any]) -> None:
        """保存缓存"""
        cache_dir = Path(GARAK_CACHE_DIR)
        cache_dir.mkdir(parents=True, exist_ok=True)
        cache_file = cache_dir / f"{cache_key}.json"
        try:
            with open(cache_file, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            logger.info("Garak cache saved: %s", cache_key)
        except Exception as e:
            logger.warning("Failed to save garak cache: %s", str(e))
