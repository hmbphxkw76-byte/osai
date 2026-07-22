# -*- coding: utf-8 -*-
"""
AI-300 Framework - Infrastructure Scan Adapter
AI 基础设施漏洞扫描适配器

设计原则：
- 优雅降级：Nuclei 未安装时使用内置 HTTP 探测
- 薄壳模式：封装 Nuclei 扫描结果，转换为标准 AdapterResult
- 子进程安全：使用 subprocess 调用 Nuclei，带超时控制
- 零硬依赖：Nuclei 为可选依赖，未安装时自动降级到内置探测

来源：protectai/ai-exploits 项目（Metasploit 模块 + Nuclei 模板）

支持的漏洞检测：
  1. Triton Inference Server - RCE (inference_server_rce)
  2. MLflow - LFI / RCE (mlflow_lfi, mlflow_rce)
  3. BentoML - Pickle RCE (bentoml_pickle_rce)
  4. Gradio - LFI (gradio_lfi)
  5. AnythingLLM - Path Traversal (anythingllm_path_traversal)
  6. H2O Flow - LFI / RCE (h2o_flow_rce)
  7. Ray - Command Injection (ray_cmd_injection)
  8. FastAPI/Flask - 信息泄露 (fastapi_info_leak)

OWASP 映射：
  - LLM05 (Supply Chain) - 组件漏洞
  - LLM07 (Insecure Plugin Design) - API 设计缺陷
  - ASI08 (Excessive Agency) - 系统级 RCE

使用方式：
    adapter = InfraScanAdapter()
    result = adapter.run("http://target:8000", config={
        "depth": "standard",
        "use_nuclei": True,  # 尝试使用 Nuclei（如果已安装）
        "timeout": 120,
    })
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

from ..base import AdapterResult, BaseAdapter
from ...utils.http_client import http_get, http_post

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    os.environ["PYTHONIOENCODING"] = "utf-8"

logger = logging.getLogger(__name__)

# Nuclei 可用性标志
NUCLEI_AVAILABLE = shutil.which("nuclei") is not None
if not NUCLEI_AVAILABLE:
    logger.debug("Nuclei not installed - InfraScanAdapter will use built-in HTTP probes")

# 缓存目录
INFRA_CACHE_DIR = "results/recon/cache/infra_scan"


# ── 漏洞检测规则 ──

# AI/ML 基础设施漏洞检测规则
INFRA_VULN_CHECKS: List[Dict[str, Any]] = [
    {
        "id": "triton_rce",
        "name": "Triton Inference Server RCE",
        "severity": "critical",
        "owasp": "ASI08",
        "paths": ["/v2/repository/models", "/v2/health/ready", "/metrics"],
        "methods": ["GET"],
        "patterns": [r"(?i)triton", r"(?i)inference.server", r"NVIDIA"],
        "description": "Triton Inference Server 可能存在远程代码执行漏洞",
        "cve": "CVE-2024-0100",
    },
    {
        "id": "mlflow_lfi",
        "name": "MLflow LFI",
        "severity": "high",
        "owasp": "LLM05",
        "paths": ["/api/2.0/mlflow/experiments/list", "/ajax-api/2.0/mlflow/experiments/list", "/mlflow"],
        "methods": ["GET"],
        "patterns": [r"(?i)mlflow", r"experiment_id", r"mlflow_version"],
        "description": "MLflow 服务器存在本地文件包含漏洞（CVE-2023-42797）",
        "cve": "CVE-2023-42797",
    },
    {
        "id": "bentoml_pickle_rce",
        "name": "BentoML Pickle RCE",
        "severity": "critical",
        "owasp": "ASI08",
        "paths": ["/healthz", "/metrics", "/docs.json"],
        "methods": ["GET"],
        "patterns": [r"(?i)bentoml", r"BentoML", r"bento_service"],
        "description": "BentoML 存在 Pickle 反序列化 RCE 漏洞",
        "cve": "CVE-2024-29117",
    },
    {
        "id": "gradio_lfi",
        "name": "Gradio LFI",
        "severity": "high",
        "owasp": "LLM05",
        "paths": ["/", "/config", "/info"],
        "methods": ["GET"],
        "patterns": [r"(?i)gradio", r"Gradio", r"gradio_version"],
        "description": "Gradio 存在本地文件包含漏洞（CVE-2024-1561）",
        "cve": "CVE-2024-1561",
    },
    {
        "id": "anythingllm_path_traversal",
        "name": "AnythingLLM Path Traversal",
        "severity": "high",
        "owasp": "LLM05",
        "paths": ["/api/system/env-dump", "/api/health", "/api/ping"],
        "methods": ["GET"],
        "patterns": [r"(?i)anythingllm", r"AnythingLLM"],
        "description": "AnythingLLM 存在路径穿越漏洞",
        "cve": "CVE-2024-10325",
    },
    {
        "id": "h2o_flow_rce",
        "name": "H2O Flow RCE",
        "severity": "critical",
        "owasp": "ASI08",
        "paths": ["/3/About", "/flow", "/3/NodePersistentStorage"],
        "methods": ["GET"],
        "patterns": [r"(?i)h2o.ai", r"H2O Flow", r"h2o_cluster"],
        "description": "H2O Flow 存在远程代码执行漏洞",
        "cve": "CVE-2024-27304",
    },
    {
        "id": "ray_cmd_injection",
        "name": "Ray Dashboard Command Injection",
        "severity": "critical",
        "owasp": "ASI08",
        "paths": ["/api/version", "/dashboard", "/api/actors"],
        "methods": ["GET"],
        "patterns": [r"(?i)ray", r"ray_version", r"ray_dashboard"],
        "description": "Ray Dashboard 存在命令注入漏洞（CVE-2023-6019）",
        "cve": "CVE-2023-6019",
    },
    {
        "id": "fastapi_info_leak",
        "name": "FastAPI/Flask Information Disclosure",
        "severity": "medium",
        "owasp": "LLM07",
        "paths": ["/docs", "/openapi.json", "/redoc", "/api/docs", "/swagger"],
        "methods": ["GET"],
        "patterns": [r"(?i)fastapi|flask|openapi|swagger", r"openapi_version", r"info"],
        "description": "API 文档端点暴露，可能导致信息泄露",
        "cve": "",
    },
]


class InfraScanAdapter(BaseAdapter):
    """
    AI 基础设施漏洞扫描适配器

    双模式运行：
    1. Nuclei 可用：调用 Nuclei + AI-Exploits 模板进行专业扫描
    2. Nuclei 不可用：使用内置 HTTP 探测进行轻量扫描

    工作流：
      1. 对目标 URL 发送 HTTP 请求探测各 AI/ML 基础设施端点
      2. 匹配响应特征识别部署的 AI/ML 框架
      3. 检查已知漏洞路径和 CVE
      4. 可选：调用 Nuclei 进行深度扫描
    """

    @property
    def name(self) -> str:
        return "infra_scan"

    def check_available(self) -> bool:
        """InfraScanAdapter 始终可用（内置探测不需要 Nuclei）"""
        return True

    def run(self, target: str, config: dict) -> AdapterResult:
        """
        执行 AI 基础设施漏洞扫描

        Args:
            target: 目标 URL（如 http://target:8000）
            config: 配置字典，支持：
                - depth: 扫描深度（quick/standard/deep）
                - use_nuclei: 是否尝试使用 Nuclei（默认 True）
                - timeout: 超时秒数
                - use_cache: 是否使用缓存

        Returns:
            AdapterResult
        """
        start_time = time.time()

        depth = config.get("depth", "standard")
        timeout = config.get("timeout", 30)
        use_cache = config.get("use_cache", True)
        use_nuclei = config.get("use_nuclei", True)

        # 解析目标 URL
        parsed = urlparse(target)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        # 缓存检查
        cache_key = self._compute_cache_key(base_url, depth)
        if use_cache:
            cached = self._load_cache(cache_key)
            if cached:
                logger.info("InfraScan cache hit: %s", cache_key)
                cached["cache_hit"] = True
                return AdapterResult(
                    tool=self.name,
                    success=True,
                    data=cached.get("data", {}),
                    findings=cached.get("findings", []),
                    duration=0.0,
                )

        try:
            logger.info("InfraScan: scanning %s (depth=%s)", base_url, depth)

            all_findings: List[Dict[str, Any]] = []
            scan_results: Dict[str, Any] = {}

            # 阶段 1：内置 HTTP 探测
            detected_services: List[Dict[str, Any]] = []
            for check in INFRA_VULN_CHECKS:
                check_start = time.time()

                # 深度控制：quick=前3个, standard=前6个, deep=全部
                check_cap = {"quick": 3, "standard": 6, "deep": len(INFRA_VULN_CHECKS)}.get(depth, 6)
                if INFRA_VULN_CHECKS.index(check) >= check_cap:
                    break

                detected, evidence = self._probe_vuln(base_url, check, timeout)
                check_duration = (time.time() - check_start) * 1000

                scan_results[check["id"]] = {
                    "name": check["name"],
                    "detected": detected,
                    "severity": check["severity"],
                    "owasp_mapping": check["owasp"],
                    "cve": check.get("cve", ""),
                    "duration_ms": round(check_duration, 1),
                }

                if detected:
                    all_findings.append({
                        "category": check["id"],
                        "severity": check["severity"],
                        "description": check["description"],
                        "evidence": evidence,
                        "owasp_mapping": check["owasp"],
                        "confidence": 0.85,
                        "trigger": f"{base_url} {check['paths']}",
                        "source": "infra_scan",
                        "cve": check.get("cve", ""),
                    })
                    detected_services.append({
                        "id": check["id"],
                        "name": check["name"],
                        "url": base_url,
                    })

                    logger.info(
                        "InfraScan %s: DETECTED - %s",
                        check["id"], check["name"],
                    )

            # 阶段 2：Nuclei 扫描（如果可用且启用）
            nuclei_results: Optional[Dict[str, Any]] = None
            if use_nuclei and NUCLEI_AVAILABLE:
                try:
                    nuclei_results = self._run_nuclei_scan(base_url, timeout, depth)
                    if nuclei_results:
                        scan_results["nuclei_scan"] = nuclei_results
                        # 将 Nuclei 发现的漏洞添加到 findings
                        for finding in nuclei_results.get("findings", []):
                            all_findings.append(finding)
                except Exception as e:
                    logger.warning("Nuclei scan failed: %s", e)
                    scan_results["nuclei_scan"] = {"error": str(e), "available": True}
            else:
                scan_results["nuclei_scan"] = {
                    "available": NUCLEI_AVAILABLE,
                    "message": "Nuclei not installed. Install from https://github.com/projectdiscovery/nuclei" if not NUCLEI_AVAILABLE else "",
                }

            duration = time.time() - start_time
            success = len(scan_results) > 0

            result_data = {
                "target": base_url,
                "depth": depth,
                "nuclei_available": NUCLEI_AVAILABLE,
                "total_checks": len(scan_results),
                "detected_services": detected_services,
                "scan_results": scan_results,
                "total_findings": len(all_findings),
                "critical_findings": len([f for f in all_findings if f.get("severity") == "critical"]),
            }

            # 保存缓存
            if use_cache and success:
                self._save_cache(cache_key, {"data": result_data, "findings": all_findings})

            return AdapterResult(
                tool=self.name,
                success=success,
                data=result_data,
                findings=all_findings,
                duration=duration,
                raw_output=json.dumps(
                    {k: v for k, v in scan_results.items()},
                    ensure_ascii=False, indent=2,
                )[:2000],
            )

        except Exception as e:
            duration = time.time() - start_time
            logger.error("InfraScan execution failed: %s", str(e))
            return AdapterResult(
                tool=self.name,
                success=False,
                errors=[str(e)],
                duration=duration,
            )

    # ── 漏洞探测 ──

    def _probe_vuln(
        self,
        base_url: str,
        check: Dict[str, Any],
        timeout: int,
    ) -> Tuple[bool, str]:
        """
        探测单个漏洞

        发送 HTTP 请求到已知漏洞路径，匹配响应特征。
        """
        for path in check["paths"]:
            url = urljoin(base_url + "/", path.lstrip("/"))

            for method in check["methods"]:
                try:
                    if method == "GET":
                        result = http_get(url, timeout=timeout)
                    else:
                        result = http_post(url, json_data={}, timeout=timeout)

                    if result["status"] == 200:
                        body = ""
                        data = result.get("data", "")
                        if isinstance(data, str):
                            body = data
                        elif isinstance(data, dict):
                            body = json.dumps(data)

                        # 匹配特征模式
                        for pattern in check["patterns"]:
                            if re.search(pattern, body):
                                return True, f"Matched {pattern} at {url}"

                        # 200 响应本身也可能是线索（特别是调试端点）
                        if path in ["/docs", "/openapi.json", "/api/system/env-dump"]:
                            if len(body) > 50:  # 有实际内容
                                return True, f"Endpoint accessible: {url}"

                    elif result["status"] in (301, 302):
                        # 重定向也可能是线索
                        return True, f"Redirect at {url}"

                except Exception as e:
                    logger.debug("InfraScan probe failed for %s: %s", url, e)

        return False, ""

    # ── Nuclei 集成 ──

    def _run_nuclei_scan(
        self,
        target: str,
        timeout: int,
        depth: str,
    ) -> Optional[Dict[str, Any]]:
        """
        调用 Nuclei 进行深度扫描

        使用 AI-Exploits 项目的 Nuclei 模板扫描 AI/ML 基础设施。
        需要 Nuclei 已安装且模板已下载。
        """
        if not NUCLEI_AVAILABLE:
            return None

        # 构建 Nuclei 命令
        severity_map = {
            "quick": ["critical"],
            "standard": ["critical", "high"],
            "deep": ["critical", "high", "medium", "low"],
        }
        severities = severity_map.get(depth, ["critical", "high"])

        # 使用 AI-Exploits 模板（如果已下载到 templates 目录）
        # 或者使用 Nuclei 内置模板
        cmd = [
            "nuclei",
            "-u", target,
            "-severity", ",".join(severities),
            "-json",
            "-silent",
            "-timeout", str(timeout),
        ]

        # 尝试使用 AI-Exploits 模板
        ai_exploits_templates = Path("templates/ai-exploits")
        if ai_exploits_templates.exists():
            cmd.extend(["-t", str(ai_exploits_templates)])
            logger.info("InfraScan: using AI-Exploits Nuclei templates")

        try:
            logger.info("InfraScan: running Nuclei scan on %s", target)
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout + 30,  # 额外 30s 缓冲
                check=False,
            )

            findings: List[Dict[str, Any]] = []
            for line in proc.stdout.strip().split("\n"):
                if not line:
                    continue
                try:
                    vuln = json.loads(line)
                    findings.append({
                        "category": vuln.get("template-id", "nuclei"),
                        "severity": vuln.get("info", {}).get("severity", "medium"),
                        "description": vuln.get("info", {}).get("description", ""),
                        "evidence": vuln.get("matched-at", vuln.get("matched", "")),
                        "owasp_mapping": "LLM05",
                        "confidence": 0.9,
                        "trigger": vuln.get("matched-at", target),
                        "source": "infra_scan_nuclei",
                        "cve": vuln.get("info", {}).get("classification", {}).get("cve-id", ""),
                    })
                except json.JSONDecodeError:
                    continue

            return {
                "available": True,
                "findings_count": len(findings),
                "findings": findings,
                "raw_output_size": len(proc.stdout),
            }

        except subprocess.TimeoutExpired:
            logger.warning("Nuclei scan timed out for %s", target)
            return {"available": True, "error": "timeout", "findings": []}
        except Exception as e:
            logger.warning("Nuclei scan failed: %s", e)
            return {"available": True, "error": str(e), "findings": []}

    # ── 工具方法 ──

    @staticmethod
    def _compute_cache_key(target: str, depth: str) -> str:
        key_str = f"infra_scan|{target}|{depth}"
        return hashlib.md5(key_str.encode("utf-8")).hexdigest()

    @staticmethod
    def _load_cache(cache_key: str) -> Optional[Dict[str, Any]]:
        cache_file = Path(INFRA_CACHE_DIR) / f"{cache_key}.json"
        if not cache_file.exists():
            return None
        import time as _time
        mtime = cache_file.stat().st_mtime
        if _time.time() - mtime > 86400:
            return None
        try:
            with open(cache_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return None

    @staticmethod
    def _save_cache(cache_key: str, data: Dict[str, Any]) -> None:
        cache_dir = Path(INFRA_CACHE_DIR)
        cache_dir.mkdir(parents=True, exist_ok=True)
        cache_file = cache_dir / f"{cache_key}.json"
        try:
            with open(cache_file, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
        except Exception as e:
            logger.warning("Failed to save infra_scan cache: %s", e)
