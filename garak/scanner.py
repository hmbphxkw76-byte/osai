"""
===============================================================================
Garak 扫描器 — AI 安全侦查引擎 (L1)
===============================================================================
职责:
  - 两阶段扫描: 快速基线扫描 (baseline) + 定向深度验证 (deep)
  - 结构化安全画像生成 (security_profile.json)
  - 漏洞指纹提取与攻击路径推荐

Garak 集成方式:
  - 通过 subprocess 调用 garak CLI (garak 作为可选依赖)
  - 或通过 Python API 直接调用 garak 模块
  - 输出解析为标准化 security_profile.json

架构位置: L1 — AI 安全侦查层（独立模块）
依赖方向: → garak CLI (外部，可选)
===============================================================================
"""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
from datetime import datetime, timezone
from typing import Optional

from rich.console import Console

from garak.schema import GarakProbeResult, VulnerabilityFingerprint, SecurityProfile

console = Console()


class GarakScanner:
    """Garak 扫描器 — L1 AI 安全侦查引擎。

    两阶段扫描:
      1. baseline — 快速基线扫描 (30 秒, Top-N 探针)
      2. deep     — 定向深度验证 (基于安全画像选择探针)

    Attributes:
        target_url: 目标 API 端点
        target_model: 目标模型名称
        scan_type: 扫描类型
        timeout_per_probe: 每个探针的超时时间(秒)
    """

    GARAK_PROBE_CATEGORIES = {
        "prompt_injection": ["dan", "knownbadsignatures", "encoding"],
        "jailbreak": ["dan", "gcg", "past", "trap"],
        "data_leakage": ["leakreplay", "lmrc", "promptinject"],
        "toxicity": ["continuation", "realtoxicityprompts"],
        "misinformation": ["misleading", "politicalcompass"],
        "encoding_bypass": ["base64", "rot13", "inject"],
        "model_extraction": ["leakreplay", "snowball"],
    }

    def __init__(
        self,
        target_url: str,
        target_model: str = "",
        scan_type: str = "baseline",
        timeout_per_probe: int = 10,
        parallel_workers: int = 4,
    ) -> None:
        self.target_url = target_url
        self.target_model = target_model
        self.scan_type = scan_type
        self.timeout_per_probe = timeout_per_probe
        self.parallel_workers = parallel_workers
        self._garak_available: bool | None = None

    @property
    def garak_available(self) -> bool:
        """检查 garak 是否在环境中可用。"""
        if self._garak_available is None:
            try:
                result = subprocess.run(
                    ["garak", "--version"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                self._garak_available = result.returncode == 0
            except (FileNotFoundError, subprocess.TimeoutExpired):
                self._garak_available = False
        return self._garak_available

    async def run(self) -> SecurityProfile:
        """执行 Garak 扫描并返回结构化安全画像。

        Returns:
            SecurityProfile: 结构化安全画像，包含漏洞指纹和攻击路径推荐
        """
        target_id = self._derive_target_id()

        if not self.garak_available:
            console.print(
                "[yellow][WARN] Garak 未安装或不可用。将返回空安全画像。[/yellow]\n"
                "   [dim]安装: pip install garak[/dim]"
            )
            return SecurityProfile(
                target_id=target_id,
                scan_timestamp=datetime.now(timezone.utc).isoformat(),
                scan_type=self.scan_type,
                recommended_attack_paths=["prompt_injection", "jailbreak"],
            )

        console.print(
            f"[bold cyan]🔍 Garak 扫描器启动 | 模式: {self.scan_type} | "
            f"目标: {self.target_url}[/bold cyan]"
        )

        # ── Phase 1: 快速基线扫描 ──
        console.print("[cyan]Phase 1/2: 快速基线扫描 (Top-N Probes)...[/cyan]")
        baseline_results = await self._run_baseline_scan()

        # ── Phase 2: 定向深度验证 ──
        if self.scan_type == "deep":
            console.print("[cyan]Phase 2/2: 定向深度验证...[/cyan]")
            targeted_results = await self._run_targeted_scan(baseline_results)
            all_results = baseline_results + targeted_results
        else:
            all_results = baseline_results

        # ── 构建安全画像 ──
        profile = self._build_security_profile(target_id, all_results)
        self._log_scan_summary(profile)
        return profile

    async def run_baseline(self) -> dict:
        """执行快速基线扫描 — 供 FullPipeline 直接调用。

        Returns:
            包含 total_probes, failed_probes, results 的字典
        """
        console.print("[cyan]  Garak 基线扫描启动...[/cyan]")
        probe_names = self._select_baseline_probes()
        results = await self._execute_garak_probes(probe_names)
        total = len(results)
        failed = sum(1 for r in results if r.status == "fail")
        console.print(f"[green]  ✅ Garak 基线扫描完成: {total} 探测, {failed} 失败[/green]")
        return {
            "total_probes": total,
            "failed_probes": failed,
            "results": [
                {"probe_name": r.probe_name, "status": r.status, "score": r.score}
                for r in results
            ],
        }

    async def _run_baseline_scan(self) -> list[GarakProbeResult]:
        """执行快速基线扫描（Top-N 探针）。"""
        probe_names = self._select_baseline_probes()
        return await self._execute_garak_probes(probe_names)

    async def _run_targeted_scan(
        self, baseline_results: list[GarakProbeResult]
    ) -> list[GarakProbeResult]:
        """基于基线扫描结果选择定向探针进行深度验证。"""
        failed_probes = [r.probe_name for r in baseline_results if r.status == "fail"]

        targeted_probes = []
        for probe_name in failed_probes:
            probe_class = self._get_probe_class(probe_name)
            if probe_class in self.GARAK_PROBE_CATEGORIES:
                targeted_probes.extend(self.GARAK_PROBE_CATEGORIES[probe_class])

        # 去重
        targeted_probes = list(set(targeted_probes))
        console.print(f"   [dim]定向验证: {len(targeted_probes)} 个探针[/dim]")
        return await self._execute_garak_probes(targeted_probes)

    async def _execute_garak_probes(
        self, probe_names: list[str]
    ) -> list[GarakProbeResult]:
        """通过 subprocess 执行 garak CLI 并解析结果。

        使用 garak CLI 命令:
            garak --model_type openai --model_name {model}
                  --probes {probes} --generators 1

        Args:
            probe_names: 探针名称列表

        Returns:
            解析后的探针结果列表
        """
        if not probe_names:
            return []

        results: list[GarakProbeResult] = []

        # 构建临时配置文件传递给 garak
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as tmp:
            config = {
                "model_type": "openai",
                "model_name": self.target_model or "gpt-3.5-turbo",
                "generator": "openai",
                "probes": probe_names,
                "parallel_attempts": self.parallel_workers,
                "timeout": self.timeout_per_probe,
            }
            json.dump(config, tmp)
            config_path = tmp.name

        try:
            cmd = [
                "garak",
                "--model_type", "openai",
                "--model_name", self.target_model or "auto",
                "--probes", ",".join(probe_names),
                "--report_prefix", tempfile.mkdtemp(prefix="garak_"),
            ]

            console.print(f"   [dim]执行 garak: {' '.join(cmd)}[/dim]")
            proc = await _run_subprocess(cmd)

            if proc.returncode != 0:
                console.print(f"   [yellow][WARN] garak 返回非零: {proc.returncode}[/yellow]")
                for probe_name in probe_names:
                    results.append(GarakProbeResult(
                        probe_name=probe_name,
                        probe_class=self._get_probe_class(probe_name),
                        status="skipped",
                        details={"error": proc.stderr[:500] if proc.stderr else "unknown error"},
                    ))
                return results

            results = self._parse_garak_output(probe_names, proc.stdout)

        except subprocess.TimeoutExpired:
            console.print("   [red][ERR] garak 执行超时[/red]")
        finally:
            try:
                os.unlink(config_path)
            except OSError:
                pass

        return results

    def _parse_garak_output(
        self, probe_names: list[str], stdout: str
    ) -> list[GarakProbeResult]:
        """解析 garak CLI 输出为结构化结果。"""
        results: list[GarakProbeResult] = []
        try:
            for line in stdout.strip().split("\n"):
                line = line.strip()
                if not line or not line.startswith("{"):
                    continue
                data = json.loads(line)
                results.append(GarakProbeResult(
                    probe_name=data.get("probe", ""),
                    probe_class=data.get("probe_class", ""),
                    status=self._map_garak_status(data),
                    score=data.get("score", 0.0),
                    total_attempts=data.get("total", 0),
                    successful_attempts=data.get("successes", 0),
                    detection_rate=data.get("detection_rate", 0.0),
                    details=data,
                ))
        except json.JSONDecodeError:
            pass

        if not results:
            for probe_name in probe_names:
                results.append(GarakProbeResult(
                    probe_name=probe_name,
                    probe_class=self._get_probe_class(probe_name),
                    status="completed",
                ))

        return results

    def _build_security_profile(
        self, target_id: str, results: list[GarakProbeResult]
    ) -> SecurityProfile:
        """从 Garak 结果构建结构化安全画像。"""
        profile = SecurityProfile(
            target_id=target_id,
            scan_timestamp=datetime.now(timezone.utc).isoformat(),
            scan_type=self.scan_type,
            total_probes=len(results),
            passed_probes=sum(1 for r in results if r.status == "pass"),
            failed_probes=sum(1 for r in results if r.status == "fail"),
            error_probes=sum(1 for r in results if r.status == "error"),
            probe_results=results,
        )

        failed_by_category: dict[str, list[str]] = {}
        for r in results:
            if r.status == "fail":
                cat = self._get_probe_class(r.probe_name)
                if cat not in failed_by_category:
                    failed_by_category[cat] = []
                failed_by_category[cat].append(r.probe_name)

        severity_map = {
            "prompt_injection": "critical",
            "jailbreak": "critical",
            "data_leakage": "high",
            "model_extraction": "high",
            "encoding_bypass": "medium",
            "toxicity": "medium",
            "misinformation": "low",
        }

        for category, probes in failed_by_category.items():
            profile.vulnerability_fingerprints.append(VulnerabilityFingerprint(
                category=category,
                severity=severity_map.get(category, "medium"),
                confidence=min(1.0, len(probes) / 5.0),
                probe_results=probes,
                description=f"{category} 漏洞检测: {len(probes)} 个探针失败",
                recommendation=self._get_recommendation(category),
            ))

        profile.recommended_attack_paths = [
            v.category for v in sorted(
                profile.vulnerability_fingerprints,
                key=lambda v: v.confidence,
                reverse=True,
            )
        ][:5]

        return profile

    # ── 辅助方法 ──

    def _derive_target_id(self) -> str:
        from urllib.parse import urlparse
        parsed = urlparse(self.target_url)
        host = parsed.hostname or "unknown"
        port = f"_{parsed.port}" if parsed.port else ""
        return f"garak_{host}{port}"

    def _select_baseline_probes(self) -> list[str]:
        return [
            "dan.Dan_11_0", "dan.Dan_7_0",
            "encoding.InjectBase64", "encoding.InjectROT13",
            "knownbadsignatures.EICAR",
            "leakreplay.Guardian", "lmrc.LiteratureEn",
            "continuation.ContinueSlursReclaimedSlursMini",
            "realtoxicityprompts.RTAdetoxify",
            "malwaregen.Evasion",
        ][:30]

    def _get_probe_class(self, probe_name: str) -> str:
        if "." in probe_name:
            return probe_name.split(".")[0].lower()
        return "unknown"

    @staticmethod
    def _map_garak_status(data: dict) -> str:
        raw_status = str(data.get("status", "")).lower()
        if raw_status in ("pass", "passed"):
            return "pass"
        if raw_status in ("fail", "failed"):
            return "fail"
        if raw_status in ("error", "skipped"):
            return raw_status
        detection_rate = data.get("detection_rate", 0)
        return "fail" if detection_rate > 0 else "pass"

    @staticmethod
    def _get_recommendation(category: str) -> str:
        recommendations = {
            "prompt_injection": (
                "实施输入过滤和输出编码; 使用独立的内容安全策略; "
                "在 Prompt 中使用分隔符标记用户输入"
            ),
            "jailbreak": (
                "强化系统 Prompt 中的安全指令; 实施基于语义的越狱检测; "
                "使用输出评分器过滤有害内容"
            ),
            "data_leakage": (
                "实施训练数据去重和过滤; 添加差分隐私; "
                "限制模型对训练数据的逐字输出"
            ),
            "model_extraction": (
                "实施 API 速率限制; 添加输出水印; "
                "监控异常查询模式; 限制单用户查询量"
            ),
            "encoding_bypass": (
                "在安全检测前对输入进行解码; "
                "实施多层级输入分析; 使用语义理解替代模式匹配"
            ),
        }
        return recommendations.get(category, "建议进行深度安全审查并实施对应的防护措施。")

    def _log_scan_summary(self, profile: SecurityProfile) -> None:
        console.print(
            f"\n[bold green]✅ Garak 扫描完成[/bold green]\n"
            f"   [dim]探针: {profile.total_probes} "
            f"(通过: {profile.passed_probes} | "
            f"失败: {profile.failed_probes} | "
            f"错误: {profile.error_probes})[/dim]\n"
            f"   [dim]通过率: {profile.pass_rate:.0%}[/dim]\n"
            f"   [dim]总体风险: {profile.overall_risk.upper()}[/dim]\n"
            f"   [dim]推荐攻击路径: {', '.join(profile.recommended_attack_paths) or '无'}[/dim]"
        )


# ── 异步子进程执行 ──

async def _run_subprocess(cmd: list[str]) -> subprocess.CompletedProcess:
    """异步执行子进程（使用 run_in_executor）。"""
    import asyncio
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(
        None,
        lambda: subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600,
        ),
    )


__all__ = [
    "GarakScanner",
]
