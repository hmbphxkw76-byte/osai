"""
===============================================================================
全流程管道编排器 — 六阶段 AI 红队全生命周期攻击管道
===============================================================================
这是 RedTeam_AI 的核心编排引擎，串联从 Web 侦察到报告生成的完整攻击链:

  1. L0: 前置侦察 (ai-recon + 浏览器登录)
  2. L1: AI 场景探测 (Garak 基线/深度扫描)
  3. L2: 攻击面分析 (OWASP LLM + Agentic 双映射)
  4. L3: 风险筛选 (按 OWASP/MITRE 评级选择攻击目标)
  5. L4: 攻击执行 (Promptfoo 提示词管理 + PyRIT 攻击)
  6. L5: 数据入库 + 报告生成 (Neo4j + OffSec 风格报告)

每个阶段完成后自动生成专家指导建议 (stage_guidance)，推荐下一步操作。

使用方式:
  # 全流程一键执行
  python -m orchestrators.full_pipeline --target-url https://target.com --auto

  # 从指定阶段开始
  python -m orchestrators.full_pipeline --stage recon --target-url https://target.com

  # 仅执行攻击面分析 + 风险筛选
  python -m orchestrators.full_pipeline --stage attack_surface --recon-profile profile.json

  # 从已有结果恢复执行
  python -m orchestrators.full_pipeline --resume-from outputs/pipeline_state.json

架构位置: L2-L6 跨层编排（顶层调度器）
依赖方向: → executor, scoring, storage, reporting（下行依赖）
===============================================================================
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.table import Table

console = Console()

# ── 项目内模块 ──
try:
    from scoring.owasp_mapper import (
        OWASPMapper,
        VulnerabilityFinding,
        AttackSurfaceReport,
        RiskLevel,
    )
    from utils.stage_guidance import generate_guidance, StageGuidance
    from storage.neo4j_client import (
        Neo4jClient,
        Neo4jConfig,
        PipelineStore,
        AttackGraphBuilder,
        GraphReconResult,
        GraphVulnerability,
        GraphAttackResult,
    )
    from executor.promptfoo_manager import (
        PromptfooManager,
        PromptEntry,
        PromptfooEvalResult,
    )
    _IMPORTS_OK = True
except ImportError:
    _IMPORTS_OK = False


# ═══════════════════════════════════════════════════════════════════════
# 枚举
# ═══════════════════════════════════════════════════════════════════════

class PipelineStage(str, Enum):
    """管道六阶段标识。"""
    RECON = "recon"
    AI_DETECT = "ai_detect"
    ATTACK_SURFACE = "attack_surface"
    RISK_SELECT = "risk_select"
    ATTACK = "attack"
    REPORT = "report"
    AUTO = "auto"  # 全流程


# ═══════════════════════════════════════════════════════════════════════
# 管道状态
# ═══════════════════════════════════════════════════════════════════════

@dataclass
class PipelineState:
    """管道执行状态 — 可序列化到 JSON 用于断点续执行。"""
    target_url: str = ""
    stage: str = "init"

    # L0
    recon_done: bool = False
    profile_path: str = ""
    profile_data: dict = field(default_factory=dict)

    # L1
    ai_detect_done: bool = False
    target_type: str = "unknown"  # basic_llm / rag / agent / multi_agent
    garak_results: dict = field(default_factory=dict)

    # L2
    attack_surface_done: bool = False
    attack_surface_path: str = ""
    attack_surface_report: Optional[AttackSurfaceReport] = None

    # L3
    risk_select_done: bool = False
    selected_findings: list = field(default_factory=list)

    # L4
    attack_done: bool = False
    attack_results: dict = field(default_factory=dict)

    # L5
    report_done: bool = False
    report_path: str = ""
    neo4j_exported: bool = False

    # 元数据
    started_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    completed_at: str = ""
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        """序列化到 JSON（排除不可序列化的对象）。"""
        d = {}
        for k, v in self.__dict__.items():
            if k == "attack_surface_report" and v:
                d[k] = {
                    "total_findings": v.total_findings,
                    "critical_count": v.critical_count,
                    "high_count": v.high_count,
                    "findings": [
                        {"id": f.finding_id, "title": f.title, "risk": f.risk_level.value}
                        for f in v.findings
                    ],
                }
            elif isinstance(v, (str, int, float, bool, list, dict, type(None))):
                d[k] = v
        return d

    def save(self, path: str):
        """保存状态到 JSON 文件。"""
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2, ensure_ascii=False, default=str)

    @classmethod
    def load(cls, path: str) -> PipelineState:
        """从 JSON 文件恢复状态。"""
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        state = cls()
        for k, v in data.items():
            if k in state.__dict__:
                setattr(state, k, v)
        return state


# ═══════════════════════════════════════════════════════════════════════
# 六阶段管道编排器
# ═══════════════════════════════════════════════════════════════════════

class FullPipeline:
    """AI 红队全生命周期管道编排器。

    串联 L0→L1→L2→L3→L4→L5 六个阶段，每阶段完成后：
      1. 保存阶段产物到 outputs/
      2. 输出专家指导建议（stage_guidance）
      3. 更新 PipelineState 支持断点续执行
    """

    def __init__(
        self,
        target_url: str = "",
        output_dir: str = "",
        neo4j_config: Optional[Neo4jConfig] = None,
    ):
        self.target_url = target_url
        self.output_dir = Path(output_dir or os.path.join(os.path.dirname(__file__), "..", "outputs"))
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.state = PipelineState(target_url=target_url)
        self.state_path = str(self.output_dir / "pipeline_state.json")

        self._neo4j_config = neo4j_config or Neo4jConfig()
        self._owasp_mapper = OWASPMapper()
        self._promptfoo_manager: Optional[PromptfooManager] = None

    # ── 阶段入口 ──

    async def run(self, start_stage: PipelineStage = PipelineStage.AUTO) -> PipelineState:
        """执行管道（自动或从指定阶段开始）。

        Args:
            start_stage: 起始阶段，PipelineStage.AUTO 表示全流程

        Returns:
            PipelineState: 完整管道状态
        """
        console.print()
        console.print(Panel.fit(
            f"目标: {self.target_url}\n模式: {start_stage.value}",
            title="[bold cyan]🚀 AI 红队全流程管道[/bold cyan]",
        ))

        stages = [
            (PipelineStage.RECON, self._run_recon),
            (PipelineStage.AI_DETECT, self._run_ai_detect),
            (PipelineStage.ATTACK_SURFACE, self._run_attack_surface),
            (PipelineStage.RISK_SELECT, self._run_risk_select),
            (PipelineStage.ATTACK, self._run_attack),
            (PipelineStage.REPORT, self._run_report),
        ]

        # 找到起始阶段索引
        start_idx = 0
        if start_stage != PipelineStage.AUTO:
            stage_values = [s[0].value for s in stages]
            if start_stage.value in stage_values:
                start_idx = stage_values.index(start_stage.value)

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("{task.completed}/{task.total}"),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("[cyan]管道执行中...", total=len(stages) - start_idx)

            for i in range(start_idx, len(stages)):
                stage_name, stage_func = stages[i]
                try:
                    await stage_func()
                    self.state.stage = stage_name.value
                    self.state.save(self.state_path)
                    progress.update(task, advance=1, description=f"[green]✅ {stage_name.value}[/green]")
                except Exception as e:
                    import traceback
                    self.state.errors.append(f"{stage_name.value}: {e}\n{traceback.format_exc()}")
                    console.print(f"[red]❌ {stage_name.value} 失败: {e}[/red]")
                    progress.update(task, advance=1, description=f"[red]❌ {stage_name.value}[/red]")
                    if i == start_idx:  # 起始阶段失败则终止
                        break

        self.state.completed_at = datetime.now(timezone.utc).isoformat()
        self.state.save(self.state_path)

        # 最终总结
        self._print_final_summary()
        return self.state

    # ── L0: 前置侦察 ──

    async def _run_recon(self):
        """执行 L0 前置侦察阶段。

        步骤:
          1. 加载已存在的 target_profile.json（如果有）
          2. 如无 profile，提示用户通过 Web UI 执行
          3. 从 profile 中提取 JWT、Cookie、API Key 等认证信息
          4. 输出专家指导
        """
        self._print_stage_header("L0: 前置侦察", "ai-recon + Web UI")

        # 尝试加载已有 profile
        recon_dir = Path(__file__).parent.parent.parent / "ai-recon" / "outputs"
        profile_files = sorted(recon_dir.glob("target_profile_*.json"), key=lambda f: f.stat().st_mtime, reverse=True)

        if profile_files:
            profile_path = str(profile_files[0])
            with open(profile_path, "r", encoding="utf-8") as f:
                profile_data = json.load(f)
            console.print(f"[green]  ✅ 加载已有侦察结果: {profile_path}[/green]")

            self.state.profile_path = profile_path
            self.state.profile_data = profile_data
            self.state.recon_done = True

            # 展示认证信息提取结果
            auth = profile_data.get("auth", {})
            console.print(f"  🔑 认证方式: {auth.get('type', 'none')}")
            if auth.get("jwt_token"):
                console.print(f"  🔑 JWT Token: {auth['jwt_token'][:50]}...")
            if auth.get("api_key"):
                console.print(f"  🔑 API Key: {auth['api_key'][:30]}...")
            if auth.get("session_cookie"):
                console.print(f"  🍪 Session Cookie: {auth['session_cookie'][:30]}...")
        else:
            console.print("[yellow]  ⚠️ 未找到 target_profile.json[/yellow]")
            console.print("  请通过以下方式启动前置侦察:")
            console.print(f"    cd ai-recon/")
            console.print(f"    python main.py --target {self.target_url}")
            console.print(f"    # 或通过 Web UI: python web_app.py")

        # 输出专家指导
        guidance = generate_guidance("recon", {
            "profile": self.state.profile_data,
            "target_url": self.target_url,
        })
        console.print(guidance.render())

    # ── L1: AI 场景探测 ──

    async def _run_ai_detect(self):
        """执行 L1 AI 场景探测阶段。

        步骤:
          1. 从 profile 中识别 RAG/Agent/多Agent 架构
          2. 如有 Garak，执行基线扫描
          3. 输出 AI 场景画像
        """
        self._print_stage_header("L1: AI 场景探测", "Garak 基线扫描")

        profile = self.state.profile_data

        # 从 profile 提取 AI 场景信息
        rag_info = profile.get("rag", {})
        agent_info = profile.get("agent", {})
        target_arch = profile.get("target", {}).get("architecture", "basic_llm")

        if rag_info.get("detected"):
            self.state.target_type = "rag"
        elif agent_info.get("multi_agent"):
            self.state.target_type = "multi_agent"
        elif agent_info.get("detected"):
            self.state.target_type = "agent"
        else:
            self.state.target_type = target_arch or "basic_llm"

        console.print(f"  🏗️ 目标架构: {self.state.target_type}")
        if rag_info.get("detected"):
            console.print(f"  📚 RAG 数据源: {rag_info.get('data_sources', [])}")
        if agent_info.get("detected"):
            console.print(f"  🤖 Agent 工具数: {agent_info.get('tools_count', 0)}")
            console.print(f"  🛠️ Agent 工具: {agent_info.get('tools', [])}")

        # 尝试 Garak 基线扫描
        garak_profile = self._try_garak_scan()
        self.state.garak_results = garak_profile
        self.state.ai_detect_done = True

        # 输出专家指导
        guidance = generate_guidance("ai_detect", {
            "ai_profile": {"architecture": self.state.target_type},
            "target_type": self.state.target_type,
            "garak_results": garak_profile,
        })
        console.print(guidance.render())

    # ── L2: 攻击面分析 ──

    async def _run_attack_surface(self):
        """执行 L2 攻击面分析阶段。

        步骤:
          1. 从侦察结果 + Garak 结果提取漏洞发现
          2. OWASP LLM Top 10 映射
          3. OWASP Agentic Top 10 映射（如为 Agent 系统）
          4. 生成攻击面分析报告 attack_surface.json
        """
        self._print_stage_header("L2: 攻击面分析", "OWASP 双映射")

        # 从行为测绘中提取（如果有）
        behavior_map = self.state.profile_data.get("behavior_map", {})

        report = self._owasp_mapper.build_attack_surface_report(
            target_url=self.target_url,
            target_type=self.state.target_type,
            recon_profile=self.state.profile_data,
            garak_profile=self.state.garak_results,
            behavior_map=behavior_map,
        )

        # 保存到文件
        report_path = str(self.output_dir / "attack_surface.json")
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump({
                "target_url": report.target_url,
                "target_type": report.target_type,
                "total_findings": report.total_findings,
                "critical_count": report.critical_count,
                "high_count": report.high_count,
                "medium_count": report.medium_count,
                "low_count": report.low_count,
                "generated_at": report.generated_at,
                "findings": [
                    {
                        "finding_id": f.finding_id,
                        "title": f.title,
                        "description": f.description,
                        "owasp_llm": f.owasp_llm.value if f.owasp_llm else None,
                        "owasp_agentic": f.owasp_agentic.value if f.owasp_agentic else None,
                        "risk_level": f.risk_level.value,
                        "cvss_score": f.cvss_score,
                        "evidence": f.evidence,
                        "remediation": f.remediation,
                    }
                    for f in report.findings
                ],
            }, f, indent=2, ensure_ascii=False)

        self.state.attack_surface_report = report
        self.state.attack_surface_path = report_path
        self.state.attack_surface_done = True

        # 终端展示
        self._owasp_mapper.display_attack_surface(report)

        console.print(f"[green]  📄 攻击面报告已保存: {report_path}[/green]")

        # 输出专家指导
        guidance = generate_guidance("attack_surface", {
            "attack_surface": {
                "total_findings": report.total_findings,
                "critical_count": report.critical_count,
                "high_count": report.high_count,
                "medium_count": report.medium_count,
            },
        })
        console.print(guidance.render())

    # ── L3: 风险筛选 ──

    async def _run_risk_select(self):
        """执行 L3 风险筛选阶段。

        步骤:
          1. 按最低风险等级筛选（默认 HIGH）
          2. 将筛选结果分为「需要提示词」和「可直接攻击」
          3. 保存 selected_risks.json
        """
        self._print_stage_header("L3: 风险筛选", "OWASP → PyRIT 路由")

        min_risk = "high"
        if not self.state.attack_surface_report:
            console.print("[yellow]  ⚠️ 无攻击面报告，跳过风险筛选[/yellow]")
            return

        report = self.state.attack_surface_report

        # 筛选 HIGH 及以上风险
        selected = self._owasp_mapper.filter_by_risk(report.findings, min_risk=min_risk)
        console.print(f"  从 {report.total_findings} 个漏洞中筛选出 {len(selected)} 个 (≥{min_risk.upper()})")

        # 分为两组: 需要提示词 vs 可直接攻击
        prompt_needed, direct_attack = self._owasp_mapper.split_by_prompt_requirement(selected)

        self.state.selected_findings = [
            {
                "finding_id": f.finding_id,
                "title": f.title,
                "risk_level": f.risk_level.value,
                "owasp_llm": f.owasp_llm.value if f.owasp_llm else None,
                "owasp_agentic": f.owasp_agentic.value if f.owasp_agentic else None,
                "prompt_needed": f in prompt_needed,
            }
            for f in selected
        ]
        self.state.risk_select_done = True

        # 保存
        select_path = str(self.output_dir / "selected_risks.json")
        with open(select_path, "w", encoding="utf-8") as f:
            json.dump(self.state.selected_findings, f, indent=2, ensure_ascii=False)

        # 展示分组
        if prompt_needed:
            console.print(f"\n  [cyan]📝 需要提示词管理 (Promptfoo): {len(prompt_needed)} 个[/cyan]")
            for f in prompt_needed:
                console.print(f"    • {f.title}")
        if direct_attack:
            console.print(f"\n  [green]⚡ 可直接攻击 (PyRIT): {len(direct_attack)} 个[/green]")
            for f in direct_attack:
                console.print(f"    • {f.title}")

        # 输出专家指导
        guidance = generate_guidance("risk_select", {
            "selected_findings": selected,
            "prompt_needed_count": len(prompt_needed),
            "direct_attack_count": len(direct_attack),
        })
        console.print(guidance.render())

    # ── L4: 攻击执行 ──

    async def _run_attack(self):
        """执行 L4 攻击阶段。

        步骤:
          1. 需要提示词 → Promptfoo 管理 → PyRIT 攻击
          2. 不需要提示词 → PyRIT 直接攻击
          3. 支持串行和并行模式
        """
        self._print_stage_header("L4: 攻击执行", "PyRIT + Promptfoo")

        if not self.state.selected_findings:
            console.print("[yellow]  ⚠️ 无筛选结果，跳过攻击[/yellow]")
            return

        prompt_needed_items = [f for f in self.state.selected_findings if f.get("prompt_needed")]
        direct_items = [f for f in self.state.selected_findings if not f.get("prompt_needed")]

        results = {"total_attacks": 0, "successes": 0, "details": []}

        # 路径 A: Promptfoo 管理提示词 → PyRIT 攻击
        if prompt_needed_items:
            console.print(f"\n[cyan]  📝 路径 A: Promptfoo 提示词管理 ({len(prompt_needed_items)} 个)[/cyan]")

            # 初始化 Promptfoo Manager
            self._promptfoo_manager = PromptfooManager()

            # 按 OWASP 分类筛选提示词
            owasp_categories = list(set(
                f.get("owasp_llm", "") for f in prompt_needed_items
                if f.get("owasp_llm")
            ))
            prompts = self._promptfoo_manager.filter_prompts(owasp_categories=owasp_categories)

            if prompts:
                self._promptfoo_manager.display_prompt_table(prompts)

                # 导出为 Promptfoo YAML 配置
                config_path = self._promptfoo_manager.export_to_yaml(
                    prompts,
                    str(self.output_dir / "promptfoo_config.yaml"),
                )
                console.print(f"[green]  ✅ Promptfoo 配置已导出: {config_path}[/green]")

                # 执行 Promptfoo 评估（可选）
                # eval_result = self._promptfoo_manager.run_eval(config_path)
            else:
                console.print("[yellow]  ⚠️ 未找到匹配的提示词，使用默认载荷[/yellow]")

        # 路径 B: PyRIT 直接攻击
        if direct_items:
            console.print(f"\n[green]  ⚡ 路径 B: PyRIT 直接攻击 ({len(direct_items)} 个)[/green]")
            console.print(f"  目标将通过以下 PyRIT 攻击策略执行:")
            console.print(f"    • PromptSendingAttack (单轮注入)")
            console.print(f"    • CrescendoAttack (多轮越狱)")
            if self.state.target_type in ("agent", "multi_agent"):
                console.print(f"    • Agent Tool Abuse (工具滥用)")
            if self.state.target_type == "rag":
                console.print(f"    • RAG Poisoning (检索投毒)")

        # 调用 PyRIT 执行攻击
        console.print("\n  ▶️ 调用 PyRIT Orchestrator...")
        try:
            attack_result = await self._run_pyrit_attack(direct_items + prompt_needed_items)
            results = attack_result
        except Exception as e:
            console.print(f"[red]  ❌ PyRIT 攻击异常: {e}[/red]")
            results["errors"] = [str(e)]

        self.state.attack_results = results
        self.state.attack_done = True

        # 输出专家指导
        guidance = generate_guidance("attack", {
            "attack_results": results,
            "promptfoo_used": bool(prompt_needed_items),
        })
        console.print(guidance.render())

    async def _run_pyrit_attack(self, targets: list[dict]) -> dict:
        """调用 PyRIT Orchestrator 执行攻击。

        通过 subprocess 执行 pyrit/main.py，传递 --from-pipeline 参数。
        也支持直接导入 pyrit 模块进行 Python API 调用。
        """
        results = {"total_attacks": 0, "successes": 0, "asr_score": 0.0, "details": []}

        # 构建 PyRIT 攻击命令
        try:
            # 优先使用 Python API 直接调用
            sys.path.insert(0, str(Path(__file__).parent.parent))

            cmd = [
                sys.executable, "main.py",
                "--lang", "cn",
                "--phase", "all",
                "--auto-gate",
                "--gate-threshold", "0.10",
                "--from-pipeline",
            ]

            if self.target_url:
                cmd.extend(["--target-url", self.target_url])

            if self.state.profile_path:
                cmd.extend(["--target-profile", self.state.profile_path])

            # 根据目标类型添加专项参数
            if self.state.target_type == "rag":
                cmd.append("--rag-mode")
            elif self.state.target_type == "agent":
                cmd.append("--agent-abuse")

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=str(Path(__file__).parent.parent),
            )

            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=600,  # 10 分钟超时
            )

            if proc.returncode != 0:
                results["errors"] = [stderr.decode("utf-8", errors="replace")]

            # 简单解析输出获取统计
            stdout_str = stdout.decode("utf-8", errors="replace")
            import re
            success_match = re.search(r"成功[:：]\s*(\d+)", stdout_str)
            total_match = re.search(r"总攻击[:：]\s*(\d+)", stdout_str)

            if total_match:
                results["total_attacks"] = int(total_match.group(1))
            else:
                results["total_attacks"] = len(targets)

            if success_match:
                results["successes"] = int(success_match.group(1))

            results["asr_score"] = results["successes"] / max(results["total_attacks"], 1)

        except FileNotFoundError:
            console.print("[yellow]  ⚠️ PyRIT main.py 未找到，跳过实际攻击[/yellow]")
        except asyncio.TimeoutError:
            console.print("[yellow]  ⚠️ PyRIT 攻击超时 (10分钟)[/yellow]")
            results["errors"] = ["攻击超时"]
        except Exception as e:
            results["errors"] = [str(e)]

        return results

    # ── L5: 报告生成 ──

    async def _run_report(self):
        """执行 L5 数据入库 + 报告生成。

        步骤:
          1. 写入 Neo4j 图数据库（如果可用）
          2. 导出 JSON 备份
          3. 调用 reporting 模块生成 OffSec 风格报告
        """
        self._print_stage_header("L5: 数据入库 + 报告生成", "Neo4j + OffSec")

        # 1. Neo4j 图数据库导入
        neo4j_exported = await self._export_to_neo4j()
        self.state.neo4j_exported = neo4j_exported

        # 2. JSON 备份
        json_path = str(self.output_dir / "pipeline_results.json")
        self.state.save(json_path)
        console.print(f"[green]  📄 JSON 备份已保存: {json_path}[/green]")

        # 3. 生成报告
        report_path = await self._generate_report()
        self.state.report_path = report_path
        self.state.report_done = True

        # 输出专家指导
        guidance = generate_guidance("report", {
            "report_path": report_path,
            "neo4j_exported": neo4j_exported,
            "json_exported": True,
        })
        console.print(guidance.render())

    async def _export_to_neo4j(self) -> bool:
        """将管道结果写入 Neo4j 图数据库。"""
        try:
            if not _IMPORTS_OK:
                console.print("[yellow]  ⚠️ Neo4j 模块导入失败，回退到 JSON[/yellow]")
                return False

            async with Neo4jClient(self._neo4j_config) as db:
                store = PipelineStore(db)

                # L0 侦察
                if self.state.recon_done:
                    await store.store_recon_result(
                        target_url=self.target_url,
                        target_type=self.state.target_type,
                        recon=AttackGraphBuilder.build_recon_result(self.state.profile_data),
                    )

                # L1 AI 场景
                if self.state.ai_detect_done:
                    await store.store_ai_scenario(
                        target_url=self.target_url,
                        scenario_type=self.state.target_type,
                        vulnerabilities=[
                            AttackGraphBuilder.build_vulnerability_from_owasp(
                                owasp_id=f.get("owasp_llm", "UNMAPPED"),
                                risk_level=f.get("risk_level", "medium"),
                                title=f.get("title", ""),
                                description=f.get("description", f.get("title", "")),
                            )
                            for f in (self.state.selected_findings or [])
                        ],
                    )

                # L4 攻击结果
                if self.state.attack_done and self.state.selected_findings:
                    vuln_results = []
                    for finding in self.state.selected_findings:
                        vuln = AttackGraphBuilder.build_vulnerability_from_owasp(
                            owasp_id=finding.get("owasp_llm", "UNMAPPED"),
                            risk_level=finding.get("risk_level", "medium"),
                            title=finding.get("title", ""),
                            description=finding.get("title", ""),
                        )
                        attack = GraphAttackResult(
                            attack_id=f"ATK-{finding.get('finding_id', 'N/A')}",
                            attack_type=self._infer_attack_type(finding),
                            target_vuln_id=finding.get("finding_id", ""),
                            success=self.state.attack_results.get("successes", 0) > 0,
                            asr_score=self.state.attack_results.get("asr_score", 0.0),
                            attempts=self.state.attack_results.get("total_attacks", 0),
                            successes=self.state.attack_results.get("successes", 0),
                        )
                        vuln_results.append((vuln, attack))
                    await store.store_attack_results(vuln_results)

                # 导出 JSON 备份
                await store.export_to_json(
                    self.target_url,
                    str(self.output_dir / "attack_graph.json"),
                )
                return True

        except Exception as e:
            console.print(f"[yellow]  ⚠️ Neo4j 导出失败 ({e})，跳过[/yellow]")
            return False

    async def _generate_report(self) -> str:
        """生成 OffSec 风格 AI 红队报告。"""
        report_dir = self.output_dir / "reports"
        report_dir.mkdir(exist_ok=True)

        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        report_name = f"AI_RedTeam_Report_{timestamp}.md"
        report_path = str(report_dir / report_name)

        # 调用 reporting 模块
        try:
            sys.path.insert(0, str(Path(__file__).parent.parent))
            cmd = [
                sys.executable, "main.py",
                "--report", "full",
                "--report-output", report_path,
                "--from-pipeline",
            ]
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=str(Path(__file__).parent.parent),
            )
            await asyncio.wait_for(proc.communicate(), timeout=120)
        except Exception:
            self._generate_minimal_report(report_path)

        console.print(f"[green]  📊 报告已生成: {report_path}[/green]")
        return report_path

    def _generate_minimal_report(self, path: str):
        """生成最小化报告（当 reporting 模块不可用时）。"""
        report = self.state
        content = f"""# AI 红队渗透测试报告

> **TLP:AMBER** — 仅供授权人员内部使用
> 生成时间: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}

## 1. 执行摘要

- **目标**: {report.target_url}
- **目标类型**: {report.target_type}
- **发现漏洞**: {len(report.selected_findings)} 个 (HIGH+)
- **攻击成功率 (ASR)**: {report.attack_results.get('asr_score', 'N/A')}

## 2. OWASP 风险映射

### LLM Top 10
"""
        # OWASP LLM 映射
        for f in (report.selected_findings or []):
            if f.get("owasp_llm"):
                content += f"- [{f.get('risk_level', '').upper()}] {f.get('owasp_llm')}: {f.get('title')}\n"

        content += "\n### Agentic Top 10\n"
        for f in (report.selected_findings or []):
            if f.get("owasp_agentic"):
                content += f"- [{f.get('risk_level', '').upper()}] {f.get('owasp_agentic')}: {f.get('title')}\n"

        content += f"""
## 3. MITRE ATLAS 映射

| Tactic | Technique | 关联漏洞 |
|--------|-----------|---------|
| Reconnaissance | AML.TA0001 | 目标: {report.target_url} |
"""

        for f in (report.selected_findings or []):
            content += f"| Initial Access | - | {f.get('title', '')} |\n"

        content += """
## 4. 修复建议矩阵

| 优先级 | 漏洞 | 修复措施 |
|--------|------|---------|
"""
        for f in (report.selected_findings or []):
            content += f"| {f.get('risk_level', '').upper()} | {f.get('title', '')} | 待评估 |\n"

        with open(path, "w", encoding="utf-8") as f:
            f.write(content)

    # ── 辅助方法 ──

    def _try_garak_scan(self) -> dict:
        """尝试执行 Garak 基线扫描。"""
        try:
            # 导入并使用 Garak 扫描器
            from executor.garak_scanner import GarakScanner
            scanner = GarakScanner()
            profile = asyncio.get_event_loop().run_until_complete(
                scanner.run_baseline(self.target_url)
            )
            return {"total_probes": profile.get("total_probes", 0),
                    "failed_probes": profile.get("failed_probes", 0),
                    "results": profile.get("results", [])}
        except ImportError:
            console.print("[dim]  (Garak 模块未导入，跳过扫描)[/dim]")
            return {}
        except Exception as e:
            console.print(f"[dim]  (Garak 扫描跳过: {e})[/dim]")
            return {}

    def _infer_attack_type(self, finding: dict) -> str:
        """根据发现推断攻击类型。"""
        owasp = finding.get("owasp_llm", "")
        if "LLM01" in owasp:
            return "injection"
        if "LLM03" in owasp:
            return "rag_poisoning"
        if "LLM07" in owasp:
            return "agent_abuse"
        if "LLM10" in owasp:
            return "extraction"
        return "general"

    def _print_stage_header(self, title: str, subtitle: str):
        console.print()
        console.print("─" * 60)
        console.print(f"[bold cyan]{title}[/bold cyan]")
        console.print(f"[dim]{subtitle}[/dim]")
        console.print("─" * 60)

    def _print_final_summary(self):
        """打印管道执行最终总结。"""
        console.print()
        table = Table(title="管道执行总结")
        table.add_column("阶段", style="cyan")
        table.add_column("状态", style="bold")
        table.add_column("关键指标")

        table.add_row(
            "L0 前置侦察",
            "✅" if self.state.recon_done else "❌",
            f"Profile: {self.state.profile_path or 'N/A'}",
        )
        table.add_row(
            "L1 AI 探测",
            "✅" if self.state.ai_detect_done else "❌",
            f"类型: {self.state.target_type}",
        )
        table.add_row(
            "L2 攻击面",
            "✅" if self.state.attack_surface_done else "❌",
            f"漏洞: {self.state.attack_surface_report.total_findings if self.state.attack_surface_report else 0}",
        )
        table.add_row(
            "L3 风险筛选",
            "✅" if self.state.risk_select_done else "❌",
            f"选中: {len(self.state.selected_findings)}",
        )
        table.add_row(
            "L4 攻击执行",
            "✅" if self.state.attack_done else "❌",
            f"ASR: {self.state.attack_results.get('asr_score', 'N/A')}",
        )
        table.add_row(
            "L5 报告",
            "✅" if self.state.report_done else "❌",
            f"Neo4j: {'✅' if self.state.neo4j_exported else '❌'}",
        )

        console.print(table)
        console.print(f"\n[green]📁 所有产物: {self.output_dir}/[/green]")

        if self.state.errors:
            console.print(f"\n[red]⚠️ {len(self.state.errors)} 个错误:[/red]")
            for e in self.state.errors[:5]:
                console.print(f"  [dim]• {e[:120]}[/dim]")


# ═══════════════════════════════════════════════════════════════════════
# CLI 入口
# ═══════════════════════════════════════════════════════════════════════

async def main_cli():
    """CLI 入口函数，支持命令行直接调用。"""
    import argparse

    parser = argparse.ArgumentParser(
        description="RedTeam_AI 全流程管道 — 六阶段 AI 红队自动化攻击",
    )
    parser.add_argument("--target-url", type=str, default="", help="目标 URL")
    parser.add_argument("--stage", type=str, default="auto",
                       choices=["auto", "recon", "ai_detect", "attack_surface", "risk_select", "attack", "report"],
                       help="起始阶段 (默认: auto — 全流程)")
    parser.add_argument("--output-dir", type=str, default="", help="输出目录")
    parser.add_argument("--profile", type=str, default="", help="已有 target_profile.json 路径")
    parser.add_argument("--resume-from", type=str, default="", help="从 pipeline_state.json 恢复")
    parser.add_argument("--min-risk", type=str, default="high",
                       choices=["critical", "high", "medium", "low"],
                       help="最低攻击风险等级")

    args = parser.parse_args()

    if not args.target_url and not args.resume_from:
        parser.error("需要 --target-url 或 --resume-from")

    target_url = args.target_url

    if args.resume_from:
        console.print("[cyan]📂 从状态文件恢复执行...[/cyan]")
        state = PipelineState.load(args.resume_from)
        target_url = state.target_url

    pipeline = FullPipeline(target_url=target_url, output_dir=args.output_dir)

    # 如果提供了 profile 路径
    if args.profile:
        with open(args.profile, "r", encoding="utf-8") as f:
            pipeline.state.profile_data = json.load(f)
        pipeline.state.profile_path = args.profile
        pipeline.state.recon_done = True

    start_stage = PipelineStage(args.stage)
    await pipeline.run(start_stage)


if __name__ == "__main__":
    asyncio.run(main_cli())
