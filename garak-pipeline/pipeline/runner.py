"""流水线编排器 (Pipeline Runner)

串联 5 个阶段，严格按产物契约传递：
  Stage1 Recon   → probe_candidates_filtered_{run_id}.json
  Stage2 Config  → 02_config/probe_selection_{run_id}.json + run_spec yaml
  Stage3 Execute → 03_execution/garak_report_{run_id}.jsonl
  Stage4 Analyze → 04_analysis/analysis_{run_id}.json
  Stage5 Report  → 05_export/pyrit_air_{run_id}.json + 终端卡片

各阶段以卡片形式展示，阶段间产物传递清晰可见。
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from .utils import (
    print_banner,
    print_result,
    print_stage_card,
)

STAGE_DIRS = {
    1: "01_recon",
    2: "02_config",
    3: "03_execution",
    4: "04_analysis",
    5: "05_export",
}


class PipelineRunner:
    """garak 全功能流水线编排器"""

    def __init__(
        self,
        target: dict[str, str],
        mode: str,
        artifacts_dir: str,
        config: dict[str, Any] | None = None,
    ) -> None:
        self.target = target
        self.mode = mode
        self.artifacts_dir = Path(artifacts_dir)
        self.config = config or {}
        self.run_id = time.strftime("%Y%m%d_%H%M")

    # ------------------------------------------------------------------
    # 路径契约
    # ------------------------------------------------------------------
    def _recon_file(self, stem: str) -> Path:
        return self.artifacts_dir / "01_recon" / f"{stem}_{self.run_id}.json"

    # ------------------------------------------------------------------
    # 编排入口
    # ------------------------------------------------------------------
    def run(self, stages: str = "all") -> dict[str, Any]:
        """运行流水线

        :param stages: "all" 或单阶段编号 (1-5) 或范围 "3-5"
        """
        print_banner(
            config_path="config/target.yaml",
            target=self.target,
            mode=self.mode,
            artifacts_dir=str(self.artifacts_dir),
        )

        # 解析阶段范围
        stage_nums = self._parse_stages(stages)
        ctx: dict[str, Any] = {}

        for n in stage_nums:
            if n == 1:
                ctx = self._run_stage1(ctx)
            elif n == 2:
                ctx = self._run_stage2(ctx)
            elif n == 3:
                ctx = self._run_stage3(ctx)
            elif n == 4:
                ctx = self._run_stage4(ctx)
            elif n == 5:
                ctx = self._run_stage5(ctx)

        print_result(self.run_id, success=True, error=None)
        return ctx

    def _parse_stages(self, stages: str) -> list[int]:
        if stages == "all":
            return [1, 2, 3, 4, 5]
        if "-" in stages:
            lo, hi = stages.split("-")
            return list(range(int(lo), int(hi) + 1))
        return [int(stages)]

    # ------------------------------------------------------------------
    # Stage 1: Recon (复用 Stage1Recon)
    # ------------------------------------------------------------------
    def _run_stage1(self, ctx: dict[str, Any]) -> dict[str, Any]:
        from .stage1_recon import Stage1Recon

        recon = Stage1Recon(
            self.target, self.mode, self.artifacts_dir, run_id=self.run_id
        )
        res = recon.run()
        if not res["success"]:
            print_result(self.run_id, success=False, error=res["error"])
            raise RuntimeError(f"Stage1 失败: {res['error']}")

        tp_path = self._recon_file("target_profile")
        filtered_path = self._recon_file("probe_candidates_filtered")

        print_stage_card(
            "1", "目标侦察 (Recon)",
            inputs=[f"config/target.yaml → {self.target['model']}"],
            outputs=[
                f"{tp_path}",
                f"{filtered_path}",
                f"{self._recon_file('connectivity_test')}",
            ],
            metrics=[
                ("活跃 Probe 总数", str(res["state"]["total_active_probes"]
                                        if "total_active_probes" in res["state"]
                                        else len(res["state"].get("active_probes", [])))),
                ("模态裁剪后", str(res["state"]["kept_probes_count"]
                                   if "kept_probes_count" in res["state"]
                                   else len(res["state"].get("kept_probes", [])))),
                ("扫描模式", self.mode),
            ],
        )
        ctx.update({"stage1": res, "filtered_path": filtered_path})
        return ctx

    # ------------------------------------------------------------------
    # Stage 2: Configure
    # ------------------------------------------------------------------
    def _run_stage2(self, ctx: dict[str, Any]) -> dict[str, Any]:
        from .stage2_configure import build_selection

        filtered_path = ctx.get("filtered_path") or self._recon_file(
            "probe_candidates_filtered"
        )
        cfg_execute = self.config.get("execute", {})
        tier_filter = cfg_execute.get("tier_filter")
        buff_spec = cfg_execute.get("buff_spec", None)
        scan_profile = cfg_execute.get("scan_profile")

        out = build_selection(
            filtered_path, self.run_id, str(self.artifacts_dir),
            tier_filter=tier_filter, buff_spec=buff_spec or None,
            scan_profile=scan_profile,
        )
        sel = out["selection"]

        print_stage_card(
            "2", "攻击配置 (Configure)",
            inputs=[str(filtered_path)],
            outputs=[out["sel_path"], out["spec_path"]],
            metrics=[
                ("扫描档位", sel["scan_profile"]),
                ("选中探针", str(sel["total_selected"])),
                ("Tier 分布", ", ".join(f"{k}:{v}" for k, v in sel["tier_breakdown"].items())),
                ("Buff 攻击链", sel["buff_spec"] or "无"),
            ],
        )
        ctx.update({"stage2": out, "selection": sel})
        return ctx

    # ------------------------------------------------------------------
    # Stage 3: Execute (garak 真驱动)
    # ------------------------------------------------------------------
    def _run_stage3(self, ctx: dict[str, Any]) -> dict[str, Any]:
        from .stage3_execute import execute_attack, parse_report_probe_names

        sel = ctx.get("selection")
        if not sel:
            raise RuntimeError("Stage3 缺少 Stage2 的 probe 选择，请先运行 Stage2")
        cfg_execute = self.config.get("execute", {})
        cfg_report = self.config.get("reporting", {})

        print("   ⚔️  驱动 garak harness 发起攻击...")
        result = execute_attack(
            self.target,
            sel["probe_names"],
            sel["buff_spec"],
            self.run_id,
            str(self.artifacts_dir),
            execute_cfg=cfg_execute,
            reporting_cfg=cfg_report,
        )
        executed = parse_report_probe_names(result["report_path"])

        print_stage_card(
            "3", "攻击执行 (Execute)",
            inputs=[out_path for out_path in [
                ctx.get("stage2", {}).get("sel_path"),
                ctx.get("stage2", {}).get("spec_path"),
            ] if out_path],
            outputs=[result["report_path"]],
            metrics=[
                ("目标生成器", result["generator"]),
                ("配置探针", str(result["probe_count"])),
                ("实际执行探针", str(len(executed))),
                ("Buff 攻击链", result["buff_spec"] or "无"),
                ("每探针 generations", str(result["generations"])),
            ],
        )
        ctx.update({"stage3": result, "executed_probes": executed})
        return ctx

    # ------------------------------------------------------------------
    # Stage 4: Analyze
    # ------------------------------------------------------------------
    def _run_stage4(self, ctx: dict[str, Any]) -> dict[str, Any]:
        from .stage4_analyze import analyze

        report_path = ctx["stage3"]["report_path"]
        # 读回 filtered probes 用于双框架分类
        filtered_path = ctx.get("filtered_path") or self._recon_file(
            "probe_candidates_filtered"
        )
        import json as _json
        with open(filtered_path, encoding="utf-8") as f:
            kept_probes = _json.load(f)

        result = analyze(
            report_path, kept_probes, self.run_id,
            str(self.artifacts_dir), garak_run_id=ctx["stage3"].get("garak_run_id"),
        )

        llm_defcon = {k: v["defcon"] for k, v in result["owasp_llm"].items()}
        agentic_defcon = {k: v["defcon"] for k, v in result["owasp_agentic"].items()}

        print_stage_card(
            "4", "攻击分析 (Analyze)",
            inputs=[report_path],
            outputs=[result["analysis_path"]],
            metrics=[
                ("评估探针数", str(result["probes_evaluated"])),
                ("OWASP 桶数", str(len(result["owasp_llm"]))),
                ("Agentic 桶数", str(len(result["owasp_agentic"]))),
                ("最差 DEFCON(LLM)", str(min(llm_defcon.values()) if llm_defcon else "-")),
                ("最差 DEFCON(Agentic)", str(min(agentic_defcon.values()) if agentic_defcon else "-")),
            ],
        )
        ctx.update({"stage4": result})
        return ctx

    # ------------------------------------------------------------------
    # Stage 5: Report & Export
    # ------------------------------------------------------------------
    def _run_stage5(self, ctx: dict[str, Any]) -> dict[str, Any]:
        from .recon_garak import OWASP_CATEGORIES
        from .stage5_report import export_pyrit_air, render_final_cards

        analysis = ctx["stage4"]
        # 完整 OWASP LLM Top10 类集合，用于透明标注未覆盖类（N/A）
        all_owasp_ids = list(OWASP_CATEGORIES.values())
        air_path = export_pyrit_air(
            analysis, str(self.artifacts_dir), self.run_id,
            all_owasp_ids=all_owasp_ids,
        )
        render_final_cards(analysis, all_owasp_ids=all_owasp_ids)

        print_stage_card(
            "5", "报告与导出 (Report/Export)",
            inputs=[analysis["analysis_path"]],
            outputs=[air_path],
            metrics=[
                ("导出格式", "PyRIT AIR v1"),
                ("产物", air_path),
            ],
        )
        ctx.update({"stage5": {"air_path": air_path}})
        return ctx
