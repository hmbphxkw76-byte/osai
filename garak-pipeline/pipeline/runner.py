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
        run_id: str | None = None,
    ) -> None:
        self.target = target
        self.mode = mode
        self.artifacts_dir = Path(artifacts_dir)
        self.config = config or {}
        # 支持复用历史 run_id（--stage 4-5 --run-id 旧批次）；
        # 未提供则用当前时间戳生成新批次
        self.run_id = run_id or time.strftime("%Y%m%d_%H%M")
        self.start_time = time.time()
        # P2-3: 保存最后一次 run() 的上下文，供 API 层查询
        self._last_ctx: dict[str, Any] = {}

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
        # config_path 仅作展示用：从 target.kind 推断实际配置文件名
        kind = self.target.get("kind", "openai")
        config_path = f"config/{kind}_target.yaml"
        print_banner(
            config_path=config_path,
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

        print_result(
            success=True,
            elapsed=time.time() - self.start_time,
            run_id=self.run_id,
            artifacts_dir=str(self.artifacts_dir),
            error=None,
        )
        self._last_ctx = ctx
        return ctx

    def get_results(self) -> dict[str, Any]:
        """P2-3: 返回最后一次 run() 的产物路径摘要（供 API 调用）

        :returns: 包含各阶段产物路径的 dict
        """
        ctx = self._last_ctx
        if not ctx:
            return {"run_id": self.run_id, "status": "not_run"}

        result: dict[str, Any] = {
            "run_id": self.run_id,
            "status": "completed",
            "artifacts_dir": str(self.artifacts_dir),
        }
        if "stage3" in ctx:
            result["report_path"] = ctx["stage3"].get("report_path")
        if "stage4" in ctx:
            result["analysis_path"] = ctx["stage4"].get("analysis_path")
        if "stage5" in ctx:
            result.update(ctx["stage5"])
        return result

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
            print_result(
                success=False,
                elapsed=0.0,
                run_id=self.run_id,
                artifacts_dir=self.artifacts_dir,
                error=res["error"],
            )
            raise RuntimeError(f"Stage1 失败: {res['error']}")

        # 降级模式：连通性未通过但探针枚举成功，不中断流水线
        state = res.get("state", {})
        degraded = state.get("degraded_mode", False)
        conn_status = state.get("connectivity_status", "ok")
        warnings = state.get("warnings", [])

        tp_path = self._recon_file("target_profile")
        filtered_path = self._recon_file("probe_candidates_filtered")

        # 降级模式下在产物卡片中标注
        mode_label = f"{self.mode}{' [降级]' if degraded else ''}"
        metrics = [
            ("活跃 Probe 总数", str(
                state.get("total_active_probes",
                          len(state.get("active_probes", [])))
            )),
            ("模态裁剪后", str(
                state.get("kept_probes_count",
                          len(state.get("kept_probes", [])))
            )),
            ("扫描模式", mode_label),
            ("连通性", conn_status),
        ]

        print_stage_card(
            "1", "目标侦察 (Recon)",
            inputs=[f"config/target.yaml → {self.target['model']}"],
            outputs=[
                f"{tp_path}",
                f"{filtered_path}",
                f"{self._recon_file('connectivity_test')}",
            ],
            metrics=metrics,
        )

        if degraded:
            for w in warnings:
                print(f"   ⚠️  {w}")

        ctx.update({
            "stage1": res,
            "filtered_path": filtered_path,
            "degraded_mode": degraded,
        })
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
        # P1-4: 读取 atkgen 配置，传递给 Stage2
        atkgen_cfg = self.config.get("atkgen", None)

        out = build_selection(
            filtered_path, self.run_id, str(self.artifacts_dir),
            tier_filter=tier_filter, buff_spec=buff_spec or None,
            scan_profile=scan_profile,
            atkgen_cfg=atkgen_cfg,
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
                ("atkgen 动态变异", "启用" if sel.get("atkgen_enabled") else "关闭"),
            ],
        )
        ctx.update({"stage2": out, "selection": sel})
        return ctx

    # ------------------------------------------------------------------
    # Stage 3: Execute (garak 真驱动)
    # ------------------------------------------------------------------
    def _run_stage3(self, ctx: dict[str, Any]) -> dict[str, Any]:
        from .stage3_execute import execute_attack, parse_report_probe_names, preflight_check

        sel = ctx.get("selection")
        if not sel:
            raise RuntimeError("Stage3 缺少 Stage2 的 probe 选择，请先运行 Stage2")
        cfg_execute = self.config.get("execute", {})
        cfg_report = self.config.get("reporting", {})

        # G6 修复：降级模式前置校验 — 连通性失败时告警
        degraded = ctx.get("degraded_mode", False)
        conn_status = ctx.get("stage1", {}).get("state", {}).get(
            "connectivity_status", "ok"
        )

        # 调用 Stage 3 前置校验函数
        preflight_warnings = preflight_check(
            self.target, sel["probe_names"], conn_status,
        )
        for w in preflight_warnings:
            print(f"   ⚠️  {w}")

        if degraded or conn_status == "failed":
            print("   ⚠️  降级模式: 连通性测试未通过，攻击执行可能失败")
            print(f"       连通性状态: {conn_status}")
            print("       建议: 手动确认端点可达性或通过 --stage 1-2 仅执行侦察")

        print("   ⚔️  驱动 garak harness 发起攻击...")
        # P2-2: 从 Stage1 侦察产物中提取速率限制，注入 target dict 供 Stage3 动态消费
        stage1_state = ctx.get("stage1", {}).get("state", {})
        model_caps = stage1_state.get("model_capabilities", {})
        if model_caps.get("rate_limits"):
            self.target["_recon_rate_limits"] = model_caps["rate_limits"]
        # P0-1: 从 Stage1 侦察产物中提取 max_tokens，注入 target 供 Stage3 配置
        if model_caps.get("max_tokens") and not self.target.get("_recon_max_tokens"):
            self.target["_recon_max_tokens"] = model_caps["max_tokens"]
        result = execute_attack(
            self.target,
            sel["probe_names"],
            sel["buff_spec"],
            self.run_id,
            str(self.artifacts_dir),
            execute_cfg=cfg_execute,
            reporting_cfg=cfg_report,
            judge_cfg=self.config.get("judge", {}),
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

        # 支持 --stage 4-5 复用历史产物：ctx 无 stage3 时从 artifacts 恢复
        stage3 = ctx.get("stage3")
        if stage3:
            report_path = stage3["report_path"]
            garak_run_id = stage3.get("garak_run_id")
            judge_path = stage3.get("judge_path")
        else:
            # 从 03_execution 目录查找 garak_report_{run_id}.jsonl
            exec_dir = self.artifacts_dir / "03_execution"
            report_path = str(exec_dir / f"garak_report_{self.run_id}.jsonl")
            garak_run_id = None
            judge_path = str(exec_dir / f"judge_results_{self.run_id}.jsonl")
            if not Path(judge_path).exists():
                judge_path = None

        # 读回 filtered probes 用于双框架分类
        filtered_path = ctx.get("filtered_path") or self._recon_file(
            "probe_candidates_filtered"
        )
        import json as _json
        with open(filtered_path, encoding="utf-8") as f:
            kept_probes = _json.load(f)

        result = analyze(
            report_path, kept_probes, self.run_id,
            str(self.artifacts_dir),
            garak_run_id=garak_run_id,
            modality_filter=ctx.get("stage1", {}).get("state", {}).get("modality_filter"),
            judge_path=judge_path,
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
        from .stage5_report import generate_full_report

        analysis = ctx["stage4"]
        # 完整 OWASP LLM Top10 类集合，用于透明标注未覆盖类（N/A）
        all_owasp_ids = list(OWASP_CATEGORIES.values())
        # L5 一站式报告生成：终端卡片 + PyRIT JSON + HTML 可视化 + AVID + PDF
        report_paths = generate_full_report(
            analysis, str(self.artifacts_dir), self.run_id,
            all_owasp_ids=all_owasp_ids,
        )
        air_path = report_paths["pyrit_air"]
        html_path = report_paths["html"]
        avid_path = report_paths.get("avid", "")
        pdf_path = report_paths.get("pdf", "")
        sarif_path = report_paths.get("sarif", "")
        conv_path = report_paths.get("conversations", "")

        # P1-2: Stage5 卡片显示全部产物路径（含 AVID + PDF + SARIF + Conversations）
        output_paths = [air_path, html_path]
        if avid_path:
            output_paths.append(avid_path)
        if pdf_path:
            output_paths.append(pdf_path)
        if sarif_path:
            output_paths.append(sarif_path)
        if conv_path:
            output_paths.append(conv_path)

        print_stage_card(
            "5", "报告与导出 (Report/Export)",
            inputs=[analysis["analysis_path"]],
            outputs=output_paths,
            metrics=[
                ("PyRIT AIR", air_path),
                ("HTML 报告", html_path),
                ("AVID 报告", avid_path or "N/A"),
                ("PDF 报告", pdf_path or "N/A"),
                ("SARIF 报告", sarif_path or "N/A"),
                ("对话上下文", conv_path or "N/A"),
                ("命中明细", analysis.get("hitlog", {}).get("markdown_path", "N/A")),
                ("可复现哈希", analysis.get("repro_hash", "N/A")),
            ],
        )
        ctx.update({"stage5": {
            "air_path": air_path,
            "html_path": html_path,
            "avid_path": avid_path,
            "pdf_path": pdf_path,
            "sarif_path": sarif_path,
            "conversations_path": conv_path,
        }})
        # P3-4: 通知/告警集成（Webhook）
        try:
            from .notify import send_notification
            notify_cfg = self.config.get("notify", None)
            send_notification(analysis, self.run_id, notify_cfg)
        except Exception:
            pass
        return ctx
