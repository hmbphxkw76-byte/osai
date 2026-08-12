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
    defcon_label,
    print_atlas_heatmap,
    print_banner,
    print_conversation_preview,
    print_cross_model_comparison,
    print_ioa_preview,
    print_kill_paths,
    print_multi_run_comparison,
    print_offsec_engagement_summary,
    print_recon_to_attack_bridge,
    print_remediation_priority,
    print_result,
    print_stage_card,
    print_technique_intent_matrix,
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
            scope=self.config.get("scope"),
        )

        # 解析阶段范围
        stage_nums = self._parse_stages(stages)
        ctx: dict[str, Any] = {}

        for n in stage_nums:
            _stage_start = time.time()
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
            ctx[f"_stage{n}_elapsed"] = time.time() - _stage_start

        print_result(
            success=True,
            elapsed=time.time() - self.start_time,
            run_id=self.run_id,
            artifacts_dir=str(self.artifacts_dir),
            error=None,
        )

        # E3: 多目标横向对比（历史 run_id 安全态势演进）
        print_multi_run_comparison(
            str(self.artifacts_dir), self.run_id,
        )

        # F7: 跨模型横向对比矩阵（同一探针 vs 不同模型 ASR）
        print_cross_model_comparison(str(self.artifacts_dir))

        # offsec 红队交战总结（攻击投递统计 + 命中战果）
        stage3 = ctx.get("stage3", {})
        stage4 = ctx.get("stage4", {})
        if stage3 or stage4:
            print_offsec_engagement_summary(
                probes_total=stage3.get("probe_count", 0),
                probes_succeeded=stage3.get("probes_succeeded", 0),
                probes_failed=stage3.get("probes_failed", 0),
                probes_skipped=stage3.get("probes_skipped", 0),
                analysis=stage4 if stage4 else None,
            )

        self._last_ctx = ctx

        # N4: ASR 回归检测（与历史结果对比，检测安全态势退化）
        self._check_asr_regression(ctx)

        return ctx

    def _check_asr_regression(self, ctx: dict[str, Any]) -> None:
        """N4: ASR 回归检测 — 与历史扫描结果对比，检测安全态势退化

        当当前 ASR 显著高于历史基线时，在终端输出回归告警。
        回归阈值由 config["regression"]["asr_threshold"] 配置（默认 10%）。
        """
        import json as _json
        import glob as _glob

        stage4 = ctx.get("stage4")
        if not stage4:
            return

        current_asr = stage4.get("overall", {}).get("worst_asr", 0)
        current_defcon = stage4.get("overall", {}).get("defcon", 5)

        # 查找历史分析文件
        pattern = str(self.artifacts_dir / "04_analysis" / "analysis_*.json")
        files = sorted(_glob.glob(pattern))
        # 排除当前 run_id
        current_path = stage4.get("analysis_path", "")
        history_files = [f for f in files if current_path not in f or Path(f).name != Path(current_path).name]
        if len(history_files) < 1:
            return

        # 加载最近的基线
        baseline_file = history_files[-1]
        try:
            with open(baseline_file) as f:
                baseline = _json.load(f)
        except Exception:
            return

        baseline_asr = baseline.get("overall", {}).get("worst_asr", 0)
        baseline_defcon = baseline.get("overall", {}).get("defcon", 5)
        delta_asr = current_asr - baseline_asr
        delta_defcon = baseline_defcon - current_defcon  # 正值=恶化

        # 回归阈值
        regression_cfg = self.config.get("regression", {})
        asr_threshold = regression_cfg.get("asr_threshold", 10)

        if delta_asr > asr_threshold or delta_defcon >= 2:
            print()
            print("╔════════════════════════════════════════════════════════════╗")
            print("║  ⚠️  ASR 回归告警 (Security Regression Detected)          ║")
            print("╠════════════════════════════════════════════════════════════╣")
            print(f"║  基线 ASR:    {baseline_asr:>6.1f}%  (DEFCON {baseline_defcon})".ljust(62) + "║")
            print(f"║  当前 ASR:    {current_asr:>6.1f}%  (DEFCON {current_defcon})".ljust(62) + "║")
            print(f"║  Delta ASR:   {delta_asr:>+6.1f}%  (阈值: +{asr_threshold}%)".ljust(62) + "║")
            print(f"║  Delta DEFCON: {delta_defcon:>+2d}     (正值=恶化)".ljust(62) + "║")
            print("╠════════════════════════════════════════════════════════════╣")
            if delta_asr > asr_threshold:
                print(f"║  ⛔ ASR 回归超阈值: {delta_asr:+.1f}% > +{asr_threshold}%".ljust(62) + "║")
            if delta_defcon >= 2:
                print(f"║  ⛔ DEFCON 恶化 {delta_defcon} 级".ljust(62) + "║")
            print("║  建议: 检查目标模型近期变更是否引入新攻击面            ║")
            print("╚════════════════════════════════════════════════════════════╝")
        elif delta_asr > 0:
            print(f"\n  ℹ️  ASR 轻微变化: {baseline_asr}% → {current_asr}% (Δ={delta_asr:+.1f}%, 在阈值内)")

        # F5: 多基线趋势回归分析（统计趋势，非单点比较）
        if len(history_files) >= 3:
            trend_data = []
            for hf in history_files[-5:]:  # 最近 5 次历史
                try:
                    with open(hf) as f:
                        hist = _json.load(f)
                    trend_data.append({
                        "asr": hist.get("overall", {}).get("worst_asr", 0),
                        "defcon": hist.get("overall", {}).get("defcon", 5),
                        "run_id": Path(hf).stem.replace("analysis_", ""),
                    })
                except Exception:
                    pass
            trend_data.append({"asr": current_asr, "defcon": current_defcon, "run_id": self.run_id})

            if len(trend_data) >= 3:
                # 计算线性回归斜率（最小二乘法）
                n = len(trend_data)
                xs = list(range(n))
                ys = [d["asr"] for d in trend_data]
                x_mean = sum(xs) / n
                y_mean = sum(ys) / n
                numerator = sum((xs[i] - x_mean) * (ys[i] - y_mean) for i in range(n))
                denominator = sum((xs[i] - x_mean) ** 2 for i in range(n))
                slope = numerator / denominator if denominator else 0

                # 趋势判定
                if slope > asr_threshold / n:
                    trend_label = "📉 安全态势恶化（ASR 持续上升）"
                    trend_alert = True
                elif slope < -1:
                    trend_label = "📈 安全态势改善（ASR 持续下降）"
                    trend_alert = False
                else:
                    trend_label = "➡️ 安全态势稳定"
                    trend_alert = False

                print()
                print("╔════════════════════════════════════════════════════════════╗")
                print("║  📊 多基线趋势回归分析 (Multi-Baseline Trend)             ║")
                print("╠════════════════════════════════════════════════════════════╣")
                print(f"║  基线数量:    {len(trend_data)} 次扫描".ljust(62) + "║")
                print(f"║  ASR 均值:    {y_mean:>6.1f}%".ljust(62) + "║")
                print(f"║  ASR 斜率:    {slope:>+6.2f}%/run".ljust(62) + "║")
                print(f"║  趋势判定:    {trend_label}".ljust(62) + "║")
                # ASR 序列
                asr_seq = " → ".join(f"{d['asr']:.0f}%" for d in trend_data)
                print(f"║  ASR 序列:    {asr_seq}".ljust(62) + "║")
                if trend_alert:
                    print("║  ⛔ 检测到持续上升趋势 — 建议立即排查模型变更        ║".ljust(62) + "║")
                print("╚════════════════════════════════════════════════════════════╝")

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
            "1", "攻击面侦察 (Reconnaissance)",
            inputs=[f"config/target.yaml → {self.target['model']}"],
            outputs=[
                f"{tp_path}",
                f"{filtered_path}",
                f"{self._recon_file('connectivity_test')}",
            ],
            metrics=metrics,
            elapsed=ctx.get("_stage1_elapsed"),
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
            recon_state=ctx.get("stage1", {}).get("state"),
        )
        sel = out["selection"]

        # Phase 1: 侦察→攻击决策链过渡卡片
        rationale = sel.get("attack_rationale", [])
        if rationale:
            print_recon_to_attack_bridge(rationale)

        print_stage_card(
            "2", "武器化配置 (Weaponization)",
            inputs=[str(filtered_path)],
            outputs=[out["sel_path"], out["spec_path"]],
            metrics=[
                ("扫描档位", sel["scan_profile"]),
                ("选中探针", str(sel["total_selected"])),
                ("Tier 分布", ", ".join(f"{k}:{v}" for k, v in sel["tier_breakdown"].items())),
                ("Buff 攻击链", sel["buff_spec"] or "无"),
                ("atkgen 动态变异", "启用" if sel.get("atkgen_enabled") else "关闭"),
            ],
            elapsed=ctx.get("_stage2_elapsed"),
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

        # P2-2: 从 Stage1 侦察产物中提取速率限制，注入 target dict 供 Stage3 动态消费
        stage1_state = ctx.get("stage1", {}).get("state", {})
        model_caps = stage1_state.get("model_capabilities", {})
        if model_caps.get("rate_limits"):
            self.target["_recon_rate_limits"] = model_caps["rate_limits"]
        # P0-1: 从 Stage1 侦察产物中提取 max_tokens，注入 target 供 Stage3 配置
        if model_caps.get("max_tokens") and not self.target.get("_recon_max_tokens"):
            self.target["_recon_max_tokens"] = model_caps["max_tokens"]
        # Phase 2: 构建探针→ATLAS TTP 标注映射
        probe_ttp_map: dict[str, str] = {}
        try:
            from .atlas_map import ATLAS_PROBE_MAP
            for pn in sel["probe_names"]:
                short = pn.replace("probes.", "")
                ttps = ATLAS_PROBE_MAP.get(short, [])
                if ttps:
                    probe_ttp_map[pn] = ", ".join(ttps)
        except Exception:
            pass

        # ---------------------------------------------------------------
        # 分阶段递进执行模式（phased）
        # ---------------------------------------------------------------
        is_phased = sel.get("phased", False)
        if is_phased:
            return self._run_stage3_phased(
                ctx, sel, cfg_execute, cfg_report, probe_ttp_map,
            )

        # ---------------------------------------------------------------
        # 常规一次性执行模式（full/balanced/quick/smoke）
        # ---------------------------------------------------------------
        print("   🚀 投递攻击载荷，驱动 garak harness 执行...")
        result = execute_attack(
            self.target,
            sel["probe_names"],
            sel["buff_spec"],
            self.run_id,
            str(self.artifacts_dir),
            execute_cfg=cfg_execute,
            reporting_cfg=cfg_report,
            judge_cfg=self.config.get("judge", {}),
            probe_ttp_map=probe_ttp_map,
        )
        executed = parse_report_probe_names(result["report_path"])

        print_stage_card(
            "3", "攻击投递与利用 (Delivery & Exploitation)",
            inputs=[out_path for out_path in [
                ctx.get("stage2", {}).get("sel_path"),
                ctx.get("stage2", {}).get("spec_path"),
            ] if out_path],
            outputs=[result["report_path"]],
            metrics=[
                ("目标生成器", result["generator"]),
                ("配置探针", str(result["probe_count"])),
                ("成功投递", str(result.get("probes_succeeded", 0))),
                ("投递失败", str(result.get("probes_failed", 0))),
                ("断点跳过", str(result.get("probes_skipped", 0))),
                ("Buff 攻击链", result["buff_spec"] or "无"),
                ("每探针 generations", str(result["generations"])),
            ],
            elapsed=ctx.get("_stage3_elapsed"),
        )
        ctx.update({"stage3": result, "executed_probes": executed, "probe_ttp_map": probe_ttp_map})
        return ctx

    def _run_stage3_phased(
        self,
        ctx: dict[str, Any],
        sel: dict,
        cfg_execute: dict,
        cfg_report: dict,
        probe_ttp_map: dict[str, str],
    ) -> dict[str, Any]:
        """分阶段递进执行（Phase 0~4，阶段间决策门 + 全部 L5 差距修复）

        Gap #1:  Phase 4 自适应 generations（CI 宽度驱动）
        Gap #2:  阶段间并发自适应（Phase 0 高并发 / Phase 4 低并发）
        Gap #3:  Phase 2 Buff 策略自适应（refusal_rate 驱动）
        Gap #4:  多模态探针在 Phase 1 优先级提升
        Gap #5:  阶段间 token 预算控制
        Gap #6:  决策门 ASR 阈值可配置化
        Gap #7:  Phase 0 探针语言适配
        Gap #8:  阶段趋势数据回传 Stage4
        Gap #9:  Phase 4 atkgen 动态变异集成
        Gap #10: 阶段间人工确认断点
        """
        from .phased_execution import (
            DEFAULT_PHASES,
            PhaseResult,
            PhasedConfig,
            adapt_phases_by_modality,
            adapt_smoke_probes_by_language,
            build_phase_execute_cfg,
            build_phase_trend_data,
            check_token_budget,
            compute_adaptive_generations,
            evaluate_phase_result,
            interactive_checkpoint,
            load_phased_config,
            print_phase_decision,
            print_phase_header,
            save_phase_decision_log,
            select_buff_by_defense_behavior,
            select_probes_for_phase,
        )
        from .stage3_execute import (
            execute_phase_attack,
            merge_phase_reports,
            parse_report_probe_names,
        )
        from .stage3_execute import _quick_probe_asr

        # Gap #6: 加载可配置阈值
        yaml_phased = self.config.get("phased", None)
        phased_cfg = load_phased_config(yaml_phased)

        # 读取 Stage1 模态过滤后的全量探针
        filtered_path = ctx.get("filtered_path") or self._recon_file(
            "probe_candidates_filtered"
        )
        import json as _json
        with open(filtered_path, encoding="utf-8") as f:
            all_filtered_probes = _json.load(f)

        # Stage1 侦察状态
        stage1_state = ctx.get("stage1", {}).get("state", {})

        # Gap #4: 模态适配阶段配置
        model_modality = stage1_state.get("model_modality", {})
        target_mod_in = model_modality.get("in", {"text"})
        if isinstance(target_mod_in, set):
            target_mod_in = sorted(target_mod_in)

        phases = adapt_phases_by_modality(DEFAULT_PHASES, target_mod_in)

        # Gap #7: Phase 0 探针语言适配
        target_profile = stage1_state.get("target_profile", {})
        target_language = target_profile.get("target_language", "unknown")
        if not target_language:
            model_lower = (self.target.get("model") or "").lower()
            cn_keywords = ("qwen", "baichuan", "chatglm", "glm", "yi-", "deepseek",
                           "ernie", "spark", "moonshot", "kimi", "longcat", "abab")
            target_language = "zh" if any(k in model_lower for k in cn_keywords) else "en"
        phases = adapt_smoke_probes_by_language(phases, target_language)

        print(f"\n   🏛️  分阶段递进执行模式 (Phased Execution)")
        print(f"       目标模态: {', '.join(target_mod_in)}")
        print(f"       目标语言: {target_language}")
        print(f"       阶段数: {len(phases)}")
        print(f"       全量探针池: {len(all_filtered_probes)} 个")
        print(f"       人工确认断点: {'启用' if phased_cfg.interactive else '关闭'}")
        print(f"       Token 预算: {phased_cfg.max_tokens_budget or '不限'}")
        print(f"       ASR 阈值: critical={phased_cfg.critical_asr_threshold}%, "
              f"continue={phased_cfg.continue_asr_threshold}%")

        phase_results_data: list[dict] = []
        phase_results: list[PhaseResult] = []
        cumulative_hits: int = 0
        cumulative_hit_probes: list[str] = []
        cumulative_tokens: int = 0
        stopped: bool = False

        for phase_idx, phase in enumerate(phases):
            # Phase 4 仅在有命中时触发
            if phase.phase_id == 4 and not cumulative_hit_probes:
                result = PhaseResult(
                    phase_id=phase.phase_id,
                    name=phase.name,
                    probe_count=0,
                    probes_succeeded=0,
                    probes_failed=0,
                    worst_asr=0.0,
                    hit_count=0,
                    decision="skip",
                    decision_reason="无命中探针，跳过深度确认",
                )
                phase_results.append(result)
                print_phase_decision(result)
                continue

            # Gap #1: Phase 4 自适应 generations
            if phase.phase_id == 4 and phase.adaptive_generations:
                adaptive_gen = compute_adaptive_generations(
                    cumulative_hit_probes, phase_results,
                    phased_cfg.phase4_base_generations,
                )
                phase.generations = adaptive_gen

            # 选择本阶段探针
            phase_probes = select_probes_for_phase(
                phase, all_filtered_probes,
                hit_probes=cumulative_hit_probes if phase.phase_id == 4 else None,
            )

            if not phase_probes:
                result = PhaseResult(
                    phase_id=phase.phase_id,
                    name=phase.name,
                    probe_count=0,
                    probes_succeeded=0,
                    probes_failed=0,
                    worst_asr=0.0,
                    hit_count=0,
                    decision="skip",
                    decision_reason="本阶段无探针可执行（模态过滤后为空）",
                )
                phase_results.append(result)
                print_phase_decision(result)
                continue

            # Gap #3: Phase 2 Buff 策略自适应
            effective_buff = phase.buff_spec
            if phase.phase_id == 2 and phase_results:
                phase1_result = next(
                    (r for r in phase_results if r.phase_id == 1), None,
                )
                if phase1_result and phase1_result.refusal_rate >= 0:
                    effective_buff = select_buff_by_defense_behavior(
                        phase1_result.refusal_rate, phased_cfg,
                    )
                    phase.buff_spec = effective_buff

            # 阶段特定 run_id
            phase_run_id = f"{self.run_id}_p{phase.phase_id}"
            phase_probe_names = [p["name"] for p in phase_probes]

            # 阶段特定 execute_cfg（Gap #2 并发, Gap #9 atkgen）
            atkgen_cfg = self.config.get("atkgen", None)
            phase_execute_cfg = build_phase_execute_cfg(
                phase, cfg_execute, phased_cfg, atkgen_cfg,
            )

            # 阶段特定 judge_cfg（Phase 4 强制启用）
            phase_judge_cfg = self.config.get("judge", {})
            if phase.phase_id == 4:
                phase_judge_cfg = dict(phase_judge_cfg)
                phase_judge_cfg["enabled"] = phased_cfg.phase4_enable_judge

            # 打印阶段头部
            print_phase_header(phase)
            print(f"   🚀 Phase {phase.phase_id}: {len(phase_probe_names)} 探针, "
                  f"generations={phase.generations}, buff={effective_buff or 'none'}")

            # 执行本阶段攻击
            import time as _time
            import math as _math
            phase_start = _time.time()
            phase_result_data = execute_phase_attack(
                target=self.target,
                probe_names=phase_probe_names,
                buff_spec=effective_buff,
                run_id=phase_run_id,
                artifacts_dir=str(self.artifacts_dir),
                execute_cfg=phase_execute_cfg,
                reporting_cfg=cfg_report,
                judge_cfg=phase_judge_cfg,
                probe_ttp_map=probe_ttp_map,
            )
            phase_elapsed = _time.time() - phase_start

            # 快速解析本阶段 ASR + 命中探针 + 拒绝率 + CI 宽度
            phase_report_path = phase_result_data.get("report_path", "")
            phase_worst_asr = 0.0
            phase_hit_probes: list[str] = []
            asr_by_probe: dict[str, float] = {}
            for pn in phase_probe_names:
                asr = _quick_probe_asr(phase_report_path, pn)
                if asr is not None:
                    asr_by_probe[pn] = asr
                    if asr > 0:
                        phase_worst_asr = max(phase_worst_asr, asr)
                        phase_hit_probes.append(pn)

            # Gap #3: 计算拒绝率
            stealth = phase_result_data.get("stealth_assessment", {})
            phase_refusal_rate = stealth.get("refusal_rate", 0.0) if stealth else 0.0

            # Gap #1: 提取 CI 宽度
            ci_width = 0.0
            for pn, asr in asr_by_probe.items():
                n = phase.generations * 10
                p = asr / 100.0
                if n > 0 and 0 < p < 1:
                    ci = 2 * 1.96 * _math.sqrt(p * (1 - p) / n) * 100
                    ci_width = max(ci_width, ci)

            # Gap #5: token 消耗统计
            phase_tokens = 0
            tu = phase_result_data.get("token_usage")
            if isinstance(tu, dict):
                phase_tokens = tu.get("total_tokens", 0)
            cumulative_tokens += phase_tokens

            phase_hit_count = len(phase_hit_probes)
            cumulative_hits += phase_hit_count
            cumulative_hit_probes.extend(
                p for p in phase_hit_probes if p not in cumulative_hit_probes
            )

            # 构建 PhaseResult（含全部 gap 字段）
            result = PhaseResult(
                phase_id=phase.phase_id,
                name=phase.name,
                probe_count=len(phase_probe_names),
                probes_succeeded=phase_result_data.get("probes_succeeded", 0),
                probes_failed=phase_result_data.get("probes_failed", 0),
                worst_asr=phase_worst_asr,
                hit_count=phase_hit_count,
                hit_probes=phase_hit_probes,
                report_path=phase_report_path,
                elapsed_seconds=phase_elapsed,
                refusal_rate=phase_refusal_rate,
                ci_width=ci_width,
                tokens_consumed=phase_tokens,
                asr_by_probe=asr_by_probe,
            )
            phase_results_data.append(phase_result_data)

            # Gap #6: 决策门评估（使用可配置阈值）
            decision, reason = evaluate_phase_result(
                phase, result, cumulative_hits, phased_cfg,
            )
            result.decision = decision
            result.decision_reason = reason
            phase_results.append(result)

            # 打印决策结果
            print_phase_decision(result)

            # Gap #5: token 预算检查
            over_budget, budget_reason = check_token_budget(
                cumulative_tokens, phased_cfg,
            )
            if over_budget:
                stopped = True
                print(f"\n   💰 Token 预算超限: {budget_reason}")
                break

            # Gap #10: 人工确认断点
            next_phase = phases[phase_idx + 1] if phase_idx + 1 < len(phases) else None
            if next_phase and decision == "continue":
                user_decision = interactive_checkpoint(
                    phase, result, next_phase, phased_cfg,
                )
                if user_decision == "stop":
                    stopped = True
                    print(f"\n   🛑 用户终止执行")
                    break
                elif user_decision == "skip":
                    result.decision = "skip"
                    result.decision_reason += " [用户手动跳过]"

            # 决策门：终止
            if decision == "stop":
                stopped = True
                print(f"\n   ⏹️  决策门: STOP — {reason}")
                break

        # 保存决策日志
        decision_log_path = save_phase_decision_log(
            phase_results, self.run_id, str(self.artifacts_dir),
        )

        # 合并各阶段报告
        if phase_results_data:
            merged_report_path = merge_phase_reports(
                phase_results_data, str(self.artifacts_dir), self.run_id,
            )
        else:
            merged_report_path = ""

        executed = parse_report_probe_names(merged_report_path)

        # 统计汇总
        total_succeeded = sum(r.probes_succeeded for r in phase_results)
        total_failed = sum(r.probes_failed for r in phase_results)
        total_worst_asr = max((r.worst_asr for r in phase_results), default=0.0)

        # Gap #8: 构建阶段趋势数据（供 Stage4 消费）
        phase_trend = build_phase_trend_data(phase_results)

        print_stage_card(
            "3", "攻击投递与利用 (Phased Delivery & Exploitation)",
            inputs=[out_path for out_path in [
                ctx.get("stage2", {}).get("sel_path"),
                ctx.get("stage2", {}).get("spec_path"),
            ] if out_path],
            outputs=[merged_report_path, decision_log_path],
            metrics=[
                ("执行模式", "分阶段递进 (Phased)"),
                ("执行阶段数", f"{sum(1 for r in phase_results if r.decision != 'skip')}/{len(phases)}"),
                ("跳过阶段数", str(sum(1 for r in phase_results if r.decision == "skip"))),
                ("总成功投递", str(total_succeeded)),
                ("总投递失败", str(total_failed)),
                ("累积命中探针", str(len(cumulative_hit_probes))),
                ("最差 ASR", f"{total_worst_asr:.1f}%"),
                ("累积 token", str(cumulative_tokens)),
                ("ASR 趋势", phase_trend["asr_trend_direction"]),
                ("决策日志", decision_log_path),
                ("是否提前终止", "是" if stopped else "否"),
            ],
        )

        # 构建统一的 stage3 result（兼容 Stage4 消费）
        merged_result = {
            "run_id": self.run_id,
            "garak_run_id": phase_results_data[0].get("garak_run_id") if phase_results_data else None,
            "generator": phase_results_data[0].get("generator", "") if phase_results_data else "",
            "probe_count": total_succeeded,
            "buff_spec": "phased (varies per phase)",
            "report_path": merged_report_path,
            "judge_path": None,
            "generations": "phased (adaptive)",
            "probes_succeeded": total_succeeded,
            "probes_failed": total_failed,
            "probes_skipped": 0,
            "stealth_assessment": phase_results_data[0].get("stealth_assessment", {}) if phase_results_data else {},
            "phased": True,
            "phase_results": [
                {
                    "phase_id": r.phase_id,
                    "name": r.name,
                    "decision": r.decision,
                    "worst_asr": r.worst_asr,
                    "hit_count": r.hit_count,
                    "hit_probes": r.hit_probes,
                    "refusal_rate": r.refusal_rate,
                    "ci_width": r.ci_width,
                    "tokens_consumed": r.tokens_consumed,
                    "asr_by_probe": r.asr_by_probe,
                    "elapsed_seconds": r.elapsed_seconds,
                }
                for r in phase_results
            ],
            "phase_trend": phase_trend,
            "cumulative_hit_probes": cumulative_hit_probes,
            "cumulative_tokens": cumulative_tokens,
        }
        ctx.update({"stage3": merged_result, "executed_probes": executed, "probe_ttp_map": probe_ttp_map})
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
            buff_spec=ctx.get("selection", {}).get("buff_spec"),
        )

        # Gap #8: 注入分阶段趋势数据（从 Stage3 phase_trend 透传到 Stage4 结果）
        stage3 = ctx.get("stage3", {})
        if stage3.get("phased") and stage3.get("phase_trend"):
            result["phased_trend"] = stage3["phase_trend"]
            result["phased_results"] = stage3.get("phase_results", [])

        # GAP-6: Stage4 卡片增强关键指标（ASR/命中/DEFCON/可靠性）
        # GAP-13: 校准 Z-score 终端展示
        calibration = result.get("calibration", {})
        z_computed = calibration.get("z_scores_computed", False)
        max_zscore: float | None = None
        if z_computed:
            for pr_info in result.get("probe_results", {}).values():
                for z_val in (pr_info.get("calibration_z_scores", {}) or {}).values():
                    try:
                        zv = float(z_val)
                        if max_zscore is None or abs(zv) > abs(max_zscore):
                            max_zscore = zv
                    except (ValueError, TypeError):
                        pass
        z_label = (
            f"max Z={max_zscore:+.2f}" if max_zscore is not None
            else "已计算" if z_computed else "未计算"
        )

        print_stage_card(
            "4", "战果分析与评估 (Impact Assessment)",
            inputs=[report_path],
            outputs=[result["analysis_path"]],
            metrics=[
                ("评估探针数", str(result["probes_evaluated"])),
                ("最差 ASR", f'{result["overall"]["worst_asr"]}%'),
                ("整体 DEFCON", defcon_label(result["overall"]["defcon"])),
                ("命中总数", str(result["hitlog"].get("hit_count", 0))),
                ("OWASP 覆盖", f'{len(result["owasp_llm"])}/10'),
                ("Agentic 覆盖", f'{len(result["owasp_agentic"])}/10'),
                ("校准 Z-score", z_label),
                ("数据可靠性", result["data_quality"]["reliability"]),
            ],
            elapsed=ctx.get("_stage4_elapsed"),
        )

        # GAP-4: Kill Path 攻击链路终端卡片
        print_kill_paths(result.get("kill_paths", []))
        # GAP-5: 修复建议优先级终端卡片
        print_remediation_priority(result.get("remediation", []))
        # E1: ATLAS 战术热力图（probe_ttp_map 从 Stage3 透传）
        probe_ttp_map = ctx.get("probe_ttp_map", {})
        print_atlas_heatmap(result.get("probe_results", {}), probe_ttp_map)
        # E2: 攻技×意图矩阵
        print_technique_intent_matrix(result.get("technique_intent_matrix", {}))

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
        native_path = report_paths.get("pyrit_native", "")
        # Phase 3: IOA 检测规则路径
        ioa_path = report_paths.get("ioa_rules", "")

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
        if native_path:
            output_paths.append(native_path)
        if ioa_path:
            output_paths.append(ioa_path)

        # GAP-7: Stage5 卡片精简 — 用文件名替代全路径，避免信息过载
        def _fname(path: str | None) -> str:
            if not path:
                return "N/A"
            return Path(path).name

        print_stage_card(
            "5", "红队交付物 (Red Team Deliverables)",
            inputs=[_fname(analysis["analysis_path"])],
            outputs=[_fname(p) for p in output_paths],
            metrics=[
                ("交付物数量", str(len([p for p in output_paths if p]))),
                ("输出目录", f"{self.artifacts_dir}/05_export/"),
                ("命中明细", _fname(analysis.get("hitlog", {}).get("markdown_path"))),
                ("可复现哈希", (analysis.get("repro_hash", "N/A") or "N/A")[:16] + "..."),
            ],
            elapsed=ctx.get("_stage5_elapsed"),
        )

        # GAP-15: IOA 检测规则终端预览
        print_ioa_preview(ioa_path)
        # E4: 对话上下文终端预览
        print_conversation_preview(conv_path)

        ctx.update({"stage5": {
            "air_path": air_path,
            "html_path": html_path,
            "avid_path": avid_path,
            "pdf_path": pdf_path,
            "sarif_path": sarif_path,
            "conversations_path": conv_path,
            "pyrit_native_path": native_path,
        }})
        # P3-4: 通知/告警集成（Webhook）
        try:
            from .notify import send_notification
            notify_cfg = self.config.get("notify", None)
            send_notification(analysis, self.run_id, notify_cfg)
        except Exception:
            pass
        return ctx
