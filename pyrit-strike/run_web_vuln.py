"""Web 漏洞攻击入口 — 多端点自动发现 + 传统 Web 漏洞 payload。

通用场景 (适配任意 API 端点):
    - 自动发现目标 API 端点 (基于通用前缀推断, 不依赖硬编码路径)
    - 为每个端点匹配攻击 payload (SQLi/XSS/SSRF/IDOR/XXE...)
    - 使用 SubStringScorer 检测漏洞指标 (0 token)
    - 可选 LLM Judge 二次验证

使用方式::

    # Web 漏洞攻击 (需要 Burp 请求文件提供 host + auth)
    python run_web_vuln.py --burp-request data/burp/request.txt

    # 指定端点目录 (手动准备 Burp 请求文件)
    python run_web_vuln.py --endpoints-dir data/burp/endpoints/

    # 同时运行 LLM Prompt + Web 漏洞
    python run_web_vuln.py --combined
"""

from __future__ import annotations

import asyncio
import logging
import os
import sys
from pathlib import Path
from typing import Any

# UTF-8 强制设置
os.environ.setdefault("PYTHONIOENCODING", "utf-8")
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from pipeline.config import ensure_output_dir, get_output_dir, parse_args, setup_environment
from pipeline.context import PipelineContext
from pipeline.utils.display import print_banner, print_phase, print_summary

logger = logging.getLogger(__name__)

_PROJECT_ROOT = Path(__file__).resolve().parent


async def run_web_vuln_pipeline() -> None:
    """Web 漏洞攻击流水线入口。"""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    print_banner()

    # 解析参数 (复用主流水线的参数解析)
    args = parse_args()
    output_dir = get_output_dir(args)
    ensure_output_dir(output_dir)

    ctx = PipelineContext(args=args, output_dir=output_dir)

    # ── 初始化 PyRIT 环境 ──
    # 传入 output_dir, 自动将 SQLite 数据库放到 output_dir/db/pyrit.db
    print_phase("INIT", "Initializing PyRIT environment...")
    await setup_environment(output_dir)

    # ── Phase 1: 侦察 ──
    print_phase("RECON", "Parsing Burp request & discovering endpoints...")

    from pipeline.recon.burp_parser import parse_burp_request
    from pipeline.recon.endpoint_discovery import (
        discover_endpoints,
        match_seeds_to_endpoints,
    )
    from pipeline.recon.endpoint_router import create_endpoint_targets
    from pipeline.recon.target_router import _check_target_availability

    parsed = parse_burp_request(args.burp_request)
    ctx.parsed_request = parsed
    ctx.model_name = f"HTTP:{parsed.host}"

    # 检查目标可用性
    target_available = await _check_target_availability(parsed)
    if not target_available:
        logger.error("Target %s is not available. Aborting.", parsed.host)
        print_phase("ERROR", f"Target {parsed.host} is not available.")
        sys.exit(1)

    # ── 端点自动发现 ──
    print_phase("RECON", "Auto-discovering API endpoints...")
    endpoints = await discover_endpoints(parsed, timeout=5.0, max_concurrent=10)

    if not endpoints:
        logger.warning("No endpoints discovered. Using base path only.")
        from pipeline.recon.endpoint_discovery import DiscoveredEndpoint
        endpoints = [DiscoveredEndpoint(path=parsed.path, method="POST", available=True)]

    print_phase(
        "RECON",
        f"Discovered {len(endpoints)} endpoints: "
        + ", ".join(ep.path for ep in endpoints[:10])
        + ("..." if len(endpoints) > 10 else ""),
    )

    # ── 加载 Web 漏洞种子 ──
    print_phase("ARM", "Loading Web vulnerability payloads...")
    import yaml

    seeds_path = _PROJECT_ROOT / "data" / "seeds" / "web_vulns.prompt"
    seeds_data = yaml.safe_load(seeds_path.read_text(encoding="utf-8"))
    if not isinstance(seeds_data, list):
        logger.error("Invalid web vuln seeds file")
        sys.exit(1)

    logger.info("Loaded %d Web vulnerability payloads", len(seeds_data))

    # ── 种子-端点匹配 ──
    print_phase("ARM", "Matching payloads to endpoints...")
    matches = match_seeds_to_endpoints(seeds_data, endpoints)

    # ── 为每个端点构建 HTTPTarget ──
    print_phase("ARM", "Building HTTPTarget for each endpoint...")

    endpoint_configs: list[dict[str, Any]] = []
    for ep in endpoints:
        # 根据端点类型决定 placeholder 位置
        if "user" in ep.path or "account" in ep.path or "profile" in ep.path:
            placeholder_pos = "path"  # IDOR: /user/{PROMPT}
        elif "search" in ep.path or "query" in ep.path or "reflect" in ep.path:
            placeholder_pos = "query"  # SQLi/XSS: /search?q={PROMPT}
        else:
            placeholder_pos = "body"  # 默认 body

        endpoint_configs.append({
            "path": ep.path,
            "method": "POST",
            "placeholder_position": placeholder_pos,
        })

    endpoint_targets = create_endpoint_targets(parsed, endpoint_configs)

    print_phase(
        "ARM",
        f"Built {len(endpoint_targets)} endpoint targets, "
        f"{sum(len(v) for v in matches.values())} matched payloads",
    )

    # ── 创建评分目标 (可选) ──
    from pipeline.recon.target_router import _create_scoring_target
    ctx.scoring_target = _create_scoring_target(ctx)

    # ── Phase 3: 攻击执行 ──
    print_phase("STRIKE", "Executing Web vulnerability attacks...")
    from pipeline.strike.web_vuln_executor import execute_web_vuln_attacks, score_web_vuln_results

    web_vuln_results = await execute_web_vuln_attacks(ctx, endpoint_targets, matches)

    # ── Phase 4: 评分 ──
    print_phase("ASSESS", "Scoring Web vulnerability results...")
    stats = await score_web_vuln_results(
        web_vuln_results,
        seeds_data,
        scoring_target=ctx.scoring_target,
    )

    # ── Phase 5: 报告 ──
    print_phase("REPORT", "Generating Web vulnerability report...")

    from pipeline.report.evidence import EvidenceCollector
    from pipeline.report.generator import generate_report

    # 合并结果到 ctx
    ctx.attack_results = web_vuln_results
    ctx.asr_per_technique = {
        ep: stats[ep]["asr"] for ep in stats if ep != "_overall"
    }
    ctx.overall_asr = stats.get("_overall", {}).get("asr", 0.0)

    target_fingerprint = parsed.target_fingerprint if parsed else {}

    collector = EvidenceCollector(
        target_model=ctx.model_name,
        target_fingerprint=target_fingerprint,
    )
    evidence = collector.collect(
        attack_results=ctx.attack_results,
        scenario_result_id=None,
        asr_per_technique=ctx.asr_per_technique,
        overall_asr=ctx.overall_asr,
    )

    # 注入端点发现信息
    evidence.web_vuln_stats = stats
    evidence.discovered_endpoints = [
        {"path": ep.path, "status": ep.status_code, "hints": ep.vuln_hints}
        for ep in endpoints
    ]

    report_path = await generate_report(ctx, evidence, output_dir)

    # ── 完成 ──
    total_attacks = stats.get("_overall", {}).get("total", 0)
    successful_attacks = stats.get("_overall", {}).get("success_count", 0)

    print_summary(
        total_attacks=total_attacks,
        successful_attacks=successful_attacks,
        overall_asr=ctx.overall_asr,
        report_path=str(report_path),
    )

    # 打印端点明细
    print()
    print("═" * 60)
    print("  Endpoint Attack Summary")
    print("═" * 60)
    for ep_path, ep_stats in stats.items():
        if ep_path == "_overall":
            continue
        status = "✓" if ep_stats["asr"] > 0 else "✗"
        print(f"  {status} {ep_path}")
        print(f"    ASR: {ep_stats['asr']:.1f}% ({ep_stats['success_count']}/{ep_stats['total']})")
    print("═" * 60)
    overall = stats.get("_overall", {})
    print(f"  Overall ASR: {overall.get('asr', 0):.1f}% ({overall.get('success_count', 0)}/{overall.get('total', 0)})")
    print("═" * 60)


async def run_combined_pipeline() -> None:
    """组合流水线 — LLM Prompt 攻击 + Web 漏洞攻击。

    先运行 LLM Prompt 攻击 (主流水线), 再运行 Web 漏洞攻击,
    合并结果生成统一报告。
    """
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    print_banner()

    args = parse_args()
    output_dir = get_output_dir(args)
    ensure_output_dir(output_dir)

    ctx = PipelineContext(args=args, output_dir=output_dir)

    # ── 初始化 ──
    # 传入 output_dir, 自动将 SQLite 数据库放到 output_dir/db/pyrit.db
    print_phase("INIT", "Initializing PyRIT environment...")
    await setup_environment(output_dir)

    # ── Phase 1-5: LLM Prompt 攻击 (主流水线) ──
    print_phase("LLM", "Running LLM Prompt attacks (main pipeline)...")


    # 运行主流水线
    # 由于 main() 是独立的 asyncio 函数, 直接 await
    try:
        # 注意: 这里不调用 main() 因为它有自己的参数解析
        # 而是复用流水线逻辑
        await _run_llm_phase(ctx)
    except Exception as e:
        logger.error("LLM attack phase failed: %s", e)
        print_phase("LLM", f"LLM phase partially failed: {e}")

    # ── Phase 6: Web 漏洞攻击 ──
    print_phase("WEB", "Running Web vulnerability attacks...")
    try:
        await _run_web_vuln_phase(ctx)
    except Exception as e:
        logger.error("Web vuln phase failed: %s", e)
        print_phase("WEB", f"Web vuln phase partially failed: {e}")

    # ── 合并报告 ──
    print_phase("REPORT", "Generating combined report...")
    from pipeline.report.evidence import EvidenceCollector
    from pipeline.report.generator import generate_report

    target_fingerprint = ctx.parsed_request.target_fingerprint if ctx.parsed_request else {}
    collector = EvidenceCollector(
        target_model=ctx.model_name,
        target_fingerprint=target_fingerprint,
    )
    evidence = collector.collect(
        attack_results=ctx.attack_results,
        scenario_result_id=ctx.scenario_result_id,
        asr_per_technique=ctx.asr_per_technique,
        overall_asr=ctx.overall_asr,
    )

    report_path = await generate_report(ctx, evidence, output_dir)

    print_summary(
        total_attacks=evidence.total_attacks,
        successful_attacks=evidence.successful_attacks,
        overall_asr=ctx.overall_asr,
        report_path=str(report_path),
    )


async def _run_llm_phase(ctx: PipelineContext) -> None:
    """运行 LLM Prompt 攻击阶段 (复用主流水线逻辑)。"""
    # 复用 main.py 的逻辑, 但不重新解析参数
    from pipeline.recon.target_router import create_target

    try:
        await create_target(ctx)
    except ConnectionError as e:
        logger.error("LLM phase target setup failed: %s", e)
        return

    # 打印目标指纹
    if ctx.parsed_request:
        fp = ctx.parsed_request.target_fingerprint
        print_phase(
            "LLM-RECON",
            f"Target: {fp.get('app_type', 'Unknown')} | "
            f"Auth: {fp.get('auth_type', 'Unknown')} | "
            f"Path: {ctx.parsed_request.path}",
        )

    # 武器化
    from pipeline.arm.converter_chains import build_converter_map
    from pipeline.arm.seed_ranker import load_seeds
    from pipeline.arm.technique_picker import filter_by_adversarial, select_techniques

    target_language = None
    if ctx.parsed_request:
        target_language = ctx.parsed_request.target_fingerprint.get("language")

    ctx.seeds = load_seeds(
        ctx.args.seeds,
        ctx.args.max_seeds or 25,
        target_language=target_language,
        enable_dos=getattr(ctx.args, "enable_dos", False),
    )

    has_adversarial = ctx.adversarial_target is not None
    ctx.techniques = select_techniques(ctx.args.techniques, has_adversarial=has_adversarial)
    ctx.techniques = filter_by_adversarial(ctx.techniques, has_adversarial)

    if ctx.args.converters == "none":
        chain_names = []
    elif ctx.args.converters == "auto":
        chain_names = ["l5_optimal"]
    else:
        chain_names = ctx.args.converters.split(",")

    ctx.converter_map = build_converter_map(
        technique_names=ctx.techniques,
        chain_names=chain_names,
        converter_target=ctx.converter_target,
    )

    # 执行
    from pipeline.strike.escalation import check_and_escalate
    from pipeline.strike.executor import execute_attacks

    await execute_attacks(ctx)

    if getattr(ctx.args, "escalation", True):
        await check_and_escalate(ctx, ctx.attack_results)

    # 评分
    from pipeline.assess.asr_tracker import (
        compute_asr,
        compute_overall_asr,
        precompute_outcomes_async,
        save_asr_history,
    )

    try:
        await precompute_outcomes_async(ctx.attack_results, score_all=False)
    except Exception:
        pass

    ctx.asr_per_technique = compute_asr(ctx.attack_results)
    ctx.overall_asr = compute_overall_asr(ctx.asr_per_technique)
    save_asr_history(ctx.asr_per_technique, attack_results=ctx.attack_results)

    print_phase("LLM", f"LLM phase complete: ASR={ctx.overall_asr:.1f}%")


async def _run_web_vuln_phase(ctx: PipelineContext) -> None:
    """运行 Web 漏洞攻击阶段。"""
    if not ctx.parsed_request:
        logger.warning("No parsed request, skipping web vuln phase")
        return

    from pipeline.recon.endpoint_discovery import (
        discover_endpoints,
        match_seeds_to_endpoints,
    )
    from pipeline.recon.endpoint_router import create_endpoint_targets

    # 端点发现
    endpoints = await discover_endpoints(ctx.parsed_request, timeout=5.0)
    if not endpoints:
        from pipeline.recon.endpoint_discovery import DiscoveredEndpoint
        endpoints = [DiscoveredEndpoint(path=ctx.parsed_request.path, available=True)]

    # 加载种子
    import yaml

    seeds_path = _PROJECT_ROOT / "data" / "seeds" / "web_vulns.prompt"
    if not seeds_path.exists():
        logger.warning("Web vuln seeds not found, skipping")
        return
    seeds_data = yaml.safe_load(seeds_path.read_text(encoding="utf-8"))

    # 匹配
    matches = match_seeds_to_endpoints(seeds_data, endpoints)

    # 构建端点 targets
    endpoint_configs = [
        {"path": ep.path, "method": "POST", "placeholder_position": _get_placeholder_pos(ep.path)}
        for ep in endpoints
    ]
    endpoint_targets = create_endpoint_targets(ctx.parsed_request, endpoint_configs)

    # 执行攻击
    from pipeline.strike.web_vuln_executor import execute_web_vuln_attacks, score_web_vuln_results

    web_results = await execute_web_vuln_attacks(ctx, endpoint_targets, matches)

    # 评分
    stats = await score_web_vuln_results(
        web_results, seeds_data,
        scoring_target=ctx.scoring_target,
    )

    # 合并结果
    ctx.attack_results.update(web_results)
    web_asr = stats.get("_overall", {}).get("asr", 0.0)
    ctx.asr_per_technique.update({ep: stats[ep]["asr"] for ep in stats if ep != "_overall"})

    # 合并 ASR
    total_llm = sum(len(v) for v in ctx.attack_results.values() if isinstance(v, list))
    total_web = stats.get("_overall", {}).get("total", 0)
    llm_success = sum(
        1 for results in ctx.attack_results.values()
        for r in (results if isinstance(results, list) else [])
        if _is_web_success(r)
    )
    web_success = stats.get("_overall", {}).get("success_count", 0)

    total = total_llm + total_web
    success = llm_success + web_success
    ctx.overall_asr = (success / total * 100) if total > 0 else 0.0

    print_phase("WEB", f"Web vuln phase complete: ASR={web_asr:.1f}%")


def _get_placeholder_pos(path: str) -> str:
    """根据端点路径决定占位符位置。"""
    if "user" in path or "account" in path or "profile" in path:
        return "path"
    if "search" in path or "query" in path or "reflect" in path:
        return "query"
    return "body"


def _is_web_success(result: Any) -> bool:
    """判断攻击结果是否成功。"""
    try:
        from pyrit.models import AttackOutcome
        outcome = getattr(result, "outcome", None)
        return outcome == AttackOutcome.SUCCESS
    except Exception:
        return False


def main() -> None:
    """同步入口。"""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        # 检查是否是组合模式
        args = parse_args()
        if args.strategy == "comprehensive":
            loop.run_until_complete(run_combined_pipeline())
        else:
            loop.run_until_complete(run_web_vuln_pipeline())
    except (KeyboardInterrupt, asyncio.CancelledError):
        print_phase("ABORT", "Pipeline interrupted by user (Ctrl+C).")
        logger.warning("Pipeline interrupted by user.")
    finally:
        pending = asyncio.all_tasks(loop)
        for task in pending:
            task.cancel()
        if pending:
            loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
        loop.close()


if __name__ == "__main__":
    main()
