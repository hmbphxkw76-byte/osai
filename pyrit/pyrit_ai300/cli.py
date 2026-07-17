"""
AI-300 Framework - CLI Interface
命令行接口：提供框架的命令行操作入口
"""

from __future__ import annotations

import argparse

from pyrit_ai300.utils import setup_logger


def main():
    """CLI 主入口"""
    parser = argparse.ArgumentParser(
        prog="ai300",
        description="AI-300 Red Teaming Framework - OffSec AI-300 Exam-Aligned Scanner",
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # OWASP command
    owasp_parser = subparsers.add_parser("owasp", help="Execute attacks by OWASP standard")
    owasp_parser.add_argument(
        "scope",
        help="OWASP scope: llm01/asi01 (single ID), llm/agentic (group), all, "
             "or ref_path (owasp:llm:llm04:rag_poison for single file)",
    )
    owasp_parser.add_argument(
        "-t", "--target",
        default="config/targets/ollama_local.yaml",
        help="Target configuration file path",
    )
    owasp_parser.add_argument(
        "-o", "--output",
        default=None,
        help="Report output path (default: auto-generated with timestamp)",
    )
    owasp_parser.add_argument(
        "--format",
        choices=["markdown", "html"],
        default="markdown",
        help="Report output format",
    )
    owasp_parser.add_argument(
        "--profile",
        default=None,
        help="Path to TargetProfile JSON (from recon command)",
    )
    owasp_parser.add_argument(
        "--auto-recon",
        action="store_true",
        help="Automatically run recon before attack",
    )
    owasp_parser.add_argument(
        "--target-url",
        default=None,
        help="Direct target URL (e.g., http://student.syxy.com), skips YAML config",
    )
    owasp_parser.add_argument(
        "--jailbreak",
        choices=["aim", "random", "all"],
        default=None,
        help="Jailbreak template to apply",
    )
    owasp_parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose logging",
    )
    
    # List command
    list_parser = subparsers.add_parser("list", help="List available components")
    list_parser.add_argument(
        "component",
        choices=["attacks", "converters", "scorers", "targets", "owasp"],
        help="Component type to list",
    )
    
    # Report command
    report_parser = subparsers.add_parser("report", help="Generate report from results")
    report_parser.add_argument(
        "-r", "--results",
        required=True,
        help="Results file path (JSON)",
    )
    report_parser.add_argument(
        "-o", "--output",
        default=None,
        help="Report output path (default: auto-generated with timestamp)",
    )
    report_parser.add_argument(
        "--format",
        choices=["markdown", "html"],
        default="markdown",
        help="Report output format",
    )

    # Recon command
    recon_parser = subparsers.add_parser("recon", help="Run reconnaissance on target")
    recon_parser.add_argument(
        "-t", "--target",
        required=True,
        help="Target URL or endpoint to recon",
    )
    recon_parser.add_argument(
        "-d", "--depth",
        choices=["quick", "standard", "deep"],
        default="standard",
        help="Reconnaissance depth (default: standard)",
    )
    recon_parser.add_argument(
        "--tools",
        nargs="+",
        default=None,
        help="Specific tools to use (default: all enabled)",
    )
    recon_parser.add_argument(
        "-o", "--output",
        default=None,
        help="Output path for TargetProfile JSON (default: results/recon/profile_<timestamp>.json)",
    )
    recon_parser.add_argument(
        "--config",
        default="config/recon/recon.yaml",
        help="Recon configuration file path",
    )
    recon_parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose logging",
    )

    args = parser.parse_args()
    
    # Setup logging
    log_level = "DEBUG" if getattr(args, "verbose", False) else "INFO"
    logger = setup_logger(level=log_level)
    
    if args.command == "owasp":
        _run_owasp(args, logger)
    elif args.command == "list":
        _list_components(args, logger)
    elif args.command == "report":
        _generate_report(args, logger)
    elif args.command == "recon":
        _run_recon(args, logger)
    else:
        parser.print_help()


def _run_owasp(args, logger):
    """执行 OWASP 标准攻击"""
    from pyrit_ai300 import AI300Engine
    from pyrit_ai300.pipeline import PipelineTracker
    from pyrit_ai300.reconnaissance import ReconEngine

    # 创建 PipelineTracker（全链路追踪）
    tracker = PipelineTracker(verbose=True)

    # 自动侦察（--auto-recon）
    profile_path = args.profile
    if args.auto_recon and not profile_path:
        logger.info("Running auto-recon before attack...")
        recon_engine = ReconEngine()
        # 优先使用 --target-url，其次使用 --target YAML
        recon_target = args.target_url or args.target
        profile = recon_engine.run(
            target=recon_target,
            tracker=tracker,
        )
        from datetime import datetime
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        profile_path = f"results/recon/auto_profile_{timestamp}.json"
        profile.save(profile_path)
        logger.info("Auto-recon profile saved to: %s", profile_path)

        # 更新 tracker 中的 profile_path
        if tracker.recon_log:
            tracker.recon_log.profile_path = profile_path

    # 创建 AI300Engine（传入 tracker + target_url）
    engine = AI300Engine(
        config_path="config/catalog/catalog.yaml",
        target_config=args.target,
        tracker=tracker,
        profile_path=profile_path,
        target_url=args.target_url,
    )

    results = engine.run(scope=args.scope)

    # 保存执行报告
    from pyrit_ai300.reporting import ExecutionReportGenerator
    report_gen = ExecutionReportGenerator()
    for result in results:
        for attack in result.get("attacks", []):
            if attack.get("mode") == "smart_match":
                report_gen.save_execution_report(
                    results=attack,
                    plan=attack.get("plan", []),
                    module_name=result.get("scope", "unknown"),
                    config_path="config/catalog/catalog.yaml",
                    target_path=args.target,
                )

    logger.info("Generating report: %s", args.output)
    engine.generate_report(output_path=args.output, format=args.format)

    logger.info("Done. Report saved to: %s", args.output)


def _list_components(args, logger):
    """列出可用组件"""
    if args.component == "attacks":
        from pyrit_ai300.orchestrators.attack_registry import list_attacks, get_attack_info
        print("Available Attacks:")
        for category in ["single_turn", "multi_turn", "compound", "streaming"]:
            attacks = list_attacks(category)
            if attacks:
                print(f"\n  {category.upper()}:")
                for attack in attacks:
                    info = get_attack_info(attack)
                    print(f"    - {attack}: {info.get('description', '')}")
    
    elif args.component == "converters":
        from pyrit_ai300.orchestrators.component_registry import CONVERTER_MAP
        print("Available Converters:")
        for converter_name in CONVERTER_MAP:
            print(f"    - {converter_name}")
    
    elif args.component == "scorers":
        from pyrit_ai300.orchestrators.component_registry import SCORER_MAP
        print("Available Scorers:")
        for scorer_name in SCORER_MAP:
            print(f"    - {scorer_name}")
    
    elif args.component == "targets":
        from pyrit_ai300.orchestrators.attack_registry import list_types
        print("Available Target Types:")
        for target_type in list_types():
            print(f"    - {target_type}")
    
    elif args.component == "owasp":
        from pyrit_ai300.payloads.payload_manager import PayloadManager
        pm = PayloadManager()
        pm.load_data_dir("data/")
        print("OWASP Scopes:")
        print("  Single ID: llm01, llm02, ..., llm10, asi01, asi02, ..., asi10")
        print("  Groups:    llm (all LLM Top 10), agentic (all Agentic Top 10)")
        print("  All:       all")
        print("  Single file: owasp:llm:llm04:rag_poison (ref_path format)")
        print(f"\n  Loaded refs: {len(pm.get_all_refs())}")
        for ref in pm.get_all_refs():
            print(f"    - {ref}")


def _generate_report(args, logger):
    """生成报告"""
    import json
    from pyrit_ai300.reporting import ReportGenerator

    with open(args.results, "r", encoding="utf-8") as f:
        results = json.load(f)

    generator = ReportGenerator(results=results)
    generator.generate(output_path=args.output, format=args.format)

    logger.info("Report generated: %s", args.output)


def _run_recon(args, logger):
    """执行侦察（独立模式，无攻击阶段）"""
    from pyrit_ai300.reconnaissance import ReconEngine
    from pyrit_ai300.pipeline import PipelineTracker

    # 创建 PipelineTracker（仅侦察阶段）
    tracker = PipelineTracker(verbose=True)

    engine = ReconEngine(config_path=args.config)

    # 检查工具可用性
    if args.verbose:
        tool_status = engine.check_tools()
        print("Tool Status:")
        for tool, available in tool_status.items():
            status = "✓" if available else "✗"
            print(f"  {status} {tool}")

    # 执行侦察（传入 tracker）
    profile = engine.run(
        target=args.target,
        depth=args.depth,
        tools=args.tools,
        tracker=tracker,
    )

    # 确定输出路径
    output_path = args.output
    if not output_path:
        from datetime import datetime
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = f"results/recon/profile_{timestamp}.json"

    # 保存结果
    profile.save(output_path)

    # 更新 tracker 中的 profile_path
    if tracker.recon_log:
        tracker.recon_log.profile_path = output_path

    # 打印摘要
    print("\nReconnaissance Complete")
    print(f"  Target: {profile.target}")
    print(f"  Tools Used: {', '.join(profile.tools_used)}")
    print(f"  Vulnerabilities: {profile.vulnerability_count}")
    print(f"  Risk Level: {profile.risk_level}")
    print(f"  OWASP Mappings: {', '.join(profile.get_owasp_mappings())}")
    print(f"  Profile saved to: {output_path}")


if __name__ == "__main__":
    main()
