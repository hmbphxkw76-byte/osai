"""
AI-300 Framework - CLI Interface
命令行接口：提供框架的命令行操作入口
"""

from __future__ import annotations

import warnings

# 屏蔽第三方库 confusables 1.2.0 的无效转义序列警告
# 该包是 pyrit 的传递依赖，已废弃不维护，Python 3.12+ 触发 SyntaxWarning
warnings.filterwarnings("ignore", category=SyntaxWarning, module=r"confusables")

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
    owasp_parser = subparsers.add_parser(
        "owasp",
        help="Execute attacks by OWASP standard",
        epilog="""\
Examples:
  # 单目标攻击（指定配置文件）
  ai300 owasp llm01 --target-file config/targets/ollama_local.yaml

  # 单目标攻击（指定 URL）
  ai300 owasp llm01 --target-url http://www.example.com

  # 多目标批量攻击（目录下所有 YAML）
  ai300 owasp llm01 --target-dir config/targets/

  # 多目标批量攻击 + HTML 报告
  ai300 owasp llm01 --target-dir config/targets/ --format html

  # 先侦察再攻击
  ai300 owasp llm01 --target-url http://target.com --auto-recon

  # 使用侦察生成的 profile
  ai300 owasp llm01 --target-file config/targets/ollama_local.yaml --profile results/recon/profile.json

  # 全量 LLM Top 10 攻击
  ai300 owasp llm --target-file config/targets/ollama_local.yaml

  # Jailbreak 模板攻击
  ai300 owasp text_jailbreak:aim --target-file config/targets/ollama_local.yaml

  # 单文件精确攻击
  ai300 owasp owasp:llm:llm04:rag_poison --target-file config/targets/ollama_local.yaml

  # 全量攻击 + HTML 报告
  ai300 owasp all --target-file config/targets/ollama_local.yaml --format html -o report.html""",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    owasp_required = owasp_parser.add_argument_group("required arguments")
    owasp_required.add_argument(
        "scope",
        help="OWASP scope: llm01/asi01 (single ID), llm/agentic (group), all, "
             "ref_path (owasp:llm:llm04:rag_poison), or text_jailbreak:aim/random/all",
    )
    owasp_target = owasp_parser.add_argument_group(
        "target specification (required, at least one)"
    )
    owasp_target.add_argument(
        "-t", "--target-file",
        default=None,
        help="Target configuration file path (e.g., config/targets/ollama_local.yaml)",
    )
    owasp_target.add_argument(
        "--target-dir",
        default=None,
        help="Directory containing target YAML files (batch mode, scans all *.yaml)",
    )
    owasp_target.add_argument(
        "--target-url",
        default=None,
        help="Direct target URL (e.g., http://www.example.com), skips YAML config",
    )
    owasp_optional = owasp_parser.add_argument_group("optional arguments")
    owasp_optional.add_argument(
        "-o", "--output",
        default=None,
        help="Report output path (default: auto-generated with timestamp)",
    )
    owasp_optional.add_argument(
        "--format",
        choices=["markdown", "html"],
        default="markdown",
        help="Report output format (default: markdown)",
    )
    owasp_optional.add_argument(
        "--profile",
        default=None,
        help="Path to TargetProfile JSON (from recon command)",
    )
    owasp_optional.add_argument(
        "--auto-recon",
        action="store_true",
        help="Automatically run recon before attack",
    )
    owasp_optional.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose logging",
    )
    
    # List command
    list_parser = subparsers.add_parser("list", help="List available components")
    list_required = list_parser.add_argument_group("required arguments")
    list_required.add_argument(
        "component",
        choices=["attacks", "converters", "scorers", "targets", "owasp"],
        help="Component type to list",
    )
    
    # Report command
    report_parser = subparsers.add_parser("report", help="Generate report from results")
    report_required = report_parser.add_argument_group("required arguments")
    report_required.add_argument(
        "-r", "--results",
        required=True,
        help="Results file path (JSON)",
    )
    report_optional = report_parser.add_argument_group("optional arguments")
    report_optional.add_argument(
        "-o", "--output",
        default=None,
        help="Report output path (default: auto-generated with timestamp)",
    )
    report_optional.add_argument(
        "--format",
        choices=["markdown", "html"],
        default="markdown",
        help="Report output format (default: markdown)",
    )

    # Recon command
    recon_parser = subparsers.add_parser("recon", help="Run reconnaissance on target")
    recon_required = recon_parser.add_argument_group("required arguments")
    recon_required.add_argument(
        "-t", "--target",
        required=True,
        help="Target URL or endpoint to recon",
    )
    recon_optional = recon_parser.add_argument_group("optional arguments")
    recon_optional.add_argument(
        "-d", "--depth",
        choices=["quick", "standard", "deep"],
        default="standard",
        help="Reconnaissance depth (default: standard)",
    )
    recon_optional.add_argument(
        "--tools",
        nargs="+",
        default=None,
        help="Specific tools to use (default: all enabled)",
    )
    recon_optional.add_argument(
        "-o", "--output",
        default=None,
        help="Output path for TargetProfile JSON (default: results/recon/profile_<timestamp>.json)",
    )
    recon_optional.add_argument(
        "--config",
        default="config/recon/recon.yaml",
        help="Recon configuration file path (default: config/recon/recon.yaml)",
    )
    recon_optional.add_argument(
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


def _resolve_targets(args):
    """
    解析目标列表（统一接口）

    Returns:
        list of (target_config, target_url) tuples
        - target_config: YAML 文件路径（或 None）
        - target_url: 直接 URL（或 None）
    """
    targets = []

    # --target-url：直接 URL
    if args.target_url:
        targets.append((None, args.target_url))

    # --target-file：单个 YAML 文件
    if args.target_file:
        targets.append((args.target_file, None))

    # --target-dir：目录下所有 YAML 文件
    if args.target_dir:
        from pathlib import Path
        target_dir = Path(args.target_dir)
        if not target_dir.is_dir():
            raise ValueError(f"--target-dir is not a directory: {args.target_dir}")
        yaml_files = sorted(target_dir.glob("*.yaml"))
        if not yaml_files:
            raise ValueError(f"No YAML files found in --target-dir: {args.target_dir}")
        for yaml_file in yaml_files:
            targets.append((str(yaml_file), None))

    return targets


def _run_owasp(args, logger):
    """执行 OWASP 标准攻击（支持多目标逐一分批）"""
    from pyrit_ai300 import AI300Engine
    from pyrit_ai300.pipeline import PipelineTracker
    from pyrit_ai300.reconnaissance import ReconEngine

    # 解析目标列表
    targets = _resolve_targets(args)
    if not targets:
        logger.error(
            "No target specified. Use --target-file, --target-dir, or --target-url"
        )
        raise ValueError("Must specify at least one target: --target-file, --target-dir, or --target-url")

    logger.info("Target count: %d", len(targets))
    for i, (target_file, target_url) in enumerate(targets, 1):
        target_label = target_url or target_file or "unknown"
        logger.info("  [%d/%d] %s", i, len(targets), target_label)

    # 逐一分批执行
    all_results = []
    for target_idx, (target_file, target_url) in enumerate(targets, 1):
        target_label = target_url or target_file or "unknown"
        logger.info("=" * 60)
        logger.info("Processing target [%d/%d]: %s", target_idx, len(targets), target_label)
        logger.info("=" * 60)

        # 每个目标独立 tracker
        tracker = PipelineTracker(verbose=True)

        # 自动侦察（--auto-recon）
        profile_path = args.profile
        if args.auto_recon and not profile_path:
            logger.info("Running auto-recon before attack...")
            recon_engine = ReconEngine()
            recon_target = target_url or target_file
            profile = recon_engine.run(
                target=recon_target,
                tracker=tracker,
            )
            from datetime import datetime
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            profile_path = f"results/recon/auto_profile_{timestamp}.json"
            profile.save(profile_path)
            logger.info("Auto-recon profile saved to: %s", profile_path)

            if tracker.recon_log:
                tracker.recon_log.profile_path = profile_path

        # 创建 AI300Engine
        engine = AI300Engine(
            config_path="config/catalog/catalog.yaml",
            target_config=target_file or "config/targets/ollama_local.yaml",
            tracker=tracker,
            profile_path=profile_path,
            target_url=target_url,
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
                        target_path=target_file or target_url or "unknown",
                    )

        # 生成报告（多目标时附加目标名）
        output_path = args.output
        if len(targets) > 1:
            from pathlib import Path
            from datetime import datetime
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            target_name = Path(target_file).stem if target_file else "url_target"
            output_path = f"results/report_{target_name}_{timestamp}.{args.format}"
            logger.info("Multi-target mode, report: %s", output_path)

        engine.generate_report(output_path=output_path, format=args.format)
        all_results.append((target_label, results))

    # 汇总
    logger.info("=" * 60)
    logger.info("All targets completed: %d/%d", len(targets), len(targets))
    for target_label, _ in all_results:
        logger.info("  ✓ %s", target_label)


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
