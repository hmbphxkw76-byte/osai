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
    
    # Run command
    run_parser = subparsers.add_parser("run", help="Run attack scenarios")
    run_parser.add_argument(
        "-c", "--config",
        default="config/catalog/catalog.yaml",
        help="Scenario configuration file path",
    )
    run_parser.add_argument(
        "-t", "--target",
        default="config/targets/ollama_local.yaml",
        help="Target configuration file path",
    )
    run_parser.add_argument(
        "-m", "--module",
        default=None,
        help="Specific module to run (e.g., single_agent)",
    )
    run_parser.add_argument(
        "-o", "--output",
        default="results/ai300_assessment_report.md",
        help="Report output path",
    )
    run_parser.add_argument(
        "--format",
        choices=["markdown", "html"],
        default="markdown",
        help="Report output format",
    )
    run_parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose logging",
    )
    
    # List command
    list_parser = subparsers.add_parser("list", help="List available components")
    list_parser.add_argument(
        "component",
        choices=["attacks", "converters", "scorers", "targets", "modules"],
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
        default="results/ai300_assessment_report.md",
        help="Report output path",
    )
    report_parser.add_argument(
        "--format",
        choices=["markdown", "html"],
        default="markdown",
        help="Report output format",
    )
    
    args = parser.parse_args()
    
    # Setup logging
    log_level = "DEBUG" if getattr(args, "verbose", False) else "INFO"
    logger = setup_logger(level=log_level)
    
    if args.command == "run":
        _run_scenario(args, logger)
    elif args.command == "list":
        _list_components(args, logger)
    elif args.command == "report":
        _generate_report(args, logger)
    else:
        parser.print_help()


def _run_scenario(args, logger):
    """执行攻击场景"""
    from pyrit_ai300 import AI300Engine
    from pyrit_ai300.display import ExecutionDisplay
    
    # 创建展示器并显示启动横幅
    visualizer = ExecutionDisplay()
    visualizer.show_banner(
        config_path=args.config,
        target_path=args.target,
    )
    
    engine = AI300Engine(
        config_path=args.config,
        target_config=args.target,
        visualizer=visualizer,
    )
    
    results = engine.run(module=args.module)
    
    # 保存执行报告
    from pyrit_ai300.reporting import ExecutionReportGenerator
    report_gen = ExecutionReportGenerator()
    for result in results:
        for attack in result.get("attacks", []):
            if attack.get("mode") == "smart_match":
                report_gen.save_execution_report(
                    results=attack,
                    plan=attack.get("plan", []),
                    module_name=result.get("module", "unknown"),
                    config_path=args.config,
                    target_path=args.target,
                )
    
    logger.info("Generating report: %s", args.output)
    engine.generate_report(output_path=args.output, format=args.format)
    
    logger.info("Done. Report saved to: %s", args.output)


def _list_components(args, logger):
    """列出可用组件"""
    if args.component == "attacks":
        from pyrit_ai300.orchestrators import AttackOrchestrator
        print("Available Attacks:")
        for category in ["single_turn", "multi_turn", "compound", "streaming"]:
            attacks = AttackOrchestrator.list_attacks(category)
            if attacks:
                print(f"\n  {category.upper()}:")
                for attack in attacks:
                    info = AttackOrchestrator.get_attack_info(attack)
                    print(f"    - {attack}: {info.get('description', '')}")
    
    elif args.component == "converters":
        from pyrit_ai300.orchestrators.attack_orchestrator import CONVERTER_MAP
        print("Available Converters:")
        for converter_name in CONVERTER_MAP:
            print(f"    - {converter_name}")
    
    elif args.component == "scorers":
        from pyrit_ai300.orchestrators.attack_orchestrator import SCORER_MAP
        print("Available Scorers:")
        for scorer_name in SCORER_MAP:
            print(f"    - {scorer_name}")
    
    elif args.component == "targets":
        from pyrit_ai300.orchestrators import AttackOrchestrator
        print("Available Target Types:")
        for target_type in AttackOrchestrator.list_types():
            print(f"    - {target_type}")
    
    elif args.component == "modules":
        from pyrit_ai300 import AI300Engine
        print("AI-300 Modules:")
        for module in AI300Engine.MODULES:
            print(f"    - {module}")


def _generate_report(args, logger):
    """生成报告"""
    import json
    from pyrit_ai300.reporting import ReportGenerator
    
    with open(args.results, "r", encoding="utf-8") as f:
        results = json.load(f)
    
    generator = ReportGenerator(results=results)
    generator.generate(output_path=args.output, format=args.format)
    
    logger.info("Report generated: %s", args.output)


if __name__ == "__main__":
    main()
