# -*- coding: utf-8 -*-
"""
ai300-eval 入口
"""

from __future__ import annotations

import json
import logging
import os
import sys
from pathlib import Path
from typing import List

from ai300_schemas import PyRITTargetConfig, TargetProfile

from .adapters import ARTAdapter, GiskardAdapter
from .adapters.base import EvalAdapter, EvalResult, EvalStrategy
from .cli import build_parser, parse_adapters, resolve_profile_path, resolve_pyrit_target_path, setup_logging
from .config import EvalConfig
from .loaders import load_pyrit_target, load_target_profile
from .reporting.eval_report import EvalReport
from .strategies import select_strategies

logger = logging.getLogger(__name__)


def get_adapter(name: str, config: EvalConfig) -> EvalAdapter:
    """根据名称获取适配器实例"""
    cfg = {
        "output_dir": config.output_dir,
        "timeout": config.timeout,
        "giskard_extra_args": config.extra.get("giskard_extra_args", []),
    }
    if name == "giskard":
        return GiskardAdapter(cfg)
    if name == "art":
        return ARTAdapter(cfg)
    raise ValueError(f"Unknown adapter: {name}")


def run_eval(
    profile: TargetProfile,
    pyrit_target: PyRITTargetConfig,
    adapters: List[str],
    config: EvalConfig,
) -> EvalReport:
    """执行评估"""
    report = EvalReport(
        target=profile.target,
        adapters=adapters,
        strategies=[],
    )

    for adapter_name in adapters:
        adapter = get_adapter(adapter_name, config)
        if not adapter.is_available():
            logger.warning("Adapter '%s' is not available, skipping.", adapter_name)
            report.results.append(
                EvalResult(
                    adapter=adapter_name,
                    strategy="",
                    success=False,
                    error="Adapter not available",
                )
            )
            continue

        strategies = select_strategies(profile, adapter=adapter_name)
        report.strategies.extend([s.name for s in strategies])

        for strategy in strategies:
            logger.info("Running strategy '%s' with adapter '%s'", strategy.name, adapter_name)
            result = adapter.run(pyrit_target, strategy)
            report.results.append(result)
            logger.info(
                "Strategy '%s' completed: success=%s findings=%d",
                strategy.name,
                result.success,
                len(result.findings),
            )

    return report


def save_report(report: EvalReport, output_dir: Path) -> Path:
    """保存评估报告"""
    output_dir.mkdir(parents=True, exist_ok=True)

    # 完整报告
    report_path = output_dir / "eval_report.json"
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report.to_dict(), f, ensure_ascii=False, indent=2)

    # 统一发现列表
    findings_path = output_dir / "findings.json"
    with open(findings_path, "w", encoding="utf-8") as f:
        json.dump([f.to_dict() for f in report.findings()], f, ensure_ascii=False, indent=2)

    # 文本摘要
    summary_path = output_dir / "summary.txt"
    with open(summary_path, "w", encoding="utf-8") as f:
        f.write(report.summary())
        f.write("\n\nDetailed Report:\n")
        f.write(report.to_json())

    logger.info("Evaluation report saved to %s", output_dir)
    return report_path


def main(argv: List[str] = None) -> int:
    """CLI 入口"""
    parser = build_parser()
    args = parser.parse_args(argv)

    setup_logging(args.verbose)

    # 加载配置
    config = EvalConfig.from_env(args.env)
    if args.output_dir:
        config.output_dir = args.output_dir
    if args.timeout:
        config.timeout = args.timeout
    if args.dry_run:
        config.dry_run = True

    # 解析输入路径
    profile_path = resolve_profile_path(args)
    pyrit_target_path = resolve_pyrit_target_path(args)

    if not profile_path or not profile_path.exists():
        logger.error("TargetProfile not found: %s", profile_path)
        return 1

    if not pyrit_target_path or not pyrit_target_path.exists():
        logger.error("PyRIT target not found: %s", pyrit_target_path)
        return 1

    profile = load_target_profile(profile_path)
    pyrit_target = load_pyrit_target(pyrit_target_path)

    adapters = parse_adapters(args.adapter)
    logger.info("Target: %s", profile.target)
    logger.info("Adapters: %s", adapters)

    if config.dry_run:
        strategies = []
        for adapter_name in adapters:
            strategies.extend(select_strategies(profile, adapter=adapter_name))
        logger.info("Dry-run mode. Selected strategies:")
        for s in strategies:
            logger.info("  - %s (%s)", s.name, s.owasp_llm_id)
        return 0

    report = run_eval(profile, pyrit_target, adapters, config)
    output_dir = Path(config.output_dir)
    save_report(report, output_dir)

    findings = report.findings()
    logger.info("Evaluation completed. Total findings: %d", len(findings))
    return 0


if __name__ == "__main__":
    sys.exit(main())
