#!/usr/bin/env python3
"""
AI-300 Framework - Full Assessment Example
完整评估示例：运行所有 AI-300 Module 的攻击场景
"""

from pyrit_ai300 import AI300Engine
from pyrit_ai300.utils import setup_logger


def main():
    # 设置日志
    logger = setup_logger(level="INFO", log_file="logs/assessment.log")
    
    logger.info("=" * 60)
    logger.info("AI-300 Full Assessment Starting")
    logger.info("=" * 60)
    
    # 1. 初始化引擎
    engine = AI300Engine(
        config_path="config/catalog/catalog.yaml",
        target_config="config/targets/ollama_local.yaml",
    )
    
    # 2. 运行所有 Module
    all_results = engine.run()
    
    # 3. 生成完整报告
    engine.generate_report(
        output_path="results/ai300_full_assessment_report.md",
        format="markdown",
    )
    
    # 6. 同时生成 HTML 报告
    engine.generate_report(
        output_path="results/ai300_full_assessment_report.html",
        format="html",
    )
    
    logger.info("=" * 60)
    logger.info("Assessment Complete")
    logger.info("Reports saved to results/")
    logger.info("=" * 60)


if __name__ == "__main__":
    main()
