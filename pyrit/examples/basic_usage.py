#!/usr/bin/env python3
"""
AI-300 Framework - Basic Usage Example
基础使用示例
"""

from pyrit_ai300 import AI300Engine


def main():
    # 1. 初始化引擎
    engine = AI300Engine(
        config_path="config/catalog/catalog.yaml",
        target_config="config/targets/ollama_local.yaml",
    )
    
    # 2. 运行指定 Module
    results = engine.run(module="single_agent")
    
    # 3. 生成报告
    engine.generate_report(
        output_path="results/assessment_report.md",
        format="markdown",
    )
    
    print("Assessment complete. Report saved to results/assessment_report.md")


if __name__ == "__main__":
    main()
