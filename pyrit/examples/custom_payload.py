#!/usr/bin/env python3
"""
AI-300 Framework - Custom Payload Example
自定义载荷示例：展示如何添加自定义攻击载荷并执行

使用新的 data/ 目录结构加载载荷
"""

from pyrit_ai300.payloads import PayloadManager
from pyrit_ai300.orchestrators import AttackOrchestrator
from pyrit_ai300.utils import setup_logger


def main():
    logger = setup_logger(level="INFO")

    # 1. 初始化载荷管理器（使用新的 data/ 目录）
    manager = PayloadManager()
    manager.load_data_dir("data/")

    # 2. 通过引用加载载荷
    payloads = manager.resolve_refs(["owasp:agentic:asi01"])
    # 按攻击面筛选（可选）
    agent_payloads = manager.get_payloads_by_surface("agent")
    logger.info("Loaded %d payloads from data/ directory", len(payloads))

    # 3. 初始化编排器
    orchestrator = AttackOrchestrator()

    # 4. 构建目标
    target_config = {
        "type": "ollama",
        "connection": {
            "endpoint": "http://localhost:11434/v1/chat/completions",
            "api_key": "not-needed",
            "model": "llama3.2:latest",
        },
    }
    target = orchestrator.build_target(target_config)

    # 5. 构建转换器
    converters = orchestrator.build_converters(["base64", "rot13"])

    # 6. 构建评分器
    scorers = orchestrator.build_scorers(["refusal", "substring"])

    # 7. 执行攻击
    attack_config = {
        "name": "custom_direct_injection",
        "payloads": payloads,
    }

    results = orchestrator.execute_attack(
        attack_config=attack_config,
        target=target,
        converters=converters,
        scorers=scorers,
    )

    logger.info("Attack results: %s", results)


if __name__ == "__main__":
    main()
