#!/usr/bin/env python
"""
===============================================================================
OffSec AI-300 统一红队演练平台 — 主入口 (PyRIT 原生 Orchestrator)
===============================================================================
框架对齐: PyRIT 0.14.0 (SQLiteMemory + CentralMemory + PromptSendingAttack)

考试期间最小化代码修改原则:
  1. 仅需修改 datasets/payloads/ 下的 YAML payload 文件
  2. 后续流程全部自动化: converters 转换 → 攻击组合选择 → 编排 → 测试 → 报告

快速使用:
  python run_redteam.py --lang cn --phase probe
  python run_redteam.py --lang cn --auto-gate
  python run_redteam.py --lang cn --target-url http://192.168.2.199:8501/ --phase probe
  python run_redteam.py --exam-mode --exam-template scenarios/templates/comprehensive.yaml
  python run_redteam.py --tech-template scenarios/templates/prompt_injection.yaml

目录结构:
  config/           — 配置文件
  templates/        — YAML 模板 (datasets + scenarios)
  prompt_converters/ — 转换器 (Base64/ROT13/Jailbreak/...)
  attack_executor/   — 攻击引擎 (single/crescendo/scoring/dashboard)
  targets/          — 攻击目标 (Azure OpenAI / 本地LLM / 自定义HTTP)
  scoring/          — 评分引擎 (Judge LLM / 分类器)
  orchestrators/    — 编排层 (PromptSendingAttack / CrescendoAttack)
  utils/            — 工具函数 (logger/helpers/retry)
  outputs/          — 输出 (logs + results)
===============================================================================
"""
import sys
import os

# 确保项目根目录在 sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# 委托给 main.py 的主逻辑
if __name__ == "__main__":
    import main
    import asyncio
    asyncio.run(main.main())
