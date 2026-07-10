# Promptfoo — Layers 5-6: 统一评估 + 报告生成

> 提示词模板管理 + 统一评估引擎 + 标准化报告生成。

## 目录结构

```
promptfoo/
├── __init__.py          # 包入口
├── schema.py            # 数据模型 (PromptEntry, PromptSet, EvalResult)
├── manager.py           # 提示词管理中心
├── eval/                # Layer 5: 统一评估判定
│   ├── engine.py        #   评估引擎 (ASR + OWASP + MITRE ATLAS)
│   └── __init__.py
├── reporting/           # Layer 6: 标准化报告生成
│   ├── generator.py     #   OffSec风格报告/MITRE ATLAS/修复建议
│   └── __init__.py
├── templates/           # 提示词模板库
│   └── README.md        #   模板规范说明
└── README.md            # 本文件
```

## 功能

### Layer 5 — 统一评估判定
- 统一 ASR (Attack Success Rate) 评分
- OWASP LLM Top 10 自动映射
- OWASP Agentic Top 10 自动映射（NEW）
- 风险等级量化

### Layer 6 — 标准化报告生成
- OffSec 风格渗透报告 (JSON + Markdown)
- MITRE ATLAS 完整映射
- 修复建议矩阵（按严重性 × 实施难度）
- 可复现测试配置包

## 使用

```python
# 提示词管理
from promptfoo import PromptfooManager
mgr = PromptfooManager()
prompts = mgr.filter_prompts(categories=["jailbreak"], risk_levels=["critical"])

# 统一评估
from promptfoo import EvalEngine
result = EvalEngine.evaluate(attack_results, target_id="target_1")
print(f"ASR: {result.asr_score:.1%}, Risk: {result.risk_level}")

# 报告生成
from promptfoo import ReportGenerator
report = ReportGenerator.generate(attack_results, target_url="http://target:8080")
ReportGenerator.save_report(report, "outputs/reports/")
```
