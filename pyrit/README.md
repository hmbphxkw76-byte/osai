# AI-300 Red Teaming Framework

## 架构概述

本框架以 PyRIT (Python Risk Identification Tool) 0.14.0 为核心引擎，完全对齐 OffSec AI-300 (OSAI+) 考试要求，构建了一套数据驱动、全流程自动化的 AI 红队评估框架。

### v3.0 架构

```
┌─────────────────────────────────────────────────────────────────────┐
│                     AI-300 Framework v3.0                            │
├─────────────────────────────────────────────────────────────────────┤
│                                                                       │
│  CLI (ai300)                                                         │
│    ├── recon  → 侦察流程                                             │
│    ├── run    → 攻击流程                                             │
│    ├── list   → 列出组件                                             │
│    └── report → 生成报告                                             │
│                                                                       │
│  ┌──────────────────────┐      ┌──────────────────────────────┐    │
│  │   侦察层 (recon)      │      │       攻击层 (attack)         │    │
│  │  ReconEngine         │      │  AI300Engine                 │    │
│  │    ├── Garak         │      │    ├── AttackOrchestrator    │    │
│  │    ├── DeepTeam      │      │    ├── SmartMatcher          │    │
│  │    └── ProfileMerger │      │    └── 7 个 Module           │    │
│  │           ↓          │      │           ↑                  │    │
│  │   TargetProfile JSON │──────┼─── ProfileLoader             │    │
│  └──────────────────────┘      └──────────────────────────────┘    │
│                                                                       │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │  数据层: data/owasp/ (251 YAML) + data/recon_templates/      │    │
│  │  配置层: config/catalog/ + config/targets/ + config/recon/   │    │
│  └─────────────────────────────────────────────────────────────┘    │
│                                                                       │
└─────────────────────────────────────────────────────────────────────┘
```

### 设计原则

1. **调度器 + 格式转换器** — 框架只做编排+格式转换，能力来自 PyRIT + 外部工具（ARCH-001）
2. **三层分离** — 数据层（data/）+ 配置层（config/）+ 引擎层（pyrit_ai300/）
3. **侦察-攻击解耦** — 两者通过 TargetProfile JSON 文件通信，不互相 import
4. **数据驱动** — 修改 YAML 配置和载荷后，全流程自动化
5. **考试对齐** — 覆盖 AI-300 全部 Module + OWASP LLM/Agentic Top 10

---

## 考试覆盖矩阵

### Module-to-Framework 映射

| AI-300 Module | 框架模块 | PyRIT 组件 | OWASP LLM |
|--------------|---------|-----------|-----------|
| Ch3: Attacking AI Agents | `single_agent` | PromptSendingAttack + Converters | LLM01, LLM06, LLM08 |
| Ch4: Multi-Agent/A2A | `multi_agent` | MultiTurnAttack + SequentialAttack | LLM01, LLM08 |
| Ch5: RAG Pipelines | `rag` | Converters + Scorers | LLM03, LLM06 |
| Ch6: Embeddings | `embeddings` | Embedding Module + Converters | LLM03, LLM10 |
| Ch7: MCP/Tool Surfaces | `mcp` | HTTP Target + PromptTarget | LLM02, LLM07 |
| Ch8: Supply Chain | `supply_chain` | Auxiliary Attacks (GCG) | LLM05 |
| Ch9: Infrastructure | `infrastructure` | Azure/OpenAI Targets | LLM04, LLM10 |

### OWASP Top 10 for LLM 完整映射

| OWASP ID | 名称 | 框架覆盖 | 攻击场景 |
|---------|------|---------|---------|
| LLM01 | Prompt Injection | ✅ 完全覆盖 | Direct/Indirect Injection, Multi-agent Injection |
| LLM02 | Insecure Output Handling | ✅ 完全覆盖 | MCP Tool Abuse, Output Manipulation |
| LLM03 | Training Data Poisoning | ✅ 完全覆盖 | RAG Poisoning, Embedding Inversion |
| LLM04 | Model DoS | ✅ 完全覆盖 | Resource Exhaustion, Cloud Misconfig |
| LLM05 | Supply Chain Vulnerabilities | ✅ 完全覆盖 | Pickle RCE, Dependency Confusion, MCP Backdoor |
| LLM06 | Sensitive Information Disclosure | ✅ 完全覆盖 | System Prompt Leak, RAG Data Extraction |
| LLM07 | Insecure Plugin Design | ✅ 完全覆盖 | MCP Tool Poisoning, Shadowing |
| LLM08 | Excessive Agency | ✅ 完全覆盖 | Agent Hijacking, A2A Impersonation |
| LLM09 | Overreliance | ✅ 完全覆盖 | Threat Model Gaps, Validation Bypass |
| LLM10 | Model Theft | ✅ 完全覆盖 | Embedding Inversion, Model Extraction |

### OWASP Agentic Top 10 (2026) 完整映射

| ASI ID | 官方名称 | 框架 Module | 状态 |
|-------|---------|------------|------|
| ASI01 | Agent Goal Hijack | single_agent | ✅ |
| ASI02 | Tool Misuse & Exploitation | single_agent | ✅ |
| ASI03 | Agent Identity & Privilege Abuse | multi_agent | ✅ |
| ASI04 | Agentic Supply Chain Vulnerabilities | multi_agent | ✅ |
| ASI05 | Unexpected Code Execution | single_agent | ✅ |
| ASI06 | Memory & Context Poisoning | single_agent | ✅ |
| ASI07 | Insecure Inter-Agent Communication | multi_agent | ✅ |
| ASI08 | Cascading Failures | multi_agent | ✅ |
| ASI09 | Human-Agent Trust Exploitation | multi_agent | ✅ |
| ASI10 | Rogue Agents | multi_agent | ✅ |

---

## 目录结构

```
pyrit/                          # 项目根目录
├── config/                     # 配置层（用户只改这里）
│   ├── catalog/               #   catalog.yaml (攻击定义+载荷)
│   ├── targets/               #   目标端点配置 YAML
│   ├── output/                #   输出报告配置
│   ├── recon/                 #   侦察配置（recon.yaml）
│   └── scores.yaml            #   外部 LLM 评分器后端配置
├── data/                       # 数据层
│   ├── owasp/                 #   载荷唯一真相源（251 YAML）
│   │   ├── llm/               #     LLM01-LLM10
│   │   └── agentic/           #     ASI01-ASI10
│   ├── recon_templates/       #   侦察探测模板
│   └── surfaces/              #   攻击面分析文档（可选）
├── pyrit_ai300/                # 代码层（纯框架引擎）
│   ├── reconnaissance/        #   侦察引擎
│   │   ├── recon_engine.py    #   统一调度入口
│   │   ├── target_profile.py  #   TargetProfile 数据模型
│   │   ├── profile_merger.py  #   多工具结果合并
│   │   ├── adapters/          #   薄壳适配器（Garak/DeepTeam）
│   │   └── utils/             #   工具函数
│   ├── attack/                #   攻击引擎扩展
│   ├── orchestrators/         #   编排器（AttackOrchestrator, SmartMatcher）
│   ├── payloads/              #   载荷管理
│   ├── pipeline/              #   流水线追踪
│   ├── reporting/             #   报告生成
│   ├── tests/                 #   单元测试（174+ tests）
│   ├── utils/                 #   工具函数
│   ├── __init__.py            #   AI300Engine 入口
│   └── cli.py                 #   命令行接口
├── docs/                       # 文档
├── examples/                   # 使用示例
├── results/                    # 输出结果
├── Makefile                    # 自动化命令
├── pyproject.toml              # 项目配置
└── README.md                   # 使用文档（本文档）
```

---

## 数据驱动工作流

### 侦察流程

```
ai300 recon -t http://target:11434 -d quick
  → ReconEngine.run()
    ├── GarakAdapter.run() ──────→ NVIDIA Garak 漏洞扫描
    ├── DeepTeamAdapter.run() ───→ Confident AI DeepTeam OWASP 红队
    └── ProfileMerger.merge() ──→ 去重 + 加权 + 风险计算
  → TargetProfile JSON (results/recon/profile_<timestamp>.json)
```

### 攻击流程

```
ai300 run -m single_agent --profile results/recon/profile_xxx.json
  → AI300Engine.run()
    ├── ProfileLoader.load() ────→ TargetProfile → SmartMatcher 参数
    ├── 遍历 7 个 Module
    │     └── AttackOrchestrator.execute_attack()
    │           ├── SmartMatcher → PyRIT 攻击策略选择
    │           ├── PyRIT 原生攻击执行
    │           └── Scorer 评分
    └── ReportGenerator.generate() → results/assessment_report.md
```

---

## 快速开始

```bash
# 方式一：uv（推荐，速度快 10-100x）
pip install uv          # 先安装 uv
uv pip install -e ".[dev,pdf,recon]"

# 方式二：pip
pip install -e .
pip install -e ".[recon]"

# 列出可用组件
ai300 list attacks
ai300 list converters
ai300 list scorers
ai300 list modules

# 侦察目标
ai300 recon -t http://localhost:11434 -d quick

# 运行指定模块（使用侦察结果）
ai300 run -m single_agent --profile results/recon/profile_xxx.json

# 自动侦察 + 攻击
ai300 run -m single_agent --auto-recon

# 运行全部模块
ai300 run

# 生成报告
ai300 report -r results.json -o report.md
```

### Python API

```python
from pyrit_ai300 import AI300Engine

# 初始化引擎
engine = AI300Engine(config_path="config/catalog/catalog.yaml")

# 执行攻击场景
results = engine.run()

# 生成报告
engine.generate_report(output_path="results/assessment_report.md")
```

---

## Smart Match 引擎（核心）

### 决策流程

```
payload → normalize_payload() → analyze_payload() → PayloadProfile(五维+置信度)
  → 两层策略选择 → PyRIT 原生攻击
```

### 攻击策略

| 策略 | 适用场景 | PyRIT 攻击 |
|------|---------|-----------|
| DIRECT_SINGLE | 直接注入，高置信度 | PromptSendingAttack |
| PROGRESSIVE | 渐进式升级 | CrescendoAttack |
| TREE_SEARCH | 多路径探索 | TreeOfAttacksAttack |
| ITERATIVE | 自动优化 | PAIRAttack |
| EXPLORATORY | 未知目标 | RedTeamingAttack |
| MULTI_PRESET | 多预设组合 | SequentialAttack |

### Fallback 链

```
CrescendoAttack → TAP → PAIR → PromptSendingAttack
```

---

## 侦察工具

| 工具 | 版本 | 定位 | AI-300 对应 |
|------|------|------|------------|
| Garak | ≥0.15.1 | 漏洞扫描 | LLM01/LLM03/LLM06/LLM08/LLM09 |
| DeepTeam | ≥1.0.7 | OWASP 红队 | OWASP Top 10 LLM + Agentic |

### Garak Probe → OWASP 映射

| Probe | OWASP | 考点 |
|-------|-------|------|
| promptinject | LLM01 | Prompt Injection |
| dan / jailbreak | LLM01 | Jailbreak |
| malgen | LLM06 | Sensitive Information Disclosure |
| hallucination | LLM09 | Overreliance |
| misinformation | LLM08 | Excessive Agency |
| toxicity | LLM03 | Training Data Poisoning |

---

## 依赖

- PyRIT >= 0.14.0
- Python >= 3.10
- PyYAML >= 6.0
- Jinja2 >= 3.1.0
- Rich >= 13.0.0
- pydantic >= 2.0.0

### 可选依赖

```bash
# 侦察工具
pip install -e ".[recon]"    # garak + deepteam

# PDF 报告
pip install -e ".[pdf]"      # weasyprint

# 开发工具
pip install -e ".[dev]"      # pytest + ruff + mypy
```

---

## 测试

```bash
# 运行全部测试
make test

# 运行侦察测试
python -m pytest pyrit_ai300/tests/test_recon/ -v

# Lint 检查
make ci
```

**当前覆盖**：174+ tests passed, 1 skipped

| 模块 | 测试数 |
|------|--------|
| TargetProfile | 13 |
| ReconEngine | 7 |
| Adapters | 16 |
| ProfileLoader | 7 |
| ProfileMerger | 26 |
| **总计** | **174+** |
