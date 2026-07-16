# AI-300 Red Teaming Framework

## 架构概述

本框架以 PyRIT (Python Risk Identification Tool) 0.14.0 为核心引擎，完全对齐 OffSec AI-300 (OSAI+) 考试要求，构建了一套数据驱动、全流程自动化的 AI 红队评估框架。

### 设计原则

1. **直接复用 PyRIT 组件** - 所有攻击、转换器、评分器、目标均通过 `import pyrit` 直接调用，不重复造轮子
2. **完全对齐 AI-300 考试** - 覆盖全部 11 个 Module 的考试场景
3. **OWASP LLM Top 10 + Agentic Top 10 映射** - 每个攻击场景都有对应的 OWASP 分类映射
4. **数据驱动自动化** - 修改攻击载荷后，攻击流程、策略组合、报告生成全程自动化
5. **专业报告输出** - 符合 OffSec AT-300 考试要求的专业红队评估报告

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
├── config/                     # 数据层（用户只改这里）
│   ├── catalog/               #   catalog.yaml (攻击定义+载荷)
│   ├── targets/               #   目标端点配置 YAML
│   ├── output/                #   输出报告配置
│   └── scorers.yaml           #   外部 LLM 评分器后端+定义
├── pyrit_ai300/                # 代码层（纯框架引擎）
│   ├── attacks/               #   攻击工厂 (AttackFactory)
│   ├── converters/            #   转换器模块（预留扩展）
│   ├── display/               #   终端展示 (ExecutionDisplay, Rich 格式化)
│   ├── orchestrators/         #   编排器 (AttackOrchestrator, SmartMatcher)
│   ├── payloads/              #   载荷管理 + 分类 (PayloadManager, PayloadClassifier)
│   ├── reporting/             #   报告生成 (ReportGenerator + ExecutionReportGenerator)
│   ├── scorers/               #   评分器模块（预留扩展）
│   ├── tests/                 #   单元测试
│   ├── utils/                 #   工具函数 (logger)
│   ├── __init__.py            #   AI300Engine 入口
│   └── cli.py                 #   命令行接口
├── docs/                       # 文档
│   ├── ARCHITECTURE.md        #   架构设计文档
│   └── DEVELOPMENT.md         #   开发规范文档
├── examples/                   # 使用示例
├── results/                    # 输出结果
├── Makefile                    # 自动化命令
├── pyproject.toml              # 项目配置
└── README.md                   # 使用文档（本文档）
```

---

## 数据驱动工作流

```
┌─────────────────────────────────────────────────────────────┐
│                    AI-300 Framework Workflow                  │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌────────┐ │
│  │  Config   │───▶│  Attack   │───▶│  Scorer  │───▶│ Report │ │
│  │  (YAML)   │    │  Engine   │    │  Engine  │    │ Output │ │
│  └──────────┘    └──────────┘    └──────────┘    └────────┘ │
│       │               │               │               │      │
│       ▼               ▼               ▼               ▼      │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌────────┐ │
│  │ Datasets │    │Converters│    │  Memory  │    │  MD/   │ │
│  │ (YAML)   │    │ (PyRIT)  │    │ (SQLite) │    │  HTML  │ │
│  └──────────┘    └──────────┘    └──────────┘    └────────┘ │
│                                                               │
└─────────────────────────────────────────────────────────────┘
```

### 自动化流程

1. **配置加载** → 从 YAML 加载目标、攻击载荷、评分规则
2. **攻击执行** → PyRIT Orchestrator 自动执行攻击链
3. **结果评分** → PyRIT Scorer 自动评估攻击效果
4. **报告生成** → 自动生成符合 OffSec 标准的专业报告

---

## 快速开始

```python
from pyrit_ai300 import AI300Engine

# 初始化引擎
engine = AI300Engine(config_path="config/catalog/catalog.yaml")

# 执行攻击场景
results = engine.run()

# 生成报告
engine.generate_report(output_path="results/assessment_report.md")
```

### 命令行使用

```bash
# 安装
pip install -e .

# 列出可用组件
ai300 list attacks
ai300 list converters
ai300 list scorers
ai300 list modules

# 运行全部模块
ai300 run

# 运行指定模块
ai300 run -m single_agent

# 生成报告
ai300 report -r results.json -o report.md
```

---

## Smart Match 引擎（核心）

### 三维决策流程

```
payload 文本 → classify_payload() → 技术类别 → 匹配 converter_preset → 匹配 attack_strategy → 执行
```

### Payload 自动分类（5类）

| 类别 | 判定条件 | 默认匹配 |
|------|---------|---------|
| direct_short | <100字符，无特殊模式 | double_encoding + single_turn |
| role_play | 含 DAN/act as 等模式 | unicode_base64 + multi_turn |
| multilingual | 非ASCII>30% | double_encoding + single_turn |
| encoded | Base64/ROT13 特征 | plain_encode + single_turn |
| long_context | >200字符 | image_wrap + multi_turn |

### 执行模式

- `chain`: 所有转换器串链（传统）
- `presets`: 预设组合逐个测试
- `smart_match`: 智能匹配（推荐，默认）

---

## 依赖

- PyRIT >= 0.14.0
- Python >= 3.10
- PyYAML >= 6.0
- Jinja2 >= 3.1.0
- Rich >= 13.0.0
- pydantic >= 2.0.0
