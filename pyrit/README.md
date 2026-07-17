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
│    ├── owasp  → OWASP 标准攻击                                      │
│    ├── recon  → 侦察流程                                             │
│    ├── list   → 列出组件                                             │
│    └── report → 生成报告                                             │
│                                                                       │
│  ┌──────────────────────┐      ┌──────────────────────────────┐    │
│  │   侦察层 (recon)      │      │       攻击层 (attack)         │    │
│  │  ReconEngine         │      │  AI300Engine                 │    │
│  │    ├── Garak         │      │    ├── AttackOrchestrator    │    │
│  │    ├── DeepTeam      │      │    ├── SmartMatcher          │    │
│  │    └── ProfileMerger │      │    └── ProfileLoader         │    │
│  │           ↓          │      │           ↑                  │    │
│  │   TargetProfile JSON │──────┼─── ProfileLoader             │    │
│  └──────────────────────┘      └──────────────────────────────┘    │
│                                                                       │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │  数据层: data/owasp/ (590+ YAML) + data/recon_templates/    │    │
│  │  配置层: config/attack/ + config/targets/ + config/scores/  │    │
│  │           + config/placeholders/ + config/recon/            │    │
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
6. **config 为唯一配置源** — 所有策略配置在 config/ 目录，代码不含硬编码

---

## 考试覆盖矩阵

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

| ASI ID | 官方名称 | 框架覆盖 | 状态 |
|-------|---------|---------|------|
| ASI01 | Agent Goal Hijack | ✅ | |
| ASI02 | Tool Misuse & Exploitation | ✅ | |
| ASI03 | Agent Identity & Privilege Abuse | ✅ | |
| ASI04 | Agentic Supply Chain Vulnerabilities | ✅ | |
| ASI05 | Unexpected Code Execution | ✅ | |
| ASI06 | Memory & Context Poisoning | ✅ | |
| ASI07 | Insecure Inter-Agent Communication | ✅ | |
| ASI08 | Cascading Failures | ✅ | |
| ASI09 | Human-Agent Trust Exploitation | ✅ | |
| ASI10 | Rogue Agents | ✅ | |

---

## 目录结构

```
pyrit/                          # 项目根目录
├── config/                     # 配置层（唯一配置源）
│   ├── attack/                 #   攻击策略配置
│   │   ├── defaults.yaml   #   默认转换器/评分器/ASI映射
│   │   └── patterns.yaml   #   攻击分类正则模式
│   ├── targets/               #   目标端点配置 YAML
│   ├── placeholders/          #   占位符配置（llm01-llm10/ + expericing/）
│   ├── recon/                 #   侦察配置（recon.yaml）
│   ├── scores/                #   评分器 LLM 后端（每后端一个 YAML）
│   ├── headers/               #   认证头文件
│   └── output/                #   输出报告配置
├── data/                       # 数据层
│   ├── owasp/                 #   载荷唯一真相源（590+ YAML）
│   │   ├── llm/               #     LLM01-LLM10
│   │   ├── agentic/           #     ASI01-ASI10
│   │   └── recon_templates/    #     侦察探测模板
│   └── recon_templates/       #   侦察探测模板
├── pyrit_ai300/                # 代码层（纯执行引擎）
│   ├── reconnaissance/        #   侦察引擎
│   ├── attack/                #   攻击引擎扩展
│   ├── orchestrators/         #   编排器（AttackOrchestrator, SmartMatcher）
│   ├── payloads/              #   载荷管理
│   ├── pipeline/              #   流水线追踪
│   ├── reporting/             #   报告生成
│   ├── tests/                 #   单元测试（168 tests）
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

## 快速开始

```bash
# 安装
pip install -e ".[dev,pdf,recon]"

# 列出可用组件
ai300 list attacks
ai300 list converters
ai300 list scorers
ai300 list owasp

# 侦察目标
ai300 recon -t http://localhost:11434 -d quick

# OWASP 标准攻击（单目标）
ai300 owasp llm01 --target-file config/targets/ollama_local.yaml

# OWASP 标准攻击（直接 URL）
ai300 owasp llm01 --target-url http://www.example.com

# 多目标批量攻击
ai300 owasp llm01 --target-dir config/targets/

# 先侦察再攻击
ai300 owasp llm01 --target-url http://target.com --auto-recon

# 使用侦察生成的 profile
ai300 owasp llm01 --target-file config/targets/ollama_local.yaml --profile results/recon/profile.json

# 全量 LLM Top 10 攻击
ai300 owasp llm --target-file config/targets/ollama_local.yaml

# 全量攻击 + HTML 报告
ai300 owasp all --target-file config/targets/ollama_local.yaml --format html -o report.html

# 实验模式（推荐）
ai300 owasp llm01 --target-file config/targets/ollama_local.yaml --experiment expericing/tier1_goal

# 列出占位符
ai300 owasp llm01 --list-placeholders

# 生成报告
ai300 report -r results.json -o report.md
```

### Python API

```python
from pyrit_ai300 import AI300Engine

# 初始化引擎
engine = AI300Engine(target_config="config/targets/ollama_local.yaml")

# 执行攻击
results = engine.run(scope="llm01")

# 生成报告
engine.generate_report(output_path="results/assessment_report.md")
```

---

## 配置系统

### 占位符系统（三级）

| 级别 | 占位符 | 填充方式 |
|------|--------|---------|
| Tier 1 | `{goal}` / `{objective}` | `--objective` 参数 |
| Tier 2 | `{base64_goal}` `{rot13_goal}` 等 14 种 | 从 objective 自动编码 |
| Tier 3 | `{domain}` `{task}` `{language}` 等 50+ 种 | `--placeholders key=value` |

### 优先级

```
--experiment > --objective > auto_discover > --placeholder-file > 交互式提示
```

### 实验模式

一个参数替代 `--objective`/`--placeholders`：

```bash
ai300 owasp llm01 --experiment expericing/tier1_goal
```

加载 `config/placeholders/expericing/tier1_goal.yaml` 中的 objective/placeholders/execution 参数。

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

---

## 依赖

- PyRIT >= 0.14.0
- Python >= 3.10
- PyYAML >= 6.0
- Jinja2 >= 3.1.0
- Rich >= 13.0.0
- pydantic >= 2.0.0

---

## 测试

```bash
# 运行全部测试
make test

# Lint 检查
make ci
```

**当前覆盖**：168 tests passed, 1 skipped

---

## 覆盖进度

- AI-300 Module: 11/11
- OWASP LLM: 10/10
- OWASP Agentic: 10/10
- 载荷库: 590 个有效载荷
- Jailbreak 模板: 165 个
- 侦察工具: 2 个（Garak + DeepTeam）
