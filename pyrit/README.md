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
│  │    ├── NativeProbe   │      │    ├── AttackOrchestrator    │    │
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
│   │   └── defaults.yaml   #   默认转换器/评分器/ASI映射
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
│   ├── reconnaissance/        #   侦察引擎 (AIMAP/NativeProbe/DeepTeam)
│   ├── core/                  #   共享核心库 (utils/protocols/models) (v3.8.0)
│   ├── attack/                #   攻击引擎扩展 (ProfileLoader)
│   ├── orchestrators/         #   编排器 (AttackOrchestrator/SmartMatcher/ScorerBuilder)
│   ├── payloads/              #   载荷管理 (Manager/Classifier/Dedup/Mutator)
│   ├── pipeline/              #   流水线编排 (Orchestrator/Tracker/CredentialManager)
│   ├── reporting/             #   报告生成 (OffSec 9段标准)
│   ├── standards/             #   标准定义 (OWASP SSoT) (v3.8.0)
│   ├── scenarios/             #   评估场景 (v3.8.0)
│   ├── tests/                 #   单元测试（900+ tests）
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

## 环境准备

### 基础安装

```bash
# 安装框架及依赖（含 PyRIT、Rich、PyYAML 等）
pip install -e ".[dev,pdf,recon]"
```

### Playwright 浏览器环境（SPA 攻击必需）

SPA 聊天应用攻击（`spa_target.yaml`）和 SPA 侦察（`--spa-config`）依赖 Playwright 浏览器自动化，需额外安装：

```bash
# 1. 安装 Playwright Python 包
uv pip install playwright
# 或使用 pip: pip install playwright

# 2. 安装 Chromium 浏览器引擎（约 150MB，仅需一次）
playwright install chromium
```

> **说明**：Playwright 是 PyRIT `PlaywrightTarget` 的底层依赖，用于浏览器自动化（Cookie 注入、选择器交互、流量捕获）。不安装将无法执行 SPA 相关的侦察和攻击。

### 敏感配置（.env 环境变量）

所有目标配置文件（`spa_target.yaml` / `llm_api_target.yaml` / `http_target.yaml`）中的敏感信息（账号、密码、API Key、Bearer Token）通过 `.env` 环境变量注入，避免硬编码泄露：

```bash
# 1. 复制模板
cp .env.example .env

# 2. 编辑 .env，填入真实凭据
#    SPA_USERNAME=your_username
#    SPA_PASSWORD=your_password
#    LLM_API_KEY=not-needed          # Ollama 填 not-needed，云端填 sk-xxx
#    HTTP_API_TOKEN=your_token
#    SCORES_API_KEY=your_key

# 3. 在 YAML 配置中通过 ${VAR} 引用（框架自动替换）
#    username: "${SPA_USERNAME}"
#    api_key: "${LLM_API_KEY}"
```

> **安全说明**：`.env` 文件已在 `.gitignore` 中排除，不会被提交到版本库。框架在导入时自动加载 `.env` 文件（`pyrit_ai300/utils/env_loader.py`）。

### Playwright 环境（SPA 侦察）

```bash
uv pip install playwright
playwright install chromium
```

### UV 快速安装（推荐）

```bash
# 创建虚拟环境并安装全部依赖
uv venv .venv
uv pip install -e ".[dev,pdf,recon]"
uv pip install playwright
playwright install chromium

# 配置敏感信息（账号密码 / API Key）
cp .env.example .env
# 编辑 .env 填入真实凭据
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

# SPA 智能助手侦察（自动凭据复用 + 浏览器登录 + 流量捕获）
# 首次：人工完成验证码/OAuth → 系统自动导出凭据到 credentials/
# 后续：自动从 credentials/{域名}.txt 复用，免重复登录
# 无认证降级：认证失败不终止流程，以未认证状态继续有限侦察
ai300 recon --spa-config config/targets/spa_target.yaml

# SPA 聊天攻击（配合侦察阶段使用，复用认证凭据）
ai300 owasp llm01 --target-file config/targets/spa_target.yaml

# OWASP 标准攻击（单目标）
ai300 owasp llm01 --target-file config/targets/llm_api_target.yaml

# OWASP 标准攻击（直接 URL）
ai300 owasp llm01 --target-url http://www.example.com

# 多目标批量攻击
ai300 owasp llm01 --target-dir config/targets/

# 先侦察再攻击
ai300 owasp llm01 --target-url http://target.com --auto-recon

# 使用侦察生成的 profile
ai300 owasp llm01 --target-file config/targets/llm_api_target.yaml --profile results/recon/profile.json

# 全量 LLM Top 10 攻击
ai300 owasp llm --target-file config/targets/llm_api_target.yaml

# 全量攻击 + HTML 报告
ai300 owasp all --target-file config/targets/llm_api_target.yaml --format html -o report.html

# 实验模式（推荐）
ai300 owasp llm01 --target-file config/targets/llm_api_target.yaml --experiment expericing/tier1_goal

# 列出占位符
ai300 owasp llm01 --list-placeholders

# 生成报告
ai300 report -r results.json -o report.md
```

### Python API

```python
from pyrit_ai300 import AI300Engine

# 初始化引擎
engine = AI300Engine(target_config="config/targets/llm_api_target.yaml")

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

| 工具 | 定位 | AI-300 对应 |
|------|------|------------|
| NativeProbe | 轻量级探针扫描 (内置) | LLM01/LLM03/LLM06/LLM08/LLM09 |
| DeepTeam | OWASP 红队 | OWASP Top 10 LLM + Agentic |
| SPAChatRecon | 浏览器自动化侦察 | SPA 应用全链路 |

---

## 依赖

- PyRIT >= 0.14.0
- Python >= 3.10
- PyYAML >= 6.0
- Jinja2 >= 3.1.0
- Rich >= 13.0.0
- pydantic >= 2.0.0
- Playwright（SPA 攻击必需，`uv pip install playwright && playwright install chromium`）

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
- 侦察工具: 3 个（NativeProbe + DeepTeam + SPAChatRecon）
