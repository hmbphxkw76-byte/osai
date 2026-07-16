# AI-300 Framework Architecture Design

## 1. 架构总览

### 1.1 设计哲学

本框架以 **PyRIT (Python Risk Identification Tool) 0.14.0** 为核心引擎，采用 **数据驱动** 设计，实现 OffSec AI-300 考试场景的全覆盖。

```
┌─────────────────────────────────────────────────────────────────────┐
│                     AI-300 Framework Architecture                     │
├─────────────────────────────────────────────────────────────────────┤
│                                                                       │
│  ┌─────────────┐   ┌─────────────┐   ┌─────────────┐   ┌──────────┐ │
│  │   Config     │   │  Attack     │   │  Score      │   │ Report   │ │
│  │   Layer      │──▶│  Engine     │──▶│  Engine     │──▶│ Generator│ │
│  │  (YAML)      │   │  (PyRIT)    │   │  (PyRIT)    │   │ (Output) │ │
│  └─────────────┘   └─────────────┘   └─────────────┘   └──────────┘ │
│         │                 │                │                │        │
│         ▼                 ▼                ▼                ▼        │
│  ┌─────────────┐   ┌─────────────┐   ┌─────────────┐   ┌──────────┐ │
│  │  Payload    │   │  Converter  │   │  Memory     │   │ Markdown/│ │
│  │  Manager    │   │  Chain      │   │  (SQLite)   │   │ HTML     │ │
│  └─────────────┘   └─────────────┘   └─────────────┘   └──────────┘ │
│                                               │                       │
│                                               ▼                       │
│                                        ┌─────────────┐               │
│                                        │  Display    │               │
│                                        │  (Rich)     │               │
│                                        └─────────────┘               │
│                                                                       │
└─────────────────────────────────────────────────────────────────────┘
```

### 1.2 核心设计原则

| 原则 | 实现方式 |
|------|---------|
| **不重复造轮子** | 所有攻击/转换器/评分器/目标均通过 `import pyrit` 直接调用 |
| **数据驱动** | 攻击载荷、目标配置、评分规则全部从 YAML 配置加载 |
| **全流程自动化** | 修改载荷后，攻击执行→评分→报告生成全程无需人工干预 |
| **考试对齐** | 每个 Module 对应独立场景配置，覆盖 AI-300 全部 11 个 Module |
| **OWASP 映射** | 每个攻击场景都有对应的 OWASP LLM Top 10 + Agentic Top 10 分类 |

### 1.3 OWASP Agentic Top 10 (2026) 基础设计原则

来源: https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/

| 原则 | 说明 | 框架体现 |
|------|------|---------|
| **Least Agency** | Agent 自主行动的自由度应受限制，默认不授予未经验证的权限 | Module 3 权限边界测试、工具范围验证 |
| **Strong Observability** | 必须能看到 Agent 在做什么、为什么、以谁的身份 | 全链路审计日志、行为基线监控 |

> **三个信任边界问题**（OWASP 要求每个信任边界回答）：
> 1. **Who is acting?** — 独立的 Agent 身份，而非借用的人类会话
> 2. **What are they authorized to do?** — 有范围、有时限、可撤销的权限
> 3. **Can we prove it later?** — 连接身份、策略决策和结果的审计追踪

---

## 2. PyRIT 组件复用矩阵

### 2.1 攻击组件 (Attacks)

| PyRIT 攻击 | 框架使用 | AI-300 Module | OWASP |
|-----------|---------|--------------|-------|
| `PromptSendingAttack` | 基础提示发送 | Ch3-Ch9 | LLM01-LLM10 |
| `ManyShotJailbreakAttack` | 多轮越狱 | Ch3, Ch4 | LLM01 |
| `SkeletonKeyAttack` | 骨架密钥 | Ch3 | LLM01 |
| `TreeOfAttacksAttack` | 树状攻击 | Ch4, Ch5, Ch6 | LLM01, LLM08 |
| `CrescendoAttack` | 渐强攻击 | Ch4, Ch7 | LLM01, LLM07 |
| `PAIRAttack` | 自动迭代优化 | Ch4 | LLM01 |
| `RedTeamingAttack` | 红队攻击 | Ch11 | All |
| `ChunkedRequestAttack` | 分块请求 | Ch3 | LLM01 |
| `MultiPromptSendingAttack` | 多提示发送 | Ch3-Ch9 | LLM01 |
| `SimulatedConversationAttack` | 模拟对话 | Ch4 | LLM01, LLM08 |
| `SequentialAttack` | 顺序攻击 | Ch11 | All |

### 2.2 转换器组件 (Converters)

| 类别 | 代表组件 | 使用场景 |
|------|---------|---------|
| Text/Encoding | Base64Converter, ROT13Converter, UnicodeConfusableConverter, LeetspeakConverter | 绕过输入过滤 |
| Translation/Language | TranslationConverter, ArabiziConverter, BidiConverter | 多语言绕过 |
| Image | AddTextImageConverter, QRCodeConverter, ImageOverlayConverter | 图片隐写注入 |
| Document | PDFConverter, WordDocConverter | 文档注入 |
| LLM-based | PersuasionConverter, MaliciousQuestionGeneratorConverter | 高级语义转换 |

### 2.3 评分器组件 (Scorers)

| 类别 | 代表组件 | 使用场景 | 对应 ASI |
|------|---------|---------|---------|
| True/False | SelfAskRefusalScorer, SubStringScorer, SelfAskCategoryScorer | 攻击成功判定 | ASI01-ASI10 |
| Float Scale | AzureContentFilterScorer, InsecureCodeScorer, LikertScorer | 风险量化评估 | ASI05, ASI09 |
| Regex | ShellCommandOutputScorer, SQLInjectionScorer, CredentialLeakScorer | 注入/执行检测 | ASI03, ASI05 |

### 2.4 目标组件 (Targets)

| PyRIT 目标 | 框架使用 | AI-300 Module |
|-----------|---------|--------------|
| `OpenAIChatTarget` | Ollama/OpenAI 兼容 API | Ch3-Ch9 |
| `HTTPTarget` | 自定义 HTTP 端点 | Ch4, Ch5, Ch7 |
| `TextTarget` | 文本输出目标 | 测试 |

---

## 3. AI-300 Module 全覆盖设计

### 3.1 覆盖矩阵

```
Module 3: Single Agent Risks (对齐 OWASP Agentic ASI01, ASI02, ASI05, ASI06)
├── ASI01 Agent Goal Hijack → PromptSendingAttack + Converters (目标劫持)
├── ASI02 Tool Misuse & Exploitation → PromptSendingAttack (工具滥用)
├── ASI05 Unexpected Code Execution → PromptSendingAttack + InsecureCodeScorer (代码执行)
└── ASI06 Memory & Context Poisoning → TextJailbreakConverter (记忆投毒)

Module 4: Multi-Agent / A2A Risks (对齐 OWASP Agentic ASI03, ASI04, ASI07, ASI08, ASI09, ASI10)
├── ASI03 Agent Identity & Privilege Abuse → TreeOfAttacksAttack (身份权限滥用)
├── ASI04 Agentic Supply Chain Vulnerabilities → PromptSendingAttack (供应链)
├── ASI07 Insecure Inter-Agent Communication → TreeOfAttacksAttack (通信安全)
├── ASI08 Cascading Failures → SequentialAttack (级联失败)
├── ASI09 Human-Agent Trust Exploitation → PAIRAttack (信任利用)
└── ASI10 Rogue Agents → SequentialAttack (流氓Agent)

Module 5: RAG Pipeline
├── Ingestion Poisoning → Document Converters
├── Retrieval Hijacking → Similarity Manipulation
└── Knowledge Extraction → TreeOfAttacksAttack

Module 6: Embeddings
├── Embedding Inversion → Zero-shot/Pretrained
├── Membership Inference → Binary Detection
└── Attribute Inference → Metadata Extraction

Module 7: MCP / Tool Surfaces
├── Tool Poisoning → Description Manipulation
├── Tool Shadowing → Malicious Tool Creation
└── Permission Bypass → Constraint Evasion

Module 8: Supply Chain
├── Pickle RCE → Malicious Model Upload
├── Dependency Confusion → Namespace Squatting
└── MCP Backdoor → Source Code Compromise

Module 9: Infrastructure
├── Cloud Misconfig → IAM/SSRF/Exposed Endpoints
├── Container Escape → K8s API Abuse
└── Model Extraction → API Query Extraction
```

### 3.2 OWASP LLM Top 10 完整映射

| OWASP | 框架覆盖 | 攻击技术 | PyRIT 组件 |
|-------|---------|---------|-----------|
| LLM01 | ✅ | Direct/Indirect Injection, Multi-agent Injection | PromptSending + Converters |
| LLM02 | ✅ | MCP Tool Abuse, Output Manipulation | HTTPTarget + Scorers |
| LLM03 | ✅ | RAG Poisoning, Embedding Inversion | Document Converters |
| LLM04 | ✅ | Resource Exhaustion, Cloud Misconfig | AzureTarget |
| LLM05 | ✅ | Pickle RCE, Dependency Confusion | Auxiliary Attacks |
| LLM06 | ✅ | System Prompt Leak, RAG Data Extraction | PromptSending + Scorers |
| LLM07 | ✅ | MCP Tool Poisoning, Shadowing | HTTPTarget + Converters |
| LLM08 | ✅ | Agent Hijacking, A2A Impersonation | MultiTurn Attacks |
| LLM09 | ✅ | Threat Model Gaps, Validation Bypass | Scenario Analysis |
| LLM10 | ✅ | Embedding Inversion, Model Extraction | Embedding Module |

### 3.3 OWASP Agentic Top 10 (2026) 完整映射

来源: https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/

| ASI ID | 风险名称 | 框架覆盖 | Module | PyRIT 组件 |
|--------|---------|---------|--------|-----------|
| ASI01 | Agent Goal Hijack | ✅ | single_agent | PromptSending + Converters + PromptShieldScorer |
| ASI02 | Tool Misuse & Exploitation | ✅ | single_agent | PromptSending + Converters |
| ASI03 | Agent Identity & Privilege Abuse | ✅ | multi_agent | TreeOfAttacks + GandalfScorer |
| ASI04 | Agentic Supply Chain Vulnerabilities | ✅ | multi_agent | PromptSending + MaliciousQuestionGeneratorConverter |
| ASI05 | Unexpected Code Execution | ✅ | single_agent | PromptSending + InsecureCodeScorer |
| ASI06 | Memory & Context Poisoning | ✅ | single_agent | PromptSending + TextJailbreakConverter |
| ASI07 | Insecure Inter-Agent Communication | ✅ | multi_agent | TreeOfAttacks + PersuasionConverter |
| ASI08 | Cascading Failures | ✅ | multi_agent | SequentialAttack |
| ASI09 | Human-Agent Trust Exploitation | ✅ | multi_agent | PAIRAttack + AzureContentFilterScorer |
| ASI10 | Rogue Agents | ✅ | multi_agent | SequentialAttack + GandalfScorer |

---

## 4. 数据驱动自动化流程

### 4.1 配置驱动攻击执行

```yaml
# 修改攻击载荷 → 自动执行 → 自动评分 → 自动报告
attack_config:
  name: "direct_prompt_injection"
  payloads:
    - "new_payload_1"  # 只需修改这里
    - "new_payload_2"
  converters: ["base64", "rot13"]
  scorers: ["refusal", "substring"]
```

### 4.2 自动化流水线

```
┌──────────┐     ┌──────────┐     ┌──────────┐     ┌──────────┐
│  Config   │────▶│  Attack   │────▶│  Score   │────▶│  Report  │
│  Load     │     │  Execute  │     │  Evaluate │     │  Generate │
└──────────┘     └──────────┘     └──────────┘     └──────────┘
     │                │                │                │
     ▼                ▼                ▼                ▼
  YAML/JSON       PyRIT           PyRIT           Markdown/
  Files           Executor        Scorers         HTML
```

---

## 5. 报告生成系统

### 5.1 报告结构（对齐 OffSec 标准）

1. **Executive Summary** - 关键发现和风险评级
2. **Scope and Rules of Engagement** - 范围和交战规则
3. **Methodology** - 方法论和框架覆盖
4. **Findings Summary** - 按 Module 汇总发现
5. **Detailed Findings** - 每个攻击的详细结果
6. **Attack Path Visualization** - 攻击路径可视化
7. **Risk Assessment** - 风险评估矩阵
8. **Remediation Recommendations** - 修复建议
9. **Appendices** - 工具、参考、元数据

### 5.2 输出格式

- **Markdown** - 默认格式，便于版本控制和协作
- **HTML** - 可视化报告，支持样式和交互

---

## 6. 扩展性设计

### 6.1 添加新攻击

1. 在 `config/catalog/catalog.yaml` 中添加攻击定义
2. 配置 PyRIT 攻击组件和转换器
3. 定义攻击载荷
4. 运行框架自动执行

### 6.2 添加新转换器

1. 在 `pyrit_ai300/orchestrators/attack_orchestrator.py` 的 `CONVERTER_MAP` 中添加映射
2. 在配置中引用新转换器名称
3. 框架自动加载和使用

### 6.3 添加新评分器

1. 在 `pyrit_ai300/orchestrators/attack_orchestrator.py` 的 `SCORER_MAP` 中添加映射
2. 在配置中引用新评分器名称
3. 框架自动加载和评分

---

## 7. 与现有 PyRIT 安装的关系

本框架作为 PyRIT 的 **上层封装**，不修改 PyRIT 任何代码：

```
pyrit_ai300/             # 本框架
├── config/               # 配置文件（项目根目录）
├── orchestrators/        # 编排器（调用 PyRIT）
├── reporting/            # 报告生成
├── display/              # 终端展示
├── converters/           # 转换器配置（映射 PyRIT）
├── scorers/              # 评分器配置（映射 PyRIT）
├── payloads/             # 载荷管理
└── attacks/              # 攻击配置（映射 PyRIT）

pyrit/                    # PyRIT 框架（独立安装）
├── executor/attack/      # 攻击执行器
├── prompt_converter/     # 转换器
├── score/                # 评分器
├── prompt_target/        # 目标
├── memory/               # 内存管理
└── datasets/             # 数据集
```

---

## 8. 考试使用指南

### 8.1 考试前准备

1. 安装框架：`pip install -e .`
2. 配置目标：编辑 `config/targets/` 下的 YAML 文件
3. 准备载荷：编辑 `config/catalog/catalog.yaml`
4. 验证配置：`ai300 list modules`

### 8.2 考试中执行

1. 运行指定 Module：`ai300 run -m single_agent`
2. 运行全部 Module：`ai300 run`
3. 生成报告：`ai300 report -r results.json -o report.md`

### 8.3 考试后分析

1. 查看执行结果
2. 分析攻击成功率
3. 生成最终报告
