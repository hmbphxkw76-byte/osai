# AI-300 Framework Architecture Design

## 1. 架构总览（v3.0）

### 1.1 设计哲学

本框架以 **PyRIT 0.14.0** 为核心引擎，采用 **三层分离 + 数据驱动** 设计，实现 OffSec AI-300 考试场景的全覆盖。

```
┌─────────────────────────────────────────────────────────────────────┐
│                     AI-300 Framework v3.0 Architecture               │
├─────────────────────────────────────────────────────────────────────┤
│                                                                       │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │                     CLI 入口 (cli.py)                        │    │
│  │         命令: run / list / report / recon                    │    │
│  └──────────────────────────┬──────────────────────────────────┘    │
│                             │                                        │
│              ┌──────────────┴──────────────┐                        │
│              ▼                              ▼                        │
│  ┌──────────────────────┐      ┌──────────────────────────────┐    │
│  │   侦察层 (recon)      │      │       攻击层 (attack)         │    │
│  │                      │      │                              │    │
│  │  ReconEngine         │      │  AI300Engine                 │    │
│  │    ├── GarakAdapter  │      │    ├── AttackOrchestrator    │    │
│  │    ├── DeepTeamAdapter│     │    ├── SmartMatcher          │    │
│  │    └── ProfileMerger │      │    ├── ProfileLoader ◄──────┼──┐ │
│  │           ↓          │      │    └── 7 个 Module           │  │ │
│  │   TargetProfile JSON │──────┼──────────────────────────────┘  │ │
│  └──────────────────────┘      └──────────────────────────────────┘ │
│                                                                       │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │                     数据层 + 配置层                           │    │
│  │  data/owasp/ (251 YAML)  │  config/catalog/  │  config/targets/│    │
│  │  data/recon_templates/   │  config/recon/    │  config/scores.yaml│   │
│  └─────────────────────────────────────────────────────────────┘    │
│                                                                       │
└─────────────────────────────────────────────────────────────────────┘
```

### 1.2 核心设计原则

| 原则 | 实现方式 |
|------|---------|
| **不重复造轮子** | 所有攻击/转换器/评分器/目标均通过 `import pyrit` 直接调用 |
| **调度器 + 格式转换器** | 框架只做编排+格式转换，能力来自 PyRIT + 外部工具（ARCH-001） |
| **三层分离** | 数据层（data/）+ 配置层（config/）+ 引擎层（pyrit_ai300/） |
| **侦察-攻击解耦** | 侦察层不 import 攻击层，通过 TargetProfile JSON 通信 |
| **数据驱动** | 攻击载荷、目标配置、评分规则全部从 YAML 配置加载 |
| **全流程自动化** | 修改载荷后，侦察→攻击→评分→报告生成全程无需人工干预 |
| **考试对齐** | 覆盖 AI-300 全部 Module，OWASP LLM Top 10 + Agentic Top 10 |
| **config 为唯一配置源** | 所有策略配置在 config/ 目录，代码不含硬编码字典 |

### 1.3 数据流

```
┌─────────────────────────────────────────────────────────────────────┐
│                         端到端数据流                                  │
├─────────────────────────────────────────────────────────────────────┤
│                                                                       │
│  ① 侦察流程（recon 命令）                                              │
│  ─────────────────────────                                            │
│  ReconEngine.run(target)                                             │
│    ├── GarakAdapter.run() ──────────┐                                │
│    ├── DeepTeamAdapter.run() ───────┤──→ ThreadPoolExecutor 并发      │
│    │                                │                                │
│    ▼                                ▼                                │
│  ProfileMerger.merge(results)                                         │
│    ├── 去重（相似度 > 0.85）                                          │
│    ├── 置信度加权（garak: 0.85, deepteam: 0.85）                       │
│    ├── 风险计算（critical/high/medium/low）                            │
│    └── 攻击建议生成                                                    │
│    │                                                                  │
│    ▼                                                                  │
│  TargetProfile JSON → results/recon/profile_<timestamp>.json          │
│                                                                       │
│  ② 攻击流程（owasp 命令）                                              │
│  ────────────────────────                                             │
│  AI300Engine.run()                                                   │
│    ├── ProfileLoader.load(profile.json) ──→ SmartMatcher 参数         │
│    ├── 从 config/attack/defaults.yaml 加载默认转换器/评分器            │
│    ├── AttackOrchestrator.build_attack_list_from_refs()              │
│    │     └── 从 OWASP ref 构建攻击列表                                │
│    ├── 遍历攻击列表                                                   │
│    │     └── AttackOrchestrator.execute_attack()                     │
│    │           ├── SmartMatcher → PyRIT 攻击策略选择                  │
│    │           ├── PyRIT 原生攻击执行                                  │
│    │           └── Scorer 评分                                        │
│    │                                                                  │
│    ▼                                                                  │
│  ReportGenerator.generate() → results/assessment_report.md            │
│                                                                       │
└─────────────────────────────────────────────────────────────────────┘
```

### 1.4 OWASP Agentic Top 10 (2026) 基础设计原则

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

## 4. 侦察引擎设计（v3.0 新增）

### 4.1 架构

```
ReconEngine (统一调度器)
  ├── GarakAdapter ────→ NVIDIA Garak 漏洞扫描
  ├── DeepTeamAdapter ──→ Confident AI DeepTeam OWASP 红队
  └── ProfileMerger ────→ 多工具结果合并（去重 + 加权 + 风险计算）
```

### 4.2 侦察工具

| 工具 | 版本 | 定位 | 集成方式 | AI-300 对应 |
|------|------|------|---------|------------|
| Garak | ≥0.15.1 | 漏洞扫描 | Python SDK (`garak.cli.main`) | LLM01/LLM03/LLM06/LLM08/LLM09 |
| DeepTeam | ≥1.0.7 | OWASP 红队 | Python API (`red_team()`) | OWASP Top 10 LLM + Agentic |

### 4.3 TargetProfile JSON Schema

```json
{
  "target": "http://localhost:11434",
  "tools_used": ["garak", "deepteam"],
  "risk_level": "high",
  "vulnerability_count": 12,
  "vulnerabilities": [
    {
      "id": "vuln_001",
      "category": "prompt_injection",
      "severity": "critical",
      "owasp": "LLM01",
      "confidence": 0.85,
      "source": "garak",
      "description": "Direct prompt injection successful"
    }
  ],
  "attack_surface": ["agent", "rag"],
  "attack_recommendations": [
    {
      "strategy": "DIRECT_SINGLE",
      "priority": 1,
      "reason": "High confidence prompt injection vulnerability"
    }
  ],
  "metadata": {
    "scan_duration": 45.2,
    "timestamp": "2026-07-17T09:40:21"
  }
}
```

### 4.4 Probe → OWASP 映射（Garak）

| Garak Probe | OWASP | AI-300 考点 |
|-------------|-------|------------|
| promptinject | LLM01 | Prompt Injection |
| dan / jailbreak | LLM01 | Jailbreak |
| malgen | LLM06 | Sensitive Information Disclosure |
| hallucination | LLM09 | Overreliance |
| misinformation | LLM08 | Excessive Agency |
| toxicity | LLM03 | Training Data Poisoning |

### 4.5 Vulnerability → OWASP 映射（DeepTeam）

| DeepTeam 漏洞类型 | OWASP |
|-------------------|-------|
| prompt_injection | LLM01 |
| jailbreak | LLM01 |
| leakage | LLM02 |
| poisoning | LLM03 |
| excessive_agency | LLM05 |
| system_prompt | LLM06 |
| rag | LLM07 |
| hallucination | LLM09 |

---

## 5. Smart Match 引擎（v3.0 核心）

### 5.1 决策流程

```
payload → normalize_payload() → analyze_payload() → PayloadProfile(五维+置信度)
  → 两层策略选择 → PyRIT 原生攻击
```

### 5.2 攻击探针族

| 策略 | 适用场景 | PyRIT 攻击 |
|------|---------|-----------|
| DIRECT_SINGLE | 直接注入，高置信度 | PromptSendingAttack |
| PROGRESSIVE | 渐进式升级 | CrescendoAttack |
| TREE_SEARCH | 多路径探索 | TreeOfAttacksAttack |
| ITERATIVE | 自动优化 | PAIRAttack |
| EXPLORATORY | 未知目标 | RedTeamingAttack |
| MULTI_PRESET | 多预设组合 | SequentialAttack |

### 5.3 Fallback 链

```
CrescendoAttack → TAP → PAIR → PromptSendingAttack
```

### 5.4 动态参数

```python
max_turns = 5 + complexity_score + token_factor
```

---

## 6. 报告生成系统

### 6.1 报告结构（对齐 OffSec 标准）

1. **Executive Summary** - 关键发现和风险评级
2. **Scope and Rules of Engagement** - 范围和交战规则
3. **Methodology** - 方法论和框架覆盖
4. **Findings Summary** - 按 Module 汇总发现
5. **Detailed Findings** - 每个攻击的详细结果
6. **Attack Path Visualization** - 攻击路径可视化
7. **Risk Assessment** - 风险评估矩阵
8. **Remediation Recommendations** - 修复建议
9. **Appendices** - 工具、参考、元数据

### 6.2 输出格式

- **Markdown** - 默认格式，便于版本控制和协作
- **HTML** - 可视化报告，支持样式和交互

---

## 7. 数据目录结构

### 7.1 唯一真相源规则（DATA-001）

```
data/
├── owasp/                        ← 载荷唯一真相源
│   ├── llm/                      ← LLM01-LLM10
│   │   ├── llm01/                ← 子目录（多级扫描）
│   │   │   ├── direct_injection.yaml
│   │   │   ├── jailbreak/        ← 多级子目录支持
│   │   │   │   ├── aim.yaml
│   │   │   │   └── ...
│   │   │   └── ...
│   │   └── ...
│   ├── agentic/                  ← ASI01-ASI10
│   └── recon_templates/          ← 侦察探测模板
│       ├── system_prompt.yaml
│       ├── capability.yaml
│       └── boundary.yaml
└── recon_templates/              ← 侦察探测模板（根目录）
```

### 7.2 元数据规范

每个 payload YAML 文件**必须**包含：

```yaml
id: llm01                         # OWASP 分类标识
name: Prompt Injection            # 人类可读名称
description: 直接提示注入         # 攻击原理描述
payloads: [...]                   # 载荷列表
```

**架构约束**：
- OWASP ID 隐含攻击面，不存储 `surfaces` 和 `ai300_chapters` 字段
- surfaces 由侦察阶段动态生成（TargetProfile.surfaces）
- AI-300 章节由 `reporting/chapter_mapper.py` 动态推导
- 多级子目录扫描（`rglob`），有子目录时顶层 YAML 不加载

---

## 8. 引擎层模块

### 8.1 目录结构

```
pyrit_ai300/                      # 代码层（纯执行引擎）
├── reconnaissance/               #   侦察引擎（完全独立，不 import attack/）
│   ├── recon_engine.py           #   统一调度入口
│   ├── target_profile.py         #   TargetProfile 数据模型（唯一接口契约）
│   ├── profile_merger.py         #   多工具结果合并
│   ├── adapters/                 #   薄壳适配器
│   │   ├── base_adapter.py       #   抽象基类
│   │   ├── garak_adapter.py      #   → import garak
│   │   └── deepteam_adapter.py   #   → import deepteam
│   └── utils/                    #   工具函数
├── attack/                       #   攻击引擎扩展
│   ├── profile_loader.py         #   读 TargetProfile → SmartMatcher 参数
│   └── __init__.py
├── orchestrators/                #   编排器
│   ├── attack_orchestrator.py   #   攻击编排 + 执行
│   ├── smart_matcher.py         #   PyRIT 攻击策略选择
│   ├── attack_registry.py       #   攻击元数据注册表
│   ├── component_registry.py    #   PyRIT 组件映射（CONVERTER_MAP / SCORER_MAP）
│   ├── rate_controller.py       #   速率控制
│   └── auth/                    #   认证配置解析
├── payloads/                     #   载荷管理
│   ├── payload_manager.py       #   载荷加载/分类/渲染
│   ├── models.py                #   PayloadProfile 数据模型
│   ├── normalizer.py            #   载荷标准化
│   ├── patterns.py              #   攻击分类模式
│   └── payload_classifier.py    #   载荷分类器
├── pipeline/                     #   流水线追踪
│   └── tracker.py               #   执行追踪 + 终端输出
├── reporting/                    #   报告生成
│   ├── report_generator.py      #   评估报告生成
│   ├── execution_report.py      #   执行报告保存
│   └── chapter_mapper.py        #   OWASP ID → AI-300 章节映射
├── tests/                        #   单元测试（168 tests）
├── utils/                        #   工具函数
│   └── logger.py                #   日志配置
├── __init__.py                   #   AI300Engine 入口
└── cli.py                        #   命令行接口
```

### 8.2 测试覆盖

| 模块 | 测试数 | 覆盖内容 |
|------|--------|---------|
| Framework | 107 | 编排器、载荷管理、SmartMatcher、报告 |
| Recon | 64 | 侦察引擎、适配器、ProfileMerger |
| **总计** | **168** | **全部通过** |

---

## 9. 与现有 PyRIT 安装的关系

本框架作为 PyRIT 的 **上层封装**，不修改 PyRIT 任何代码：

```
pyrit_ai300/             # 本框架
├── config/               # 配置文件（项目根目录）
├── orchestrators/        # 编排器（调用 PyRIT）
├── reporting/            # 报告生成
├── payloads/             # 载荷管理
├── reconnaissance/       # 侦察引擎（调用外部工具）
├── attack/               # 攻击引擎扩展
├── pipeline/             # 执行追踪
└── tests/                # 单元测试

pyrit/                    # PyRIT 框架（独立安装）
├── executor/attack/      # 攻击执行器
├── prompt_converter/     # 转换器
├── score/                # 评分器
├── prompt_target/        # 目标
├── memory/               # 内存管理
└── datasets/             # 数据集
```

---

## 10. 考试使用指南

### 10.1 考试前准备

1. 安装框架：`pip install -e .`（无网络环境见 [`OFFLINE_INSTALL.md`](./OFFLINE_INSTALL.md)）
2. 安装侦察工具：`pip install -e ".[recon]"`
3. 配置目标：编辑 `config/targets/` 下的 YAML 文件
4. 验证配置：`ai300 list owasp`

### 10.2 考试中执行

```bash
# 侦察目标
ai300 recon -t http://target:11434 -d quick

# OWASP 标准攻击（单目标）
ai300 owasp llm01 --target-file config/targets/ollama_local.yaml

# 先侦察再攻击
ai300 owasp llm01 --target-url http://target.com --auto-recon

# 使用侦察生成的 profile
ai300 owasp llm01 --target-file config/targets/ollama_local.yaml --profile results/recon/profile.json

# 全量 LLM Top 10 攻击
ai300 owasp llm --target-file config/targets/ollama_local.yaml

# 全量攻击 + HTML 报告
ai300 owasp all --target-file config/targets/ollama_local.yaml --format html -o report.html

# 生成报告
ai300 report -r results.json -o report.md
```

### 10.3 考试后分析

1. 查看执行结果
2. 分析攻击成功率
3. 生成最终报告
