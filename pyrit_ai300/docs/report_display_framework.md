# 报告展示层框架设计 — 数据流闭环验证

> **版本**: v1.0  
> **对齐标准**: PyRIT 1.0.0 原生 output 模块  
> **L5 专家级**: 原生优先 · 数据驱动 · 攻击效果理想  
> **创建日期**: 2026-07-29  

---

## 目录

1. [架构总览](#1-架构总览)
2. [数据流完整闭环验证](#2-数据流完整闭环验证)
3. [报告展示层框架设计图](#3-报告展示层框架设计图)
4. [方案B: Converter Transformation Log](#4-方案b-converter-transformation-log)
5. [方案C: Converter Variant Preview](#5-方案c-converter-variant-preview)
6. [命名一致性: snake_case ↔ PascalCase](#6-命名一致性-snake_case--pascalcase)
7. [报告增强: identifier.children 提取 Converter 信息](#7-报告增强-identifierchildren-提取-converter-信息)
8. [三级证据链架构](#8-三级证据链架构)
9. [原生 PyRIT output 集成](#9-原生-pyrit-output-集成)
10. [文件变更清单](#10-文件变更清单)

---

## 1. 架构总览

### 1.1 设计原则

| 原则 | 描述 | 实现方式 |
|------|------|----------|
| **原生优先** | 最大化使用 PyRIT 1.0.0 原生 output API | `output_attack_async` / `PrettyAttackResultPrinter` / `MarkdownAttackResultMemoryPrinter` |
| **数据驱动** | 所有展示数据可追溯到 Pipeline 阶段 | StrategySelection → AttackPlan → AttackResult → Report |
| **攻击效果理想** | Converter 变体增强 ASR，转换日志可视化 | extra_request_converters + 后处理重转换 |
| **不修改核心** | 增强功能不修改 PyRIT 核心执行路径 | 后处理重转换 + 标识符提取 |
| **闭环验证** | 数据从生成到展示全链路可追溯 | identifier.children → converter 类名 → chain name |

### 1.2 核心模块

```
src/reporting/
├── __init__.py              # 公共 API 导出（58+ 接口）
├── report_generator.py      # 报告生成器（8章 Markdown 报告 + CSV + ZIP 证据包）
├── output_manager.py        # 输出管理器（双通道: StdoutSink + FileSink）
├── converter_log.py         # ⭐ 新增: 转换日志 + 变体预览 + 命名映射
├── diversity_analyzer.py    # 攻击多样性分析（Shannon 熵/OWASP 覆盖）
└── format_converter.py      # Markdown → HTML/PDF 格式转换
```

---

## 2. 数据流完整闭环验证

### 2.1 数据流全景图

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         PIPELINE (9 STAGES)                             │
│                                                                         │
│  Stage 2: Analysis          Stage 4: Datasets        Stage 5: Matching  │
│  ┌─────────────────┐        ┌─────────────────┐      ┌────────────────┐ │
│  │ StrategySelection│       │ AttackPlan       │      │ converter_chains│ │
│  │ • attack_techniques│─────►│ • attack_technique│◄────│ (Target-Aware) │ │
│  │   (snake_case)  │        │ • converter_chain │      │ Router 推荐    │ │
│  └─────────────────┘        │   _name           │      └───────┬────────┘ │
│                              │ • prompt_item     │              │          │
│                              │   • objective     │              │          │
│                              │   • converter_    │              │          │
│                              │     chains        │              │          │
│                              └────────┬──────────┘              │          │
│                                       │                          │          │
│  Stage 6: Execute                     ▼                          │          │
│  ┌──────────────────────────────────────────────────────────────┐│          │
│  │  AI300AdaptiveScenario                                         ││          │
│  │  • attack_plans → seed_groups → AttackSeedGroup               ││          │
│  │  • extra_request_converters (Converter 变体)                   ││◄─────────┘
│  │  • AttackTechniqueFactory.create()                             ││
│  │  • FIRST_SUCCESS 停止策略                                       ││
│  └────────────────────────┬───────────────────────────────────────┘│
│                           │                                           │
│                           ▼                                           │
│  ┌──────────────────────────────────────────────────────────────────┐│
│  │  AttackResult (PyRIT 原生)                                       ││
│  │  ┌──────────────────────────────────────────────────────────┐   ││
│  │  │ AttackStrategyIdentifier                                   │   ││
│  │  │  • class_name: "PromptSendingAttack"                      │   ││
│  │  │  • unique_name: "PromptSendingAttack::49fe4c34"          │   ││
│  │  │  • children:                                               │   ││
│  │  │    "request_converters": [                                 │   ││
│  │  │      ConverterIdentifier(class_name="Base64Converter"),   │   ││
│  │  │      ConverterIdentifier(class_name="ROT13Converter"),    │   ││
│  │  │    ]                                                       │   ││
│  │  │  • labels:                                                 │   ││
│  │  │    "owasp_id": "LLM01"                                    │   ││
│  │  │    "converter_chain_name": "stealth_evasion" (可能缺失)    │   ││
│  │  └──────────────────────────────────────────────────────────┘   ││
│  │  • conversation: [MessagePiece(role="user", original_value=...)]││
│  │  • last_score: Score(score_value=True, ...)                     ││
│  └────────────────────────┬─────────────────────────────────────────┘│
│                           │                                           │
└───────────────────────────┼───────────────────────────────────────────┘
                            │
                            ▼
┌───────────────────────────────────────────────────────────────────────┐
│                       REPORT DISPLAY LAYER                             │
│                                                                       │
│  ┌─────────────────────┐  ┌──────────────────────┐                   │
│  │ OutputManager       │  │ ReportGenerator       │                   │
│  │ (实时双通道输出)     │  │ (最终报告生成)         │                   │
│  │                     │  │                       │                   │
│  │ output_attack_async │  │ 1. Introduction       │                   │
│  │ • Pretty (终端)     │  │ 2. Executive Summary  │                   │
│  │ • Markdown (文件)   │  │ 3. OWASP Coverage     │                   │
│  │                     │  │ 4. Detailed Findings  │                   │
│  │ 原生 API:           │  │ 5. Attack Timeline    │                   │
│  │ • Attack Summary    │  │ 5.5 Success Highlights│                   │
│  │ • Conversation      │  │ 5.6 ⭐Converter Analysis│ ← 新增           │
│  │ • Converted content │  │ 6. MITRE ATT&CK       │                   │
│  │                     │  │ 7. Tool Usage         │                   │
│  └─────────────────────┘  │ 8. Appendix           │                   │
│                            └──────────────────────┘                   │
│                                                                       │
│  ┌─────────────────────────────────────────────────────────────────┐ │
│  │ EvidenceExporter (证据导出)                                      │ │
│  │ • per-attack Markdown (含 ⭐Converter Transformation Log)       │ │
│  │ • per-conversation Markdown                                     │ │
│  │ • per-score Markdown                                            │ │
│  │ • attack_summary.csv                                            │ │
│  │ • owasp_coverage_matrix.csv                                     │ │
│  │ • attack_timeline.csv                                           │ │
│  │ • evidence.json (model_dump)                                    │ │
│  └─────────────────────────────────────────────────────────────────┘ │
└───────────────────────────────────────────────────────────────────────┘
```

### 2.2 Attack Type 数据流验证

| 阶段 | 字段 | 值示例 | 来源 |
|------|------|--------|------|
| Stage 2: StrategySelection | `attack_techniques` | `["prompt_sending", "crescendo"]` | snake_case 技术名 |
| Stage 4: Datasets | `AttackPlan.attack_technique` | `"prompt_sending"` | 从 StrategySelection 传入 |
| Stage 6: Execute | `ATTACK_CLASS_MAP[technique]` | `PromptSendingAttack` | snake_case → PascalCase 映射 |
| Stage 6: AttackResult | `identifier.class_name` | `"PromptSendingAttack"` | PyRIT 原生 `get_attack_strategy_identifier()` |
| Report: `_get_attack_type()` | 从 identifier 提取 | `"PromptSendingAttack"` | `str(strategy_id).split("::")[0]` |
| Report: Timeline | `attack_technique_display` | `"prompt_sending (PromptSendingAttack)"` | `format_technique_display()` ⭐新增 |

**验证结论**: Attack Type 从 `StrategySelection` 的 snake_case 技术名，经过 `ATTACK_CLASS_MAP` 映射为 PascalCase 攻击类名，存储在 `AttackStrategyIdentifier.class_name` 中，最终在报告中通过 `format_technique_display()` 同时展示两种命名形式，消除命名不一致。

### 2.3 Converter Chain 数据流验证

| 阶段 | 字段 | 值示例 | 来源 |
|------|------|--------|------|
| Stage 5: Matching | `ctx.converter_chains` | `["stealth_evasion", "encoding_bypass"]` | Target-Aware Router 推荐 |
| Stage 4: Datasets | `AttackPlan.converter_chain_name` | `"stealth_evasion"` | 从 prompt_item.converter_chains 传入 |
| Stage 6: Execute | `extra_request_converters` | `[Base64Converter, ROT13Converter]` | `load_preset_converter_chain()` 创建 |
| Stage 6: AttackResult | `identifier.children["request_converters"]` | `[ConverterIdentifier(class_name="Base64Converter"), ...]` | PyRIT 原生 API |
| Stage 6: AttackResult | `labels["converter_chain_name"]` | `"stealth_evasion"` | 可能缺失（Adaptive 路径） |
| Report: Summary | `converter_usage` | `{"stealth_evasion": 3}` | labels → identifier 回退 ⭐增强 |
| Report: Details | `converter_chain_name` | `"stealth_evasion"` | `extract_converter_info_from_result()` ⭐新增 |
| Report: 5.6 Section | Transformation Log | 步骤表 | `ConverterTransformationLog` ⭐新增 |

**验证结论**: Converter Chain 信息从 Stage 5 的 Router 推荐链名，经 Stage 6 执行后存储在 `AttackResult.identifier.children["request_converters"]` 中（Converter 类名列表）。当 `labels` 缺失 `converter_chain_name` 时（Adaptive 路径常见），通过 `extract_converter_info_from_result()` 从 identifier.children 提取 converter 类名，并通过反向匹配恢复 chain name，实现数据流闭环。

### 2.4 Converter 信息提取回退链

```
extract_converter_info_from_result(attack_result)
    │
    ├── 1. 优先从 labels 获取
    │   labels["converter_chain_name"] → 直接返回
    │
    ├── 2. 从 identifier.children 提取
    │   identifier = attack_result.get_attack_strategy_identifier()
    │   children = identifier.children
    │   request_converters = children["request_converters"]
    │   → [ConverterIdentifier.class_name, ...]
    │   → _match_chain_by_converter_names(class_names)
    │   → 反向匹配 chain name
    │
    └── 3. SequentialAttackResult 子结果
        child_attack_results → 递归提取
```

---

## 3. 报告展示层框架设计图

### 3.1 整体架构

```
┌─────────────────────────────────────────────────────────────────────┐
│                    报告展示层 (Report Display Layer)                  │
│                                                                     │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────────┐  │
│  │  实时输出     │  │  最终报告     │  │  证据导出                 │  │
│  │  (Stage 6)   │  │  (Stage 8)   │  │  (Stage 8)               │  │
│  │              │  │              │  │                          │  │
│  │ OutputManager│  │ReportGenerator│  │EvidenceExporter          │  │
│  │              │  │              │  │                          │  │
│  │ ┌──────────┐ │  │ ┌──────────┐│  │ ┌──────────────────────┐│  │
│  │ │终端通道  │ │  │ │Markdown  ││  │ │ attacks/             ││  │
│  │ │Pretty格式│ │  │ │报告(8章) ││  │ │  attack_0001.md      ││  │
│  │ │Attack    │ │  │ │          ││  │ │  ⭐ + Conv Log       ││  │
│  │ │Summary   │ │  │ │ Ch1 Intro││  │ │ conversations/       ││  │
│  │ │+Conv Hist│ │  │ │ Ch2 Exec ││  │ │  conv_xxxx.md        ││  │
│  │ └──────────┘ │  │ │ Ch3 OWASP││  │ │ scores/              ││  │
│  │ ┌──────────┐ │  │ │ Ch4 Detail││  │ │  score_0001.md       ││  │
│  │ │文件通道  │ │  │ │ Ch5 Time ││  │ │ evidence.json        ││  │
│  │ │Markdown  │ │  │ │ Ch5.5 Hi ││  │ │ attack_summary.csv   ││  │
│  │ │全量日志  │ │  │ │ ⭐Ch5.6  ││  │ │ owasp_coverage.csv   ││  │
│  │ └──────────┘ │  │ │  Conv    ││  │ │ attack_timeline.csv  ││  │
│  │              │  │ │  Analysis││  │ └──────────────────────┘│  │
│  └──────────────┘  │ │ Ch6 MITRE││  │                          │  │
│                    │ │ Ch7 Tools││  │  → ZIP 证据包             │  │
│  原生 API:         │ │ Ch8 App  ││  │                          │  │
│  output_attack_    │ └──────────┘│  │  原生 API:               │  │
│    async()         │              │  │  MarkdownAttackResult   │  │
│  PrettyAttackResult│  → HTML/PDF  │  │    MemoryPrinter         │  │
│    Printer         │  (可选)      │  │  MarkdownConversation    │  │
│  MarkdownAttack    │              │  │    MemoryPrinter         │  │
│    ResultPrinter   │              │  │  MarkdownScorePrinter    │  │
│                    │              │  │  (render_async)          │  │
│                    │              │  │                          │  │
│                    │              │  │  ⭐ 增强:                │  │
│                    │              │  │  extract_converter_info  │  │
│                    │              │  │    _from_result()        │  │
│                    │              │  │  ConverterTransformation │  │
│                    │              │  │    Log (方案B)           │  │
│                    │              │  │  ConverterVariantPreview │  │
│                    │              │  │    (方案C)               │  │
│                    │              │  │                          │  │
│  └──────────────┘  └──────────────┘  └──────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
```

### 3.2 Markdown 报告章节结构

```
# AI Red Team Assessment Report
│
├── 1. Introduction
│   ├── Objective
│   └── Requirements
│
├── 2. Executive Summary
│   ├── Overview
│   ├── High-Level Attack Path
│   ├── Findings Summary
│   ├── Attack Summary
│   ├── Feedback Loop Statistics
│   ├── Attack Technique Distribution
│   ├── Converter Chain Usage ⭐ (增强: identifier 回退)
│   ├── Failure Analysis
│   └── Diversity & Coverage Analysis
│
├── 3. OWASP Coverage Matrix
│   ├── OWASP Top 10 for LLM Applications 2025
│   └── OWASP Top 10 for Agentic AI
│
├── 4. Detailed Findings (Attack Narrative) — 三级证据链
│   └── 4.x. Finding
│       ├── OWASP ID / Framework / Severity / CVSS
│       ├── Attack Type ⭐ (format_technique_display)
│       ├── Confidence / Description
│       ├── Indicators / Remediation
│       └── Steps to Reproduce
│           ├── Objective / Outcome / Turns / Time
│           ├── Score Details
│           ├── ⭐ Converter Chain / Converter Classes
│           └── Conversation History (完整对话)
│
├── 5. Attack Timeline
│   └── Table (# | Timestamp | Attack Type ⭐ | Objective | Outcome | Turns | Time)
│
├── 5.5 Successful Attack Highlights
│   └── 5.5.x. Successful Attack
│       ├── Attack Type ⭐ (format_technique_display)
│       ├── Score Details
│       ├── ⭐ Converter Chain / Converter Classes
│       └── Conversation History (完整对话)
│
├── 5.6 ⭐ Converter Analysis (新增)
│   ├── 方案B: Transformation Log (每条链的逐步转换)
│   │   └── 5.6.x. Transformation Log: {chain_name}
│   │       ├── Attack Type / Objective / Outcome
│   │       ├── Converter Classes
│   │       └── Step-by-Step Table
│   └── 方案C: Variant Preview Summary
│       └── Chain | Count | Description | LLM
│
├── 6. MITRE ATT&CK Mapping
│
├── 7. Tool Usage
│
└── 8. Appendix
    ├── A | Evidence Archive
    ├── B | Risk Definitions
    └── C | Configuration Summary
```

### 3.3 终端实时输出结构 (Stage 6)

```
┌─────────────────────────────────────────────────────────────────┐
│  Stage 6: Executor 执行层                                       │
│                                                                 │
│  ① 执行配置 + 攻击计划摘要                                      │
│  ② ★ 攻击载荷 × Converter 组合矩阵                              │
│     ┌─ 技术1 ─────────────────────────────────────────┐        │
│     │ ◆ snake_case (PascalCase) · 描述  ⭐命名一致性   │        │
│     │ 模式: 单轮直发 | 学术 ASR: 82% (Tier S)          │        │
│     │ ┌─ 载荷 (N 个) ─────────────────────────────┐   │        │
│     │ │ P1 (severity)                              │   │        │
│     │ │   OWASP / Source / Mode / Target           │   │        │
│     │ └───────────────────────────────────────────┘   │        │
│     │ ┌─ Converter 增强 (N 条) ────────────────────┐  │        │
│     │ │ P1 [非LLM] chain_name                       │  │        │
│     │ │     └─ 描述                                 │  │        │
│     │ └───────────────────────────────────────────┘  │        │
│     │ 执行流程: ... → 首次成功即停止                   │        │
│     └─────────────────────────────────────────────────┘        │
│  ③ ★ 执行清单 (逐载荷)                                          │
│     │ #1 P1 [OWASP] snake_case (PascalCase) Tier S ASR 82% ⭐  │
│     │     ↳ chain1 → chain2 → chain3                           │
│  ④ [OK] 开始执行...                                             │
│  ⑤ 执行结果概要                                                 │
│  ⑥ ★ 逐载荷执行结果                                             │
│     ┌─ P1 [OWASP] Tech  ✅成功/❌失败 ───────────────┐         │
│     │ Converter: Base64Converter, ROT13Converter      │         │
│     │ 评分: SUCCESS (True)                             │         │
│     │ ┌─ 攻击对话 ──────────────────────────┐         │         │
│     │ │ [USER] 原始文本                      │         │         │
│     │ │       ↳ [Converter 变换]             │         │         │
│     │ │ [ASST] 模型回复                      │         │         │
│     │ └─────────────────────────────────────┘         │         │
│     └─────────────────────────────────────────────────┘         │
│  ⑧ ★ Per-Group Breakdown (格式对齐②)                           │
│     ┌─ Tech  ✅ 82% (9/11) ─────────────────────────┐          │
│     │ ┌─ 结果统计 ──────────────────────────────┐   │          │
│     │ │ Results: 11, Success: 9, Failure: 2     │   │          │
│     │ └─────────────────────────────────────────┘   │          │
│     │ ┌─ 攻击技术 ──────────────────────────────┐   │          │
│     │ │   PromptSendingAttack                    │   │          │
│     │ └─────────────────────────────────────────┘   │          │
│     │ ┌─ Converter 变体 (2 条) ─────────────────┐   │          │
│     │ │   Base64Converter                        │   │          │
│     │ │   ROT13Converter                         │   │          │
│     │ └─────────────────────────────────────────┘   │          │
│     │ OWASP:  LLM01: Prompt Injection               │          │
│     └─────────────────────────────────────────────────┘          │
│                                                                 │
│  原生 PyRIT Attack Summary (每个攻击自动输出):                   │
│  ═════════════════════════════════════════════                    │
│  ✅ ATTACK RESULT: SUCCESS ✅                                    │
│  📋 Basic Information                                           │
│    • Objective: ...                                             │
│    • Attack Type: PromptSendingAttack  ← 从 identifier 提取      │
│    • Conversation ID: ...                                       │
│  ⚡ Execution Metrics                                           │
│  🎯 Outcome                                                     │
│  Final Score                                                    │
│  Conversation History with Objective Target                     │
│    🔹 Turn 1 - USER                                            │
│      Original: ...      ← PyRIT 原生 Converted content 展示      │
│      Converted: ...     ← 当 original ≠ converted 时显示        │
│    🔸 ASSISTANT                                                  │
│      ...                                                         │
└─────────────────────────────────────────────────────────────────┘
```

---

## 4. 方案B: Converter Transformation Log

### 4.1 设计目标

展示 Converter 链的逐步转换过程，让用户清晰看到原始文本如何经过每个 Converter 变换为最终发送给目标的文本。

### 4.2 实现原理

```
原始文本 (从 AttackResult.conversation 第一条 user 消息提取)
    │
    ▼
Converter 1 (如 Base64Converter)
    │ convert_async(prompt=原始文本)
    ▼
中间文本 1
    │
    ▼
Converter 2 (如 ROT13Converter)
    │ convert_async(prompt=中间文本1)
    ▼
中间文本 2
    │
    ▼
... (链中每个 Converter 依次应用)
    │
    ▼
最终文本 (发送给目标的内容)
```

### 4.3 类设计

```python
class ConverterTransformationLog:
    """Converter 转换日志 — 后处理重转换"""

    def __init__(self, chain_name: str, converter_target: Any = None):
        self.chain_name = chain_name
        self.converter_target = converter_target

    async def generate_log(self, original_text: str) -> List[Dict[str, Any]]:
        """生成转换日志"""
        # 1. 加载 chain 配置，创建 converter 实例
        # 2. 依次应用每个 converter
        # 3. 记录每步的输入/输出
        # 返回: [{step, converter_name, converter_class, requires_llm,
        #         input_text, output_text, skipped}, ...]

    async def generate_log_from_result(self, attack_result: Any) -> List[Dict[str, Any]]:
        """从 AttackResult 提取原始文本并生成转换日志"""
        # 1. 从 conversation 提取第一条 user 消息的 original_value
        # 2. 调用 generate_log()
```

### 4.4 输出示例

**Markdown 报告中的 Transformation Log:**

```markdown
### 5.6.1 Transformation Log: stealth_evasion

- **Attack Type**: prompt_sending (PromptSendingAttack)
- **Objective**: Give step-by-step instructions for picking a lock
- **Outcome**: SUCCESS
- **Converter Classes**: Base64Converter, ROT13Converter, SuffixAppendConverter

*Transformation log shows the step-by-step conversion process.
Each step represents one converter in the chain applied sequentially.*

| Step | Converter | Description |
|------|-----------|-------------|
| 1 | Base64Converter | Applied sequentially |
| 2 | ROT13Converter | Applied sequentially |
| 3 | SuffixAppendConverter | Applied sequentially |

*Note: Full transformation log with intermediate text outputs
is available in the evidence archive (per-attack Markdown files).*
```

**Per-attack Markdown 中的 Transformation Log:**

```markdown
## Converter Transformation Log: `stealth_evasion`

- **Converter Classes**: Base64Converter, ROT13Converter, SuffixAppendConverter

| Step | Converter Class |
|------|----------------|
| 1 | Base64Converter |
| 2 | ROT13Converter |
| 3 | SuffixAppendConverter |

*Full transformation log with intermediate text outputs is generated
via post-processing re-conversion.*
```

### 4.5 技术约束

| 约束 | 处理方式 |
|------|----------|
| 非 LLM Converter (Base64/ROT13/Caesar 等) | 确定性执行，无 API 调用 |
| LLM Converter (Persuasion/Decomposition 等) | 需要 `converter_target`，缺失时标注 "requires LLM" |
| PyRIT 核心执行路径 | 不修改，纯后处理重转换 |
| 原始文本来源 | `AttackResult.conversation` 第一条 user 消息的 `original_value` |

---

## 5. 方案C: Converter Variant Preview

### 5.1 设计目标

对一组 Converter chain，分别展示每条链对原始文本的最终转换效果，便于用户快速比较不同变体的效果差异。

### 5.2 实现原理

```
原始文本
    ├──→ Chain 1 (stealth_evasion)     → 最终输出 1
    ├──→ Chain 2 (encoding_bypass)     → 最终输出 2
    ├──→ Chain 3 (multi_encoding_v2)   → 最终输出 3
    └──→ Chain N (...)                  → 最终输出 N
```

### 5.3 类设计

```python
class ConverterVariantPreview:
    """Converter 变体预览 — 多链效果对比"""

    def __init__(self, chain_names: List[str], converter_target: Any = None):
        self.chain_names = chain_names
        self.converter_target = converter_target

    async def generate_preview(self, original_text: str) -> List[Dict[str, Any]]:
        """生成变体预览"""
        # 对每条 chain:
        # 1. 创建 ConverterTransformationLog
        # 2. 执行完整链
        # 3. 提取最终输出
        # 返回: [{chain_name, description, requires_llm,
        #         final_output, steps_count, skipped}, ...]
```

### 5.4 输出示例

**Markdown 报告中的 Variant Preview Summary:**

```markdown
### Converter Variant Preview Summary

The following converter chains were available and used during the assessment:

| Chain | Count | Description |
|-------|-------|-------------|
| stealth_evasion | 5 | Unicode 混淆 + Base64 + 后缀追加 |
| encoding_bypass | 3 | Base64 + ROT13 + Caesar 编码绕过 |
| multi_encoding_v2 | 2 | 四层编码: Base64 + ROT13 + Caesar(5) + Atbash |
| persuasion_authority [LLM] | 1 | 权威说服: authority_endorsement + formal + en |

*Variant previews with actual text transformations are available in
the evidence archive for each attack.*
```

---

## 6. 命名一致性: snake_case ↔ PascalCase

### 6.1 问题

| 位置 | 命名风格 | 示例 |
|------|----------|------|
| StrategySelection / AttackPlan | snake_case | `prompt_sending` |
| AttackResult.identifier | PascalCase | `PromptSendingAttack` |
| 报告 Attack Timeline | 原来混用 | `PromptSendingAttack` 或 `unknown` |
| 终端预执行展示 | 原来仅 snake_case | `prompt_sending` |

### 6.2 解决方案

```python
# src/reporting/converter_log.py

TECHNIQUE_NAME_MAP: Dict[str, str] = {
    "prompt_sending": "PromptSendingAttack",
    "multi_prompt_sending": "MultiPromptSendingAttack",
    "many_shot": "ManyShotJailbreakAttack",
    "skeleton": "SkeletonKeyAttack",
    "chunked_request": "ChunkedRequestAttack",
    "red_teaming": "RedTeamingAttack",
    "crescendo": "CrescendoAttack",
    "crescendo_simulated": "CrescendoAttack",
    "tap": "TAPAttack",
    "pair": "PAIRAttack",
    "tree_of_attacks_pruned": "TreeOfAttacksWithPruningAttack",
    "sequential": "SequentialAttack",
}

def format_technique_display(technique_name: str) -> str:
    """格式化技术名显示: 'prompt_sending (PromptSendingAttack)'"""
    class_name = get_attack_class_name(technique_name)
    if class_name != technique_name:
        return f"{technique_name} ({class_name})"
    return technique_name
```

### 6.3 应用位置

| 位置 | 文件 | 效果 |
|------|------|------|
| 终端攻击执行矩阵 | `s6_execute.py` `_display_unified_attack_matrix` | `◆ prompt_sending (PromptSendingAttack) · 描述` (v7.0 合并了旧执行清单) |
| 报告 Attack Timeline | `report_generator.py` | Timeline 表格中 Attack Type 列显示双命名 |
| 报告 Success Highlights | `report_generator.py` | `**Attack Type**: prompt_sending (PromptSendingAttack)` |
| 报告 Detailed Findings | `report_generator.py` | Step 详情中包含 `attack_technique_display` |

---

## 7. 报告增强: identifier.children 提取 Converter 信息

### 7.1 问题

在 Adaptive 执行路径中，`AttackResult.labels` 可能不包含 `converter_chain_name`（因为 Converter 变体是通过 `extra_request_converters` 动态追加的，labels 在 Scenario 层设置时可能遗漏此字段）。

### 7.2 解决方案

```python
def extract_converter_info_from_result(attack_result: Any) -> Dict[str, Any]:
    """从 AttackResult 提取 Converter 信息（三级回退）"""

    # 1. 优先从 labels 获取
    labels = getattr(attack_result, "labels", {})
    chain_name = labels.get("converter_chain_name")
    if chain_name:
        return {"converter_chain_name": chain_name, ...}

    # 2. 从 identifier.children 提取
    identifier = attack_result.get_attack_strategy_identifier()
    class_names = _extract_converter_class_names_from_identifier(identifier)
    # → ["Base64Converter", "ROT13Converter", ...]

    # 3. 反向匹配 chain name
    chain_name = _match_chain_by_converter_names(class_names)
    # 遍历 CONVERTER_VARIANT_CHAINS，加载每个 chain 的 YAML 配置，
    # 比较 converter 类名集合是否匹配

    return {
        "converter_class_names": class_names,
        "converter_chain_name": chain_name,
        "has_converters": bool(class_names),
    }
```

### 7.3 数据流

```
AttackResult
    │
    ├── labels["converter_chain_name"] ──→ 直接使用 (最优)
    │
    ├── get_attack_strategy_identifier()
    │       │
    │       ├── .children["request_converters"]
    │       │       │
    │       │       └── [ConverterIdentifier.class_name, ...]
    │       │               │
    │       │               └── _match_chain_by_converter_names()
    │       │                       │
    │       │                       ├── 遍历 CONVERTER_VARIANT_CHAINS
    │       │                       ├── 加载每个 chain 的 YAML 配置
    │       │                       ├── 比较 converter 类名集合
    │       │                       └── 返回匹配的 chain_name
    │       │
    │       └── .children["response_converters"] (如有)
    │
    └── child_attack_results (SequentialAttackResult)
            │
            └── 递归提取子结果
```

### 7.4 应用位置

| 位置 | 用途 |
|------|------|
| `_generate_summary()` | 统计 `converter_usage` 时 labels 缺失则回退 |
| `_collect_attack_details()` | 每个 attack detail 包含 converter 信息 |
| `_export_attack_markdowns()` | Per-attack Markdown 追加 Transformation Log |
| 报告 Section 5.6 | Converter Analysis 章节使用 |
| 报告 Section 4 | Steps to Reproduce 展示 Converter Chain/Classes |
| 报告 Section 5.5 | Successful Attack Highlights 展示 Converter 信息 |

---

## 8. 三级证据链架构

```
Level 1: OWASP Finding (漏洞发现)
    │
    ├── owasp_id / severity / cvss_score
    ├── attack_type / confidence
    ├── indicators / remediation
    └── evidence_ids → 关联到 Level 2
            │
            ▼
Level 2: AttackResult (攻击结果)
    │
    ├── objective / outcome / outcome_reason
    ├── executed_turns / execution_time_ms
    ├── score (value / type / category / rationale)
    ├── ⭐ converter_chain_name / converter_class_names
    ├── ⭐ attack_technique_display (snake_case + PascalCase)
    └── conversation_id → 关联到 Level 3
            │
            ▼
Level 3: Conversation History (完整对话)
    │
    ├── [USER] 原始/转换后文本
    ├── [ASSISTANT] 模型回复
    ├── [USER] 后续追问 (多轮)
    ├── [ASSISTANT] 后续回复
    └── Scores (每轮评分)
```

---

## 9. 原生 PyRIT output 集成

### 9.1 使用的原生 API

| API | 用途 | 位置 |
|-----|------|------|
| `output_attack_async()` | 单个攻击结果双通道输出 | `OutputManager` |
| `output_scenario_async()` | 场景级摘要输出 | `ReportGenerator` |
| `output_scorer_async()` | 评分器评估指标 | `ReportGenerator` |
| `PrettyAttackResultPrinter` | 终端 Pretty 格式 | `output_attack_async(format="pretty")` |
| `MarkdownAttackResultMemoryPrinter` | Markdown 格式 (render_async) | `EvidenceExporter` |
| `MarkdownConversationMemoryPrinter` | 对话 Markdown (render_async) | `EvidenceExporter` |
| `MarkdownScorePrinter` | 评分 Markdown (render_async) | `EvidenceExporter` |
| `StdoutSink` | 终端输出 Sink | `OutputManager` |
| `FileSink` | 文件输出 Sink | `OutputManager` |
| `get_default_sink()` | 环境自动检测 | `OutputManager` |
| `AttackResult.get_attack_strategy_identifier()` | 提取技术名+Converter | `converter_log.py` |
| `ComponentIdentifier.children` | 提取 Converter 子组件 | `converter_log.py` |
| `Converter.convert_async()` | 后处理重转换 | `ConverterTransformationLog` |

### 9.2 原生 Attack Summary 格式

PyRIT 原生 `PrettyAttackResultPrinter` 自动生成以下内容:

```
════════════════════════════════════════════════════════════════
                     ✅ ATTACK RESULT: SUCCESS ✅
════════════════════════════════════════════════════════════════

 Attack Summary
────────────────────────────────────────────────────────────────
  📋 Basic Information
    • Objective: ...
    • Attack Type: PromptSendingAttack  ← 从 identifier.class_name 提取
    • Conversation ID: ...

  ⚡ Execution Metrics
    • Turns Executed: 1
    • Execution Time: 18.76s

  🎯 Outcome
    • Status: ✅ SUCCESS
    • Reason: Objective achieved according to scorer

  Final Score
    Scorer: TrueFalseInverterScorer
    • Category: ['refusal']
    • Type: true_false
    • Value: True
    • Rationale: ...

 Conversation History with Objective Target
────────────────────────────────────────────────────────────────
🔹 Turn 1 - USER
  Original: ...       ← 当 original ≠ converted 时显示
  Converted: ...      ← PyRIT 原生 Converted content 展示

🔸 ASSISTANT
  ...
```

**关键**: `Attack Type` 的值来自 `result.get_attack_strategy_identifier().class_name`，这是 PascalCase 攻击类名，由 `ATTACK_CLASS_MAP` 在创建 Attack 实例时确定，数据流完全可追溯。

---

## 10. 文件变更清单

### 10.1 新增文件

| 文件 | 描述 |
|------|------|
| `src/reporting/converter_log.py` | Converter 转换日志 + 变体预览 + 命名映射 + identifier 提取 |
| `docs/report_display_framework.md` | 本文档 |

### 10.2 修改文件

| 文件 | 变更内容 |
|------|----------|
| `src/reporting/report_generator.py` | 导入 converter_log 模块; `_generate_summary()` 增强 converter 信息提取; `_collect_attack_details()` 增加 converter/technique_display 字段; `_render_markdown_report()` 新增 Section 5.6 Converter Analysis; Steps to Reproduce/Success Highlights 增加 Converter 信息; Timeline 使用 format_technique_display; `_export_attack_markdowns()` 追加 Transformation Log |
| `src/reporting/__init__.py` | 导出 converter_log 模块的 12 个公共 API |
| `pipeline/stages/s6_execute.py` | 导入 format_technique_display; 组合矩阵和执行清单使用双命名展示 |

### 10.3 新增公共 API

```python
# src/reporting/converter_log.py

# 命名映射
TECHNIQUE_NAME_MAP: Dict[str, str]           # snake_case → PascalCase
get_attack_class_name(technique_name: str)   # → PascalCase
get_technique_name(class_name: str)           # → snake_case
format_technique_display(technique_name: str) # → "snake_case (PascalCase)"

# Converter 信息提取
extract_converter_info_from_result(ar)        # → {converter_chain_name, converter_class_names, has_converters}

# 方案B: 转换日志
ConverterTransformationLog(chain_name, converter_target)
    .generate_log(original_text)              # → [step dicts]
    .generate_log_from_result(attack_result)  # → [step dicts]

# 方案C: 变体预览
ConverterVariantPreview(chain_names, converter_target)
    .generate_preview(original_text)          # → [preview dicts]

# 便捷函数
generate_converter_log_for_result(ar, converter_target)
generate_variant_preview_for_technique(tech, text, converter_target, target_type)

# Markdown 渲染
render_transformation_log_markdown(steps, chain_name)
render_variant_preview_markdown(previews, original_text)
```

---

## 附录: 数据流闭环验证检查表

| # | 数据项 | 生成阶段 | 传递路径 | 展示位置 | 闭环状态 |
|---|--------|----------|----------|----------|----------|
| 1 | Attack Type (snake_case) | Stage 2 | StrategySelection → AttackPlan → ATTACK_CLASS_MAP | 报告 Timeline + 终端展示 | ✅ 闭环 |
| 2 | Attack Type (PascalCase) | Stage 6 | identifier.class_name → _get_attack_type() | 原生 Attack Summary + 报告 | ✅ 闭环 |
| 3 | 命名一致性 | — | format_technique_display() | 终端 + 报告 (双命名) | ✅ ⭐新增 |
| 4 | Converter Chain (labels) | Stage 6 | labels["converter_chain_name"] | 报告 Summary + Details | ✅ 闭环 |
| 5 | Converter Chain (identifier) | Stage 6 | identifier.children["request_converters"] | 报告 Details + 5.6 | ✅ ⭐新增 |
| 6 | Converter Chain (反向匹配) | Report | _match_chain_by_converter_names() | 报告 Summary (回退) | ✅ ⭐新增 |
| 7 | Converter 类名列表 | Stage 6 | ConverterIdentifier.class_name | 报告 Details + 5.6 + 终端 | ✅ ⭐新增 |
| 8 | Transformation Log | Report | ConverterTransformationLog.generate_log() | 报告 5.6 + per-attack MD | ✅ ⭐新增 |
| 9 | Variant Preview | Report | ConverterVariantPreview.generate_preview() | 报告 5.6 | ✅ ⭐新增 |
| 10 | OWASP ID | Stage 4 | AttackPlan.owasp_id → labels["owasp_id"] | 报告 3 + Per-Group | ✅ 闭环 |
| 11 | Conversation History | Stage 6 | AttackResult.conversation → memory | 原生 Attack Summary + 报告 | ✅ 闭环 |
| 12 | Score | Stage 6 | AttackResult.last_score | 原生 Attack Summary + 报告 | ✅ 闭环 |
| 13 | Execution Metrics | Stage 6 | AttackResult.executed_turns/execution_time_ms | 原生 Attack Summary + 报告 | ✅ 闭环 |
