# Datasets 子系统架构文档

> 对齐 `pyrit.datasets` + `pyrit.models` — PyRIT 1.0.0 完整五层数据驱动架构
> 含当前代码与官方标准差距分析

---

## 目录

1. [架构概览](#1-架构概览)
2. [目录结构](#2-目录结构)
3. [各层详细设计](#3-各层详细设计)
4. [数据流全景](#4-数据流全景)
5. [配置说明](#5-配置说明)
6. [与 Executor 子系统的衔接](#6-与-executor-子系统的衔接)
7. [开发规则](#7-开发规则)
8. [当前代码与官方标准差距分析](#8-当前代码与官方标准差距分析)
9. [差距优先级排序与建议路线图](#9-差距优先级排序与建议路线图)

---

## 1. 架构概览

```
┌─────────────────────────────────────────────────────────────────────────┐
│                     DATASETS 子系统（完整五层 + ②.5）                      │
│                                                                         │
│  核心不变量 🟢：数据驱动 — 所有攻击数据通过五层架构流转                      │
│  核心对象 🟢：SeedDataset → SeedGroup → AttackSeedGroup → AttackResult    │
│  管道设计 🔵：CentralMemory 数据枢纽 + 多维查询 + 交互式选择                  │
│                                                                         │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │  ① 数据准备层 🟢                                                   │  │
│  │  "多种数据源 → SeedDataset → CentralMemory"                        │  │
│  │  → DatasetManager, PayloadSourceLoader, OwaspLocalDatasetProvider  │  │
│  └────────────────────────────┬──────────────────────────────────────┘  │
│  ┌────────────────────────────┴──────────────────────────────────────┐  │
│  │  ② 数据管理层 🟢                                                   │  │
│  │  "CentralMemory 作为数据枢纽 — 规范化、去重、多维查询"                │  │
│  │  → CentralMemory.add_seed_datasets_to_memory_async()              │  │
│  │  → CentralMemory.get_seed_groups() / get_seeds()                 │  │
│  └────────────────────────────┬──────────────────────────────────────┘  │
│  ┌────────────────────────────┴──────────────────────────────────────┐  │
│  │  ②.5 交互式选择层 🟢 (自研增强 — 三层渐进式)                         │  │
│  │  "CentralMemory → TargetProfileRouter → ASRRankBuilder → Wizard"    │  │
│  │  Layer 1: TargetProfileRouter (目标类型 → OWASP 映射)               │  │
│  │  Layer 2: ASRRankBuilder (ASR 分层排序 + 启发式代理)                │  │
│  │  Layer 3: TieredSelectionWizard (三层交互 + 降级策略选择)           │  │
│  │  Legacy:  SeedGroupSelector (向后兼容)                             │  │
│  └────────────────────────────┬──────────────────────────────────────┘  │
│  ┌────────────────────────────┴──────────────────────────────────────┐  │
│  │  ③ 攻击准备层 🟢                                                   │  │
│  │  "SeedGroup → AttackSeedGroup — 原生 from_seed_group_async 提取"    │  │
│  │  → AttackPreparator (prepare / prepare_batch / select_technique)  │  │
│  └────────────────────────────┬──────────────────────────────────────┘  │
│  ┌────────────────────────────┴──────────────────────────────────────┐  │
│  │  ③→④ 桥接层 🟡                                                    │  │
│  │  "AttackSeedGroup ↔ PromptBatch 双向适配 (兼容管道)"                │  │
│  │  → SeedPromptAdapter (dataset_to_batches / seed_groups_to_batches) │  │
│  │  → PayloadPlanner (plan_attacks → AttackPlan[])                   │  │
│  └────────────────────────────┬──────────────────────────────────────┘  │
│  ┌────────────────────────────┴──────────────────────────────────────┐  │
│  │  ④ 攻击执行层 (→ Executor 子系统)                                   │  │
│  │  "AttackPlan → execute_batch_attacks → BatchAttackResult"         │  │
│  └────────────────────────────┬──────────────────────────────────────┘  │
│  ┌────────────────────────────┴──────────────────────────────────────┐  │
│  │  ⑤ 评估与追踪层 (→ Scorer + Memory)                                │  │
│  │  "Scorer + PyRIT Memory 审计链"                                    │  │
│  └───────────────────────────────────────────────────────────────────┘  │
│                                                                         │
│  横切组件 🟢：                                                          │
│  ┌──────────────────┐ ┌──────────────────┐ ┌──────────────────┐        │
│  │SeedGroupBuilder  │ │SeedPromptAdapter │ │OwaspLocalProvider │        │
│  │(AttackPlan→      │ │(SeedDataset↔     │ │(_LocalDataset     │        │
│  │ AttackSeedGroup) │ │ PromptBatch)     │ │ Loader 桥接)      │        │
│  └──────────────────┘ └──────────────────┘ └──────────────────┘        │
│                                                                         │
│  数据目录：                                                              │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐                                │
│  │data/owasp│ │data/custom│ │PyRIT远程  │                                │
│  │/llm/     │ │/*.yaml   │ │60+ Provider│                                │
│  │/agentic/ │ │          │ │           │                                │
│  └──────────┘ └──────────┘ └──────────┘                                │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 2. 目录结构

```
src/payloads/                               ← Datasets 子系统核心
├── __init__.py                             ← 顶层统一导出
│
├── models.py                               ← 数据模型 (PromptItem, PromptBatch, AttackPlan)
│
├── source_loader.py                        ← ① 数据准备层 (兼容管道)
├── dataset_manager.py                      ← ①② 数据准备+管理层 (推荐管道)
├── owasp_provider.py                       ← ① OWASP 本地数据集 Provider 桥接
│
├── seed_selector.py                        ← ②.5 交互式选择层 (旧版兼容)
├── target_profile_router.py                ← ②.5 Layer 1: 目标类型→OWASP映射
├── asr_rank_builder.py                     ← ②.5 Layer 2: ASR分层排序+启发式
├── tiered_selection_wizard.py              ← ②.5 Layer 3: 三层渐进式交互
├── group_fallback_executor.py              ← ④增强: 组级ASR降级链
├── attack_preparator.py                    ← ③ 攻击准备层
├── seed_adapter.py                         ← ③→④ 桥接适配器
├── planner.py                              ← ④ 载荷规划器 (兼容管道)
│
└── (src/executor/attack/component/
    └── seed_group_builder.py)              ← 横切: AttackSeedGroup 构建

data/                                       ← 数据目录
├── owasp/                                  ← OWASP 本地数据集
│   ├── llm/                                ← OWASP Top 10 for LLM
│   │   ├── _registry.yaml                  ← 框架元数据注册表
│   │   ├── llm01/direct_injection.yaml
│   │   ├── llm02/memory_extraction.yaml
│   │   ├── ...
│   │   └── llm10/resource_exhaustion.yaml
│   └── agentic/                            ← OWASP Top 10 for Agentic AI
│       ├── _registry.yaml
│       ├── asi01/goal_hijack.yaml
│       ├── ...
│       └── asi10/rogue_agent.yaml
├── custom/                                 ← 自定义数据集 (含考试快速启动载荷)
│   └── exam_quickstart.yaml                ← AI-300 考试快速启动载荷
└── burp/                                   ← Burp Suite 请求样本
```

---

## 3. 各层详细设计

### ① 数据准备层 — `dataset_manager.py` + `source_loader.py`

| 模块 | 对齐 PyRIT 原生 | 功能 |
|:--|:--|:--|
| `dataset_manager.py` | `pyrit.datasets.SeedDatasetProvider` + `pyrit.memory.CentralMemory` | CentralMemory 数据枢纽（推荐管道） |
| `source_loader.py` | `pyrit.datasets.SeedDatasetProvider` + `pyrit.models.SeedDataset` | PromptBatch 加载器（兼容管道） |
| `owasp_provider.py` | `pyrit.datasets.seed_datasets.local._LocalDatasetLoader` | OWASP YAML 注册为原生 Provider |

**核心 API（推荐管道）**:
```python
from src.payloads import DatasetManager

manager = DatasetManager()

# ①→② 自由组合数据源
await manager.load_datasets(
    owasp=True,                    # OWASP 本地 YAML
    owasp_frameworks=["llm", "agentic"],
    owasp_ids=["LLM01"],          # 可选筛选
    custom=True,                   # 自定义 YAML
    remote=False,                  # PyRIT 60+ 远程数据集
    remote_dataset_names=["harmbench"],
)
```

**核心 API（兼容管道）**:
```python
from src.payloads import load_all_payloads_async

batches = await load_all_payloads_async(
    owasp_ids=None,
    include_custom=True,
    include_remote=False,
    remote_dataset_names=["harmbench"],
)
# → List[PromptBatch]
```

**数据源**:

| 数据源 | 目录/API | 加载方式 | 说明 |
|:--|:--|:--|:--|
| OWASP 本地 (LLM) | `data/owasp/llm/llm01-llm10/` | `SeedDataset.from_yaml_file()` | OWASP Top 10 for LLM 2025 |
| OWASP 本地 (Agentic) | `data/owasp/agentic/asi01-asi10/` | `SeedDataset.from_yaml_file()` | OWASP Top 10 for Agentic AI |
| 自定义 | `data/custom/*.yaml` | `SeedDataset.from_yaml_file()` | 用户自定义载荷 + 考试快速启动载荷 |
| PyRIT 远程 | `SeedDatasetProvider` | `fetch_datasets_async()` | 100+ 远程数据集 |

### ② 数据管理层 — `CentralMemory`

| 维度 | 说明 |
|:--|:--|
| 数据枢纽 | `CentralMemory` 作为唯一数据来源 |
| 入口 | `memory.add_seed_datasets_to_memory_async(datasets, added_by)` |
| 查询 | `memory.get_seed_groups()` / `memory.get_seeds()` |
| 去重 | 基于 `value_sha256` 自动去重 |
| 审计 | `added_by` 标签追踪数据来源 |

**查询参数**（全部透传 PyRIT 原生 API）:

| 参数 | 类型 | 说明 |
|:--|:--|:--|
| `harm_categories` | Sequence[str] | 危害类别过滤 |
| `dataset_name` | str | 精确匹配 |
| `dataset_name_pattern` | str | SQL LIKE 模式匹配 |
| `added_by` | str | 添加者过滤 |
| `authors` | Sequence[str] | 作者过滤 |
| `groups` | Sequence[str] | 组过滤 |
| `source` | str | 来源过滤 |
| `seed_type` | str | 类型过滤 |
| `metadata` | dict | 元数据过滤 |
| `group_length` | Sequence[int] | 组内数量过滤 |

### ②.5 交互式选择层 — 三层渐进式披露系统 (自研增强)

#### ②.5 架构概览

```
CentralMemory.get_seed_groups()
    ↓
┌───────────────────────────────────────────────────────────────┐
│  Layer 1: TargetProfileRouter   (目标类型 → OWASP 映射)        │
│  8 选项: LLM Direct / Agent / RAG / MCP / VectorDB / Safety   │
│         / WebOutput / Full Sweep                               │
│  + 能力自动推断 (chat/tool/memory/retrieval → target_type)     │
└───────────────────────────┬───────────────────────────────────┘
┌───────────────────────────┴───────────────────────────────────┐
│  Layer 2: ASRRankBuilder        (ASR 分层排序 + 启发式代理)     │
│  Tier S (≥80%) → Tier A (50-80%) → Tier B (30-50%) → C → D    │
│  无 ASR 数据 → 启发式代理 (difficulty/evasion/mode 加权)       │
└───────────────────────────┬───────────────────────────────────┐
┌───────────────────────────┴───────────────────────────────────┐
│  Layer 3: TieredSelectionWizard (交互确认 + 降级策略选择)      │
│  3 选项: Sequential ASR-desc / Parallel / Adaptive             │
└───────────────────────────┬───────────────────────────────────┘
    ↓ List[SeedGroup] + FallbackStrategy
```

**724 → 3 决策点效果**: Layer 1 (8选项) + Layer 2 (5-10推荐) + Layer 3 (3选项) = ~18选项

#### Layer 1: TargetProfileRouter — `target_profile_router.py`

| 功能 | API | 说明 |
|:--|:--|:--|
| 目标类型映射 | `get_profile(TargetType.AGENT)` | → OWASP ASI01-10 |
| 能力推断 | `infer_profile(capabilities=...)` | chat/tool/memory → agent |
| OWASP 提示推断 | `infer_profile(owasp_hint="LLM04")` | → RAG |
| 种子组过滤 | `filter_seed_groups(groups, profile)` | 按目标类型过滤 |
| 菜单构建 | `get_target_options(groups)` | 含 group/seed 计数的选项列表 |

**TargetType 枚举**: `LLM_DIRECT` / `AGENT` / `RAG` / `MCP_TOOL` / `VECTOR_DB` / `LLM_SAFETY` / `WEB_OUTPUT` / `FULL_SWEEP`

**TargetType → OWASP 映射**:

| 目标类型 | OWASP 类别 | 攻击场景 |
|:--|:--|:--|
| `LLM_DIRECT` | LLM01,02,03,07 | 直接 LLM 越狱/泄露/注入 |
| `AGENT` | ASI01-10 | Agent 目标劫持/工具误用/信任 |
| `RAG` | LLM04 | RAG 投毒/间接注入 |
| `MCP_TOOL` | LLM06 | MCP 工具投毒/能力混淆 |
| `VECTOR_DB` | LLM08 | 向量注入/嵌入反转 |
| `LLM_SAFETY` | LLM09,10 | 幻觉/资源耗尽 |
| `WEB_OUTPUT` | LLM05 | XSS/不安全输出 |
| `FULL_SWEEP` | All | 全覆盖 |

#### Layer 2: ASRRankBuilder — `asr_rank_builder.py`

| 功能 | API | 说明 |
|:--|:--|:--|
| 排序构建 | `build_ranked_groups(seed_groups)` | 按有效分数降序排列 |
| 降级链构建 | `build_fallback_chain(ranked)` | S→A→B→C→D 分层列表 |
| Top-N 选择 | `get_top_n(ranked, n=5, min_tier=S)` | 取前 N 个组 |
| 分层统计 | `get_tier_summary(ranked)` | 各层组/种子数统计 |

**ASR 分层体系**:

| Tier | ASR 范围 | 优先级 | 说明 |
|:--|:--|:--|:--|
| S | ≥80% | 100 | 近乎成功，首选 |
| A | 50-80% | 80 | 高成功率，首选降级 |
| B | 30-50% | 60 | 中等，次级降级 |
| C | 15-30% | 40 | 低，最后手段 |
| D | <15% | 20 | 极低，默认跳过 |
| UNKNOWN | 无数据 | 50 | 启发式代理排序 |

**启发式代理排序** (无 ASR 数据时):
```
heuristic_score = avg(difficulty_weight) * 10
                + avg(evasion_weight) * 10
                + avg(mode_weight) * 10
  difficulty: easy(3) > medium(2) > hard(1)
  evasion:   high(3) > medium(2) > low(1)
  mode:      single_turn(3) > converter(2.5) > sequential(2) > multi_turn(1.5)
```

#### Layer 3: TieredSelectionWizard — `tiered_selection_wizard.py`

| 功能 | API | 说明 |
|:--|:--|:--|
| 三层选择 | `wizard.select(seed_groups)` | → TieredSelectionResult |
| 预设模式 | `SelectionPreset(target_type=AGENT, top_n=3)` | 非交互自动选择 |
| 全自动 | `TieredSelectionWizard(enabled=False)` | 全选 + 默认策略 |

**FallbackStrategy 枚举**:

| 策略 | 说明 | 适用场景 |
|:--|:--|:--|
| `SEQUENTIAL_ASR_DESC` | S→A→B→C 逐层执行，首次成功停止 | 考试安全 (默认) |
| `PARALLEL` | 全部组并行执行 | 最快 |
| `ADAPTIVE` | 顺序执行 + FailureTypeRoutingSelector 升级 | 智能升级 |

**TieredSelectionResult**: `selected_groups` + `fallback_strategy` + `fallback_chain` + `target_profile`

#### ④ 增强: GroupFallbackExecutor — `group_fallback_executor.py`

| 功能 | API | 说明 |
|:--|:--|:--|
| 组级降级执行 | `execute_with_fallback(plans, chain, strategy, ...)` | → FallbackExecutionResult |
| 计划分区 | `_partition_plans(plans, chain)` | 按技术组分区 |

**设计原则**: 组级降级（非种子级）—— 同一技术组失败后切换技术原理，而非同原理变体

#### 旧版兼容: SeedGroupSelector — `seed_selector.py`

| 功能 | API | 说明 |
|:--|:--|:--|
| 目录构建 | `build_catalog(seed_groups)` | 从 SeedGroup 列表构建 SeedGroupEntry |
| 终端展示 | `display(catalog)` | 表格化展示种子组目录 |
| 多维过滤 | `filter_by_owasp/harm/mode/severity` | 按 OWASP ID/危害/模式/严重度过滤 |
| 交互选择 | `prompt_user(catalog)` | 终端交互界面选择 |
| 预设选择 | `preset_owasp/preset_modes` | 脚本模式非交互选择 |

> **配置控制**: `tiered_selection.enabled: false` 时回退到旧版 SeedGroupSelector，零影响

### ③ 攻击准备层 — `attack_preparator.py`

| 功能 | API | 说明 |
|:--|:--|:--|
| 单个转换 | `prepare(seed_group)` | SeedGroup → AttackSeedGroup |
| 批量转换 | `prepare_batch(seed_groups)` | List[SeedGroup] → List[AttackSeedGroup] |
| 条件分派 | `select_attack_technique(group)` | 推荐攻击技术 |
| 多轮判定 | `is_multi_turn(group)` | 是否多轮攻击 |
| 单轮判定 | `is_single_turn(group)` | 是否单轮攻击 |

**条件分派逻辑** (不可变):

```
有 prepended_conversation → "crescendo" (多轮渐进)
有 next_message           → "prompt_sending" (单轮直接)
无 next_message           → "red_teaming" (目标导向)
```

**合成 Objective**: 为无 objective 的种子组自动创建合成 objective（从第一个 prompt 的 value 提取）。

### ③→④ 桥接层 — `seed_adapter.py` + `planner.py`

| 模块 | 功能 |
|:--|:--|
| `seed_adapter.py` | PyRIT SeedDataset ↔ PromptBatch 双向适配器 |
| `planner.py` | PromptBatch → AttackPlan 载荷规划器 |

**SeedPromptAdapter 核心 API**:

| 方法 | 方向 | 说明 |
|:--|:--|:--|
| `dataset_to_batches(dataset)` | SeedDataset → PromptBatch | 使用原生 `dataset.seed_groups` 分组 |
| `seed_groups_to_batches(groups)` | SeedGroup[] → PromptBatch | 桥接 CentralMemory → 兼容管道 |
| `remote_datasets_to_batches(datasets)` | SeedDataset[] → PromptBatch | 批量远程数据集转换 |
| `item_to_objective(item)` | PromptItem → SeedObjective | 反向转换（写入 Memory） |
| `items_to_dataset(items)` | PromptItem[] → SeedDataset | 反向转换（导出原生格式） |
| `create_simulated_conversation_objective(...)` | → SeedSimulatedConversation | 编程创建模拟对话配置 |

**PayloadPlanner 核心 API**:

| 方法 | 说明 |
|:--|:--|
| `plan_attacks(batches, strategy_selection)` | PromptBatch → AttackPlan[] |
| `enhance_with_jailbreak(batches, ...)` | TextJailBreak 模板增强 |
| `_select_attack_technique(item, meta, pool)` | 智能技术选择 |
| `_auto_match_sequential_steps(item, meta)` | 顺序攻击步骤自动匹配 |
| `_calculate_priority(item, meta)` | 优先级计算 (0-100) |

---

## 4. 数据流全景

### 4.1 推荐管道（CentralMemory 驱动）

```
① DatasetManager.load_datasets()
    ↓ datasets → CentralMemory
② CentralMemory.get_seed_groups()
    ↓ Sequence[SeedGroup] (如 72 个)
②.5 SeedGroupSelector
    ├─ build_catalog()     → List[SeedGroupEntry]
    ├─ display()           → 终端表格
    ├─ filter_by_*()       → 过滤子集
    ├─ prompt_user()       → 用户交互
    └─ select()            → List[SeedGroup] (用户选中)
        ↓ selected_groups
③ AttackPreparator.prepare_batch(selected_groups)
    ↓ List[AttackSeedGroup]
    ├─ .objective           → SeedObjective
    ├─ .next_message        → Message | None
    └─ .prepended_conversation → list[Message] | None
        ↓
    NativeAttackExecutor.execute_attack_from_seed_groups_async()
        ↓ AttackResult[]
⑤ Scorer + Memory 审计链
```

### 4.2 兼容管道（PromptBatch 驱动）

```
① load_all_payloads_async()
    ↓ List[PromptBatch]
③→④ SeedPromptAdapter + PayloadPlanner
    ├─ seed_groups_to_batches()  → List[PromptBatch]
    └─ plan_attacks()            → List[AttackPlan]
        ↓
    ScenarioOrchestrator.execute_batch_attacks(attack_plans)
        ↓ BatchAttackResult
⑤ Scorer + Memory 审计链
```

### 4.3 OWASP Provider 自动注册

```
模块导入 owasp_provider.py
    ↓ _register_owasp_datasets()
    ↓ 扫描 data/owasp/{llm,agentic}/*/*.yaml
    ↓ 为每个 YAML 动态创建 _OwaspLocalDatasetProvider 子类
    ↓ __init_subclass__ 自动注册到 SeedDatasetProvider
    ↓ SeedDatasetProvider.get_all_dataset_names_async() 可发现 OWASP 数据集
```

---

## 5. 配置说明

`config/config.yaml` 中的 `dataset_manager` 配置段:

```yaml
dataset_manager:
  # OWASP 本地数据集
  owasp:
    frameworks: [llm, agentic]
    owasp_ids: []        # 空 = 全部
    exclude_ids: []

  # 自定义载荷
  custom:
    enabled: true

  # PyRIT 远程数据集
  remote:
    enabled: false
    datasets: []

  # ②.5 交互式选择层
  interactive_selection:
    enabled: true              # false = 全选跳过（CI/CD 兼容）
    auto_select_if_single: true # 只有 1 个种子组时自动选择
    page_size: 20              # 每页显示条目数
```

---

## 6. 与 Executor 子系统的衔接

Datasets 子系统与 Executor 子系统在 **④ 攻击执行层** 衔接：

```
Datasets 子系统                           Executor 子系统
═══════════════════                      ══════════════════

① 数据准备层                             Layer 1: Prompt Generators
   DatasetManager.load_datasets()          AnecdoctorWrapper / FuzzerWrapper
        │                                      │
        ▼                                      │ (可选：自动扩展种子库)
② 数据管理层                                  │
   CentralMemory                              │
        │                                      ▼
②.5 交互选择层                          ──── 衔接点 ────
   SeedGroupSelector                     (AttackSeedGroup)
        │                                      │
        ▼                                      ▼
③ 攻击准备层                             Layer 2: Attack 执行层
   AttackPreparator                       NativeAttackExecutor
   (SeedGroup → AttackSeedGroup)         (AttackSeedGroup → AttackResult)
        │                                      │
        ▼                                      ▼
③→④ 桥接                               Layer 3: Compound (可选)
   SeedPromptAdapter                      SequentialExecutor
   PayloadPlanner                         (fallback chain)
        │                                      │
        ▼                                      ▼
④ 攻击执行层 ←━━━━━━━━━━━━━━━━━━━━━ ScenarioOrchestrator
   execute_batch_attacks()               (N objectives × 1 流程)
```

**关键衔接点**:
1. **AttackPreparator → NativeAttackExecutor**: `AttackSeedGroup` 是数据桥梁
2. **SeedPromptAdapter.seed_groups_to_batches()**: 兼容管道桥接
3. **PayloadPlanner.plan_attacks()**: `AttackPlan` 列表是兼容管道入口
4. **SeedGroupBuilder.build()**: `AttackPlan → AttackSeedGroup`（Executor 侧）

---

## 7. 开发规则

### 7.1 数据驱动原则

1. **禁止直接构造 PromptItem**: 必须从 YAML → SeedDataset → CentralMemory → SeedGroup → AttackSeedGroup 流转
2. **禁止绕过交互选择层**: pipeline 必须经过 `SeedGroupSelector`（可通过 `enabled: false` 跳过交互）
3. **禁止修改 SeedGroup 对象**: 选择层是过滤器，不修改原始数据

### 7.2 条件分派不可变原则

- 有 `prepended_conversation` → `crescendo` (多轮)
- 有 `next_message` → `prompt_sending` (单轮)
- 无 `next_message` → `red_teaming` (目标导向)

### 7.3 新增数据源原则

1. 在 `DatasetManager` 中添加 `load_*_datasets()` 方法
2. 方法内部调用 `memory.add_seed_datasets_to_memory_async()` 存入 CentralMemory
3. 在 `load_datasets()` 统一入口中添加开关参数
4. 在 `config.yaml` 的 `dataset_manager` 中添加配置段
5. 确保数据格式为 PyRIT 原生 `SeedDataset`

### 7.4 YAML 种子元数据规范

```yaml
metadata:
  owasp_id: "LLM01"           # 必填
  technique: "direct"          # 必填
  severity: "high"             # 必填
  attack_mode: "single_turn"   # 必填
  rationale: "..."             # 可选
```

---

## 8. 当前代码与官方标准差距分析

> 评估日期：2026-07-26 | 评估基准：PyRIT 1.0.0 官方 Datasets 文档（6 页）
> 评估范围：`src/payloads/` 全部模块 + `data/` 数据目录
> ⚠️ 本节仅分析，不包含代码修改

### 8.1 评分矩阵

| 层级 | 模块 | 官方对应 | 对齐度 | 评级 |
|:--|:--|:--|:--:|:--:|
| ① | DatasetManager | `SeedDatasetProvider` + `CentralMemory` | 95% | 🟢 |
| ① | PayloadSourceLoader (兼容) | `SeedDatasetProvider` | 90% | 🟢 |
| ① | OwaspLocalDatasetProvider | `_LocalDatasetLoader` | 90% | 🟢 |
| ② | CentralMemory 集成 | `pyrit.memory.CentralMemory` | 95% | 🟢 |
| ②.5 | SeedGroupSelector (自研) | — (无官方对应) | N/A | 🟢 |
| ③ | AttackPreparator | `from_seed_group_async` 管道 | 85% | 🟢 |
| ③→④ | SeedPromptAdapter | — (桥接层) | 80% | 🟡 |
| ③→④ | PayloadPlanner | — (兼容层) | 75% | 🟡 |
| 横切 | SeedGroupBuilder | `pyrit.executor.attack.component` | 85% | 🟢 |
| 横切 | **SeedSimulatedConversation** | `SeedSimulatedConversation` | **50%** | 🟡 |
| 横切 | **Remote Dataset Loader** | `_RemoteDatasetLoader` | **0%** | 🔴 |
| 横切 | **generate_simulated_conversation_async** | `pyrit.executor.attack` | **0%** | 🔴 |
| 数据 | YAML 格式合规 | `SeedDataset.from_yaml_file()` | 90% | 🟢 |
| **整体对齐度** | | | **~82%** | 🟡 |

### 8.2 评级标准

| 评级 | 范围 | 含义 |
|:--:|:--|:--|
| 🟢 | 85-100% | 对齐 L5 专家水平，可直接用于生产 |
| 🟡 | 60-84% | 基本对齐但存在功能缺口，需要增强 |
| 🔴 | <60% | 存在重大差距，影响核心功能 |

### 8.3 核心发现

**✅ 已对齐的强项（7/14 项 🟢）**：
- DatasetManager 使用原生 `CentralMemory` + `SeedDatasetProvider` 双通道加载
- OWASP 本地数据集通过 `_LocalDatasetLoader` 子类注册为原生 Provider
- CentralMemory 多维查询参数完全透传原生 API
- SeedGroupSelector 自研交互式选择层（官方无对应，属增量增强）
- AttackPreparator 返回原生 `AttackSeedGroup`，由 `from_seed_group_async` 自动提取
- YAML 格式使用原生 `SeedDataset.from_yaml_file()` 加载
- SeedGroupBuilder 角色交替规则正确，与原生提取逻辑一致

**⚠️ 需要改进的差距（4/14 项 🟡）**：
- SeedPromptAdapter 双向适配引入了非原生的 `PromptItem`/`PromptBatch` 中间层
- PayloadPlanner 是兼容管道的遗留组件，与原生 `AttackExecutor` 管道存在重复
- SeedSimulatedConversation 仅在 Adapter 中有编程创建方法，未在 YAML 数据中实际使用
- YAML 数据中部分种子的角色交替不完全符合原生预期（多轮对话中缺少 assistant 角色）

**🔴 重大差距（2/14 项 🔴）**：
- **远程数据集加载器**：项目未实现自定义 `_RemoteDatasetLoader` 子类，无法贡献项目特定远程数据集
- **模拟对话生成**：未集成 `generate_simulated_conversation_async` 工具函数

---

### 8.4 逐模块差距分析

#### 8.4.1 DatasetManager 🟢 (95%)

| 维度 | 官方标准 | 项目实现 | 差距 |
|:--|:--|:--|:--|
| 数据源组合 | `SeedDatasetProvider.fetch_datasets_async()` | ✅ 三源自由组合（OWASP/自定义/远程） | 无 |
| CentralMemory 写入 | `add_seed_datasets_to_memory_async(datasets, added_by)` | ✅ 完全对齐 | 无 |
| CentralMemory 查询 | `get_seed_groups()` / `get_seeds()` | ✅ 11 个查询参数全部透传 | 无 |
| 远程数据集 | `SeedDatasetProvider.fetch_datasets_async(dataset_names)` | ✅ 使用原生 API | 无 |
| 数据集名称列举 | `get_all_dataset_names_async()` | ✅ `get_dataset_names()` 透传 | 无 |
| **元数据管理** | `added_by` 审计追踪 | ✅ 可配置 `added_by` | 无 |
| **批量加载并发** | `max_concurrency` 参数 | ✅ 透传 `max_concurrency=3` | 无 |

**差距**：DatasetManager 在 `load_remote_datasets` 中未暴露 `cache` 参数到 `load_datasets` 统一入口（但底层支持）。

#### 8.4.2 PayloadSourceLoader (兼容管道) 🟢 (90%)

| 维度 | 官方标准 | 项目实现 | 差距 |
|:--|:--|:--|:--|
| YAML 加载 | `SeedDataset.from_yaml_file()` | ✅ 使用原生 API | 无 |
| OWASP 目录扫描 | — | ✅ 支持 framework / owasp_ids / exclude_ids | 自研增强 |
| 远程数据集 | `SeedDatasetProvider.fetch_datasets_async()` | ✅ `load_remote_datasets_async()` | 无 |
| **输出格式** | `SeedDataset` | ⚠️ 输出 `PromptBatch`（非原生格式） | 需经 Adapter 转换 |

**差距**：兼容管道输出 `PromptBatch` 而非原生 `SeedDataset`，需要 `SeedPromptAdapter` 桥接。推荐管道（DatasetManager）已无此问题。

#### 8.4.3 OwaspLocalDatasetProvider 🟢 (90%)

| 维度 | 官方标准 | 项目实现 | 差距 |
|:--|:--|:--|:--|
| 继承关系 | `_LocalDatasetLoader` | ✅ 继承原生类 | 无 |
| 自动注册 | `__init_subclass__` + `should_register` | ✅ 动态创建子类 + `should_register=True` | 无 |
| 元数据解析 | `_parse_metadata_async` | ✅ 覆写增强（tags/size/modalities 推断） | 无 |
| **元数据验证** | `SeedDatasetMetadata._validate_singular_fields` | ✅ 调用原生验证 | 无 |
| **数据集发现** | `SeedDatasetProvider.get_all_dataset_names_async()` | ✅ 注册后可被发现 | 未验证集成 |

**差距**：注册后是否真正被 `SeedDatasetProvider` 发现和消费未端到端验证。

#### 8.4.4 CentralMemory 集成 🟢 (95%)

| 维度 | 官方标准 | 项目实现 | 差距 |
|:--|:--|:--|:--|
| 初始化 | `initialize_pyrit_async(memory_db_type)` | ✅ 项目初始化时调用 | 无 |
| 数据写入 | `add_seed_datasets_to_memory_async()` | ✅ DatasetManager 内部调用 | 无 |
| 种子组查询 | `get_seed_groups()` | ✅ 11 个参数全部透传 | 无 |
| 种子查询 | `get_seeds()` | ✅ 10 个参数透传 | 无 |
| **数据集名称查询** | `get_seed_dataset_names()` | ✅ 透传 | 无 |
| **去重** | `value_sha256` 自动去重 | ✅ 原生处理 | 无 |

**差距**：无重大差距。

#### 8.4.5 SeedGroupSelector (自研增强) 🟢 (N/A)

| 维度 | 官方标准 | 项目实现 | 说明 |
|:--|:--|:--|:--|
| 官方对应 | 无 | 自研增强 | PyRIT 1.0.0 无交互式选择层 |
| 设计原则 | — | 过滤器不修改原始对象 | ✅ 正确 |
| 溯源链 | — | `source_seed_group` 保留引用 | ✅ 正确 |
| CI/CD 兼容 | — | `enabled=false` 全选 | ✅ 正确 |
| 多维过滤 | — | OWASP/harm/mode/severity | ✅ 丰富 |
| 统计信息 | — | `get_statistics()` | ✅ 增强 |

**说明**：此模块为项目独创的增量增强，官方无对应功能。设计合理，与原生 API 无冲突。

#### 8.4.6 AttackPreparator 🟢 (85%)

| 维度 | 官方标准 | 项目实现 | 差距 |
|:--|:--|:--|:--|
| 返回类型 | `AttackSeedGroup` (原生) | ✅ 返回原生 `AttackSeedGroup` | 无 |
| Objective 保证 | 强制恰好一个 objective | ✅ 使用原生 `AttackSeedGroup(seeds=...)` | 无 |
| 合成 Objective | — | ✅ 从首条 prompt 自动创建 | 自研增强 |
| 条件分派 | — | ✅ prepended→crescendo, next→prompt, else→red_team | 自研增强 |
| **from_seed_group_async** | 攻击自动调用 | ⚠️ AttackPreparator 不直接调用 | 由 Executor 调用 |
| **SeedSimulatedConversation** | `from_seed_group_async` 自动处理 | ⚠️ prepare() 未处理 simulated conversation | 见 8.4.10 |

**差距**：
1. `prepare()` 方法接收 `adversarial_chat` 和 `objective_scorer` 参数但仅透传，未实际使用（这些参数在 `from_seed_group_async` 时才需要）
2. 未处理含有 `SeedSimulatedConversation` 的 SeedGroup（原生 `from_seed_group_async` 会自动处理）

#### 8.4.7 SeedPromptAdapter 🟡 (80%)

| 维度 | 官方标准 | 项目实现 | 差距 |
|:--|:--|:--|:--|
| SeedDataset → PromptBatch | — (非原生管道) | ✅ 使用原生 `dataset.seed_groups` | 中间层冗余 |
| SeedGroup → PromptItem | — (非原生管道) | ✅ 使用原生 `seed_group.objective/prompts` | 中间层冗余 |
| PromptItem → SeedObjective | — | ✅ 反向转换支持 | 无 |
| PromptItem[] → SeedDataset | — | ✅ 反向转换支持 | 无 |
| **多模态处理** | SeedPrompt 支持 image_path 等 | ⚠️ `_seed_group_to_item` 仅取 `prompts[0]` | 多模态种子丢失 |
| **角色交替** | sequence + role | ⚠️ MULTI_TURN 模式将所有 prompt 作为 multi_turn_steps | 不符合原生角色交替 |
| **SeedSimulatedConversation 提取** | 原生属性 | ✅ `_extract_simulated_config` 提取配置 | 无 |

**差距**：
1. 引入 `PromptItem`/`PromptBatch` 中间层 — 原生管道应直接使用 `AttackSeedGroup`
2. `_seed_group_to_item` 在 SINGLE_TURN 模式仅取 `prompts[0]`，丢失多模态种子
3. MULTI_TURN 模式将所有 prompt 作为 `multi_turn_steps`（字符串列表），丢失角色信息

#### 8.4.8 PayloadPlanner 🟡 (75%)

| 维度 | 官方标准 | 项目实现 | 差距 |
|:--|:--|:--|:--|
| 攻击计划生成 | `AttackExecutor.execute_attack_from_seed_groups_async()` | ⚠️ 自定义 `AttackPlan` 模型 | 非原生管道 |
| 技术选择 | — | ✅ 多级策略匹配（technique_hint → owasp_strategy → default） | 自研增强 |
| Converter 链展开 | — | ✅ YAML 显式 + 自动匹配双模式 | 自研增强 |
| Jailbreak 增强 | `TextJailBreak` API | ✅ 使用原生 `TextJailBreak.get_jailbreak()` | 无 |
| **优先级排序** | — | ✅ severity + mode + metadata 多因子 | 自研增强 |
| **memory_labels** | `execute_async(memory_labels=...)` | ✅ 自动构建标签 | 无 |

**差距**：`PayloadPlanner` + `AttackPlan` 是兼容管道的核心，但原生管道应直接使用 `AttackExecutor.execute_attack_from_seed_groups_async(seed_groups)`，无需中间 `AttackPlan` 层。

#### 8.4.9 SeedGroupBuilder 🟢 (85%)

| 维度 | 官方标准 | 项目实现 | 差距 |
|:--|:--|:--|:--|
| AttackSeedGroup 构建 | `AttackSeedGroup(seeds=[...])` | ✅ 使用原生构造 | 无 |
| 角色交替 | even→user, odd→assistant | ✅ 正确实现 | 无 |
| 最后一轮强制 user | 确保提取为 next_message | ✅ 正确 | 无 |
| **objective 注入** | SeedObjective 在 seeds 列表首位 | ✅ 正确 | 无 |
| **多模态支持** | SeedPrompt(data_type="image_path") | ⚠️ 未处理多模态种子 | 仅文本 |
| **system prompt** | role="system" | ⚠️ 未处理 system 角色 | 仅 user/assistant |

**差距**：
1. 仅处理文本种子（`multi_turn_steps` 为字符串列表），不支持多模态
2. 未处理 `role="system"` 的 SeedPrompt（system prompt 应通过 `prepended_conversation` 传入）

#### 8.4.10 SeedSimulatedConversation 集成 🟡 (50%)

| 维度 | 官方标准 | 项目实现 | 差距 |
|:--|:--|:--|:--|
| YAML 声明 | `seed_type: "simulated_conversation"` | ⚠️ YAML 数据中未使用 | 未实际测试 |
| 编程创建 | `SeedSimulatedConversation(...)` | ✅ `create_simulated_conversation_objective()` | 有 API |
| **from_seed_group_async** | 自动处理 SimulatedConversation | ❌ AttackPreparator 未集成 | 重大缺口 |
| **generate_simulated_conversation_async** | 独立工具函数 | ❌ 未集成 | 重大缺口 |
| **重放到不同目标** | prepended_conversation + next_message | ❌ 未实现 | 重大缺口 |

**差距**：
1. `SeedSimulatedConversation` 在 `SeedPromptAdapter._extract_simulated_config` 中有提取逻辑，但仅转换为字典元数据，未在执行时使用
2. `AttackPreparator.prepare()` 未处理含有 `SeedSimulatedConversation` 的 SeedGroup
3. 未集成 `generate_simulated_conversation_async` 工具函数
4. 未实现"在不同目标上重放模拟对话"的流程

#### 8.4.11 远程数据集加载器 🔴 (0%)

| 维度 | 官方标准 | 项目实现 | 差距 |
|:--|:--|:--|:--|
| _RemoteDatasetLoader 子类 | 创建自定义远程加载器 | ❌ 未实现 | 完全缺失 |
| HuggingFace 获取 | `_fetch_from_huggingface_async()` | ❌ 仅通过 `SeedDatasetProvider` 间接使用 | 未自定义 |
| 自动发现注册 | `__init_subclass__` | ❌ 未实现 | 完全缺失 |

**差距**：项目未实现任何自定义 `_RemoteDatasetLoader` 子类。虽然可以通过 `DatasetManager.load_remote_datasets()` 使用 PyRIT 内置的远程数据集，但无法贡献项目特定的远程数据集（如自定义 HuggingFace 数据集或 API 端点数据）。

#### 8.4.12 generate_simulated_conversation_async 🔴 (0%)

| 维度 | 官方标准 | 项目实现 | 差距 |
|:--|:--|:--|:--|
| 函数集成 | `from pyrit.executor.attack import generate_simulated_conversation_async` | ❌ 未导入和使用 | 完全缺失 |
| 对话生成 | 对抗 LLM + 模拟目标多轮对话 | ❌ 未实现 | 完全缺失 |
| 结果包装 | `SeedGroup(seeds=simulated_prompts)` | ❌ 未实现 | 完全缺失 |
| 重放到不同目标 | `execute_async(prepended_conversation=..., next_message=...)` | ❌ 未实现 | 完全缺失 |

**差距**：这是 PyRIT 1.0.0 的重要功能 — 预计算昂贵的多轮对话前缀，然后在其他模型上复用。项目完全缺失此功能。

#### 8.4.13 YAML 数据格式合规 🟢 (90%)

| 维度 | 官方标准 | 项目实现 | 差距 |
|:--|:--|:--|:--|
| dataset_name | 必填 | ✅ 所有 YAML 均有 | 无 |
| seeds 列表 | 必填 | ✅ 所有 YAML 均有 | 无 |
| seed_type 标记 | "objective" / "prompt" | ✅ 正确使用 | 无 |
| prompt_group_alias | 种子分组 | ✅ 正确使用 | 无 |
| sequence | 多轮序号 | ✅ 正确使用 | 无 |
| role | user/assistant/system | ⚠️ 多轮种子全为 user | 缺少 assistant |
| metadata | 自定义元数据 | ✅ owasp_id/technique/severity/attack_mode | 无 |
| data_type | text/image_path/... | ✅ 使用 text | 仅文本 |
| harm_categories | 危害类别 | ✅ 正确使用 | 无 |
| **is_jinja_template** | Jinja 模板标记 | ❌ 未使用 | 未使用 Jinja |

**差距**：
1. 多轮对话种子全部使用 `role: "user"`，缺少 `assistant` 角色（原生预期角色交替）
2. 未使用 `is_jinja_template` 标记（Jinja 模板种子）
3. 未使用 `data_type: "image_path"` 等多模态类型

---

## 9. 差距优先级排序与建议路线图

### 9.1 差距汇总

| 优先级 | 模块 | 对齐度 | 评级 | 核心差距 |
|:--:|:--|:--:|:--:|:--|
| **P0** | generate_simulated_conversation_async | 0% | 🔴 | 完全缺失模拟对话生成功能 |
| **P0** | SeedSimulatedConversation 集成 | 50% | 🟡 | AttackPreparator 未处理 SimulatedConversation |
| **P1** | _RemoteDatasetLoader 自定义 | 0% | 🔴 | 未实现项目特定远程数据集加载器 |
| **P1** | SeedPromptAdapter 多模态处理 | 80% | 🟡 | 单轮模式丢失多模态种子 |
| **P2** | SeedGroupBuilder 多模态/system | 85% | 🟢 | 未处理 image_path 和 system 角色 |
| **P2** | YAML 角色交替 | 90% | 🟢 | 多轮种子缺少 assistant 角色 |
| **P3** | PayloadPlanner 原生管道迁移 | 75% | 🟡 | AttackPlan 中间层冗余 |
| **P3** | SeedPromptAdapter 中间层 | 80% | 🟡 | PromptItem/PromptBatch 冗余 |

### 9.2 建议路线图

```
P0（高优先级 — 补齐核心功能缺口）
├── 集成 generate_simulated_conversation_async
│   ├── 导入并封装为项目工具函数
│   ├── 实现"预计算对话前缀 → 重放到不同目标"流程
│   └── 添加 CLI/配置入口
├── AttackPreparator 集成 SeedSimulatedConversation
│   ├── prepare() 检测 SimulatedConversation 种子
│   ├── 透传 adversarial_chat 参数到 from_seed_group_async
│   └── 确保 AttackExecutor 自动处理模拟对话生成
│
P1（中优先级 — 增强数据管道完整性）
├── 实现自定义 _RemoteDatasetLoader 子类
│   ├── 为项目特定数据源创建远程加载器
│   ├── 支持 HuggingFace / 自定义 API 端点
│   └── 自动注册到 SeedDatasetProvider
├── SeedPromptAdapter 多模态增强
│   ├── _seed_group_to_item 处理多模态 SeedPrompt
│   └── 保留 image_path/audio_path 数据类型
│
P2（低优先级 — 提升数据质量）
├── SeedGroupBuilder 多模态/system 支持
│   ├── 处理 data_type="image_path" 种子
│   └── 处理 role="system" 种子
├── YAML 数据角色交替修正
│   ├── 多轮对话种子添加 assistant 角色
│   └── 符合原生 from_seed_group_async 预期
│
P3（长期优化 — 原生管道迁移）
├── 逐步迁移兼容管道到原生管道
│   ├── 减少 PromptItem/PromptBatch 中间层使用
│   └── 直接使用 AttackSeedGroup + AttackExecutor
└── 评估 AttackPlan 中间层的长期必要性
```

### 9.3 AI-300 考试就绪度评估

| 考试领域 | Datasets 就绪度 | 说明 |
|:--|:--:|:--|
| LLM 攻击 (LLM01-10) | 🟢 90% | YAML 数据完整，覆盖全部 10 个 OWASP LLM 类别 |
| Agent 攻击 (ASI01-10) | 🟢 85% | YAML 数据完整，覆盖全部 10 个 ASI 类别 |
| 多轮对话攻击 | 🟡 70% | 有多轮种子但缺少角色交替，未集成模拟对话 |
| 模拟对话重放 | 🔴 0% | 完全缺失 generate_simulated_conversation_async |
| 远程数据集利用 | 🟢 85% | 可使用 100+ PyRIT 内置远程数据集 |
| 多模态攻击 | 🟡 30% | 数据管道仅支持文本，未处理图片/音频种子 |

---

## 附录：文件清单

| 文件 | 层 | 职责 | 对齐度 |
|:--|:--|:--|:--:|
| `src/payloads/models.py` | — | 数据模型 (PromptItem, PromptBatch, AttackPlan) | 🟡 |
| `src/payloads/source_loader.py` | ① | 数据源加载器 (兼容管道) | 🟢 |
| `src/payloads/dataset_manager.py` | ①② | CentralMemory 数据枢纽 (推荐管道) | 🟢 |
| `src/payloads/owasp_provider.py` | ① | OWASP 本地 Provider 桥接 | 🟢 |
| `src/payloads/seed_selector.py` | ②.5 | 交互式种子组选择 (自研) | 🟢 |
| `src/payloads/attack_preparator.py` | ③ | SeedGroup → AttackSeedGroup | 🟢 |
| `src/payloads/seed_adapter.py` | ③→④ | PyRIT ↔ PromptBatch 适配器 | 🟡 |
| `src/payloads/planner.py` | ④ | 载荷规划器 (兼容管道) | 🟡 |
| `src/executor/attack/component/seed_group_builder.py` | 横切 | AttackSeedGroup 构建 | 🟢 |
| `data/owasp/llm/` | 数据 | OWASP Top 10 for LLM | 🟢 |
| `data/owasp/agentic/` | 数据 | OWASP Top 10 for Agentic AI (含考试补充载荷) | 🟢 |
| `data/custom/` | 数据 | 自定义载荷目录 (含考试快速启动载荷) | 🟢 |
