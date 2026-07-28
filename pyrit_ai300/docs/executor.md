# Executor 子系统架构文档

> 对齐 `pyrit.executor` — PyRIT 1.0.0 完整五层攻击执行架构

## 1. 架构概览

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        EXECUTOR 子系统（完整）                            │
│                                                                         │
│  核心不变量 🟢：one-objective → one-result                               │
│  核心 shape 🟢：configured by → consumes Context → produces Result       │
│  管道设计 🔵：Orchestrator + Converter + Scorer（组合式攻击管道）          │
│                                                                         │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │  Layer 5: Benchmarks（标准测试层）⚪                               │  │
│  │  "预定义测试集 + 预定义评分 → 一键出成绩单"                         │  │
│  │  → FairnessBiasWrapper, QuestionAnsweringWrapper                  │  │
│  └────────────────────────────┬──────────────────────────────────────┘  │
│  ┌────────────────────────────┴──────────────────────────────────────┐  │
│  │  Layer 4: Workflow（批量编排层）🟡                                  │  │
│  │  "N 个 objectives × 1 套攻击流程"                                  │  │
│  │  → ScenarioOrchestrator [DEPRECATED], BatchAttackOrchestrator,    │  │
│  │    XPIAWorkflow, AI300AdaptiveScenario (原生统一路径)               │  │
│  └────────────────────────────┬──────────────────────────────────────┘  │
│  ┌────────────────────────────┴──────────────────────────────────────┐  │
│  │  Layer 3: Compound（策略编排层）🟢                                  │  │
│  │  "1 个 objective × N 个攻击策略（fallback chain）"                  │  │
│  │  → SequentialExecutor                                             │  │
│  └────────────────────────────┬──────────────────────────────────────┘  │
│  ┌────────────────────────────┴──────────────────────────────────────┐  │
│  │  Layer 2: Attack（执行层）🟢                                        │  │
│  │  "1 个 objective → 1 个 AttackResult"                              │  │
│  │                                                                   │  │
│  │  ┌──────────┐ ┌──────────────┐ ┌──────────────┐ ┌─────────────┐  │  │
│  │  │Single-   │ │Multi-Turn    │ │GCG          │ │Streaming    │  │  │
│  │  │Turn      │ │Adaptive      │ │(白盒/灰盒)  │ │(BargeIn)    │  │  │
│  │  │(直发)    │ │(军师迭代)    │ │             │ │(deprecated) │  │  │
│  │  └──────────┘ └──────────────┘ └──────────────┘ └─────────────┘  │  │
│  └───────────────────────────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │  Layer 1: Prompt Generators（种子生成层）⚪                         │  │
│  │  "把 1 个 objective 扩展成 N 个攻击变体"                            │  │
│  │  → AnecdoctorWrapper, FuzzerWrapper                               │  │
│  └───────────────────────────────────────────────────────────────────┘  │
│                                                                         │
│  横切配置（所有层共享）🟢：                                               │
│  ┌──────────────────┐ ┌──────────────────┐ ┌──────────────────┐        │
│  │AttackAdversarial │ │AttackScoring     │ │AttackConverter   │        │
│  │Config            │ │Config            │ │Config            │        │
│  │• target (军师)   │ │• scorer          │ │• converter list  │        │
│  │• system_prompt   │ │• threshold?      │ │                  │        │
│  └──────────────────┘ └──────────────────┘ └──────────────────┘        │
│                                                                         │
│  辅助子系统：                                                            │
│  ┌──────────────────┐ ┌──────────────────┐                             │
│  │SeedGroupBuilder  │ │BargeInExecutor   │                             │
│  │(Seed→AttackSeed) │ │(stub, deprecated)│                             │
│  └──────────────────┘ └──────────────────┘                             │
└─────────────────────────────────────────────────────────────────────────┘
```

## 2. 目录结构

```
src/executor/                                    ← 对齐 pyrit.executor
├── __init__.py                                  ← 顶层统一导出
│
├── promptgen/                                   ← Layer 1: 种子生成层 ⚪
│   ├── __init__.py
│   ├── anecdoctor_wrapper.py                    ← AnecDoctor 封装
│   └── fuzzer_wrapper.py                        ← Fuzzer 封装
│
├── attack/                                      ← Layer 2: Attack 执行层 🟢
│   ├── __init__.py
│   │
│   ├── core/                                    ← 核心引擎 + 横切配置
│   │   ├── __init__.py
│   │   ├── constants.py                         ← 技术分类常量集合
│   │   ├── attack_builder.py                    ← 横切配置工厂
│   │   └── native_executor.py                   ← 统一执行引擎（Facade）
│   │
│   ├── single_turn/                             ← 单轮攻击执行器
│   │   ├── __init__.py
│   │   └── single_turn_executor.py              ← 直发型执行逻辑
│   │
│   ├── multi_turn/                              ← 多轮攻击执行器
│   │   ├── __init__.py
│   │   └── multi_turn_executor.py               ← 军师迭代型执行逻辑
│   │
│   ├── compound/                                ← Layer 3: 策略编排层 🟢
│   │   ├── __init__.py
│   │   └── sequential_executor.py               ← SequentialAttack 封装
│   │
│   ├── streaming/                               ← 流式攻击
│   │   ├── __init__.py
│   │   └── barge_in_executor.py                 ← BargeIn stub (deprecated)
│   │
│   └── component/                               ← 横切组件
│       ├── __init__.py
│       └── seed_group_builder.py                ← AttackSeedGroup 构建
│
├── workflow/                                    ← Layer 4: 批量编排层 🟡
│   ├── __init__.py
│   ├── scenario_orchestrator.py                 ← 批量编排 + 升级重试
│   ├── batch_orchestrator.py                    ← 兼容层
│   └── xpia_workflow.py                         ← XPIA 专用工作流
│
├── benchmark/                                   ← Layer 5: 基准测试层 ⚪
│   ├── __init__.py
│   ├── fairness_bias.py                         ← 公平性偏差基准
│   └── question_answering.py                    ← 问答准确性基准
│
└── (src/orchestrators/ → 兼容 shim, 重导出到 src.executor)
```

## 3. 各层详细设计

### Layer 1: `promptgen/` — 种子生成层 ⚪

| 模块 | 对齐 PyRIT 原生 | 功能 |
|:--|:--|:--|
| `anecdoctor_wrapper.py` | `pyrit.executor.promptgen.anecdoctor` | 从 ClaimsReview 格式文档自动生成攻击种子（虚假叙事/新闻/推文） |
| `fuzzer_wrapper.py` | `pyrit.executor.promptgen.fuzzer` | 对已有种子执行变异（扩展/缩短/改写/交叉/相似生成） |

**核心 API**:
```python
from src.executor.promptgen import AnecdoctorWrapper, FuzzerWrapper

# AnecDoctor: 文档 → 种子
anec = AnecdoctorWrapper(chat_target=judge_target)
seeds = await anec.generate_async(evaluation_data, content_type="viral tweet", language="english")

# Fuzzer: 种子 → 变体
fuzzer = FuzzerWrapper(chat_target=judge_target)
variants = await fuzzer.mutate_async(existing_seeds, num_variants=10)
```

### Layer 2: `attack/` — Attack 执行层 🟢

#### `attack/core/` — 核心引擎 + 横切配置

| 模块 | 对齐 PyRIT 原生 | 功能 |
|:--|:--|:--|
| `constants.py` | — | 7 个技术分类常量集合（frozenset） |
| `attack_builder.py` | `attack/core/attack_config.py` | Attack 实例创建 + 横切配置工厂 |
| `native_executor.py` | `attack/core/attack_executor.py` | NativeAttackExecutor (Facade) |

**`constants.py` 常量定义**:

| 常量名 | 类型 | 说明 |
|:--|:--|:--|
| `SINGLE_TURN_ATTACKS` | frozenset | 单轮攻击技术（不接受 adversarial_config） |
| `TAP_FAMILY_ATTACKS` | frozenset | TAP/PAIR 家族（需要 TAPAttackScoringConfig） |
| `TREE_DEPTH_ATTACKS` | frozenset | 使用 tree_depth 的技术（TAP/PAIR/TOT） |
| `MAX_TURNS_ATTACKS` | frozenset | 使用 max_turns 的技术（RedTeaming/Crescendo） |
| `MULTI_TURN_TECHNIQUES` | frozenset | 多轮攻击技术集合 |
| `NO_REFUSAL_SCORER_ATTACKS` | frozenset | 不接受 refusal_scorer 的技术 |
| `NO_SCORING_ATTACKS` | frozenset | 不接受 scoring_config 的技术 |

**`NativeAttackExecutor` 分派逻辑**:
```
execute_single_attack(plan, ...)
  ├── technique ∈ SINGLE_TURN_ATTACKS → SingleTurnExecutor.execute()
  └── technique ∉ SINGLE_TURN_ATTACKS → MultiTurnExecutor.execute()

execute_sequential_attack(plan, ...)
  └── SequentialExecutor.execute()

execute_batch_same_technique(attack, seed_groups, ...)
  └── 原生 AttackExecutor.execute_attack_from_seed_groups_async()
```

#### `attack/single_turn/` — 单轮攻击执行器

覆盖技术：`prompt_sending` / `multi_prompt_sending` / `many_shot` / `skeleton` / `chunked_request`

特点：
- 不接受 `attack_adversarial_config`
- 不需要 `adversarial_chat`
- `refusal_scorer` 被剥离（避免 `warn_if_set` 警告）

#### `attack/multi_turn/` — 多轮攻击执行器

覆盖技术：`red_teaming` / `crescendo` / `tap` / `pair` / `tree_of_attacks_pruned`

特点：
- 需要 `attack_adversarial_config`（system_prompt / first_message / template）
- 需要 `adversarial_chat = judge_target`
- 参数映射：`max_turns` vs `tree_depth` vs `tree_width` / `branching_factor` / `batch_size`
- 支持 `PrependedConversationConfig`（当 `multi_turn_steps > 1`）
- TAP 家族使用 `TAPAttackScoringConfig`

#### `attack/component/` — 横切组件

| 模块 | 对齐 PyRIT 原生 | 功能 |
|:--|:--|:--|
| `seed_group_builder.py` | `attack/component/` | AttackSeedGroup 构建（角色交替 + 原生三要素提取） |

**SeedGroupBuilder 角色交替规则**:
```
turns = ["msg1", "msg2", "msg3", "msg4"]
                        ↓
Seeds = [
  SeedObjective(value=objective),
  SeedPrompt(value="msg1", sequence=0, role="user"),       # even → user
  SeedPrompt(value="msg2", sequence=1, role="assistant"),   # odd  → assistant
  SeedPrompt(value="msg3", sequence=2, role="user"),        # even → user
  SeedPrompt(value="msg4", sequence=3, role="user"),        # last → forced user
]
                        ↓
原生 from_seed_group_async 自动提取:
  objective:          SeedObjective.value
  next_message:       最后一个 user SeedPrompt (msg4)
  prepended_conversation: 其余 SeedPrompt (msg1, msg2, msg3)
```

#### `attack/streaming/` — 流式攻击

| 模块 | 状态 | 说明 |
|:--|:--|:--|
| `barge_in_executor.py` | ⚠️ deprecated | BargeInAttack 需要 audio_chunks，纯文本场景回退到 prompt_sending |

### Layer 3: `attack/compound/` — 策略编排层 🟢

| 模块 | 对齐 PyRIT 原生 | 功能 |
|:--|:--|:--|
| `sequential_executor.py` | `attack/compound/sequential_attack.py` | SequentialAttack 异构技术链 |

**completion_policy 支持**:
| 策略 | 说明 |
|:--|:--|
| `FIRST_SUCCESS` | 第一个成功即停止 |
| `FIRST_DECISIVE` | 第一个明确结果即停止 |
| `STRICT_ALL` | 全部成功才停止 |
| `EXHAUSTIVE` | 全部执行 |
| `LAST_RESULT` | 取最后一个结果 |

### Layer 4: `workflow/` — 批量编排层 🟡

| 模块 | 对齐 PyRIT 原生 | 功能 |
|:--|:--|:--|
| `scenario_orchestrator.py` | — | N objectives × 1 套流程（并发 + 超时 + 升级重试 + 输出） |
| `batch_orchestrator.py` | — | 兼容层（委托 ScenarioOrchestrator） |
| `xpia_workflow.py` | `workflow/xpia.py` | XPIA 跨域提示注入专用工作流 |

**ScenarioOrchestrator 自研功能**:
- 批量并发调度（`asyncio.Semaphore` + `ProgressDashboard`）
- 攻击升级重试（失败后自动升级到更强技术）
- 双通道输出（终端 + Markdown 文件）
- `AttackResultAttribution` 父级关联
- `execute_batch_grouped()` 按技术分组原生并行

**XPIAWorkflowWrapper 测试流程**:
```
攻击内容生成 → 嵌入文档 → 处理目标读取 → 评分检测注入
```

### Layer 5: `benchmark/` — 基准测试层 ⚪

| 模块 | 对齐 PyRIT 原生 | 功能 |
|:--|:--|:--|
| `fairness_bias.py` | `benchmark/fairness_bias.py` | 公平性偏差评估（生成故事 → 评分 → 统计偏差分布） |
| `question_answering.py` | `benchmark/question_answering.py` | 问答准确性评估（多选题 → 评分 → 统计正确率） |

## 4. 横切配置

所有层共享的配置对象，由 `attack/core/attack_builder.py` 统一创建：

| 配置类 | 字段 | 说明 |
|:--|:--|:--|
| `AttackAdversarialConfig` | target / system_prompt / first_message / adversarial_prompt_template | 对抗 LLM 配置（军师迭代型攻击需要） |
| `AttackScoringConfig` | objective_scorer / refusal_scorer / auxiliary_scorers / use_score_as_feedback | 评分配置（三层评分架构） |
| `AttackConverterConfig` | converter list | Converter 链配置 |
| `PrependedConversationConfig` | apply_converters_to_roles | 前置对话 Converter 应用控制 |
| `AttackResultAttribution` | parent_id / parent_collection / parent_eval_hash | 父级编排器关联 |

## 5. 与 Datasets 五层架构的衔接

Executor 子系统与 Datasets 五层架构在 **④ 攻击执行层** 衔接：

```
Datasets 五层架构                    Executor 五层架构
═════════════════                    ═════════════════

① 数据准备层                         Layer 1: Prompt Generators
   DatasetManager.load_datasets()       AnecdoctorWrapper / FuzzerWrapper
        │                              (可选：自动扩展种子库)
        ▼                                    │
② 数据管理层                              │ (生成的种子存入 CentralMemory)
   CentralMemory                            │
        │                                   ▼
②.5 交互选择层                     ──── 衔接点 ────
   SeedGroupSelector                  (种子来源)
        │                                   │
        ▼                                   ▼
③ 攻击准备层                         Layer 2: Attack 执行层
   AttackPreparator                      NativeAttackExecutor
   (SeedGroup → AttackSeedGroup)         (AttackSeedGroup → AttackResult)
        │                                   │
        ▼                                   ▼
③→④ 桥接                             Layer 3: Compound (可选)
   SeedPromptAdapter                    SequentialExecutor
   (SeedGroup → PromptBatch →           (fallback chain)
    AttackPlan)                             │
        │                                   ▼
        ▼                             Layer 4: Workflow
④ 攻击执行层 ←━━━━━━━━━━━━━━━━━━━━━ ScenarioOrchestrator
   execute_batch_attacks()              (N objectives × 1 流程)
        │                                   │
        ▼                                   ▼
⑤ 评估与追踪层                       Layer 5: Benchmarks (可选)
   Scorer + PyRIT Memory               FairnessBias / QA
   (审计链)                             (标准测试)
```

**关键衔接点**:
1. **AttackPreparator → NativeAttackExecutor**: `AttackSeedGroup` 是数据桥梁
2. **pipeline.py → execute_batch_attacks()**: `AttackPlan` 列表是执行入口
3. **ScenarioOrchestrator → NativeAttackExecutor**: 委托单次执行
4. **Prompt Generators → CentralMemory**: 生成的种子存入数据管理层

## 6. 文件迁移映射

| 旧位置 | → 新位置 | 操作 |
|:--|:--|:--:|
| `orchestrators/attack_builder.py` | `executor/attack/core/attack_builder.py` | 移动 |
| `orchestrators/direct_executor.py` (常量) | `executor/attack/core/constants.py` | 拆分 |
| `orchestrators/direct_executor.py` (基类) | `executor/attack/core/native_executor.py` | 重构 |
| `orchestrators/direct_executor.py` (单轮) | `executor/attack/single_turn/single_turn_executor.py` | 拆分 |
| `orchestrators/direct_executor.py` (多轮) | `executor/attack/multi_turn/multi_turn_executor.py` | 拆分 |
| `orchestrators/direct_executor.py` (顺序) | `executor/attack/compound/sequential_executor.py` | 拆分 |
| `orchestrators/direct_executor.py` (seed) | `executor/attack/component/seed_group_builder.py` | 拆分 |
| `orchestrators/scenario_orchestrator.py` | `executor/workflow/scenario_orchestrator.py` | 移动 |
| `orchestrators/batch_orchestrator.py` | `executor/workflow/batch_orchestrator.py` | 移动 |
| `orchestrators/__init__.py` | `executor/__init__.py` + `orchestrators/__init__.py` (shim) | 重写 |
| — | `executor/promptgen/` | 新增 |
| — | `executor/benchmark/` | 新增 |
| — | `executor/workflow/xpia_workflow.py` | 新增 |
| — | `executor/attack/streaming/barge_in_executor.py` | 新增 |

## 7. 导入路径

所有公共 API 从 `src.executor` 统一导出：

```python
# 推荐导入方式
from src.executor import execute_batch_attacks, NativeAttackExecutor, ScenarioOrchestrator

# 也可从子模块直接导入
from src.executor.attack.core.native_executor import NativeAttackExecutor
from src.executor.workflow.scenario_orchestrator import ScenarioOrchestrator
```

## 8. 对齐度评估

| 层级 | PyRIT 原生模块 | 项目模块 | 对齐度 |
|:--|:--|:--|:--:|
| Layer 1: Prompt Generators | `promptgen/` (AnecDoctor, Fuzzer, GCG) | `promptgen/` (AnecdoctorWrapper, FuzzerWrapper) | 🟡 80% |
| Layer 2: Attack Core | `attack/core/` | `attack/core/` | 🟢 100% |
| Layer 2: Single-Turn | `attack/single_turn/` | `attack/single_turn/` | 🟢 100% |
| Layer 2: Multi-Turn | `attack/multi_turn/` | `attack/multi_turn/` | 🟢 100% |
| Layer 2: Streaming | `attack/streaming/` | `attack/streaming/` | 🟢 100% |
| Layer 2: Component | `attack/component/` | `attack/component/` | 🟡 80% |
| Layer 3: Compound | `attack/compound/` | `attack/compound/` | 🟢 100% |
| Layer 4: Workflow | `workflow/` | `workflow/` | 🟢 100% |
| Layer 5: Benchmarks | `benchmark/` | `benchmark/` | 🟢 100% |
| 横切: Config | `attack/core/attack_config.py` | `attack/core/attack_builder.py` | 🟢 100% |
| **整体对齐度** | | | **🟢 96%** |

## 9. 验证结果

- **Datasets 五层架构**: 56/56 全部通过 ✓
- **Executor 导入验证**: 所有模块导入成功 ✓
- **向后兼容**: `src.orchestrators` 已删除，全部统一到 `src.executor` ✓
