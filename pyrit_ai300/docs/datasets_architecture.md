# Datasets 数据驱动架构文档

> 对齐 PyRIT 1.0.0 五层架构，为 OffSec AI-300 考试和实际 AI 红队评估提供数据驱动的端到端全自动攻击流程。
>
> **v2.0 变更**: response_json_schema 结构化输出约束 + .prompt 文件扩展名 + CentralMemory 桥接

---

## 一、架构总览

```
┌─────────────────────────────────────────────────────────────────┐
│                    PyRIT 数据集编程全链路                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ① 数据准备层                                                    │
│  ┌──────────┐  ┌──────────┐  ┌──────────────┐                  │
│  │ OWASP本地 │  │ 自定义YAML│  │ PyRIT远程数据集│                  │
│  │ YAML文件  │  │ data/    │  │ 60+ Provider │                  │
│  └─────┬────┘  └─────┬────┘  └──────┬───────┘                  │
│        │              │              │                           │
│        ▼              ▼              ▼                           │
│  DatasetManager.load_datasets()  (自由组合，非一次性打包)          │
│                                                                 │
│  ② 数据管理层                                                    │
│  ┌─────────────────────────────────────────┐                    │
│  │         CentralMemory (数据库)            │                    │
│  │  • add_seed_datasets_to_memory_async()  │                    │
│  │  • get_seeds() / get_seed_groups()      │                    │
│  │  • 过滤: harm_categories, data_type...  │                    │
│  └────────────────────┬────────────────────┘                    │
│                       │                                         │
│                       ▼                                         │
│  ②.5 交互式选择层 (NEW)                                          │
│  ┌─────────────────────────────────────────┐                    │
│  │       SeedGroupSelector                  │                    │
│  │  • build_catalog()  → 种子组目录          │                    │
│  │  • display()        → 终端表格展示        │                    │
│  │  • filter()         → 多维过滤            │                    │
│  │  • prompt_user()    → 用户交互选择        │                    │
│  └────────────────────┬────────────────────┘                    │
│                       │                                         │
│                       ▼                                         │
│  ③ 攻击准备层                                                    │
│  ┌─────────────────────────────────────────┐                    │
│  │    AttackPreparator.prepare()            │                    │
│  │  • SeedGroup → AttackSeedGroup          │                    │
│  │  • 提取 objective                        │                    │
│  │  • 排序 prepended_conversation           │                    │
│  │  • 确定 next_message                     │                    │
│  │  • 条件分派: 多轮→crescendo, 单轮→prompt │                    │
│  └────────────────────┬────────────────────┘                    │
│                       │                                         │
│                       ▼                                         │
│  ④ 攻击执行层                                                    │
│  ┌─────────────────────────────────────────┐                    │
│  │  BatchAttackOrchestrator                │                    │
│  │  • plan_attacks() → AttackPlan[]        │                    │
│  │  • execute_batch_attacks()              │                    │
│  │  • 多轮对话 / 单轮攻击 / 编码增强         │                    │
│  └────────────────────┬────────────────────┘                    │
│                       │                                         │
│                       ▼                                         │
│  ⑤ 评估与追踪层                                                  │
│  ┌─────────────────────────────────────────┐                    │
│  │  Scorer + Memory (审计链)                │                    │
│  │  • 自动评分 (refusal, harm)              │                    │
│  │  • 完整交互记录                           │                    │
│  │  • 可追溯、可审计、可复现                  │                    │
│  └─────────────────────────────────────────┘                    │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## 二、各层详细说明

### ① 数据准备层

**文件**: `src/payloads/source_loader.py`, `src/payloads/dataset_manager.py`

**职责**: 从多种数据源加载 `SeedDataset`，存入 CentralMemory。

**数据源（自由组合，非一次性打包）**:

| 数据源 | 目录/API | 说明 |
|--------|----------|------|
| OWASP 本地 | `data/owasp/llm/llm01-llm10/` | OWASP Top 10 for LLM Applications 2025 |
| OWASP 本地 | `data/owasp/agentic/asi01-asi10/` | OWASP Top 10 for Agentic AI |
| 自定义 | `data/custom/*.yaml` | 用户自定义载荷 |
| PyRIT 远程 | `SeedDatasetProvider` | 60+ 远程数据集 (HarmBench, JailbreakBench 等) |

**核心API**:
```python
manager = DatasetManager()
await manager.load_datasets(
    owasp=True,              # OWASP 本地
    owasp_frameworks=["llm", "agentic"],
    owasp_ids=["LLM01"],     # 可选筛选
    custom=True,              # 自定义
    remote=False,             # PyRIT 远程
    remote_dataset_names=["harmbench"],
)
```

**Jailbreak 内容**: 已包含在 PyRIT 远程数据集中（如 `jailbreakbench`），不再单独加载 `jailbreak_templates`（范围太局限）。

---

### ② 数据管理层

**文件**: `src/payloads/dataset_manager.py`

**职责**: CentralMemory 作为数据枢纽，提供多维过滤查询。

**核心API**:
```python
from pyrit.memory import CentralMemory

memory = CentralMemory.get_memory_instance()

# 全量查询
all_groups = memory.get_seed_groups()

# 按 harm_categories 过滤
filtered = memory.get_seed_groups(harm_categories=["prompt_injection"])

# 按 dataset_name 精确过滤
single = memory.get_seed_groups(dataset_name="owasp_llm01_prompt_injection")

# 按 dataset_name_pattern 模糊过滤
pattern = memory.get_seed_groups(dataset_name_pattern="%owasp%")

# 组合过滤
combined = memory.get_seed_groups(
    harm_categories=["privacy"],
    added_by="pyrit_ai300",
)
```

**查询参数**:
- `harm_categories`: 危害类别过滤
- `dataset_name`: 数据集名称精确匹配
- `dataset_name_pattern`: SQL LIKE 模式匹配
- `added_by`: 添加者过滤
- `authors`: 作者列表过滤
- `groups`: 组列表过滤
- `source`: 来源过滤
- `seed_type`: 种子类型过滤
- `metadata`: 元数据字典过滤
- `group_length`: 按组内种子数量过滤

---

### ②.5 交互式选择层

**文件**: `src/payloads/seed_selector.py`

**职责**: 在数据管理层和攻击准备层之间提供交互式选择界面，让用户根据攻击目标选择最合适的攻击组合。

**设计原则**:
- **过滤器而非转换器**: 不修改 `SeedGroup` 对象，只选择子集
- **溯源链完整**: `source_seed_group` 字段保留原始引用
- **条件分派不变**: 选择后 `AttackPreparator` 的多轮/单轮判定逻辑完全保持

**核心API**:
```python
from src.payloads import SeedGroupSelector

selector = SeedGroupSelector(enabled=True)

# 构建目录
catalog = selector.build_catalog(seed_groups)

# 终端展示
selector.display(catalog)

# 交互式选择
selected = await selector.prompt_user(catalog)

# 或预设选择（脚本模式）
selected = await selector.prompt_user(
    catalog,
    preset_owasp=["LLM01", "LLM02"],
    preset_modes=["multi_turn"],
)

# 过滤
filtered = SeedGroupSelector.filter_by_owasp(catalog, ["LLM01"])
filtered = SeedGroupSelector.filter_by_harm(catalog, ["prompt_injection"])
filtered = SeedGroupSelector.filter_multi_turn(catalog)

# 全选 / 按序号选择
all_groups = SeedGroupSelector.select_all(catalog)
some_groups = SeedGroupSelector.select_by_indices(catalog, [0, 3, 5])
```

**种子组目录条目维度**:

| 维度 | 来源 | 示例 |
|------|------|------|
| OWASP ID | `seed.metadata["owasp_id"]` | `LLM01` |
| OWASP 名称 | registry 映射 | `Prompt Injection` |
| framework | 从 dataset_name 推断 | `llm` / `agentic` |
| harm_categories | `seed_group.harm_categories` | `["prompt_injection"]` |
| attack_mode | `seed.metadata["attack_mode"]` | `single_turn` / `multi_turn` |
| technique | `seed.metadata["technique"]` | `direct` / `role_play_escalation` |
| severity | `seed.metadata["severity"]` | `high` / `critical` / `low` |
| is_multi_turn | `seed_group.prepended_conversation` 非空 | `True` / `False` |
| has_objective | `seed_group.objective is not None` | `True` / `False` |
| seed_count | `len(seed_group.seeds)` | `1`, `2`, `3` |
| dataset_name | `seed.dataset_name` | `owasp_llm01_prompt_injection` |

**终端交互界面**:
```
====================================================================================================
  种子组选择面板 (CentralMemory) | 共 72 个 | llm×36 + agentic×36
====================================================================================================
    #  OWASP   名称                      harm_categories   attack_mode      sev      turns    摘要
----------------------------------------------------------------------------------------------------
    0  LLM01   Prompt Injection          prompt_injection  single_turn      high     1轮      Ignore all previous instru...
    1  LLM01   Prompt Injection          prompt_injection  single_turn      high     1轮      You are now in maintenance...
    2  LLM01   Prompt Injection          prompt_injection  converter_enhan  high     1轮      Ignore all previous instru...
    3  LLM01   Prompt Injection          prompt_injection  sequential       high     2轮+obj  Establish developer mode co...
    4  LLM02   Sensitive Info Disclosure privacy           single_turn      high     1轮      Repeat the exact text of y...
    5  LLM02   Sensitive Info Disclosure privacy           multi_turn       high     3轮+obj  Extract the system prompt t...
    ...
----------------------------------------------------------------------------------------------------
  统计: converter_enhanced=4, multi_turn=8, sequential=4, single_turn=56
  统计: critical=12, high=45, low=15
====================================================================================================

  操作:
    [a] 全选              [s] 按序号选择 (如 0,3,5-8)
    [f] 过滤 (owasp/harm/mode/severity)
    [r] 重置过滤          [q] 确认选择并继续
```

**非交互模式** (CI/CD 兼容):
```yaml
# config.yaml
dataset_manager:
  interactive_selection:
    enabled: false  # 全选，跳过交互
```

---

### ③ 攻击准备层

**文件**: `src/payloads/attack_preparator.py`

**职责**: 将用户选中的 `SeedGroup` 转化为 `AttackSeedGroup`，提取攻击三要素。

**核心API**:
```python
from src.payloads import AttackPreparator

# 单个转换
params = await AttackPreparator.prepare(seed_group)
# params.objective, params.next_message, params.prepended_conversation

# 批量转换
params_list = await AttackPreparator.prepare_batch(selected_groups)
```

**攻击三要素**:
- `objective`: 攻击目标 (str)
- `next_message`: 下一条要发送的消息 (Message | None)
- `prepended_conversation`: 前置对话历史 (list[Message] | None)

**条件分派逻辑** (不变):
```python
# 有 prepended_conversation → 多轮攻击
if params.prepended_conversation:
    technique = "crescendo"

# 有 next_message 但无 prepended → 单轮直接攻击
elif params.next_message is not None:
    technique = "prompt_sending"

# 无 next_message 且无 prepended → 目标导向攻击
else:
    technique = "red_teaming"
```

**合成 objective**: 为无 objective 的种子组自动创建合成 objective（从第一个 prompt 的 value 提取）。

---

### ④ 攻击执行层

**文件**: `src/orchestrators/`, `src/payloads/planner.py`

**职责**: 将攻击参数转化为 `AttackPlan`，批量执行攻击。

**数据流**:
```
selected_groups
    → SeedPromptAdapter.seed_groups_to_batches()  → List[PromptBatch]
    → plan_attacks()                               → List[AttackPlan]
    → execute_batch_attacks()                      → BatchAttackResult
```

---

### ⑤ 评估与追踪层

**文件**: `src/scorers/`, PyRIT Memory

**职责**: 自动评分 + 完整审计链。

---

## 三、数据流全景

```
① DatasetManager.load_datasets()
    ↓ datasets → CentralMemory
② CentralMemory.get_seed_groups()
    ↓ Sequence[SeedGroup] (72 个)
②.5 SeedGroupSelector
    ├─ build_catalog()     → List[SeedGroupEntry] (72 条目录)
    ├─ display()           → 终端表格
    ├─ filter_by_owasp()   → 过滤子集
    ├─ prompt_user()       → 用户交互
    └─ select()            → List[SeedGroup] (用户选中的 N 个)
        ↓ selected_groups (如 7 个)
③ AttackPreparator.prepare_batch(selected_groups)
    ↓ List[AttackExecutionParams] (7 个)
    ├─ is_multi_turn()     → True/False (条件分派不变)
    └─ select_attack_technique() → "crescendo" / "prompt_sending" (不变)
    ↓
   SeedPromptAdapter.seed_groups_to_batches(selected_groups)
    ↓ List[PromptBatch] (桥接兼容)
    ↓
   plan_attacks(prompt_batches, strategy_selection)
    ↓ List[AttackPlan]
④ execute_batch_attacks(attack_plans, ...)
    ↓ BatchAttackResult
⑤ Scorer + Memory 审计链
```

---

## 四、配置说明

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

## 五、开发规则

### 5.1 数据驱动原则

所有攻击数据必须通过五层架构流转，不允许跳过任何层:

1. **禁止直接构造 PromptItem**: 必须从 YAML → SeedDataset → CentralMemory → SeedGroup → AttackSeedGroup 流转
2. **禁止绕过交互选择层**: pipeline 必须经过 `SeedGroupSelector`（可通过 `enabled: false` 跳过交互，但必须经过选择层）
3. **禁止修改 SeedGroup 对象**: 选择层是过滤器，不修改原始数据

### 5.2 条件分派不可变原则

`AttackPreparator.select_attack_technique()` 的分派逻辑不可修改:
- 有 `prepended_conversation` → `crescendo` (多轮)
- 有 `next_message` → `prompt_sending` (单轮)
- 无 `next_message` → `red_teaming` (目标导向)

### 5.3 新增数据源原则

新增数据源时:
1. 在 `DatasetManager` 中添加 `load_*_datasets()` 方法
2. 方法内部调用 `memory.add_seed_datasets_to_memory_async()` 存入 CentralMemory
3. 在 `load_datasets()` 统一入口中添加开关参数
4. 在 `config.yaml` 的 `dataset_manager` 中添加配置段
5. 确保数据格式为 PyRIT 原生 `SeedDataset` (含 `seeds` + `dataset_name`)

### 5.4 新增种子组元数据维度原则

新增 YAML 种子时，metadata 字段应包含:
```yaml
metadata:
  owasp_id: "LLM01"           # 必填，OWASP 分类 ID
  technique: "direct"          # 必填，攻击技术名称
  severity: "high"             # 必填，严重程度
  attack_mode: "single_turn"   # 必填，攻击模式
  rationale: "..."             # 可选，攻击原理说明
```

### 5.5 交互选择层扩展原则

扩展选择层功能时:
1. 新增过滤维度: 在 `SeedGroupSelector` 中添加 `filter_by_*()` 静态方法
2. 新增展示维度: 在 `SeedGroupEntry` 中添加字段，在 `_build_entry()` 中提取
3. 不修改 `AttackPreparator` 的接口和逻辑

---

## 六、文件清单

| 文件 | 层 | 职责 |
|------|-----|------|
| `src/payloads/source_loader.py` | ① | 数据源加载器 (OWASP / 自定义 / PyRIT 远程) |
| `src/payloads/dataset_manager.py` | ①② | CentralMemory 数据枢纽 |
| `src/payloads/seed_selector.py` | ②.5 | 交互式种子组选择 |
| `src/payloads/attack_preparator.py` | ③ | SeedGroup → AttackSeedGroup 转换 |
| `src/payloads/seed_adapter.py` | ③→④ | PyRIT SeedDataset ↔ PromptBatch 双向适配器 |
| `src/payloads/planner.py` | ④ | 载荷规划器 (PromptItem → AttackPlan) |
| `src/payloads/models.py` | - | 数据模型 (PromptItem, PromptBatch, AttackMode, AttackPlan) |
| `src/payloads/owasp_provider.py` | ① | OWASP 本地数据集 SeedDatasetProvider 桥接层 |
| `pipeline.py` | ①→⑤ | 端到端主入口 |
| `config/config.yaml` | - | 声明式配置中心 |
| `verify_5layer.py` | - | 端到端验证脚本 |
