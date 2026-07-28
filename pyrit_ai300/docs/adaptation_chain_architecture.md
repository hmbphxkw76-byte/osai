# 适配链架构设计 (Adaptation Chain Architecture)

> **版本**: v3.0 | **对齐标准**: PyRIT 1.0.0 L5 专家水准 | **最后更新**: 2026-07-28

## 目录

1. [架构概述](#1-架构概述)
2. [九阶段流水线](#2-九阶段流水线)
3. [阶段间适配链设计](#3-阶段间适配链设计)
4. [Recon → Analysis 适配链](#4-recon--analysis-适配链)
5. [Analysis → Datasets 适配链](#5-analysis--datasets-适配链)
6. [Datasets → Selection 适配链](#6-datasets--selection-适配链)
7. [Selection → Executor 适配链](#7-selection--executor-适配链)
8. [Executor → Reporting 适配链](#8-executor--reporting-适配链)
9. [ASR 经验反馈闭环](#9-asr-经验反馈闭环)
10. [噪音过滤与展示层](#10-噪音过滤与展示层)
11. [关键设计决策](#11-关键设计决策)

---

## 1. 架构概述

### 1.1 核心理念

适配链（Adaptation Chain）是指 Pipeline 各阶段之间**数据驱动**的传递关系：每个阶段的输出作为下一阶段的输入，指导后续阶段自动适配目标特性，最大化攻击成功率（ASR）。

```
[1] Init → [2] Recon → [3] Analysis → [4] Datasets → [5] Selection → [6] Execute → [7] Output → [8] Report → [9] Summary
              │            │              │              │              │
              ▼            ▼              ▼              ▼              ▼
         target_type   model_tier    OWASP 覆盖    ASR 排序     Converter 路由
         model_tier    strategy_mode  技术覆盖     Tier 分层     失败路由
         capabilities  priority     seed_groups   fallback_chain  实测 ASR
```

### 1.2 设计原则

| 原则 | 说明 | 实现 |
|------|------|------|
| **PyRIT 原生优先** | 优先使用原生 API，自建仅补充原生不可覆盖的功能 | `AI300AdaptiveScenario` extends 原生 `AdaptiveScenario` |
| **数据驱动适配** | 每个适配决策基于上游数据，不依赖硬编码 | `model_tier` → `strategy_mode` → ASR 排序 → Converter 路由 |
| **显式传递** | 适配参数通过函数参数显式传递，不依赖全局状态 | `run_adaptive_scenario_async(model_tier=..., strategy_mode=...)` |
| **学术先验驱动** | ASR 决策基于学术实验数据（HarmBench/JailbreakBench） | `asr_prior_registry` + `technique_name_mapper` |
| **经验反馈闭环** | 执行后实测 ASR 写回，供后续运行使用 | `batch_update_empirical_asr()` |

---

## 2. 九阶段流水线

| 阶段 | 名称 | 核心模块 | 关键产出 |
|------|------|----------|----------|
| [1/9] | 初始化 | `AI300SetupManager` + 6 个初始化器 | CentralMemory + SQLite + 34 个技术注册 |
| [2/9] | 侦察 | `recon_engine` | `target_type`, `model_tier`, `capabilities` |
| [3/9] | 分析 | `StrategySelector` + `asr_strategy_display` | `strategy_mode`, `strategy_info`, `priority_score` |
| [4/9] | 数据准备 | `DatasetManager` → `CentralMemory` | `seed_groups`, OWASP 覆盖, 技术覆盖 |
| [5/9] | 选择+准备 | `TieredSelectionWizard` + `AttackPreparator` | `selected_groups`, `attack_plans`, `fallback_chain` |
| [6/9] | 执行 | `AI300AdaptiveScenario` (原生 `Scenario.run_async`) | `AdaptiveRunResult`, `batch_result` |
| [7/9] | 输出 | 原生 `output_attack_async` + `display_enhanced_group_breakdown` | Per-Group Breakdown + 成功结果展示 |
| [8/9] | 报告 | `ReportGenerator` + `EvidenceExporter` | Markdown/HTML/PDF 报告 + 证据 ZIP |
| [9/9] | 总结 | — | Pipeline 汇总 |

---

## 3. 阶段间适配链设计

### 3.1 适配链全景图

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         适配链数据流                                       │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  [2/9] Recon                                                            │
│    │  recon_target(url, model_name)                                     │
│    │  → ReconResult { target_type, model_tier, ai_system_type,          │
│    │                   capabilities, detected_endpoint }                │
│    │                                                                    │
│    ▼  target_type ──────────────────────────────────┐                   │
│  [3/9] Analysis                                      │                   │
│    │  StrategySelector.recommend_strategy_mode()     │                   │
│    │  → strategy_mode = {academic|exam|balanced}     │                   │
│    │  display_analysis_stage()                        │                   │
│    │  → strategy_info { model_name, model_tier,      │                   │
│    │                     strategy_mode }              │                   │
│    │                                                 │                   │
│    ▼  strategy_info ────────────────────┐            │                   │
│  [4/9] Datasets                          │            │                   │
│    │  DatasetManager.load_datasets()     │            │                   │
│    │  → seed_groups (CentralMemory)      │            │                   │
│    │  target_type 驱动载荷预筛选展示 ←────┼────────────┘                   │
│    │                                                 │                   │
│    ▼  seed_groups + strategy_info ───────┐                              │
│  [5/9] Selection                         │                              │
│    │  TieredSelectionWizard.select()     │                              │
│    │  model_name → ASR 排序 → Tier 分层   │                              │
│    │  → selected_groups, fallback_chain  │                              │
│    │  AttackPreparator.prepare_batch()   │                              │
│    │  → attack_groups, attack_plans      │                              │
│    │                                    │                              │
│    ▼  attack_plans + strategy_info ──────┘                              │
│  [6/9] Execute                                                         │
│    │  target_type → Converter 路由 (P3 展示)                             │
│    │  model_tier → Combo ASR 评估                                        │
│    │  strategy_mode → 执行策略                                           │
│    │  run_adaptive_scenario_async(                                      │
│    │      target_type=..., model_tier=..., strategy_mode=...,            │
│    │      converter_target=...)                                          │
│    │  → AdaptiveRunResult { batch_result, native_result,                │
│    │      converter_variants_used, failure_type_distribution }           │
│    │                                                                   │
│    ▼  AdaptiveRunResult                                                │
│  [7/9] Output                                                          │
│    │  display_post_execution() — ASR 实测 vs 学术先验                    │
│    │  display_enhanced_group_breakdown() — Per-Group 统计                │
│    │  output_attack_async() — 成功结果展示                               │
│    │                                                                   │
│    ▼  batch_result.results                                             │
│  [8/9] Report                                                          │
│    │  generate_report(scenario_result=batch_result.results)             │
│    │  → OWASP 映射 + 证据导出 + 多格式报告                               │
│    │                                                                   │
│    ▼  empirical_asr_map                                                │
│  [6/9→未来] ASR 写回                                                    │
│    │  batch_update_empirical_asr(empirical_map, model_name)             │
│    │  → asr_prior_registry 更新（供后续 run 使用）                       │
│    └───────────────────────────────────────────────────────────────────┘
```

---

## 4. Recon → Analysis 适配链

### 4.1 数据传递

```
ReconResult.target_type  ──→  StrategySelector (能力感知技术池筛选)
ReconResult.model_tier   ──→  StrategySelector.recommend_strategy_mode()
ReconResult.capabilities ──→  策略选择（MULTI_TURN / SYSTEM_PROMPT 过滤）
```

### 4.2 model_tier 驱动策略模式

```python
# src/analysis/strategy_selector.py
@staticmethod
def recommend_strategy_mode(recon_result: ReconResult) -> str:
    # 环境变量 STRATEGY_MODE 优先
    env_mode = os.getenv("STRATEGY_MODE", "").lower()
    if env_mode in ("academic", "exam", "balanced"):
        return env_mode

    # 自动推荐
    tier = recon_result.model_tier
    if tier == "strong":
        return "academic"    # 多轮迭代 + Converter 增强
    elif tier == "weak":
        return "exam"        # 编码优先快速验证
    else:
        return "balanced"    # 均衡
```

| model_tier | 推荐策略模式 | 适配逻辑 |
|------------|-------------|----------|
| strong | `academic` | 优先多轮迭代 + Converter 增强（Tier S/A 技术） |
| moderate | `balanced` | 策略 + 编码交替，兼顾覆盖与效率 |
| weak | `exam` | 编码优先快速验证，弱过滤模型编码即可生效 |
| unknown | `academic` | 默认保守策略 |

### 4.3 strategy_info 传递

`display_analysis_stage()` 返回 `strategy_info` 字典，在后续阶段持续传递：

```python
strategy_info = {
    "model_name": "gpt-4o",         # ASR 查询用的模型名
    "model_tier": "strong",          # 模型分层
    "strategy_mode": "academic",     # 策略模式
}
```

---

## 5. Analysis → Datasets 适配链

### 5.1 数据传递

```
strategy_info["model_name"]  ──→  TieredSelectionWizard (ASR 排序查询)
target_type                  ──→  载荷预筛选展示 (Target 感知分组)
```

### 5.2 target_type 驱动载荷预筛选

在 [4/9] 阶段，`target_type` 从 Recon 传递到 Datasets 层，用于展示 Target 感知分组：

```python
# pipeline.py [4/9]
_recon_target_type = getattr(recon_result, "target_type", "")
if _recon_target_type:
    from src.converters.target_aware_router import get_target_group
    _target_group = get_target_group(_recon_target_type)
    print(f"  [OK] Target 感知分组: {_recon_target_type} → {_target_group}")
```

---

## 6. Datasets → Selection 适配链

### 6.1 数据传递

```
seed_groups (CentralMemory)     ──→  TieredSelectionWizard.select()
strategy_info["model_name"]     ──→  ASR 排序 (asr_prior_registry 查询)
strategy_info["strategy_mode"]  ──→  ASR 排序展示模式
```

### 6.2 ASR 分层选择

`TieredSelectionWizard` 接收 `model_name` 参数，通过 `ASRRankBuilder` 查询学术 ASR 先验：

```python
# 三级 ASR 查询优先级
1. YAML asr_baseline (实测数据)
2. 学术先验 (asr_prior_registry → technique_name_mapper 标准化映射)
3. 启发式代理 (基于技术类型的经验估计)
```

统一 Tier 阈值（三个系统共用）：

| Tier | ASR 范围 | 技术类型 |
|------|---------|----------|
| S | ≥ 70% | 多轮迭代攻击（学术验证最高 ASR） |
| A | 40-70% | 树搜索/迭代/模拟对话 |
| B | 15-40% | 说服/角色扮演/包装 |
| C | 5-15% | 编码变换/基线（兜底） |
| D | < 5% | 极低 ASR（默认跳过） |

### 6.3 model_name 全链路传递

```
pipeline.py
  └→ strategy_info["model_name"]
      └→ TieredSelectionWizard(model_name=...)
          └→ ASRRankBuilder.build_ranked_groups(model_name=...)
              └→ get_normalized_asr(technique, model_name)
                  └→ asr_prior_registry.get_initial_q_value(technique, model_name)
```

---

## 7. Selection → Executor 适配链

### 7.1 数据传递

```
attack_plans            ──→  AI300AdaptiveScenario (攻击计划)
target_type             ──→  Converter 路由 (target_aware_router)
strategy_info           ──→  Combo ASR 评估 + 执行策略
converter_target        ──→  LLM 辅助 Converter (Persuasion/Decomposition)
model_tier              ──→  FailureTypeRoutingSelector (失败路由策略)
```

### 7.2 target_type 驱动 Converter 路由

```python
# pipeline.py [6/9] — 执行前展示 Target 感知 Converter 路由
from src.converters.target_aware_router import (
    get_target_group,
    get_target_converter_profile,
    select_converter_chains_for_target,
)
if target_type:
    _group = get_target_group(target_type)
    _profile = get_target_converter_profile(target_type)
    _chains = select_converter_chains_for_target(target_type)
```

Target 感知路由将 `target_type`（如 `openai_chat`, `azure_ml`）映射到分组（如 `llm_direct_strong`），并推荐适配的 Converter 链。

### 7.3 适配链决策汇总展示

在 [6/9] 阶段，`PipelineDisplay.display_adaptation_chain()` 展示从 Recon → Analysis → Converters → Executor 的完整适配链传递结果：

```
  ┌─ 适配链决策 ─────────────────────────────────────┐
  │ Target 类型:   openai_chat
  │ Target 分组:   llm_direct_strong
  │ 模型分层:     strong
  │ 策略模式:     academic
  │ Converter 链: persuasion_authority, stealth_evasion, ...
  │ 攻击技术:     crescendo, tap, pair, ...
  └──────────────────────────────────────────────────┘
```

### 7.4 Converter Target 适配

关键设计：Converter Target 不能使用 judge_target（安全对齐模型会拒绝生成攻击内容）。

```python
# pipeline.py [6/9]
converter_endpoint = os.getenv("CONVERTER_ENDPOINT", target_endpoint)
converter_model = os.getenv("CONVERTER_MODEL", target_model)

if converter_endpoint == target_endpoint and converter_model == target_model:
    converter_target = objective_target  # 复用（避免重复连接池）
else:
    converter_target = await create_prompt_target(...)  # 独立 Target
```

### 7.5 原生 AdaptiveScenario 执行

```python
# pipeline.py [6/9]
adaptive_result = await run_adaptive_scenario_async(
    objective_target=objective_target,
    judge_target=judge_target,
    attack_plans=attack_plans,
    converter_target=converter_target,
    target_type=target_type,
    strategy_mode=strategy_info.get("strategy_mode", "academic"),
    model_name=strategy_info.get("model_name", target_model),
    model_tier=strategy_info.get("model_tier", recon_result.model_tier),
    max_concurrency=adaptive_max_concurrency,
)
```

---

## 8. Executor → Reporting 适配链

### 8.1 数据传递

```
AdaptiveRunResult.batch_result.results  ──→  ReportGenerator (OWASP 映射 + 证据导出)
AdaptiveRunResult.native_result          ──→  display_enhanced_group_breakdown (Per-Group 统计)
AdaptiveRunResult.failure_type_distribution ──→  失败诊断输出
```

### 8.2 三级证据链

```
Finding (OWASP 漏洞发现)
  └─ AttackResult (攻击结果)
       └─ Conversation (完整对话历史)
```

---

## 9. ASR 经验反馈闭环

### 9.1 闭环流程

```
[6/9] 执行完成
  │
  ▼  遍历 batch_result.results
  │  按技术名分组统计成功率
  │  → empirical_map: {technique: {success, total, asr}}
  │
  ▼  batch_update_empirical_asr(empirical_map, model_name)
  │  → asr_prior_registry._empirical_asr_cache 更新
  │
  ▼  后续运行时 get_initial_q_value() 优先返回实测 ASR
  │  → TieredSelectionWizard 排序更准确
  │  → FailureTypeRoutingSelector 初始 Q 值更准确
```

### 9.2 实测 ASR 写回

```python
# pipeline.py [6/9] 执行后
from src.payloads.asr_prior_registry import batch_update_empirical_asr

# 收集各技术实测 ASR
_empirical_map = {}
for result in batch_result.results:
    tech = extract_technique_name(result)
    if tech:
        _empirical_map[tech]["total"] += 1
        if result.outcome == SUCCESS:
            _empirical_map[tech]["success"] += 1

# 写回 registry
batch_update_empirical_asr(_empirical_map, model_name)
```

### 9.3 ASR 查询优先级

```python
# asr_prior_registry.get_initial_q_value()
1. 实测 ASR（运行后更新，最高优先级）
2. 学术先验 ASR（JailbreakBench/HarmBench 数据）
3. 中性先验 0.3（未知技术默认值）
```

---

## 10. 噪音过滤与展示层

### 10.1 PyRIT 噪音日志过滤

`PipelineDisplay` 安装 `PyRITNoiseFilter` 到 PyRIT logger，将内部噪音日志重定向到 `.noise.log` 文件：

```python
# pipeline.py 启动时
display = get_display(stage_total=9)
display.install_noise_filter(log_path)
```

过滤的噪音模式包括：`Skipping scorer`, `No scoring configuration`, `Empty response, retrying`, `Rate limit hit`, `Invalid JSON` 等。

### 10.2 适配链决策展示

在 [6/9] 执行阶段，`display_adaptation_chain()` 以可视化框图展示完整适配链决策，让用户清晰看到从 Recon → Executor 的数据传递结果。

---

## 11. 关键设计决策

### 11.1 为什么删除 adaptation_context.py 和 combo_asr_evaluator.py？

这两个模块在 v3.0 设计阶段创建，但 `pipeline.py` 最终选择了更轻量的"局部变量 + 显式参数传递"方案，未使用集中式上下文对象。因此这两个模块从未被导入，属于死代码。

**实际采用的方案**：
- 适配链数据通过 `strategy_info` 字典在阶段间传递
- `run_adaptive_scenario_async()` 的显式参数传递 `target_type`/`model_tier`/`strategy_mode`
- ASR 经验反馈通过内联代码 + `batch_update_empirical_asr()` 实现

### 11.2 为什么保留 inline ASR 写回而不使用 PipelineContext.collect_empirical_asr()？

`PipelineContext` 是死代码（已删除）。ASR 写回逻辑直接内联在 `pipeline.py` 中，约 20 行代码，清晰且无需额外抽象层。

### 11.3 为什么 Converter Target 默认复用 objective_target？

被测试的模型通常限制较少（非安全对齐模型），适合用于 Converter 的 LLM 辅助变换（Persuasion/Decomposition）。而 judge_target 是安全对齐模型，会拒绝生成攻击内容，导致 Converter 500 错误。

### 11.4 为什么使用 TieredSelectionWizard 而非 SeedGroupSelector？

`TieredSelectionWizard` 基于 ASR 分层（S/A/B/C/D）进行渐进式选择，比 `SeedGroupSelector` 的简单列表选择更符合数据驱动适配的理念。`SeedGroupSelector` 保留为向后兼容路径。
