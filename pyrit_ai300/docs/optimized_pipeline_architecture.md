# 优化后 Pipeline 架构 (7 阶段) — v8.0 完整优化架构

> **版本**: v8.0  
> **日期**: 2026-07-29  
> **对齐标准**: PyRIT 1.0.0 原生优先 + L5 专家水平  
> **测试结果**: 1261 单元测试全部通过, 0 ruff 错误

---

## ★ 优化后 Pipeline 架构 (7 阶段) ★

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    PyRIT AI-300 全自动 AI 红队框架                       │
│                    Pipeline v8.0 — 7 阶段编排器                         │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  Pre   s0_init           初始化 PyRIT (静默)                            │
│   │                                                                     │
│   ▼                                                                     │
│  1/7   s1_recon          Recon 侦察层                                   │
│   │   ├── 模型能力探测 (3-step gradient probe)                          │
│   │   ├── 模型分层 (strong/moderate/weak)                                │
│   │   └── → model_tier + target_type                                    │
│   ▼                                                                     │
│  2/7   s2_analysis       Strategy 策略层                                │
│   │   ├── 策略选择 (StrategySelector)                                    │
│   │   ├── ASR策略: 策略分析展示                                          │
│   │   ├── ★ ASR 经验加载 (Tier 2 warm-start)                           │
│   │   ├── ★ Patched 技术检测                                            │
│   │   ├── ★ 策略建议生成                                                 │
│   │   └── → strategy_info + warm_start_asr + empirical_asr_data          │
│   ▼                                                                     │
│  3/7   s3_targets        Target 接入 + Converter 路由                    │
│   │   ├── 创建 Objective/Judge/Converter 三个 Target                    │
│   │   ├── ★ 原 Stage 5a: Target 感知 Converter 路由 (合并)              │
│   │   ├── ★ L2 韧性: Converter 健康监控器初始化                        │
│   │   └── → objective_target + converter_chains + health_monitor        │
│   ▼                                                                     │
│  4/7   s4_datasets       Datasets 数据载荷端                             │
│   │   ├── 4a 数据加载 (OWASP + 自定义 + 学术 + 远程)                    │
│   │   ├── 4b 预筛选 (target_group 驱动)                                  │
│   │   ├── 4c 选择与排序 (TieredSelectionWizard + ASR 先验)              │
│   │   ├── 4d 攻击计划生成 (AttackPreparator → PromptBatch → AttackPlan) │
│   │   └── → attack_plans + selected_groups                              │
│   ▼                                                                     │
│  5/7   s6_execute        Executor 执行层                                │
│   │   ├── ★ 原 Stage 5b/5c: 执行策略 (合并)                            │
│   │   │   ├── 技术排序 (Tier S→A→B→C→D)                                │
│   │   │   ├── 失败路由策略表                                            │
│   │   │   └── 停止策略 (FIRST_SUCCESS + L2/L3 运行时)                   │
│   │   ├── ★ 攻击载荷 × Converter 组合矩阵                              │
│   │   ├── [OK] 原生 AdaptiveScenario 执行                               │
│   │   │   ├── 原生 tqdm 进度条                                          │
│   │   │   ├── 原生 max_retries 弹性恢复                                 │
│   │   │   ├── 原生 FIRST_SUCCESS 提前停止                               │
│   │   │   └── 原生 extra_request_converters 渐进式升级                  │
│   │   ├── 执行结果概要                                                  │
│   │   ├── 逐载荷执行结果 (★ 风格)                                      │
│   │   └── Per-Group Breakdown                                           │
│   ▼                                                                     │
│  6/7   s7_post_analysis  执行后分析 + ASR 经验写回                      │
│   │   ├── ASR 实测 vs 学术先验对比                                      │
│   │   ├── 载荷级成功/失败摘要                                           │
│   │   ├── ★ ASR 经验写回 (Tier 2 持久化)                               │
│   │   │   ├── 融合公式: new = (old×count + new) / (count+1)            │
│   │   │   ├── 存储路径: output/empirical_asr/{model_slug}.json         │
│   │   │   └── 自动 warm-start 下次运行                                  │
│   │   ├── ★ 运行时停止策略统计                                         │
│   │   └── → tech_stats + patched_techniques + strategy_recommendations │
│   ▼                                                                     │
│  7/7   s8_report         报告 + 总结                                    │
│       ├── OWASP 映射 + 证据导出                                         │
│       ├── Markdown 报告 + HTML/PDF 转换                                  │
│       ├── 三级证据链 (Finding → AttackResult → Conversation)           │
│       ├── Converter 转换日志 (方案B)                                    │
│       ├── Converter 变体预览 (方案C)                                    │
│       └── → report_result                                              │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### v8.0 阶段变更说明

| 变更 | 说明 |
|------|------|
| **合并 Stage 5 Matching → Stage 3** | Converter 路由 (5a) 合并到 Stage 3 Targets，消除空壳阶段 |
| **合并 Stage 5 Matching → Stage 5** | 执行策略 (5b/5c) 合并到 Stage 5 Execute 展示 |
| **Stage 7 → Stage 6** | 执行后分析增加 ASR 经验写回 (Tier 2 持久化) |
| **Stage 8 → Stage 7** | 报告阶段不变，仅重新编号 |
| **总阶段数** | 8 → 7 (消除空壳 Stage 5 Matching) |

---

## 1. 架构总览

### 1.1 设计原则

1. **PyRIT 原生优先** — 最大化利用 PyRIT 1.0.0 原生 API
2. **攻击成功率首要** — ASR 数据驱动技术选择和排序
3. **L5 专家水平** — 数据流完整性、执行韧性、可观测性
4. **最佳实践** — 单一数据流、单一真相源、分层韧性

### 1.2 核心架构不变量

```
PipelineContext = 唯一状态容器
  ↓
Stage N 读取 ctx → 处理 → 写入 ctx → Stage N+1 读取 ctx
  ↓
数据流闭环: 每个 ctx 字段标注来源阶段 (# src: Stage N)
```

### 1.3 五层韧性体系

| 层 | 组件 | 功能 | 实现位置 |
|----|------|------|----------|
| L1 | PyRIT FIRST_SUCCESS | 同一 objective 首成功即停 | AdaptiveScenario 原生 |
| L2 | Converter 熔断器 | 连续失败 N 次禁用 Converter | `converter_health_monitor.py` |
| L3 | 运行时停止 EventHandler | OWASP 阈值 + 全局首成功 | `runtime_stop_handler.py` |
| L4 | max_retries + max_concurrency | Scenario 级弹性恢复 | PyRIT 原生 |
| L5 | Memory 持久化 + resume | 中断后可恢复 | PyRIT CentralMemory |

---

## 2. ASR 三层数据架构 (完整详尽)

### 2.1 三层架构图

```
┌─────────────────────────────────────────────────────────────────────┐
│                     ASR 三层数据架构                                │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  Tier 1: 学术先验 (只读, 不可变)                                    │
│  ┌───────────────────────────────────────────────────────────┐     │
│  │ src/payloads/asr_prior_registry.py                        │     │
│  │                                                           │     │
│  │ 数据来源:                                                 │     │
│  │   • JailbreakBench (arXiv:2402.01135, NeurIPS 2024)     │     │
│  │   • HarmBench (arXiv:2402.04249, ICML 2024)             │     │
│  │   • PyRIT 官方 Scenario 文档                              │     │
│  │                                                           │     │
│  │ 内容: 24 个技术的 per-model ASR                           │     │
│  │   • GPT-4o / GPT-4 / GPT-3.5 / Claude-3.5 / Llama-3.1   │     │
│  │   • 未知模型 → model_tier 回退 (strong→GPT-4o 等)        │     │
│  │                                                           │     │
│  │ Tier 阈值 (唯一权威定义):                                 │     │
│  │   Tier S: ASR ≥ 70%   (极高)                             │     │
│  │   Tier A: ASR ≥ 40%   (高)                               │     │
│  │   Tier B: ASR ≥ 15%   (中)                               │     │
│  │   Tier C: ASR ≥  5%   (低)                               │     │
│  │   Tier D: ASR <  5%   (极低)                             │     │
│  │                                                           │     │
│  │ Patched 标记:                                             │     │
│  │   • many_shot_jailbreak (GPT-4o: patched=True)           │     │
│  │   • base64 (GPT-4o: ASR 4%, 接近 patched)                │     │
│  └───────────────────────────────────────────────────────────┘     │
│                              ↓                                     │
│  Tier 2: 经验 ASR (JSON 持久化, per-model)  ← v8.0 新增            │
│  ┌───────────────────────────────────────────────────────────┐     │
│  │ src/scenarios/empirical_asr_store.py                      │     │
│  │                                                           │     │
│  │ 存储: output/empirical_asr/{model_slug}.json              │     │
│  │   • model_slug: 文件安全 slug (如 "longcat-2_0")          │     │
│  │                                                           │     │
│  │ 数据结构:                                                 │     │
│  │   {                                                       │     │
│  │     "model_name": "LongCat-2.0",                          │     │
│  │     "model_tier": "moderate",                             │     │
│  │     "run_count": 3,                                       │     │
│  │     "last_updated": "2026-07-29T20:01:02Z",               │     │
│  │     "techniques": {                                       │     │
│  │       "crescendo": {                                      │     │
│  │         "attempts": 10,                                   │     │
│  │         "successes": 8,                                   │     │
│  │         "failures": 2,                                    │     │
│  │         "empirical_asr": 0.80,                            │     │
│  │         "failure_types": {"model_refusal": 2},           │     │
│  │         "total_runs": 3                                   │     │
│  │       },                                                  │     │
│  │       "prompt_sending": { ... }                           │     │
│  │     },                                                    │     │
│  │     "converter_effectiveness": {                          │     │
│  │       "persuasion_authority": {                           │     │
│  │         "attempts": 5,                                    │     │
│  │         "successes": 2,                                   │     │
│  │         "asr": 0.40,                                      │     │
│  │         "disabled": false,                                │     │
│  │         "failure_reason": ""                              │     │
│  │       },                                                  │     │
│  │       "decomposition_chain": {                             │     │
│  │         "attempts": 3,                                    │     │
│  │         "successes": 0,                                   │     │
│  │         "asr": 0.0,                                       │     │
│  │         "disabled": true,                                 │     │
│  │         "failure_reason": "EmptyResponseException: 204"  │     │
│  │       }                                                   │     │
│  │     }                                                     │     │
│  │   }                                                       │     │
│  │                                                           │     │
│  │ 融合权重曲线:                                             │     │
│  │   run_count = 0:    100% Tier1 + 0% Tier2                │     │
│  │   run_count ≤ 2:     80% Tier1 + 20% Tier2               │     │
│  │   run_count ≤ 5:     60% Tier1 + 40% Tier2               │     │
│  │   run_count > 5:     50% Tier1 + 50% Tier2 (上限)        │     │
│  │                                                           │     │
│  │ 融合公式:                                                 │     │
│  │   effective_asr = (1-w) × academic_asr + w × empirical   │     │
│  │   其中 w = _get_empirical_weight(run_count)               │     │
│  │                                                           │     │
│  │ Patched 检测:                                             │     │
│  │   判定标准: 实测 ASR < 学术先验 - 30%                     │     │
│  │   条件: academic > 15% 且 attempts ≥ 2                    │     │
│  │   示例: Crescendo 学术 82% → 实测 20% (Δ-62%) = patched  │     │
│  └───────────────────────────────────────────────────────────┘     │
│                              ↓                                     │
│  Tier 3: 运行时 Q 值 (SQLite 持久化)                               │
│  ┌───────────────────────────────────────────────────────────┐     │
│  │ PyRIT 原生 CentralMemory + EpsilonGreedyTechniqueSelector │     │
│  │                                                           │     │
│  │ 存储: SQLite (output/db/pyrit.db)                         │     │
│  │   • Laplace 平滑 Q 值                                      │     │
│  │   • 跨 run 学习 (SelectorScope.all_runs)                  │     │
│  │   • epsilon=0.2 随机探索                                  │     │
│  │                                                           │     │
│  │ 数据流:                                                   │     │
│  │   selector.select_async() → Q 值排序 → 技术选择           │     │
│  │   执行结果 → outcome → selector 更新 Q 值                 │     │
│  │   下次 run 自动从 memory 加载 Q 值                        │     │
│  └───────────────────────────────────────────────────────────┘     │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### 2.2 ASR 数据流完整闭环

```
Stage 2 (Strategy)
  ├── load_empirical_asr(model_name)          ← Tier 2 加载
  ├── compute_effective_asr(tech, model, ...)  ← Tier 1+2 融合
  ├── detect_patched_techniques(academic, emp)  ← Patched 检测
  └── generate_strategy_recommendation(...)     ← 策略建议
         ↓
Stage 4 (Datasets)
  ├── display_selection_stage(groups, ...)     ← ASR 先验排序展示
  └── TieredSelectionWizard.select(groups)     ← ASR 驱动选择
         ↓
Stage 5 (Execute)
  ├── display_execution_stage(plans, ...)      ← 执行顺序展示
  ├── AI300EpsilonGreedySelector                ← Tier 3 Q 值排序
  │     └── initial Q = effective_asr (Tier 1+2 融合)
  └── AdaptiveScenario.run_async()             ← 执行
         ↓
Stage 6 (Feedback)
  ├── display_post_execution(result, ...)      ← 实测 vs 先验对比
  ├── extract_tech_stats_from_results(result)  ← 提取统计
  ├── update_empirical_asr(model, stats, ...)  ← Tier 2 写回 ★
  └── detect_patched_techniques(...)            ← Patched 更新
         ↓
  下次运行: Stage 2 自动加载经验 ASR → warm-start
```

### 2.3 学术 ASR 先验数据 (Tier 1 完整表)

| 技术 | GPT-4o | GPT-4 | GPT-3.5 | Claude-3.5 | Llama-3.1 | Tier | Patched | 来源 |
|------|--------|-------|---------|------------|-----------|------|---------|------|
| Crescendo | 82% | 75% | 95% | 65% | 90% | S | - | JailbreakBench |
| TAP | 62% | 56% | 80% | 48% | 72% | A | - | JailbreakBench |
| Red Teaming | 55% | 48% | 70% | 42% | 65% | A | - | PyRIT Doc |
| PAIR | 53% | 45% | 72% | 38% | 68% | A | - | JailbreakBench |
| Persuasion | 35% | 30% | 50% | 25% | 55% | B | - | HarmBench |
| Best-of-N | 35% | 28% | 48% | 22% | 52% | B | - | HarmBench |
| Many-shot | 5% | 4% | 15% | 3% | 25% | C | ✓ patched | Anthropic |
| Base64 | 4% | 3% | 12% | 2% | 45% | C | - | HarmBench |
| ROT13 | 3% | 2% | 8% | 1% | 40% | C | - | HarmBench |
| prompt_sending | 2% | 1% | 15% | 1% | 30% | D | - | PyRIT baseline |

### 2.4 融合权重曲线

```
权重
 1.0 ┤
     │  Tier 1 (学术) ███████████████████████████████████████████████████
     │  Tier 2 (经验) ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
 0.5 ┤                                                       ─ ─ ─ ─ ─
     │                                    ─ ─ ─ ─ ─
     │                  ─ ─ ─ ─ ─
 0.0 ┤  ─ ─ ─ ─ ─
     └──┬────┬────┬────┬────┬────┬────┬────┬────┬────┬────
        0    1    2    3    4    5    6    7    8    9   10
                        run_count

    ─ ─ ─  Tier 2 经验权重
    █████  Tier 1 学术权重

    run_count = 0:   100% Tier1 +   0% Tier2 (首次运行)
    run_count ≤ 2:    80% Tier1 +  20% Tier2
    run_count ≤ 5:    60% Tier1 +  40% Tier2
    run_count > 5:     50% Tier1 + 50% Tier2 (上限)
```

### 2.5 Patched 技术检测

```python
# 检测逻辑 (empirical_asr_store.py)
def detect_patched_techniques(academic_map, empirical_data, threshold=0.3):
    """
    判定标准:
      1. 学术 ASR > 15% (低 ASR 技术不判定)
      2. 尝试次数 ≥ 2 (样本不足不判定)
      3. 实测 ASR < 学术 ASR - 30%

    示例:
      Crescendo: 学术 82% → 实测 20% (Δ-62%) → patched ✓
      Base64:    学术 4%  → 实测 0%  (Δ-4%)  → 不判定 (学术 < 15%)
      PAIR:      学术 53% → 实测 48% (Δ-5%)  → 不判定 (差异 < 30%)
    """
```

---

## 3. 执行韧性体系 (10/10)

### 3.1 五层韧性架构

```
┌─────────────────────────────────────────────────────────────────────┐
│                     五层执行韧性体系                                │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  Layer 1: 原生 FIRST_SUCCESS (PyRIT 内置)                          │
│  ┌───────────────────────────────────────────────────────────┐     │
│  │ 同一 objective 的 SequentialAttack 首成功即停止           │     │
│  │ 自动跳过剩余 Converter 变体                                │     │
│  │ 成本: O(max_attempts × objectives)                        │     │
│  └───────────────────────────────────────────────────────────┘     │
│                                                                     │
│  Layer 2: Converter 熔断器 (converter_health_monitor.py) ★ v8.0   │
│  ┌───────────────────────────────────────────────────────────┐     │
│  │ Circuit Breaker Pattern (M. Nygard, "Release It!")       │     │
│  │                                                           │     │
│  │ 状态:                                                     │     │
│  │   closed  → 正常运行, 记录失败计数                         │     │
│  │   open    → 失败达到阈值(2次), 禁用 converter              │     │
│  │                                                           │     │
│  │ 功能:                                                     │     │
│  │   • register(name) — 注册 Converter                       │     │
│  │   • is_disabled(name) — 检查是否熔断                      │     │
│  │   • record_success(name) — 记录成功 (重置计数)            │     │
│  │   • record_failure(name, error) — 记录失败                │     │
│  │   • filter_chains(chains) — 过滤被熔断的链                 │     │
│  │   • get_stats() — 获取统计摘要                             │     │
│  │                                                           │     │
│  │ 解决问题:                                                 │     │
│  │   日志显示 13/23 错误 (56%) 来自 DecompositionConverter   │     │
│  │   的 EmptyResponseException (204)                         │     │
│  │   安全对齐模型对 Converter 的 JSON 分解请求返回空响应      │     │
│  │   → 熔断器自动禁用, 避免重复失败                           │     │
│  └───────────────────────────────────────────────────────────┘     │
│                                                                     │
│  Layer 3: 运行时停止 EventHandler (runtime_stop_handler.py) ★ v8.0│
│  ┌───────────────────────────────────────────────────────────┐     │
│  │ 替代预过滤停止策略, 基于实际成功数动态决策                │     │
│  │                                                           │     │
│  │ L2: OWASP 分类成功率阈值                                  │     │
│  │   threshold=0.3 → 每类 OWASP 30% 成功率即跳过剩余         │     │
│  │   上限: min(ceil(total × threshold), 5)                  │     │
│  │                                                           │     │
│  │ L3: 全局首成功即停                                       │     │
│  │   stop_on_first_success=True → 首个成功攻击即停止全部     │     │
│  │                                                           │     │
│  │ 实现: PyRIT 原生 StrategyEventHandler 接口               │     │
│  │   ON_POST_EXECUTE 事件中追踪成功/失败                     │     │
│  │   达到阈值时设置 should_stop=True                         │     │
│  └───────────────────────────────────────────────────────────┘     │
│                                                                     │
│  Layer 4: max_retries + max_concurrency (PyRIT 原生)               │
│  ┌───────────────────────────────────────────────────────────┐     │
│  │ Scenario 级弹性恢复:                                      │     │
│  │   max_retries=3 → 自动重试失败的 atomic attack            │     │
│  │   max_concurrency=4 → 并发执行 (API 级限速保护)           │     │
│  │   自动恢复: 中断后可 resume (scenario_result_id)          │     │
│  └───────────────────────────────────────────────────────────┘     │
│                                                                     │
│  Layer 5: Memory 持久化 + resume (PyRIT 原生)                      │
│  ┌───────────────────────────────────────────────────────────┐     │
│  │ CentralMemory (SQLite):                                   │     │
│  │   • AttackResult 持久化                                   │     │
│  │   • ScenarioResult 持久化                                 │     │
│  │   • EpsilonGreedyTechniqueSelector Q 值                   │     │
│  │   • 中断后通过 scenario_result_id 精确恢复                │     │
│  └───────────────────────────────────────────────────────────┘     │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### 3.2 错误降级流程

```
Converter 执行错误
  ↓
ConverterHealthMonitor.record_failure(chain_name, error_msg)
  ↓
consecutive_failures >= threshold (2)?
  ├── No → 继续使用
  └── Yes → disabled=True, 熔断
              ↓
        filter_chains() 自动移除被熔断的链
              ↓
        下次变体选择跳过被熔断的链
              ↓
        避免重复失败, 提高整体 ASR
```

---

## 4. 新增模块详解

### 4.1 converter_health_monitor.py

| 功能 | API | 说明 |
|------|-----|------|
| 注册 | `register(name)` | 注册 Converter 到监控 |
| 检查 | `is_disabled(name)` | 检查是否被熔断 |
| 成功 | `record_success(name)` | 记录成功, 重置计数 |
| 失败 | `record_failure(name, error)` | 记录失败, 达阈值熔断 |
| 过滤 | `filter_chains(chains)` | 过滤链列表, 返回 (enabled, disabled) |
| 统计 | `get_stats()` | 获取所有 Converter 统计 |
| 熔断列表 | `get_disabled_converters()` | 获取被熔断的列表 |
| 错误提取 | `extract_converter_name_from_error(msg)` | 从错误消息提取 Converter 名 |
| 链名提取 | `extract_chain_name_from_error(msg)` | 从错误消息提取链名 |

### 4.2 empirical_asr_store.py

| 功能 | API | 说明 |
|------|-----|------|
| 加载 | `load_empirical_asr(model_name)` | 加载 per-model 经验 ASR |
| 更新 | `update_empirical_asr(model, tier, stats, conv_stats)` | 融合本次运行结果 |
| 融合计算 | `compute_effective_asr(tech, model, academic, empirical)` | 三层融合 |
| Patched 检测 | `detect_patched_techniques(academic_map, empirical)` | 检测被补丁修复的技术 |
| 策略建议 | `generate_strategy_recommendation(model, empirical, academic, patched)` | 生成下次运行建议 |
| 统计提取 | `extract_tech_stats_from_results(native_result, model)` | 从原生结果提取统计 |

### 4.3 runtime_stop_handler.py

| 功能 | API | 说明 |
|------|-----|------|
| 事件处理 | `on_event_async(event_data)` | ON_POST_EXECUTE 追踪成功/失败 |
| L2 阈值 | `check_threshold(owasp_id, threshold)` | 检查 OWASP 分类阈值 |
| L3 停止 | `stop_on_first_success` | 全局首成功即停 |
| 统计 | `get_stats()` | 获取停止策略统计 |

---

## 5. 数据流完整性验证

### 5.1 PipelineContext 字段追踪

| 字段 | 来源阶段 | 使用阶段 | 类型 |
|------|----------|----------|------|
| `recon_result` | Stage 1 | Stage 2, 3 | ReconResult |
| `model_tier` | Stage 1 | Stage 2, 3, 5 | str |
| `target_type` | Stage 1 | Stage 3, 5 | str |
| `strategy_info` | Stage 2 | Stage 4, 5, 6 | dict |
| `empirical_asr_data` | Stage 2 | Stage 5, 6 | dict/None |
| `warm_start_asr` | Stage 2 | Stage 4, 5 | dict |
| `patched_techniques` | Stage 2 | Stage 6 | list |
| `strategy_recommendations` | Stage 2 | Stage 6 | list |
| `objective_target` | Stage 3 | Stage 5 | PromptTarget |
| `judge_target` | Stage 3 | Stage 5 | PromptTarget |
| `converter_target` | Stage 3 | Stage 5 | PromptTarget |
| `converter_chains` | Stage 3 | Stage 5 | list[str] |
| `converter_health_monitor` | Stage 3 | Stage 5, 6 | ConverterHealthMonitor |
| `attack_plans` | Stage 4 | Stage 5 | list[AttackPlan] |
| `adaptive_result` | Stage 5 | Stage 6, 7 | AdaptiveRunResult |
| `stop_context` | Stage 5 | Stage 6 | StopStrategyContext |
| `tech_stats` | Stage 6 | Stage 7 | dict |
| `report_result` | Stage 7 | - | ReportResult |

### 5.2 OWASP ID 全链路传递

```
CLI 参数 / .env 配置
  ↓ owasp_ids
PipelineContext.owasp_ids
  ↓
Stage 4: config_owasp_ids
  ↓
AttackPlan.owasp_id
  ↓
Stage 5: run_adaptive_scenario_async(owasp_id=...)
  ↓
build_memory_labels(owasp_id=..., exam_id=...)
  ↓
memory_labels → scenario.set_params_from_args(memory_labels=...)
  ↓
AttackResult.memory_labels["owasp_id"]
  ↓
Stage 6: extract_tech_stats_from_results → tech_stats
  ↓
Stage 7: generate_report → OWASP Findings
```

---

## 6. 文件变更清单

### 6.1 新增文件 (3 个)

| 文件 | 功能 |
|------|------|
| `src/scenarios/converter_health_monitor.py` | L2 韧性: Converter 熔断器 |
| `src/scenarios/empirical_asr_store.py` | Tier 2 ASR: 经验 ASR 持久化 |
| `src/scenarios/runtime_stop_handler.py` | L3 韧性: 运行时停止 EventHandler |

### 6.2 修改文件 (8 个)

| 文件 | 变更说明 |
|------|----------|
| `pipeline/context.py` | 新增字段: empirical_asr_data, warm_start_asr, converter_chains (从 Stage 5 移入), converter_health_monitor, stop_context, tech_stats, patched_techniques, strategy_recommendations |
| `pipeline/__init__.py` | 8 阶段 → 7 阶段, 删除 s5_matching 调用, 重新编号 |
| `pipeline/stages/s2_analysis.py` | 新增 ASR 经验加载 + Patched 检测 + 策略建议 |
| `pipeline/stages/s3_targets.py` | 合并原 Stage 5a Converter 路由 + 健康监控器初始化 |
| `pipeline/stages/s6_execute.py` | 合并原 Stage 5b/5c 执行策略展示 + 阶段编号 6→5 |
| `pipeline/stages/s7_post_analysis.py` | 新增 ASR 经验写回 + 停止策略统计 + 阶段编号 7→6 |
| `pipeline/stages/s8_report.py` | 阶段编号 8→7 |
| `src/scenarios/__init__.py` | 导出 3 个新模块的 16 个公共 API |

### 6.3 未修改文件 (保持不变)

- `pipeline/stages/s0_init.py` — 初始化 (无变化)
- `pipeline/stages/s1_recon.py` — 侦察 (无变化)
- `pipeline/stages/s4_datasets.py` — 数据载荷 (无变化)
- `src/scenarios/adaptive_runner.py` — 执行入口 (无变化)
- `src/scenarios/ai300_adaptive_scenario.py` — AdaptiveScenario (无变化)
- `src/payloads/asr_prior_registry.py` — Tier 1 学术先验 (无变化)

---

## 7. 三级输出策略

| 级别 | 目标 | 内容 | 位置 |
|------|------|------|------|
| Summary | 快速概览 | 成功率、执行时间、关键发现 | stdout (始终显示) |
| Detailed | 诊断信息 | 技术排序、失败路由、Converter 矩阵、逐载荷结果 | stdout (始终显示) |
| Verbose | 完整细节 | 成功攻击对话、评分详情 | stdout (--verbose) + 日志文件 |

---

## 8. 设计哲学

### 8.1 原生优先

- 最大化使用 PyRIT 1.0.0 原生 API
- AdaptiveScenario + EpsilonGreedyTechniqueSelector + CentralMemory
- 仅在原生无法满足时自建 (Converter 熔断器、经验 ASR)

### 8.2 数据驱动

- ASR 三层数据驱动技术选择
- 经验 ASR 自动 warm-start 下次运行
- Patched 技术自动检测并降级

### 8.3 攻击成功率首要

- 高 ASR 技术优先执行 (Tier S → A → B → C → D)
- Converter 变体渐进式升级 (FIRST_SUCCESS)
- 熔断器避免重复失败, 释放资源给有效技术

### 8.4 可观测性

- 每阶段结构化展示卡片
- ASR 实测 vs 学术先验对比
- 经验 ASR 更新摘要
- 运行时停止策略统计

---

## 9. 验证结果

| 检查项 | 结果 |
|--------|------|
| 单元测试 | 1261 passed |
| Ruff 检查 | 0 errors |
| __pycache__ 清理 | ✓ |
| 新模块导入验证 | ✓ |
| Pipeline 导入验证 | ✓ |
| 阶段编号一致性 | ✓ (7 阶段) |

---

*本文档为 v8.0 优化后架构的完整记录，覆盖 7 阶段 Pipeline、ASR 三层数据架构、五层韧性体系、数据流完整性验证。*
