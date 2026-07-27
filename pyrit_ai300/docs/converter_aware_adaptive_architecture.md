# Converter-Aware Adaptive Architecture — 原生优先 Converter 升级架构

> 版本: 1.0.0 | 日期: 2026-07-27

## 1. 架构概述

本文档描述 AI-300 项目的 **Converter-Aware Adaptive Architecture** — 通过原生 PyRIT 机制实现 Converter 渐进式升级，消除自建 `AttackUpgradeStrategy` 双轨。

### 1.1 设计原则

| 原则 | 描述 |
|------|------|
| **原生优先** | 使用 PyRIT 原生 `AdaptiveScenario` + `AdaptiveTechniqueDispatcher` + `SequentialAttack(FIRST_SUCCESS)` |
| **消除双轨** | 移除自建 `AttackUpgradeStrategy` 的多候选递归逻辑，依赖原生 `FIRST_SUCCESS` 提前停止 |
| **保留自建** | `per_attack_timeout`（PyRIT 无 per-attack 超时）+ OWASP 映射（通过 `memory_labels`） |

### 1.2 核心架构

```
┌─────────────────────────────────────────────────────────────┐
│                    pipeline.py (P3)                          │
│  USE_ADAPTIVE_SCENARIO=true → run_adaptive_scenario_async() │
└────────────────────────┬────────────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────────┐
│              adaptive_runner.py (P3+P4)                      │
│  1. register_ai300_techniques(include_variants=True)        │
│  2. AI300AdaptiveScenario(converter_target=judge_target)    │
│  3. scenario.initialize_async() + run_async()               │
│  4. per_attack_timeout 包裹 (asyncio.wait_for)              │
│  5. _convert_native_to_batch_result() (向后兼容)             │
└────────────────────────┬────────────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────────┐
│           AI300AdaptiveScenario (P2)                         │
│  extends AdaptiveScenario                                    │
│  ├─ _get_attack_technique_factories() ← 覆盖                │
│  │   └─ build_converter_variant_factories() (P0)            │
│  ├─ FailureTypeRoutingSelector (P1)                         │
│  │   └─ Converter 变体感知排序                               │
│  └─ per_attack_timeout (自建保留)                            │
└────────────────────────┬────────────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────────┐
│         原生 AdaptiveTechniqueDispatcher                     │
│  ├─ SequentialAttack(FIRST_SUCCESS)                         │
│  │   ├─ base technique (无 Converter)                       │
│  │   ├─ base+stealth_evasion (Converter 变体)                │
│  │   ├─ base+encoding_bypass (Converter 变体)                │
│  │   └─ base+llm_assisted (Converter 变体, 需 LLM)           │
│  └─ 成功即停止 ← 天然替代自建递归升级                          │
└─────────────────────────────────────────────────────────────┘
```

## 2. P0: Converter-Aware TechniqueBundle 注册

### 2.1 设计

为每个基础攻击技术注册多个 **Converter 变体**作为独立的 `AttackTechniqueFactory`，将 `AttackConverterConfig` 烘焙到 `attack_kwargs` 中。

### 2.2 Converter 变体链

| 链名 | 优先级 | 需要 LLM | 描述 |
|------|--------|---------|------|
| `stealth_evasion` | 1 | 否 | Unicode 混淆 + Base64 + 后缀追加 |
| `encoding_bypass` | 2 | 否 | Base64 + ROT13 + Caesar 编码绕过 |
| `llm_assisted` | 3 | 是 | 说服 + 语气 + 翻译 (LLM 辅助) |
| `persuasion_chain` | 4 | 是 | 说服攻击链 (LLM 辅助) |

### 2.3 适用基础技术

仅单轮技术适合追加 Converter（多轮技术内部已有 adversarial chat 迭代）：

- `prompt_sending` → stealth_evasion, encoding_bypass, llm_assisted
- `many_shot` → stealth_evasion, encoding_bypass
- `skeleton_key` → stealth_evasion, encoding_bypass
- `chunked_request` → encoding_bypass
- `multi_prompt_sending` → encoding_bypass

### 2.4 命名规则

变体名称格式: `{base_technique}+{converter_chain}`

示例: `prompt_sending+stealth_evasion`, `many_shot+encoding_bypass`

### 2.5 关键函数

```python
# 构建变体工厂
build_converter_variant_factories(converter_target=None) -> List[AttackTechniqueFactory]

# 注册时包含变体
register_ai300_techniques(tags=["all"], include_variants=True, converter_target=target)

# 工具函数
is_converter_variant("prompt_sending+stealth_evasion")  # True
get_base_technique_from_variant("prompt_sending+stealth_evasion")  # "prompt_sending"
get_converter_chain_from_variant("prompt_sending+stealth_evasion")  # "stealth_evasion"
```

## 3. P1: FailureTypeRoutingSelector Converter 感知排序

### 3.1 路由策略

| 失败类型 | 排序策略 | 原理 |
|---------|---------|------|
| `model_refusal` | Converter 变体优先（按链优先级排序）| 编码/混淆绕过内容过滤 |
| `timeout` | 基础单轮技术优先（无 Converter）| 减少转换开销和执行时间 |
| `objective_not_achieved` | 强技术 + Converter 变体优先 | 多轮升级 + 编码绕过 |
| `scorer_validation_error` | 保持 epsilon-greedy 默认排序 | 技术多样性 |
| `None`（首次） | Converter 变体 + 编码技术优先 | 快速高成功率 |

### 3.2 Converter 链优先级排序

当多个 Converter 变体同时存在时，按 `CONVERTER_VARIANT_CHAINS` 中的 `priority` 字段排序：

```
stealth_evasion (priority=1) < encoding_bypass (priority=2) < llm_assisted (priority=3) < persuasion_chain (priority=4)
```

## 4. P2: AI300AdaptiveScenario Converter 变体集成

### 4.1 覆盖 `_get_attack_technique_factories()`

```python
class AI300AdaptiveScenario(AdaptiveScenario):
    def _get_attack_technique_factories(self):
        # 1. 获取原生基础技术工厂
        base_factories = super()._get_attack_technique_factories()
        # 2. 追加 Converter 变体工厂
        variant_factories = build_converter_variant_factories(
            converter_target=self._converter_target,
        )
        # 3. 合并（不覆盖已有的）
        for factory in variant_factories:
            if factory.name not in base_factories:
                base_factories[factory.name] = factory
        return base_factories
```

### 4.2 原生 FIRST_SUCCESS 自动停止

原生 `AdaptiveTechniqueDispatcher` 构建 `SequentialAttack(FIRST_SUCCESS)`：
- 按 selector 排序尝试多个技术（含 Converter 变体）
- **成功即停止**（提前停止）
- 成本 O(max_attempts × objectives) 而非 O(techniques × objectives)

## 5. P3: pipeline.py 原生优先执行路径

### 5.1 执行路径选择

```python
use_adaptive_path = os.getenv("USE_ADAPTIVE_SCENARIO", "true").lower() in ("1", "true", "yes")

if use_adaptive_path:
    # 原生 AdaptiveScenario 路径（默认）
    adaptive_result = await run_adaptive_scenario_async(...)
    batch_result = adaptive_result.batch_result
elif fallback_strategy != FallbackStrategy.PARALLEL and fallback_chain:
    # 降级链执行路径（向后兼容）
    ...
else:
    # 直接批量执行（旧版兼容）
    ...
```

### 5.2 环境变量

| 变量 | 默认 | 描述 |
|------|------|------|
| `USE_ADAPTIVE_SCENARIO` | `true` | 使用原生 AdaptiveScenario 路径 |

## 6. P4: per_attack_timeout 包裹 + 向后兼容

### 6.1 per_attack_timeout（自建保留）

PyRIT 原生无 per-attack 超时，通过 `asyncio.wait_for` 补充：

```python
if per_attack_timeout > 0:
    native_result = await asyncio.wait_for(
        scenario.run_async(),
        timeout=per_attack_timeout,
    )
```

### 6.2 结果转换（向后兼容）

`_convert_native_to_batch_result()` 将原生 `ScenarioResult` 转换为 `BatchAttackResult`：
- 从 `get_display_groups()` 提取攻击结果
- 统计成功/失败/错误
- 保持 `BatchAttackResult` 接口不变

### 6.3 ScenarioResultBridge 增强

`ScenarioResultBridge` 保存 `_native_result` 引用，使 `output_scenario_async` 可直接使用原生 `ScenarioResult`。

## 7. 消除双轨对照表

| 自建逻辑 | 原生替代 | 状态 |
|---------|---------|------|
| `AttackUpgradeStrategy.generate_upgrade_plans()` | `AdaptiveTechniqueDispatcher` 自动构建 | ✅ 消除 |
| `AttackUpgradeStrategy._add_converter()` | Converter 变体预注册 + `FIRST_SUCCESS` | ✅ 消除 |
| `ScenarioOrchestrator._try_upgrade_plans()` 递归 | `SequentialAttack(FIRST_SUCCESS)` 提前停止 | ✅ 消除 |
| `extract_failure_type()` → `add_converter` 路由 | `FailureTypeRoutingSelector` Converter 感知排序 | ✅ 消除 |
| `upgrade_strategy.py` 配置加载 | `CONVERTER_VARIANT_CHAINS` 常量 | ✅ 消除 |
| `per_attack_timeout` | PyRIT 无此功能 | 🔒 保留自建 |
| OWASP 映射 | 通过 `memory_labels` 集成 | 🔒 保留自建 |

## 8. 文件变更清单

| 文件 | 变更类型 | 描述 |
|------|---------|------|
| `src/scenarios/technique_factories.py` | 修改 | P0: 新增 Converter 变体工厂构建 |
| `src/scenarios/failure_type_selector.py` | 重写 | P1: Converter 感知排序增强 |
| `src/scenarios/ai300_adaptive_scenario.py` | 重写 | P2: 覆盖 `_get_attack_technique_factories` |
| `src/scenarios/adaptive_runner.py` | 新增 | P3+P4: 原生执行入口 + 结果转换 |
| `src/scenarios/__init__.py` | 修改 | 导出新 API |
| `pipeline.py` | 修改 | P3: 原生 AdaptiveScenario 执行路径 |
| `tests/unit/test_converter_aware_adaptive.py` | 新增 | 33 个测试覆盖 P0-P4 |
| `docs/converter_aware_adaptive_architecture.md` | 新增 | 本文档 |
