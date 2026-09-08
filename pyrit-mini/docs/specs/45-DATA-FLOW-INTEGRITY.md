# 45 — 数据流完整性规约（Data Flow Integrity Specification）

> **文档层级**：L3 / 五层规约金字塔第三层（架构层）
> **效力**：BLOCKING 级别 — 所有模块修改必须通过数据流完整性验证，未通过视为合入失败
> **执行机制**：三层防线（git hook 自动验证 / architecture_guard R-DATA-1 规则 / pytest 自动化测试）
> **版本**：v1.0（2026-09-08 初始版本，定义 ARM→Strike→Assess 主攻击链数据流契约）

---

## 第一章：数据流架构概述

### 1.1 主攻击链数据流拓扑

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        PipelineContext (数据总线)                            │
│                   _SINGLE_SOURCE_OF_TRUTH_ 唯一状态容器                        │
├────────────┬────────────┬────────────┬────────────┬─────────────────────────┤
│   Recon    │    ARM     │   Strike   │   Assess   │        Report           │
│            │            │            │            │                         │
│ objective_ │   seeds    │  attack_   │  asr_per_  │  final_report          │
│ target     │ techniques │  results──→│  technique │  evidence_collection   │
│ service_   │ converter_ │            │  overall_  │  wilson_ci             │
│ profile ──→│    map     │            │    asr     │  orchestration_log     │
│ target_    │ mcpsec_    │            │  dual_judge│                         │
│ fingerprint│ surface    │            │   _stats   │                         │
└────────────┴────────────┴────────────┴────────────┴─────────────────────────┘
```

### 1.2 核心原则

| 原则 | 说明 |
|------|------|
| **SSOT** | PipelineContext 是唯一数据总线，禁止阶段间直接私下传递数据 |
| **契约化** | 每个 Phase 边界必须满足字段契约（类型 + 非空约束） |
| **快照可验证** | 每个阶段结束时生成快照，支持事后审计与回溯 |
| **失败显式化** | 任何数据传递断点必须显式报告，禁止静默降级 |

---

## 第二章：Phase 字段契约

### 2.1 Recon Phase 输出契约 (post_recon)

| 字段名 | 类型 | 约束 | 说明 |
|--------|------|------|------|
| `ctx.objective_target` | Target | not_none | 攻击目标实例 |
| `ctx.parsed_request.target_fingerprint` | dict | not_empty | 目标指纹（model_family/language/capabilities） |
| `ctx.service_profile` | dict | not_empty | 服务画像（model_name/auth_type/rag_kb_map） |
| `ctx.orchestration_log` | list | append("recon") | 审计日志必须包含 recon 阶段 |

**消费端**: ARM 阶段（通过 `ctx.parsed_request.target_fingerprint.model_family` 选择种子策略）

### 2.2 ARM Phase 输出契约 (post_arm)

| 字段名 | 类型 | 约束 | 说明 |
|--------|------|------|------|
| `ctx.seeds` | list[AttackSeed] | len > 0 | 攻击种子列表 |
| `ctx.techniques` | list[str] | len > 0 | 攻击技术列表 |
| `ctx.converter_map` | dict[str, list] | len > 0 | 技术→转换器映射 |
| `ctx.orchestration_log` | list | append("arm") | 审计日志必须包含 arm 阶段 |

**消费端**: Strike 阶段（executor.py 遍历 `ctx.seeds` 和 `ctx.converter_map`）

### 2.3 Strike Phase 输出契约 (post_strike)

| 字段名 | 类型 | 约束 | 说明 |
|--------|------|------|------|
| `ctx.attack_results` | dict[str, list] | len > 0 | 技术→攻击结果列表映射 |
| `ctx.orchestration_log` | list | append("strike") | 审计日志必须包含 strike 阶段 |

**消费端**: Assess 阶段（遍历 `ctx.attack_results` 计算 ASR）

### 2.4 Assess Phase 输出契约 (post_assess)

| 字段名 | 类型 | 约束 | 说明 |
|--------|------|------|------|
| `ctx.asr_per_technique` | dict[str, float] | len > 0 | 各技术 ASR |
| `ctx.overall_asr` | float | [0, 100] | 总体 ASR 百分比 |
| `ctx.dual_judge_stats` | dict | not_none | 双评判统计（total_scored/cohens_kappa） |
| `ctx.wilson_ci` | tuple | len == 2 | 威尔逊置信区间 |
| `ctx.orchestration_log` | list | append("assess") | 审计日志必须包含 assess 阶段 |

**消费端**: Report 阶段（生成报告、导出证据）

---

## 第三章：数据传递规则

### 3.1 强制规则（R-DATA-1 ~ R-DATA-10）

| 规则 ID | 名称 | 级别 | 验证内容 |
|---------|------|------|----------|
| R-DATA-1 | service_profile 传递 | BLOCKING | Recon→ARM: `ctx.service_profile` 非空且包含 model_name |
| R-DATA-2 | target_fingerprint 传递 | BLOCKING | Recon→ARM: `ctx.parsed_request.target_fingerprint` 存在 |
| R-DATA-3 | seeds 传递 | BLOCKING | ARM→Strike: `ctx.seeds` 列表长度 > 0 |
| R-DATA-4 | converter_map 传递 | BLOCKING | ARM→Strike: `ctx.converter_map` 包含已选技术的映射 |
| R-DATA-5 | techniques 传递 | BLOCKING | ARM→Strike: `ctx.techniques` 列表长度 > 0 |
| R-DATA-6 | attack_results 传递 | BLOCKING | Strike→Assess: `ctx.attack_results` 包含所有技术的攻击结果 |
| R-DATA-7 | asr_per_technique 计算 | BLOCKING | Assess→Report: `ctx.asr_per_technique` 覆盖所有攻击技术 |
| R-DATA-8 | overall_asr 范围 | BLOCKING | Assess→Report: `ctx.overall_asr` ∈ [0, 100] |
| R-DATA-9 | dual_judge_stats 完整 | WARNING | Assess→Report: `ctx.dual_judge_stats` 包含 cohens_kappa |
| R-DATA-10 | orchestration_log 完整 | WARNING | 所有阶段记录存在于 orchestration_log |

### 3.2 跨阶段一致性规则（R-DATA-C1 ~ R-DATA-C3）

| 规则 ID | 名称 | 级别 | 验证内容 |
|---------|------|------|----------|
| R-DATA-C1 | ASR 覆盖一致性 | BLOCKING | `ctx.attack_results` 中的每种技术都出现在 `ctx.asr_per_technique` 中 |
| R-DATA-C2 | 审计日志阶段完整 | WARNING | `orchestration_log` 包含 recon/arm/strike/assess 全部阶段 |
| R-DATA-C3 | 评判统计完整性 | WARNING | `dual_judge_stats` 与 `wilson_ci` 同时非空 |

---

## 第四章：工具链与自动化

### 4.1 核验工具清单

| 工具 | 路径 | 用途 | 执行时机 |
|------|------|------|----------|
| DataFlowValidator | `tools/data_flow_validator.py` | 快照提取 + 规则验证 + 报告生成 | 命令行 / API / pytest |
| data_flow_hooks | `tools/data_flow_hooks.py` | 快照钩子 + 流水线集成 API | 流水线内部调用 |
| test_data_flow_integrity | `tests/test_data_flow_integrity.py` | 25 个自动化测试用例 | pytest / CI |
| Architecture Guard 检查器 | `tools/guard.py` (check_data_flow_integrity) | R-DATA-1 规则 | `py -m tools.guard` |
| Git Hooks | `.git/hooks/pre-commit` + `pre-push` | 自动执行数据流测试 | git commit / push |

### 4.2 命令速查

```bash
# 手动 CLI 演示模式
py tools/data_flow_validator.py

# pytest 全量测试
py -m pytest tests/test_data_flow_integrity.py -v

# Architecture Guard (含 R-DATA-1)
py -m tools.guard

# 审计 orchestration_log
py tools/data_flow_validator.py --log-file outputs/strike_xxx/orchestration_log.json

# 安装/重装 git hooks
py -m tools.install_hooks_local
py -m tools.install_hooks_local --remove
```

---

## 第五章：GitHub Hooks 集成

### 5.1 pre-commit 流程

```bash
git commit → 自动触发:
  [1/2] Data Flow Validator (pytest -q --tb=line)
       └─ 25 个测试验证数据传递
  [2/2] Architecture Guard (py -m tools.guard)
       └─ R-DATA-1 规则 + 19 项架构检查

  结果:
    INFO/PASS → Commit 继续
    WARNING  → Commit 继续 (仅警告)
    BLOCKING → Commit 阻断，提示: py -m tools.guard
```

### 5.2 pre-push 流程

```bash
git push → 自动触发:
  [1/2] Data Flow Validator (全量测试 -v --tb=short)
       └─ 任何测试失败均阻断 push
  [2/2] Architecture Guard (全量检查)

  结果:
    全部 PASS → Push 继续
    任何 BLOCKING → Push 阻断
```

---

## 第六章：流水线集成 API

### 6.1 细粒度控制 (DataFlowValidator)

```python
from tools.data_flow_validator import DataFlowValidator, format_report

validator = DataFlowValidator(ctx)
validator.snapshot("post_recon")   # Recon 完成后
validator.snapshot("post_arm")      # ARM 完成后
validator.snapshot("post_strike")   # Strike 完成后
validator.snapshot("post_assess")   # Assess 完成后
report = validator.validate_all()
print(format_report(report))
```

### 6.2 自动钩子 (snapshot_hook)

```python
from tools.data_flow_hooks import snapshot_hook

# 在 _run_recon_phase 末尾
snapshot_hook(ctx, "post_recon")

# 在 _run_arm_phase 末尾
snapshot_hook(ctx, "post_arm")

# 在 _run_strike_phase 末尾
snapshot_hook(ctx, "post_strike")

# 在 _run_assess_phase 末尾
snapshot_hook(ctx, "post_assess")
```

### 6.3 一键验证 (validate_and_report)

```python
from tools.data_flow_hooks import validate_and_report

# 流水线末尾，生成完整报告
report = validate_and_report(ctx)
logger.info("数据流验证:\n%s", report)
```

### 6.4 快速检查 (validate_quick)

```python
from tools.data_flow_hooks import validate_quick

# 流水线末尾，返回 bool
if not validate_quick(ctx):
    raise RuntimeError("数据流完整性验证失败")
```

---

## 第七章：模块修改检查清单

### 7.1 修改 Recon 模块时的必检项

- [ ] `ctx.service_profile` 仍为非空 dict
- [ ] `ctx.parsed_request.target_fingerprint` 仍包含 model_family
- [ ] `target_fingerprint.model_family` 取值范围不变 (gpt/claude/gemini/deepseek/llama)
- [ ] `orchestration_log` 仍被正确 append

### 7.2 修改 ARM 模块时的必检项

- [ ] `ctx.seeds` 仍为非空 list
- [ ] `ctx.techniques` 仍为非空 list
- [ ] `ctx.converter_map` 的 key 覆盖 `ctx.techniques` 中所有技术
- [ ] `converter_map[key]` 为非空 list

### 7.3 修改 Strike 模块时的必检项

- [ ] `ctx.attack_results` 的 key 覆盖 `ctx.techniques` 中所有技术
- [ ] `attack_results` 中每个 result 有正确的 scorer 结果
- [ ] 攻击失败时 `attack_results` 不丢失 (空 list 而非 missing key)

### 7.4 修改 Assess 模块时的必检项

- [ ] `ctx.asr_per_technique` 的 key 覆盖 `ctx.attack_results` 中所有技术
- [ ] `ctx.overall_asr` ∈ [0, 100]
- [ ] `ctx.dual_judge_stats` 包含 `cohens_kappa`
- [ ] `ctx.wilson_ci` 为长度为 2 的 tuple 且 lower <= upper

---

## 第八章：异常处理与降级

### 8.1 快照机制

每个阶段结束时调用 `snapshot()`，即使阶段内部发生异常，也会捕获当前状态用于诊断：

```python
try:
    await _run_recon_phase(ctx)
except Exception as e:
    logger.error("Recon 阶段失败: %s", e)
    validator.snapshot("post_recon", {"error": str(e)})  # 仍然快照
    raise
```

### 8.2 规则失败分级

| 严重程度 | 处理方式 | 示例 |
|----------|----------|------|
| `BLOCKING` | 阻断流水线 / commit | `ctx.seeds` 为空列表 |
| `WARNING` | 记录日志，流水线继续 | `cohens_kappa` 缺失 |
| `INFO` | 仅记录 | 学术引用提醒 |

### 8.3 快照回放

验证失败时可从快照回放定位断点：

```python
# 失败报告包含每个快照的关键字段值
[post_recon] seeds_count: 0     ← 异常点
[post_arm]   seeds_count: 0     ← 问题根因在此
[post_strike] attack_results_total: 0
[post_assess] asr_techniques_count: 0
```

---

## 第九章：版本记录

| 版本 | 日期 | 变更 |
|------|------|------|
| v1.0 | 2026-09-08 | 初始版本：定义字段契约 4 组、强制规则 10 条、一致性规则 3 条、工具链 5 项 |

---

## 附录 A：字段命名规范

所有快照字段遵循命名规范：

| 前缀 | 含义 | 示例 |
|------|------|------|
| `has_` | 布尔存在性 | `has_objective_target` |
| `_count` | 列表/字典长度 | `seeds_count`, `techniques_count` |
| `_size` | 字典键数量 | `service_profile_size`, `converter_map_size` |
| `_total` | 聚合总数 | `attack_results_total`, `converter_map_total_converters` |
| `_list` | 内容列表 | `techniques_list` |
| `_keys` | 字典键列表 | `attack_results_keys` |

## 附录 B：测试用例清单

25 个自动化测试用例分布：

| 类别 | 数量 | 覆盖内容 |
|------|------|----------|
| TestFieldContracts | 7 | 各阶段输出字段存在性 |
| TestInterPhaseTransfer | 4 | 阶段间数据传递 |
| TestCrossPhaseConsistency | 3 | 跨阶段一致性 |
| TestFullPipeline | 2 | 端到端完整流水线 |
| TestEdgeCases | 4 | 空值/None/边界处理 |
| TestReportFormat | 2 | 报告格式化输出 |
| TestIntegration | 3 | 模块可导入性 |
| **总计** | **25** | |
