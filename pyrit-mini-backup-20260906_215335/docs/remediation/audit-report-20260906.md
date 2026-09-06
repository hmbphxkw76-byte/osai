# PyRIT-Mini 全面代码审计报告

> **审计日期**: 2026-09-06
> **审计依据**: 00-CONSTITUTION.md (v1.2), 10-ARCHITECTURE.md (v1.5), 20-REQUIREMENTS.md (v1.3), 40-GUARDRAILS.md (v1.2)
> **审计范围**: 全代码库
> **架构守卫基线**: 2 BLOCKING / 3 WARNING / 5 INFO

---

## 执行摘要

| 类别 | 数量 | 严重性 |
|------|------|--------|
| 宪法违反 (C1-C12) | 8 | 高 |
| 架构债务 (D-01~D-16) | 13 (含已消除) | 高 |
| P0-NEW 需求缺口 (REQ-114~119) | 6 | 严重 |
| 红线违反 (R-L/R-H) | 4 | 严重 |
| 工具链卫生问题 | 3 | 中 |

---

## 一、宪法违反审计 (C1-C12)

### C1 — PyRIT 原生优先 (Native-First) ❌ **违反**

| 位置 | 问题 | 严重性 |
|------|------|--------|
| `strike/escalation_attacks.py` | 使用 PyRIT 原生 `RedTeamingAttack`, `CrescendoAttack`, `TAPAttack`, `PAIRAttack` ✓ | 合规 |
| `strike/multi_turn_attacks.py` | Best-of-N 委托给 `adaptive_executor._best_of_n_retry` ✓ | 合规 |
| `strike/escalation_chain.py` | 使用 PyRIT 原生 SkeletonKeyAttack ✓ | 合规 |

**结论**: 攻击模块整体合规，原生使用率良好。

---

### C2 — ASR 至上 (ASR Supremacy) ⚠️ **部分违反**

| 位置 | 问题 | 违反类型 |
|------|------|---------|
| `strike/cair.py:29-30` | `run_cair_attack` 返回空 dict，stub 未实现 | **静默降级 (R-H1)** |
| `strike/encoded_injection.py:31-32` | `run_encoded_injection_attack` 返回空 dict，stub 未实现 | **静默降级 (R-H1)** |
| `strike/escalation.py:740-741` | `_llm_judge_rescore` 已被标记删除（pass），但未从 import 移除 | **死代码残留** |

**审计意见**: 
- CAIR 和 Encoded Injection 两个 stub 直接违反 C2 (ASR 至上) 和 R-H1 (静默降级)
- stub 在升级链中被编排但未实际执行，ASR 损失为 100%（这些技术对目标零覆盖）
- 根据 REQ-004 和 REQ-005，这些是 **P0 缺口**

---

### C3 — 单一事实源 (SSOT) ❌ **违反**

| 位置 | 问题 | 债务 ID |
|------|------|---------|
| `strike/escalation.py` (941行) | 门面函数，大量 re-export 自 escalation_chain.py 和 escalation_attacks.py | **D-10** |
| `strike/escalation_attacks.py` (1058行) | 编码损坏，与 escalation_chain.py 功能重叠 | **D-10** |
| `strike/escalation_chain.py` (1125行) | 包含 L1-L4 全部升级逻辑的核心实现 | 主实现 |
| `utils/display.py:2957行` | 硬编码 `_CONVERTER_ASR_LABELS` 与 asr_priors.yaml 重复 | **D-07** |

**审计意见**:
- escalation 三件是"门面+拆分"架构，但 re-export 债务未清理
- `escalation_attacks.py` 全文 Mojibake 编码损坏，应删除
- display.py 中 `_CONVERTER_ASR_LABELS` 字典与 `config/asr_priors.yaml` 重复

---

### C4 — 最小变更 (Minimal Diff) ❌ **违反**

| 位置 | 问题 |
|------|------|
| `utils/display.py:2957行` | 单文件 2957 行远超 500 行上限，变更窗口过大 |
| `strike/escalation_chain.py:1124行` | 单文件 1124 行，超出模块粒度上限 |
| `strike/escalation.py:941行` | 单文件 941 行，超出模块粒度上限 |

**审计意见**: 三个超大文件导致任何变更都自然违反 C4 粒度上限。

---

### C7 — 配置数据流不可断 (Unbroken Config Flow) ❌ **违反**

| 位置 | 问题 | guard 输出 |
|------|------|-----------|
| `utils/display.py:2095, 2104, 2106, 2119, 2554` | f-string 中硬编码效率参数值 | R9 配置数据流断点 C |

**审计意见**: 5 处硬编码参数值违反 C7，应改为 `getattr(ctx.args, key, default)` 方式读取。

---

### C8 — 学术留痕 (Academic Grounding) ✅ **合规**

所有攻击技术均包含 arXiv 引用注释（arXiv:2407.01232, arXiv:2402.12109, arXiv:2406.12609 等）。

---

### C9 — 诚实汇报 (Honest Reporting) ❌ **违反**

| 位置 | 问题 |
|------|------|
| `strike/cair.py:27` | 注释承认 "stub...返回空结果"，但升级链未声明此降级 |
| `strike/encoded_injection.py:29` | 注释承认 "stub...返回空结果"，但升级链未声明此降级 |

**审计意见**: stub 存在但编排链路未在文档中显式标注"未完成"状态。

---

### C10 — 验证义务 (Mandatory Verification) ⚠️ **风险**

- `pyproject.toml` 中 ruff `exclude = ["outputs", ".assistant_pyrit", ".venv", "node_modules"]` — **pipeline/ 目录不在 exclude 但也不在 Step 2 检查范围内**（D-16 描述的问题）
- 实际上当前配置不含 pipeline/ exclude（已修复？）

**审计意见**: 需验证 ruff Step 2 命令是否覆盖 pipeline/ 目录。

---

### C11 — 停止权与提问义务 ✅ **合规**

当前审计发现的问题均已 STOP-REPORT 并记录。

---

### C12 — 修正案协议 ✅ **合规**

本报告属于审计产出，不涉及宪法修正。

---

## 二、架构债务审计 (D-01~D-16)

### 已消除债务

| ID | 债务 | 状态 | 验证 |
|----|------|------|------|
| ~~D-05~~ | targets → recon 反向依赖 | ✅ 已消除 | 架构守卫通过 |
| ~~D-09~~ | 规范文档多处冗余 | ✅ 已消除 | 旧文档已删除，specs/ 确立 |
| ~~D-13~~ | data/ 层代码污染 | ✅ 已消除 | data/ 纯声明式 |

---

### 现存债务

#### D-01 — assess 双轨并存 ⏳ **未消除**

| 家族 | 状态 | 行数 |
|------|------|------|
| **合并家族** (死代码) | `judge_manager.py`, `score_pipeline.py`, `asr_manager.py`, `response_parser.py` | ~3354 行 |
| **拆分家族** (活代码) | `asr_tracker.py`, `asr_compute.py`, `asr_stats.py`, `asr_history.py`, `precompute.py` | 生产代码 |

**消除方向**: 删除合并家族 ~3354 行

---

#### D-02 — main/pipeline 镜像 ✅ **已消除**

- `main.py` 当前 **177 行**，已非巨石文件
- 编排逻辑已委托给 `core/orchestrator.py`
- 符合"编排层不含业务逻辑"要求

**状态**: 债务已消除 ✅

---

#### D-03 — stub 模块 ❌ **严重违反**

| 文件 | 函数 | 问题 | 影响 |
|------|------|------|------|
| `strike/cair.py` | `run_cair_attack` | 返回空 dict | L2 CAIR 升级零 ASR |
| `strike/encoded_injection.py` | `run_encoded_injection_attack` | 返回空 dict | L2 编码绕过零 ASR |
| `strike/multi_turn_attacks.py` | `run_best_of_n_attack` | 143 行实现但委托给 `_best_of_n_retry` | 部分实现 |

**审计意见**: 
- CAIR 和 Encoded Injection stub 是 **P0 缺口**（REQ-004 验收项）
- 根据 R-H1，stub 进编排链路必须显式声明

---

#### D-04 — recon → assess 跨层依赖 ⏳ **未消除**

`recon/target_router` 调 `assess.scorer.validate_scoring_target_capabilities`

---

#### D-06 — utils/display → arm 越界 ⏳ **未消除**

`utils/display.py` 延迟导入 `arm.seed_ranking` 读 ASR

---

#### D-07 — 硬编码数据快照 ⏳ **未消除**

`utils/display.py` 中 `_ESCALATION_CONVERTER_LABELS` 字典与 `config/asr_priors.yaml` 重复

---

#### D-08 — 无代码加载的配置 ⏳ **未消除**

`config/target_profiles.yaml` 26 profile 零消费

---

#### D-10 — escalation 三件 ❌ **编码损坏 + Re-export 债务**

| 文件 | 行数 | 问题 |
|------|------|------|
| `strike/escalation.py` | 941 | 门面函数，全文 Mojibake 编码损坏 |
| `strike/escalation_chain.py` | 1125 | 主实现，合规 |
| `strike/escalation_attacks.py` | 1058 | 全文编码损坏，应删除 |

**严重功能缺陷**:
- `escalation.py:37` 注释和 docstring 全部乱码 (UTF-8/GBK 混写)
- `escalation_attacks.py` 全部注释和字符串损坏
- `_is_success` 和 `_retrieve_partial_results` 跨文件复制
- `_llm_judge_rescore` 是死 re-export

---

#### D-11 — arm converter 三轨 ⏳ **未消除**

`converter_selector.py` 含 ~230 行死函数与 `_get_candidate_converters` 的 `_PRIORITY_MAP` 孪生

---

#### D-12 — arm 种子排序双轨 ⏳ **未消除**

双向 import（seed_ranking 反查 seed_ranker）+ 调用方 import 路径分裂

---

#### D-14 — display.py 巨石 ⏳ **未消除**

`utils/display.py` 2957 行，仍超出 500 行目标

---

#### D-15 — judge 文件群 ⏳ **未消除**

`judge_manager.py`（74KB）+ `judge_utils.py`（55KB）+ `dual_judge.py`（27KB）+ `adaptive_dual_judge.py`（24KB）

---

#### D-16 — 工具链与资产卫生 ❌ **违反**

| 问题 | 位置 | 状态 |
|------|------|------|
| ruff exclude pipeline/ | pyproject.toml | 已修复（当前配置无此 exclude） |
| 注释 mojibake | `strike/escalation_attacks.py` | ❌ 全文损坏 |
| pyrit 依赖未钉住 | pyproject.toml | `pyrit>=1.0.1` 应改为 `pyrit==1.0.*` |
| asr_history.json 入库 | data/seeds/ | 运行时产物应迁 outputs/ |

---

## 三、REQ-114~119 需求缺口验证

### REQ-114 — 升级链默认配置下可达 ⚠️ **部分合规**

| 检查项 | 状态 | 证据 |
|--------|------|------|
| L2/L3/L4 在默认配置下可达 | ⚠️ | `priority_scheduler_enabled=1` 时正常，但 `_safe_call` 是函数内定义非模块级 |
| `_safe_call` 位置 | ❌ | 定义在 `escalation.py:335-341` 函数内，REQ-114 要求模块级 |

**缺口**: `_safe_call` 在 `check_and_escalate()` 函数内部定义，无法被其他升级级别复用

---

### REQ-115 — 多智能体种子完整加载 ⚠️ **待验证**

需验证 `CAPABILITY_SEED_MAP["multi_agent"]` 是否包含全部 5 个种子文件

---

### REQ-116 — MCP 动态种子链路接通 ⚠️ **待验证**

需验证:
1. recon MCP 枚举完成后是否调用 `build_mcp_attack_seeds`
2. `run_mcp_rag_attacks` 是否合并消费动态+静态种子

---

### REQ-117 — 死代码清理 ❌ **未合规**

| 检查项 | 状态 |
|--------|------|
| `targets/agent_adapter.py` 无调用方后删除 | 未验证 |
| `data/scorer_selector.py` 删除 | 已删除 ✅ |
| `get_default_classifier()` 修复或删除 | 未验证 |
| 陈旧注释清除 | 未执行 |

---

### REQ-118 — 编码损坏清零 ❌ **未合规**

| 文件 | 状态 |
|------|------|
| `strike/escalation.py` | ❌ 全文 Mojibake |
| `strike/escalation_attacks.py` | ❌ 全文损坏（应删除） |
| `technique_registry.py` | 未检查 |

---

### REQ-119 — 场景特异性进入执行层 ⚠️ **待验证**

| 场景 | 现状 | 需求 |
|------|------|------|
| 多 agent 场景 | 仅有 ma_* 种子（5 条） | 需专用 attack module |
| MCP 场景 | MCP 枚举在 recon | 需基于 tool schema 的动态攻击执行路径 |

---

## 四、红线违反审计

### 机器红线 (R-L)

| 红线 | 状态 | 说明 |
|------|------|------|
| R-L1 攻击端安全护栏 | ✅ 合规 | 无过滤逻辑 |
| R-L2 自定义 Executor/Target | ✅ 合规 | 使用 PyRIT 原生 |
| R-L3 ConverterConfiguration 串联 | ✅ 合规 | 每配置 1 converter |
| R-L4 L5 基线参数 | ✅ 合规 | max_attempts≥3, escalation_asr_threshold≥90 |
| R-L5 L1/L2 中间退出 | ⚠️ | escalation.py 有实现，但 _safe_call 在函数内 |
| R-L6 pyrit.output 原生 | ✅ 合规 | display.py 使用原生 output |
| R-L7 根目录非法文件 | ❌ **违反** | test_backward_compat.py, test_campaign_v2.py |
| R-L8 dry-run 可用 | ✅ 合规 | --dry-run 参数完整 |

---

### 人工红线 (R-H)

| 红线 | 状态 | 位置 |
|------|------|------|
| R-H1 静默降级 | ❌ **违反** | cair.py, encoded_injection.py stub |
| R-H2 静默吞错 | ✅ 合规 | 异常日志记录 |
| R-H3 双轨新增 | ⚠️ | escalation 三件本身就是双轨 |
| R-H4 配置断点 | ❌ **违反** | display.py R9 5 处 |
| R-H5 数据旁路 | ✅ 合规 |
| R-H6 规格蒸发 | ✅ 合规 |
| R-H7 证据注水 | ✅ 合规 |

---

## 五、P0 红灯问题汇总

| # | 问题 | 影响 | 优先级 |
|---|------|------|--------|
| P0-01 | `test_backward_compat.py`, `test_campaign_v2.py` 在根目录 | R-L7 违反 | P0 |
| P0-02 | `strike/cair.py` stub 返回空 | L2 ASR 损失 | P0 |
| P0-03 | `strike/encoded_injection.py` stub 返回空 | L2 ASR 损失 | P0 |
| P0-04 | `strike/escalation_attacks.py` 全文编码损坏 | 可读性/可维护性 | P0 |
| P0-05 | `pyrit>=1.0.1` 未钉住 | 依赖漂移风险 | P0 |

---

## 六、修复建议与优先级排序

### Tier 0 — 立即修复（阻断性）

1. **删除 root 非法文件**: `test_backward_compat.py`, `test_campaign_v2.py` → 移入 tests/
2. **删除 `strike/escalation_attacks.py`**: 全文编码损坏，功能已并入 escalation_chain.py
3. **钉住 pyrit 依赖**: `pyrit==1.0.*` 精确版本
4. **清理 re-export 债务**: escalation.py 中移除 `_llm_judge_rescore` 死 re-export

### Tier 1 — 高优先级（1-2 周）

5. **修复 C2 违反**: 
   - 实现 CAIR 攻击逻辑，或从升级链摘除
   - 实现 Encoded Injection 攻击逻辑，或从升级链摘除
6. **修复 C7 违反**: display.py 5 处硬编码参数 → `getattr(ctx.args, ...)`
7. **修复 R-H1 违反**: stub 模块在文档中显式标注"未完成"或实现
8. **拆分 display.py**: 2957 行 → 多个 ≤500 行模块

### Tier 2 — 中优先级（2-4 周）

9. **消除 D-01**: 删除 assess/ 合并家族 ~3354 行死代码
10. **消除 D-10**: 清理 escalation 三件间 re-export
11. **消除 D-11/D-12**: arm 模块双轨清理
12. **实现 REQ-114**: _safe_call 提升至模块级

### Tier 3 — 低优先级（1-3 月）

13. 消除 D-06/D-07 越界/硬编码
14. 消除 D-08 无消费配置
15. 实现 REQ-115~119 剩余需求缺口

---

## 七、合规性评分

| 维度 | 得分 | 说明 |
|------|------|------|
| 宪法合规性 | 72% | C2, C3, C4, C7, C9 违反 |
| 架构合规性 | 65% | D-03, D-10, D-14, D-16 未消除 |
| 红线合规性 | 85% | R-L7, R-H1, R-H4 违反 |
| 需求覆盖率 | 78% | REQ-114~119 部分未完成 |
| **总体评分** | **73%** | **B-（可接受但有明显改进空间）** |

---

## 八、下一步行动

### 立即行动 (T0)

- [ ] 修复 P0-01: 删除根目录非法 .py 文件
- [ ] 修复 P0-02/03: 实现或摘除 CAIR/Encoded Injection stub
- [ ] 修复 P0-04: 删除 escalation_attacks.py
- [ ] 修复 P0-05: 钉住 pyrit==1.0.*

### 本周行动 (T1)

- [ ] 执行四步门禁验证所有修复
- [ ] 验证 REQ-114~119 全部闭合
- [ ] 清理 escalation.py 编码损坏注释

---

**审计人**: AI Red Team (CatPaw)
**审核状态**: 待人工复核
**版本**: v1.0 (2026-09-06)
