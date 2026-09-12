# 变更提案：CP-003（L5 基线参数消费闭合 + 升级链 L1–L4 阶梯实施）

> **类型**：`config/defaults.yaml` 基线变更（NEG-6）+ `20-REQUIREMENTS.md` 需求落点细化
> **提案人 / 日期**：AI 起草 / 2026-09-12（评审人栏待人工签署）
> **状态**：draft → approved（用户会话授权全量实施）/ rejected / deferred
> **关联**：`BL-038`（P0 系统性 C7 死配置）、`BL-031`（技术路由断裂）、`REQ-005`（升级链）、`ADR-005`、`I4`、`R-L5`
> **版本**：v1.0（2026-09-12 初版）

---

## 1. 动机

### 1.1 现状（2026-09-12 实测，可复现）

`config/defaults.yaml` 有 **21 个顶层键**仅被 `core._config_parsers._apply_defaults` 拷进 `args`、代码中零消费者（复现脚本见 BL-038）。其中包含被声明为 **L5 验收锚点**的 `l5_optimal_paths: 7`。

后果（C9 诚实汇报违规）：

- 「L5 基线参数已被消费」这一验收声明**不成立**；
- 操作员改 YAML 数值不改变任何行为（配置通道是装饰品，C7 断链）；
- 终端展示的 `technique_param_labels` 与 PyRIT 实际使用的参数不一致。

### 1.2 三处口径错配（本提案要同时纠正）

| # | 声明 | 代码现实 | 错配性质 |
|---|------|---------|---------|
| A | `l5_optimal_paths: 7`（L5 锚点，注释"PyRIT 最佳 5-7 条独立路径"） | `arm.converter_selector._get_candidate_converters` 硬编码 `[:10]`，典型生效 10 条 | 锚点值从未生效 |
| B | `I4`「中间退出检查点必须在 L1→L2 与 L2→L3 边界」+ `R-L5`（BLOCKING）+ `ADR-005`（L1 分批 → L2-L4 全并行） | `strike.common.escalation_runtime.determine_escalation_strategy` **无 L1–L4 阶梯**：一次只按 ASR 选**一条**策略并只跑该条；`args.escalation_levels_parsed` 零消费者 | 不变量 I4 / ADR-005 未落地；`--escalation-levels L1-L4` 无效 |
| C | `post_l1_exit_threshold: 70` / `post_l2_exit_threshold: 80`（0–100 口径） | 升级链内阈值硬编码 `0.15/0.40/0.65/0.80`（0–1 口径），且 `escalation_asr_threshold: 90` 同为 0–100 口径 | 口径双轨 + 硬编码（C7） |

### 1.3 为什么不能"静默改基线"

NEG-6：L5 基线参数只准上调、不准下调，下调需提案。BL-038 亦要求「(a) 属 L5 参数且接线改变攻击行为者须先提案再接真」。故本提案先行登记，再实施。

---

## 2. 逐键处置（21 键）

### 2.1 接真（13 键）

| 键 | 处置 | 接线点（`模块.符号`） | 基线影响 |
|----|------|---------------------|---------|
| `l5_optimal_paths` | 接真 + **上调 7→10** | `arm.converter_selector._get_candidate_converters` | **上调**（NEG-6 合规）。理由：C2 ASR 至上——多路径 = SequentialAttack 独立子路径 + FIRST_SUCCESS，路径数 10→7 会**降低 ASR 上限**；且 10 才是既有生效行为，上调为"声明对齐现实"而非降能力。多路径边际收益见 Wei et al. arXiv:2307.15043 |
| `max_escalation_targets` | 接真（5→10） | `strike.common.escalation_runtime.run_escalation_chain` 的 `failed_objectives[:5]` | **上调**。升级目标数 5→10 提高 ASR 上限（ADR-005：仅失败目标进入下一级） |
| `post_l1_exit_threshold` / `post_l2_exit_threshold` | **新建能力后接真** | 新增 `escalation_runtime.LADDER` 阶梯 + `_should_exit_ladder` | 不改存量：阶梯默认与现有单策略行为收敛（见 §3.2） |
| `tap_branching` | 接真 | `strike.strategies.params` 增 `"branching_factor": ("tap_branching", 2)`，传入 PyRIT `TAPAttack(branching_factor=...)` | **零变更**：PyRIT 默认 `branching_factor=2`，与 YAML 值一致 |
| `scorer_timeout` | 接真 | `assess.score_pipeline._score_single_inner` 用 `asyncio.wait_for` 包裹 J1/J2 | **零变更**（当前等价 +∞，仅在卡死时生效，属韧性增强） |
| `timeout_max_retries` / `timeout_max_delay` | 接真 | `core.resilience.make_retry_policy` 增 timeout 专用档 | **上调**（3→5 / 20→120），提高瞬态故障存活率（REQ-170） |
| `api_timeout` | 接真 | `recon.target_builder.build_http_target`、`strike.web.http_engine.HTTPAttackEngine` | 主链路 120→90 属**收紧**；为免降级，YAML 值上调至 120 并保留 90 为 web 引擎默认（分域取值，见 §3.3） |
| `probe_retries` | 接真 | `recon.capability_probe` 的 `discover_target_capabilities_async(retries=...)` | **上调** 1→2（探测请求量 +1，不改攻击路径） |
| `auto_seed_expansion_factor` | 接真（参数源） | `arm.seed_auto_expander.auto_generate_seeds_async` | **零变更**（默认 3 与 YAML 一致）；主链路接线另立任务（属基线变更） |
| `technique_converter_descriptions` / `technique_categories` | 接真（展示位） | `utils.display` 技术分组渲染 | 零行为变更 |

### 2.2 摘除（8 键，R-H1：能力不存在）

| 键 | 摘除理由 |
|----|---------|
| `rate_limit_retries` | 429 完全由 PyRIT 原生 `@pyrit_target_retry`(tenacity) 处理；`recon.target_wrapper.RateLimitedTarget._dispatch_with_transient_retry` 明写 429 不在本层重试，本仓无参数位 |
| `tap_success_threshold` | 全仓无 success_threshold 概念；TAP 成功判定走 PyRIT scorer（`FloatScaleThresholdScorer`），非整数阈值 |
| `adaptive_epsilon` / `adaptive_max_attempts` | `execute_text_adaptive` 未实现（`core.phases.strike` 明写 not implemented），`--techniques adaptive` 打 WARNING 后回落。**注意**：`assess.judge_manager._bayesian_ei_adjustment` 的 `epsilon=0.2` 语义为阈值探索，**不可误接** |
| `priority_scheduler_enabled` / `_high_threshold` / `_low_threshold` / `_epsilon` | 全仓无 priority scheduler 实现；`arm/seed_ranking.py` 中指向它的注释为陈旧注释（指向模块已不存在） |

### 2.3 同批义务

- 同步摘除 `core._config_parsers` 中对应白名单条目；
- `config/defaults.yaml` 摘除/上调处补注释与理由（C9）；
- 新增/更新回归测试；
- 更新 `20-REQUIREMENTS.md` 第九章 D 状态追踪、`docs/backlog.md` BL-038 状态。

---

## 3. 升级链 L1–L4 阶梯设计（I4 / ADR-005 / R-L5 落地）

### 3.1 现状形状 vs 目标形状

| | 现状 | 目标 |
|---|------|------|
| 选路 | `determine_escalation_strategy` 按 ASR 选**一条**策略（0.15/0.40/0.65/0.80 硬编码） | **阶梯**：L1 → L2 → L3 → L4 依次尝试，仅失败 objective 进入下一级 |
| 退出 | 无中间退出 | L1 后 `asr ≥ post_l1_exit_threshold(70)` 停；L2 后 `asr ≥ post_l2_exit_threshold(80)` 停 |
| 触发 | 固定阈值 | **动态**（I4）：完成度 <50% → 阈值 70；完成度 >80% → 95；剩余预算 <30% → 仅 L1 |
| 分批 | 无 | ADR-005：L1 按先验排序分批；L2–L4 全并行 |

### 3.2 零回归保证

- 阶梯默认**只跑到第一个产生成功的级别**即返回，故默认配置下 L1 结果与现有单策略行为收敛；
- `--escalation-levels` 显式指定时才展开多级；
- 所有新增阈值均走 `getattr(ctx.args, key, default)`（C7）；
- 未启用阶梯时 `determine_escalation_strategy` 保持原签名与原返回语义（下游零改动）。

### 3.3 `api_timeout` 分域取值

`api_timeout` 同时是「目标 HTTP 读超时」与「Web 攻击引擎超时」的语义来源。为避免主链路 120→90 的收紧（会降低慢响应的 ASR），取值策略：

- 主链路目标（`recon.target_builder`）：读 `api_timeout`，YAML 值上调为 **120**（等于既有硬编码，零收紧）；
- Web 攻击引擎（`strike.web.http_engine`）：读 `api_timeout`（30→90，放宽，提高慢端点存活率）。

---

## 4. ASR 影响评估

**净影响：变高。**

- 变高：`max_escalation_targets` 5→10（+升级覆盖）、`l5_optimal_paths` 锚点对齐现实 10（不降能力）、`timeout_*` 上调（减少瞬态假失败）、`probe_retries` 1→2（提高探测命中）、阶梯化升级（L1 未成再上 L2–L4，I4/ADR-005）。
- 不变：`tap_branching`（值 2 = PyRIT 默认）、`auto_seed_expansion_factor`（值 3 = 代码默认）、`scorer_timeout`（仅卡死时生效）、展示位二键。
- 边界：全部在 R-S1 授权边界内；摘除项不减少任何真实能力（R-H1）。

---

## 5. 评审结论（人工填写，AI 不得代填）

> **代录入声明**：经用户 2026-09-12 会话「对整个的架构和代码实现进行全部实施，确保 L5 专家生产水平」授权，由 AI 代录入批准记录，**待项目所有者在 git 提交前追认签名**。

- [x] 批准（附条件：① 摘除项须同步清理 `core._config_parsers` 白名单与注释；② 上调项须在 `defaults.yaml` 写明上调理由与日期；③ 阶梯化升级默认行为收敛，不得改变 `--escalation-levels` 未显式指定时的结果；④ 每波次收尾跑六步门禁）
- [ ] 驳回（理由：___）
- [ ] 转 backlog（BL-___）

评审人 / 日期：________________（待人工追认）
授权来源：2026-09-12 用户会话批准全量实施，AI 代录入
