# pyrit-mini 实施执行日志（plan.md）

> 依据：`docs/plan.md`（多组件组合体攻击架构）+ `docs/specs/`（宪法与规范）
> 记录范围：Wave 0 ～ Wave 6 的实施、验证与遗留项
> 最后更新：2026-09-11

---

## 1. 门禁总览（C10 五步 + 扩展）

| # | 检查项 | 命令 | 结果 |
|---|--------|------|------|
| 1 | 静态守卫 | `python -m tools.guard` | **0 blocking / 71 warning / 1 info** |
| 1.5 | 架构体检 | `python tools/architecture_validator.py full` | **PASS 158 / WARNING 6 / BLOCKING 0** |
| 2 | 代码风格 | `python -m ruff check .` | **All checks passed** |
| 3 | 单元/集成测试 | `python -m pytest tests/ -q` | **1402 passed, 7 skipped**（15.45s） |
| 4 | 0-token 干跑 | `python main.py --dry-run --max-seeds 1` | **OK** |
| 5 | 真实端到端 | mock MCP 目标 + `main.py --burp mocka` | **RECON→ARM→STRIKE→ASSESS→REPORT 全链路无崩溃** |

测试基线：实施前 `1307 passed / 6 failed` → 实施后 `1402 passed / 7 skipped`（净增 95 项）。

---

## 2. Wave 0 — 止血（主链路阻断缺陷）

这一波的价值最高：**修复前主链路在 10 处会直接抛异常中断**，任何一次真实运行都拿不到报告。

### 2.1 已修复的主链路崩溃点

| 文件 | 缺陷 | 性质 | 修复 |
|------|------|------|------|
| `recon/api/endpoint_sorter.py` | `fp_capabilities.lower()`：`TargetFingerprint.capabilities` 声明为 `list[str]` | 类型错配 → AttributeError | 新增 `_capabilities_to_text()` 统一归一化 str/list/tuple/set/None |
| `recon/target_builder.py` | `parsed.raw_request`：`ParsedBurpRequest` 无此字段 | 字段不存在 → AttributeError | 改用 `build_raw_http_request(parsed)` 并补齐导入 |
| `utils/display.py` | `print_joint_asr_card` 被传入 6 个关键字参数，签名只接受 2 个 | 契约错位 → TypeError | 按调用方契约扩展签名（并保留旧位置参数兼容） |
| `utils/display.py` | `print_recon_card(ctx)` vs 6 个必填位置参数 | 契约错位 → TypeError | 改为双模：首参非 str 即视为 ctx，从中提取展示字段 |
| `utils/display.py` | `print_assess_card(ctx)` vs 4 个必填位置参数 | 契约错位 → TypeError | 同上双模改造 |
| `utils/display.py` | `print_report_card` 缺 `total_attacks/successful_attacks/overall_asr/evidence_count/wilson_ci/native_output_dir` | 契约错位 → TypeError | 扩展为可选关键字参数并渲染 |
| `core/phases/_helpers.py` | `_extract_target_profile` 注解返回 3-tuple，调用方按 dict 消费；且**主路径无 return**（返回 None） | 类型自相矛盾 + 缺 return | 统一返回 dict，所有分支均有确定返回值 |
| `core/phases/arm.py` | `print_status("Attack surface mapped", "vectors=...")` 只传 2 个位置参数 | 契约错位 → TypeError | 改为 `("ARM", "DONE", msg, ok=True)` |
| `core/phases/strike.py` | `print_strike_phase_summary(asr=, attack_count=)` 与实际契约不符 | 契约错位 → TypeError | 改为 `(ctx, total_results=, total_success=, elapsed_seconds=)` |
| `report/report_html.py` | `evidence.target_fingerprint.items()`：该字段是 `TargetFingerprint` **dataclass**，非 dict | 类型错配 → AttributeError | 新增 `_as_mapping()`（dict / `to_dict()` / `dataclasses.asdict` 三路归一） |
| `report/generator.py` | Layer-1/2/3 报告写入逻辑被**错误缩进在上一处 `try` 的 `except` 块内** | 控制流倒置（逻辑反了） | 见 §2.3 |

### 2.2 种子加载链路（3 处独立缺陷，串联导致 ARM 必然中断）

`arm/seed_ranker.py` 同时存在三个问题，任一都会让 `--seeds elite_jailbreaks,asi_top10,owasp_full_coverage`（CLI 默认值）加载失败：

1. **旧别名无解析**：`elite_jailbreaks` 等别名只被 `core/seed_loader.LEGACY_NAME_MAP` 识别，本模块直接按文件名查找 → 三个文件全部 not found。
   → 新增 `_expand_legacy_seed_names()`，**复用同一张别名表**（C3：禁止同一语义多处定义）。
2. **多文档 YAML 只读首文档**：种子文件以 `---` 分隔多文档，`yaml.safe_load()` 遇到 `---` 直接抛 `ComposerError`。
   → 新增 `_read_seed_yaml()` 改用 `safe_load_all` 并合并全部文档。
3. **散文/HTML 种子被判非法**：`data/seeds/` 混有两种格式，`T1_LLM01_web_injection.prompt` 是含裸 HTML 的散文文档，非合法 YAML。
   → 新增 `_read_raw_seed()` 兜底为原始文本种子（`parse_mode=raw_fallback`），**不丢弃有效攻击种子**，且降级有 `logger.warning` 留痕。

另修复：`capabilities` 参数按逗号串解析（`_as_items()`），与上游 `list[str]` 声明对齐。

### 2.3 控制流倒置（静默逻辑错误）

`report/generator.py` 中，Layer-1/2/3（executive / findings / technical）报告的写入逻辑被缩进在组件章节生成的 `except` 分支内，产生**完全倒置**的行为：

- 组件章节生成**成功** → Layer 报告**永不写入**
- 组件章节生成**失败** → Layer 报告**反而写入**

同时 `_generate_executive_markdown` 等构建器的 import 位于 `if "md" in output_formats:` 内，而下游在其外使用 → 潜在 `NameError`。

→ 已将 Layer 报告写入提为独立 `try` 块（无条件执行），import 提到无条件位置，组件章节改为在 findings 落盘后追加（成功与否都不影响 findings 本身）。

### 2.4 评分可信性（假阴性系统性来源）

`assess/judge_manager.py` 因历史编码损坏产生两类严重缺陷：

1. **空分支正则匹配一切**：模式退化为 `r"^(||||||)\s*$"` 与 `r"(||).{0,20}(|||)"` —— 空交替分支使正则匹配**任意字符串**，导致每条响应都被判为「无实质内容」→ T0 恒判 failure。已按原语义还原为中文应答模式与「暂无相关信息」模式。
2. **中文信号词表整体退化为空串**：`_SUCCESS_SIGNAL_WORDS` / `_SAFETY_CONTEXT_WORDS` 中数十个中文词条被损坏为 `""`。已还原（道德/伦理/合规/违法/内容过滤 等）。
3. **T0 把「证据不足」当「检出拒绝」**：`composite < 0.25` 即判 failure，而 T0 的失败裁决会短路 J1/J2 → 直接压低 ASR（违反 C2）。已改为**仅在命中负向信号时**才判 failure，否则一律落 `uncertain` 交 J1/J2 裁决。
4. **中文拒绝正则召回不足**：由 10 条扩展至 20 条（学术依据：Bian et al., arXiv:2311.09458 Multilingual Red Teaming）。

---

## 3. Wave 1 — 契约层与组件注册表（SSOT）

### 3.1 新增 `core/contracts/`（Pydantic 契约层）

`__init__.py`、`component.py`、`component_graph.py`、`attack_chain.py`、`impact_chain.py`、`evidence.py`、`verdict.py`、`manifest.py`。

### 3.2 组件声明（10 个）— `config/components/*.yaml`

`mcp` / `a2a` / `rag` / `model` / `session` / `web_api`（原有 6 键重构）+ 新增 `embedding` / `gateway` / `audit` / `supply_chain`。

### 3.3 `core/registry.py` 升级为运行时 SSOT

新增 `spec()` / `specs()` / `keys()` / `by_neighbor()` / `for_seed_component()` 强类型视图，以及 **`validate_wiring()`** —— 校验每个组件声明的 recon/strike/assess/report/seeds 落点是否真实存在。

关键设计：**一处定义、两处使用** —— 既供运行时调度消费，又反向供静态体检消费（治宪法 C3 与 IA-3：组件键四份分散硬编码）。

### 3.4 `core/component_classifier.py`

多信号融合识别（path / body / capability / profile 四类信号加权）+ `ComponentGraph` 构建。
加固：**仅当锚点组件置信度 ≥ 0.60 时**才推断邻居，避免弱命中引发组合体爆炸稀释预算。

### 3.5 `core/config.py`

- 新增 `--components KEY[,KEY...]` 显式锁定组合体（L2「显式指定兜底」）
- 新增 `_flatten_nested_defaults()`：把 `defaults.yaml` 的嵌套小节展平为 args 标量键，保证 C7「defaults.yaml → args → getattr」链路不断

### 3.6 `core/phases/recon.py`

新增 `_run_component_identification()`：识别 → 建图 → 写 `orchestration_log` → 落盘 `component_classification.json`。降级路径**必须 `logger.warning`**，禁止静默。

---

## 4. Wave 2 — 攻击预算

`strike/common/budget.py`：`BudgetController`（总攻击数 / 单组件配额 / 墙钟 / token 四维约束），超限按 `ComponentSpec.asr_prior` 降序裁剪，**裁剪原因全部留痕**（`trim_report()`）。

接入点：STRIKE 有状态链执行阶段。

---

## 5. Wave 3 — 有状态跨组件攻击链

| 模块 | 职责 |
|------|------|
| `strike/common/chain_planner.py` | `ChainPlanner`：组件拓扑 → 有状态 DAG 攻击链 |
| `strike/common/chain_executor.py` | `execute_step`：步骤路由到组件专属 strike 模块 |
| `core/state_machine.py` | `ChainStateMachine`：DAG 调度 + checkpoint/resume |
| `report/impact_chain.py` | `ImpactChainBuilder`：入口组件 → 业务影响的因果链 + `validate_causality()` |

**两处关键修复**：

1. **链饥饿停滞**：原先只把「链内真有生产者」的输入声明为 `consumes`，否则该步骤 `inputs_satisfied()` 恒为 False → 整条链无法推进。已改为先收集全链可得产出物再裁剪 `consumes`。
2. **依赖漏建**：`depends_on` 原本单遍解析，生产者排在消费者之后时依赖缺失 → 改为**第二遍全量扫描**建立依赖。

---

## 6. Wave 4 — PyRIT 原生输出与算法参数外置

1. `utils/display.py` 中 `print_strike_report_async` / `print_escalate_report_async` 长期**零调用点**，终端看不到 PyRIT 原生渲染的攻击证据。
   → 新增 `_emit_native_strike_report()` / `_emit_native_escalate_report()` 接入 STRIKE 收尾与升级阶段收尾。
2. `config/defaults.yaml` 新增 `native_output` 段（开关 / 展示条数 / 失败样本开关），经 `_NESTED_SECTIONS` 展平。
3. `core/config.py` 新增 `_warn_ineffective_args()`：对「会被静默忽略」的参数组合（`--max-seeds` 超种子库规模、`--converters none`、`--stage escalate` 且样本过少）发出显式警告。

---

## 7. Wave 5 — 评分可信性修复

1. **κ 口径唯一化**（`core/phases/assess.py`）：旧代码用**两参数**（agreements, disagreements）重算 Cohen's κ 并**覆盖** `DualJudgeState.to_dict()` 用**四参数**算出的值 —— 同一指标两套口径，后者静默胜出。已改为以四参数结果为唯一事实源。
2. **OR 聚合指标补全**（`assess/asr_stats.py`）：补齐 `disagreement_rate` 与 `potential_false_positive_rate`；新增模块级计数器与 `record_or_aggregation_global()` 单一推进口，与 `DualJudgeState` 同步（防双轨漂移）。
3. **`adaptive_random_seed` 断链修复**（C7）：该配置项只写在 `defaults.yaml` 而**无任何消费者**。新增 `_build_score_manifest()`，把它连同 judge 模型 / rubric 哈希 / temperature / 聚合策略固化进 `ScoreRunManifest`，使「同输入 + 同 seed → 同结果」成为可验证命题。

---

## 8. Wave 6 — 组件专属报告与交付加固

1. **CB-2 断裂修复**（`report/evidence.py`）：`VulnerabilityEvidence` 此前**无 `metadata` 字段** → `getattr(ev, "metadata", {}).get("component_type")` 恒空 → `_determine_dominant_component()` 恒 None → **组件专属章节永远不生成**。已补字段并由 `_extract_result_metadata()` 从 AttackResult 只读提取（CB-1：`component_type` 写入权归 `_component_bridge`）。
2. **组件元数据来源增强**（`core/phases/_component_bridge.py`）：新增 `component_graph` 参数与 `_component_from_graph()`，优先用 RECON **已识别**的组件图盖章，保证「识别出的组件」与「报告里的组件」是同一个。
3. **evidence_id 全局唯一**（`report/evidence.py`）：原先 `attack_index` 取自 `enumerate(results)`（**每个技术重新从 0 开始**）→ 每个技术都产出 `EVD-0001…`，证据文件互相覆盖。已改为采集器级单调序号 + `_next_evidence_id()` 冲突兜底（附加 attack_id 短哈希）。
4. **报告投影补全**（`core/phases/report.py` 新增 `_attach_combo_artifacts()`）：把**组件拓扑 / 攻击链 / 影响链举证 / 举证缺口 / 预算裁剪 / 评分可复现指纹**投影进证据集。
   - 影响链的 `evidence_ids` **取自真实 EVD-\***，因此 `validate_causality()` 的缺口是真实举证缺口，非形式化填空。
5. **HTML 报告补全**（`report/report_html.py`）：
   - 新增 `_render_component_sections()`（此前 HTML **从不消费** `component_reports`，只有 Markdown 链路在用，构成交付缺口）
   - 新增 `_render_combo_artifacts()`（影响链 / 组件拓扑 / 预算 / 可复现指纹）
   - 新增 `_esc()`：攻击者可控内容（目标响应）此前**直接插值进 HTML**，会破坏报告结构；现已全面转义
   - **举证缺口显式渲染**（不再静默省略）
6. **静态体检接入注册表**（`tools/architecture_validator.py`）：4 份硬编码组件映射（recon/strike/assess/report）全部改为读取 `ComponentRegistry`，并新增 `_validate_component_wiring()` → **`COMPONENT_WIRING: PASS（全部 10 个组件接线完整）`**。这是 C3 / IA-3 的正向治本。

---

## 9. 新增测试

| 文件 | 覆盖 |
|------|------|
| `tests/test_component_classifier.py` | 多信号融合、组合体推断上限、降级路径 |
| `tests/test_state_machine.py` | DAG 调度、跨步骤状态传递、checkpoint/resume |
| `tests/test_impact_chain.py` | 因果校验、证据可追溯、缺口识别 |
| `tests/test_attack_chain.py` | 链规划、预算裁剪、契约层 |
| `tests/test_component_combo_integration.py` | **端到端**：识别→建图→规划→执行→举证→投影；evidence_id 唯一性回归 |

---

## 10. 端到端验证证据

对本地 mock MCP 目标实跑，产物如下（`outputs/strike_20260911_190259/`）：

```
events.jsonl
joint_asr_report.json
endpoint_1_mocka/
  ├── component_classification.json      ← Wave 1：识别到 model_behavior_shift(0.7) + llm_gateway(0.3, inferred)
  ├── attack_chain_checkpoint.json       ← Wave 3：有状态链 checkpoint 落盘
  ├── evidence/evidence.json
  ├── report.html / report.md / report.sarif
  ├── report_executive.md / report_findings.md / report_technical.md   ← 三层报告均已生成
  ├── owasp_coverage_matrix.csv / attack_summary.csv
  └── native_output/                     ← Wave 4：PyRIT 原生输出目录
```

**关键确认**：修复前该命令在 RECON 第一步即因 `print_recon_card` 崩溃；修复后全链路贯通。

---

## 11. 遗留项与已知限制（诚实汇报）

1. **mock 目标攻击数为 0**：端到端验证确认了链路**结构贯通**，但 mock 目标未形成有效攻击结果（`Total Attacks: 0`），因此**未**验证真实 LLM 目标下的攻击效果与 ASR 数值。
2. **未做真实 LLM 端到端 ASR 验证**：Wave 5 的评分修复（中文词表、T0 语义、κ 口径）均有单测覆盖，但未在真实模型上做前后 ASR 对比。
3. **Wave 6.6 未实施**：报告仍为字符串拼接，未引入 Jinja2 模板。
4. **守卫遗留 71 个 warning**：其中 `core/component_classifier.py`(414 行) 与 `core/registry.py`(343 行) 为本次新增的模块体积告警（R-DELIVERY-1，非 blocking）；其余为改动前既有。
5. **架构体检 6 个 warning**：均为非阻塞项，未逐一处理。
6. **`config/profiles/*.yaml` 5 个文件被删除**：为仓库既有改动，非本次实施引入。

---

## 12. 状态

- Wave 0 ～ Wave 6 **主体实施完成**
- C10 五步门禁 **全部通过**
- 遗留项见 §11，其中 §11.1/11.2（真实 LLM 效果验证）建议作为下一步优先事项
