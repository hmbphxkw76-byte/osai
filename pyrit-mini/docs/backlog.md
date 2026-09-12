# backlog — 唯一待办池

> **规则**（30-TASKS 第二章 / 宪法 C4 豁免通道）：
> 一行一条；登记时**不动代码**；AI 在执行任务途中发现的任何**非本任务**问题，一律进此处，不就地修。
> **状态**：`open` / `converted`（转为 REQ / DEBT / 任务规格）/ `discarded` / `completed`
> **完结项不保留明细**（文档纪律 D3）：已完成条目只保留统计与 git 考古入口。

---

## 1. 活跃待办（open）

| ID | 登记日期 | 内容 | 来源 | 状态 |
|----|---------|------|------|------|
| BL-002 | 2026-09-05 | NFR-6 Python ≥3.13 与 PyRIT 1.0.1 官方支持矩阵核对；若 3.13 超出支持区间，按 NFR-6 硬边界以 PyRIT 区间为准并修订登记 | REV-01 P2-4 | **open** |
| BL-024 | 2026-09-12 | **组件 `id` ≠ YAML 文件名 stem**（违反 80 IA-8）：`session.yaml` 的 `id` 为 `memory_session_tenant`、`web_api.yaml` 的 `id` 为 `web_infra`。`core/registry.py` 的 `names()/get(id)` 与目录定位混用两个语义，修正前禁止编写依赖 `id == stem` 的代码。改动属**数据层**，须持专项任务规格 | 2026-09-12 规约梳理 | **open** |
| BL-025 | 2026-09-12 | **`config/components/*.yaml` 新旧双 schema 并存**：`mcp.yaml` 等同时携带 W0 遗留字段（`seed_sets`/`converter_vectors`/`strike_modules`/`assess`/`report_builder`/`poc_template`/`neighbors`/`owasp`）与新契约字段（`labels`/`detect`/`recon`/`seeds`/`scorer`/`report_section`/`cleanup`）。按蓝图 13.3「兼容层只减不增」，需专项任务清理并核对 `core/registry.py` 无旧字段消费者 | 2026-09-12 规约梳理 | **open** |
| BL-026 | 2026-09-12 | **`tools/guard_extended.py` 约 2071 行 > R-TOOLS-2 上限 850 行**：当前为仓库最大 Python 文件（34 个检查器）。拆分属债务消除，须登记 `DEBT-xxx` 专项任务，**禁止日常任务顺手重构**（C4 / NEG-1） | 2026-09-12 实测 | **open** |
| BL-027 | 2026-09-12 | **`docs/guides/ai-dev-guides.md`（约 1960 行）与 `specs/` 职责重叠**：同一套「task-spec 模板 / STOP-REPORT / 交付验收清单 / 跨模型一致性 / 三栏汇报」在三处定义（guides、specs、`.assistant_pyrit/skills/*/SKILL.md`），违反 C3。待裁决：`docs/guides/` 降级为「方法论与 why」、`specs/` 为「本项目规则与 what」，并删除重复模板 | 2026-09-12 规约梳理 | **open** |
| BL-028 | 2026-09-12 | **护栏 1F 登记簿与代码存在双向滞后**：本表为索引、代码为权威，需定期跑 `40-GUARDRAILS.md` 1F 头部命令对齐（当前代码 46 个 `def check_*`，登记簿列出 39 行） | 2026-09-12 实测 | **open** |
| BL-029 | 2026-09-12 | ~~**MCPSec 桥为永久 null object → MCP 专项侦察实际禁用**~~ **已闭环（recon-deep 波次）**：`recon/_target_router_helpers._probe_mcp_locally` 作为桥不可用时的**本地回退**已接线，依次调用 `recon.mcp.{capability_probe,surface_scanner,version_fingerprint}`（工具清单仅在已发现 tool schema 时评估），结果写入 `target_fingerprint.extra`（I12）与 `ctx.service_profile.mcp_local_recon`；子探测逐个隔离（单个失败不影响其余）。回归：`tests/common/test_recon_deep_wiring.py::TestMcpLocalFallback` | 2026-09-12 recon-deep | **resolved** |
| BL-030 | 2026-09-12 | ~~**5 个桩模块曾被声明进 `config/components/*.yaml` 攻击矩阵（R-H1）**~~ **已闭环**：`recon.api.openapi_capture`、`recon.embedding.similarity_probe`、`recon.rag.kb_enumerator`、`recon.rag.embedding_scan`、`recon.model.capability_detector` 五个桩经实测确认**均返回编造数据**（`_simulate_kb_response` 伪造知识库、`_detect_dimension` 硬编码 1536、`_probe_models_endpoint` 伪造 `gpt-4-turbo` 列表、相似度测试为罐头值），违反 C9/R-H1。已**整体摘除**（文件删除 + 4 个包 `__init__` 导出清理 + R-L1 白名单条目清理 + `chain_planner` 产物名 `similarity_probe`→`embedding_dimension`）。真实能力由 `recon/api/openapi_discoverer.py`、`recon/rag/pipeline_probe.py`、`recon/embedding/vector_probe.py`、`recon/capability_detector.py` 提供。验证：`python -c "import recon.api,recon.rag,recon.embedding,recon.model"` | 2026-09-12 recon-deep | **resolved** |
| BL-031 | 2026-09-12 | **`ctx.techniques` 只喂 Converter、不选 Executor（技术路由断裂）**：`core/phases/arm.py` 经 `arm.technique_picker.select_techniques` + `augment_techniques_by_capability` 写入 `ctx.techniques`，并仅以其为 `arm.converter_presets.build_converter_map(technique_names=...)` 的分桶输入；`core/phases/strike.py` 读取 `ctx.techniques` 后**只写入 orchestration_log**；`strike/common/*` 无任何 `ctx.techniques` 消费者。故 `--techniques tap` 只影响 Converter 链，**不强制 TAPAttack 执行**（实际执行类由 `--strike`/`escalation_runtime.determine_escalation_strategy` 按 ASR 决定）。正确归宿是 REQ-151 PlaybookEngine（W2）——**禁止新建第二套链机制**（C3） | 2026-09-12 technique-routing 实测 | **open** |
| BL-032 | 2026-09-12 | ~~**REQ-160 ④「裸 URL 爬取与关联端点发现」未实施**~~ **已闭环（recon-adapters 波次）**：新增 `recon/api/url_endpoint_discoverer.discover_related_endpoints`（有界：默认词表 21 条 + 超时 5s + 并发上限 8，仅收录 <400 端点，不做全字典爆破，R-H3），在 `recon/_target_router_helpers._run_background_probes` 浅层段接入，将发现收敛进 `target_fingerprint.extra["related_endpoints"]`（I12）；浅层、非致命（dry-run 不触发）。注：`recon/api/recursive_expander.py` / `health_probe._enumerate_api_endpoints` 为更深的全站点爬取，超出本项"有界关联端点"范围，保留待后续专项（不引入本项以免过度工程）。回归：`tests/common/test_recon_deep_wiring.py::TestRelatedEndpointDiscovery` | 2026-09-12 recon-adapters | **resolved** |
| BL-033 | 2026-09-12 | ~~**REQ-161 ①「GraphQL introspection」已有实现但未接入主链路**~~ **已闭环（recon-deep 波次）**：`recon/_target_router_helpers._run_background_probes` 深度段已注册 GraphQL 探测（`probe_graphql_endpoint` + 被动 `is_graphql_signal` 双通道），结果写入 `target_fingerprint.extra["graphql"]`（I12，含 detected/introspection_enabled/types/queries/mutations/evidence）。**残留**：端点/类型列表并入 REQ-150 SurfaceGraph 待该需求实施。回归：`tests/common/test_recon_deep_wiring.py::TestGraphQLWiring` | 2026-09-12 recon-deep | **resolved** |
| BL-036 | 2026-09-12 | ~~**深度段"顺序决定饥饿"**~~ **已闭环（recon-adapters 波次）**：① 预算静默覆盖缺陷（日志访问不存在的 `behavioral_verify_budget` 键 → `KeyError` 被 `except` 吞掉 → 降级字典覆盖真实预算）已在 recon-deep 波次修复；② 深度探测段由 4 个顺序 `if can_deep_probe(...)` 块重构为 `_run_deep_probe_queue` **显式优先级队列**：每个探测声明 `(priority, cost)` 二元组，按 priority 降序贪心入队，`deep_probe_budget` 内确定性调度，预算不足时低优先级探测**显式跳过并记录**（消除"代码顺序决定饥饿"）；③ cost 已按真实请求数校准（deep_capabilities 8→4、openapi 5→3）。回归：`tests/common/test_recon_deep_wiring.py::TestDeepProbeQueue`（紧预算下 deep_capabilities+graphql 运行、openapi+rate_limit 跳过；宽预算全运行）。该调度逻辑属 L5 行为调优，本次按 BL-036 建议一并落地（非静默改基线：deep_probe_budget 默认值未变） | 2026-09-12 recon-adapters | **resolved** |
| BL-037 | 2026-09-12 | ~~**TargetAdapter 已落地但主链路仍走旧路径（REQ-149 ④ 的"完整攻击"未闭环）**~~ **已闭环（playbook 波次）**：`recon/adapters.build_adapter` 新增 `_TargetAdapterWrapper(BaseAdapter)`，把 PyRIT `MCPTarget/RAGTarget/A2ATarget` 包装为合规 `TargetAdapter`（`.name`/`.send`/`.close`/`.describe()` 含 auth/session，并转发 `handshake/list_tools/call_tool/query/send_task/fetch_agent_card`），成为 PlaybookEngine（REQ-151）按 `step.adapter` 选择它们的唯一入口（IC-2）；`build_adapter(kind=mcp/rag/a2a)` 此前为死代码（choose_kind 永不返回这些 kind）现已真正路由（mcp 内部走 JSONRPCAdapter）。`RAGTarget.query` 补语义动作。`recon/target_router.py` 旧路径**未改动**（零回归成立），攻击编排统一收敛到 PlaybookEngine（C3）。回归：`tests/common/test_playbook_engine.py`（4 passed）、`tests/common/test_adapters.py::TestAdapterContract`（含 mcp/rag/a2a 契约） | 2026-09-12 playbook | **resolved** |
| BL-034 | 2026-09-12 | ~~**15 个扁平键无引用**~~ **已闭环（recon-adapters 波次，2026-09-12）**：精确审计改为"排除映射表/测试后逐键判定"，结论分两类。① **接真**（4 键，修 C9 终端展示≠实际攻击的不实）：`many_shot_example_count`/`chunked_request_chunk_size`/`chunked_request_total_length`/`red_teaming_max_turns` → 经 `strike/strategies/params.py` 新增 `many_shot_params`/`chunked_request_params`/`red_teaming_params`，传入 PyRIT `ManyShotJailbreakAttack`(`example_count`)/`ChunkedRequestAttack`(`chunk_size`,`total_length`)/`RedTeamingAttack`(`max_turns`)（`strike/model/filter_bypass.py`）；② **摘除**（12 键，R-H1，功能不存在）：`bon_persuasion_count`、`cair_*`×3、`tap_branching_factor`（与 `tap_branching` 重复）、`dos_*`×3、`auto_l4_*`×4（含 `auto_l4_agent_surfaces`）；③ 修正 `technique_param_labels`/`technique_converter_descriptions` 的虚假"display.py 消费"注释（C9）并移除悬空引用（`cair_max_iterations`/`gcg_suffix_len`/`gcg_max_iterations`/`cot_hijack_max_turns`）。回归：`tests/common/test_bypass_params_wiring.py`(22 用例)。**残留**：仍死键升 BL-038 | 2026-09-12 recon-adapters | **resolved** |
| BL-038 | 2026-09-12 | **系统性 C7 死配置（P0，动摇"L5 基线参数已被消费"声明）**：BL-034 的"排除映射表"审计揭示 `defaults.yaml` 共 **34 个顶层键仅被 `_config_parsers._apply_defaults` 拷进 `args` 而从未被任何代码读取**（含用户指定的 **L5 验收锚点 `l5_optimal_paths=7`**）。BL-034 已处置 12 摘除 + 4 接真，**仍死 19 键**：`adaptive_epsilon`、`adaptive_max_attempts`、`api_timeout`、`auto_seed_expansion_factor`、`l5_optimal_paths`、`max_escalation_targets`、`post_l1_exit_threshold`、`post_l2_exit_threshold`、`priority_scheduler_enabled/epsilon/high_threshold/low_threshold`、`probe_retries`、`rate_limit_retries`、`scorer_timeout`、`tap_branching`、`tap_success_threshold`、`timeout_max_delay`、`timeout_max_retries`。其中 `l5_optimal_paths`/`post_l1/l2_exit_threshold`/`max_escalation_targets`/`priority_scheduler_*` 属 **L5 基线验收参数**，当前却零消费者（验收声明与实际不符，C9）。处置要求（R-H1/C7/NEG-6）：逐键判定——(a) 属 L5 参数且接线改变攻击行为者**须先提案**再接真（不得静默改基线）；(b) 功能不存在者摘除；(c) 预留型保留并标注。另：`technique_param_labels` 仍引用不存在的 `gcg_suffix_len`/`gcg_max_iterations`/`cot_hijack_max_turns`（config 腐烂，已摘除悬空引用，但 gcg/cot_hijack 攻击参数本身未接线，应纳入本项一并处置）。复现：见 BL-034 审计脚本（`rglob` 全仓 `.py` 排除 `_config_parsers.py`/`tests/` 后做键名包含检查） | 2026-09-12 recon-adapters 实测 | **open** |
| BL-035 | 2026-09-12 | **跨模型审查（C14 / R-CROSS-1~4）未执行，标记 `needs-cross-model-pending`**：本轮 CP-002 五波次含 **L0–L4 规约变更**（`10-ARCHITECTURE` v3.2、`20-REQUIREMENTS` v3.0、`40-GUARDRAILS` v3.3/v3.4、新增 CP-002），依 C14 应先过跨模型审查；但 `60-CROSS-MODEL-VERIFICATION.md` 所述工具链**未在仓库实施**（无多模型池/编排脚本），故按 R-CROSS 降级条款：**转人工审查模式 + 代码存档记录**，不阻断合入但须标记待审。审阅要点：REQ-160~171 陈述与实现一致性、ADR-008 四态口径、R-ROE-1/R-EVID-1/R-AUDIT-1 判定逻辑、认证/授权路径改动（`core/context.enforce_authorized_scope`） | 2026-09-12 spec-sync-gate | **open** |
| BL-039 | 2026-09-12 | **R-DOC-4 检查器白名单未含 `docs/specs/90-AI-DEV-ARCHITECTURE.md`**：`tools.guard_extended.check_readme_version_synced` 的 `doc_files` 硬编码 00/10/20/30/40/50/55/60/80 九个文档，90 已登记进 `specs/README.md` §1 索引（v1.0）但版本同步暂无自动校验（1C-DOC 漂移类型）；纳入需改 `tools/guard_extended.py`，属代码变更须持专项任务规格 | 90 总纲接线 | **open** |

---

## 2. 已转化（converted）

| ID | 登记日期 | 内容 | 转化去向 |
|----|---------|------|---------|
| BL-012 | 2026-09-05 | Best-of-N stub 缺口 | → REQ-004 内标注 P0 缺口 + 路线图 T0-1 |

---

## 3. 已完成（completed）

**统计**：BL-001、BL-003 ~ BL-011、BL-013 ~ BL-023 共 **26 条**已闭环（2026-09-05 ~ 2026-09-10），覆盖：外部锚点核对、Guard 检查器登记簿锚定、SKILL.md frontmatter、文档收敛、死代码清理、编码损坏修复、pyproject 工具链、运行时产物 gitignore、L2→L4 升级链 UnboundLocalError、多智能体种子加载、MCP 动态种子链路、D-01~D-16 债务量化等。

**明细考古**：`git log -- docs/backlog.md`（文档纪律 D3，正文不再保留逐条完成记录）。

---

## 4. 登记格式（新增条目照抄）

```
| BL-0NN | YYYY-MM-DD | 一句话描述（含可验证的现象或坐标） | 来源 | **open** |
```

**硬性要求**：
1. **一行一条**，禁止把多个问题塞进一行；
2. 描述必须**可验证**（给出命令、路径或现象），禁止"某某可能有问题"式模糊登记；
3. 登记时**不动代码**——修改须另起任务规格（C4）；
4. 转化/完成后**改状态 + 移入对应章节**，不在 open 区保留完结项。
