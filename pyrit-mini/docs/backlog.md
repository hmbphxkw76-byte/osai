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
| BL-024 | 2026-09-12 | ~~**组件 `id` ≠ YAML 文件名 stem**（违反 80 IA-8）~~ **已闭环**：`web_api.yaml` 的 `id` 由 `web_infra`→`web_api`、`session.yaml` 的 `id` 由 `memory_session_tenant`→`session`；二者实测零消费方，语义保留在 `labels` 内。现 `names()` = `[a2a, audit, embedding, gateway, mcp, model, multimodal_upload, rag, session, supply_chain, web_api]`，全部 `id == stem`。回归：`validate_wiring()` 0 错、pytest 1979 passed | 2026-09-12 规约梳理 → CP-004 §8.11 | **completed** |
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
| BL-040 | 2026-09-12 | **`tools/gate.py` 未覆盖 `specs/README.md` §2 六步门禁**：commit 阶段仅 ruff+guard+registry，Step 1.5 架构体检 / Step 3 `pytest tests/ -q` / Step 4 `main.py --dry-run` 从未被执行；而 README §2 称其为"唯一代码实现"（C10 结构性违例） | CP-004 审计 E-01 | **open** |
| BL-041 | 2026-09-12 | **gate.py 存在结构性静默降级**：`_ruff()` 在 ruff 未安装时打印 `[SKIP] …跳过（非阻塞）`、`_run()` 遇 `FileNotFoundError` 同样"视为非阻塞"（C9 / R-H1） | CP-004 审计 E-06 | **open** |
| BL-042 | 2026-09-12 | **README §4 与 40-G §6/7E 引用不存在的模块**：`tools/quick_check.py`、`tools/watch_guard.py`、`tools/cross_model_review.py`（已于 v3.0 并入 guard.py），对应 `pyrit-quick`/`pyrit-watch`/`pyrit-cross` 三条 CLI 不存在（D5） | CP-004 审计 E-02 | **open** |
| BL-043 | 2026-09-12 | **`10-ARCHITECTURE.md` 文件头引用不存在的 `tools/data_flow_validator.py`**（实际为 `tools/dataflow/validator.py`，40-G 1A-DATA 同引前者） | CP-004 审计 E-03 | **open** |
| BL-044 | 2026-09-12 | **执行计划引用不存在的 `docs/guides/`**：`plans/447be21ad0594078a923a53f701087d3-EXECUTION-PLAN.md` §2.2 / §12 / W5-4 三处 | CP-004 审计 E-04 | **open** |
| BL-045 | 2026-09-12 | **`.git/hooks/pre-commit` 未安装**：README §2.1 声称三层防线在线，实际 L3 Git 门禁离线且无文档声明该降级（40-G 第三章） | CP-004 审计 E-05 | **open** |
| BL-046 | 2026-09-12 | **BL-038 状态滞后于代码**：实测其中 13 键已接真（`l5_optimal_paths`/`max_escalation_targets`/`tap_branching`/`post_l1&l2_exit`/`api_timeout`/`probe_retries`/`scorer_timeout`/`timeout_max_*` 等均有 1–3 个消费者）、7 键已摘除，条目仍标"仍死 19 键" | CP-004 审计 E-07 | **open** |
| BL-047 | 2026-09-12 | **升级链 L1–L4 阶梯已落地但未回填**：`strike.common.escalation_runtime` 已含 `_LADDER` / `resolve_ladder_levels` / `should_exit_ladder`，而 REQ-005 状态与 README §2 2026-09-12 基线均未反映（I4 / ADR-005 / R-L5 闭环未登记） | CP-004 审计 E-08 | **open** |
| BL-048 | 2026-09-12 | **组件矩阵缺 `agent`**：无 `config/components/agent.yaml`、`strike/agent/`、`recon/agent/`、`T*_agent_*` 种子集；企业第一大类目标（ReAct/Tool-use Agent）依 C6「未登记 = 不存在」 | CP-004 审计 E-10 / REQ-172 | **open** |
| BL-049 | 2026-09-12 | ~~**`gateway` / `web_api` / `audit` 三组件共用 `strike/web/` + `recon/web/`**~~ **已撤回（误判，CP-004 §8.11 D-10 / §8.12 D-11）**：目录由 YAML 的 `recon_dir`/`strike_dir` **显式声明**，三者分别为 `api`+`web`、`model`+`model`、`""`+`evasion`，**并不共用**；此判断仅据目录名推断、未读声明字段。三组件**全部保留**（41 处引用零改动） | CP-004 审计 E-11 → §8.11 | **discarded** |
| BL-050 | 2026-09-12 | **10/10 份 `config/components/*.yaml` 仍带 W0 遗留字段**（`seed_sets`/`converter_vectors`/`strike_modules`/`report_builder`/`neighbors`/`owasp`）：BL-025 登记后未推进，违反蓝图 13.3「兼容层只减不增」 | CP-004 审计 E-09 | **open** |
| BL-051 | 2026-09-12 | ~~**`pyproject.toml` 与 `.gitignore` 正文为中文乱码**~~ **已撤回（伪缺陷，CP-004 §8.8 D-7）**：字节级校验两文件均为合法 UTF-8（`U+FFFD`=0），"乱码"是 Windows PowerShell 对无 BOM UTF-8 按 ANSI/GBK 渲染的**显示假象**；`data/seeds/**/*.prompt` 同批复核亦全部干净。**禁止据此开工** | CP-004 §8.8 D-7 | **discarded** |
| BL-052 | 2026-09-12 | **`data/seeds/asr_history.json` 仍在 git 跟踪中**（`git ls-files` 命中）：运行时写入导致每次运行工作树变脏，NEG-7 / 债务簿 D-16② 未闭环 | CP-004 审计 E-13 | **open** |
| BL-053 | 2026-09-12 | **R-TOOLS-2（≤850 行）实测 6 个超限文件**，`backlog` 仅登记 guard_extended 一条：`tools/guard_extended.py`(2469) / `arm/attack_surface_mapper.py`(1150) / `core/_arg_parser.py`(1109) / `tools/guard.py`(911) / `utils/display.py`(863) / `assess/judge_manager.py`(850 临界) | CP-004 审计 E-14 | **open** |
| BL-054 | 2026-09-12 | **`--resume` 的 `help="imports"` 为无意义占位**：字面满足 R-DOC-1（非空），实质违背"代码自描述"要求 | CP-004 审计 E-15 | **open** |
| BL-055 | 2026-09-12 | **打包与 CLI 元数据不一致**：`[tool.setuptools.packages.find] include` 缺 `targets*`（而 R-L7 白名单已含 `targets/`）；`[project.scripts]` 缺 gate/mock_range/oob/architecture，与 README §4 不对齐 | CP-004 审计 E-19/E-20 | **open** |
| BL-056 | 2026-09-12 | **`tests/e2e/` 不存在**：REQ-156⑤「e2e 进 CI」未达成（现有 `tests/golden/` 与 `tools/mock_range --check` 不等价于 5 靶标 × 4 维 e2e 断言） | CP-004 审计 B5 | **open** |
| BL-057 | 2026-09-12 | **组件化后路径已迁移但规约未回填（E-17，纯治理滞后，功能未丢）**：`strike/file_upload_executor.py`→`strike/injection/`、`output_filter_bypass.py`→`strike/model/filter_bypass.py`、`multimodal_injection.py`→`strike/model/multimodal.py`、`backdoor_attack.py`→`strike/model/backdoor.py`、`auth_attacks/web_attacks/audit_evasion.py`→`strike/web/attacks.py`、`web_orchestrator.py`→`strike/web/orchestrator.py`、`incremental_trust_builder.py`→`strike/a2a/trust_builder.py`、`a2a_workflow_attacker.py`→`strike/a2a/workflow_attacker.py`、`recon/multi_agent_topology.py`→`recon/a2a/topology.py`。受影响文档：`10-ARCHITECTURE` 第十章、`55-ATTACK-GAP-CLOSURE` §2/§3/§4/§5/§11 | CP-004 审计 E-17 | **open** |
| BL-058 | 2026-09-12 | **组件↔种子路由断裂**：全库种子 frontmatter 的 `suitable_for` 取值 100% 为 technique 名（无一是 `component_key`），且 `core.registry.for_seed_component` **零消费者** → 80 的 IA-5 / C-NAME-2 口径与现实脱节。**裁决（§8.4 D-3）：修订 IA-5 承认 technique 语义，归属改由 YAML `seeds:` 字段承载；禁止批量改写 117 份种子** | CP-004 审计 E-18 / §8.4 | **open** |
| BL-059 | 2026-09-12 | **组件集合缺 `multimodal_upload`**：`config/components/` 无对应 YAML，REQ-157①「三者注册入 ComponentRegistry」未闭环；实现现栖于 `strike/injection/file_upload_executor.py`（非 `strike/<id>/` 形态） | CP-004 审计 E-19 | **open** |
| BL-060 | 2026-09-12 | **审计证据纪律（建议新增文档纪律 D8）**：任何"编码损坏/乱码/不可读"结论**必须以字节级解码为准**（`read_bytes().decode('utf-8')`），禁止以终端打印 / IDE 预览 / PowerShell `Get-Content` 输出为准——Windows 对无 BOM UTF-8 的默认渲染必然产生伪乱码（BL-051 即由此误判） | CP-004 §8.8 D-7 | **open** |
| BL-061 | 2026-09-12 | **`config/components/session.yaml` 注释含行号坐标** `architecture_validator.py:83`，违反文档纪律 D2（禁行号坐标，改用 `模块.符号`） | CP-004 审计 | **open** |
| BL-062 | 2026-09-12 | **`multimodal_upload` 专用种子集待补**：当前复用 `data/seeds/web/`（`config/components/multimodal_upload.yaml` 已注明）；需新增 `data/seeds/_attack_surface/T*_UPLOAD_*`（frontmatter `category` 为技术标签，归属由 YAML `seeds:` 声明，依 §8.4 D-3） | 本次登记（P3-7 交付） | **open** |
| BL-063 | 2026-09-12 | **`multimodal_upload` 专用判据与报告章节待实装**：当前复用 `model_behavior_shift` 的 T0 与 rubric、`report.component_reports.model` 章节（无虚假设声明，已在 YAML 注明）；需新增 `t0_multimodal_upload_check`、`data/scorers/component_scorers/multimodal_upload.yaml`、`_build_multimodal_upload_sections` | 本次登记（P3-7 交付） | **open** |
| BL-064 | 2026-09-12 | **P0：`delete_uploaded_document` cleanup 动作尚未实现**：`multimodal_upload.yaml` 已按 I13 声明 cleanup，但动作未实装 → **含上传的副作用步在实装前只允许 dry-run 执行**（非 dry-run 必须被拒）。实装为本组件启用真实攻击的前置 | 本次登记（I13） | **open** |
| BL-065 | 2026-09-12 | ~~**P0（发布阻断）：`tools/gate.py` 未覆盖六步 + 存在静默降级**~~ **已闭环**：① `tools/gate.py` 重写为步骤注册表（`STEP_DESCRIPTIONS` / `COMMIT_STEPS` / `PUSH_STEPS`），commit=guard+architecture+ruff+dry-run，push=上述+pytest+drift+dataflow+e2e（e2e 缺目录时显式 INFO 并登记 BL-056）；② 删除全部静默降级——`_ruff()` 缺 ruff、`_run()` 命令不存在均**阻塞**（NEG-9）；③ 新增 `tools/guard_gate.py` 实现 R-GATE-1（阶段等价）/ R-GATE-2（禁静默跳过）/ R-GATE-3（hooks 在线性），已注册进 `tools/guard.py`；④ 新增 `--describe`（ADR-009，规约文档改引用命令输出）。验证：`python -m tools.gate --stage push` → `[GATE PASS] 8 步 + registry 接线`；R-GATE-2 负面测试（回退为旧静默行为）→ 2 阻塞、退出码 1 | CP-004 §8.7 D-6 | **completed** |
| BL-066 | 2026-09-12 | **偶发失败（flaky）测试**：`tests/common/test_adapters.py::TestComponentTargets::test_a2a_fetch_card_and_send_task` —— 单独跑该用例报 `KeyError: 'name'`，整文件或全量跑则通过（1996 passed）。疑似 `MockRange(port=0)` 的端口绑定时序/用例顺序依赖。**全量门禁曾因此出现 1 failed**，未做定向修复（避免掩盖） | 本次门禁实测 | **open** |
| BL-067 | 2026-09-12 | **`tools/guard.py` 自身存在静默降级**：`_register_all_extended_checks()` / `_register_gate_checks()` 用 `logger.debug` 吞掉 `ImportError` → 扩展检查器整体失效时无人察觉（同 E-06 病根）。应改为 `logger.warning` 或计为 WARNING violation | 本次实测 | **open** |
| BL-068 | 2026-09-12 | **规约同步（ADR-009 / R-DOC-4）待办**：① `specs/README.md §2` 六步表改为引用 `python -m tools.gate --describe` 输出（禁手抄命令）；② `40-GUARDRAILS.md` 1F 登记簿增 `check_gate_stage_parity` / `check_gate_no_silent_skip` / `check_hooks_installed` 三行；③ 1J 后补 R-GATE-1~3 红线条目。属文档层，须持专项任务规格 | 本次交付 | **open** |
| BL-069 | 2026-09-12 | **e2e 门禁步骤处于"目录不存在即跳过"状态**：`tools/gate.py` 的 e2e 步在 `tests/e2e/` 缺失时打印 INFO 并跳过（不阻塞）。`tests/e2e/` 落地后该步自动生效，届时**须把跳过改为阻塞**（否则 REQ-156⑤ 形同虚设） | 本次交付 / BL-056 | **open** |

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
