# 变更提案：CP-004（生产级硬化：规约–代码真实一致 + 门禁归位 + AI 组件面补齐）

> **类型**：L0/L1/L2/L4 多点联动修正（C12 修正案通道）+ 需求登记（`20-REQUIREMENTS.md` 第九章 E）+ 护栏登记（`40-GUARDRAILS.md`）
> **提案人 / 日期**：AI 起草 / 2026-09-12（**评审人栏待人工签署，AI 不得代填**）
> **状态**：`draft` → `评审中` → `approved / rejected / deferred`（转 backlog）
> **关联既有提案 / 计划**：`CP-001`（v4.0 六抽象，W0–W5）、`CP-002`（REQ-160~171）、`CP-003`（L5 基线接线）、`447be21ad0594078a923a53f701087d3-EXECUTION-PLAN.md`
> **去重声明（C3）**：本提案**不重复登记** TargetAdapter(149) / SurfaceGraph(150) / PlaybookEngine(151) / ImpactChain(152) / ComponentRegistry(153) / Mock 靶场(156) / 脱敏快照(158)；只做**加严**与**补齐尚未登记的组件缺口**。
> **版本**：v1.0（2026-09-12 初版）
> **证据基准**：本文 §1 全部结论来自 2026-09-12 对本工作区的实测（命令可复跑），非文档转述。

---

## 0. 三句话速记

| | |
|---|---|
| **本文主张** | `pyrit-mini` 离生产级的**最大差距不是功能缺失，而是"声明与实现不一致"**：声称的唯一门禁入口实际只跑六步中的三步、文档引用了根本不存在的模块与 CLI、backlog 状态滞后于已闭环的代码、以及**企业第一大类目标（单 Agent）在组件矩阵中根本未登记**。 |
| **一句话痛点** | 一个严谨的操作员按 `specs/README.md §2` 跑"唯一门禁入口"，实际只跑了六步中的三步；而 C10 要求"全部执行、全部通过"。这是结构性 C9/C10 违例，不是文档小瑕疵。 |
| **产出形态** | 5 个波次（W-P1~P5），每波可执行 DoD + Go/No-Go；新增 REQ-172~176 / NFR-20~24 / NEG-8~10 / ADR-009~011 / I14~I15 / R-GATE-1~2 · R-DOC-6 · R-COMP-2。全部走既有任务协议（≤3 文件 / ≤300 行 / ≤2 模块 / ≤1 新文件）。 |

---

## 1. 动机：为什么"看起来齐了"却不到生产级

### 1.1 三条系统性病害

| # | 病害 | 表现 | 根因一句话 |
|---|------|------|------|
| **D-A** | **治理漂移（Governance Drift）** | 规约声明的能力/门禁/命令，实际不存在或未执行；反之代码已闭环的能力，状态表仍标"待实施" | 文档写一张表、代码写另一套，中间没有机器守恒 |
| **D-B** | **组件面缺位（Component Blind Spot）** | 企业第一大类目标——**单 Agent（ReAct / Tool-use）**——未登记为组件；`gateway`/`web_api`/`audit` 三组件共用一套目录 | 蓝图 13.4 / 执行计划 §4 的"9 类组件矩阵"停留在 plan 文档，未落到 `config/components/*.yaml` 这个 SSOT |
| **D-C** | **交付确定性不足** | 交付包不含 `targets/`；`asr_history.json` 仍被 git 跟踪（每次运行污染工作树）；`pyproject.toml` / `.gitignore` 正文为乱码 | NEG-7 / NFR-19 无机器检查器守 |

> **为什么必须先修这三条**：宪法 C9「诚实汇报」与 C10「验证义务」是本项目治理的根。根是虚的，上面盖得再高的 ASR 优化都无法被信任——**你无法判断一次观察到的 ASR 上升是能力变强，还是门禁没跑**。

### 1.2 实测证据表（E-01 ~ E-16）

> 复现方式：在本仓库根目录（`pyrit-mini/`）执行"复现"列命令，并对照"规约声称"。

| # | 实测现象 | 复现 | 规约声称（矛盾点） |
|---|---------|------|-------------------|
| **E-01** | `tools/gate.py` 的 commit 阶段仅跑 **ruff + guard + registry wiring**；push 阶段再加 **drift + data-flow**。README §2 六步中的 **Step 1.5 架构体检、`Step 3 pytest tests/` 全量、`Step 4 main.py --dry-run` 三步从未被 gate 执行** | `python -m tools.gate --stage commit`<br>`rg "def _run\|_ruff\|_registry_wiring" tools/gate.py` | README §2：`python -m tools.gate` 是上表的**唯一代码实现**；C10：全部执行缺一不可 |
| **E-02** | `tools/quick_check.py` / `tools/watch_guard.py` / `tools/cross_model_review.py` **均不存在**（已并入 `guard.py`，pyproject v3.0 注释亦如此） | `Test-Path tools/quick_check.py` → False | README §4 CLI 表列 `pyrit-quick` / `pyrit-watch` / `pyrit-cross` 三条；40-G §6 与 7E 同样引用 |
| **E-03** | `tools/data_flow_validator.py` 不存在，实际为 `tools/dataflow/validator.py` | `Test-Path tools/data_flow_validator.py` → False | 10-ARCHITECTURE 文件头"已合并"段 + 40-G 1A-DATA 引用前者 |
| **E-04** | `docs/guides/` 目录不存在 | `Test-Path docs/guides` → False | EXECUTION-PLAN §2.2、§12「REQ-144 同步 `docs/guides/`」、W5-4 落点 |
| **E-05** | `.git/hooks/pre-commit` **未安装** | `Test-Path .git/hooks/pre-commit` → False | README §2.1「三层防线」称 pre-commit/pre-push 已在线；40-G 第三章称三层必须同时在线 |
| **E-06** | `tools/gate.py` 的 `_ruff()` 在 ruff 未安装时打印 `[SKIP] …跳过（非阻塞）`；`_run()` 遇 `FileNotFoundError` 同样"视为非阻塞"。**这是结构性静默降级** | `rg "SKIP\|非阻塞" tools/gate.py` | C9 / R-H1：静默降级一律须显式声明；40-G 第三章禁止静默旁路 |
| **E-07** | **CP-003 实际已落地完毕，但状态表未反映**：`defaults.yaml` 中 `l5_optimal_paths`、`max_escalation_targets`、`tap_branching`、`auto_seed_expansion_factor`、`post_l1/post_l2_exit_threshold`、`api_timeout`、`probe_retries`、`scorer_timeout`、`timeout_max_{retries,delay}` 全部已有 1–3 个真实消费者；原 BL-038 列表中的 `adaptive_epsilon`/`tap_success_threshold`/`priority_scheduler_*`/`rate_limit_retries`/`gcg_suffix_len`/`dos_*`/`auto_l4_*` 已摘除 | 逐键 `rg <key> --glob '*.py'`（排除 `tests/`、`_config_parsers.py`） | BL-038 仍标 `open` 并称"仍死 19 键"；README §2 基线未更新；20-REQUIREMENTS 第九章 D3 未回填 |
| **E-08** | 升级链 **L1–L4 阶梯已实现**：`strike/common/escalation_runtime.py` 存在 `_LADDER` / `resolve_ladder_levels()` / `_resolve_ladder_strategies()` / `should_exit_ladder()`，且已从 ctx 读 `post_l1_exit_threshold` / `post_l2_exit_threshold` | `rg "_LADDER\|should_exit_ladder" strike/common/escalation_runtime.py` | 20-REQUIREMENTS REQ-005 状态、README §2 2026-09-12 基线均未反映 I4/ADR-005/R-L5 阶梯已闭环 |
| **E-09** | **10/10 份** `config/components/*.yaml` 仍同时携带 W0 遗留字段 `seed_sets`/`converter_vectors`/`strike_modules`/`report_builder`/`neighbors`/`owasp` | `rg "^ *(seed_sets\|converter_vectors\|strike_modules\|report_builder\|neighbors\|owasp):" config/components/` | 蓝图 13.3「兼容层只减不增」；80 §6.1 Checklist 明写"不写遗留字段"（BL-025） |
| **E-10** | **组件矩阵缺 `agent`**：无 `config/components/agent.yaml`，`strike/` 与 `recon/` 下无 `agent/`，无 `T*_agent_*` 种子集；而 `strike/a2a`、`strike/mcp`、`strike/rag`、`strike/session` 均有目录 | `ls strike/`、`ls recon/`、`ls data/seeds/_attack_surface/` | 蓝图 13.4 / EXECUTION-PLAN §4 列有 **Agent** 一行（"越权工具调用/未确认执行/参数越界"）；但按 C6「未登记 = 不存在」，YAML 中无 `agent` 即不存在 |
| **E-11** | `gateway`(key `llm_gateway`)、`web_api`(id-in-yaml `web_infra`)、`audit` 三组件**共用 `strike/web/` + `recon/web/`**，无各自目录 | `ls strike/ recon/` | 80 §4 **C-NAME-1**：`id` 与目录名字面一致 |
| ~~**E-12**~~ **（已撤回，见 §9 D-7）** | ~~`pyproject.toml` 与 `.gitignore` 正文为中文乱码~~ **撤回**：字节级校验表明两者均为合法 UTF-8（`U+FFFD` 计数为 0），此前判定的"乱码"是 Windows PowerShell 对**无 BOM UTF-8** 文件按 ANSI/GBK 渲染产生的**假象**，非缺陷 | `python -c "import pathlib;pathlib.Path('pyproject.toml').read_bytes().decode('utf-8')"` → 无异常 | 无（原登记 **BL-051 同步撤回**）；教训见 §9 D-7 |
| **E-13** | `data/seeds/asr_history.json` **仍在 git 跟踪中**（虽已在 `.gitignore` 列表内，但历史已入库），运行时写入 → 每次运行工作树变脏 | `git ls-files \| rg asr_history` | NEG-7 明令禁止运行时产物入库；债务簿 D-16② 称"asr_history 迁 outputs/ 并入 .gitignore" |
| **E-14** | R-TOOLS-2（≤850 行）现存 **6 个超限文件**：`tools/guard_extended.py`(2469) / `arm/attack_surface_mapper.py`(1150) / `core/_arg_parser.py`(1109) / `tools/guard.py`(911) / `utils/display.py`(863) / `assess/judge_manager.py`(850 临界) | 见 50-ROADMAP §1.2 行数实测量命令 | 40-G 1A-TOOLS R-TOOLS-2；backlog 仅登记 `guard_extended` 一条（BL-026），**登记不全** |
| **E-15** | `--resume` 的 `help="imports"` 是无意义占位 | `rg '"--resume"' core/_arg_parser.py` | R-DOC-1 要求"代码自描述，运行 `--help` 即得"；字面满足、实质违背 |
| **E-16** | IC-1 迁移半途：`component_type` 出现在 36 个文件，`component_labels` 仅 8 个、`label_confidence` 11 个、`graph_ref` 6 个；`strike/common/dispatcher.py` 仍有 19 处、core/phases 12 处字面量组件名 | `rg -c "component_type\|component_labels"` + `rg '"(mcp\|a2a\|rag\|agent)"' core/phases/*.py strike/common/dispatcher.py` | IC-1/IC-3（W1-9）；ADR-007 / R-EVENT-1 |
| **E-17** | **组件化后路径已迁移但规约未回填**：`strike/file_upload_executor.py`→`strike/injection/file_upload_executor.py`；`output_filter_bypass.py`→`strike/model/filter_bypass.py`；`multimodal_injection.py`→`strike/model/multimodal.py`；`backdoor_attack.py`→`strike/model/backdoor.py`；`auth_attacks.py`/`web_attacks.py`/`audit_evasion.py`→`strike/web/attacks.py`；`web_orchestrator.py`→`strike/web/orchestrator.py`；`incremental_trust_builder.py`→`strike/a2a/trust_builder.py`；`a2a_workflow_attacker.py`→`strike/a2a/workflow_attacker.py`；`recon/multi_agent_topology.py`→`recon/a2a/topology.py` | `Test-Path strike/auth_attacks.py` → False；`rg run_output_filter_bypass -l` → `strike/model/filter_bypass.py` | 10-ARCHITECTURE 第十章、55-ATTACK-GAP-CLOSURE §2/§3/§4/§5/§11 全部仍引用旧路径（D5）；**功能均未丢失，纯治理滞后**（区别于 E-02 的"能力不存在"） |
| **E-18** | **组件↔种子路由断裂**：全库种子 frontmatter 的 `suitable_for` 取值**全部是 technique 名**（`prompt_sending`/`crescendo`/`tap`/`skeleton_key`/`rag_attack`…），**无一个是 `component_key`**；且 `core.registry.for_seed_component` **零消费者** | `rg "^\s*suitable_for:" data/seeds -h \| sort -u`；`rg for_seed_component -l` → 仅 `core/registry.py` | 80 §3.3 **C-NAME-2** / **IA-5**（`suitable_for` 必须等于 `component_key`）与现实脱节 |
| **E-19** | **组件集合缺 `multimodal_upload`**：`config/components/` 无对应 YAML，而 REQ-157① 要求三者"注册入 ComponentRegistry"（实现在 `strike/injection/file_upload_executor.py`，非 `strike/<id>/` 形态） | `ls config/components/`；`Test-Path strike/multimodal_upload` → False | REQ-157① / IA-8 / 执行计划 §4「Multimodal/Upload」一行 |

> **证据纪律**：上表每条均可由命令独立复现。若某条在读到此文前已被其他工作闭环，**以代码现实为准**（C9），并把差集登记进 backlog；不得反向删改本表来"对齐"。

---

## 2. 生产级判据（Production-Grade Bar）

> 本节定义"什么算生产级"，避免方案自我论证（这是本次不同于以往提案的关键：先立标尺，再排任务）。

| # | 维度 | 判据（可勾选 / 可机器化） | 当前 |
|---|------|--------------------------|------|
| **B1** | **Verifiable（可判定）** | 规约中每条红线/不变量都有检查器，且检查器在 `python -m tools.guard --list-checks` 可解析 | 🟡 部分（1F 登记 39 行 vs 代码 46 个 `def check_*`，BL-028） |
| **B2** | **Executable（可执行）** | 单点命令 `python -m tools.gate --stage push` **覆盖 README §2 全部六步**；缺失依赖 = 环境不合格 = BLOCKING（不允许 SKIP） | 🔴 **未达标**（E-01 / E-06） |
| **B3** | **Reproducible（可复现）** | 同一 commit + 同一 `targets/mock/fixtures/expected.yaml` → 每类靶标的"识别标签 / playbook 成功率 / verdict 四态 / cleanup 后状态"可断言 | 🟡 有 `tools/mock_range --check` + `tests/golden/`，**无 `tests/e2e/`** |
| **B4** | **Explainable（可解释）** | 任一 finding 可回溯：`evidence_id → EventLog 事件 ts → SurfaceGraph 节点 → 组件标签 + 置信度` | 🟡 EventLog/EventLog 哈希链已落（REQ-169），多归因（IC-3）未收敛 |
| **B5** | **Regressible（可回归）** | 5 类靶标 e2e 进 CI；新增组件必须先有 e2e 断言才准接入框架层 | 🔴 **未达标**（`tests/e2e/` 不存在，REQ-156⑤） |
| **B6** | **Deliverable（可交付）** | `pip install -e .` 后 `pyrit-*` 入口与 README §4 双向一致；脱敏 + `evidence_manifest.sha256` + PoC 独立可跑；跑完 `--dry-run` 后 `git status` 仍 clean | 🟡 打包缺 `targets*`；E-13 使 git 不 clean |

**判定规则**：B2 与 B5 为**发布阻断**（任一 🔴 = 不具备生产级交付资格）；其余为 90 天内补齐项。

---

## 3. 规格 diff（精确到文件与位置）

### 3.1 新增需求：`20-REQUIREMENTS.md` 第九章 E（AI 组件面补齐）

> **背景**：针对"企业 LLM 应用核心组件（agent / 多 agent / mcp / rag / embedding）"的生产级覆盖。以下全部为 **C6 留白项**（当前未登记 = 不存在）。

| ID | 陈述 | 验收标准 | 优先级 |
|----|------|----------|--------|
| **REQ-172** | **单 Agent（ReAct / Tool-use）组件登记与接线** | ① 新增 `config/components/agent.yaml`（`id: agent`，`component_key: agent_tool_integrity`，含 `labels`/`detect.signals`(含 `tools[]`/`functions[]`/`tool_calls`)/`recon`/`seeds`/`converters`/`playbooks`/`scorer`/`report_section`/`cleanup`）；② `recon/agent/` 提供工具 Schema 抽取 + 权限边界 + 确认点探测；③ `strike/agent/` 覆盖越权工具调用 / 未确认副作用执行 / 参数越界 / 工具返回值注入四类，全部经 PyRIT 原生 `PromptSendingAttack`/`CrescendoAttack` 投递（C1）；④ 新增种子集 `data/seeds/_attack_surface/T*_agent_*`，归属由 `agent.yaml` 的 `seeds:` 字段声明，frontmatter `category` 保留为技术标签（**依 §8.4 D-3：`suitable_for` 现役语义为 technique 过滤器，不再要求等于 `component_key`**）；⑤ `assess/component_scorers.py` 注册 T0 + rubric；`report/component_reports.py` + `component_poc.py` 注册；⑥ `get_registry().validate_wiring()` 返回空 | **P0** |
| **REQ-173** | **Multi-Agent / A2A 跨 agent 攻击执行层**（承接并加严 REQ-109） | ① cross-agent injection / agent impersonation / workflow corruption 三类**以 `config/playbooks/*.yaml` 表达**（不再仅以种子形态存在）；② 在 `targets/mock/a2a_agent` 靶标端到端跑通并有 e2e 断言；③ 复用已落地的 `_TargetAdapterWrapper` → `A2ATarget`（IC-2），不得另建第二套链机制（C3 / IC-4） | P1 |
| **REQ-174** | **MCP 深链覆盖面扩展** | ① 在既有 `mcp_enum_call.yaml` 之外补 `mcp_schema_poison.yaml`（工具描述投毒 → 采纳验证）与 `mcp_tool_chain.yaml`（工具串链 → 外传信道验证）；② 三条链在 `mcp_server` 靶标均有 success/verdict/cleanup 断言；③ 原 `strike/mcp/malicious_server.py` 硬编码分支随迁移删除（IC-4，删除期限登记 backlog） | P1 |
| **REQ-175** | **RAG 投毒链与跨租户 IDOR** | ① `rag_poison.yaml`（写→触发→"投毒文档被引用"验证）迁移自 `strike/rag/data_poisoning.py` + `strike/common/_executor_doc_poison.py`；② 跨租户 `doc_id` IDOR 判定成立需 **二次独立请求确认**（IC-6）；③ 迁移后删原分支 | P1 |
| **REQ-176** | **Embedding 的 Q4 裁决机器化** | ① `config/components/embedding.yaml` 增显式标记 `attack_execution: recon_only`（契约新增字段，见 `config/components/README.md`）；② **任何向 `recon_only` 组件写入 strike/执行分支的 diff 由 `check_recon_only_component()` BLOCKING**（把 90 §4 / 蓝图 Q4 的"黑盒 HTTP 不可测试 → 编排内不实装"从人工记忆变成机器兜底）；③ Embedding 风险经间接注入（arXiv:2302.12173）与 RAG 投毒（arXiv:2406.04245）路径覆盖，不在 embedding 组件内实装执行；④ **黑盒命中的 embedding 相关 finding 一律多归属到 `rag` 或 `session`（IC-3）**，`embedding` 只出现在 labels 与"侦察风险清单"章节，**不产生独立 finding、不计入 ASR 分母**（与 `supply_chain` 同处理）；⑤ 豁免 I15 / IA-8 对 `strike/<id>/` 目录的要求，该豁免须由 YAML 的 `recon_only` 标记驱动（依 §8.5 D-4） | P1 |

### 3.2 新增 NFR

| ID | 维度 | 标准 |
|----|------|------|
| **NFR-20** | 门禁等价性 | `python -m tools.gate --stage push` 的执行集合 ≡ `specs/README.md §2` 六步表；由 `check_gate_stage_parity()` 校验，**不等价即 BLOCKING** |
| **NFR-21** | 文档引用可执行性 | 规约正文出现的 `tools.<mod>` / `pyrit-*` / 相对文件路径必须可 import 或存在；失败进 `check_spec_code_sync()` 的 WARNING 及以上 |
| **NFR-22** | e2e 回归 | 5 类 mock 靶标 ×（识别标签 / playbook 成功率 / verdict 四态 / cleanup 后状态）四个维度必须存在断言；新增组件无 e2e 断言不准接入框架层 |
| **NFR-23** | 续跑幂等 | `--resume <run_id>` 从 `events.jsonl` 恢复，已完成 step 不重跑；同一 run 重复 `--resume` 两次，产出的 `evidence_manifest.sha256` 除时间戳外一致（可由 `<run_id>` 归档目录 diff 验证） |
| **NFR-24** | 打包与CLI一致性 | `[project.scripts]` 与 README §4 双向对齐（不多不少）；`[tool.setuptools.packages.find] include` 必须包含所有被 R-L7 白名单接受的顶层包 |

### 3.3 新增 NEG（负需求）

| ID | 禁止事项 | 理由 |
|----|---------|------|
| **NEG-8** | 禁止在规约文档中引用仓库内不存在的模块路径、CLI 或 entry_point | D5 / R-DRIFT-2；E-02~E-04 复发护栏 |
| **NEG-9** | 禁止 `tools/gate.py` 的阶段覆盖与 `specs/README.md §2` 六步不等价；禁止在 gate 内把缺失依赖降级为 `[SKIP] 非阻塞` | C9 / R-H1；E-01 + E-06 |
| **NEG-10** | 禁止在未跑 `python -m tools.gate --stage push` 的情况下把 L0–L4 规约变更声明为"已验证" | C10 / C9 |

### 3.4 新增 ADR

| ADR | 决策 | 摘要 |
|-----|------|------|
| **ADR-009** | **单一门禁入口即门禁本体** | README §2 不再手工抄写六步命令表，改为描述"阶段 → 责任"并**指向 `tools/gate.py` 的阶段常量**（`--stage commit/push/all`）；命令清单由代码生成（`python -m tools.gate --describe`），彻底消灭"文档表 vs 代码实现"这对孪生漂移源（C3 / D1） |
| **ADR-010** | **组件面以 YAML 为唯一事实源，plan 文档降级为说明** | EXECUTION-PLAN §4 的"9 类组件矩阵"不再是权威；组件的存在性一律以 `config/components/*.yaml` + `get_registry().keys()` 为准。任何 plan 文档中出现而 YAML 中缺席的组件视为**未登记**（C6），落地前必须补 YAML |
| **ADR-011** | **裁决机器化（Q4 → `recon_only`）** | 凡属"黑盒 HTTP 不可测试"的组件（当前：embedding），其裁决结论**必须在 YAML 中落为机器可读标记**并由 guard BLOCKING 兜底，不得只写在规约正文里靠人记忆 |

### 3.5 新增不变量

| # | 不变量 | 依据 |
|---|--------|------|
| **I14** | 门禁等价：`tools.gate --stage push` 的执行步骤集合 ≡ README §2 所声称的全部步骤；环境缺失依赖不产生"非阻塞跳过" | NFR-20 / NEG-9 / C10 |
| **I15** | 组件–目录一致：`get_registry().names()` 中每个 `id` 必须存在 `strike/<id>/` 或 `recon/<id>/`；侦察级组件须在 YAML 显式声明 `recon_only: true` 方可豁免 | 80 §3.1 / S-DIR-1 / C-NAME-1 |

### 3.6 新增红线与 guard 检查器

| # | 红线 | 级别 | 检查器（随波次落地） |
|---|------|------|---------------------|
| **R-GATE-1** | 门禁等价：gate 阶段覆盖与规约声明不等价 | BLOCKING | `check_gate_stage_parity()` |
| **R-GATE-2** | 门禁不得静默跳过：gate 内存在 `[SKIP] 非阻塞` 分支 / 缺失依赖未阻断 | BLOCKING | `check_gate_no_silent_skip()` |
| **R-GATE-3** | hooks 在线性：仓库未按 `python -m tools.hooks` 安装 pre-commit/pre-push 且未在汇报声明 | WARNING | `check_hooks_installed()` |
| **R-DOC-6** | 文档引用可执行：规约正文路径/模块引用不可解析 | WARNING | 扩展 `check_spec_code_sync()` |
| **R-COMP-2** | 组件–目录一致（I15） | WARNING（P3 完成起 BLOCKING） | `check_component_dir_consistency()` |
| **R-COMP-3** | `recon_only` 组件被写入执行分支（ADR-011） | BLOCKING | `check_recon_only_component()` |

> 依 40-GUARDRAILS 1F 纪律：**先改代码、再同步登记簿**；上表在实施前为登记占位，**不产生门禁效力**。

---

## 4. 执行波次（W-P1 ~ W-P5）

> 领任务规则沿用 30-TASKS 第三章粒度上限（≤3 文件 / ≤300 行 / ≤2 模块 / ≤1 新文件）；每波次退出条件未满足**不得进入下一波**（Go/No-Go 门禁）。

### W-P1 · 规约–代码对齐（零行为变更，纯文档 + backlog）

| ID | 任务 | 落点 | DoD |
|----|------|------|-----|
| P1-1 | 修 README §4 CLI 表：删除 `pyrit-cross`/`pyrit-quick`/`pyrit-watch` 三行；改为 ADR-009 的"指向 `--describe` 生成清单"形式 | `specs/README.md` | 表中无不存在模块 |
| P1-2 | 修 40-G §6 / 7E 的 `quick_check`/`watch_guard` 引用 | `40-GUARDRAILS.md` | 同 P1-1 |
| P1-3 | 修 10-ARCHITECTURE 文件头 `tools/data_flow_validator.py` → `tools.dataflow.validator` | `10-ARCHITECTURE.md` | 路径可 import |
| P1-4 | 修 EXECUTION-PLAN §2.2 / §12 / W5-4 的 `docs/guides/` 引用 | plans/ 执行计划 | 路径存在或删除引用 |
| P1-5 | **backlog 状态核对**：BL-025/026/031/037/038 复核，按 E-07/E-08 结论标 `converted`/`completed` 并移出 open 区 | `docs/backlog.md` | open 区每条可复现 |
| P1-6 | 登记 REQ-172~176 / NFR-20~24 / NEG-8~10 / ADR-009~013 / I14~I15 / R-GATE-1~3 · R-DOC-6 · R-COMP-2~3；**登记新纪律 D8（证据须字节级可验证）** | `20-REQUIREMENTS.md`、`40-GUARDRAILS.md`、`10-ARCHITECTURE.md`、`specs/README.md` | ID 唯一性自检 `dups: none` |
| P1-7 | **§8.2/§8.3 合并裁决落地（纯数据变更，不受粒度上限约束）**：新建 `config/components/web.yaml`（`id: web` / `component_key: web_infra` / `labels: [web_infra, llm_gateway, audit_evasion]`），删 `gateway.yaml` + `audit.yaml` + `web_api.yaml`；`session.yaml` 的 `id` 改为 `session`；E-17 的路径回填一并处理 | `config/components/`、`10-ARCHITECTURE.md`、`55-ATTACK-GAP-CLOSURE.md` | `get_registry().keys()` 由 10 → 8，`names()` 与目录一一对应；BL-024/BL-049 收敛 |

**Go/No-Go**：`python -m tools.drift_detector --full` 0 BLOCKING；REQ/NFR/NEG/R/ADR ID 唯一性命令输出 `dups: none`；README 版本列同步（R-DOC-4）。

### W-P2 · 门禁归位（发布阻断项，最高优先级）

| ID | 任务 | 落点 | DoD |
|----|------|------|-----|
| P2-1 | `tools/gate.py` 阶段补齐：`commit` 增 Step 1.5 架构体检；`push` 增 Step 3 `pytest tests/ -q` 与 Step 4 `main.py --dry-run --max-seeds 1` | `tools/gate.py` | `--stage push` 覆盖六步 |
| P2-2 | 去除静默跳过：`_ruff()` 未安装 → BLOCKING；`_run()` `FileNotFoundError` → BLOCKING | 同上 | 无 `[SKIP] 非阻塞` 分支 |
| P2-3 | 新增 `check_gate_stage_parity()` / `check_gate_no_silent_skip()` / `check_hooks_installed()` | `tools/guard_extended.py` | 违规可复现 BLOCKING/WARNING |
| P2-4 | 同步 40-G 1F 登记簿 + 1.5 Step 说明；删除 1F 中已不存在的检查器行（BL-028 同批处置） | `40-GUARDRAILS.md` | 登记簿 ⊆ 代码实际 `def check_*` |
| P2-5 | README §2 改为引用 gate 阶段常量（ADR-009），命令清单由 `python -m tools.gate --describe` 产出 | `specs/README.md`、`tools/gate.py` | 不等价即 R-GATE-1 命中 |

**Go/No-Go**：干净环境执行 `python -m tools.hooks && python -m tools.gate --stage push`，**六步全部真实执行**且任一步失败可中止提交；故意删掉 ruff 后 gate 返回非零。

### W-P3 · AI 组件面补齐（Agent / Multi-Agent）— 回应用户核心目标对象

| ID | 任务 | 落点 | DoD |
|----|------|------|-----|
| P3-1 | `config/components/agent.yaml`（REQ-172①）+ 契约字段定义写入 `config/components/README.md` | `config/components/` | `get_registry().spec("agent_tool_integrity")` 可读 |
| P3-2 | `recon/agent/`：工具 Schema 抽取 + 权限边界 + 确认点探测 | `recon/agent/` | 对 mock `tool_agent` 识别标签 `agent` 命中 |
| P3-3 | `strike/agent/`：越权工具调用 / 未确认副作用 / 参数越界 / 工具返回值注入（全部 PyRIT 原生投递） | `strike/agent/` | 四类在靶场各有 verdict |
| P3-4 | 种子集 `T*_agent_*` + **`agent.yaml` 的 `seeds:` 字段声明归属** + `assess/component_scorers.py` T0/rubric + report/PoC 注册 | `data/seeds/_attack_surface/`、`assess/`、`report/` | `validate_wiring()` 空 |
| P3-5 | REQ-173：A2A 三条跨 agent 链改 playbook YAML + `a2a_agent` 靶标 e2e | `config/playbooks/`、`tests/e2e/` | 三条链 success + cleanup 生效 |
| P3-6 | REQ-176：embedding 落 `attack_execution: recon_only` + `check_recon_only_component()`（判定粒度见 §8.6 D-5） | `config/components/embedding.yaml`、`tools/guard_extended.py` | 向 embedding 写执行分支被 BLOCKING；侦察增强类 diff 不被误伤 |
| P3-7 | **D-8 组件补齐**：`multimodal_upload` 组件登记 + `strike/multimodal_upload/`（**迁移** `strike/injection/file_upload_executor.py`，`strike/injection/` 作为共享位保留） | `config/components/`、`strike/` | `get_registry().keys()` 含 `multimodal_upload`；E-19 收敛 |

**Go/No-Go**：`get_registry().keys()` 含 `agent_tool_integrity` 与 `multimodal_upload`；`validate_wiring()` 空；`check_component_dir_consistency()` 对**攻击级**组件 0 WARNING（`embedding` / `supply_chain` 依 `recon_only` 标记豁免）；组件集合 ≡ §8.9 D-8 的 10 项。

### W-P4 · 深链迁移 + 影响链 + e2e（B3/B5 达标）

| ID | 任务 | 落点 | DoD |
|----|------|------|-----|
| P4-1 | REQ-175：`rag_poison.yaml`（**迁移非新建**，IC-4）+ 跨租户 doc_id IDOR（IC-6 二次确认） | `config/playbooks/` | 靶场端到端 + 删原分支 |
| P4-2 | REQ-174：MCP schema 投毒 + 工具串链两条 playbook | 同上 | 靶场端到端 + 删原分支 |
| P4-3 | `assess/impact/{model,canary}.py` 补齐（plan §2.1 落点） | `assess/impact/` | 四态判定可单测 |
| P4-4 | `tests/e2e/` 5 靶标 × 4 维断言 + `fixtures/expected.yaml`，进 `python -m tools.gate --stage push` | `tests/e2e/`、`tools/gate.py` | REQ-156⑤ 达成 |
| P4-5 | 迁移完成登记：删除 `strike/rag/data_poisoning.py`、`strike/common/_executor_doc_poison.py`、`_executor_vuln_inject.py`、`strike/mcp/malicious_server.py` 原分支 | 删除 + backlog 期限 | 无第二套链机制（IC-4 / RK-8） |

**Go/No-Go**：5 靶标 e2e 全绿；`rg "data_poisoning|malicious_server" strike/` 零生产引用；报告含影响链章节；脱敏 0 命中。

### W-P5 · 交付与包装一致性（B6 达标）

| ID | 任务 | 落点 | DoD |
|----|------|------|-----|
| P5-1 | `pyproject.toml`：`include` 补 `targets*`；`[project.scripts]` 按 README §4 双向对齐（补 gate/mock_range/oob/architecture 或删文档行）；修复乱码 | `pyproject.toml` | NFR-24 达成 |
| P5-2 | E-13 处置：`git rm --cached data/seeds/asr_history.json` + 运行时产物迁 `outputs/` | 仓库卫生 | 跑完 `--dry-run` 后 `git status` 仍 clean |
| P5-3 | `.gitignore` 乱码修复 + 规则复核 | `.gitignore` | 可读 |
| P5-4 | E-14 处置：为 6 个超限文件登记 `DEBT-xxx` 专项拆分任务（**不在本波拆分**，C4/NEG-1） | `10-ARCHITECTURE.md` 债务簿、`docs/backlog.md` | 债务簿"只减不增"成立 |
| P5-5 | E-09 处置：10 份 YAML 清遗留字段 + 核对 `core/registry.py` 无旧字段消费者 | `config/components/*.yaml` | 旧字段 0 命中（BL-025 闭环） |

**Go/No-Go**：`pip install -e .` 全新安装 → `pyrit-gate --stage push` 通过；CI（仓库根 `.github/workflows/spec-gate.yml`）全绿；`git status` clean。

---

## 5. 风险与裁决

| ID | 风险 | 触发信号 | 应对 |
|----|------|---------|------|
| **RK-P1** ✅ 已裁决（§8.7 D-6） | W-P2 补齐 pytest/dry-run 后 commit 变慢，开发者倾向 `--no-verify` | pre-commit 超时 >60s | 阶段分层不变：快检留在 commit，pytest/dry-run 留 push；超时本身作为待优化项登记 backlog，**不得通过删减门禁步骤解决**（NEG-5 / NEG-9） |
| **RK-P2** ✅ 已裁决（§8.6 D-5） | P3-6 的 BLOCKING 误伤合法 diff（例如对 embedding 的侦察改进） | 检查器误报率 >10% | 判定粒度收敛到"是否向 `recon_only` 组件写入 strike/执行分支"，侦察合入不改写的 diff 一律放行 |
| **RK-P3** ✅ 已裁决（§8.2 D-1 / §8.3 D-2） | W-P3 中 `gateway`/`web_api`/`audit` 三组件共目录的整改方向存在两种合法答案（拆目录 vs 合并组件） | 已由 §8.2 裁决 | **裁决：合并为单一组件（方案 B）**——`config/components/web.yaml`（`id: web` / `component_key: web_infra` / `labels: [web_infra, llm_gateway, audit_evasion]`），删 `gateway.yaml` 与 `audit.yaml`；**目录 `strike/web/`、`recon/web/` 保持不动**；`session.yaml` 的 `id` 同批修正为 `session`。**拆目录方案已否决**，不得实施 |
| **RK-P4** | BL-038 状态复核与 CP-003 的实际落地状态在证据上有偏差 | P1-5 复核结果与 §1.2 E-07 不一致 | 以**实测量**为准并在任务汇报 ⚠️ 栏显式声明差集（C9）；不得反向修改本文证据表来"对齐" |
| **RK-P5** | W-P4 迁移导致既有 A2A/MCP 路径行为漂移 | `--escalation-levels` 未显式指定时结果变化 | 沿用 CP-003 §3.2 零回归保证：迁移初版默认走旧路径，开关 `--playbook` 显式才启用，删除期限入 backlog |

---

## 6. ASR 影响评估

**净影响：中期显著变高，短期中性；门禁如实汇报带来的可归因性，其价值高于任何单点 ASR 提升。**

| 波次 | 对 ASR 的影响 | 依据 |
|------|--------------|------|
| W-P1 / W-P2 | **中性**（不改攻击路径），但**恢复可归因性** | 只有六步全跑，`reported_asr` 变化才能被归因到此 diff；这是阶段 0.5「基线后才允许声称 ASR 优化」的前置条件 |
| W-P3（Agent 组件） | **变高** | 企业第一大类目标此前**未登记**＝不存在（C6）。Tool-use Agent 的越权工具调用 / 未确认副作用执行 / 参数越界，目前既无组件声明、无专项侦察、无专属评分器，属成片未覆盖；登记后按 REQ-172 接线，四种判据均可进入 `reported_asr` 分子 |
| W-P4（深链迁移） | **变高**（长期）/ 口径收紧（短期） | 有状态多步链（RAG 投毒 / MCP 串链）可表达之前不可表达的成功；同时 IC-5/IC-6 使部分"文本命中但无实证"的样本降为 `exfil_suspected`/`content_only` → **`confirmed_asr` 下降属口径收紧而非能力退化**（ADR-008 / NFR-13④ / RK-7），报告须四态分列并注明口径 |
| W-P5 | 中性 | 交付卫生，不改攻击面 |

**授权边界**：全部在 R-S1~R-S5 之内。本提案**不引入任何新运行时依赖**（NEG-4）；P5-1 仅调整打包元数据。

---

## 7. 同批义务（批准后必做）

1. 更新受影响文档文件头版本号：`00-CONSTITUTION`（若触及）/ `10-ARCHITECTURE` / `20-REQUIREMENTS` / `40-GUARDRAILS` / `specs/README.md` §1 索引（R-DOC-4）；
2. 把 `90-AI-DEV-ARCHITECTURE.md` 第四章「已知差距与归宿」指针表补 REQ-172~176 与 R-GATE-*（该文自称无裁决权威，只引用）；
3. 跑 ID 唯一性自检（REQ/NFR/NEG/R/ADR 四类前缀）；
4. 按 C14 / R-CROSS-1：**本提案属 L0–L4 多点变更，合入前须过跨模型审查**；工具链当前未实施（BL-035），按降级条款走**人工审查模式 + 代码存档记录**，并标记 `needs-cross-model-pending`。

---

## 8. 裁决记录（2026-09-12，依 §8.1 两项原则）

> 用户要求按「AI 红队攻击者最佳实践原则 + PyRIT 原生优先原则」对本提案的待裁决项作出裁决。本节为**裁决正文**，裁决范围内的 CONFLICT 以本节为准（裁决序：§8 > §4 波次任务表 > 既有状态表）。

### 8.1 裁决所依据的原则

**原则 P1 — AI 红队攻击者最佳实践原则**

| 子条 | 内容 |
|------|------|
| P1-R1 | **攻击面按「可利用原语（exploitable primitive）+ 信任边界」划分，不按企业 IT 名词划分**。MITRE ATLAS / OWASP LLM Top 10 / OWASP AI Testing Guide / PTES 均按 technique 与系统层分类，没有一个主流框架按"网关/审计 模块"这种产品名词建攻击面 |
| P1-R2 | **一个组件必须能落到一级成立判据**：`ImpactChain`（能力→动作→影响）或 `ExfilChannel`（外传回执）（蓝图 13.7 横切判据）。两个候选组件若共享同一套原语、同一 TargetAdapter、同一判据族，则它们是**一个组件的两个 technique**，而不是两个组件 |
| P1-R3 | 判定等级由"实证强度"决定（ADR-008 四态），**不由分配到的组件名决定**；组件名不产生证据力 |
| P1-R4 | **可复现优先于覆盖面**（NFR-5）：PoC 必须单一可执行。把一次 HTTP 请求拆成"三个组件三个 PoC"直接破坏可复现性 |
| P1-R5 | **宁深勿广**：组件数增加 ⇒ 每组件平均接线深度下降 ⇒ 误报与回归难度上升；新增组件必须带来新的成立判据或新的 TargetAdapter，否则不算新组件（执行计划 RK-1 的同一 risk） |

**原则 P2 — PyRIT 原生优先（宪法 C1）**

| 子条 | 内容 |
|------|------|
| P2-N1 | PyRIT 的**域边界** = "与 LLM 的 prompt 交互与响应评估"（蓝图 [sid:10-ch3]）。域内的多样性由 `PromptConverter` / `Attack` / `Scorer` 表达，**不是由"新建组件/新建目录"表达** |
| P2-N2 | Web 侧三个攻击向量的终点是**同一个 `HTTPTarget`**（宪法 7C.4）。"多了一种 payload 构造器" ≠ "多了一种 target 类型"；自研部分必须收在 Glue / Enhancement / Output 三类之内（C13 企业扩展三原则） |
| P2-N3 | **复用原生 > 新建分支**：差异应由同一组件的 `converters` / `playbooks` / `scorer` 字段表达（ADR-007），不得用新目录表达同一原语内部的差异 |

---

### 8.2 D-1（原 RK-P3）：`gateway` / `web_api` / `audit` 三组件 → **合并**（方案 B）

> **⚠️ 本裁决已撤回（2026-09-12 后续取证，见 §8.11 D-10）。保留 `web_api` / `llm_gateway` / `audit_evasion` 三个组件。**
> 撤回前的原裁决为"合并"；后续读代码发现两处推翻性事实：① 三者在 `strike/common/chain_planner.py` 的**能力依赖不同**（`web_api` 需 `auth_token`、`llm_gateway` 需 `guardrail_profile`、`audit_evasion` 需 `log_blind_spot`）→ 按 P1-R1/P1-R2 是三个不同原语；② 三者**并未共用目录**（`strike_dir` 分别为 `web` / `model` / `evasion`），E-11 前提错误。以下论证保留以存档，但不再作为执行依据。

| 依据 | 论证 |
|------|------|
| P2-N2 | 三者最终都落 `HTTPTarget` + `PromptSendingAttack`（蓝图 10.4 / 宪法 7C.4）。在 PyRIT 原生视角它们是**同一个目标的三种 payload 构造器**，不是三种 target 类型。拆目录 = 用"新建自研目录"表达"转换器差异"，违反 P2-N3 |
| P1-R2 | 三者成立判据同族：都是"HTTP 请求头/体可控 ⇒ 服务端行为改变"，且都落到同一个 `ExfilChannel`（HTTP 侧信道）。同判据族的三个 key 拆开，会让"一次请求同时命中三个组件"变成常态（JWT alg=none + 日志注入可同一请求发出），产生 finding 归属爆炸与重复 PoC（违反 P1-R4） |
| P1-R1 | auth / rate-limit / cache / log-injection 在 PTES 与 OWASP API Top 10 里同属"Implementation / Runtime 层"，不构成三个独立攻击面 |
| **代码已先行投票（决定性 tie-break）** | E-17：组件化重构已把三者收敛进 **`strike/web/attacks.py` + `orchestrator.py` + `http_engine.py`**——代码侧**已经是合并态**，滞后的只有 YAML。合并方案的工作量 = **删 2 个 YAML + 0 行新代码**；拆分方案 = 新增 4 个目录 + 2 份 YAML + 全套接线（recon / seeds / assess / report / PoC），**远超 30-TASKS 第三章粒度上限**，且违反 C4 最小 diff 与蓝图 13.6「兼容层只减不增」 |

---

### 8.3 D-2：合并后的命名、目录与 `id == stem` 收敛

> **⚠️ 本裁决部分撤回（§8.11 D-10）**：不新建 `web.yaml`、不删任何组件。**仅保留"修正 `id == stem`"这一半**（已执行）。

| 决策点 | 裁决 | 理由 |
|--------|------|------|
| 哪个 key 保留 | 保留 `web_infra`（`llm_gateway`/`audit_evasion` 降级为 labels） | `web_infra` 已覆盖"基础设施面"语义；降级者保留为 labels 符合 IC-1 多标签，且**不丢分类学信息**（ATLAS/OWASP 映射仍可命中） |
| 为什么改 YAML 而不改目录 | IA-8「`id` 必须等于 YAML 文件名 stem」是硬规则，但**目录名 `web` 与三个 key 都不等**；改 YAML id（1 条数据）成本远低于改两个目录（涉及 imports、tests、guard 白名单、80 §3.1） | C4 最小 diff；S-DIR-1 已满足（`strike/web/` 是子目录，不是根目录攻击实现） |
| `session` 同案处理 | `session.yaml` 的 `id` 由 `memory_session_tenant` 改为 `session`（目录已是 `strike/session/`、`recon/session/`） | IA-8 同案；**BL-024 与 BL-049 并入同一批次**处置，不单独立项 |

---

### 8.4 D-3（原 E-18）：`suitable_for` 口径 —— **修订 IA-5 / C-NAME-2，不迁种子**

> **裁决**：承认 `suitable_for` 的现役语义是 **technique 过滤器**并据此修订 80 的 IA-5 / C-NAME-2；组件↔种子的归属改由 YAML `seeds:` 字段（80 §6.1 已要求）承载。**禁止为了打通该口径而批量改写 117 份种子 frontmatter。**

| 依据 | 论证 |
|------|------|
| 事实 | 实测 `suitable_for` 取值 100% 是 technique 名，`core.registry.for_seed_component` **零消费者**（E-18）——即 IA-5 从未被真正执行，改口是"把规则对齐现实"，不是降标准 |
| P2-N1 | 按 technique 过滤恰恰与 PyRIT 的心智模型一致：`ConverterConfiguration` 与攻击类选择本就按 technique/converter 走，不按目标组件走。让 frontmatter 承载 technique 是**原生友好**的，让它承载 `component_key` 反而制造了一个 PyRIT 域外概念 |
| P1-R5 / C4 | 迁 117 份文件是超大 diff、零 ASR 收益、高风险纯改造；而 YAML `seeds:` 字段已然存在且被 `validate_wiring()` 消费——**用已有的东西，不要再做一个** |
| **对 REQ-172 的修改** | 验收标准 ④ 中原写 `suitable_for: [agent_tool_integrity]`，**改为**：「新增种子集由 `config/components/agent.yaml` 的 `seeds:` 字段声明；frontmatter `category` 保留为粗粒度技术标签」 |

---

### 8.5 D-4（原 RK-P2 / REQ-176）：Embedding —— **维持 Q4 裁决，保留组件身份 + `recon_only: true`**

> **裁决**：embedding **保留为一个组件**（不降级为纯 label），但显式标记 `attack_execution: recon_only` 且 `attack_paths: []`；豁免 I15 / IA-8 对 `strike/<id>/` 目录的要求。

| 依据 | 论证 |
|------|------|
| P2-N1（决定性） | Embedding 反演/成员推断**不在 PyRIT 域内**（PyRIT 无此原生组件）。若实装 ⇒ 必为纯自研 ⇒ 违反 C1；而自研又必然产出 stub ⇒ 违反 R-H1。**两条路都堵死**，故 Q4 裁决必须维持 |
| P1-R2 | embedding 的黑盒风险面已被 `rag`（间接注入 / 语料投毒 / 跨租户检索泄漏）与 `session`（记忆污染）**完整覆盖**——它是风险来源，不是独立成立判据。P1-R3：判定等级与"挂哪个组件名"无关，挂 `rag` 一样能出 impact 判定 |
| P1-R1 | 保留组件身份是因为 OWASP AI Testing Guide 与 ATLAS 都有 embeddings 条目，**交付报告需要"该组件已被评估"的可举证性**——这不是技术需要，是合规举证需要，价值真实 |
| 防回潮约束 | 黑盒命中的 embedding 相关 finding 一律**多归属**到 `rag` 或 `session`（IC-3）；`embedding` 只出现在 labels 与"侦察风险清单"报告章节，**不产生独立 finding、不计入 ASR 分母**（与 `supply_chain` 同处理） |

---

### 8.6 D-5：R-COMP-3（`recon_only` 护栏）判定粒度 —— **三条件 AND 才 BLOCKING**

> **裁决**：以下三条**同时成立**才 BLOCKING，否则一律放行。针对 RK-P2 的"误伤合法 diff"担忧。

1. 目标 YAML 带 `attack_execution: recon_only`；
2. **且** diff 触及 `strike/<该 id>/`（新增或修改），或给该 YAML 增加非空的 `strike_modules` / `playbooks` / `attack_paths` 字段；
3. **且** 变更内容不是纯 `__init__.py` 导出 / 类型标注 / 文档字符串。

→ **明确放行**：`recon/embedding/` 的侦察增强、`recon:` 字段编辑、`labels` 调整、report 章节、`detect.signals` 扩充。

---

### 8.7 D-6（原 RK-P1）：门禁 stage 划分 —— **commit = 1/1.5/2/4；push = 3/5/6 + e2e**

> **裁决**：按此划分执行，并同步修订 `specs/README.md §2` 的原注（该注只写了"每次变更后 1–4 / pre-push 5–6"，缺少与 `--stage` 的映射，这正是 E-01 能长期漏检的直接原因）。

| stage | 步骤 | 裁决理由 |
|-------|------|---------|
| **commit（快门禁）** | 1 guard、1.5 架构体检、2 ruff、**4 dry-run** | `dry-run` 是**唯一 0-token 的运行时证据**（NFR-5），也是唯一能在秒级发现 `ImportError`/`AttributeError`/`KeyError`/`TypeError` 的手段——静态 guard 抓不到这一大类"数据流断点"（这恰是 C10 把 Step 4 单列的初衷）。成本几秒，收益极高 |
| **push / CI（全量）** | **3 pytest 全量**、5 drift、6 data-flow、**+ e2e** | pytest 全量放 push 而非 commit：在 commit 触发全量会诱导 `--no-verify`，而 40-G 第三章**明令禁止绕过 hooks**——`--no-verify` 比"晚一点发现"危险得多（RK-P1 的核心权衡） |
| **性能问题** | pre-commit > 60s 时 | **登记 backlog 作为性能专项**，通过缓存/增量/测试分片解决。**禁止以"太慢"为由删减门禁步骤**（NEG-5 / NEG-9） |

---

### 8.8 D-7（自我修正）：**撤回 E-12 与 BL-051**（伪缺陷，禁止据此开工）

> **裁决**：撤回。字节级校验确认 `pyproject.toml`、`.gitignore` 均为合法 UTF-8（`U+FFFD` 计数 = 0），此前判定的"乱码"是 **Windows PowerShell 对无 BOM UTF-8 文件按 ANSI/GBK 渲染产生的显示假象**，不是文件缺陷。

**这条撤回本身就是一条产出**——它暴露了一个会反复制造假缺陷的审计方法问题，故固化为纪律：

| 新纪律（建议登记入 `specs/README.md` §5） | 内容 |
|---|---|
| **D8 · 证据须字节级可验证** | 任何"编码损坏 / 乱码 / 不可读"类结论，**必须以字节级解码结果为准**（`Path.read_bytes().decode('utf-8')`），**禁止以终端打印、IDE 预览或 `Get-Content` 输出为准**。Windows PowerShell 对无 BOM UTF-8 文件的默认渲染必然产生伪乱码 |
| **影响范围复核** | 同理复核了 `data/seeds/**/*.prompt`（一度被误读为 117/117 损坏）：**全部干净**，无此项缺陷。已避免把无谓的"重编码 117 份种子"任务排入 W-P5 |

---

### 8.9 D-8：组件集合终态 —— **9 个攻击级 + 1 个 recon-only**

> **裁决**：组件集合以此为准，写入 `config/components/`；执行计划 §4 的"9 类矩阵"自此**降级为说明**（ADR-010），YAML 为唯一事实源。

| # | `id` | `component_key` | 处置 | 依据 |
|---|------|-----------------|------|------|
| 1 | `model` | `model_behavior_shift` | 保留（已含 filter_bypass / multimodal / backdoor → `strike/model/`） | 现状 |
| 2 | **`agent`** | `agent_tool_integrity` | **新增**（REQ-172） | P1-R1：Tool-use 是企业第一大类目标；P2-N2：其 TargetAdapter = HTTP + tool_calls 的可观测差异，构成独立原语 |
| 3 | `mcp` | `mcp_tool_poisoning` | 保留 | 现状 |
| 4 | `a2a` | `a2a_agent_integrity` | 保留 | 现状 |
| 5 | `rag` | `rag_pipeline` | 保留 | 现状 |
| 6 | **`multimodal_upload`** | `multimodal_upload` | **新增**（REQ-157①，E-19） | P1-R2：构造→上传→触发→验证 是**另一条**原语（multipart + 二次触发），与 `model` 的单轮 prompt 不同 |
| 7 | `session` | `session_memory` | 保留，**`id` 修正**（D-2） | BL-024 并入本批次 |
| 8 | **`web`** | `web_infra` | **合并三为一**（D-1/D-2） | 见 §8.2 |
| 9 | `supply_chain` | `supply_chain` | 保留，**侦察级**（不计 ASR 分母） | 现状（蓝图 13.4） |
| 10 | `embedding` | `embedding` | 保留，**`attack_execution: recon_only`**（D-4） | 见 §8.5 |

**迁移边界（IC-4，迁移非新建）**：`multimodal_upload` 的实现基础是已有的 `strike/injection/file_upload_executor.py`；`strike/injection/` 作为跨组件共享位**保留**（与 `strike/common/` 同性质，见 80 §3.3），执行器本体迁入 `strike/multimodal_upload/`。**禁止新建第二套文件上传执行器**（C3）。

---

### 8.10 裁决 → 提案条文的影响对照

| 提案原条文 | 裁决后状态 |
|-----------|-----------|
| §5 RK-P1（门禁 stage） | **已裁决** → §8.7 D-6；W-P2 的 P2-1 按 commit=1/1.5/2/4、push=3/5/6+e2e 实施 |
| §5 RK-P2（recon_only 误伤） | **已裁决** → §8.6 D-5；R-COMP-3 判定粒度固化为三条件 AND |
| §5 RK-P3（三组件 vs 合并） | **已裁决** → §8.2 D-1 + §8.3 D-2；**选合并**，否决拆目录 |
| §4 W-P3 P3-4（种子 `suitable_for`） | **修订** → §8.4 D-3；改为 YAML `seeds:` 字段声明，不迁 117 份种子 |
| §3.1 REQ-172 ④ | **修订**（同上） |
| §3.1 REQ-176（embedding） | **维持并加严** → §8.5 D-4；新增"多归属到 rag/session""不计入 ASR 分母" |
| §1.2 E-12 | **撤回** → §8.8 D-7；BL-051 同步撤回（标 `discarded`） |
| §1.2（新增） E-17 / E-18 / E-19 | **新增** → 分别对应 D-3/D-8 的证据基础；E-17 为纯治理滞后（功能未丢），**优先级低于 E-01/E-06** |
| §3.4 ADR | 追加 **ADR-012（组件粒度：按可利用原语与 TargetAdapter 划分，主体见 §8.2 / §8.3）**、**ADR-013（门禁 stage 划分，主体见 §8.7）** |

---

### 8.11 D-10（推翻 D-1 / 部分推翻 D-2）：**保留三个 Web 组件，撤回合并**

> **裁决**：`web_api` / `llm_gateway` / `audit_evasion` **各自保留为独立组件**；D-1 的合并方案与 D-2 的 `web.yaml` 新建方案**一并作废**。仅执行 D-2 中"修正 `id == stem`"的一半。

**推翻依据（均为执行前补做的代码取证，非推测）**：

| # | 事实 | 出处 | 对裁决的影响 |
|---|------|------|-------------|
| F-1 | 三者**能力依赖不同**：`web_api`→(`reachable_endpoint`,`auth_token`)；`llm_gateway`→(`system_prompt`,`guardrail_profile`)；`audit_evasion`→(`log_blind_spot`) | `strike/common/chain_planner.py:39,40,47` | 按 **P1-R1**（按可利用原语划分）与 **P1-R2**（判据族），它们是**三个不同原语**。合并会使 `chain_planner` 的能力依赖表失去表达力 → 可表达的多步链减少 → **降低 ASR**（违反 C2） |
| F-2 | 三者**语义关系类型不同**：`web_api`→`gated_by`、`llm_gateway`→`gated_by`、`audit_evasion`→`observes`；且入口节点候选只取 `web_api`/`llm_gateway` | `core/component_classifier.py:357-359,412` | `audit_evasion` 属**可观测性面**，取证方式（注入后日志内容是否改变）与前两者（即时请求/响应差异）不同族 |
| F-3 | **E-11 前提错误**：三者**并未共用目录**——目录由 YAML 的 `recon_dir`/`strike_dir` **显式声明**，分别为 `api`+`web`、`model`+`model`、`""`+`evasion` | `config/components/{web_api,gateway,audit}.yaml` | D-1 的"代码已先行投票（已合并到 `strike/web/`）"论证不成立；"三组件共目录"是**误判** |
| F-4 | 三键共 **41 处**代码引用（含 classifier / chain_planner / graph / scorers / report），语义不可互换 | 全仓 grep | 合并 = 行为变更 + 远超粒度上限，风险不可控 |

**自我检讨**：D-1 的论证把"**payload 构造器相同（同一个 `HTTPTarget`）**"错误地等同于"**可利用原语相同**"。按 P2-N2 前者成立，但组件划分的唯一依据是原语与判据（P1-R1/P1-R2）——所有 HTTP 攻击都用 `HTTPTarget`，若据此合并，则全站应只有一个组件，结论显然荒谬。**此为原则误用，予以更正。**

**执行结果（已完成）**：
- `web_api.yaml`：`id: web_infra` → `web_api`（对齐 stem；实测 `web_infra` 零消费方）
- `session.yaml`：`id: memory_session_tenant` → `session`（对齐 stem；实测零消费方）
- `config/components/README.md`：9 类组件清单同步为 `session` / `web_api`
- **未删除任何 YAML、未新增 `web.yaml`、未改动任何 `component_key`** → 41 处引用零改动，零回归

### 8.12 D-11：`id` 与目录的关系 —— 目录由声明决定，不由 `id` 推导

> **裁决**：80 的 IA-8（`id` == 文件名 stem）**保留为硬规则**；C-NAME-1 中"`id` 与目录名字面一致"**修订为**：目录归属由 YAML 的 `recon_dir` / `strike_dir` **显式声明**，`id` 只需等于 stem。据此修订 I15。

- 依据：`config/components/*.yaml` 已普遍使用 `recon_dir`/`strike_dir` 显式声明目录（如 `web_api`→`recon_dir: api`+`strike_dir: web`），这是既有事实标准；`id` 同时承担"文件名标识"职责，强迫它再等于目录名会造成三元冲突（stem / dir / id 三者不等时无解）。
- **I15 修订为**：组件必须在 YAML 中声明至少一个**真实存在**的落点（`strike_modules` 或 `recon_modules` 经 `validate_wiring()` 校验）；`strike/<id>/` 专属目录为推荐形态，共享位（`common` / `injection` / `evasion` / `web`）为合法形态。
- **BL-049 撤回**（`discarded`）：其"三组件共用目录"的判断基于目录名推断，未读 `strike_dir` 声明，属误判。

---

## 9. 评审结论（人工填写，AI 不得代填）

> **代录入声明**：本节按 C12 须由人工签署。**截至本文起草时尚未获签字**，REQ-172~176 与 R-GATE-* 等在批准前**不得进入编码**（C6 规格先行）。

- [ ] 批准（附条件建议：① W-P1/W-P2 为零容忍发布阻断项，优先于任何新功能；② W-P3 的 RK-P3 须先裁决再实现；③ W-P4 迁移遵守"迁移非新建"（IC-4），原分支删除期限登记 backlog；④ 每波收尾必须跑 `python -m tools.gate --stage push` 并保持 `specs/README.md` 版本列同步）
- [ ] 驳回（理由：___）
- [ ] 转 backlog（BL-___）

评审人 / 日期：________________（待人工签署）
