# 90 — AI 编程架构设计总纲（AI Development Architecture Master Plan）

> **文档层级**：配套层（与 50-ROADMAP 同级，**无独立裁决权威**）。本文件是 AI 编码代理的"需求 → 落点 → 流程"导航图：只做映射与引用，**不声明任何新规则**。规则本体全部在 00–80 规约金字塔，任何冲突以金字塔为准（裁决序见 `00-CONSTITUTION.md` 第二章）。
> **读者**：新会话冷启动的 AI 编码代理（必读）、评审 AI 交付物的人工。
> **版本**：v1.0（2026-09-12：初版，产品契约映射 / 架构落点 / 遵循流程 / 差距指针 / 纪律自检）
> **版本史**：`git log -- docs/specs/90-AI-DEV-ARCHITECTURE.md`（文档纪律 D3，正文不再维护）

---

## 0. 三句话速记 [sid:90-ch0]

| | |
|---|---|
| **本文是什么** | 产品契约（五条需求）→ 六阶段流水线 / v4.0 六层架构 / REQ 编号的**映射表**，外加 AI 编码的强制流程导航与差距指针。 |
| **本文不是什么** | 不是规则源。所有规则（原生优先 / SSOT / 门禁 / 红线 / 粒度上限）的唯一权威在 00/10/20/30/40/80，本文一律引用。 |
| **AI 何时读** | 每个新会话冷启动第一篇；实施任何任务前，用第二章定位落点、用第三章走流程、用第四章确认不踩差距冻结区。 |

---

## 第一章：产品契约（五条需求的规范化陈述） [sid:90-ch1]

> 需求 ID 的唯一登记处在 `20-REQUIREMENTS.md`（宪法 C6：未登记 = 不存在）。本章只做"用户语言 → 需求编号"的映射，不开新需求。

| # | 需求（规范化陈述） | 映射需求 ID | 边界裁决 |
|---|------|------------|---------|
| ① | **双入口分级侦察**：以用户输入的目标 URL 或 Burp 拦截 `.txt` 为起点做浅层侦察（解析 / 指纹 / 能力探测），再按识别出的组件做专项深探（MCP / RAG / Embedding / GraphQL / 关联端点） | REQ-001 / REQ-002 / REQ-149 / REQ-150 / REQ-160 / REQ-161 | 阶段间数据只经 PipelineContext + EventLog（蓝图 I12） |
| ② | **组件感知武器化**：按侦察结果识别组件归属，组件化选择高 ASR 的 seeds 与 converters，并结合 strike 策略编排 | REQ-003 / REQ-153 / REQ-155 | **Embedding 特殊口径**：REQ-110 裁决（蓝图 Q4）——黑盒 HTTP 不可测试，编排内不实装攻击执行；Embedding 组件仅承担侦察与识别，攻击向量由间接注入种子覆盖 |
| ③ | **PyRIT 原生执行托管**：编排完成后，攻击执行全部交给 PyRIT 原生框架（攻击类 / Target / Converter / Scorer） | REQ-004 / REQ-005 / REQ-151 | 原生优先是宪法 C1；自研仅限 Glue / Enhancement / Output 三类 |
| ④ | **攻击者视角进度呈现**：执行过程中实时呈现攻击进度与成功信息，由 PyRIT 原生 output 与统一事件总线承载 | REQ-148 / REQ-164 | 报告必须含 PyRIT 原生输出（蓝图 I9）；终端展示层与事件流同源 |
| ⑤ | **组件专项报告 + OffSec 合规证据链**：按组件输出专项分析报告（如 MCP 专项报告规范），收集攻击者视角的可复现证据，符合 OffSec 行业标准（风险分级 / OWASP LLM / MITRE ATLAS / 可复现 PoC） | REQ-006 / REQ-007 / REQ-113 / REQ-152 / REQ-164 / REQ-165~171（CP-002 差距闭合组） | ASR 双口径分列（NFR-13 / I11）；判定四态（ADR-008）；授权边界 R-S1~R-S5 之外没有 ASR 可言（宪法 C2 边界条款） |

**使命锚点**：五条需求共同服务宪法第 0 条唯一使命——对 Burp 黑盒目标以 ASR 为首要度量、交付可复现证据链。裁决一切分歧的终极问题见 `00-CONSTITUTION.md` 第 0 条。

---

## 第二章：需求 → 架构落点映射矩阵（代码实证） [sid:90-ch2]

> 本章每个落点均为**代码实证**（或显式标注"蓝图 v4.0 规划，未落地"）。引用形式为 `模块.符号`（文档纪律 D2 禁行号坐标）。动态清单（组件、门禁命令）一律以命令实时读取为准（D4），不在本文抄写。

### 2.0 总览：五条需求在六阶段流水线上的分布

```
输入契约                    六阶段攻击流水线（10-ARCHITECTURE 第一章）          输出契约
──────────                ─────────────────────────────────────              ──────────
URL / burp.txt    ──►  ① RECON ── ② ARM ── ③ STRIKE ── ④ ESCALATE          outputs/strike_*/
（需求① 双入口）        │          │          │            │                   ├── report*.md/.html/.sarif
                        │          │          └── ⑤ ASSESS ─┴── ⑥ REPORT      ├── evidence/ + poc/
                        │          │            （需求⑤ 判定/取证/交付）       ├── native_output/
                        │          └─ 需求② 组件化武器化                       └── db/pyrit.db
                        └─ 需求① 专项深探
需求③ PyRIT 原生执行 = ③④⑤ 的全部执行路径（宪法 C1）
需求④ 进度呈现 = EventLog（core/events.py）+ 终端展示 + PyRIT 原生 output
```

v4.0 六层目标架构（L0 输入与作用域 → L5 交付）与六个一等公民抽象的完整定义见 `10-ARCHITECTURE.md` 第十三章；六阶段流水线是其运行实例。下表标注每条需求主要落在哪些层。

### 2.1 需求① 双入口分级侦察 → ① RECON（六层：L0 / L1）

| 维度 | 落点（代码实证） |
|------|----------------|
| 输入契约 | `data/burp/*.txt` / `config/burp/*.txt`（蓝图 [sid:10-ch5]承诺：`{PROMPT}` 占位符经 PyRIT 原生 `HTTPTarget` 注入，任何模块不得自行拼接 prompt 进 body） |
| CLI 入口 | `--burp` / `--target` 等 argparse 定义以 `python main.py --help` 实时输出为唯一权威（R-DOC-1，代码即 CLI 文档） |
| 浅层探测 | `recon._target_router_helpers._run_background_probes`（含关联端点发现 `recon.api.url_endpoint_discoverer`，BL-032 已闭环） |
| 深度探测 | `recon._target_router_helpers._run_deep_probe_queue`——显式优先级队列 + `deep_probe_budget` 预算确定性调度，低优先级探测显式跳过并记录（BL-036 已闭环） |
| MCP 专项深探 | `recon.mcp`（capability_probe / surface_scanner / version_fingerprint）；MCPSec 桥不可用时走 `recon._target_router_helpers._probe_mcp_locally` 本地回退（BL-029 已闭环），结果写 `target_fingerprint.extra`（蓝图 I12） |
| RAG / Embedding / GraphQL 深探 | `recon.rag.pipeline_probe` / `recon.embedding.vector_probe` / GraphQL 双通道探测（被动信号 + 主动 introspection，BL-033 已闭环） |
| 目标构建 | `recon.target_router`（现状主链路）与 `recon.adapters`（http / sse / jsonrpc / multipart 协议适配，已落地；**主链接线为差距 BL-037，归宿 REQ-151**） |
| 攻击面图谱 | `ctx.surface_graph` 字段已在蓝图 4.4 总表登记（REQ-150）；实现按蓝图 [sid:10-ch13]波次推进（当前无 `recon/surface/` 目录，勿按已落地引用） |
| 需求 / 不变量 / 验证 | REQ-001/002/149/150/160/161；I12；回归 `pytest tests/common/test_recon_deep_wiring.py -q` |

### 2.2 需求② 组件感知武器化 → ② ARM（六层：L2）

| 维度 | 落点（代码实证） |
|------|----------------|
| 组件差异 SSOT | `config/components/*.yaml` + `core.registry`（ADR-007 / REQ-153）。声明清单只准实时读取：`python -c "from core.registry import get_registry; print(get_registry().keys())"`；接线完整性：`get_registry().validate_wiring()` |
| 组件 YAML 契约 | **唯一权威 = `config/components/README.md`**（labels 多标签 IC-1 / detect / recon / seeds / converters / playbooks / scorer / report_section / cleanup 字段定义）。新增组件走 `80-COMPONENT-ARCHITECTURE-RULES.md` 第六章 Checklist（IA-7：只增 YAML + 实现，不改框架层调度） |
| 种子选择 | `arm.seed_ranker`——UCB1 排序 + 类别多样性保底 + 零 ASR 剪枝（蓝图 I6）；运行时反馈账本 `data/seeds/asr_history.json` EMA 闭环（I7：assess 唯一写者、arm 读取） |
| Converter 链 | `arm.converter_selector` / `arm.converter_presets`——每 `ConverterConfiguration` 恰 1 converter（蓝图 I1），多路径 = 独立子路径 + FIRST_SUCCESS |
| 策略路由 | `core.scenario_router`（组件/场景 → technique_tags，ADR-004 轻量化）+ `--target` / `--strike` 分发（`strike.common.dispatcher`，含渐进模式 Phase 1→4 自动升级） |
| Embedding 口径 | REQ-110 裁决（蓝图 Q4）：编排内不实装 embedding 反演攻击；`recon.embedding.vector_probe` 仅服务组件识别与侦察。禁止维持 stub 编排状态（R-H1） |
| **已知差距** | `ctx.techniques` 只喂 Converter、不选 Executor（技术路由断裂，BL-031）——归宿 REQ-151 PlaybookEngine，**禁止新建第二套链机制**（宪法 C3） |
| 需求 / 不变量 | REQ-003/153/155；I1 / I6 / I7；组件归属传递见 80 第五章（CB-1/CB-2、IC-1/IC-3） |

### 2.3 需求③ PyRIT 原生执行托管 → ③ STRIKE + ④ ESCALATE（六层：L2 / L3）

| 维度 | 落点（代码实证） |
|------|----------------|
| 原生优先决策树 | 写新能力前的强制四问（Q1 原生现成？Q2 包装原生？Q3 Glue/Output 范畴？）见 `10-ARCHITECTURE.md` 第三章；原生组件完整速查见 `00-CONSTITUTION.md` 7C |
| 目标类型 → 最优攻击 | `00-CONSTITUTION.md` 7B 映射表 + `10-ARCHITECTURE.md` 9.2 攻击路径决策树（按 capability 指纹分支）与 9.1 原生攻击类落点表 |
| 攻击编排 | PyRIT 原生 `PromptSendingAttack` 多路径 FIRST_SUCCESS（REQ-004）+ 升级链 L1→L4（REQ-005，蓝图 I4 动态阈值；触发参数唯一汇总见蓝图 6.1 SSOT 表） |
| Playbook | 现状：`strike.playbook` 单模块 + `config/playbooks/*.yaml`。蓝图 [sid:10-ch13]的 `strike/playbook/` 目录形态为 v4.0 规划落点，**未落地前勿按目录形态引用** |
| 协议旁路 | MCP JSON-RPC 结构化直发（ADR-003，唯一 HTTPTarget 占位符机制例外） |
| 执行适配 | `recon.adapters`（TargetAdapter，REQ-149）——已落地并通过 MockRange 端到端测试；**主链切换到 adapter 是差距 BL-037**（归宿 REQ-151 step.adapter，IC-2），禁止在 router 内另建适配分支（C3） |
| 需求 / 不变量 | REQ-004/005/151；I2（攻击路径 0-token 评分）/ I4 / I5（三角色分离）/ IC-2 / IC-4（四条多步链迁 playbook 时是迁移不是新建） |

### 2.4 需求④ 攻击进度呈现 → 全阶段横切（六层：L4 观测）

| 维度 | 落点（代码实证） |
|------|----------------|
| 事件总线 | `core.events.EventLog`（REQ-148）——append-only 事件流，落盘 `outputs/<run_id>/events.jsonl`，终端 / 报告 / 证据 / 续跑的唯一派生源；`--no-events` 为 W0 期旁路开关（蓝图 13.6 兼容层，到期删除） |
| 终端展示 | `utils.display.bind_event_log`——display 不持有 ctx，显式注入同一 EventLog，展示与事件流同源（不另立平行输出通道） |
| PyRIT 原生输出 | `report.pyrit_native_output`——报告必须含 PyRIT 原生输出（蓝图 I9）；原生 output 组件速查见宪法 7C.6 |
| 纪律 | 阶段间只经 PipelineContext + EventLog（蓝图 I12，NEG-3 机器化）；阶段产出必须有 EventLog 事件（R-EVENT-2）；编排层禁止硬编码组件名（R-EVENT-1）——红线唯一定义见 `40-GUARDRAILS.md` |
| 需求 / 不变量 | REQ-148/164；I9 / I12 |

### 2.5 需求⑤ 组件专项报告 + OffSec 合规证据链 → ⑤ ASSESS + ⑥ REPORT（六层：L4 / L5）

| 维度 | 落点（代码实证） |
|------|----------------|
| 级联评分 | T0→J1→J2→J3 固定级联（蓝图 I3）；0-token 攻击路径评分（I2）；双 Judge OR 聚合（ADR-001）；ASR 统计与 Wilson CI（REQ-006） |
| 判定四态 | `impact` / `exfil_confirmed` / `exfil_suspected` / `content_only`（ADR-008）；仅前两态计入 `confirmed_asr`，与 `reported_asr` 双口径分列（NFR-13 / 蓝图 I11） |
| 影响链取证 | `assess.impact.exfil` / `assess.impact.verdict`；外传成立必须 OOB 回执——canary + `tools.oob_listener`（蓝图 IC-5）；副作用成立必须二次独立请求确认（IC-6）。`assess/impact/` 其余件（model / canary 独立模块化）按蓝图 [sid:10-ch13]波次落地，勿按已存在引用 |
| 组件专项报告 | `report.component_reports`——组件级 report_section 插件（组件 YAML 契约见 `config/components/README.md`；MCP 等组件的专项报告结构经此承载，不另立报告管线，C3） |
| OffSec 标准结构 | REQ-113 四段结构（executive summary / findings 含风险等级 / impact / remediation）；OWASP LLM 2025 与 MITRE ATLAS 映射：`report.owasp_mapping` / `report.owasp_constants` / `report.standards` |
| 证据链 | `report.evidence` + `report.evidence_manifest`（Why-Success 取证字段组 R-DATA-3：`successful_evidence_log` / `refusal_classification_log` / `guardrail_triggers`）；PoC 独立可执行（NFR-5）：`report.poc_generator` / `report.component_poc` / `report._poc_templates`；SARIF：`report.sarif_report`；多格式：`report.report_markdown` / `report.report_html` |
| 合规红线 | 取证与合规红线（R-ROE-1 / R-EVID-1 / R-AUDIT-1）见 `40-GUARDRAILS.md` 1J-COMPLIANCE；考试合规与证据完整性见其第八章（8A~8D）；报告离线可检（NFR-7） |
| 需求 / 不变量 | REQ-006/007/113/152/164 + CP-002 组（REQ-165~171）；I3 / I9 / I11；R-DATA-3 |

---

## 第三章：AI 编程遵循流程（编码代理执行契约） [sid:90-ch3]

> 本章是流程**导航**，不是流程**定义**。八步协议 / STOP-REPORT / 粒度上限的唯一权威在 `30-TASKS.md`；裁决序与条款在 `00-CONSTITUTION.md`；门禁命令唯一表在 `specs/README.md` §2。

### 3.1 会话冷启动阅读顺序

1. 本文件（第二章定位落点、第四章确认冻结区）
2. `00-CONSTITUTION.md`——第 0 条使命 + 第二章裁决序（Step 1 宪法自检）
3. `30-TASKS.md`——第四章八步协议（Step 2~8 的执行骨架）
4. `10-ARCHITECTURE.md` 相关章节（Step 2 蓝图落点声明）
5. `20-REQUIREMENTS.md` 对应 REQ 的验收标准（Step 3 规格核对；未登记 = 不存在）

### 3.2 每次编码任务的强制闭环（30-TASKS 八步协议引用）

| 步 | 动作 | 唯一权威 |
|----|------|---------|
| 1 | 宪法自检 | 00-CONSTITUTION |
| 2 | 蓝图落点声明 | 10-ARCHITECTURE（本文第二章是导航入口） |
| 3 | 规格核对（task-spec + REQ 验收标准可勾选） | 20-REQUIREMENTS / 30-TASKS |
| 4 | 代码精读（先读后写，C5） | 00-CONSTITUTION C5 |
| 5 | 计划复述 | 30-TASKS |
| 6 | 最小实现（C4 粒度上限内） | 00-CONSTITUTION C4 / 30-TASKS 第三章 |
| 7 | 门禁全过（命令唯一表，顺序固定） | specs/README §2（统一入口 `python -m tools.gate`） |
| 8 | 如实汇报（三态：已验证 / 未验证 / 未完成） | 00-CONSTITUTION C9 / 30-TASKS |

### 3.3 L5 质量锚点（全部为引用，本文不复述数值）

| 质量维度 | 唯一权威 |
|---------|---------|
| PyRIT 原生优先 | 宪法 C1（判定标准 + 违例示例）+ 7C 组件速查 |
| ASR 至上与边界 | 宪法 C2 + 蓝图 I1~I4 / I8 |
| 配置数据流不可断 | 宪法 C7 + 蓝图 4.4 ctx 字段总表（唯一登记簿） |
| 学术留痕 | 宪法 C8（arXiv 三处之一） |
| 组件化规则 | 80 第七章 IA-1~IA-8 + 第六章新增组件 Checklist + 第二章双命名空间 |
| 任务粒度上限 | 30-TASKS 第三章（文件数 / diff 行数 / 跨模块数硬上限） |
| 非功能标准 | 20-REQUIREMENTS 第四章 NFR-1~13 |
| 红线与门禁 | 40-GUARDRAILS 第一章（1A 机器可查 / 1B 人工评审 / 1C 安全合规）+ specs/README §2 |
| 决策系统约束 | 40-GUARDRAILS 1G-DECIDE（R-DECIDE-1~6）+ 蓝图 11.5（ID-1~ID-5） |

### 3.4 偏航熔断（STOP-REPORT）

六类触发信号（规格含糊 / 未登记变更 / 超受影响清单 / 超粒度上限 / 红线风险 / ASR 裁决无依据）的完整定义见 `00-CONSTITUTION.md` C11 与 `30-TASKS.md` 第五章（含格式模板）。**原则：猜着做 = 违宪；停下来问 = 合宪。**

---

## 第四章：已知差距与归宿（指针登记，禁止顺手实施） [sid:90-ch4]

> 宪法 C4：差距消除只能由专项任务（REQ/DEBT/BL 转化）承担，日常任务禁止触碰。本表是**指针**，现象与处置要求的完整描述以 `docs/backlog.md` 与 `10-ARCHITECTURE.md` 第八章债务簿为准（D1：不在本文复述细节）。

| 差距 | 一句话现象（可验证） | 归宿 |
|------|---------------------|------|
| BL-031 | `ctx.techniques` 只喂 Converter、不选 Executor（技术路由断裂） | REQ-151 PlaybookEngine（禁止第二套链机制） |
| BL-037 | TargetAdapter（`recon.adapters`）已落地但主链路仍走旧路径 | REQ-151 step.adapter（IC-2） |
| BL-038 | `defaults.yaml` 存在仅被拷入 args、从未被消费的死配置键（含 L5 验收锚点） | 逐键 a/b/c 判定专项任务（R-H1/C7/NEG-6） |
| BL-035 | 跨模型审查（C14 / R-CROSS-1~4）未执行 | 60-CROSS-MODEL-VERIFICATION 协议（降级条款：人工审查模式） |
| BL-024 | 组件 `id` ≠ YAML 文件名 stem（session / web_api） | IA-8 数据层专项任务 |
| BL-025 | `config/components/*.yaml` 新旧双 schema 并存 | 蓝图 13.3 兼容层"只减不增"专项清理 |
| BL-027 | `docs/guides/ai-dev-guides.md` 与 specs 职责重叠（违反 C3） | 待裁决（降级为方法论 / 删除重复模板） |
| BL-039 | R-DOC-4 检查器白名单未含本文件（90 版本同步暂无自动校验） | guard_extended 专项任务（1C-DOC） |
| D-04 | recon → assess 跨层依赖（target_router 调 assess.scorer 验证函数） | 蓝图 [sid:10-ch8]债务簿（验证函数移入 core 或 targets） |
| D-16 | `pyrit>=1.0.1` 未钉住 + `asr_history.json` 运行时产物入库 | 蓝图 [sid:10-ch8]债务簿 |
| v4.0 未落地件 | `recon/surface/`、`strike/playbook/` 目录形态、`assess/impact/` 独立模块化等 | 蓝图 [sid:10-ch13]执行计划波次（引用其 plans/ 执行计划，不在本文复制波次表） |

**Embedding 特别注记**：需求②中"embedding 的 strike 策略"按 REQ-110 裁决口径收敛——黑盒 HTTP 目标不可测试 embedding 反演，编排内不实装；该攻击向量经间接注入种子覆盖，Embedding 组件的 recon / detect / seeds 字段仅服务组件识别。任何"补齐 embedding 攻击编排"的提议均须先走 change-proposal 推翻 Q4 裁决（C12）。

---

## 第五章：本文件纪律自检（文档纪律 D1~D8 落地） [sid:90-ch5]

本文件自身受 `specs/README.md` §5 文档纪律约束。每次修订本文件后，逐项核验：

| # | 纪律 | 自检方式 |
|---|------|---------|
| D1 | 一概念一处声明：本文只引用不复制规则 | 抽查本文任意规则陈述，确认附有金字塔引用且无数值/命令复述 |
| D2 | 禁行号坐标 | `rg "\.py:\d+" docs/specs/90-AI-DEV-ARCHITECTURE.md` 零命中 |
| D3 | 版本史外置 | 正文仅文件头一个版本行，无变更记录表 |
| D4 | 清单不进正文 | 不手工抄写组件清单 / 门禁命令 / 检查器数量；一律给出实时读取命令 |
| D5 | 路径必须存在 | 第二章所有 `模块.符号` 与文件路径经代码实证（初版核验记录见 git 提交）；蓝图规划未落地项显式标注 |
| D6 | 已完结内容归档 | 差距表只留指针，完结项从表中移除 |
| D7 | 无占位符 | `rg "TASK-___|\[CMD\]|待填|TODO" docs/specs/90-AI-DEV-ARCHITECTURE.md` 零命中 |
