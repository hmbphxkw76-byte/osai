# 变更提案：CP-001（目标架构 v4.0：事件总线 / 适配层 / 攻击面图谱 / 攻击链引擎 / 影响链判定 / 组件注册表）

> **类型**：蓝图变更 + 需求登记（20-REQUIREMENTS 第五章）
> **提案人 / 日期**：AI 起草 / 2026-09-11（提案人栏待人工签署）
> **状态**：draft → 评审中 → approved / rejected / deferred（转 backlog BL-___）
> **关联计划**：`docs/specs/plans/447be21ad0594078a923a53f701087d3-EXECUTION-PLAN.md`（v1.1）
> **版本**：v1.1（2026-09-11 复审补强：新增 §3.5 三条主线复审 + IC-1~IC-6 + §4 口径收紧预告；§2 增补 4 行条款 diff）
> **提案编号说明**：CP-001 为本目录首批提案编号，若与既有提案编号冲突，以人工裁定为准并回填本栏。

---

## 1. 动机

### 1.1 现状

`pyrit-mini` v3.0.0 已实现六阶段链路（recon→arm→strike→escalate→assess→report），并已具备组件化雏形：`recon/{mcp,a2a,rag,model}`、`strike/common/dispatcher.py`、`assess/component_router.py` + `data/scorers/component_scorers/*.yaml`、`report/component_reports.py`、`data/seeds/{mcp,a2a,rag,model}`。P0 主链路可用（REQ-001~008 implemented）。

### 1.2 为什么不够

面向企业主流 AI 应用场景时，现有架构存在三处**架构级误配**，均无法通过局部补丁解决：

| # | 现状形状 | 企业真实形状 | 不改的后果 |
|---|---------|-------------|-----------|
| A | 输入 = URL / burp.txt，隐含"无状态单请求"假设 | 认证态（Bearer/Cookie/OAuth/mTLS）+ 多步会话（chat_id/thread_id）+ 流式/多协议（SSE/WS/JSON-RPC/multipart）+ 多租户 | 每接一个目标补一次认证/会话代码，协议分支散落 recon/arm/strike 三处，后期全面重写 |
| B | 侦察输出 = 单标签分类（`MCP/A2A/RAG/Agent/Model`） | 攻击面图谱：多标签 + 置信度 + 信任边界 + 数据流边 | 组合链攻击（间接注入→工具调用→数据外传）无法表达；每加一种组合都要改分类体系 |
| C | 成功判据 = ASR（模型是否产出有害内容） | 影响链：能力 → 动作 → 影响（含外传回执/副作用实证） | 报告只能写"模型输出了不当内容"，写不出"危害成立"，交付物被判定无效 |

### 1.3 与现行条款的冲突或留白

- **留白**：`10-ARCHITECTURE.md` 第四章 ctx 字段总表无任何"事件/图谱/攻击链/影响判定"字段 → 新增能力无处落点（违反"落不了点的变更需先走 change-proposal 修改蓝图"）。
- **留白**：`10-ARCHITECTURE.md` 2.1 分层表无"协议适配层"与"攻击链编排层" → 协议与多步链只能寄生在 `strike/` 内部（与 1.1 阶段词汇映射中"escalate 非独立模块"同理，会形成新的双轨）。
- **留白**：`20-REQUIREMENTS.md` 无"输入作用域/RoE"、"副作用治理"、"断点续跑"、"交付物脱敏"、"组件注册表"类需求 → 属未登记需求，按 C6 不得实现。
- **张力**：`assess/` 现有判定以 ASR 为唯一 KPI（I11/NFR-13 只规范口径，未规范"成立判据"）→ 需新增影响链判定维度，且不得污染 `reported/confirmed` 双口径（NFR-13）。
- **不冲突**：不改变 C1 PyRIT 原生优先、I1（每 ConverterConfiguration 恰 1 converter）、I2/I3（0-token 前置 + 评分级联）、I5（三角色分离）、I10（SQLite WAL）。

---

## 2. 条款/规格 diff（精确到文件与位置）

| 文件 | 位置 | 现文 | 改为 |
|------|------|------|------|
| `10-ARCHITECTURE.md` | 第一章 系统全景图 | 输入 → 六阶段流水线 → 输出（三层） | 改为六层：L0 输入与作用域 / L1 侦察与图谱 / L2 攻击链编排 / L3 执行适配 / L4 判定与取证 / L5 交付；六阶段作为 L0–L5 的运行实例保留 |
| `10-ARCHITECTURE.md` | 2.1 模块分层表 | 编排/核心/阶段/工具/支撑/数据 六层 | 阶段层内新增子层说明：`recon/adapters/`（协议适配）、`strike/playbook/`（攻击链编排）、`assess/impact/`（影响判定）、`targets/mock/`（靶场，非交付包） |
| `10-ARCHITECTURE.md` | 2.2 依赖方向矩阵 | 无 adapters/playbook/impact 行 | 新增：三者只依赖 `core/`（context+events），与阶段层其他模块仅经 PipelineContext + EventLog 交接 |
| `10-ARCHITECTURE.md` | 4.4 ctx 字段总表 | 无事件/图谱/链/判定字段 | 新增 4 行：`event_log`(EventLog/recon..report 各阶段追加/全部)、`surface_graph`(SurfaceGraph/recon/arm·strike·report)、`playbook_state`(PlaybookState/strike/report)、`impact_verdicts`(list/assess/report) |
| `10-ARCHITECTURE.md` | 第六章 不变量 | I1–I11 | 新增 **I12**：阶段间数据只经 PipelineContext 与 EventLog，禁止旁路（NEG-3 的机器化表述）；**I13**：产生副作用的攻击步必须声明 cleanup，否则 dry-run 之外禁止执行 |
| `10-ARCHITECTURE.md` | 第七章 ADR | ADR-001~006 | 新增 **ADR-007**：组件差异全部声明式（`config/components/*.yaml` + 注册表），编排层禁止硬编码组件名；**ADR-008**：判定分三类（impact / exfil / content_only），`content_only` 不计入 confirmed |
| `20-REQUIREMENTS.md` | 第二章起 | REQ-001~147 | 新增 **REQ-148~158**（见下表 §3.1 清单，验收标准随文登记） |
| `40-GUARDRAILS.md` | 相关登记簿 | 无对应规则 | 新增 **R-EVENT-1**（编排层禁止硬编码组件名字面量）、**R-EVENT-2**（阶段产出必须有对应 EventLog 事件，禁止静默）、**R-COMP-1**（组件插件必须经 ComponentRegistry 注册，禁止直接 import 具体实现） |
| `pyproject.toml` | `[tool.setuptools.packages.find] include` | `["core*","recon*","arm*","strike*","assess*","report*","utils*","tools*"]` | 不变（`recon*` 已覆盖 `recon/adapters/`；`targets/mock/` 为本地靶场不打包，**不新增依赖**，符合 NEG-4） |
| `10-ARCHITECTURE.md` | 第十三章（复审补强） | 13.1–13.6 | 新增 **13.7 三条主线贯穿性约束**：IC-1~IC-6（多标签归属 / step 支持 node_ref+adapter / finding 多归属 / 迁移非新建 / OOB 回执 / 二次独立确认）+ ASR 口径收紧预告 |
| `10-ARCHITECTURE.md` | 第七章 ADR-008 | 判定三类分列（impact / exfil / content_only） | 修订为**四态分列**：`impact` / `exfil_confirmed` / `exfil_suspected` / `content_only`；仅 `impact` 与 `exfil_confirmed` 计入 `confirmed_asr` |
| `20-REQUIREMENTS.md` | 第四章 NFR-13 | ①②③ | 增补 **④ 影响链口径收紧预告**（四态判定 + 下降属口径收紧非能力退化 + 禁止与历史数值直接对比） |
| `20-REQUIREMENTS.md` | 第九章 C1 REQ-150/151/152 | 初版验收 | 验收加严：REQ-150 增 ⑥⑦（IC-1/IC-3）、REQ-151 增 ⑤⑥（IC-2/IC-4）、REQ-152 增 ③④⑤（IC-5/IC-6） |

---

## 3. 影响面

### 3.1 触及的需求 / 债务 / 不变量 / 红线

- **新增 REQ**（待登记入 `20-REQUIREMENTS.md`）：

| ID | 陈述 | 优先级 |
|----|------|-------|
| REQ-148 | EventLog 事件总线：全阶段 append-only 事件流，为终端/报告/证据/回放/续跑的唯一派生源 | P1 |
| REQ-149 | TargetAdapter：协议（http/sse/ws/jsonrpc/multipart/browser）、认证态、会话态统一归一 | P1 |
| REQ-150 | SurfaceGraph 攻击面图谱：多标签 + 置信度 + 信任边界 + 数据流边，含未知目标兜底 | P1 |
| REQ-151 | PlaybookEngine 攻击链 DAG：每步含 precondition/action/verifier/cleanup | P1 |
| REQ-152 | ImpactChain + ExfilChannel 影响链判定（一期 3 类外传信道 + 1 类副作用验证） | P1 |
| REQ-153 | ComponentRegistry + 声明式攻击矩阵 YAML（组件差异禁入编排层） | P1 |
| REQ-154 | 副作用治理：dry-run / 隔离目标标记 / cleanup 钩子 | P1 |
| REQ-155 | 断点续跑（`--resume <run_id>`，从 EventLog 恢复） | P2 |
| REQ-156 | Mock 靶场与 CI 断言（标准库实现，零新增运行时依赖） | P1 |
| REQ-157 | 新增三个组件攻击面：多模态/文件上传间接注入、记忆·会话·多租户隔离、Web 基础设施面 | P1 |
| REQ-158 | 交付物脱敏与密钥剥离 + 版本化可复现快照 | P1 |

- **触及不变量**：新增 I12 / I13（见 §2）；**不破坏** I1–I11。
- **触及红线**：副作用治理涉及 **R-S1**（授权边界）—— 靶场仅绑定 `127.0.0.1`，作用域白名单硬校验；涉及 **R-S2**（报告零密钥）—— REQ-158 为其机器化。
- **债务**：本提案**不新增债务**；W5 将删除本轮引入的兼容层（`recon/surface/legacy.py`、双轨开关），删除期限登记 backlog。

### 3.2 guard 检查器（C12 第 3 步）

| 规则 | 检查器落点 | 级别 |
|------|-----------|------|
| R-EVENT-1 编排层禁止硬编码组件名 | `tools/guard_extended.py` 新增检查器 | BLOCKING |
| R-EVENT-2 阶段产出必须有 EventLog 事件 | 同上 | WARNING（W2 后升级 BLOCKING） |
| R-COMP-1 组件插件必须经注册表 | 同上 | BLOCKING |

### 3.3 同批义务

- 更新 `10-ARCHITECTURE.md` 文件头版本号（v2.8 → v3.0）+ 文末版本记录；
- 更新 `20-REQUIREMENTS.md` 文件头版本号（v2.5 → v2.6）+ 文末版本记录；
- 更新 `specs/README.md` 金字塔索引版本列；
- 更新 `50-ROADMAP.md` 依赖链（新增"阶段 2A 目标架构迁移"，依赖阶段 1C）。

### 3.4 迁移 / 兼容义务

- `recon/surface/legacy.py` 导出旧 `target_fingerprint` 兼容视图，保证 W1 期间下游零改动；**W5 删除**。
- Playbook 与现有 `strike/common/executor.py` 双轨并存，开关默认旧路径；**删除日期登记 backlog**，护栏到期告警（防 D-01 重演）。
- EventLog W0 阶段为**旁路埋点**，提供 `--no-events` 开关，保证零行为回归。
- `component_type` → `component_labels` + `label_confidence`（IC-1）：兼容期保留单值派生视图（取最高置信度），保证下游零回归；**W5 删除单值视图**。

### 3.5 复审补强（2026-09-11）

按"**多组件组合体 / 有状态攻击链 / 影响链取证**"三条主线全盘复审后，新增 BLOCKING 约束 **IC-1~IC-6**（唯一定义见蓝图 13.7），并据此加严 REQ-150/151/152 验收标准：

| 主线 | 复审发现（代码证据） | 补强约束 |
|------|-------------------|---------|
| ① 多组件组合体 | `component_type` 为单值 str，贯穿 strike→assess→report（`core/phases/_component_bridge.py:85`）；`AttackDispatcher(target: str)` 单值路由；`report/evidence.py` `attack_surface` 扁平单值 | **IC-1** 多标签 + 置信度；**IC-2** Playbook step 支持 `node_ref` + `adapter`；**IC-3** finding 可多归属 |
| ② 有状态攻击链 | 四条多步链已硬编码：`strike/common/_executor_doc_poison.py`、`_executor_vuln_inject.py`、`strike/rag/data_poisoning.py`、`strike/mcp/malicious_server.py` | **IC-4** W2 为"迁移"**非"新建"**，迁为 YAML 后删原分支（期限入 backlog），禁止第二套链机制（C3） |
| ③ 影响链取证 | 全仓库 **0 处** OOB/canary；exfil 判据为响应文本正则（`assess/component_scorers.py:53-54`），可被复述/幻觉击穿 | **IC-5** 外传须 OOB 回执（`tools/oob_listener.py`，标准库，NEG-4），T0 正则降级 `exfil_suspected`；**IC-6** 副作用须二次独立请求确认，自证不计成立 |

> **IC-2 时效性**：step 的 `node_ref`/`adapter` 字段现在加只是加字段；W2 引擎落地后再加需改引擎结构。故列为 W2-7 且不得延后。

---

## 4. ASR 影响评估

**中长期：显著变高（预期）；短期：中性。**

- 变高依据：① 认证/会话/协议归一使目前"打不进去"的企业目标进入可攻击面（I8 端点价值排序受益）；② 多步攻击链覆盖 RAG 投毒、MCP 工具滥用等现有单轮 prompt 打不到的场景；③ 影响链判定使真正成功的攻击不被"无法证明"埋没。
- 中性/略降风险：① 副作用门禁（dry-run/cleanup）会拒绝部分不可逆操作，**属安全红线优先于 ASR**（宪法 C2 边界条款，R-S1）；② `content_only` 单列会使 `confirmed_asr` 短期内数值下降 —— **这是口径修正而非能力下降**，须在报告中注明（NFR-13）。
- 授权边界：涉及 **R-S1**（只打授权目标）、**R-S2**（报告零密钥）、**R-S***（副作用不可逆操作须人工确认）。安全红线与 ASR 冲突时安全红线优先。
- **口径收紧预告（复审新增，重要）**：IC-5/IC-6 生效后 `confirmed_asr` 会下降——被降级者是"响应文本命中但无真实外传/副作用"的样本（现有 `assess/component_scorers.py` 的 T0 正则可被复述或幻觉击穿）。**这是口径收紧，不是能力退化**。已同步写入 NFR-13 ④ 与 ADR-008（四态分列），报告须注明口径并禁止与历史数值直接对比。若未提前登记，W3 极易被误判为"优化失败"并触发错误回滚——故本条为提案批准的前置知悉项。

---

## 5. 评审结论（人工填写，AI 不得代填）

> **代录入声明（审计要求）**：本节按 C12 须由人工签署。经用户于 2026-09-11 会话中口头授权"签署 CP-001（批准）"，由 AI 代为录入批准记录。**本签署待项目所有者在 git 提交前追认签名**；未追认前，REQ-148~158 的编码许可以用户本次会话授权为准。

- [x] 批准（附条件：① 蓝图 13.7 的 IC-1~IC-6 为 BLOCKING，其中 **W1-9**（`component_labels`）与 **W2-7**（step `node_ref`+`adapter`）不得延后；② **W2 四条硬编码链迁移期限须在启动 W2 时登记 backlog**，逾期视为新增债务；③ **IC-5/IC-6 生效后 `confirmed_asr` 下降属口径收紧**，已按 NFR-13 ④ 与 ADR-008 预告，不得据此判定优化失败或触发回滚；④ Mock 靶场禁止新增运行时依赖（NEG-4，标准库 `http.server` 实现））
- [ ] 驳回（理由：___）
- [ ] 转 backlog（BL-___）

评审人 / 日期：\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_（待人工追认）
授权来源：2026-09-11 用户会话口头批准，AI 代录入
