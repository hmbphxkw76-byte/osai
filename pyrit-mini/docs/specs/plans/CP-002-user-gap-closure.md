# 变更提案：CP-002（用户诉求差距闭合：输入扩展 / 侦察扩展 / 分类本体 / RoE / L1–L4 / 证据不可否认性 / 报告标准 / 多租户 / 部署 / 审计防篡改 / 弹性 / HITL）

> **类型**：蓝图变更 + 需求登记（20-REQUIREMENTS 第六章）+ 护栏登记（40-GUARDRAILS）
> **提案人 / 日期**：AI 起草 / 2026-09-12（提案人栏待人工签署）
> **状态**：draft → 评审中 → approved / rejected / deferred（转 backlog BL-___）
> **关联计划**：`pyrit-mini-L5-expert-gap-closure`（用户 2026-09-12 会话批准，执行序号 e5f91de2fb584626a9e49c398f889b06）
> **关联既有提案**：`plans/CP-001-target-architecture-v4.0.md`（REQ-148~158 已登记，本提案**不重复**其范围）
> **版本**：v1.0（2026-09-12 初版）

---

## 1. 动机

### 1.1 现状

`pyrit-mini` 已实现六阶段链路（recon→arm→strike→escalate→assess→report）与组件化雏形，并对**用户提出的约 40 项架构/模块/横切问题**做了逐条代码核对（结论见本提案 §3.1 的"现状—差距"映射）。核对结论：部分能力已具备（授权白名单、EventLog、组件注册表、UCB1 种子排序、T0→J1→J2 级联评分、OWASP LLM/MITRE ATLAS/CVSS 映射）；但存在**成片的未登记留白**与**已登记未落地**两类缺口。

### 1.2 为什么不够

用户诉求中有 12 类能力**在 `20-REQUIREMENTS.md` 中完全未登记**。按宪法 **C6（未登记 = 不存在）**，这些能力一律不得编码。若沿用"边想边补"，将重演 C4/C6 违例（diff 无法关联 REQ）。故必须先登记、再编码。

同时，`10-ARCHITECTURE.md` 4.4 ctx 字段总表**无** L1–L4 判定与 HITL 字段，属蓝图留白（落不了点 = 禁止实现）。

### 1.3 与现行条款的冲突或留白

| 类型 | 内容 |
|------|------|
| **留白（需求）** | 多形态输入解析 / GraphQL·WAF·限流探测 / 分类本体 / RoE 文件 / L1–L4 分层 / 证据不可否认性补强 / 报告标准扩展 / 多租户 / 部署形态 / 审计防篡改 / 弹性 / HITL —— 12 项均无 REQ |
| **留白（蓝图）** | 4.4 无 `attack_success_levels` / `hitl_state` 字段；第十章目标架构 v4.0 未涵盖"判定分层"与"部署形态" |
| **张力（口径）** | L1–L4 分层需与 NFR-13 双口径、ADR-008 四态判定**叠加而不冲突**：层级用于"证据强度"，四态用于"外传/副作用成立性" |
| **不冲突** | 不改变 C1 PyRIT 原生优先、I1（每 ConverterConfiguration 恰 1 converter）、I2/I3（0-token 前置 + 评分级联）、I5（三角色分离）、I10（SQLite WAL）、I12/I13 |
| **与 CP-001 去重** | TargetAdapter（REQ-149）、SurfaceGraph（REQ-150）、ImpactChain/Exfil（REQ-152）、组件注册表（REQ-153）、Mock 靶场（REQ-156）、交付物脱敏与版本快照（REQ-158）**已登记**，本提案只做**引用/加严**，不重复登记（C3） |

---

## 2. 条款/规格 diff（精确到文件与位置）

| 文件 | 位置 | 现文 | 改为 |
|------|------|------|------|
| `20-REQUIREMENTS.md` | 文件头 | `**版本**：v2.9` | `**版本**：v3.0`（新增 第九章 D） |
| `20-REQUIREMENTS.md` | 第九章 C 之后 / 第十章之前 | 无 | 新增 **第九章 D：用户诉求差距闭合需求**，登记 **REQ-160~171** + **NFR-17~19** |
| `20-REQUIREMENTS.md` | 第十章 需求追踪表 | 无对应组 | 新增一行：`REQ-160~171（用户诉求闭合） \| 🟡 规约已登记 \| 待 Wave G 后按波次实施` |
| `10-ARCHITECTURE.md` | 文件头 | `**版本**：v3.1` | `**版本**：v3.2` |
| `10-ARCHITECTURE.md` | 4.4 ctx 字段总表 | 无 L1–L4 / HITL 字段 | 新增 2 行：`attack_success_levels`(dict/assess/report)、`hitl_state`(dict/strike/report) |
| `40-GUARDRAILS.md` | 文件头 | `**版本**：v3.2` | `**版本**：v3.3` |
| `40-GUARDRAILS.md` | 第一章 | 无 RoE/证据/审计红线 | 新增 **1J-COMPLIANCE**：`R-ROE-1`、`R-EVID-1`、`R-AUDIT-1`（含检查器落点与待实施标注） |
| `specs/README.md` | §1 文档地图版本列 | `10 v3.1 / 20 v2.9 / 40 v3.2` | 同步为 `10 v3.2 / 20 v3.0 / 40 v3.3` |

---

## 3. 影响面

### 3.1 新增 REQ（逐条含代码现状—差距，来源于 2026-09-12 实测）

| ID | 陈述 | 现状（代码证据） | 差距 | 优先级 |
|----|------|-----------------|------|--------|
| REQ-160 | 多形态输入解析：HAR / 单文件多请求序列 / Site Map(XML·JSON) / Postman / 裸 URL 爬取与关联端点发现 | 仅 `recon.burp_parser.parse_burp_request`（单请求+响应）；无 HAR、无多请求、无 SiteMap/Postman、无裸 URL 爬取 | 全部缺失 | P1 |
| REQ-161 | 侦察扩展：GraphQL introspection + WAF 指纹 + 主链路速率限制探测 | 全仓 0 处 GraphQL；0 处 WAF；限流探测仅在未接线的 `recon.mcp.surface_scanner._detect_rate_limiting` | 全部缺失 | P1 |
| REQ-162 | 目标类型分类本体（Taxonomy）：架构模式 / 通信协议 / 输入模态 / 认证方式 四维、多标签 + 置信度 | 有组件分类（`core.registry` / `core.component_classifier`）但为单值 `component_type` | 无四维本体；单值须迁多标签（IC-1） | P1 |
| REQ-163 | RoE 授权文件与强制边界：启动期加载授权文件（目标清单 + 时间窗 + 授权编号），`--require-roe` 时缺失即拒绝启动 | 有 `core.context.enforce_authorized_scope`（CLI/YAML 白名单，空名单仅 WARNING） | 无授权文件、无时间窗、无强制开关 | P0 |
| REQ-164 | 成功判定分层 L1–L4 + 语义 Scorer：L1 防护绕过 / L2 有害输出 / L3 目标达成 / L4 影响确认；新增 `ToolExecutionScorer`、`RetrievalPoisoningScorer`（PyRIT `TrueFalseScorer` 子类） | 成功为二值（`assess.asr_stats._get_outcome`）；无 L1–L4；无上述 Scorer | 全部缺失 | P0 |
| REQ-165 | 证据不可否认性补强：证据文件 **SHA-256 打包哈希清单** + **Kill Chain 时间线**（取自 EventLog `ts`）+ **PyRIT Memory 导出**（SQLite/JSON 归档） | `report.evidence._next_evidence_id` 用 SHA-1；无打包哈希；`timeline` 仅在 `strike.memory.forensics_extractor` 未接入证据；无 Memory 导出 | 全部缺失 | P0 |
| REQ-166 | 报告标准扩展：OWASP AI Testing Guide 分层 + PTES 阶段结构 + AI-SSCV 评分（与 REQ-113 的 OWASP LLM 2025 + MITRE ATLAS 互补） | 0 处 AITG；PTES 仅注释；0 处 AI-SSCV | 全部缺失 | P1 |
| REQ-167 | 多租户与并行会话隔离：运行级租户/操作员隔离，禁跨 run 污染（memory labels + run 隔离 + 会话注册） | 仅 `--memory-labels` 级作用域；单进程单 run；并发 clamp [1,3] | 无操作员/并行隔离 | P2 |
| REQ-168 | 部署形态扩展：REST API / SDK / 容器化（先登记需求，实施须另立任务） | CLI-only；无 REST/SDK/Dockerfile | 全部缺失 | P2 |
| REQ-169 | 审计防篡改与操作员身份：EventLog 哈希链（防篡改）+ `operator` 身份（who/when/what/why 完整） | `core.events.EventLog` 为 plain JSONL append+flush，无哈希链、无 operator | 全部缺失 | P1 |
| REQ-170 | 熔断与瞬态故障弹性：5xx/限流熔断（暂停·降速·终止可配）+ 客户端 5xx 重试；接线 `ctx._circuit_breaker_states` | `ctx._circuit_breaker_states` 字段无消费者（stub）；无 5xx 重试 | 全部缺失 | P1 |
| REQ-171 | 运行期人工干预（HITL）：暂停/恢复、手动注入 seed、策略覆盖钩子，全部写入 EventLog | 仅协作取消 `core.cancellation` + 事后 checkpoint `core.state_machine`；无暂停/注入/审批 | 全部缺失 | P2 |

### 3.2 新增 NFR

| ID | 维度 | 标准 |
|----|------|------|
| NFR-17 | 审计可验证性 | EventLog 每条事件含前序哈希（哈希链），提供离线校验入口；篡改可被检出 |
| NFR-18 | 证据包可离线校验 | 报告产出含 `evidence_manifest.sha256`，逐文件哈希可离线复算（不依赖网络） |
| NFR-19 | 交付可复现 | 容器化构建可复现（依赖锁定 + 固定基础镜像），构建产物与本地一致 |

### 3.3 触及不变量 / 红线

- **不变量**：不破坏 I1–I13；REQ-164 的 L1–L4 与 ADR-008 四态**正交叠加**（层级=证据强度，四态=成立性）；REQ-169 哈希链仍满足 I12（EventLog 为唯一派生源）。
- **红线**：新增 `R-ROE-1`（强制 RoE 时缺失即拒绝启动，涉及 R-S1 授权边界）、`R-EVID-1`（成功证据须含 SHA-256 与时间线引用）、`R-AUDIT-1`（EventLog 须为哈希链）。
- **负需求**：REQ-168 涉及新增运行时依赖（Web 框架）时**必须另行走 NEG-4 提案**，本提案仅登记需求、不授权加依赖。

### 3.4 guard 检查器（C12 第 3 步）

| 规则 | 检查器落点 | 级别 | 状态 |
|------|-----------|------|------|
| R-ROE-1 | `tools/guard_extended.py` 新增 `check_roe_enforcement()` | BLOCKING | 待实施（随 REQ-163） |
| R-EVID-1 | `tools/guard_extended.py` 新增 `check_evidence_hash_present()` | WARNING | 待实施（随 REQ-165） |
| R-AUDIT-1 | `tools/guard_extended.py` 新增 `check_event_log_hash_chain()` | WARNING | 待实施（随 REQ-169） |

> 依 40-GUARDRAILS 1F 纪律：检查器**先改代码、再同步登记簿**；上表为登记占位，未实施前不产生门禁效力。

### 3.5 同批义务

- 更新 `10-ARCHITECTURE.md`（v3.1→v3.2）、`20-REQUIREMENTS.md`（v2.9→v3.0）、`40-GUARDRAILS.md`（v3.2→v3.3）文件头版本号；
- 更新 `specs/README.md` §1 文档地图版本列（R-DOC-4）；
- 跑 REQ/NFR ID 唯一性自检（20 第十章命令）。

### 3.6 迁移 / 兼容义务

- REQ-163 默认行为**不改变**（未提供 `--roe-file` 时沿用现状 WARNING），仅 `--require-roe` 时强制——保证存量测试与考试 Runbook 零回归。
- REQ-165 将 `report.evidence._next_evidence_id` 的 SHA-1 改为 SHA-256 属**ID 生成口径变更**：ID 仍唯一，但历史 ID 不可复现；须在报告注明"证据 ID 生成算法版本"。
- REQ-164 引入 L1–L4 后 `confirmed_asr` **不下降**（L1–L4 为附加维度，不改变 success 二值的分子分母）；与 CP-001 IC-5/IC-6 的口径收紧互不影响。

---

## 4. ASR 影响评估

**中长期：显著变高；短期：中性。**

- 变高依据：① REQ-160/161 扩展可发现的目标面（HAR 时序、GraphQL、WAF 规避）直接扩大攻击入口；② REQ-164 的 L3/L4 语义 Scorer 使"MCP 工具被劫持执行""RAG 返回投毒内容"这类真实成功不再被二值评分埋没；③ REQ-170 弹性降低瞬态 5xx/限流造成的假失败。
- 中性依据：REQ-167/168/169/171 为工程与合规能力，不直接改变单次攻击的 ASR 上限。
- 授权边界：REQ-163 强化 **R-S1**（仅攻击授权目标）；安全红线与 ASR 冲突时安全红线优先（宪法 C2 边界条款）。
- 口径声明：本提案**不触发** `confirmed_asr` 下降；CP-001 的 IC-5/IC-6 口径收紧预告继续有效且互不叠加。

---

## 5. 评审结论（人工填写，AI 不得代填）

> **代录入声明（审计要求）**：本节按 C12 须由人工签署。经用户于 2026-09-12 会话中通过"`Accept plan and start now`"批准本提案所归属的执行计划（`e5f91de2fb584626a9e49c398f889b06`，该计划明确包含"起草 change-proposal 并登记 REQ/NFR/红线"），由 AI 代为录入批准记录。**本签署待项目所有者在 git 提交前追认签名**；未追认前，REQ-160~171 的编码许可以上述用户会话授权为准。

- [x] 批准（附条件：① Wave G 只做规格登记，**不落码**；② REQ-163 默认行为不得改变（`--require-roe` 为 opt-in）；③ REQ-168 若引入新依赖，必须另行走 NEG-4 提案，不得随本提案夹带；④ 每波次收尾必须过六步门禁并保持 `specs/README.md` 版本列同步）
- [ ] 驳回（理由：___）
- [ ] 转 backlog（BL-___）

评审人 / 日期：________________（待人工追认）
授权来源：2026-09-12 用户会话批准执行计划，AI 代录入
