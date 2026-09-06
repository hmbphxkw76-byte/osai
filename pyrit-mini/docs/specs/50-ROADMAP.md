# 50 — 使命执行路线图（Roadmap & Vibe Coding Master Plan）

> **文档层级**：配套资产（宪法第六章附则，v1.2）。**无裁决权威**——与 ③需求/④任务规格冲突时以后者为准；40-GUARDRAILS 对本文件无门禁效力。
> **职能**：任务顺序与依赖、阶段退出条件、vibe coding 会话模型、考试日 Runbook 的**唯一登记处**。
> **版本**：v1.0（2026-09-05 REV-02 创建，用户会话批准）

---

## 第一章：现状基线（2026-09-05 源码审计快照）

审计对象：`github.com/hmbphxkw76-byte/osai` / `pyrit-mini`（commit `0b8e28c`）。方法：GitHub API 全量文件树 + 关键文件抽读。

### 1.1 总体结论

**架构与蓝图吻合**：六阶段链路（recon→arm→strike→escalate→assess→report）在 pipeline/orchestrator.py 文档串中得到源码级证实；九模块划分、campaign 配置（4 个 yaml）、测试集（18 个 test 文件）、三角色 .env 均在位。**规约文档描述的 9 项债务中，D-09 规范文档冗余已于 2026-09-06 消除**（B/C 类旧文档全部删除，specs/ 金字塔确立为项目唯一权威源），其余 8 项（D-01~D-08）+ 新发现 D-10~D-16 共 14 项债务在源码中证实。

### 1.2 规模热点（Top 文件）

| 文件 | 大小 | 判定 |
|------|------|------|
| utils/display.py | 119KB | D-14：全库最大巨石，支撑层失控 |
| main.py | 87KB | D-02：编排层含业务逻辑（蓝图 2.1 直接违例） |
| core/architecture_guard.py | 82KB | 门禁本体，规模可接受 |
| recon/burp_parser.py | 75KB | 功能核心，偏高 |
| assess/judge_manager.py | 74KB | D-01/D-15：双轨之一 |
| recon/target_router.py | 65KB | 功能核心 |
| .assistant_pyrit/.../SKILL.md | 57KB | D-09 加剧：810→1400+ 行 |
| assess/judge_utils.py | 55KB | D-15 |

### 1.3 P0 红灯（先于一切新功能）

1. **Best-of-N stub**（multi_turn_attacks.py 返回空 dict）——REQ-004 P0 验收项不满足；
2. **encoded_injection / cair stub 被升级链编排**——R-H1 静默降级实证（注释自认"调用方 try/except 优雅降级"）；
3. **ruff lint 盲区**（pyproject exclude pipeline/）——门禁 Step 2 覆盖不全。

### 1.4 债务全景

D-01~D-09（制宪登记）+ D-10~D-16（REV-02 新增）共 16 项，消除方向见蓝图第八章。核心模式：**合并版/拆分版、镜像文件、三轨演化**——典型"AI 生成但未收敛"形态，正是五层规约体系要根治的对象。

---

## 第二章：双重使命与 AI-300 考纲映射

### 2.1 双重使命

- **A 产品使命**（宪法第 0 条，不变）：Burp 黑盒目标 ASR 最大化 + 可复现证据链；
- **B 认证使命**（REV-02 登记）：OffSec AI-300 / OSAI 备考武器化。考试形态：24h 实战 + 24h 报告；**允许** PyRIT、Burp Suite、自写脚本、个人笔记与既往报告；**禁止**交互式 AI 聊天助手。→ 本项目 = 考试合法工具链 + 考前知识资产库。

### 2.2 考纲 11 模块 → 项目能力映射

| # | AI-300 模块 | 项目落点 | 现状 | 差距任务 |
|---|------------|---------|------|---------|
| M1 | Red Teaming AI Systems 方法论 | 六阶段链路 + ASR 度量体系 | ✅ 已具备 | — |
| M2 | Recon for AI Targets | recon/（burp_parser / capability / port_expander / openapi / mcp_enumerator / system_prompt_extractor） | ✅ 强项 | — |
| M3 | Attacking AI Agents | agent 种子（T1_Agent / ASI01-10 / ASI03 workflow / ASI09 session） | 🟡 种子完备 | 执行链验证 |
| M4 | Multi-Agent & A2A | ma_* 种子 5 条 + targets/agent_adapter | 🟡 仅种子无执行 | **REQ-109** |
| M5 | RAG Pipelines | rag 种子 + strike/mcp_rag_attack | 🟡 部分 | 强化验证 |
| M6 | Embeddings | strike/embedding_inversion.py（8.4KB） | ⚠️ 待锚定（疑 stub 化） | **REQ-110** |
| M7 | MCP & Tool Surfaces | mcp 种子 11 条 + mcp_enumerator + ADR-003 | ✅ 差异化优势 | — |
| M8 | Supply Chain | T2_LLM03_supply_chain_SBOM 种子 | 🔴 仅种子 | **REQ-111** |
| M9 | AI Infra & Deployment | port_expander + openapi_discoverer | 🟡 部分 | — |
| M10 | Threat Modeling | data/attack_surface_classifier + ATLAS/OWASP 报告映射 | 🟡 部分 | **REQ-113** |
| M11 | Capstone 24h Engagement | 本项目全链路本体 | 🟧 待硬化 | **REQ-112** + 第六章 Runbook |

---

## 第三章：AI 红队最佳实践基线（标准锚定）

1. **框架三角**：OWASP Top 10 for LLM Applications 2025（种子命名 LLM01-10 已对齐）+ MITRE ATLAS（报告映射）+ NIST AI 600-1（风险分级口径）。
2. **证据链纪律**：成功攻击必须可复现（PoC 独立可执行，NFR-5）；ASR=0 也交付零成功证据链与失败分析（P0 总验收 v1.1）——考试中"没打穿但证明了为什么"同样是分数。
3. **报告即交付物**：考试报告与技术发现同权重（OffSec 惯例）→ REQ-113 四段结构（executive summary / findings+风险等级 / impact / remediation）。
4. **RoE 与边界**：R-S1~S5 不因考试妥协；考试下发目标集即授权边界。
5. **学术留痕**：宪法 C8（arXiv 注释）继续——考试开卷，注释即速查知识库。
6. **Token 纪律**：NFR-1 级联评分省 token = 考试 24h 时间盒内多打目标。

---

## 第四章：阶段规划（任务序列）

> 领任务规则：按本表自上而下领取；每个任务走完整八步协议（30-TASKS 第四章）；粒度上限（≤3 文件/≤300 行/≤2 模块）不可豁免，超限先拆分。任务 ID 为占位符，task-spec 中正式编号。

### 阶段 0 — 稳定化（P0，先于一切新功能）

| 序 | 任务 | 引用 | 说明 |
|----|------|------|------|
| T0-1 | Best-of-N 实装 | REQ-004 / D-03 | 消除 P0 缺口：真实现（多 temperature 采样）或从升级链摘除（STOP-REPORT 三选项裁决） |
| T0-2 | stub 裁决（encoded_injection / cair） | D-03 | 各自"实现或摘除"，禁止维持现状 |
| T0-3 | 工具链修复 | D-16 / BL-008~010 | ruff 去 exclude、钉 pyrit、修 mojibake、asr_history 出库 |
| T0-4 | escalation 孪生合并 | D-10 / BL-007 | 先 diff 确认孪生，保留 chain 语义一套 |
| T0-5 | seed 排序双轨合并 | D-12 | seed_ranker/seed_ranking 合一 |
| T0-6 | converter 三轨裁决 | D-11 | 按选择器/预设/构建职责分离或合并 |
| T0-7 | judge 文件群收敛 | D-01/D-15 | 双轨归一，asr_tracker re-export 删除 |
| T0-8 | main.py 瘦身第一刀 | D-02 | 仅切一块业务逻辑下沉（后续波次另立任务） |
| T0-9 | data/ 代码迁出 | D-13 | 4 个 .py 迁至 core/ 或阶段层 |
| T0-10 | display.py 拆分第一刀 | D-06/D-07/D-14 | 读 yaml 替代硬编码 + 拆一个职责块 |

**退出条件**：① REQ-004 运行时可验（Tier 2）；② guard BLOCKING 存量清零或全部降级登记；③ 四步门禁全绿；④ 债务簿只减未增。

### 阶段 1 — 考域补全

| 序 | 任务 | 引用 | 说明 |
|----|------|------|------|
| T1-1 | A2A/多智能体攻击执行 | REQ-109 | cross-agent injection / impersonation / workflow corruption 三类入升级链（多轮技术） |
| T1-2 | Embedding 攻击落地 | REQ-110 | 按蓝图 Q4 决策树裁决实装或外部工具形态 |
| T1-3 | 供应链侦察清单 | REQ-111 | fingerprint 增 supply-chain 检查项 → 报告渲染 |
| T1-4 | M3/M5 执行链验证 | REQ-004/005 | 对 mock 目标跑通 agent/RAG 种子的完整攻击路径 |

**退出条件**：REQ-109~111 验收全勾 + Tier 2 证据归档。

### 阶段 2 — 考试硬化

| 序 | 任务 | 引用 | 说明 |
|----|------|------|------|
| T2-1 | exam_mode campaign | REQ-112 | config/campaigns/exam_mode.yaml：快速链 + token 预算 + 证据实时落盘 |
| T2-2 | OffSec 风格报告 section | REQ-113 | 四段结构并入现有报告管线（不另立，C3） |
| T2-3 | 模拟考 | 本文件第六章 | 对 data/burp/ 测试目标完整走一遍 24h 流程出报告，按 40-G 第五章清单自评 |

**退出条件**：模拟考报告通过自评 + exam_mode 单命令可跑。

### 阶段 3 — 持续运营（无终点）

- ASR 反馈闭环（I7）：定期人工修订 asr_priors（history 提供数据）；
- 种子库扩充（纯数据任务）：新攻击面（A2A 新协议、新 MCP 漏洞模式）随时入库；
- 考后复盘：考试发现的新差距 → change-proposal → 新 REQ。

### 依赖链（简）

`T0-1 → T0-2 → {T0-3…T0-10 可并行领取} → 阶段1 → 阶段2 → 阶段3`

---

## 第五章：Vibe Coding 会话操作模型

### 5.1 会话入口仪式（= 八步协议，此处只列动线）

```
读宪法(00) → 查本路线图领任务 → 读蓝图相关章节声明落点
→ 核对 REQ 验收标准 → 填 task-spec → Step 5 计划复述（用户确认）
→ 最小实现 → 四步门禁 → 三栏汇报 → 关闭并回填 20-REQUIREMENTS 状态表
```

### 5.2 会话类型配额（防漂移节奏）

| 类型 | 规格 | 频率约束 |
|------|------|---------|
| 债务消除型 | task-spec 引用 DEBT-ID | **每周 ≥1 个**（阶段 0 期间唯一允许的类型，除 bug 修复） |
| 需求实现型 | task-spec 引用 REQ-ID | 按路线图序列 |
| 数据增强型 | 纯数据任务（种子/rubric/priors） | 随时；粒度豁免但仍需规格 |
| 审计型 | 只读分析 + backlog 登记 | 疑似漂移时立即触发 |

### 5.3 防漂移三条铁律（vibe coding 三大死亡陷阱 ↔ 规约封条）

1. **开始前无规格** ↔ C6 规格先行 + 本路线图领任务制；
2. **写到一半自由发挥** ↔ STOP-REPORT 熔断（30-TASKS 第五章）；
3. **"顺手"扩范围** ↔ C4 最小 diff + 40-G 评审清单第一项。

### 5.4 会话收尾义务

每次会话（无论完成与否）：三栏汇报 + 状态表回填 + backlog 增量登记。**未完成 ≠ 失败；隐瞒未完成 = 违宪（C9）。**

---

## 第六章：考试日 Runbook（24h 实战 + 24h 报告）

### 6.1 战前检查单（考前一周）

- [ ] exam_mode.yaml 冻结（REQ-112）且单命令可跑；
- [ ] 三角色 .env 就绪（objective/adversarial/scoring），密钥不入任何笔记；
- [ ] Burp 目标导入演练通过（考试下发后第一时间转 `data/burp/*.txt`）；
- [ ] 模拟考（T2-3）完成，报告自评通过；
- [ ] 离线兜底：报告生成不依赖网络（NFR-7）。

### 6.2 作战时间盒

| 时段 | 动作 | 使用 |
|------|------|------|
| H0–H2 | 全量 Burp 导入 → recon 指纹 → attack_surface_graph → 价值排序 | `--stage recon` |
| H2–H4 | 武器化：prior 排序 + 场景路由 technique_tags | `--stage arm` |
| H4–H16 | 打击：单轮 FIRST_SUCCESS → <90% 升级链；**证据边打边落盘** | `--stage strike`（exam_mode） |
| H16–H20 | 评分与联合 ASR | `--stage assess` |
| H20–H24 | 报告生成 + PoC 独立复跑验证 | `--stage report` |
| +24h | 以生成报告为底稿人工精修为 PDF | REQ-113 四段结构 |

### 6.3 战场纪律

- **卡死切换**：任一 endpoint 超 1h 无进展 → 切下一目标（多 endpoint 串行天然支持）；
- **token 告警**：50% 预算时降采样，80% 时只跑高 prior 路径；
- **证据优先**：宁可少打一个目标，不可丢失已成功攻击的证据链（REQ-007 全字段）；
- **边界**：只打考试下发目标（R-S1）；报告零密钥（R-S2）；
- **合规**：全程不使用交互式 AI 聊天助手（考试规则）；本项目 LLM 三角色仅作为攻击引擎运行，属工具而非助手。

---

## 第七章：治理衔接

- 本路线图阶段/序列变更 → change-proposal（20-REQUIREMENTS 第五章流程）；
- 领取的任务与 ③④ 层冲突时 → STOP-REPORT，以 ③④ 为准；
- 每完成一个任务，回填 20-REQUIREMENTS 第七章状态表；每完成一个阶段，在本文件版本记录追加一行。

---

## 第八章：考试就绪评分卡与快速交战 Playbook（v1.2 增补）

> **用途**：考试前一周的最终就绪确认 + 考试期间的快速行动指南。结合项目能力与 OffSec AI-300 考纲 11 模块的全面就绪评估。

### 8A. 考试就绪评分卡（Exam Readiness Scorecard）

> **评估时机**：考试前一周完成评估，满分 100 分，≥80 分判定为"可参加考试"。

| # | 维度 | 权重 | 评估标准 | 得分 |
|---|------|------|---------|------|
| R1 | **P0 主链路完整性** | 25% | REQ-001~008 全部 implemented 且 Tier 2 验证通过 | /25 |
| R2 | **Toolchain 健康度** | 15% | ruff 全绿、pytest 全过、guard BLOCKING 零新增、dry-run 无 ImportError | /15 |
| R3 | **PyRIT 攻击引擎就绪** | 15% | PromptSendingAttack + SkeletonKeyAttack + 三多轮（Crescendo/TAP/PAIR）全部可跑通 | /15 |
| R4 | **考域覆盖度（11 模块）** | 20% | M1-M11 映射中 ≥9 模块有"已具备"或"可执行"评级 | /20 |
| R5 | **考试模式 campaign** | 10% | exam_mode.yaml 配置完成且单命令可跑、时间盒降级逻辑生效 | /10 |
| R6 | **报告生成能力** | 10% | REQ-113 四段结构可即时生成、证据全字段非空验证通过 | /10 |
| R7 | **模拟考通过** | 5% | T2-3 模拟考完成、报告自评通过 | /5 |

**就绪等级**：
- **A 级（≥90 分）**：完全就绪，可策略性选目标深度打击
- **B 级（80-89 分）**：基本就绪，可参加考试，优先高先验目标
- **C 级（70-79 分）**：部分就绪，需考前补强（聚焦 P0 缺陷修复）
- **D 级（<70 分）**：不建议参加考试，需完成阶段 0 稳定化

### 8B. 考域覆盖度详细评估（M1-M11）

| 模块 | 权重 | 现状代码证据 | 就绪标志 |
|------|------|---------|------|
| M1 Red Teaming 方法论 | — | 六阶段链路 + ASR 度量体系 | ✅ 自动就绪 |
| M2 Recon for AI Targets | — | recon/ 全量模块（burp_parser/capacity/mcp/system_prompt） | ✅ 自动就绪 |
| M3 Attacking AI Agents | — | agent 种子 10+ 条 + SkeletonKeyAttack 包装 | 🟡 需 Tier 2 验证 |
| M4 Multi-Agent & A2A | — | ma_* 种子 5 条（REQ-109 执行层待补） | 🟡 需 REQ-109 |
| M5 RAG Pipelines | — | rag 种子 + mcp_rag_attack | 🟡 需执行验证 |
| M6 Embeddings | — | embedding_inversion.py（待锚定） | 🔴 需 REQ-110 |
| M7 MCP & Tool Surfaces | — | mcp 种子 11 条 + ADR-003 旁路 + mcp_enumerator | ✅ 自动就绪 |
| M8 Supply Chain | — | T2_LLM03_supply_chain_SBOM 种子 + REQ-111 清单 | 🟡 需 REQ-111 |
| M9 AI Infra & Deployment | — | port_expander + openapi_discoverer | 🟡 部分就绪 |
| M10 Threat Modeling | — | ATLAS/OWASP 映射 + attack_surface_graph | 🟡 需 REQ-113 |
| M11 Capstone 24h | — | 全链路 + exam_mode campaign | 🟧 需 T2-3 模拟考 |

### 8C. 快速交战 Playbook（Rapid Engagement Playbook）

> **用途**：考试期间根据目标类型的预定义攻击剧本。直接使用预配置 campaign，无需现场设计攻击方案。

**Playbook A：通用 LLM Chat 目标（预计 30min）**

```bash
# Step 1: 快速指纹（5min）
python main.py --burp target.txt --stage recon

# Step 2: 选择高先验种子 + 默认 Converter
python main.py --stage arm --seeds T1_LLM01_elite_jailbreaks --converters default

# Step 3: 多路径打击（15min）
python main.py --stage strike --max-seeds 15

# Step 4: 若 ASR < 90%，触发升级链（10min）
python main.py --stage escalate --auto

# Step 5: 评分 + 证据（5min）
python main.py --stage assess --stage report
```

**Playbook B：AI Agent 目标（预计 45min）**

```bash
# Step 1: 快速指纹 + tool 探测（5min）
python main.py --burp target.txt --stage recon --deep-probe tools

# Step 2: Agent 专用种子（tool_hijack + workflow_escalation）
python main.py --stage arm --seeds T1_ASI02_function_call_exploit,T1_ASI03_workflow_escalation

# Step 3: SkeletonKeyAttack 首发（ASR 80-95%）
python main.py --stage strike --technique skeleton_key_native

# Step 4: CrescendoAttack 渐进升级
python main.py --stage escalate --level L1 --technique crescendo

# Step 5: 评分 + 报告
python main.py --stage assess --stage report
```

**Playbook C：MCP Server 目标（预计 45min）**

```bash
# Step 1: MCP 枚举 + 工具分析（10min）
python main.py --burp target.txt --stage recon --mcp-deep

# Step 2: MCP 专用种子 + 动态种子生成
python main.py --stage arm --seeds mcp_server_injection,mcp_tool_chaining,mcp_tool_hijack --dynamic

# Step 3: JSON-RPC 旁路直发（ADR-003）
python main.py --stage strike --protocol jsonrpc

# Step 4: MCP 升级链 + 信任链攻击
python main.py --stage escalate --level L1-L2

# Step 5: 评分 + 报告
python main.py --stage assess --stage report
```

**Playbook D：RAG Pipeline 目标（预计 30min）**

```bash
# Step 1: RAG 侦察 + 知识库探测（5min）
python main.py --burp target.txt --stage recon --rag-probe

# Step 2: 间接注入种子 + 检索污染
python main.py --stage arm --seeds T1_LLM01_indirect_injection,rag_full_attack_surface

# Step 3: 多 Converter 间接注入路径
python main.py --stage strike --max-seeds 10

# Step 4: 升级链
python main.py --stage escalate --auto

# Step 5: 评分 + 报告
python main.py --stage assess --stage report
```

### 8D. 考试日应急预案（Exam Day Contingencies）

| 情形 | 应急动作 | 预计恢复时间 |
|------|---------|------------|
| 目标完全不可达（ConnectionError） | 立即切换下一目标，记录失败原因 | 0min |
| PyRIT 版本不兼容 | 激活 venv + pyrit==1.0.* 钉住回滚 | 5min |
| Token 预算耗尽（80%） | 切换高先验种子-only 模式 + 禁用升级链 | 2min |
| 证据链字段缺失 | 运行 evidence_validator.py 补全 | 10min |
| 报告生成超时 | 使用 --fast-mode 生成最小可用报告 | 2min |
| 自定义 LLM 评分器超时 | 降级到 0-token 拒绝检测-only 模式 | 1min |

---

## 版本记录

| 版本 | 日期 | 变更摘要 | 批准 |
|------|------|---------|------|
| v1.0 | 2026-09-05 | REV-02 创建：源码审计基线（@0b8e28c）、双重使命与 AI-300 考纲 11 模块映射、红队最佳实践基线、四阶段任务序列（T0-1~T2-3 + 持续运营）、vibe coding 会话操作模型、考试日 Runbook | 用户会话批准 |
| v1.1 | 2026-09-06 | REV-03 AI-300 考试路线图优化：① 新增第八章 考试就绪评分卡与快速交战 Playbook（就绪评分卡 8A、考域覆盖度详细评估 8B、快速交战 Playbook A-D 8C、考试日应急预案 8D）；② 阶段规划本体无变更 | 用户会话批准 |
