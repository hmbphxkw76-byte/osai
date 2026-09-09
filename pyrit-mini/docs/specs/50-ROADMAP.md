# 50 — 使命执行路线图（Roadmap & Vibe Coding Master Plan）

> **文档层级**：配套资产（宪法第六章附则，v1.2）。**无裁决权威**——与 ③需求/④任务规格冲突时以后者为准；40-GUARDRAILS 对本文件无门禁效力。
> **职能**：任务顺序与依赖、阶段退出条件、vibe coding 会话模型、考试日 Runbook 的**唯一登记处**。
> **版本**：v1.9（2026-09-09 规约优化 P0+P1：阶段 0.5 ASR 基准校准；T1C-6/R-DECIDE-1~6；Best-of-N 仲裁；1B REQ 重对齐；SKIP_UPGRADE 口径裁定）

---

## 第一章：现状基线（2026-09-09 文档同步快照）

审计对象：`github.com/hmbphxkw76-byte/osai` / `pyrit-mini`。方法：代码全量审计 + 文档交叉验证。

### 1.1 总体结论

**架构与蓝图吻合**：六阶段链路（recon→arm→strike→escalate→assess→report）在 `core/phases/` + `strike/executor.py` 源码级证实。九模块划分、campaign 配置、测试集、三角色 .env 均在位。

**债务清理状态**：制宪登记的 D-01~D-09 共 9 项债务，已于 2026-09-08 全部消除：
- D-01 judge 双轨 → ✅ 合并到 `assess/judge_manager.py` SSOT
- D-02 main.py 业务逻辑 → ✅ dry_run 下沉到 `utils/dry_run.py`
- D-03 stub 静默降级 → ✅ encoded_injection/cair/multi_turn_attacks 全部摘除
- D-05 escalation 孪生文件 → ✅ 重复文件全部删除
- D-06 display.py 巨石 → ✅ 从 119KB 精简到 606 行
- D-07 display_* 碎片 → ✅ 合并到 `utils/display.py`
- D-08 asset_mapper 孤儿 → ✅ 删除
- D-09 规范文档冗余 → ✅ 确立 specs/ 金字塔唯一权威
- D-10~D-16 新发现债务 → ✅ 全部消除（2026-09-08 红队精简审计）

### 1.2 规模热点（Top 文件，2026-09-09 更新）

| 文件 | 行数 | 判定 |
|------|------|------|
| tools/guard.py | ~257行 | 门禁本体，规模可接受 |
| tools/guard_extended.py | ~1400行 | 扩展检查器（20+ 规则），功能核心 |
| recon/target_router.py | ~400行 | 功能核心 |
| assess/judge_manager.py | ~1688行 | 评分 SSOT，功能核心 |
| strike/executor.py | ~800行 | 攻击执行核心 |
| utils/display.py | ~606行 | 统一展示门面 |

### 1.3 P0 状态

✅ **全部消除**（2026-09-08）：
1. Best-of-N stub → 已摘除（multi_turn_attacks.py 删除）；Best-of-N 已实装于 `strike/adaptive_executor.py` `_best_of_n_retry`
2. encoded_injection / cair stub → 已摘除（cair.py/encoded_injection.py 删除）
3. ruff lint 盲区 → 已修复（pyproject exclude 清理）

---

## 第二章：双重使命与 AI-300 考纲映射

### 2.1 双重使命

- **A 产品使命**（宪法第 0 条，不变）：Burp 黑盒目标 ASR 最大化 + 可复现证据链；
- **B 认证使命**（REV-02 登记）：OffSec AI-300 / OSAI 备考武器化。考试形态：24h 实战 + 24h 报告；**允许** PyRIT、Burp Suite、自写脚本、个人笔记与既往报告；**禁止**交互式 AI 聊天助手。→ 本项目 = 考试合法工具链 + 考前知识资产库。

### 2.2 考纲 11 模块 → 项目能力映射

| # | AI-300 模块 | 项目落点 | 现状 | 差距任务 |
|---|------------|---------|------|---------|
| M1 | Red Teaming AI Systems 方法论 | 六阶段链路 + ASR 度量体系 | ✅ 已具备 | — |
| M2 | Recon for AI Targets | recon/（burp_parser/capability/openapi/system_prompt/health_probe） | ✅ 强项 | — |
| M3 | Attacking AI Agents | agent 种子（T1_Agent / ASI01-10） | 🟡 种子完备 | 执行链验证 |
| M4 | Multi-Agent & A2A | ma_* 种子 5 条 + recon/a2a_* 模块 | 🟡 种子+侦察完备 | **REQ-109** 执行层 |
| M5 | RAG Pipelines | rag 种子 + recon/rag_* 模块 | 🟡 部分 | 强化验证 |
| M6 | Embeddings | ⚠️ 已摘除（embedding_inversion.py 黑盒不可测试） | 🔴 需外部工具 | — |
| M7 | MCP & Tool Surfaces | mcp 种子 11 条 + MCPSec 桥接 | ✅ 差异化优势 | — |
| M8 | Supply Chain | T2_LLM03_supply_chain_SBOM 种子 | 🔴 仅种子 | **REQ-111** |
| M9 | AI Infra & Deployment | openapi_discoverer + health_probe | 🟡 部分 | — |
| M10 | Threat Modeling | ATLAS/OWASP 报告映射 | 🟡 部分 | **REQ-113** |
| M11 | Capstone 24h Engagement | 本项目全链路本体 | 🟧 待硬化 | **REQ-112** + 第六章 Runbook |

---

## 第三章：AI 红队最佳实践基线（标准锚定）

1. **框架三角**：OWASP Top 10 for LLM Applications 2025（种子命名 LLM01-10 已对齐）+ MITRE ATLAS（报告映射）+ NIST AI 600-1（风险分级口径）。
2. **证据链纪律**：成功攻击必须可复现（PoC 独立可执行，NFR-5）；ASR=0 也交付零成功证据链与失败分析。
3. **报告即交付物**：考试报告与技术发现同权重 → REQ-113 四段结构。
4. **RoE 与边界**：R-S1~S5 不因考试妥协；考试下发目标集即授权边界。
5. **学术留痕**：宪法 C8（arXiv 注释）继续——考试开卷，注释即速查知识库。
6. **Token 纪律**：NFR-1 级联评分省 token = 考试 24h 时间盒内多打目标。

---

## 第四章：阶段规划（任务序列）

> 领任务规则：按本表自上而下领取；每个任务走完整八步协议（30-TASKS 第四章）；粒度上限（≤3 文件/≤300 行/≤2 模块）不可豁免，超限先拆分。

### 阶段 0 — 稳定化（P0，先于一切新功能）

| 序 | 任务 | 引用 | 状态 |
|----|------|------|------|
| T0-1 | Best-of-N 实装 | REQ-004 / D-03 | ✅ 完成（仲裁 v1.8：stub 已从 multi_turn_attacks.py 摘除；Best-of-N 实装于 `strike/adaptive_executor.py` `_best_of_n_retry`，参数 `best_of_n_retries: 5` 来自 defaults.yaml） |
| T0-2 | stub 裁决（encoded_injection / cair） | D-03 | ✅ 已摘除 |
| T0-3 | 工具链修复 | D-16 | ✅ 已完成 |
| T0-4 | escalation 孪生合并 | D-10 | ✅ 已完成 |
| T0-5 | seed 排序双轨合并 | D-12 | ✅ 已完成 |
| T0-6 | converter 三轨裁决 | D-11 | ✅ 已完成 |
| T0-7 | judge 文件群收敛 | D-01/D-15 | ✅ 已完成 |
| T0-8 | main.py 瘦身第一刀 | D-02 | ✅ 已完成 |
| T0-9 | data/ 代码迁出 | D-13 | ✅ 已完成 |
| T0-10 | display.py 拆分第一刀 | D-06/D-07/D-14 | ✅ 已完成 |

**阶段 0 完成状态**：✅ **已完成**（2026-09-08 全部 10 项任务完成）

### 阶段 0.5 — ASR 基准校准（v1.8 新增，先于一切优化/决策工作）

> **目的**：落实 I11/NFR-13"以 ASR 为度量、为目标、为校验闭环"——在没有任何优化动作前先产出**可复现的基线**，后续一切 ASR 变化都对照本基线归因。未完成本阶段前，禁止声称任何"ASR 提升"。

| 序 | 任务 | 引用 | 说明 |
|----|------|------|------|
| T0.5-1 | 基线运行 | I11 | 默认配置全量跑一遍 Burp 目标集，产出 `reported_asr` 基线（含 Wilson CI），报告标题注明口径 |
| T0.5-2 | 双口径基线分列 | NFR-13 | 对基线成功样本抽样人工复核，登记 `confirmed_asr`（无复核能力时标注 n/a 并记入 backlog） |
| T0.5-3 | 目标锚点校验 | I11 / `target_asr` | 对照 `config/defaults.yaml` `target_asr`，量化"基线 → 目标"缺口，输出优化优先级排序（缺口最大的技术/端点优先） |
| T0.5-4 | 账本初始化核对 | I7 | 确认 `asr_history.json` 在基线运行后写入结构完整（种子/converter/GCG 后缀三级），EMA 可计算 |

**退出条件**：基线报告归档（含 reported/confirmed 双列 + target_asr 缺口表）+ T0.5-4 核对通过。基线数值写入 50-ROADMAP 第一章现状基线表。

**依赖**：阶段 0 ✅ → **阶段 0.5** → 阶段 1/1B/1C 全部以本基线为对照。

### 阶段 1 — 考域补全

| 序 | 任务 | 引用 | 说明 |
|----|------|------|------|
| T1-1 | A2A/多智能体攻击执行 | REQ-109 | cross-agent injection / impersonation / workflow corruption |
| T1-2 | ~~Embedding 攻击落地~~ | ~~REQ-110~~ | ~~已移除（黑盒HTTP不可测试）~~ |
| T1-3 | 供应链侦察清单 | REQ-111 | fingerprint 增 supply-chain 检查项 → 报告渲染 |
| T1-4 | M3/M5 执行链验证 | REQ-004/005 | 对 mock 目标跑通 agent/RAG 种子的完整攻击路径 |

**退出条件**：REQ-109/111 验收全勾 + Tier 2 证据归档。

### 阶段 1B — 企业基础设施攻击（Web 攻击层实施）

> **目的**：通过 strike/ 下 Web 攻击模块覆盖企业级 AI 系统（认证、API 网关、审计）的攻击面。对应 10-ARCHITECTURE 与 40-GUARDRAILS R-WEB-1~R-WEB-5 护栏。

| 序 | 任务 | 引用 | 状态 |
|----|------|------|------|
| T1B-1 | Web攻击层骨架搭建 | REQ-133 | ✅ 已完成（strike/ 扁平化 + 延迟导入机制） |
| T1B-2 | 认证攻击 | REQ-127 | ✅ 已完成 |
| T1B-3 | ~~向量 DB 攻击~~ | ~~REQ-128~~ | N/A（黑盒不可测试） |
| T1B-4 | API 网关攻击 | REQ-129 | ✅ 已完成 |
| T1B-5 | 审计逃逸 | REQ-130 | ✅ 已完成（精简为日志注入） |
| T1B-6 | ~~微调后门~~ | ~~REQ-131~~ | N/A（黑盒不可测试） |
| T1B-7 | 统一编排器 | REQ-132 | ✅ 已完成 |
| T1B-8 | 护栏检查器锚定 | R-WEB-1~5 | ✅ 已完成 |

> **v1.8 REQ 重对齐**：原表引用与 20-REQUIREMENTS 权威登记错位（REQ-127=认证 / 128=向量DB已移除 / 129=API网关 / 130=审计逃逸 / 131=微调已移除 / 132=编排器 / 133=延迟导入），已全部按 20 权威登记修正。

**阶段 1B 完成状态**：✅ **已完成**（2026-09-08 全部有效任务完成）

### 阶段 1C — 全链路自主决策引擎（架构设计完成，待实施）

> **目的**：基于已实施的 Strike 阶段战术决策系统，扩展为覆盖 Recon→ARM→Strike→Assess→Report 全链路的自主决策引擎。
> **架构依据**：`10-ARCHITECTURE.md` 第十一章 + `55-ATTACK-GAP-CLOSURE.md` 第九章 + `20-REQUIREMENTS.md` 第九章。

| 序 | 任务 | 引用 | 说明 |
|----|------|------|------|
| T1C-1 | 决策引擎框架 | REQ-135 | 统一 `determine_*_strategy` 接口 + 决策触发条件配置 + `ctx.decision_log` |
| T1C-2 | Recon 阶段决策 | REQ-136 | `determine_probe_strategy()` 自适应探测深度 + WAF 自动 stealth |
| T1C-3 | ARM 阶段决策 | REQ-137 | 动态种子排序 + Converter 链优化 |
| T1C-4 | Assess+Report 决策 | REQ-137 | 评分器自适应选择 + 报告格式自适应 |
| T1C-5 | 跨阶段反馈闭环 | REQ-135 | ASR 趋势追踪器 + 预算消耗监控器 + 策略调整引擎 |
| T1C-6 | 决策系统护栏 | R-DECIDE-1~5 | 安全边界保护 + 审计追踪 + 决策稳定性 + 人类控制权 |

**阶段 1C 完成状态**：🟡 **架构设计完成**（2026-09-09 文档更新）

**退出条件**：
- REQ-135/136/137 验收全勾
- R-DECIDE-1~5 机器检查器全部满足 + R-DECIDE-6 人工评审通过（唯一定义见 40-GUARDRAILS 1G-DECIDE）
- 决策系统测试覆盖率 ≥80%

### 阶段 2 — 考试硬化

| 序 | 任务 | 引用 | 说明 |
|----|------|------|------|
| T2-1 | exam_mode campaign | REQ-112 | config/campaigns/exam_mode.yaml |
| T2-2 | OffSec 风格报告 section | REQ-113 | 四段结构并入现有报告管线 |
| T2-3 | 模拟考 | 本文件第六章 | 完整走一遍 24h 流程出报告 |

**退出条件**：模拟考报告通过自评 + exam_mode 单命令可跑。

### 阶段 3 — 持续运营（无终点）

- ASR 反馈闭环：定期人工修订 asr_priors
- 种子库扩充：新攻击面随时入库
- 考后复盘：考试发现的新差距 → change-proposal → 新 REQ

### 依赖链

`T0-1~T0-10 → 阶段1 → 阶段1B → 阶段1C → 阶段2 → 阶段3`

- **阶段 0**：✅ 已完成
- **阶段 1**：🟡 未启动（A2A/多智能体、供应链）
- **阶段 1B**：✅ 已完成
- **阶段 1C**：🟡 架构设计完成（全链路自主决策引擎）
- **阶段 2**：🟡 未启动
- **阶段 3**：🔄 持续运营

---

## 第五章：Vibe Coding 会话操作模型

### 5.1 会话入口仪式

```
读宪法(00) → 查本路线图领任务 → 读蓝图相关章节声明落点
→ 核对 REQ 验收标准 → 填 task-spec → Step 5 计划复述（用户确认）
→ 最小实现 → 四步门禁 → 三栏汇报 → 关闭并回填 20-REQUIREMENTS 状态表
```

### 5.2 会话类型配额

| 类型 | 规格 | 频率约束 |
|------|------|---------|
| 需求实现型 | task-spec 引用 REQ-ID | 按路线图序列 |
| 数据增强型 | 纯数据任务（种子/rubric/priors） | 随时；粒度豁免但仍需规格 |
| 审计型 | 只读分析 + backlog 登记 | 疑似漂移时立即触发 |

### 5.3 防漂移三条铁律

1. **开始前无规格** ↔ C6 规格先行 + 本路线图领任务制；
2. **写到一半自由发挥** ↔ STOP-REPORT 熔断（30-TASKS 第五章）；
3. **"顺手"扩范围** ↔ C4 最小 diff + 40-G 评审清单第一项。

### 5.4 会话收尾义务

每次会话（无论完成与否）：三栏汇报 + 状态表回填 + backlog 增量登记。**未完成 ≠ 失败；隐瞒未完成 = 违宪（C9）。**

---

## 第六章：考试日 Runbook（24h 实战 + 24h 报告）

### 6.1 战前检查单（考前一周）

- [ ] exam_mode.yaml 冻结（REQ-112）且单命令可跑
- [ ] 三角色 .env 就绪（objective/adversarial/scoring），密钥不入任何笔记
- [ ] Burp 目标导入演练通过
- [ ] 模拟考（T2-3）完成，报告自评通过
- [ ] 离线兜底：报告生成不依赖网络（NFR-7）

### 6.2 作战时间盒

| 时段 | 动作 | 使用 |
|------|------|------|
| H0–H2 | 全量 Burp 导入 → recon 指纹 → 价值排序 | `--stage recon` |
| H2–H4 | 武器化：prior 排序 + 场景路由 | `--stage arm` |
| H4–H16 | 打击：单轮 FIRST_SUCCESS → <90% 升级链；证据边打边落盘 | `--stage strike` |
| H16–H20 | 评分与联合 ASR | `--stage assess` |
| H20–H24 | 报告生成 + PoC 独立复跑验证 | `--stage report` |
| +24h | 以生成报告为底稿人工精修为 PDF | REQ-113 四段结构 |

### 6.3 战场纪律

- **卡死切换**：任一 endpoint 超 1h 无进展 → 切下一目标
- **token 告警**：50% 预算时降采样，80% 时只跑高 prior 路径
- **证据优先**：宁可少打一个目标，不可丢失已成功攻击的证据链
- **边界**：只打考试下发目标（R-S1）；报告零密钥（R-S2）
- **合规**：全程不使用交互式 AI 聊天助手（考试规则）

---

## 第七章：治理衔接

- 本路线图阶段/序列变更 → change-proposal
- 领取的任务与 ③④ 层冲突时 → STOP-REPORT，以 ③④ 为准
- 每完成一个任务，回填 20-REQUIREMENTS 状态表；每完成一个阶段，在本文件版本记录追加一行

---

## 第八章：考试就绪评分卡与快速交战 Playbook

### 8A. 考试就绪评分卡

> **评估时机**：考试前一周完成评估，满分 100 分，≥80 分判定为"可参加考试"。

| # | 维度 | 权重 | 评估标准 | 得分 |
|---|------|------|---------|------|
| R1 | **P0 主链路完整性** | 25% | REQ-001~008 全部 implemented 且 Tier 2 验证通过 | /25 |
| R2 | **Toolchain 健康度** | 15% | ruff 全绿、pytest 全过、guard BLOCKING 零新增 | /15 |
| R3 | **PyRIT 攻击引擎就绪** | 15% | PromptSendingAttack + SkeletonKeyAttack + 三多轮（Crescendo/TAP/PAIR）全部可跑通 | /15 |
| R4 | **考域覆盖度（11 模块）** | 20% | M1-M11 映射中 ≥9 模块有"已具备"或"可执行"评级 | /20 |
| R5 | **考试模式 campaign** | 10% | exam_mode.yaml 配置完成且单命令可跑 | /10 |
| R6 | **报告生成能力** | 10% | REQ-113 四段结构可即时生成、证据全字段非空验证通过 | /10 |
| R7 | **模拟考通过** | 5% | T2-3 模拟考完成、报告自评通过 | /5 |

**就绪等级**：
- **A 级（≥90 分）**：完全就绪
- **B 级（80-89 分）**：基本就绪
- **C 级（70-79 分）**：部分就绪，需考前补强
- **D 级（<70 分）**：不建议参加考试

### 8B. 快速交战 Playbook

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

# Step 2: Agent 专用种子
python main.py --stage arm --seeds T1_ASI02_function_call_exploit,T1_ASI03_workflow_escalation

# Step 3: SkeletonKeyAttack 首发
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
python main.py --stage arm --seeds mcp_server_injection,mcp_tool_chaining --dynamic

# Step 3: JSON-RPC 旁路直发
python main.py --stage strike --protocol jsonrpc

# Step 4: MCP 升级链
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

### 8C. 考试日应急预案与故障降级矩阵

> **设计原则**：考试中时间有限，故障时优先保证产出（ASR + 证据完整），而非追求完美修复。

#### 8C.1 快速应急响应表

| 情形 | 应急动作 | 预计恢复时间 | ASR 影响 |
|------|---------|------------|---------|
| 目标完全不可达 | 立即切换下一目标，记录失败原因 | 0min | — |
| PyRIT 版本不兼容 | 激活 venv + pyrit 钉住回滚 | 5min | — |
| Token 预算耗尽（80%） | 切换高先验种子-only 模式 | 2min | -10% |
| 证据链字段缺失 | 运行 evidence_validator.py 补全 | 10min | — |
| 报告生成超时 | 使用 --fast-mode 生成最小可用报告 | 2min | — |
| 自定义 LLM 评分器超时 | 降级到 0-token 拒绝检测-only 模式 | 1min | -5% |
| 升级链 L2-L4 执行失败 | 跳过当前级别，直接报告 L1 结果 | 0min | -15% |
| Recon/ARM 阶段超时 | 跳过深度探测，使用默认配置 | 0min | -20% |

#### 8C.2 故障降级决策树

```
阶段异常发生
      │
      ▼
┌─────────────────────────────────┐
│ 评估：剩余时间 vs 修复成本      │
└────────┬────────────────────────┘
         │
    ┌────┴────┐
    │ 修复时间 │
    │ < 5min?  │
    └────┬────┘
         │
    ┌────┴────┐     是     ┌─────────────────┐
    │ 尝试修复 │──────────▶│ 记录修复日志    │
    │         │           │ 继续原定计划    │
    └────┬────┘           └─────────────────┘
         │ 否
         ▼
┌─────────────────────────────────┐
│ 评估：降级后 ASR 损失           │
│ - 0-token-only: -5%             │
│ - 跳过升级 L2-L4: -15%          │
│ - 跳过 Recon/ARM: -20%          │
└────────┬────────────────────────┘
         │
    ┌────┴────┐
    │ ASR损失  │
    │ < 20%?   │
    └────┬────┘
         │
    ┌────┴────┐     是     ┌─────────────────┐
    │ 执行降级 │──────────▶│ 标记降级模式    │
    │         │           │ 报告中标注      │
    └────┬────┘           └─────────────────┘
         │ 否
         ▼
┌─────────────────────────────────┐
│ 切换目标：启动新 endpoint 攻击  │
│ （保留已有结果，不丢失证据）    │
└─────────────────────────────────┘
```

#### 8C.3 降级模式触发阈值

| 降级模式 | 触发条件 | 恢复条件 | 报告标注 |
|---------|---------|---------|---------|
| `FAST_MODE` | 剩余时间 < 总预算 20% | — | `[FAST]` 标记 |
| `HIGH_PRIOR_ONLY` | 剩余 Token < 30% | Token 补充后 | `[PRIOR_ONLY]` 标记 |
| `ZERO_TOKEN_ONLY` | LLM Judge 连续超时 3 次 | 手动恢复 | `[0-TOKEN]` 标记 |
| `SKIP_UPGRADE` | 升级链连续失败 2 次 | — | `[NO-UPGRADE]` 标记 |
| `MINIMAL_RECON` | Recon 阶段超时 (> 300s) | — | `[MIN-RECON]` 标记 |

> **注意**：所有降级操作必须记录到 `ctx.orchestration_log["degradation_events"]`，报告生成时自动汇总到附录。
> **口径裁定**（蓝图 6.1）：`SKIP_UPGRADE` 的"连续失败 2 次"属**考试日资源应急降级**（宁少勿滥），与决策稳定性 R-DECIDE-3 的"≥3 次连续失败"（常态防抖动，仅约束策略切换）分属不同机制，数值不互通、禁止互相改写。

---

## 版本记录

| 版本 | 日期 | 变更摘要 | 批准 |
|------|------|---------|------|
| v1.0 | 2026-09-05 | REV-02 创建：源码审计基线、双重使命与 AI-300 考纲映射、四阶段任务序列、vibe coding 会话操作模型、考试日 Runbook | 用户会话批准 |
| v1.1 | 2026-09-06 | REV-03 AI-300 考试路线图优化：新增第八章 考试就绪评分卡与快速交战 Playbook | 用户会话批准 |
| v1.2 | 2026-09-08 | REV-04 企业攻击路线图增补：新增阶段 1B 企业基础设施攻击（Glue 层实施） | 用户会话批准 |
| v1.3 | 2026-09-08 | REV-05 过度工程化清理：删除 T1B-3/T1B-6（黑盒不可测试），精简 T1B-5 | 用户会话批准 |
| v1.4 | 2026-09-09 | REV-06 任务状态标记更新：阶段 0/1B 全部标记完成 | 用户会话批准 |
| v1.5 | 2026-09-09 | REV-07 文档瘦身与代码同步：① 删除过时引用（glue/、pipeline/、targets/、已删除模块）；② 修正债务状态（D-01~D-16 全部消除）；③ 更新规模热点（display.py 606行）；④ 精简冗余描述；⑤ 阶段 1 删除 T1-2（Embedding 黑盒不可测试） | 用户会话批准 |
| v1.6 | 2026-09-09 | REV-08 新增阶段 1C 全链路自主决策引擎：① T1C-1 决策引擎框架（REQ-135）；② T1C-2 Recon 阶段决策（REQ-136）；③ T1C-3/4 ARM+Assess+Report 决策（REQ-137）；④ T1C-5 跨阶段反馈闭环；⑤ T1C-6 决策系统护栏（R-DECIDE-1~5）；⑥ 依赖链更新（阶段 1B → 阶段 1C → 阶段 2） | 用户会话批准 |
| v1.7 | 2026-09-09 | REV-09 考试日故障降级矩阵增补：① 快速应急响应表增加 ASR 影响列 + 新增 2 种故障情形；② 新增 8C.2 故障降级决策树；③ 新增 8C.3 降级模式触发阈值表（5 种降级模式 + 报告标注规范） | 用户会话批准 |
| v1.8 | 2026-09-09 | 规约优化 P0-A3/A5/A6：① T1C-6 与阶段 1C 退出条件更新至 R-DECIDE-1~6（唯一定义锚定 40-GUARDRAILS 1G）；② T0-1 Best-of-N 状态仲裁（stub 摘除 + 实装于 adaptive_executor.py，消除"实装→已摘除"表述矛盾）；③ 阶段 1B 八处 REQ 引用按 20-REQUIREMENTS 权威登记重对齐 | 用户会话批准 |
| v1.9 | 2026-09-09 | 规约优化 P1-B4/B5：① 新增阶段 0.5 ASR 基准校准（T0.5-1~4：基线运行/双口径分列/target_asr 缺口/账本核对），依赖链改为 阶段 0 → 0.5 → 1/1B/1C；② 8C.3 增补 SKIP_UPGRADE 口径裁定（2 次应急降级 ≠ R-DECIDE-3 ≥3 次策略切换，裁定锚点蓝图 6.1 统一表） | 用户会话批准 |
