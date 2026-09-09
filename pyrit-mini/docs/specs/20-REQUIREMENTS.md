# 20 — 需求与规格层：做什么（Requirements & Specifications）

> **文档层级**：L2 / 五层规约金字塔第三层
> **效力**：本项目"做什么"的唯一登记处。**未登记于此的需求 = 不存在**。AI 不得实现未登记需求（宪法 C6）。
> **格式**：每条需求有 ID、一句话陈述、可勾选的验收标准（DoD）。验收标准是任务完成的**唯一**判据。
> **版本**：v2.0（2026-09-09 精简：归档已实现需求 REQ-001~REQ-134 为摘要，保留活跃需求 + NFR/NEG 核心规则，修复章节编号冲突）

---

## 第一章：需求分级

| 级别 | 定义 | 变更门槛 |
|------|------|---------|
| **P0** | ASR 主链路：Burp 目标 → 攻击 → 评分 → 证据。任何 P0 回归 = 发布阻断 | 修改需 change-proposal + 宪法级评审 |
| **P1** | 支撑能力：报告格式、多 endpoint、配置体系、可观测性、考域覆盖（REV-02 起） | 修改需规格变更（本文件 diff） |
| **P2** | 体验与优化：终端 UI、性能调优、文档 | 可经普通任务规格变更 |

## 第二章：P0 — ASR 主链路需求（已实现 ✅）

> P0 的总验收标准（一条顶一切）：**对 `data/burp/` 下任一真实目标，`python main.py` 端到端运行后，`ctx.overall_asr` 为有效数值且 `evidence.total_attacks > 0`；若存在成功攻击（overall_asr > 0），每条成功必须附可复现 PoC；若 ASR = 0（目标确未攻破），须交付零成功证据链与失败分析——攻击未成功 ≠ 验收失败，证据链缺失才是。**

### P0 需求归档摘要（2026-09-08 全面审计确认 implemented）

| ID | 陈述 | 实现状态 | 代码落点 |
|----|------|---------|---------|
| REQ-001 | Burp 目标接入 | ✅ 已实现 | `recon/target_builder.py` + `core/config.py` |
| REQ-002 | 目标能力侦察（三级探测→fingerprint） | ✅ 已实现 | `recon/health_probe.py` + `recon/capability_probe.py` |
| REQ-003 | 武器化（UCB1 排序 + Converter 多路径） | ✅ 已实现 | `arm/seed_ranker.py` + `arm/converter_selector.py` |
| REQ-004 | 单轮攻击（SequentialAttack + FIRST_SUCCESS） | ✅ 已实现 | `strike/executor.py` + `strike/escalation_runtime.py` |
| REQ-005 | 多轮升级链（L1→L4 + 中间退出） | ✅ 已实现 | `strike/escalation_runtime.py` |
| REQ-006 | 级联评分（T0→J1→J2→J3 + Wilson CI） | ✅ 已实现 | `assess/scorer.py` + `assess/asr_stats.py` |
| REQ-007 | 证据与报告（多格式 + PoC） | ✅ 已实现 | `report/generator.py` + `report/evidence.py` |
| REQ-008 | 多 endpoint 联合攻击（能力排序 + 联合 ASR） | ✅ 已实现 | `main.py` 多 endpoint 循环 |

## 第三章：P1 — 支撑需求（已实现 ✅，摘要）

| ID | 陈述 | 代码落点 |
|----|------|---------|
| REQ-101 | 四级配置体系（CLI > config-file > defaults > 硬编码） | `core/config.py` |
| REQ-102 | 战役预设（4 个 campaign yaml） | `config/profiles/*.yaml` |
| REQ-103 | 分阶段调试（`--stage` 六值独立运行） | `main.py` |
| REQ-104 | dry-run（0 token 走通六阶段） | `utils/dry_run.py` |
| REQ-105 | ASR 先验矩阵（priors 人工修订 + history 运行时 SSOT） | `config/asr_priors.yaml` + `assess/asr_stats.py` |
| REQ-106 | 攻击面场景路由（分类→technique_tags） | `core/scenario_router.py` |
| REQ-107 | 资源生命周期（LIFO + 幂等清理） | `core/context.py` |
| REQ-108 | 架构守卫（BLOCKING 违规阻断提交） | `tools/guard.py` |

## 第 3A 章：考域覆盖需求（部分实现，活跃）

> 背景：项目第二使命为 OSAI/AI-300 备考武器化（24h 实战 + 报告）。考纲 11 模块与本项目的映射及差距分析见 `specs/50-ROADMAP.md` 第二章。本登记只收"进入代码的做"的部分；映射本身不入代码。

| ID | 陈述 | 关键验收 | 考纲模块 |
|----|------|---------|---------|
| REQ-109 | A2A/多智能体攻击执行 | 现状仅有 ma_* 种子（5 条）；执行层须支持至少 cross-agent injection / agent impersonation / workflow corruption 三类攻击编排进升级链（多轮技术，尊重 adversarial target 有无） | M4 Multi-Agent & A2A |
| REQ-110 | Embedding 攻击落地 | strike/embedding_inversion.py（8.4KB）实装或按蓝图 Q4 决策树裁决：属 PyRIT 域则实装（信息抽取/倒置两类），域外则以外部工具形态接入并回填数据；**禁止维持 stub 编排状态（R-H1）** | M6 Embeddings |
| REQ-111 | 供应链侦察 | 仅报告侦察建议（SBOM/依赖/模型权重来源检查项清单，写入 fingerprint → report 渲染）；**不引入新运行时依赖（NEG-4 约束）** | M8 Supply Chain |
| REQ-112 | 考试模式 campaign | `config/profiles/exam_mode.yaml`：单 endpoint 快速链路（recon→strike→report 精简路径）+ token 预算上限 + 证据优先策略（evidence/ 实时落盘）+ 时间盒超时；与 REQ-102 战役预设同机制 |
| REQ-113 | OffSec 风格报告 | 报告生成器输出四段结构：executive summary / findings（含风险等级 CVSS 类比 + OWASP LLM 2025 + MITRE ATLAS 映射）/ impact / remediation；作为现有 REQ-007 多格式报告的增量 section，不另立报告管线（C3） |

## 第 3B 章：P0-NEW / P0-EXAM — 已修复需求归档（2026-09-08 ✅）

> 以下需求原为 2026-09-06 代码审计发现的缺陷和考试优化需求，已于 2026-09-08 全面过度工程化清理中全部修复。

| ID | 陈述 | 修复状态 | 代码落点 |
|----|------|---------|---------|
| REQ-114 | 升级链默认配置下可达 | ✅ 已修复 | `strike/escalation_runtime.py` |
| REQ-115 | 多智能体种子完整加载 | ✅ 已修复 | `arm/seed_ranker.py` |
| REQ-116 | MCP 动态种子链路接通 | ✅ 已修复 | `strike/mcpsec_orchestrator.py` |
| REQ-117 | 死代码清理 | ✅ 已修复 | 删除 `targets/agent_adapter.py` + `data/scorer_selector.py` |
| REQ-118 | 编码损坏清零 | ✅ 已修复 | 删除损坏文件 + 清理乱码 |
| REQ-119 | 场景特异性进入执行层 | ✅ 已修复 | `strike/executor.py` 场景分支 |
| REQ-120~126 | 考试关键需求（时间盒/证据落盘/Token 监控） | ✅ exam-ready | `config/profiles/exam_mode.yaml` + `main.py` |

## 第四章：非功能需求

| ID | 维度 | 标准 |
|----|------|------|
| NFR-1 | Token 效率 | T0 过滤率≥30%；J1→J2 跳过率≥40%；总节省≥60%（日志可审计） |
| NFR-2 | 时间 | 单 endpoint 默认预算 1800s（quick_scan 300s；exam_mode 另定）；技术级超时受控 |
| NFR-3 | 并发 | get_effective_concurrency SSOT，clamp [1,3]；SQLite WAL |
| NFR-4 | 鲁棒 | 三级 fallback（adaptive→multi_path→partial）；空输入守卫；部分结果回收 |
| NFR-5 | 可复现 | --max-seeds 1 全链路可跑；PoC 独立可执行 |
| NFR-6 | Python ≥3.13（硬边界：PyRIT 1.0.1 官方支持区间；取交集内 ≥3.13，冲突则以 PyRIT 区间为准并登记 backlog，见 BL-002） | 全类型标注；keyword-only 参数；async 后缀 `_async` |
| NFR-7 | 离线可检 | 报告/PoC 生成不依赖网络（考试环境审查点）；依赖锁定（pyproject 钉 pyrit==1.0.* 区间，D-16 修复项） |
| NFR-8 | 考试鲁棒性 | 任一阶段失败不影响其他阶段输出；partial 结果可独立生成报告（REQ-126） |

## 第五章：Web 攻击层需求（已实现 ✅，摘要）

> **背景**：企业 AI 系统的攻击覆盖面不仅限于 LLM prompt 层，还包括认证、API Gateway、审计系统等。
> **v2.0 变更**：Glue 层已扁平化到 `strike/` 目录（原 glue/ 目录已删除）。向量 DB/Fine-tuning 攻击已移除（黑盒 HTTP 不可测试）。

| ID | 陈述 | 代码落点 | 状态 |
|----|------|---------|------|
| REQ-127 | 认证攻击覆盖（JWT/OAuth/Session） | `strike/auth_attacks.py` | ✅ |
| REQ-129 | API Gateway 攻击覆盖（速率限制/走私/缓存投毒） | `strike/web_attacks.py` | ✅ |
| REQ-130 | 审计逃逸攻击覆盖（日志注入） | `strike/audit_evasion.py` | ✅ |
| REQ-132 | 统一编排器 | `strike/web_orchestrator.py` | ✅ |
| REQ-133 | 延迟导入机制 | 全部 Web 攻击模块 | ✅ |
| REQ-134 | 攻击成功率度量 | 全部 Web 攻击模块 | ✅ |
| REQ-128/131 | ~~向量 DB/Fine-tuning 攻击~~ | 已移除（黑盒不可测试） | — |

## 第六章：需求变更流程（防偏航核心）

**任何新想法（无论来自用户还是 AI）进入代码的唯一路径**：

```
想法 → specs/templates/change-proposal.md 填写件
     → 人工评审（批准 / 驳回 / 转 backlog）
     → 批准：在本文件登记 REQ/DEBT 条目（含验收标准）
     → 才允许生成任务规格（30-TASKS）
     → 才允许编码
```

**AI 的义务**：
- 用户口头提出的新功能 = 一个待写的 change-proposal，**不是**开工指令；
- 评审未完成前，AI 可以做的只有：写提案、回答澄清问题、做不落码的调研。

## 第七章：负需求（禁止清单）

与正向需求同等效力的"不做"需求：

| ID | 禁止事项 | 理由 |
|----|---------|------|
| NEG-1 | 禁止扩展 D-01~D-16 债务涉及的任何双轨/stub（如给 stub 增加调用方、给合并版和拆分版同时加功能） | C3 SSOT |
| NEG-2 | 禁止在攻击端（strike/arm/recon）添加内容过滤、安全护栏、"稳妥降级"（指以安全/稳妥为由过滤攻击内容、降级攻击强度或跳过攻击路径；不含 REQ-003 的运营性种子裁剪，见其注） | C2 / R1 |
| NEG-3 | 禁止新增绕过 PipelineContext 的阶段间数据通道 | 蓝图 2.2 |
| NEG-4 | 禁止引入 pyproject.toml 之外的新运行时依赖（提案制） | C1 / 供应链 |
| NEG-5 | 禁止修改 guard 检查器以"让违规消失"（检查器只能因规则变更而变更，走 C12） | D3 |
| NEG-6 | 禁止未经提案修改 `config/defaults.yaml` 中 L5 基线参数（只准上调不准下调，下调需提案） | R4 |
| NEG-7 | 禁止运行时产物（asr_history.json、outputs/、db/pyrit.db、guard 基线）入 git；`.gitignore` 为唯一防线 | I7 SSOT / 仓库卫生（D-16） |

## 第九章：全链路自主决策需求（v2.1 新增）

> **背景**：基于已实施的 Strike 阶段战术决策系统，扩展为覆盖全链路的自主决策引擎。详细架构见 `10-ARCHITECTURE.md` 第十一章和 `55-ATTACK-GAP-CLOSURE.md` 第九章。

### 第九章 A：决策引擎核心需求

| ID | 陈述 | 验收标准 | 优先级 |
|----|------|----------|--------|
| REQ-135 | 全链路自主决策引擎框架 | ① 决策引擎接口定义（`determine_*_strategy` 统一签名）；② 决策触发条件可配置；③ `ctx.decision_log` 字段记录所有决策；④ 决策系统护栏 R-DECIDE-1~4 全部满足 | P1 |
| REQ-136 | Recon 阶段自适应决策 | ① `determine_probe_strategy()` 基于预算和目标类型选择探测深度；② 检测到 WAF 自动启用 stealth 模式；③ 决策输出写入 `ctx.probe_level` 和 `ctx.stealth_config` | P1 |
| REQ-137 | ARM+Assess+Report 阶段决策 | ① ARM 阶段实现动态种子排序 + Converter 链优化；② Assess 阶段实现评分器自适应选择；③ Report 阶段实现报告格式自适应 | P2 |

### 第九章 B：决策系统非功能需求

| ID | 维度 | 标准 |
|----|------|------|
| NFR-9 | 决策透明度 | 所有自主决策必须记录到 `ctx.decision_log`，包含决策原因、输入数据、输出结果 |
| NFR-10 | 人工覆盖 | CLI 参数优先级高于自主决策（人类控制权） |
| NFR-11 | 决策稳定性 | 单次决策变更需基于 ≥3 次连续失败或 ASR 显著下降，避免频繁抖动 |
| NFR-12 | 决策可测试性 | 每个决策函数必须有独立单元测试，覆盖策略选择逻辑 |

### 第九章 C：决策需求状态追踪

| 需求组 | 状态 | 备注 |
|--------|------|------|
| REQ-135 决策引擎框架 | 🟡 架构设计完成 | 待实施 |
| REQ-136 Recon 决策 | 🟡 架构设计完成 | 待实施 |
| REQ-137 ARM+Assess+Report 决策 | 🟡 架构设计完成 | 待实施 |
| NFR-9~12 决策非功能需求 | 🟡 架构设计完成 | 随实施同步验证 |

---

## 第十章：需求追踪

**状态登记表**（2026-09-09 v2.0 精简重构）：

| 需求组 | 状态 | 备注 |
|--------|------|------|
| REQ-001 ~ REQ-008（P0 主链路） | ✅ implemented | 六阶段链路完整，Best-of-N 已集成 |
| REQ-101 ~ REQ-108（P1 支撑） | ✅ implemented | 配置体系、dry-run、ASR 先验矩阵均已在位 |
| REQ-109 ~ REQ-113（考域覆盖） | ⚡ partial | exam_mode (REQ-112) 已实现；A2A 执行 (REQ-109) 种子就绪待验证 |
| REQ-114 ~ REQ-126（P0-NEW + P0-EXAM） | ✅ implemented | 2026-09-08 修复/考试就绪 |
| REQ-127 ~ REQ-134（Web 攻击层） | ✅ implemented | 认证/API Gateway/审计逃逸/编排器 |
| REQ-135 ~ REQ-137（自主决策） | 🟡 架构设计完成 | 决策引擎框架 + Recon + ARM/Assess/Report |
| NFR-1 ~ NFR-8 | ✅ implemented | 非功能需求全部达成 |
| NFR-9 ~ NFR-12（决策非功能） | 🟡 架构设计完成 | 决策透明度/人工覆盖/稳定性/可测试性 |

- 活跃需求（待实现）：**REQ-109** A2A 执行层落地（种子已有，需验证编排进升级链）；
- 本表为需求登记 SSOT；历史追踪文档 `requirement_traceability_matrix.md` 已于 2026-09-06 删除（D-09 债务消除）。

---

## 版本记录

| 版本 | 日期 | 变更摘要 | 批准 |
|------|------|---------|------|
| v1.0 | 2026-09-05 | 初版：P0/P1/P2 分级、REQ-001~008、REQ-101~108、NFR-1~6、NEG-1~6、变更流程 | — |
| v1.1 | 2026-09-05 | REV-01：P0 总验收改条件式；REQ-003 加运营裁剪注；REQ-105 明确 EMA 回写目标；状态登记表实例化 | 用户会话批准 |
| v1.2 | 2026-09-05 | REV-02：新增第 3A 章考域覆盖需求 REQ-109~113；新增 NFR-7/NEG-7；REQ-004 标注 Best-of-N stub 为 P0 缺口 | 用户会话批准 |
| v1.3 | 2026-09-06 | REV-03：新增第 3B 章 P0-NEW 需求缺口 REQ-114~119（代码审计发现） | — |
| v1.4 | 2026-09-06 | REV-04：新增第 3C 章 P0-EXAM 考试关键需求 REQ-120~126；新增 NFR-8 考试鲁棒性 | 用户会话批准 |
| v1.5 | 2026-09-06 | REV-07 目录结构重构（Burp 目标文件迁移、Campaign 重命名） | 用户会话批准 |
| v1.6 | 2026-09-08 | REV-08：新增第五章企业 Glue 层需求 REQ-127~134 | 用户会话批准 |
| v1.7 | 2026-09-08 | REV-09：精简 Glue 层（移除向量 DB/Fine-tuning 攻击需求） | 用户会话批准 |
| v2.0 | 2026-09-09 | REV-10 精简重构：① P0/P1 主链路需求归档为摘要表（REQ-001~008 + REQ-101~108）；② P0-NEW/P0-EXAM 合并为已修复归档（REQ-114~126 全部 implemented/exam-ready）；③ Web 攻击层需求精简（REQ-127~134，Glue→扁平化）；④ 修复两个"第七章"编号冲突（第七章负需求→第八章追踪）；⑤ 状态登记表重构（标记活跃缺口 REQ-109）；⑥ 删除 ~200 行冗余验收细节，文档从 269 行精简至 ~130 行 | 用户会话批准 |
| v2.1 | 2026-09-09 | REV-11 新增第九章全链路自主决策需求：① REQ-135 决策引擎框架（P1）；② REQ-136 Recon 阶段自适应决策（P1）；③ REQ-137 ARM+Assess+Report 阶段决策（P2）；④ NFR-9~12 决策非功能需求（透明度/人工覆盖/稳定性/可测试性）；⑤ 原第八章"需求追踪"重命名为第十章 | 用户会话批准 |
