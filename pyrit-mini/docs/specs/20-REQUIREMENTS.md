# 20 — 需求与规格层：做什么（Requirements & Specifications）

> **文档层级**：L2 / 五层规约金字塔第三层
> **效力**：本项目"做什么"的唯一登记处。**未登记于此的需求 = 不存在**。AI 不得实现未登记需求（宪法 C6）。
> **格式**：每条需求有 ID、一句话陈述、可勾选的验收标准（DoD）。验收标准是任务完成的**唯一**判据。
> **版本**：v2.8（2026-09-11 REV-16：三条主线复审补强——NFR-13 ④ 影响链口径收紧预告、REQ-150/151/152 验收加严（IC-1~IC-6））

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
| REQ-102 | ~~战役预设~~（已删除，功能被 `--target`/`--strike` CLI 路由替代） | ~~`config/profiles/*.yaml`~~ → `strike/dispatcher.py` + `data/seeds/_attack_surface/` |
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
| REQ-110 | Embedding 攻击落地 | **✅ 已裁决（蓝图 Q4）**：黑盒 HTTP 不可测试 → 编排内不实装（`strike/embedding_inversion.py` 不存在且不再创建）；仅允许域外工具形态接入回填数据（对齐 50-ROADMAP M6 / 蓝图 9.2 Embedding 分支）。禁止维持 stub 编排状态（R-H1） | M6 Embeddings |
| REQ-111 | 供应链侦察 | 仅报告侦察建议（SBOM/依赖/模型权重来源检查项清单，写入 fingerprint → report 渲染）；**不引入新运行时依赖（NEG-4 约束）** | M8 Supply Chain |
| REQ-112 | 考试模式 campaign | `--target model --strike prompt_sending --max-seeds 5 --timeout 300`：单 endpoint 快速链路 + token 预算上限 + 证据优先策略（evidence/ 实时落盘）+ 时间盒超时；通过 CLI 参数组合实现（原 REQ-102 已删除） |
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
| REQ-120~126 | 考试关键需求（时间盒/证据落盘/Token 监控） | ✅ exam-ready | CLI 参数组合（`--max-seeds`/`--timeout`/`--technique-filter`）+ `main.py` |

## 第四章：非功能需求

| ID | 维度 | 标准 |
|----|------|------|
| NFR-1 | Token 效率 + 精确度 | T0 过滤率≥30%；J1→J2 跳过率≥40%；总节省≥60%（日志可审计）；**精确度约束**：T0 假阴性率≤5%；J1/J2 分歧 OR 聚合假阳性率≤8%；0-token 与 LLM Judge 一致性≥85%；边界案例（confidence 0.4-0.6）自动升级到 LLM Judge |
| NFR-2 | 时间 | 单 endpoint 默认预算 1800s（quick_scan 300s；exam_mode 另定）；技术级超时受控 |
| NFR-3 | 并发 | get_effective_concurrency SSOT，clamp [1,3]；SQLite WAL |
| NFR-4 | 鲁棒 | 三级 fallback（adaptive→multi_path→partial）；空输入守卫；部分结果回收 |
| NFR-5 | 可复现 | --max-seeds 1 全链路可跑；PoC 独立可执行 |
| NFR-6 | Python ≥3.13（硬边界：PyRIT 1.0.1 官方支持区间；取交集内 ≥3.13，冲突则以 PyRIT 区间为准并登记 backlog，见 BL-002） | 全类型标注；keyword-only 参数；async 后缀 `_async` |
| NFR-7 | 离线可检 | 报告/PoC 生成不依赖网络（考试环境审查点）；依赖锁定（pyproject 钉 pyrit==1.0.* 区间，D-16 修复项） |
| NFR-8 | 考试鲁棒性 | 任一阶段失败不影响其他阶段输出；partial 结果可独立生成报告（REQ-126） |
| NFR-13 | ASR 度量口径 | ① 双口径分列：`reported_asr`（自动评分级联）/ `confirmed_asr`（人工复核）禁止混用，报告标题注明口径，无复核时 confirmed 标注 n/a；② 目标锚点 SSOT：目标 ASR 唯一定义于 `config/defaults.yaml` `target_asr`（I11），禁止文档/代码硬编码百分比；③ timeout/error 计失败，scorer 未判定归 unparsed 不计成功；④ **影响链口径收紧预告（ADR-008 / 蓝图 IC-5/IC-6）**：判定四态 `impact` / `exfil_confirmed` / `exfil_suspected` / `content_only`，**仅 `impact` 与 `exfil_confirmed` 计入 `confirmed_asr`**；启用 OOB 回执与二次独立确认后 `confirmed_asr` 会下降，属**口径收紧而非能力退化**，报告须注明口径并禁止与历史数值直接对比得出退化结论 |

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

## 第 5A 章：文件上传攻击需求（已实现 ✅，v2.4 新增）

> **背景**：支持任意 HTTP 目标系统的文件上传攻击场景，包括 multipart/form-data 上传和后续处理触发。
> **学术依据**：Greshake et al. (arXiv:2302.12173) 间接 Prompt 注入、Zou et al. (arXiv:2406.04245) PoisonedRAG 投毒。

| ID | 陈述 | 关键验收 | 代码落点 | 状态 |
|----|------|---------|----------|------|
| REQ-138 | 通用文件上传执行 | ① 支持 multipart/form-data 上传；② 支持任意端口 (0-65535)；③ 支持自定义表单字段名 | `strike/file_upload_executor.py` | ✅ |
| REQ-139 | 处理触发机制 | ① 支持上传后触发处理端点；② 支持自定义 HTTP 方法 (POST/GET/PUT)；③ 支持 JSON 请求体 | `strike/file_upload_executor.py` | ✅ |
| REQ-140 | 多文件攻击链 | ① 支持单/多文件顺序上传；② 支持分文档注入模式；③ 支持知识库投毒模式 | `strike/file_upload_executor.py` | ✅ |
| REQ-141 | CLI 参数支持 | ① `--file-upload-target` 指定目标 URL；② `--upload-files` 指定文件列表；③ `--upload-endpoint` / `--trigger-endpoint` 指定端点路径 | `core/config.py` | ✅ |
| REQ-142 | 流水线集成 | ① 集成到 `_run_file_upload_phase()`；② 结果存入 `ctx.attack_results`；③ 审计日志记录到 `orchestration_log` | `core/phases/strike.py` | ✅ |
| REQ-143 | 测试覆盖 | ① 39 个测试用例覆盖全部核心功能；② CLI 参数解析测试；③ 边界情况测试 | `tests/test_file_upload_executor.py` | ✅ |
| REQ-144 | 代码-文档同步 | ① CLI 参数变更必须同步更新 `red-team-dev-guide.md` 附录 D；② 新增攻击模块必须同步更新 `55-ATTACK-GAP-CLOSURE.md`；③ 新增需求/红线必须同步更新 `20-REQUIREMENTS.md` 和 `40-GUARDRAILS.md`；④ 文档版本号变更必须同步更新 `README.md` 金字塔索引 | `docs/specs/` + `docs/guides/` | ✅ |

**CLI 参数清单**：

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `--file-upload-target` | str | None | 目标基础 URL（如 `http://192.168.50.22:8004`） |
| `--upload-endpoint` | str | `/upload` | 上传端点路径 |
| `--trigger-endpoint` | str | `/summarize` | 处理触发端点路径 |
| `--upload-files` | str | None | 逗号分隔的文件路径列表 |
| `--upload-field-name` | str | `file` | 表单字段名（如 `document`、`attachment`） |
| `--trigger-method` | str | `POST` | 触发请求方法（POST/GET/PUT） |

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
| REQ-135 | 全链路自主决策引擎框架 | ① 决策引擎接口定义（`determine_*_strategy` 统一签名）；② 决策触发条件可配置；③ `ctx.decision_log` 字段记录所有决策；④ 决策系统护栏 R-DECIDE-1~6 全部满足（唯一定义见 40-GUARDRAILS 1G-DECIDE；R-DECIDE-6 为 INFO 人工评审） | P1 |
| REQ-136 | Recon 阶段自适应决策 | ① `determine_probe_strategy()` 基于预算和目标类型选择探测深度；② 检测到 WAF 自动启用 stealth 模式；③ 决策输出写入 `ctx.probe_level` 和 `ctx.stealth_config` | P1 |
| REQ-137 | ARM+Assess+Report 阶段决策 | ① ARM 阶段实现动态种子排序 + Converter 链优化；② Assess 阶段实现评分器自适应选择；③ Report 阶段实现报告格式自适应 | P2 |

### 第九章 B：决策系统非功能需求

| ID | 维度 | 标准 |
|----|------|------|
| NFR-9 | 决策透明度 | 所有自主决策必须记录到 `ctx.decision_log`，包含决策原因、输入数据、输出结果 |
| NFR-10 | 人工覆盖 | CLI 参数优先级高于自主决策（人类控制权） |
| NFR-11 | 决策稳定性 | 单次决策变更需基于 ≥3 次连续失败或 ASR 显著下降，避免频繁抖动；**升级链触发稳定性**：ASR < 70% 且 Strike 完成度 < 50% 才触发；ASR < 95% 且完成度 > 80% 触发 |
| NFR-12 | 决策可测试性 | 每个决策函数必须有独立单元测试，覆盖策略选择逻辑 |

### 第九章 C：决策需求状态追踪

| 需求组 | 状态 | 备注 |
|--------|------|------|
| REQ-135 决策引擎框架 | 🟡 架构设计完成 | 待实施 |
| REQ-136 Recon 决策 | 🟡 架构设计完成 | 待实施 |
| REQ-137 ARM+Assess+Report 决策 | 🟡 架构设计完成 | 待实施 |
| NFR-9~12 决策非功能需求 | 🟡 架构设计完成 | 随实施同步验证 |

---

## 第九章 B：跨模型规约审查需求（v2.2 新增）

> **背景**：基于 00-CONSTITUTION C14 条款，定义跨模型规约审查的功能需求。详细协议见 `60-CROSS-MODEL-VERIFICATION.md`。

### 第九章 B1：审查引擎核心需求

| ID | 陈述 | 验收标准 | 优先级 |
|----|------|---------|--------|
| REQ-144 | 系统应支持多模型并行审查 | ① 支持 ≥3 模型同时审查；② 各模型独立输出 JSON 报告；③ 模型池可配置 | P1 |
| REQ-145 | 系统应自动计算一致性指标 | ① 计算 Pairwise κ 和 Overall κ；② 输出 agreement_rate 和仲裁率；③ κ < 0.6 时阻断合入 | P1 |
| REQ-146 | 系统应支持分级仲裁 | ① confirmed findings 自动采纳；② single-model findings 标记待人工；③ disputed findings 按保守原则升级 | P1 |

### 第九章 B2：审查非功能需求

| ID | 维度 | 标准 |
|----|------|------|
| NFR-14 | 审查时效 | FULL 审查单次耗时 ≤ 5 分钟（3 模型并行） |
| NFR-15 | 审查存储 | 审查记录永久保留，支持历史 κ 趋势分析 |
| NFR-16 | 降级能力 | 模型池不足时自动降级到单模型+人工模式 |

### 第九章 B3：审查需求状态追踪

| 需求组 | 状态 | 备注 |
|--------|------|------|
| REQ-144~146 审查引擎 | 🟡 规约已登记 | 待工具链实施 |
| NFR-14~16 审查非功能 | 🟡 规约已登记 | 随实施同步验证 |

---

## 第九章 C：目标架构 v4.0 需求（v2.6 新增）

> **背景**：现有架构面向"单组件 / 单轮 prompt / 以 ASR 为唯一判据"，与企业主流 AI 应用场景（认证态 + 多步会话 + 多协议 + 多租户的组合体）存在三处架构级误配。本组需求为`10-ARCHITECTURE.md` 目标架构 v4.0 的功能登记。
> **关联提案**：`docs/specs/plans/CP-001-target-architecture-v4.0.md`（approved 后方可编码）
> **执行计划**：`docs/specs/plans/447be21ad0594078a923a53f701087d3-EXECUTION-PLAN.md`
> **护栏**：R-EVENT-1 / R-EVENT-2 / R-COMP-1（唯一定义见 `40-GUARDRAILS.md`，本表不重复登记）
> **不变量**：I12（阶段间只经 ctx + EventLog）/ I13（副作用步必须声明 cleanup）—— 见蓝图第六章

### 第九章 C1：核心需求登记

| ID | 陈述 | 验收标准 | 优先级 |
|----|------|---------|--------|
| REQ-148 | EventLog 事件总线：全阶段 append-only 事件流，作为终端/报告/证据/回放/续跑的唯一派生源 | ① `core/events.py` 提供事件写入与读取（schema：`ts/run_id/phase/node_id/etype/payload/refs`）；② 六阶段每阶段至少 1 类事件落盘 `outputs/<run_id>/events.jsonl`；③ 终端渲染与报告生成均从 EventLog 派生，不再直接读阶段内部内存结构；④ `--no-events` 旁路开关存在，W0 期间零行为回归 | P1 |
| REQ-149 | TargetAdapter：协议、认证态、会话态统一归一 | ① `recon/adapters/` 提供统一 `send()` 协议接口；② 至少实现 http / sse / jsonrpc / multipart 四类；③ 认证态（Bearer/Cookie/OAuth/mTLS 配置位）与会话态（chat_id/thread_id）在 adapter 内闭环，**编排层不可见协议差异**；④ 现有 Burp 目标经 adapter 可完整攻击（行为零回归） | P1 |
| REQ-150 | SurfaceGraph 攻击面图谱：多标签 + 置信度 + 信任边界 + 数据流边 | ① 节点支持多标签与分组件置信度（非单值分类）；② 边含 `data_flow` / `trust_boundary` 类型；③ 每个节点可回溯到 EventLog 证据；④ 识别失败时有 `fallback_labels` 兜底路径；⑤ W5 前旧 `target_fingerprint` 兼容视图不丢字段；⑥ **`component_type: str` 迁移为 `component_labels: list[str]` + `label_confidence: dict`**（IC-1），单值视图仅为兼容派生（W5 删除），迁移期下游零回归；⑦ **一个 finding 可归属多个组件**（IC-3），`report/evidence.py` 的 `attack_surface` 增 `graph_ref` | P1 |
| REQ-151 | PlaybookEngine 攻击链 DAG | ① 攻击链 YAML 每个 step 含 `precondition/action/verifier/cleanup`；② 支持 `depends_on` DAG 与 `on_fail`；③ 每步执行结果写入 EventLog；④ 至少落地 `rag_poison` 与 `mcp_enum_call` 两条链并在 mock 靶场端到端成功；⑤ **step 支持 `node_ref`（指向 SurfaceGraph 节点）+ `adapter`（选择 TargetAdapter）**，使跨组件链可表达（IC-2）；⑥ **迁移而非新建（IC-4）**：`strike/common/_executor_doc_poison.py`、`_executor_vuln_inject.py`、`strike/rag/data_poisoning.py`、`strike/mcp/malicious_server.py` 四条硬编码链迁为 `playbooks/*.yaml` 并删除原分支（删除期限登记 backlog），禁止出现第二套链机制 | P1 |
| REQ-152 | ImpactChain + ExfilChannel 影响链判定 | ① 判定输出四态：`impact` / `exfil_confirmed` / `exfil_suspected` / `content_only`，仅前两者计入 `confirmed_asr`（ADR-008）；② 一期实现 3 类外传信道（markdown_image / tool_param / callback）+ canary 与 OOB 验真接口；③ **外传成立必须 OOB 回执**（`tools/oob_listener.py`，标准库实现，NEG-4 合规），现有响应文本正则降级为 `exfil_suspected`（IC-5）；④ **副作用成立必须二次独立请求确认**，payload 自证字段（`side_effects` 等）不计成立（IC-6）；⑤ 报告可渲染"影响链证据"章节并注明口径 | P1 |
| REQ-153 | ComponentRegistry + 声明式攻击矩阵 YAML | ① `config/components/*.yaml` 覆盖 9 类组件（model/agent/mcp/a2a/rag/multimodal_upload/memory_session_tenant/web_infra/supply_chain）；② 每份声明 `detect/recon/seeds/converters/playbooks/scorer/report_section/cleanup`；③ `strike/common/dispatcher.py` 与 `core/phases/` 中零硬编码组件名；④ guard R-EVENT-1 对违规 BLOCKING | P1 |
| REQ-154 | 副作用治理：dry-run / 隔离目标标记 / cleanup 钩子 | ① `dry-run` 可走通含副作用链而不产生真实写入；② 无 cleanup 声明的副作用步在非 dry-run 下被拒绝执行；③ 隔离目标标记生效；④ mock 靶场验证 cleanup 后靶标状态复原 | P1 |
| REQ-155 | 断点续跑（`--resume <run_id>`） | ① 从 EventLog 恢复 playbook 状态；② 已完成 step 不重跑；③ 中断后已落盘证据不丢失 | P2 |
| REQ-156 | Mock 靶场与 CI 断言 | ① `targets/mock/` 提供 5 类靶标（mcp_server / rag_service / a2a_agent / tool_agent / web_gateway）；② **标准库 `http.server` 实现，零新增运行时依赖**（NEG-4）；③ `tools/mock_range.py --up/--down/--list` 可用；④ `fixtures/expected.yaml` 含期望标签/链/判据/清理后状态；⑤ e2e 进 CI | P1 |
| REQ-157 | 新增三个组件攻击面 | ① **多模态/文件上传**：构造→上传→触发→验证链可跑（复用 `strike/file_upload_executor.py`）；② **记忆/会话/多租户**：跨会话持久化生效可验 + 跨租户越权（IDOR on `chat_id`/`doc_id`/`tenant_id`）判定成立；③ **Web 基础设施面**：认证绕过 / 限流失效 / 日志注入 / 成本放大 DoW 四类均有验真回执（复用 `strike/{auth_attacks,web_attacks,audit_evasion}.py`）；④ 三者均注册入 ComponentRegistry | P1 |
| REQ-158 | 交付物脱敏与版本化可复现 | ① 报告 / PoC / 证据自动剥离 Authorization / Cookie / API Key；② PII 打码；③ 证据含目标快照 + 种子库版本 + 评分器版本 + PyRIT 版本 + 模型版本；④ 交付物密钥扫描 0 命中 | P1 |

### 第九章 C2：本组需求状态追踪

| 需求组 | 状态 | 备注 |
|--------|------|------|
| REQ-148 EventLog | ⚡ W0 已实施 | `core/events.py` + ctx 挂载/收尾 + `--no-events` + 5 阶段埋点 + 终端接入；17 测试通过；**W1 起成为报告/续跑消费方** |
| REQ-149 TargetAdapter | 🟡 规约已登记 | W1-1~W1-3 |
| REQ-150 SurfaceGraph | 🟡 规约已登记 | W1-4~W1-9 |
| REQ-151 PlaybookEngine | 🟡 规约已登记 | W2（先 RAG + MCP 两条深链，迁移非新建） |
| REQ-152 ImpactChain/Exfil | 🟡 规约已登记 | W3（OOB 回执为准） |
| REQ-153 ComponentRegistry | ⚡ W0 骨架已落地 | `core/registry.py` + `config/components/README.md` 契约；**空注册表（合法）**，W4 落齐 9 组件 |
| REQ-154 副作用治理 | 🟡 规约已登记 | W2-3（随 Playbook 门禁） |
| REQ-155 断点续跑 | 🟡 规约已登记 | W2-2 |
| REQ-156 Mock 靶场 | 🟡 规约已登记 | W1-6/W1-7 + W3-7/W3-8 |
| REQ-157 三个新组件面 | 🟡 规约已登记 | W4 |
| REQ-158 脱敏与可复现 | 🟡 规约已登记 | W3-5/W3-6 |

> **前置门禁**：CP-001 批准 + 蓝图 v3.0 落点（I12/I13、ADR-007/008、ctx 新字段登记）完成前，本组需求**不得进入编码**（C6 规格先行）。

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
| REQ-138 ~ REQ-144（文件上传攻击） | ✅ implemented | 通用文件上传执行器 + CLI参数 + 流水线集成 + 39测试 + 文档同步 |
| REQ-145 ~ REQ-147（跨模型审查） | 🟡 规约已登记 | 多模型并行/一致性指标/分级仲裁 |
| NFR-1 ~ NFR-8 | ✅ implemented | 非功能需求全部达成 |
| NFR-9 ~ NFR-12（决策非功能） | 🟡 架构设计完成 | 决策透明度/人工覆盖/稳定性/可测试性 |
| NFR-13（ASR 度量口径） | 🟡 规约已登记 | reported/confirmed 双口径 + `target_asr` 锚点（defaults.yaml 已落盘）；报告双列分列待实施 |
| NFR-14 ~ NFR-16（审查非功能） | 🟡 规约已登记 | 审查时效/存储/降级能力 |
| REQ-148 ~ REQ-158（目标架构 v4.0） | ⚡ W0 已实施 | CP-001 已批准（代录入待追认）；W0-4~W0-8 完成（EventLog 埋点 / ctx 四字段 / Registry 骨架 / R-EVENT-1 护栏 / 终端接入）；剩余 W1~W5 |

- 活跃需求（待实现）：**REQ-109** A2A 执行层落地（种子已有，需验证编排进升级链）；**REQ-148~158** 目标架构 v4.0 六大抽象（待 CP-001 批准）；
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
| v2.2 | 2026-09-09 | REV-12 P0 全面优化实施：① NFR-1 增补评分器精确度约束（T0 假阴性≤5%、J1/J2 假阳性≤8%、0-token 一致性≥85%、边界案例自动升级）；② NFR-11 增强升级链触发稳定性（Strike 完成度感知阈值） | 用户会话批准 |
| v2.3 | 2026-09-09 | 规约优化 P1-B1~B3：① 新增 NFR-13 ASR 度量口径（reported/confirmed 双口径分列 + timeout/error 计失败规则）；② 目标锚点 SSOT `target_asr`（config/defaults.yaml，与 I11 联动）；③ REQ-135 护栏引用锚定 40-GUARDRAILS 1G 唯一定义 | 用户会话批准 |
| v2.4 | 2026-09-09 | 新增第 5A 章文件上传攻击需求 REQ-138~143：① REQ-138 通用文件上传执行（multipart/form-data）；② REQ-139 处理触发机制（自定义 HTTP 方法）；③ REQ-140 多文件攻击链（分文档注入/知识库投毒）；④ REQ-141 CLI 参数支持（6 个新参数）；⑤ REQ-142 流水线集成；⑥ REQ-143 测试覆盖（39 个测试用例）；⑦ 更新需求追踪登记表 | 用户会话批准 |
| v2.5 | 2026-09-09 | 新增 REQ-144 代码-文档同步需求：① CLI 参数变更必须同步更新 `red-team-dev-guide.md` 附录 D；② 新增攻击模块必须同步更新 `55-ATTACK-GAP-CLOSURE.md`；③ 新增需求/红线必须同步更新 `20-REQUIREMENTS.md` 和 `40-GUARDRAILS.md`；④ 文档版本号变更必须同步更新 `README.md` 金字塔索引 | 用户会话批准 |
| v2.6 | 2026-09-09 | REV-14 新增第九章 B 跨模型规约审查需求：① REQ-145 多模型并行审查（≥3 模型+独立 JSON 输出+模型池可配置）；② REQ-146 一致性指标自动计算（Pairwise/Overall κ+阻断阈值）；③ REQ-147 分级仲裁（confirmed 自动采纳/single-model 标记/disputed 保守升级）；④ NFR-14~16 审查非功能需求（时效/存储/降级能力）；⑤ 更新需求追踪登记表新增 REQ-145~147 + NFR~14~16 条目 | 用户会话批准 |
| v2.7 | 2026-09-11 | REV-15 新增第九章 C 目标架构 v4.0 需求：① REQ-148 EventLog 事件总线（终端/报告/证据/回放/续跑唯一派生源）；② REQ-149 TargetAdapter 协议/认证/会话归一；③ REQ-150 SurfaceGraph 攻击面图谱（多标签+置信度+信任边界）；④ REQ-151 PlaybookEngine 攻击链 DAG（含 cleanup）；⑤ REQ-152 ImpactChain + ExfilChannel 影响链判定；⑥ REQ-153 ComponentRegistry + 声明式攻击矩阵 YAML；⑦ REQ-154 副作用治理；⑧ REQ-155 断点续跑；⑨ REQ-156 Mock 靶场与 CI 断言（零新增依赖）；⑩ REQ-157 三个新组件面（多模态上传/记忆会话多租户/WebInfra）；⑪ REQ-158 交付物脱敏与版本化可复现；⑫ 状态登记表与活跃需求同步；⑬ 关联提案 CP-001 + 执行计划 PLAN-447be21 | 用户会话批准 |
| v2.8 | 2026-09-11 | REV-16 三条主线复审补强（按"多组件组合体/有状态攻击链/影响链取证"全盘复审）：① NFR-13 增补 ④ 影响链口径收紧预告（判定四态，仅 impact 与 exfil_confirmed 计入 confirmed_asr，下降属口径收紧非能力退化）；② REQ-150 增补 ⑥⑦（component_type→component_labels+label_confidence、finding 多归属 + evidence.graph_ref）；③ REQ-151 增补 ⑤⑥（step 支持 node_ref/adapter、四条硬编码链迁移而非新建）；④ REQ-152 增补 ③④⑤（OOB 回执为准、T0 正则降级为 exfil_suspected、副作用需二次独立确认）；⑤ 对齐蓝图 IC-1~IC-6 与 ADR-008 四态判定 | 用户会话批准 |
