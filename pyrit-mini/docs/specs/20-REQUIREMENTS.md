# 20 — 需求与规格层：做什么（Requirements & Specifications）

> **文档层级**：L2 / 五层规约金字塔第三层
> **效力**：本项目"做什么"的唯一登记处。**未登记于此的需求 = 不存在**。AI 不得实现未登记需求（宪法 C6）。
> **格式**：每条需求有 ID、一句话陈述、可勾选的验收标准（DoD）。验收标准是任务完成的**唯一**判据。
> **版本**：v3.0（2026-09-12 REV-20：新增 **第九章 D：用户诉求差距闭合需求**，登记 REQ-160~171 + NFR-17~19 + 红线 R-ROE-1/R-EVID-1/R-AUDIT-1；依据 `plans/CP-002-user-gap-closure.md`。REV-17 的 REQ-159 改号等项保持有效）
> **版本史**：`git log -- docs/specs/20-REQUIREMENTS.md`

> **ID 分配纪律**：REQ-xxx 全局唯一、只增不改。发现重号即为 P0 文档缺陷，须立即登记 backlog 并改号（不得改需求语义）。

---

## 第一章：需求分级 [sid:20-ch1]

| 级别 | 定义 | 变更门槛 |
|------|------|---------|
| **P0** | ASR 主链路：Burp 目标 → 攻击 → 评分 → 证据。任何 P0 回归 = 发布阻断 | 修改需 change-proposal + 宪法级评审 |
| **P1** | 支撑能力：报告格式、多 endpoint、配置体系、可观测性、考域覆盖（REV-02 起） | 修改需规格变更（本文件 diff） |
| **P2** | 体验与优化：终端 UI、性能调优、文档 | 可经普通任务规格变更 |

## 第二章：P0 — ASR 主链路需求（已实现 ✅） [sid:20-ch2]

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

## 第三章：P1 — 支撑需求（已实现 ✅，摘要） [sid:20-ch3]

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

## 第 3A 章：考域覆盖需求（部分实现，活跃） [sid:20-ch3a]

> 背景：项目第二使命为 OSAI/AI-300 备考武器化（24h 实战 + 报告）。考纲 11 模块与本项目的映射及差距分析见 `specs/50-ROADMAP.md` 第二章。本登记只收"进入代码的做"的部分；映射本身不入代码。

| ID | 陈述 | 关键验收 | 考纲模块 |
|----|------|---------|---------|
| REQ-109 | A2A/多智能体攻击执行 | 现状仅有 ma_* 种子（5 条）；执行层须支持至少 cross-agent injection / agent impersonation / workflow corruption 三类攻击编排进升级链（多轮技术，尊重 adversarial target 有无） | M4 Multi-Agent & A2A |
| REQ-110 | Embedding 攻击落地 | **✅ 已裁决（蓝图 Q4）**：黑盒 HTTP 不可测试 → 编排内不实装（`strike/embedding_inversion.py` 不存在且不再创建）；仅允许域外工具形态接入回填数据（对齐 50-ROADMAP M6 / 蓝图 9.2 Embedding 分支）。禁止维持 stub 编排状态（R-H1） | M6 Embeddings |
| REQ-111 | 供应链侦察 | 仅报告侦察建议（SBOM/依赖/模型权重来源检查项清单，写入 fingerprint → report 渲染）；**不引入新运行时依赖（NEG-4 约束）** | M8 Supply Chain |
| REQ-112 | 考试模式 campaign | `--target model --strike prompt_sending --max-seeds 5 --timeout 300`：单 endpoint 快速链路 + token 预算上限 + 证据优先策略（evidence/ 实时落盘）+ 时间盒超时；通过 CLI 参数组合实现（原 REQ-102 已删除） |
| REQ-113 | OffSec 风格报告 | 报告生成器输出四段结构：executive summary / findings（含风险等级 CVSS 类比 + OWASP LLM 2025 + MITRE ATLAS 映射）/ impact / remediation；作为现有 REQ-007 多格式报告的增量 section，不另立报告管线（C3） |

## 第 3B 章：P0-NEW / P0-EXAM — 已修复需求归档（2026-09-08 ✅） [sid:20-ch3b]

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

## 第四章：非功能需求 [sid:20-ch4]

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

## 第五章：Web 攻击层需求（已实现 ✅，摘要） [sid:20-ch5]

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

## 第 5A 章：文件上传攻击需求（已实现 ✅，v2.4 新增） [sid:20-ch5a]

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
| REQ-159 | 代码-文档同步 | ① CLI 参数变更必须同步更新 `main.py`/`core/config.py` 的 argparse 定义（代码即 CLI 文档，运行 `--help` 即得；R-DOC-1 的 SSOT 目标）；② 新增攻击模块必须同步更新 `55-ATTACK-GAP-CLOSURE.md`；③ 新增需求/红线必须同步更新 `20-REQUIREMENTS.md` 和 `40-GUARDRAILS.md`；④ 规约文档遵守 `specs/README.md` §5 文档纪律（禁行号坐标 / 禁正文版本史 / 清单读代码） | `docs/specs/` | ✅ |

> **改号说明**（REV-17）：本条原编号 REQ-144 与第九章 B 的「跨模型审查 REQ-144」重号。REQ-xxx 全局唯一，**本条改号 REQ-159**；语义不变。

**CLI 参数清单**：

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `--file-upload-target` | str | None | 目标基础 URL（如 `http://192.168.50.22:8004`） |
| `--upload-endpoint` | str | `/upload` | 上传端点路径 |
| `--trigger-endpoint` | str | `/summarize` | 处理触发端点路径 |
| `--upload-files` | str | None | 逗号分隔的文件路径列表 |
| `--upload-field-name` | str | `file` | 表单字段名（如 `document`、`attachment`） |
| `--trigger-method` | str | `POST` | 触发请求方法（POST/GET/PUT） |

## 第六章：需求变更流程（防偏航核心） [sid:20-ch6]

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

## 第七章：负需求（禁止清单） [sid:20-ch7]

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

## 第九章：全链路自主决策需求（v2.1 新增） [sid:20-ch9]

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

## 第九章 B：跨模型规约审查需求（v2.2 新增） [sid:20-ch9b]

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

## 第九章 C：目标架构 v4.0 需求（v2.6 新增） [sid:20-ch9c]

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
| REQ-153 | ComponentRegistry + 声明式攻击矩阵 YAML | ① 组件差异**唯一**声明于 `config/components/*.yaml`（字段契约见该文件目录 `README.md`），规约层不抄写清单；② `core/registry.py` 提供 `keys()/names()/spec()/specs()/by_neighbor()/validate_wiring()`；③ `strike/common/dispatcher.py` 与 `core/phases/` 中零硬编码组件名；④ guard R-EVENT-1 对违规 BLOCKING；⑤ 双命名空间（`id`=文件/目录标识，`component_key`=运行时调度主键）规则见 `80-COMPONENT-ARCHITECTURE-RULES.md` 第二章 | P1 |
| REQ-154 | 副作用治理：dry-run / 隔离目标标记 / cleanup 钩子 | ① `dry-run` 可走通含副作用链而不产生真实写入；② 无 cleanup 声明的副作用步在非 dry-run 下被拒绝执行；③ 隔离目标标记生效；④ mock 靶场验证 cleanup 后靶标状态复原 | P1 |
| REQ-155 | 断点续跑（`--resume <run_id>`） | ① 从 EventLog 恢复 playbook 状态；② 已完成 step 不重跑；③ 中断后已落盘证据不丢失 | P2 |
| REQ-156 | Mock 靶场与 CI 断言 | ① `targets/mock/` 提供 5 类靶标（mcp_server / rag_service / a2a_agent / tool_agent / web_gateway）；② **标准库 `http.server` 实现，零新增运行时依赖**（NEG-4）；③ `tools/mock_range.py --up/--down/--list` 可用；④ `fixtures/expected.yaml` 含期望标签/链/判据/清理后状态；⑤ e2e 进 CI | P1 |
| REQ-157 | 新增三个组件攻击面 | ① **多模态/文件上传**：构造→上传→触发→验证链可跑（复用 `strike/file_upload_executor.py`）；② **记忆/会话/多租户**：跨会话持久化生效可验 + 跨租户越权（IDOR on `chat_id`/`doc_id`/`tenant_id`）判定成立；③ **Web 基础设施面**：认证绕过 / 限流失效 / 日志注入 / 成本放大 DoW 四类均有验真回执（复用 `strike/{auth_attacks,web_attacks,audit_evasion}.py`）；④ 三者均注册入 ComponentRegistry | P1 |
| REQ-158 | 交付物脱敏与版本化可复现 | ① 报告 / PoC / 证据自动剥离 Authorization / Cookie / API Key；② PII 打码；③ 证据含目标快照 + 种子库版本 + 评分器版本 + PyRIT 版本 + 模型版本；④ 交付物密钥扫描 0 命中 | P1 |

### 第九章 C2：本组需求状态追踪

| 需求组 | 状态 | 备注 |
|--------|------|------|
| REQ-148 EventLog | ⚡ W0 已实施 | `core/events.py` + ctx 挂载/收尾 + `--no-events` + 5 阶段埋点 + 终端接入；17 测试通过；**W1 起成为报告/续跑消费方** |
| REQ-149 TargetAdapter | ⚡ 已实施 | ①②③ 已落地：`recon/adapters/{base,http,sse,jsonrpc,multipart}.py` 提供统一 `send()/send_request()/close()`（`TargetAdapter` Protocol），认证态（Bearer/Cookie/API Key/OAuth/mTLS）与会话态（chat_id/thread_id/session_id）在 `AuthState`/`SessionState` 内闭环，编排层不可见协议差异；`build_adapter`/`choose_kind` 由入口特征自动择协议。另落地 `strike/targets/{mcp,rag,a2a}.py`（`MCPTarget` handshake→tools/list→tools/call、`RAGTarget` query→retrieve→generate、`A2ATarget` agent card→tasks/send），三者均为 PyRIT `PromptTarget` 子类。④ **零回归已证**（旧 Burp 路径未改动，全套 1812 测试通过）；**已闭环**：主链路按 `step.adapter` 选择 TargetAdapter 归 REQ-151 PlaybookEngine（BL-037 已 resolved）；`build_adapter(kind=mcp/rag/a2a)` 此前为死代码（choose_kind 永不返回这些 kind），现经 `_TargetAdapterWrapper` 真正路由到 `MCPTarget/RAGTarget/A2ATarget`（mcp 内部走 JSONRPCAdapter）。回归：`tests/common/test_adapters.py`（含 MockRange 端到端 + `TestAdapterContract` mcp/rag/a2a 契约） |
| REQ-150 SurfaceGraph | 🟡 规约已登记 | W1-4~W1-9 |
| REQ-151 PlaybookEngine | ⚡ 已实施 | `strike/playbook.py` 提供 `PlaybookEngine`：`_order_steps` 按 `depends_on` 做 Kahn 拓扑排序（环回退声明序），未知动作回退 `send`，单步失败不阻断整链（优雅降级）；`build_adapter` 经 `_TargetAdapterWrapper(BaseAdapter)` 把 PyRIT `MCPTarget/RAGTarget/A2ATarget` 包装为合规 `TargetAdapter`（`.name`/`.send`/`.close`/`.describe()` 含 auth/session，转发 `handshake/list_tools/call_tool/query/send_task/fetch_agent_card`），成为按 `step.adapter` 选择目标的唯一入口（IC-2）；落地 `config/playbooks/mcp_enum_call.yaml`（handshake→list_tools→call_tool，工具名动态解析）与 `rag_query.yaml` 两条链。回归：`tests/common/test_playbook_engine.py`（4 用例）+ `tests/common/test_adapters.py::TestAdapterContract`（含 mcp/rag/a2a 契约） |
| REQ-152 ImpactChain/Exfil | 🟡 规约已登记 | W3（OOB 回执为准） |
| REQ-153 ComponentRegistry | ⚡ W0 骨架已落地 | `core/registry.py` + `config/components/README.md` 契约；**空注册表（合法）**，W4 落齐 9 组件 |
| REQ-154 副作用治理 | 🟡 规约已登记 | W2-3（随 Playbook 门禁） |
| REQ-155 断点续跑 | 🟡 规约已登记 | W2-2 |
| REQ-156 Mock 靶场 | 🟡 规约已登记 | W1-6/W1-7 + W3-7/W3-8 |
| REQ-157 三个新组件面 | 🟡 规约已登记 | W4 |
| REQ-158 脱敏与可复现 | 🟡 规约已登记 | W3-5/W3-6 |

> **前置门禁**：CP-001 批准 + 蓝图 v3.0 落点（I12/I13、ADR-007/008、ctx 新字段登记）完成前，本组需求**不得进入编码**（C6 规格先行）。

---

## 第九章 D：用户诉求差距闭合需求（v3.0 新增） [sid:20-ch9d]

> **背景**：针对用户提出的"企业主流 LLM 应用（agent / 多 agent / rag / mcp / embedding）红队测试框架"约 40 项架构、模块、横切问题，经 2026-09-12 全量代码核对后，识别出 12 类**未登记能力**。
> **关联提案**：`docs/specs/plans/CP-002-user-gap-closure.md`
> **关联执行计划**：`pyrit-mini-L5-expert-gap-closure`（用户会话批准）
> **去重声明（C3）**：TargetAdapter（REQ-149）、SurfaceGraph（REQ-150）、ImpactChain/Exfil（REQ-152）、ComponentRegistry（REQ-153）、Mock 靶场（REQ-156）、交付物脱敏与版本快照（REQ-158）**已登记**，本组只引用/加严，不重复登记。
> **前置门禁**：CP-002 批准前，本组需求**不得进入编码**（C6 规格先行）。

### 第九章 D1：核心需求登记

| ID | 陈述 | 验收标准 | 优先级 |
|----|------|----------|--------|
| REQ-160 | 多形态输入解析扩展 | ① 支持 Burp HAR 导出（保留请求/响应完整时序）；② 支持单文件多请求序列切分；③ 支持 Site Map（XML/JSON）与 Postman 集合导入；④ 支持裸 URL 入口的关联端点发现（如 `/api/chat` → `/api/tools`、`/api/embeddings`）；⑤ 全部解析结果**收敛进现有 `ctx.parsed_request` 契约**，禁止另立平行数据流（I12） | P1 |
| REQ-161 | 侦察扩展：GraphQL / WAF / 限流 | ① GraphQL introspection 探测 + schema 提取（端点/类型/字段）；② WAF 指纹检测（含 Cloudflare / AWS WAF 等常见指纹）；③ 主链路速率限制探测（429 阈值 + 恢复窗口）；④ 结果写入 `target_fingerprint` / `service_profile`（recon 唯一输出总线） | P1 |
| REQ-162 | 目标类型分类本体（Taxonomy） | ① 定义四维标签 schema：架构模式（单 LLM / ReAct Agent / Multi-Agent / RAG / MCP-Connected / 混合）、通信协议（REST / WebSocket / SSE / MCP(stdio·SSE) / gRPC）、输入模态（纯文本 / 多模态 / 文件上传 / 代码执行）、认证方式（无 / API Key / OAuth2 / Session Cookie）；② 节点为**多标签 + 分组件置信度**（IC-1）；③ 本体落在 `surface_graph`（REQ-150）内，单值视图仅为兼容派生（W5 删除）；④ 识别失败有 `fallback_labels` 兜底 | P1 |
| REQ-163 | RoE 授权文件与强制边界 | ① 支持 `--roe-file` 加载授权文件（目标清单 + 授权时间窗 + 授权编号）；② `--require-roe` 时缺失/失效/越窗即**启动期拒绝**（满足 `R-ROE-1`）；③ **默认行为不改变**（未提供 `--roe-file` 时沿用现状：空名单 WARNING 留痕）；④ 授权时间窗外禁止发起攻击流量（涉及 R-S1） | P0 |
| REQ-164 | 成功判定分层 L1–L4 + 语义 Scorer | ① 定义四层：L1 防护绕过 / L2 有害输出 / L3 目标达成 / L4 影响确认；② 新增 `ToolExecutionScorer`（判定 Agent 是否执行非预期工具调用）与 `RetrievalPoisoningScorer`（判定 RAG 是否返回投毒内容），二者均为 PyRIT `TrueFalseScorer` 子类（C1/R-NATIVE-3）；③ 各组件声明关注层级（MCP→L3、通用 LLM→L2）；④ 层级写入 `ctx.attack_success_levels`，报告分列；⑤ **L1–L4 为附加维度，不改变 success 二值的分子/分母**（`confirmed_asr` 不因此下降） | P0 |
| REQ-165 | 证据不可否认性补强 | ① 证据文件产出 **SHA-256 打包哈希清单**（`evidence_manifest.sha256`，满足 `R-EVID-1` / NFR-18）；② 攻击链 **Kill Chain 时间线**（事件 `ts` 取自 `ctx.event_log`，按时间线串联证据）；③ **PyRIT Memory 导出**（SQLite/JSON 归档入证据包，作为原始证据）；④ 证据 ID 生成由 SHA-1 改为 SHA-256 并在报告标注算法版本；⑤ 版本化快照复用 REQ-158 ④，不重复实现 | P0 |
| REQ-166 | 报告标准扩展 | ① 报告映射 **OWASP AI Testing Guide** 分层（Model / Implementation / System / Runtime）；② 报告含 **PTES 阶段结构**（Pre-engagement / Intelligence Gathering / Threat Modeling / Vulnerability Analysis / Exploitation / Post-Exploitation / Reporting）；③ 支持 **AI-SSCV** 评分；④ 作为 REQ-113 四段结构 + 现有 OWASP LLM/MITRE ATLAS/CVSS 映射的**增量 section**，不另立报告管线（C3） | P1 |
| REQ-167 | 多租户与并行会话隔离 | ① 提供运行级租户/操作员标识（`--operator` / `--tenant`），写入 EventLog 与 memory labels；② 并发 run 的 PyRIT Memory 按 run 隔离，禁跨 run 污染；③ 提供会话注册/清理接口；④ 不改变单进程单 run 的默认行为 | P2 |
| REQ-168 | 部署形态扩展 | ① 登记 REST API / SDK / 容器化三类部署形态需求；② **实施须另立任务**；③ 若引入 Web 框架等新依赖，必须另行走 NEG-4 提案，本需求不授权加依赖 | P2 |
| REQ-169 | 审计防篡改与操作员身份 | ① EventLog 升级为**哈希链**（每条含前序哈希，满足 `R-AUDIT-1` / NFR-17）；② 提供离线校验入口（检出篡改）；③ 记录 `operator` 身份（who/when/what/why 完整）；④ 仍满足 I12（EventLog 为唯一派生源） | P1 |
| REQ-170 | 熔断与瞬态故障弹性 | ① 目标 5xx/限流触发熔断，策略可配（暂停 / 降速 / 终止）；② 客户端 5xx 重试（退避 + jitter，尊重 `defaults.yaml`）；③ 接线 `ctx._circuit_breaker_states`（消除 stub）；④ 熔断决策写入 `ctx.orchestration_log` + EventLog | P1 |
| REQ-171 | 运行期人工干预（HITL） | ① 支持运行中暂停/恢复；② 支持手动注入 seed；③ 支持策略覆盖钩子（人工指令优先级高于自主决策，NFR-10）；④ 全部动作写入 EventLog；⑤ 默认关闭，不影响非交互运行 | P2 |

### 第九章 D2：非功能需求

| ID | 维度 | 标准 |
|----|------|------|
| NFR-17 | 审计可验证性 | EventLog 每条事件含前序哈希（哈希链），提供离线校验入口；篡改可被检出 |
| NFR-18 | 证据包可离线校验 | 报告产出含 `evidence_manifest.sha256`，逐文件哈希可离线复算（不依赖网络，对齐 NFR-7） |
| NFR-19 | 交付可复现 | 容器化构建可复现（依赖锁定 + 固定基础镜像），构建产物与本地一致 |

### 第九章 D3：本组需求状态追踪

| 需求组 | 状态 | 备注 |
|--------|------|------|
| REQ-160~171（用户诉求闭合） | ⚡ 实施中 | 依据 CP-002。**已实施**：REQ-160 ①②③；REQ-161 ①②③（`recon.graphql_probe` + `recon.waf_detector`，WAF 接入 `recon.burp_parser._extract_fingerprint`）；REQ-162（`recon.taxonomy` + `core.phases.recon._attach_taxonomy`）；REQ-163（`core.roe` + `--roe-file/--require-roe`）；**REQ-164 ①②③④⑤**；REQ-165（`report.evidence_manifest` + 报告接线）；REQ-166（`report.standards` + `standards_alignment.md`）；**REQ-167**（`--tenant`/`--operator` 并入 memory labels）；**REQ-169**（`core.events` 哈希链 + `--operator` + `verify_event_log`）；**REQ-170**（`core.resilience` 熔断 + 5xx 退避重试，接线 `recon.target_wrapper` 4 个构造点并消费 `ctx._circuit_breaker_states`）；REQ-152（`assess.impact` + `tools/oob_listener`）；**REQ-156**（`targets/mock/` 5 靶标 + `tools.mock_range --check` + `tests/golden/golden_set.yaml` 量化门禁）。按 R-H1 摘除 5 桩声明。**待实施**：REQ-160 ④（BL-032）；REQ-161 GraphQL 接线（BL-033）+ MCP 接线（BL-029）；REQ-168（REST/SDK/容器，须 NEG-4 提案）；REQ-171（HITL）。关卡：BL-029~035（含 BL-035 跨模型审查待办） |
| NFR-17~19 | 🟡 规约已登记 | 随对应 REQ 实施同步验证 |

> **红线**：`R-ROE-1` / `R-EVID-1` / `R-AUDIT-1` 登记于 `40-GUARDRAILS.md` 1J-COMPLIANCE（检查器随实施落地，未实施前不产生门禁效力）。

---

## 第十章：需求追踪 [sid:20-ch10]

**状态登记表**（2026-09-09 v2.0 精简重构）：

| 需求组 | 状态 | 备注 |
|--------|------|------|
| REQ-001 ~ REQ-008（P0 主链路） | ✅ implemented | 六阶段链路完整，Best-of-N 已集成 |
| REQ-101 ~ REQ-108（P1 支撑） | ✅ implemented | 配置体系、dry-run、ASR 先验矩阵均已在位 |
| REQ-109 ~ REQ-113（考域覆盖） | ⚡ partial | exam_mode (REQ-112) 已实现；A2A 执行 (REQ-109) 种子就绪待验证 |
| REQ-114 ~ REQ-126（P0-NEW + P0-EXAM） | ✅ implemented | 2026-09-08 修复/考试就绪 |
| REQ-127 ~ REQ-134（Web 攻击层） | ✅ implemented | 认证/API Gateway/审计逃逸/编排器 |
| REQ-135 ~ REQ-137（自主决策） | 🟡 架构设计完成 | 决策引擎框架 + Recon + ARM/Assess/Report |
| REQ-138 ~ REQ-143 + REQ-159（文件上传 + 代码文档同步） | ✅ implemented | 通用文件上传执行器 + CLI 参数 + 流水线集成 + 39 测试 + 文档同步 |
| REQ-144 ~ REQ-146（跨模型审查） | 🟡 规约已登记 | 多模型并行 / 一致性指标 / 分级仲裁 |
| NFR-1 ~ NFR-8 | ✅ implemented | 非功能需求全部达成 |
| NFR-9 ~ NFR-12（决策非功能） | 🟡 架构设计完成 | 决策透明度/人工覆盖/稳定性/可测试性 |
| NFR-13（ASR 度量口径） | 🟡 规约已登记 | reported/confirmed 双口径 + `target_asr` 锚点（defaults.yaml 已落盘）；报告双列分列待实施 |
| NFR-14 ~ NFR-16（审查非功能） | 🟡 规约已登记 | 审查时效/存储/降级能力 |
| REQ-148 ~ REQ-158（目标架构 v4.0） | ⚡ W0 已实施 | CP-001 已批准（代录入待追认）；W0-4~W0-8 完成（EventLog 埋点 / ctx 四字段 / Registry 骨架 / R-EVENT-1 护栏 / 终端接入）；剩余 W1~W5 |
| REQ-160 ~ REQ-171（用户诉求差距闭合） | 🟡 规约已登记 | CP-002；含 NFR-17~19 与红线 R-ROE-1/R-EVID-1/R-AUDIT-1；按执行计划波次实施 |

- 活跃需求（待实现）：**REQ-109** A2A 执行层落地（种子已有，需验证编排进升级链）；**REQ-148~158** 目标架构 v4.0 六大抽象（待 CP-001 批准）；
- 本表为需求登记 SSOT；历史追踪文档 `requirement_traceability_matrix.md` 已于 2026-09-06 删除（D-09 债务消除）。
- **ID 唯一性自检**（每次新增需求后必跑，防止再次出现 REQ-144 重号）：

```bash
python -c "import re,collections,pathlib;rows=re.findall(r'^\|\s*(REQ-\d+)\s*\|',pathlib.Path('docs/specs/20-REQUIREMENTS.md').read_text(encoding='utf-8'),re.M);print('dups:',[k for k,v in collections.Counter(rows).items() if v>1] or 'none')"
```

> 期望输出 `dups: none`。同一命令可推广到 R-*/NFR-*/NEG-*（把正则中的 `REQ-` 换成对应前缀）。

---

---

> **版本史**：不再于正文维护（文档纪律 D3）——`git log -- docs/specs/20-REQUIREMENTS.md`
