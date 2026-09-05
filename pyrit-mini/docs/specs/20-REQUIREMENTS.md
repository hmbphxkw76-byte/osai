# 20 — 需求与规格层：做什么（Requirements & Specifications）

> **文档层级**：L2 / 五层规约金字塔第三层
> **效力**：本项目"做什么"的唯一登记处。**未登记于此的需求 = 不存在**。AI 不得实现未登记需求（宪法 C6）。
> **格式**：每条需求有 ID、一句话陈述、可勾选的验收标准（DoD）。验收标准是任务完成的**唯一**判据。
> **版本**：v1.2（2026-09-05 初版；同日 REV-01/REV-02 修正；版本记录见文末）

---

## 第一章：需求分级

| 级别 | 定义 | 变更门槛 |
|------|------|---------|
| **P0** | ASR 主链路：Burp 目标 → 攻击 → 评分 → 证据。任何 P0 回归 = 发布阻断 | 修改需 change-proposal + 宪法级评审 |
| **P1** | 支撑能力：报告格式、多 endpoint、配置体系、可观测性、考域覆盖（REV-02 起） | 修改需规格变更（本文件 diff） |
| **P2** | 体验与优化：终端 UI、性能调优、文档 | 可经普通任务规格变更 |

## 第二章：P0 — ASR 主链路需求

> P0 的总验收标准（一条顶一切）：**对 `data/burp/` 下任一真实目标，`python main.py` 端到端运行后，`ctx.overall_asr` 为有效数值且 `evidence.total_attacks > 0`；若存在成功攻击（overall_asr > 0），每条成功必须附可复现 PoC；若 ASR = 0（目标确未攻破），须交付零成功证据链与失败分析——攻击未成功 ≠ 验收失败，证据链缺失才是（v1.1）。**

### REQ-001 Burp 目标接入

**陈述**：从 Burp 拦截文件构建可攻击的 PyRIT Target。

- [ ] `data/burp/*.txt`（请求+响应完整交互）被解析为 `ParsedBurpRequest`
- [ ] `{PROMPT}` 占位符按 4 策略启发式注入；`{CHAT_ID}` 会话占位符支持
- [ ] 目标不可达（402/503/连接失败）抛 `ConnectionError` 终止该 endpoint，不静默
- [ ] 非 Burp 路径（LiteLLM/API/浏览器）收敛进相同 ctx 数据契约
- 关联：guard `check_dry_run_available`（部分）；蓝图第五章

### REQ-002 目标能力侦察

**陈述**：被动/主动/深度三级探测产出 `target_fingerprint`，驱动下游武器化。

- [ ] 三级探测（被动关键词 → 3 主动探针 → 8 并行深探针）结果全部写入 fingerprint
- [ ] 模型族识别（90+ 精确型号映射）与 asr_priors.yaml key 对齐
- [ ] 检测到 MCP 能力时执行 JSON-RPC 枚举 + 工具安全分析 + 动态种子生成
- [ ] fingerprint 落盘 `recon_fingerprint.json` + `attack_surface_graph.json`

### REQ-003 武器化

**陈述**：种子按历史 ASR 排序，Converter 多路径构建，技术按能力路由。

- [ ] 种子加载支持能力自适应增补 / DoS 过滤 / 语言配比 / metadata 过滤
- [ ] UCB1 排序 + 零 ASR 剪枝（≥3 次尝试且 0%）+ OWASP 类别保底（不变量 I6）
- [ ] Converter 候选三级优先级（默认→OWASP 多数票→category 多数票），裁剪保底 4 路径
- [ ] 技术选择尊重 adversarial target 有无（无则剔除多轮技术）
- 注（v1.1）：本条的过滤/裁剪/剔除均为 **ASR 驱动的运营性种子选择**（保命中率与目标可用性），非 NEG-2 禁止的攻击端安全护栏（后者以安全为由削弱攻击）。判定特征相反：运营裁剪让攻击更准，安全护栏让攻击更弱。

### REQ-004 单轮攻击

**陈述**：PyRIT 原生 SequentialAttack 多路径独立执行，FIRST_SUCCESS 短路。

- [ ] 每种子×每 Converter = 1 条独立 PromptSendingAttack 子路径（不变量 I1）
- [ ] FIRST_SUCCESS 判定用 0-token 拒绝检测评分器（不变量 I2）
- [ ] 种子数>15 时降级为手动多路径循环（行为一致）
- [ ] 失败目标 Best-of-N（N 从 defaults.yaml 读取）——**REV-02 审计：当前 multi_turn_attacks.py 为返回空的 stub，本条为现行 P0 缺口（D-03），最高优先修复**

### REQ-005 多轮升级链

**陈述**：单轮 ASR<90% 触发 L1→L4 升级链，中间退出省 token。

- [ ] L1 四技术（red_teaming/crescendo/tap/pair）按先验优先级分批执行
- [ ] L1≥70% 跳过 L2-L4；L2≥80% 跳过 L3-L4（不变量 I4）
- [ ] 仅失败目标进入下一级，上限 max(10, max_seeds//3)
- [ ] 升级结果回填 converter 标签，编入 orchestration_log

### REQ-006 级联评分与 ASR 统计

**陈述**：T0→J1→J2→J3 级联评分 + Wilson CI + 双 Judge 统计。

- [ ] T0 0-token 预过滤链先于一切 LLM 调用（不变量 I3）
- [ ] J1 高置信跳过 J2；J1/J2 分歧按配置聚合（默认 OR，ADR-001）
- [ ] ASR = successes/total_decided；Wilson 95% CI；Cohen's Kappa 输出
- [ ] T0 准确率自监控（与 Judge 真值对照的 FPR/FNR）
- [ ] 种子/Converter/GCG 后缀三级 ASR 历史写回（不变量 I7）

### REQ-007 证据与报告

**陈述**：完整证据链 + 多格式报告，成功攻击可复现。

- [ ] 证据全字段非空（jailbreak_prompt/harmful_output/conversation/scorer_results/converter_log/arxiv_reference/validation_runs/testing_conditions）
- [ ] 报告含 PyRIT 原生输出（不变量 I9）+ MD 分层 + SARIF + PoC（PyRIT 原生类，端点环境变量化）
- [ ] OWASP 三标准（Web/LLM/ASI）+ MITRE ATLAS 映射
- [ ] orchestration_log 覆盖全部 6 阶段并渲染进报告

### REQ-008 多 endpoint 联合攻击

**陈述**：多 Burp 目标能力指纹排序后逐个深度攻击，汇总联合 ASR。

- [ ] 0 网络请求静态预排序（MCP>function_calling>RAG>…>chat）
- [ ] 每 endpoint 独立子目录 + 独立 SQLite + `exclude_shared=True` 中间清理（不变量 I10）
- [ ] 全局统计计数器每 endpoint 循环开始处重置
- [ ] 联合 ASR = 1-∏(1-ASRᵢ) 落盘 `joint_asr_report.json`

## 第三章：P1 — 支撑需求（摘要）

| ID | 陈述 | 关键验收 |
|----|------|---------|
| REQ-101 | 四级配置体系 | CLI > config-file > defaults > 硬编码；嵌套 section 平铺；`--config-file` 值真实到达执行模块（R9 零断点） |
| REQ-102 | 战役预设 | 4 个 campaign yaml 可用且与文档宣称一致 |
| REQ-103 | 分阶段调试 | `--stage` 六值各自可独立运行并在该阶段后停止 |
| REQ-104 | dry-run | 0 token 走通六阶段数据流，产出（可为空的）报告 |
| REQ-105 | ASR 先验矩阵 | asr_priors.yaml 被 arm/strike 消费；运行后 EMA 回写至 **asr_history.json**（不变量 I7，assess 唯一写者）；asr_priors.yaml 仅限人工修订，禁止运行时写入（防双簿） |
| REQ-106 | 攻击面场景路由 | 分类→technique_tags→TextAdaptive 过滤；无标签时全量技术 |
| REQ-107 | 资源生命周期 | LIFO + 幂等清理 + 共享/专属分离 + 信号优雅退出 |
| REQ-108 | 架构守卫 | 18 项检查可用（清单以 guard 实现为准，规约引用登记见 40-GUARDRAILS 1D 登记簿）；BLOCKING 违规阻断 git 提交 |

## 第 3A 章：P1 — 考域覆盖需求（REV-02 登记，对齐 OffSec AI-300/OSAI 考纲与 AI 红队最佳实践）

> 背景：项目第二使命为 OSAI/AI-300 备考武器化（24h 实战 + 报告）。考纲 11 模块与本项目的映射及差距分析见 `specs/50-ROADMAP.md` 第二章。本登记只收"进入代码的做"的部分；映射本身不入代码。

| ID | 陈述 | 关键验收 | 考纲模块 |
|----|------|---------|---------|
| REQ-109 | A2A/多智能体攻击执行 | 现状仅有 ma_* 种子（5 条）；执行层须支持至少 cross-agent injection / agent impersonation / workflow corruption 三类攻击编排进升级链（多轮技术，尊重 adversarial target 有无） | M4 Multi-Agent & A2A |
| REQ-110 | Embedding 攻击落地 | strike/embedding_inversion.py（8.4KB）实装或按蓝图 Q4 决策树裁决：属 PyRIT 域则实装（信息抽取/倒置两类），域外则以外部工具形态接入并回填数据；**禁止维持 stub 编排状态（R-H1）** | M6 Embeddings |
| REQ-111 | 供应链侦察 | 仅报告侦察建议（SBOM/依赖/模型权重来源检查项清单，写入 fingerprint → report 渲染）；**不引入新运行时依赖（NEG-4 约束）** | M8 Supply Chain |
| REQ-112 | 考试模式 campaign | `config/campaigns/exam_mode.yaml`：单 endpoint 快速链路（recon→strike→report 精简路径）+ token 预算上限 + 证据优先策略（evidence/ 实时落盘）+ 时间盒超时；与 REQ-102 战役预设同机制 |
| REQ-113 | OffSec 风格报告 | 报告生成器输出四段结构：executive summary / findings（含风险等级 CVSS 类比 + OWASP LLM 2025 + MITRE ATLAS 映射）/ impact / remediation；作为现有 REQ-007 多格式报告的增量 section，不另立报告管线（C3） |

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

## 第五章：需求变更流程（防偏航核心）

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

## 第六章：负需求（禁止清单）

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

## 第七章：需求追踪

**状态登记表**（v1.1 建立；任务 verified 时回填本表，task-spec 与任务汇报同步引用）：

| 需求组 | 状态 | 备注 |
|--------|------|------|
| REQ-001 ~ REQ-008（P0 主链路） | 待核验 | 规约登记时未附代码库；REV-02 已完成文件级审计（@0b8e28c）：六阶段链路吻合、**REQ-004 Best-of-N 现为 stub 缺口**；逐条运行时核验待首个代码会话（BL-001） |
| REQ-101 ~ REQ-108（P1 支撑） | 待核验 | 同上 |
| REQ-109 ~ REQ-113（考域覆盖） | 待实现 | REV-02 登记；实现顺序见 50-ROADMAP 第四章 |
| NFR-1 ~ NFR-7 | 待核验 | 同上；NFR-7 为 REV-02 新增 |

- 状态取值：`待核验`（初始态）/ `implemented` / `partial` / `planned` / `待实现`（REV-02 新增，指已登记未开工）；
- 历史追踪文档 `docs/requirement_traceability_matrix.md` 降为存档，不再更新；新追踪以本表为准（D-09 迁移项）。

---

## 版本记录

| 版本 | 日期 | 变更摘要 | 批准 |
|------|------|---------|------|
| v1.0 | 2026-09-05 | 初版：P0/P1/P2 分级、REQ-001~008、REQ-101~108、NFR-1~6、NEG-1~6、变更流程 | — |
| v1.1 | 2026-09-05 | REV-01：① P0 总验收改条件式（ASR=0 须交付零成功证据链而非判失败）；② REQ-003 加运营裁剪注 + NEG-2 措辞收窄，消解两者文本冲突；③ REQ-105 明确 EMA 回写目标为 asr_history.json，asr_priors 仅人工修订（消双簿）；④ NFR-6 加 PyRIT 1.0.1 兼容硬边界（BL-002）；⑤ REQ-108 交叉引用 40-G 1D 登记簿；⑥ 第七章状态登记表实例化（初始态：待核验） | 用户会话批准 |
| v1.2 | 2026-09-05 | REV-02：① 新增第 3A 章考域覆盖需求 REQ-109~113（A2A 执行、embedding 落地、供应链侦察、exam_mode campaign、OffSec 风格报告，对齐 AI-300 考纲）；② 新增 NFR-7 离线可检与依赖锁定；③ 新增 NEG-7 运行时产物禁入 git；④ REQ-004 标注 Best-of-N stub 为现行 P0 缺口；⑤ NEG-1 范围扩至 D-01~D-16；⑥ 状态登记表更新（新增待实现态与 REV-02 审计备注） | 用户会话批准 |
