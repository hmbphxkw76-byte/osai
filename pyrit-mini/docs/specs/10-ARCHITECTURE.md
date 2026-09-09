# 10 — 架构与设计层：技术蓝图（Architecture Blueprint）

> **文档层级**：L1 / 五层规约金字塔第二层
> **效力**：定义系统的目标架构、模块边界、数据契约与架构不变量。任何代码变更必须能在本蓝图上"落点"——落不了点的变更需要先走 change-proposal 修改蓝图。
> **读者**：实施任务前的 AI（必读相关章节）、评审 diff 的人工/AI。
> **版本**：v2.3（2026-09-09 合并 45-DATA-FLOW-INTEGRITY.md：Phase 字段契约 4.2 + 数据传递规则 4.3；债务簿从 16 项瘦身至 2 项；章节编号修复；Glue→Web 攻击层重命名）
> **归档文件**：`45-DATA-FLOW-INTEGRITY.md` 已合并入本文件的第四章，原文档不再独立维护（其验证工具链 `tools/data_flow_validator.py` + `tools/data_flow_hooks.py` + `tests/test_data_flow_integrity.py` 仍正常运行）

---

## 第一章：系统全景

```
输入契约                    六阶段攻击流水线                          输出契约
──────────                ──────────────────────                    ──────────
data/burp/*.txt    ──►     ① RECON    侦察/指纹/Target 构建    ──►    outputs/strike_*/
(Burp 完整 HTTP            ② ARM      种子/Converter/技术             ├── report*.md / .html
 交互，含响应)              ③ STRIKE   单轮多路径 FIRST_SUCCESS         ├── report.sarif
.env 三角色 LLM            ④ ESCALATE L1→L4 升级链                    ├── evidence/ + poc/
 config/defaults.yaml      ⑤ ASSESS   T0→J1→J2 级联评分                ├── native_output/
 config/asr_priors.yaml    ⑥ REPORT   证据/多格式报告                   └── db/pyrit.db
 data/seeds/*.prompt
config/burp/*.txt                 ← Burp 目标文件
config/profiles/asset_index.yaml  ← 统一资产索引
```

**使命映射**（见宪法第 0 条）：蓝图的每个部分都服务于"Burp 黑盒目标 ASR 最大化"。判断一个架构改动是否正当的唯一标准：它是否让 ①-⑥ 链路对 Burp 目标打出更高 ASR、或让证据链更可复现。

### 1.1 阶段词汇映射

| 惯用口径 | 架构落点 | 备注 |
|---------|---------|------|
| recon / 侦察 | ① RECON | recon/ 模块；target_fingerprint 是对下游的唯一输出总线 |
| arm / 武器化 | ② ARM | arm/ 模块 |
| strike / 打击 / 单轮 | ③ STRIKE | strike/ 模块 |
| escalate / 升级链 | ④ ESCALATE | strike/ 模块内部逻辑，非独立模块 |
| 评分 / judge / ASR 统计 | ⑤ ASSESS | assess/ 模块（post-hoc；唯一允许 LLM Judge 的位置） |
| report / 报告 | ⑥ REPORT | report/ 模块 |
| **evidence / 证据** | **输出契约，非阶段** | 由 ASSESS + REPORT 产出；**禁止新建 evidence/ 模块** |

## 第二章：分层与依赖规则

### 2.1 模块分层

| 层 | 模块 | 职责一句话 |
|----|------|-----------|
| 编排层 | `main.py` (根目录) | 六阶段顺序编排 + 多 endpoint 循环；**不得包含业务逻辑** |
| 核心层 | `core/` | 配置解析（唯一默认值定义地）、PipelineContext；**禁止带 `__main__`** |
| 阶段层 | `recon/ arm/ strike/ assess/ report/` | 各攻击阶段的实现；彼此只通过 PipelineContext 交接 |
| 工具层 | `tools/` | CLI 开发/运维工具（宪法守卫、hooks 安装）；**所有带 `__main__` 的脚本必须放在此处** |
| 支撑层 | `utils/` | 终端展示、日志、资源清理 |
| 数据层 | `data/` + `config/` | 种子、评分器 rubric、ASR 先验、defaults（**全部为声明式资产**） |

### 2.2 依赖方向矩阵

| 依赖方 ↓ 被依赖方 → | core | recon | arm | strike | assess | report | utils | data(config) |
|---|---|---|---|---|---|---|---|---|
| main.py | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | — |
| core/ | — | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | 读写 defaults.yaml |
| recon/ | ✓（context） | 内部 | ✗ | ✗ | ✗* | ✗ | ✓ | 只读 |
| arm/ | ✓ | ✗ | 内部 | ✗ | ✗ | ✗ | ✗ | 只读 asr_priors；读 asr_history |
| strike/ | ✓ | ✗ | ✓ | 内部 | ✓** | ✗ | ✓ | 只读 |
| assess/ | ✓ | ✗ | ✗ | ✗ | 内部 | ✗ | ✗ | 读写 asr_history |
| report/ | ✓ | ✗ | ✗ | ✗ | ✗ | 内部 | ✗ | 只读 |
| utils/ | ✓（context 类型） | ✗ | ✗ | ✗ | ✗ | ✗ | 内部 | 只读 |

\* recon/target_router 调 `assess.scorer.validate_scoring_target_capabilities` —— 已登记债务 D-04。
\** strike → assess 仅限 `precompute_outcomes_async`（升级前预评分），不得扩大。

**硬规则**：
1. 阶段层模块之间（recon/arm/strike/assess/report）**只准通过 PipelineContext 字段交接数据**，禁止直接 import 对方实现（表内已标注的既存例外除外，且例外只减不增）。
2. `core/context.py` 是唯一被全员依赖的枢纽；`core/config.py` 是唯一允许定义参数默认值的模块。
3. 循环导入的合法解法只有三种：函数内延迟导入 / TYPE_CHECKING / 合并到同一模块（拆分后 re-export 属于债务，不再新增）。

## 第三章：PyRIT 原生判定决策树

写新能力前的强制四问（对应宪法 C1）：

```
Q1: PyRIT 1.0.1 有现成组件吗？
    ├─ 有 → 直接用，结束
    └─ 无 → Q2: 能用"包装原生组件"实现吗？
             ├─ 能 → Enhancement wrapper，结束
             └─ 不能 → Q3: 属于 Glue / Output 三类自研范畴吗？
                      ├─ 是 → 实现，结束
                      └─ 否 → STOP-REPORT（C11）
```

**PyRIT 域边界**：`与 LLM 的 prompt 交互与响应评估`；域外问题只能以外部工具形态接入。

---

## 第四章：PipelineContext 数据契约

### 4.1 字段唯一写者原则

| 字段 | 唯一写者 | 读者 | 备注 |
|------|---------|------|------|
| `args` / `output_dir` | main | 全部 | 创建后只读 |
| `parsed_request`（含 target_fingerprint） | recon | arm/strike/report | fingerprint 是 recon 对下游的总线 |
| `objective_target` / `multi_turn_target` | recon | strike / cleanup | per-endpoint，循环内须重置 |
| `adversarial_target` / `scoring_target` | recon | strike/assess | **跨 endpoint 共享** |
| `seeds` / `techniques` / `converter_map` | arm | strike | — |
| `attack_results` | strike（含 escalate 追加） | assess/report | `{technique: [AttackResult]}` |
| `asr_per_technique` / `overall_asr` / `wilson_ci` / `dual_judge_stats` | assess | report / main | — |
| `orchestration_log` | 各阶段（自己追加自己的条目） | report | 每阶段至少一条 |

### 4.2 Phase 字段契约（BLOCKING）

| 阶段 | 字段 | 类型 | 约束 |
|------|------|------|------|
| **Recon** | `ctx.objective_target` | Target | not_none |
| | `ctx.parsed_request.target_fingerprint` | dict | not_empty |
| | `ctx.service_profile` | dict | not_empty |
| | `ctx.orchestration_log` | list | append("recon") |
| **ARM** | `ctx.seeds` | list | len > 0 |
| | `ctx.techniques` | list | len > 0 |
| | `ctx.converter_map` | dict | len > 0 |
| | `ctx.orchestration_log` | list | append("arm") |
| **Strike** | `ctx.attack_results` | dict | len > 0 |
| | `ctx.orchestration_log` | list | append("strike") |
| **Assess** | `ctx.asr_per_technique` | dict | len > 0 |
| | `ctx.overall_asr` | float | [0, 100] |
| | `ctx.dual_judge_stats` | dict | not_none |
| | `ctx.wilson_ci` | tuple | len == 2 |
| | `ctx.orchestration_log` | list | append("assess") |
| **Report** | `ctx.evidence_collection` | EvidenceCollection | not_none |
| | `ctx.orchestration_log` | list | append("report") |

### 4.3 数据传递规则（BLOCKING）

| 规则 | 说明 |
|------|------|
| Recon→ARM | `ctx.objective_target` 非空 + `ctx.service_profile` 非空 |
| ARM→Strike | `ctx.seeds` / `ctx.techniques` / `ctx.converter_map` 均非空 |
| Strike→Assess | `ctx.attack_results` 包含所有技术的攻击结果 |
| Assess→Report | `ctx.asr_per_technique` 覆盖所有攻击技术 + `ctx.overall_asr` ∈ [0,100] |
| 一致性 | `converter_map` 的键覆盖 `techniques` 中所有技术 |
| 一致性 | `ctx.attack_results` 中的每种技术都出现在 `ctx.asr_per_technique` 中 |

**新增 ctx 字段的义务**：在本表登记 + 在 20-REQUIREMENTS 对应需求验收标准中体现。

## 第五章：Burp 目标数据流（输入契约）

**合法输入**：`data/burp/*.txt`，Burp 保存的完整 HTTP 交互（请求 + 响应）。解析器承诺：

1. `{PROMPT}` 占位符：解析器启发式注入（4 策略）；下游一切攻击注入经由 PyRIT 原生 `HTTPTarget` 替换，**任何模块不得自行拼接 prompt 进 body**。会话状态 (chat_id) 由 `ChatIdStateManager` 外部管理，不侵入 Target。
2. 响应提取：回调选择优先级 = 已探测 JSON 路径 → SSE → 自适应 JSON；新增提取逻辑必须挂入 `_select_callback` 优先级链，不得旁路。
3. `target_fingerprint` 是 recon 的唯一输出总线：能力/模型族/MCP 工具/端口/OpenAPI/系统提示泄露全部写入此字典，禁止另立平行结构。
4. 目标不可达（402/503/连接失败）→ `ConnectionError` 终止该 endpoint，禁止静默降级为"跳过"。

**非 Burp 路径**（LiteLLM/API 直连/浏览器）为兼容分支，只准收敛进与 Burp 相同的 ctx 数据契约（`_ensure_parsed_request_for_api_path` 模式），禁止平行数据流。

## 第六章：ASR 架构不变量（Invariants）

以下不变量任何变更不得破坏（均可由 guard 或 dry-run 检查）：

| # | 不变量 | 依据 |
|---|--------|------|
| I1 | 每 `ConverterConfiguration` 恰 1 converter；多路径 = SequentialAttack 独立子路径 + FIRST_SUCCESS | arXiv:2307.15043 / 2407.01232 |
| I2 | 攻击执行路径评分器零 LLM token（0-token 拒绝检测）；LLM Judge 只出现在 post-hoc assess | R6 §6.2 |
| I3 | 评分级联序固定 T0→J1→J2→J3，禁止跳过 T0 直呼 LLM | arXiv:2402.04249 / 2308.07920 |
| I4 | 升级链触发 ASR<90%；中间退出检查点必须在 L1→L2 与 L2→L3 边界 | arXiv:2406.12609 |
| I5 | 三角色分离：objective / adversarial / scoring target 相互独立，.env 配置 | R6 §6.5 |
| I6 | 种子排序 UCB1 + 类别多样性保底 + 零 ASR 剪枝（比例≤50%，每 OWASP 类保底 1） | arXiv:cs/0207052 |
| I7 | ASR 反馈闭环：**asr_history.json 是运行时观测唯一账本**（种子/converter/GCG 后缀三级，EMA α=0.3；assess 唯一写者，arm 读取）；**asr_priors.yaml 是人工先验唯一源，禁止运行时写入**；arm 读取次序：history 命中 > priors 兜底 | 设计决策 |
| I8 | 联合 ASR = 1 - ∏(1-ASRᵢ)，多 endpoint 串行深度攻击 | arXiv:2310.08419 / 2302.12173 |
| I9 | 报告必须含 PyRIT 原生输出（pyrit.output）+ 证据全字段非空 | R2 / R6 §6.6 |
| I10 | 每 endpoint 独立 SQLite（WAL）+ Singleton 三步清除；共享 LLM target 跨 endpoint 复用 | R8 §8.1/8.3 |

## 第七章：决策记录（ADR 索引）

已固化的架构决策（变更需走 change-proposal）：

| ADR | 决策 | 摘要 |
|-----|------|------|
| ADR-001 | OR 聚合评分 | J1/J2 分歧默认 OR（ASR 最大化优先，假阳性 ~3-5% 可接受，v56 起可配置） |
| ADR-002 | GCG 用后缀池非梯度 | 黑盒场景无 logits，用静态池+LLM 变异+历史重排（arXiv:2310.04775） |
| ADR-003 | MCP 枚举旁路 HTTPTarget | JSON-RPC 结构化请求不适合 {PROMPT} 占位符机制，httpx 直发（唯一例外） |
| ADR-004 | 场景路由轻量化 | v60 起 synergy 只产出 technique_tags，种子/评分器选择回归 SSOT 配置 |
| ADR-005 | 升级链技术分四级 | L1 优先级分批（先验排序）→ L2-L4 全并行；仅失败目标进入下一级 |
| ADR-006 | 多 endpoint 串行 | 高价值优先（能力指纹排序）逐个深度攻击，不做并行（全局状态安全） |

## 第八章：架构债务登记簿（冻结区）

以下为已识别的**冻结债务**：日常任务禁止触碰（C3/C4），只能由专项任务（DEBT-xxx）消除。**只减不增**。2026-09-08 全面过度工程化清理后，仅余 2 项低优先级债务。

| ID | 债务 | 现状 | 消除方向 |
|----|------|------|---------|
| D-04 | recon → assess 跨层依赖 | target_router 调 assess.scorer 验证函数 | 验证函数移入 core 或 targets |
| D-16 | 工具链与资产卫生 | ① 依赖 `pyrit>=1.0.1` 未钉住（规约口径为 1.0.1）；② data/seeds/asr_history.json 运行时产物入库 | 钉 1.0.1；asr_history 迁 outputs/ 并入 .gitignore |

**新增债务的流程**：发现新双轨/越界 → 登记 backlog（一行）→ 评估后入本表。**禁止直接修**。

**已消除债务归档**（2026-09-06 ~ 2026-09-08）：
- D-01 assess 双轨 → judge_manager/score_pipeline/asr_manager/response_parser 合并家族已删除
- D-02 main/pipeline 镜像 → orchestrator.py 已删除，编排逻辑入 core/phases/
- D-03 stub 模块 → 未实现模块已从升级链摘除
- D-05 targets→recon → target_wrapper 已迁移至 recon/
- D-06 display→arm 越界 → display.py 已瘦身，不再导入 arm
- D-07 硬编码数据快照 → display.py 移除 _CONVERTER_ASR_LABEL
- D-08 无代码加载配置 → target_profiles.yaml 已删除
- D-09 规范冗余 → glue/ 目录已扁平化到 strike/
- D-10 escalation 三件 → 合并为 executor.py 内单一实现
- D-11 arm converter 三轨 → converter_selector.py 已清理死函数
- D-12 arm 种子排序双轨 → seed_ranker/seed_ranking 关系已理清
- D-13 data/代码污染 → 代码移出 data/ 层
- D-14 display.py 巨石 → 从 ~119KB 瘦身至 ~20KB
- D-15 judge 文件群 → judge_manager 已精简

---

## 第九章：PyRIT 原生攻击引擎架构（v1.6 增补）

> **目的**：明确 PyRIT 原生攻击组件在本项目六阶段流水线中的落点，以及针对不同目标类型的最优攻击路径编排。考试期间此章作为架构速查。

### 9.1 PyRIT 原生攻击 → 阶段落点映射

| PyRIT 原生类 | 落点阶段 | 调用模式 | 考试优先级 |
|------|------|------|------|
| `PromptSendingAttack` | ④ STRIKE (Executor) | 批量多路径 FIRST_SUCCESS | ⭐⭐⭐⭐⭐ 首发必用 |
| `SkeletonKeyAttack` | ④ STRIKE (Native) | 单目标前缀注入（ASR 80-95%） | ⭐⭐⭐⭐ 通用绕过 |
| `CrescendoAttack` | ⑤ ESCALATE (L1) | 渐进式多轮（max_backtracks=10） | ⭐⭐⭐⭐ Agent/Multi-Agent |
| `TAPAttack` | ⑤ ESCALATE (L2) | 树状分支渗透（width=5, depth=3） | ⭐⭐⭐ 复杂边界 |
| `PAIRAttack` | ⑤ ESCALATE (L3) | 攻击者-Judge 配对迭代 | ⭐⭐⭐ 高价值目标 |
| `PromptConverter` | ③ ARM (Converter Chain) | 编码/翻译/混淆变换 | ⭐⭐⭐⭐ 绕过防御 |
| `SelfAskScorer` / `ContentClassifierScorer` | ⑥ ASSESS (T0) | 0-token 拒绝检测 | ⭐⭐⭐⭐⭐ 省 token |
| `AzureAISc contentScorer` | ⑥ ASSESS (J1/J2) | LLM Judge 深度评估 | ⭐⭐⭐ 最终判定 |

### 9.2 考试攻击路径决策树（按目标能力指纹分支）

```
recon 完成 → capability 指纹分支:
    │
    ├─ 通用 LLM (仅 chat)
    │   └─ PromptSendingAttack 多 Converter 路径 (FIRST_SUCCESS)
    │       └─ ASR<90% → SkeletonKeyAttack
    │
    ├─ Agent (function_calling / tool_use)
    │   ├─ SkeletonKeyAttack (工具劫持前缀)
    │   └─ CrescendoAttack (渐进式工具滥用)
    │
    ├─ Multi-Agent / A2A
    │   ├─ CrescendoAttack (agent 间信任渗透)
    │   └─ PAIRAttack (agent 身份欺骗)
    │
    ├─ RAG (retrieval_augmented)
    │   ├─ PromptSendingAttack (间接注入 via 知识库)
    │   └─ 检索污染链 (自定义序列)
    │
    ├─ MCP Server (model_context_protocol)
    │   ├─ 旁路 JSON-RPC 直发 (ADR-003)
    │   └─ 工具链利用 (mcp_tool_chaining/hijack)
    │
    └─ Embedding Model
        └─ 领域外工具接入回填 (embedding_inversion.py)
```

### 9.3 攻击路径 ASR 优化策略（PyRIT 攻击优势最大化）

> **原则**：PyRIT 的多路径 + FIRST_SUCCESS + Converter 多样性 = 考试 24h 内最高 ASR 产出

| 策略 | 实现方式 | ASR 提升 | Token 节省 |
|------|---------|---------|-----------|
| **多 Converter 并行** | 每种子×每 Converter = 1 条独立路径（不变量 I1） | +15-25% | — |
| **FIRST_SUCCESS 短路** | 首条成功立即停当前种子其他路径 | — | -40% |
| **0-token 预过滤** | T0 拒绝检测链先于一切 LLM（不变量 I2/I3） | — | -60% |
| **ASR 反馈闭环** | asr_history.json EMA α=0.3 种子排序 | +10-15% | -20% |
| **分层升级** | <90% 触发 L1→L4 按先验分批（ADR-005） | +20-30% | -30% |

### 9.4 考试快速攻击模板速查

> **用途**：考试期间快速选择预配置的攻击 profile。对应 `config/profiles/*.yaml` 四预设 + exam_mode。

| Campaign | 配置 | 适用目标 | 预计 ASR | Token 预算 |
|------|------|---------|---------|-----------|
| `exam_mode.yaml` (REQ-112) | 精简链路 + 证据优先 | 考试首选 | 最大化 | 受限（80% cap） |
| `deep_spectrum.yaml` | 全量技术 + 最大并行 | 高价值单一目标 | 最高 | 无限制 |
| `mcp_targeted.yaml` | MCP/Agent 技术优先 | Agent/MCP 目标 | 85-98% | 中等 |
| `quick_scan.yaml` | 仅 recon + 基础打击 | 首次侦察 / 时间紧迫 | 中等 | 最低 |
| `standard_redteam.yaml` | 均衡配置 | 标准红队评估 | 高 | 中等 |

---

## 版本记录

| 版本 | 日期 | 变更摘要 | 批准 |
|------|------|---------|------|
| v1.0 | 2026-09-05 | 初版：系统全景、分层与依赖矩阵、PyRIT 判定树、ctx 契约、Burp 数据流、不变量 I1-I10、ADR-001~006、债务簿 D-01~D-09 | — |
| v1.1 | 2026-09-05 | REV-01：① §1.1 阶段词汇映射表（统一 recon/arm/strike/report/evidence 口径，防凭空造阶段或模块）；② I7 明确 asr_history（运行时唯一账本）与 asr_priors（人工先验唯一源）的 SSOT 关系；③ 依赖矩阵补 arm 读取 asr_history、"—"图例；④ 版本记录机制 | 用户会话批准 |
| v1.2 | 2026-09-05 | REV-02 源码对齐（审计 @0b8e28c）：① 新登记债务 D-10~D-16（escalation 孪生、converter 三轨、seed 排序双轨、data/ 层代码污染、display 巨石、judge 文件群、工具链卫生）；② D-02/D-03 现状更新（main.py 87KB 巨石证实；Best-of-N stub 定性为 P0 缺口）；③ §1.1/§2.1 标注现状违例。架构本体（分层/契约/不变量/ADR）无变更 | 用户会话批准 |
| v1.3 | 2026-09-06 | REV-03 代码审计修正（remediation/audit-remediation.md）：① D-01 量化修正（合并家族实际 ~3354 行死代码）；② D-10 修正（非 9 字节孪生，实为\"门面+拆分\"三件 + 编码损坏）；③ D-11 修正（非纯粹三轨，实为死函数 + _PRIORITY_MAP 孪生）；④ D-12 修正（非孪生，实为拆分+re-export+双向 import） | — |
| v1.4 | 2026-09-06 | REV-04 D-13 消除：① data/asset_mapper.py → core/asset_mapper.py；② data/attack_surface_classifier.py → recon/attack_surface_classifier.py；③ data/scorer_selector.py 已删除；④ data/burp/ → config/targets/burp/；⑤ 全量更新 import 路径与文档引用；⑥ 4 测试文件路径同步更新 | 用户会话批准 |
| v1.5 | 2026-09-06 | REV-05 recon 违宪整改（按 00-CONSTITUTION 优先级全部解决）：① P0-01 能力检测三轨合一 — `_probe_capabilities` 内部委托给 `confidence_scorer.score_capability()` SSOT，关键词与正则模式从 capability_detector.py 迁移至 confidence_scorer.py（含 capability_detector 中 MCP/Agent/RAG/Embedding 的结构化模式），原 capability_detector 中 ~200 行重复关键词/正则代码删除；② P0-02 探测风暴裁剪（保留 ≤2 个核心同步探针，其余移异步）— 已完成于会话前期；③ P0-03 自定义 Target 废弃（JSONSafeHTTPTarget → PyRIT 原生 HTTPTarget + ChatIdStateManager）— 已完成于会话前期 | 用户会话批准 |
| v1.6 | 2026-09-06 | REV-06 AI-300 考试架构优化：① 新增第九章 PyRIT 原生攻击引擎架构（PyRIT→阶段落点映射 9.1、考试攻击路径决策树 9.2、ASR 优化策略 9.3、考试快速攻击模板速查 9.4）；② 架构本体（分层/契约/不变量/ADR）无变更 | 用户会话批准 |
| v1.7 | 2026-09-06 | REV-07 目录结构重构：① Burp 目标文件从 config/campaigns/targets/ 扁平化迁移至 config/targets/；② asset_index.yaml 从 config/campaigns/ 迁移至 config/profiles/ (固定参数集)；③ 4 Campaign 重命名清晰化 (rapid_recon→quick_scan, full_spectrum_max_asr→deep_spectrum, mcp_agent_targeted→mcp_targeted, standard_redteam 保留) 并迁移至 config/profiles/；④ 删除 config/campaigns/ 目录 | 用户会话批准 |
| v1.8 | 2026-09-06 | REV-08 消除命名冲突：① config/targets/ 重命名为 config/burp/ (区分代码 targets/ 适配层与 Burp 输入契约)；② 更新 core/config.py、core/scenario_router.py 路径引用 | 用户会话批准 |
| v1.9 | 2026-09-06 | REV-09 适配层重命名：① targets/ → adapters/ (精准描述 PyRIT 原生组件包装职责)；② 更新 recon/target_router.py import 路径 | 用户会话批准 |
| v2.0 | 2026-09-08 | REV-10 企业AI红队融合解决方案：① 新增Glue层架构（模块清单、架构原则、攻击类型映射、依赖拓扑）；② 更新分层表新增Glue层；③ 更新依赖方向矩阵新增glue行 | 用户会话批准 |
| v2.1 | 2026-09-08 | REV-11 过度工程化清理（黑盒可测性约束）：① 删除 vector_db_glue.py（向量DB SDK需直访，黑盒HTTP不可测试）；② 删除 fine_tuning_glue.py（需训练环境API，黑盒HTTP不可测试）；③ 精简 audit_evasion_glue.py 为仅日志注入（移除 SIEM/审计路径）；④ 同步化 enterprise_auth_glue.py；⑤ 更新 Glue 层架构图（3模块精简） | 用户会话批准 |
| v2.2 | 2026-09-08 | REV-12 全面过度工程化清理后债务簿瘦身：① 债务登记从 16 项（D-01~D-16）精简至 2 项（D-04/D-16）；② 已消除 14 项债务移至归档区（含 assess 双轨、display 巨石、escalation 三件、judge 文件群等）；③ 章节编号修复（原两个"九章"冲突→九章/十章）；④ Glue 层重命名为 Web 攻击层（目录扁平化对齐） | 用户会话批准 |
| v2.3 | 2026-09-09 | REV-13 合并 45-DATA-FLOW-INTEGRITY.md：① 第四章新增 Phase 字段契约（4.2）和数据传递规则（4.3）；② 数据流完整性验证工具链（DataFlowValidator/data_flow_hooks）保留在 tools/ 目录；③ 45-DATA-FLOW-INTEGRITY.md 标记为归档参见本文件 | 用户会话批准 |

---

## 第十章：Web 攻击层架构（v2.0 增补，原 Glue 层扁平化）

> **目的**：定义 Web 攻击模块的架构设计、模块职责、与 PyRIT 框架的集成方式。
> 2026-09-08 目录扁平化：glue/ 目录已合并到 strike/ 目录。

### 10.1 Web 攻击模块清单

| 模块 | 职责 | 专用工具 | PyRIT 集成 |
|------|------|---------|----------|
| `strike/auth_attacks.py` | 认证攻击（JWT/OAuth/Session） | PyJWT | HTTPTarget |
| `strike/web_attacks.py` | API Gateway 攻击（速率限制/请求走私/缓存投毒） | urllib.request | HTTPTarget |
| `strike/audit_evasion.py` | 审计逃逸（日志注入） | logging、base64 | HTTPTarget |
| `strike/web_orchestrator.py` | 统一编排器 | 上述所有 | HTTPTarget |

### 10.2 Web 攻击层架构原则

1. **PyRIT 原生优先**（宪法 C1）：所有攻击执行最终通过 PyRIT 的 `PromptSendingAttack` 和 `HTTPTarget` 完成
2. **专用工具辅助**：专用工具只用于 payload 生成和验证，不替代 PyRIT 核心功能
3. **延迟导入**：所有专用工具采用运行时 `try/except ImportError` 导入，避免硬依赖
4. **SSOT 合规**：统一由 `strike/web_orchestrator.py` 编排，避免双轨

### 10.3 Web 攻击类型映射

| 攻击类别 | 覆盖场景 | ASR 先验 | 学术依据 |
|---------|---------|---------|---------|
| 认证攻击 | JWT alg=none、RS256→HS256、kid 注入、OAuth Scope 提升 | 38.4% | arXiv:2402.19181 |
| API Gateway 攻击 | 速率限制测试、请求走私、缓存投毒 | 60-80% | OWASP API Top 10 |
| 审计逃逸攻击 | 日志注入（CRLF/ANSI/时间戳伪造） | 70-90% | OWASP Log Injection |

> **注意**：向量 DB 投毒和微调后门注入需直接 SDK 访问或训练环境 API，不在黑盒 HTTP 目标测试范围内。相关攻击向量通过间接注入 seed 覆盖。

### 10.4 Web 攻击层依赖拓扑

```
web_orchestrator.py (统一入口)
        │
        ├── auth_attacks.py ← PyJWT（可选）
        ├── web_attacks.py ← urllib.request（标准库）
        └── audit_evasion.py ← logging（标准库）
        
所有模块共享：
- pyrit.prompt_target.HTTPTarget（原生）
- pyrit.executor.attack.PromptSendingAttack（原生）
```

---

## 第十一章：全链路自主决策引擎架构（v2.4 增补）

> **目的**：定义覆盖 Recon→ARM→Strike→Assess→Report 全链路的自主决策引擎架构，明确各阶段决策点、决策依赖与数据流契约。
> **详细规约**：见 `docs/specs/55-ATTACK-GAP-CLOSURE.md` 第九章。

### 11.1 决策引擎在架构分层中的位置

```
┌─────────────────────────────────────────────────────────────────┐
│                        编排层 (main.py)                         │
├─────────────────────────────────────────────────────────────────┤
│  ┌───────────────────────────────────────────────────────────┐  │
│  │              决策引擎层 (新增)                             │  │
│  │  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐        │  │
│  │  │  Recon  │ │   ARM   │ │ Strike  │ │ Assess  │        │  │
│  │  │ Decision│ │ Decision│ │ Decision│ │ Decision│        │  │
│  │  └────┬────┘ └────┬────┘ └────┬────┘ └────┬────┘        │  │
│  │       │           │           │           │              │  │
│  │       └───────────┴─────┬─────┴───────────┘              │  │
│  │                         │                                 │  │
│  │                         ▼                                 │  │
│  │              ┌─────────────────────┐                      │  │
│  │              │  Decision Dependency │                      │  │
│  │              │      Engine          │                      │  │
│  │              │  (ASR Tracker +      │                      │  │
│  │              │   Capability Registry│                      │  │
│  │              │   + Budget Manager)  │                      │  │
│  │              └─────────────────────┘                      │  │
│  └───────────────────────────────────────────────────────────┘  │
├─────────────────────────────────────────────────────────────────┤
│              阶段层 (recon/ arm/ strike/ assess/ report/)      │
├─────────────────────────────────────────────────────────────────┤
│              核心层 (core/) + 工具层 (tools/)                   │
└─────────────────────────────────────────────────────────────────┘
```

### 11.2 决策点与 PipelineContext 字段契约

| 阶段 | 决策函数 | 读取 ctx 字段 | 写入 ctx 字段 |
|------|----------|--------------|--------------|
| Recon | `determine_probe_strategy()` | `args.budget`, `target_info` | `ctx.probe_level`, `ctx.stealth_config` |
| ARM | `determine_armament_strategy()` | `ctx.capabilities`, `ctx.service_profile` | `ctx.seeds`, `ctx.techniques`, `ctx.converter_map` |
| Strike | `_run_advanced_attacks_phase()` ✅ | `ctx.current_asr`, `ctx.capabilities` | `ctx.advanced_attack_results` |
| Assess | `determine_assessment_strategy()` | `ctx.attack_results` | `ctx.evidence_level`, `ctx.assess_mode` |
| Report | `determine_report_strategy()` | `ctx.evidence_collection`, `args.output_format` | `ctx.report_format`, `ctx.detail_level` |

### 11.3 决策依赖引擎核心组件

| 组件 | 职责 | 数据来源 | 消费者 |
|------|------|----------|--------|
| **ASR Tracker** | 实时追踪 ASR 变化趋势 | `ctx.overall_asr`, `ctx.asr_per_technique` | 所有决策函数 |
| **Capability Registry** | 维护目标能力指纹 | `ctx.service_profile`, `ctx.capabilities` | ARM + Strike 决策 |
| **Budget Manager** | 监控 token/time 消耗 | `ctx.orchestration_log` | 所有决策函数 |
| **Timing Analyzer** | 分析响应延迟模式 | `ctx.timing_metadata` | Recon + Assess 决策 |

### 11.4 决策触发条件与反馈闭环

```
Phase N 执行完成
      │
      ▼
┌─────────────────┐
│ ASR 变化检测    │ ← 比较 ASR_new vs ASR_old
└────────┬────────┘
         │
    ┌────┴────┐
    │ ASR_delta│
    │ < threshold? │
    └────┬────┘
         │
    ┌────┴────┐     是     ┌─────────────────┐
    │ 触发策略 │──────────▶│ 决策引擎计算    │
    │ 调整?   │           │ 最优下一动作    │
    └────┬────┘           └────────┬────────┘
         │ 否                      │
         ▼                         ▼
    ┌──────────┐          ┌─────────────────┐
    │ 继续当前 │          │ 应用新策略到    │
    │ 策略     │          │ Phase N+1       │
    └──────────┘          └─────────────────┘
```

**决策触发条件**：
1. ASR 低于预期 50% → 触发策略调整
2. 预算消耗 > 80% → 切换到高先验-only 模式
3. 连续失败 > 3 次 → 切换攻击策略
4. 新能力发现 → 扩展攻击面

### 11.5 决策系统架构不变量

| # | 不变量 | 依据 |
|---|--------|------|
| ID-1 | 决策系统不得绕过人工确认的安全边界 (R-S1) | 安全合规红线 |
| ID-2 | 所有决策调整必须记录到 orchestration_log | 审计追踪 |
| ID-3 | 自动策略切换需基于 ≥3 次连续失败或 ASR 显著下降 | 稳定性约束 |
| ID-4 | 决策引擎输出必须可被人工覆盖 (CLI 参数优先) | 人类控制权 |
| ID-5 | 决策依赖数据必须来自 PipelineContext，禁止旁路 | 数据流完整性 |

### 11.6 决策引擎数据流契约（新增 ctx 字段）

| 字段 | 类型 | 唯一写者 | 读者 | 决策用途 |
|------|------|---------|------|----------|
| `ctx.current_asr` | float | Strike/Assess | 决策引擎 | 触发策略调整 |
| `ctx.expected_asr` | float | ARM | 决策引擎 | ASR 预期基准 |
| `ctx.budget_consumed` | dict | 各阶段 | 决策引擎 | 预算控制 |
| `ctx.consecutive_failures` | int | Strike | 决策引擎 | 失败计数 |
| `ctx.decision_log` | list | 决策引擎 | Report | 决策审计追踪 |

---

## 版本记录

| 版本 | 日期 | 变更摘要 | 批准 |
|------|------|---------|------|
| v1.0 | 2026-09-05 | 初版：系统全景、分层与依赖矩阵、PyRIT 判定树、ctx 契约、Burp 数据流、不变量 I1-I10、ADR-001~006、债务簿 D-01~D-09 | — |
| v1.1 | 2026-09-05 | REV-01：① §1.1 阶段词汇映射表（统一 recon/arm/strike/report/evidence 口径，防凭空造阶段或模块）；② I7 明确 asr_history（运行时唯一账本）与 asr_priors（人工先验唯一源）的 SSOT 关系；③ 依赖矩阵补 arm 读取 asr_history、"—"图例；④ 版本记录机制 | 用户会话批准 |
| v1.2 | 2026-09-05 | REV-02 源码对齐（审计 @0b8e28c）：① 新登记债务 D-10~D-16（escalation 孪生、converter 三轨、seed 排序双轨、data/ 层代码污染、display 巨石、judge 文件群、工具链卫生）；② D-02/D-03 现状更新（main.py 87KB 巨石证实；Best-of-N stub 定性为 P0 缺口）；③ §1.1/§2.1 标注现状违例。架构本体（分层/契约/不变量/ADR）无变更 | 用户会话批准 |
| v1.3 | 2026-09-06 | REV-03 代码审计修正（remediation/audit-remediation.md）：① D-01 量化修正（合并家族实际 ~3354 行死代码）；② D-10 修正（非 9 字节孪生，实为"门面+拆分"三件 + 编码损坏）；③ D-11 修正（非纯粹三轨，实为死函数 + _PRIORITY_MAP 孪生）；④ D-12 修正（非孪生，实为拆分+re-export+双向 import） | — |
| v1.4 | 2026-09-06 | REV-04 D-13 消除：① data/asset_mapper.py → core/asset_mapper.py；② data/attack_surface_classifier.py → recon/attack_surface_classifier.py；③ data/scorer_selector.py 已删除；④ data/burp/ → config/targets/burp/；⑤ 全量更新 import 路径与文档引用；⑥ 4 测试文件路径同步更新 | 用户会话批准 |
| v1.5 | 2026-09-06 | REV-05 recon 违宪整改（按 00-CONSTITUTION 优先级全部解决）：① P0-01 能力检测三轨合一 — `_probe_capabilities` 内部委托给 `confidence_scorer.score_capability()` SSOT，关键词与正则模式从 capability_detector.py 迁移至 confidence_scorer.py（含 capability_detector 中 MCP/Agent/RAG/Embedding 的结构化模式），原 capability_detector 中 ~200 行重复关键词/正则代码删除；② P0-02 探测风暴裁剪（保留 ≤2 个核心同步探针，其余移异步）— 已完成于会话前期；③ P0-03 自定义 Target 废弃（JSONSafeHTTPTarget → PyRIT 原生 HTTPTarget + ChatIdStateManager）— 已完成于会话前期 | 用户会话批准 |
| v1.6 | 2026-09-06 | REV-06 AI-300 考试架构优化：① 新增第九章 PyRIT 原生攻击引擎架构（PyRIT→阶段落点映射 9.1、考试攻击路径决策树 9.2、ASR 优化策略 9.3、考试快速攻击模板速查 9.4）；② 架构本体（分层/契约/不变量/ADR）无变更 | 用户会话批准 |
| v1.7 | 2026-09-06 | REV-07 目录结构重构：① Burp 目标文件从 config/campaigns/targets/ 扁平化迁移至 config/targets/；② asset_index.yaml 从 config/campaigns/ 迁移至 config/profiles/ (固定参数集)；③ 4 Campaign 重命名清晰化 (rapid_recon→quick_scan, full_spectrum_max_asr→deep_spectrum, mcp_agent_targeted→mcp_targeted, standard_redteam 保留) 并迁移至 config/profiles/；④ 删除 config/campaigns/ 目录 | 用户会话批准 |
| v1.8 | 2026-09-06 | REV-08 消除命名冲突：① config/targets/ 重命名为 config/burp/ (区分代码 targets/ 适配层与 Burp 输入契约)；② 更新 core/config.py、core/scenario_router.py 路径引用 | 用户会话批准 |
| v1.9 | 2026-09-06 | REV-09 适配层重命名：① targets/ → adapters/ (精准描述 PyRIT 原生组件包装职责)；② 更新 recon/target_router.py import 路径 | 用户会话批准 |
| v2.0 | 2026-09-08 | REV-10 企业AI红队融合解决方案：① 新增Glue层架构（模块清单、架构原则、攻击类型映射、依赖拓扑）；② 更新分层表新增Glue层；③ 更新依赖方向矩阵新增glue行 | 用户会话批准 |
| v2.1 | 2026-09-08 | REV-11 过度工程化清理（黑盒可测性约束）：① 删除 vector_db_glue.py（向量DB SDK需直访，黑盒HTTP不可测试）；② 删除 fine_tuning_glue.py（需训练环境API，黑盒HTTP不可测试）；③ 精简 audit_evasion_glue.py 为仅日志注入（移除 SIEM/审计路径）；④ 同步化 enterprise_auth_glue.py；⑤ 更新 Glue 层架构图（3模块精简） | 用户会话批准 |
| v2.2 | 2026-09-08 | REV-12 全面过度工程化清理后债务簿瘦身：① 债务登记从 16 项（D-01~D-16）精简至 2 项（D-04/D-16）；② 已消除 14 项债务移至归档区（含 assess 双轨、display 巨石、escalation 三件、judge 文件群等）；③ 章节编号修复（原两个"九章"冲突→九章/十章）；④ Glue 层重命名为 Web 攻击层（目录扁平化对齐） | 用户会话批准 |
| v2.3 | 2026-09-09 | REV-13 合并 45-DATA-FLOW-INTEGRITY.md：① 第四章新增 Phase 字段契约（4.2）和数据传递规则（4.3）；② 数据流完整性验证工具链（DataFlowValidator/data_flow_hooks）保留在 tools/ 目录；③ 45-DATA-FLOW-INTEGRITY.md 标记为归档参见本文件 | 用户会话批准 |
| v2.4 | 2026-09-09 | REV-14 新增第十一章全链路自主决策引擎架构：① 决策引擎在架构分层中的位置（11.1）；② 决策点与 ctx 字段契约（11.2）；③ 决策依赖引擎核心组件（11.3）；④ 决策触发条件与反馈闭环（11.4）；⑤ 决策系统架构不变量 ID-1~ID-5（11.5）；⑥ 决策引擎数据流契约（11.6） | 用户会话批准 |
