# 10 — 架构与设计层：技术蓝图（Architecture Blueprint）

> **文档层级**：L1 / 五层规约金字塔第二层
> **效力**：定义系统的目标架构、模块边界、数据契约与架构不变量。任何代码变更必须能在本蓝图上"落点"——落不了点的变更需要先走 change-proposal 修改蓝图。
> **读者**：实施任务前的 AI（必读相关章节）、评审 diff 的人工/AI。
> **版本**：v1.9（2026-09-06 REV-09：targets/ → adapters/ 适配层精准命名；REV-08：config/burp/ 消除冲突；初版 2026-09-05）

---

## 第一章：系统全景

```
输入契约                    六阶段攻击流水线                          输出契约
──────────                ──────────────────────                    ──────────
data/burp/*.txt    ──►     ① RECON    侦察/指纹/Target 构建    ──►    outputs/strike_*/
(Burp 完整 HTTP            ② SYNERGY  攻击面分类/场景路由             ├── report*.md / .html
 交互，含响应)              ③ ARM      种子/Converter/技术             ├── report.sarif
.env 三角色 LLM            ④ STRIKE   单轮多路径 FIRST_SUCCESS         ├── evidence/ + poc/
 config/defaults.yaml      ⑤ ESCALATE L1→L4 升级链                    ├── native_output/
 config/asr_priors.yaml    ⑥ ASSESS   T0→J1→J2 级联评分                └── db/pyrit.db
 data/seeds/*.prompt       (REPORT    证据/多格式报告)
config/burp/*.txt                 ← Burp 目标文件 (v64 消除命名冲突)
config/profiles/asset_index.yaml  ← 统一资产索引 (v63 固定参数集)
```

**使命映射**（见宪法第 0 条）：蓝图的每个部分都服务于"Burp 黑盒目标 ASR 最大化"。判断一个架构改动是否正当的唯一标准：它是否让 ①-⑥ 链路对 Burp 目标打出更高 ASR、或让证据链更可复现。

### 1.1 阶段词汇映射（口径统一，v1.1 增补）

需求侧/会话中的惯用口径与本蓝图六阶段流水线的**唯一权威对应关系**（防止凭空发明第七阶段或同名模块）：

| 惯用口径 | 架构落点 | 备注 |
|---------|---------|------|
| recon / 侦察 | ① RECON | recon/ 模块；target_fingerprint 是对下游的唯一输出总线 |
| 攻击面分类 / 场景路由 | ② SYNERGY | **无独立模块**：由 core/ 场景路由实现，仅产出 technique_tags（ADR-004）；禁止新建 synergy/ 包。v61 已消除越层代码（D-13） |
| arm / 武器化 | ③ ARM | arm/ 模块 |
| strike / 打击 / 单轮 | ④ STRIKE | strike/ 模块 |
| escalate / 升级链 | ⑤ ESCALATE | strike/ 模块内部逻辑，非独立模块 |
| 评分 / judge / ASR 统计 | ⑥ ASSESS | assess/ 模块（post-hoc；唯一允许 LLM Judge 的位置，I2/I3） |
| report / 报告 | REPORT | report/ 模块 |
| **evidence / 证据** | **输出契约，非阶段** | 由 ASSESS（评分结论）+ REPORT（证据文件）产出；见 REQ-007 与不变量 I9；**禁止新建 evidence/ 模块** |

**规则**：会话中出现未登记口径（如"改 evidence 阶段"）→ 先查本表映射再动手；映射不出去 → STOP-REPORT（C11），禁止发明新阶段或新建同名模块（C3/C4）。

## 第二章：分层与依赖规则

### 2.1 模块分层

| 层 | 模块 | 职责一句话 |
|----|------|-----------|
| 编排层 | `main.py` | 六阶段顺序编排 + 多 endpoint 循环；**不得包含业务逻辑**（现状违例：87KB 巨石，D-02） |
| 核心层 | `core/` | 配置解析（唯一默认值定义地）、PipelineContext、架构守卫、场景路由 |
| 阶段层 | `recon/ arm/ strike/ assess/ report/` | 各攻击阶段的实现；彼此只通过 PipelineContext 交接 |
| 适配层 | `adapters/` | PyRIT 原生 Target 包装（限速/认证/内容过滤标记扩展） |
| 支撑层 | `utils/ pipeline/` | 终端展示、缓存清理、日志、资源清理（现状违例：display.py 119KB，D-14） |
| 数据层 | `data/` + `config/` | 种子、评分器 rubric、ASR 先验、defaults（**全部为声明式资产**，D-13 已消除：代码迁至 core/ 或 recon/；burp/ → config/targets/burp/；asset_index.yaml → config/） |

### 2.2 依赖方向矩阵（允许 ↓ / 禁止 ✗）

| 依赖方 ↓ 被依赖方 → | core | recon | arm | strike | assess | report | targets | utils | data(config) |
|---|---|---|---|---|---|---|---|---|---|
| main.py | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | — |
| core/ | — | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | 读写 defaults.yaml |
| recon/ | ✓（context） | 内部 | ✗ | ✗ | ✗* | ✗ | ✓ | ✓ | 只读 |
| arm/ | ✓ | ✗ | 内部 | ✗ | ✗ | ✗ | ✗ | ✗ | 只读 asr_priors；读 asr_history（I7 运行时账本） |
| strike/ | ✓ | ✗ | ✓ | 内部 | ✓** | ✗ | ✗ | ✓ | 只读 |
| assess/ | ✓ | ✗ | ✗ | ✗ | 内部 | ✗ | ✗ | ✗ | 读写 asr_history |
| report/ | ✓ | ✗ | ✗ | ✗ | ✗ | 内部 | ✗ | ✗ | 只读 |
| targets/ | ✗ | ✓*** | ✗ | ✗ | ✗ | ✗ | 内部 | ✗ | 只读 |
| utils/ | ✓（context 类型） | ✗ | ✗**** | ✗ | ✗ | ✗ | ✗ | 内部 | 只读 |

\* recon/target_router 调 `assess.scorer.validate_scoring_target_capabilities` —— 已登记债务 D-04。
\** strike → assess 仅限 `precompute_outcomes_async`（升级前预评分），不得扩大。
\*** targets/agent_adapter 现引用 PyRIT 原生 HTTPTarget —— 债务 D-05 已解除 (P0-03)。
\**** utils/display 延迟导入 arm/seed_ranking 读 ASR 历史 —— 已登记债务 D-06（展示层越界）。

**图例**（v1.1）：✓ 允许；✗ 禁止；"—" = 不适用（对角线自身单元格）或禁止（本表仅一处：main.py × 数据层——main 不得直接解析 data/config 资产，一律经 core/config.py 或阶段模块。未来新出现的"—"必须随行注明语义）。

**硬规则**：
1. 阶段层模块之间（recon/arm/strike/assess/report）**只准通过 PipelineContext 字段交接数据**，禁止直接 import 对方实现（表内已标注的既存例外除外，且例外只减不增）。
2. `core/context.py` 是唯一被全员依赖的枢纽；`core/config.py` 是唯一允许定义参数默认值的模块。
3. 循环导入的合法解法只有三种：函数内延迟导入 / TYPE_CHECKING / 合并到同一模块（拆分后 re-export 属于债务，不再新增）。

## 第三章：PyRIT 原生判定决策树

写新能力前的强制四问（对应宪法 C1）：

```
Q1: PyRIT 1.0.1 有现成组件吗？（检索 pyrit.executor.attack / pyrit.prompt_target /
    pyrit.scorer / pyrit.converter / pyrit.memory / pyrit.output）
    ├─ 有 → 直接用，结束
    └─ 无 → Q2: 能用"包装原生组件"实现吗？（继承/组合原生类，原生引擎为主）
             ├─ 能 → Enhancement wrapper（如 RateLimitedTarget 模式），结束
             └─ 不能 → Q3: 属于 Glue / Output 三类自研范畴吗？
                      │  Glue   = 连接原生组件（如 burp 解析 → HTTPTarget）
                      │  Output = 读 PyRIT 结果产证据/报告（如 evidence.py）
                      ├─ 是 → 实现，结束
                      └─ 否 → Q4: 超出 PyRIT 域（ML 推理/HTTP 协议层/供应链）？
                               ├─ 是 → STOP-REPORT（C11）：提案引入外部框架或拒绝
                               └─ 否 → STOP-REPORT（C11）：大概率你错了，重新检索
```

**原生组件强制使用清单**（attack 10 类 + target + scorer + converter + memory + output，详见 SKILL.md R2 表——该表继续有效）。**PyRIT 域边界**：`与 LLM 的 prompt 交互与响应评估`；域外问题（如梯度级 GCG）只能以外部工具形态接入并回填数据。

## 第四章：PipelineContext 数据契约

ctx 字段采用**唯一写者**原则（一个字段只准一个阶段写）：

| 字段 | 唯一写者 | 读者 | 备注 |
|------|---------|------|------|
| `args` / `output_dir` | main | 全部 | 创建后只读 |
| `parsed_request`（含 target_fingerprint） | recon | arm/strike/report | fingerprint 是 recon 对下游的总线 |
| `objective_target` / `multi_turn_target` / `extra_objective_targets` | recon | strike / cleanup | per-endpoint，循环内须重置 |
| `adversarial_target` / `scoring_target` / `converter_target` / `extra_adversarial_targets` | recon | strike/assess | **跨 endpoint 共享**，循环末清理 |
| `synergy_config` / `scenario_config` / `scenario_name` | synergy/scenario 路由 | strike(adaptive) | 攻击面→技术标签 |
| `seeds` / `techniques` / `converter_map` | arm | strike | — |
| `attack_results` / `_failed_objectives` | strike（含 escalate 追加） | assess/report | `{technique: [AttackResult]}` |
| `asr_per_technique` / `overall_asr` / `wilson_ci` / `dual_judge_stats` / `scorer` | assess | report / main | — |
| `orchestration_log` | 各阶段（自己追加自己的条目） | report | 六阶段每阶段至少一条 |
| `_mcp_dynamic_seeds` | recon(MCP 枚举) | strike(mcp_rag) | — |
| Playwright 三字段 | recon | cleanup | 共享，仅末尾清理 |

**新增 ctx 字段的义务**：在本表登记 + 在 20-REQUIREMENTS 对应需求验收标准中体现 + 单 endpoint 循环开始处明确"重置 / 保留"归属（多 endpoint 隔离，见 40-GUARDRAILS 引用的 R8 §8.3）。

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

以下为已识别的**冻结债务**：日常任务禁止触碰（C3/C4），只能由专项任务（DEBT-xxx）消除。**只减不增**。D-01~D-09 为制宪时登记；D-10~D-16 为 REV-02 源码审计（commit 0b8e28c）新登记。

| ID | 债务 | 现状 | 消除方向 |
|----|------|------|---------|
| D-01 | assess 双轨并存 | **合并家族**（judge_manager 1654行 + score_pipeline 654行 + asr_manager 728行 + response_parser 318行）≈ **3354 行整体死代码**，仅死文件互引；**拆分家族**（asr_tracker/asr_compute/asr_stats/asr_history/precompute）为生产活代码 | 保留拆分家族，删除合并家族 ~3354 行 |
| D-02 | main/pipeline 镜像 | main.py 87KB 巨石（编排层含业务逻辑，违 2.1）；pipeline/orchestrator.py 实为薄转发（v58 重构半途，委托 main.run） | main 调用 pipeline 包，删除本地副本；业务逻辑下沉阶段层 |
| D-03 | stub 模块 | encoded_injection.py / cair.run_cair_attack / multi_turn_attacks（Best-of-N）返回空 dict，注释自认"调用方 try/except 优雅降级"= R-H1 静默降级 | 要么实现（提 REQ），要么从升级链摘除；禁止维持"编排了但没实现"状态。**注意：Best-of-N 属 REQ-004 P0 验收项，此 stub 是现行 P0 缺口** |
| D-04 | recon → assess 跨层依赖 | target_router 调 assess.scorer 验证函数 | 验证函数移入 core 或 targets |
| ~~D-05~~ | ~~targets → recon 反向依赖~~ | **已消除** (P0-03)：JSONSafeHTTPTarget 已废弃，改用 PyRIT 原生 HTTPTarget；会话状态由 ChatIdStateManager 外部管理 | ✅ 已完成 (2026-09-06) |
| D-06 | utils/display → arm 越界 | 展示层延迟导入 arm.seed_ranking 读 ASR | ASR 数据经 ctx 或独立查询模块传递 |
| D-07 | 硬编码数据快照 | display._CONVERTER_ASR_LABEL 与 asr_priors.yaml 重复 | 展示层读 yaml |
| D-08 | 无代码加载的配置 | config/target_profiles.yaml 26 profile 零消费 | 要么接 asset_mapper 要么删除 |
| D-09 | 规范文档多处冗余 | SKILL.md（实测 57KB）/ docs/ 与 specs 职责重叠 | **已消除**：B/C 类旧文档（implementation_checklist/RTM/attack_strategy/escalate/scenariod/terminal_report_optimization）已于 2026-09-06 删除，specs/ 金字塔确立为唯一权威源；SKILL.md 降位为⑤细则（frontmatter 指向宪法，Supporting Documents 表已重写为 specs/ 引用）；剩余 BL-011 本体收敛按路线图推进 |
| D-10 | escalation 三件 | 非 9 字节孪生，实为"门面+拆分"三件（escalation.py 940行门面 / chain 1124 / attacks 1057），函数集互不重叠；实际债务：re-export 债务 + `_llm_judge_rescore` 死 re-export + `_is_success`/_retrieve_partial_results 跨文件复制 + escalation_attacks.py 全文编码损坏 | 删 escalation_attacks.py + 清 re-export + 统一跨文件复制 |
| D-11 | arm converter 三轨 | 三文件职责互补（链构建/预设分配/候选选择），非纯粹三轨；实际债务：converter_selector.py 含 ~230 行死函数（与 _get_candidate_converters 含逐字相同的 23 项 _PRIORITY_MAP 孪生）+ 循环 re-export 尾巴 | 删死函数 + 消 _PRIORITY_MAP 孪生 + 删 re-export 尾巴 |
| D-12 | arm 种子排序双轨 | 非孪生，实为拆分+12 符号 re-export 门面；实际债务：双向 import（seed_ranking 反查 seed_ranker）+ 调用方 import 路径分裂（main/strike 走门面、executor/display 直连） | 统一 import 路径 + 消除双向 import |
| ~~D-13~~ | ~~data/ 层代码污染~~ | **已消除** (v61)：asset_mapper → core/；attack_surface_classifier → recon/；synergy_orchestrator → core/scenario_router；scorer_selector 已删除；burp/ → config/targets/burp/；data/__init__.py 已删除（load_asset_index 迁至 core/asset_mapper）；asset_index.yaml → config/asset_index.yaml；data/ 纯声明式资产 | ✅ 已完成 (2026-09-06) |
| D-14 | display.py 巨石 | utils/display.py 119KB 全库最大文件（含 D-06/D-07 关联问题） | 拆分展示/数据查询职责；读 yaml 替代硬编码 |
| D-15 | judge 文件群 | judge_manager（74KB）+ judge_utils（55KB）+ dual_judge（27KB）+ adaptive_dual_judge（24KB）四文件，D-01 的具体形态 | 并入 D-01 消除方案统一裁决（单文件 ≤500 行目标） |
| D-16 | 工具链与资产卫生 | ① pyproject.toml ruff exclude pipeline/（门禁 Step 2 空洞）；② report/output.py 注释 mojibake（UTF-8/GBK 混写）；③ 依赖 `pyrit>=1.0.1` 未钉住（规约口径为 1.0.1）；④ data/seeds/asr_history.json 运行时产物入库 | 修 pyproject（去 exclude、钉 1.0.1）；修乱码；asr_history 迁 outputs/ 并入 .gitignore |

**新增债务的流程**：发现新双轨/越界 → 登记 backlog（一行）→ 评估后入本表。**禁止直接修**。

---

## 第九章：PyRIT 原生攻击引擎架构（v1.6 增补，OffSec AI-300 考试优化）

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
