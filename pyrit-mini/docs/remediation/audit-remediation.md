# 代码审计与整改规格（Code Audit & Remediation Spec）

> **文档层级**：整改中心（remediation/）/ 独立于 specs/ 规约金字塔的专项整改层
> **效力**：本项目历史代码问题的权威登记处与整改验收标准。本文件登记的每条 P0/P1/P2 问题必须由专项任务（TASK-xxx）消除，日常任务禁止触碰（C3/C4）。
> **读者**：实施整改任务的 AI（必读）、评审 diff 的人工/AI。
> **版本**：v1.0（2026-09-06 首次全面代码审计）
> **交叉引用**：[specs/](../specs/) 规约金字塔（宪法 C1-C12 / 不变量 I1-I10 / 需求 REQ-xxx）

---

## 第一章：审计方法论与评级体系

### 1.1 审计范围

本次审计覆盖以下维度：
- **P0 缺陷**：直接伤害 ASR 使命的未登记致命缺陷
- **攻击执行完成度**：五类 Agent 应用攻击的执行现状
- **已登记 P0 缺口验证**：原债务簿中 P0 项的实际情况
- **双轨债务验证与修正**：债务簿描述的精确化
- **巨石与分层违规**：架构违规实证
- **工具链与仓库卫生**：门禁与 hygiene 问题

### 1.2 缺陷评级标准

| 级别 | 定义 | 处理时限 | 影响 |
|------|------|---------|------|
| **P0-NEW** | 未登记于任何债务簿的新发现致命缺陷 | 必须优先于路线图修复 | 直接导致 ASR=0 或攻击链路整体失效 |
| **P0** | 已登记或 ASR 主链路核心缺口 | 最高优先任务 | 关键功能不可用 |
| **P1** | 支撑能力缺陷 | 高优先 | 影响可维护性/可扩展性 |
| **P2** | 体验与卫生问题 | 中优先 | 影响开发效率 |

### 1.3 审计验证方法论

每条问题必须满足以下验证标准：
1. **源码定位**：精确到文件名和行号范围
2. **根因分析**：说明为何产生，非表面症状
3. **影响范围**：说明影响哪些功能/链路
4. **触发条件**：说明何时触发缺陷
5. **违反条款**：关联到宪法/蓝图/需求的具体条款

---

## 第二章：P0-NEW 致命缺陷登记（未登记于债务簿）

> **紧急性**：以下四项为审计新发现的**致命缺陷**，未登记于原债务簿任何位置，但直接违反 ASR 至上使命（C2），必须优先于路线图已有任务处理。

### P0-NEW-1：默认配置下 L2→L4 升级链整体失效（UnboundLocalError）

**登记日期**：2026-09-06  
**状态**：open  
**影响**：全部 L2-L4 技术（含 GCG、SkeletonKey、MultiPrompt、Chunked、Rogue Agent、Embedding Inversion、MCP/RAG）在默认配置下**永不执行**

#### 2.1.1 源码定位

| 位置 | 问题 |
|------|------|
| `strike/escalation.py:335` | `_safe_call` 仅定义在 `priority_scheduler_enabled < 1.0` 的 else 分支内 |
| `config/defaults.yaml:137` | 默认 `priority_scheduler_enabled: 1` → 走优先级分批分支 |
| `strike/escalation.py:483-486` | L2 调用点引用 `_safe_call` |
| `strike/escalation.py:617-620` | L3 调用点引用 `_safe_call` |
| `strike/escalation.py:685-687` | L4 调用点引用 `_safe_call` |
| `main.py:1348-1352` | 捕获后仅记日志"升级失败 — 继续处理单轮结果"（静默吞错） |

#### 2.1.2 根因分析

Python 函数内定义的 `async def _safe_call` 是局部作用域绑定。当 `priority_scheduler_enabled >= 1.0` 时执行 if 分支，else 分支内的 `_safe_call` 永不定义。后续 L2/L3/L4 调用时触发 `UnboundLocalError`。

#### 2.1.3 触发条件

1. 使用默认配置（未显式设置 `priority_scheduler_enabled: 0`）
2. 单轮 ASR < 90% 触发升级链
3. post-L1 ASR < 70% 未提前退出

#### 2.1.4 后果

所有已实装的 agent 类攻击技术在默认配置下一次都不会执行。这直接解释了为何 stub 能长期潜伏不被发现——升级链从未真正运行过。

#### 2.1.5 违反条款

- **C2**（ASR 至上）：攻击链路实际不可用
- **不变量 I4**：升级链触发条件满足但执行失败
- **REQ-005**：多轮升级链核心需求未实现

#### 2.1.6 整改验收标准

- [ ] `_safe_call` 在 L1 if/else 两分支外定义（模块级函数）
- [ ] 默认配置下 L2/L3/L4 可正常执行（dry-run 验证）
- [ ] main.py 升级失败时不再静默吞错（至少 warn 级别 + 用户可见）
- [ ] 补充回归测试：模拟 ASR<90% 触发升级链

---

### P0-NEW-2：多智能体种子 5 条中 3 条永不加载

**登记日期**：2026-09-06  
**状态**：open  
**影响**：`ma_memory_poisoning`、`ma_trust_chain_break`、`ma_cascading_failure` 三个多智能体攻击面永远不进攻击池

#### 2.2.1 源码定位

| 位置 | 问题 |
|------|------|
| `arm/seed_ranker.py:41-82` | `CAPABILITY_SEED_MAP` 仅映射 `ma_cross_agent_injection`、`ma_identity_spoofing` |
| `data/seeds/_attack_surface/T1_ASI06-09_multi_agent/` | 目录下实际存在 5 个种子文件，3 个无映射 |

#### 2.2.2 根因分析

`CAPABILITY_SEED_MAP` 的 `multi_agent` 条目只列出了 2 个种子文件路径，而 `_attack_surface/T1_ASI06-09_multi_agent/` 目录下存在 5 个种子文件。新增种子时未同步更新映射表。

#### 2.2.3 违反条款

- **REQ-002**：MCP/RAG/多智能体能力侦察后的定向种子加载不完整
- **REQ-109**：多智能体攻击覆盖不完整

#### 2.2.4 整改验收标准

- [ ] `CAPABILITY_SEED_MAP["multi_agent"]` 映射全部 5 个种子文件
- [ ] 补充自动化测试：验证 map 中所有路径的文件存在性

---

### P0-NEW-3：MCP 动态种子链路断裂（已实现但未接线）

**登记日期**：2026-09-06  
**状态**：open  
**影响**：MCP 枚举→定向 payload 这条最能提升 MCP ASR 的链路被掐断

#### 2.3.1 源码定位

| 位置 | 问题 |
|------|------|
| `recon/mcp_enumerator.py:774-907` | `build_mcp_attack_seeds` 完整实现但**零生产调用**（仅测试调用） |
| `strike/mcp_rag_attack.py` | 仅加载 12 个静态种子，不消费 `target_fingerprint["mcp_tools"]` |
| `core/context.py:92-93` | `_mcp_dynamic_seeds` 字段声明但未填充未消费 |
| `main.py:459` | 仅置空 `_mcp_dynamic_seeds = []` |
| `core/context.py:93` | 注释引用 `_execute_specialized_seeds` 全库不存在（陈旧注释） |

#### 2.3.2 根因分析

recon 侧的 MCP 枚举功能完整（枚举 tool schema → 生成定向种子），但 strike 侧的 `run_mcp_rag_attacks` 只加载静态种子文件。`ctx._mcp_dynamic_seeds` 是死字段：声明处仅初始化，无任何模块填充，无模块消费。

#### 2.3.3 违反条款

- **REQ-002**：MCP 枚举后动态种子生成的链路未接通
- **C11**：陈旧注释误导开发者相信已实现

#### 2.3.4 整改验收标准

- [ ] MCP 枚举完成后调用 `build_mcp_attack_seeds` 填充 `ctx._mcp_dynamic_seeds`
- [ ] `run_mcp_rag_attacks` 合并消费 `_mcp_dynamic_seeds` 与静态种子
- [ ] 删除 `core/context.py:93` 的陈旧注释（引用不存在的函数）
- [ ] 补充集成测试：MCP 目标攻击链路由动态种子

---

### P0-NEW-4：死代码未登记

**登记日期**：2026-09-06  
**状态**：open  
**影响**：~4000 行死代码持续制造"改错文件"风险

#### 2.4.1 死代码清单

| 文件 | 行数 | 状态 | 问题 |
|------|------|------|------|
| `targets/agent_adapter.py` | ~574 | 死代码 | 零调用方，实际 Target 构建走 `recon/target_router.py` |
| `data/scorer_selector.py` | ~252 | 死代码 | 仅被测试 import，生产链路无消费者 |
| `data/attack_surface_classifier.py:458-464` | — | 坏掉的占位 | `get_default_classifier()` 永远返回 None |
| `assess/judge_manager.py` | 1655 | 合并家族死代码 | 自称 SSOT 但无生产消费者 |
| `assess/score_pipeline.py` | 655 | 合并家族死代码 | 仅死文件互引 |
| `assess/asr_manager.py` | 728 | 合并家族死代码 | 仅死文件互引 |
| `assess/response_parser.py` | 318 | 合并家族死代码 | 仅死文件互引 |

#### 2.4.2 违反条款

- **C3**（SSOT）：多个模块自称 SSOT 实际是尸体
- **D-01**：原债务簿只登记了 assess 双轨的外在表现，未量化死代码规模

#### 2.4.3 整改验收标准

- [ ] 确认 `targets/agent_adapter.py` 无调用方后删除
- [ ] 确认 `data/scorer_selector.py` 无生产调用后删除
- [ ] 修复或删除 `get_default_classifier()` 坏掉的占位
- [ ] assess 死代码随 D-01/DEBT-01 任务统一处理（保留拆分家族 asr_tracker/asr_compute/asr_stats/asr_history/precompute）

---

## 第三章：五类 Agent 应用攻击执行完成度

> **背景**：本项目以"基于 LLM 开发的 Agent 应用攻击"为核心目标。以下五类攻击的执行完成度直接衡量使命达成度。

### 3.1 总览

| 类别 | 完成度 | 现状 | 主要问题 |
|------|--------|------|---------|
| 单 Agent | ✅ 完整 | 能力指纹→定向种子→agent_targeted→单轮多路径+L1-L3 | 无 |
| 多 Agent | ❌ stub 级 | 仅 2/5 种子可达 | P0-NEW-2、REQ-109 三类编排缺失 |
| A2A | 🟡 单轮 prompt 级 | rogue_agent.py 实装但挂 L4 | 死于 P0-NEW-1，无协议层攻击 |
| MCP | 🟡 断链 | recon 枚举完整 + strike 静态化 | P0-NEW-3、动态链路断裂 |
| Embedding | 🟡 实装但失效 | embedding_inversion.py 真实实现 | 挂 L4 死于 P0-NEW-1 |

### 3.2 多 Agent 攻击缺失详单（REQ-109）

**现状**：`attack/strike/` 目录下 `impersonation`、`cross_agent`、`workflow` 关键词零命中。

**缺失的三类编排**：

| 攻击类型 | 学术依据 | 缺失表现 |
|---------|---------|---------|
| Cross-agent injection | arXiv:2407.16924 (Eidam et al.) | 无 attack module |
| Agent impersonation | arXiv:2402.01135 (Chao et al.) | 无 attack module |
| Workflow corruption | arXiv:2307.00929 (InjecAgent) | 无 attack module |

**整改验收标准**：
- [ ] 多智能体种子 5 条全部可加载（P0-NEW-2 修复）
- [ ] 升级链 L4 集成多 agent 攻击技术
- [ ] 至少实现 cross-agent injection 一种编排

### 3.3 A2A 攻击缺失详单

**现状**：`strike/rogue_agent.py` 实装（A2A/2.0 伪造身份前缀）挂 L4——但死于 P0-NEW-1。

**缺失的攻击维度**：
- Agent card 劫持（协议层）
- Service endpoint spoofing
- Trust chain manipulation

**整改验收标准**：
- [ ] L4 修复后 rogue_agent 可达（P0-NEW-1 修复）
- [ ] 补充 agent card 劫持协议层攻击

### 3.4 MCP 攻击缺失详单

**现状**：recon 侧 `mcp_enumerator.py` 完整（差异化优势），strike 侧静态化。

**缺失的攻击链路**：
- 枚举 tool schema → 动态生成定向 payload（P0-NEW-3）
- Resource poisoning
- Cross-server trust exploitation

**整改验收标准**：
- [ ] MCP 动态种子链路接通（P0-NEW-3 修复）
- [ ] 枚举到的 tool schema 驱动攻击 payload 生成

### 3.5 Embedding 攻击缺失详单

**现状**：`strike/embedding_inversion.py` 207 行为真实实现（REQ-110 比规格预判乐观），但挂 L4 同样死于 P0-NEW-1。

**整改验收标准**：
- [ ] L4 修复后 embedding_inversion 可达
- [ ] 保持现有实现质量

---

## 第四章：已登记 P0 缺口验证

### 4.1 D-03 stub 模块验证

**原登记**：encoded_injection.py / cair.run_cair_attack / multi_turn_attacks（Best-of-N）返回空 dict

**审计结论**：全部证实，且存在更严重的静默降级链 R-H1。

#### 4.1.1 三层静默降级链确认（R-H1）

```
包装层 try/except → {}
    → _safe_call → {}
        → main.py 整体吞错
```

**实证**：
- `strike/multi_turn_attacks.py:32-33`：`return {}`
- `strike/encoded_injection.py:31-32`：`return {}`
- `strike/cair.py:29-30`：`return {}`
- `main.py:1350-1352`：`except Exception as e: logger.error(...) — 继续处理单轮结果`

#### 4.1.2 测试固化 stub 行为

`tests/test_strike.py` 存在 `test_*_stub` 用例断言 `== {}`，把 stub 行为固化成了契约。

**违反条款**：
- **C9**（诚实汇报）：stub 冒充实现
- **C10**（验证义务）：测试断言 stub 输出

**整改验收标准**：
- [ ] 移除/修改断言 `== {}` 的测试用例
- [ ] 实现对应的真实攻击逻辑，或从升级链摘除

---

## 第五章：双轨债务验证与精确化

### 5.1 D-01 assess 双轨（⚠️ 证实且更严重）

**原登记**：judge_manager/judge_utils/asr_manager/score_pipeline 合并版与拆分版功能重复

**审计修正**：
- "合并家族"（judge_manager 1654 + score_pipeline 654 + asr_manager 728 + response_parser 318）≈ **3354 行整体死代码**
- 仅死文件互引，无生产消费者
- 活的是"拆分家族"（asr_tracker 门面→asr_compute/asr_stats/asr_history/precompute）
- `architecture_guard.py:993` 的排除清单只承认拆分家族

**整改验收标准**：
- [ ] 删除合并家族 3354 行死代码
- [ ] 保留拆分家族（asr_tracker/asr_compute/asr_stats/asr_history/precompute）
- [ ] 更新 architecture_guard 排除清单

### 5.2 D-10 escalation 孪生（⚠️ 与现状不符）

**原登记**：escalation.py 与 escalation_chain.py 仅差 9 字节，疑似孪生复制

**审计修正**：
- 本地代码为"门面+拆分"三件（escalation.py 940 行门面 / chain 1124 / attacks 1057）
- 函数集互不重叠，非 9 字节孪生
- 实际债务：
  - 门面 re-export 债务（蓝图 2.2 规则 3 明令"拆分后 re-export 属于债务"）
  - `_llm_judge_rescore` 死 re-export
  - `_is_success`/_retrieve_partial_results` 跨文件复制
  - `escalation_attacks.py` 全文编码损坏（乱码+双倍空行）

**整改验收标准**：
- [ ] 删除 escalation_attacks.py（编码损坏全文不可读）
- [ ] 消除 re-export 债务
- [ ] 统一 `_is_success`/_retrieve_partial_results` 实现

### 5.3 D-11 converter 三轨（⚠️ 部分修正）

**原登记**：converter_chains.py / converter_presets.py / converter_selector.py 各 ~40KB

**审计修正**：
- 三文件职责互补（链构建/预设分配/候选选择），非纯粹三轨
- 实际债务：`converter_selector.py:532` 的 `_build_converter_config` 是 ~230 行死函数
- 该函数与 `_get_candidate_converters` 含逐字相同的 23 项 `_PRIORITY_MAP` 孪生
- 另有无人使用的循环 re-export 尾巴（converter_chains:959-972）

**整改验收标准**：
- [ ] 删除 `_build_converter_config` 死函数
- [ ] 消除 `_PRIORITY_MAP` 孪生
- [ ] 删除循环 re-export 尾巴

### 5.4 D-12 seed 排序双轨（⚠️ 部分修正）

**原登记**：seed_ranker.py 与 seed_ranking.py 职责重叠

**审计修正**：
- 非孪生，是拆分+12 符号 re-export 门面
- 实际债务：
  - 双向 import（seed_ranking 反查 seed_ranker）
  - 调用方 import 路径分裂（main/strike 走门面、executor/display 直连）

**整改验收标准**：
- [ ] 统一 import 路径
- [ ] 消除双向 import

---

## 第六章：巨石与分层违规验证

### 6.1 main.py 1754 行（D-02 证实）

**现状**：`_run_single_endpoint` 单函数 959 行装下全部六阶段业务（RECON→SYNERGY→Scenario→Auto-L4→种子→Converter→STRIKE→ESCALATE→ASSESS→REPORT）

**违反**：
- 蓝图 2.1：编排层不得包含业务逻辑
- pipeline/orchestrator.py（41 行）是倒置依赖空壳（`from main import run`）——与蓝图 2.1 完全相反

**整改验收标准**：
- [ ] main.py 拆分为编排层（<500 行）+ 业务逻辑下沉阶段层
- [ ] pipeline/orchestrator.py 成为真正的编排入口
- [ ] main.py 成为可被 import 的业务逻辑聚合

### 6.2 display.py 2956 行（D-14 证实且扩大）

**现状**：
- `_CONVERTER_ASR_LABEL` 硬编码（1115-1123，与 asr_priors.yaml 双簿）
- 6 处函数内延迟 import `arm.seed_ranking`（展示层越界）
- 全名 2956 行（原登记 119KB 低估）

**违反**：
- D-06 展示层越界
- D-07 硬编码数据快照

**整改验收标准**：
- [ ] 硬编码替换为 yaml 读取
- [ ] 展示层不再导入 arm 模块
- [ ] 拆分为 <500 行的子模块

### 6.3 跨层依赖确认

| 依赖 | 位置 | 违反 |
|------|------|------|
| recon → assess | `target_router.py:932` | D-04 确认 |
| targets → recon | `agent_adapter.py:498` | D-05 确认 |

### 6.4 D-08 target_profiles.yaml 零代码加载（确认且扩大）

**现状**：
- `target_profiles.yaml` 零代码加载
- `cookie:` 配置节（TARGET_COOKIE/cookie.txt）同样断链
- `.env.example:63` 的声明是假的

**整改验收标准**：
- [ ] 接 asset_mapper 消费 target_profiles.yaml，或删除
- [ ] 修复 cookie 配置链路或删除相关声明

### 6.5 data/ 层 4 个 .py 代码污染确认（D-13）

| 文件 | 应迁位置 |
|------|---------|
| `data/asset_mapper.py` | core/ 或 recon/ |
| `data/attack_surface_classifier.py` | core/ 或 recon/ |
| `data/scorer_selector.py` | assess/ 或删除（死代码） |
| `data/synergy_orchestrator.py` | core/ |

---

## 第七章：工具链与仓库卫生（D-16 证实）

### 7.1 pyproject.toml 配置问题

| 位置 | 问题 | 违反 |
|------|------|------|
| `pyproject.toml:25` | ruff `exclude` 含 `pipeline/` | 门禁 Step 2 空洞 |
| `pyproject.toml:7` | `pyrit>=1.0.1` 未钉住 | NFR-7 |

**整改验收标准**：
- [ ] 移除 ruff exclude 中的 pipeline/
- [ ] 钉住 pyrit==1.0.*

### 7.2 运行时产物入库

| 文件 | 问题 |
|------|------|
| `data/seeds/asr_history.json` | 运行时产物在库中 |
| `.gitignore` | 无对应条目 |

**违反**：NEG-7（不变量 I7 相关）

**整改验收标准**：
- [ ] asr_history.json 迁移至 outputs/
- [ ] .gitignore 补齐运行时产物规则

### 7.3 编码损坏范围

**原登记**（D-16②）：report/output.py 注释 mojibake

**审计修正**：范围更大
- `escalation.py`（310、436-449 等处）存在 UTF-8/GBK 混写
- `escalation_attacks.py` 全文编码损坏（乱码+双倍空行）
- `technique_registry.py` 全文存在编码损坏

**整改验收标准**：
- [ ] 修复 escalation.py 编码混写
- [ ] 删除 escalation_attacks.py（全文损坏不可读）
- [ ] 修复 technique_registry.py 编码问题

---

## 第八章：场景特异性未进入执行层

### 8.1 technique_registry.py 问题

**现状**：注册的 10 项技术全部是通用越狱类（PyRIT 原生），agent/MCP/RAG 特异性仅靠 technique_tags 标签过滤——"场景特异性"没有进入攻击执行本体。

**分析**：

| 注册技术 | 类型 | 场景特异性 |
|---------|------|-----------|
| PromptSending | 通用 | 仅 tag 过滤 |
| Crescendo | 通用越狱 | 仅 tag 过滤 |
| TAP | 通用越狱 | 仅 tag 过滤 |
| PAIR | 通用越狱 | 仅 tag 过滤 |
| BestOfN | 通用 | 仅 tag 过滤 |
| RedTeaming | 通用越狱 | 仅 tag 过滤 |
| SkeletonKey | 通用越狱 | 仅 tag 过滤 |
| ManyShotJailbreak | 通用越狱 | 仅 tag 过滤 |
| MultiPromptSending | 通用越狱 | 仅 tag 过滤 |
| ChunkedRequest | 通用越狱 | 仅 tag 过滤 |

**违反**：
- C2（ASR 至上）：场景特异性攻击（多 agent 编排、MCP 协议层攻击、Embedding 倒置）未进入执行层
- REQ-109/110：考域覆盖需求

**整改验收标准**：
- [ ] 为多 agent 场景实现专用 attack module（非仅 tag 过滤）
- [ ] 为 MCP 场景实现基于 tool schema 的动态攻击
- [ ] Embedding 攻击有独立执行路径（修复后可达）

---

## 第九章：整改路线图建议

### 9.1 T0 紧急修复（ASR 至上 - 优先于已有路线图）

| 任务 | 对应问题 | 目标 |
|------|---------|------|
| T0-01 | P0-NEW-1 | 修复 `_safe_call` 作用域 + 升级链可达 |
| T0-02 | P0-NEW-2 | 补全多 agent 种子映射 |
| T0-03 | P0-NEW-3 | 接通 MCP 动态种子链路 |
| T0-04 | D-16 编码 | 修复 escalation.py + 删除 escalation_attacks.py |

### 9.2 T1 高优先级（攻击能力补全）

| 任务 | 对应问题 | 目标 |
|------|---------|------|
| T1-01 | REQ-004 P0 | Best-of-N 真实实现 |
| T1-02 | REQ-109 | 多 agent 三类编排实现 |
| T1-03 | REQ-110 | Embedding 攻击链路确认 |
| T1-04 | D-03 | 剩余 stub 实现或摘除 |

### 9.3 T2 中优先级（架构健康）

| 任务 | 对应问题 | 目标 |
|------|---------|------|
| T2-01 | D-01 | assess 死代码清除 |
| T2-02 | D-02 | main.py 拆分 |
| T2-03 | D-11 | converter 债务消除 |
| T2-04 | D-13 | data/ 层代码迁移 |

---

## 第十章：整体验收清单

### 10.1 P0-NEW 缺陷关闭标准

- [ ] P0-NEW-1：默认配置下 L2/L3/L4 可执行（dry-run 验证）
- [ ] P0-NEW-2：`CAPABILITY_SEED_MAP["multi_agent"]` 映射完整
- [ ] P0-NEW-3：MCP 动态种子链路接通
- [ ] P0-NEW-4：死代码确认清除

### 10.2 ASR 主链路健康标准

- [ ] 单轮攻击（PromptSending）可达
- [ ] 升级链完整（L1→L4）可达
- [ ] 目标类别攻击（单 Agent/多 Agent/A2A/MCP/Embedding）均有执行路径

### 10.3 架构健康标准

- [ ] main.py < 500 行
- [ ] 所有模块 < 500 行
- [ ] 编码损坏清零
- [ ] 门禁完整（无空洞）

### 10.4 文档同步标准

- [ ] `specs/10-ARCHITECTURE.md` 债务簿 D-10/D-11/D-12 修正
- [ ] `specs/20-REQUIREMENTS.md` 新增 P0-NEW 发现的需求缺口
- [ ] `specs/50-ROADMAP.md` T0 紧急任务同步

---

## 版本记录

| 版本 | 日期 | 变更摘要 | 批准 |
|------|------|---------|------|
| v1.0 | 2026-09-06 | 首次全面代码审计：P0-NEW 致命缺陷、五类攻击完成度、债务验证与修正、巨石分层违规、工具链卫生、场景特异性分析 | — |
