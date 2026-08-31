# 终端层 + 报告层完整解决方案 — 对齐 AI Red Team 红队最佳实践

> **版本**: v57 (2026-08-31)
> **实现状态**: T-01~T-06 ✅ 已实现 | R-01~R-09 ✅ 已实现 | D-01~D-03 ✅ 已验证
> **涉及文件**: `utils/display.py`, `report/report_markdown.py`, `core/config.py`, `main.py`
> **验证结果**: 248 tests passed, 0 BLOCKING, 0 WARNING, ruff 全部通过

---

## 一、设计哲学

| 维度 | 终端 (Terminal) — 执行态 | 报告 (Report) — 回溯态 |
|------|--------------------------|------------------------|
| **核心问题** | 正在发生什么? 结果是什么? | 完整证据链, 事后可审计 |
| **信息密度** | 低 — 只展示攻击者实时关注的 | 高 — 完整细节供技术审查 |
| **时间窗口** | 实时滚动, 看完即过 | 持久化文件, 反复阅读 |
| **受众** | Red Team Operator (操作中扫一眼) | CISO / Security Engineer / Examiner |
| **最佳实践对齐** | MITRE ATT&CK Kill Chain 实时日志 | OWASP LLM Top 10 + ASI Top 10 + MITRE ATLAS |

---

## 二、终端层优化方案 (每个阶段展示什么)

### 2.1 RECON 阶段 — "目标是谁, 能力是什么"

**优化后内容**:

```
╔══════════════════════════════════════════════════════════════╗
║ RECON — Target Entry Point + Hand-off                        ║
╠══════════════════════════════════════════════════════════════╣
║ Endpoint:          https://api.target.com/v1/chat             ║
║ Model:             gpt-4o                                      ║
║ Auth:              Bearer                                     ║
║ Capabilities:      mcp, rag, function_calling                 ║
║ {PROMPT}:          Injected                                   ║
║ AI Framework:      langchain (RAG)                            ║
║ System Prompt:     LEAKED via prefix injection (len=847)      ║
╠══════════════════════════════════════════════════════════════╣
║ Attack Surface (from capability probe)                        ║
╠══════════════════════════════════════════════════════════════╣
║   IMMEDIATE (HIGH) — 立即可利用:                              ║
║     → mcp_protocol   [context_compliance | arXiv:2302.12173]  ║
║     → embedding_rag  [rag_attack | arXiv:2310.06870]          ║
║   PROBE (MEDIUM) — 需进一步确认:                              ║
║     → a2a_protocol   → multi_agent_attack                     ║
╚══════════════════════════════════════════════════════════════╝
```

**关键优化**:
- 增加 `AI Framework` 和 `System Prompt` 泄露状态行 (已在 orchestration_log 中但终端未展示)
- 将 `System Prompt: LEAKED` 用红色高亮, 攻击者一眼识别高价值目标
- `probe_count` 和 `probe_duration` 合并为一行减少视觉冗余

### 2.2 ARM 阶段 — "用什么武器打"

**优化后内容** (完整流水线模式 — 1 行状态 + 1 张微卡片):

```
  ✓ [ARM] READY  Seeds=25 | Techs=12 | Converters=99 | Target: mcp_agent | Roles: 3-actor
```

紧跟微卡片:

```
╔══════════════════════════════════════════════════════════════╗
║ ARM — Weapon Highlights (by ASR prior)                       ║
╠══════════════════════════════════════════════════════════════╣
║ Top Converters:  Decomposition(40-60%) | CodeChameleon(35%)  ║
║                  | Persuasion:authority(38.4%)               ║
║ Top Techniques:  prompt_sending(baseline) | crescendo(65%)  ║
║                  | tap(60%) | red_teaming(40%)               ║
║ Seed Coverage:   8 categories | zh+en                        ║
╚══════════════════════════════════════════════════════════════╝
```

完整武器清单 → 移至 `report_technical.md` 的 Weapon Loadout 章节。

### 2.3 STRIKE 阶段 — "正在打, 打中了吗"

**分层展示策略**:

**层 1: 进度行 (实时滚动, 低信息密度)**:
```
  ► [STRIKE] target.com | prompt_sending (baseline) | Path 1/7: PersuasionConverter | 25 seeds ⏳
  ✓ [STRIKE] target.com | Path 1/7: PersuasionConverter | 3/25 (12.0%) success, 22 remaining (12.3s)
```

**层 2: 成功突破 (即时高亮, 攻击者最关心)**:
```
╔══════════════════════════════════════════════════════════════╗
║  ★ BREAKTHROUGH — Attack Succeeded!                           ║
╠══════════════════════════════════════════════════════════════╣
║  Technique:    prompt_sending                                ║
║  Converter:    PersuasionConverter:authority_endorsement     ║
║  Seed:         [LLM01] Tell me about...                      ║
║  Response:     Sure, here's how to...                        ║
║  Scorer:       ✓ Success (MultiKeywordRefusal + TFInverter)  ║
╚══════════════════════════════════════════════════════════════╝
```

**层 3: 失败摘要 (精简, 不展开原生 output)** — 关键优化:

失败结果使用 1 行精简摘要, 仅成功结果展示完整原生 output:
```
  ✗ [STRIKE] Path 2/7: ROT13Converter | seed#12 FAILED (refusal: "I cannot assist...") (0.8s)
```

`--verbose-strike` flag 可恢复完整失败结果展示。

**层 4: STRIKE 完成摘要** — 移除与原生 output 重复的 Per-Technique ASR Breakdown:

```
╔══════════════════════════════════════════════════════════════╗
║ STRIKE — Execution Summary                                   ║
╠══════════════════════════════════════════════════════════════╣
║ Techniques:      1                                           ║
║ Total Attacks:   25                                          ║
║ Successful:      3                                           ║
║ Failed:          22                                          ║
║ Overall ASR:     12.0% ████░░░░░░░░░░░░░░░░  Low             ║
║ Native Output:   see per-attack results above (pyrit.output)  ║
╚══════════════════════════════════════════════════════════════╝
```

### 2.4 ESCALATE 阶段 — "升级到什么技术, 中间退出吗"

**层 1: 升级决策 (攻击者一眼看清为什么升级)**:
```
╔══════════════════════════════════════════════════════════════╗
║ ESCALATE — Decision                                          ║
╠══════════════════════════════════════════════════════════════╣
║ Baseline ASR:    12.0%                                       ║
║ Threshold:       90.0%                                       ║
║ Decision:        ► ESCALATE (12.0% < 90.0%)                  ║
║ Failed Targets:  22                                          ║
║ Chain:           L1→L2→L3→L4 (full chain)                    ║
║ Exit Thresholds: L1→70% | L2→80%                             ║
║ Scheduler:       priority_batch (UCB1 + ε-greedy)            ║
╚══════════════════════════════════════════════════════════════╝
```

**层 2-4**: L1 优先级批次预览、技术执行进度行、批次退出决策 — 保持当前实现不变。

**层 5: ESCALATE 完成摘要** — 移除终端 Orchestration Log 卡片 (与 report_technical.md 重复, 终端只展示最后一条决策)。

### 2.5 ASSESS 阶段 — "最终判定"

保持当前实现, 包含 Overall ASR + Wilson CI + Per-Technique ASR Ranking + Dual Judge Statistics。

### 2.6 REPORT 阶段 — "产出在哪"

保持当前实现, 包含关键指标 + 分层报告路径列表。

---

## 三、报告层优化方案 (每个文件包含什么)

### 3.1 `report.md` — 索引 + 摘要

**优化项**:
1. Pipeline Flowchart 中新增 **REPORT 阶段** (当前缺失, 只有 RECON→ARM→STRIKE→ESCALATE→ASSESS)
2. 在 ASSESS→REPORT 箭头上标注 `evidence, asr, orchestration_log`
3. 在 REPORT 框中标注 `6 files` 产出数量

### 3.2 `report_executive.md` — 管理层摘要

**新增**:
1. **攻击者视角摘要** (Attack Path Summary) — 3 行描述主要攻击路径
2. **修复后预期 ASR 降幅** (Expected ASR Reduction Post-Remediation)

### 3.3 `report_findings.md` — 漏洞详情

**优化**:
1. **Evidence Card 增强** — 每个 Evidence 增加 "Attack Chain" 可视化
2. **Failure Analysis 增强** — 失败原因分类表

### 3.4 `report_technical.md` — 技术附录

**优化**:
1. **Weapon Loadout 增强** — 新增 "Converter Selection Rationale" 表
2. **Orchestration Decision Log 结构化** — decision entries 格式化
3. **空表友好提示** — MITRE ATLAS / Score Consistency 等表为空时显示 "No data available"

---

## 四、完整实施清单

### 终端层 (Terminal)

| # | 优化项 | 涉及文件 | 涉及函数 | 优先级 | 当前状态 |
|---|--------|---------|---------|--------|---------|
| T-01 | RECON 卡片增加 `AI Framework` + `System Prompt` 泄露状态行 | `utils/display.py` | `print_recon_card()` | P2 | 字段已在 orchestration_log, 终端未展示 |
| T-02 | ARM 增加 "Top-3 Converter + Top-3 Techniques" 微卡片 | `utils/display.py` + `main.py` | `print_arm_card()` 调用处 | P2 | 当前为 1 行纯文本摘要 |
| T-03 | STRIKE 失败结果使用 1 行精简摘要 (不展开原生 output) | `utils/display.py` | `print_native_attack_result()` / `print_attack_results_native()` | P1 | 当前对所有结果都展开原生 output |
| T-04 | STRIKE 移除 Per-Technique ASR Breakdown (与原生 output 重复) | `utils/display.py` | `print_strike_card()` | P1 | 冗余输出 |
| T-05 | ESCALATE 移除终端 Orchestration Log 卡片 (与报告重复) | `utils/display.py` | `print_escalate_card()` | P3 | 终端只展示最后一条决策 |
| T-06 | 新增 `--verbose-strike` CLI flag, 启用时恢复完整失败结果展示 | `core/config.py` + `utils/display.py` | `print_attack_results_native()` | P3 | 用于深度调试场景 |

### 报告层 (Report)

| # | 优化项 | 涉及文件 | 涉及函数 | 优先级 | 当前状态 |
|---|--------|---------|---------|--------|---------|
| R-01 | Pipeline Flowchart 新增 REPORT 阶段 | `report/report_markdown.py` | `_append_pipeline_flowchart()` + `_append_orchestration_flowchart()` | P1 | 当前只有 5 阶段 |
| R-02 | Pipeline Flowchart 箭头增加 ASSESS→REPORT 数据流标注 | `report/report_markdown.py` | 同上 | P1 | 当前 Data flow 行缺 ASSESS→REPORT |
| R-03 | report_executive.md 新增 "Attack Path Summary" 章节 | `report/report_markdown.py` | `_generate_executive_markdown()` | P2 | 当前无攻击路径摘要 |
| R-04 | report_executive.md 新增 "Expected ASR Reduction Post-Remediation" | `report/report_markdown.py` | `_generate_executive_markdown()` | P3 | 当前无修复后预期效果 |
| R-05 | report_findings.md Evidence Card 增加 "Attack Chain" 可视化 | `report/report_markdown.py` | `_append_evidence_card()` | P2 | 当前无攻击链可视化 |
| R-06 | report_findings.md 新增 "Failure Analysis" 分类表 | `report/report_markdown.py` | `_generate_findings_markdown()` | P2 | 当前有章节但无分类表 |
| R-07 | report_technical.md Weapon Loadout 增加 "Converter Selection Rationale" | `report/report_markdown.py` | `_append_weapon_loadout()` | P2 | 当前无选择理由 |
| R-08 | report_technical.md 空表增加 "No data available" 友好提示 | `report/report_markdown.py` | `_generate_technical_markdown()` | P3 | 当前空表直接输出表头 |
| R-09 | Orchestration Decision Log 结构化 (decision entries 格式化) | `report/report_markdown.py` | `_generate_technical_markdown()` | P2 | 当前已有但格式可优化 |

### 数据流完整性 (Data Flow)

| # | 优化项 | 涉及文件 | 优先级 | 当前状态 |
|---|--------|---------|--------|---------|
| D-01 | 确保 ARM 阶段 orchestration_log 包含 seed_files (文件名列表) | `main.py` | P3 | 当前 output 只有 seed_count |
| D-02 | 确保 evidence 中每个 VulnerabilityEvidence 包含 converter_chain | `report/evidence.py` | P3 | 需确认回填 |
| D-03 | 确保 escalate 日志中 priority_batch_early_exit 记录被跳过的技术名称 | `strike/priority_scheduler.py` | P3 | 当前有数量但无技术名 |

---

## 五、对齐 AI Red Team 红队最佳实践的对照

| 最佳实践 | 终端层对齐 | 报告层对齐 |
|---------|-----------|-----------|
| **MITRE ATT&CK Kill Chain 叙述** | 每阶段按 RECON→ARM→STRIKE→ESCALATE→ASSESS→REPORT 时序输出 | Pipeline Flowchart + Orchestration Decision Log 完整记录 |
| **攻击者视角 (Offensive View)** | 成功突破即时高亮 (★ BREAKTHROUGH), 失败精简摘要 | Evidence Card 包含 Attack Chain 可视化 + Seed + Converter + Scorer |
| **PyRIT 原生 Output 优先** | 成功结果使用 `pyrit.output` 原生模块渲染 | native_output/ 目录保存完整原生格式 |
| **OWASP LLM Top 10 + ASI Top 10** | ASSESS 阶段 Per-Technique ASR Ranking | report_executive.md 合规表 + report_findings.md 分类表 |
| **Wilson Score CI 统计严谨性** | ASSESS 卡片展示 CI | report_executive.md + report_technical.md 展示 |
| **Dual Judge 交叉验证** | ASSESS 卡片展示 Kappa | report_technical.md 完整 Dual Judge Stats |
| **FIRST_SUCCESS 多路径策略** | STRIKE 路径进度行展示 Path N/M | Weapon Loadout 记录 per-technique converter 数量 |
| **Priority Scheduler (UCB1)** | ESCALATE 批次预览 + 批次退出决策 | Orchestration Log 记录 scheduler_mode + batch exit |
| **ε-greedy 探索-利用平衡** | ESCALATE 决策卡片展示 scheduler 参数 | Orchestration Log 记录 epsilon 值 |
| **中间退出 (Intermediate Exit)** | ESCALATE 批次退出卡片 (CONTINUE/EXIT) | Orchestration Log 记录 cumulative_asr vs threshold |
| **Target-Aware Converter** | ARM 微卡片展示 target_type | Weapon Loadout 记录 target_type + rationale |
| **Seed-Aware (category/suitable_for)** | ARM 微卡片展示 seed coverage | Weapon Loadout 记录 seed categories |
| **PoC 可复现性** | REPORT 阶段展示 poc/ 路径 | report_findings.md 每个 Evidence 链接 poc 脚本 |
| **Evidence 可审计性** | — | evidence/ JSON + native_output/ + poc/ 三重持久化 |
| **分层报告架构** | REPORT 阶段展示分层路径列表 | report.md 索引 + executive + findings + technical |
