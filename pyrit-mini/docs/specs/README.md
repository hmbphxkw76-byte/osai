# specs/ — 规约金字塔（项目治理文件索引）

本项目 AI 编码行为的全部规约。**裁决序**（宪法第二章）：00 宪法 > 10 蓝图 > 20 需求 > 30 任务 > 40 护栏 > 用户即时指令（仅经合法通道生效） > AI 自由裁量（默认权限为零）。护栏**红线部分**视同宪法级。

> **双使命**：① 产品使命 = Burp 黑盒目标 ASR 最大化 + 可复现证据链；② 认证使命 = OffSec AI-300/OSAI 备考武器化（24h 实战 + 24h 报告）。

---

## 🎯 三元组开发规范（最精简记忆）

> **记忆口诀**：开发必看 → 开发必跑 → 开发必验

| 阶段 | 触发词 | 别名 | AI 自动执行 | 覆盖内容 |
|------|--------|------|------------|---------|
| **开发前** | **`开发规范`** | **开发必看** | 查看文档 | 宪法 / 蓝图 / 需求 / 红线 |
| **开发中** | **`开发验证`** | **开发必跑** | 跑检查 + 自动修复 | guard → ruff → test → dry-run → drift → dataflow |
| **开发后** | **`开发交付`** | **开发必验** | 跑验收清单 | 40-GUARDRAILS 第七章交付标准 |

> **同义词**：
> - `"开发必看"` = `"开发规范"`（开发前必看）
> - `"开发必跑"` = `"开发验证"` = `"完整验证"` = `"规范对齐"`（开发中必跑）
> - `"开发必验"` = `"开发交付"` = `"交付标准"`（开发后必验）

### 📋 开发规范覆盖的文档（开发前必看）

| 文档 | 内容 | 作用 |
|------|------|------|
| `00-CONSTITUTION` | AI 行为宪法、裁决序、C1-C15 | 了解 AI 行为边界 |
| `10-ARCHITECTURE` | 分层依赖、ctx 契约、不变量 | 了解架构设计 |
| `20-REQUIREMENTS` | P0/P1/P2 需求、NFR、NEG | 了解需求状态 |
| `30-TASKS` | 任务生命周期、八步协议 | 了解任务执行流程 |
| `40-GUARDRAILS` | 红线清单、R-CROSS 跨模型红线 | 了解红线与门禁 |
| `50-ROADMAP` | 任务序列、会话模型 | 了解开发路线 |
| `55-ATTACK-GAP` | 攻击缺口闭环状态 | 了解攻击覆盖 |
| `60-CROSS-MODEL-VERIFICATION` | 跨模型审查协议、三级仲裁 | 了解跨模型一致性 |

### 🔧 开发验证覆盖的工具（开发中必跑）

| 工具/命令 | 作用 | 通过标准 |
|-----------|------|---------|
| `py -m tools.guard` | 架构守卫静态检查 | 0 BLOCKING |
| `ruff check .` | 代码风格检查 | 0 errors |
| `pytest tests/` | 全量测试 | 0 failed |
| `python main.py --dry-run` | 运行时数据流验证 | 无异常 |
| `py -m tools.drift_detector --full` | 规范漂移检测 | 0 BLOCKING |
| `pytest tests/test_data_flow_integrity.py` | 数据流完整性 | 全部通过 |

### 📝 开发交付覆盖的标准（开发后必验）

| 标准 | 来源 | 格式 |
|------|------|------|
| 交付验证清单 | 40-GUARDRAILS 第七章 | 架构规则+代码质量+测试覆盖+集成点 |
| 任务验收标准 | templates/task-spec.md | 任务规格验收 |
| 待办闭环 | backlog.md | BL-xxx 状态更新 |

---

## 🚀 完整验证（一键触发）

> **触发词**：**"完整验证"** / **"规范对齐"** / **"开发验证"** / **"开发必跑"**

当用户对 AI 说出触发词时，自动执行以下 6 步验证 + 修复所有问题 + 汇报最终结果：

| 步骤 | 命令 | 通过标准 | 自动修复 |
|------|------|---------|---------|
| 1 | `py -m tools.guard` | 0 BLOCKING | 修复 BLOCKING 违规 |
| 2 | `ruff check .` | 0 errors | `ruff check --fix` 自动修复 |
| 3 | `pytest tests/ -v --tb=short` | 0 failed | 分析并修复 |
| 4 | `python main.py --dry-run --max-seeds 1` | 无异常 | 修复数据流断点 |
| 5 | `py -m tools.drift_detector --full` | 0 BLOCKING | 同步文档/代码 |
| 6 | `pytest tests/test_data_flow_integrity.py -v` | 全部通过 | 修复契约违规 |

**详细规则文档**: `tools/__init__.py` — 【完整验证触发规则】
**快速参考卡片**: `DEV-TRIAD-CHECKLIST.md` — 【开发全审速查表】

---

## 🎯 开发规范触发词汇总

| 类别 | 触发词 | AI 自动执行 |
|------|--------|------------|
| **核心操作** | `"完整验证"` / `"规范对齐"` / `"开发验证"` / `"开发必跑"` | 6 步全流程验证 + 修复 |
| | `"门禁"` | 四步质量门禁 |
| | `"守卫"` | 架构守卫静态检查 |
| | `"漂移"` | 规范漂移检测 |
| | `"数据流"` | 数据流完整性验证 |
| | `"交付标准"` / `"开发交付"` / `"开发必验"` | 按 40-GUARDRAILS 第七章生成验收清单 |
| **开发流程** | `"开发规范"` / `"开发必看"` | 查看 宪法/蓝图/需求/红线 |
| | `"领任务"` | 从 50-ROADMAP 查看下一个任务 |
| | `"任务规格"` | 生成 TASK-xxx 规格文件 |
| | `"宪法"` | 查看 00-CONSTITUTION 核心条款 |
| | `"蓝图"` | 查看 10-ARCHITECTURE 架构设计 |
| | `"需求"` | 查看 20-REQUIREMENTS 需求状态 |
| | `"红线"` | 查看 40-GUARDRAILS 红线清单 |
| **快速检查** | `"lint"` | ruff check . 代码风格检查 |
| | `"dry-run"` | python main.py --dry-run 运行时验证 |
| | `"测试"` | pytest tests/ 运行测试 |
| | `"backlog"` | 查看/登记待办池 |
| | `"hooks"` | 安装/检查 git hooks |
| **跨模型审查** | `"跨模型审查"` | 执行跨模型规约审查（FULL 模式：3 模型并行 + κ 计算 + 仲裁） |
| | `"交叉校验"` | 执行跨模型交叉确认（LIGHT 模式：1 模型快速审查） |
| | `"审查报告"` | 查看最新跨模型审查报告 |
| **考试场景** | `"考试模式"` | 切换为 OffSec AI-300 考试流程 |
| | `"考试合规"` | 运行 7D 定期自检 |
| | `"模板"` | 查看攻击模板速查表 (TPL-*) |

---

| 层 | 文件 | 职责 | 版本 |
|----|------|------|------|
| L0 | [00-CONSTITUTION.md](00-CONSTITUTION.md) | AI 行为宪法：使命 / 裁决序 / C1-C14 (含跨模型一致性优先) / 违宪症状 / 制宪配套 / 考试专项附录 | v2.2 |
| L1 | [10-ARCHITECTURE.md](10-ARCHITECTURE.md) | 技术蓝图：分层依赖 / ctx 契约（4.4 SSOT 总表） / 不变量 / ADR / 债务簿 / PyRIT攻击引擎 / Web攻击层 + 数据流完整性 / 全链路自主决策引擎 (第十一章) / 跨模型规约审查架构 (第十二章) | v2.8 |
| L2 | [20-REQUIREMENTS.md](20-REQUIREMENTS.md) | 需求登记：P0 (已实现 ✅) / P1 (已实现 ✅) / 活跃需求 / NFR（含 NFR-13 ASR 双口径与 target_asr 锚点 + NFR-14~16 审查非功能） / NEG / 自主决策需求 / 文件上传攻击需求 (REQ-138~144) / 跨模型审查需求 (REQ-144~146) | v2.5 |
| L3 | [30-TASKS.md](30-TASKS.md) | 任务协议：生命周期 / 粒度上限 / 八步协议 / STOP-REPORT / 考试速查 / 跨模型审查任务协议 (第十章) | v2.2 |
| L4 | [40-GUARDRAILS.md](40-GUARDRAILS.md) | 红线 R-L / R-H / R-S / R-WEB (含R-WEB-6任意端口) / R-DRIFT / R-DATA / R-DECIDE / R-TOOLS / R-DOC (代码-文档同步，含R-DOC-5命令行文档) / R-CROSS (跨模型审查) / 四步门禁 / 三层防线 / 登记簿 (46项，1F 唯一，含R-L1/R-L7新实现) / 交付验证清单 (7D CLI文档验收) / 考试合规 / spec-code drift 修复 (v3.0) | v3.0 |
| 配套 | [50-ROADMAP.md](50-ROADMAP.md) | 路线图：AI-300 考纲映射 / 红队实践 / 基准校准 (阶段 0.5) / 任务序列 / 会话模型 / Runbook / 考试日故障降级矩阵 / 跨模型审查系统 (阶段 1D) | v1.10 |
| 配套 | [55-ATTACK-GAP-CLOSURE.md](55-ATTACK-GAP-CLOSURE.md) | 攻击缺口闭环：四大缺口分析 / 文件上传攻击缺口 (v1.4新增) / 黑盒可测性约束 (4.1-B) / 全链路自主决策架构 / 跨模型规约审查集成 (v1.5新增) / A2A多智能体侦察框架 (v1.7新增) / Workflow Evasion安全扫描绕过 (v1.8新增) | v1.8 |
| 配套 | [60-CROSS-MODEL-VERIFICATION.md](60-CROSS-MODEL-VERIFICATION.md) | 跨模型规约审查协议：审查模型注册簿 / 触发规则 / Prompt模板 / 差异对齐 / 仲裁协议 / Schema标准 / 存储结构 / κ度量指标 / 工具链集成 | v1.0 |
| 配套 | [templates/task-spec.md](templates/task-spec.md) | 任务规格模板 + 考试变体 | v1.1 |
| 配套 | [templates/cross-model-review.md](templates/cross-model-review.md) | 跨模型审查报告模板（快速决策卡 + 差异对齐表 + κ指标 + 修复清单） | v1.0 |
| 配套 | [templates/change-proposal.md](templates/change-proposal.md) | 变更提案模板 | v1.0 |

> **已归档文件**：
> - `45-DATA-FLOW-INTEGRITY.md` → 合并入 `10-ARCHITECTURE.md` 第四章（PipelineContext 数据契约 + Phase 字段契约 + 数据传递规则）。原独立文档不再独立维护，验证工具链（`tools/data_flow_validator.py` + 29 项测试）仍正常运行。
> - `60-REDTEAM-DELIVERY-FRAMEWORK.md` → 合并入 `40-GUARDRAILS.md` 第七章。原独立文档不再维护，验证工具链仍正常运行。

---

## AI 会话标准动线（30-TASKS 第四章八步协议的入口）

**标准模式**（开发期）：
1. 每会话至少读一次 00（Step 1 宪法自检）；
2. 查 [50-ROADMAP.md](50-ROADMAP.md) 第四章任务序列领取下一个任务（顺序以路线图为准）；
3. 按任务读 10 相关章节并**声明落点**（模块/依赖方向/ctx 字段/invariants）；
4. 核对 20 对应 REQ 验收标准，抄入 task-spec；
5. 全程遵守 30 八步协议，收尾跑 40 第二章四步门禁并按三栏格式汇报。

**考试模式**（OffSec AI-300 实战，使用 30-TASKS 第九章变体协议）：
1. 考前读 00-第七章（7D 合规检查单）+ 确认 .env 就绪；
2. 读 50-ROADMAP 第八章（8A 评分卡确认就绪等级 ≥ B）；
3. 目标下发后：recon fingerprint → 查 00-7B 攻击匹配表选模板（TPL-*）；
4. 按 50-ROADMAP 8C Playbook 执行四步压缩协议（S1→S4）；
5. 每 4h 跑 40-第八章 7D 定期自检（目标/工具/证据/密钥/时间盒）。

---

## 变更流程

- **宪法**：C12 修正案——change-proposal + 人工批准 + 版本号与本索引同批更新 + 受影响 guard 检查器同步；
- **蓝图 / 需求**：20-REQUIREMENTS 第五章流程（change-proposal → 登记 → 任务规格 → 编码）；
- **路线图**：阶段与任务序列变更走 change-proposal（规格变更流程）；
- **模板与索引**：随其服务层级变更，同批更新本表版本号。

---

## 项目使命（一切裁决的终极问题）

对 Burp 拦截的、基于 LLM 开发的 AI 应用（黑盒 HTTP 目标），以攻击成功率（ASR）为首要度量，交付可复现的完整攻击证据链——**这个决定让 ASR 变高还是变低？**（仅限 R-S1~R-S5 授权边界之内，见宪法 C2 边界条款）

第二使命（REV-02 登记）：OffSec AI-300/OSAI 备考武器化——本项目作为考试合法工具链（允许 PyRIT/Burp/自写脚本/个人笔记），映射与规划见 50-ROADMAP。

---

## 项目级资产（docs/ 根目录）

| 文件 | 职责 | 关联 |
|------|------|------|
| [backlog.md](../backlog.md) | 唯一待办池（宪法 C4 豁免通道） | 任务 BL-xxx 登记 → 转化为 REQ / DEBT / 任务规格 |

---

## CLI 命令速查 (tools/)

开发期常用工具入口 (`pip install -e .` 后 entry_points 可用)：

| 命令 | 功能 | 使用场景 |
|------|------|----------|
| `pyrit-guard` (或 `py -m tools.guard`) | 宪法守卫 (R-H1/H2/H3 + 红线护栏) | 每次开发后、提交前 |
| `pyrit-drift` (或 `py -m tools.drift_detector`) | 规范漂移检测 (快速模式，不含版本锁定) | **开发时高频检测** |
| `pyrit-drift --full` | 规范漂移检测 (全量模式，含版本锁定) | 发布前/CI/CD |
| `pyrit-drift --full --report` | JSON 报告输出 | CI 集成 |
| `pyrit-dataflow` (或 `py -m tools.data_flow_validator`) | 数据流完整性验证 (ARM→Strike→Assess) | commit/push 时自动触发 |
| `pyrit-cross` (或 `py -m tools.cross_model_review`) | 跨模型规约审查（FULL 模式：3 模型并行 + κ 计算 + 仲裁） | 规约文档变更时触发 |
| `pyrit-cross --full` | 全量跨模型审查 | L0-L4 核心文档变更时 |
| `pyrit-cross --light` | 快速单模型审查 | 单文件 docstring/注释变更时 |
| `pyrit-watch` (或 `py -m tools.watch_guard`) | 实时文件监视 | 开发期持续运行 |
| `pyrit-quick` (或 `py -m tools.quick_check`) | 单文件快速架构检查 | 修改单个模块后 |
| `pyrit-hooks` (或 `py -m tools.hooks`) | Git hooks 安装 | 初始化工作区 |

**别名规律**：`py -m tools.xxx` = `pyrit-xxx`（entry_points 注册）

---

## 边界说明

- 本目录**只含规约层文档**。被治理的代码库位于 github.com/hmbphxkw76-byte/osai/pyrit-mini。
- 规约文件被修改时，**必须**同步更新：文件头版本号、文末版本记录表、本索引版本列。
- **已删除文档**（2026-09-09 清理）：
  - `35-MULTIMODAL_ASSESSMENT.md`
  - `36-LLM06_SANDBOX_ESCAPE_OPTIMIZATION.md`
  - `MIGRATION.md`
  - `60-REDTEAM-DELIVERY-FRAMEWORK.md`（合并入 40-GUARDRAILS.md）
  - `tasks/TASK-A2A-001.md` / `tasks/TASK-A2A-002.md`（stale 任务规格）
  - `remediation/` 目录（历史审计报告已闭环）
