# specs/ — 规约金字塔（项目治理文件索引）

本项目 AI 编码行为的全部规约。**裁决序**（宪法第二章）：00 宪法 > 10 蓝图 > 20 需求 > 30 任务 > 40 护栏 > 用户即时指令（仅经合法通道生效） > AI 自由裁量（默认权限为零）。护栏**红线部分**视同宪法级。

> **双使命**：① 产品使命 = Burp 黑盒目标 ASR 最大化 + 可复现证据链；② 认证使命 = OffSec AI-300/OSAI 备考武器化（24h 实战 + 24h 报告）。

| 层 | 文件 | 职责 | 版本 |
|----|------|------|------|
| L0 | [00-CONSTITUTION.md](00-CONSTITUTION.md) | AI 行为宪法：使命 / 裁决序 / C1-C13 / 违宪症状 / 制宪配套 / 考试专项附录 | v1.9 |
| L1 | [10-ARCHITECTURE.md](10-ARCHITECTURE.md) | 技术蓝图：分层依赖 / ctx 契约 / 不变量 / ADR / 债务簿 / PyRIT攻击引擎 / Glue层 | v2.1 |
| L2 | [20-REQUIREMENTS.md](20-REQUIREMENTS.md) | 需求登记：P0/P1/P0-NEW/P0-EXAM / NFR / NEG / 企业Glue需求 / 状态登记表 | v1.7 |
| L3 | [30-TASKS.md](30-TASKS.md) | 任务协议：生命周期 / 粒度上限 / 八步协议 / STOP-REPORT / 考试变体 | v1.3 |
| L4 | [40-GUARDRAILS.md](40-GUARDRAILS.md) | 红线 R-L / R-H / R-S / R-WEB / R-DRIFT / 四步门禁 / 三层防线 / 登记簿 (29项) / 考试合规 | v1.6 |
| 配套 | [50-ROADMAP.md](50-ROADMAP.md) | 路线图：AI-300 考纲映射 / 红队实践 / 任务序列 / 会话模型 / Runbook | v1.3 |
| 配套 | [60-REDTEAM-DELIVERY-FRAMEWORK.md](60-REDTEAM-DELIVERY-FRAMEWORK.md) | 红队交付保障框架：R-DELIVERY 规则 / 实时监视 (watch/quick) / 自动启动 / Git hooks | v2.2 |
| 配套 | [45-DATA-FLOW-INTEGRITY.md](45-DATA-FLOW-INTEGRITY.md) | 数据流完整性规约：Phase 字段契约 / 数据传递规则 / Git hooks | v1.0 |
| 配套 | [templates/task-spec.md](templates/task-spec.md) | 任务规格模板 + 考试变体 | v1.1 |
| 配套 | [templates/change-proposal.md](templates/change-proposal.md) | 变更提案模板 | v1.0 |
| 配套 | [backlog.md](backlog.md) | 唯一待办池 | v1.2 |
| 配套 | [templates/task-spec.md](templates/task-spec.md) | 任务规格模板 + **考试快速任务变体**（宪法 C6、30-TASKS 第四/九章） | v1.1 |
| 配套 | [templates/change-proposal.md](templates/change-proposal.md) | 变更提案模板（宪法 C12、20-REQUIREMENTS 第五章） | v1.0 |
| 配套 | [backlog.md](backlog.md) | 唯一待办池（宪法 C4 豁免通道） | v1.2 |

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
5. 每 4h 跑 40-第七章 7D 定期自检（目标/工具/证据/密钥/时间盒）。

## 变更流程

- **宪法**：C12 修正案——change-proposal + 人工批准 + 版本号与本索引同批更新 + 受影响 guard 检查器同步；
- **蓝图 / 需求**：20-REQUIREMENTS 第五章流程（change-proposal → 登记 → 任务规格 → 编码）；
- **路线图**：阶段与任务序列变更走 change-proposal（规格变更流程）；
- **模板与索引**：随其服务层级变更，同批更新本表版本号。

## 项目使命（一切裁决的终极问题）

对 Burp 拦截的、基于 LLM 开发的 AI 应用（黑盒 HTTP 目标），以攻击成功率（ASR）为首要度量，交付可复现的完整攻击证据链——**这个决定让 ASR 变高还是变低？**（仅限 R-S1~R-S5 授权边界之内，见宪法 C2 边界条款）

第二使命（REV-02 登记）：OffSec AI-300/OSAI 备考武器化——本项目作为考试合法工具链（允许 PyRIT/Burp/自写脚本/个人笔记），映射与规划见 50-ROADMAP。

## 交叉引用：整改中心

代码审计与整改已独立至 [remediation/](../remediation/) 目录：

| 目录 | 职责 | 关联 |
|------|------|------|
| [remediation/](../remediation/) | 整改中心：审计问题登记 / 整改验收标准 / P0-NEW 致命缺陷跟踪 | 整改任务必须引用本金字塔的 REQ ID + 宪法条款 + 不变量 |

**双向引用规则**：
- `remediation/audit-remediation.md` 每条整改项引用本目录的 REQ/C/I 条款
- 整改完成后必须同步更新 `20-REQUIREMENTS.md` 状态与本目录 `backlog.md`

## CLI 命令速查 (tools/)

开发期常用工具入口 (`pip install -e .` 后 entry_points 可用)：

| 命令 | 功能 | 使用场景 |
|------|------|----------|
| `pyrit-guard` (或 `py -m tools.guard`) | 宪法守卫 (R-H1/H2/H3 + 红线护栏) | 每次开发后、提交前 |
| `pyrit-drift` (或 `py -m tools.drift_detector`) | 规范漂移检测 (快速模式，不含版本锁定) | **开发时高频检测** |
| `pyrit-drift --full` | 规范漂移检测 (全量模式，含版本锁定) | 发布前/CI/CD |
| `pyrit-drift --full --report` | JSON 报告输出 | CI 集成 |
| `pyrit-dataflow` (或 `py -m tools.data_flow_validator`) | 数据流完整性验证 (ARM→Strike→Assess) | commit/push 时自动触发 |
| `pyrit-watch` (或 `py -m tools.watch_guard`) | 实时文件监视 | 开发期持续运行 |
| `pyrit-quick` (或 `py -m tools.quick_check`) | 单文件快速架构检查 | 修改单个模块后 |
| `pyrit-hooks` (或 `py -m tools.hooks`) | Git hooks 安装 | 初始化工作区 |

**别名规律**：`py -m tools.xxx` = `pyrit-xxx`（entry_points 注册）

## 边界说明

- 本目录**只含规约层文档**。被治理的代码库位于 github.com/hmbphxkw76-byte/osai/pyrit-mini。
- 规约文件被修改时，**必须**同步更新：文件头版本号、文末版本记录表、本索引版本列。
- 已删除文档：35-MULTIMODAL_ASSESSMENT.md / 36-LLM06_SANDBOX_ESCAPE_OPTIMIZATION.md / MIGRATION.md（2026-09-09 清理）。
