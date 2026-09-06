# specs/ — 规约金字塔（项目治理文件索引）

本项目 AI 编码行为的全部规约。**裁决序**（宪法第二章）：00 宪法 > 10 蓝图 > 20 需求 > 30 任务 > 40 护栏 > 用户即时指令（仅经合法通道生效） > AI 自由裁量（默认权限为零）。护栏**红线部分**视同宪法级。

| 层 | 文件 | 职责 | 版本 |
|----|------|------|------|
| L0 | [00-CONSTITUTION.md](00-CONSTITUTION.md) | AI 行为宪法：使命 / 裁决序 / C1-C12 / 违宪症状速查表 / 制宪配套附则 | v1.2 |
| L1 | [10-ARCHITECTURE.md](10-ARCHITECTURE.md) | 技术蓝图：分层与依赖矩阵 / 阶段词汇映射 / ctx 契约 / 不变量 I1-I10 / ADR / 债务簿 D-01~D-16 | v1.3 |
| L2 | [20-REQUIREMENTS.md](20-REQUIREMENTS.md) | 需求登记：REQ-001~008（P0）/ REQ-101~108（P1）/ REQ-109~113（考域）/ REQ-114~119（P0-NEW）/ NFR / NEG 负需求 / 状态登记表 | v1.3 |
| L3 | [30-TASKS.md](30-TASKS.md) | 任务协议：生命周期 / 粒度硬上限 / 八步协议 / STOP-REPORT / 三栏汇报格式 | v1.2 |
| L4 | [40-GUARDRAILS.md](40-GUARDRAILS.md) | 红线 R-L / R-H / R-S / 四步门禁 / 三层防线 / 检查器登记簿 | v1.2 |
| 配套 | [50-ROADMAP.md](50-ROADMAP.md) | 使命执行路线图：源码审计基线 / AI-300 考纲映射 / 红队最佳实践 / 阶段任务序列 / vibe coding 会话模型 / 考试日 Runbook | v1.0 |
| 配套 | [templates/task-spec.md](templates/task-spec.md) | 任务规格模板（宪法 C6、30-TASKS 第四章） | v1.0 |
| 配套 | [templates/change-proposal.md](templates/change-proposal.md) | 变更提案模板（宪法 C12、20-REQUIREMENTS 第五章） | v1.0 |
| 配套 | [backlog.md](backlog.md) | 唯一待办池（宪法 C4 豁免通道） | v1.2 |

## AI 会话标准动线（30-TASKS 第四章八步协议的入口）

1. 每会话至少读一次 00（Step 1 宪法自检）；
2. 查 [50-ROADMAP.md](50-ROADMAP.md) 第四章任务序列领取下一个任务（顺序以路线图为准）；
3. 按任务读 10 相关章节并**声明落点**（模块/依赖方向/ctx 字段/invariants）；
4. 核对 20 对应 REQ 验收标准，抄入 task-spec；
5. 全程遵守 30 八步协议，收尾跑 40 第二章四步门禁并按三栏格式汇报。

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

## 边界说明

- 本目录**只含规约层文档**。被治理的代码库位于 github.com/hmbphxkw76-byte/osai/pyrit-mini——REV-02 已完成文件级审计（commit 0b8e28c，见 50-ROADMAP 第一章），guard 18 项检查器锚点与深读核验仍待首个代码会话（BL-001）。
- 规约文件被修改时，**必须**同步更新：文件头版本号、文末版本记录表、本索引版本列。
