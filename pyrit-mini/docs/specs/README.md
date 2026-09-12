# specs/ — 规约金字塔（唯一权威入口）

> **本文件是整个项目文档体系的唯一入口。** 其他所有文档只准被本文件索引，不准自行复制本文件已声明的内容（宪法 C3）。

---

## 0. 三句话速记

| | |
|---|---|
| **使命** | 对 Burp 拦截的 LLM 应用（黑盒 HTTP 目标），以 **ASR 为首要度量**，交付可复现的完整攻击证据链。 |
| **裁决一切分歧的终极问题** | **这个决定让 ASR 变高还是变低？**（仅在 R-S1~R-S5 授权边界之内） |
| **裁决序** | 00 宪法 > 10 蓝图 > 20 需求 > 30 任务规格 > 40 护栏 > 用户即时指令（须经合法通道）> AI 自由裁量（默认 0 权限）。护栏**红线部分**视同宪法级。 |

> **第二使命**：OffSec AI-300 / OSAI 备考武器化（24h 实战 + 24h 报告）。映射与 Runbook 见 `50-ROADMAP.md`。

---

## 1. 文档地图（按需加载）

**规则**：只加载与当前任务相关的文件。禁止"全读一遍"。

| 层 | 文件 | 版本 | 职责 | 何时读 |
|----|------|------|------|--------|
| **入口** | [../../AGENTS.md](../../AGENTS.md) | v1.0 | AI 编码代理唯一入口（跨 IDE/跨模型自动加载）：冷启动顺序 / 编辑 specs 纪律 S1–S6 / 跨模型 review-only | 每个 AI 会话开头 |
| **L0** | [00-CONSTITUTION.md](00-CONSTITUTION.md) | v2.3 | AI 行为宪法：使命 / 裁决序 / C1–C14 / 违宪症状 / PyRIT 原生速查（7C）/ 考试附录 | 每会话开头（Step 1 宪法自检） |
| **L1** | [10-ARCHITECTURE.md](10-ARCHITECTURE.md) | v3.2 | 技术蓝图：分层依赖 / ctx 字段契约（4.4 SSOT 总表）/ 不变量 I1–I13 / ADR / 债务簿 / 目标架构 v4.0 | 编码前声明架构落点时（Step 2） |
| **L1** | [80-COMPONENT-ARCHITECTURE-RULES.md](80-COMPONENT-ARCHITECTURE-RULES.md) | v2.0 | 组件化规则：双命名空间 / 目录命名 / 新增组件 Checklist | 新增或修改组件时 |
| **L2** | [20-REQUIREMENTS.md](20-REQUIREMENTS.md) | v3.0 | 需求登记：P0/P1/P2、NFR、NEG。**未登记 = 不存在** | 领取任务时核对验收标准（Step 3） |
| **L3** | [30-TASKS.md](30-TASKS.md) | v2.3 | 任务协议：生命周期 / 粒度上限 / 八步协议 / STOP-REPORT / 三栏汇报 | 每次编码任务全程 |
| **L4** | [40-GUARDRAILS.md](40-GUARDRAILS.md) | v3.6 | 红线 R-* / 门禁纪律 / 三层防线 / 交付验证清单 / 考试合规 | 编码后验证（Step 7） |
| 配套 | [50-ROADMAP.md](50-ROADMAP.md) | v1.12 | 任务序列、考试 Runbook、考纲映射。**无裁决权威** | 领取下一个任务时 |
| 配套 | [55-ATTACK-GAP-CLOSURE.md](55-ATTACK-GAP-CLOSURE.md) | v1.8 | 攻击面缺口登记处（R-DOC-2 依赖，**路径勿改**） | 新增攻击模块时登记 |
| 配套 | [60-CROSS-MODEL-VERIFICATION.md](60-CROSS-MODEL-VERIFICATION.md) | v1.1 | 跨模型审查协议（C14 落地）：审查级别 / review-only 落笔权（§4.4）/ Schema | 变更 L0–L4 规约时 |
| 配套 | [90-AI-DEV-ARCHITECTURE.md](90-AI-DEV-ARCHITECTURE.md) | v1.0 | AI 编程总纲：产品契约（5 需求）→ 架构落点映射 / 遵循流程 / 差距指针（无独立裁决权威，只引用不复制） | 新会话冷启动 / 实施任务前定位落点 |
| 配套 | [plans/](plans/) | — | 活跃变更提案与执行计划 | 提案批准后才进入编码 |
| 模板 | [templates/](templates/) | — | `task-spec.md` / `change-proposal.md` / `cross-model-review.md` | 起草规格时 |
| 运行态 | [../backlog.md](../backlog.md) | — | 唯一待办池（AI 发现的非本任务问题一律入此，不动代码） | 会话收尾时 |

> 版本列由 R-DOC-4（`check_readme_version_synced`）自动校验：此处版本号与各文档文件头 `**版本**：vX.Y` 必须一致；不一致 → INFO 级漂移告警。

### 1.1 组件键的唯一来源

**`config/components/*.yaml` 是组件差异的唯一事实源**（ADR-007 / REQ-153）。规约层不得再抄写组件清单——本文件与 `80` 只定义**规则**，清单一律读 YAML：

```bash
python -c "from core.registry import get_registry; print(get_registry().keys())"
```

双命名空间定义（`id` vs `component_key`）见 `80-COMPONENT-ARCHITECTURE-RULES.md` 第二章。

---

## 2. 唯一门禁（SSOT —— 命令以代码为准，文档只描述阶段）

宪法 C10。**全部执行、全部通过、缺一不可、顺序固定**。

> ### ⚠️ 命令的唯一权威是 `tools/gate.py`，不是本表（ADR-009 / NFR-20）
>
> 本表只描述"**阶段 → 步骤 → 拦截什么**"。具体命令行由代码生成：
>
> ```bash
> python -m tools.gate --describe     # 输出 commit / push 两阶段的完整步骤清单
> ```
>
> 任何文档、钩子、CI **禁止手抄命令**——历史教训：本表曾长期声称 `tools.gate`
> 是"唯一代码实现"，而 gate 实际只跑了六步中的三步（E-01），手抄表无法发现这类失效。
> 现在由 `R-GATE-1` 检查器守护"阶段覆盖 ≡ 规约步骤"，不等价即 BLOCKING。

**统一入口（唯一）**：

| 场景 | 命令 |
|------|------|
| 每次变更后 | `python -m tools.gate --stage commit` |
| pre-push / CI | `python -m tools.gate --stage push` |

**阶段 → 步骤映射**（名称与 `tools/gate.py` 的 `STEP_DESCRIPTIONS` 一一对应）：

| 阶段 | 步骤 | 拦截什么 |
|------|------|---------|
| **commit** | 1 `guard` · 1.5 `architecture` · 2 `ruff` · 4 `dry-run` | 红线违规 / 架构越界 / 风格 / 运行时数据流断点 |
| **push**（含上列全部） | 3 `pytest` · 5 `drift` · 6 `dataflow` · 7 `e2e` | 功能回归 / 规范↔代码漂移 / ctx 契约 / 靶场端到端 |

> **为什么 `dry-run` 在 commit、`pytest` 在 push**（裁决 CP-004 §8.7 D-6）：`dry-run` 是唯一
> 0-token 的运行时证据，能在秒级发现 `ImportError`/`AttributeError`/`KeyError`/`TypeError`
> ——静态 guard 抓不到这类断点；`pytest` 全量放 commit 会诱导 `--no-verify`，
> 而绕过 hooks 比"晚一点发现"危险得多（40-G 第三章）。
>
> **禁止静默跳过**（NEG-9 / R-GATE-2）：依赖缺失 = 环境不合格 = 阻塞，不降级为 SKIP。
> **纪律**："改动很小"不豁免任何一步；guard 通过 ≠ 代码可用；门禁失败禁止标记任务完成。
> `tests/e2e/` 未落地前，e2e 步显式 INFO 跳过并登记 `BL-056`/`BL-069`（落地即改阻塞）。

**2026-09-11 基线**（变更前后对照用，非验收标准）：guard `0 blocking / 71 warning`；架构体检 `PASS 158 / WARNING 6 / BLOCKING 0`；pytest `1402 passed / 7 skipped`。

**2026-09-12 基线**（CP-002 五波次实施后，变更前后对照用，非验收标准）：guard `0 blocking / 79 warning`；架构体检 `PASS 154 / WARNING 0 / BLOCKING 0`；pytest `1812 passed / 7 skipped`；`python -m tools.mock_range --check` → PASS（5 类靶标）。L5 参数消费审计结论见 backlog `BL-034`；跨模型审查待办见 `BL-035`；深度探测预算与侦察接线残留见 `BL-036`；TargetAdapter 主链路归宿见 `BL-037`。

### 2.1 自动执行（防跑偏核心保障）

门禁若只靠"记得跑"必然漂移。本项目用三层强制，使**不合规的变更无法进入仓库**：

1. **本地钩子（个人强制）**：由 `tools/hooks.py` 安装（运行 `python -m tools.hooks` 自动写入真实仓库根的 `.git/hooks/`，并定位 `pyrit-mini` 子目录）。`pre-commit` 跑 `tools.gate --stage commit`（guard + 架构体检 + ruff + dry-run + registry 接线），`pre-push` 跑 `--stage push`（再 + pytest 全量 + drift + dataflow + e2e）。任一阻塞项直接中止提交/推送。绕过须显式 `git commit --no-verify`，而**绕过门禁本身即 C10 违例**，须登记 STOP-REPORT。
2. **CI（团队强制）**：仓库根 `.github/workflows/spec-gate.yml`（`working-directory: pyrit-mini`）在每次 push/PR 执行全量 `tools.gate`；CI 红灯 = 禁止合并。
3. **规范漂移回看（周期强制）**：见 §6 / backlog，定期跑 `python -m tools.drift_detector --full` 复核 SSOT 是否仍与代码一致。

> 钩子通过 `python -m tools.hooks` 安装（勿手改 `.git/hooks/`）；CI 位于仓库根 `.github/workflows/`。两者命令**只许调用 `tools.gate`**，不得各自抄写明细（C3）。

---

## 3. 开发三元组（单一定义）

| 阶段 | 触发词 | 动作 |
|------|--------|------|
| **开发必看** | `开发规范` / `开发必看` | 加载 §1 文档地图中对应层级文件 |
| **开发必跑** | `开发验证` / `开发必跑` / `完整验证` / `规范对齐` | 按 §2 执行 6 步门禁，修复全部问题后汇报 |
| **开发必验** | `开发交付` / `开发必验` / `交付标准` | 按 `40-GUARDRAILS.md` 第七章交付验证清单逐项打勾 |

> 同义触发词以本表为准。禁止在其他文档重复定义触发词表。

---

## 4. CLI 工具速查（`pip install -e .` 后可用）

| 命令 | 等价模块调用 | 用途 |
|------|-------------|------|
| `pyrit-gate [--stage commit\|push\|all] [--describe]` | `python -m tools.gate` | **统一门禁（唯一入口，见 §2）** |
| `pyrit-guard` | `python -m tools.guard` | 宪法守卫 |
| `pyrit-drift [--full] [--report]` | `python -m tools.drift_detector` | 规范漂移检测 |
| `pyrit-dataflow` | `python -m tools.dataflow.validator` | 数据流完整性 |
| `pyrit-hooks` | `python -m tools.hooks` | 安装 Git hooks |
| `pyrit-mock-range` | `python -m tools.mock_range` | Mock 靶场起停（`--up/--down/--list/--check`） |
| `pyrit-oob` | `python -m tools.oob_listener` | OOB 外传回执接收（IC-5） |
| `pyrit-poc` | `python -m tools.poc` | PoC 复跑验证 |
| `pyrit-*` 审计族 | `tools.{security,test,dependency,component,dev,release}_audit` | 安全/测试/依赖/组件/开发/发布审计 |

> **2026-09-12 修正（BL-042）**：原表 `pyrit-cross` / `pyrit-quick` / `pyrit-watch` 三条指向
> `tools.cross_model_review` / `tools.quick_check` / `tools.watch_guard` —— **三者均不存在**
> （已并入 `guard.py`），属 D5 违规，已删除。
> 别名规律：`python -m tools.<x>` = `pyrit-<x>`（entry_points 注册）；**新增/删除工具必须同批
> 同步本表与 `pyproject.toml` 的 `[project.scripts]`**（NFR-24）。
> CLI 参数以 `main.py` 与 `core/config.py` 的 argparse 定义为唯一权威（运行 `python main.py --help` 即得完整清单）；specs 不另立参数文档（R-DOC-1 的 SSOT 目标即代码本身）。

---

## 5. 文档纪律（R-DOC 摘要，完整版见 40-GUARDRAILS 1C-DOC）

规约文档自身也受宪法 C3 约束。违反以下任一条即为文档漂移，须登记 backlog：

| # | 纪律 | 反例（禁止） |
|---|------|-------------|
| D1 | **一概念一处声明**：同一规则/命令/阈值/清单只准在金字塔中声明一次，其余处只准引用 | 门禁命令在宪法、40、70、README 各写一份且不一致 |
| D2 | **禁止行号坐标**：引用代码用 `模块.符号` 或 grep 可验证的模式，不用 `file.py:417` | `utils/display.py:417`（次日即失效） |
| D3 | **版本史外置**：正文只保留当前版本号，变更历史交 git log / CHANGELOG | 每个文件末尾 20 行版本记录表 |
| D4 | **清单不进正文**：动态清单（组件、检查器、测试数）指向代码/命令，不手工抄写 | 手工维护"46 项检查器"计数 |
| D5 | **路径必须存在**：文档引用的文件路径必须真实存在，含空格路径须引号包裹 | 引用仓库中不存在的路径（如已删除的 `docs/red team/`、`docs/archive/`） |
| D6 | **已完结内容归档**：完成态的执行记录/提案移出活跃规约（归档保留于 git 历史；物理目录 `docs/archive/` 当前未启用），不留在 specs 活跃文档 | 已完成的 Wave 执行日志留在 specs 活跃文档 |
| D7 | **无占位符**：文档不得出现未填实的 `[CMD]` / `TASK-___` 等模板占位 | `[CROSSMODEL_CMD] --task TASK-___` |

---

## 6. 变更流程

| 变更对象 | 流程 |
|---------|------|
| **宪法** | C12 修正案：`templates/change-proposal.md` → 人工批准 → 同批更新版本号、本索引、受影响 guard 检查器 → 跑 §2 门禁 |
| **蓝图 / 需求** | `change-proposal` → 登记 REQ/DEBT → 任务规格 → 编码（20 第六章） |
| **L0–L4 规约** | 先过跨模型审查（C14 / R-CROSS-1）→ 再走上述流程 |
| **路线图** | `change-proposal`（序列变更） |
| **模板 / 本索引** | 随其服务层级变更，同批更新版本号 |

---

## 7. 归档与已删除清单

**已归档 / 迁出**（内容或已合并入 specs，或仅存于 git 历史，不再维护）：

| 原路径 | 现位置 / 去向 |
|--------|--------------|
| `docs/plan.md`、`docs/plan-execution-log.md` | 已从仓库移除（Wave 0–6 历史执行记录仅存于 git 历史，含失效行号坐标，仅作考古用） |
| `45-DATA-FLOW-INTEGRITY.md` | 已合并入 `10-ARCHITECTURE.md` 第四章，原文件删除 |
| `60-REDTEAM-DELIVERY-FRAMEWORK.md` | 已合并入 `40-GUARDRAILS.md` 第七章 |

**已删除**（内容与规约重复或已被 SSOT 取代）：

| 文件 | 删除理由 |
|------|---------|
| `70-DEV-TRIAD-CHECKLIST.md` | 与 §2/§3 逐条重复（C3）；且含虚构条款 C15 与未填实命令占位符（D7） |
| `56-A2A-MULTI-AGENT-ATTACK.md` | 方案类文档；A2A 攻击面已由 `config/components/a2a.yaml` + `80` 承载（SSOT） |
| `35-MULTIMODAL_ASSESSMENT.md` 等 | 见 git 历史（2026-09-09 清理） |

---

## 8. 边界说明

- 本目录**只含规约层文档**。被治理的代码库为本仓库源码树。
- 规约文件被修改时，**必须**同步：文件头版本号、§1 文档地图中该行描述（若职责变化）。**不得**在文末追加版本记录表（D3）。
- 文档中出现的任何代码事实，必须有可执行的验证命令伴随；无法验证的陈述一律标注 `[未验证]`。
