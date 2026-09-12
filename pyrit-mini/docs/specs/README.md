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
| **L0** | [00-CONSTITUTION.md](00-CONSTITUTION.md) | v2.3 | AI 行为宪法：使命 / 裁决序 / C1–C14 / 违宪症状 / PyRIT 原生速查（7C）/ 考试附录 | 每会话开头（Step 1 宪法自检） |
| **L1** | [10-ARCHITECTURE.md](10-ARCHITECTURE.md) | v3.1 | 技术蓝图：分层依赖 / ctx 字段契约（4.4 SSOT 总表）/ 不变量 I1–I13 / ADR / 债务簿 / 目标架构 v4.0 | 编码前声明架构落点时（Step 2） |
| **L1** | [80-COMPONENT-ARCHITECTURE-RULES.md](80-COMPONENT-ARCHITECTURE-RULES.md) | v2.0 | 组件化规则：双命名空间 / 目录命名 / 新增组件 Checklist | 新增或修改组件时 |
| **L2** | [20-REQUIREMENTS.md](20-REQUIREMENTS.md) | v2.9 | 需求登记：P0/P1/P2、NFR、NEG。**未登记 = 不存在** | 领取任务时核对验收标准（Step 3） |
| **L3** | [30-TASKS.md](30-TASKS.md) | v2.3 | 任务协议：生命周期 / 粒度上限 / 八步协议 / STOP-REPORT / 三栏汇报 | 每次编码任务全程 |
| **L4** | [40-GUARDRAILS.md](40-GUARDRAILS.md) | v3.1 | 红线 R-* / 门禁纪律 / 三层防线 / 交付验证清单 / 考试合规 | 编码后验证（Step 7） |
| 配套 | [50-ROADMAP.md](50-ROADMAP.md) | v1.12 | 任务序列、考试 Runbook、考纲映射。**无裁决权威** | 领取下一个任务时 |
| 配套 | [55-ATTACK-GAP-CLOSURE.md](55-ATTACK-GAP-CLOSURE.md) | v1.8 | 攻击面缺口登记处（R-DOC-2 依赖，**路径勿改**） | 新增攻击模块时登记 |
| 配套 | [60-CROSS-MODEL-VERIFICATION.md](60-CROSS-MODEL-VERIFICATION.md) | v1.0 | 跨模型审查协议（C14 落地） | 变更 L0–L4 规约时 |
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

## 2. 唯一门禁（SSOT —— 其他文档只准引用本表）

宪法 C10。**全部执行、全部通过、缺一不可、顺序固定**。任何文档/脚本引用门禁命令时，必须与本表逐字一致。

> **统一入口（推荐）**：`python -m tools.gate`（commit 阶段）/ `python -m tools.gate --stage push`（pre-push）/ `python -m tools.gate`（CI 全量）。该命令是上表的唯一代码实现（`tools/gate.py`），手写命令易漂移，统一走 `tools.gate`。

| 步 | 命令 | 通过标准 | 拦截什么 |
|----|------|---------|---------|
| 1 | `python -m tools.guard` | 0 **新增** BLOCKING | 红线 1A 架构模式违规 |
| 1.5 | `python tools/architecture_validator.py full` | 0 BLOCKING | 阶段边界 / 组件传播 / 模块路由 / 组件接线 |
| 2 | `ruff check .` | 0 违规 | 风格 / 导入 / 未用变量 |
| 3 | `python -m pytest tests/ -q` | 0 失败 | 功能回归 |
| 4 | `python main.py --dry-run --max-seeds 1` | 无 ImportError/AttributeError/KeyError/TypeError，到达 REPORT | 运行时数据流断点 |
| 5 | `python -m tools.drift_detector --full` | 0 BLOCKING | 规范↔代码漂移 |
| 6 | `python -m pytest tests/common/test_data_flow_integrity.py -q` | 全部通过 | ctx 字段契约违规 |

> 步骤 5/6 为 `pre-push` 强制；步骤 1–4 为每次变更后强制。
> **纪律**："改动很小"不豁免任何一步；guard 通过 ≠ 代码可用；门禁失败禁止标记任务完成。

**2026-09-11 基线**（变更前后对照用，非验收标准）：guard `0 blocking / 71 warning`；架构体检 `PASS 158 / WARNING 6 / BLOCKING 0`；pytest `1402 passed / 7 skipped`。

### 2.1 自动执行（防跑偏核心保障）

门禁若只靠"记得跑"必然漂移。本项目用三层强制，使**不合规的变更无法进入仓库**：

1. **本地钩子（个人强制）**：`pre-commit` 跑 `tools.gate --stage commit`（ruff+guard+registry），`pre-push` 跑 `--stage push`（再 + drift + data-flow）。任一阻塞项直接中止提交/推送。绕过须显式 `git commit --no-verify`，而**绕过门禁本身即 C10 违例**，须登记 STOP-REPORT。
2. **CI（团队强制）**：`.github/workflows/spec-gate.yml` 在每次 push/PR 执行全量 `tools.gate`；CI 红灯 = 禁止合并。
3. **规范漂移回看（周期强制）**：见 §6 / backlog，定期跑 `python -m tools.drift_detector --full` 复核 SSOT 是否仍与代码一致。

> 钩子文件位于 `.git/hooks/`；CI 位于 `.github/workflows/`。两者命令**只许调用 `tools.gate`**，不得各自抄写明细（C3）。

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
| `pyrit-guard` | `python -m tools.guard` | 宪法守卫 |
| `pyrit-drift [--full] [--report]` | `python -m tools.drift_detector` | 规范漂移检测 |
| `pyrit-dataflow` | `python -m tools.dataflow.validator` | 数据流完整性 |
| `pyrit-cross [--full\|--light]` | `python -m tools.cross_model_review` | 跨模型规约审查 |
| `pyrit-quick <file>` | `python -m tools.quick_check` | 单文件快速检查 |
| `pyrit-watch` | `python -m tools.watch_guard` | 实时文件监视 |
| `pyrit-hooks` | `python -m tools.hooks` | 安装 Git hooks |

> 别名规律：`python -m tools.<x>` = `pyrit-<x>`（entry_points 注册）。
> 完整 CLI 参数参考见 **`docs/red team/red-team-dev-guide.md` 附录 D**（注意路径含空格；R-DOC-1 的 SSOT 目标）。

---

## 5. 文档纪律（R-DOC 摘要，完整版见 40-GUARDRAILS 1C-DOC）

规约文档自身也受宪法 C3 约束。违反以下任一条即为文档漂移，须登记 backlog：

| # | 纪律 | 反例（禁止） |
|---|------|-------------|
| D1 | **一概念一处声明**：同一规则/命令/阈值/清单只准在金字塔中声明一次，其余处只准引用 | 门禁命令在宪法、40、70、README 各写一份且不一致 |
| D2 | **禁止行号坐标**：引用代码用 `模块.符号` 或 grep 可验证的模式，不用 `file.py:417` | `utils/display.py:417`（次日即失效） |
| D3 | **版本史外置**：正文只保留当前版本号，变更历史交 git log / CHANGELOG | 每个文件末尾 20 行版本记录表 |
| D4 | **清单不进正文**：动态清单（组件、检查器、测试数）指向代码/命令，不手工抄写 | 手工维护"46 项检查器"计数 |
| D5 | **路径必须存在**：文档引用的文件路径必须真实存在，含空格路径须引号包裹 | `docs/guides/red-team-dev-guide.md`（实际在 `docs/red team/`） |
| D6 | **已完结内容归档**：完成态的执行记录/提案移入 `docs/archive/`，不留在活跃规约 | 已完成的 Wave 执行日志留在 specs |
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

**已归档**（内容仍在，不再维护）：

| 原路径 | 现位置 / 去向 |
|--------|--------------|
| `docs/plan.md`、`docs/plan-execution-log.md` | `docs/archive/`（Wave 0–6 历史执行记录，含失效行号坐标，仅作考古用） |
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
