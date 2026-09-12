# backlog — 唯一待办池

> **规则**（30-TASKS 第二章 / 宪法 C4 豁免通道）：
> 一行一条；登记时**不动代码**；AI 在执行任务途中发现的任何**非本任务**问题，一律进此处，不就地修。
> **状态**：`open` / `converted`（转为 REQ / DEBT / 任务规格）/ `discarded` / `completed`
> **完结项不保留明细**（文档纪律 D3）：已完成条目只保留统计与 git 考古入口。

---

## 1. 活跃待办（open）

| ID | 登记日期 | 内容 | 来源 | 状态 |
|----|---------|------|------|------|
| BL-002 | 2026-09-05 | NFR-6 Python ≥3.13 与 PyRIT 1.0.1 官方支持矩阵核对；若 3.13 超出支持区间，按 NFR-6 硬边界以 PyRIT 区间为准并修订登记 | REV-01 P2-4 | **open** |
| BL-024 | 2026-09-12 | **组件 `id` ≠ YAML 文件名 stem**（违反 80 IA-8）：`session.yaml` 的 `id` 为 `memory_session_tenant`、`web_api.yaml` 的 `id` 为 `web_infra`。`core/registry.py` 的 `names()/get(id)` 与目录定位混用两个语义，修正前禁止编写依赖 `id == stem` 的代码。改动属**数据层**，须持专项任务规格 | 2026-09-12 规约梳理 | **open** |
| BL-025 | 2026-09-12 | **`config/components/*.yaml` 新旧双 schema 并存**：`mcp.yaml` 等同时携带 W0 遗留字段（`seed_sets`/`converter_vectors`/`strike_modules`/`assess`/`report_builder`/`poc_template`/`neighbors`/`owasp`）与新契约字段（`labels`/`detect`/`recon`/`seeds`/`scorer`/`report_section`/`cleanup`）。按蓝图 13.3「兼容层只减不增」，需专项任务清理并核对 `core/registry.py` 无旧字段消费者 | 2026-09-12 规约梳理 | **open** |
| BL-026 | 2026-09-12 | **`tools/guard_extended.py` 约 2071 行 > R-TOOLS-2 上限 850 行**：当前为仓库最大 Python 文件（34 个检查器）。拆分属债务消除，须登记 `DEBT-xxx` 专项任务，**禁止日常任务顺手重构**（C4 / NEG-1） | 2026-09-12 实测 | **open** |
| BL-027 | 2026-09-12 | **`docs/guides/ai-dev-guides.md`（约 1960 行）与 `specs/` 职责重叠**：同一套「task-spec 模板 / STOP-REPORT / 交付验收清单 / 跨模型一致性 / 三栏汇报」在三处定义（guides、specs、`.assistant_pyrit/skills/*/SKILL.md`），违反 C3。待裁决：`docs/guides/` 降级为「方法论与 why」、`specs/` 为「本项目规则与 what」，并删除重复模板 | 2026-09-12 规约梳理 | **open** |
| BL-028 | 2026-09-12 | **护栏 1F 登记簿与代码存在双向滞后**：本表为索引、代码为权威，需定期跑 `40-GUARDRAILS.md` 1F 头部命令对齐（当前代码 46 个 `def check_*`，登记簿列出 39 行） | 2026-09-12 实测 | **open** |

---

## 2. 已转化（converted）

| ID | 登记日期 | 内容 | 转化去向 |
|----|---------|------|---------|
| BL-012 | 2026-09-05 | Best-of-N stub 缺口 | → REQ-004 内标注 P0 缺口 + 路线图 T0-1 |

---

## 3. 已完成（completed）

**统计**：BL-001、BL-003 ~ BL-011、BL-013 ~ BL-023 共 **26 条**已闭环（2026-09-05 ~ 2026-09-10），覆盖：外部锚点核对、Guard 检查器登记簿锚定、SKILL.md frontmatter、文档收敛、死代码清理、编码损坏修复、pyproject 工具链、运行时产物 gitignore、L2→L4 升级链 UnboundLocalError、多智能体种子加载、MCP 动态种子链路、D-01~D-16 债务量化等。

**明细考古**：`git log -- docs/backlog.md`（文档纪律 D3，正文不再保留逐条完成记录）。

---

## 4. 登记格式（新增条目照抄）

```
| BL-0NN | YYYY-MM-DD | 一句话描述（含可验证的现象或坐标） | 来源 | **open** |
```

**硬性要求**：
1. **一行一条**，禁止把多个问题塞进一行；
2. 描述必须**可验证**（给出命令、路径或现象），禁止"某某可能有问题"式模糊登记；
3. 登记时**不动代码**——修改须另起任务规格（C4）；
4. 转化/完成后**改状态 + 移入对应章节**，不在 open 区保留完结项。
