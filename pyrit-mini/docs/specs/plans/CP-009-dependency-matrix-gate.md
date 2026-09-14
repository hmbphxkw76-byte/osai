# CP-009 — 依赖方向矩阵机器校验（R-IMPORT）+ 现存跨层违例收口

> 状态：**approved（<user> 本会话批准进入 S0/S1；S0/S1 已落地）**
> S0/S1 执行结果（2026-09-14）：矩阵补 `core/phases/` 行；`check_dependency_matrix()` 已实现并注册，
> 40-G 1A 红线表 + 1F 登记簿同步。首扫即暴露 **3 组此前无任何检查器覆盖的跨层违例**（BL-090）。
> 期间修复两个假绿缺陷：① Windows `str(Path)` 反斜杠使行前缀匹配全落空；② 矩阵单元格注解
> （`✓（context）` / `—`）被误判为禁止。详见 §3 验收与 BL-090。
> 关联：BL-082（跨层违例 4 组）、BL-083（矩阵缺 `core/phases/` 行）、蓝图 [sid:10-ch2] 2.2 依赖方向矩阵
> 跨模型审查：按 R-CROSS-1 降级为人工审查（needs-cross-model-pending = true，单模型环境）

## 1. 背景

2026-09-14 开发全审（八个目录 A→L 全审）实测发现：**依赖方向矩阵没有任何机器检查器覆盖**。
表现是 `tools.guard` 报 0 阻塞 / 0 警告、`tools.drift_detector --full` 报 HEALTHY，而代码中存在 4 组
矩阵明令禁止的跨阶段 import（见 §2）。这与 E-01（门禁声称六步、实际三步）是同一类"规约存在但无人守护"的
结构性缺口：**矩阵只写在文档里，不进 CI，就等同于建议**。

本 CP 把矩阵变成可执行判据（R-IMPORT），并把 4 组现存违例按切片收口（每组 ≤3 文件，符 [sid:30-ch3] 粒度上限）。

## 2. 证据（实测，2026-09-14）

| # | 违例（依赖方 → 被依赖方） | 位置（模块.符号） | 矩阵口径 | 现状 |
|---|------|------|------|------|
| ① | strike → assess | `strike.common._executor_helpers` 内 `from assess.judge_manager import _t0_refusal_check_text, _t0_non_substantive_check_text` | strike→assess **仅限 `precompute_outcomes_async`**，不得扩大；且引用对方私有符号 | 未修 |
| ② | recon → strike | `recon._target_router_helpers`（`strike.mcp.orchestrator`）、`recon.target_builder`（`strike.session`）、`recon.adapters`（`strike.targets.{mcp,rag,a2a}`）共 4 处 | ✗（BL-037 TargetAdapter 引入） | 未修（并入 REQ-151） |
| ③ | assess → arm | `assess.asr_manager` 内 `arm.seed_ranker` / `arm.seed_ranking` 共 3 处 | ✗（asr_history 写入反向依赖） | 未修 |
| ④ | arm → recon | `arm.attack_surface_mapper` 内 `recon.orchestrator.ComponentProfile` | ✗ | **已闭环（本会话）**：`ComponentProfile` 下沉至 `core.component_profile`，两侧改依赖 core，re-export 保兼容 |

> ④ 的修复验证：`from recon.orchestrator import ComponentProfile is from core.component_profile import ComponentProfile` → True；
> `pytest tests/common/test_attack_surface_mapper.py tests/common/test_arm.py tests/common/test_recon.py` → 90 passed。

## 3. 设计：R-IMPORT 检查器

| 项 | 决定 | 理由 |
|----|------|------|
| **数据源** | **解析 `10-ARCHITECTURE.md` §2.2 矩阵表**（不做第二份硬编码清单） | C3 / D1：一概念一处声明；规约改了，检查器自动跟随 |
| **实现位置** | `tools/guard_extended.py`，登记入 40-G 1F 检查器登记簿 | 既有 BLOCKING 检查器聚居地，随 `tools.guard` 每次变更运行 |
| **扫描范围** | AST 解析全仓 first-party import，**含函数内延迟导入** | 现存 4 组违例有 3 组是函数内延迟导入，只扫模块级等于没扫 |
| **判定** | 依赖方目录 → 被依赖方目录 查矩阵；`✗` 且不在例外白名单 → BLOCKING | 与矩阵口径逐格一致 |
| **例外白名单** | 显式声明（初值：`strike → assess` 仅 `precompute_outcomes_async`；`recon → assess` 的 D-04 债务条目） | 矩阵脚注已声明的例外；白名单**只减不增** |
| **级别** | 上线先 WARNING 观察一个迭代，确认零误报后升 BLOCKING | 避免误伤主链路（CP-007 同款升級路径） |

**验收（可勾选）**：
- [ ] 注入 1 处违例（如 `strike` 内 import `recon`）→ R-IMPORT 判 BLOCKING，`tools.gate` 非零退出
- [ ] 白名单内合法例外（如 `precompute_outcomes_async`）→ 不报
- [ ] `core/phases/` 编排层行为 → 不报（依赖 §4 矩阵补行）
- [ ] 收口完成后，真实代码 R-IMPORT 0 违规

## 4. 矩阵补 `core/phases/` 行（BL-083）

`core/phases/{recon,arm,strike,assess,report}.py` 实为**阶段编排层**：80 的反模式段与 CP-001 护栏段均以
"编排层 = `core/phases/` + `strike/common/dispatcher.py`" 表述，其 import 阶段层属设计内行为。
当前矩阵仅有 `core/` 行（→ 各阶段 ✗），按字面执行会让编排层数十处导入全成违例。

**改法**（L1 蓝图变更，走 C12）：矩阵增设一行

| 依赖方 ↓ 被依赖方 → | core | recon | arm | strike | assess | report | utils | data(config) |
|---|---|---|---|---|---|---|---|---|
| `core/phases/`（编排层） | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | — | 只读 |

并注明：编排层对阶段层的调用**只经 PipelineContext + EventLog 交接**，沿用 R-EVENT-1 / R-EVENT-2 约束；
禁止硬编码组件名。该行必须与 R-IMPORT 同批落地，否则补了行仍无人守。

## 5. 违例收口切片（每片 ≤3 文件）

| 片 | 动作 | 涉及文件 | 前置 |
|----|------|---------|------|
| S0 | 矩阵补 `core/phases/` 行 | `10-ARCHITECTURE.md`（+ README/40 若需同步） | C12 批准 |
| S1 | R-IMPORT 检查器（WARNING → BLOCKING） | `tools/guard_extended.py` + 1F 登记簿 | S0 |
| S2 | 修 ①：T0 文本判定下沉 `core.t0_text_checks`；`assess` 改从 core 导入并 re-export | 新增 `core/t0_text_checks.py`、`assess/judge_manager.py`、`strike/common/_executor_helpers.py` | S1（有检查器兜底） |
| S3 | 修 ③：asr_history 读写器下沉 `core.asr_history`（回归蓝图 I7：assess 写、arm 读） | 新增 `core/asr_history.py`、`assess/asr_manager.py`、`arm/seed_ranker.py` | S1 |
| S4 | 修 ②：`strike.targets.*` 下沉支撑层或改由注册表/工厂解析（IC-2） | 跨模块 → 并入 REQ-151 PlaybookEngine | REQ-151 波次 |

## 6. 风险与回滚

| 风险 | 缓解 |
|------|------|
| 函数级延迟导入扫描误报（可选依赖 / `try: ... except ImportError`） | 白名单 + 观察期 WARNING；误报条目进白名单须注明理由并登记 backlog（只减不增） |
| 矩阵表解析随文档排版变化而失效 | 解析器对表头做显式断言（列顺序/行数），解析失败即 BLOCKING 报"矩阵不可解析"（禁止静默跳过，NEG-9） |
| S2/S3 下沉改变运行时行为 | 两片均只搬移定义 + re-export，零语义改动；验证以既有测试全绿为准 |

## 7. 不做的事

- 不新建第二套链 / 第二套组件机制（C3）；
- 不顺手拆分超限文件（BL-026 / BL-053 专项）；
- 不修 BL-081 注释乱码（另立专项，见 backlog 考古结论）。
