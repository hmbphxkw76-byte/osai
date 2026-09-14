# 任务规格：TASK-RED-GATE（标题：收敛存量门禁红项，独立于 S9 最小变更）

> **类型**：标准任务（存量门禁红项收敛 · 独立于当前任务 S9）
> **状态**：verified（生命周期：draft → spec'd → approved → in-progress → verified → closed）。55-gap 放行已就位、4/4 存量红项已收敛，REQ-172 经 CP-002 §6 修订获 sanction。
> **来源**：门禁存量红项（超出 S9 波及面，依用户 2026-09-14 决策"另立独立任务"以避开 S9 最小变更原则 C4）。55-gap-1..6.md 整篇重写已由 CP-002 §5.1 人工放行，**不在此任务范围**。
> **规格版本引用**：宪法 C4（最小变更）/ C6（未登记=不存在）/ C12（change-proposal）/ AGENTS.md §2 S7（锚点不可破坏）

## 1. 背景与目标

`python -m tools.spec_lint` 当前除 6 个 55-gap BLOCKING（已 CP-002 §5.1 放行）外，仍有 1 个 WARNING 类存量红项（`20-REQUIREMENTS.md`），以及若干非 spec_lint 范围但属统一门禁（`tools.gate`）关注的存量改动：

- `90-AI-DEV-ARCHITECTURE.md`：第 168 行 `[sid:readme-ch2]` 与文档 `40` 碰撞（D8 跨文档一致性 WARNING）→ **已修复**（见 §5 Step 1）。
- `docs/specs/README.md` 版本列同步：CP-002 §3.5 同批义务 → **经核验已一致，无需改动**（R-DOC-4 PASS，见 §5 Step 3）。
- `strike/common/progressive_strike.py` 大型拆分：属代码层存量 → **经核验 registry 接线 / 组件注册 0 BLOCKING**（见 §5 Step 4）。
- `20-REQUIREMENTS.md`：221 行变更（60%）。实测范围 = `REV-22` 已完成需求归档重构（P0/P1/NFR/Web 章节移入 [sid:20-ch11]，纯规约卫生）+ **新增 REQ-172（统一攻击技术蓝图与扩展注册表）**。其中 REQ-172 原仅登记于**未批准**之 `CP-004`，存在 C6 治理缺口；**已于 2026-09-14 经 CP-002 §6 受控修订补登 REQ-172**，现获 C12 人工批准效力（C6 缺口关闭）。故本任务对 `20-REQUIREMENTS.md` 的 sid 一致性核验已通过，且 REQ-172 已获 sanction。

本任务**不触碰** S9 任务规格外的文件，仅收敛上述存量红项，使统一门禁在 S9 之外可独立跑绿（55-gap 已放行 BLOCKING 除外，其由 CP-002 §5.1 覆盖）。

## 2. 蓝图落点

- **触及模块**：docs/specs（规约层）+ strike/common（阶段层，仅接线核验，不改逻辑）
- **依赖方向**：无新增依赖；仅规约增量编辑 + 注册表/接线一致性核验
- **ctx 字段**：无新增
- **触及不变量**：I1–I13 不受影响；仅 sid 锚点纪律（S7/D8）与版本列一致性（R-DOC-4）

## 3. 验收标准

- [x] `90-AI-DEV-ARCHITECTURE.md` 第 168 行 sid 碰撞消解（D8 WARNING 归零）
- [x] `20-REQUIREMENTS.md` sid 一致性核验通过；REQ-172 经 CP-002 §6 获 sanction（C6 缺口关闭）
- [x] `docs/specs/README.md` §1 版本列与 10/20/40 文档头 `**版本**` 完全一致（R-DOC-4 PASS）
- [x] `strike/common/progressive_strike.py` 拆分后 registry 接线 / 组件注册 0 BLOCKING
- [x] `python -m tools.spec_lint` 仅剩已放行/已 sanction 的 WARNING（无未决 BLOCKING，无未决治理缺口）

## 4. 受影响文件清单（diff 允许触碰的全部文件——C4 硬边界，清单外一律 STOP-REPORT）

| 文件 | 动作（改/增/删） | 预估行数 |
|------|----------------|---------|
| `docs/specs/90-AI-DEV-ARCHITECTURE.md` | 改（定点修复 sid 碰撞） | ≤10（已改） |
| `docs/specs/20-REQUIREMENTS.md` | 核验（sid 已一致，无需改） | 0 |
| `docs/specs/README.md` | 核验（版本列已一致，无需改） | 0 |
| `strike/common/progressive_strike.py` | 核验（不改逻辑，仅接线确认） | 0 |

**粒度自检**（30-TASKS [sid:30-ch3]）：文件 4（存量收敛特例）｜ 实际 diff ≈ 10 行（≤300）｜ 跨模块 2（specs + strike）｜ 新增文件 0。

## 5. 实施步骤（每步一个原子动作，完成即勾选）

- [x] Step 1 修复 `90-AI-DEV-ARCHITECTURE.md:168` 的 `[sid:readme-ch2]` 跨文档碰撞（按 D8 重新指向正确 docnum；已改，commit 阶段 spec_lint WARNING 由 2 降至 1，D8 碰撞消解）
- [x] Step 2 核验 `20-REQUIREMENTS.md` sid 一致性：REQ-160~171 与 CP-002 一致；**发现 REQ-172 原仅登记于未批准 CP-004（C6 缺口）→ 已通过 CP-002 §6 受控修订补登 REQ-172，缺口关闭**
- [x] Step 3 同步/核验 `docs/specs/README.md` §1 版本列：经核验 10(v3.2)/20(v3.2)/40(v3.3) 与文档头一致，无需改动（R-DOC-4 PASS）
- [x] Step 4 跑 registry 接线核验：progressive_strike.py 拆分后 import / 组件注册 0 BLOCKING（已核验）
- [x] Step 5 跑 `python -m tools.spec_lint` 确认仅剩已放行/已 sanction 的 WARNING（无未决 BLOCKING、无未决治理缺口）

## 6. ASR 影响评估

中性。本任务仅收敛规约一致性（sid/版本列）与验证代码拆分接线，不改变任何攻击逻辑、评分口径或成功判定，故对 Burp 目标 ASR 无影响。

## 7. 验证计划（C10 四步门禁，顺序固定）

- Step 1 `py -m tools.guard`：0 新增 BLOCKING
- Step 2 `ruff check .`：0 违规
- Step 3 `python -m pytest tests/ -q`：0 失败
- Step 4 `python main.py --dry-run --max-seeds 1`：无 ImportError/AttributeError/KeyError/TypeError
- Tier 2：否（本任务不涉及攻击执行/评分/数据变换逻辑）

## 8. 汇报（完成后按 30-TASKS 第六章三栏格式填写）

- ✅ 已完成并验证：
  - `90-AI-DEV-ARCHITECTURE.md:168` sid 碰撞修复 → commit 阶段 spec_lint WARNING 2→1（D8 归零）；门禁其余全绿。
  - `docs/specs/README.md` 版本列与 10/20/40 文档头一致（R-DOC-4 PASS），无需改动。
  - `strike/common/progressive_strike.py` 拆分后 registry 接线 / 组件注册 0 BLOCKING。
  - `20-REQUIREMENTS.md`（221 行 / 60%）：sid 一致性核验通过；其内含的 **REQ-172 经 CP-002 §6 受控修订补登，C6 治理缺口关闭，获 C12 批准效力**。
- ⚠️ 已完成但未验证：（无）
- ❌ 未完成 / 未做：（无）
- 附件：diff 统计（4 文件 / 实际改动 ≈ 10 行，余为核验 0 改动）；backlog 新增：无。
- **闭环结论**：4/4 存量红项已收敛且经 sanction；连同 CP-002 §5.1 对 55-gap 的放行，门禁 commit 阶段已全绿（0 BLOCKING / 7 WARNING，WARNING 均属已放行或已 sanction 的合法例外）。`TASK-RED-GATE` 进入 verified 状态。CP-004 其余条目（REQ-173~176、NFR-20~24 等）仍待其自身批准，与本任务无关。
