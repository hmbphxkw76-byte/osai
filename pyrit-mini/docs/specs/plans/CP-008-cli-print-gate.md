# CP-008 — CLI/测试层 print→logging 收口 + ruff T201 接入门禁

> 状态：**approved（<user> 本会话"确认"视为 C12 批准；切片 0 执行中）**
> 跨模型审查：按 R-CROSS-1 降级为人工审查（needs-cross-model-pending = true，单模型环境）
> 关联：CP-006 §2（P2 库层 print→logging 收口；CLI/测试层按计递延）

> ⚠ **范围修正（slice 0 执行中发现，2026-09-13）**：全仓 `print\(` 扫描显示**库层（`core/` `arm/` `strike/` `recon/` `scripts/`）仍有大量残留 print**——CP-006 的"86 处收口"并未净尽。真实范围 ≈ **52 个 .py 文件、跨全部层**（不止原 §2 的 CLI/测试层 4 目录）。原 §2 计数 450 仅覆盖 `tools/`+`report/`+`tests/`+`main.py`，**已偏低**。本 CP 范围据此扩展为**全层收口**；T201 过渡豁免涵盖全部 52 文件。迁移切片（§5）相应扩展至所有层。证据以 slice 0 全仓扫描为准（C9 / R-H1）。

## 1. 背景

CP-006 把库层（`core/` `arm/` `assess/` `strike/` `recon/` `utils/`）的 `print` 全部迁移到 `logging`（86 处），
但 CLI 层（`tools/` `report/` `main.py`）与 `tests/` 按原计划**递延**——理由是其 `print` 多为用户面向输出（报告 / PoC / 结果回显），
直接迁移会丢失终端交付物。

然而当前护栏存在结构性缺口（R-GATE-2「禁止非阻塞降级」）：

- `pyproject.toml` 的 `[tool.ruff.lint] select = ["E","F","W","I"]` **未含 `T201`**，
  即 `ruff` 根本不检查 `print`；`tools.gate` 的 ruff 步虽在 commit/push 阶段运行，但对 `print` 视而不见。
- 结果：CLI/测试层至今残留约 **450 处 `print`**，其中相当比例为**诊断性**输出（trace / debug / 状态），
  排障无级别、无开关，且门禁零覆盖——与「诊断信息应走 logging」的最佳实践相悖。

本 CP 在 **不破坏既有 push、不丢失用户交付物** 的前提下，把剩余 `print` 收口，并把 `T201` 接入门禁使其永久强制。

## 2. 证据（C9 / R-H1，按行计数）

| 目录 / 文件 | print 行数 | 备注 |
|------|------|------|
| `tools/` 合计 | **345** | 含 `component_audit_core.py` 116、`guard.py` 52、`hooks.py` 32、`drift_detector.py` 25、`component_audit_config.py` 25、`dev_audit_full.py` 37、`gate.py` 20、`dataflow/cli.py` 6 等 |
| `report/` 合计 | **85** | 含 `_poc_templates.py` 72（PoC 模板文本，多为**用户面向输出**）、`component_poc.py` 9、`poc_generator.py` 4 |
| `tests/` 合计 | **20** | 多为断言调试 / `capsys` 验证残留 |
| `main.py` | **0** | 仅根日志引导（CP-007 已加） |
| **总计** | **450** | — |

> 行计数（非出现次数）；单文件可能存在一行多 `print`，迁移时以实际出现次数为准。

## 3. 分类规则（每个 print 站必归一类）

| 类 | 判定 | 处置 |
|----|------|------|
| **A 诊断** | trace / debug / 状态 / 进度，无终端交付语义 | → `logger.debug/info`（迁移） |
| **B 用户输出** | 最终报告、PoC 文本、CLI 结果回显、给操作员的产物 | **保留 `print`**，但须经集中出口 `cli_out()`（或命名 logger `"cli"`），禁止在诊断语境滥用；列入最小 `per-file-ignores` 白名单 |
| **C 测试** | 测试内 `print`（断言调试 / `capsys` 验证） | 删除；或改用 `logger` / pytest fixture；确认无 `capsys` 断言依赖后再删 |

误判风险：B 类若误迁 logging → 丢失终端交付物。**切片 2（`report/`）须逐文件人工确认分类**，B 类保留。

## 4. 门禁接入（核心，闭合 R-GATE-2 缺口）

1. **启用 T201**：`pyproject.toml` `[tool.ruff.lint] select` 增加 `"T201"`
   （与现有 `"E","F","W","I"` 并列）。`tools.gate` 的 ruff 步在 commit/push 阶段已运行，T201 自然随 ruff 生效为 **BLOCKING**（ruff 非零退出即阻断）。**无需新增 gate 步骤**。
2. **过渡豁免（保证启用即不破坏既有 push）**：在同一 `[tool.ruff.lint.per-file-ignores]` 段，
   为当前全部 450 处 `print` 承载文件逐条加 `["T201"]` 豁免。这样切片 0 合并后 `gate` 仍全绿。
3. **增量收口**：每清理一个文件，即从 `per-file-ignores` 删除该文件条目（豁免随迁移同步收缩）。
4. **终态**：T201 全仓强制，仅保留极短白名单（真正 B 类用户面向输出文件，如 `report/` 生成器）。

> 该策略满足 S2「增量」与「门禁全程不破」：任一切片合并前 `gate` 必绿，绝不出现「启用即全员阻断」。

## 5. 执行切片（每片一个任务，避免超 30-TASKS 粒度上限）

| 切片 | 内容 | 门禁影响 |
|------|------|----------|
| **切片 0** | `pyproject.toml`：启用 `T201` + 为当前 print 承载文件加 `per-file-ignores` 过渡豁免 | 启用后全绿（豁免兜底） |
| **切片 1** | `tools/` 诊断 print（A 类）→ logging；非用户输出文件优先 | 边迁边删对应豁免 |
| **切片 2** | `report/` 分类：B 类保留经 `cli_out()`、A 类→logging（逐文件人工确认） | 仅 B 类留白名单 |
| **切片 3** | `tests/` print 清理（C 类） | 删对应豁免 |
| **切片 4** | 收缩 `per-file-ignores` 至最小白名单；终态 `rg "print\(" ` ≈ 仅 B 类 | T201 全仓强制 |

> **范围扩展**：上述切片现已覆盖**全部 52 个 .py 文件**（含 `core/` `arm/` `strike/` `recon/` `scripts/` 的残留 print），不再限于 CLI/测试层。每切片按目录分批迁移，逐文件移除对应豁免。

## 6. 风险

- **误伤用户交付物**：B 类误迁 → 终端产物丢失。**缓解**：切片 2 逐文件人工确认；B 类保留并集中出口。
- **测试 `capsys` 依赖**：删测试 print 前须确认无 `capsys` 断言依赖（否则测试失效）。**缓解**：切片 3 逐文件核对。
- **规模**：450 处，须分片；**禁止单任务大改写**（NEG-1 / C4）。
- **豁免膨胀**：过渡期 `per-file-ignores` 暂含 ~30 文件，须在切片 4 收缩，避免「豁免即变相放行」。

## 7. 验证

- 每切片：`python -m tools.gate --stage push` 全绿。
- 终态：
  - `ruff` 对 `T201` 全仓零豁免（除最小白名单）；
  - `rg "print\(" tools report tests main.py` ≈ 仅 B 类（用户面向输出）；
  - `pytest tests/ -q` 全过（输出不丢）。
- R-GATE-2 缺口闭合：`print` 在诊断语境被门禁强制拦截，不再「非阻塞降级」。

## 8. 审查（人工）

- 批准人：<user>（C12，本 CP 批准后方可进入切片编码）
- needs-cross-model-pending：true（R-CROSS-1 降级，单模型环境）
- 合并裁决：人工
- 关联登记：执行落地后于 `docs/backlog.md` 补 `completed` 行（参照 BL-076/BL-077）
