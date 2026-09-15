# TASK-CP016 — BL-101：S9 baseline 降级留痕

> **状态**：approved（2026-09-15 自动批准；保留降级语义、仅增可观测性、ASR 中性）
> **关联**：CP-016 / BL-101 / C9 / R-H1

## 关键决策（本会话核实）

1. **降级要保留，沉默要消除**：`_baselines()` 返回 `{}` 的容错契约是合理的（tools/注册表不可用时主链路仍可运行），问题只在于**降级无任何留痕**。故改为 `logger.warning` + 保留 `return {}`，不改为抛异常。
2. **不扩大范围**（NEG-1）：全库可能还有其他静默 `except` 写法，本次**不顺手清理**；如需治理应另立专项 CP 并逐批进行。
3. **提交卫生**：本次执行期间用户正并发进行 `tests/` 目录重组与 `tools/audit/` 迁入，历史上曾发生"批量 add 把他人 WIP 卷入提交"的事故。本任务所有提交一律 `git commit --only -- <显式路径>`。

## 切片

| 片 | 任务 | 落点 | 验收 |
|----|------|------|------|
| **S1** | 降级路径补 WARNING + docstring 过时信息修正 | `core/component_techniques.py` | ruff 干净；既有 `component_techniques` 用例仍全绿 |
| **S2** | 留痕回归（caplog）+ 测试文件过时路径注释同步 | `tests/common/test_component_techniques.py` | 6 passed（含新增留痕断言） |
| **S3** | backlog BL-101 completed + CP/TASK 记录 | `docs/backlog.md`、`CP-016`、`TASK-CP016` | BL-101 closed |

## 每片验收（勾选）

- [x] **S1** 完成：`_baselines()` 降级留痕，行为未变（`commit 20ec409`）
- [x] **S2** 完成：caplog 留痕断言通过（`commit dd23662`）
- [x] **S3** 完成：BL-101 closed + 过程文档落地
