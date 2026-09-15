# TASK-CP010-S5 — 兼容层收敛：删 ComponentSpec legacy merge 逻辑（step ②）

> 状态：执行中（2026-09-15）
> 关联：CP-010 S5 / BL-025 / BL-050
> 流程：CP-010(approved draft) → 本 TASK plan → 切片 → 实现 → gate → 提交

## 背景（关键认知修正）

- `core/contracts/component.py` 的 `ComponentSpec.model_post_init` 将 legacy 别名字段并入 canonical 字段：
  `detect`→`detection`、`recon`→`recon_modules`、`seeds`→`seed_sets`、`converters`→`converter_vectors`、`scorer`→`assess.rubric`、`report_section`→`report_builder`。
- **canonical = `seed_sets`/`assess`/`report_builder`/`recon_modules`/`converter_vectors`/`detection`**（注册表 `core/registry.py` 直接消费这些）；legacy 别名（`seeds`/`scorer`/`report_section`/`converters`/`recon`/`detect`）**无裸 dict 消费者**（tools/target.py、测试命中均为输出种子/报告字典，非组件 YAML）。
- 12 份组件 YAML 的 legacy 别名已由 W-P5 P5-5（commit `e2638ce`）删除；`recon`/`converters`/`detect` 从未写入 YAML（仅 README 示例）。
- 故 `model_post_init` 内全部 legacy merge 分支现为死代码（恒为 no-op）。BL-025/CP-010-S5 step ② = 删除该 merge 逻辑。

## 切片

| 片 | 任务 | 落点 | 验收 |
|----|------|------|------|
| S5a | 删除 `model_post_init` 内 legacy 归一化分支（detect 字典 / 列表别名 / scorer/report_section） | `core/contracts/component.py` | gate 全绿；`ComponentSpec.from_yaml` 行为不变（canonical 字段仍被消费） |
| S5b | 删除无用的 `_merge` 辅助函数 | `core/contracts/component.py` | ruff 无未用定义 |

## 收口（文档，CP-010 §3 要求）

- `docs/backlog.md`：BL-025 → completed（认知修正：legacy 别名已删、merge 逻辑已删；canonical 字段保留且被消费）；BL-050 → completed（同问题，字段分类口径已修正）
- `docs/specs/plans/CP-010-backlog-convergence.md`：S5 → 本切片完成

## 验收

- [ ] gate 全绿（pytest + e2e + validate_wiring + spec_lint）
- [ ] 无新增裸 dict 消费者（grep 复核 `seeds`/`scorer`/`report_section`/`converters`/`recon`/`detect` 仅作为字段定义存在，无 merge 读取）
- [ ] BL-025 / BL-050 completed
