# CP-011 — spec_lint 整篇重写判定口径修正（P3）

> 状态：approved（用户于全审闭环后确认执行，视为 C12 批准）
> 跨模型审查：按 R-CROSS-1 降级为人工审查（needs-cross-model-pending = true，单模型环境）

## 1. 背景

`tools/spec_lint.py` 的 `check_diff_scale`（规则 #1 整篇覆盖重写）原判定为
`del_ratio = 删行数 / 新文件总行数`。

该口径存在一个度量缺陷：当某个规约/子文件被**压缩变短**（如删冗余实现细节、改为引用代码 SSOT，
符合宪法 D1 文档纪律）时，删除行数会**超过**变小后的新文件总行数，导致 `del_ratio` 被算成 >100%，
误报 BLOCKING「整篇覆盖重写」，进而阻塞 commit 门禁。

实际案例：`docs/specs/55-gap-*.md`（缺口登记子文件，非规约）v1.8→v1.9 的合法精简
（删 47–107 行 / 增 11–25 行，旧 63–130 行→新 34–41 行）被整篇重写规则全部误判为 BLOCKING，
而 S2 的真实意图是禁止「整篇*替换*」，并非惩罚「删除冗余、指向 SSOT」的精简。

## 2. 评估原则

- **对齐 S2 真实意图**：「整篇覆盖重写」= 旧内容几乎被整体删光 **且** 新内容几乎全为新写（二者同时成立才是替换）。
- **保留信号不误阻塞**：仅大量删行而新增很少 = 合法精简/压缩 → 降为 WARNING（供人工复核，符合 D1）。
- **不弱化防护**：真正的整篇替换（新旧双向高占比）仍判 BLOCKING，无防护退化。

## 3. 规则变更

| 项 | 旧口径 | 新口径 |
|----|--------|--------|
| 整篇重写判定 | `删行数 / 新文件总行 ≥ 70%` → BLOCKING | 反推 `old = new + dele - add`；`删比 = dele/old ≥ 70%` **且** `新写比 = add/new ≥ 70%` 同时成立 → BLOCKING |
| 纯精简 | 误判 BLOCKING | 降为 WARNING（churn ≥ 50%） |
| 权威说明 | 模块头 + `--describe` 描述旧口径 | 同步更新为「旧删比×新写比双高才 BLOCKING；纯精简 WARNING」 |

## 4. 本次变更

- `tools/spec_lint.py`：`check_diff_scale` 改为反推旧总行并按「旧删比 ∧ 新写比」双阈值判定；
  同步更新模块 docstring 与 `main()` 中 `_describe()` 的输出文本（`--describe` 为规约引用的权威源，须与实现一致）。
- 仅改判定逻辑与说明，未改动 sid 锚点体系、未扩扫描范围。

## 5. 验证

- `python -m tools.spec_lint` → `0 BLOCKING / 7 WARNING`（55-gap-*.md 由 BLOCKING 降为 WARNING；20-REQUIREMENTS.md 为既有 churn WARNING）。
- `python -m pytest tests/test_spec_lint.py -q` → 18 passed（无回归）。
- `python -m tools.gate --stage push` → `[GATE PASS] 所有门禁通过（10 步 + registry 接线）`；pytest 2102 passed、drift HEALTHY、dataflow 29 passed、e2e 3 passed。

## 6. 审查（人工）

- 批准人：<user>（全审闭环后确认执行）
- needs-cross-model-pending：true（R-CROSS-1 降级，单模型环境）
- 合并裁决：人工
