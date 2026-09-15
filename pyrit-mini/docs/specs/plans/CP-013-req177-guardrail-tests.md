# CP-013 — REQ-177 组件一致性护栏（R-COMP-2 / R-COMP-3）单测收口

> **类型**：测试收口（闭环 c000075 遗留的 R-DELIVERY-2 缺口）
> **提案人 / 日期**：AI (CodeBuddy) / 2026-09-15
> **状态**：draft → **approved**（2026-09-15 自动批准：用户授权"全程自动批准符合最佳实践的方案"；纯测试、最小变更、非阻塞、ASR 中性）
> 跨模型审查：按 R-CROSS-1 降级为人工审查（needs-cross-model-pending = true，单模型环境）

## 1. 动机

`c000075` 已注册 R-COMP-2（`check_component_dir_consistency`）与 R-COMP-3（`check_recon_only_component`）两套组件一致性护栏（REQ-177 / ADR-011 / I15），并入 gate 的 commit/push 阶段。但该提交**未带单测**，违反 40-G R-DELIVERY-2「新增护栏须有对应测试」的默认 WARNING 纪律（非阻塞，但属质量缺口）。本 CP 闭环该缺口，使护栏具备可回归的机器验证。

## 2. 条款/规格 diff

| 文件 | 位置 | 现文 | 改为 |
|------|------|------|------|
| `tests/test_component_guardrails.py` | 新增 | — | R-COMP-2 三态（violation / strike_dir ok / recon_dir ok / recon_only 豁免）+ R-COMP-3 三态（strike 模块 BLOCKING / `__init__.py` 导出豁免 / YAML `strike_modules` BLOCKING / 无 diff 放行）+ 3 个纯函数单测（`_is_recon_only` / `_component_yaml_fields` / `_field_adds_nonempty_list`） |

> 不改动任何生产代码；护栏注册逻辑（c000075）保持不变。

## 3. 影响面

- REQ-177（组件一致性护栏）；40-G 1K-GATE / R-DELIVERY-2。
- 唯一变更 = 新增测试文件；gate 的 pytest 步纳入；R-DELIVERY-2 缺口闭环。

## 4. ASR 影响评估

**中性**：纯测试，零攻击/评分行为变更，无授权边界变动。

## 5. 收口切片（每片 ≤3 文件，符 [sid:30-ch3] 粒度上限）

| 片 | 状态 | 动作 | 涉及文件 |
|----|------|------|---------|
| **S1** | ✅ DONE | 新增 `tests/test_component_guardrails.py`（R-COMP-2 三态 + R-COMP-3 三态 + 3 纯函数单测），`tools.gate` 绿、`pytest` 全绿 | `tests/test_component_guardrails.py` |
| **闭环判据** | — | `pytest tests/test_component_guardrails.py` 全绿；`tools.gate` 0 BLOCKING；R-DELIVERY-2 缺口闭环（c000075 遗留） | — |

## 6. 风险与回滚

| 风险 | 缓解 |
|------|------|
| 测试误依赖仓库真实 git/dir 状态 | 全程以 `tmp_path` 构造 root + `unittest.mock.patch` 替换 `subprocess.run`，与仓库状态完全隔离 |
| 误报/漏报 | 三态（violation / ok / exempt）齐覆盖，含 BLOCKING 与 WARNING 两类 severity |
