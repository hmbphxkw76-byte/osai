# CP-016 — BL-101：S9 baseline 降级必须留痕（禁止静默）

> **类型**：缺陷收口（C9 诚实汇报 / R-H1 禁止静默降级）
> **提案人 / 日期**：AI (CodeBuddy) / 2026-09-15
> **状态**：draft → **approved**（2026-09-15 自动批准：用户授权"全程自动批准符合最佳实践的方案"；行为保持兼容、仅增可观测性、差异 ≤16 行、ASR 中性）
> 跨模型审查：按 R-CROSS-1 降级为人工审查（needs-cross-model-pending = true，单模型环境）

## 1. 动机（实测归因）

CP-014 收口过程中，系统在 push 门禁处出现两次看似无关的症状：`ModuleNotFoundError: No module named 'tools.component_purity'` 与 `tests/common/test_attack_chain.py::TestChainPlannerS9Routing` 断言失败。二者实为同一根因：

- `tools/_purity_baselines`、`tools/component_purity` 等 14 个模块迁入 `tools/audit/` 子包；
- `core/component_techniques.py:26-32` 的 `_baselines()` 以 `except Exception: return {}` **无差别吞掉**了由此产生的 `ImportError`；
- 于是 technique→component 反向索引**静默变空**，真实故障不在故障点暴露，而是远距离表现为"逐 technique 路由退化"，最终由一个断言错误呈现。

这类"错误在远处爆炸"的模式正是 C9（诚实汇报）与 R-H1（禁止静默降级）要防的情形：**降级本身合理，不可观测才不可接受**。

## 2. 方案

降级语义**完全保留**（仍返回 `{}`，零回归、不阻断主链路），仅在降级路径补一条 `WARNING`，使故障在真正的故障点即可观测：

```python
except Exception as exc:
    logger.warning(
        "[component_techniques] S9 baseline 表不可用，technique 索引降级为空：%s: %s",
        type(exc).__name__, exc,
    )
    return {}
```

明确**不做**（避免过度设计）：不改为抛异常（会破坏"tools 不可用时仍可用"的既有容错契约）；不引入重试/备用源；不顺手清理其它模块的同类写法（跨较多文件，属 NEG-1「禁止顺手重构」，另立专项）。

同批修正该模块 docstring 的过时信息：第 3 行 SSOT 路径（`tools._purity_baselines` → `tools.audit._purity_baselines`）与"静默降级"的政策描述（D5）。

## 3. 影响面

- **触及**：`core/component_techniques.py` 单模块；`tests/common/test_component_techniques.py`。
- **不触及**：`core/side_effect_cleanup`、组件 YAML、依赖矩阵、任何护栏/不变量/红线。
- **governance**：不新增红线与不变量。

## 4. ASR 影响评估

**中性**：不改变任何返回值、不改变路由结果；仅增加一条日志。无攻击/评分行为变更，无授权边界变动。

## 5. 收口切片（每片 ≤3 文件 / 跨模块 ≤2 / 新增 ≤1，符 [sid:30-ch3]）

| 片 | 状态 | 动作 | 涉及文件 |
|----|------|------|---------|
| **S1** | ✅ DONE | `_baselines()` 降级路径补 `WARNING`；docstring 过时路径与政策描述修正 | `core/component_techniques.py` |
| **S2** | ✅ DONE | 回归：import 失败时仍返回 `{}` **且**留下 `caplog` WARNING；同步测试文件内的过时路径注释 | `tests/common/test_component_techniques.py` |
| **S3** | ✅ DONE | 记录闭环：backlog BL-101 completed + CP-016 / TASK-CP016 | `docs/backlog.md` + 本文件 + `TASK-CP016.md` |
| **闭环判据** | — | 降级可观测（`pytest -k component_techniques` 全绿且含留痕断言）；降级仍不阻断主链路（`_baselines() == {}`）；`tools.gate` 0 BLOCKING；BL-101 closed | — |

## 6. 风险与回滚

| 风险 | 缓解 |
|------|------|
| 正常路径被日志淹没 | 仅在异常路径打印；正常导入零日志新增 |
| 日志内容泄漏敏感信息 | 仅打印异常类型与消息，无密钥/目标/会话数据 |
| 误改容错契约为抛错 | 明确保留 `return {}`，由 S2 断言返回值未变 |
| 与其它进行中的重构（tests/ 重组）相互污染 | 所有提交以 `git commit --only -- <路径>` 进行，拒绝批量 `git add` |
