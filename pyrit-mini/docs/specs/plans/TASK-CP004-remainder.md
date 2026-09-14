# TASK-CP004-remainder — W-P4 收尾 + W-P5（执行计划）

> **状态**：approved（2026-09-14 自动批准：符合 C4/C5/IC-4/RK-P5/最小变更/机器校验等最佳实践；CP-004 已 approved）
> **关联**：CP-004（W-P4 P4-3/P4-4/P4-5、W-P5 P5-1~P5-5）、BL-094（P4-5 暂缓）
> **执行策略**：沿用开发全审流程（change-proposal=CP-004 → review → TASK plan → 切片 → 实现 → gate → 提交）；每片孤立提交（仅本片文件），粒度 ≤3 文件 / ≤300 行 / ≤2 模块（[sid:30-ch3]）。

## 关键决策（本会话核实）

1. **9 处悬空 playbook 引用 — 已核实不存在（无需改动）**：核对 `config/components/*.yaml` 全部 `playbooks:` 字段，引用均指向真实文件（a2a×3 / mcp×3 / rag×2 / embedding×1；supply_chain 为空）。前序 FINDING 中的 `jailbreak_ladder`/`guardrail_bypass`/`route_hijack`/`log_evasion`/`persist_poison`/`cross_tenant_read` 实为 `converter_vectors` / `strike_modules` 合法引用或 technique/seed 类别名，非 `playbooks:` 引用。依最小变更（C4）**不补文件、不删引用**，注册表本就诚实。
2. **P4-5 删原分支 — 暂缓（不盲删）**：4 个旧执行器（`strike/rag/data_poisoning.py`、`strike/common/_executor_doc_poison.py`、`_executor_vuln_inject.py`、`strike/mcp/malicious_server.py`）仍被活跃 import（`strike/rag/__init__.py`、`strike/common/executor.py`、`strike/__init__.py`、`strike/mcp/orchestrator.py` 及测试）。playbook YAML 已补但运行时仍走旧执行器 → 等价验证（RK-P5）未满足。删除会破坏构建，登记 **BL-094** 暂缓，待 playbook 驱动路径真正取代旧执行器后删除。

## 切片

| 片 | 任务 | 落点 | 验收 |
|----|------|------|------|
| **S1** | P4-4 e2e 断言：9 个 playbook × 四维（识别/良构/成功率/cleanup）+ verdict 四态 + `fixtures/expected.yaml` | `tests/e2e/`、`tests/e2e/fixtures/` | gate e2e 10 passed；`python -m tools.gate` 绿 |
| **S2** | P4-3 收尾：修复 W-P4 引擎重构遗留的测试/兼容断点（canary 下沉 `exfil` re-export + 2 个 playbook 测试指向新 `build_adapter` 入口） | `assess/impact/exfil.py`、`tests/test_playbook*.py` | gate pytest 全绿（原 8 失败已修复） |
| **S3** | P4-5 暂缓落地：BL-094 登记（本文件决策 2 已含，登记进 `docs/backlog.md`） | `docs/backlog.md` | 条目可复现、状态 open |
| **S4** | W-P5 P5-2：`git rm --cached data/seeds/asr_history.json` + 运行时产物迁 `outputs/` | 仓库卫生 | dry-run 后 `git status` clean（BL-052 已闭环，复核一致性） |
| **S5** | W-P5 P5-1：`pyproject.toml` `include` 补 `targets*` + `[project.scripts]` 与 README §4 对齐（BL-055 已闭环，复核） | `pyproject.toml` | NFR-24 达成 |
| **S6** | W-P5 P5-4：6 个超限文件登记 `DEBT-xxx`（不拆分，C4/NEG-1） | `10-ARCHITECTURE.md` 债务簿、`docs/backlog.md` | 债务簿只减不增成立（BL-026/BL-053 关联） |
| **S7** | W-P5 P5-5：YAML 遗留字段清理（先迁消费者再删字段，并入 CP-010，不本波拆） | `config/components/*.yaml` | 旧字段 0 命中（BL-025/BL-050 关联） |
| — | W-P5 P5-3：`.gitignore` 乱码 — **SKIP**：E-12 已撤回，文件为合法 UTF-8（字节级校验 U+FFFD=0），改动违背最小变更 | — | 不动作 |

## W-P5 状态（交付包装）

| 子项 | 结论 | 说明 |
|------|------|------|
| P5-1 `pyproject.toml` | ✅ 已满足（无改动） | `include` 已含 `targets*`（pyproject:63）；`[project.scripts]` 已含 `pyrit-mock-range`/`pyrit-oob`（BL-055 已闭环）；E-12 乱码已撤回 |
| P5-2 `asr_history` | ✅ 已满足（no-op） | 文件在磁盘但已 gitignore 且**未跟踪**（`git ls-files` 空 + `git check-ignore` 命中）；`git rm --cached` 无对象，运行时产物不污染工作树 |
| P5-3 `.gitignore` | ⏭ SKIP | E-12 已撤回，文件为合法 UTF-8（U+FFFD=0），改动违背最小变更 |
| P5-4 超限文件 DEBT | ✅ 已登记 | BL-095~BL-100 登记 E-14 六超限文件（不在本波拆分，C4/NEG-1） |
| P5-5 遗留 YAML 字段 | ⏸ 延缓（下一谨慎切片） | `mcp.yaml` 等 `seeds`/`scorer` 标注「W0 契约字段 / 供 core/registry 老调用方消费」；须先核对 `core/registry.py` + 全量消费者零旧字段引用（C5 谨慎、呼应「不盲删」），再清理。本波不动作 |

## 每片验收（勾选）

- [x] **S1** 完成：e2e 10 passed；gate 绿
- [x] **S2** 完成：gate pytest 全绿（8 失败 + test_adapter_registry I001/F401 已修复）
- [x] **S3** 完成：P4-5 暂缓登记 BL-094
- [x] **W-P5 P5-1/P5-2** 已满足（无改动）
- [x] **W-P5 P5-4** 完成：BL-095~BL-100 登记
- [ ] **W-P5 P5-5** 遗留 YAML 字段清理：待消费者核对后作为下一谨慎切片
