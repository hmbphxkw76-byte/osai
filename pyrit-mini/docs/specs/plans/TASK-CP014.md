# TASK-CP014 — BL-093 收口：agent I13 副作用清理分发器

> **状态**：approved（2026-09-15 自动批准；沿用 BL-064 同款机制，非新建第二套机制（C3））
> **关联**：CP-014 / BL-093 / I13 / BL-064（同型先例）

## 关键决策（本会话核实）

1. **agent 的 cleanup 动作已实装**：`unregister_rogue_tool` / `restore_agent_tools` 均在 `strike/agent/cleanup.py` 注册并通过 `preflight_cleanup`。缺口**仅在分发器缺失**——全仓无 `run_agent_attack`，故清理从未在真实攻击路径执行。
2. **沿用既有三段式，不新建机制（C3）**：模式与 `run_file_upload_attack`（`strike/multimodal_upload/file_upload_executor.py:443-595`）完全一致（preflight → 攻击 → log → cleanup）。唯一新增 verbs = 与既有 `/tools/unregister`、`/tools/restore` 对称的 `/tools/register` POST。
3. **dry-run 早退**：`_run_file_upload_phase:625` 现行约定为 dry-run 直接返回；本任务的 `_run_agent_attack_phase` 沿用同一约定，dry-run 不产生任何副作用。

## 切片

| 片 | 任务 | 落点 | 验收 |
|----|------|------|------|
| **S1** | `run_agent_attack` 分发器（preflight → 注册 → log → cleanup） | `strike/agent/attacks.py`(新) + `__init__.py` | 函数可导入；`__all__` 含之 |
| **S2** | 流水线接线：`_run_agent_attack_phase` + `strike.py` await | `core/phases/_strike_subphases.py` + `core/phases/strike.py` | 路径可达；dry-run 早退 |
| **S3** | CLI 参数（`--agent-target` 等 4 项） | `core/_arg_parser.py` | `main.py --help` 可见；`--dry-run` 不报错 |
| **S4** | 回归单测（aiohttp 全 mock，R-S4） | `tests/agent/test_attacks.py`(新) | pytest 全绿 |
| **S5** | 记录闭环（backlog + 过时注释） | `docs/backlog.md` + `config/components/agent.yaml` + `strike/agent/cleanup.py` | BL-093 closed；无"待 BL-093"残留注释 |

## 每片验收（勾选）

- [x] **S1** 完成：`run_agent_attack` 落地并导出
- [x] **S2** 完成：`strike.py` 真实接线
- [x] **S3** 完成：CLI 参数可用
- [x] **S4** 完成：`pytest tests/agent/test_attacks.py` 全绿
- [x] **S5** 完成：BL-093 闭环 + 过时注释清理
