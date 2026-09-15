# CP-014 — BL-093 收口：agent 组件 I13 副作用清理分发器（`run_agent_attack`）

> **类型**：缺口闭环（BL-093 / 不变量 I13）
> **提案人 / 日期**：AI (CodeBuddy) / 2026-09-15
> **状态**：draft → **approved**（2026-09-15 自动批准：用户授权"全程自动批准符合最佳实践的方案"；沿用 BL-064 已验收的同款机制，非新建第二套清理/分发机制（C3），ASR 中性）
> 跨模型审查：按 R-CROSS-1 降级为人工审查（needs-cross-model-pending = true，单模型环境）

## 1. 动机（坐标签证）

`agent` 组件的副作用清理**已实装但未接线**：

- `config/components/agent.yaml:74` 声明 `cleanup: [unregister_rogue_tool, restore_agent_tools]`；
- 两动作均已实装并经 `@register_cleanup_action` 注册（`strike/agent/cleanup.py:26/75`），`preflight_cleanup` 校验通过；
- **但**全仓无 `run_agent_attack`（`strike/agent/` 仅有 `__init__/cleanup/exfiltration/rogue_tool/tool_injector`），故 `preflight_cleanup` / `run_side_effect_cleanup` 从未在真实攻击路径被调用。

后果：rogue 工具注册（OWASP ASI10）在目标侧留下持久副作用，I13 安全保证缺失（BL-093 open）。此为 BL-064（`multimodal_upload`）的同型缺口——后者已由「分发器 + preflight + 清理」三段式闭环，ASR 由 0 升 >0 且验证 `tests/multimodal_upload/test_cleanup.py` 全绿。本 CP 对该已验收机制做同构复用。

## 2. 方案（不新建机制，C3）

沿用 `run_file_upload_attack`（`strike/multimodal_upload/file_upload_executor.py:443-595`）已验收的三段式：

1. 读 `ctx.args` 配置 + `dry_run` 判定；
2. **副作用步前** `preflight_cleanup(ctx, "agent", dry_run=...)` → 不通过则记 `orchestration_log` 并返回 `status="blocked"`（不静默放行，C9 / R-H2）；
3. 执行攻击（复用既有 payload 构造器，不做二次实现：`build_rogue_tool_schema` / `register_rogue_tool_prompt`）；
4. 记 `orchestration_log`；
5. **副作用步后** `run_side_effect_cleanup(ctx, "agent", artifacts, dry_run=...)`，结果如实回传（含 `failed` 名单）。

分发路径对齐既有：`core/phases/strike.py` → `await _run_agent_attack_phase(ctx)` → `strike.agent.attacks.run_agent_attack(ctx)`（镜像 `_run_file_upload_phase:599` 与其在 `strike.py:156` 的 await）。

**新增的唯一攻击语义**：向目标工具注册端点 POST rogue tool schema（`/tools/register` 缺省），与已存在的注销端点（cleanup 用 `/tools/unregister`、`/tools/restore`）严格对称，无第二套 I/O 机制。

## 3. 影响面

- **触及**：BL-093；不变量 **I13**；`config/components/agent.yaml`；`core/phases/*`；40-G R-H2 / C9（不静默）。
- **不触及**：`core/side_effect_cleanup.py`（共享基建不改）；组件 YAML 的 `cleanup:` 声明不变；依赖矩阵（`strike→core` ✓）。
- **governance**：不新增护栏/不变量/红线。

## 4. ASR 影响评估

**有条件转正，非静默**：接线后 `agent` 组件的**非 dry-run** 攻击才具备可执行的安全前置（I13 保证由 `preflight_cleanup` 硬性把关，动作未实装即 `blocked`）。dry-run 路径不变。是否实际产生 ASR 取决于实标高，本 CP 不做数值承诺。

## 5. 收口切片（每片 ≤3 文件 / diff ≤300 行 / 跨模块 ≤2 / 新增 ≤1，符 [sid:30-ch3]）

| 片 | 状态 | 动作 | 涉及文件 |
|----|------|------|---------|
| **S1** | ⏳ | 新增 `strike/agent/attacks.py`：`run_agent_attack(ctx)`（preflight → 注册 rogue tool → orchestration_log → cleanup）；从 `__init__.py` 导出 | `strike/agent/attacks.py`(新) + `strike/agent/__init__.py` |
| **S2** | ⏳ | 流水线接线：`_run_agent_attack_phase`（dry-run 早退）→ `strike.py` import + `await` | `core/phases/_strike_subphases.py` + `core/phases/strike.py` |
| **S3** | ⏳ | CLI 参数：`--agent-target` / `--agent-register-endpoint` / `--rogue-tool-name` / `--agent-baseline-tools` | `core/_arg_parser.py` |
| **S4** | ⏳ | 回归单测（`aiohttp` 全 mock，R-S4）：非 dry-run 下 preflight 放行且 cleanup 被调用；preflight 拒绝则 `blocked` 且不注册；dry-run 不产生副作用 | `tests/agent/test_attacks.py`(新) |
| **S5** | ⏳ | 记录闭环：`docs/backlog.md` BL-093 → completed；清除 `agent.yaml` / `strike/agent/cleanup.py` 中"待 BL-093 闭环"的过时注释 | `docs/backlog.md` + `config/components/agent.yaml` + `strike/agent/cleanup.py` |
| **闭环判据** | — | `run_agent_attack` 存在且在被 I13 preflight 把关的前提下于副作用步后调用 `run_side_effect_cleanup`；agent 攻击路径经 `strike.py` 真实 reach；S4 全绿；`tools.gate` 0 BLOCKING；BL-093 closed | — |

## 6. 风险与回滚

| 风险 | 缓解 |
|------|------|
| 动作未实装即放行 → 目标侧残留 | `preflight_cleanup` 硬性把关；非 dry-run 且 `missing` 非空 → `blocked`（继承 `core/side_effect_cleanup.py:89-99`） |
| 清理动作部分失败被吞 | `run_side_effect_cleanup` 已保证 `status="failed"` + `failed` 名单（C9）；分发器如实回传并在 `orchestration_log` 留痕 |
| 新增攻击语义越界（C11） | 唯一新增 verbs = 与既有注销端点对称的 `/tools/register` POST；payload 复用既有构造器，不重写 ASN/进攻逻辑 |
| 循环导入 / 层级违规 | `strike→core` 单向（`core.side_effect_cleanup`）；无 `strike→recon` / `core→recon` 引入 |
