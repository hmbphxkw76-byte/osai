# TASK-CP012 — 收口 REQ-151 前置跨层违例 S4/S5/S6（执行计划）

> **状态**：approved（CP-012 已 approved，2026-09-14 自动批准：符合 NEG-4 / C3 / IC-2 / [sid:30-ch3] / ASR 中性）
> **关联**：CP-012、BL-082 ②、BL-090、REQ-151（前置依赖，非特性本体）
> **执行策略**：沿用 CP-009 S2/S3/S7 的"共享符号下沉 `core` + 原模块 re-export 保兼容"模式；每片 ≤3 文件 / diff ≤300 / 跨模块 ≤2（[sid:30-ch3]）；逐片 `tools.gate` 全绿后孤立提交；不实现 PlaybookEngine 特性本体。

## 切片

| 片 | 跨层对 | 符号 | 收口手法 | 验收 |
|----|--------|------|----------|------|
| **S6** | strike→recon | `AgentCard` / `get_stealth_manager` / `get_tls_verify` | 经 core.adapter_registry 注册表取用（recon 登记 3 符号 / strike 9 站点改经 get_adapter） | 零裸 import + 删 `("strike","recon")` 豁免 + gate 绿 |
| **S4** | recon→strike | `get_shared_bridge` / `SessionConfig` / `SessionStateManager` | 下沉 `core`（recon/strike 双侧改经 core 引用 + 原模块 re-export） | 零裸 import + 删 `("recon","strike")` 豁免 + gate 绿 |
| **S5** | core→recon | `ParsedBurpRequest` / `parse_burp_request` / `get_playwright_handles` | 下沉 `core`（定义迁 core，recon 侧改经 core 引用 + re-export） | 零裸 import + 删 `("core","recon")` 豁免 + gate 绿 |

## 每片验收（勾选）

- [ ] 该跨层对零裸 import（`grep 'from <dep>\.'` 确认）
- [ ] 删对应 `_IMPORT_DEBT_EXCEPTIONS` 条目后 `tools.gate` R-IMPORT 0 违规
- [ ] `ruff check .` 全树 0 违例
- [ ] 既有测试全绿 + 针对性 re-export 兼容单测
- [ ] 孤立提交（仅本片文件，不带入兄弟切片/特性 WIP）
