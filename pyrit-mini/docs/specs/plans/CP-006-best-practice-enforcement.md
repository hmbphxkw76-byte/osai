# CP-006 — 最佳实践执行加固（P0–P4）

> 状态：approved（用户授权执行，视为 C12 批准）
> 跨模型审查：按 R-CROSS-1 降级为人工审查（needs-cross-model-pending = true，单模型环境）

## 1. 背景
扫描证实 `tools/security_audit.py` 已具备密钥/危险调用扫描能力，但未接入门禁（P0 缺口）；
异常吞掉（155+ 处 `except`）、库代码 `print`（57 文件）、WARNING 级护栏未升级等问题待治理。
本 CP 将"已有原则"接进门禁，把最佳实践从"有脚本没人跑"变为"强制闸"。

## 2. 变更清单
### 2.1 tools/gate.py（护栏基础设施）
- `COMMIT_STEPS` 新增 `security` 阶段：`python -m tools.security_audit`（仅真实密钥/危险调用 BLOCKING）。
- 同步更新模块 docstring 阶段描述与 `STEP_DESCRIPTIONS`（ADR-009：文档以代码为准）。
- 注：P2 的 `print` 统计**不接入门禁**——`R-GATE-2` 禁止门禁内出现非阻塞降级分支（[SKIP]/非阻塞字样）。改为手动命令 `ruff check --select T201 --statistics` 供增量重构参考（见 §3）。

### 2.2 tools/security_audit.py（护栏基础设施）
- `_SECRET_PATTERNS` 扩展：`sk-` / `ghp_` / `glpat-` / `AIza` / `ya29.` / `xox`（BLOCKING，覆盖常见云/API 令牌）。
- 新增 `BARE_EXCEPT` 检测（WARNING）：裸 `except:` 静默吞异常，破坏可观测性、污染 ASR 统计。

### 2.3 .gitignore
- 新增 `*.pem` / `*.key` / `*.p12` / `*.pfx` / `credentials*.json` / `secrets/`（P3 兜底，不影响已跟踪文件）。

## 3. 不在此 CP（后续增量）
- **P2 实际重构**：手动 `ruff check --select T201 --statistics` 查看 `print` 使用分布，按目录增量改 `logging`（不一次性重写，避免 C4 违反 + ruff 阻塞；且不接入门禁，因 R-GATE-2 禁止非阻塞降级）。
- **P4 WARNING→BLOCKING 升级**：列出候选 R-*（如 R-DOC-2），单独 CP 评估，不在此批量改动。

## 4. 验证
- `python -m tools.security_audit` → 退出码 0（无 BLOCKING）。
- `python -m tools.gate --stage commit` → 全绿（含 security 阶段）。
- `python -m tools.gate --stage push` → 全绿（security 阶段仅 BLOCKING 密钥/危险调用）。

## 5. 审查（人工）
- 批准人：<user>（本会话授权"按 ROI 执行"）
- needs-cross-model-pending：true（R-CROSS-1 降级，单模型环境）
- 合并裁决：人工
