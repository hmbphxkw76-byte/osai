# CP-007 — WARNING→BLOCKING 护栏升级评估（P4）

> 状态：approved（用户授权执行，视为 C12 批准）
> 跨模型审查：按 R-CROSS-1 降级为人工审查（needs-cross-model-pending = true，单模型环境）

## 1. 背景
`tools/guard` 当前对大量红线规则仅报 WARNING（不阻断 push），红队工具在"原则 ≠ 强制"的缺口下，易在迭代中悄悄退化。
本 CP 评估每条 WARNING 规则的升级可行性，仅把**当前零违规且项目已授权**的规则升为 BLOCKING，把"有意保持 WARNING"的规则显式记录在案（避免将来误判）。

## 2. 评估原则
- **安全升级**：仅当该规则当前 `tools.guard` 实跑 **0 违规**时才可升 BLOCKING（否则立即阻断既有 push）。
- **有意 WARNING 不升**：guard.md 明确写明的"人工编排降级 / 设计即 WARNING"规则（R-CROSS-*、R-DATA-*、R-WEB-*、R-DECIDE-*、R-DOC-*、R-DRIFT-*、R-GATE-3）保持 WARNING，因其阻断需配套自动化/流程到位。
- **已授权升级**：规则自身注释/规约写明"X 起 BLOCKING"的，按授权升级。

## 3. 规则逐条评估

| 规则 | 当前级 | 当前违规 | 处置 | 理由 |
|------|--------|----------|------|------|
| R-EVENT-1 编排层硬编码组件名 | WARNING | 0 | **→ BLOCKING** | 代码注释明示"W4 起 BLOCKING"；dispatcher 仍豁免直至迁移完成 |
| R-DATA-1 数据流完整性 | INFO/WARNING | 0 | 保持 WARNING | 设计即 INFO/WARNING（提示修复） |
| R-DATA-2 ctx 仅服务 ASR | WARNING | 0 | 保持 WARNING | 设计即 WARNING |
| R-DOC-1/2/3/5 文档同步 | WARNING | 0 | 保持 WARNING | 文档纪律，非硬错 |
| R-DRIFT-2/5 漂移检测 | WARNING | 0 | 保持 WARNING | 文档-代码同步提示 |
| R-DECIDE-2/3/5 自主决策 | WARNING | 0 | 保持 WARNING | 决策治理提示 |
| R-WEB-2/3/4 Web 攻击 | WARNING | 0 | 保持 WARNING | Web 适配提示 |
| R-CROSS-1/3/4/5 跨模型 | WARNING | 0 | 保持 WARNING | 人工编排降级（RE-25 明示），自动化就位后升 |
| R-GATE-3 钩子安装 | WARNING | 0 | 保持 WARNING | 环境提示 |
| R-PIPE-3/6 流水线集成 | WARNING | 0 | 保持 WARNING | 集成完整性提示 |
| R-REDTEAM-1 红队实践 | WARNING | 0 | 保持 WARNING | 实践提示 |

## 4. 本次变更
- `tools/guard_extended.py`：`check_no_hardcoded_component_names`（R-EVENT-1）`severity=Severity.WARNING` → `Severity.BLOCKING`；同步更新级别注释。
- 其余 WARNING 规则维持不变（见 §3 表，均有据"有意 WARNING"）。

## 5. 验证
- `python -m tools.guard` → R-EVENT-1 仍 0 违规（dispatcher 豁免），整体不新增 BLOCKING 阻断。
- `python -m tools.gate --stage commit` → 全绿（除既有 S2 文档重组 waiver）。

## 6. 审查（人工）
- 批准人：<user>（本会话授权"按 ROI 执行"）
- needs-cross-model-pending：true（R-CROSS-1 降级，单模型环境）
- 合并裁决：人工
