# 变更提案：CP-005（拆分超长规约文档 + 不变量清单外置）

> **类型**：蓝图变更 + 债务登记（新 DEBT）
> **提案人 / 日期**：AI 代理 / 2026-09-13
> **状态**：draft

## 1. 动机

`55-ATTACK-GAP-CLOSURE.md`（802 行）、`10-ARCHITECTURE.md`（527 行）、`40-GUARDRAILS.md`（487 行）超长。整文件读+写成本高、易丢内容，是"换个模型就整篇重写"的主要诱因之一（本会话已用 `[sid:...]` 锚点 + `spec_lint` 缓解，但文件体量本身未变）。

与现行条款的冲突/留白：
- 宪法 C4（最小变更）：大文件上一处小改，diff 也易扩散；
- 文档纪律 D4（清单不进正文）：`10-ARCHITECTURE.md` 第六章不变量表（I1–I13）仍在正文手工维护，未外置。

## 2. 条款/规格 diff（精确到文件与结构）

| 文件 | 位置 | 现文 | 改为 |
|------|------|------|------|
| `55-ATTACK-GAP-CLOSURE.md` | 全文 | 缺口 1–6 + 集成/验证/文件清单/引用/决策 12 章同文件 | 保留为**索引**（缺口清单 + 指针 + 决策章）；缺口 1–6 各拆为 `55-gap-1.md` ~ `55-gap-6.md`（每文件 ≤200 行） |
| `10-ARCHITECTURE.md` | 第六章（I1–I13 不变量表） | 正文手工表格 | 外置 `config/invariants.yaml`，正文改为"清单读 YAML"（D4），由 `tools/drift_detector.py` 读取校验 |
| `40-GUARDRAILS.md` | 1F 检查器登记簿 | 已指向代码（D4 满足） | **不拆**（已合规） |

## 3. 影响面

- 触及：D4（清单外置）、C4（最小变更）、R-DOC-2（`check_attack_gap_documented` 硬依赖 `55-ATTACK-GAP-CLOSURE.md` 单文件路径）
- **guard 检查器**：`tools/guard_extended.py` 的 `_DOCS_GAP_PATH` 从单文件改为 glob 匹配 `55-gap-*.md`（同步 `check_attack_gap_documented`）
- 同批义务：`specs/README.md` §1 索引 55 行改为"索引 + 缺口子文件"；各拆分文件头版本号
- 迁移/兼容：`drift_detector.py` 不变量表改读 `config/invariants.yaml`；`55` 的 sid 锚点保留（`[sid:55-gap1-filter]` 等随文件迁移）

## 4. ASR 影响评估

**中性**——纯文档结构重构，不触碰任何攻击/评分/数据流代码路径。

## 5. 评审结论（人工填写，AI 不得代填）

- [ ] 批准（附条件：___）
- [ ] 驳回（理由：___）
- [ ] 转 backlog（BL-___）

评审人 / 日期：
