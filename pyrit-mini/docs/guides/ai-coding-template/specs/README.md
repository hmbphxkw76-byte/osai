# ${PROJECT_NAME} — specs/ 目录说明

本目录使用 AI 编程规范框架（见 `ai-dev-guides.md` / `ai-dev-audit.md`）管理**规范分层金字塔**。

| 文件 | 层级 | 作用 |
|------|------|------|
| `00-CONSTITUTION.md` | L0 宪法 | 最高约束、使命、红线 |
| `10-ARCHITECTURE.md` | L1 蓝图 | 架构、模块、数据契约 |
| `20-REQUIREMENTS.md` | L2 需求 | 做什么、验收、负需求 |
| `40-GUARDRAILS.md` | L4 护栏 | 红线、质量关卡 |
| `60-CROSS-MODEL.md` | 跨模型政策 | 多模型一致性政策 |
| `backlog.md` | 待办池 | 非本任务问题登记 |
| `TASK-TEMPLATE.md` | L3 任务模板 | 复制为 `TASK-xxx.md` |
| `CHANGE-PROPOSAL-TEMPLATE.md` | 变更提案 | 规范变更流程 |
| `cross-model/REVIEW-TEMPLATE.md` | 审查报告 | 跨模型审查归档 |

## 工作流
开发前必看（规范）→ 开发中必跑（质量关卡）→ 开发后必验（交付验收清单）。

## 初始化
本骨架由 `ai-coding-template` 生成：编辑 `template.config.yaml` 后运行 `python init.py`。
