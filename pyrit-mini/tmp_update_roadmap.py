#!/usr/bin/env python
"""Temporary script to update ROADMAP.md"""

with open('docs/specs/50-ROADMAP.md', 'r', encoding='utf-8') as f:
    content = f.read()

# Replace Phase 1B section
old_phase1b = '''### 阶段 1B — 企业基础设施攻击（Glue 层实施）

> **目的**：通过 Glue 层扩展 PyRIT 原生框架，覆盖企业级 AI 系统（认证、向量 DB、网关、审计、微调）的攻击面。本阶段对应 10-ARCHITECTURE 新增 glue/ 层与 40-GUARDRAILS R-GLUE-1~R-GLUE-5 护栏。

| 序 | 任务 | 引用 | 说明 |
|----|------|------|------|
| T1B-1 | Glue 层骨架搭建 | REQ-127 | 创建 glue/ 目录结构 + `__init__.py` 入口 + 基类定义 |
| T1B-2 | 认证攻击 Glue | REQ-128 | `enterprise_auth_glue.py`：JWT alg=none、RS256→HS256 降级、JWKS 注入（arXiv:2207.01077） |
| T1B-3 | 向量 DB 攻击 Glue | REQ-129 | `vector_glue.py`：恶意文档注入、相似度操纵（arXiv:2302.12173） |
| T1B-4 | API 网关攻击 Glue | REQ-130 | `gateway_glue.py`：CL.TE/TE.CL 走私、路径参数覆盖 |
| T1B-5 | 审计逃逸 Glue | REQ-131 | `audit_evasion_glue.py`：CRLF 注入、日志格式绕过（CVE-2023-50164） |
| T1B-6 | 微调后门 Glue | REQ-132 | `finetuning_glue.py`：数据投毒、训练样本污染（arXiv:2301.00553） |
| T1B-7 | 统一编排器 | REQ-133 | `enterprise_orchestrator.py`：整合 5 大 Glue 模块 + orchestration_log 集成 |
| T1B-8 | 护栏检查器锚定 | R-GLUE-1~5 | 在 `architecture_guard.py` 实现 5 项 Glue 层检查器 |

**退出条件**：① 5 大 Glue 模块全部通过 `try/except ImportError` 插件化隔离测试（R-GLUE-1）；② 全部攻击向量有 arXiv/CVE 注释（R-GLUE-5 INFO 清零）；③ `enterprise_orchestrator.py` 单命令可跑 dry-run；④ 40-GUARDRAILS 1D 护栏全量合规。'''

new_phase1b = '''### 阶段 1B — 企业基础设施攻击（Glue 层实施，v1.3 精简）

> **v1.3 变更（2026-09-08 过度工程化清理）**：原规划 8 项任务精简为 4 项有效任务。删除 T1B-3（向量DB攻击 Glue）和 T1B-6（微调后门 Glue）——需向量DB SDK/训练环境API直接访问，黑盒HTTP目标测试场景无法执行。相关攻击向量通过间接注入seed覆盖。精简 T1B-5（审计逃逸）为仅日志注入。

| 序 | 任务 | 引用 | 说明 |
|----|------|------|------|
| T1B-1 | Glue 层骨架搭建 | REQ-127 | 创建 glue/ 目录结构 + `__init__.py` 入口 |
| T1B-2 | 认证攻击 Glue | REQ-127 | `enterprise_auth_glue.py`：JWT alg=none、RS256→HS256 降级、kid注入 |
| T1B-3 | ~~向量 DB 攻击 Glue~~ | ~~已删除~~ | ~~需向量DB SDK直访，黑盒HTTP不可测试，通过间接注入seed覆盖~~ |
| T1B-4 | API 网关攻击 Glue | REQ-129 | `gateway_glue.py`：CL.TE/TE.CL 走私、路径参数覆盖 |
| T1B-5 | 审计逃逸 Glue | REQ-130 | `audit_evasion_glue.py`：CRLF/ANSI/时间戳伪造日志注入 |
| T1B-6 | ~~微调后门 Glue~~ | ~~已删除~~ | ~~需训练环境API访问，黑盒HTTP不可测试，通过间接注入seed覆盖~~ |
| T1B-7 | 统一编排器 | REQ-132 | `enterprise_orchestrator.py`：整合 3 大 Glue 模块 |
| T1B-8 | 护栏检查器锚定 | R-GLUE-1~5 | 在 `architecture_guard.py` 实现 5 项 Glue 层检查器 |

**退出条件**：① 3 大 Glue 模块（auth/gateway/audit）全部通过 `try/except ImportError` 插件化隔离测试（R-GLUE-1）；② 全部攻击向量有 arXiv/CVE 注释（R-GLUE-5 INFO 清零）；③ `enterprise_orchestrator.py` 单命令可跑 dry-run；④ 40-GUARDRAILS 1D 护栏全量合规。'''

content = content.replace(old_phase1b, new_phase1b)

# Update version history
old_version = '| v1.2 | 2026-09-08 | REV-04 企业攻击路线图增补：① 新增阶段 1B 企业基础设施攻击（Glue 层实施，含 8 项任务 T1B-1~T1B-8）；② 依赖链更新为包含阶段 1B；③ 覆盖企业 AI 系统 5 大攻击面（JWT 认证、向量 DB、API 网关、审计日志、微调后门） | 用户会话批准 |'
new_version = '| v1.2 | 2026-09-08 | REV-04 企业攻击路线图增补：① 新增阶段 1B 企业基础设施攻击（Glue 层实施，含 8 项任务 T1B-1~T1B-8）；② 依赖链更新为包含阶段 1B；③ 覆盖企业 AI 系统 5 大攻击面（JWT 认证、向量 DB、API 网关、审计日志、微调后门） | 用户会话批准 |\n| v1.3 | 2026-09-08 | REV-05 过度工程化清理（精简 Glue 层路线图）：① 删除 T1B-3 向量DB攻击（黑盒HTTP不可测试）；② 删除 T1B-6 微调后门（黑盒HTTP不可测试）；③ 精简 T1B-5 审计逃逸为仅日志注入；④ 退出条件从"5大模块"更新为"3大模块" | 用户会话批准 |'

content = content.replace(old_version, new_version)

with open('docs/specs/50-ROADMAP.md', 'w', encoding='utf-8') as f:
    f.write(content)

print('ROADMAP updated successfully')
