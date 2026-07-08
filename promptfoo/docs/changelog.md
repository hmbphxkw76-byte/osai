# 变更日志 (Changelog)

> 记录提示词、配置、测试用例的重要变更

---

## [Unreleased]

### 2026-07-08 - 项目重构

#### Added
- 新增标准目录结构（prompts/, tests/, assertions/, providers/, datasets/, redteam/, scripts/, docs/）
- 新增根级核心配置文件: `promptfooconfig.yaml`, `promptfooconfig.redteam.yaml`, `promptfooconfig.regression.yaml`
- 新增提示词模板: system_prompt, chat_completion, summarize, translate, rag/retrieval, rag/answer
- 新增测试用例集: tests.yaml, edge_cases.yaml, safety_tests.yaml, multilingual.csv
- 新增自定义断言: custom_assertion.js, semantic_similarity.py, pii_checker.js
- 新增自定义 Provider: custom_api_provider.py, mock_provider.py
- 新增数据集: golden_dataset.json, conversation_logs.jsonl, synthetic_data.csv
- 新增红队配置: attack_prompts.yaml, policies/safety_policy.yaml, plugins/custom_plugin.js
- 新增辅助脚本: run_eval.sh, run_redteam.sh, compare_results.js
- 新增文档: evaluation_strategy.md, module_mapping.md
- 新增 .gitignore 文件

#### Added (补充)
- 新增 `promptfooconfig.quick.yaml` - 快速扫描配置（5-10min，从旧 simple 配置迁移）
- 新增 `promptfooconfig.advanced.yaml` - 深度扫描配置（20-30min，从旧 advanced 配置迁移）

#### Changed
- 所有 M01-M19 模块的 YAML 配置迁移至 `redteam/modules/` 目录
- 所有模块文档迁移至 `docs/` 目录
- send_redteam.py 重构为 `providers/custom_api_provider.py`
- 旧的 promptfooconfig.yaml/simple/advanced 三个通用配置重组为根目录四个场景配置:
  - `promptfooconfig.yaml` (标准)
  - `promptfooconfig.quick.yaml` (快速扫描)
  - `promptfooconfig.advanced.yaml` (深度扫描)
  - `promptfooconfig.redteam.yaml` (红队全量)
  - `promptfooconfig.regression.yaml` (回归测试)

#### Removed
- 删除旧目录: `00_通用配置/`, `M01_*` ~ `M19_*` (所有内容已迁移至新结构)
- 删除根目录 `AI300_module_mapping.md` (已迁移至 `docs/module_mapping.md`)

### 2026-07-08 - 文档目录重组

#### Changed
- 重组 `docs/` 目录结构，按最佳实践将散落的文档分类到子目录：
  - `docs/guides/` - 用户指南（7 个：ARCHITECTURE、FRONTIER_VULNS、PAYLOAD_LOADING、PENETRATING_MODE_GUIDE、evaluation_strategy、promptfooconfig、send_redteam）
  - `docs/modules/` - 红队模块文档（15 个，对应 redteam/modules/*.yaml）
  - `docs/reference/` - 参考资料（module_mapping.md）
  - `docs/dev-standards/` - 开发规范（保持不变，4 个）
- 重写 `docs/README.md` 为文档总索引，按"快速开始/架构与原理/红队模块/开发规范"分类

#### Fixed
- 修复所有因文件移动而失效的相对链接：
  - `docs/guides/*.md` 中指向 dev-standards/ 的链接（8 处 `dev-standards/` → `../dev-standards/`）
  - `docs/guides/PENETRATING_MODE_GUIDE.md` 中 module_mapping.md 链接（→ `../reference/module_mapping.md`）
  - `.trae/skills/promptfoo-project-standard/SKILL.md` 中 4 个用户文档链接（→ `docs/guides/*.md`）
  - `docs/dev-standards/architecture-design.md` 目录结构图与项目检查清单
  - `docs/dev-standards/README.md` 目录结构图
  - 修复预存错误：`dev-standards/README.md` 中 `architecture-patterns.md` → `architecture-design.md`

### 2026-07-08 - 开发规范 IDE 无关化

#### Added
- 新增 `docs/dev-standards/` 自包含开发规范体系（IDE 无关）:
  - `README.md` - 规范入口与索引
  - `architecture-design.md` - 目录结构、命名约定、注释规范、版本控制、项目检查清单
  - `config-patterns.md` - 核心配置、环境变量、提示词模板、自定义 Provider、测试最佳实践
  - `yaml-patterns.md` - 测试用例、断言、红队测试规范、模块组织
- 新增用户文档:
  - `docs/ARCHITECTURE.md` - 项目架构说明（面向使用者）
  - `docs/FRONTIER_VULNS.md` - 前沿漏洞类型（OWASP/Agentic AI/MCP/A2A）
  - `docs/PAYLOAD_LOADING.md` - Payload 加载机制详解
  - `docs/PENETRATING_MODE_GUIDE.md` - 渗透模式选择指南

#### Changed
- `.trae/skills/promptfoo-project-standard/SKILL.md` 改造为轻量级入口，规范主体迁移至 `docs/dev-standards/`
- 开发规范不再依赖 Trae IDE 目录，兼容任意 IDE（VS Code、Cursor、JetBrains 等）

---

## [历史版本]

### v1.0.0 - 初始版本（重构前）

#### Added
- 00_通用配置: 基础 promptfooconfig 配置和 send_redteam.py 自定义 Provider
- M01-M19: LLM 渗透测试 各模块红队测试配置
  - M01: LLM 基础与攻击面
  - M02: 提示注入与越狱
  - M03: RAG 系统攻击
  - M04: 多智能体系统攻击
  - M05: MCP 协议攻击
  - M06: A2A 协议攻击
  - M07: AI 编码助手攻击
  - M08: 多模态 AI 攻击
  - M09: 多输入 API 攻击
  - M10: AI 供应链安全
  - M11: 嵌入与向量数据库攻击
  - M12: AI 基础设施安全
  - M13: 模型漂移与安全监控
  - M14: 行业合规与垂直领域
  - M15: OWASP 标准对照
  - M16: AgentAI 标准对照
  - M17: MCP 标准对照
  - M18: A2A 标准对照
  - M19: 全量覆盖与终极套件
- .env.example: 多平台 API 配置模板
- AI300_module_mapping.md: 测试大纲映射表
