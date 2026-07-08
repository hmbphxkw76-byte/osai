---
name: "promptfoo-project-standard"
description: "Promptfoo 项目开发标准与设计框架。在创建新的 promptfoo 项目、重构现有项目、或需要遵循标准化目录结构和开发规范时调用。规范主体位于 docs/dev-standards/，IDE 无关。"
---

# Promptfoo 项目开发标准（Trae 入口）

> **本文件是 Trae IDE 的轻量级触发入口。**
> **规范主体始终以 `docs/dev-standards/` 为准，确保 IDE 无关。**

---

## 规范主体位置

完整的开发标准体系位于项目根目录的 `docs/dev-standards/`，可被任意 IDE 访问：

| 文档 | 内容 |
|------|------|
| [`docs/dev-standards/README.md`](../../../docs/dev-standards/README.md) | 规范入口与索引 |
| [`docs/dev-standards/architecture-design.md`](../../../docs/dev-standards/architecture-design.md) | 目录结构、命名约定、注释规范、版本控制、项目检查清单 |
| [`docs/dev-standards/config-patterns.md`](../../../docs/dev-standards/config-patterns.md) | 核心配置、环境变量、提示词模板、自定义 Provider、测试最佳实践 |
| [`docs/dev-standards/yaml-patterns.md`](../../../docs/dev-standards/yaml-patterns.md) | 测试用例、断言、红队测试规范、模块组织 |

## 用户文档

面向使用者的文档位于 `docs/guides/`：

| 文档 | 内容 |
|------|------|
| [`docs/guides/ARCHITECTURE.md`](../../../docs/guides/ARCHITECTURE.md) | 项目架构说明 |
| [`docs/guides/FRONTIER_VULNS.md`](../../../docs/guides/FRONTIER_VULNS.md) | 前沿漏洞类型 |
| [`docs/guides/PAYLOAD_LOADING.md`](../../../docs/guides/PAYLOAD_LOADING.md) | Payload 加载机制 |
| [`docs/guides/PENETRATING_MODE_GUIDE.md`](../../../docs/guides/PENETRATING_MODE_GUIDE.md) | 渗透模式指南 |

---

## 调用本 Skill 后的行为

当本 Skill 被触发时，应：

1. **优先阅读** `docs/dev-standards/README.md` 获取规范全貌
2. **按需查阅** 以下子文档：
   - 新建/重构项目 → `architecture-design.md`
   - 编写配置/Provider → `config-patterns.md`
   - 编写测试/红队配置 → `yaml-patterns.md`
3. **遵循规范** 中定义的目录结构、命名约定和最佳实践

---

## 设计原则速记

| 原则 | 说明 |
|------|------|
| 数据与逻辑分离 | 测试数据、配置、提示词全部外置 |
| 最小化修改 | 测试仅改 `.env` + YAML body 字段名 |
| 数据默认 JSON | 数据集使用结构化格式 |
| 命名统一 | 英文命名，`.md` 与代码同名 |
| 代码可读 | 中文逐行注释 |
| IDE 无关 | 规范主体在 `docs/`，不依赖特定 IDE |

---

## 其他 IDE 集成方式

本规范不依赖 Trae，其他 IDE 可通过以下方式使用：

- **VS Code**: 将 `docs/dev-standards/` 添加到工作区推荐文档
- **Cursor**: 在 `.cursorrules` 中引用 `docs/dev-standards/README.md`
- **JetBrains**: 使用 Live Templates 引用规范模板
- **任意编辑器**: 直接阅读 `docs/dev-standards/` 下的 Markdown 文件
