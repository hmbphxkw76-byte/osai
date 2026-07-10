# 贡献指南

> GitHub 会自动在 Issue/PR 创建时提示本文档。
> 详细开发规范见 [`docs/contributing/`](docs/contributing/).

---

## 快速索引

| 文档 | 内容 |
|------|------|
| [DEVELOPMENT_STANDARDS.md](docs/contributing/DEVELOPMENT_STANDARDS.md) | **唯一权威规范** — 核心理念、命名、架构、YAML、编码、集成、门禁 |
| [architecture-design.md](docs/contributing/architecture-design.md) | 架构分层与数据流详解 |
| [7-layer-architecture.md](docs/contributing/7-layer-architecture.md) | 七层攻击架构设计 |
| [config-patterns.md](docs/contributing/config-patterns.md) | 配置管理模式与实战 |
| [yaml-patterns.md](docs/contributing/yaml-patterns.md) | YAML 驱动开发模式 |
| [execution-guidance.md](docs/contributing/execution-guidance.md) | 执行期专家指导规范 |

---

> 完整项目结构见 [README.md § 目录结构](README.md#目录结构)。

## 开发流程

1. **阅读规范** → [`docs/contributing/DEVELOPMENT_STANDARDS.md`](docs/contributing/DEVELOPMENT_STANDARDS.md)
2. **确认阶段** → 在六阶段管道中找到对应落位
3. **YAML 优先** → 数据变更只改 YAML，代码是执行引擎
4. **遵循命名** → 全称、复数、动名词，参见规范第 3.1 节
5. **写类型注解** → 所有公开函数必须包含类型注解
6. **每个阶段后输出专家指导** → 使用 `utils/stage_guidance.py`

---

## 禁止事项

- ❌ 在顶层新增目录（除 `docs/` 外）
- ❌ 模块命名使用缩写（`cli/`、`exec/`、`conv/` 等）
- ❌ Python 代码中硬编码业务数据（Prompt、Payload、漏洞索引）
- ❌ 跨层反向依赖
- ❌ 文件包含 BOM 头
- ❌ CRLF 与 LF 混用
