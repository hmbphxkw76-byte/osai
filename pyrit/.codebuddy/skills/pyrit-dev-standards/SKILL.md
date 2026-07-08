---
name: pyrit-dev-standards
description: >
  PyRIT 红队演练平台研发规范。当进行架构设计、模块拆分、配置管理、YAML 定义、命名决策、
  文件组织或代码重构时，应使用此规范确保一致性。适用场景包括：新增模块、新增配置节、
  新增攻击策略、新增 YAML 场景模板、CLI 参数设计、模块重命名、依赖管理。
---

# PyRIT 研发规范（CodeBuddy Skill）

> **唯一真实来源**: 框架级规范目录 `contributing/`（入口: `README.md`）。
> 此 skill 是 CodeBuddy 入口层，实际规范内容以 `contributing/` 为准，兼容所有 IDE。

## 使用方式

当触发此 skill 时，CodeBuddy 应：

1. **读取** `contributing/README.md` — 七章核心规范（核心理念、代码组织、命名、配置、YAML、Python 规范、依赖管理）
2. **按需读取** `contributing/` 下的参考资料：
   - `architecture-design.md` — 架构分层与 5 种设计模式
   - `config-patterns.md` — 配置管理模式与实战示例
   - `yaml-patterns.md` — YAML 三层体系与加载器模式
3. **严格遵循**规范执行所有架构、配置、代码相关决策

## 规范概览（快速索引）

| 场景 | 查阅章节 | 关键原则 |
|------|---------|---------|
| 新增模块/文件 | 第三、六章 | 全称命名、语义优先、`__init__.py` 公开 API |
| 新增配置 | 第一.2、第四章 | `configs/` 定义、`.env` 选择、优先级 CLI > 预设 > 默认 |
| 新增 YAML | 第一.1、第五章 | 三层体系、索引驱动、Front Matter 注释 |
| 架构重构 | 第一.3、第二章 | Bootstrap/Facade/Factory/Router/Strategy 模式 |
| 新增依赖 | 第七章 | 版本上限锁定、审批三问 |
| 控制台输出 | 第六.4 | Rich Console、emoji 状态行格式 |
