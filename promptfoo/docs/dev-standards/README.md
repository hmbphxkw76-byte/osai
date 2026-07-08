# Promptfoo 项目开发标准

> **IDE 无关的自包含规范体系** — 适用于任意编辑器/IDE（VS Code、Cursor、Trae、JetBrains 等）。
> 本规范定义了 Promptfoo LLM 评估项目的目录结构、命名规范、配置约定和最佳实践。
> 适用于 安全评估 LLM 渗透测试 / LLM 安全评估 实战演练及生产级 LLM 评估项目。

---

## 📐 设计哲学

| 原则 | 说明 |
|------|------|
| **数据与逻辑分离** | 测试数据、配置、提示词全部外置，不硬编码在代码中 |
| **最小化修改** | 测试仅需改 `.env` + YAML 中 `body` 字段名（1 行） |
| **数据默认 JSON** | 数据集使用 JSON/JSONL/CSV 等结构化格式 |
| **命名统一** | 英文命名，体现主要功能，`.md` 与对应代码同名 |
| **代码可读** | 中文逐行注释，便于学习和实践 |
| **IDE 无关** | 规范不依赖任何特定 IDE 目录，纯文档自包含 |

---

## 📚 规范体系索引

本规范体系由以下文件组成，按需查阅：

| 文档 | 内容 | 适用场景 |
|------|------|----------|
| **[architecture-design.md](architecture-design.md)** | 目录结构标准、命名约定、注释规范、数据与逻辑分离、版本控制、项目检查清单 | 新建项目、重构项目、理解整体架构 |
| **[config-patterns.md](config-patterns.md)** | 核心配置文件规范、环境变量、提示词模板、自定义 Provider、测试最佳实践 | 编写配置、创建 Provider、实战演练 |
| **[yaml-patterns.md](yaml-patterns.md)** | 测试用例规范、断言最佳实践、红队测试规范、模块组织、测试快速选择 | 编写测试、红队配置、选择攻击模块 |

---

## 🚀 快速开始

### 新建项目检查清单

参见 [architecture-design.md#项目创建检查清单](architecture-design.md#六项目创建检查清单)。

### 测试三步法

参见 [config-patterns.md#测试场景最佳实践](config-patterns.md#测试场景最佳实践)。

```bash
# 第 0 步：一次性配置
cp .env.example .env  # 填入 TARGET_URL, AUTH_TOKEN, OPENAI_API_KEY

# 第 1 步：根据场景选模块
cp redteam/modules/rag_redteam.yaml promptfooconfig.yaml

# 第 2 步：改 body 字段名 + 运行
promptfoo redteam run && promptfoo redteam report
```

---

## 🗂️ 与项目结构的关系

本规范体系位于 `docs/dev-standards/`，是项目文档的一部分：

```
项目根目录/
├── docs/
│   ├── README.md                    ← 文档总索引
│   ├── changelog.md
│   ├── guides/                      ← 用户指南
│   │   ├── ARCHITECTURE.md          ← 项目架构说明
│   │   ├── FRONTIER_VULNS.md        ← 前沿漏洞类型
│   │   ├── PAYLOAD_LOADING.md       ← Payload 加载机制
│   │   ├── PENETRATING_MODE_GUIDE.md ← 渗透模式指南
│   │   ├── evaluation_strategy.md
│   │   ├── promptfooconfig.md
│   │   └── send_redteam.md
│   ├── modules/                     ← 红队模块文档
│   ├── reference/                   ← 参考资料
│   │   └── module_mapping.md
│   └── dev-standards/               ← 本规范体系（自包含）
│       ├── README.md                ← 当前文件（入口）
│       ├── architecture-design.md
│       ├── config-patterns.md
│       └── yaml-patterns.md
```

---

## 🔄 Trae IDE Skill 集成（可选）

本项目同时在 `.trae/skills/promptfoo-project-standard/SKILL.md` 保留了一个轻量级入口，
用于在 Trae IDE 中自动触发本规范。该入口仅包含元数据与指向本目录的引用，
**规范主体始终以本目录为准**，确保 IDE 无关。

其他 IDE 用户可直接阅读本目录下的文档，或通过以下方式集成：

- **VS Code**: 可使用 [Prompt Snippets](https://marketplace.visualstudio.com/) 引用本规范模板
- **Cursor**: 在 `.cursorrules` 中引用本规范路径
- **JetBrains**: 使用 Live Templates 引用本规范模板
