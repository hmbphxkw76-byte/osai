# 贡献指南

> GitHub 会自动在 Issue/PR 创建时提示本文档。
> 详细开发规范见 [`docs/contributing/`](docs/contributing/).

---

## 快速索引

| 文档 | 内容 |
|------|------|
| [README.md](docs/contributing/README.md) | **核心规范** — 命名、架构、配置、YAML 设计模式 |
| [DEVELOPMENT_STANDARDS.md](docs/contributing/DEVELOPMENT_STANDARDS.md) | **强制标准** — 六阶段管道、数据流、目录结构约束 |
| [architecture-design.md](docs/contributing/architecture-design.md) | 架构分层与数据流详解 |
| [7-layer-architecture.md](docs/contributing/7-layer-architecture.md) | 七层攻击架构设计 |
| [config-patterns.md](docs/contributing/config-patterns.md) | 配置管理模式与实战 |
| [yaml-patterns.md](docs/contributing/yaml-patterns.md) | YAML 驱动开发模式 |
| [execution-guidance.md](docs/contributing/execution-guidance.md) | 执行期专家指导规范 |

---

## 项目结构

```
RedTeam_AI/
├── README.md                     # 项目总览 + 快速启动
├── Makefile                      # 统一命令入口
├── CONTRIBUTING.md               # 本文档
├── docs/
│   ├── architecture.md           # 项目级架构文档
│   └── contributing/             # 📋 开发规范标准（唯一权威）
│       ├── README.md             #   核心研发规范
│       ├── DEVELOPMENT_STANDARDS.md  #   强制标准
│       └── ...                   #   专题规范
│
├── recon/                        # L0 前置侦察引擎
│   ├── recon/                    # 侦察引擎核心
│   │   ├── scanners/             # Web 扫描器
│   │   ├── probes/               # AI 探针
│   │   ├── auth/                 # 认证自动化
│   │   └── analysis/             # 行为分析
│   ├── web/                      # Web UI (Flask)
│   ├── templates/                # 前端模板
│   ├── wordlists/                # 扫描字典
│   └── outputs/                  # 侦察结果
│
└── pyrit/                        # L1-L5 AI 攻击框架
    ├── main.py                   # CLI 入口
    ├── entrypoint/               # CLI 层（解析→回显→引导→路由）
    ├── orchestrators/            # 编排层（六阶段管道 + PyRIT 原生编排）
    ├── executor/                 # 执行器层（Garak/Promptfoo/RAG/Agent）
    ├── converters/               # 载荷变形器
    ├── targets/                  # 目标适配器
    ├── scoring/                  # 评分层（含 OWASP 映射）
    ├── reporting/                # 报告生成
    ├── storage/                  # Neo4j 图数据库
    ├── datasets/                 # 载荷数据（YAML）
    ├── configs/                  # 环境配置
    ├── scenarios/                # 场景模板
    ├── schemas/                  # 数据模型
    ├── scripts/                  # 工具脚本
    ├── utils/                    # 通用工具
    ├── guides/                   # 用户指南
    │   └── user/                 #   使用文档
    └── outputs/                  # 攻击结果
```

---

## 开发流程

1. **阅读规范** → [`docs/contributing/README.md`](docs/contributing/README.md)
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
