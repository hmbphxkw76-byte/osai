# 项目架构说明

> 面向使用者的 Promptfoo 红队测试项目架构文档
> 适用: 安全评估 LLM 渗透测试 / LLM 安全评估 实战演练及生产级 LLM 安全评估

---

## 一、架构概览

本项目采用**数据与逻辑分离**的分层架构，专为 AI 红队测试场景优化。

```
┌─────────────────────────────────────────────────────────────┐
│                    用户交互层 (CLI)                          │
│         promptfoo redteam run / eval / report               │
├─────────────────────────────────────────────────────────────┤
│  配置层          │  数据层          │  模板层                │
│  promptfooconfig │  tests/          │  prompts/              │
│  *.yaml + .env   │  datasets/       │  (Nunjucks模板)        │
├─────────────────────────────────────────────────────────────┤
│  逻辑层          │  红队层          │  工具层                │
│  providers/      │  redteam/        │  scripts/              │
│  assertions/     │  (插件/策略/模块) │  (自动化脚本)          │
├─────────────────────────────────────────────────────────────┤
│                    文档层 (docs/)                            │
│      用户文档 + dev-standards/ 开发规范                      │
└─────────────────────────────────────────────────────────────┘
```

---

## 二、核心组件

### 2.1 配置层

| 文件 | 职责 | 运行时间 |
|------|------|---------|
| `promptfooconfig.yaml` | 主配置（标准测试） | 10-20min |
| `promptfooconfig.quick.yaml` | 快速扫描 | 5-10min |
| `promptfooconfig.advanced.yaml` | 深度扫描 | 20-30min |
| `promptfooconfig.redteam.yaml` | 红队全量 | 30-45min |
| `promptfooconfig.regression.yaml` | 回归测试 | 10-15min |
| `.env` | 环境变量（密钥、URL） | - |

**设计原则**: 修改 `.env` 即可切换环境，无需改 YAML。

### 2.2 数据层

| 目录 | 内容 | 格式 |
|------|------|------|
| `tests/` | 测试用例 + 断言 | YAML / CSV |
| `datasets/` | 评估数据集 | JSON / JSONL / CSV |
| `redteam/modules/` | 红队攻击配置（20个模块） | YAML |
| `redteam/attack_prompts.yaml` | 手动攻击提示词 | YAML |
| `redteam/policies/` | 安全策略定义 | YAML |

### 2.3 逻辑层

| 目录 | 职责 | 触发方式 |
|------|------|----------|
| `providers/` | 自定义 API Provider | `file://providers/xxx.py` |
| `assertions/` | 自定义断言脚本 | `type: javascript/python` |
| `redteam/plugins/` | 自定义红队插件 | `redteam.plugins` 配置 |

### 2.4 模板层

| 目录 | 内容 |
|------|------|
| `prompts/` | 通用提示词模板（system, chat, summarize, translate） |
| `prompts/rag/` | RAG 场景专用提示词（retrieval, answer） |

---

## 三、数据流

### 3.1 红队测试数据流

```
1. 读取 .env
   ↓ env.TARGET_URL, env.AUTH_TOKEN
2. 加载 promptfooconfig.yaml
   ↓ targets + redteam 配置
3. 攻击生成模型 (provider)
   ↓ 根据 purpose + plugins 生成攻击 payload
4. 注入 payload 到 targets.body.{{prompt}}
   ↓ HTTP POST 到目标 API
5. 获取目标响应
   ↓
6. 评估器 (grader) 判断
   ↓ 基于 graderGuidance / 断言
7. 生成报告
   ↓ output/results.json + HTML 报告
```

### 3.2 评估测试数据流

```
1. 加载 tests/tests.yaml
   ↓ 测试用例 + vars + assert
2. 渲染 prompts/*.txt 模板
   ↓ Nunjucks 变量替换
3. 调用 targets
   ↓ HTTP POST 或 Provider
4. 获取响应
   ↓
5. 执行断言
   ↓ contains / not-contains / javascript / python
6. 生成报告
```

---

## 四、目录结构速查

```
promptfoo/
├── .env.example                    # 环境变量模板
├── .gitignore
├── promptfooconfig*.yaml           # 5 个场景配置
│
├── prompts/                        # 提示词模板 (6)
├── tests/                          # 测试用例 (6)
├── assertions/                     # 自定义断言 (3)
├── providers/                      # 自定义 Provider (2)
├── datasets/                       # 数据集 (3)
├── redteam/                        # 红队测试 (23)
│   ├── modules/                    # 20 个攻击模块
│   ├── plugins/
│   └── policies/
├── scripts/                        # 辅助脚本 (3)
├── output/                         # 评估输出
│
└── docs/                           # 项目文档
    ├── ARCHITECTURE.md             # 本文件
    ├── FRONTIER_VULNS.md           # 前沿漏洞
    ├── PAYLOAD_LOADING.md          # Payload 加载
    ├── PENETRATING_MODE_GUIDE.md   # 渗透模式指南
    ├── evaluation_strategy.md
    ├── changelog.md
    └── dev-standards/              # 开发规范（IDE 无关）
```

---

## 五、设计决策

### 5.1 为什么数据与逻辑分离？

- **可维护性**: 修改测试数据不影响代码逻辑
- **可复用性**: 同一 Provider 可服务多个测试用例
- **可读性**: 配置即文档，YAML 比 Python 更易读
- **测试友好**: 测试中只改数据，不改逻辑

### 5.2 为什么用多个 promptfooconfig？

- **场景隔离**: 不同测试深度独立配置，互不干扰
- **时间管理**: 根据剩余时间选择合适配置
- **渐进测试**: quick → standard → advanced 层层递进

### 5.3 为什么红队模块按前缀分类？

- **快速定位**: 根据场景关键词快速找到对应模块
- **职责单一**: 每个模块专注一类攻击场景
- **可组合**: 可按需组合多个模块的插件

### 5.4 为什么规范放在 docs/dev-standards/？

- **IDE 无关**: 不依赖 `.trae`、`.vscode` 等特定 IDE 目录
- **自包含**: 规范体系完整，可随项目迁移
- **版本控制**: 规范纳入 Git 管理，可追溯变更

---

## 六、扩展指南

### 6.1 添加新的攻击模块

1. 在 `redteam/modules/` 创建 `xxx_redteam.yaml`
2. 遵循 [dev-standards/yaml-patterns.md](../dev-standards/yaml-patterns.md) 的红队配置结构
3. 更新 `docs/module_mapping.md` 的模块映射表

### 6.2 添加自定义 Provider

1. 在 `providers/` 创建 `xxx_provider.py`
2. 遵循 [dev-standards/config-patterns.md](../dev-standards/config-patterns.md) 的 Provider 模板
3. 在 YAML 中用 `id: 'file://providers/xxx_provider.py'` 引用

### 6.3 添加自定义断言

1. 在 `assertions/` 创建 `xxx_assertion.js` 或 `.py`
2. 在测试用例中用 `type: javascript` 或 `type: python` 引用

---

## 相关文档

- [前沿漏洞类型](FRONTIER_VULNS.md) - AI 安全威胁全景
- [Payload 加载机制](PAYLOAD_LOADING.md) - 攻击 payload 如何注入
- [渗透模式指南](PENETRATING_MODE_GUIDE.md) - 测试模式选择
- [开发规范](../dev-standards/README.md) - 项目开发标准
