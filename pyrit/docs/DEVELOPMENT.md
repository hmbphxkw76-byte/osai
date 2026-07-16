# AI-300 Framework - 开发规范

## 1. 编码规范

### 1.1 强制 UTF-8（Windows 必须）

所有 Python 脚本**必须**在文件入口处添加以下代码，放在 `import` 语句之前或之后：

```python
import sys
import os

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    os.environ["PYTHONIOENCODING"] = "utf-8"
```

**原因**：Windows 默认使用 GBK 编码，Rich Console、logging 等输出中文时会报 `UnicodeEncodeError`。

**适用范围**：
- 所有 `examples/` 下的示例脚本
- 所有 `tests/` 下的测试脚本
- `cli.py` 主入口
- 任何直接执行的 Python 文件

### 1.2 文件编码声明

所有 Python 文件使用 UTF-8 编码保存，文件头可选添加：

```python
# -*- coding: utf-8 -*-
```

## 2. 死代码清理（强制）

**每次代码调整或优化后，必须清除所有死代码和未调用代码，保持代码简洁。**

### 2.1 清理范围

每次重构/优化后，检查并清除：

| 类型 | 示例 | 处理方式 |
|------|------|---------|
| 未使用的 import | `import xxx` 后全文无引用 | 删除 |
| 未调用的函数/方法 | 定义后无任何地方调用 | 删除 |
| 未使用的类 | 定义后无实例化/继承 | 删除 |
| 注释掉的代码 | `# 旧代码...` | 删除（git 历史可恢复） |
| 废弃的模块文件 | 整个文件不再被引用 | 删除文件 |
| 废弃的目录 | 整个目录无有效内容 | 删除目录 |
| 重复实现 | 同一逻辑多处实现 | 合并到一处，删除其余 |
| 未使用的变量/常量 | 定义后未读取 | 删除 |

### 2.2 检查方法

```bash
# 使用 vulture 检测未使用代码
pip install vulture
vulture pyrit_ai300/ --min-confidence 80

# 或使用 IDE 内置检查（PyCharm/VSCode 灰色高亮 = 未使用）
```

### 2.3 执行时机

- **每次重构完成后**：立即清理本次引入的死代码
- **每次合并前**：全量扫描一次
- **每次发布前**：全量扫描 + 确认清理

### 2.4 记录

已删除的死代码记录在 `MEMORY.md` 的「已删除的死代码」章节，便于追溯。

## 3. PyRIT 组件使用规范

### 3.1 转换器（Converters）

| 配置名称 | PyRIT 类名 | 注意事项 |
|---------|-----------|---------|
| base64 | `Base64Converter` | 无参数 |
| rot13 | `ROT13Converter` | 注意全大写 ROT |
| unicode_confusable | `UnicodeConfusableConverter` | 无参数 |
| leetspeak | `LeetspeakConverter` | 无参数 |
| search_replace | `SearchReplaceConverter` | 参数为 `pattern=`, `replace=` |
| persuasion | `PersuasionConverter` | 无参数 |
| malicious_question_generator | `MaliciousQuestionGeneratorConverter` | 无参数 |
| add_text_image | `AddTextImageConverter` | 无参数 |
| pdf | `PDFConverter` | 无参数 |
| word_doc | `WordDocConverter` | 无参数 |

### 3.2 评分器（Scorers）

| 配置名称 | PyRIT 类名 | 类型 | 注意事项 |
|---------|-----------|------|---------|
| refusal | `SelfAskRefusalScorer` | LLM | 需要 LLM 目标（外部后端或 objective_target） |
| true_false | `SelfAskTrueFalseScorer` | LLM | 需要 LLM 目标 |
| substring | `SubStringScorer` | 规则 | 纯文本匹配，无需 LLM |
| category | `SelfAskCategoryScorer` | LLM | 需要 LLM 目标 |

### 3.3 外部 LLM 评分器配置

评分器支持绑定外部 LLM 后端（OpenAI 兼容 API），配置集中在 `config/scorers.yaml`：

```yaml
# LLM 评分器后端定义
scorer_llm_backends:
  local_ollama:
    provider: "ollama"
    base_url: "http://localhost:11434/v1"
    api_key: "not-needed"
    model_name: "qwen3:0.6b"
    temperature: 0.0  # 评分用低温，更确定

# 评分器定义（引用后端）
scorer_definitions:
  refusal_local:
    type: "refusal"
    backend: "local_ollama"
    description: "拒绝检测 — 本地 Ollama"
    params: {}

# 按场景推荐最佳评分器
best_scorer_by_scenario:
  ASI01_agent_goal_hijack: "refusal_local"
```

**三种配置方式**（在 attack 配置的 `scorers` 字段）：

1. **简单名称**（使用 objective_target 作为 LLM）：
   ```yaml
   scorers:
     - {"name": "refusal"}
   ```

2. **外部 LLM 后端**（指定后端名称）：
   ```yaml
   scorers:
     - {"name": "refusal", "backend": "openai_gpt4"}
   ```

3. **评分器定义引用**（从 scorers.yaml 读取完整配置）：
   ```yaml
   scorers:
     - {"definition": "refusal_gpt4"}
   ```

**环境变量支持**：`api_key` 支持 `${ENV_VAR}` 格式，运行时自动替换：
```yaml
api_key: "${OPENAI_API_KEY}"
```

**回退机制**：如果指定的后端不存在，自动回退到 objective_target。

### 3.4 YAML 多文档加载

目标配置文件（如 `ollama_local.yaml`）使用 `---` 分隔多个文档，必须用：

```python
import yaml

with open(path, "r", encoding="utf-8") as f:
    docs = list(yaml.safe_load_all(f))
    config = docs[0] if docs else {}
```

## 4. 目录结构规范

```
pyrit/                          # 项目根目录
├── config/                     # 数据层（用户只改这里）
│   ├── catalog/               #   catalog.yaml (攻击定义+载荷)
│   ├── targets/               #   目标端点配置 YAML
│   ├── output/                #   输出报告配置
│   └── scorers.yaml           #   外部 LLM 评分器后端+定义
├── pyrit_ai300/                # 代码层（纯框架引擎）
│   ├── attacks/               #   攻击工厂 (AttackFactory)
│   ├── converters/            #   转换器模块（预留扩展）
│   ├── display/               #   终端展示 (ExecutionDisplay, Rich 格式化)
│   ├── orchestrators/         #   编排器 (AttackOrchestrator, SmartMatcher)
│   ├── payloads/              #   载荷管理 + 分类 (PayloadManager, PayloadClassifier)
│   ├── reporting/             #   报告生成 (ReportGenerator + ExecutionReportGenerator)
│   ├── scorers/               #   评分器模块（预留扩展）
│   ├── tests/                 #   单元测试
│   ├── utils/                 #   工具函数 (logger)
│   ├── __init__.py            #   AI300Engine 入口
│   └── cli.py                 #   命令行接口
├── docs/                       # 文档
│   ├── ARCHITECTURE.md        #   架构设计文档
│   └── DEVELOPMENT.md         #   开发规范文档（本文档）
├── examples/                   # 使用示例（必须含 UTF-8 头）
├── results/                    # 输出结果
├── Makefile                    # 自动化命令
├── pyproject.toml              # 项目配置
└── README.md                   # 使用文档
```

## 5. 数据与代码分离（核心架构原则）

**强制规则**：数据（配置 + 载荷）与代码（框架引擎）必须物理分离。

| 层级 | 位置 | 职责 | 谁改 |
|------|------|------|------|
| **数据层** | `config/` | 攻击定义、目标端点、载荷文本、报告配置 | 用户 |
| **代码层** | `pyrit_ai300/` | 攻击执行、转换器链、评分、报告生成 | 开发者 |
| **入口** | `examples/`, `Makefile`, `cli.py` | 调用引擎、加载数据 | 用户/开发者 |

**设计约束**：
1. `pyrit_ai300/` 下的代码**不得**包含硬编码的攻击载荷或目标配置
2. 所有数据文件使用相对路径（`config/...`），从项目根目录解析
3. 用户只需编辑 `config/` 即可定制全部攻击流程
4. 新增攻击技术：只改 `config/catalog/catalog.yaml`，不改代码
5. 新增目标类型：只改 `config/targets/*.yaml`，不改代码

**端到端数据驱动流程**：
```
用户编辑 config/
  → python -m pyrit_ai300.cli run
    → 引擎自动加载配置
    → 自动执行攻击
    → 自动评分
    → 自动生成报告 → results/
```

## 6. 命名规范

- **目录名**：小写 + 下划线（`attack_factory/` ✗ → `attacks/` ✓）
- **文件名**：小写 + 下划线（`attack_factory.py`）
- **类名**：大驼峰（`AttackFactory`）
- **函数/变量**：小写 + 下划线（`build_target`）
- **配置键名**：小写 + 下划线（`pyrit_converters`）

## 7. 配置驱动原则

见第 4 节「数据与代码分离」。核心要点：
- 新增攻击技术：只改 `config/catalog/catalog.yaml`
- 新增目标类型：只改 `config/targets/*.yaml`
- 新增外部 LLM 评分器后端：只改 `config/scorers.yaml` 的 `scorer_llm_backends`
- 新增评分器定义：只改 `config/scorers.yaml` 的 `scorer_definitions`
- 新增转换器/评分器映射：只改 `pyrit_ai300/orchestrators/attack_orchestrator.py` 的 `CONVERTER_MAP` / `SCORER_MAP`
- **不修改代码逻辑**即可扩展攻击能力

## 8. 日志规范

```python
import logging

logger = logging.getLogger(__name__)

# 使用 % 风格（推荐）
logger.info("Executing attack: %s with %d payloads", attack_name, len(payloads))
logger.error("Attack failed: %s", str(e))
```

## 9. 测试规范

- 测试文件命名：`test_<module>.py`
- 测试函数命名：`test_<function>_<scenario>`
- 使用 `pytest` 框架
- 运行：`make test` 或 `python -m pytest pyrit_ai300/tests/ -v`
