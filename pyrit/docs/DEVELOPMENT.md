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
# 使用 ruff 检测未使用代码（推荐）
ruff check pyrit_ai300/ --select F401,F841

# 全量扫描（含风格）
ruff check pyrit_ai300/ --select F,I,E,W

# 自动修复
ruff check pyrit_ai300/ --fix

# 或使用 vulture 作为补充
pip install vulture
vulture pyrit_ai300/ --min-confidence 80
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

### 3.3 评分器自动选择 + 外部 LLM 配置

**评分器类型选择**由 SmartMatcher 根据 ASI 类别自动完成，用户无需手动指定：

| ASI 类别 | 自动选择的评分器类型 | 原因 |
|---------|-------------------|------|
| ASI01, ASI06, ASI09, LLM01, LLM02, LLM09 | refusal | 目标劫持/记忆污染/信任利用 → 检测是否拒绝 |
| ASI02, ASI04, ASI07, LLM03, LLM06, LLM10 | true_false | 工具滥用/通信安全 → 判断是否执行 |
| ASI03, ASI08, ASI10, LLM05, LLM08 | category | 身份滥用/级联失败 → 多类别判断 |
| ASI05, LLM04, LLM07 | substring | 代码执行/RAG → 检测 system prompt 泄露 |

**外部 LLM 评分器配置**（`config/scores.yaml`）：

```yaml
scorer_llm_backends:
  local_ollama:
    provider: "ollama"
    base_url: "http://localhost:11434/v1"
    api_key: "not-needed"
    model_name: "qwen3:0.6b"
    temperature: 0.0
    max_tokens: 1024
```

**CLI 参数覆盖**（优先级最高）：
```bash
# 使用智谱 GLM 作为评分器
ai300 owasp llm01 --target-file config/targets/ollama_local.yaml \
  --scorer-url https://open.bigmodel.cn/api/paas/v4 \
  --scorer-key $ZHIPUAI_API_KEY \
  --scorer-model glm-4-flash
```

**优先级**：CLI 参数 > 环境变量 > 配置文件 > 默认 local_ollama

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

## 4. 目录结构规范（v3.0）

```
pyrit/                          # 项目根目录
├── config/                     # 配置层（用户只改这里）
│   ├── catalog/               #   catalog.yaml (攻击定义+载荷)
│   ├── targets/               #   目标端点配置 YAML
│   ├── output/                #   输出报告配置
│   ├── recon/                 #   侦察配置（recon.yaml）
│   └── scores.yaml            #   外部 LLM 评分器后端配置
├── data/                       # 数据层
│   ├── owasp/                 #   载荷唯一真相源（251 YAML）
│   │   ├── llm/               #     LLM01-LLM10
│   │   └── agentic/           #     ASI01-ASI10
│   ├── recon_templates/       #   侦察探测模板
│   └── surfaces/              #   攻击面分析文档（可选）
├── pyrit_ai300/                # 代码层（纯框架引擎）
│   ├── reconnaissance/        #   侦察引擎（完全独立）
│   │   ├── recon_engine.py    #   统一调度入口
│   │   ├── target_profile.py  #   TargetProfile 数据模型
│   │   ├── profile_merger.py  #   多工具结果合并
│   │   ├── adapters/          #   薄壳适配器
│   │   │   ├── base_adapter.py
│   │   │   ├── garak_adapter.py
│   │   │   └── deepteam_adapter.py
│   │   └── utils/
│   ├── attack/                #   攻击引擎扩展
│   │   └── profile_loader.py  #   TargetProfile → SmartMatcher
│   ├── orchestrators/         #   编排器
│   │   ├── attack_orchestrator.py
│   │   ├── smart_matcher.py
│   │   ├── attack_registry.py
│   │   └── component_registry.py
│   ├── payloads/              #   载荷管理
│   ├── pipeline/              #   流水线追踪
│   ├── reporting/             #   报告生成
│   ├── tests/                 #   单元测试
│   │   └── test_recon/        #   侦察测试
│   ├── utils/                 #   工具函数
│   ├── __init__.py            #   AI300Engine 入口
│   └── cli.py                 #   命令行接口
├── docs/                       # 文档
│   ├── ARCHITECTURE.md        #   架构设计文档
│   ├── DEVELOPMENT.md         #   开发规范文档（本文档）
│   └── OFFLINE_INSTALL.md     #   离线安装指南
├── examples/                   # 使用示例
├── results/                    # 输出结果
├── Makefile                    # 自动化命令
├── pyproject.toml              # 项目配置
└── README.md                   # 使用文档
```

## 5. OWASP 唯一真相源（强制）

**规则编号**: DATA-001（详见 `.codebuddy/rules/data-architecture.md`）

所有攻击载荷（payload）**必须且只能**存储在 `data/owasp/` 目录下，任何其他位置不得存储载荷内容。

```
data/owasp/          ← 唯一真相源
  ├── llm/           ← LLM01-LLM10（含子目录技术组文件）
  └── agentic/       ← ASI01-ASI10
```

**核心约束**：
1. **禁止重复存储** — 不得在 `by_surface/` 或其他目录重复存储载荷
2. **surfaces/ 目录可选** — `data/surfaces/` 为分析文档，可安全删除

**YAML 三要素规范（强制）**：

所有载荷 YAML 文件必须包含 `id`、`name`、`description` 三个字段，映射 OWASP 官方分类：

| 字段 | 含义 | 示例 |
|------|------|------|
| `id` | OWASP 分类标识 | `LLM01`, `ASI01` |
| `name` | 人类可读类别名 | `Prompt Injection` |
| `description` | 技术组攻击原理描述 | `直接提示注入 — 指令覆盖、角色扮演` |

**新增载荷流程**：
1. 确定 OWASP 类别 → 在对应目录创建 YAML
2. 填写 `id`、`name`、`description` 三要素
3. 在 `config/catalog/catalog.yaml` 中添加引用
4. **不需要**修改代码逻辑

## 6. 数据与代码分离（核心架构原则）

**强制规则**：数据（配置 + 载荷）与代码（框架引擎）必须物理分离。

| 层级 | 位置 | 职责 | 谁改 |
|------|------|------|------|
| **数据层** | `data/` | 载荷库、侦察模板、攻击面文档 | 用户 |
| **配置层** | `config/` | 攻击定义、目标端点、侦察配置、评分器 | 用户 |
| **引擎层** | `pyrit_ai300/` | 侦察调度、攻击编排、载荷管理、报告生成 | 开发者 |
| **入口** | `examples/`, `Makefile`, `cli.py` | 调用引擎、加载数据 | 用户/开发者 |

**设计约束**：
1. `pyrit_ai300/` 下的代码**不得**包含硬编码的攻击载荷或目标配置
2. 所有数据文件使用相对路径（`config/...`），从项目根目录解析
3. 用户只需编辑 `config/` 和 `data/` 即可定制全部攻击流程
4. 新增攻击技术：只改 `config/catalog/catalog.yaml`，不改代码
5. 新增目标类型：只改 `config/targets/*.yaml`，不改代码
6. 侦察层不 import 攻击层，两者通过 TargetProfile JSON 通信

**端到端数据驱动流程**：
```
用户编辑 config/ + data/
  → ai300 recon -t <target>
    → ReconEngine 调度 Garak + DeepTeam
    → ProfileMerger 合并结果
    → TargetProfile JSON
  → ai300 run --profile <json>
    → ProfileLoader 加载画像
    → SmartMatcher 选择策略
    → PyRIT 原生攻击执行
    → 自动评分
    → 自动生成报告 → results/
```

## 7. 命名规范

- **目录名**：小写 + 下划线（`orchestrators/` ✓）
- **文件名**：小写 + 下划线（`attack_orchestrator.py`）
- **类名**：大驼峰（`AttackOrchestrator`）
- **函数/变量**：小写 + 下划线（`build_target`）
- **配置键名**：小写 + 下划线（`pyrit_converters`）

## 8. 配置驱动原则

见第 4 节「数据与代码分离」。核心要点：
- 新增攻击技术：只改 `config/catalog/catalog.yaml`
- 新增目标类型：只改 `config/targets/*.yaml`
- 新增侦察工具配置：只改 `config/recon/recon.yaml`
- 新增外部 LLM 评分器后端：只改 `config/scores.yaml` 的 `scorer_llm_backends`（或使用 CLI `--scorer-url`/`--scorer-key`/`--scorer-model`）
- 新增转换器/评分器映射：只改 `pyrit_ai300/orchestrators/component_registry.py` 的 `CONVERTER_MAP` / `SCORER_MAP`
- **不修改代码逻辑**即可扩展攻击能力

## 9. 日志规范

```python
import logging

logger = logging.getLogger(__name__)

# 使用 % 风格（推荐）
logger.info("Executing attack: %s with %d payloads", attack_name, len(payloads))
logger.error("Attack failed: %s", str(e))
```

## 10. 调度器 + 格式转换器原则（强制）

**规则编号**: ARCH-001（详见 `.codebuddy/rules/recon-architecture.md`）

**生效日期**: 2026-07-17
**优先级**: 强制（MUST）

**核心原则**：本框架只做"调度器 + 格式转换器"，不重复造轮子。

**含义**：
- **调度器**：统一调度开源工具，编排执行顺序，处理并发和错误
- **格式转换器**：将各工具的输出格式转为统一的 TargetProfile JSON
- **不重复造轮子**：所有侦察/攻击能力来自开源工具，本框架不重写任何探测逻辑

**设计约束**：
1. 所有第三方工具的能力通过 Adapter 薄壳调用（每个 Adapter ≤ 150 行）
2. 侦察模块不 import 攻击模块，攻击模块不 import 侦察模块
3. 两者通过 TargetProfile JSON 文件通信（唯一接口契约）
4. 新增工具只需实现 BaseAdapter 接口，不影响现有代码

**推荐工具组合（AI-300 考试）**：

| 工具 | 版本 | 定位 | 集成方式 | 复用程度 |
|------|------|------|---------|---------|
| Garak | ≥0.15.1 | 漏洞扫描 | Python SDK (`garak.cli.main`) | 100% |
| DeepTeam | ≥1.0.7 | OWASP 红队 | Python API (`red_team()`) | 100% |

**安装方式**：
```bash
# Garak + DeepTeam（PyPI）
pip install -e ".[recon]"
```

## 11. 测试规范

### 11.1 测试文件规范

- 测试文件命名：`test_<module>.py`
- 测试函数命名：`test_<function>_<scenario>`
- 使用 `pytest` 框架
- 运行：`make test` 或 `python -m pytest pyrit_ai300/tests/ -v`

### 11.2 测试分层策略（强制）

| 阶段 | 跑什么 | 命令 | 耗时 | 定位 |
|------|--------|------|------|------|
| **每次代码修改后** | 单元测试（全量） | `make test` | ~15s | 快速发现回归 |
| **提交前 / 合并前** | Lint + 单元测试 | `make ci` | ~20s | 代码质量 + 正确性 |
| **发布前** | 覆盖率报告 | `make test-cov` | ~20s | 确认覆盖无退化 |

**核心原则：本项目的单元测试就是回归测试。** 174+ 个测试覆盖侦察引擎、适配器、ProfileMerger、攻击编排、载荷管理等核心模块。

### 11.3 回归测试执行时机

- **每次修改代码后**：必须跑 `make test`，确认全部通过
- **每次重构完成后**：跑 `make ci`（lint + test）
- **每次合并前**：全量扫描 + 确认清理
- **每次发布前**：跑 `make test-cov`，确认覆盖率无退化

### 11.4 集成测试

集成测试 = 连接真实目标执行攻击，需要目标在线且耗时长，不适合"每次修改后"跑。

**执行时机**：
- 考试前用真实目标跑一次 `ai300 run -m single_agent` 验证端到端
- 日常开发只跑单元测试

## 12. 载荷跟踪与添加规则（强制）

**规则编号**: DATA-002（详见 `.codebuddy/rules/payload-tracking.md`）

**生效日期**: 2026-07-17
**优先级**: 强制（MUST）

### 12.1 跟踪来源优先级

| 优先级 | 来源 | 评估标准 | 典型周期 |
|--------|------|---------|---------|
| **P0** | CVE（NVD） | 有 CVE 编号 + PoC 公开 | 即时响应 |
| **P1** | 学术论文（arXiv） | 对主流模型有效 + 可复现 | 1-3 天 |
| **P2** | 安全博客/PoC | 实战验证有效 | 1 周内 |
| **P3** | 红队工具更新 | Garak/DeepTeam/PyRIT 新版本 | 随版本更新 |
| **P4** | 实战发现 | 自行测试有效 | 按需添加 |

### 12.2 添加流程

```
发现新技术 → 创建跟踪清单（data/owasp/_tracking/<ID>.yaml）
  → 评估有效性 → 编写 YAML 载荷 → 更新 _registry.core.yaml
  → 测试验证 → 标记 done
```

### 12.3 跟踪清单状态

| 状态 | 含义 |
|------|------|
| `pending` | 刚发现，待评估 |
| `researching` | 正在研究技术细节 |
| `writing` | 正在编写 YAML 载荷 |
| `testing` | 正在验证载荷效果 |
| `done` | 已添加并验证通过 |
| `rejected` | 评估后不添加（记录原因） |

### 12.4 模板文件

跟踪清单模板位于 `data/owasp/_tracking.template.yaml`，包含：
- 基本信息（ID、状态、优先级）
- 来源信息（CVE/论文/博客链接）
- OWASP 分类映射
- 技术评估（有效性、规避级别、检测风险）
- 载荷信息（技术名、文件路径）
- 验证记录（测试目标、结果）

### 12.5 定期审计

| 频率 | 操作 |
|------|------|
| 每周 | 检查 NVD 新增 AI/LLM 相关 CVE |
| 每月 | 检查 arXiv 新论文 |
| 每季度 | 审计现有载荷，删除已被修复的过时内容 |

## 13. 研究资料搜索规则（强制）

**规则编号**: RES-001（详见 `.codebuddy/rules/research-sources.md`）

**生效日期**: 2026-07-17
**优先级**: 强制（MUST）

### 12.1 搜索优先级

当需要查找 AI 红队相关技术资料时，**必须**按以下优先级顺序搜索：

| 优先级 | 来源 | 用途 | 搜索方式 |
|--------|------|------|---------|
| **1（最高）** | [arxiv.org](https://arxiv.org) | 学术论文、技术报告 | 关键词搜索 |
| **2** | [github.com](https://github.com) | 开源项目、代码实现 | 仓库搜索 |
| **3（兜底）** | 其他来源 | 前两者未覆盖的资料 | 自行查询 |

### 12.2 搜索流程

```
1. 确定搜索关键词（中英文均可）
   ↓
2. 访问 arxiv.org/search/ 搜索论文
   - 提取：标题、作者、摘要、arXiv ID、发布日期
   ↓
3. 访问 github.com/search/ 搜索开源项目
   - 提取：仓库名、描述、Star 数、语言、最后更新
   ↓
4. 整理结果，去重筛选
   ↓
5. 如前两者结果不足，自行扩展搜索（Google、技术博客等）
```

### 12.3 搜索关键词建议

| 主题 | 推荐关键词 |
|------|-----------|
| AI 红队通用 | `AI Red Teaming`, `Automated Red Teaming` |
| LLM 越狱 | `LLM Jailbreak`, `Jailbreak Attack` |
| 提示注入 | `Prompt Injection`, `Adversarial Prompt` |
| 多模态攻击 | `Multi-modal Attack`, `Vision Language Model Attack` |
| Agent 安全 | `AI Agent Security`, `Agent Red Teaming` |
| 安全评估 | `AI Safety Evaluation`, `LLM Safety Benchmark` |
| 对抗攻击 | `Adversarial Attack`, `Evasion Attack` |

### 12.4 结果记录规范

搜索结果需记录到三库：
- **开发规范**（本文档）：搜索规则和流程
- **规则库** `.codebuddy/rules/research-sources.md`：规则编号 RES-001
- **记忆库** `.codebuddy/memory/MEMORY.md`：搜索日期和关键发现
