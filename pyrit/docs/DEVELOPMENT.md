# AI-300 Framework - 开发规范

> **最后更新**: 2026-07-19
> **版本**: v3.5
> **关联模块**: pyrit_ai300/
> **状态**: 已完成

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
| 未调用的函数/方法 | 定义后任何地方调用 | 删除 |
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
| **ensemble** (REV-4) | **`EnsembleScorer`** | 集成 | 多评分器并行 + 投票策略（多数/加权/一致），由 `ScorerBuilder` 自动启用 |
| **semantic** (REV-5) | **`SemanticScorer`** | 语义 | LLM 语义判定 + 关键词降级模式，由 `ScorerBuilder` 自动启用 |

> **REV-4/REV-5 说明**（v3.5）：`ScorerBuilder.build()` 默认为关键类别（LLM01/02/06/07/08, ASI01/02/05/06）自动启用集成评分和语义评分，无需手动配置。配置详见 `ai300 list scorers` 命令输出。

### 3.3 评分器自动选择 + 外部 LLM 配置

**评分器类型选择**由 SmartMatcher 根据 ASI 类别自动完成，用户无需手动指定：

| ASI 类别 | 自动选择的评分器类型 | 原因 |
|---------|-------------------|------|
| ASI01, ASI06, ASI09, LLM01, LLM02, LLM09 | refusal | 目标劫持/记忆污染/信任利用 → 检测是否拒绝 |
| ASI02, ASI04, ASI07, LLM03, LLM06, LLM10 | true_false | 工具滥用/通信安全 → 判断是否执行 |
| ASI03, ASI08, ASI10, LLM05, LLM08 | category | 身份滥用/级联失败 → 多类别判断 |
| ASI05, LLM04, LLM07 | substring | 代码执行/RAG → 检测 system prompt 泄露 |

**外部 LLM 评分器配置**（`config/scores/` 目录，2 个 YAML 文件）：
- `scorer_backends.yaml` — 评分器后端（local_provider + openai_compatible）
- `generator_backends.yaml` — 生成器后端（generator_local + generator_openai）
- ASI 类别映射已移至 `pyrit_ai300/orchestrators/asi_mapping.yaml`（包内部配置）

```yaml
scorer_llm_backends:
  local_provider:
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
ai300 owasp llm01 --target-file config/targets/llm_api_target.yaml \
  --scorer-url https://open.bigmodel.cn/api/paas/v4 \
  --scorer-key $SCORES_API_KEY \
  --scorer-model glm-4-flash
```

**优先级**：CLI 参数 > 环境变量 > 配置文件 > 默认 local_provider

**环境变量支持**：`api_key` 支持 `${ENV_VAR}` 格式，运行时自动替换：
```yaml
api_key: "${OPENAI_API_KEY}"
```

**回退机制**：如果指定的后端不存在，自动回退到 objective_target。

#### 3.3.1 评分器多级回退链（v3.8 新增）

为确保评分器失效不中断流水线，`ScorerBuilder` 实现了 5 级回退链：

```
LLM 评分器构建回退链：

  ┌─ 1. openai_compatible ─────────────────────────────────┐
  │    云端高精度 API（智谱/DeepSeek/Moonshot 等）          │
  │    需要 SCORES_API_KEY，未配置则跳过                    │
  └──────────────────────────────────────────────────────┘
           │ 失败（无 API Key / 网络不可达）
           ▼
  ┌─ 2. local_provider ───────────────────────────────────┐
  │    本地模型服务（Ollama / LM Studio / vLLM）          │
  │    无需认证，开箱即用                                   │
  └──────────────────────────────────────────────────────┘
           │ 失败（本地服务未启动）
           ▼
  ┌─ 3. objective_target ─────────────────────────────────┐
  │    复用攻击目标作为评分器后端                           │
  │    精度较低但不中断流水线                               │
  └──────────────────────────────────────────────────────┘
           │ 失败（无目标）
           ▼
  ┌─ 4. static_prompt_injection ──────────────────────────┐
  │    规则评分器兑底（无需 LLM）                           │
  │    内置 6 类注入检测模式（指令覆盖/系统提示提取/越狱等）│
  │    适用于 refusal/true_false/category 等 LLM 评分器降级 │
  └──────────────────────────────────────────────────────┘
           │ 不适用
           ▼
  ┌─ 5. 无评分器 ─────────────────────────────────────────┐
  │    PyRIT 默认行为（攻击照常执行，仅缺少评分）           │
  │    AttackScoringConfig() 不传 objective_scorer          │
  └──────────────────────────────────────────────────────┘
```

**设计原则**：
- 评分器构建 **永不抛异常**，所有失败路径均被捕获
- 优先使用高精度后端，逐步降级到高可用方案
- 规则评分器兑底确保至少有基本的检测能力
- 即使无评分器，攻击流水线也能正常执行

**降级映射**（LLM 评分器 → 规则评分器）：

| LLM 评分器 | 规则评分器兑底 | 原因 |
|-----------|--------------|------|
| refusal | static_prompt_injection | 检测注入模式（指令覆盖/越狱等）|
| true_false | static_prompt_injection | 检测注入模式 |
| category | static_prompt_injection | 检测注入模式 |

> 选择 `StaticPromptInjectionScorer` 作为通用兑底的原因：无需必需参数、内置 6 类注入检测模式、适用于大多数 LLM 攻击场景。

### 3.4 YAML 多文档加载

目标配置文件（如 `llm_api_target.yaml`）使用 `---` 分隔多个文档，必须用：

```python
import yaml

with open(path, "r", encoding="utf-8") as f:
    docs = list(yaml.safe_load_all(f))
    config = docs[0] if docs else {}
```

## 4. 目录结构规范（v3.1）

```
pyrit/                          # 项目根目录
├── config/                     # 配置层（唯一配置源）
│   ├── targets/               #   目标端点配置 YAML
│   ├── recon/                 #   侦察配置（recon.yaml + 19项优化开关）
│   ├── scores/                #   评分器 LLM 后端 + ASI 映射
│   ├── placeholders/          #   占位符配置（llm01-10/ + expericing/）
│   ├── headers/               #   认证头文件
│   └── output/                #   输出报告配置
├── data/                       # 数据层
│   ├── owasp/                 #   载荷唯一真相源（82 YAML，632 payloads）
│   │   ├── _registry.core.yaml #   注册表 v2.0.0
│   │   ├── llm/               #     LLM01-LLM10
│   │   │   ├── llm01/          #     32 文件（Skeleton Key/BoN/Bad Likert/...）
│   │   │   │   ├── jailbreak/  #     75 活跃 + 90 归档
│   │   │   │   │   ├── _metadata_defaults.yaml
│   │   │   │   │   └── archive/ #   6 子目录归档
│   │   │   │   └── _goals.yaml #     6层分类结构
│   │   │   └── llm02-10/       #     各 OWASP 类别
│   │   └── agentic/           #     ASI01-ASI10
├── pyrit_ai300/                # 代码层（纯执行引擎）
│   ├── reconnaissance/        #   侦察引擎（完全独立）
│   │   ├── recon_engine.py    #   统一调度入口 (OPT-E1-E3)
│   │   ├── target_profile.py  #   TargetProfile 数据模型
│   │   ├── profile_merger.py  #   多工具结果合并 (OPT-M1-M2)
│   │   ├── owasp_taxonomy.py  #   OWASP 分类法
│   │   ├── adapters/          #   薄壳适配器
│   │   │   ├── protocol_fingerprint_adapter.py  # AIMAP (OPT-A1-A6)
│   │   │   ├── garak_adapter.py                  # Garak (OPT-G1-G6)
│   │   │   └── deepteam_adapter.py               # DeepTeam (OPT-D1-D5)
│   │   └── utils/             #   工具函数
│   ├── attack/                #   攻击引擎扩展
│   │   └── profile_loader.py  #   TargetProfile → SmartMatcher
│   ├── orchestrators/         #   编排器
│   │   ├── attack_orchestrator.py  # 攻击编排 + 执行
│   │   ├── smart_matcher.py        # 两层策略选择 + 转换器选择
│   │   ├── scorer_builder.py       # ASI 感知评分器构建 (v3.1)
│   │   ├── converter_builder.py    # 转换器构建 (v3.1)
│   │   ├── target_builder.py       # 目标构建 (v3.1)
│   │   ├── pyrit_initializer.py    # PyRIT 初始化 (v3.1)
│   │   ├── plugin_loader.py        # 插件加载 (v3.1)
│   │   ├── attack_registry.py
│   │   ├── component_registry.py
│   │   ├── encoding_selector.py    # 三阶段编码选择器
│   │   ├── rate_controller.py      # 速率控制器
│   │   ├── auth/              #   认证配置解析
│   │   └── interactions/      #   交互函数
│   ├── payloads/              #   载荷管理
│   │   ├── payload_manager.py      # 载荷加载/分类/渲染
│   │   ├── payload_classifier.py   # 五维分类器
│   │   ├── payload_dedup.py        # 语义去重 (Jaccard ≥ 0.85)
│   │   ├── payload_mutator.py      # 载荷变异器 (P1-F)
│   │   ├── payload_generator.py    # 载荷生成器
│   │   ├── template_renderer.py    # 模板渲染器
│   │   ├── models.py               # PayloadProfile 数据模型
│   │   ├── normalizer.py           # 载荷标准化
│   │   └── patterns.py             # 攻击分类模式
│   ├── pipeline/              #   流水线追踪
│   │   ├── tracker.py              # 全链路追踪 (20 stage)
│   │   └── feedback_analyzer.py    # 反馈分析 + 变异生成 (P1-F)
│   ├── reporting/             #   报告生成
│   │   ├── report_generator.py     # OffSec 9段标准报告
│   │   └── execution_report.py     # 执行报告保存
│   ├── tests/                 #   单元测试（220+ tests）
│   ├── tests/                 #   单元测试（220+ tests）
│   ├── utils/                 #   工具函数
│   ├── __init__.py            #   AI300Engine 入口
│   └── cli.py                 #   命令行接口
├── docs/                       # 文档
│   ├── ARCHITECTURE.md        #   架构设计文档
│   ├── DEVELOPMENT.md         #   开发规范文档（本文档）
│   └── OFFLINE_INSTALL.md     #   离线安装指南
├── examples/                   # 使用示例
├── .garak/                     #   Garak 独立 venv（隔离 datasets 冲突）
├── .ai-assistant/              #   AI 助手知识库（VSCode 等 IDE 用）
│   ├── memory/                 #     记忆库（每日日志 + MEMORY.md）
│   ├── plans/                  #     实施计划文档
│   ├── rules/                  #     规则库（DATA-001/ARCH-001/TEST-001 等）
│   └── scripts/                #     工具脚本
├── results/                    # 输出结果
├── Makefile                    # 自动化命令
├── pyproject.toml              # 项目配置
└── README.md                   # 使用文档
```

## 5. OWASP 唯一真相源（强制）

**规则编号**: DATA-001

所有攻击载荷（payload）**必须且只能**存储在 `data/owasp/` 目录下，任何其他位置不得存储载荷内容。

```
data/owasp/          ← 唯一真相源
  ├── llm/           ← LLM01-LLM10（含多级子目录）
  │   └── llm08/
  │       ├── _goals.yaml  ← 攻击目标占位符
  │       └── *.yaml       ← 载荷文件
  ├── agentic/       ← ASI01-ASI10
  └── recon_templates/ ← 侦察探测模板
```

**核心约束**：
1. **禁止重复存储** — 不得在其他目录重复存储载荷
2. **OWASP ID 隐含攻击面** — 不存储 `surfaces` 和 `ai300_chapters` 字段
3. **多级子目录扫描** — `load_data_dir()` 使用 `rglob` 递归
4. **顶层文件跳过规则** — 有子目录时顶层 YAML 不加载
5. **占位符迁移** — 攻击目标统一存放在 `_goals.yaml` 而非 `config/placeholders/`

**YAML 三要素规范（强制）**：

所有载荷 YAML 文件必须包含 `id`、`name`、`description` 三个字段：

| 字段 | 含义 | 示例 |
|------|------|------|
| `id` | OWASP 分类标识 | `LLM01`, `ASI01` |
| `name` | 人类可读类别名 | `Prompt Injection` |
| `description` | 技术组攻击原理描述 | `直接提示注入 — 指令覆盖、角色扮演` |

**新增载荷流程**：
1. 确定 OWASP 类别 → 在对应目录创建 YAML
2. 填写 `id`、`name`、`description` 三要素
3. **不需要**修改代码逻辑

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
4. 新增攻击技术：只改 `data/owasp/` 下的 YAML，不改代码
5. 新增目标类型：只改 `config/targets/*.yaml`，不改代码
6. 侦察层不 import 攻击层，两者通过 TargetProfile JSON 通信
7. config/ 为唯一配置源：策略配置（转换器/评分器/ASI映射）内置在代码常量中

**端到端数据驱动流程**：
```
用户编辑 config/ + data/
  → ai300 recon -t <target>
    → ReconEngine 调度 Garak + DeepTeam
    → ProfileMerger 合并结果
    → TargetProfile JSON
  → ai300 owasp <scope> --target-file <yaml>
    → ProfileLoader 加载画像
    → 模板渲染（_goals.yaml + 14种编码变体）
    → SmartMatcher 选择策略
    → RateController 控制并发
    → PyRIT 原生攻击执行
    → 自动评分
    → 自动生成报告 → results/
```

### 6.1 PayloadGenerator 与 data/ 目录的关系

**核心问题**：`PayloadGenerator`（LLM 自动生成载荷）与 `data/owasp/`（手工策展载荷库）的关系是什么？如何协调？

#### 角色定位

| 组件 | 位置 | 角色 | 数据来源 |
|------|------|------|---------|
| **PayloadManager** | `pyrit_ai300/payloads/` | 载荷库管理器 | 从 `data/owasp/` 加载 YAML |
| **PayloadGenerator** | `pyrit_ai300/payloads/` | 载荷草稿生成器 | LLM 从 CVE/论文/描述生成 |
| **data/owasp/** | `data/` | 载荷唯一真相源 | 手工策展 + 社区贡献 |
| **PayloadMutator** | `pyrit_ai300/payloads/` | 载荷变异器 | 基于反馈对已有载荷变异 |

#### 数据流向

```
                   ┌─────────────────────────────────────────┐
                   │           载荷生命周期                    │
                   └─────────────────────────────────────────┘

  [手工策展]                    [LLM 生成]                    [变异增强]
      │                             │                             │
      ▼                             ▼                             ▼
 data/owasp/*.yaml          PayloadGenerator              PayloadMutator
 (唯一真相源)               .generate_from_cve()          .mutate_from_feedback()
      │                             │                             │
      │                    ┌────────┴────────┐                    │
      │                    │                 │                    │
      │                    ▼                 ▼                    │
      │             保存到 data/      直接用于攻击              保存到 data/
      │             owasp/ 对应目录    (临时，不入库)           owasp/ 对应目录
      │                    │                                   │
      ▼                    ▼                                   ▼
 PayloadManager.load_data_dir()  ← 统一加载入口
      │
      ▼
 resolve_refs() → 攻击执行
```

#### 协调方案

**1. data/ 是唯一真相源（DATA-001 规则不变）**

- `data/owasp/` 下的 YAML 文件是所有攻击载荷的唯一来源
- `PayloadManager` 从该目录加载所有载荷
- `PayloadGenerator` 生成的载荷**不是**直接用于攻击，而是保存为 YAML 文件后由 `PayloadManager` 统一加载

**2. Generator 是"载荷工厂"，不是"载荷仓库"**

- `PayloadGenerator` 的职责：从 CVE/论文/描述自动生成载荷草稿
- 生成结果通过 `save_to_file()` 保存到 `data/owasp/` 对应目录
- 保存后即可被 `PayloadManager` 自动发现和加载（无需修改代码）
- Generator 复用 `config/scores/generator_backends.yaml` 的 LLM 后端配置

**3. 使用场景**

| 场景 | 使用方式 | 说明 |
|------|---------|------|
| **标准测试** | 直接使用 `data/owasp/` 中的载荷 | PayloadManager 加载已有 YAML |
| **新漏洞响应** | `ai300 payload generate --cve CVE-2026-XXXX` | Generator 生成草稿 → 保存到 data/ → 自动可用 |
| **论文复现** | `ai300 payload generate --paper "..."` | 从论文摘要生成载荷 |
| **变异增强** | FeedbackAnalyzer → PayloadMutator | 基于攻击反馈变异已有载荷 |

**4. Generator 与 data/ 的接口**

```python
# Generator 生成载荷 → 保存到 data/ 目录 → PayloadManager 自动加载
from pyrit_ai300.payloads import PayloadGenerator

# 1. 从 CVE 生成载荷草稿
generator = PayloadGenerator.from_backend_config(backends, "generator_local")
result = generator.generate_from_cve("CVE-2026-25253", description="...", owasp_id="LLM01")

# 2. 保存到 data/owasp/ 对应目录（成为唯一真相源的一部分）
generator.save_to_file(result, "data/owasp/llm/llm01/")

# 3. PayloadManager 自动发现并加载（下次运行时自动可用）
#    无需修改任何代码
```

**5. 配置共享**

- `PayloadGenerator` 复用 `scorer_llm_backends` 配置体系（`config/scores/*.yaml`）
- 独立温度参数：Generator 使用 0.7（创造性），Scorer 使用 0.0（确定性）
- 环境变量统一：`${SCORES_BASE_URL}` / `${SCORES_API_KEY}` / `${SCORES_MODEL_NAME}`

**6. CVE 获取机制**

> **重要**：`PayloadGenerator` **不会自动获取最新 CVE**。它是按需触发的被动工具。

| 问题 | 答案 |
|------|------|
| 是否自动定时获取 CVE？ | ❌ 否。无定时任务、无 CVE API 集成、无自动轮询 |
| 如何触发生成？ | 用户手动调用 `generate_from_cve(cve_id, description)` |
| CVE 描述从哪里来？ | 用户手动提供（可从 NVD/CNNVD/安全公告复制） |
| 生成频率？ | 完全由用户控制，按需触发 |

**典型工作流（新 CVE 响应）**：

```
1. 安全研究员发现新 CVE（如 NVD 公告 CVE-2026-XXXXX）
2. 复制 CVE 描述 → 调用 generate_from_cve()
3. Generator 用 LLM 生成 9 个载荷草稿（basic/advanced/stealth 三层）
4. save_to_file() 保存到 data/owasp/llm/{LLM0X}/ 目录
5. 下次运行 ai300 owasp 时，PayloadManager 自动加载新载荷
```

**7. 命名规范（载荷文件）**

`save_to_file()` 自动生成的文件名遵循以下规范，与 `data/owasp/` 现有 CVE 载荷对齐：

| 来源类型 | 命名格式 | 示例 |
|---------|---------|------|
| CVE | `cve_{year}_{number}_{short_name}.yaml` | `cve_2026_25253_openclaw_token_theft.yaml` |
| 论文 | `paper_{technique_group}.yaml` | `paper_many_shot_jailbreak.yaml` |
| 描述 | `gen_{technique_group}.yaml` | `gen_hidden_injection.yaml` |

其中 `{short_name}` 取自 LLM 生成的 `technique_group` 字段（snake_case）。

**8. 重复处理策略**

| 层级 | 机制 | 说明 |
|------|------|------|
| **保存时** | `save_to_file(overwrite=False)` | 文件名已存在时跳过（默认），`overwrite=True` 可覆盖 |
| **加载时** | `PayloadManager.resolve_refs()` | 按 `payload` 字段内容去重，相同载荷文本只保留首次出现 |
| **文件级** | OWASP ID + 文件名唯一 | 同一 OWASP 目录下文件名唯一，不同目录可同名 |

```python
# 保存时去重示例
result = generator.generate_from_cve("CVE-2026-25253", description="...")
path = generator.save_to_file(result, "data/owasp/llm/llm06/")
# → 如果 cve_2026_25253_*.yaml 已存在，跳过并返回原路径
# → 如需覆盖：save_to_file(result, output_dir, overwrite=True)
```

## 7. 命名规范

- **目录名**：小写 + 下划线（`orchestrators/` ✓）
- **文件名**：小写 + 下划线（`attack_orchestrator.py`）
- **类名**：大驼峰（`AttackOrchestrator`）
- **函数/变量**：小写 + 下划线（`build_target`）
- **配置键名**：小写 + 下划线（`pyrit_converters`）

## 8. Playwright 浏览器环境（SPA 攻击必需）

### 8.1 安装步骤

SPA 聊天应用攻击（`spa_target.yaml`）和 SPA 侦察（`--spa-config`）依赖 Playwright 浏览器自动化，需额外安装：

```bash
# 1. 安装 Playwright Python 包
uv pip install playwright
# 或使用 pip: pip install playwright

# 2. 安装 Chromium 浏览器引擎（约 150MB，仅需一次）
playwright install chromium
```

### 8.2 适用场景

| 场景 | 命令 | 是否需要 Playwright |
|------|------|-------------------|
| SPA 聊天攻击 | `ai300 owasp llm01 --target-file config/targets/spa_target.yaml` | ✅ 必需 |
| SPA 侦察 | `ai300 recon --spa-config config/targets/spa_target.yaml` | ✅ 必需 |
| LLM API 攻击 | `ai300 owasp llm01 --target-file config/targets/llm_api_target.yaml` | ❌ 不需要 |
| HTTP API 攻击 | `ai300 owasp llm01 --target-file config/targets/http_target.yaml` | ❌ 不需要 |
| 全链路编排（SPA） | `ai300 pipeline --spa-config config/targets/spa_target.yaml` | ✅ 必需 |
| 全链路编排（API） | `ai300 pipeline --target-url http://api.example.com` | ❌ 不需要 |

### 8.3 底层依赖说明

Playwright 是 PyRIT `PlaywrightTarget` 的底层依赖，用于：
- **浏览器自动化**：启动 Chromium、导航到目标 URL
- **认证注入**：通过 `playwright_injector.py` 注入 Cookie + Authorization
- **选择器交互**：通过 `web_chat.py` 工厂函数定位输入框/发送按钮/响应容器
- **流量捕获**：通过 `traffic_capture.py` 拦截 LLM API 请求/响应

### 8.4 Makefile 快捷命令

```bash
# 一键安装 Playwright + Chromium
make setup-playwright
```

## 9. 配置驱动原则

见第 4 节「数据与代码分离」。核心要点：
- 新增攻击技术：只改 `data/owasp/` 下的 YAML
- 新增目标类型：只改 `config/targets/*.yaml`
- 新增侦察工具配置：只改 `config/recon/recon.yaml`
- 新增外部 LLM 评分器后端：只改 `config/scores/*.yaml`（或使用 CLI `--scorer-url`/`--scorer-key`/`--scorer-model`）
- 新增转换器/评分器映射：只改 `pyrit_ai300/orchestrators/component_registry.py` 的 `CONVERTER_MAP` / `SCORER_MAP`
- **不修改代码逻辑**即可扩展攻击能力

## 10. 日志规范

```python
import logging

logger = logging.getLogger(__name__)

# 使用 % 风格（推荐）
logger.info("Executing attack: %s with %d payloads", attack_name, len(payloads))
logger.error("Attack failed: %s", str(e))
```

## 11. 调度器 + 格式转换器原则（强制）

**规则编号**: ARCH-001（详见 `.ai-assistant/rules/recon-architecture.md`）

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

**Garak 独立 venv**：
```bash
# garak 与 pyrit 存在 datasets 版本冲突，使用独立 venv
make setup-garak
```

## 12. 测试规范

### 12.1 测试文件规范

- 测试文件命名：`test_<module>.py`
- 测试函数命名：`test_<function>_<scenario>`
- 使用 `pytest` 框架
- 运行：`make test` 或 `python -m pytest pyrit_ai300/tests/ -v`

### 12.2 测试分层策略（强制）

| 阶段 | 跑什么 | 命令 | 耗时 | 定位 |
|------|--------|------|------|------|
| **每次代码修改后** | 单元测试（全量） | `make test` | ~15s | 快速发现回归 |
| **提交前 / 合并前** | Lint + 单元测试 | `make ci` | ~20s | 代码质量 + 正确性 |
| **发布前** | 覆盖率报告 | `make test-cov` | ~20s | 确认覆盖无退化 |

**核心原则：本项目的单元测试就是回归测试。** 220+ 个测试覆盖侦察引擎、适配器、ProfileMerger、攻击编排、载荷管理、速率控制、认证解析、报告生成等核心模块。

### 12.3 回归测试执行时机

- **每次修改代码后**：必须跑 `make test`，确认全部通过
- **每次重构完成后**：跑 `make ci`（lint + test）
- **每次合并前**：全量扫描 + 确认清理
- **每次发布前**：跑 `make test-cov`，确认覆盖率无退化

### 12.3.1 回归测试优先原则（强制）

**规则编号**: TEST-002（详见 `.ai-assistant/rules/regression-testing.md`）

**核心原则：每次代码改动前，先准备回归测试；每次改动后，立即运行验证。**

执行流程：

```bash
# 1. 改动前：运行现有测试确认基线绿
python -m pytest pyrit_ai300/tests/ -v --tb=short

# 2. 编写回归测试（针对即将改动的行为，先写"期望正确"的测试）
#    放入 pyrit_ai300/tests/test_regression.py

# 3. 改动中：每完成一个逻辑点，运行回归测试
python -m pytest pyrit_ai300/tests/test_regression.py -v  # ~5s

# 4. 改动后：全量验证
make test  # ~25s
```

**必须新增回归测试的场景**：
- 修复 bug（测试空值/边界条件不崩溃）
- 配置格式变更（测试变量解析 + 模板一致性）
- 安全相关修复（测试不泄露/不回退到不安全值）
- API 行为变更（测试返回结构完整性）

**禁止**：改完代码不跑测试直接提交。

### 12.4 集成测试

集成测试 = 连接真实目标执行攻击，需要目标在线且耗时长，不适合"每次修改后"跑。

**执行时机**：
- 考试前用真实目标跑一次 `ai300 owasp llm01 --target-file config/targets/xxx.yaml` 验证端到端
- 日常开发只跑单元测试

### 12.5 测试模块覆盖（2026-07-18 更新）

| 测试类 | 覆盖模块 | 测试数 |
|--------|---------|--------|
| TestPayloadClassifier | 载荷分类器基础功能 | 7 |
| TestPayloadAnalyzerV3 | 载荷多维分析器 | 16 |
| TestSmartMatcherV3 | 智能匹配引擎 v3.0 | 18 |
| TestAttackProbeFamilies | 攻击探针族 | 3 |
| TestNormalizePayload | 载荷归一化 | 3 |
| TestPayloadManager | 载荷管理器 | 12 |
| TestPipelineTrackerScorer | 流水线追踪（评分器） | 4 |
| TestPipelineEncodingSelection | 流水线追踪（编码选择） | 7 |
| TestHeaderParser | 认证头解析 | 12 |
| TestWebChatInteraction | Web 聊天交互 | 3 |
| TestPlaywrightTargetConfig | Playwright 目标配置 | 2 |
| TestRateController | 速率控制器 | 14 |
| TestRateControlConfig | 速率控制配置 | 2 |
| TestReportGeneratorDetailedFindings | 报告详细发现 | 4 |
| **总计** | | **107+** |

## 13. 载荷跟踪与添加规则（强制）

**规则编号**: DATA-002（详见 `.ai-assistant/rules/payload-tracking.md`）

**生效日期**: 2026-07-17
**优先级**: 强制（MUST）

### 13.1 跟踪来源优先级

| 优先级 | 来源 | 评估标准 | 典型周期 |
|--------|------|---------|---------|
| **P0** | CVE（NVD） | 有 CVE 编号 + PoC 公开 | 即时响应 |
| **P1** | 学术论文（arXiv） | 对主流模型有效 + 可复现 | 1-3 天 |
| **P2** | 安全博客/PoC | 实战验证有效 | 1 周内 |
| **P3** | 红队工具更新 | Garak/DeepTeam/PyRIT 新版本 | 随版本更新 |
| **P4** | 实战发现 | 自行测试有效 | 按需添加 |

### 13.2 添加流程

```
发现新技术 → 评估有效性 → 编写 YAML 载荷
  → 更新 _registry.core.yaml → 测试验证 → 标记完成
```

### 13.3 跟踪清单状态

| 状态 | 含义 |
|------|------|
| `pending` | 刚发现，待评估 |
| `researching` | 正在研究技术细节 |
| `writing` | 正在编写 YAML 载荷 |
| `testing` | 正在验证载荷效果 |
| `done` | 已添加并验证通过 |
| `rejected` | 评估后不添加（记录原因） |

### 13.4 定期审计

| 频率 | 操作 |
|------|------|
| 每周 | 检查 NVD 新增 AI/LLM 相关 CVE |
| 每月 | 检查 arXiv 新论文 |
| 每季度 | 审计现有载荷，删除已被修复的过时内容 |

## 14. 研究资料搜索规则（强制）

**规则编号**: RES-001（详见 `.ai-assistant/rules/research-sources.md`）

**生效日期**: 2026-07-17
**优先级**: 强制（MUST）

### 14.1 搜索优先级

当需要查找 AI 红队相关技术资料时，**必须**按以下优先级顺序搜索：

| 优先级 | 来源 | 用途 | 搜索方式 |
|--------|------|------|---------|
| **1（最高）** | [arxiv.org](https://arxiv.org) | 学术论文、技术报告 | 关键词搜索 |
| **2** | [github.com](https://github.com) | 开源项目、代码实现 | 仓库搜索 |
| **3（兜底）** | 其他来源 | 前两者未覆盖的资料 | 自行查询 |

### 14.2 搜索流程

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

### 14.3 搜索关键词建议

| 主题 | 推荐关键词 |
|------|-----------|
| AI 红队通用 | `AI Red Teaming`, `Automated Red Teaming` |
| LLM 越狱 | `LLM Jailbreak`, `Jailbreak Attack` |
| 提示注入 | `Prompt Injection`, `Adversarial Prompt` |
| 多模态攻击 | `Multi-modal Attack`, `Vision Language Model Attack` |
| Agent 安全 | `AI Agent Security`, `Agent Red Teaming` |
| 安全评估 | `AI Safety Evaluation`, `LLM Safety Benchmark` |
| 对抗攻击 | `Adversarial Attack`, `Evasion Attack` |

### 14.4 结果记录规范

搜索结果需记录到三库：
- **开发规范**（本文档）：搜索规则和流程
- **规则库** `.ai-assistant/rules/research-sources.md`：规则编号 RES-001
- **记忆库** `.ai-assistant/memory/MEMORY.md`：搜索日期和关键发现

## 15. 目标配置类型（v3.0 更新）

### 15.1 支持的类型

| 类型 | 说明 | 并发 | 速率 |
|------|------|------|------|
| ollama | 本地 Ollama 服务 | 2 | 0 |
| openai | OpenAI 兼容 API | 5 | 10 req/s |
| http | 自定义 HTTP 端点 | 3 | 0 |
| playwright | 浏览器自动化（SPA） | 1 | 0 |

### 15.2 Playwright 目标配置示例

```yaml
# config/targets/spa_target.yaml (极简格式)
target:
  type: playwright
  connection:
    url: "https://chat.example.com"
    browser: chromium
    headless: true
    ignore_https_errors: true
  auth:
    header_file: "config/targets/credentials/student.syxy.ouchn.cn.txt"
  selectors:
    input: "#chat-input"
    send_button: "#send-btn"
    response: ".response"
  rate_control:
    max_concurrent: 1
```

## 16. 报告生成格式（v2.0）

### 16.1 Detailed Findings 格式

```markdown
### Findings Details

#### ⚡ Finding #1: {中文标题}

| Severity | Source | Category | OWASP LLM | MITRE ATLAS | Endpoint |
|----------|--------|----------|-----------|-------------|----------|
| **{SEVERITY}** | {Attack Name} | {Category} | {OWASP ID} | {MITRE} | {URL} |

**Description**: {攻击描述}

**Evidence**:
```{language}
{原始响应，不截断}
```

**Remediation**: {修复建议}
```

### 16.2 标题映射表

| OWASP 技术 ID | 自动生成标题 |
|---------------|-------------|
| embedding_inversion | 嵌入系统信息泄露 |
| prompt_injection | 提示注入 |
| agent_goal_hijack | Agent 目标劫持 |
| system_prompt_leak | 系统提示泄露 |
| tool_hijack | 工具劫持 |
| goal_hijack | 目标劫持 |
| resource_exhaustion | 资源耗尽 |
| unknown | 安全风险 |

### 16.3 严重度计算

| 优先级 | 条件 | 结果 |
|--------|------|------|
| 1 | YAML catalog 中定义 severity | 使用定义值 |
| 2 | 成功率 ≥ 80% | CRITICAL |
| 3 | 成功率 ≥ 50% | HIGH |
| 4 | 成功率 ≥ 20% | MEDIUM |
| 5 | 成功率 < 20% | LOW |

## 17. 深度优化实现规范（v3.7.1 整合）

> 本节整合自 payload_optimization_implementation.md、recon_optimization_implementation.md（已归并）

### 17.1 载荷优化成果汇总

| 指标 | 优化前 | 优化后 | 变化 |
|------|--------|--------|------|
| 载荷文件总数 | 69 | 82 | +13 |
| 载荷总数 | 537 | 632 | +95 |
| Jailbreak 活跃模板 | 165 | 75 | -90 (归档) |
| ASR 基线覆盖率 | 0% | 100% | +100% |
| 预期整体 ASR | 15-30% | 50-75% | +35-45% |

### 17.2 载荷归档规则（强制）

**归档标准**：对 2026 模型 ASR < 10% 的模板必须归档至 `archive/` 目录。

| 归档目录 | 模板数 | 归档原因 |
|---------|--------|---------|
| archive/dan/ | 11 | RLHF 已完全覆盖 |
| archive/dude/ | 3 | DAN 衍生变体 |
| archive/stan/ | 4 | "无限制 AI" 变体 |
| archive/dev_mode/ | 5 | "开发者模式"套路 |
| archive/early_pliny/ | 15 | 针对 2023-2024 早期模型 |
| archive/legacy/ | 52 | 2022-2023 经典角色扮演 |

### 17.3 ASR 基线数据规范

所有载荷必须包含 `asr_baseline` 字段，格式如下：

```yaml
asr_baseline:
  gpt_4o: 0.85        # OpenAI GPT-4o
  claude_3_5_sonnet: 0.70  # Anthropic Claude 3.5
  default: 0.50        # 默认值（无精确匹配时使用）
```

**ASR 排序公式**（红队最佳实践）：
```
effective_asr = base_asr × decay_factor × confidence_factor − uncertainty_penalty
```

- `decay_factor`: 指数衰减（半衰期 6 个月），最低 0.3
- `confidence_factor`: 基于 test_count（10 次后完全置信），最低 0.5
- `uncertainty_penalty`: 无 ASR 数据时扣减 0.15

### 17.4 侦察优化项清单（OPT-A~E 共 19 项）

| 分类 | 优化项 | 优先级 | 核心文件 |
|------|--------|--------|----------|
| AIMAP | OPT-A1 协议探测并行化 | P0 | `protocol_fingerprint_adapter.py` |
| AIMAP | OPT-A2 深度 MCP 探测 | P1 | `protocol_fingerprint_adapter.py` |
| AIMAP | OPT-A3 RAG 端点探测 | P1 | `protocol_fingerprint_adapter.py` |
| AIMAP | OPT-A4 Agent 框架探测 | P1 | `protocol_fingerprint_adapter.py` |
| AIMAP | OPT-A5 认证深度检测 | P1 | `protocol_fingerprint_adapter.py` |
| AIMAP | OPT-A6 模型能力深度探测 | P2 | `protocol_fingerprint_adapter.py` |
| Garak | OPT-G1 Probe 动态选择 | P0 | `garak_adapter.py` |
| Garak | OPT-G2 深度分层 Probe | P1 | `garak_adapter.py` |
| Garak | OPT-G3 结果解析增强 | P1 | `garak_adapter.py` |
| Garak | OPT-G4 Detector 精确配置 | P2 | `garak_adapter.py` |
| Garak | OPT-G5 增量执行缓存 | P1 | `garak_adapter.py` |
| Garak | OPT-G6 通用预热 | P1 | `garak_adapter.py` |
| DeepTeam | OPT-D1 攻击类型全量覆盖 | P0 | `deepteam_adapter.py` |
| DeepTeam | OPT-D2 Agentic 漏洞覆盖 | P1 | `deepteam_adapter.py` |
| DeepTeam | OPT-D3 model_callback 增强 | P2 | `deepteam_adapter.py` |
| DeepTeam | OPT-D4 异步模式启用 | P1 | `deepteam_adapter.py` |
| DeepTeam | OPT-D5 攻击方法配置 | P2 | `deepteam_adapter.py` |
| Merger | OPT-M1 语义去重 | P1 | `profile_merger.py` |
| Merger | OPT-M2 动态攻击建议 | P1 | `profile_merger.py` |
| Engine | OPT-E1 AIMAP 与 DeepTeam 并行 | P0 | `recon_engine.py` |
| Engine | OPT-E2 增量缓存 | P1 | `recon_engine.py` |
| Engine | OPT-E3 深度自适应超时 | P2 | `recon_engine.py` |

### 17.5 新增高 ASR 载荷技术清单

| 技术 | 文件 | OWASP | 预期 ASR |
|------|------|-------|---------|
| Skeleton Key | skeleton_key.yaml | LLM01 | 90% (GPT-4o) |
| Best-of-N (BoN) | bon_jailbreak.yaml | LLM01 | 75% |
| Bad Likert Judge | bad_likert_judge.yaml | LLM01 | 80% |
| Wrapping | wrapping_attack.yaml | LLM01 | 70% |
| PAIR/TAP | pair_tap.yaml | LLM01 | 65% |
| CipherChat | cipherchat.yaml | LLM01 | 60% |
| DeepInception | deepinception.yaml | LLM01 | 55% |
| AutoDAN | autodan.yaml | LLM01 | 50% |
| FigStep-V2 | multimodal_jailbreak_v2.yaml | LLM01 | 75% |
| A2A Injection | a2a_injection.yaml | LLM06 | 85% (MCP) |
| Vector DB Query Injection | vector_db_query_injection.yaml | LLM08 | 85% (ChromaDB) |

### 17.6 ASI 载荷结构升级规范

ASI 载荷必须使用带元数据的对象列表格式：

```yaml
payloads:
  - id: asi01_001
    text: "载荷文本内容"
    metadata:
      technique: "goal_hijack"
      complexity: "low"
      asr_baseline:
        gpt_4o: 0.85
```

