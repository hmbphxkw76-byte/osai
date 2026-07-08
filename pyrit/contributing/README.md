# PyRIT 研发规范

> **定位**: PyRIT 框架级开发规范，适用所有 IDE。CodeBuddy 用户通过 skill 自动加载。

---

## 一、核心理念

### 1.1 YAML 是唯一真实来源

所有可变化的数据（Prompt、Payload、场景定义、攻击组合、漏洞索引）存储在 YAML 文件中。
Python 代码是执行引擎，不包含业务数据。修改攻击行为时只改 YAML 不改代码。

```
datasets/payloads/           → Prompt 载荷（core/ 经典 + 模块专项）
datasets/payloads/manifest.yaml → 模块→文件索引，新增模块在此注册
scenarios/templates/         → 攻击场景模板（YAML 声明阶段+策略）
scenarios/frontier/           → 前沿漏洞（index.yaml + vulns/*/manifest.yaml）
```

- 新增载荷模块：在 `datasets/payloads/` 新建 `xxx_payloads.yaml`，在 `manifest.yaml` 注册。
- 新增漏洞：在 `scenarios/frontier/vulns/FRONTIER-YYYY-NNN_name/` 下创建 `manifest.yaml` + `payloads.yaml`。
- 新增场景模板：在 `scenarios/templates/` 新建 `xxx.yaml`。

### 1.2 配置分离，关注点独立

```
.env                        → 选择器 + 通用参数（TARGET_PRESET= / PLATFORM_SELECTOR=）
configs/platforms.env        → 平台模型定义 [OPENAI]/[OLLAMA]/[CUSTOM]...
configs/targets.env          → 目标场景预设 [TARGET_DEMO_CHAT]/[TARGET_DUAL_AUTH]...
```

- `.env` 只管"选什么"，不管"怎么定义"。
- `configs/` 只管"定义"，不管"选择"。
- 新增配置类型时优先考虑独立文件，避免 `.env` 膨胀。

### 1.3 模块化部署，职责单一

每个顶层包的职责边界清晰，不跨层引用：

| 包 | 职责 | 依赖方向 |
|---|---|---|
| `entrypoint/` | CLI 入口（解析 → 回显 → 引导 → 路由） | → targets, datasets, converters |
| `orchestrators/` | 攻击工作流编排（Facade） | → executor, converters, reporting |
| `executor/` | 攻击执行引擎 | → targets, datasets |
| `converters/` | 攻击策略转换器 | → 外部 PyRIT 框架 |
| `targets/` | 目标封装 + 工厂 + 配置加载 | → 外部 API |
| `datasets/` | 数据加载（只读 YAML） | 无内部依赖 |
| `reporting/` | 结果分析 + 报告生成 | → executor |
| `scoring/` | 评分重导出层 | → executor |
| `scripts/` | 独立工具脚本 | 可跨层 |

- 只能从上层引用下层，禁止反向依赖。
- `__init__.py` 定义包的公开 API（`__all__`），包内部细节不对外暴露。

### 1.4 最小化改动原则

- 新增功能优先在 YAML 层实现，不修改 Python 代码。
- 修改现有行为时，确保向后兼容（legacy 路径保留）。
- 重构时优先提取而非重写：旧代码注释标记而非删除。
- CLI 参数新增时提供合理默认值，不破坏已有脚本。

---

## 二、代码组织规范

### 2.1 入口模式

`main.py` 严格保持精简（<100 行），只做 4 件事：

```python
# 1. 解析 → 2. 回显 → 3. 引导 → 4. 路由
args = build_parser().parse_args()
print_cli_args(args)
ctx = await bootstrap_environment(args)
await route_command(args, ctx)
```

所有复杂逻辑下沉到 `entrypoint/` 子模块。

### 2.2 Bootstrap Context 模式

环境初始化结果通过 `@dataclass` 统一传递，避免函数返回多个未命名元组：

```python
@dataclass
class BootstrapContext:
    attack_target: PromptTarget | None = None
    scorer_target: PromptTarget | None = None
    attacker_config: dict = field(default_factory=dict)
    scorer_config: dict = field(default_factory=dict)
    # ... 所有初始化产物都在这里
```

### 2.3 工厂模式创建目标

```python
# targets/factories.py 统一创建入口
create_scorer_target(config)     → AzureOpenAIChatTarget / OpenAIChatTarget
create_attack_target(config)     → OpenAIChatTarget / OpenAICompatibleTarget / GeminiTarget / ClaudeTarget
build_custom_target(endpoint, ..) → OpenAICompatibleTarget / GeminiTarget / ClaudeTarget / CustomHttpChatTarget
```

**Target SDK 选型标准（SDK 优先，不重复造轮子）：**

| API 类型 | Target 类 | SDK | 说明 |
|---|---|---|---|
| OpenAI / Ollama / vLLM 等 | `OpenAICompatibleTarget` | `openai` | `/v1/chat/completions` 兼容端点 |
| Google Gemini | `GeminiTarget` | `google-genai` | Gemini API（generateContent） |
| Anthropic Claude | `ClaudeTarget` | `anthropic` | Claude Messages API |
| 非标准 Web Chat API | `CustomHttpChatTarget` | `httpx` | form-urlencoded、GET 探测等兜底 |

**选型规则**：
1. 所有主流 LLM API 必须使用对应官方 SDK 实现，禁止手工构造 HTTP 请求
2. `CustomHttpChatTarget` 仅作为非标准 API 的兜底方案
3. 新增 API 接入时，优先使用已有 SDK；若无对应 SDK，在 `contributing/` 中补充理由

新增目标类型时在 factories 中添加工厂函数。

### 2.4 Router 分发模式

```python
# entrypoint/router.py — 所有执行模式的分发入口
async def route_command(args, ctx):
    if args.penetrating_mode:
        await _route_penetrating_mode(args, ctx)
    elif args.exploring_template:
        await _route_exploring_mode(args, ctx)
    elif args.orch == "legacy":
        await _route_legacy_mode(args, ctx)
    else:
        await _route_native_mode(args, ctx)
```

---

## 三、命名规范

### 3.1 模块命名：全称单词，禁用缩写

| ✅ 正确 | ❌ 错误 | 说明 |
|---------|---------|------|
| `entrypoint/` | `cli/`, `entry/` | 与 `orchestrators/converters/executor` 一致 |
| `converters/` | `conv/`, `prompt_converters/` | 全称 |
| `executor/` | `exec/`, `attack_executor/` | 全称 |
| `orchestrators/` | `orch/`, `orchestration/` | 复数 |
| `reporting/` | `report/`, `reports/` | 动名词 |
| `datasets/` | `data/`, `dataset/` | 复数 |

### 3.2 文件命名：小写 + 下划线，语义优先于简洁

| ✅ 正确 | ❌ 错误 |
|---------|---------|
| `http_target.py` | `http.py`, `target.py` |
| `model_probe.py` | `probe.py` |
| `pyrit_orchestrator.py` | `orch.py`, `native.py` |
| `scenario_runner.py` | `runner.py` |

### 3.3 函数命名

- 公开函数：`verb_noun` 格式 (`build_custom_target`, `load_env_config`, `route_command`)
- 私有辅助：`_verb_noun` 前缀 (`_build_config`, `_clean_value`, `_resolve`)
- 异步函数：`async def`，调用方统一 `await`

---

## 四、配置优先级链

所有可配置值遵循统一优先级：

```
CLI 显式参数  >  预设选择器  >  系统默认值
    ↑               ↑
  --target-url   TARGET_PRESET / PLATFORM_SELECTOR
```

实现模式（在 bootstrap 中使用 `_resolve` 合并）：

```python
def _resolve(key: str, default=None):
    cli_val = getattr(args, key, None)
    if cli_val and cli_val_is_not_default(cli_val, key):
        return cli_val
    return target_preset.get(key, default)
```

---

## 五、YAML 设计规范

### 5.1 清单文件结构

```yaml
metadata:
  version: "1.0"
  description: "..."

config:           # 执行配置（并发、超时、策略）
  max_concurrent: 3
  converter_presets: [...]

payloads:         # 或 prompts: / cases: — 核心攻击数据
  - id: "..."     # 全局唯一 ID
    objective: "..."  # 攻击目标描述
    criterion: "..."  # 判定标准
```

### 5.2 索引驱动

- 新模块必须在 `manifest.yaml` 注册 `module_id`、`key`、`file`、`loader`。
- 新漏洞必须在 `frontier/index.yaml` 注册 `id`、`category`、`severity`、`status`。
- 索引即文档：渗透者通过索引找到目标 YAML，不需要看代码。

### 5.3 Front Matter 注释

每个 YAML 文件开头必须包含标准注释块：

```yaml
# ===============================================================================
# 文件用途描述
# ===============================================================================
# 使用方式：命令行示例
# 维护者：维护说明
# ===============================================================================
```

---

## 六、Python 代码规范

### 6.1 Import 规范

```python
# 1. 标准库
import os
from dataclasses import dataclass

# 2. 第三方库
from rich.console import Console
from pyrit.memory import SQLiteMemory

# 3. 项目内部
from targets import load_env_config
from entrypoint.parser import build_parser
```

使用 `from targets import X` 而非 `from targets.config import X`，由 `__init__.py` 控制公开 API。

### 6.2 类型注解

- 所有公开函数必须包含类型注解。
- 使用 `| None` 而非 `Optional[X]`（Python 3.10+）。
- dataclass 字段使用 `field(default_factory=...)` 处理可变默认值。

### 6.3 文档字符串

- 每个公开函数包含中英文混合 docstring。
- 模块开头包含标准分隔注释块：

```python
"""
===============================================================================
模块名称 — 一句话职责描述
===============================================================================
使用方式: ...
===============================================================================
"""
```

### 6.4 控制台输出

- 统一使用 `rich.console.Console`。
- 状态行格式：`[emoji] [状态] [标签] 详情`
  - `✅ 攻击者 [OLLAMA] qwen3:0.6b @ http://...`
  - `🔍 评分器 [CUSTOM_SCORER] (独立平台) deepseek-v4-flash`
  - `❌ 错误: 具体原因`
  - `⚠️ 警告: 具体原因`

### 6.5 文件编码规范

**所有项目文本文件必须遵循统一的编码标准，确保跨平台、跨工具兼容。**

| 规范项 | 要求 | 说明 |
|--------|------|------|
| **字符编码** | UTF-8 without BOM | 禁止 UTF-8 with BOM、UTF-16、GBK 等其他编码 |
| **换行符** | LF (`\n`) | 统一 Unix 风格，禁止 CRLF（Windows）混用 |
| **缩进** | 空格（4 空格） | 禁止 Tab 字符 |
| **行尾空格** | 无 | 每行末尾不允许存在空白字符 |
| **文件末尾** | 单个空行结尾 | 最后一行后恰好一个换行符 |

**编码适用文件范围**：

| 文件类型 | 示例 | 关键约束 |
|----------|------|----------|
| Python 源码 | `*.py` | 所有字符串字面量使用标准 ASCII + UTF-8 多字节序列 |
| YAML 配置 | `*.yaml`, `*.yml` | 中文注释使用 UTF-8 编码，分隔线用标准 Unicode 字符（如 `─` U+2500） |
| 环境变量 | `.env`, `*.env` | 纯 ASCII，不包含非 ASCII 注释 |
| 依赖清单 | `requirements.txt` | 纯 ASCII，版本运算符 `>=`, `<`, `,` 均为标准 ASCII |
| Markdown 文档 | `*.md` | UTF-8 without BOM，中文标点使用全角形式 |

**检查与修复命令**：

```bash
# 检测文件编码（PowerShell）
Get-Content -Path <file> -Encoding UTF8 | Out-Null

# 检测 BOM 头
[System.IO.File]::ReadAllBytes("<file>")[0..2] -eq @(0xEF, 0xBB, 0xBF)

# 转换 CRLF → LF（Git）
git config core.autocrlf input

# 批量移除行尾空格（PowerShell）
(Get-Content <file>) -replace '\s+$', '' | Set-Content <file> -Encoding UTF8
```

**反例警示**：

| ❌ 禁止 | 后果 |
|---------|------|
| 文件包含 BOM (0xEF 0xBB 0xBF) | pip/解析器将 BOM 视为有效字符，导致语法错误 |
| 全角 ASCII 运算符（如 `＞＝` 代替 `>=`） | pip 等工具无法识别，报 `Invalid requirement` |
| CRLF 与 LF 混用 | Git diff 显示全文件变更，代码审查困难 |
| Tab 与空格混用 | Python 解释器报 `IndentationError` |
| 非 UTF-8 编码（GBK/Shift-JIS） | 跨平台打开乱码，CI/CD 解析失败 |

---

## 七、依赖管理

### 7.1 版本约束

```
pyrit>=0.14.0,<1.0.0          # 主框架：下限+上限
httpx>=0.27,<1.0               # HTTP 客户端
openai>=1.0,<3.0               # OpenAI SDK
google-genai>=1.0,<2.0          # Google Gemini SDK
anthropic>=0.40,<1.0           # Anthropic Claude SDK
python-dotenv>=1.0,<2.0       # 环境变量
pyyaml>=6.0,<7.0               # YAML 解析
pydantic>=2.0,<3.0             # 数据验证
rich>=13.0,<15.0               # 终端 UI
```

所有依赖必须锁定上限版本，禁止 `>=X` 无上限约束。

### 7.2 新增依赖审批

新增依赖前必须说明：
1. 功能必要性（为什么现有依赖无法实现）
2. 是否纯 Python（C 扩展需要跨平台编译）
3. 许可证是否兼容

### 7.3 Target SDK 依赖（核心依赖）

项目使用以下官方 SDK 对接各大 LLM API，**禁止手工构造 HTTP 请求替代**：

| 依赖 | 版本 | 对接 API | 文件 |
|---|---|---|---|
| `openai` | `>=1.0,<3.0` | OpenAI / Ollama / vLLM / ZHIPU / DeepSeek 等 | `targets/openai_sdk_target.py` |
| `google-genai` | `>=1.0,<2.0` | Google Gemini | `targets/gemini_target.py` |
| `anthropic` | `>=0.40,<1.0` | Anthropic Claude | `targets/claude_target.py` |
| `httpx` | `>=0.27,<1.0` | 非标准 API 兜底（raw 格式） | `targets/http_target.py` |

**选型原则（SDK 优先，不重复造轮子）：**
1. 所有主流 LLM API 必须使用对应官方 SDK 实现
2. SDK 自动处理：重试、流控、错误分类、响应反序列化
3. `CustomHttpChatTarget` 仅作为非标准 API 兜底，**禁止向其添加新格式支持**
4. 新增 API 接入时，优先使用已有 SDK；若无对应 SDK，在此文档中补充理由

**`CustomHttpChatTarget` 最小化原则：**
- `api_format` 始终为 `"raw"`，不针对任何特定 API 做格式适配
- 请求体固定为 `{"prompt": text}`，复杂格式通过 `extra_headers` + `content_type` 覆盖
- 响应直接返回原始文本或 JSON 字符串，不做字段级解析
- 新增 API 格式 → 新建 SDK Target 文件，禁止在 `http_target.py` 中添加 `_build_xxx_payload` / `_parse_xxx_response` 方法

---

## 八、执行期专家指导规范

### 8.1 四阶段指导模型

```
Stage 0: 配置就绪 (Readiness Gate) → scripts/config_center.py (Web GUI)
Stage 1: 探测后 (Pre-Execution)     → targets/target_type_probe.py
Stage 2: 执行中 (In-Execution)      → executor/dashboard.py + utils/guidance.py
Stage 3: 执行后 (Post-Execution)    → reporting/engine.py + reporting/terminal.py
```

### 8.0 Stage 0 — 配置就绪门禁 (Readiness Gate)

攻击前通过 Web 界面完成配置准备和就绪检查：

```
python scripts/config_center.py              # http://127.0.0.1:5051
python scripts/config_center.py --port 8080  # 自定义端口
```

功能:
- **配置浏览/编辑**: 管理 `configs/shared.env`、`platforms.env`、`targets.env`、`recons.env`
- **凭证管理**: 管理 `configs/tokens/` 下的 JWT/Cookie/API Key
- **语法校验**: 保存时自动校验 configparser 语法 + `%(VAR)s` 插值完整性
- **目标探测**: 连通性测试、API 类型识别、模型列表枚举
- **就绪检查**: 汇总所有配置完整性，确认通过后方可进入攻击阶段

架构:
```
scripts/config_center/          ← Web 框架包
├── __init__.py                  ← create_app() 工厂
├── routes.py                    ← API 路由 (Blueprint)
├── utils.py                     ← 配置读写与校验
├── readiness_probe.py           ← 目标探测聚合层（委托 targets/ 层）
├── templates/index.html         ← 前端页面
└── static/style.css             ← 样式
```

探测功能全部委托给 `targets/` 层已有函数，零新增探测逻辑。

### 8.2 Stage 2 执行中指导设计要求

- **实时仪表盘集成**: Dashboard 新增 `guidance` 面板，每次攻击完成后刷新
- **纯函数生成**: 指导逻辑放在 `utils/guidance.py` 独立纯函数，不耦合 UI
- **数据驱动**: 基于已完成攻击结果（成功率、突破组合、失败模式）动态生成
- **可复制命令**: 所有推荐必须是可直接 `复制粘贴` 执行的 CLI 命令
- **渐进降级**: 即使无有效结果也显示通用建议，不出现空面板

详细参见: `execution-guidance.md`

---

## 九、参考资料

详细模式说明和示例参见：
- `architecture-design.md` — 架构分层与数据流详解
- `config-patterns.md` — 配置管理模式与实战示例
- `yaml-patterns.md` — YAML 驱动开发完整模式
- `execution-guidance.md` — 执行期专家指导规范（三阶段模型、仪表盘集成）
