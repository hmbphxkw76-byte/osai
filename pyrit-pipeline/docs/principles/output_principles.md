# Output 模块原理说明

> 对齐 PyRIT 1.0.1 `pyrit.output` 官方文档  
> 版本: v2.1 | 更新日期: 2026-8-1  
> Pipeline 对接：原生输出由 `pipeline/stages/stage_output.py` 调用，证据收集由 `pipeline/analysis/evidence_collector.py` 实现，详见 [end_to_end_architecture.md](../end_to_end_architecture.md#七stage-6-结果输出)

---

## 目录

1. [核心概念](#1-核心概念)
2. [三层分离架构](#2-三层分离架构)
3. [Sink 体系](#3-sink-体系)
4. [Printer 基类与继承体系](#4-printer-基类与继承体系)
5. [Domain Printer 详解](#5-domain-printer-详解)
6. [Composition Pattern（组合模式）](#6-composition-pattern组合模式)
7. [render_async vs write_async](#7-render_async-vs-write_async)
8. [Blur Images（图片模糊）](#8-blur-images图片模糊)
9. [blurred_dir 参数](#9-blurred_dir-参数)
10. [include_reasoning_trace（推理轨迹）](#10-include_reasoning_trace推理轨迹)
11. [Convenience Functions（便捷函数）](#11-convenience-functions便捷函数)
12. [Image/Audio/Error 内容处理](#12-imageaudioerror-内容处理)
13. [AI-300 考试知识映射](#13-ai-300-考试知识映射)
14. [设计哲学](#14-设计哲学)

---

## 1. 核心概念

PyRIT Output 模块负责渲染攻击结果、场景结果、对话历史、评分和评分器信息。

核心设计原则：**三层分离** — 将"输出长什么样"（Format）、"输出到哪里"（Sink）和"数据从哪里来"（Abstract Methods）彻底解耦。

```
┌─────────────────────────────────────────┐
│  Convenience Functions (helpers.py)     │  ← 一行调用
│  output_attack_async / output_score...  │
├─────────────────────────────────────────┤
│  Domain Printers (pretty.py/markdown.py)│  ← 格式逻辑
│  AttackResult / Conversation / Score... │
├─────────────────────────────────────────┤
│  Sinks (sink.py)                        │  ← 输出目标
│  StdoutSink / FileSink / IPython...     │
└─────────────────────────────────────────┘
```

---

## 2. 三层分离架构

### Layer 1: Sink（输出目标）

Sink 定义输出去哪里，与格式无关：

| Sink | 说明 | 使用场景 |
|------|------|---------|
| `StdoutSink` | 打印到 stdout | 终端 pretty 输出 |
| `FileSink` | 写入文件 | Markdown 持久化 |
| `IPythonMarkdownSink` | IPython display(Markdown) | Jupyter Notebook |

`get_default_sink()` 自动检测环境：Notebook 内用 `IPythonMarkdownSink`，否则 `StdoutSink`。

### Layer 2: Printer（格式逻辑）

Printer 定义输出长什么样，与目标无关：

- **Pretty** (`pretty.py`): ANSI 着色，适合终端
- **Markdown** (`markdown.py`): Markdown 格式，适合 Notebook / 文件

每个 Domain Printer 都有 `render_async()` 和 `write_async()` 两个方法：
- `render_async()`: 返回渲染后的字符串
- `write_async()`: 调用 `render_async()` 然后通过 Sink 写出（concrete method）

### Layer 3: Abstract Methods（数据来源）

子类实现数据获取方法：
- `_get_conversation_async()`: 从 Memory/REST 获取对话
- `_get_scores_async()`: 从 Memory/REST 获取评分
- `_display_image_async()`: 在 Notebook 中显示图片

**Framework** 变体（`*MemoryPrinter`）通过 `CentralMemory` 获取数据。  
**Thin-client** 变体可通过 REST 端点获取数据。

---

## 3. Sink 体系

### Sink ABC

```python
class Sink(ABC):
    @abstractmethod
    async def write_async(self, data: str) -> None:
        """写入渲染后的输出"""
```

### StdoutSink

```python
class StdoutSink(Sink):
    async def write_async(self, data: str) -> None:
        encoding = sys.stdout.encoding or "utf-8"
        try:
            data.encode(encoding)
        except (LookupError, UnicodeEncodeError):
            data = data.encode(encoding, errors="replace").decode(encoding)
        sys.stdout.write(data)
```

### FileSink

- 支持 `mode="w"`（覆盖）和 `mode="a"`（追加）
- 使用 `asyncio.Lock()` 保证并发安全
- 实际写入通过 `asyncio.to_thread()` 在线程中执行

### IPythonMarkdownSink

- 在 Notebook 中使用 `IPython.display.Markdown` 渲染
- 非 Notebook 环境回退到 `print()`

### get_default_sink()

```python
def get_default_sink(default: type[Sink] | None = None) -> Sink:
    if default is not None:
        return default()
    if is_in_ipython_session():
        return IPythonMarkdownSink()
    return StdoutSink()
```

---

## 4. Printer 基类与继承体系

### PrinterBase

```python
class PrinterBase(ABC):
    def __init__(self, *, sink: Sink | None = None) -> None:
        self._sink = sink or StdoutSink()

    @abstractmethod
    async def render_async(self, *args, **kwargs) -> str:
        """子类实现：渲染并返回字符串"""

    async def write_async(self, *args, **kwargs) -> None:
        """Concrete: 调用 render_async 然后 _write_async"""
        content = await self.render_async(*args, **kwargs)
        await self._write_async(content)
```

### Domain Base Classes

| Base Class | Abstract Methods |
|-----------|-----------------|
| `AttackResultPrinterBase` | `_get_conversation_async()`, `_get_scores_async()` |
| `ConversationPrinterBase` | `_get_scores_async()`, `_display_image_async()`, `render_async()` |
| `ScenarioResultPrinterBase` | `render_async()` |
| `ScorerPrinterBase` | `_get_objective_metrics()`, `_get_harm_metrics()`, `render_async()` |
| `PrettyScorePrinter` / `MarkdownScorePrinter` | 直接继承 `PrinterBase`（无中间抽象层）|

---

## 5. Domain Printer 详解

### 5.1 AttackResult Printer

**Pretty**: `PrettyAttackResultPrinter` → `PrettyAttackResultMemoryPrinter`  
**Markdown**: `MarkdownAttackResultPrinter` → `MarkdownAttackResultMemoryPrinter`

渲染内容：
1. **Header**: outcome 图标 + 大写状态（✅ SUCCESS / ❌ FAILURE / ❓ UNDETERMINED）
2. **Summary**: 基本信息 + 执行指标 + 结果
3. **Conversation History**: 目标对话
4. **Pruned Conversations**（可选）: 树形攻击剪枝分支（仅最后一条消息 + 评分）
5. **Adversarial Conversation**（可选）: 红队 LLM 的推理对话
6. **Metadata**（可选）: 额外元数据
7. **Footer**: 时间戳

### 5.2 Conversation Printer

**Pretty**: `PrettyConversationPrinter` → `PrettyConversationMemoryPrinter`  
**Markdown**: `MarkdownConversationPrinter` → `MarkdownConversationMemoryPrinter`

特殊处理：
- **Reasoning pieces**: `original_value_data_type == "reasoning"` 时提取 summary
- **Blocked content**: `piece.is_blocked()` 显示 🚫 + partial_content
- **Converted content**: 显示 Original → Converted 转换对比
- **System messages**: 特殊格式
- **Simulated responses**: "Assistant (Simulated)" 标签
- **Image pieces**: Pretty 在 Notebook 中 display(Image)；Markdown 生成 `![Image](path)`
- **Audio pieces**: HTML5 `<audio>` 播放器
- **Error pieces**: 错误类型 + JSON 代码块

### 5.3 Score Printer

**Pretty**: `PrettyScorePrinter` — ANSI 着色，支持 `_render_score()` 内联使用  
**Markdown**: `MarkdownScorePrinter` — Markdown 列表，支持 `_format_score()` 内联使用

### 5.4 ScenarioResult Printer

**Pretty**: `PrettyScenarioResultPrinter` → `PrettyScenarioResultMemoryPrinter`  
（仅 Pretty 格式，不支持 Markdown）

渲染内容：
- 场景信息（名称/版本/PyRIT版本/描述）
- 目标信息（类型/模型/端点）
- 评分器信息与评估指标（委托 `ScorerPrinter`）
- 总体统计（技术数/攻击结果数/总体成功率）
- 逐组统计（支持 `sort_groups_by_success_rate` 排序）

### 5.5 Scorer Printer

**Pretty**: `PrettyScorerPrinter` → `PrettyScorerMemoryPrinter`  
（仅 Pretty 格式）

渲染内容：
- 评分器标识（类型/参数/子评分器递归）
- 目标信息（模型/温度）
- 性能指标：
  - Objective: accuracy / F1 / precision / recall / average_score_time
  - Harm: MAE / Krippendorff α / average_score_time

---

## 6. Composition Pattern（组合模式）

AttackResult Printer **组合** Conversation Printer 和 Score Printer：

```python
class PrettyAttackResultPrinter(AttackResultPrinterBase):
    def __init__(self, *, sink, ..., conversation_printer=None, score_printer=None):
        self._score_printer = score_printer or PrettyScorePrinter(sink=sink, ...)
        self._conversation_printer = conversation_printer or PrettyConversationPrinter(
            sink=sink, ..., score_printer=self._score_printer
        )
```

```
AttackResultPrinter
├── ConversationPrinter (对话渲染)
│   └── ScorePrinter (内联评分)
└── ScorePrinter (最终评分)
```

优势：
- 单一职责：每个 Printer 只负责自己的格式
- 代码复用：ConversationPrinter 被 AttackResultPrinter 和独立对话输出共享
- 可替换：可注入自定义 Printer

---

## 7. render_async vs write_async

### render_async

```python
content = await printer.render_async(result, include_auxiliary_scores=True)
# content 是渲染后的字符串，不写入任何 Sink
```

用途：
- 获取渲染字符串用于自定义处理
- 写入多个目标（如同时写文件和 zip 包）
- 消除 `write_async() + read-back` 冗余 I/O

### write_async

```python
await printer.write_async(result, include_auxiliary_scores=True)
# 自动调用 render_async 然后通过 Sink 写出
```

用途：
- 一行调用直接输出
- 使用便捷函数时内部调用

### L5 对齐实践

项目 `EvidenceExporter` 使用 `render_async()` 直接获取字符串：
- 同时写入独立文件和 zip 包
- 消除 `write_async() + read-back` 冗余 I/O
- 支持错误处理和 fallback

---

## 8. Blur Images（图片模糊）

### 设计目标

当攻击使用图片 Converter 或返回图片的 Target 时，渲染输出可能包含不适宜直接查看的图片。`blur_images=True` 在渲染前应用高斯模糊。

**重要**: 原始图片文件不被修改 — 这是审查者暴露控制旋钮，不是访问控制。

### Pretty 格式

- 图片在内存中模糊（`blur_image_bytes()`）
- Notebook 中 `display(Image(data=blurred_bytes))`
- 模糊失败时记录警告并显示原始图片

### Markdown 格式

- 模糊副本写入磁盘（`<stem>_blurred.png`）
- Markdown 链接到模糊副本而非原始
- 模糊失败时回退为纯文本链接（不渲染内联图片，避免审查者意外暴露）

### blur_image_bytes()

```python
def blur_image_bytes(*, image_bytes: bytes, radius: int = 20) -> bytes:
    # 使用 PIL ImageFilter.GaussianBlur
    # 返回 PNG 编码的模糊图片
    # 失败时返回原始 bytes
```

---

## 9. blurred_dir 参数

### 功能

`blurred_dir` 控制模糊图片副本的写入位置（仅 Markdown 格式）：

| 值 | 行为 |
|----|------|
| `None` | 写在原图旁边（`<stem>_blurred.png`） |
| 路径字符串 | 写在指定目录下（`<dir>/<stem>_blurred.png`） |

### 使用场景

- **证据导出**: 将模糊副本写入证据目录的 `blurred/` 子目录，纳入 zip 包
- **源代码树保护**: 将模糊副本重定向到源代码树之外，避免污染

### 原子写入

模糊副本通过原子写入保证并发安全：
1. 写入临时文件 `<name>.tmp.<pid>`
2. `os.replace()` 原子替换为目标文件
3. 失败时清理临时文件

### 缓存策略

已存在的模糊副本被复用（按路径缓存），避免重复模糊。调用者负责清理过期的模糊副本。

### L5 对齐实践

项目 `EvidenceExporter` 使用专用 `blurred_dir`：
- 自动创建 `evidence_dir/blurred/` 目录
- 模糊副本写入该目录
- 导出 zip 时通过 `_collect_blurred_images()` 收集并打包

---

## 10. include_reasoning_trace（推理轨迹）

### 功能

o1/o3 等推理模型返回的 `reasoning` 类型消息片段包含推理轨迹。`include_reasoning_trace=True` 在对话渲染中显示推理摘要。

### 实现细节

- 检测 `piece.original_value_data_type == "reasoning"`
- 从 JSON 中提取 `summary` 字段
- 显示为 `💭 Reasoning Summary:`

### 仅 Pretty 格式

Markdown 对话打印机接受此参数但不使用（接口兼容性）。

---

## 11. Convenience Functions（便捷函数）

### output_attack_async

```python
async def output_attack_async(
    result: AttackResult,
    *,
    format: OutputFormat = "pretty",
    sink: Sink | None = None,
    include_auxiliary_scores: bool = False,
    include_pruned_conversations: bool = False,
    include_adversarial_conversation: bool = False,
    blur_images: bool = False,
    blur_radius: int = 20,
    blurred_dir: str | os.PathLike[str] | None = None,
) -> None:
```

- `format="pretty"`: 使用 `PrettyAttackResultMemoryPrinter`
- `format="markdown"`: 使用 `MarkdownAttackResultMemoryPrinter`（支持 `blurred_dir`）
- `sink=None`: Pretty 默认 `StdoutSink`，Markdown 默认自动检测

### output_conversation_async

```python
async def output_conversation_async(
    messages: list[Message],
    *,
    format: OutputFormat = "pretty",  # 仅支持 "pretty"
    sink: Sink | None = None,
    include_scores: bool = False,
    include_reasoning_trace: bool = False,
    blur_images: bool = False,
    blur_radius: int = 20,
) -> None:
```

### output_score_async

```python
async def output_score_async(
    scores: list[Score],
    *,
    format: OutputFormat = "pretty",  # 仅支持 "pretty"
    sink: Sink | None = None,
) -> None:
```

### output_scenario_async

```python
async def output_scenario_async(
    result: ScenarioResult,
    *,
    format: OutputFormat = "pretty",  # 仅支持 "pretty"
    sink: Sink | None = None,
    sort_groups_by_success_rate: bool = False,
) -> None:
```

### output_scorer_async

```python
async def output_scorer_async(
    *,
    scorer_identifier: ComponentIdentifier,
    harm_category: str | None = None,
    format: OutputFormat = "pretty",  # 仅支持 "pretty"
    sink: Sink | None = None,
) -> None:
```

---

## 12. Image/Audio/Error 内容处理

### Image 内容

| 格式 | 处理方式 |
|------|---------|
| Pretty (Notebook) | `display(Image(data=bytes))`，支持内存模糊 |
| Pretty (非 Notebook) | 不显示图片 |
| Markdown | `![Image](path)`，支持磁盘模糊副本 |

路径处理：优先相对路径（Notebook 渲染器兼容），跨盘符回退到 `file://` URI。

### Audio 内容

Markdown 格式生成 HTML5 `<audio>` 播放器：
```html
<audio controls>
  <source src="path" type="audio/mpeg">
</audio>
```

### Error 内容

- **Blocked**: `piece.is_blocked()` → 🚫 + partial_content
- **Error**: `piece.has_error()` → 错误类型 + JSON 代码块

---

## 13. AI-300 考试知识映射

| 考试领域 | Output 模块知识点 |
|---------|-----------------|
| 攻击结果展示 | `output_attack_async` + pretty/markdown 双格式 |
| 对话历史渲染 | `output_conversation_async` + reasoning trace |
| 评分展示 | `output_score_async` + ScorePrinter |
| 场景级摘要 | `output_scenario_async` + 逐组统计 |
| 评分器评估 | `output_scorer_async` + Objective/Harm 指标 |
| 多模态输出 | blur_images + image_path 渲染 + audio 播放器 |
| 证据导出 | render_async + FileSink + blurred_dir + zip 打包 |
| 报告生成 | Markdown 报告 + HTML/PDF 转换 + OWASP 矩阵 |

---

## 14. 设计哲学

### 三层分离

- **Format** (Printer) — "输出长什么样"
- **Sink** (Destination) — "输出到哪里"
- **Data Source** (Abstract Methods) — "数据从哪里来"

三者正交组合，任意格式 × 任意目标 × 任意数据源。

### Composition over Inheritance

AttackResult Printer 组合 Conversation Printer 和 Score Printer，而非继承。每个 Printer 保持单一职责。

### render_async First

`render_async` 是核心抽象，`write_async` 是便捷封装。需要自定义处理时直接使用 `render_async`。

### Fail-Safe Blurring

模糊失败时不静默显示原始图片：
- Pretty: 记录警告，返回原始 bytes（已在内存中）
- Markdown: 记录警告，回退为纯文本链接

### Atomic Writes

模糊副本通过临时文件 + `os.replace()` 原子写入，并发安全。

### Environment Auto-Detection

`get_default_sink()` 自动检测运行环境，无需手动指定 Sink 类型。
