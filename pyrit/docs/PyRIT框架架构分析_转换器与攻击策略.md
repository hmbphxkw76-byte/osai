# PyRIT 框架架构分析：转换器与攻击策略

> 整理自 AI-300 项目代码分析与讨论，用于后续学习与总结。

---

## 一、核心理解：转换器 vs 攻击策略

**结论：转换器快速迭代，攻击策略相对稳定。**

| 架构层 | 内容 | 更新频率 | 说明 |
|--------|------|----------|------|
| 用例层 (`data/*.json`) | "what to ask" — 攻击目标/考题 | ⭐⭐⭐ 高频 | 新漏洞场景不断涌现 |
| 转换器层 (`converters.py`) | "how to wrap" — 单一攻击技巧 | ⭐⭐⭐ 高频 | 新论文 → 新手法 |
| 组合层 (`GLOBAL_ATTACK_COMBINATIONS`) | "which converters to stack" — 策略编排 | ⭐⭐☆ 中频 | 组合爆炸，发现有效排列才加 |

---

## 二、转换器 = 原子能力，迭代最快

### 2.1 新增一个转换器只需 ~20 行代码

```python
class NewestJailbreak2025(PromptConverter):
    """新论文里的最新手法"""
    def __init__(self):
        self.prefix = "..."  # 新的 prompt 包装话术

    async def convert_async(self, *, prompt, input_type="text"):
        return ConverterResult(
            output_text=self.prefix + prompt,
            output_type="text"
        )
```

然后注册到 `CONVERTER_MAP` 即可。

### 2.2 当前已有的转换器阵容

本项目已有 **14 个自定义转换器 + 10 个 PyRIT 编码转换器**，覆盖从 2023 到 2024 的前沿攻击手法：

**自定义越狱转换器（14 个）：**

| 转换器 | 技术来源 | 类别 |
|--------|----------|------|
| `RoleplayJailbreakConverter` | DAN 6.0 精简版 | 角色扮演越狱 |
| `ContextualPrimingConverter` | 学术研究身份伪装 | 合规伪装 |
| `PAIRJailbreakConverter` | JB 基准黑盒攻击 Top1 | 迭代反驳引导 |
| `DAN6FullJailbreakConverter` | DAN 6.0 完整版 | 角色扮演越狱 |
| `AIMJailbreakConverter` | Always Intelligent & Machiavellian | 逻辑诱导型 |
| `AcademicResearchConverter` | 学术研究身份掩护 | 合规伪装 Top1 |
| `DeveloperModeConverter` | 调试模式心理暗示 | 权限模拟 |
| `SuffixAppendConverter` | 指令覆盖后缀注入 | 追加注入 |
| `TranslationBypassConverter` | 跨语言安全训练绕过 | 翻译绕过 |
| `DeepInceptionConverter` | Li et al., 2024 | 多层嵌套场景 |
| `FewShotPrimingConverter` | ICL 上下文学习利用 | Few-Shot 引导 |

**PyRIT 编码混淆转换器（10 个）：**
`Base64`, `ROT13`, `Caesar`, `Leetspeak`, `UnicodeConfusable`, `ZeroWidth`, `Morse`, `AsciiArt`, `CharSwap`, `StringJoin`

---

## 三、组合策略 = 排列组合，相对稳定

### 3.1 组合范式

`GLOBAL_ATTACK_COMBINATIONS` 的排列模式是有限的：

| 组合范式 | 示例 |
|----------|------|
| 单一越狱前缀 | `PAIR_Jailbreak` |
| 越狱 + 一层编码 | `PAIR + Base64` |
| 越狱 + 两层编码 | `PAIR + Base64 + ZeroWidth` |
| 跨类别混合 | `FewShot + Translation` |
| 双学术包装叠加 | `Double_Academic` |

### 3.2 当前组合清单（30 组）

```
纯越狱前缀类 (7):
  PAIR_Jailbreak, DAN6_Full, AIM_Jailbreak, Academic_Research,
  Developer_Mode, Roleplay_Jailbreak, Contextual_Priming

越狱 + 编码混淆 (10):
  PAIR + Base64, DAN6 + ZeroWidth, AIM + UnicodeConfusable,
  Academic + Base64, DevMode + ROT13, Jailbreak + Base64,
  Academic_Priming + ZeroWidth, Contextual + Base64,
  Contextual + ROT13, Academic + ZeroWidth

纯编码混淆 (4):
  Base64 + ZeroWidth, ROT13 + UnicodeConfusable,
  Leetspeak + ZeroWidth, Caesar + Base64

三层编码链 (3):
  PAIR + Base64 + ZeroWidth, DAN6 + ROT13 + Unicode,
  AIM + Leetspeak + ZeroWidth

翻译绕过 (3):
  Translation_Bypass_Zulu, Translation + Base64,
  Translation + Academic

深度嵌套 & Few-Shot (4):
  DeepInception, DeepInception + Base64,
  FewShot_Priming, FewShot + ZeroWidth

Suffix 注入 (2):
  Suffix_Injection, Suffix + Base64

高对抗组合拳 (3):
  DeepInception + ROT13, FewShot + Translation,
  DAN6 + Suffix + Base64

AI-300 考试专项 (7):
  PAIR + Morse, DAN6 + AsciiArt, AIM + CharSwap,
  Academic + StringJoin, Morse + ZeroWidth,
  AsciiArt + Base64, CharSwap + ROT13

PROBE 热力图驱动 (3):
  Academic + Roleplay, Contextual + Suffix,
  Double_Academic
```

---

## 四、扩展机制分析

### 4.1 三层注册架构

```
┌─────────────────────────────────────────────────┐
│  1. 写类 (~20 行)                                 │
│     class NewAttack(PromptConverter):            │
│         ...convert_async(...)                    │
├─────────────────────────────────────────────────┤
│  2. 注册到 CONVERTER_MAP (1 行)                    │
│     "NewAttack": NewAttack                       │
├─────────────────────────────────────────────────┤
│  3. 加组合策略 (可选, 1~2 行)                       │
│     {"name": "NewAttack + Base64",               │
│      "converters": ["NewAttack", "Base64"]}      │
└─────────────────────────────────────────────────┘
```

### 4.2 关键设计点

**1. `CONVERTER_MAP` — 唯一注册入口**

```python
CONVERTER_MAP = {
    "Base64Converter": Base64Converter,
    "ROT13Converter": ROT13Converter,
    # ... 更多转换器
    "FewShotPrimingConverter": FewShotPrimingConverter,
}
```

每种新转换器在此加一行即完成注册。字符串到类的映射，完全解耦。

**2. `resolve_converters()` — 统一工厂函数**

```python
def resolve_converters(converter_names: list) -> list:
    """将转换器名称字符串列表解析为实例列表。"""
    return [CONVERTER_MAP[name]() for name in converter_names if name in CONVERTER_MAP]
```

所有引擎通过这个函数按**名称字符串**取转换器，不直接依赖类。新转换器注册后，引擎层无需改动任何代码。

**3. `GLOBAL_ATTACK_COMBINATIONS` — 策略编排**

组合策略也走字符串名称。新转换器上线后，按"名称 + 编码器"的范式机械添加组合即可。

### 4.3 实际扩展示例

以添加 2025 新论文的 `TreeOfThoughtsConverter` 为例：

```python
# 第 1 步：在 converters.py 中写类
class TreeOfThoughtsConverter(PromptConverter):
    SUPPORTED_INPUT_TYPES = ("text",)
    SUPPORTED_OUTPUT_TYPES = ("text",)
    def __init__(self):
        self.prefix = "Let's think this through step by step..."
    async def convert_async(self, *, prompt, input_type="text"):
        return ConverterResult(
            output_text=self.prefix + prompt,
            output_type="text"
        )

# 第 2 步：注册到 CONVERTER_MAP
CONVERTER_MAP["TreeOfThoughts"] = TreeOfThoughtsConverter

# 第 3 步：加组合策略（可选）
# 单用：{"name": "TreeOfThoughts", "converters": ["TreeOfThoughts"]},
# 混用：{"name": "TreeOfThoughts + Base64", "converters": ["TreeOfThoughts", "Base64"]},
```

**引擎层不动任何代码**，`resolve_converters` 自动识别新名称并实例化。

---

## 五、攻击流程 vs 速度因素

### 5.1 攻击流程中的角色分工

```
AI-300 (本地编排)      目标 API (被攻击 LLM)      评分器 API (Judge LLM)
       │                      │                        │
       ├── POST 攻击 prompt ──→│  ← 网络RTT + 推理时间    │
       │←── 响应文本 ──────────│                        │
       │                      │                        │
       │──────────────────────────────────────→│  ← 评分请求
       │←──────────────────────────────────────│  ← True/False
```

AI-300 只负责：① 构造 prompt、② HTTP 收发、③ 评分编排。**所有推理在远端 API 上完成。**

### 5.2 速度影响因素

| 因素 | 影响程度 | 说明 |
|------|----------|------|
| `--concurrent` 并发数 | ⭐⭐⭐ | 最大可调参数，`asyncio.Semaphore` 控制 |
| API 速率限制 (429) | ⭐⭐⭐ | 指数退避重试，最多 3 次 |
| 网络延迟 (RTT) | ⭐⭐⭐ | 每个任务 4 次网络往返 |
| 目标模型推理速度 | ⭐⭐ | 远端 API 则取决于对方 GPU |
| 评分器推理速度 | ⭐⭐ | 每次攻击调一次 Judge LLM |
| 异常重试 | ⭐ | 遇到 429/500/503/Timeout 时指数退避 |

### 5.3 GPU 何时有用

**只有一种场景**：自己在本机跑目标 LLM（如 Ollama/vLLM），用 `--target-url http://localhost:11434/...` 攻击时，GPU 加速的是**目标模型的推理响应**。AI-300 自身代码完全不涉及 GPU 计算（无 torch/CUDA 依赖）。

---

## 六、报告输出机制

| 运行命令 | 输出文件 |
|----------|----------|
| `--phase probe` | `results/AI-300_PROBE_Recon_Exam_Report_HHMMSS.md` |
| `--phase single` | `results/AI-300_SingleTurn_Assault_Exam_Report_HHMMSS.md` |
| `--phase crescendo` | `results/AI-300_Crescendo_Siege_Exam_Report_HHMMSS.md` |
| `--auto-gate` | `results/AI-300_Combined_All_Phases_Exam_Report_HHMMSS.md` |
| `--phase all` | `results/AI-300_Full_Campaign_Exam_Report_HHMMSS.md` |

下一步攻击命令同时写入：① 终端 Console 实时查看、② Markdown 报告文件持久保存（位于"下一步攻击命令（自动生成）"章节）。

---

## 七、总结

> **转换器是插件，框架是管道。**

| 更新内容 | 成本 | 频率 |
|----------|------|------|
| 新攻击手法 → 写 Converter 类 | ~20 行代码 + 1 行注册 | 高（跟随论文/社区） |
| 新组合策略 → 加 `GLOBAL_ATTACK_COMBINATIONS` | ~2 行 JSON | 中（机械操作） |
| 攻击策略框架（单轮/Crescendo/门控） | 基本不变 | 低（架构层面） |

这是 PyRIT 框架设计的精髓：**转换器是原子化的攻击能力单元，框架提供标准的管道和编排能力，二者完全解耦。** 新转换器接入后自动享受所有现有组合策略和引擎支持。
