# PyRIT Scoring 原理说明文档

> 基于 PyRIT 1.0.1 官方文档（5 个页面）系统梳理 — 以 PyRIT 专家架构师视角  
> 文档版本：v1.1 | 更新日期：2026-8-1  
> Pipeline 对接：评分器由 `pipeline/stages/stage_scenario.py` 获取 (三级 fallback)，评分结果在 `stage_execute.py` 分析，详见 [end_to_end_architecture.md](../end_to_end_architecture.md#三stage-2-asr-驱动场景配置)

---

## 目录

1. [Scoring 核心概念](#1-scoring-核心概念)
2. [两种返回类型：true_false 与 float_scale](#2-两种返回类型true_false-与-float_scale)
3. [Scorer 参考表（全量分类）](#3-scorer-参考表全量分类)
4. [Scorer 类继承体系](#4-scorer-类继承体系)
5. [True/False 评分器详解](#5-truefalse-评分器详解)
6. [Float-Scale 评分器详解](#6-float-scale-评分器详解)
7. [组合与堆叠评分器（Combining & Stacking）](#7-组合与堆叠评分器combining--stacking)
8. [自定义评分器（Custom Scorers）](#8-自定义评分器custom-scorers)
9. [ScorerPromptValidator 验证器体系](#9-scorerpromptvalidator-验证器体系)
10. [ResponseHandler 响应契约体系](#10-responsehandler-响应契约体系)
11. [Blocked Content 处理策略](#11-blocked-content-处理策略)
12. [对话级评分（Conversation Scoring）](#12-对话级评分conversation-scoring)
13. [多模态评分器（Multimodal Scorers）](#13-多模态评分器multimodal-scorers)
14. [批量评分（Batch Scoring）](#14-批量评分batch-scoring)
15. [Scorer Metrics 评估指标体系](#15-scorer-metrics-评估指标体系)
16. [评分器身份与注册表（Identity & Registry）](#16-评分器身份与注册表identity--registry)
17. [攻击中的三层评分架构](#17-攻击中的三层评分架构)
18. [AI-300 考试知识映射](#18-ai-300-考试知识映射)
19. [Scoring 设计哲学：何时需要新的 Scorer 类](#19-scoring-设计哲学何时需要新的-scorer-类)

---

## 1. Scoring 核心概念

### 1.1 定义

**Scoring**（评分）评估 *提示发生了什么*。它是 PyRIT 回答以下问题的方式：

- 是否检测到提示注入？
- 提示是否被阻止？为什么？
- 响应中是否有有害内容？有多严重？

一个 **Scorer**（评分器）接受一个响应（或整个对话）并返回一个或多个 `Score` 对象。

### 1.2 三种使用方式

| 方式 | 说明 | API |
|:--|:--|:--|
| **直接评分** | 手动调用 `scorer.score_text_async(text=...)` | 本页 |
| **攻击内评分** | 作为 objective_scorer 传给 Attack，自动评分 | `AttackScoringConfig(objective_scorer=scorer)` |
| **批量评分** | 对 Memory 中已存储的响应批量评分 | `BatchScorer` |

### 1.3 核心不变量

```
response → Scorer → Score(s)
```

每个 Scorer 接受 `Message`（响应），返回 `list[Score]`。一个响应可能产生多个 Score（例如按类别评分）。

---

## 2. 两种返回类型：true_false 与 float_scale

每个具体评分器返回两种分数类型之一：

### 2.1 `true_false` — 布尔值

- `score.get_value()` 返回 `bool`
- 适用于：成功标准（"攻击是否成功？"）、拒绝检测、策略检查
- 典型场景：objective_scorer（攻击目标达成判定）

### 2.2 `float_scale` — 归一化浮点数

- `score.get_value()` 返回 `float`（0.0–1.0）
- 适用于：量化 *某种特性的程度*（如有害内容严重度）
- 不同后端使用不同原始范围（Azure Content Safety 0–7，Likert 1–5），PyRIT 统一归一化到 0–1

### 2.3 两种类型的相互转换

```
float_scale → true_false  通过 FloatScaleThresholdScorer 应用阈值
true_false  → float_scale  不直接支持（True 即 1.0，False 即 0.0）
```

---

## 3. Scorer 参考表（全量分类）

### 3.1 True/False 评分器

| Scorer | 使用 LLM | 说明 |
|:--|:--:|:--|
| SubStringScorer | ❌ | 子字符串匹配 |
| RegexScorer | ❌ | 正则表达式匹配 |
| CredentialLeakScorer | ❌ | 凭证泄露检测（RegexScorer 子类） |
| MarkdownInjectionScorer | ❌ | Markdown 注入检测 |
| StaticPromptInjectionScorer | ❌ | 静态注入检测（RegexScorer 子类） |
| DecodingScorer | ❌ | 解码检测（请求文本是否出现在响应中） |
| PromptShieldScorer | ❌ | Azure Prompt Shield 集成 |
| QuestionAnswerScorer | ❌ | 问答匹配（非 LLM） |
| AnthraxKeywordScorer | ❌ | 炭疽关键词检测 |
| FentanylKeywordScorer | ❌ | 芬太尼关键词检测 |
| MethKeywordScorer | ❌ | 冰毒关键词检测 |
| NerveAgentKeywordScorer | ❌ | 神经毒剂关键词检测 |
| XSSOutputScorer | ❌ | XSS 输出检测 |
| SQLInjectionOutputScorer | ❌ | SQL 注入输出检测 |
| ShellCommandOutputScorer | ❌ | Shell 命令输出检测 |
| PathTraversalOutputScorer | ❌ | 路径遍历输出检测 |
| SSRFOutputScorer | ❌ | SSRF 输出检测 |
| SSTIOutputScorer | ❌ | SSTI 模板注入检测 |
| XXEOutputScorer | ❌ | XXE XML 实体注入检测 |
| OpenRedirectOutputScorer | ❌ | 开放重定向检测 |
| LDAPInjectionOutputScorer | ❌ | LDAP 注入检测 |
| FloatScaleThresholdScorer | ❌ | 浮点→布尔阈值转换 |
| TrueFalseCompositeScorer | ❌ | 多评分器逻辑组合 |
| TrueFalseInverterScorer | ❌ | 逻辑取反 |
| VideoTrueFalseScorer | ❌ | 视频帧检测 |
| AudioTrueFalseScorer | ❌ | 音频转写检测 |
| GandalfScorer | ✅ | Gandalf 密码检测 |
| SelfAskTrueFalseScorer | ✅ | 通用真/假判断 |
| SelfAskGeneralTrueFalseScorer | ✅ | 通用真/假判断（自定义系统提示） |
| SelfAskCategoryScorer | ✅ | 分类评分 |
| SelfAskQuestionAnswerScorer | ✅ | 问答准确性评分 |
| SelfAskRefusalScorer | ✅ | 拒绝检测 |
| LlamaGuardScorer | ✅ | Llama Guard 3 内容安全 |

### 3.2 Float-Scale 评分器

| Scorer | 使用 LLM | 说明 |
|:--|:--:|:--|
| AzureContentFilterScorer | ❌ | Azure Content Safety API（0–7 归一化） |
| PlagiarismScorer | ❌ | 抄袭检测（LCS/Levenshtein/Jaccard） |
| VideoFloatScaleScorer | ❌ | 视频帧聚合评分 |
| AudioFloatScaleScorer | ❌ | 音频转写评分 |
| SelfAskLikertScorer | ✅ | Likert 量表评分（1–5 归一化） |
| SelfAskScaleScorer | ✅ | 自定义数值量表评分 |
| SelfAskGeneralFloatScaleScorer | ✅ | 通用浮点评分（自定义系统提示） |
| InsecureCodeScorer | ✅ | 不安全代码风险评分 |

---

## 4. Scorer 类继承体系

```
<<abstract>>
Scorer
├── <<abstract>> TrueFalseScorer
│   ├── SubStringScorer
│   ├── RegexScorer
│   │   ├── CredentialLeakScorer
│   │   ├── XSSOutputScorer / SQLInjectionOutputScorer / ...
│   │   ├── MarkdownInjectionScorer
│   │   ├── StaticPromptInjectionScorer
│   │   └── *KeywordScorer (Anthrax/Fentanyl/Meth/NerveAgent)
│   ├── SelfAskTrueFalseScorer
│   ├── SelfAskRefusalScorer
│   ├── SelfAskCategoryScorer
│   ├── SelfAskQuestionAnswerScorer
│   ├── SelfAskGeneralTrueFalseScorer
│   ├── TrueFalseCompositeScorer
│   ├── TrueFalseInverterScorer
│   ├── FloatScaleThresholdScorer
│   ├── GandalfScorer
│   ├── PromptShieldScorer
│   ├── LlamaGuardScorer
│   ├── QuestionAnswerScorer
│   └── DecodingScorer
│
├── <<abstract>> FloatScaleScorer
│   ├── AzureContentFilterScorer
│   ├── PlagiarismScorer
│   ├── SelfAskLikertScorer
│   ├── SelfAskScaleScorer
│   ├── SelfAskGeneralFloatScaleScorer
│   └── InsecureCodeScorer
│
└── <<abstract>> ConversationScorer  (从不直接实例化)
    └── create_conversation_scorer() 动态创建混合子类
```

**关键设计**：`ConversationScorer` 从不直接实例化。`create_conversation_scorer()` 构建一个将其与 `TrueFalseScorer` 或 `FloatScaleScorer` 混合的子类，使包装的评分器能在整个对话上运行。

---

## 5. True/False 评分器详解

### 5.1 快速评分器（无 LLM）

这些在本地确定性地运行 — 无模型调用、无需凭据。适合 CI 和大规模评分。

#### 5.1.1 RegexScorer

正则表达式匹配。返回 `True` 如果任何命名模式匹配。子类化以实现领域特定检测器。

```python
contact_scorer = RegexScorer(
    patterns={
        "email": r"(?i)[\w.+-]+@[\w-]+\.[\w.-]+",
        "phone": r"\b\d{3}[-.]\d{3}[-.]\d{4}\b",
    },
    categories=["pii"],
)
```

PyRIT 内置的 RegexScorer 子类：
- `CredentialLeakScorer` — 泄露的密钥/令牌（AWS/GitHub/Google/Slack/JWT/Private Key）
- `MethKeywordScorer` / `FentanylKeywordScorer` / `NerveAgentKeywordScorer` / `AnthraxKeywordScorer` — 关键词检测
- OWASP LLM02 输出检测器家族（见下）

#### 5.1.2 OWASP LLM02 输出检测器

一组 `RegexScorer` 子类，标记模型可能输出的不安全内容：

| Scorer | 检测内容 |
|:--|:--|
| `XSSOutputScorer` | `<script>`, `onerror=`, `javascript:` URI, SVG 嵌入脚本 |
| `SQLInjectionOutputScorer` | `UNION SELECT`, `;DROP TABLE`, `';--` |
| `ShellCommandOutputScorer` | `curl ... \| sh`, `rm -rf /`, 反向 shell |
| `PathTraversalOutputScorer` | `../../etc/passwd` 等路径遍历 |
| `SSRFOutputScorer` | `169.254.169.254` 元数据, `http://localhost`, `gopher://` |
| `SSTIOutputScorer` | `{{7*7}}` / `${7*7}` 评估探针, `__class__` / `__globals__` 链 |
| `XXEOutputScorer` | `<!ENTITY ... SYSTEM>` 外部实体 |
| `OpenRedirectOutputScorer` | `redirect=//evil`, `%2f%2f` 绕过 |
| `LDAPInjectionOutputScorer` | `*)(uid=*)` 过滤器破坏 |

每个都附带默认模式集；传入自己的 `patterns` 字典可完全替换。

#### 5.1.3 SubStringScorer

最简单的快速评分器 — 子字符串匹配。

#### 5.1.4 StaticPromptInjectionScorer

`RegexScorer` 子类，本地标记提示注入尝试（OWASP LLM01）— 指令覆盖、系统提示提取、越狱角色扮演、编码规避。偏向召回而非精度，适合作为模型评分器（如 `PromptShieldScorer`）前的廉价预过滤器。

#### 5.1.5 DecodingScorer

检查请求文本（`original_value`、`converted_value` 或解码元数据）是否出现在响应中 — 判断目标是否解码了编码提示的快速确定性方法。支持 Garak 编码场景。

### 5.2 慢速评分器（LLM Self-Ask）

`SelfAsk*` 评分器请求 chat target 对响应进行推理。灵活且能处理细微差别，代价是每次评分一次模型调用。

#### 5.2.1 SelfAskTrueFalseScorer

通用 self-ask 评分器。无模板时判断目标是否达成；传入内置 `TrueFalseQuestionPaths` 模板用于特定问题（如检测成功提示注入）。

```python
injection_scorer = SelfAskTrueFalseScorer.from_question(
    chat_target=OpenAIChatTarget(),
    question=TrueFalseQuestion.from_yaml(TrueFalseQuestionPaths.PROMPT_INJECTION.value),
)
```

**内置 TrueFalseQuestionPaths（9 种预设）**：

| 预设 | 用途 |
|:--|:--|
| `TASK_ACHIEVED` | 任务达成判定（最常用） |
| `TASK_ACHIEVED_REFINED` | 精化任务达成判定 |
| `PROMPT_INJECTION` | 提示注入检测 |
| `QUESTION_ANSWERING` | 问答准确性 |
| `GROUNDED` | 接地性/幻觉检测 |
| `CURRENT_EVENTS` | 时事准确性 |
| `GANDALF` | Gandalf 专用 |
| `YES_NO` | 是/否回答检测 |
| `CRIMINAL_PERSONA` | 犯罪人格检测 |

#### 5.2.2 SelfAskRefusalScorer

专门检测拒绝。返回 `True` 表示拒绝；当目标完全阻止响应（`response_error="blocked"`）时短路返回 `True`（无 LLM 调用）。部分阻止的响应仍有内容，由 LLM 正常评分。

**关键设计**：
- 完全阻止 → 确定性短路（`True`），不调用 LLM
- 部分阻止 → 仍有 `partial_content`，由 LLM 正常评分
- 常见于内容过滤器

#### 5.2.3 SelfAskCategoryScorer

将响应分类为一组类别之一（或无）。当响应匹配有害类别时 `score=True`；`score.score_category` 保存匹配的标签。

```python
category_scorer = SelfAskCategoryScorer.from_content_classifier(
    chat_target=OpenAIChatTarget(),
    content_classifier=ContentClassifier.from_yaml(
        ContentClassifierPaths.HARMFUL_CONTENT_CLASSIFIER.value
    ),
)
```

#### 5.2.4 SelfAskQuestionAnswerScorer

检查响应是否正确回答了已知问题（用于问答数据集）。

#### 5.2.5 QuestionAnswerScorer

`SelfAskQuestionAnswerScorer` 的快速、非 LLM 变体，直接匹配预期答案。

#### 5.2.6 SelfAskGeneralTrueFalseScorer

完全控制：提供自己的系统提示和 JSON schema，当内置模板不合适时使用。

### 5.3 外部分类器集成

三个 true/false 评分器包装托管服务而非生成式 LLM：

| Scorer | 服务 | 返回 True 条件 |
|:--|:--|:--|
| `PromptShieldScorer` | Azure Prompt Shield（越狱分类器） | 检测到提示或文档中的攻击 |
| `GandalfScorer` | Gandalf 挑战 | 密码被揭示 |
| `LlamaGuardScorer` | Llama Guard 3（8B S1-S14） | 不安全内容（元数据含违规类别） |

三者都需要各自的端点/凭据，尽管它们不是 "self-ask"。

### 5.4 多模态评分器

音频和视频响应通过转写或采样后委托给文本/图像 true/false 评分器：

- `AudioTrueFalseScorer` — 转写音频（Azure Speech-to-Text），用包装的 `TrueFalseScorer` 评分转写文本
- `VideoTrueFalseScorer` — 从视频提取帧，用包装的图像 `TrueFalseScorer` 评分（任一帧匹配即 True）；可选音频评分器 AND 组合

---

## 6. Float-Scale 评分器详解

### 6.1 快速评分器

#### 6.1.1 AzureContentFilterScorer

Azure Content Safety API 检测文本或图像中的危害类别（hate、violence、sexual、self-harm）。调用托管分类器（非生成式 LLM）— 需要端点和凭据但无需 chat target。

**归一化**：原始 0–7 严重度归一化到 0–1。每个类别一个 Score，`score_metadata` 保存原始严重度。

#### 6.1.2 PlagiarismScorer

测量响应与参考文本之间的文本重叠。支持三种度量：

| 度量 | 说明 |
|:--|:--|
| `PlagiarismMetric.LCS` | 最长公共子序列 |
| `PlagiarismMetric.LEVENSHTEIN` | Levenshtein 距离 |
| `PlagiarismMetric.JACCARD` | Jaccard 相似度 |

本地运行，无 LLM。

### 6.2 慢速评分器（LLM Self-Ask）

这些请求 chat target 按量表对响应评分，然后归一化到 0–1。

#### 6.2.1 SelfAskLikertScorer

按预定义 Likert 量表（1–5）对响应评分。PyRIT 通过 `LikertScalePaths` 提供量表：

- `MISINFORMATION_SCALE` — 虚假信息严重度
- `HARM_SCALE` — 危害严重度
- `BEHAVIOR_CHANGE_SCALE` — 行为变化程度
- `EXPLOITS_SCALE` — 漏洞利用程度

**归一化**：1→0.0, 2→0.25, 3→0.5, 4→0.75, 5→1.0

#### 6.2.2 InsecureCodeScorer

评估代码片段的风险程度，标记注入、弱认证等漏洞。

```python
insecure_code_scorer = InsecureCodeScorer.from_harm_categories(chat_target=OpenAIChatTarget())
```

#### 6.2.3 SelfAskScaleScorer

按自定义 `NumericRubric`（内存构造或 YAML 加载）评分。

#### 6.2.4 SelfAskGeneralFloatScaleScorer

完全控制：提供自己的系统提示、JSON schema 和 `NumericRange`。

### 6.3 多模态评分器

float-scale 媒体评分器镜像其 true/false 对应物：

- `AudioFloatScaleScorer` — 转写音频并评分转写文本
- `VideoFloatScaleScorer` — 采样帧并聚合各类别浮点分数（默认 MAX）；可选音频评分器折叠

---

## 7. 组合与堆叠评分器（Combining & Stacking）

评分器是可组合的。不构建一个复杂评分器，而是组合小的评分器。

### 7.1 TrueFalseCompositeScorer — 逻辑聚合

将多个 `TrueFalseScorer` 聚合为一个结果：

| 聚合器 | 逻辑 | 说明 |
|:--|:--|:--|
| `TrueFalseScoreAggregator.AND` | 全部 True 才 True | 多重条件同时满足 |
| `TrueFalseScoreAggregator.OR` | 任一 True 即 True | 多种检测方式任一命中 |
| `TrueFalseScoreAggregator.MAJORITY` | 过半数 True 才 True | 多评分器投票 |

子评分器**并行执行**，结果通过聚合函数合并。

### 7.2 TrueFalseInverterScorer — 逻辑取反

取反包装的评分器：`True → False`, `False → True`。

典型用途：将 `SelfAskRefusalScorer`（检测拒绝=True）取反为 "未拒绝" 指标。

### 7.3 FloatScaleThresholdScorer — 阈值转换

包装 `FloatScaleScorer`，当归一化分数 ≥ 阈值时返回 `True`。这是将严重度分数转换为 pass/fail 成功标准的标准方法。

```
score >= threshold → True
score <  threshold → False
```

**聚合器策略**（多 piece 响应时）：

| 聚合器 | 说明 |
|:--|:--|
| `FloatScaleScoreAggregator.MAX` | 取最高分（默认） |
| `FloatScaleScoreAggregator.AVERAGE` | 取平均分 |
| `FloatScaleScoreAggregator.MIN` | 取最低分 |

原始浮点值保留在 `score_metadata["original_float_value"]` 中，供多轮攻击反馈循环使用。

### 7.4 组合评分器的可组合性

这些包装器本身也是评分器，因此它们像叶子评分器一样插入攻击和批量评分器。

```python
# 三重组合：注入成功 AND 未拒绝 AND 内容泄露
composite = TrueFalseCompositeScorer(
    aggregator=TrueFalseScoreAggregator.AND,
    scorers=[injection_scorer, TrueFalseInverterScorer(refusal_scorer), leak_scorer],
)
```

---

## 8. 自定义评分器（Custom Scorers）

当内置模板不合适时，通用 self-ask 评分器让你提供自己的系统提示和 JSON schema，而非编写新类：

### 8.1 SelfAskGeneralTrueFalseScorer

- 提供自定义 `system_prompt_format_string`（支持 `{objective}` 占位符）
- 提供自定义 JSON schema
- 提供自定义 `rationale_output_key`

### 8.2 SelfAskGeneralFloatScaleScorer

- 提供自定义系统提示和 JSON schema
- 提供自定义 `NumericRange`（非标准 0–1 范围）
- 评分值自动归一化到 0–1

**设计原则**：大多数评分器行为通过配置实现，而非新代码。在编写新的 Scorer 类之前，先检查是否可以用通用评分器 + 自定义配置实现。

---

## 9. ScorerPromptValidator 验证器体系

### 9.1 核心概念

`ScorerPromptValidator` 是 PyRIT 1.0.1 在 Scorer 基类中引入的验证层，在评分前检查输入是否符合评分器的要求：

| 验证维度 | 参数 | 说明 |
|:--|:--|:--|
| 数据类型 | `supported_data_types` | 支持的数据类型列表（text/image_path/audio_path/...） |
| 角色 | `supported_roles` | 支持的角色列表（assistant/simulated_assistant/...） |
| Piece 数量 | `max_pieces_in_response` | 最大 piece 数 |
| 文本长度 | `max_text_length` | 文本最大字符数 |
| 元数据 | `required_metadata` | 必需的元数据键 |
| Objective | `is_objective_required` | 是否必须提供 objective |
| 强制模式 | `enforce_all_pieces_valid` | 是否所有 piece 必须有效 |
| 异常模式 | `raise_on_no_valid_pieces` | 无有效 piece 时是否抛异常 |

### 9.2 默认验证器

- 默认验证器：接受所有数据类型和角色，不限制 piece 数/文本长度
- 无效 piece 自动跳过（除非 `enforce_all_pieces_valid=True`）
- 无有效 piece 时返回空列表（除非 `raise_on_no_valid_pieces=True`）

---

## 10. ResponseHandler 响应契约体系

### 10.1 核心概念

`ResponseHandler` 拥有评分 LLM 响应的契约 — 定义如何将原始文本解析为结构化评分：

| 组件 | 说明 |
|:--|:--|
| `score_value_output_key` | 分数值的 JSON 键名 |
| `rationale_output_key` | 评分理由的 JSON 键名 |
| `description_output_key` | 描述的 JSON 键名 |
| `metadata_output_key` | 元数据的 JSON 键名 |
| `category_output_key` | 分类的 JSON 键名 |

### 10.2 两种实现

| 实现 | 说明 | 适用场景 |
|:--|:--|:--|
| `JsonSchemaResponseHandler` | JSON Schema 结构化输出 | 标准场景（LLM 原生返回 JSON） |
| `CallableResponseHandler` | 自定义解析函数 | 非 JSON 格式（如 LlamaGuard 的 "safe\\nS1,S2"） |

### 10.3 与验证器的关系

`ResponseHandler` 处理 LLM 输出解析，`ScorerPromptValidator` 处理输入验证。两者可独立配置，也可组合使用。

---

## 11. Blocked Content 处理策略

### 11.1 两个关键参数

PyRIT 1.0.1 在 Scorer 基类中引入两个关键参数：

| 参数 | 默认值 | 说明 |
|:--|:--|:--|
| `score_blocked_content` | `False` | 是否评分被拦截响应的 `partial_content` |
| `raise_if_scorer_blocks` | `True` | 评分器自身 LLM 被拦截时是否抛异常 |

### 11.2 行为矩阵

| 场景 | `score_blocked_content=True` | `score_blocked_content=False` |
|:--|:--|:--|
| 目标完全阻止 | 使用 `partial_content` 评分 | 返回 fallback（TrueFalse→False, FloatScale→0.0） |
| 目标部分阻止 | 使用 `partial_content` 正常评分 | 使用 `partial_content` 正常评分 |

| 场景 | `raise_if_scorer_blocks=True` | `raise_if_scorer_blocks=False` |
|:--|:--|:--|
| 评分器 LLM 被拦截 | 抛 `ScorerLLMResponseBlockedException` | 返回类型默认值 |

### 11.3 推荐配置

| 场景 | `score_blocked_content` | `raise_if_scorer_blocks` |
|:--|:--|:--|
| **红队测试** | `True` | `False` |
| **正式评估** | `False` | `True` |

红队场景中，目标响应经常被内容过滤拦截，评分器自身也容易被拦截（因为评分 rationale 引用了有害内容）。

---

## 12. 对话级评分（Conversation Scoring）

### 12.1 核心概念

某些信号只在跨轮次中显现 — 说服、渐进人格突破、升级。`create_conversation_scorer()` 包装任何 `TrueFalseScorer` 或 `FloatScaleScorer`，使其评分连接的整个对话而非单条消息。

### 12.2 工作原理

```
create_conversation_scorer(scorer=base_scorer)
    │
    ├── 动态创建同时继承 ConversationScorer + base_scorer 基类的子类
    ├── 返回的评分器同时是 ConversationScorer 和 TrueFalseScorer/FloatScaleScorer 的实例
    └── 评分时：
        1. 从任何一条消息的 conversation_id 拉取完整对话历史
        2. 将对话拼接为单个文本
        3. 交给包装的评分器评分
```

### 12.3 典型用例

- **多轮渐进攻击（CrescendoAttack）**：评估整体渐进效果而非单轮
- **心理社会危害**：跨多轮逐渐显现的危害
- **说服/欺骗检测**：需要完整对话上下文
- **行为变化测量**：用 `BEHAVIOR_CHANGE_SCALE` 包装 `SelfAskLikertScorer`

---

## 13. 多模态评分器（Multimodal Scorers）

### 13.1 架构

```
┌─────────────────────────────────────────────────────────┐
│                 多模态评分架构                           │
│                                                         │
│  ┌──────────────────┐                                   │
│  │ audio_path 响应   │                                   │
│  └────────┬─────────┘                                   │
│           │                                             │
│           ▼                                             │
│  ┌──────────────────┐     ┌──────────────────────┐     │
│  │ Azure Speech     │────▶│ 转写文本             │     │
│  │ -to-Text 转写    │     │                      │     │
│  └──────────────────┘     └──────────┬───────────┘     │
│                                      │                  │
│                                      ▼                  │
│                           ┌──────────────────────┐     │
│                           │ 包装的文本评分器       │     │
│                           │ (TrueFalse/FloatScale)│     │
│                           └──────────────────────┘     │
│                                                         │
│  ┌──────────────────┐                                   │
│  │ video_path 响应   │                                   │
│  └────────┬─────────┘                                   │
│           │                                             │
│     ┌─────┴─────┐                                       │
│     ▼           ▼                                       │
│  帧采样      音频提取                                   │
│     │           │                                       │
│     ▼           ▼                                       │
│  图像评分    音频评分                                   │
│  (per frame) (转写+评分)                                │
│     │           │                                       │
│     └─────┬─────┘                                       │
│           │                                             │
│           ▼                                             │
│  聚合（MAX / AND 组合）                                 │
└─────────────────────────────────────────────────────────┘
```

### 13.2 评分器类型

| 类型 | TrueFalse 版本 | FloatScale 版本 |
|:--|:--|:--|
| 音频 | `AudioTrueFalseScorer` | `AudioFloatScaleScorer` |
| 视频 | `VideoTrueFalseScorer` | `VideoFloatScaleScorer` |

### 13.3 视频聚合策略

- `VideoTrueFalseScorer`：任一帧匹配 → True；可选音频评分器 AND 组合（视觉和转写都必须匹配）
- `VideoFloatScaleScorer`：各类别帧分数聚合（默认 MAX）；可选音频评分器折叠

---

## 14. 批量评分（Batch Scoring）

### 14.1 核心概念

`BatchScorer` 评分 Memory 中已存储的响应 — 例如攻击发送的所有内容。它并行运行，可按对话、prompt id、memory 标签、时间戳等选择响应。

### 14.2 API

```python
batch_scorer = BatchScorer()
scores = await batch_scorer.score_responses_by_filters_async(
    scorer=scorer,
    prompt_ids=prompt_ids,
)
```

### 14.3 选择维度

| 过滤维度 | 说明 |
|:--|:--|
| `prompt_ids` | 按 prompt ID 列表 |
| `conversation_id` | 按对话 ID |
| `memory_labels` | 按 memory 标签 |
| `timestamps` | 按时间范围 |
| `role` | 按角色 |

`BatchScorer` 适用于任何评分器；它内部处理并行执行和并发控制。

---

## 15. Scorer Metrics 评估指标体系

### 15.1 评分器身份（Scorer Identity）

每个评分器有一个唯一的身份哈希 `eval_hash`，从其完整配置计算：

- Scorer 类型（如 `SelfAskRefusalScorer`）
- 系统和用户提示模板
- 目标模型信息（模型名称）
- 温度和其他生成参数
- 任何评分器特定配置

**关键含义**：更改任何这些值会创建新的评分器身份。指标按此身份哈希存储和检索。

### 15.2 Objective 指标（TrueFalse 评分器）

Objective 评分器产生 true/false 输出，通过标准分类指标评估：

| 指标 | 说明 |
|:--|:--|
| **Accuracy** | 预测与人工标签匹配的比例 |
| **Precision** | 所有 "True" 预测中，多少是正确的（高精度 = 少误报） |
| **Recall** | 所有实际 "True" 中，多少被捕获（高召回 = 少漏报） |
| **F1 Score** | 精确率和召回率的调和平均 |
| **Accuracy Standard Error** | 准确率估计的统计不确定性 |

**指标选择指南**：
- 误报代价高（如将安全内容标记为有害）→ 优先 Precision
- 漏报代价高（如遗漏真实越狱）→ 优先 Recall
- 平衡场景 → 使用 F1 Score

### 15.3 Harm 指标（FloatScale 评分器）

Harm 评分器产生浮点分数（0.0–1.0）表示严重度：

| 指标 | 说明 |
|:--|:--|
| **Mean Absolute Error (MAE)** | 模型与人工分数的平均绝对差 |
| **MAE Standard Error** | MAE 估计的不确定性 |
| **t-statistic** | 单样本 t 检验。正 = 模型评分高于人类；负 = 低于 |
| **p-value** | 若小（如 < 0.05），差异统计显著 |
| **Krippendorff's α (combined)** | 人类与模型之间的总体一致性（-1.0–1.0） |
| **Krippendorff's α (humans)** | 人工评估者之间的一致性（标签质量基线） |
| **Krippendorff's α (model)** | 多次模型评分试验的一致性（模型一致性） |

**Krippendorff's α 解读**：
- 1.0 = 完美一致
- 0.8+ = 强一致
- 0.6–0.8 = 中等一致
- < 0.6 = 弱一致

### 15.4 指标检索

当评分器指标通过 `evaluate_async()` 计算后，可保存到 JSONL 注册表文件，无需重新运行评估即可检索：

```python
# 检索缓存的指标
cached_metrics = scorer.get_scorer_metrics()

# 加载所有配置并比较
all_scorers = get_all_objective_metrics()  # 返回 ScorerMetricsWithIdentity
sorted_by_f1 = sorted(all_scorers, key=lambda x: x.metrics.f1_score, reverse=True)
```

### 15.5 指标创建

通过 `ScorerEvaluator` 框架创建新指标：

```python
evaluator = ScorerEvaluator.from_scorer(scorer)
metrics = await evaluator.run_evaluation_async(
    dataset_files=dataset_files,
    num_scorer_trials=3,
    update_registry_behavior=RegistryUpdateBehavior.SKIP_IF_EXISTS,
)
```

### 15.6 RegistryUpdateBehavior 缓存策略

| 策略 | 行为 |
|:--|:--|
| `SKIP_IF_EXISTS`（默认） | 检查注册表已有结果，有则返回缓存 |
| `ALWAYS_UPDATE` | 始终重新评估并覆盖 |
| `NEVER_UPDATE` | 始终重新评估但不写入注册表 |

### 15.7 HumanLabeledDataset

评估数据集使用人工标注数据：

| 类型 | 说明 |
|:--|:--|
| `ObjectiveHumanLabeledEntry` | TrueFalse 评分器评估（text + label: bool + objective） |
| `HarmHumanLabeledEntry` | FloatScale 评分器评估（text + label: float + harm_category + harm_definition） |

---

## 16. 评分器身份与注册表（Identity & Registry）

### 16.1 ScorerIdentifier

每个评分器有一个 `ScorerIdentifier`，包含：
- `class_name` — 评分器类名
- `params` — 所有配置参数（系统提示、阈值、子评分器等）
- `hash` — 从上述内容计算的唯一哈希
- `children` — 复合评分器的子评分器标识

### 16.2 get_scorer_info()

`get_scorer_info()` 静态方法在不实例化评分器的情况下检查每个评分器类，返回：
- `name` — 评分器名称
- `score_type` — 返回类型（true_false / float_scale）
- `uses_llm` — 是否使用 LLM

### 16.3 ScorerRegistry

PyRIT 1.0.1 使用 `ScorerRegistry` 管理评分器：
- 自动发现 `pyrit.score` 包中的所有 Scorer 子类
- `register_class()` 注册类（而非实例）
- `create_instance(class_name)` 按类名创建实例
- `get_class_names()` 列出所有已注册类名

---

## 17. 攻击中的三层评分架构

### 17.1 AttackScoringConfig

PyRIT 1.0.1 引入三层评分架构：

| 层 | 字段 | 类型 | 说明 |
|:--|:--|:--|:--|
| **Objective** | `objective_scorer` | `TrueFalseScorer` | 判断攻击目标是否达成 |
| **Refusal** | `refusal_scorer` | `TrueFalseScorer \| None` | 检测目标是否拒绝响应 |
| **Auxiliary** | `auxiliary_scorers` | `list[Scorer] \| None` | 辅助评分（注入检测、泄露检测等） |

### 17.2 评分流程

```
目标响应
    │
    ├──▶ objective_scorer  ──▶ Score (True/False: 目标是否达成)
    │
    ├──▶ refusal_scorer    ──▶ Score (True/False: 目标是否拒绝)
    │         │
    │         └── True → 攻击标记为 "目标拒绝"（不同于 "攻击失败"）
    │
    └──▶ auxiliary_scorers ──▶ [Score, Score, ...] (辅助信号)
```

### 17.3 use_score_as_feedback

| 参数 | 默认值 | 说明 |
|:--|:--|:--|
| `use_score_as_feedback` | `True` | 评分结果作为多轮攻击迭代反馈 |

启用后：
- 多轮攻击（RedTeamingAttack/CrescendoAttack/PAIRAttack/TAPAttack）动态利用评分结果优化后续轮次
- 评分结果作为对抗 LLM 的 context，形成 "Attack → Score → Adapt → Attack" 闭环
- 成功率高 20–40%

### 17.4 TAPAttackScoringConfig

TAP/PAIR/TreeOfAttacksWithPruning 攻击要求专用评分配置：
- `objective_scorer` 必须是 `FloatScaleThresholdScorer`（非 `TrueFalseScorer`）
- 内部使用 `SelfAskScaleScorer.from_scale()` 加载 `TASK_ACHIEVED_SCALE`
- 阈值参数控制成功判定：分数 ≥ threshold 视为成功

### 17.5 role_filter 与 skip_on_error_result

`Scorer.score_response_async()` 静态方法暴露两个过滤参数：

| 参数 | 默认值 | 说明 |
|:--|:--|:--|
| `role_filter` | `"assistant"` | 只评分指定角色的响应 |
| `skip_on_error_result` | `True` | 跳过 error 响应 |

特殊值：
- `role_filter="assistant"` — 只评分真实 assistant 响应
- `role_filter="simulated_assistant"` — 只评分模拟响应
- `role_filter=None` — 评分所有角色

---

## 18. AI-300 考试知识映射

### 18.1 评分器选择指南

| 攻击场景 | 推荐 Scorer | 类型 |
|:--|:--|:--|
| LLM 越狱 | `SelfAskTrueFalseScorer` (TASK_ACHIEVED) | true_false |
| 拒绝检测 | `SelfAskRefusalScorer` | true_false |
| 提示注入（直接） | `SelfAskTrueFalseScorer` (PROMPT_INJECTION) | true_false |
| 提示注入（间接/XPIA） | `SubStringScorer` + `StaticPromptInjectionScorer` | true_false |
| 数据泄露 | `CredentialLeakScorer` + `SelfAskTrueFalseScorer` | true_false |
| Web 注入 | `XSSOutputScorer` + `SQLInjectionOutputScorer` + ... | true_false |
| 有害内容 | `SelfAskLikertScorer` (HARM_SCALE) | float_scale |
| 虚假信息 | `SelfAskLikertScorer` (MISINFORMATION_SCALE) | float_scale |
| 不安全代码 | `InsecureCodeScorer` | float_scale |
| 问答准确性 | `SelfAskQuestionAnswerScorer` | true_false |
| 行为变化 | `SelfAskLikertScorer` (BEHAVIOR_CHANGE_SCALE) + `ConversationScorer` | float_scale |
| Agent 工具注入 | `SubStringScorer` + `StaticPromptInjectionScorer` | true_false |
| RAG 知识库投毒 | `SubStringScorer` + `SelfAskTrueFalseScorer` | true_false |

### 18.2 评分策略配置

| 场景 | `score_blocked_content` | `raise_if_scorer_blocks` |
|:--|:--|:--|
| 红队攻击执行 | `True` | `False` |
| 正式评估 | `False` | `True` |
| CI/CD 自动化 | `True` | `False` |

### 18.3 OWASP 映射

| OWASP 类别 | 对应 Scorer |
|:--|:--|
| LLM01: Prompt Injection | `StaticPromptInjectionScorer`, `SelfAskTrueFalseScorer` (PROMPT_INJECTION) |
| LLM02: Insecure Output | `XSSOutputScorer`, `SQLInjectionOutputScorer`, `ShellCommandOutputScorer`, ... |
| LLM06: Sensitive Info | `CredentialLeakScorer`, `SelfAskTrueFalseScorer` |
| LLM08: Vector Weaknesses | `SubStringScorer`, `SelfAskTrueFalseScorer` (XPIA 检测) |

---

## 19. Scoring 设计哲学：何时需要新的 Scorer 类

### 19.1 核心原则

> 大多数评分器行为来自其 *配置*，而非新代码。在编写新的 Scorer 类之前，先问自己：评分逻辑是否真的是新的 — 还是用不同的配置组合现有评分器就够了？

### 19.2 决策树

```
需要新的 Scorer 类吗？

├── 是否是简单的模式匹配（正则/子字符串）？
│   └── YES → 使用 RegexScorer / SubStringScorer，不需要新类
│
├── 是否是标准 yes/no 判断？
│   └── YES → 使用 SelfAskTrueFalseScorer + 内置/自定义问题，不需要新类
│
├── 是否是非标准数值量表？
│   └── YES → 使用 SelfAskScaleScorer + 自定义 NumericRubric，不需要新类
│
├── 是否需要完全自定义的系统提示和 JSON schema？
│   └── YES → 使用 SelfAskGeneralTrueFalseScorer / SelfAskGeneralFloatScaleScorer
│
├── 是否需要组合多个评分器的结果？
│   └── YES → 使用 TrueFalseCompositeScorer / TrueFalseInverterScorer / FloatScaleThresholdScorer
│
├── 是否需要评估整个对话而非单条消息？
│   └── YES → 使用 create_conversation_scorer() 包装
│
└── 是否需要全新的检测逻辑（非文本匹配、非 LLM 推理）？
    └── YES → 需要新的 Scorer 类
        └── 示例: AzureContentFilterScorer（调用外部 API）、PlagiarismScorer（文本相似度算法）
```

### 19.3 新类的持久价值

对于评分器而言，新类的持久价值在于：
1. **全新检测逻辑** — 不能通过正则、子字符串或 LLM 推理实现的检测（如外部 API 集成、文本相似度算法）
2. **领域专用检测器** — RegexScorer 子类提供预设模式集（如 `CredentialLeakScorer`）
3. **多模态桥接** — 将媒体响应转写/采样后委托给文本/图像评分器

### 19.4 配置优先原则

| 情况 | 正确做法 |
|:--|:--|
| 简单模式匹配 | `RegexScorer` / `SubStringScorer` |
| Yes/No 判断 | `SelfAskTrueFalseScorer` + 问题模板 |
| 数值量表 | `SelfAskScaleScorer` + `NumericRubric` |
| 完全自定义 | `SelfAskGeneral*Scorer` |
| 多评分器组合 | `TrueFalseCompositeScorer` / `TrueFalseInverterScorer` |
| 浮点→布尔 | `FloatScaleThresholdScorer` |
| 对话级 | `create_conversation_scorer()` |

---

## 附录：官方文档引用

| 文档页面 | URL |
|:--|:--|
| Scoring 总览 | https://microsoft.github.io/PyRIT/1.0.0/code/scoring/scoring/ |
| True/False Scorers | https://microsoft.github.io/PyRIT/1.0.0/code/scoring/true-false-scorers/ |
| Float-Scale Scorers | https://microsoft.github.io/PyRIT/1.0.0/code/scoring/float-scale-scorers/ |
| Combining & Stacking Scorers | https://microsoft.github.io/PyRIT/1.0.0/code/scoring/combining-scorers/ |
| Scorer Metrics | https://microsoft.github.io/PyRIT/1.0.0/code/scoring/scorer-metrics/ |
