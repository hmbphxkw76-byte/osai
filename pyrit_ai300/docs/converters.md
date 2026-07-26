# Converter 子系统架构文档

> 对齐 `pyrit.converter` — PyRIT 1.0.0 完整 Converter 转换架构  
> 文档版本：v1.0 | 更新日期：2026-07-26

## 1. 架构概览

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      CONVERTER 子系统（完整）                                  │
│                                                                             │
│  核心不变量 🟢：prompt → convert_async() → ConverterResult                    │
│  核心约束 🟢：SUPPORTED_INPUT_TYPES × SUPPORTED_OUTPUT_TYPES                  │
│  链式设计 🔵：模态兼容链式串联 + SelectiveTextConverter 组合包装                │
│                                                                             │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │  Converter 注册层 🟢                                                    │  │
│  │  "统一映射表 + 反射检测 + PyRIT Registry 集成"                          │  │
│  │  → CONVERTER_CLASS_MAP (snake_case + 类名双键)                         │  │
│  │  → _requires_converter_target (反射检测)                                │  │
│  │  → register_converters_to_pyrit_registry()                             │  │
│  └────────────────────────────────┬──────────────────────────────────────┘  │
│  ┌────────────────────────────────┴──────────────────────────────────────┐  │
│  │  模态分类层 🟢                                                        │  │
│  │  "按转换方向分组的 frozenset 常量"                                     │  │
│  │  → TEXT_TO_TEXT_CONVERTERS / TEXT_TO_FILE_CONVERTERS                  │  │
│  │  → IMAGE_CONVERTERS / AUDIO_CONVERTERS / VIDEO_CONVERTERS              │  │
│  │  → MULTIMODAL_CONVERTERS                                              │  │
│  └────────────────────────────────┬──────────────────────────────────────┘  │
│  ┌────────────────────────────────┴──────────────────────────────────────┐  │
│  │  配置构建层 🟢                                                        │  │
│  │  "Converter 链配置工厂"                                               │  │
│  │  → create_converter_instance (反射 + @apply_defaults)                 │  │
│  │  → create_converter_chain_config (模态验证 + 链构建)                  │  │
│  │  → create_attack_converter_config (request/response 双链)             │  │
│  │  → load_preset_converter_chain (YAML 配置加载)                        │  │
│  └────────────────────────────────┬──────────────────────────────────────┘  │
│  ┌────────────────────────────────┴──────────────────────────────────────┐  │
│  │  Selective Converting 层 🟢                                           │  │
│  │  "选择性文本转换组合包装器"                                            │  │
│  │  → SELECTION_STRATEGY_MAP (13 种策略)                                 │  │
│  │  → create_selective_text_converter (组合包装器工厂)                    │  │
│  └────────────────────────────────┬──────────────────────────────────────┘  │
│  ┌────────────────────────────────┴──────────────────────────────────────┐  │
│  │  预置链工厂层 🟢                                                      │  │
│  │  "常用 Converter 链快捷方法"                                          │  │
│  │  → create_stealth_evasion_chain / create_encoding_bypass_chain        │  │
│  │  → create_llm_assisted_chain / create_unicode_attack_chain            │  │
│  │  → create_policy_puppetry_chain / create_decomposition_chain          │  │
│  │  → create_noise_chain / create_noise_case_chain                     │  │
│  │  → create_task_framing_chain / create_selective_encoding_chain      │  │
│  │  → create_multimodal_text_to_image_chain                             │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                                                                             │
│  横切配置（攻击层共享）🟢：                                                    │
│  ┌──────────────────┐                                                        │
│  │AttackConverter   │ ← request_converters / response_converters          │
│  │Config            │                                                        │
│  └──────────────────┘                                                        │
│  ┌──────────────────┐                                                        │
│  │ConverterConfigu- │ ← converters / indexes_to_apply /                    │
│  │ration            │   prompt_data_types_to_apply                         │  │
│  └──────────────────┘                                                        │
│                                                                             │
│  与 Executor 衔接点：                                                         │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐        │
│  │SingleTurnExecutor│  │MultiTurnExecutor  │  │XPIAWorkflowWrapper│       │
│  │load_preset_chain │  │load_preset_chain  │  │converter_config  │        │
│  └──────────────────┘  └──────────────────┘  └──────────────────┘        │
└─────────────────────────────────────────────────────────────────────────────┘
```

## 2. 目录结构

```
src/converters/                                    ← 对齐 pyrit.converter
├── __init__.py                                   ← 顶层统一导出（52+ 公共 API）
└── converter_registry.py                          ← Converter 注册 + 链构建 + 预置链

配置文件：
src/core/defaults/payload_strategy_matrix.yaml    ← Converter 链预置配置 + Scenario 映射
```

> **注意**：项目不重新实现 PyRIT Converter 类，而是通过 `converter_registry.py` 提供 **注册、配置、链构建、预置链** 等上层服务，委托原生 PyRIT Converter 类执行实际转换。

## 3. 各层详细设计

### 3.1 Converter 注册层

| 模块 | 对齐 PyRIT 原生 | 功能 |
|:--|:--|:--|
| `CONVERTER_CLASS_MAP` | `pyrit.converter.__init__.__all__` | snake_case + 类名双键映射表（100+ 条目） |
| `_build_converter_map()` | — | 自动添加类名别名（如 "Base64Converter" → Base64Converter） |
| `_requires_converter_target()` | `@apply_defaults` | 反射检测构造函数是否接受 `converter_target` 参数 |
| `_query_global_default_target()` | `GlobalDefaultValues` | 从 PyRIT 全局注册表查询 converter_target |
| `register_converters_to_pyrit_registry()` | `ConverterRegistry` | 将非 LLM 辅助 Converter 注册到 PyRIT Registry |
| `get_converter_from_pyrit_registry()` | `ConverterRegistry.create_instance()` | 从 Registry 获取 Converter 实例 |
| `list_registered_converters()` | `ConverterRegistry.get_class_names()` | 列出已注册 Converter |

**关键设计**：
- snake_case 和类名双键映射（如 `"base64"` 和 `"Base64Converter"` 都映射到 `Base64Converter`）
- 反射检测 `converter_target` 需求，结果缓存避免重复反射
- 跳过 LLM 辅助 Converter 的注册（需要 `converter_target` 参数，Registry 无法自动创建）
- 使用延迟导入避免循环依赖（`_ensure_registry_imported()`）

### 3.2 模态分类层

| 常量 | 类型 | 包含 Converter |
|:--|:--|:--|
| `TEXT_TO_TEXT_CONVERTERS` | frozenset | 编码 + Unicode + 语义 + 格式 + LLM 辅助 + 特殊类（~60+ 条目） |
| `TEXT_TO_FILE_CONVERTERS` | frozenset | pdf, word_doc, qr_code, add_image_text |
| `IMAGE_CONVERTERS` | frozenset | text→image + image→image Converter |
| `AUDIO_CONVERTERS` | frozenset | text→audio + audio→text + audio→audio |
| `VIDEO_CONVERTERS` | frozenset | add_image_video |
| `MULTIMODAL_CONVERTERS` | frozenset | IMAGE \| AUDIO \| VIDEO |

**模态感知工具函数**：

| 函数 | 功能 |
|:--|:--|
| `get_all_converter_modalities()` | 封装 PyRIT `get_converter_modalities()` |
| `get_converter_supported_types(name)` | 获取指定 Converter 的输入/输出模态 |
| `validate_converter_chain_modality(names)` | 验证链中相邻 Converter 的模态兼容性 |
| `filter_converters_by_input_type(converters, input_type)` | 按输入模态过滤 |

### 3.3 配置构建层

**`create_converter_instance(name, converter_target, **kwargs)`**：
- 反射检测是否需要 `converter_target`
- 优先使用显式传入的 `converter_target`
- 尝试从 PyRIT 全局注册表获取
- 让 PyRIT `@apply_defaults` 处理最终缺失情况

**`create_converter_chain_config(names, params, converter_target, ...)`**：
- 模态感知链路验证（可配置 `validate_modality`）
- 逐个创建 Converter 实例
- 支持 `indexes_to_apply` / `prompt_data_types_to_apply` 高级字段
- 返回 `ConverterConfiguration` 实例

**`create_attack_converter_config(names, params, apply_to_request, apply_to_response, ...)`**：
- 构建 `AttackConverterConfig`（request_converters / response_converters）
- 双链模式：request 和 response 各创建独立链
- 单链模式：仅 request 或仅 response

**`load_preset_converter_chain(chain_name, converter_target)`**：
- 从 YAML 配置文件加载预置链
- 支持标准 Converter 名称和 SelectiveTextConverter 组合字典
- 自动处理预构建的 SelectiveTextConverter 实例
- 模态验证

### 3.4 Selective Converting 层

**`SELECTION_STRATEGY_MAP`**：13 种选择策略映射

| 策略类别 | 策略名称 |
|:--|:--|
| 字符级 | index / regex / keyword / position / proportion / range |
| 词级 | all_words / word_index / word_keyword / word_proportion / word_regex / word_position |
| Token | token |

**`create_selective_text_converter(sub_converter_name, selection_strategy_name, ...)`**：
- 创建 `SelectiveTextConverter` 组合包装器
- 支持 `preserve_tokens` 链式选择转换
- 自定义 `start_token` / `end_token` / `word_separator`
- 子 Converter 参数和策略参数分离传入

### 3.5 预置链工厂层

| 快捷方法 | 链组成 | 模态 |
|:--|:--|:--|
| `create_stealth_evasion_chain()` | UnicodeConfusable → Base64 → SuffixAppend | text→text→text→text |
| `create_encoding_bypass_chain()` | Base64 → ROT13 → Caesar | text→text→text→text |
| `create_format_injection_chain()` | AsciiArt | text→text |
| `create_llm_assisted_chain()` | Persuasion → Tone → Translation | text→text→text→text |
| `create_unicode_attack_chain()` | UnicodeConfusable → Bidi → ZeroWidth | text→text→text→text |
| `create_multi_encoding_chain()` | Base64 → ROT13 → Caesar → Atbash | text→text→text→text→text |
| `create_leetspeak_chain()` | Leetspeak → Flip → RepeatToken | text→text→text→text |
| `create_policy_puppetry_chain()` | PolicyPuppetry | text→text |
| `create_decomposition_chain()` | Decomposition | text→text |
| `create_noise_chain()` | Noise | text→text |
| `create_noise_case_chain()` | Noise → RandomCapitalLetters → Base64 | text→text→text→text |
| `create_task_framing_chain()` | TaskFraming → Persuasion | text→text→text |
| `create_selective_encoding_chain()` | SelectiveTextConverter(Base64) | text→text |
| `create_multimodal_text_to_image_chain()` | QRCode / AddImageText / ImagePromptStyle | text→image_path |

## 4. 与 Executor 子系统的衔接

```
Converter 子系统                           Executor 子系统
═════════════════                          ═════════════════

payload_strategy_matrix.yaml               SingleTurnExecutor
  converter_chains:                           load_preset_converter_chain()
    stealth_evasion:                          ↓
      - UnicodeConfusableConverter            AttackConverterConfig
      - Base64Converter                       ↓
      - SuffixAppendConverter               create_attack_instance()
    ...                                     ↓
        │                                  PromptSendingAttack
        ▼                                  (attack_converter_config=...)
  load_preset_converter_chain()             ↓
        │                                  execute_attack_from_seed_groups_async()
        ▼                                  ↓
  AttackConverterConfig                     目标系统接收转换后 prompt
  (request_converters=[chain])
        │
        ├──→ SingleTurnExecutor.execute()
        │      converter_chain_override → load_preset_converter_chain()
        │
        ├──→ MultiTurnExecutor.execute()
        │      converter_chain_override → load_preset_converter_chain()
        │
        └──→ XPIAWorkflowWrapper
               converter_config → 原生 XPIAWorkflow
```

**关键衔接点**：
1. **`load_preset_converter_chain(chain_name)`**：Executor 从 YAML 配置加载预置链
2. **`converter_target=judge_target`**：Executor 将 judge_target 作为 LLM 辅助 Converter 的 converter_target
3. **`AttackConverterConfig`**：构建 `AttackConverterConfig` 传入 Attack 构造函数
4. **`converter_chain_override`**：Executor 支持运行时覆盖 Converter 链（升级重试时使用）

## 5. 配置说明

### 5.1 YAML 配置（payload_strategy_matrix.yaml）

```yaml
converter_chains:
  # 标准链（使用类名）
  stealth_evasion:
    converters:
      - UnicodeConfusableConverter
      - Base64Converter
      - SuffixAppendConverter
    params:
      SuffixAppendConverter:
        suffix: "!"

  # SelectiveTextConverter 组合链
  selective_example:
    converters:
      - selective: true
        sub_converter: base64
        strategy: word_proportion
        preserve_tokens: true
        params:
          strategy:
            proportion: 0.3

  # apply_to_response 链
  response_chain:
    converters:
      - DenylistConverter
    apply_to_response: true
```

### 5.2 Scenario 配置

```yaml
scenario_matrix:
  airt.jailbreak:
    converters:          # 推荐 Converter 列表
      - unicode_confusable
      - base64
      - rot13
      - persuasion
    converter_chains:    # 推荐 Converter 链
      - stealth_evasion
      - encoding_bypass
      - llm_assisted
```

### 5.3 OWASP 策略映射

```yaml
owasp_strategy_map:
  LLM01:
    recommended_converter_chains:
      - stealth_evasion
      - encoding_bypass
  ASI01:
    recommended_converter_chains:
      - stealth_evasion
      - encoding_bypass
```

## 6. 导入路径

```python
# 推荐导入方式
from src.converters import (
    create_attack_converter_config,
    load_preset_converter_chain,
    create_selective_text_converter,
    create_stealth_evasion_chain,
    # ...
)

# 也可从子模块直接导入
from src.converters.converter_registry import CONVERTER_CLASS_MAP
```

---

## 7. 差距分析

### 7.1 评估方法

逐项对比 PyRIT 1.0.0 官方 Converter 子系统与当前项目实现，按以下维度评分：

- 🟢 **已对齐**（90-100%）：功能完整，API 一致
- 🟡 **部分对齐**（50-89%）：核心功能存在，但有缺失或不一致
- 🔴 **重大差距**（<50%）：关键功能缺失

### 7.2 逐项评估

#### 7.2.1 Converter 注册与映射 🟢 95%

| 评估项 | PyRIT 原生 | 项目实现 | 状态 |
|:--|:--|:--|:--:|
| Converter 类导入覆盖 | 100+ 类 | 100+ 类（全量导入） | 🟢 |
| snake_case + 类名双键 | — | ✅ 双键映射 | 🟢 |
| PyRIT Registry 集成 | `ConverterRegistry` | `register_converters_to_pyrit_registry()` | 🟢 |
| Registry 实例创建 | `create_instance()` | `get_converter_from_pyrit_registry()` | 🟢 |
| Registry 列表查询 | `get_class_names()` | `list_registered_converters()` | 🟢 |
| 模态分类常量 | `get_converter_modalities()` | 6 个 frozenset + 4 个工具函数 | 🟢 |
| PolicyPuppetryTemplate 导出 | ✅ | ✅ | 🟢 |
| 延迟导入（Audio/TextJailbreak）| PEP 562 `__getattr__` | ❌ 直接导入（可能影响启动时间） | 🟡 |

**评价**：注册层对齐度极高。唯一差距是未使用 PEP 562 延迟导入机制（PyRIT 对 Audio Converter 和 TextJailbreakConverter 使用延迟导入避免 scipy/pandas 启动开销），项目直接全量导入。

#### 7.2.2 @apply_defaults 对齐 🟢 90%

| 评估项 | PyRIT 原生 | 项目实现 | 状态 |
|:--|:--|:--|:--:|
| `@apply_defaults` 装饰器 | 原生使用 | 反射模拟 | 🟡 |
| `converter_target` 反射检测 | `inspect.signature` | ✅ `_requires_converter_target()` | 🟢 |
| 全局默认值查询 | `GlobalDefaultValues` | ✅ `_query_global_default_target()` | 🟢 |
| 缓存优化 | — | ✅ `_target_requirement_cache` | 🟢 |
| `get_converters_requiring_target()` | — | ✅ 自动检测列表 | 🟢 |

**评价**：项目未直接使用 `@apply_defaults` 装饰器，而是通过反射机制模拟其行为。功能等价，但实现方式不同。`create_converter_instance()` 正确处理了 `converter_target` 优先级链（显式 > 全局注册表 > PyRIT 处理）。

#### 7.2.3 Converter 链构建 🟢 95%

| 评估项 | PyRIT 原生 | 项目实现 | 状态 |
|:--|:--|:--|:--:|
| `ConverterConfiguration` 使用 | 原生类 | ✅ 从 `pyrit.prompt_normalizer` 导入 | 🟢 |
| `AttackConverterConfig` 使用 | 原生类 | ✅ 从 `pyrit.executor.attack` 导入 | 🟢 |
| 模态链路验证 | `get_converter_modalities()` | ✅ `validate_converter_chain_modality()` | 🟢 |
| `indexes_to_apply` 支持 | 原生字段 | ✅ 透传 | 🟢 |
| `prompt_data_types_to_apply` 支持 | 原生字段 | ✅ 透传 | 🟢 |
| request/response 双链 | `AttackConverterConfig` | ✅ `create_attack_converter_config()` | 🟢 |
| `PrependedConversationConfig` | 原生类 | ✅ `create_prepended_conversation_config()` | 🟢 |

**评价**：链构建层完全对齐。模态验证是项目自研增强（PyRIT 不提供链路验证工具函数），提供运行时安全保障。

#### 7.2.4 Selective Converting 🟢 95%

| 评估项 | PyRIT 原生 | 项目实现 | 状态 |
|:--|:--|:--|:--:|
| `SelectiveTextConverter` | 原生类 | ✅ 直接导入使用 | 🟢 |
| 13 种选择策略 | 原生类 | ✅ 全量导入 | 🟢 |
| `SELECTION_STRATEGY_MAP` | — | ✅ snake_case 映射 | 🟢 |
| `create_selective_text_converter()` | — | ✅ 组合包装器工厂 | 🟢 |
| `preserve_tokens` 链式转换 | 原生机制 | ✅ 支持 | 🟢 |
| YAML 配置支持组合链 | — | ✅ 支持 selective 字典格式 | 🟢 |
| `WordLevelConverter` 验证 | 原生验证 | ❌ 未显式处理冲突检测 | 🟡 |

**评价**：Selective Converting 层高度对齐。`WordLevelConverter` 冲突检测是 PyRIT 原生 `SelectiveTextConverter.__init__` 中的验证逻辑，项目委托原生类处理，不需要额外实现。

#### 7.2.5 File Converters（PDF / WordDoc）🟡 75%

| 评估项 | PyRIT 原生 | 项目实现 | 状态 |
|:--|:--|:--|:--:|
| `PDFConverter` 导入 | ✅ | ✅ | 🟢 |
| `WordDocConverter` 导入 | ✅ | ✅ | 🟢 |
| PDF 模板生成模式 | `prompt_template` 参数 | ❌ 未在预置链中暴露 | 🟡 |
| PDF 修改现有 PDF | `existing_pdf` + `injection_items` | ❌ 未在预置链中暴露 | 🟡 |
| WordDoc 占位符注入 | `existing_docx` + `placeholder` | ❌ 未在预置链中暴露 | 🟡 |
| YAML 配置中 File Converter | — | ✅ format_injection 链含 QRCode/PDF | 🟢 |
| 模态验证（text→binary_path）| — | ✅ `TEXT_TO_FILE_CONVERTERS` | 🟢 |
| XPIA 文档投递集成 | `AzureBlobStorageTarget` | ✅ `XPIAWorkflowWrapper` | 🟢 |

**评价**：File Converter 的 *类* 已正确导入和注册，但 *高级功能*（PDF 注入、WordDoc 占位符替换）未在预置链和快捷方法中暴露。当前 `format_injection` 链中的 PDFConverter 只使用默认参数（直接文本→PDF），未利用修改现有 PDF 的注入能力。这对于 AI-300 考试中的 XPIA/RAG 攻击场景是一个功能性缺失。

#### 7.2.6 Text-to-Text Converters 🟢 95%

| 评估项 | PyRIT 原生 | 项目实现 | 状态 |
|:--|:--|:--|:--:|
| 编码类（11 种） | 全量 | ✅ 全量导入 | 🟢 |
| Unicode 类（15 种） | 全量 | ✅ 全量导入 | 🟢 |
| 语义类（16 种） | 全量 | ✅ 全量导入 | 🟢 |
| LLM 辅助类（9 种） | 全量 | ✅ 全量导入 | 🟢 |
| 特殊类（9 种） | 全量 | ✅ 全量导入 | 🟢 |
| PyRIT 1.0.0 新增 | Noise/Decomposition/PolicyPuppetry/RandomCapitalLetters/TaskFraming | ✅ 全量导入 | 🟢 |
| `TextJailbreakConverter` | 从 `TextJailBreak` 数据集加载 | ✅ 导入（延迟导入） | 🟢 |
| 预置链覆盖 | — | ✅ 14 种预置链 | 🟢 |
| YAML 配置使用类名 | — | ⚠️ YAML 使用类名而非 snake_case | 🟡 |

**评价**：Text-to-Text Converter 覆盖完整。YAML 配置中使用类名（如 `UnicodeConfusableConverter`）而非 snake_case（如 `unicode_confusable`），虽然双键映射支持两种格式，但与 Scenario 配置中的 snake_case 风格不一致，可能导致混淆。

#### 7.2.7 多模态 Converters（Image/Audio/Video）🟡 70%

| 评估项 | PyRIT 原生 | 项目实现 | 状态 |
|:--|:--|:--|:--:|
| Image Converter 导入 | 8 种 | ✅ 全量导入 | 🟢 |
| Audio Converter 导入 | 7 种 | ✅ 全量导入 | 🟢 |
| Video Converter 导入 | 1 种 | ✅ 全量导入 | 🟢 |
| 模态分类常量 | — | ✅ 3 个 frozenset | 🟢 |
| 多模态预置链 | — | ✅ `create_multimodal_text_to_image_chain()` | 🟢 |
| Audio Converter 延迟导入 | PEP 562 | ❌ 直接导入 | 🟡 |
| 多模态 Target 集成 | `OpenAIImageTarget` 等 | ❌ 未集成到攻击管道 | 🔴 |
| 模态反馈机制 | `TargetCapabilities` | ❌ 完全缺失 | 🔴 |

**评价**：多模态 Converter *类* 全量导入，但 *集成到攻击管道* 严重不足。当前攻击管道不支持多模态 Target（如 `OpenAIImageTarget`），也没有 `TargetCapabilities` 模态反馈机制。这意味着多模态 Converter 虽然可以创建，但无法在实际攻击中端到端使用。

#### 7.2.8 Converter 在 Executor 中的集成 🟢 90%

| 评估项 | PyRIT 原生 | 项目实现 | 状态 |
|:--|:--|:--|:--:|
| SingleTurnExecutor Converter 加载 | `attack_converter_config` | ✅ `load_preset_converter_chain()` | 🟢 |
| MultiTurnExecutor Converter 加载 | `attack_converter_config` | ✅ `load_preset_converter_chain()` | 🟢 |
| `converter_target` 传递 | `judge_target` | ✅ `converter_target=judge_target` | 🟢 |
| `converter_chain_override` | — | ✅ 运行时覆盖 | 🟢 |
| `PrependedConversationConfig` | 原生类 | ✅ `create_prepended_conversation_config()` | 🟢 |
| XPIA `converter_config` | `XPIAWorkflow` | ✅ `XPIAWorkflowWrapper` | 🟢 |
| 升级重试 Converter 切换 | — | ✅ `failure_type_routing` → `prefer_converter_chains` | 🟢 |
| `response_converters` 使用 | `AttackConverterConfig` | ⚠️ 仅 YAML `apply_to_response` 配置 | 🟡 |

**评价**：Converter 在 Executor 中的集成高度对齐。升级重试中的 Converter 切换是项目自研增强（按失败类型路由到不同 Converter 链）。`response_converters` 仅通过 YAML 的 `apply_to_response: true` 配置，缺少编程式灵活控制。

#### 7.2.9 ConverterConfiguration 高级字段 🟡 80%

| 评估项 | PyRIT 原生 | 项目实现 | 状态 |
|:--|:--|:--|:--:|
| `converters` 字段 | list[Converter] | ✅ | 🟢 |
| `indexes_to_apply` 字段 | list[int] \| None | ✅ 参数透传 | 🟢 |
| `prompt_data_types_to_apply` 字段 | list[PromptDataType] \| None | ✅ 参数透传 | 🟢 |
| `from_converters()` 类方法 | 每个 Converter 一个配置 | ❌ 未使用 | 🟡 |
| YAML 配置中使用高级字段 | — | ❌ 未在 YAML 中配置 | 🟡 |

**评价**：`ConverterConfiguration` 的高级字段在 API 层面已支持（参数透传），但在实际使用中（YAML 配置、预置链）未利用。`indexes_to_apply` 和 `prompt_data_types_to_apply` 允许精确控制 Converter 应用到哪些响应片段和哪些数据类型，这对于多模态对话场景非常重要。

#### 7.2.10 YAML 配置一致性 🟡 75%

| 评估项 | 状态 | 说明 |
|:--|:--:|:--|
| converter_chains 使用类名 | ⚠️ | YAML 中使用 `UnicodeConfusableConverter` 而非 `unicode_confusable` |
| scenario.converters 使用 snake_case | ⚠️ | Scenario 配置中使用 `unicode_confusable` |
| 双键映射兼容 | ✅ | `CONVERTER_CLASS_MAP` 支持两种格式 |
| 预置链工厂参数名 | ⚠️ | 部分 YAML 参数名与 PyRIT 构造函数参数名不一致（如 `persuasion_technique: "authority"` 应为 `"authority_endorsement"`） |
| SelectiveTextConverter YAML 格式 | ✅ | 支持 selective 字典格式 |
| 模态不兼容链 | ⚠️ | `format_injection` 链包含 AsciiArt + QRCode + PDF，但 QRCode 输出 image_path，PDF 输入需要 text |

**评价**：YAML 配置存在一致性问题。双键映射掩盖了命名风格不统一的问题。部分参数值不正确（如 `persuasion_technique: "authority"` 不是 PyRIT 支持的值，应为 `"authority_endorsement"`）。`format_injection` 链的模态不兼容问题已在 `create_format_injection_chain()` 中通过只取 `ascii_art` 规避，但 YAML 配置中的完整链仍可能产生模态验证警告。

---

## 8. 对齐度总结

### 8.1 总体评分

| 维度 | 对齐度 | 评分 |
|:--|:--:|:--:|
| Converter 注册与映射 | 95% | 🟢 |
| @apply_defaults 对齐 | 90% | 🟢 |
| Converter 链构建 | 95% | 🟢 |
| Selective Converting | 95% | 🟢 |
| File Converters | 75% | 🟡 |
| Text-to-Text Converters | 95% | 🟢 |
| 多模态 Converters | 70% | 🟡 |
| Executor 集成 | 90% | 🟢 |
| ConverterConfiguration 高级字段 | 80% | 🟡 |
| YAML 配置一致性 | 75% | 🟡 |
| **整体对齐度** | **~86%** | **🟢** |

### 8.2 强项（7/10）

1. **🟢 全量 Converter 导入**：100+ Converter 类全量导入，包括 PyRIT 1.0.0 新增的 5 种
2. **🟢 模态感知链路验证**：自研 `validate_converter_chain_modality()` 提供运行时模态兼容性检查
3. **🟢 @apply_defaults 反射模拟**：通过 `inspect.signature` 反射检测 + 全局注册表查询实现等价功能
4. **🟢 SelectiveTextConverter 完整支持**：13 种选择策略 + 组合包装器工厂 + YAML 配置
5. **🟢 PyRIT Registry 集成**：注册/查询/创建实例全流程对齐
6. **🟢 14 种预置链工厂**：覆盖编码/混淆/LLM辅助/PolicyPuppetry/Decomposition/Noise/TaskFraming/Selective 等全场景
7. **🟢 升级重试 Converter 切换**：按失败类型路由到不同 Converter 链（model_refusal → stealth_evasion）

### 8.3 重大差距（2 项）

1. **🔴 多模态攻击管道完全缺失（0%）**：
   - 无 `OpenAIImageTarget` / `AzureSpeechTarget` 等多模态 Target
   - 无 `TargetCapabilities` 模态反馈机制
   - 无多模态种子消息构建
   - 多模态 Converter 虽然导入但无法端到端使用
   - **影响**：AI-300 考试多模态攻击就绪度 ~10%

2. **🔴 File Converter 高级功能未暴露（50%）**：
   - `PDFConverter` 的 `existing_pdf` + `injection_items` 修改模式未在预置链中暴露
   - `WordDocConverter` 的 `existing_docx` + `placeholder` 占位符注入模式未暴露
   - 这两个功能是 XPIA/RAG 攻击中文档投递的关键手段
   - **影响**：AI-300 考试 XPIA/RAG 攻击的文档投递能力受限

### 8.4 中等差距（3 项）

1. **🟡 Audio Converter 延迟导入缺失**：PyRIT 使用 PEP 562 `__getattr__` 延迟导入 Audio Converter（避免 scipy 启动开销），项目直接全量导入

2. **🟡 YAML 配置一致性**：
   - converter_chains 使用类名，scenario.converters 使用 snake_case
   - 部分参数值不正确（如 `persuasion_technique: "authority"` 应为 `"authority_endorsement"`）
   - `format_injection` 链存在模态不兼容（QRCode 输出 image_path 无法链到 PDFConverter）

3. **🟡 ConverterConfiguration 高级字段未使用**：`indexes_to_apply` 和 `prompt_data_types_to_apply` 在 API 层面支持但实际配置中未使用，限制了多片段响应的精细控制

### 8.5 AI-300 考试就绪度

| 考试领域 | 就绪度 | 说明 |
|:--|:--:|:--|
| **编码绕过攻击** | 95% | 全量编码 Converter + 预置链 + 模态验证 |
| **Unicode 混淆攻击** | 95% | 全量 Unicode Converter + 预置链 |
| **LLM 辅助攻击** | 90% | Persuasion/Translation/Tone/Noise/Decomposition 全量，参数值需修正 |
| **选择性混淆** | 95% | SelectiveTextConverter 全量 + 13 种策略 |
| **文件投递攻击** | 50% | PDF/WordDoc 类已导入但高级注入功能未暴露 |
| **多模态攻击** | 10% | Converter 类已导入但攻击管道不支持多模态 Target |
| **XPIA/RAG 攻击** | 70% | XPIAWorkflow 集成但缺少文件注入和 RAG 检索模拟 |
| **GCG 后缀攻击** | 80% | SuffixAppendConverter 可用但无 AML 管道生成后缀 |

### 8.6 建议路线图

```
P0（高优先级 — AI-300 考试核心）:
  ├── File Converter 高级功能暴露
  │   ├── create_pdf_injection_chain(existing_pdf, injection_items)
  │   ├── create_worddoc_injection_chain(existing_docx, placeholder)
  │   └── YAML 配置支持 existing_pdf/existing_docx 参数
  └── YAML 参数值修正
      ├── persuasion_technique: "authority" → "authority_endorsement"
      └── 统一 converter_chains 命名风格（snake_case）

P1（中优先级 — 多模态攻击）:
  ├── 多模态 Target 集成
  │   ├── OpenAIImageTarget
  │   └── TargetCapabilities 模态反馈
  ├── Audio Converter 延迟导入（PEP 562）
  └── ConverterConfiguration 高级字段 YAML 配置

P2（低优先级 — 增强）:
  ├── response_converters 编程式控制
  ├── TextJailbreakConverter 数据集集成
  └── GCG AML 管道 → SuffixAppendConverter 集成
```

## 9. 验证结果

- **Converter 导入验证**：100+ Converter 类全量导入成功 ✓
- **模态分类验证**：6 个 frozenset 常量覆盖全部模态 ✓
- **预置链验证**：14 种预置链工厂方法可用 ✓
- **SelectiveTextConverter**：13 种选择策略 + 组合包装器 ✓
- **PyRIT Registry**：注册/查询/创建实例全流程 ✓
- **Executor 集成**：SingleTurn/MultiTurn/XPIA 三处衔接 ✓
