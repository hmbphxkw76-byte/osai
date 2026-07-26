# Targets 子系统：当前代码与 PyRIT 1.0.0 官方标准差距分析

> 评估日期：2026-07-26 | 评估基准：PyRIT 1.0.0 官方文档（21 个页面）
> 评估范围：`src/targets/` 全部模块 + 相关配置文件 | 评估方法：逐模块代码审查 + 官方文档对比
> ⚠️ 本文档仅分析，不包含代码修改

---

## 目录

1. [评估总览](#1-评估总览)
2. [OpenAI Chat Target 专项分析](#2-openai-chat-target-专项分析)
3. [OpenAI Responses Target 专项分析](#3-openai-responses-target-专项分析)
4. [HTTP Target 专项分析](#4-http-target-专项分析)
5. [Target Capabilities 体系专项分析](#5-target-capabilities-体系专项分析)
6. [MessageNormalizer 专项分析](#6-messagenormalizer-专项分析)
7. [多模态 Target 专项分析](#7-多模态-target-专项分析)
8. [其他 Target 类型分析](#8-其他-target-类型分析)
9. [Optional 文档分析（仅分析，不做差距评分）](#9-optional-文档分析仅分析不做差距评分)
10. [AI-300 考试就绪度评估](#10-ai-300-考试就绪度评估)
11. [差距优先级排序与建议路线图](#11-差距优先级排序与建议路线图)

---

## 1. 评估总览

### 1.1 评分矩阵

| 模块 | 官方对应 | 对齐度 | 评级 |
|:--|:--|:--:|:--:|
| TargetFactory 工厂类 | `pyrit.prompt_target` 全部 Target 类型 | 85% | 🟢 |
| OpenAIChatTarget 集成 | `OpenAIChatTarget` | 90% | 🟢 |
| OpenAIResponseTarget 集成 | `OpenAIResponseTarget` | 85% | 🟢 |
| LiteLLMChatTarget 集成 | `LiteLLMChatTarget` | 80% | 🟢 |
| HTTPTarget 集成 | `HTTPTarget` | 95% | 🟢 |
| HTTPXAPITarget 集成 | `HTTPXAPITarget` | 90% | 🟢 |
| Burp Target 构建器 | `HTTPTarget` + 回调函数 | 95% | 🟢 |
| PlaywrightTarget 集成 | `PlaywrightTarget` | 85% | 🟢 |
| WebSocketCopilotTarget 集成 | `WebSocketCopilotTarget` | 85% | 🟢 |
| PlaywrightCopilotTarget 集成 | `PlaywrightCopilotTarget` | 80% | 🟢 |
| AzureBlobStorageTarget 集成 | `AzureBlobStorageTarget` | 85% | 🟢 |
| PromptShieldTarget 集成 | `PromptShieldTarget` | 80% | 🟢 |
| OpenAIImageTarget 集成 | `OpenAIImageTarget` | **60%** | 🟡 |
| **TargetCapabilities 体系** | `TargetConfiguration` / `CapabilityHandlingPolicy` | **50%** | 🔴 |
| **MessageNormalizer** | `MessageNormalizer` 系列 | **0%** | 🔴 |
| **OpenAIVideoTarget** | `OpenAIVideoTarget` | **0%** | 🔴 |
| **OpenAITTSTarget** | `OpenAITTSTarget` | **0%** | 🔴 |
| **AzureMLChatTarget** | `AzureMLChatTarget` | **0%** | 🔴 |
| Rate Limiting | `max_requests_per_minute` | 100% | 🟢 |
| 认证体系（双重认证） | `get_azure_openai_auth` / `is_azure_openai_endpoint` | 95% | 🟢 |
| 能力探测 | `discover_target_capabilities_async` | 90% | 🟢 |
| 三级配置体系 | 显式参数 > 环境变量 > config.yaml | 90% | 🟢 |
| **整体对齐度** | | **~78%** | 🟡 |

### 1.2 评级标准

| 评级 | 范围 | 含义 |
|:--:|:--|:--|
| 🟢 | 85-100% | 对齐 L5 专家水平，可直接用于生产 |
| 🟡 | 60-84% | 基本对齐但存在功能缺口，需要增强 |
| 🔴 | <60% | 存在重大差距，影响核心功能 |

### 1.3 核心发现

**✅ 已对齐的强项（14/23 项 🟢）**：
- 使用原生 PyRIT Target 类（`OpenAIChatTarget`、`OpenAIResponseTarget`、`HTTPTarget` 等）
- `TargetFactory` 统一工厂模式，12 种 Target 类型全覆盖 AI-300 核心场景
- Side-effect-free 目标类型自动检测（GET-only 探测，含 `/v1/responses` 检测）
- 双重认证模式（`api_key` / `identity` / Entra ID 自动选择）
- `httpx_client_kwargs` 双路径构建（AsyncOpenAI 兼容拆分 + httpx-only 预配置 client）
- 推理参数全链路透传（temperature/top_p/seed/reasoning_effort 等）
- `extra_body_parameters` 透传
- `underlying_model` 标识（Azure 部署名 ≠ 模型名）
- Agentic Tool Calling 支持（`custom_functions` + `fail_on_missing_function`）
- 能力探测 `apply=True`（直接应用到 Target）
- 增强型 Burp Target 构建器（SSE 检测 + JSON 路径推断 + 多级回调）
- Rate Limiting 全 Target 类型支持
- 三级配置体系（显式参数 > 环境变量 > config.yaml）
- 向后兼容别名（`_LEGACY_TYPE_ALIASES`）

**🟡 需要改进的差距（3/23 项 🟡）**：
- `OpenAIImageTarget` 集成存在 bug（`detect_auth_mode` 调用方式错误）
- `LiteLLMChatTarget` 缺少 `reasoning_effort` / `reasoning_summary` 支持
- `PlaywrightCopilotTarget` 未导出 `CopilotType` 枚举到配置层

**🔴 重大差距（5/23 项 🔴）**：
- **TargetCapabilities 体系不完整**：缺少 `CapabilityHandlingPolicy`（ADAPT vs RAISE）、`ConversationNormalizationPipeline`、`CHAT_TARGET_REQUIREMENTS` 验证、`get_default_configuration` / `get_known_capabilities` 模型档案查询
- **MessageNormalizer 完全缺失**：无 `ChatMessageNormalizer`、`GenericSystemSquashNormalizer`、`TokenizerTemplateNormalizer`、`ConversationContextNormalizer`
- **OpenAIVideoTarget 完全缺失**：无法进行视频生成攻击测试
- **OpenAITTSTarget 完全缺失**：无法进行 TTS 攻击测试
- **AzureMLChatTarget 完全缺失**：无法测试 AML 托管模型

---

## 2. OpenAI Chat Target 专项分析

### 2.1 官方标准

`OpenAIChatTarget` 是 PyRIT 内部最常用的 chat target，支持 OpenAI 兼容模型（gpt-4o, gpt-4, DeepSeek, llama, phi-4, gpt-3.5）。

**核心能力**：
1. Chat Completions API（`/v1/chat/completions`）
2. JSON Output（通过 `prompt_metadata.response_format = "json"` + `json_schema`）
3. Multi-Modal Input（文本 + 图片组合）
4. LM Studio 支持（OpenAI 兼容本地服务器）
5. 环境变量配置（`OPENAI_CHAT_ENDPOINT` / `OPENAI_CHAT_MODEL` / `OPENAI_CHAT_KEY`）
6. Azure OpenAI + Entra ID 认证

### 2.2 项目实现

**文件**：`src/targets/target_factory.py` — `_create_openai_chat()`

| 维度 | 官方标准 | 项目实现 | 对齐 |
|:--|:--|:--|:--:|
| 原生类使用 | `OpenAIChatTarget` | ✅ 直接使用原生类 | ✅ |
| Chat Completions API | `/v1/chat/completions` | ✅ `_resolve_endpoint()` 自动添加 `/v1` | ✅ |
| JSON Output | `prompt_metadata.response_format` | ✅ 通过原生 Target 自动支持 | ✅ |
| Multi-Modal Input | `SeedPrompt(data_type="image_path")` | ✅ 通过原生 Target 自动支持 | ✅ |
| LM Studio 支持 | OpenAI 兼容端点 | ✅ `detect_target_type()` 检测 `/v1/models` | ✅ |
| 环境变量配置 | `OPENAI_CHAT_*` | ✅ `_apply_env_defaults()` + 显式参数 | ✅ |
| Azure Entra ID 认证 | `get_azure_openai_auth(endpoint)` | ✅ `detect_auth_mode()` 自动选择 | ✅ |
| 推理参数 | temperature/top_p/seed 等 | ✅ 7 个推理参数全透传 | ✅ |
| extra_body_parameters | 请求体注入 | ✅ 透传 | ✅ |
| httpx_client_kwargs | 超时/SSL/代理 | ✅ 双路径构建（`_build_openai_httpx_kwargs`） | ✅ |
| underlying_model | Azure 部署名标识 | ✅ 透传 | ✅ |
| max_requests_per_minute | 速率限制 | ✅ 透传 | ✅ |
| **custom_configuration** | 实例级能力覆盖 | ❌ TargetParams 无此字段 | 🔴 |
| **get_default_configuration** | 已知模型档案查询 | ❌ 未使用 | 🔴 |
| **developer_role** | o1/o3/gpt-4.1+ developer 角色 | ❌ 未支持 | 🟡 |

### 2.3 差距分析

**差距 1：`custom_configuration` 参数缺失（中等）**

官方允许通过 `custom_configuration` 传入 `TargetConfiguration` 来覆盖实例级能力声明：

```python
# 官方标准
restricted_target = OpenAIChatTarget(
    model_name="custom-model",
    endpoint="https://example.invalid/",
    api_key="sk-not-a-real-key",
    custom_configuration=restricted_config,  # ← 项目缺失
)
```

**影响**：无法为 OpenAI 兼容端点（如 vLLM 部署的自定义模型）声明非标准能力。当前依赖运行时 `discover_capabilities` 探测，但探测可能失败或不准确。

**差距 2：`get_default_configuration` / `get_known_capabilities` 未使用（低）**

官方提供已知模型档案查询：

```python
gpt_4o = OpenAIChatTarget.get_default_configuration(underlying_model="gpt-4o")
gpt_5 = OpenAIChatTarget.get_default_configuration(underlying_model="gpt-5")
# gpt-5 获得 supports_json_schema=True
```

**影响**：无法在创建 Target 前预知模型能力，可能导致攻击策略选择不当（如对不支持 JSON schema 的模型使用 JSON schema 攻击）。

**差距 3：`developer_role` 未支持（低）**

o1/o3/gpt-4.1+ 模型使用 "developer" 角色替代 "system" 角色。`ChatMessageNormalizer(use_developer_role=True)` 可处理此转换，但项目中 MessageNormalizer 完全缺失。

### 2.4 对齐度：90% 🟢

OpenAI Chat Target 集成是项目的最强项，核心功能完整对齐。主要差距是 `custom_configuration` 参数缺失，但不影响 AI-300 考试核心场景。

---

## 3. OpenAI Responses Target 专项分析

### 3.1 官方标准

`OpenAIResponseTarget` 使用 Responses API（`/v1/responses`），比 Chat Completions 更新，支持 reasoning、tool use、web search 等。

**核心能力**：
1. Reasoning Configuration（`reasoning_effort` / `reasoning_summary`）
2. JSON Generation（`response_format: "json_schema"`）
3. Tool Use with Custom Functions（Agentic Tool Calling 循环）
4. Built-in Web Search Tool
5. 多种输入类型（text, image, web search, file search, functions, reasoning, computer use）

### 3.2 项目实现

**文件**：`src/targets/target_factory.py` — `_create_openai_responses()`

| 维度 | 官方标准 | 项目实现 | 对齐 |
|:--|:--|:--|:--:|
| 原生类使用 | `OpenAIResponseTarget` | ✅ 直接使用原生类 | ✅ |
| Responses API 端点 | `/v1/responses` | ✅ `_resolve_endpoint()` + `detect_target_type()` 检测 405/401 | ✅ |
| `reasoning_effort` | minimal/low/medium/high | ✅ 透传 | ✅ |
| `reasoning_summary` | auto/concise/detailed | ✅ 透传 | ✅ |
| `max_output_tokens` | Responses API 专用 | ✅ 透传 | ✅ |
| `custom_functions` | Agentic Tool Calling | ✅ 透传 | ✅ |
| `fail_on_missing_function` | 工具调用缺失处理 | ✅ 透传 | ✅ |
| JSON Generation | `response_format: "json_schema"` | ✅ 通过原生 Target 自动支持 | ✅ |
| `extra_body_parameters` | 请求体注入 | ✅ 透传 | ✅ |
| `underlying_model` | 模型标识 | ✅ 透传 | ✅ |
| `httpx_client_kwargs` | 推理模型需要更长超时 | ✅ 双路径构建 | ✅ |
| `max_requests_per_minute` | 速率限制 | ✅ 透传 | ✅ |
| **内置 Web Search 工具** | `extra_body_parameters={"tools": [{"type": "web_search"}]}` | ⚠️ 可通过 `extra_body_parameters` 间接支持，但无专用配置 | 🟡 |
| **`custom_configuration`** | 实例级能力覆盖 | ❌ TargetParams 无此字段 | 🔴 |
| **`temperature`** | Responses API 也支持 | ✅ 透传 | ✅ |
| **`top_p`** | Responses API 也支持 | ✅ 透传 | ✅ |

### 3.3 差距分析

**差距 1：内置 Web Search 工具无专用配置（低）**

官方示例通过 `extra_body_parameters` 启用 web search：

```python
target = OpenAIResponseTarget(
    extra_body_parameters={"tools": [{"type": "web_search"}]},
)
```

项目可以通过 `TargetParams.extra_body_parameters` 间接实现，但没有专用配置字段或预设模板。**影响很小** — 用户可以通过 `extra_body_parameters` 手动配置。

**差距 2：`custom_configuration` 参数缺失（中等）**

同 OpenAI Chat Target 差距。对于 o1/o3 等推理模型，可能需要声明 `supports_system_prompt=False` 并设置 ADAPT 策略，当前无法做到。

### 3.4 对齐度：85% 🟢

Responses Target 集成质量很高，reasoning 和 tool calling 核心功能完整。主要差距是 `custom_configuration` 缺失。

---

## 4. HTTP Target 专项分析

### 4.1 官方标准

PyRIT 提供两种 HTTP Target：

1. **`HTTPTarget`** — 原始 HTTP 请求（从 Burp Suite 导出）
   - `http_request`：原始 HTTP 请求字符串
   - `prompt_regex_string`：提示词占位符（默认 `{PROMPT}`）
   - `callback_function`：响应解析回调
   - `use_tls`：是否使用 TLS

2. **`HTTPXAPITarget`** — 结构化 HTTP API
   - `http_url`、`method`、`headers`、`json_data`、`form_data`、`params`、`file_path`

**内置回调函数**：
- `get_http_target_json_response_callback_function(key)` — JSON 路径提取
- `get_http_target_regex_matching_callback_function(pattern, url)` — 正则匹配

### 4.2 项目实现

**文件**：
- `src/targets/target_factory.py` — `_create_http_api()` / `_create_http_raw()`
- `src/targets/burp_target.py` — 增强型 Burp Target 构建器

| 维度 | 官方标准 | 项目实现 | 对齐 |
|:--|:--|:--|:--:|
| `HTTPTarget` 原生类使用 | `HTTPTarget` | ✅ 直接使用 | ✅ |
| `HTTPXAPITarget` 原生类使用 | `HTTPXAPITarget` | ✅ 直接使用 | ✅ |
| 原始 HTTP 请求支持 | `http_request` 参数 | ✅ `raw_http_request` 字段 | ✅ |
| `{PROMPT}` 占位符 | `prompt_regex_string` | ✅ 默认 `{PROMPT}` | ✅ |
| JSON 回调函数 | `get_http_target_json_response_callback_function` | ✅ 使用原生函数 | ✅ |
| 正则回调函数 | `get_http_target_regex_matching_callback_function` | ✅ 使用原生函数 | ✅ |
| `use_tls` | TLS 控制 | ✅ 透传 | ✅ |
| `httpx_client_kwargs` | 超时/SSL/代理 | ✅ 透传 | ✅ |
| `max_requests_per_minute` | 速率限制 | ✅ 透传 | ✅ |
| `model_name` | Target 标识 | ✅ 透传 | ✅ |
| **SSE 流式响应检测** | 官方未提供 | ✅ 自研增强：`text/event-stream` → 正则回调 | 🟢+ |
| **JSON 路径自动推断** | 官方未提供 | ✅ 自研增强：请求体结构分析 → 响应路径推断 | 🟢+ |
| **API Key 自动注入** | 官方未提供 | ✅ 自研增强：Burp 请求自动注入 Authorization 头 | 🟢+ |
| **Content-Type 回调映射** | 官方未提供 | ✅ 自研增强：`_CONTENT_TYPE_CALLBACK_MAP` | 🟢+ |
| **多级回调回退策略** | 官方未提供 | ✅ 自研增强：JSON → SSE → HTML → XML → 无回调 | 🟢+ |
| **文件加载 Burp 请求** | 官方未提供 | ✅ `TARGET_RAW_REQUEST_FILE` 环境变量 | 🟢+ |
| **回调函数名称解析** | 官方未提供 | ✅ `_resolve_callback_function()` 支持 json_response/regex_match | 🟢+ |
| **`custom_configuration`** | 实例级能力覆盖 | ❌ 缺失 | 🔴 |

### 4.3 差距分析

**差距 1：`custom_configuration` 参数缺失（中等）**

`HTTPTarget` 的能力依赖部署配置。官方文档明确说明：

> 对于能力依赖部署的目标（HTTP 端点、Playwright UI、自定义后端），传入 `TargetConfiguration` 来覆盖。

当前项目无法为 HTTP 目标声明 `supports_multi_turn` 或 `supports_system_prompt`，只能依赖运行时探测。

**优势：Burp Target 构建器超出官方标准**

项目的 `burp_target.py` 实现了多项官方未提供的增强功能：
- SSE 流式响应自动检测和正则回调
- 请求体结构分析自动推断 JSON 响应路径
- API Key 自动注入到 Burp 请求
- Content-Type 到回调策略的映射
- 多级回退策略
- 从文件加载 Burp 请求

这些增强功能显著提升了 HTTP Target 的易用性，是项目的亮点。

### 4.4 对齐度：95% 🟢（含自研增强）

HTTP Target 集成是项目的最强项之一，原生功能完整对齐，且有显著的自研增强。

---

## 5. Target Capabilities 体系专项分析

### 5.1 官方标准

PyRIT 1.0.0 的 TargetCapabilities 体系是 Target 子系统的核心创新，包含：

1. **`TargetCapabilities`** — 不可变的能力声明（8 个标志 + 模态集合）
2. **`CapabilityHandlingPolicy`** — ADAPT vs RAISE 策略
3. **`ConversationNormalizationPipeline`** — 有序 normalizer 管道
4. **`TargetConfiguration`** — 组合上述三者
5. **`TargetRequirements`** — 消费者需求声明 + 验证
6. **`CHAT_TARGET_REQUIREMENTS`** — 预设的 chat-style 需求常量
7. **`get_default_configuration(underlying_model)`** — 已知模型档案查询
8. **`get_known_capabilities(model_name)`** — 模型能力查询
9. **`discover_target_capabilities_async()`** — 运行时能力探测

### 5.2 项目实现

| 维度 | 官方标准 | 项目实现 | 对齐 |
|:--|:--|:--|:--:|
| `TargetCapabilities` 导入 | 原生类 | ✅ `target_factory.py` 导入使用 | ✅ |
| `TargetConfiguration` 导入 | 原生类 | ✅ `target_factory.py` 导入使用 | ✅ |
| `discover_target_capabilities_async` | 运行时探测 | ✅ `discover_capabilities()` 方法，`apply=True` | ✅ |
| 5 种能力探针 | SYSTEM_PROMPT/MULTI_MESSAGE/MULTI_TURN/JSON_OUTPUT/JSON_SCHEMA | ✅ 通过原生函数自动支持 | ✅ |
| `modality_router.py` 预设能力 | GPT4O/IMAGE_GEN/REASONING 预设 | ✅ 自研增强，4 种预设 | 🟢+ |
| **`CapabilityHandlingPolicy`** | ADAPT vs RAISE 策略 | ❌ 完全缺失 | 🔴 |
| **`ConversationNormalizationPipeline`** | 有序 normalizer 管道 | ❌ 完全缺失 | 🔴 |
| **`TargetRequirements`** | 消费者需求验证 | ❌ 完全缺失 | 🔴 |
| **`CHAT_TARGET_REQUIREMENTS`** | chat-style 需求常量 | ❌ 未使用 | 🔴 |
| **`get_default_configuration`** | 已知模型档案 | ❌ 未使用 | 🔴 |
| **`get_known_capabilities`** | 模型能力查询 | ❌ 未使用 | 🔴 |
| **`custom_configuration` 参数** | 实例级覆盖 | ❌ TargetParams 无此字段 | 🔴 |
| **ADAPT 策略 normalizer** | HistorySquashNormalizer / GenericSystemSquashNormalizer | ❌ 完全缺失 | 🔴 |

### 5.3 差距分析

**差距 1：`CapabilityHandlingPolicy`（ADAPT vs RAISE）完全缺失（重大）**

官方允许为可适配能力（`MULTI_TURN`、`SYSTEM_PROMPT`）配置 ADAPT 策略，使不支持这些能力的 Target 仍可用于多轮攻击：

```python
adapt_config = TargetConfiguration(
    capabilities=single_turn_caps,
    policy=CapabilityHandlingPolicy(
        behaviors={
            CapabilityName.MULTI_TURN: UnsupportedCapabilityBehavior.ADAPT,
            CapabilityName.SYSTEM_PROMPT: UnsupportedCapabilityBehavior.ADAPT,
        }
    ),
)
# 管道自动安装: [GenericSystemSquashNormalizer, HistorySquashNormalizer]
```

**影响**：
- 不支持 multi_turn 的 HTTP 端点无法用于多轮攻击（Crescendo、RedTeaming 等）
- 不支持 system_prompt 的推理模型（o1/o3）无法接收系统提示
- 当前只能 RAISE（默认），无法自动适配

**AI-300 考试影响**：中等。AI-300 考试主要关注 OpenAI 兼容端点（通常支持 multi_turn 和 system_prompt），但某些自定义 HTTP 端点可能不支持。

**差距 2：`TargetRequirements` / `CHAT_TARGET_REQUIREMENTS` 验证缺失（重大）**

官方允许消费者在构造时验证目标是否满足需求：

```python
from pyrit.prompt_target import CHAT_TARGET_REQUIREMENTS
CHAT_TARGET_REQUIREMENTS.validate(target=target)
```

**影响**：
- 攻击策略无法在构造时验证目标是否兼容（如 PAIR 需要 editable_history）
- 错误延迟到运行时才暴露，调试困难
- 可能对不支持的目标运行不兼容的攻击，产生无效结果

**差距 3：`get_default_configuration` / `get_known_capabilities` 未使用（中等）**

官方提供已知模型档案查询，可在创建 Target 前预知能力：

```python
gpt_5_caps = OpenAIChatTarget.get_default_configuration(underlying_model="gpt-5")
# gpt-5: supports_json_schema=True
```

**影响**：
- 无法在攻击策略选择前预知模型能力
- 可能对不支持 JSON schema 的模型使用 JSON schema 攻击
- `modality_router.py` 有自研预设（GPT4O_CAPABILITIES 等），但未使用原生档案查询

**差距 4：`custom_configuration` 参数缺失（中等）**

TargetParams 缺少 `custom_configuration` 字段，无法为实例指定自定义能力声明。

### 5.4 对齐度：50% 🔴

TargetCapabilities 体系是项目最大的差距。虽然能力探测和 `modality_router.py` 自研增强部分弥补了这一差距，但 ADAPT/RAISE 策略、需求验证、模型档案查询等核心功能完全缺失。

---

## 6. MessageNormalizer 专项分析

### 6.1 官方标准

PyRIT 1.0.0 提供完整的 MessageNormalizer 体系，用于将 `Message` 格式转换为目标所需的格式：

| Normalizer | 功能 | 输出类型 |
|-----------|------|---------|
| `ChatMessageNormalizer` | 转换为 OpenAI ChatMessage 格式 | `list[ChatMessage]` / JSON str |
| `GenericSystemSquashNormalizer` | 合并 system 消息到 user 消息 | `list[Message]` |
| `ConversationContextNormalizer` | 格式化为轮次文本 | `str` |
| `TokenizerTemplateNormalizer` | 使用 HuggingFace tokenizer chat template | `str` |

关键特性：
- `ChatMessageNormalizer` 支持 `use_developer_role=True`（o1/o3/gpt-4.1+）
- `TokenizerTemplateNormalizer` 支持 6 种模型别名（chatml/phi3/qwen/llama3/gemma/mistral）
- System 消息处理策略：`keep` / `squash` / `ignore` / `developer`
- 自定义 Normalizer 接口（`MessageListNormalizer[T]` / `MessageStringNormalizer`）

### 6.2 项目实现

**完全缺失**。项目中没有任何 MessageNormalizer 的导入或使用。

```
搜索结果：No matches found for MessageNormalizer|ChatMessageNormalizer|
GenericSystemSquashNormalizer|TokenizerTemplateNormalizer
```

### 6.3 差距分析

**影响分析**：

1. **ADAPT 策略无法工作**：`CapabilityHandlingPolicy` 的 ADAPT 策略依赖 `GenericSystemSquashNormalizer`（系统消息压缩）和 `HistorySquashNormalizer`（历史扁平化）。没有 MessageNormalizer，ADAPT 策略无法实现。

2. **非 OpenAI 模型格式适配缺失**：HuggingFace 模型（Llama、Mistral、Phi-3 等）需要特定的 chat template 格式。`TokenizerTemplateNormalizer` 可处理此转换，但项目中缺失。

3. **developer 角色不支持**：o1/o3/gpt-4.1+ 模型使用 "developer" 角色替代 "system"。`ChatMessageNormalizer(use_developer_role=True)` 可处理此转换，但项目中缺失。

4. **对话历史格式化缺失**：`ConversationContextNormalizer` 可将对话历史格式化为轮次文本字符串，用于攻击提示中包含上下文。项目中缺失。

**AI-300 考试影响**：低-中。AI-300 考试主要使用 OpenAI 兼容端点（OpenAIChatTarget 自动处理消息格式），MessageNormalizer 主要用于非标准端点和 ADAPT 策略。

### 6.4 对齐度：0% 🔴

MessageNormalizer 完全缺失，但由于 OpenAI 原生 Target 类内部已处理消息格式转换，对 AI-300 核心场景影响有限。

---

## 7. 多模态 Target 专项分析

### 7.1 OpenAIImageTarget

| 维度 | 官方标准 | 项目实现 | 对齐 |
|:--|:--|:--|:--:|
| 原生类使用 | `OpenAIImageTarget` | ✅ 导入使用 | ✅ |
| Text → Image | 从文本生成图片 | ✅ 支持 | ✅ |
| Image Editing | 文本+图片 → 图片 | ✅ 通过原生类支持 | ✅ |
| `output_format` | png/jpeg/webp | ✅ 透传 | ✅ |
| `image_size` | auto/1024x1024/... | ✅ 透传 | ✅ |
| `quality` | auto/low/medium/high | ✅ 透传（`image_quality` 字段） | ✅ |
| `background` | transparent/opaque/auto | ✅ 透传（`image_background` 字段） | ✅ |
| `deployment` | Azure 部署名 | ✅ `underlying_model` / `model_name` 映射 | ✅ |
| `httpx_client_kwargs` | 超时/SSL/代理 | ✅ 透传 | ✅ |
| **认证模式检测** | `detect_auth_mode` | ❌ **BUG**：`_create_openai_image` 调用 `detect_auth_mode(target_url, params)` 但 `detect_auth_mode` 是 `TargetFactory` 的静态方法，应调用 `TargetFactory.detect_auth_mode(target_url, params)` | 🔴 |
| **`api_key` 透传** | Azure Entra ID | ⚠️ identity 模式下未设置 `api_key=None`，可能导致认证失败 | 🟡 |
| **`max_requests_per_minute`** | 速率限制 | ❌ 未透传 | 🟡 |

**BUG 详情**：

`_create_openai_image()` 函数第 1119 行：
```python
auth_mode = detect_auth_mode(target_url, params)  # ← NameError: detect_auth_mode 未定义
```

应改为：
```python
auth_mode = TargetFactory.detect_auth_mode(target_url, params)
```

此 bug 会导致 `openai_image` 类型 Target 创建时抛出 `NameError`。

### 7.2 OpenAIVideoTarget

| 维度 | 官方标准 | 项目实现 | 对齐 |
|:--|:--|:--|:--:|
| 原生类使用 | `OpenAIVideoTarget` | ❌ 完全缺失 | 🔴 |
| Text-to-Video | 文本 → 视频 | ❌ | 🔴 |
| Remix | 视频变体 | ❌ | 🔴 |
| Text+Image-to-Video | 图片首帧 → 视频 | ❌ | 🔴 |
| 视频评分 | `VideoTrueFalseScorer` / `VideoFloatScaleScorer` | ❌ | 🔴 |
| 音频联合评分 | `AudioTrueFalseScorer` | ❌ | 🔴 |

**影响**：无法进行视频生成攻击测试。AI-300 考试中视频攻击不是核心场景，但多模态攻击覆盖度降低。

### 7.3 OpenAITTSTarget

| 维度 | 官方标准 | 项目实现 | 对齐 |
|:--|:--|:--|:--:|
| 原生类使用 | `OpenAITTSTarget` | ❌ 完全缺失 | 🔴 |
| Text → Speech | 文本转语音 | ❌ | 🔴 |
| Converter 链集成 | 翻译 → TTS | ❌ | 🔴 |

**影响**：无法进行 TTS 攻击测试。AI-300 考试中 TTS 攻击不是核心场景。

### 7.4 对齐度

| Target | 对齐度 | 评级 |
|:--|:--:|:--:|
| OpenAIImageTarget | 60% | 🟡 |
| OpenAIVideoTarget | 0% | 🔴 |
| OpenAITTSTarget | 0% | 🔴 |

---

## 8. 其他 Target 类型分析

### 8.1 AzureMLChatTarget

| 维度 | 官方标准 | 项目实现 | 对齐 |
|:--|:--|:--|:--:|
| 原生类使用 | `AzureMLChatTarget` | ❌ 完全缺失 | 🔴 |
| AML 端点配置 | `AZURE_ML_MANAGED_ENDPOINT` / `AZURE_ML_KEY` | ❌ | 🔴 |
| `**param_kwargs` | 模型参数透传 | ❌ | 🔴 |

**影响**：无法测试 Azure ML 托管模型。AI-300 考试中 AML 不是核心场景，但 Azure 生态覆盖度降低。

**建议**：可通过 `LiteLLMChatTarget` 或 `OpenAIChatTarget`（如果 AML 端点兼容 OpenAI API）间接覆盖。

### 8.2 LiteLLMChatTarget

| 维度 | 官方标准 | 项目实现 | 对齐 |
|:--|:--|:--|:--:|
| 原生类使用 | `LiteLLMChatTarget` | ✅ 导入使用 | ✅ |
| 100+ Provider 支持 | Anthropic/Google/Cohere/Mistral | ✅ 通过 LiteLLM 库 | ✅ |
| 推理参数 | temperature/top_p/seed | ✅ 部分透传 | ✅ |
| `extra_body_parameters` | 请求体注入 | ✅ 透传 | ✅ |
| `httpx_client_kwargs` | 超时/SSL/代理 | ✅ 透传 | ✅ |
| `max_requests_per_minute` | 速率限制 | ✅ 透传 | ✅ |
| **`reasoning_effort`** | 推理模型支持 | ❌ 未透传 | 🟡 |
| **`reasoning_summary`** | 推理摘要 | ❌ 未透传 | 🟡 |
| **`max_output_tokens`** | 最大输出 token | ❌ 未透传 | 🟡 |
| **`frequency_penalty`** | 频率惩罚 | ❌ 未透传 | 🟡 |
| **`presence_penalty`** | 存在惩罚 | ❌ 未透传 | 🟡 |
| **`n`** | 多候选 | ❌ 未透传 | 🟡 |
| **fallback 策略** | 安装失败时回退 | ✅ 回退到 `OpenAIChatTarget` | ✅ |

**对齐度**：80% 🟢。核心功能完整，部分推理参数未透传。

### 8.3 PlaywrightTarget

| 维度 | 官方标准 | 项目实现 | 对齐 |
|:--|:--|:--|:--:|
| 原生类使用 | `PlaywrightTarget` | ✅ 导入使用 | ✅ |
| `interaction_func` | 自定义交互函数 | ✅ 必填参数 | ✅ |
| `page` | Playwright Page 对象 | ✅ 必填参数 | ✅ |
| `max_requests_per_minute` | 速率限制 | ✅ 透传 | ✅ |
| 安装检查 | playwright 依赖 | ✅ ImportError 友好提示 | ✅ |

**对齐度**：85% 🟢。完整对齐官方标准。

### 8.4 WebSocketCopilotTarget

| 维度 | 官方标准 | 项目实现 | 对齐 |
|:--|:--|:--|:--:|
| 原生类使用 | `WebSocketCopilotTarget` | ✅ 导入使用 | ✅ |
| 自动认证 | `CopilotAuthenticator` | ✅ username + password | ✅ |
| 手动认证 | `ManualCopilotAuthenticator` | ✅ access_token | ✅ |
| 环境变量配置 | `COPILOT_USERNAME` / `COPILOT_PASSWORD` / `COPILOT_ACCESS_TOKEN` | ✅ 全部支持 | ✅ |
| `max_requests_per_minute` | 速率限制 | ✅ 透传 | ✅ |
| 安装检查 | websockets 依赖 | ✅ ImportError 友好提示 | ✅ |
| **多模态支持** | 文本+图片 | ⚠️ 原生类支持，项目未显式配置 | 🟡 |

**对齐度**：85% 🟢。完整对齐官方标准。

### 8.5 AzureBlobStorageTarget

| 维度 | 官方标准 | 项目实现 | 对齐 |
|:--|:--|:--|:--:|
| 原生类使用 | `AzureBlobStorageTarget` | ✅ 导入使用 | ✅ |
| `container_url` | 容器 URL | ✅ 参数 + 环境变量 | ✅ |
| `sas_token` | SAS 令牌 | ✅ 参数 + 环境变量 | ✅ |
| `blob_content_type` | 内容类型 | ✅ `SupportedContentType` 枚举 | ✅ |
| `max_requests_per_minute` | 速率限制 | ✅ 透传 | ✅ |
| 安装检查 | azure-storage-blob 依赖 | ✅ ImportError 友好提示 | ✅ |

**对齐度**：85% 🟢。完整对齐官方标准。

### 8.6 PromptShieldTarget [optional]

| 维度 | 官方标准 | 项目实现 | 对齐 |
|:--|:--|:--|:--:|
| 原生类使用 | `PromptShieldTarget` | ✅ 导入使用 | ✅ |
| `azure_endpoint` | Content Safety 端点 | ✅ 参数 + 环境变量 | ✅ |
| `api_key` | API Key | ✅ 参数 + 环境变量 | ✅ |
| `force_entry_field` | userPrompt/documents | ✅ 透传 | ✅ |
| `max_requests_per_minute` | 速率限制 | ✅ 透传 | ✅ |

**对齐度**：80% 🟢。完整对齐官方标准。（此为 optional 文档，仅分析不做差距评分）

---

## 9. Optional 文档分析（仅分析，不做差距评分）

以下文档在官方标注为 "optional"，此处仅做分析记录，不进行差距评分。

### 9.1 OpenAI Completions [optional]

`OpenAICompletionTarget` 使用 Legacy Completions API（`/v1/completions`），已被 Chat Completions API 取代。

**项目状态**：未实现。由于 Legacy API 已过时，且 AI-300 考试不涉及，不建议实现。

### 9.2 Prompt Shield Target [optional]

`PromptShieldTarget` 用于测试 Azure AI Content Safety Prompt Shield 防御能力。

**项目状态**：✅ 已实现（见 8.6）。

### 9.3 Realtime Target [optional]

`RealtimeTarget` 使用 Realtime Audio API（WebSocket），支持实时语音交互。

**项目状态**：未实现。AI-300 考试不涉及实时音频交互。

### 9.4 HuggingFace Chat Target [optional]

使用 `TokenizerTemplateNormalizer` 格式化消息，支持 HuggingFace 模型（ChatML, Llama, Mistral 等）。

**项目状态**：MessageNormalizer 完全缺失。但可通过 `LiteLLMChatTarget` 间接支持 HuggingFace 模型。

### 9.5 Round Robin Target [optional]

`RoundRobinTarget` 在多个目标之间轮询发送请求。

**项目状态**：未实现。可通过 `ScenarioOrchestrator` 的并发+多目标模式间接实现类似功能。

---

## 10. AI-300 考试就绪度评估

### 10.1 考试场景覆盖度

| 考试场景 | 相关 Target | 就绪度 | 说明 |
|---------|-----------|:------:|------|
| LLM 攻击（Prompt Injection, Jailbreak） | `OpenAIChatTarget` | **95%** | 核心场景，完整对齐 |
| OpenAI 兼容端点攻击 | `OpenAIChatTarget` (vLLM/Ollama/LM Studio) | **95%** | 自动检测 + 环境变量配置 |
| 推理模型攻击（o1/o3） | `OpenAIResponseTarget` | **90%** | reasoning_effort/summary 完整 |
| Agentic AI 攻击（Tool Calling） | `OpenAIResponseTarget` | **90%** | custom_functions 完整 |
| HTTP API 攻击（非标准端点） | `HTTPTarget`, `HTTPXAPITarget` | **95%** | 增强型 Burp 构建器 |
| Burp Suite 集成 | `HTTPTarget` | **95%** | SSE 检测 + JSON 路径推断 |
| Web UI 攻击 | `PlaywrightTarget` | **85%** | 完整对齐 |
| Copilot 攻击 | `WebSocketCopilotTarget` | **85%** | 双重认证 + 多模态 |
| XPIA / RAG 注入 | `AzureBlobStorageTarget` | **85%** | 完整对齐 |
| 多 LLM Provider 攻击 | `LiteLLMChatTarget` | **80%** | 部分推理参数缺失 |
| 多模态攻击（图片） | `OpenAIImageTarget` | **60%** | 存在 bug + 认证问题 |
| 多模态攻击（视频） | `OpenAIVideoTarget` | **0%** | 完全缺失 |
| 多模态攻击（TTS） | `OpenAITTSTarget` | **0%** | 完全缺失 |
| 防御测试 | `PromptShieldTarget` | **80%** | 完整对齐 |
| 能力自适应攻击 | `TargetCapabilities` 体系 | **50%** | ADAPT/RAISE 缺失 |

### 10.2 综合就绪度

```
AI-300 考试 Target 就绪度：
├── LLM 攻击 ████████████████████░ 95%
├── Agentic 攻击 ██████████████████░░ 90%
├── HTTP 攻击 ████████████████████░ 95%
├── Web/Copilot 攻击 █████████████████░░░ 85%
├── XPIA/RAG 攻击 █████████████████░░░ 85%
├── 多模态攻击 ████████████░░░░░░░░░ 40%
├── 能力自适应 ██████████░░░░░░░░░░ 50%
└── 综合就绪度 ████████████████░░░░ 80%
```

---

## 11. 差距优先级排序与建议路线图

### 11.1 差距优先级矩阵

| 优先级 | 差距 | 影响范围 | AI-300 影响 | 实现难度 |
|:------:|:--|:--|:--:|:--:|
| **P0** | OpenAIImageTarget bug（`detect_auth_mode` 调用错误） | 图片生成攻击 | 中 | 低 |
| **P0** | `custom_configuration` 参数缺失 | 所有 Target 类型 | 中 | 中 |
| **P1** | `CapabilityHandlingPolicy`（ADAPT vs RAISE）缺失 | 多轮攻击兼容性 | 中 | 高 |
| **P1** | `TargetRequirements` / `CHAT_TARGET_REQUIREMENTS` 验证缺失 | 攻击策略选择 | 中 | 中 |
| **P1** | `get_default_configuration` / `get_known_capabilities` 未使用 | 模型能力预知 | 低 | 低 |
| **P2** | MessageNormalizer 完全缺失 | 非 OpenAI 模型 + ADAPT 策略 | 低 | 高 |
| **P2** | OpenAIVideoTarget 缺失 | 视频攻击 | 低 | 中 |
| **P2** | OpenAITTSTarget 缺失 | TTS 攻击 | 低 | 中 |
| **P3** | AzureMLChatTarget 缺失 | AML 模型测试 | 低 | 低 |
| **P3** | LiteLLMChatTarget 推理参数缺失 | 多 Provider 推理模型 | 低 | 低 |

### 11.2 建议路线图

#### P0：立即修复（1-2 天）

1. **修复 OpenAIImageTarget bug**
   - 将 `detect_auth_mode(target_url, params)` 改为 `TargetFactory.detect_auth_mode(target_url, params)`
   - 修复 identity 模式下 `api_key` 未设置的问题
   - 添加 `max_requests_per_minute` 透传

2. **添加 `custom_configuration` 参数**
   - 在 `TargetParams` 中添加 `custom_configuration: Optional[TargetConfiguration] = None`
   - 在所有 Target 创建器中透传此参数

#### P1：短期增强（3-5 天）

3. **实现 `CapabilityHandlingPolicy`（ADAPT vs RAISE）**
   - 在 `TargetParams` 中添加 `capability_policy` 字段
   - 集成 `CapabilityHandlingPolicy` 和 `UnsupportedCapabilityBehavior`
   - 在 `discover_capabilities` 中合并用户策略

4. **集成 `TargetRequirements` 验证**
   - 在攻击策略选择前调用 `CHAT_TARGET_REQUIREMENTS.validate(target)`
   - 捕获 `ValueError` 并提供友好错误消息

5. **使用 `get_default_configuration` / `get_known_capabilities`**
   - 在 `create_target_with_detection` 中，根据 `underlying_model` 预加载能力档案
   - 将结果与运行时探测结果合并

#### P2：中期增强（1-2 周）

6. **集成 MessageNormalizer**
   - 导入 `ChatMessageNormalizer`、`GenericSystemSquashNormalizer` 等
   - 在 ADAPT 策略中使用 `GenericSystemSquashNormalizer` 和 `HistorySquashNormalizer`
   - 添加 `use_developer_role` 支持

7. **添加 OpenAIVideoTarget 支持**
   - 在 `TargetParams` 中添加视频生成参数
   - 创建 `_create_openai_video()` 创建器
   - 注册到 `_TARGET_CREATORS`

8. **添加 OpenAITTSTarget 支持**
   - 创建 `_create_openai_tts()` 创建器
   - 注册到 `_TARGET_CREATORS`

#### P3：长期增强（按需）

9. **添加 AzureMLChatTarget 支持**
   - 创建 `_create_azure_ml()` 创建器
   - 环境变量 `AZURE_ML_KEY` / `AZURE_ML_MANAGED_ENDPOINT`

10. **LiteLLMChatTarget 参数补全**
    - 添加 `reasoning_effort` / `reasoning_summary` / `max_output_tokens` 透传
    - 添加 `frequency_penalty` / `presence_penalty` / `n` 透传

---

## 附录 A：官方文档覆盖清单

| # | 官方页面 | 获取状态 | 差距分析 |
|---|---------|:-------:|:-------:|
| 1 | Prompt Targets（概览） | ✅ | ✅ |
| 2 | OpenAI Chat Target | ✅ | ✅ |
| 3 | OpenAI Responses Target | ✅ | ✅ |
| 4 | OpenAI Image Target | ✅ | ✅ |
| 5 | OpenAI Video Target | ✅ | ✅ |
| 6 | OpenAI TTS Target | ✅ | ✅ |
| 7 | Creating Custom Targets | ✅ | ✅ |
| 8 | Target Capabilities | ✅ | ✅ |
| 9 | AML Chat Targets | ✅ | ✅ |
| 10 | Azure Blob Storage Targets | ✅ | ✅ |
| 11 | Rate Limit (RPM) Threshold | ✅ | ✅ |
| 12 | HTTP Target | ⚠️ 部分 | ✅ |
| 13 | MessageNormalizer | ✅ | ✅ |
| 14 | Generic Playwright Target | ✅ | ✅ |
| 15 | Playwright Copilot Target | ⚠️ 部分 | ✅ |
| 16 | WebSocket Copilot Target | ✅ | ✅ |
| 17 | OpenAI Completions [optional] | ⚠️ 部分 | 仅分析 |
| 18 | Prompt Shield Target [optional] | ⚠️ 部分 | 仅分析 |
| 19 | Realtime Target [optional] | ⚠️ 部分 | 仅分析 |
| 20 | HuggingFace Chat Target [optional] | ⚠️ 部分 | 仅分析 |
| 21 | Round Robin Target [optional] | ⚠️ 部分 | 仅分析 |

---

## 附录 B：项目文件清单

| 文件 | 行数 | 职责 |
|------|------|------|
| `src/targets/target_factory.py` | ~1540 | 核心工厂（TargetFactory + TargetParams + 12 创建器） |
| `src/targets/burp_target.py` | ~321 | 增强型 Burp Target 构建器 |
| `src/targets/__init__.py` | ~87 | 模块导出 |
| `src/executor/attack/core/modality_router.py` | ~370 | 模态路由器（自研增强） |
| `config/targets/endpoints.yaml` | ~81 | 端点路径定义 |
| `config/targets/ai_types.yaml` | ~84 | AI 类型识别规则 |
| `config/targets/connection.yaml` | ~109 | 连接配置 + 攻击映射 |
