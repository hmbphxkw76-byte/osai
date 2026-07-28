# Target-Aware Converter Routing — 高成功率 Converter 组合指南

> **版本**: v2.0  
> **日期**: 2026-07-27  
> **状态**: R0-R6 全部实施完成 + 三层过滤（LLM/模态/运行时参数） + 动态链选择 + R0 fallback

## 1. 架构概述

### 1.1 问题

当前架构中 Converter 链选择仅由 OWASP ID / Scenario 驱动，不感知 Target 类型（LLM Direct / Agent / Output Handling / Multimodal）。这导致：

- 对 LLM Direct 目标使用了文件注入链（低效）
- 对 RAG 目标使用了编码绕过链（不匹配）
- 对 Agent 目标缺少专用注入链（成功率低）

### 1.2 解决方案

在 OWASP/Scenario 驱动之上增加 **Target 维度**：

```
Target 类型 → 安全机制分析 → 最优 Converter 链序列
```

**三层路由叠加**：
1. OWASP 层：根据 OWASP Top 10 风险选择技术大类
2. **Target 层（新增）**：根据 Target 类型选择高 ASR Converter 链
3. Failure 层：根据失败类型（model_refusal / timeout 等）动态调整优先级

### 1.3 核心组件

| 组件 | 文件 | 职责 |
|------|------|------|
| `TargetAwareConverterRouter` | `src/converters/target_aware_router.py` | Target 类型 → Converter 链路由 |
| `FailureTypeRoutingSelector` | `src/scenarios/failure_type_selector.py` | 失败类型 + Target 感知排序 |
| `CONVERTER_VARIANT_CHAINS` | `src/scenarios/technique_factories.py` | Converter 变体注册表 |
| `target_aware_converter_profiles` | `payload_strategy_matrix.yaml` | YAML 配置（10 分组） |

---

## 2. 10 个 Target 分组

### 2.1 分组映射表

| # | Target Group | PyRIT Target Types | 安全机制 | 描述 |
|---|---|---|---|---|
| 1 | `llm_direct` | openai_chat, openai_responses, litellm, azure_ml | content_filter | LLM 直连 — 内容过滤 + 关键词检测 + 拒绝分类器 |
| 2 | `llm_safety` | prompt_shield | prompt_shield_detection | LLM Safety — Prompt Shield 检测绕过 |
| 3 | `agent_web` | playwright, playwright_copilot | input_validation | Agent (Web UI) — 前端输入验证 + 后端双重检查 |
| 4 | `agent_copilot` | websocket_copilot | grounding_safety | Agent (Copilot) — 系统提示 + Grounding + 工具权限 |
| 5 | `agent_api` | http_api | api_schema_validation | Agent (API) — API 层验证 + Schema 约束 |
| 6 | `rag` | azure_blob | no_content_check | RAG — 文档投毒 / XPIA 载荷投递 |
| 7 | `output_handling` | http_raw | man_in_middle | Output Handling — 中间人位置 / 原始 HTTP |
| 8 | `multimodal_image` | openai_image | image_content_policy | Multimodal (Image) — 图片内容策略 + 安全分类器 |
| 9 | `multimodal_video` | openai_video | pre_generation_review | Multimodal (Video) — 生成前审核 |
| 10 | `multimodal_audio` | openai_tts | voice_content_review | Multimodal (Audio/TTS) — 语音内容审核 |

---

## 3. 高成功率 Converter 组合（按 Target 分组）

### 3.1 LLM Direct — 高成功率组合

适用: `openai_chat`, `openai_responses`, `litellm`, `azure_ml`

| 组合名 | Converter 链 | 预估 ASR | 机制 | 适用场景 |
|--------|-------------|----------|------|---------|
| **multi_encoding_v2** (新) | Base64Converter → ROT13Converter → CaesarConverter(5) → AtbashConverter | 80-95% | 四层编码，内容过滤器无法识别 | 强内容过滤（Azure OpenAI Content Filter） |
| **stealth_evasion** (已有) | UnicodeConfusable → Base64 → SuffixAppend | 70-85% | Unicode 混淆 + 编码 + 后缀追加 | 关键词检测绕过 |
| **encoding_bypass** (已有) | Base64 → ROT13 → Caesar | 60-80% | 三层编码绕过 | 基础编码绕过 |
| **persuasion_authority** (新) | PersuasionConverter(authority) → ToneConverter(formal) → TranslationConverter(en) | 50-70% | 权威背书 + 正式语气 + 语言切换 | 语义安全分类器绕过（需 LLM 辅助） |
| **policy_puppetry** | PolicyPuppetryConverter | 40-60% | 策略伪装 | 系统提示提取 |
| **noise_case_chain** | RandomCapitalLetters → NoiseConverter | 30-50% | 随机大小写 + 噪声注入 | 弱过滤绕过 |
| **unicode_attack** | UnicodeSubstitution → Bidi → ZeroWidth | 30-50% | Unicode 替换 + 双向 + 零宽 | 高级 Unicode 攻击 |

### 3.2 LLM Safety — 高成功率组合

适用: `prompt_shield`

| 组合名 | Converter 链 | 预估 ASR | 机制 | 适用场景 |
|--------|-------------|----------|------|---------|
| **stealth_evasion** (已有) | UnicodeConfusable → Base64 → SuffixAppend | 60-80% | Unicode 混淆绕过 Prompt Shield 检测 | Prompt Shield 绕过 |
| **multi_encoding_v2** (新) | Base64 → ROT13 → Caesar(5) → Atbash | 60-80% | 四层编码，Shield 无法解码 | 强 Shield 检测 |
| **encoding_bypass** (已有) | Base64 → ROT13 → Caesar | 50-70% | 三层编码绕过 | 基础 Shield 绕过 |
| **decomposition_chain** | DecompositionConverter | 40-60% | 任务分解绕过 | 语义检测绕过（需 LLM 辅助） |
| **persuasion_authority** (新) | PersuasionConverter(authority) → ToneConverter → TranslationConverter | 40-60% | 权威说服 + 语言切换 | 拒绝分类器绕过（需 LLM 辅助） |

### 3.3 Output Handling / XPIA / RAG — 高成功率组合

适用: `azure_blob` (RAG), `http_raw` (Output Handling)

| 组合名 | Converter 链 | 预估 ASR | 机制 | 适用场景 |
|--------|-------------|----------|------|---------|
| **xpia_stealth_chain** (新) | PDFConverter(white, 6pt) | 60-80% | 白色小字嵌入 PDF | XPIA 文档投递 / RAG 投毒 |
| **pdf_injection** (已有) | PDFConverter(existing_pdf, injection_items) | 60-80% | 修改现有 PDF 注入攻击文本 | XPIA 文档投递 |
| **format_injection** (已有) | MarkdownInjectionConverter | 50-70% | Markdown 格式注入 | Output Handling 中间人 |
| **text_jailbreak** (已有) | TextJailbreakConverter | 50-70% | 越狱模板包装 | RAG 文档投毒 |
| **worddoc_injection** (已有) | WordDocConverter(existing_docx, placeholder) | 40-60% | Word 文档注入 | XPIA 文档投递 |

### 3.4 Agent (Web/Copilot/API) — 高成功率组合

适用: `playwright`, `playwright_copilot`, `websocket_copilot`, `http_api`

| 组合名 | Converter 链 | 预估 ASR | 机制 | 适用场景 |
|--------|-------------|----------|------|---------|
| **agent_injection_chain** (新) | UnicodeConfusable → SuffixAppend → TaskFraming | 50-70% | Unicode 混淆 + 后缀追加 + 任务伪装 | Agent 目标劫持 + 工具参数注入 |
| **stealth_evasion** (已有) | UnicodeConfusable → Base64 → SuffixAppend | 40-60% | Unicode 混淆 + 编码 | 前端输入验证绕过 |
| **encoding_bypass** (已有) | Base64 → ROT13 → Caesar | 40-60% | 三层编码绕过 | API Schema 验证绕过 |
| **unicode_attack** (已有) | UnicodeSubstitution → Bidi → ZeroWidth | 30-50% | Unicode 替换 + 双向 + 零宽 | 高级 Unicode 注入 |
| **persuasion_authority** (新) | PersuasionConverter(authority) → ToneConverter → TranslationConverter | 30-50% | 权威说服 | Grounding 绕过（需 LLM 辅助） |
| **task_framing_chain** | TaskFramingConverter | 30-50% | 任务格式伪装 | API 参数注入 |
| **policy_puppetry_chain** | PolicyPuppetryConverter | 30-50% | 策略伪装 | 系统提示提取 |

### 3.5 Multimodal (Image/Video/Audio) — 高成功率组合

适用: `openai_image`, `openai_video`, `openai_tts`

| 组合名 | Converter 链 | 预估 ASR | 机制 | 适用场景 |
|--------|-------------|----------|------|---------|
| **multimodal_image_attack** (已有) | QRCodeConverter | 40-60% | 文本转 QR 码图片 | 图片内容策略绕过 |
| **multimodal_steganography** (已有) | AddTextImageConverter | 30-50% | 图片隐写 | 图片安全分类器绕过 |
| **stealth_evasion** (已有) | UnicodeConfusable → Base64 → SuffixAppend | 30-50% | Unicode 混淆 + 编码 | TTS 语音内容审核绕过 |
| **encoding_bypass** (已有) | Base64 → ROT13 → Caesar | 30-50% | 三层编码绕过 | TTS 语音内容审核绕过 |

---

## 4. 新增 Converter 链详解（P1）

### 4.1 multi_encoding_v2 — 四层编码链

```
输入文本 → Base64Converter → ROT13Converter → CaesarConverter(5) → AtbashConverter → 输出
```

**预估 ASR**: 80-95%（对强内容过滤效果最佳）

**为什么高效**：
- Base64 将文本转为纯字母数字，绕过关键词检测
- ROT13 对 Base64 输出再次混淆
- Caesar(5) 位移进一步破坏模式
- Atbash 镜像反转最终输出
- 四层叠加使任何单一解码器都无法还原

**YAML 配置**:
```yaml
multi_encoding_v2:
  converters:
    - Base64Converter
    - ROT13Converter
    - CaesarConverter
    - AtbashConverter
  params:
    CaesarConverter:
      caesar_offset: 5
```

### 4.2 persuasion_authority — 权威说服链

```
输入文本 → PersuasionConverter(authority_endorsement) → ToneConverter(formal) → TranslationConverter(en) → 输出
```

**预估 ASR**: 50-70%（需 LLM 辅助）

**为什么高效**：
- 权威背书策略利用信任权威的心理偏差
- 正式语气降低安全分类器的警觉
- 语言切换（如中文→英文）绕过语言特定检测

**注意**: 需要 `converter_target`（LLM 辅助目标）

### 4.3 agent_injection_chain — Agent 注入链

```
输入文本 → UnicodeConfusableConverter → SuffixAppendConverter(!) → TaskFramingConverter → 输出
```

**预估 ASR**: 50-70%

**为什么高效**：
- Unicode 混淆隐藏注入指令的关键词
- 后缀追加破坏输入验证正则
- 任务格式伪装将注入包装为合法任务请求
- 三层组合针对 Agent 的输入验证 + Schema 约束 + Grounding

### 4.4 xpia_stealth_chain — XPIA 隐写链

```
输入文本 → PDFConverter(font_color=(255,255,255), font_size=6) → 输出 PDF
```

**预估 ASR**: 60-80%

**为什么高效**：
- 白色小字（6pt）在 PDF 中不可见
- RAG 系统会索引 PDF 文本内容
- 攻击内容被嵌入文档中，绕过内容检查
- 适用于文档投毒和 XPIA 载荷投递

---

## 5. Target 感知路由实现（P0-P3）

### 5.1 P0: TargetAwareConverterRouter

**文件**: `src/converters/target_aware_router.py`

纯函数式路由器，输入 `target_type` 输出有序链名列表：

```python
from src.converters import TargetAwareConverterRouter

router = TargetAwareConverterRouter()

# 获取 LLM Direct 的最优链序列
chains = router.select_chains("openai_chat")
# ["multi_encoding_v2", "stealth_evasion", "encoding_bypass",
#  "persuasion_authority", "decomposition_chain", "llm_assisted",
#  "policy_puppetry", "noise_case_chain"]

# 获取 RAG 的最优链序列
chains = router.select_chains("azure_blob")
# ["xpia_stealth_chain", "pdf_injection", "worddoc_injection", "text_jailbreak"]

# 获取链在特定 Target 下的优先级
priority = router.get_priority("multi_encoding_v2", "openai_chat")  # 1（最高）
priority = router.get_priority("multi_encoding_v2", "azure_blob")   # 99（不适用）
```

### 5.2 P2: CONVERTER_VARIANT_CHAINS 扩展

**文件**: `src/scenarios/technique_factories.py`

新增 3 条链到 `CONVERTER_VARIANT_CHAINS`：

| 链名 | requires_llm | priority | 描述 |
|------|-------------|----------|------|
| `multi_encoding_v2` | False | 1 | 四层编码 |
| `agent_injection_chain` | False | 3 | Agent 注入 |
| `persuasion_authority` | True | 4 | 权威说服 |

`BASE_TECHNIQUES_FOR_VARIANTS` 扩展：
- `prompt_sending`: 新增 `multi_encoding_v2`, `agent_injection_chain`, `persuasion_authority`
- `many_shot`: 新增 `multi_encoding_v2`
- `chunked_request`: 新增 `agent_injection_chain`

### 5.3 P3: FailureTypeRoutingSelector Target 感知

**文件**: `src/scenarios/failure_type_selector.py`

`FailureTypeRoutingSelector` 新增 `target_type` 参数：

```python
from src.scenarios import AI300EpsilonGreedySelector

# 方式 1: 构造时传入
selector = AI300EpsilonGreedySelector(target_type="openai_chat")

# 方式 2: 运行时设置
selector = AI300EpsilonGreedySelector()
selector.set_target_type("playwright")
```

**排序逻辑**：

| 失败类型 | 排序策略 |
|---------|---------|
| `None`（首次） | Target 感知优先级排序（high_asr → llm_assisted → medium_asr） |
| `model_refusal` | Converter 变体优先（按 Target 感知优先级排序）+ 编码技术 |
| `timeout` | 基础单轮技术优先（无 Converter，减少开销） |
| `objective_not_achieved` | 强技术 + Converter 变体优先（按 Target 感知优先级排序） |

**AI300AdaptiveScenario 集成**：

```python
from src.scenarios import AI300AdaptiveScenario

scenario = AI300AdaptiveScenario(
    converter_target=judge_target,
    target_type="openai_chat",  # P3: Target 感知
)
```

### 5.4 YAML 配置

**文件**: `src/core/defaults/payload_strategy_matrix.yaml`

新增 `target_aware_converter_profiles` 配置段（10 分组）和 4 条新 Converter 链定义。

---

## 6. 使用指南

### 6.1 Pipeline 集成

在 `pipeline.py` 中通过 `target_type` 参数激活 Target 感知：

```python
# pipeline.py 中的调用示例
scenario = AI300AdaptiveScenario(
    converter_target=judge_target,
    target_type=target_params.target_type,  # 如 "openai_chat"
)
```

### 6.2 执行前展示

```python
from src.converters import display_target_converter_profiles
display_target_converter_profiles()
```

输出示例：
```
================================================================
  Target-Aware Converter 链 Profile
================================================================

  ── llm_direct ──
  Targets: azure_ml, litellm, openai_chat, openai_responses
  Mechanism: content_filter
  Description: LLM 直连 — 内容过滤 + 关键词检测 + 拒绝分类器
  High ASR:    multi_encoding_v2, stealth_evasion, encoding_bypass
  LLM Assist:  persuasion_authority, decomposition_chain, llm_assisted
  Medium ASR:  policy_puppetry, noise_case_chain, unicode_attack

  ── rag ──
  Targets: azure_blob
  Mechanism: no_content_check
  Description: RAG — 文档投毒 / XPIA 载荷投递
  High ASR:    xpia_stealth_chain, pdf_injection
  LLM Assist:  (none)
  Medium ASR:  worddoc_injection, text_jailbreak
================================================================
```

### 6.3 执行后分析

```python
from src.scenarios import AI300AdaptiveScenario

# 展示实际使用的 Converter 变体及结果
AI300AdaptiveScenario.display_used_converters(native_result)
```

---

## 7. ASR 预估方法论

### 7.1 数据来源

ASR 预估基于以下数据源综合分析：

1. **PyRIT 官方文档**: Converter 效果描述和适用场景
2. **学术研究**: 编码绕过、Unicode 混淆、说服技术的公开 ASR 数据
3. **项目 ASR 排名**: `tiered_selection_wizard.py` 中的历史 ASR 数据
4. **安全机制分析**: 不同 Target 类型的安全机制强度对比

### 7.2 预估等级

| ASR 范围 | 等级 | 说明 |
|---------|------|------|
| 80-95% | 极高 | 多层编码/混淆，几乎所有过滤器失效 |
| 60-80% | 高 | 单层编码/混淆 + 文件隐写 |
| 50-70% | 中高 | LLM 辅助语义变换 |
| 40-60% | 中 | 策略伪装/任务框架 |
| 30-50% | 中低 | 噪声/Unicode 替换 |

### 7.3 影响因素

- **Target 安全配置**: Content Filter 强度、System Prompt 质量
- **模型版本**: GPT-4o > GPT-3.5 的安全检测能力
- **Converter 参数**: Caesar offset、font_size 等
- **攻击目标**: 有害内容生成 vs 信息泄露 vs 注入

---

## 8. 测试覆盖

**文件**: `tests/unit/test_target_aware_converter_routing.py`

| 测试类 | 测试数 | 覆盖内容 |
|--------|--------|---------|
| `TestTargetGroupMapping` | 10 | Target 类型到分组映射 |
| `TestTargetConverterProfile` | 4 | Profile 获取和字段完整性 |
| `TestSelectConverterChains` | 7 | 链选择逻辑（含 LLM 辅助排除） |
| `TestChainPriority` | 4 | 优先级查询和跨 Target 对比 |
| `TestTargetAwareConverterRouter` | 5 | Router 类接口 |
| `TestNewConverterChains` | 5 | 4 条新链工厂 |
| `TestConverterVariantChainsExtension` | 6 | 链注册和变体工厂 |
| `TestFailureTypeRoutingSelectorTargetAware` | 8 | P3 Target 感知排序 |
| `TestYAMLConfigConsistency` | 3 | YAML 与代码一致性 |
| **总计** | **52** | **全部通过** |

---

## 9. 架构决策记录

### 9.1 为什么选择 10 个分组而非按 Target 类型逐一映射？

- **简洁性**: 10 个分组覆盖 15+ Target 类型，减少配置复杂度
- **共性**: 同组 Target 共享安全机制（如所有 LLM Direct 都有内容过滤）
- **可维护性**: 新增 Target 类型只需归入已有分组

### 9.2 为什么非 LLM 链优先于 LLM 辅助链？

- **速度**: 非 LLM 链无需额外 LLM 调用，执行速度快 10-100x
- **稳定性**: 不依赖 `converter_target` 可用性
- **考试策略**: AI-300 考试时间有限，快速高成功率优先
- **成本**: 非 LLM 链不消耗额外 API 调用

### 9.3 为什么 `xpia_stealth_chain` 在 RAG 和 Output Handling 中排名不同？

- **RAG**: 文档投毒是主要攻击向量，`xpia_stealth_chain` 排第一
- **Output Handling**: 中间人位置可修改输出，`format_injection` 更直接

---

## 10. 文件变更清单

| 文件 | 变更类型 | 说明 |
|------|---------|------|
| `src/converters/target_aware_router.py` | **新建** | P0: TargetAwareConverterRouter + 10 分组 Profile |
| `src/converters/converter_registry.py` | 修改 | P1: 4 条新链工厂函数 |
| `src/converters/__init__.py` | 修改 | 导出新 API（13 个） |
| `src/core/defaults/payload_strategy_matrix.yaml` | 修改 | P0: target_aware_converter_profiles + P1: 4 条新链 YAML |
| `src/scenarios/technique_factories.py` | 修改 | P2: CONVERTER_VARIANT_CHAINS + BASE_TECHNIQUES_FOR_VARIANTS 扩展 |
| `src/scenarios/failure_type_selector.py` | **重写** | P3: target_type 参数 + _target_aware_sort_key |
| `src/scenarios/ai300_adaptive_scenario.py` | 修改 | P3: target_type 参数透传 |
| `tests/unit/test_target_aware_converter_routing.py` | **新建** | 52 个测试 |
| `docs/target_aware_converter_routing.md` | **新建** | 本文档 |
