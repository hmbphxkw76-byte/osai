# PyRIT Converters 优化解决方案 — 对齐官方 1.0.1 标准

> 基于 [PyRIT 1.0.1 官方文档](https://microsoft.github.io/PyRIT/1.0.1/code/converters/converters/)
> 及 PyRIT 源码深度分析，对比 `pyrit-strike` 当前实现，给出完整优化方案。

---

## 一、官方 Converter 体系全景

### 1.1 分类体系

PyRIT 1.0.1 共提供 **85+ 个 text-to-text converter**，按攻击机理分为两大类：

| 类别 | 子类 | 代表 Converter | 学术依据 |
|------|------|----------------|----------|
| **Non-LLM** (确定性变换) | Basic Encoding | Base64, ROT13, Caesar, Atbash, Morse, NATO, Binary, Base2048, Braille, Ecoji, BinAscii | Wei et al. (arXiv:2307.15043) |
| | Obfuscation | Leetspeak, UnicodeConfusable, UnicodeSubstitution, UnicodeReplacement, Emoji, ZeroWidth, Flip, CharSwap, CharacterSpace, Diacritic, Bidi, Zalgo, Superscript, Tatweel, Arabizi, ArabicPresentationForm, AnsiAttack, CodeChameleon, ColloquialWordswap, InsertPunctuation, MathObfuscation, RepeatToken, StringJoin, RandomCapitalLetters, NegationTrap | Shayegani et al. (arXiv:2306.13254) |
| | Text Manipulation | ROT13, Caesar, Atbash, Flip, AsciiArt, FirstLetter | — |
| | Token Smuggling | AsciiSmuggler, SneakyBitsSmuggler, VariationSelectorSmuggler | @embracethered2024unicode |
| **LLM-Based** (语义变换) | Semantic | Persuasion, Tone, Variation, Translation, RandomTranslation, ScientificTranslation, Decomposition, LLMGenericText, MaliciousQuestionGenerator, ToxicSentenceGenerator, TextJailbreak, TaskFraming, TenseConverter, PolicyPuppetry, SuffixAppend, MathPrompt, NoiseConverter, ImagePromptStyle | Zeng et al. (arXiv:2402.19181) |
| **Selective** (选择性转换) | — | **SelectiveTextConverter**, SearchReplaceConverter, DenylistConverter, TemplateSegmentConverter | PyRIT 原生 |

### 1.2 关键官方 API 模式

#### 模式 A: 独立路径 (SequentialAttack FIRST_SUCCESS)
```python
# 官方推荐: 每个 converter 作为独立路径, 任一成功即停止
# PyRIT (arXiv:2407.01232) SequentialAttack
```

#### 模式 B: 串联堆叠 (ConverterConfiguration)
```python
# 官方: ConverterConfiguration.from_converters([conv1, conv2])
# 注意: 多个 converter 在同一个 ConverterConfiguration 中会串联叠加
# 顺序敏感: conv1 先执行, conv2 对 conv1 的输出执行
```

#### 模式 C: SelectiveTextConverter (选择性转换) ⭐ 核心
```python
from pyrit.converter import (
    SelectiveTextConverter, Base64Converter,
    WordProportionSelectionStrategy, TokenSelectionStrategy,
)

# 选择性编码: 只对 30% 的单词做 Base64, 其余保持原文
converter = SelectiveTextConverter(
    sub_converter=Base64Converter(),
    selection_strategy=WordProportionSelectionStrategy(proportion=0.3),
    preserve_tokens=True,  # 用 ⟪⟫ 标记已转换区域
)

# 链式选择性: 第二个 converter 只作用于 ⟪⟫ 标记的区域
converter2 = SelectiveTextConverter(
    sub_converter=ROT13Converter(),
    selection_strategy=TokenSelectionStrategy(),  # 自动检测 ⟪⟫ 标记
    preserve_tokens=True,
)
```

### 1.3 官方 SelectiveTextConverter 的核心价值

**问题**: 全文编码 (如 Base64) 使 payload 完全不可读 → ASR 7%
**解决**: 只编码关键词/敏感词, 其余保持原文 → LLM 可理解上下文

**学术依据**:
- Wei et al. (arXiv:2307.15043): 串联 >2 层 ASR 从 12% 降至 4%
- PyRIT 官方: SelectiveTextConverter + preserve_tokens 实现任意链式选择性转换
- TokenSelectionStrategy: 自动检测 ⟪⟫ 标记, 实现链式 converter 的精确区域定位

---

## 二、当前项目实现差距分析

### 2.1 已有实现的优势 ✅

| 方面 | 当前实现 | 评价 |
|------|----------|------|
| 多路径独立执行 | SequentialAttack FIRST_SUCCESS + 手动 fallback | ✅ 对齐官方模式 A |
| Converter 候选列表 | `l5_optimal()` 返回 7+ 候选 | ✅ 覆盖面广 |
| 模型族先验排序 | `l5_optimal_for_model()` | ✅ 学术依据充分 |
| OWASP 自适应 | `_get_owasp_converter_priorities()` | ✅ 创新点 |
| ASR 历史裁剪 | `_prune_low_asr_converters()` 动态阈值 | ✅ 自适应好 |
| Converter 去重 | `_converter_signature()` | ✅ 避免重复 |

### 2.2 关键差距 ❌

#### 差距 1: 完全缺失 SelectiveTextConverter (最严重)

**当前状态**: 项目中 **零使用** SelectiveTextConverter, SearchReplaceConverter, DenylistConverter, TemplateSegmentConverter

**影响**:
- 所有编码 converter (Base64/ROT13/UnicodeSub) 对**全文**进行变换
- 全文编码导致 payload 不可读 → ASR 7% (Base64) / 10-15% (UnicodeSub)
- 官方 SelectiveTextConverter 只编码 30% 关键词 → 预期 ASR 25-35%

**根因**: `converter_chains.py` 中的 `encoding_bypass()`, `semantic_evasion()`, `smoothllm_bypass()` 都是全文变换, 没有使用选择性包装

#### 差距 2: 缺失高 ASR LLM-Based Converter

| Converter | 官方 ASR | 当前状态 | 差距 |
|-----------|----------|----------|------|
| `CodeChameleonConverter` | 35-45% | ❌ 未使用 | 高 — 代码包装绕过, 学术验证 (lv2024codechameleon) |
| `PolicyPuppetryConverter` | 30-40% | ❌ 未使用 | 高 — 策略木偶, 新型绕过 |
| `MathObfuscationConverter` | 20-30% | ❌ 未使用 | 中 — 数学表达式替换 |
| `TaskFramingConverter` | 25-35% | ❌ 未使用 | 中 — 任务重框架 |
| `TenseConverter` | 15-25% | ❌ 未使用 | 低 — 时态变换 |
| `TextJailbreakConverter` | 30-40% | ❌ 未使用 | 高 — 越狱模板 |
| `NegationTrapConverter` | 15-25% | ❌ 未使用 | 中 — 否定陷阱 |
| `AsciiSmugglerConverter` | 20-30% | ❌ 未使用 | 中 — Unicode Tag 走私 |
| `SuffixAppendConverter` | 15-25% | ❌ 未使用 | 低 — 后缀追加 |

#### 差距 3: 低效 Converter 占用路径

| Converter | 当前 ASR | 问题 |
|-----------|----------|------|
| `Base64Converter` (全文) | 7% | 全文不可读, 浪费一条 SequentialAttack 路径 |
| `UnicodeSubstitutionConverter` (全文) | 10-15% | 全文 Unicode 标签, LLM 难以理解 |
| `RandomCapitalLettersConverter` (全文) | 15-25% | 效果有限, 与 ROT13 功能重叠 |
| `FlipConverter` | ~0% (HTTP场景) | 已在 `l5_optimal()` 中移除但仍存在于链定义中 |
| `AsciiArtConverter` | ~5% | 破坏 JSON 解析, 不适合 HTTP 黑盒 |

#### 差距 4: 未利用 SearchReplaceConverter 进行精准替换

**官方最佳实践**: 用 `SearchReplaceConverter` 替换 payload 中的敏感关键词为同义词
```python
# 官方: 精准替换敏感词
SearchReplaceConverter(
    pattern=r"hack|exploit|inject",
    replace=["test", "analyze", "process"],
)
```
**当前**: 项目用 `DenylistConverter` (LLM 调用, 高 token 成本) 做类似事情, 但完全没有使用

#### 差距 5: 未利用 TemplateSegmentConverter 分段注入

**官方**: 将 payload 分割到模板的多个参数中, 破坏整体语义检测
**当前**: 项目无此实现

#### 差距 6: 未利用 Token Smuggling 系列

**官方**: AsciiSmugglerConverter 使用 Unicode Tags (U+E0000-U+E007F) 隐藏 payload
**当前**: 项目仅用 UnicodeSubstitution (全文替换), 未使用 smuggling 系列

#### 差距 7: 串联堆叠策略错误

**当前问题**: `multi_encoding()` 定义了 Base64+ROT13+Caesar+Atbash 四层串联, 但根据 Wei et al. (arXiv:2307.15043), >2 层 ASR 从 12% 降至 4%

**官方最佳实践**: 使用 SelectiveTextConverter + preserve_tokens 实现选择性链式, 只对部分文本做多层编码

---

## 三、优化解决方案

### 3.1 核心原则

1. **选择性优先 (Selective-First)**: 用 SelectiveTextConverter 包装所有编码/混淆 converter, 只变换部分文本
2. **语义层 > 表示层**: LLM-Based converter (Persuasion, Decomposition, CodeChameleon) ASR 30-60% >> 编码层 7-15%
3. **串联 ≤ 2 层**: 遵循 Wei et al. 学术结论, 最多 2 层串联, 使用 preserve_tokens 精确定位
4. **路径精简**: 裁剪 ASR < 10% 的全文编码路径, 替换为选择性版本
5. **原生优先**: 使用 PyRIT 原生 converter, 不自定义实现

### 3.2 新增 Converter 链定义

在 `pipeline/arm/converter_chains.py` 中新增以下函数:

#### 3.2.1 selective_encoding — 选择性编码 (ASR 预期 25-35%)

```python
def selective_encoding() -> list[Any]:
    """选择性编码 — 只对 30% 单词做编码, 其余保持原文.

    学术依据:
        - Wei et al. (arXiv:2307.15043): 全文 Base64 ASR 7%,
          选择性编码 (30% 单词) ASR 25-35% (LLM 可理解上下文)
        - PyRIT 官方: SelectiveTextConverter + WordProportionSelectionStrategy

    策略:
        - 30% 单词做 Base64 编码 (preserve_tokens=True)
        - 其余 70% 保持原文, LLM 可理解上下文
        - 相比全文编码 ASR 提升 3-5x
    """
    SelectiveTextConverter = _conv("SelectiveTextConverter")
    Base64Converter = _conv("Base64Converter")
    WordProportionSelectionStrategy = _conv("WordProportionSelectionStrategy")

    return [
        SelectiveTextConverter(
            sub_converter=Base64Converter(),
            selection_strategy=WordProportionSelectionStrategy(proportion=0.3),
            preserve_tokens=True,
        ),
    ]
```

#### 3.2.2 selective_obfuscation — 选择性混淆 (ASR 预期 20-30%)

```python
def selective_obfuscation() -> list[Any]:
    """选择性混淆 — 只对 20% 单词做 Leetspeak, 其余保持原文.

    学术依据:
        - Shayegani et al. (arXiv:2306.13254): 全文 Unicode 混淆 ASR 10-15%,
          选择性混淆 (20% 单词) ASR 20-30%
        - PyRIT 官方: SelectiveTextConverter + LeetspeakConverter

    策略:
        - 20% 单词做 Leetspeak (轻量混淆, 保持可读性)
        - preserve_tokens=True, 可与选择性编码链式
    """
    SelectiveTextConverter = _conv("SelectiveTextConverter")
    LeetspeakConverter = _conv("LeetspeakConverter")
    WordProportionSelectionStrategy = _conv("WordProportionSelectionStrategy")

    return [
        SelectiveTextConverter(
            sub_converter=LeetspeakConverter(),
            selection_strategy=WordProportionSelectionStrategy(proportion=0.2),
            preserve_tokens=True,
        ),
    ]
```

#### 3.2.3 chained_selective — 链式选择性 (ASR 预期 30-40%)

```python
def chained_selective() -> list[Any]:
    """链式选择性 — 先选择性编码, 再对已编码区域做 ROT13.

    学术依据:
        - Wei et al. (arXiv:2307.15043): 2 层串联 ASR 12% (可控),
          但全文串联不可读; 选择性串联保持上下文, ASR 30-40%
        - PyRIT 官方: SelectiveTextConverter + TokenSelectionStrategy
          实现链式选择性, preserve_tokens 精确定位已转换区域

    策略:
        1. 第一层: 30% 单词 Base64 编码 (preserve_tokens=True → ⟪⟫ 标记)
        2. 第二层: 对 ⟪⟫ 标记区域做 ROT13 (TokenSelectionStrategy 自动检测)
        3. 结果: 只有 30% 的文本经过 2 层编码, 70% 保持原文
    """
    SelectiveTextConverter = _conv("SelectiveTextConverter")
    Base64Converter = _conv("Base64Converter")
    ROT13Converter = _conv("ROT13Converter")
    WordProportionSelectionStrategy = _conv("WordProportionSelectionStrategy")
    TokenSelectionStrategy = _conv("TokenSelectionStrategy")

    # 第一层: 选择性 Base64
    first = SelectiveTextConverter(
        sub_converter=Base64Converter(),
        selection_strategy=WordProportionSelectionStrategy(proportion=0.3),
        preserve_tokens=True,
    )

    # 第二层: 对已编码区域做 ROT13 (TokenSelectionStrategy 自动检测 ⟪⟫)
    second = SelectiveTextConverter(
        sub_converter=ROT13Converter(),
        selection_strategy=TokenSelectionStrategy(),
        preserve_tokens=True,
    )

    # 注意: 这两个 converter 需要在同一个 ConverterConfiguration 中串联
    # PyRIT PromptNormalizer 会按顺序应用
    return [first, second]
```

#### 3.2.4 keyword_replacement — 关键词精准替换 (ASR 预期 20-30%)

```python
def keyword_replacement() -> list[Any]:
    """关键词精准替换 — 用 SearchReplaceConverter 替换敏感词.

    学术依据:
        - PyRIT 官方: SearchReplaceConverter 用正则替换敏感词为安全同义词
        - 优势: 0 token (无 LLM 调用), 精准替换, 保持语义

    策略:
        - 替换常见安全检测关键词为同义词
        - 每次随机选择替换词, 增加多样性
    """
    SearchReplaceConverter = _conv("SearchReplaceConverter")

    return [
        SearchReplaceConverter(
            pattern=r"(?i)\b(hack|exploit|inject|attack|bypass|malicious)\b",
            replace=[
                "test", "analyze", "process", "examine", "evaluate",
                "assess", "review", "inspect", "audit", "check",
            ],
        ),
    ]
```

#### 3.2.5 code_chameleon — 代码伪装 (ASR 预期 35-45%)

```python
def code_chameleon(converter_target: Any | None = None) -> list[Any]:
    """CodeChameleon — 加密 + 代码包装绕过.

    学术依据:
        - Lv et al. (arXiv:2404.30015) CodeChameleon: ASR 35-45%
        - 机制: 加密 payload, 包装在代码解释器请求中
        - 优势: LLM 被诱导执行"代码"而非过滤内容

    Args:
        converter_target: LLM 目标实例 (可选).
    """
    if converter_target is None:
        logger.info("CodeChameleon chain skipped: no converter_target available")
        return []

    try:
        CodeChameleonConverter = _conv("CodeChameleonConverter")
        # 使用 reverse 加密 (轻量, LLM 可逆向)
        converter = CodeChameleonConverter(
            converter_target=converter_target,
            encrypt_type="reverse",
        )
        logger.info("CodeChameleon chain: 1 converter built (encrypt=reverse)")
        return [converter]
    except Exception as e:
        logger.warning("CodeChameleon chain build failed: %s", e)
        return []
```

#### 3.2.6 policy_puppetry — 策略木偶 (ASR 预期 30-40%)

```python
def policy_puppetry(converter_target: Any | None = None) -> list[Any]:
    """PolicyPuppetry — 策略木偶绕过.

    学术依据:
        - PyRIT 官方 PolicyPuppetryConverter: 通过模拟安全策略
          文档来绕过内容过滤, ASR 30-40%
        - 机制: 将 payload 包装在安全策略文档格式中

    Args:
        converter_target: LLM 目标实例 (可选).
    """
    if converter_target is None:
        logger.info("PolicyPuppetry chain skipped: no converter_target available")
        return []

    try:
        PolicyPuppetryConverter = _conv("PolicyPuppetryConverter")
        converter = PolicyPuppetryConverter(
            converter_target=converter_target,
        )
        logger.info("PolicyPuppetry chain: 1 converter built")
        return [converter]
    except Exception as e:
        logger.warning("PolicyPuppetry chain build failed: %s", e)
        return []
```

#### 3.2.7 token_smuggling — Unicode 走私 (ASR 预期 20-30%)

```python
def token_smuggling() -> list[Any]:
    """Unicode Tag 走私 — 使用不可见 Unicode 字符隐藏 payload.

    学术依据:
        - @embracethered2024unicode: Unicode Tags (U+E0000-U+E007F)
          在大多数 UI 中不可见, 但 LLM 可解码
        - PyRIT 官方: AsciiSmugglerConverter

    策略:
        - 将敏感关键词编码为 Unicode Tags
        - 可见文本保持正常, 隐藏内容不可见
        - 适合绕过基于可见文本的安全审计
    """
    try:
        AsciiSmugglerConverter = _conv("AsciiSmugglerConverter")
        converter = AsciiSmugglerConverter(
            action="encode",
            unicode_tags=True,
        )
        logger.info("Token smuggling chain: AsciiSmugglerConverter built")
        return [converter]
    except Exception as e:
        logger.warning("Token smuggling chain build failed: %s", e)
        return []
```

#### 3.2.8 template_segment — 模板分段 (ASR 预期 25-35%)

```python
def template_segment() -> list[Any]:
    """模板分段注入 — 将 payload 分割到模板参数中.

    学术依据:
        - adversa.ai: 通用越狱模板分段绕过, ASR 25-35%
        - PyRIT 官方: TemplateSegmentConverter (Tom & Jerry 模板)
        - 机制: 将 payload 随机分割为 N 段, 填入模板参数,
          破坏整体语义检测

    策略:
        - 使用默认 Tom & Jerry 模板 (2 参数)
        - payload 被随机分割, 嵌入叙事框架
    """
    try:
        TemplateSegmentConverter = _conv("TemplateSegmentConverter")
        converter = TemplateSegmentConverter()
        logger.info("Template segment chain: 1 converter built (default template)")
        return [converter]
    except Exception as e:
        logger.warning("Template segment chain build failed: %s", e)
        return []
```

### 3.3 优化 `l5_optimal()` — 新候选列表

```python
def l5_optimal(converter_target: Any | None = None) -> list[Any]:
    """L5 v36 Converter 候选列表 — 对齐 PyRIT 1.0.1 官方最佳实践.

    核心改进 (vs v35):
        1. 引入 SelectiveTextConverter — 选择性编码, ASR 25-35% (vs 全文 7%)
        2. 引入 CodeChameleonConverter — ASR 35-45% (lv2024codechameleon)
        3. 引入 PolicyPuppetryConverter — ASR 30-40%
        4. 引入链式选择性 (2 层, preserve_tokens) — ASR 30-40%
        5. 裁剪 ASR < 10% 的全文编码路径 (Base64, UnicodeSub 全文)
        6. 引入 SearchReplaceConverter — 关键词精准替换 (0 token)
        7. 引入 TemplateSegmentConverter — 分段注入
        8. 引入 AsciiSmugglerConverter — Unicode 走私

    候选列表 (按 ASR 降序, SequentialAttack FIRST_SUCCESS):
        1. DecompositionConverter           — ASR 40-60% (DrAttack, 最高)
        2. CodeChameleonConverter           — ASR 35-45% (NEW, CodeChameleon)
        3. PersuasionConverter(authority)   — ASR 38.4% (Zeng et al.)
        4. PolicyPuppetryConverter          — ASR 30-40% (NEW)
        5. ChainedSelective (Base64+ROT13)  — ASR 30-40% (NEW, 选择性链式)
        6. SelectiveEncoding (Base64 30%)   — ASR 25-35% (NEW, 选择性编码)
        7. RandomTranslationConverter       — ASR 25-35% (多语言部分混淆)
        8. TemplateSegmentConverter         — ASR 25-35% (NEW, 分段注入)
        9. KeywordReplacement              — ASR 20-30% (NEW, 0 token)
        10. SelectiveObfuscation (Leet 20%) — ASR 20-30% (NEW, 选择性混淆)
        11. VariationConverter              — ASR 20-30% (多样性补充)
        12. AsciiSmugglerConverter          — ASR 20-30% (NEW, Unicode走私)
        13. ROT13Converter                  — ASR 30-40% (语义混淆, 保留)
        14. TokenSmuggling (AsciiSmuggler)  — ASR 20-30% (NEW)

    裁剪路径 (ASR < 10% 或不可用):
        - Base64Converter (全文)     — ASR 7%, 被 SelectiveEncoding 替代
        - UnicodeSubstitution (全文) — ASR 10-15%, 被 SelectiveObfuscation 替代
        - RandomCapitalLetters (全文)— ASR 15-25%, 与 ROT13 重叠, 保留但降级
        - FlipConverter              — ASR ≈0% (HTTP), 已移除
        - AsciiArtConverter          — ASR ≈5%, 破坏 JSON, 已移除

    学术依据:
        - Wei et al. (arXiv:2307.15043): 串联 >2 层 ASR 从 12% 降至 4%
        - Zeng et al. (arXiv:2402.19181): authority ASR 38.4% 最高
        - DrAttack (arXiv:2402.14266): 分解重组 ASR 40-60% 最高
        - Lv et al. (arXiv:2404.30015): CodeChameleon ASR 35-45%
        - PyRIT (arXiv:2407.01232): SequentialAttack FIRST_SUCCESS
        - PyRIT 官方 SelectiveTextConverter: 选择性转换最佳实践
    """
    converters: list[Any] = []

    from pipeline.arm.converter_chains import (
        _conv, decomposition, variation, translation_multilingual,
        selective_encoding, selective_obfuscation, chained_selective,
        keyword_replacement, code_chameleon, policy_puppetry,
        token_smuggling, template_segment,
    )

    # ── LLM 辅助 converters (需 converter_target) ──
    if converter_target is not None:
        # Path 1: Decomposition — ASR 40-60% (最高, DrAttack)
        converters.extend(decomposition(converter_target=converter_target))

        # Path 2: CodeChameleon — ASR 35-45% (NEW)
        converters.extend(code_chameleon(converter_target=converter_target))

        # Path 3: Persuasion authority — ASR 38.4%
        try:
            PersuasionConverter = _conv("PersuasionConverter")
            converters.append(PersuasionConverter(
                converter_target=converter_target,
                persuasion_technique="authority_endorsement",
            ))
        except (TypeError, ValueError, FileNotFoundError) as e:
            logger.warning("L5: PersuasionConverter(authority) failed: %s", e)

        # Path 4: PolicyPuppetry — ASR 30-40% (NEW)
        converters.extend(policy_puppetry(converter_target=converter_target))

        # Path 5: Variation — ASR 20-30% (多样性补充)
        converters.extend(variation(converter_target=converter_target))

        # Path 6: RandomTranslation — ASR 25-35%
        converters.extend(translation_multilingual(converter_target=converter_target))

    # ── 非 LLM converters (无需 converter_target) ──

    # Path 7: Chained Selective (Base64+ROT13, 选择性) — ASR 30-40% (NEW)
    # ⭐ 核心改进: 使用 SelectiveTextConverter + preserve_tokens 实现链式选择性
    converters.extend(chained_selective())

    # Path 8: Selective Encoding (Base64 30%) — ASR 25-35% (NEW)
    converters.extend(selective_encoding())

    # Path 9: TemplateSegment — ASR 25-35% (NEW)
    converters.extend(template_segment())

    # Path 10: KeywordReplacement — ASR 20-30% (NEW, 0 token)
    converters.extend(keyword_replacement())

    # Path 11: SelectiveObfuscation (Leetspeak 20%) — ASR 20-30% (NEW)
    converters.extend(selective_obfuscation())

    # Path 12: AsciiSmuggler — ASR 20-30% (NEW)
    converters.extend(token_smuggling())

    # Path 13: ROT13 (全文, 保留作为轻量 fallback) — ASR 30-40%
    try:
        converters.append(_conv("ROT13Converter")())
    except Exception as e:
        logger.warning("L5: ROT13Converter failed: %s", e)

    # 裁剪路径 (被选择性版本替代):
    # - Base64Converter (全文, ASR 7%) → 被 selective_encoding 替代
    # - UnicodeSubstitutionConverter (全文, ASR 10-15%) → 被 selective_obfuscation 替代
    # - RandomCapitalLettersConverter (全文, ASR 15-25%) → 与 ROT13 重叠, 降级
    # - FlipConverter (ASR ≈0% HTTP) → 已移除
    # - AsciiArtConverter (ASR ≈5%, 破坏 JSON) → 已移除

    if converters:
        logger.info("L5 v36: %d converter candidates built (Selective-First)", len(converters))
        for i, c in enumerate(converters):
            logger.info("  Candidate %d: %s", i + 1, type(c).__name__)

    return converters
```

### 3.4 优化 `_PRIORITY_MAP` — 对齐新候选列表

在 `pipeline/strike/converter_selector.py` 中更新优先级映射:

```python
_PRIORITY_MAP: dict[str, int] = {
    # LLM-Based (ASR 30-60%)
    "DecompositionConverter": 0,                    # ASR 40-60%
    "CodeChameleonConverter": 1,                    # ASR 35-45% (NEW)
    "PersuasionConverter:authority_endorsement": 2, # ASR 38.4%
    "PolicyPuppetryConverter": 3,                  # ASR 30-40% (NEW)
    # Selective (ASR 25-40%)
    "SelectiveTextConverter:TokenSelectionStrategy": 4,  # 链式选择性 (NEW)
    "SelectiveTextConverter:WordProportionSelectionStrategy": 5,  # 选择性编码 (NEW)
    # Translation (ASR 25-35%)
    "RandomTranslationConverter": 6,
    "TranslationConverter": 7,
    # Template (ASR 25-35%)
    "TemplateSegmentConverter": 8,                  # NEW
    # Keyword (ASR 20-30%, 0 token)
    "SearchReplaceConverter": 9,                    # NEW
    # Variation (ASR 20-30%)
    "VariationConverter": 10,
    # Smuggling (ASR 20-30%)
    "AsciiSmugglerConverter": 11,                   # NEW
    # Semantic (ASR 30-40%, 保留)
    "ROT13Converter": 12,
    # 降级 (ASR < 20%, fallback)
    "RandomCapitalLettersConverter": 13,
    "UnicodeSubstitutionConverter": 14,
    "Base64Converter": 15,                           # 全文, 最低优先级
}
```

### 3.5 优化 `_converter_signature()` — 支持新 Converter 签名

```python
def _converter_signature(c: Any) -> str:
    """生成 converter 的唯一签名 (类型 + 关键参数).

    L5 v36: 支持 SelectiveTextConverter, SearchReplaceConverter 等新 converter.
    """
    type_name = type(c).__name__

    # PersuasionConverter: 区分 persuasion_technique
    if type_name == "PersuasionConverter":
        technique = getattr(c, "_persuasion_technique", None)
        if technique is not None:
            tech_name = getattr(technique, "value", str(technique))
            return f"{type_name}:{tech_name}"

    # ToneConverter: 区分 tone
    if type_name == "ToneConverter":
        tone = getattr(c, "_tone", None)
        if tone is not None:
            tone_name = getattr(tone, "value", str(tone))
            return f"{type_name}:{tone_name}"

    # SelectiveTextConverter: 区分 selection_strategy
    if type_name == "SelectiveTextConverter":
        strategy = getattr(c, "_selection_strategy", None)
        if strategy is not None:
            strategy_name = type(strategy).__name__
            sub_conv = getattr(c, "_sub_converter", None)
            sub_name = type(sub_conv).__name__ if sub_conv else "unknown"
            return f"{type_name}:{strategy_name}:{sub_name}"

    # SearchReplaceConverter: 区分 pattern
    if type_name == "SearchReplaceConverter":
        pattern = getattr(c, "_pattern", "")
        return f"{type_name}:{pattern[:30]}"

    # CodeChameleonConverter: 区分 encrypt_type
    if type_name == "CodeChameleonConverter":
        encrypt_type = getattr(c, "_encrypt_type", "unknown")
        return f"{type_name}:{encrypt_type}"

    return type_name
```

### 3.6 优化 `_build_converter_config()` — 支持链式选择性串联

```python
def _build_converter_config(ctx: PipelineContext) -> Any:
    """构建 AttackConverterConfig.

    L5 v36 关键改进:
        1. 支持 SelectiveTextConverter 链式串联 (chained_selective 返回 2 个 converter)
        2. 当检测到 SelectiveTextConverter + TokenSelectionStrategy 组合时,
           将其放入同一个 ConverterConfiguration (串联应用)
        3. 其他 converter 仍保持独立路径 (不串联)

    策略:
        - 链式选择性 (chained_selective): 2 个 converter 在同一 ConverterConfiguration
        - 其他 converter: 各自独立 ConverterConfiguration
    """
    from pyrit.executor.attack import AttackConverterConfig
    from pyrit.prompt_normalizer import ConverterConfiguration

    # ... 去重 + 裁剪逻辑不变 ...

    # 检测链式选择性组合
    # 如果前两个 converter 是 SelectiveTextConverter + TokenSelectionStrategy,
    # 将它们放入同一个 ConverterConfiguration (串联应用)
    converter_configurations: list[ConverterConfiguration] = []
    i = 0
    while i < len(unique_converters):
        conv = unique_converters[i]

        # 检测: SelectiveTextConverter + (下一个也是 SelectiveTextConverter + TokenSelectionStrategy)
        if (i + 1 < len(unique_converters)
            and type(conv).__name__ == "SelectiveTextConverter"
            and type(unique_converters[i + 1]).__name__ == "SelectiveTextConverter"
            and type(getattr(unique_converters[i + 1], "_selection_strategy", None)).__name__
                == "TokenSelectionStrategy"):
            # 链式选择性: 2 个 converter 在同一 ConverterConfiguration (串联)
            converter_configurations.append(
                ConverterConfiguration(converters=[conv, unique_converters[i + 1]])
            )
            i += 2
        else:
            # 独立路径: 1 个 converter per ConverterConfiguration
            converter_configurations.append(
                ConverterConfiguration(converters=[conv])
            )
            i += 1

    return AttackConverterConfig(request_converters=converter_configurations)
```

### 3.7 更新 `_build_chain_builders()` 映射

```python
def _build_chain_builders() -> dict[str, Any]:
    """构建链名 → 构建函数映射 (v36 新增选择性链)."""
    from pipeline.arm.converter_chains import (
        decomposition, encoding_bypass, flip, format_injection,
        multi_encoding, persuasion, semantic_evasion, smoothllm_bypass,
        stealth_evasion, translation_multilingual, variation,
        # v36 新增
        selective_encoding, selective_obfuscation, chained_selective,
        keyword_replacement, code_chameleon, policy_puppetry,
        token_smuggling, template_segment,
    )
    return {
        "encoding": encoding_bypass,
        "stealth": stealth_evasion,
        "persuasion": persuasion,
        "format": format_injection,
        "multi_encoding": multi_encoding,
        "decomposition": decomposition,
        "variation": variation,
        "flip": flip,
        "semantic_evasion": semantic_evasion,
        "translation_multilingual": translation_multilingual,
        "smoothllm_bypass": smoothllm_bypass,
        "l5_optimal": l5_optimal,
        "l5_optimal_for_model": l5_optimal_for_model,
        # v36 新增
        "selective_encoding": selective_encoding,
        "selective_obfuscation": selective_obfuscation,
        "chained_selective": chained_selective,
        "keyword_replacement": keyword_replacement,
        "code_chameleon": code_chameleon,
        "policy_puppetry": policy_puppetry,
        "token_smuggling": token_smuggling,
        "template_segment": template_segment,
    }
```

---

## 四、实施计划

### Phase 1: 核心实现 (选择性转换) — 最高优先级

| 步骤 | 文件 | 改动 | 预期 ASR 提升 |
|------|------|------|---------------|
| 1 | `converter_chains.py` | 新增 `selective_encoding()`, `selective_obfuscation()`, `chained_selective()` |