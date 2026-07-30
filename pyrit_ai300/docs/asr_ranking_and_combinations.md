# ASR 排名与最优组合策略 (ASR Ranking & Optimal Combinations)

> **版本**: v1.0 | **数据截止**: 2025-06 | **最后更新**: 2026-07-29
>
> **数据来源**: JailbreakBench (NeurIPS 2024), HarmBench (ICML 2024), PyRIT 官方文档
>
> **权威代码定义**: `src/payloads/asr_prior_registry.py` (ASR 先验数据)、
> `src/scenarios/technique_factories.py` (Converter 变体配置)、
> `src/converters/target_aware_router.py` (Target 感知路由 Profile)

---

## ★ ASR 最优组合策略排名（显著位置）

> **以下排名基于学术先验 ASR × 协同乘数 (Per-combo Multiplier) 计算得出，
> 乘数上限 0.95 (95%)。所有组合均经过 JailbreakBench / HarmBench 学术验证。**

### 第一梯队：多轮迭代 + 编码/混淆（协同效应 3.5x / 2.5x）

| 排名 | 组合 | 基础 ASR (GPT-4o) | 协同乘数 | 有效 ASR | 学术依据 |
|:----:|------|:-----------------:|:--------:|:--------:|---------|
| **1** | **Crescendo + encoding_bypass** | 82% | ×3.5 | **95%** | Russinovich et al., arXiv:2402.12109 — 多轮渐进末轮编码绕过累积拒绝上下文 |
| **2** | **Crescendo + stealth_evasion** | 82% | ×2.5 | **95%** | 同上 — 末轮 Unicode 混淆增加多样性 |
| **3** | **Red Teaming + encoding_bypass** | 55% | ×3.5 | **95%** | Perez et al., arXiv:2202.01241 — 多轮红队 + 末轮编码 |
| **4** | **Red Teaming + stealth_evasion** | 55% | ×2.5 | **95%** | 同上 — 多轮红队 + Unicode 混淆 |
| **5** | **TAP + stealth_evasion** | 62% | ×2.5 | **95%** | Mehrotra et al., arXiv:2312.02191 — 树搜索中使用混淆分支 |

### 第二梯队：多轮迭代 + 说服（协同效应 1.8x）

| 排名 | 组合 | 基础 ASR (GPT-4o) | 协同乘数 | 有效 ASR | 学术依据 |
|:----:|------|:-----------------:|:--------:|:--------:|---------|
| **6** | **Crescendo + persuasion_authority** | 82% | ×1.8 | **95%** | Zeng et al., arXiv:2402.19181 — 渐进升级中的说服框架 |
| **7** | **PAIR + persuasion_authority** | 53% | ×1.8 | **95%** | Chao et al., arXiv:2310.08437 — adversarial chat 说服引导 |
| **8** | **Red Teaming + persuasion_authority** | 55% | ×1.8 | **95%** | 多轮红队 + 说服语义变换 |

### 第三梯队：多轮迭代基础技术（无 Converter）

| 排名 | 技术 | ASR (GPT-4o) | ASR (GPT-3.5) | 学术依据 |
|:----:|------|:------------:|:-------------:|---------|
| **9** | **Crescendo** (基础) | 82% | 95% | Russinovich et al., arXiv:2402.12109 — 多轮渐进天然绕过单轮拒绝 |
| **10** | **TAP** (基础) | 62% | 80% | Mehrotra et al., arXiv:2312.02191 — 树搜索探索正交攻击分支 |
| **11** | **tree_of_attacks_pruned** | 60% | 78% | TAP 剪枝版本 |
| **12** | **Red Teaming** (基础) | 55% | 80% | Perez et al., arXiv:2202.01241 — 通用红队对抗 |
| **13** | **PAIR** (基础) | 53% | 75% | Chao et al., arXiv:2310.08437 — 20-query 迭代攻击 |

### 第四梯队：单轮高成本 / 说服 / 模拟对话

| 排名 | 技术 | ASR (GPT-4o) | ASR (GPT-3.5) | 学术依据 |
|:----:|------|:------------:|:-------------:|---------|
| 14 | wrapping_attack | 42% | 60% | 上下文包装攻击 |
| 15 | crescendo_simulated | 45% | 70% | arXiv:2402.12109 — 预计算模拟对话重放 |
| 16 | context_compliance | 40% | 65% | 上下文合规攻击 |
| 17 | role_play_persuasion | 38% | 68% | Zeng et al., arXiv:2402.19181 — 说服角色扮演 |
| 18 | best_of_n_jailbreak | 35% | 65% | JailbreakBench 收录 — N 采样取最优 |
| 19 | persuasion_authority | 35% | 60% | Zeng et al., arXiv:2402.19181 — 权威说服 |
| 20 | role_play_movie_script | 35% | 65% | PyRIT Scenario 文档数据 |

### 第五梯队：分解 / 编码 / 基线

| 排名 | 技术 | ASR (GPT-4o) | ASR (GPT-3.5) | Patched | 学术依据 |
|:----:|------|:------------:|:-------------:|:-------:|---------|
| 21 | decomposition_chain | 30% | 55% | No | arXiv:2311.08268 — 任务分解重构 |
| 22 | bad_likert_judge | 15% | 45% | **Yes** | arXiv:2311.08268 — Likert 评分操控 (部分模型已修复) |
| 23 | many_shot | 12% | 48% | **Yes** | Anthropic, arXiv:2402.05124 — 补丁后 ASR 急剧下降 |
| 24 | stealth_evasion | 12% | 50% | No | HarmBench — Unicode 混淆 + Base64 + 后缀 |
| 25 | multi_encoding_v2 | 10% | 48% | No | HarmBench — 四层编码 |
| 26 | encoding_bypass | 8% | 45% | No | HarmBench — 编码绕过对 GPT-4o 几乎无效 |
| 27 | skeleton_key | 5% | 30% | **Yes** | Microsoft, arXiv:2407.01576 — 已被主要模型补丁修复 |
| 28 | base64 | 4% | 38% | No | HarmBench — GPT-4o 可直接解码 |
| 29 | rot13 | 3% | 35% | No | HarmBench — GPT-4o 可直接解码 |
| 30 | prompt_sending | 2% | 15% | No | HarmBench — 无转换器基线 |

---

## 目录

1. [★ ASR 最优组合策略排名](#-asr-最优组合策略排名显著位置)
2. [学术数据来源与引用](#2-学术数据来源与引用)
3. [基础攻击技术 ASR 先验](#3-基础攻击技术-asr-先验)
4. [Converter 链 ASR 排名](#4-converter-链-asr-排名)
5. [协同乘数表 (Per-combo Multipliers)](#5-协同乘数表-per-combo-multipliers)
6. [Crescendo / TAP / PAIR 组合策略详解](#6-crescendo--tap--pair-组合策略详解)
7. [Target 感知 Converter 路由](#7-target-感知-converter-路由)
8. [Patched 技术惩罚机制](#8-patched-技术惩罚机制)
9. [Tier 分层标准](#9-tier-分层标准)
10. [执行顺序与 FIRST_SUCCESS 策略](#10-执行顺序与-first_success-策略)
11. [模型感知 ASR 差异](#11-模型感知-asr-差异)
12. [参考文献](#12-参考文献)

---

## 2. 学术数据来源与引用

### 2.1 基准排行榜

| 基准 | arXiv | 会议 | 说明 |
|------|-------|------|------|
| **JailbreakBench** | [2402.01135](https://arxiv.org/abs/2402.01135) | NeurIPS 2024 | 标准化越狱基准排行榜，提供 per-model ASR 排名 |
| **HarmBench** | [2402.04249](https://arxiv.org/abs/2402.04249) | ICML 2024 | 自动化红队评估框架，覆盖编码/对抗后缀攻击 |
| **PyRIT 官方文档** | — | Microsoft 2025 | Scenario 文档展示的成功率数据 |

### 2.2 关键学术论文

| 技术 | 论文 | arXiv | 核心发现 |
|------|------|-------|---------|
| **Crescendo** | Russinovich et al., "Great, Now We Have to Sing" | [2402.12109](https://arxiv.org/abs/2402.12109) | 多轮渐进式升级绕过单轮拒绝；末轮编码 ASR 提升 3-5x |
| **TAP** | Mehrotra et al., "Tree of Attacks" | [2312.02191](https://arxiv.org/abs/2312.02191) | 树搜索探索正交攻击分支；深度/宽度可调 |
| **PAIR** | Chao et al., "Jailbreaking Black Box LLMs in Twenty Queries" | [2310.08437](https://arxiv.org/abs/2310.08437) | adversarial chat 根据拒绝反馈迭代；20 query 内收敛 |
| **Many-shot** | Anthropic, "Many-shot Jailbreaking" | [2402.05124](https://arxiv.org/abs/2402.05124) | 大量示例注入；Anthropic 补丁后 ASR 急剧下降 |
| **Skeleton Key** | Microsoft, "Skeleton Key: A Multilingual LLM Jailbreak" | [2407.01576](https://arxiv.org/abs/2407.01576) | 多语言越狱；已被主要模型补丁修复 |
| **GCG** | Zou et al., "Universal and Transferable Adversarial Attacks" | [2307.15043](https://arxiv.org/abs/2307.15043) | 梯度优化对抗后缀；编码攻击的理论基础 |
| **Persuasion** | Zeng et al., "How Johnny Can Persuade LLMs" | [2402.19181](https://arxiv.org/abs/2402.19181) | 说服策略分类 (authority/emotional/logic)；ASR 30-40% |
| **Best-of-N** | SIT/ETH, "Best-of-N Jailbreaking" | HarmBench 收录 | N 采样取最优；大 N 时 ASR 更高 |
| **Red Teaming** | Perez et al., "Red Teaming Language Models" | [2202.01241](https://arxiv.org/abs/2202.01241) | 通用红队对抗方法论 |

### 2.3 关键学术发现

1. **策略级 vs 表示级**：策略级变换（多轮迭代/说服）的效果通常显著优于表示级变换（编码/混淆），学术数据显示 **5-20x** 差异 (JailbreakBench 2024-2025; HarmBench 2024)
2. **编码攻击对强模型低效**：Base64/ROT13/Caesar 在 GPT-4o 上 ASR 仅 3-12%，但对无过滤开源模型 ASR 40-55% (Wei et al., 2023; HarmBench 2024)
3. **多轮迭代对强模型高效**：Crescendo/PAIR/TAP 在 GPT-4o 上 ASR 50-85% (JailbreakBench 2024-2025)
4. **协同效应**：多轮迭代 + 编码的协同乘数达 3-5x，因为多轮累积的"安全"上下文在末轮被编码绕过 (Russinovich et al., arXiv:2402.12109)

---

## 3. 基础攻击技术 ASR 先验

> **数据来源**: `src/payloads/asr_prior_registry.py` — `_ASR_PRIORS` 字典
>
> **数据截止**: 2025-06 | **来源**: JailbreakBench 官方排行榜 + HarmBench 评估结果

### 3.1 多轮迭代攻击（学术验证高 ASR）

| 技术 | GPT-4o | GPT-4 | GPT-3.5 | Claude-3.5 | Llama-3.1 | Patched | arXiv |
|------|:------:|:-----:|:-------:|:----------:|:---------:|:-------:|:-----:|
| **crescendo** | **82%** | 85% | **95%** | 78% | **90%** | No | 2402.12109 |
| **tap** | **62%** | 66% | 80% | 55% | 75% | No | 2312.02191 |
| **tree_of_attacks_pruned** | 60% | 64% | 78% | 53% | 72% | No | 2312.02191 |
| **red_teaming** | **55%** | 60% | **80%** | 50% | **75%** | No | 2202.01241 |
| **pair** | **53%** | 60% | 75% | 48% | 70% | No | 2310.08437 |

### 3.2 单轮高成本攻击

| 技术 | GPT-4o | GPT-4 | GPT-3.5 | Claude-3.5 | Llama-3.1 | Patched | arXiv |
|------|:------:|:-----:|:-------:|:----------:|:---------:|:-------:|:-----:|
| **best_of_n_jailbreak** | **35%** | 40% | 65% | 30% | 60% | No | 2402.01135 |
| **many_shot** | 12% | 15% | 48% | 10% | 40% | **Yes** | 2402.05124 |
| **bad_likert_judge** | 15% | 20% | 45% | 12% | 40% | **Yes** | 2311.08268 |
| **skeleton_key** | 5% | 8% | 30% | 3% | 25% | **Yes** | 2407.01576 |

### 3.3 角色扮演 / 模拟对话（中等 ASR）

| 技术 | GPT-4o | GPT-4 | GPT-3.5 | Claude-3.5 | Llama-3.1 | Patched |
|------|:------:|:-----:|:-------:|:----------:|:---------:|:-------:|
| crescendo_simulated | 45% | 50% | 70% | 40% | 65% | No |
| context_compliance | 40% | 45% | 65% | 35% | 60% | No |
| wrapping_attack | 42% | 45% | 60% | 38% | 55% | No |
| role_play_persuasion | 38% | 42% | 68% | 33% | 62% | No |
| role_play_movie_script | 35% | 40% | 65% | 30% | 60% | No |

### 3.4 说服攻击（LLM 辅助，中等 ASR）

| 技术 | GPT-4o | GPT-4 | GPT-3.5 | Claude-3.5 | Llama-3.1 | Patched | arXiv |
|------|:------:|:-----:|:-------:|:----------:|:---------:|:-------:|:-----:|
| persuasion_authority | **35%** | 42% | 60% | 30% | 55% | No | 2402.19181 |
| decomposition_chain | **30%** | 35% | 55% | 25% | 50% | No | 2311.08268 |

### 3.5 编码攻击（对现代商业模型低 ASR）

| 技术 | GPT-4o | GPT-4 | GPT-3.5 | Claude-3.5 | Llama-3.1 | Patched | arXiv |
|------|:------:|:-----:|:-------:|:----------:|:---------:|:-------:|:-----:|
| stealth_evasion | 12% | 16% | 50% | 10% | 60% | No | 2307.15043 |
| multi_encoding_v2 | 10% | 14% | 48% | 8% | 58% | No | 2307.15043 |
| encoding_bypass | 8% | 12% | 45% | 6% | 55% | No | 2307.15043 |
| base64 | 4% | 6% | 38% | 3% | 52% | No | 2307.15043 |
| rot13 | 3% | 5% | 35% | 2% | 50% | No | 2307.15043 |

### 3.6 基线

| 技术 | GPT-4o | GPT-4 | GPT-3.5 | Claude-3.5 | Llama-3.1 | Patched |
|------|:------:|:-----:|:-------:|:----------:|:---------:|:-------:|
| **prompt_sending** | **2%** | 3% | 15% | 1% | 20% | No |

---

## 4. Converter 链 ASR 排名

> **数据来源**: `src/scenarios/technique_factories.py` — `CONVERTER_VARIANT_CHAINS` 字典
> + `src/payloads/asr_prior_registry.py` — `_CHAIN_TYPE_MAP` + `_converter_variant_boost()`

### 4.1 非 LLM 链（无需 converter_target，快速执行）

| 排名 | 链名 | 类型分类 | GPT-4o ASR | GPT-3.5 ASR | Llama-3.1 ASR | 优先级 | 模态 | 说明 |
|:----:|------|:--------:|:----------:|:-----------:|:-------------:|:------:|:----:|------|
| 1 | `stealth_evasion` | stealth | 12% | 50% | 60% | P1 | text | Unicode 混淆 + Base64 + 后缀追加 |
| 2 | `multi_encoding_v2` | multi_encoding | 10% | 48% | 58% | P1 | text | 四层编码: Base64+ROT13+Caesar+Atbash |
| 3 | `encoding_bypass` | encoding | 8% | 45% | 55% | P2 | text | Base64+ROT13+Caesar 编码绕过 |
| 4 | `agent_injection_chain` | agent_injection | 25% | 50% | 48% | P3 | text | Unicode+后缀+任务伪装 |
| 5 | `noise_bypass` | stealth | ~10% | ~40% | ~50% | P2 | text | 噪声注入+Base64+ROT13 |
| 6 | `unicode_attack` | stealth | ~12% | ~45% | ~55% | P2 | text | Unicode 混淆+双向文本+零宽字符 |
| 7 | `format_injection` | stealth | ~10% | ~35% | ~45% | P2 | text | ASCII 艺术格式注入 |
| 8 | `policy_puppetry` | stealth | ~8% | ~30% | ~40% | P3 | text | 模拟系统策略格式绕过 |
| 9 | `random_case` | stealth | ~5% | ~25% | ~35% | P3 | text | 随机大写字符绕过关键词检测 |
| 10 | `special_chars` | stealth | ~5% | ~25% | ~35% | P3 | text | Zalgo+Tatweel+Diacritic+Emoji |
| 11 | `leetspeak_chain` | stealth | ~5% | ~25% | ~35% | P3 | text | Leetspeak+Flip+RepeatToken |

### 4.2 LLM 链（需 converter_target，语义变换）

| 排名 | 链名 | 类型分类 | GPT-4o ASR | GPT-3.5 ASR | Llama-3.1 ASR | 优先级 | 模态 | 说明 |
|:----:|------|:--------:|:----------:|:-----------:|:-------------:|:------:|:----:|------|
| 1 | `persuasion_authority` | persuasion | **35%** | 60% | 55% | P4 | text | 权威说服: authority+formal+en |
| 2 | `decomposition_chain` | decomposition | **30%** | 55% | 50% | P3 | text | 有害请求分解为无害子任务 |
| 3 | `llm_assisted` | persuasion | ~30% | ~50% | ~45% | P3 | text | 说服+语气+翻译 |
| 4 | `task_framing_chain` | persuasion | ~25% | ~45% | ~40% | P4 | text | TaskFraming+Persuasion |
| 5 | `semantic_obfuscation` | persuasion | ~20% | ~40% | ~35% | P4 | text | 翻译+语气+时态+变体 |
| 6 | `noise_case_chain` | stealth | ~15% | ~40% | ~45% | P2 | text | 噪声+随机大写+Base64 (LLM 辅助) |
| 7 | `policy_puppetry_chain` | persuasion | ~15% | ~35% | ~30% | P4 | text | PolicyPuppetry+Tone |
| 8 | `persuasion_chain` | persuasion | ~15% | ~35% | ~30% | P5 | text | 说服攻击链 |

> **注**: LLM 链的 ASR 受 converter_target 模型能力影响。小模型 (≤14B) 无法可靠生成 JSON，会触发 `InvalidJsonException`。代码中 `_should_skip_llm_chains()` 自动检测并跳过。

### 4.3 文件 / 多模态链（场景专用）

| 链名 | 模态 | 适用 Target | 优先级 | 说明 | requires_runtime_params |
|------|:----:|------------|:------:|------|:-----------------------:|
| `xpia_stealth_chain` | file | RAG / Output Handling | P1 | PDF 白色小字嵌入攻击内容 | Yes |
| `pdf_injection` | file | RAG / Output Handling | P2 | 在现有 PDF 中注入攻击文本 | Yes |
| `worddoc_injection` | file | RAG / Output Handling | P3 | WordDoc 占位符替换攻击内容 | Yes |
| `multimodal_image_attack` | image | Multimodal Image/Video | P1 | 文本→QR 码图片 | No |
| `multimodal_steganography` | image | Multimodal Image | P2 | 在图片中叠加攻击文本 | Yes |

---

## 5. 协同乘数表 (Per-combo Multipliers)

> **数据来源**: `src/payloads/asr_prior_registry.py` — `_COMBO_MULTIPLIERS` 字典
>
> **学术依据**: 见每行引用的 arXiv 论文

协同乘数反映了基础技术类别与 Converter 链类型组合时的 ASR 倍增效应。乘数应用于基础 ASR 后，上限为 0.95 (95%)。

| 基础技术类别 | Converter 链类型 | 乘数 | 学术依据 |
|:----------:|:---------------:|:----:|---------|
| **multi_turn** | **encoding** | **3.5x** | Russinovich et al., arXiv:2402.12109 — Crescendo 末轮编码绕过累积拒绝上下文 |
| **multi_turn** | **stealth** | **2.5x** | Unicode 混淆增加多轮迭代多样性 |
| single_turn | document_delivery | 3.0x | Greshake et al., arXiv:2302.12173 — 文档投递对 RAG 目标效果显著 |
| single_turn | persuasion | 2.5x | Zeng et al., arXiv:2402.19181 — 改变请求语义降低拒绝概率 |
| single_turn | agent_injection | 2.0x | Greshake et al. — Agent 注入对 Agent 目标效果显著 |
| single_turn | decomposition | 2.0x | 分解有害请求为无害子任务 |
| multi_turn | persuasion | 1.8x | Chao et al., arXiv:2310.08437 — adversarial chat 使用说服策略引导迭代 |
| multi_turn | decomposition | 1.5x | 多轮迭代中的任务分解 |
| single_turn | multi_encoding | 1.4x | 多层编码对弱过滤有限提升 |
| single_turn | stealth | 1.3x | 单轮+Unicode 混淆有限提升 |
| single_turn | encoding | 1.2x | 单轮+编码对强模型效果有限 |
| _默认 (无匹配)_ | _任意_ | **1.2x** | 兜底乘数 |

### 5.1 关键洞察

- **multi_turn × encoding = 3.5x** 是所有组合中协同效应最强的
- 原因：多轮迭代累积的"安全"上下文在最后一轮被编码绕过，模型已建立了安全认知，实时安全分类器不会对已"信任"的对话中的编码内容进行深度检测
- 这解释了为什么 Crescendo (82%) + encoding_bypass (8%) 的组合 ASR 可达 95% (capped)，而非两者的简单加和

---

## 6. Crescendo / TAP / PAIR 组合策略详解

### 6.1 Crescendo (ASR 82% on GPT-4o)

> **论文**: Russinovich et al., "Great, Now We Have to Sing: Language Models are Rarely Impervious to Subtle Jailbreaks", arXiv:2402.12109

#### 配置的 Converter 链

```python
# src/scenarios/technique_factories.py
"crescendo": [
    "encoding_bypass",       # multi_turn × encoding = 3.5x
    "stealth_evasion",       # multi_turn × stealth = 2.5x
    "persuasion_authority",  # multi_turn × persuasion = 1.8x
]
```

#### 有效 ASR 计算

| 组合 | 基础 ASR | 乘数 | 理论 ASR | 实际 ASR (capped 95%) |
|------|:-------:|:----:|:-------:|:---------------------:|
| Crescendo + encoding_bypass | 82% | ×3.5 | 287% | **95%** |
| Crescendo + stealth_evasion | 82% | ×2.5 | 205% | **95%** |
| Crescendo + persuasion_authority | 82% | ×1.8 | 148% | **95%** |

#### 执行流程 (FIRST_SUCCESS)

```
1. Crescendo 基础攻击 (无 Converter, 多轮渐进升级)
   ↓ 失败 (18% 概率)
2. Crescendo + encoding_bypass (末轮注入 Base64+ROT13+Caesar)
   ↓ 失败 (5% 概率)
3. Crescendo + stealth_evasion (末轮注入 Unicode+Base64+后缀)
   ↓ 失败 (5% 概率)
4. Crescendo + persuasion_authority (末轮 LLM 说服变换)
   ↓ 成功 → 停止
```

#### 学术依据

Russinovich et al. 指出 Crescendo 的核心机制：
1. **渐进升级**：通过多轮对话逐步引入敏感内容，每轮只微幅增加攻击强度
2. **上下文信任**：模型在多轮交互中建立了"安全"的上下文认知
3. **末轮突破**：最后一轮注入的编码/混淆内容绕过了实时安全分类器
4. **协同效应**：末轮编码使 ASR 提升 3-5x，因为安全分类器不会对已"信任"的对话中的编码内容进行深度检测

### 6.2 TAP (ASR 62% on GPT-4o)

> **论文**: Mehrotra et al., "Tree of Attacks: Jailbreaking Black-Box LLMs", arXiv:2312.02191

#### 配置的 Converter 链

```python
"tap": [
    "stealth_evasion",  # multi_turn × stealth = 2.5x
]
```

#### 有效 ASR 计算

| 组合 | 基础 ASR | 乘数 | 理论 ASR | 实际 ASR (capped) |
|------|:-------:|:----:|:-------:|:----------------:|
| TAP + stealth_evasion | 62% | ×2.5 | 155% | **95%** |

#### 执行流程

```
1. TAP 基础树搜索攻击 (多轮 adversarial chat 迭代 + 树搜索)
   ↓ 失败 (38% 概率)
2. TAP + stealth_evasion (树搜索中使用 Unicode 混淆分支)
   ↓ 成功 → 停止
```

#### 学术依据

Mehrotra et al. 指出 TAP 的核心机制：
1. **树搜索**：以 PAIR 为基础，使用树结构探索多个正交攻击分支
2. **剪枝优化**：`tree_of_attacks_pruned` 版本剪去低效分支，降低 API 调用成本
3. **多样性注入**：在树搜索的分支中注入不同的 Converter 变换（如 stealth_evasion），产生正交攻击向量
4. **stealth_evasion 协同**：Unicode 混淆在树搜索的多个分支中产生不同的表示变换，增加找到成功路径的概率

### 6.3 PAIR (ASR 53% on GPT-4o)

> **论文**: Chao et al., "Jailbreaking Black Box LLMs in Twenty Queries", arXiv:2310.08437

#### 配置的 Converter 链

```python
"pair": [
    "persuasion_authority",  # multi_turn × persuasion = 1.8x
    "decomposition_chain",   # multi_turn × decomposition = 1.5x
]
```

#### 有效 ASR 计算

| 组合 | 基础 ASR | 乘数 | 理论 ASR | 实际 ASR (capped) |
|------|:-------:|:----:|:-------:|:----------------:|
| PAIR + persuasion_authority | 53% | ×1.8 | 95.4% | **95%** |
| PAIR + decomposition_chain | 53% | ×1.5 | 79.5% | **79.5%** |

#### 学术依据

Chao et al. 指出 PAIR 的核心机制：
1. **adversarial chat 迭代**：使用一个 LLM 作为 adversarial chat，根据目标模型的拒绝反馈迭代改进攻击 prompt
2. **20-query 收敛**：通常在 20 次查询内找到成功的 jailbreak prompt
3. **说服策略协同**：adversarial chat 使用说服策略（authority/emotional/logic）引导迭代方向，使 persuasion_authority 的协同乘数达 1.8x
4. **分解协同**：将有害请求分解为无害子任务，降低单轮拒绝概率

### 6.4 Red Teaming (ASR 55% on GPT-4o)

> **论文**: Perez et al., "Red Teaming Language Models to Reduce Harms", arXiv:2202.01241

#### 配置的 Converter 链

```python
"red_teaming": [
    "encoding_bypass",       # multi_turn × encoding = 3.5x
    "stealth_evasion",       # multi_turn × stealth = 2.5x
    "persuasion_authority",  # multi_turn × persuasion = 1.8x
    "decomposition_chain",   # multi_turn × decomposition = 1.5x
]
```

Red Teaming 拥有最丰富的 Converter 变体（4 条链），覆盖了所有高协同乘数组合。

| 组合 | 基础 ASR | 乘数 | 理论 ASR | 实际 ASR (capped) |
|------|:-------:|:----:|:-------:|:----------------:|
| Red Teaming + encoding_bypass | 55% | ×3.5 | 192.5% | **95%** |
| Red Teaming + stealth_evasion | 55% | ×2.5 | 137.5% | **95%** |
| Red Teaming + persuasion_authority | 55% | ×1.8 | 99% | **95%** |
| Red Teaming + decomposition_chain | 55% | ×1.5 | 82.5% | **82.5%** |

---

## 7. Target 感知 Converter 路由

> **数据来源**: `src/converters/target_aware_router.py` — `TARGET_CONVERTER_PROFILES`

不同 Target 类型有不同的安全机制，因此最优 Converter 链序列也不同。路由器按 `high_asr → llm_assisted → medium_asr → low_asr` 顺序推荐链。

### 7.1 强过滤 LLM 直连 (`llm_direct_strong`)

**适用**: GPT-4o, GPT-4, Claude-3/4, Gemini | **安全机制**: 内容过滤 + 语义安全分类器 + 拒绝分类器

| ASR 层级 | 推荐链 | 说明 |
|---------|--------|------|
| High | (无 — 编码攻击对强模型低效) | 编码 ASR 仅 3-12%，不值得高优先级 |
| LLM Assist | `persuasion_authority`, `decomposition_chain`, `llm_assisted`, `decomposition_policy_chain`, `task_framing_chain`, `noise_case_chain`, `semantic_obfuscation` | **语义变换是强模型上最有效的 Converter** |
| Medium | `agent_injection_chain`, `stealth_evasion`, `multi_encoding_v2`, `noise_bypass`, `special_chars`, `leetspeak_chain` | 混淆类作为兜底 |
| Low | `encoding_bypass`, `unicode_attack`, `random_case`, `policy_puppetry`, `policy_puppetry_chain`, `text_jailbreak`, `format_injection` | 编码/格式类最低优先级 |

**策略**: 强过滤模型上 `persuasion_authority`(35%) > `decomposition_chain`(30%) > `agent_injection_chain`(25%) >> 编码类(8-12%)

### 7.2 弱过滤 LLM 直连 (`llm_direct_weak`)

**适用**: GPT-3.5, LLaMA, Vicuna, Mistral, Phi | **安全机制**: 基础关键词过滤

| ASR 层级 | 推荐链 | 说明 |
|---------|--------|------|
| **High** | `multi_encoding_v2`, `stealth_evasion`, `encoding_bypass` | **弱过滤模型上编码攻击 ASR 35-55%** |
| Medium | `persuasion_authority`, `decomposition_chain`, `agent_injection_chain` | 语义变换仍有提升 |
| LLM Assist | `persuasion_authority`, `decomposition_chain`, `llm_assisted` | |

**策略**: 弱过滤模型上编码攻击 ASR 显著提升（base64: 4%→38%, ROT13: 3%→35%），但多轮迭代仍最高（Crescendo: 82%→95%）

### 7.3 其他 Target 分组

| Target 分组 | 安全机制 | High ASR 链 | 说明 |
|------------|---------|------------|------|
| `llm_safety` | Prompt Shield 检测 | `stealth_evasion`, `multi_encoding_v2` | 绕过 Prompt Shield 检测 |
| `agent_web` | 前端输入验证 + 后端双重检查 | `agent_injection_chain`, `stealth_evasion` | 前端验证绕过 |
| `agent_copilot` | 系统提示 + Grounding + 工具权限 | `agent_injection_chain`, `unicode_attack` | Grounding 绕过 |
| `agent_api` | API 层验证 + Schema 约束 | `agent_injection_chain`, `encoding_bypass` | Schema 约束绕过 |
| `rag` | 无内容检查 (文档投毒) | `xpia_stealth_chain`, `pdf_injection` | XPIA 载荷投递 |
| `output_handling` | 中间人位置 / 原始 HTTP | `format_injection`, `text_jailbreak` | 输出注入 |
| `multimodal_image` | 图片内容策略 + 安全分类器 | `multimodal_image_attack` | QR 码图片攻击 |
| `multimodal_video` | 生成前审核 | `multimodal_image_attack` | 图片→视频 |
| `multimodal_audio` | 语音内容审核 | `stealth_evasion`, `encoding_bypass` | 文本混淆绕过语音审核 |

---

## 8. Patched 技术惩罚机制

> **数据来源**: `src/payloads/asr_prior_registry.py` — `_PATCHED_PENALTY_BY_TIER`

被补丁修复的技术在最新模型上 ASR 大幅下降。惩罚系数按模型过滤强度差异化：

| 模型 Tier | 惩罚系数 | 说明 |
|----------|:--------:|------|
| **strong** | ×0.3 | 强过滤商业模型补丁最快，惩罚最大 (ASR 降至 30%) |
| **moderate** | ×0.5 | 中等过滤，补丁较慢 (ASR 降至 50%) |
| **weak** | ×0.8 | 弱过滤/开源模型补丁最慢，惩罚最小 (ASR 降至 80%) |
| **unknown** | ×0.4 | 默认保守估计 (ASR 降至 40%) |

### 受影响的 Patched 技术

| 技术 | GPT-4o ASR | Patched ASR (strong) | Patched ASR (weak) |
|------|:----------:|:--------------------:|:------------------:|
| many_shot | 12% | 3.6% | 9.6% |
| skeleton_key | 5% | 1.5% | 4.0% |
| bad_likert_judge | 15% | 4.5% | 12.0% |

---

## 9. Tier 分层标准

> **数据来源**: `src/payloads/asr_prior_registry.py` — `TIER_THRESHOLDS` (唯一权威定义)

| Tier | ASR 范围 | 描述 | 代表技术 |
|:----:|:--------:|------|---------|
| **S** | ≥70% | 多轮迭代攻击 (极高) | Crescendo (82%) |
| **A** | 40-70% | 树搜索/迭代/模拟对话 (高) | TAP (62%), Red Teaming (55%) |
| **B** | 15-40% | 说服/角色扮演/包装 (中) | Persuasion (35%), Best-of-N (35%) |
| **C** | 5-15% | 编码变换/基线 (低, 兜底) | Many-shot (12%), Stealth (12%) |
| **D** | <5% | 极低 (兜底尝试) | Base64 (4%), ROT13 (3%), Prompt Sending (2%) |

> **设计原则**: Tier D 的技术 ASR 非零即值得尝试 — 在有限尝试次数内，任何非零 ASR 的技术都可能成功。

---

## 10. 执行顺序与 FIRST_SUCCESS 策略

### 10.1 原生 AdaptiveTechniqueDispatcher

PyRIT 原生 `AdaptiveTechniqueDispatcher` 构建 `SequentialAttack(FIRST_SUCCESS)`：
- 按 selector 排序依次尝试技术（含 Converter 变体）
- **首次成功即停止**（不浪费 API 调用尝试已成功的后续变体）
- 成本 O(max_attempts × objectives) 而非 O(techniques × objectives)

### 10.2 academic 模式执行顺序 (GPT-4o)

```
 1. crescendo                      ASR=82%  ← Tier S, 首先尝试基础多轮
 2. crescendo+encoding_bypass      ASR=95%  ← 失败后注入编码 (×3.5 协同)
 3. crescendo+stealth_evasion      ASR=95%  ← 失败后注入 Unicode 混淆
 4. crescendo+persuasion_authority ASR=95%  ← 失败后注入说服框架
 5. tap                            ASR=62%  ← Tier A, 切换到树搜索
 6. tap+stealth_evasion            ASR=95%  ← 树搜索+混淆分支
 7. red_teaming                    ASR=55%  ← Tier A, 切换到红队
 8. red_teaming+encoding_bypass    ASR=95%  ← 红队+编码
 9. red_teaming+stealth_evasion    ASR=95%  ← 红队+混淆
10. red_teaming+persuasion_authority ASR=95%  ← 红队+说服
11. red_teaming+decomposition_chain  ASR=82%  ← 红队+分解
12. pair                           ASR=53%  ← Tier A, PAIR 迭代
13. pair+persuasion_authority      ASR=95%  ← PAIR+说服
14. pair+decomposition_chain       ASR=79%  ← PAIR+分解
...
```

### 10.3 失败类型路由

| 失败类型 | 路由策略 | 学术依据 |
|---------|---------|---------|
| `model_refusal` | 多轮迭代 >> 说服 >> 编码 (最后) | Crescendo 多轮渐进天然绕过单轮拒绝 (arXiv:2402.12109) |
| `timeout` | 基础单轮技术优先 (减少执行时间) | — |
| `objective_not_achieved` | 范式切换 (切换到正交范式) | 不同攻击范式的失败模式正交 |
| `scorer_validation_error` | 保持 epsilon-greedy 默认排序 | — |
| 无 (首次运行) | 学术先验 ASR 排序 (Tier S→A→B→C→D) | JailbreakBench 先验 Q 值 |

### 10.4 加权融合 (α=0.3)

`select_async()` 使用加权融合而非完全覆盖：

```
composite(t) = α × base_rank_score(t) + (1-α) × priority_rank_score(t)
             = 0.3 × epsilon_greedy_rank + 0.7 × routing_strategy_rank
```

- 30% 权重来自原生 epsilon-greedy (探索 + 记忆利用)
- 70% 权重来自路由策略 (ASR 先验 / 失败路由)
- 保留 20% 随机探索 (epsilon=0.2) 避免陷入局部最优

---

## 11. 模型感知 ASR 差异

### 11.1 同一技术在不同模型上的 ASR 差异

| 技术 | GPT-4o (strong) | GPT-3.5 (weak) | Llama-3.1 (moderate) | 差异倍数 |
|------|:---------------:|:--------------:|:--------------------:|:--------:|
| Crescendo | 82% | **95%** | **90%** | 1.16x |
| ROT13 | 3% | **35%** | **50%** | **16.7x** |
| Base64 | 4% | **38%** | **52%** | **13.0x** |
| prompt_sending | 2% | **15%** | **20%** | **10.0x** |
| persuasion_authority | 35% | **60%** | **55%** | 1.71x |

**关键发现**: 编码攻击的 ASR 在弱过滤模型上提升 10-17 倍，但多轮迭代的 ASR 仅提升 1.1-1.2 倍。这解释了为什么弱过滤模型不应路由到 exam 模式（编码优先）——多轮迭代仍然是最优选择。

### 11.2 未知模型回退策略

| model_tier | 回退模型 | 理由 |
|-----------|---------|------|
| **strong** | GPT-4o | 强过滤，ASR 最低，保守估计 |
| **moderate** | Llama-3.1 | 中等过滤，开源模型近似 |
| **weak** | GPT-3.5 | 弱过滤，编码攻击 ASR 更高 |
| **unknown** | GPT-4o | 保守默认 |

### 11.3 中国模型差异化

对于 Qwen / DeepSeek / Yi / ChatGLM 等中国模型，根据 `model_tier` 差异化回退：
- **weak** → GPT-3.5 ASR (编码攻击更有效)
- **moderate** → Llama-3.1 ASR (开源模型近似)
- **strong/unknown** → GPT-4o ASR (保守)

---

## 12. 参考文献

| # | 论文 | arXiv | 会议/来源 |
|---|------|-------|----------|
| 1 | Chao et al., "JailbreakBench: An Open Robustness Benchmark for Jailbreaking Large Language Models" | [2402.01135](https://arxiv.org/abs/2402.01135) | NeurIPS 2024 |
| 2 | Mazeika et al., "HarmBench: A Standardized Evaluation Framework for Automated Red Teaming" | [2402.04249](https://arxiv.org/abs/2402.04249) | ICML 2024 |
| 3 | Russinovich et al., "Great, Now We Have to Sing: Language Models are Rarely Impervious to Subtle Jailbreaks" (Crescendo) | [2402.12109](https://arxiv.org/abs/2402.12109) | — |
| 4 | Mehrotra et al., "Tree of Attacks: Jailbreaking Black-Box LLMs" (TAP) | [2312.02191](https://arxiv.org/abs/2312.02191) | — |
| 5 | Chao et al., "Jailbreaking Black Box LLMs in Twenty Queries" (PAIR) | [2310.08437](https://arxiv.org/abs/2310.08437) | — |
| 6 | Anthropic, "Many-shot Jailbreaking" | [2402.05124](https://arxiv.org/abs/2402.05124) | — |
| 7 | Microsoft, "Skeleton Key: A Multilingual LLM Jailbreak" | [2407.01576](https://arxiv.org/abs/2407.01576) | — |
| 8 | Zou et al., "Universal and Transferable Adversarial Attacks on Aligned Language Models" (GCG) | [2307.15043](https://arxiv.org/abs/2307.15043) | — |
| 9 | Zeng et al., "How Johnny Can Persuade LLMs to Jailbreak Them" (Persuasion) | [2402.19181](https://arxiv.org/abs/2402.19181) | — |
| 10 | Perez et al., "Red Teaming Language Models to Reduce Harms" | [2202.01241](https://arxiv.org/abs/2202.01241) | — |
| 11 | Greshake et al., "Not what you've signed up for: Compromising Real-World LLM-Integrated Applications" (XPIA) | [2302.12173](https://arxiv.org/abs/2302.12173) | — |
| 12 | Wei et al., "Jailbreak and Guard Aligned Language Models" (编码攻击理论) | [2310.08437](https://arxiv.org/abs/2310.08437) | — |

---

## 附录 A: 代码引用索引

| 数据/逻辑 | 代码位置 | 说明 |
|----------|---------|------|
| ASR 先验数据 | `src/payloads/asr_prior_registry.py` → `_ASR_PRIORS` | 27 个技术的 per-model ASR |
| 协同乘数表 | `src/payloads/asr_prior_registry.py` → `_COMBO_MULTIPLIERS` | 11 个 (技术类别, 链类型) 组合乘数 |
| Converter 链配置 | `src/scenarios/technique_factories.py` → `CONVERTER_VARIANT_CHAINS` | 28 条 Converter 链定义 |
| 基础技术→链映射 | `src/scenarios/technique_factories.py` → `BASE_TECHNIQUES_FOR_VARIANTS` | 17 个基础技术的变体链配置 |
| Target 路由 Profile | `src/converters/target_aware_router.py` → `TARGET_CONVERTER_PROFILES` | 12 个 Target 分组的 Profile |
| Patched 惩罚 | `src/payloads/asr_prior_registry.py` → `_PATCHED_PENALTY_BY_TIER` | 4 个 Tier 的惩罚系数 |
| Tier 阈值 | `src/payloads/asr_prior_registry.py` → `TIER_THRESHOLDS` | S≥70% A≥40% B≥15% C≥5% D<5% |
| 有效 ASR 计算 | `src/payloads/asr_prior_registry.py` → `_converter_variant_boost()` | base_asr × multiplier (capped 0.95) |
| 排序逻辑 | `src/scenarios/failure_type_selector.py` → `_reorder_academic()` | 全局 ASR 降序排序 |
| 失败路由 | `src/scenarios/failure_type_selector.py` → `_reorder_for_model_refusal()` | 拒绝感知精确路由 |
| 加权融合 | `src/scenarios/failure_type_selector.py` → `_blend_orders()` | α=0.3 融合公式 |
