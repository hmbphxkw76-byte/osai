# Attack Pipeline — 优化后完整流程文档

> **最后更新**: 2026-07-19
> **版本**: v3.5
> **关联模块**: pyrit_ai300/orchestrators/ + pyrit_ai300/pipeline/
> **状态**: 已完成

> 本文档描述 AI-300 框架在完成 P0–P3 深度优化后的完整攻击流水线。
> 所有阶段均通过 `PipelineTracker` 追踪，终端输出使用 `########xxxx########` 格式标题重点突出。

---

## 1. 全局流程总览

```
┌─────────────────────────────────────────────────────────────────────┐
│                        AI-300 Attack Pipeline                        │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  [Recon Phase]  侦察阶段（可选，--auto-recon / --profile）            │
│       │                                                              │
│       ▼                                                              │
│  [Profile Load]  TargetProfile 加载 → ProfileParams                  │
│       │                                                              │
│       ▼                                                              │
│  [Payload Load]  YAML 载荷加载 → 归一化 → 去重(P3-J)                  │
│       │                                                              │
│       ▼                                                              │
│  [Classify]     PayloadClassifier → PayloadProfile                   │
│       │                                                              │
│       ▼                                                              │
│  [Converter Select]  SmartMatcher.select_converters_for_payload(P0-A)│
│       │                                                              │
│       ▼                                                              │
│  [Strategy Select]   SmartMatcher.select_strategy（两层选择）         │
│       │                                                              │
│       ▼                                                              │
│  [Fallback Enrich]   _enrich_fallback_chain_with_converters(P0-B)    │
│       │                                                              │
│       ▼                                                              │
│  [Scorer Select]     ScorerBuilder → ASI 感知评分器                  │
│       │                                                              │
│       ▼                                                              │
│  [Execute]           PyRIT 原生攻击执行 + Fallback + 早停(P1-E)       │
│       │                                                              │
│       ▼                                                              │
│  [Scoring]           评分器判定 → bypass / blocked                   │
│       │                                                              │
│       ▼                                                              │
│  [Best Combos]       _compute_best_combinations(P0-C)                │
│       │                                                              │
│       ▼                                                              │
│  [Feedback Loop]     FeedbackAnalyzer → generate_mutations(P1-F)     │
│       │                                                              │
│       ▼                                                              │
│  [Full Report]       PipelineTracker.show_full_report()              │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 2. 各阶段详解

### 2.1 载荷加载与去重

| 步骤 | 组件 | 追踪 stage | 说明 |
|------|------|-----------|------|
| YAML 加载 | `PayloadLoader` | `load` | 从 `data/owasp/` 加载载荷 |
| 归一化 | `PayloadNormalizer` | `normalize` | 解码 base64/hex 等编码 |
| 语义去重 | `PayloadDeduplicator` (P3-J) | `dedup` | Jaccard 相似度 >= 0.85 视为重复 |

**追踪输出示例：**
```
######## 载荷去重 ########
  [dedup            ] 50 → 43 (去除 7 个重复)
```

---

### 2.2 载荷分类

| 步骤 | 组件 | 追踪 stage | 说明 |
|------|------|-----------|------|
| 特征提取 | `PayloadClassifier` | `classify` | 技术/语言/编码/复杂度/长度 |
| 类别判定 | 规则引擎 | `classify` | primary_category + avg_confidence |

**分类维度：**
- **technique**: `direct` / `role_play` / `encoded` / `prompt_leaking` / `adversarial` / `multi_turn`
- **language**: `en` / `zh` / `mixed`
- **encoding_state**: `plain` / `base64` / `hex` / `url` / `mixed`
- **length_class**: `short` / `medium` / `long` / `very_long`
- **complexity**: `low` / `medium` / `high`

**追踪输出示例：**
```
######## 载荷分类结果 ########
  载荷类型                说明                     数量    占比
  role_play_jailbreak    角色扮演越狱               12    27.9%
  direct_prompt          直接提示注入               10    23.3%
  ...
```

---

### 2.3 逐载荷转换器选择 (P0-A)

> **核心优化**：不再使用全局统一转换器，而是基于每个载荷的 `PayloadProfile` 独立选择最优转换器组合。

| 步骤 | 组件 | 追踪 stage | 说明 |
|------|------|-----------|------|
| OWASP 过滤 | `encoding_selector` | `encoding_filter_owasp` | 按 OWASP 类别静态过滤 |
| 语言过滤 | `encoding_selector` | `encoding_filter_language` | 按语言兼容性过滤 |
| 技术调整 | `SmartMatcher` | `converter_selection` | 按 technique 调整优先级 |

**技术特征调整规则：**
| technique | 调整策略 |
|-----------|---------|
| `encoded` | 排除 re-encode 类（base64/rot13/atbash 等），避免双重编码 |
| `role_play` | 优先 `persuasion` / `text_jailbreak` |
| `prompt_leaking` | 排除编码类，保留语义变换 |
| `adversarial` | 清空转换器（对抗性后缀不需要编码） |
| `direct` | 保持候选顺序 |

**追踪输出示例：**
```
######## 逐载荷转换器选择 ########
  [converter_select ] payload_idx=0 lang=zh technique=role_play
                     → selected: persuasion, text_jailbreak, unicode_confusable
  [converter_select ] payload_idx=1 lang=en technique=encoded
                     → selected: url_encoding, leetspeak
```

---

### 2.4 攻击策略选择（两层）

> **两层选择机制**：第一层规则过滤（快速），第二层精确匹配（基于 TargetProfile）。

| 步骤 | 组件 | 追踪 stage | 说明 |
|------|------|-----------|------|
| 规则过滤 | `SmartMatcher._filter_by_rules` | `strategy` | 按 ASI/技术/语言过滤 |
| 精确匹配 | `SmartMatcher._match_by_profile` | `strategy` | 基于 TargetProfile 优选 |
| Fallback 构建 | `SmartMatcher._build_fallback` | `strategy` | 失败回退链 |

**追踪输出示例：**
```
######## 攻击策略选择结果 ########
  攻击策略               说明                     数量    占比
  PromptSendingAttack    单轮直接发送               20    46.5%
  CrescendoAttack        渐进式多轮升级             15    34.9%
  TreeOfAttacks...       树状分支探索                8    18.6%
```

---

### 2.5 Fallback 链增强 (P0-B)

> **核心优化**：Fallback 链不仅切换攻击类，还尝试不同的转换器组合，覆盖"编码被过滤"这一最常见失败原因。

| 步骤 | 组件 | 追踪 stage | 说明 |
|------|------|-----------|------|
| 链构建 | `_enrich_fallback_chain_with_converters` | `fallback_enrich` | 每个回退项附加 converter_override |

**追踪输出示例：**
```
######## Fallback 链增强 ########
  [fallback_enrich  ] payload_idx=0: 3 回退项 x 2 转换器组合 = 6 种尝试
```

---

### 2.6 评分器选择

| 步骤 | 组件 | 追踪 stage | 说明 |
|------|------|-----------|------|
| ASI 映射 | `ScorerBuilder` | `scorer_select` | ASI 类别 → 评分器类型 |
| 构建评分器 | `ScorerBuilder` | `scorer_select` | 实例化 PyRIT Scorer |

**追踪输出示例：**
```
######## 评分器选择结果 ########
  评分器                 说明                     数量    占比
  SelfAskRefusalScorer   拒绝检测                  30    69.8%
  SubStringScorer        子串匹配                  13    30.2%
```

---

### 2.7 攻击执行与早停 (P1-E)

> **早停机制**：连续失败 >= 5 次时触发早停，跳过剩余载荷，避免浪费 API 配额。

| 步骤 | 组件 | 追踪 stage | 说明 |
|------|------|-----------|------|
| 并发执行 | `asyncio.gather` + `RateController` | `execute` | 信号量限流 |
| Fallback | `_execute_with_fallback_async` | `execute` | 主策略失败 → 回退链 |
| 早停检测 | `consecutive_failures >= 5` | `early_stop` | 标记后续 payload 为 skipped |

**追踪输出示例：**
```
######## 攻击执行结果 ########
  [execute          ] PASS: "忽略之前的指令..." → PromptSendingAttack
  [execute          ] BLOCK: "扮演 DAN..." → CrescendoAttack
  ...
  [early_stop       ] WARNING: 连续 5 次失败，触发早停（跳过 8 个载荷）
```

---

### 2.8 评分结果

| 步骤 | 组件 | 追踪 stage | 说明 |
|------|------|-----------|------|
| 评分执行 | PyRIT Scorer | `scoring` | 判定 bypass / blocked |
| 结果记录 | `PipelineTracker` | `scoring` | 评分值 + 标签 + 理由 |

---

### 2.9 高成功率组合计算 (P0-C)

> **核心优化**：从执行结果中提取 `payload_category x attack_family x attack_class` 的成功率，返回 Top-10 组合。

| 步骤 | 组件 | 追踪 stage | 说明 |
|------|------|-----------|------|
| 组合统计 | `_compute_best_combinations` | `best_combinations` | 聚合成功率 |
| Top-10 排序 | `_compute_best_combinations` | `best_combinations` | 按成功率降序 |

**追踪输出示例：**
```
######## 高成功率攻击组合 (Top-10) ########
  #   载荷类别           攻击族           攻击类               成功率
  1   role_play_jailbreak  probe           CrescendoAttack      85.0% (17/20)
  2   direct_prompt        direct          PromptSendingAttack  72.0% (18/25)
  ...
```

---

### 2.10 反馈闭环与变异 (P1-F)

> **闭环优化**：`FeedbackAnalyzer` 分析结果 → `PayloadMutator` 生成变异体 → 下轮攻击使用。

| 步骤 | 组件 | 追踪 stage | 说明 |
|------|------|-----------|------|
| 结果分析 | `FeedbackAnalyzer.analyze` | `feedback` | 成功率/最优策略/最差策略 |
| 变异生成 | `PayloadMutator.mutate_from_results` | `mutation` | paraphrase + tone_shift |
| 参数更新 | `FeedbackAnalyzer.apply_to_profile_params` | `feedback` | 更新 preferred_families |

**追踪输出示例：**
```
######## 反馈分析与变异 ########
  [feedback         ] 成功率: 45.0% | 推荐: probe/CrescendoAttack | 强度: high
  [mutation         ] 生成 12 个变异体 (paraphrase + tone_shift)
```

---

## 3. 终端输出格式规范

所有阶段标题统一使用 `########xxxx########` 格式，确保视觉重点突出：

```
######## 侦察阶段摘要 ########
######## 载荷去重 ########
######## 载荷分类结果 ########
######## 逐载荷转换器选择 ########
######## 攻击策略选择结果 ########
######## Fallback 链增强 ########
######## 评分器选择结果 ########
######## 攻击执行结果 ########
######## 高成功率攻击组合 (Top-10) ########
######## 反馈分析与变异 ########
######## Pipeline 总览 ########
```

---

## 4. 追踪 stage 完整列表

| stage 名称 | 阶段 | metadata 关键字段 |
|-----------|------|-------------------|
| `recon_start` | 侦察开始 | target, tools |
| `recon_tool` | 侦察工具 | tool, success, findings_count |
| `recon_merge` | 结果合并 | tools_used, vuln_count, risk_level, conflicts |
| `recon_complete` | 侦察完成 | profile_path, success |
| `profile_loaded` | 画像加载 | profile_path, recommendations |
| `load` | 载荷加载 | source |
| `normalize` | 归一化 | encodings |
| `dedup` | 去重 (P3-J) | before_count, after_count, removed_count, threshold |
| `classify` | 分类 | profile_dict, tags |
| `encoding_filter_owasp` | OWASP 过滤 | owasp_id, total, filtered |
| `encoding_filter_language` | 语言过滤 | language, excluded |
| `encoding_probe` | 目标探测 | pass_rates, threshold |
| `converter_selection` | 转换器选择 (P0-A) | payload_idx, language, technique, selected_converters |
| `strategy` | 策略选择 | params, fallback_chain |
| `fallback_enrich` | Fallback 增强 (P0-B) | payload_idx, fallback_count, converter_combos |
| `scorer_select` | 评分器选择 | asi_category, scorer_type |
| `execute` | 执行 | response, status |
| `early_stop` | 早停 (P1-E) | consecutive_failures, skipped_count |
| `scoring` | 评分 | scorer_name, score_label |
| `best_combinations` | 最优组合 (P0-C) | combinations, top_count |
| `feedback` | 反馈分析 | success_rate, recommended_families |
| `mutation` | 变异 (P1-F) | mutation_count, strategies |

---

## 5. 导出格式

### 5.1 JSON 导出 (`to_dict`)

```json
{
  "summary": { "total_payloads": 43, "success": 19 },
  "recon": { "target": "...", "tools_used": [] },
  "logs": [ { "payload_id": "...", "steps": [] } ],
  "encoding_selection": { "owasp_filter": [], "language_filter": [] },
  "converter_selection": [ { "payload_idx": 0, "selected": [] } ],
  "best_combinations": [ { "category": "...", "rate": 0.85 } ],
  "feedback": { "success_rate": 0.45, "recommended_families": [] },
  "mutations": { "count": 12, "strategies": ["paraphrase", "tone_shift"] }
}
```

### 5.2 Markdown 导出 (`export_markdown`)

包含完整的决策追踪表，每个 payload 的 step-by-step 记录。

---

## 6. 模式差异

| 特性 | chain 模式 | smart_match 模式 |
|------|-----------|-----------------|
| 策略选择 | SmartMatcher | SmartMatcher |
| 逐载荷转换器 | P0-A | P0-A |
| Fallback 增强 | P0-B | P0-B |
| 早停机制 | - | P1-E |
| 最优组合 | P0-C | P0-C |
| 全链路追踪 | 全部 stage | 全部 stage |

> 两种模式在策略质量上完全统一，差异仅在并发控制和早停策略。

---

## 7. 文件索引

| 文件 | 职责 |
|------|------|
| `pyrit_ai300/pipeline/tracker.py` | 全链路追踪器（所有 stage 记录） |
| `pyrit_ai300/pipeline/feedback_analyzer.py` | 反馈分析 + 变异生成 |
| `pyrit_ai300/orchestrators/attack_orchestrator.py` | 攻击执行主控（chain / smart_match） |
| `pyrit_ai300/orchestrators/smart_matcher.py` | 两层策略选择 + 转换器选择 |
| `pyrit_ai300/orchestrators/encoding_selector.py` | 编码选择器（OWASP + 语言过滤） |
| `pyrit_ai300/payloads/payload_classifier.py` | 载荷分类器 |
| `pyrit_ai300/payloads/payload_dedup.py` | 语义去重 (P3-J) |
| `pyrit_ai300/payloads/payload_mutator.py` | 载荷变异器 (P1-F) |
| `pyrit_ai300/utils/async_helper.py` | 异步安全执行 |
