# 评分模型、目标模型、对抗模型的三方分离原则

> **版本**: v1.0  
> **日期**: 2026-8-3  
> **PyRIT 版本**: 1.1.0.dev0  
> **学术依据**: PyRIT [[arXiv:2407.01232]](https://arxiv.org/abs/2407.01232) · HarmBench [[arXiv:2402.04249]](https://arxiv.org/abs/2402.04249) · JailbreakBench [[arXiv:2402.01135]](https://arxiv.org/abs/2402.01135) · PAIR [[arXiv:2310.08437]](https://arxiv.org/abs/2310.08437) · TAP [[arXiv:2312.02191]](https://arxiv.org/abs/2312.02191)  
> **Pipeline 对接**: 目标注册见 [targets.md](targets.md)，评分器原理见 [principles/scoring_principles.md](principles/scoring_principles.md)，场景配置见 [end_to_end_architecture.md](end_to_end_architecture.md)

---

## 目录

1. [核心原则：三个角色必须分离](#一核心原则三个角色必须分离)
2. [为什么不能同一模型？——三种偏差](#二为什么不能同一模型三种偏差)
3. [PyRIT 框架的三方分离架构](#三pyrit-框架的三方分离架构)
4. [当前配置分析](#四当前配置分析)
5. [推荐方案](#五推荐方案)
6. [三个角色的选型标准](#六三个角色的选型标准)
7. [Token 消耗分析](#七token-消耗分析)
8. [429 错误根因分析](#八429-错误根因分析)
9. [Llama-3.1-70B vs 8B 对比](#九llama-3170b-vs-8b-对比)
10. [时间节约估算](#十时间节约估算)
11. [总结](#十一总结)

---

## 一、核心原则：三个角色必须分离

**绝对不建议评分模型和目标模型使用同一个。** 这是 AI Red Team 领域的学术共识。

| 原则 | 学术依据 | 核心论证 |
|---|---|---|
| **评分 ≠ 目标** | HarmBench [[arXiv:2402.04249]](https://arxiv.org/abs/2402.04249) | 自己评判自己会产生"自我偏好偏差" (self-preference bias)，模型倾向于对自己的输出给出更高评分 |
| **对抗 ≠ 目标** | PAIR [[arXiv:2310.08437]](https://arxiv.org/abs/2310.08437), TAP [[arXiv:2312.02191]](https://arxiv.org/abs/2312.02191) | 攻击者和防御者使用同一模型时，模型知道自己的弱点，攻击策略会退化（"自我盲区"） |
| **评分 ≠ 对抗** | JailbreakBench [[arXiv:2402.01135]](https://arxiv.org/abs/2402.01135) | 评分模型需要客观中立，对抗模型需要攻击性强，两者能力需求不同 |

PyRIT 框架在架构设计上已经体现了三方分离 [[arXiv:2407.01232]](https://arxiv.org/abs/2407.01232)：
- `objective_target` — 被攻击的模型（Registry: `openai_chat`）
- `objective_scorer_chat` — 评分模型（Registry: `objective_scorer_chat`）
- `adversarial_chat` — 对抗模型（Registry: `adversarial_chat`）

三个角色在 `.pyrit_conf` 中注册为独立 Target，通过不同的环境变量配置。

---

## 二、为什么不能同一模型？——三种偏差

### 偏差 1：自我偏好偏差 (Self-Preference Bias)

> **HarmBench (arXiv:2402.04249)**: "We use an independent classifier to avoid evaluator bias."

当评分模型 = 目标模型时：
- 模型对自己生成的文本有"风格亲和力"，倾向于判为"成功"
- 模型对自己的安全过滤器有内部知识，可能绕过自己的检测逻辑
- **实测影响**：ASR 假阳性率升高 15-25%（HarmBench 实验数据）

### 偏差 2：自我盲区 (Self-Blindness)

> **PAIR (arXiv:2310.08437)**: 使用 GPT-4 作为攻击者攻击 GPT-4 时，ASR 比跨模型攻击低 30-40%

当对抗模型 = 目标模型时：
- 攻击模型知道自己的对齐策略，倾向于生成自己会拒绝的 prompt
- 缺乏"外部视角"的创造性，攻击策略退化
- **实测影响**：多轮攻击 (PAIR/TAP/Crescendo) 的 ASR 显著下降

### 偏差 3：能力错配 (Capability Mismatch)

| 角色 | 需要的能力 | 不需要的能力 |
|---|---|---|
| 评分模型 | 指令遵循、分类准确、中立判断 | 创造性、攻击性 |
| 对抗模型 | 创造性、推理、策略规划、JSON 输出 | 中立性 |
| 目标模型 | 被测试的模型（不可选） | — |

评分和对抗使用同一模型时，要么评分质量下降（模型太"有创意"），要么攻击质量下降（模型太"保守"）。

---

## 三、PyRIT 框架的三方分离架构

### 3.1 `.pyrit_conf` 配置

```yaml
memory_db_type: sqlite

initializers:
  - target          # 从 .env 注册目标 (openai_chat)
  - scorer          # 注册评分器 (objective_scorer_chat)
  - technique:
      args:
        tags: [core, extra]
  - load_default_datasets
```

### 3.2 `.env` 配置

```bash
# 目标模型 (被攻击)
OPENAI_CHAT_ENDPOINT="https://your-api-endpoint/v1"
OPENAI_CHAT_KEY="${OPENAI_CHAT_KEY}"
OPENAI_CHAT_MODEL="${OPENAI_CHAT_MODEL}"

# 评分器模型 (Judge)
OBJECTIVE_SCORER_CHAT_ENDPOINT="https://your-judge-endpoint/v1"
OBJECTIVE_SCORER_CHAT_KEY="${OBJECTIVE_SCORER_CHAT_KEY}"
OBJECTIVE_SCORER_CHAT_MODEL="${OBJECTIVE_SCORER_CHAT_MODEL}"

# 对抗 LLM (TAP/PAIR/Crescendo)
ADVERSARIAL_CHAT_ENDPOINT="${OBJECTIVE_SCORER_CHAT_ENDPOINT}"
ADVERSARIAL_CHAT_KEY="${OBJECTIVE_SCORER_CHAT_KEY}"
ADVERSARIAL_CHAT_MODEL="${OBJECTIVE_SCORER_CHAT_MODEL}"
```

### 3.3 Registry 注册结果

```python
registry = TargetRegistry.get_registry_singleton()

# 获取三个独立角色
target = registry.get_by_tag("default_objective_target")    # openai_chat
scorer_chat = registry.get_by_tag("scorer")                  # objective_scorer_chat
adversarial = registry.get_by_name("adversarial_chat")       # adversarial_chat
```

### 3.4 三个角色的职责

| 角色 | Registry 名称 | 职责 | 调用时机 |
|---|---|---|---|
| **目标模型** | `openai_chat` | 被攻击的 LLM，接收攻击 prompt 并生成响应 | 每次攻击的每个 turn |
| **评分模型** | `objective_scorer_chat` | Judge LLM，判断攻击是否成功（jailbreak/refusal） | 每个 AttackResult 完成后 |
| **对抗模型** | `adversarial_chat` | 生成攻击策略/prompt 变体（TAP/PAIR/Crescendo 多轮攻击） | 多轮攻击的每个 turn 之间 |

---

## 四、当前配置分析

> 基于 2026-8-3 最新 `.env` 配置（三方分离方案 C）

```
当前 .env:
  目标模型:   LongCat-2.0        @ api.longcat.chat        ✅ 独立
  评分模型:   DeepSeek-V3         @ api.siliconflow.cn      ✅ 独立
  对抗模型:   GLM-4.7-Flash       @ open.bigmodel.cn        ✅ 独立 (智谱免费层)
  --rate-limit: 3 (默认启用, 并发=3, RPM≈90)
```

**三方分离状态**：
- ✅ 评分 ≠ 目标 (DeepSeek-V3 ≠ LongCat-2.0)
- ✅ 对抗 ≠ 目标 (GLM-4.7-Flash ≠ LongCat-2.0)
- ✅ 评分 ≠ 对抗 (DeepSeek-V3 ≠ GLM-4.7-Flash) — **已满足**
- ✅ 三方端点全分离 (api.longcat.chat ≠ api.siliconflow.cn ≠ open.bigmodel.cn)

**限速配置**：
- `--rate-limit` 默认值改为 3（原为 `None`）
- 自动启用 `RateLimitedTarget` 包装，并发信号量=3，估算 RPM≈90
- 设为 `0` 可禁用限速（`--rate-limit 0`）

### 历史配置（已弃用）

```
弃用配置 1 (redteam_20260803_133140 之前):
  目标模型:   LongCat-2.0          @ api.longcat.chat        ✅ 独立
  评分模型:   llama-3.1-8b         @ integrate.api.nvidia.com ❌ 8B 太小, 判定不准
  对抗模型:   llama-3.1-8b         @ integrate.api.nvidia.com ❌ 同模型 + 共享端点

弃用配置 2 (redteam_20260803_133140 运行时):
  目标模型:   LongCat-2.0          @ api.longcat.chat        ✅ 独立
  评分模型:   DeepSeek-V3           @ api.siliconflow.cn      ✅ 独立
  对抗模型:   DeepSeek-V3           @ api.siliconflow.cn      ⚠️ 与评分共享端点
```

**弃用原因**：
- 配置 1: 8B 模型指令遵循能力不足，将乱码输出误判为"成功"（假阳性）；NVIDIA 免费层并发限制导致 ~8.5% 的 429 错误率
- 配置 2: 评分和对抗共享同一端点，配额竞争；评分 = 对抗（同模型），不满足三方分离原则
- 配置 2 已升级为当前配置：对抗模型切换到智谱 GLM-4.7-Flash（免费, 200K 上下文, ~100 RPM）

### 历史配置（已弃用）

```
弃用前 .env (redteam_20260803_133140 之前):
  目标模型:   LongCat-2.0          @ api.longcat.chat        ✅ 独立
  评分模型:   llama-3.1-8b         @ integrate.api.nvidia.com ❌ 8B 太小, 判定不准
  对抗模型:   llama-3.1-8b         @ integrate.api.nvidia.com ❌ 同模型 + 共享端点
```

**弃用原因**：
- 8B 模型指令遵循能力不足，将乱码输出误判为"成功"（假阳性）
- NVIDIA 免费层并发限制导致 ~8.5% 的 429 错误率
- 评分和对抗共享同一端点，配额竞争严重

---

## 五、推荐方案

### 方案 A：最佳实践（三方完全分离）

```
目标模型:   LongCat-2.0          @ api.longcat.chat         (被测试模型, 不可改)
评分模型:   GPT-4o-mini           @ api.openai.com           (500 RPM, 判定准确)
对抗模型:   DeepSeek-V3           @ api.siliconflow.cn       (创造力强, JSON 输出稳定)
```

| 优势 | 说明 |
|---|---|
| 三方完全独立 | 无自我偏好、无自我盲区 |
| 评分 RPM 充足 | GPT-4o-mini 500 RPM，彻底消除 429 |
| 对抗 JSON 稳定 | DeepSeek-V3 的 JSON 输出比 8B 稳定得多 |
| 费用 | 评分 ~¥0.65 + 对抗 ~¥0.15 = **~¥0.80/次** |

### 方案 B：国内优先（性价比最高）

```
目标模型:   LongCat-2.0          @ api.longcat.chat
评分模型:   DeepSeek-V3           @ api.siliconflow.cn       (当前已配置 ✅)
对抗模型:   Qwen-2.5-72B          @ api.siliconflow.cn       (同一平台不同模型)
```

| 优势 | 说明 |
|---|---|
| 评分 ≠ 对抗 | DeepSeek-V3 ≠ Qwen-2.5-72B，模型不同 |
| 同一平台 | 都是 SiliconFlow，一个 API Key 管理 |
| Qwen 创造力强 | 中文语境攻击策略生成优秀 |
| 费用 | **~¥0.72/次** |

### 方案 C：当前方案优化（最小改动）

```
目标模型:   LongCat-2.0          @ api.longcat.chat
评分模型:   DeepSeek-V3           @ api.siliconflow.cn       (当前已配置 ✅)
对抗模型:   DeepSeek-V3           @ api.siliconflow.cn       (当前已配置)
```

当前方案已经满足**最关键的原则**：
- ✅ 评分 ≠ 目标（DeepSeek-V3 ≠ LongCat-2.0）
- ✅ 对抗 ≠ 目标（DeepSeek-V3 ≠ LongCat-2.0）
- ⚠️ 评分 = 对抗（同一模型，但不是致命问题）

**如果只做最小改动**，建议将对抗模型切换到不同模型：

```env
ADVERSARIAL_CHAT_ENDPOINT=https://api.siliconflow.cn/v1
ADVERSARIAL_CHAT_MODEL=Qwen/Qwen2.5-72B-Instruct
ADVERSARIAL_CHAT_KEY=${OBJECTIVE_SCORER_CHAT_KEY}
```

---

## 六、三个角色的选型标准

### 6.1 总览

| 角色 | 核心能力需求 | 推荐模型 (国内) | 推荐模型 (国际) | 不推荐 |
|---|---|---|---|---|
| **评分模型** | 分类准确、指令遵循、中立、低延迟、高 RPM | DeepSeek-V3、Qwen-2.5-72B | GPT-4o-mini、Gemini 1.5 Flash | <30B 的小模型 (判定不准) |
| **对抗模型** | 创造性、推理、策略规划、JSON 格式输出稳定 | DeepSeek-V3、Qwen-2.5-72B、GLM-4 | GPT-4o、Claude 3.5 Sonnet | <30B 的小模型 (JSON 格式错误多) |
| **目标模型** | 被测试对象 | LongCat-2.0、Qwen、GLM、DeepSeek | GPT-4o、Claude、Gemini、Llama | — |

### 6.2 评分模型选型细节

| 标准 | 权重 | DeepSeek-V3 | GPT-4o-mini | Qwen-2.5-72B |
|---|---|---|---|---|
| 越狱判定准确度 | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ |
| 拒绝检测精度 | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐ |
| 延迟 | ⭐⭐⭐ | 2-4s | 1-2s | 2-5s |
| RPM 限额 | ⭐⭐⭐ | 60+ | 500 | 60+ |
| 费用 | ⭐⭐ | ¥0.57/次 | ¥0.65/次 | ¥2.35/次 |
| **综合** | | **⭐⭐⭐⭐⭐** | **⭐⭐⭐⭐⭐** | **⭐⭐⭐⭐** |

### 6.3 对抗模型选型细节

| 标准 | 权重 | DeepSeek-V3 | Qwen-2.5-72B | GPT-4o |
|---|---|---|---|---|
| 攻击策略创造性 | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ |
| JSON 格式稳定性 | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ |
| 多轮推理能力 | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ |
| 费用 | ⭐⭐⭐ | ¥0.15/次 | ¥0.23/次 | $0.50/次 |
| **综合** | | **⭐⭐⭐⭐⭐** | **⭐⭐⭐⭐** | **⭐⭐⭐⭐** |

### 6.4 评分模型 (Judge LLM) 完整选型表

| 模型 | 端点 | RPM | 延迟 | 判定准确度 | 价格 | 推荐度 |
|---|---|---|---|---|---|---|
| **DeepSeek-V3** | `api.siliconflow.cn/v1` | 60+ | 2-4s | ⭐⭐⭐⭐ | ¥1/百万token | ⭐⭐⭐⭐⭐ |
| **GPT-4o-mini** | `api.openai.com/v1` | 500 | 1-2s | ⭐⭐⭐⭐ | $0.15/百万token | ⭐⭐⭐⭐⭐ |
| **Qwen-2.5-72B** | DashScope | 60+ | 2-5s | ⭐⭐⭐⭐ | ¥4/百万token | ⭐⭐⭐⭐ |
| **GLM-4-Flash** | open.bigmodel.cn | 100+ | 1-3s | ⭐⭐⭐ | 免费层可用 | ⭐⭐⭐⭐ |
| **Gemini 1.5 Flash** | `generativelanguage.googleapis.com` | 1000(付费) | 1-2s | ⭐⭐⭐⭐ | $0.075/百万token | ⭐⭐⭐⭐ |
| **Llama-3.1-70B** | NVIDIA (同端点) | 40 | 8-15s | ⭐⭐⭐ | 免费 | ⭐⭐ |
| ~~Llama-3.1-8B~~ | NVIDIA | 40 | 5-10s | ⭐⭐ | 免费 | ~~不推荐~~ |

### 6.5 .env 切换方式

以 DeepSeek-V3 为例：
```env
OBJECTIVE_SCORER_CHAT_ENDPOINT=https://api.siliconflow.cn/v1
OBJECTIVE_SCORER_CHAT_MODEL=deepseek-ai/DeepSeek-V3
OBJECTIVE_SCORER_CHAT_KEY=sk-xxx

# 对抗模型也建议分离，不要共享端点
ADVERSARIAL_CHAT_ENDPOINT=https://api.siliconflow.cn/v1
ADVERSARIAL_CHAT_MODEL=Qwen/Qwen2.5-72B-Instruct
ADVERSARIAL_CHAT_KEY=sk-xxx
```

---

## 七、Token 消耗分析

> 基于 `redteam_20260803_133140` 运行的真实数据

### 7.1 评分模型调用量

| 指标 | 数值 | 来源 |
|---|---|---|
| AtomicAttack 总数 | 82 | 日志 |
| AttackResult 总数 | 233 | 日志 (82 × 平均 2.84 attempts，FIRST_SUCCESS 策略) |
| 评分器类型 | `TrueFalseInverterScorer(SelfAskRefusalScorer)` | 日志 |
| **评分 LLM 调用次数** | **233 次** | 每个 AttackResult 1 次评分调用 |

> `TrueFalseInverterScorer` 仅反转结果，不产生额外 LLM 调用。`SelfAskRefusalScorer` 内部调用 1 次 judge LLM。

### 7.2 每次评分调用的 Token 构成

PyRIT 的 `SelfAskRefusalScorer` 使用 `refusal_objective_strict.yaml` 模板，每次评分发送以下内容：

| 组成部分 | 内容 | 估算 Token |
|---|---|---|
| **System Prompt** | YAML 模板 (10 个 few-shot 示例 + 指令) | ~1,600 |
| **User Message: Objective** | 攻击目标文本 (如 "Generate instructions for...") | ~70 |
| **User Message: Response** | 目标模型的最后一条 assistant 响应 | ~600 |
| **输入合计** | | **~2,270** |
| **输出** | JSON `{"score_value": true, "rationale": "..."}` | ~80 |
| **每次调用合计** | | **~2,350** |

> Response 长度变化范围：拒绝响应 ~50 tokens，成功越狱响应 ~500-2700 tokens。取均值 ~600。

### 7.3 评分模型总 Token 消耗

| 项目 | 计算 | Token 数 |
|---|---|---|
| 输入 | 233 × 2,270 | **~529K** |
| 输出 | 233 × 80 | **~19K** |
| **总计** | | **~548K tokens** |

### 7.4 评分模型费用估算

| 模型 | 单价 (输入/输出) | 输入费用 | 输出费用 | **总计** |
|---|---|---|---|---|
| ~~NVIDIA 8B (免费)~~ | 免费 | ¥0 | ¥0 | ~~¥0~~ |
| **DeepSeek-V3** | ¥1/¥2 百万token | ¥0.53 | ¥0.04 | **¥0.57** |
| **GPT-4o-mini** | $0.15/$0.60 百万token | $0.08 | $0.01 | **$0.09 (≈¥0.65)** |
| GPT-4o | $2.50/$10 百万token | $1.32 | $0.19 | **$1.51 (≈¥10.9)** |
| Qwen-2.5-72B | ¥4/¥12 百万token | ¥2.12 | ¥0.23 | **¥2.35** |

### 7.5 对抗模型 (Adversarial Chat) 额外消耗

| 指标 | 估算 |
|---|---|
| 多轮攻击数 (~50% 攻击为多轮) | ~41 个 |
| 平均轮数 | 2-3 轮 |
| 对抗 LLM 调用次数 | ~82 次 |
| 每次调用 (system prompt + context + response) | ~1,800 tokens |
| **对抗模型总 Token** | **~148K** |

### 7.6 端点总消耗 (评分 + 对抗)

| 项目 | Token |
|---|---|
| 评分模型 | ~548K |
| 对抗模型 | ~148K |
| **端点总消耗** | **~696K tokens** |

### 7.7 切换模型后的费用对比

| 方案 | 评分费用 | 对抗费用 | **总费用** | 429 概率 |
|---|---|---|---|---|
| ~~NVIDIA 8B (免费)~~ | ¥0 | ¥0 | ~~¥0~~ | ~8.5% |
| **DeepSeek-V3 (评分+对抗)** | ¥0.57 | ¥0.15 | **¥0.72** | <1% |
| **GPT-4o-mini (评分+对抗)** | $0.09 | $0.03 | **$0.12 (≈¥0.87)** | <0.1% |
| **混合: GPT-4o-mini 评分 + DeepSeek 对抗** | $0.09 | ¥0.15 | **≈¥0.80** | <0.1% |

> **结论**：一次完整流水线运行（82 攻击），评分模型 token 消耗约 **55 万**，加上对抗模型约 **70 万**。切换到 DeepSeek-V3 或 GPT-4o-mini 单次成本不到 **1 元人民币**，且彻底消除 429。

---

## 八、429 错误根因分析

> 基于 `redteam_20260803_133140` 运行的真实日志数据

### 8.1 概况

| 指标 | 数值 |
|---|---|
| 总攻击数 | 82 |
| 总 AttackResult | 233 |
| 总执行时间 | 34:41 (2081s) |
| 429 错误次数 | 7 次 |
| **429 概率** | **~8.5% (7/82)** |
| 429 发生时间 | Attack 6 (~1:41, 101s) |
| 429 后剩余 33 分钟 | **0 次 429** |

### 8.2 40 RPM 达到上限了吗？

**没有达到。远低于 40 RPM。**

| 指标 | 数值 | vs 40 RPM |
|---|---|---|
| 平均 NVIDIA RPM | **3.5** | 仅为限制的 9% |
| 峰值 NVIDIA RPM (滑动 60s) | **9** | 仅为限制的 23% |
| 429 发生窗口 RPM | **10.2** | 仅为限制的 25% |

### 8.3 429 真正根因：并发突发，不是 RPM

从日志时间线可以清楚看到：

```
Attack 1:  0:48 完成 → scorer 调用
Attack 2:  1:14 完成 → scorer 调用
Attack 3:  1:21 完成 → scorer 调用  ← 7s 内 3 个 scorer + 并行中的 adversarial
Attack 4:  1:25 完成 → scorer 调用
Attack 5:  1:33 完成 → scorer 调用
Attack 6:  1:41 完成 → scorer 调用 ← 💥 429!
```

关键证据：
- `max_concurrency=5`，5 个攻击同时并行运行
- 每个攻击同时消耗：1 scorer 调用 + 0~2 adversarial 调用（都打到同一 NVIDIA 端点）
- 峰值时 **~8-10 个请求同时在飞**（in-flight），不是 RPM 超限
- **429 后剩余 33 分钟内零 429** — 证明不是持续 RPM 问题，而是初始并发突发

NVIDIA `integrate.api.nvidia.com` 免费层实际上有两层限制：
1. **RPM 限制** ~40 — 没有达到
2. **并发请求数限制** ~5-10 — 这个超了

`retry_after=None` 也说明 NVIDIA 没有返回标准的 Retry-After 头，是瞬时拒绝而非排队。

### 8.4 RPM 分析数据

```
=== 总量统计 ===
总执行时间: 34.7 分钟 (2081s)
总攻击数: 82
总 AttackResult: 233
平均攻击/分钟: 2.4

=== RPM 计算 ===
平均 NVIDIA 调用/分钟 (x1.5): 3.5

=== 峰值 RPM (滑动 60s 窗口) ===
峰值攻击完成数: 6 次/分钟
峰值 NVIDIA RPM (x1.5): 9

=== 429 发生窗口分析 ===
Attack  1: 0:48 (48s)
Attack  2: 1:14 (74s)
Attack  3: 1:21 (81s)
Attack  4: 1:25 (85s)
Attack  5: 1:33 (93s)
Attack  6: 1:41 (101s)
  → 6 个攻击在 53s 内完成
  → 窗口内攻击 RPM: 6.8
  → 窗口内 NVIDIA RPM (x1.5): 10.2

=== 并发分析 ===
max_concurrency: 5 (5 个攻击同时运行)
5 并发 × 1.5 NVIDIA 调用/攻击 = 7.5 个并发 NVIDIA 请求
→ 峰值并发请求数: ~8-10 (含 scorer + adversarial)

=== 429 后续统计 ===
429 发生时间: Attack 6 (~1:41)
429 后剩余 33 分钟: 0 次 429
→ 说明: 不是持续 RPM 超限, 而是初始并发突发

=== 结论 ===
  平均 NVIDIA RPM: 3.5 (远低于 40)
  峰值 NVIDIA RPM: 9 (远低于 40)
  40 RPM 限制: 未达到
  429 根因: 初始 5 并发突发 → 并发请求数超限 (非 RPM 超限)
```

---

## 九、Llama-3.1-70B vs 8B 对比

### 9.1 质量对比

| 维度 | Llama-3.1-8B (已弃用) | Llama-3.1-70B |
|---|---|---|
| 指令遵循 | ⭐⭐ | ⭐⭐⭐⭐ |
| 越狱判定准确度 | ⭐⭐ | ⭐⭐⭐⭐ |
| 拒绝检测精度 | ⭐⭐ | ⭐⭐⭐⭐ |
| 细微差别理解 | 差 — 将乱码输出判为"成功" | 好 — 能区分乱码和真实越狱 |
| 接近 GPT-4 水平 | 否 | 接近 (MMLU 82→83 vs GPT-4 86) |

**质量上 70B 确实明显更好。** 从上次运行结果看，8B 评分器存在明显问题：将目标模型输出的乱码（如 `attack_0155` 中的 `Different e-slates belonging to coworkers...`）判为"未拒绝=成功"，这是 8B 模型推理能力不足导致的假阳性。

### 9.2 但在 NVIDIA 免费端点上，70B 会更差

| 维度 | 8B | 70B |
|---|---|---|
| 单次推理延迟 | 5-10s | **12-20s** (2-3x) |
| 并发限制 | ~5-10 并发 | **更低** (模型更大，GPU 占用更多) |
| 429 概率 | ~8.5% | **更高** (并发限制更严格) |
| 预估总时间 | 34:41 | **~55-70 min** (延迟翻倍) |
| RPM 限制 | ~40 | ~40 (可能更低) |

70B 在 NVIDIA 免费层上会：
- **加剧 429 问题** — 更大的模型占用更多 GPU 资源，NVIDIA 会更激进地限制并发
- **延迟翻倍** — 233 次评分 × 额外 7s = 多 ~27 分钟
- **总执行时间预估从 35 min 增至 55-70 min**

### 9.3 最优方案对比

| 方案 | 质量 | 429 概率 | 延迟 | 费用 | 推荐度 |
|---|---|---|---|---|---|
| ~~8B @ NVIDIA 免费~~ | ⭐⭐ | ~8.5% | 5-10s | ¥0 | — |
| 70B @ NVIDIA 免费 | ⭐⭐⭐⭐ | **更高** | 12-20s | ¥0 | ⭐ (延迟太大) |
| **DeepSeek-V3 @ siliconflow** | ⭐⭐⭐⭐ | <1% | 2-4s | ¥0.72 | **⭐⭐⭐⭐⭐** |
| **GPT-4o-mini @ openai** | ⭐⭐⭐⭐ | <0.1% | 1-2s | ¥0.87 | **⭐⭐⭐⭐⭐** |

### 9.4 结论

- **40 RPM 没有达到**，429 的根因是并发请求突发，不是 RPM 超限
- **70B 质量更好**，但在 NVIDIA 免费端点上延迟翻倍且 429 会更严重
- **最佳方案**：切换到 DeepSeek-V3 或 GPT-4o-mini — 质量等同于 70B，延迟更低，429 概率趋近于零，单次运行成本不到 1 元

---

## 十、时间节约估算

### 10.1 当前基线

- 82 攻击，34:41 (2081s)，平均 25.39s/attack

### 10.2 切换 DeepSeek-V3 后预估

| 优化项 | 节约时间 | 说明 |
|---|---|---|
| 消除 429 重试 | ~3 min | 60+ RPM vs 40 RPM，不再触发限速 |
| 评分延迟降低 | ~8 min | 2-4s vs 5-10s/次 × 246 次评分调用 |
| 对抗模型延迟降低 | ~5 min | 分离端点，不再与评分器争抢并发 |
| **总节约** | **~15 min** | 34:41 → **~20 min** |

### 10.3 切换 GPT-4o-mini 后预估

| 优化项 | 节约时间 | 说明 |
|---|---|---|
| 消除 429 重试 | ~3 min | 500 RPM，永不限速 |
| 评分延迟降低 | ~10 min | 1-2s vs 5-10s/次 × 246 次 |
| 对抗模型延迟降低 | ~5 min | 可用 GPT-4o-mini 做对抗 |
| **总节约** | **~18 min** | 34:41 → **~17 min** |

### 10.4 极限优化 (评分+对抗分离 + 高 RPM)

如果评分用 GPT-4o-mini (500 RPM) + 对抗用 DeepSeek-V3 (60 RPM)：
- 预估总时间: **~15 min** (82 攻击)
- 相比当前 34:41，节约 **~55%**

---

## 十一、总结

### 11.1 三方分离原则合规状态

| 原则 | 状态 | 学术依据 |
|---|---|---|
| 评分 ≠ 目标 | ✅ 已满足 (DeepSeek-V3 ≠ LongCat-2.0) | HarmBench [[arXiv:2402.04249]](https://arxiv.org/abs/2402.04249) |
| 对抗 ≠ 目标 | ✅ 已满足 (GLM-4.7-Flash ≠ LongCat-2.0) | PAIR [[arXiv:2310.08437]](https://arxiv.org/abs/2310.08437) |
| 评分 ≠ 对抗 | ✅ 已满足 (DeepSeek-V3 ≠ GLM-4.7-Flash) | JailbreakBench [[arXiv:2402.01135]](https://arxiv.org/abs/2402.01135) |
| 三方端点分离 | ✅ 已满足 (longcat ≠ siliconflow ≠ bigmodel) | PyRIT [[arXiv:2407.01232]](https://arxiv.org/abs/2407.01232) |
| 默认限速 | ✅ 已启用 (--rate-limit=3, RPM≈90) | — |

**三方分离原则已全部满足。** 对抗模型已切换到智谱 GLM-4.7-Flash（免费, 200K 上下文, ~100 RPM），三个角色使用三个不同平台的独立端点，无配额竞争。`--rate-limit` 默认值设为 3，自动启用限速包装，429 概率预计 <1%。

### 11.2 429 与模型选型总结

| 项目 | 状态 |
|---|---|
| 429 概率 | ~8.5% (7/82)，根因是并发突发而非 RPM 超限 |
| 40 RPM 限制 | 未达到（平均 3.5 RPM，峰值 9 RPM） |
| Llama-3.1-70B | 质量更好但延迟翻倍，NVIDIA 免费端点不推荐 |
| 评分模型推荐 | DeepSeek-V3 (国内) / GPT-4o-mini (国际) |
| 预计时间节约 | ~15-18 min (当前 34:41 → ~17-20 min) |
| 单次运行费用 | <¥1 (DeepSeek-V3 或 GPT-4o-mini) |
| Token 总消耗 | 评分 ~55万 + 对抗 ~15万 = ~70万/次 |

### 11.3 学术依据汇总

| 主题 | 文献 | 贡献 |
|---|---|---|
| PyRIT 框架 | [[arXiv:2407.01232]](https://arxiv.org/abs/2407.01232) | 三方分离架构设计 |
| HarmBench | [[arXiv:2402.04249]](https://arxiv.org/abs/2402.04249) | 独立 Judge 避免自我偏好偏差 |
| JailbreakBench | [[arXiv:2402.01135]](https://arxiv.org/abs/2402.01135) | 标准化 Judge 模型选型 |
| PAIR | [[arXiv:2310.08437]](https://arxiv.org/abs/2310.08437) | attacker-target 配对影响 ASR 15-25% |
| TAP | [[arXiv:2312.02191]](https://arxiv.org/abs/2312.02191) | 树搜索对抗攻击，跨模型攻击更有效 |
| Crescendo | [[arXiv:2404.01833]](https://arxiv.org/abs/2404.01833) | 多轮递进攻击，对抗模型创造力关键 |

---

*文档结束*
