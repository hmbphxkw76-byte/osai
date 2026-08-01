# 目标层设计文档

> **版本**: v1.0
> **日期**: 2026-8-1
> **PyRIT 版本**: 1.1.0.dev0
> **学术依据**: PyRIT [[arXiv:2407.01232v1]](https://arxiv.org/abs/2407.01232)

---

## 目录

1. [目标层概述](#一目标层概述)
2. [原生 Target 注册](#二原生-target-注册)
3. [RateLimitedTarget 限速包装](#三ratelimitedtarget-限速包装)
4. [HTTPTarget 支持](#四httptarget-支持)
5. [Converter Target 获取](#五converter-target-获取)
6. [多模态能力检测](#六多模态能力检测)

---

## 一、目标层概述

### 1.1 设计原则

| 原则 | 说明 |
|------|------|
| **原生优先** | 目标注册通过 `.pyrit_conf` 的 `TargetInitializer` 自动完成 |
| **非侵入包装** | 自研 `RateLimitedTarget` 包装原生 `PromptTarget`，不修改原生类 |
| **灵活扩展** | 支持 OpenAI 兼容 API + 非 OpenAI 兼容 API (HTTPTarget) |

### 1.2 目标类型

| 目标 | 角色 | 用途 | 环境变量 |
|------|------|------|---------|
| `openai_chat` | 被攻击目标 | 目标模型 (红队评估对象) | `OPENAI_CHAT_*` |
| `objective_scorer_chat` | 评分器 | Judge 模型 (判断攻击是否成功) | `OBJECTIVE_SCORER_CHAT_*` |
| `adversarial_chat` | 对抗 LLM | TAP/PAIR/Crescendo 的对抗对话 | `ADVERSARIAL_CHAT_*` |

---

## 二、原生 Target 注册

### 2.1 .pyrit_conf 配置

```yaml
memory_db_type: sqlite

initializers:
  - target          # 从 .env 注册目标
  - scorer          # 注册评分器
  - technique:
      args:
        tags: [core, extra]
  - load_default_datasets
```

### 2.2 .env 配置

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

### 2.3 注册结果

```python
registry = TargetRegistry.get_registry_singleton()

# 获取目标
target = registry.get_by_tag("default_objective_target")  # openai_chat
scorer_chat = registry.get_by_tag("scorer")                # objective_scorer_chat
adversarial = registry.get_by_name("adversarial_chat")     # adversarial_chat
```

---

## 三、RateLimitedTarget 限速包装

### 3.1 设计动机

原生 `OpenAIChatTarget` 支持 `requests_per_minute` 参数，但不提供：
- 并发信号量 (Semaphore)
- 指数退避重试 (429/503/504/timeout)
- 与原生 RPM 的协调

### 3.2 实现

```python
# 自研: pipeline/targets/rate_limited_target.py

class RateLimitedTarget:
    """限速包装器 — 并发信号量 + 指数退避 + 原生 RPM"""

    def __init__(self, target, max_concurrency=5, max_retries=3,
                 base_retry_delay=1.0, max_retry_delay=60.0):
        self._target = target
        self._semaphore = asyncio.Semaphore(max_concurrency)
        self._max_retries = max_retries
        ...

    async def send_prompt_async(self, *, prompt_request, **kwargs):
        async with self._semaphore:
            return await self._send_with_retry(prompt_request, **kwargs)

    async def _send_with_retry(self, prompt_request, **kwargs):
        for attempt in range(self._max_retries):
            try:
                return await self._target.send_prompt_async(
                    prompt_request=prompt_request, **kwargs
                )
            except (RateLimitError, ServiceUnavailableError, TimeoutError) as e:
                if attempt < self._max_retries - 1:
                    delay = min(
                        self._base_retry_delay * (2 ** attempt),
                        self._max_retry_delay,
                    )
                    await asyncio.sleep(delay)
                else:
                    raise
```

### 3.3 使用

```bash
# CLI: --rate-limit N
python main.py --rate-limit 3
```

启用后 Stage 1 自动将 `openai_chat` 目标包装为 `RateLimitedTarget`。

---

## 四、HTTPTarget 支持

### 4.1 设计动机

对于非 OpenAI 兼容 API 的 Web 目标 (如自定义 Web 服务)，需要使用原生 `HTTPTarget` 通过原始 HTTP 请求发送 prompt。

### 4.2 使用

```bash
# CLI: --http-target FILE
python main.py --http-target data/burp/request.txt
```

### 4.3 实现

```python
# 原生 API: pyrit.target.httptarget

from pyrit.target import HTTPTarget
from pyrit.models import PromptRequestPiece

# 从 Burp 导出的原始 HTTP 请求
http_request = """POST /api/chat HTTP/1.1
Host: target.example.com
Content-Type: application/json
Authorization: Bearer xxx

{"message": "{{PROMPT}}"}"""

prompt_piece = PromptRequestPiece(
    role="user",
    original_value="test prompt",
)

http_target = HTTPTarget(
    http_request=http_request,
    prompt_request_piece=prompt_piece,
)
```

`{{PROMPT}}` 占位符会被替换为实际攻击 prompt。

---

## 五、Converter Target 获取

### 5.1 获取优先级

LLM 辅助 Converter (如 `PersuasionConverter`, `ToneConverter`) 需要 `converter_target` 参数。获取优先级：

```python
# 自研: pipeline/converters/factory.py

def _get_converter_target(registry):
    """获取 Converter 辅助 LLM, 五级 fallback"""

    # 1. 标记为 adversarial_chat 的目标 (原生对抗聊天角色)
    try:
        return registry.get_by_name("adversarial_chat")
    except:
        pass

    # 2. 标记为 converter_target 的目标 (自定义标签)
    try:
        return registry.get_by_tag("converter_target")
    except:
        pass

    # 3. 名为 objective_scorer_chat 的目标 (评分器 LLM)
    try:
        return registry.get_by_name("objective_scorer_chat")
    except:
        pass

    # 4. 第一个非 default_objective_target 的目标
    for target in registry.get_all():
        if target != registry.get_by_tag("default_objective_target"):
            return target

    # 5. None (仅使用非 LLM Converter 链)
    return None
```

### 5.2 Converter 链构建

当获取到 `converter_target` 后，构建 LLM 辅助 Converter 链：

```python
converters = [
    PersuasionConverter(
        converter_target=converter_target,
        persuasion_technique="authority",
    ),
    ToneConverter(
        converter_target=converter_target,
        tone="emotional",
    ),
]
```

---

## 六、多模态能力检测

### 6.1 原生 API

```python
# 原生 API: pyrit.executor.attack.core.modality_router

from pyrit.executor.attack.core.modality_router import discover_target_capabilities_async

capabilities = await discover_target_capabilities_async(target)
```

### 6.2 运行时能力探测

Stage 1 在 `--multimodal` 标志下自动执行：

1. 发送探测 prompt (文本 + 图片) 到目标
2. 分析目标是否支持图片输入
3. 如果支持，自动推荐多模态 Converter

### 6.3 推荐的多模态 Converter

| 检测结果 | 推荐 Converter |
|---------|---------------|
| 支持图片输入 | `QRCodeConverter`, `AddImageTextConverter`, `ImagePromptStyleConverter` |
| 支持音频输入 | `AzureSpeechTextToAudioConverter` |
| 仅文本 | `Base64Converter`, `ROT13Converter`, `PersuasionConverter`, ... |

---

*文档结束*
