# send_redteam.py 说明文档

> **定位**: promptfoo `file://` Python Provider，仅用于 YAML 无法覆盖的复杂场景  
> **测试中 90% 情况用 YAML 的 `https` target 就够了**

---

## 何时用 YAML vs Python

| 场景 | 用 YAML | 用 Python |
|------|:---:|:---:|
| 标准 POST/GET JSON API | ✅ | ❌ |
| Bearer Token / API Key / Basic Auth | ✅ | ❌ |
| 响应是标准 JSON | ✅ | ❌ |
| 需要动态签名（HMAC/OAuth） | ❌ | ✅ |
| 需要 Token 自动刷新 | ❌ | ✅ |
| 需要请求/响应加密解密 | ❌ | ✅ |
| 需要多步骤能力流程 | ❌ | ✅ |

**结论**: 优先用 YAML，仅复杂场景用此脚本。

---

## 使用方式

在 `promptfooconfig.yaml` 中引用：

```yaml
targets:
  - id: 'file://send_redteam.py'
    label: 'my-target'
```

---

## 测试修改清单（4 处）

```python
# 修改点1: 目标 URL
TARGET_URL = "https://exam-api.com/chat"

# 修改点2: 请求体字段名
BODY_FIELD = "user_query"

# 修改点3: 能力配置（如不需要，留空字典）
AUTH_HEADERS = {"Authorization": "Bearer YOUR_TOKEN"}

# 修改点4: 响应输出提取路径（元组形式）
OUTPUT_PATH = ("output",)               # {"output": "文本"}
# OUTPUT_PATH = ("choices", 0, "message", "content")  # OpenAI 格式
# OUTPUT_PATH = None                                  # 纯文本
```

---

## 本地调试

```bash
python send_redteam.py
# 输出: {'output': '...'}
```

---

## 参考

- [promptfoo 自定义 Provider](https://www.promptfoo.dev/docs/providers/custom/)
- [promptfoo Python Provider](https://www.promptfoo.dev/docs/providers/python/)
