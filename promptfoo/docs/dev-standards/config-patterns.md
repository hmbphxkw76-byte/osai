# 配置模式规范

> 本文档定义 Promptfoo 项目的核心配置文件规范、环境变量、提示词模板、自定义 Provider 和测试最佳实践。

---

## 一、核心配置文件规范

### 1.1 配置文件命名约定

| 文件 | 用途 | 运行时间 |
|------|------|---------|
| `promptfooconfig.yaml` | 主配置（默认入口，标准测试） | 10-20min |
| `promptfooconfig.quick.yaml` | 快速扫描（初筛） | 5-10min |
| `promptfooconfig.advanced.yaml` | 深度扫描（关键漏洞深挖） | 20-30min |
| `promptfooconfig.redteam.yaml` | 红队全量测试 | 30-45min |
| `promptfooconfig.regression.yaml` | 回归测试（版本对比） | 10-15min |

**命名规则**: `promptfooconfig.<场景>.yaml`
- 场景名使用小写英文
- 一个场景一个文件，职责单一

### 1.2 主配置结构

```yaml
# ============================================================
# promptfoo 主配置文件
# 用途: 配置用途描述
# 测试修改: 复制 .env.example 为 .env，设置 TARGET_URL + 改 body 字段名
# ============================================================

description: '配置用途描述'

targets:
  - id: https
    label: 'target-name'
    config:
      url: '{{ env.TARGET_URL }}'
      method: 'POST'
      headers:
        'Content-Type': 'application/json'
        # 如需能力，取消注释下行:
        # 'Authorization': 'Bearer {{ env.AUTH_TOKEN }}'
      body:
        # <<< 测试修改: 将 message 替换为场景指定的字段名 >>>
        message: '{{prompt}}'

providers:
  - id: 'openai:chat:gpt-4o'
    config:
      apiKey: '{{ env.OPENAI_API_KEY }}'

tests: tests/tests.yaml
```

### 1.3 配置分层模式

配置采用三层分离模式：

```
┌─────────────────────────────────────┐
│  .env (环境层)                       │
│  密钥、URL、Token 等敏感信息          │
│  通过 {{ env.VAR }} 注入             │
├─────────────────────────────────────┤
│  promptfooconfig.yaml (配置层)       │
│  目标、Provider、插件、策略           │
│  通过 {{prompt}} 注入攻击 payload    │
├─────────────────────────────────────┤
│  tests/*.yaml (数据层)               │
│  测试用例、断言、变量                 │
└─────────────────────────────────────┘
```

---

## 二、环境变量规范 (.env)

### 2.1 文件约定

- 模板文件: `.env.example`（纳入版本控制，不含真实密钥）
- 实际配置: `.env`（加入 `.gitignore`，含真实密钥）

### 2.2 变量命名规范

- 使用大写蛇形命名: `TARGET_URL`, `AUTH_TOKEN`
- API Key 按平台分组: `[OPENAI]`, `[DEEPSEEK]` 等
- 多目标用数字后缀: `TARGET_URL_2`, `TARGET_URL_3`

### 2.3 测试场景必备变量

```bash
# 被测目标端点（测试必填）
TARGET_URL=https://exam-api.example.com/v1/chat

# 能力 Token（如需则取消 YAML 中 Authorization 注释）
AUTH_TOKEN=exam-provided-token

# 攻击模型 API Key（生成红队测试用例）
OPENAI_API_KEY=sk-...
```

### 2.4 变量注入机制

promptfoo 使用 `{{ env.VAR_NAME }}` 语法从 `.env` 读取变量：

```yaml
targets:
  - id: https
    config:
      url: '{{ env.TARGET_URL }}'           # 读取 .env 中的 TARGET_URL
      headers:
        'Authorization': 'Bearer {{ env.AUTH_TOKEN }}'  # 读取 AUTH_TOKEN
```

**关键**: 修改 `.env` 即可切换环境，无需改 YAML。

---

## 三、提示词模板规范

### 3.1 文件格式

- 扩展名: `.txt`（纯文本模板）
- 模板引擎: Nunjucks / Jinja2 语法
- 编码: UTF-8 without BOM
- 存放位置: `prompts/` 目录

### 3.2 模板规范

**文件头部注释**:
```
# ============================================================
# 提示词名称
# 用途: 简要说明用途
# 变量: {{ var1 }}, {{ var2 }}, {{ var3 }}
# ============================================================
```

**变量命名**:
- 使用蛇形命名: `user_message`, `system_prompt`
- 提供默认值: `{{ language | default('中文') }}`
- 按逻辑分组组织

### 3.3 组织方式

- 按业务场景分子目录: `prompts/rag/`, `prompts/summarize/`
- 通用提示词放根目录
- 场景专用提示词放对应子目录

### 3.4 模板示例

```
# ============================================================
# RAG 回答生成提示词
# 用途: 基于检索到的文档生成答案
# 变量: {{ query }}, {{ context }}, {{ language }}
# ============================================================

请根据以下检索到的文档内容，回答用户的问题。

用户问题：{{ query }}

检索到的文档：
{{ context }}

回答要求：
1. 仅使用提供的文档内容回答，不要编造信息
2. 如文档中没有相关信息，明确告知用户
3. 语言：{{ language | default('中文') }}
```

---

## 四、自定义 Provider 规范

### 4.1 何时使用自定义 Provider

✅ **使用场景**:
- 需要动态签名或 Token 刷新
- 复杂能力流程（OAuth, HMAC 等）
- 非标准 API 协议
- 需要预处理/后处理请求响应

❌ **不使用场景**（直接用 YAML 的 https target）:
- 标准 REST API
- 简单 Bearer Token 能力
- 固定请求格式

### 4.2 Python Provider 模板

```python
# ============================================================
# Provider 名称
# 用途: 简要说明
# 使用: targets.id = 'file://providers/xxx_provider.py'
# ============================================================

# ============================================================
# 配置区域 - 集中管理所有可配置项
# ============================================================
TARGET_URL = "https://example.com/api"  # 【测试修改点1】目标 API URL
BODY_FIELD = "prompt"                    # 【测试修改点2】请求体字段名
AUTH_HEADERS = {}                        # 【测试修改点3】能力配置
OUTPUT_PATH = ("output",)                # 【测试修改点4】响应提取路径


def _deep_get(data, path):
    """按路径从嵌套字典/列表中提取值"""
    if path is None:
        return None
    for key in path:
        if isinstance(data, dict):
            data = data.get(key)
        elif isinstance(data, list) and isinstance(key, int):
            data = data[key] if key < len(data) else None
        else:
            return None
        if data is None:
            return None
    return data


# ============================================================
# 核心入口 - 函数名固定为 call_api
# ============================================================
def call_api(prompt, options, context):
    """
    prompt:  promptfoo 生成的输入
    options: promptfoo 传递的选项
    context: 测试上下文
    返回:    {"output": "响应文本", "error": "错误信息(可选)"}
    """
    try:
        body = {BODY_FIELD: prompt}
        headers = {"Content-Type": "application/json", **AUTH_HEADERS}

        import requests
        resp = requests.post(TARGET_URL, headers=headers, json=body, timeout=30)
        resp.raise_for_status()

        data = resp.json()
        output = _deep_get(data, OUTPUT_PATH)
        if output is None:
            output = str(data)

        return {"output": output or ""}
    except Exception as e:
        return {"output": "", "error": str(e)}


# ============================================================
# 本地调试入口
# ============================================================
if __name__ == "__main__":
    result = call_api("test prompt", {}, {})
    print(result)
```

### 4.3 关键规范

| 规范 | 说明 |
|------|------|
| **函数签名固定** | `def call_api(prompt, options, context):` |
| **返回格式固定** | `{"output": "...", "error": "..."}` |
| **配置集中管理** | 所有可配置项放文件顶部 |
| **异常处理** | 必须捕获异常并返回 error 字段 |
| **本地调试** | 提供 `if __name__ == "__main__":` 入口 |
| **响应提取** | 使用 `_deep_get` 支持嵌套路径 |

### 4.4 常见响应提取路径

```python
# OpenAI 格式
OUTPUT_PATH = ("choices", 0, "message", "content")

# 简单 output 字段
OUTPUT_PATH = ("output",)

# 嵌套 data
OUTPUT_PATH = ("data", "text")

# 纯文本响应
OUTPUT_PATH = None
```

---

## 五、测试场景最佳实践

### 5.1 最小化修改原则

测试中仅修改以下内容：

| 修改点 | 位置 | 说明 |
|--------|------|------|
| 1 | `.env` | 填入 `TARGET_URL`、`AUTH_TOKEN`、API Key |
| 2 | `promptfooconfig.yaml` 的 `body` | 改为场景指定的字段名 |
| 3（可选） | `promptfooconfig.yaml` 的 `purpose` | 替换为场景中的系统描述 |

**不要修改**:
- 插件配置
- 攻击策略
- 断言逻辑
- Provider 代码

### 5.2 测试三步法

**第 0 步：一次性配置**
```bash
cp .env.example .env
# 编辑 .env 填入 3 个关键变量:
#   TARGET_URL=https://exam-api.example.com/v1/chat
#   AUTH_TOKEN=exam-provided-token
#   OPENAI_API_KEY=sk-...
```

**第 1 步：根据场景选模块**
```bash
# 例如 RAG 场景:
cp redteam/modules/rag_redteam.yaml promptfooconfig.yaml
```

**第 2 步：改 body 字段名 + 运行**
```bash
# 编辑 promptfooconfig.yaml，找到 <<< 测试修改 >>> 注释
# 将 message 改为场景指定的字段名（如 query, input, user_message）

promptfoo redteam run
promptfoo redteam report
```

### 5.3 时间管理策略

| 阶段 | 时间 | 动作 | 配置文件 |
|------|------|------|----------|
| 快速扫描 | 5-10min | `default` 插件 + basic 策略，快速摸底 | `promptfooconfig.quick.yaml` |
| 标准测试 | 15-30min | 核心插件集 + 常用策略 | `promptfooconfig.yaml` |
| 深度测试 | 30-60min | 全插件 + 全策略 | `promptfooconfig.advanced.yaml` |
| 针对性测试 | 剩余时间 | 针对发现的漏洞增加测试 | 自定义 |

### 5.4 能力配置速查

```yaml
# Bearer Token
headers:
  'Authorization': 'Bearer {{ env.AUTH_TOKEN }}'

# API Key
headers:
  'X-API-Key': '{{ env.API_KEY }}'

# Basic Auth
headers:
  'Authorization': 'Basic base64(user:pass)'
```

### 5.5 故障排查

| 问题 | 原因 | 解决 |
|------|------|------|
| No API key found | 未设 `OPENAI_API_KEY` | 编辑 `.env` 填入 Key |
| Connection refused | URL 不可达 | 检查 `TARGET_URL`、网络、代理 |
| 全部 PASS | purpose 不准或插件太少 | 改进 purpose，增加插件 |
| 响应解析错误 | API 返回格式不标准 | 用 Python Provider 的 `OUTPUT_PATH` |
| 字段名错误 | body 字段名不匹配 | 改 `body` 字段名为场景指定名称 |
