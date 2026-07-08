# promptfooconfig.yaml 说明文档

> **测试用途**: 安全评估 LLM 渗透测试 / LLM 安全评估 红队测试  
> **核心原则**: 充分使用 promptfoo 框架原生能力，测试中仅改 2 处

---

## 📋 测试修改清单（仅 2 处！）

```
修改点1: targets.config.url       → 替换为测试提供的 API URL
修改点2: targets.config.body       → 替换字段名为场景要求的字段名
```

其他所有配置（插件、策略、语言、框架）已预设好，无需修改。

---

## YAML 结构速览

```yaml
targets:           # 被测试的目标（promptfoo 原生 https 支持）
  - id: https      # 固定值，表示 HTTP API 测试
    config:
      url: '...'   # ← 测试改这里
      body:
        xxx: '{{prompt}}'  # ← 测试改字段名

redteam:           # 红队测试配置
  injectVar: 'prompt'  # 注入变量名，与 {{prompt}} 对应
  purpose: '...'       # 系统用途描述（从场景复制）
  provider: '...'      # 攻击生成模型
  plugins: [...]       # 漏洞检测插件
  strategies: [...]    # 攻击策略
  language: [...]      # 测试语言
```

---

## Targets 配置详解

### promptfoo 原生支持的 target 类型

| id | 说明 | 测试场景 |
|----|------|---------|
| `https` | HTTP API 测试 | **最常用**，无需 Python 脚本 |
| `openai:模型名` | 直接测试 OpenAI 模型 | 场景给 API Key 时 |
| `file://脚本.py` | 自定义 Python Provider | 仅需动态签名等复杂场景 |

### https target 完整配置

```yaml
targets:
  - id: https
    label: 'my-target'              # 报告标签
    config:
      url: 'https://api.example.com/v1/chat'  # 目标 URL
      method: 'POST'                # HTTP 方法
      headers:                      # 请求头
        'Content-Type': 'application/json'
        # 能力方式（按需取消注释）
        # 'Authorization': 'Bearer TOKEN'
        # 'X-API-Key': 'KEY_VALUE'
      body:                         # 请求体
        prompt_field: '{{prompt}}'  # {{prompt}} 是占位符
```

### 能力配置（promptfoo 原生支持，无需 Python）

```yaml
# Bearer Token
headers:
  'Authorization': 'Bearer eyJhbGciOi...'

# API Key
headers:
  'X-API-Key': 'your-api-key'

# Basic Auth
headers:
  'Authorization': 'Basic base64(user:pass)'
```

---

## Redteam 配置详解

### injectVar

```yaml
injectVar: 'prompt'
```

- 指定将攻击 payload 注入到哪个变量
- 必须与 targets 中的 `{{变量名}}` 一致
- 只有一个变量时可省略（promptfoo 自动推断）

### purpose（测试关键！）

```yaml
purpose: |
  The user is a budget traveler...
  The system is a travel agent...
```

- 直接决定生成的攻击测试质量
- **测试技巧**: 从场景中直接复制关键描述
- 越详细越好：用户角色 + 系统功能 + 安全限制

### provider

```yaml
provider: 'openai:chat:gpt-4o'
```

- 攻击生成模型（独立于被测试目标）
- 需要设置 `OPENAI_API_KEY` 环境变量
- 也可用本地模型: `ollama:chat:llama3.3`

### plugins（核心配置）

#### 预设集合（一行覆盖多类漏洞）

```yaml
plugins:
  - 'default'       # 核心插件集（推荐首选）
  - 'harmful'       # 所有有害内容插件
  - 'pii'           # 所有 PII 插件
```

#### 单独指定（精准控制）

```yaml
plugins:
  - id: 'bola'           # 插件 ID
    numTests: 10         # 测试数量
    severity: 'critical' # 严重级别: low/medium/high/critical
    config:
      graderGuidance: |  # 自定义评分指导
        ...
      graderExamples:    # 评分示例
        - output: "I cannot access that."
          pass: true
          score: 1.0
```

#### 合规框架预设

```yaml
plugins:
  - 'owasp:llm'         # OWASP LLM Top 10
  - 'nist:ai:measure'   # NIST AI RMF
  - 'mitre:atlas'       # MITRE ATLAS
```

### strategies

```yaml
strategies:
  - 'basic'                # 原始测试（必选）
  - 'jailbreak'            # LLM 迭代越狱
  - 'jailbreak:composite'  # 组合越狱
  - 'base64'               # Base64 编码绕过
  - 'leetspeak'            # Leetspeak 编码绕过
```

### language

```yaml
language: ['en', 'zh', 'fr', 'de', 'es']
```

- 多语言测试可发现仅英语下防御良好的漏洞
- 低资源语言（小语种）往往更容易绕过安全防护

---

## 三个配置文件对比

| 文件 | 插件方式 | 测试量 | 运行时间 | 适用场景 |
|------|---------|--------|---------|---------|
| `promptfooconfig_simple.yaml` | `default` 预设 | ~100 | 5-10min | 快速初扫 |
| `promptfooconfig.yaml` | `default` + 补充 | ~200 | 10-20min | 标准测试 |
| `promptfooconfig_advanced.yaml` | 逐个指定 | ~300 | 20-30min | 深度测试 |

**测试策略**: simple → standard → advanced，层层递进。

---

## 常用命令

```bash
# 初始化
promptfoo redteam init

# 运行（默认读 promptfooconfig.yaml）
promptfoo redteam run

# 运行指定配置
promptfoo redteam run -c promptfooconfig_advanced.yaml

# 强制重新生成测试（不用缓存）
promptfoo redteam run --force

# 查看报告
promptfoo redteam report

# 设置 API Key
export OPENAI_API_KEY="sk-..."
```

---

## 故障排查

| 问题 | 原因 | 解决 |
|------|------|------|
| No API key found | 未设 OPENAI_API_KEY | `export OPENAI_API_KEY="sk-..."` |
| Connection refused | URL 不可达 | 检查 URL、网络、代理 |
| 全部 PASS | purpose 不准或插件太少 | 改进 purpose，增加插件 |
| 响应解析错误 | API 返回格式不标准 | 用 Python 脚本的 `call_api` |

---

## 参考

- [promptfoo 红队快速入门](https://www.promptfoo.dev/docs/red-team/quickstart/)
- [红队配置参考](https://www.promptfoo.dev/docs/red-team/configuration/)
- [LLM 漏洞类型](https://www.promptfoo.dev/docs/red-team/llm-vulnerability-types/)
