# OffSec AI-300 多平台API配置指南

## 概述

本文档详细介绍了 OffSec AI-300 考试中支持的16大主流AI平台的配置方法，帮助备考人员快速切换不同平台进行测试。

---

## ⚠️ 重要提示：非兼容平台额外依赖

> **以下平台不兼容OpenAI格式，需要额外安装对应的Python库：**

| 平台 | 需要安装的库 | 安装命令 |
|------|--------------|----------|
| Anthropic Claude | `anthropic` | `pip install anthropic` |
| Google Gemini | `google-generativeai` | `pip install google-generativeai` |
| AWS Bedrock | `boto3` | `pip install boto3` |
| Cohere | `cohere` | `pip install cohere` |
| Voyage AI | `voyageai` | `pip install voyageai` |

> **推荐优先使用以下OpenAI兼容平台**（无需额外安装库）：
> ZHIPU、QWEN、DEEPSEEK、OPENAI、AZURE_OPENAI、OLLAMA、HUGGINGFACE、MISTRAL、PERPLEXITY、META_LLAMA

---

## 一、快速开始

### 1.1 切换平台

只需修改 `.env` 文件的第一行：

```bash
# 默认使用智谱
PLATFORM_SELECTOR=ZHIPU

# 切换到其他平台
PLATFORM_SELECTOR=QWEN    # 阿里千问
PLATFORM_SELECTOR=OPENAI  # OpenAI
PLATFORM_SELECTOR=OLLAMA  # 本地Ollama
PLATFORM_SELECTOR=MISTRAL # 法国Mistral
```

### 1.2 配置API Key

在 `.env` 文件中找到对应平台的配置段落，填写你的API Key：

```bash
[ZHIPU]
OPENAI_CHAT_ENDPOINT=https://open.bigmodel.cn/api/paas/v4
OPENAI_CHAT_MODEL=glm-4-plus
OPENAI_CHAT_KEY=你的智谱API_Key  # ← 在此填写
```

### 1.3 运行测试

```bash
# 单转换器测试
py.exe '.\single_converter_test.py'

# 链式转换器测试
py.exe '.\chained_converter_test.py'
```

---

## 二、平台配置详解

### 2.1 国内平台

#### 智谱 AI (Zhipu AI)

```bash
[ZHIPU]
OPENAI_CHAT_ENDPOINT=https://open.bigmodel.cn/api/paas/v4
OPENAI_CHAT_MODEL=glm-4-plus
OPENAI_CHAT_KEY=your-zhipu-api-key
# 可选模型: glm-4-flash, glm-4-plus, glm-5-52b
```

**官网**: https://open.bigmodel.cn

#### 阿里千问 (Aliyun Qwen)

```bash
[QWEN]
OPENAI_CHAT_ENDPOINT=https://dashscope.aliyuncs.com/compatible-mode/v1
OPENAI_CHAT_MODEL=qwen-turbo
OPENAI_CHAT_KEY=your-qwen-api-key
# 可选模型: qwen-turbo, qwen-plus, qwen-max, qwen2-7b
```

**官网**: https://dashscope.console.aliyun.com

#### 百度文心一言 (Baidu ERNIE)

```bash
[BAIDU]
OPENAI_CHAT_ENDPOINT=https://aip.baidubce.com/rpc/2.0/ai_custom/v1/wenxinworkshop/chat/completions
OPENAI_CHAT_MODEL=ernie-4.0-turbo
OPENAI_CHAT_KEY=your-baidu-api-key
BAIDU_SECRET_KEY=your-baidu-secret-key  # ← 额外需要
# 可选模型: ernie-4.0-turbo, ernie-3.5-turbo, ernie-3.0
```

**官网**: https://cloud.baidu.com/product/wenxinworkshop

#### DeepSeek (深度求索)

```bash
[DEEPSEEK]
OPENAI_CHAT_ENDPOINT=https://api.deepseek.com/v1
OPENAI_CHAT_MODEL=deepseek-chat
OPENAI_CHAT_KEY=your-deepseek-api-key
# 可选模型: deepseek-chat, deepseek-r1-chat, deepseek-r1.5-chat
```

**官网**: https://platform.deepseek.com

---

### 2.2 国外主流平台

#### OpenAI

```bash
[OPENAI]
OPENAI_CHAT_ENDPOINT=https://api.openai.com/v1
OPENAI_CHAT_MODEL=gpt-4o
OPENAI_CHAT_KEY=your-openai-api-key
# 可选模型: gpt-4o-mini, gpt-4-turbo, gpt-4, gpt-3.5-turbo
```

**官网**: https://platform.openai.com

#### Anthropic Claude ⚠️ 需要额外安装库

```bash
[ANTHROPIC]
ANTHROPIC_API_KEY=your-anthropic-api-key
ANTHROPIC_MODEL=claude-3-sonnet-20240229
# 可选模型: claude-3-opus-20240229, claude-3-sonnet-20240229, claude-3-haiku-20240307
```

**安装命令**: `pip install anthropic`

**官网**: https://console.anthropic.com

#### Azure OpenAI

```bash
[AZURE_OPENAI]
OPENAI_CHAT_ENDPOINT=https://your-resource.openai.azure.com/openai/deployments/gpt-4o/chat/completions?api-version=2024-12-01-preview
OPENAI_CHAT_MODEL=gpt-4o
OPENAI_CHAT_KEY=your-azure-api-key
```

**官网**: https://azure.microsoft.com/zh-cn/products/ai-services/openai-service

#### AWS Bedrock ⚠️ 需要额外安装库

```bash
[AWS_BEDROCK]
BEDROCK_MODEL=anthropic.claude-3-sonnet-20240229-v1:0
BEDROCK_REGION=us-east-1
BEDROCK_ACCESS_KEY=your-aws-access-key
BEDROCK_SECRET_KEY=your-aws-secret-key
# 可选模型: anthropic.claude-3-opus, amazon.titan-text-lite-v1, meta.llama3-70b-chat
```

**安装命令**: `pip install boto3`

**官网**: https://aws.amazon.com/bedrock

#### Google Gemini ⚠️ 需要额外安装库

```bash
[GOOGLE_GEMINI]
GEMINI_API_KEY=your-gemini-api-key
GEMINI_MODEL=gemini-1.5-flash
# 可选模型: gemini-1.5-pro, gemini-2.0-flash, gemini-2.0-pro
```

**安装命令**: `pip install google-generativeai`

**官网**: https://ai.google.dev

---

### 2.3 开源本地平台

#### Ollama (本地部署)

```bash
[OLLAMA]
OPENAI_CHAT_ENDPOINT=http://localhost:11434/v1
OPENAI_CHAT_MODEL=llama3.2:3b
OPENAI_CHAT_KEY=ollama
# 可选模型: qwen3:0.6b, qwen3:1.8b, gemma2:2b, phi3:3.8b, mistral:7b, llama3.3:70b
```

**启动命令**: `ollama serve`

**官网**: https://ollama.com

#### Hugging Face Inference Endpoints

```bash
[HUGGINGFACE]
OPENAI_CHAT_ENDPOINT=https://api-inference.huggingface.co/v1
OPENAI_CHAT_MODEL=HuggingFaceH4/zephyr-7b-beta
OPENAI_CHAT_KEY=your-huggingface-api-key
# 可选模型: meta-llama/Llama-2-7b-chat-hf, mistralai/Mistral-7B-Instruct-v0.3
```

**官网**: https://huggingface.co/inference-endpoints

---

### 2.4 欧洲平台

#### Cohere ⚠️ 需要额外安装库

```bash
[COHERE]
COHERE_API_KEY=your-cohere-api-key
COHERE_MODEL=command-r-plus
# 可选模型: command-r-plus, command-r, command, command-light
```

**安装命令**: `pip install cohere`

**官网**: https://cohere.com

#### Mistral AI (法国)

```bash
[MISTRAL]
OPENAI_CHAT_ENDPOINT=https://api.mistral.ai/v1
OPENAI_CHAT_MODEL=mistral-large-latest
OPENAI_CHAT_KEY=your-mistral-api-key
# 可选模型: mistral-large-latest, mistral-medium, mistral-small, open-mistral-7b
```

**官网**: https://mistral.ai

#### Voyage AI ⚠️ 需要额外安装库

```bash
[VOYAGE]
VOYAGE_API_KEY=your-voyage-api-key
VOYAGE_MODEL=voyage-large-2
# 可选模型: voyage-large-2, voyage-2
```

**安装命令**: `pip install voyageai`

**官网**: https://www.voyageai.com

#### Perplexity AI

```bash
[PERPLEXITY]
OPENAI_CHAT_ENDPOINT=https://api.perplexity.ai
OPENAI_CHAT_MODEL=llama-3-sonar-large-32k-chat
OPENAI_CHAT_KEY=your-perplexity-api-key
# 可选模型: llama-3-sonar-large-32k-chat, llama-3-sonar-small-32k-chat
```

**官网**: https://www.perplexity.ai

---

### 2.5 Meta平台

#### Meta Llama Cloud

```bash
[META_LLAMA]
OPENAI_CHAT_ENDPOINT=https://api.llama.meta.com/v1
OPENAI_CHAT_MODEL=llama-3.3-70b
OPENAI_CHAT_KEY=your-meta-api-key
# 可选模型: llama-3.3-8b, llama-3.3-70b, llama-3.3-400b
```

**官网**: https://llama.meta.com

---

## 三、平台兼容性速查表

| 平台 | 兼容OpenAI | 需要额外安装库 | 推荐程度 |
|------|------------|----------------|----------|
| ZHIPU | ✅ | 否 | ⭐⭐⭐⭐⭐ |
| QWEN | ✅ | 否 | ⭐⭐⭐⭐ |
| BAIDU | ✅ | 否 | ⭐⭐⭐⭐ |
| DEEPSEEK | ✅ | 否 | ⭐⭐⭐⭐ |
| OPENAI | ✅ | 否 | ⭐⭐⭐⭐⭐ |
| ANTHROPIC | ❌ | `anthropic` | ⭐⭐⭐ |
| AZURE_OPENAI | ✅ | 否 | ⭐⭐⭐⭐ |
| AWS_BEDROCK | ❌ | `boto3` | ⭐⭐⭐ |
| GOOGLE_GEMINI | ❌ | `google-generativeai` | ⭐⭐⭐⭐ |
| OLLAMA | ✅ | 否 | ⭐⭐⭐⭐⭐ |
| HUGGINGFACE | ✅ | 否 | ⭐⭐⭐ |
| COHERE | ❌ | `cohere` | ⭐⭐⭐ |
| MISTRAL | ✅ | 否 | ⭐⭐⭐⭐ |
| VOYAGE | ❌ | `voyageai` | ⭐⭐ |
| PERPLEXITY | ✅ | 否 | ⭐⭐⭐ |
| META_LLAMA | ✅ | 否 | ⭐⭐⭐⭐ |

---

## 四、考试策略建议

### 4.1 推荐测试顺序

```
1. 智谱 (ZHIPU)           → 默认平台，响应快
2. Ollama (OLLAMA)        → 本地部署，无需网络
3. 千问 (QWEN)            → 国内平台，兼容性好
4. Mistral (MISTRAL)      → 欧洲平台，可能有不同的安全策略
5. OpenAI (OPENAI)        → 参考基准
```

### 4.2 配置文件结构

```
.env 文件结构：
├── PLATFORM_SELECTOR=ZHIPU  ← 平台选择器（修改这里切换平台）
├── [ZHIPU]                  ← 智谱配置
├── [QWEN]                   ← 千问配置
├── [OPENAI]                 ← OpenAI配置
├── ...                      ← 其他平台配置
└── 通用配置                  ← 超时时间、调试模式等
```

### 4.3 配置加载原理

[platform_config_loader.py](platform_config_loader.py) 会根据 `PLATFORM_SELECTOR` 的值：

1. 读取 `.env` 文件中对应段落的配置
2. 将配置加载到环境变量中
3. 对特殊平台进行额外处理（如百度、AWS等）

---

## 五、故障排除

### 5.1 常见问题

| 问题 | 可能原因 | 解决方案 |
|------|----------|----------|
| API Key无效 | Key填写错误或已过期 | 检查API Key是否正确 |
| 连接超时 | 网络问题或API地址错误 | 检查网络和API地址 |
| 模型不存在 | 模型名称错误 | 查看平台官网的模型列表 |
| 缺少依赖库 | 非兼容平台未安装对应库 | 参考第二章安装对应库 |
| 平台配置不存在 | PLATFORM_SELECTOR值错误 | 检查平台名称是否正确 |

### 5.2 调试模式

在 `.env` 文件末尾启用调试模式：

```bash
DEBUG_MODE=true
```

---

## 六、文件清单

| 文件 | 用途 |
|------|------|
| [.env](.env) | 多平台API配置文件 |
| [platform_config_loader.py](platform_config_loader.py) | 配置加载器 |
| [platform_config_loader.md](platform_config_loader.md) | 本文档 |
| [single_turn_attack.py](single_turn_attack.py) | 单轮攻击脚本 |
| [single_turn_attack.md](single_turn_attack.md) | 单轮攻击学习指南 |
| [single_converter_test.py](single_converter_test.py) | 单转换器测试脚本 |
| [single_converter_test.md](single_converter_test.md) | 单转换器学习指南 |
| [chained_converter_test.py](chained_converter_test.py) | 链式转换器测试脚本 |
| [chained_converter_test.md](chained_converter_test.md) | 链式转换器学习指南 |

---

## 七、参考资料

- PyRIT官方文档：https://github.com/Azure/PyRIT
- 智谱API文档：https://open.bigmodel.cn/dev/api
- Ollama文档：https://ollama.com/docs
- Mistral API文档：https://docs.mistral.ai
