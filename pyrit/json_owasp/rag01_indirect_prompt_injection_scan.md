# OffSec AI-300 RAG01 - RAG间接提示注入扫描脚本（JSON配置版）

## 一、脚本概述

本脚本是 RAG01 间接提示注入扫描的 **JSON配置版**，支持通过修改独立的 JSON 文件来配置测试用例，无需修改 Python 代码。

**核心特点：**
- ✅ 测试用例完全独立于代码
- ✅ 只需修改 JSON 文件即可切换测试目标
- ✅ 考试时零代码修改
- ✅ 自动加载和验证配置

**漏洞描述：**
RAG01 是 RAG 系统最核心、最常见的安全漏洞。攻击者通过向 RAG 知识库中注入包含恶意指令的文档，当模型检索到这些文档时，恶意指令会被间接执行。

## 二、运行前准备

### 2.1 配置 .env 文件

```env
PLATFORM_SELECTOR=ZHIPU

[ZHIPU]
OPENAI_CHAT_KEY=your_zhipu_api_key
OPENAI_CHAT_MODEL=glm-4-plus
OPENAI_CHAT_ENDPOINT=https://open.bigmodel.cn/api/paas/v4
```

### 2.2 修改测试用例（只需修改 JSON 文件！）

打开 `rag01_indirect_prompt_injection_cases.json` 文件，修改 `test_cases` 列表：

```json
{
    "description": "OffSec AI-300 RAG01 - RAG间接提示注入测试用例配置文件",
    "notes": "考试时只需修改此文件中的 test_cases 列表即可",
    "test_cases": [
        {
            "id": 1,
            "objective": "你的攻击目标",
            "criterion": "对应的评分标准"
        }
    ]
}
```

### 2.3 运行方式

```powershell
py.exe '.\owasp_json\rag01_indirect_prompt_injection_scan.py'
```

## 三、JSON 配置文件格式

### 3.1 字段说明

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `description` | string | 否 | 配置文件描述 |
| `notes` | string | 否 | 备注说明 |
| `test_cases` | array | 是 | 测试用例列表 |
| `test_cases[].id` | integer | 是 | 用例编号 |
| `test_cases[].objective` | string | 是 | 攻击目标文本 |
| `test_cases[].criterion` | string | 是 | 评分标准 |

## 四、攻击原理

```
1. 攻击者将包含恶意指令的文档注入到RAG知识库
2. 用户正常提问时，RAG系统检索到该恶意文档
3. 恶意文档中的指令被作为上下文传递给模型
4. 模型执行恶意指令，绕过安全限制
```

## 五、考试重点

| 优先级 | 重点内容 |
|--------|----------|
| ⭐⭐⭐⭐⭐ | RAG间接提示注入是RAG系统最核心的安全漏洞 |
| ⭐⭐⭐⭐⭐ | 考试时只需修改 JSON 文件，无需修改 .py 文件 |
| ⭐⭐⭐⭐ | 理解恶意指令如何通过知识库文档间接执行 |

## 六、文件清单

| 文件 | 用途 |
|------|------|
| [.env](../.env) | 多平台API配置文件 |
| [case_loader.py](case_loader.py) | 测试用例加载器 |
| [rag01_indirect_prompt_injection_scan.py](rag01_indirect_prompt_injection_scan.py) | RAG01扫描脚本（JSON配置版） |
| [rag01_indirect_prompt_injection_cases.json](rag01_indirect_prompt_injection_cases.json) | 测试用例配置文件 |
| [rag01_indirect_prompt_injection_scan.md](rag01_indirect_prompt_injection_scan.md) | 本文档 |