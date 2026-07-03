# OffSec AI-300 RAG02 - RAG语料库投毒扫描脚本（JSON配置版）

## 一、脚本概述

本脚本是 RAG02 语料库投毒扫描的 **JSON配置版**，支持通过修改独立的 JSON 文件来配置测试用例，无需修改 Python 代码。

**核心特点：**
- ✅ 测试用例完全独立于代码
- ✅ 只需修改 JSON 文件即可切换测试目标
- ✅ 考试时零代码修改
- ✅ 自动加载和验证配置

**漏洞描述：**
RAG02 是 RAG 系统的数据层面攻击。攻击者通过向 RAG 语料库中注入恶意文档，污染训练或检索数据，从而影响模型的输出结果。

**与 RAG01 的区别：**
| 漏洞 | 攻击层面 | 特点 |
|------|----------|------|
| RAG01 | 提示词层面 | 恶意指令直接执行 |
| RAG02 | 数据层面 | 污染语料库数据 |

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

打开 `rag02_corpus_poisoning_cases.json` 文件，修改 `test_cases` 列表：

```json
{
    "description": "OffSec AI-300 RAG02 - RAG语料库投毒测试用例配置文件",
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
py.exe '.\owasp_json\rag02_corpus_poisoning_scan.py'
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
1. 攻击者上传或修改RAG语料库中的文档
2. 注入包含错误信息、恶意指令或误导性内容的文档
3. 当用户提问时，系统检索到被污染的文档
4. 模型基于错误信息生成响应，导致安全漏洞
```

## 五、考试重点

| 优先级 | 重点内容 |
|--------|----------|
| ⭐⭐⭐⭐⭐ | RAG语料库投毒是数据层面的攻击 |
| ⭐⭐⭐⭐⭐ | 与RAG01的区别：数据层面 vs 提示词层面 |
| ⭐⭐⭐⭐ | 理解语料库污染如何影响模型输出 |

## 六、文件清单

| 文件 | 用途 |
|------|------|
| [.env](../.env) | 多平台API配置文件 |
| [case_loader.py](case_loader.py) | 测试用例加载器 |
| [rag02_corpus_poisoning_scan.py](rag02_corpus_poisoning_scan.py) | RAG02扫描脚本（JSON配置版） |
| [rag02_corpus_poisoning_cases.json](rag02_corpus_poisoning_cases.json) | 测试用例配置文件 |
| [rag02_corpus_poisoning_scan.md](rag02_corpus_poisoning_scan.md) | 本文档 |