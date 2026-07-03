# OffSec AI-300 RAG03 - RAG检索操纵扫描脚本（JSON配置版）

## 一、脚本概述

本脚本是 RAG03 检索操纵扫描的 **JSON配置版**，支持通过修改独立的 JSON 文件来配置测试用例，无需修改 Python 代码。

**核心特点：**
- ✅ 测试用例完全独立于代码
- ✅ 只需修改 JSON 文件即可切换测试目标
- ✅ 考试时零代码修改
- ✅ 自动加载和验证配置

**漏洞描述：**
RAG03 是 RAG 系统的检索机制攻击。攻击者通过操纵检索算法，影响检索结果的排序和选择，使系统返回攻击者期望的文档。

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

打开 `rag03_retrieval_manipulation_cases.json` 文件，修改 `test_cases` 列表：

```json
{
    "description": "OffSec AI-300 RAG03 - RAG检索操纵测试用例配置文件",
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
py.exe '.\owasp_json\rag03_retrieval_manipulation_scan.py'
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
1. 攻击者分析检索算法（如向量相似度、关键词匹配）
2. 通过精心构造查询或文档，影响检索排序
3. 使恶意文档被优先检索到
4. 模型基于恶意文档生成响应
```

## 五、考试重点

| 优先级 | 重点内容 |
|--------|----------|
| ⭐⭐⭐⭐ | RAG检索操纵是检索机制层面的攻击 |
| ⭐⭐⭐⭐ | 理解检索算法的弱点和操纵方法 |
| ⭐⭐⭐ | 掌握向量相似度和关键词匹配的攻击技巧 |

## 六、文件清单

| 文件 | 用途 |
|------|------|
| [.env](../.env) | 多平台API配置文件 |
| [case_loader.py](case_loader.py) | 测试用例加载器 |
| [rag03_retrieval_manipulation_scan.py](rag03_retrieval_manipulation_scan.py) | RAG03扫描脚本（JSON配置版） |
| [rag03_retrieval_manipulation_cases.json](rag03_retrieval_manipulation_cases.json) | 测试用例配置文件 |
| [rag03_retrieval_manipulation_scan.md](rag03_retrieval_manipulation_scan.md) | 本文档 |