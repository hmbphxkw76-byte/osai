# OffSec AI-300 EMB02-向量投毒攻击扫描脚本（JSON配置版）

## 一、脚本概述

本脚本是 EMB02-向量投毒攻击扫描的 **JSON配置版**，支持通过修改独立的 JSON 文件来配置测试用例，无需修改 Python 代码。

**核心特点：**
- ✅ 测试用例完全独立于代码
- ✅ 只需修改 JSON 文件即可切换测试目标
- ✅ 考试时零代码修改
- ✅ 自动加载和验证配置

**漏洞描述：**
- **EMB02 - 向量投毒攻击**：攻击者通过操纵embedding向量，使系统返回错误的检索结果或做出错误的分类决策。与RAG03检索操纵的区别在于，向量投毒是在向量表示层面的攻击，而非检索算法层面。

**攻击原理：**
1. 攻击者在向量数据库中插入恶意向量
2. 恶意向量与正常向量非常接近
3. 当用户查询时，系统检索到恶意向量对应的文档
4. 模型基于错误信息生成响应

**考试重点：** ⭐⭐⭐⭐⭐（最高优先级）

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

打开 `owasp_json/emb02_vector_poisoning_cases.json` 文件，修改 `test_cases` 列表：

```json
{
    "description": "OffSec AI-300 EMB02-向量投毒攻击测试用例配置文件",
    "notes": "考试时只需修改此文件中的 test_cases 列表即可，无需修改 .py 文件",
    "test_cases": [
        {
            "id": 1,
            "objective": "你的攻击目标",
            "criterion": "对应的评分标准"
        },
        {
            "id": 2,
            "objective": "你的攻击目标",
            "criterion": "对应的评分标准"
        }
    ]
}
```

### 2.3 运行方式

```powershell
py.exe '.\owasp_json\emb02_vector_poisoning_scan.py'
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

## 四、考试重点

### 4.1 考试中如何使用

**零代码修改原则：** 考试时只需修改 `owasp_json/emb02_vector_poisoning_cases.json` 文件：

1. 打开 `owasp_json/emb02_vector_poisoning_cases.json`
2. 修改 `test_cases` 列表中的测试用例
3. 运行 `py.exe '.\owasp_json\emb02_vector_poisoning_scan.py'`

### 4.2 攻击测试要点

- 向量数据库注入攻击
- 恶意向量插入技术
- 余弦相似度操纵
- 向量索引污染
- 模型投毒攻击

## 五、文件清单

| 文件 | 用途 |
|------|------|
| [.env](../.env) | 多平台API配置文件 |
| [platform_config_loader.py](../platform_config_loader.py) | 配置加载器 |
| [owasp_json/case_loader.py](case_loader.py) | 测试用例加载器 |
| [owasp_json/emb02_vector_poisoning_scan.py](emb02_vector_poisoning_scan.py) | EMB02扫描脚本（JSON配置版） |
| [owasp_json/emb02_vector_poisoning_cases.json](emb02_vector_poisoning_cases.json) | 测试用例配置文件 |
| [owasp_json/emb02_vector_poisoning_scan.md](emb02_vector_poisoning_scan.md) | 本文档 |