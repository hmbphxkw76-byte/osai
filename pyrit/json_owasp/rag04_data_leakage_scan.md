# OffSec AI-300 RAG04 - RAG数据泄露扫描脚本（JSON配置版）

## 一、脚本概述

本脚本是 RAG04 数据泄露扫描的 **JSON配置版**，支持通过修改独立的 JSON 文件来配置测试用例，无需修改 Python 代码。

**核心特点：**
- ✅ 测试用例完全独立于代码
- ✅ 只需修改 JSON 文件即可切换测试目标
- ✅ 考试时零代码修改
- ✅ 自动加载和验证配置

**漏洞描述：**
RAG04 是 RAG 系统的数据泄露攻击。攻击者通过精心构造查询，从 RAG 索引中提取敏感数据，包括 PII、商业机密、内部文档等。

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

打开 `rag04_data_leakage_cases.json` 文件，修改 `test_cases` 列表：

```json
{
    "description": "OffSec AI-300 RAG04 - RAG数据泄露测试用例配置文件",
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
py.exe '.\owasp_json\rag04_data_leakage_scan.py'
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
1. 攻击者分析RAG系统的索引内容和检索模式
2. 通过模糊查询、通配符查询或间接提问
3. 触发系统返回包含敏感数据的文档片段
4. 从响应中提取敏感信息
```

## 五、考试重点

| 优先级 | 重点内容 |
|--------|----------|
| ⭐⭐⭐⭐⭐ | RAG数据泄露是最常见的安全风险之一 |
| ⭐⭐⭐⭐⭐ | 掌握各种敏感数据类型的提取方法 |
| ⭐⭐⭐⭐ | 理解模糊查询和间接提问的技巧 |

## 六、常见泄露数据类型

| 数据类型 | 示例 |
|----------|------|
| PII | 姓名、工号、邮箱、联系方式 |
| 财务数据 | 收入、支出、利润、合同价格 |
| 配置信息 | API密钥、数据库连接字符串 |
| 商业机密 | 战略规划、未公开产品信息 |
| 安全信息 | 漏洞列表、风险评估、修复计划 |

## 七、文件清单

| 文件 | 用途 |
|------|------|
| [.env](../.env) | 多平台API配置文件 |
| [case_loader.py](case_loader.py) | 测试用例加载器 |
| [rag04_data_leakage_scan.py](rag04_data_leakage_scan.py) | RAG04扫描脚本（JSON配置版） |
| [rag04_data_leakage_cases.json](rag04_data_leakage_cases.json) | 测试用例配置文件 |
| [rag04_data_leakage_scan.md](rag04_data_leakage_scan.md) | 本文档 |