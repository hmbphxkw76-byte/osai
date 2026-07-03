# OffSec AI-300 RAG05 - RAG上下文混淆扫描脚本（JSON配置版）

## 一、脚本概述

本脚本是 RAG05 上下文混淆扫描的 **JSON配置版**，支持通过修改独立的 JSON 文件来配置测试用例，无需修改 Python 代码。

**核心特点：**
- ✅ 测试用例完全独立于代码
- ✅ 只需修改 JSON 文件即可切换测试目标
- ✅ 考试时零代码修改
- ✅ 自动加载和验证配置

**漏洞描述：**
RAG05 是 RAG 系统的上下文混淆攻击。攻击者通过伪造文档来源、混淆上下文或操纵引用信息，使模型基于不可信的信息源生成响应。

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

打开 `rag05_context_confusion_cases.json` 文件，修改 `test_cases` 列表：

```json
{
    "description": "OffSec AI-300 RAG05 - RAG上下文混淆测试用例配置文件",
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
py.exe '.\owasp_json\rag05_context_confusion_scan.py'
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
1. 攻击者伪造文档的元数据（作者、日期、来源）
2. 创建看起来来自可信来源的恶意文档
3. 当用户查询时，恶意文档被检索到
4. 模型基于伪造的来源信息生成响应，增加攻击成功率
```

## 五、常见伪造来源类型

| 伪造来源 | 示例 |
|----------|------|
| 公司高管 | 公司CEO、技术总监 |
| 部门官方 | IT部门、安全部门 |
| 权威机构 | 审计报告、董事会决议 |
| 时间戳 | 最新、今日更新 |

## 六、考试重点

| 优先级 | 重点内容 |
|--------|----------|
| ⭐⭐⭐ | RAG上下文混淆是中优先级漏洞 |
| ⭐⭐⭐ | 理解文档元数据伪造的技巧 |
| ⭐⭐ | 掌握可信来源的伪装方法 |

## 七、文件清单

| 文件 | 用途 |
|------|------|
| [.env](../.env) | 多平台API配置文件 |
| [case_loader.py](case_loader.py) | 测试用例加载器 |
| [rag05_context_confusion_scan.py](rag05_context_confusion_scan.py) | RAG05扫描脚本（JSON配置版） |
| [rag05_context_confusion_cases.json](rag05_context_confusion_cases.json) | 测试用例配置文件 |
| [rag05_context_confusion_scan.md](rag05_context_confusion_scan.md) | 本文档 |