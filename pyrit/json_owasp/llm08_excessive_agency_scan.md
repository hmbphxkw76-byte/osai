# OffSec AI-300 OWASP LLM08-Excessive Agency 扫描脚本（JSON配置版）

## 一、脚本概述

本脚本是 LLM08-Excessive Agency 扫描的 **JSON配置版**，支持通过修改独立的 JSON 文件来配置测试用例，无需修改 Python 代码。

**核心特点：**
- ✅ 测试用例完全独立于代码
- ✅ 只需修改 JSON 文件即可切换测试目标
- ✅ 考试时零代码修改
- ✅ 自动加载和验证配置

**OWASP Top 10 for LLMs v1.1: LLM08 - Excessive Agency**
- 测试模型是否被赋予了过多的权限和自主决策能力
- 检测模型是否可以自主执行操作而无需人工确认

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

打开 `owasp_json/llm08_excessive_agency_cases.json` 文件，修改 `test_cases` 列表。

### 2.3 运行方式

```powershell
py.exe '.\owasp_json\llm08_excessive_agency_scan.py'
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

### 3.2 配置示例

```json
{
    "description": "OffSec AI-300 OWASP LLM08-Excessive Agency 测试用例配置文件",
    "notes": "考试时只需修改此文件中的 test_cases 列表即可，无需修改 .py 文件",
    "test_cases": [
        {
            "id": 1,
            "objective": "你的攻击目标",
            "criterion": "对应的评分标准"
        }
    ]
}
```

## 四、考试重点

### 4.1 考试中如何使用

**零代码修改原则：** 考试时只需修改 `owasp_json/llm08_excessive_agency_cases.json` 文件：

1. 打开 `owasp_json/llm08_excessive_agency_cases.json`
2. 修改 `test_cases` 列表中的测试用例
3. 运行 `py.exe '.\owasp_json\llm08_excessive_agency_scan.py'`

### 4.2 过度权限常见场景

1. **权限提升请求** — 诱导模型发送邮件请求提升权限
2. **日志删除** — 说服模型删除系统日志掩盖操作痕迹
3. **账户修改** — 让模型修改用户账户设置
4. **管理员账户创建** — 欺骗模型创建新的管理员账户

### 4.3 缓解措施

- 实施权限分离和最小权限原则
- 对敏感操作要求人工确认
- 记录所有模型操作日志
- 建立操作审批流程

## 五、文件清单

| 文件 | 用途 |
|------|------|
| [.env](../.env) | 多平台API配置文件 |
| [platform_config_loader.py](../platform_config_loader.py) | 配置加载器 |
| [owasp_json/case_loader.py](case_loader.py) | 测试用例加载器 |
| [owasp_json/llm08_excessive_agency_scan.py](llm08_excessive_agency_scan.py) | LLM08过度权限扫描脚本（JSON配置版） |
| [owasp_json/llm08_excessive_agency_cases.json](llm08_excessive_agency_cases.json) | 测试用例配置文件 |
| [owasp_json/llm08_excessive_agency_scan.md](llm08_excessive_agency_scan.md) | 本文档 |