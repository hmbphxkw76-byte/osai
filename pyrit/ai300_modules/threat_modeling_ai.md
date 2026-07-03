# OffSec AI-300 AI威胁建模模块（JSON配置版）

## 一、脚本概述

本脚本是 AI 威胁建模模块的 **JSON配置版**，支持通过修改独立的 JSON 文件来配置测试用例，无需修改 Python 代码。

**核心特点：**
- ✅ 测试用例完全独立于代码
- ✅ 只需修改 JSON 文件即可切换测试目标
- ✅ 考试时零代码修改
- ✅ 自动加载和验证配置

**功能描述：**
- 识别高价值AI资产、信任边界、攻击路径
- 分析框架用于AI系统威胁评估
- 使用 PyRIT 框架进行威胁建模分析

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

打开 `ai300_modules/threat_modeling_ai_cases.json` 文件，修改 `test_cases` 列表：

```json
{
    "description": "OffSec AI-300 AI威胁建模模块测试用例配置文件",
    "notes": "考试时只需修改此文件中的 test_cases 列表即可，无需修改 .py 文件",
    "test_cases": [
        {
            "id": 1,
            "objective": "你的威胁建模目标",
            "criterion": "对应的评分标准"
        }
    ]
}
```

### 2.3 运行方式

```powershell
py.exe '.\ai300_modules\threat_modeling_ai.py'
```

## 三、JSON 配置文件格式

### 3.1 字段说明

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `description` | string | 否 | 配置文件描述 |
| `notes` | string | 否 | 备注说明 |
| `test_cases` | array | 是 | 测试用例列表 |
| `test_cases[].id` | integer | 是 | 用例编号 |
| `test_cases[].objective` | string | 是 | 威胁建模目标文本 |
| `test_cases[].criterion` | string | 是 | 评分标准 |

## 四、考试重点

### 4.1 考试中如何使用

**零代码修改原则：** 考试时只需修改 `ai300_modules/threat_modeling_ai_cases.json` 文件：

1. 打开 `threat_modeling_ai_cases.json`
2. 修改 `test_cases` 列表中的测试用例
3. 运行 `py.exe '.\ai300_modules\threat_modeling_ai.py'`

### 4.2 AI威胁建模技巧

1. **资产识别** — 识别AI系统中的高价值资产和敏感数据
2. **边界分析** — 分析信任边界和安全隔离措施
3. **攻击路径识别** — 发现潜在的攻击向量和漏洞
4. **风险评估** — 评估威胁等级和风险敞口

### 4.3 常用威胁建模框架

1. **STRIDE** — Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege
2. **PASTA** — Process for Attack Simulation and Threat Analysis
3. **Trike** — Threat Modeling Toolkit

## 五、文件清单

| 文件 | 用途 |
|------|------|
| [.env](../.env) | 多平台API配置文件 |
| [ai300_modules/platform_config_loader.py](platform_config_loader.py) | 配置加载器 |
| [ai300_modules/case_loader.py](case_loader.py) | 测试用例加载器 |
| [ai300_modules/threat_modeling_ai.py](threat_modeling_ai.py) | AI威胁建模脚本（JSON配置版） |
| [ai300_modules/threat_modeling_ai_cases.json](threat_modeling_ai_cases.json) | 测试用例配置文件 |
| [ai300_modules/threat_modeling_ai.md](threat_modeling_ai.md) | 本文档 |