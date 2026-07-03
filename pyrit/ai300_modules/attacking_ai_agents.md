# OffSec AI-300 攻击AI代理模块（JSON配置版）

## 一、脚本概述

本脚本是 攻击AI代理模块 的 **JSON配置版**，支持通过修改独立的 JSON 文件来配置测试用例，无需修改 Python 代码。

**核心特点：**
- ✅ 测试用例完全独立于代码
- ✅ 只需修改 JSON 文件即可切换测试目标
- ✅ 考试时零代码修改
- ✅ 自动加载和验证配置

**功能描述：**
- 通过滥用提示词指令、记忆系统和工具集成来操纵AI代理
- 演示攻击者如何影响自主AI应用同时保持隐蔽
- 测试AI代理的安全性和防护机制

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

打开 `ai300_modules/attacking_ai_agents_cases.json` 文件，修改 `test_cases` 列表：

```json
{
    "description": "OffSec AI-300 攻击AI代理模块测试用例配置文件",
    "notes": "考试时只需修改此文件中的 test_cases 列表即可，无需修改 .py 文件",
    "test_cases": [
        {
            "id": 1,
            "objective": "你的测试目标",
            "criterion": "对应的评分标准"
        }
    ]
}
```

### 2.3 运行方式

```powershell
py.exe '.\ai300_modules\attacking_ai_agents.py'
```

## 三、JSON 配置文件格式

### 3.1 字段说明

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `description` | string | 否 | 配置文件描述 |
| `notes` | string | 否 | 备注说明 |
| `test_cases` | array | 是 | 测试用例列表 |
| `test_cases[].id` | integer | 是 | 用例编号 |
| `test_cases[].objective` | string | 是 | 测试目标文本 |
| `test_cases[].criterion` | string | 是 | 评分标准 |

## 四、考试重点

### 4.1 考试中如何使用

**零代码修改原则：** 考试时只需修改 `ai300_modules/attacking_ai_agents_cases.json` 文件：

1. 打开 `attacking_ai_agents_cases.json`
2. 修改 `test_cases` 列表中的测试用例
3. 运行 `py.exe '.\ai300_modules\attacking_ai_agents.py'`

### 4.2 攻击AI代理技巧

1. **提示词指令滥用** — 通过精心构造的提示词绕过代理的安全限制
2. **记忆系统攻击** — 利用代理的上下文记忆提取信息或植入恶意指令
3. **工具调用劫持** — 操纵代理调用工具的方式执行非预期操作
4. **角色扮演攻击** — 通过身份伪装诱导代理执行特定任务

## 五、文件清单

| 文件 | 用途 |
|------|------|
| [.env](../.env) | 多平台API配置文件 |
| [ai300_modules/platform_config_loader.py](platform_config_loader.py) | 配置加载器 |
| [ai300_modules/case_loader.py](case_loader.py) | 测试用例加载器 |
| [ai300_modules/attacking_ai_agents.py](attacking_ai_agents.py) | 攻击AI代理脚本（JSON配置版） |
| [ai300_modules/attacking_ai_agents_cases.json](attacking_ai_agents_cases.json) | 测试用例配置文件 |
| [ai300_modules/attacking_ai_agents.md](attacking_ai_agents.md) | 本文档 |
