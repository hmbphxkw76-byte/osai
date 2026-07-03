# OffSec AI-300 ASI07 - Insecure Inter-Agent Communication (A2A) 扫描脚本（JSON配置版）

## 一、脚本概述

本脚本是 ASI07 - Insecure Inter-Agent Communication 扫描的 **JSON配置版**，支持通过修改独立的 JSON 文件来配置测试用例，无需修改 Python 代码。

**核心特点：**
- ✅ 测试用例完全独立于代码
- ✅ 只需修改 JSON 文件即可切换测试目标
- ✅ 考试时零代码修改
- ✅ 自动加载和验证配置

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

打开 `asi07_insecure_inter_agent_communication_cases.json` 文件，修改 `test_cases` 列表：

```json
{
    "description": "OffSec AI-300 ASI07 - Insecure Inter-Agent Communication (A2A) 测试用例配置文件",
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
py.exe '.\owasp_json\asi07_insecure_inter_agent_communication_scan.py'
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

**零代码修改原则：** 考试时只需修改 `asi07_insecure_inter_agent_communication_cases.json` 文件：

1. 打开 `asi07_insecure_inter_agent_communication_cases.json`
2. 修改 `test_cases` 列表中的测试用例
3. 运行 `py.exe '.\owasp_json\asi07_insecure_inter_agent_communication_scan.py'`

### 4.2 常见攻击场景

- **中间人攻击**：拦截和篡改Agent间通信
- **消息伪造**：冒充其他Agent发送消息
- **重放攻击**：重复发送旧消息
- **窃听攻击**：窃取敏感通信内容
- **明文传输**：使用明文协议传输敏感数据
- **通信注入**：向通信通道注入恶意指令
- **身份伪造**：伪造Agent间的身份认证消息

## 五、文件清单

| 文件 | 用途 |
|------|------|
| [.env](../.env) | 多平台API配置文件 |
| [platform_config_loader.py](platform_config_loader.py) | 配置加载器 |
| [case_loader.py](case_loader.py) | 测试用例加载器 |
| [asi07_insecure_inter_agent_communication_scan.py](asi07_insecure_inter_agent_communication_scan.py) | ASI07 扫描脚本（JSON配置版） |
| [asi07_insecure_inter_agent_communication_cases.json](asi07_insecure_inter_agent_communication_cases.json) | 测试用例配置文件 |
| [asi07_insecure_inter_agent_communication_scan.md](asi07_insecure_inter_agent_communication_scan.md) | 本文档 |