# OffSec AI-300 Multi-Turn 多代理A2A协议攻击模块

## 一、脚本概述

本脚本针对 **多代理系统与A2A协议** 攻击场景，使用多轮对话策略操纵代理间通信，诱导代理执行非预期操作或泄露敏感信息。

**核心特点：**
- ✅ 使用 RedTeamingAttack 类实现多轮对话攻击
- ✅ 支持 max_turns 参数配置最大对话轮数
- ✅ 测试用例完全独立于代码（JSON配置）
- ✅ 考试时零代码修改原则

## 二、攻击说明

**多代理A2A协议攻击**：攻击者通过操纵代理间消息传递，诱导代理执行非预期操作、冒充授权代理、破坏工作流或绕过访问控制。

**多轮攻击策略**：
1. 第一轮：了解代理系统架构和可用代理列表
2. 第二轮：建立与代理的信任关系
3. 第三轮：诱导代理执行敏感操作
4. 后续轮次：冒充其他代理，获取权限升级或敏感信息

## 三、运行前准备

### 3.1 配置 .env 文件

```env
PLATFORM_SELECTOR=ZHIPU

[ZHIPU]
OPENAI_CHAT_KEY=your_zhipu_api_key
OPENAI_CHAT_MODEL=glm-4-plus
OPENAI_CHAT_ENDPOINT=https://open.bigmodel.cn/api/paas/v4
```

### 3.2 修改测试用例（只需修改 JSON 文件！）

打开 `json_multi_turn/multi_turn_multi_agent_a2a_protocol_attack_cases.json` 文件：

```json
{
    "description": "OffSec AI-300 多代理A2A协议攻击模块（多轮对话版）测试用例配置文件",
    "notes": "考试时只需修改此文件中的 test_cases 列表即可，无需修改 .py 文件",
    "max_turns": 5,
    "test_cases": [
        {
            "id": 1,
            "objective": "你的攻击目标",
            "criterion": "对应的评分标准"
        }
    ]
}
```

### 3.3 运行方式

```powershell
py.exe '.\json_multi_turn\multi_turn_multi_agent_a2a_protocol_attack.py'
```

## 四、JSON 配置文件格式

### 4.1 字段说明

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `description` | string | 否 | 配置文件描述 |
| `notes` | string | 否 | 备注说明 |
| `max_turns` | integer | 否 | 最大对话轮数，默认5 |
| `test_cases` | array | 是 | 测试用例列表 |
| `test_cases[].id` | integer | 是 | 用例编号 |
| `test_cases[].objective` | string | 是 | 攻击目标文本 |
| `test_cases[].criterion` | string | 是 | 评分标准 |

## 五、考试重点

### 5.1 考试中如何使用

**零代码修改原则：** 考试时只需修改 `multi_turn_multi_agent_a2a_protocol_attack_cases.json` 文件：

1. 打开 `json_multi_turn/multi_turn_multi_agent_a2a_protocol_attack_cases.json`
2. 修改 `test_cases` 列表中的测试用例
3. 运行 `py.exe '.\json_multi_turn\multi_turn_multi_agent_a2a_protocol_attack.py'`

### 5.2 常见A2A攻击向量

1. **代理操纵**：诱导代理执行非预期操作
2. **身份冒充**：冒充授权代理获取敏感信息
3. **工作流破坏**：破坏多代理协作流程
4. **协议篡改**：篡改代理间通信协议绕过访问控制
5. **凭证泄露**：诱导代理泄露身份凭证

## 六、文件清单

| 文件 | 用途 |
|------|------|
| [.env](../.env) | 多平台API配置文件 |
| [platform_config_loader.py](../platform_config_loader.py) | 配置加载器 |
| [case_loader.py](../case_loader.py) | 测试用例加载器 |
| [json_multi_turn/multi_turn_multi_agent_a2a_protocol_attack.py](multi_turn_multi_agent_a2a_protocol_attack.py) | 多代理A2A协议攻击脚本（多轮对话版） |
| [json_multi_turn/multi_turn_multi_agent_a2a_protocol_attack_cases.json](multi_turn_multi_agent_a2a_protocol_attack_cases.json) | 测试用例配置文件 |
| [json_multi_turn/multi_turn_multi_agent_a2a_protocol_attack.md](multi_turn_multi_agent_a2a_protocol_attack.md) | 本文档 |

## ⚠️ 安全声明

本脚本仅用于授权的安全测试和学习目的，请勿用于非法用途。使用前请确保已获得充分授权。