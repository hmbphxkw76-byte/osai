# OffSec AI-300 Multi-Turn AI目标侦察模块

## 一、脚本概述

本脚本针对 **AI目标侦察** 场景，使用多轮对话策略逐步收集目标AI系统的信息，包括模型类型、API端点、基础设施架构等。

**核心特点：**
- ✅ 使用 RedTeamingAttack 类实现多轮对话攻击
- ✅ 支持 max_turns 参数配置最大对话轮数
- ✅ 测试用例完全独立于代码（JSON配置）
- ✅ 考试时零代码修改原则

## 二、攻击说明

**AI目标侦察**：通过多轮对话逐步收集目标AI系统的详细信息，建立完整的目标画像。

**多轮攻击策略**：
1. 第一轮：建立信任，了解系统基本功能
2. 第二轮：询问技术架构和组件信息
3. 第三轮：深入获取模型细节和版本信息
4. 后续轮次：逐步渗透，获取基础设施和安全配置信息

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

打开 `json_multi_turn/multi_turn_reconnaissance_ai_targets_cases.json` 文件：

```json
{
    "description": "OffSec AI-300 AI目标侦察模块（多轮对话版）测试用例配置文件",
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
py.exe '.\json_multi_turn\multi_turn_reconnaissance_ai_targets.py'
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

**零代码修改原则：** 考试时只需修改 `multi_turn_reconnaissance_ai_targets_cases.json` 文件：

1. 打开 `json_multi_turn/multi_turn_reconnaissance_ai_targets_cases.json`
2. 修改 `test_cases` 列表中的测试用例
3. 运行 `py.exe '.\json_multi_turn\multi_turn_reconnaissance_ai_targets.py'`

### 5.2 常见侦察目标

1. **模型信息收集**：获取AI模型类型、版本、供应商信息
2. **API端点探测**：发现系统暴露的API接口和服务配置
3. **基础设施侦察**：了解部署环境、云服务提供商、网络架构
4. **安全边界识别**：发现访问控制机制、认证方式、权限模型

## 六、文件清单

| 文件 | 用途 |
|------|------|
| [.env](../.env) | 多平台API配置文件 |
| [platform_config_loader.py](../platform_config_loader.py) | 配置加载器 |
| [case_loader.py](../case_loader.py) | 测试用例加载器 |
| [json_multi_turn/multi_turn_reconnaissance_ai_targets.py](multi_turn_reconnaissance_ai_targets.py) | AI目标侦察脚本（多轮对话版） |
| [json_multi_turn/multi_turn_reconnaissance_ai_targets_cases.json](multi_turn_reconnaissance_ai_targets_cases.json) | 测试用例配置文件 |
| [json_multi_turn/multi_turn_reconnaissance_ai_targets.md](multi_turn_reconnaissance_ai_targets.md) | 本文档 |

## ⚠️ 安全声明

本脚本仅用于授权的安全测试和学习目的，请勿用于非法用途。使用前请确保已获得充分授权。