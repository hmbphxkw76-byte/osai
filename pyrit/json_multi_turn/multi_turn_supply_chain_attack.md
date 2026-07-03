# OffSec AI-300 Multi-Turn AI/ML供应链攻击模块

## 一、脚本概述

本脚本针对 **AI/ML供应链攻击** 场景，使用多轮对话策略获取供应链信息，识别潜在攻击点并执行攻击。

**核心特点：**
- ✅ 使用 RedTeamingAttack 类实现多轮对话攻击
- ✅ 支持 max_turns 参数配置最大对话轮数
- ✅ 测试用例完全独立于代码（JSON配置）
- ✅ 考试时零代码修改原则

## 二、攻击说明

**AI/ML供应链攻击**：攻击者通过污染训练数据、篡改模型权重、注入恶意依赖等方式，在AI系统的供应链环节实施攻击，获取系统控制权或植入后门。

**多轮攻击策略**：
1. 第一轮：了解目标AI系统的供应链组成和依赖关系
2. 第二轮：获取训练数据来源和处理流程信息
3. 第三轮：识别供应链中的薄弱环节和攻击入口
4. 后续轮次：深入了解模型架构和训练管道，执行具体攻击

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

打开 `json_multi_turn/multi_turn_supply_chain_attack_cases.json` 文件：

```json
{
    "description": "OffSec AI-300 AI/ML供应链攻击模块（多轮对话版）测试用例配置文件",
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
py.exe '.\json_multi_turn\multi_turn_supply_chain_attack.py'
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

**零代码修改原则：** 考试时只需修改 `multi_turn_supply_chain_attack_cases.json` 文件：

1. 打开 `json_multi_turn/multi_turn_supply_chain_attack_cases.json`
2. 修改 `test_cases` 列表中的测试用例
3. 运行 `py.exe '.\json_multi_turn\multi_turn_supply_chain_attack.py'`

### 5.2 常见供应链攻击向量

1. **数据污染**：污染训练数据集，使模型产生错误输出
2. **权重篡改**：篡改模型权重，植入后门或恶意行为
3. **依赖注入**：注入恶意依赖包，获取系统控制权
4. **组件替换**：替换模型组件，引入安全漏洞
5. **管道操纵**：操纵模型训练管道，影响模型行为

## 六、文件清单

| 文件 | 用途 |
|------|------|
| [.env](../.env) | 多平台API配置文件 |
| [platform_config_loader.py](../platform_config_loader.py) | 配置加载器 |
| [case_loader.py](../case_loader.py) | 测试用例加载器 |
| [json_multi_turn/multi_turn_supply_chain_attack.py](multi_turn_supply_chain_attack.py) | AI/ML供应链攻击脚本（多轮对话版） |
| [json_multi_turn/multi_turn_supply_chain_attack_cases.json](multi_turn_supply_chain_attack_cases.json) | 测试用例配置文件 |
| [json_multi_turn/multi_turn_supply_chain_attack.md](multi_turn_supply_chain_attack.md) | 本文档 |

## ⚠️ 安全声明

本脚本仅用于授权的安全测试和学习目的，请勿用于非法用途。使用前请确保已获得充分授权。