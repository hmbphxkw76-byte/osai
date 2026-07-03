# OffSec AI-300 Multi-Turn AI威胁建模模块

## 一、脚本概述

本脚本针对 **AI威胁建模** 场景，使用多轮对话策略分析目标AI系统的威胁态势，识别攻击路径和安全漏洞。

**核心特点：**
- ✅ 使用 RedTeamingAttack 类实现多轮对话攻击
- ✅ 支持 max_turns 参数配置最大对话轮数
- ✅ 测试用例完全独立于代码（JSON配置）
- ✅ 考试时零代码修改原则

## 二、攻击说明

**AI威胁建模**：通过多轮对话逐步分析目标AI系统的安全态势，识别高价值资产、信任边界、攻击路径和威胁等级，制定防御策略。

**多轮攻击策略**：
1. 第一轮：了解目标AI系统的基本架构和功能
2. 第二轮：识别系统中的高价值资产和敏感数据
3. 第三轮：分析信任边界和安全隔离措施
4. 后续轮次：深入评估威胁等级，制定防御策略

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

打开 `json_multi_turn/multi_turn_threat_modeling_ai_cases.json` 文件：

```json
{
    "description": "OffSec AI-300 AI威胁建模模块（多轮对话版）测试用例配置文件",
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
py.exe '.\json_multi_turn\multi_turn_threat_modeling_ai.py'
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

**零代码修改原则：** 考试时只需修改 `multi_turn_threat_modeling_ai_cases.json` 文件：

1. 打开 `json_multi_turn/multi_turn_threat_modeling_ai_cases.json`
2. 修改 `test_cases` 列表中的测试用例
3. 运行 `py.exe '.\json_multi_turn\multi_turn_threat_modeling_ai.py'`

### 5.2 常见威胁建模目标

1. **资产识别**：识别高价值资产和敏感数据
2. **边界分析**：分析信任边界和安全隔离措施
3. **漏洞识别**：识别潜在攻击路径和漏洞
4. **风险评估**：评估威胁等级和风险敞口
5. **防御策略**：制定防御策略和缓解措施

## 六、文件清单

| 文件 | 用途 |
|------|------|
| [.env](../.env) | 多平台API配置文件 |
| [platform_config_loader.py](../platform_config_loader.py) | 配置加载器 |
| [case_loader.py](../case_loader.py) | 测试用例加载器 |
| [json_multi_turn/multi_turn_threat_modeling_ai.py](multi_turn_threat_modeling_ai.py) | AI威胁建模脚本（多轮对话版） |
| [json_multi_turn/multi_turn_threat_modeling_ai_cases.json](multi_turn_threat_modeling_ai_cases.json) | 测试用例配置文件 |
| [json_multi_turn/multi_turn_threat_modeling_ai.md](multi_turn_threat_modeling_ai.md) | 本文档 |

## ⚠️ 安全声明

本脚本仅用于授权的安全测试和学习目的，请勿用于非法用途。使用前请确保已获得充分授权。