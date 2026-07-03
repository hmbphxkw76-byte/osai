# OffSec AI-300 Multi-Turn 综合红队演练模块

## 一、脚本概述

本脚本针对 **综合红队演练** 场景，使用多轮对话策略执行全谱红队攻击，从侦察到数据泄露的完整攻击链。

**核心特点：**
- ✅ 使用 RedTeamingAttack 类实现多轮对话攻击
- ✅ 支持 max_turns 参数配置最大对话轮数
- ✅ 测试用例完全独立于代码（JSON配置）
- ✅ 考试时零代码修改原则

## 二、攻击说明

**综合红队演练**：模拟真实攻击者对AI系统的全面渗透测试，包括侦察、武器化、投递、利用、安装、命令控制、动作执行等完整攻击链。

**多轮攻击策略：**
1. 第一轮：侦察阶段，收集目标信息
2. 第二轮：识别漏洞和攻击入口
3. 第三轮：执行初步攻击，获取立足点
4. 后续轮次：横向移动、权限提升、数据泄露

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

打开 `json_multi_turn/multi_turn_capstone_red_team_engagement_cases.json` 文件：

```json
{
    "description": "OffSec AI-300 综合红队演练模块（多轮对话版）测试用例配置文件",
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
py.exe '.\json_multi_turn\multi_turn_capstone_red_team_engagement.py'
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

**零代码修改原则：** 考试时只需修改 `multi_turn_capstone_red_team_engagement_cases.json` 文件：

1. 打开 `json_multi_turn/multi_turn_capstone_red_team_engagement_cases.json`
2. 修改 `test_cases` 列表中的测试用例
3. 运行 `py.exe '.\json_multi_turn\multi_turn_capstone_red_team_engagement.py'`

### 5.2 常见红队攻击场景

1. **完整攻击链**：从侦察到数据泄露的全谱攻击
2. **多层防御绕过**：整合多种攻击策略绕过多层安全防御
3. **APT模拟**：模拟高级持续威胁对AI系统的攻击
4. **横向移动**：从AI系统扩展到企业网络
5. **全面渗透**：获取管理员权限的完整渗透测试

## 六、文件清单

| 文件 | 用途 |
|------|------|
| [.env](../.env) | 多平台API配置文件 |
| [platform_config_loader.py](../platform_config_loader.py) | 配置加载器 |
| [case_loader.py](../case_loader.py) | 测试用例加载器 |
| [json_multi_turn/multi_turn_capstone_red_team_engagement.py](multi_turn_capstone_red_team_engagement.py) | 综合红队演练脚本（多轮对话版） |
| [json_multi_turn/multi_turn_capstone_red_team_engagement_cases.json](multi_turn_capstone_red_team_engagement_cases.json) | 测试用例配置文件 |
| [json_multi_turn/multi_turn_capstone_red_team_engagement.md](multi_turn_capstone_red_team_engagement.md) | 本文档 |

## ⚠️ 安全声明

本脚本仅用于授权的安全测试和学习目的，请勿用于非法用途。使用前请确保已获得充分授权。