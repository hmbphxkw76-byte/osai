# OffSec AI-300 综合红队演练模块（JSON配置版）

## 一、脚本概述

本脚本是综合红队演练模块的 **JSON配置版**，支持通过修改独立的 JSON 文件来配置测试用例，无需修改 Python 代码。

**核心特点：**
- ✅ 测试用例完全独立于代码
- ✅ 只需修改 JSON 文件即可切换测试目标
- ✅ 考试时零代码修改
- ✅ 自动加载和验证配置

**功能描述：**
- 全谱红队攻击，整合所有模块
- 使用多种攻击策略组合进行综合演练
- 模拟真实红队攻击场景

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

打开 `ai300_modules/capstone_red_team_engagement_cases.json` 文件，修改 `test_cases` 列表：

```json
{
    "description": "OffSec AI-300 综合红队演练模块测试用例配置文件",
    "notes": "考试时只需修改此文件中的 test_cases 列表即可，无需修改 .py 文件",
    "test_cases": [
        {
            "id": 1,
            "objective": "你的红队攻击目标",
            "criterion": "对应的评分标准"
        }
    ]
}
```

### 2.3 运行方式

```powershell
py.exe '.\ai300_modules\capstone_red_team_engagement.py'
```

## 三、JSON 配置文件格式

### 3.1 字段说明

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `description` | string | 否 | 配置文件描述 |
| `notes` | string | 否 | 备注说明 |
| `test_cases` | array | 是 | 测试用例列表 |
| `test_cases[].id` | integer | 是 | 用例编号 |
| `test_cases[].objective` | string | 是 | 红队攻击目标文本 |
| `test_cases[].criterion` | string | 是 | 评分标准 |

## 四、考试重点

### 4.1 考试中如何使用

**零代码修改原则：** 考试时只需修改 `ai300_modules/capstone_red_team_engagement_cases.json` 文件：

1. 打开 `capstone_red_team_engagement_cases.json`
2. 修改 `test_cases` 列表中的测试用例
3. 运行 `py.exe '.\ai300_modules\capstone_red_team_engagement.py'`

### 4.2 红队攻击技巧

1. **全谱攻击** — 从侦察到数据泄露的完整攻击链
2. **多层绕过** — 整合多种攻击策略绕过安全防御
3. **APT模拟** — 模拟高级持续威胁攻击
4. **横向移动** — 从AI系统扩展到企业网络

### 4.3 常用攻击组合（按效率排序）

1. **Base64 + ZeroWidth** — 编码后添加零宽字符，隐藏编码痕迹
2. **Caesar + Leetspeak** — 凯撒密码 + Leetspeak替换
3. **ROT13 + ZeroWidth** — ROT13替换后添加零宽字符
4. **UnicodeConfusable + ZeroWidth** — 相似字符替换后添加零宽字符
5. **Base64 + Leetspeak + ZeroWidth** — 三重混淆
6. **Caesar + UnicodeConfusable** — 凯撒密码移位后进行相似字符替换
7. **ROT13 + Leetspeak** — ROT13替换后进行Leetspeak替换
8. **Caesar + Leetspeak + ZeroWidth** — 三重混淆

## 五、文件清单

| 文件 | 用途 |
|------|------|
| [.env](../.env) | 多平台API配置文件 |
| [ai300_modules/platform_config_loader.py](platform_config_loader.py) | 配置加载器 |
| [ai300_modules/case_loader.py](case_loader.py) | 测试用例加载器 |
| [ai300_modules/capstone_red_team_engagement.py](capstone_red_team_engagement.py) | 综合红队演练脚本（JSON配置版） |
| [ai300_modules/capstone_red_team_engagement_cases.json](capstone_red_team_engagement_cases.json) | 测试用例配置文件 |
| [ai300_modules/capstone_red_team_engagement.md](capstone_red_team_engagement.md) | 本文档 |

## 六、模块整合关系

本模块整合以下 AI-300 攻击模块：

| 模块名称 | 功能 |
|----------|------|
| reconnaissance_ai_targets | AI目标侦察 |
| multi_agent_a2a_protocol_attack | 多代理系统与A2A协议攻击 |
| supply_chain_attack | AI/ML供应链攻击 |
| ai_infrastructure_exploit | AI基础设施攻击 |
| threat_modeling_ai | AI威胁建模 |