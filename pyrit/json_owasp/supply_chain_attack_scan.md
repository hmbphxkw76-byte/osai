# OffSec AI-300 AI Supply Chain Attack 扫描脚本（JSON配置版）

## 一、脚本概述

本脚本是 AI Supply Chain Attack 扫描的 **JSON配置版**，支持通过修改独立的 JSON 文件来配置测试用例，无需修改 Python 代码。

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

打开 `supply_chain_attack_cases.json` 文件，修改 `test_cases` 列表：

```json
{
    "description": "OffSec AI-300 AI Supply Chain Attack 测试用例配置文件",
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
py.exe '.\owasp_json\supply_chain_attack_scan.py'
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

**零代码修改原则：** 考试时只需修改 `supply_chain_attack_cases.json` 文件：

1. 打开 `supply_chain_attack_cases.json`
2. 修改 `test_cases` 列表中的测试用例
3. 运行 `py.exe '.\owasp_json\supply_chain_attack_scan.py'`

### 4.2 供应链攻击类型

- 数据集投毒：在训练数据中注入恶意样本
- 模型权重篡改：替换权重文件植入后门
- 恶意适配器：在模型适配器中注入恶意代码
- 依赖包攻击：在Python包中注入恶意代码
- 恶意模型分发：创建恶意模型诱骗用户下载

## 五、文件清单

| 文件 | 用途 |
|------|------|
| [.env](../.env) | 多平台API配置文件 |
| [platform_config_loader.py](platform_config_loader.py) | 配置加载器 |
| [case_loader.py](case_loader.py) | 测试用例加载器 |
| [supply_chain_attack_scan.py](supply_chain_attack_scan.py) | AI Supply Chain Attack 扫描脚本（JSON配置版） |
| [supply_chain_attack_cases.json](supply_chain_attack_cases.json) | 测试用例配置文件 |
| [supply_chain_attack_scan.md](supply_chain_attack_scan.md) | 本文档 |