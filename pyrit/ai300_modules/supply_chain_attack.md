# OffSec AI-300 AI/ML供应链攻击模块（JSON配置版）

## 一、脚本概述

本脚本是 AI/ML 供应链攻击模块的 **JSON配置版**，支持通过修改独立的 JSON 文件来配置测试用例，无需修改 Python 代码。

**核心特点：**
- ✅ 测试用例完全独立于代码
- ✅ 只需修改 JSON 文件即可切换测试目标
- ✅ 考试时零代码修改
- ✅ 自动加载和验证配置

**功能描述：**
- 数据集污染、模型权重篡改、依赖注入
- 针对训练数据和模型组件的攻击
- 使用 PyRIT 框架进行供应链安全测试

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

打开 `ai300_modules/supply_chain_attack_cases.json` 文件，修改 `test_cases` 列表：

```json
{
    "description": "OffSec AI-300 AI/ML供应链攻击模块测试用例配置文件",
    "notes": "考试时只需修改此文件中的 test_cases 列表即可，无需修改 .py 文件",
    "test_cases": [
        {
            "id": 1,
            "objective": "你的攻击目标",
            "criterion": "对应的评分标准"
        }
    ]
}
```

### 2.3 运行方式

```powershell
py.exe '.\ai300_modules\supply_chain_attack.py'
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

**零代码修改原则：** 考试时只需修改 `ai300_modules/supply_chain_attack_cases.json` 文件：

1. 打开 `supply_chain_attack_cases.json`
2. 修改 `test_cases` 列表中的测试用例
3. 运行 `py.exe '.\ai300_modules\supply_chain_attack.py'`

### 4.2 供应链攻击技巧

1. **数据集污染** — 在训练数据中注入恶意样本
2. **模型权重篡改** — 修改模型参数植入后门
3. **依赖注入** — 植入恶意依赖包
4. **组件替换** — 替换可信组件为恶意版本

### 4.3 常用攻击转换器（按效率排序）

1. **Base64 + ZeroWidth** — 编码后添加零宽字符
2. **ROT13 + Leetspeak** — 双重字符替换
3. **Leetspeak替换** — 字符混淆
4. **Base64编码** — 基础编码
5. **ROT13替换** — 简单替换

## 五、文件清单

| 文件 | 用途 |
|------|------|
| [.env](../.env) | 多平台API配置文件 |
| [ai300_modules/platform_config_loader.py](platform_config_loader.py) | 配置加载器 |
| [ai300_modules/case_loader.py](case_loader.py) | 测试用例加载器 |
| [ai300_modules/supply_chain_attack.py](supply_chain_attack.py) | AI/ML供应链攻击脚本（JSON配置版） |
| [ai300_modules/supply_chain_attack_cases.json](supply_chain_attack_cases.json) | 测试用例配置文件 |
| [ai300_modules/supply_chain_attack.md](supply_chain_attack.md) | 本文档 |