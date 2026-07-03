# OffSec AI-300 EMB06-嵌入空间碰撞攻击扫描脚本（JSON配置版）

## 一、脚本概述

本脚本是 EMB06-嵌入空间碰撞攻击扫描的 **JSON配置版**，支持通过修改独立的 JSON 文件来配置测试用例，无需修改 Python 代码。

**核心特点：**
- ✅ 测试用例完全独立于代码
- ✅ 只需修改 JSON 文件即可切换测试目标
- ✅ 考试时零代码修改
- ✅ 自动加载和验证配置

**漏洞描述：**
- **EMB06 - 嵌入空间碰撞攻击**：攻击者构造不同的输入，使其产生相同或非常接近的embedding向量，从而绕过基于embedding的检测系统或身份验证机制。

**攻击原理：**
1. 攻击者分析embedding模型的向量空间
2. 构造两个不同的输入，使其向量距离非常接近
3. 一个输入是正常的，一个输入是恶意的
4. 系统将恶意输入误认为正常输入，从而绕过检测

**考试重点：** ⭐⭐⭐（中优先级）

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

打开 `owasp_json/emb06_embedding_space_collision_cases.json` 文件，修改 `test_cases` 列表：

```json
{
    "description": "OffSec AI-300 EMB06-嵌入空间碰撞攻击测试用例配置文件",
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
py.exe '.\owasp_json\emb06_embedding_space_collision_scan.py'
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

**零代码修改原则：** 考试时只需修改 `owasp_json/emb06_embedding_space_collision_cases.json` 文件：

1. 打开 `owasp_json/emb06_embedding_space_collision_cases.json`
2. 修改 `test_cases` 列表中的测试用例
3. 运行 `py.exe '.\owasp_json\emb06_embedding_space_collision_scan.py'`

### 4.2 攻击测试要点

- 向量空间碰撞技术
- 内容过滤绕过方法
- 身份验证冒充攻击
- 版权检测绕过
- 同义词替换攻击
- 向量组合异常行为

## 五、文件清单

| 文件 | 用途 |
|------|------|
| [.env](../.env) | 多平台API配置文件 |
| [platform_config_loader.py](../platform_config_loader.py) | 配置加载器 |
| [owasp_json/case_loader.py](case_loader.py) | 测试用例加载器 |
| [owasp_json/emb06_embedding_space_collision_scan.py](emb06_embedding_space_collision_scan.py) | EMB06扫描脚本（JSON配置版） |
| [owasp_json/emb06_embedding_space_collision_cases.json](emb06_embedding_space_collision_cases.json) | 测试用例配置文件 |
| [owasp_json/emb06_embedding_space_collision_scan.md](emb06_embedding_space_collision_scan.md) | 本文档 |