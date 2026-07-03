# OffSec AI-300 Crescendo ASI02-Tool Misuse 攻击脚本

## 一、脚本概述

本脚本是 ASI02-Tool Misuse 的 **Crescendo渐进式攻击版**，采用多轮渐进式策略逐步诱导工具滥用。

**核心特点：**
- ✅ 多轮渐进式攻击，逐步诱导工具滥用
- ✅ 支持 max_turns 和 max_backtracks 参数控制攻击深度
- ✅ 测试用例完全独立于代码
- ✅ 只需修改 JSON 文件即可切换测试目标
- ✅ 考试时零代码修改

**OWASP AI Agent Top 10: ASI02 - Tool Misuse (Crescendo模式)**
- 测试代理是否容易被诱导滥用工具
- 通过多轮对话逐步突破工具使用限制
- 适合逐步诱导工具滥用的场景

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

打开 `json_crescendo/crescendo_asi02_tool_misuse_cases.json` 文件，修改配置。

### 2.3 运行方式

```powershell
py.exe '.\json_crescendo\crescendo_asi02_tool_misuse.py'
```

## 三、JSON 配置文件格式

### 3.1 字段说明

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `description` | string | 否 | 配置文件描述 |
| `notes` | string | 否 | 备注说明 |
| `max_turns` | integer | 否 | 最大对话轮数，默认10 |
| `max_backtracks` | integer | 否 | 最大回溯次数，默认4 |
| `test_cases` | array | 是 | 测试用例列表 |
| `test_cases[].id` | integer | 是 | 用例编号 |
| `test_cases[].objective` | string | 是 | 攻击目标文本 |
| `test_cases[].criterion` | string | 是 | 评分标准 |

## 四、Crescendo 攻击策略

### 4.1 策略说明

Crescendo 攻击是一种多轮渐进式攻击策略：
1. **初始探测** - 发送初步请求，了解工具使用的限制机制
2. **逐步推进** - 根据反馈调整策略，逐步诱导工具滥用
3. **回溯调整** - 当遇到拒绝时，回溯并尝试不同路径
4. **最终突破** - 在适当时机诱导工具执行恶意操作

### 4.2 适用场景

- 代理有工具使用限制机制
- 需要绕过工具使用权限控制
- 需要逐步诱导工具滥用
- 单次攻击难以成功诱导工具滥用的场景

## 五、考试重点

### 5.1 考试中如何使用

**零代码修改原则：** 考试时只需修改 `json_crescendo/crescendo_asi02_tool_misuse_cases.json` 文件。

### 5.2 Crescendo 参数调优

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `max_turns` | 10 | 增加可提高成功率，但耗时更长 |
| `max_backtracks` | 4 | 增加可尝试更多路径，但可能陷入循环 |

## 六、文件清单

| 文件 | 用途 |
|------|------|
| [.env](../.env) | 多平台API配置文件 |
| [platform_config_loader.py](platform_config_loader.py) | 配置加载器 |
| [case_loader.py](case_loader.py) | 测试用例加载器 |
| [crescendo_asi02_tool_misuse.py](crescendo_asi02_tool_misuse.py) | ASI02 Crescendo攻击脚本 |
| [crescendo_asi02_tool_misuse_cases.json](crescendo_asi02_tool_misuse_cases.json) | 测试用例配置文件 |
| [crescendo_asi02_tool_misuse.md](crescendo_asi02_tool_misuse.md) | 本文档 |