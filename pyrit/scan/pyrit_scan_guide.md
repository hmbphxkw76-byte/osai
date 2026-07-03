# OffSec AI-300 PyRIT Scan 命令行工具使用指南

## 📋 概述

`pyrit_scan` 是 PyRIT 框架的核心命令行工具，用于对 AI 系统进行自动化安全评估和红队攻击测试。它基于场景（Scenario）机制，支持灵活配置不同的攻击策略和目标端点。

**考试重点**：理解场景、初始化器、策略的概念，能够快速配置和运行扫描任务。

## 🚀 快速入门

### 1. 查看帮助信息

```powershell
pyrit_scan --help
```

**逐行解释**：
- `pyrit_scan`：PyRIT 的命令行扫描工具
- `--help`：显示帮助信息，包括所有可用命令和参数

**输出内容**：
- 可用场景列表
- 可用初始化器列表
- 命令格式和参数说明

### 2. 列出所有可用场景

```powershell
pyrit_scan --list-scenarios
```

**逐行解释**：
- `--list-scenarios`：列出所有已注册的测试场景
- 场景是预定义的测试流程，包含攻击策略和数据集配置

**常见场景**：
| 场景 | 说明 | 适用场景 |
|------|------|---------|
| `airt.rapid_response` | 快速响应场景 | 多类别有害内容测试 |
| `airt.psychosocial` | 心理社会危害场景 | 危机处理、治疗师冒充测试 |
| `airt.cyber` | 网络安全场景 | 恶意软件生成测试 |
| `airt.jailbreak` | 越狱攻击场景 | 模板式越狱测试 |
| `foundry.red_team_agent` | Foundry红队代理 | 综合红队测试 |
| `garak.encoding` | Garak编码测试 | 编码混淆攻击测试 |

### 3. 列出所有可用初始化器

```powershell
pyrit_scan --list-initializers
```

**逐行解释**：
- `--list-initializers`：列出所有已注册的初始化器
- 初始化器用于配置扫描环境（目标、评分器、数据集等）

**常用初始化器**：
| 初始化器 | 说明 |
|---------|------|
| `target` | 注册目标模型（OpenAIChatTarget） |
| `scorer` | 注册评分器（用于评估攻击结果） |
| `simple` | 简单初始化（包含target和scorer） |
| `load_default_datasets` | 加载默认测试数据集 |

## 📝 运行场景

### 基本命令格式

```powershell
pyrit_scan <场景名称> --target <目标名称> --initializers <初始化器1> <初始化器2> --strategies <策略1> <策略2>
```

**逐行解释**：
- `<场景名称>`：要运行的测试场景（如 `airt.rapid_response`）
- `--target <目标名称>`：指定攻击目标（如 `openai_chat`）
- `--initializers`：指定初始化器（可多个，空格分隔）
- `--strategies`：指定攻击策略（可多个，空格分隔）

### 示例1：运行 AIRT 快速响应场景

```powershell
pyrit_scan airt.rapid_response ^
  --initializers target load_default_datasets ^
  --target openai_chat ^
  --strategies role_play ^
  --dataset-names airt_hate ^
  --max-dataset-size 1
```

**逐行解释**：
- `airt.rapid_response`：场景名称，测试多类别有害内容
- `--initializers target load_default_datasets`：使用 target 和 load_default_datasets 初始化器
- `--target openai_chat`：目标是 OpenAI 兼容的聊天模型
- `--strategies role_play`：使用角色扮演攻击策略
- `--dataset-names airt_hate`：使用仇恨言论数据集
- `--max-dataset-size 1`：数据集大小限制为1条（快速测试）

**可用策略**：
- `ALL`：所有策略
- `DEFAULT`：默认策略
- `SINGLE_TURN`：单轮攻击
- `MULTI_TURN`：多轮攻击
- `role_play`：角色扮演攻击
- `many_shot`：多样本攻击
- `tap`：树状搜索攻击

### 示例2：运行 AIRT 网络安全场景

```powershell
pyrit_scan airt.cyber ^
  --initializers target load_default_datasets ^
  --target openai_chat ^
  --strategies multi_turn ^
  --max-dataset-size 1
```

**逐行解释**：
- `airt.cyber`：场景名称，测试恶意软件生成
- `--strategies multi_turn`：使用多轮攻击策略

**可用策略**：
- `ALL`：所有策略
- `MULTI_TURN`：多轮攻击
- `red_teaming`：红队攻击

### 示例3：运行 AIRT 心理社会危害场景

```powershell
pyrit_scan airt.psychosocial ^
  --target openai_chat ^
  --strategies imminent_crisis ^
  --max-dataset-size 1
```

**逐行解释**：
- `airt.psychosocial`：场景名称，测试心理社会危害
- `--strategies imminent_crisis`：测试紧急危机处理能力

**可用策略**：
- `ALL`：所有策略
- `ImminentCrisis`：紧急危机处理
- `LicensedTherapist`：持证治疗师冒充

### 示例4：运行 AIRT 越狱攻击场景

```powershell
pyrit_scan airt.jailbreak ^
  --initializers target load_default_datasets ^
  --target openai_chat ^
  --strategies prompt_sending ^
  --max-dataset-size 1
```

**逐行解释**：
- `airt.jailbreak`：场景名称，测试越狱攻击
- `--strategies prompt_sending`：使用直接提示发送策略

**可用策略**：
- `ALL`：所有策略
- `SIMPLE`：简单策略
- `COMPLEX`：复杂策略
- `PromptSending`：直接提示发送
- `ManyShot`：多样本攻击
- `SkeletonKey`：骨架密钥攻击
- `RolePlay`：角色扮演攻击

### 示例5：运行 Foundry 红队代理场景

```powershell
pyrit_scan foundry.red_team_agent ^
  --target openai_chat ^
  --initializers load_default_datasets target ^
  --strategies base64
```

**逐行解释**：
- `foundry.red_team_agent`：场景名称，Foundry红队代理
- `--strategies base64`：使用Base64编码策略

## ⚙️ 高级配置

### 覆盖运行参数

```powershell
# 设置并发数和重试次数
pyrit_scan foundry.red_team_agent ^
  --target openai_chat ^
  --initializers load_default_datasets target ^
  --max-concurrency 10 ^
  --max-retries 3

# 添加自定义内存标签（用于追踪）
pyrit_scan foundry.red_team_agent ^
  --target openai_chat ^
  --initializers load_default_datasets target ^
  --memory-labels '{"experiment": "test1", "version": "v2", "researcher": "alice"}'
```

**参数说明**：
| 参数 | 说明 | 默认值 |
|------|------|--------|
| `--max-concurrency` | 最大并发攻击数 | 1 |
| `--max-retries` | 最大重试次数 | 0 |
| `--memory-labels` | 自定义标签（JSON格式） | 无 |

### 使用自定义初始化脚本

```powershell
pyrit_scan garak.encoding --initialization-scripts ./my_custom_config.py
```

**逐行解释**：
- `--initialization-scripts`：指定自定义初始化脚本路径
- `./my_custom_config.py`：自定义配置脚本

## 🎯 考试实战技巧

### 技巧1：快速测试多个策略

```powershell
# 同时测试多个策略
pyrit_scan airt.rapid_response ^
  --target openai_chat ^
  --initializers target load_default_datasets ^
  --strategies role_play many_shot tap ^
  --max-dataset-size 2
```

### 技巧2：使用 ALL 策略快速覆盖

```powershell
# 使用所有策略进行全面测试
pyrit_scan airt.jailbreak ^
  --target openai_chat ^
  --initializers target load_default_datasets ^
  --strategies ALL ^
  --max-dataset-size 1
```

### 技巧3：指定多个数据集

```powershell
# 测试多个有害类别
pyrit_scan airt.rapid_response ^
  --target openai_chat ^
  --initializers target load_default_datasets ^
  --strategies role_play ^
  --dataset-names airt_hate airt_violence airt_sexual ^
  --max-dataset-size 1
```

### 技巧4：结合配置文件使用

```powershell
# 使用配置文件（默认 ~/.pyrit/.pyrit_conf）
pyrit_scan airt.rapid_response ^
  --config-file ./.pyrit_conf ^
  --strategies role_play
```

## 📊 结果分析

### 场景结果输出格式

```
====================================================================================================
📊 SCENARIO RESULTS: RapidResponse 
====================================================================================================

▼ Scenario Information
────────────────────────────────────────────────────────────────────────────────────────────────────
 📋 Scenario Details
 • Name: RapidResponse
 • Scenario Version: 2
 • PyRIT Version: 0.14.0.dev0

 🎯 Target Information
 • Target Type: OpenAIChatTarget
 • Target Model: gpt-4o-japan-nilfilter

 📊 Scorer Information
 • Scorer Type: TrueFalseInverterScorer
 • Composite of 1 scorer(s):
   • SelfAskRefusalScorer

▼ Overall Statistics
────────────────────────────────────────────────────────────────────────────────────────────────────
 📈 Summary
 • Total Strategies: 2
 • Total Attack Results: 2
 • Overall Success Rate: 0%
 • Unique Objectives: 1

▼ Per-Strategy Breakdown
────────────────────────────────────────────────────────────────────────────────────────────────────
 🔸 Strategy: baseline
 • Number of Results: 1
 • Success Rate: 0%

 🔸 Strategy: airt_hate
 • Number of Results: 1
 • Success Rate: 0%
====================================================================================================
```

### 关键指标解读

| 指标 | 说明 | 考试关注点 |
|------|------|-----------|
| **Overall Success Rate** | 总体成功率 | 评估目标模型的安全性 |
| **Per-Strategy Success Rate** | 各策略成功率 | 识别有效的攻击方法 |
| **Scorer Type** | 评分器类型 | 理解评估机制 |
| **Target Model** | 目标模型 | 确认测试对象 |

## 🔗 相关资源

| 资源 | 说明 |
|------|------|
| [pyrit_scan_wrapper.py](file:///D:/文档/codes/ai_sec/pyrit/pyrit_scan_wrapper.py) | pyrit_scan 代码封装脚本 |
| [airt_scan.py](file:///D:/文档/codes/ai_sec/pyrit/airt_scan.py) | AIRT 场景测试脚本 |
| [pyrit_shell_guide.md](file:///D:/文档/codes/ai_sec/pyrit/pyrit_shell_guide.md) | pyrit_shell 交互式工具指南 |
| [custom_scenario_example.py](file:///D:/文档/codes/ai_sec/pyrit/custom_scenario_example.py) | 自定义场景示例 |

## ⚠️ 安全声明

本指南仅用于授权的安全测试和学习目的，请勿用于非法用途。使用前请确保已获得充分授权。