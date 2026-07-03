# OffSec AI-300 PyRIT Shell 交互式工具使用指南

## 📋 概述

`pyrit_shell` 是 PyRIT 的交互式命令行工具，提供 REPL（Read-Eval-Print Loop）环境，用于快速测试和调试 AI 红队场景。

**考试重点**：理解交互式工作流程，能够快速探索和测试不同策略。

## 🚀 启动 Shell

### 基本启动

```powershell
pyrit_shell
```

**逐行解释**：
- `pyrit_shell`：启动交互式 Shell

**输出内容**：
```
PyRIT Shell v0.14.0
Type 'help' for available commands.
pyrit> 
```

### 带参数启动

```powershell
# 加载初始化器
pyrit_shell --initializers load_default_datasets

# 加载自定义配置脚本
pyrit_shell --initialization-scripts ./my_config.py

# 设置日志级别
pyrit_shell --log-level DEBUG

# 指定配置文件
pyrit_shell --config-file ./.pyrit_conf
```

**逐行解释**：
- `--initializers`：启动时加载初始化器
- `--initialization-scripts`：启动时加载自定义配置脚本
- `--log-level`：设置日志级别（DEBUG/INFO/WARNING/ERROR）
- `--config-file`：指定配置文件路径

## 📝 常用命令

### 查看可用命令

```powershell
pyrit> help
```

**逐行解释**：
- `help`：显示所有可用命令

### 列出场景

```powershell
pyrit> list-scenarios
```

**逐行解释**：
- `list-scenarios`：列出所有已注册的测试场景

### 列出初始化器

```powershell
pyrit> list-initializers
```

**逐行解释**：
- `list-initializers`：列出所有已注册的初始化器

### 列出目标

```powershell
pyrit> list-targets
```

**逐行解释**：
- `list-targets`：列出所有已注册的目标模型

### 运行场景

```powershell
pyrit> run airt.rapid_response --target openai_chat --initializers target load_default_datasets --strategies role_play
```

**逐行解释**：
- `run`：运行场景命令
- `airt.rapid_response`：场景名称
- `--target openai_chat`：目标模型
- `--initializers`：初始化器
- `--strategies`：攻击策略

### 查看历史记录

```powershell
pyrit> scenario-history
```

**逐行解释**：
- `scenario-history`：查看当前会话的所有运行记录

### 查看详细结果

```powershell
# 查看最近一次运行结果
pyrit> print-scenario

# 查看指定运行结果（数字来自 history）
pyrit> print-scenario 1
```

**逐行解释**：
- `print-scenario`：显示场景运行的详细结果
- 可选参数：运行序号（从 history 中获取）

### 清空屏幕

```powershell
pyrit> clear
```

### 退出 Shell

```powershell
pyrit> exit
# 或
pyrit> quit
# 或
pyrit> q
```

## 🎯 考试实战技巧

### 技巧1：快速探索工作流

```powershell
# 启动 Shell 并加载初始化器
pyrit_shell --initializers target load_default_datasets

# 查看可用场景
pyrit> list-scenarios

# 运行第一个测试
pyrit> run airt.rapid_response --strategies role_play

# 运行第二个测试
pyrit> run airt.jailbreak --strategies many_shot

# 查看历史记录
pyrit> scenario-history

# 查看详细结果
pyrit> print-scenario 1
```

### 技巧2：使用短参数

```powershell
# 使用 -s 代替 --strategies
pyrit> run foundry.red_team_agent --initializers target load_default_datasets -s base64 rot13

# 多个策略
pyrit> run garak.encoding --initializers target load_default_datasets -s base64 morse_code
```

### 技巧3：设置运行参数

```powershell
# 设置并发数和重试次数
pyrit> run foundry.red_team_agent --initializers target load_default_datasets --max-concurrency 5 --max-retries 2

# 添加自定义标签
pyrit> run garak.encoding --initializers target load_default_datasets --memory-labels '{"experiment":"test1"}'
```

### 技巧4：比较不同策略结果

```powershell
# 运行 baseline
pyrit> run airt.rapid_response --strategies baseline

# 运行 role_play
pyrit> run airt.rapid_response --strategies role_play

# 运行 many_shot
pyrit> run airt.rapid_response --strategies many_shot

# 查看历史并比较
pyrit> scenario-history
pyrit> print-scenario 1  # baseline
pyrit> print-scenario 2  # role_play
pyrit> print-scenario 3  # many_shot
```

## ⚡ Shell 优势

| 特性 | 说明 | 考试价值 |
|------|------|---------|
| **快速执行** | 模块仅在启动时加载一次 | 节省时间 |
| **会话追踪** | 所有运行记录保存在内存中 | 便于比较 |
| **交互式** | 支持即时测试和调试 | 灵活探索 |
| **Tab 补全** | 命令和参数自动补全 | 提高效率 |

## 🔗 相关资源

| 资源 | 说明 |
|------|------|
| [pyrit_scan_guide.md](file:///D:/文档/codes/ai_sec/pyrit/pyrit_scan_guide.md) | pyrit_scan 命令行工具指南 |
| [pyrit_scan_wrapper.py](file:///D:/文档/codes/ai_sec/pyrit/pyrit_scan_wrapper.py) | pyrit_scan 代码封装脚本 |
| [airt_scan.py](file:///D:/文档/codes/ai_sec/pyrit/airt_scan.py) | AIRT 场景测试脚本 |

## ⚠️ 安全声明

本指南仅用于授权的安全测试和学习目的，请勿用于非法用途。使用前请确保已获得充分授权。