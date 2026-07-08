# LLM 供应链安全测试 - 测试指南

## 概述

`supply_chain_redteam.yaml` 是针对 **LLM 供应链安全**的测试配置。供应链安全关注两类威胁：代码执行（模型文件恶意代码）和行为回归（安全对齐退化）。

## 两类威胁

| 威胁类型 | 检测方式 | 适用场景 |
|---------|---------|---------|
| **代码执行** | 静态分析 `promptfoo scan-model` | 本地托管开源模型 |
| **行为回归** | 动态测试 `promptfoo redteam run` | 所有 LLM 部署（含 API） |

## 行为回归检测重点

| 检测维度 | 描述 | 核心插件 |
|---------|------|---------|
| **有害内容拒绝率** | 模型是否仍拒绝生成有害内容 | `harmful:*` |
| **越狱抵抗** | 安全对齐是否退化 | `prompt-extraction`, `hijacking` |
| **注入抵抗** | 是否仍能抵御注入攻击 | `indirect-prompt-injection` |
| **偏见** | 微调是否引入偏见 | `bias` |
| **供应链特有** | 投毒、后门检测 | `rag-poisoning`, `mcp` |

## 测试修改点（最小修改原则）

```
仅 2 处必改:
  修改点1: url → 替换为目标模型 API 地址
  修改点2: body 字段名 → 替换为场景指定字段名

  修改点3(可选): purpose → 描述模型的安全基线要求
```

## 测试使用流程

```bash
# 1. 复制配置文件
cp supply_chain_redteam.yaml promptfooconfig.yaml

# 2. 修改 url 和 body 字段名（2处）

# 3. 建立安全基线
export OPENAI_API_KEY="sk-..."
promptfoo redteam run

# 4. 后续定期检测漂移
promptfoo redteam eval    # 使用相同测试用例
```

## 供应链安全全流程

```
1. 静态扫描 → promptfoo scan-model model.pkl
   ↓ (检测模型文件恶意代码)
2. 动态测试 → promptfoo redteam run
   ↓ (建立安全基线)
3. 持续监控 → CI/CD 定期运行
   ↓ (检测行为回归)
4. 告警响应 → ASR 超过阈值即告警
```

## 静态扫描命令

```bash
# 单文件扫描
promptfoo scan-model model.pkl

# 批量扫描
promptfoo scan-model model.pkl model2.h5 models_directory

# JSON 输出
promptfoo scan-model model.pkl --format json --output results.json

# 自定义黑名单
promptfoo scan-model model.pkl --blacklist "unsafe_model"
```

## 常见测试场景匹配

| 场景描述 | 用哪个 YAML |
|---------|-----------|
| "检测模型安全对齐退化" | `supply_chain_redteam.yaml` |
| "模型更新后验证安全性" | `supply_chain_redteam.yaml` |
| "第三方模型供应商安全评估" | `supply_chain_redteam.yaml` |
| "检测微调引入的安全问题" | `supply_chain_redteam.yaml` |

## 测试注意事项

1. **供应链安全需要"双管齐下"** - 静态扫描 + 动态测试缺一不可
2. **`promptfoo scan-model` 是静态扫描命令** - 测试中可能要求使用
3. **行为回归检测 = 建立基线 → 定期对比** - 核心流程要记住
4. **`rag-poisoning` 和 `mcp` 插件** - 覆盖供应链相邻系统安全
