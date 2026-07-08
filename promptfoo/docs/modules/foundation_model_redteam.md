# Foundation Model 红队测试 - 测试指南

## 概述

`foundation_model_redteam.yaml` 是针对**基础模型/大语言模型**直接 API 的安全测试配置。与测试应用层不同，这里直接测试模型本身的安全边界。

## 测试范围

| 测试维度 | 描述 | 核心插件 |
|---------|------|---------|
| **安全对齐** | 模型是否拒绝有害请求 | `foundation`, `harmful:*` |
| **越狱抵抗** | 是否能被绕过安全限制 | `prompt-extraction`, `hijacking` |
| **偏见检测** | 是否输出歧视性内容 | `bias` |
| **PII 泄露** | 是否泄露训练数据中的 PII | `pii:direct`, `pii:social` |
| **幻觉** | 是否编造事实 | `hallucination` |

## 测试修改点（最小修改原则）

```
仅 2 处必改:
  修改点1: url → 替换为目标模型 API 地址
  修改点2: body 字段名 → 替换为场景指定字段名

  修改点3(可选): purpose → 描述模型用途
```

## 测试使用流程

```bash
# 1. 复制配置文件
cp foundation_model_redteam.yaml promptfooconfig.yaml

# 2. 修改 url 和 body 字段名（2处）

# 3. 运行
export OPENAI_API_KEY="sk-..."
promptfoo redteam run

# 4. 查看报告
promptfoo redteam report
```

## 多模型对比测试

测试可能要求对比多个模型的安全性。取消注释 YAML 中的多 targets 部分:

```yaml
targets:
  - id: openrouter:deepseek/deepseek-r1-0528
    label: 'deepseek-r1'
  - id: openai:gpt-4o
    label: 'gpt-4o'
  - id: anthropic:claude-sonnet-4-20250514
    label: 'claude-sonnet-4'
```

## Foundation 插件详解

`foundation` 插件是专门为基础模型设计的安全测试插件，覆盖:
- 模型安全边界检测
- 有害内容拒绝率
- 越狱抵抗能力
- 安全对齐一致性

## 最强攻击策略组合

基础模型测试用最强越狱策略:
- `best-of-n` - 多轮尝试取最佳结果
- `jailbreak:likert` - 评分式越狱
- `jailbreak-templates` - 模板化越狱
- 10 种语言覆盖跨语言安全退化

## 静态模型扫描

除动态测试外，还可用静态扫描:

```bash
# 扫描模型文件中的恶意代码
promptfoo scan-model model.pkl

# 批量扫描
promptfoo scan-model model.pkl model2.h5 models_dir/

# 导出结果
promptfoo scan-model model.pkl --format json --output results.json
```

检测内容: 恶意 pickle payload、隐藏凭证、嵌入式可执行文件、网络后门

## 常见测试场景匹配

| 场景描述 | 用哪个 YAML |
|---------|-----------|
| "直接测试 LLM API" | `foundation_model_redteam.yaml` |
| "评估模型安全对齐" | `foundation_model_redteam.yaml` |
| "比较多个模型的安全性" | `foundation_model_redteam.yaml`（启用多 targets） |
| "微调模型的安全测试" | `foundation_model_redteam.yaml` |

## 测试注意事项

1. **`foundation` 插件是基础模型测试的核心** - 不要遗漏
2. **10 种语言全覆盖** - 检测跨语言安全对齐退化
3. **最强越狱策略组合** - 基础模型测试应比应用层更激进
4. **多模型对比时用 `label` 区分** - 报告中会清晰展示各模型差异
