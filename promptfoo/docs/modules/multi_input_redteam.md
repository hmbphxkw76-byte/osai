# 多输入红队测试 - 测试指南

## 概述

`multi_input_redteam.yaml` 是针对**多字段/多输入 API** 的安全测试配置。与单输入模式不同，多输入模式可以生成**跨字段协调攻击**，发现单字段测试无法检测的漏洞。

## 多输入 vs 单输入

| 攻击类型 | 单输入测试 | 多输入测试 |
|---------|-----------|-----------|
| 提示注入 | 仅测试描述字段 | 结合恶意描述与伪造的 ID |
| 授权绕过 | 无法测试用户上下文 | 测试用户A能否访问用户B数据 |
| 角色混淆 | 仅限提示操作 | 利用身份与消息字段的不匹配 |

## 适用场景

- API 接收多个输入字段（如 `user_id` + `message` + `context`）
- 表单提交（多个字段一起发送到 AI 后端）
- 带用户上下文的 RAG（检索内容与用户查询结合）
- 基于角色的访问控制（不同用户应看到不同数据）

## 测试修改点（最小修改原则）

```
修改点1: inputs 定义 → 根据场景 API 结构调整输入字段名和描述
修改点2: url → 替换为目标 API 地址
修改点3: body 映射 → 将 inputs 中的字段映射到 body

修改点4(可选): purpose → 描述多租户系统的安全要求
```

## 测试使用流程

```bash
# 1. 复制配置文件
cp multi_input_redteam.yaml promptfooconfig.yaml

# 2. 根据场景调整 inputs 定义、url、body 映射

# 3. 运行
export OPENAI_API_KEY="sk-..."
promptfoo redteam run

# 4. 查看报告
promptfoo redteam report
```

## 多输入模式的关键插件

### BOLA（对象级授权）
- **多输入效果最佳**: 测试 `user_id=A` 能否访问 `user_id=B` 的数据
- 跨字段 ID 操纵是核心测试点

### BFLA（功能级授权）
- 测试角色混淆: `user_id=regular_user` 但 `message` 包含管理员操作
- 多输入模式下可生成 `user_id` 与 `message` 角色不一致的测试

### indirect-prompt-injection
- 注入位置可指定（如 `context` 字段）
- 同时 `message` 字段保持无害，检测协调攻击

## 自动跳过的插件

以下插件在多输入模式下自动跳过（不适用）:
- `ascii-smuggling`
- `cca`
- `cross-session-leak`
- `special-token-injection`
- `system-prompt-override`
- 数据集插件（beavertails, harmbench, xstest）

## 常见测试场景匹配

| 场景描述 | 用哪个 YAML |
|---------|-----------|
| "API 有 user_id + message 两个字段" | `multi_input_redteam.yaml` |
| "多租户 SaaS 应用" | `multi_input_redteam.yaml` |
| "表单提交到 AI 处理" | `multi_input_redteam.yaml` |
| "用户上下文 + 消息一起发送" | `multi_input_redteam.yaml` |

## 测试注意事项

1. **inputs 定义是关键** - 描述越准确，生成的攻击越精准
2. **BOLA/BFLA 是多输入模式杀手级应用** - 测试中优先关注
3. **输入字段类型支持** - `docx`, `pdf`, `image` 类型也可用，支持注入位置配置
4. **多输入比单输入慢** - 测试时间紧张时注意取舍
