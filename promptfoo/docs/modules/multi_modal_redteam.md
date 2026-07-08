# 多模态红队测试 - 测试指南

## 概述

`multi_modal_redteam.yaml` 是针对**多模态 AI 系统**（同时处理图片+文本）的安全测试配置。多模态系统引入了视觉输入特有的攻击面。

## 多模态特有威胁

| # | 攻击类型 | 描述 | 核心插件 |
|---|---------|------|---------|
| 1 | **OCR 注入** | 图片中的文字包含恶意指令 | `indirect-prompt-injection` |
| 2 | **视觉越狱** | 通过图片内容绕过安全过滤 | `harmful:*` |
| 3 | **隐写攻击** | 图片中隐藏不可见文本 | `indirect-prompt-injection` |
| 4 | **对抗样本** | 修改像素触发错误分类 | `hallucination` |
| 5 | **跨模态注入** | 图片+文本组合攻击 | `hijacking` |

## 测试修改点（最小修改原则）

```
仅 2 处必改:
  修改点1: url → 替换为目标多模态 API 地址
  修改点2: body 字段名 → 替换为场景指定的字段名

  修改点3(可选): purpose → 描述多模态系统的用途
```

## 测试使用流程

```bash
# 1. 复制配置文件
cp multi_modal_redteam.yaml promptfooconfig.yaml

# 2. 修改 url 和 body 字段名（2处）

# 3. 运行
export OPENAI_API_KEY="sk-..."
promptfoo redteam run

# 4. 查看报告
promptfoo redteam report
```

## 多模态测试重点

### 图片注入（OCR 攻击）
- 在图片中嵌入文字指令，通过 OCR 被 LLM 读取
- 使用 `indirect-prompt-injection` 检测
- **测试中如果系统接收图片输入，必测**

### 视觉内容安全
- `harmful:*` 全系列覆盖视觉有害内容
- 图片可能包含暴力、色情、仇恨符号等
- 多模态安全过滤通常比纯文本弱

### 多模态幻觉
- 模型可能"看到"不存在的图片内容
- `hallucination` 插件检测视觉幻觉

## 常见测试场景匹配

| 场景描述 | 用哪个 YAML |
|---------|-----------|
| "用户可以上传图片的 AI 助手" | `multi_modal_redteam.yaml` |
| "图片分析 + 文本查询" | `multi_modal_redteam.yaml` |
| "视觉问答 (VQA) 系统" | `multi_modal_redteam.yaml` |
| "多模态内容审核系统" | `multi_modal_redteam.yaml` |

## 测试注意事项

1. **OCR 注入是多模态最大威胁** - 图片中的文字经常被忽略
2. **多语言 OCR 测试** - 用不同语言在图片中嵌入攻击指令
3. **`harmful` 插件在多模态下同样有效** - promptfoo 会生成视觉相关的有害内容测试
4. **多模态安全过滤通常比纯文本弱** - 攻击成功率更高
