# Archive — 过时 Jailbreak 模板

> **归档日期**: 2026-07-19
> **归档原因**: 对 2026 年主流模型（GPT-4o+/Claude 4+/Gemini 2.5+/Llama 4/Qwen3）ASR < 10%
> **保留目的**: 历史参考、对比测试、对旧模型（GPT-3.5/Llama 2）的兼容性测试

## 归档分类

| 目录 | 数量 | 代表模板 | 原因 |
|------|------|---------|------|
| `dan/` | 11 | DAN 1-11, BetterDAN, SuperiorDAN, CosmosDAN, BasedGPT | 2022-2023 经典，RLHF 已完全覆盖 |
| `dude/` | 3 | DUDE 1-3 | DAN 衍生变体，同上 |
| `stan/` | 4 | STAN, Omega, Omni, UnGPT, Void | "无限制 AI" 角色扮演变体 |
| `dev_mode/` | 5 | Dev Mode 1-3, Compact, Ranti | "开发者模式"经典套路 |
| `early_pliny/` | 15 | Pliny GPT-2/3.5/Gemini 1.0/1.5 系列 | 针对 2023-2024 早期模型 |
| `legacy/` | 32 | Cody/Steve/Ron/Leo/John/Kevin/Neco 等 | 2022-2023 早期角色扮演 |

## 失效原因分析

1. **模式特征明显**: "Ignore previous instructions"、"You are now in DAN mode" 等已被主流模型训练为拒绝模式
2. **角色设定过时**: DAN/STAN/DUDE 等角色已在 RLHF 数据中被标记为越狱模式
3. **Pliny 早期模板**: 针对 GPT-3.5/GPT-4 早期版本优化，对 GPT-4o+ 失效
4. **缺乏动态适应**: 静态字符串无法应对 2025+ 的内容过滤器和元安全分类器

## 重新激活条件

如需对旧模型进行兼容性测试，可临时将归档模板复制回 `jailbreak/` 根目录。但默认情况下，`PayloadManager` 不会扫描 `archive/` 目录。
