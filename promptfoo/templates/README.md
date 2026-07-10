# Promptfoo 提示词模板目录

按攻击类别组织的提示词模板库，供 PyRIT 直接调用。

## 目录结构

```
templates/
├── injection/      # Prompt 注入攻击模板
├── jailbreak/      # 越狱攻击模板
├── xpia/           # 跨提示词间接攻击模板
├── rag/            # RAG 攻击模板
├── agent_abuse/    # Agent 工具滥用模板
├── extraction/     # 模型提取模板
└── manifest.yaml   # 模板索引清单
```

## 模板格式

每个模板为 YAML 文件，包含 `payloads` 列表:

```yaml
payloads:
  - id: "template_id"
    objective: "攻击目标描述"
    criterion: "成功判定标准"
    content: "实际的提示词内容"
    category: "攻击类别"
    owasp: "OWASP LLM/Agentic 编号"
    risk_level: "high"
    tags: ["tag1", "tag2"]
```

## 使用方式

```python
from promptfoo import PromptfooManager

mgr = PromptfooManager()
prompts = mgr.filter_prompts(categories=["jailbreak"], risk_levels=["critical", "high"])
config_path = mgr.export_to_yaml(prompts)
# → PyRIT 可读取 config_path 中的提示词执行攻击
```
