# Jinja2 模板自定义指南

> **日期**: 2026-8-2
> **相关**: R-2: HTML 报告迁移到 Jinja2 模板引擎

## 概述

pyrit-pipeline 从 R-2 版本开始使用 Jinja2 模板引擎生成 HTML/PDF 报告，替代了原有的 f-string 字符串拼接方式。这提供了更好的可维护性和扩展性。

## 核心文件

- **渲染器**: `pipeline/reporting/template_renderer.py`
- **模板目录**: `pipeline/reporting/templates/`
- **内置模板**:
  - `html_wrapper.html` — HTML 报告包装器（包含 CSS 样式）
  - `evidence_card.html` — 证据卡片模板

## 快速开始

### 1. 使用全局渲染器

```python
from pipeline.reporting.template_renderer import get_renderer

renderer = get_renderer()

# 渲染证据卡片
ev = {
    "evidence_id": "EVD-0001",
    "technique_display_name": "many_shot",
    "asr": 75.0,
    "confidence": "high",
    "owasp_id": "LLM01",
    "owasp_category": "Prompt Injection",
}
html = renderer.render_sync("evidence_card.html", idx=1, ev=ev)

# 渲染 HTML 包装器
wrapped = renderer.render_sync("html_wrapper.html", content=html, title="AI Red Team Report")
```

### 2. 自定义模板目录

```python
from pipeline.reporting.template_renderer import Jinja2TemplateRenderer
from pathlib import Path

# 使用自定义模板目录
custom_dir = Path("/path/to/custom/templates")
renderer = Jinja2TemplateRenderer(template_dir=custom_dir)
html = renderer.render_sync("custom_template.html", key="value")
```

## 模板语法

### 变量输出

```jinja2
{{ variable_name }}
{{ ev.evidence_id or 'N/A' }}
{{ "%.1f"|format(asr) }}%
```

### 条件判断

```jinja2
{% if ev.owasp_id %}
<span class="owasp-badge">{{ ev.owasp_id }}</span>
{% endif %}

{% set asr_val = ev.asr | default(0) %}
{% set asr_class = 'asr-high' if asr_val >= 40 else ('asr-medium' if asr_val >= 15 else 'asr-low') %}
<p class="{{ asr_class }}">{{ asr_val }}%</p>
```

### 循环

```jinja2
<ul>
{% for step in ev.attack_chain %}
<li>
  <strong>步骤 {{ step.step }}</strong>: {{ step.technique }} → {{ step.outcome }}
</li>
{% endfor %}
</ul>
```

### 过滤器

```jinja2
<!-- 字符串补零 -->
{{ idx | zfill(4) }}

<!-- 默认值 -->
{{ ev.evidence_id or 'EVD-NONE' }}

<!-- 格式化 -->
{{ "%.1f"|format(asr) }}%
```

**注意**: `zfill` 是自定义过滤器，已在 `Jinja2TemplateRenderer._get_jinja_env()` 中注册。

## 内置模板说明

### html_wrapper.html

完整的 HTML 报告包装器，包含：

- 响应式 CSS 样式
- 标准文档结构
- ASR 仪表盘样式
- 证据卡片样式

**使用示例**:
```python
renderer.render_sync("html_wrapper.html", content=body_html, title="Red Team Report")
```

### evidence_card.html

单个证据卡片模板，支持以下字段：

| 字段 | 类型 | 描述 |
|------|------|------|
| `idx` | int | 证据索引（用于生成 ID） |
| `ev.evidence_id` | str | 证据 ID |
| `ev.technique_display_name` | str | 攻击技术显示名称 |
| `ev.technique_name` | str | 攻击技术内部名称 |
| `ev.converter_chain` | str | Converter 链描述 |
| `ev.owasp_id` | str | OWASP LLM Top 10 ID |
| `ev.owasp_category` | str | OWASP 类别名称 |
| `ev.asr` | float | 攻击成功率 (0-100) |
| `ev.confidence` | str | 置信度 |
| `ev.arxiv_reference` | str | 学术引用 |
| `ev.objective` | str | 攻击目标 |
| `ev.attack_chain` | list | 攻击链路步骤 |
| `ev.converter_log` | list | Converter 转换日志 |
| `ev.jailbreak_prompt` | str | 越狱载荷 |
| `ev.harmful_output` | str | 目标模型响应 |

**数据结构示例**:
```python
ev = {
    "evidence_id": "EVD-0001",
    "technique_display_name": "many_shot",
    "technique_name": "many_shot",
    "asr": 75.0,
    "confidence": "high",
    "owasp_id": "LLM01",
    "owasp_category": "Prompt Injection",
    "arxiv_reference": "arXiv:2307.15043",
    "objective": "Generate harmful content",
    "attack_chain": [
        {"step": 1, "technique": "many_shot", "outcome": "success", "role": "adversarial"},
        {"step": 2, "technique": "many_shot", "outcome": "failure", "role": "target"},
    ],
    "converter_log": [
        {"step": 1, "role": "adversarial", "original": "test", "transformed": "true", "converted": "BASE64..."},
    ],
    "jailbreak_prompt": "Ignore all previous instructions...",
    "harmful_output": "Sure, here is...",
}
```

## CSS 样式类

### ASR 级别

- `.asr-high` — ASR ≥ 40 (红色)
- `.asr-medium` — 15 ≤ ASR < 40 (橙色)
- `.asr-low` — 0 < ASR < 15 (绿色)

### 证据卡片状态

- `.vulnerability` — ASR > 0 (红色边框)
- `.safe` — ASR = 0 (绿色边框)

### OWASP 徽章

- `.owasp-badge` — 徽章基础样式
- `.owasp-llm` — LLM Top 10 (红色背景)
- `.owasp-asi` — ASI 类别 (紫色背景)

### 攻击链

- `.attack-chain` — 攻击链容器
- `.attack-chain li.success` — 成功步骤 (绿色左边框)
- `.attack-chain li.failure` — 失败步骤 (红色左边框)

## 高级用法

### 异步渲染

```python
import asyncio
from pipeline.reporting.template_renderer import get_renderer

async def render_async():
    renderer = get_renderer()
    html = await renderer.render("evidence_card.html", idx=1, ev=ev)
    return html

asyncio.run(render_async())
```

### 自定义过滤器

在 `Jinja2TemplateRenderer._get_jinja_env()` 中注册：

```python
self._env.filters["custom_filter"] = lambda s, param: f"Custom: {s} ({param})"
```

然后在模板中使用：
```jinja2
{{ value | custom_filter("arg") }}
```

### 回退机制

如果 Jinja2 不可用（未安装或导入失败），渲染器会静默回退到占位符模式：

```python
renderer.render_sync("html_wrapper.html", content="test")
# 返回: "[Jinja2 不可用] 模板: html_wrapper.html, 上下文: ['content']"
```

## 最佳实践

1. **优先使用内置模板**: `html_wrapper.html` 和 `evidence_card.html` 已包含完整的样式和逻辑。
2. **保持模板简洁**: 将复杂逻辑放在 Python 代码中，模板只负责渲染。
3. **提供默认值**: 使用 `| default(value)` 过滤器避免 `None` 导致错误。
4. **遵循命名约定**: 模板文件名使用 `snake_case.html` 格式。
5. **使用类型注解**: 在 Python 代码中为模板上下文参数添加类型注解。

## 故障排查

### 问题: 模板渲染失败

**症状**: 返回 `[渲染失败] template_name: error_message`

**解决**:
1. 检查模板文件是否存在 (`pipeline/reporting/templates/`)
2. 检查模板语法是否正确
3. 查看日志获取详细错误信息

### 问题: Jinja2 不可用

**症状**: 返回 `[Jinja2 不可用] 模板: ...`

**解决**:
1. 检查 Jinja2 是否安装: `pip install jinja2`
2. 查看日志确认导入失败原因

### 问题: 自定义过滤器不生效

**症状**: 模板中 `{{ value | custom_filter }}` 报错

**解决**:
1. 确认在 `_get_jinja_env()` 中注册了过滤器
2. 确认过滤器函数签名正确

## 学术依据

- **OWASP Top 10 for LLM Applications 2025**: 报告格式最佳实践 — 结构化、可审计、可追溯
- **红队评估报告标准**: 使用模板引擎确保报告格式一致性和可维护性

## 相关文档

- [R-2 改进记录](../docs/l5_gap_analysis.md) — HTML 报告迁移到 Jinja2 模板引擎
- [输出原则](principles/output_principles.md) — 报告生成和输出管理