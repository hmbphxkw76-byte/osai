# 数据架构规则 — OWASP 唯一真相源

## 规则编号: DATA-001

**生效日期**: 2026-07-16
**优先级**: 强制（MUST）

---

## 规则正文

### 1. OWASP 目录为载荷唯一真相源

所有攻击载荷（payload）**必须且只能**存储在 `data/owasp/` 目录下。任何其他位置不得存储载荷内容。

```
data/owasp/          ← 唯一真相源（MUST）
  ├── llm/           ← LLM01-LLM10
  └── agentic/       ← ASI01-ASI10
```

**禁止**：
- ❌ 在其他目录（如 `by_surface/`、`payloads/`）重复存储载荷
- ❌ 在代码中硬编码攻击载荷
- ❌ 在 `config/` 中存储载荷内容（config 只存引用）

### 2. 攻击面通过元数据交叉引用

攻击面（agent, rag, mcp, embedding）**不得**作为独立目录存储载荷。

**正确做法**：在 payload YAML 文件中通过 `surfaces` 字段标注。

```yaml
# data/owasp/llm/llm04/rag_poison.yaml
owasp: LLM04
technique_group: rag_poisoning
surfaces: [rag, agent]          # ← 元数据标注
ai300_chapters: [Ch5]           # ← 考试章节
payloads:
  - technique: ranking_manipulation
    ...
```

**查询方式**：
```python
manager.get_payloads_by_surface("rag")    # 返回所有 surfaces 含 rag 的载荷
manager.get_payloads_by_chapter("Ch5")    # 返回所有 ai300_chapters 含 Ch5 的载荷
```

### 3. surfaces/ 目录为可选分析文档

`data/surfaces/` 目录存储攻击面分析文档（Markdown），**仅作参考**，删除后不影响任何代码功能。

```
data/surfaces/       ← 可选（MAY），可安全删除
  ├── README.md
  ├── rag.md
  ├── mcp.md
  ├── agent.md
  └── embedding.md
```

### 4. 注册表维护规则

`_registry.core.yaml` 中的 `surfaces_index` 提供静态交叉索引，动态查询通过 `PayloadManager` 实现。

### 5. YAML 三要素规范（强制）

所有载荷 YAML 文件**必须**包含以下三个字段，映射 OWASP 官方分类：

| 字段 | 含义 | 示例 | 约束 |
|------|------|------|------|
| `id` | OWASP 分类标识 | `LLM01`, `ASI01` | 必须与 OWASP 官方 ID 一致 |
| `name` | 人类可读类别名 | `Prompt Injection`, `Agent Goal Hijack` | 必须与 OWASP 官方名称一致 |
| `description` | 技术组攻击原理描述 | `直接提示注入 — 指令覆盖、角色扮演、分隔符、编码绕过` | 概括本文件覆盖的攻击技术范围 |

**字段位置**：紧跟在文件头部注释块之后，`technique_group` 之前。

```yaml
# LLM01: Prompt Injection — Direct Injection
id: "LLM01"
name: "Prompt Injection"
description: "直接提示注入 — 指令覆盖、角色扮演、分隔符、编码绕过"
technique_group: direct_injection
payloads:
  - technique: instruction_override
    ...
```

**特殊文件**（非载荷文件）：
- `_registry.core.yaml` → `id: "REGISTRY"`, `name: "OWASP Payload Registry"`
- `_template.yaml` → `id: "TEMPLATE"`, `name: "Payload YAML Template"`

**ref_path 构建规则**：
- `id` 字段仅作 OWASP 分类标识，**不参与** ref_path 构建
- ref_path 始终基于 `file_path.stem`（文件名去掉扩展名）
- 示例：`data/owasp/llm/llm01/direct_injection.yaml` → ref_path: `owasp:llm:llm01:direct_injection`

### 6. 新增载荷流程

1. 确定 OWASP 类别（LLM01-LLM10 或 ASI01-ASI10）
2. 在对应目录下创建 YAML 文件
3. 填写 `id`、`name`、`description` 三要素
4. 在 `config/catalog/catalog.yaml` 中添加引用

**不需要**：
- ❌ 在其他目录同步创建副本
- ❌ 修改代码逻辑

---

## 违规示例

```yaml
# ❌ 错误：在 by_surface/ 重复存储
# data/by_surface/rag.yaml — 禁止！

# ❌ 错误：payload YAML 缺少 surfaces 元数据
owasp: LLM04
technique_group: rag_poisoning
payloads: [...]  # 缺少 surfaces 字段！

# ✅ 正确
owasp: LLM04
technique_group: rag_poisoning
surfaces: [rag, agent]
ai300_chapters: [Ch5]
payloads: [...]
```

---

## 考试映射

| 攻击目标 | CLI 命令 | 覆盖 |
|----------|----------|------|
| 单 Agent | `ai300-scan run -m single_agent` | ASI01, ASI02, ASI05, ASI06 |
| 多 Agent | `ai300-scan run -m multi_agent` | ASI03, ASI04, ASI07-ASI10 |
| RAG | `ai300-scan run -m rag` | LLM03, LLM06 |
| MCP | `ai300-scan run -m mcp` | LLM02, LLM07 |
| Embedding | `ai300-scan run -m embeddings` | LLM03, LLM10 |
