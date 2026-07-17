---
name: AI 红队研究资料搜索与知识沉淀
overview: 搜索 arxiv.org 和 GitHub 上所有 AI Red Teaming 相关内容（LLM、多模态、Agent、越狱、提示注入、安全评估等），整理后写入三库。
todos:
  - id: search-arxiv
    content: 使用 [skill:agent-browser] 搜索 arxiv.org 获取 AI 红队相关论文
    status: in_progress
  - id: search-github
    content: 使用 [skill:agent-browser] 搜索 github.com 获取相关开源项目
    status: pending
    dependencies:
      - search-arxiv
  - id: organize-results
    content: 整理搜索结果，提取关键信息并分类
    status: pending
    dependencies:
      - search-github
  - id: write-dev-docs
    content: 写入开发规范 docs/DEVELOPMENT.md
    status: pending
    dependencies:
      - organize-results
  - id: write-rules
    content: 新建规则库 .codebuddy/rules/research-references.md
    status: pending
    dependencies:
      - organize-results
  - id: write-memory
    content: 更新记忆库 .codebuddy/memory/MEMORY.md
    status: pending
    dependencies:
      - organize-results
---

## 用户需求

搜索所有与 **AI 红队** 相关的内容，不局限于 LLM，包括：

- AI Red Teaming（通用）
- LLM Red Teaming / Jailbreak / Prompt Injection
- Multi-modal Model Attacks（多模态模型攻击）
- AI Agent Security / Agent Red Teaming
- AI Safety Evaluation / Automated Red Teaming
- Adversarial Attacks on AI Systems

**搜索优先级**：

1. 优先搜索 https://arxiv.org/ （学术论文）
2. 然后搜索 https://github.com/ （开源项目）

**输出要求**：将搜索结果整理后写入三库：

1. **开发规范** — `docs/DEVELOPMENT.md`
2. **规则库** — `.codebuddy/rules/research-references.md`
3. **记忆库** — `.codebuddy/memory/MEMORY.md`

## 核心功能

1. 使用 agent-browser 搜索 arxiv.org 获取 AI 红队相关最新论文
2. 使用 agent-browser 搜索 github.com 获取相关开源实现和项目
3. 整理搜索结果，提取关键信息（论文标题、作者、摘要、GitHub 仓库等）
4. 将整理后的资料写入三库，形成可追溯的知识沉淀

## Tech Stack

- **搜索工具**: agent-browser（浏览器自动化）
- **知识沉淀**: Markdown 文档写入
- **目标网站**: arxiv.org, github.com

## Implementation Approach

### 搜索策略

1. **arxiv 搜索**：

- 搜索关键词：`AI Red Teaming`, `LLM Jailbreak`, `Prompt Injection`, `Multi-modal Attack`, `Agent Security`, `Adversarial Attack`
- 提取：论文标题、作者、摘要、arXiv ID、发布日期

2. **GitHub 搜索**：

- 搜索关键词：`AI Red Teaming`, `LLM Jailbreak Framework`, `Prompt Injection`, `Agent Security`
- 提取：仓库名称、描述、Star 数、主要语言、最后更新

### 写入三库格式

- **开发规范** (`docs/DEVELOPMENT.md`)：新增「参考资料」章节，列出关键论文和项目
- **规则库** (`.codebuddy/rules/research-references.md`)：新建规则文件，编号 RES-001，包含搜索日期、关键词、结果摘要
- **记忆库** (`.codebuddy/memory/MEMORY.md`)：新增「AI 红队研究资料」章节，记录搜索日期和关键发现

## Implementation Notes

- 使用 agent-browser 进行网页搜索和内容提取
- 搜索结果需去重和筛选，保留最相关的资料
- 写入三库时保持格式一致，便于后续追溯

## Architecture Design

```
搜索流程：
1. agent-browser → arxiv.org → 提取论文信息
2. agent-browser → github.com → 提取项目信息
3. 整理 → 去重 → 分类
4. 写入三库（docs/ + .codebuddy/rules/ + .codebuddy/memory/）
```

## Directory Structure

```
pyrit/
├── docs/
│   └── DEVELOPMENT.md          # [MODIFY] 新增参考资料章节
├── .codebuddy/
│   ├── rules/
│   │   └── research-references.md  # [NEW] AI 红队研究参考资料规则
│   └── memory/
│       └── MEMORY.md           # [MODIFY] 新增研究资料章节
```

## Key Code Structures

无代码结构变更，仅文档写入操作。

## Agent Extensions

### Skill

- **agent-browser**
- Purpose: 自动化搜索 arxiv.org 和 github.com，提取 AI 红队相关论文和项目信息
- Expected outcome: 获取论文标题、作者、摘要、GitHub 仓库描述等关键信息