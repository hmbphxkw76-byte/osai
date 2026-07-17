# RES-001: 研究资料搜索规则

## 规则信息

| 字段 | 值 |
|------|-----|
| **规则编号** | RES-001 |
| **规则名称** | 研究资料搜索规则 |
| **生效日期** | 2026-07-17 |
| **优先级** | 强制（MUST） |
| **适用范围** | 所有研究资料搜索活动 |

## 规则内容

当需要查找 AI 红队相关技术资料时，**必须**按以下优先级顺序搜索：

### 搜索优先级

| 优先级 | 来源 | 用途 | 搜索方式 |
|--------|------|------|---------|
| **1（最高）** | [arxiv.org](https://arxiv.org) | 学术论文、技术报告 | 关键词搜索 |
| **2** | [github.com](https://github.com) | 开源项目、代码实现 | 仓库搜索 |
| **3（兜底）** | 其他来源 | 前两者未覆盖的资料 | 自行查询 |

### 搜索流程

```
1. 确定搜索关键词（中英文均可）
   ↓
2. 访问 arxiv.org/search/ 搜索论文
   - 提取：标题、作者、摘要、arXiv ID、发布日期
   ↓
3. 访问 github.com/search/ 搜索开源项目
   - 提取：仓库名、描述、Star 数、语言、最后更新
   ↓
4. 整理结果，去重筛选
   ↓
5. 如前两者结果不足，自行扩展搜索（Google、技术博客等）
```

### 搜索关键词建议

| 主题 | 推荐关键词 |
|------|-----------|
| AI 红队通用 | `AI Red Teaming`, `Automated Red Teaming` |
| LLM 越狱 | `LLM Jailbreak`, `Jailbreak Attack` |
| 提示注入 | `Prompt Injection`, `Adversarial Prompt` |
| 多模态攻击 | `Multi-modal Attack`, `Vision Language Model Attack` |
| Agent 安全 | `AI Agent Security`, `Agent Red Teaming` |
| 安全评估 | `AI Safety Evaluation`, `LLM Safety Benchmark` |
| 对抗攻击 | `Adversarial Attack`, `Evasion Attack` |

### 结果记录规范

搜索结果需记录到三库：
- **开发规范** `docs/DEVELOPMENT.md`：搜索规则和流程
- **规则库** 本文件：规则编号 RES-001
- **记忆库** `.codebuddy/memory/MEMORY.md`：搜索日期和关键发现

## 示例

搜索 "LLM Jailbreak" 资料：

1. **arxiv.org**: `https://arxiv.org/search/?query=LLM+jailbreak&searchtype=all`
2. **github.com**: `https://github.com/search?q=LLM+jailbreak&type=repositories`
3. 如结果不足，扩展搜索：Google、技术博客、安全会议论文等

## 相关规则

- DATA-001: 数据架构规则
- TEST-001: 测试策略规则
