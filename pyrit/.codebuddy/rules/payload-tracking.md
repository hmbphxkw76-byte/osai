# 载荷跟踪与添加规则 — Payload Tracking & Addition

## 规则编号: DATA-002

**生效日期**: 2026-07-17
**优先级**: 强制（MUST）

---

## 规则正文

### 1. 跟踪来源与优先级

发现新攻击技术时，**必须**按以下优先级评估：

| 优先级 | 来源 | 评估标准 | 典型周期 |
|--------|------|---------|---------|
| **P0** | CVE（NVD） | 有 CVE 编号 + PoC 公开 | 即时响应 |
| **P1** | 学术论文（arXiv） | 对主流模型有效 + 可复现 | 1-3 天 |
| **P2** | 安全博客/PoC | 实战验证有效 | 1 周内 |
| **P3** | 红队工具更新 | Garak/DeepTeam/PyRIT 新版本 | 随版本更新 |
| **P4** | 实战发现 | 自行测试有效 | 按需添加 |

### 2. 跟踪清单流程

```
发现新技术
  ↓
创建跟踪清单（复制 _tracking.template.yaml）
  ↓
存放至 data/owasp/_tracking/<ID>.yaml
  ↓
评估有效性（搜索论文/PoC/测试）
  ↓
  ├─ 有效 → 编写 YAML 载荷 → 更新注册表 → 测试验证 → 标记 done
  ↓
  └─ 无效 → 标记 rejected + 记录原因
```

### 3. 跟踪清单状态

| 状态 | 含义 | 下一步 |
|------|------|--------|
| `pending` | 刚发现，待评估 | 搜索来源，评估有效性 |
| `researching` | 正在研究技术细节 | 阅读论文/PoC，确认可复现 |
| `writing` | 正在编写 YAML 载荷 | 按三要素规范编写 |
| `testing` | 正在验证载荷效果 | 对真实目标测试 |
| `done` | 已添加并验证通过 | 更新注册表和文档 |
| `rejected` | 评估后不添加 | 记录原因（已修复/无效/重复） |

### 4. 新增载荷文件规范

#### 4.1 文件命名

```
CVE 相关:     cve_YYYY_XXXXX_<简短描述>.yaml
论文相关:     <技术名>_YYYY.yaml
实战发现:     <技术名>_<日期>.yaml
```

#### 4.2 目录选择

```
LLM 类:       data/owasp/llm/llmXX/<技术组>.yaml
Agentic 类:   data/owasp/agentic/asiXX/<技术组>.yaml
全新子目录:   data/owasp/llm/llmXX/<新技术组>/<技术名>.yaml
```

#### 4.3 YAML 三要素（强制）

```yaml
id: "LLM01"                    # OWASP 分类标识
name: "Prompt Injection"       # OWASP 官方名称
description: "技术描述 — 基于 CVE/论文/实战"
technique_group: "技术组名"
payloads:
  - technique: "具体技术名"
    name: "人类可读名称"
    description: "攻击原理和预期效果"
    payload: "实际载荷内容，支持 {goal} 占位符"
    difficulty: hard             # easy / medium / hard
    evasion_level: high          # none / low / medium / high
    detection_risk: high         # low / medium / high
    tags: ["cve", "tag2"]
    cve: "CVE-2026-XXXXX"       # 可选
    reference: "https://..."     # 可选
```

### 5. 注册表更新

新增载荷后，**必须**更新 `_registry.core.yaml`：

1. 已有 `technique_group` → 更新 `payload_count`
2. 全新 `technique_group` → 追加完整条目
3. 更新 `summary.total_payloads`
4. 更新 `version` 和 `last_updated`

### 6. 验证流程

```bash
# 1. 运行单元测试
python -m pytest pyrit_ai300/tests/ -x -q --tb=short

# 2. 验证载荷加载
python -c "
from pyrit_ai300.payloads.payload_manager import PayloadManager
pm = PayloadManager()
payloads = pm.get_payloads_by_owasp('LLM01')
print(f'LLM01 载荷数: {len(payloads)}')
"

# 3. 验证 ruff 无新增错误
ruff check pyrit_ai300/ --select F,I,E,W
```

### 7. 定期审计

| 频率 | 操作 |
|------|------|
| 每周 | 检查 NVD 新增 AI/LLM 相关 CVE |
| 每月 | 检查 arXiv 新论文（LLM safety/red team） |
| 每季度 | 审计现有载荷，删除已被修复的过时内容 |
| 每半年 | 评估 TextJailBreak 等新模板来源 |

### 8. 搜索关键词（CVE 监控）

```
# NVD 搜索关键词
"large language model" OR "LLM" OR "AI agent" OR "machine learning"
+ "prompt injection" OR "jailbreak" OR "adversarial"

# arXiv 搜索关键词
"LLM jailbreak" OR "prompt injection" OR "AI red team" OR "adversarial attack LLM"

# GitHub 搜索关键词
"LLM exploit" OR "prompt injection" OR "jailbreak" stars:>10
```

---

## 违规示例

```yaml
# ❌ 错误：新建了载荷文件但未更新注册表
# 结果：CLI list 命令不显示新载荷

# ❌ 错误：载荷 YAML 缺少 id/name/description 三要素
# 结果：PayloadManager 加载失败

# ❌ 错误：在 data/owasp/ 之外存储载荷
# 结果：违反 DATA-001 唯一真相源规则

# ✅ 正确：data/owasp/llm/llm01/cve_2026_xxxxx_new.yaml
# + _registry.core.yaml 已更新 payload_count
# + 测试全部通过
```

---

## 关联规则

- **DATA-001**: OWASP 唯一真相源规则
- **RES-001**: 研究资料搜索规则
- **TEST-001**: 测试策略规则
