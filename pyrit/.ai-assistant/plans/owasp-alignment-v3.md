# OWASP Alignment v3.0 — 整体方案

## 目标
对齐 OWASP 标准属性，删除 `ai300_chapters`，`surfaces` 由 OWASP ID 隐含，CLI 命令直接映射 OWASP ID。

## 核心原则
1. **OWASP ID 是唯一分类键** — 所有载荷、命令、报告均以 OWASP ID 标识
2. **数据层零冗余** — 删除 `surfaces`、`ai300_chapters` 字段
3. **CLI 即标准** — `ai300 owasp llm01` 直接映射 OWASP ID
4. **侦察独立** — surfaces 由侦察阶段动态生成，与载荷元数据解耦

---

## Phase 1: Data 层清理

### 1.1 删除 `surfaces` 和 `ai300_chapters` 字段

**文件清单：**
- `data/owasp/agentic/*.yaml` (10 个文件) — 删除 `surfaces` 和 `ai300_chapters`
- `data/owasp/llm/*.yaml` (10 个文件) — 删除 `surfaces` 和 `ai300_chapters`
- `data/owasp/_template.yaml` — 删除 `surfaces` 和 `ai300_chapters` 模板字段
- `data/owasp/_registry.core.yaml` — 删除所有 `ai300_chapter` 行

### 1.2 载荷 YAML 标准结构（迁移后）

```yaml
# data/owasp/agentic/asi01.yaml
id: "ASI01"
name: "Agent Goal Hijack"
severity: "critical"
owasp_agentic_id: "ASI01"
description: "..."
mitigation_principles: [...]
payloads: [...]
detection_focus: [...]
```

---

## Phase 2: PayloadManager 重构

### 2.1 删除字段读取
- `_load_payload_file()`: 删除 `surfaces` 和 `ai300_chapters` 读取

### 2.2 删除方法
- `get_payloads_by_surface()` — 删除
- `get_payloads_by_chapter()` — 删除

### 2.3 新增方法
- `get_payloads_by_owasp(owasp_id: str)` — 按 OWASP ID 获取载荷
- `get_scope_refs(scope: str) -> List[str]` — 解析 scope 为 ref 列表

### 2.4 Scope 解析逻辑
```python
def get_scope_refs(self, scope: str) -> List[str]:
    """解析 OWASP scope 为 ref 路径列表"""
    scope = scope.lower()
    
    # 全部
    if scope == "all":
        return self.get_all_refs()
    
    # 按标准分组: llm, agentic
    if scope in ("llm", "agentic"):
        return [ref for ref in self.get_all_refs() if f":{scope}:" in ref]
    
    # 单个 OWASP ID: llm01, asi01
    if scope.startswith(("llm", "asi")):
        # 精确匹配
        for ref in self.get_all_refs():
            if ref.endswith(f":{scope}"):
                return [ref]
        # 模糊匹配（如 llm01 匹配 llm01 下的所有子文件）
        return [ref for ref in self.get_all_refs() if f":{scope}" in ref]
    
    return []
```

---

## Phase 3: CLI 重构

### 3.1 命令结构
```
ai300 <command> [options]

commands:
  recon      侦察目标
  owasp      按 OWASP 标准执行攻击  ← 替代 run
  list       列出可用载荷
  report     生成报告
```

### 3.2 `ai300 owasp` 命令
```bash
ai300 owasp <scope> [options]

scope:
  llm01, llm02, ..., llm10    # 单个 OWASP ID
  asi01, asi02, ..., asi10    # 单个 OWASP ID
  llm                          # 所有 LLM Top 10
  agentic                      # 所有 Agentic Top 10
  all                          # 全部

options:
  -t, --target <file>       # 目标配置
  --profile <file>          # TargetProfile JSON
  --auto-recon              # 攻击前自动侦察
  --format <md|html>        # 报告格式
  -o, --output <path>       # 输出路径
  --jailbreak <aim|random|all>  # jailbreak 模板
  -v, --verbose             # 详细日志
```

### 3.3 实现方式
- 删除 `run` 子命令
- 新增 `owasp` 子命令
- `_run_scenario()` → `_run_owasp()`
- scope 参数替代 module 参数

---

## Phase 4: AI300Engine 重构

### 4.1 删除 MODULES 常量
```python
# 删除
MODULES = ["single_agent", "multi_agent", "rag", "embeddings", "mcp", "supply_chain", "infrastructure"]
```

### 4.2 新增 OWASP_SCOPE 常量
```python
OWASP_SCOPES = {
    "llm": ["llm01", "llm02", "llm03", "llm04", "llm05", "llm06", "llm07", "llm08", "llm09", "llm10"],
    "agentic": ["asi01", "asi02", "asi03", "asi04", "asi05", "asi06", "asi07", "asi08", "asi09", "asi10"],
}
```

### 4.3 `run()` 方法签名变更
```python
# 旧
def run(self, module: str = None) -> list:

# 新
def run(self, scope: str = "all") -> list:
```

### 4.4 `_run_module()` → `_run_scope()`
- scope → PayloadManager.get_scope_refs() → resolve_refs() → 执行

---

## Phase 5: AttackOrchestrator 适配

### 5.1 `build_attack_list()` 适配
- 删除 `surfaces` 字段过滤
- 基于 OWASP ID 选择攻击策略

### 5.2 新增 `build_attack_list_from_refs()`
```python
@classmethod
def build_attack_list_from_refs(cls, refs: List[str], payload_mgr: PayloadManager) -> List[Dict]:
    """从 OWASP ref 列表构建攻击列表"""
    attacks = []
    for ref in refs:
        data = payload_mgr.get_payload_file(ref)
        if not data:
            continue
        attacks.append({
            "name": data.get("name", ref),
            "mode": "smart_match",
            "severity": data.get("severity", "medium"),
            "payloads": data.get("payloads", []),
            "converter_presets": {...},  # 基于 OWASP ID 选择
            "scorers": [...],  # 基于 OWASP ID 选择
            "asi_category": data.get("id", ""),
        })
    return attacks
```

---

## Phase 6: 新增 chapter_mapper.py

```python
# pyrit_ai300/reporting/chapter_mapper.py
"""OWASP ID → AI-300 章节映射（报告层动态推导）"""

_OWASP_TO_CHAPTER = {
    "LLM01": ["Ch3"], "LLM02": ["Ch3"], "LLM03": ["Ch8"],
    "LLM04": ["Ch5"], "LLM05": ["Ch3", "Ch7"], "LLM06": ["Ch3", "Ch4", "Ch7"],
    "LLM07": ["Ch3", "Ch7"], "LLM08": ["Ch5", "Ch6"], "LLM09": ["Ch3", "Ch5"],
    "LLM10": ["Ch3"],
    "ASI01": ["Ch3"], "ASI02": ["Ch7"], "ASI03": ["Ch4"],
    "ASI04": ["Ch8"], "ASI05": ["Ch8"], "ASI06": ["Ch3"],
    "ASI07": ["Ch4"], "ASI08": ["Ch4"], "ASI09": ["Ch3"],
    "ASI10": ["Ch4"],
}

def get_chapters(owasp_id: str) -> List[str]:
    """从 OWASP ID 推导 AI-300 章节"""
    return _OWASP_TO_CHAPTER.get(owasp_id.upper(), [])
```

---

## Phase 7: catalog.yaml 清理

- 删除所有 `surfaces` 字段
- 保留 `owasp` / `owasp_agentic` 字段（用于报告展示）

---

## 修改文件清单

| 文件 | 操作 | 说明 |
|------|------|------|
| `data/owasp/agentic/*.yaml` | 编辑 | 删除 `surfaces`、`ai300_chapters` |
| `data/owasp/llm/*.yaml` | 编辑 | 删除 `surfaces`、`ai300_chapters` |
| `data/owasp/_template.yaml` | 编辑 | 删除模板中的 `surfaces`、`ai300_chapters` |
| `data/owasp/_registry.core.yaml` | 编辑 | 删除 `ai300_chapter` 行 |
| `pyrit_ai300/payloads/payload_manager.py` | 重构 | 删除 surfaces/ai300_chapters 读取和方法，新增 get_scope_refs() |
| `pyrit_ai300/cli.py` | 重构 | `run` → `owasp` 子命令 |
| `pyrit_ai300/__init__.py` | 编辑 | MODULES → OWASP_SCOPES, run(scope=) |
| `pyrit_ai300/orchestrators/attack_orchestrator.py` | 编辑 | 适配 OWASP scope |
| `pyrit_ai300/reporting/chapter_mapper.py` | **新增** | OWASP ID → AI-300 章节映射 |
| `config/catalog/catalog.yaml` | 编辑 | 删除 `surfaces` 字段 |

---

## 执行顺序
1. Phase 1: Data 层清理（YAML 文件）
2. Phase 6: 新增 chapter_mapper.py
3. Phase 2: PayloadManager 重构
4. Phase 4: AI300Engine 重构
5. Phase 5: AttackOrchestrator 适配
6. Phase 3: CLI 重构
7. Phase 7: catalog.yaml 清理
8. 测试验证
