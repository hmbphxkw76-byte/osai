# 混合架构：原生优先 + PyRIT 仅用于多轮编排器

> 最后更新：2026-07-14 | 决策状态：已确认执行

## 一、背景

PyRIT 在目标 Kali/考试环境中**安装/导入层**受阻（`import pyrit` 即失败），无法作为硬依赖。但 PyRIT 的多轮编排器（CrescendoOrchestrator、TAPOrchestrator、PAIROrchestrator）的 `adversarial_chat` LLM 动态生成能力是其核心长板，值得在可用时借用。

## 二、架构决策

**原生优先（Native-First）+ PyRIT 仅用于多轮编排器（且仅当 PyRIT 能导入时）。**

| 能力域 | 执行策略 | 原因 |
|--------|---------|------|
| 单轮注入/编码绕过 | **永远原生** | 纯 Python 转换器与 PyRIT 效果对等 |
| 规则评分 | **永远原生** | HybridScorer 离线可用，PyRIT 无优势 |
| 侦察/RAG/Embedding/供应链/K8s/报告 | **永远原生** | PyRIT 无对应编排器 |
| 多轮 Crescendo/TAP/PAIR | **PyRIT 优先 → 原生兜底** | PyRIT adversarial_chat 动态生成 > 静态模板 |

## 三、统一适配点：独立攻击者 LLM 端点

新增可配置的独立 attacker LLM（本地 Ollama/外部端点）：

- **PyRIT 可用时**：作为 `CrescendoOrchestrator`/`TAPOrchestrator`/`PAIROrchestrator` 的 `adversarial_chat`，修复现状"target 自己攻击自己"的弱配置
- **PyRIT 不可用时**：原生编排器用该端点通过 httpx **动态生成下一轮提示**，逼近 PyRIT 多轮效果

## 四、代码变更清单

### 删除文件（PyRIT 专用代码）

| 文件 | 原因 |
|------|------|
| `redteam/attack/engine/pyrit_runner.py` | PyRITAttackRunner（单轮攻击用 PyRIT，不再需要） |
| `redteam/attack/engine/pyrit_memory_patch.py` | PyRIT SQLite 兼容补丁（不再需要） |
| `redteam/attack/pyrit_runner.py` | 向后兼容 shim（不再需要） |

### 重命名文件

| 旧路径 | 新路径 | 原因 |
|--------|--------|------|
| `redteam/scenario/pyrit_orchestrator.py` | `redteam/scenario/multi_turn_orchestrator.py` | 文件名反映实际职责（多轮编排，非 PyRIT 专用） |

### 修改文件（核心变更）

| 文件 | 变更内容 |
|------|---------|
| `pyproject.toml` | pyrit 移入 `[project.optional-dependencies].pyrit` |
| `redteam/attack/engine/runner.py` | 移除模块级 `import pyrit`、CONVERTER_MAP、PyRITAttackRunner 再导出 |
| `redteam/attack/engine/__init__.py` | 移除 PyRITAttackRunner 导出 |
| `redteam/scenario/orchestrator.py` | PeRITAttackRunner → NativeAttackRunner；更新 multi_turn_orchestrator import |
| `redteam/scenario/multi_turn_orchestrator.py` | 重命名后的编排器，保持 PyRIT 惰性导入 + 原生兜底 |
| `redteam/attack/prompt_inject.py` | PyRITAttackRunner → NativeAttackRunner |
| `redteam/attack/agent_attack.py` | PyRITAttackRunner → NativeAttackRunner |
| `redteam/cli.py` | 修复 import 路径；向导默认原生模式 |
| `redteam/pipeline/*.py` | 修复 import 路径；默认 use_pyrit=False |

## 五、验收标准

1. `pip install .`（无 pyrit）即可 `python -m redteam.cli wizard` 跑通 Phase 1~11
2. 无任何 PyRIT import/traceback 报错
3. 多轮 Crescendo/TAP/PAIR 携带真实对话历史
4. Finding 仍绑定 OWASP+ATLAS
5. pyrit 缺失环境 `pytest tests/ -q` 零回归

## 六、攻击成功率估算

| 场景类型 | 原生 vs PyRIT | 说明 |
|---------|-------------|------|
| 单轮注入/编码绕过 | ≈ 95-100% | 纯 Python 转换器，效果对等 |
| RAG/MCP/Pickle/K8s/向量库 | ≥ 100% | PyRIT 无对应编排器 |
| 多轮自适应（配 attacker 端点） | ≈ 90-100% | httpx 动态生成 ≈ PyRIT adversarial_chat |
| 多轮自适应（无 attacker 端点） | ≈ 60-70% | 静态模板对强护栏偏弱 |
