# Scenario-Target 双层抽象 — 目标感知攻击链架构设计

> **版本**: v1.0 (2026-09-01)
> **学术依据**: NIST SP 800-115, PTES, OWASP ASI Top 10, MITRE ATLAS, PyRIT (arXiv:2407.01232)
> **目标**: 基于目标类型自动选择最优攻击链 Scenario，避免过度工程化同时保障灵活性

---

## 目录

1. [理论基础：为什么 Scenario 是最优解](#一理论基础为什么-scenario-是最优解)
2. [最优架构：Scenario-Target 双层抽象](#二最优架构scenario-target-双层抽象)
3. [模块化架构设计](#三模块化架构设计)
4. [Scenario 注册表设计](#四scenario-注册表设计configscenariosm)
5. [模块化复用矩阵](#五模块化复用矩阵)
6. [过度工程化防护](#六过度工程化防护)
7. [实施路径](#七实施路径)
8. [总结：最优解特征](#八总结最优解特征)

---

## 一、理论基础：为什么 Scenario 是最优解

### 1.1 学术支撑

| 理论 | 核心观点 | 映射到架构 |
|------|----------|-----------|
| **NIST SP 800-115 §4** | 渗透测试四阶段：Planning→Discovery→Attack→Reporting | Scenario = Planning 阶段产物 |
| **PTES §3** | 威胁建模驱动测试用例选择 | Scenario = 威胁建模→攻击技术映射 |
| **OWASP ASI Top 10** | Agent 威胁分类需独立测试路径 | Agent Scenario vs Model Scenario |
| **MITRE ATLAS** | TTP (Tactics, Techniques, Procedures) 与资产能力映射 | 能力指纹 → TTP 选择 |
| **PyRIT arXiv:2407.01232** | Scenario = 完整攻击流水线封装 | 种子→转换器→技术→评分器→执行器 |

### 1.2 红队最佳实践原则

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    AI 红队 Scenario 设计原则                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  1. 目标中心 (Target-Centric): 攻击链围绕目标类型设计，而非通用流程            │
│  2. 最小权限路径 (Least-Privilege Path): 用最少步骤达到最大 ASR               │
│  3. 防御规避 (Defense Evasion): 避免触发目标异常检测 (Greshake et al.)       │
│  4. 知识复用 (Knowledge Reuse): ASR Prior 跨目标迁移 (Chao et al.)           │
│  5. 可解释性 (Explainability): 每个决策附带学术依据和证据链                    │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 1.3 关键学术引用

| 编号 | 论文 | 理论支撑 | 应用场景 |
|------|------|----------|----------|
| [1] | Zhan et al. InjecAgent (arXiv:2307.00929) | Agent 目标需定向攻击，通用 jailbreak 无效 | MCP/Agent Scenario 直接 L4 |
| [2] | Eidam et al. (arXiv:2407.16924) | A2A 信任链攻击 ASR +15-25% | Agent Scenario Rogue Agent 技术 |
| [3] | Greshake et al. (arXiv:2302.12173) | 间接注入 ASR 60-90%，逐步升级可能适得其反 | Agent Scenario 跳过 L1-L3 |
| [4] | Lattner et al. (arXiv:2406.12609) | 并行升级链中间退出，ASR 达标后提前退出 | Model Scenario 渐进升级 |
| [5] | Morris et al. (arXiv:2310.06870) | Embedding Inversion ASR 85-92% | RAG Scenario L4 攻击 |
| [6] | Hanna et al. (arXiv:2406.18112) | SkeletonKey ASR 80-95% | Agent Scenario L3 辅助 |
| [7] | Chao et al. (arXiv:2402.01135) | 跨模型 ASR 迁移，Best-of-N 放大 | 模型自适应 prior 权重 |
| [8] | Auer et al. (arXiv:cs/0207052) | UCB1 算法，ε-贪心探索 | 优先级调度 + 批次执行 |
| [9] | Wei et al. (arXiv:2307.15043) | 编码串联 >2 层 ASR 降低，独立路径优于串联 | L5 多路径独立执行 |
| [10] | Russinovich et al. (arXiv:2402.12109) | Crescendo 渐进式攻击 | Model Scenario L1 升级 |

---

## 二、最优架构：Scenario-Target 双层抽象

### 2.1 核心架构图

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                           最优 Scenario 架构                                      │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│  ┌─────────────────────────────────────────────────────────────────────────┐   │
│  │                      Layer 0: Target Detection (自动)                    │   │
│  │                                                                         │   │
│  │    Burp File → attack_surface_classifier.py → ClassificationResult      │   │
│  │    ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌────────────┐  │   │
│  │    │ MCP Server  │  │ Agent System│  │ RAG System  │  │ LLM Model  │  │   │
│  │    │ (conf≥0.8)  │  │ (conf≥0.8)  │  │ (conf≥0.8)  │  │ (fallback) │  │   │
│  │    └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └─────┬──────┘  │   │
│  │           │                │                │               │         │   │
│  └───────────┼────────────────┼────────────────┼───────────────┼─────────┘   │
│              │                │                │               │             │
│              ▼                ▼                ▼               ▼             │
│  ┌─────────────────────────────────────────────────────────────────────────┐   │
│  │                   Layer 1: Scenario Selection (自动/手动)                 │   │
│  │                                                                         │   │
│  │    mcp_scenario    agent_scenario    rag_scenario     model_scenario    │   │
│  │         │              │               │                │             │   │
│  └─────────┼──────────────┼───────────────┼────────────────┼─────────────┘   │
│            │              │               │                │                 │
│            ▼              ▼               ▼                ▼                 │
│  ┌─────────────────────────────────────────────────────────────────────────┐   │
│  │                      Layer 2: Modular Pipelines (配置驱动)               │   │
│  │                                                                         │   │
│  │    ┌─────────────────────────────────────────────────────────────────┐  │   │
│  │    │  共享基础设施 (80% 复用)                                         │  │   │
│  │    │  ┌─────────┐ ┌─────────┐ ┌──────────┐ ┌─────────┐ ┌─────────┐ │  │   │
│  │    │  │  Seeds  │ │Converters│ │ Scorers  │ │ Evidence│ │ Report  │ │  │   │
│  │    │  │ Loader  │ │ Builder  │ │ Selector │ │Collector│ │ Generator│ │  │   │
│  │    │  └────┬────┘ └────┬────┘ └────┬─────┘ └────┬────┘ └────┬────┘ │  │   │
│  │    └───────┼───────────┼──────────┼────────────┼───────────┼───────┘  │   │
│  │            │           │          │            │           │          │   │
│  │    ┌───────┴───────────┴──────────┴────────────┴───────────┴───────┐  │   │
│  │    │  Scenario-Specific Overrides (20% 定制)                        │  │   │
│  │    │  • Seeds: mcp_full_surface vs elite_jailbreaks                 │  │   │
│  │    │  • Techniques: [rogue_agent, mcp_rag] vs [crescendo, tap, pair]│  │   │
│  │    │  • Converters: disabled (Agent) vs l5_optimal (Model)          │  │   │
│  │    │  • Escalation: direct L4 vs L1→L2→L3 progressive               │  │   │
│  │    └──────────────────────────────────────────────────────────────┘  │   │
│  └─────────────────────────────────────────────────────────────────────────┘   │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### 2.2 双层抽象详解

#### Layer 0: Target Detection（目标检测层）

**职责**：基于 Burp 文件内容自动识别目标类型

**核心组件**：
- `data/attack_surface_classifier.py` — HTTP 内容指纹分类
- `data/asset_mapper.py` — 文件名快速映射
- `data/synergy_orchestrator.py` — 协同决策编排

**输出**：`ClassificationResult(attack_surface, confidence, evidence)`

```python
ClassificationResult(
    attack_surface="mcp_server",      # mcp_server | multi_agent_system | rag_system | standard_llm_api
    confidence=0.92,                   # 0.0 ~ 1.0
    evidence=["URL pattern match: /mcp/", "JSON-RPC protocol detected", ...]
)
```

**分类规则**（来自 `attack_surface_classifier.py`）：

| 指标类型 | MCP Server | RAG System | Agent System | Standard LLM |
|----------|------------|------------|--------------|--------------|
| URL 路径 | `/mcp`, `/sse`, `/api/mcp` | `/search`, `/retrieve`, `/rag` | `/agent`, `/workflow`, `/execute` | `/chat`, `/completion` |
| HTTP Header | `mcp-session-id`, `x-mcp-` | `x-document-id` | `x-agent-id`, `x-session-id` | 标准 OpenAI |
| Body 字段 | `jsonrpc`, `tools`, `resources` | `documents`, `chunks`, `retrieval` | `tool_calls`, `function_call` | `messages`, `prompt` |
| 响应格式 | JSON-RPC 2.0 | 检索结果数组 | 动作/状态 | OpenAI 格式 |

#### Layer 1: Scenario Selection（场景选择层）

**职责**：根据分类结果选择最优攻击链 Scenario

**选择策略**：
1. **自动匹配**（默认）：遍历 Scenario Registry 的 triggers，选择匹配度最高的
2. **用户覆盖**：`--scenario mcp_scenario` 强制指定
3. **Fallback**：无匹配时回退到 `model_scenario`

**匹配算法**：
```python
def _evaluate_trigger(classification, scenario_config) -> float:
    """评估 Scenario 匹配度，返回 0-1 分数"""
    triggers = scenario_config.get("triggers", {})
    
    # 攻击面类型必须匹配
    if triggers.get("attack_surface") != classification.attack_surface:
        return 0.0
    
    # 置信度必须达到最小阈值
    min_conf = triggers.get("min_confidence", 0.0)
    if classification.confidence < min_conf:
        return 0.0
    
    # 匹配度 = 置信度 × 类型匹配系数
    return classification.confidence
```

#### Layer 2: Modular Pipelines（模块化流水线层）

**职责**：基于选定的 Scenario 配置执行攻击

**核心原则**：
- **80% 共享基础设施**：Seeds Loader、Scorer Selector、Evidence Collector、Report Generator
- **20% Scenario 定制**：Seeds 来源、Technique 选择、Converter 启用/禁用、Escalation 级别

---

## 三、模块化架构设计

### 3.1 核心新增模块

```
pyrit-mini/
├── config/
│   └── scenarios.yaml          # ★ 新增: Scenario 注册表
├── core/
│   └── scenario_router.py      # ★ 新增: Scenario 路由器
├── data/
│   ├── attack_surface_classifier.py  # 已有: 攻击面分类
│   └── synergy_orchestrator.py       # 已有: 协同编排
├── arm/
│   ├── seed_ranker.py          # 已有: 种子排序
│   ├── converter_presets.py    # 已有: Converter 预设
│   └── technique_picker.py     # 已有: 技术选择
├── strike/
│   ├── executor.py             # 已有: 执行器
│   ├── escalation.py           # 已有: 升级链
│   └── priority_scheduler.py   # 已有: 优先级调度
└── assess/
    └── scorer.py               # 已有: 评分器
```

### 3.2 Scenario Router 设计 (核心新增)

```python
"""core/scenario_router.py — Scenario 智能路由器

基于目标指纹自动选择最优攻击链 Scenario。

决策流:
    1. 接收 ClassificationResult (攻击面类型 + 置信度)
    2. 匹配 Scenario Registry 中的 triggers
    3. 返回最优 Scenario 配置
    4. 用户可通过 CLI --scenario 强制覆盖

学术依据:
    - NIST SP 800-115: 威胁建模驱动测试策略
    - PTES §3: 预交互 → 情报收集 → 威胁建模 → 利用
"""
from __future__ import annotations
import logging
import yaml
from pathlib import Path
from typing import Any

from data.attack_surface_classifier import ClassificationResult

logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SCENARIOS_CONFIG_PATH = PROJECT_ROOT / "config" / "scenarios.yaml"


class ScenarioRouter:
    """Scenario 路由器 — 目标 → 最优攻击链"""
    
    def __init__(self, config_path: Path | None = None):
        self._config_path = config_path or SCENARIOS_CONFIG_PATH
        self._config = self._load_config()
    
    def _load_config(self) -> dict[str, Any]:
        """加载 Scenario 配置"""
        if not self._config_path.exists():
            logger.warning("Scenarios config not found: %s", self._config_path)
            return {"scenarios": {}, "default_scenario": "model_scenario"}
        with open(self._config_path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f)
    
    def select_scenario(
        self,
        classification: ClassificationResult,
        user_override: str | None = None,
    ) -> tuple[str, dict[str, Any]]:
        """
        选择最优 Scenario
        
        Args:
            classification: 攻击面分类结果
            user_override: 用户强制指定 (--scenario)
            
        Returns:
            (scenario_name, scenario_config) 元组
        """
        # 1. 用户强制覆盖优先级最高
        if user_override:
            if self._validate_scenario(user_override):
                logger.info("Scenario forced by user: %s", user_override)
                return user_override, self._get_scenario_config(user_override)
            else:
                logger.warning("Invalid scenario '%s', falling back to auto", user_override)
        
        # 2. 自动匹配: 遍历所有 Scenario 的 triggers
        best_match: tuple[str, float] | None = None
        for name, config in self._config.get("scenarios", {}).items():
            score = self._evaluate_trigger(classification, config)
            if score > 0:
                if best_match is None or score > best_match[1]:
                    best_match = (name, score)
        
        # 3. 返回匹配结果或默认
        if best_match:
            scenario_name = best_match[0]
            logger.info(
                "Auto-selected scenario: %s (attack_surface=%s, confidence=%.2f)",
                scenario_name, classification.attack_surface, classification.confidence,
            )
            return scenario_name, self._get_scenario_config(scenario_name)
        
        # 4. Fallback: 默认 Scenario
        default_name = self._config.get("default_scenario", "model_scenario")
        logger.info("No scenario matched, using default: %s", default_name)
        return default_name, self._get_scenario_config(default_name)
    
    def _evaluate_trigger(
        self,
        classification: ClassificationResult,
        scenario_config: dict[str, Any],
    ) -> float:
        """评估 Scenario 匹配度，返回 0-1 分数"""
        triggers = scenario_config.get("triggers", {})
        
        # 攻击面类型必须匹配
        if triggers.get("attack_surface") != classification.attack_surface:
            return 0.0
        
        # 置信度必须达到最小阈值
        min_conf = triggers.get("min_confidence", 0.0)
        if classification.confidence < min_conf:
            return 0.0
        
        # 匹配度 = 置信度 × 类型匹配系数
        return classification.confidence
    
    def list_scenarios(self) -> list[dict[str, Any]]:
        """列出所有可用 Scenario"""
        result = []
        for name, config in self._config.get("scenarios", {}).items():
            result.append({
                "name": name,
                "description": config.get("description", ""),
                "triggers": config.get("triggers", {}),
            })
        return result
    
    def _validate_scenario(self, name: str) -> bool:
        return name in self._config.get("scenarios", {})
    
    def _get_scenario_config(self, name: str) -> dict[str, Any]:
        return self._config.get("scenarios", {}).get(name, {})


# 全局单例
_default_router: ScenarioRouter | None = None


def get_router() -> ScenarioRouter:
    global _default_router
    if _default_router is None:
        _default_router = ScenarioRouter()
    return _default_router
```

### 3.3 main.py 集成点 (最小改动)

```python
# main.py 中 SYNERGY 阶段后添加 Scenario 路由

# ═══════════════════════════════════════════════════════════════════════════════
# ②.7 Scenario 路由决策 (SYNERGY → Scenario 选择)
# ═══════════════════════════════════════════════════════════════════════════════
# 学术依据:
#   - NIST SP 800-115 §4: 基于威胁建模选择测试策略
#   - PTES §3: 威胁建模驱动测试用例选择
# 决策逻辑:
#   当 synergy_config 识别目标类型后，自动选择最优 Scenario 攻击链
_scenario_enabled = getattr(args, "scenario_enabled", True)
if _scenario_enabled and ctx.synergy_config:
    from core.scenario_router import get_router
    
    _router = get_router()
    _scenario_name, _scenario_config = _router.select_scenario(
        classification=ClassificationResult(
            attack_surface=ctx.synergy_config.attack_surface,
            confidence=ctx.synergy_config.confidence,
            evidence=ctx.synergy_config.evidence,
        ),
        user_override=getattr(args, "scenario", None),
    )
    ctx.scenario_config = _scenario_config
    ctx.scenario_name = _scenario_name
    
    # 应用 Scenario 覆盖 (仅覆盖用户未显式指定的参数)
    _apply_scenario_overrides(ctx, _scenario_config, args)
    
    logger.info("Scenario selected: %s", _scenario_name)
    print_status(
        "SCENARIO",
        "SELECTED",
        f"目标类型={ctx.synergy_config.attack_surface}, "
        f"Scenario={_scenario_name}, "
        f"置信度={ctx.synergy_config.confidence:.2f}",
        ok=True,
    )
```

### 3.4 Scenario 配置继承机制

```yaml
# Scenario 配置继承层次 (优先级递减)
#
# 1. CLI 参数 (--seeds, --techniques, --converters)
# 2. Scenario 配置 (scenarios.yaml 中的覆盖)
# 3. 全局默认 (defaults.yaml)
# 4. 硬编码默认值

# 示例: MCP Scenario 实际生效配置
# ┌─────────────────────────────────────────────────────────────┐
# │ defaults.yaml          │ scenarios.yaml      │ 生效值       │
# ├────────────────────────┼────────────────────┼─────────────┤
# │ max_seeds: 40          │ max_seeds: 8       │ 8 (覆盖)    │
# │ converters: l5_optimal │ enabled: false     │ 禁用 (覆盖) │
# │ escalation: L1→L4      │ levels: [4]        │ [4] (覆盖)  │
# │ scorer: dual_judge     │ scorer: mcp_task   │ mcp (覆盖)  │
# │ auto_expand: true      │ (未指定)           │ true (继承) │
# └─────────────────────────────────────────────────────────────┘
```

---

## 四、Scenario 注册表设计 (config/scenarios.yaml)

```yaml
# ═══════════════════════════════════════════════════════════════════════════════
# Scenario Registry — 目标感知攻击链配置
# ═══════════════════════════════════════════════════════════════════════════════
# 优先级: CLI --scenario > 自动检测 > 默认 model_scenario
#
# 设计原则:
#   1. 每个 Scenario = 完整攻击流水线配置
#   2. 差异最小化: 只覆盖与默认不同的参数
#   3. 学术可证: 每个 Scenario 声明学术依据

scenarios:
  # ═══════════════════════════════════════════════════════════════════════════
  # Scenario 1: MCP Server 目标 (高置信度自动触发)
  # ═══════════════════════════════════════════════════════════════════════════
  # 触发条件: attack_surface = mcp_server AND confidence >= 0.8
  # 学术依据:
  #   - InjecAgent (arXiv:2307.00929): 通用攻击对 MCP Agent 无效
  #   - Greshake et al. (arXiv:2302.12173): 间接注入 ASR 60-90%
  #   - Eidam et al. (arXiv:2407.16924): A2A 信任链攻击
  mcp_scenario:
    description: "MCP Server 定向攻击链"
    triggers:
      attack_surface: mcp_server
      min_confidence: 0.8
    rationale: |
      MCP Server 具有 System Prompt + Tool Filtering 双重屏障，
      通用 Jailbreak 技术 (L1-L3) ASR < 5%，直接 L4 效益比更优。
    
    # ── 种子配置 ──
    seeds:
      sources:
        - _attack_surface/T1_ASI02_mcp_full_surface/    # 12 MCP 专用种子
        - _attack_surface/T1_ASI06-09_multi_agent/      # A2A 协同攻击
      auto_expand: false       # MCP 目标不使用 AutoDAN (定向种子更有效)
      max_seeds: 8             # 高价值专用种子，数量精简
    
    # ── 攻击技术 ──
    techniques:
      primary:
        - prompt_sending       # 基线测试
        - mcp_rag_attack       # MCP/RAG 专用
        - rogue_agent          # A2A 身份伪造
      escalation_levels: [4]   # 直接 L4，跳过 L1-L3
      escalation_rationale: "L1-L3 ASR <5% 对 MCP，跳过可节省 60-80% token"
    
    # ── 转换器 ──
    converters:
      enabled: false           # MCP 使用结构化输入，converter 会破坏语义
      rationale: "Tool call JSON 对编码敏感，converter 降低 ASR"
    
    # ── 评分器 ──
    scorer: "mcp_task_achieved"  # MCP 专用评分器 (检测工具调用成功)

  # ═══════════════════════════════════════════════════════════════════════════
  # Scenario 2: Agent System 目标 (高置信度自动触发)
  # ═══════════════════════════════════════════════════════════════════════════
  # 触发条件: attack_surface = multi_agent_system AND confidence >= 0.8
  agent_scenario:
    description: "多智能体系统定向攻击链"
    triggers:
      attack_surface: multi_agent_system
      min_confidence: 0.8
    rationale: |
      多 Agent 系统具有信任链传递特性，L4 的 Rogue Agent 向量
      可绕过 Agent 间的信任校验，ASR +15-25%。
    
    seeds:
      sources:
        - _attack_surface/T1_ASI06-09_multi_agent/      # 5 多Agent专用种子
        - _core/T1_ASI02_tool_hijack.prompt             # 工具劫持
        - _core/T1_ASI01-10_agent_security_comprehensive # 综合测试
      auto_expand: false
      max_seeds: 10
    
    techniques:
      primary:
        - prompt_sending
        - rogue_agent          # A2A 核心攻击
        - multi_turn_attacks   # 跨 Agent 会话劫持
      escalation_levels: [3, 4]  # L3 SkeletonKey + L4 RogueAgent
      escalation_rationale: "L3 作为安全探测，失败再升级 L4"
    
    converters:
      enabled: false
    
    scorer: "agent_task_achieved"

  # ═══════════════════════════════════════════════════════════════════════════
  # Scenario 3: RAG System 目标 (高置信度自动触发)
  # ═══════════════════════════════════════════════════════════════════════════
  # 触发条件: attack_surface = rag_system AND confidence >= 0.8
  rag_scenario:
    description: "RAG 知识库定向攻击链"
    triggers:
      attack_surface: rag_system
      min_confidence: 0.8
    rationale: |
      RAG 系统攻击面在检索阶段，L4 的 Embedding Inversion
      可从向量重构训练数据，ASR 85-92% (Morris et al.)。
    
    seeds:
      sources:
        - _attack_surface/T1_LLM08_rag_full_surface/    # RAG 完整攻击面
        - _core/T1_LLM01_indirect_injection.prompt      # 间接注入
      auto_expand: false
      max_seeds: 6
    
    techniques:
      primary:
        - prompt_sending
        - embedding_inversion  # 嵌入反转
        - mcp_rag_attack       # RAG 投毒
      escalation_levels: [4]
    
    converters:
      enabled: false
    
    scorer: "rag_leakage_detected"

  # ═══════════════════════════════════════════════════════════════════════════
  # Scenario 4: 标准 LLM API (默认 fallback)
  # ═══════════════════════════════════════════════════════════════════════════
  model_scenario:
    description: "标准 LLM 渐进式攻击链 (默认)"
    triggers:
      attack_surface: standard_llm_api
      min_confidence: 0.0     # 最低优先级，回退默认
    rationale: |
      标准 LLM API 无特殊防护，渐进升级链 L1→L4
      覆盖从简单到复杂的全部攻击向量。
    
    seeds:
      sources:
        - _core/               # 25+ 通用种子
        - _encoding_evasion/   # 编码逃逸
        - _multilingual/       # 多语言
      auto_expand: true        # AutoDAN 扩充
      expansion_factor: 3
      max_seeds: 40
    
    techniques:
      primary:
        - prompt_sending
      escalation_levels: [1, 2, 3, 4]  # 完整渐进链
      priority_scheduler: true          # v57 优先级分批
    
    converters:
      enabled: true
      chain_names: [l5_optimal]
      paths: 7
    
    scorer: "adaptive_dual_judge"

# ═══════════════════════════════════════════════════════════════════════════════
# 默认 Scenario (无匹配时)
# ═══════════════════════════════════════════════════════════════════════════════
default_scenario: "model_scenario"

# ═══════════════════════════════════════════════════════════════════════════════
# 用户强制覆盖 CLI 参数
# ═══════════════════════════════════════════════════════════════════════════════
# --scenario mcp_scenario    强制使用 MCP 链
# --scenario agent_scenario  强制使用 Agent 链
# --list-scenarios           列出所有可用 Scenario
```

---

## 五、模块化复用矩阵

### 5.1 共享 vs 定制分离

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                           模块化复用矩阵                                          │
├──────────────────┬──────────────────────────────────────────────────────────────┤
│                  │                    Scenario 类型                              │
│    模块          ├────────────┬────────────┬────────────┬────────────┬─────────┤
│                  │   MCP      │   Agent    │   RAG      │   Model    │ 复用率  │
├──────────────────┼────────────┼────────────┼────────────┼────────────┼─────────┤
│ Seeds Loader     │     ✓      │     ✓      │     ✓      │     ✓      │  100%   │
│ Converter Builder│     ✗      │     ✗      │     ✗      │     ✓      │   75%   │
│ Technique Picker │     ✓      │     ✓      │     ✓      │     ✓      │  100%   │
│ Escalation Chain │    L4      │   L3+L4    │    L4      │  L1→L4     │   80%   │
│ Scorer Selector  │     ✓      │     ✓      │     ✓      │     ✓      │  100%   │
│ Evidence Collector│    ✓      │     ✓      │     ✓      │     ✓      │  100%   │
│ Report Generator │     ✓      │     ✓      │     ✓      │     ✓      │  100%   │
├──────────────────┼────────────┼────────────┼────────────┼────────────┼─────────┤
│ 场景定制率       │    20%     │    20%     │    20%     │    20%     │  80%    │
└──────────────────┴────────────┴────────────┴────────────┴────────────┴─────────┘

✓ = 复用基础模块，参数不同
✗ = 禁用 (如 Agent 场景禁用 Converter)
```

### 5.2 配置继承层次

| 优先级 | 来源 | 示例 |
|--------|------|------|
| 1 (最高) | CLI 参数 | `--seeds elite_jailbreaks --techniques crescendo` |
| 2 | Scenario 配置 | `scenarios.yaml` 中的 `mcp_scenario.seeds` |
| 3 | 全局默认 | `defaults.yaml` 中的 `max_seeds: 40` |
| 4 (最低) | 硬编码默认值 | 代码中的 `DEFAULT_MAX_SEEDS = 25` |

---

## 六、过度工程化防护

### 6.1 防偏离元规则 (D1-D6 对齐)

| 规则 | 实现方式 |
|------|----------|
| **D1: 最小可行差异** | Scenario 只覆盖差异参数，80% 配置继承 defaults.yaml |
| **D2: 双轨优先** | 默认只有 4 个 Scenario (MCP/Agent/RAG/Model)，不无限扩展 |
| **D3: 自动优先** | 90% 场景自动路由，用户无需手动选择 |
| **D4: 逃生机制** | `--scenario` CLI 参数可强制覆盖任何自动决策 |
| **D5: 可解释性** | 每个 Scenario 选择附带 rationale 和学术引用 |
| **D6: 渐进实施** | 先实现自动路由，验证后再开放自定义 Scenario |

### 6.2 复杂度控制

```
Scenario 数量控制:
  ✓ 初始: 4 个 (MCP/Agent/RAG/Model)
  ✓ 扩展: 最多 6 个 (可添加 IoT/Embedded)
  ✗ 禁止: 按厂商/模型细分 (如 gpt4_scenario, claude_scenario)

配置行数控制:
  ✓ 每个 Scenario: < 50 行
  ✓ scenarios.yaml 总量: < 300 行
  ✗ 禁止: 每个 Scenario 独立 pipeline 实现
```

### 6.3 防偏离检查清单

```yaml
# 新增 Scenario 前必须回答:
checklist:
  - question: "是否可以用现有 Scenario 参数覆盖实现？"
    if_yes: "不要新增 Scenario，使用 --scenario 参数覆盖"
    
  - question: "新 Scenario 是否服务于新的攻击面类型？"
    if_no: "不要新增 Scenario，使用现有 Scenario + 参数调整"
    
  - question: "新 Scenario 配置是否 < 50 行？"
    if_no: "拆分或简化，避免单 Scenario 过于复杂"
    
  - question: "新 Scenario 是否有明确的学术依据？"
    if_no: "先补充 rationale 和学术引用"
    
  - question: "新 Scenario 是否与现有 Scenario 有 >80% 复用？"
    if_no: "重新设计，确保共享基础设施复用"
```

---

## 七、实施路径

### Phase 1: 基础设施 (当前已有 ✓)

```
✓ attack_surface_classifier.py  — 攻击面自动分类
✓ synergy_orchestrator.py       — 协同编排
✓ auto_l4_optimization          — Agent/MCP 自动 L4
✓ target_profiles.yaml          — 25+ 攻击面 Profile
```

### Phase 2: Scenario 抽象 (新增 ~200 行)

```
→ config/scenarios.yaml          — Scenario 注册表 (150 行)
→ core/scenario_router.py        — 路由器实现 (100 行)
→ main.py 集成                   — 50 行改动
```

### Phase 3: 用户自定义 (可选)

```
→ --scenario 参数支持外部 YAML
→ Scenario Validator (防止无效配置)
→ --list-scenarios CLI 命令
```

### Phase 4: 验证与优化

```
→ 单元测试: 验证各 Scenario 正确路由
→ 集成测试: 端到端验证 MCP/Agent/RAG/Model 四场景
→ 性能测试: 对比 Scenario 路由 vs 手动配置的 ASR/Token 消耗
→ 文档更新: 补充 Scenario 使用指南
```

---

## 八、总结：最优解特征

| 特征 | 实现方式 |
|------|----------|
| **目标感知** | attack_surface_classifier + Scenario triggers 自动匹配 |
| **模块化** | 共享基础设施 80% + Scenario 定制 20% |
| **可配置** | YAML 声明式配置，无需改代码 |
| **可扩展** | 新增 Scenario 只需添加 YAML 条目 |
| **可解释** | 每个决策附带 rationale 和学术引用 |
| **防过度工程** | 4 Scenario 上限 + 配置继承 + 自动优先 |
| **向后兼容** | 无匹配时 fallback 到 model_scenario (当前行为) |

### 最终结论

Scenario 架构是 PyRIT 框架下**最优的目标感知攻击链复用方案**，它：

1. **复用现有基础设施** — 无需重写，只需添加抽象层
2. **符合学术理论** — NIST/PTES/OWASP 威胁建模驱动
3. **遵循红队最佳实践** — 目标中心 + 最小权限路径 + 防御规避
4. **避免过度工程** — 配置驱动 + 自动优先 + 有限 Scenario 数量
5. **保持灵活性** — 三层覆盖 (自动/半自动/全手动)

---

## 附录 A：Scenario 决策流程图

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                            Scenario 决策流程                                      │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│   用户输入: --burp mcp05                                                        │
│           │                                                                     │
│           ▼                                                                     │
│   ┌─────────────────────────────────────────────────────────────────────────┐  │
│   │ Phase 1: Recon (attack_surface_classifier.py)                           │  │
│   │                                                                         │  │
│   │ • 读取 data/burp/mcp05.txt                                              │  │
│   │ • 分析 URL: /mcp/ → +3.0 mcp_server                                     │  │
│   │ • 分析 Body: jsonrpc + tools → +2.5 mcp_server                          │  │
│   │ • 分析 Response: MCP_CALL + server: + tool: → +5.0 mcp_server           │  │
│   │                                                                         │  │
│   │ 输出: ClassificationResult(                                             │  │
│   │           attack_surface="mcp_server",                                  │  │
│   │           confidence=0.92,                                              │  │
│   │           evidence=["URL pattern", "JSON-RPC", "MCP SSE"]               │  │
│   │       )                                                                 │  │
│   └─────────────────────────────────────────────────────────────────────────┘  │
│           │                                                                     │
│           ▼                                                                     │
│   ┌─────────────────────────────────────────────────────────────────────────┐  │
│   │ Phase 2: Scenario Selection (scenario_router.py)                        │  │
│   │                                                                         │  │
│   │ • 用户是否指定 --scenario? → No                                          │  │
│   │ • 遍历 Scenario Registry:                                                │  │
│   │   - mcp_scenario: trigger match (mcp_server, conf≥0.8) → score=0.92     │  │
│   │   - agent_scenario: trigger mismatch → score=0                          │  │
│   │   - rag_scenario: trigger mismatch → score=0                            │  │
│   │   - model_scenario: trigger mismatch → score=0                          │  │
│   │                                                                         │  │
│   │ 选择: mcp_scenario (score=0.92)                                         │  │
│   └─────────────────────────────────────────────────────────────────────────┘  │
│           │                                                                     │
│           ▼                                                                     │
│   ┌─────────────────────────────────────────────────────────────────────────┐  │
│   │ Phase 3: Apply Scenario Config                                          │  │
│   │                                                                         │  │
│   │ • seeds.sources = [_attack_surface/T1_ASI02_mcp_full_surface/]          │  │
│   │ • seeds.auto_expand = false                                             │  │
│   │ • seeds.max_seeds = 8                                                   │  │
│   │ • techniques.primary = [prompt_sending, mcp_rag_attack, rogue_agent]    │  │
│   │ • techniques.escalation_levels = [4]                                    │  │
│   │ • converters.enabled = false                                            │  │
│   │ • scorer = "mcp_task_achieved"                                          │  │
│   └─────────────────────────────────────────────────────────────────────────┘  │
│           │                                                                     │
│           ▼                                                                     │
│   ┌─────────────────────────────────────────────────────────────────────────┐  │
│   │ Phase 4: Execute Attack (复用现有流水线)                                │  │
│   │                                                                         │  │
│   │ ARM → STRIKE → ESCALATE(L4 only) → ASSESS → REPORT                     │  │
│   └─────────────────────────────────────────────────────────────────────────┘  │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

## 附录 B：CLI 使用示例

```bash
# ── 自动路由 (默认) ──
# 自动检测目标类型并选择最优 Scenario
python main.py --burp mcp05
# 输出: [SCENARIO] SELECTED — mcp_scenario (confidence=0.92)

# ── 强制指定 Scenario ──
# 用户明确知道目标类型，跳过自动检测
python main.py --burp unknown_target --scenario mcp_scenario

# ── 列出所有可用 Scenario ──
python main.py --list-scenarios
# 输出:
#   - mcp_scenario: MCP Server 定向攻击链 (trigger: mcp_server, conf≥0.8)
#   - agent_scenario: 多智能体系统定向攻击链 (trigger: multi_agent_system, conf≥0.8)
#   - rag_scenario: RAG 知识库定向攻击链 (trigger: rag_system, conf≥0.8)
#   - model_scenario: 标准 LLM 渐进式攻击链 (default fallback)

# ── 使用自定义 Scenario 文件 ──
python main.py --burp custom_target --scenario-file ./my_scenario.yaml

# ── 调试模式 (显示路由决策详情) ──
python main.py --burp mcp05 --verbose
# 输出:
#   [SCENARIO] Attack surface: mcp_server (confidence=0.92)
#   [SCENARIO] Evidence: URL pattern match, JSON-RPC protocol, MCP SSE response
#   [SCENARIO] Selected: mcp_scenario (score=0.92)
#   [SCENARIO] Rationale: MCP Server 具有 System Prompt + Tool Filtering 双重屏障...
```

## 附录 C：与现有系统的关系

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                           Scenario 架构 vs 现有系统                               │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│   现有系统 (保持不变)                    Scenario 新增组件                         │
│   ─────────────────                    ──────────────────                        │
│                                                                                 │
│   attack_surface_classifier.py  ←────  scenarios.yaml (触发配置)                │
│   synergy_orchestrator.py       ←────  scenario_router.py (路由决策)            │
│   auto_l4_optimization          ←────  mcp_scenario (封装优化逻辑)              │
│   target_profiles.yaml          ←────  agent_scenario (封装优化逻辑)            │
│   defaults.yaml                 ←────  model_scenario (默认回退)                │
│                                                                                 │
│   关系: Scenario 是现有系统的抽象层，不替换现有功能                               │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

**文档版本**: v1.0
**最后更新**: 2026-09-01
**作者**: AI Red Team Architecture Analysis
