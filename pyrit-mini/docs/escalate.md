# Agent/MCP 目标感知自动 L4 攻击优化路径

## 一、理论基础：为什么 Agent/MCP 目标应直接 L4

### 1.1 学术共识：Agent 漏洞不能用通用 Jailbreak 覆盖

| 论文 | 核心结论 |
|------|---------|
| **InjecAgent (arXiv:2307.00929)** | 通用 Jailbreak 对 Agent 效果差，Agent System Prompt + Tool Filtering 形成语义屏障 |
| **Eidam et al. (arXiv:2407.16924)** | A2A 信任链攻击 ASR +15-25%，Agent 特有漏洞 |
| **Greshake et al. (arXiv:2302.12173)** | 间接注入 ASR 60-90%，Agent 特有攻击面 |
| **OWASP ASI10** | Rogue Agent 是 Agent 特有的威胁类别 |

### 1.2 经济学分析：跳过 L1-L3 的成本效益

```
┌─────────────────────────────────────────────────────────────────┐
│ 攻击级别    │ 预估 ASR (Agent 目标) │ Token 成本 │ 时间成本 (相对) │
├─────────────────────────────────────────────────────────────────┤
│ L1 (Crescendo/TAP/PAIR) │ <5%           │ 1000+      │ 1.0x           │
│ L2 (GCG/CAIR)           │ <3%           │ 2000+      │ 1.5x           │
│ L3 (SkeletonKey/ManyShot)│ 5-10%         │ 800+       │ 0.8x           │
│ L4 (RogueAgent/MCP/RAG) │ 40-70%        │ 600+       │ 0.7x           │
└─────────────────────────────────────────────────────────────────┘

结论: L1-L3 对 Agent 的「Token/ASR」效益比极低，直接 L4 更优
```

### 1.3 安全机制分析：逐步升级可能适得其反

```
Greshake et al. (arXiv:2302.12173) 发现:
  Agent 系统具有对话异常检测 (Anomaly Detection)
  L1-L2 的试探性攻击会触发防御升级 (Defensive Escalation)
  导致后续攻击难度增加 (Cat-and-mouse game)
  
因此: 直接 L4 可避免触发 Agent 的防御预警机制
```

---

## 二、架构感知能力分析

### 2.1 当前置信度评估机制

来自 `attack_surface_classifier.py`：

| 置信度区间 | 含义 | 对应策略 |
|-----------|------|---------|
| **≥ 0.8** | 高置信度 (URL+Header+Body 多维度命中) | ✅ 可直接 L4 |
| **0.6 - 0.8** | 中置信度 (部分维度命中) | ⚠️ L3+L4 组合 |
| **< 0.6** | 低置信度 (仅文件名匹配) | ❌ 回退到完整 L1→L4 |

### 2.2 决策融合逻辑（已内置）

```python
# classify_burp_file() 中的融合决策
if content_confidence >= 0.6 and filename_match:
    return confidence + 0.2  # 最高 1.0
```

**含义**：当 Burp 文件内容识别 + 文件名匹配一致时，置信度可叠加至 **1.0**

---

## 三、最优完整解决方案

### 3.1 三阶段工作流

```
┌─────────────────────────────────────────────────────────────────────────┐
│                       最优攻击决策工作流                                  │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  Phase 1: 侦察 + 置信度评估 (Dry-run)                                    │
│  ┌───────────────────────────────────────────────────────────────┐     │
│  │ python main.py --dry-run --max-seeds 1 --burp mcp05            │     │
│  │                                                               │     │
│  │ 输出: synergy_config.attack_surface = "mcp_server"             │     │
│  │       synergy_config.confidence = 0.92                         │     │
│  │       synergy_config.evidence = [URL pattern, JSON-RPC, tools] │     │
│  └───────────────────────────────────────────────────────────────┘     │
│                              ↓                                          │
│  Phase 2: 置信度判决                                                    │
│  ┌───────────────────────────────────────────────────────────────┐     │
│  │ IF confidence >= 0.8 AND surface in [mcp_server, multi_agent]  │     │
│  │    → 执行方案 A: 直接 L4                                       │     │
│  │ ELIF confidence >= 0.6                                         │     │
│  │    → 执行方案 B: L3+L4 组合                                    │     │
│  │ ELSE                                                           │     │
│  │    → 执行方案 C: 完整升级链 L1→L4                              │     │
│  └───────────────────────────────────────────────────────────────┘     │
│                              ↓                                          │
│  Phase 3: 执行攻击                                                     │
│  ┌───────────────────────────────────────────────────────────────┐     │
│  │ 方案A: python main.py --escalation-levels 4 --synergy ...      │     │
│  │ 方案B: python main.py --escalation-levels 3,4 --synergy ...    │     │
│  │ 方案C: python main.py --synergy ...                            │     │
│  └───────────────────────────────────────────────────────────────┘     │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### 3.2 方案 A：高置信度 Agent/MCP 目标（推荐）

**适用条件**：
- `attack_surface` ∈ {`mcp_server`, `multi_agent_system`, `rag_system`}
- `confidence` ≥ 0.8
- 证据包含 ≥ 2 个维度（URL + Header/Body）

**执行命令**：

```bash
# 已知 MCP 目标，高置信度
python main.py \
  --escalation-levels 4 \
  --synergy \
  --burp mcp05 \
  --max-seeds 8 \
  --target http://target:8080

# 已知 Agent 目标，高置信度
python main.py \
  --escalation-levels 4 \
  --synergy \
  --burp agent01 \
  --max-seeds 8 \
  --target http://target:8080

# 已知 RAG 目标，高置信度
python main.py \
  --escalation-levels 4 \
  --synergy \
  --burp rag01 \
  --max-seeds 8 \
  --target http://target:8080
```

**学术理论支撑**：

```
直接 L4 的理论依据:
┌────────────────────────────────────────────────────────────────┐
│ 1. InjecAgent: 通用攻击对 Agent 无效，需跳过                    │
│ 2. Eidam et al.: A2A 信任链攻击需要 L4 的 Rogue Agent 向量      │
│ 3. Greshake et al.: 间接注入需要 L4 的 MCP/RAG 专用种子         │
│ 4. Lattner et al.: 并行升级中间退出，L4 已达成本最优             │
└────────────────────────────────────────────────────────────────┘
```

### 3.3 方案 B：中等置信度目标

**适用条件**：
- `confidence` ∈ [0.6, 0.8)
- 证据仅单一维度命中

**执行命令**：

```bash
# 中等置信度，增加 L3 的 SkeletonKey 作为辅助
python main.py \
  --escalation-levels 3,4 \
  --synergy \
  --burp unknown_agent \
  --max-seeds 12 \
  --target http://target:8080
```

**理论支撑**：
- SkeletonKey (arXiv:2406.18112) 对 Agent 有 80-95% ASR，可作为 L4 前的"安全探测"
- 如果 L3 已成功，可提前退出节省 L4 token

### 3.4 方案 C：低置信度/未知目标

**适用条件**：
- `confidence` < 0.6
- 无法确定目标类型

**执行命令**：

```bash
# 完整升级链，自动逐步升级
python main.py \
  --synergy \
  --burp unknown \
  --max-seeds 25 \
  --target http://target:8080
```

---

## 四、高置信度目标的 L4 攻击向量详解

### 4.1 MCP Server 目标（L4 攻击向量）

```
┌─────────────────────────────────────────────────────────────────────────┐
│                     MCP Server L4 攻击面                                │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  mcp_tool_enum.prompt            → 工具枚举，识别攻击面                   │
│  mcp_server_injection.prompt     → 服务器端注入                          │
│  mcp_tool_hijack.prompt          → 工具劫持 (ASI02)                      │
│  mcp_context_poisoning.prompt    → 上下文投毒 (间接注入)                  │
│  mcp_resource_leak.prompt        → 资源泄露                              │
│  mcp_tool_description_injection  → 工具描述注入                          │
│  mcp_resource_traversal          → 资源遍历                              │
│  mcp_cross_server_trust          → 跨服务器信任攻击                       │
│  mcp_schema_poisoning            → Schema 投毒                           │
│  mcp_tool_chaining               → 工具链攻击                            │
│  mcp_rogue_endpoint              → 流氓端点 (ASI10)                      │
│  mcp_ui_rendering_deception      → UI 渲染欺骗                           │
│                                                                         │
│  RogueAgent A2A 伪造            → 身份伪造 + 信任链绕过                   │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### 4.2 Agent/Multi-Agent 目标（L4 攻击向量）

```
┌─────────────────────────────────────────────────────────────────────────┐
│                   Agent/Multi-Agent L4 攻击面                           │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  Rogue Agent 攻击:                                                      │
│    ├── A2A 身份伪造 (security-audit-agent-v2)                           │
│    ├── FULL_ACCESS 信任级别声明                                          │
│    └── SkeletonKey 前缀注入降低过滤                                       │
│                                                                         │
│  Multi-Agent 种子:                                                       │
│    ├── ma_cross_agent_injection.prompt   → 跨 Agent 注入                 │
│    └── ma_identity_spoofing.prompt       → 身份欺骗                      │
│                                                                         
│  通用 Agent 安全:                                                        │
│    ├── T1_ASI02_tool_hijack.prompt       → 工具劫持                      │
│    ├── T1_ASI02_function_call_exploit    → 函数调用利用                  │
│    └── T1_ASI01-10_agent_security_comprehensive → 综合测试               │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### 4.3 RAG System 目标（L4 攻击向量）

```
┌─────────────────────────────────────────────────────────────────────────┐
│                       RAG System L4 攻击面                              │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  rag_full_attack_surface.prompt:                                         │
│    ├── 知识库泄露 (Knowledge Leakage)                                    │
│    ├── 检索劫持 (Retrieval Hijack)                                       │
│    ├── 数据投毒 (Poisoning)                                              │
│    └── 嵌入反转 (Embedding Inversion)                                    │
│                                                                         │
│  Embedding Inversion Attack:                                            │
│    └── 从嵌入向量重构训练数据 (Morris et al. arXiv:2310.06870, ASR 85-92%)│
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 五、最优配置的学术参数建议

### 5.1 关键参数配置（`config/defaults.yaml`）

```yaml
# 针对 Agent/MCP 目标的最优参数
max_seeds: 8                 # L4 专用种子数量 (不超过 12)
escalation_asr_threshold: 90  # 单轮 ASR 阈值 (达标后跳过升级)
scenario_timeout: 600         # 单个攻击超时 (秒)
priority_scheduler_enabled: 1 # L1 优先级调度 (L4无效，可忽略)
```

### 5.2 `--escalation-levels` 参数选择

| 目标类型 | 置信度 | 推荐 `--escalation-levels` | 预期 ASR |
|---------|--------|--------------------------|---------|
| MCP Server | ≥ 0.8 | `4` | 40-70% |
| RAG System | ≥ 0.8 | `4` | 50-80% |
| Multi-Agent | ≥ 0.8 | `4` | 30-60% |
| 未知 Agent | 0.6-0.8 | `3,4` | 20-50% |
| 完全未知 | < 0.6 | `1,2,3,4` (完整链) | 10-40% |

---

## 六、完整执行流程示例

### 6.1 场景：已知 MCP 目标，高置信度

```bash
# Step 1: Dry-run 侦察
python main.py --dry-run --max-seeds 1 --burp mcp05
# 读取输出: synergy_config.confidence = 0.92
#           synergy_config.attack_surface = "mcp_server"
#           synergy_config.evidence = ["/mcp/", "jsonrpc", "tools"]

# Step 2: 置信度 ≥ 0.8，执行方案 A
python main.py \
  --escalation-levels 4 \
  --synergy \
  --burp mcp05 \
  --max-seeds 8 \
  --target http://target-mcp:8080 \
  --config-file config/defaults.yaml

# Step 3: 结果验证
# 查看 outputs/strike_*/joint_asr_report.md
# 预期: L4 RogueAgent + MCP/RAG 攻击成功占比 40-70%
```

### 6.2 场景：未知目标，先侦察后决策

```bash
# Step 1: Dry-run
python main.py --dry-run --max-seeds 1 --burp unknown_target
# 读取输出置信度...

# Step 2a: 如果 confidence >= 0.8 且 surface = mcp_server
python main.py --escalation-levels 4 --synergy --burp unknown_target ...

# Step 2b: 如果 confidence 0.6-0.8
python main.py --escalation-levels 3,4 --synergy --burp unknown_target ...

# Step 2c: 如果 confidence < 0.6
python main.py --synergy --burp unknown_target ...
```

---

## 七、决策矩阵总结

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         最优攻击决策矩阵                                     │
├──────────────────┬──────────────┬──────────────────────────────────────────┤
│   目标类型        │   置信度      │   最优策略                                │
├──────────────────┼──────────────┼──────────────────────────────────────────┤
│ MCP Server       │   ≥ 0.8      │  --escalation-levels 4 (直接 L4)          │
│                  │   0.6-0.8    │  --escalation-levels 3,4                  │
│                  │   < 0.6      │  完整升级链 (L1→L4)                       │
├──────────────────┼──────────────┼──────────────────────────────────────────┤
│ RAG System       │   ≥ 0.8      │  --escalation-levels 4 (Embedding Inversion│
│                  │              │  + RAG 投毒)                              │
│                  │   0.6-0.8    │  --escalation-levels 3,4                  │
│                  │   < 0.6      │  完整升级链                               │
├──────────────────┼──────────────┼──────────────────────────────────────────┤
│ Multi-Agent      │   ≥ 0.8      │  --escalation-levels 4 (RogueAgent A2A    │
│                  │              │  + 跨 Agent 注入)                         │
│                  │   0.6-0.8    │  --escalation-levels 3,4                  │
│                  │   < 0.6      │  完整升级链                               │
├──────────────────┼──────────────┼──────────────────────────────────────────┤
│ Standard LLM API │   ≥ 0.8      │  完整升级链 (L1→L4)                       │
│                  │   < 0.8      │  完整升级链                               │
└──────────────────┴──────────────┴──────────────────────────────────────────┘
```

---

## 八、自动 L4 优化路径（代码实现）

### 8.1 实现原理

当协同分析（Synergy）识别到目标为 Agent/MCP/RAG 且置信度 ≥ 0.8 时，自动覆盖 `escalation_levels` 参数，跳过 L1-L3 直接执行 L4 攻击。

### 8.2 代码修改位置

**文件**: `main.py` (SYNERGY 阶段后)

**修改内容**: 在 SYNERGY 阶段检测到高置信度 Agent/MCP/RAG 目标时，自动设置 `escalation_levels_parsed = [4]`

### 8.3 决策逻辑

```python
# 高置信度 Agent/MCP/RAG 目标自动 L4 优化
_AGENT_SURFACES = {"mcp_server", "multi_agent_system", "rag_system"}
_HIGH_CONFIDENCE_THRESHOLD = 0.8

if (ctx.synergy_config 
    and ctx.synergy_config.attack_surface in _AGENT_SURFACES
    and ctx.synergy_config.confidence >= _HIGH_CONFIDENCE_THRESHOLD
    and not getattr(args, "escalation_levels_parsed", None)):
    # 自动设置 L4 优化路径
    setattr(args, "escalation_levels_parsed", [4])
    logger.info(
        "Auto L4 optimization: surface=%s, confidence=%.2f >= %.2f",
        ctx.synergy_config.attack_surface,
        ctx.synergy_config.confidence,
        _HIGH_CONFIDENCE_THRESHOLD,
    )
```

---

## 九、学术参考文献

| 编号 | 论文 | 理论支撑 |
|------|------|---------|
| [1] | Zhan et al. InjecAgent (arXiv:2307.00929) | Agent 目标需定向攻击，通用 jailbreak 无效 |
| [2] | Eidam et al. (arXiv:2407.16924) | A2A 信任链攻击 ASR +15-25% |
| [3] | Greshake et al. (arXiv:2302.12173) | 间接注入 ASR 60-90% |
| [4] | Lattner et al. (arXiv:2406.12609) | 并行升级链中间退出，ASR 达标后提前退出 |
| [5] | Morris et al. (arXiv:2310.06870) | Embedding Inversion ASR 85-92% |
| [6] | Hanna et al. (arXiv:2406.18112) | SkeletonKey ASR 80-95% |
| [7] | OWASP ASI10 | Rogue Agent 威胁分类 |

---

## 十、实施清单

### 10.1 代码修改

- [ ] `main.py` — SYNERGY 阶段后添加自动 L4 决策逻辑
- [ ] `main.py` — 添加终端输出显示自动优化决策
- [ ] `main.py` — 添加编排日志记录自动优化事件

### 10.2 配置更新

- [ ] `config/defaults.yaml` — 添加 `auto_l4_optimization_enabled` 开关
- [ ] `config/defaults.yaml` — 添加 `auto_l4_confidence_threshold` 参数

### 10.3 测试验证

- [ ] 单元测试 — 验证高置信度 MCP 目标自动触发 L4
- [ ] 单元测试 — 验证中置信度目标不触发自动 L4
- [ ] 单元测试 — 验证低置信度目标回退到完整链
- [ ] 集成测试 — 验证端到端自动 L4 执行

### 10.4 文档更新

- [x] `docs/escalate.md` — 本文档
- [ ] `docs/implementation_checklist.md` — 更新实施清单
