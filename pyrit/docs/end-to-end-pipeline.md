# 四、端到端全自动渗透测试（End-to-End Pipeline）

> **核心理念**：指定一个目标 URL 后，框架自动完成 侦察→攻击→评分→报告 全流程，无需人工干预。

---

**📖 手册导航**：[← 三、攻击后研判](post-attack-analysis.md) | [五、自适应引擎 →](adaptive-engine.md)

---

### 4.1 端到端一键命令

```bash
# ============================================================
#  场景 A：内网自部署模型（无认证），全阶段门控
#  【推荐】最平衡的方案：自动阶梯升级，避免无效攻击
# ============================================================
python main.py --lang cn \
  --target-url http://192.168.2.199:8501/v1/chat/completions \
  --auto-gate --gate-threshold 0.10
```

> **特别说明**：
> - `--auto-gate` 是端到端的核心开关，开启后自动执行三段阶梯：PROBE→SINGLE→CRESCENDO
> - `--gate-threshold 0.10` 的含义：如果 PROBE 阶段成功率低于 10%，自动跳过后续所有阶段。这在目标防御极强时能节省大量时间和 Token
> - 无需传 Key、无需指定模型名、无需指定格式，框架全部自动探测
> - 执行完毕后终端会打印战报，`outputs/results/` 下生成 JSON 日志 + PNG 热力图 + Markdown 报告

```bash
# ============================================================
#  场景 B：内网自部署模型，全阶段 + 自适应引擎
#  【最强】最高成功率方案：动态300+组合 + Bandit智能调度
# ============================================================
python main.py --lang cn \
  --target-url http://192.168.2.199:8501/v1/chat/completions \
  --adaptive --auto-gate --gate-threshold 0.10
```

> **特别说明**：
> - `--adaptive` 在门控基础上额外启用自适应引擎
> - 动态组合从静态 67 种扩展到 300+ 种（笛卡尔积展开 + 智能剪枝）
> - Bandit 调度器以 85% 概率 exploit 最优组合、15% 概率 explore 新组合
> - 成功组合自动跨用例传播（折扣因子 0.7），加速全局收敛
> - 混合评分器输出 0-1 灰度分数，比二元 True/False 更精准
> - 厂商检测自动匹配已知弱点载荷（如 OpenAI → 角色扮演+代码解释器绕过）
> - **注意**：`--adaptive` 会增加攻击时间和 Token 消耗，建议针对高价值目标使用

```bash
# ============================================================
#  场景 C：OpenAI 兼容端点（需认证），全阶段
# 【标准】云 API 的标准攻击流程
# ============================================================
python main.py --lang cn \
  --target-url https://api.internal.example.com/v1/chat/completions \
  --target-api-key sk-your-key \
  --target-model gpt-4 \
  --auto-gate --gate-threshold 0.10
```

> **特别说明**：
> - 外部 API 需要 `--target-api-key`，框架自动在 HTTP 头注入 `Authorization: Bearer {key}`
> - `--target-model gpt-4` 手动指定模型名，可跳过自动探测加速启动
> - 如果目标是 HTTPS 自签证书，添加 `--target-no-ssl` 跳过验证
> - Gemini API 需要额外传 `--target-api-format gemini`
> - Claude API 需要额外传 `--target-api-format claude`

```bash
# ============================================================
#  场景 D：raw 格式端点（非标准 Web Chat），全阶段
# 【兜底】非 OpenAI 兼容的 Web Chat 应用
# ============================================================
python main.py --lang cn \
  --target-url http://192.168.2.199:8501/api/chat \
  --target-api-format raw \
  --auto-gate --gate-threshold 0.10
```

> **特别说明**：
> - `raw` 格式的 POST Body 为 `{"message":"...", "conversation_id":""}`，不包含 `model` 字段
> - 可配合 `--target-cookie` / `--target-jwt` 实现认证
> - 可配合 `--target-extra-headers` 注入自定义头
> - 如果 raw 端点需要 form-urlencoded 格式，参考[二、攻击阶段→场景 3](attack-scenarios.md) 使用 `--scenario form-cookie`

```bash
# ============================================================
#  场景 E：直达全量攻击（跳过门控，直接执行所有策略）
# 【火力全开】一步到位覆盖所有攻击策略
# ============================================================
python main.py --lang cn \
  --target-url http://192.168.2.199:8501/v1/chat/completions \
  --phase all
```

> **特别说明**：
> - `--phase all` 直接执行全部 9 种攻击策略，不经过门控判断
> - 适合确信目标存在漏洞的场景，或者需要完整攻击矩阵覆盖时使用
> - **⚠ 注意**：`--phase all` 攻击量级大，Token 消耗高，建议先跑 `--auto-gate` 试探
> - 可与 `--adaptive` 叠加获得最强攻击效果
> - 可与 `--target-api-key` / `--target-api-format` 等参数自由组合
> - 执行时间：单并发约 30-120 分钟（取决于用例数和目标响应速度）

### 4.2 端到端管线的 4 大阶段

```
┌──────────────────────────────────────────────────────────────────┐
│  $ python main.py --lang cn --target-url URL --auto-gate         │
│  $ python main.py --lang cn --target-url URL --adaptive --all    │
└──────────────────────────────┬───────────────────────────────────┘
                               ▼
┌──────────────────────────────────────────────────────────────────┐
│ 阶段一：环境初始化（bootstrap.py，9 步）                          │
│                                                                  │
│  Step 0: 创建 SQLiteMemory + 注册到 CentralMemory 全局单例       │
│          → outputs/results/pyrit_redteam_memory_xxx.db           │
│  Step 1: 加载 .env 配置 → attacker_config + scorer_config        │
│  Step 2: 校验模型是否配置，失败则提前退出                          │
│  Step 3: 创建 Judge LLM（评分器 Target）                          │
│  Step 4: 自动探测目标 URL 可达性 + 模型名称，构建 HTTP Target      │
│  Step 5: auto_probe_target_type() 判断目标架构类型                │
│          → LLM / RAG / MCP / Agent / Multi-Agent / Multimodal    │
│  Step 6: 加载 Payload 模板变量（中文/英文 payload）               │
│  Step 7: 自动扫描 converters/ 目录加载所有转换器（72+ 个）        │
│  Step 8: 汇总攻击组合（127+ 组单层/双层/三层链）                  │
│  Step 9: 解析 --case / --exclude-case / --phase → 最终用例列表   │
└──────────────────────────────┬───────────────────────────────────┘
                               ▼
┌──────────────────────────────────────────────────────────────────┐
│ 阶段二：路由分发（router.py）                                     │
│                                                                  │
│  route_command() 根据 CLI 参数选择执行路径：                      │
│                                                                  │
│  --auto-gate  → run_phased_campaign()  阶梯式门控                │
│                 ├── STAGE 1: PROBE 快速探测                      │
│                 ├── STAGE 2: 单轮主力突破（门控: 成功率 ≥ 阈值）  │
│                 └── STAGE 3: Crescendo 多轮攻坚                  │
│                                                                  │
│  无 --auto-gate → run_native_single_phase() 直接执行             │
│                   ├── --phase probe      快速探测                 │
│                   ├── --phase single     单轮突破                 │
│                   ├── --phase crescendo  Crescendo 渐进          │
│                   ├── --phase pair       PAIR 反驳式              │
│                   ├── --phase tap        TAP 树搜索              │
│                   ├── --phase flip       Flip 翻转               │
│                   ├── --phase chunked    分块绕过                 │
│                   ├── --phase manyshot   洪水攻击                 │
│                   ├── --phase skeleton_key 解除限制               │
│                   └── --phase all        全部策略                 │
│                                                                  │
│  --adaptive   → 动态组合生成(300+) + Bandit 调度 + 厂商差异化     │
│  --penetrating-mode → YAML 模板驱动渗透模式                       │
└──────────────────────────────┬───────────────────────────────────┘
                               ▼
┌──────────────────────────────────────────────────────────────────┐
│ 阶段三：攻击执行（orchestrators/pyrit_orchestrator.py）           │
│                                                                  │
│  单次攻击微观管道：                                               │
│                                                                  │
│  测试用例 objective                                              │
│      → Converter 管道（编码/角色扮演/语义包装等 N 层转换）        │
│          → HTTP POST 到目标 URL                                  │
│              → 目标 LLM 响应                                     │
│                  → Judge LLM 评分（True/False/灰度）              │
│                      → 结果存入 SQLite Memory                    │
│                          → 返回统一格式 dict                     │
│                                                                  │
│  攻击策略矩阵（9 种核心策略）：                                   │
│                                                                  │
│  | 策略          | 攻击器                  | 原理                 │
│  |---------------|------------------------|----------------------│
│  | probe         | PromptSendingAttack    | 轻量快速弱点扫描     │
│  | single        | PromptSendingAttack    | 单轮攻击全覆盖       │
│  | crescendo     | CrescendoAttack        | 多轮渐进递进+回退    │
│  | pair          | PAIRAttack             | 迭代反驳式越狱       │
│  | tap           | TAPAttack              | 树搜索MCTS剪枝       │
│  | flip          | FlipAttack             | 对话翻转攻击         │
│  | chunked       | ChunkedRequestAttack   | 分块请求绕过         │
│  | manyshot      | ManyShotJailbreakAttack| 大量示例淹没上下文   │
│  | skeleton_key  | SkeletonKeyAttack      | 直接解除限制指令     │
│                                                                  │
│  自适应引擎增强（--adaptive）：                                   │
│  • 动态组合生成：300+ 种 converter 组合（vs 静态 67 种）         │
│  • Bandit 调度：epsilon-greedy 策略实时选择最优组合               │
│  • 跨用例传播：成功组合自动推广到其他用例                          │
│  • 混合评分：LLM Judge(40%)+关键词密度(25%)+拒绝模式(20%)+内容比(15%) │
│  • 厂商差异化：6 大厂商针对性载荷和弱点利用                        │
└──────────────────────────────┬───────────────────────────────────┘
                               ▼
┌──────────────────────────────────────────────────────────────────┐
│ 阶段四：报告生成（reporting/）                                    │
│                                                                  │
│  攻击完成 → router.py 自动依次调用：                              │
│                                                                  │
│  1. export_results() → JSON 攻击日志                             │
│     outputs/results/{campaign}_log_{timestamp}.json              │
│                                                                  │
│  2. analyze_and_visualize() → PNG 热力图                         │
│     outputs/results/*_heatmap_*.png                              │
│     combo_name × case_id 成功率矩阵可视化                         │
│                                                                  │
│  3. print_detailed_report() → 终端 Rich 战报                     │
│     • 总体统计（SUCCESS/FAILURE/ERROR）                           │
│     • 漏洞详情（Prompt→Response→评分理由）                        │
│     • 防御统计（成功拒绝的攻击向量）                               │
│     • 下一步攻击命令（自动生成可复制命令）                         │
│                                                                  │
│  4. generate_penetrating_report() → Markdown 渗透报告             │
│     outputs/results/{campaign}_Exam_Report_{timestamp}.md       │
│     10 章标准报告结构（TLP:AMBER 封面 → 执行摘要 → 方法论        │
│     → 漏洞详情+证据 → 根因分析 → 修复建议 → 结论 → 附录）         │
│     + MITRE ATLAS / OWASP LLM Top 10 / NIST AI RMF 标准映射      │
└──────────────────────────────────────────────────────────────────┘
```

### 4.3 底层代码路径详解

端到端一条命令背后的完整调用链：

| 步骤 | 文件 | 关键函数 | 核心逻辑 |
|------|------|---------|---------|
| ① 入口 | `main.py` | `main()` | 解析 CLI → 回显 banner → 调用 `bootstrap()` |
| ② 初始化 | `entrypoint/bootstrap.py` | `bootstrap()` | 9 步初始化：Memory→配置→Target→架构→Payload→Converter→组合→用例 |
| ③ 路由 | `entrypoint/router.py` | `route_command()` | 根据 `--auto-gate`/`--adaptive`/`--phase` 选择执行路径 |
| ④ 门控 | `orchestrators/pyrit_orchestrator.py` | `run_phased_campaign()` | 阶梯式：Probe → Single → Crescendo，每阶段检查成功率阈值 |
| ⑤ 单轮 | `orchestrators/pyrit_orchestrator.py` | `_execute_prompt_sending_attack()` | 构建评分器→转换器→攻击器→执行→提取结果 |
| ⑥ 多轮 | `orchestrators/pyrit_orchestrator.py` | `_execute_crescendo_attack()` | 渐进取进+回退重试，每轮基于上一轮响应调整 |
| ⑦ 自适应 | `orchestrators/pyrit_orchestrator.py` | `run_adaptive_campaign()` | 动态组合+Bandit调度+跨用例传播+提前终止 |
| ⑧ JSON 导出 | `orchestrators/pyrit_orchestrator.py` | `export_results()` | 遍历所有结果，结构化写入 JSON |
| ⑨ 可视化 | `reporting/visualizer.py` | `analyze_and_visualize()` | 生成 combo×case 成功率热力图 |
| ⑩ 终端战报 | `reporting/terminal.py` | `print_detailed_report()` | Rich 格式化：统计面板+漏洞详单+防御统计+下一命令 |
| ⑪ 渗透报告 | `reporting/penetrating.py` | `generate_penetrating_report()` | 10 章 Markdown：封面→摘要→方法论→证据→RCA→修复→结论 |

### 4.4 完整命令速查

```bash
# ============================================================
#  一、侦察阶段（仅探测，不攻击）
# ============================================================
python main.py --lang cn --target-url http://192.168.2.199:8501/ --phase probe

# ============================================================
#  二、门控阶梯攻击（推荐）
# ============================================================
# 基础门控
python main.py --lang cn --target-url http://192.168.2.199:8501/v1/chat/completions \
  --auto-gate --gate-threshold 0.10

# 门控 + 自适应引擎
python main.py --lang cn --target-url http://192.168.2.199:8501/v1/chat/completions \
  --adaptive --auto-gate --gate-threshold 0.10

# 门控 + 自适应 + 去重缓存 + 提前终止（最省资源）
python main.py --lang cn --target-url http://192.168.2.199:8501/v1/chat/completions \
  --adaptive --auto-gate --use-dedup-cache --enable-early-stop

# ============================================================
#  三、全量攻击（不门控，直接所有策略）
# ============================================================
python main.py --lang cn --target-url http://192.168.2.199:8501/v1/chat/completions \
  --phase all

python main.py --lang cn --target-url http://192.168.2.199:8501/v1/chat/completions \
  --adaptive --phase all

# ============================================================
#  四、单阶段攻击（按需选择）
# ============================================================
python main.py --lang cn --target-url http://192.168.2.199:8501/v1/chat/completions --phase single
python main.py --lang cn --target-url http://192.168.2.199:8501/v1/chat/completions --phase crescendo
python main.py --lang cn --target-url http://192.168.2.199:8501/v1/chat/completions --phase pair
python main.py --lang cn --target-url http://192.168.2.199:8501/v1/chat/completions --phase tap
python main.py --lang cn --target-url http://192.168.2.199:8501/v1/chat/completions --phase chunked
python main.py --lang cn --target-url http://192.168.2.199:8501/v1/chat/completions --phase manyshot
python main.py --lang cn --target-url http://192.168.2.199:8501/v1/chat/completions --phase skeleton_key

# ============================================================
#  五、带认证的端到端攻击
# ============================================================
# OpenAI 兼容 API
python main.py --lang cn \
  --target-url https://api.internal.example.com/v1/chat/completions \
  --target-api-key sk-your-key --phase all

# Gemini API
python main.py --lang cn \
  --target-url https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent \
  --target-api-format gemini --target-api-key YOUR_KEY --phase all

# Claude API
python main.py --lang cn \
  --target-url https://api.anthropic.com/v1/messages \
  --target-api-format claude --target-api-key YOUR_KEY \
  --target-model claude-3-sonnet-20240229 --phase all

# Cookie/JWT 认证的 Web 应用
python main.py --lang cn \
  --target-url http://192.168.1.100/api/chat \
  --target-api-format raw --target-cookie "session=abc" --phase all

# ============================================================
#  六、渗透模式（YAML 模板驱动全自动编排）
# ============================================================
python main.py --penetrating-mode --penetrating-template jailbreak_arsenal.yaml \
  --target-url http://192.168.2.199:8501/v1/chat/completions

python main.py --penetrating-mode --penetrating-template rag_pipeline.yaml \
  --target-url http://192.168.2.199:8501/api/rag --target-api-key sk-xxx

python main.py --penetrating-mode --penetrating-template agent_multi_agent.yaml \
  --target-url http://192.168.2.199:8501/api/agent --target-api-key sk-xxx
```

### 4.5 产物清单（每次执行完毕后自动生成）

| 产物 | 路径 | 说明 |
|------|------|------|
| JSON 攻击日志 | `outputs/results/{campaign}_log_{timestamp}.json` | 完整 attack → response → score 结构化数据 |
| PNG 热力图 | `outputs/results/*_heatmap_*.png` | converter×case 成功率矩阵可视化 |
| SQLite 记忆库 | `outputs/results/pyrit_redteam_memory_*.db` | PyRIT 原生持久化（PromptPiece/Score/Conversation） |
| 终端 Rich 战报 | Console 输出 | SUCCESS/FAILURE/ERROR 统计+漏洞详情+下一步命令 |
| Markdown 渗透报告 | `outputs/results/{campaign}_Exam_Report_{timestamp}.md` | 10 章 OSCP 标准报告（含 MITRE/OWASP/NIST 映射） |

### 4.6 特别说明：常见场景与注意事项

#### 4.6.1 `--auto-gate` vs `--phase all` 如何选？

| 场景 | 推荐命令 | 原因 |
|------|---------|------|
| 初次探测新目标 | `--auto-gate` | 先轻量试探，避免在强防御目标上浪费资源 |
| 目标已知脆弱 | `--phase all` | 直接火力全开，追求最大发现量 |
| 生产环境正式评估 | `--auto-gate --gate-threshold 0.10` | 标准化流程，输出可审计的阶梯报告 |
| 对高价值目标深挖 | `--auto-gate --adaptive` | 智能组合 + 厂商弱点利用，成功率最高 |

#### 4.6.2 目标不可达时的处理

当框架探测到目标不可达时，会**立即中止所有后续攻击**，并输出红色诊断面板：

```
❌ 目标不可达 — 模型自动探测未成功
🔍 诊断建议:
  1. 确认目标服务是否已启动
  2. 检查防火墙/安全组/网络策略是否放行
  3. 确认是否需要 VPN/代理访问内网目标
  4. 如果是 HTTPS 自签证书，加 --target-no-ssl 参数
⛔ 攻击流程已终止
```

> **重要**：这是安全设计。目标不可达时不会执行任何攻击任务，避免无效重试和 Token 浪费。

#### 4.6.3 并发控制与限流规避

```
侦察阶段建议:
  框架内置自适应限流：初始 3 并发 → 检测 429 → 自动降速
  侦察输出会给出推荐并发数（取上限 50% 安全边际）

攻击阶段建议:
  --concurrent 1   默认值，最安全
  --concurrent 2   内网环境通常安全
  --concurrent 4   高性能目标，先跑 PROBE 侦察确认
  --concurrent 8+  云端 API，先用侦察确认 RPM 限制
```

#### 4.6.4 攻击容错机制

框架内置多层容错，确保端到端执行的鲁棒性：

| 机制 | 说明 | 触发条件 |
|------|------|---------|
| HTTP 重试 | 指数退避重试 3 次 | 网络超时 / 5xx 错误 |
| 用例跳过 | 跳过不可恢复的失败用例 | 连续失败 / 目标拒绝 |
| 攻击回退 | Crescendo 攻击回退重试 | 多轮对话偏离方向 |
| 门控跳过 | 跳过低成功率的后续阶段 | 阶段成功率 < `--gate-threshold` |
| 提前终止 | 停止已饱和的用例 | 连续 3 次 FULL_SUCCESS（需 `--enable-early-stop`） |
| 去重缓存 | 跳过重复 prompt | 相同目标+相同 prompt（需 `--use-dedup-cache`） |

#### 4.6.5 报告中的标准映射

所有攻击结果自动映射到三大 AI 安全标准，无需手动标注：

| 标准 | 映射覆盖 | 报告位置 |
|------|---------|---------|
| MITRE ATLAS | 19 个技术（AML.T0015-T0057） | §4 漏洞详情表格 |
| OWASP LLM Top 10 (2025) | LLM01-LLM10 + CVSS 评分 | §4 漏洞卡片 + §8 修复方案 |
| NIST AI RMF | GOVERN/MAP/MEASURE/MANAGE | §2 测试方法论 |

#### 4.6.6 环境变量配置

端到端执行前需在 `.env` 中配置攻击者 LLM 和评分器 LLM：

```bash
# configs/attacker.env — 攻击者 LLM（生成越狱 prompt）
ATTACKER_OPENAI_KEY=sk-xxx
ATTACKER_OPENAI_ENDPOINT=https://api.openai.com/v1
ATTACKER_OPENAI_MODEL=gpt-4o
# 或使用内网自部署攻击者
ATTACKER_OLLAMA_ENDPOINT=http://192.168.1.100:11434/v1
ATTACKER_OLLAMA_MODEL=qwen2.5:72b

# configs/scorer.env — 评分器 LLM（目标兼容 Judge，客观中立）
SCORER_OPENAI_KEY=sk-xxx
SCORER_OPENAI_ENDPOINT=https://api.openai.com/v1
SCORER_OPENAI_MODEL=gpt-4o
```

> **特别说明**：攻击者 LLM 和评分器 LLM 应与目标 LLM 保持独立。评分器 LLM 必须是一个可信任的、客观中立的模型。

#### 4.6.7 执行时间估算

| 命令 | 预计耗时 | 攻击次数（约） | 说明 |
|------|---------|---------------|------|
| `--phase probe` | 3-10 分钟 | 30-100 | 轻量探测，输出侦察结果 |
| `--phase single` | 10-30 分钟 | 200-500 | 单轮全覆盖 |
| `--phase crescendo` | 20-60 分钟 | 100-300 | 多轮渐进，单次耗时长 |
| `--auto-gate` | 10-90 分钟 | 100-800 | 取决于各阶段门控是否通过 |
| `--phase all` | 30-120 分钟 | 500-1500 | 全部 9 种策略 |
| `--adaptive --auto-gate` | 20-150 分钟 | 200-2000 | 动态组合数量浮动大 |

> **注意**：以上为单并发估算。增加 `--concurrent` 可显著缩短时间，但可能触发目标限流。

---

**📖 手册导航**：[← 三、攻击后研判](post-attack-analysis.md) | [五、自适应引擎 →](adaptive-engine.md)
