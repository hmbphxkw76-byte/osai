# garak-pipeline — AI 红队全链路扫描平台

> 版本 3.0.0 | 更新 2026-08-11

基于 [garak](https://github.com/NVIDIA/garak) 原生框架的 **AI 红队全链路流水线**，对齐 L5 专家水平。
覆盖 kill chain 全阶段：侦察 → 武器化 → 投递利用 → 战果分析 → 红队交付。

## 快速开始

```bash
# 1. 安装依赖
pip install -r requirements.txt
playwright install chromium

# 2. 配置目标（编辑 .env）
WEB_TARGET_URL=http://192.168.40.198/
TARGET_USERNAME=your_username
TARGET_PASSWORD=your_password

# 3. 全链路扫描（Web 认证模式，默认）
python main.py

# 4. OpenAI 直连模式
python main.py --openai

# 5. 多页面批量扫描
python main.py --batch config/web_target_list.yaml
```

## 运行模式

| 命令 | 说明 |
|------|------|
| `python main.py` | Web 认证模式：Playwright 登录 → 端点发现 → 全链路扫描 |
| `python main.py --openai` | OpenAI 直连模式：API Key 认证 → 全链路扫描 |
| `python main.py --batch <yaml>` | 多目标批量扫描：逐目标独立运行 + 汇总对比 |
| `python main.py --stage 1` | 仅侦察（攻击面枚举 + OWASP 分类） |
| `python main.py --stage 1-2` | 侦察 + 配置（不执行攻击） |
| `python main.py --stage 4-5 --run-id <id>` | 复用历史产物做分析 + 报告 |
| `python main.py --profile balanced` | 扫描档位：full / balanced / quick / smoke |
| `python main.py --resume` | 断点续扫 |

## 5 阶段流水线

| 阶段 | 名称 | offsec 语义 | 核心能力 |
|------|------|------------|---------|
| 1 | 侦察 | Reconnaissance | 连通性级联探测 + garak 探针枚举 + OWASP LLM/Agentic 双分类 + 模态侦察 + WAF 前置探测 |
| 2 | 配置 | Weaponization | Tier 优先级排序 + scan_profile 档位 + Buff 攻击链 + atkgen 动态变异 |
| 3 | 攻击 | Delivery & Exploitation | garak harness 真驱动 + 自适应速率 + 会话刷新 + 断点续扫 + ATLAS TTP 标注 |
| 4 | 分析 | Impact Assessment | ASR/DEFCON + Bootstrap 置信区间 + nones 假阴性检测 + LLM-as-Judge + 隐蔽性评估 |
| 5 | 报告 | Red Team Deliverables | HTML + PyRIT AIR + AVID + SARIF + PDF + IOA 检测规则 + 合规映射 |

## 攻击面覆盖

### OWASP LLM Top 10

| ID | 类别 | garak 原生 | 自研探针 |
|----|------|-----------|---------|
| LLM01 | Prompt Injection | ✅ | — |
| LLM02 | Insecure Output | ✅ | — |
| LLM03 | Training Data Poisoning | — | ✅ `llm03_training_data` |
| LLM04 | Model DoS | ✅ | — |
| LLM05 | Supply Chain | ✅ | — |
| LLM06 | Sensitive Info Disclosure | ✅ | — |
| LLM07 | Insecure Plugin Design | — | ✅ `llm07_plugin_design` + `mcp_abuse` |
| LLM08 | Vector Embedding | — | ✅ `llm08_vector_embedding` |
| LLM09 | Misinformation | ✅ | — |
| LLM10 | Unbounded Consumption | ✅ | — |

### OWASP Agentic AI Top 10 + Multi-agent

| 探针 | 攻击场景 | Tier |
|------|---------|------|
| `ASI07_AgentImpersonation` | 伪造 inter-agent 消息 | T2 |
| `ASI07_MessageInjection` | 消息通道 prompt injection | T3 |
| `ASI08_CascadingFailure` | 级联失败传播 | T3 |
| `MCP_ToolPoisoning` | MCP 工具描述嵌入恶意指令 | T2 |
| `MCP_FunctionCallInjection` | Function call 参数注入 | T2 |
| `AgentIndirectInjection` | 工具输出中间接注入 | **T1** |
| `AgentMemoryPoisoning` | 记忆/上下文投毒 | T2 |
| `AgentGoalHijack` | 目标劫持 via function call | **T1** |
| `AgentOrchestrationExploit` | 编排层信任边界利用 | T2 |
| `AgentMultiTurnManipulation` | 多轮渐进操纵 | T2 |
| `AgentPrivilegeEscalation` | 工具链权限提升 | **T1** |

## 认证模式

### Web 认证（默认）

```
Playwright 打开浏览器 → 自动填充凭据 → 人工配合 2FA/验证码
→ 端点发现（JS 变量 / /models / SPA fetch 拦截）
→ Cookie 落盘 → garak 注入认证头 → 扫描
```

- **会话复用**：同域多页面共享 Cookie，避免重复登录
- **会话刷新**：长扫描中 401/403 → 无头重登录 → Cookie 更新 → 重试
- **凭据嗅探**：从 localStorage / 请求头 / JS bundle 抓取 API Key → 直连绕过 Cookie

### OpenAI 直连（`--openai`）

```
API Key 环境变量注入 → OpenAICompatible generator → garak 扫描
```

## 扫描档位

| 档位 | 探针范围 | Buff | 耗时 | 场景 |
|------|---------|------|------|------|
| `full` | 全量 93 探针 | 双 Buff | 最长 | 完整安全评估 |
| `balanced` | T1+T2 | 单 Buff | 中等 | 默认，覆盖高危面 |
| `quick` | 仅 T1 | 无 | 快 | 快速验证 |
| `smoke` | 3 探针 | 无 | 最快 | 端到端冒烟测试 |

## 自适应速率控制

- **慢启动**：初始并发=4，每 30s 倍增至目标并发
- **请求抖动**：0.05~0.30s 随机延迟，打破时间指纹
- **429 退避**：并发降 50%，抖动扩大 1.5 倍
- **渐进恢复**：60s 无 429 → 并发 +4，抖动缩小 0.8 倍
- **熔断**：连续失败 5 次 → 冷却 30s

## 产物

```
outputs/
├── 01_recon/           # 侦察产物
│   ├── target_profile_{run_id}.json
│   ├── probe_candidates_filtered_{run_id}.json
│   ├── connectivity_test_{run_id}.json
│   └── defense_profile_{run_id}.json      # WAF/防御探测
├── 02_config/          # 武器化配置
│   ├── probe_selection_{run_id}.json
│   └── run_spec_{run_id}.yaml
├── 03_execution/       # 攻击执行
│   ├── garak_report_{run_id}.jsonl
│   └── judge_results_{run_id}.jsonl       # LLM-as-Judge
├── 04_analysis/        # 战果分析
│   ├── analysis_{run_id}.json
│   ├── hitlog_{run_id}.md
│   └── cross_target_{run_id}.json         # 跨目标关联
└── 05_export/          # 红队交付
    ├── report_{run_id}.html
    ├── pyrit_air_{run_id}.json
    ├── avid_{run_id}.json
    ├── sarif_{run_id}.json
    ├── compliance_{run_id}.json           # 合规映射
    └── ioa_rules_{run_id}.json            # IOA 检测规则
```

## 配置文件

| 文件 | 说明 |
|------|------|
| `.env` | 环境变量（目标 URL、凭据、Judge、atkgen） |
| `config/web_target.yaml` | Web 认证目标配置 |
| `config/web_target_list.yaml` | 多页面批量扫描配置 |
| `config/openai_target.yaml` | OpenAI 直连目标配置 |

## 开发规则

详见 `.assistant_garak/rules.md`，核心要点：

- **R1**：garak 原生框架优先，禁止修改 garak 源码
- **R2**：offsec 红队视角，kill chain 全阶段覆盖
- **R3**：代码改动后自动全量测试（ruff + pytest）
- **R4**：优化须先出 L5 差距分析再改码
- **R5**：工程规范（main.py 纯编排、logging、类型注解、pycache 清理）

## 测试

```bash
python -m pytest tests/ -v          # 全量测试
python -m ruff check pipeline/      # lint 检查
```

当前覆盖：291 passed, 0 failed

## 目录结构

```
garak-pipeline/
├── main.py                          # 入口（纯编排）
├── .env                             # 环境变量配置
├── config/                          # 配置文件
│   ├── web_target.yaml              # Web 认证目标
│   ├── web_target_list.yaml         # 多页面批量扫描
│   └── openai_target.yaml           # OpenAI 直连目标
├── pipeline/                        # 核心模块
│   ├── runner.py                    # 5 阶段编排器
│   ├── stage1_recon.py              # 侦察
│   ├── stage2_configure.py          # 配置
│   ├── stage3_execute.py            # 攻击执行
│   ├── stage4_analyze.py            # 分析
│   ├── stage5_report.py             # 报告
│   ├── recon_garak.py               # 探针枚举 + OWASP 分类
│   ├── adaptive_rate.py             # 自适应速率控制
│   ├── adaptive_payload.py          # 实时防御规避
│   ├── batch_runner.py              # 多目标批量扫描
│   ├── cross_target.py              # 跨目标关联分析
│   ├── compliance_map.py            # 合规框架映射
│   ├── scheduler.py                 # 定时调度
│   ├── dashboard.py                 # Web UI 看板
│   ├── auth/                        # 认证模块
│   │   ├── bootstrap.py             # Playwright 半自动登录
│   │   ├── model_probe.py           # 端点嗅探
│   │   ├── multi_page.py            # 多页面发现
│   │   ├── defense_probe.py         # WAF 前置探测
│   │   ├── session_refresh.py       # 会话刷新
│   │   ├── cookie_session.py        # Cookie 管理
│   │   ├── provider.py              # 认证工厂
│   │   └── selectors.py             # DOM 选择器
│   └── custom_probes/               # 自研探针
│       ├── agent_injection.py       # Multi-agent 攻击（6 探针）
│       ├── asi07_inter_agent.py     # Inter-agent 劫持
│       ├── asi08_cascading.py       # 级联失败
│       ├── mcp_abuse.py             # MCP 工具滥用
│       ├── llm03_training_data.py   # 训练数据投毒
│       ├── llm07_plugin_design.py   # 插件设计缺陷
│       └── llm08_vector_embedding.py # 向量嵌入弱点
├── tests/                           # 测试（291 passed）
├── outputs/                         # 产物
├── sessions/                        # Cookie 会话
└── data/                            # 本地数据资产
```
