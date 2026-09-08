# MCPSec + PyRIT 集成架构图

**MCPSec Version**: v2.7.2 (2026-09-08)
**PyRIT Version**: Latest compatible
**License**: MIT (both)

---

## 系统架构总览

```
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                           MCPSec + PyRIT Unified Attack Platform                         │
├─────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                          │
│  ┌─────────────────────────────────────────────────────────────────────────────────�    │
│  │                          MCP Orchestrator (编排层)                                │    │
│  │                                                                                  │    │
│  │   Phase 1          Phase 2          Phase 3          Phase 4                     │    │
│  │   RECON    ──→     SCAN    ──→     SEED    ──→     ATTACK                       │    │
│  │   ┌─────�          ┌─────┐          ┌─────┐          ┌─────�                     │    │
│  │   │enum │          │vuln │          │fuzz │          │PyRIT│                     │    │
│  │   └─────�          └─────┘          └─────�          └─────┘                     │    │
│  │      │                │                │                │                         │    │
│  │      ▼                ▼                ▼                ▼                         │    │
│  │   ┌──────────────────────────────────────────────────────────────────────┐      │    │
│  │   │                    Attack Report (统一报告)                             │      │    │
│  │   │  Vulnerabilities + ASR + Side-effects + Recommendations                │      │    │
│  │   └──────────────────────────────────────────────────────────────────────┘      │    │
│  └─────────────────────────────────────────────────────────────────────────────────┘    │
│                                          │                                               │
│           ┌──────────────────────────────�──────────────────────────────┐               │
│           │                              │                              │               │
│           ▼                              ▼                              ▼               │
│  �────────────────�           ┌────────────────┐           ┌────────────────┐          │
│  │  MCPSec CLI    │           │  PyRIT Core    │           │  Malicious MCP │          │
│  │  (侦察/扫描)    │           │  (攻击执行)     │           │  Server (验证) │          │
│  └────────────────┘           └────────────────�           └────────────────┘          │
│                                                                                          │
└─────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 详细组件架构

```
�──────────────────────────────────────────────────────────────────────────────────────────┐
│                               MCP Orchestrator Pipeline                                   │
├──────────────────────────────────────────────────────────────────────────────────────────�
│                                                                                           │
│  �─────────────────────────────────────────────────────────────────────────────────────� │
│  │                              Phase 1: RECON (侦察)                                   │ │
│  │                                                                                      │ │
│  │    MCPSecBridge.enumerate_surface()                                                  │ │
│  │         │                                                                            │ │
│  │         ├──→ mcpsec info --http://target/mcp                                         │ │
│  │         │    ├── tools/list     → 获取工具描述 (JSON Schema)                         │ │
│  │         │    ├── resources/list → 获取资源列表                                       │ │
│  │         │    ├── prompts/list   → 获取提示列表                                       │ │
│  │         │    └── initialize     → 获取服务器信息 (名称/版本/协议)                    │ │
│  │         │                                                                            │ │
│  │         └──→ Output: AttackSurface {tools[], resources[], prompts[], server_info}    │ │
│  └─────────────────────────────────────────────────────────────────────────────────────� │
│                                           │                                               │
│                                           ▼                                               │
│  ┌─────────────────────────────────────────────────────────────────────────────────────┐ │
│  │                              Phase 2: SCAN (扫描)                                    │ │
│  │                                                                                      │ │
│  │    MCPSecBridge.scan_target()                                                        │ │
│  │         │                                                                            │ │
│  │         ├──→ mcpsec scan --http://target/mcp --intensity high                       │ │
│  │         │    ├── prompt-injection scanner (检测工具描述中的注入)                     │ │
│  │         │    ├── command-injection scanner (CMDi payload检测)                        │ │
│  │         │    ├── path-traversal scanner (路径穿越检测)                               │ │
│  │         │    ├── ssrf scanner (SSRF漏洞检测)                                         │ │
│  │         │    ├── sql scanner (SQL注入/DB指纹)                                        │ │
│  │         │    ├── auth-audit scanner (认证缺失检测)                                   │ │
│  │         │    ├── chains scanner (危险工具组合检测)                                   │ │
│  │         │    └── ... (16 scanners total)                                             │ │
│  │         │                                                                            │ │
│  │         └──→ Output: List[MCPSecScanResult] (漏洞证据+payload)                       │ │
│  └─────────────────────────────────────────────────────────────────────────────────────� │
│                                           │                                               │
│                                           ▼                                               │
│  �─────────────────────────────────────────────────────────────────────────────────────� │
│  │                           Phase 3: SEED (种子生成)                                    │ │
│  │                                                                                      │ │
│  │    dynamic_mcp_seeds.generate_dynamic_seeds()                                        │ │
│  │         │                                                                            │ │
│  │         ├──→ Path A: MCPSec Fuzz → Seeds (首选)                                     │ │
│  │         │    ├── mcpsec fuzz --http://target/mcp --intensity high                   │ │
│  │         │    ├── 解析 800+ fuzz cases → Seed列表                                     │ │
│  │         │    └── 过滤高价值payload (Critical/High优先)                               │ │
│  │         │                                                                            │ │
│  │         ├──→ Path B: Tool-specific Seeds (工具特定)                                  │ │
│  │         │    ├── 基于工具名/描述/schema生成针对性payload                              │ │
│  │         │    ├── path/file参数 → 路径穿越payload                                     │ │
│  │         │    └── query/url参数 → 注入payload                                         │ │
│  │         │                                                                            │ │
│  │         ├──→ Path C: Static Fallback (离线回退)                                      │ │
│  │         │    └── 使用内置静态种子模板 (SkeletonKey + MCP patterns)                    │ │
│  │         │                                                                            │ │
│  │         └──→ Output: SeedDataset (PyRIT兼容格式)                                     │ │
│  └─────────────────────────────────────────────────────────────────────────────────────┘ │
│                                           │                                               │
│                                           ▼                                               │
│  ┌─────────────────────────────────────────────────────────────────────────────────────┐ │
│  │                           Phase 4: ATTACK (攻击执行)                                  │ │
│  │                                                                                      │ │
│  │    MCPOrchestrator._phase_attack()                                                   │ │
│  │         │                                                                            │ │
│  │         ├──→ PyRIT PromptSendingAttack (单轮基线)                                     │ │
│  │         │    ├── 每个seed绑定FIRST_SUCCESS scorer (0 LLM调用)                         │ │
│  │         │    ├── 并发度: Semaphore(2) 或自适应计算                                      │ │
│  │         │    └── ASR = success / total                                               │ │
│  │         │                                                                            │ │
│  │         ├──→ PyRIT SkeletonKeyAttack (前缀注入)                                       │ │
│  │         │    ├── System Override模式 → 降低安全过滤器                                  │ │
│  │         │    ├── arXiv:2406.18112 - ASR 80-95%                                       │ │
│  │         │    └── 作为PromptSendingAttack的prepended_conversation                      │ │
│  │         │                                                                            │ │
│  │         ├──→ PyRIT CrescendoAttack (渐进升级) [可选]                                  │ │
│  │         │    ├── 多轮对话逐步升级攻击强度                                               │ │
│  │         │    ├── arXiv:2404.01833 - ASR 65%                                           │ │
│  │         │    └── max_turns=10, max_backtracks=5                                      │ │
│  │         │                                                                            │ │
│  │         └──→ Output: Dict[str, List[AttackResult]]                                   │ │
│  │              (按技术分类的攻击结果)                                                      │ │
│  └─────────────────────────────────────────────────────────────────────────────────────� │
│                                           │                                               │
│                                           ▼                                               │
│  �─────────────────────────────────────────────────────────────────────────────────────� │
│  │                           Phase 5: VERIFY (效果验证)                                   │ │
│  │                                                                                      │ │
│  │    基于客观side-effect的attack success验证                                              │ │
│  │         │                                                                            │ │
│  │         ├──→ MCPAgentTarget.side_effects[]                                           │ │
│  │         │    ├── file_read → 攻击是否触发了文件读取?                                   │ │
│  │         │    ├── network_request → 攻击是否触发了外联请求?                              │ │
│  │         │    ├── command_exec → 攻击是否执行了系统命令?                                │ │
│  │         │    └── env_read → 攻击是否读取了环境变量?                                    │ │
│  │         │                                                                            │ │
│  │         ├──→ MaliciousMCPServer.side_effects[]                                       │ │
│  │         │    └── 恶意MCP Server记录的工具调用 = 攻击成功证据                             │ │
│  │         │                                                                            │ │
│  │         └──→ Ground Truth Analysis                                                   │ │
│  │              ├── True Positive: 有side-effect + response无拒绝                         │ │
│  │              ├── False Positive: response有拒绝 + 无side-effect                        │ │
│  │              └── False Negative: 有side-effect + response模糊                          │ │
│  └─────────────────────────────────────────────────────────────────────────────────────� │
│                                           │                                               │
│                                           ▼                                               │
│  �─────────────────────────────────────────────────────────────────────────────────────� │
│  │                           Phase 6: REPORT (报告生成)                                   │ │
│  │                                                                                      │ │
│  │    MCPAttackReport                                                                   │ │
│  │         │                                                                            │ │
│  │         ├──→ Vulnerabilities (MCPSec发现)                                             │ │
│  │         │    ├── Critical/High/Medium/Low/Info 分级                                   │ │
│  │         │    ├── Scanner Coverage (16 scanners)                                       │ │
│  │         │    └── Evidence + Payload                                                   │ │
│  │         │                                                                            │ │
│  │         ├──→ Attack Results (PyRIT执行)                                               │ │
│  │         │    ├── ASR_final (Overall Attack Success Rate)                              │ │
│  │         │    ├── Per-technique breakdown (PromptSending/SkeletonKey/Crescendo)         │ │
│  │         │    └── Seed execution statistics                                            │ │
│  │         │                                                                            │ │
│  │         ├──→ Side-effects (Ground Truth)                                              │ │
│  │         │    ├── Objective evidence of attack impact                                  │ │
│  │         │    └── Remediation priority                                                 │ │
│  │         │                                                                            │ │
│  │         └──→ Recommendations                                                         │ │
│  │              ├── 针对性修复建议                                                        │ │
│  │              └── OWASP/MITRE ATLAS映射                                                 │ │
│  └─────────────────────────────────────────────────────────────────────────────────────┘ │
│                                                                                           │
└───────────────────────────────────────────────────────────────────────────────────────────�
```

---

## MCPSec + PyRIT 攻击流

```
┌──────────────────────────────────────────────────────────────────────────────────────────┐
│                                    Attack Execution Flow                                 │
├──────────────────────────────────────────────────────────────────────────────────────────�
│                                                                                           │
│                        ┌─────────────────────────────────────┐                          │
│                        │          Target MCP Server           │                          │
│                        │     (http://target:8080/mcp)         │                          │
│                        └─────────────────�───────────────────┘                          │
│                                          │                                               │
│            ┌─────────────────────────────┼─────────────────────────────�                │
│            │                             │                             │                │
│            ▼                             ▼                             ▼                │
│   ┌────────────────�          �────────────────┐          ┌────────────────┐          │
│   │   MCPSec CLI   │          │   MCPSec CLI   │          │   MCPSec CLI   │          │
│   │  (Recon)       │          │  (Scan)        │          │  (Audit)       │          │
│   ├────────────────┤          ├────────────────�          ├────────────────┤          │
│   │ mcpsec info    │          │ mcpsec scan    │          │ mcpsec audit   │          │
│   │ mcpsec enum    │          │ --intensity    │          │ --ai           │          │
│   │                │          │ --scanners     │          │                │          │
│   └───────┬────────┘          └───────�────────┘          └───────┬────────┘          │
│           │                           │                           │                    │
│           ▼                           ▼                           ▼                    │
│   ┌─────────────────────────────────────────────────────────────────────────────�      │
│   │                        PyRIT Orchestrator Layer                              │      │
│   │  ┌───────────────────────────────────────────────────────────────────────┐  │      │
│   │  │                         Converter Pipeline                            │  │      │
│   │  │  ┌─────────────┐   ┌─────────────┐   ┌─────────────┐   ┌──────────┐ │  │      │
│   │  │  │ Variation   │ → │ Unicode     │ → │ Translation │ → │ Newline  │ │  │      │
│   │  │  │ Converter   │   │ Encoder     │   │ Converter   │   │ Insert  │ │  │      │
│   │  │  └─────────────┘   └─────────────┘   └─────────────┘   └──────────� │  │      │
│   │  └───────────────────────────────────────────────────────────────────────�  │      │
│   │                                        │                                      │      │
│   │  ┌─────────────────────────────────────┼─────────────────────────────────┐  │      │
│   │  │                   Attack Strategies │                                 │  │      │
│   │  │  ┌────────────────�  �────────────────┐  ┌────────────────┐          │  │      │
│   │  │  │  Option A      │  │  Option B      │  │  Option C      │          │  │      │
│   │  │  │  Direct LLM    │  │  MCP Agent     │  │  Pyramid       │          │  │      │
│   │  │  │  Target        │  │  Target        │  │  Attack        │          │  │      │
│   │  │  │                │  │                │  │                │          │  │      │
│   │  │  │  send_prompt() │  │  send_prompt() │  │  �──────────� │          │  │      │
│   │  │  │       ↓        │  │       ↓        │  │  │ LLM      │ │          │  │      │
│   │  │  │  LLM Response  │  │  Agent → MCP   │  │  │ Agent    │ │          │  │      │
│   │  │  │                │  │  Tool Call     │  │  │  ↓       │ │          │  │      │
│   │  │  │  Best for:     │  │       ↓        │  │  │ MCP Tool │ │          │  │      │
│   │  │  │  - API密钥泄露 │  │  MCP Response  │  │  │  ↓       │ │          │  │      │
│   │  │  │  - 间接注入   │  │       ↓        │  │  │ Side     │ │          │  │      │
│   │  │  │  - 越权测试   │  │  Agent Response│  │  │ Effect   │ │          │  │      │
│   │  │  │                │  │                │  │  └──────────┘ │          │  │      │
│   │  │  └────────────────┘  └────────────────┘  └────────────────┘          │  │      │
│   │  └──────────────────────────────────────────────────────────────────────�  │      │
│   │                                        │                                      │      │
│   │  ┌─────────────────────────────────────┴─────────────────────────────────┐  │      │
│   │  │                            Scoring Layer                               │  │      │
│   │  │                                                                        │  │      │
│   │  │  ┌──────────────────────────────────────────────────────────────────┐ │  │      │
│   │  │  │                   FIRST_SUCCESS Scorer (T0)                       │ │  │      │
│   │  │  │                                                                    │ │  │      │
│   │  │  │  _MultiKeywordRefusalScorer (30+ 拒绝模式)                         │ │  │      │
│   │  │  │       │                                                            │ │  │      │
│   │  │  │       ├──→ Refusal detected → score=True → Inverter → False      │ │  │      │
│   │  │  │       ├──→ No refusal → score=False → Inverter → True (成功)     │ │  │      │
│   │  │  │       │                                                            │ │  │      │
│   │  │  │       └──→ Short response (<50 chars) → Refusal=True             │ │  │      │
│   │  │  │                                                                    │ │  │      │
│   │  │  │  0 LLM calls, <1ms latency → FIRST SUCCESS (Stop on first)       │ │  │      │
│   │  │  └──────────────────────────────────────────────────────────────────� │  │      │
│   │  │                                                                        │  │      │
│   │  │  ┌──────────────────────────────────────────────────────────────────� │  │      │
│   │  │  │              Dual Judge Scorer (T1 - 可选加强)                     │ │  │      │
│   │  │  │                                                                    │ │  │      │
│   │  │  │  assess.judge_manager (Heuristic + LLM Judge)                     │ │  │      │
│   │  │  │       │                                                            │ │  │      │
│   │  │  │       ├──→ Cohen's Kappa agreement                                │ │  │      │
│   │  │  │       └──→ Arbiter (当双Judge不一致时)                             │ │  │      │
│   │  │  └──────────────────────────────────────────────────────────────────┘ │  │      │
│   │  └────────────────────────────────────────────────────────────────────────┘  │      │
│   └─────────────────────────────────────────────────────────────────────────────�      │
│                                          │                                               │
│                                          ▼                                               │
│   ┌─────────────────────────────────────────────────────────────────────────────┐      │
│   │                           Result Aggregation                                 │      │
│   │                                                                              │      │
│   │   AttackReport {                                                             │      │
│   │       asr: float                          // 最终攻击成功率                  │      │
│   │       vulnerabilities: List[Vuln],        // MCPSec发现                     │      │
│   │       attack_results: Map<String, List>,  // PyRIT按技术分                  │      │
│   │       side_effects: List[SideEffect],     // 客观验证                       │      │
│   │       recommendations: List[str]          // 修复建议                       │      │
│   │   }                                                                          │      │
│   └─────────────────────────────────────────────────────────────────────────────┘      │
│                                                                                           │
└───────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## MCPSec Tool Integration Points

```
┌──────────────────────────────────────────────────────────────────────────────────────────�
│                              MCPSec v2.7.2 Tool Map                                     │
├──────────────────────────────────────────────────────────────────────────────────────────�
│                                                                                           │
│  ┌────────────────────────────────────────────────────────────────────────────────────�  │
│  │                                    RECON LAYER                                     │  │
│  │                                                                                    │  │
│  │   mcpsec info    ──→  MCPSecBridge.enumerate_surface()  ──→  tools/resources/prompts│  │
│  │   mcpsec enum    ──→  MCPSecBridge.enumerate_surface()  ──→  attack surface map     │  │
│  │                                                                                    │  │
│  │   Output: {                                                                        │  │
│  │     tools: [{name, description, inputSchema, annotations}],                         │  │
│  │     resources: [{uri, name, description}],                                          │  │
│  │     prompts: [{name, description}],                                                 │  │
│  │     serverInfo: {name, version, protocolVersion}                                    │  │
│  │   }                                                                                │  │
│  └────────────────────────────────────────────────────────────────────────────────────┘  │
│                                          │                                               │
│                                          ▼                                               │
│  ┌────────────────────────────────────────────────────────────────────────────────────�  │
│  │                                    SCAN LAYER                                      │  │
│  │                                                                                    │  │
│  │   mcpsec scan    ──→  MCPSecBridge.scan_target()        ──→  vulnerabilities       │  │
│  │                                                                                    │  │
│  │   16 Scanners:                                                                     │  │
│  │   ├── prompt-injection         (工具描述中的Prompt注入)                              │  │
│  │   ├── command-injection        (138 payloads)                                      │  │
│  │   ├── path-traversal           (104 payloads)                                      │  │
│  │   ├── ssrf                     (81 payloads)                                       │  │
│  │   ├── sql                       (Error/Time/Boolean/Stacked + DB指纹)              │  │
│  │   ├── auth-audit                (认证缺失 + 危险组合)                                │  │
│  │   ├── description-prompt-injection  (LLM操纵 via descriptions)                     │  │
│  │   ├── resource-ssrf             (SSRF via MCP资源URI)                                │  │
│  │   ├── capability-escalation     (未声明能力滥用)                                     │  │
│  │   ├── chains                    (危险工具组合检测)                                   │  │
│  │   ├── code-execution            (eval/exec/compile sinks)                           │  │
│  │   ├── template-injection        (SSTI/markdown)                                     │  │
│  │   ├── rag-poisoning             (Write→Read数据流检测)                               │  │
│  │   ├── idor                      (不安全的直接对象引用)                               │  │
│  │   ├── info-leak                 (环境变量/凭证泄露)                                  │  │
│  │   └── deserialization           (Pickle/YAML/XXE)                                   │  │
│  └────────────────────────────────────────────────────────────────────────────────────┘  │
│                                          │                                               │
│                                          ▼                                               │
│  �────────────────────────────────────────────────────────────────────────────────────�  │
│  │                                    FUZZ LAYER                                      │  │
│  │                                                                                    │  │
│  │   mcpsec fuzz    ──→  MCPSecBridge.fuzz_target()        ──→  dynamic seeds        │  │
│  │                                                                                    │  │
│  │   22 Fuzz Generators:                                                              │  │
│  │   ├── Low (~65):     malformed_json, protocol_violation, type_confusion,           │  │
│  │   │                  boundary_testing, unicode_attacks                               │  │
│  │   ├── Medium (~200): + session_attacks, encoding_attacks, integer_boundaries       │  │
│  │   ├── High (~800):   + injection_payloads, method_mutations, param_mutations,      │  │
│  │   │                  timing_attacks, header_mutations, json_edge_cases,             │  │
│  │   │                  protocol_state, id_confusion, concurrency_attacks,             │  │
│  │   │                  regex_dos, deserialization                                    │  │
│  │   └── Insane (~1500+): + resource_exhaustion, memory_exhaustion                    │  │
│  └────────────────────────────────────────────────────────────────────────────────────┘  │
│                                          │                                               │
│                                          ▼                                               │
│  ┌────────────────────────────────────────────────────────────────────────────────────┐  │
│  │                                    AUDIT LAYER                                     │  │
│  │                                                                                    │  │
│  │   mcpsec audit   ──→  MCPSecBridge.audit_source()       ──→  static analysis      │  │
│  │                                                                                    │  │
│  │   7-Stage Pipeline:                                                                │  │
│  │   ├── Stage 1: Fetch        (GitHub clone / local path)                            │  │
│  │   ├── Stage 2: Detect       (Language, MCP SDK, Framework)                         │  │
│  │   ├── Stage 3: Sink Scan    (3,450+ patterns, 12 languages)                        │  │
│  │   ├── Stage 4: Semgrep      (149 AST rules)                                        │  │
│  │   ├── Stage 5: AST          (Python/JS taint flow)                                 │  │
│  │   ├── Stage 6: Reachability (LLM taint tracing)                                    │  │
│  │   └── Stage 7: Deduplicate  (Merge, rank, report)                                  │  │
│  └────────────────────────────────────────────────────────────────────────────────────┘  │
│                                          │                                               │
│                                          ▼                                               │
│  �────────────────────────────────────────────────────────────────────────────────────�  │
│  │                                   SUPPORT TOOLS                                   │  │
│  │                                                                                    │  │
│  │   mcpsec chains       ──→  MCPSecBridge.check_tool_chains()  ──→  危险组合报告     │  │
│  │   mcpsec sql          ──→  SQLi scanner w/ DB fingerprinting                      │  │
│  │   mcpsec exploit      ──→  Interactive exploitation REPL                          │  │
│  │   mcpsec rogue-server ──→  MaliciousMCPServer (本地替代)                          │  │
│  └────────────────────────────────────────────────────────────────────────────────────┘  │
│                                                                                           │
└───────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 数据流与API交互

```
┌──────────────────────────────────────────────────────────────────────────────────────────�
│                                  API Interaction Flow                                     │
├──────────────────────────────────────────────────────────────────────────────────────────�
│                                                                                           │
│    call                        │ strike/                  │                              │
│    │                           │ mcpsec_bridge.py         │                              │
│    │                           │                          │                              │
│    ├─→ scan_target() ─────────├─→ _run_mcpsec() ─────────�──→ subprocess → `mcpsec scan` │
│    │   Returns: List[]        │   Parses JSON output     │    ├── 16 scanners           │
│    │                           │                          │    └── vulnerabilities.json  │
│    │                           │                          │                              │
│    ├─→ fuzz_target() ────────├─→ _run_mcpsec() ─────────┼──→ subprocess → `mcpsec fuzz` │
│    │   Returns: List[]        │   Parses JSON output     │    ├── 22 generators         │
│    │                           │                          │    └── findings.json          │
│    │                           │                          │                              │
│    ├─→ enumerate_surface() ──├─→ _run_mcpsec() ─────────┼──→ subprocess → `mcpsec info` │
│    │   Returns: Dict          │   Parses JSON output     │    └── server_info.json       │
│    │                           │                          │                              │
│    ├─→ audit_source() ───────├─→ _run_mcpsec() ─────────�──→ subprocess → `mcpsec audit`│
│    │   Returns: Dict          │   Parses SARIF/JSON       │    └── audit_results.json     │
│    │                           │                          │                              │
│    └─→ check_tool_chains() ──├─→ _run_mcpsec() ─────────┼──→ subprocess → `mcpsec chain`│
│        Returns: List[]        │   Parses JSON output     │    └── chains.json            │
│                                │                          │                              │
│   ─────────────────────────────────────────────────────────────────────────────────────   │
│                                                                                           │
│    PyRIT ←────────────→ MCPSec Integration:                                               │
│                                                                                           │
│    MCPSecBridge                                                                          │
│         │                                                                                │
│         ├─→ generate_attack_seeds() ──→ List[dict] (PyRIT SeedPrompt format)             │
│         │                                                                                │
│         │    StrikeDataset.from_yaml() ──→ SeedDataset                                    │
│         │         │                                                                      │
│         │         └─→ executor.execute_attack_async()                                     │
│         │                                                                                │
│         └─→ scan_target() → vulnerabilities → arm/converter_selector (技术选择增强)       │
│                                                                                           │
│                                                                                           │
│    MCPAgentTarget ←─────→ PyRIT Native:                                                   │
│                                                                                           │
│    MCPAgentTarget.send_prompt_async()                                                     │
│         │                                                                                │
│         ├─→ objective_target.send_prompt_async()  (HTTP forwarding)                      │
│         │                                                                                │
│         └─→ Records side_effects[] → MCPSecBridge verification                           │
│                                                                                           │
│                                                                                           │
│    MaliciousMCPServer ←──→ Client-Side Testing:                                          │
│                                                                                           │
│    Agent (client) ──→ MaliciousMCPServer                                                 │
│         │                                                                                │
│         ├─→ list_tools() → poisoned descriptions                                        │
│         │                                                                                │
│         └─→ call_tool() → records SideEffectRecord                                       │
│                            → ground truth for attack verification                        │
│                                                                                           │
└───────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 模块依赖关系

```
┌──────────────────────────────────────────────────────────────────────────────────────────┐
│                                   Module Dependencies                                    │
├──────────────────────────────────────────────────────────────────────────────────────────�
│                                                                                           │
│                             ┌─────────────────────────────┐                             │
│                             │     mcpsec_orchestrator     │                             │
│                             │     (编排层 - 入口点)        │                             │
│                             └─────────────�───────────────┘                             │
│                                           │                                              │
│              ┌────────────────────────────┼────────────────────────────�                │
│              │                            │                            │                │
│              ▼                            ▼                            ▼                │
│   ┌──────────────────┐      ┌──────────────────┐      ┌──────────────────┐            │
│   │  mcpsec_bridge   │      │dynamic_mcp_seeds │      │ malicious_mcp_   │            │
│   │  (CLI桥接)       │      │ (动态种子)       │      │ server (恶意服务) │            │
│   └────────┬─────────�      └────────┬─────────┘      └────────┬─────────┘            │
│            │                         │                         │                         │
│            │                         │                         │                         │
│            ▼                         │                         │                         │
│   ┌──────────────────┐               │                         │                         │
│   │   mcpsec CLI     │               │                         │                         │
│   │   (外部依赖)      │               │                         │                         │
│   │   v2.7.2 PyPI    │               │                         │                         │
│   └──────────────────┘               │                         │                         │
│                                      │                         │                         │
│   ┌──────────────────┐               │                         │                         │
│   │ mcp_agent_target │◄──────────────┘                         │                         │
│   │ (PyRIT Target)   │    (使用生成的seeds)                     │                         │
│   └────────�─────────┘                                         │                         │
│            │                                                    │                         │
│            │                                                    │                         │
│            ▼                                                    │                         │
│   �──────────────────�                                         │                         │
│   │   PyRIT Core     │                                         │                         │
│   │ (AttackExecutor, │                                         │                         │
│   │  PromptSending,  │                                         │                         │
│   │  ScoringConfig)  │                                         │                         │
│   └──────────────────┘                                         │                         │
│                                                                │                         │
│   ┌──────────────────────────────────────────────────────────┐ │                         │
│   │                    Existing Infrastructure                │ │                         │
│   │  strike/executor.py  │  strike/_scoring.py               │ │                         │
│   │  arm/converter_*.py  │  assess/judge_*.py                 │ │                         │
│   └──────────────────────────────────────────────────────────┘ │                         │
│                                                                                           │
└───────────────────────────────────────────────────────────────────────────────────────────�
```

---

## 实施状态

| 模块 | 状态 | 行数 | 说明 |
|------|------|------|------|
| `mcp_agent_target.py` | ✅ 完成 | ~280 | PyRIT MCP Target实现 |
| `malicious_mcp_server.py` | ✅ 完成 | ~350 | 恶意MCP服务器 |
| `mcpsec_bridge.py` | ✅ 完成 | ~450 | MCPSec CLI桥接 |
| `mcpsec_orchestrator.py` | ✅ 完成 | ~380 | 编排流水线 |
| `dynamic_mcp_seeds.py` | ✅ 完成 | ~250 | 动态种子生成 |
| `strike/__init__.py` | ✅ 更新 | - | 导出新模块 |
| **总计** | | **~1,710行** | 替换原~2,200行自研代码 |

**代码质量**:
- ✅ 所有新模块通过 `py_compile` 语法验证
- ✅ MCPSec v2.7.2 已安装并验证可用
- ✅ 兼容现有PyRIT AttackExecutor和ScoringConfig
- ✅ 向后兼容静态种子文件（fallback模式）
- ✅ 惰性导入避免硬依赖

---

## 与原自研代码对比

| 能力 | 原自研代码 | MCPSec集成后 | 提升 |
|------|-----------|-------------|------|
| JSON-RPC协议 | 300行手写 | CLI调用 | -95%代码 |
| 工具枚举 | 200行手写 | mcpsec info | -95%代码 |
| 漏洞扫描 | 10条正则 | 16个专用扫描器 | 10x覆盖 |
| Fuzzing | 无 | 800+ cases | 新能力 |
| 静态分析 | 无 | 3450+ patterns | 新能力 |
| 种子生成 | 12静态文件 | 动态生成 | 自适应 |
| 恶意服务器 | 简易模板 | 交互式REPL | 10x能力 |
| 总维护代码 | ~2,200行 | ~1,710行 | -22% |

---

*文档生成: 2026-09-08*
*MCPSec Version: v2.7.2*
*PyRIT Compatible: Latest*
*License: MIT*
