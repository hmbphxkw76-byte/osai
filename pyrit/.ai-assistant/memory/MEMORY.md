# AI-300 Framework - Long-Term Memory

## 项目概述
基于 PyRIT 0.14.0 的 OffSec AI-300 (OSAI+) 考试全覆盖红队评估框架。
目标：修改 YAML 配置和攻击载荷后，全流程自动化执行并生成专业报告。

**核心技术栈：**
- Python >= 3.10
- PyRIT >= 0.14.0（核心攻击引擎）
- PyYAML >= 6.0
- Rich >= 13.0.0（终端输出）
- pydantic >= 2.0.0

---

## 关键规则

### Windows 编码（强制）
- 所有 Python 脚本必须在入口处强制 UTF-8（sys.stdout.reconfigure + PYTHONIOENCODING）
- Rich Console 在 Windows 默认使用 GBK，不设置会报 `UnicodeEncodeError`

### PyRIT 组件使用
- `ROT13Converter`（非 Rot13Converter）
- `SearchReplaceConverter(pattern=, replace=)`（非 old_value/new_value）
- YAML 含多文档分隔符 `---` 时用 `yaml.safe_load_all()`

### 死代码清理（强制）
- 每次代码调整/优化后，必须清除所有死代码和未调用代码
- **默认检查工具：`ruff`**
  - `ruff check pyrit_ai300/ --select F,I,E,W` — 未使用导入/变量 + 风格
  - `ruff check pyrit_ai300/ --select F401,F841` — 仅死代码检测
  - `ruff check pyrit_ai300/ --fix` — 自动修复可修复项

---

## 架构设计原则

### 核心原则（ARCH-001）
- **调度器 + 格式转换器**：框架只做编排+格式转换，能力来自 PyRIT + 外部工具
- **三层分离**：数据层（data/）+ 配置层（config/）+ 引擎层（pyrit_ai300/）
- **侦察-攻击解耦**：两者通过 TargetProfile JSON 文件通信，不互相 import
- **数据驱动**：修改 YAML 配置和载荷后，全流程自动化
- **考试对齐**：覆盖 AI-300 全部 Module + OWASP LLM/Agentic Top 10

### 组件映射集中管理
- `component_registry.py`：CONVERTER_MAP (39个转换器) / SCORER_MAP (12个评分器)
- `attack_registry.py`：ATTACK_REGISTRY (攻击注册表)

### v3.0 执行层原则
- SmartMatcher 只负责选择 PyRIT 攻击策略，执行全部交给 PyRIT 原生攻击
- 模块独立：reconnaissance/ 不 import attack/，通过 TargetProfile JSON 通信

---

## 核心模块架构

### 1. CLI 入口 (`pyrit_ai300/cli.py`)
- 命令：`ai300 owasp` / `ai300 recon` / `ai300 list` / `ai300 report` / `ai300 pipeline`
- `pipeline` 命令（v3.7）：全链路一键执行（凭据→侦察→攻击→报告）
- 专家引导向导（无子命令时自动启动）

### 2. 主引擎 (`pyrit_ai300/__init__.py` → AI300Engine)
- 整合所有组件
- 支持 target_file / target_url / target_dir 多目标模式
- 支持 --auto-recon 自动侦察

### 3. 攻击编排器 (`orchestrators/attack_orchestrator.py`)
- `AttackOrchestrator`：PyRIT 原生攻击执行器
- 三种模式：smart_match / presets / chain
- ASI 自动选择评分器（_ASI_SCORER_MAP）
- Fallback 链：主策略失败时自动尝试备选
- **模板渲染系统**：14种编码变体占位符（base64/rot13/bidi/zalgo 等）

### 4. 智能匹配器 (`orchestrators/smart_matcher.py`)
- **两层策略选择**：快速规则筛选 → 精确模型匹配
- **攻击探针族**：DIRECT_SINGLE / PROGRESSIVE / TREE_SEARCH / ITERATIVE / EXPLORATORY
- Fallback 链：CrescendoAttack → TAP → PAIR → PromptSendingAttack
- ASI 感知策略选择（ASI01-ASI10）
- 运行时模型探测（probe_target_model）

### 5. 智能编码选择器 (`orchestrators/encoding_selector.py`)
- **第1级（静态过滤）**：CONVERTER_OWASP_COMPATIBILITY（39转换器 × OWASP 类别）
- **第2级（语言兼容）**：LANGUAGE_INCOMPATIBLE_CONVERTERS（CJK 排除 rot13/leetspeak 等）
- **第3级（目标自适应）**：TargetProfile 运行时探测编码通过率

### 6. 速率控制器 (`orchestrators/rate_controller.py`) [NEW]
- 并发控制：Semaphore + rate_limit
- 目标类型默认值：ollama=2, openai=5, http=3, playwright=1（强制串行）
- CLI 可覆盖：max_concurrent / rate_limit

### 7. 认证系统 + 凭据管理 (`orchestrators/auth/` + `pipeline/credential_manager.py`) [v3.7]
- `header_parser.py`：解析 Bearer Token / Cookie / 组合认证
- JWT Token 过期时间解析
- `playwright_injector.py`：浏览器认证注入
- **CredentialManager**（v3.6 新增）：统一凭据管理器
  - 跨阶段（认证→侦察→攻击）的凭据发现、验证与注入
  - JWT 过期检查（预留 5 分钟缓冲）
  - 工具适配方法：`for_garak()` / `for_deepteam()` / `for_openai_target()` / `for_http_target()` / `for_playwright()`
  - HTTP 预检验证（`validate_with_http()`，向目标发送带认证的 GET 请求验证有效性）
  - 凭据状态打印（`print_status()`，终端友好格式）
- **凭据自动导出**（v1.3）：`auto_spa_recon.py` 的 `export_credentials()` 函数
  - 认证完成后自动将 Cookie/JWT/API Key 导出到 `config/targets/credentials/{domain}.txt`
  - 格式为 HTTP Request Headers（与 `header_parser.py` 兼容）
  - 来源优先级：localStorage JWT > API 请求头 Authorization > Playwright Cookie
  - 自动过滤跟踪类 Cookie（_ga / _gid / _gat 等）
- **凭据自动发现**（v1.3）：`target_builder.py` 的 `find_credential_file()`
  - 攻击阶段按目标 URL 域名自动匹配 `credentials/{domain}.txt`
  - 优先级：显式 `auth.header_file` > 域名自动发现
- **凭据注入到侦察工具**（v3.7）：
  - Garak：通过 `OPENAI_API_KEY` 环境变量注入 Bearer Token
  - DeepTeam：通过 `base_headers` 请求头注入 Authorization + Cookie
  - PyRIT Target：通过 `api_key` 构造参数注入

### 8. Web 交互 (`orchestrators/interactions/web_chat.py`) [NEW]
- `create_web_chat_interaction(selectors)` 构建 Playwright 交互函数
- 支持自定义选择器：input / send_button / response

### 9. 侦察引擎 (`reconnaissance/recon_engine.py`)
- **适配器**：GarakAdapter / DeepTeamAdapter / ProtocolFingerprintAdapter
- **AIMAP→Garak 顺序侦察**：协议识别 → 端点提取 → 配置 Garak → 执行
- **流式侦察**：`run_streaming()` 生成器，每个工具完成即 yield
- `ProfileMerger`：增量合并 + 冲突检测 + 交叉验证
- **v2 优化（2026-07-19）**：OPT-A1~A6 / OPT-G1~G6 / OPT-D1~D5 / OPT-M1~M2 / OPT-E1~E3（共 19 项）
  - OPT-E1：AIMAP 与 DeepTeam 并行执行（ThreadPoolExecutor(2)）
  - OPT-E2：Profile 级增量缓存（target+depth+tools 哈希，TTL 24h）
  - OPT-E3：深度自适应超时（quick/standard/deep 三级）
  - OPT-A1：协议探测并行化（ThreadPoolExecutor(8)，~30s→~8s）
  - OPT-A2：深度 MCP 探测（权限隔离 + session 固定 + 注入风险）
  - OPT-A3：RAG 端点探测（embeddings / ChromaDB / search / vector DB）
  - OPT-A4：Agent 框架探测（LangGraph / AutoGen / CrewAI / Dify）
  - OPT-A5：认证深度检测（Bearer / API Key / Cookie / OAuth / JWT / 绕过）
  - OPT-A6：模型能力深度探测（function_calling / json_mode / vision / streaming）
  - OPT-G1：Probe 动态选择（基于 AIMAP 结果）
  - OPT-G2：深度分层 Probe（quick=2 / standard=6 / deep=14）
  - OPT-G3：结果解析增强（hitlog + report.html + fail 记录）
  - OPT-G4：Detector 精确配置（PROBE_DETECTOR_MAP）
  - OPT-G5：增量执行缓存（target+model+probe 哈希，TTL 24h）
  - OPT-G6：通用预热（Ollama + vLLM + OpenAI-compat）
  - OPT-D1：攻击类型全量覆盖（quick=2 / standard=11 / deep=18）
  - OPT-D2：Agentic 漏洞覆盖（条件触发 ASI01-04）
  - OPT-D3：model_callback 增强（重试 + 超时自适应 + function_calling）
  - OPT-D4：异步模式（async_mode=True, max_concurrent=3）
  - OPT-D5：攻击方法配置（16 种自动匹配）
  - OPT-M1：语义去重（Jaccard threshold=0.80）
  - OPT-M2：动态攻击建议（模型家族 + 能力 + 攻击面 + 风险等级）
  - Pipeline 追踪：`log_recon_optimization` + `show_recon_optimizations`

### 10. 载荷管理器 (`payloads/payload_manager.py`)
- 从 data/ 目录加载 YAML 载荷
- **OWASP 为唯一真相源**
- 支持 scope 解析（llm01 / asi01 / llm / agentic / all / ref_path）

### 11. 载荷分类器 (`payloads/payload_classifier.py`)
- `analyze_payload()`：五维分析（technique / encoding_state / language / length_class / complexity）
- 置信度评分（technique/encoding/language 三维置信度）
- `normalize_payload()`：多层编码解码（base64 / html_entities / rot13 等）
- 上下文窗口感知（target_model → 自动窗口大小）

### 12. 检测模式 (`payloads/patterns.py`)
- ROLE_PLAY_PATTERNS：角色扮演越狱（含中英文）
- PROMPT_LEAKING_PATTERNS：提示泄露检测
- MARKDOWN_INJECTION_PATTERNS：Markdown/HTML 注入
- INDIRECT_INJECTION_PATTERNS：间接注入（ASI06/ASI07）
- INSTRUCTION_OVERRIDE_PATTERNS：指令覆盖
- PAYLOAD_SPLITTING_PATTERNS：载荷拆分
- ENCODED_PATTERNS：编码特征检测（7种编码）
- ADVERSARIAL_SUFFIX_PATTERN：GCG 风格对抗后缀
- CONTEXT_SPLITTING_PATTERNS：上下文拆分
- DATA_EXFILTRATION_PATTERNS：数据渗出
- CROSS_CONTEXT_CONTAMINATION_PATTERNS：跨上下文污染
- CONTEXT_MANIPULATION_PATTERNS：上下文操纵

### 13. 流水线追踪器 (`pipeline/tracker.py`)
- 全链路记录：recon → load → normalize → dedup → classify → converter_selection → strategy → fallback_enrich → scorer_select → execute → early_stop → scoring → best_combinations → feedback → mutation
- Rich 终端展示 + Markdown 导出（所有阶段统一 `########xxxx########` 格式标题）
- 编码选择三阶段追踪：owasp_filter → language_filter → probe → selection
- **P0-P3 优化阶段追踪**（v3.1+）：
  - `log_dedup` (P3-J)：载荷去重追踪
  - `log_converter_selection` (P0-A)：逐载荷转换器选择追踪
  - `log_fallback_enrich` (P0-B)：Fallback 链增强追踪
  - `log_early_stop` (P1-E)：早停触发追踪
  - `log_best_combinations` (P0-C)：高成功率组合追踪
  - `log_feedback`：反馈分析追踪
  - `log_mutation` (P1-F)：变异体生成追踪
- **Recon 优化阶段追踪**（v2，2026-07-19）：
  - `log_recon_optimization`：记录 OPT-A/G/D/M/E 优化项执行
  - `show_recon_optimizations`：在 `show_full_report` 中展示优化摘要
  - 标题格式：`######## 侦察阶段优化（OPT-A/G/D/M/E） ########`
  - `to_dict` 导出 `recon_optimizations` 字段
  - `export_markdown` 导出优化阶段表格
- 展示方法：`show_full_report()` 按顺序展示全部 11 个 `########` 标题段落
- JSON 导出 `to_dict()` 包含全部 P0-P3 阶段数据

### 13.5 全链路编排器 (`pipeline/orchestrator.py`) [v3.7 新增]
- **PipelineOrchestrator**：一键编排 凭据→侦察→攻击→报告
- 四阶段执行：credential → recon → attack → report（可配置跳过）
- 凭据优先复用：从 `credentials/` 目录发现有效凭据，JWT 过期检查
- 凭据自动注入：Garak（环境变量）/ DeepTeam（请求头）/ PyRIT（api_key）
- 侦察驱动攻击：画像自动驱动 REV-1 载荷过滤 + REV-2 ASR 排序
- 结果突出显示：Rich 格式化各阶段关键指标（漏洞数/风险/成功率/耗时）
- 便捷方法：`run_recon_only()` / `run_attack_only()`
- CLI 命令：`ai300 pipeline --target-url ... --scope all`
- **自适应编排（v3.7.1）**：目标类型自动检测（SPA vs API）
  - SPA 路径：SPA Recon → Garak + DeepTeam（跳过 AIMAP，凭据+端点直接传递）
  - API 路径：AIMAP → Garak + DeepTeam（传统流程）
  - 探测消息发送验证 + API 降级重试（`_try_direct_api_send`）

### 13.6 SPA Chat 侦察适配器增强（v3.7.1）

#### 提供商推断 v2（全球覆盖）
- `_infer_provider(model_name, api_url)` 双重策略：
  - **模型名匹配**（优先）：覆盖 30+ 提供商
    - 中国：火山引擎/DeepSeek/阿里/智谱/百度/月之暗面/MiniMax/百川/讯飞/腾讯/零一/阶跃
    - 欧美：OpenAI(gpt/o1/o3/dall-e/whisper/tts/sora)/Anthropic(claude)/Google(gemini/gemma/palm)/Meta(llama)/Mistral(mistral/ministral/mixtral/codestral/pixtral)/Microsoft(phi)/Cohere(command)/Amazon(nova/titan)/IBM(granite)/Perplexity(pplx/sonar)/Stability/AI21/Reka/Databricks/xAI(grok)
  - **API 域名匹配**（补充）：覆盖 25+ 域名
    - 欧美域名：api.openai.com / api.anthropic.com / generativelanguage.googleapis.com / api.mistral.ai / api.cohere.ai / bedrock-runtime.amazonaws.com / api.perplexity.ai / api.x.ai / api.together.xyz / api.fireworks.ai / api.groq.com / api.deepinfra.com / openrouter.ai 等

#### AI 响应容器选择器 v2（全面覆盖）
- `response_fallback_sels` 降级列表从 14 个扩展到 40+ 个选择器
- 覆盖框架：ChatGPT/OpenAI、Claude/Anthropic、国产 AI 应用、Vercel AI SDK、LangChain/Gradio/Streamlit、推理/思维链容器、ARIA 语义角色
- `page.evaluate` 批量扫描同步扩展（两处保持一致）

#### 探测消息发送增强
- 发送后验证逻辑：UI 发送后短时间内未检测到 LLM API 调用则触发降级
- `_try_direct_api_send`：通过 `page.evaluate` 使用 `fetch` 直接调用 LLM API
- `_direct_api_probe`：三重策略（非流式请求 → 流式请求+增强解析 → JS 全局变量提取）

### 14. 报告生成器 (`reporting/report_generator.py`)
- 符合 OffSec AI-300 考试报告标准
- 支持 Markdown / HTML 格式
- Detailed Findings 格式：Finding #1 / #2... 含 Severity/Source/Category/OWASP/MITRE ATLAS/Endpoint
- 标题自动生成（中文）：`_generate_title("embedding_inversion") → "嵌入系统信息泄露"`
- 严重度计算：catalog 优先 > 成功率推算
- 内容字段：Description / Evidence（无截断）/ Remediation

---

## 占位符系统（Placeholder System v2.0）

### 三级分类
| 级别 | 占位符 | 来源 |
|------|--------|------|
| Tier 1 | `{goal}` / `{objective}` | `_goals.yaml`（类别级别） |
| Tier 2 | 编码变体（14种） | 自动从 objective 编码 |
| Tier 3 | 50+ 种领域参数 | 模板 `placeholders:` 自声明 |

### 编码变体占位符（14种）
```
{base64_goal}      → Base64 编码
{base32_goal}      → Base32 编码
{ascii85_goal}     → ASCII85 编码
{french_goal}      → 多语言模拟
{bidi_override_goal} → Bidi 覆盖
{unicode_tag_goal} → Unicode 标签字符
{zalgo_goal}       → Zalgo 变形
{chain_encoded_goal} → 链式编码
{ascii_tag_deep_goal} → 深层 ASCII
{hex_goal}         → 十六进制
{rot13_goal}       → ROT13
{sneaky_bits_goal} → 零宽隐写
{interlinear_ws_goal} → 行间空白
{multi_tag_mix_goal} → 多标签混合
```

### 自动发现
- 框架扫描模板 `placeholders:` 段提取默认值
- 合并策略：append（默认）/ prepend / replace

### CLI 优先级
```
--experiment > --objective > auto_discover > --placeholder-file > 交互式提示
```

### _goals.yaml 文件 [NEW]
- 存放在 OWASP 类别目录下（如 `data/owasp/llm/llm08/_goals.yaml`）
- 包含 `goals:` 列表，模板中 `{goal}` 占位符自动遍历
- 目前仅 LLM08 有 _goals.yaml（Excessive Agency 攻击目标）

---

## 目录结构

```
pyrit/                          # 项目根目录
├── config/                     # 配置层
│   ├── targets/               #   目标端点配置 YAML（3 个极简模板）
│   │   ├── spa_target.yaml    #     SPA 聊天（4 字段：url/username/password/auth_mode）
│   │   ├── llm_api_target.yaml#     LLM API（4 字段：type/endpoint/model/api_key）
│   │   ├── http_target.yaml   #     HTTP API（2 字段：use_tls/http_request）
│   │   └── credentials/       #     凭据文件（侦察自动导出，域名命名）
│   ├── recon/                 #   侦察配置（recon.yaml + garak.yaml）
│   ├── scores/                #   评分器 LLM 后端（每后端一个 YAML）
│   ├── headers/               #   认证头文件
│   └── output/                #   输出报告配置
├── data/                       # 数据层
│   ├── owasp/                 #   载荷唯一真相源
│   │   ├── llm/               #   LLM01-10
│   │   ├── agentic/           #   ASI01-10
│   │   ├── _registry.core.yaml
│   │   └── _goals.yaml        #   各类别攻击目标
│   └── recon_templates/       #   侦察探测模板
├── pyrit_ai300/                # 代码层（纯执行引擎）
│   ├── reconnaissance/        #   侦察引擎
│   ├── attack/                #   攻击引擎扩展
│   ├── orchestrators/         #   编排器（核心）
│   ├── payloads/              #   载荷管理
│   ├── pipeline/              #   流水线追踪
│   ├── reporting/             #   报告生成
│   ├── tests/                 #   单元测试
│   ├── utils/                 #   工具函数
│   ├── __init__.py            #   AI300Engine 入口
│   └── cli.py                 #   命令行接口
├── results/                    # 输出结果
└── docs/                       # 文档
```

---

## 评分器配置（目录模式）

### 目录模式
- **配置目录**：`config/scores/`（每个后端一个 YAML 文件）
- **默认后端**：local_ollama（qwen3:0.6b @ http://localhost:11434/v1）
- **可覆盖**：--scorer-url / --scorer-key / --scorer-model

### ASI 自动选择
- `AttackOrchestrator._ASI_SCORER_MAP`：ASI → 评分器映射
- refusal / true_false / category / substring 四种类型

### 优先级：
- CLI 参数 > 环境变量 > 配置文件 > 默认 local_ollama

---

## 数据架构规则（DATA-001）

### OWASP 载荷存储规则
- OWASP 目录为唯一真相源
- **ref_path 格式**：`owasp:llm:llm01:jailbreak:aim`
- 多级子目录扫描（`rglob` 递归）
- **顶层文件跳过规则**：有子目录时顶层 YAML 不加载

### OWASP ID 标识
- `id` 字段用于 OWASP 分类标识
- ID 隐含攻击面，不存储 `surfaces` 和 `ai300_chapters`
- surfaces 由侦察动态生成（ReconEngine）

---

## P0-P3 深度优化（2026-07-19 完成）

### 优化清单
| 优先级 | 编号 | 名称 | 实现文件 |
|--------|------|------|---------|
| P0-A | 逐载荷转换器选择 | `SmartMatcher.select_converters_for_payload` | `smart_matcher.py` |
| P0-B | Fallback 链增强 | `_enrich_fallback_chain_with_converters` | `smart_matcher.py` |
| P0-C | 高成功率组合 | `_compute_best_combinations` | `attack_orchestrator.py` |
| P1-E | 早停机制 | 连续失败 >=5 触发 | `attack_orchestrator.py` |
| P1-F | 闭环变异 | `FeedbackAnalyzer.generate_mutations` | `feedback_analyzer.py` |
| P3-J | 载荷去重 | `PayloadDeduplicator` (Jaccard >=0.85) | `payload_dedup.py` |

### 新增文件
- `pyrit_ai300/pipeline/feedback_analyzer.py`：反馈分析 + 变异生成
- `pyrit_ai300/payloads/payload_dedup.py`：语义去重
- `pyrit_ai300/payloads/payload_mutator.py`：载荷变异器
- `pyrit_ai300/payloads/payload_generator.py`：载荷生成器
- `pyrit_ai300/payloads/template_renderer.py`：模板渲染
- `pyrit_ai300/orchestrators/converter_builder.py`：转换器构建器
- `pyrit_ai300/orchestrators/scorer_builder.py`：评分器构建器
- `pyrit_ai300/orchestrators/target_builder.py`：目标构建器
- `pyrit_ai300/orchestrators/pyrit_initializer.py`：PyRIT 初始化
- `pyrit_ai300/utils/async_helper.py`：异步安全执行
- `pyrit_ai300/utils/platform.py`：平台工具
- `docs/pipeline_attack_flow.md`：完整流程文档

### 文档
- `docs/pipeline_attack_flow.md`：优化后完整攻击流水线文档（10 阶段 + 22 个追踪 stage）

---

## 覆盖进度（2026-07-19 更新）

| 类别 | 进度 |
|------|------|
| AI-300 Module | 11/11 |
| OWASP LLM | 10/10 |
| OWASP Agentic | 10/10 |
| 载荷库 | 537+（69 YAML 文件） |
| 转换器 | 39 个 |
| 评分器 | 12 个 |
| 侦察工具 | 3 个（Garak + DeepTeam + ProtocolFingerprint）|
| 测试 | 220+ passed |

---

## CLI 命令速查

```bash
# OWASP 标准攻击
ai300 owasp <scope> -t <target> [options]
  scope: llm01/asi01/llm/agentic/all/ref_path
  --target-file / --target-dir / --target-url
  --profile <json>      # 侦察生成的 TargetProfile
  --objective <text>    # 攻击目标
  --experiment <path>   # 实验配置
  --auto-recon          # 先侦察再攻击
  --format md|html      # 报告格式
  --scorer-url          # 外部 LLM 评分器 URL
  --scorer-key          # 外部 LLM 评分器 Key
  --scorer-model        # 外部 LLM 评分器模型

# 侦察
ai300 recon -t <target> -d quick|standard|deep

# 列表
ai300 list attacks|converters|scorers|targets|owasp

# 报告
ai300 report -r <results.json> -o <output>
```

---

## 已删除的死代码历史

### 2026-07-19（v1.3 配置极简化 + 凭据自动导出）
- `config/targets/sso_login.yaml` — 被 `spa_target.yaml` 极简版替代
- `config/targets/spa_chat_attack.yaml` — 被 `spa_target.yaml` 极简版替代
- `config/targets/qianwen_chat.yaml` — 被 `spa_target.yaml` 的 manual 模式替代
- `config/targets/ollama.yaml` — 被 `llm_api_target.yaml` 替代
- `config/targets/openai_compatible.yaml` — 被 `llm_api_target.yaml` 替代
- `config/targets/http_api.yaml` — 被 `http_target.yaml` 替代
- `auto_spa_recon.py` 中从 credentials 文件按 `username:password` 格式提取的死代码 — 凭据文件是 HTTP Headers 格式，不是 username:password

### 2026-07-18
- `reporting/chapter_mapper.py` — OWASP→AI-300 章节映射（集成到报告生成器）
- `config/attack/defaults.yaml` — 攻击默认配置（不再需要）
- `config/attack/patterns.yaml` — 攻击模式配置（不再需要）
- `config/placeholders/` 目录 — 占位符文件迁移到 `_goals.yaml`

### 2026-07-17
- `config/scores/` 旧目录（6 个文件）→ 简化为目录模式
- `AI300Engine.MODULES` / `_run_module()` → 删除
- `SmartMatcher.AttackMemory` / `AdaptiveExplorationManager` → 删除
- `PayloadManager.get_payloads()` 5个 legacy 方法 → 删除

### 2026-07-16
- `converters/`, `scorers/`, `attacks/` 空壳目录 → 删除
- `display/` 目录 → 拆分为 pipeline/ + reporting/

---

## Garak 独立 venv 架构

### 原因
- garak 0.15.1 与 pyrit 0.14.0 的 datasets 版本冲突

### 方案
- 独立 venv `.garak/` + subprocess 调用
- 安装：`make setup-garak`

---

## OWASP Registry（v1.4.0）

### 统计
- **总类别**：20（LLM01-10 + ASI01-10）
- **总文件**：69
- **总载荷**：537
- **最后清理**：2026-07-17 删除 52 个对当前模型无效的载荷

### LLM08 新增载荷（2026-07-18）
- `embedding_inversion_practical.yaml`：嵌入反演/成员推断/向量DB API利用
- `_goals.yaml`：Excessive Agency 攻击目标（RCE + 权限滥用 + 持久化）

---

## 关键 API 参考

### AI300Engine
```python
from pyrit_ai300 import AI300Engine

engine = AI300Engine(
    target_config="config/targets/llm_api_target.yaml",
    profile_path="results/recon/profile.json",
    target_url="http://target.com",
    scorer_url="http://localhost:11434/v1",
)
results = engine.run(scope="llm01")
engine.generate_report(output_path="report.md", format="html")
```

### ReconEngine
```python
from pyrit_ai300.reconnaissance import ReconEngine

engine = ReconEngine()
profile = engine.run(target="http://localhost:11434", depth="standard")
# 或流式
for tool_name, partial_profile, is_complete in engine.run_streaming(target=target):
    print(f"{tool_name}: {partial_profile.vulnerability_count}")
```

### AttackOrchestrator
```python
from pyrit_ai300.orchestrators import AttackOrchestrator

orch = AttackOrchestrator(scorer_url="http://...", scorer_key="...", scorer_model="gpt-4o-mini")
target = orch.build_target(target_config)
attacks = AttackOrchestrator.build_attack_list_from_refs(refs, payload_mgr, target_model="gpt-4")
```

---

## 环境变量

| 变量 | 说明 |
|------|------|
| `SCORER_BASE_URL` | 外部评分 LLM URL |
| `SCORER_API_KEY` | 外部评分 LLM API Key |
| `SCORER_MODEL_NAME` | 外部评分 LLM 模型名 |
| `PYTHONIOENCODING` | 强制 UTF-8（Windows）|

---

## 常用目标配置类型

| 类型 | 配置文件 | 并发 | 速率 | 说明 |
|------|---------|------|------|------|
| ollama | `llm_api_target.yaml` | 2 | 0 | 本地 Ollama |
| openai | `llm_api_target.yaml` | 5 | 10 req/s | OpenAI 兼容 API |
| http | `http_target.yaml` | 3 | 0 | 自定义 HTTP 端点 |
| spa_chat | `spa_target.yaml` | 1 | 0 | 浏览器自动化（强制串行）|

### 配置极简化架构（v1.3，2026-07-19）

**3 个极简模板**（用户只需填 2-4 个字段）：

| 模板 | 字段 | 认证方式 |
|------|------|---------|
| `spa_target.yaml` | url / username / password / auth_mode | 侦察自动登录 → 自动导出凭据 |
| `llm_api_target.yaml` | type / endpoint / model / api_key | api_key 字段直接填 |
| `http_target.yaml` | use_tls / http_request | 认证写在 http_request 的 Header 中 |

**SPA 认证模式（auth_mode）**：
| 模式 | 适用场景 | 验证码 |
|------|---------|--------|
| sso | passport SSO 跳转 | 人工完成（滑窗/图形/拼图） |
| credentials | 简单账号密码 | 自动检测，有则等人工 |
| manual | 扫码/手机号+短信/OAuth | 完全手动 |
| none | 公开页面 | 无需认证 |

**凭据自动导出/复用流程**：
```
侦察阶段（auto_spa_recon.py）
  → 认证完成（sso/credentials/manual）
  → export_credentials() 导出 Cookie/JWT/API Key 到 credentials/{domain}.txt
  → update_yaml_with_results() 回写选择器到 spa_target.yaml 的 auto_detected 段

攻击阶段（target_builder.py）
  → find_credential_file(domain) 自动发现凭据文件
  → parse_header_file() 解析为 AuthProfile
  → inject_auth() 注入到 Playwright 浏览器
```

**已删除的旧配置文件**（v1.3）：
- `sso_login.yaml` → 被 `spa_target.yaml` 极简版替代
- `spa_chat_attack.yaml` → 被 `spa_target.yaml` 极简版替代
- `qianwen_chat.yaml` → 被 `spa_target.yaml` 的 manual 模式替代
- `ollama.yaml` → 被 `llm_api_target.yaml` 替代
- `openai_compatible.yaml` → 被 `llm_api_target.yaml` 替代
- `http_api.yaml` → 被 `http_target.yaml` 替代

> 代码向后兼容旧格式，但推荐使用极简模板。

