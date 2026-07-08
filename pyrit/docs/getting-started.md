# PyRIT 红队渗透测试实战手册 — 快速入门

> **场景**：红队仅拿到一个目标 URL，对背后模型名称、架构类型、部署位置一无所知。
> 以下按渗透测试自然流程组织，从侦察到攻击逐步推进。
>
> **📖 完整手册导航**：
> - [一、侦察阶段](reconnaissance-guide.md)
> - [二、攻击阶段：三种认证场景](attack-scenarios.md)
> - [三、攻击后研判与渗透深化](post-attack-analysis.md)
> - [四、端到端全自动渗透测试](end-to-end-pipeline.md)
> - [五、自适应攻击引擎](adaptive-engine.md)
> - **🆕 按目标类型专项攻击手册**：[PER_TARGET_ATTACK_GUIDE.md](PER_TARGET_ATTACK_GUIDE.md)
>   覆盖 7 种目标架构（Basic LLM / RAG / MCP / Agent / Multi-Agent / A2A / Embedding），
>   对齐 OFF SEC AI-300 全部考点。

---

## 快速导航：端到端命令行速查手册

> 不想看原理？直接复制以下命令执行即可。框架自动完成从侦察到报告的全流程。

### 按目标类型快速选择命令

| 你的目标 | 一键命令 | 自动做什么 |
|----------|---------|-----------|
| 内网 vLLM/Ollama（无认证） | `python main.py --lang cn --target-url http://IP:PORT/ --phase probe` | 端点枚举→模型识别→架构探测→框架指纹 |
| 内网模型，要求自动攻击 | `python main.py --lang cn --target-url http://IP:PORT/v1/chat/completions --auto-gate --gate-threshold 0.10` | 侦察→阶梯攻击(Probe→Single→Crescendo)→评分→报告 |
| 内网模型，最高成功率 | `python main.py --lang cn --target-url http://IP:PORT/v1/chat/completions --adaptive --auto-gate --gate-threshold 0.10` | 以上 + 动态300+组合 + Bandit智能调度 + 厂商载荷 |
| OpenAI/Gemini/Claude API | `python main.py --lang cn --target-url https://API_URL --target-api-key sk-xxx --phase all` | 侦察→全策略攻击→评分→报告 |
| 非标准 Web Chat | `python main.py --lang cn --target-url http://IP:PORT/api/chat --target-api-format raw --auto-gate` | 使用 raw 格式 POST，其余流程同上 |
| 仅探测不攻击 | `python main.py --lang cn --target-url http://IP:PORT/ --phase probe` | 输出端点列表+模型名+架构类型+部署位置 |
| 仅单轮快速扫描 | `python main.py --lang cn --target-url http://IP:PORT/v1/chat/completions --phase single` | 用 127+ 种攻击组合一次性覆盖 |
| 仅多轮纵深突破 | `python main.py --lang cn --target-url http://IP:PORT/v1/chat/completions --phase crescendo` | 渐进式多轮越狱，对付高防线模型 |

### 核心参数特别说明

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `--target-url` | **必填** | — | 目标 LLM 服务端点。可传根路径（如 `http://IP:8501/`），框架自动枚举子路径；也可直接传完整 chat 端点 |
| `--lang` | cn/en | en | 语言选择：`cn` 使用中文 payload，`en` 使用英文 payload |
| `--phase` | 枚举值 | `probe` | 攻击阶段：`probe`(探测) / `single`(单轮) / `crescendo`(渐进) / `pair`(反驳) / `tap`(树搜索) / `flip`(翻转) / `chunked`(分块) / `manyshot`(洪水) / `skeleton_key`(解锁) / `all`(全部) |
| `--auto-gate` | flag | False | **推荐开启**。阶梯式门控：Probe→Single→Crescendo，每阶段成功率低于阈值自动跳过 |
| `--gate-threshold` | float | 0.10 | 门控阈值。例如 0.10 = 某阶段成功率 < 10% 则自动跳过该阶段 |
| `--adaptive` | flag | False | **推荐开启**。动态组合生成(300+) + Bandit 智能调度 + 跨用例策略共享 + 混合评分 |
| `--target-api-key` | str | "" | API 密钥。对于需要认证的目标必填。OpenAI 格式 → `Authorization: Bearer {key}`；Claude → `x-api-key: {key}`；Gemini → URL query 参数 |
| `--target-api-format` | str | `openai` | 请求格式：`openai`(标准) / `raw`(非标准 Web Chat) / `claude` / `gemini` |
| `--target-cookie` | str | "" | Cookie 认证。适用于内网 Web 应用，格式 `session_id=abc` |
| `--target-jwt` | str | "" | JWT Token 认证。格式 `eyJhbGci...` |
| `--target-extra-headers` | JSON | "" | 自定义请求头。格式 `'{"X-API-Key":"xxx","X-CSRF":"yyy"}'` |
| `--target-model` | str | auto | 模型名称。留空则自动探测；手动指定可跳过探测加速 |
| `--no-probe` | flag | False | 完全跳过侦察阶段（目标信息已确知时使用） |
| `--concurrent` | int | 1 | 并发请求数。根据目标承载能力调整，太高可能触发限流 |
| `--case` | str | "" | 指定攻击用例 ID，逗号分隔。如 `CAP_001,CAP_005`。快捷别名：`all-single` / `all-crescendo` / `all-error` |
| `--exclude-case` | str | "" | 排除不适用用例，逗号分隔 |
| `--payload-preset` | str | `default` | 载荷预设：`stealth`(隐匿) / `bruteforce`(暴力) / `redteam`(红队) / `academic`(学术) / `minimal`(精简) |
| `--payload-vars` | JSON | "" | 命令行注入额外 payload 变量，最高优先级。如 `'{"bypass_hint":"roleplay","target_lang":"en"}'` |
| `--converters` | str | "" | 手动指定转换器链。如 `"Base64" "ROT13"`。留空则自动使用默认组合 |
| `--use-dedup-cache` | flag | False | 启用去重缓存。重复 prompt 自动跳过，节省 Token 和时间 |
| `--enable-early-stop` | flag | False | 启用提前终止。连续 3 次成功则停止当前用例 |
| `--target-vendor` | str | `auto` | 目标厂商：`openai`/`anthropic`/`google`/`deepseek`/`qwen`/`zhipu`/`auto`。`auto` 自动从模型名检测 |
| `--target-no-ssl` | flag | False | 跳过 SSL 验证（自签证书目标使用） |
| `--orch` | str | `native` | 调度引擎：`native`(PyRIT 原生) / `legacy`(旧版兼容) |
| `--penetrating-mode` | — | — | 渗透模式入口，与 `--penetrating-template` 配合使用 |
| `--penetrating-template` | str | — | 渗透模板 YAML，如 `jailbreak_arsenal.yaml` |

### 端到端执行流程速览

```
一条命令触发全自动链：

python main.py --lang cn --target-url URL --auto-gate [--adaptive]
    │
    ├─ [自动] bootstrap 初始化（Memory/配置/Target/架构/payload/converter）
    ├─ [自动] 目标可达性检测（不可达 → 立即中止，输出诊断）
    ├─ [自动] 模型名称探测（5 策略降级，成功 → 注入攻击管线）
    ├─ [自动] 架构类型识别（LLM/RAG/MCP/Agent → 匹配攻击策略）
    ├─ [自动] 框架指纹 + 厂商检测（注入厂商差异化载荷）
    │
    ├─ [--auto-gate] 阶梯式攻击
    │   ├─ STAGE 1: --phase probe     → 轻量探测，成功率 < 阈值? → 跳过后续
    │   ├─ STAGE 2: --phase single    → 单轮全覆盖，成功率 < 阈值? → 跳过后续
    │   └─ STAGE 3: --phase crescendo → 多轮渐进越狱
    │
    ├─ [--adaptive] 自适应增强（可与门控叠加）
    │   ├─ 动态组合生成：300+ 种 converter 组合
    │   ├─ Bandit 调度：epsilon-greedy 最优组合选择
    │   ├─ 跨用例传播：成功组合自动推广
    │   └─ 混合评分：LLM+关键词+拒绝模式+内容比 四维加权
    │
    └─ [自动] 报告生成（攻击完毕后全自动）
        ├─ JSON 攻击日志 → outputs/results/*_log_*.json
        ├─ PNG 成功率热力图 → outputs/results/*_heatmap_*.png
        ├─ 终端 Rich 战报 → Console（SUCCESS/FAILURE/下一命令）
        └─ Markdown 渗透报告 → outputs/results/*_Exam_Report_*.md
           （10 章 OSCP 标准 + MITRE/OWASP/NIST 映射）
```

---

**下一步**：阅读 [一、侦察阶段](reconnaissance-guide.md) 了解从单个 URL 出发的自动信息收集。
