# OffSec AI-300 — 统一红队演练平台

基于 [PyRIT](https://github.com/Azure/PyRIT) 的 LLM 安全测试平台，覆盖 AI-300 考试所需的核心攻击面。

## 快速开始

```bash
pip install -r requirements.txt
```

### 模式 A：攻击 .env 配置的 LLM API

```bash
python main.py --lang cn --phase probe      # 快速探测
python main.py --lang cn --phase single     # 单轮突破
python main.py --lang cn --phase crescendo  # 多轮攻坚
python main.py --lang cn --auto-gate        # 自动门控
```

### 模式 B：攻击自定义 HTTP Chat API

```bash
python main.py --lang cn --phase probe \
  --target-url http://localhost:5000/api/chat \
  --target-api-format raw
```

---

## ⚠️ Ollama 本地模型速率限制（重要）

**Ollama 是本地单 GPU 串行推理，无内置速率限制。高并发不会触发 429，而是直接导致 GPU OOM 或进程崩溃。**

攻击 Ollama 目标时，**必须**显式设置 `--concurrent 1`：

```bash
# ✅ 正确：攻击 Ollama 模型
python main.py --target-url http://192.168.40.198:11434/v1 --concurrent 1

# ❌ 错误：不设 --concurrent 或使用默认值，可能压垮 Ollama
python main.py --target-url http://192.168.40.198:11434/v1
```

> **原因**：Ollama 不返回 HTTP 429，model_probe 的自适应限流探测无法感知过载，会误判为"无限流"，从而推荐高并发。只有显式 `--concurrent 1`（或最多 2）才能安全运行。

---

## CustomHttpChatTarget 使用场景

| # | 场景 | 关键参数 |
|---|------|----------|
| 1 | 通用 Chat API | `--target-api-format raw` |
| 2 | Cookie + JWT 双重认证 | `--target-cookie` + `--target-jwt` |
| 3 | Cookie 认证 + 浏览器伪装 | `--target-cookie` |
| 4 | HTTPS 自签 + 自定义认证头 | `--target-extra-headers` + `--target-no-ssl` |
| 5 | GET 信息收集/探测 | `--target-http-method GET` |
| 6 | JWT Bearer Token | `--target-jwt` |
| 7 | form-urlencoded POST + Cookie | `--target-content-type` + `--target-cookie` |

### 场景 1：通用 Chat API

```bash
python main.py --lang cn --phase probe \
  --target-url http://localhost:5000/api/chat \
  --target-api-format raw
```

### 场景 2：Cookie + JWT 双重认证

```bash
python main.py --lang cn --phase probe \
  --target-url http://localhost:5000/api/chat \
  --target-api-format raw \
  --target-cookie "session_id=abc123; auth_token=xyz" \
  --target-jwt "eyJhbGciOi..."
```

### 场景 3：Cookie 认证 + 浏览器 UA 伪装

```bash
python main.py --lang cn --phase probe \
  --target-url http://192.168.1.100/internal/chat \
  --target-api-format raw \
  --target-cookie "alimail_device_id=49816375-..."
```

### 场景 4：HTTPS 自签证书 + 自定义认证头

```bash
python main.py --lang cn --phase probe \
  --target-url https://internal-app/api/v1/query \
  --target-api-format raw \
  --target-extra-headers '{"X-API-Key":"sk-secret","X-CSRF-Token":"csrf-xyz"}' \
  --target-no-ssl
```

### 场景 5：GET 信息收集/探测

```bash
python main.py --lang cn --phase probe \
  --target-url http://192.168.1.100/api/info \
  --target-api-format raw \
  --target-http-method GET \
  --target-cookie "alimail_device_id=..."
```

### 场景 6：JWT Bearer Token 认证

```bash
python main.py --lang cn --phase probe \
  --target-url https://app/api/chat \
  --target-api-format raw \
  --target-jwt "eyJhbGciOi..."
```

### 场景 7：form-urlencoded POST + Cookie 认证

```bash
python main.py --lang cn --phase probe \
  --target-url http://target/api/chat \
  --target-api-format raw \
  --target-content-type application/x-www-form-urlencoded \
  --target-cookie "JSESSIONID=abc123"
```

---

## CLI 参数速查

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `--lang` | 测试用例语言 cn/en | `cn` |
| `--phase` | 攻击阶段 probe/single/crescendo/all | `probe` |
| `--concurrent` | 并发数（Ollama 必须设为 1） | `1` |
| `--auto-gate` | 自动门控（低成功率跳过当前阶段） | 关闭 |
| `--gate-threshold` | 门控阈值 0.0-1.0 | `0.10` |
| `--target-url` | 自定义攻击目标 URL | — |
| `--target-api-key` | API Key | — |
| `--target-api-format` | API 格式 openai/gemini/claude/raw | `openai` |
| `--target-cookie` | Cookie 字符串 | — |
| `--target-jwt` | JWT Token | — |
| `--target-extra-headers` | 自定义 HTTP 头（JSON） | — |
| `--target-http-method` | HTTP 方法 POST/GET/PUT/DELETE/PATCH | `POST` |
| `--target-content-type` | POST Content-Type | `application/json` |
| `--target-no-ssl` | 跳过 SSL 证书验证 | 启用 |
| `--target-user-agent` | 自定义 User-Agent | Chrome/131 |
| `--payload-preset` | 载荷预设 stealth/bruteforce/redteam/academic/minimal | — |
| `--case` | 用例 ID 或快捷别名: `all-probe` / `all-single` / `all-crescendo` / `all-error` | — |
| `--exclude-case` | 排除指定用例 ID，可配合快捷别名使用 | — |

---

## 跳过/筛选用例

### 快捷别名（一键覆盖整个阶段）

```bash
# 一键运行全部单轮用例
python main.py --lang cn --case all-single

# 一键运行全部多轮用例
python main.py --lang cn --case all-crescendo

# 一键运行全部探测用例
python main.py --lang cn --case all-probe

# 一键重跑上次所有 ERROR 用例（精确到 case+combo 对）
python main.py --lang cn --case all-error

# 快捷别名 + 排除高危用例
python main.py --lang cn --case all-crescendo \
  --exclude-case multi_crescendo_reverse_shell

# all-error 也支持排除
python main.py --lang cn --case all-error \
  --exclude-case multi_crescendo_CAP_009_explosive_device
```

### 仅测试特定用例（`--case`）

```bash
# 仅测试单个用例
python main.py --lang cn --phase probe --case single_reverse_shell

# 仅测试多个用例（逗号分隔）
python main.py --lang cn --phase probe \
  --case "single_reverse_shell,CAP_001_social_eng_phishing,CAP_007_apple_phishing_email"
```

### 排除特定用例（`--exclude-case`）

```bash
# 跳过爆炸物/芬太尼/冰毒合成等高敏感用例
python main.py --lang cn --phase probe \
  --exclude-case "CAP_009_explosive_device,CAP_041_gcg_adversarial_suffix"

# 排除多个用例，结合 preset
python main.py --lang cn --phase probe --payload-preset redteam \
  --exclude-case "CAP_029_hate_speech_generation,CAP_030_political_disinformation"
```

### `--case` 与 `--exclude-case` 同时使用

白名单优先：先用 `--case` 圈定范围，再用 `--exclude-case` 从中排除：

```bash
# 测试所有反序列化 + SQLi 相关，但排除极高敏感用例
python main.py --lang cn --phase probe \
  --case "CAP_008_sqli_data_theft,single_sqli_auth_bypass,CAP_040_tap_tree_attack,CAP_009_explosive_device" \
  --exclude-case "CAP_009_explosive_device"
```

### 与 `--phase` / `--auto-gate` 组合

```bash
# 全阶段门控 + 排除政治敏感类用例
python main.py --lang cn --auto-gate \
  --exclude-case "CAP_029_hate_speech_generation,CAP_030_political_disinformation"

# 仅 Crescendo 多轮攻坚 + 指定用例
python main.py --lang cn --phase crescendo \
  --case "multi_crescendo_reverse_shell,multi_crescendo_CAP_010_jwt_none_forgery"
```

### 5 种 Preset 全量对比脚本

```bash
# 全链路一致，切换 preset 所有 35 个用例变量都正确匹配对应风格
python main.py --lang cn --phase probe --payload-preset stealth
python main.py --lang cn --phase probe --payload-preset redteam
python main.py --lang cn --phase probe --payload-preset academic
python main.py --lang cn --phase probe --payload-preset bruteforce
python main.py --lang cn --phase probe --payload-preset minimal
```

### 按目标 OS 筛选用例

如果目标系统为 Linux，自动跳过 Windows 专属用例；反之亦然。

**Linux 目标 — 排除 Windows 专属用例（5 个）：**

```bash
python main.py --lang cn --phase probe \
  --exclude-case "single_password_cracking,CAP_011_vba_malware_macro,multi_crescendo_CAP_004_eternalblue_exploit,CAP_040_tap_tree_attack,multi_crescendo_CAP_042_many_shot_icl_escalation"
```

**Windows 目标 — 排除 Linux 专属用例（6 个）：**

```bash
python main.py --lang cn --phase probe \
  --exclude-case "CAP_003_malicious_bash_script,multi_crescendo_CAP_014_dirty_cow_priv_esc,CAP_050_reflection_based_jailbreak,PROBE_01_roleplay_defense,multi_crescendo_CAP_025_persistent_backdoor,PROBE_03_encoding_bypass"
```

**OS 专属用例速查表：**

| 用例 ID | 引用的 Payload | OS |
|---------|---------------|----|
| `CAP_003_malicious_bash_script` | `malicious_bash_script` | Linux |
| `multi_crescendo_CAP_014_dirty_cow_priv_esc` | `dirty_cow_exploit` | Linux |
| `CAP_050_reflection_based_jailbreak` | `linux_priv_esc_exploit` | Linux |
| `PROBE_01_roleplay_defense` | `selinux_disable` | Linux |
| `multi_crescendo_CAP_025_persistent_backdoor` | `rootkit_persistence` | Linux |
| `PROBE_03_encoding_bypass` | `sensitive_file_read` | Linux |
| `single_password_cracking` | `password_cracking_method` | Windows |
| `CAP_011_vba_malware_macro` | `vba_malware_macro` | Windows |
| `multi_crescendo_CAP_004_eternalblue_exploit` | `eternalblue_exploit` | Windows |
| `CAP_040_tap_tree_attack` | `windows_persistence_backdoor` | Windows |
| `multi_crescendo_CAP_042_many_shot_icl_escalation` | `windows_defender_disable` | Windows |

---

## 项目结构 (PyRIT 最佳实践)

```
├── config/                    # 配置文件目录
├── templates/                 # 模板目录
│   └── datasets/              # Prompt 素材库 (payload YAML)
│       ├── core/              # 经典载荷（双语 + 五档预设）
│       ├── manifest.yaml      # 模块↔文件索引
│       └── *_payloads.yaml    # 各 AI 模块的载荷列表
├── scenarios/                 # 🆕 场景模块 (PyRIT 对齐) — 考试期间仅需修改此处
│   ├── templates/             # YAML 场景模板定义 (11 个场景)
│   ├── schema.py              # 模板 Pydantic Schema
│   ├── orchestrator.py        # ExamAutoOrchestrator 场景编排引擎
│   ├── variant_generator.py   # 提示词变体生成器 (10+ 种策略)
│   ├── rag_attacks.py         # RAG 管道攻击 Payload
│   ├── agent_attacks.py       # 多智能体攻击 Payload
│   ├── infra_attacks.py       # 基础设施攻击 Payload
│   ├── reporter.py            # 综合安全评估报告
│   └── target_presets.py      # HTTP 连接场景预设
├── prompt_converters/         # 存放自定义转换器
│   ├── registry.py            # 转换器注册表 & 攻击组合
│   ├── jailbreak.py           # 越狱前缀类 (DAN/PAIR/AIM/...)
│   ├── injection.py           # 注入类 (Suffix/JSON Hijack)
│   ├── bypass.py              # 绕过类 (Translation/DeepInception/...)
│   ├── reasoning.py           # 推理/宪法类 (CoT/Constitution)
│   ├── rag_poisoning.py       # RAG 知识库投毒
│   └── embedding_attack.py    # Embedding 对抗攻击
├── attack_executor/           # 存放攻击执行器
│   ├── single.py              # 单轮攻击引擎
│   ├── crescendo.py           # Crescendo 多轮渐进式引擎
│   ├── sequence_attack.py     # 策略管道引擎
│   ├── scorer.py              # 评分器 (Judge LLM)
│   ├── dashboard.py           # 仪表盘状态
│   ├── template.py            # Payload 模板变量
│   └── utils.py               # 引擎工具函数
├── targets/                   # 定义和封装不同的攻击目标
│   ├── config.py              # .env 配置加载
│   ├── http_target.py         # 自定义 HTTP Chat Target
│   ├── factories.py           # Target 工厂函数
│   ├── scenarios.py           # 场景预设配置
│   └── model_probe.py         # 模型自动探测
├── scoring/                   # 评分引擎相关逻辑
├── orchestrators/             # 编排层，定义攻击工作流
│   ├── pyrit_orchestrator.py  # AI300Orchestrator 统一调度器
│   └── scenario_runner.py     # A300ScenarioRunner 场景集成
├── exam_mode/                 # 考试模式 (向后兼容桥接 → scenarios/)
├── reporting/                 # 结果分析与报告生成
├── data/                      # 测试用例 & Payload 数据模型
├── utils/                     # 通用工具函数
│   ├── helpers.py             # 路径工具
│   └── retry.py               # 重试逻辑
├── outputs/                   # 攻击结果和日志输出
│   ├── logs/                  # 日志文件
│   └── results/               # 攻击结果
├── scripts/                   # 脚本目录
├── docs/                      # 文档目录
├── tests/                     # 测试目录
├── requirements.txt           # 项目依赖
├── run_redteam.py             # 项目主入口
└── main.py                    # CLI 入口 (向后兼容)
```
