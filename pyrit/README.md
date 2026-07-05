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
| `--concurrent` | 并发数 | `1` |
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
| `--case` | 仅测试指定用例 ID（逗号分隔） | — |
| `--exclude-case` | 排除指定用例 ID（逗号分隔） | — |

---

## 跳过/筛选用例

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

## 项目结构

```
├── main.py                    # CLI 入口 & 任务编排
├── targets.py                 # .env 配置加载 & HTTP Target 工厂
├── engines.py                 # 核心攻击引擎 & 仪表盘
├── converters.py              # 攻击策略转换器
├── reporter.py                # 结果分析与报告生成
├── validator.py               # 测试用例校验
├── requirements.txt           # Python 依赖
├── data/                      # 测试用例 & Payload 定义
│   ├── multi_stage_capstone_cases_cn.json
│   ├── multi_stage_capstone_cases_en.json
│   ├── payloads_cn.yaml        # CN Payload 变量注册表
│   └── payloads_en.yaml        # EN Payload 变量注册表
└── results/                   # 输出目录（日志/热力图/报告）
```
