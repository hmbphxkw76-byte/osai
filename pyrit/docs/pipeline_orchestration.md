# AI-300 全链路编排文档

> **最后更新**: 2026-07-20 / 版本: v1.0 / 关联模块: pyrit_ai300/pipeline/ / 状态: 已完成

## 1. 概述

全链路编排器 (`PipelineOrchestrator`) 实现 AI 红队评估的一键执行：
**凭据检查 → 侦察 → 攻击 → 报告**

### 1.1 核心特性

| 特性 | 说明 |
|------|------|
| 凭据优先复用 | 从 `config/targets/credentials/` 自动发现有效凭据（JWT 过期检查） |
| 凭据自动注入 | Garak（环境变量）/ DeepTeam（请求头）/ PyRIT（api_key） |
| 侦察驱动攻击 | 侦察画像自动驱动 REV-1 载荷过滤 + REV-2 ASR 排序 |
| 结果突出显示 | 每个阶段的关键指标用 Rich 格式清晰展示 |
| 错误隔离 | 单个阶段失败可配置为跳过或终止 |

### 1.2 架构位置

```
CLI (ai300 pipeline)
  └── PipelineOrchestrator
        ├── CredentialManager    → 凭据发现/验证/注入
        ├── ReconEngine          → AIMAP/Garak/DeepTeam 并行侦察
        ├── AI300Engine          → PyRIT 攻击执行
        └── ReportGenerator      → CVSS+ATLAS+Mermaid+ROI 报告
```

## 2. 凭据管理（CredentialManager）

### 2.1 设计原则

1. **域名隔离**：域名 A 只读取 A 的凭据文件，绝不交叉读取
2. **JWT 缓冲**：Token 预留 5 分钟缓冲，临界过期视为已过期
3. **优先复用**：有效凭据直接使用，避免重复登录
4. **自动导出**：认证成功后凭据自动导出到 `credentials/` 目录

### 2.2 凭据格式

凭据文件存储在 `config/targets/credentials/{domain}.txt`，格式为 HTTP Request Headers：

```
Authorization: Bearer eyJhbGciOiJIUzI1NiIs...
Cookie: SESSIONID=abc123; csrftoken=xyz789
User-Agent: Mozilla/5.0...
```

### 2.3 凭据注入策略

| 目标工具 | 注入方式 | 代码位置 |
|----------|----------|----------|
| Garak | `OPENAI_API_KEY` 环境变量 | `garak/adapter.py` |
| DeepTeam | `base_headers` 请求头 | `deepteam/adapter.py` |
| PyRIT OpenAIChatTarget | `api_key` 构造参数 | `target_builder.py` |
| PyRIT HTTPTarget | `Authorization` 头 | `target_builder.py` |
| PlaywrightTarget | `inject_auth()` 注入 | `playwright_injector.py` |

### 2.4 API

```python
from pyrit_ai300.pipeline import CredentialManager

mgr = CredentialManager()
resolution = mgr.resolve("https://student.syxy.ouchn.cn/#/home")

if resolution.has_credentials:
    # 凭据有效，直接使用
    garak_env = CredentialManager.for_garak(resolution)
    deepteam_headers = CredentialManager.for_deepteam(resolution)
    oai_kwargs = CredentialManager.for_openai_target(resolution)
else:
    # 凭据过期或缺失，需要重新认证
    ...
```

## 3. 全链路编排（PipelineOrchestrator）

### 3.1 执行阶段

| 阶段 | 名称 | 说明 | 可跳过 |
|------|------|------|--------|
| credential | 凭据检查 | 从 credentials/ 发现并验证凭据 | 是 |
| recon | 侦察 | AIMAP/Garak/DeepTeam 并行执行 | 是（`--profile`） |
| attack | 攻击 | PyRIT OWASP 标准攻击 | 是（`--recon-only`） |
| report | 报告 | CVSS+ATLAS+Mermaid+ROI | 是 |

### 3.2 CLI 使用

```bash
# 全链路执行（LLM API 目标）
ai300 pipeline --target-url http://localhost:11434 --scope all

# 全链路执行（SPA 智能助手目标，含认证）
ai300 pipeline --spa-config config/targets/spa_target.yaml --scope llm01

# 指定侦察深度 + HTML 报告
ai300 pipeline --target-url http://target.com --scope all -d deep --format html

# 仅执行侦察阶段
ai300 pipeline --target-url http://target.com --recon-only

# 跳过侦察，直接攻击（使用已有画像）
ai300 pipeline --target-url http://target.com --scope llm01 \
  --profile results/recon/profile.json

# 使用外部评分器
ai300 pipeline --target-url http://target.com --scope all \
  --scorer-url https://open.bigmodel.cn/api/paas/v4 \
  --scorer-key $ZHIPUAI_API_KEY --scorer-model glm-4-flash
```

### 3.3 Python API

```python
from pyrit_ai300.pipeline import PipelineOrchestrator

orchestrator = PipelineOrchestrator()
result = orchestrator.run(
    target_url="https://student.syxy.ouchn.cn/#/home",
    spa_config="config/targets/spa_target.yaml",
    scope="llm01",
    depth="standard",
)

# 查看结果
print(result.summary_table())
print(f"侦察成功: {result.recon_success}")
print(f"攻击成功: {result.attack_success}")
print(f"画像路径: {result.profile_path}")
print(f"报告路径: {result.report_path}")
```

### 3.4 便捷方法

```python
# 仅执行侦察
result = orchestrator.run_recon_only(
    target_url="http://target.com",
    depth="deep",
)

# 仅执行攻击（使用已有画像）
result = orchestrator.run_attack_only(
    target_url="http://target.com",
    scope="all",
    profile_path="results/recon/profile.json",
)
```

## 4. 文件清单

| 文件 | 行数 | 说明 |
|------|------|------|
| `pipeline/credential_manager.py` | 480 | 统一凭据管理器 |
| `pipeline/orchestrator.py` | 580 | 全链路编排器 |
| `pipeline/__init__.py` | 35 | 模块导出 |
| `cli.py` (pipeline 部分) | 120 | CLI 命令定义 + 执行函数 |

## 5. 最佳实践

### 5.1 凭据生命周期

```
首次使用 → 认证流程（SPA 侦察/手动登录）
         → 凭据导出到 credentials/{domain}.txt
         → 后续阶段直接复用（JWT 过期检查）
         → 过期时重新认证
```

### 5.2 侦察→攻击数据流

```
ReconEngine.run()
  → TargetProfile JSON（fingerprint + surfaces + vulnerabilities）
    → AI300Engine._build_target_config()
      → endpoint 覆盖（侦察发现的 LLM API 端点）
      → model 覆盖（侦察识别的模型名）
    → PayloadFilter (REV-1)：基于 surfaces 过滤不相关 OWASP 类别
    → ASRRanker (REV-2)：按目标模型 ASR 降序排序
    → AttackOrchestrator.execute_attack()
```

### 5.3 错误处理策略

| 场景 | 策略 |
|------|------|
| 凭据过期 | 标记为无效，继续执行（无凭据模式） |
| 侦察失败 | 记录错误，跳过攻击阶段（可配置） |
| 攻击失败 | 保存部分结果，生成报告 |
| 报告失败 | 打印错误，返回已有结果 |
