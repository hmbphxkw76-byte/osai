# config/defaults/ — 优化默认值

本目录存放调优过的默认参数，按功能分类管理。
`.env` 仅存放每次运行必须修改的凭证和端点，其余参数均在本目录配置。

## 配置文件

| 文件 | 说明 | 关键参数 |
|------|------|----------|
| `pipeline.yaml` | 执行流水线参数 | 策略模式、并发数、超时、停止策略、重试配置、最大尝试次数 |
| `model_params.yaml` | 模型推理参数 | temperature、top_p、max_tokens、reasoning_effort |
| `http_client.yaml` | HTTP 客户端参数 | 超时、SSL验证、HTTP/2、速率限制 |
| `paths.yaml` | 输出路径配置 | 数据库路径、日志目录、报告目录、证据目录 |

## 配置优先级

```
.env 环境变量 > config/defaults/*.yaml > config/runtime.yaml
```

## 修改方式

1. **快速覆盖**: 在 `.env` 中设置同名环境变量（大写 + 下划线）
2. **持久修改**: 直接编辑本目录下的 YAML 文件
3. **全局配置**: 编辑 `config/runtime.yaml`

## 参数速查

### pipeline.yaml

| 参数 | 环境变量 | 默认值 | 说明 |
|------|----------|--------|------|
| `strategy_mode` | `STRATEGY_MODE` | `academic` | 策略模式 (academic/exam/balanced) |
| `scenario_max_retries` | `SCENARIO_MAX_RETRIES` | `1` | Scenario 重试次数 |
| `owasp_success_threshold` | `OWASP_SUCCESS_THRESHOLD` | `0.5` | L2 OWASP 成功率阈值 |
| `max_attempts_per_objective` | `MAX_ATTEMPTS_PER_OBJECTIVE` | `5` | 每载荷最大尝试次数 |
| `adaptive_max_concurrency` | `ADAPTIVE_MAX_CONCURRENCY` | `4` | Adaptive 并发数 |
| `api_max_concurrency` | `API_MAX_CONCURRENCY` | `3` | API 级并发信号量 |
| `per_attack_timeout` | — | `180` | 单次攻击超时（秒） |
| `retry.max_num_attempts` | `RETRY_MAX_NUM_ATTEMPTS` | `3` | 低层 HTTP 重试次数 |

### model_params.yaml

| 参数 | 环境变量 | 默认值 | 说明 |
|------|----------|--------|------|
| `target.temperature` | `TARGET_TEMPERATURE` | `0.9` | 目标温度 (ASR 最大化) |
| `target.top_p` | `TARGET_TOP_P` | `0.95` | 核采样 |
| `judge.temperature` | — | `0` | 评分器温度 (确定性) |

### http_client.yaml

| 参数 | 环境变量 | 默认值 | 说明 |
|------|----------|--------|------|
| `target.timeout` | `TARGET_HTTPX_TIMEOUT` | `120` | HTTP 读取超时（秒） |
| `target.verify` | `TARGET_HTTPX_VERIFY` | `false` | SSL 证书验证 |
