# config/ — 配置目录

## 文件结构

```
config/
├── runtime.yaml             运行时参数（考试模式 / PyRIT Memory / 报告）
├── targets/                 目标相关配置
│   ├── endpoints.yaml       公共端点定义（唯一定义源）
│   ├── ai_types.yaml         AI 系统类型识别规则（引用端点名，可扩展列表）
│   └── connection.yaml       目标连接（认证模板 / 目标参数 / 攻击映射）
├── defaults/                 调优默认值（非密钥，按需覆盖）
│   ├── model_params.yaml   模型推理参数（temperature / top_p / max_tokens）
│   ├── pipeline.yaml       Pipeline 运行参数（并发 / 超时 / verbose / 重试）
│   ├── http_client.yaml    HTTP 客户端参数（超时 / SSL验证 / 代理）
│   ├── paths.yaml          路径与输出（数据库 / 日志 / 报告路径）
│   └── README.md           defaults/ 目录说明
└── README.md               本文件
```

## 配置优先级

```
.env 环境变量  >  config/defaults/*.yaml  >  config/*.yaml  >  src/core/defaults/*.yaml
  ↑ 密钥/必改     ↑ 调优默认值              ↑ 架构级配置        ↑ 系统不可变默认
```

## 各文件职责

### runtime.yaml — 运行时参数
- `global`: debug / log_level / request_interval_ms
- `exam`: 考试模式开关 / 时长 / 报告格式
- `pyrit`: Memory 后端类型 / 并发数
- `report`: 报告格式 / OWASP / 证据 / 时间线 / CVSS 基准

### targets/ — 目标配置子目录

#### targets/endpoints.yaml — 公共端点定义
- `endpoints`: 端点名 → 路径映射（唯一定义源，修改路径只改这一处）
- `supported_endpoints`: 侦察探测的完整端点列表

#### targets/ai_types.yaml — AI 类型识别（列表格式）
- 列表格式，每个条目含 `name` 和 `endpoint_names`
- `endpoint_names` 引用 `endpoints.yaml` 中 `endpoints` 段的 key
- 扩展方式：在列表末尾追加新条目即可

#### targets/connection.yaml — 目标连接
- `authentication`: API Key / Bearer / Cookie / OAuth 认证模板
- `target`: 目标类型 / 认证模式 / 能力探测 / 速率限制 / 回调
- `target_to_attack_mapping`: 目标类型 → 推荐 Attack 类映射

### defaults/ — 调优默认值
- 非密钥的调优参数，有合理默认值
- 用户可通过 .env 环境变量覆盖
- 详见 `defaults/README.md`

## 扩展指南

### 添加新 AI 系统类型
1. 在 `targets/endpoints.yaml` 的 `endpoints` 段定义新端点（如 `my_endpoint: "/my/api"`）
2. 在 `targets/ai_types.yaml` 的 `ai_types` 列表末尾追加：
```yaml
  - name: my_new_type
    description: "新类型说明"
    endpoint_names: [my_endpoint]      # 引用 endpoints 段的 key
    pyrit_attackable: true
    recommended_attacks:
      - PromptSendingAttack
```

### 修改端点路径
只需修改 `targets/endpoints.yaml` 中 `endpoints` 段的对应值，所有引用该端点的 AI 类型自动更新。

### 添加新认证模板
编辑 `targets/connection.yaml` 的 `authentication` 段，添加新模板。
