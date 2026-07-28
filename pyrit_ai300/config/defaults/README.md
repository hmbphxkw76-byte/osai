# config/defaults/ — 优化默认值

本目录存放调优过的默认参数，按功能分类管理。

## 配置文件

| 文件 | 说明 | 关键参数 |
|------|------|----------|
| `pipeline.yaml` | 执行流水线参数 | 并发数、超时、停止策略、交互选择、重试配置 |
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
