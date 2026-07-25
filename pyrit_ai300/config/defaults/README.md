# config/defaults/ — 默认配置目录

本目录存放**已调优的默认参数**，遵循最佳实践原则。

## 配置文件说明

| 文件 | 说明 | 典型参数 |
|------|------|----------|
| `model_params.yaml` | 模型推理参数 | temperature / top_p / max_tokens / reasoning_effort |
| `pipeline.yaml` | Pipeline 运行参数 | 并发数 / 超时 / verbose / 重试 |
| `http_client.yaml` | HTTP 客户端参数 | 超时 / SSL验证 / 代理 |
| `paths.yaml` | 路径与输出 | 数据库 / 日志 / 报告路径 |

## 配置优先级

```
显式 CLI 参数 > .env 环境变量 > config/defaults/*.yaml > 硬编码兜底
```

## 设计原则

1. **`.env` 只放用户每次必改的参数**：目标 URL、API Key、认证信息
2. **`config/defaults/` 放调优过的默认值**：temperature=0、超时阈值等
3. **`config/config.yaml` 放架构级配置**：攻击技术映射、端点探测、数据源

## 修改方式

- **临时修改**：在 `.env` 中覆盖对应环境变量
- **长期修改**：直接编辑本目录下的 YAML 文件
