# third_party

本目录存放 AI-300 Monorepo 依赖的外部工具源码，保持与核心项目的清晰边界。

## 当前内容

| 目录 | 来源 | 用途 |
|---|---|---|
| `skillspector/` | NVIDIA SkillSpector 官方仓库 | 扫描 AI agent skill / MCP skill 的安全问题，由 `ai300-recon/src/integration/skillspector/` 包装后子进程或 Docker 调用 |

## 使用方式

### 子进程模式（推荐本地开发）

```bash
cd third_party/skillspector
pip install -e .
cd ../..
python ai300-recon/examples/run_recon_with_skillspector.py
```

### Docker 模式

```bash
docker compose -f ai300-recon/docker-compose.integration.yml --profile scan build skillspector
docker compose -f ai300-recon/docker-compose.integration.yml --profile scan up skillspector
```

## 设计原则

- `third_party/` 内的代码**不修改**：任何适配逻辑放在 `ai300-recon/src/integration/` 中。
- 版本升级时直接替换 `third_party/skillspector/` 目录内容即可。
