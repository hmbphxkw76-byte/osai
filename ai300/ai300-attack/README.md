# ai300-attack

基于 `ai300-recon` 侦察结果，调用 PyRIT / Garak 执行 LLM 对话层攻击。

## 职责

- 读取 `ai300-recon` 生成的 `TargetProfile` 和 `PyRITTargetConfig`
- 根据目标特征自动选择攻击策略
- 调用 Garak（子进程）或 PyRIT（Python 库）执行攻击
- 输出统一发现格式 `UnifiedFinding`

## 安装

```powershell
cd ai300-attack
pip install -e .
# 或安装 Garak 支持
pip install -e ".[garak]"
# 或安装 PyRIT 支持
pip install -e ".[pyrit]"
# 或全部安装
pip install -e ".[all]"
```

## 使用

```powershell
# 使用默认最新侦察结果
python -m ai300_attack.main --adapter garak

# 指定侦察结果
python -m ai300_attack.main \
  --profile ../ai300-recon/results/recon/profiles/example.json \
  --pyrit-target ../ai300-recon/results/recon/pyrit/example_pyrit_target.json \
  --adapter garak

# 仅预览策略
python -m ai300_attack.main --dry-run
```

## 目录结构

```
ai300-attack/
├── src/ai300_attack/
│   ├── adapters/        # Garak / PyRIT 适配器
│   ├── loaders/         # 侦察结果加载器
│   ├── strategies/      # 攻击策略选择器
│   ├── reporting/       # UnifiedFinding 报告
│   ├── cli.py
│   └── main.py
├── tests/
└── pyproject.toml
```

## 测试

```powershell
pytest ai300-attack/tests
```
