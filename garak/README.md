# Garak — Layer 1: AI 安全侦查

> 基于 [Garak](https://github.com/NVIDIA/garak) 的 AI 安全侦查引擎 — 两阶段扫描 + 结构化安全画像。

## 功能

- **快速基线扫描**: Top-N 探针覆盖，30 秒快速评估
- **定向深度验证**: 基于基线结果的定向探针选择
- **漏洞指纹提取**: 可复现的漏洞特征描述
- **攻击路径推荐**: 自动推荐最优攻击向量
- **结构化安全画像**: 标准化 `security_profile.json` 输出

## 使用

```bash
# 基线扫描
python -m garak.scanner --target-url http://target:8080/v1 --scan-type baseline

# 深度扫描
python -m garak.scanner --target-url http://target:8080/v1 --scan-type deep

# 在 PyRIT 中调用
from garak import GarakScanner
scanner = GarakScanner(target_url="http://target:8080/v1", scan_type="deep")
profile = await scanner.run()
```

## 输出

扫描结果输出到 `garak/outputs/security_profile_*.json`。

## 依赖

- `garak` CLI (可选，通过 `pip install garak` 安装)
- 未安装时返回空安全画像（推荐攻击路径: prompt_injection + jailbreak）
