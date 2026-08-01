# garak 目标侦察 — LLM 攻击面枚举

> **版本: 1.2.0**

基于 [garak](https://github.com/NVIDIA/garak) 原生框架的 **目标侦察** 工具，用于枚举目标 LLM 的攻击面（活跃 Probe + OWASP Top10 分类 + 模型模态/多生成能力），作为 LLM 安全扫描的前置阶段。

```
编辑 config/target.yaml → 运行 python main.py → 生成攻击面画像
```

## 快速开始

```bash
# 1. 安装 garak（以 editable 模式从源码安装，支持二次开发）
pip install -e /path/to/garak-source
# 或直接 pip install garak

# 2. 进入项目目录
cd garak-pipeline

# 3. 编辑 config/target.yaml，填入目标 LLM 信息

# 4. 一键侦察
python main.py
```

## 配置方式

**唯一需要修改的文件**: `config/target.yaml`

```yaml
# --- 目标模型 (被侦察的 LLM) ---
target:
  endpoint: "https://api.longcat.chat/openai/v1"
  model: "LongCat-2.0"
  api_key: "ak_xxx"

mode: "standard"
```

## 命令行覆盖

```bash
python main.py                          # 使用 target.yaml 默认配置
python main.py --config my_target.yaml  # 使用自定义配置文件
```

## 侦察内容

| 步骤 | 说明 | 产物 |
|------|------|------|
| 连通性测试 | openai SDK 测试目标 API 可达性 + 延迟 | `01_recon_{run_id}/connectivity_test_{run_id}.json` |
| Probe 枚举 | 动态枚举 garak 所有活跃 Probe（按 OWASP Top10 分类） | `01_recon_{run_id}/probe_candidates_{run_id}.json` |
| 模态侦察 | 探测模型输入/输出模态能力与多生成支持 | （写入 target_profile） |
| 目标画像 | 汇总上述信息生成目标画像 | `01_recon_{run_id}/target_profile_{run_id}.json` |

## 运行测试

```bash
python -m pytest tests/ -v
```

## 目录结构

```
garak-pipeline/
├── main.py              # 一键启动入口（纯编排）
├── config/              # 配置文件
│   └── target.yaml      # 唯一需要修改的配置文件
├── pipeline/            # 侦察核心模块
│   ├── __init__.py
│   ├── recon_garak.py   # garak Probe 枚举 + OWASP 分类（纯逻辑）
│   ├── stage1_recon.py  # Stage 1 目标侦察编排
│   └── utils.py         # 公共工具（配置加载 / pycache 清理）
├── outputs/             # 产物目录（侦察产物落在此处）
└── tests/               # 测试用例
```

> **目录约定**: 所有产物统一组织到 `outputs/` 下，根目录保持整洁。
