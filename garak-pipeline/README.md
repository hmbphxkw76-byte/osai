# garak 目标侦察 — LLM 攻击面枚举

> **版本: 2.0.0**

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
| 连通性测试 | 级联探测目标 API 可达性（SDK → HTTP → POST） | `01_recon/connectivity_test_{run_id}.json` |
| Probe 枚举 | 动态枚举 garak 所有活跃 Probe（按 OWASP Top10 分类） | `01_recon/probe_candidates_{run_id}.json` |
| 模态侦察 | 探测模型输入/输出模态能力与多生成支持 | （写入 target_profile） |
| 目标画像 | 汇总上述信息生成目标画像 | `01_recon/target_profile_{run_id}.json` |

## 降级模式（Degraded Mode）

当目标端点不可达或非标准 OpenAI 兼容 API 时，侦察自动进入**降级模式**，不中断流水线。

### 连通性级联探测

连通性测试采用三级级联策略，覆盖从标准 API 到 Web 应用的全谱目标：

| 级别 | 方法 | 适用场景 | 状态 |
|------|------|---------|------|
| Level 1 | OpenAI SDK `/models` | 标准 OpenAI 兼容端点 | `ok` |
| Level 2 | 原始 HTTP GET `/models` | 非标准响应格式（纯文本/HTML） | `ok` |
| Level 3 | POST 最小对话请求 | 仅有对话 POST 页面的 Web 应用 | `degraded` |
| 全失败 | — | 端点完全不可达 | `failed` |

### 降级模式行为

| 场景 | 连通性 | 探针枚举 | 模态侦察 | Stage 3 |
|------|--------|---------|---------|---------|
| 正常 | `ok` | ✅ 正常 | ✅ generator 加载 | ✅ 直接执行 |
| POST 可达 | `degraded` | ✅ 正常 | ✅ 启发式推断 | ⚠️ 前置告警 |
| 不可达 | `failed` | ✅ 正常 | ✅ 启发式推断 | ⚠️ 前置告警 |
| 异常中断 | — | ✅ 已枚举探针保存 | — | ❌ RuntimeError |

### recon_coverage 可审计性

`target_profile.json` 包含 `recon_coverage` 字段，结构化记录每个侦察步骤的状态：

```json
{
  "recon_coverage": {
    "connectivity": "ok",          // ok | degraded | failed
    "probe_enumeration": "ok",     // ok | pending
    "modality_detection": "ok",    // ok | heuristic
    "classification": "ok"         // ok | pending
  }
}
```

### Stage 3 前置校验

进入攻击执行前，`preflight_check()` 函数检测以下风险：
- `target.endpoint` 为空
- `target.model` 为空或占位值 `unknown-model`
- 连通性状态为 `failed` 或 `degraded`
- 探针列表为空

告警输出到终端，不阻断执行（用户可选择 `--stage 1-2` 仅执行侦察）。

### 异常路径产物保存

即使 `run()` 中途异常（如 garak 未安装），仍保存：
- `connectivity_test.json`（已执行的连通性结果）
- `target_profile.json`（最小画像 + 错误信息 + recon_coverage）
- `probe_candidates.json`（如探针已枚举，R1 修复）

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
│   ├── stage1_recon.py  # Stage 1 目标侦察编排（含降级模式）
│   ├── stage3_execute.py # Stage 3 攻击执行（含 preflight_check）
│   ├── runner.py        # 流水线编排器（降级模式传播）
│   └── utils.py         # 公共工具（配置加载 / pycache 清理）
├── outputs/             # 产物目录（侦察产物落在此处）
└── tests/               # 测试用例
    ├── test_stage1_recon.py              # Stage 1 单元测试（30 个）
    └── test_degraded_mode_integration.py # 降级模式集成测试
```

> **目录约定**: 所有产物统一组织到 `outputs/` 下，根目录保持整洁。
