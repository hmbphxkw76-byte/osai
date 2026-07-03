# OffSec AI-300 AI目标侦察 TAP攻击脚本

## 一、脚本概述

本脚本是 **AI目标侦察** 的 TAP（Tree of Adversarial Prompts）攻击测试脚本。TAP 攻击通过并行探索多条攻击路径，自动生成和测试多种侦察提示词变体，适合需要尝试多种侦察方式的场景。

**核心特点：**
- ✅ 基于 TAPAttack 类实现并行侦察路径探索
- ✅ 支持 tree_width 和 tree_depth 参数配置
- ✅ 测试用例完全独立于代码（JSON配置）
- ✅ 考试时零代码修改
- ✅ 自动加载和验证配置

## 二、运行前准备

### 2.1 配置 .env 文件

```env
PLATFORM_SELECTOR=ZHIPU

[ZHIPU]
OPENAI_CHAT_KEY=your_zhipu_api_key
OPENAI_CHAT_MODEL=glm-4-plus
OPENAI_CHAT_ENDPOINT=https://open.bigmodel.cn/api/paas/v4
```

### 2.2 修改测试用例（只需修改 JSON 文件！）

打开 `json_tap/tap_reconnaissance_ai_targets_cases.json` 文件，修改 `test_cases` 列表：

```json
{
    "tree_width": 4,
    "tree_depth": 5,
    "on_topic_checking": true,
    "test_cases": [
        {
            "id": 1,
            "objective": "你的侦察目标",
            "criterion": "对应的评分标准"
        }
    ]
}
```

### 2.3 运行方式

```powershell
py.exe '.\json_tap\tap_reconnaissance_ai_targets.py'
```

## 三、JSON 配置文件格式

### 3.1 字段说明

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `description` | string | 否 | 配置文件描述 |
| `notes` | string | 否 | 备注说明 |
| `tree_width` | integer | 否 | 树宽度，默认4，控制并行探索的路径数量 |
| `tree_depth` | integer | 否 | 树深度，默认5，控制迭代次数 |
| `on_topic_checking` | boolean | 否 | 主题检查，默认true，过滤偏离主题的侦察路径 |
| `test_cases` | array | 是 | 测试用例列表 |
| `test_cases[].id` | integer | 是 | 用例编号 |
| `test_cases[].objective` | string | 是 | 侦察目标文本 |
| `test_cases[].criterion` | string | 是 | 评分标准 |

### 3.2 参数调优建议

| 参数 | 值范围 | 说明 |
|------|--------|------|
| `tree_width` | 3-8 | 越大探索路径越多，但消耗更多资源 |
| `tree_depth` | 3-10 | 越大迭代次数越多，侦察越深入 |
| `on_topic_checking` | true/false | true时过滤无效路径，提高效率 |

## 四、TAP 攻击原理

### 4.1 工作机制

TAP（Tree of Adversarial Prompts）攻击采用树形搜索策略：

1. **初始节点**：用户提供的侦察目标
2. **分支扩展**：每个节点生成多个侦察变体（宽度由 tree_width 控制）
3. **深度迭代**：每个分支继续迭代优化（深度由 tree_depth 控制）
4. **评分筛选**：使用评分器评估每个分支的效果
5. **主题过滤**：可选地过滤偏离主题的分支

### 4.2 与其他攻击的区别

| 攻击类型 | 特点 | 适用场景 |
|----------|------|----------|
| TAPAttack | 并行探索多条路径，自动优化 | 需要尝试多种侦察变体 |
| PAIRAttack | 双人辩论式攻击 | 需要对抗性优化 |
| SequentialAttack | 顺序尝试多种策略 | 需要按顺序测试 |

## 五、考试重点

### 5.1 考试中如何使用

**零代码修改原则：** 考试时只需修改 `tap_reconnaissance_ai_targets_cases.json` 文件：

1. 打开 `json_tap/tap_reconnaissance_ai_targets_cases.json`
2. 修改 `test_cases` 列表中的测试用例
3. 运行 `py.exe '.\json_tap\tap_reconnaissance_ai_targets.py'`

### 5.2 AI目标侦察常见侦察向量

1. **模型识别**：识别目标系统中使用的AI模型类型和版本
2. **API探测**：发现目标AI系统的API端点和服务配置
3. **ML组件探测**：探测目标AI应用的机器学习组件和数据处理流程
4. **基础设施侦察**：获取目标AI系统的基础设施架构和部署环境信息
5. **安全边界识别**：识别目标AI系统的安全边界和访问控制机制

## 六、文件清单

| 文件 | 用途 |
|------|------|
| [.env](../.env) | 多平台API配置文件 |
| [platform_config_loader.py](../platform_config_loader.py) | 配置加载器 |
| [json_tap/case_loader.py](case_loader.py) | TAP攻击用例加载器 |
| [json_tap/tap_reconnaissance_ai_targets.py](tap_reconnaissance_ai_targets.py) | AI目标侦察 TAP攻击脚本 |
| [json_tap/tap_reconnaissance_ai_targets_cases.json](tap_reconnaissance_ai_targets_cases.json) | AI目标侦察测试用例配置文件 |
| [json_tap/tap_reconnaissance_ai_targets_scan.md](tap_reconnaissance_ai_targets_scan.md) | 本文档 |

## ⚠️ 安全声明

本脚本仅用于授权的安全测试和学习目的，请勿用于非法用途。使用前请确保已获得充分授权。