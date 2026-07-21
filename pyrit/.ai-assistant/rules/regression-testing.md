# 回归测试优先原则（强制）

**规则编号**: TEST-002
**生效日期**: 2026-07-20
**优先级**: 强制（MUST）

## 核心原则

**每次代码改动前，先准备回归测试；每次改动后，立即运行验证。**

这是 TDD（测试驱动开发）的简化版，适用于本项目的所有代码修改场景。

## 执行流程

### 改动前（准备阶段）

1. **分析影响面**：明确改动会影响哪些模块、函数、配置
2. **编写测试用例**：针对即将改动的行为编写测试（先写"期望正确"的测试）
3. **运行现有测试**：确保改动前的代码基线是绿的（`make test`）

```bash
# 改动前验证基线
python -m pytest pyrit_ai300/tests/ -v --tb=short
```

### 改动中（实施阶段）

1. **小步改动**：每次只改一个逻辑点，不要批量修改多个不相关模块
2. **即时验证**：每完成一个逻辑点，运行相关测试

```bash
# 快速验证回归测试（~5s）
python -m pytest pyrit_ai300/tests/test_regression.py -v
```

### 改动后（验证阶段）

1. **全量测试**：运行所有测试，确认无回归
2. **回归测试**：确保 `test_regression.py` 全部通过
3. **Lint 检查**：确保无 lint 错误

```bash
# 全量验证（~25s）
make test
# 或
python -m pytest pyrit_ai300/tests/ -v --tb=short

# Lint
make lint
```

## 测试文件规范

### 回归测试文件位置

```
pyrit_ai300/tests/test_regression.py   # 回归测试套件（覆盖历史 bug）
```

### 新增回归测试的场景

以下场景**必须**新增回归测试：

| 场景 | 示例 | 测试内容 |
|------|------|---------|
| 修复 bug | `KeyError: 'model_capabilities'` | 测试空 dict 的 setdefault 安全性 |
| 配置格式变更 | YAML 模板新增 `${VAR}` | 测试变量解析 + 模板一致性 |
| 安全相关修复 | `.env` 不回退到文件路径 | 测试 `_resolve_target` 不返回文件路径 |
| API 行为变更 | `load_spa_config` 返回结构 | 测试返回结构的完整性和正确性 |

### 测试命名规范

```python
class TestXxxSafety(unittest.TestCase):
    """回归测试：Xxx 安全性
    Bug: <bug 描述>
    """
    def test_xxx_does_not_crash(self):
        ...
```

## 反面案例（禁止）

### ❌ 改完代码不跑测试

```python
# 错误：改了 adapter.py 后直接提交
result_data["model_capabilities"]["parameters"] = result_data["model_parameters"]
# ↑ 改完后没跑测试 → KeyError 崩溃 → 用户报错
```

### ❌ 批量改多个模块后一次性测试

```python
# 错误：同时改 env_loader + adapter + pipeline + auth_mixin
# 然后一次性跑测试 → 无法定位哪个改动引入了 bug
```

### ✅ 正确做法

```python
# 1. 先写测试
def test_setdefault_model_capabilities():
    result_data = {}
    result_data.setdefault("model_capabilities", {})["parameters"] = {}

# 2. 运行测试（应该失败，因为旧代码用 [] 不是 setdefault）
# 3. 修复代码
result_data.setdefault("model_capabilities", {})["parameters"] = result_data["model_parameters"]
# 4. 运行测试（应该通过）
# 5. 运行全量测试（确认无回归）
```

## 测试覆盖率要求

| 模块 | 最低覆盖率 | 关键测试点 |
|------|-----------|-----------|
| `env_loader.py` | `${VAR}` 替换、`.env` 加载、降级处理 | URL 中的 `#` 不截断 |
| `recon_engine.py` | `load_spa_config` 环境变量解析 | 返回结构正确性 |
| `pipeline/orchestrator.py` | `_resolve_target` 不返回文件路径 | 空值降级 |
| `adapter.py` | `result_data` 嵌套 dict `setdefault` | `KeyError` 防护 |
| `auth_mixin.py` | `page.url` 异常安全 | SSO 配置传递 |
