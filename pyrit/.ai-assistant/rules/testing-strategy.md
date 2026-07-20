# 测试策略规则

## 规则编号: TEST-001

**生效日期**: 2026-07-16
**优先级**: 强制（MUST）

---

## 规则正文

### 1. 测试分层

| 阶段 | 跑什么 | 命令 | 耗时 | 定位 |
|------|--------|------|------|------|
| **每次代码修改后** | 单元测试（全量） | `make test` | ~15s | 快速发现回归 |
| **提交前 / 合并前** | Lint + 单元测试 | `make ci` | ~20s | 代码质量 + 正确性 |
| **发布前** | 覆盖率报告 | `make test-cov` | ~20s | 确认覆盖无退化 |

### 2. 核心原则

**本项目的单元测试就是回归测试。** 65 个测试覆盖 PayloadManager、SmartMatcher、PayloadClassifier、AttackOrchestrator 等核心模块，跑一遍就能发现绝大多数回归问题。

### 3. 执行时机（强制）

- **每次修改代码后**：必须跑 `make test`，确认全部通过
- **每次重构完成后**：跑 `make ci`（lint + test）
- **每次合并前**：全量扫描 + 确认清理
- **每次发布前**：跑 `make test-cov`，确认覆盖率无退化

### 4. 集成测试规范

集成测试 = 连接真实目标执行攻击，需要目标在线且耗时长，不适合"每次修改后"跑。

**执行时机**：
- 考试前用真实目标跑一次 `make run-module MODULE=single_agent` 验证端到端
- 日常开发只跑单元测试

### 5. 测试文件规范

- 测试文件命名：`test_<module>.py`
- 测试函数命名：`test_<function>_<scenario>`
- 使用 `pytest` 框架
- 运行：`make test` 或 `python -m pytest pyrit_ai300/tests/ -v`

---

## 违规示例

```
# ❌ 错误：修改代码后不跑测试就直接提交
git add . && git commit -m "update payload manager"

# ✅ 正确：修改代码 → 跑测试 → 确认通过 → 提交
make test  # 65 passed
git add . && git commit -m "update payload manager"
```
