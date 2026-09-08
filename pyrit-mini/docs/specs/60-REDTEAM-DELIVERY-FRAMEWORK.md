# 60-REDTEAM-DELIVERY-FRAMEWORK - 红队交付保障框架规范

> **版本**: v2.0
> **生效日期**: 2026-09-08
> **维护者**: AI Red Team
> **适用范围**: 所有包的任意模块和功能优化

## 1. 概述

本规范定义了 PyRIT Mini 项目的**红队交付保障框架** (Red Team Delivery Assurance Framework, RT-DAF)，确保所有代码修改和优化方案都能按照标准化流程执行，并自动验证完整性。

### 1.1 通用性原则

本框架 **不局限于特定模块**，适用于以下所有场景：

| 包 | 典型优化场景 |
|----|-------------|
| `strike/` | 攻击执行器、升级链、会话管理、MCP/RAG 攻击 |
| `recon/` | 侦察探针、目标构建、能力发现、隐蔽枚举 |
| `arm/` | 种子排序、技术选择、转换器链、数据集配置 |
| `assess/` | 评分管道、ASR 统计、双法官、自适应判断 |
| `core/` | 上下文管理、流水线编排、阶段执行器 |
| `report/` | 报告生成、证据收集、PoC 输出、SARIF |
| `utils/` | 显示层、攻击工具、干跑逻辑 |
| `tools/` | CLI 工具、架构守卫、验证器 |

## 2. 框架目标

| 目标 | 说明 |
|------|------|
| **完整性** | 确保优化方案的每个组件100%实现 |
| **一致性** | 代码修改遵循统一的设计原则和架构约束 |
| **可验证性** | 每次修改后自动验证所有依赖和集成点 |
| **可追溯性** | 清晰的审计日志追踪每个组件的实现状态 |
| **通用性** | 规则适用于任意包和任意功能优化 |

## 3. 架构守卫规则体系

### 3.1 R-DELIVERY 系列 — 通用交付流程规则

| 规则 | 描述 | 级别 | 检查内容 | 适用包 |
|------|------|------|----------|--------|
| R-DELIVERY-1 | 单点职责 | WARNING | 每个模块不超过 300 行 | 全部 (strike/recon/arm/assess/core/report/utils) |
| R-DELIVERY-2 | 测试覆盖率 | WARNING | 公共模块有对应测试文件 | strike/recon/arm/assess/core/report |
| R-DELIVERY-3 | 架构对齐 | BLOCKING | 新代码符合 10-ARCHITECTURE.md 分层 | 全部 (检查跨层导入) |
| R-DELIVERY-4 | 导出规范 | INFO | 公共 API 在 `__init__.py` 导出 | 全部包 |
| R-DELIVERY-5 | 文档一致性 | INFO | 新模块有 docstring 说明 | 全部包 |

### 3.2 R-SESSION 系列 — 会话感知攻击框架 (特定模块)

| 规则 | 描述 | 级别 | 检查内容 |
|------|------|------|----------|
| R-SESSION-1 | 模块完整性 | BLOCKING | 所有必需的会话模块和类已定义 |
| R-SESSION-2 | 集成完整性 | BLOCKING | executor/escalation/target_builder 已集成 |
| R-SESSION-3 | 配置文件 | WARNING | defaults.yaml 存在 |
| R-SESSION-4 | 测试覆盖 | WARNING | 核心模块有对应测试 |
| R-SESSION-5 | PyRIT 原生兼容 | BLOCKING | 通过 callback_function 集成 |
| R-SESSION-6 | Context 字段集成 | WARNING | PipelineContext 有 session_state 字段 |

### 3.3 其他规则系列

```
R-SIZE        : 文件大小限制 (< 850 行警告, > 1500 行阻塞)
R-CONV        : Converter 使用规范
R-IMPORT      : 导入依赖检查
R-STACK       : 堆叠限制
R-CLASS       : 禁止自定义类
R-TOOLS       : CLI 工具位置
R-PIPE        : 流水线集成完整性
R-REDTEAM     : 红队最佳实践
R-EVID        : 证据收集完整性
R-REPORT      : 报告生成完整性
R-NATIVE      : PyRIT 原生组件优先
R-DATA        : 数据流完整性
```

## 4. 代码修改标准流程 (通用)

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    代码修改标准流程 (任意模块)                            │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  1. 方案设计 (Design)                                                    │
│     ├── 确定修改范围和影响组件                                          │
│     ├── 对照架构守卫规则评估约束                                        │
│     ├── 确认模块所属包和分层职责                                        │
│     └── 编写设计说明 (如有必要)                                         │
│                                                                          │
│  2. 代码实现 (Implementation)                                            │
│     ├── 按照设计实现代码                                                │
│     ├── 确保 PyRIT 原生优先 (如适用)                                    │
│     ├── 保持模块 < 300 行 (R-DELIVERY-1)                               │
│     ├── 添加模块 docstring (R-DELIVERY-5)                               │
│     └── 在 __init__.py 导出公共 API (R-DELIVERY-4)                      │
│                                                                          │
│  3. 自动化验证 (Auto Verification)                                       │
│     ├── 运行 `py -m tools.guard` 检查架构规则                          │
│     │   └── R-DELIVERY-1~5 自动验证                                    │
│     ├── 运行 `ruff check` 检查代码质量                                  │
│     ├── 运行 `py_compile` 验证语法                                      │
│     └── 运行相关测试 `pytest tests/`                                    │
│                                                                          │
│  4. 集成验证 (Integration Verification)                                  │
│     ├── 确认所有集成点已更新                                            │
│     ├── 确认现有功能未破坏                                              │
│     ├── 确认新组件符合架构分层 (R-DELIVERY-3)                           │
│     └── 确认测试文件已创建 (R-DELIVERY-2)                               │
│                                                                          │
│  5. 最终审计 (Final Audit)                                               │
│     ├── 架构守卫: 0 BLOCKING                                            │
│     ├── ruff: 0 errors                                                  │
│     ├── 测试: 全部通过                                                  │
│     └── 文档: 已更新                                                    │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

## 5. 验证清单模板 (通用)

每次代码修改必须完成以下检查：

```markdown
## 交付验证清单

### 架构规则 (R-DELIVERY 通用)
- [ ] `py -m tools.guard` → 0 BLOCKING
- [ ] R-DELIVERY-1: 新模块 < 300 行
- [ ] R-DELIVERY-2: 新模块有对应测试文件
- [ ] R-DELIVERY-3: 架构分层对齐 (无跨层导入)
- [ ] R-DELIVERY-4: 公共 API 在 __init__.py 导出
- [ ] R-DELIVERY-5: 新模块有 docstring

### 代码质量
- [ ] `ruff check` → 0 errors
- [ ] `py_compile` → 全部通过

### 测试覆盖
- [ ] 单元测试: 全部通过
- [ ] 新模块测试: tests/test_<module>.py 存在且通过

### 集成点
- [ ] 新模块在 __init__.py 导出
- [ ] 消费者已更新 (如需要)
- [ ] PipelineContext 已更新 (如需要)
```

## 6. 自动化执行

### 6.1 架构守卫命令

```bash
# 运行全量检查 (包含所有 R-DELIVERY 规则)
py -m tools.guard

# 详细模式
py -m tools.guard -v
```

### 6.2 配置规范

```bash
# 代码质量检查
ruff check .
ruff check --fix .

# 语法验证
py -m py_compile path/to/module.py

# 测试运行
pytest tests/ -v
pytest tests/test_specific_module.py -v
```

### 6.3 Pre-commit Hook

项目已配置 `.git/hooks/pre-commit`，每次 commit 自动运行架构守卫。

## 7. 模块职责矩阵 (通用)

| 属性 | 规范 |
|------|------|
| **文件命名** | snake_case，描述性命名 |
| **行数限制** | 单文件 < 300 行 (R-DELIVERY-1) |
| **模块 docstring** | 必须包含模块功能、架构对齐、学术引用 (如适用) |
| **类型注解** | 所有公共方法必须有类型注解 |
| **测试文件** | 对应 `tests/test_<module>.py` (R-DELIVERY-2) |
| **公共 API** | 在 `__init__.py` 导出 (R-DELIVERY-4) |
| **架构对齐** | 符合 `10-ARCHITECTURE.md` 分层要求 (R-DELIVERY-3) |

## 8. 新增模块规范 (通用)

任何新增模块必须满足以下条件：

1. **目录结构**: 放入正确的包目录 (strike/, recon/, arm/, assess/, core/, report/, utils/, tools/)
2. **文件命名**: 使用 snake_case，描述性命名
3. **行数限制**: 单文件 < 300 行 (R-DELIVERY-1)
4. **模块 docstring**: 必须包含模块说明、架构对齐、学术引用 (R-DELIVERY-5)
5. **类型注解**: 所有公共方法必须有类型注解
6. **测试文件**: 对应 `tests/test_<module>.py` (R-DELIVERY-2)
7. **公共 API**: 在 `__init__.py` 导出 (R-DELIVERY-4)
8. **架构对齐**: 符合 `10-ARCHITECTURE.md` 分层要求 (R-DELIVERY-3)

## 9. 跨层导入规则 (R-DELIVERY-3)

```
允许的导入方向:
  recon → core (使用上下文)
  arm → core, recon (使用侦察数据)
  strike → core, arm, recon (使用武器化数据)
  assess → core, strike (使用攻击结果)
  report → core, assess (使用评分数据)
  utils → 无 (基础工具层)
  tools → 全部 (CLI 工具层)

禁止的导入方向:
  report → strike (报告层不应依赖攻击层)
  utils → 其他包 (工具层不应依赖业务层)
```

## 10. 附录：架构守卫完整规则列表

```
基础规则:
  R-SIZE        : 文件大小限制 (< 850 行警告, > 1500 行阻塞)
  R-CONV        : Converter 使用规范
  R-IMPORT      : 导入依赖检查
  R-STACK       : 堆叠限制
  R-CLASS       : 禁止自定义类
  R-TOOLS       : CLI 工具位置

流水线规则:
  R-PIPE        : 流水线集成完整性
  R-DATA        : 数据流完整性

红队规则:
  R-REDTEAM     : 红队最佳实践
  R-EVID        : 证据收集完整性
  R-REPORT      : 报告生成完整性
  R-NATIVE      : PyRIT 原生组件优先

交付保障规则 (通用):
  R-DELIVERY-1  : 单点职责 (模块 < 300 行)
  R-DELIVERY-2  : 测试覆盖率 (公共模块有测试)
  R-DELIVERY-3  : 架构对齐 (无跨层导入) [BLOCKING]
  R-DELIVERY-4  : 导出规范 (__init__.py 导出)
  R-DELIVERY-5  : 文档一致性 (模块 docstring)

会话感知规则 (特定):
  R-SESSION-1~6 : 会话感知攻击框架
```

---

**版本历史**:
- v2.0 (2026-09-08): 通用化重构，R-DELIVERY 规则适用于任意模块优化
- v1.0 (2026-09-08): 初始版本，包含 R-SESSION 和 R-DELIVERY 规则体系
