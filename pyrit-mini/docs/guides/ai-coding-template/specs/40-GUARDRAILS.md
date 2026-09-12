# 40 — ${PROJECT_NAME} 护栏（Guardrails）

> 红线 + 质量关卡。问题等级（BLOCKING/WARNING/INFO）定义见 `ai-dev-audit.md` §4。详见 `ai-dev-guides.md` §4.4。

## 红线分类
| 类别 | 级别 | 检查方式 |
|------|------|---------|
| 机器红线 R-L | BLOCKING | guard 自动 |
| 人工红线 R-H | WARNING | diff 评审 |
| 安全红线 R-S | BLOCKING | 人工评审 |
| 跨模型红线 R-CROSS | WARNING | 跨模型审查 |

## 自定义红线清单（示例，按项目启用检查器）
| # | 名称 | 检查器 |
|---|------|--------|
| R-L1 | 业务逻辑红线 | `check_red_line_1()` |
| R-L2 | 自定义基类替代框架原生 | `check_native_first()` |
| R-H1 | 静默降级 stub 进主干 | `check_stub()` |
| R-H2 | 静默吞错 `except: pass` | `check_bare_except()` |
| R-H3 | 双轨新增 | `check_dual_track()` |
| R-H4 | 配置断点硬编码 | `check_hardcoded()` |
| R-H5 | 数据旁路 | `check_data_bypass()` |

## 安全红线（政策级，详见 `ai-dev-guides.md` §4.5）
- R-SEC-01 禁止未净化外部输入参与代码执行
- R-SEC-02 禁止未授权系统命令调用
- R-SEC-03 禁止输出 PII / 密钥 / 凭证
- R-SEC-04 禁止已知 CVE 依赖
- R-SEC-05 禁止绕过安全检查
- R-SEC-06 敏感操作须审计日志
- R-SEC-07 依赖更新须安全扫描

## 质量关卡（Gate Stages，开发必跑）
- 基础版：`${LINT_CMD}` → `${TEST_CMD}`
- 生产版：`${GUARD_CMD}` → `${LINT_CMD}` → `${TEST_CMD}` → `${DRYRUN_CMD}` → `${DRIFT_CMD}` → `${DATAFLOW_CMD}`
- 跨模型版：以上 + `${CROSSMODEL_CMD}`（见 `ai-dev-audit.md` §5）
