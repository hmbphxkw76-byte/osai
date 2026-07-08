# 评估策略说明

> 本文档描述本项目的 LLM 评估策略和最佳实践

---

## 一、评估目标

### 1.1 核心目标
- **功能正确性**: 验证 LLM 是否能正确完成指定任务
- **安全性**: 检测安全漏洞和风险（红队测试）
- **一致性**: 确保输出质量的稳定性
- **合规性**: 符合 OWASP LLM Top 10 等安全标准

### 1.2 评估维度
| 维度 | 说明 | 测试方法 |
|------|------|----------|
| 功能质量 | 任务完成度、准确性 | 自动化断言 + 人工评审 |
| 安全性 | 注入、越狱、PII 泄露 | 红队测试 + 安全断言 |
| 性能 | 延迟、吞吐量 | 压测 + 性能监控 |
| 一致性 | 输出稳定性 | 多次运行对比 |
| 可解释性 | 结果可追溯 | 链路追踪 + 日志分析 |

---

## 二、评估方法

### 2.1 自动化评估
使用 promptfoo 进行自动化评估：

```bash
# 标准评估
promptfoo eval -c promptfooconfig.yaml

# 红队测试
promptfoo redteam run -c promptfooconfig.redteam.yaml

# 回归测试
promptfoo eval -c tests/regression/v1_baseline.yaml
```

### 2.2 人工评估
对于主观性较强的任务（如创意写作、风格判断），采用人工评审：
- 建立评分标准（Rubric）
- 多人盲评减少偏差
- 计算评审者间一致性（Kappa 系数）

### 2.3 A/B 对比测试
同时测试多个模型或提示词版本：

```yaml
targets:
  - id: 'openai:gpt-4o'
    label: 'GPT-4o'
  - id: 'anthropic:messages:claude-sonnet-4-20250514'
    label: 'Claude Sonnet'
```

---

## 三、红队测试策略

### 3.1 测试分层
| 层级 | 范围 | 频率 | 时间 |
|------|------|------|------|
| 快速扫描 | default 插件 + 基础策略 | 每次提交 | 5-10min |
| 标准测试 | 核心插件集 + 常用策略 | 每日构建 | 15-30min |
| 完整测试 | 全部插件 + 全部策略 | 每周/版本 | 45-60min |

### 3.2 攻击面覆盖
参考 LLM 渗透测试 测试模块，覆盖以下攻击面：
1. **提示注入与越狱**: 直接注入、间接注入、编码绕过
2. **数据泄露**: PII、会话泄露、跨租户数据访问
3. **权限绕过**: BOLA、BFLA、RBAC 绕过
4. **过度代理**: 工具滥用、目标偏移、权限提升
5. **有害内容**: 暴力、仇恨、色情、自伤
6. **供应链**: 模型投毒、插件漏洞、依赖风险
7. **多模态**: 图像注入、视觉越狱、OCR 绕过

### 3.3 严重级别定义
| 级别 | 定义 | 示例 |
|------|------|------|
| Critical | 可直接获取系统控制权 | 远程代码执行、系统完全越狱 |
| High | 可获取敏感信息或越权操作 | PII 泄露、越权访问他人数据 |
| Medium | 部分功能受影响或信息泄露 | 部分绕过、非敏感信息泄露 |
| Low | 影响较小的问题 | 输出格式异常、轻微幻觉 |
| Info | 仅作信息记录 | 最佳实践建议、风格问题 |

---

## 四、断言策略

### 4.1 内置断言类型
- `contains` / `not-contains`: 包含/不包含指定文本
- `icontains` / `not-icontains`: 大小写不敏感的包含检查
- `contains-any`: 包含任一指定值
- `regex` / `not-regex`: 正则表达式匹配
- `is-json`: JSON 格式验证
- `startswith` / `endswith`: 前缀/后缀检查
- `levenshtein`: 编辑距离
- `javascript`: 自定义 JavaScript 断言
- `python`: 自定义 Python 断言

### 4.2 自定义断言
复杂断言使用自定义脚本：
- JavaScript: `assertions/custom_assertion.js`
- Python: `assertions/semantic_similarity.py`

### 4.3 语义相似度
对于不要求精确匹配的场景，使用语义相似度断言：
- 模型: all-MiniLM-L6-v2 (轻量) / all-mpnet-base-v2 (高质量)
- 阈值建议:
  - 高相似: 0.85+
  - 中等相似: 0.7-0.85
  - 低相似: 0.5-0.7

---

## 五、数据集管理

### 5.1 数据集类型
| 类型 | 用途 | 格式 | 位置 |
|------|------|------|------|
| 黄金标准 | 核心功能验证 | JSON | `datasets/golden_dataset.json` |
| 真实对话 | 真实场景测试 | JSONL | `datasets/conversation_logs.jsonl` |
| 合成数据 | 边界/压力测试 | CSV | `datasets/synthetic_data.csv` |

### 5.2 数据版本管理
- 数据集纳入版本控制
- 重要变更记录在 CHANGELOG
- 使用数据卡片（Data Card）记录数据来源和处理方式

---

## 六、回归测试

### 6.1 基线建立
```bash
# V1 基线
promptfoo eval -c tests/regression/v1_baseline.yaml -o output/v1_results.json

# V2 测试
promptfoo eval -c tests/regression/v2_upgrade.yaml -o output/v2_results.json
```

### 6.2 结果对比
```bash
node scripts/compare_results.js output/v1_results.json output/v2_results.json
```

### 6.3 回归判定标准
- 通过率下降 > 5%: 严重回归
- 通过率下降 2-5%: 中等回归
- 通过率下降 < 2%: 轻微波动（可接受）

---

## 七、持续集成

### 7.1 CI/CD 流水线
1. **代码提交**: 触发快速扫描（5-10min）
2. **PR 构建**: 运行标准测试（15-30min）
3. **夜间构建**: 运行完整测试（45-60min）
4. **版本发布**: 运行完整测试 + 人工抽检

### 7.2 质量门禁
- 红队通过率 >= 95%
- 无 Critical / High 级别安全问题
- 功能测试通过率 >= 90%
- 无性能退化

---

## 八、最佳实践

### 8.1 提示词工程
- 使用 Nunjucks 模板引擎组织提示词
- 系统提示词与用户提示词分离
- 提示词版本化管理

### 8.2 测试设计
- 测试用例与代码分离
- 每个测试用例包含明确的断言
- 覆盖正常路径、边界情况、异常场景

### 8.3 结果分析
- 定期审查失败案例
- 分类归纳常见问题
- 将发现转化为新的测试用例

### 8.4 文档记录
- 重要变更记录在 changelog
- 评估方法和标准文档化
- 保留历史评估结果用于趋势分析
