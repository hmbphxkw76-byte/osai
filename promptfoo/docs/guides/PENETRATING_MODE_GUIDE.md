# 渗透模式指南

> Promptfoo 红队测试的多种渗透模式选择指南
> 根据测试时间、目标和深度选择合适的测试模式

---

## 一、模式总览

本项目提供 5 种渗透模式，按深度递进：

```
快速扫描  →  标准测试  →  深度扫描  →  红队全量  →  针对性测试
  5-10min     10-20min     20-30min     30-45min     按需
```

| 模式 | 配置文件 | 插件数 | 策略数 | 时间 | 适用场景 |
|------|---------|:------:|:------:|:----:|---------|
| 快速扫描 | `promptfooconfig.quick.yaml` | ~5 | 2 | 5-10min | 初筛、摸底 |
| 标准测试 | `promptfooconfig.yaml` | ~15 | 5 | 10-20min | 日常测试 |
| 深度扫描 | `promptfooconfig.advanced.yaml` | ~25 | 8 | 20-30min | 关键漏洞深挖 |
| 红队全量 | `promptfooconfig.redteam.yaml` | ~30 | 10 | 30-45min | 全面安全评估 |
| 回归测试 | `promptfooconfig.regression.yaml` | - | - | 10-15min | 版本对比 |

---

## 二、模式详解

### 2.1 快速扫描模式 (Quick Scan)

**配置**: `promptfooconfig.quick.yaml`
**时间**: 5-10 分钟
**插件**: `default` + `policy`
**策略**: `basic` + `jailbreak`

**适用场景**:
- 测试第一步，快速了解目标基本安全状况
- CI/CD 流水线中的快速门禁
- 时间紧迫时的初步评估

**特点**:
- ✅ 速度快，覆盖核心漏洞
- ⚠️ 覆盖面有限，可能遗漏深层漏洞

```bash
promptfoo redteam run -c promptfooconfig.quick.yaml
```

### 2.2 标准测试模式 (Standard)

**配置**: `promptfooconfig.yaml`
**时间**: 10-20 分钟
**插件**: `default` + 注入/隐私/业务逻辑补充
**策略**: `basic` + `jailbreak` + `jailbreak:composite` + `base64` + `leetspeak`

**适用场景**:
- 日常安全测试
- 测试主要测试阶段
- 功能上线前评估

**特点**:
- ✅ 覆盖 OWASP LLM Top 10 核心项
- ✅ 多语言测试（5 种语言）
- ✅ 平衡速度与覆盖面

```bash
promptfoo redteam run  # 默认读取 promptfooconfig.yaml
```

### 2.3 深度扫描模式 (Deep Scan)

**配置**: `promptfooconfig.advanced.yaml`
**时间**: 20-30 分钟
**插件**: 逐个指定，精准控制
**策略**: 8 种策略（含 `rot13`、`crescendo`）

**适用场景**:
- 快速扫描发现问题后的深挖
- 关键漏洞类别的详细测试
- 测试中后期的针对性测试

**特点**:
- ✅ 每个插件有 `graderGuidance` 精准评分
- ✅ `testGenerationInstructions` 指导生成
- ✅ 多语言（7 种）
- ⚠️ 耗时较长

```bash
promptfoo redteam run -c promptfooconfig.advanced.yaml
```

### 2.4 红队全量模式 (Full Redteam)

**配置**: `promptfooconfig.redteam.yaml`
**时间**: 30-45 分钟
**插件**: 全量插件集（30+）
**策略**: 10 种策略
**语言**: 10 种语言

**适用场景**:
- 全面安全评估
- 版本发布前的完整测试
- 测试时间充裕时的深度测试

**特点**:
- ✅ 最全面的覆盖
- ✅ 包含所有攻击策略
- ✅ 10 种语言测试
- ⚠️ 耗时最长

```bash
promptfoo redteam run -c promptfooconfig.redteam.yaml
```

### 2.5 回归测试模式 (Regression)

**配置**: `promptfooconfig.regression.yaml`
**时间**: 10-15 分钟
**内容**: 功能一致性 + 安全一致性

**适用场景**:
- 模型版本升级前后对比
- 提示词修改后的行为验证
- 漂移监控

**流程**:
```bash
# 1. 建立基线
promptfoo eval -c tests/regression/v1_baseline.yaml -o output/v1.json

# 2. 升级后测试
promptfoo eval -c tests/regression/v2_upgrade.yaml -o output/v2.json

# 3. 对比结果
node scripts/compare_results.js output/v1.json output/v2.json
```

---

## 三、场景化模块选择

除上述通用模式外，`redteam/modules/` 提供 20 个场景专用模块：

### 3.1 按目标类型选择

| 目标类型 | 推荐模块 | 插件数 | 时间 |
|---------|---------|:------:|:----:|
| 基础 LLM API | `foundation_model_redteam.yaml` | 18 | 15-25min |
| 聊天机器人 | `chatbot_redteam.yaml` | 16 | 10-15min |
| RAG 系统 | `rag_redteam.yaml` | 18 | 15-20min |
| 多智能体 | `agent_redteam.yaml` | 19 | 20-30min |
| MCP 协议 | `mcp_redteam.yaml` | 22 | 25-30min |
| A2A 协议 | `a2a_redteam.yaml` | 24 | 25-30min |
| 编码助手 | `coding_agent_redteam.yaml` | 25 | 20-25min |
| 多模态 | `multi_modal_redteam.yaml` | 15 | 15-20min |
| 多输入 API | `multi_input_redteam.yaml` | 14 | 20-30min |

### 3.2 按合规标准选择

| 标准 | 推荐模块 | 插件数 | 时间 |
|------|---------|:------:|:----:|
| OWASP LLM Top 10 | `owasp_llm_top10.yaml` | 25 | 30-40min |
| Agentic AI Top 10 | `agentic_ai_top10.yaml` | 28 | 35-45min |
| MCP Top 10 | `mcp_top10.yaml` | 25 | 25-30min |
| A2A Top 10 | `a2a_top10.yaml` | 22 | 25-30min |

### 3.3 全量覆盖

| 模块 | 说明 | 插件数 | 时间 |
|------|------|:------:|:----:|
| `broad_automated_scan.yaml` | 全量扫描 | 35 | 20-30min |
| `full_attack_suite.yaml` | 终极套件 | 55+ | 45-60min |

---

## 四、测试模式选择策略

### 4.1 时间分配建议（24 小时测试）

| 阶段 | 时间 | 模式 | 目的 |
|------|------|------|------|
| 初始侦察 | 0-1h | 快速扫描 | 摸底，了解基本安全状况 |
| 深入测试 | 1-8h | 场景模块 | 根据场景类型选择对应模块 |
| 深度挖掘 | 8-16h | 深度扫描 | 对发现的问题深挖 |
| 全面覆盖 | 16-20h | 红队全量 | 确保不遗漏 |
| 报告整理 | 20-24h | - | 整理发现，编写报告 |

### 4.2 按场景类型选择

```
测试场景描述                        →  推荐模式

"快速测试 + 初步评估"               →  快速扫描 (quick)
"标准安全测试"                      →  标准测试 (默认)
"深度安全评估"                      →  深度扫描 (advanced)
"全面红队测试"                      →  红队全量 (redteam)
"不确定目标类型"                    →  chatbot_redteam.yaml (覆盖面最广)
"特定场景 (RAG/Agent/MCP等)"        →  对应 redteam/modules/ 模块
```

### 4.3 渐进式测试流程

```bash
# 第 1 步：快速摸底（5-10min）
cp promptfooconfig.quick.yaml promptfooconfig.yaml
promptfoo redteam run

# 第 2 步：根据场景选模块深挖（15-30min）
cp redteam/modules/rag_redteam.yaml promptfooconfig.yaml
promptfoo redteam run

# 第 3 步：深度扫描关键漏洞（20-30min）
promptfoo redteam run -c promptfooconfig.advanced.yaml

# 第 4 步：全量覆盖（如时间允许，30-45min）
promptfoo redteam run -c promptfooconfig.redteam.yaml
```

---

## 五、运行命令速查

```bash
# 快速扫描
promptfoo redteam run -c promptfooconfig.quick.yaml

# 标准测试（默认配置）
promptfoo redteam run

# 深度扫描
promptfoo redteam run -c promptfooconfig.advanced.yaml

# 红队全量
promptfoo redteam run -c promptfooconfig.redteam.yaml

# 强制重新生成（不用缓存）
promptfoo redteam run --force

# 查看报告
promptfoo redteam report

# 回归测试
promptfoo eval -c promptfooconfig.regression.yaml

# 一键脚本
./scripts/run_eval.sh                    # 标准评估
./scripts/run_redteam.sh                 # 红队测试
node scripts/compare_results.js a.json b.json  # 结果对比
```

---

## 相关文档

- [架构说明](ARCHITECTURE.md) - 项目整体架构
- [前沿漏洞类型](FRONTIER_VULNS.md) - 各模式针对的漏洞
- [Payload 加载机制](PAYLOAD_LOADING.md) - 攻击 payload 流程
- [开发规范 - 配置模式](../dev-standards/config-patterns.md) - 测试最佳实践
- [开发规范 - YAML 模式](../dev-standards/yaml-patterns.md) - 模块选择指南
- [测试大纲映射](../reference/module_mapping.md) - LLM 渗透测试 模块完整映射
