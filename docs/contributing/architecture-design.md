# 架构分层与数据流

## 分层依赖图

```
main.py (90行入口)
  │
  ▼
entrypoint/       ← CLI 层（解析→回显→引导→路由）
  │  parser.py        argparse 参数定义
  │  display.py       Rich 控制台回显
  │  bootstrap.py     环境初始化 + BootstrapContext
  │  router.py        命令分发
  │
  ├──→ orchestrators/  ← 编排层（攻击工作流）
  │      pyrit_orchestrator.py     PyRITNativeOrchestrator (Facade)
  │      scenario_runner.py        PyRITScenarioRunner
  │
  ├──→ executor/       ← 执行引擎层
  │      single.py         单轮攻击
  │      crescendo.py      Crescendo 多轮
  │      exploring.py      探索模式
  │      scorer.py         多维度评分
  │      dashboard.py      Rich 仪表盘
  │
  ├──→ converters/     ← 攻击策略层
  │      registry.py       攻击组合注册表
  │      jailbreak.py      越狱前缀
  │      injection.py      注入类
  │      bypass.py         绕过类
  │      reasoning.py      推理/宪法
  │
  ├──→ targets/        ← 目标抽象层
  │      config.py              .env 配置加载
  │      factories.py           Target 工厂
  │      openai_sdk_target.py   OpenAICompatibleTarget (openai SDK)
  │      gemini_target.py       GeminiTarget (google-genai SDK)
  │      claude_target.py       ClaudeTarget (anthropic SDK)
  │      http_target.py         CustomHttpChatTarget (raw 格式兜底)
  │      model_probe.py         模型探测
  │      auto_probe.py          自动探测
  │      target_builder.py      统一 Target 构建工厂
  │
  ├──→ datasets/       ← 数据层（只读 YAML）
  │      loader.py         Payload 加载器
  │      payloads/         YAML Payload 文件
  │
  └──→ reporting/      ← 报告层
         engine.py         攻击推荐引擎
         heatmap.py        热力图
         terminal.py       终端报告
```

## 数据流

```
CLI args ──→ parser ──→ BootstrapContext ──→ router ──→ orchestrator
                 │              │                            │
                 ▼              ▼                            ▼
            .env 加载     Target 创建              executor 执行
            configs/*      Payload 加载              converters 转换
                           Memory 初始化             scorer 评分
                                                     reporting 报告
```

## 关键设计模式

### Facade 模式（Orchestrator）

`PyRITNativeOrchestrator` 整合 9 种攻击策略的调度，对外暴露统一接口。
内部组合 scorer、executor、converter、reporter 的子模块。

### Bootstrap 模式

`bootstrap_environment()` 函数一次性完成所有初始化步骤，返回 `BootstrapContext` dataclass。
失败时返回 `None`，调用方检查后退出，避免部分初始化状态。

### Factory 模式（Target）

`create_scorer_target()` / `create_attack_target()` / `build_custom_target()` 三个工厂函数
统一所有 Target 创建逻辑，调用方不直接实例化 Target 类。

**Target 选型标准（SDK 优先，不重复造轮子）：**

| API 类型 | Target 类 | SDK | 文件 |
|---|---|---|---|
| OpenAI / Ollama / vLLM 等 | `OpenAICompatibleTarget` | `openai` | `targets/openai_sdk_target.py` |
| Google Gemini | `GeminiTarget` | `google-genai` | `targets/gemini_target.py` |
| Anthropic Claude | `ClaudeTarget` | `anthropic` | `targets/claude_target.py` |
| 非标准 Web Chat API | `CustomHttpChatTarget` | `httpx` (手工) | `targets/http_target.py` |

**选型规则**：
1. 所有主流 LLM API 必须使用对应官方 SDK 实现，禁止手工构造 HTTP 请求
2. `CustomHttpChatTarget` 仅作为非标准 API 的兜底方案，**禁止向其添加新 API 格式**
3. 新增 API 接入时，优先使用已有 SDK；若无对应 SDK，在 `contributing/` 中补充理由
4. `CustomHttpChatTarget` 代码保持最小化：`{"prompt": text}` 固定格式，不做字段级解析

### Router 模式（Command Dispatch）

`route_command()` 根据 CLI 参数将请求分发到不同执行模式：
- `--penetrating-mode` → 渗透模式
- `--exploring-template` → 探索模式
- `--orch legacy` → 旧版引擎
- 默认 → PyRIT 原生模式

### Strategy 模式（Scorer）

`executor/scorer.py` 中的评分引擎根据攻击类型自动选择评分策略：
- 普通攻击 → 标准评分
- 越狱攻击 → 防假阴性评分
- 编码绕过 → 解码后评分
