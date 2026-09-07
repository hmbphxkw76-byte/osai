#!/usr/bin/env python3
"""Utility to replace Chinese comments/docstrings with English equivalents - v2 with comprehensive mapping."""
import re
from pathlib import Path

# Extensive translation mapping
TRANSLATIONS = {
    # ===== main.py module docstring =====
    "PyRIT 攻击链路入口 (纯编排层)。": "PyRIT attack pipeline entry point (orchestration layer).",
    "攻击链路 (6 阶段, arXiv:2407.01232 — PyRIT 原生框架):": "Attack pipeline (6 phases, arXiv:2407.01232 - PyRIT native framework):",
    "① recon     → Burp 拦截: 读取 HTTP 请求 + 侦察: 解析, 探测能力指纹, 构建 HTTPTarget": "① recon     -> Burp intercept: read HTTP requests + recon: parse, probe capability fingerprint, build HTTPTarget",
    "② arm       → 种子选取: 从 YAML 种子文件加载, 按历史 ASR 排序 + Converter: 构建 L5 最优链": "② arm       -> Seed selection: load from YAML seed files, sort by historical ASR + Converter: build L5 optimal chain",
    "③ strike    → 攻击发送: PyRIT 原生 PromptSendingAttack 多路径执行 (FIRST_SUCCESS)": "③ strike    -> Attack execution: PyRIT native PromptSendingAttack multi-path execution (FIRST_SUCCESS)",
    "④ escalate  → 多轮升级: Crescendo→TAP→PAIR→GCG→native (ASR<90% 触发, 含中间退出)": "④ escalate  -> Multi-turn escalation: Crescendo->TAP->PAIR->GCG->native (triggered when ASR<90%, with mid-exit)",
    "⑤ assess    → 评分判定: T0→J1→J2→J3 级联评分, ASR 统计, Wilson CI, 双 Judge 交叉验证": "⑤ assess    -> Scoring: T0->J1->J2->J3 cascade scoring, ASR statistics, Wilson CI, dual Judge cross-validation",
    "(or_aggregation OR 聚合追踪, scorer_metrics T0 评分器指标)": "(or_aggregation OR aggregation tracking, scorer_metrics T0 scorer metrics)",
    "⑥ report    → 报告生成: 证据收集 + MD/HTML/JSON/PoC/SARIF": "⑥ report    -> Report generation: evidence collection + MD/HTML/JSON/PoC/SARIF",
    "不指定 --stage 时按顺序执行全部 6 个阶段 (strike+escalate 合为一步), 向后兼容。": "When --stage is not specified, all 6 phases are executed in order (strike+escalate combined), backward compatible.",
    "指定 --stage <name> 时执行到该阶段完成后停止, 便于分阶段开发和调试。": "When --stage <name> is specified, stop after that phase completes, for phased development and debugging.",
    "模块化架构:": "Modular architecture:",
    "core/       — 流水线编排 (orchestrator), 上下文 (context), 配置 (config), 日志 (logging_config), 清理 (cleanup)": "core/       - Pipeline orchestrator, context, config, logging, cleanup",
    "recon/      — Burp 拦截, HTTP 解析, 目标指纹, 能力探测": "recon/      - Burp intercept, HTTP parsing, target fingerprint, capability probe",
    "arm/        — 种子选取, Converter 链, 技术选择": "arm/        - Seed selection, Converter chain, technique selection",
    "strike/     — 攻击执行, 多路径, 升级链": "strike/     - Attack execution, multi-path, escalation chain",
    "assess/     — 评分器, ASR 统计, 双 Judge": "assess/     - Scorer, ASR statistics, dual Judge",
    "report/     — 证据收集, 报告生成 (MD/HTML/JSON/PoC/SARIF)": "report/     - Evidence collection, report generation (MD/HTML/JSON/PoC/SARIF)",
    "targets/    — RateLimitedTarget, 内容过滤": "targets/    - RateLimitedTarget, content filtering",
    "utils/      — 终端输出, 缓存清理": "utils/      - Terminal output, cache cleanup",
    "使用方式:": "Usage:",
    "# 全火力模式 (AI-300 考试首选 — 最高 ASR 配置)": "# Full power mode (AI-300 exam preferred - highest ASR configuration)",
    "# 分阶段执行 (--stage 控制, 6 个阶段可独立调试):": "# Phased execution (--stage control, 6 phases can be debugged independently):",
    "# 自定义参数": "# Custom parameters",
    
    # ===== adapters/__init__.py =====
    "PyRIT 原生组件适配器层（包装与扩展）。": "PyRIT native component adapter layer (wrapping and extension).",
    "对齐 PyRIT 1.0.1 原生 Target 体系:": "Aligned with PyRIT 1.0.1 native Target system:",
    "本包不替代 PyRIT 原生 Target, 仅提供增强包装器:": "This package does not replace PyRIT native Targets, only provides enhanced wrappers:",
    "PyRIT 1.0.1 原生 Target (直接使用):": "PyRIT 1.0.1 native Target (direct use):",
    "OpenAIChatTarget: Chat Completions API (gpt-4o, DeepSeek 等)": "OpenAIChatTarget: Chat Completions API (gpt-4o, DeepSeek, etc.)",
    "OpenAIResponseTarget: Responses API (o1/o3/GPT-5)": "OpenAIResponseTarget: Responses API (o1/o3/GPT-5)",
    "LiteLLMChatTarget: 100+ LLM 提供商 (Anthropic, Bedrock, Vertex)": "LiteLLMChatTarget: 100+ LLM providers (Anthropic, Bedrock, Vertex)",
    "HTTPTarget: 原始 HTTP 请求 (Burp 场景)": "HTTPTarget: Raw HTTP request (Burp scenario)",
    "HTTPXAPITarget: API 模式 (文件上传/multipart)": "HTTPXAPITarget: API mode (file upload/multipart)",
    "PlaywrightTarget: 浏览器自动化 (JS 渲染 Chat UI)": "PlaywrightTarget: Browser automation (JS rendered Chat UI)",
    "RoundRobinTarget: 多目标轮询 (负载分散)": "RoundRobinTarget: Multi-target polling (load distribution)",
    "本包增强模块:": "This package enhancement modules:",
    "RateLimitedTarget: 并发控制 + 认证恢复 + 能力验证": "RateLimitedTarget: Concurrency control + auth recovery + capability verification",
    "(PyRIT 原生 @limit_requests_per_minute + @pyrit_target_retry": "(PyRIT native @limit_requests_per_minute + @pyrit_target_retry",
    "装饰器保留在被包装 target 上)": "decorators preserved on wrapped target)",
    "ContentFilterExt: 扩展 PyRIT 原生 CONTENT_FILTER_MARKERS": "ContentFilterExt: Extends PyRIT native CONTENT_FILTER_MARKERS",
    "(直接扩展 exception_classes 模块属性)": "(directly extends exception_classes module attribute)",
    "原生组件映射 (Rule 2: PyRIT 原生优先):": "Native component mapping (Rule 2: PyRIT native priority):",
    "| 层 | MUST use (PyRIT native) | Enhancement (本包) |": "| Layer | MUST use (PyRIT native) | Enhancement (this package) |",
    "|-------|-------------------------|--------------------------|": "|-------|-------------------------|--------------------------|",
    "| Target | OpenAIChatTarget, OpenAIResponseTarget, HTTPTarget, HTTPXAPITarget, LiteLLMChatTarget, PlaywrightTarget, RoundRobinTarget | RateLimitedTarget (并发+认证)": "| Target | OpenAIChatTarget, OpenAIResponseTarget, HTTPTarget, HTTPXAPITarget, LiteLLMChatTarget, PlaywrightTarget, RoundRobinTarget | RateLimitedTarget (concurrency+auth)",
    "| RPM 限速 | @limit_requests_per_minute | RateLimitedTarget 透传": "| RPM limit | @limit_requests_per_minute | RateLimitedTarget passthrough",
    "| 重试 | @pyrit_target_retry (tenacity) | RateLimitedTarget 透传": "| Retry | @pyrit_target_retry (tenacity) | RateLimitedTarget passthrough",
    "| 错误处理 | _handle_openai_request_async | 不覆盖": "| Error handling | _handle_openai_request_async | Not overridden",
    "| 内容过滤 | CONTENT_FILTER_MARKERS | ContentFilterExt 扩展": "| Content filtering | CONTENT_FILTER_MARKERS | ContentFilterExt extension",
    "| 能力验证 | TargetRequirements.validate() | RateLimitedTarget 调用": "| Capability verification | TargetRequirements.validate() | RateLimitedTarget invocation",
    "| 能力发现 | discover_target_capabilities_async | RateLimitedTarget.apply_discovered_capabilities": "| Capability discovery | discover_target_capabilities_async | RateLimitedTarget.apply_discovered_capabilities",
    "| 目标路由 | recon/target_router.py 统一路由 | —": "| Target routing | recon/target_router.py unified routing | —",
    "惰性导入 content_filter 模块函数。": "Lazy import content_filter module functions.",
    
    # ===== arm/__init__.py =====
    "种子选取 + Converter 转换阶段。": "Seed selection + Converter transformation phase.",
    "攻击链路第 2-3 步:": "Attack pipeline steps 2-3:",
    "种子选取: 从 YAML 种子文件加载攻击种子, 按历史 ASR 排序": "Seed selection: Load attack seeds from YAML seed files, sort by historical ASR",
    "Converter 转换: 构建 L5 最优 Converter 链 (编码/说服/分解/混淆)": "Converter transformation: Build L5 optimal Converter chain (encoding/persuasion/decomposition/obfuscation)",
    "核心模块:": "Core modules:",
    "seed_ranker: 种子加载 + ASR 排序 + 语言自适应": "seed_ranker: Seed loading + ASR sorting + language adaptation",
    "converter_chains: L5 专家级 Converter 链定义": "converter_chains: L5 expert-level Converter chain definitions",
    "converter_presets: l5_optimal 预设 + build_converter_map": "converter_presets: l5_optimal preset + build_converter_map",
    "technique_picker: 攻击技术选择 (单轮/多轮/自适应)": "technique_picker: Attack technique selection (single-turn/multi-turn/adaptive)",
    "converter_selector: Converter 候选选择 + OWASP 优先级 + ASR 裁剪": "converter_selector: Converter candidate selection + OWASP priority + ASR pruning",
    
    # ===== assess/__init__.py =====
    "评分判定阶段。": "Scoring phase.",
    "攻击链路第 5 步: 对攻击结果进行评分, 计算 ASR, 双 Judge 交叉验证。": "Attack pipeline step 5: Score attack results, calculate ASR, dual Judge cross-validation.",
    "核心模块 (SSOT):": "Core modules (SSOT):",
    "score_pipeline: 评分管线 (响应解析 + 异步预计算, 原 precompute + response_parser 合并)": "score_pipeline: Scoring pipeline (response parsing + async precompute, merged from precompute + response_parser)",
    "asr_manager: ASR 统一管理 (统计 + 历史 + 联合 ASR, 原 asr_compute + asr_history + joint_asr 合并)": "asr_manager: ASR unified management (statistics + history + joint ASR, merged from asr_compute + asr_history + joint_asr)",
    "asr_stats: 双 Judge 统计 + Cohen's Kappa + Wilson Score CI (全局计数器 SSOT)": "asr_stats: Dual Judge statistics + Cohen's Kappa + Wilson Score CI (global counter SSOT)",
    "scorer: 评分器注册 (AdaptiveDualJudgeScorer + fallback)": "scorer: Scorer registration (AdaptiveDualJudgeScorer + fallback)",
    "adaptive_dual_judge: 自适应双 Judge (高置信度直接返回)": "adaptive_dual_judge: Adaptive dual Judge (high confidence direct return)",
    "judge_manager: LLM 双判 + 仲裁 + 并发式判": "judge_manager: LLM dual judging + arbitration + concurrent judging",
    
    # ===== Common code comments =====
    "主流程入口": "Main entry",
    "初始化环境": "Initialize environment",
    "启动攻击链路编排器": "Start attack pipeline orchestrator",
    "编排逻辑委托给": "Orchestration delegated to",
    "此处仅负责:": "This function only handles:",
    "此处仅负责": "This function only handles",
    "日志配置 (终端 WARNING+, 文件全量 INFO)": "Logging configuration (terminal WARNING+, file INFO)",
    "日志配置": "Logging configuration",
    "信号处理 (SIGINT/SIGTERM 优雅退出)": "Signal handling (SIGINT/SIGTERM graceful exit)",
    "信号处理": "Signal handling",
    "优雅退出": "graceful exit",
    "参数解析 + 环境初始化 (PyRIT DB)": "Parameter parsing + environment initialization (PyRIT DB)",
    "参数解析": "Parameter parsing",
    "环境初始化": "Environment initialization",
    "流水线上下文构建 (PipelineContext)": "Pipeline context construction (PipelineContext)",
    "流水线上下文构建": "Pipeline context construction",
    "生产级 try/finally 保障资源清理": "Production-grade try/finally ensure resource cleanup",
    "生产级": "Production-grade",
    "保障资源清理": "ensure resource cleanup",
    "导入核心模块": "Import core modules",
    "R11: 导入": "R11: Import",
    "Scenario 路由器以启用目标感知攻击链": "Scenario router to enable target-aware attack chain",
    "R1: 精准投放四大机制集成声明": "R1: Four precision delivery mechanism integration declarations",
    "机制1 (三级Converter排序): arm/converter_selector.py → orchestrator 调用": "Mechanism 1 (three-level Converter sorting): arm/converter_selector.py -> orchestrator call",
    "机制2 (ASR历史排序UCB1): arm/seed_ranking.py _rank_by_asr + save_asr_history": "Mechanism 2 (ASR history sorting UCB1): arm/seed_ranking.py _rank_by_asr + save_asr_history",
    "机制3 (0%ASR种子裁剪): arm/seed_ranker.py _prune_zero_asr_seeds": "Mechanism 3 (0% ASR seed pruning): arm/seed_ranker.py _prune_zero_asr_seeds",
    "机制4 (模型特定先验): load_asr_priors(model_family) + update_asr_priors(model_family, asr)": "Mechanism 4 (model-specific priors): load_asr_priors(model_family) + update_asr_priors(model_family, asr)",
    "数据流: load_seeds(model_family=...) → save_asr_history() → update_asr_priors()": "Data flow: load_seeds(model_family=...) -> save_asr_history() -> update_asr_priors()",
    "数据流": "Data flow",
    "上述调用已在 core/orchestrator.py 中完整实现 (run_attack_pipeline)": "The above calls are fully implemented in core/orchestrator.py (run_attack_pipeline)",
    "日志基础配置": "Basic logging configuration",
    "打印横幅": "Print banner",
    "解析参数 + 输出目录": "Parse arguments + output directory",
    "解析参数": "Parse arguments",
    "输出目录": "Output directory",
    "配置文件日志 + 终端控制": "Configure file logging + terminal control",
    "配置文件日志": "Configure file logging",
    "终端控制": "Terminal control",
    "rate_limit 环境变量": "rate_limit environment variable",
    "构建流水线上下文": "Build pipeline context",
    "安装信号处理器": "Install signal handlers",
    "INIT: 初始化 PyRIT 环境...": "INIT: Initialize PyRIT environment...",
    "INIT: 初始化": "INIT: Initialize",
    "执行攻击链路编排 (try/finally 保障资源清理)": "Execute attack pipeline orchestration (try/finally ensure resource cleanup)",
    "执行攻击链路编排": "Execute attack pipeline orchestration",
    "R10: dry-run 零 token 流水线完整性验证": "R10: dry-run zero-token pipeline integrity verification",
    "main.py 层面: 早期返回,跳过 run_attack_pipeline()": "main.py level: early return, skip run_attack_pipeline()",
    "main.py 层面": "main.py level",
    "早期返回": "early return",
    "跳过 run_attack_pipeline()": "skip run_attack_pipeline()",
    "orchestrator.py 层面: 防御性第二道防线,即使 main.py 逻辑失效也能跳过攻击": "orchestrator.py level: defensive second line, skip attack even if main.py logic fails",
    "orchestrator.py 层面": "orchestrator.py level",
    "防御性第二道防线": "defensive second line",
    "即使 main.py 逻辑失效也能跳过攻击": "skip attack even if main.py logic fails",
    "[DRY-RUN] 零 token 验证模式 — 跳过真实 API 调用": "[DRY-RUN] Zero token verification mode - skip real API calls",
    "[DRY-RUN] 零 token 验证模式": "[DRY-RUN] Zero token verification mode",
    "跳过真实 API 调用": "Skip real API calls",
    "[DRY-RUN] [DRY-RUN] 跳过攻击执行 (execute_attacks)": "[DRY-RUN] Skip attack execution (execute_attacks)",
    "[DRY-RUN] [DRY-RUN] 跳过升级链 (check_and_escalate)": "[DRY-RUN] Skip escalation chain (check_and_escalate)",
    "R11: Scenario 路由器集成 — 将路由器传递给编排器,启用目标感知攻击链": "R11: Scenario router integration - pass router to orchestrator, enable target-aware attack chain",
    "R11: Scenario 路由器集成": "R11: Scenario router integration",
    "将路由器传递给编排器,启用目标感知攻击链": "Pass router to orchestrator, enable target-aware attack chain",
    "R1: 流水线完整性校验 — 确保 model_family 数据流贯通至 load_seeds": "R1: Pipeline integrity verification - ensure model_family data flow through to load_seeds",
    "R1: 流水线完整性校验": "R1: Pipeline integrity verification",
    "确保 model_family 数据流贯通至 load_seeds": "Ensure model_family data flow through to load_seeds",
    "编排委托前,先提取 model_family 并注入 ctx,确保 arm 阶段可访问": "Before orchestration delegation, extract model_family and inject into ctx, ensure accessible in arm phase",
    "R1: 流水线闭环验证 — 确保 ASR 历史已写入 + priors 已更新": "R1: Pipeline closure verification - ensure ASR history written + priors updated",
    "R1: 流水线闭环验证": "R1: Pipeline closure verification",
    "ASR 历史已写入": "ASR history written",
    "priors 已更新": "priors updated",
    "这些调用在 orchestrator 中已执行,此处做最终审计确认": "These calls are already executed in orchestrator, final audit confirmation here",
    "收到中断信号, 执行资源清理...": "Received interrupt signal, executing resource cleanup...",
    "收到中断信号": "Received interrupt signal",
    "执行资源清理": "Execute resource cleanup",
    "R-H2 合规: 不静默吞错, 记录非致命异常": "R-H2 compliant: do not silently swallow errors, log non-fatal exceptions",
    "不静默吞错": "do not silently swallow errors",
    "记录非致命异常": "log non-fatal exceptions",
    "中断清理时资源释放失败 (non-fatal):": "Resource release failure during interrupt cleanup (non-fatal):",
    "最终保障: 如果仍有残留资源, 尝试清理": "Final guarantee: if residual resources remain, attempt cleanup",
    "最终保障": "Final guarantee",
    "如果仍有残留资源, 尝试清理": "If residual resources remain, attempt cleanup",
    "确保所有 FileHandler flush + close": "Ensure all FileHandler flush + close",
    "用户中断, 退出": "User interrupt, exit",
    
    # ===== Function docstrings =====
    "R1 流水线闭环验证: 确保 model_family 数据流 + ASR 历史写入 + priors 更新均已正确执行。": "R1 Pipeline closure verification: ensure model_family data flow + ASR history write + priors update are all correctly executed.",
    "R1 流水线闭环验证": "R1 Pipeline closure verification",
    "确保 model_family 数据流 + ASR 历史写入 + priors 更新均已正确执行": "Ensure model_family data flow + ASR history write + priors update are all correctly executed",
    "学术依据:": "Academic basis:",
    "ASR 历史对 UCB 排序至关重要": "ASR history is critical for UCB sorting",
    "跨目标知识迁移 (EMA priors) 提升 ASR 15-20%": "Cross-target knowledge transfer (EMA priors) improves ASR by 15-20%",
    "验证项:": "Verification items:",
    "model_family: 确保模型族数据已传递到 load_seeds (种子排序/过滤)": "model_family: ensure model family data is passed to load_seeds (seed sorting/filtering)",
    "model_family:": "model_family:",
    "确保模型族数据已传递到 load_seeds (种子排序/过滤)": "Ensure model family data is passed to load_seeds (seed sorting/filtering)",
    "save_asr_history: 确保 ASR 历史已写入 (UCB 排序数据源)": "save_asr_history: ensure ASR history is written (UCB sorting data source)",
    "save_asr_history:": "save_asr_history:",
    "确保 ASR 历史已写入 (UCB 排序数据源)": "Ensure ASR history is written (UCB sorting data source)",
    "update_asr_priors: 确保 priors 已更新 (跨目标知识迁移)": "update_asr_priors: ensure priors are updated (cross-target knowledge transfer)",
    "验证 1: model_family 数据流贯通": "Verification 1: model_family data flow",
    "验证 2: ASR 历史写入确认": "Verification 2: ASR history write confirmation",
    "验证 3: priors 更新确认": "Verification 3: priors update confirmation",
    "R1 验证通过: model_family='%s' 已传递到 load_seeds": "R1 verification passed: model_family='%s' passed to load_seeds",
    "R1 验证通过": "R1 verification passed",
    "已传递到 load_seeds": "passed to load_seeds",
    "R1 验证通过: save_asr_history 已执行, %d 项技术 ASR 已写入": "R1 verification passed: save_asr_history executed, %d technique ASR written",
    "save_asr_history 已执行": "save_asr_history executed",
    "项技术 ASR 已写入": "technique ASR written",
    "确认 update_asr_priors 在 assess 阶段已调用": "Confirm update_asr_priors is called in assess phase",
    "在 assess 阶段已调用": "called in assess phase",
    "检查 priors 文件是否存在": "Check if priors file exists",
    "R1 验证通过: update_asr_priors 已执行, priors 文件已更新": "R1 verification passed: update_asr_priors executed, priors file updated",
    "update_asr_priors 已执行": "update_asr_priors executed",
    "priors 文件已更新": "priors file updated",
    
    # ===== adapters/content_filter.py =====
    "扩展 PyRIT 原生Content filtering器标记。": "Extends PyRIT native Content filter markers.",
    "对齐 PyRIT 1.0.1 架构:": "Aligned with PyRIT 1.0.1 architecture:",
    "PyRIT 1.0.1 中": "In PyRIT 1.0.1,",
    "定义在": "is defined in",
    "pyrit.exceptions.exception_classes": "pyrit.exceptions.exception_classes",
    "模块中 (frozenset)。": "module (frozenset).",
    "函数 (在": "function (in",
    "openai_error_handling": "openai_error_handling",
    "模块中)": "module)",
    "从": "imports",
    "导入": "from",
    "并执行": "and performs",
    "子串扫描来判断是否为Content filtering错误。": "substring scanning to determine if it is a content filter error.",
    "本模块通过直接扩展": "This module directly extends",
    "frozenset 来增强 PyRIT 原生Content filtering检测能力，无需包装函数。": "frozenset to enhance PyRIT native content filter detection, no wrapper function needed.",
    "三Layer防御机制:": "Three-layer defense mechanism:",
    "L1: 静态标记 (YAML 配置文件)": "L1: Static markers (YAML configuration file)",
    "L2: 默认扩展标记 (覆盖第三方 API 中文安全标记)": "L2: Default extended markers (covers third-party API Chinese security markers)",
    "L3: heuristic 动态发现 (从错误信息中发现新标记, 持久化缓存)": "L3: Heuristic dynamic discovery (discover new markers from error messages, persistent cache)",
    "扩展 PyRIT 原生": "Extends PyRIT native",
    "(三Layer防御)。": "(three-layer defense).",
    "对齐 PyRIT 1.0.1:": "Aligned with PyRIT 1.0.1:",
    "PyRIT 1.0.1 的": "PyRIT 1.0.1's",
    "执行流程:": "Execution flow:",
    "加载 YAML 静态配置 (L1)": "Load YAML static configuration (L1)",
    "合并默认扩展标记 (L2)": "Merge default extended markers (L2)",
    "加载上次运行发现的标记缓存 (L3)": "Load cached markers discovered in last run (L3)",
    "扩展": "Extend",
    "frozenset": "frozenset",
    "功能验证 — Ensure扩展标记被 PyRIT 识别": "Functional verification - ensure extended markers are recognized by PyRIT",
    "YAML 配置文件路径 (可选)。": "YAML configuration file path (optional).",
    "所有扩展标记的 frozenset。": "Frozenset of all extended markers.",
    "L1:": "L1:",
    "L2:": "L2:",
    "L3:": "L3:",
    "缓存": "cache",
    "heuristic": "heuristic",
    "加载": "Load",
    "上次运行发现的标记缓存": "cached markers discovered in last run",
    "功能验证 — Ensure扩展标记被 PyRIT 识别。": "Functional verification - ensure extended markers are recognized by PyRIT.",
    "扩展标记被 PyRIT 识别": "extended markers are recognized by PyRIT",
    "持久化动态发现的标记到 JSON 文件。": "Persist dynamically discovered markers to JSON file.",
    "加载上次运行发现的标记缓存。": "Load cached markers discovered in last run.",
    "从错误信息中 heuristic 发现新Content filtering标记。": "Heuristic discovery of new content filter markers from error messages.",
    "错误信息字符串。": "Error message string.",
    "新发现的标记集合。": "Set of newly discovered markers.",
    
    # ===== Common function/method comments =====
    "项目根目录加入 sys.path": "Add project root to sys.path",
    "UTF-8 强制 (Windows GBK 终端兼容)": "UTF-8 enforcement (Windows GBK terminal compatible)",
    "R11: 导入 Scenario 路由器以启用目标感知攻击链": "R11: Import Scenario router to enable target-aware attack chain",
    "R1: 流水线闭环验证": "R1: Pipeline closure verification",
    "用户中断": "User interrupt",
    
    # ===== converter_chains.py =====
    "L5 专家级 Converter 链定义": "L5 expert-level Converter chain definitions",
    "基于 arXiv 学术研究的最优组合。": "Optimal combination based on academic research.",
    "L5 v34 关键更新:": "L5 v34 key updates:",
    "PyRIT PromptSendingAttack 的": "PyRIT PromptSendingAttack's",
    "会将": "will",
    "所有": "all",
    "串联叠加到同一条消息上 (非独立路径)。": "cascade and superimpose on the same message (not independent paths).",
    "因此": "Therefore,",
    "executor.py 的": "executor.py's",
    "只取最优": "only selects optimal",
    "个 converter。": "converter(s).",
    "本文档定义的 l5_optimal 返回 converter 列表, executor 从中选最优": "This document defines l5_optimal returns a list of converters, executor selects optimal from them",
    "学术依据:": "Academic basis:",
    "encoding_bypass: Wei et al. (arXiv:2307.15043) — 编码变换绕过关键词过滤": "encoding_bypass: Wei et al. (arXiv:2307.15043) - Encoding bypass keyword filtering",
    "单层 Base64 ASR 7%, 双层 Base64+ROT13 ASR 12%, 三层 ASR 4% (payload 不可读)": "Single-layer Base64 ASR 7%, double-layer Base64+ROT13 ASR 12%, triple-layer ASR 4% (payload unreadable)",
    "最优层级 = 2 层 (Base64 + ROT13), 但仅在 PromptSendingAttack 外层使用": "Optimal level = 2 layers (Base64 + ROT13), but only used outside PromptSendingAttack",
    "stealth_evasion: Shayegani et al. (arXiv:2306.13254) — Unicode 混淆绕过文本过滤": "stealth_evasion: Shayegani et al. (arXiv:2306.13254) - Unicode obfuscation bypasses text filtering",
    "最优层级 = 1 层 (UnicodeSubstitution only, ZeroWidth 破坏 JSON)": "Optimal level = 1 layer (UnicodeSubstitution only, ZeroWidth breaks JSON)",
    "persuasion: Zeng et al. (arXiv:2402.19181) — 说服策略 ASR 30-40%": "persuasion: Zeng et al. (arXiv:2402.19181) - Persuasion strategies ASR 30-40%",
    "Authority endorsement ASR 38.4%, Logical appeal ASR 28.7%, Tone ASR 22.1%": "Authority endorsement ASR 38.4%, Logical appeal ASR 28.7%, Tone ASR 22.1%",
    "最优 = 1 个 (authority), v34 合 executor 只取": "Optimal = 1 (authority), v34 combined with executor only selects",
    "个 converter": "converter(s)",
    "format_injection: 图像化文字绕过 OCR/文本检测": "format_injection: Imaged text bypasses OCR/text detection",
    "multi_encoding: 多层编码叠加 — 学术研究表明 >3 层 ASR 下降": "multi_encoding: Multi-layer encoding - research shows >3 layers ASR decreases",
    "decomposition: DrAttack (arXiv:2402.14266) — 分解重组 ASR 40-60%": "decomposition: DrAttack (arXiv:2402.14266) - Decomposition and reconstruction ASR 40-60%",
    "最优 = 1 个 (多层串联 recall 下降至 <0.3)": "Optimal = 1 (multi-layer cascade recall drops to <0.3)",
    "variation: 变体重写绕过关键词过滤 ASR 20-30%": "variation: Variant rewriting bypasses keyword filtering ASR 20-30%",
    "Best-of-N (N=3) ASR 提升 1.5x (v34: N 从 10 降到 3)": "Best-of-N (N=3) ASR improvement 1.5x (v34: N reduced from 10 to 3)",
    "flip: 翻转文本绕过前缀过滤 ASR 15-25% (但白盒漏洞场景 ASR": "flip: Flipped text bypasses prefix filtering ASR 15-25% (but white-box vulnerability scenario ASR",
    "L5 v34 Converter 候选列表 (l5_optimal):": "L5 v34 Converter candidate list (l5_optimal):",
    "返回候选 converter 列表, executor.py 去重+裁剪后按优先级只取最优": "Returns candidate converter list, executor.py deduplicates+clips and selects optimal by priority",
    "个": "converter(s)",
    "优先级: authority(38.4%) > variation(20-30%) > ROT13(30-40%) > ...": "Priority: authority(38.4%) > variation(20-30%) > ROT13(30-40%) > ...",
    "预期综合 ASR (单路径 + Best-of-N + escalation): 23-35%": "Expected combined ASR (single-path + Best-of-N + escalation): 23-35%",
    "v34 运行数据: ASR=23.4%, Cohen's Kappa=0.729 (substantial)": "v34 runtime data: ASR=23.4%, Cohen's Kappa=0.729 (substantial)",
    "学术依据: PyRIT (arXiv:2407.01232) SequentialAttack 设计": "Academic basis: PyRIT (arXiv:2407.01232) SequentialAttack design",
    "Wei et al. (arXiv:2307.15043) 串联 >2 层 ASR 急剧下降": "Wei et al. (arXiv:2307.15043) Cascade >2 layers ASR drops sharply",
    "惰性导入 PyRIT 原生 Converter。": "Lazy import PyRIT native Converter.",
    "Converter 类名。": "Converter class name.",
    "Converter 类。": "Converter class.",
    "Converter 不存在。": "Converter does not exist.",
    "第 5 代 Converter 架构设计": "5th generation Converter architecture design",
    "NOTE (L5 v42): encoding_bypass and multi_encoding removed from _build_chain_builders.": "NOTE (L5 v42): encoding_bypass and multi_encoding removed from _build_chain_builders.",
    "Reasons: 3-4 layer stack violates Wei et al. (arXiv:2307.15043) decay law (ASR <4%).": "Reasons: 3-4 layer stack violates Wei et al. (arXiv:2307.15043) decay law (ASR <4%).",
    "Replacements: selective_encoding (single conv, ASR 25-35%) or chained_selective (2-layer, ASR 30-40%).": "Replacements: selective_encoding (single conv, ASR 25-35%) or chained_selective (2-layer, ASR 30-40%).",
    "ZeroWidth + UnicodeSub 隐藏注入。": "ZeroWidth + UnicodeSub hidden injection.",
    "学术依据: Shayegani et al. (arXiv:2306.13254) — Unicode 混淆绕过文本过滤。": "Academic basis: Shayegani et al. (arXiv:2306.13254) - Unicode obfuscation bypasses text filtering.",
    "L5 策略: 仅使用 UnicodeSubstitution (轻量), 不使用 ZeroWidth (可能破坏 JSON)。": "L5 Strategy: Use only UnicodeSubstitution (lightweight), not ZeroWidth (may break JSON).",
    "Persuasion + Tone 说服层链 (需 converter_target)。": "Persuasion + Tone persuasion layer chain (requires converter_target).",
    "学术依据: Zeng et al. (arXiv:2402.19181) — 说服策略 ASR 30-40%。": "Academic basis: Zeng et al. (arXiv:2402.19181) - Persuasion strategies ASR 30-40%.",
    "L5 优化策略:": "L5 optimization strategy:",
    "使用 authority_endorsement (权威背功) → ASR 最高": "Use authority_endorsement (authority endorsement) -> Highest ASR",
    "使用 logical_appeal (逻辑感层) → 对技术型目标有效": "Use logical_appeal (logical appeal) -> Effective for technical targets",
    "使用 academic tone (学术语式) → 绕过安全关键词过滤": "Use academic tone (academic tone) -> Bypass security keyword filtering",
    "LLM 目标实例 (可空, 缺失时返回空列表)。": "LLM target instance (nullable, returns empty list if missing).",
    "Persuasion chain skipped: no converter_target available": "Persuasion chain skipped: no converter_target available",
}


def replace_chinese_in_file(filepath: Path) -> bool:
    """Replace Chinese text with English equivalents in a file. Returns True if changes were made."""
    original = filepath.read_text(encoding="utf-8")
    content = original
    
    # Phase 1: Apply specific translations (longest first to avoid partial replacements)
    for cn, en in sorted(TRANSLATIONS.items(), key=lambda x: -len(x[0])):
        content = content.replace(cn, en)
    
    # Phase 2: Handle separator lines - replace with ascii
    content = re.sub(r"[═─━┃│┌┐└┘├┤┬┴┼]+", lambda m: "=" * len(m.group()), content)
    
    # Phase 3: Remove any remaining Chinese characters in comment lines
    lines = content.split("\n")
    cleaned_lines = []
    for line in lines:
        # Check if this is a comment line (starts with #)
        stripped = line.lstrip()
        if stripped.startswith("#"):
            # Remove Chinese characters but keep the # and any English content
            cleaned = re.sub(r"[\u4e00-\u9fff\u3000-\u303f\uff00-\uffef]", "", line)
            cleaned_lines.append(cleaned)
        # Check if it's a string literal with Chinese
        elif '"""' in line or "'''" in line:
            # Remove Chinese from docstrings
            cleaned = re.sub(r"[\u4e00-\u9fff\u3000-\u303f\uff00-\uffef]+", "", line)
            cleaned_lines.append(cleaned)
        else:
            # For code lines, remove trailing comments with Chinese
            if "#" in line:
                code_part, comment_part = line.split("#", 1)
                if re.search(r"[\u4e00-\u9fff]", comment_part):
                    # Remove Chinese from comment, keep English
                    cleaned_comment = re.sub(r"[\u4e00-\u9fff\u3000-\u303f\uff00-\uffef]+", "", comment_part)
                    cleaned_lines.append(code_part + "#" + cleaned_comment)
                else:
                    cleaned_lines.append(line)
            else:
                cleaned_lines.append(line)
    
    content = "\n".join(cleaned_lines)
    
    if content != original:
        filepath.write_text(content, encoding="utf-8")
        return True
    return False


def main():
    project_root = Path(__file__).parent
    py_files = list(project_root.rglob("*.py"))
    
    # Exclude this script itself
    py_files = [f for f in py_files if f.name != "_remove_chinese_v2.py" and f.name != "_remove_chinese.py"]
    
    modified = 0
    for f in py_files:
        if replace_chinese_in_file(f):
            modified += 1
            print(f"Cleaned: {f.relative_to(project_root)}")
    
    print(f"\nTotal: {modified}/{len(py_files)} files cleaned")


if __name__ == "__main__":
    main()
