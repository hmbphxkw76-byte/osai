#!/usr/bin/env python3
"""Utility to replace Chinese comments/docstrings with English equivalents."""
import re
from pathlib import Path

# Comprehensive translation mapping for common Chinese patterns
TRANSLATIONS = {
    # Module-level docstrings - full patterns
    "PyRIT 攻击链路入口 (纯编排层)。": "PyRIT attack pipeline entry point (orchestration layer).",
    "攻击链路 (6 阶段, arXiv:2407.01232 — PyRIT 原生框架):": "Attack pipeline (6 phases, arXiv:2407.01232 - PyRIT native framework):",
    "recon     → Burp 拦截: 读取 HTTP 请求 + 侦察: 解析, 探测能力指纹, 构建 HTTPTarget": "recon     -> Burp intercept: read HTTP requests + recon: parse, probe capability fingerprint, build HTTPTarget",
    "arm       → 种子选取: 从 YAML 种子文件加载, 按历史 ASR 排序 + Converter: 构建 L5 最优链": "arm       -> Seed selection: load from YAML seed files, sort by historical ASR + Converter: build L5 optimal chain",
    "strike    → 攻击发送: PyRIT 原生 PromptSendingAttack 多路径执行 (FIRST_SUCCESS)": "strike    -> Attack execution: PyRIT native PromptSendingAttack multi-path execution (FIRST_SUCCESS)",
    "escalate  → 多轮升级: Crescendo→TAP→PAIR→GCG→native (ASR<90% 触发, 含中间退出)": "escalate  -> Multi-turn escalation: Crescendo->TAP->PAIR->GCG->native (triggered when ASR<90%, with mid-exit)",
    "assess    → 评分判定: T0→J1→J2→J3 级联评分, ASR 统计, Wilson CI, 双 Judge 交叉验证": "assess    -> Scoring: T0->J1->J2->J3 cascade scoring, ASR statistics, Wilson CI, dual Judge cross-validation",
    "报告生成: 证据收集 + MD/HTML/JSON/PoC/SARIF": "Report generation: evidence collection + MD/HTML/JSON/PoC/SARIF",
    "or_aggregation OR 聚合追踪, scorer_metrics T0 评分器指标": "or_aggregation OR aggregation tracking, scorer_metrics T0 scorer metrics",
    "report    → 报告生成: 证据收集 + MD/HTML/JSON/PoC/SARIF": "report    -> Report generation: evidence collection + MD/HTML/JSON/PoC/SARIF",
    "不指定 --stage 时按顺序执行全部 6 个阶段 (strike+escalate 合为一步), 向后兼容。": "When --stage is not specified, all 6 phases are executed in order (strike+escalate combined), backward compatible.",
    "指定 --stage <name> 时执行到该阶段完成后停止, 便于分阶段开发和调试。": "When --stage <name> is specified, execution stops after that phase completes, for phased development and debugging.",
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
    
    # Common Chinese phrases in comments
    "主流程入口": "Main entry",
    "初始化环境": "Initialize environment",
    "启动攻击链路编排器": "Start attack pipeline orchestrator",
    "编排逻辑委托给": "Orchestration delegated to",
    "此处仅负责": "This function only handles",
    "日志配置": "Logging configuration",
    "信号处理": "Signal handling",
    "参数解析": "Parameter parsing",
    "环境初始化": "Environment initialization",
    "流水线上下文构建": "Pipeline context construction",
    "生产级": "Production-grade",
    "保障资源清理": "Ensure resource cleanup",
    "导入核心模块": "Import core modules",
    "R11: 导入": "R11: Import",
    "路由器": "router",
    "以启用目标感知攻击链": "to enable target-aware attack chain",
    "R1: 精准投放四大机制集成声明": "R1: Four precision delivery mechanism integration declarations",
    "三级Converter排序": "Three-level Converter sorting",
    "ASR历史排序UCB1": "ASR history sorting UCB1",
    "ASR种子裁剪": "ASR seed pruning",
    "模型特定先验": "Model-specific priors",
    "数据流": "Data flow",
    "上述调用已在": "The above calls are already in",
    "中完整实现": "fully implemented",
    "日志基础配置": "Basic logging configuration",
    "打印横幅": "Print banner",
    "解析参数": "Parse arguments",
    "输出目录": "Output directory",
    "配置文件日志": "Configure file logging",
    "终端控制": "Terminal control",
    "rate_limit 环境变量": "rate_limit environment variable",
    "构建流水线上下文": "Build pipeline context",
    "安装信号处理器": "Install signal handlers",
    "INIT: 初始化": "INIT: Initialize",
    "执行攻击链路编排": "Execute attack pipeline orchestration",
    "R10: dry-run 零 token 流水线完整性验证": "R10: dry-run zero-token pipeline integrity verification",
    "main.py 层面": "main.py level",
    "早期返回": "Early return",
    "跳过": "Skip",
    "orchestrator.py 层面": "orchestrator.py level",
    "防御性第二道防线": "Defensive second line",
    "即使": "Even if",
    "逻辑失效也能跳过攻击": "logic fails, can still skip attack",
    "R10: dry-run 零 token 验证模式": "R10: dry-run zero-token verification mode",
    "跳过真实 API 调用": "Skip real API calls",
    "跳过攻击执行": "Skip attack execution",
    "跳过升级链": "Skip escalation chain",
    "R11: Scenario 路由器集成": "R11: Scenario router integration",
    "将路由器传递给编排器": "Pass router to orchestrator",
    "启用目标感知攻击链": "Enable target-aware attack chain",
    "R1: 流水线完整性校验": "R1: Pipeline integrity verification",
    "确保": "Ensure",
    "数据流贯通至": "data flow through to",
    "编排委托前": "Before orchestration delegation",
    "先提取": "First extract",
    "并注入": "and inject into",
    "确保 arm 阶段可访问": "Ensure accessible in arm phase",
    "R1: 流水线闭环验证": "R1: Pipeline closure verification",
    "已写入": "written",
    "已更新": "updated",
    "这些调用在": "These calls are in",
    "中已执行": "already executed",
    "此处做最终审计确认": "Final audit confirmation here",
    "收到中断信号": "Received interrupt signal",
    "执行资源清理": "Execute resource cleanup",
    "R-H2 合规": "R-H2 compliant",
    "不静默吞错": "Do not silently swallow errors",
    "记录非致命异常": "Log non-fatal exceptions",
    "中断清理时资源释放失败 (non-fatal)": "Resource release failure during interrupt cleanup (non-fatal)",
    "最终保障": "Final guarantee",
    "如果仍有残留资源": "If residual resources remain",
    "尝试清理": "Attempt cleanup",
    "确保所有": "Ensure all",
    "flush + close": "flush + close",
    "user interrupt, exit": "user interrupt, exit",
    "用户中断": "User interrupt",
    
    # Function docstrings
    "R1 流水线闭环验证: 确保 model_family 数据流 + ASR 历史写入 + priors 更新均已正确执行。": "R1 Pipeline closure verification: ensure model_family data flow + ASR history write + priors update are all correctly executed.",
    "学术依据:": "Academic basis:",
    "ASR 历史对 UCB 排序至关重要": "ASR history is critical for UCB sorting",
    "跨目标知识迁移 (EMA priors) 提升 ASR 15-20%": "Cross-target knowledge transfer (EMA priors) improves ASR by 15-20%",
    "验证项:": "Verification items:",
    "model_family: 确保模型族数据已传递到 load_seeds (种子排序/过滤)": "model_family: ensure model family data is passed to load_seeds (seed sorting/filtering)",
    "save_asr_history: 确保 ASR 历史已写入 (UCB 排序数据源)": "save_asr_history: ensure ASR history is written (UCB sorting data source)",
    "update_asr_priors: 确保 priors 已更新 (跨目标知识迁移)": "update_asr_priors: ensure priors are updated (cross-target knowledge transfer)",
    "验证 1: model_family 数据流贯通": "Verification 1: model_family data flow",
    "验证 2: ASR 历史写入确认": "Verification 2: ASR history write confirmation",
    "验证 3: priors 更新确认": "Verification 3: priors update confirmation",
    "R1 验证通过": "R1 verification passed",
    "已传递到": "passed to",
    "已执行": "executed",
    "项技术 ASR 已写入": "technique ASR written",
    "确认": "Confirmation",
    "在 assess 阶段已调用": "called in assess phase",
    "检查 priors 文件是否存在": "Check if priors file exists",
    
    # adapters module
    "PyRIT 原生组件适配器层（包装与扩展）。": "PyRIT native component adapter layer (wrapping and extension).",
    "对齐 PyRIT 1.0.1 原生 Target 体系:": "Aligned with PyRIT 1.0.1 native Target system:",
    "本包不替代 PyRIT 原生 Target, 仅提供增强增强包装器:": "This package does not replace PyRIT native Targets, only provides enhanced wrappers:",
    "PyRIT 1.0.1 原生 Target (直接使用):": "PyRIT 1.0.1 native Target (direct use):",
    "OpenAIChatTarget: Chat Completions API": "OpenAIChatTarget: Chat Completions API",
    "OpenAIResponseTarget: Responses API": "OpenAIResponseTarget: Responses API",
    "LiteLLMChatTarget: 100+ LLM 提供商": "LiteLLMChatTarget: 100+ LLM providers",
    "HTTPTarget: 原始 HTTP 请求 (Burp 场景)": "HTTPTarget: Raw HTTP request (Burp scenario)",
    "HTTPXAPITarget: API 模式": "HTTPXAPITarget: API mode",
    "PlaywrightTarget: 浏览器自动化": "PlaywrightTarget: Browser automation",
    "RoundRobinTarget: 多目标轮询 (负载分散)": "RoundRobinTarget: Multi-target polling (load distribution)",
    "本包增强模块:": "This package enhancement modules:",
    "RateLimitedTarget: 并发控制 + 认证恢复 + 能力验证": "RateLimitedTarget: Concurrency control + auth recovery + capability verification",
    "PyRIT 原生 @limit_requests_per_minute + @pyrit_target_retry": "PyRIT native @limit_requests_per_minute + @pyrit_target_retry",
    "装饰器保留在被包装 target 上)": "decorators preserved on wrapped target)",
    "ContentFilterExt: 扩展 PyRIT 原生 CONTENT_FILTER_MARKERS": "ContentFilterExt: Extends PyRIT native CONTENT_FILTER_MARKERS",
    "直接扩展 exception_classes 模块属性)": "Directly extends exception_classes module attribute)",
    "原生组件映射 (Rule 2: PyRIT 原生优先):": "Native component mapping (Rule 2: PyRIT native priority):",
    "层": "Layer",
    "MUST use (PyRIT native)": "MUST use (PyRIT native)",
    "Enhancement (本包)": "Enhancement (this package)",
    "Target": "Target",
    "并发+认证": "Concurrency+Auth",
    "RPM 限速": "RPM rate limit",
    "RateLimitedTarget 透传": "RateLimitedTarget passthrough",
    "重试": "Retry",
    "错误处理": "Error handling",
    "不覆盖": "Not overridden",
    "内容过滤": "Content filtering",
    "ContentFilterExt 扩展": "ContentFilterExt extension",
    "能力验证": "Capability verification",
    "RateLimitedTarget 调用": "RateLimitedTarget invocation",
    "能力发现": "Capability discovery",
    "RateLimitedTarget.apply_discovered_capabilities": "RateLimitedTarget.apply_discovered_capabilities",
    "目标路由": "Target routing",
    "统一路由": "Unified routing",
    "惰性导入 content_filter 模块函数。": "Lazy import content_filter module function.",
    
    # arm module
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
    
    # assess module
    "评分判定阶段。": "Scoring phase.",
    "攻击链路第 5 步: 对攻击结果进行评分, 计算 ASR, 双 Judge 交叉验证。": "Attack pipeline step 5: Score attack results, calculate ASR, dual Judge cross-validation.",
    "核心模块 (SSOT):": "Core modules (SSOT):",
    "score_pipeline: 评分管线 (响应解析 + 异步预计算, 原 precompute + response_parser 合并)": "score_pipeline: Scoring pipeline (response parsing + async precompute, merged from precompute + response_parser)",
    "asr_manager: ASR 统一管理 (统计 + 历史 + 联合 ASR, 原 asr_compute + asr_history + joint_asr 合并)": "asr_manager: ASR unified management (statistics + history + joint ASR, merged from asr_compute + asr_history + joint_asr)",
    "asr_stats: 双 Judge 统计 + Cohen's Kappa + Wilson Score CI (全局计数器 SSOT)": "asr_stats: Dual Judge statistics + Cohen's Kappa + Wilson Score CI (global counter SSOT)",
    "scorer: 评分器注册 (AdaptiveDualJudgeScorer + fallback)": "scorer: Scorer registration (AdaptiveDualJudgeScorer + fallback)",
    "adaptive_dual_judge: 自适应双 Judge (高置信度直接返回)": "adaptive_dual_judge: Adaptive dual Judge (high confidence direct return)",
    "judge_manager: LLM 双判 + 仲裁 + 并发式判": "judge_manager: LLM dual judging + arbitration + concurrent judging",
}


def replace_chinese_in_file(filepath: Path) -> bool:
    """Replace Chinese text with English equivalents in a file. Returns True if changes were made."""
    original = filepath.read_text(encoding="utf-8")
    content = original
    
    # Apply translations (longest first to avoid partial replacements)
    for cn, en in sorted(TRANSLATIONS.items(), key=lambda x: -len(x[0])):
        content = content.replace(cn, en)
    
    # Handle separator lines with Chinese characters
    content = re.sub(
        r"═{10,}",
        lambda m: "=" * len(m.group()),
        content
    )
    
    # Remove any remaining Chinese characters in comments (lines starting with #)
    def clean_comment_line(line):
        if line.strip().startswith("#"):
            # Replace Chinese characters in comment lines
            return re.sub(r"[\u4e00-\u9fff\u3000-\u303f\uff00-\uffef]+", "", line)
        return line
    
    lines = content.split("\n")
    new_lines = [clean_comment_line(line) for line in lines]
    content = "\n".join(new_lines)
    
    if content != original:
        filepath.write_text(content, encoding="utf-8")
        return True
    return False


def main():
    project_root = Path(__file__).parent
    py_files = list(project_root.rglob("*.py"))
    
    # Exclude this script itself
    py_files = [f for f in py_files if f.name != "_remove_chinese.py"]
    
    modified = 0
    for f in py_files:
        if replace_chinese_in_file(f):
            modified += 1
            print(f"Cleaned: {f.relative_to(project_root)}")
    
    print(f"\nTotal: {modified}/{len(py_files)} files cleaned")


if __name__ == "__main__":
    main()
