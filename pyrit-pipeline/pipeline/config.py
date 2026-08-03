# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""命令行参数解析。.

独立模块，仅依赖标准库 ``argparse``。
修改参数定义不影响任何 Stage 文件。
"""

import argparse
import os
import warnings


def setup_environment() -> None:
    """全局环境初始化 (必须在任何 PyRIT import 之前调用)。.

    1. 抑制第三方库的 SyntaxWarning / DeprecationWarning / FutureWarning
    2. 提前加载 .env (项目根目录) 到 os.environ
    """
    warnings.filterwarnings("ignore", category=SyntaxWarning)
    warnings.filterwarnings("ignore", category=DeprecationWarning)
    warnings.filterwarnings("ignore", category=FutureWarning)

    from dotenv import load_dotenv
    load_dotenv()


def parse_args() -> argparse.Namespace:
    """解析命令行参数。."""
    parser = argparse.ArgumentParser(
        description="PyRIT 原生端到端 AI Red Team 流水线 (核心攻击/评分/输出 100% 原生 API, ASR 驱动增强)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # ── 数据集 (全部预下载到本地, 不支持运行时远程拉取) ──
    parser.add_argument(
        "--datasets",
        nargs="+",
        default=["harmbench", "jbb_behaviors", "strong_reject"],
        help=(
            "数据集名称列表 (从 data/seed_datasets/benchmarks/{name}.prompt 本地加载).\n"
            "需先运行 scripts/download_datasets.py 预下载.\n"
            "默认: harmbench jbb_behaviors strong_reject"
        ),
    )
    parser.add_argument(
        "--max-dataset-size",
        type=int,
        default=10,
        help="每个数据集最大采样数 (默认: 10, 独立预算 per-dataset)",
    )
    parser.add_argument(
        "--local-datasets",
        nargs="+",
        default=None,
        help="额外的本地 .prompt 数据集文件路径列表 (富元数据格式)",
    )
    parser.add_argument(
        "--load-owasp-local",
        action="store_true",
        default=True,
        help=(
            "自动加载 data/ 清单中所有 default=true 的本地数据集 (OWASP + Agentic).\n"
            "默认开启 — 项目以 data/ 目录数据集为数据源主入口。\n"
            "使用 --no-owasp-local 可禁用。"
        ),
    )
    parser.add_argument(
        "--no-owasp-local",
        action="store_true",
        default=False,
        help="禁用自动加载 data/ 清单中的 OWASP + Agentic 数据集 (默认: 不禁用)",
    )
    parser.add_argument(
        "--model",
        type=str,
        default="",
        help=(
            "目标模型名 (如 gpt-4o, llama-3-8b).\n"
            "指定后自动加载模型专属精简种子集 (curated_seeds_{model}.prompt),\n"
            "并使用该模型的 ASR 先验进行种子排序."
        ),
    )
    parser.add_argument(
        "--tier-layer",
        type=int,
        choices=[0, 1, 2, 3],
        default=0,
        help=(
            "三层渐进式选择层级 (0=禁用, 自动选择).\n"
            "  1: 快速评估 (Tier S/A, 5 个技术, 5 seeds)\n"
            "  2: 标准评估 (+ Tier B, 12 个技术, 10 seeds)\n"
            "  3: 深度评估 (全技术, 20 seeds)"
        ),
    )
    parser.add_argument(
        "--auto-tier-params",
        action="store_true",
        default=False,
        help=(
            "G3: 自动根据 model_tier 覆盖攻击参数 (max_attempts/epsilon/max_concurrency).\n"
            "  当启用时, CLI 未显式指定的参数将从 model_tiers.yaml 的 attack_params_by_tier 加载.\n"
            "  学术依据: Crescendo (arXiv:2402.12109), HarmBench (arXiv:2402.04249)"
        ),
    )
    parser.add_argument(
        "--epsilon-decay",
        action="store_true",
        default=False,
        help=(
            "P2-1: 动态 epsilon 衰减 (运行初期高探索, 后期高利用).\n"
            "  当启用时, epsilon 从初始值线性衰减到 epsilon_min=0.02.\n"
            "  学术依据: Sutton & Barto (RL 2018) epsilon-greedy 衰减策略"
        ),
    )

    # ── 技术选择 ──
    parser.add_argument(
        "--techniques",
        nargs="+",
        default=None,
        help=(
            "技术名称列表 (默认: TextAdaptive DEFAULT 聚合).\n"
            "可用聚合: ALL, core, extra, DEFAULT\n"
            "可用单项: many_shot, tap, crescendo_simulated, pair, skeleton_key, flip, ..."
        ),
    )
    parser.add_argument(
        "--max-attempts",
        type=int,
        default=3,
        help="每个 objective 最多尝试的技术数 (默认: 3, SequentialAttack FIRST_SUCCESS)",
    )

    # ── ASR 驱动选择器 ──
    parser.add_argument(
        "--epsilon",
        type=float,
        default=0.1,
        help="Epsilon-greedy 探索概率 (默认: 0.1, 10%% 随机探索 / 90%% 利用历史 ASR)",
    )
    parser.add_argument(
        "--selector-scope",
        choices=["all_runs", "current_run"],
        default="all_runs",
        help=(
            "ASR 查询范围 (默认: all_runs).\n"
            "  all_runs: 查询全部历史 AttackResult (跨运行学习)\n"
            "  current_run: 仅查询当前运行 (隔离学习)"
        ),
    )

    # ── 执行控制 ──
    parser.add_argument(
        "--max-concurrency",
        type=int,
        default=5,
        help="最大并发 AtomicAttack 数 (默认: 5)",
    )
    parser.add_argument(
        "--max-retries",
        type=int,
        default=3,
        help="失败自动重试次数 (默认: 3, 从上次中断处继续)",
    )
    parser.add_argument(
        "--resume",
        type=str,
        default=None,
        help="断点续跑的 ScenarioResult ID",
    )
    parser.add_argument(
        "--no-baseline",
        action="store_true",
        help="禁用 baseline (prompt_sending) 对比运行",
    )

    # ── Converter 路由 (P3) ──
    parser.add_argument(
        "--converters",
        nargs="+",
        default=None,
        help=(
            "Converter 名称列表 (ASR 驱动路由, 可选).\n"
            "可用: rot13, base64, leetspeak, colloquial_wordswap, persuasion, ...\n"
            "示例: --converters rot13 base64"
        ),
    )

    # ── 统一目标 URL (自动判别 + 智能路由) ──
    # 优先级: 命令行 --target-url > .env 中 TARGET_URL > .env 中 WEB_REDTEAM_TARGET_URL
    parser.add_argument(
        "--target-url",
        type=str,
        default=None,
        help=(
            "统一目标 URL — 自动判别目标类型 (LLM Web 应用 / LLM API 平台),\n"
            "自动探测认证拓扑和 MFA, 自动路由到最佳攻击流程.\n"
            "也可通过 .env 文件设置 TARGET_URL 或 WEB_REDTEAM_TARGET_URL.\n"
            "示例: --target-url https://chat.example.com\n"
            "      --target-url https://api.longcat.chat/openai/v1/chat/completions"
        ),
    )
    parser.add_argument(
        "--target-type",
        type=str,
        choices=["auto", "web_app", "api_platform"],
        default="auto",
        help=(
            "目标类型 (默认: auto 自动判别).\n"
            "  auto: 自动探测目标类型\n"
            "  web_app: 强制为 LLM Web 应用 (PlaywrightTarget)\n"
            "  api_platform: 强制为 LLM API 平台 (HTTPTarget)"
        ),
    )
    parser.add_argument(
        "--mfa-timeout",
        type=int,
        default=300,
        help="MFA 操作等待超时秒数 (默认: 300s)",
    )
    parser.add_argument(
        "--recon",
        action="store_true",
        help="启用 recon-pipeline 侦察 (自动发现 API 端点、注入面、攻击推荐)",
    )

    # ── 兼容旧参数 (向后兼容, 内部映射到新参数) ──
    parser.add_argument(
        "--web-target-url",
        type=str,
        default=None,
        help="[已废弃] 请使用 --target-url. 向后兼容保留.",
    )
    parser.add_argument(
        "--web-target-profile",
        type=str,
        default=None,
        help="Web 目标配置文件路径 (YAML), 包含认证策略和交互选择器配置",
    )
    parser.add_argument(
        "--web-headless",
        action="store_true",
        help="Web 目标浏览器使用 headless 模式 (不显示浏览器窗口)",
    )

    # ── 场景选择 (P1: 多场景) ──
    parser.add_argument(
        "--scenario",
        type=str,
        default="text_adaptive",
        help=(
            "场景类型 (默认: text_adaptive).\n"
            "  text_adaptive: 文本自适应 (epsilon-greedy, ASR 驱动)\n"
            "  airt_jailbreak: AIRT 越狱攻击\n"
            "  airt_cyber: AIRT 网络安全\n"
            "  airt_leakage: AIRT 信息泄露\n"
            "  airt_psychosocial: AIRT 心理社会攻击\n"
            "  airt_rapid_response: AIRT 快速响应\n"
            "  airt_scam: AIRT 诈骗\n"
            "  garak_encoding: Garak 编码攻击\n"
            "  garak_doctor: Garak Doctor 探测\n"
            "  garak_web_injection: Garak Web 注入\n"
            "  benchmark_adversarial: 对抗基准 (跨模型 ASR 对比)\n"
            "  foundry_red_team: Foundry 自主红队代理"
        ),
    )

    # ── GCG 对抗后缀生成 (P0: 原生 pyrit.executor.promptgen.gcg) ──
    parser.add_argument(
        "--gcg-model",
        type=str,
        default=None,
        help=(
            "GCG 对抗后缀生成的 HuggingFace 模型名 (如 meta-llama/Llama-2-7b-chat-hf).\n"
            "指定后将在 Stage 1.5 执行 GCG 优化，生成对抗后缀注入数据集。\n"
            "需要 torch + transformers + GPU。"
        ),
    )
    parser.add_argument(
        "--gcg-steps",
        type=int,
        default=100,
        help="GCG 优化步数 (默认: 100, 论文用 500)",
    )
    parser.add_argument(
        "--gcg-batch-size",
        type=int,
        default=128,
        help="GCG 每步候选数 (默认: 128, 论文用 512)",
    )

    # ── Fuzzer 载荷变异 (P0: 原生 pyrit.executor.promptgen.fuzzer) ──
    parser.add_argument(
        "--fuzzer-iterations",
        type=int,
        default=None,
        help=(
            "启用 Fuzzer MCTS 载荷变异，指定最大迭代次数 (如 50).\n"
            "指定后将使用原生 GPTFUZZER 变异种子 prompt，生成更多变体。"
        ),
    )

    # ── 多模态攻击 (P0: 原生 ModalityRouter) ──
    parser.add_argument(
        "--multimodal",
        action="store_true",
        help=("启用多模态攻击 (自动检测目标模态并路由图像 Converter).\n需要目标支持 image 输入 (如 GPT-4 Vision)."),
    )
    parser.add_argument(
        "--multimodal-converters",
        nargs="+",
        default=None,
        help=(
            "手动指定多模态 Converter 预设名称列表.\n"
            "可用: image_text_overlay, image_prompt_style, image_overlay,\n"
            "      image_resizing, image_rotation, image_compression,\n"
            "      image_color_saturation\n"
            "示例: --multimodal-converters image_text_overlay image_resizing"
        ),
    )

    # ── XPIA 工作流 (P1: 原生 pyrit.executor.workflow.xpia) ──
    parser.add_argument(
        "--xpia",
        action="store_true",
        help=(
            "启用 XPIA (Cross-Domain Prompt Injection Attack) 工作流.\n"
            "需要在 .env 中配置 ATTACK_SETUP_TARGET 和 PROCESSING_TARGET."
        ),
    )
    parser.add_argument(
        "--xpia-attack-content",
        type=str,
        default=None,
        help="XPIA 攻击内容 (嵌入的恶意指令)",
    )

    # ── HTTP Target (P2: 原生 HTTPTarget) ──
    parser.add_argument(
        "--http-target",
        type=str,
        default=None,
        help=(
            "HTTP Target 原始请求文件路径 (如 Burp 导出的 .txt).\n"
            "指定后将使用原生 HTTPTarget 替代 OpenAIChatTarget.\n"
            "适用于非 OpenAI 兼容 API 的 Web 目标红队测试。"
        ),
    )

    # ── 限速控制 (P2: 自研 RateLimitedTarget) ──
    parser.add_argument(
        "--rate-limit",
        type=int,
        default=None,
        help=(
            "API 请求最大并发数 (如 3).\n"
            "指定后将用 RateLimitedTarget 包装原始 Target，\n"
            "增加并发信号量 + 指数退避重试 (429/503/504/timeout)."
        ),
    )
    parser.add_argument(
        "--rate-limit-retries",
        type=int,
        default=5,
        help="限速重试最大次数 (默认: 5)",
    )

    # ── EXHAUSTIVE 策略 (P2: 评估模式) ──
    parser.add_argument(
        "--exhaustive",
        action="store_true",
        help=(
            "EXHAUSTIVE 策略: 对每个 objective 尝试所有技术 (不提前停止).\n"
            "适用于全面评估场景，生成完整 ASR 对比矩阵。\n"
            "注意: 执行时间显著增加。"
        ),
    )

    # F3 修复: --verbose 参数 (对齐参考日志 Verbose 字段)
    parser.add_argument(
        "--verbose",
        action="store_true",
        default=True,
        help="开启详细输出 (成功攻击详情, 默认开启)",
    )

    # ── 报告格式 (P3: HTML/PDF) ──
    parser.add_argument(
        "--html-report",
        action="store_true",
        help="生成 HTML 格式报告 (默认: 仅 Markdown)",
    )
    parser.add_argument(
        "--pdf-report",
        action="store_true",
        help="生成 PDF 格式报告 (需要 weasyprint 或 xhtml2pdf)",
    )

    # ── 配置文件 ──
    parser.add_argument(
        "--config-file",
        type=str,
        default="config/.pyrit_conf",
        help="PyRIT 配置文件路径 (默认: config/.pyrit_conf — 结构配置保留在 config/ 目录)",
    )

    # ── 离线分析 (优化4: 可选增强报告) ──
    parser.add_argument(
        "--analyze",
        action="store_true",
        help=(
            "启用离线分析报告 (攻击多样性分析 + Converter 转换日志 + 三层选择向导).\n"
            "默认不执行, 缩短流水线时间。详细评估时添加此标志。"
        ),
    )

    # ── 输出 ──
    parser.add_argument(
        "--output-dir",
        type=str,
        default=None,
        help="报告输出目录 (默认: output/redteam_YYYYMMDD_HHMMSS)",
    )
    args = parser.parse_args()

    # ── 统一目标 URL 解析: 命令行 > .env TARGET_URL > .env WEB_REDTEAM_TARGET_URL ──
    if not args.target_url:
        args.target_url = os.environ.get("TARGET_URL") or os.environ.get("WEB_REDTEAM_TARGET_URL")
    # 兼容旧参数 --web-target-url
    if not args.target_url and args.web_target_url:
        args.target_url = args.web_target_url

    # ── --no-owasp-local 覆盖 --load-owasp-local ──
    if args.no_owasp_local:
        args.load_owasp_local = False

    return args
