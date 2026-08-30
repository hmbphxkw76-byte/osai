"""CLI 参数解析 + 环境初始化 + 输出目录管理。

攻击链路配置入口:
    优先级: CLI --flag > config/defaults.yaml > 硬编码默认值

职责:
    - parse_args: CLI 参数解析 (argparse)
    - get_output_dir: 输出目录路径生成 (带时间戳)
    - ensure_output_dir: 创建输出目录及子目录
    - setup_environment: PyRIT 环境初始化 (SQLite WAL 模式)
"""

from __future__ import annotations

import argparse
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml

# 自动加载 .env 文件 (python-dotenv)
try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    pass

logger = logging.getLogger(__name__)

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_DEFAULTS_YAML = _PROJECT_ROOT / "config" / "defaults.yaml"


def _load_defaults() -> dict[str, Any]:
    """从 config/defaults.yaml 加载默认值 (SSOT)."""
    if not _DEFAULTS_YAML.exists():
        return {}
    try:
        with open(_DEFAULTS_YAML, encoding="utf-8") as f:
            data = yaml.safe_load(f)
        return data if isinstance(data, dict) else {}
    except Exception as e:
        logger.warning("Failed to load defaults.yaml: %s", e)
        return {}


def _apply_defaults(args: argparse.Namespace, defaults: dict[str, Any]) -> None:
    """用 YAML 默认值填充 args 中为 None 的参数."""
    key_map = {"scenario_timeout": "timeout"}
    for yaml_key, default_val in defaults.items():
        arg_key = key_map.get(yaml_key, yaml_key)
        current = getattr(args, arg_key, None)
        if current is None:
            setattr(args, arg_key, default_val)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """解析 CLI 参数 — 攻击链路统一入口.

    Args:
        argv: 可选参数列表。None 时使用 sys.argv。

    Returns:
        argparse Namespace 对象, 已应用 YAML 默认值。
    """
    parser = argparse.ArgumentParser(
        description="PyRIT-Strike — Burp拦截→侦察→种子→Converter→攻击→评分→证据 攻击链路",
    )

    # ── 流水线阶段控制 ──
    # 7 阶段划分 (对齐 OWASP AI-300 Five-Step + PyRIT 原生流水线):
    #   recon     → Burp 解析 + 目标探测 + 能力指纹 + HTTPTarget 构建
    #   arm       → 种子加载/ASR 排序 + Converter 链构建 + 技术选择
    #   strike    → 单轮 PyRIT 原生多路径攻击 (PromptSendingAttack FIRST_SUCCESS)
    #   escalate  → 多轮升级链 (Crescendo→TAP→PAIR→GCG→native, ASR<90% 触发)
    #   assess    → T0→J1→J2→J3 级联评分 + ASR 统计 + Wilson CI
    #   report    → 证据收集 + MD/HTML/JSON/PoC/SARIF 生成
    # 不指定 --stage 时按顺序执行全部阶段 (strike+escalate 合为一步), 向后兼容。
    parser.add_argument(
        "--stage",
        type=str,
        default=None,
        choices=["recon", "arm", "strike", "escalate", "assess", "report"],
        help="只执行到指定阶段后停止 (recon/arm/strike/escalate/assess/report), "
             "不指定则执行完整链路",
    )

    # ── 侦察: Burp 拦截 ──
    # 用法: --burp <name> (单个) 或 --burp MM_05 --burp MM_03 (多个)
    #   自动解析为 data/burp/<name>.txt
    #   不指定时自动扫描 data/burp/*.txt 全部文件 (逐个深度攻击)
    #   也可直接传完整路径: --burp data/burp/deepseek.txt
    #   多个 endpoint: --burp MM_05 --burp MM_03 --burp MM_08
    #   学术依据: Greshake et al. (arXiv:2302.12173) — 逐个深度攻击 + 联合 ASR
    parser.add_argument(
        "--burp",
        type=str,
        default=None,
        metavar="NAME",
        action="append",
        help="Burp 拦截的 HTTP 请求文件名 (自动查找 data/burp/<NAME>.txt), "
             "可重复指定多个 endpoint; 不指定时自动扫描 data/burp/*.txt 全部文件",
    )

    # ── 种子选取 ──
    parser.add_argument(
        "--seeds",
        type=str,
        default="elite_jailbreaks,asi_top10,owasp_full_coverage",
        help="种子文件名 (逗号分隔)",
    )
    parser.add_argument("--max-seeds", type=int, default=None, help="最大种子数 (默认 25)")
    parser.add_argument("--auto-seeds", action="store_true", default=False, help="自动种子扩充 (3x)")
    parser.add_argument("--enable-dos", action="store_true", default=False, help="启用 DoS 攻击")

    # ── Converter 转换 ──
    parser.add_argument(
        "--converters", type=str, default="auto", help="Converter 链 (auto, l5_optimal, none, ...)"
    )

    # ── 攻击发送 ──
    parser.add_argument(
        "--techniques", type=str, default="auto", help="攻击技术 (auto, single, crescendo, ...)"
    )
    parser.add_argument("--max-attempts", type=int, default=None, help="每个种子最大重试次数")
    parser.add_argument("--max-concurrency", type=int, default=None, help="最大并发数 (默认 3)")
    parser.add_argument("--timeout", type=int, default=None, help="场景超时秒数 (默认 1200)")

    # ── 升级 ──
    parser.add_argument("--escalation", action="store_true", default=None, help="启用多轮升级")
    parser.add_argument("--no-escalation", action="store_false", dest="escalation", help="禁用多轮升级")

    # ── 模式标志 ──
    parser.add_argument("--offensive", action="store_true", default=False, help="全火力模式")
    parser.add_argument("--rate-limit", type=int, default=None, help="API 限速 (RPM)")

    # ── 报告 ──
    parser.add_argument("--html-report", action="store_true", default=False, help="生成 HTML 报告")

    # ── 目标路由 (对齐 PyRIT 1.0.1 原生 Target 体系) ──
    # 学术依据: PyRIT (arXiv:2407.01232) — 多原生 Target 路由
    # 优先级: --litellm-model > --target-api-endpoint > --browser-url > --burp
    parser.add_argument(
        "--litellm-model",
        type=str,
        default=None,
        metavar="MODEL",
        help="LiteLLM 模型字符串 (如 anthropic/claude-sonnet-4-6, bedrock/anthropic.claude-v2), "
             "通过 LiteLLM SDK 访问 100+ LLM 提供商; 配置 LITELLM_API_KEY/LITELLM_ENDPOINT 环境变量",
    )
    parser.add_argument(
        "--target-api-endpoint",
        type=str,
        default=None,
        metavar="URL",
        help="OpenAI 兼容 API 端点 (如 https://api.openai.com/v1), "
             "配合 --target-api-key 使用, 路由到 OpenAIChatTarget/OpenAIResponseTarget",
    )
    parser.add_argument(
        "--target-api-key",
        type=str,
        default=None,
        metavar="KEY",
        help="API 密钥 (配合 --target-api-endpoint 使用)",
    )
    parser.add_argument(
        "--target-api-model",
        type=str,
        default=None,
        metavar="MODEL",
        help="模型名称 (如 gpt-4o, o3-mini; 配合 --target-api-endpoint 使用)",
    )
    parser.add_argument(
        "--target-api-type",
        type=str,
        default="chat",
        choices=["chat", "responses"],
        help="API 类型: chat=Chat Completions API, responses=Responses API (o1/o3/GPT-5)",
    )
    parser.add_argument(
        "--browser-url",
        type=str,
        default=None,
        metavar="URL",
        help="浏览器渲染 Chat UI URL (路由到 PyRIT 原生 PlaywrightTarget), "
             "用于攻击需要 JS 渲染的 Web Chat 界面",
    )
    parser.add_argument(
        "--auto-discover-capabilities",
        action="store_true",
        default=False,
        help="运行 PyRIT 原生 discover_target_capabilities_async 自动探测目标能力",
    )

    # ── 输出 ──
    parser.add_argument("--output-dir", type=str, default=None, help="输出目录")
    parser.add_argument("--resume", type=str, default=None, help="从已有场景恢复")

    args = parser.parse_args(argv)

    explicit_escalation = args.escalation

    # ── 应用 YAML 默认值 ──
    defaults = _load_defaults()
    _apply_defaults(args, defaults)

    # ── 应用 --offensive 预设 ──
    if args.offensive:
        args.converters = "l5_optimal"
        args.html_report = True
        if args.max_attempts is None:
            args.max_attempts = 3

    # ── escalation 处理 ──
    if explicit_escalation is not None:
        args.escalation = explicit_escalation
    elif args.escalation is None:
        args.escalation = True

    # ── Burp 请求路径解析 ──
    # 不指定 --burp → 自动扫描 data/burp/*.txt 全部文件 (逐个深度攻击)
    # --burp <name> → data/burp/<name>.txt (自动补全路径, 单个 endpoint)
    # 支持多值: --burp MM_05 --burp MM_03 → ["data/burp/MM_05.txt", "data/burp/MM_03.txt"]
    # 单值: --burp request → "data/burp/request.txt"
    # 多值时返回 list[str], 单值时返回 str (向后兼容)
    # 如果传入的值已包含路径分隔符或 .txt 后缀, 视为完整路径
    raw_burps = args.burp
    if raw_burps is None:
        # 不指定 --burp → 自动扫描 data/burp/ 目录下所有 .txt 文件
        # 学术依据: Greshake et al. (arXiv:2302.12173) — 逐个深度攻击
        burp_dir = _PROJECT_ROOT / "data" / "burp"
        if burp_dir.is_dir():
            raw_burps = sorted(
                str(f) for f in burp_dir.glob("*.txt") if f.is_file()
            )
        if not raw_burps:
            # 目录不存在或无 .txt 文件 → fallback 到默认 request.txt
            raw_burps = ["request"]
        logger.info(
            "No --burp specified: auto-discovered %d .txt file(s) in data/burp/",
            len(raw_burps),
        )
    elif isinstance(raw_burps, str):
        raw_burps = [raw_burps]

    resolved_burps: list[str] = []
    for burp_val in raw_burps:
        if "/" not in burp_val and "\\" not in burp_val and not burp_val.endswith(".txt"):
            # 纯文件名 → 自动补全为 data/burp/<name>.txt
            resolved_burps.append(str(_PROJECT_ROOT / "data" / "burp" / f"{burp_val}.txt"))
        elif not Path(burp_val).is_absolute() and ("/" in burp_val or "\\" in burp_val):
            # 相对路径 → 相对于项目根目录
            resolved_burps.append(str(_PROJECT_ROOT / burp_val))
        else:
            resolved_burps.append(burp_val)

    # 向后兼容: 单值返回 str, 多值返回 list[str]
    if len(resolved_burps) == 1:
        args.burp = resolved_burps[0]
    else:
        args.burp = resolved_burps
    # 额外保留列表形式供 main.py 判断是否多 endpoint
    args._burp_list = resolved_burps

    return args


def get_output_dir(args: argparse.Namespace) -> Path:
    """生成输出目录路径."""
    if args.output_dir is not None:
        return Path(args.output_dir)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return _PROJECT_ROOT / "outputs" / f"strike_{timestamp}"


def ensure_output_dir(output_dir: Path) -> Path:
    """创建输出目录及子目录 (evidence/, db/, poc/)."""
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "evidence").mkdir(parents=True, exist_ok=True)
    (output_dir / "db").mkdir(parents=True, exist_ok=True)
    return output_dir


async def setup_environment(output_dir: Path) -> None:
    """初始化 PyRIT 环境 — SQLite WAL 模式 + 内存实例.

    生产级: 多 endpoint 模式下重复调用时, 先释放旧 DB 引擎防止泄漏。
    学术依据: PyRIT (arXiv:2407.01232) — dispose_db_engine() 资源释放
    """
    try:
        from dotenv import load_dotenv
        load_dotenv()
    except ImportError:
        pass

    from pyrit.setup.initialization import initialize_pyrit_async

    db_path = Path(output_dir) / "db" / "pyrit.db"
    db_path.parent.mkdir(parents=True, exist_ok=True)

    os.environ["PYRIT_DB_URL"] = f"sqlite:///{db_path}"
    os.environ.setdefault("PYRIT_SQLITE_JOURNAL_MODE", "WAL")
    os.environ.setdefault("PYRIT_SQLITE_BUSY_TIMEOUT", "5000")

    # 生产级: 重复调用时先释放旧 DB 引擎, 防止连接泄漏
    # 多 endpoint 模式下每个 endpoint 调用一次 setup_environment,
    # 如果不释放旧引擎, SQLAlchemy 连接池和 SQLite 文件句柄会累积
    try:
        from pyrit.memory import CentralMemory
        _existing_engine = getattr(CentralMemory, "_db_engine", None)
        if _existing_engine is not None:
            await CentralMemory.dispose_db_engine()
            logger.debug("Disposed previous PyRIT DB engine before re-init")
    except Exception as e:
        logger.debug("DB engine dispose before re-init skipped: %s", e)

    await initialize_pyrit_async(
        memory_db_type="SQLite",
        load_defaults=True,
        silent=True,
        db_path=str(db_path),
    )
    logger.info("PyRIT environment initialized (DB: %s)", db_path)
