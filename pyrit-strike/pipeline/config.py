"""CLI 参数解析 + 环境初始化 + 输出目录管理.

职责:
    - _load_defaults: 从 config/defaults.yaml 加载 YAML 默认值
    - _apply_defaults: 用 YAML 默认值填充 None 参数
    - parse_args: CLI 参数解析 (argparse)
    - get_output_dir: 输出目录路径生成 (带时间戳)
    - ensure_output_dir: 创建输出目录及子目录 (evidence/, db/, poc/)
    - setup_environment: PyRIT 环境初始化 (SQLite WAL 模式)

优先级: CLI --flag > config/defaults.yaml > 硬编码默认值
"""

from __future__ import annotations

import argparse
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml

# L5 v46: 自动加载 .env 文件 (python-dotenv)
# 确保从 CLI 运行时能正确读取 ADVERSARIAL_CHAT_*, SCORING_CHAT_* 等环境变量
try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    pass

logger = logging.getLogger(__name__)

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_DEFAULTS_YAML = _PROJECT_ROOT / "config" / "defaults.yaml"


def _load_defaults() -> dict[str, Any]:
    """从 config/defaults.yaml 加载默认值.

    Returns:
        包含默认参数的字典。如果 YAML 文件不存在则返回空字典。
    """
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
    """用 YAML 默认值填充 args 中为 None 的参数.

    映射关系:
        YAML max_seeds → args.max_seeds
        YAML max_attempts → args.max_attempts
        YAML max_concurrency → args.max_concurrency
        YAML scenario_timeout → args.timeout
        其余同名字段直接映射

    Args:
        args: argparse Namespace 对象 (原地修改).
        defaults: _load_defaults() 返回的字典.
    """
    # 特殊映射: YAML scenario_timeout → args.timeout
    key_map = {
        "scenario_timeout": "timeout",
    }
    for yaml_key, default_val in defaults.items():
        arg_key = key_map.get(yaml_key, yaml_key)
        current = getattr(args, arg_key, None)
        if current is None:
            setattr(args, arg_key, default_val)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """解析 CLI 参数.

    Args:
        argv: 可选参数列表。None 时使用 sys.argv。

    Returns:
        argparse Namespace 对象, 已应用 YAML 默认值和策略预设。
    """
    parser = argparse.ArgumentParser(
        description="PyRIT-Strike — AI Red Team Automated Attack Pipeline",
    )

    # ── 目标配置 ──
    parser.add_argument(
        "--burp-request",
        type=str,
        default="data/burp/request.txt",
        help="Burp 拦截的 HTTP 请求文件路径",
    )
    parser.add_argument(
        "--browser-url",
        type=str,
        default=os.environ.get("BROWSER_TARGET_URL"),
        help="浏览器目标 URL (PlaywrightTarget, 用于前端渲染目标)",
    )
    parser.add_argument(
        "--auth-state",
        type=str,
        default=None,
        help="认证状态 JSON 文件路径 (用于注入 auth headers)",
    )

    # ── 攻击配置 ──
    parser.add_argument(
        "--seeds",
        type=str,
        default="elite_jailbreaks,asi_top10,owasp_full_coverage",
        help="种子文件名 (逗号分隔)",
    )
    parser.add_argument(
        "--techniques",
        type=str,
        default="auto",
        help="攻击技术 (auto, single, crescendo_simulated, tap, pair, adaptive, ...)",
    )
    parser.add_argument(
        "--converters",
        type=str,
        default="auto",
        help="Converter 链 (auto, l5_optimal, encoding, stealth, none, ...)",
    )
    parser.add_argument(
        "--max-seeds",
        type=int,
        default=None,
        help="最大种子数 (默认从 config/defaults.yaml 读取 = 25)",
    )
    parser.add_argument(
        "--max-attempts",
        type=int,
        default=None,
        help="每个种子的最大重试次数 (默认从 config/defaults.yaml = 3, arXiv:2402.01135)",
    )
    parser.add_argument(
        "--max-concurrency",
        type=int,
        default=None,
        help="最大并发数 (默认从 config/defaults.yaml = 3, SQLite WAL 安全上限)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=None,
        help="场景超时秒数 (默认从 config/defaults.yaml = 1200)",
    )

    # ── 策略预设 ──
    from pipeline.strategy.presets import STRATEGY_PRESETS

    strategy_choices = list(STRATEGY_PRESETS.keys()) + ["auto"]
    parser.add_argument(
        "--strategy",
        type=str,
        default=None,
        choices=strategy_choices,
        help="攻击策略预设 (覆盖 seeds, techniques, converters 等)",
    )

    # ── 升级 ──
    parser.add_argument(
        "--escalation",
        action="store_true",
        default=None,
        help="启用多轮升级 (Crescendo→TAP→PAIR→GCG, ASR<90%%时触发)",
    )
    parser.add_argument(
        "--no-escalation",
        action="store_false",
        dest="escalation",
        help="禁用多轮升级",
    )

    # ── 模式标志 ──
    parser.add_argument(
        "--offensive",
        action="store_true",
        default=False,
        help="全火力模式 (converters=l5_optimal + html_report + max_attempts=3)",
    )
    parser.add_argument(
        "--auto-seeds",
        action="store_true",
        default=False,
        help="自动种子扩充 (AutoDAN 3x, ASR +1.5-2x, arXiv:2310.04451)",
    )
    parser.add_argument(
        "--enable-dos",
        action="store_true",
        default=False,
        help="启用 DoS 攻击 (LLM10, 消耗大量 token, 默认禁用)",
    )

    # ── 报告 ──
    parser.add_argument(
        "--html-report",
        action="store_true",
        default=False,
        help="生成 HTML 报告 (含 PoC 脚本 + OWASP 覆盖矩阵)",
    )

    # ── 输出 ──
    parser.add_argument(
        "--output-dir",
        type=str,
        default=None,
        help="输出目录 (默认自动生成 outputs/redteam_YYYYMMDD_HHMMSS)",
    )
    parser.add_argument(
        "--resume",
        type=str,
        default=None,
        help="从已有场景恢复 (场景 ID)",
    )

    # ── 日志 ──
    parser.add_argument(
        "--verbose",
        action="store_true",
        default=True,
        help="详细日志输出 (含 ASR/Wilson CI/Dual Judge 统计)",
    )
    parser.add_argument(
        "--quiet",
        action="store_false",
        dest="verbose",
        help="减少日志输出",
    )

    args = parser.parse_args(argv)

    # 记录用户是否显式设置了 escalation (在策略预设覆盖之前)
    explicit_escalation = args.escalation  # None=未设置, True/--escalation, False/--no-escalation

    # ── 应用 YAML 默认值 ──
    defaults = _load_defaults()
    _apply_defaults(args, defaults)

    # ── 应用 --offensive 预设 ──
    if args.offensive:
        args.converters = "l5_optimal"
        args.html_report = True
        if args.max_attempts is None:
            args.max_attempts = 3

    # ── 应用 --strategy 预设 (优先级高于 --offensive) ──
    if args.strategy:
        from pipeline.strategy.presets import get_strategy_args

        strategy_overrides = get_strategy_args(args.strategy)
        for key, val in strategy_overrides.items():
            setattr(args, key, val)

    # ── escalation 处理 ──
    # 优先级: 用户显式设置 (--escalation/--no-escalation) > 策略预设 > 默认 True
    if explicit_escalation is not None:
        args.escalation = explicit_escalation
    elif args.escalation is None:
        args.escalation = True

    return args


def get_output_dir(args: argparse.Namespace) -> Path:
    """生成输出目录路径.

    规则:
        1. 如果 args.output_dir 不为 None, 直接使用
        2. 否则自动生成: outputs/redteam_YYYYMMDD_HHMMSS[_strategy]

    Args:
        args: parse_args() 返回的 Namespace.

    Returns:
        输出目录的 Path 对象。
    """
    if args.output_dir is not None:
        return Path(args.output_dir)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    strategy = getattr(args, "strategy", None)

    if strategy and strategy != "auto":
        dir_name = f"redteam_{timestamp}_{strategy}"
    else:
        dir_name = f"redteam_{timestamp}"

    return _PROJECT_ROOT / "outputs" / dir_name


def ensure_output_dir(output_dir: Path) -> Path:
    """创建输出目录及子目录.

    子目录:
        - evidence/ — 证据文件
        - db/ — SQLite 数据库
        - poc/ — PoC 脚本 (可选, 延迟创建)

    Args:
        output_dir: 输出目录路径.

    Returns:
        创建后的输出目录路径。
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "evidence").mkdir(parents=True, exist_ok=True)
    (output_dir / "db").mkdir(parents=True, exist_ok=True)
    return output_dir


async def setup_environment(output_dir: Path) -> None:
    """初始化 PyRIT 环境.

    - 自动加载 .env (如果尚未加载)
    - 设置 SQLite 数据库路径 (output_dir/db/pyrit.db)
    - 启用 WAL 模式 + busy_timeout
    - 初始化 PyRIT 内存实例

    Args:
        output_dir: 输出目录路径。
    """
    # L5 v46: 确保 .env 已加载 (双重保险, parse_args 中已调用过 load_dotenv)
    try:
        from dotenv import load_dotenv
        load_dotenv()
    except ImportError:
        pass

    from pyrit.setup.initialization import initialize_pyrit_async

    db_path = Path(output_dir) / "db" / "pyrit.db"
    db_path.parent.mkdir(parents=True, exist_ok=True)

    # 设置环境变量, PyRIT initialize 会读取
    os.environ["PYRIT_DB_URL"] = f"sqlite:///{db_path}"

    # L5 v25: WAL 模式 + busy_timeout (并发安全)
    os.environ.setdefault("PYRIT_SQLITE_JOURNAL_MODE", "WAL")
    os.environ.setdefault("PYRIT_SQLITE_BUSY_TIMEOUT", "5000")

    await initialize_pyrit_async(
        memory_db_type="SQLite",
        load_defaults=True,
        silent=True,
        db_path=str(db_path),
    )
    logger.info("PyRIT environment initialized (DB: %s)", db_path)
