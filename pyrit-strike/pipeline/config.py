"""CLI 参数解析 + 环境初始化 + 输出目录管理.
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
    """
    parser = argparse.ArgumentParser(
        description="PyRIT-Strike — AI Red Team Automated Attack Pipeline",
    )

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

    from pipeline.strategy.presets import STRATEGY_PRESETS

    strategy_choices = list(STRATEGY_PRESETS.keys()) + ["auto"]
    parser.add_argument(
        "--strategy",
        type=str,
        default=None,
        choices=strategy_choices,
        help="攻击策略预设 (覆盖 seeds, techniques, converters 等)",
    )

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

    parser.add_argument(
        "--html-report",
        action="store_true",
        default=False,
        help="生成 HTML 报告 (含 PoC 脚本 + OWASP 覆盖矩阵)",
    )

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

    defaults = _load_defaults()
    _apply_defaults(args, defaults)

    if args.offensive:
        args.converters = "l5_optimal"
        args.html_report = True
        if args.max_attempts is None:
            args.max_attempts = 3

    if args.strategy:
        from pipeline.strategy.presets import get_strategy_args

        strategy_overrides = get_strategy_args(args.strategy)
        for key, val in strategy_overrides.items():
            setattr(args, key, val)

    # 优先级: 用户显式设置 (--escalation/--no-escalation) > 策略预设 > 默认 True
    if explicit_escalation is not None:
        args.escalation = explicit_escalation
    elif args.escalation is None:
        args.escalation = True

    return args

def get_output_dir(args: argparse.Namespace) -> Path:
    """生成输出目录路径.
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
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "evidence").mkdir(parents=True, exist_ok=True)
    (output_dir / "db").mkdir(parents=True, exist_ok=True)
    return output_dir

async def setup_environment(output_dir: Path) -> None:
    """初始化 PyRIT 环境.
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
