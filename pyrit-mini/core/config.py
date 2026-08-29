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

    # ── 侦察: Burp 拦截 ──
    parser.add_argument(
        "--burp-request",
        type=str,
        default="data/burp/request.txt",
        help="Burp 拦截的 HTTP 请求文件路径",
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
    """初始化 PyRIT 环境 — SQLite WAL 模式 + 内存实例."""
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

    await initialize_pyrit_async(
        memory_db_type="SQLite",
        load_defaults=True,
        silent=True,
        db_path=str(db_path),
    )
    logger.info("PyRIT environment initialized (DB: %s)", db_path)
