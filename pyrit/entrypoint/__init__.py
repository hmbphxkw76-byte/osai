"""
===============================================================================
PyRIT Red Team — 入口层
===============================================================================
将 main.py 的 CLI 职责按单一职责原则拆分为:

  entrypoint/parser.py   — argparse 参数定义与构建
  entrypoint/display.py  — 控制台信息展示与状态回显
  entrypoint/bootstrap.py — 环境初始化（Memory + Config + Target + Payload + Converters）
  entrypoint/router.py   — 命令路由（探索/渗透/legacy/原生模式分发）

使用方式:
  from entrypoint import build_parser, bootstrap_environment, route_command
===============================================================================
"""
from entrypoint.parser import build_parser
from entrypoint.display import print_cli_args
from entrypoint.bootstrap import bootstrap_environment
from entrypoint.router import route_command

__all__ = [
    "build_parser",
    "print_cli_args",
    "bootstrap_environment",
    "route_command",
]
