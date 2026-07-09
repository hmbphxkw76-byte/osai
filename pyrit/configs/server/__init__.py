"""
===============================================================================
PyRIT Config Center — Flask 应用工厂 + CLI 入口
===============================================================================
基于 Flask，提供 Web 界面管理 configs/ 目录下的所有环境变量配置文件。

启动方式:
  python -m configs.server                    # http://127.0.0.1:80
  python -m configs.server --port 8080        # 自定义端口
  python run_config_center.py                 # 根目录快捷启动（同效）

目录结构:
  configs/server/                 ← Web 框架包
  ├── __init__.py                  ← create_app() + main() 入口（本文件）
  ├── routes.py                    ← API 路由 (Blueprint) + 探测逻辑 + auto-configure
  ├── utils.py                     ← 配置读写与校验
  ├── target_config.py             ← 目标配置 & SDK 连接测试
  ├── templates/index.html         ← 前端 SPA
  └── static/style.css             ← 样式

依赖: flask, httpx, configparser（全部已在 requirements.txt 中）
===============================================================================
"""
from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

from flask import Flask

_PACKAGE_DIR = Path(__file__).resolve().parent


def create_app() -> Flask:
    """创建并配置 Flask 应用"""
    app = Flask(
        __name__,
        template_folder=str(_PACKAGE_DIR / "templates"),
        static_folder=str(_PACKAGE_DIR / "static"),
    )

    from .routes import bp
    app.register_blueprint(bp)

    return app


def run_async(coro):
    """同步包装器 — 在 Flask 同步路由中运行异步协程"""
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            try:
                import nest_asyncio
                nest_asyncio.apply()
            except ImportError:
                pass
            return loop.run_until_complete(coro)
        return loop.run_until_complete(coro)
    except RuntimeError:
        return asyncio.run(coro)


def main():
    parser = argparse.ArgumentParser(
        description="PyRIT Config Center — Web 端管理环境变量配置和探测目标"
    )
    parser.add_argument("--host", default="127.0.0.1",
                        help="监听地址 (默认 127.0.0.1，设为 0.0.0.0 将暴露到所有网络接口)")
    parser.add_argument("--port", type=int, default=80,
                        help="监听端口 (默认 80)")
    parser.add_argument("--debug", action="store_true",
                        help="调试模式 (生产环境禁止开启)")
    parser.add_argument("--no-open", action="store_true",
                        help="不自动打开浏览器 (默认自动打开)")
    args = parser.parse_args()

    if args.host in ("0.0.0.0", "::"):
        print("\n" + "=" * 60)
        print("  ⚠️  安全警告: 正在监听所有网络接口 (0.0.0.0)")
        print("  API Key 和凭证可能被同一网络中的其他设备访问")
        print("  仅在受信任的网络环境中使用此配置")
        print("=" * 60 + "\n")

    app = create_app()

    url = f"http://{args.host}:{args.port}"
    if args.host == "0.0.0.0":
        url = f"http://localhost:{args.port}"

    banner = f"""
╔══════════════════════════════════════════════════════════╗
║        PyRIT Config Center v2.0                         ║
║                                                          ║
║  打开浏览器访问: {url:<40} ║
║                                                          ║
║  功能:                                                   ║
║    [+] 配置预览 -- 结构化浏览所有 .env 变量              ║
║    [*] 配置编辑 -- 直接修改并保存回写文件                ║
║    [#] 凭证管理 -- api_key / jwt / cookie 文件           ║
║    [~] 目标探测 -- 连通性 / API 类型 / 模型枚举         ║
║    [=] 就绪检查 -- 配置完整性 + 目标可达性               ║
║    [>>] 一键配置 -- URL → 探测 → 自动填充（端到端）     ║
║                                                          ║
║  按 Ctrl+C 停止服务                                      ║
╚══════════════════════════════════════════════════════════╝
"""
    print(banner)

    if not args.no_open:
        import webbrowser
        webbrowser.open(url)

    app.run(host=args.host, port=args.port, debug=args.debug)


if __name__ == "__main__":
    main()
