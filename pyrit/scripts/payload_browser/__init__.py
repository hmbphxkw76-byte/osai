"""
===============================================================================
PyRIT Payload Browser — Flask 应用工厂
===============================================================================
"""
from __future__ import annotations

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

    # 延迟导入避免循环依赖
    from .routes import bp
    app.register_blueprint(bp)

    return app
