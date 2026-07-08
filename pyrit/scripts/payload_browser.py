"""
===============================================================================
PyRIT Payload Browser — 入口脚本
===============================================================================
基于 Flask + Monaco Editor，提供：
  1. 直观浏览所有 datasets/payloads/ 下的 YAML 载荷
  2. 浏览器内编辑 payload 内容并自动保存到对应 YAML 文件
  3. 搜索/复制/统计功能，渗透测试期间提高效率

启动方式:
  python scripts/payload_browser.py              # 默认 http://127.0.0.1:5050
  python scripts/payload_browser.py --port 8080  # 自定义端口

目录结构:
  scripts/payload_browser/          ← Web 框架包
  ├── __init__.py                   ← create_app() 工厂
  ├── routes.py                     ← API 路由 (Blueprint)
  ├── utils.py                      ← 工具函数
  ├── templates/index.html          ← 前端页面
  └── static/style.css              ← 样式

依赖: flask, pyyaml (已在 requirements.txt 中)
===============================================================================
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

# 确保项目根目录在 sys.path 中
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

from scripts.payload_browser import create_app


def main():
    parser = argparse.ArgumentParser(
        description="PyRIT Payload Browser — Web 端浏览和编辑 YAML 载荷文件"
    )
    parser.add_argument("--host", default="127.0.0.1", help="监听地址 (默认 127.0.0.1)")
    parser.add_argument("--port", type=int, default=5050, help="监听端口 (默认 5050)")
    parser.add_argument("--debug", action="store_true", help="调试模式")
    parser.add_argument("--no-open", action="store_true",
                        help="不自动打开浏览器 (默认自动打开)")
    args = parser.parse_args()

    app = create_app()

    url = f"http://{args.host}:{args.port}"
    print(f"""
╔══════════════════════════════════════════════════════════╗
║          ⚡ PyRIT Payload Browser v1.0                    ║
║                                                          ║
║  打开浏览器访问: {url:<40} ║
║                                                          ║
║  功能:                                                   ║
║    📋 预览模式 — 结构化浏览所有 payload                  ║
║    ✏️ 编辑模式 — Monaco 编辑器直接修改 YAML             ║
║    💾 Ctrl+S 保存 — 自动回写文件                        ║
║    🔍 全局搜索 — 跨模块关键词检索                       ║
║                                                          ║
║  按 Ctrl+C 停止服务                                      ║
╚══════════════════════════════════════════════════════════╝
""")

    if not args.no_open:
        import webbrowser
        webbrowser.open(url)

    app.run(host=args.host, port=args.port, debug=args.debug)


if __name__ == "__main__":
    main()
