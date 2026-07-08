"""
===============================================================================
PyRIT Config Center — 入口脚本
===============================================================================
基于 Flask，提供 Web 界面管理 configs/ 目录下的所有环境变量配置文件。
功能：
  1. 浏览并编辑 shared.env / platforms.env / targets.env / recons.env
  2. 管理 configs/tokens/ 下的临时凭证文件
  3. 语法校验 + %(VAR)s 插值完整性检查
  4. 目标端点连通性探测 + API 类型识别 + 模型枚举
  5. 就绪检查 — 确保所有配置完整后再进入攻击阶段

启动方式:
  python scripts/config_center.py              # 默认 http://127.0.0.1:5051
  python scripts/config_center.py --port 8080  # 自定义端口
  python scripts/config_center.py --debug      # 调试模式

目录结构:
  scripts/config_center/          ← Web 框架包
  ├── __init__.py                  ← create_app() 工厂
  ├── routes.py                    ← API 路由 (Blueprint)
  ├── utils.py                     ← 配置读写与校验
  ├── readiness_probe.py           ← 目标探测聚合层（委托 targets/ 层）
  ├── templates/index.html         ← 前端页面
  └── static/style.css             ← 样式

依赖: flask, httpx, configparser (全部已在 requirements.txt 中，零新增)
===============================================================================
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

# 确保项目根目录在 sys.path 中
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

from scripts.config_center import create_app


def main():
    parser = argparse.ArgumentParser(
        description="PyRIT Config Center — Web 端管理环境变量配置和探测目标"
    )
    parser.add_argument("--host", default="127.0.0.1",
                        help="监听地址 (默认 127.0.0.1，设为 0.0.0.0 将暴露到所有网络接口)")
    parser.add_argument("--port", type=int, default=5051,
                        help="监听端口 (默认 5051)")
    parser.add_argument("--debug", action="store_true",
                        help="调试模式 (生产环境禁止开启)")
    parser.add_argument("--no-open", action="store_true",
                        help="不自动打开浏览器 (默认自动打开)")
    args = parser.parse_args()

    # 安全检查：绑定 0.0.0.0 时显式警告
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

    # 使用 ANSI 兼容字符，避免 Windows GBK 编码错误
    banner = f"""
╔══════════════════════════════════════════════════════════╗
║        PyRIT Config Center v1.0                         ║
║                                                          ║
║  打开浏览器访问: {url:<40} ║
║                                                          ║
║  功能:                                                   ║
║    [+] 配置预览 -- 结构化浏览所有 .env 变量              ║
║    [*] 配置编辑 -- 直接修改并保存回写文件                ║
║    [#] 凭证管理 -- api_key / jwt / cookie 文件           ║
║    [~] 目标探测 -- 连通性 / API 类型 / 模型枚举         ║
║    [=] 就绪检查 -- 配置完整性 + 目标可达性               ║
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
