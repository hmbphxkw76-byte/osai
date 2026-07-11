#!/usr/bin/env python3
"""
cookie_to_authfile.py — 浏览器 Cookie → --auth-file 格式转换器

支持的输入格式:
  1. 浏览器 DevTools → Network → 右键请求 → "Copy request headers"
  2. 浏览器 DevTools → Network → 右键请求 → "Copy as cURL (bash)"
  3. 浏览器 DevTools → Network → 右键请求 → "Copy as fetch (Node.js)"
  4. 手动粘贴纯 Cookie 字符串 (key1=value1; key2=value2; ...)
  5. Netscape cookies.txt (浏览器扩展导出格式)
  6. 直接从 stdin 或文件读取

用法:
  # 交互式粘贴（最常用）
  python tools/cookie_to_authfile.py

  # 从文件读取
  python tools/cookie_to_authfile.py -i raw_cookie.txt

  # 指定输出文件
  python tools/cookie_to_authfile.py -o auth_cookie.txt

  # 静默模式（管道友好）
  echo "key1=val1; key2=val2" | python tools/cookie_to_authfile.py -q
"""

import argparse
import re
import sys
from pathlib import Path


# ── 格式解析器 ──

def parse_copy_as_curl(text: str) -> str | None:
    """从 'Copy as cURL' 中提取 Cookie 和关键 Header。

    格式: curl 'https://...' -H 'Cookie: k1=v1; k2=v2' -H 'XSRF-TOKEN: xxx' ...
    """
    cookies = []
    headers = []

    # 匹配 -H 'Header-Name: header-value'
    header_pattern = re.findall(
        r"""-H\s+['"]([^'"]+)['"]""", text
    )
    for h in header_pattern:
        if ": " in h:
            name, _, value = h.partition(": ")
            if name.lower() == "cookie":
                cookies.append(value)
            # 收集可能和认证相关的 header
            elif name.lower() in {
                "authorization", "x-xsrf-token", "x-csrf-token",
                "xsrf-token", "csrf-token", "x-api-key",
            }:
                headers.append((name, value))

    if cookies:
        result = "; ".join(cookies)
        # 如果有 JWT/Cookie 混合的情况，追加 Authorization
        for name, value in headers:
            result += f"\n# Extra header: {name}: {value}"
        return result
    return None


def parse_copy_as_fetch(text: str) -> str | None:
    """从 'Copy as fetch' 中提取 Cookie 和关键 Header。

    格式: fetch("https://...", {headers: {"Cookie": "k1=v1", ...}})
    """
    # 提取整个 headers 对象
    # 匹配 "Cookie": "value" 或 "Cookie": 'value'
    header_block = re.search(
        r'''"headers"\s*:\s*\{([^}]+(?:\{[^}]*\}[^}]*)*)\}''',
        text, re.DOTALL
    )
    if not header_block:
        return None

    headers_str = header_block.group(1)
    cookies = []

    # 匹配 "Header-Name": "value" 或 "Header-Name": 'value'
    cookie_match = re.findall(
        r'''"Cookie"\s*:\s*["']([^"']+)["']''',
        headers_str
    )
    cookies.extend(cookie_match)

    if cookies:
        return "; ".join(cookies)
    return None


def parse_request_headers(text: str) -> str | None:
    """从原始请求头文本中提取 Cookie。

    格式:
        GET /path HTTP/1.1
        Host: example.com
        Cookie: key1=value1; key2=value2
        XSRF-TOKEN: xxx
    """
    cookies = []
    lines = text.strip().split("\n")
    for line in lines:
        if ":" in line:
            name, _, value = line.partition(":")
            if name.strip().lower() == "cookie":
                cookies.append(value.strip())

    if cookies:
        return "; ".join(cookies)

    # 如果没找到 Cookie: 行，尝试找 set-cookie
    # (但 set-cookie 一般是响应头，用户大概率复制错了)
    return None


def parse_netscape_cookies(text: str) -> str | None:
    """从 Netscape cookies.txt 格式提取。

    格式（每行）:
        domain  flag  path  secure  expiration  name  value
        .example.com  TRUE  /  FALSE  1234567890  key  value
    """
    pairs = []
    for line in text.strip().split("\n"):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) >= 7:
            name = parts[5].strip()
            value = parts[6].strip()
            pairs.append(f"{name}={value}")
        elif len(parts) >= 6:
            # 有些导出可能只有 6 列
            name = parts[5].strip()
            pairs.append(name)

    if pairs:
        return "; ".join(pairs)
    return None


def parse_raw_cookie(text: str) -> str | None:
    """纯 Cookie 字符串: key1=value1; key2=value2; ..."""
    text = text.strip()
    if "=" in text:
        return text
    return None


def is_netscape_format(text: str) -> bool:
    """检测是否是 Netscape cookies.txt 格式."""
    lines = [l for l in text.strip().split("\n") if l.strip() and not l.strip().startswith("#")]
    if not lines:
        return False
    # Netscape 格式: 每行至少 7 个 tab 分隔的字段
    tab_lines = [l for l in lines if "\t" in l and len(l.split("\t")) >= 6]
    return len(tab_lines) >= len(lines) * 0.5


def is_curl_format(text: str) -> bool:
    """检测是否是 cURL 格式."""
    return bool(re.search(r"curl\s+['\"]", text))


def is_fetch_format(text: str) -> bool:
    """检测是否是 fetch 格式."""
    return bool(re.search(r'fetch\s*\(', text)) and '"headers"' in text


def is_request_headers_format(text: str) -> bool:
    """检测是否是原始请求头格式."""
    first_line = text.strip().split("\n")[0].strip()
    return bool(re.match(r'^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+', first_line))


def convert(text: str) -> tuple[str, str]:
    """主转换函数：自动检测格式并提取 Cookie 字符串。

    Returns:
        (cookie_string, format_description)
    """
    text = text.strip()

    if not text:
        raise ValueError("输入为空")

    # 按优先级检测格式
    detectors = [
        (is_curl_format, parse_copy_as_curl, "Copy as cURL (bash)"),
        (is_fetch_format, parse_copy_as_fetch, "Copy as fetch (Node.js)"),
        (is_request_headers_format, parse_request_headers, "Copy request headers"),
        (is_netscape_format, parse_netscape_cookies, "Netscape cookies.txt"),
    ]

    for detector, parser, desc in detectors:
        if detector(text):
            result = parser(text)
            if result:
                return result, desc
            else:
                raise ValueError(f"检测到 {desc} 格式，但提取 Cookie 失败（可能不含 Cookie）")

    # 兜底：纯 Cookie 字符串
    result = parse_raw_cookie(text)
    if result:
        return result, "Raw Cookie string"
    else:
        raise ValueError(
            "无法识别输入格式。请确认已从浏览器 DevTools 复制了正确的内容。\n"
            "支持的格式：Copy as cURL / Copy as fetch / Copy request headers / 纯 Cookie 字符串 / cookies.txt"
        )


def sanitize_cookie(cookie_str: str) -> str:
    """清洗 Cookie：去除首尾空白，确保分号分隔规范."""
    # 标准化分号分隔（有些工具用逗号分隔，有些混用 ; 和 ;）
    cookie_str = cookie_str.strip()
    # 移除多余的空白
    cookie_str = re.sub(r'\s*;\s*', '; ', cookie_str)
    return cookie_str


# ── CLI ──

def interactive_mode(output_path: str | None, quiet: bool = False):
    """交互式模式：从控制台多行输入。"""
    if not quiet:
        print("=" * 60)
        print("  Cookie → auth-file 转换器")
        print("=" * 60)
        print()
        print("📋 操作步骤:")
        print("  1. 在浏览器中打开目标 AI 应用并登录")
        print("  2. 按 F12 打开开发者工具 → Network 标签")
        print("  3. 刷新页面，找到任一 API 请求（如 /chat 或 /api/xxx）")
        print("  4. 右键该请求 → Copy → Copy as cURL (bash)")
        print("     （或 Copy request headers / Copy as fetch）")
        print("  5. 粘贴到下方，输入完成后按 Enter 再按 Ctrl+Z (Windows)")
        print("     或 Ctrl+D (Mac/Linux) 结束")
        print()
        print("💡 你也可以直接粘贴 Cookie 字符串:")
        print("     key1=value1; key2=value2; ...")
        print()
        print("─" * 40)
        print("请粘贴（多行可，Ctrl+Z/Ctrl+D 结束输入）:")
        print()

    lines = []
    try:
        for line in sys.stdin:
            lines.append(line)
    except KeyboardInterrupt:
        print("\n\n已取消。")
        sys.exit(0)

    text = "".join(lines).strip()

    if not text:
        if not quiet:
            print("❌ 未检测到任何输入。")
        sys.exit(1)

    process(text, output_path, quiet)


def process(text: str, output_path: str | None, quiet: bool = False):
    """处理输入文本并写入文件."""
    try:
        cookie_str, fmt_desc = convert(text)
        cookie_str = sanitize_cookie(cookie_str)

        if output_path:
            outpath = Path(output_path)
        else:
            outpath = Path("auth_cookie.txt")

        outpath.write_text(cookie_str, encoding="utf-8")

        if not quiet:
            # 统计信息
            pair_count = cookie_str.count("=")
            print()
            print("=" * 60)
            print("  ✅ 转换成功！")
            print("=" * 60)
            print(f"  检测格式 : {fmt_desc}")
            print(f"  Cookie 长度 : {len(cookie_str)} 字符")
            print(f"  Cookie 对数 : 约 {pair_count} 个 key=value 对")
            print(f"  输出文件 : {outpath.absolute()}")
            print()
            print("─" * 40)
            print("🚀 使用方式:")
            print()
            print(f"  python recon/main.py --target <目标URL> \\")
            print(f"    --storage-state {outpath} \\")
            print(f"    --har-output outputs/traffic.har")
            print()
            print("  # 或用 --auth-cookie 临时注入（仅 Cookie，不含 localStorage/sessionStorage）:")
            print(f"  python recon/main.py --target <目标URL> \\")
            print(f"    --auth-cookie $(cat {outpath})")
            print()
            print("💡 提示:")
            print("  • Cookie 可能会过期，如果侦察报 401/403，请重新导出")
            print("  • 请在生产环境使用前确保有合法授权")
            print("  • 文件内容可通过 notepad auth_cookie.txt 查看")
        else:
            # 静默模式：只输出文件路径
            print(str(outpath.absolute()))

    except ValueError as e:
        if not quiet:
            print(f"\n❌ 错误: {e}")
            print()
            print("🔧 故障排除:")
            print("  1. 确认已从 Network 标签复制了完整的请求信息")
            print("  2. 推荐使用 'Copy as cURL (bash)' 格式（兼容性最好）")
            print("  3. 检查粘贴的内容是否包含 'Cookie:' 前缀或 cookie 键值对")
            print("  4. 如果手动输入 Cookie，格式应为: key1=value1; key2=value2")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="浏览器 Cookie → RedTeam_AI --auth-file 格式转换器",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  # 交互式粘贴
  python tools/cookie_to_authfile.py

  # 从文件读取并指定输出
  python tools/cookie_to_authfile.py -i curl_dump.txt -o my_auth.txt

  # 管道输入
  cat raw_cookie.txt | python tools/cookie_to_authfile.py -q -o auth.txt
        """,
    )
    parser.add_argument(
        "-i", "--input",
        help="输入文件路径（不指定则进入交互式粘贴模式）",
    )
    parser.add_argument(
        "-o", "--output",
        default="auth_cookie.txt",
        help="输出文件路径（默认: auth_cookie.txt）",
    )
    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="静默模式：不输出提示信息，仅输出结果文件路径",
    )
    args = parser.parse_args()

    if args.input:
        # 从文件读取
        input_path = Path(args.input)
        if not input_path.exists():
            print(f"❌ 文件不存在: {args.input}")
            sys.exit(1)
        text = input_path.read_text(encoding="utf-8")
        process(text, args.output, args.quiet)
    else:
        interactive_mode(args.output, args.quiet)


if __name__ == "__main__":
    main()
