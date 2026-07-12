"""自动安装外部侦察/扫描二进制（构建时一次性运行）。

Library-First：本项目不重新实现路径爆破、指纹识别等能力，而是直接复用成熟开源工具：
  - dirsearch (Python)  路径枚举（pip 依赖，无需额外安装）
  - nuclei (Go)         AI 基础设施/配置不当
  - katana (Go)         JS/SPA 端点爬取
  - arjun (Python)      HTTP 参数发现
  - mcp-scan (Python)   MCP 组件专项
  - AIMap (Bishop Fox)  AI 攻击面发现

本脚本把它们下载/安装到仓库内的 `tools/` 目录，并把路径写入 `config/settings.yaml` 的
`tools.*`，供运行期 ToolResolver 解析。运行需联网；仅下载官方发布物，不做任何修改系统全局
环境的事。

用法：
    py -m scripts.install_tools
    python scripts/install_tools.py
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parent.parent
TOOLS_DIR = ROOT / "tools"
SETTINGS = ROOT / "config" / "settings.yaml"
GITHUB_API = "https://api.github.com/repos/{repo}/releases/latest"


def log(msg: str) -> None:
    print(f"[install_tools] {msg}")


def _req(url: str) -> bytes:
    req = Request(url, headers={"User-Agent": "redteam-ai-installer"})
    with urlopen(req, timeout=60) as resp:
        return resp.read()


def run(cmd: list[str]) -> int:
    log("> " + " ".join(cmd))
    return subprocess.call(cmd)


def download(url: str, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    data = _req(url)
    dest.write_bytes(data)
    log(f"downloaded {dest.name} ({len(data)} bytes)")


def latest_asset_url(repo: str, match) -> str:
    """从 GitHub releases/latest 找到首个名称匹配的资产下载地址。"""
    meta = json.loads(_req(GITHUB_API.format(repo=repo)))
    assets = meta.get("assets", [])
    for a in assets:
        name = a["name"].lower()
        if callable(match):
            ok = match(name)
        else:
            ok = all(k in name for k in match)
        if ok:
            return a["browser_download_url"]
    raise RuntimeError(f"no matching asset in {repo} latest release (assets={[a['name'] for a in assets]})")


def install_github_windows(repo: str, name: str, match) -> Path | None:
    """下载 windows amd64 的 zip 发布物，解压并把 exe 放到 tools/<name>.exe。"""
    try:
        url = latest_asset_url(repo, match)
    except Exception as e:  # noqa: BLE001
        log(f"SKIP {name}: {e}")
        return None
    zip_path = TOOLS_DIR / f"_{name}.zip"
    download(url, zip_path)
    extract_dir = TOOLS_DIR / f"_{name}_extract"
    if extract_dir.exists():
        shutil.rmtree(extract_dir)
    extract_dir.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(zip_path) as zf:
        zf.extractall(extract_dir)
    exes = list(extract_dir.rglob("*.exe"))
    if not exes:
        log(f"SKIP {name}: no exe found after extract")
        return None
    target = TOOLS_DIR / f"{name}.exe"
    shutil.copy(exes[0], target)
    shutil.rmtree(extract_dir)
    zip_path.unlink(missing_ok=True)
    log(f"installed {target}")
    return target


def install_pip(pkg: str) -> bool:
    code = run([sys.executable, "-m", "pip", "install", pkg])
    return code == 0


def install_aimap() -> bool:
    """AIMap：克隆仓库后尝试 pip 安装（部分为 Go 单文件，失败则给出手动提示）。"""
    repo_dir = TOOLS_DIR / "aimap_src"
    if not repo_dir.exists():
        code = run(["git", "clone", "https://github.com/BishopFox/aimap", str(repo_dir)])
        if code != 0:
            log("SKIP aimap: git clone failed")
            return False
    code = run([sys.executable, "-m", "pip", "install", "-e", str(repo_dir)])
    if code == 0:
        log("installed aimap (pip -e)")
        return True
    log("aimap pip install failed; 视其发布形态可能需要 'go install' 或直接使用发布二进制，请参考 BishopFox/aimap README")
    return False


def patch_settings(paths: dict[str, str | None]) -> None:
    if not SETTINGS.exists():
        return
    import yaml

    data = yaml.safe_load(SETTINGS.read_text(encoding="utf-8")) or {}
    tools = data.setdefault("tools", {})
    for k, v in paths.items():
        if v:
            rel = Path(v)
            tools[k] = str(rel) if rel.is_absolute() else str(rel)
    SETTINGS.write_text(yaml.safe_dump(data, sort_keys=False, allow_unicode=True), encoding="utf-8")
    log("patched config/settings.yaml tools.*")


def main() -> int:
    TOOLS_DIR.mkdir(parents=True, exist_ok=True)
    log(f"tools dir: {TOOLS_DIR}")

    results: dict[str, str | None] = {}

    # dirsearch 通过 pip 安装（requirements.txt 已声明），此处无需额外下载
    results["nuclei"] = str(
        install_github_windows("projectdiscovery/nuclei", "nuclei", ["windows", "amd64", ".zip"])
        or TOOLS_DIR / "nuclei.exe"
    )
    results["katana"] = str(
        install_github_windows("projectdiscovery/katana", "katana", ["windows", "amd64", ".zip"])
        or TOOLS_DIR / "katana.exe"
    )

    if not install_pip("arjun"):
        log("arjun pip install 失败，可手动 'pip install arjun'")
    if not install_pip("mcp-scan"):
        log("mcp-scan pip install 失败，可手动 'pip install mcp-scan'（包名以官方为准）")

    # AIMap 之名在 tools.* 中指向可执行入口；能 pip 装则用命令名，否则保留占位
    if install_aimap():
        results["aimap"] = "aimap"
    else:
        results["aimap"] = "aimap"  # 命令名，需用户按 README 完成安装

    patch_settings(results)
    log("done. 重新运行流水线即可；缺失工具会在 auto 模式下自动跳过。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
