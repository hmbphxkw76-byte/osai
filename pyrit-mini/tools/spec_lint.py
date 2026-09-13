"""规约最小 diff 门禁 (Spec Minimal-Diff Linter)。

把「编辑 specs 的硬纪律」从"靠自觉"变成"机器可校验"，落地 `AGENTS.md` §2 的
S2（禁整文件覆盖）/ S3（禁重排章节号）/ S6（规模自检），以及稳定锚点 sid 的
唯一性校验。规则本体见宪法 C4 / `docs/specs/README.md` §5 文档纪律。

检测项：
  1. 整篇覆盖重写（相对 HEAD，单文件删除行 ≥ 70% 总行且非新增）→ BLOCKING
  2. 大规模改动（增+删 ≥ 50% 总行）→ WARNING（提示拆分为增量编辑）
  3. sid 锚点唯一性（全局）→ BLOCKING（重复）/ WARNING（格式）
  4. sid 引用存在性（正文 [sid:...] 须指向已声明锚点）→ BLOCKING（悬空，D8）
  5. 文档路径存在性（markdown 链接本地路径须真实存在）→ WARNING（失效，D5）

用法：
  python -m tools.spec_lint              # 检测 docs/specs 相对 HEAD 的 diff 规模
  python -m tools.spec_lint --sid        # 校验 [sid:...] 锚点唯一性
  python -m tools.spec_lint --describe   # 打印检查规则说明（供规约引用）

退出码：0 = 通过（含仅 WARNING）；1 = 存在 BLOCKING。
"""
from __future__ import annotations

import argparse
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SPECS_DIR = ROOT / "docs" / "specs"

# 整篇重写判定：相对 HEAD 的删除行数占比 ≥ 该值 → BLOCKING
_REWRITE_DEL_RATIO = 0.70
# 大规模改动判定：增+删 占比 ≥ 该值 → WARNING
_LARGE_CHURN_RATIO = 0.50

# sid 格式：[sid:<doc>-<slug>]，如 [sid:40-ch1]；仅匹配标题行（## / ###）行尾的 sid，
# 避免误判规范说明/示例中的 [sid:...] 字样。
_SID_TITLE_RE = re.compile(r"^#{2,3}\s+.*\[sid:([a-z0-9]+-[a-z0-9\-]+)\]\s*$")


def _git_diff_numstat() -> list[tuple[int, int, str]]:
    """返回 (add, del, path) 列表，path 为相对 ROOT 的 docs/specs 下 md 文件。

    BL-070：git 输出必须显式 UTF-8 解码（Windows 非 ASCII 路径按 GBK 解码会乱码）。
    """
    try:
        proc = subprocess.run(
            ["git", "diff", "--numstat", "HEAD", "--", "docs/specs"],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            encoding="utf-8",
            check=False,
        )
    except FileNotFoundError:
        return []
    rows: list[tuple[int, int, str]] = []
    for line in proc.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) < 3:
            continue
        add_s, del_s, path = parts[0], parts[1], parts[2]
        if not add_s.isdigit() and not del_s.isdigit():
            continue  # 二进制 / rename
        add = int(add_s) if add_s.isdigit() else 0
        dele = int(del_s) if del_s.isdigit() else 0
        if path.endswith(".md"):
            rows.append((add, dele, path))
    return rows


def _line_count(rel_path: str) -> int:
    p = ROOT / rel_path
    if not p.exists():
        return 0
    try:
        return sum(1 for _ in p.read_text(encoding="utf-8", errors="replace").splitlines())
    except OSError:
        return 0


def check_diff_scale() -> tuple[list[str], list[str]]:
    """检测整篇重写(BLOCKING)与大规模改动(WARNING)。"""
    blocking: list[str] = []
    warning: list[str] = []
    for add, dele, path in _git_diff_numstat():
        total = _line_count(path)
        if total <= 0:
            continue
        if add <= 0 and dele <= 0:
            continue
        del_ratio = dele / total
        churn_ratio = (add + dele) / total
        if del_ratio >= _REWRITE_DEL_RATIO:
            blocking.append(
                f"{path}: 疑似整篇覆盖重写（删 {dele}/{total} 行 = {del_ratio:.0%}，"
                f"违反 AGENTS.md S2 增量编辑）。若为经批准的合法重写，请走 change-proposal 并人工放行"
            )
        elif churn_ratio >= _LARGE_CHURN_RATIO:
            warning.append(
                f"{path}: 大规模改动（增 {add} 删 {dele} 共 {add+dele}/{total} 行 = {churn_ratio:.0%}），"
                f"疑似重排章节，违反 AGENTS.md S3/S6。请拆分为增量编辑"
            )
    return blocking, warning


def check_sid_uniqueness() -> tuple[list[str], list[str]]:
    """校验 [sid:...] 锚点全局唯一 + 格式（BLOCKING=重复，WARNING=格式）。"""
    blocking: list[str] = []
    warning: list[str] = []
    seen: dict[str, str] = {}
    for md in sorted(SPECS_DIR.rglob("*.md")):
        rel = md.relative_to(ROOT).as_posix()
        try:
            text = md.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for line in text.splitlines():
            m = _SID_TITLE_RE.match(line.strip())
            if not m:
                continue
            sid = m.group(1)
            if sid in seen:
                blocking.append(f"{rel}: sid `{sid}` 重复（首次出现在 {seen[sid]}）")
            else:
                seen[sid] = rel
    # 格式告警：非法字符（已由正则约束，仅提示是否为空/过短）
    for sid in seen:
        if len(sid.split("-")) < 2:
            warning.append(f"sid `{sid}` 格式过短（应为 <doc>-<slug>）")
    return blocking, warning


def _describe() -> None:
    print(
        "规约最小 diff 门禁规则（唯一权威 = 本文件常量；规约文档引用本输出，不手抄）\n"
        f"  整篇覆盖重写  : 相对 HEAD 单文件删除行 ≥ {_REWRITE_DEL_RATIO:.0%} 总行 → BLOCKING\n"
        f"  大规模改动    : 增+删 ≥ {_LARGE_CHURN_RATIO:.0%} 总行 → WARNING\n"
        "  sid 唯一性    : [sid:<doc>-<slug>] 全局唯一 → BLOCKING(重复) / WARNING(格式)\n"
        "  sid 引用      : 正文 [sid:...] 须指向已声明锚点 → BLOCKING(悬空, D8)\n"
        "  路径存在性    : markdown 链接本地路径须存在 → WARNING(失效, D5)\n"
        "  豁免          : 经批准的合法重写走 change-proposal（C12），不在本门禁豁免之列\n"
    )


def _collect_defined_sids() -> set[str]:
    """收集所有规约标题中声明的 [sid:...] 锚点（D8 权威集）。"""
    defined: set[str] = set()
    for md in sorted(SPECS_DIR.rglob("*.md")):
        try:
            text = md.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for line in text.splitlines():
            m = _SID_TITLE_RE.match(line.strip())
            if m:
                defined.add(m.group(1))
    return defined


def check_sid_references() -> tuple[list[str], list[str]]:
    """校验正文 [sid:...] 引用均指向已声明锚点（D8 跨文档引用；BLOCKING=悬空）。

    仅校验方括号形式 `[sid:<doc>-<slug>]`（D8 规范写法）；标题自身的 sid 已在
    权威集中，不会误报；只有指向「从未声明的 sid」的引用才升级为 BLOCKING。
    """
    blocking: list[str] = []
    warning: list[str] = []
    defined = _collect_defined_sids()
    for md in sorted(SPECS_DIR.rglob("*.md")):
        rel = md.relative_to(ROOT).as_posix()
        try:
            text = md.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for i, line in enumerate(text.splitlines(), 1):
            for m in re.finditer(r"\[sid:([a-z0-9]+-[a-z0-9\-]+)\]", line):
                if m.group(1) not in defined:
                    blocking.append(
                        f"{rel}:{i}: 悬空 sid 引用 `[sid:{m.group(1)}]`（未在任意规约标题声明，违反 D8）"
                    )
    return blocking, warning


_MD_LINK_RE = re.compile(r"\[[^\]]*\]\(([^)]+)\)")


def check_path_references() -> tuple[list[str], list[str]]:
    """校验正文 markdown 链接的本地路径真实存在（D5；WARNING=失效路径）。

    跳过：外部链接(http/https/mailto/tel)、纯 #anchor、outputs/ 运行时目录、
    templates/ 与 plans/ 下的示例/计划文档（含故意占位路径）。
    解析顺序：先相对链接所在目录，再相对仓库根（兼容 `docs/specs/X` 写法）。
    """
    blocking: list[str] = []
    warning: list[str] = []
    for md in sorted(SPECS_DIR.rglob("*.md")):
        rel = md.relative_to(ROOT).as_posix()
        if rel.startswith("docs/specs/templates/") or rel.startswith("docs/specs/plans/"):
            continue
        try:
            text = md.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for i, line in enumerate(text.splitlines(), 1):
            for m in _MD_LINK_RE.finditer(line):
                target = m.group(1).strip()
                if not target or target.startswith(("#", "http://", "https://", "mailto:", "tel:")):
                    continue
                if target.startswith("outputs/"):
                    continue
                path_part = target.split("#", 1)[0]
                if not path_part:
                    continue
                cand = (ROOT / md.parent / path_part).resolve()
                if not cand.exists():
                    cand2 = (ROOT / path_part).resolve()
                    if cand2.exists():
                        continue
                    warning.append(f"{rel}:{i}: 文档引用路径不存在（D5）：{target}")
    return blocking, warning


def main() -> int:
    ap = argparse.ArgumentParser(description="规约最小 diff 门禁")
    ap.add_argument("--sid", action="store_true", help="兼容别名：默认已含 sid 锚点校验")
    ap.add_argument("--describe", action="store_true", help="打印检查规则后退出")
    args = ap.parse_args()

    if args.describe:
        _describe()
        return 0

    blocking: list[str] = []
    warning: list[str] = []

    # 规模门禁（相对 HEAD diff）+ 锚点体系（D8）+ 路径存在性（D5）
    b, w = check_diff_scale()
    blocking += b
    warning += w
    b, w = check_sid_uniqueness()
    blocking += b
    warning += w
    b, w = check_sid_references()
    blocking += b
    warning += w
    b, w = check_path_references()
    blocking += b
    warning += w

    for msg in warning:
        print(f"  [WARN] {msg}")
    for msg in blocking:
        print(f"  [阻塞] {msg}")

    if blocking:
        print(f"\n[SPEC-LINT FAIL] {len(blocking)} BLOCKING / {len(warning)} WARNING")
        return 1
    if warning:
        print(f"\n[SPEC-LINT PASS] 0 BLOCKING / {len(warning)} WARNING（不阻断，请人工复核）")
    else:
        print("\n[SPEC-LINT PASS] 规约改动规模合规")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
