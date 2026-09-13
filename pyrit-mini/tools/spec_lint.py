"""规约最小 diff 门禁 (Spec Minimal-Diff Linter)。

把「编辑 specs 的硬纪律」从"靠自觉"变成"机器可校验"，落地 `AGENTS.md` §2 的
S2（禁整文件覆盖）/ S3（禁重排章节号）/ S6（规模自检）/ S7（锚点不可破坏），以及
稳定锚点 sid 的完整性校验。规则本体见宪法 C4 / `docs/specs/README.md` §5 文档纪律。

检测项：
  1. 整篇覆盖重写（相对 HEAD，单文件删除行 ≥ 70% 总行且非新增）→ BLOCKING
  2. 大规模改动（增+删 ≥ 50% 总行）→ WARNING（提示拆分为增量编辑）
  3. sid 锚点唯一性（全局）→ BLOCKING（重复）/ WARNING（格式）
  4. sid 引用存在性（正文 [sid:...] 须指向已声明锚点）→ BLOCKING（悬空，D8）
  5. 文档路径存在性（markdown 链接本地路径须真实存在）→ WARNING（失效，D5）
  6. sid 语法完整性（畸形/嵌套/粘连/未闭合）→ BLOCKING（跨模型协作的锚点地基）
  7. sid 文档号登记（docnum 须存在于文档号登记簿）→ WARNING
  8. 跨文档 sid 一致性（同行点名文档与 sid 文档号须相容）→ WARNING
  9. 章节 sid 覆盖率（活动规约 `##` 标题须带 sid）→ WARNING
 10. AI 入口唯一性（AGENTS.md 存在且被索引；冷启动顺序不得另立门户）→ BLOCKING/WARNING

用法：
  python -m tools.spec_lint              # 全量校验（规模 + 锚点体系 + 入口唯一性）
  python -m tools.spec_lint --sid        # 兼容别名：默认已含全部锚点校验
  python -m tools.spec_lint --describe   # 打印检查规则说明（供规约引用）

退出码：0 = 通过（含仅 WARNING）；1 = 存在 BLOCKING。
"""
from __future__ import annotations

import argparse
import re
import string
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

# --- 锚点语法与语义校验（跨模型协作地基：锚点必须稳定、可解析、可定位） ----------
# 畸形 sid 的真实形态（均由"批量替换 sid"的历史事故产生）：
#   [sid:30-c[sid:30-ch4]]  嵌套   ｜  [sid[sid:30-ch8]-ch1] 缺冒号
#   20-REQUIREM[sid:55-ref]S.md 粘连 ｜ [sid:8[sid:80-ch6]h4] 截断
# 旧版只校验"合法 token"，畸形片段被静默跳过 —— 这正是锚点失效却门禁全绿的根因。
_SID_OPEN_RE = re.compile(r"\[sid(?!:)")
_SID_START_RE = re.compile(r"\[sid:")
_SID_TOKEN_RE = re.compile(r"\[sid:([a-z0-9]+(?:-[a-z0-9]+)*)\]")
# 粘连判定：sid 左侧紧邻 ASCII 字母/数字/下划线/连字符/点 → 说明替换时吃掉了正文
# （`/` 与 `|`、`（` 允许：`[sid:a-ch1]/[sid:b-ch2]` 是合法并列引用）
_GLUE_BEFORE = set(string.ascii_letters + string.digits + "_-.")
# 文档号登记簿：来自规约文件名数字前缀 + 无数字前缀的入口文档
_DOCNUM_RE = re.compile(r"(?<![0-9A-Za-z._\-])(00|10|20|30|40|50|55|60|80|90)(?![0-9])")
_NAMED_DOCNUMS = ("readme", "agents")
# 中文文档别名 → 文档号。**集合由受控实验测定**（2026-09-13）：在注入 6 个已知错指缺陷的
# 污染语料上，{宪法,跨模型}=4/6、{宪法,跨模型,蓝图}=6/6、扩到 9 个（含"需求/组件"）=5/6
# （"需求/组件"作普通名词出现在同一行时，会把真正的错指判成相容而漏报）；三者在当前真实
# 语料上的误报数**均为 0**。故取 6/6 且 0 误报的 {宪法,跨模型,蓝图}。
# 变更本集合 = 变更召回/误报权衡，**必须重跑同一实验再改**，禁止凭直觉增删。
_DOCNUM_ALIASES = {"宪法": "00", "跨模型": "60", "蓝图": "10"}
# 说明性占位行（如 D8 细则里的 `[sid:<docnum>-<slug>]` 示例）不参与语法/一致性判定
_SID_SPEC_LINE_MARKERS = ("<docnum>", "<slug>", "<doc>-")
# 冻结文档：plans/（历史提案）与 templates/（模板）不参与语法/覆盖类判定，
# 其 sid 引用有效性仍受 check_sid_references 守护（冻结 ≠ 可以留坏锚点）。
_FROZEN_PREFIXES = ("docs/specs/templates/", "docs/specs/plans/")


def _iter_content_lines(text: str):
    """产出 (行号, 行内容)；跳过 ``` 围栏内的代码块（示例/模板不构成规约锚点）。"""
    in_fence = False
    for i, line in enumerate(text.splitlines(), 1):
        if line.lstrip().startswith("```"):
            in_fence = not in_fence
            continue
        if not in_fence:
            yield i, line


def _iter_spec_files() -> list[Path]:
    """规约扫描范围：`docs/specs/**.md` + 仓库根 `AGENTS.md`（AI 统一入口）。"""
    files = sorted(SPECS_DIR.rglob("*.md"))
    agents = ROOT / "AGENTS.md"
    if agents.exists():
        files.append(agents)
    return files


def _own_docnum(rel: str) -> str:
    """返回文件自身的文档号（自引用恒合法，用于消除跨文档一致性检查的误报）。"""
    name = rel.rsplit("/", 1)[-1].lower()
    if name == "readme.md":
        return "readme"
    if name == "agents.md":
        return "agents"
    head = name.split("-", 1)[0]
    return head if head.isdigit() else ""


def _docnum_registry() -> set[str]:
    """文档号登记簿 = 规约文件名数字前缀 ∪ {readme, agents}（D4：以实际文件为准）。"""
    nums: set[str] = set(_NAMED_DOCNUMS)
    for md in SPECS_DIR.glob("*.md"):
        head = md.stem.split("-", 1)[0]
        if head.isdigit():
            nums.add(head)
    return nums


def _git_repo_root() -> Path:
    """返回 git 仓库根（兼容 pyrit-mini 作为父仓库子目录的拓扑，BL-070 同源）。"""
    try:
        out = (
            subprocess.run(
                ["git", "rev-parse", "--show-toplevel"],
                cwd=str(ROOT),
                capture_output=True,
                text=True,
                encoding="utf-8",
                check=False,
            )
            .stdout.strip()
        )
        return Path(out) if out else ROOT
    except Exception:
        return ROOT


def _git_diff_numstat() -> list[tuple[int, int, str]]:
    """返回 (add, del, path) 列表，path 为相对 ROOT 的 docs/specs 下 md 文件。

    BL-070：git 输出必须显式 UTF-8 解码（Windows 非 ASCII 路径按 GBK 解码会乱码）。
    仓库拓扑兼容：pyrit-mini 可能是父仓库（如 osai）的子目录，git pathspec 相对
    cwd 解析会失效（曾导致整篇重写 BLOCKING 静默误判为通过）；故改用「仓库根 +
    全量 diff + 按 SPECS_DIR 前缀过滤」，path 归一到相对 ROOT 以便 _line_count 使用。
    """
    repo_root = _git_repo_root()
    try:
        proc = subprocess.run(
            ["git", "diff", "--numstat", "HEAD"],
            cwd=str(repo_root),
            capture_output=True,
            text=True,
            encoding="utf-8",
            check=False,
        )
    except FileNotFoundError:
        return []
    specs_root = SPECS_DIR.resolve()
    rows: list[tuple[int, int, str]] = []
    for line in proc.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) < 3:
            continue
        add_s, del_s, path = parts[0], parts[1], parts[2]
        if not add_s.isdigit() and not del_s.isdigit():
            continue  # 二进制 / rename
        abs_path = (repo_root / path).resolve()
        if not str(abs_path).startswith(str(specs_root)):
            continue
        rel_path = abs_path.relative_to(ROOT).as_posix()
        add = int(add_s) if add_s.isdigit() else 0
        dele = int(del_s) if del_s.isdigit() else 0
        if rel_path.endswith(".md"):
            rows.append((add, dele, rel_path))
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
    for md in _iter_spec_files():
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
        "  sid 语法      : 禁嵌套/粘连/未闭合/大写 → BLOCKING(畸形锚点比无锚点更危险)\n"
        "  sid 文档号    : docnum 须在登记簿(文件名前缀+readme/agents) → WARNING\n"
        "  sid 跨文档    : 同行点名文档与 sid docnum 须相容 → WARNING(错指锚点)\n"
        "  章节 sid 覆盖 : 活动规约 `##` 标题须带 sid 尾标 → WARNING\n"
        "  AI 入口唯一性 : AGENTS.md 存在且被 README 索引 → BLOCKING；冷启动顺序"
        "另立门户 → WARNING\n"
        "  路径存在性    : markdown 链接本地路径须存在 → WARNING(失效, D5)\n"
        "  扫描范围      : docs/specs/**.md + 仓库根 AGENTS.md\n"
        "  豁免          : 经批准的合法重写走 change-proposal（C12），不在本门禁豁免之列\n"
    )


def _collect_defined_sids() -> set[str]:
    """收集所有规约标题中声明的 [sid:...] 锚点（D8 权威集）。"""
    defined: set[str] = set()
    for md in _iter_spec_files():
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
    """校验正文 [sid:...] 引用均指向已声明锚点（D8 跨文档引用；BLOCKING=悬空）。"""
    blocking: list[str] = []
    warning: list[str] = []
    defined = _collect_defined_sids()
    for md in _iter_spec_files():
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


def check_sid_syntax() -> tuple[list[str], list[str]]:
    """校验 sid 字面完整性（BLOCKING）：畸形锚点比"没有锚点"更危险——它看起来可解析。"""
    blocking: list[str] = []
    warning: list[str] = []
    for md in _iter_spec_files():
        rel = md.relative_to(ROOT).as_posix()
        if rel.startswith(_FROZEN_PREFIXES):
            continue
        for i, line in _iter_content_lines(md.read_text(encoding="utf-8", errors="replace")):
            if any(marker in line for marker in _SID_SPEC_LINE_MARKERS):
                continue
            for m in _SID_OPEN_RE.finditer(line):
                if not line.startswith("[sid:", m.start()):
                    blocking.append(
                        f"{rel}:{i}: 畸形 sid（`[sid` 后缺 `:`）：{line.strip()[:80]}（D8）"
                    )
            for m in _SID_START_RE.finditer(line):
                start = m.start()
                end = line.find("]", start)
                seg = line[start : end + 1] if end != -1 else line[start:]
                inner = seg[5:-1] if end != -1 else seg[5:]
                if end == -1:
                    blocking.append(f"{rel}:{i}: 未闭合 sid `{seg[:40]}`（D8）")
                    continue
                if "[" in inner or re.search(r"[A-Z\s]", inner):
                    blocking.append(
                        f"{rel}:{i}: 畸形/嵌套 sid `{seg[:40]}`（禁止嵌套与大写，D8）"
                    )
                if start > 0 and line[start - 1] in _GLUE_BEFORE:
                    blocking.append(
                        f"{rel}:{i}: sid 与正文粘连 `...{line[max(0, start-12):start]}`"
                        f"（替换吃掉了正文，D8）"
                    )
    return blocking, warning


def check_sid_docnum() -> tuple[list[str], list[str]]:
    """sid 的文档号必须存在于登记簿（WARNING）：防止 `[sid:99-ch1]` 指向不存在的文档。"""
    blocking: list[str] = []
    warning: list[str] = []
    registry = _docnum_registry()
    for md in _iter_spec_files():
        rel = md.relative_to(ROOT).as_posix()
        if rel.startswith(_FROZEN_PREFIXES):
            continue
        for i, line in _iter_content_lines(md.read_text(encoding="utf-8", errors="replace")):
            if any(marker in line for marker in _SID_SPEC_LINE_MARKERS):
                continue
            for m in _SID_TOKEN_RE.finditer(line):
                docnum = m.group(1).split("-", 1)[0]
                if docnum not in registry:
                    warning.append(
                        f"{rel}:{i}: sid `[sid:{m.group(1)}]` 的文档号 `{docnum}` 未登记"
                        f"（登记簿来自文件名前缀 + readme/agents，D8）"
                    )
    return blocking, warning


def check_sid_crossdoc_coherence() -> tuple[list[str], list[str]]:
    """同行点名了文档 A 却引用文档 B 的 sid → WARNING（错指锚点，跨模型最难发现的一类）。"""
    blocking: list[str] = []
    warning: list[str] = []
    for md in _iter_spec_files():
        rel = md.relative_to(ROOT).as_posix()
        if rel.startswith(_FROZEN_PREFIXES):
            continue
        for i, line in _iter_content_lines(md.read_text(encoding="utf-8", errors="replace")):
            if any(marker in line for marker in _SID_SPEC_LINE_MARKERS):
                continue
            # 标题行自带章节号（如 "## 10. 与其他规约的关系 [sid:60-ch10]"）不参与判定
            if re.match(r"^#{1,6}\s", line):
                continue
            sids = list(_SID_TOKEN_RE.finditer(line))
            if not sids:
                continue
            own = _own_docnum(rel)
            stripped = _SID_TOKEN_RE.sub(" ", line)
            mentioned = set(_DOCNUM_RE.findall(stripped))
            for alias, num in _DOCNUM_ALIASES.items():
                if alias in stripped:
                    mentioned.add(num)
            lower = stripped.lower()
            for name in _NAMED_DOCNUMS:
                if name in lower:
                    mentioned.add(name)
            if not mentioned:
                continue  # 该行未点名任何文档 → 不判定
            for m in sids:
                docnum = m.group(1).split("-", 1)[0]
                if docnum == own:
                    continue  # 自引用恒合法（本文件引用本文件章节）
                if docnum not in mentioned:
                    warning.append(
                        f"{rel}:{i}: sid `[sid:{m.group(1)}]` 与同行点名的文档 "
                        f"{sorted(mentioned)} 不一致（疑似错指锚点，D8）"
                    )
    return blocking, warning


def check_heading_sid_coverage() -> tuple[list[str], list[str]]:
    """活动规约的一级标题（`##`）必须携带 sid（WARNING）：无锚点 = 不可被跨文档引用。"""
    blocking: list[str] = []
    warning: list[str] = []
    for md in sorted(SPECS_DIR.rglob("*.md")):
        rel = md.relative_to(ROOT).as_posix()
        if rel.startswith(_FROZEN_PREFIXES):
            continue
        for i, line in _iter_content_lines(md.read_text(encoding="utf-8", errors="replace")):
            if re.match(r"^##\s+", line) and "[sid:" not in line:
                warning.append(f"{rel}:{i}: 一级标题缺 sid 尾标（D8）：{line.strip()[:60]}")
    return blocking, warning


def check_ai_entry_unified() -> tuple[list[str], list[str]]:
    """AI 入口唯一性：AGENTS.md 必须存在且被 README 索引；冷启动顺序不得另立门户。"""
    blocking: list[str] = []
    warning: list[str] = []
    agents = ROOT / "AGENTS.md"
    if not agents.exists():
        blocking.append("AGENTS.md: AI 编码代理统一入口缺失（跨 IDE/跨模型协作前提）")
        return blocking, warning
    readme = SPECS_DIR / "README.md"
    readme_text = readme.read_text(encoding="utf-8", errors="replace") if readme.exists() else ""
    if "AGENTS.md" not in readme_text:
        blocking.append(
            "docs/specs/README.md: 未索引 AGENTS.md（统一入口必须在金字塔入口可达，D1/C3）"
        )
    for md in _iter_spec_files():
        rel = md.relative_to(ROOT).as_posix()
        if rel.endswith("AGENTS.md"):
            continue
        lines = md.read_text(encoding="utf-8", errors="replace").splitlines()
        for i, line in enumerate(lines, 1):
            if "冷启动阅读顺序" not in line or "AGENTS.md" in line:
                continue
            # 允许"标题声明 + 紧随其后的正文指向"（避免要求同一行塞满）
            context = "\n".join(lines[i : i + 12])
            if "AGENTS.md" not in context:
                warning.append(
                    f"{rel}:{i}: 声明冷启动顺序但未指向 AGENTS.md（入口唯一性，D1）：{line.strip()[:60]}"
                )
    return blocking, warning


_MD_LINK_RE = re.compile(r"\[[^\]]*\]\(([^)]+)\)")


def check_path_references() -> tuple[list[str], list[str]]:
    """校验正文 markdown 链接的本地路径真实存在（D5；WARNING=失效路径）。"""
    blocking: list[str] = []
    warning: list[str] = []
    for md in sorted(SPECS_DIR.rglob("*.md")):
        rel = md.relative_to(ROOT).as_posix()
        if rel.startswith(_FROZEN_PREFIXES):
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

    b, w = check_diff_scale()
    blocking += b
    warning += w
    b, w = check_sid_uniqueness()
    blocking += b
    warning += w
    b, w = check_sid_references()
    blocking += b
    warning += w
    b, w = check_sid_syntax()
    blocking += b
    warning += w
    b, w = check_sid_docnum()
    blocking += b
    warning += w
    b, w = check_sid_crossdoc_coherence()
    blocking += b
    warning += w
    b, w = check_heading_sid_coverage()
    blocking += b
    warning += w
    b, w = check_ai_entry_unified()
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
