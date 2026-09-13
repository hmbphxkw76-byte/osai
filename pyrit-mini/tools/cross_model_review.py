"""跨模型规约审查的机器校验（C14 / R-CROSS-1~5 落地）。

把 `60-CROSS-MODEL-VERIFICATION.md` §9.2 承诺的 5 个检查器从「纸面协议」变为可执行：

  1. check_cross_model_review   —— 规约变更须先过跨模型审查（无记录 → WARNING 降级，R-CROSS-1）
  2. check_review_schema        —— 审查报告 JSON Schema 合规（60 §5.1）
  3. check_adjudication_record  —— 仲裁记录完整（R-CROSS-3 永久保留）
  4. check_review_model_pool    —— 审查模型池健康（≥ 2 可用，R-CROSS-4）
  5. check_review_freshness     —— 审查时效（< 90 天，R-CROSS-5）

设计原则（不阻断现行人工编排模式）：
  - 仅当 `docs/specs` 在工作区有变更（staged / unstaged / untracked）时介入；否则零产出，
    故纯代码提交完全无感。
  - 当前处于人工编排模式（`outputs/cross_model_review/` 审查记录通常由人工落地，BL-042），
    无审查记录时按 R-CROSS-1 降级为 WARNING（不阻断），仅标记 `needs-cross-model-pending`。
  - 审查记录「存在但」结构/时效不合规时，才升级为 BLOCKING——即机器校验只在
    「已经有审查流程却做错」时卡死，不卡「还没接自动化」的存量人工模式。
  - 每个检查器独立 try/except 友好（guard.check_all 已统一吞异常为 debug 日志）。

注册：被 `tools/guard.py` 在模块级调用 `register(ArchitectureGuard)`，从而自动纳入
`python -m tools.guard` 与 `python -m tools.gate` 的 commit 阶段。
"""
from __future__ import annotations

import json
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SPECS_DIR = ROOT / "docs" / "specs"
REVIEW_ROOT = ROOT / "outputs" / "cross_model_review"

# 审查时效上限（R-CROSS-5）
_FRESHNESS_DAYS = 90


def _get_violation_classes():
    from tools.guard import Severity, Violation

    return Severity, Violation


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


def _specs_changed() -> bool:
    """工作区是否含 docs/specs 变更（staged / unstaged / untracked）。

    仓库拓扑兼容：pyrit-mini 可能是父仓库（如 osai）的子目录，git pathspec 相对
    cwd 解析会失效（曾导致跨模型检查器在 specs 改动时静默跳过、永不告警）；故改用
    「仓库根 + 全量 status + 按 SPECS_DIR 前缀过滤」，使 R-CROSS-1 在 specs 变更时
    必然触发 WARNING 降级（而非静默无感）。
    """
    repo_root = _git_repo_root()
    try:
        proc = subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=str(repo_root),
            capture_output=True,
            text=True,
            encoding="utf-8",
            check=False,
        )
    except FileNotFoundError:
        return False
    specs_root = SPECS_DIR.resolve()
    for line in proc.stdout.splitlines():
        parts = line.split()
        if not parts:
            continue
        abs_path = (repo_root / parts[-1]).resolve()
        if str(abs_path).startswith(str(specs_root)):
            return True
    return False


def _latest_review_dir() -> Path | None:
    """返回 outputs/cross_model_review/ 下字典序最大的审查记录目录（最新一次）。"""
    if not REVIEW_ROOT.exists():
        return None
    sub = [p for p in REVIEW_ROOT.iterdir() if p.is_dir()]
    if not sub:
        return None
    return max(sub, key=lambda p: p.name)


def check_cross_model_review(self) -> None:
    """R-CROSS-1：规约变更须先过跨模型审查；无记录 → WARNING 降级（人工编排模式）。"""
    Severity, Violation = _get_violation_classes()
    if not _specs_changed():
        return
    if not REVIEW_ROOT.exists():
        self.violations.append(
            Violation(
                rule="R-CROSS-1",
                severity=Severity.WARNING,
                file="docs/specs",
                line=0,
                description=(
                    "规约变更未检出跨模型审查记录（outputs/cross_model_review/ 缺失）；"
                    "按 R-CROSS-1 降级为人工审查模式，标记 needs-cross-model-pending（BL-035）"
                ),
                fix_hint="执行跨模型审查并写入 outputs/cross_model_review/{YYYYMMDD}-{change_id}/；或人工登记 backlog 待审",
            )
        )
        return
    latest = _latest_review_dir()
    if latest is None:
        self.violations.append(
            Violation(
                rule="R-CROSS-1",
                severity=Severity.WARNING,
                file="docs/specs",
                line=0,
                description="规约变更但未关联任何跨模型审查记录目录；按 R-CROSS-1 降级为人工审查模式",
                fix_hint="将本次变更关联至 outputs/cross_model_review/{YYYYMMDD}-{change_id}/",
            )
        )


def check_review_schema(self) -> None:
    """R-CROSS-2：审查报告 JSON 必须可解析且含 60 §5.1 必需字段（model/findings）。"""
    Severity, Violation = _get_violation_classes()
    if not _specs_changed():
        return
    latest = _latest_review_dir()
    if latest is None:
        return
    raw = latest / "raw"
    if not raw.exists():
        self.violations.append(
            Violation(
                rule="R-CROSS-2",
                severity=Severity.WARNING,
                file=str(raw.relative_to(ROOT)),
                line=0,
                description="审查记录缺 raw/ 原始报告目录（60 §5.1 Schema）",
                fix_hint="写入各模型 raw/{model}.json，符合 60 §5.1 Schema",
            )
        )
        return
    for jf in sorted(raw.glob("*.json")):
        try:
            data = json.loads(jf.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            self.violations.append(
                Violation(
                    rule="R-CROSS-2",
                    severity=Severity.BLOCKING,
                    file=str(jf.relative_to(ROOT)),
                    line=0,
                    description=f"审查报告 JSON 解析失败：{e}",
                    fix_hint="修正 JSON 格式，符合 60 §5.1 Schema",
                )
            )
            continue
        if "model" not in data or "findings" not in data or not isinstance(data.get("findings"), list):
            self.violations.append(
                Violation(
                    rule="R-CROSS-2",
                    severity=Severity.BLOCKING,
                    file=str(jf.relative_to(ROOT)),
                    line=0,
                    description="审查报告缺必需字段 model/findings（60 §5.1）",
                    fix_hint="补全 model + findings[]，符合 60 §5.1 Schema",
                )
            )


def check_adjudication_record(self) -> None:
    """R-CROSS-3：审查记录须含 adjudication/decision.json（永久保留）。"""
    Severity, Violation = _get_violation_classes()
    if not _specs_changed():
        return
    latest = _latest_review_dir()
    if latest is None:
        return
    adj = latest / "adjudication" / "decision.json"
    if not adj.exists():
        self.violations.append(
            Violation(
                rule="R-CROSS-3",
                severity=Severity.WARNING,
                file=str(latest.relative_to(ROOT)),
                line=0,
                description="审查记录缺 adjudication/decision.json（R-CROSS-3 永久保留）；当前人工编排模式，不阻断",
                fix_hint="人工终审后写入 adjudication/decision.json + summary.md",
            )
        )


def check_review_model_pool(self) -> None:
    """R-CROSS-4：审查模型池须 ≥ 2 可用；否则降级人工审查（INFO）。"""
    Severity, Violation = _get_violation_classes()
    if not _specs_changed():
        return
    pool_doc = SPECS_DIR / "60-CROSS-MODEL-VERIFICATION.md"
    if not pool_doc.exists():
        return
    text = pool_doc.read_text(encoding="utf-8", errors="replace")
    available = len(re.findall(r"^\|\s*\S+\s*\|\s*\S+\s*\|\s*(主审查|副审查|第三审查|仲裁)\s*\|", text, re.M))
    if available < 2:
        self.violations.append(
            Violation(
                rule="R-CROSS-4",
                severity=Severity.INFO,
                file="docs/specs/60-CROSS-MODEL-VERIFICATION.md",
                line=0,
                description=f"审查模型池可用数 {available} < 2，按 R-CROSS-1 降级人工审查",
                fix_hint="恢复 ≥ 2 个可用审查模型",
            )
        )


def check_review_freshness(self) -> None:
    """R-CROSS-5：审查记录须 < 90 天；过期 → WARNING。"""
    Severity, Violation = _get_violation_classes()
    if not _specs_changed():
        return
    latest = _latest_review_dir()
    if latest is None:
        return
    m = re.match(r"(\d{8})", latest.name)
    if not m:
        return
    try:
        review_date = datetime.strptime(m.group(1), "%Y%m%d").replace(tzinfo=timezone.utc)
    except ValueError:
        return
    age_days = (datetime.now(timezone.utc) - review_date).days
    if age_days > _FRESHNESS_DAYS:
        self.violations.append(
            Violation(
                rule="R-CROSS-5",
                severity=Severity.WARNING,
                file=str(latest.relative_to(ROOT)),
                line=0,
                description=f"审查记录已 {age_days} 天（> {_FRESHNESS_DAYS}），时效过期（R-CROSS-5）",
                fix_hint="重新执行跨模型审查",
            )
        )


def register(guard_cls) -> None:
    """注册 5 个跨模型检查器到 ArchitectureGuard（被 guard.py 在模块级调用）。"""
    guard_cls.check_cross_model_review = check_cross_model_review
    guard_cls.check_review_schema = check_review_schema
    guard_cls.check_adjudication_record = check_adjudication_record
    guard_cls.check_review_model_pool = check_review_model_pool
    guard_cls.check_review_freshness = check_review_freshness
