"""Stage 2 — 攻击配置

读取 Stage1 模态裁剪后的探针候选，按 Tier 优先级排序、组合 Buff 攻击链，
生成 garak run.spec 选择语法与 probe_selection 产物，供 Stage3 真正执行攻击。

不修改 garak 源码：仅产出配置（run_spec YAML + probe_selection JSON），
由 Stage3 注入 _config 驱动 harness。
"""

from __future__ import annotations

from pathlib import Path

import yaml

from .recon_garak import tier_rank  # 规则三：Tier 优先级

# 默认 Buff 攻击链（规则三）：编码绕过 + 小写归一化 叠加
# 注意：garak 0.15 buff 命名格式为 "buffs.<module>.<Class>"（点分隔，带 buffs 前缀）
DEFAULT_BUFF_SPEC = "buffs.encoding.Base64,buffs.lowercase.Lowercase"

# ---------------------------------------------------------------------------
# 扫描档位（效果 × 时间权衡）
# 规则：full = 全量最高危覆盖最慢；balanced = 默认，剔除 tier3 长尾 + 单 Buff；
#       quick = 仅 tier1 高危面 + 无 Buff，最快。
# 每档定义：保留的 tier 集合 + 使用的 Buff 链。
# ---------------------------------------------------------------------------
SCAN_PROFILES: dict[str, dict[str, Any]] = {
    "full": {
        "tiers": None,  # None = 全 tier
        "buff_spec": DEFAULT_BUFF_SPEC,
        "desc": "全量 93 探针 + 双 Buff，覆盖最全，耗时最长",
    },
    "balanced": {
        "tiers": {1, 2},  # 剔除 tier3 长尾
        "buff_spec": "buffs.encoding.Base64",  # 单 Buff（Base64 绕过）
        "desc": "tier1+tier2 + 单 Buff，覆盖高危面，约省 40% 时间",
    },
    "quick": {
        "tiers": {1},  # 仅最高危
        "buff_spec": "",  # 无 Buff
        "desc": "仅 tier1 + 无 Buff，最快，覆盖最高危攻击面",
    },
}


def resolve_scan_profile(
    profile: str | None,
    tier_filter: list[str] | None = None,
    buff_spec: str | None = None,
) -> dict[str, Any]:
    """解析扫描档位，返回 {tiers: set|None, buff_spec: str, profile: str}

    优先级：显式 tier_filter/buff_spec 参数 > profile 档位 > full 默认。
    即用户若在 config 显式指定 tier_filter/buff_spec，则覆盖 profile 默认值。

    :param profile: scan_profile 名称（full/balanced/quick），None 视为 full
    :param tier_filter: 显式 tier 过滤（覆盖 profile）
    :param buff_spec: 显式 Buff 链（覆盖 profile）
    :returns: 解析后的 {tiers, buff_spec, profile}
    """
    key = (profile or "full").lower()
    if key not in SCAN_PROFILES:
        key = "full"
    cfg = SCAN_PROFILES[key]

    tiers = cfg["tiers"]
    buff = cfg["buff_spec"]

    # 显式参数覆盖 profile
    if tier_filter:
        norm: set[int] = set()
        for t in tier_filter:
            s = str(t).lower().replace("tier", "").strip()
            try:
                norm.add(int(s))
            except ValueError:
                continue
        if norm:
            tiers = norm

    if buff_spec is not None:
        buff = buff_spec

    return {"tiers": tiers, "buff_spec": buff, "profile": key}


def load_filtered_probes(filtered_path: Path) -> list[dict]:
    """读取 Stage1 模态裁剪后的探针候选

    :param filtered_path: probe_candidates_filtered_{run_id}.json 路径
    :returns: kept_probes 列表（每项含 name/tier/...）
    :raises FileNotFoundError: 产物不存在
    """
    if not filtered_path.exists():
        raise FileNotFoundError(f"未找到模态裁剪产物: {filtered_path}")
    import json

    with open(filtered_path, encoding="utf-8") as f:
        data = json.load(f)
    # Stage1 产物可能直接是 list，或 {"kept_probes": [...]}
    if isinstance(data, list):
        return data
    return data.get("kept_probes", [])


def sort_by_tier(probes: list[dict]) -> list[dict]:
    """按 Tier 优先级排序（规则三：tier1 > tier2 > tier3 > 其他）

    :param probes: 探针元数据列表
    :returns: 同列表，按 Tier 升序排列（tier1 在前）
    """
    return sorted(
        probes,
        key=lambda p: tier_rank(p.get("tier")),
    )


def build_probe_spec(probes: list[dict]) -> list[str]:
    """生成 garak run.spec 的 probe 选择语法（规则一：兼容 garak CLI run.spec）

    garak 接受形如 "probes.<namespace>.<name>" 的 spec，支持通配。
    此处直接使用完整 plugin 名（probe name 即 plugin 路径）。

    :param probes: 排序后的探针列表
    :returns: probe spec 字符串列表，如 ["probes.knownbadsignatures.*", ...]
    """
    specs: list[str] = []
    seen: set[str] = set()
    for p in probes:
        name: str = p["name"]
        # name 形如 "probes.knownbadsignatures.IndirectInjection"
        # 聚合到 namespace 通配（probes.<ns>.*）以减少 spec 数量并保证完整覆盖
        parts = name.split(".")
        ns_spec = f"probes.{parts[1]}.*" if len(parts) >= 3 else name
        if ns_spec not in seen:
            seen.add(ns_spec)
            specs.append(ns_spec)
    return specs


def build_selection(
    filtered_path: Path,
    run_id: str,
    artifacts_dir: str,
    tier_filter: list[str] | None = None,
    buff_spec: str | None = None,
    scan_profile: str | None = None,
) -> dict:
    """构建攻击选择产物

    :param filtered_path: Stage1 模态裁剪产物路径
    :param run_id: 本次运行标识
    :param artifacts_dir: 产物根目录
    :param tier_filter: 显式 tier 过滤（覆盖 profile）
    :param buff_spec: 显式 Buff 攻击链 spec（覆盖 profile）
    :param scan_profile: 扫描档位 full/balanced/quick（默认 full）
    :returns: 选择结果 dict（同时写出 JSON + run_spec YAML）
    """
    resolved = resolve_scan_profile(scan_profile, tier_filter, buff_spec)
    effective_tiers = resolved["tiers"]
    effective_buff = resolved["buff_spec"]

    probes = load_filtered_probes(filtered_path)
    if effective_tiers:
        probes = [
            p for p in probes if tier_rank(p.get("tier")) in effective_tiers
        ]
    probes = sort_by_tier(probes)

    probe_spec = build_probe_spec(probes)

    selection = {
        "run_id": run_id,
        "scan_profile": resolved["profile"],
        "total_selected": len(probes),
        "tier_breakdown": _tier_breakdown(probes),
        "probe_names": [p["name"] for p in probes],
        "probe_spec": probe_spec,
        "buff_spec": effective_buff,
    }

    out_dir = Path(artifacts_dir) / "02_config"
    out_dir.mkdir(parents=True, exist_ok=True)

    sel_path = out_dir / f"probe_selection_{run_id}.json"
    spec_path = out_dir / f"run_spec_{run_id}.yaml"

    import json

    with open(sel_path, "w", encoding="utf-8") as f:
        json.dump(selection, f, ensure_ascii=False, indent=2)

    spec_doc = {
        "plugins": {
            "probe_spec": probe_spec,
            "buff_spec": [b.strip() for b in effective_buff.split(",")] if effective_buff else [],
        }
    }
    with open(spec_path, "w", encoding="utf-8") as f:
        yaml.safe_dump(spec_doc, f, allow_unicode=True, sort_keys=False)

    return {
        "selection": selection,
        "sel_path": str(sel_path),
        "spec_path": str(spec_path),
    }


def _tier_breakdown(probes: list[dict]) -> dict[str, int]:
    """统计各 Tier 包含探针数"""
    out: dict[str, int] = {}
    for p in probes:
        t = p.get("tier", "other")
        out[t] = out.get(t, 0) + 1
    return dict(sorted(out.items(), key=lambda kv: tier_rank(kv[0])))
