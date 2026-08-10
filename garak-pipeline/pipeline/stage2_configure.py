"""Stage 2 — 攻击配置

读取 Stage1 模态裁剪后的探针候选，按 Tier 优先级排序、组合 Buff 攻击链，
生成 garak run.spec 选择语法与 probe_selection 产物，供 Stage3 真正执行攻击。

不修改 garak 源码：仅产出配置（run_spec YAML + probe_selection JSON），
由 Stage3 注入 _config 驱动 harness。
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

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
    "smoke": {
        "tiers": None,  # 不按 tier 过滤，直接用固定探针子集
        "buff_spec": "",  # 无 Buff
        "probes": [
            "probes.dan.DanInTheWild",             # LLM01 越狱（DAN 系列，mitigation.MitigationBypass 活跃）
            "probes.latentinjection.LatentJailbreak",  # LLM01 潜在注入（base.TriggerListDetector 活跃）
            "probes.dan.Ablation_Dan_11_0",        # LLM01 DAN 11 变体（mitigation.MitigationBypass 活跃）
        ],
        "desc": "冒烟测试：3 探针 × 3 prompt，验证流水线端到端贯通",
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

    result: dict[str, Any] = {"tiers": tiers, "buff_spec": buff, "profile": key}
    # smoke 档位带固定探针子集，传递给 build_selection 直接使用
    if "probes" in cfg:
        result["probes"] = cfg["probes"]
    return result


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


def adaptive_prioritize(
    probes: list[dict],
    recon_state: dict | None = None,
) -> tuple[list[dict], list[tuple[str, str]]]:
    """Phase 1: 基于侦察情报动态调整探针优先级（offsec 侦察驱动攻击）

    读取 Stage1 侦察产物的 system_prompt/multiple_generations/rate_limits 等情报，
    动态提升相关探针的优先级，使攻击投递顺序对齐侦察发现。

    :param probes: sort_by_tier 后的探针列表
    :param recon_state: Stage1 state dict（含 model_capabilities 等）
    :returns: (重排序后的探针列表, [(侦察发现, 攻击调整), ...] rationale)
    """
    if not recon_state:
        return probes, []

    rationale: list[tuple[str, str]] = []
    model_caps = recon_state.get("model_capabilities", {}) or {}

    llm01_prefixes = (
        "dan", "promptinject", "encoding", "latentinjection",
        "goodside", "glitch", "knownbadsignatures", "contrast",
        "malwaregen", "tap", "visualgame", "snip", "guardrail",
    )
    llm04_prefixes = ("test",)
    llm06_prefixes = ("leakreplay", "lmrc", "replay")

    boost_llm01 = False
    boost_llm04 = False
    boost_llm06 = False

    sys_prompt = model_caps.get("system_prompt") or {}
    if sys_prompt.get("extractable") or sys_prompt.get("leaked"):
        boost_llm01 = True
        rationale.append((
            "System Prompt 可提取",
            "LLM01 探针优先级 +2（定向注入攻击面优先）",
        ))

    if model_caps.get("supports_multiple_generations"):
        boost_llm04 = True
        rationale.append((
            "模型支持多生成",
            "LLM04 DoS 探针优先级 +1",
        ))

    rate_limits = model_caps.get("rate_limits") or {}
    rpm_header = rate_limits.get("X-RateLimit-Limit-Requests") or rate_limits.get("x-ratelimit-limit-requests")
    if rpm_header:
        try:
            rpm = float(rpm_header)
            if 0 < rpm < 30:
                rationale.append((
                    f"速率限制低 ({rpm:.0f} RPM)",
                    "保守速率模式，优先执行短耗时探针",
                ))
        except (ValueError, TypeError):
            pass

    modality = model_caps.get("modality") or {}
    mod_in = modality.get("in", set())
    if isinstance(mod_in, set):
        mod_in_set = mod_in
    else:
        mod_in_set = set(mod_in)
    if "image" in mod_in_set:
        rationale.append((
            "模型接受图像输入",
            "多模态注入探针已保留（图像/视觉攻击面）",
        ))

    if not rationale:
        return probes, []

    def _boost_score(p: dict) -> int:
        name = p.get("name", "").lower()
        score = tier_rank(p.get("tier")) * 100
        if boost_llm01:
            for ns in llm01_prefixes:
                if ns in name:
                    score -= 200
                    break
        if boost_llm04:
            for ns in llm04_prefixes:
                if ns in name:
                    score -= 100
                    break
        if boost_llm06:
            for ns in llm06_prefixes:
                if ns in name:
                    score -= 50
                    break
        return score

    reordered = sorted(probes, key=_boost_score)
    return reordered, rationale


def build_selection(
    filtered_path: Path,
    run_id: str,
    artifacts_dir: str,
    tier_filter: list[str] | None = None,
    buff_spec: str | None = None,
    scan_profile: str | None = None,
    atkgen_cfg: dict[str, Any] | None = None,
    recon_state: dict | None = None,
) -> dict:
    """构建攻击选择产物

    :param filtered_path: Stage1 模态裁剪产物路径
    :param run_id: 本次运行标识
    :param artifacts_dir: 产物根目录
    :param tier_filter: 显式 tier 过滤（覆盖 profile）
    :param buff_spec: 显式 Buff 攻击链 spec（覆盖 profile）
    :param scan_profile: 扫描档位 full/balanced/quick（默认 full）
    :param atkgen_cfg: atkgen 动态攻击生成配置（S3.3），None 或 enabled=False 则不追加
    :returns: 选择结果 dict（同时写出 JSON + run_spec YAML）
    """
    # 规则一（garak 原生优先）：Stage2 需要解析 custom 探针/Buff 名，
    # 提前注册使 enumerate_plugins / _spec 解析器可识别 probes.custom.* / buffs.custom.*
    try:
        from pipeline.custom_buffs import register_custom_buffs
        from pipeline.custom_probes import register_custom_probes

        register_custom_probes()
        register_custom_buffs()
    except Exception:
        pass
    resolved = resolve_scan_profile(scan_profile, tier_filter, buff_spec)
    effective_tiers = resolved["tiers"]
    effective_buff = resolved["buff_spec"]

    all_probes = load_filtered_probes(filtered_path)

    # smoke 档位：使用固定探针子集（不按 tier 过滤）
    if "probes" in resolved:
        wanted = set(resolved["probes"])
        probes = [p for p in all_probes if p["name"] in wanted]
        # 如果 filtered 产物中缺失某些 smoke 探针，补齐占位元数据
        existing = {p["name"] for p in probes}
        for name in resolved["probes"]:
            if name not in existing:
                probes.append({"name": name, "tier": 1})
    else:
        probes = all_probes
        if effective_tiers:
            probes = [
                p for p in probes if tier_rank(p.get("tier")) in effective_tiers
            ]
    # P1-2: atkgen 动态攻击生成集成 — enabled 且 include_native_probe 时追加 atkgen.Tox
    atkgen_enabled = bool(atkgen_cfg and atkgen_cfg.get("enabled", False))
    if atkgen_enabled and atkgen_cfg.get("include_native_probe", True):
        atkgen_probe_name = "probes.atkgen.Tox"
        existing_names = {p["name"] for p in probes}
        if atkgen_probe_name not in existing_names:
            probes.append({"name": atkgen_probe_name, "tier": 1})

    probes = sort_by_tier(probes)

    # Phase 1: 基于侦察情报自适应重排序
    attack_rationale: list[tuple[str, str]] = []
    if recon_state:
        probes, attack_rationale = adaptive_prioritize(probes, recon_state)

    probe_spec = build_probe_spec(probes)

    # P3-5: 扫描成本预估
    # 基于探针数量 × generations × 每探针 prompt 数 × 估算 token/prompt
    # 预估总 API 调用次数和 token 消耗
    total_prompts = sum(len(p.get("prompts", [])) for p in probes if isinstance(p.get("prompts"), list))
    # 如果 prompts 不可用（filtered 产物不含 prompts），用探针数 × 估算均值
    if total_prompts == 0:
        total_prompts = len(probes) * 10  # 经验均值：每探针约 10 条 prompt

    # 从 atkgen_cfg 或默认值获取 generations
    generations = 1
    if atkgen_cfg and isinstance(atkgen_cfg, dict):
        generations = atkgen_cfg.get("generations", 1)
    # 尝试从 config 获取 generations
    try:
        from pipeline.utils import load_config as _lc
        # 不重复加载，使用传入参数
    except Exception:
        pass

    # 估算每 prompt 的输入/输出 token
    est_input_tokens_per_prompt = 50   # 平均 prompt 长度
    est_output_tokens_per_prompt = 200 # 平均响应长度
    # 每个探针通常配 1-2 个 detector，detector 也需调用 LLM
    detector_multiplier = 2.0

    total_api_calls = total_prompts * generations
    est_input_tokens = total_api_calls * est_input_tokens_per_prompt
    est_output_tokens = total_api_calls * est_output_tokens_per_prompt * detector_multiplier
    est_total_tokens = est_input_tokens + est_output_tokens

    cost_estimate = {
        "total_probes": len(probes),
        "total_prompts": total_prompts,
        "generations": generations,
        "estimated_api_calls": total_api_calls,
        "estimated_input_tokens": est_input_tokens,
        "estimated_output_tokens": int(est_output_tokens),
        "estimated_total_tokens": int(est_total_tokens),
        "note": "成本预估为经验估算，实际消耗取决于模型响应长度和 detector 配置",
    }

    selection = {
        "run_id": run_id,
        "scan_profile": resolved["profile"],
        "total_selected": len(probes),
        "tier_breakdown": _tier_breakdown(probes),
        "probe_names": [p["name"] for p in probes],
        "probe_spec": probe_spec,
        "buff_spec": effective_buff,
        "atkgen_enabled": atkgen_enabled,
        "attack_rationale": attack_rationale,
        "cost_estimate": cost_estimate,
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
