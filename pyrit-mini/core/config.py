"""CLI 参数解析 + 环境初始化 + 输出目录管理。

攻击链路配置入口:
    优先级: CLI --flag > --config-file YAML > config/defaults.yaml > 硬编码默认值

职责:
    - parse_args: CLI 参数解析 (argparse)
    - load_config_file: 加载 --config-file 统一 YAML 配置
    - get_output_dir: 输出目录路径生成 (带时间戳)
    - ensure_output_dir: 创建输出目录及子目录
    - setup_environment: PyRIT 环境初始化 (SQLite WAL 模式)

增量借鉴 (pyrit_scan CLI 模式):
    - --memory-labels: 运行标签 (JSON), 写入 CentralMemory 用于结果过滤
    - --seed-filters: 种子元数据过滤 (KEY=VALUE), 精准选取种子
    - --converters 新增 technique:converter.xxx 语法: per-technique 追加 converter
    - --add-initializer: 动态 Target 注册 (class_name,arg=value)
    - --config-file: 统一 YAML 配置, 可声明 seeds/converters/techniques/burp
"""

from __future__ import annotations

import argparse
import json
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml

# 自动加载 .env 文件 (python-dotenv)
try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    pass

logger = logging.getLogger(__name__)

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_DEFAULTS_YAML = _PROJECT_ROOT / "config" / "defaults.yaml"


def _load_defaults() -> dict[str, Any]:
    """从 config/defaults.yaml 加载默认值 (SSOT)."""
    if not _DEFAULTS_YAML.exists():
        return {}
    try:
        with open(_DEFAULTS_YAML, encoding="utf-8") as f:
            data = yaml.safe_load(f)
        return data if isinstance(data, dict) else {}
    except Exception as e:
        logger.warning("Failed to load defaults.yaml: %s", e)
        return {}


def _apply_defaults(args: argparse.Namespace, defaults: dict[str, Any]) -> None:
    """用 YAML 默认值填充 args 中为 None 的参数."""
    key_map = {"scenario_timeout": "timeout"}
    for yaml_key, default_val in defaults.items():
        arg_key = key_map.get(yaml_key, yaml_key)
        current = getattr(args, arg_key, None)
        if current is None:
            setattr(args, arg_key, default_val)


def _load_config_file(path: str) -> dict[str, Any]:
    """加载 --config-file 指定的 YAML 配置文件。

    支持 YAML 键:
        seeds: string          # 种子文件名 (逗号分隔)
        converters: string     # Converter 链 (auto, l5_optimal, none, 或 technique:converter.xxx 语法)
        techniques: string     # 攻击技术 (auto, single, crescendo, ...)
        burp: [string]         # Burp 文件名列表
        max_seeds: int         # 最大种子数
        max_attempts: int      # 每个种子最大重试
        max_concurrency: int   # 最大并发数
        timeout: int           # 场景超时秒数
        memory_labels: dict    # 运行标签 (写入 CentralMemory)
        seed_filters: dict     # 种子过滤 (KEY=VALUE)
        add_initializer: [string]  # 动态 Initializer 注册
        offensive: bool        # 全火力模式
        escalation: bool       # 启用/禁用升级
        html_report: bool      # 生成 HTML 报告
        rate_limit: int        # API 限速 (RPM)
        target_api_endpoint: string
        target_api_key: string
        target_api_model: string
        target_api_type: string  # chat | responses
        litellm_model: string
        browser_url: string
    """
    config_path = Path(path)
    if not config_path.is_absolute():
        config_path = _PROJECT_ROOT / config_path
    if not config_path.exists():
        logger.warning("Config file not found: %s", config_path)
        return {}
    try:
        with open(config_path, encoding="utf-8") as f:
            data = yaml.safe_load(f)
        if not isinstance(data, dict):
            logger.warning("Config file %s is not a dict, ignoring", config_path)
            return {}
        logger.info("Loaded config file: %s (%d keys)", config_path, len(data))
        return data
    except Exception as e:
        logger.warning("Failed to load config file %s: %s", config_path, e)
        return {}


def _apply_config_file(args: argparse.Namespace, config: dict[str, Any]) -> None:
    """用 --config-file YAML 填充 args 中仍为 None 的参数。

    优先级: CLI --flag > --config-file > config/defaults.yaml > 硬编码
    因此只填充 args 中仍为 None 或默认值的参数。

    支持 YAML 嵌套 section (所有 section 的 key 平铺到 args 顶层, 与 defaults.yaml key 对齐):
        scoring:       # 评分配置 — 控制 T0/J1/J2/J3 级联评分策略
            dual_judge_enabled: bool
            dual_judge_high_confidence_threshold: float
            wilson_confidence_level: float
            scorer_timeout: int
            best_of_n_retries: int
        escalation:    # 多轮升级配置 — 控制 Crescendo/TAP/PAIR 参数
            escalation_asr_threshold: float
            post_l1_exit_threshold: float
            post_l2_exit_threshold: float
            max_escalation_targets: int
            crescendo_max_turns: int
            tap_tree_width: int
            tap_tree_depth: int
            tap_branching: int
            tap_success_threshold: int
            pair_tree_width: int
            pair_tree_depth: int
        probe:         # 黑盒探测配置
            probe_timeout: int
            probe_retries: int
            deep_probe_timeout: int
            parallel_probe_timeout: int
            max_concurrent_probes: int
        adaptive:      # PyRIT TextAdaptive 自适应配置
            adaptive_epsilon: float
            adaptive_random_seed: int
            adaptive_max_attempts: int
            adaptive_technique_filter: list | null
        execution:     # 执行控制
            max_concurrency: int
            max_attempts: int
            max_seeds: int
            scenario_timeout: int
            api_timeout: int
            rate_limit: int
            l5_optimal_paths: int
            auto_seed_expansion_factor: int
    """
    # 字符串/数值参数: 仅在 None 时填充
    _str_keys = [
        "seeds", "converters", "techniques", "max_seeds", "max_attempts",
        "max_concurrency", "timeout", "rate_limit",
        "litellm_model", "target_api_endpoint", "target_api_key",
        "target_api_model", "target_api_type", "browser_url",
    ]
    for key in _str_keys:
        yaml_val = config.get(key)
        if yaml_val is not None and getattr(args, key, None) is None:
            setattr(args, key, yaml_val)

    # burp: 特殊处理 — config_file 中的 burp 是列表, args.burp 可能是 None
    burp_cfg = config.get("burp")
    if burp_cfg is not None and args.burp is None:
        if isinstance(burp_cfg, list):
            args.burp = burp_cfg[0] if len(burp_cfg) == 1 else burp_cfg
        else:
            args.burp = burp_cfg

    # bool 参数: 仅在 None/默认值时填充
    if config.get("offensive") is not None and not args.offensive:
        args.offensive = bool(config["offensive"])
    if config.get("html_report") is not None and not args.html_report:
        args.html_report = bool(config["html_report"])
    if config.get("escalation") is not None and args.escalation is None:
        args.escalation = bool(config["escalation"])

    # escalation_levels: config_file 中是字符串 (如 "L2,L4"), CLI 中也是字符串
    # 如果 CLI 未指定 --escalation-levels (None), 则用 config_file 的
    # 实际解析在 parse_args 末尾通过 _parse_escalation_levels 完成
    el_cfg = config.get("escalation_levels")
    if el_cfg is not None and getattr(args, "escalation_levels", None) is None:
        if isinstance(el_cfg, (str, list)):
            args.escalation_levels = ",".join(el_cfg) if isinstance(el_cfg, list) else el_cfg

    # memory_labels: config_file 中是 dict, CLI 中是 JSON 字符串
    # 如果 CLI 未指定 --memory-labels (None), 则用 config_file 的
    ml_cfg = config.get("memory_labels")
    if ml_cfg is not None and args.memory_labels is None:
        if isinstance(ml_cfg, dict):
            args.memory_labels = ml_cfg  # _parse_memory_labels 会处理 dict

    # seed_filters: config_file 中是 dict, CLI 中是 KEY=VALUE 字符串
    sf_cfg = config.get("seed_filters")
    if sf_cfg is not None and args.seed_filters is None:
        if isinstance(sf_cfg, dict):
            # 转为逗号分隔的 KEY=VALUE 字符串, _parse_seed_filters 会再解析
            args.seed_filters = ",".join(f"{k}={v}" for k, v in sf_cfg.items())

    # add_initializer: config_file 中是列表
    ai_cfg = config.get("add_initializer")
    if ai_cfg is not None and args.add_initializer is None:
        if isinstance(ai_cfg, list):
            args.add_initializer = [str(x) for x in ai_cfg]

    # ── 嵌套 section: scoring / escalation / probe / adaptive / execution ──
    # 所有 section 的 key 平铺到 args 顶层 (与 defaults.yaml key 对齐)
    # 由于 _apply_config_file 在 _apply_defaults 之前运行,
    # 填充后的值不会被 defaults.yaml 覆盖 (因为不再是 None)
    _section_keys = [
        # scoring section — 评分策略
        ("scoring", ["dual_judge_enabled", "dual_judge_high_confidence_threshold",
                      "wilson_confidence_level", "scorer_timeout", "best_of_n_retries"]),
        # escalation section — 多轮升级
        ("escalation", ["escalation_asr_threshold", "post_l1_exit_threshold",
                         "post_l2_exit_threshold", "max_escalation_targets",
                         "crescendo_max_turns", "tap_tree_width", "tap_tree_depth",
                         "tap_branching", "tap_success_threshold",
                         "pair_tree_width", "pair_tree_depth", "escalation_levels"]),
        # probe section — 黑盒探测
        ("probe", ["probe_timeout", "probe_retries", "deep_probe_timeout",
                     "parallel_probe_timeout", "max_concurrent_probes"]),
        # adaptive section — PyRIT TextAdaptive
        ("adaptive", ["adaptive_epsilon", "adaptive_random_seed",
                        "adaptive_max_attempts", "adaptive_technique_filter"]),
        # execution section — 执行控制 (补充 _str_keys 中未覆盖的)
        ("execution", ["scenario_timeout", "api_timeout", "rate_limit_retries",
                        "timeout_max_retries", "timeout_max_delay",
                        "l5_optimal_paths", "auto_seed_expansion_factor",
                        "rate_limit", "max_concurrency", "max_attempts", "max_seeds"]),
    ]

    for section_name, keys in _section_keys:
        section_data = config.get(section_name)
        if not isinstance(section_data, dict):
            continue
        for key in keys:
            if key not in section_data:
                continue
            val = section_data[key]
            # 仅在 args 中仍为 None 时填充 (CLI 优先)
            if getattr(args, key, None) is None:
                setattr(args, key, val)
                logger.debug("config-file section '%s': %s = %s", section_name, key, val)


def _parse_memory_labels(raw: Any) -> dict[str, str]:
    """解析 --memory-labels 参数为 dict。

    支持:
        - JSON 字符串: '{"run_id":"r001","target":"deepseek"}'
        - dict (来自 config_file): 直接返回
        - None/空: 返回 {}
    """
    if not raw:
        return {}
    if isinstance(raw, dict):
        return {str(k): str(v) for k, v in raw.items()}
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, dict):
                return {str(k): str(v) for k, v in parsed.items()}
            logger.warning("--memory-labels JSON is not a dict: %s", type(parsed).__name__)
        except json.JSONDecodeError as e:
            logger.warning("--memory-labels is not valid JSON: %s (value=%s)", e, raw[:100])
    return {}


def _parse_seed_filters(raw: Any) -> dict[str, str]:
    """解析 --seed-filters 参数为 dict。

    支持:
        - 逗号分隔 KEY=VALUE: "owasp_id=LLM01,difficulty=high"
        - dict (来自 config_file): 直接返回
        - None/空: 返回 {}
    """
    if not raw:
        return {}
    if isinstance(raw, dict):
        return {str(k): str(v) for k, v in raw.items()}
    if isinstance(raw, str):
        result: dict[str, str] = {}
        for pair in raw.split(","):
            pair = pair.strip()
            if not pair:
                continue
            if "=" not in pair:
                logger.warning("Invalid seed-filter (expected KEY=VALUE): %s", pair)
                continue
            k, v = pair.split("=", 1)
            k = k.strip()
            v = v.strip()
            if k:
                result[k] = v
        return result
    return {}


def _parse_converter_overrides(converters_str: str | None) -> dict[str, list[str]]:
    """解析 --converters 中的 technique:converter.xxx 追加语法。

    语法: --converters "auto;tap:persuasion;pair:decomposition,base64"
    - 分号分隔: 前面是全局 converter 链, 后面是 per-technique 追加
    - 冒号前是 technique 名, 冒号后是逗号分隔的 converter chain 名
    - 返回 {technique: [chain_name, ...]}

    如果没有分号语法, 返回 {} (向后兼容)。
    """
    if not converters_str or ";" not in converters_str:
        return {}

    overrides: dict[str, list[str]] = {}
    parts = converters_str.split(";")
    for part in parts[1:]:  # 跳过第一个 (全局链)
        part = part.strip()
        if not part or ":" not in part:
            continue
        tech, chains = part.split(":", 1)
        tech = tech.strip()
        chain_list = [c.strip() for c in chains.split(",") if c.strip()]
        if tech and chain_list:
            overrides[tech] = chain_list
    return overrides


def _parse_converter_global(converters_str: str | None) -> str:
    """提取 --converters 中的全局 converter 链 (分号前的部分)。

    "auto;tap:persuasion" → "auto"
    "l5_optimal" → "l5_optimal"
    "none;pair:base64" → "none"
    """
    if not converters_str:
        return "auto"
    if ";" in converters_str:
        return converters_str.split(";")[0].strip()
    return converters_str.strip()


def _parse_initializer_specs(raw: list[str] | None) -> list[dict[str, Any]]:
    """解析 --add-initializer 列表为结构化 spec。

    输入: ["ClassName,arg1=val1,arg2=val2", "OtherInit"]
    输出: [
        {"class": "ClassName", "args": {"arg1": "val1", "arg2": "val2"}},
        {"class": "OtherInit", "args": {}},
    ]
    """
    if not raw:
        return []
    specs: list[dict[str, Any]] = []
    for item in raw:
        parts = item.split(",")
        class_name = parts[0].strip()
        if not class_name:
            continue
        kwargs: dict[str, str] = {}
        for part in parts[1:]:
            part = part.strip()
            if not part or "=" not in part:
                continue
            k, v = part.split("=", 1)
            k = k.strip()
            v = v.strip()
            if k:
                kwargs[k] = v
        specs.append({"class": class_name, "args": kwargs})
    return specs


def _parse_escalation_levels(raw: str) -> set[int] | None:
    """解析 --escalation-levels 参数为级别集合。

    支持:
        - 逗号分隔: "L1,L2,L4" → {1, 2, 4}
        - 范围: "L1-L4" → {1, 2, 3, 4}
        - 混合: "L1,L3-L4" → {1, 3, 4}
        - 大小写不敏感: "l1,l2" → {1, 2}
        - "all" → {1, 2, 3, 4}
        - "none"/"" → None (完整链)

    Args:
        raw: 原始字符串。

    Returns:
        级别集合 (如 {1, 2, 4}), None 表示完整链。
    """
    if not raw or not raw.strip():
        return None
    raw = raw.strip().lower()
    if raw == "all":
        return {1, 2, 3, 4}
    if raw in ("none", "default"):
        return None

    levels: set[int] = set()
    parts = raw.split(",")
    for part in parts:
        part = part.strip()
        if not part:
            continue
        # 范围语法: L1-L4
        if "-" in part:
            range_parts = part.split("-")
            if len(range_parts) == 2:
                try:
                    start = int(range_parts[0].strip().lstrip("lL"))
                    end = int(range_parts[1].strip().lstrip("lL"))
                    for i in range(start, end + 1):
                        if 1 <= i <= 4:
                            levels.add(i)
                except ValueError:
                    logger.warning("Invalid escalation level range: %s", part)
            continue
        # 单个级别: L1
        try:
            num = int(part.lstrip("lL"))
            if 1 <= num <= 4:
                levels.add(num)
            else:
                logger.warning("Escalation level out of range (1-4): %s", part)
        except ValueError:
            logger.warning("Invalid escalation level: %s", part)

    if not levels:
        logger.warning("No valid escalation levels parsed from '%s', using full chain", raw)
        return None
    return levels


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """解析 CLI 参数 — 攻击链路统一入口.

    Args:
        argv: 可选参数列表。None 时使用 sys.argv。

    Returns:
        argparse Namespace 对象, 已应用 YAML 默认值。
    """
    parser = argparse.ArgumentParser(
        description="PyRIT-Strike — Burp拦截→侦察→种子→Converter→攻击→评分→证据 攻击链路",
    )

    # ── 流水线阶段控制 ──
    # 7 阶段划分 (对齐 OWASP AI-300 Five-Step + PyRIT 原生流水线):
    #   recon     → Burp 解析 + 目标探测 + 能力指纹 + HTTPTarget 构建
    #   arm       → 种子加载/ASR 排序 + Converter 链构建 + 技术选择
    #   strike    → 单轮 PyRIT 原生多路径攻击 (PromptSendingAttack FIRST_SUCCESS)
    #   escalate  → 多轮升级链 (Crescendo→TAP→PAIR→GCG→native, ASR<90% 触发)
    #   assess    → T0→J1→J2→J3 级联评分 + ASR 统计 + Wilson CI
    #   report    → 证据收集 + MD/HTML/JSON/PoC/SARIF 生成
    # 不指定 --stage 时按顺序执行全部阶段 (strike+escalate 合为一步), 向后兼容。
    parser.add_argument(
        "--stage",
        type=str,
        default=None,
        choices=["recon", "arm", "strike", "escalate", "assess", "report"],
        help="只执行到指定阶段后停止 (recon/arm/strike/escalate/assess/report), "
             "不指定则执行完整链路",
    )

    # ── 侦察: Burp 拦截 ──
    # 用法: --burp <name> (单个) 或 --burp MM_05 --burp MM_03 (多个)
    #   自动解析为 data/burp/<name>.txt
    #   不指定时自动扫描 data/burp/*.txt 全部文件 (逐个深度攻击)
    #   也可直接传完整路径: --burp data/burp/deepseek.txt
    #   多个 endpoint: --burp MM_05 --burp MM_03 --burp MM_08
    #   学术依据: Greshake et al. (arXiv:2302.12173) — 逐个深度攻击 + 联合 ASR
    parser.add_argument(
        "--burp",
        type=str,
        default=None,
        metavar="NAME",
        action="append",
        help="Burp 拦截的 HTTP 请求文件名 (自动查找 data/burp/<NAME>.txt), "
             "可重复指定多个 endpoint; 不指定时自动扫描 data/burp/*.txt 全部文件",
    )

    # ── 种子选取 ──
    parser.add_argument(
        "--seeds",
        type=str,
        default=None,  # config-file 或 defaults.yaml 填充, 最终 fallback "elite_jailbreaks,asi_top10,owasp_full_coverage"
        help="种子文件名 (逗号分隔)",
    )
    parser.add_argument("--max-seeds", type=int, default=None, help="最大种子数 (默认 25)")
    parser.add_argument("--auto-seeds", action="store_true", default=False, help="自动种子扩充 (3x)")
    parser.add_argument("--enable-dos", action="store_true", default=False, help="启用 DoS 攻击")

    # ── Converter 转换 ──
    parser.add_argument(
        "--converters", type=str, default=None, help="Converter 链 (auto, l5_optimal, none, ...)"
    )

    # ── 攻击发送 ──
    parser.add_argument(
        "--techniques", type=str, default=None, help="攻击技术 (auto, single, crescendo, ...)"
    )
    parser.add_argument("--max-attempts", type=int, default=None, help="每个种子最大重试次数")
    parser.add_argument("--max-concurrency", type=int, default=None, help="最大并发数 (默认 3)")
    parser.add_argument("--timeout", type=int, default=None, help="场景超时秒数 (默认 1200)")

    # ── 升级 ──
    parser.add_argument("--escalation", action="store_true", default=None, help="启用多轮升级")
    parser.add_argument("--no-escalation", action="store_false", dest="escalation", help="禁用多轮升级")
    parser.add_argument(
        "--escalation-levels",
        type=str,
        default=None,
        metavar="L1,L2,L3,L4",
        help="指定升级级别组合 (逗号分隔), 如 'L2,L4' 只执行 L2+L4; "
             "不指定时执行完整 L1→L2→L3→L4 链 (向后兼容); "
             "可选值: L1 (RedTeaming+CoT+Crescendo+TAP+PAIR), "
             "L2 (GCG+CAIR+Best-of-N+Encoded), "
             "L3 (Multi-Model+SkeletonKey+Many-Shot+CoT+Chunked), "
             "L4 (RogueAgent+EmbeddingInversion+MCP/RAG)",
    )

    # ── 模式标志 ──
    parser.add_argument("--offensive", action="store_true", default=False, help="全火力模式")
    parser.add_argument("--rate-limit", type=int, default=None, help="API 限速 (RPM)")

    # ── R10: --dry-run 零 token 流水线完整性验证 ──
    # 跳过 strike/escalate 阶段的真实 API 调用, 验证所有阶段的数据流贯通
    # 用途: 每次代码修改后运行 python main.py --dry-run --max-seeds 1
    # 确保: 导入链完整, ctx 字段传递无断点, 编排日志覆盖 6 阶段, 报告生成无异常
    parser.add_argument(
        "--dry-run",
        action="store_true",
        default=False,
        help="零 token 流水线完整性验证 (R10) — 跳过 strike/escalate 真实 API 调用, "
             "验证所有阶段数据流贯通; 用法: python main.py --dry-run --max-seeds 1",
    )

    # ── 报告 ──
    parser.add_argument("--html-report", action="store_true", default=False, help="生成 HTML 报告")

    # ── 增量借鉴: --memory-labels 运行标签 ──
    # 借鉴 pyrit_scan 的 --memory-labels: 运行时标签写入 CentralMemory,
    # 用于后续结果查询过滤 (如 label=production,target=deepseek)
    # 格式: JSON 字符串 {"run_id": "r001", "target": "deepseek"}
    parser.add_argument(
        "--memory-labels",
        type=str,
        default=None,
        metavar="JSON",
        help='运行标签 (JSON 字符串, 如 \'{"run_id":"r001","target":"deepseek"}\'); '
             '写入 CentralMemory 用于结果过滤和报告标记',
    )

    # ── 增量借鉴: --seed-filters 种子过滤 ──
    # 借鉴 pyrit_scan 的 --seed-filters: 按 metadata KEY=VALUE 过滤种子
    # 格式: owasp_id=LLM01,difficulty=high — 仅保留匹配的种子
    # 支持多值 (逗号分隔): category=attack,language=en
    parser.add_argument(
        "--seed-filters",
        type=str,
        default=None,
        metavar="KEY=VALUE",
        help='种子元数据过滤 (逗号分隔 KEY=VALUE, 如 owasp_id=LLM01,difficulty=high); '
             '仅保留 metadata 中匹配的种子',
    )

    # ── 增量借鉴: --add-initializer 动态 Target 注册 ──
    # 借鉴 pyrit_scan 的 --add-initializer: 运行时动态注册 PyRIT Initializer
    # 格式: ClassName,arg1=val1,arg2=val2 — 反射实例化并注册到 PyRIT
    # 可重复: --add-initializer MyInit,foo=bar --add-initializer OtherInit
    parser.add_argument(
        "--add-initializer",
        type=str,
        default=None,
        metavar="CLASS[,args]",
        action="append",
        help='动态注册 PyRIT Initializer (可重复); '
             '格式: ClassName,arg1=val1,arg2=val2 — 反射实例化并注册',
    )

    # ── 增量借鉴: --config-file 统一 YAML 配置 ──
    # 借鉴 pyrit_scan 的 --config-file: 一个 YAML 声明所有攻击组件
    # 支持声明: seeds, converters, techniques, burp, memory_labels, seed_filters
    # 优先级: CLI --flag > --config-file > config/defaults.yaml > 硬编码
    parser.add_argument(
        "--config-file",
        type=str,
        default=None,
        metavar="PATH",
        help='统一 YAML 配置文件路径; 可声明 seeds/converters/techniques/burp 等; '
             'CLI --flag 优先级高于配置文件',
    )

    # ── 目标路由 (对齐 PyRIT 1.0.1 原生 Target 体系) ──
    # 学术依据: PyRIT (arXiv:2407.01232) — 多原生 Target 路由
    # 优先级: --litellm-model > --target-api-endpoint > --browser-url > --burp
    parser.add_argument(
        "--litellm-model",
        type=str,
        default=None,
        metavar="MODEL",
        help="LiteLLM 模型字符串 (如 anthropic/claude-sonnet-4-6, bedrock/anthropic.claude-v2), "
             "通过 LiteLLM SDK 访问 100+ LLM 提供商; 配置 LITELLM_API_KEY/LITELLM_ENDPOINT 环境变量",
    )
    parser.add_argument(
        "--target-api-endpoint",
        type=str,
        default=None,
        metavar="URL",
        help="OpenAI 兼容 API 端点 (如 https://api.openai.com/v1), "
             "配合 --target-api-key 使用, 路由到 OpenAIChatTarget/OpenAIResponseTarget",
    )
    parser.add_argument(
        "--target-api-key",
        type=str,
        default=None,
        metavar="KEY",
        help="API 密钥 (配合 --target-api-endpoint 使用)",
    )
    parser.add_argument(
        "--target-api-model",
        type=str,
        default=None,
        metavar="MODEL",
        help="模型名称 (如 gpt-4o, o3-mini; 配合 --target-api-endpoint 使用)",
    )
    parser.add_argument(
        "--target-api-type",
        type=str,
        default="chat",
        choices=["chat", "responses"],
        help="API 类型: chat=Chat Completions API, responses=Responses API (o1/o3/GPT-5)",
    )
    parser.add_argument(
        "--browser-url",
        type=str,
        default=None,
        metavar="URL",
        help="浏览器渲染 Chat UI URL (路由到 PyRIT 原生 PlaywrightTarget), "
             "用于攻击需要 JS 渲染的 Web Chat 界面",
    )
    parser.add_argument(
        "--auto-discover-capabilities",
        action="store_true",
        default=False,
        help="运行 PyRIT 原生 discover_target_capabilities_async 自动探测目标能力",
    )

    # ── 输出 ──
    parser.add_argument("--output-dir", type=str, default=None, help="输出目录")
    parser.add_argument("--resume", type=str, default=None, help="从已有场景恢复")

    # ── 日志控制 ──
    # --verbose: 终端也显示 INFO 级别日志 (默认终端只显示卡片 + WARNING/ERROR)
    # 过程性日志始终写入 {output_dir}/pipeline.log
    parser.add_argument(
        "--verbose",
        action="store_true",
        default=False,
        help="终端显示 INFO 级别过程日志 (默认只显示卡片+WARNING/ERROR, "
             "完整日志写入 {output_dir}/pipeline.log)",
    )

    args = parser.parse_args(argv)

    explicit_escalation = args.escalation

    # ── 加载 --config-file 统一 YAML 配置 ──
    # 优先级: CLI --flag > --config-file > config/defaults.yaml > 硬编码
    # config_file 只填充 args 中仍为 None 的参数 (不覆盖 CLI 显式指定的值)
    config_file_data: dict[str, Any] = {}
    if getattr(args, "config_file", None):
        config_file_data = _load_config_file(args.config_file)
        _apply_config_file(args, config_file_data)

    # ── 应用 YAML 默认值 (config/defaults.yaml) ──
    defaults = _load_defaults()
    _apply_defaults(args, defaults)

    # ── 应用 --offensive 预设 ──
    if args.offensive:
        args.converters = "l5_optimal"
        args.html_report = True
        if args.max_attempts is None:
            args.max_attempts = 3

    # ── escalation 处理 ──
    if explicit_escalation is not None:
        args.escalation = explicit_escalation
    elif args.escalation is None:
        args.escalation = True

    # ── 增量借鉴: 解析 --converters technique:converter.xxx 追加语法 ──
    # 先从原始 converters 字符串解析 per-technique overrides (保留 ; 语法)
    # 然后再提取全局 converter 链 (去掉 ; 语法)
    _raw_converters = getattr(args, "converters", None)
    args.converter_overrides = _parse_converter_overrides(_raw_converters)

    # ── 增量借鉴: 提取全局 converter 链 (去掉 technique:converter.xxx 语法) ──
    # args.converters 可能包含 "auto;tap:persuasion" 格式
    # 提取分号前的部分作为全局 converter 链, 确保 main.py 的 split(",") 正常工作
    if args.converters and ";" in str(args.converters):
        args.converters = _parse_converter_global(args.converters)

    # ── Burp 请求路径解析 ──
    # 不指定 --burp → 自动扫描 data/burp/*.txt 全部文件 (逐个深度攻击)
    # --burp <name> → data/burp/<name>.txt (自动补全路径, 单个 endpoint)
    # 支持多值: --burp MM_05 --burp MM_03 → ["data/burp/MM_05.txt", "data/burp/MM_03.txt"]
    # 单值: --burp request → "data/burp/request.txt"
    # 多值时返回 list[str], 单值时返回 str (向后兼容)
    # 如果传入的值已包含路径分隔符或 .txt 后缀, 视为完整路径
    raw_burps = args.burp
    if raw_burps is None:
        # 不指定 --burp → 自动扫描 data/burp/ 目录下所有 .txt 文件
        # 学术依据: Greshake et al. (arXiv:2302.12173) — 逐个深度攻击
        burp_dir = _PROJECT_ROOT / "data" / "burp"
        if burp_dir.is_dir():
            raw_burps = sorted(
                str(f) for f in burp_dir.glob("*.txt") if f.is_file()
            )
        if not raw_burps:
            # 目录不存在或无 .txt 文件 → fallback 到默认 request.txt
            raw_burps = ["request"]
        logger.info(
            "No --burp specified: auto-discovered %d .txt file(s) in data/burp/",
            len(raw_burps),
        )
    elif isinstance(raw_burps, str):
        raw_burps = [raw_burps]

    resolved_burps: list[str] = []
    for burp_val in raw_burps:
        if "/" not in burp_val and "\\" not in burp_val and not burp_val.endswith(".txt"):
            # 纯文件名 → 自动补全为 data/burp/<name>.txt
            resolved_burps.append(str(_PROJECT_ROOT / "data" / "burp" / f"{burp_val}.txt"))
        elif not Path(burp_val).is_absolute() and ("/" in burp_val or "\\" in burp_val):
            # 相对路径 → 相对于项目根目录
            resolved_burps.append(str(_PROJECT_ROOT / burp_val))
        else:
            resolved_burps.append(burp_val)

    # 向后兼容: 单值返回 str, 多值返回 list[str]
    if len(resolved_burps) == 1:
        args.burp = resolved_burps[0]
    else:
        args.burp = resolved_burps
    # 额外保留列表形式供 main.py 判断是否多 endpoint
    args._burp_list = resolved_burps

    # ── 增量借鉴: 解析 --memory-labels JSON ──
    # 将 JSON 字符串解析为 dict, 存入 args.memory_labels_parsed
    # main.py 中读取并写入 CentralMemory
    args.memory_labels_parsed = _parse_memory_labels(getattr(args, "memory_labels", None))

    # ── 增量借鉴: 解析 --seed-filters KEY=VALUE ──
    # 解析逗号分隔的 KEY=VALUE 为 dict, 存入 args.seed_filters_parsed
    args.seed_filters_parsed = _parse_seed_filters(getattr(args, "seed_filters", None))

    # ── 增量借鉴: 解析 --add-initializer 列表 ──
    # 将 ["ClassName,arg1=val1", ...] 解析为 [{"class": "...", "args": {...}}, ...]
    args.initializer_specs = _parse_initializer_specs(getattr(args, "add_initializer", None))

    # ── 解析 --escalation-levels 级别组合 ──
    # 支持: "L1,L2,L4" / "l1,l3" / "L1-L4" / "all" / None (完整链)
    # 输出: args.escalation_levels_parsed = set[int] 如 {1, 2, 4}, None=完整链
    raw_levels = getattr(args, "escalation_levels", None)
    if raw_levels is not None:
        args.escalation_levels_parsed = _parse_escalation_levels(raw_levels)
    else:
        args.escalation_levels_parsed = None  # None = 完整 L1-L4 链

    # ── 硬编码 fallback (CLI + config-file + defaults.yaml 都未指定时) ──
    if args.seeds is None:
        args.seeds = "elite_jailbreaks,asi_top10,owasp_full_coverage"
    if args.converters is None:
        args.converters = "auto"
    if args.techniques is None:
        args.techniques = "auto"

    return args


def get_output_dir(args: argparse.Namespace) -> Path:
    """生成输出目录路径."""
    if args.output_dir is not None:
        return Path(args.output_dir)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return _PROJECT_ROOT / "outputs" / f"strike_{timestamp}"


def ensure_output_dir(output_dir: Path) -> Path:
    """创建输出目录及子目录 (evidence/, db/, poc/)."""
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "evidence").mkdir(parents=True, exist_ok=True)
    (output_dir / "db").mkdir(parents=True, exist_ok=True)
    return output_dir


async def setup_environment(output_dir: Path) -> None:
    """初始化 PyRIT 环境 — SQLite WAL 模式 + 内存实例.

    生产级: 多 endpoint 模式下重复调用时, 必须清除 Singleton 缓存 +
    释放旧 DB 引擎, 确保每个 endpoint 拥有独立的 SQLite DB 实例。

    根因 (PyRIT 1.0.1 Singleton 机制):
        SQLiteMemory 使用 metaclass=Singleton, 第二次调用 SQLiteMemory(db_path=...)
        时, Singleton.__call__ 直接返回旧实例, __init__ 不执行, db_path 被忽略。
        CentralMemory._memory_instance 也是类变量单例, 同理。

        仅调用 dispose_engine() 释放 SQLAlchemy 连接池是不够的 —
        Singleton._instances 字典中的旧实例仍然存在, 新 db_path 不会生效。

    修复: 三步清除
        1. 释放旧 MemoryInterface 的 SQLAlchemy engine (dispose_engine)
        2. 从 Singleton._instances 中删除 SQLiteMemory 缓存
        3. 清除 CentralMemory._memory_instance 引用

    学术依据: PyRIT (arXiv:2407.01232) — dispose_db_engine() 资源释放
    """
    try:
        from dotenv import load_dotenv
        load_dotenv()
    except ImportError:
        pass

    from pyrit.setup.initialization import initialize_pyrit_async

    db_path = Path(output_dir) / "db" / "pyrit.db"
    db_path.parent.mkdir(parents=True, exist_ok=True)

    os.environ["PYRIT_DB_URL"] = f"sqlite:///{db_path}"
    os.environ.setdefault("PYRIT_SQLITE_JOURNAL_MODE", "WAL")
    os.environ.setdefault("PYRIT_SQLITE_BUSY_TIMEOUT", "5000")

    # ── 三步清除: 确保多 endpoint 模式下 DB 真正隔离 ──
    # 不清除缓存时, SQLiteMemory Singleton 返回旧实例, 新 db_path 被忽略,
    # 所有 endpoint 的攻击数据都写入第一次初始化的 DB 路径 (顶层 db/pyrit.db)。
    try:
        from pyrit.common.singleton import Singleton
        from pyrit.memory import CentralMemory
        from pyrit.memory.sqlite_memory import SQLiteMemory

        # Step 1: 释放旧 MemoryInterface 的 SQLAlchemy engine
        _old_memory = CentralMemory._memory_instance
        if _old_memory is not None:
            try:
                _old_memory.dispose_engine()
                logger.debug("Disposed previous SQLAlchemy engine")
            except Exception as e:
                logger.debug("Engine dispose skipped (non-fatal): %s", e)

        # Step 2: 清除 SQLiteMemory Singleton 缓存
        # 这一步是关键 — 让下次 SQLiteMemory(db_path=...) 真正执行 __init__
        if SQLiteMemory in Singleton._instances:
            del Singleton._instances[SQLiteMemory]
            logger.debug("Cleared SQLiteMemory Singleton cache")

        # Step 3: 清除 CentralMemory 单例引用
        # 让 initialize_pyrit_async 中的 set_memory_instance 生效
        CentralMemory._memory_instance = None
        logger.debug("Cleared CentralMemory singleton reference")
    except ImportError as e:
        logger.debug("Singleton cache clear skipped (import): %s", e)
    except Exception as e:
        logger.debug("Singleton cache clear skipped (non-fatal): %s", e)

    await initialize_pyrit_async(
        memory_db_type="SQLite",
        load_defaults=True,
        silent=True,
        db_path=str(db_path),
    )
    logger.info("PyRIT environment initialized (DB: %s)", db_path)
