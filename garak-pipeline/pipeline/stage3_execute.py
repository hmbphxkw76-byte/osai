"""Stage 3 — 攻击执行（garak 核心能力真驱动）

真正调用 garak harness 对目标发起攻击：
- 注入 OpenAICompatible generator（从 target.yaml 读 endpoint/key/model）
- 调用 command.probewise_run 执行探针 + Detector 评估
- 叠加 Buff 攻击链（编码绕过 + 翻译 + 角色扮演）
- 自适应速率控制（规则八：令牌桶限速 + Retry-After 退避 + 熔断 + 并发降级）

产物：garak 原生 <uuid>.report.jsonl（规则一：与 garak CLI 报告兼容）
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path

from garak import _config, _plugins, command
from garak.evaluators.base import ThresholdEvaluator

from .adaptive_rate import AdaptiveRateController

logger = logging.getLogger(__name__)


def _make_downgrade_cb():
    """生成并发降级回调：将新并发数写回 _config.run.parallel_requests

    闭包捕获 _config，运行时由 AdaptiveRateController 触发。
    """

    def cb(new_parallel: int) -> None:
        if hasattr(_config.run, "parallel_requests"):
            _config.run.parallel_requests = new_parallel
        logger.warning("自适应速率：并发降级至 %d", new_parallel)

    return cb


def _configure_garak(
    target: dict,
    execute_cfg: dict,
    reporting_cfg: dict,
    artifacts_dir: str,
) -> None:
    """注入 _config：目标、并发、置信区间

    :param target: target.yaml 的 target 段
    :param execute_cfg: config execute 段（generations/parallel/jitter）
    :param reporting_cfg: config reporting 段（置信区间参数）
    :param artifacts_dir: 产物根目录（garak 报告落点 = artifacts_dir/03_execution）
    """
    _config.plugins.target_type = "openai.OpenAICompatible"
    _config.plugins.target_name = target["model"]
    # API key 经环境变量注入（见 execute_attack 中
    # os.environ["OpenAICompatible_API_KEY"]）；garak 0.15.x 的
    # _config.plugins 无 api_key 属性，用 hasattr 守卫以兼容。
    if hasattr(_config.plugins, "api_key"):
        _config.plugins.api_key = target["api_key"]

    # generator 连接参数（nested_dict 字典访问，避免 crystallise 后属性丢失）
    gen_ns = _config.plugins.generators["openai"]["OpenAICompatible"]
    gen_ns["name"] = target["model"]
    gen_ns["uri"] = target["endpoint"]
    gen_ns["timeout"] = execute_cfg.get("timeout", 30)
    gen_ns["generations"] = execute_cfg.get("generations", 10)

    # 置信区间（规则三 + garak 原生 bootstrap）
    ci = reporting_cfg or {}
    if ci.get("confidence_interval_method") == "bootstrap":
        _config.reporting.confidence_interval_method = "bootstrap"
        _config.reporting.bootstrap_confidence_level = ci.get(
            "bootstrap_confidence_level", 0.95
        )
        _config.reporting.bootstrap_min_sample_size = ci.get(
            "bootstrap_min_sample_size", 30
        )
        _config.reporting.bootstrap_num_iterations = ci.get(
            "bootstrap_n_resamples", 1000
        )
    else:
        _config.reporting.confidence_interval_method = "none"

    _config.run.generations = execute_cfg.get("generations", 10)
    # garak: run.parallel_requests 守卫赋值以兼容多版本
    if hasattr(_config.run, "parallel_requests"):
        _config.run.parallel_requests = execute_cfg.get("parallel_requests", 1)

    # 将 garak 原生报告目录直接指向本仓库产物目录（outputs/03_execution），
    # 避免默认 garak_runs/ 二次落点 + 根目录污染。
    report_dir = Path(artifacts_dir) / "03_execution"
    report_dir.mkdir(parents=True, exist_ok=True)
    _config.reporting.report_dir = str(report_dir.resolve())


def execute_attack(
    target: dict,
    probe_names: list[str],
    buff_spec: str,
    run_id: str,
    artifacts_dir: str,
    execute_cfg: dict | None = None,
    reporting_cfg: dict | None = None,
) -> dict:
    """驱动 garak 对目标发起真正攻击

    :param target: target.yaml 的 target 段
    :param probe_names: 来自 Stage2 的探针完整名列表
    :param buff_spec: Buff 攻击链（逗号分隔，如 "encoding:Rot13,..."）
    :param run_id: 运行标识
    :param artifacts_dir: 产物根目录
    :param execute_cfg: 执行参数（generations/timeout/parallel_requests）
    :param reporting_cfg: 置信区间参数
    :returns: 执行结果（含 garak 报告路径）
    """
    execute_cfg = execute_cfg or {}
    reporting_cfg = reporting_cfg or {}
    buff_names = [b.strip() for b in buff_spec.split(",") if b.strip()]

    # 确保 garak 基础配置已加载（填充 system/run 子配置默认值）
    # 版本兼容：garak 0.16 用 `is_loaded` 属性(bool)；0.15 用 `loaded` 属性。
    if hasattr(_config, "is_loaded"):
        config_loaded = bool(_config.is_loaded)
    elif hasattr(_config, "loaded"):
        config_loaded = bool(_config.loaded)
    else:
        config_loaded = False
    if not config_loaded:
        _config.load_base_config()

    # OpenAICompatible 要求 API key 在 OpenAICompatible_API_KEY 环境变量
    import os

    os.environ["OpenAICompatible_API_KEY"] = target.get("api_key", "")

    _configure_garak(target, execute_cfg, reporting_cfg, artifacts_dir)

    # 构造 generator（从 _config 读取 endpoint/key/model）
    generator = _plugins.load_plugin(
        "generators.openai.OpenAICompatible", config_root=_config
    )

    # 规则八：自适应速率（令牌桶 + Retry-After + 熔断 + 并发降级）
    rate_cfg = execute_cfg.get("rate_limit", {}) or {}
    rate = AdaptiveRateController(
        generator,
        max_rpm=rate_cfg.get("max_rpm", 60.0),
        base_delay=rate_cfg.get("base_delay", 1.0),
        max_delay=rate_cfg.get("max_delay", 60.0),
        max_retries=rate_cfg.get("max_retries", 5),
        cooldown=rate_cfg.get("cooldown", 30.0),
        cooldown_threshold=rate_cfg.get("cooldown_threshold", 5),
        downgrade_at=rate_cfg.get("downgrade_at", 3),
        jitter=rate_cfg.get("jitter", True),
        on_downgrade=_make_downgrade_cb(),
    )
    rate.patch()

    evaluator = ThresholdEvaluator(_config.run.eval_threshold if hasattr(_config.run, "eval_threshold") else 0.5)

    # command.start_run/end_run 依赖 _config.transient 的多个字段（CLI 入口注入），
    # 此处自行补齐以满足其运行（不修改 garak 源码）
    import argparse
    import datetime
    from pathlib import Path

    _config.transient.cli_args = argparse.Namespace(
        list_probes=None, list_detectors=None, list_generators=None,
        list_buffs=None, list_config=None, plugin_info=None,
    )
    # CLI run parser 会向 run/system 注入额外字段，此处补齐以满足 start_run/end_run
    if not hasattr(_config.run, "interactive"):
        _config.run.interactive = False
    _config.transient.data_dir = Path(_config.reporting.report_dir or "reports").parent \
        if _config.reporting.report_dir else Path(".")
    # 确保 data_dir 存在且为绝对路径
    _config.transient.data_dir = Path(_config.transient.data_dir).resolve()
    _config.transient.data_dir.mkdir(parents=True, exist_ok=True)
    _config.transient.starttime = datetime.datetime.now()
    _config.transient.starttime_iso = _config.transient.starttime.isoformat()
    if not hasattr(_config.transient, "hitlogfile"):
        _config.transient.hitlogfile = None

    # garak 报告生命周期（报告已直接写入 outputs/03_execution/）
    command.start_run()
    report_filename = str(_config.transient.report_filename)
    try:
        command.probewise_run(generator, probe_names, evaluator, buff_names)
    finally:
        command.end_run()
        rate.unpatch()

    # 规范化文件名：garak.<uuid>.report.jsonl → garak_report_{run_id}.jsonl
    # （规则一：保留 garak 原生格式，仅统一命名，不另起拷贝）
    src = Path(report_filename)
    # 从 garak 原生报告文件名提取 run uuid（garak.<uuid>.report.jsonl）
    garak_run_id = None
    import re as _re

    m = _re.search(r"garak\.([0-9a-fA-F-]{36})", src.name)
    if m:
        garak_run_id = m.group(1)

    report_out = report_filename
    if src.exists():
        dest = src.with_name(f"garak_report_{run_id}.jsonl")
        if dest != src:
            src.replace(dest)
        report_out = str(dest)

    # 统计探针数
    probe_count = len(probe_names)

    return {
        "run_id": run_id,
        "garak_run_id": garak_run_id,
        "generator": f"{_config.plugins.target_type} {target['model']}",
        "probe_count": probe_count,
        "buff_spec": buff_spec,
        "report_path": report_out,
        "generations": _config.run.generations,
    }


def parse_report_probe_names(report_path: str) -> list[str]:
    """从 garak 报告中提取实际执行的探针名（供 Stage4 校验覆盖）

    :param report_path: garak 报告 JSONL 路径
    :returns: 探针名集合
    """
    names: set[str] = set()
    p = Path(report_path)
    if not p.exists():
        return []
    with open(p, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if rec.get("entry_type") == "probe_summary" and rec.get("probe"):
                names.add(rec["probe"])
    return sorted(names)


def _is_garak_uuid(name: str) -> bool:
    """判断文件名是否含 garak 运行 uuid"""
    return bool(re.search(r"[0-9a-f]{8}-[0-9a-f]{4}-", name))
