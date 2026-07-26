"""
Config Loader
=============

本模块负责从 YAML 配置文件加载配置（遵循开发规则 1.4.2）。

配置分层架构（最佳实践）：
  ┌─────────────────────────────────────────────────────────┐
  │  .env                        ← 运行时必改参数（唯一入口）│
  │    TARGET_ENDPOINT / API_KEY / JUDGE_* / ...            │
  ├─────────────────────────────────────────────────────────┤
  │  config/defaults/            ← 调优默认值（可覆盖）      │
  │    model_params.yaml           模型推理参数（temp/top_p）│
  │    pipeline.yaml               Pipeline 运行参数         │
  │    http_client.yaml            HTTP 客户端参数           │
  │    paths.yaml                  路径与输出                │
  ├─────────────────────────────────────────────────────────┤
  │  config/config.yaml          ← 架构级配置（攻击映射等）  │
  │  config/owasp_mapping.yaml   ← 可选用户覆盖（高优先级） │
  │  config/payload_strategy_matrix.yaml ← 可选用户覆盖      │
  ├─────────────────────────────────────────────────────────┤
  │  src/core/defaults/          ← 系统默认配置（不可变）    │
  │    owasp_mapping.yaml          OWASP 标准定义（官方）     │
  │    payload_strategy_matrix.yaml  攻击策略矩阵（系统级）  │
  └─────────────────────────────────────────────────────────┘

加载优先级：.env > config/defaults/ > config/config.yaml > src/core/defaults/

设计原则：
  - .env 只放用户每次必改的参数（URL / API Key / 认证）
  - config/defaults/ 放调优过的默认值（temperature=0、超时等）
  - config/config.yaml 放架构级配置（攻击技术映射、端点探测）
  - src/core/defaults/ 放系统级配置（OWASP 标准、策略矩阵），防止误改/误删
"""

import os
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

# ============================================================
# 路径常量
# ============================================================

# src/core/ 目录（本文件所在目录）
_CORE_DIR = Path(__file__).parent

# 系统默认配置目录（打包在包内，不可误删）
_DEFAULTS_DIR = _CORE_DIR / "defaults"

# 项目根目录
_PROJECT_ROOT = _CORE_DIR.parent.parent

# 用户配置目录
_CONFIG_DIR = _PROJECT_ROOT / "config"


# ============================================================
# 配置加载器类
# ============================================================


class ConfigLoader:
    """配置加载器 - 分层加载 YAML 配置文件

    加载策略：
      1. 用户配置 (config/*.yaml) — 多文件合并加载
         config.yaml → target.yaml → ai_types.yaml → datasets.yaml
      2. 调优默认值 (config/defaults/*.yaml) — 独立加载
      3. 系统级配置 (owasp_mapping.yaml / payload_strategy_matrix.yaml) —
         优先从 config/ 加载用户覆盖，回退到 src/core/defaults/ 系统默认
    """

    def __init__(self, config_dir: Optional[Path] = None):
        """
        初始化配置加载器

        Args:
            config_dir: 用户配置文件目录，默认为项目根目录的 config/ 子目录
        """
        if config_dir is None:
            config_dir = _CONFIG_DIR

        self.config_dir = Path(config_dir)
        self.config_dir.mkdir(parents=True, exist_ok=True)

        # 系统默认配置目录（打包在 src/core/defaults/ 内）
        self.defaults_dir = _DEFAULTS_DIR

        # 用户调优默认值目录（config/defaults/，可编辑覆盖）
        self.user_defaults_dir = self.config_dir / "defaults"

        # 用户可调配置文件路径（始终从 config/ 加载）
        self.config_file = self.config_dir / "runtime.yaml"

        # 系统级配置文件路径（支持用户覆盖）
        # 优先级：config/ 下同名文件 > src/core/defaults/ 下系统默认
        self.owasp_file = self._resolve_config_path("owasp_mapping.yaml")
        self.strategy_file = self._resolve_config_path("payload_strategy_matrix.yaml")

        # 缓存
        self._global_config: Optional[Dict[str, Any]] = None
        self._owasp_config: Optional[Dict[str, Any]] = None
        self._strategy_config: Optional[Dict[str, Any]] = None
        self._defaults_cache: Dict[str, Dict[str, Any]] = {}

    # -----------------------------------------------------------------
    # 路径解析（核心：系统默认 + 用户覆盖）
    # -----------------------------------------------------------------

    def _resolve_config_path(self, filename: str) -> Path:
        """
        解析配置文件路径 — 用户覆盖优先，回退系统默认

        查找顺序：
          1. config/<filename>          — 用户覆盖（如果存在）
          2. src/core/defaults/<filename> — 系统默认（打包在包内）

        Args:
            filename: 配置文件名，如 "owasp_mapping.yaml"

        Returns:
            实际加载的文件路径

        Raises:
            FileNotFoundError: 系统默认文件也不存在（不应发生）
        """
        # 1. 检查用户覆盖
        user_override = self.config_dir / filename
        if user_override.exists():
            return user_override

        # 2. 回退系统默认
        system_default = self.defaults_dir / filename
        if system_default.exists():
            return system_default

        # 系统默认也不存在 — 这是异常状态
        raise FileNotFoundError(
            f"配置文件不存在且无系统默认: {filename}\n"
            f"  用户覆盖路径: {user_override}\n"
            f"  系统默认路径: {system_default}"
        )

    def _load_yaml(self, file_path: Path) -> Dict[str, Any]:
        """加载 YAML 文件（内部工具方法）"""
        with open(file_path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f)

    # -----------------------------------------------------------------
    # 全局配置加载
    # -----------------------------------------------------------------

    # 拆分配置文件列表（按加载顺序，后加载的覆盖先加载的同名键）
    _SPLIT_CONFIG_FILES = [
        "runtime.yaml",           # 运行时：global / exam / pyrit / report
        "targets/endpoints.yaml",   # 公共端点定义（唯一定义源）
        "targets/ai_types.yaml",     # AI 类型识别规则（引用端点名）
        "targets/connection.yaml",   # 目标连接：认证 / target / attack_mapping
        # data_sources.yaml 已移除：默认值融入代码，.env 仍可覆盖
    ]

    def load_global_config(self) -> Dict[str, Any]:
        """
        加载全局配置 — 多文件合并

        按顺序加载并合并 config/ 下的拆分配置文件：
          1. runtime.yaml             — 运行时参数 (global / exam / pyrit / report)
          2. targets/endpoints.yaml    — 公共端点定义（唯一定义源）
          3. targets/ai_types.yaml      — AI 类型识别规则 (列表格式，引用端点名)
          4. targets/connection.yaml     — 目标连接配置 (auth / target / attack_mapping)

        数据源默认值已融入代码（原 data_sources.yaml），.env 仍可覆盖。

        后加载的文件中同名顶层键会覆盖先加载的（但实际拆分已避免键冲突）。
        缺失的文件跳过（向后兼容旧版单文件配置）。

        Returns:
            合并后的全局配置字典
        """
        if self._global_config is not None:
            return self._global_config

        merged: Dict[str, Any] = {}

        for filename in self._SPLIT_CONFIG_FILES:
            file_path = self.config_dir / filename
            if file_path.exists():
                partial = self._load_yaml(file_path)
                if partial and isinstance(partial, dict):
                    merged.update(partial)

        # runtime.yaml 至少必须存在
        if not (self.config_dir / "runtime.yaml").exists():
            raise FileNotFoundError(f"运行时配置文件不存在: {self.config_file}")

        self._global_config = merged
        return self._global_config

    def get_global_config(self) -> Dict[str, Any]:
        """获取全局配置（带缓存）"""
        return self.load_global_config()

    def get_global_value(self, *keys: str, default: Any = None) -> Any:
        """
        从全局配置获取嵌套值

        Args:
            *keys: 配置键路径，如 ("pyrit", "memory_db_type")
            default: 默认值

        Returns:
            配置值，如果不存在则返回默认值
        """
        config = self.get_global_config()
        value = config
        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return default
        return value

    # -----------------------------------------------------------------
    # OWASP 配置加载（系统默认 + 可选用户覆盖）
    # -----------------------------------------------------------------

    def load_owasp_config(self) -> Dict[str, Any]:
        """
        加载 OWASP 映射配置

        加载优先级：
          1. config/owasp_mapping.yaml（用户覆盖，如果存在）
          2. src/core/defaults/owasp_mapping.yaml（系统默认）

        Returns:
            OWASP 配置字典
        """
        if self._owasp_config is not None:
            return self._owasp_config

        if not self.owasp_file.exists():
            raise FileNotFoundError(f"OWASP 配置文件不存在: {self.owasp_file}")

        self._owasp_config = self._load_yaml(self.owasp_file)

        return self._owasp_config

    def get_owasp_config(self) -> Dict[str, Any]:
        """获取 OWASP 配置（带缓存）"""
        return self.load_owasp_config()

    def get_owasp_mapping(self) -> Dict[str, List[str]]:
        """获取攻击类型到 OWASP 的映射（LLM + Agentic AI）"""
        return self.get_owasp_config().get("attack_to_owasp", {})

    def get_owasp_llm_top_10(self) -> Dict[str, Dict[str, Any]]:
        """
        获取 OWASP Top 10 for LLM Applications 2025 定义

        Returns:
            OWASP LLM Top 10 (2025版) 字典，键为 LLM01-LLM10
        """
        return self.get_owasp_config().get("owasp_llm_top_10", {})

    def get_owasp_asi_top_10(self) -> Dict[str, Dict[str, Any]]:
        """
        获取 OWASP Top 10 for Agentic AI 定义

        Returns:
            OWASP Agentic AI Top 10 字典，键为 ASI01-ASI10
        """
        return self.get_owasp_config().get("owasp_asi_top_10", {})

    def get_all_owasp_standards(self) -> Dict[str, Dict[str, Any]]:
        """
        获取所有 OWASP 安全标准定义（LLM Top 10 + Agentic AI Top 10）

        Returns:
            合并后的 OWASP 字典，包含 LLM01-LLM10 和 ASI01-ASI10
        """
        llm_top_10 = self.get_owasp_llm_top_10()
        asi_top_10 = self.get_owasp_asi_top_10()
        return {**llm_top_10, **asi_top_10}

    def get_owasp_details(self, owasp_id: str) -> Optional[Dict[str, Any]]:
        """
        获取特定 OWASP 漏洞的详细信息

        支持两种 ID 格式：
        - LLM01-LLM10: OWASP Top 10 for LLM Applications 2025
        - ASI01-ASI10: OWASP Top 10 for Agentic AI

        Args:
            owasp_id: OWASP ID，如 "LLM01" 或 "ASI01"

        Returns:
            OWASP 漏洞详细信息字典，如果不存在则返回 None
        """
        all_standards = self.get_all_owasp_standards()
        return all_standards.get(owasp_id)

    # -----------------------------------------------------------------
    # 策略矩阵配置加载（系统默认 + 可选用户覆盖）
    # -----------------------------------------------------------------

    def load_strategy_config(self) -> Dict[str, Any]:
        """
        加载载荷策略矩阵配置

        加载优先级：
          1. config/payload_strategy_matrix.yaml（用户覆盖，如果存在）
          2. src/core/defaults/payload_strategy_matrix.yaml（系统默认）

        Returns:
            策略矩阵配置字典
        """
        if self._strategy_config is not None:
            return self._strategy_config

        if not self.strategy_file.exists():
            raise FileNotFoundError(f"策略矩阵配置文件不存在: {self.strategy_file}")

        self._strategy_config = self._load_yaml(self.strategy_file)

        return self._strategy_config

    def get_strategy_config(self) -> Dict[str, Any]:
        """获取策略矩阵配置（带缓存）"""
        return self.load_strategy_config()

    def get_ai_type_to_scenario_mapping(self) -> Dict[str, List[str]]:
        """获取 AI 系统类型到 Scenario 的映射"""
        return self.get_strategy_config().get("ai_type_to_scenario", {})

    def get_scenario_matrix(self) -> Dict[str, Dict[str, Any]]:
        """获取 Scenario 详细配置矩阵"""
        return self.get_strategy_config().get("scenario_matrix", {})

    def get_scenario_config(self, scenario_name: str) -> Optional[Dict[str, Any]]:
        """
        获取特定 Scenario 的配置

        Args:
            scenario_name: Scenario 名称，如 "airt.jailbreak"

        Returns:
            Scenario 配置字典，如果不存在则返回 None
        """
        return self.get_scenario_matrix().get(scenario_name)

    def get_capability_to_scenario_mapping(self) -> Dict[str, List[str]]:
        """获取能力到 Scenario 的映射"""
        return self.get_strategy_config().get("capability_to_scenario", {})

    def get_converter_chains(self) -> Dict[str, Dict[str, Any]]:
        """获取 Converter 链配置"""
        return self.get_strategy_config().get("converter_chains", {})

    def get_converter_chain_config(self, chain_name: str) -> Optional[Dict[str, Any]]:
        """
        获取特定 Converter 链的配置

        Args:
            chain_name: 链名称，如 "stealth_evasion"

        Returns:
            Converter 链配置字典，如果不存在则返回 None
        """
        return self.get_converter_chains().get(chain_name)

    def get_scorer_selection(self) -> Dict[str, List[str]]:
        """获取 Scorer 选择配置"""
        return self.get_strategy_config().get("scorer_selection", {})

    def get_scorers_for_type(self, scorer_type: str) -> List[str]:
        """
        获取特定攻击类型的推荐 Scorer

        Args:
            scorer_type: 评分器类型，如 "leakage_detection"

        Returns:
            Scorer 类名列表
        """
        return self.get_scorer_selection().get(scorer_type, [])

    def get_attack_techniques_config(self) -> Dict[str, Dict[str, Any]]:
        """获取 Attack 技术配置"""
        return self.get_strategy_config().get("attack_techniques", {})

    def get_attack_technique_config(self, technique_name: str) -> Optional[Dict[str, Any]]:
        """
        获取特定 Attack 技术的配置

        Args:
            technique_name: 技术名称，如 "prompt_sending"

        Returns:
            Attack 技术配置字典，如果不存在则返回 None
        """
        return self.get_attack_techniques_config().get(technique_name)

    def get_owasp_strategy_map(self) -> Dict[str, Dict[str, Any]]:
        """
        获取 OWASP ID → 完整策略自动匹配映射表

        每个 OWASP ID 包含：
        - scorer_type: 评分器类型
        - default_attack_mode: 默认攻击模式
        - default_attack_technique: 默认攻击技术
        - recommended_converter_chains: 推荐 Converter 链列表
        - upgrade_techniques: 升级技术列表

        Returns:
            OWASP 策略映射字典
        """
        return self.get_strategy_config().get("owasp_strategy_map", {})

    def get_owasp_strategy(self, owasp_id: str) -> Optional[Dict[str, Any]]:
        """
        获取特定 OWASP ID 的策略配置

        Args:
            owasp_id: OWASP ID，如 "LLM01" 或 "ASI05"

        Returns:
            策略配置字典，如果不存在则返回 None
        """
        return self.get_owasp_strategy_map().get(owasp_id)

    def get_technique_hint_map(self) -> Dict[str, str]:
        """
        获取技术提示到攻击技术的映射表

        Returns:
            technique_hint → attack_technique 映射字典
        """
        return self.get_strategy_config().get("technique_hint_map", {})

    # -----------------------------------------------------------------
    # 特定配置查询方法
    # -----------------------------------------------------------------

    def get_supported_endpoints(self) -> List[str]:
        """获取支持的端点列表"""
        # 优先从 endpoints.yaml 的 supported_endpoints 读取
        endpoints = self.get_global_value("supported_endpoints", default=None)
        if endpoints and isinstance(endpoints, list):
            return endpoints
        # 回退：从 target.supported_endpoints 读取（向后兼容）
        return self.get_global_value("target", "supported_endpoints", default=[])

    def get_ai_type_detection_rules(self) -> Dict[str, Dict[str, Any]]:
        """
        获取 AI 系统类型识别规则

        兼容三种格式：
        - 列表+端点名（新）：ai_types.yaml 中的 ai_types 列表，
          每项含 endpoint_names 引用 endpoints.yaml 中 endpoints 段的 key
        - 列表+端点路径（旧）：ai_types 列表，每项含 endpoint_patterns 直接路径
        - 字典格式（最旧）：config.yaml 中的 ai_type_detection 字典

        Returns:
            AI 系统类型名 → 配置字典的映射（endpoint_names 已解析为 endpoint_patterns）
        """
        # 优先列表格式（ai_types.yaml）
        raw = self.get_global_value("ai_types", default=None)
        if isinstance(raw, list):
            # 获取端点名→路径映射表
            endpoint_map = self.get_global_value("endpoints", default={})

            result = {}
            for item in raw:
                if not isinstance(item, dict) or "name" not in item:
                    continue
                item_copy = dict(item)

                # 将 endpoint_names 解析为 endpoint_patterns（实际路径）
                names = item_copy.pop("endpoint_names", None)
                if names and isinstance(names, list) and endpoint_map:
                    item_copy["endpoint_patterns"] = [
                        endpoint_map[name]
                        for name in names
                        if name in endpoint_map
                    ]

                result[item_copy["name"]] = item_copy
            return result

        # 回退字典格式（向后兼容旧 config.yaml）
        legacy = self.get_global_value("ai_type_detection", default={})
        if isinstance(legacy, dict):
            return legacy

        return {}

    def get_ai_type_config(self, ai_type: str) -> Optional[Dict[str, Any]]:
        """
        获取特定 AI 系统类型的配置

        Args:
            ai_type: AI 系统类型，如 "llm", "multi_agent"

        Returns:
            AI 系统类型配置字典，如果不存在则返回 None
        """
        return self.get_ai_type_detection_rules().get(ai_type)

    def is_pyrit_attackable(self, ai_type: str) -> bool:
        """
        判断特定 AI 系统类型是否可用 PyRIT 攻击

        Args:
            ai_type: AI 系统类型，如 "llm", "multi_agent"

        Returns:
            是否可用 PyRIT 攻击
        """
        config = self.get_ai_type_config(ai_type)
        if config is None:
            return False
        return config.get("pyrit_attackable", False)

    def get_recommended_attacks(self, ai_type: str) -> List[str]:
        """
        获取特定 AI 系统类型的推荐攻击技术

        Args:
            ai_type: AI 系统类型，如 "llm", "multi_agent"

        Returns:
            推荐的 Attack 类名列表
        """
        config = self.get_ai_type_config(ai_type)
        if config is None:
            return []
        return config.get("recommended_attacks", [])

    def get_external_tools(self, ai_type: str) -> List[str]:
        """
        获取特定 AI 系统类型的外部工具推荐

        Args:
            ai_type: AI 系统类型，如 "embeddings", "infrastructure"

        Returns:
            外部工具名称列表
        """
        config = self.get_ai_type_config(ai_type)
        if config is None:
            return []
        return config.get("external_tools", [])

    def get_pyrit_config(self) -> Dict[str, Any]:
        """获取 PyRIT 配置"""
        return self.get_global_value("pyrit", default={})

    def get_memory_db_type(self) -> str:
        """获取 Memory 后端类型"""
        return self.get_global_value("pyrit", "memory_db_type", default="SQLite")

    def get_db_path(self) -> str:
        """获取数据库文件路径"""
        return self.get_global_value("pyrit", "db_path", default="output/db/exam_results.db")

    def get_evidence_dir(self) -> str:
        """获取证据输出目录"""
        return self.get_global_value("pyrit", "evidence_dir", default="output/evidence")

    def get_logs_dir(self) -> str:
        """获取日志输出目录"""
        return self.get_global_value("pyrit", "logs_dir", default="output/logs")

    def get_max_concurrency(self) -> int:
        """获取最大并发数"""
        return self.get_global_value("global", "max_concurrent_attacks", default=4)

    def get_timeout(self) -> int:
        """获取超时时间（秒）"""
        return self.get_global_value("global", "timeout", default=300)

    def get_request_interval_ms(self) -> int:
        """获取请求间隔（毫秒）"""
        return self.get_global_value("global", "request_interval_ms", default=2000)

    def get_exam_config(self) -> Dict[str, Any]:
        """获取考试模式配置"""
        return self.get_global_value("exam", default={})

    def is_exam_mode_enabled(self) -> bool:
        """判断考试模式是否启用"""
        return self.get_global_value("exam", "enabled", default=False)

    def get_exam_duration_hours(self) -> int:
        """获取考试时长（小时）"""
        return self.get_global_value("exam", "duration_hours", default=24)

    # -----------------------------------------------------------------
    # 数据源配置 (批量多源攻击)
    # -----------------------------------------------------------------
    # 原配置已从 data_sources.yaml 融入代码，以下为硬编码默认值。
    # .env 环境变量仍可覆盖（如 INTERACTIVE_SELECTION、REMOTE_DATASETS_ENABLED 等）。
    # -----------------------------------------------------------------

    # 数据源硬编码默认值
    _DS_OWASP_ENABLED = True
    _DS_OWASP_BASE_PATH = "data/owasp"
    _DS_OWASP_FRAMEWORKS = ["llm", "agentic"]
    _DS_CUSTOM_ENABLED = True
    _DS_CUSTOM_PATH = "data/custom"
    _DS_REMOTE_ENABLED = False
    _DS_REMOTE_MAX_CONCURRENCY = 3
    _DS_REMOTE_CACHE = True
    _DS_TEXT_JAILBREAK_ENABLED = False
    _DS_TEXT_JAILBREAK_TEMPLATE = ""
    _DS_TEXT_JAILBREAK_RANDOM = False
    _DS_SIM_CONV_ENABLED = False
    _DS_SIM_CONV_TURNS = 3
    _DS_INTERACTIVE_AUTO_SELECT = True
    _DS_INTERACTIVE_PAGE_SIZE = 20

    def get_payload_sources_config(self) -> Dict[str, Any]:
        """获取数据源配置（从遗留 YAML 或硬编码默认值）"""
        return self.get_global_value("payload_sources", default={})

    def get_owasp_source_config(self) -> Dict[str, Any]:
        """获取 OWASP 目录数据源配置"""
        return self.get_payload_sources_config().get("owasp", {})

    def is_owasp_source_enabled(self) -> bool:
        """OWASP 数据源是否启用"""
        return self.get_owasp_source_config().get("enabled", self._DS_OWASP_ENABLED)

    def get_owasp_source_base_path(self) -> str:
        """获取 OWASP 数据源根路径"""
        return self.get_owasp_source_config().get("base_path", self._DS_OWASP_BASE_PATH)

    def get_owasp_source_frameworks(self) -> List[str]:
        """获取 OWASP 数据源启用的框架列表"""
        return self.get_owasp_source_config().get("frameworks", self._DS_OWASP_FRAMEWORKS)

    def get_owasp_source_ids(self) -> List[str]:
        """获取指定的 OWASP ID 列表（空 = 全部）"""
        return self.get_owasp_source_config().get("owasp_ids", [])

    def get_owasp_exclude_ids(self) -> List[str]:
        """获取排除的 OWASP ID 列表"""
        return self.get_owasp_source_config().get("exclude_ids", [])

    def is_custom_source_enabled(self) -> bool:
        """自定义数据源是否启用"""
        return self.get_payload_sources_config().get("custom", {}).get("enabled", self._DS_CUSTOM_ENABLED)

    def get_custom_source_path(self) -> str:
        """获取自定义数据源路径"""
        return self.get_payload_sources_config().get("custom", {}).get("path", self._DS_CUSTOM_PATH)

    # -----------------------------------------------------------------
    # 远程数据集配置 (PyRIT 1.0.0 SeedDatasetProvider)
    # -----------------------------------------------------------------

    def get_remote_datasets_config(self) -> Dict[str, Any]:
        """获取远程数据集配置"""
        return self.get_payload_sources_config().get("remote", {})

    def is_remote_datasets_enabled(self) -> bool:
        """远程数据集是否启用"""
        return self.get_remote_datasets_config().get("enabled", self._DS_REMOTE_ENABLED)

    def get_remote_dataset_names(self) -> List[str]:
        """获取指定的远程数据集名称列表（空 = 全部）"""
        return self.get_remote_datasets_config().get("datasets", [])

    def get_remote_max_concurrency(self) -> int:
        """获取远程加载并发数"""
        return self.get_remote_datasets_config().get("max_concurrency", self._DS_REMOTE_MAX_CONCURRENCY)

    def is_remote_cache_enabled(self) -> bool:
        """远程数据集是否使用缓存"""
        return self.get_remote_datasets_config().get("cache", self._DS_REMOTE_CACHE)

    # -----------------------------------------------------------------
    # TextJailBreak 模板包装配置 (可选，用于增强单轮提示词)
    # -----------------------------------------------------------------

    def get_text_jailbreak_config(self) -> Dict[str, Any]:
        """获取 TextJailBreak 模板包装配置"""
        return self.get_payload_sources_config().get("text_jailbreak", {})

    def is_text_jailbreak_enabled(self) -> bool:
        """TextJailBreak 模板包装是否启用"""
        return self.get_text_jailbreak_config().get("enabled", self._DS_TEXT_JAILBREAK_ENABLED)

    def get_text_jailbreak_template(self) -> str:
        """获取指定的 TextJailBreak 模板文件名"""
        return self.get_text_jailbreak_config().get("template_file", self._DS_TEXT_JAILBREAK_TEMPLATE)

    def is_text_jailbreak_random(self) -> bool:
        """是否随机选择 TextJailBreak 模板"""
        return self.get_text_jailbreak_config().get("random", self._DS_TEXT_JAILBREAK_RANDOM)

    # 向后兼容别名（旧代码可能仍调用 get_jailbreak_* 方法）
    def is_jailbreak_enabled(self) -> bool:
        """向后兼容: 等同于 is_text_jailbreak_enabled()"""
        return self.is_text_jailbreak_enabled()

    def get_jailbreak_template(self) -> str:
        """向后兼容: 等同于 get_text_jailbreak_template()"""
        return self.get_text_jailbreak_template()

    def is_jailbreak_random(self) -> bool:
        """向后兼容: 等同于 is_text_jailbreak_random()"""
        return self.is_text_jailbreak_random()

    # -----------------------------------------------------------------
    # DatasetManager 配置 (CentralMemory 五层架构)
    # -----------------------------------------------------------------
    # 原配置已从 data_sources.yaml 融入代码。
    # DatasetManager 方法委托 payload_sources 同等方法（消除重复）。
    # -----------------------------------------------------------------

    def get_dataset_manager_config(self) -> Dict[str, Any]:
        """获取 DatasetManager 配置（委托 payload_sources，消除重复）"""
        return self.get_payload_sources_config()

    def get_dataset_manager_owasp_config(self) -> Dict[str, Any]:
        """获取 DatasetManager OWASP 配置（委托 payload_sources）"""
        return self.get_owasp_source_config()

    def get_dataset_manager_custom_config(self) -> Dict[str, Any]:
        """获取 DatasetManager 自定义载荷配置（委托 payload_sources）"""
        custom = self.get_payload_sources_config().get("custom", {})
        return custom if custom else {"enabled": self._DS_CUSTOM_ENABLED}

    def get_dataset_manager_remote_config(self) -> Dict[str, Any]:
        """获取 DatasetManager 远程数据集配置（委托 payload_sources）"""
        return self.get_remote_datasets_config()

    def get_interactive_selection_config(self) -> Dict[str, Any]:
        """获取 ②.5 交互式选择层配置（硬编码默认值 + 遗留 YAML 覆盖）"""
        defaults = {
            "enabled": True,
            "auto_select_if_single": self._DS_INTERACTIVE_AUTO_SELECT,
            "page_size": self._DS_INTERACTIVE_PAGE_SIZE,
        }
        legacy = self.get_global_value("dataset_manager", default={}).get("interactive_selection", {})
        if legacy:
            defaults.update(legacy)
        return defaults

    # -----------------------------------------------------------------
    # Simulated Conversation 配置 (PyRIT 1.0.0 SeedSimulatedConversation)
    # -----------------------------------------------------------------

    def get_simulated_conversation_config(self) -> Dict[str, Any]:
        """获取模拟对话配置（SeedSimulatedConversation）"""
        return self.get_payload_sources_config().get("simulated_conversation", {})

    def is_simulated_conversation_enabled(self) -> bool:
        """是否启用模拟对话"""
        return self.get_simulated_conversation_config().get("enabled", self._DS_SIM_CONV_ENABLED)

    def get_simulated_conversation_default_turns(self) -> int:
        """获取模拟对话默认轮数"""
        return self.get_simulated_conversation_config().get("default_turns", self._DS_SIM_CONV_TURNS)

    # -----------------------------------------------------------------
    # SeedDatasetFilter 集成 (PyRIT 1.0.0 数据集发现)
    # -----------------------------------------------------------------

    async def discover_datasets_by_filter_async(
        self,
        tags: Optional[set] = None,
        size: Optional[set] = None,
        modalities: Optional[set] = None,
        source_type: Optional[set] = None,
        strict_match: bool = False,
    ) -> List[str]:
        """
        使用 PyRIT 1.0.0 SeedDatasetFilter 发现数据集

        通过元数据过滤发现所有已注册的数据集（包括 OWASP 本地和远程），
        返回匹配的数据集名称列表。

        Args:
            tags: 标签过滤（如 {"safety", "prompt_injection"}）
            size: 大小过滤（如 {"small", "medium"}）
            modalities: 模态过滤（如 {"text"}）
            source_type: 来源类型过滤（如 {"local", "remote"}）
            strict_match: 是否严格匹配（AND vs OR）

        Returns:
            匹配的数据集名称列表
        """
        try:
            from pyrit.datasets import SeedDatasetFilter, SeedDatasetProvider
        except ImportError:
            return []

        # 构建 filter kwargs
        filter_kwargs: Dict[str, Any] = {"strict_match": strict_match}
        if tags:
            filter_kwargs["tags"] = tags
        if size:
            filter_kwargs["size"] = size
        if modalities:
            filter_kwargs["modalities"] = modalities
        if source_type:
            filter_kwargs["source_type"] = source_type

        filters = SeedDatasetFilter(**filter_kwargs)
        return await SeedDatasetProvider.get_all_dataset_names_async(filters)

    async def discover_owasp_datasets_async(self) -> List[str]:
        """
        发现所有已注册的 OWASP 本地数据集

        Returns:
            OWASP 数据集名称列表
        """
        return await self.discover_datasets_by_filter_async(
            source_type={"local"},
            tags={"safety", "prompt_injection", "agent_security"},
        )

    # -----------------------------------------------------------------
    # 批量执行配置
    # -----------------------------------------------------------------

    def get_batch_execution_config(self) -> Dict[str, Any]:
        """获取批量执行配置"""
        return self.get_global_value("batch_execution", default={})

    def get_batch_max_concurrency(self) -> int:
        """获取批量执行最大并发数"""
        return self.get_batch_execution_config().get("max_concurrency", 4)

    def is_batch_fail_fast(self) -> bool:
        """批量执行是否快速失败"""
        return self.get_batch_execution_config().get("fail_fast", False)

    def get_batch_per_attack_timeout(self) -> int:
        """获取单次攻击超时（秒）"""
        return self.get_batch_execution_config().get("per_attack_timeout", 300)

    def get_batch_timeout_overrides(self) -> Dict[str, int]:
        """
        获取按攻击模式差异化的超时配置

        Returns:
            攻击模式到超时秒数的映射字典，如 {"single_turn": 90, "multi_turn": 300}
            如果未配置则返回空字典，调用方应回退到 per_attack_timeout
        """
        return self.get_batch_execution_config().get("timeout_overrides", {})

    # -----------------------------------------------------------------
    # config/defaults/ 调优默认值加载
    # -----------------------------------------------------------------

    def _load_defaults_file(self, filename: str) -> Dict[str, Any]:
        """
        加载 config/defaults/ 下的 YAML 文件（带缓存）

        Args:
            filename: 文件名，如 "model_params.yaml"

        Returns:
            配置字典；文件不存在时返回空字典
        """
        if filename in self._defaults_cache:
            return self._defaults_cache[filename]

        file_path = self.user_defaults_dir / filename
        if file_path.exists():
            data = self._load_yaml(file_path)
        else:
            data = {}

        self._defaults_cache[filename] = data
        return data

    def get_model_params_defaults(self) -> Dict[str, Any]:
        """获取模型推理参数默认值 (config/defaults/model_params.yaml)"""
        return self._load_defaults_file("model_params.yaml")

    def get_pipeline_defaults(self) -> Dict[str, Any]:
        """获取 Pipeline 运行参数默认值 (config/defaults/pipeline.yaml)"""
        return self._load_defaults_file("pipeline.yaml")

    def get_http_client_defaults(self) -> Dict[str, Any]:
        """获取 HTTP 客户端参数默认值 (config/defaults/http_client.yaml)"""
        return self._load_defaults_file("http_client.yaml")

    def get_paths_defaults(self) -> Dict[str, Any]:
        """获取路径默认值 (config/defaults/paths.yaml)"""
        return self._load_defaults_file("paths.yaml")

    # --- 模型参数查询（.env > config/defaults/ > 硬编码兜底）---

    def get_target_temperature(self) -> Optional[float]:
        """获取目标模型 temperature（.env TARGET_TEMPERATURE > defaults > null）"""
        env_val = os.getenv("TARGET_TEMPERATURE")
        if env_val is not None and env_val.strip():
            return float(env_val)
        return self.get_model_params_defaults().get("target", {}).get("temperature")

    def get_target_top_p(self) -> Optional[float]:
        """获取目标模型 top_p（.env TARGET_TOP_P > defaults > null）"""
        env_val = os.getenv("TARGET_TOP_P")
        if env_val is not None and env_val.strip():
            return float(env_val)
        return self.get_model_params_defaults().get("target", {}).get("top_p")

    def get_target_max_completion_tokens(self) -> Optional[int]:
        """获取目标模型 max_completion_tokens"""
        env_val = os.getenv("TARGET_MAX_COMPLETION_TOKENS")
        if env_val is not None and env_val.strip():
            return int(env_val)
        return self.get_model_params_defaults().get("target", {}).get("max_completion_tokens")

    def get_target_max_output_tokens(self) -> Optional[int]:
        """获取目标模型 max_output_tokens (Responses API)"""
        env_val = os.getenv("TARGET_MAX_OUTPUT_TOKENS")
        if env_val is not None and env_val.strip():
            return int(env_val)
        return self.get_model_params_defaults().get("target", {}).get("max_output_tokens")

    def get_target_reasoning_effort(self) -> Optional[str]:
        """获取目标模型 reasoning_effort"""
        env_val = os.getenv("TARGET_REASONING_EFFORT")
        if env_val is not None and env_val.strip():
            return env_val
        return self.get_model_params_defaults().get("target", {}).get("reasoning_effort")

    def get_target_reasoning_summary(self) -> Optional[str]:
        """获取目标模型 reasoning_summary"""
        env_val = os.getenv("TARGET_REASONING_SUMMARY")
        if env_val is not None and env_val.strip():
            return env_val
        return self.get_model_params_defaults().get("target", {}).get("reasoning_summary")

    def get_target_frequency_penalty(self) -> Optional[float]:
        """获取目标模型 frequency_penalty"""
        env_val = os.getenv("TARGET_FREQUENCY_PENALTY")
        if env_val is not None and env_val.strip():
            return float(env_val)
        return self.get_model_params_defaults().get("target", {}).get("frequency_penalty")

    def get_target_presence_penalty(self) -> Optional[float]:
        """获取目标模型 presence_penalty"""
        env_val = os.getenv("TARGET_PRESENCE_PENALTY")
        if env_val is not None and env_val.strip():
            return float(env_val)
        return self.get_model_params_defaults().get("target", {}).get("presence_penalty")

    def get_target_seed(self) -> Optional[int]:
        """获取目标模型 seed"""
        env_val = os.getenv("TARGET_SEED")
        if env_val is not None and env_val.strip():
            return int(env_val)
        return self.get_model_params_defaults().get("target", {}).get("seed")

    def get_judge_temperature(self) -> float:
        """获取评分器 temperature（默认 0 确保评分一致）"""
        env_val = os.getenv("JUDGE_TEMPERATURE")
        if env_val is not None and env_val.strip():
            return float(env_val)
        return self.get_model_params_defaults().get("judge", {}).get("temperature", 0.0)

    def get_judge_top_p(self) -> float:
        """获取评分器 top_p"""
        env_val = os.getenv("JUDGE_TOP_P")
        if env_val is not None and env_val.strip():
            return float(env_val)
        return self.get_model_params_defaults().get("judge", {}).get("top_p", 1.0)

    def get_judge_force_json_output(self) -> bool:
        """评分器是否强制 JSON 输出"""
        env_val = os.getenv("JUDGE_FORCE_JSON_OUTPUT")
        if env_val is not None and env_val.strip():
            return env_val.lower() in ("1", "true", "yes")
        return self.get_model_params_defaults().get("judge", {}).get("force_json_output", True)

    def get_adversarial_temperature(self) -> float:
        """获取对抗模型 temperature"""
        env_val = os.getenv("ADVERSARIAL_TEMPERATURE")
        if env_val is not None and env_val.strip():
            return float(env_val)
        return self.get_model_params_defaults().get("adversarial", {}).get("temperature", 0.7)

    def get_adversarial_top_p(self) -> float:
        """获取对抗模型 top_p"""
        env_val = os.getenv("ADVERSARIAL_TOP_P")
        if env_val is not None and env_val.strip():
            return float(env_val)
        return self.get_model_params_defaults().get("adversarial", {}).get("top_p", 0.95)

    # --- Pipeline 参数查询（.env > config/defaults/ > config.yaml > 硬编码）---

    def get_verbose(self) -> bool:
        """获取 verbose 模式（.env VERBOSE > defaults > false）"""
        env_val = os.getenv("VERBOSE")
        if env_val is not None and env_val.strip():
            return env_val.lower() in ("1", "true", "yes")
        return self.get_pipeline_defaults().get("verbose", False)

    def get_verbose_success(self) -> bool:
        """获取 verbose_success 模式（.env VERBOSE_SUCCESS > defaults > true）"""
        env_val = os.getenv("VERBOSE_SUCCESS")
        if env_val is not None and env_val.strip():
            return env_val.lower() in ("1", "true", "yes")
        return self.get_pipeline_defaults().get("verbose_success", True)

    def get_interactive_selection_enabled(self) -> bool:
        """获取交互式选择是否启用（.env INTERACTIVE_SELECTION > defaults > true）"""
        env_val = os.getenv("INTERACTIVE_SELECTION")
        if env_val is not None and env_val.strip():
            return env_val.lower() in ("1", "true", "yes")
        return self.get_pipeline_defaults().get("interactive_selection", True)

    def get_retry_max_attempts(self) -> int:
        """获取最大重试次数"""
        env_val = os.getenv("RETRY_MAX_NUM_ATTEMPTS")
        if env_val is not None and env_val.strip():
            return int(env_val)
        return self.get_pipeline_defaults().get("retry", {}).get("max_num_attempts", 3)

    def get_retry_wait_min(self) -> int:
        """获取重试最小等待秒数"""
        env_val = os.getenv("RETRY_WAIT_MIN_SECONDS")
        if env_val is not None and env_val.strip():
            return int(env_val)
        return self.get_pipeline_defaults().get("retry", {}).get("wait_min_seconds", 1)

    def get_retry_wait_max(self) -> int:
        """获取重试最大等待秒数"""
        env_val = os.getenv("RETRY_WAIT_MAX_SECONDS")
        if env_val is not None and env_val.strip():
            return int(env_val)
        return self.get_pipeline_defaults().get("retry", {}).get("wait_max_seconds", 10)

    def get_pipeline_max_concurrency(self) -> int:
        """获取 Pipeline 最大并发数（.env > config/defaults/ > config.yaml）

        兼容环境变量：BATCH_MAX_CONCURRENCY（CLI --concurrency）和 MAX_CONCURRENCY（.env）
        """
        # CLI --concurrency 优先设置 BATCH_MAX_CONCURRENCY
        env_val = os.getenv("BATCH_MAX_CONCURRENCY")
        if env_val is not None and env_val.strip():
            return int(env_val)
        env_val = os.getenv("MAX_CONCURRENCY")
        if env_val is not None and env_val.strip():
            return int(env_val)
        defaults_val = self.get_pipeline_defaults().get("max_concurrency")
        if defaults_val is not None:
            return int(defaults_val)
        return self.get_batch_max_concurrency()

    def get_pipeline_per_attack_timeout(self) -> int:
        """获取单次攻击超时（.env > defaults > config.yaml）"""
        env_val = os.getenv("BATCH_PER_ATTACK_TIMEOUT")
        if env_val is not None and env_val.strip():
            return int(env_val)
        defaults_val = self.get_pipeline_defaults().get("per_attack_timeout")
        if defaults_val is not None:
            return int(defaults_val)
        return self.get_batch_per_attack_timeout()

    def get_pipeline_timeout_overrides(self) -> Dict[str, int]:
        """获取差异化超时（defaults > config.yaml）"""
        defaults_val = self.get_pipeline_defaults().get("timeout_overrides")
        if defaults_val:
            return defaults_val
        return self.get_batch_timeout_overrides()

    def get_pipeline_fail_fast(self) -> bool:
        """获取 fail_fast（defaults > config.yaml）"""
        defaults_val = self.get_pipeline_defaults().get("fail_fast")
        if defaults_val is not None:
            return bool(defaults_val)
        return self.is_batch_fail_fast()

    def get_scenario_max_retries(self) -> int:
        """
        获取 Scenario 级别重试次数（高层工作流弫性恢复）

        优先级：.env SCENARIO_MAX_RETRIES > config/defaults/pipeline.yaml > 0

        Returns:
            Scenario 最大重试次数（0=快速失败，3=弫性恢复）
        """
        env_val = os.getenv("SCENARIO_MAX_RETRIES")
        if env_val is not None and env_val.strip():
            return int(env_val)
        return self.get_pipeline_defaults().get("scenario_max_retries", 0)

    # --- HTTP 客户端参数查询（.env > config/defaults/ > 硬编码）---

    def get_target_httpx_timeout(self) -> int:
        """获取目标 HTTP 超时"""
        env_val = os.getenv("TARGET_HTTPX_TIMEOUT")
        if env_val is not None and env_val.strip():
            return int(env_val)
        return self.get_http_client_defaults().get("target", {}).get("timeout", 180)

    def get_target_httpx_verify(self) -> bool:
        """获取目标 SSL 验证"""
        env_val = os.getenv("TARGET_HTTPX_VERIFY")
        if env_val is not None and env_val.strip():
            return env_val.lower() in ("1", "true", "yes")
        return self.get_http_client_defaults().get("target", {}).get("verify", False)

    def get_target_httpx_proxy(self) -> Optional[str]:
        """获取目标代理 URL"""
        env_val = os.getenv("TARGET_HTTPX_PROXY")
        if env_val is not None and env_val.strip():
            return env_val
        return self.get_http_client_defaults().get("target", {}).get("proxy")

    def get_judge_httpx_timeout(self) -> int:
        """获取评分器 HTTP 超时"""
        env_val = os.getenv("JUDGE_HTTPX_TIMEOUT")
        if env_val is not None and env_val.strip():
            return int(env_val)
        return self.get_http_client_defaults().get("judge", {}).get("timeout", 120)

    def get_rate_limit_per_minute(self) -> Optional[int]:
        """获取速率限制"""
        env_val = os.getenv("TARGET_MAX_REQUESTS_PER_MINUTE")
        if env_val is not None and env_val.strip():
            return int(env_val)
        return self.get_http_client_defaults().get("rate_limit", {}).get("max_requests_per_minute")

    # --- 路径参数查询（.env > config/defaults/ > config.yaml）---

    def get_memory_db_path(self) -> str:
        """获取数据库路径（.env MEMORY_DB_PATH > defaults > config.yaml）"""
        env_val = os.getenv("MEMORY_DB_PATH")
        if env_val and env_val.strip():
            return env_val
        defaults_val = self.get_paths_defaults().get("memory", {}).get("db_path")
        if defaults_val:
            return defaults_val
        return self.get_db_path()

    def get_report_output_dir(self) -> str:
        """获取报告输出目录"""
        env_val = os.getenv("REPORT_OUTPUT_DIR")
        if env_val and env_val.strip():
            return env_val
        defaults_val = self.get_paths_defaults().get("report", {}).get("output_dir")
        if defaults_val:
            return defaults_val
        return self.get_global_value("report", "output_dir", default="output/reports")

    def get_evidence_output_dir(self) -> str:
        """获取证据输出目录"""
        env_val = os.getenv("EVIDENCE_DIR")
        if env_val and env_val.strip():
            return env_val
        defaults_val = self.get_paths_defaults().get("evidence_dir")
        if defaults_val:
            return defaults_val
        return self.get_evidence_dir()

    # -----------------------------------------------------------------
    # 缓存管理
    # -----------------------------------------------------------------

    def reload_config(self) -> None:
        """重新加载所有配置（清除缓存）"""
        self._global_config = None
        self._owasp_config = None
        self._strategy_config = None
        self._defaults_cache = {}

        # 重新解析路径（用户可能在此期间创建了覆盖文件）
        self.owasp_file = self._resolve_config_path("owasp_mapping.yaml")
        self.strategy_file = self._resolve_config_path("payload_strategy_matrix.yaml")


# ============================================================
# 全局配置加载器实例
# ============================================================

# 全局单例实例
_global_config_loader: Optional[ConfigLoader] = None


def get_config_loader() -> ConfigLoader:
    """
    获取全局配置加载器实例（单例模式）

    Returns:
        ConfigLoader 实例
    """
    global _global_config_loader
    if _global_config_loader is None:
        _global_config_loader = ConfigLoader()
    return _global_config_loader
