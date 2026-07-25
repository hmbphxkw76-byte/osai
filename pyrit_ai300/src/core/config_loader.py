"""
Config Loader
=============

本模块负责从 YAML 配置文件加载配置（遵循开发规则 1.4.2）。

所有配置从外部 YAML 文件读取，避免硬编码。
"""

from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

# ============================================================
# 配置加载器类
# ============================================================


class ConfigLoader:
    """配置加载器 - 从 YAML 文件加载配置"""

    def __init__(self, config_dir: Optional[Path] = None):
        """
        初始化配置加载器

        Args:
            config_dir: 配置文件目录，默认为项目根目录的 config/ 子目录
        """
        if config_dir is None:
            # 默认：项目根目录 / config
            project_root = Path(__file__).parent.parent.parent
            config_dir = project_root / "config"

        self.config_dir = Path(config_dir)
        self.config_dir.mkdir(parents=True, exist_ok=True)

        # 配置文件路径
        self.config_file = self.config_dir / "config.yaml"
        self.owasp_file = self.config_dir / "owasp_mapping.yaml"
        self.strategy_file = self.config_dir / "payload_strategy_matrix.yaml"

        # 缓存
        self._global_config: Optional[Dict[str, Any]] = None
        self._owasp_config: Optional[Dict[str, Any]] = None
        self._strategy_config: Optional[Dict[str, Any]] = None

    # -----------------------------------------------------------------
    # 全局配置加载
    # -----------------------------------------------------------------

    def load_global_config(self) -> Dict[str, Any]:
        """
        加载全局配置

        Returns:
            全局配置字典
        """
        if self._global_config is not None:
            return self._global_config

        if not self.config_file.exists():
            raise FileNotFoundError(f"配置文件不存在: {self.config_file}")

        with open(self.config_file, "r", encoding="utf-8") as f:
            self._global_config = yaml.safe_load(f)

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
    # OWASP 配置加载
    # -----------------------------------------------------------------

    def load_owasp_config(self) -> Dict[str, Any]:
        """
        加载 OWASP 映射配置

        Returns:
            OWASP 配置字典
        """
        if self._owasp_config is not None:
            return self._owasp_config

        if not self.owasp_file.exists():
            raise FileNotFoundError(f"OWASP 配置文件不存在: {self.owasp_file}")

        with open(self.owasp_file, "r", encoding="utf-8") as f:
            self._owasp_config = yaml.safe_load(f)

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
    # 策略矩阵配置加载
    # -----------------------------------------------------------------

    def load_strategy_config(self) -> Dict[str, Any]:
        """
        加载载荷策略矩阵配置

        Returns:
            策略矩阵配置字典
        """
        if self._strategy_config is not None:
            return self._strategy_config

        if not self.strategy_file.exists():
            raise FileNotFoundError(f"策略矩阵配置文件不存在: {self.strategy_file}")

        with open(self.strategy_file, "r", encoding="utf-8") as f:
            self._strategy_config = yaml.safe_load(f)

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
        return self.get_global_value("target", "supported_endpoints", default=[])

    def get_ai_type_detection_rules(self) -> Dict[str, Dict[str, Any]]:
        """获取 AI 系统类型识别规则"""
        return self.get_global_value("ai_type_detection", default={})

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

    def get_payload_sources_config(self) -> Dict[str, Any]:
        """获取数据源配置"""
        return self.get_global_value("payload_sources", default={})

    def get_owasp_source_config(self) -> Dict[str, Any]:
        """获取 OWASP 目录数据源配置"""
        return self.get_payload_sources_config().get("owasp", {})

    def is_owasp_source_enabled(self) -> bool:
        """OWASP 数据源是否启用"""
        return self.get_owasp_source_config().get("enabled", True)

    def get_owasp_source_base_path(self) -> str:
        """获取 OWASP 数据源根路径"""
        return self.get_owasp_source_config().get("base_path", "data/owasp")

    def get_owasp_source_frameworks(self) -> List[str]:
        """获取 OWASP 数据源启用的框架列表"""
        return self.get_owasp_source_config().get("frameworks", ["llm"])

    def get_owasp_source_ids(self) -> List[str]:
        """获取指定的 OWASP ID 列表（空 = 全部）"""
        return self.get_owasp_source_config().get("owasp_ids", [])

    def get_owasp_exclude_ids(self) -> List[str]:
        """获取排除的 OWASP ID 列表"""
        return self.get_owasp_source_config().get("exclude_ids", [])

    def is_custom_source_enabled(self) -> bool:
        """自定义数据源是否启用"""
        return self.get_payload_sources_config().get("custom", {}).get("enabled", True)

    def get_custom_source_path(self) -> str:
        """获取自定义数据源路径"""
        return self.get_payload_sources_config().get("custom", {}).get("path", "data/custom")

    # -----------------------------------------------------------------
    # 远程数据集配置 (PyRIT 1.0.0 SeedDatasetProvider)
    # -----------------------------------------------------------------

    def get_remote_datasets_config(self) -> Dict[str, Any]:
        """获取远程数据集配置"""
        return self.get_payload_sources_config().get("remote", {})

    def is_remote_datasets_enabled(self) -> bool:
        """远程数据集是否启用"""
        return self.get_remote_datasets_config().get("enabled", False)

    def get_remote_dataset_names(self) -> List[str]:
        """获取指定的远程数据集名称列表（空 = 全部）"""
        return self.get_remote_datasets_config().get("datasets", [])

    def get_remote_max_concurrency(self) -> int:
        """获取远程加载并发数"""
        return self.get_remote_datasets_config().get("max_concurrency", 3)

    def is_remote_cache_enabled(self) -> bool:
        """远程数据集是否使用缓存"""
        return self.get_remote_datasets_config().get("cache", True)

    # -----------------------------------------------------------------
    # TextJailBreak 模板包装配置 (可选，用于增强单轮提示词)
    # -----------------------------------------------------------------

    def get_text_jailbreak_config(self) -> Dict[str, Any]:
        """获取 TextJailBreak 模板包装配置"""
        return self.get_payload_sources_config().get("text_jailbreak", {})

    def is_text_jailbreak_enabled(self) -> bool:
        """TextJailBreak 模板包装是否启用"""
        return self.get_text_jailbreak_config().get("enabled", False)

    def get_text_jailbreak_template(self) -> str:
        """获取指定的 TextJailBreak 模板文件名"""
        return self.get_text_jailbreak_config().get("template_file", "")

    def is_text_jailbreak_random(self) -> bool:
        """是否随机选择 TextJailBreak 模板"""
        return self.get_text_jailbreak_config().get("random", False)

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

    def get_dataset_manager_config(self) -> Dict[str, Any]:
        """获取 DatasetManager 配置 (dataset_manager 配置段)"""
        return self.get_global_value("dataset_manager", default={})

    def get_dataset_manager_owasp_config(self) -> Dict[str, Any]:
        """获取 DatasetManager OWASP 配置"""
        return self.get_dataset_manager_config().get("owasp", {})

    def get_dataset_manager_custom_config(self) -> Dict[str, Any]:
        """获取 DatasetManager 自定义载荷配置"""
        return self.get_dataset_manager_config().get("custom", {})

    def get_dataset_manager_remote_config(self) -> Dict[str, Any]:
        """获取 DatasetManager 远程数据集配置"""
        return self.get_dataset_manager_config().get("remote", {})

    def get_interactive_selection_config(self) -> Dict[str, Any]:
        """获取 ②.5 交互式选择层配置"""
        return self.get_dataset_manager_config().get("interactive_selection", {})

    # -----------------------------------------------------------------
    # Simulated Conversation 配置 (PyRIT 1.0.0 SeedSimulatedConversation)
    # -----------------------------------------------------------------

    def get_simulated_conversation_config(self) -> Dict[str, Any]:
        """获取模拟对话配置（SeedSimulatedConversation）"""
        return self.get_payload_sources_config().get("simulated_conversation", {})

    def is_simulated_conversation_enabled(self) -> bool:
        """是否启用模拟对话"""
        return self.get_simulated_conversation_config().get("enabled", False)

    def get_simulated_conversation_default_turns(self) -> int:
        """获取模拟对话默认轮数"""
        return self.get_simulated_conversation_config().get("default_turns", 3)

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

    # -----------------------------------------------------------------
    # 缓存管理
    # -----------------------------------------------------------------

    def reload_config(self) -> None:
        """重新加载所有配置（清除缓存）"""
        self._global_config = None
        self._owasp_config = None
        self._strategy_config = None


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