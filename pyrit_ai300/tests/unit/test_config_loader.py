"""
配置加载器测试
==============

测试 ConfigLoader 的 OWASP 配置加载功能。

遵循开发规则 1.4.9 测试先行原则
"""

import pytest

from src.core.config_loader import ConfigLoader


# ============================================================
# ConfigLoader 单例和初始化测试
# ============================================================


class TestConfigLoaderInit:
    """测试 ConfigLoader 初始化"""

    def test_config_loader_can_be_instantiated(self):
        """测试 ConfigLoader 可以被实例化"""
        loader = ConfigLoader()
        assert loader is not None

    def test_config_dir_exists(self):
        """测试配置目录存在"""
        loader = ConfigLoader()
        assert loader.config_dir.exists()

    def test_config_files_exist(self):
        """测试配置文件存在"""
        loader = ConfigLoader()
        # config.yaml 始终从 config/ 加载
        assert loader.config_file.exists(), f"config.yaml 不存在: {loader.config_file}"
        # owasp_mapping.yaml 和 payload_strategy_matrix.yaml 从 src/core/defaults/ 加载
        # （或 config/ 下用户覆盖，如果存在）
        assert loader.owasp_file.exists(), f"owasp_mapping.yaml 不存在: {loader.owasp_file}"
        assert loader.strategy_file.exists(), f"payload_strategy_matrix.yaml 不存在: {loader.strategy_file}"

    def test_system_defaults_dir_exists(self):
        """测试系统默认配置目录存在"""
        loader = ConfigLoader()
        assert loader.defaults_dir.exists(), f"系统默认目录不存在: {loader.defaults_dir}"
        # 系统默认文件必须存在
        assert (loader.defaults_dir / "owasp_mapping.yaml").exists()
        assert (loader.defaults_dir / "payload_strategy_matrix.yaml").exists()

    def test_config_resolves_to_system_defaults(self):
        """测试无用户覆盖时，解析到系统默认路径"""
        loader = ConfigLoader()
        # 如果 config/ 下没有用户覆盖文件，应回退到 src/core/defaults/
        # 注意：用户可能创建了覆盖文件，所以检查路径指向的文件存在即可
        assert loader.owasp_file.exists()
        assert loader.strategy_file.exists()
        # 系统默认路径应指向 src/core/defaults/
        assert loader.defaults_dir.name == "defaults"
        assert loader.defaults_dir.parent.name == "core"


# ============================================================
# OWASP 配置加载测试
# ============================================================


class TestOWASPConfigLoading:
    """测试 OWASP 配置加载"""

    @pytest.fixture
    def config_loader(self):
        """创建配置加载器实例"""
        return ConfigLoader()

    def test_load_owasp_config(self, config_loader):
        """测试加载 OWASP 配置"""
        config = config_loader.load_owasp_config()
        assert config is not None
        assert isinstance(config, dict)

    def test_get_owasp_llm_top_10(self, config_loader):
        """测试获取 OWASP LLM Top 10"""
        llm_top_10 = config_loader.get_owasp_llm_top_10()
        assert len(llm_top_10) == 10
        assert "LLM01" in llm_top_10
        assert "LLM10" in llm_top_10

    def test_get_owasp_asi_top_10(self, config_loader):
        """测试获取 OWASP Agentic AI Top 10"""
        asi_top_10 = config_loader.get_owasp_asi_top_10()
        assert len(asi_top_10) == 10
        assert "ASI01" in asi_top_10
        assert "ASI10" in asi_top_10

    def test_get_all_owasp_standards(self, config_loader):
        """测试获取所有 OWASP 标准（合并后）"""
        all_standards = config_loader.get_all_owasp_standards()
        assert len(all_standards) == 20  # 10 LLM + 10 ASI
        assert "LLM01" in all_standards
        assert "ASI01" in all_standards

    def test_get_owasp_details_for_llm(self, config_loader):
        """测试获取 LLM OWASP 详情"""
        details = config_loader.get_owasp_details("LLM01")
        assert details is not None
        assert details["name"] == "Prompt Injection"
        assert details["version"] == "2025"

    def test_get_owasp_details_for_asi(self, config_loader):
        """测试获取 Agentic AI OWASP 详情"""
        details = config_loader.get_owasp_details("ASI01")
        assert details is not None
        assert details["name"] == "Goal Hijacking"

    def test_get_owasp_details_invalid_id(self, config_loader):
        """测试获取无效 OWASP ID 的详情"""
        details = config_loader.get_owasp_details("INVALID")
        assert details is None

    def test_get_owasp_mapping(self, config_loader):
        """测试获取攻击类型到 OWASP 的映射"""
        mapping = config_loader.get_owasp_mapping()
        assert len(mapping) > 0
        assert "prompt_injection" in mapping

    def test_owasp_mapping_references_valid_ids(self, config_loader):
        """测试攻击映射引用的 OWASP ID 都是有效的"""
        mapping = config_loader.get_owasp_mapping()
        all_standards = config_loader.get_all_owasp_standards()

        for attack_type, owasp_ids in mapping.items():
            for owasp_id in owasp_ids:
                assert owasp_id in all_standards, (
                    f"攻击类型 '{attack_type}' 引用了无效的 OWASP ID: {owasp_id}"
                )

    def test_config_caching(self, config_loader):
        """测试配置缓存"""
        config1 = config_loader.get_owasp_config()
        config2 = config_loader.get_owasp_config()
        assert config1 is config2  # 同一个对象（缓存）

    def test_reload_config(self, config_loader):
        """测试重新加载配置"""
        config1 = config_loader.get_owasp_config()
        config_loader.reload_config()
        config2 = config_loader.get_owasp_config()
        assert config1 is not config2  # 不同对象（重新加载）
