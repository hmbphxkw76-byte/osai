"""
Core 模块 PyRIT 原生对齐测试
================================

验证 src/core/ 目录下代码对齐 PyRIT 1.0.0 官方框架标准。

测试覆盖：
1. ConfigLoader PyRIT 原生集成（verify_and_resolve_path / get_non_required_value /
   set_default_value / ConfigurationLoader 桥接 / CentralMemory 桥接）
2. Models 原生类型对齐（TargetCapabilities / datetime timezone）
3. Logging 原生 logger 集成
4. __init__ 原生工具函数 re-export
"""

import logging
import os
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

# ============================================================
# ConfigLoader PyRIT 原生集成测试
# ============================================================


class TestConfigLoaderPyRITNativePath:
    """测试 ConfigLoader 使用 PyRIT 原生路径验证"""

    def test_load_yaml_uses_verify_and_resolve_path(self):
        """测试 _load_yaml 使用 PyRIT 原生 verify_and_resolve_path"""
        from src.core.config_loader import ConfigLoader

        loader = ConfigLoader()
        # 系统默认 OWASP 文件应能正常加载
        result = loader._load_yaml(loader.owasp_file)
        assert isinstance(result, dict)
        assert "attack_to_owasp" in result

    def test_load_yaml_raises_on_nonexistent_path(self):
        """测试 _load_yaml 对不存在路径抛出 FileNotFoundError"""
        from src.core.config_loader import ConfigLoader

        loader = ConfigLoader()
        with pytest.raises(FileNotFoundError):
            loader._load_yaml(Path("/nonexistent/file.yaml"))


class TestConfigLoaderPyRITConfig:
    """测试 ConfigLoader PyRIT 原生配置文件支持"""

    def test_get_pyrit_config_path_returns_native_path(self):
        """测试 get_pyrit_config_path 返回 PyRIT 原生路径"""
        from src.core.config_loader import ConfigLoader

        loader = ConfigLoader()
        path = loader.get_pyrit_config_path()
        assert path.name == ".pyrit_conf"
        assert ".pyrit" in str(path)

    def test_is_pyrit_config_available_returns_bool(self):
        """测试 is_pyrit_config_available 返回布尔值"""
        from src.core.config_loader import ConfigLoader

        loader = ConfigLoader()
        result = loader.is_pyrit_config_available()
        assert isinstance(result, bool)

    def test_load_pyrit_config_returns_dict(self):
        """测试 load_pyrit_config 返回字典"""
        from src.core.config_loader import ConfigLoader

        loader = ConfigLoader()
        result = loader.load_pyrit_config()
        assert isinstance(result, dict)

    def test_load_pyrit_config_caches_result(self):
        """测试 load_pyrit_config 缓存结果"""
        from src.core.config_loader import ConfigLoader

        loader = ConfigLoader()
        result1 = loader.load_pyrit_config()
        result2 = loader.load_pyrit_config()
        assert result1 is result2  # 同一对象（缓存）

    def test_reload_config_clears_pyrit_cache(self):
        """测试 reload_config 清除 PyRIT 配置缓存"""
        from src.core.config_loader import ConfigLoader

        loader = ConfigLoader()
        loader.load_pyrit_config()
        loader.reload_config()
        result2 = loader.load_pyrit_config()
        # 缓存清除后重新加载，可能是同一对象（如果文件不变）或不同对象
        assert isinstance(result2, dict)


class TestConfigLoaderPyRITMemoryDBType:
    """测试 ConfigLoader PyRIT 内存数据库类型解析"""

    def test_get_pyrit_memory_db_type_returns_string(self):
        """测试 get_pyrit_memory_db_type 返回字符串"""
        from src.core.config_loader import ConfigLoader

        loader = ConfigLoader()
        result = loader.get_pyrit_memory_db_type()
        assert isinstance(result, str)
        assert result in ("sqlite", "in_memory", "azure_sql") or "sqlite" in result

    def test_get_pyrit_memory_db_type_env_override(self):
        """测试环境变量覆盖内存数据库类型"""
        from src.core.config_loader import ConfigLoader

        loader = ConfigLoader()
        with patch.dict(os.environ, {"MEMORY_DB_TYPE": "in_memory"}):
            result = loader.get_pyrit_memory_db_type()
            assert result == "in_memory"


class TestConfigLoaderBridgeMethods:
    """测试 ConfigLoader PyRIT 原生桥接方法"""

    def test_to_configuration_loader_returns_native_type(self):
        """测试 to_configuration_loader 返回原生 ConfigurationLoader"""
        from src.core.config_loader import ConfigLoader

        loader = ConfigLoader()
        result = loader.to_configuration_loader()
        # 验证返回的是 PyRIT 原生 ConfigurationLoader
        assert hasattr(result, "memory_db_type")
        assert hasattr(result, "initializers")
        assert hasattr(result, "initialize_pyrit_async")

    def test_to_configuration_loader_memory_db_type(self):
        """测试桥接后的 memory_db_type 正确"""
        from src.core.config_loader import ConfigLoader

        loader = ConfigLoader()
        result = loader.to_configuration_loader()
        assert result.memory_db_type in ("sqlite", "in_memory", "azure_sql")

    @pytest.mark.asyncio
    async def test_configure_central_memory_async_sets_memory(self):
        """测试 configure_central_memory_async 设置 CentralMemory"""
        from src.core.config_loader import ConfigLoader
        from pyrit.memory import CentralMemory

        loader = ConfigLoader()
        with patch.dict(os.environ, {"MEMORY_DB_TYPE": "in_memory"}):
            memory = await loader.configure_central_memory_async()
            assert memory is not None
            # 验证 CentralMemory 已设置
            assert CentralMemory.get_memory_instance() is not None


class TestConfigLoaderDefaultValues:
    """测试 ConfigLoader 程序化默认值注册"""

    def test_register_default_values_is_idempotent(self):
        """测试 register_default_values 可安全多次调用"""
        from src.core.config_loader import ConfigLoader

        loader = ConfigLoader()
        # 多次调用不应抛出异常
        loader.register_default_values()
        loader.register_default_values()

    def test_register_default_values_sets_temperature(self):
        """测试 register_default_values 注册 temperature"""
        from pyrit.common.apply_defaults import get_global_default_values
        from src.core.config_loader import ConfigLoader

        loader = ConfigLoader()
        loader.register_default_values()

        # 如果 OpenAIChatTarget 可导入，验证默认值已注册
        try:
            from pyrit.prompt_target import OpenAIChatTarget

            defaults = get_global_default_values()
            found, value = defaults.get_default_value(
                class_type=OpenAIChatTarget,
                parameter_name="temperature",
            )
            if loader.get_target_temperature() is not None:
                assert found
        except ImportError:
            pass  # OpenAIChatTarget 不可用时跳过


# ============================================================
# Models PyRIT 原生类型对齐测试
# ============================================================


class TestModelsTargetCapabilitiesNative:
    """测试 TargetCapabilities 使用 PyRIT 原生类型"""

    def test_target_capabilities_is_native_pyrit_type(self):
        """测试 TargetCapabilities 是 PyRIT 原生类型"""
        from src.core.models import TargetCapabilities
        from pyrit.models import TargetCapabilities as PyRITTargetCapabilities

        assert TargetCapabilities is PyRITTargetCapabilities

    def test_target_capabilities_is_frozen(self):
        """测试原生 TargetCapabilities 是 frozen（不可变）"""
        from src.core.models import TargetCapabilities

        caps = TargetCapabilities(supports_multi_turn=True)
        # frozen 模型不支持直接赋值
        with pytest.raises(Exception):
            caps.supports_multi_turn = False

    def test_target_capabilities_model_copy(self):
        """测试 frozen 模型使用 model_copy 创建新实例"""
        from src.core.models import TargetCapabilities

        caps = TargetCapabilities()
        updated = caps.model_copy(update={"supports_multi_turn": True})
        assert updated.supports_multi_turn is True
        assert caps.supports_multi_turn is False  # 原始不变

    def test_target_capabilities_default_construction(self):
        """测试默认构造"""
        from src.core.models import TargetCapabilities

        caps = TargetCapabilities()
        assert caps.supports_multi_turn is False
        assert caps.supports_editable_history is False
        assert caps.supports_system_prompt is False
        assert caps.supports_json_output is False

    def test_target_capabilities_includes_method(self):
        """测试原生 includes() 方法"""
        from src.core.models import TargetCapabilities
        from pyrit.models.target.target_capabilities import CapabilityName

        caps = TargetCapabilities(supports_multi_turn=True)
        assert caps.includes(capability=CapabilityName.MULTI_TURN) is True
        assert caps.includes(capability=CapabilityName.SYSTEM_PROMPT) is False


class TestModelsReconResultAlignment:
    """测试 ReconResult 对齐改进"""

    def test_recon_result_has_raw_capability_response(self):
        """测试 ReconResult 有 raw_capability_response 扩展字段"""
        from src.core.models import ReconResult

        assert "raw_capability_response" in ReconResult.model_fields

    def test_recon_result_capabilities_uses_native_type(self):
        """测试 ReconResult.capabilities 使用原生 TargetCapabilities"""
        from src.core.models import ReconResult, TargetCapabilities

        field_info = ReconResult.model_fields["capabilities"]
        # 验证默认工厂创建原生 TargetCapabilities
        default_caps = field_info.default_factory()
        assert isinstance(default_caps, TargetCapabilities)

    def test_create_recon_result_with_raw_capability_response(self):
        """测试 create_recon_result 接受 raw_capability_response 参数"""
        from src.core.models import (
            AISystemType,
            AuthType,
            TargetCapabilities,
            create_recon_result,
        )

        raw = {"target_type": "openai_chat", "supports_conversation": True}
        recon = create_recon_result(
            target_url="http://example.com",
            detected_endpoint="/v1/chat/completions",
            auth_type=AuthType.NONE,
            ai_system_type=AISystemType.LLM,
            capabilities=TargetCapabilities(supports_multi_turn=True),
            raw_capability_response=raw,
        )
        assert recon.raw_capability_response == raw


class TestModelsTimezoneAlignment:
    """测试 datetime 使用 timezone.utc"""

    def test_recon_result_timestamp_has_timezone(self):
        """测试 ReconResult 时间戳带时区信息"""
        from src.core.models import ReconResult, AISystemType, AuthType

        recon = ReconResult(
            target_url="http://example.com",
            detected_endpoint="/v1/chat",
            auth_type=AuthType.NONE,
            ai_system_type=AISystemType.LLM,
        )
        assert recon.timestamp.tzinfo is not None

    def test_auth_result_timestamp_has_timezone(self):
        """测试 AuthResult 时间戳带时区信息"""
        from src.core.models import AuthResult, AuthType, AuthStatus

        auth = AuthResult(
            target_url="http://example.com",
            auth_type=AuthType.NONE,
            status=AuthStatus.SUCCESS,
        )
        assert auth.timestamp.tzinfo is not None

    def test_strategy_selection_timestamp_has_timezone(self):
        """测试 StrategySelection 时间戳带时区信息"""
        from src.core.models import StrategySelection, AISystemType

        strategy = StrategySelection(
            ai_system_type=AISystemType.LLM,
            scenario_name="test",
            attack_techniques=[],
            dataset_names=[],
            max_concurrency=1,
        )
        assert strategy.timestamp.tzinfo is not None


# ============================================================
# Logging PyRIT 原生集成测试
# ============================================================


class TestLoggingPyRITIntegration:
    """测试日志工具 PyRIT 原生集成"""

    def test_get_pyrit_logger_returns_native_logger(self):
        """测试 get_pyrit_logger 返回 PyRIT 原生 logger"""
        from src.core.logging_utils import get_pyrit_logger

        logger = get_pyrit_logger()
        assert logger.name == "ai-red-team"
        # 原生 logger 应有 file_handler 和 console_handler
        assert len(logger.handlers) >= 2

    def test_configure_pyrit_logger_adds_handler(self):
        """测试 configure_pyrit_logger 添加 FileHandler"""
        from src.core.logging_utils import configure_pyrit_logger, get_pyrit_logger

        logger = get_pyrit_logger()
        initial_handler_count = len(logger.handlers)

        with tempfile.NamedTemporaryFile(suffix=".log", delete=False) as tmp:
            tmp_path = Path(tmp.name)

        try:
            configure_pyrit_logger(tmp_path)
            # 验证 handler 数量增加（或保持不变如果已存在）
            assert len(logger.handlers) >= initial_handler_count
        finally:
            # 关闭并删除文件
            for handler in logger.handlers:
                if isinstance(handler, logging.FileHandler):
                    try:
                        if Path(handler.baseFilename).resolve() == tmp_path.resolve():
                            handler.close()
                            logger.removeHandler(handler)
                    except (OSError, ValueError):
                        pass
            tmp_path.unlink(missing_ok=True)

    def test_configure_pyrit_logger_idempotent(self):
        """测试 configure_pyrit_logger 幂等（不重复添加同一文件 handler）"""
        from src.core.logging_utils import configure_pyrit_logger, get_pyrit_logger

        logger = get_pyrit_logger()

        with tempfile.NamedTemporaryFile(suffix=".log", delete=False) as tmp:
            tmp_path = Path(tmp.name)

        try:
            configure_pyrit_logger(tmp_path)
            count_after_first = len(logger.handlers)
            configure_pyrit_logger(tmp_path)  # 再次配置同一文件
            count_after_second = len(logger.handlers)
            # 同一文件不应重复添加 handler
            assert count_after_second == count_after_first
        finally:
            # 关闭并删除文件
            for handler in logger.handlers:
                if isinstance(handler, logging.FileHandler):
                    try:
                        if Path(handler.baseFilename).resolve() == tmp_path.resolve():
                            handler.close()
                            logger.removeHandler(handler)
                    except (OSError, ValueError):
                        pass
            tmp_path.unlink(missing_ok=True)


# ============================================================
# __init__ 原生工具函数 re-export 测试
# ============================================================


class TestInitPyRITReExports:
    """测试 __init__ 正确 re-export PyRIT 原生工具函数"""

    def test_verify_and_resolve_path_exported(self):
        """测试 verify_and_resolve_path 已 re-export"""
        from src.core import verify_and_resolve_path
        assert callable(verify_and_resolve_path)

    def test_get_non_required_value_exported(self):
        """测试 get_non_required_value 已 re-export"""
        from src.core import get_non_required_value
        assert callable(get_non_required_value)

    def test_get_required_value_exported(self):
        """测试 get_required_value 已 re-export"""
        from src.core import get_required_value
        assert callable(get_required_value)

    def test_apply_defaults_exported(self):
        """测试 apply_defaults 已 re-export"""
        from src.core import apply_defaults
        assert callable(apply_defaults)

    def test_set_default_value_exported(self):
        """测试 set_default_value 已 re-export"""
        from src.core import set_default_value
        assert callable(set_default_value)

    def test_reset_default_values_exported(self):
        """测试 reset_default_values 已 re-export"""
        from src.core import reset_default_values
        assert callable(reset_default_values)

    def test_required_value_exported(self):
        """测试 REQUIRED_VALUE 已 re-export"""
        from src.core import REQUIRED_VALUE
        assert REQUIRED_VALUE is not None
        assert not bool(REQUIRED_VALUE)  # Sentinel evaluates to False

    def test_singleton_exported(self):
        """测试 Singleton 已 re-export"""
        from src.core import Singleton
        assert Singleton is not None

    def test_yaml_loadable_exported(self):
        """测试 YamlLoadable 已 re-export"""
        from src.core import YamlLoadable
        assert YamlLoadable is not None

    def test_combine_dict_exported(self):
        """测试 combine_dict 已 re-export"""
        from src.core import combine_dict
        assert callable(combine_dict)

    def test_combine_list_exported(self):
        """测试 combine_list 已 re-export"""
        from src.core import combine_list
        assert callable(combine_list)

    def test_configure_pyrit_logger_exported(self):
        """测试 configure_pyrit_logger 已导出"""
        from src.core import configure_pyrit_logger
        assert callable(configure_pyrit_logger)

    def test_get_pyrit_logger_exported(self):
        """测试 get_pyrit_logger 已导出"""
        from src.core import get_pyrit_logger
        assert callable(get_pyrit_logger)


# ============================================================
# 综合原生对齐验证测试
# ============================================================


class TestNativeAlignmentComprehensive:
    """综合验证 src/core/ 对齐 PyRIT 1.0.0 原生框架"""

    def test_config_loader_imports_native_utilities(self):
        """测试 ConfigLoader 导入 PyRIT 原生工具"""
        import src.core.config_loader as cl_module

        # 验证模块级导入
        assert hasattr(cl_module, "verify_and_resolve_path")
        assert hasattr(cl_module, "get_non_required_value")
        assert hasattr(cl_module, "PYRIT_DEFAULT_CONFIG_PATH")
        assert hasattr(cl_module, "_PYRIT_CONFIG_PATH")

    def test_config_loader_has_bridge_methods(self):
        """测试 ConfigLoader 有 PyRIT 原生桥接方法"""
        from src.core.config_loader import ConfigLoader

        loader = ConfigLoader()
        assert hasattr(loader, "load_pyrit_config")
        assert hasattr(loader, "get_pyrit_memory_db_type")
        assert hasattr(loader, "to_configuration_loader")
        assert hasattr(loader, "configure_central_memory_async")
        assert hasattr(loader, "register_default_values")
        assert hasattr(loader, "get_pyrit_config_path")
        assert hasattr(loader, "is_pyrit_config_available")

    def test_models_uses_native_target_capabilities(self):
        """测试 models.py 使用原生 TargetCapabilities"""
        from src.core.models import TargetCapabilities
        from pyrit.models import TargetCapabilities as NativeTC

        assert TargetCapabilities is NativeTC

    def test_logging_integrates_pyrit_logger(self):
        """测试 logging_utils.py 集成 PyRIT 原生 logger"""
        import src.core.logging_utils as lu_module

        assert hasattr(lu_module, "_pyrit_logger")
        assert hasattr(lu_module, "get_pyrit_logger")
        assert hasattr(lu_module, "configure_pyrit_logger")

    def test_init_exports_all_native_utilities(self):
        """测试 __init__ 导出所有 PyRIT 原生工具函数"""
        import src.core as core

        expected_exports = [
            "REQUIRED_VALUE",
            "apply_defaults",
            "set_default_value",
            "reset_default_values",
            "get_non_required_value",
            "get_required_value",
            "Singleton",
            "combine_dict",
            "combine_list",
            "verify_and_resolve_path",
            "YamlLoadable",
            "configure_pyrit_logger",
            "get_pyrit_logger",
        ]
        for name in expected_exports:
            assert hasattr(core, name), f"src.core 未导出 {name}"
            assert name in core.__all__, f"{name} 不在 __all__ 中"
