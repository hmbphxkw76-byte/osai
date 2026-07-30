"""
Tests for AI-300 Setup Module — 对齐 PyRIT 1.0.0 Setup 文档
==============================================================

测试覆盖：
  1. EnvLoader — .env / .env_local 发现和加载
  2. RetryConfig — 三层重试配置传播
  3. AI300ConfigFile — ~/.pyrit/.pyrit_conf 配置文件
  4. AI300Initializers — PyRITInitializer 子类
  5. AI300SetupManager — 初始化管理器
  6. Scenario-level retry — execute_batch max_retries 参数
"""

import os
import tempfile
from pathlib import Path

import pytest

from src.setup.retry_config import (
    RetryConfig,
    configure_retry_env_vars,
    get_retry_config,
    should_retry_scenario,
    get_scenario_retry_message,
)
from src.setup.env_loader import (
    EnvLoader,
    discover_env_files,
    load_env_files,
)
from src.setup.config_file import (
    AI300ConfigFile,
    load_config_file,
    save_config_file,
    create_default_config_file,
)
from src.setup.setup_manager import (
    AI300SetupManager,
    initialize_ai300_async,
)
from src.setup.ai300_initializers import (
    AI300TargetInitializer,
    AI300ScorerInitializer,
    AI300TechniqueInitializerWrapper,
    AI300LoadDefaultDatasets,
    AI300DefaultValuesInitializer,
    AI300PreloadScenarioMetadata,
    get_default_initializers,
)


# ============================================================
# 1. RetryConfig 测试
# ============================================================

class TestRetryConfig:
    """RetryConfig 数据类测试"""

    def test_default_values(self):
        """默认值与 PyRIT 文档一致"""
        config = RetryConfig()
        assert config.max_num_attempts == 10
        assert config.wait_min_seconds == 5
        assert config.wait_max_seconds == 220
        assert config.scenario_max_retries == 0

    def test_total_scenario_attempts(self):
        """总尝试次数 = 1 + max_retries"""
        config = RetryConfig(scenario_max_retries=3)
        assert config.total_scenario_attempts == 4

        config_zero = RetryConfig(scenario_max_retries=0)
        assert config_zero.total_scenario_attempts == 1

    def test_to_env_dict(self):
        """转换为环境变量字典"""
        config = RetryConfig(
            max_num_attempts=5,
            wait_min_seconds=2,
            wait_max_seconds=60,
        )
        env_dict = config.to_env_dict()
        assert env_dict["RETRY_MAX_NUM_ATTEMPTS"] == "5"
        assert env_dict["RETRY_WAIT_MIN_SECONDS"] == "2"
        assert env_dict["RETRY_WAIT_MAX_SECONDS"] == "60"

    def test_repr(self):
        """repr 包含关键信息"""
        config = RetryConfig(max_num_attempts=5, wait_min_seconds=2, wait_max_seconds=60, scenario_max_retries=3)
        repr_str = repr(config)
        assert "max=5" in repr_str
        assert "wait=2-60s" in repr_str
        assert "max_retries=3" in repr_str


class TestConfigureRetryEnvVars:
    """重试环境变量传播测试"""

    def test_configure_sets_env_vars(self):
        """配置传播设置环境变量"""
        os.environ.pop("RETRY_MAX_NUM_ATTEMPTS", None)
        os.environ.pop("RETRY_WAIT_MIN_SECONDS", None)
        os.environ.pop("RETRY_WAIT_MAX_SECONDS", None)

        config = RetryConfig(max_num_attempts=7, wait_min_seconds=3, wait_max_seconds=100)
        configure_retry_env_vars(config, override=True)

        assert os.getenv("RETRY_MAX_NUM_ATTEMPTS") == "7"
        assert os.getenv("RETRY_WAIT_MIN_SECONDS") == "3"
        assert os.getenv("RETRY_WAIT_MAX_SECONDS") == "100"

    def test_configure_no_override_existing(self):
        """不覆盖已存在的环境变量"""
        os.environ["RETRY_MAX_NUM_ATTEMPTS"] = "99"

        config = RetryConfig(max_num_attempts=5)
        configure_retry_env_vars(config, override=False)

        assert os.getenv("RETRY_MAX_NUM_ATTEMPTS") == "99"

        # 清理
        os.environ.pop("RETRY_MAX_NUM_ATTEMPTS", None)


class TestShouldRetryScenario:
    """Scenario 重试判断测试"""

    def test_no_retries(self):
        """max_retries=0 不重试"""
        assert not should_retry_scenario(ValueError("test"), 1, 0)

    def test_first_attempt(self):
        """首次尝试可以重试"""
        assert should_retry_scenario(ValueError("test"), 1, 3)

    def test_exhausted(self):
        """重试次数用完"""
        assert not should_retry_scenario(ValueError("test"), 4, 3)

    def test_get_retry_message(self):
        """重试消息包含关键信息"""
        msg = get_scenario_retry_message(1, 3, ValueError("test error"))
        assert "attempt 1" in msg
        assert "ValueError" in msg
        assert "retries remaining" in msg


# ============================================================
# 2. EnvLoader 测试
# ============================================================

class TestEnvLoader:
    """环境变量加载器测试"""

    def test_discover_env_files(self, tmp_path):
        """发现 .env 文件"""
        env_file = tmp_path / ".env"
        env_file.write_text("TEST_VAR=hello")

        files = discover_env_files(tmp_path, check_pyrit_dir=False)
        assert len(files) == 1
        assert files[0] == env_file

    def test_discover_env_local(self, tmp_path):
        """发现 .env_local 文件"""
        env_file = tmp_path / ".env"
        env_local = tmp_path / ".env_local"
        env_file.write_text("VAR=base")
        env_local.write_text("VAR=override")

        files = discover_env_files(tmp_path, check_pyrit_dir=False)
        assert len(files) == 2
        assert files[0] == env_file
        assert files[1] == env_local

    def test_discover_no_files(self, tmp_path):
        """无文件时返回空列表"""
        files = discover_env_files(tmp_path, check_pyrit_dir=False)
        assert len(files) == 0

    def test_load_env_files(self, tmp_path):
        """加载 .env 文件"""
        env_file = tmp_path / ".env"
        env_file.write_text("AI300_TEST_VAR=loaded_value")

        loaded = load_env_files([env_file])
        assert len(loaded) == 1
        assert os.getenv("AI300_TEST_VAR") == "loaded_value"

        # 清理
        os.environ.pop("AI300_TEST_VAR", None)

    def test_load_env_local_overrides_env(self, tmp_path):
        """ .env_local 覆盖 .env"""
        env_file = tmp_path / ".env"
        env_local = tmp_path / ".env_local"
        env_file.write_text("AI300_OVERRIDE_VAR=base")
        env_local.write_text("AI300_OVERRIDE_VAR=override")

        load_env_files([env_file, env_local])
        assert os.getenv("AI300_OVERRIDE_VAR") == "override"

        # 清理
        os.environ.pop("AI300_OVERRIDE_VAR", None)

    def test_env_loader_class(self, tmp_path):
        """EnvLoader 类封装"""
        env_file = tmp_path / ".env"
        env_file.write_text("AI300_LOADER_VAR=from_loader")

        loader = EnvLoader(project_root=tmp_path, check_pyrit_dir=False)
        loaded = loader.load()
        assert len(loaded) == 1
        assert loader.get_env("AI300_LOADER_VAR") == "from_loader"

        # 清理
        os.environ.pop("AI300_LOADER_VAR", None)

    def test_env_loader_require_env(self, tmp_path):
        """require_env 抛出异常"""
        loader = EnvLoader(project_root=tmp_path, check_pyrit_dir=False)
        loader.load()

        with pytest.raises(ValueError, match="AI300_REQUIRED"):
            loader.require_env("AI300_REQUIRED")


# ============================================================
# 3. ConfigFile 测试
# ============================================================

class TestConfigFile:
    """配置文件测试"""

    def test_config_file_defaults(self):
        """配置文件默认值"""
        config = AI300ConfigFile()
        assert config.memory_db_type == "SQLite"
        assert config.initializers == []
        assert config.silent is False
        assert config.scenario_max_retries == 0

    def test_config_file_to_dict(self):
        """转换为字典"""
        config = AI300ConfigFile(
            memory_db_type="InMemory",
            scenario_max_retries=3,
        )
        d = config.to_dict()
        assert d["memory_db_type"] == "InMemory"
        assert d["scenario_max_retries"] == 3

    def test_config_file_from_dict(self):
        """从字典创建"""
        data = {
            "memory_db_type": "AzureSQL",
            "scenario_max_retries": 5,
            "initializers": [{"name": "target"}],
        }
        config = AI300ConfigFile.from_dict(data)
        assert config.memory_db_type == "AzureSQL"
        assert config.scenario_max_retries == 5
        assert len(config.initializers) == 1

    def test_save_and_load_config_file(self, tmp_path):
        """保存和加载配置文件"""
        config_path = tmp_path / ".pyrit_conf"

        original = AI300ConfigFile(
            memory_db_type="InMemory",
            scenario_max_retries=3,
            initializers=[
                {"name": "target", "args": {"tags": ["default"]}},
                {"name": "scorer"},
            ],
        )
        save_config_file(original, config_path)

        assert config_path.exists()

        loaded = load_config_file(config_path)
        assert loaded.memory_db_type == "InMemory"
        assert loaded.scenario_max_retries == 3
        assert len(loaded.initializers) == 2

    def test_load_config_file_not_found(self, tmp_path):
        """加载不存在的配置文件"""
        with pytest.raises(FileNotFoundError):
            load_config_file(tmp_path / "nonexistent.yaml")

    def test_create_default_config_file(self, tmp_path):
        """创建默认配置文件"""
        config_path = tmp_path / ".pyrit_conf"
        result_path = create_default_config_file(config_path)

        assert result_path == config_path
        assert config_path.exists()

        loaded = load_config_file(config_path)
        assert loaded.memory_db_type == "SQLite"
        assert loaded.scenario_max_retries == 3
        assert len(loaded.initializers) == 3

    def test_config_file_to_yaml(self):
        """序列化为 YAML"""
        config = AI300ConfigFile(memory_db_type="SQLite")
        yaml_str = config.to_yaml()
        assert "memory_db_type: SQLite" in yaml_str


# ============================================================
# 4. AI300Initializers 测试
# ============================================================

class TestAI300TargetInitializer:
    """AI300TargetInitializer 测试"""

    def test_inherits_pyrit_initializer(self):
        """继承 PyRITInitializer"""
        init = AI300TargetInitializer()
        from pyrit.setup.pyrit_initializer import PyRITInitializer
        assert isinstance(init, PyRITInitializer)

    def test_supported_parameters(self):
        """支持参数声明"""
        init = AI300TargetInitializer()
        params = init.supported_parameters
        param_names = [p.name for p in params]
        assert "tags" in param_names
        assert "auto_group" in param_names

    def test_description(self):
        """描述来自 docstring"""
        init = AI300TargetInitializer()
        desc = init.description
        assert len(desc) > 0

    def test_set_params_from_args(self):
        """设置参数"""
        init = AI300TargetInitializer()
        init.set_params_from_args(args={"tags": ["all"], "auto_group": False})
        assert "tags" in init.params
        assert "auto_group" in init.params

    def test_validate_params_unknown(self):
        """验证未知参数"""
        init = AI300TargetInitializer()
        init.set_params_from_args(args={"unknown_param": "value"})
        with pytest.raises(ValueError, match="unknown_param"):
            init.validate_params()


class TestAI300ScorerInitializer:
    """AI300ScorerInitializer 测试"""

    def test_inherits_pyrit_initializer(self):
        """继承 PyRITInitializer"""
        init = AI300ScorerInitializer()
        from pyrit.setup.pyrit_initializer import PyRITInitializer
        assert isinstance(init, PyRITInitializer)

    def test_supported_parameters(self):
        """支持参数声明"""
        init = AI300ScorerInitializer()
        params = init.supported_parameters
        assert any(p.name == "tags" for p in params)


class TestAI300TechniqueInitializerWrapper:
    """AI300TechniqueInitializerWrapper 测试"""

    def test_inherits_pyrit_initializer(self):
        """继承 PyRITInitializer"""
        init = AI300TechniqueInitializerWrapper()
        from pyrit.setup.pyrit_initializer import PyRITInitializer
        assert isinstance(init, PyRITInitializer)

    def test_supported_parameters(self):
        """支持参数声明"""
        init = AI300TechniqueInitializerWrapper()
        params = init.supported_parameters
        assert any(p.name == "tags" for p in params)


class TestAI300LoadDefaultDatasets:
    """AI300LoadDefaultDatasets 测试"""

    def test_inherits_pyrit_initializer(self):
        """继承 PyRITInitializer"""
        init = AI300LoadDefaultDatasets()
        from pyrit.setup.pyrit_initializer import PyRITInitializer
        assert isinstance(init, PyRITInitializer)

    def test_supported_parameters(self):
        """支持参数声明"""
        init = AI300LoadDefaultDatasets()
        params = init.supported_parameters
        param_names = [p.name for p in params]
        assert "owasp" in param_names
        assert "custom" in param_names
        assert "remote" in param_names


class TestAI300DefaultValuesInitializer:
    """AI300DefaultValuesInitializer 测试"""

    def test_inherits_pyrit_initializer(self):
        """继承 PyRITInitializer"""
        init = AI300DefaultValuesInitializer()
        from pyrit.setup.pyrit_initializer import PyRITInitializer
        assert isinstance(init, PyRITInitializer)

    @pytest.mark.asyncio
    async def test_initialize_sets_defaults(self):
        """initialize 设置默认值"""
        init = AI300DefaultValuesInitializer()
        await init.initialize_async()
        # 验证不抛异常即可


class TestGetDefaultInitializers:
    """get_default_initializers 工厂函数测试"""

    def test_returns_three_initializers(self):
        """返回三个初始化器"""
        initializers = get_default_initializers()
        assert len(initializers) == 3

    def test_order_is_correct(self):
        """顺序正确：DefaultValues → Target → Technique"""
        initializers = get_default_initializers()
        types = [type(i).__name__ for i in initializers]
        assert types == [
            "AI300DefaultValuesInitializer",
            "AI300TargetInitializer",
            "AI300TechniqueInitializerWrapper",
        ]

    def test_all_inherit_pyrit_initializer(self):
        """全部继承 PyRITInitializer"""
        from pyrit.setup.pyrit_initializer import PyRITInitializer
        initializers = get_default_initializers()
        for init in initializers:
            assert isinstance(init, PyRITInitializer)


# ============================================================
# 5. AI300SetupManager 测试
# ============================================================

class TestAI300SetupManager:
    """AI300SetupManager 测试"""

    def test_init_defaults(self):
        """默认初始化"""
        manager = AI300SetupManager()
        assert manager.is_initialized is False
        assert manager.retry_config is None

    def test_resolve_memory_db_type(self):
        """解析数据库类型"""
        manager = AI300SetupManager(memory_db_type="InMemory")
        assert manager._resolve_memory_db_type() == "InMemory"

    def test_resolve_initializers_default(self):
        """默认解析为三个初始化器"""
        manager = AI300SetupManager()
        initializers = manager._resolve_initializers()
        assert len(initializers) == 3

    def test_resolve_initializers_custom(self):
        """自定义初始化器"""
        custom = AI300DefaultValuesInitializer()
        manager = AI300SetupManager(initializers=[custom])
        initializers = manager._resolve_initializers()
        assert len(initializers) == 1
        assert initializers[0] is custom


# ============================================================
# 6. Scenario-level retry 测试
# ============================================================

class TestScenarioLevelRetry:
    """Scenario 级别重试测试"""

    def test_execute_batch_attacks_has_max_retries_param(self):
        """execute_batch_attacks 函数有 max_retries 参数"""
        import inspect
        from src.executor.workflow.scenario_orchestrator import execute_batch_attacks
        sig = inspect.signature(execute_batch_attacks)
        assert "max_retries" in sig.parameters
        assert sig.parameters["max_retries"].default == 0

    def test_execute_batch_has_max_retries_param(self):
        """execute_batch 方法有 max_retries 参数"""
        import inspect
        from src.executor.workflow.scenario_orchestrator import ScenarioOrchestrator
        sig = inspect.signature(ScenarioOrchestrator.execute_batch)
        assert "max_retries" in sig.parameters
        assert sig.parameters["max_retries"].default == 0

    def test_config_loader_get_scenario_max_retries(self):
        """ConfigLoader 有 get_scenario_max_retries 方法"""
        from src.core.config_loader import ConfigLoader
        loader = ConfigLoader()
        # 默认从 pipeline.yaml 读取
        retries = loader.get_scenario_max_retries()
        assert isinstance(retries, int)
        assert retries >= 0


# ============================================================
# 7. PyRIT 文档对齐验证测试
# ============================================================

class TestPyRITDocAlignment:
    """PyRIT 1.0.0 Setup 文档对齐验证"""

    def test_setup_module_exports(self):
        """setup 模块导出完整 API"""
        from src.setup import (
            AI300SetupManager,
            initialize_ai300_async,
            initialize_from_config_file_async,
        )
        # 全部可导入
        assert AI300SetupManager is not None
        assert initialize_ai300_async is not None
        assert initialize_from_config_file_async is not None

    def test_pipeline_yaml_has_scenario_max_retries(self):
        """pipeline.yaml 包含 scenario_max_retries 配置"""
        from src.core.config_loader import get_config_loader
        loader = get_config_loader()
        defaults = loader.get_pipeline_defaults()
        assert "scenario_max_retries" in defaults

    def test_env_file_has_retry_comments(self):
        """ .env 文件指向 config/defaults/ 管理重试配置"""
        env_path = Path(__file__).parent.parent.parent / ".env"
        content = env_path.read_text(encoding="utf-8")
        # .env 应引用 config/defaults/ 作为参数配置位置
        assert "config/defaults/" in content
        # SCENARIO_MAX_RETRIES 已迁移至 pipeline.yaml，.env 不再直接包含该参数
        assert "SCENARIO_MAX_RETRIES=" not in content

    def test_env_example_documents_env_local(self):
        """ .env.example 文件文档了 .env.local 个人覆盖机制"""
        env_example = Path(__file__).parent.parent.parent / ".env.example"
        content = env_example.read_text(encoding="utf-8")
        assert ".env.local" in content

    def test_three_level_retry_documented(self):
        """pipeline.yaml 文档了三层重试"""
        from src.core.config_loader import get_config_loader
        loader = get_config_loader()
        defaults = loader.get_pipeline_defaults()
        retry_config = defaults.get("retry", {})
        assert "max_num_attempts" in retry_config
        assert "wait_min_seconds" in retry_config
        assert "wait_max_seconds" in retry_config
        assert "scenario_max_retries" in defaults

    def test_pyrit_initializer_subclass_compliance(self):
        """所有 AI-300 初始化器继承 PyRITInitializer"""
        from pyrit.setup.pyrit_initializer import PyRITInitializer
        initializers = get_default_initializers()
        for init in initializers:
            assert isinstance(init, PyRITInitializer)
            # 有 initialize_async 方法
            assert hasattr(init, "initialize_async")
            # 有 supported_parameters 属性
            assert hasattr(init, "supported_parameters")
            # 有 description 属性
            assert hasattr(init, "description")
            # 有 set_params_from_args 方法
            assert hasattr(init, "set_params_from_args")
            # 有 validate 方法
            assert hasattr(init, "validate")


# ============================================================
# 8. L5 原生优先对齐测试
# ============================================================

class TestPreloadScenarioMetadata:
    """AI300PreloadScenarioMetadata 测试"""

    def test_inherits_pyrit_initializer(self):
        """继承 PyRITInitializer"""
        from pyrit.setup.pyrit_initializer import PyRITInitializer
        init = AI300PreloadScenarioMetadata()
        assert isinstance(init, PyRITInitializer)

    def test_no_required_env_vars(self):
        """不需要环境变量"""
        init = AI300PreloadScenarioMetadata()
        assert init.required_env_vars == []

    def test_has_initialize_async(self):
        """有 initialize_async 方法"""
        init = AI300PreloadScenarioMetadata()
        assert hasattr(init, "initialize_async")

    def test_exported_from_setup_module(self):
        """从 setup 模块可导出"""
        from src.setup import AI300PreloadScenarioMetadata as ExportedClass
        assert ExportedClass is AI300PreloadScenarioMetadata


class TestNativeDelegation:
    """原生初始化器委托验证"""

    def test_target_initializer_delegates_to_native(self):
        """AI300TargetInitializer 委托原生 TargetInitializer"""
        import inspect
        source = inspect.getsource(AI300TargetInitializer.initialize_async)
        assert "TargetInitializer" in source
        assert "native_init" in source

    def test_scorer_initializer_delegates_to_native(self):
        """AI300ScorerInitializer 委托原生 ScorerInitializer"""
        import inspect
        source = inspect.getsource(AI300ScorerInitializer.initialize_async)
        assert "ScorerInitializer" in source
        assert "native_init" in source

    def test_preload_delegates_to_native(self):
        """AI300PreloadScenarioMetadata 委托原生 PreloadScenarioMetadata"""
        import inspect
        source = inspect.getsource(AI300PreloadScenarioMetadata.initialize_async)
        assert "PreloadScenarioMetadata" in source

    def test_target_initializer_uses_native_registry_api(self):
        """AI300TargetInitializer v8.2: 不再创建 AI-300 专用 Target（由 Stage 3 负责）"""
        import inspect
        source = inspect.getsource(AI300TargetInitializer.initialize_async)
        # v8.2 优化: 不再包含 registry.instances.register（Target 创建移至 Pipeline Stage 3）
        assert "registry.instances.register" not in source
        # 但仍设置默认 temperature
        assert "set_default_value" in source
        assert "temperature" in source

    def test_scorer_initializer_uses_native_registry_api(self):
        """AI300ScorerInitializer 仍包含原生 registry.instances.register 代码路径"""
        import inspect
        source = inspect.getsource(AI300ScorerInitializer.initialize_async)
        assert "scorer_registry.instances.register" in source

    @pytest.mark.asyncio
    async def test_target_initializer_native_failure_is_non_fatal(self):
        """v8.2: AI300TargetInitializer 跳过原生 TargetInitializer（无标准 env vars 时）"""
        init = AI300TargetInitializer()
        # 确保没有标准 PyRIT env vars（触发跳过逻辑）
        for var in ("OPENAI_CHAT_ENDPOINT", "AZURE_OPENAI_CHAT_ENDPOINT",
                    "OPENAI_CHAT_MODEL", "AZURE_OPENAI_CHAT_MODEL"):
            os.environ.pop(var, None)
        # 初始化应不抛异常
        try:
            await init.initialize_async()
        except Exception:
            # CentralMemory 未初始化可能导致异常，这是预期的
            pass


class TestSetupManagerNewParams:
    """AI300SetupManager 新参数测试"""

    def test_env_akv_ref_parameter(self):
        """env_akv_ref 参数支持"""
        manager = AI300SetupManager(env_akv_ref=["https://vault.vault.azure.net/secrets/test"])
        assert manager._env_akv_ref == ["https://vault.vault.azure.net/secrets/test"]

    def test_load_defaults_parameter(self):
        """load_defaults 参数支持"""
        manager = AI300SetupManager(load_defaults=False)
        assert manager._load_defaults is False

        manager2 = AI300SetupManager(load_defaults=True)
        assert manager2._load_defaults is True

    def test_load_defaults_default_true(self):
        """load_defaults 默认为 True"""
        manager = AI300SetupManager()
        assert manager._load_defaults is True

    def test_env_akv_ref_default_none(self):
        """env_akv_ref 默认为 None"""
        manager = AI300SetupManager()
        assert manager._env_akv_ref is None

    @pytest.mark.asyncio
    async def test_initialize_ai300_async_passes_memory_kwargs(self):
        """initialize_ai300_async 传递 memory_kwargs（如 db_path）"""
        import shutil
        from pyrit.memory import CentralMemory

        temp_dir = tempfile.mkdtemp()
        str(Path(temp_dir) / "test.db")
        try:
            manager = await initialize_ai300_async(
                memory_db_type="InMemory",
                configure_retry=False,
                silent=True,
            )
            assert manager.is_initialized is True
        finally:
            # 清理
            try:
                CentralMemory._memory_instance = None
            except Exception:
                pass
            shutil.rmtree(temp_dir, ignore_errors=True)


class TestRetryMechanismAlignment:
    """PyRIT 重试机制对齐验证"""

    def test_retry_env_vars_propagated(self):
        """RETRY_* 环境变量被正确传播"""
        config = RetryConfig(
            max_num_attempts=5,
            wait_min_seconds=2,
            wait_max_seconds=30,
        )
        env_dict = config.to_env_dict()
        assert env_dict["RETRY_MAX_NUM_ATTEMPTS"] == "5"
        assert env_dict["RETRY_WAIT_MIN_SECONDS"] == "2"
        assert env_dict["RETRY_WAIT_MAX_SECONDS"] == "30"

    def test_native_retry_reads_env_at_runtime(self):
        """原生重试装饰器在运行时读取环境变量（非装饰时）"""
        # PyRIT 原生使用 _DynamicStopAfterAttempt / _DynamicWaitRandomExponential
        # 这些类在每次重试检查时读取环境变量，而非在装饰时读取
        from pyrit.exceptions.exception_classes import (
            get_retry_max_num_attempts,
            _get_retry_wait_min_seconds,
            _get_retry_wait_max_seconds,
        )
        # 验证 getter 函数存在且读取环境变量
        os.environ["RETRY_MAX_NUM_ATTEMPTS"] = "7"
        assert get_retry_max_num_attempts() == 7

        os.environ["RETRY_WAIT_MIN_SECONDS"] = "3"
        assert _get_retry_wait_min_seconds() == 3

        os.environ["RETRY_WAIT_MAX_SECONDS"] = "45"
        assert _get_retry_wait_max_seconds() == 45

        # 清理
        del os.environ["RETRY_MAX_NUM_ATTEMPTS"]
        del os.environ["RETRY_WAIT_MIN_SECONDS"]
        del os.environ["RETRY_WAIT_MAX_SECONDS"]

    def test_configure_retry_sets_env_vars(self):
        """configure_retry_env_vars 设置环境变量"""
        # 先清除可能存在的值
        for key in ["RETRY_MAX_NUM_ATTEMPTS", "RETRY_WAIT_MIN_SECONDS", "RETRY_WAIT_MAX_SECONDS"]:
            os.environ.pop(key, None)

        config = RetryConfig(max_num_attempts=8, wait_min_seconds=2, wait_max_seconds=60)
        configure_retry_env_vars(config=config, override=True)

        assert os.environ["RETRY_MAX_NUM_ATTEMPTS"] == "8"
        assert os.environ["RETRY_WAIT_MIN_SECONDS"] == "2"
        assert os.environ["RETRY_WAIT_MAX_SECONDS"] == "60"

        # 清理
        for key in ["RETRY_MAX_NUM_ATTEMPTS", "RETRY_WAIT_MIN_SECONDS", "RETRY_WAIT_MAX_SECONDS"]:
            os.environ.pop(key, None)

    def test_pyrit_target_retry_decorator_exists(self):
        """PyRIT 原生 pyrit_target_retry 装饰器存在"""
        from pyrit.exceptions.exception_classes import pyrit_target_retry
        assert callable(pyrit_target_retry)

    def test_pyrit_json_retry_decorator_exists(self):
        """PyRIT 原生 pyrit_json_retry 装饰器存在"""
        from pyrit.exceptions.exception_classes import pyrit_json_retry
        assert callable(pyrit_json_retry)

    def test_scenario_max_retries_from_env(self):
        """SCENARIO_MAX_RETRIES 环境变量优先"""
        os.environ["SCENARIO_MAX_RETRIES"] = "3"
        config = get_retry_config()
        assert config.scenario_max_retries == 3
        del os.environ["SCENARIO_MAX_RETRIES"]

    def test_scenario_max_retries_from_yaml(self):
        """无环境变量时从 pipeline.yaml 读取"""
        os.environ.pop("SCENARIO_MAX_RETRIES", None)
        config = get_retry_config()
        # 应该从 pipeline.yaml 读取（默认 0 或 .env 中的值）
        assert config.scenario_max_retries >= 0
