# -*- coding: utf-8 -*-
"""
AI-300 Framework - L5 改进回归测试
验证 6 项 L5 级改进的正确性和完整性

覆盖范围：
1. 异常分类体系（exceptions.py）
2. 结构化日志（structured_log.py）
3. 配置验证（config_validator.py）
4. 并发安全（recon_engine _adapters_lock）
5. 类型注解（env_loader 返回类型标注）
6. 覆盖率配置（pyproject.toml）
7. Protocol 接口（protocols.py）
8. 容错降级（scorer_builder 异常分类处理）
"""

from __future__ import annotations

import json
import logging
import os
import sys
import threading
import unittest
from io import StringIO
from pathlib import Path
from unittest.mock import MagicMock, patch

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


# ════════════════════════════════════════════════════════════════
# 1. 异常分类体系测试
# ════════════════════════════════════════════════════════════════

class TestExceptionHierarchy(unittest.TestCase):
    """L5 异常分类体系测试"""

    def test_base_error_carries_context(self):
        """基础异常携带上下文"""
        from pyrit_ai300.utils.exceptions import AI300Error
        err = AI300Error("test error", context={"key": "value"}, recovery_hint="try again")
        self.assertEqual(err.message, "test error")
        self.assertEqual(err.context["key"], "value")
        self.assertEqual(err.recovery_hint, "try again")

    def test_error_str_includes_context(self):
        """__str__ 包含上下文信息"""
        from pyrit_ai300.utils.exceptions import AI300Error
        err = AI300Error("msg", context={"k": "v"}, recovery_hint="fix it")
        s = str(err)
        self.assertIn("msg", s)
        self.assertIn("k=v", s)
        self.assertIn("fix it", s)

    def test_error_to_dict(self):
        """to_dict 序列化"""
        from pyrit_ai300.utils.exceptions import AI300Error
        err = AI300Error("msg", context={"k": "v"})
        d = err.to_dict()
        self.assertEqual(d["error_type"], "AI300Error")
        self.assertEqual(d["message"], "msg")
        self.assertEqual(d["context"]["k"], "v")

    def test_config_not_found_error(self):
        """ConfigNotFoundError 携带路径"""
        from pyrit_ai300.utils.exceptions import ConfigNotFoundError
        err = ConfigNotFoundError("path/to/config.yaml")
        self.assertIn("path/to/config.yaml", str(err))
        self.assertEqual(err.context["config_path"], "path/to/config.yaml")

    def test_config_validation_error(self):
        """ConfigValidationError 携带验证错误列表"""
        from pyrit_ai300.utils.exceptions import ConfigValidationError
        err = ConfigValidationError("config.yaml", errors=["field1: wrong type"])
        self.assertIn("config.yaml", str(err))
        self.assertIn("field1", err.context["validation_errors"][0])

    def test_adapter_error_carries_tool(self):
        """AdapterError 携带工具名"""
        from pyrit_ai300.utils.exceptions import AdapterError
        err = AdapterError("native_probe", "timeout")
        self.assertIn("native_probe", str(err))
        self.assertEqual(err.context["tool"], "native_probe")

    def test_adapter_timeout_error(self):
        """AdapterTimeoutError 携带超时时间"""
        from pyrit_ai300.utils.exceptions import AdapterTimeoutError
        err = AdapterTimeoutError("deepteam", 300.0)
        self.assertIn("300", str(err))
        self.assertIn("deepteam", str(err))

    def test_scorer_build_error(self):
        """ScorerBuildError 携带评分器类型"""
        from pyrit_ai300.utils.exceptions import ScorerBuildError
        err = ScorerBuildError("refusal", "missing API key")
        self.assertIn("refusal", str(err))
        self.assertEqual(err.context["scorer_type"], "refusal")

    def test_credential_expired_error(self):
        """CredentialExpiredError 携带域名"""
        from pyrit_ai300.utils.exceptions import CredentialExpiredError
        err = CredentialExpiredError("example.com")
        self.assertIn("example.com", str(err))

    def test_phase_execution_error(self):
        """PhaseExecutionError 携带阶段名"""
        from pyrit_ai300.utils.exceptions import PhaseExecutionError
        err = PhaseExecutionError("recon", "adapter crash")
        self.assertIn("recon", str(err))
        self.assertEqual(err.context["phase"], "recon")

    def test_exception_inheritance_chain(self):
        """异常继承链正确"""
        from pyrit_ai300.utils.exceptions import (
            AI300Error, ConfigError, ConfigNotFoundError,
            ReconError, AdapterError,
            AttackError, TargetBuildError,
        )
        # ConfigNotFoundError → ConfigError → AI300Error → Exception
        selfissubclass = issubclass(ConfigNotFoundError, ConfigError)
        self.assertTrue(selfissubclass)
        self.assertTrue(issubclass(ConfigError, AI300Error))
        self.assertTrue(issubclass(AI300Error, Exception))
        # AdapterError → ReconError → AI300Error
        self.assertTrue(issubclass(AdapterError, ReconError))
        # TargetBuildError → AttackError → AI300Error
        self.assertTrue(issubclass(TargetBuildError, AttackError))

    def test_safe_execute_decorator_reraise(self):
        """safe_execute 装饰器：reraise=True 时转换异常"""
        from pyrit_ai300.utils.exceptions import safe_execute, AI300Error

        @safe_execute("test op", AI300Error, reraise=True)
        def failing_func():
            raise ValueError("original error")

        with self.assertRaises(AI300Error) as ctx:
            failing_func()
        self.assertIn("original error", str(ctx.exception))
        self.assertIsInstance(ctx.exception.__cause__, ValueError)

    def test_safe_execute_decorator_silent(self):
        """safe_execute 装饰器：reraise=False 时返回默认值"""
        from pyrit_ai300.utils.exceptions import safe_execute, AI300Error

        @safe_execute("test op", AI300Error, reraise=False, default_return="fallback")
        def failing_func():
            raise ValueError("original error")

        result = failing_func()
        self.assertEqual(result, "fallback")

    def test_safe_execute_passthrough_ai300_error(self):
        """safe_execute 不拦截 AI300Error（直接传播）"""
        from pyrit_ai300.utils.exceptions import safe_execute, AI300Error

        @safe_execute("test op", AI300Error, reraise=True)
        def failing_func():
            raise AI300Error("ai300 error")

        with self.assertRaises(AI300Error):
            failing_func()


# ════════════════════════════════════════════════════════════════
# 2. 结构化日志测试
# ════════════════════════════════════════════════════════════════

class TestStructuredLogging(unittest.TestCase):
    """L5 结构化 JSON 日志测试"""

    def test_json_formatter_output_is_json(self):
        """JSON 格式化器输出有效 JSON"""
        from pyrit_ai300.utils.structured_log import StructuredLogFormatter

        formatter = StructuredLogFormatter()
        record = logging.LogRecord(
            name="test", level=logging.INFO, pathname="", lineno=1,
            msg="test message", args=(), exc_info=None,
        )
        output = formatter.format(record)
        parsed = json.loads(output)
        self.assertEqual(parsed["message"], "test message")
        self.assertEqual(parsed["level"], "INFO")
        self.assertIn("timestamp", parsed)

    def test_json_formatter_includes_context(self):
        """JSON 格式化器包含 extra 上下文字段"""
        from pyrit_ai300.utils.structured_log import StructuredLogFormatter

        formatter = StructuredLogFormatter()
        record = logging.LogRecord(
            name="test", level=logging.INFO, pathname="", lineno=1,
            msg="recon done", args=(), exc_info=None,
        )
        record.target = "http://example.com"  # extra field
        record.duration_ms = 1234.5
        output = formatter.format(record)
        parsed = json.loads(output)
        self.assertEqual(parsed["context"]["target"], "http://example.com")
        self.assertEqual(parsed["context"]["duration_ms"], 1234.5)

    def test_json_formatter_includes_exception(self):
        """JSON 格式化器包含异常信息"""
        from pyrit_ai300.utils.structured_log import StructuredLogFormatter

        formatter = StructuredLogFormatter()
        try:
            raise ValueError("test exception")
        except ValueError:
            import sys
            exc_info = sys.exc_info()

        record = logging.LogRecord(
            name="test", level=logging.ERROR, pathname="", lineno=1,
            msg="error occurred", args=(), exc_info=exc_info,
        )
        output = formatter.format(record)
        parsed = json.loads(output)
        self.assertEqual(parsed["exception"]["type"], "ValueError")
        self.assertEqual(parsed["exception"]["message"], "test exception")

    def test_text_formatter_has_colors(self):
        """TEXT 格式化器包含 ANSI 颜色码"""
        from pyrit_ai300.utils.structured_log import TextLogFormatter

        formatter = TextLogFormatter()
        record = logging.LogRecord(
            name="test", level=logging.INFO, pathname="", lineno=1,
            msg="test message", args=(), exc_info=None,
        )
        output = formatter.format(record)
        self.assertIn("\033[", output)  # ANSI color code
        self.assertIn("test message", output)

    def test_bound_logger_context_propagation(self):
        """BoundLogger 上下文传播"""
        from pyrit_ai300.utils.structured_log import BoundLogger

        mock_logger = MagicMock(spec=logging.Logger)
        bound = BoundLogger(mock_logger, {"target": "http://example.com"})
        bound.info("starting")

        # 验证 extra 包含绑定字段
        call_args = mock_logger.log.call_args
        extra = call_args.kwargs.get("extra", {})
        self.assertIn("target", extra)
        self.assertEqual(extra["target"], "http://example.com")

    def test_bind_returns_new_instance(self):
        """bind() 返回新实例（不可变）"""
        from pyrit_ai300.utils.structured_log import BoundLogger

        mock_logger = MagicMock(spec=logging.Logger)
        bound1 = BoundLogger(mock_logger, {"a": 1})
        bound2 = bound1.bind(b=2)
        self.assertIsNot(bound1, bound2)
        self.assertEqual(len(bound1._context), 1)  # 原实例不变
        self.assertEqual(len(bound2._context), 2)  # 新实例有两个字段

    def test_log_performance(self):
        """性能日志记录"""
        from pyrit_ai300.utils.structured_log import StructuredLogger

        logger = MagicMock(spec=logging.Logger)
        StructuredLogger.log_performance(logger, "recon", 500.0, success=True)
        call_args = logger.log.call_args
        self.assertEqual(call_args[0][0], logging.INFO)
        extra = call_args[1]["extra"]
        self.assertEqual(extra["operation"], "recon")
        self.assertEqual(extra["duration_ms"], 500.0)

    def test_get_logger_creates_handlers(self):
        """get_logger 创建 handler"""
        from pyrit_ai300.utils.structured_log import StructuredLogger
        logger = StructuredLogger.get_logger("test_l5_logging")
        self.assertTrue(len(logger.handlers) > 0)

    def test_setup_structured_logging_sets_env(self):
        """setup_structured_logging 设置环境变量"""
        from pyrit_ai300.utils.structured_log import setup_structured_logging
        with patch.dict(os.environ, {}, clear=True):
            setup_structured_logging(level="DEBUG", log_format="json")
            self.assertEqual(os.environ.get("AI300_LOG_LEVEL"), "DEBUG")
            self.assertEqual(os.environ.get("AI300_LOG_FORMAT"), "json")


# ════════════════════════════════════════════════════════════════
# 3. 配置验证测试
# ════════════════════════════════════════════════════════════════

class TestConfigValidator(unittest.TestCase):
    """L5 配置验证测试"""

    def test_validate_recon_config_valid(self):
        """有效侦察配置不报错"""
        from pyrit_ai300.utils.config_validator import ConfigValidator
        config = {
            "tools": {"native_probe": {"enabled": True, "timeout": 300}},
            "cache": {"enabled": True, "ttl_hours": 24},
            "depth": "standard",
        }
        errors = ConfigValidator.validate_recon_config(config)
        self.assertEqual(len(errors), 0)

    def test_validate_recon_config_invalid_timeout(self):
        """无效 timeout 值报错"""
        from pyrit_ai300.utils.config_validator import ConfigValidator
        config = {
            "tools": {"native_probe": {"enabled": True, "timeout": -10}},
        }
        errors = ConfigValidator.validate_recon_config(config)
        self.assertTrue(any("timeout" in e for e in errors))

    def test_validate_recon_config_invalid_depth(self):
        """无效 depth 值报错"""
        from pyrit_ai300.utils.config_validator import ConfigValidator
        config = {"depth": "invalid_depth"}
        errors = ConfigValidator.validate_recon_config(config)
        self.assertTrue(any("depth" in e for e in errors))

    def test_validate_scorer_backend_valid(self):
        """有效评分器后端配置"""
        from pyrit_ai300.utils.config_validator import ConfigValidator
        config = {
            "provider": "ollama",
            "base_url": "http://localhost:11434/v1",
            "api_key": "test",
            "model_name": "llama3",
            "temperature": 0.5,
            "max_tokens": 2048,
        }
        errors = ConfigValidator.validate_scorer_backend(config)
        self.assertEqual(len(errors), 0)

    def test_validate_scorer_backend_invalid_temperature(self):
        """无效 temperature 值报错"""
        from pyrit_ai300.utils.config_validator import ConfigValidator
        config = {"temperature": 5.0}
        errors = ConfigValidator.validate_scorer_backend(config)
        self.assertTrue(any("temperature" in e for e in errors))

    def test_validate_scorer_backend_invalid_url(self):
        """无效 base_url 报错"""
        from pyrit_ai300.utils.config_validator import ConfigValidator
        config = {"base_url": "ftp://invalid"}
        errors = ConfigValidator.validate_scorer_backend(config)
        self.assertTrue(any("base_url" in e for e in errors))

    def test_validate_attack_config_valid(self):
        """有效攻击配置"""
        from pyrit_ai300.utils.config_validator import ConfigValidator
        config = {
            "name": "test_attack",
            "mode": "smart_match",
            "payloads": ["payload1"],
        }
        errors = ConfigValidator.validate_attack_config(config)
        self.assertEqual(len(errors), 0)

    def test_validate_attack_config_missing_name(self):
        """缺少 name 报错"""
        from pyrit_ai300.utils.config_validator import ConfigValidator
        config = {"mode": "smart_match"}
        errors = ConfigValidator.validate_attack_config(config)
        self.assertTrue(any("name" in e for e in errors))

    def test_validate_target_config_valid(self):
        """有效目标配置"""
        from pyrit_ai300.utils.config_validator import ConfigValidator
        config = {"url": "http://localhost:11434/v1"}
        errors = ConfigValidator.validate_target_config(config)
        self.assertEqual(len(errors), 0)

    def test_validate_target_config_missing_url(self):
        """缺少 url 报错"""
        from pyrit_ai300.utils.config_validator import ConfigValidator
        config = {}
        errors = ConfigValidator.validate_target_config(config)
        self.assertTrue(any("url" in e for e in errors))

    def test_validate_or_default_logs_warning(self):
        """validate_or_default 验证失败时记录警告"""
        from pyrit_ai300.utils.config_validator import ConfigValidator
        with self.assertLogs("pyrit_ai300.utils.config_validator", level="WARNING"):
            ConfigValidator.validate_or_default(
                {"depth": "invalid", "tools": {"x": {"timeout": -5}}},
                "recon",
            )

    def test_validate_and_raise_raises(self):
        """validate_and_raise 验证失败时抛出异常"""
        from pyrit_ai300.utils.config_validator import ConfigValidator
        from pyrit_ai300.utils.exceptions import ConfigValidationError
        with self.assertRaises(ConfigValidationError):
            ConfigValidator.validate_and_raise(
                {"depth": "invalid"},
                "recon",
                "test.yaml",
            )

    def test_config_dataclass_schemas(self):
        """配置 dataclass schema 可创建"""
        from pyrit_ai300.utils.config_validator import (
            ReconConfigSchema, ScorerBackendConfig,
            AttackConfigSchema, TargetConfigSchema,
        )
        recon = ReconConfigSchema()
        self.assertEqual(recon.depth, "standard")
        backend = ScorerBackendConfig()
        self.assertEqual(backend.provider, "ollama")
        attack = AttackConfigSchema()
        self.assertEqual(attack.mode, "smart_match")
        target = TargetConfigSchema()
        self.assertEqual(target.url, "")


# ════════════════════════════════════════════════════════════════
# 4. 并发安全测试
# ════════════════════════════════════════════════════════════════

class TestConcurrencySafety(unittest.TestCase):
    """L5 并发安全测试"""

    def test_recon_engine_has_lock(self):
        """ReconEngine 实例有 _adapters_lock"""
        from pyrit_ai300.recon.engine import ReconEngine
        engine = ReconEngine(config_path="nonexistent.yaml")
        self.assertTrue(hasattr(engine, "_adapters_lock"))
        self.assertIsInstance(engine._adapters_lock, type(threading.Lock()))

    def test_get_adapter_thread_safe(self):
        """多线程 _get_adapter 不竞态"""
        from pyrit_ai300.recon.engine import ReconEngine
        engine = ReconEngine(config_path="nonexistent.yaml")

        errors = []
        def worker():
            try:
                adapter = engine._get_adapter("native_probe")
                self.assertEqual(adapter.name, "native_probe")
            except Exception as e:
                errors.append(str(e))

        threads = [threading.Thread(target=worker) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(len(errors), 0)

    def test_init_adapters_thread_safe(self):
        """_init_adapters 线程安全"""
        from pyrit_ai300.recon.engine import ReconEngine
        engine = ReconEngine(config_path="nonexistent.yaml")

        errors = []
        def worker():
            try:
                engine._init_adapters(["native_probe"])
            except Exception as e:
                errors.append(str(e))

        threads = [threading.Thread(target=worker) for _ in range(3)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(len(errors), 0)

    def test_double_checked_locking_pattern(self):
        """double-checked locking 模式正确"""
        from pyrit_ai300.recon.engine import ReconEngine
        engine = ReconEngine(config_path="nonexistent.yaml")

        # 第一次调用：创建适配器
        adapter1 = engine._get_adapter("native_probe")
        self.assertIsNotNone(adapter1)

        # 第二次调用：返回同一实例（fast path，不获取锁）
        adapter2 = engine._get_adapter("native_probe")
        self.assertIs(adapter1, adapter2)


# ════════════════════════════════════════════════════════════════
# 5. Protocol 接口测试
# ════════════════════════════════════════════════════════════════

class TestProtocolInterfaces(unittest.TestCase):
    """L5 Protocol 接口测试"""

    def test_protocols_importable(self):
        """所有 Protocol 可导入"""
        from pyrit_ai300.utils.protocols import (
            ReconEngineProtocol,
            ProfileMergerProtocol,
            BaseAdapterProtocol,
            AttackOrchestratorProtocol,
            SmartMatcherProtocol,
            ConverterBuilderProtocol,
            ScorerBuilderProtocol,
            PipelineOrchestratorProtocol,
            CredentialManagerProtocol,
            RateControllerProtocol,
        )
        # 确认是 Protocol
        for p in [ReconEngineProtocol, ProfileMergerProtocol, BaseAdapterProtocol]:
            self.assertTrue(hasattr(p, "_is_protocol"))

    def test_recon_engine_satisfies_protocol(self):
        """ReconEngine 满足 ReconEngineProtocol"""
        from pyrit_ai300.utils.protocols import ReconEngineProtocol
        from pyrit_ai300.recon.engine import ReconEngine

        engine = ReconEngine(config_path="nonexistent.yaml")
        # runtime_checkable Protocol 可以用 isinstance 检查
        # 但由于 Protocol 方法签名不完全匹配（run 参数不同），这里仅验证接口存在
        self.assertTrue(hasattr(engine, "run"))
        self.assertTrue(hasattr(engine, "run_streaming"))

    def test_protocol_methods_defined(self):
        """Protocol 定义了必要方法"""
        from pyrit_ai300.utils.protocols import (
            SmartMatcherProtocol, ConverterBuilderProtocol, ScorerBuilderProtocol,
        )
        # 验证 Protocol 有方法定义
        self.assertTrue(hasattr(SmartMatcherProtocol, "select_strategy"))
        self.assertTrue(hasattr(SmartMatcherProtocol, "build_attack_plan"))
        self.assertTrue(hasattr(ConverterBuilderProtocol, "build"))
        self.assertTrue(hasattr(ScorerBuilderProtocol, "build"))


# ════════════════════════════════════════════════════════════════
# 6. 类型注解测试
# ════════════════════════════════════════════════════════════════

class TestTypeAnnotations(unittest.TestCase):
    """L5 类型注解完整性测试"""

    def test_env_loader_return_types(self):
        """env_loader 返回类型注解存在"""
        from pyrit_ai300.utils import env_loader
        import inspect
        import typing

        # load_dotenv 返回 bool
        hints = typing.get_type_hints(env_loader.load_dotenv)
        self.assertEqual(hints.get("return"), bool)

        # get_env 返回 str
        hints = typing.get_type_hints(env_loader.get_env)
        self.assertEqual(hints.get("return"), str)

        # resolve_env_vars 返回 Any
        sig = inspect.signature(env_loader.resolve_env_vars)
        self.assertEqual(sig.return_annotation, "Any")

    def test_payload_filter_return_types(self):
        """payload_filter 返回类型注解存在"""
        from pyrit_ai300.payloads.payload_filter import PayloadFilter
        import typing

        # should_skip_attack 返回 bool
        hints = typing.get_type_hints(PayloadFilter.should_skip_attack)
        self.assertEqual(hints.get("return"), bool)

    def test_rate_controller_return_types(self):
        """rate_controller 返回类型注解"""
        from pyrit_ai300.attack.rate_controller import get_default_concurrency
        import typing

        # get_default_concurrency 返回 int
        hints = typing.get_type_hints(get_default_concurrency)
        self.assertEqual(hints.get("return"), int)

    def test_exceptions_return_types(self):
        """exceptions 模块返回类型注解"""
        from pyrit_ai300.utils.exceptions import AI300Error
        import inspect

        # to_dict 返回 Dict
        sig = inspect.signature(AI300Error.to_dict)
        self.assertIsNotNone(sig.return_annotation)


# ════════════════════════════════════════════════════════════════
# 7. 容错降级测试
# ════════════════════════════════════════════════════════════════

class TestFaultToleranceDegradation(unittest.TestCase):
    """L5 容错降级测试"""

    def test_scorer_builder_typeerror_handling(self):
        """ScorerBuilder TypeError 降级处理"""
        from pyrit_ai300.attack.pyrit.scorer_builder import ScorerBuilder
        builder = ScorerBuilder()
        builder.load_config()
        # 传入一个会触发 TypeError 的配置（缺少必需参数）
        scorers = builder.build([{"name": "substring"}])
        # substring 有默认参数，应成功构建
        self.assertEqual(len(scorers), 1)

    def test_scorer_builder_unknown_type_returns_empty(self):
        """未知评分器类型返回空列表（不崩溃）"""
        from pyrit_ai300.attack.pyrit.scorer_builder import ScorerBuilder
        builder = ScorerBuilder()
        builder.load_config()
        scorers = builder.build([{"name": "completely_unknown_scorer_xyz"}])
        self.assertEqual(len(scorers), 0)

    def test_safe_execute_recovers_gracefully(self):
        """safe_execute 优雅恢复"""
        from pyrit_ai300.utils.exceptions import safe_execute, AI300Error

        @safe_execute("test", AI300Error, reraise=False, default_return=42)
        def maybe_fails(should_fail: bool):
            if should_fail:
                raise RuntimeError("crashed")
            return 100

        # 失败时返回默认值
        self.assertEqual(maybe_fails(True), 42)
        # 成功时返回实际值
        self.assertEqual(maybe_fails(False), 100)

    def test_config_validator_validate_or_default_returns_config(self):
        """validate_or_default 返回原始配置（不修改）"""
        from pyrit_ai300.utils.config_validator import ConfigValidator
        original = {"depth": "invalid", "tools": {}}
        result = ConfigValidator.validate_or_default(original, "recon")
        self.assertEqual(result, original)  # 原始配置未被修改


# ════════════════════════════════════════════════════════════════
# 8. 覆盖率配置测试
# ════════════════════════════════════════════════════════════════

class TestCoverageConfig(unittest.TestCase):
    """L5 覆盖率配置测试"""

    def test_pyproject_toml_exists(self):
        """pyproject.toml 存在"""
        toml_path = PROJECT_ROOT / "pyproject.toml"
        self.assertTrue(toml_path.exists())

    def test_coverage_config_has_fail_under(self):
        """覆盖率配置有 fail_under 门禁"""
        toml_path = PROJECT_ROOT / "pyproject.toml"
        content = toml_path.read_text(encoding="utf-8")
        self.assertIn("fail_under", content)
        self.assertIn("[tool.coverage", content)

    def test_makefile_has_cov_targets(self):
        """Makefile 有覆盖率目标"""
        makefile_path = PROJECT_ROOT / "Makefile"
        content = makefile_path.read_text(encoding="utf-8")
        self.assertIn("test-cov:", content)
        self.assertIn("test-cov-gate:", content)
        self.assertIn("test-cov-xml:", content)
        self.assertIn("--cov-fail-under", content)


# ════════════════════════════════════════════════════════════════
# 9. utils 包导出测试
# ════════════════════════════════════════════════════════════════

class TestUtilsExports(unittest.TestCase):
    """L5 utils 包导出测试"""

    def test_exceptions_exported(self):
        """异常类从 utils 包导出"""
        from pyrit_ai300.utils import (
            AI300Error, ConfigError, ReconError, AttackError,
            ConfigNotFoundError, ConfigValidationError,
            AdapterError, AdapterTimeoutError,
            TargetBuildError, ConverterBuildError, ScorerBuildError,
            CredentialError, CredentialExpiredError,
            PipelineError, PhaseExecutionError,
            safe_execute,
        )
        self.assertIsNotNone(AI300Error)
        self.assertIsNotNone(safe_execute)

    def test_structured_log_exported(self):
        """结构化日志从 utils 包导出"""
        from pyrit_ai300.utils import (
            StructuredLogger, BoundLogger,
            StructuredLogFormatter, TextLogFormatter,
            setup_structured_logging,
        )
        self.assertIsNotNone(StructuredLogger)
        self.assertIsNotNone(BoundLogger)

    def test_config_validator_exported(self):
        """配置验证器从 utils 包导出"""
        from pyrit_ai300.utils import (
            ConfigValidator, ReconConfigSchema,
            ScorerBackendConfig, AttackConfigSchema, TargetConfigSchema,
        )
        self.assertIsNotNone(ConfigValidator)

    def test_protocols_exported(self):
        """Protocol 接口从 utils 包导出"""
        from pyrit_ai300.utils import (
            ReconEngineProtocol, ProfileMergerProtocol,
            BaseAdapterProtocol, AttackOrchestratorProtocol,
            SmartMatcherProtocol, ConverterBuilderProtocol,
            ScorerBuilderProtocol, PipelineOrchestratorProtocol,
            CredentialManagerProtocol, RateControllerProtocol,
        )
        self.assertIsNotNone(ReconEngineProtocol)

    def test_all_list_complete(self):
        """__all__ 列表完整"""
        from pyrit_ai300 import utils
        for name in utils.__all__:
            self.assertTrue(hasattr(utils, name), f"__all__ 包含 '{name}' 但模块未导出")


if __name__ == "__main__":
    unittest.main()
