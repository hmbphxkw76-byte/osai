"""
Pipeline Display — 统一展示层
==============================

为 Pipeline 提供噪音日志过滤和适配链决策展示。

设计原则：
  - PyRIT 原生优先：使用原生 output 模块（output_attack_async / StdoutSink）
  - 分离关注点：展示逻辑与执行逻辑完全分离
  - 安全调用：所有展示函数 catch 异常，绝不影响 pipeline 执行
  - 噪音过滤：将 PyRIT 内部 DEBUG/INFO 日志重定向到文件
"""

import logging
from pathlib import Path
from typing import Optional, Union

logger = logging.getLogger(__name__)


# ============================================================
# PyRIT 噪音日志过滤
# ============================================================

# PyRIT 内部日志中常见的噪音模式（这些日志不应出现在用户终端）
# 涵盖原生初始化器输出 + 自建初始化器非致命警告
_PYRIT_NOISE_PATTERNS: list[str] = [
    # 原生 ScorerInitializer / TargetInitializer 跳过消息
    "Skipping scorer",
    "required target not found in TargetRegistry",
    "No scorers in category",
    "No composite scorers available",
    "TargetRegistry entry",
    "not found. Falling back",
    # 原生 PreloadScenarioMetadata 预热失败（无 OPENAI_CHAT_MODEL 时正常）
    "PreloadScenarioMetadata failed",
    "OPENAI_CHAT_MODEL is required",
    # 运行时噪音
    "No scoring configuration",
    "Empty response, retrying",
    "Rate limit hit, retrying",
    "Retrying request",
    "Using fallback",
    "Generator returned empty",
    "Response was empty",
    "json validation failed",
    "Invalid JSON",
]


class PyRITNoiseFilter(logging.Filter):
    """
    PyRIT 噪音日志过滤器

    将匹配噪音模式的 PyRIT DEBUG/INFO 日志重定向到文件，
    而不是打印到终端，保持终端输出的清晰度。
    """

    def __init__(self, redirect_path: Optional[str] = None):
        super().__init__()
        self._redirect_path = redirect_path
        self._file_handler: Optional[logging.FileHandler] = None
        if redirect_path:
            try:
                self._file_handler = logging.FileHandler(redirect_path, encoding="utf-8")
                self._file_handler.setLevel(logging.DEBUG)
            except Exception:
                self._file_handler = None

    def filter(self, record: logging.LogRecord) -> bool:
        """过滤噪音日志"""
        msg = record.getMessage().lower()
        for pattern in _PYRIT_NOISE_PATTERNS:
            if pattern.lower() in msg:
                if self._file_handler:
                    self._file_handler.emit(record)
                return False
        return True


# ============================================================
# Pipeline 展示器
# ============================================================


class PipelineDisplay:
    """
    Pipeline 统一展示器

    提供：
    1. PyRIT 噪音日志过滤
    2. 适配链决策展示
    """

    STAGE_TOTAL = 7

    def __init__(self, stage_total: int = 7):
        self.stage_total = stage_total
        self._noise_filter: Optional[PyRITNoiseFilter] = None

    # ----------------------------------------------------------
    # 适配链展示
    # ----------------------------------------------------------

    def display_adaptation_chain(
        self,
        target_type: str = "",
        target_group: str = "",
        model_tier: str = "",
        strategy_mode: str = "",
        converter_chains: Optional[list[str]] = None,
        attack_techniques: Optional[list[str]] = None,
    ) -> None:
        """
        展示适配链关键决策

        在阶段 6 中调用，展示从 Recon → Analysis → Converters → Executor
        的完整适配链传递结果。
        """
        print("\n  ┌─ 适配链决策 ─────────────────────────────────────┐")
        if target_type:
            print(f"  │ Target 类型:   {target_type}")
        if target_group:
            print(f"  │ Target 分组:   {target_group}")
        if model_tier:
            print(f"  │ 模型分层:     {model_tier}")
        if strategy_mode:
            print(f"  │ 策略模式:     {strategy_mode}")
        if converter_chains:
            chains_str = ", ".join(converter_chains[:5])
            if len(converter_chains) > 5:
                chains_str += f" ... (+{len(converter_chains) - 5})"
            print(f"  │ Converter 链: {chains_str}")
        if attack_techniques:
            tech_str = ", ".join(attack_techniques[:5])
            if len(attack_techniques) > 5:
                tech_str += f" ... (+{len(attack_techniques) - 5})"
            print(f"  │ 攻击技术:     {tech_str}")
        print("  └──────────────────────────────────────────────────┘")

    # ----------------------------------------------------------
    # 噪音过滤安装
    # ----------------------------------------------------------

    def install_noise_filter(self, log_path: Optional[Union[str, Path]] = None) -> None:
        """安装 PyRIT 噪音日志过滤器

        关键：Python logging 传播机制中，父 Logger 的 Filter 不会被检查，
        只有 Handler 的 Filter 会被检查。因此必须将过滤器安装到 Handler 上，
        而非 Logger 上。

        安装位置：
        1. logging.lastResort — Python 兜底 handler（无其他 handler 时使用）
        2. pyrit 原生 logger (ai-red-team) 的所有 handler
        3. root logger 的所有 handler（如有）
        """
        redirect_path = None
        if log_path:
            log_path_str = str(log_path)
            base = log_path_str.rsplit(".", 1)
            redirect_path = f"{base[0]}.noise.{base[1]}" if len(base) > 1 else f"{log_path_str}.noise"

        self._noise_filter = PyRITNoiseFilter(redirect_path=redirect_path)

        try:
            # 1. 安装到 lastResort handler（Python 兜底 handler）
            # 当 pyrit.* 子 logger 的消息找不到 handler 时，走 lastResort → stderr
            if logging.lastResort is not None:
                logging.lastResort.addFilter(self._noise_filter)

            # 2. 安装到 pyrit 原生 logger (ai-red-team) 的所有 handler
            try:
                from pyrit.common.logger import logger as _pyrit_native_logger
                for h in _pyrit_native_logger.handlers:
                    h.addFilter(self._noise_filter)
            except Exception:
                pass

            # 3. 安装到 root logger 的所有 handler（如有）
            root_logger = logging.getLogger()
            for h in root_logger.handlers:
                h.addFilter(self._noise_filter)

            # 4. 也安装到 logger 上（直接在 pyrit/src.setup logger 上 log 的消息）
            logging.getLogger("pyrit").addFilter(self._noise_filter)
            logging.getLogger("src.setup").addFilter(self._noise_filter)

            logger.debug("PyRIT noise filter installed (handlers + loggers)")
        except Exception as e:
            logger.debug(f"Failed to install noise filter: {e}")

    def uninstall_noise_filter(self) -> None:
        """卸载 PyRIT 噪音日志过滤器"""
        if self._noise_filter:
            try:
                # 从 lastResort handler 移除
                if logging.lastResort is not None:
                    logging.lastResort.removeFilter(self._noise_filter)
                # 从 pyrit 原生 logger 的 handler 移除
                try:
                    from pyrit.common.logger import logger as _pyrit_native_logger
                    for h in _pyrit_native_logger.handlers:
                        h.removeFilter(self._noise_filter)
                except Exception:
                    pass
                # 从 root logger 的 handler 移除
                for h in logging.getLogger().handlers:
                    h.removeFilter(self._noise_filter)
                # 从 logger 移除
                logging.getLogger("pyrit").removeFilter(self._noise_filter)
                logging.getLogger("src.setup").removeFilter(self._noise_filter)
            except Exception:
                pass
            self._noise_filter = None


# ============================================================
# 便捷工厂函数
# ============================================================


_display_instance: Optional[PipelineDisplay] = None


def get_display(stage_total: int = 7) -> PipelineDisplay:
    """获取全局 PipelineDisplay 实例"""
    global _display_instance
    if _display_instance is None:
        _display_instance = PipelineDisplay(stage_total=stage_total)
    return _display_instance


def reset_display() -> None:
    """重置全局 PipelineDisplay 实例"""
    global _display_instance
    if _display_instance is not None:
        _display_instance.uninstall_noise_filter()
    _display_instance = None
