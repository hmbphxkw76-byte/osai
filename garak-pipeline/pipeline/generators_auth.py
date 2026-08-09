"""认证版 OpenAICompatible generator — 把认证头注入 garak

继承 garak 的 OpenAICompatible，仅重写 _load_unsafe 在构造 openai client 时
注入 extra_headers（如 {"Cookie": "..."}）。garak 源码不修改。

注意：garak 0.15.1 的 OpenAICompatible 仅接受 (name, config_root) 构造参数，
api_key 经 _config.plugins.generators[...] 注入，认证头则经本类 extra_headers 传入。
"""

from __future__ import annotations

import logging
import sys
from typing import Any

from garak import _config
from garak.generators.openai import OpenAICompatible

logger = logging.getLogger(__name__)


class AuthenticatedOpenAICompatible(OpenAICompatible):
    """支持自定义请求头（Cookie / Bearer）的 OpenAI 兼容 generator"""

    def __init__(
        self,
        name: str = "",
        config_root: Any = _config,
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        self._extra_headers = extra_headers or {}
        super().__init__(name, config_root)

    def _load_unsafe(self):
        # 纯 Cookie 认证场景下 api_key 可空，用占位避免 openai SDK 报错
        api_key = self.api_key or "cookie-auth"
        kwargs: dict[str, Any] = {
            "base_url": self.uri,
            "api_key": api_key,
        }
        if self._extra_headers:
            kwargs["default_headers"] = dict(self._extra_headers)
        import openai

        self.client = openai.OpenAI(**kwargs)
        if self.name in ("", None):
            raise ValueError(
                f"{self.generator_family_name} requires model name to be set"
            )
        self.generator = self.client.chat.completions


# garak 在写报告 / 生成 plugin_cache 时用 `plugin.__class__.__module__` 作为类别前缀。
# 本类位于 pipeline.generators_auth 包，__module__ 会被解析为 "pipeline.generators_auth"，
# 导致 garak 将其归类为 "pipeline" 类别插件——而 "pipeline" 不在 garak 的 PLUGIN_TYPES
# （probes/detectors/generators/harnesses）中，触发 `Not a recognised plugin type: pipeline`。
#
# 修复：把本类注册到 garak 的 generators.openai 模块命名空间，并将 __module__ 重写为
# "garak.generators.openai"。这样 garak 记录的 classpath 为
# "generators.openai.AuthenticatedOpenAICompatible"（合法 generators 类别），且 garak 的
# plugin_info 能通过 import 分支反射到本类（继承自 OpenAICompatible 的 metadata），不再报错。
import garak.generators.openai as _openai_mod

AuthenticatedOpenAICompatible.__module__ = "garak.generators.openai"
_openai_mod.AuthenticatedOpenAICompatible = AuthenticatedOpenAICompatible
sys.modules.setdefault("garak.generators.openai").__dict__[
    "AuthenticatedOpenAICompatible"
] = AuthenticatedOpenAICompatible
