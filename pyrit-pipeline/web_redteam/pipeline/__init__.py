# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""流水线层: 五阶段串联，阶段间通过 Context 解耦。."""

from web_redteam.pipeline.context import WebRedTeamContext

__all__ = ["WebRedTeamContext"]
