# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""流水线阶段包。

阶段文件以 *_stage.py 命名, 由 recon-main.py 通过 importlib 动态发现并注册,
无需在此静态导入。新增阶段只需在本目录放置继承 PipelineStage 的 *_stage.py 文件。
"""
