"""
Pipeline Stages — 8 阶段模块
============================

每个模块是一个独立的 async run(ctx) 函数，接收 PipelineContext 并修改其字段。
编排器按顺序调用各阶段。
"""
