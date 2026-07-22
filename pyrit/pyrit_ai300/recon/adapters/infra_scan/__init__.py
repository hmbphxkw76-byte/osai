# -*- coding: utf-8 -*-
"""
AI-300 Framework - Infrastructure Scan Adapter
AI 基础设施漏洞扫描适配器：集成 Nuclei 模板扫描 AI/ML 基础设施漏洞

组件：
  - InfraScanAdapter: 主适配器类
  - 检测维度：RCE / LFI / SSRF / CSRF / Path Traversal / Deserialization
  - 覆盖目标：Triton / MLflow / BentoML / Gradio / AnythingLLM / Ray / FastAPI / Flask
"""
from .adapter import InfraScanAdapter

__all__ = ["InfraScanAdapter"]
