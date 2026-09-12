# -*- coding: utf-8 -*-
"""strike/multimodal_upload - 多模态 / 文件上传攻击面（组件实现）

组件声明：`config/components/multimodal_upload.yaml`（component_key = multimodal_upload）。
攻击形状：**构造 → 上传 → 触发 → 验证** 四步链（multipart 上传 + 二次触发端点），
区别于单轮 prompt 面——这是本组件作为独立组件登记的依据（CP-004 §8.2 / P1-R2）。

学术依据：
    - Greshake et al. (arXiv:2302.12173) — 间接 Prompt 注入（文档载体）
    - Zou et al. (arXiv:2406.04245) — PoisonedRAG（知识库投毒）
    - Shayegani et al. (arXiv:2306.13254) — 多模态文档载体
"""
