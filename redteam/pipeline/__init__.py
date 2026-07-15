"""AI-300 红队攻击流水线模块（Pipeline）。

基于 OffSec AI-300 课程 11 章的完整攻击链编排，对齐 OSAI+ 认证考试要求。

目录结构：
  - __init__.py: 统一导出入口
  - runner.py: 主流水线编排器（含 YAML 配置驱动模式）
  - runner_display.py: 显示工具函数（速率限制建议等）
  - runner_extensions.py: 扩展方法 Mixin（阶段快捷方法、场景驱动）
    - execution/: 攻击执行层（Phase 0~11）
      recon_phase.py, injection_phase.py, agent_phase.py,
      multi_agent_phase.py, rag_phase.py, embeddings_phase.py,
      supply_chain_phase.py, infra_phase.py, threat_modeling_phase.py
      exploit/: 利用证明管线（Detect→Exploit 双阶段闭环，8/8 类别全覆盖）
        registry.py, common.py, embeddings.py, injection.py,
        agent_exploit.py, rag.py, supply_chain.py, infra.py, mcp_exploit.py
  - reporting/: 报告产出管线（增量写入 + 正式出版）
      writer.py, publisher.py

设计原则：
  - Library-First：所有 HTTP/探测能力委托 httpx + 成熟工具
  - 渐进式：每一步基于上一步的发现推进
  - 失败隔离：单阶段失败不阻断后续阶段
  - 结果持久化：每个阶段产出 JSON checkpoint
  - YAML 驱动：支持 config/pipeline.yaml 配置驱动模式（考试推荐）
"""

from .runner import AIPipeline

__all__ = [
    "AIPipeline",
]
