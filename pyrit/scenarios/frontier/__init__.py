"""
===============================================================================
前沿 AI 漏洞追踪模块 — 统一入口
===============================================================================
用途: 快速追踪 2026 H2 及以后新出现的前沿 AI 安全漏洞。

目录结构:
  frontier/
  ├── __init__.py       # 包入口，统一导出
  ├── base.py           # 基础数据结构 (FrontierVuln, FrontierPayload)
  ├── registry.py       # 注册中心 (FrontierRegistry)
  ├── index.yaml        # 总索引文件（所有活跃漏洞的汇总视图）
  └── vulns/            # 漏洞目录
      ├── _scaffold/    # 脚手架（新建漏洞模板）
      │   ├── manifest.yaml.example
      │   └── payloads.yaml.example
      └── <vuln-name>/  # 每个目录 = 一个前沿漏洞
          ├── manifest.yaml   # 元数据（唯一必填）
          └── payloads.yaml   # Payload 数据

快速添加新漏洞:
  1. cp -r vulns/_scaffold vulns/2026H2-<漏洞名>
  2. 编辑 manifest.yaml（更新 id/name/status 等元数据）
  3. 编辑 payloads.yaml（填写攻击 payload）
  4. 将 status 改为 "active" → 自动加入攻击管道
  5. 运行 python main.py --penetrating-mode → 自动生效，无需改代码

导入方式:
  from scenarios.frontier import get_registry, get_frontier_vulns
  registry = get_registry()
  vulns = registry.get_active()
===============================================================================
"""
from scenarios.frontier.base import (
    FrontierVuln, FrontierPayload,
    FrontierStatus, SeverityLevel,
)
from scenarios.frontier.registry import (
    FrontierRegistry,
    get_registry,
    get_frontier_vulns,
    get_frontier_strategies,
)

__all__ = [
    # 数据结构
    "FrontierVuln", "FrontierPayload",
    "FrontierStatus", "SeverityLevel",
    # 注册中心
    "FrontierRegistry",
    "get_registry",
    "get_frontier_vulns",
    "get_frontier_strategies",
]
