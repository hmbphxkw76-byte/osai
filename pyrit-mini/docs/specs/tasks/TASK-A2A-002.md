# 任务规格：TASK-A2A-002 - 创建A2A协议发现与深度探测模块

> **类型**：标准任务
> **状态**：spec'd
> **来源**：增强 - A2A协议深度探测
> **规格版本引用**：宪法 v1.6 相关条款 / 蓝图 v1.9 相关章节

## 1. 背景与目标

在Agent Card数据模型基础上，实现A2A协议的深度探测能力：
- 发现A2A端点（从HTTP响应头、Agent Card、OpenAPI spec）
- 枚举JSON-RPC方法（tasks/send, tasks/get, tasks/cancel, tasks/sendSubscribe等）
- 探测多Agent拓扑（从Agent Card的provider URL、skills引用）

## 2. 蓝图落点（30-TASKS Step 2）

- **触及模块**：recon/
- **依赖方向**：依赖a2a_agent_card.py，无其他外部依赖
- **ctx 字段**：复用ctx.a2a_agent_card，新增ctx.a2a_discovered_endpoints
- **触及不变量**：无新增不变量

## 3. 验收标准

- [ ] 创建recon/a2a_discoverer.py模块（≤250行）
- [ ] 实现A2A端点发现（从HTTP头、Agent Card、OpenAPI）
- [ ] 实现JSON-RPC方法枚举
- [ ] 实现多Agent拓扑发现
- [ ] ruff check通过，0违规

## 4. 受影响文件清单

| 文件 | 动作（改/增/删） | 预估行数 |
|------|----------------|---------|
| recon/a2a_discoverer.py | 增 | 230 |
| core/context.py | 改 | +5 |

**粒度自检**：文件 2 ≤3 ｜ diff 235 ≤300 行 ｜ 跨模块 1 ≤2 ｜ 新增文件 1 ≤1 ✅

## 5. 实施步骤

- [ ] 创建recon/a2a_discoverer.py
- [ ] 实现discover_a2a_endpoints函数
- [ ] 实现enumerate_jsonrpc_methods函数
- [ ] 实现discover_agent_topology函数
- [ ] 在core/context.py添加a2a_discovered_endpoints字段
- [ ] ruff check验证
- [ ] py_compile验证

## 6. ASR 影响评估

本变更让对Burp目标的ASR变高。依据：
- A2A端点发现可暴露更多攻击面
- JSON-RPC方法枚举可识别可利用的API
- 多Agent拓扑发现可揭示信任链攻击路径
- 涉及安全红线：无（仅探测，无攻击执行）

## 7. 验证计划

- Step 1 `python core/architecture_guard.py`：0新增BLOCKING
- Step 2 `ruff check recon/a2a_discoverer.py`：0违规
- Step 3 `python -m pytest tests/ -v`：0失败
- Step 4 `python main.py --dry-run --max-seeds 1`：无ImportError
- Tier 2：否（仅探测逻辑）

## 8. 汇报（完成后填写）

- ✅ 已完成并验证：（改动点 → 门禁证据）
- ⚠️ 已完成但未验证：（差集及理由）
- ❌ 未完成 / 未做：（显式列出及原因）
- 附件：diff 统计（N 文件 / +A -B 行）；backlog 新增（BL-___）
