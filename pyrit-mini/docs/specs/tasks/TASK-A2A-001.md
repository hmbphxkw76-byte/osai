# 任务规格：TASK-A2A-001 - 创建A2A Agent Card数据模型与解析器

> **类型**：标准任务
> **状态**：spec'd
> **来源**：增强 - A2A协议深度探测
> **规格版本引用**：宪法 v1.6 相关条款 / 蓝图 v1.9 相关章节

## 1. 背景与目标

当前项目仅有基础的A2A协议关键词探测（在capability_probe.py中），缺乏Google A2A规范中定义的Agent Card结构化解析能力。本任务旨在创建独立的Agent Card数据模型与解析器，支持：
- 从HTTP端点获取Agent Card JSON
- 解析Agent Card v2.0规范字段
- 提取skills、securitySchemes、capabilities等关键信息

## 2. 蓝图落点（30-TASKS Step 2）

- **触及模块**：recon/
- **依赖方向**：新增模块，无外部依赖（仅aiohttp）
- **ctx 字段**：新增ctx.a2a_agent_card字段（AgentCard对象）
- **触及不变量**：无新增不变量

## 3. 验收标准

- [ ] 创建recon/a2a_agent_card.py模块（≤200行）
- [ ] 定义AgentCard数据类（符合Google A2A规范v2.0）
- [ ] 实现从URL获取并解析Agent Card的异步函数
- [ ] 支持skills、securitySchemes、capabilities解析
- [ ] 支持字段缺失时的安全降级（Optional字段）
- [ ] ruff check通过，0违规

## 4. 受影响文件清单

| 文件 | 动作（改/增/删） | 预估行数 |
|------|----------------|---------|
| recon/a2a_agent_card.py | 增 | 180 |
| core/context.py | 改 | +5 |

**粒度自检**：文件 2 ≤3 ｜ diff 185 ≤300 行 ｜ 跨模块 1 ≤2 ｜ 新增文件 1 ≤1 ✅

## 5. 实施步骤

- [ ] 创建recon/a2a_agent_card.py，定义AgentCard数据类
- [ ] 实现fetch_agent_card异步函数
- [ ] 实现parse_agent_card解析函数
- [ ] 在core/context.py添加a2a_agent_card字段
- [ ] ruff check验证
- [ ] py_compile验证

## 6. ASR 影响评估

本变更让对Burp目标的ASR变高。依据：
- Agent Card解析可暴露更多攻击面（skills、endpoints）
- 为后续A2A探测提供结构化数据基础
- 涉及安全红线：无（仅数据解析，无攻击执行）

## 7. 验证计划

- Step 1 `py -m tools.guard`：0新增BLOCKING
- Step 2 `ruff check recon/a2a_agent_card.py`：0违规
- Step 3 `python -m pytest tests/ -v`：0失败（不新增测试，后续任务补充）
- Step 4 `python main.py --dry-run --max-seeds 1`：无ImportError
- Tier 2（涉及攻击执行/评分/数据变换逻辑时）：否（仅数据模型）

## 8. 汇报（完成后填写）

- ✅ 已完成并验证：（改动点 → 门禁证据）
- ⚠️ 已完成但未验证：（差集及理由）
- ❌ 未完成 / 未做：（显式列出及原因）
- 附件：diff 统计（N 文件 / +A -B 行）；backlog 新增（BL-___）
