# 执行期专家指导规范

> **定位**: 定义在攻击测试执行过程中，如何基于实时状态生成和展示 PyRIT 专家指导，提升非框架熟悉者的攻击成功率。

---

## 一、设计理念

### 1.1 三阶段指导模型

```
┌──────────────────────────────────────────────────────────────────┐
│                      PyRIT 专家指导三阶段模型                       │
│                                                                  │
│  Stage 1: 探测后 (Pre-Execution)                                  │
│  ├── 位置: targets/target_type_probe.py                          │
│  ├── 触发: 架构探测完成后                                         │
│  ├── 产物: 新手测试指引 + 专家测试建议 + 下一步攻击命令              │
│  └── 数据源: TargetTypeResult（架构类型、维度得分、RAG/MCP检测）    │
│                                                                  │
│  Stage 2: 执行中 (In-Execution)  ← 本规范核心                      │
│  ├── 位置: executor/dashboard.py + orchestrators/                 │
│  ├── 触发: 每个攻击任务完成时、每个阶段结束时                        │
│  ├── 产物: 实时战术建议面板、阶段过渡推荐、自适应引擎统计            │
│  └── 数据源: 已完成攻击结果（成功率、突破组合、失败模式）             │
│                                                                  │
│  Stage 3: 执行后 (Post-Execution)                                 │
│  ├── 位置: reporting/engine.py + reporting/terminal.py            │
│  ├── 触发: 全部攻击完成后                                         │
│  ├── 产物: 后续攻击命令推荐（按手法×领域扩散）、最快聚合路径         │
│  └── 数据源: 完整攻击结果集                                        │
└──────────────────────────────────────────────────────────────────┘
```

### 1.2 核心原则

1. **数据驱动**: 指导内容必须基于实际攻击结果，不做无依据的猜测。
2. **即时反馈**: 攻击结果产生后立即更新指导，不等待全量完成。
3. **层次化展示**: 新手指引（通俗语言）+ 专家建议（技术术语）并排展示。
4. **可执行命令**: 所有推荐必须包含可直接复制执行的 CLI 命令。
5. **渐进增强**: 即使结果不理想也给出下一步建议，不出现"无建议"的空面板。

---

## 二、Stage 2 执行中指导架构

### 2.1 数据流

```
攻击任务完成 (单个 coroutine)
        │
        ├─→ 1. 结果入队 (all_results.append)
        ├─→ 2. 更新 DashboardState (stats counters)
        ├─→ 3. 反馈自适应引擎 (adaptive_selector.report_result)
        ├─→ 4. 🆕 累计实时统计 → 触发指导刷新
        │       ├─ 统计: 总体/按手法/按用例/按阶段的成功率
        │       ├─ 分析: 最有效手法 Top-N、突破模式识别
        │       └─ 生成: 立即可执行的下一步命令
        │
        └─→ 5. Dashboard 布局更新 (live.update)
                ├─ header: 标题 + 任务总数
                ├─ progress: 进度条
                ├─ stats: 成功/失败/错误计数
                ├─ guidance: 🆕 实时专家建议面板
                └─ log: 最新攻击流
```

### 2.2 指导面板集成点

```python
# executor/dashboard.py — DashboardState 扩展

class DashboardState:
    def __init__(self, total_tasks: int):
        # ... 现有字段 ...
        self.guidance_lines: list[str] = []  # 🆕 实时指导行
        self.phase_stats: dict = {}          # 🆕 分阶段统计

    def refresh_guidance(self, results: list[dict], phase: str = ""):
        """基于当前累计结果刷新实时指导。
        
        每次攻击完成时调用，分析已完成结果生成：
        - 当前成功率
        - 最有效攻击手法
        - 推荐下一步操作
        """
        # 由 utils/guidance.py 中的纯函数计算
        self.guidance_lines = generate_realtime_guidance(results, phase)

    def get_layout(self, progress, task_id) -> Layout:
        layout = Layout()
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="progress", size=3),
            Layout(name="stats", size=5),
            Layout(name="guidance", size=8),  # 🆕 实时指导面板
            Layout(name="log", size=3),
        )
        # ... 现有 layout 更新 ...
        layout["guidance"].update(
            Panel("\n".join(self.guidance_lines), 
                  title="🧠 PyRIT 实时专家建议", 
                  border_style="cyan")
        )
        return layout
```

### 2.3 指导内容生成规则

指导内容必须基于以下量化指标：

| 指标 | 阈值 | 指导内容 |
|------|------|---------|
| 总体成功率 > 50% | 高 | "目标防线已被突破，建议立即扩大攻击面" |
| 总体成功率 10-50% | 中 | "部分手法有效，推荐聚焦 {Top-N 手法}" |
| 总体成功率 < 10% | 低 | "建议切换攻击策略/升级到自适应引擎" |
| 某组合成功率 > 80% | 特化 | "{组合名} 对该目标杀伤力极强，建议全量覆盖" |
| 连续 N 次相同失败 | 疲劳 | "该攻击路径已饱和，建议换用其他领域用例" |
| 跨用例手法推广 | 自适应 | "{手法} 在 {N} 个不同用例中均成功，建议全局推广" |
| 拒绝模式识别 | 模式 | "目标对中文注入/角色扮演类有强防御，避免此类手法" |

### 2.4 阶段过渡指导（门控/分阶段执行）

在 `run_phased_campaign()` 中，每个阶段结束后必须输出过渡指导：

```
STAGE 1 (PROBE) 完成 →
  ├── 成功率 >= 阈值: "探测验证通过，进入单轮主力突破阶段"
  │     推荐命令: python main.py --lang cn --phase single --case ...
  ├── 成功率 < 阈值: "目标防线较强，跳过单轮阶段，直接升级 Crescendo"
  │     推荐命令: python main.py --lang cn --phase crescendo --case ...
  └── 所有阶段完成: "建议启动全量自适应攻击以获得最高覆盖率"
        推荐命令: python main.py --lang cn --adaptive --case all
```

---

## 三、实现规范

### 3.1 纯函数 vs 状态管理

**指导生成必须是纯函数**，放在 `utils/guidance.py` 或类似位置：

```python
def generate_realtime_guidance(
    results: list[dict],
    phase: str = "",
    total_tasks: int = 0,
) -> list[str]:
    """基于已完成的攻击结果生成实时专家指导。
    
    Args:
        results: 已完成的所有攻击结果
        phase: 当前阶段名称
        total_tasks: 总任务数（用于计算完成百分比）
    
    Returns:
        Rich 格式化的指导行列表（可直接渲染到 Panel）
        
    要求:
        - 纯函数，不依赖全局状态
        - 始终返回非空列表（最少包含一条通用建议）
        - 返回的每行以 Rich markup 格式编写
        - 命令部分用 [bold] 标记，可直接复制
    """
```

### 3.2 仪表盘集成规范

```python
# orchestrators/pyrit_orchestrator.py — run_campaign() 中的 Live 块

from utils.guidance import generate_realtime_guidance

with Live(dashboard.get_layout(progress, task_id), ...) as live:
    for coro in asyncio.as_completed(coros):
        result = await coro
        all_results.append(result)
        
        # 1. 更新进度
        progress.advance(task_id)
        
        # 2. 反馈自适应引擎
        if adaptive_selector:
            adaptive_selector.report_result(...)
        
        # 3. 🆕 刷新实时指导
        dashboard.refresh_guidance(all_results, phase=phase.value)
        
        # 4. 更新状态
        dashboard.update(status, log_msg)
        
        # 5. 刷新布局
        live.update(dashboard.get_layout(progress, task_id))
```

### 3.3 新手友好命令格式

所有推荐的攻击命令必须遵循以下格式，确保不熟悉框架的用户可直接复制执行：

```
✅ 正确格式:
  python main.py --lang cn --phase single --case CASE_001,CASE_002

❌ 错误格式:
  # 缺少 --lang（无法确定语言）
  # 使用缩写（如 --p 代替 --phase）
  # 包含占位符（如 <TARGET_URL>）但未在上下文中说明如何替换
```

命令推荐优先级（从上到下排列）：

1. **一键聚合命令**（影响面最大）: `--case all-single --adaptive`
2. **领域聚焦命令**（突破点最精准）: `--case CASE_001,CASE_003`
3. **手法强化命令**（最高成功率）: `--combo-filter "xxx"`
4. **全自动命令**（零配置）: `--auto-gate --gate-threshold 0.10`

### 3.4 颜色与图标约定

| 场景 | 颜色 | 图标 | 示例 |
|------|------|------|------|
| 高成功率推荐 | `bold green` | 🎯 | 建议立即执行的命令 |
| 中等成功率 | `bold yellow` | ⚡ | 值得尝试的命令 |
| 低成功率/警告 | `bold red` | ⚠️ | 不建议继续的路径 |
| 战术提示 | `dim cyan` | 💡 | 非命令的纯技巧建议 |
| 阶段过渡 | `bold cyan` | 🚀 | 下一阶段入口命令 |

---

## 四、与现有组件的集成

### 4.1 集成清单

| 组件 | 文件 | 集成方式 | 优先级 |
|------|------|---------|--------|
| 实时仪表盘 | `executor/dashboard.py` | 新增 `guidance` 面板 + `refresh_guidance()` 方法 | P0 |
| 原生编排器 | `orchestrators/pyrit_orchestrator.py` | 在 `Live` 循环中调用 `dashboard.refresh_guidance()` | P0 |
| 指导生成引擎 | `utils/guidance.py` | 新建纯函数模块 | P0 |
| 门控阶段过渡 | `orchestrators/pyrit_orchestrator.py` `run_phased_campaign()` | 每个阶段结束输出过渡指导 | P1 |
| 终端战报 | `reporting/terminal.py` | 增强现有的 `_render_followup_terminal()` | P1 |
| 探测后指导 | `targets/target_type_probe.py` | 已有新手+专家双面板，本规范不重复 | 已完成 |

### 4.2 向后兼容

- Dashboard 新增面板不得影响现有 header/progress/stats/log 面板的尺寸和位置。
- `DashboardState.__init__()` 新增字段必须提供合理默认值。
- 当指导生成异常时，降级显示静态提示而非崩溃。

---

## 五、测试要求

### 5.1 指导内容验证

每当新增或修改指导生成逻辑时，必须验证：

```python
# 测试: 指导函数对所有输入都返回非空结果
def test_guidance_always_returns_content():
    assert len(generate_realtime_guidance([])) > 0  # 空结果也要有建议
    assert len(generate_realtime_guidance([{"status": "ERROR"}])) > 0
    assert len(generate_realtime_guidance([{"status": "SUCCESS", ...}])) > 0
```

### 5.2 集成验证

```bash
# 1. 基础攻击验证指导面板显示正常
python main.py --lang cn --phase probe --case CASE_001 --concurrent 1

# 2. 分阶段执行验证过渡指导
python main.py --lang cn --auto-gate --gate-threshold 0.10 --concurrent 1

# 3. 自适应引擎验证实时指导刷新
python main.py --lang cn --adaptive --concurrent 1
```

---

## 六、参考实现

### 6.1 现有 Stage 1 实现

`targets/target_type_probe.py`:
- `_render_beginner_guidance()` — 新手测试指引（📖 系统解释 + 🔓 漏洞位置 + ⚔️ 攻击计划 + 💡 实战技巧）
- `_render_expert_guidance()` — 专家测试建议（📋 战略评估 + 🎯 推荐测试进程 + ⚡ 踩坑经验）

### 6.2 现有 Stage 3 实现

`reporting/engine.py` + `reporting/terminal.py`:
- `build_followup_suggestions()` — 纯逻辑推荐引擎
- `_render_followup_terminal()` — 终端渲染（命令复制格式（PROBE 映射→单轮扩散→多轮扩散→最快路径））

### 6.3 Stage 2 新增实现位置

```
utils/guidance.py                   ← 🆕 指导生成纯函数
executor/dashboard.py               ← 🆕 DashboardState 扩展
orchestrators/pyrit_orchestrator.py ← 🆕 Live 循环集成
```
