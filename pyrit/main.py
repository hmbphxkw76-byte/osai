"""
===============================================================================
PyRIT Red Team — 统一红队演练平台 (v10.0 — PyRIT Native Orchestrator)
===============================================================================
核心升级:
1. ✅ PyRIT 原生 Memory: SQLiteMemory + CentralMemory 全局单例（最佳实践）
2. ✅ PyRIT 原生 Orchestrator: PromptSendingAttack + CrescendoAttack（多轮自适应攻击）
3. ✅ PyRIT Scenarios 集成: PyRITScenarioRunner 声明式阶段编排
4. ✅ 向后兼容: --orch legacy 回退旧版 execute_single/crescendo_attack
5. Crescendo 渐进式多轮攻击引擎，覆盖单轮无法突破的高阶考点
6. JailbreakBench Top5 模板 + 67组攻击组合（含17组三层链） + 防假阴性评分
7. --phase / --auto-gate 分阶段门控执行（PyRIT 最佳实践）
8. 2026 最热点攻击面：CoT/Constitution/MCP/A2A + 三层编码链全覆盖

架构变化:
  旧: engines/single.py + engines/crescendo.py + 手动 DuckDB
  新: orchestrators/pyrit_orchestrator.py (PyRIT 原生) + SQLiteMemory
  旧: main.py 1537 行单体 CLI 入口
  新: entrypoint/ 包 (parser/display/bootstrap/router) + main.py ~150 行

模块拆分:
- entrypoint/   → 🆕 入口层 (parser/display/bootstrap/router)
- converters/   → 攻击策略转换器 & 攻击组合配置
- targets/      → .env 配置加载 & Target 工厂 & 自动探测
- executor/     → 评分器 & 仪表盘 & 模板 & 探索模式
- orchestrators/ → 🆕 PyRIT 原生调度器 & Scenario 集成
- reporting/    → 结果分析与报告生成
- main.py       → CLI 入口 & 顶层编排 (精简版)

===============================================================================
快速使用指南 (Quick Reference)
===============================================================================
  模式 A: 不指定 --target-url → 攻击 .env 中配置的 LLM API:
    python main.py --lang cn --phase probe              # 仅 PROBE 快速探测
    python main.py --lang cn --phase single             # 仅单轮主力突破
    python main.py --lang cn --phase crescendo          # 仅 Crescendo 多轮攻坚
    python main.py --lang cn --auto-gate                # 自动门控 (阈值 10%)

  模式 B: 指定 --target-url → 攻击自定义 Chat API:
    python main.py --lang cn --target-url http://192.168.2.199:8501/ --phase probe

  模式 C: --target-url + --target-api-format → 攻击非 OpenAI 格式 API:
    python main.py --lang cn --phase probe --target-url https://api.anthropic.com/v1/messages --target-api-key YOUR_KEY --target-api-format claude --target-model claude-3-sonnet-20240229

  模式 D: --target-url + --target-api-format raw → 攻击非标准内部 Web 应用:
    python main.py --lang cn --phase probe --target-url http://192.168.1.100/internal/chat --target-api-format raw --target-cookie "session_id=abc123"

  探索模式: python main.py --exploring-template tech_mode.yaml
  渗透模式: python main.py --penetrating-mode --penetrating-template penetrating_prompts.yaml

  回退旧版引擎: 添加 --orch legacy 回到旧版引擎
===============================================================================
"""
import asyncio

from rich.console import Console

from entrypoint.parser import build_parser
from entrypoint.display import print_cli_args
from entrypoint.bootstrap import bootstrap_environment
from entrypoint.router import route_command

console = Console()


async def main():
    """PyRIT Red Team CLI 入口 — 精简编排层。

    职责:
      1. 解析 CLI 参数
      2. 回显参数
      3. 引导环境（Memory + Config + Target + Payload + Converters）
      4. 路由到对应执行模式
    """
    # ── 1. 解析 CLI 参数 ──
    args = build_parser().parse_args()

    # ── 2. 回显参数 ──
    print_cli_args(args)

    # ── 3. 环境引导 ──
    ctx = await bootstrap_environment(args)

    # ── 4. 路由分发 ──
    await route_command(args, ctx)


if __name__ == "__main__":
    asyncio.run(main())
