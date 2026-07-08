"""
===============================================================================
PyRIT Red Team — 统一红队演练平台 (v11.0 Streamlined — PyRIT Native Orchestrator)
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
快速使用指南 (Quick Reference) v11.0 Streamlined
===============================================================================
  默认语言: 中文 (--lang cn)，无需显式指定；英文用 --lang en
  核心参数: --target-url + --auth + --phase（probe 自动探测定模型/格式/并发）

  # ── [1] 已知模型 API: 只需 URL + API Key ──
  python main.py --target-url https://api.openai.com/v1 --auth sk-xxx --phase probe
  # → 自动: format=openai, model=gpt-4, SSL=verify, concurrent=auto

  # ── [2] 内网自部署模型 (vLLM/Ollama) ──
  python main.py --target-url http://192.168.2.199:8501/ --target-type model --auth sk-xxx --phase probe
  # → 自动: format=openai, model=auto-probe, concurrent=auto

  # ── [3] 自定义 AI 应用 (Web Chat UI) ──
  python main.py --target-url http://192.168.1.100/api/chat --auth "session=abc123" --phase probe
  # → 自动: 端点枚举 → 架构探测 → 策略推荐

  # ── [4] HTTPS 自签证书 + 自定义 Header 认证 ──
  python main.py --target-url https://internal-app/api/v1/query --ssl-skip --auth '{"X-API-Key":"sk-secret"}' --phase probe

  # ── [5] Cookie 认证 ──
  python main.py --target-url http://192.168.1.100/api/chat --auth "session_id=abc;token=xyz" --phase probe

  # ── [6] JWT 认证 ──
  python main.py --target-url https://api.internal.com/v1/chat --auth eyJhbGciOi... --phase probe

  # ── [7] 自适应攻击引擎 ──
  python main.py --target-url http://192.168.2.199:8501/v1/chat --auth sk-xxx --adaptive --phase single

  探索模式: python main.py --exploring-template tech_mode.yaml
  渗透模式: python main.py --penetrating-mode --penetrating-template penetrating_prompts.yaml
  回退旧版引擎: 添加 --orch legacy 回到旧版引擎

  报告输出: 所有攻击模式完成后自动生成 10 章标准渗透报告（TLP:AMBER 封面 + 执行摘要 + 方法论 + RCA + 修复时间线）
    产物路径: outputs/results/PyRIT_RedTeam_*_Report_*.md / *_Exam_Report_*.md / *_log_*.json
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
