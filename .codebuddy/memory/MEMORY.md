# RedTeam-AI 项目长期记忆

## 项目定位

AI 红队攻击模拟工具，面向 OffSec AI-300 (OSAI) 考试备考和实际 AI 红队评估。Kali Linux 环境，纯原生（Native-Only）零框架依赖。

## 六大核心设计原则

1. **YAML 数据驱动**：载荷/场景/参数全通过 YAML 定义，缺失时回退 Python fallback
2. **AI 红队专家风格**：专业安全分析师视角呈现 — 侦察情报简报、策略推荐、风险指标
3. **纯原生（Native-Only）**：`NativeAttackRunner`（httpx），零框架依赖，考试环境 100% 可跑
4. **多轮编排原生化**：Crescendo/TAP/PAIR 由 `MultiTurnOrchestrator` 纯原生实现
5. **全局统筹**：Phase 1~12 完整攻击链，侦察结果自动驱动后续阶段
6. **阶段提示**：统一双线边框横幅（72 字符 + AI-300 标注 + ⏳/⚔️/✓）

## 五大核心铁律

1. **Library-First**：纯 Python 库优先，严禁外部小众 CLI 工具
2. **Pydantic BaseModel**：API 边界禁止裸 dict
3. **Finding 绑定 OWASPLlm/OWASP_AGENTIC + MITREATLASTactic**：不允许无分类标签
4. **枚举优先于字符串常量**
5. **目录结构强制合规**：所有新建文件/目录必须遵循已有项目目录结构。创建前必须先阅读父目录结构。严禁在 `pipeline/` 根目录创建与 `execution/`/`reporting/` 平级的独立目录

## 项目目录结构（强制读写参考）

```
redteam/
├── attack/              ← 攻击模块（按类型分子目录）
├── core/                ← 核心基础设施（models, store, terminal_output）
├── pipeline/            ← 流水线编排
│   ├── execution/       ← **所有阶段实现**（recon/injection/agent/...）+ exploit/
│   ├── reporting/       ← 报告生成
│   └── runner*.py       ← 运行器
├── recon/               ← 侦察模块
└── cli.py               ← CLI
```

**规则**：pipeline/ 下只有 execution/ + reporting/ + runner*.py。创新模块必须先放入已有子目录。

## 管道阶段模型

Phase 1~12 完整攻击链，阶段间通过 JSON 在 `results/{run_id}/` 传递，Checkpoint/Resume 模式。

## 数据目录（v2.0 results/reports 分离）

```
results/{run_id}/     ← 原始攻击数据（中间产物）
├── recon/            ← 侦察产物
├── detect/           ← 检测阶段 Findings
├── exploit/          ← 利用证明 Findings
└── AI300_Report.md   ← 中间报告

reports/{run_id}/     ← 正式提交报告（精加工产出）
└── AI300_Report.md   ← OffSec AI-300 考试提交
```

## 覆盖标准（三层）

| 标准 | 枚举 | 状态 |
|------|------|------|
| OWASP LLM Top 10 (2025) | `OWASPLlm` LLM01-LLM10 | ✅ 全覆盖 |
| OWASP Agentic Top 10 (2026) | `OWASP_AGENTIC` ASI01-ASI10 | ✅ 全覆盖 (2026-07-15) |
| MITRE ATLAS | `MITREATLASTactic` | ✅ 9 战术 |

## OWASP Agentic Top 10 (2026)

ASI01 代理目标劫持 / ASI02 工具误用 / ASI03 身份权限滥用 / ASI04 供应链入侵 / ASI05 意外代码执行 / ASI06 记忆上下文投毒 / ASI07 不安全代理间通信 / ASI08 级联故障 / ASI09 人机信任利用 / ASI10 恶意代理注入

## AI Kill Chain（对齐 OffSec AI-300）

```
Reconnaissance → Initial Access → Execution → Persistence → Privilege Escalation
    → Credential Access → Discovery → Collection → C2 → Actions on Objective
```

映射关系：AI 资产发现(侦察) → 提示注入/目标劫持(初始访问) → 工具误用/代码执行(执行) → 记忆投毒(持久化) → 权限滥用/代理间提权(提权) → 系统提示提取(凭据) → 配置提取(发现) → RAG 泄露/嵌入反演(收集) → 恶意代理(C2) → 数据泄露/级联故障(目标行动)

## OSAI 考试对齐（7+1 规则）

R1 章节映射 / R2 OWASP 全覆盖 / R3 手动能力保留 / R4 报告 5 维度 / R5 ATLAS 链 ≥4 战术 / R6 工具最小化 / R7 考试 P0 优先 / R8 OWASP Agentic 对齐

## 代码规范

Python >= 3.10 + Type Hints, Pydantic v2, Google docstring, snake_case, 单一模块 ≤500 行

## 测试规范

pytest, mock 外部调用, 合成数据, 禁止真实凭据, 每模块三路径（正常+边界+空）

## Payload 载荷库

43 个 YAML，420 条载荷，覆盖 OWASP LLM01-LLM10 + OWASP Agentic ASI01-ASI10

## 禁止事项

真实凭据、非 Kali CLI 工具、硬编码 URL、YAML 内部 ASCII 引号（用 Unicode `\u201c\u201d`）、临时文件残留

## 用户偏好

中文交流/注释/文档；偏好编辑现有文件；Kali Linux 目标环境；三级搜索策略（arXiv → GitHub → Web）

## 同步规则

`.trae/rules/` ↔ `.codebuddy/rules/` 双向同步；Makefile 变更 → 同步 `docs/COMMAND_REFERENCE.md`

## 关键实施记录

- v1.3 子目录分离（recon/detect/exploit）— 2026-07-15，229 测试零回归
- v2.0 results/reports 双目录 + Reports Pipeline (Phase 12) — 2026-07-15
- Exploit Pipeline (Detect→Exploit) — 2026-07-15，216 测试
- OWASP Agentic Top 10 (2026) 对齐 — 2026-07-15，ASI01-ASI10 枚举/覆盖/报告整合
