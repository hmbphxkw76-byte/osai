# Output 子系统架构文档

> 对齐 `pyrit.output` — PyRIT 1.0.0 完整 Output 渲染与报告生成架构  
> 文档版本：v2.0 | 更新日期：2026-07-27  
> **v2.0 变更**：output_scenario_async + Per-Group Breakdown 集成 + 失败类型分布诊断

---

## 目录

1. [架构概览](#1-架构概览)
2. [目录结构](#2-目录结构)
3. [各模块详细设计](#3-各模块详细设计)
4. [数据流全景](#4-数据流全景)
5. [与 PyRIT 原生 Output 的衔接](#5-与-pyrit-原生-output-的衔接)
6. [配置说明](#6-配置说明)
7. [L5 对齐差距分析](#7-l5-对齐差距分析)
8. [开发规则](#8-开发规则)

---

## 1. 架构概览

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      OUTPUT 子系统（完整）                                     │
│                                                                             │
│  核心不变量 🟢：三层分离 = Format(Printer) × Sink(Destination) × DataSource   │
│  核心约束 🟢：render_async() 返回字符串 / write_async() = render_async + Sink │
│  组合模式 🔵：AttackResultPrinter 组合 ConversationPrinter + ScorePrinter    │
│                                                                             │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │  统一输出管理器 🟢                                                     │  │
│  │  "双通道输出：终端 Pretty + 文件 Markdown"                             │  │
│  │  → OutputManager（output_attack_async 双格式调度）                     │  │
│  │  → ProgressDashboard（终端 ANSI 实时进度仪表盘）                       │  │
│  │  → SummaryTable（批量完成后的交叉统计汇总表）                          │  │
│  │  → blurred_dir / blur_images / include_reasoning_trace 全链路传递     │  │
│  └────────────────────────────────┬──────────────────────────────────────┘  │
│  ┌────────────────────────────────┴──────────────────────────────────────┐  │
│  │  报告生成器 🟢                                                        │  │
│  │  "三级证据链 Finding → AttackResult → Conversation"                  │  │
│  │  → ReportGenerator（Markdown 报告 8 章节结构）                        │  │
│  │  → OWASPMapper（LLM Top 10 + Agentic AI Top 10 双标准映射 + 矩阵）   │  │
│  │  → output_scenario_async / output_scorer_async 原生摘要集成           │  │
│  └────────────────────────────────┬──────────────────────────────────────┘  │
│  ┌────────────────────────────────┴──────────────────────────────────────┐  │
│  │  证据导出器 🟢                                                        │  │
│  │  "render_async() 直接获取字符串，消除 write_async()+read-back 冗余 I/O" │  │
│  │  → EvidenceExporter（ZIP 证据包打包）                                 │  │
│  │  → MarkdownAttackResultMemoryPrinter.render_async（每攻击独立 MD）    │  │
│  │  → MarkdownConversationMemoryPrinter.render_async（每对话独立 MD）    │  │
│  │  → MarkdownScorePrinter.render_async（每评分独立 MD）                 │  │
│  │  → blurred_dir 模糊图片副本收集 + 纳入 ZIP                            │  │
│  │  → evidence.json（model_dump） / attack_summary.csv /                │  │
│  │    owasp_coverage_matrix.csv / attack_timeline.csv                    │  │
│  └────────────────────────────────┬──────────────────────────────────────┘  │
│  ┌────────────────────────────────┴──────────────────────────────────────┐  │
│  │  格式转换器 🟢                                                        │  │
│  │  "Markdown → HTML / PDF 渐进增强 + 优雅降级"                          │  │
│  │  → convert_markdown_to_html（markdown 库 + 7 扩展 + CSS 内嵌）        │  │
│  │  → convert_markdown_to_pdf（weasyprint > xhtml2pdf > 仅 HTML 降级）   │  │
│  │  → convert_report_formats（批量转换便捷方法）                         │  │
│  │  → check_pdf_engine_available（引擎可用性检测）                       │  │
│  └────────────────────────────────┬──────────────────────────────────────┘  │
│  ┌────────────────────────────────┴──────────────────────────────────────┐  │
│  │  多样性分析器 🟢                                                      │  │
│  │  "Shannon 熵 + OWASP 覆盖 + 失败集中度"                               │  │
│  │  → calculate_shannon_entropy / calculate_normalized_entropy           │  │
│  │  → DiversityAnalyzer.analyze（6 大指标批量计算）                      │  │
│  │  → render_diversity_section（Markdown 章节渲染）                      │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                                                                             │
│  PyRIT 原生 API re-export 🟢：                                               │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐         │
│  │  Sink 体系        │  │  便捷函数         │  │  Printer 基类    │         │
│  │  StdoutSink       │  │  output_attack_  │  │  PrinterBase     │         │
│  │  FileSink         │  │    async         │  │  OutputFormat    │         │
│  │  IPythonMarkdown  │  │  output_conver-  │  └──────────────────┘         │
│  │  Sink             │  │    sation_async  │                               │
│  │  get_default_sink │  │  output_score_   │                               │
│  └──────────────────┘  │    async         │                               │
│                        │  output_scenario_ │                               │
│                        │    async         │                               │
│                        │  output_scorer_  │                               │
│                        │    async         │                               │
│                        └──────────────────┘                               │
│                                                                             │
│  与上层衔接点：                                                               │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐         │
│  │  BatchOrchestrator│  │  ScenarioOrchest-│  │  Pipeline        │         │
│  │  → OutputManager  │  │  rator           │  │  → generate_report│       │
│  │    .output_attack │  │  → generate_     │  └──────────────────┘         │
│  │      _result()    │  │    report()      │                               │
│  └──────────────────┘  └──────────────────┘                               │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. 目录结构

```
src/reporting/                                     ← 对齐 pyrit.output
├── __init__.py                                   ← 顶层统一导出（30+ 公共 API）
├── output_manager.py                             ← 双通道输出管理器 + 进度仪表盘
├── report_generator.py                           ← 报告生成器 + OWASP 映射 + 证据导出
├── format_converter.py                           ← Markdown → HTML/PDF 格式转换
└── diversity_analyzer.py                         ← 攻击多样性与覆盖度分析器

测试文件：
tests/unit/
├── test_output_manager.py                        ← OutputManager 单元测试
├── test_evidence_exporter.py                     ← EvidenceExporter 单元测试
├── test_format_converter.py                      ← 格式转换器单元测试
├── test_diversity_analyzer.py                    ← 多样性分析器单元测试
└── test_upgrade_strategy.py                      ← 升级策略单元测试

输出目录：
output/
├── evidence/                                     ← 证据导出目录
│   └── {exam_id}/
│       ├── attacks/                              ← 每攻击独立 Markdown
│       ├── conversations/                        ← 每对话独立 Markdown
│       ├── scores/                               ← 每评分独立 Markdown
│       ├── blurred/                              ← 模糊图片副本目录
│       └── {exam_id}_evidence.zip                ← 完整证据包
├── reports/                                      ← 报告输出目录
│   ├── {exam_id}_report.md                       ← Markdown 报告
│   ├── {exam_id}_report.html                     ← HTML 报告（可选）
│   └── {exam_id}_report.pdf                      ← PDF 报告（可选）
└── logs/                                         ← 日志目录
    └── {exam_id}_attacks.md                      ← 全量 Markdown 攻击日志
```

> **注意**：项目不重新实现 PyRIT Printer 类，而是通过 `output_manager.py` 和 `report_generator.py` 提供**双通道输出调度、报告生成、证据导出、格式转换**等上层服务，委托原生 PyRIT Printer 执行实际渲染。

---

## 3. 各模块详细设计

### 3.1 统一输出管理器（OutputManager）

| 模块 | 对齐 PyRIT 原生 | 功能 |
|:--|:--|:--|
| `OutputManager` | `output_attack_async` | 双通道输出调度（终端 Pretty + 文件 Markdown） |
| `ProgressDashboard` | — | 终端 ANSI 着色实时进度仪表盘 |
| `SummaryTable` | — | 批量完成后的攻击模式/技术/OWASP 交叉统计汇总表 |

**关键设计**：

1. **双通道调度**：
   - 终端通道：`output_attack_async(format="pretty", sink=stdout_sink)` — ANSI 着色
   - 文件通道：`output_attack_async(format="markdown", sink=file_sink)` — Markdown 持久化

2. **环境自动检测**：
   - `get_default_sink(StdoutSink)` 自动检测运行环境
   - Jupyter Notebook → `IPythonMarkdownSink`（`display(Markdown)`）
   - 终端 → `StdoutSink`（`sys.stdout.write`）

3. **智能终端显示**：
   - `_should_show_terminal()` — 非 verbose 模式下仅显示前 5 个成功结果
   - verbose 模式下显示全部
   - 失败结果始终记录到文件

4. **L5 参数透传**：
   - `blur_images` / `blur_radius` — 图片模糊（终端内存模糊 + 文件磁盘模糊）
   - `blurred_dir` — 模糊图片副本重定向到专用目录（仅 Markdown 格式）
   - `include_reasoning_trace` — o1/o3 推理模型推理轨迹

5. **场景级摘要集成**：
   - `output_scenario_result()` — 委托 `output_scenario_async` 渲染场景级摘要
   - `output_scorer_info()` — 委托 `output_scorer_async` 渲染评分器评估指标

6. **FileSink 并发安全**：
   - 使用追加模式 `mode="a"`，避免多次运行截断
   - PyRIT `FileSink` 内部使用 `asyncio.Lock()` 保证并发安全

### 3.2 报告生成器（ReportGenerator）

| 模块 | 对齐 PyRIT 原生 | 功能 |
|:--|:--|:--|
| `ReportGenerator` | `output_scenario_async` + `output_scorer_async` | 生成考试专用 Markdown 报告（8 章节） |
| `OWASPMapper` | — | OWASP 双标准映射（LLM Top 10 + Agentic AI Top 10） |
| `generate_report()` | — | 工厂函数（便捷调用） |
| `map_attacks_to_owasp()` | — | 工厂函数（便捷调用） |

**报告章节结构**（8 章节）：

| 章节 | 内容 | 证据链层级 |
|:--|:--|:--|
| 1. Introduction | 目标、需求、AI 工具使用声明 | — |
| 2. Executive Summary | 概览、攻击路径、发现汇总、技术分布、Converter 使用、失败分析、多样性分析 | 摘要级 |
| 3. OWASP Coverage Matrix | LLM Top 10 + Agentic AI Top 10 双标准覆盖矩阵 | 覆盖级 |
| 4. Detailed Findings | 每个 Finding 的攻击叙事 + MITRE 映射 + 修复建议 + 步骤重现 | 第一级 + 第二级 + 第三级 |
| 5. Attack Timeline | 按时间戳排序的攻击时间线表格 | 时间线级 |
| 5.5 Successful Attack Highlights | 每个成功攻击的完整对话历史 | 第三级（完整证据） |
| 6. MITRE ATT&CK Mapping | MITRE 技术到 OWASP ID 的反向映射 | 映射级 |
| 7. Tool Usage | 动态提取的工具使用统计 | 工具级 |
| 8. Appendix | 证据归档说明、风险定义、配置摘要 | 附录级 |

**三级证据链**：

```
第一级：OWASPFinding（漏洞发现）
  ├── owasp_id / owasp_name / severity / cvss_score
  ├── attack_type / confidence（动态计算）
  ├── indicators / remediation / mitre_techniques
  └── evidence_ids（conversation_id 列表）
        │
        ▼
第二级：AttackResult（攻击结果）
  ├── objective / outcome / outcome_reason
  ├── executed_turns / execution_time_ms
  ├── last_score（value / type / category / rationale）
  └── conversation_id
        │
        ▼
第三级：Conversation（完整对话历史）
  └── [{role, text, timestamp}, ...]
```

**OWASPMapper 关键设计**：

- **动态 confidence 计算**：基于成功比例（80%）+ 评分器确认加权（20%）
- **覆盖矩阵**：统计每个 OWASP ID 的攻击数、成功数、成功率
- **攻击类型分组**：按 `attack_type` 分组 AttackResult，关联到对应 OWASP ID
- **双标准支持**：LLM Top 10（LLM01-LLM10）+ Agentic AI Top 10（ASI01-ASI10）

**原生摘要集成**：

```python
# 场景级摘要
await output_scenario_async(
    native_scenario_result,
    format="pretty",
    sort_groups_by_success_rate=True,
)

# 评分器评估指标
await output_scorer_async(
    scorer_identifier=scorer_identifier,
    format="pretty",
)
```

### 3.3 证据导出器（EvidenceExporter）

| 方法 | 对齐 PyRIT 原生 | 功能 |
|:--|:--|:--|
| `export_all_evidence()` | — | 导出完整 ZIP 证据包 |
| `_export_attack_markdowns()` | `MarkdownAttackResultMemoryPrinter.render_async()` | 每攻击独立 Markdown |
| `_export_conversation_markdowns()` | `MarkdownConversationMemoryPrinter.render_async()` | 每对话独立 Markdown |
| `_export_score_markdowns()` | `MarkdownScorePrinter.render_async()` | 每评分独立 Markdown |
| `_render_conversation_log_async()` | `MarkdownConversationMemoryPrinter.render_async()` | 汇总对话历史 Markdown |
| `_collect_blurred_images()` | `blurred_dir` 机制 | 收集模糊图片副本 |
| `_build_evidence_json()` | `model_dump(mode="json")` | 结构化 JSON 证据 |
| `_render_attack_summary_csv()` | — | 完整列攻击摘要 CSV |
| `_render_coverage_matrix_csv()` | — | OWASP 覆盖矩阵 CSV |
| `_render_attack_timeline_csv()` | — | 攻击时间线 CSV |

**ZIP 证据包结构**：

```
{exam_id}_evidence.zip
├── evidence.json                    ← 结构化数据（model_dump）
├── conversation_history.md          ← 汇总对话历史
├── attack_summary.csv               ← 完整列攻击摘要
├── owasp_coverage_matrix.csv        ← OWASP 覆盖矩阵
├── attack_timeline.csv              ← 攻击时间线
├── attacks/                         ← 每攻击独立 Markdown
│   ├── attack_0001.md
│   ├── attack_0002.md
│   └── ...
├── conversations/                   ← 每对话独立 Markdown
│   ├── conv_{id8}.md
│   └── ...
├── scores/                          ← 每评分独立 Markdown
│   ├── score_0001.md
│   ├── score_0002.md
│   └── ...
└── blurred/                         ← 模糊图片副本（blur_images=True 时）
    ├── image1_blurred.png
    └── ...
```

**L5 对齐关键实践**：

1. **render_async 替代 write_async+read-back**：
   ```python
   # ❌ 旧方式：冗余 I/O
   await printer.write_async(result, sink=FileSink(path=tmp))
   content = tmp.read_text()

   # ✅ L5 方式：直接获取字符串
   content = await printer.render_async(result, include_auxiliary_scores=True)
   file_path.write_text(content)
   ```

2. **blurred_dir 专用目录**：
   - `blurred_dir=None` → 自动创建 `evidence_dir/blurred/`
   - `blurred_dir=path` → 使用指定目录
   - `_collect_blurred_images()` 扫描 `*_blurred.png` 并纳入 ZIP

3. **model_dump 替代 str()**：
   - `evidence.json` 使用 `model_dump(mode="json")` 确保结构化数据
   - 回退到 `str()` 处理非 Pydantic 对象

4. **错误处理与 fallback**：
   - 渲染失败时记录 warning 并生成 fallback Markdown
   - 不影响其他证据的导出

### 3.4 格式转换器（FormatConverter）

| 函数 | 功能 | 依赖 |
|:--|:--|:--|
| `convert_markdown_to_html()` | Markdown → 带样式 HTML | `markdown` 库（必需） |
| `convert_markdown_to_pdf()` | Markdown → PDF | `weasyprint` > `xhtml2pdf` > None |
| `convert_report_formats()` | 批量转换（HTML + PDF） | 上述两者 |
| `check_pdf_engine_available()` | 检测可用 PDF 引擎 | 无 |

**设计原则**：

1. **渐进增强**：HTML 为基础输出（零系统依赖），PDF 为可选输出
2. **优雅降级**：PDF 引擎不可用时跳过并记录警告，不影响 HTML 输出
3. **CSS 内嵌**：HTML 文件自带完整样式，无需外部 CSS 文件
4. **纯函数设计**：不依赖 ReportGenerator 内部状态

**Markdown 扩展**（7 个）：

| 扩展 | 功能 |
|:--|:--|
| `tables` | 表格支持 |
| `fenced_code` | ``` 代码块 |
| `codehilite` | 代码高亮（Monokai 主题） |
| `toc` | 目录生成 |
| `nl2br` | 换行转 `<br>` |
| `sane_lists` | 智能列表 |
| `smarty` | 智能引号 |

**PDF 引擎优先级**：

| 引擎 | 质量 | 系统依赖 | 安装 |
|:--|:--|:--|:--|
| `weasyprint` | 高 | 需要 GTK/Cairo | `pip install weasyprint` |
| `xhtml2pdf` | 中 | 纯 Python，无系统依赖 | `pip install xhtml2pdf` |
| 仅 HTML | — | 无 | 浏览器打印为 PDF |

### 3.5 多样性分析器（DiversityAnalyzer）

| 函数/类 | 功能 |
|:--|:--|
| `calculate_shannon_entropy()` | Shannon 熵（衡量分布均匀度） |
| `calculate_normalized_entropy()` | 归一化熵（0.0~1.0） |
| `calculate_coverage_ratio()` | 覆盖率计算 |
| `calculate_concentration_ratio()` | 集中度（最大类别占比） |
| `split_technique_distribution_by_outcome()` | 按成功/失败拆分技术分布 |
| `calculate_owasp_coverage_breadth()` | OWASP 覆盖广度 |
| `DiversityAnalyzer.analyze()` | 批量计算 6 大指标 |
| `DiversityAnalysisResult` | 结果容器（含 `to_dict()` 和 `get_diversity_grade()`） |
| `render_diversity_section()` | Markdown 章节渲染 |

**6 大多样性指标**：

| 指标 | 计算方式 | 含义 |
|:--|:--|:--|
| 技术 Shannon 熵 | `-Σ p·log2(p)` | 技术分布均匀度（越高越多样） |
| 归一化熵 | `熵 / log2(n)` | 0-1 范围标准化 |
| 技术覆盖率 | `独立技术数 / 12` | 已使用技术占可用技术的比例 |
| OWASP 覆盖率 | `已覆盖 OWASP ID / 20` | 安全标准覆盖广度 |
| Converter 多样性 | `使用比例 × 种类多样性` | Converter 链使用多样性 |
| 失败集中度 | `最大失败原因数 / 总失败数` | 失败模式集中程度 |

**多样性等级**：

| 归一化熵范围 | 等级 |
|:--|:--|
| ≥ 0.8 | Excellent |
| ≥ 0.6 | Good |
| ≥ 0.4 | Moderate |
| ≥ 0.2 | Low |
| < 0.2 | Poor |

---

## 4. 数据流全景

```
                    ┌─────────────────────┐
                    │  BatchOrchestrator   │
                    │  / ScenarioOrchestr. │
                    └─────────┬───────────┘
                              │ AttackResult
                              ▼
              ┌───────────────────────────────┐
              │       OutputManager            │
              │                               │
              │  ┌─── 终端通道 (Pretty) ───┐  │
              │  │ output_attack_async(     │  │
              │  │   format="pretty",       │  │
              │  │   sink=stdout_sink,      │  │
              │  │   blur_images=...,       │  │
              │  │   blur_radius=...        │  │
              │  │ )                        │  │
              │  └──────────────────────────┘  │
              │                               │
              │  ┌─── 文件通道 (Markdown) ─┐  │
              │  │ output_attack_async(     │  │
              │  │   format="markdown",     │  │
              │  │   sink=file_sink,        │  │
              │  │   blur_images=...,       │  │
              │  │   blur_radius=...,       │  │
              │  │   blurred_dir=...        │  │
              │  │ )                        │  │
              │  └──────────────────────────┘  │
              └───────────────┬───────────────┘
                              │
                    ┌─────────▼─────────┐
                    │  output/logs/     │
                    │  {id}_attacks.md  │
                    └───────────────────┘

              ┌───────────────────────────────┐
              │     ReportGenerator            │
              │                               │
              │  1. output_scenario_async()   │ ← 原生场景级摘要
              │  2. output_scorer_async()     │ ← 原生评分器指标
              │  3. OWASPMapper                │
              │     .map_attacks_to_findings() │ ← 第一级证据
              │     .build_coverage_matrix()   │
              │  4. _generate_summary()        │
              │     + DiversityAnalyzer        │ ← 多样性分析
              │  5. _collect_attack_details()  │ ← 第二级+第三级证据
              │  6. _render_markdown_report()  │ ← 8 章节报告
              │  7. format_converter           │ ← HTML/PDF 转换
              │  8. EvidenceExporter           │ ← 证据 ZIP 导出
              └───────────────┬───────────────┘
                              │
              ┌───────────────▼───────────────┐
              │     EvidenceExporter           │
              │                               │
              │  ┌─── 原生 Printer ────────┐  │
              │  │ MarkdownAttackResult    │  │
              │  │   MemoryPrinter         │  │
              │  │   .render_async()       │  │ → attacks/*.md
              │  │                         │  │
              │  │ MarkdownConversation    │  │
              │  │   MemoryPrinter         │  │
              │  │   .render_async()       │  │ → conversations/*.md
              │  │                         │  │
              │  │ MarkdownScorePrinter    │  │
              │  │   .render_async()       │  │ → scores/*.md
              │  └─────────────────────────┘  │
              │                               │
              │  ┌─── 结构化数据 ─────────┐  │
              │  │ evidence.json          │  │ ← model_dump
              │  │ attack_summary.csv     │  │
              │  │ owasp_coverage.csv     │  │
              │  │ attack_timeline.csv    │  │
              │  └─────────────────────────┘  │
              │                               │
              │  ┌─── 模糊图片 ───────────┐  │
              │  │ _collect_blurred_      │  │
              │  │   images()             │  │ → blurred/*.png
              │  └─────────────────────────┘  │
              │                               │
              │  → ZIP 打包                   │
              └───────────────┬───────────────┘
                              │
                    ┌─────────▼─────────┐
                    │  output/reports/  │
                    │  {id}_report.md   │
                    │  {id}_report.html │
                    │  {id}_report.pdf  │
                    │  output/evidence/ │
                    │  {id}_evidence.zip│
                    └───────────────────┘
```

---

## 5. 与 PyRIT 原生 Output 的衔接

### 5.1 Re-export 策略

`src/reporting/__init__.py` re-export PyRIT 原生 output 公共 API，便于上层统一导入：

```python
from pyrit.output import (
    # Sink 体系
    FileSink, IPythonMarkdownSink, StdoutSink, Sink, get_default_sink,
    # Printer 基类
    PrinterBase, OutputFormat,
    # 便捷函数
    output_attack_async, output_conversation_async,
    output_scenario_async, output_score_async, output_scorer_async,
)
```

### 5.2 衔接点映射

| 项目模块 | PyRIT 原生 API | 衔接方式 |
|:--|:--|:--|
| `OutputManager.output_attack_result()` | `output_attack_async()` | 双格式调度（pretty + markdown） |
| `OutputManager.output_scores()` | `output_score_async()` | 终端 Pretty 输出 |
| `OutputManager.output_conversation()` | `output_conversation_async()` | 终端 Pretty 对话输出 |
| `OutputManager.output_scenario_result()` | `output_scenario_async()` | 终端场景级摘要 |
| `OutputManager.output_scorer_info()` | `output_scorer_async()` | 终端评分器评估指标 |
| `EvidenceExporter._export_attack_markdowns()` | `MarkdownAttackResultMemoryPrinter.render_async()` | 每攻击独立 Markdown |
| `EvidenceExporter._export_conversation_markdowns()` | `MarkdownConversationMemoryPrinter.render_async()` | 每对话独立 Markdown |
| `EvidenceExporter._export_score_markdowns()` | `MarkdownScorePrinter.render_async()` | 每评分独立 Markdown |
| `EvidenceExporter._render_conversation_log_async()` | `MarkdownConversationMemoryPrinter.render_async()` | 汇总对话历史 |
| `ReportGenerator.generate_report()` | `output_scenario_async()` + `output_scorer_async()` | 原生摘要集成 |

### 5.3 参数透传链

```
Pipeline / BatchOrchestrator
  │
  ├─ blur_images: bool = False
  ├─ blur_radius: int = 20
  ├─ blurred_dir: Optional[PathLike] = None
  ├─ include_reasoning_trace: bool = True
  │
  ▼
OutputManager.__init__(blur_images, blur_radius, blurred_dir, include_reasoning_trace)
  │
  ├─ output_attack_async(format="pretty", blur_images=, blur_radius=)
  │    └─ PrettyAttackResultMemoryPrinter(blur_images, blur_radius)
  │         └─ PrettyConversationPrinter(blur_images, blur_radius)
  │              └─ blur_image_bytes(image_bytes, radius)  ← 内存模糊
  │
  └─ output_attack_async(format="markdown", blur_images=, blur_radius=, blurred_dir=)
       └─ MarkdownAttackResultMemoryPrinter(blur_images, blur_radius, blurred_dir)
            └─ MarkdownConversationPrinter(blur_images, blur_radius, blurred_dir)
                 └─ 磁盘模糊副本写入 blurred_dir  ← 原子写入

ReportGenerator.generate_report(blur_images, blur_radius, blurred_dir, include_reasoning_trace)
  │
  └─ EvidenceExporter(blur_images, blur_radius, blurred_dir, include_reasoning_trace)
       ├─ MarkdownAttackResultMemoryPrinter(blur_images, blur_radius, blurred_dir)
       ├─ MarkdownConversationMemoryPrinter(blur_images, blur_radius, blurred_dir)
       └─ _collect_blurred_images()  ← 扫描 blurred_dir 收集模糊副本
```

---

## 6. 配置说明

### 6.1 config.yaml 配置项

```yaml
pyrit:
  evidence_dir: "output/evidence"    # 证据导出根目录

report:
  output_dir: "output/reports"       # 报告输出目录

output:
  logs_dir: "output/logs"            # 日志目录
```

### 6.2 OutputManager 初始化参数

| 参数 | 类型 | 默认值 | 说明 |
|:--|:--|:--|:--|
| `exam_id` | `str` | — | 考试 ID（必填） |
| `verbose` | `bool` | `False` | 是否终端输出每个攻击完整详情 |
| `include_reasoning_trace` | `bool` | `False` | 是否包含推理模型推理轨迹 |
| `blur_images` | `bool` | `False` | 是否模糊图片内容 |
| `blur_radius` | `int` | `20` | 高斯模糊半径 |
| `blurred_dir` | `Optional[PathLike]` | `None` | 模糊图片副本目录（None=原图旁边） |

### 6.3 EvidenceExporter 初始化参数

| 参数 | 类型 | 默认值 | 说明 |
|:--|:--|:--|:--|
| `exam_id` | `str` | — | 考试 ID（必填） |
| `include_reasoning_trace` | `bool` | `True` | 是否包含推理轨迹 |
| `blur_images` | `bool` | `False` | 是否模糊图片 |
| `blur_radius` | `int` | `20` | 模糊半径 |
| `blurred_dir` | `Optional[PathLike]` | `None` | 模糊副本目录（None=`evidence_dir/blurred/`） |

### 6.4 ReportGenerator.generate_report 参数

| 参数 | 类型 | 默认值 | 说明 |
|:--|:--|:--|:--|
| `scenario_result` | `Any` | — | ScenarioResult 实例或 AttackResult 列表 |
| `exam_id` | `str` | — | 考试 ID |
| `start_time` | `datetime` | — | 开始时间 |
| `end_time` | `datetime` | — | 结束时间 |
| `include_reasoning_trace` | `bool` | `True` | 推理轨迹 |
| `blur_images` | `bool` | `False` | 图片模糊 |
| `blur_radius` | `int` | `20` | 模糊半径 |
| `blurred_dir` | `Optional[PathLike]` | `None` | 模糊副本目录 |

---

## 7. L5 对齐差距分析

### 7.1 对齐度总览

| 维度 | 对齐度 | 状态 |
|:--|:--|:--|
| Sink 体系（StdoutSink/FileSink/IPythonMarkdownSink） | 100% | 🟢 完全对齐 |
| 便捷函数（output_attack_async 等 5 个） | 100% | 🟢 完全对齐 |
| Printer 基类（PrinterBase/OutputFormat） | 100% | 🟢 完全对齐 |
| render_async vs write_async | 100% | 🟢 完全对齐 |
| blur_images / blur_radius | 100% | 🟢 完全对齐 |
| blurred_dir | 100% | 🟢 完全对齐 |
| include_reasoning_trace | 100% | 🟢 完全对齐 |
| MarkdownAttackResultMemoryPrinter | 100% | 🟢 完全对齐 |
| MarkdownConversationMemoryPrinter | 100% | 🟢 完全对齐 |
| MarkdownScorePrinter | 100% | 🟢 完全对齐 |
| output_scenario_async | 100% | 🟢 完全对齐 |
| output_scorer_async | 100% | 🟢 完全对齐 |
| get_default_sink 环境自动检测 | 100% | 🟢 完全对齐 |
| Composition Pattern | 100% | 🟢 完全对齐 |
| 证据 ZIP 打包 | 100% | 🟢 完全对齐 |
| **整体对齐度** | **100%** | 🟢 |

### 7.2 已实施优化清单

| 优化项 | 对齐前 | 对齐后 | 说明 |
|:--|:--|:--|:--|
| render_async 替代 write_async+read-back | ❌ 冗余 I/O | ✅ 直接获取字符串 | EvidenceExporter 全方法对齐 |
| blurred_dir 参数 | ❌ 缺失 | ✅ 全链路传递 | OutputManager + EvidenceExporter + ReportGenerator |
| 模糊图片副本收集 | ❌ 缺失 | ✅ `_collect_blurred_images()` | 扫描 `*_blurred.png` 纳入 ZIP |
| 独立 Score Markdown | ❌ 缺失 | ✅ `_export_score_markdowns()` | MarkdownScorePrinter.render_async |
| scores/ 目录 | ❌ 缺失 | ✅ ZIP 内 `scores/` 目录 | 每评分独立文件 |
| model_dump 替代 str() | ❌ 字符串序列化 | ✅ 结构化 JSON | `model_dump(mode="json")` |
| output_scenario_async 集成 | ❌ 缺失 | ✅ ReportGenerator 集成 | 原生场景级摘要 |
| output_scorer_async 集成 | ❌ 缺失 | ✅ ReportGenerator 集成 | 原生评分器评估指标 |
| PyRIT 原生 API re-export | ❌ 缺失 | ✅ __init__.py 导出 | 30+ 公共 API 统一导入 |

### 7.3 AI-300 考试就绪度

| 考试领域 | 就绪度 | 说明 |
|:--|:--|:--|
| 攻击结果展示 | 100% | pretty/markdown 双格式 + blur_images + blurred_dir |
| 对话历史渲染 | 100% | include_reasoning_trace + 原生 ConversationPrinter |
| 评分展示 | 100% | ScorePrinter.render_async + scores/ 目录 |
| 场景级摘要 | 100% | output_scenario_async 原生集成 |
| 评分器评估 | 100% | output_scorer_async 原生集成 |
| 多模态输出 | 100% | blur_images + 图片模糊副本 + 音频播放器 |
| 证据导出 | 100% | render_async + ZIP 打包 + blurred_dir + CSV |
| 报告生成 | 100% | Markdown + HTML/PDF + OWASP 矩阵 + 多样性分析 |
| **综合就绪度** | **100%** | |

---

## 8. 开发规则

### 8.1 核心规则

1. **原生优先**：使用 PyRIT 原生 Printer / Sink / 便捷函数，不重新实现渲染逻辑
2. **render_async First**：需要获取渲染字符串时使用 `render_async()`，不使用 `write_async() + read-back`
3. **参数透传**：`blur_images` / `blur_radius` / `blurred_dir` / `include_reasoning_trace` 必须全链路传递
4. **blurred_dir 仅 Markdown**：`blurred_dir` 仅对 `format="markdown"` 生效，Pretty 格式在内存中模糊

### 8.2 最佳实践

1. **双通道输出**：终端用 Pretty（ANSI 着色），文件用 Markdown（持久化）
2. **环境自动检测**：使用 `get_default_sink(StdoutSink)` 自动检测运行环境
3. **错误处理**：渲染失败时记录 warning 并生成 fallback，不影响其他证据导出
4. **并发安全**：FileSink 使用追加模式 `mode="a"`，PyRIT 内部 `asyncio.Lock()` 保证安全
5. **渐进增强**：HTML 为基础输出，PDF 为可选输出，引擎不可用时优雅降级
6. **CSS 内嵌**：HTML 文件自带完整样式，无需外部 CSS 文件
7. **model_dump 序列化**：结构化数据使用 `model_dump(mode="json")`，回退到 `str()`
8. **三级证据链**：Finding → AttackResult → Conversation，每级可独立追溯

### 8.3 禁止事项

1. **禁止**重新实现 PyRIT Printer 类的渲染逻辑
2. **禁止**使用 `write_async() + read-back` 获取渲染字符串（使用 `render_async()`）
3. **禁止**在 Pretty 格式传递 `blurred_dir`（仅 Markdown 格式生效）
4. **禁止**修改原始图片文件（模糊是审查者暴露控制，不是访问控制）
5. **禁止**在 PDF 引擎不可用时阻断报告生成（优雅降级为仅 HTML）
