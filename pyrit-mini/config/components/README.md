# config/components/ — 声明式攻击矩阵（REQ-153 / ADR-007）

> **唯一来源**：组件差异只准声明在本目录的 YAML 中。**编排层禁止硬编码组件名**
> （护栏 `R-EVENT-1`，BLOCKING；蓝图第十三章 IC-1）。
> **加载器**：`core/registry.py` → `ComponentRegistry` / `get_registry()`。
> **状态**：W0 仅建契约（空注册表合法，零行为变更）；**W4 落齐 9 个组件**。

## 文件命名

`<component_id>.yaml`，如 `mcp.yaml` / `a2a.yaml` / `rag.yaml`。

## 字段契约

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `id` | str | 否 | 组件标识；缺省取文件名（`mcp.yaml` → `mcp`） |
| `labels` | list[str] | ✅ | **多标签**（IC-1）：一个组件可属多个标签，一个标签也可命中多个组件 |
| `detect.signals` | list[str] | ✅ | 识别信号（路径/响应特征/JSON-RPC 方法等） |
| `detect.min_confidence` | float | ✅ | 识别置信度下限（低于则归入 `unknown` 走兜底） |
| `recon` | list[str] | ✅ | 专项侦察器 dotted path（如 `recon.mcp.enum_tools`） |
| `seeds` | list[str] | ✅ | 种子目录/glob（如 `data/seeds/mcp/*`） |
| `converters` | list[str] | 否 | 推荐 Converter 链 |
| `playbooks` | list[str] | 否 | 攻击链 id（对应 `strike/playbook/playbooks/*.yaml`） |
| `scorer` | str | ✅ | 评分 rubric 名（`data/scorers/component_scorers/<name>.yaml`） |
| `report_section` | str | 否 | 报告章节 dotted path |
| `cleanup` | list[str] | ✅ | 副作用清理动作（**I13**：未声明 cleanup 的副作用步禁止执行） |

## 一期 9 类组件（W4 落齐）

`model` `agent` `mcp` `a2a` `rag` `multimodal_upload` `session`
`web_api` `supply_chain`（末者为侦察级，不计入 ASR 分母）

> **`id` 纪律（IA-8）**：`id` 必须等于 YAML 文件名 stem；目录由 `recon_dir` / `strike_dir`
> **显式声明**，不由 `id` 推导（同一目录可被多组件声明使用，如 `strike_dir: web`）。
> 2026-09-12 修正：`web_infra`→`web_api`、`memory_session_tenant`→`session`（二者实测零消费方）。

## 示例

```yaml
id: mcp
labels: [mcp, tool_surface]
detect:
  signals: ["tools/list", "jsonrpc:2.0", "/.well-known/mcp", "mcp-session-id"]
  min_confidence: 0.6
recon:
  - recon.mcp.enum_tools
  - recon.mcp.schema_extract
seeds: ["data/seeds/mcp/*"]
converters: [json_rpc_wrap, base64, unicode_tag]
playbooks: [mcp_enum_call, mcp_tool_chaining]
scorer: mcp_tool_poisoning
report_section: report.component_reports.mcp
cleanup: [unregister_tool, restore_schema]
```

> **注意**：本目录为**声明式资产**（蓝图 2.1 数据层），不得放置可执行代码。
