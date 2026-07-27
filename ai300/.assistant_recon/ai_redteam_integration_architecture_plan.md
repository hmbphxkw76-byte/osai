# AI 红队侦察一体化集成架构实施计划

> 本计划将 `pyrit-web-recon`、`AI-Infra-Guard`、`RedAmon`、`SkillSpector` 的整合拆分为 6 个里程碑（M1~M6），每个里程碑有明确交付物、验收标准和风险点。

---

## 里程碑总览

| 里程碑 | 主题 | 交付物 | 状态 |
|--------|------|--------|------|
| M1 | 基础设施 | `docker-compose.integration.yml`、网络配置、环境变量模板 | 已创建 |
| M2 | 共享契约 | `UnifiedFinding` Schema、跨工具数据模型 | 已完成 |
| M3 | pyrit-web-recon 集成 | `ExternalDispatchStage` 事件发布、Profile 导出到对象存储 | 已完成 |
| M4 | AI-Infra-Guard 集成 | HTTP Client、Task Builder、Result Normalizer | 已完成 |
| M5 | RedAmon 集成 | Profile → Neo4j Graph Adapter、HTTP Client | 已完成 |
| M6 | 编排层 | `JobScheduler` / `Orchestrator`、去重关联、报告生成 | 已完成 |

---

## M1 基础设施

### 目标
为外部工具提供统一的运行环境：消息总线、对象存储、网络、容器编排。

### 交付物
- `docker-compose.integration.yml`
  - Redis（消息总线）
  - MinIO（对象存储）
  - AI-Infra-Guard Webserver + Agent（官方镜像）
  - RedAmon Neo4j + PostgreSQL + Webapp/API/Agent
  - SkillSpector（按需构建）
- `.env.example.integration`
- 共享 Docker 网络 `pyrit_recon_net`

### 验收标准
```powershell
# 基础设施健康检查
docker compose -f docker-compose.integration.yml up -d
# Redis、MinIO、AIG、RedAmon 均 healthy
curl http://localhost:8088/        # AIG
curl http://localhost:8010/health  # RedAmon API

# 集成测试：验证各服务网络连通性
pytest tests/integration/test_infrastructure.py
```

### 风险点
- RedAmon 无官方预构建镜像，需先 `git clone` 源码。
- OpenVAS 资源消耗大，AI recon 阶段默认不启用。

---

## M2 共享契约

### 目标
定义跨工具数据模型，使 recon、scan、attack 结果可统一处理。

### 交付物
- `src/integration/schemas/unified_finding.py`
  - `UnifiedFinding` dataclass
  - `Evidence` dataclass
  - `dedup_findings()` 去重函数

### 字段覆盖
- 基础身份：`finding_id`、`source_tool`、`task_type`
- 目标定位：`target`、`endpoint_url`、`method`、`parameter`
- 风险评级：`severity`、`confidence`
- 分类映射：`category`、`owasp_llm_id`、`atlas_technique`、`cwe_id`、`capec_id`、`cve_id`
- AI 红队专用：`ai_asr`、`ai_trials`、`ai_payload_class`、`ai_transcript_ref`
- 证据与溯源：`evidence`、`session_id`、`raw`

### 验收标准
```python
from src.integration.schemas import UnifiedFinding, dedup_findings
findings = [UnifiedFinding(...), UnifiedFinding(...)]
unique = dedup_findings(findings)
assert len(unique) <= len(findings)
```
```powershell
# 单元测试
pytest tests/unit/integration/schemas/
# 集成测试
pytest tests/integration/test_unified_finding.py
```

---

## M3 pyrit-web-recon 集成

### 目标
让 pyrit-web-recon 成为一体化流程的触发器，输出标准化 Profile 并发布事件。

### 交付物
- `src/pipeline/stages/external_dispatch.py`
  - ExportStage 后发布 `recon.profile.created`
  - 支持直接触发 AIG/RedAmon/SkillSpector
- `src/export/profile_exporter.py`
  - JSON/YAML Profile 导出
  - PyRIT target JSON 导出

### 验收标准
运行 `python main.py` 后：
- `results/recon/profiles/*.json` 存在且字段完整
- `results/recon/pyrit/*.json` 存在
- 事件可被 JobScheduler 消费

```powershell
# 单元测试：各 Stage 独立验证
pytest tests/unit/pipeline/stages/
# 集成测试：端到端 recon + export
pytest tests/integration/test_pyrit_recon_pipeline.py
```

---

## M4 AI-Infra-Guard 集成

### 目标
根据 `TargetProfile` 自动构造 AIG 扫描任务，异步获取结果并归一化。

### 交付物
- `src/integration/aig/client.py`
  - `upload_file()`、`create_task()`、`wait_for_task()`
- `src/integration/aig/task_builder.py`
  - `build_ai_infra_scan()`
  - `build_agent_scan()`
  - `build_mcp_scan()`
  - `build_model_redteam_report()`
- `src/integration/aig/result_normalizer.py`
  - AIG JSON → `List[UnifiedFinding]`

### 任务类型映射
| Profile 信号 | AIG 任务类型 |
|-------------|-------------|
| 暴露的 AI 服务 / 模型 API | `ai_infra_scan` |
| Agent 特征 | `agent_scan` |
| MCP 特征 | `mcp_scan` |
| 已知模型名 | `model_redteam_report` |

### 验收标准
```python
from src.integration.aig import AIGClient, AIGTaskBuilder
client = AIGClient()
session_id = await client.create_task("ai_infra_scan", {...})
result = await client.wait_for_task(session_id)
findings = AIGResultNormalizer().normalize(result, target="...")
assert len(findings) >= 0
```
```powershell
# 单元测试
pytest tests/unit/integration/aig/
# 集成测试：AIG Client + Task Builder + Normalizer 联动
pytest tests/integration/test_aig_integration.py
```

---

## M5 RedAmon 集成

### 目标
将 `TargetProfile` 写入 RedAmon 知识图谱，支持后续攻击面扩展与查询。

### 交付物
- `src/integration/redamon/client.py`
  - `ingest_profile()`：写入 Profile
  - `trigger_recon()`：触发 RedAmon recon
  - `query_graph()`：Cypher 查询
- `src/integration/redamon/profile_to_graph_adapter.py`
  - Profile → Neo4j `MERGE` 语句

### 图模型映射
| Profile 字段 | Neo4j 节点/关系 |
|-------------|----------------|
| target | Domain |
| chat_urls | BaseURL → Endpoint |
| model_name/model_family | ModelFamily |
| rag_features/agent_features | Technology |
| vulnerabilities | Vulnerability |
| extracted_credentials | Credential |

### 验收标准
```python
from src.integration.redamon import RedAmonClient, ProfileToGraphAdapter
adapter = ProfileToGraphAdapter()
cypher = adapter.to_cypher(profile)
assert "MERGE" in cypher
```
```powershell
# 单元测试
pytest tests/unit/integration/redamon/
# 集成测试：Profile → Graph Adapter → Client 写入
pytest tests/integration/test_redamon_integration.py
```

---

## M6 编排层

### 目标
统一调度各工具，完成去重、关联、评分、写图、报告。

### 交付物
- `src/orchestrator/job_scheduler.py`
  - RoE 校验
  - 顺序/并行执行各工具
  - 异步轮询 AIG 结果
  - 统一结果聚合
- `src/integration/correlator.py`（可扩展）
  - 跨工具去重
  - 风险评分
  - 写 Neo4j
- `src/report/`（可扩展）
  - Markdown/PDF 报告生成

### 执行策略
```python
config = JobConfig(
    enable_pyrit_web_recon=True,
    enable_aig=True,
    enable_redamon=True,
    enable_skillspector=True,
)
```

### 验收标准
```powershell
python examples/run_recon_with_skillspector.py
# 输出：success=True，skillspector_findings > 0

# 单元测试
pytest tests/unit/orchestrator/
# 集成测试：Orchestrator + 各工具 Client 联动
pytest tests/integration/test_orchestrator.py
# 系统测试：完整多模块端到端流水线
pytest tests/system/test_end_to_end.py
```

---

## 7. 测试规范（新增）

### 7.1 测试触发规则

| 改动范围 | 必须执行的测试 | 必须补充的测试文件 |
|---------|--------------|-------------------|
| 单个模块内代码改动 | 单元测试 | `tests/unit/{module}/test_*.py` |
| 跨模块代码改动 | 集成测试 | `tests/integration/test_*.py` |
| 多个模块同时改动 | 完整系统测试 | `tests/system/test_*.py` |

### 7.2 测试文件要求

- 文件名统一为 `test_*.py`。
- 覆盖正常路径、异常路径、边界条件、错误处理。
- 系统测试必须验证 pyrit-web-recon → AIG/RedAmon/SkillSpector → Report 的完整链路。

### 7.3 持续验证

- 每次提交前执行对应层级的测试。
- 多模块改动必须跑通 `pytest tests/system`，否则视为未完成。

---

## 8. 迭代节奏建议

| 迭代 | 内容 | 预计时间 |
|------|------|---------|
| 迭代 1 | pyrit-web-recon 端到端跑通 | 1~2 天 |
| 迭代 2 | + SkillSpector 子进程 + AIG Docker | 2~3 天 |
| 迭代 3 | + RedAmon 图写入 + 统一报告 | 2~3 天 |

---

## 9. 关键决策记录

1. **RedAmon 部署方式**：Docker Compose，先克隆源码构建；OpenVAS 默认不启用。
2. **AI-Infra-Guard 部署方式**：使用官方镜像 `zhuquelab/aig-server` / `zhuquelab/aig-agent`。
3. **SkillSpector 运行方式**：开发验证用子进程，生产隔离用 Docker。
4. **统一数据模型**：`UnifiedFinding` 作为唯一跨工具输出格式。
5. **配置管理**：`.env` 仅保留目标 URL 和凭据，外部工具密钥放 `.env.integration`。
