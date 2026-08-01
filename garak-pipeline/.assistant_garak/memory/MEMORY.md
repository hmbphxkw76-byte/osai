# Garak-Pipeline 项目长期记忆

## OWASP Alignment v3.0 架构决策（2026-07-17）
- **核心原则**：OWASP ID 是唯一分类键，所有载荷、命令、报告均以 OWASP ID 标识
- **数据层零冗余**：删除 `surfaces` 和 `ai300_chapters` 字段，OWASP ID 隐含攻击面
- **CLI 即标准**：`ai300 owasp llm01` 直接映射 OWASP ID，无需记忆框架自定义名称
- **侦察独立**：surfaces 由侦察阶段动态生成（TargetProfile.surfaces），与载荷元数据解耦
- **章节映射**：`reporting/chapter_mapper.py` 动态推导 OWASP ID → AI-300 章节
- **命令结构**：`ai300 owasp <scope>` — 支持单个 ID（llm01）、分组（llm/agentic）、全部（all）

## garak 版本与 _config 兼容性（重要，实测，2026-08-01 修正）
- **流水线运行环境是 `.venv`,实际装 garak 0.15.1**(注:此前记忆记成 0.16 是错的)。全局 `python` 亦 0.15.1,API 一致。
- garak 0.15 `_config` 关键事实:`loaded` 属性存在(bool);`is_loaded` 不存在(故 `stage3_execute` 用 hasattr 区分)。`plugins.api_key` 不存在 → API key 走 `OPENAICOMPATIBLE_API_KEY` 环境变量。`run.parallel_requests` 存在(默认可能 False),generator 实例有 `parallel_requests` 属性(初始 False),harness 每次生成时读取。
- generator 构造器仅接受 `(name, config_root)`,URI/key/model 经 `_config.plugins.generators[...]` nested dict 注入,非构造参数。
- `pipeline/stage3_execute.py` 已做 0.15/0.16 兼容守卫。改 garak 集成代码必须在 venv 的 0.15.1 下验证。

## PyRIT 版本与 Score 原生消费（重要，实测）
- **环境实际装的是 PyRIT 1.0.0**（非 0.14.0）。`pyrit.dataset` 模块不存在；数据集在 `pyrit.datasets`。
- `Score` 类位于 `pyrit.score.scorer.Score`，是 pydantic model，加载用 `Score.model_validate(dict)`（无 `import_obj`/`to_dict`）。
- **Score 字段硬约束**：`score_value` 必须 str 且 float_scale∈[0,1]；`score_category` 必须 list[str]；`message_piece_id` 必须合法 UUID str（不可 null）；`timestamp` 必须带时区；`score_metadata` 仅标量值（dict/list 需 json.dumps 成 str）；模型 `extra_forbidden`(每条 Score 不可含 `schema` 键)。
- 本仓库 `stage5_report.export_pyrit_air` 导出 `scores[]` 为合法 Score dict 数组（归一化 score_value=str(asr/100)，message_piece_id 用 uuid5(DNS, run_id+probe) 派生可复现），下游 `Score.model_validate()` 可直接加载。

## 历史技术笔记（已失效，仅留痕）
- ⚠️ 以下记忆因 2026-08-01 裁剪已失效，保留仅为避免重复踩坑：
  - httpcore/httpx reentrant、LongCat2.0 扫描 nones 根因、模态感知探针选择(stage2) — 这些均涉及已删除的 execute/stage2 代码，本仓库已无相关实现。
  - Ollama 兼容与自适应速率控制器**已恢复实装**(见下"自适应速率控制器")，不再失效。
  - `supports_multiple_generations` 探测逻辑仍保留在 `stage1_recon._detect_model_modality()` 中（写入 target_profile），作为目标画像信息，但已无下游 stage2 钳制消费。

## 项目范围（2026-08-01 修正：实际是完整 5 阶段流水线）
- **定位**：garak 全功能红队流水线——`runner.py` 编排 5 阶段：① Stage1 侦察(模态过滤+OWASP 分类) → ② Stage2 配置(按 tier 选探针+Buff 链) → ③ Stage3 攻击(garak harness 真驱动) → ④ Stage4 分析(ASR+DEFCON 双框架) → ⑤ Stage5 报告+PyRIT 导出。
- **关键文件**：`main.py`(走 `PipelineRunner`)、`pipeline/runner.py`、`stage1_recon.py`/`stage2_configure.py`/`stage3_execute.py`/`stage4_analyze.py`/`stage5_report.py`、`recon_garak.py`(枚举+分类+模态过滤核心)、`adaptive_rate.py`。
- **产物命名**：阶段目录固定名 `01_recon`/`02_config`/`03_execution`/`04_analysis`/`05_export`（无 `_date_time` 后缀）；文件含 `_date_time`（run_id）。
- **模态过滤**：`recon_garak.filter_probes_by_modality` 用两阶段解析（显式 modality → 关键词启发式推断），text-only 目标剔除 image/audio 探针。
- **注意**：`pipeline/stage5_export.py` 是旧版死代码(schema=pyrit-consumable/v1)，runner 实际调 `stage5_report.export_pyrit_air`(产物 `pyrit_air_{run_id}.json`)。

## ⚠️ AI-Infra-Guard 集成已彻底删除（2026-08-01 晚）
- **决策**：AIG 核心引擎是 Go 后端（无 Go 工具链），Python 子模块是散装 CLI 无统一 SDK；完整能力仅在 Docker 子进程 `:8088` HTTP API 后。源码 import 只拿到 data/ yaml 知识库，非能力本身 → 用户决定回归纯 garak 场景。
- **已删除**：`pipeline/recon_infra.py`（AIGFingerprintLoader/InfraRecon/InfraEvidence）、`tests/test_recon_infra.py`、`stage1_recon.py` 中全部 CrossMapper 代码（`_AI300_CHAPTER_MAP`/`_build_coverage`/`_bucket_infra_evidence`/`_print_coverage`/`_run_infra_recon`/`_evidence_to_dict` + run() Step3/Step4 + target_profile.infra_recon）、`runner.py` 的 `infra_recon` 参数、`main.py` 的 `infra_recon` 读取、`config/target.yaml` 的 `infra_recon` 段。
- **当前 Stage1 架构（纯 garak）**：`recon_garak.py` 封装 `enumerate_garak_probes()` + `classify_probes()`（映射表驱动，OWASP10 全保真 + 专题桶），消除原 20 个 `Other` 孤儿；`stage1_recon.py` 仅做连通性测试 + garak 攻击面枚举 + 模型模态侦察 + 目标画像。无 AIG 源码/数据依赖。
- **测试同步**：78 passed 全绿（原 86 - 8），lint 0 error。

## 产物命名规范（2026-08-01 起）
- 侦察产物落在 `outputs/01_recon_{run_id}/` 下，文件名含 `_date_time_`（`_ts_name` 方法）：
  - `target_profile_{run_id}.json`、`probe_candidates_{run_id}.json`、`connectivity_test_{run_id}.json`
- 仅侦察阶段，无 02_config/03_execution/04_analysis/05_export 产物。

## 开发流程约定（2026-08-01，规则十一）
- **每次方案优化/调整/修复后，改代码前必须先产出三步并待用户确认**：
  1. 优化后的完整方案
  2. 与 100% 对齐 L5 专家水平的**差距分析报告**（覆盖攻击面覆盖、检测评估严谨性、工程健壮性、代码质量、未触及能力）
  3. 对齐 100% L5 的**完整优化解决方案**（具体文件/方法/伪代码）
- 例外：纯文档/注释/记忆更新，或用户当次显式指令"立即实现/直接改"可跳过确认
- 正式规则见 `.assistant_garak/rules.md` 规则十一

## 自适应速率控制器（2026-08-01 实装，防 API 限流封禁）
- **位置**：`pipeline/adaptive_rate.py`，在 `stage3_execute.execute_attack` 中对 garak generator 的 `_call_model` 打 monkeypatch（不修改 garak 源码）。
- **四层防护**：
  1. `TokenBucket` 主动节流（按 `max_rpm` 令牌桶，从源头不突破配额）；
  2. `Retry-After` 优先解析（从异常挂的 `response.headers` 取秒数或 HTTP Date，优先于指数退避）；
  3. 指数退避 + 全抖动（full jitter 防惊群重试风暴），可重试信号含 429/503/529/timeout/connection/busy 等；
  4. 连续失败熔断（达 `cooldown_threshold` 静默 `cooldown` 秒）+ 并发自动降级（达 `downgrade_at` 次触发 `on_downgrade` 回调，写回 `_config.run.parallel_requests = max(1, cur//2)`）。
- **硬失败不重试**：401/403/400/invalid api key 等直接抛出（避免加速封禁/暴露无效凭据）。
- **Ollama 兼容**：`_call_model` 返回值若为原生 `response` 字段则归一化为 `choices[].message.content`。
- **配置**：`config/target.yaml` 的 `execute.rate_limit` 段（max_rpm/base_delay/max_delay/max_retries/cooldown/cooldown_threshold/downgrade_at/jitter），`stage3_execute` 读取并构造控制器。
- **测试**：`tests/test_adaptive_rate.py`（14 passed），全量 38 passed。

## 数据资产（2026-08-01 起）
- 远程下载数据集**已提前下载到本地目录**，且**周期性更新**（由外部机制负责，非本仓库代码）。
- 因此 `DataManager`/`datasets.yaml`/`--prefetch`/`--sync-data` 等远程下载机制**已删除**，本仓库只做 recon，不负责资产同步。
- **存储位置（2026-08-01 补充）**：数据集**不存 `outputs/`**，单独放仓库根的 `data/` 目录（与运行产物分离、`.gitignore` 忽略、不入库）。`config/target.yaml` 用 `data_dir: "data"` 登记根路径，供下游阶段统一引用。详见 `data/README.md`。
