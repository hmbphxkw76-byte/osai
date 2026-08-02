# Assistant Garak — 项目规则

> 更新: 2026-08-01 18:15

> **继承**: 本项目同时受全局规则约束，详见 [`.assistant/rules.md`](../../.assistant/rules.md)（G-001 ~ G-108）。
> 全局规则涵盖：架构原则、代码质量、分级测试、改动流程、Git 规范、依赖管理、API 设计、性能、安全、代码审查、废弃策略。
> 以下为 Garak 项目专项规则（规则一 ~ 规则十二），是全局规则的补充细化，不得与全局规则冲突。

## 规则一：garak 原生框架优先

- 所有攻击探测、检测、评估逻辑必须优先使用 garak 原生框架提供的 API
- 禁止绕过 garak 的插件体系自行实现 Probe / Detector / Generator
- 如需扩展，必须遵循 garak 的插件规范（继承 `garak.probes.base.Probe` 等基类）
- 配置格式必须兼容 garak 的 `run.spec` 统一选择语法
- 报告格式必须兼容 garak 的 JSONL 报告规范

## 规则二：源码目录不可修改

- garak 源码存放在 `D:\文档\GitHub\osai\src\garak-0.15.1`
- 后续开发均基于此源码目录进行二次开发
- **禁止修改 `src/garak-0.15.1/` 目录下的任何文件**
- 如需扩展 garak 功能，应在 `garak-pipeline/` 项目内通过继承或封装实现
- `.venv` 中通过 `.pth` 文件引用源码（改源码立即生效），但不修改源码本身

## 规则三：对齐 L5 专家水平

- 攻击面覆盖必须完整：OWASP LLM Top 10 全部类别
- Probe 选择必须按 Tier 优先级排序（Tier1 > Tier2 > Tier3）
- 攻击链组合：支持 Buff 叠加（编码绕过 + 翻译 + 角色扮演）
- 报告必须包含 DEFCON 评分、攻击成功率 (ASR)、置信区间
- 代码质量：类型注解、docstring、异常处理完备

## 规则四：测试规范（强制执行）

- **每次代码修改都必须至少运行一次单元测试**
  - 命令：`python -m pytest tests/test_<module_name>.py -v`
  - 覆盖正常路径、边界条件、异常路径
- **涉及模块之间交互的改动，必须运行集成测试**
  - 命令：`python -m pytest tests/test_integration.py -v`
  - 验证模块间数据传递和状态流转
- **多模块同时修改，必须运行回归测试**
  - 命令：`python -m pytest tests/ -v`
  - 确保所有已有测试全部通过
- 测试文件命名：`tests/test_<module_name>.py`

## 规则五：文档更新

- 每次文档更新都使用最新的时间标签
- 格式：`YYYY-MM-DD HH:MM`（如 `2026-08-01 16:30`）
- 在文档顶部或修改处标注更新时间

## 规则六：代码风格

- 遵循 garak 项目的代码风格：British English 字符串、pathlib 优先
- 使用 `logging` 而非 `print` 进行调试输出
- 遵循 `pyproject.toml` 中的 black 配置（line-length=88）
- 不添加新依赖，优先使用 garak 已有依赖

## 规则七：模态感知探针选择（2026-08-01 新增）

- **Stage 1 侦察**必须检测目标模型的输入/输出模态能力
  - 优先从 garak Generator 的 `modality` 属性获取
  - 回退到模型名启发式推断（vision/vl/gpt-4o → image, whisper/audio → audio）
  - 模态信息必须存入 `target_profile.json` 的 `model_modality` 字段
- **Stage 2 配置**必须按模态过滤 Probe 候选
  - 匹配规则：`probe.modality["in"] ⊆ model.modality["in"]`（与 garak `_modality_match(strict=False)` 一致）
  - 不兼容的 Probe 必须在配置阶段移除，不可留到执行时被 harness 静默跳过
  - 过滤统计必须写入 `probe_selection.json` 的 `modality_filter` 字段
- **理论基础**：SDEval (arxiv 2508.06142), MMSafeAware (arxiv 2502.11184), OpenRT (arxiv 2601.01592), RAS (arxiv 2510.13698)
  - 跨模态安全交互需精准匹配攻击面，单一模态测试不足以覆盖真实威胁面
  - 静态评估基准存在数据泄漏问题，动态/自适应评估是趋势

## 规则八：自适应速率控制（2026-08-01 新增）

- 扫描必须使用慢启动策略（初始并发=4，逐步提升到目标并发）
  - 慢启动间隔默认 30 秒，每次倍增
- 每次 API 调用前必须加随机抖动延迟（默认 0.05-0.30 秒）
  - 打破规律时间指纹，避免被 WAF/API 速率检测识别为自动化扫描
- 检测到 429 限流必须自动降速
  - 并发缩减为当前的 50%，抖动范围扩大 1.5 倍
- 一段时间（默认 60s）无 429 后必须渐进恢复并发
  - 每次恢复步长 +4，抖动范围缩小 0.8 倍
- 控制器实现：`pipeline/adaptive_rate.py` → `AdaptiveRateController`
  - 通过 monkey-patch generator._call_model 注入抖动和 429 检测
  - 后台线程负责慢启动加速和渐进恢复
  - 统计信息写入 `execution_log.json` 的 `rate_control` 字段

## 规则九：HuggingFace 镜像容错（2026-08-01 新增）

- **Stage 3 执行前**必须检测 HuggingFace 官方站可达性
  - HEAD 请求 `huggingface.co`（超时 5s）
  - 官方不可达时，自动设置 `HF_ENDPOINT` 环境变量指向国内镜像 `https://hf-mirror.com`
  - 如果用户已显式设置 `HF_ENDPOINT`，尊重用户选择，跳过自动检测
- **huggingface_hub 原生支持**：`constants.ENDPOINT = os.getenv("HF_ENDPOINT", "https://huggingface.co")`
  - 设置环境变量后，所有 `from_pretrained()`、`hf_hub_download()`、`snapshot_download()` 自动走镜像
  - 无需修改任何 garak 或 transformers 源码
- **镜像不可达时的降级策略**：打印警告，继续执行（尝试使用本地缓存）
- **实现位置**：`pipeline/stage3_execute.py` → `_setup_hf_mirror()`
- **理论基础**：
  - LLM 供应链韧性 (arxiv 2411.01604)：模型中心是供应链关键节点，可用性直接影响安全评估可行性
  - MalHug (arxiv 2409.09368)：在蚂蚁集团 HuggingFace 镜像上验证了镜像作为替代源的可行性
  - ATOM Report (arxiv 2604.07190)：HuggingFace 不是唯一分发渠道，ModelScope 等中国平台也是重要替代源
  - SWIFT (arxiv 2408.05517)：阿里 ModelScope 团队已实现 HuggingFace + ModelScope 双源加载
  - 离线部署 (arxiv 2604.22768)：气隙隔离环境下安全评估需要离线/镜像资源支持

## 规则十：__pycache__ 自动清理 + main.py 纯编排（2026-08-01 新增）

- **每次 Pipeline 运行前和运行后**，必须自动清理项目下所有 `__pycache__` 目录
  - 防止 stale bytecode 导致 `TypeError: got an unexpected keyword argument`（参数变更后旧 .pyc 仍被加载）
  - 实现位置：`pipeline/utils.py` → `clean_pycache(project_root)`
  - 调用时机：`main.py` 在执行前和执行后各调用一次
- **main.py 必须是纯编排**，不包含任何业务逻辑
  - 只做：CLI 解析 → 配置加载 → pycache 清理 → 启动信息 → PipelineRunner.run() → 结果打印
  - 所有子功能必须从 `pipeline/` 模块导入（`pipeline.utils`, `pipeline.runner` 等）
  - 配置加载、启动信息打印、结果打印均在 `pipeline/utils.py` 中实现
  - 避免在 main.py 中直接实现业务逻辑，降低单点变更风险

## 规则十一：优化方案须先给出 L5 专家差距分析报告，确认后再改代码（2026-08-01 新增）

- **触发条件**：每次对方案进行优化、调整、重构或修复后（无论大小），在动手修改代码之前必须执行以下流程。
- **步骤 1 — 给出优化后的方案**：清晰描述本次优化/调整后的完整技术方案（做了什么、为什么、预期效果）。
- **步骤 2 — 给出 L5 专家水平差距分析报告**：以 L5（顶级专家）水准为基准，客观分析当前优化后方案与 100% 对齐 L5 专家水平之间仍存在哪些差距，至少覆盖：
  - 攻击面覆盖完整性（OWASP LLM Top 10 是否全覆盖、Tier 优先级、攻击链组合）
  - 检测与评估严谨性（DEFCON、ASR、置信区间、Judge 检测器严谨度）
  - 工程健壮性（并发/限流/重试/容错、跨平台兼容性如 Ollama 非标准格式）
  - 代码质量（类型注解、docstring、异常处理、测试覆盖）
  - 任何本次优化未触及但 L5 应具备的能力
- **步骤 3 — 给出对齐 100% L5 的完整优化解决方案**：针对步骤 2 的每一项差距，给出可落地的完整修复方案（含具体文件、方法、伪代码级别指引），目标是 100% 对齐 L5 专家水平。
- **步骤 4 — 待用户确认**：上述三步产出（优化方案 + 差距分析 + 完整解决方案）必须**先呈现给用户，等待用户明确确认后**再执行任何代码修改。禁止在未经确认前自动改代码。
- **例外**：纯文档/注释纠错、记忆库更新、用户已显式要求"立即实现/直接改"的指令，可跳过此确认流程（以用户当次指令为准）。
- **理论基础**：L5 专家验收标准（规则三）要求攻击面完整、Tier 排序、攻击链组合、DEFCON/ASR/置信区间、代码质量完备；任何优化都应以该标准为对齐目标，差距分析确保不降级、不遗漏。

## 规则十二：数据资产本地化 + 月度自动同步 + 官方优先回退镜像（2026-08-01 新增）

- **数据资产必须提前下载到本地目录**，避免扫描时远程下载慢或失败导致评估降级
  - 清单文件：`config/datasets.yaml`（每项含 `name` / `type` / `hf_repo` / `revision` 版本锁定 / `local_dir` / `mirror_repo` / 可选 `checksum`）
  - 管理器：`pipeline/data_manager.py` → `DataManager`
  - 本地根目录：`artifacts/datasets/`（已被 `.gitignore` 忽略，不入库）
- **下载源优先级（强制）**：**官网 (huggingface.co / 原始 URL) 优先 → 失败自动回退国内镜像 (hf-mirror.com / ModelScope)**
  - 实现：`DataManager._resolve_endpoints()` 生成 (官方, 镜像...) 端点列表，依次尝试
  - 切换机制：通过 `HF_ENDPOINT` 环境变量切换 HuggingFace 源，官方失败设 `HF_ENDPOINT=https://<mirror_host>` 重试
- **每月自动更新（增量同步）**：
  - 手动触发：`python main.py --sync-data`（增量）
  - 全量预下载：`python main.py --prefetch`
  - 自动注册系统定时任务：`python main.py --register-schedule`
    - Windows：注册 `schtasks` 月度计划任务（每月 1 日 03:10）
    - Linux/macOS：追加 `crontab` 条目（`10 3 1 * *`）
  - Pipeline 运行前若检测到本地缺失资产，自动预拉（可用 `--no-auto-prefetch` 关闭）
- **可复现性**：清单必须锁定 `revision`（commit hash 或分支）；可选 `checksum` 校验本地目录
- **同步日志**：每次同步写入 `artifacts/datasets/datasets_sync_log.json`
- **理论基础**：
  - LLM 供应链韧性 (arxiv 2411.01604)：模型/数据集中心是供应链关键节点，本地化保障评估可用性
  - MalHug (arxiv 2409.09368) / ATOM Report (arxiv 2604.07190) / SWIFT (arxiv 2408.05517)：镜像作为官方替代源的可行性与双源加载实践
  - 评估可复现性要求：固定版本 + 本地资产，避免上游变更导致评估漂移