# pyrit-web-recon 项目规则

## 核心禁令（最高优先级，必须始终遵循）

> **严禁修改、删除或创建 `pyrit_ai300` 目录及其子目录下的任何文件和内容。**
> **严禁修改、删除或创建本项目（`pyrit-web-recon`）外的任何文件。**

这是本项目的第一守则。无论用户要求、IDE 自动提示还是任何工具建议，都不得以任何理由触碰外部目录（尤其是 `pyrit_ai300`）。

## 1. 项目边界原则

**绝对禁止修改、删除或创建本项目外的任何文件。**

- 工作目录：`d:\\文档\\GitHub\\osai\\pyrit-web-recon`
- 只允许在当前项目目录及其子目录内进行文件操作。
- **特别禁止**：访问、修改、删除、创建 `..\\pyrit_ai300` 目录及其任何子目录或文件。
- 不允许访问、修改、删除其他任何外部路径。
- 如果用户明确要求操作外部文件，必须先让用户确认并提供完整路径，且仍建议优先在项目内完成。

## 2. 安全与敏感信息

- 禁止将真实 API Key、密码、Cookie、Token 等敏感信息硬编码到代码中。
- 敏感配置应通过 `.env` 文件提供；`.env` 已被 `.gitignore` 忽略，不会进入版本控制。
- 凭据文件统一保存到 `credentials/` 目录，该目录下的具体 `.txt` 文件被忽略，仅保留 `credentials/.gitkeep`。
- `.env.example` 原则上只保留 `RECON_TARGET_URL` 一个必填参数；其余参数使用内置默认值。
  例外：当目标需要先登录时，允许在 `.env` 中可选配置 `RECON_USERNAME` / `RECON_PASSWORD`，
  由 Pipeline 在检测到登录页后自动填充表单（不点击登录/不处理验证码）。
  该例外已在 `.env.example` 和 `README.md` 中显式说明。

## 3. 代码风格

- 使用 Python 3.10+ 类型注解。
- 保持模块职责单一，优先复用现有工具函数和类。
- 中文注释面向学习者，关键逻辑需逐行或按块说明。
- 不重复造轮子，优先使用成熟开源库（Playwright、httpx、pyyaml、python-dotenv 等）。

## 4. 流水线约定

- 所有侦察功能通过 `src/pipeline` 的 Stage 实现。
- `main.py` 统一使用 `PipelineRunner` 编排阶段。
- 每个 Stage 应返回 `StageResult`，异常由 `PipelineStage.execute` 统一捕获。
- 浏览器阶段（navigation / entry_discovery / dom_recon / network_interception / probe_interaction）在 `target_type == "api"` 时自动跳过。

## 5. 输出规范

- 侦察结果输出到 `results/recon/`、`data/burp/`。
- 生成三类产物：TargetProfile（JSON/YAML）、Burp/Repeater 模板、PyRIT target 配置。
- 截图、浏览器状态、凭据等敏感产物不得提交到 Git。

## 6. 测试与验证

- 新增功能需提供可运行的验证步骤。
- 本地测试优先使用 `tests/mock_llm_server.py`，避免对外部真实目标发起请求。
- 每次修改后运行 `python main.py --help` 和至少一种目标类型的 Pipeline 验证。
