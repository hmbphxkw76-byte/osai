# RedTeam-AI 项目长期记忆

## 项目约定

### 技术栈偏好
- Python >= 3.10，类型提示必须
- Pydantic v2 风格数据模型
- httpx 异步 HTTP 客户端
- 枚举优先于字符串常量

### 开发规范
- 每个 Finding 必须绑定 OWASPLlm + MITREATLASTactic
- 禁止在代码/配置中存储真实凭据
- 测试使用合成数据
- 文件命名 snake_case
- Library-First 原则：首选纯 Python 库，次选 Kali 标准工具

### 用户偏好
- 中文交流，中文注释和文档
- 偏好使用现有文件编辑而非创建新文件
- Kali Linux 目标环境

## 目录结构规范

### .trae/（强制规则，Git 版本控制，Source of Truth）
- `.trae/rules/`：Trae IDE 强制规则，团队协作共享
- **规则修改优先更新 `.trae`，再同步 `.codebuddy`**

### .codebuddy/（辅助记忆，副本）
- `.codebuddy/memory/`：项目长期记忆和会话记忆
- `.codebuddy/rules/`：辅助规则，与 `.trae` 保持一致
- **仅作为辅助参考，规则变更以 `.trae` 为准**

## AI-300 攻击方法学

### 攻击循环：Enumerate-Attack-Detect-Evade
1. **Enumerate**：探测端点、工具发现、权限边界
2. **Attack Naive**：直接使用已知技术
3. **Detect**：检查检测规则触发情况
4. **Evade**：字符间隔、Base64编码、多轮crescendo、CSS隐藏等

### Agent 核心组件
- LLM Core、System Prompt、Tools、Memory（短期/长期）、Guardrails

### 攻击面分类
- 单 Agent 攻击（提示注入、记忆投毒）
- 多 Agent 攻击（A2A 协议、协调模式）
- RAG 管道攻击（检索器、知识库投毒）
- Embedding 攻击（反演、成员推断、属性推断）
- 供应链攻击（Pickle、模型投毒、依赖混淆）
- 基础设施攻击（云配置、容器利用）

## 项目文档体系

| 文档 | 路径 | 用途 |
|------|------|------|
| 开发标准 | `docs/DEVELOPMENT_STANDARDS.md` | 代码架构、数据模型、代码风格规范 |
| OSAI 对齐规则 | `docs/OSAI_ALIGNMENT_RULES.md` | AI-300 考试对齐的 7 条核心规则 |
| 考试工具指南 | `docs/AI300_EXAM_TOOLS.md` | AI-300 考试备考工具参考，含工具与章节映射 |
| 强制规则 | `.trae/rules/redteam-dev-standards/RULE.mdc` | Trae IDE 强制规则（Source of Truth） |
| 辅助规则 | `.codebuddy/rules/redteam-dev-standards/RULE.mdc` | 辅助规则（与 .trae 同步） |
