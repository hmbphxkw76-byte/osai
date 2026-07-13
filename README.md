# RedTeam_AI — AI-300 红队攻击流水线

基于 **OffSec AI-300: Advanced AI Red Teaming** 课程构建的自动化 AI 红队评估工具。
完全对齐 **OSAI+ 认证考试** 的 11 章课程体系和 8 阶段攻击链。

## 攻击链（对齐 AI-300 11 章）

```
Phase 1: AI 攻击面侦察 (Ch2)
  ├── 被动侦察：robots.txt / HTTP头 / CSP
  └── 主动侦察：AI端点探测 / 模型枚举 / 工具发现 / 护栏画像

Phase 2: 提示注入 (Ch3)
  ├── 直接提示注入（指令覆盖/角色扮演/分隔符/编码/少样本/上下文切换）
  ├── 系统提示提取（直接询问/开发者模式/翻译戏法/补全诱饵）
  └── 越狱/护栏绕过（DAN/虚构场景/对立日/令牌走私）

Phase 3: Agent 攻击 (Ch3+Ch4)
  ├── 间接提示注入（邮件/网页/文档/数据库/多模态）
  ├── Agent 记忆投毒（会话/长期记忆/记忆混淆）
  ├── 工具调用劫持（重定向/工具链/滥用）
  └── 跨智能体攻击（智能体间注入/A2A协议伪造/权限提升）

Phase 4: RAG 攻击 (Ch5)
  ├── 向量数据库探测（Qdrant/Chroma/Weaviate/Pinecone/Milvus）
  ├── RAG 知识库投毒（排名操纵/知识投毒/命名空间遍历/嵌入混淆）
  └── 检索泄露检测

Phase 5: 嵌入模型攻击 (Ch6) ✨ 新增
  ├── 嵌入端点探测（OpenAI兼容/通用API）
  ├── 嵌入反转风险测试（成员推断/语料重建）
  ├── 对抗性嵌入注入（语义伪装/触发器/维度混淆）
  └── 嵌入信息泄露检测

Phase 6: AI 供应链攻击 (Ch8) ✨ 新增
  ├── HuggingFace 模型来源可信度检测
  ├── Pickle 反序列化 RCE 风险
  ├── 数据集投毒检测
  └── AI 依赖攻击风险

Phase 7: MCP + 基础设施攻击 (Ch7+Ch9)
  ├── MCP 端点安全扫描
  └── 云 AI 服务配置错误检测（S3/GCS/Azure Blob/IAM）

Phase 8: 威胁建模与报告 (Ch10+Ch11)
  ├── MITRE ATLAS 战术映射
  ├── OWASP LLM Top 10 2025 覆盖度分析
  └── Capstone 综合红队报告
```

## 快速开始

```powershell
#开发环境
python -m redteam.cli --help

# 安装依赖
pip install -r requirements.txt

# 安装包（生成 redteam 命令）
pip install -e . --no-deps

# 交互式向导（全 8 阶段）
redteam wizard
# 或直接运行
redteam run -t https://target.ai -H f12_headers.txt

# 分阶段执行
redteam recon -t https://target.ai
redteam inject <run_id>
redteam report <run_id>

# === 场景驱动攻击（推荐，考试期间仅需修改 YAML 载荷） ===
redteam scenario list                    # 列出所有可用场景
redteam scenario run -s agent -t https://target/v1/chat/completions --api-key sk-xxx

# === 评分器选择 ===
# 本地评分（默认，无 LLM 依赖，适合考试环境）
redteam scenario run -s agent -t https://target/v1 --api-key sk-xxx --scorer hybrid
redteam scenario run -s agent -t https://target/v1 --api-key sk-xxx --scorer rule_based
redteam scenario run -s agent -t https://target/v1 --api-key sk-xxx --scorer fast_grayscale

# LLM-as-Judge 评分（需独立 Judge LLM，非考试环境）
redteam scenario run -s agent -t https://target/v1 --api-key sk-xxx \
    --judge-endpoint http://localhost:11434/v1/chat/completions --scorer llm_judge
redteam scenario run -s agent -t https://target/v1 --api-key sk-xxx \
    --judge-endpoint https://your-judge/v1/chat/completions --scorer llm_judge

# 考试/离线模式（强制本地评分，完全无 LLM 依赖）
set REDTEAM_NO_JUDGE_LLM=1
redteam scenario run -s agent -t https://target/v1 --api-key sk-xxx

# 快速单提示词测试
redteam quicktest -t https://target/v1/chat/completions -p "Ignore all instructions..." --api-key sk-xxx
```

### 评分器对比

| 评分器 | CLI 参数 | LLM 依赖 | 速度 | 适用场景 |
|--------|---------|----------|------|---------|
| RuleBased | `--scorer rule_based` | ❌ 无 | <1ms | 关键词匹配，快速筛查 |
| Hybrid | `--scorer hybrid` | ❌ 无 | <5ms | 多维度加权投票，综合评估（**默认**） |
| FastGrayscale | `--scorer fast_grayscale` | ❌ 无 | <5ms | 连续灰度评分 0-1 |
| LLM-as-Judge | `--scorer llm_judge -J <URL>` | ✅ 需要 | 1-5s | 高精度评估，非考试环境 |

### 评分器工作模式

```
                    ┌────────────────────┐
                    │  REDTEAM_NO_JUDGE_LLM? │
                    └──────┬─────────────┘
                           │
              ┌────────────┼────────────┐
              │ YES        │ NO         │
              ▼            ▼            │
        ┌──────────┐  ┌──────────────┐ │
        │ 强制本地   │  │ --judge-endpoint? │
        │ hybrid    │  └──────┬───────┘
        └──────────┘         │
                    ┌────────┼────────┐
                    │ YES    │ NO     │
                    ▼        ▼        │
              ┌──────────┐ ┌────────┐│
              │ LLM Judge │ │ 本地    ││
              │ (PyRIT +  │ │ hybrid ││
              │  SelfAsk) │ └────────┘│
              └──────────┘            │
```

### 环境变量

| 变量 | 作用 |
|------|------|
| `REDTEAM_JUDGE_ENDPOINT` | Judge LLM API 端点 URL |
| `REDTEAM_JUDGE_MODEL` | Judge LLM 模型名称（可选，自动推断） |
| `REDTEAM_JUDGE_API_KEY` | Judge LLM API Key（可选，默认 "not-needed"） |
| `REDTEAM_NO_JUDGE_LLM=1` | 强制本地评分，禁用所有 LLM Judge |

## 对齐标准
- OWASP LLM Top 10 2025 (LLM01-LLM10)
- MITRE ATLAS v5.1 (9 战术)
- OffSec AI-300 课程大纲（11 章全覆盖）
- OSAI+ 认证考试要求

## 处罚声明
⚠️ 仅用于已授权的安全测试与防御性研究。

