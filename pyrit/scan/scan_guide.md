# OffSec AI-300 Scan 目录使用指南

## 📋 概述

`scan` 目录包含针对 **OWASP Top 10 for LLMs (GenAI)**、**OWASP Agentic AI Top 10**、**RAG安全漏洞**、**Embedding安全漏洞**、**MCP Top 10**、**AI供应链攻击** 和 **AI基础设施漏洞** 的专用扫描脚本，每个安全类别都有独立的测试脚本，便于考试期间快速定位和测试特定漏洞类型。

**考试重点**：理解每个脚本对应的安全类别，能够快速选择和运行相关测试。

### OWASP Top 10 for LLMs v1.1 官方定义

| 编号 | 安全类别 | 英文名称 |
|------|---------|---------|
| LLM01 | 提示注入 | Prompt Injection |
| LLM02 | 不安全输出处理 | Insecure Output Handling |
| LLM03 | 训练数据投毒 | Training Data Poisoning |
| LLM04 | 模型拒绝服务 | Model Denial of Service |
| LLM05 | 供应链漏洞 | Supply Chain Vulnerabilities |
| LLM06 | 敏感信息泄露 | Sensitive Information Disclosure |
| LLM07 | 不安全插件设计 | Insecure Plugin Design |
| LLM08 | 过度代理权限 | Excessive Agency |
| LLM09 | 过度依赖 | Overreliance |
| LLM10 | 模型窃取 | Model Theft |

### OWASP Agentic AI Top 10 (2026) 官方定义

| 编号 | 安全类别 | 英文名称 |
|------|---------|---------|
| ASI01 | Agent目标劫持 | Agent Goal Hijack |
| ASI02 | 工具滥用与利用 | Tool Misuse and Exploitation |
| ASI03 | 身份与特权滥用 | Identity and Privilege Abuse |
| ASI04 | Agent供应链漏洞 | Agentic Supply Chain Vulnerabilities |
| ASI05 | 意外代码执行 | Unexpected Code Execution |
| ASI06 | 内存投毒 | Memory Poisoning |
| ASI07 | 不安全Agent间通信（A2A） | Insecure Inter-Agent Communication |
| ASI08 | 级联故障 | Cascading Failures |
| ASI09 | 利用人机信任 | Exploitation of Human-Agent Trust |
| ASI10 | 恶意Agent | Rogue Agents |

### RAG安全漏洞分类

| 编号 | 安全类别 | 英文名称 |
|------|---------|---------|
| RAG01 | RAG间接提示注入 | RAG Indirect Prompt Injection |
| RAG02 | RAG语料库投毒 | RAG Corpus Poisoning |
| RAG03 | RAG检索操纵 | RAG Retrieval Manipulation |
| RAG04 | RAG数据泄露 | RAG Data Leakage |
| RAG05 | RAG上下文混淆 | RAG Context Confusion |
| RAG06 | RAG幻觉利用 | RAG Hallucination Exploitation |

### Embedding安全漏洞分类

| 编号 | 安全类别 | 英文名称 |
|------|---------|---------|
| EMB01 | 向量反转攻击 | Embedding Inversion |
| EMB02 | 向量投毒攻击 | Vector Poisoning |
| EMB03 | 对抗性嵌入攻击 | Adversarial Embedding |
| EMB04 | 向量数据库提取 | Vector Database Extraction |
| EMB05 | 成员推理攻击 | Membership Inference |
| EMB06 | 嵌入空间碰撞 | Embedding Space Collision |

### OWASP Top 10 for LLMs 2025 Edition 新增类别

| 编号 | 安全类别 | 英文名称 |
|------|---------|---------|
| LLM07 (2025) | 系统提示词泄露 | System Prompt Leakage |
| LLM08 (2025) | 向量与嵌入弱点 | Vector and Embedding Weaknesses |

### MCP Top 10 完整列表

| 编号 | 安全类别 | 英文名称 |
|------|---------|---------|
| MCP01 | Token管理不当与密钥泄露 | Token Mismanagement & Secret Exposure |
| MCP02 | 范围蔓延导致权限提升 | Privilege Escalation via Scope Creep |
| MCP03 | 工具投毒 | Tool Poisoning |
| MCP04 | 软件供应链攻击与依赖篡改 | Software Supply Chain Attacks & Dependency Tampering |
| MCP05 | 命令注入与执行 | Command Injection & Execution |
| MCP06 | 意图流颠覆 | Intent Flow Subversion |
| MCP07 | 认证与授权不足 | Insufficient Authentication & Authorization |
| MCP08 | 审计与遥测不足 | Lack of Audit and Telemetry |
| MCP09 | 影子MCP服务器 | Shadow MCP Servers |
| MCP10 | 上下文注入与过度分享 | Context Injection & Over-Sharing |

### AI供应链攻击分类

| 编号 | 安全类别 | 英文名称 |
|------|---------|---------|
| SC01 | 数据集投毒 | Dataset Poisoning |
| SC02 | 模型权重篡改 | Model Weight Tampering |
| SC03 | 第三方依赖攻击 | Third-Party Dependency Attack |
| SC04 | 适配器恶意代码注入 | Adapter Malicious Code Injection |

### AI基础设施漏洞分类

| 编号 | 安全类别 | 英文名称 |
|------|---------|---------|
| INF01 | 云AI平台漏洞 | Cloud AI Platform Vulnerabilities |
| INF02 | 模型服务器攻击 | Model Server Attacks |
| INF03 | 容器逃逸 | Container Escape |
| INF04 | API未授权访问 | Unauthorized API Access |
| INF05 | 配置错误利用 | Configuration Exploitation |

## 📂 目录结构

```
scan/
├── platform_config_loader.py                     # 平台配置加载器
├── llm01_prompt_injection_scan.py                # LLM01 - 提示注入
├── llm02_insecure_output_scan.py                 # LLM02 - 不安全输出处理
├── llm03_training_data_poisoning_scan.py         # LLM03 - 训练数据投毒
├── llm04_model_inversion_scan.py                 # LLM04 - 模型反演
├── llm05_denial_of_service_scan.py               # LLM05 - 拒绝服务
├── llm06_supply_chain_scan.py                    # LLM06 - 供应链漏洞（旧版命名）
├── llm06_sensitive_info_disclosure_scan.py      # LLM06 - 敏感信息泄露（标准命名）
├── llm07_insecure_plugin_scan.py                 # LLM07 - 不安全插件设计（旧版命名）
├── llm07_insecure_plugin_design_scan.py          # LLM07 - 不安全插件设计（标准命名）
├── llm08_excessive_agency_scan.py                # LLM08 - 过度代理权限
├── llm09_overreliance_scan.py                    # LLM09 - 过度依赖
├── llm10_model_theft_scan.py                     # LLM10 - 模型窃取
├── mcp01_context_injection_scan.py               # MCP01 - 上下文注入
├── mcp02_tool_abuse_scan.py                      # MCP02 - 工具滥用
├── mcp03_information_leakage_scan.py             # MCP03 - 信息泄露
├── mcp04_prompt_leakage_scan.py                  # MCP04 - 提示泄露
├── mcp05_authentication_bypass_scan.py           # MCP05 - 认证绕过
├── asi01_agent_goal_hijack_scan.py               # ASI01 - Agent目标劫持
├── asi02_tool_misuse_scan.py                     # ASI02 - 工具滥用与利用
├── asi03_identity_privilege_abuse_scan.py        # ASI03 - 身份与特权滥用
├── asi04_supply_chain_vulnerabilities_scan.py    # ASI04 - Agent供应链漏洞
├── asi05_unexpected_code_execution_scan.py       # ASI05 - 意外代码执行
├── asi06_memory_poisoning_scan.py                # ASI06 - 内存投毒
├── asi07_insecure_inter_agent_communication_scan.py # ASI07 - 不安全Agent间通信（A2A）
├── asi08_cascading_failures_scan.py              # ASI08 - 级联故障
├── asi09_human_agent_trust_scan.py               # ASI09 - 利用人机信任
├── asi10_rogue_agents_scan.py                    # ASI10 - 恶意Agent
├── rag01_indirect_prompt_injection_scan.py       # RAG01 - 间接提示注入
├── rag02_corpus_poisoning_scan.py                # RAG02 - 语料库投毒
├── rag03_retrieval_manipulation_scan.py          # RAG03 - 检索操纵
├── rag04_data_leakage_scan.py                    # RAG04 - 数据泄露
├── rag05_context_confusion_scan.py               # RAG05 - 上下文混淆
├── rag06_hallucination_exploitation_scan.py      # RAG06 - 幻觉利用
├── emb01_embedding_inversion_scan.py             # EMB01 - 向量反转攻击
├── emb02_vector_poisoning_scan.py                # EMB02 - 向量投毒攻击
├── emb03_adversarial_embedding_scan.py           # EMB03 - 对抗性嵌入攻击
├── emb04_vector_database_extraction_scan.py      # EMB04 - 向量数据库提取
├── emb05_membership_inference_scan.py            # EMB05 - 成员推理攻击
├── emb06_embedding_space_collision_scan.py       # EMB06 - 嵌入空间碰撞
├── mcp06_intent_flow_subversion_scan.py          # MCP06 - 意图流颠覆
├── mcp07_insufficient_authentication_scan.py     # MCP07 - 认证与授权不足
├── mcp08_lack_of_audit_scan.py                   # MCP08 - 审计与遥测不足
├── mcp09_shadow_mcp_servers_scan.py              # MCP09 - 影子MCP服务器
├── mcp10_context_injection_oversharing_scan.py   # MCP10 - 上下文注入与过度分享
├── llm07_2025_system_prompt_leakage_scan.py      # LLM07-2025 - 系统提示词泄露
├── supply_chain_attack_scan.py                   # AI供应链攻击
├── infrastructure_exploit_scan.py                # AI基础设施漏洞
├── comprehensive_scan.py                         # 快速全面扫描（覆盖所有类别）
├── exam_focus_scan.py                            # 考试重点扫描（高频考点）
└── scan_guide.md                                 # 本指南
```

## 🚀 使用方式

### 1. 配置平台

修改上级目录的 `.env` 文件：

```powershell
PLATFORM_SELECTOR=ZHIPU  # 选择平台: ZHIPU, OLLAMA, OPENAI, AZURE_OPENAI, DEEPSEEK, GEMINI
```

### 2. 运行单个类别扫描

```powershell
# 运行 LLM01 提示注入扫描
py.exe '.\scan\llm01_prompt_injection_scan.py'

# 运行 LLM02 不安全输出扫描
py.exe '.\scan\llm02_insecure_output_scan.py'

# 运行 MCP01 上下文注入扫描
py.exe '.\scan\mcp01_context_injection_scan.py'
```

### 3. 运行快速全面扫描

```powershell
# 扫描所有安全类别（16个测试用例）
py.exe '.\scan\comprehensive_scan.py'
```

### 4. 运行考试重点扫描

```powershell
# 扫描考试高频考点（18个测试用例）
py.exe '.\scan\exam_focus_scan.py'
```

## 🎯 安全类别对应表

### OWASP Top 10 for LLMs (GenAI) v1.1

| 脚本 | 安全类别 | 考试重要性 | 说明 |
|------|---------|-----------|------|
| `llm01_prompt_injection_scan.py` | LLM01 - Prompt Injection | ⭐⭐⭐⭐⭐ | 提示注入攻击 |
| `llm02_insecure_output_scan.py` | LLM02 - Insecure Output Handling | ⭐⭐⭐⭐⭐ | 不安全输出处理 |
| `llm03_training_data_poisoning_scan.py` | LLM03 - Training Data Poisoning | ⭐⭐⭐ | 训练数据投毒 |
| `llm04_model_inversion_scan.py` | LLM04 - Model Inversion | ⭐⭐⭐⭐⭐ | 模型反演 |
| `llm05_denial_of_service_scan.py` | LLM05 - Denial of Service | ⭐⭐ | 拒绝服务 |
| `llm06_sensitive_info_disclosure_scan.py` | LLM06 - Sensitive Information Disclosure | ⭐⭐⭐⭐⭐ | 敏感信息泄露 |
| `llm07_insecure_plugin_design_scan.py` | LLM07 - Insecure Plugin Design | ⭐⭐⭐ | 不安全插件设计 |
| `llm08_excessive_agency_scan.py` | LLM08 - Excessive Agency | ⭐⭐⭐⭐⭐ | 过度代理权限 |
| `llm09_overreliance_scan.py` | LLM09 - Overreliance | ⭐⭐ | 过度依赖 |
| `llm10_model_theft_scan.py` | LLM10 - Model Theft | ⭐⭐⭐⭐⭐ | 模型窃取 |

### MCP Top 10

| 脚本 | 安全类别 | 考试重要性 | 说明 |
|------|---------|-----------|------|
| `mcp01_context_injection_scan.py` | MCP01 - Context Injection | ⭐⭐⭐⭐⭐ | 上下文注入 |
| `mcp02_tool_abuse_scan.py` | MCP02 - Tool Abuse | ⭐⭐⭐ | 工具滥用 |
| `mcp03_information_leakage_scan.py` | MCP03 - Information Leakage | ⭐⭐⭐⭐⭐ | 信息泄露 |
| `mcp04_prompt_leakage_scan.py` | MCP04 - Prompt Leakage | ⭐⭐⭐ | 提示泄露 |
| `mcp05_authentication_bypass_scan.py` | MCP05 - Authentication Bypass | ⭐⭐⭐⭐⭐ | 认证绕过 |
| `mcp06_intent_flow_subversion_scan.py` | MCP06 - Intent Flow Subversion | ⭐⭐⭐⭐⭐ | 意图流颠覆（最高优先级） |
| `mcp07_insufficient_authentication_scan.py` | MCP07 - Insufficient Authentication & Authorization | ⭐⭐⭐⭐⭐ | 认证与授权不足（最高优先级） |
| `mcp08_lack_of_audit_scan.py` | MCP08 - Lack of Audit and Telemetry | ⭐⭐⭐ | 审计与遥测不足（中优先级） |
| `mcp09_shadow_mcp_servers_scan.py` | MCP09 - Shadow MCP Servers | ⭐⭐⭐ | 影子MCP服务器（中优先级） |
| `mcp10_context_injection_oversharing_scan.py` | MCP10 - Context Injection & Over-Sharing | ⭐⭐⭐⭐⭐ | 上下文注入与过度分享（最高优先级） |

### OWASP Top 10 for LLMs 2025 Edition 新增

| 脚本 | 安全类别 | 考试重要性 | 说明 |
|------|---------|-----------|------|
| `llm07_2025_system_prompt_leakage_scan.py` | LLM07 (2025) - System Prompt Leakage | ⭐⭐⭐⭐⭐ | 系统提示词泄露（最高优先级） |

### AI供应链攻击

| 脚本 | 安全类别 | 考试重要性 | 说明 |
|------|---------|-----------|------|
| `supply_chain_attack_scan.py` | AI Supply Chain Attacks | ⭐⭐⭐⭐⭐ | AI供应链攻击（最高优先级） |

### AI基础设施漏洞

| 脚本 | 安全类别 | 考试重要性 | 说明 |
|------|---------|-----------|------|
| `infrastructure_exploit_scan.py` | AI Infrastructure Exploits | ⭐⭐⭐⭐⭐ | AI基础设施漏洞（最高优先级） |

### OWASP Agentic AI Top 10 (2026)

| 脚本 | 安全类别 | 考试重要性 | 说明 |
|------|---------|-----------|------|
| `asi01_agent_goal_hijack_scan.py` | ASI01 - Agent Goal Hijack | ⭐⭐⭐⭐⭐ | Agent目标劫持 |
| `asi02_tool_misuse_scan.py` | ASI02 - Tool Misuse and Exploitation | ⭐⭐⭐⭐⭐ | 工具滥用与利用 |
| `asi03_identity_privilege_abuse_scan.py` | ASI03 - Identity and Privilege Abuse | ⭐⭐⭐⭐⭐ | 身份与特权滥用 |
| `asi04_supply_chain_vulnerabilities_scan.py` | ASI04 - Agentic Supply Chain Vulnerabilities | ⭐⭐⭐ | Agent供应链漏洞 |
| `asi05_unexpected_code_execution_scan.py` | ASI05 - Unexpected Code Execution | ⭐⭐⭐⭐⭐ | 意外代码执行 |
| `asi06_memory_poisoning_scan.py` | ASI06 - Memory Poisoning | ⭐⭐⭐⭐⭐ | 内存投毒 |
| `asi07_insecure_inter_agent_communication_scan.py` | ASI07 - Insecure Inter-Agent Communication (A2A) | ⭐⭐⭐⭐⭐ | 不安全Agent间通信（A2A核心） |
| `asi08_cascading_failures_scan.py` | ASI08 - Cascading Failures | ⭐⭐ | 级联故障 |
| `asi09_human_agent_trust_scan.py` | ASI09 - Exploitation of Human-Agent Trust | ⭐⭐⭐ | 利用人机信任 |
| `asi10_rogue_agents_scan.py` | ASI10 - Rogue Agents | ⭐⭐⭐⭐ | 恶意Agent |

### RAG安全漏洞

| 脚本 | 安全类别 | 考试重要性 | 说明 |
|------|---------|-----------|------|
| `rag01_indirect_prompt_injection_scan.py` | RAG01 - Indirect Prompt Injection | ⭐⭐⭐⭐⭐ | 间接提示注入（最高优先级） |
| `rag02_corpus_poisoning_scan.py` | RAG02 - Corpus Poisoning | ⭐⭐⭐⭐⭐ | 语料库投毒（最高优先级） |
| `rag03_retrieval_manipulation_scan.py` | RAG03 - Retrieval Manipulation | ⭐⭐⭐⭐ | 检索操纵（高优先级） |
| `rag04_data_leakage_scan.py` | RAG04 - Data Leakage | ⭐⭐⭐⭐⭐ | 数据泄露（最高优先级） |
| `rag05_context_confusion_scan.py` | RAG05 - Context Confusion | ⭐⭐⭐ | 上下文混淆（中优先级） |
| `rag06_hallucination_exploitation_scan.py` | RAG06 - Hallucination Exploitation | ⭐⭐⭐ | 幻觉利用（中优先级） |

### Embedding安全漏洞

| 脚本 | 安全类别 | 考试重要性 | 说明 |
|------|---------|-----------|------|
| `emb01_embedding_inversion_scan.py` | EMB01 - Embedding Inversion | ⭐⭐⭐⭐⭐ | 向量反转攻击（最高优先级） |
| `emb02_vector_poisoning_scan.py` | EMB02 - Vector Poisoning | ⭐⭐⭐⭐⭐ | 向量投毒攻击（最高优先级） |
| `emb03_adversarial_embedding_scan.py` | EMB03 - Adversarial Embedding | ⭐⭐⭐⭐ | 对抗性嵌入攻击（高优先级） |
| `emb04_vector_database_extraction_scan.py` | EMB04 - Vector Database Extraction | ⭐⭐⭐⭐⭐ | 向量数据库提取（最高优先级） |
| `emb05_membership_inference_scan.py` | EMB05 - Membership Inference | ⭐⭐⭐ | 成员推理攻击（中优先级） |
| `emb06_embedding_space_collision_scan.py` | EMB06 - Embedding Space Collision | ⭐⭐⭐ | 嵌入空间碰撞（中优先级） |

## ✏️ 修改测试用例

每个脚本都有明确的 `ATTACK_TEST_CASES` 配置区域，考试时只需修改这里：

```python
# ============================================
# 🎯 攻击测试用例配置（考试时只需修改这里！）
# ============================================
ATTACK_TEST_CASES = [
    {
        "id": 1,
        "objective": "你的攻击目标",
        "criterion": "对应的评分标准",
    },
    # 添加更多测试用例...
]
```

**配置说明**：
- `id`：用例编号
- `objective`：攻击目标，即发送给模型的提示词
- `criterion`：评分标准，用于判断攻击是否成功

## 📊 考试实战策略

### 策略1：先全面扫描，再深入测试

```powershell
# 第一步：运行全面扫描快速定位漏洞
py.exe '.\scan\comprehensive_scan.py'

# 第二步：根据结果深入测试成功的类别
py.exe '.\scan\llm01_prompt_injection_scan.py'  # 如果 LLM01 成功
py.exe '.\scan\mcp01_context_injection_scan.py'  # 如果 MCP01 成功
```

### 策略2：直接测试高频考点

```powershell
# 优先测试考试重点
py.exe '.\scan\exam_focus_scan.py'
```

### 策略3：针对特定题目测试

```powershell
# 如果题目涉及提示注入
py.exe '.\scan\llm01_prompt_injection_scan.py'

# 如果题目涉及信息泄露
py.exe '.\scan\mcp03_information_leakage_scan.py'

# 如果题目涉及认证绕过
py.exe '.\scan\mcp05_authentication_bypass_scan.py'

# 如果题目涉及Agent目标劫持
py.exe '.\scan\asi01_agent_goal_hijack_scan.py'

# 如果题目涉及A2A通信安全（Agent-to-Agent）
py.exe '.\scan\asi07_insecure_inter_agent_communication_scan.py'

# 如果题目涉及工具滥用
py.exe '.\scan\asi02_tool_misuse_scan.py'

# 如果题目涉及RAG间接提示注入
py.exe '.\scan\rag01_indirect_prompt_injection_scan.py'

# 如果题目涉及RAG语料库投毒
py.exe '.\scan\rag02_corpus_poisoning_scan.py'

# 如果题目涉及RAG数据泄露
py.exe '.\scan\rag04_data_leakage_scan.py'

# 如果题目涉及向量反转攻击
py.exe '.\scan\emb01_embedding_inversion_scan.py'

# 如果题目涉及向量投毒攻击
py.exe '.\scan\emb02_vector_poisoning_scan.py'

# 如果题目涉及向量数据库提取
py.exe '.\scan\emb04_vector_database_extraction_scan.py'

# 如果题目涉及意图流颠覆（MCP06）
py.exe '.\scan\mcp06_intent_flow_subversion_scan.py'

# 如果题目涉及认证与授权不足（MCP07）
py.exe '.\scan\mcp07_insufficient_authentication_scan.py'

# 如果题目涉及上下文注入与过度分享（MCP10）
py.exe '.\scan\mcp10_context_injection_oversharing_scan.py'

# 如果题目涉及系统提示词泄露（LLM07-2025）
py.exe '.\scan\llm07_2025_system_prompt_leakage_scan.py'

# 如果题目涉及AI供应链攻击
py.exe '.\scan\supply_chain_attack_scan.py'

# 如果题目涉及AI基础设施漏洞
py.exe '.\scan\infrastructure_exploit_scan.py'
```

## 📝 代码结构说明

所有脚本遵循统一的结构：

```python
"""
头部注释：脚本说明、使用方式、安全声明
"""

# 导入依赖
import asyncio
import os
import sys

# 加载平台配置
from platform_config_loader import load_platform_config
load_platform_config()

# 导入 PyRIT 模块
from pyrit.setup import IN_MEMORY, initialize_pyrit_async
from pyrit.prompt_target import OpenAIChatTarget
from pyrit.score import SelfAskTrueFalseScorer, TrueFalseQuestion
from pyrit.executor.attack import AttackScoringConfig, PromptSendingAttack
from pyrit.output.attack_result.pretty import PrettyAttackResultMemoryPrinter

# 🎯 测试用例配置区域（考试时修改这里！）
ATTACK_TEST_CASES = [...]

# 异步扫描函数
async def run_xxx_scan():
    # 初始化 PyRIT
    await initialize_pyrit_async(memory_db_type=IN_MEMORY)
    
    # 创建目标和评分器
    target = OpenAIChatTarget()
    scorer_target = OpenAIChatTarget()
    
    # 遍历测试用例执行攻击
    for case in ATTACK_TEST_CASES:
        scorer = SelfAskTrueFalseScorer(...)
        attack = PromptSendingAttack(...)
        result = await attack.execute_async(...)
    
    # 输出结果汇总

# 运行入口
asyncio.run(run_xxx_scan())
```

## ⚠️ 安全声明

本目录中的脚本仅用于授权的安全测试和学习目的，请勿用于非法用途。使用前请确保已获得充分授权。

## 🔗 相关资源

| 资源 | 说明 |
|------|------|
| [pyrit_scan_guide.md](file:///D:/文档/codes/ai_sec/pyrit/pyrit_scan_guide.md) | pyrit_scan 命令行工具指南 |
| [pyrit_scan_wrapper.py](file:///D:/文档/codes/ai_sec/pyrit/pyrit_scan_wrapper.py) | pyrit_scan 代码封装脚本 |
| [airt_scan.py](file:///D:/文档/codes/ai_sec/pyrit/airt_scan.py) | AIRT 场景测试脚本 |
| [custom_scenario_example.py](file:///D:/文档/codes/ai_sec/pyrit/custom_scenario_example.py) | 自定义场景示例 |