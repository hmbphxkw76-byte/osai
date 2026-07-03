# OffSec AI-300 OWASP 扫描脚本指南

## 📋 概述

本指南提供了 OffSec AI-300 考试所需的所有 OWASP 扫描脚本的完整说明。所有脚本均基于 PyRIT 框架实现，遵循最小化修改原则，便于考试期间快速复用。

## 📁 目录结构

```
owasp/
├── platform_config_loader.py      # 平台配置加载器
├── scan_guide.md                  # 扫描指南文档
├── recon_ai_targets_scan.py       # AI目标侦察扫描
├── threat_modeling_scan.py        # AI威胁建模扫描
├── infrastructure_exploit_scan.py # AI基础设施攻击扫描
├── supply_chain_attack_scan.py    # AI供应链攻击扫描
├── llm01_prompt_injection_scan.py         # LLM01-提示注入
├── llm02_insecure_output_scan.py          # LLM02-不安全输出
├── llm03_training_data_poisoning_scan.py  # LLM03-训练数据投毒
├── llm04_model_inversion_scan.py         # LLM04-模型逆向
├── llm05_denial_of_service_scan.py       # LLM05-拒绝服务
├── llm06_sensitive_info_disclosure_scan.py # LLM06-敏感信息泄露
├── llm06_supply_chain_scan.py            # LLM06-供应链攻击
├── llm07_insecure_plugin_scan.py         # LLM07-不安全插件
├── llm07_insecure_plugin_design_scan.py  # LLM07-插件设计缺陷
├── llm07_2025_system_prompt_leakage_scan.py # LLM07-系统提示泄露
├── llm08_excessive_agency_scan.py        # LLM08-过度代理
├── llm09_overreliance_scan.py            # LLM09-过度依赖
├── llm10_model_theft_scan.py             # LLM10-模型窃取
├── asi01_agent_goal_hijack_scan.py          # ASI01-Agent目标劫持
├── asi02_tool_misuse_scan.py                # ASI02-工具滥用
├── asi03_identity_privilege_abuse_scan.py   # ASI03-身份权限滥用
├── asi04_supply_chain_vulnerabilities_scan.py # ASI04-供应链漏洞
├── asi05_unexpected_code_execution_scan.py   # ASI05-意外代码执行
├── asi06_memory_poisoning_scan.py            # ASI06-内存投毒
├── asi07_insecure_inter_agent_communication_scan.py # ASI07-不安全Agent间通信
├── asi08_cascading_failures_scan.py          # ASI08-级联故障
├── asi09_human_agent_trust_scan.py           # ASI09-人机信任
├── asi10_rogue_agents_scan.py                # ASI10-恶意Agent
├── rag01_indirect_prompt_injection_scan.py   # RAG01-间接提示注入
├── rag02_corpus_poisoning_scan.py            # RAG02-语料投毒
├── rag03_retrieval_manipulation_scan.py     # RAG03-检索操纵
├── rag04_data_leakage_scan.py                # RAG04-数据泄露
├── rag05_context_confusion_scan.py          # RAG05-上下文混淆
├── rag06_hallucination_exploitation_scan.py # RAG06-幻觉利用
├── emb01_embedding_inversion_scan.py        # EMB01-嵌入逆向
├── emb02_vector_poisoning_scan.py           # EMB02-向量投毒
├── emb03_adversarial_embedding_scan.py      # EMB03-对抗性嵌入
├── emb04_vector_database_extraction_scan.py # EMB04-向量数据库提取
├── emb05_membership_inference_scan.py       # EMB05-成员推断
├── emb06_embedding_space_collision_scan.py  # EMB06-嵌入空间碰撞
├── mcp01_context_injection_scan.py          # MCP01-上下文注入
├── mcp02_tool_abuse_scan.py                 # MCP02-工具滥用
├── mcp03_information_leakage_scan.py        # MCP03-信息泄露
├── mcp04_prompt_leakage_scan.py             # MCP04-提示泄露
├── mcp05_authentication_bypass_scan.py      # MCP05-认证绕过
├── mcp06_intent_flow_subversion_scan.py     # MCP06-意图流颠覆
├── mcp07_insufficient_authentication_scan.py # MCP07-认证不足
├── mcp08_lack_of_audit_scan.py              # MCP08-缺乏审计
├── mcp09_shadow_mcp_servers_scan.py         # MCP09-影子MCP服务器
└── mcp10_context_injection_oversharing_scan.py # MCP10-上下文过度共享
```

## 🎯 考试模块对应关系

| 考试模块 | 脚本文件 | 数量 | 状态 |
|---------|---------|------|------|
| Reconnaissance for AI Targets | recon_ai_targets_scan.py | 1 | ✅ |
| Attacking AI Agents | llm01-llm10 | 10 | ✅ |
| Attacking Multi-Agent Systems | asi01-asi10 | 10 | ✅ |
| Exploiting RAG Pipelines | rag01-rag06 | 6 | ✅ |
| Attacking Embeddings | emb01-emb06 | 6 | ✅ |
| Attacking Model Context Protocol | mcp01-mcp10 | 10 | ✅ |
| Supply Chain Attacks | supply_chain_attack_scan.py | 1 | ✅ |
| AI Infrastructure Exploits | infrastructure_exploit_scan.py | 1 | ✅ |
| Threat Modeling for AI-Enabled Targets | threat_modeling_scan.py | 1 | ✅ |

**总计: 46个扫描脚本**

## 🚀 快速开始

### 1. 配置环境

在项目根目录创建 `.env` 文件：

```ini
[DEFAULT]
PLATFORM_SELECTOR=ZHIPU

[ZHIPU]
AZURE_OPENAI_API_KEY=your_api_key
AZURE_OPENAI_ENDPOINT=https://open.bigmodel.cn/api/paas/v4/
AZURE_OPENAI_API_VERSION=2023-05-15
AZURE_OPENAI_CHAT_DEPLOYMENT_NAME=glm-4

[OLLAMA]
AZURE_OPENAI_API_KEY=ollama
AZURE_OPENAI_ENDPOINT=http://localhost:11434/v1
AZURE_OPENAI_API_VERSION=2023-05-15
AZURE_OPENAI_CHAT_DEPLOYMENT_NAME=llama3

[OPENAI]
AZURE_OPENAI_API_KEY=your_openai_key
AZURE_OPENAI_ENDPOINT=https://api.openai.com/v1
AZURE_OPENAI_API_VERSION=2023-05-15
AZURE_OPENAI_CHAT_DEPLOYMENT_NAME=gpt-4o

[DEEPSEEK]
AZURE_OPENAI_API_KEY=your_deepseek_key
AZURE_OPENAI_ENDPOINT=https://api.deepseek.com/v1
AZURE_OPENAI_API_VERSION=2023-05-15
AZURE_OPENAI_CHAT_DEPLOYMENT_NAME=deepseek-chat

[GEMINI]
AZURE_OPENAI_API_KEY=your_gemini_key
AZURE_OPENAI_ENDPOINT=https://generativelanguage.googleapis.com/v1
AZURE_OPENAI_API_VERSION=2023-05-15
AZURE_OPENAI_CHAT_DEPLOYMENT_NAME=models/gemini-pro
```

### 2. 运行扫描脚本

```powershell
# 切换到项目目录
cd d:\文档\codes\ai_sec\pyrit

# 运行单个扫描脚本
py.exe .\owasp\llm01_prompt_injection_scan.py

# 运行侦察扫描
py.exe .\owasp\recon_ai_targets_scan.py

# 运行威胁建模扫描
py.exe .\owasp\threat_modeling_scan.py
```

## 📝 脚本结构说明

所有扫描脚本遵循统一的代码结构：

### 1. 文档头部（第1-23行）
- 脚本标题和说明
- 使用说明（配置.env、修改测试用例、运行方式）
- OWASP分类描述

### 2. 导入模块（第25-41行）
- 基础模块：asyncio, os, sys
- 平台配置：platform_config_loader
- PyRIT核心模块：setup, prompt_target, score, executor, output

### 3. 攻击测试用例配置（第43-80行）
```python
ATTACK_TEST_CASES = [
    {
        "id": 1,
        "objective": "攻击目标描述",
        "criterion": "评分标准（成功条件）",
    },
    # 考试时在此添加更多测试用例
]
```

### 4. 扫描函数（第82-154行）
- 初始化PyRIT
- 创建目标和评分器
- 遍历测试用例执行攻击
- 输出结果汇总

## 💡 考试策略

### 最小化修改原则

考试期间只需修改 `ATTACK_TEST_CASES` 列表中的内容：

1. **添加新测试用例**：复制注释模板，修改 `objective` 和 `criterion`
2. **修改现有测试用例**：根据目标系统调整攻击目标和评分标准
3. **删除不需要的测试用例**：注释或删除不适用的用例

### 快速复用技巧

1. **提前准备测试用例库**：根据常见场景准备多组攻击payload
2. **复制粘贴**：使用已有脚本作为模板，快速创建新的测试用例
3. **批量执行**：编写批处理脚本一次性运行多个扫描脚本

### 攻击效率提升

1. **优先执行高成功率攻击**：先运行侦察和提示注入类脚本
2. **链式攻击**：利用侦察结果定制后续攻击payload
3. **结果分析**：根据扫描结果调整攻击策略

## ⚠️ 注意事项

1. **仅用于授权测试**：所有脚本仅供安全测试和学习目的
2. **遵守法律法规**：在合法授权范围内使用
3. **数据保护**：测试过程中注意保护敏感信息
4. **环境隔离**：建议在隔离环境中进行测试

## 📊 结果解读

扫描结果包含：
- ✅ **成功**：攻击有效，目标存在漏洞
- ❌ **失败**：攻击无效，目标防御有效
- ⚠️ **错误**：执行过程中发生错误

成功率计算公式：`成功数 / 总用例数 × 100%`

---

*文档版本: v1.0*
*更新日期: 2026-07-03*