"""AI 攻击面侦察（AI-300 Ch2-Ch11: Comprehensive Reconnaissance for AI Targets）。

模块：
  - discover.py: AI 服务发现、被动/主动侦察、端点枚举（含 A2A Agent Card + SIEM 检测）
  - fingerprint.py: 模型指纹识别（8种技术，含推理引擎指纹）
  - guardrail.py: 四阶段护栏画像（指纹/分类测试/绕过评估/输出过滤器检测）
  - rag_recon.py: RAG 流水线侦察（12项技术，含摄入端点+One-shot枚举+访问控制）
  - mcp_recon.py: MCP 协议侦察（传输类型检测/错误枚举/命令检测）
  - a2a_recon.py: A2A 协议侦察（Agent Card深度解析/协调模式/信任链分析）
  - evasion.py: 检测与规避（金丝雀令牌/隐蔽探测/速率限制探测/JS分析）
  - source_recon.py: 源代码仓库挖掘（含 MCP 模式/Pickle 漏洞/检查点检测）
  - git_recon.py: GitHub/GitLab 仓库侦察（含 GitLab PAT 认证/部署流水线/MCP 代码检测）
  - infra_recon.py: 云/基础设施侦察（SSRF 元数据/K8s API/S3/Vault/SageMaker）
  - domain_recon.py: AD/域侦察（计算机枚举/SPN/信任关系/权限分析/RDS Gateway）
  - auth_parse.py: 浏览器 F12 请求头解析
  - ai_surface.py: 向后兼容 shim

核心功能：
  - discover_ai_services: AI 服务发现（含 Agent Card + SIEM 路径）
  - passive_recon: 被动侦察（增强版，含AI插件+Agent Card发现）
  - profile_guardrails: 四阶段护栏画像（含输出过滤器检测）
  - fingerprint_model: 模型指纹识别（8种技术，含推理引擎指纹）
  - probe_rate_limit: 速率限制阈值探测
  - probe_rag_pipeline: RAG 流水线侦察（含向量数据库+摄入端点+One-shot）
  - probe_mcp_server: MCP 协议侦察（含传输检测+错误枚举）
  - probe_a2a_endpoint: A2A 协议侦察（Agent Card深度解析+协调模式）
  - probe_cloud_metadata: 云元数据探测（AWS/Azure/GCP IMDS）
  - probe_domain_ai_endpoints: AD/域 AI 服务侦察
  - scan_local_git_repo: 本地 Git 仓库扫描
  - probe_git_server: GitHub/GitLab 服务器侦察
  - probe_gitlab_with_token: GitLab PAT 认证私有仓库枚举
  - detect_mcp_server_patterns: 源代码 MCP 服务器模式检测
  - scan_pickle_vulnerabilities: Pickle 反序列化漏洞扫描
"""

# AI 服务发现（Ch2）
from .discover import (
    discover_ai_services,
    probe_ai_endpoint,
    passive_recon,
    enum_protected_endpoints,
    probe_realtime_endpoints,
)

# 模型指纹识别（Ch2.3）
from .fingerprint import (
    fingerprint_model,
)

# 四阶段护栏画像（Ch2+Ch3）
from .guardrail import (
    profile_guardrails,
    assess_output_filter,
)

# RAG 流水线侦察（Ch5）
from .rag_recon import (
    probe_rag_pipeline,
    probe_rag_ingestion_endpoints,
    enumerate_knowledge_base_via_oneshot,
    probe_access_control,
)

# MCP 协议侦察（Ch7）
from .mcp_recon import (
    probe_mcp_server,
    enumerate_mcp_tools,
    call_mcp_tool,
    enumerate_mcp_via_errors,
    detect_mcp_server_command,
)

# A2A 侦察（Ch4）
from .a2a_recon import (
    probe_a2a_endpoint,
    enumerate_agent_capabilities,
    map_trust_relationships,
    analyze_multi_agent_trust_chain,
    parse_agent_card_deep,
    detect_coordination_pattern,
)

# 检测与规避（Ch2.4）
from .evasion import (
    detect_canary_token,
    stealth_probe,
    probe_rate_limit,
    probe_determinism,
    analyze_detection_signatures,
    analyze_js_client,
)

# 源代码仓库挖掘（Ch2.2/Ch8）
from .source_recon import (
    analyze_git_repository,
    detect_mcp_server_patterns,
    scan_pickle_vulnerabilities,
)

# GitHub/GitLab 代码仓库侦察（Ch2.4/Ch8）
from .git_recon import (
    scan_local_git_repo,
    probe_git_server,
    probe_gitlab_with_token,
    detect_deployment_pipeline,
    detect_mcp_code_in_repo,
    GitRepoScanResult,
)

# 云/基础设施侦察（Ch9）
from .infra_recon import (
    probe_cloud_metadata,
    probe_kubernetes_api,
    probe_s3_storage,
    probe_vault_server,
    probe_sagemaker_endpoints,
)

# AD/域侦察（Ch11）
from .domain_recon import (
    enumerate_domain_computers,
    enumerate_spn_accounts,
    discover_domain_trusts,
    analyze_group_permissions,
    detect_rds_gateway,
    enumerate_ai_services_on_domain,
    probe_domain_ai_endpoints,
)

__all__ = [
    # AI 服务发现
    "discover_ai_services",
    "probe_ai_endpoint",
    "passive_recon",
    "enum_protected_endpoints",
    "probe_realtime_endpoints",
    # 模型指纹识别
    "fingerprint_model",
    # 护栏画像（四阶段）
    "profile_guardrails",
    "assess_output_filter",
    # RAG 侦察（12项技术）
    "probe_rag_pipeline",
    "probe_rag_ingestion_endpoints",
    "enumerate_knowledge_base_via_oneshot",
    "probe_access_control",
    # MCP 侦察
    "probe_mcp_server",
    "enumerate_mcp_tools",
    "call_mcp_tool",
    "enumerate_mcp_via_errors",
    "detect_mcp_server_command",
    # A2A 侦察
    "probe_a2a_endpoint",
    "enumerate_agent_capabilities",
    "map_trust_relationships",
    "analyze_multi_agent_trust_chain",
    "parse_agent_card_deep",
    "detect_coordination_pattern",
    # 检测与规避
    "detect_canary_token",
    "stealth_probe",
    "probe_rate_limit",
    "probe_determinism",
    "analyze_detection_signatures",
    "analyze_js_client",
    # 源代码侦察（Ch8 增强）
    "analyze_git_repository",
    "detect_mcp_server_patterns",
    "scan_pickle_vulnerabilities",
    # Git 仓库侦察（Ch8 增强）
    "scan_local_git_repo",
    "probe_git_server",
    "probe_gitlab_with_token",
    "detect_deployment_pipeline",
    "detect_mcp_code_in_repo",
    "GitRepoScanResult",
    # 云/基础设施侦察（Ch9）
    "probe_cloud_metadata",
    "probe_kubernetes_api",
    "probe_s3_storage",
    "probe_vault_server",
    "probe_sagemaker_endpoints",
    # AD/域侦察（Ch11）
    "enumerate_domain_computers",
    "enumerate_spn_accounts",
    "discover_domain_trusts",
    "analyze_group_permissions",
    "detect_rds_gateway",
    "enumerate_ai_services_on_domain",
    "probe_domain_ai_endpoints",
]