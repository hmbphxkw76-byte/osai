"""recon — Burp 拦截与侦察阶段。

攻击链路第 1 步: 从 Burp 拦截的 HTTP 请求解析目标信息,
构建 HTTPTarget, 探测目标能力指纹。

核心模块:
    - burp_parser: 解析 Burp HTTP 请求, 提取 URL/Headers/Body, 注入 {PROMPT}
    - target_router: 构建 HTTPTarget + RateLimitedTarget, 创建 adversarial/scoring target
    - capability_detector: 探测目标能力 (agent/mcp/rag/embedding)
    - confidence_scorer: 能力置信度评分 (SSOT)
    - mcp_enumerator: MCP 协议深度探测
    - system_prompt_extractor: 系统提示泄露探测
    - endpoint_sorter: 多 endpoint 攻击优先级排序
    - adaptive_probe_config: 自适应探测深度 (按目标复杂度动态分配)
    - behavioral_verifier: 行为验证层 (验证声明能力 vs 实际能力)
    - capability_monitor: 能力漂移检测 (攻击过程中监测目标变化)
    - guardrail_detector: 护栏探测 (识别目标安全护栏类型)
    - model_seed_mapper: 种子映射 (模型指纹 → 最优种子配置)
    - stealth_config: Stealth Level 分级 (隐蔽性控制)
"""

from recon.adaptive_probe_config import compute_probe_budget, should_run_probe
from recon.behavioral_verifier import BehavioralVerifyReport, behavioral_verify
from recon.burp_parser import ParsedBurpRequest, build_http_target, parse_burp_request
from recon.capability_monitor import CapabilityDriftMonitor, CapabilitySnapshot, get_drift_monitor
from recon.confidence_scorer import (
    CapabilityResult,
    ConvergenceResult,
    aggregate_capabilities,
    merge_verification_into_capabilities,
    score_capability,
    score_capability_with_convergence,
)
from recon.endpoint_sorter import sort_burp_list_by_priority, sort_endpoints_by_priority
from recon.guardrail_detector import GuardrailReport, detect_guardrail
from recon.model_seed_mapper import (
    ModelSeedMapper,
    detect_model_family,
    get_mapper,
    get_seeds_for_model,
)
from recon.stealth_config import StealthLevelManager, StealthPolicy, get_stealth_manager
from recon.target_router import create_target

__all__ = [
    # Core (existing)
    "ParsedBurpRequest",
    "parse_burp_request",
    "build_http_target",
    "create_target",
    "sort_burp_list_by_priority",
    "sort_endpoints_by_priority",
    # Adaptive probing (NEW - Strategy 3)
    "compute_probe_budget",
    "should_run_probe",
    # Behavioral verification (NEW - Strategy 2)
    "BehavioralVerifyReport",
    "behavioral_verify",
    # Confidence scoring with convergence (NEW - Strategy 1)
    "CapabilityResult",
    "ConvergenceResult",
    "aggregate_capabilities",
    "score_capability",
    "score_capability_with_convergence",
    "merge_verification_into_capabilities",
    # Capability drift monitor (NEW - Strategy 4)
    "CapabilityDriftMonitor",
    "CapabilitySnapshot",
    "get_drift_monitor",
    # Guardrail detection (NEW)
    "GuardrailReport",
    "detect_guardrail",
    # Model seed mapping (NEW - Strategy 6)
    "ModelSeedMapper",
    "detect_model_family",
    "get_mapper",
    "get_seeds_for_model",
    # Stealth config (NEW - Strategy 5)
    "StealthLevelManager",
    "StealthPolicy",
    "get_stealth_manager",
]
