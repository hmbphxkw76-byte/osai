"""基础设施攻击阶段 (AI-300 Ch7+Ch9)。

执行基础设施攻击（11 步递进流程）：
  [1/5] 云元数据探测 — SSRF → IMDS → IAM 凭据提取 (Ch9.1)
  [2/5] K8s API 探测 — 容器编排平台侦察 (Ch9.3)
  [3/5] S3/存储端点探测 — 对象存储发现 (Ch9.2)
  [4/5] 推理端点探测 — SageMaker/Triton 模型服务 (Ch9.2)
  [5/5] 云配置错误检测 — IAM/网络安全组/公开暴露检查
  [6/11] MCP L1 服务器漏洞利用 — 版本泄露、未授权工具调用 (Ch7)
  [7/11] MCP L2 传输层攻击 — SSE注入、stdio劫持、协议降级 (Ch7)
  [8/11] MCP L3 消息格式注入 — 批量溢出、深度嵌套、Unicode转义 (Ch7)
  [9/11] MCP Token 泄露检测 — 工具参数/错误消息/调试信息 (Ch7 MCP-01)
  [10/11] MCP 能力混淆 — 同名工具/范围绕过/描述欺骗 (Ch7 MCP-07)
  [11/11] MCP 会话固定 — 会话注入/重用/URL泄露 (Ch7 MCP-08)

对齐 OWASP LLM Top 10: LLM05, LLM10, LLM06, LLM02
对齐 OWASP ASI Top 10: ASI02 (Tool Misuse), ASI03 (Identity Abuse)
"""
from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from redteam.core.models import AIService, AuthContext, Finding, ReconResult, OWASPLlm, OWASP_AGENTIC, MITREATLASTactic
from redteam.core.store import load_json, save_json

from redteam.attack.infra import scan_cloud_misconfigs, generate_infra_findings
from redteam.recon.infra_recon import (
    probe_cloud_metadata,
    probe_kubernetes_api,
    probe_s3_storage,
    probe_vault_server,
    probe_sagemaker_endpoints,
)
from redteam.attack.mcp_advanced import (
    probe_mcp_server_exploit,
    probe_mcp_transport_attack,
    probe_mcp_message_injection,
    run_mcp_deep_attack_suite,
)
from redteam.attack.mcp_l6 import (
    probe_mcp_token_leak,
    probe_mcp_capability_confusion,
    probe_mcp_session_fixation,
    run_mcp_l6_attack_suite,
)


def _extract_base_url(target: str) -> str:
    """从目标 URL 提取 scheme+netloc 基础部分。"""
    parsed = urlparse(target)
    return f"{parsed.scheme}://{parsed.netloc}"


def infra_attack_phase(
    run_id: str,
    recon: ReconResult,
    services: list[AIService],
    auth: AuthContext | None = None,
) -> list[Finding]:
    """AI 基础设施攻击 (Ch7+Ch9) — 5 步递进流程。

    云/基础设施侦察在自动攻击阶段执行（而非 Phase 1 侦察阶段），
    因为这些探测需要已获得 SSRF 入口或内网立足点。仅当 recon 结果
    指示目标为云/K8s 环境时触发对应探测。

    本阶段聚焦：
      - 云元数据服务探测 (Ch9.1 SSRF → IMDS)
      - K8s API 侦察与密钥枚举 (Ch9.3)
      - S3/MinIO 存储发现 (Ch9.2)
      - SageMaker/Triton 推理端点识别 (Ch9.2)
      - Vault 密钥管理检测 (Ch9.3)
    """
    all_findings: list[Finding] = []
    base_url = _extract_base_url(recon.target)
    cloud_evidence: list[dict] = []

    # ═══════════════════════════════════════════════════════════════
    # [1/5] 云元数据探测 — SSRF 凭据提取
    # ═══════════════════════════════════════════════════════════════
    print("\n[1/5] 云元数据探测 (IMDS)...")
    metadata_result = probe_cloud_metadata(target=base_url, auth=auth, timeout=5.0)
    if metadata_result.get("metadata_detected"):
        provider = metadata_result.get("cloud_provider", "unknown")
        roles = metadata_result.get("iam_roles", [])
        creds = metadata_result.get("credentials_found", [])
        print(f"  ⚠️  检测到云提供商: {provider}")
        print(f"  IAM 角色: {len(roles)} 个")
        print(f"  凭据泄露: {len(creds)} 条")
        cloud_evidence.append({
            "type": "cloud_metadata",
            "provider": provider,
            "iam_roles": roles,
            "credentials_count": len(creds),
        })
    else:
        print("  未检测到云元数据端点")

    # ═══════════════════════════════════════════════════════════════
    # [2/5] K8s API 探测
    # ═══════════════════════════════════════════════════════════════
    print("\n[2/5] K8s API 探测...")
    k8s_result = probe_kubernetes_api(target=base_url, auth=auth, timeout=5.0)
    if k8s_result.get("k8s_detected"):
        version = k8s_result.get("version", "unknown")
        nss = len(k8s_result.get("namespaces", []))
        secrets = len(k8s_result.get("secrets", []))
        pods = len(k8s_result.get("pods", []))
        print(f"  ⚠️  检测到 Kubernetes 集群: v{version}")
        print(f"  命名空间: {nss}  密钥: {secrets}  Pods: {pods}")
        cloud_evidence.append({
            "type": "kubernetes",
            "version": version,
            "namespace_count": nss,
            "secret_count": secrets,
            "pod_count": pods,
        })
    else:
        print("  未检测到 K8s API")

    # ═══════════════════════════════════════════════════════════════
    # [3/5] S3/对象存储探测
    # ═══════════════════════════════════════════════════════════════
    print("\n[3/5] S3/对象存储探测...")
    s3_result = probe_s3_storage(target=base_url, auth=auth, timeout=5.0)
    if s3_result.get("storage_detected"):
        stype = s3_result.get("storage_type", "unknown")
        buckets = len(s3_result.get("buckets", []))
        print(f"  ⚠️  检测到对象存储: {stype} ({buckets} 个 buckets)")
        cloud_evidence.append({
            "type": "object_storage",
            "storage_type": stype,
            "bucket_count": buckets,
        })
    else:
        print("  未检测到对象存储端点")

    # ═══════════════════════════════════════════════════════════════
    # [4/5] AI 推理端点探测
    # ═══════════════════════════════════════════════════════════════
    print("\n[4/5] AI 推理端点探测 (SageMaker/Triton)...")
    inference_result = probe_sagemaker_endpoints(target=base_url, auth=auth, timeout=5.0)
    if inference_result.get("inference_detected"):
        itype = inference_result.get("inference_type", "unknown")
        models = inference_result.get("models", [])
        print(f"  ⚠️  检测到推理端点: {itype}")
        if models:
            print(f"  模型: {', '.join(models[:5])}")
        cloud_evidence.append({
            "type": "inference_endpoint",
            "inference_type": itype,
            "model_count": len(models),
        })
    else:
        print("  未检测到 AI 推理端点")

    # ═══════════════════════════════════════════════════════════════
    # [5/5] 云配置错误检测
    # ═══════════════════════════════════════════════════════════════
    print("\n[5/5] AI 云端配置检查...")
    cloud_findings = scan_cloud_misconfigs(recon.target)
    if cloud_findings:
        print(f"  发现 {len(cloud_findings)} 个配置问题")
    else:
        print("  未发现明显配置问题")

    # ═══════════════════════════════════════════════════════════════
    # [6/8] MCP L1 服务器漏洞利用探测
    # ═══════════════════════════════════════════════════════════════
    mcp_findings: list[dict] = []
    mcp_services = [s for s in services if s.protocol == "mcp" or "mcp" in s.url.lower()]
    if mcp_services:
        print("\n[6/8] MCP L1 服务器漏洞利用 (Server Exploitation)...")
        for mcp_svc in mcp_services[:3]:  # 限制探测 3 个 MCP 服务
            try:
                results = probe_mcp_server_exploit(mcp_svc, auth=auth, timeout=10.0)
                succeeded = [r for r in results if r.success]
                if succeeded:
                    techniques = [getattr(r, 'technique', '') or r.technique for r in succeeded]
                    mcp_findings.append({
                        "source": "infra_mcp_l1",
                        "category": "mcp_server_exploit",
                        "severity": "high",
                        "title": f"MCP服务器漏洞利用: {mcp_svc.url}",
                        "description": f"发现 {len(succeeded)}/{len(results)} 个MCP服务器漏洞利用向量: {', '.join(techniques)}",
                        "owasp_llm": OWASPLlm.LLM06_EXCESSIVE_AGENCY.value,
                        "owasp_agentic": OWASP_AGENTIC.ASI02_TOOL_MISUSE.value,
                        "mitre_atlas_tactic": MITREATLASTactic.EXECUTION.value,
                        "endpoint": mcp_svc.url,
                        "evidence": str(succeeded[0].response_preview)[:500] if succeeded else "",
                    })
                    print(f"  ⚠️  MCP服务器漏洞利用成功: {mcp_svc.url} ({len(succeeded)} vectors)")
                else:
                    print(f"  MCP服务器硬防护正常: {mcp_svc.url}")
            except Exception as e:
                print(f"  ⚠ MCP L1 探测异常: {mcp_svc.url} - {str(e)[:80]}")

        # ── [7/8] MCP L2 传输层攻击 ──
        print("\n[7/8] MCP L2 传输层攻击 (Transport Attack)...")
        for mcp_svc in mcp_services[:3]:
            try:
                results = probe_mcp_transport_attack(mcp_svc, auth=auth, timeout=10.0)
                succeeded = [r for r in results if r.success]
                if succeeded:
                    techniques = [getattr(r, 'technique', '') or r.technique for r in succeeded]
                    mcp_findings.append({
                        "source": "infra_mcp_l2",
                        "category": "mcp_transport_attack",
                        "severity": "critical" if any("hijack" in t for t in techniques) else "high",
                        "title": f"MCP传输层攻击: {mcp_svc.url}",
                        "description": f"发现 {len(succeeded)}/{len(results)} 个MCP传输层攻击向量: {', '.join(techniques)}",
                        "owasp_llm": OWASPLlm.LLM06_EXCESSIVE_AGENCY.value,
                        "owasp_agentic": OWASP_AGENTIC.ASI02_TOOL_MISUSE.value,
                        "mitre_atlas_tactic": MITREATLASTactic.INITIAL_ACCESS.value,
                        "endpoint": mcp_svc.url,
                        "evidence": str(succeeded[0].response_preview)[:500] if succeeded else "",
                    })
                    print(f"  ⚠️  MCP传输层攻击成功: {mcp_svc.url} ({len(succeeded)} vectors)")
                else:
                    print(f"  MCP传输层安全: {mcp_svc.url}")
            except Exception as e:
                print(f"  ⚠ MCP L2 探测异常: {mcp_svc.url} - {str(e)[:80]}")

        # ── [8/8] MCP L3 消息格式注入 ──
        print("\n[8/8] MCP L3 消息格式注入 (Message Injection)...")
        for mcp_svc in mcp_services[:3]:
            try:
                results = probe_mcp_message_injection(mcp_svc, auth=auth, timeout=10.0)
                succeeded = [r for r in results if r.success]
                if succeeded:
                    techniques = [getattr(r, 'technique', '') or r.technique for r in succeeded]
                    mcp_findings.append({
                        "source": "infra_mcp_l3",
                        "category": "mcp_message_injection",
                        "severity": "high",
                        "title": f"MCP消息格式注入: {mcp_svc.url}",
                        "description": f"发现 {len(succeeded)}/{len(results)} 个MCP消息注入向量: {', '.join(techniques)}",
                        "owasp_llm": OWASPLlm.LLM05_OUTPUT_HANDLING.value,
                        "owasp_agentic": OWASP_AGENTIC.ASI02_TOOL_MISUSE.value,
                        "mitre_atlas_tactic": MITREATLASTactic.EXECUTION.value,
                        "endpoint": mcp_svc.url,
                        "evidence": str(succeeded[0].response_preview)[:500] if succeeded else "",
                    })
                    print(f"  ⚠️  MCP消息注入成功: {mcp_svc.url} ({len(succeeded)} vectors)")
                else:
                    print(f"  MCP消息过滤正常: {mcp_svc.url}")
            except Exception as e:
                print(f"  ⚠ MCP L3 探测异常: {mcp_svc.url} - {str(e)[:80]}")
        # ── [9/11] MCP Token 泄露检测 (L6) ──
        print("\n[9/11] MCP Token 泄露检测 (MCP-01)...")
        for mcp_svc in mcp_services[:3]:
            try:
                results = probe_mcp_token_leak(mcp_svc, auth=auth, timeout=10.0)
                succeeded = [r for r in results if r.success]
                leak_detected = [r for r in results if getattr(r, 'leak_detected', False)]
                if leak_detected or succeeded:
                    mcp_findings.append({
                        "source": "infra_mcp_token_leak",
                        "category": "mcp_token_leak",
                        "severity": "critical",
                        "title": f"MCP Token泄露: {mcp_svc.url}",
                        "description": f"发现 {len(leak_detected) or len(succeeded)} 个Token泄露指标",
                        "owasp_llm": OWASPLlm.LLM02_SENSITIVE_INFO.value,
                        "owasp_agentic": OWASP_AGENTIC.ASI02_TOOL_MISUSE.value,
                        "mitre_atlas_tactic": MITREATLASTactic.EXFILTRATION.value,
                        "endpoint": mcp_svc.url,
                        "evidence": str(succeeded[0].response_preview)[:500] if succeeded else "",
                    })
                    print(f"  ⚠️  Token泄露检测成功: {mcp_svc.url}")
                else:
                    print(f"  Token管理安全: {mcp_svc.url}")
            except Exception as e:
                print(f"  ⚠ MCP Token检测异常: {mcp_svc.url} - {str(e)[:80]}")

        # ── [10/11] MCP 能力混淆 (L6) ──
        print("\n[10/11] MCP 能力混淆检测 (MCP-07)...")
        for mcp_svc in mcp_services[:3]:
            try:
                results = probe_mcp_capability_confusion(mcp_svc, auth=auth, timeout=10.0)
                succeeded = [r for r in results if r.success]
                if succeeded:
                    mcp_findings.append({
                        "source": "infra_mcp_capability_confusion",
                        "category": "mcp_capability_confusion",
                        "severity": "high",
                        "title": f"MCP能力混淆: {mcp_svc.url}",
                        "description": f"发现 {len(succeeded)} 个能力混淆漏洞",
                        "owasp_llm": OWASPLlm.LLM06_EXCESSIVE_AGENCY.value,
                        "owasp_agentic": OWASP_AGENTIC.ASI02_TOOL_MISUSE.value,
                        "mitre_atlas_tactic": MITREATLASTactic.DEFENSE_EVASION.value,
                        "endpoint": mcp_svc.url,
                        "evidence": str(succeeded[0].response_preview)[:500] if succeeded else "",
                    })
                    print(f"  ⚠️  能力混淆检测成功: {mcp_svc.url}")
                else:
                    print(f"  能力边界清晰: {mcp_svc.url}")
            except Exception as e:
                print(f"  ⚠ MCP能力混淆异常: {mcp_svc.url} - {str(e)[:80]}")

        # ── [11/11] MCP 会话固定 (L6) ──
        print("\n[11/11] MCP 会话固定检测 (MCP-08)...")
        for mcp_svc in mcp_services[:3]:
            try:
                results = probe_mcp_session_fixation(mcp_svc, auth=auth, timeout=10.0)
                succeeded = [r for r in results if r.success]
                if succeeded:
                    mcp_findings.append({
                        "source": "infra_mcp_session_fix",
                        "category": "mcp_session_fixation",
                        "severity": "high",
                        "title": f"MCP会话固定: {mcp_svc.url}",
                        "description": f"发现 {len(succeeded)} 个会话固定漏洞",
                        "owasp_llm": OWASPLlm.LLM06_EXCESSIVE_AGENCY.value,
                        "owasp_agentic": OWASP_AGENTIC.ASI03_IDENTITY_ABUSE.value,
                        "mitre_atlas_tactic": MITREATLASTactic.INITIAL_ACCESS.value,
                        "endpoint": mcp_svc.url,
                        "evidence": str(succeeded[0].response_preview)[:500] if succeeded else "",
                    })
                    print(f"  ⚠️  会话固定检测成功: {mcp_svc.url}")
                else:
                    print(f"  会话管理安全: {mcp_svc.url}")
            except Exception as e:
                print(f"  ⚠ MCP会话固定异常: {mcp_svc.url} - {str(e)[:80]}")
    else:
        print("\n[9/11] MCP 深度攻击 — 未检测到 MCP 服务，跳过")

    # 汇总 Cloud evidence 到 cloud_findings
    supply_risks: list[dict] = []

    findings = generate_infra_findings(supply_risks, supply_risks, cloud_findings)
    all_findings.extend(findings)
    # 追加 MCP Findings
    all_findings.extend(mcp_findings)

    # 存储基础设施侦察结果到 JSON（含 MCP 攻击结果）
    infra_recon_data = {
        "cloud_metadata": metadata_result,
        "kubernetes": k8s_result,
        "object_storage": s3_result,
        "inference_endpoints": inference_result,
        "cloud_evidence": cloud_evidence,
        "mcp_findings_count": len(mcp_findings),
    }
    save_json(run_id, "infra_recon", infra_recon_data, subdir="recon")

    # Persist accumulated findings to JSON store (for checkpoint/resume)
    prior = load_json(run_id, "findings") or []
    accumulated = prior + [f.model_dump() if hasattr(f, 'model_dump') else f for f in all_findings]
    save_json(run_id, "findings", accumulated, subdir="detect")
    # Return ONLY this phase's own findings (not accumulated history)
    return all_findings


__all__ = [
    "infra_attack_phase",
]