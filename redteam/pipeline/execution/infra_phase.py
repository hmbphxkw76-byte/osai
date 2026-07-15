"""基础设施攻击阶段 (AI-300 Ch7+Ch9)。

执行基础设施攻击（5 步递进流程）：
  [1/5] 云元数据探测 — SSRF → IMDS → IAM 凭据提取 (Ch9.1)
  [2/5] K8s API 探测 — 容器编排平台侦察 (Ch9.3)
  [3/5] S3/存储端点探测 — 对象存储发现 (Ch9.2)
  [4/5] 推理端点探测 — SageMaker/Triton 模型服务 (Ch9.2)
  [5/5] 云配置错误检测 — IAM/网络安全组/公开暴露检查

对齐 OWASP LLM Top 10: LLM05 (Insecure Output Handling), LLM10 (Unbounded Consumption)
"""
from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from redteam.core.models import AIService, AuthContext, Finding, ReconResult
from redteam.core.store import load_json, save_json
from redteam.core.terminal_output import print_section_header
from redteam.attack.infra import scan_cloud_misconfigs, generate_infra_findings
from redteam.recon.infra_recon import (
    probe_cloud_metadata,
    probe_kubernetes_api,
    probe_s3_storage,
    probe_vault_server,
    probe_sagemaker_endpoints,
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
    print_section_header("[Phase 8] AI 基础设施攻击", "Cloud Metadata + K8s + Inference Endpoints")

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

    # 汇总 Cloud evidence 到 cloud_findings
    supply_risks: list[dict] = []

    findings = generate_infra_findings([], supply_risks, cloud_findings)
    all_findings.extend(findings)

    # 存储基础设施侦察结果到 JSON
    infra_recon_data = {
        "cloud_metadata": metadata_result,
        "kubernetes": k8s_result,
        "object_storage": s3_result,
        "inference_endpoints": inference_result,
        "cloud_evidence": cloud_evidence,
    }
    save_json(run_id, "infra_recon", infra_recon_data, subdir="recon")

    prior = load_json(run_id, "findings") or []
    all_findings = prior + [f.model_dump() for f in all_findings]
    save_json(run_id, "findings", all_findings, subdir="detect")
    return [Finding(**f) if isinstance(f, dict) else f for f in all_findings]


__all__ = [
    "infra_attack_phase",
]