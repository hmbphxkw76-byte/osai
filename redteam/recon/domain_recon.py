"""AD/域服务侦察（AI-300 Ch11 Capstone Red Team Engagement）。

实现 AI-300 考试（Ch11）中的域侦察技术：
  1. AD 域计算机枚举：DirectorySearcher LDAP 查询
  2. SPN 服务主体名称枚举：识别关键服务（TERMSRV, WSMAN, RDS）
  3. 域信任关系发现：跨域森林信任分析
  4. 组权限分析：GenericWrite/WriteDacl 等危险权限发现
  5. RDS Gateway 检测与策略枚举：Remote Desktop Services 网关注册
  6. AI 服务域关联分析：发现域控环境中运行的 AI 服务

考试场景（AI-300 Ch11）：
  1. Public Website → AI Chatbot → Tool hijack → DB01 foothold
  2. DB01 → AD enumeration → WEB01 discovery → credential extraction
  3. Domain trust enumeration → DEV domain → RDS Gateway pivot
  4. SPN discovery → service targeting → lateral movement
  5. Group membership manipulation → privilege escalation

对齐 OWASP LLM Top 10: LLM06 (Excessive Agency), LLM05 (Insecure Output Handling)
"""

from __future__ import annotations

import re
import socket
import time
from typing import Any
from urllib.parse import urlparse

from redteam.core.models import DomainServiceInfo

# === AD/LDAP 常见属性（AI-300 Ch11.1 Domain Enumeration） ===
_AD_COMPUTER_CLASSES = ["computer", "server", "workstation"]
_AD_SERVICE_SPNS = [
    "TERMSRV",      # Remote Desktop Services
    "WSMAN",        # WinRM
    "HOST",         # Host service
    "HTTP",         # Web services
    "MSSQLSvc",    # SQL Server
    "CIFS",         # File sharing
    "LDAP",         # Directory services
    "RestrictedKrbHost",  # Kerberos host
    "RDS",          # Remote Desktop Gateway
    "GC",           # Global Catalog
]
_AD_AI_SERVICE_INDICATORS = [
    "ollama",
    "vllm",
    "langchain",
    "milvus",
    "qdrant",
    "chromadb",
    "pinecone",
    "weaviate",
    "mlflow",
    "sagemaker",
    "triton",
    "ray",
    "kubeflow",
    "airflow",
    "ml-pipeline",
    "mcp-server",
    "agent",
    "rag",
    "vector-db",
    "embedding",
    "llm",
    "ai-engine",
    "inference",
    "gpu",
    "cuda",
]


# === LDAP 查询模板（AI-300 Ch11.2 使用 .NET DirectorySearcher 进行隐身枚举） ===
_LDAP_COMPUTER_QUERY = "(&(objectClass=computer))"
_LDAP_SPN_QUERY = "(&(objectClass=user)(servicePrincipalName=*))"
_LDAP_GROUP_QUERY = "(&(objectClass=group))"
_LDAP_TRUST_QUERY = "(&(objectClass=trustedDomain))"
_LDAP_USER_QUERY = "(&(objectClass=user)(objectCategory=person))"

# === 危险 AD 权限（AI-300 Ch11.3 组权限分析） ===
_DANGEROUS_AD_RIGHTS = [
    "GenericWrite",
    "WriteDacl",
    "WriteOwner",
    "GenericAll",
    "ExtendedRight",
    "Self",
    "WriteProperty",
    "AllExtendedRights",
]


def enumerate_domain_computers(
    domain_controller: str | None = None,
    domain: str | None = None,
    use_adsi: bool = True,
    timeout: float = 30.0,
) -> list[dict[str, str]]:
    """枚举域内计算机（AI-300 Ch11.2 Domain Enumeration）。

    支持通过 LDAP 或 ADSI 接口枚举域内所有计算机对象，
    提取 dNSHostName、operatingSystem、description 等属性。

    Args:
        domain_controller: 域控制器地址（None 则自动发现）
        domain: 域名（None 则从 domain_controller 推断）
        use_adsi: 是否使用 ADSI WinNT 提供程序
        timeout: 超时时间

    Returns:
        计算机列表，每项包含 name, dns_hostname, os, description
    """
    computers: list[dict[str, str]] = []

    if use_adsi:
        # === Windows ADSI 路径 ===
        # 示例: WinNT://domain/computer, computer
        # 纯 Python fallback: 使用子进程调用 PowerShell
        try:
            import subprocess
            ps_cmd = (
                "[ADSISearcher]'(objectClass=computer)' | "
                "ForEach-Object { $_.Properties | Select-Object "
                "cn,dnshostname,operatingsystem,description } | "
                "ConvertTo-Json"
            )
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_cmd],
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            if result.returncode == 0 and result.stdout.strip():
                import json
                try:
                    data = json.loads(result.stdout)
                    if isinstance(data, dict):
                        data = [data]
                    for item in data if isinstance(data, list) else []:
                        computers.append({
                            "name": str(item.get("cn", "")),
                            "dns_hostname": str(item.get("dnshostname", "")),
                            "os": str(item.get("operatingsystem", "")),
                            "description": str(item.get("description", "")),
                        })
                except json.JSONDecodeError:
                    pass
        except Exception:
            pass

    # Python fallback: 简单的 DNS 查询（不依赖 PowerShell）
    if domain_controller and not computers:
        try:
            import socket
            # 尝试通过 DNS SRV 记录发现域控制器
            if domain:
                results = socket.getaddrinfo(
                    f"_ldap._tcp.{domain}", 389,
                    socket.AF_UNSPEC, socket.SOCK_STREAM
                )
                for r in results:
                    computers.append({
                        "name": r[4][0],
                        "dns_hostname": r[4][0],
                        "os": "unknown (domain controller)",
                        "description": f"Discovered via DNS SRV record",
                    })
        except Exception:
            pass

    return computers


def enumerate_spn_accounts(
    domain_controller: str | None = None,
    domain: str | None = None,
    timeout: float = 30.0,
) -> list[dict]:
    """枚举具有 SPN 的服务账户（AI-300 Ch11.2 SPN Enumeration）。

    SPN 枚举可发现关键服务：RDS Gateway (TERMSRV)、WinRM (WSMAN)、
    MSSQL、HTTP 服务等的运行位置和服务账户。

    Args:
        domain_controller: 域控制器地址
        domain: 域名
        timeout: 超时时间

    Returns:
        SPN 账户列表，每项包含 account_name, spn, service_type
    """
    spn_accounts: list[dict] = []

    try:
        import subprocess
        ps_cmd = (
            "[ADSISearcher]'(&(objectClass=user)(servicePrincipalName=*))' | "
            "ForEach-Object { "
            "[PSCustomObject]@{"
            "samaccountname=$_.Properties.samaccountname;"
            "serviceprincipalname=($_.Properties.serviceprincipalname -join ',');"
            "cn=$_.Properties.cn"
            "} } | ConvertTo-Json"
        )
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_cmd],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if result.returncode == 0 and result.stdout.strip():
            import json
            try:
                data = json.loads(result.stdout)
                if isinstance(data, dict):
                    data = [data]
                for item in data if isinstance(data, list) else []:
                    spns = str(item.get("serviceprincipalname", ""))
                    # 分类 SPN 服务类型
                    service_type = _classify_spn(spns)

                    # 检查是否为 AI 相关服务
                    is_ai_service = _is_ai_related_spn(spns)

                    spn_accounts.append({
                        "account_name": str(item.get("samaccountname", "")),
                        "cn": str(item.get("cn", "")),
                        "spn": spns,
                        "service_type": service_type,
                        "is_ai_service": is_ai_service,
                    })
            except json.JSONDecodeError:
                pass
    except Exception:
        pass

    return spn_accounts


def _classify_spn(spns: str) -> str:
    """根据 SPN 值分类服务类型。"""
    spns_lower = spns.lower()
    if "termsrv" in spns_lower:
        return "RDS/Terminal Services"
    if "wsman" in spns_lower:
        return "WinRM"
    if "mssqlsvc" in spns_lower or "mssql" in spns_lower:
        return "MSSQL"
    if "http" in spns_lower:
        return "HTTP/Web"
    if "cifs" in spns_lower:
        return "File Sharing (CIFS)"
    if "host" in spns_lower:
        return "Host"
    if "ldap" in spns_lower:
        return "LDAP"
    if "restrictedkrbhost" in spns_lower:
        return "Kerberos Host"
    if "gc" in spns_lower:
        return "Global Catalog"
    return "Other"


def _is_ai_related_spn(spns: str) -> bool:
    """检测 SPN 是否关联 AI/ML 服务。"""
    spns_lower = spns.lower()
    for indicator in _AD_AI_SERVICE_INDICATORS:
        if indicator in spns_lower:
            return True
    return False


def discover_domain_trusts(
    domain_controller: str | None = None,
    timeout: float = 30.0,
) -> list[dict[str, str]]:
    """发现域信任关系（AI-300 Ch11.3 Trust Discovery）。

    通过 AD LDAP 查询受信任域列表，识别跨域/跨森林访问路径，
    这是 Ch11 Capstone 中从 DMZ 域转向 DEV 域的关键技术。

    Args:
        domain_controller: 域控制器地址
        timeout: 超时时间

    Returns:
        信任关系列表，每项包含 trusted_domain, direction, type
    """
    trusts: list[dict[str, str]] = []

    try:
        import subprocess
        ps_cmd = (
            "([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain())."
            "GetAllTrustRelationships() | "
            "ForEach-Object { "
            "[PSCustomObject]@{"
            "SourceName=$_.SourceName;"
            "TargetName=$_.TargetName;"
            "TrustDirection=$_.TrustDirection;"
            "TrustType=$_.TrustType"
            "} } | ConvertTo-Json"
        )
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_cmd],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if result.returncode == 0 and result.stdout.strip():
            import json
            try:
                data = json.loads(result.stdout)
                if isinstance(data, dict):
                    data = [data]
                for item in (data if isinstance(data, list) else []):
                    direction = str(item.get("TrustDirection", ""))
                    direction_map = {
                        "0": "Disabled",
                        "1": "Inbound",
                        "2": "Outbound",
                        "3": "Bidirectional",
                    }
                    trust_type = str(item.get("TrustType", ""))
                    trust_type_map = {
                        "1": "Forest",
                        "2": "External",
                        "3": "Realm",
                        "4": "ParentChild",
                        "5": "TreeRoot",
                    }

                    trusts.append({
                        "source_name": str(item.get("SourceName", "")),
                        "target_name": str(item.get("TargetName", "")),
                        "direction": direction_map.get(direction, direction),
                        "type": trust_type_map.get(trust_type, trust_type),
                    })
            except json.JSONDecodeError:
                pass
    except Exception:
        pass

    return trusts


def analyze_group_permissions(
    group_name: str | None = None,
    user_name: str | None = None,
    timeout: float = 30.0,
) -> list[dict[str, str]]:
    """分析 AD 组权限和危险的成员操作能力（AI-300 Ch11.3 Permission Analysis）。

    检测 GenericWrite、WriteDacl、WriteOwner 等危险权限，
    这些是 AD 权限提升的关键入口（如 dmzsvc 对 VPN Users 组的 GenericWrite）。

    Args:
        group_name: 目标组名（None 则检查所有组）
        user_name: 要检查的用户名（None 则使用当前用户）
        timeout: 超时时间

    Returns:
        权限分析结果列表，每项包含 group_name, right, access_type, identity
    """
    permissions: list[dict[str, str]] = []

    try:
        import subprocess
        group_filter = f"(cn={group_name})" if group_name else "(objectClass=group)"
        ps_cmd = (
            f"$groups = [ADSISearcher]'{group_filter}'.FindAll(); "
            "$results = @(); "
            "foreach ($g in $groups) { "
            "$de = $g.GetDirectoryEntry(); "
            "$acl = $de.ObjectSecurity.Access; "
            "foreach ($ace in $acl) { "
            "$results += [PSCustomObject]@{"
            "GroupName=$de.Name;"
            "ActiveDirectoryRights=$ace.ActiveDirectoryRights;"
            "AccessControlType=$ace.AccessControlType;"
            "IdentityReference=$ace.IdentityReference"
            "} } }; "
            "$results | ConvertTo-Json"
        )
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_cmd],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if result.returncode == 0 and result.stdout.strip():
            import json
            try:
                data = json.loads(result.stdout)
                if isinstance(data, dict):
                    data = [data]
                for item in (data if isinstance(data, list) else []):
                    rights = str(item.get("ActiveDirectoryRights", ""))
                    identity = str(item.get("IdentityReference", ""))

                    # 过滤出危险权限
                    for dangerous in _DANGEROUS_AD_RIGHTS:
                        if dangerous in rights:
                            # 可按用户名过滤
                            if user_name and user_name.lower() not in identity.lower():
                                continue
                            permissions.append({
                                "group_name": str(item.get("GroupName", "")),
                                "right": dangerous,
                                "access_type": str(item.get("AccessControlType", "")),
                                "identity": identity,
                            })
            except json.JSONDecodeError:
                pass
    except Exception:
        pass

    return permissions


def detect_rds_gateway(
    target_host: str | None = None,
    domain_controller: str | None = None,
    timeout: float = 30.0,
) -> dict[str, Any]:
    """检测 RDS Gateway 及其策略（AI-300 Ch11.3 RDS Gateway Discovery）。

    在 Ch11 Capstone 中，RDS Gateway (CONNECT02) 是进入 DEV 子域的关键跳板。
    该功能探测 RDS Gateway 注册表和策略（RAP/CAP）。

    Args:
        target_host: 目标 RDS 网关主机名（可选）
        domain_controller: 域控制器地址
        timeout: 超时时间

    Returns:
        RDS Gateway 探测结果，包含 policies, target_domain, 等
    """
    result: dict[str, Any] = {
        "rds_gateway_found": False,
        "gateway_hostname": "",
        "gateway_policies": [],
        "cap_policies": [],
        "target_domains": [],
        "allowed_computers": [],
        "evidence": [],
    }

    try:
        import subprocess

        if target_host:
            # 通过 WinRM 在目标上执行 RDS Gateway 探测
            ps_cmd = (
                f"Invoke-Command -ComputerName {target_host} -ScriptBlock {{"
                "Import-Module RemoteDesktopServices -ErrorAction SilentlyContinue; "
                "Get-ChildItem 'RDS:\\GatewayServer\\RAP\\' -ErrorAction SilentlyContinue | "
                "ForEach-Object { [PSCustomObject]@{Name=$_.Name; "
                "ComputerGroup=$_.ComputerGroup; PortNumbers=$_.PortNumbers"
                "} } | ConvertTo-Json"
                "}"
            )
        else:
            # 本地检查 RDS Gateway 服务
            ps_cmd = (
                "Get-Service -Name 'TSGateway' -ErrorAction SilentlyContinue | "
                "Select-Object Name,Status,DisplayName | ConvertTo-Json"
            )

        ps_result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_cmd],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if ps_result.returncode != 0 or not ps_result.stdout.strip():
            return result

        import json
        try:
            data = json.loads(ps_result.stdout)
            if isinstance(data, dict):
                data = [data]

            if target_host:
                for policy in (data if isinstance(data, list) else []):
                    policy_entry = {
                        "name": str(policy.get("Name", "")),
                        "computer_group": str(policy.get("ComputerGroup", "")),
                        "port_numbers": str(policy.get("PortNumbers", "")),
                    }
                    result["gateway_policies"].append(policy_entry)
                    result["evidence"].append(
                        f"RDS Gateway RAP found: {policy_entry['name']}"
                    )

                    # 解析目标域信息
                    cg = policy_entry["computer_group"]
                    domain_match = re.search(r'@(\S+)', cg)
                    if domain_match:
                        target_domain = domain_match.group(1)
                        if target_domain not in result["target_domains"]:
                            result["target_domains"].append(target_domain)

                if result["gateway_policies"]:
                    result["rds_gateway_found"] = True
                    result["gateway_hostname"] = target_host
            else:
                service_name = str(data[0].get("Name", "")) if isinstance(data, list) else str(data.get("Name", ""))
                if service_name:
                    result["rds_gateway_found"] = True
                    result["evidence"].append("TSGateway service detected locally")

        except json.JSONDecodeError:
            result["evidence"].append(
                f"Non-JSON response from RDS Gateway probe: {ps_result.stdout[:200]}"
            )

    except Exception as e:
        result["evidence"].append(f"RDS Gateway detection error: {e}")

    return result


def enumerate_ai_services_on_domain(
    domain_controller: str | None = None,
    domain: str | None = None,
    subnet_cidr: str | None = None,
    timeout: float = 30.0,
) -> list[dict[str, str]]:
    """发现域环境中运行的 AI 服务（AI-300 Ch11 Cross-Domain AI Recon）。

    结合 SPN 枚举和端口扫描，发现域环境中暴露的 AI/ML 服务，
    如 MCP 服务器、向量数据库、模型推理端点等。

    Args:
        domain_controller: 域控制器地址
        domain: 域名
        subnet_cidr: 目标子网 CIDR
        timeout: 超时时间

    Returns:
        AI 服务列表，每项包含 host, service_type, port, details
    """
    ai_services: list[dict[str, str]] = []

    # 方法1: 检查 SPN 中的 AI 关键服务
    spn_accounts = enumerate_spn_accounts(domain_controller, domain, timeout)
    for spn_acct in spn_accounts:
        if spn_acct.get("is_ai_service"):
            ai_services.append({
                "host": spn_acct.get("account_name", ""),
                "service_type": f"SPN: {spn_acct.get('service_type', 'Unknown')}",
                "port": "",
                "details": spn_acct.get("spn", ""),
                "discovery_method": "SPN",
            })

    # 方法2: 按计算机名关键词匹配
    computers = enumerate_domain_computers(domain_controller, domain, timeout=timeout)
    for comp in computers:
        hostname = comp.get("dns_hostname", "").lower()
        desc = comp.get("description", "").lower()
        combined = f"{hostname} {desc}"

        for indicator in _AD_AI_SERVICE_INDICATORS:
            if indicator.lower() in combined:
                ai_services.append({
                    "host": comp.get("dns_hostname", ""),
                    "service_type": f"Hostname hint: {indicator}",
                    "port": "",
                    "details": f"os={comp.get('os')}, desc={comp.get('description')}",
                    "discovery_method": "Computer Name Analysis",
                })
                break

    return ai_services


def probe_domain_ai_endpoints(
    domain_controller: str | None = None,
    domain: str | None = None,
    timeout: float = 10.0,
) -> DomainServiceInfo:
    """完整的域侦察入口函数（AI-300 Ch11 综合域侦察）。

    汇集所有域侦察技术，返回统一的 DomainServiceInfo 模型。

    Args:
        domain_controller: 域控制器地址
        domain: 域名
        timeout: 超时时间

    Returns:
        DomainServiceInfo 模型，包含完整的域侦察结果
    """
    info = DomainServiceInfo()

    if domain:
        info.domain_name = domain

    start_time = time.time()

    # 1. 域控制器发现
    dc_computers = enumerate_domain_computers(domain_controller, domain, timeout=timeout)
    for dc in dc_computers:
        if "domain controller" in dc.get("description", "").lower():
            info.domain_controllers.append(dc.get("dns_hostname", ""))
        # 也检查 name 发现
        if dc.get("dns_hostname") and dc.get("dns_hostname") not in info.domain_controllers:
            info.domain_controllers.append(dc.get("dns_hostname", ""))

    # 2. SPN 枚举
    info.spn_accounts = enumerate_spn_accounts(domain_controller, domain, timeout=timeout)
    info.evidence.append(
        f"SPN accounts enumerated: {len(info.spn_accounts)} found"
    )

    # 3. 信任关系
    trusts = discover_domain_trusts(domain_controller, timeout=timeout)
    if trusts:
        info.evidence.append(
            f"Domain trusts discovered: {len(trusts)} relationships"
        )
        for t in trusts:
            info.evidence.append(
                f"Trust: {t.get('source_name')} -> {t.get('target_name')}"
                f" ({t.get('direction')}, {t.get('type')})"
            )

    # 4. 组权限分析（检查通用写权限）
    permissions = analyze_group_permissions(timeout=timeout)
    if permissions:
        info.evidence.append(
            f"Dangerous group permissions found: {len(permissions)}"
        )

    # 5. AI 域服务发现
    info.ai_services_on_domain = [
        svc.get("host", "") for svc in
        enumerate_ai_services_on_domain(domain_controller, domain, timeout=timeout)
        if svc.get("host")
    ]

    elapsed = time.time() - start_time
    info.evidence.append(
        f"Domain reconnaissance completed in {elapsed:.1f}s"
    )

    return info


# === curl 命令示例（AI-300 Ch11 考试参考） ===
# 域计算机枚举（.NET 方式，隐身）:
#   powershell -c "$s=New-Object DirectoryServices.DirectorySearcher; $s.Filter='(objectClass=computer)'; $s.FindAll()"
#
# SPN 枚举:
#   powershell -c "$s=New-Object DirectoryServices.DirectorySearcher; $s.Filter='(&(objectClass=computer)(cn=CONNECT02))'; $s.PropertiesToLoad.Add('servicePrincipalName')|Out-Null; $s.FindOne().Properties['servicePrincipalName']"
#
# RDS Gateway 策略枚举:
#   Invoke-Command -ComputerName CONNECT02 -ScriptBlock { Import-Module RemoteDesktopServices; Get-ChildItem 'RDS:\GatewayServer\RAP\' }
#
# 组权限检查:
#   powershell -c "$s=New-Object DirectoryServices.DirectorySearcher; $s.Filter='(&(objectClass=group)(cn=VPN Users))'; $g=$s.FindOne().GetDirectoryEntry(); $g.ObjectSecurity.Access | ?{$_.IdentityReference -match 'dmzsvc'} | ft ActiveDirectoryRights,AccessControlType,IdentityReference -AutoSize"

__all__ = [
    "enumerate_domain_computers",
    "enumerate_spn_accounts",
    "discover_domain_trusts",
    "analyze_group_permissions",
    "detect_rds_gateway",
    "enumerate_ai_services_on_domain",
    "probe_domain_ai_endpoints",
]
