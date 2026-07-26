# -*- coding: utf-8 -*-
"""
Profile → RedAmon Graph Adapter
===============================

将 pyrit-web-recon 输出的 TargetProfile 映射为 Neo4j 图数据库中的节点与关系。

映射出的核心节点类型：
- Domain
- BaseURL
- Endpoint
- ModelFamily
- Technology
- Vulnerability
- Credential

核心关系：
- (Domain)-[:HAS_BASEURL]->(BaseURL)
- (BaseURL)-[:HAS_ENDPOINT]->(Endpoint)
- (Endpoint)-[:USES_MODEL]->(ModelFamily)
- (Endpoint)-[:HAS_TECHNOLOGY]->(Technology)
- (Endpoint)-[:HAS_VULNERABILITY]->(Vulnerability)
- (Endpoint)-[:LEAKS]->(Credential)
"""

from __future__ import annotations

import json
from typing import Any, Dict, List

from src.recon.target_profile import TargetProfile


class ProfileToGraphAdapter:
    """TargetProfile 到 RedAmon Neo4j 图的适配器"""

    def __init__(self, project_id: str, user_id: str = ""):
        """
        初始化适配器。

        Args:
            project_id: RedAmon 项目 ID，用于租户隔离
            user_id: 可选的用户 ID，用于审计
        """
        self.project_id = project_id
        self.user_id = user_id

    def to_cypher_statements(self, profile: TargetProfile) -> List[str]:
        """
        将 Profile 转换为 Neo4j Cypher MERGE 语句列表。

        Args:
            profile: pyrit-web-recon 输出的 TargetProfile

        Returns:
            可直接执行的 Cypher 语句列表
        """
        statements: List[str] = []
        fp = profile.fingerprint
        domain = fp.domain or self._extract_domain(profile.target)

        if not domain:
            return statements

        # 1. 创建 Domain 节点
        statements.append(self._merge_domain(domain))

        # 2. 创建 BaseURL 节点（来自 chat_urls 和目标 URL）
        base_urls = self._collect_base_urls(profile)
        for base_url in base_urls:
            statements.append(self._merge_base_url(domain, base_url))

        # 3. 创建 Endpoint 节点（来自 llm_api_endpoints 和 entry_points）
        for ep in fp.llm_api_endpoints:
            statements.append(self._merge_endpoint(domain, ep, source="traffic"))

        for entry in profile.entry_points:
            statements.append(self._merge_entry_point(domain, entry))

        # 4. 创建 ModelFamily 节点
        if fp.model_family or fp.model_name:
            statements.append(self._merge_model_family(domain, fp.model_family, fp.model_name))

        # 5. 创建 Technology 节点（RAG / Agent / MCP 等）
        for feat in fp.rag_features:
            statements.append(self._merge_technology(domain, feat, category="ai-rag"))
        for feat in fp.agent_features:
            statements.append(self._merge_technology(domain, feat, category="ai-agent"))

        # 6. 创建 Vulnerability 节点
        for vuln in profile.vulnerabilities:
            statements.append(self._merge_vulnerability(domain, vuln))

        # 7. 创建 Credential 节点（标记敏感）
        for cred in fp.extracted_credentials:
            statements.append(self._merge_credential(domain, cred))

        return statements

    def to_redamon_payload(self, profile: TargetProfile) -> Dict[str, Any]:
        """
        构造提交给 RedAmon API 的 JSON payload。

        Args:
            profile: pyrit-web-recon 输出的 TargetProfile
        """
        return {
            "project_id": self.project_id,
            "user_id": self.user_id,
            "source_tool": "pyrit-web-recon",
            "profile": profile.to_dict(),
            "cypher_statements": self.to_cypher_statements(profile),
        }

    # ------------------- Cypher 生成辅助方法 -------------------

    def _merge_domain(self, domain: str) -> str:
        """创建 Domain 节点"""
        return (
            "MERGE (d:Domain {name: $domain, project_id: $project_id}) "
            "SET d.updated_at = datetime(), d.source_tool = 'pyrit-web-recon'"
        ).replace("$domain", self._quote(domain))

    def _merge_base_url(self, domain: str, base_url: str) -> str:
        """创建 BaseURL 节点并关联到 Domain"""
        return (
            "MERGE (d:Domain {name: $domain, project_id: $project_id}) "
            "MERGE (b:BaseURL {url: $base_url, project_id: $project_id}) "
            "SET b.updated_at = datetime() "
            "MERGE (d)-[:HAS_BASEURL]->(b)"
        ).replace("$domain", self._quote(domain)).replace("$base_url", self._quote(base_url))

    def _merge_endpoint(
        self,
        domain: str,
        endpoint: Dict[str, Any],
        source: str = "traffic",
    ) -> str:
        """创建 Endpoint 节点"""
        url = endpoint.get("url", "")
        path = endpoint.get("path", "")
        method = endpoint.get("method", "POST")
        model_name = endpoint.get("model_name", "")
        ai_type = endpoint.get("api_type", "llm-chat")

        props = {
            "url": url,
            "path": path,
            "method": method.upper(),
            "ai_interface_type": ai_type,
            "model_name": model_name,
            "source": source,
            "project_id": self.project_id,
        }
        if endpoint.get("protocol"):
            props["protocol"] = endpoint.get("protocol")

        # 将 JSON 属性转为 Cypher SET 子句
        set_clause = self._dict_to_set(props)

        return (
            "MERGE (d:Domain {name: $domain, project_id: $project_id}) "
            "MERGE (e:Endpoint {url: $url, project_id: $project_id}) "
            f"SET {set_clause}, e.updated_at = datetime() "
            "MERGE (d)-[:HAS_ENDPOINT]->(e)"
        ).replace("$domain", self._quote(domain)).replace("$url", self._quote(url))

    def _merge_entry_point(self, domain: str, entry: Dict[str, Any]) -> str:
        """将 entry_points 也映射为 Endpoint 节点"""
        url = entry.get("url", "")
        selector = entry.get("selector", "")
        entry_type = entry.get("type", "unknown")
        api_type = entry.get("api_type", "")
        model_name = entry.get("model_name", "")
        score = entry.get("score", 0.0)

        props = {
            "url": url or selector,
            "path": url,
            "entry_type": entry_type,
            "selector": selector,
            "api_type": api_type,
            "model_name": model_name,
            "score": score,
            "source": "entry_point",
            "project_id": self.project_id,
        }
        set_clause = self._dict_to_set(props)

        return (
            "MERGE (d:Domain {name: $domain, project_id: $project_id}) "
            "MERGE (e:Endpoint {url: $url, project_id: $project_id}) "
            f"SET {set_clause}, e.updated_at = datetime() "
            "MERGE (d)-[:HAS_ENDPOINT]->(e)"
        ).replace("$domain", self._quote(domain)).replace("$url", self._quote(props["url"]))

    def _merge_model_family(
        self,
        domain: str,
        model_family: str,
        model_name: str,
    ) -> str:
        """创建 ModelFamily 节点并关联到 Domain"""
        family = model_family or "unknown"
        name = model_name or "unknown"

        return (
            "MERGE (d:Domain {name: $domain, project_id: $project_id}) "
            "MERGE (m:ModelFamily {name: $family, project_id: $project_id}) "
            "SET m.model_name = $model_name, m.updated_at = datetime() "
            "MERGE (d)-[:USES_MODEL_FAMILY]->(m)"
        ).replace("$domain", self._quote(domain)).replace("$family", self._quote(family)).replace("$model_name", self._quote(name))

    def _merge_technology(
        self,
        domain: str,
        feature: Dict[str, Any],
        category: str,
    ) -> str:
        """创建 Technology 节点（RAG / Agent / MCP 等）"""
        tech_name = feature.get("name") or feature.get("type") or category
        evidence_json = json.dumps(feature, ensure_ascii=False)

        return (
            "MERGE (d:Domain {name: $domain, project_id: $project_id}) "
            "MERGE (t:Technology {name: $tech_name, category: $category, project_id: $project_id}) "
            "SET t.evidence = $evidence, t.updated_at = datetime() "
            "MERGE (d)-[:HAS_TECHNOLOGY]->(t)"
        ).replace("$domain", self._quote(domain)).replace("$tech_name", self._quote(tech_name)).replace("$category", self._quote(category)).replace("$evidence", self._quote(evidence_json))

    def _merge_vulnerability(self, domain: str, vuln: Any) -> str:
        """创建 Vulnerability 节点"""
        # vuln 可能是 VulnerabilityFinding 对象或字典
        if hasattr(vuln, "to_dict"):
            vuln_dict = vuln.to_dict()
        else:
            vuln_dict = dict(vuln)

        owasp = vuln_dict.get("owasp_category", "")
        desc = vuln_dict.get("description", "")
        risk = vuln_dict.get("risk_level", "low")
        remediation = vuln_dict.get("remediation", "")
        evidence_json = json.dumps(vuln_dict.get("evidence", {}), ensure_ascii=False)

        # 用 OWASP + 描述哈希作为唯一键（简化）
        vuln_id = f"{self.project_id}:{owasp}:{hash(desc) & 0xFFFFFFFF}"

        return (
            "MERGE (d:Domain {name: $domain, project_id: $project_id}) "
            "MERGE (v:Vulnerability {vuln_id: $vuln_id, project_id: $project_id}) "
            "SET v.owasp_category = $owasp, v.description = $desc, "
            "v.risk_level = $risk, v.remediation = $remediation, "
            "v.evidence = $evidence, v.updated_at = datetime() "
            "MERGE (d)-[:HAS_VULNERABILITY]->(v)"
        ).replace("$domain", self._quote(domain)).replace("$vuln_id", self._quote(vuln_id)).replace("$owasp", self._quote(owasp)).replace("$desc", self._quote(desc)).replace("$risk", self._quote(risk)).replace("$remediation", self._quote(remediation)).replace("$evidence", self._quote(evidence_json))

    def _merge_credential(self, domain: str, cred: Dict[str, Any]) -> str:
        """创建 Credential 节点（敏感，仅标记存在，不存明文）"""
        ctype = cred.get("type", "unknown")
        # 不存储明文 value，只存类型和来源
        source = cred.get("source", "")
        masked = cred.get("masked", "***")

        cred_id = f"{self.project_id}:{ctype}:{hash(source) & 0xFFFFFFFF}"

        return (
            "MERGE (d:Domain {name: $domain, project_id: $project_id}) "
            "MERGE (c:Credential {cred_id: $cred_id, project_id: $project_id}) "
            "SET c.type = $ctype, c.source = $source, c.masked = $masked, "
            "c.updated_at = datetime() "
            "MERGE (d)-[:LEAKS_CREDENTIAL]->(c)"
        ).replace("$domain", self._quote(domain)).replace("$cred_id", self._quote(cred_id)).replace("$ctype", self._quote(ctype)).replace("$source", self._quote(source)).replace("$masked", self._quote(masked))

    # ------------------- 工具方法 -------------------

    def _extract_domain(self, url: str) -> str:
        """从 URL 中提取域名"""
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            return parsed.netloc.split(":")[0] or url
        except Exception:
            return url

    def _collect_base_urls(self, profile: TargetProfile) -> List[str]:
        """收集 BaseURL 列表"""
        urls: List[str] = []
        candidates = [profile.target] + list(profile.fingerprint.chat_urls)
        for url in candidates:
            if url and url not in urls:
                urls.append(url)
        return urls

    def _quote(self, value: Any) -> str:
        """将字符串转义为 Cypher 字符串字面量"""
        if value is None:
            return "''"
        text = str(value)
        # 转义单引号
        text = text.replace("\\", "\\\\").replace("'", "\\'")
        return f"'{text}'"

    def _dict_to_set(self, props: Dict[str, Any]) -> str:
        """将字典转换为 Cypher SET 子句"""
        clauses = []
        for key, value in props.items():
            clauses.append(f"e.{key} = {self._quote(value)}")
        return ", ".join(clauses)
