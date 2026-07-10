"""
===============================================================================
Neo4j 图数据库客户端 — 攻击数据持久化 (L0-L6 全流程)
===============================================================================
职责:
  - 6 阶段管道数据的图模式映射与存储
  - 攻击面 → 漏洞 → 攻击 → 结果的关系图构建
  - OWASP / MITRE ATLAS 节点自动标记
  - 支持 Cypher 查询供报告生成消费

数据模型 (节点标签):
  Target — 目标系统
  ReconResult — L0 侦察结果
  AIScenario — L1 AI 场景探测
  Vulnerability — L3 漏洞发现
  AttackPath — L4-L5 攻击路径
  AttackResult — L5 攻击结果
  RiskAssessment — L6 风险评估
  OWASP_Category — OWASP 分类
  MITRE_Technique — MITRE ATLAS 技法

关系类型:
  HAS_RECON — Target → ReconResult
  HAS_SCENARIO — Target → AIScenario
  HAS_VULN — AIScenario → Vulnerability
  MAPPED_TO — Vulnerability → OWASP_Category
  EXPLOITED_BY — Vulnerability → AttackPath
  PRODUCED — AttackPath → AttackResult
  ASSESSED_AS — AttackResult → RiskAssessment

使用方式:
  from storage import Neo4jClient

  async with Neo4jClient() as db:
      await db.upsert_target(profile)
      await db.link_recon_result(profile, recon)
      await db.build_attack_graph(results)
===============================================================================
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from rich.console import Console

console = Console()

# Neo4j 为可选依赖 — 安装指令: pip install neo4j
try:
    from neo4j import AsyncGraphDatabase, AsyncSession
    _NEO4J_AVAILABLE = True
except ImportError:
    _NEO4J_AVAILABLE = False
    AsyncGraphDatabase = None  # type: ignore
    AsyncSession = None  # type: ignore


# ── 配置 ──

@dataclass
class Neo4jConfig:
    """Neo4j 连接配置，从环境变量或参数注入。"""
    uri: str = field(default_factory=lambda: os.getenv("NEO4J_URI", "bolt://localhost:7687"))
    user: str = field(default_factory=lambda: os.getenv("NEO4J_USER", "neo4j"))
    password: str = field(default_factory=lambda: os.getenv("NEO4J_PASSWORD", "neo4j"))
    database: str = field(default_factory=lambda: os.getenv("NEO4J_DATABASE", "neo4j"))


# ── 图数据模型 ──

@dataclass
class GraphTarget:
    """图数据库中的目标系统节点。"""
    url: str
    name: str = ""
    target_type: str = "unknown"  # basic_llm / rag / agent / multi_agent
    platform: str = "unknown"
    first_seen: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass
class GraphReconResult:
    """图数据库中的侦察结果节点。"""
    profile_path: str = ""
    endpoints_count: int = 0
    auth_type: str = "none"
    has_jwt: bool = False
    has_api_key: bool = False
    has_cookie: bool = False
    model_name: str = "unknown"
    waf_detected: bool = False
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass
class GraphVulnerability:
    """图数据库中的漏洞节点。"""
    vuln_id: str
    title: str
    owasp_category: str  # e.g. "LLM01: Prompt Injection"
    risk_level: str  # critical / high / medium / low
    cvss_score: float = 0.0
    description: str = ""
    evidence: str = ""
    remediation: str = ""
    discovered_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass
class GraphAttackResult:
    """图数据库中的攻击结果节点。"""
    attack_id: str
    attack_type: str  # injection / jailbreak / xpia / rag / agent_abuse / extraction
    target_vuln_id: str = ""
    success: bool = False
    asr_score: float = 0.0
    attempts: int = 0
    successes: int = 0
    payload_used: str = ""
    response_snippet: str = ""
    executed_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


# ── Neo4j 客户端 ──

class Neo4jClient:
    """Neo4j 图数据库异步客户端 — 封装连接管理与基础 CRUD。"""

    def __init__(self, config: Optional[Neo4jConfig] = None):
        self.config = config or Neo4jConfig()
        self._driver: Optional[object] = None
        self._available = _NEO4J_AVAILABLE

    async def __aenter__(self):
        if self._available:
            try:
                self._driver = AsyncGraphDatabase.driver(
                    self.config.uri,
                    auth=(self.config.user, self.config.password),
                )
                await self._driver.verify_connectivity()
                console.print("[green]✅ Neo4j 连接成功[/green]")
            except Exception as e:
                console.print(f"[yellow]⚠️ Neo4j 连接失败 ({e})，回退到 JSON 存储[/yellow]")
                self._available = False
        return self

    async def __aexit__(self, *args):
        if self._driver:
            await self._driver.close()

    async def _run(self, cypher: str, params: dict = None) -> list:
        """执行 Cypher 查询并返回记录列表。"""
        if not self._available or not self._driver:
            return []
        async with self._driver.session(database=self.config.database) as session:
            result = await session.run(cypher, params or {})
            records = await result.data()
            return records

    # ── 节点操作 ──

    async def upsert_target(self, target: GraphTarget) -> str:
        """创建或更新目标节点。"""
        cypher = """
        MERGE (t:Target {url: $url})
        SET t.name = $name,
            t.target_type = $target_type,
            t.platform = $platform,
            t.updated_at = $updated_at
        RETURN t.url as url
        """
        records = await self._run(cypher, {
            "url": target.url,
            "name": target.name,
            "target_type": target.target_type,
            "platform": target.platform,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        })
        return records[0]["url"] if records else target.url

    async def create_recon_result(self, result: GraphReconResult) -> str:
        """创建侦察结果节点。"""
        cypher = """
        CREATE (r:ReconResult {
            profile_path: $profile_path,
            endpoints_count: $endpoints_count,
            auth_type: $auth_type,
            has_jwt: $has_jwt,
            has_api_key: $has_api_key,
            has_cookie: $has_cookie,
            model_name: $model_name,
            waf_detected: $waf_detected,
            created_at: $created_at,
            id: randomUUID()
        })
        RETURN r.id as id
        """
        records = await self._run(cypher, {
            "profile_path": result.profile_path,
            "endpoints_count": result.endpoints_count,
            "auth_type": result.auth_type,
            "has_jwt": result.has_jwt,
            "has_api_key": result.has_api_key,
            "has_cookie": result.has_cookie,
            "model_name": result.model_name,
            "waf_detected": result.waf_detected,
            "created_at": result.created_at,
        })
        return records[0]["id"] if records else ""

    async def create_vulnerability(self, vuln: GraphVulnerability) -> str:
        """创建漏洞节点并链接到 OWASP 分类节点。"""
        cypher_vuln = """
        CREATE (v:Vulnerability {
            vuln_id: $vuln_id,
            title: $title,
            owasp_category: $owasp_category,
            risk_level: $risk_level,
            cvss_score: $cvss_score,
            description: $description,
            evidence: $evidence,
            remediation: $remediation,
            discovered_at: $discovered_at
        })
        RETURN v.vuln_id as vid
        """
        records = await self._run(cypher_vuln, {
            "vuln_id": vuln.vuln_id,
            "title": vuln.title,
            "owasp_category": vuln.owasp_category,
            "risk_level": vuln.risk_level,
            "cvss_score": vuln.cvss_score,
            "description": vuln.description,
            "evidence": vuln.evidence,
            "remediation": vuln.remediation,
            "discovered_at": vuln.discovered_at,
        })

        # 链接到 OWASP 分类
        await self._run("""
            MERGE (o:OWASP_Category {name: $category})
            WITH o
            MATCH (v:Vulnerability {vuln_id: $vuln_id})
            MERGE (v)-[:MAPPED_TO]->(o)
        """, {"category": vuln.owasp_category, "vuln_id": vuln.vuln_id})

        return records[0]["vid"] if records else vuln.vuln_id

    async def create_attack_result(self, result: GraphAttackResult) -> str:
        """创建攻击结果节点。"""
        cypher = """
        CREATE (a:AttackResult {
            attack_id: $attack_id,
            attack_type: $attack_type,
            target_vuln_id: $target_vuln_id,
            success: $success,
            asr_score: $asr_score,
            attempts: $attempts,
            successes: $successes,
            payload_used: $payload_used,
            response_snippet: $response_snippet,
            executed_at: $executed_at
        })
        RETURN a.attack_id as aid
        """
        records = await self._run(cypher, {
            "attack_id": result.attack_id,
            "attack_type": result.attack_type,
            "target_vuln_id": result.target_vuln_id,
            "success": result.success,
            "asr_score": result.asr_score,
            "attempts": result.attempts,
            "successes": result.successes,
            "payload_used": result.payload_used,
            "response_snippet": result.response_snippet,
            "executed_at": result.executed_at,
        })
        return records[0]["aid"] if records else result.attack_id

    # ── 关系操作 ──

    async def link_target_recon(self, target_url: str):
        """链接 Target → ReconResult。"""
        await self._run("""
            MATCH (t:Target {url: $url})
            MATCH (r:ReconResult)
            WHERE NOT (t)-[:HAS_RECON]->(:ReconResult)
            WITH t, r ORDER BY r.created_at DESC LIMIT 1
            MERGE (t)-[:HAS_RECON]->(r)
        """, {"url": target_url})

    async def link_target_scenario(self, target_url: str, scenario_type: str):
        """链接 Target → AIScenario。"""
        await self._run("""
            MATCH (t:Target {url: $url})
            MERGE (s:AIScenario {type: $type, target_url: $url})
            MERGE (t)-[:HAS_SCENARIO]->(s)
        """, {"url": target_url, "type": scenario_type})

    async def link_scenario_vuln(self, vuln_id: str, scenario_type: str, target_url: str):
        """链接 AIScenario → Vulnerability。"""
        await self._run("""
            MATCH (s:AIScenario {type: $type, target_url: $url})
            MATCH (v:Vulnerability {vuln_id: $vuln_id})
            MERGE (s)-[:HAS_VULN]->(v)
        """, {"vuln_id": vuln_id, "type": scenario_type, "url": target_url})

    async def link_vuln_attack(self, vuln_id: str, attack_id: str):
        """链接 Vulnerability → AttackResult。"""
        await self._run("""
            MATCH (v:Vulnerability {vuln_id: $vuln_id})
            MATCH (a:AttackResult {attack_id: $attack_id})
            MERGE (v)-[:EXPLOITED_BY]->(a)
        """, {"vuln_id": vuln_id, "attack_id": attack_id})

    async def query_attack_graph(self, target_url: str) -> list:
        """查询完整攻击图。"""
        return await self._run("""
            MATCH (t:Target {url: $url})
            OPTIONAL MATCH (t)-[:HAS_RECON]->(r:ReconResult)
            OPTIONAL MATCH (t)-[:HAS_SCENARIO]->(s:AIScenario)
            OPTIONAL MATCH (s)-[:HAS_VULN]->(v:Vulnerability)
            OPTIONAL MATCH (v)-[:MAPPED_TO]->(o:OWASP_Category)
            OPTIONAL MATCH (v)-[:EXPLOITED_BY]->(a:AttackResult)
            RETURN t, r, s, v, o, a
        """, {"url": target_url})


class PipelineStore:
    """管道数据的完整图存储 — 封装六阶段数据的 Neo4j 写入逻辑。"""

    def __init__(self, db: Neo4jClient):
        self._db = db

    async def store_recon_result(
        self,
        target_url: str,
        target_type: str,
        recon: GraphReconResult,
    ):
        """存储 L0 侦察结果。"""
        await self._db.upsert_target(GraphTarget(
            url=target_url,
            target_type=target_type,
        ))
        await self._db.create_recon_result(recon)
        await self._db.link_target_recon(target_url)
        console.print("[green]  ✅ L0 侦察结果已写入 Neo4j[/green]")

    async def store_ai_scenario(
        self,
        target_url: str,
        scenario_type: str,
        vulnerabilities: list[GraphVulnerability],
    ):
        """存储 L1-L3 AI 场景探测 + 漏洞。"""
        await self._db.link_target_scenario(target_url, scenario_type)
        for vuln in vulnerabilities:
            vuln_id = await self._db.create_vulnerability(vuln)
            await self._db.link_scenario_vuln(vuln_id, scenario_type, target_url)
        console.print(f"[green]  ✅ {len(vulnerabilities)} 个漏洞已写入 Neo4j[/green]")

    async def store_attack_results(
        self,
        vuln_results: list[tuple[GraphVulnerability, GraphAttackResult]],
    ):
        """存储 L4-L5 攻击结果，链接到对应漏洞。"""
        for vuln, result in vuln_results:
            aid = await self._db.create_attack_result(result)
            await self._db.link_vuln_attack(vuln.vuln_id, aid)
        console.print(f"[green]  ✅ {len(vuln_results)} 个攻击结果已写入 Neo4j[/green]")

    async def export_to_json(self, target_url: str, output_path: str) -> str:
        """从 Neo4j 导出完整攻击图到 JSON 文件。"""
        records = await self._db.query_attack_graph(target_url)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(records, f, indent=2, ensure_ascii=False, default=str)
        console.print(f"[green]  📄 攻击图已导出: {output_path}[/green]")
        return output_path


class AttackGraphBuilder:
    """攻击图构建器 — 从管道结果构建 Neo4j 图模型。"""

    @staticmethod
    def build_recon_result(profile: dict) -> GraphReconResult:
        """从 target_profile.json 构建侦察结果图节点。"""
        auth = profile.get("auth", {})
        endpoints = profile.get("api_endpoints", [])
        return GraphReconResult(
            profile_path=profile.get("meta", {}).get("profile_path", ""),
            endpoints_count=len(endpoints),
            auth_type=auth.get("type", "none"),
            has_jwt=bool(auth.get("jwt_token")),
            has_api_key=bool(auth.get("api_key")),
            has_cookie=bool(auth.get("session_cookie")),
            model_name=profile.get("target", {}).get("model", "unknown"),
            waf_detected=bool(profile.get("defense", {}).get("waf", False)),
        )

    @staticmethod
    def build_vulnerability_from_owasp(
        owasp_id: str,
        risk_level: str,
        title: str,
        description: str,
        evidence: str = "",
        remediation: str = "",
    ) -> GraphVulnerability:
        """从 OWASP 映射构建漏洞图节点。"""
        cvss_map = {"critical": 9.5, "high": 7.5, "medium": 5.0, "low": 2.5, "none": 0.0}
        return GraphVulnerability(
            vuln_id=f"VULN-{owasp_id}-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}",
            title=title,
            owasp_category=owasp_id,
            risk_level=risk_level,
            cvss_score=cvss_map.get(risk_level, 0.0),
            description=description,
            evidence=evidence,
            remediation=remediation,
        )
