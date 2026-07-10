"""
WAF/IPS 检测模块 — 识别目标前端的安全防护设施。

参考: llm-con WAF detection、wafw00f、WhatWaf
支持 20+ 种 WAF/CDN/IPS 签名识别。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class WafMatch:
    """单条 WAF 匹配"""
    name: str           # WAF 名称
    vendor: str         # 厂商
    confidence: str     # high / medium / low
    evidence: str = ""  # 匹配证据（header name: value）
    match_type: str = ""  # header / cookie / body / status


@dataclass
class WafScanResult:
    """WAF 扫描完整结果"""
    detections: list[WafMatch] = field(default_factory=list)
    waf_count: int = 0
    summary: str = ""
    implications: str = ""  # 对后续攻击的影响


# ═══════════════════════════════════════════════════════════════════════════
# WAF 签名库 (20+ WAF/CDN/IPS)
# ═══════════════════════════════════════════════════════════════════════════

_WafSig = tuple[str, str, str, str, str]  # (name, vendor, confidence, match_type, pattern)

_WAF_SIGNATURES: list[_WafSig] = [
    # ── Cloud WAFs ──
    ("Cloudflare", "Cloudflare", "high", "header",
     r'(?i)(?:cf-ray|CF-RAY|__cfduid|cf-cache-status|cf-chl-)'),
    ("Cloudflare", "Cloudflare", "medium", "body",
     r'(?i)cloudflare[- ]?(?:challenge|captcha|ray\s*id|error\s*\d{3})'),
    ("Cloudflare", "Cloudflare", "high", "body",
     r'(?i)attention\s+required.*cloudflare'),
    ("AWS WAF", "Amazon", "high", "header",
     r'(?i)(?:x-amzn-waf|X-Amzn-Waf|x-amz-waf|X-Amz-Waf)'),
    ("AWS CloudFront", "Amazon", "medium", "header",
     r'(?i)(?:x-amz-cf-id|X-Amz-Cf-Id|x-amz-cf-pop|X-Amz-Cf-Pop)'),
    ("Google Cloud Armor", "Google", "high", "header",
     r'(?i)(?:x-cloud-armor|x-goog-)'),
    ("Azure WAF / Front Door", "Microsoft", "medium", "header",
     r'(?i)(?:x-azure-ref|x-ms-ref|x-azure-)'),
    ("Azure Application Gateway", "Microsoft", "medium", "header",
     r'(?i)(?:x-ms-request-id|x-azure-requestchain)'),

    # ── Enterprise WAFs ──
    ("Imperva / Incapsula", "Imperva", "high", "header",
     r'(?i)(?:X-Iinfo|x-iinfo|incap_ses|visid_incap)'),
    ("Imperva / Incapsula", "Imperva", "high", "body",
     r'(?i)(?:incapsula.{0,20}(?:error|security)|imperva.{0,20}(?:error|security))'),
    ("F5 BIG-IP ASM", "F5", "high", "header",
     r'(?i)(?:X-Cnection|x-wa-info|X-WA-Info|TS[a-f0-9]{6,})'),
    ("F5 BIG-IP", "F5", "high", "body",
     r'(?i)(?:the\s+requested\s+url\s+was\s+rejected|please\s+consult\s+with\s+your\s+administrator)'),
    ("Akamai", "Akamai", "high", "header",
     r'(?i)(?:akamai-origin-hop|x-akamai|x-akamai-request-id)'),
    ("Akamai", "Akamai", "medium", "body",
     r'(?i)reference\s+#[\d.]+\s+\w{8,}.*akamai'),
    ("Fortinet FortiWeb", "Fortinet", "high", "header",
     r'(?i)(?:fortiwaf|FORTIWAFSID)'),
    ("Fortinet FortiWeb", "Fortinet", "high", "body",
     r'(?i)(?:fortiweb|powered\s+by\s+fortiweb)'),
    ("Barracuda WAF", "Barracuda", "high", "header",
     r'(?i)(?:barracuda|BARRA_COUNTRY)'),
    ("Barracuda WAF", "Barracuda", "medium", "body",
     r'(?i)(?:barracuda.{0,20}(?:web\s+application\s+firewall|security))'),
    ("Citrix NetScaler", "Citrix", "medium", "header",
     r'(?i)(?:ns_af=|citrix_ns_id|NSC_)'),
    ("Radware", "Radware", "medium", "header",
     r'(?i)(?:X-RoadRunner|X-SL-CompState|CloudWebSec)'),

    # ── Open Source WAFs ──
    ("ModSecurity", "OWASP", "high", "header",
     r'(?i)(?:Mod_Security|mod_security|ModSecurity)'),
    ("ModSecurity", "OWASP", "medium", "body",
     r'(?i)(?:modsecurity|mod_security.{0,20}(?:blocked|denied|forbidden))'),
    ("NAXSI", "NBS System", "medium", "header",
     r'(?i)(?:naxsi|X-Naxsi-Sig)'),
    ("NAXSI", "NBS System", "medium", "body",
     r'(?i)naxsi\s+(?:blocked|monitoring)'),

    # ── API Gateways (relevant for AI endpoints) ──
    ("Kong API Gateway", "Kong", "high", "header",
     r'(?i)(?:x-kong-|X-Kong-|kong-request-id)'),
    ("Kong API Gateway", "Kong", "medium", "body",
     r'(?i)(?:kong\s+gateway|kong\s+api)'),
    ("NGINX App Protect", "NGINX", "medium", "header",
     r'(?i)(?:x-nap-waf|x-edge-request)'),
    ("Envoy Proxy", "Envoy", "medium", "header",
     r'(?i)(?:x-envoy-|x-request-id.*envoy)'),

    # ── Generic / Heuristic ──
    ("Generic WAF (403 Forbidden pattern)", "unknown", "low", "status",
     r'^403$'),
    ("Generic WAF (Security Block page)", "unknown", "low", "body",
     r'(?i)(?:blocked\s+by\s+(?:security|firewall|waf)|access\s+denied\s+by\s+security)'),
    ("Generic WAF (Challenge page)", "unknown", "low", "body",
     r'(?i)(?:security\s+check|ddos\s+protection|waiting\s+room|checking\s+your\s+browser)'),
]


class WafDetector:
    """WAF/CDN/IPS 检测器。

    分析 HTTP 响应头和响应体，识别 20+ 种安全防护设施。
    对 AI 红队至关重要：不同 WAF 有不同的 payload 绕过策略。
    """

    def __init__(self):
        self._signatures = _WAF_SIGNATURES

    def detect(self, headers: dict, body: str = "",
               status_code: int = 200) -> WafScanResult:
        """从 HTTP 响应中检测 WAF。

        Args:
            headers: 响应头字典
            body: 响应体文本
            status_code: HTTP 状态码

        Returns:
            WafScanResult
        """
        detections = []
        seen_wafs = set()

        # 收集所有文本源
        header_text = "\n".join(f"{k}: {v}" for k, v in headers.items())
        status_text = str(status_code)

        for name, vendor, confidence, match_type, pattern in self._signatures:
            if match_type == "header" or match_type == "cookie":
                text = header_text
            elif match_type == "status":
                text = status_text
            else:
                text = body

            if not text:
                continue

            m = re.search(pattern, text, re.IGNORECASE)
            if m:
                evidence = m.group(0)[:100]
                if match_type == "header":
                    # 找到具体的 header 行
                    for line in header_text.split("\n"):
                        if m.group(0).lower() in line.lower():
                            evidence = line.strip()[:120]
                            break

                if name not in seen_wafs:
                    seen_wafs.add(name)
                    detections.append(WafMatch(
                        name=name,
                        vendor=vendor,
                        confidence=confidence,
                        evidence=evidence,
                        match_type=match_type,
                    ))

        # 过滤低置信度假阳性
        detections = self._filter_false_positives(detections)

        # 生成 implications
        implications = self._generate_implications(detections)

        summary = ""
        if detections:
            high_confs = [d for d in detections if d.confidence == "high"]
            if high_confs:
                summary = f"检测到 {len(high_confs)} 个 WAF: {', '.join(d.name for d in high_confs)}"
            else:
                summary = f"检测到 {len(detections)} 个潜在 WAF 信号"

        return WafScanResult(
            detections=detections,
            waf_count=len(detections),
            summary=summary or "未检测到 WAF",
            implications=implications,
        )

    def detect_from_probe(self, probe_headers: dict, probe_body: str = "",
                          status: int = 200) -> WafScanResult:
        """从单次探测结果中检测 WAF（别名，与 detect 相同）。"""
        return self.detect(probe_headers, probe_body, status)

    def _filter_false_positives(self, detections: list[WafMatch]) -> list[WafMatch]:
        """过滤低置信度误报。"""
        if not detections:
            return detections

        high_confs = [d for d in detections if d.confidence == "high"]
        if high_confs:
            # 有高置信度命中时，过滤掉可能冲突的低置信度
            high_names = {d.name for d in high_confs}
            filtered = [d for d in detections if d.confidence == "high"
                        or d.name not in high_names]
            return filtered

        # 没有高置信度时，限制低置信度数量
        return detections[:5]

    def _generate_implications(self, detections: list[WafMatch]) -> str:
        """生成 WAF 对后续红队操作的影响评估。"""
        if not detections:
            return "无 WAF 检测。可以直接进行高并发扫描。"

        waf_names = {d.name for d in detections}

        implications = []
        if "Cloudflare" in waf_names:
            implications.append(
                "Cloudflare 检测到：注意请求频率限制(通常1000 req/min)；"
                "建议使用真实浏览器 User-Agent；绕过重点：HTTP/2 smuggling、"
                "Origin IP 直连、Cloudflare Workers 信任域利用"
            )
        if "AWS WAF" in waf_names:
            implications.append(
                "AWS WAF 检测到：SQL injection/XSS 规则可能误拦 payload；"
                "建议编码绕过（Unicode/Base64）、分块传输、速率控制在 500 RPM 以下"
            )
        if "Imperva" in waf_names or "Incapsula" in waf_names:
            implications.append(
                "Imperva/Incapsula：强 JS challenge，推荐使用 headless browser；"
                "payload 需要严格编码，避免括号/引号触发的 HTML 注入规则"
            )
        if "ModSecurity" in waf_names:
            implications.append(
                "ModSecurity：OWASP CRS 规则集，可以使用经典 bypass 技术；"
                "参数污染(HPP)、multipart 边界混淆、HTTP 参数拆分"
            )
        if "F5" in waf_names:
            implications.append(
                "F5 BIG-IP ASM：注意签名绕过，支持请求 smuggling；"
                "建议使用 Transfer-Encoding 混淆"
            )
        if "Kong" in waf_names:
            implications.append(
                "Kong API Gateway：重点在 API 层防护，可能存在 plugin 配置漏洞；"
                "关注 CORS 配置、rate-limit plugin bypass"
            )

        if not implications:
            implications.append(
                f"检测到 {', '.join(waf_names)}，建议手动确认后调整攻击策略"
            )

        return " | ".join(implications)

    def to_dict(self, result: WafScanResult) -> dict:
        """将 WAF 扫描结果转为可序列化的 dict。"""
        return {
            "detections": [
                {
                    "name": d.name,
                    "vendor": d.vendor,
                    "confidence": d.confidence,
                    "evidence": d.evidence,
                    "match_type": d.match_type,
                }
                for d in result.detections
            ],
            "waf_count": result.waf_count,
            "summary": result.summary,
            "implications": result.implications,
        }
