"""
密钥泄露扫描模块 — 从 HTTP 响应和 JS 源码中检测泄露的 API 密钥。

参考: TruffleHog、llm-con credential scanner
支持 25+ 种密钥模式，覆盖主流 AI 平台和云服务。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class CredentialFinding:
    """单条密钥发现"""
    credential_type: str         # 密钥类型，如 "openai_api_key"
    platform: str                # 所属平台，如 "openai"
    risk_level: str              # critical / high / medium / low
    match_snippet: str           # 脱敏后的匹配片段
    source: str                  # 来源 (response_body/js_file/http_header)
    source_detail: str = ""      # 来源详情 (URL/文件名)
    line_context: str = ""       # 上下文行


@dataclass
class CredentialScanResult:
    """密钥扫描完整结果"""
    findings: list[CredentialFinding] = field(default_factory=list)
    total_scanned: int = 0
    critical_count: int = 0
    high_count: int = 0
    summary: str = ""


# ═══════════════════════════════════════════════════════════════════════════
# 密钥模式库 (25+ patterns)
# ═══════════════════════════════════════════════════════════════════════════

_CredPattern = tuple[str, str, str, str, bool]  # (type, platform, risk, regex, is_precise)

_CREDENTIAL_PATTERNS: list[_CredPattern] = [
    # ── AI Platform Keys (Critical) ──
    ("openai_api_key", "openai", "critical",
     r'(?:sk-|OPENAI_API_KEY[=:]\s*["\']?)(sk-[A-Za-z0-9-_]{20,60})', True),
    ("openai_proj_key", "openai", "critical",
     r'(?:sk-proj-|OPENAI_PROJECT_KEY[=:]\s*["\']?)(sk-proj-[A-Za-z0-9-_]{20,80})', True),
    ("openai_admin_key", "openai", "critical",
     r'(?:sk-admin-|OPENAI_ADMIN_KEY[=:]\s*["\']?)(sk-admin-[A-Za-z0-9-_]{20,80})', True),
    ("anthropic_api_key", "anthropic", "critical",
     r'(?:sk-ant-|ANTHROPIC_API_KEY[=:]\s*["\']?)(sk-ant-(?:api|admin)\d{2}-[A-Za-z0-9-_]{60,120})', True),
    ("google_ai_key", "google", "critical",
     r'(?:AIza[0-9A-Za-z_-]{35}|GOOGLE_API_KEY[=:]\s*["\']?AIza[0-9A-Za-z_-]{35})', True),
    ("mistral_api_key", "mistral", "critical",
     r'(?:MISTRAL_API_KEY[=:]\s*["\']?)([A-Za-z0-9]{24,48})', False),
    ("cohere_api_key", "cohere", "critical",
     r'(?:COHERE_API_KEY[=:]\s*["\']?)([A-Za-z0-9]{32,48})', False),
    ("groq_api_key", "groq", "critical",
     r'(?:GROQ_API_KEY[=:]\s*["\']?)(gsk_[A-Za-z0-9]{30,60})', True),
    ("replicate_api_key", "replicate", "critical",
     r'(?:REPLICATE_API_TOKEN[=:]\s*["\']?)(r8_[A-Za-z0-9]{30,60})', True),
    ("deepseek_api_key", "deepseek", "critical",
     r'(?:DEEPSEEK_API_KEY[=:]\s*["\']?)(sk-[A-Za-z0-9]{20,60})', False),
    ("huggingface_token", "huggingface", "high",
     r'(?:HF_TOKEN[=:]\s*["\']?|huggingface\.co/settings/tokens)(hf_[A-Za-z0-9]{25,40})', True),
    ("together_api_key", "together", "high",
     r'(?:TOGETHER_API_KEY[=:]\s*["\']?)([A-Za-z0-9]{40,64})', False),
    ("perplexity_api_key", "perplexity", "high",
     r'(?:PPLX_API_KEY[=:]\s*["\']?)(pplx-[A-Za-z0-9]{30,60})', False),
    ("fireworks_api_key", "fireworks", "high",
     r'(?:FIREWORKS_API_KEY[=:]\s*["\']?)(fw_[A-Za-z0-9]{30,60})', False),

    # ── Gateway / Proxy Keys ──
    ("openrouter_api_key", "openrouter", "critical",
     r'(?:OPENROUTER_API_KEY[=:]\s*["\']?)(sk-or-[A-Za-z0-9]{30,60})', True),
    ("litellm_master_key", "litellm", "critical",
     r'(?:LITELLM_MASTER_KEY[=:]\s*["\']?)(sk-[A-Za-z0-9-]{30,80})', False),
    ("nvidia_nim_key", "nvidia", "high",
     r'(?:NVIDIA_API_KEY[=:]\s*["\']?)(nvapi-[A-Za-z0-9_-]{40,80})', True),

    # ── Vector DB / RAG ──
    ("pinecone_api_key", "pinecone", "high",
     r'(?:PINECONE_API_KEY[=:]\s*["\']?)([A-Fa-f0-9-]{36,48})', False),
    ("weaviate_api_key", "weaviate", "high",
     r'(?:WEAVIATE_API_KEY[=:]\s*["\']?)([A-Za-z0-9-_]{24,48})', False),
    ("chroma_token", "chroma", "medium",
     r'(?:CHROMA_SERVER_AUTH[=:]\s*["\']?)([A-Za-z0-9-_]{16,64})', False),

    # ── Ollama (无认证通常，但检测泄露的 host/配置) ──
    ("ollama_host_exposure", "ollama", "medium",
     r'OLLAMA_HOST[=:]\s*["\'](https?://[^"\'\s]+)', False),
    ("ollama_exposed_endpoint", "ollama", "low",
     r'http://[0-9.]+:11434', False),

    # ── Generic API Key Patterns (Beware: noisy) ──
    ("generic_bearer_token", "generic", "high",
     r'(?:Authorization|auth|token)\s*[:=]\s*["\']?(?:Bearer\s+)?(eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,})["\']?', True),
    ("generic_api_key_assign", "generic", "medium",
     r'(?:API_KEY|apiKey|api_key|apikey|secret_key|SECRET)\s*[:=]\s*["\']([A-Za-z0-9_-]{20,80})["\']', False),
    ("generic_endpoint_cred", "generic", "medium",
     r'(?:password|passwd|pwd)\s*[:=]\s*["\']([^"\'\s]{6,64})["\']', False),

    # ── Cloud AI Services ──
    ("aws_access_key", "aws", "critical",
     r'(?:AWS_ACCESS_KEY_ID|aws_access_key_id)[=:]\s*["\']?(AKIA[0-9A-Z]{16})["\']?', True),
    ("aws_secret_key", "aws", "critical",
     r'(?:AWS_SECRET_ACCESS_KEY|aws_secret_access_key)[=:]\s*["\']?([0-9a-zA-Z/+]{40})["\']?', False),
    ("azure_openai_key", "azure", "critical",
     r'(?:AZURE_OPENAI_API_KEY|AZURE_OPENAI_KEY)[=:]\s*["\']([A-Za-z0-9]{32,64})', False),
    ("gcp_service_account", "gcp", "high",
     r'("type"\s*:\s*"service_account".*?"private_key")', False),
]

# 需要精确匹配的高优先级模式 (避免误报)
_PRECISE_CRED_TYPES = {p[0] for p in _CREDENTIAL_PATTERNS if p[4]}


class CredentialScanner:
    """AI 密钥泄露扫描器。

    从 HTTP 响应体、JS 源码、响应头中检测泄露的 API 密钥。
    支持脱敏输出和风险分级。
    """

    def __init__(self):
        self._patterns = _CREDENTIAL_PATTERNS

    def scan_text(self, text: str, source: str = "response_body",
                  source_detail: str = "") -> list[CredentialFinding]:
        """扫描单段文本中的密钥泄露。"""
        findings = []
        if not text or len(text) < 20:
            return findings

        for cred_type, platform, risk, pattern, is_precise in self._patterns:
            try:
                for m in re.finditer(pattern, text, re.IGNORECASE | re.MULTILINE):
                    matched_text = m.group(0)
                    key_value = m.group(1) if m.lastindex else matched_text

                    # 对于非精确模式，做额外的熵验证
                    if not is_precise:
                        if not self._basic_entropy_check(key_value):
                            continue

                    # 脱敏处理
                    sanitized = self._sanitize(matched_text, key_value)

                    # 提取上下文行
                    start = max(0, m.start() - 60)
                    end = min(len(text), m.end() + 60)

                    findings.append(CredentialFinding(
                        credential_type=cred_type,
                        platform=platform,
                        risk_level=risk,
                        match_snippet=sanitized,
                        source=source,
                        source_detail=source_detail,
                        line_context=text[start:end].replace('\n', ' ').strip(),
                    ))
            except Exception:
                continue

        return findings

    def scan_response(self, body: str, url: str = "", headers: dict | None = None) -> list[CredentialFinding]:
        """扫描 HTTP 响应中的密钥泄露。"""
        findings = []

        # 扫描响应体
        if body:
            findings.extend(self.scan_text(body, source="response_body", source_detail=url))

        # 扫描响应头
        if headers:
            headers_text = "\n".join(f"{k}: {v}" for k, v in headers.items())
            findings.extend(self.scan_text(headers_text, source="http_header", source_detail=url))

        return findings

    def scan_js(self, js_content: str, filename: str = "") -> list[CredentialFinding]:
        """扫描 JavaScript 文件中的密钥泄露。"""
        return self.scan_text(js_content, source="js_file", source_detail=filename)

    def scan_batch(self, texts: list[tuple[str, str, str]]) -> CredentialScanResult:
        """批量扫描多个文本源。

        Args:
            texts: [(content, source, source_detail), ...] 列表

        Returns:
            CredentialScanResult
        """
        all_findings = []
        seen = set()

        for content, source, detail in texts:
            findings = self.scan_text(content, source=source, source_detail=detail)
            for f in findings:
                # 去重（同一类型 + 来源）
                key = (f.credential_type, f.source, f.match_snippet[:20])
                if key not in seen:
                    seen.add(key)
                    all_findings.append(f)

        critical = [f for f in all_findings if f.risk_level == "critical"]
        high = [f for f in all_findings if f.risk_level == "high"]

        summary = ""
        if all_findings:
            parts = []
            if critical: parts.append(f"{len(critical)} 严重")
            if high: parts.append(f"{len(high)} 高危")
            parts.append(f"{len(all_findings) - len(critical) - len(high)} 中低风险")
            platforms = set(f.platform for f in all_findings)
            summary = f"发现 {', '.join(parts)} 密钥泄露 ({', '.join(sorted(platforms))})"

        return CredentialScanResult(
            findings=all_findings,
            total_scanned=len(texts),
            critical_count=len(critical),
            high_count=len(high),
            summary=summary,
        )

    @staticmethod
    def _sanitize(text: str, key: str) -> str:
        """脱敏密钥展示。"""
        if len(key) <= 8:
            return text.replace(key, key[:2] + "***" + key[-2:])
        return text.replace(key, key[:4] + "***" + key[-4:])

    @staticmethod
    def _basic_entropy_check(s: str) -> bool:
        """简单熵检查：过滤掉像 'localhost' 之类的常见词。"""
        if not s or len(s) < 12:
            return False
        # 排除纯数字
        if s.isdigit():
            return False
        # 排除常见无害值
        common_false_positives = {
            'localhost', 'example', 'test', 'changeme', 'password',
            'undefined', 'null', 'none', 'your-api-key', 'your_api_key',
            'xxxx', '****', 'insert', 'replace', '<your', '${',
        }
        lower = s.lower()
        for fp in common_false_positives:
            if fp in lower:
                return False
        return True

    def to_dict(self, result: CredentialScanResult) -> dict:
        """将扫描结果转为可序列化的 dict。"""
        return {
            "findings": [
                {
                    "credential_type": f.credential_type,
                    "platform": f.platform,
                    "risk_level": f.risk_level,
                    "match_snippet": f.match_snippet,
                    "source": f.source,
                    "source_detail": f.source_detail,
                }
                for f in result.findings
            ],
            "total_scanned": result.total_scanned,
            "critical_count": result.critical_count,
            "high_count": result.high_count,
            "summary": result.summary,
        }
