"""
JS SDK 指纹扫描模块 — 从 JavaScript bundles 中识别 AI SDK 引用。

参考: Valtik ai-endpoint-discovery、Julius、llm-con
检测 Vercel AI SDK、OpenAI、Anthropic、Google、Mistral、Cohere、
Groq、Replicate、LangChain、LlamaIndex、OpenRouter、LiteLLM、Ollama 等。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional


# ═══════════════════════════════════════════════════════════════════════════
# AI SDK 签名指纹库
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class SdkSignature:
    """单个 SDK 签名定义"""
    provider: str            # 提供商名称
    type: str                # sdk / framework / platform
    patterns: list[str]      # JS 源码匹配正则
    url_patterns: list[str]  # 提取 URL 的正则组
    priority: int = 5        # 优先级 1-10


# 完整的 AI SDK 指纹库（42 条签名）
_SDK_SIGNATURES: list[SdkSignature] = [
    # ── AI Provider SDKs ──
    SdkSignature("openai", "sdk", [
        r'openai[/"\'][\s,;)\]}]', r'from\s+["\']openai["\']',
        r'require\(["\']openai["\']\)', r'import.*openai',
        r'new\s+OpenAI\s*\(', r'OpenAI\s*\(\s*\{',
        r'api\.openai\.com', r'\.openai\.com/v1',
    ], [r'(?:baseURL|apiKey|api_url|url)\s*[:=]\s*["\'](https?://[^"\']+)["\']'], priority=10),
    SdkSignature("anthropic", "sdk", [
        r'@anthropic[/"\'][\s,;)\]}]', r'from\s+["\']@anthropic',
        r'require\(["\']@anthropic', r'import.*anthropic',
        r'new\s+Anthropic\s*\(', r'Anthropic\s*\(\s*\{',
        r'api\.anthropic\.com', r'claude-[\d.-]+',
    ], [r'(?:baseURL|apiKey|api_url)\s*[:=]\s*["\'](https?://[^"\']+)["\']'], priority=10),
    SdkSignature("google-gemini", "sdk", [
        r'@google/generative-ai', r'@google-ai/generativelanguage',
        r'GoogleGenerativeAI', r'generativelanguage\.googleapis\.com',
        r'gemini-[\d.]+', r'from\s+["\']@google/',
    ], [r'(?:baseURL|apiKey|api_url)\s*[:=]\s*["\'](https?://[^"\']+)["\']'], priority=10),
    SdkSignature("mistral", "sdk", [
        r'@mistralai[/"\'][\s,;)\]}]', r'from\s+["\']@mistralai',
        r'require\(["\']@mistralai', r'import.*mistral',
        r'new\s+Mistral\s*\(', r'mistral-\w+',
    ], [r'(?:baseURL|url|endpoint)\s*[:=]\s*["\'](https?://[^"\']+)["\']'], priority=9),
    SdkSignature("cohere", "sdk", [
        r'cohere-ai[/"\'][\s,;)\]}]', r'from\s+["\']cohere',
        r'require\(["\']cohere', r'new\s+Cohere\s*\(',
        r'api\.cohere\.(ai|com)', r'command-r?[\d.+-]*',
    ], [r'(?:baseURL|endpoint)\s*[:=]\s*["\'](https?://[^"\']+)["\']'], priority=8),
    SdkSignature("groq", "sdk", [
        r'groq-sdk[/"\'][\s,;)\]}]', r'from\s+["\']groq',
        r'require\(["\']groq', r'new\s+Groq\s*\(',
        r'api\.groq\.com', r'llama-[\d.]+-\d+b',
    ], [r'(?:baseURL|url)\s*[:=]\s*["\'](https?://[^"\']+)["\']'], priority=8),
    SdkSignature("replicate", "sdk", [
        r'replicate[/"\'][\s,;)\]}]', r'from\s+["\']replicate["\']',
        r'require\(["\']replicate["\']\)', r'new\s+Replicate\s*\(',
        r'api\.replicate\.com', r'replicate\.com/v1',
    ], [r'(?:baseURL|url)\s*[:=]\s*["\'](https?://[^"\']+)["\']'], priority=8),
    SdkSignature("deepseek", "sdk", [
        r'deepseek[/"\'][\s,;)\]}]', r'from\s+["\']deepseek',
        r'api\.deepseek\.com', r'deepseek-\w+',
    ], [r'(?:baseURL|url)\s*[:=]\s*["\'](https?://[^"\']+)["\']'], priority=8),

    # ── AI Frameworks ──
    SdkSignature("langchain", "framework", [
        r'langchain[/"\'][\s,;)\]}]', r'from\s+["\']langchain',
        r'require\(["\']langchain', r'import.*langchain',
        r'@langchain/', r'langchain_core', r'langchain_community',
    ], [r'(?:base_url|api_url|endpoint_url)\s*[:=]\s*["\'](https?://[^"\']+)["\']'], priority=9),
    SdkSignature("llamaindex", "framework", [
        r'llama-index[/"\'][\s,;)\]}]', r'llamaindex[/"\'][\s,;)\]}]',
        r'from\s+["\']llama_index', r'import.*llama_index',
        r'require\(["\']llamaindex', r'OpenAIEmbedding',
    ], [r'(?:base_url|api_url)\s*[:=]\s*["\'](https?://[^"\']+)["\']'], priority=8),
    SdkSignature("vercel-ai-sdk", "sdk", [
        r'@ai-sdk[/"\'][\s,;)\]}]', r'from\s+["\']ai["\']',
        r'from\s+["\']@ai-sdk', r'import.*ai-sdk',
        r'experimental_StreamData', r'streamText\s*\(',
        r'generateText\s*\(', r'gateway\.ai\.vercel\.app',
    ], [r'(?:baseURL|gateway_url)\s*[:=]\s*["\'](https?://[^"\']+)["\']'], priority=10),

    # ── AI Gateway / Proxy ──
    SdkSignature("openrouter", "platform", [
        r'openrouter\.ai', r'OPENROUTER_API_KEY',
        r'openrouter[/"\'][\s,;)\]}]',
    ], [r'(?:baseURL|openrouter_url)\s*[:=]\s*["\'](https?://[^"\']+)["\']'], priority=9),
    SdkSignature("litellm", "platform", [
        r'litellm[/"\'][\s,;)\]}]', r'from\s+["\']litellm["\']',
        r'import.*litellm', r'litellm\.completion',
        r'litellm\.acompletion', r'litellm_proxy',
    ], [r'(?:base_url|api_base|proxy_url)\s*[:=]\s*["\'](https?://[^"\']+)["\']'], priority=9),

    # ── Local Runtimes ──
    SdkSignature("ollama-client", "platform", [
        r'ollama[/"\'][\s,;)\]}]', r'from\s+["\']ollama["\']',
        r'import.*ollama', r'ollama\.chat\s*\(',
        r'ollama\.generate\s*\(', r'ollama\.list\s*\(',
        r'localhost:11434', r'OLLAMA_HOST',
    ], [r'(?:host|OLLAMA_HOST|url)\s*[:=]\s*["\'](https?://[^"\']+)["\']'], priority=9),
    SdkSignature("lm-studio", "platform", [
        r'lm-studio[/"\'][\s,;)\]}]', r'LMStudio',
        r'localhost:1234', r'lmstudio',
    ], [], priority=7),
    SdkSignature("vllm", "platform", [
        r'vllm[/"\'][\s,;)\]}]', r'from\s+["\']vllm["\']',
        r'vllm\.entrypoints', r'vllm_server',
    ], [r'(?:host|url|api_url)\s*[:=]\s*["\'](https?://[^"\']+)["\']'], priority=7),

    # ── Vector DBs & RAG ──
    SdkSignature("pinecone", "platform", [
        r'pinecone[/"\'][\s,;)\]}]', r'Pinecone\s*\(',
        r'@pinecone-database/', r'pinecone\.io',
    ], [r'(?:url|environment)\s*[:=]\s*["\'](https?://[^"\']+)["\']'], priority=7),
    SdkSignature("chroma", "platform", [
        r'chromadb[/"\'][\s,;)\]}]', r'chroma[/"\'][\s,;)\]}]',
        r'from\s+["\']chromadb["\']', r'ChromaClient',
    ], [r'(?:host|url)\s*[:=]\s*["\'](https?://[^"\']+)["\']'], priority=7),
    SdkSignature("weaviate", "platform", [
        r'weaviate[/"\'][\s,;)\]}]', r'from\s+["\']weaviate',
        r'weaviate\.client', r'weaviate-client',
    ], [r'(?:url|host)\s*[:=]\s*["\'](https?://[^"\']+)["\']'], priority=7),

    # ── Agent Frameworks ──
    SdkSignature("crewai", "framework", [
        r'crewai[/"\'][\s,;)\]}]', r'from\s+["\']crewai["\']',
        r'import.*crewai', r'Crew\s*\(', r'Agent\s*\(\s*role',
    ], [], priority=7),
    SdkSignature("autogen", "framework", [
        r'autogen[/"\'][\s,;)\]}]', r'from\s+["\']autogen',
        r'pyautogen', r'ConversableAgent', r'GroupChat',
    ], [], priority=7),
    SdkSignature("semantic-kernel", "framework", [
        r'semantic-kernel[/"\'][\s,;)\]}]', r'@microsoft/semantic-kernel',
        r'from\s+["\']semantic_kernel', r'SemanticKernel',
    ], [], priority=7),

    # ── AI Gateway / Proxy URLs (直接 URL 匹配) ──
    SdkSignature("huggingface-inference", "platform", [
        r'huggingface\.co/api', r'api-inference\.huggingface\.co',
        r'HfInference\s*\(', r'@huggingface/inference',
    ], [r'(?:url|endpoint)\s*[:=]\s*["\'](https?://api-inference\.huggingface\.co[^"\']*)["\']'], priority=8),
    SdkSignature("together-ai", "platform", [
        r'together\.xyz[/"\'][\s,;)\]}]', r'api\.together\.xyz',
        r'together-ai[/"\'][\s,;)\]}]',
    ], [r'(?:baseURL|url)\s*[:=]\s*["\'](https?://[^"\']+)["\']'], priority=8),
    SdkSignature("perplexity", "platform", [
        r'perplexity[/"\'][\s,;)\]}]', r'api\.perplexity\.ai',
        r'pplx-api', r'PPLX_API_KEY',
    ], [r'(?:baseURL|url)\s*[:=]\s*["\'](https?://[^"\']+)["\']'], priority=8),
    SdkSignature("fireworks", "platform", [
        r'fireworks[/"\'][\s,;)\]}]', r'api\.fireworks\.ai',
        r'FIREWORKS_API_KEY',
    ], [r'(?:baseURL|url)\s*[:=]\s*["\'](https?://[^"\']+)["\']'], priority=7),
    SdkSignature("ai-gateway", "platform", [
        r'agw\.ai', r'ai-gateway', r'ai_gateway',
        r'llm-proxy', r'llm_proxy',
    ], [r'(?:base_url|gateway_url|proxy_url)\s*[:=]\s*["\'](https?://[^"\']+)["\']'], priority=6),
]


@dataclass
class JsSdkFinding:
    """JS SDK 指纹发现结果"""
    provider: str       # 提供商
    type: str           # sdk / framework / platform
    confidence: str     # high / medium / low
    extracted_urls: list[str] = field(default_factory=list)
    match_snippet: str = ""
    source_file: str = ""
    priority: int = 5


@dataclass
class JsSdkScanResult:
    """JS SDK 扫描完整结果"""
    findings: list[JsSdkFinding] = field(default_factory=list)
    total_scripts_scanned: int = 0
    total_matches: int = 0
    extracted_api_urls: list[str] = field(default_factory=list)
    summary: str = ""


class JsSdkScanner:
    """JavaScript SDK 指纹扫描器。

    扫描 JavaScript bundles 中的 AI SDK 客户端签名，
    提取隐式 API base URL 和 gateway 地址。
    """

    def __init__(self):
        self._signatures = _SDK_SIGNATURES

    def scan_text(self, js_content: str, source_label: str = "") -> list[JsSdkFinding]:
        """扫描单段 JS 文本，返回匹配结果。"""
        findings = []
        if not js_content or len(js_content) < 50:
            return findings

        for sig in self._signatures:
            url_extracted = []
            match_snippet = ""
            matched = False

            for pat in sig.patterns:
                m = re.search(pat, js_content, re.IGNORECASE)
                if m:
                    matched = True
                    match_snippet = js_content[max(0, m.start() - 40):m.end() + 40]
                    break

            if matched:
                # 提取 URL
                for url_pat in sig.url_patterns:
                    for um in re.finditer(url_pat, js_content, re.IGNORECASE):
                        extracted = um.group(1)
                        if extracted and extracted not in url_extracted:
                            url_extracted.append(extracted)

                confidence = "high" if sig.priority >= 9 else "medium" if sig.priority >= 7 else "low"
                findings.append(JsSdkFinding(
                    provider=sig.provider,
                    type=sig.type,
                    confidence=confidence,
                    extracted_urls=url_extracted,
                    match_snippet=match_snippet[:200],
                    source_file=source_label,
                    priority=sig.priority,
                ))

        return findings

    def scan_multiple(self, scripts: dict[str, str]) -> JsSdkScanResult:
        """扫描多个 JS 文件。

        Args:
            scripts: {文件名: JS内容} 字典

        Returns:
            JsSdkScanResult 聚合结果
        """
        all_findings = []
        all_urls = []

        for fname, content in scripts.items():
            findings = self.scan_text(content, source_label=fname)
            all_findings.extend(findings)
            for f in findings:
                all_urls.extend(f.extracted_urls)

        # 去重 + 按优先级排序
        seen_providers = set()
        unique_findings = []
        for f in sorted(all_findings, key=lambda x: -x.priority):
            key = (f.provider, f.type)
            if key not in seen_providers:
                seen_providers.add(key)
                unique_findings.append(f)

        all_urls = list(dict.fromkeys(all_urls))

        # 生成摘要
        providers = [f.provider for f in unique_findings]
        summary = ""
        if providers:
            sdk_count = sum(1 for f in unique_findings if f.type == "sdk")
            fw_count = sum(1 for f in unique_findings if f.type == "framework")
            plat_count = sum(1 for f in unique_findings if f.type == "platform")
            parts = []
            if sdk_count: parts.append(f"{sdk_count} AI SDK(s)")
            if fw_count: parts.append(f"{fw_count} framework(s)")
            if plat_count: parts.append(f"{plat_count} platform(s)")
            summary = f"发现 {', '.join(parts)}: {', '.join(providers[:8])}"
            if len(providers) > 8:
                summary += f" ... (+{len(providers) - 8} more)"

        return JsSdkScanResult(
            findings=unique_findings,
            total_scripts_scanned=len(scripts),
            total_matches=len(all_findings),
            extracted_api_urls=all_urls,
            summary=summary,
        )

    def to_dict(self, result: JsSdkScanResult) -> dict:
        """将扫描结果转为可序列化的 dict。"""
        return {
            "findings": [
                {
                    "provider": f.provider,
                    "type": f.type,
                    "confidence": f.confidence,
                    "extracted_urls": f.extracted_urls,
                    "match_snippet": f.match_snippet,
                    "source_file": f.source_file,
                    "priority": f.priority,
                }
                for f in result.findings
            ],
            "total_scripts_scanned": result.total_scripts_scanned,
            "total_matches": result.total_matches,
            "extracted_api_urls": result.extracted_api_urls,
            "summary": result.summary,
        }
