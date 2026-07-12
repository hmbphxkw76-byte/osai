"""AIMap（Bishop Fox）封装：AI 原生攻击面发现 / 组件指纹 / 风险评分。

Library-First：直接调用 AIMap 二进制（开源，专攻暴露的 MCP/Ollama/vLLM/LangServe/
Gradio/ComfyUI/OpenWebUI/Flowise）。其 CLI/输出格式随版本演进，这里做**尽力而为**解析。

增强策略（针对 AI 应用侦察成功率）：
1. 协议级结构化解析 → AIFingerprint（不仅正则匹配关键词）
2. Bishop Fox 风险评分模型 → 每个暴露 AI 服务的 0-10 风险评分
3. Finding 生成 → 将 AIMap 发现转化为统一漏洞模型
4. 多源关联 → 与 nuclei/katana/endpoint_recon 结果交叉验证

自研理由：AIMap 输出格式为文本报告而非结构化 JSON，需要自研解析器提取
协议指纹与风险因子。暂无 PyPI 库可替代此解析逻辑。
"""
from __future__ import annotations

import re
import subprocess
from typing import Any

from redteam.core.models import AIFingerprint, AIProtocol, Endpoint, Finding, Severity
from redteam.core.tools import ToolResolver


def _risk_to_severity(score: float) -> str:
    if score <= 0:
        return Severity.INFO.value
    if score <= 2.5:
        return Severity.LOW.value
    if score <= 5.0:
        return Severity.MEDIUM.value
    if score <= 7.5:
        return Severity.HIGH.value
    return Severity.CRITICAL.value

# ---- 协议检测正则 ----

_PROTOCOL_PATTERNS: dict[str, re.Pattern] = {
    "mcp": re.compile(r"(?i)\bMCP\b.*?(server|endpoint|protocol|detected|discovered|exposed|running)"),
    "ollama": re.compile(r"(?i)\bollama\b.*?(detected|discovered|exposed|running|endpoint|API)"),
    "vllm": re.compile(r"(?i)\bvLLM\b.*?(detected|discovered|endpoint|API)"),
    "litellm": re.compile(r"(?i)\b(litellm|LiteLLM)\b.*?(detected|discovered|proxy|endpoint|API)"),
    "langserve": re.compile(r"(?i)\blangserve\b.*?(detected|discovered|endpoint|playground)"),
    "gradio": re.compile(r"(?i)\bgradio\b.*?(detected|discovered|app|endpoint|interface)"),
    "comfyui": re.compile(r"(?i)\bcomfyui\b.*?(detected|discovered|endpoint|workflow)"),
    "openwebui": re.compile(r"(?i)\bopen[_\s]?webui\b.*?(detected|discovered|endpoint)"),
    "flowise": re.compile(r"(?i)\bflowise\b.*?(detected|discovered|endpoint|flow)"),
}

# ---- 风险因素关键词 ----
_AUTH_ABSENT = re.compile(r"(?i)(no\s*auth|without\s*auth|unauthenticated|auth.*?none|auth.*?disabled|anonymous\s*access)")
_AUTH_REQUIRED = re.compile(r"(?i)(auth.*?required|requires?\s*auth|authentication.*?enabled|protected)")
_TLS_MISSING = re.compile(r"(?i)(no\s*TLS|without\s*TLS|HTTP\s*only|plaintext)")
_CORS_OPEN = re.compile(r"(?i)(CORS.*?(open|wildcard|allow.*?\*|bypass|misconfig))")
_PROMPT_LEAKED = re.compile(r"(?i)(system[_\s]?prompt.*?(leak|exposed|discovered|visible|accessible))")
_UNCENSORED = re.compile(r"(?i)(uncensored|unfiltered|no[_\s]?guardrail|jailbreak.*?possible)")
_CRITICAL_TOOLS = re.compile(r"(?i)\b(exec_code|run_shell|execute_command|shell_exec|run_command|eval|system_call)\b")

# ---- URL 抽取 ----
_URL_RE = re.compile(r"https?://[^\s\"'<>\)\]]+")

# ---- 组件名关键词（基础匹配，兜底） ----
_COMP_RE = re.compile(r"(ollama|vllm|litellm|langserve|gradio|comfyui|mcp|openwebui|flowise)", re.I)

# ---- 版本提取 ----
_VERSION_RE = re.compile(r"(?i)\bversion\s*[:=]?\s*([\d.]+)")


def _extract_urls(text: str, protocol: str | None = None) -> list[str]:
    """从文本提取 URL，可选按协议过滤。"""
    urls = _URL_RE.findall(text)
    if protocol:
        urls = [u for u in urls if protocol.lower() in u.lower()
                or any(k in u.lower() for k in _protocol_path_hints(protocol))]
    return sorted(set(urls))


def _protocol_path_hints(protocol: str) -> list[str]:
    """返回协议相关的路径关键词。"""
    hints: dict[str, list[str]] = {
        "ollama": ["/api/tags", "/api/generate", "11434"],
        "vllm": ["/v1/models", "/v1/completions"],
        "mcp": ["/mcp", "/sse", ".well-known/mcp"],
        "gradio": ["gradio", "/queue/join"],
        "comfyui": ["comfyui", "/prompt", "/ws"],
        "langserve": ["langserve", "/playground"],
    }
    return hints.get(protocol, [])


def _parse_fingerprint(text: str, protocol: str) -> AIFingerprint:
    """从 AIMap 输出解析特定协议的结构化指纹。"""
    fp = AIFingerprint(protocol=protocol)

    # 认证状态
    if _AUTH_ABSENT.search(text):
        fp.auth_required = False
        fp.auth_type = "none"
    elif _AUTH_REQUIRED.search(text):
        fp.auth_required = True
        fp.auth_type = "unknown"

    # 安全状态
    fp.tls = not bool(_TLS_MISSING.search(text))
    fp.cors_open = bool(_CORS_OPEN.search(text))
    fp.system_prompt_leaked = bool(_PROMPT_LEAKED.search(text))
    fp.uncensored_model = bool(_UNCENSORED.search(text))

    # 版本
    vm = _VERSION_RE.search(text)
    if vm:
        fp.version = vm.group(1)

    # 工具
    fp.tools = sorted(set(_CRITICAL_TOOLS.findall(text)))

    # 风险因素
    if not fp.auth_required:
        fp.risk_factors.append("无认证暴露")
    if not fp.tls:
        fp.risk_factors.append("无 TLS 加密")
    if fp.cors_open:
        fp.risk_factors.append("CORS 策略开放")
    if fp.system_prompt_leaked:
        fp.risk_factors.append("系统提示词泄漏")
    if fp.uncensored_model:
        fp.risk_factors.append("无审查模型")
    if fp.tools:
        fp.risk_factors.append(f"暴露关键工具: {','.join(fp.tools)}")

    return fp


def _parse_models(text: str, protocol: str) -> list[str]:
    """从 AIMap 输出解析暴露的模型名。"""
    models: list[str] = []
    # Ollama 模型格式
    if protocol == "ollama":
        ollama_model = re.findall(r"(?i)model[s]?\s*[:=]?\s*['\"]?([a-zA-Z][a-zA-Z0-9._\-:]+)", text)
        models.extend(ollama_model)
    # OpenAI 兼容格式
    model_ids = re.findall(r"(?i)(?:model|id)[_\s]*(?:name)?\s*[:=]\s*['\"]?([a-zA-Z][a-zA-Z0-9._\-]+)", text)
    models.extend(model_ids)
    # 排除明显非模型名的
    exclude = {"model", "models", "name", "id", "version", "type", "none", "null", "default"}
    return sorted(set(m for m in models if m.lower() not in exclude))


def _parse_nuclei_findings(text: str) -> list[dict[str, Any]]:
    """尝试从输出中解析 JSONL 格式的 nuclei 扫描结果。"""
    findings: list[dict[str, Any]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            import json
            obj = json.loads(line)
            if "template-id" in obj or "info" in obj:
                findings.append(obj)
        except Exception:
            continue
    return findings


def _generate_findings(
    fingerprints: list[AIFingerprint],
    endpoints: list[Endpoint],
    nuclei_results: list[dict],
) -> list[Finding]:
    """将 AIMap 发现转化为统一 Finding 模型。"""
    findings: list[Finding] = []

    # nuclei 模板发现
    for nr in nuclei_results:
        info = nr.get("info", {})
        findings.append(Finding(
            source="aimap",
            category=nr.get("template-id", "ai-exposure"),
            severity=info.get("severity", "medium"),
            title=info.get("name", nr.get("template-id", "")),
            evidence=nr.get("matched-at", "") or nr.get("extracted-results", ""),
            remediation=info.get("remediation", "") or "",
            endpoint=nr.get("matched-at"),
        ))

    # 指纹风险发现
    for fp in fingerprints:
        if fp.risk_score > 0:
            findings.append(Finding(
                source="aimap",
                category=f"{fp.protocol}_exposure",
                severity=_risk_to_severity(fp.risk_score),
                title=f"{fp.protocol.upper()} 服务暴露 - 风险评分 {fp.risk_score:.1f}/10",
                evidence=f"风险因素: {', '.join(fp.risk_factors)}",
                remediation=_remediation_hint(fp),
            ))

    # 端点发现
    for ep in endpoints:
        if ep.ai_fingerprint and ep.ai_fingerprint.risk_score > 0:
            findings.append(Finding(
                source="aimap",
                category="ai_endpoint_discovered",
                severity=_risk_to_severity(ep.ai_fingerprint.risk_score),
                title=f"AI 端点发现: {ep.url}",
                evidence=f"协议: {ep.kind}, 认证: {'需要' if ep.requires_auth else '不需要'}",
                endpoint=ep.url,
            ))

    return findings


def _remediation_hint(fp: AIFingerprint) -> str:
    """根据风险因素生成修复建议。"""
    hints = []
    if not fp.auth_required:
        hints.append("为 AI 服务添加认证（API Key / OAuth2）")
    if not fp.tls:
        hints.append("启用 HTTPS/TLS 加密传输")
    if fp.cors_open:
        hints.append("限制 CORS 策略，避免通配符 *")
    if fp.tools:
        hints.append(f"审查暴露的工具权限: {', '.join(fp.tools[:5])}")
    if fp.system_prompt_leaked:
        hints.append("隐藏系统提示词，通过服务端注入")
    return "; ".join(hints) if hints else "评估 AI 服务暴露面风险"


def run(
    target: str,
    resolver: ToolResolver | None = None,
    timeout: int = 180,
    authorized: bool = False,
) -> tuple[list[str], list[Endpoint], list[Finding], list[AIFingerprint]]:
    """运行 AIMap AI 攻击面发现。

    Args:
        target: 目标 URL
        resolver: 工具解析器
        timeout: 超时（秒）
        authorized: 是否为授权测试（仅法律声明用）

    Returns:
        (components, endpoints, findings, fingerprints)
    """
    resolver = resolver or ToolResolver()
    cmd = [resolver.resolve("aimap"), "-t", target]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except Exception:  # noqa: BLE001
        return [], [], [], []

    out = proc.stdout + "\n" + proc.stderr

    # === 基础组件检测（原有逻辑） ===
    components = sorted(set(m.group(1).lower() for m in _COMP_RE.finditer(out)))

    # === 协议级指纹解析 ===
    fingerprints: list[AIFingerprint] = []
    for protocol, pattern in _PROTOCOL_PATTERNS.items():
        if pattern.search(out):
            fp = _parse_fingerprint(out, protocol)
            fp.models = _parse_models(out, protocol)
            fingerprints.append(fp)

    # === URL 抽取（按协议分组） ===
    all_urls: list[str] = []
    for protocol in _PROTOCOL_PATTERNS:
        urls: list[str] = []
        for u in _extract_urls(out, protocol):
            if u not in all_urls:
                all_urls.append(u)
                urls.append(u)

    endpoints: list[Endpoint] = []
    for u in all_urls:
        ep = Endpoint(
            url=u,
            kind="web",
            discovered_by="aimap",
        )
        # 尝试匹配协议
        for p in AIProtocol:
            if p.value.replace("_", "") in u.lower().replace("-", "").replace("_", ""):
                ep.kind = p.value
                break
        # 尝试关联指纹
        for fp in fingerprints:
            if any(hint in u.lower() for hint in _protocol_path_hints(fp.protocol)):
                ep.ai_fingerprint = fp
                ep.risk_score = fp.risk_score
                ep.risk_level = _risk_to_severity(fp.risk_score)
                break
        endpoints.append(ep)

    # === nuclei 扫描结果解析 ===
    nuclei_results = _parse_nuclei_findings(out)

    # === Finding 生成 ===
    findings = _generate_findings(fingerprints, endpoints, nuclei_results)

    return components, endpoints, findings, fingerprints
