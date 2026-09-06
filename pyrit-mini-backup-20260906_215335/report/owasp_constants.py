"""OWASP 鏍囧噯甯搁噺 鈥?浠?evidence.py 鎷嗗垎鑰屾潵.

鍖呭惈 MITRE ATLAS 鏄犲皠, OWASP 鏍囧噯寮曠敤, OWASP Web Top 10 缂撹В寤鸿.
"""

# 鈹€鈹€ MITRE ATT&CK for AI Systems (ATLAS) 鏄犲皠 鈹€鈹€
# Reference: https://atlas.mitre.org/
# 瀛︽湳渚濇嵁: MITRE ATLAS (Adversarial Threat Landscape for AI Systems)
#  frames AI-specific attack techniques analogous to ATT&CK for traditional IT.
_MITRE_ATLAS_TECHNIQUES: dict[str, dict[str, str]] = {
    "LLM01": {
        "tactic": "Execution",
        "technique_id": "AML.T0051",
        "technique_name": "LLM Prompt Injection",
        "url": "https://atlas.mitre.org/techniques/AML.T0051",
    },
    "LLM02": {
        "tactic": "Collection",
        "technique_id": "AML.T0044",
        "technique_name": "ML Model Inversion",
        "url": "https://atlas.mitre.org/techniques/AML.T0044",
    },
    "LLM03": {
        "tactic": "Initial Access",
        "technique_id": "AML.T0010",
        "technique_name": "ML Supply Chain Compromise",
        "url": "https://atlas.mitre.org/techniques/AML.T0010",
    },
    "LLM04": {
        "tactic": "Persistence",
        "technique_id": "AML.T0018",
        "technique_name": "Data Poisoning",
        "url": "https://atlas.mitre.org/techniques/AML.T0018",
    },
    "LLM05": {
        "tactic": "Impact",
        "technique_id": "AML.T0050",
        "technique_name": "LLM Misinformation / Harmful Output",
        "url": "https://atlas.mitre.org/techniques/AML.T0050",
    },
    "LLM06": {
        "tactic": "Execution",
        "technique_id": "AML.T0051",
        "technique_name": "LLM Prompt Injection 鈫?Excessive Agency",
        "url": "https://atlas.mitre.org/techniques/AML.T0051",
    },
    "LLM07": {
        "tactic": "Discovery",
        "technique_id": "AML.T0044",
        "technique_name": "System Prompt Extraction",
        "url": "https://atlas.mitre.org/techniques/AML.T0044",
    },
    "LLM08": {
        "tactic": "Persistence",
        "technique_id": "AML.T0018",
        "technique_name": "Vector DB Poisoning",
        "url": "https://atlas.mitre.org/techniques/AML.T0018",
    },
    "LLM09": {
        "tactic": "Impact",
        "technique_id": "AML.T0050",
        "technique_name": "LLM Misinformation Generation",
        "url": "https://atlas.mitre.org/techniques/AML.T0050",
    },
    "LLM10": {
        "tactic": "Impact",
        "technique_id": "AML.T0029",
        "technique_name": "Denial of ML Service",
        "url": "https://atlas.mitre.org/techniques/AML.T0029",
    },
    "ASI01": {
        "tactic": "Initial Access",
        "technique_id": "AML.T0010",
        "technique_name": "Agent Identity Spoofing",
        "url": "https://atlas.mitre.org/techniques/AML.T0010",
    },
    "ASI02": {
        "tactic": "Execution",
        "technique_id": "AML.T0051",
        "technique_name": "Agent Tool Misuse",
        "url": "https://atlas.mitre.org/techniques/AML.T0051",
    },
    "ASI03": {
        "tactic": "Execution",
        "technique_id": "AML.T0051",
        "technique_name": "Unauthorized Agent Actions",
        "url": "https://atlas.mitre.org/techniques/AML.T0051",
    },
    "ASI04": {
        "tactic": "Exfiltration",
        "technique_id": "AML.T0044",
        "technique_name": "Agent Data Exfiltration",
        "url": "https://atlas.mitre.org/techniques/AML.T0044",
    },
    "ASI05": {
        "tactic": "Privilege Escalation",
        "technique_id": "AML.T0011",
        "technique_name": "Agent Privilege Escalation",
        "url": "https://atlas.mitre.org/techniques/AML.T0011",
    },
    "ASI06": {
        "tactic": "Persistence",
        "technique_id": "AML.T0018",
        "technique_name": "Agent Memory Poisoning",
        "url": "https://atlas.mitre.org/techniques/AML.T0018",
    },
    "ASI07": {
        "tactic": "Lateral Movement",
        "technique_id": "AML.T0051",
        "technique_name": "Cross-Agent Injection",
        "url": "https://atlas.mitre.org/techniques/AML.T0051",
    },
    "ASI08": {
        "tactic": "Impact",
        "technique_id": "AML.T0029",
        "technique_name": "Agent Cascading Failure",
        "url": "https://atlas.mitre.org/techniques/AML.T0029",
    },
    "ASI09": {
        "tactic": "Defense Evasion",
        "technique_id": "AML.T0014",
        "technique_name": "Trust Boundary Violation",
        "url": "https://atlas.mitre.org/techniques/AML.T0014",
    },
    "ASI10": {
        "tactic": "Impact",
        "technique_id": "AML.T0050",
        "technique_name": "Rogue Agent Hijacking",
        "url": "https://atlas.mitre.org/techniques/AML.T0050",
    },
}

# 鈹€鈹€ OWASP Top 10 (2025) 鈥?浼犵粺 Web 瀹夊叏婕忔礊 鈹€鈹€
# Reference: https://owasp.org/www-project-top-10/
_OWASP_WEB_CATEGORIES = {
    "A01": "Broken Access Control",
    "A02": "Cryptographic Failures",
    "A03": "Injection",
    "A04": "Insecure Design",
    "A05": "Security Misconfiguration",
    "A06": "Vulnerable and Outdated Components",
    "A07": "Identification and Authentication Failures",
    "A08": "Software and Data Integrity Failures",
    "A09": "Security Logging and Monitoring Failures",
    "A10": "Server-Side Request Forgery (SSRF)",
}

# 鈹€鈹€ OWASP LLM Top 10 for LLM Applications (2025 Edition) 鈹€鈹€
# Reference: https://owasp.org/www-project-top-10-for-large-language-model-applications/
_OWASP_LLM_CATEGORIES = {
    "LLM01": "Prompt Injection",
    "LLM02": "Sensitive Information Disclosure",
    "LLM03": "Supply Chain",
    "LLM04": "Data and Model Poisoning",
    "LLM05": "Improper Output Handling",
    "LLM06": "Excessive Agency",
    "LLM07": "System Prompt Leakage",
    "LLM08": "Vector and Embedding Weaknesses",
    "LLM09": "Misinformation",
    "LLM10": "Unbounded Consumption",
}

# 鈹€鈹€ OWASP Agentic AI Top 10 鈹€鈹€
# Reference: https://owasp.org/www-project-agent-security/
# (鍓嶈韩: Agent Security Initiative, 2025 鏇村悕涓?Agentic AI Top 10)
_OWASP_ASI_CATEGORIES = {
    "ASI01": "Agent Identity Spoofing",
    "ASI02": "Tool Misuse",
    "ASI03": "Unauthorized Actions",
    "ASI04": "Data Exfiltration",
    "ASI05": "Privilege Escalation",
    "ASI06": "Memory Poisoning",
    "ASI07": "Cross-Agent Injection",
    "ASI08": "Cascading Failures",
    "ASI09": "Trust Boundary Violation",
    "ASI10": "Rogue Agent",
}

# 鈹€鈹€ OWASP 鏍囧噯涓ラ噸鎬х瓑绾?(CVSS-like 椋庨櫓璇勫垎) 鈹€鈹€
_OWASP_SEVERITY_LEVELS = {
    "critical": {"score_range": (9.0, 10.0), "color": "#ff0000", "description": "Immediate exploitation risk, requires urgent remediation"},
    "high": {"score_range": (7.0, 8.9), "color": "#ff4444", "description": "Significant risk, remediate within 7 days"},
    "medium": {"score_range": (4.0, 6.9), "color": "#ffaa00", "description": "Moderate risk, remediate within 30 days"},
    "low": {"score_range": (1.0, 3.9), "color": "#00aa00", "description": "Limited impact, remediate within 90 days"},
    "info": {"score_range": (0.0, 0.9), "color": "#888888", "description": "Informational, no direct risk"},
}

# 鈹€鈹€ OWASP LLM Top 10 鏍囧噯缂撹В寤鸿 鈹€鈹€
_OWASP_LLM_MITIGATIONS = {
    "LLM01": [
        "Implement input validation and sanitization for all prompts",
        "Use role-based access control (RBAC) to restrict model capabilities",
        "Deploy prompt injection detection classifiers",
        "Enforce human-in-the-loop for high-privilege operations",
    ],
    "LLM02": [
        "Implement data minimization in model responses",
        "Use output filtering and redaction for PII/sensitive data",
        "Apply differential privacy techniques",
        "Enforce strict data access controls and audit logging",
    ],
    "LLM03": [
        "Vet and verify all third-party model components",
        "Maintain Software Bill of Materials (SBOM) for ML supply chain",
        "Use model signing and integrity verification",
        "Implement dependency scanning for ML artifacts",
    ],
    "LLM04": [
        "Implement data provenance tracking and validation",
        "Use adversarial training with poisoning detection",
        "Apply statistical anomaly detection on training data",
        "Maintain data versioning and rollback capabilities",
    ],
    "LLM05": [
        "Implement output encoding and sanitization",
        "Use context-aware output filtering",
        "Apply structured output schemas with validation",
        "Deploy WAF rules for LLM-generated content",
    ],
    "LLM06": [
        "Implement least-privilege tool access controls",
        "Require explicit human approval for destructive actions",
        "Use tool allowlisting and capability scoping",
        "Deploy action auditing and anomaly detection",
    ],
    "LLM07": [
        "Avoid storing sensitive information in system prompts",
        "Use prompt isolation techniques",
        "Implement system prompt leakage detection",
        "Apply layered prompt architecture with isolation boundaries",
    ],
    "LLM08": [
        "Implement access controls on vector databases",
        "Use embedding sanitization and input validation",
        "Apply retrieval-augmented generation (RAG) security controls",
        "Monitor for embedding poisoning attacks",
    ],
    "LLM09": [
        "Implement fact-checking and verification mechanisms",
        "Use grounding techniques with trusted sources",
        "Apply confidence scoring and uncertainty quantification",
        "Deploy hallucination detection and filtering",
    ],
    "LLM10": [
        "Implement rate limiting and quota management",
        "Use API token bucket algorithms for resource control",
        "Monitor for anomalous consumption patterns",
        "Apply cost caps and usage alerts",
    ],
}

# 鈹€鈹€ OWASP ASI Top 10 鏍囧噯缂撹В寤鸿 鈹€鈹€
_OWASP_ASI_MITIGATIONS = {
    "ASI01": [
        "Implement agent identity verification and authentication",
        "Use mutual TLS for agent-to-agent communication",
        "Deploy agent identity attestation mechanisms",
        "Enforce per-agent cryptographic identity tokens",
    ],
    "ASI02": [
        "Implement tool input validation and parameter constraints",
        "Use tool allowlisting and capability scoping",
        "Deploy tool call monitoring and anomaly detection",
        "Require human approval for high-risk tool operations",
    ],
    "ASI03": [
        "Implement action authorization with policy enforcement",
        "Use capability-based security for agent actions",
        "Deploy action auditing with real-time alerting",
        "Enforce principle of least privilege for all agent operations",
    ],
    "ASI04": [
        "Implement data loss prevention (DLP) for agent outputs",
        "Use egress filtering for sensitive data",
        "Deploy exfiltration detection and blocking",
        "Apply data classification and tagging for agent-accessible data",
    ],
    "ASI05": [
        "Implement privilege boundaries and isolation",
        "Use role escalation detection and alerting",
        "Deploy privilege attribute verification",
        "Enforce multi-factor authorization for privilege changes",
    ],
    "ASI06": [
        "Implement memory integrity verification",
        "Use memory access controls and encryption",
        "Deploy memory poisoning detection mechanisms",
        "Apply memory snapshot and rollback capabilities",
    ],
    "ASI07": [
        "Implement agent isolation boundaries",
        "Use message sanitization between agents",
        "Deploy cross-agent injection detection",
        "Apply trust verification for inter-agent communication",
    ],
    "ASI08": [
        "Implement circuit breakers and failure isolation",
        "Use cascading failure detection and prevention",
        "Deploy graceful degradation mechanisms",
        "Apply dependency mapping and failure impact analysis",
    ],
    "ASI09": [
        "Implement trust boundary enforcement",
        "Use context isolation between trust domains",
        "Deploy boundary violation detection",
        "Apply zero-trust architecture for agent interactions",
    ],
    "ASI10": [
        "Implement agent behavioral monitoring",
        "Use rogue agent detection and containment",
        "Deploy kill switches and emergency shutdown",
        "Apply continuous behavioral baselines and deviation alerting",
    ],
}

# 鈹€鈹€ OWASP Web Top 10 (2025) 鏍囧噯缂撹В寤鸿 鈹€鈹€
_OWASP_WEB_MITIGATIONS = {
    "A01": [
        "Implement proper access control checks on every request",
        "Use deny-by-default for all resources",
        "Validate user ownership before returning data (prevent IDOR)",
        "Sanitize and validate all path parameters to prevent traversal",
    ],
    "A02": [
        "Use strong encryption algorithms (AES-256, bcrypt/argon2 for passwords)",
        "Never store plaintext passwords or hardcode secrets",
        "Enforce TLS 1.2+ for all communications",
        "Implement proper key management and rotation policies",
    ],
    "A03": [
        "Use parameterized queries / prepared statements for all database access",
        "Implement input validation and output encoding for XSS prevention",
        "Use Content-Security-Policy (CSP) headers",
        "Sanitize all user input before command execution",
    ],
    "A04": [
        "Implement threat modeling in the design phase",
        "Enforce rate limiting and resource throttling",
        "Use property-level authorization (prevent mass assignment)",
        "Implement business logic validation and anomaly detection",
    ],
    "A05": [
        "Disable directory listing and default error pages",
        "Remove default credentials and unused features",
        "Implement secure XML parsing (disable external entities for XXE)",
        "Enforce security headers (HSTS, X-Frame-Options, X-Content-Type-Options)",
    ],
    "A06": [
        "Maintain an up-to-date SBOM (Software Bill of Materials)",
        "Implement automated dependency scanning (SCA tools)",
        "Patch and upgrade components regularly",
        "Monitor CVE databases for known vulnerabilities in dependencies",
    ],
    "A07": [
        "Implement multi-factor authentication (MFA)",
        "Use secure session management (regenerate session IDs)",
        "Enforce strong password policies",
        "Implement account lockout and rate limiting for login attempts",
    ],
    "A08": [
        "Verify integrity of all external data (signatures, checksums)",
        "Use safe deserialization libraries (avoid pickle, yaml.load)",
        "Implement CI/CD pipeline security (signed builds, artifact verification)",
        "Isolate and sandbox untrusted data processing",
    ],
    "A09": [
        "Implement centralized logging for all security events",
        "Use log injection prevention (sanitize log input)",
        "Ensure audit logs are tamper-proof (append-only, WORM storage)",
        "Deploy real-time alerting for suspicious activities",
    ],
    "A10": [
        "Implement allowlists for outbound URLs (network segmentation)",
        "Validate and sanitize all redirect/fetch parameters",
        "Disable unused URL schemes (file://, gopher://, dict://)",
        "Isolate application services from internal networks (DMZ)",
    ],
}

# 鈹€鈹€ OWASP 鏍囧噯寮曠敤 鈹€鈹€
OWASP_WEB_TOP10_REFERENCE = (
    "OWASP Top 10 (2025) 鈥?"
    "https://owasp.org/www-project-top-10/"
)
OWASP_LLM_TOP10_REFERENCE = (
    "OWASP Top 10 for LLM Applications (2025 Edition) 鈥?"
    "https://owasp.org/www-project-top-10-for-large-language-model-applications/"
)
OWASP_ASI_TOP10_REFERENCE = (
    "OWASP Agentic AI Top 10 鈥?"
    "https://owasp.org/www-project-agent-security/"
)

