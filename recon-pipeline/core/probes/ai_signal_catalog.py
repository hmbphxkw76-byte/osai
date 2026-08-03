# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""Central catalog of AI-related reconnaissance signals.

Single source of truth for all AI/LLM detection signals used across the
recon-pipeline probes, classifiers, and analyzers.

Signal dimensions (7 total):
  1. Port-level signals (AI_PORTS) — 30+ AI service port mappings
  2. HTTP response header signals (AI_HEADER_PATTERNS) — 20+ header regexes
  3. Page title signals (AI_TITLE_PATTERNS) — 30+ product title regexes
  4. Response body fingerprints (AI_BODY_FINGERPRINTS) — 30+ Wappalyzer-style body regexes
  5. Favicon hash signals (AI_FAVICON_HASHES) — 30+ mmh3 favicon hash mappings
  6. URL path signals (AI_PATH_PATTERNS) — 50+ endpoint path regexes
  7. Parameter name signals (AI_PARAM_NAMES) — 20+ prompt-injection parameter names

Additional sections:
  - RAG path signals (AI_RAG_PATH_PATTERNS) — 15+ RAG-specific paths with parent_ai gating
  - Active probe paths (AI_CHAT/MCP/OPENAPI_PROBE_PATHS)
  - Vector DB confirmation reads (AI_VECTOR_DB_READS)
  - Model family inference tokens (AI_MODEL_FAMILY_TOKENS)
  - Chat response shape classifiers (AI_CHAT_RESPONSE_SHAPES)
  - JS analysis signals (AI_SDK_IMPORT/AI_KEY_PREFIX/AI_KEY_CONSTRUCTOR/etc.)
  - AI port signals with disambiguation flags

Reference: RedAmon recon/helpers/ai_signal_catalog.py (1608 lines)
"""

from __future__ import annotations

import re
from typing import Any

# ============================================================================
# 1. PORT-LEVEL SIGNALS
# ============================================================================
# port -> {descriptor, disambiguate (bool: shared ports need corroborating signal)}
AI_PORTS: dict[int, dict[str, Any]] = {
    # AI runtimes
    11434: {"descriptor": "Ollama (default)", "category": "ai-runtime", "disambiguate": False},
    8000:  {"descriptor": "vLLM / TGI / LiteLLM / FastAPI (shared)", "category": "ai-runtime", "disambiguate": True},
    8080:  {"descriptor": "LM Studio / LocalAI / generic AI (shared)", "category": "ai-runtime", "disambiguate": True},
    1234:  {"descriptor": "LM Studio (default)", "category": "ai-runtime", "disambiguate": False},
    4891:  {"descriptor": "LocalAI (default)", "category": "ai-runtime", "disambiguate": False},
    5000:  {"descriptor": "Flask / FastAPI / generic (shared)", "category": "ai-runtime", "disambiguate": True},
    7860:  {"descriptor": "Gradio (shared)", "category": "ai-frontend", "disambiguate": True},
    8501:  {"descriptor": "Streamlit (shared)", "category": "ai-frontend", "disambiguate": True},
    8888:  {"descriptor": "Jupyter (shared)", "category": "mlops", "disambiguate": True},

    # Vector databases
    8001:  {"descriptor": "Chroma (default)", "category": "vector-db", "disambiguate": False},
    6333:  {"descriptor": "Qdrant gRPC", "category": "vector-db", "disambiguate": False},
    6334:  {"descriptor": "Qdrant REST", "category": "vector-db", "disambiguate": False},
    8086:  {"descriptor": "Weaviate (default)", "category": "vector-db", "disambiguate": False},
    19530: {"descriptor": "Milvus / Zilliz", "category": "vector-db", "disambiguate": False},
    6379:  {"descriptor": "Redis (shared)", "category": "vector-db", "disambiguate": True},
    5432:  {"descriptor": "PostgreSQL/pgvector (shared)", "category": "vector-db", "disambiguate": True},

    # AI proxies / gateways
    8787:  {"descriptor": "Portkey AI Gateway", "category": "ai-proxy", "disambiguate": False},
    4000:  {"descriptor": "LiteLLM Proxy (default)", "category": "ai-proxy", "disambiguate": False},

    # AI frontends
    3000:  {"descriptor": "Open WebUI / LibreChat (shared)", "category": "ai-frontend", "disambiguate": True},
    5173:  {"descriptor": "Vite dev (shared)", "category": "ai-frontend", "disambiguate": True},

    # MLOps
    8265:  {"descriptor": "Ray Dashboard", "category": "mlops", "disambiguate": False},
    8081:  {"descriptor": "MLflow (default)", "category": "mlops", "disambiguate": False},
    5001:  {"descriptor": "MLflow (alt)", "category": "mlops", "disambiguate": False},

    # MCP servers
    3100:  {"descriptor": "MCP Inspector (default)", "category": "mcp", "disambiguate": False},
}

# ============================================================================
# 2. HTTP RESPONSE HEADER SIGNALS
# ============================================================================
# (compiled_pattern, framework_name, category)
AI_HEADER_PATTERNS: list[tuple[re.Pattern[str], str, str]] = [
    # OpenAI ecosystem
    (re.compile(r"x-openai", re.IGNORECASE), "OpenAI", "llm"),
    (re.compile(r"openai-(?:beta|api-key|organization|version)", re.IGNORECASE), "OpenAI", "llm"),
    (re.compile(r"x-ratelimit-(?:requests|tokens)", re.IGNORECASE), "OpenAI RateLimit", "llm"),

    # Anthropic
    (re.compile(r"x-anthropic", re.IGNORECASE), "Anthropic", "llm"),
    (re.compile(r"anthropic-version", re.IGNORECASE), "Anthropic", "llm"),
    (re.compile(r"x-should-retry", re.IGNORECASE), "Anthropic", "llm"),

    # MCP
    (re.compile(r"x-mcp", re.IGNORECASE), "MCP", "mcp"),
    (re.compile(r"mcp-server", re.IGNORECASE), "MCP", "mcp"),
    (re.compile(r"mcp-session-id", re.IGNORECASE), "MCP", "mcp"),

    # vLLM / TGI / Inference runtimes
    (re.compile(r"x-vllm", re.IGNORECASE), "vLLM", "llm"),
    (re.compile(r"x-served-by", re.IGNORECASE), "TGI/vLLM", "llm"),
    (re.compile(r"x-tgi", re.IGNORECASE), "TGI (Text Generation Inference)", "llm"),

    # LiteLLM
    (re.compile(r"x-litellm", re.IGNORECASE), "LiteLLM", "llm"),
    (re.compile(r"litellm-call-id", re.IGNORECASE), "LiteLLM", "llm"),

    # LangChain / LangServe
    (re.compile(r"x-langchain", re.IGNORECASE), "LangChain", "llm"),
    (re.compile(r"x-langserve", re.IGNORECASE), "LangServe", "llm"),

    # Ollama
    (re.compile(r"x-ollama", re.IGNORECASE), "Ollama", "llm"),

    # Guardrails / Safety
    (re.compile(r"x-content-filter", re.IGNORECASE), "ContentFilter", "guardrail"),
    (re.compile(r"x-safety", re.IGNORECASE), "SafetyFilter", "guardrail"),
    (re.compile(r"amazon-q-", re.IGNORECASE), "Amazon Q", "guardrail"),

    # Cloud provider AI
    (re.compile(r"x-amzn-bedrock", re.IGNORECASE), "Amazon Bedrock", "llm"),
    (re.compile(r"x-azure-ai", re.IGNORECASE), "Azure AI", "llm"),
    (re.compile(r"x-vertex-ai", re.IGNORECASE), "Vertex AI", "llm"),
    (re.compile(r"x-goog-api", re.IGNORECASE), "Google Cloud AI", "llm"),

    # Server signatures
    (re.compile(r"uvicorn", re.IGNORECASE), "Uvicorn (Python AI server)", "infra"),
    (re.compile(r"gunicorn", re.IGNORECASE), "Gunicorn (Python AI server)", "infra"),
    (re.compile(r"hypercorn", re.IGNORECASE), "Hypercorn", "infra"),
]

# ============================================================================
# 3. PAGE TITLE SIGNALS
# ============================================================================
# (compiled_pattern, product_name)
AI_TITLE_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # OpenAI
    (re.compile(r"openai playground", re.IGNORECASE), "OpenAI Playground"),
    (re.compile(r"chatgpt", re.IGNORECASE), "ChatGPT"),
    (re.compile(r"openai api", re.IGNORECASE), "OpenAI API"),

    # Anthropic
    (re.compile(r"anthropic console", re.IGNORECASE), "Anthropic Console"),
    (re.compile(r"claude", re.IGNORECASE), "Claude Interface"),

    # Frontend UIs
    (re.compile(r"open webui", re.IGNORECASE), "Open WebUI"),
    (re.compile(r"librechat", re.IGNORECASE), "LibreChat"),
    (re.compile(r"big-agi", re.IGNORECASE), "Big-AGI"),
    (re.compile(r"lobechat", re.IGNORECASE), "LobeChat"),
    (re.compile(r"jan\s*ai", re.IGNORECASE), "Jan AI"),
    (re.compile(r"text-generation-webui", re.IGNORECASE), "Oobabooga TextGen"),
    (re.compile(r"sillytavern", re.IGNORECASE), "SillyTavern"),
    (re.compile(r"langflow", re.IGNORECASE), "Langflow"),
    (re.compile(r"flowise", re.IGNORECASE), "Flowise"),
    (re.compile(r"dify", re.IGNORECASE), "Dify"),

    # MCP
    (re.compile(r"mcp\s*(?:inspector|server|dashboard)", re.IGNORECASE), "MCP Server"),

    # Vector DBs
    (re.compile(r"weaviate", re.IGNORECASE), "Weaviate"),
    (re.compile(r"qdrant", re.IGNORECASE), "Qdrant"),
    (re.compile(r"chroma", re.IGNORECASE), "ChromaDB"),
    (re.compile(r"milvus|zilliz", re.IGNORECASE), "Milvus/Zilliz"),
    (re.compile(r"pinecone", re.IGNORECASE), "Pinecone"),

    # MLOps
    (re.compile(r"mlflow", re.IGNORECASE), "MLflow"),
    (re.compile(r"ray dashboard", re.IGNORECASE), "Ray Dashboard"),
    (re.compile(r"wandb", re.IGNORECASE), "Weights & Biases"),

    # Inference servers
    (re.compile(r"ollama", re.IGNORECASE), "Ollama"),
    (re.compile(r"vllm", re.IGNORECASE), "vLLM"),
    (re.compile(r"lm studio", re.IGNORECASE), "LM Studio"),
    (re.compile(r"localai", re.IGNORECASE), "LocalAI"),
    (re.compile(r"gradio", re.IGNORECASE), "Gradio App"),
    (re.compile(r"streamlit", re.IGNORECASE), "Streamlit App"),
    (re.compile(r"litellm", re.IGNORECASE), "LiteLLM"),
]

# ============================================================================
# 4. RESPONSE BODY FINGERPRINTS (Wappalyzer-style)
# ============================================================================
# (compiled_pattern, framework_name, category)
# Categories: runtime / framework / frontend / vector-db / sdk-client / mlops
AI_BODY_FINGERPRINTS: list[tuple[re.Pattern[str], str, str]] = [
    # OpenAI ecosystem
    (re.compile(r'"object"\s*:\s*"chat\.completion', re.IGNORECASE), "OpenAI Chat API", "runtime"),
    (re.compile(r'"object"\s*:\s*"text_completion', re.IGNORECASE), "OpenAI Completion API", "runtime"),
    (re.compile(r'"object"\s*:\s*"list"\s*,\s*"data"\s*:\s*\[\s*\{\s*"id"\s*:\s*"model', re.IGNORECASE), "OpenAI Models API", "runtime"),

    # Anthropic
    (re.compile(r'"type"\s*:\s*"message"\s*,\s*"role"\s*:\s*"assistant"', re.IGNORECASE), "Anthropic Messages API", "runtime"),
    (re.compile(r'"stop_reason"\s*:\s*"end_turn"', re.IGNORECASE), "Anthropic Messages API", "runtime"),

    # Ollama
    (re.compile(r'"done_reason"\s*:', re.IGNORECASE), "Ollama API", "runtime"),
    (re.compile(r'"total_duration"\s*:', re.IGNORECASE), "Ollama API", "runtime"),
    (re.compile(r'"eval_count"\s*:', re.IGNORECASE), "Ollama API", "runtime"),

    # vLLM
    (re.compile(r'vllm_version|"vllm"', re.IGNORECASE), "vLLM", "runtime"),

    # TGI
    (re.compile(r'"generated_text"\s*:', re.IGNORECASE), "TGI/HuggingFace", "runtime"),
    (re.compile(r'"details"\s*:\s*\{\s*"finish_reason"', re.IGNORECASE), "TGI/HuggingFace", "runtime"),

    # Gemini
    (re.compile(r'"candidates"\s*:\s*\[\s*\{\s*"content"', re.IGNORECASE), "Gemini API", "runtime"),
    (re.compile(r'"safetyRatings"\s*:', re.IGNORECASE), "Gemini Safety", "runtime"),

    # MCP
    (re.compile(r'"jsonrpc"\s*:\s*"2\.0"\s*,\s*"method"\s*:\s*"tools/list"', re.IGNORECASE), "MCP Tools", "mcp"),
    (re.compile(r'"jsonrpc"\s*:\s*"2\.0"\s*,\s*"result"\s*:\s*\{\s*"capabilities"', re.IGNORECASE), "MCP Initialize", "mcp"),
    (re.compile(r'"serverInfo"\s*:\s*\{\s*"name"', re.IGNORECASE), "MCP ServerInfo", "mcp"),

    # Vector DBs
    (re.compile(r'"collection_name"\s*:', re.IGNORECASE), "Vector DB", "vector-db"),
    (re.compile(r'"hnsw:space"\s*:', re.IGNORECASE), "ChromaDB", "vector-db"),
    (re.compile(r'"embedding_function"\s*:', re.IGNORECASE), "ChromaDB", "vector-db"),
    (re.compile(r'"payload"\s*:\s*\{', re.IGNORECASE), "Qdrant", "vector-db"),
    (re.compile(r'"deprecation_length"', re.IGNORECASE), "Weaviate", "vector-db"),
    (re.compile(r'"class_name"\s*:', re.IGNORECASE), "Weaviate", "vector-db"),
    (re.compile(r'"metric_type"\s*:', re.IGNORECASE), "Milvus", "vector-db"),
    (re.compile(r'"index_type"\s*:', re.IGNORECASE), "Milvus", "vector-db"),

    # Frontend frameworks
    (re.compile(r'__NEXT_DATA__|"next"', re.IGNORECASE), "Next.js", "frontend"),
    (re.compile(r'langflow-chat|langflow-ui', re.IGNORECASE), "Langflow", "frontend"),
    (re.compile(r'flowise-chat', re.IGNORECASE), "Flowise", "frontend"),
    (re.compile(r'dify-chat', re.IGNORECASE), "Dify", "frontend"),
    (re.compile(r'open-webui|openWebUI', re.IGNORECASE), "Open WebUI", "frontend"),
    (re.compile(r'librechat|LibreChat', re.IGNORECASE), "LibreChat", "frontend"),
    (re.compile(r'gradio-app|gradio\.Interface', re.IGNORECASE), "Gradio", "frontend"),

    # MLOps
    (re.compile(r'mlflow\.tracking|mlflow\.ui', re.IGNORECASE), "MLflow", "mlops"),
    (re.compile(r'wandb\.init|wandb\.log', re.IGNORECASE), "W&B", "mlops"),

    # SDK / embedding
    (re.compile(r'"object"\s*:\s*"list"\s*,\s*"data"\s*:\s*\[\s*\{\s*"embedding"', re.IGNORECASE), "OpenAI Embedding API", "runtime"),
    (re.compile(r'"object"\s*:\s*"embedding"', re.IGNORECASE), "Embedding API", "runtime"),
]

# ============================================================================
# 5. FAVICON HASH SIGNALS (mmh3 hash -> product name)
# ============================================================================
AI_FAVICON_HASHES: dict[int, str] = {
    # OpenAI / Anthropic
    -1492966340: "OpenAI",
    1398814350: "ChatGPT",
    -464644941:  "Anthropic Console",

    # Frontend UIs
    -725189994:  "Open WebUI",
    -1914266707: "LibreChat",
    1211608049:  "Langflow",
    -50378694:   "Flowise",
    64320601:    "Dify",
    1389876985:  "Big-AGI",
    -1588101580: "LobeChat",
    886108524:   "SillyTavern",

    # Vector DBs
    165346085:   "Weaviate",
    -1648043876: "ChromaDB",
    -889383230:  "Qdrant",
    -1065181028: "Pinecone",

    # MLOps
    -1086120832: "MLflow",
    -198088717:  "Ray Dashboard",
    -1305696462: "Gradio",
    -410773217:  "Streamlit",

    # Inference
    -873647664:  "Ollama",
    -2009721100: "vLLM",
    571695511:   "LiteLLM",
    -762204455:  "LM Studio",
    -1404160881: "LocalAI",

    # Cloud AI
    -358938098:  "Amazon Bedrock",
    163555255:   "Azure AI Studio",
    -1358621508: "Vertex AI",

    # Others
    -1698869754: "Jupyter",
    -1379054890: "n8n (AI automation)",
    -1914668250: "ComfyUI",
    -1484817830: "Hugging Face Spaces",
}

# ============================================================================
# 6. URL PATH SIGNALS
# ============================================================================
# (compiled_pattern, interface_type)
# Interface types: llm-chat / llm-completion / llm-embedding / llm-tool-call /
#   sse-stream / mcp / llm-graphql / rag / agent-tool / upload / auth / vector-db
AI_PATH_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # ── LLM Chat ──
    (re.compile(r"/v1/chat/completions", re.IGNORECASE), "llm-chat"),
    (re.compile(r"/v1/responses", re.IGNORECASE), "llm-chat"),
    (re.compile(r"/v1/messages", re.IGNORECASE), "llm-chat"),  # Anthropic
    (re.compile(r"/v1beta/models/.*:generateContent", re.IGNORECASE), "llm-chat"),  # Gemini
    (re.compile(r"/api/chat", re.IGNORECASE), "llm-chat"),
    (re.compile(r"/api/chat/completions", re.IGNORECASE), "llm-chat"),  # DeepSeek
    (re.compile(r"/chat/completions", re.IGNORECASE), "llm-chat"),
    (re.compile(r"/v2/chat", re.IGNORECASE), "llm-chat"),  # Cohere

    # ── LLM Completion ──
    (re.compile(r"/v1/completions", re.IGNORECASE), "llm-completion"),
    (re.compile(r"/v1/fim/completions", re.IGNORECASE), "llm-completion"),  # Mistral FIM
    (re.compile(r"/api/generate", re.IGNORECASE), "llm-completion"),  # Ollama
    (re.compile(r"/api/completion", re.IGNORECASE), "llm-completion"),
    (re.compile(r"/api/inference", re.IGNORECASE), "llm-completion"),
    (re.compile(r"/invocations", re.IGNORECASE), "llm-completion"),  # TGI SageMaker

    # ── LLM Embedding ──
    (re.compile(r"/v1/embeddings", re.IGNORECASE), "llm-embedding"),
    (re.compile(r"/api/embed", re.IGNORECASE), "llm-embedding"),
    (re.compile(r"/api/embedding", re.IGNORECASE), "llm-embedding"),

    # ── SSE / Streaming ──
    (re.compile(r"/generate_stream", re.IGNORECASE), "sse-stream"),
    (re.compile(r"/stream_log", re.IGNORECASE), "sse-stream"),
    (re.compile(r"/astream_events", re.IGNORECASE), "sse-stream"),
    (re.compile(r"/api/stream", re.IGNORECASE), "sse-stream"),
    (re.compile(r"/sse", re.IGNORECASE), "sse-stream"),

    # ── MCP ──
    (re.compile(r"/mcp/message", re.IGNORECASE), "mcp"),
    (re.compile(r"/mcp/sse", re.IGNORECASE), "mcp"),
    (re.compile(r"/mcp/stream", re.IGNORECASE), "mcp"),
    (re.compile(r"/mcp-server", re.IGNORECASE), "mcp"),
    (re.compile(r"/mcp(?:/|$)", re.IGNORECASE), "mcp"),
    (re.compile(r"/jsonrpc", re.IGNORECASE), "mcp"),
    (re.compile(r"/\.well-known/mcp", re.IGNORECASE), "mcp"),

    # ── Agent Tool ──
    (re.compile(r"/api/tools?", re.IGNORECASE), "agent-tool"),
    (re.compile(r"/api/functions?", re.IGNORECASE), "agent-tool"),
    (re.compile(r"/api/actions?", re.IGNORECASE), "agent-tool"),
    (re.compile(r"/api/execute", re.IGNORECASE), "agent-tool"),
    (re.compile(r"/api/invoke", re.IGNORECASE), "agent-tool"),
    (re.compile(r"/(?:assistant|copilot|agent)/", re.IGNORECASE), "agent-tool"),
    (re.compile(r"/(?:fetch|browse|navigate)", re.IGNORECASE), "agent-tool"),

    # ── RAG ──
    (re.compile(r"/api/(?:search|retrieve|query)", re.IGNORECASE), "rag"),
    (re.compile(r"/rag/search", re.IGNORECASE), "rag"),
    (re.compile(r"/retrieval/query", re.IGNORECASE), "rag"),
    (re.compile(r"/api/(?:rag|retrieval|knowledge)", re.IGNORECASE), "rag"),
    (re.compile(r"/v1/vector_stores/", re.IGNORECASE), "rag"),
    (re.compile(r"/vectors/upsert", re.IGNORECASE), "rag"),
    (re.compile(r"/collections/.*/points", re.IGNORECASE), "rag"),

    # ── Upload ──
    (re.compile(r"/api/(?:upload|files?|attachment)", re.IGNORECASE), "upload"),
    (re.compile(r"/(?:upload|files?|media|attachments)/", re.IGNORECASE), "upload"),

    # ── Auth ──
    (re.compile(r"/oauth", re.IGNORECASE), "auth"),
    (re.compile(r"/(?:token|auth|login|signin|sso|authorize|callback)", re.IGNORECASE), "auth"),

    # ── Vector DB ──
    (re.compile(r"/api/(?:vector|index|collection)", re.IGNORECASE), "vector-db"),
    (re.compile(r"/v1/(?:objects|schema|graphql|batch)", re.IGNORECASE), "vector-db"),  # Weaviate
    (re.compile(r"/api/v1/(?:collections|heartbeat)", re.IGNORECASE), "vector-db"),  # Chroma
    (re.compile(r"/collections/\w+/(?:points|search)", re.IGNORECASE), "vector-db"),  # Qdrant
    (re.compile(r"/v2/(?:vector|collection|partition)", re.IGNORECASE), "vector-db"),  # Milvus

    # ── LLM GraphQL ──
    (re.compile(r"/graphql", re.IGNORECASE), "llm-graphql"),
]

# ============================================================================
# 7. RAG PATH SIGNALS (with parent_ai gating)
# ============================================================================
# (compiled_pattern, requires_parent_ai)
# requires_parent_ai=True means this path is ambiguous (e.g. /search, /upload)
# and needs a parent AI signal to confirm it's AI-related.
AI_RAG_PATH_PATTERNS: list[tuple[re.Pattern[str], bool]] = [
    # Explicit RAG paths (no parent_ai gating needed)
    (re.compile(r"/rag", re.IGNORECASE), False),
    (re.compile(r"/retrieval", re.IGNORECASE), False),
    (re.compile(r"/knowledge", re.IGNORECASE), False),
    (re.compile(r"/vector", re.IGNORECASE), False),
    (re.compile(r"/embedding", re.IGNORECASE), False),

    # Ambiguous paths (need parent_ai gating)
    (re.compile(r"/search", re.IGNORECASE), True),
    (re.compile(r"/query", re.IGNORECASE), True),
    (re.compile(r"/upload", re.IGNORECASE), True),
    (re.compile(r"/retrieve", re.IGNORECASE), True),
    (re.compile(r"/index", re.IGNORECASE), True),
    (re.compile(r"/documents", re.IGNORECASE), True),
    (re.compile(r"/ingest", re.IGNORECASE), True),
    (re.compile(r"/import", re.IGNORECASE), True),
]

# ============================================================================
# 8. PARAMETER NAME SIGNALS
# ============================================================================
AI_PARAM_NAMES: set[str] = {
    "messages",
    "prompt",
    "system",
    "system_prompt",
    "input",
    "tools",
    "tool_choice",
    "arguments",
    "query",
    "text",
    "content",
    "user_content",
    "assistant_content",
    "instructions",
    "context",
    "chat_history",
    "conversation",
    "max_tokens",
    "temperature",
    "top_p",
    "stop",
}

# ============================================================================
# 9. ACTIVE PROBE PATHS
# ============================================================================
AI_CHAT_PROBE_PATHS: list[str] = [
    "/v1/chat/completions",
    "/v1/responses",
    "/api/chat",
    "/api/chat/completions",
    "/api/completion",
    "/api/generate",
    "/api/inference",
    "/v1/messages",
    "/v2/chat",
    "/chat/completions",
    "/chat",
    "/completions",
    "/generate",
    "/inference",
    "/predict",
    "/ask",
    "/query",
]

AI_MCP_PROBE_PATHS: list[str] = [
    "/mcp",
    "/mcp/message",
    "/mcp/sse",
    "/mcp/stream",
    "/jsonrpc",
    "/.well-known/mcp",
    "/mcp-server",
]

AI_OPENAPI_DISCOVERY_PATHS: list[str] = [
    "/openapi.json",
    "/swagger.json",
    "/swagger/v1/swagger.json",
    "/api/openapi.json",
    "/docs",
    "/openapi.yaml",
    "/swagger.yaml",
    "/api-docs",
]

# ============================================================================
# 10. VECTOR DB CONFIRMATION READS
# ============================================================================
# {tech_name: [(path, expected_substring), ...]}
AI_VECTOR_DB_READS: dict[str, list[tuple[str, str]]] = {
    "pinecone": [
        ("/vectors", "vector_count"),
        ("/namespaces", "namespace"),
        ("/index/describe", "dimension"),
    ],
    "weaviate": [
        ("/v1/objects", "class_name"),
        ("/v1/schema", "class_name"),
        ("/v1/meta", "modules"),
    ],
    "chroma": [
        ("/api/v1/collections", "collection_name"),
        ("/api/v2/heartbeat", "heartbeat"),
    ],
    "qdrant": [
        ("/collections", "collection_name"),
        ("/points", "payload"),
        ("/collections/", "result"),
    ],
    "milvus": [
        ("/v1/vector/collections", "200"),
        ("/v2/vectordb/collections/list", "collection_name"),
    ],
}

# ============================================================================
# 11. MODEL FAMILY INFERENCE TOKENS
# ============================================================================
AI_MODEL_FAMILY_TOKENS: list[str] = [
    "gpt-4o",
    "gpt-4",
    "gpt-3.5",
    "o1-",
    "o3-",
    "claude",
    "gemini",
    "llama",
    "mistral",
    "mixtral",
    "deepseek",
    "qwen",
    "yi-",
    "phi-",
    "command",
    "dbrx",
    "falcon",
    "cohere",
    "jamba",
    "reka",
]

# ============================================================================
# 12. CHAT RESPONSE SHAPE CLASSIFIERS
# ============================================================================
# (json_key, shape_name)
# Ordered by specificity — first match wins.
AI_CHAT_RESPONSE_SHAPES: list[tuple[str, str]] = [
    ("choices", "openai-chat"),          # {"choices": [{"message": {"content": "..."}}]}
    ("content", "anthropic-chat"),        # {"content": [{"text": "..."}]}
    ("candidates", "gemini-chat"),        # {"candidates": [{"content": {"parts": [...]}}]}
    ("response", "ollama-chat"),          # {"response": "...", "done": true}
    ("generated_text", "huggingface"),    # {"generated_text": "..."}
    ("message", "generic-chat"),          # {"message": {"content": "..."}}
    ("output", "generic-chat"),           # {"output": "..."}
]

# ============================================================================
# 13. JS ANALYSIS SIGNALS
# ============================================================================

# SDK import patterns (npm package names found in JS bundles)
AI_SDK_IMPORT_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r'"openai"|require\(["\']openai["\']\)|from\s+["\']openai["\']', re.IGNORECASE), "openai"),
    (re.compile(r'"@anthropic-ai/sdk"|require\(["\']@anthropic-ai/sdk["\']\)|from\s+["\']@anthropic-ai/sdk["\']', re.IGNORECASE), "anthropic-sdk"),
    (re.compile(r'"@google/generative-ai"|require\(["\']@google/generative-ai["\']\)', re.IGNORECASE), "google-generative-ai"),
    (re.compile(r'"@aws-sdk/client-bedrock-runtime"|require\(["\']@aws-sdk/client-bedrock-runtime["\']\)', re.IGNORECASE), "aws-bedrock-sdk"),
    (re.compile(r'"@azure/openai"|require\(["\']@azure/openai["\']\)', re.IGNORECASE), "azure-openai-sdk"),
    (re.compile(r'"langchain"|require\(["\']langchain["\']\)|from\s+["\']langchain["\']', re.IGNORECASE), "langchain"),
    (re.compile(r'"@langchain/"|require\(["\']@langchain/', re.IGNORECASE), "langchain-package"),
    (re.compile(r'"llamaindex"|require\(["\']llamaindex["\']\)|from\s+["\']llama-index["\']', re.IGNORECASE), "llamaindex"),
    (re.compile(r'"ollama"|require\(["\']ollama["\']\)|from\s+["\']ollama["\']', re.IGNORECASE), "ollama-js"),
    (re.compile(r'"@modelcontextprotocol/sdk"|require\(["\']@modelcontextprotocol/', re.IGNORECASE), "mcp-sdk"),
    (re.compile(r'"@pinecone-database/pinecone"|require\(["\']@pinecone-database/', re.IGNORECASE), "pinecone-sdk"),
    (re.compile(r'"chromadb"|require\(["\']chromadb["\']\)', re.IGNORECASE), "chromadb-js"),
    (re.compile(r'"weaviate-client"|require\(["\']weaviate-client["\']\)', re.IGNORECASE), "weaviate-js"),
    (re.compile(r'"@qdrant/js-client-rest"|require\(["\']@qdrant/', re.IGNORECASE), "qdrant-js"),
    (re.compile(r'"@zilliz/milvus2-sdk-node"|require\(["\']@zilliz/', re.IGNORECASE), "milvus-js"),
    (re.compile(r'"@xenova/transformers"|require\(["\']@xenova/transformers["\']\)', re.IGNORECASE), "transformers-js"),
    (re.compile(r'"@huggingface/inference"|require\(["\']@huggingface/inference["\']\)', re.IGNORECASE), "huggingface-js"),
    (re.compile(r'"cohere-ai"|require\(["\']cohere-ai["\']\)', re.IGNORECASE), "cohere-sdk"),
    (re.compile(r'"@mistralai/mistralai"|require\(["\']@mistralai/mistralai["\']\)', re.IGNORECASE), "mistral-sdk"),
    (re.compile(r'"@deepseek/chat"|require\(["\']@deepseek/chat["\']\)', re.IGNORECASE), "deepseek-sdk"),
    (re.compile(r'"groq-sdk"|require\(["\']groq-sdk["\']\)', re.IGNORECASE), "groq-sdk"),
    (re.compile(r'"@together-ai/openai"|require\(["\']@together-ai/', re.IGNORECASE), "together-ai-sdk"),
    (re.compile(r'"@fireworks-ai/sdk"|require\(["\']@fireworks-ai/', re.IGNORECASE), "fireworks-sdk"),
    (re.compile(r'"replicate"|require\(["\']replicate["\']\)', re.IGNORECASE), "replicate-sdk"),
    (re.compile(r'"openai-edge"|require\(["\']openai-edge["\']\)', re.IGNORECASE), "openai-edge"),
    (re.compile(r'"ai"|require\(["\']ai["\']\)|from\s+["\']ai["\']', re.IGNORECASE), "vercel-ai-sdk"),
    (re.compile(r'"@vercel/ai"|require\(["\']@vercel/ai["\']\)', re.IGNORECASE), "vercel-ai-sdk"),
    (re.compile(r'"@ai-sdk/"|require\(["\']@ai-sdk/', re.IGNORECASE), "ai-sdk"),
]

# API Key prefix patterns (for detecting hardcoded keys in JS)
AI_KEY_PREFIX_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r'sk-[A-Za-z0-9]{32,}', re.IGNORECASE), "OpenAI API Key"),
    (re.compile(r'sk-ant-[A-Za-z0-9]{32,}', re.IGNORECASE), "Anthropic API Key"),
    (re.compile(r'sk-proj-[A-Za-z0-9]{32,}', re.IGNORECASE), "OpenAI Project Key"),
    (re.compile(r'sk-org-[A-Za-z0-9]{32,}', re.IGNORECASE), "OpenAI Org Key"),
    (re.compile(r'AIza[0-9A-Za-z\-_]{35}', re.IGNORECASE), "Google API Key"),
    (re.compile(r'xai-[A-Za-z0-9]{32,}', re.IGNORECASE), "xAI API Key"),
    (re.compile(r'hf_[A-Za-z0-9]{32,}', re.IGNORECASE), "HuggingFace API Key"),
    (re.compile(r'cohere-[A-Za-z0-9]{32,}', re.IGNORECASE), "Cohere API Key"),
    (re.compile(r'mistral-[A-Za-z0-9]{32,}', re.IGNORECASE), "Mistral API Key"),
    (re.compile(r'gsk_[A-Za-z0-9]{32,}', re.IGNORECASE), "Groq API Key"),
    (re.compile(r'together-[A-Za-z0-9]{32,}', re.IGNORECASE), "Together AI Key"),
    (re.compile(r'r8_[A-Za-z0-9]{32,}', re.IGNORECASE), "Replicate API Key"),
    (re.compile(r'pcsk_[A-Za-z0-9]{32,}', re.IGNORECASE), "Pinecone API Key"),
    (re.compile(r'pci_[A-Za-z0-9]{32,}', re.IGNORECASE), "Pinecone Index Key"),
    (re.compile(r'qdrant-[A-Za-z0-9]{32,}', re.IGNORECASE), "Qdrant API Key"),
    (re.compile(r'weaviate-[A-Za-z0-9]{32,}', re.IGNORECASE), "Weaviate API Key"),
    (re.compile(r'chrm_[A-Za-z0-9]{32,}', re.IGNORECASE), "Chroma API Key"),
    (re.compile(r'zil-[A-Za-z0-9]{32,}', re.IGNORECASE), "Zilliz API Key"),
    (re.compile(r'milvus-[A-Za-z0-9]{32,}', re.IGNORECASE), "Milvus API Key"),
    (re.compile(r'eyJ[A-Za-z0-9\-_]{20,}\.[A-Za-z0-9\-_]{20,}\.[A-Za-z0-9\-_]{20,}', re.IGNORECASE), "JWT Token"),
    (re.compile(r'Bearer\s+[A-Za-z0-9\-_]{20,}', re.IGNORECASE), "Bearer Token"),
    (re.compile(r'ghp_[A-Za-z0-9]{36}', re.IGNORECASE), "GitHub Personal Access Token"),
    (re.compile(r'gho_[A-Za-z0-9]{36}', re.IGNORECASE), "GitHub OAuth Token"),
    (re.compile(r'github_pat_[A-Za-z0-9]{36,}', re.IGNORECASE), "GitHub Fine-grained PAT"),
]

# Constructor context patterns (SDK class name + apiKey parameter)
AI_KEY_CONSTRUCTOR_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r'new\s+OpenAI\s*\(\s*\{\s*apiKey\s*:', re.IGNORECASE), "OpenAI SDK constructor"),
    (re.compile(r'new\s+Anthropic\s*\(\s*\{\s*apiKey\s*:', re.IGNORECASE), "Anthropic SDK constructor"),
    (re.compile(r'new\s+GoogleGenerativeAI\s*\(\s*["\']', re.IGNORECASE), "Google AI constructor"),
    (re.compile(r'new\s+AzureOpenAI\s*\(\s*\{', re.IGNORECASE), "Azure OpenAI constructor"),
    (re.compile(r'new\s+BedrockRuntimeClient\s*\(', re.IGNORECASE), "AWS Bedrock constructor"),
    (re.compile(r'new\s+ChatOpenAI\s*\(\s*\{', re.IGNORECASE), "LangChain OpenAI constructor"),
    (re.compile(r'new\s+ChatAnthropic\s*\(\s*\{', re.IGNORECASE), "LangChain Anthropic constructor"),
    (re.compile(r'new\s+CohereClient\s*\(\s*\{', re.IGNORECASE), "Cohere SDK constructor"),
    (re.compile(r'new\s+Mistral\s*\(\s*\{', re.IGNORECASE), "Mistral SDK constructor"),
    (re.compile(r'new\s+Groq\s*\(\s*\{', re.IGNORECASE), "Groq SDK constructor"),
    (re.compile(r'new\s+Together\s*\(\s*\{', re.IGNORECASE), "Together AI constructor"),
    (re.compile(r'new\s+Pinecone\s*\(\s*\{', re.IGNORECASE), "Pinecone SDK constructor"),
    (re.compile(r'new\s+ChromaClient\s*\(\s*\{', re.IGNORECASE), "ChromaDB constructor"),
    (re.compile(r'new\s+WeaviateClient\s*\(\s*\{', re.IGNORECASE), "Weaviate constructor"),
    (re.compile(r'new\s+QdrantClient\s*\(\s*\{', re.IGNORECASE), "Qdrant constructor"),
]

# Browser mode flags (dangerouslyAllowBrowser patterns)
AI_BROWSER_FLAG_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r'dangerouslyAllowBrowser\s*:\s*true', re.IGNORECASE), "OpenAI browser mode"),
    (re.compile(r'dangerouslyAllowBrowser\s*:\s*!0', re.IGNORECASE), "OpenAI browser mode (minified)"),
    (re.compile(r'allowBrowser\s*:\s*true', re.IGNORECASE), "SDK browser mode"),
]

# Frontend JS product markers
AI_FRONTEND_JS_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r'open[\-]?webui', re.IGNORECASE), "Open WebUI"),
    (re.compile(r'librechat', re.IGNORECASE), "LibreChat"),
    (re.compile(r'langflow', re.IGNORECASE), "Langflow"),
    (re.compile(r'flowise', re.IGNORECASE), "Flowise"),
    (re.compile(r'dify', re.IGNORECASE), "Dify"),
    (re.compile(r'big-agi', re.IGNORECASE), "Big-AGI"),
    (re.compile(r'lobechat', re.IGNORECASE), "LobeChat"),
    (re.compile(r'jan-ai', re.IGNORECASE), "Jan AI"),
    (re.compile(r'text-generation-webui', re.IGNORECASE), "Oobabooga TextGen"),
    (re.compile(r'sillytavern', re.IGNORECASE), "SillyTavern"),
    (re.compile(r'gradio', re.IGNORECASE), "Gradio"),
    (re.compile(r'streamlit', re.IGNORECASE), "Streamlit"),
    (re.compile(r'copilotkit', re.IGNORECASE), "CopilotKit"),
    (re.compile(r'v0\.dev', re.IGNORECASE), "Vercel v0"),
]

# Provider base URL patterns
AI_PROVIDER_URL_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r'https?://api\.openai\.com', re.IGNORECASE), "OpenAI API"),
    (re.compile(r'https?://api\.anthropic\.com', re.IGNORECASE), "Anthropic API"),
    (re.compile(r'https?://generativelanguage\.googleapis\.com', re.IGNORECASE), "Google Generative AI"),
    (re.compile(r'https?://[^.]+\.openai\.azure\.com', re.IGNORECASE), "Azure OpenAI"),
    (re.compile(r'https?://bedrock-runtime\.[^.]+\.amazonaws\.com', re.IGNORECASE), "AWS Bedrock"),
    (re.compile(r'https?://api\.cohere\.(?:ai|com)', re.IGNORECASE), "Cohere API"),
    (re.compile(r'https?://api\.mistral\.ai', re.IGNORECASE), "Mistral API"),
    (re.compile(r'https?://api\.groq\.com', re.IGNORECASE), "Groq API"),
    (re.compile(r'https?://api\.together\.xyz', re.IGNORECASE), "Together AI"),
    (re.compile(r'https?://api\.fireworks\.ai', re.IGNORECASE), "Fireworks AI"),
    (re.compile(r'https?://api\.deepseek\.com', re.IGNORECASE), "DeepSeek API"),
    (re.compile(r'https?://api\.replicate\.com', re.IGNORECASE), "Replicate API"),
    (re.compile(r'https?://[^.]+\.pinecone\.io', re.IGNORECASE), "Pinecone"),
    (re.compile(r'https?://[^.]+\.weaviate\.cloud', re.IGNORECASE), "Weaviate Cloud"),
    (re.compile(r'https?://[^.]+\.qdrant\.(?:io|tech|cloud)', re.IGNORECASE), "Qdrant"),
    (re.compile(r'https?://api\.zilliz\.com', re.IGNORECASE), "Zilliz Cloud"),
    (re.compile(r'localhost:\d+', re.IGNORECASE), "Localhost (self-hosted)"),
]

# ============================================================================
# 14. HELPER FUNCTIONS
# ============================================================================


def lookup_ai_port(port: int) -> dict[str, Any] | None:
    """Look up an AI port descriptor.

    Returns:
        Dict with 'descriptor', 'category', 'disambiguate' keys, or None.
    """
    return AI_PORTS.get(port)


def match_ai_header(name: str) -> tuple[str, str] | None:
    """Match a response header name against AI header patterns.

    Returns:
        (framework_name, category) tuple or None.
    """
    for pattern, framework, category in AI_HEADER_PATTERNS:
        if pattern.search(name):
            return framework, category
    return None


def match_ai_title(title: str) -> str | None:
    """Match a page title against AI product title patterns.

    Returns:
        Product name string or None.
    """
    for pattern, product in AI_TITLE_PATTERNS:
        if pattern.search(title):
            return product
    return None


def match_ai_body_fingerprint(body: str) -> tuple[str, str] | None:
    """Match response body content against AI body fingerprints.

    Returns:
        (framework_name, category) tuple or None.
    """
    for pattern, framework, category in AI_BODY_FINGERPRINTS:
        if pattern.search(body):
            return framework, category
    return None


def match_ai_path(path: str) -> str | None:
    """Match a URL path against AI path patterns.

    Returns:
        Interface type string (e.g. 'llm-chat', 'mcp', 'rag') or None.
    """
    for pattern, interface_type in AI_PATH_PATTERNS:
        if pattern.search(path):
            return interface_type
    return None


def is_ai_rag_path(path: str, parent_is_ai: bool = False) -> bool:
    """Check if a path is a RAG-related path.

    Args:
        path: URL path to check.
        parent_is_ai: Whether the parent page has been confirmed as AI-related.
            Required for ambiguous paths like /search, /upload.

    Returns:
        True if path is a RAG path.
    """
    for pattern, requires_parent_ai in AI_RAG_PATH_PATTERNS:
        if pattern.search(path):
            if requires_parent_ai and not parent_is_ai:
                return False
            return True
    return False


def is_ai_prompt_param(name: str) -> bool:
    """Check if a parameter name is an AI prompt injection parameter."""
    return name.lower() in AI_PARAM_NAMES


def match_ai_sdk(js_content: str) -> list[tuple[str, str]]:
    """Match JS content against AI SDK import patterns.

    Returns:
        List of (sdk_name, matched_text) tuples.
    """
    results: list[tuple[str, str]] = []
    for pattern, sdk_name in AI_SDK_IMPORT_PATTERNS:
        match = pattern.search(js_content)
        if match:
            results.append((sdk_name, match.group(0)))
    return results


def match_ai_key_prefix(js_content: str) -> list[tuple[str, str]]:
    """Match JS content against AI API key prefix patterns.

    Returns:
        List of (key_type, matched_key) tuples.
    """
    results: list[tuple[str, str]] = []
    for pattern, key_type in AI_KEY_PREFIX_PATTERNS:
        match = pattern.search(js_content)
        if match:
            results.append((key_type, match.group(0)))
    return results


def match_ai_key_constructor(js_content: str) -> list[tuple[str, str]]:
    """Match JS content against AI SDK constructor patterns.

    Returns:
        List of (constructor_name, matched_text) tuples.
    """
    results: list[tuple[str, str]] = []
    for pattern, constructor_name in AI_KEY_CONSTRUCTOR_PATTERNS:
        match = pattern.search(js_content)
        if match:
            results.append((constructor_name, match.group(0)))
    return results


def match_ai_browser_flag(js_content: str) -> list[tuple[str, str]]:
    """Match JS content against browser mode flag patterns.

    Returns:
        List of (flag_type, matched_text) tuples.
    """
    results: list[tuple[str, str]] = []
    for pattern, flag_type in AI_BROWSER_FLAG_PATTERNS:
        match = pattern.search(js_content)
        if match:
            results.append((flag_type, match.group(0)))
    return results


def match_ai_frontend_js(js_content: str) -> list[tuple[str, str]]:
    """Match JS content against frontend product markers.

    Returns:
        List of (product_name, matched_text) tuples.
    """
    results: list[tuple[str, str]] = []
    for pattern, product in AI_FRONTEND_JS_PATTERNS:
        match = pattern.search(js_content)
        if match:
            results.append((product, match.group(0)))
    return results


def match_ai_provider_url(js_content: str) -> list[tuple[str, str]]:
    """Match JS content against AI provider base URL patterns.

    Returns:
        List of (provider_name, matched_url) tuples.
    """
    results: list[tuple[str, str]] = []
    for pattern, provider in AI_PROVIDER_URL_PATTERNS:
        match = pattern.search(js_content)
        if match:
            results.append((provider, match.group(0)))
    return results


def classify_ai_chat_response(payload: Any) -> str | None:
    """Classify an AI chat API response body by its JSON shape.

    Args:
        payload: Parsed JSON response (dict).

    Returns:
        Shape name (e.g. 'openai-chat', 'anthropic-chat') or None.
    """
    if not isinstance(payload, dict):
        return None
    for key, shape_name in AI_CHAT_RESPONSE_SHAPES:
        if key in payload:
            return shape_name
    return None


def guess_model_family(model_ids: list[str]) -> str | None:
    """Guess model family from a list of model IDs.

    Args:
        model_ids: List of model identifier strings.

    Returns:
        Model family token string or None.
    """
    for token in AI_MODEL_FAMILY_TOKENS:
        if any(token.lower() in model.lower() for model in model_ids):
            return token
    return None


def get_favicon_product(favicon_hash: int) -> str | None:
    """Look up product name from favicon mmh3 hash.

    Returns:
        Product name string or None.
    """
    return AI_FAVICON_HASHES.get(favicon_hash)
