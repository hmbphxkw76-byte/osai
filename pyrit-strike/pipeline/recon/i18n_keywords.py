"""中英文双语能力检测关键词库。

学术依据:
    - Greshake et al. (arXiv:2302.12173) §4 — 间接注入探测依赖目标
      响应中的能力声明, 不同语言的目标使用不同表述。
    - Zheng et al. (arXiv:2306.05685) §4.3 — LLM-as-Judge 鲁棒性:
      多语言匹配减少假阴性, 单语言检测在非英语目标上 ASR 降低 15-30%。
    - Mazeika et al. (arXiv:2406.18510, WILDTEAMING) — 不同模型族/语言
      的安全对齐策略不同, 中文模型 (Qwen, GLM, DeepSeek) 使用中文措辞。
    - PyRIT (arXiv:2407.01232) §3.3 — 黑盒目标能力指纹需要适配多语言。

设计原则:
    每个能力维度同时包含英文和中文关键词,
    匹配时对两种语言进行 OR 逻辑, 降低假阴性率。
    英文关键词匹配时转为小写 (case-insensitive),
    中文关键词匹配时保持原样 (中文不区分大小写)。
"""

from __future__ import annotations

# ══════════════════════════════════════════════════════════════
# 双语关键词库 — 按能力维度组织
# ══════════════════════════════════════════════════════════════

_CAPABILITY_KEYWORDS_I18N: dict[str, dict[str, list[str]]] = {
    "agent": {
        "en": [
            "i have access to tools",
            "i can use tools",
            "function_call",
            "tool_call",
            "i am an agent",
            "as an ai assistant",
            "i can help you with",
            "my capabilities include",
            "i have access to functions",
            "available tools",
            "i can execute",
        ],
        "zh": [
            "我可以使用工具",
            "我可以调用工具",
            "我有工具",
            "我可以执行",
            "作为一个ai助手",
            "作为一个智能助手",
            "我的能力包括",
            "可用工具",
            "函数调用",
            "工具调用",
            "我是一个agent",
            "我是一个智能体",
            "我可以帮你",
            "我有访问工具的权限",
        ],
    },
    "rag": {
        "en": [
            "based on the retrieved",
            "knowledge base",
            "from the documents",
            "according to the context",
            "retrieved information",
            "search results show",
            "from my knowledge",
            "based on available data",
            "reference document",
            "source material",
        ],
        "zh": [
            "根据检索到的",
            "知识库",
            "从文档中",
            "根据上下文",
            "检索到的信息",
            "搜索结果显示",
            "根据我的知识",
            "根据可用数据",
            "参考文档",
            "原始材料",
            "从知识库中",
            "检索结果",
            "根据提供的资料",
            "基于已检索",
        ],
    },
    "mcp": {
        "en": [
            "model context protocol",
            "mcp server",
            "mcp tool",
            "protocol server",
            "i'm connected to",
            "connected tools",
            "server-side tools",
        ],
        "zh": [
            "模型上下文协议",
            "mcp服务器",
            "mcp服务端",
            "mcp工具",
            "协议服务器",
            "我连接了",
            "已连接的工具",
            "服务端工具",
            "我已连接到",
        ],
    },
    "embedding": {
        "en": [
            "embedding",
            "vector search",
            "semantic search",
            "similarity search",
            "vector database",
            "nearest neighbor",
        ],
        "zh": [
            "嵌入",
            "向量搜索",
            "语义搜索",
            "相似度搜索",
            "向量数据库",
            "最近邻",
            "向量检索",
            "嵌入模型",
        ],
    },
    "multi_agent": {
        "en": [
            "multiple agents",
            "collaborate with",
            "delegate to",
            "i work with other",
            "team of agents",
            "multi-agent",
            "coordinator",
        ],
        "zh": [
            "多个agent",
            "多个智能体",
            "协作",
            "委派给",
            "我与其它",
            "我与其他",
            "团队智能体",
            "多智能体",
            "协调者",
            "协同工作",
        ],
    },
    "code_execution": {
        "en": [
            "i can execute code",
            "code interpreter",
            "python execution",
            "run code",
            "sandbox",
            "i can write and run",
            "code execution",
        ],
        "zh": [
            "我可以执行代码",
            "代码解释器",
            "python执行",
            "运行代码",
            "沙箱",
            "沙盒",
            "我可以编写并运行",
            "代码执行",
        ],
    },
    "web_search": {
        "en": [
            "i can search",
            "web search",
            "search the web",
            "online search",
            "internet search",
            "browsing",
        ],
        "zh": [
            "我可以搜索",
            "网络搜索",
            "搜索网络",
            "在线搜索",
            "互联网搜索",
            "浏览网页",
            "联网搜索",
        ],
    },
    # ── 深度探测维度 ──
    "function_calling": {
        "en": [
            "function",
            "tool",
            "call",
            "schema",
            "parameter",
            "openapi",
            "endpoint",
            "api",
            "method",
        ],
        "zh": [
            "函数",
            "工具",
            "调用",
            "模式",
            "参数",
            "接口",
            "端点",
            "方法",
        ],
    },
    "memory": {
        "en": [
            "memory",
            "remember",
            "previous",
            "history",
            "session",
            "persistent",
            "stored",
            "context",
        ],
        "zh": [
            "记忆",
            "记住",
            "之前的",
            "历史",
            "会话",
            "持久",
            "存储的",
            "上下文",
            "之前的对话",
        ],
    },
    "workflow": {
        "en": [
            "workflow",
            "pipeline",
            "step",
            "chain",
            "sequence",
            "orchestrat",
            "flow",
            "process",
        ],
        "zh": [
            "工作流",
            "流水线",
            "步骤",
            "链",
            "序列",
            "编排",
            "流程",
            "过程",
        ],
    },
    "multi_tenant": {
        "en": [
            "tenant",
            "organization",
            "org",
            "workspace",
            "namespace",
            "account",
            "project",
        ],
        "zh": [
            "租户",
            "组织",
            "工作空间",
            "命名空间",
            "账户",
            "项目",
        ],
    },
    "session_auth": {
        "en": [
            "session",
            "token",
            "cookie",
            "bearer",
            "jwt",
            "auth",
            "login",
            "user",
        ],
        "zh": [
            "会话",
            "令牌",
            "cookie",
            "bearer",
            "jwt",
            "认证",
            "登录",
            "用户",
        ],
    },
    "mcp_protocol": {
        "en": [
            "mcp",
            "model context protocol",
            "server",
            "tool",
            "resource",
            "prompt",
        ],
        "zh": [
            "mcp",
            "模型上下文协议",
            "服务器",
            "服务端",
            "工具",
            "资源",
            "提示",
        ],
    },
    "a2a_protocol": {
        "en": [
            "a2a",
            "agent-to-agent",
            "agent card",
            "json-rpc",
            "well-known",
            "inter-agent",
            "orchestrat",
            "delegate",
            "skill",
            "task lifecycle",
            "multi-agent",
        ],
        "zh": [
            "a2a",
            "agent间通信",
            "智能体间",
            "agent卡",
            "智能体卡片",
            "json-rpc",
            "well-known",
            "跨agent",
            "编排",
            "委派",
            "技能",
            "任务生命周期",
            "多智能体",
        ],
    },
    "embedding_rag": {
        "en": [
            "embedding",
            "vector",
            "rag",
            "retrieval",
            "similarity",
            "index",
            "collection",
            "knowledge base",
            "semantic search",
        ],
        "zh": [
            "嵌入",
            "向量",
            "rag",
            "检索",
            "相似度",
            "索引",
            "集合",
            "知识库",
            "语义搜索",
            "向量数据库",
        ],
    },
}


def match_capability_i18n(
    response_text: str,
    capability: str,
) -> bool:
    """双语关键词匹配 — 同时检测中英文关键词。

    学术依据:
        - Greshake et al. (arXiv:2302.12173) §4 — 能力探测依赖响应关键词
        - Zheng et al. (arXiv:2306.05685) §4.3 — 多语言匹配提升鲁棒性
        - 中文不区分大小写, 英文转为小写匹配

    Args:
        response_text: 目标响应文本。
        capability: 能力维度名 (agent/rag/mcp/embedding/multi_agent/...)。

    Returns:
        True 如果检测到该能力 (任一语言关键词命中)。
    """
    keywords = _CAPABILITY_KEYWORDS_I18N.get(capability, {})
    if not keywords:
        return False

    text_lower = response_text.lower()

    # 英文关键词 (小写匹配)
    for kw in keywords.get("en", []):
        if kw in text_lower:
            return True

    # 中文关键词 (case-insensitive, 因 "AI" 常为大写混入中文)
    for kw in keywords.get("zh", []):
        if kw in text_lower:
            return True

    return False


def get_i18n_keywords(capability: str) -> dict[str, list[str]]:
    """获取指定能力维度的双语关键词列表。

    Args:
        capability: 能力维度名。

    Returns:
        {"en": [...], "zh": [...]} 关键词字典。
    """
    return _CAPABILITY_KEYWORDS_I18N.get(capability, {"en": [], "zh": []})


def get_all_capability_names() -> list[str]:
    """获取所有能力维度名称列表。

    Returns:
        能力维度名称列表。
    """
    return list(_CAPABILITY_KEYWORDS_I18N.keys())
