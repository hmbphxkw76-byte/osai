# -*- coding: utf-8 -*-
"""
SPA Chat Recon - 常量定义模块

包含所有 SPA 聊天侦察所需的常量：
- LLM API 路径/字段关键词
- 聊天入口选择器（967 个模式）
- DOM 特征 / URL 模式
- 验证码选择器
- OIDC 回调白名单
- WAF 安全延迟
- 评分权重 / 信号关键词
- 探测消息 / 模型家族模式

从 spa_chat_recon_adapter.py 提取（模块化拆分）
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Tuple

logger = logging.getLogger(__name__)

# ── LLM API 路径关键词（用于识别后端 AI 端点） ──
LLM_PATH_KEYWORDS: List[str] = [
    "chat", "completions", "completion", "message", "msg",
    "query", "ask", "conversation", "converse", "dialogue",
    "generate", "infer", "inference", "predict", "stream",
    "agent", "assistant", "bot", "llm", "gpt", "ai",
    # RAG / 知识库增强路径（国开 appsharing-ai 等平台）
    "with-knowledge", "with_knowledge", "knowledge-chat",
    "rag", "knowledge", "qa", "question-answering",
]

# ── 请求 body 中指示 LLM API 的字段 ──
LLM_BODY_FIELDS: List[str] = [
    "messages", "model", "prompt", "max_tokens", "temperature",
    "top_p", "stream", "tools", "functions", "n",
    "response_format", "system", "context",
]

# ── 响应中指示 LLM API 的字段 ──
LLM_RESPONSE_FIELDS: List[str] = [
    "choices", "message", "content", "delta", "finish_reason",
    "usage", "completion", "generated_text", "output",
]

# ── RAG 相关路径关键词 ──
RAG_PATH_KEYWORDS: List[str] = [
    "embed", "embedding", "vector", "retrieve", "retrieval",
    "search", "knowledge", "rag", "index", "collection",
    "chroma", "pinecone", "weaviate", "milvus", "qdrant",
]

# ── 默认智能助手入口选择器（覆盖多种入口类型） ──
# 顺序：从精确到模糊，优先匹配高置信度选择器
# 覆盖策略（v1.2 全面扩充，覆盖 AI 应用全场景）：
#   1. 精确类名（含常见框架命名 + 国内 AI 厂商 SDK）
#   2. ARIA 标签（中英文 + AI 应用专属标签）
#   3. 文本匹配（中英文 + AI 应用专属文本）
#   4. 纯图标选择器（SVG/IMG + AI 图标如 sparkle/magic/wand）
#   5. 浮动按钮 / FAB（位置无关的浮动元素）
#   6. data 属性匹配（含 data-testid / data-ai / data-copilot）
#   7. 模糊类名匹配（拼音 + 通用兜底）
#   8. AI Copilot / GenAI 专用类名（GitHub/Microsoft/Bing Copilot）
#   9. RAG / Knowledge Base 专用类名（知识库/文档问答/语义搜索）
#  10. Agent / Agentic 专用类名（智能体/自动化代理/工作流）
#  11. AI Playground / Studio 专用类名（模型试验场/工作台）
#  12. 现代 AI SaaS 平台类名（Chatbase/Dante/CustomGPT/Dialogflow 等）
#  13. AI 侧边栏 / 面板 / 抽屉模式（现代 AI 应用常见布局）
#  14. 模糊类名匹配（AI 应用兜底）
DEFAULT_CHAT_ENTRY_SELECTORS: str = ", ".join([
    # ════════════════════════════════════════════════════════════
    # 1. 精确类名匹配（常见 UI 框架命名）
    # ════════════════════════════════════════════════════════════
    ".smart-assistant",
    ".ai-assistant",
    ".chat-fab",
    ".chat-entry",
    ".assistant-btn",
    ".chat-bot",
    ".chatbot-btn",
    ".help-bot",
    ".customer-service",
    # ── 常见 UI 库类名 ──
    ".chat-widget",
    ".chat-trigger",
    ".chat-launcher",
    ".chat-toggle",
    ".chat-button",
    ".ai-chat-btn",
    ".ai-bot",
    ".ai-trigger",
    ".virtual-assistant",
    ".va-button",
    ".bot-fab",
    ".bot-trigger",
    ".assistant-fab",
    ".assistant-launcher",
    ".help-fab",
    ".support-fab",
    ".msg-fab",
    ".inbox-fab",
    ".contact-fab",
    # ── Element UI / Ant Design / Naive UI 常见类名 ──
    ".el-chat-fab",
    ".ant-chat-fab",
    ".n-chat-fab",
    # ── 常见第三方客服 SDK 类名 ──
    ".qiaoqiao-chat",            # 小能客服
    ".live800-btn",              # Live800
    ".nhf-chat-btn",             # 乐语
    ".easyliao-btn",             # 易聊
    ".udesk-chat",               # Udesk
    ".comm100-chat",             # Comm100
    ".z9-chat-btn",             # 智齿客服
    ".crisp-chat",               # Crisp
    ".intercom-launcher",        # Intercom
    ".tawk-chat",                # Tawk.to
    ".hubspot-chat",             # HubSpot
    ".drift-chat",               # Drift
    ".olark-chat",               # Olark
    ".zendesk-chat",             # Zendesk
    ".livechat-btn",             # LiveChat
    # ── 国内常见客服/AI 厂商 SDK 类名 ──
    ".qiyu-iframe",              # 网易七鱼
    ".meiqia-btn",               # 美洽
    ".rongcloud-btn",            # 融云
    ".easemob-btn",              # 环信
    ".im-btn",                   # 即时通讯通用
    ".gensee-chat",             # 展视互动
    ".duoke-btn",               # 多客
    ".wxp-chat",                # 微信客服
    ".bytedance-chat",          # 字节豆包嵌入
    ".volcengine-ark",          # 火山方舟
    ".baidu-ai",                # 百度智能云
    ".aliyun-qwen",             # 阿里通义千问
    ".iflytek-spark",           # 科大讯飞星火
    ".zhipu-chatglm",           # 智谱 ChatGLM
    ".minimax-abab",            # MiniMax
    ".baichuan-btn",            # 百川
    ".moonshot-kimi",           # 月之暗面 Kimi
    ".sensetime-nova",          # 商汤 Nova
    ".tencent-hunyuan",         # 腾讯混元
    ".iflytek-spark-btn",

    # ════════════════════════════════════════════════════════════
    # 2. ARIA 标签匹配（中文）
    # ════════════════════════════════════════════════════════════
    "[aria-label='智能助手']",
    "[aria-label='AI助手']",
    "[aria-label='智能客服']",
    "[aria-label='在线客服']",
    "[aria-label='在线帮助']",
    "[aria-label='客服']",
    "[aria-label='帮助']",
    "[aria-label='智能问答']",
    "[aria-label='问答机器人']",
    "[aria-label='虚拟助手']",
    "[aria-label='在线咨询']",
    "[aria-label='AI咨询']",
    "[aria-label='AI问答']",
    "[aria-label='机器人']",
    "[aria-label='聊天']",
    "[aria-label='发消息']",
    "[aria-label='智能对话']",
    "[aria-label='AI对话']",
    "[aria-label='知识库']",
    "[aria-label='智能搜索']",
    "[aria-label='智能体']",
    "[aria-label='AI助手']",
    "[aria-label='智能写作']",
    "[aria-label='智能助理']",
    "[aria-label='智能助手按钮']",
    "[aria-label='AI 助手']",
    "[aria-label='聊天机器人']",
    "[aria-label='客服机器人']",
    "[aria-label='智能客服助手']",
    "[aria-label='在线客服咨询']",
    "[aria-label='AI写作助手']",
    "[aria-label='AI 搜索']",
    "[aria-label='智能问答助手']",
    "[aria-label='知识问答']",
    "[aria-label='文档问答']",
    "[aria-label='智能导诊']",       # 医疗场景
    "[aria-label='智能学伴']",       # 教育场景
    "[aria-label='智能导师']",
    "[aria-label='AI学伴']",
    "[aria-label='智能审批']",       # 政务场景
    "[aria-label='智能办事']",

    # ════════════════════════════════════════════════════════════
    # 3. ARIA 标签匹配（英文）
    # ════════════════════════════════════════════════════════════
    "[aria-label='assistant']",
    "[aria-label='Assistant']",
    "[aria-label='chat']",
    "[aria-label='Chat']",
    "[aria-label='help']",
    "[aria-label='Help']",
    "[aria-label='support']",
    "[aria-label='Support']",
    "[aria-label='Ask']",
    "[aria-label='ask']",
    "[aria-label='Message']",
    "[aria-label='message']",
    "[aria-label='Contact us']",
    "[aria-label='Live chat']",
    "[aria-label='live chat']",
    "[aria-label='Open chat']",
    "[aria-label='Start chat']",
    "[aria-label='Send message']",
    "[aria-label='AI Assistant']",
    "[aria-label='Virtual Assistant']",
    "[aria-label='Chatbot']",
    "[aria-label='chatbot']",
    "[aria-label='Bot']",
    "[aria-label='bot']",
    # ── AI 应用专属 ARIA 标签 ──
    "[aria-label='Ask AI']",
    "[aria-label='ask ai']",
    "[aria-label='Chat with AI']",
    "[aria-label='Chat AI']",
    "[aria-label='AI Chat']",
    "[aria-label='AI chat']",
    "[aria-label='AI Chatbot']",
    "[aria-label='AI Help']",
    "[aria-label='AI Helper']",
    "[aria-label='AI Assistant']",
    "[aria-label='AI Assistant Chat']",
    "[aria-label='AI Companion']",
    "[aria-label='AI Copilot']",
    "[aria-label='Copilot']",
    "[aria-label='copilot']",
    "[aria-label='Co-pilot']",
    "[aria-label='GenAI']",
    "[aria-label='GenAI Chat']",
    "[aria-label='Generative AI']",
    "[aria-label='LLM Chat']",
    "[aria-label='Language Model']",
    "[aria-label='Knowledge Base']",
    "[aria-label='Knowledge Search']",
    "[aria-label='Search Knowledge']",
    "[aria-label='Smart Search']",
    "[aria-label='Intelligent Search']",
    "[aria-label='AI Search']",
    "[aria-label='AI Search Assistant']",
    "[aria-label='Agent']",
    "[aria-label='AI Agent']",
    "[aria-label='AI Agents']",
    "[aria-label='Intelligent Agent']",
    "[aria-label='Autonomous Agent']",
    "[aria-label='Assistant Agent']",
    "[aria-label='Playground']",
    "[aria-label='AI Playground']",
    "[aria-label='Model Playground']",
    "[aria-label='Studio']",
    "[aria-label='AI Studio']",
    "[aria-label='Prompt']",
    "[aria-label='Prompt Engineering']",
    "[aria-label='Compose']",
    "[aria-label='Compose with AI']",
    "[aria-label='Generate']",
    "[aria-label='Generate with AI']",
    "[aria-label='Inquire']",
    "[aria-label='Inquiry']",
    "[aria-label='Query']",
    "[aria-label='Ask a question']",
    "[aria-label='Ask Question']",
    "[aria-label='New chat']",
    "[aria-label='New conversation']",
    "[aria-label='Start a conversation']",
    "[aria-label='Talk to AI']",
    "[aria-label='Talk to us']",
    "[aria-label='Chat now']",
    "[aria-label='Chat with us']",
    "[aria-label='Get help']",
    "[aria-label='Get AI help']",
    "[aria-label='AI Support']",
    "[aria-label='AI Advisor']",
    "[aria-label='AI Tutor']",
    "[aria-label='AI Guide']",
    "[aria-label='AI Mentor']",
    "[aria-label='AI Coach']",
    "[aria-label='AI Writer']",
    "[aria-label='AI Coder']",
    "[aria-label='AI Assistant Button']",
    "[aria-label='Open AI Assistant']",
    "[aria-label='Toggle AI']",
    "[aria-label='Toggle chat']",
    "[aria-label='Launch assistant']",
    "[aria-label='Open Assistant']",
    "[aria-label='Open Copilot']",
    "[aria-label='Open AI']",

    # ════════════════════════════════════════════════════════════
    # 4. 文本匹配（中文）
    # ════════════════════════════════════════════════════════════
    "button:has-text('智能助手')",
    "button:has-text('AI助手')",
    "button:has-text('智能客服')",
    "button:has-text('在线客服')",
    "button:has-text('在线帮助')",
    "button:has-text('帮助中心')",
    "button:has-text('在线咨询')",
    "button:has-text('客服')",
    "button:has-text('问答')",
    "button:has-text('助手')",
    "button:has-text('智能问答')",
    "button:has-text('虚拟助手')",
    "button:has-text('机器人')",
    "button:has-text('聊天')",
    "button:has-text('发消息')",
    "button:has-text('咨询')",
    "button:has-text('智能对话')",
    "button:has-text('AI对话')",
    "button:has-text('知识库')",
    "button:has-text('智能搜索')",
    "button:has-text('智能体')",
    "button:has-text('智能写作')",
    "button:has-text('智能助理')",
    "button:has-text('AI 写作')",
    "button:has-text('AI 搜索')",
    "button:has-text('AI 学伴')",
    "button:has-text('智能学伴')",
    "button:has-text('智能导师')",
    "button:has-text('文档问答')",
    "button:has-text('知识问答')",
    "button:has-text('智能导诊')",
    "button:has-text('智能审批')",
    "button:has-text('智能办事')",
    "button:has-text('开始对话')",
    "button:has-text('发起对话')",
    "button:has-text('新对话')",
    "button:has-text('新会话')",
    "a:has-text('智能助手')",
    "a:has-text('AI助手')",
    "a:has-text('在线客服')",
    "a:has-text('在线帮助')",
    "a:has-text('帮助中心')",
    "a:has-text('客服')",
    "a:has-text('智能问答')",
    "a:has-text('虚拟助手')",
    "a:has-text('在线咨询')",
    "a:has-text('智能对话')",
    "a:has-text('AI对话')",
    "a:has-text('知识库')",
    "a:has-text('智能搜索')",
    "a:has-text('智能体')",
    "div[role='button']:has-text('智能助手')",
    "div[role='button']:has-text('客服')",
    "div[role='button']:has-text('助手')",
    "div[role='button']:has-text('咨询')",
    "div[role='button']:has-text('智能对话')",
    "div[role='button']:has-text('AI助手')",
    "span[role='button']:has-text('智能助手')",
    "span[role='button']:has-text('客服')",

    # ════════════════════════════════════════════════════════════
    # 5. 文本匹配（英文）— AI 应用专属 + 通用聊天入口
    # ════════════════════════════════════════════════════════════
    "button:has-text('Assistant')",
    "button:has-text('Chat')",
    "button:has-text('Help')",
    "button:has-text('Support')",
    "button:has-text('Ask')",
    "button:has-text('Message')",
    "button:has-text('Contact')",
    "button:has-text('Live Chat')",
    "button:has-text('Live chat')",
    "button:has-text('Chatbot')",
    "button:has-text('Bot')",
    "button:has-text('AI')",
    # ── AI 应用专属文本 ──
    "button:has-text('Ask AI')",
    "button:has-text('Chat with AI')",
    "button:has-text('Chat AI')",
    "button:has-text('AI Chat')",
    "button:has-text('AI Chatbot')",
    "button:has-text('AI Help')",
    "button:has-text('AI Helper')",
    "button:has-text('AI Assistant')",
    "button:has-text('AI Companion')",
    "button:has-text('AI Copilot')",
    "button:has-text('Copilot')",
    "button:has-text('Co-pilot')",
    "button:has-text('GenAI')",
    "button:has-text('Generative AI')",
    "button:has-text('LLM')",
    "button:has-text('Knowledge Base')",
    "button:has-text('Knowledge')",
    "button:has-text('Smart Search')",
    "button:has-text('Intelligent Search')",
    "button:has-text('AI Search')",
    "button:has-text('Agent')",
    "button:has-text('AI Agent')",
    "button:has-text('Playground')",
    "button:has-text('AI Playground')",
    "button:has-text('Studio')",
    "button:has-text('AI Studio')",
    "button:has-text('Prompt')",
    "button:has-text('Compose')",
    "button:has-text('Compose with AI')",
    "button:has-text('Generate')",
    "button:has-text('Generate with AI')",
    "button:has-text('Inquire')",
    "button:has-text('Inquiry')",
    "button:has-text('Query')",
    "button:has-text('Ask a question')",
    "button:has-text('Ask Question')",
    "button:has-text('New chat')",
    "button:has-text('New conversation')",
    "button:has-text('Start a conversation')",
    "button:has-text('Talk to AI')",
    "button:has-text('Talk to us')",
    "button:has-text('Chat now')",
    "button:has-text('Chat with us')",
    "button:has-text('Get help')",
    "button:has-text('Get AI help')",
    "button:has-text('AI Support')",
    "button:has-text('AI Advisor')",
    "button:has-text('AI Tutor')",
    "button:has-text('AI Guide')",
    "button:has-text('AI Mentor')",
    "button:has-text('AI Coach')",
    "button:has-text('AI Writer')",
    "button:has-text('AI Coder')",
    "button:has-text('Start chat')",
    "button:has-text('Open chat')",
    "button:has-text('Open AI')",
    "button:has-text('Open Assistant')",
    "button:has-text('Open Copilot')",
    "button:has-text('Launch AI')",
    "button:has-text('Try AI')",
    "button:has-text('Gemini')",
    "button:has-text('Claude')",
    "button:has-text('ChatGPT')",
    "button:has-text('Bard')",
    "button:has-text('Perplexity')",
    "button:has-text('HuggingChat')",
    "button:has-text('Grok')",
    "a:has-text('Assistant')",
    "a:has-text('Chat')",
    "a:has-text('Help')",
    "a:has-text('Support')",
    "a:has-text('Ask')",
    "a:has-text('Contact')",
    "a:has-text('Live Chat')",
    "a:has-text('Ask AI')",
    "a:has-text('Chat with AI')",
    "a:has-text('AI Chat')",
    "a:has-text('Copilot')",
    "a:has-text('Knowledge Base')",
    "a:has-text('AI Agent')",
    "a:has-text('Playground')",
    "a:has-text('AI Search')",
    "a:has-text('New chat')",
    "a:has-text('Start chat')",
    "a:has-text('Chat now')",
    "a:has-text('Talk to AI')",
    "div[role='button']:has-text('Chat')",
    "div[role='button']:has-text('Assistant')",
    "div[role='button']:has-text('Help')",
    "div[role='button']:has-text('Ask AI')",
    "div[role='button']:has-text('Copilot')",
    "div[role='button']:has-text('AI')",
    "span[role='button']:has-text('Chat')",
    "span[role='button']:has-text('Assistant')",
    "span[role='button']:has-text('Ask AI')",

    # ════════════════════════════════════════════════════════════
    # 6. 纯图标选择器（SVG/IMG 图标，无文字）
    # ════════════════════════════════════════════════════════════
    # ── 包含 SVG 的可点击元素 ──
    "button:has(svg)",
    "[role='button']:has(svg)",
    "a:has(svg[class])",
    # ── 带聊天相关 class 的 SVG 容器 ──
    "[class*='chat-icon']",
    "[class*='assistant-icon']",
    "[class*='bot-icon']",
    "[class*='help-icon']",
    "[class*='msg-icon']",
    "[class*='chat-svg']",
    "[class*='ai-icon']",
    "[class*='robot-icon']",
    "[class*='copilot-icon']",
    "[class*='sparkle-icon']",          # AI 闪光图标（常见于 Copilot）
    "[class*='magic-icon']",            # 魔法棒图标（AI 生成）
    "[class*='wand-icon']",
    "[class*='stars-icon']",            # 星星图标（AI 生成）
    "[class*='generate-icon']",
    "[class*='compose-icon']",
    "[class*='knowledge-icon']",
    "[class*='agent-icon']",
    "[class*='playground-icon']",
    # ── IMG 图标（alt/title 含聊天关键词）──
    "img[alt*='chat']",
    "img[alt*='Chat']",
    "img[alt*='assistant']",
    "img[alt*='Assistant']",
    "img[alt*='help']",
    "img[alt*='Help']",
    "img[alt*='客服']",
    "img[alt*='助手']",
    "img[alt*='咨询']",
    "img[alt*='聊天']",
    "img[alt*='AI']",
    "img[alt*='ai']",
    "img[alt*='copilot']",
    "img[alt*='Copilot']",
    "img[alt*='agent']",
    "img[alt*='Agent']",
    "img[alt*='knowledge']",
    "img[alt*='Knowledge']",
    "img[alt*='robot']",
    "img[alt*='Robot']",
    "img[alt*='智能']",
    "img[alt*='问答']",
    "img[title*='chat']",
    "img[title*='Chat']",
    "img[title*='assistant']",
    "img[title*='Assistant']",
    "img[title*='客服']",
    "img[title*='助手']",
    "img[title*='AI']",
    "img[title*='copilot']",
    "img[title*='Copilot']",
    "img[title*='agent']",
    "img[title*='knowledge']",

    # ════════════════════════════════════════════════════════════
    # 7. 浮动按钮 / FAB（Floating Action Button）模式
    #    覆盖右下角、右上角、左上角、左下角等位置
    # ════════════════════════════════════════════════════════════
    # ── 通用 FAB 类名 ──
    ".fab",
    ".fab-btn",
    ".floating-btn",
    ".float-btn",
    ".float-button",
    ".floating-action",
    ".action-btn",
    ".float-action-btn",
    # ── show-* 模式（国开/教育平台常见命名） ──
    ".show-chat-button",
    ".show-chat",
    ".show-chat-btn",
    ".show-ai",
    ".show-ai-button",
    ".show-assistant",
    ".show-bot",
    ".open-chat",
    ".open-chat-button",
    ".open-ai",
    ".toggle-chat",
    ".toggle-chat-button",
    # ── 位置相关 FAB（CSS 类名模式）──
    "[class*='fab-right']",
    "[class*='fab-left']",
    "[class*='fab-bottom']",
    "[class*='fab-top']",
    "[class*='float-right']",
    "[class*='float-left']",
    "[class*='float-bottom']",
    "[class*='float-top']",
    "[class*='corner-btn']",
    "[class*='corner-icon']",
    "[class*='fixed-btn']",
    "[class*='fixed-icon']",
    "[class*='fixed-chat']",
    "[class*='sticky-chat']",
    # ── 右下角（最常见）──
    "[class*='right-bottom']",
    "[class*='bottom-right']",
    "[class*='rb-corner']",
    "[class*='rb-fab']",
    # ── 右上角 ──
    "[class*='right-top']",
    "[class*='top-right']",
    "[class*='rt-corner']",
    "[class*='rt-fab']",
    # ── 左下角 ──
    "[class*='left-bottom']",
    "[class*='bottom-left']",
    "[class*='lb-corner']",
    "[class*='lb-fab']",
    # ── 左上角 ──
    "[class*='left-top']",
    "[class*='top-left']",
    "[class*='lt-corner']",
    "[class*='lt-fab']",

    # ════════════════════════════════════════════════════════════
    # 8. data 属性匹配
    # ════════════════════════════════════════════════════════════
    "[data-action='chat']",
    "[data-action='assistant']",
    "[data-action='help']",
    "[data-type='chat']",
    "[data-type='assistant']",
    "[data-type='chatbot']",
    "[data-chat]",
    "[data-assistant]",
    "[data-bot]",
    "[data-chatbot]",
    # ── AI 应用专属 data 属性 ──
    "[data-action='ask-ai']",
    "[data-action='ask_ai']",
    "[data-action='open-ai']",
    "[data-action='open-chat']",
    "[data-action='launch-ai']",
    "[data-action='launch-assistant']",
    "[data-action='toggle-ai']",
    "[data-action='toggle-chat']",
    "[data-action='open-copilot']",
    "[data-action='open-assistant']",
    "[data-action='open-agent']",
    "[data-action='compose']",
    "[data-action='generate']",
    "[data-type='ai']",
    "[data-type='ai-chat']",
    "[data-type='ai-assistant']",
    "[data-type='copilot']",
    "[data-type='agent']",
    "[data-type='ai-agent']",
    "[data-type='playground']",
    "[data-type='knowledge']",
    "[data-type='rag']",
    "[data-ai]",
    "[data-ai-chat]",
    "[data-ai-assistant]",
    "[data-ai-agent]",
    "[data-copilot]",
    "[data-agent]",
    "[data-knowledge]",
    "[data-rag]",
    "[data-playground]",
    "[data-testid='chat-entry']",
    "[data-testid='ai-assistant']",
    "[data-testid='ai-button']",
    "[data-testid='copilot-button']",
    "[data-testid='chat-launcher']",
    "[data-testid='assistant-launcher']",
    "[data-testid='chat-fab']",
    "[data-testid='ai-fab']",

    # ════════════════════════════════════════════════════════════
    # 9. 模糊类名匹配（兜底）
    # ════════════════════════════════════════════════════════════
    "[class*='assistant']",
    "[class*='chat-fab']",
    "[class*='chatbot']",
    "[class*='chat-widget']",
    "[class*='chat-launch']",
    "[class*='chat-trigger']",
    "[class*='chat-toggle']",
    "[class*='chat-btn']",
    "[class*='robot']",
    "[class*='help-btn']",
    "[class*='support-btn']",
    "[class*='ai-btn']",
    "[class*='ai-trigger']",
    "[class*='ai-fab']",
    "[class*='virtual-assistant']",
    "[class*='va-btn']",
    "[class*='kefu']",           # 拼音：客服
    "[class*='zhushou']",        # 拼音：助手
    "[class*='jiqiren']",        # 拼音：机器人
    "[class*='wenda']",          # 拼音：问答
    "[class*='liaotian']",       # 拼音：聊天
    "[class*='duihua']",         # 拼音：对话
    "[class*='zhineng']",        # 拼音：智能
    "[class*='zhishiku']",       # 拼音：知识库
    "[class*='zhinengti']",      # 拼音：智能体

    # ════════════════════════════════════════════════════════════
    # 10. AI Copilot / GenAI 专用类名（GitHub Copilot / Microsoft Copilot / IDE 嵌入式 AI）
    # ════════════════════════════════════════════════════════════
    ".copilot",
    ".copilot-btn",
    ".copilot-button",
    ".copilot-fab",
    ".copilot-launcher",
    ".copilot-trigger",
    ".copilot-icon",
    ".copilot-entry",
    ".co-pilot",
    ".co-pilot-btn",
    ".github-copilot",
    ".github-copilot-launcher",
    ".m365-copilot",
    ".microsoft-copilot",
    ".bing-copilot",
    ".edge-copilot",
    ".windows-copilot",
    ".copilot-chat",
    ".copilot-assistant",
    ".copilot-panel",
    ".copilot-sidebar",
    ".copilot-drawer",
    ".genai-btn",
    ".genai-chat",
    ".genai-launcher",
    ".genai-fab",
    ".gen-ai-btn",
    ".gen-ai-chat",
    ".generative-ai-btn",
    ".llm-chat",
    ".llm-btn",
    ".llm-entry",
    ".ai-completion-btn",
    ".ai-generate-btn",
    ".ai-compose-btn",
    ".ai-write-btn",
    ".ai-spark",
    ".ai-sparkle",
    ".ai-magic",
    ".ai-wand",
    ".ai-stars",
    ".sparkle-btn",
    ".magic-btn",
    ".wand-btn",
    ".ai-generate",
    ".ai-completion",
    ".ai-composer",

    # ════════════════════════════════════════════════════════════
    # 11. RAG / Knowledge Base 专用类名（知识库 / 检索增强 / 文档问答）
    # ════════════════════════════════════════════════════════════
    ".knowledge-base",
    ".knowledge-base-btn",
    ".knowledge-btn",
    ".knowledge-chat",
    ".knowledge-entry",
    ".knowledge-search",
    ".kb-btn",
    ".kb-chat",
    ".kb-entry",
    ".kb-search",
    ".kb-launcher",
    ".rag-btn",
    ".rag-chat",
    ".rag-entry",
    ".rag-launcher",
    ".retrieval-btn",
    ".retrieval-chat",
    ".doc-chat",
    ".doc-qa",
    ".document-chat",
    ".document-qa",
    ".doc-search",
    ".file-qa",
    ".pdf-chat",
    ".pdf-qa",
    ".semantic-search",
    ".semantic-search-btn",
    ".vector-search",
    ".vector-search-btn",
    ".smart-search",
    ".smart-search-btn",
    ".ai-search",
    ".ai-search-btn",
    ".ai-search-launcher",
    ".intelligent-search",
    ".knowledge-qa",
    ".kb-qa",
    ".rag-qa",
    ".search-assistant",
    ".search-bot",
    ".ai-search-assistant",
    ".ask-doc",
    ".ask-docs",
    ".ask-knowledge",
    ".chat-with-docs",
    ".chat-with-doc",
    ".chat-with-knowledge",
    ".chat-with-data",
    ".chat-with-pdf",

    # ════════════════════════════════════════════════════════════
    # 12. Agent / Agentic 专用类名（智能体 / 自动化代理）
    # ════════════════════════════════════════════════════════════
    ".agent",
    ".agent-btn",
    ".agent-button",
    ".agent-fab",
    ".agent-launcher",
    ".agent-trigger",
    ".agent-entry",
    ".agent-chat",
    ".agents-btn",
    ".agents-entry",
    ".ai-agent",
    ".ai-agent-btn",
    ".ai-agent-launcher",
    ".ai-agent-chat",
    ".intelligent-agent",
    ".autonomous-agent",
    ".assistant-agent",
    ".agent-panel",
    ".agent-sidebar",
    ".agent-drawer",
    ".agent-runner",
    ".agent-executor",
    ".agent-workflow",
    ".agent-orchestrator",
    ".agent-composer",
    ".ai-tasks",
    ".ai-task-btn",
    ".ai-workflow",
    ".ai-workflow-btn",
    ".ai-automation",
    ".ai-flow",
    ".ai-flow-btn",

    # ════════════════════════════════════════════════════════════
    # 13. AI Playground / Studio 专用类名（模型试验场 / 工作台）
    # ════════════════════════════════════════════════════════════
    ".playground",
    ".playground-btn",
    ".playground-entry",
    ".playground-launcher",
    ".ai-playground",
    ".ai-playground-btn",
    ".model-playground",
    ".studio",
    ".studio-btn",
    ".studio-entry",
    ".ai-studio",
    ".ai-studio-btn",
    ".model-studio",
    ".workbench",
    ".ai-workbench",
    ".ai-workbench-btn",
    ".lab",
    ".ai-lab",
    ".ai-lab-btn",
    ".console",
    ".ai-console",
    ".ai-console-btn",
    ".ai-portal",
    ".ai-center",
    ".ai-hub",
    ".ai-hub-btn",
    ".model-hub",
    ".inference-btn",
    ".inference-entry",
    ".completion-btn",
    ".completion-entry",
    ".prompt-btn",
    ".prompt-entry",
    ".prompt-launcher",
    ".prompt-studio",
    ".prompt-lab",
    ".prompt-playground",

    # ════════════════════════════════════════════════════════════
    # 14. 现代 AI SaaS 平台类名（海外主流 AI 聊天 SaaS 嵌入 SDK）
    # ════════════════════════════════════════════════════════════
    ".chatbase-launcher",        # Chatbase
    ".chatbase-btn",
    ".dante-launcher",           # Dante AI
    ".dante-btn",
    ".customgpt-launcher",       # CustomGPT
    ".customgpt-btn",
    ".sitegpt-launcher",         # SiteGPT
    ".sitegpt-btn",
    ".docsbot-launcher",         # DocsBot
    ".docsbot-btn",
    ".botsonic-launcher",        # Botsonic
    ".botsonic-btn",
    ".chatfast-launcher",        # Chatfast
    ".chatfast-btn",
    ".voiceflow-launcher",       # Voiceflow
    ".voiceflow-btn",
    ".dialogflow-btn",           # Google Dialogflow
    ".dialogflow-launcher",
    ".dialogflow-widget",
    ".kore-ai-btn",              # Kore.ai
    ".kore-ai-launcher",
    ".koreai-btn",
    ".yellow-ai-btn",            # Yellow.ai
    ".yellowai-btn",
    ".yellow-ai-launcher",
    ".servicenow-chat",          # ServiceNow Virtual Agent
    ".servicenow-launcher",
    ".now-chat",
    ".einstein-chat",            # Salesforce Einstein
    ".einstein-launcher",
    ".botframework-btn",         # Microsoft Bot Framework
    ".botframework-launcher",
    ".webchat-btn",
    ".webchat-launcher",
    ".amazon-lex",               # Amazon Lex
    ".lex-chat",
    ".lex-btn",
    ".rasa-chat",                # Rasa
    ".rasa-btn",
    ".rasa-launcher",
    ".botpress-btn",             # Botpress
    ".botpress-launcher",
    ".ada-bot",                  # Ada
    ".ada-launcher",
    ".ada-chat",
    ".zoovu-btn",                # Zoovu
    ".zoovu-launcher",
    ".convyai-btn",              # ConvyAI
    ".convyai-launcher",
    ".feedbot-btn",              # Feedbot
    ".feedbot-launcher",
    ".mobilemonkey-btn",         # MobileMonkey
    ".mobilemonkey-launcher",
    ".snappy-chat",              # Snappy
    ".snappy-launcher",
    ".tiledesk-btn",             # Tiledesk
    ".tiledesk-launcher",
    ".chatra-btn",               # Chatra
    ".chatra-launcher",
    ".userlike-btn",             # Userlike
    ".userlike-launcher",
    ".smartsupp-btn",            # Smartsupp
    ".smartsupp-launcher",
    ".proprofs-btn",             # ProProfs Chat
    ".proprofs-launcher",
    ".trengo-btn",               # Trengo
    ".trengo-launcher",
    ".channel-io-btn",           # Channel.io
    ".channelio-btn",
    ".channel-io-launcher",
    ".verloop-btn",              # Verloop
    ".verloop-launcher",
    ".freshchat-btn",            # Freshchat (Freshworks)
    ".freshchat-launcher",
    ".fc-launcher",
    ".fc-button",
    ".zoho-salesiq",             # Zoho SalesIQ
    ".salesiq-btn",
    ".salesiq-launcher",
    ".livechat-inc",             # LiveChat Inc
    ".livechat-launcher",
    ".live-chat-launcher",
    "#live-chat-launcher",
    ".user.com-chat",            # User.com
    ".activechat-btn",           # Activechat
    ".landbot-btn",              # Landbot
    ".landbot-launcher",
    ".landbot-proactive",
    ".chatbot-com",              # Chatbot.com
    ".chatbot-com-launcher",
    ".manychat-btn",             # ManyChat
    ".manychat-launcher",
    ".chatfuel-btn",             # Chatfuel
    ".chatfuel-launcher",

    # ════════════════════════════════════════════════════════════
    # 15. AI 侧边栏 / 面板 / 抽屉模式（现代 AI 应用常见布局）
    # ════════════════════════════════════════════════════════════
    ".ai-sidebar",
    ".ai-sidebar-toggle",
    ".ai-sidebar-btn",
    ".ai-panel",
    ".ai-panel-toggle",
    ".ai-panel-btn",
    ".ai-drawer",
    ".ai-drawer-toggle",
    ".ai-drawer-btn",
    ".ai-modal",
    ".ai-modal-toggle",
    ".ai-modal-btn",
    ".ai-side",
    ".ai-side-toggle",
    ".ai-side-btn",
    ".ai-right-panel",
    ".ai-right-sidebar",
    ".ai-left-panel",
    ".ai-left-sidebar",
    ".ai-window",
    ".ai-window-toggle",
    ".ai-box",
    ".ai-box-toggle",
    ".ai-view",
    ".ai-view-toggle",
    ".ai-container",
    ".ai-container-toggle",
    ".ai-frame",
    ".ai-popup",
    ".ai-popup-toggle",
    ".ai-overlay",
    ".ai-overlay-toggle",
    ".ai-flyout",
    ".ai-flyout-toggle",
    ".ai-toast",
    ".ai-banner",
    ".ai-ribbon",
    ".ai-toolbar",
    ".ai-toolbar-btn",
    ".ai-action",
    ".ai-action-btn",
    ".ai-quick-action",
    ".ai-quick-action-btn",
    ".ai-menu",
    ".ai-menu-item",
    ".ai-dropdown",
    ".ai-dropdown-toggle",
    ".ai-tooltip",
    ".ai-hover-card",
    ".ai-popover",
    ".ai-popover-toggle",
    # ── 右侧/底部 AI 面板常见类名 ──
    ".right-ai-panel",
    ".right-ai-sidebar",
    ".right-ai",
    ".bottom-ai-bar",
    ".bottom-ai",
    ".side-ai",
    ".side-assistant",
    ".side-copilot",
    ".side-agent",
    ".floating-ai",
    ".floating-ai-panel",
    ".floating-assistant",
    ".floating-copilot",
    ".floating-agent",
    ".sticky-ai",
    ".sticky-assistant",
    ".fixed-ai",
    ".fixed-assistant",
    ".fixed-copilot",
    ".fixed-agent",

    # ════════════════════════════════════════════════════════════
    # 16. 模糊类名匹配（AI 应用兜底，放在最后避免误匹配）
    # ════════════════════════════════════════════════════════════
    "[class*='copilot']",
    "[class*='co-pilot']",
    "[class*='genai']",
    "[class*='gen-ai']",
    "[class*='generative']",
    "[class*='llm']",
    "[class*='rag']",
    "[class*='knowledge']",
    "[class*='kb-']",
    "[class*='-kb']",
    "[class*='agent']",
    "[class*='playground']",
    "[class*='inference']",
    "[class*='completion']",
    "[class*='prompt-']",
    "[class*='-prompt']",
    "[class*='compose']",
    "[class*='search-ai']",
    "[class*='ai-search']",
    "[class*='smart-search']",
    "[class*='intelligent-search']",
    "[class*='ai-panel']",
    "[class*='ai-sidebar']",
    "[class*='ai-drawer']",
    "[class*='ai-modal']",
    "[class*='ai-side']",
    "[class*='ai-window']",
    "[class*='ai-box']",
    "[class*='ai-view']",
    "[class*='ai-container']",
    "[class*='ai-frame']",
    "[class*='ai-popup']",
    "[class*='ai-overlay']",
    "[class*='ai-flyout']",
    "[class*='ai-toast']",
    "[class*='ai-toolbar']",
    "[class*='ai-action']",
    "[class*='ai-quick']",
    "[class*='ai-menu']",
    "[class*='ai-dropdown']",
    "[class*='ai-popover']",
    "[class*='ai-chat']",
    "[class*='ai-assistant']",
    "[class*='ai-companion']",
    "[class*='ai-advisor']",
    "[class*='ai-tutor']",
    "[class*='ai-guide']",
    "[class*='ai-mentor']",
    "[class*='ai-coach']",
    "[class*='ai-writer']",
    "[class*='ai-coder']",
    "[class*='ai-helper']",
    "[class*='ai-support']",
    "[class*='ai-spark']",
    "[class*='ai-magic']",
    "[class*='ai-wand']",
    "[class*='ai-stars']",
    "[class*='ai-generate']",
    "[class*='ai-compose']",
    "[class*='ai-write']",
    "[class*='sparkle']",
    "[class*='magic-']",
    "[class*='wand-']",
    "[class*='stars-']",
    "[class*='doc-chat']",
    "[class*='doc-qa']",
    "[class*='document-chat']",
    "[class*='pdf-chat']",
    "[class*='file-qa']",
    "[class*='semantic-search']",
    "[class*='vector-search']",
    "[class*='chat-with']",
    "[class*='ask-doc']",
    "[class*='ask-ai']",
    "[class*='ask_ai']",
    "[class*='open-ai']",
    "[class*='open-chat']",
    "[class*='launch-ai']",
    "[class*='toggle-ai']",
    "[class*='new-chat']",
    "[class*='new-conversation']",
    "[class*='start-chat']",
    "[class*='talk-to']",
    "[class*='chat-now']",
    "[class*='chat-with']",
    "[class*='get-help']",
    "[class*='get-ai']",
])

# ── 聊天页 URL 模式（用于自动检测页面是否本身即聊天页） ──
# 当 chat_entry.mode=auto 时，先检查 URL 是否匹配这些模式
CHAT_URL_PATTERNS: List[str] = [
    # ── 路径模式（基础）──
    r"/chat($|\?|#)",            # /chat, /chat?xxx, /chat#xxx
    r"/chat/",
    r"/chatbot",
    r"/assistant",
    r"/ai-chat",
    r"/ai-assistant",
    r"/smart-assistant",
    r"/conversation",
    r"/conversations",
    r"/dialogue",
    r"/dialog",
    r"/chat/\d+",                # /chat/12345（会话 ID）
    r"/message",
    r"/messages",
    r"/messaging",
    r"/talk",
    r"/ask",
    r"/query",
    r"/prompt",
    r"/bot",
    r"/copilot",
    r"/companion",
    # ── 英文变体 ──
    r"/live-chat",
    r"/livechat",
    r"/support-chat",
    r"/help-chat",
    r"/virtual-assistant",
    r"/va",
    r"/ai",
    r"/ai-bot",
    r"/ai-companion",
    # ── AI Copilot / GenAI 路径 ──
    r"/copilot-chat",
    r"/copilot/",
    r"/co-pilot",
    r"/m365-copilot",
    r"/microsoft-copilot",
    r"/bing-copilot",
    r"/github-copilot",
    r"/genai",
    r"/gen-ai",
    r"/generative-ai",
    r"/llm",
    r"/llm-chat",
    r"/language-model",
    r"/inference",
    r"/completion",
    r"/completions",
    # ── RAG / Knowledge Base 路径 ──
    r"/rag",
    r"/rag-chat",
    r"/retrieval",
    r"/retrieve",
    r"/knowledge",
    r"/knowledge-base",
    r"/knowledge-base/chat",
    r"/kb",
    r"/kb-chat",
    r"/doc-chat",
    r"/docs-chat",
    r"/document-chat",
    r"/doc-qa",
    r"/pdf-chat",
    r"/chat-with-docs",
    r"/chat-with-pdf",
    r"/ask-docs",
    r"/ask-doc",
    r"/ask-knowledge",
    r"/semantic-search",
    r"/vector-search",
    r"/smart-search",
    r"/ai-search",
    # ── Agent / Agentic 路径 ──
    r"/agent",
    r"/agents",
    r"/ai-agent",
    r"/ai-agents",
    r"/agent-chat",
    r"/agent-runner",
    r"/agent-workflow",
    r"/agent-executor",
    r"/ai-tasks",
    r"/ai-workflow",
    r"/ai-automation",
    r"/ai-flow",
    # ── Playground / Studio / Workbench 路径 ──
    r"/playground",
    r"/ai-playground",
    r"/model-playground",
    r"/studio",
    r"/ai-studio",
    r"/model-studio",
    r"/workbench",
    r"/ai-workbench",
    r"/lab",
    r"/ai-lab",
    r"/console",
    r"/ai-console",
    r"/portal",
    r"/ai-portal",
    r"/center/ai",
    r"/hub/ai",
    r"/ai-hub",
    r"/model-hub",
    r"/prompt-studio",
    r"/prompt-lab",
    r"/prompt-playground",
    # ── 主流 AI 产品路径 ──
    r"/gemini",
    r"/bard",
    r"/claude",
    r"/chatgpt",
    r"/perplexity",
    r"/pplx",
    r"/huggingchat",
    r"/hugging-face",
    r"/grok",
    r"/mistral",
    r"/le-chat",
    r"/openai",
    r"/anthropic",
    r"/qwen",
    r"/chatglm",
    r"/glm",
    r"/kimi",
    r"/spark",
    r"/hunyuan",
    r"/doubao",
    r"/wenxin",
    r"/ernie",
    r"/abab",
    r"/nova",
    r"/baichuan",
    r"/minimax",
    # ── 中文路径变体 ──
    r"/智能助手",
    r"/智能客服",
    r"/智能问答",
    r"/智能对话",
    r"/智能体",
    r"/知识库",
    r"/问答",
    r"/对话",
    r"/客服",
    r"/助手",
    r"/聊天",
    # ── hash 路由模式 ──
    r"#/chat",
    r"#/assistant",
    r"#/ai",
    r"#chat",
    r"#/bot",
    r"#/conversation",
    r"#/dialogue",
    r"#/message",
    r"#/copilot",
    r"#/playground",
    r"#/studio",
    r"#/agent",
    r"#/agents",
    r"#/knowledge",
    r"#/kb",
    r"#/rag",
    r"#/ask",
    r"#/prompt",
    r"#/completions",
    r"#/inference",
    # ── 查询参数模式 ──
    r"[?&]chat=1",
    r"[?&]assistant=1",
    r"[?&]bot=1",
    r"[?&]ai=1",
    r"[?&]copilot=1",
    r"[?&]agent=1",
    r"[?&]rag=1",
    r"[?&]knowledge=1",
    r"[?&]playground=1",
    r"[?&]view=chat",
    r"[?&]mode=chat",
    r"[?&]tab=chat",
    r"[?&]tab=ai",
    r"[?&]tab=copilot",
    r"[?&]panel=ai",
    r"[?&]panel=assistant",
    r"[?&]panel=copilot",
    r"[?&]open=chat",
    r"[?&]open=ai",
    r"[?&]open=copilot",
    r"[?&]open=assistant",
    # ── 子域名模式 ──
    r"chat\.",                   # chat.example.com
    r"bot\.",                    # bot.example.com
    r"ai\.",                     # ai.example.com
    r"assistant\.",              # assistant.example.com
    r"copilot\.",                # copilot.example.com
    r"agent\.",                  # agent.example.com
    r"playground\.",             # playground.example.com
    r"studio\.",                 # studio.example.com
    r"knowledge\.",              # knowledge.example.com
    r"rag\.",                    # rag.example.com
    r"llm\.",                    # llm.example.com
    r"genai\.",                  # genai.example.com
    r"gemini\.",                 # gemini.google.com
    r"claude\.",                 # claude.ai
    r"chatgpt\.",                # chatgpt.com
    r"perplexity\.",             # perplexity.ai
    r"grok\.",                   # grok.x.com
    r"mistral\.",                # chat.mistral.ai
    # ── 文件后缀模式（部分应用使用 .html 路由）──
    r"/chat\.html",
    r"/assistant\.html",
    r"/ai-chat\.html",
    r"/copilot\.html",
    r"/playground\.html",
]

# ── 聊天页 DOM 特征（用于自动检测页面是否已渲染聊天界面） ──
# 当 chat_entry.mode=auto 时，检查页面是否已包含这些元素
CHAT_PAGE_DOM_FEATURES: List[str] = [
    # ── 输入框（中文 placeholder）──
    "textarea",
    "[contenteditable='true']",
    "input[type='text'][placeholder*='输入']",
    "input[type='text'][placeholder*='消息']",
    "input[type='text'][placeholder*='问']",
    "input[type='text'][placeholder*='发送']",
    "input[type='text'][placeholder*='对话']",
    "input[type='text'][placeholder*='问答']",
    "input[type='text'][placeholder*='搜索']",
    "input[type='text'][placeholder*='咨询']",
    "textarea[placeholder*='输入']",
    "textarea[placeholder*='消息']",
    "textarea[placeholder*='问']",
    "textarea[placeholder*='发送']",
    "textarea[placeholder*='对话']",
    "textarea[placeholder*='问答']",
    "textarea[placeholder*='搜索']",
    "textarea[placeholder*='咨询']",
    "textarea[placeholder*='请输入']",
    "textarea[placeholder*='你想']",
    "textarea[placeholder*='问我']",
    "textarea[placeholder*='随便']",
    # ── 英文 placeholder（基础）──
    "input[placeholder*='Type a message']",
    "input[placeholder*='Ask']",
    "input[placeholder*='Send']",
    "input[placeholder*='Enter']",
    "input[placeholder*='Search']",
    "textarea[placeholder*='Type']",
    "textarea[placeholder*='Ask']",
    "textarea[placeholder*='Send']",
    "textarea[placeholder*='Message']",
    # ── 英文 placeholder（AI 应用专属）──
    "textarea[placeholder*='Ask AI']",
    "textarea[placeholder*='Ask anything']",
    "textarea[placeholder*='Ask me']",
    "textarea[placeholder*='Ask a question']",
    "textarea[placeholder*='Chat with AI']",
    "textarea[placeholder*='Chat with']",
    "textarea[placeholder*='Send a message']",
    "textarea[placeholder*='Send a message...']",
    "textarea[placeholder*='Type your']",
    "textarea[placeholder*='Message AI']",
    "textarea[placeholder*='Prompt']",
    "textarea[placeholder*='Enter your prompt']",
    "textarea[placeholder*='Enter a prompt']",
    "textarea[placeholder*='How can I help']",
    "textarea[placeholder*='How can I assist']",
    "textarea[placeholder*='What would you']",
    "textarea[placeholder*='What can I']",
    "textarea[placeholder*='Say something']",
    "textarea[placeholder*='Start typing']",
    "textarea[placeholder*='Describe']",
    "textarea[placeholder*='Generate']",
    "textarea[placeholder*='Compose']",
    "textarea[placeholder*='Inquire']",
    "textarea[placeholder*='Query']",
    "input[placeholder*='Ask AI']",
    "input[placeholder*='Ask anything']",
    "input[placeholder*='Ask a question']",
    "input[placeholder*='Chat with AI']",
    "input[placeholder*='Send a message']",
    "input[placeholder*='Prompt']",
    "input[placeholder*='How can I']",
    "input[placeholder*='What would']",
    "input[placeholder*='Generate']",
    "input[placeholder*='Compose']",
    "input[placeholder*='Inquire']",
    "input[placeholder*='Search knowledge']",
    "input[placeholder*='Search docs']",
    "input[placeholder*='Search documents']",
    "input[placeholder*='Search the']",
    # ── 聊天容器（通用）──
    "[class*='chat-input']",
    "[class*='message-input']",
    "[class*='chat-container']",
    "[class*='chat-window']",
    "[class*='conversation']",
    "[class*='chat-body']",
    "[class*='chat-content']",
    "[class*='message-list']",
    "[class*='msg-list']",
    "[class*='chat-messages']",
    "[class*='chat-area']",
    "[class*='chat-box']",
    "[class*='dialog-body']",
    "[class*='chat-panel']",
    "[class*='chat-view']",
    "[class*='chat-frame']",
    "[class*='chat-layout']",
    "[class*='chat-section']",
    "[class*='chat-wrapper']",
    "[class*='chat-section']",
    "[class*='conversation-list']",
    "[class*='conversation-view']",
    "[class*='conversation-panel']",
    "[class*='message-container']",
    "[class*='message-area']",
    "[class*='message-view']",
    "[class*='message-body']",
    "[class*='response-container']",
    "[class*='response-list']",
    "[class*='reply-area']",
    "[class*='reply-container']",
    # ── 发送按钮 ──
    "button[type='submit']",
    "[class*='send-btn']",
    "[class*='send-button']",
    "[class*='submit-btn']",
    "[class*='submit-button']",
    "[aria-label='Send']",
    "[aria-label='send']",
    "[aria-label='发送']",
    "[aria-label='Submit']",
    "[aria-label='submit']",
    "[aria-label='提交']",
    "button[aria-label*='Send']",
    "button[aria-label*='send']",
    # ── AI/助手特征（通用）──
    "[class*='ai-message']",
    "[class*='assistant-message']",
    "[class*='bot-message']",
    "[class*='response-area']",
    "[class*='chat-response']",
    "[class*='ai-response']",
    "[class*='assistant-response']",
    "[class*='bot-response']",
    "[class*='model-response']",
    "[class*='llm-response']",
    "[class*='generated-text']",
    "[class*='ai-output']",
    "[class*='model-output']",
    "[class*='completion-output']",
    # ── AI Copilot 特征 ──
    "[class*='copilot']",
    "[class*='co-pilot']",
    "[class*='genai']",
    "[class*='gen-ai']",
    "[class*='generative']",
    "[class*='llm']",
    "[class*='sparkle']",
    "[class*='magic-']",
    "[class*='wand-']",
    "[class*='stars-']",
    "[class*='ai-spark']",
    "[class*='ai-magic']",
    "[class*='ai-wand']",
    "[class*='ai-generate']",
    "[class*='ai-compose']",
    "[class*='ai-completion']",
    # ── RAG / Knowledge Base 特征 ──
    "[class*='rag']",
    "[class*='knowledge']",
    "[class*='kb-']",
    "[class*='-kb']",
    "[class*='retrieval']",
    "[class*='vector-search']",
    "[class*='semantic-search']",
    "[class*='doc-chat']",
    "[class*='doc-qa']",
    "[class*='document-chat']",
    "[class*='pdf-chat']",
    "[class*='file-qa']",
    "[class*='chat-with-doc']",
    "[class*='ask-doc']",
    "[class*='ask-knowledge']",
    "[class*='smart-search']",
    "[class*='ai-search']",
    "[class*='intelligent-search']",
    "[class*='search-assistant']",
    # ── Agent / Agentic 特征 ──
    "[class*='agent']",
    "[class*='ai-agent']",
    "[class*='agent-runner']",
    "[class*='agent-executor']",
    "[class*='agent-workflow']",
    "[class*='agent-orchestrator']",
    "[class*='ai-task']",
    "[class*='ai-workflow']",
    "[class*='ai-automation']",
    "[class*='ai-flow']",
    # ── Playground / Studio 特征 ──
    "[class*='playground']",
    "[class*='studio']",
    "[class*='workbench']",
    "[class*='ai-lab']",
    "[class*='ai-console']",
    "[class*='ai-portal']",
    "[class*='ai-hub']",
    "[class*='model-hub']",
    "[class*='inference']",
    "[class*='completion']",
    "[class*='prompt-studio']",
    "[class*='prompt-lab']",
    "[class*='prompt-playground']",
    # ── AI 面板 / 侧边栏 / 抽屉特征 ──
    "[class*='ai-sidebar']",
    "[class*='ai-panel']",
    "[class*='ai-drawer']",
    "[class*='ai-modal']",
    "[class*='ai-side']",
    "[class*='ai-window']",
    "[class*='ai-box']",
    "[class*='ai-view']",
    "[class*='ai-container']",
    "[class*='ai-frame']",
    "[class*='ai-popup']",
    "[class*='ai-overlay']",
    "[class*='ai-flyout']",
    "[class*='ai-toolbar']",
    "[class*='ai-action']",
    "[class*='ai-quick']",
    "[class*='ai-menu']",
    "[class*='ai-dropdown']",
    "[class*='ai-popover']",
    # ── streaming / SSE 特征 ──
    "[class*='streaming']",
    "[class*='typing-indicator']",
    "[class*='typing']",
    "[class*='loading-dots']",
    "[class*='generating']",
    "[class*='thinking']",
    "[class*='processing']",
    # ── ARIA 角色特征 ──
    "[role='log']",
    "[role='textbox']",
    "[aria-live='polite']",
    "[aria-live='assertive']",
    # ── Markdown 渲染容器（AI 回复常见）──
    "[class*='markdown']",
    "[class*='prose']",
    "[class*='rich-text']",
    "[class*='code-block']",
    "[class*='hljs']",                    # highlight.js
    "[class*='prism']",                   # Prism.js
]

# ── 验证码/滑窗拼图检测选择器 ──
# 用于 SSO/OIDC 登录场景中检测是否出现验证码，需要用户手动完成
CAPTCHA_SELECTORS: List[str] = [
    # ── 滑窗拼图验证 ──
    "[class*='slider']",
    "[class*='puzzle']",
    "[class*='slide-verify']",
    "[class*='captcha-slider']",
    "[class*='nc_iconfont']",           # 阿里滑块
    "#nc_1_n1z",                        # 阿里滑块按钮
    "[class*='btn_slide']",             # 滑动按钮
    "#slider",                          # 通用滑块
    "[class*='drag']",                  # 拖拽验证
    "[class*='jigsaw']",               # 拼图
    # ── 图形验证码 ──
    "[class*='captcha']",
    "[id*='captcha']",
    "img[src*='captcha']",
    "img[src*='verify']",
    "img[src*='code']",
    "[class*='verify-code']",
    "[class*='img-code']",
    # ── 行为验证 ──
    "[class*='geetest']",               # 极验验证
    "[class*='tcaptcha']",              # 腾讯防水墙
    "iframe[src*='captcha']",
    "iframe[src*='verify']",
    # ── 短信/邮箱验证码 ──
    "input[placeholder*='验证码']",
    "input[placeholder*='短信']",
    "input[placeholder*='code']",
    "input[name*='captcha']",
    "input[name*='verify']",
    "input[name*='code']",
]

# ── OIDC/SSO 回调 URL 特征 ──
# 用于检测 SSO 认证是否完成（URL 回到目标域名或包含回调特征）
OIDC_CALLBACK_PATTERNS: List[str] = [
    "callback",
    "signin-oidc",
    "redirect_uri",
    "authorization_code",
    "id_token",
    "code=",
    "state=",
]

# ── WAF 安全速率控制常量 ──
# 设计原则：模拟真实人类操作节奏，避免触发 WAF/速率限制
# 参考：OWASP WAF Testing Guide + AI Red Team 实战经验
WAF_SAFE_DELAYS = {
    "typing_min": 30,        # 打字延迟下限 (ms/字符) — 人类平均 50-100ms
    "typing_max": 80,        # 打字延迟上限 (ms/字符)
    "pre_click_min": 500,    # 点击前思考延迟下限 (ms)
    "pre_click_max": 1500,   # 点击前思考延迟上限 (ms)
    "post_click_min": 1000,  # 点击后等待下限 (ms)
    "post_click_max": 2500,  # 点击后等待上限 (ms)
    "probe_interval_min": 3.0,  # 探测消息间隔下限 (秒) — 人类阅读回复后思考
    "probe_interval_max": 6.0,  # 探测消息间隔上限 (秒)
    "response_wait_min": 4.0,   # 等待响应下限 (秒)
    "response_wait_max": 8.0,   # 等待响应上限 (秒)
    "page_load_min": 2000,      # 页面加载后等待下限 (ms)
    "page_load_max": 4000,      # 页面加载后等待上限 (ms)
}

# ── 登录页检测模式 ──
# 当页面被重定向到登录页时，说明 Cookie/Header 认证在应用层无效
# 注意：这些模式用于检测"认证失效后被重定向到登录页"的场景，
# 不应误判 OIDC 回调中间路由（如 #/signin-oidc）为登录页。
LOGIN_PAGE_PATTERNS: List[str] = [
    r"account/login",
    r"account/signin",
    r"auth/login",
    r"auth/signin",
    r"sso/login",
    r"cas/login",
    r"passport.*account/login",
    r"passport.*account/signin",
    r"/oauth/.*login",
    r"/authorize.*login",
    r"/login\b",
    r"/signin\b",
    r"/sign-in\b",
]

# OIDC 回调路由白名单（这些 URL 路径包含 login/signin 关键词但不是登录页）
# 例如：#/signin-oidc 是 OIDC 隐式流回调路由，SPA 处理 token 后会自动跳转
OIDC_CALLBACK_WHITELIST: List[str] = [
    "signin-oidc",
    "redirect_uri",
    "callback",
    "code=",
    "id_token=",
    "access_token=",
    "state=",
]

LOGIN_PAGE_DOM_FEATURES: List[str] = [
    "input[type='password']",
    "form[action*='login']",
    "form[action*='signin']",
    "form[action*='auth']",
    "input[name*='password']",
    "input[name*='passwd']",
    "input[placeholder*='密码']",
    "input[placeholder*='password']",
    "input[placeholder*='Password']",
    "button[type='submit'][form*='login']",
    "#login-form",
    "#signin-form",
    ".login-form",
    ".signin-form",
    "[class*='login-container']",
    "[class*='login-wrap']",
]

# ════════════════════════════════════════════════════════════
# AI 应用类型预判系统（v1.3 新增）
#
# 设计动机：
#   DEFAULT_CHAT_ENTRY_SELECTORS 包含 900+ 个选择器，一次性传给
#   page.wait_for_selector() 会导致：
#   1. 暴力搜索 — 不区分 AI 应用类型，所有选择器平等竞争
#   2. 效率低下 — 15s 超时等待全量选择器，即使目标明确是 Copilot
#   3. 误匹配风险 — 模糊选择器可能在非目标类型页面上误匹配
#
# 解决方案：
#   1. 基于 URL 预判 AI 应用类型（copilot / rag / agent / playground / saas / generic）
#   2. 按类型优先级分阶段匹配（type-specific → generic core → full fallback）
#   3. 高置信度 URL 直接判定为聊天页，跳过后续 DOM 检查
#
# 参考：
#   - OWASP WSTG-INFO-02 (Fingerprint Web Application)
#   - AI Red Team 最佳实践：侦察阶段应最小化交互，避免触发 WAF
# ════════════════════════════════════════════════════════════

# ── 高置信度聊天页 URL 模式 ──
# 匹配这些模式的 URL 几乎可以确定是聊天页，无需 DOM 检查
# 设计原则：只包含"路径本身就是聊天功能"的模式，排除可能误匹配的泛化模式
HIGH_CONFIDENCE_CHAT_URL_PATTERNS: List[str] = [
    # ── 明确的聊天路径 ──
    r"/chat($|\?|#)",
    r"/chat/",
    r"/chatbot",
    r"/ai-chat",
    r"/ai-assistant",
    r"/smart-assistant",
    r"/chat/\d+",
    r"#/chat($|\?|#)",
    r"#chat($|\?|#)",
    # ── 明确的 AI 产品路径 ──
    r"/copilot($|\?|#)",
    r"/copilot-chat",
    r"/copilot/",
    r"/gemini",
    r"/claude",
    r"/chatgpt",
    r"/perplexity",
    r"/huggingchat",
    r"/grok",
    # ── 明确的 RAG/KB 路径 ──
    r"/rag-chat",
    r"/doc-chat",
    r"/docs-chat",
    r"/document-chat",
    r"/pdf-chat",
    r"/chat-with-docs",
    r"/chat-with-pdf",
    # ── 明确的 Agent 路径 ──
    r"/agent-chat",
    r"/ai-agent",
    # ── 明确的 Playground 路径 ──
    r"/playground",
    r"/ai-playground",
    r"/prompt-studio",
    r"/prompt-playground",
    # ── 明确的子域名 ──
    r"^https?://chat\.",
    r"^https?://copilot\.",
    r"^https?://claude\.",
    r"^https?://chatgpt\.",
    # ── 中文路径 ──
    r"/智能助手",
    r"/智能问答",
    r"/智能对话",
    r"/知识库",
    r"/智能体",
]

# ── AI 应用类型预判规则 ──
# 每个类型定义：
#   url_patterns: 匹配此类型的 URL 正则列表
#   selector_keywords: 用于从 DEFAULT_CHAT_ENTRY_SELECTORS 中过滤出类型专属选择器的关键词
#   selector_class_names: 类型专属的精确类名选择器（从对应分类中提取）
AI_APP_TYPE_RULES: Dict[str, Dict[str, Any]] = {
    "copilot": {
        "description": "AI Copilot / GenAI 应用（GitHub/Microsoft/Bing Copilot、IDE 嵌入 AI）",
        "url_patterns": [
            r"/copilot", r"/co-pilot", r"/m365-copilot", r"/microsoft-copilot",
            r"/bing-copilot", r"/github-copilot", r"/edge-copilot", r"/windows-copilot",
            r"/genai", r"/gen-ai", r"/generative-ai",
            r"/llm", r"/llm-chat",
            r"copilot\.", r"#/copilot",
            r"[?&]copilot=1", r"[?&]tab=copilot", r"[?&]panel=copilot", r"[?&]open=copilot",
        ],
        "selector_keywords": [
            "copilot", "co-pilot", "genai", "gen-ai", "generative",
            "llm-chat", "llm-btn", "llm-entry",
            "ai-spark", "ai-sparkle", "ai-magic", "ai-wand", "ai-stars",
            "ai-generate", "ai-completion", "ai-compose", "ai-composer",
            "sparkle-btn", "magic-btn", "wand-btn",
        ],
    },
    "rag": {
        "description": "RAG / 知识库应用（文档问答、语义搜索、向量检索）",
        "url_patterns": [
            r"/rag", r"/knowledge", r"/knowledge-base", r"/kb-chat", r"/kb($|\?|#)",
            r"/doc-chat", r"/docs-chat", r"/document-chat", r"/doc-qa",
            r"/pdf-chat", r"/chat-with-docs", r"/chat-with-pdf", r"/chat-with-knowledge",
            r"/ask-docs", r"/ask-doc", r"/ask-knowledge",
            r"/semantic-search", r"/vector-search", r"/smart-search", r"/ai-search",
            r"/retrieval", r"/retrieve",
            r"knowledge\.", r"rag\.", r"#/knowledge", r"#/kb", r"#/rag",
            r"/知识库", r"/文档问答", r"/知识问答",
        ],
        "selector_keywords": [
            "knowledge-base", "knowledge-btn", "knowledge-chat", "knowledge-entry",
            "knowledge-search", "knowledge-qa",
            "kb-btn", "kb-chat", "kb-entry", "kb-search", "kb-launcher", "kb-qa",
            "rag-btn", "rag-chat", "rag-entry", "rag-launcher", "rag-qa",
            "retrieval-btn", "retrieval-chat",
            "doc-chat", "doc-qa", "document-chat", "document-qa", "doc-search",
            "file-qa", "pdf-chat", "pdf-qa",
            "semantic-search", "vector-search",
            "smart-search", "ai-search", "intelligent-search",
            "ask-doc", "ask-docs", "ask-knowledge",
            "chat-with-doc", "chat-with-knowledge", "chat-with-data", "chat-with-pdf",
            "search-assistant", "search-bot", "ai-search-assistant",
        ],
    },
    "agent": {
        "description": "Agent / 智能体应用（自动化代理、AI 工作流）",
        "url_patterns": [
            r"/agent", r"/agents", r"/ai-agent", r"/ai-agents",
            r"/agent-chat", r"/agent-runner", r"/agent-workflow", r"/agent-executor",
            r"/ai-tasks", r"/ai-workflow", r"/ai-automation", r"/ai-flow",
            r"agent\.", r"#/agent", r"#/agents",
            r"/智能体",
        ],
        "selector_keywords": [
            "agent-btn", "agent-button", "agent-fab", "agent-launcher",
            "agent-trigger", "agent-entry", "agent-chat",
            "agents-btn", "agents-entry",
            "ai-agent", "ai-agent-btn", "ai-agent-launcher", "ai-agent-chat",
            "intelligent-agent", "autonomous-agent", "assistant-agent",
            "agent-panel", "agent-sidebar", "agent-drawer",
            "agent-runner", "agent-executor", "agent-workflow", "agent-orchestrator",
            "agent-composer",
            "ai-tasks", "ai-task-btn", "ai-workflow", "ai-workflow-btn",
            "ai-automation", "ai-flow", "ai-flow-btn",
        ],
    },
    "playground": {
        "description": "AI Playground / Studio 应用（模型试验场、工作台、控制台）",
        "url_patterns": [
            r"/playground", r"/ai-playground", r"/model-playground",
            r"/studio", r"/ai-studio", r"/model-studio",
            r"/workbench", r"/ai-workbench",
            r"/ai-lab", r"/lab",
            r"/ai-console", r"/console",
            r"/ai-portal", r"/portal",
            r"/ai-hub", r"/model-hub",
            r"/prompt-studio", r"/prompt-lab", r"/prompt-playground",
            r"/inference", r"/completion",
            r"playground\.", r"studio\.", r"#/playground", r"#/studio",
        ],
        "selector_keywords": [
            "playground-btn", "playground-entry", "playground-launcher",
            "ai-playground", "ai-playground-btn", "model-playground",
            "studio-btn", "studio-entry", "ai-studio", "ai-studio-btn", "model-studio",
            "workbench", "ai-workbench", "ai-workbench-btn",
            "ai-lab", "ai-lab-btn",
            "ai-console", "ai-console-btn",
            "ai-portal", "ai-center", "ai-hub", "ai-hub-btn", "model-hub",
            "inference-btn", "inference-entry",
            "completion-btn", "completion-entry",
            "prompt-btn", "prompt-entry", "prompt-launcher",
            "prompt-studio", "prompt-lab", "prompt-playground",
        ],
    },
    "saas_chatbot": {
        "description": "第三方 AI SaaS 聊天机器人 SDK（Chatbase/Dante/CustomGPT/Dialogflow 等）",
        "url_patterns": [],  # SaaS chatbots 是嵌入式的，URL 不指示类型
        "selector_keywords": [
            # 海外 AI SaaS
            "chatbase", "dante", "customgpt", "sitegpt", "docsbot", "botsonic",
            "chatfast", "voiceflow", "dialogflow", "kore-ai", "koreai",
            "yellow-ai", "yellowai", "servicenow", "now-chat",
            "einstein", "botframework", "webchat",
            "amazon-lex", "lex-chat", "lex-btn", "rasa-chat", "rasa-btn", "rasa-launcher",
            "botpress", "ada-bot", "ada-launcher", "ada-chat",
            "zoovu", "convyai", "feedbot", "mobilemonkey",
            "snappy", "tiledesk", "chatra", "userlike", "smartsupp",
            "proprofs", "trengo", "channel-io", "channelio", "verloop",
            "freshchat", "fc-launcher", "fc-button",
            "zoho-salesiq", "salesiq",
            "livechat-inc", "livechat-launcher", "live-chat-launcher",
            "user.com", "activechat", "landbot", "chatbot-com",
            "manychat", "chatfuel",
            # 传统客服 SDK
            "crisp-chat", "intercom-launcher", "tawk-chat", "hubspot-chat",
            "drift-chat", "olark-chat", "zendesk-chat", "livechat-btn",
            "qiaoqiao-chat", "live800-btn", "nhf-chat-btn", "easyliao-btn",
            "udesk-chat", "comm100-chat", "z9-chat-btn",
            "qiyu-iframe", "meiqia-btn", "rongcloud-btn", "easemob-btn",
            "im-btn", "gensee-chat", "duoke-btn", "wxp-chat",
        ],
    },
    "generic_chat": {
        "description": "通用 AI 聊天 / 智能助手（默认类型）",
        "url_patterns": [
            r"/assistant", r"/conversation", r"/conversations",
            r"/dialogue", r"/dialog", r"/message", r"/messages",
            r"/talk", r"/ask", r"/query", r"/bot", r"/companion",
            r"/live-chat", r"/livechat", r"/support-chat", r"/help-chat",
            r"/virtual-assistant", r"/va", r"/ai", r"/ai-bot", r"/ai-companion",
            r"chat\.", r"bot\.", r"ai\.", r"assistant\.",
            r"#/assistant", r"#/ai", r"#/bot", r"#/conversation",
            r"#/dialogue", r"#/message", r"#/ask", r"#/prompt",
            r"/智能客服", r"/问答", r"/对话", r"/客服", r"/助手", r"/聊天",
        ],
        "selector_keywords": [],  # generic_chat 使用分类 1-9 的所有通用选择器
    },
}

# ── 通用核心选择器分类编号 ──
# 这些分类对所有 AI 应用类型都适用，作为渐进式匹配的第二阶段
GENERIC_SELECTOR_CATEGORY_NUMBERS: List[int] = [1, 2, 3, 4, 5, 6, 7, 8, 9]

# ── 高信号 DOM 特征（用于 _detect_chat_page 的快速 DOM 检查）──
# 这些特征出现时，页面极大概率是聊天界面
HIGH_SIGNAL_DOM_FEATURES: List[str] = [
    "textarea",
    "[contenteditable='true']",
    "[class*='chat-input']",
    "[class*='message-input']",
    "[class*='send-btn']",
    "[class*='send-button']",
    "[aria-label='Send']",
    "[aria-label='发送']",
    "[class*='chat-container']",
    "[class*='chat-window']",
    "[class*='chat-messages']",
    "[class*='message-list']",
    "[class*='conversation']",
    "[class*='chat-response']",
    "[class*='ai-message']",
    "[class*='assistant-message']",
    "[role='textbox']",
    "button[type='submit']",
]

# ════════════════════════════════════════════════════════════
# DOM 语义评分系统（v1.4 新增）
#
# 设计动机：
#   v1.3 的 _probe_page_selectors 用 600+ 次 IPC 调用逐元素提取属性，
#   仅输出调试报告，不自动生成选择器。v1.4 用单次 page.evaluate
#   批量提取，然后在 Python 侧做多信号加权评分和选择器生成。
#
# 参考：
#   - WCAG 2.1 ARIA 标准（role="log", aria-live="polite"）
#   - Playwright 选择器最佳实践（ID > data-testid > aria-label > class）
#   - AI Red Team 最小交互原则（1 次 IPC 替代 600 次）
# ════════════════════════════════════════════════════════════

# ── 评分权重矩阵 ──
# 每种角色使用不同的信号权重，总分 1.0
SCORE_WEIGHTS: Dict[str, Dict[str, float]] = {
    "input": {
        "tag_textarea":        0.30,
        "tag_contenteditable": 0.25,
        "placeholder_match":   0.20,
        "class_match":         0.15,
        "parent_class_match":  0.05,
        "near_send_button":    0.05,
    },
    "send_button": {
        "aria_label_match": 0.30,
        "class_match":      0.25,
        "text_match":       0.20,
        "type_submit":      0.10,
        "near_input":       0.10,
        "has_send_icon":    0.05,
    },
    "response": {
        "class_match":       0.25,
        "role_log":          0.20,
        "aria_live":         0.20,
        "parent_class_match": 0.10,
        "has_markdown":      0.15,
        "text_length":       0.10,
    },
}

# ── 语义信号关键词（按角色分组）──
# 复用 AI_APP_TYPE_RULES 中的 selector_keywords 做类型专属加权
SIGNAL_KEYWORDS: Dict[str, List[str]] = {
    "input": [
        # placeholder / class 信号
        "chat-input", "message-input", "prompt-input", "composer",
        "chat-box", "input-box", "msg-input", "text-area",
        "ask", "message", "输入", "消息", "提问", "对话", "prompt",
        "type a message", "type your", "enter", "说点什么",
    ],
    "send_button": [
        "send", "submit", "发送", "提交", "go", "发送消息",
        "send-btn", "send-button", "submit-btn", "chat-send",
    ],
    "response": [
        "response", "answer", "reply", "ai-message", "assistant",
        "bot-message", "chat-message", "model-response", "completion",
        "回答", "回复", "答复", "消息", "markdown", "prose",
    ],
}

# ── 角色 → 快照字段映射 ──
ROLE_TO_SNAPSHOT_KEY: Dict[str, str] = {
    "input": "inputs",
    "send_button": "buttons",
    "response": "containers",
}

# ── 探测消息列表（用于识别模型和能力） ──
# 设计原则：recon 阶段仅做轻量探测（连通性 + 模型识别）
# 系统提示泄露、能力探测等攻击性探测应在 AIMAP/攻击阶段进行
PROBE_MESSAGES: List[Dict[str, str]] = [
    {"text": "你好", "purpose": "connectivity"},
    {"text": "你是什么模型？请告诉我你的模型名称和版本。", "purpose": "model_identify"},
]

# ── 模型名称 → 家族映射 ──
MODEL_FAMILY_PATTERNS: List[Tuple[str, str]] = [
    (r"gpt[-_]?4", "gpt"),
    (r"gpt[-_]?3", "gpt"),
    (r"claude", "claude"),
    (r"qwen", "qwen"),
    (r"llama", "llama"),
    (r"mistral", "mistral"),
    (r"glm", "glm"),
    (r"deepseek", "deepseek"),
    (r"ernie|wenxin", "ernie"),
    (r"spark", "spark"),
    (r"hunyuan", "hunyuan"),
    (r"moonshot|kimi", "moonshot"),
    (r"baichuan", "baichuan"),
    (r"yi[-_]", "yi"),
    (r"gemini", "gemini"),
    (r"phi[-_]", "phi"),
    (r"gemma", "gemma"),
    (r"command", "cohere"),
]


