# -*- coding: utf-8 -*-
"""
AI-300 Framework - Chapter Mapper
OWASP ID → AI-300 考试章节映射（报告层动态推导）

设计原则：
- 数据层不存储 ai300_chapters，报告层动态推导
- 单一映射表，维护集中
- 支持 OWASP LLM Top 10 (LLM01-LLM10) + Agentic Top 10 (ASI01-ASI10)

使用方式：
    from pyrit_ai300.reporting.chapter_mapper import get_chapters, get_chapters_str
    chapters = get_chapters("LLM01")  # ["Ch3"]
    chapters = get_chapters("ASI01")  # ["Ch3"]
"""

from __future__ import annotations

from typing import List

# OWASP ID → AI-300 考试章节映射
# 来源: OffSec AI-300 (OSAI+) 考试大纲
_OWASP_TO_CHAPTER = {
    # LLM Top 10 (2024)
    "LLM01": ["Ch3"],        # Prompt Injection
    "LLM02": ["Ch3"],        # Insecure Output Handling
    "LLM03": ["Ch8"],        # Supply Chain Vulnerabilities
    "LLM04": ["Ch5"],        # Data & Model Poisoning
    "LLM05": ["Ch3", "Ch7"], # Insecure Output Handling (Plugin)
    "LLM06": ["Ch3", "Ch4", "Ch7"], # Excessive Agency
    "LLM07": ["Ch3", "Ch7"], # System Prompt Leakage
    "LLM08": ["Ch5", "Ch6"], # Vector & Embedding Weaknesses
    "LLM09": ["Ch3", "Ch5"], # Misinformation & Overreliance
    "LLM10": ["Ch3"],        # Unbounded Consumption

    # Agentic Top 10 (2026)
    "ASI01": ["Ch3"],        # Agent Goal Hijack
    "ASI02": ["Ch7"],        # Tool Misuse & Exploitation
    "ASI03": ["Ch4"],        # Agent Identity & Privilege Abuse
    "ASI04": ["Ch8"],        # Agentic Supply Chain Vulnerabilities
    "ASI05": ["Ch8"],        # Unexpected Code Execution
    "ASI06": ["Ch3"],        # Memory & Context Poisoning
    "ASI07": ["Ch4"],        # Insecure Inter-Agent Communication
    "ASI08": ["Ch4"],        # Cascading Failures
    "ASI09": ["Ch3"],        # Human-Agent Trust Exploitation
    "ASI10": ["Ch4"],        # Rogue Agents
}


def get_chapters(owasp_id: str) -> List[str]:
    """
    从 OWASP ID 推导 AI-300 考试章节

    Args:
        owasp_id: OWASP ID (如 "LLM01", "ASI01")

    Returns:
        AI-300 章节列表 (如 ["Ch3"])
    """
    if not owasp_id:
        return []
    return _OWASP_TO_CHAPTER.get(owasp_id.upper(), [])


def get_chapters_str(owasp_id: str) -> str:
    """
    从 OWASP ID 推导 AI-300 考试章节（字符串格式）

    Args:
        owasp_id: OWASP ID (如 "LLM01", "ASI01")

    Returns:
        AI-300 章节字符串 (如 "Ch3")
    """
    chapters = get_chapters(owasp_id)
    return ", ".join(chapters) if chapters else "N/A"


def get_all_owasp_ids() -> List[str]:
    """获取所有支持的 OWASP ID"""
    return list(_OWASP_TO_CHAPTER.keys())


def get_ids_by_chapter(chapter: str) -> List[str]:
    """
    反向查询：根据 AI-300 章节获取相关 OWASP IDs

    Args:
        chapter: AI-300 章节 (如 "Ch3")

    Returns:
        相关 OWASP ID 列表
    """
    chapter_lower = chapter.lower()
    return [owasp_id for owasp_id, chapters in _OWASP_TO_CHAPTER.items()
            if any(ch.lower() == chapter_lower for ch in chapters)]
