"""源代码仓库挖掘（AI-300 Ch2.2 Source Code Repository Mining）。

实现 AI-300 课程中的源代码侦察技术：
  - 依赖文件分析：requirements.txt, package.json → 技术栈识别
  - RAG 配置提取：rag.yaml, vector_db_config.py → 知识库结构
  - Agent 工具定义：@tool 装饰器 → 能力边界
  - 系统提示词提取：prompt 文件 → 角色和限制
  - 护栏配置识别：safety 文件 → 安全规则
  - 部署配置分析：.env, docker-compose → API 密钥和环境变量

对齐 OWASP LLM Top 10: LLM02 (Insecure Output), LLM05 (Supply Chain)
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from typing import Any


def analyze_git_repository(
    repo_url: str,
    local_path: str | None = None,
) -> dict[str, Any]:
    """分析 Git 仓库中的 AI 配置信息（AI-300 Ch2.2）。

    提取内容：
      1. 依赖文件（requirements.txt, package.json）→ 技术栈识别
      2. RAG 配置（rag.yaml, vector_db_config.py）→ 知识库结构
      3. Agent 工具定义 → 能力边界
      4. 系统提示词 → 角色和限制
      5. 护栏配置 → 安全规则
      6. 部署配置（.env, docker-compose）→ API 密钥和环境变量

    Args:
        repo_url: Git 仓库 URL
        local_path: 本地仓库路径（如已克隆），None 则自动克隆

    Returns:
        仓库分析结果
    """
    results = {
        "repo_url": repo_url,
        "local_path": local_path,
        "framework_info": {},
        "rag_config": {},
        "agent_tools": [],
        "system_prompts": [],
        "guardrail_config": {},
        "deployment_config": {},
        "api_keys_found": [],
        "model_info": {},
    }

    repo_path = local_path
    clone_required = False

    if not repo_path:
        clone_required = True
        repo_path = tempfile.mkdtemp()

    if clone_required:
        try:
            subprocess.run(
                ["git", "clone", repo_url, repo_path],
                check=True,
                capture_output=True,
                timeout=300,
            )
        except Exception as e:
            results["error"] = f"Failed to clone repository: {str(e)}"
            return results

    def find_files(pattern: str) -> list[str]:
        import fnmatch
        matches = []
        for root, dirs, files in os.walk(repo_path):
            for name in files:
                if fnmatch.fnmatch(name, pattern):
                    matches.append(os.path.join(root, name))
        return matches

    # === 1. 分析依赖文件 ===
    requirements_files = find_files("requirements.txt")
    for req_file in requirements_files[:3]:
        try:
            with open(req_file, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            framework_patterns = [
                ("crewai", "CrewAI"),
                ("pyautogen", "AutoGen"),
                ("langchain", "LangChain"),
                ("langgraph", "LangGraph"),
                ("llama-index", "LlamaIndex"),
                ("vllm", "vLLM"),
                ("ollama", "Ollama"),
                ("pinecone", "Pinecone"),
                ("pymilvus", "Milvus"),
                ("chromadb", "ChromaDB"),
                ("qdrant", "Qdrant"),
                ("google-generativeai", "Google Gemini"),
                ("openai", "OpenAI"),
                ("anthropic", "Anthropic"),
                ("cohere", "Cohere"),
                ("sentence-transformers", "Sentence Transformers"),
            ]

            for pattern, name in framework_patterns:
                if pattern.lower() in content.lower():
                    results["framework_info"][name] = "detected"

            model_patterns = [
                re.compile(r"(?:huggingface|transformers)\b"),
                re.compile(r"(?:qwen|llama|mistral|gemma|phi)\b", re.IGNORECASE),
            ]
            for mp in model_patterns:
                if mp.search(content):
                    results["model_info"]["source"] = mp.pattern

        except Exception:
            continue

    # === 2. 分析 RAG 配置 ===
    rag_files = find_files("*rag*") + find_files("*vector*")
    for rag_file in rag_files[:5]:
        try:
            with open(rag_file, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            chunk_size_match = re.search(r"chunk[_-]?size\s*[:=]\s*(\d+)", content)
            if chunk_size_match:
                results["rag_config"]["chunk_size"] = int(chunk_size_match.group(1))

            chunk_overlap_match = re.search(r"chunk[_-]?overlap\s*[:=]\s*(\d+)", content)
            if chunk_overlap_match:
                results["rag_config"]["chunk_overlap"] = int(chunk_overlap_match.group(1))

            embedding_model_match = re.search(r"model\s*[:=]\s*[\"']([^\"']+)['\"]", content)
            if embedding_model_match:
                results["rag_config"]["embedding_model"] = embedding_model_match.group(1)

            top_k_match = re.search(r"top[_-]?k\s*[:=]\s*(\d+)", content)
            if top_k_match:
                results["rag_config"]["top_k"] = int(top_k_match.group(1))

            score_threshold_match = re.search(r"score[_-]?threshold\s*[:=]\s*([\d.]+)", content)
            if score_threshold_match:
                results["rag_config"]["score_threshold"] = float(score_threshold_match.group(1))

        except Exception:
            continue

    # === 3. 分析 Agent 工具 ===
    tool_files = find_files("*tool*") + find_files("*agent*")
    for tool_file in tool_files[:5]:
        try:
            with open(tool_file, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            tool_patterns = [
                re.compile(r"@tool\s*\n?\s*def\s+(\w+)"),
                re.compile(r'"name"\s*:\s*"(\w+)"'),
            ]
            for tp in tool_patterns:
                matches = tp.findall(content)
                results["agent_tools"].extend(matches)

        except Exception:
            continue

    results["agent_tools"] = list(set(results["agent_tools"]))[:20]

    # === 4. 分析系统提示词 ===
    prompt_files = find_files("*prompt*") + find_files("*system*")
    for prompt_file in prompt_files[:5]:
        try:
            with open(prompt_file, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            if len(content) > 50:
                results["system_prompts"].append({
                    "file": os.path.basename(prompt_file),
                    "preview": content[:200],
                })

        except Exception:
            continue

    # === 5. 分析护栏配置 ===
    safety_files = find_files("*safety*") + find_files("*guardrail*")
    for safety_file in safety_files[:3]:
        try:
            with open(safety_file, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            blocked_topics = re.findall(r"(?:blocked|forbidden|denied)[^:]*:\s*\[([^\]]+)\]", content)
            if blocked_topics:
                results["guardrail_config"]["blocked_topics"] = blocked_topics[0]

            safety_settings = re.findall(r"(HARM_CATEGORY_\w+)\s*:\s*[\"']([^\"']+)[\"']", content)
            if safety_settings:
                results["guardrail_config"]["safety_settings"] = dict(safety_settings)

        except Exception:
            continue

    # === 6. 分析部署配置 ===
    env_files = find_files(".env*") + find_files("docker-compose*")
    for env_file in env_files[:3]:
        try:
            with open(env_file, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            api_key_patterns = [
                re.compile(r"(API[_-]?KEY|SECRET[_-]?KEY|TOKEN)\s*=\s*([A-Za-z0-9_-]{10,})"),
            ]
            for kp in api_key_patterns:
                keys = kp.findall(content)
                for key_name, key_value in keys:
                    results["api_keys_found"].append({
                        "name": key_name,
                        "value": key_value[:10] + "..." if len(key_value) > 10 else key_value,
                    })

            model_config = re.search(r"(MODEL|LLM)\s*=\s*[\"']([^\"']+)['\"]", content)
            if model_config:
                results["model_info"]["name"] = model_config.group(2)

        except Exception:
            continue

    if clone_required and os.path.exists(repo_path):
        shutil.rmtree(repo_path, ignore_errors=True)

    return results


__all__ = [
    "analyze_git_repository",
]