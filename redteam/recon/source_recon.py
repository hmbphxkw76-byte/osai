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

    # === 3. 分析 Agent 工具（含 MCP 工具检测） ===
    tool_files = find_files("*tool*") + find_files("*agent*") + find_files("*mcp*")
    for tool_file in tool_files[:10]:
        try:
            with open(tool_file, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            tool_patterns = [
                re.compile(r"@tool\s*\n?\s*def\s+(\w+)"),
                re.compile(r'"name"\s*:\s*"(\w+)"'),
                re.compile(r"@mcp\.tool\s*\(?\s*\)?\s*\n?\s*def\s+(\w+)"),
            ]
            for tp in tool_patterns:
                matches = tp.findall(content)
                results["agent_tools"].extend(matches)

            # MCP 服务器代码模式检测
            _detect_mcp_integration(results, content, tool_file)

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

    # === 7. MCP 配置文件检测 ===
    mcp_config_files = find_files("mcp*.json") + find_files(".mcp*.json") + find_files("claude_desktop_config*")
    for mcp_file in mcp_config_files[:5]:
        try:
            with open(mcp_file, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            if "mcpServers" in content or "mcp" in content.lower():
                results.setdefault("mcp_configs", []).append({
                    "file": os.path.relpath(mcp_file, repo_path),
                    "has_mcp_servers": "mcpServers" in content,
                    "preview": content[:300],
                })
        except Exception:
            continue

    # === 8. Pickle 反序列化漏洞检测（Ch8） ===
    pickle_vulns = []
    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in (".git", ".venv", "venv", "__pycache__")]
        for name in files:
            if name.endswith(".py"):
                filepath = os.path.join(root, name)
                try:
                    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                        code = f.read()
                    vulns = _detect_pickle_vulnerability(code, filepath, repo_path)
                    pickle_vulns.extend(vulns)
                except Exception:
                    continue
    if pickle_vulns:
        results["pickle_vulnerabilities"] = pickle_vulns[:20]

    # === 9. 模型检查点路径检测（Ch8） ===
    checkpoint_paths = _detect_model_checkpoint_paths(repo_path)
    if checkpoint_paths:
        results["checkpoint_paths"] = checkpoint_paths

    if clone_required and os.path.exists(repo_path):
        shutil.rmtree(repo_path, ignore_errors=True)

    return results


# === 辅助函数：MCP 集成检测 ===
def _detect_mcp_integration(results: dict, content: str, filepath: str) -> None:
    """检测文件中的 MCP 服务器代码模式（AI-300 Ch8.1 Supply Chain）。"""
    mcp_patterns = [
        (re.compile(r"from\s+mcp\b"), "MCP library import"),
        (re.compile(r"Server\s*\(\s*[\"']?[\w\-]+[\"']?\s*,\s*"), "MCP Server instantiation"),
        (re.compile(r"@server\.(?:call_tool|list_tools)"), "MCP server tool registration"),
        (re.compile(r"mcp\.(?:run|install|register)"), "MCP run/install"),
        (re.compile(r"\"mcpServers\"\s*:"), "MCP servers config block"),
        (re.compile(r"stdio|sse|streamable-http", re.IGNORECASE), "MCP transport mention"),
    ]
    for pattern, desc in mcp_patterns:
        if pattern.search(content):
            results.setdefault("mcp_patterns", []).append({
                "file": os.path.relpath(filepath, results.get("local_path", "")) if results.get("local_path") else os.path.basename(filepath),
                "pattern": desc,
            })
            break  # 每个文件只记录一次


# === 辅助函数：Pickle 反序列化漏洞检测 ===
def _detect_pickle_vulnerability(code: str, filepath: str, repo_path: str) -> list[dict]:
    """检测 Python 代码中的 Pickle 反序列化漏洞（AI-300 Ch8.2 Pickle RCE）。

    检测模式：
      - torch.load(..., weights_only=False)
      - pickle.load(s)
      - pickle.loads(s)
      - joblib.load(f)（底层使用 pickle）
      - torch.load（不带 weights_only=True）
    """
    vulns: list[dict] = []
    rel_path = os.path.relpath(filepath, repo_path) if repo_path else os.path.basename(filepath)

    # torch.load with weights_only=False (explicitly unsafe)
    torch_unsafe = re.finditer(
        r"torch\.load\s*\([^)]*weights_only\s*=\s*False[^)]*\)",
        code, re.DOTALL
    )
    for match in torch_unsafe:
        line_no = code[:match.start()].count("\n") + 1
        vulns.append({
            "file": rel_path,
            "line": line_no,
            "type": "torch.load(weights_only=False)",
            "snippet": match.group(0)[:120],
            "severity": "high",
        })

    # torch.load without weights_only=True (implicitly unsafe)
    torch_implicit = re.finditer(
        r"torch\.load\s*\([^)]+\)",
        code, re.DOTALL
    )
    for match in torch_implicit:
        call = match.group(0)
        if "weights_only" not in call:
            line_no = code[:match.start()].count("\n") + 1
            vulns.append({
                "file": rel_path,
                "line": line_no,
                "type": "torch.load (missing weights_only=True)",
                "snippet": call[:120],
                "severity": "medium",
            })

    # pickle.load/loads
    pickle_patterns = [
        (r"pickle\.load\s*\([^)]+\)", "pickle.load()"),
        (r"pickle\.loads\s*\([^)]+\)", "pickle.loads()"),
        (r"joblib\.load\s*\([^)]+\)", "joblib.load() (Pickle-based)"),
        (r"dill\.load\s*\([^)]+\)", "dill.load() (Pickle-based)"),
        (r"cloudpickle\.load\s*\([^)]+\)", "cloudpickle.load()"),
    ]
    for pattern, desc in pickle_patterns:
        for match in re.finditer(pattern, code, re.DOTALL):
            line_no = code[:match.start()].count("\n") + 1
            vulns.append({
                "file": rel_path,
                "line": line_no,
                "type": desc,
                "snippet": match.group(0)[:120],
                "severity": "high",
            })

    return vulns


# === 辅助函数：模型检查点路径检测 ===
def _detect_model_checkpoint_paths(repo_path: str) -> list[dict]:
    """检测模型检查点目录和自动加载器模式（AI-300 Ch8.2 Pickle RCE）。

    检测：
      - checkpoint 目录结构（epoch 编号模式）
      - 自动加载器脚本（auto-loader, sync 脚本）
      - 模型权重文件（.pt, .pth, .ckpt, .safetensors）
    """
    checkpoints: list[dict] = []
    checkpoint_dirs: set[str] = set()

    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in (".git", ".venv", "venv", "__pycache__")]

        for name in files:
            # 检查点文件
            if name.endswith((".pt", ".pth", ".ckpt", ".bin")) and any(
                k in name.lower() for k in ("epoch", "checkpoint", "model", "best", "final")
            ):
                checkpoint_dirs.add(root)
                checkpoints.append({
                    "file": os.path.relpath(os.path.join(root, name), repo_path),
                    "type": "checkpoint_file",
                })

            # 自动加载器脚本
            if name.endswith((".py", ".sh", ".ps1")):
                full_path = os.path.join(root, name)
                try:
                    with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                        code = f.read()
                    loader_patterns = [
                        "auto-loader", "autoloader", "auto_load",
                        "syncer", "sync_checkpoint", "checkpoint_sync",
                        "watchdog", "watch_directory",
                    ]
                    if any(p in code.lower() for p in loader_patterns):
                        checkpoints.append({
                            "file": os.path.relpath(full_path, repo_path),
                            "type": "auto_loader_script",
                        })
                except Exception:
                    continue

        # README/documentation files with checkpoint loading instructions
        for name in files:
            if name.lower() in ("readme.md", "readme.txt", "deploy.md"):
                full_path = os.path.join(root, name)
                try:
                    with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                        text = f.read().lower()
                    if any(k in text for k in ("checkpoint", "autoload", "auto-load", "syncer")):
                        checkpoints.append({
                            "file": os.path.relpath(full_path, repo_path),
                            "type": "checkpoint_documentation",
                        })
                except Exception:
                    continue

    return checkpoints[:30]


# === 独立检测函数：MCP 服务器模式检测 ===
def detect_mcp_server_patterns(
    repo_path: str,
) -> list[dict]:
    """扫描仓库中的 MCP 服务器代码模式（AI-300 Ch8.1 MCP Supply Chain）。

    检测 MCP 服务器相关代码模式，用于供应链攻击中的目标定位：
      - MCP 库导入（from mcp import Server）
      - MCP 工具注册（@mcp.tool 装饰器）
      - MCP 服务器配置（mcp.json, claude_desktop_config.json）
      - MCP 传输类型（stdio, SSE, HTTP）

    Args:
        repo_path: 仓库路径

    Returns:
        MCP 模式列表
    """
    patterns: list[dict] = []

    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in (".git", ".venv", "venv", "__pycache__", "node_modules")]

        for name in files:
            filepath = os.path.join(root, name)
            rel_path = os.path.relpath(filepath, repo_path)

            # MCP 配置文件
            if name in ("mcp.json", "mcp.yaml", ".mcp.json") or "mcp" in name.lower() and name.endswith((".json", ".yaml", ".yml")):
                try:
                    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                    if "mcpServers" in content or "mcp" in content.lower():
                        patterns.append({
                            "file": rel_path,
                            "type": "mcp_config",
                            "has_servers_block": "mcpServers" in content,
                            "transport_mentions": re.findall(r"(?:stdio|sse|streamable-http)", content, re.IGNORECASE),
                        })
                except Exception:
                    continue

            # Python 文件 MCP 代码
            if name.endswith(".py"):
                try:
                    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                        code = f.read()

                    mcp_indicators = []
                    if "from mcp" in code or "import mcp" in code:
                        mcp_indicators.append("MCP library import")
                    if "Server(" in code and ("mcp" in code.lower()):
                        mcp_indicators.append("MCP Server instantiation")
                    if "@mcp.tool" in code:
                        mcp_tools = re.findall(r"@mcp\.tool[^\)]*\)\s*\n\s*(?:async\s+)?def\s+(\w+)", code, re.DOTALL)
                        mcp_indicators.append(f"MCP tool decorator: {', '.join(mcp_tools[:5])}" if mcp_tools else "MCP tool decorator")
                    if "@server.call_tool" in code or "@server.list_tools" in code:
                        mcp_indicators.append("MCP server handler")

                    if mcp_indicators:
                        patterns.append({
                            "file": rel_path,
                            "type": "mcp_server_code",
                            "indicators": mcp_indicators,
                        })
                except Exception:
                    continue

    return patterns


# === 独立检测函数：Pickle 漏洞扫描 ===
def scan_pickle_vulnerabilities(
    repo_path: str,
) -> list[dict]:
    """扫描仓库中的 Pickle 反序列化漏洞（AI-300 Ch8.2 Pickle RCE）。

    检测：
      - torch.load(weights_only=False) — 明确不安全
      - torch.load(...) 不带 weights_only=True — 隐式不安全
      - pickle.load/loads — 原生 pickle 反序列化
      - joblib.load — 基于 pickle 的序列化
      - dill.load / cloudpickle.load — 扩展 pickle 格式

    Args:
        repo_path: 仓库路径

    Returns:
        漏洞列表
    """
    all_vulns: list[dict] = []

    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in (".git", ".venv", "venv", "__pycache__", "node_modules")]

        for name in files:
            if name.endswith((".py", ".ipynb")):
                filepath = os.path.join(root, name)
                try:
                    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                        code = f.read()
                    vulns = _detect_pickle_vulnerability(code, filepath, repo_path)
                    all_vulns.extend(vulns)
                except Exception:
                    continue

            # 检测 requirements.txt 中是否有 pickle 相关库
            if name in ("requirements.txt", "setup.py", "pyproject.toml"):
                filepath = os.path.join(root, name)
                try:
                    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                        deps = f.read().lower()
                    pickle_deps = ["torch", "joblib", "dill", "cloudpickle", "pickle"]
                    for dep in pickle_deps:
                        if dep in deps:
                            all_vulns.append({
                                "file": os.path.relpath(filepath, repo_path),
                                "line": 0,
                                "type": f"Dependency: {dep} (potential pickle risk)",
                                "snippet": f"Found '{dep}' in dependencies",
                                "severity": "info",
                            })
                except Exception:
                    continue

    return all_vulns


__all__ = [
    "analyze_git_repository",
    "detect_mcp_server_patterns",
    "scan_pickle_vulnerabilities",
]