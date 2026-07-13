"""代码仓库侦察（AI-300 Ch2.4 Source Code Recon）。

实现 AI-300 课程中的代码仓库侦察技术：
  1. 本地Git仓库分析：提取提交历史、配置文件、敏感信息
  2. GitHub/GitLab API侦察：仓库枚举、分支信息、成员列表
  3. 敏感文件扫描：.env、.gitconfig、密钥文件、配置文件
  4. 代码泄露检测：硬编码密钥、API密钥、访问令牌
  5. CI/CD配置分析：GitHub Actions、GitLab CI、Jenkinsfile

对齐 OWASP LLM Top 10: LLM05 (Supply Chain), LLM09 (Data Leakage)
"""
from __future__ import annotations

import json
import os
import re
import subprocess
from typing import Any
from urllib.parse import urlparse

import httpx

from redteam.core.models import AuthContext


class GitRepoScanResult:
    def __init__(self):
        self.repo_name = ""
        self.repo_url = ""
        self.repo_path = ""
        self.branch_count = 0
        self.commit_count = 0
        self.latest_commit = ""
        self.sensitive_files = []
        self.credentials_found = []
        self.config_files = []
        self.cicd_configs = []
        self.secret_patterns_found = []
        self.git_history_leaks = []
        self.remotes = []
        self.errors = []


SENSITIVE_FILE_PATTERNS = [
    ".env",
    ".env.local",
    ".env.development",
    ".env.production",
    ".env.staging",
    ".gitconfig",
    ".gitignore",
    ".dockerignore",
    ".htaccess",
    "config/secrets.yml",
    "config/database.yml",
    "config/application.yml",
    "config/credentials.yml.enc",
    "config/master.key",
    "secrets.json",
    "appsettings.json",
    "web.config",
    "pom.xml",
    "package-lock.json",
    "yarn.lock",
    "composer.lock",
    "requirements.txt",
    "Pipfile.lock",
    "Gemfile.lock",
    "go.mod",
    "go.sum",
    "Dockerfile",
    "docker-compose.yml",
    "Jenkinsfile",
    ".github/workflows/",
    ".gitlab-ci.yml",
    ".travis.yml",
    ".circleci/config.yml",
    "terraform/",
    "ansible/",
    "kubernetes/",
    "helm/",
]

SECRET_PATTERNS = [
    (r"(?i)(api[_-]?key|api[_-]?secret|api[_-]?token)\s*[=:]\s*['\"]([^'\"]+)['\"]", "API Key"),
    (r"(?i)(secret[_-]?key|secret[_-]?token)\s*[=:]\s*['\"]([^'\"]+)['\"]", "Secret Key"),
    (r"(?i)(access[_-]?key|access[_-]?token)\s*[=:]\s*['\"]([^'\"]+)['\"]", "Access Token"),
    (r"(?i)(password|pass|pwd)\s*[=:]\s*['\"]([^'\"]+)['\"]", "Password"),
    (r"(?i)(bearer|token)\s*['\"]([A-Za-z0-9_\-\.]+)['\"]", "Bearer Token"),
    (r"(?i)(ssh[_-]?key|private[_-]?key)\s*['\"]?([A-Za-z0-9+/=]{20,})", "SSH Key"),
    (r"(?i)(aws[_-]?(access|secret)[_-]?key)\s*[=:]\s*['\"]([^'\"]+)['\"]", "AWS Key"),
    (r"(?i)(slack[_-]?token|slack[_-]?webhook)\s*[=:]\s*['\"]([^'\"]+)['\"]", "Slack Token"),
    (r"(?i)(github[_-]?(token|secret))\s*[=:]\s*['\"]([^'\"]+)['\"]", "GitHub Token"),
    (r"(?i)(openai[_-]?(key|api[_-]?key))\s*[=:]\s*['\"]([^'\"]+)['\"]", "OpenAI Key"),
    (r"(?i)(anthropic[_-]?(key|api[_-]?key))\s*[=:]\s*['\"]([^'\"]+)['\"]", "Anthropic Key"),
    (r"(?i)(pinecone[_-]?(key|api[_-]?key))\s*[=:]\s*['\"]([^'\"]+)['\"]", "Pinecone Key"),
    (r"(?i)(milvus[_-]?(key|api[_-]?key))\s*[=:]\s*['\"]([^'\"]+)['\"]", "Milvus Key"),
    (r"(?i)(qdrant[_-]?(key|api[_-]?key))\s*[=:]\s*['\"]([^'\"]+)['\"]", "Qdrant Key"),
]


def scan_local_git_repo(repo_path: str) -> GitRepoScanResult:
    result = GitRepoScanResult()
    result.repo_path = repo_path

    try:
        if not os.path.isdir(os.path.join(repo_path, ".git")):
            result.errors = ["Not a git repository"]
            return result

        result.repo_name = os.path.basename(repo_path)

        result.remotes = _get_git_remotes(repo_path)
        if result.remotes:
            result.repo_url = result.remotes[0].get("url", "")

        result.branch_count = _get_branch_count(repo_path)
        result.commit_count = _get_commit_count(repo_path)
        result.latest_commit = _get_latest_commit(repo_path)

        result.sensitive_files = _find_sensitive_files(repo_path)
        result.config_files = _find_config_files(repo_path)
        result.cicd_configs = _find_cicd_configs(repo_path)

        result.credentials_found = _scan_for_credentials(repo_path)
        result.secret_patterns_found = _scan_for_secret_patterns(repo_path)

        result.git_history_leaks = _scan_git_history(repo_path)

    except Exception as e:
        result.errors = [str(e)]

    return result


def _get_git_remotes(repo_path: str) -> list[dict[str, str]]:
    remotes = []
    try:
        result = subprocess.run(
            ["git", "remote", "-v"],
            cwd=repo_path,
            capture_output=True,
            text=True,
            timeout=30,
        )
        for line in result.stdout.strip().split("\n"):
            parts = line.split()
            if len(parts) >= 2:
                remotes.append({"name": parts[0], "url": parts[1]})
    except Exception:
        pass
    return remotes


def _get_branch_count(repo_path: str) -> int:
    try:
        result = subprocess.run(
            ["git", "branch", "-a"],
            cwd=repo_path,
            capture_output=True,
            text=True,
            timeout=30,
        )
        return len([b for b in result.stdout.strip().split("\n") if b.strip()])
    except Exception:
        return 0


def _get_commit_count(repo_path: str) -> int:
    try:
        result = subprocess.run(
            ["git", "rev-list", "--count", "HEAD"],
            cwd=repo_path,
            capture_output=True,
            text=True,
            timeout=30,
        )
        return int(result.stdout.strip())
    except Exception:
        return 0


def _get_latest_commit(repo_path: str) -> str:
    try:
        result = subprocess.run(
            ["git", "log", "-1", "--format=%H %s"],
            cwd=repo_path,
            capture_output=True,
            text=True,
            timeout=30,
        )
        return result.stdout.strip()
    except Exception:
        return ""


def _find_sensitive_files(repo_path: str) -> list[str]:
    sensitive_files = []
    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d != ".git"]
        for filename in files:
            full_path = os.path.relpath(os.path.join(root, filename), repo_path)
            for pattern in SENSITIVE_FILE_PATTERNS:
                if pattern.startswith(".") and filename == pattern:
                    sensitive_files.append(full_path)
                elif pattern.endswith("/") and pattern[:-1] in full_path:
                    sensitive_files.append(full_path)
                elif full_path == pattern:
                    sensitive_files.append(full_path)
    return list(set(sensitive_files))


def _find_config_files(repo_path: str) -> list[str]:
    config_extensions = [".yml", ".yaml", ".json", ".toml", ".ini", ".cfg", ".conf"]
    config_files = []
    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d != ".git"]
        for filename in files:
            full_path = os.path.relpath(os.path.join(root, filename), repo_path)
            if any(filename.endswith(ext) for ext in config_extensions):
                config_files.append(full_path)
    return config_files


def _find_cicd_configs(repo_path: str) -> list[str]:
    cicd_patterns = [".github/workflows", ".gitlab-ci.yml", "Jenkinsfile", ".travis.yml"]
    cicd_configs = []
    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d != ".git"]
        for filename in files:
            full_path = os.path.relpath(os.path.join(root, filename), repo_path)
            for pattern in cicd_patterns:
                if pattern in full_path:
                    cicd_configs.append(full_path)
                    break
    return list(set(cicd_configs))


def _scan_for_credentials(repo_path: str) -> list[dict[str, str]]:
    credentials = []
    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d != ".git"]
        for filename in files:
            if filename in [".env", ".env.local", ".env.development", ".env.production"]:
                full_path = os.path.join(root, filename)
                try:
                    with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                        for line in content.split("\n"):
                            line = line.strip()
                            if line and not line.startswith("#"):
                                if any(key in line.lower() for key in ["api_key", "api-secret", "password", "secret", "token"]):
                                    credentials.append({
                                        "file": os.path.relpath(full_path, repo_path),
                                        "line": line[:100],
                                    })
                except Exception:
                    pass
    return credentials


def _scan_for_secret_patterns(repo_path: str) -> list[dict[str, str]]:
    secrets = []
    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d != ".git"]
        for filename in files:
            full_path = os.path.join(root, filename)
            if any(ext in filename for ext in [".py", ".js", ".ts", ".go", ".java", ".rb", ".php", ".env", ".yaml", ".yml", ".json"]):
                try:
                    with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                        for pattern, secret_type in SECRET_PATTERNS:
                            matches = re.findall(pattern, content)
                            for match in matches[:5]:
                                secret_value = match[-1] if isinstance(match, tuple) else match
                                if len(secret_value) > 8:
                                    secrets.append({
                                        "file": os.path.relpath(full_path, repo_path),
                                        "type": secret_type,
                                        "value": secret_value[:50] + "..." if len(secret_value) > 50 else secret_value,
                                    })
                except Exception:
                    pass
    return secrets


def _scan_git_history(repo_path: str) -> list[dict[str, str]]:
    history_leaks = []
    try:
        result = subprocess.run(
            ["git", "log", "--all", "--full-history", "--", ".env", ".env*", "*.key"],
            cwd=repo_path,
            capture_output=True,
            text=True,
            timeout=60,
        )
        if result.stdout.strip():
            history_leaks.append({"type": "env_files_in_history", "description": "Sensitive .env files found in git history"})

        result = subprocess.run(
            ["git", "log", "--all", "--oneline", "--grep=secret", "--grep=password", "--grep=api_key", "-i"],
            cwd=repo_path,
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.stdout.strip():
            commits = result.stdout.strip().split("\n")[:5]
            history_leaks.append({"type": "suspicious_commits", "description": f"Suspicious commit messages: {commits}"})

    except Exception:
        pass
    return history_leaks


def probe_git_server(
    server_url: str,
    auth: AuthContext | None = None,
    timeout: float = 10.0,
) -> dict[str, Any]:
    result = {
        "server_type": "",
        "server_url": server_url,
        "repositories": [],
        "users": [],
        "groups": [],
        "evidence": [],
    }

    headers = auth.to_header_dict() if auth else {}
    headers.setdefault("Accept", "application/json")

    parsed = urlparse(server_url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    with httpx.Client(timeout=timeout, verify=False) as client:
        if _detect_github_server(client, base, headers):
            result["server_type"] = "github"
            result["repositories"] = _github_list_repos(client, base, headers)
            result["evidence"].append("GitHub API detected")

        elif _detect_gitlab_server(client, base, headers):
            result["server_type"] = "gitlab"
            result["repositories"] = _gitlab_list_repos(client, base, headers)
            result["evidence"].append("GitLab API detected")

    return result


def _detect_github_server(client: httpx.Client, base: str, headers: dict) -> bool:
    try:
        resp = client.get(f"{base}/api/v3", headers=headers)
        if resp.status_code == 200 and "GitHub" in resp.text:
            return True
        resp = client.get(f"{base}/api/v4", headers=headers)
        if resp.status_code == 200:
            return True
        return False
    except Exception:
        return False


def _detect_gitlab_server(client: httpx.Client, base: str, headers: dict) -> bool:
    try:
        resp = client.get(f"{base}/api/v4/version", headers=headers)
        if resp.status_code == 200:
            data = resp.json()
            if isinstance(data, dict) and data.get("version"):
                return True
        return False
    except Exception:
        return False


def _github_list_repos(client: httpx.Client, base: str, headers: dict) -> list[dict]:
    repos = []
    try:
        resp = client.get(f"{base}/api/v3/user/repos", headers=headers)
        if resp.status_code == 200:
            data = resp.json()
            if isinstance(data, list):
                for repo in data[:20]:
                    repos.append({
                        "name": repo.get("name", ""),
                        "full_name": repo.get("full_name", ""),
                        "url": repo.get("html_url", ""),
                        "description": repo.get("description", ""),
                        "private": repo.get("private", False),
                    })

        resp = client.get(f"{base}/api/v3/orgs", headers=headers)
        if resp.status_code == 200:
            data = resp.json()
            if isinstance(data, list):
                for org in data[:10]:
                    org_repos = client.get(f"{base}/api/v3/orgs/{org.get('login')}/repos", headers=headers)
                    if org_repos.status_code == 200:
                        org_repos_data = org_repos.json()
                        if isinstance(org_repos_data, list):
                            for repo in org_repos_data[:10]:
                                repos.append({
                                    "name": repo.get("name", ""),
                                    "full_name": repo.get("full_name", ""),
                                    "url": repo.get("html_url", ""),
                                    "description": repo.get("description", ""),
                                    "private": repo.get("private", False),
                                })
    except Exception:
        pass
    return repos[:30]


def _gitlab_list_repos(client: httpx.Client, base: str, headers: dict) -> list[dict]:
    repos = []
    try:
        resp = client.get(f"{base}/api/v4/projects", headers=headers, params={"per_page": 20})
        if resp.status_code == 200:
            data = resp.json()
            if isinstance(data, list):
                for repo in data[:20]:
                    repos.append({
                        "name": repo.get("name", ""),
                        "full_name": repo.get("path_with_namespace", ""),
                        "url": repo.get("web_url", ""),
                        "description": repo.get("description", ""),
                        "private": repo.get("visibility") != "public",
                    })

        resp = client.get(f"{base}/api/v4/groups", headers=headers, params={"per_page": 10})
        if resp.status_code == 200:
            data = resp.json()
            if isinstance(data, list):
                for group in data[:10]:
                    group_repos = client.get(f"{base}/api/v4/groups/{group.get('id')}/projects", headers=headers, params={"per_page": 10})
                    if group_repos.status_code == 200:
                        group_repos_data = group_repos.json()
                        if isinstance(group_repos_data, list):
                            for repo in group_repos_data[:10]:
                                repos.append({
                                    "name": repo.get("name", ""),
                                    "full_name": repo.get("path_with_namespace", ""),
                                    "url": repo.get("web_url", ""),
                                    "description": repo.get("description", ""),
                                    "private": repo.get("visibility") != "public",
                                })
    except Exception:
        pass
    return repos[:30]


__all__ = [
    "scan_local_git_repo",
    "probe_git_server",
    "probe_gitlab_with_token",
    "detect_deployment_pipeline",
    "detect_mcp_code_in_repo",
    "GitRepoScanResult",
]


# === GitLab Token 认证私有仓库枚举（AI-300 Ch8.1 MCP Supply Chain） ===
def probe_gitlab_with_token(
    gitlab_url: str,
    personal_access_token: str,
    timeout: float = 15.0,
) -> dict[str, Any]:
    """使用 PAT 认证探测 GitLab 私有仓库（AI-300 Ch8.1 MCP Supply Chain）。

    考试场景：获得 Andres Mahone 凭据后，通过 GitLab API 枚举其可访问的
    所有仓库（包括私有仓库），识别 MCP 服务器代码仓库（如 mcp-biotools）。

    Args:
        gitlab_url: GitLab 服务器 URL（如 http://192.168.50.20）
        personal_access_token: GitLab Personal Access Token
        timeout: 超时时间

    Returns:
        包含仓库列表、用户信息、群组信息的结果字典
    """
    result: dict[str, Any] = {
        "server_url": gitlab_url,
        "server_type": "gitlab",
        "authenticated": False,
        "current_user": {},
        "repositories": [],
        "groups": [],
        "mcp_related_repos": [],
        "evidence": [],
    }

    headers = {
        "PRIVATE-TOKEN": personal_access_token,
        "Accept": "application/json",
    }

    parsed = urlparse(gitlab_url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    try:
        with httpx.Client(timeout=timeout, verify=False) as client:
            # 验证认证
            user_resp = client.get(f"{base}/api/v4/user", headers=headers)
            if user_resp.status_code == 200:
                user_data = user_resp.json()
                result["authenticated"] = True
                result["current_user"] = {
                    "username": user_data.get("username", ""),
                    "name": user_data.get("name", ""),
                    "email": user_data.get("email", ""),
                    "id": user_data.get("id", 0),
                }
                result["evidence"].append(
                    f"Authenticated as {user_data.get('username', 'unknown')}"
                )
            else:
                result["evidence"].append("Authentication failed")
                return result

            # 枚举项目（按创建时间降序，包含私有仓库）
            page = 1
            all_repos: list[dict] = []
            while page <= 5:  # 最多5页
                projects_resp = client.get(
                    f"{base}/api/v4/projects",
                    headers=headers,
                    params={
                        "per_page": 50,
                        "page": page,
                        "order_by": "last_activity_at",
                        "sort": "desc",
                        "membership": True,  # 仅用户为成员的仓库
                    },
                )
                if projects_resp.status_code != 200:
                    break

                projects = projects_resp.json()
                if not projects:
                    break

                for repo in projects:
                    repo_info = {
                        "name": repo.get("name", ""),
                        "full_name": repo.get("path_with_namespace", ""),
                        "url": repo.get("web_url", ""),
                        "description": repo.get("description", ""),
                        "visibility": repo.get("visibility", "private"),
                        "default_branch": repo.get("default_branch", ""),
                        "last_activity": repo.get("last_activity_at", ""),
                    }
                    all_repos.append(repo_info)

                    # 识别 MCP 相关仓库
                    if _is_mcp_related_repo(repo_info):
                        result["mcp_related_repos"].append(repo_info)
                        result["evidence"].append(
                            f"MCP-related repo: {repo_info['full_name']}"
                        )

                page += 1

            result["repositories"] = all_repos

            # 枚举群组
            groups_resp = client.get(
                f"{base}/api/v4/groups",
                headers=headers,
                params={"per_page": 20, "min_access_level": 10},
            )
            if groups_resp.status_code == 200:
                for group in groups_resp.json():
                    result["groups"].append({
                        "name": group.get("name", ""),
                        "full_path": group.get("full_path", ""),
                        "id": group.get("id", 0),
                    })

            result["evidence"].append(
                f"Total repos: {len(all_repos)}, MCP-related: {len(result['mcp_related_repos'])}"
            )

    except Exception as e:
        result["evidence"].append(f"Error: {str(e)}")

    return result


def _is_mcp_related_repo(repo: dict) -> bool:
    """判断仓库是否与 MCP 相关。"""
    name_lower = repo.get("name", "").lower()
    desc_lower = repo.get("description", "").lower()
    full_name_lower = repo.get("full_name", "").lower()
    combined = f"{name_lower} {desc_lower} {full_name_lower}"

    mcp_keywords = [
        "mcp", "mcp-server", "mcp-tool", "mcp-bio",
        "agent-tool", "tool-server", "model-context",
    ]
    return any(kw in combined for kw in mcp_keywords)


# === 部署流水线分析（AI-300 Ch8.1 Supply Chain） ===
def detect_deployment_pipeline(
    repo_path: str,
) -> dict[str, Any]:
    """分析仓库中的部署流水线配置（AI-300 Ch8.1）。

    识别：
      - CI/CD 配置文件（GitHub Actions, GitLab CI, Jenkins）
      - Docker/K8s 部署配置
      - 自动更新/同步脚本
      - 环境配置（开发/测试/生产）

    Args:
        repo_path: 仓库路径

    Returns:
        部署流水线分析结果
    """
    import os

    result: dict[str, Any] = {
        "repo_path": repo_path,
        "ci_cd_configs": [],
        "docker_configs": [],
        "k8s_configs": [],
        "deployment_scripts": [],
        "env_configs": [],
        "auto_update_scripts": [],
    }

    cicd_indicators = [
        ".github/workflows",
        ".gitlab-ci.yml",
        "Jenkinsfile",
        ".travis.yml",
        ".circleci",
        "azure-pipelines.yml",
        ".drone.yml",
        "bitbucket-pipelines.yml",
    ]

    docker_indicators = [
        "Dockerfile",
        "docker-compose.yml",
        "docker-compose.yaml",
        ".dockerignore",
        "Dockerfile.prod",
        "Dockerfile.dev",
    ]

    k8s_indicators = [
        "deployment.yaml", "deployment.yml",
        "service.yaml", "service.yml",
        "configmap.yaml", "configmap.yml",
        "secret.yaml", "secret.yml",
        "ingress.yaml", "ingress.yml",
        "namespace.yaml", "namespace.yml",
        "helm", "kustomization.yaml",
        "Chart.yaml",
    ]

    auto_update_indicators = [
        "auto-deploy", "auto_deploy", "auto-update", "auto_update",
        "syncer", "watchdog", "cron", "scheduler",
        "webhook", "trigger",
    ]

    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in (".git", ".venv", "venv", "__pycache__", "node_modules")]

        for name in files:
            rel_path = os.path.relpath(os.path.join(root, name), repo_path)

            for indicator in cicd_indicators:
                if indicator in rel_path.replace("\\", "/"):
                    result["ci_cd_configs"].append(rel_path)
                    break

            for indicator in docker_indicators:
                if indicator.lower() in name.lower():
                    result["docker_configs"].append(rel_path)
                    break

            for indicator in k8s_indicators:
                if indicator.lower() in name.lower() or indicator.lower() in rel_path.lower():
                    result["k8s_configs"].append(rel_path)
                    break

            if name.endswith((".sh", ".ps1", ".py")) and not name.startswith("test"):
                full_path = os.path.join(root, name)
                try:
                    with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read().lower()
                    for indicator in auto_update_indicators:
                        if indicator.lower() in content:
                            result["auto_update_scripts"].append(rel_path)
                            break
                except Exception:
                    continue

            if name in (".env", ".env.local", ".env.dev", ".env.prod", ".env.staging",
                        "appsettings.json", "application.yml", "application.yaml"):
                result["env_configs"].append(rel_path)

    return result


# === 仓库中 MCP 代码检测（AI-300 Ch8.1 Supply Chain） ===
def detect_mcp_code_in_repo(
    repo_path: str,
) -> list[dict]:
    """扫描 Git 仓库中的 MCP 服务器代码（AI-300 Ch8.1 MCP Supply Chain）。

    检测 MCP 服务器相关的代码模式，用于供应链攻击目标定位：
      - MCP 库导入（from mcp import Server）
      - MCP 工具装饰器（@mcp.tool）
      - MCP 服务器配置（mcpServers block）
      - 传输类型（stdio/sse/streamable-http）
      - 常见 MCP 服务器函数（list_datasets, get_schema 等）

    Args:
        repo_path: 仓库路径

    Returns:
        MCP 代码检测结果列表
    """
    import os

    patterns: list[dict] = []

    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in (".git", ".venv", "venv", "__pycache__", "node_modules")]

        for name in files:
            filepath = os.path.join(root, name)
            rel_path = os.path.relpath(filepath, repo_path)

            if name.endswith(".py"):
                try:
                    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                        code = f.read()

                    indicators = []

                    if re.search(r"from\s+mcp\b", code) or re.search(r"import\s+mcp\b", code):
                        indicators.append("MCP library import")

                    if "@mcp.tool" in code:
                        tool_names = re.findall(
                            r"@mcp\.tool[^)]*\)\s*\n\s*(?:async\s+)?def\s+(\w+)",
                            code, re.DOTALL,
                        )
                        indicators.append(
                            f"MCP tools: {', '.join(tool_names[:5])}"
                            if tool_names else "MCP tool decorator"
                        )

                    if "@server.call_tool" in code or "@server.list_tools" in code:
                        indicators.append("MCP server handler")

                    if '"mcpServers"' in code:
                        indicators.append("MCP servers config block")

                    if re.search(r"Server\s*\(\s*[\"'][\w\-]+[\"']", code):
                        if "mcp" in code.lower():
                            indicators.append("MCP Server instantiation")

                    if indicators:
                        patterns.append({
                            "file": rel_path,
                            "type": "mcp_server_code",
                            "indicators": indicators,
                            "line_count": len(code.split("\n")),
                        })

                except Exception:
                    continue

            if name in ("mcp.json", "mcp.yaml", ".mcp.json", "claude_desktop_config.json"):
                try:
                    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                        config = f.read()
                    transport_types = re.findall(
                        r"(?:stdio|sse|streamable-http)", config, re.IGNORECASE
                    )
                    patterns.append({
                        "file": rel_path,
                        "type": "mcp_config",
                        "has_servers": "mcpServers" in config,
                        "transports": list(set(transport_types)),
                    })
                except Exception:
                    continue

    return patterns


def _print_scan_result(result: GitRepoScanResult) -> None:
    """打印本地 Git 仓库扫描结果。"""
    print(f"\n{'='*60}")
    print(f"[扫描结果] {result.repo_name}")
    print(f"{'='*60}")
    
    if result.repo_path:
        print(f"仓库路径: {result.repo_path}")
    
    if result.repo_url:
        print(f"仓库 URL: {result.repo_url}")
    
    print(f"\n[基本信息]")
    print(f"  分支数: {result.branch_count}")
    print(f"  提交数: {result.commit_count}")
    print(f"  最近提交: {result.latest_commit}")
    
    if result.remotes:
        print(f"\n[远程仓库]")
        for remote in result.remotes:
            print(f"  - {remote['name']}: {remote['url']}")
    
    if result.sensitive_files:
        print(f"\n[敏感文件] ({len(result.sensitive_files)} 个)")
        for f in result.sensitive_files[:10]:
            print(f"  ⚠️  {f}")
        if len(result.sensitive_files) > 10:
            print(f"  ... 还有 {len(result.sensitive_files) - 10} 个")
    else:
        print(f"\n[敏感文件] 未发现敏感文件")
    
    if result.config_files:
        print(f"\n[配置文件] ({len(result.config_files)} 个)")
        for f in result.config_files[:10]:
            print(f"  {f}")
    
    if result.cicd_configs:
        print(f"\n[CI/CD 配置] ({len(result.cicd_configs)} 个)")
        for f in result.cicd_configs:
            print(f"  {f}")
    
    has_credentials = len(result.credentials_found) > 0 or len(result.secret_patterns_found) > 0
    
    if has_credentials:
        print(f"\n{'#'*60}")
        print(f"# ⚠️  发现敏感凭据信息 (高危) ⚠️")
        print(f"{'#'*60}")
    
    if result.credentials_found:
        print(f"\n[凭据信息] ({len(result.credentials_found)} 条)")
        for cred in result.credentials_found:
            print(f"  \033[31m文件: {cred['file']}\033[0m")
            print(f"    \033[33m内容: {cred['line']}\033[0m")
            print(f"    {'-'*40}")
    
    if result.secret_patterns_found:
        print(f"\n[密钥模式匹配] ({len(result.secret_patterns_found)} 条)")
        for secret in result.secret_patterns_found[:10]:
            print(f"  \033[31m文件: {secret['file']}\033[0m")
            print(f"    \033[32m类型: {secret['type']}\033[0m")
            print(f"    \033[33m值: {secret['value']}\033[0m")
            print(f"    {'-'*40}")
        if len(result.secret_patterns_found) > 10:
            print(f"  ... 还有 {len(result.secret_patterns_found) - 10} 条")
    
    if not has_credentials:
        print(f"\n[凭据信息] \033[32m✓ 未发现敏感凭据信息\033[0m")
    
    if result.git_history_leaks:
        print(f"\n[Git 历史泄露] ({len(result.git_history_leaks)} 条)")
        for leak in result.git_history_leaks:
            print(f"  \033[31m类型: {leak['type']}\033[0m")
            print(f"    描述: {leak['description']}")
    else:
        print(f"\n[Git 历史泄露] \033[32m✓ 未发现历史泄露\033[0m")
    
    if result.errors:
        print(f"\n[错误]")
        for error in result.errors:
            print(f"  ❌ {error}")


def _print_server_result(result: dict[str, Any]) -> None:
    """打印远程 Git 服务器探测结果。"""
    print(f"\n{'='*60}")
    print(f"[服务器探测] {result['server_url']}")
    print(f"{'='*60}")
    
    print(f"服务器类型: {result['server_type'] or '未知'}")
    
    if result["repositories"]:
        print(f"\n[仓库列表] ({len(result['repositories'])} 个)")
        for repo in result["repositories"][:10]:
            status = "🔒" if repo.get("private") else "🔓"
            print(f"  {status} {repo.get('name', '')}")
            if repo.get("description"):
                print(f"      {repo.get('description')}")
            print(f"      URL: {repo.get('url', '')}")
        if len(result["repositories"]) > 10:
            print(f"  ... 还有 {len(result['repositories']) - 10} 个仓库")
    
    if result["evidence"]:
        print(f"\n[证据]")
        for ev in result["evidence"]:
            print(f"  ✓ {ev}")


if __name__ == "__main__":
    print("""
╔══════════════════════════════════════════════════════════════╗
║              Git 仓库侦察工具 (AI-300 Ch2.4)                ║
║              Source Code Repository Recon                   ║
╚══════════════════════════════════════════════════════════════╝
    """)
    
    mode = input("请选择操作模式:\n"
                "  1. 扫描本地 Git 目录 (如 D:\\文档\\GitHub\\codes\\ai_labs)\n"
                "  2. 探测远程 Git 服务器 (GitHub/GitLab API)\n"
                "请输入选项 [1/2]: ").strip()
    
    while mode not in ("1", "2"):
        mode = input("无效选项，请输入 1 或 2: ").strip()
    
    if mode == "1":
        repo_path = input("\n请输入本地 Git 目录路径: ").strip()
        while not repo_path:
            repo_path = input("路径不能为空，请输入: ").strip()
        
        print(f"\n正在扫描: {repo_path}")
        result = scan_local_git_repo(repo_path)
        _print_scan_result(result)
    
    else:
        server_url = input("\n请输入 Git 服务器 URL (支持 http/https): ").strip()
        while not server_url:
            server_url = input("URL 不能为空，请输入: ").strip()
        
        if not server_url.startswith("http://") and not server_url.startswith("https://"):
            use_https = input("是否使用 https? [Y/n]: ").strip().lower()
            if use_https in ("", "y", "yes"):
                server_url = "https://" + server_url
            else:
                server_url = "http://" + server_url
        
        use_api_key = input("\n是否使用 API Key 认证? [y/N]: ").strip().lower()
        auth = None
        if use_api_key in ("y", "yes"):
            api_key = input("请输入 API Key: ").strip()
            if api_key:
                auth = AuthContext(bearer=api_key)
        
        print(f"\n正在探测: {server_url}")
        result = probe_git_server(server_url, auth)
        _print_server_result(result)
    
    print(f"\n{'='*60}")
    print("扫描完成")
    print(f"{'='*60}")
