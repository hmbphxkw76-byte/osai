"""AI 供应链攻击阶段 (AI-300 Ch8)。

执行 AI 供应链攻击（7 步递进流程）：
  [1/7] HuggingFace 模型来源可信度检测
  [2/7] Pickle 反序列化 RCE 风险
  [3/7] 数据集投毒风险
  [4/7] 依赖攻击风险
  [5/7] GitLab PAT 私有仓库枚举（Ch8.1 MCP Supply Chain）
  [6/7] 仓库 MCP 代码检测（Ch8.1 MCP Supply Chain）
  [7/7] 部署流水线分析（Ch8.1 CI/CD 后门）

对齐 OWASP LLM Top 10: LLM05 (Supply Chain)
"""
from __future__ import annotations

from typing import Any

from redteam.core.models import AIService, AuthContext, Finding
from redteam.core.store import load_json, save_json

from redteam.attack.supply_chain import (
    detect_hf_model_source, check_pickle_deserialization_risk,
    check_dataset_poisoning_risks, check_dependency_risks,
    generate_supply_chain_findings,
)


def supply_chain_phase(
    run_id: str,
    services: list[AIService],
    auth: AuthContext | None = None,
    gitlab_url: str | None = None,
    gitlab_token: str | None = None,
    repo_path: str | None = None,
) -> list[Finding]:
    """AI 供应链攻击阶段 — 7 步递进流程。

    AI-300 Ch8 完整攻击链：
    1. HuggingFace 模型来源可信度检测
    2. Pickle 反序列化 RCE 风险
    3. 数据集投毒风险
    4. 依赖攻击风险
    5. GitLab PAT 私有仓库枚举 (Ch8.1 MCP Supply Chain)
    6. 仓库 MCP 代码检测 (Ch8.1)
    7. 部署流水线分析 (Ch8.1 CI/CD 后门)

    Args:
        run_id: 运行 ID
        services: AI 服务列表
        auth: 认证上下文
        gitlab_url: GitLab 服务器 URL（可选，用于 PAT 枚举）
        gitlab_token: GitLab Personal Access Token（可选）
        repo_path: 本地仓库路径（可选，用于代码分析）
    """
    all_findings: list[Finding] = []

    for svc in services[:3]:
        print(f"\n[SupplyChain] 目标: [{svc.protocol}] {svc.url}")

        print("  [1/7] 模型来源可信度检测...")
        hf_risks = detect_hf_model_source(svc)
        high_risk = sum(1 for r in hf_risks if r.get("risk_level") in ("high", "critical"))
        print(f"    发现 {len(hf_risks)} 个模型, {high_risk} 个高风险")

        print("  [2/7] Pickle 反序列化 RCE 风险...")
        pickle_risks = check_pickle_deserialization_risk(svc, auth)
        vulnerable = sum(1 for r in pickle_risks if r.get("vulnerable"))
        print(f"    风险端点: {vulnerable}/{len(pickle_risks)}")

        print("  [3/7] 数据集投毒风险检查...")
        dataset_risks = check_dataset_poisoning_risks(svc, auth)
        print(f"    发现 {len(dataset_risks)} 个风险点")

        print("  [4/7] 依赖攻击风险检查...")
        dependency_risks = check_dependency_risks(svc)
        print(f"    发现 {len(dependency_risks)} 个风险点")

        findings = generate_supply_chain_findings(
            svc, hf_risks, pickle_risks, dataset_risks, dependency_risks,
        )
        all_findings.extend(findings)

    # ═══════════════════════════════════════════════════════════════
    # [5/7] GitLab PAT 私有仓库枚举 (Ch8.1 MCP Supply Chain)
    # ═══════════════════════════════════════════════════════════════
    if gitlab_url and gitlab_token:
        print(f"\n  [5/7] GitLab PAT 私有仓库枚举...")
        from redteam.recon.git_recon import probe_gitlab_with_token
        gitlab_result = probe_gitlab_with_token(gitlab_url, gitlab_token, timeout=15.0)
        if gitlab_result.get("authenticated"):
            user = gitlab_result.get("current_user", {}).get("username", "unknown")
            repos = len(gitlab_result.get("repositories", []))
            mcp_repos = len(gitlab_result.get("mcp_related_repos", []))
            print(f"    认证: {user}  |  仓库: {repos} 个  |  MCP 相关: {mcp_repos} 个")
            save_json(run_id, "gitlab_recon", gitlab_result, subdir="recon")

            # 对 MCP 相关仓库执行更深入分析
            for mcp_repo in gitlab_result.get("mcp_related_repos", []):
                print(f"    🔍 MCP 仓库: {mcp_repo.get('full_name', '')}")
        else:
            print("    GitLab PAT 认证失败")
    else:
        print(f"\n  [5/7] GitLab PAT 枚举 — 跳过（未提供 GitLab URL/Token）")

    # ═══════════════════════════════════════════════════════════════
    # [6/7] 仓库 MCP 代码检测 (Ch8.1)
    # ═══════════════════════════════════════════════════════════════
    if repo_path:
        print(f"\n  [6/7] 仓库 MCP 代码检测...")
        from redteam.recon.git_recon import detect_mcp_code_in_repo
        mcp_code = detect_mcp_code_in_repo(repo_path)
        if mcp_code:
            python_files = [f for f in mcp_code if f.get("type") == "mcp_server_code"]
            config_files = [f for f in mcp_code if f.get("type") == "mcp_config"]
            print(f"    MCP 服务器代码: {len(python_files)} 个文件")
            print(f"    MCP 配置文件: {len(config_files)} 个文件")
            save_json(run_id, "mcp_code_detection", mcp_code, subdir="recon")
        else:
            print("    未检测到 MCP 代码模式")
    else:
        print(f"\n  [6/7] 仓库 MCP 代码检测 — 跳过（未提供仓库路径）")

    # ═══════════════════════════════════════════════════════════════
    # [7/7] 部署流水线分析 (Ch8.1 CI/CD)
    # ═══════════════════════════════════════════════════════════════
    if repo_path:
        print(f"\n  [7/7] 部署流水线分析...")
        from redteam.recon.git_recon import detect_deployment_pipeline
        pipeline = detect_deployment_pipeline(repo_path)
        cicd = len(pipeline.get("ci_cd_configs", []))
        docker = len(pipeline.get("docker_configs", []))
        k8s = len(pipeline.get("k8s_configs", []))
        auto = len(pipeline.get("auto_update_scripts", []))
        print(f"    CI/CD 配置: {cicd}  |  Docker: {docker}  |  K8s: {k8s}  |  自动脚本: {auto}")
        if pipeline.get("auto_update_scripts"):
            print(f"    ⚠️  检测到自动更新/同步脚本 — 供应链后门潜在入口")
        save_json(run_id, "deployment_pipeline", pipeline, subdir="recon")
    else:
        print(f"\n  [7/7] 部署流水线分析 — 跳过（未提供仓库路径）")

    # Persist accumulated findings to JSON store (for checkpoint/resume)
    prior = load_json(run_id, "findings") or []
    accumulated = prior + [f.model_dump() for f in all_findings]
    save_json(run_id, "findings", accumulated, subdir="detect")
    # Return ONLY this phase's own findings (not accumulated history)
    return all_findings


__all__ = [
    "supply_chain_phase",
]