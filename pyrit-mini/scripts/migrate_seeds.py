#!/usr/bin/env python3
"""migrate_seeds.py — 种子文件迁移脚本

将旧的 _attack_surface/ 结构迁移到新的组件目录结构。
与 strike/ 和 recon/ 目录对齐。
"""

import shutil
from pathlib import Path

SEEDS_DIR = Path(__file__).resolve().parent.parent / "data" / "seeds"
ATTACK_SURFACE_DIR = SEEDS_DIR / "_attack_surface"

# 迁移映射: (源文件路径, 目标目录, 新文件名)
MIGRATIONS = [
    # MCP 文件 (从 T1_ASI02_mcp_full_surface/)
    ("T1_ASI02_mcp_full_surface/mcp_context_poisoning.prompt", "mcp", None),
    ("T1_ASI02_mcp_full_surface/mcp_cross_server_trust.prompt", "mcp", None),
    ("T1_ASI02_mcp_full_surface/mcp_resource_leak.prompt", "mcp", None),
    ("T1_ASI02_mcp_full_surface/mcp_resource_traversal.prompt", "mcp", None),
    ("T1_ASI02_mcp_full_surface/mcp_rogue_endpoint.prompt", "mcp", None),
    ("T1_ASI02_mcp_full_surface/mcp_schema_poisoning.prompt", "mcp", None),
    ("T1_ASI02_mcp_full_surface/mcp_server_injection.prompt", "mcp", None),
    ("T1_ASI02_mcp_full_surface/mcp_tool_chaining.prompt", "mcp", None),
    ("T1_ASI02_mcp_full_surface/mcp_tool_description_injection.prompt", "mcp", None),
    ("T1_ASI02_mcp_full_surface/mcp_tool_enum.prompt", "mcp", None),
    ("T1_ASI02_mcp_full_surface/mcp_tool_hijack.prompt", "mcp", None),
    ("T1_ASI02_mcp_full_surface/mcp_ui_rendering_deception.prompt", "mcp", None),
    # A2A 文件 (从 T1_ASI06-09_multi_agent/)
    ("T1_ASI06-09_multi_agent/a2a_agent_card_spoofing.prompt", "a2a", None),
    ("T1_ASI06-09_multi_agent/data_poison_injection.prompt", "a2a", "a2a_data_poison_injection.prompt"),
    ("T1_ASI06-09_multi_agent/link_evasion.prompt", "a2a", "a2a_link_evasion.prompt"),
    ("T1_ASI06-09_multi_agent/llm_mssql_injection.prompt", "a2a", "a2a_sql_injection.prompt"),
    ("T1_ASI06-09_multi_agent/ma_cascading_failure.prompt", "a2a", "a2a_cascading_failure.prompt"),
    ("T1_ASI06-09_multi_agent/ma_cross_agent_injection.prompt", "a2a", "a2a_cross_agent_injection.prompt"),
    ("T1_ASI06-09_multi_agent/ma_identity_spoofing.prompt", "a2a", "a2a_identity_spoofing.prompt"),
    ("T1_ASI06-09_multi_agent/ma_memory_poisoning.prompt", "a2a", "a2a_memory_poisoning.prompt"),
    ("T1_ASI06-09_multi_agent/ma_trust_chain_break.prompt", "a2a", "a2a_trust_chain_break.prompt"),
    ("T1_ASI06-09_multi_agent/a2a_rogue_agent_registration.prompt", "a2a", None),
    ("T1_ASI06-09_multi_agent/sql_injection_evasion.prompt", "a2a", "a2a_sql_injection_evasion.prompt"),
    ("T1_ASI06-09_multi_agent/a2a_workflow_integrity_manipulation.prompt", "a2a", None),
    # RAG 文件
    ("T1_LLM08_rag_full_surface/rag_full_attack_surface.prompt", "rag", None),
    ("T1_LLM08_rag_advanced_seeds.prompt", "rag", "rag_advanced_seeds.prompt"),
    ("T1_LLM08_vector_db_poisoning.prompt", "rag", "rag_vector_db_poisoning.prompt"),
    # Model 文件
    ("T1_LLM10_model_theft.prompt", "model", "model_theft.prompt"),
    ("T1_LLM03_finetuning_indirect_injection.prompt", "model", "model_finetuning_indirect_injection.prompt"),
    # Web 文件
    ("T1_agent_protocol_fuzzing.prompt", "web", "agent_protocol_fuzzing.prompt"),
    # Memory 文件 (从 T1_MEMORY/)
    ("T1_MEMORY/memory_injection.prompt", "memory", None),
    ("T1_MEMORY/rag_kb_injection.prompt", "rag", "rag_kb_injection.prompt"),
    ("T1_MEMORY/session_id_enumeration.prompt", "session", "session_id_enumeration.prompt"),
]


def migrate():
    """执行迁移"""
    print("=== PyRIT-Seeds Migration Script ===")
    print(f"Seeds directory: {SEEDS_DIR}")
    print()

    # 创建目标目录
    targets = ["a2a", "mcp", "rag", "model", "memory", "session", "web"]
    for t in targets:
        path = SEEDS_DIR / t
        path.mkdir(exist_ok=True)
        print(f"Created directory: {t}/")

    print()

    # 执行迁移
    success_count = 0
    skip_count = 0

    for src_rel, dst_dir, new_name in MIGRATIONS:
        src_path = ATTACK_SURFACE_DIR / src_rel

        if not src_path.exists():
            print(f"  WARNING: Source not found: {src_rel}")
            skip_count += 1
            continue

        # 确定目标文件名
        dst_filename = new_name if new_name else src_path.name
        dst_path = SEEDS_DIR / dst_dir / dst_filename

        # 复制文件
        shutil.copy2(src_path, dst_path)
        print(f"  {src_rel} -> {dst_dir}/{dst_filename}")
        success_count += 1

    print()
    print("=== Migration Complete ===")
    print()
    print("Summary of new structure:")

    for dir_name in targets:
        dir_path = SEEDS_DIR / dir_name
        if dir_path.exists():
            files = list(dir_path.glob("*.prompt"))
            print(f"  {dir_name}/ : {len(files)} files")

    print()
    print(f"Migrated: {success_count}, Skipped: {skip_count}")


if __name__ == "__main__":
    migrate()
