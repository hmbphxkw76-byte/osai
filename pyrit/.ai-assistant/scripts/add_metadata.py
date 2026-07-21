#!/usr/bin/env python3
"""批量为 OWASP payload YAML 文件添加 surfaces 和 ai300_chapters 元数据"""
import sys
sys.stdout.reconfigure(encoding='utf-8')

import yaml
from pathlib import Path

# 完整映射表
MAPPING = {
    "llm/llm01/direct_injection.yaml": {"surfaces": ["agent"], "ai300_chapters": ["Ch3"]},
    "llm/llm01/jailbreak.yaml": {"surfaces": ["agent"], "ai300_chapters": ["Ch3"]},
    "llm/llm01/crescendo_jailbreak.yaml": {"surfaces": ["agent"], "ai300_chapters": ["Ch3"]},
    "llm/llm01/many_shot_jailbreak.yaml": {"surfaces": ["agent"], "ai300_chapters": ["Ch3"]},
    "llm/llm01/adversarial_suffix.yaml": {"surfaces": ["agent"], "ai300_chapters": ["Ch3"]},
    "llm/llm01/indirect_injection.yaml": {"surfaces": ["rag", "agent"], "ai300_chapters": ["Ch3"]},
    "llm/llm01/system_prompt_extraction.yaml": {"surfaces": ["agent"], "ai300_chapters": ["Ch3"]},
    "llm/llm01/memory_poison.yaml": {"surfaces": ["agent"], "ai300_chapters": ["Ch3"]},
    "llm/llm01/multimodal_injection.yaml": {"surfaces": ["agent"], "ai300_chapters": ["Ch3"]},
    "llm/llm01/encoding_bypass.yaml": {"surfaces": ["agent"], "ai300_chapters": ["Ch3"]},
    "llm/llm01/special_token_injection.yaml": {"surfaces": ["agent"], "ai300_chapters": ["Ch3"]},
    "llm/llm01/cca_context_compliance.yaml": {"surfaces": ["agent"], "ai300_chapters": ["Ch3"]},
    "llm/llm01/token_smuggling.yaml": {"surfaces": ["agent"], "ai300_chapters": ["Ch3"]},
    "llm/llm01/few_shot_backdoor.yaml": {"surfaces": ["agent"], "ai300_chapters": ["Ch3"]},
    "llm/llm01/format_injection.yaml": {"surfaces": ["agent"], "ai300_chapters": ["Ch3"]},
    "llm/llm01/structured_field_injection.yaml": {"surfaces": ["agent"], "ai300_chapters": ["Ch3"]},
    "llm/llm01/prompt_smuggling.yaml": {"surfaces": ["agent"], "ai300_chapters": ["Ch3"]},
    "llm/llm01/glitch_token.yaml": {"surfaces": ["agent"], "ai300_chapters": ["Ch3"]},
    "llm/llm01/adaptive_jailbreak.yaml": {"surfaces": ["agent"], "ai300_chapters": ["Ch3"]},
    "llm/llm01/cve_2025_32711_m365_echoleak.yaml": {"surfaces": ["agent", "rag"], "ai300_chapters": ["Ch3"]},
    "llm/llm01/frontier_2025_001_hcot_injection.yaml": {"surfaces": ["agent"], "ai300_chapters": ["Ch3"]},
    "llm/llm02/sensitive_info.yaml": {"surfaces": ["agent"], "ai300_chapters": ["Ch3"]},
    "llm/llm02/memory_extraction.yaml": {"surfaces": ["agent"], "ai300_chapters": ["Ch3"]},
    "llm/llm02/training_data_extraction.yaml": {"surfaces": ["agent", "embedding"], "ai300_chapters": ["Ch3"]},
    "llm/llm03/model_deserialization.yaml": {"surfaces": ["agent"], "ai300_chapters": ["Ch8"]},
    "llm/llm03/dependency_confusion.yaml": {"surfaces": ["agent"], "ai300_chapters": ["Ch8"]},
    "llm/llm03/docker_label_injection.yaml": {"surfaces": ["agent"], "ai300_chapters": ["Ch8"]},
    "llm/llm03/package_hallucination.yaml": {"surfaces": ["agent"], "ai300_chapters": ["Ch8"]},
    "llm/llm03/cve_2025_1716_picklescan_pypi_rce.yaml": {"surfaces": ["agent"], "ai300_chapters": ["Ch8"]},
    "llm/llm03/cve_2026_25874_lerobot_pickle_rce.yaml": {"surfaces": ["agent"], "ai300_chapters": ["Ch8"]},
    "llm/llm04/rag_poison.yaml": {"surfaces": ["rag"], "ai300_chapters": ["Ch5"]},
    "llm/llm04/rag_indirect_injection.yaml": {"surfaces": ["rag"], "ai300_chapters": ["Ch5"]},
    "llm/llm04/rag_source_attribution.yaml": {"surfaces": ["rag"], "ai300_chapters": ["Ch5"]},
    "llm/llm05/plugin_injection.yaml": {"surfaces": ["agent", "mcp"], "ai300_chapters": ["Ch7"]},
    "llm/llm05/insecure_output.yaml": {"surfaces": ["agent"], "ai300_chapters": ["Ch3"]},
    "llm/llm06/tool_hijack.yaml": {"surfaces": ["agent"], "ai300_chapters": ["Ch3"]},
    "llm/llm06/goal_hijack.yaml": {"surfaces": ["agent"], "ai300_chapters": ["Ch3"]},
    "llm/llm06/parameter_pollution.yaml": {"surfaces": ["agent"], "ai300_chapters": ["Ch3"]},
    "llm/llm06/mcp_tool_poison.yaml": {"surfaces": ["mcp", "agent"], "ai300_chapters": ["Ch7"]},
    "llm/llm06/cross_agent.yaml": {"surfaces": ["agent"], "ai300_chapters": ["Ch4"]},
    "llm/llm06/agent_break.yaml": {"surfaces": ["agent"], "ai300_chapters": ["Ch4"]},
    "llm/llm06/mcp_token_leak.yaml": {"surfaces": ["mcp", "agent"], "ai300_chapters": ["Ch7"]},
    "llm/llm06/mcp_capability_confusion.yaml": {"surfaces": ["mcp", "agent"], "ai300_chapters": ["Ch7"]},
    "llm/llm06/mcp_session_fix.yaml": {"surfaces": ["mcp", "agent"], "ai300_chapters": ["Ch7"]},
    "llm/llm06/frontier_2025_003_mcp_tool_poison.yaml": {"surfaces": ["mcp", "agent"], "ai300_chapters": ["Ch7"]},
    "llm/llm06/frontier_2025_004_tool_data_exfil.yaml": {"surfaces": ["agent"], "ai300_chapters": ["Ch3"]},
    "llm/llm06/cve_2026_22812_opencode_unauth_rce.yaml": {"surfaces": ["agent"], "ai300_chapters": ["Ch3"]},
    "llm/llm06/cve_2026_25253_openclaw_token_theft.yaml": {"surfaces": ["agent"], "ai300_chapters": ["Ch3"]},
    "llm/llm06/cve_2026_25592_semantic_kernel_sandbox_escape.yaml": {"surfaces": ["agent"], "ai300_chapters": ["Ch7"]},
    "llm/llm06/cve_2026_40933_flowise_mcp_injection.yaml": {"surfaces": ["mcp", "agent"], "ai300_chapters": ["Ch7"]},
    "llm/llm07/system_prompt_leak.yaml": {"surfaces": ["agent"], "ai300_chapters": ["Ch3"]},
    "llm/llm07/config_extraction.yaml": {"surfaces": ["agent", "mcp"], "ai300_chapters": ["Ch7"]},
    "llm/llm07/frontier_2025_002_echoleak_prompt_leak.yaml": {"surfaces": ["agent"], "ai300_chapters": ["Ch3"]},
    "llm/llm08/embedding_inversion_practical.yaml": {"surfaces": ["embedding", "rag"], "ai300_chapters": ["Ch6"]},
    "llm/llm08/adversarial_embedding.yaml": {"surfaces": ["embedding"], "ai300_chapters": ["Ch6"]},
    "llm/llm08/vector_weakness.yaml": {"surfaces": ["rag", "embedding"], "ai300_chapters": ["Ch5"]},
    "llm/llm08/cve_2026_45829_chromadb_rce.yaml": {"surfaces": ["rag", "embedding"], "ai300_chapters": ["Ch5"]},
    "llm/llm08/_embedding_verify.yaml": {"surfaces": ["embedding"], "ai300_chapters": ["Ch6"]},
    "llm/llm09/hallucination_exploitation.yaml": {"surfaces": ["agent", "rag"], "ai300_chapters": ["Ch3"]},
    "llm/llm09/deepfake_social_engineering.yaml": {"surfaces": ["agent"], "ai300_chapters": ["Ch3"]},
    "llm/llm09/misinformation.yaml": {"surfaces": ["agent", "rag"], "ai300_chapters": ["Ch5"]},
    "llm/llm09/citation_elicitation.yaml": {"surfaces": ["agent", "rag"], "ai300_chapters": ["Ch3"]},
    "llm/llm10/resource_exhaustion.yaml": {"surfaces": ["agent", "rag"], "ai300_chapters": ["Ch3"]},
    "llm/llm10/context_padding.yaml": {"surfaces": ["agent"], "ai300_chapters": ["Ch3"]},
    "agentic/asi01.yaml": {"surfaces": ["agent"], "ai300_chapters": ["Ch3"]},
    "agentic/asi02.yaml": {"surfaces": ["agent", "mcp"], "ai300_chapters": ["Ch7"]},
    "agentic/asi03.yaml": {"surfaces": ["agent"], "ai300_chapters": ["Ch4"]},
    "agentic/asi04.yaml": {"surfaces": ["agent", "mcp"], "ai300_chapters": ["Ch8"]},
    "agentic/asi05.yaml": {"surfaces": ["agent"], "ai300_chapters": ["Ch8"]},
    "agentic/asi06.yaml": {"surfaces": ["agent", "rag"], "ai300_chapters": ["Ch3"]},
    "agentic/asi07.yaml": {"surfaces": ["agent"], "ai300_chapters": ["Ch4"]},
    "agentic/asi08.yaml": {"surfaces": ["agent"], "ai300_chapters": ["Ch4"]},
    "agentic/asi09.yaml": {"surfaces": ["agent"], "ai300_chapters": ["Ch3"]},
    "agentic/asi10.yaml": {"surfaces": ["agent"], "ai300_chapters": ["Ch4"]},
}

DATA_DIR = Path(__file__).resolve().parent.parent.parent / "data" / "owasp"

def add_metadata_to_file(rel_path: str, metadata: dict) -> bool:
    """为单个 YAML 文件添加 surfaces 和 ai300_chapters"""
    file_path = DATA_DIR / rel_path
    if not file_path.exists():
        print(f"  SKIP (not found): {rel_path}")
        return False

    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()

    # 检查是否已存在
    if 'surfaces:' in content and 'ai300_chapters:' in content:
        print(f"  SKIP (already has metadata): {rel_path}")
        return False

    lines = content.split('\n')
    
    # 找到 description 行，在其后插入
    insert_idx = None
    for i, line in enumerate(lines):
        if line.startswith('description:'):
            insert_idx = i + 1
            break
    
    if insert_idx is None:
        # 没找到 description，在第一个 payloads 前插入
        for i, line in enumerate(lines):
            if line.startswith('payloads:'):
                insert_idx = i
                break
    
    if insert_idx is None:
        print(f"  SKIP (no insert point): {rel_path}")
        return False

    # 构建插入文本
    surfaces_str = ", ".join(metadata["surfaces"])
    chapters_str = ", ".join(metadata["ai300_chapters"])
    insert_lines = [
        f"surfaces: [{surfaces_str}]",
        f"ai300_chapters: [{chapters_str}]",
        "",  # 空行分隔
    ]

    # 插入
    new_lines = lines[:insert_idx] + insert_lines + lines[insert_idx:]
    
    with open(file_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(new_lines))
    
    print(f"  OK: {rel_path}")
    return True


def main():
    print(f"Data dir: {DATA_DIR}")
    print(f"Total files to process: {len(MAPPING)}")
    print()
    
    success = 0
    skip = 0
    fail = 0
    
    for rel_path, metadata in MAPPING.items():
        result = add_metadata_to_file(rel_path, metadata)
        if result:
            success += 1
        else:
            skip += 1
    
    print()
    print(f"Done: {success} updated, {skip} skipped")


if __name__ == "__main__":
    main()
