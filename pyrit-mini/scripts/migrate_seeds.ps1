# migrate_seeds.ps1 - 种子文件迁移脚本
# 将旧的 _attack_surface/ 结构迁移到新的组件目录结构

$SEEDS_DIR = "d:\文档\GitHub\osai\pyrit-mini\data\seeds"
$ATTACK_SURFACE_DIR = Join-Path $SEEDS_DIR "_attack_surface"

Write-Host "=== PyRIT-Seeds Migration Script ===" -ForegroundColor Cyan
Write-Host "Seeds directory: $SEEDS_DIR" -ForegroundColor Gray
Write-Host ""

# 创建目标目录
$targets = @("a2a", "mcp", "rag", "model", "memory", "session", "web")
foreach ($t in $targets) {
    $path = Join-Path $SEEDS_DIR $t
    if (-not (Test-Path $path)) {
        New-Item -ItemType Directory -Force -Path $path | Out-Null
        Write-Host "Created directory: $t/" -ForegroundColor Green
    }
}

Write-Host ""
Write-Host "--- Migrating MCP seeds ---" -ForegroundColor Yellow

# MCP 文件 (从 T1_ASI02_mcp_full_surface/)
$mcpDir = Join-Path $ATTACK_SURFACE_DIR "T1_ASI02_mcp_full_surface"
if (Test-Path $mcpDir) {
    $mcpFiles = @(
        "mcp_context_poisoning.prompt",
        "mcp_cross_server_trust.prompt",
        "mcp_resource_leak.prompt",
        "mcp_resource_traversal.prompt",
        "mcp_rogue_endpoint.prompt",
        "mcp_schema_poisoning.prompt",
        "mcp_server_injection.prompt",
        "mcp_tool_chaining.prompt",
        "mcp_tool_description_injection.prompt",
        "mcp_tool_enum.prompt",
        "mcp_tool_hijack.prompt",
        "mcp_ui_rendering_deception.prompt"
    )
    foreach ($f in $mcpFiles) {
        $src = Join-Path $mcpDir $f
        $dst = Join-Path (Join-Path $SEEDS_DIR "mcp") $f
        if (Test-Path $src) {
            Copy-Item -Path $src -Destination $dst -Force
            Write-Host "  $f -> mcp/$f" -ForegroundColor Green
        }
    }
}

Write-Host ""
Write-Host "--- Migrating A2A seeds ---" -ForegroundColor Yellow

# A2A 文件 (从 T1_ASI06-09_multi_agent/)
$a2aDir = Join-Path $ATTACK_SURFACE_DIR "T1_ASI06-09_multi_agent"
if (Test-Path $a2aDir) {
    $a2aMappings = @{
        "a2a_agent_card_spoofing.prompt" = "a2a_agent_card_spoofing.prompt"
        "data_poison_injection.prompt" = "a2a_data_poison_injection.prompt"
        "link_evasion.prompt" = "a2a_link_evasion.prompt"
        "llm_mssql_injection.prompt" = "a2a_sql_injection.prompt"
        "ma_cascading_failure.prompt" = "a2a_cascading_failure.prompt"
        "ma_cross_agent_injection.prompt" = "a2a_cross_agent_injection.prompt"
        "ma_identity_spoofing.prompt" = "a2a_identity_spoofing.prompt"
        "ma_memory_poisoning.prompt" = "a2a_memory_poisoning.prompt"
        "ma_trust_chain_break.prompt" = "a2a_trust_chain_break.prompt"
        "a2a_rogue_agent_registration.prompt" = "a2a_rogue_agent_registration.prompt"
        "sql_injection_evasion.prompt" = "a2a_sql_injection_evasion.prompt"
        "a2a_workflow_integrity_manipulation.prompt" = "a2a_workflow_integrity_manipulation.prompt"
    }
    foreach ($srcName in $a2aMappings.Keys) {
        $src = Join-Path $a2aDir $srcName
        $dstName = $a2aMappings[$srcName]
        $dst = Join-Path (Join-Path $SEEDS_DIR "a2a") $dstName
        if (Test-Path $src) {
            Copy-Item -Path $src -Destination $dst -Force
            Write-Host "  $srcName -> a2a/$dstName" -ForegroundColor Green
        }
    }
}

Write-Host ""
Write-Host "--- Migrating RAG seeds ---" -ForegroundColor Yellow

# RAG 文件
$ragDir = Join-Path $ATTACK_SURFACE_DIR "T1_LLM08_rag_full_surface"
if (Test-Path $ragDir) {
    $src = Join-Path $ragDir "rag_full_attack_surface.prompt"
    $dst = Join-Path (Join-Path $SEEDS_DIR "rag") "rag_full_attack_surface.prompt"
    if (Test-Path $src) {
        Copy-Item -Path $src -Destination $dst -Force
        Write-Host "  rag_full_attack_surface.prompt -> rag/rag_full_attack_surface.prompt" -ForegroundColor Green
    }
}

$src = Join-Path $ATTACK_SURFACE_DIR "T1_LLM08_rag_advanced_seeds.prompt"
$dst = Join-Path (Join-Path $SEEDS_DIR "rag") "rag_advanced_seeds.prompt"
if (Test-Path $src) {
    Copy-Item -Path $src -Destination $dst -Force
    Write-Host "  T1_LLM08_rag_advanced_seeds.prompt -> rag/rag_advanced_seeds.prompt" -ForegroundColor Green
}

$src = Join-Path $ATTACK_SURFACE_DIR "T1_LLM08_vector_db_poisoning.prompt"
$dst = Join-Path (Join-Path $SEEDS_DIR "rag") "rag_vector_db_poisoning.prompt"
if (Test-Path $src) {
    Copy-Item -Path $src -Destination $dst -Force
    Write-Host "  T1_LLM08_vector_db_poisoning.prompt -> rag/vector_db_poisoning.prompt" -ForegroundColor Green
}

Write-Host ""
Write-Host "--- Migrating Model seeds ---" -ForegroundColor Yellow

# Model 文件
$src = Join-Path $ATTACK_SURFACE_DIR "T1_LLM10_model_theft.prompt"
$dst = Join-Path (Join-Path $SEEDS_DIR "model") "model_theft.prompt"
if (Test-Path $src) {
    Copy-Item -Path $src -Destination $dst -Force
    Write-Host "  T1_LLM10_model_theft.prompt -> model/model_theft.prompt" -ForegroundColor Green
}

$src = Join-Path $ATTACK_SURFACE_DIR "T1_LLM03_finetuning_indirect_injection.prompt"
$dst = Join-Path (Join-Path $SEEDS_DIR "model") "model_finetuning_indirect_injection.prompt"
if (Test-Path $src) {
    Copy-Item -Path $src -Destination $dst -Force
    Write-Host "  T1_LLM03_finetuning_indirect_injection.prompt -> model/finetuning_indirect_injection.prompt" -ForegroundColor Green
}

# Agent protocol fuzzing -> web
$src = Join-Path $ATTACK_SURFACE_DIR "T1_agent_protocol_fuzzing.prompt"
$dst = Join-Path (Join-Path $SEEDS_DIR "web") "agent_protocol_fuzzing.prompt"
if (Test-Path $src) {
    Copy-Item -Path $src -Destination $dst -Force
    Write-Host "  T1_agent_protocol_fuzzing.prompt -> web/agent_protocol_fuzzing.prompt" -ForegroundColor Green
}

Write-Host ""
Write-Host "--- Migrating Memory seeds ---" -ForegroundColor Yellow

# Memory 文件 (从 T1_MEMORY/)
$memDir = Join-Path $ATTACK_SURFACE_DIR "T1_MEMORY"
if (Test-Path $memDir) {
    $memFiles = @(
        "memory_injection.prompt"
    )
    foreach ($f in $memFiles) {
        $src = Join-Path $memDir $f
        $dst = Join-Path (Join-Path $SEEDS_DIR "memory") $f
        if (Test-Path $src) {
            Copy-Item -Path $src -Destination $dst -Force
            Write-Host "  $f -> memory/$f" -ForegroundColor Green
        }
    }
    
    # rag_kb_injection -> rag
    $src = Join-Path $memDir "rag_kb_injection.prompt"
    $dst = Join-Path (Join-Path $SEEDS_DIR "rag") "rag_kb_injection.prompt"
    if (Test-Path $src) {
        Copy-Item -Path $src -Destination $dst -Force
        Write-Host "  rag_kb_injection.prompt -> rag/kb_injection.prompt" -ForegroundColor Green
    }
    
    # session_id_enumeration -> session
    $src = Join-Path $memDir "session_id_enumeration.prompt"
    $dst = Join-Path (Join-Path $SEEDS_DIR "session") "session_id_enumeration.prompt"
    if (Test-Path $src) {
        Copy-Item -Path $src -Destination $dst -Force
        Write-Host "  session_id_enumeration.prompt -> session/session_id_enumeration.prompt" -ForegroundColor Green
    }
}

Write-Host ""
Write-Host "=== Migration Complete ===" -ForegroundColor Cyan
Write-Host ""
Write-Host "Summary of new structure:" -ForegroundColor Yellow

foreach ($dir in $targets) {
    $path = Join-Path $SEEDS_DIR $dir
    if (Test-Path $path) {
        $files = Get-ChildItem -Path $path -Filter "*.prompt" -File
        Write-Host "  $($dir)/ : $($files.Count) files" -ForegroundColor White
    }
}
