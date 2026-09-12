# cleanup_strike_root.ps1 - 清理 strike/ 根目录冗余文件
$files = @(
    "a2a_workflow_attacker.py",
    "adaptive_executor.py",
    "agent_card_spoofer.py",
    "asr_forensics.py",
    "asr_trend_tracker.py",
    "attack_knowledge_base.py",
    "audit_evasion.py",
    "auth_attacks.py",
    "backdoor_attack.py",
    "data_poisoning_injector.py",
    "decision_safety.py",
    "dispatcher.py",
    "document_poisoner.py",
    "dynamic_mcp_seeds.py",
    "escalation_runtime.py",
    "executor.py",
    "file_upload_executor.py",
    "http_attack_engine.py",
    "incremental_trust_builder.py",
    "indirect_pi_generator.py",
    "link_evasion.py",
    "llm_sql_injection_attacker.py",
    "malicious_mcp_server.py",
    "mcpsec_orchestrator.py",
    "mcp_rag_attack.py",
    "multimodal_injection.py",
    "output_filter_bypass.py",
    "pair_tap_strategies.py",
    "progressive_strike.py",
    "rag_targeted_consumer.py",
    "rogue_agent_registrar.py",
    "sql_injection_evasion.py",
    "stealth_exec.py",
    "web_attacks.py",
    "web_orchestrator.py",
    "web_page_injector.py",
    "_executor_attack_paths.py",
    "_executor_doc_poison.py",
    "_executor_feedback.py",
    "_executor_helpers.py",
    "_executor_vuln_inject.py"
)

$deleted = 0
$failed = 0

foreach ($f in $files) {
    if (Test-Path $f) {
        try {
            Remove-Item $f -Force
            Write-Host "[OK] Deleted: $f" -ForegroundColor Green
            $deleted++
        } catch {
            Write-Host "[FAIL] Could not delete: $f - $_" -ForegroundColor Red
            $failed++
        }
    } else {
        Write-Host "[SKIP] Not found: $f" -ForegroundColor Yellow
    }
}

Write-Host ""
Write-Host "=== Cleanup Summary ===" -ForegroundColor Cyan
Write-Host "Deleted: $deleted files" -ForegroundColor Green
Write-Host "Failed:  $failed files" -ForegroundColor Red
