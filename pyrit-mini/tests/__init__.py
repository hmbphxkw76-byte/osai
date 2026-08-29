"""Test suite for pyrit-mini attack pipeline.

Test structure mirrors module structure:
    test_recon.py     — Burp parsing + target building + capability probing
    test_arm.py       — Seed ranking + converter selection + technique picking
    test_strike.py    — Attack execution + escalation chain
    test_assess.py    — Scorer + ASR tracker + dual judge
    test_report.py    — Evidence collection + report generation
    test_e2e.py       — End-to-end pipeline (mocked API calls)
"""
