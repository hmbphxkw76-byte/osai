"""
RedTeam_AI Web Dashboard
========================
Flask-based web UI for the full six-stage (L0-L5) AI red team pipeline.

Stages:
  L0: Recon   — target reconnaissance & profiling
  L1: Garak   — AI model baseline scanning
  L2: Bridge  — Garak → Seeds mapping
  L3: Promptfoo — prompt template management
  L4: PyRIT   — deep adversarial attacks
  L5: Report  — unified OffSec reporting

Usage:
  cd RedTeam_AI && python web/server.py
  → http://127.0.0.1:8086
"""

__version__ = "1.0.0"
