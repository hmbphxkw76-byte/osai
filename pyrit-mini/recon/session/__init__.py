"""
recon/session/ - Session Reconnaissance Components.

Session-specific reconnaissance strategies for analyzing authentication
mechanisms, session management, and context isolation vulnerabilities.

Components:
    - session_id_analyzer: Session ID entropy and predictability analysis
    - session_auth_probe: Authentication mechanism probing
    - session_fixation_detector: Session fixation vulnerability detection
    - session_token_extractor: Session token extraction from responses

Academic basis:
    - OWASP Session Management Cheat Session
    - Robertson et al. (USENIX Security 2023) - Session fixation in LLM agents
    - NIST SP 800-63B - Session management requirements
"""

from recon.session.session_auth_probe import SessionAuthProbe
from recon.session.session_fixation_detector import SessionFixationDetector
from recon.session.session_id_analyzer import SessionIdAnalyzer
from recon.session.session_token_extractor import SessionTokenExtractor

__all__ = [
    "SessionIdAnalyzer",
    "SessionAuthProbe",
    "SessionFixationDetector",
    "SessionTokenExtractor",
]
