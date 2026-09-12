"""
recon/web/ - Web API & Application Reconnaissance Components.

Web-specific reconnaissance strategies for API endpoint discovery,
authentication mapping, and input surface analysis.

Components:
    - web_api_discoverer: API endpoint discovery and cataloging
    - web_auth_mapper: Authentication and authorization flow mapping
    - web_input_mapper: Input point identification and classification

Academic basis:
    - OWASP API Security Top 10
    - Gavrichenko et al. (2023) - REST API attack surface analysis
    - Wang et al. (S&P 2021) - Automated API abuse detection
"""

from recon.web.web_api_discoverer import WebApiDiscoverer
from recon.web.web_auth_mapper import WebAuthMapper
from recon.web.web_input_mapper import WebInputMapper

__all__ = [
    "WebApiDiscoverer",
    "WebAuthMapper",
    "WebInputMapper",
]
