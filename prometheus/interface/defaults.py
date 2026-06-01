"""Shared defaults for prometheus entry points."""

from __future__ import annotations

# Default skills loaded by the root agent.
# Both cli.py and tui/app.py import this instead of maintaining separate copies.
DEFAULT_SKILLS: list[str] = [
    # Core vulnerability testing — always loaded
    "threat_intelligence",
    "information_disclosure",
    "idor",
    "sql_injection",
    "nosql_injection",
    "ssrf",
    "xss",
    "csrf",
    "xxe",
    "ssti",
    "rce",
    "authentication_jwt",
    "oauth_vulnerabilities",
    "business_logic",
    "supply_chain",
    "security_misconfiguration",
    "cors_misconfiguration",
    "open_redirect",
    "path_traversal_lfi_rfi",
    "deserialization",
    "race_conditions",
    "insecure_file_uploads",
    "mass_assignment",
    "broken_function_level_authorization",
    # Specialized skills — load on-demand via load_skill() or create_agent(skills=[...])
    # "cloudflare_credentials",        # 14K — load when Cloudflare detected
    # "cloud_credential_exploitation", # 19K — load when Firebase/Supabase/GCP/Azure detected
    # "ai_llm_attacks",                # 19K — load when AI/LLM endpoints detected
    # "dns_network",                   # 14K — load for subdomain enumeration phase
    # "container_escape",              # 15K — load when Docker/K8s detected
    # "mobile_api",                    # 16K — load when mobile endpoints detected
    # "threat_modeling",               # 15K — load for whitebox/code review
    # "prototype_pollution",           # load when Node.js/JS backend detected
    # "header_injection",              # load when custom header handling detected
    # "http_request_smuggling",        # load when reverse proxy/CDN detected
    # "clickjacking",                  # load when frameable pages detected
    # "subdomain_takeover",            # load when DNS enumeration phase
    # "graphql_attacks",               # load when GraphQL endpoints detected
    # "websocket_security",            # load when WebSocket endpoints detected
    # "js_bundle_analysis",            # load when SPA/React/Angular detected
    # "cryptographic_failures",        # load when TLS/crypto endpoints detected
    # "logging_monitoring_failures",   # load when log endpoints detected
    # "integrity_failures",            # load when CI/CD or update mechanisms detected
    # "exception_handling",            # load when error pages detected
    # "rest_api_security",             # load when REST API endpoints detected
]
