"""PoC Validation Module for prometheus.

Executes PoC code to verify findings actually work before reporting.
Prevents false positives from being filed as real vulnerabilities.

This module addresses the gap where prometheus would report findings based on
observation (e.g., "internal hostname leaked in response") without verifying
the finding has actual security impact (e.g., "used internal hostname to
access internal service and extract data").
"""

from __future__ import annotations

import logging
import re
import subprocess
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class PoCValidationResult:
    """Result of validating a PoC."""
    
    finding_title: str
    poc_executed: bool  # Whether the PoC code was actually executed
    poc_successful: bool  # Whether the PoC demonstrated exploitation
    impact_demonstrated: bool  # Whether real security impact was shown
    verdict: str  # 'exploitable', 'informational', 'false_positive', 'unvalidated'
    reason: str
    confidence: float  # 0.0-1.0
    evidence: str  # Actual output from PoC execution
    missing: str  # What's needed to make this a real finding
    recommendations: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Patterns that indicate INFORMATIONAL findings (not real vulnerabilities)
# ---------------------------------------------------------------------------

_INFORMATIONAL_PATTERNS = [
    # SSR internal hostname/IP disclosure
    (r"(?:ssr|server.side.render|nuxt|next|angular).*?(?:internal|private|local).*?(?:hostname|ip|address|server)", 
     "SSR internal hostname/IP disclosure is reconnaissance, not a vulnerability"),
    (r"(?:internal|private|local).*?(?:hostname|ip|address).*?(?:leak|disclos|expos|found|discover)",
     "Internal hostname/IP discovery is reconnaissance, not exploitation"),
    (r"(?:railway|vercel|heroku|aws|gcp|azure).*?(?:internal|private).*?(?:hostname|ip|address)",
     "Cloud platform internal addressing is expected infrastructure behavior"),
    
    # Version/fingerprint disclosure
    (r"(?:version|banner|fingerprint).*?(?:disclos|leak|expos|found|discover)",
     "Version/banner disclosure is reconnaissance, not a vulnerability"),
    (r"(?:nginx|apache|express|django|laravel|rails|next|nuxt|angular|react|vue).*?(?:version|header|banner)",
     "Technology fingerprinting is reconnaissance, not exploitation"),
    
    # Missing headers without impact
    (r"missing.*?(?:header|policy|cors|csp|hsts|x-frame|content-type|referrer)",
     "Missing security headers without demonstrated impact are informational"),
    (r"(?:header|policy|cors|csp|hsts).*?(?:missing|absent|not present|not set)",
     "Security header absence without exploitation is informational"),
    
    # Configuration observations
    (r"(?:misconfiguration|misconfig|weak|insecure).*?(?:found|discover|detect|identif)",
     "Configuration observations without exploitation are reconnaissance"),
    (r"(?:ssl|tls|certificate).*?(?:weak|insecure|deprecated|expired)",
     "SSL/TLS observations without exploitation are informational"),
]

# Patterns that indicate REAL vulnerabilities (exploitable)
_EXPLOITABLE_PATTERNS = [
    # Data access/exfiltration
    (r"(?:accessed|read|retrieved|extracted|exfiltrated|downloaded).*?(?:data|records|documents|files|database)",
     "Demonstrated unauthorized data access"),
    (r"(?:used|called|executed).*?(?:api|endpoint|service|command).*?(?:with|using).*?(?:found|discovered|leaked)",
     "Used discovered credentials to access unauthorized resources"),
    
    # Authentication/authorization bypass
    (r"(?:bypassed|circumvented|evaded).*?(?:auth|authorization|access.control|permission)",
     "Demonstrated authentication/authorization bypass"),
    (r"(?:accessed|viewed|modified).*?(?:other.user|another.user|admin|privilege)",
     "Accessed unauthorized user data or admin functions"),
    
    # Code execution
    (r"(?:executed|ran|injected).*?(?:command|code|script|payload).*?(?:on.server|in.browser|in.context)",
     "Demonstrated code/command execution"),
    (r"(?:reverse.shell|command.injection|code.injection).*?(?:successful|confirmed|established)",
     "Confirmed code/command injection"),
    
    # Data modification
    (r"(?:modified|created|deleted|updated|changed).*?(?:data|record|document|account|user)",
     "Demonstrated unauthorized data modification"),
    
    # Financial impact
    (r"(?:stole|transferred|withdrew|manipulated).*?(?:funds|money|balance|credit|payment)",
     "Demonstrated financial impact"),
]


def _classify_poc_type(poc_description: str, poc_code: str, title: str) -> str:
    """Classify the PoC type based on description and code.
    
    Returns:
        'exploitable' - PoC demonstrates real exploitation
        'informational' - PoC only shows observation/reconnaissance
        'unvalidated' - Cannot determine from text alone
    """
    all_text = f"{title} {poc_description} {poc_code}".lower()
    
    # Check for exploitable patterns first (higher priority)
    for pattern, description in _EXPLOITABLE_PATTERNS:
        if re.search(pattern, all_text, re.IGNORECASE):
            logger.info("PoC classified as exploitable: %s", description)
            return "exploitable"
    
    # Check for informational patterns
    for pattern, description in _INFORMATIONAL_PATTERNS:
        if re.search(pattern, all_text, re.IGNORECASE):
            logger.info("PoC classified as informational: %s", description)
            return "informational"
    
    return "unvalidated"


def _extract_curl_commands(poc_code: str) -> list[str]:
    """Extract curl commands from PoC code."""
    commands = []
    
    # Find curl commands (handle multiline with backslash continuation)
    curl_pattern = r'curl\s.*?(?:\n\s*\\\s*.*)*'
    matches = re.findall(curl_pattern, poc_code, re.MULTILINE | re.DOTALL)
    
    for match in matches:
        # Clean up continuation lines
        cmd = re.sub(r'\s*\\\n\s*', ' ', match).strip()
        if cmd.startswith('curl '):
            commands.append(cmd)
    
    return commands


def _execute_curl_command(command: str, timeout: int = 30) -> tuple[bool, str, str]:
    """Execute a curl command and return success, stdout, stderr.
    
    Returns:
        Tuple of (success, stdout, stderr)
    """
    try:
        # Add timeout and follow redirects
        if '--max-time' not in command:
            command = f"{command} --max-time {timeout}"
        if '-L' not in command and '--location' not in command:
            command = f"{command} -L"
        
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout + 5,
        )
        return result.returncode == 0, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return False, "", "Command timed out"
    except Exception as e:
        return False, "", str(e)


def _analyze_curl_output(
    success: bool,
    stdout: str, 
    stderr: str, 
    expected_patterns: list[str],
) -> tuple[bool, str]:
    """Analyze curl output to determine if exploitation was successful.
    
    Args:
        success: Whether curl command succeeded
        stdout: Standard output from curl
        stderr: Standard error from curl
        expected_patterns: Regex patterns that indicate successful exploitation
    
    Returns:
        Tuple of (exploited, evidence)
    """
    if not success:
        return False, f"Command failed: {stderr}"
    
    output = stdout + stderr
    
    # Check for expected exploitation patterns
    for pattern in expected_patterns:
        if re.search(pattern, output, re.IGNORECASE):
            return True, f"Exploitation confirmed: pattern '{pattern}' found in output"
    
    # Check for error patterns that indicate exploitation failed
    error_patterns = [
        r"403\s*forbidden",
        r"401\s*unauthorized",
        r"404\s*not\s*found",
        r"access\s*denied",
        r"permission\s*denied",
        r"invalid\s*(?:token|key|credential)",
        r"authentication\s*failed",
    ]
    
    for pattern in error_patterns:
        if re.search(pattern, output, re.IGNORECASE):
            return False, f"Exploitation failed: {pattern} in response"
    
    # If we have output but no clear exploitation signal, it's ambiguous
    if output.strip():
        return False, f"Ambiguous output (length={len(output)}): no clear exploitation signal"
    
    return False, "Empty output"


def validate_poc_execution(
    finding: dict[str, Any],
    execute_poc: bool = False,
    timeout: int = 30,
) -> PoCValidationResult:
    """Validate a PoC by analyzing and optionally executing it.
    
    This function:
    1. Classifies the PoC type (exploitable, informational, unvalidated)
    2. If execute_poc=True, executes curl commands to verify they work
    3. Returns a verdict on whether the finding is reportable
    
    Args:
        finding: Dict with 'title', 'poc_description', 'poc_script_code', etc.
        execute_poc: Whether to actually execute the PoC code (requires sandbox)
        timeout: Timeout for PoC execution in seconds
    
    Returns:
        PoCValidationResult with verdict and evidence
    """
    title = finding.get("title", "")
    poc_desc = finding.get("poc_description", "")
    poc_code = finding.get("poc_script_code", "")
    
    # Step 1: Classify PoC type based on text analysis
    poc_type = _classify_poc_type(poc_desc, poc_code, title)
    
    if poc_type == "informational":
        return PoCValidationResult(
            finding_title=title,
            poc_executed=False,
            poc_successful=False,
            impact_demonstrated=False,
            verdict="informational",
            reason=(
                "PoC description indicates reconnaissance/observation, not exploitation. "
                "The finding describes discovering information (internal hostnames, versions, "
                "configurations) without demonstrating how that information enables an attack."
            ),
            confidence=0.8,
            evidence="",
            missing=(
                "To make this reportable: demonstrate actual exploitation using the discovered "
                "information. For example, if you found an internal hostname, show how accessing "
                "it reveals sensitive data or enables unauthorized actions."
            ),
            recommendations=[
                "Chain the discovery with a concrete attack (e.g., SSRF to internal service)",
                "Show unauthorized data access using the discovered information",
                "Demonstrate privilege escalation or authentication bypass",
                "If you cannot exploit it, note it in agent notes as reconnaissance",
            ],
        )
    
    if poc_type == "exploitable":
        # Even if classified as exploitable, verify the PoC actually works
        if execute_poc and poc_code:
            return _execute_and_validate_poc(finding, timeout)
        
        return PoCValidationResult(
            finding_title=title,
            poc_executed=False,
            poc_successful=False,
            impact_demonstrated=True,
            verdict="exploitable",
            reason=(
                "PoC description indicates real exploitation (data access, auth bypass, "
                "code execution, etc.). Text analysis suggests this is a valid finding."
            ),
            confidence=0.7,
            evidence="",
            missing="",
            recommendations=[
                "Verify the PoC works by executing it",
                "Document the exact HTTP requests and responses",
                "Include evidence of the exploitation in the report",
            ],
        )
    
    # For unvalidated type, try to execute if possible
    if execute_poc and poc_code:
        return _execute_and_validate_poc(finding, timeout)
    
    return PoCValidationResult(
        finding_title=title,
        poc_executed=False,
        poc_successful=False,
        impact_demonstrated=False,
        verdict="unvalidated",
        reason=(
            "Cannot determine if PoC demonstrates real exploitation from text analysis alone. "
            "Execution required to verify."
        ),
        confidence=0.5,
        evidence="",
        missing="Execute the PoC to verify it works and demonstrates real impact",
        recommendations=[
            "Execute the PoC code to verify it works",
            "Document the actual HTTP requests and responses",
            "Show concrete evidence of exploitation, not just observation",
        ],
    )


def _execute_and_validate_poc(
    finding: dict[str, Any],
    timeout: int = 30,
) -> PoCValidationResult:
    """Execute PoC code and validate the results."""
    title = finding.get("title", "")
    poc_desc = finding.get("poc_description", "")
    poc_code = finding.get("poc_script_code", "")
    
    # Extract curl commands from PoC code
    curl_commands = _extract_curl_commands(poc_code)
    
    if not curl_commands:
        return PoCValidationResult(
            finding_title=title,
            poc_executed=False,
            poc_successful=False,
            impact_demonstrated=False,
            verdict="unvalidated",
            reason="No curl commands found in PoC code to execute",
            confidence=0.4,
            evidence="",
            missing="Provide executable curl commands in the PoC code",
            recommendations=[
                "Include actual curl commands that demonstrate the vulnerability",
                "Show the HTTP request and response that proves exploitation",
            ],
        )
    
    # Execute each curl command
    all_evidence = []
    any_successful = False
    exploitation_confirmed = False
    
    for i, cmd in enumerate(curl_commands, 1):
        logger.info("Executing PoC curl command %d/%d: %s", i, len(curl_commands), cmd[:100])
        
        success, stdout, stderr = _execute_curl_command(cmd, timeout)
        
        if success:
            any_successful = True
            
            # Analyze output for exploitation signals
            # Look for signs that the vulnerability was actually exploited
            output = stdout + stderr
            
            # Check for data exfiltration patterns
            data_patterns = [
                r'"[^"]*":\s*"[^"]*"',  # JSON data
                r'<[^>]+>[^<]*</[^>]+>',  # HTML/XML content
                r'api[_-]?key|token|secret|password|credential',
                r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',  # IP addresses
                r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',  # Email addresses
            ]
            
            for pattern in data_patterns:
                if re.search(pattern, output, re.IGNORECASE):
                    exploitation_confirmed = True
                    all_evidence.append(
                        f"Command {i}: SUCCESS - Found data pattern '{pattern}' in response"
                    )
                    break
            else:
                all_evidence.append(
                    f"Command {i}: Request succeeded but no clear exploitation evidence in response"
                )
        else:
            all_evidence.append(f"Command {i}: FAILED - {stderr}")
    
    evidence_text = "\n".join(all_evidence)
    
    if exploitation_confirmed:
        return PoCValidationResult(
            finding_title=title,
            poc_executed=True,
            poc_successful=True,
            impact_demonstrated=True,
            verdict="exploitable",
            reason="PoC executed successfully and demonstrated exploitation",
            confidence=0.9,
            evidence=evidence_text,
            missing="",
            recommendations=[
                "Document the exact HTTP requests and responses in the report",
                "Include the evidence from PoC execution",
            ],
        )
    elif any_successful:
        return PoCValidationResult(
            finding_title=title,
            poc_executed=True,
            poc_successful=False,
            impact_demonstrated=False,
            verdict="informational",
            reason=(
                "PoC commands executed but did not demonstrate clear exploitation. "
                "The requests succeeded but the responses did not show unauthorized access "
                "or data exfiltration."
            ),
            confidence=0.7,
            evidence=evidence_text,
            missing=(
                "The PoC shows the endpoint responds but does not demonstrate unauthorized "
                "access, data exfiltration, or other security impact."
            ),
            recommendations=[
                "Modify the PoC to demonstrate actual exploitation",
                "Show unauthorized data access or privilege escalation",
                "Include evidence of security impact in the response",
            ],
        )
    else:
        return PoCValidationResult(
            finding_title=title,
            poc_executed=True,
            poc_successful=False,
            impact_demonstrated=False,
            verdict="false_positive",
            reason="PoC execution failed - all curl commands returned errors",
            confidence=0.8,
            evidence=evidence_text,
            missing="The PoC does not work as described",
            recommendations=[
                "Verify the target URL and parameters are correct",
                "Check if the vulnerability still exists",
                "Update the PoC with working commands",
            ],
        )


def validate_finding_with_poc(
    finding: dict[str, Any],
    execute_poc: bool = False,
    timeout: int = 30,
) -> dict[str, Any]:
    """Validate a finding by analyzing and optionally executing its PoC.
    
    This is the main entry point for PoC validation. It combines:
    1. Text-based classification (informational vs exploitable)
    2. Optional PoC execution to verify it works
    3. Output analysis to confirm exploitation
    
    Args:
        finding: Dict with finding details (title, poc_description, poc_script_code, etc.)
        execute_poc: Whether to actually execute the PoC code
        timeout: Timeout for PoC execution in seconds
    
    Returns:
        Dict with validation result, verdict, and recommendations
    """
    result = validate_poc_execution(finding, execute_poc, timeout)
    
    return {
        "finding_title": result.finding_title,
        "poc_executed": result.poc_executed,
        "poc_successful": result.poc_successful,
        "impact_demonstrated": result.impact_demonstrated,
        "verdict": result.verdict,
        "reason": result.reason,
        "confidence": result.confidence,
        "evidence": result.evidence,
        "missing": result.missing,
        "recommendations": result.recommendations,
        "reportable": result.verdict == "exploitable" and result.impact_demonstrated,
    }
