"""Shared Finding data model used by every scanner module and the
report generator."""
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}

REMEDIATION_MAP = {
    "API1:2023 BOLA": (
        "Enforce object-level authorization checks on every request that "
        "accesses a resource by ID. Verify the authenticated user owns or "
        "is permitted to access that specific object — not just that they "
        "are authenticated at all."
    ),
    "API2:2023 Broken Authentication": (
        "Pin the expected signing algorithm(s) server-side and never trust "
        "the 'alg' header inside the token itself. Always require and "
        "verify a valid signature, and reject expired tokens."
    ),
    "API3:2023 Broken Object Property Level Authorization": (
        "Use an explicit allow-list of client-writable fields on every "
        "write endpoint. Never bind a request body directly onto an "
        "internal model."
    ),
    "API4:2023 Unrestricted Resource Consumption": (
        "Apply per-IP and/or per-account rate limiting on all endpoints, "
        "especially authentication endpoints. Key rate limits off "
        "connection-level data (e.g. the socket's remote address), not "
        "client-supplied headers like X-Forwarded-For unless you control "
        "and trust the upstream proxy chain."
    ),
    "API5:2023 Broken Function Level Authorization": (
        "Enforce role checks on every administrative or privileged route "
        "through a centralized authorization layer, not ad-hoc per-route "
        "logic, and never rely solely on a client-supplied claim."
    ),
    "API8:2023 Security Misconfiguration": (
        "Disable debug mode and verbose stack traces outside local "
        "development. Set standard security headers "
        "(X-Content-Type-Options, X-Frame-Options, "
        "Strict-Transport-Security, Content-Security-Policy) on every "
        "response."
    ),
    "Secrets Exposure": (
        "Remove secrets from responses, headers, logs, and error "
        "messages. Rotate any credential that may have been exposed and "
        "store secrets in a dedicated secrets manager, not in code or "
        "responses."
    ),
}

DEFAULT_REMEDIATION = (
    "Review the affected endpoint and apply the relevant OWASP API "
    "Security Top 10 (2023) mitigation for this category."
)


@dataclass
class Finding:
    severity: str          # CRITICAL | HIGH | MEDIUM | LOW | INFO
    owasp: str              # e.g. "API1:2023 BOLA"
    endpoint: str
    evidence: str
    title: Optional[str] = None
    remediation: Optional[str] = None
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def __post_init__(self):
        if self.title is None:
            self.title = self.owasp
        if self.remediation is None:
            self.remediation = REMEDIATION_MAP.get(self.owasp, DEFAULT_REMEDIATION)
