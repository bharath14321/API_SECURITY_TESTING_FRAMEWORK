"""Secrets/API key exposure scanner - regex + Shannon entropy analysis
on response bodies and headers. Mirrors the approach real tools like
TruffleHog/GitLeaks use for repo scanning, applied to live HTTP traffic
instead of git history."""
import math
import re
from collections import Counter

from scanner.findings import Finding

REGEX_PATTERNS = {
    "AWS Access Key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "Generic API Key": re.compile(r"(?i)api[_-]?key[\"'=:\s]+[0-9a-zA-Z]{16,45}"),
    "Private Key Block": re.compile(r"-----BEGIN (RSA|EC|OPENSSH|DSA) PRIVATE KEY-----"),
    "JWT in response body": re.compile(r"(?i)\"?token\"?\s*[:=]\s*\"?eyJ[0-9A-Za-z_-]{10,}"),
    "Generic Secret Assignment": re.compile(r"(?i)(secret|password|passwd|pwd)[\"'=:\s]+[^\s\"']{8,}"),
}

ENTROPY_THRESHOLD = 4.3  # bits/char - typical for random tokens/keys
MIN_TOKEN_LENGTH = 20
MAX_ENTROPY_HITS_PER_RESPONSE = 3


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def find_high_entropy_tokens(text: str):
    candidates = re.findall(r"[A-Za-z0-9+/_=-]{20,}", text)
    return [t for t in candidates if len(t) >= MIN_TOKEN_LENGTH and shannon_entropy(t) >= ENTROPY_THRESHOLD]


class SecretsScanner:
    def __init__(self, base_url, session, sample_endpoints):
        self.base_url = base_url.rstrip("/")
        self.session = session
        self.sample_endpoints = sample_endpoints

    def _scan_text(self, text, source_label, url):
        findings = []
        for name, pattern in REGEX_PATTERNS.items():
            if pattern.search(text):
                findings.append(Finding(
                    severity="HIGH",
                    owasp="Secrets Exposure",
                    endpoint=url,
                    title=f"Possible {name} in {source_label}",
                    evidence=(
                        f"A pattern matching '{name}' was found in "
                        f"{source_label}. Value redacted in this report."
                    ),
                ))
        for token in find_high_entropy_tokens(text)[:MAX_ENTROPY_HITS_PER_RESPONSE]:
            findings.append(Finding(
                severity="MEDIUM",
                owasp="Secrets Exposure",
                endpoint=url,
                title=f"High-entropy string in {source_label}",
                evidence=(
                    f"A {len(token)}-character high-entropy string was "
                    f"found in {source_label} (entropy >= "
                    f"{ENTROPY_THRESHOLD} bits/char). This may be an "
                    f"accidentally exposed token or key."
                ),
            ))
        return findings

    def run(self):
        findings = []
        for endpoint in self.sample_endpoints:
            url = f"{self.base_url}{endpoint}"
            try:
                resp = self.session.get(url)
            except Exception:
                continue
            findings.extend(self._scan_text(resp.text, "response body", url))
            findings.extend(self._scan_text(str(dict(resp.headers)), "response headers", url))
        return findings
