"""API8:2023 Security misconfiguration - missing security headers and
verbose debug output."""
from scanner.findings import Finding

EXPECTED_HEADERS = [
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Strict-Transport-Security",
    "Content-Security-Policy",
]


class SecurityHeadersChecker:
    def __init__(self, base_url, session, sample_endpoints):
        self.base_url = base_url.rstrip("/")
        self.session = session
        self.sample_endpoints = sample_endpoints

    def run(self):
        findings = []
        for endpoint in self.sample_endpoints:
            url = f"{self.base_url}{endpoint}"
            try:
                resp = self.session.get(url)
            except Exception:
                continue

            missing = [h for h in EXPECTED_HEADERS if h not in resp.headers]
            if missing:
                findings.append(Finding(
                    severity="LOW",
                    owasp="API8:2023 Security Misconfiguration",
                    endpoint=url,
                    title="Missing security headers",
                    evidence=f"Response is missing: {', '.join(missing)}.",
                ))

            if "Traceback (most recent call last)" in resp.text:
                findings.append(Finding(
                    severity="MEDIUM",
                    owasp="API8:2023 Security Misconfiguration",
                    endpoint=url,
                    title="Verbose error/debug output exposed",
                    evidence="Response body appears to contain a Python stack trace.",
                ))
        return findings
