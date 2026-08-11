"""API1:2023 BOLA (Broken Object Level Authorization) tester.

Given two authenticated sessions for two different users, try to
access user A's resources using user B's session/token.
"""
from scanner.findings import Finding


class BOLATester:
    def __init__(self, base_url, session_a, session_b, user_a_id):
        self.base_url = base_url.rstrip("/")
        self.session_a = session_a
        self.session_b = session_b
        self.user_a_id = user_a_id

    def test_endpoint(self, path_template, resource_id, owasp_tag="API1:2023 BOLA"):
        """
        path_template: e.g. '/api/orders/{id}' — a resource that belongs
        to user A, accessed with user B's session.
        """
        url = f"{self.base_url}{path_template.format(id=resource_id)}"
        resp = self.session_b.get(url)
        if resp.status_code == 200:
            return Finding(
                severity="CRITICAL",
                owasp=owasp_tag,
                endpoint=url,
                title="Cross-user object access (BOLA)",
                evidence=(
                    f"User B's session retrieved user A's resource at {url} "
                    f"(status {resp.status_code}). The response did not "
                    f"enforce an ownership check."
                ),
            )
        return None

    def run(self, endpoints):
        """endpoints: list of (path_template, resource_id) tuples."""
        findings = []
        for path_template, resource_id in endpoints:
            finding = self.test_endpoint(path_template, resource_id)
            if finding:
                findings.append(finding)
        return findings
