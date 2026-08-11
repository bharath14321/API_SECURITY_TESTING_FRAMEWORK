"""API4:2023 Unrestricted resource consumption - rate limit tester.

Floods an endpoint with concurrent requests (asyncio + httpx) to check
whether any rate limiting is enforced, then — only if limiting IS
present — checks whether it can be defeated by rotating
X-Forwarded-For / X-Real-IP headers.
"""
import asyncio

import httpx

from scanner.findings import Finding


class RateLimitTester:
    def __init__(self, base_url, endpoint, method="POST", json_body=None, concurrency=30):
        self.base_url = base_url.rstrip("/")
        self.endpoint = endpoint
        self.method = method
        self.json_body = json_body or {}
        self.concurrency = concurrency

    async def _flood(self):
        url = f"{self.base_url}{self.endpoint}"
        async with httpx.AsyncClient(timeout=10) as client:
            tasks = [
                client.request(self.method, url, json=self.json_body)
                for _ in range(self.concurrency)
            ]
            return await asyncio.gather(*tasks, return_exceptions=True)

    def test_flood(self):
        responses = asyncio.run(self._flood())
        statuses = [r.status_code for r in responses if not isinstance(r, Exception)]
        rate_limited = sum(1 for s in statuses if s == 429)
        successful = sum(1 for s in statuses if s < 400)
        if statuses and rate_limited == 0:
            return Finding(
                severity="HIGH",
                owasp="API4:2023 Unrestricted Resource Consumption",
                endpoint=f"{self.base_url}{self.endpoint}",
                title="No rate limiting detected",
                evidence=(
                    f"Sent {self.concurrency} concurrent requests to "
                    f"{self.method} {self.endpoint}; {successful} were "
                    f"accepted and 0 received HTTP 429. No rate limiting "
                    f"appears to be enforced."
                ),
            )
        return None

    def test_header_spoof_bypass(self, spoof_headers=None):
        """Only meaningful once test_flood() has confirmed rate limiting
        IS active — checks whether rotating forwarding headers defeats it."""
        spoof_headers = spoof_headers or ["X-Forwarded-For", "X-Real-IP"]
        url = f"{self.base_url}{self.endpoint}"
        statuses = []
        with httpx.Client(timeout=10) as client:
            for i in range(self.concurrency):
                headers = {h: f"10.0.{i % 255}.{i % 255}" for h in spoof_headers}
                resp = client.request(self.method, url, json=self.json_body, headers=headers)
                statuses.append(resp.status_code)
        rate_limited = sum(1 for s in statuses if s == 429)
        if statuses and rate_limited == 0:
            return Finding(
                severity="MEDIUM",
                owasp="API4:2023 Unrestricted Resource Consumption",
                endpoint=url,
                title="Rate limit bypass via spoofed forwarding headers",
                evidence=(
                    f"Rotating {', '.join(spoof_headers)} across "
                    f"{self.concurrency} requests produced 0 HTTP 429 "
                    f"responses, suggesting the rate limiter trusts "
                    f"client-supplied headers."
                ),
            )
        return None

    def run(self):
        findings = []
        flood_result = self.test_flood()
        if flood_result:
            findings.append(flood_result)
        else:
            # Rate limiting is active - now check whether it can be
            # bypassed via spoofed forwarding headers.
            bypass_result = self.test_header_spoof_bypass()
            if bypass_result:
                findings.append(bypass_result)
        return findings
