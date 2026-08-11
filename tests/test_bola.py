"""Integration test: BOLA tester against the vulnerable target."""
import requests

from scanner.modules.bola_tester import BOLATester


def _login(base_url, username, password):
    resp = requests.post(f"{base_url}/api/login", json={"username": username, "password": password})
    resp.raise_for_status()
    return resp.json()["token"]


def test_bola_detects_vulnerability(vulnerable_target):
    token_a = _login(vulnerable_target, "alice", "alicepassword")
    token_b = _login(vulnerable_target, "bob", "bobpassword")

    session_a = requests.Session()
    session_a.headers.update({"Authorization": f"Bearer {token_a}"})
    session_b = requests.Session()
    session_b.headers.update({"Authorization": f"Bearer {token_b}"})

    tester = BOLATester(vulnerable_target, session_a, session_b, user_a_id=1)
    findings = tester.run([("/api/orders/{id}", 101)])

    assert len(findings) == 1
    assert findings[0].owasp == "API1:2023 BOLA"
    assert findings[0].severity == "CRITICAL"
