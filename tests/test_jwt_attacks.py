"""Integration test: JWT alg=none bypass against the vulnerable target."""
import requests

from scanner.modules.jwt_attacks import JWTAttackSuite


def test_alg_none_bypass_detected(vulnerable_target):
    resp = requests.post(
        f"{vulnerable_target}/api/login",
        json={"username": "alice", "password": "alicepassword"},
    )
    token = resp.json()["token"]

    suite = JWTAttackSuite(vulnerable_target, "/api/accounts/1", token, requests.Session())
    finding = suite.test_alg_none()

    assert finding is not None
    assert finding.title == "JWT alg=none bypass"


def test_weak_secret_detected(vulnerable_target):
    resp = requests.post(
        f"{vulnerable_target}/api/login",
        json={"username": "alice", "password": "alicepassword"},
    )
    token = resp.json()["token"]

    suite = JWTAttackSuite(vulnerable_target, "/api/accounts/1", token, requests.Session())
    finding = suite.test_weak_secret()

    assert finding is not None
    assert finding.title == "Weak JWT signing secret"
